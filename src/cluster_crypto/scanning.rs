use self::crypto_objects::DiscoveredCryptoObect;
use super::{
    certificate, crypto_objects, crypto_utils,
    locations::{FileContentLocation, FileLocation, K8sResourceLocation, Location, LocationValueType},
};
use crate::{
    cluster_crypto::{crypto_objects::process_unknown_value, json_crawl},
    config::path::ConfigPath,
    file_utils::{self, read_file_to_string},
    k8s_etcd::InMemoryK8sEtcd,
    recert::timing::RunTime,
};
use anyhow::{bail, ensure, Context, Error, Result};
use futures_util::future::join_all;
use serde_json::Value;
use std::{
    collections::HashSet,
    os::unix::prelude::OsStrExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::task::JoinHandle;

pub(crate) mod external_certs;

pub(crate) type ExternalCertsName = String;
pub(crate) type ExternalCertsHash = String;

#[derive(Clone, Debug)]
pub(crate) struct ExternalCerts(HashSet<(ExternalCertsName, ExternalCertsHash)>);

impl ExternalCerts {
    pub(crate) fn has_cert(&self, hashable_cert: &certificate::Certificate) -> Result<bool> {
        let der_bytes = hashable_cert.cert.constructed_data();
        let sha256bytes = crypto_utils::sha256(der_bytes).context("sha256")?;
        let sha256hex = hex::encode(sha256bytes);

        Ok(self.0.contains(&(hashable_cert.subject.to_string(), sha256hex)))
    }

    pub(crate) fn empty() -> Self {
        Self(HashSet::new())
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

pub(crate) async fn crypto_scan(
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    crypto_dirs: Vec<ConfigPath>,
    crypto_files: Vec<ConfigPath>,
    external_certs: ExternalCerts,
) -> Result<(RunTime, Vec<DiscoveredCryptoObect>)> {
    log::info!("Scanning for cryptographic objects...");

    let start_time = std::time::Instant::now();

    // Launch separate paralllel long running background task
    let discovered_filesystem_dir_crypto_objects = scan_crypto_dirs(crypto_dirs, &external_certs);
    let discovered_filesystem_file_crypto_objects = scan_crypto_files(crypto_files, &external_certs);
    let external_certs = external_certs.clone();
    let discovered_etcd_crypto_objects = tokio::spawn(async move {
        scan_etcd_resources(in_memory_etcd_client, &external_certs)
            .await
            .context("etcd resources")
    });

    // ... and join them
    log::info!("Waiting for scanning to complete...");
    let discovered_etcd_objects = discovered_etcd_crypto_objects.await??;
    log::info!("Etcd scanning complete");
    let discovered_filesystem_dir_objects = discovered_filesystem_dir_crypto_objects.await??;
    log::info!("Static dir scanning complete");
    let discovered_filesystem_file_objects = discovered_filesystem_file_crypto_objects.await??;
    log::info!("Static file scanning complete");

    log::info!(
        "Scanning complete, filesystem dir objects: {}, filesystem file objects: {}, etcd objects: {}",
        discovered_filesystem_dir_objects.len(),
        discovered_filesystem_file_objects.len(),
        discovered_etcd_objects.len()
    );

    // Return all objects discovered as one large vector
    let all_discovered_objects = discovered_etcd_objects
        .into_iter()
        .chain(discovered_filesystem_dir_objects)
        .chain(discovered_filesystem_file_objects)
        .collect::<Vec<_>>();

    log::info!(
        "Scanning for cryptographic objects done, found {} objects",
        all_discovered_objects.len()
    );

    Ok((RunTime::since_start(start_time), all_discovered_objects))
}

fn scan_crypto_dirs(crypto_dirs: Vec<ConfigPath>, external_certs: &ExternalCerts) -> JoinHandle<Result<Vec<DiscoveredCryptoObect>, Error>> {
    let external_certs = external_certs.clone();
    tokio::spawn(async move {
        anyhow::Ok(
            join_all(
                crypto_dirs
                    .into_iter()
                    .map(|crypto_dir| {
                        let external_certs = external_certs.clone();
                        tokio::spawn(async move {
                            log::trace!("Scanning dir {:?}", crypto_dir);
                            scan_filesystem_directory(&crypto_dir, external_certs)
                                .await
                                .with_context(|| format!("static dir {:?}", crypto_dir))
                        })
                    })
                    .collect::<Vec<_>>(),
            )
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>(),
        )
    })
}

fn scan_crypto_files(
    crypto_files: Vec<ConfigPath>,
    external_certs: &ExternalCerts,
) -> JoinHandle<Result<Vec<DiscoveredCryptoObect>, Error>> {
    let external_certs = external_certs.clone();
    tokio::spawn(async move {
        anyhow::Ok(
            join_all(
                crypto_files
                    .into_iter()
                    .map(|crypto_file| {
                        let external_certs = external_certs.clone();
                        tokio::spawn(async move {
                            log::trace!("Scanning file {:?}", crypto_file);
                            scan_filesystem_file(crypto_file.to_path_buf(), external_certs)
                                .await
                                .with_context(|| format!("crypto file {:?}", crypto_file))
                        })
                    })
                    .collect::<Vec<_>>(),
            )
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>(),
        )
    })
}

/// Read all relevant resources from etcd, scan them for cryptographic objects and record them
/// in the appropriate data structures.
pub(crate) async fn scan_etcd_resources(
    etcd_client: Arc<InMemoryK8sEtcd>,
    external_certs: &ExternalCerts,
) -> Result<Vec<DiscoveredCryptoObect>> {
    let key_lists = {
        let etcd_client = &etcd_client;
        [
            &(etcd_client.list_keys("secrets").await.context("listing secrets")?),
            &(etcd_client.list_keys("configmaps").await.context("listing configmaps")?),
            &(etcd_client
                .list_keys("validatingwebhookconfigurations")
                .await
                .context("listing validatingwebhookconfigurations")?),
            &(etcd_client
                .list_keys("mutatingwebhookconfigurations")
                .await
                .context("listing validatingwebhookconfigurations")?),
            &(etcd_client
                .list_keys("apiregistration.k8s.io/apiservices")
                .await
                .context("listing apiservices")?),
            &(etcd_client
                .list_keys("machineconfiguration.openshift.io/machineconfigs")
                .await
                .context("listing machineconfigs")?),
            &(etcd_client
                .list_keys("machineconfiguration.openshift.io/controllerconfigs")
                .await
                .context("listing controllerconfigs")?),
        ]
    };

    let all_keys = key_lists.into_iter().flatten().collect::<Vec<_>>();

    if all_keys.is_empty() && etcd_client.etcd_client.is_some() {
        bail!("No keys found in etcd - is the etcd database empty/corrupt?")
    }

    Ok(join_all(
        all_keys
            .into_iter()
            .map(|key| {
                let key = key.clone();
                let etcd_client = Arc::clone(&etcd_client);
                let external_certs = external_certs.clone();
                tokio::spawn(async move {
                    log::trace!("Scanning etcd key {:?}", key);
                    let etcd_result = etcd_client
                        .get(key.clone())
                        .await
                        .with_context(|| format!("getting key {:?}", key))?
                        .context("key disappeared")?;
                    let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                        .with_context(|| format!("deserializing value of key {:?}", key,))?;
                    let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                    // Ensure our as_etcd_key function knows to generates the correct key, while we
                    // still have the key to compare to. TODO: Find a more robust way to generate
                    // etcd keys, kubernetes is doing it weirdly which is why as_etcd_key is so
                    // complicated. Couldn't find documentation on how it should be done properly
                    ensure!(
                        etcd_result.key == k8s_resource_location.as_etcd_key(),
                        "{:?} != {:?}",
                        etcd_result.key,
                        k8s_resource_location.as_etcd_key()
                    );

                    let decoded_yaml_values = json_crawl::crawl_json(value)
                        .with_context(|| format!("crawling yaml of key {:?}", key))?
                        .iter()
                        .map(|yaml| json_crawl::decode_json_value(yaml).context(format!("decoding yaml of key {:?}", key)))
                        .collect::<Result<Vec<_>>>()?;

                    anyhow::Ok(
                        decoded_yaml_values
                            .into_iter()
                            .flatten()
                            .map(|(yaml_location, yaml_value)| {
                                process_unknown_value(
                                    yaml_value,
                                    &Location::k8s_yaml(&k8s_resource_location, &yaml_location),
                                    &external_certs,
                                )
                                .with_context(|| format!("processing yaml value of key {:?} at location {:?}", key, yaml_location))
                            })
                            .collect::<Result<Vec<_>>>()?
                            .into_iter()
                            .flatten()
                            .collect::<Vec<_>>(),
                    )
                })
            })
            .collect::<Vec<_>>(),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .flatten()
    .collect::<Vec<_>>())
}

/// Recursively scans a directoy for files which exclusively contain a PEM bundle (as opposed
/// to being embedded in a YAML file) and records them in the appropriate data structures.
pub(crate) async fn scan_filesystem_directory(dir: &Path, external_certs: ExternalCerts) -> Result<Vec<DiscoveredCryptoObect>> {
    let external_certs = external_certs.clone();
    Ok(join_all(
        file_utils::globvec(dir, "**/*.pem")?
            .into_iter()
            // Other classic PEM extensions
            .chain(file_utils::globvec(dir, "**/*.crt")?.into_iter())
            .chain(file_utils::globvec(dir, "**/*.key")?.into_iter())
            .chain(file_utils::globvec(dir, "**/*.pub")?.into_iter())
            // Also scan for the .mcdorig versions of the above files, which are sometimes created
            // by machine-config-daemon
            .chain(file_utils::globvec(dir, "**/*.crt.mcdorig")?.into_iter())
            .chain(file_utils::globvec(dir, "**/*.key.mcdorig")?.into_iter())
            .chain(file_utils::globvec(dir, "**/*.pub.mcdorig")?.into_iter())
            // A file-system copy of machineconfig objects found in /etc/machine-config-daemon/currentconfig
            .chain(file_utils::globvec(dir, "**/currentconfig")?.into_iter())
            // A file used by MCS
            .chain(file_utils::globvec(dir, "**/mcs-machine-config-content.json")?.into_iter())
            // The various names for kubeconfig files
            .chain(file_utils::globvec(dir, "**/*kubeconfig")?.into_iter())
            .chain(file_utils::globvec(dir, "**/kubeconfig")?.into_iter())
            .chain(file_utils::globvec(dir, "**/kubeConfig")?.into_iter())
            // JWT tokens can be found in files named "token"
            .chain(file_utils::globvec(dir, "**/token")?.into_iter())
            .map(|file_path| tokio::spawn(scan_filesystem_file(file_path.clone(), external_certs.clone())))
            .collect::<Vec<_>>(),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .flatten()
    .collect::<Vec<_>>())
}

async fn scan_filesystem_file(file_path: PathBuf, external_certs: ExternalCerts) -> Result<Vec<DiscoveredCryptoObect>> {
    log::trace!("Reading file {:?}", file_path);

    let contents = read_file_to_string(&file_path).await?;

    anyhow::Ok(
        if String::from_utf8(file_path.file_name().context("non-file")?.as_bytes().to_vec())?
            .to_lowercase()
            .contains("kubeconfig")
            || String::from_utf8(file_path.file_name().context("non-file")?.as_bytes().to_vec())? == "currentconfig"
            || String::from_utf8(file_path.file_name().context("non-file")?.as_bytes().to_vec())? == "mcs-machine-config-content.json"
        {
            process_static_resource_yaml(contents, &file_path, &external_certs)
                .with_context(|| format!("processing static resource yaml of file {:?}", file_path))?
        } else {
            crypto_objects::process_unknown_value(
                contents,
                &Location::Filesystem(FileLocation {
                    path: file_path.to_string_lossy().to_string(),
                    content_location: FileContentLocation::Raw(LocationValueType::YetUnknown),
                }),
                &external_certs,
            )
            .with_context(|| format!("processing pem bundle of file {:?}", file_path))?
        },
    )
}

pub(crate) fn process_static_resource_yaml(
    contents: String,
    yaml_path: &Path,
    external_certs: &ExternalCerts,
) -> Result<Vec<DiscoveredCryptoObect>> {
    Ok(json_crawl::crawl_json((serde_yaml::from_str::<Value>(contents.as_str())?).clone())?
        .iter()
        .map(json_crawl::decode_json_value)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .map(|opt| opt.context("failed to decode yaml"))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .map(|(yaml_location, decoded_yaml_value)| {
            process_unknown_value(
                decoded_yaml_value,
                &Location::file_yaml(&yaml_path.to_string_lossy(), &yaml_location),
                external_certs,
            )
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>())
}
