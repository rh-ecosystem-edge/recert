use self::crypto_objects::DiscoveredCryptoObect;
use super::{
    crypto_objects,
    locations::{FileContentLocation, FileLocation, K8sResourceLocation, Location, LocationValueType},
};
use crate::{
    cluster_crypto::{crypto_objects::process_unknown_value, json_crawl},
    file_utils::{self, read_file_to_string},
    k8s_etcd::{get_etcd_json, InMemoryK8sEtcd},
    rules,
};
use anyhow::{bail, ensure, Context, Result};
use clio::ClioPath;
use futures_util::future::join_all;
use serde_json::Value;
use std::{
    os::unix::prelude::OsStrExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use x509_certificate::X509Certificate;

pub(crate) async fn discover_external_certs(in_memory_etcd_client: Arc<InMemoryK8sEtcd>) -> Result<()> {
    let mut pem_strings = vec![];

    for location in [
        K8sResourceLocation {
            namespace: Some("openshift-apiserver-operator".into()),
            kind: "ConfigMap".into(),
            apiversion: "v1".into(),
            name: "trusted-ca-bundle".into(),
        },
        K8sResourceLocation {
            namespace: Some("openshift-config".into()),
            kind: "ConfigMap".into(),
            apiversion: "v1".into(),
            name: "user-ca-bundle".into(),
        },
    ] {
        let json = get_etcd_json(&in_memory_etcd_client, &location)
            .await
            .context("getting trusted-ca-bundle")?;

        if let Some(json) = json {
            pem_strings.push(
                json.pointer("/data/ca-bundle.crt")
                    .context("parsing ca-bundle.crt")?
                    .as_str()
                    .context("must be string")?
                    .to_string(),
            );
        } else {
            println!("INFO: {:?} not found, will not be considered in external certs", location);
        }
    }

    let yaml = get_etcd_json(
        &in_memory_etcd_client,
        &(K8sResourceLocation {
            namespace: Some("openshift-config".into()),
            kind: "ConfigMap".into(),
            apiversion: "v1".into(),
            name: "registry-cas".into(),
        }),
    )
    .await
    .context("getting registry-cas")?;

    // registry-cas doesn't always exist
    if let Some(yaml) = yaml {
        for (_k, v) in yaml
            .pointer("/data")
            .context("parsing registry-cas")?
            .as_object()
            .context("must be object")?
        {
            pem_strings.push(v.as_str().context("must be string")?.to_string());
        }
    }

    for pem_string in pem_strings {
        let pem_bundle = pem::parse_many(pem_string).context("parsing ca-bundle.crt")?;

        for pem in pem_bundle {
            if pem.tag() != "CERTIFICATE" {
                continue;
            }

            let crt = X509Certificate::from_der(pem.contents()).context("parsing certificate from ca-bundle.crt")?;
            let cn = crt.subject_name().user_friendly_str().unwrap_or("undecodable".to_string());

            // TODO: Don't use a global for this
            rules::EXTERNAL_CERTS.write().unwrap().insert(cn.to_string());
        }
    }

    Ok(())
}

pub(crate) async fn crypto_scan(
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    static_dirs: Vec<ClioPath>,
    static_files: Vec<ClioPath>,
) -> Result<Vec<DiscoveredCryptoObect>> {
    // Launch separate paralllel long running background tasks
    let discovered_etcd_objects = tokio::spawn(async move { scan_etcd_resources(in_memory_etcd_client).await.context("etcd resources") });
    let discovered_filesystem_dir_objects = scan_static_dirs(static_dirs);
    let discovered_filesystem_file_objects = scan_static_files(static_files);

    // ... and join them
    let discovered_crypto_objects = discovered_etcd_objects.await??;
    let discovered_filesystem_dir_objects = discovered_filesystem_dir_objects.await??;
    let discovered_filesystem_file_objects = discovered_filesystem_file_objects.await??;

    // Return all objects discovered as one large vector
    Ok(discovered_crypto_objects
        .into_iter()
        .chain(discovered_filesystem_dir_objects)
        .chain(discovered_filesystem_file_objects)
        .collect::<Vec<_>>())
}

fn scan_static_dirs(static_dirs: Vec<ClioPath>) -> tokio::task::JoinHandle<std::result::Result<Vec<DiscoveredCryptoObect>, anyhow::Error>> {
    tokio::spawn(async move {
        anyhow::Ok(
            join_all(
                static_dirs
                    .into_iter()
                    .map(|static_dir| {
                        tokio::spawn(async move {
                            scan_filesystem_directory(&static_dir)
                                .await
                                .with_context(|| format!("static dir {:?}", static_dir))
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

fn scan_static_files(
    static_files: Vec<ClioPath>,
) -> tokio::task::JoinHandle<std::result::Result<Vec<DiscoveredCryptoObect>, anyhow::Error>> {
    tokio::spawn(async move {
        anyhow::Ok(
            join_all(
                static_files
                    .into_iter()
                    .map(|static_file| {
                        tokio::spawn(async move {
                            scan_filesystem_file(static_file.to_path_buf())
                                .await
                                .with_context(|| format!("static file {:?}", static_file))
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
pub(crate) async fn scan_etcd_resources(etcd_client: Arc<InMemoryK8sEtcd>) -> Result<Vec<DiscoveredCryptoObect>> {
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
                tokio::spawn(async move {
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
                                process_unknown_value(yaml_value, &Location::k8s_yaml(&k8s_resource_location, &yaml_location))
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
pub(crate) async fn scan_filesystem_directory(dir: &Path) -> Result<Vec<DiscoveredCryptoObect>> {
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
            .map(|file_path| tokio::spawn(scan_filesystem_file(file_path.clone())))
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

async fn scan_filesystem_file(file_path: PathBuf) -> Result<Vec<DiscoveredCryptoObect>> {
    let contents = read_file_to_string(file_path.to_path_buf()).await?;

    anyhow::Ok(
        if String::from_utf8(file_path.file_name().context("non-file")?.as_bytes().to_vec())?
            .to_lowercase()
            .contains("kubeconfig")
            || String::from_utf8(file_path.file_name().context("non-file")?.as_bytes().to_vec())? == "currentconfig"
            || String::from_utf8(file_path.file_name().context("non-file")?.as_bytes().to_vec())? == "mcs-machine-config-content.json"
        {
            process_static_resource_yaml(contents, &file_path)
                .with_context(|| format!("processing static resource yaml of file {:?}", file_path))?
        } else {
            crypto_objects::process_unknown_value(
                contents,
                &Location::Filesystem(FileLocation {
                    path: file_path.to_string_lossy().to_string(),
                    content_location: FileContentLocation::Raw(LocationValueType::YetUnknown),
                }),
            )
            .with_context(|| format!("processing pem bundle of file {:?}", file_path))?
        },
    )
}

pub(crate) fn process_static_resource_yaml(contents: String, yaml_path: &Path) -> Result<Vec<DiscoveredCryptoObect>> {
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
            )
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>())
}
