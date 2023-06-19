use self::crypto_objects::DiscoveredCryptoObect;
use super::{
    crypto_objects,
    locations::{FileContentLocation, FileLocation, K8sResourceLocation, Location, LocationValueType},
};
use crate::{
    cluster_crypto::{crypto_objects::process_yaml_value, yaml_crawl},
    file_utils::{self, read_file_to_string},
    k8s_etcd::InMemoryK8sEtcd,
};
use anyhow::{Context, Result};
use futures_util::future::join_all;
use serde_json::Value;
use std::{
    os::unix::prelude::OsStrExt,
    path::{Path, PathBuf},
    sync::Arc,
};

pub(crate) async fn crypto_scan(
    in_memory_etcd_client: Arc<InMemoryK8sEtcd>,
    static_dirs: Vec<PathBuf>,
    kubeconfig: Option<PathBuf>,
) -> Result<Vec<DiscoveredCryptoObect>> {
    let discovered_etcd_objects = tokio::spawn(async move { scan_etcd_resources(in_memory_etcd_client).await.context("etcd resources") });
    let discovered_filesystem_objects = scan_static_dirs(static_dirs);
    let discovered_crypto_objects = discovered_etcd_objects.await??;
    let discovered_filesystem_objects = discovered_filesystem_objects.await??;

    // If we have a kubeconfig, we can also process that
    let kubeconfig_crypto_objects = if let Some(kubeconfig_path) = kubeconfig {
        scan_kubeconfig(kubeconfig_path).await?
    } else {
        vec![]
    };

    Ok(discovered_crypto_objects
        .into_iter()
        .chain(discovered_filesystem_objects)
        .chain(kubeconfig_crypto_objects)
        .collect::<Vec<_>>())
}

async fn scan_kubeconfig(kubeconfig_path: PathBuf) -> Result<Vec<DiscoveredCryptoObect>, anyhow::Error> {
    Ok(process_static_resource_yaml(
        read_file_to_string(kubeconfig_path.clone())
            .await
            .with_context(|| format!("reading kubeconfig {:?}", kubeconfig_path))?,
        &kubeconfig_path,
    )?)
}

fn scan_static_dirs(static_dirs: Vec<PathBuf>) -> tokio::task::JoinHandle<std::result::Result<Vec<DiscoveredCryptoObect>, anyhow::Error>> {
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
                .list_keys("apiregistration.k8s.io/apiservices")
                .await
                .context("listing apiservices")?),
            &(etcd_client
                .list_keys("machineconfiguration.openshift.io/machineconfigs")
                .await
                .context("listing machineconfigs")?),
        ]
    };

    let all_keys = key_lists.into_iter().flatten();

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
                        .with_context(|| format!("getting key {:?}", key))?;
                    let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                        .with_context(|| format!("deserializing value of key {:?}", key,))?;
                    let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                    // Ensure our as_etcd_key function knows to generates the correct key, while we
                    // still have the key to compare to. TODO: Find a more robust way to generate
                    // etcd keys, kubernetes is doing it weirdly which is why as_etcd_key is so
                    // complicated. Couldn't find documentation on how it should be done properly
                    assert_eq!(etcd_result.key, k8s_resource_location.as_etcd_key());

                    let decoded_yaml_values = yaml_crawl::crawl_yaml(value)
                        .with_context(|| format!("crawling yaml of key {:?}", key))?
                        .iter()
                        .map(|yaml| yaml_crawl::decode_yaml_value(yaml).context("decoding yaml"))
                        .collect::<Result<Vec<_>>>()?;

                    anyhow::Ok(
                        decoded_yaml_values
                            .into_iter()
                            .flatten()
                            .map(|(yaml_location, yaml_value)| {
                                process_yaml_value(yaml_value, &Location::k8s_yaml(&k8s_resource_location, &yaml_location))
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
            .chain(file_utils::globvec(dir, "**/*.crt")?.into_iter())
            .chain(file_utils::globvec(dir, "**/*.key")?.into_iter())
            .chain(file_utils::globvec(dir, "**/*.pub")?.into_iter())
            // Also scan for the .mcdorig versions of the above files, which are sometimes created
            // by machine-config-daemon
            .chain(file_utils::globvec(dir, "**/*.crt.mcdorig")?.into_iter())
            .chain(file_utils::globvec(dir, "**/*.key.mcdorig")?.into_iter())
            .chain(file_utils::globvec(dir, "**/*.pub.mcdorig")?.into_iter())
            .map(|file_path| {
                tokio::spawn(async move {
                    let contents = read_file_to_string(file_path.clone()).await?;

                    anyhow::Ok(
                        if String::from_utf8(file_path.file_name().context("non-file")?.as_bytes().to_vec())?.ends_with("kubeconfig")
                            || String::from_utf8(file_path.file_name().context("non-file")?.as_bytes().to_vec())? == "currentconfig"
                        {
                            process_static_resource_yaml(contents, &file_path)?
                        } else {
                            crypto_objects::process_pem_bundle(
                                &contents,
                                &Location::Filesystem(FileLocation {
                                    path: file_path.to_string_lossy().to_string(),
                                    content_location: FileContentLocation::Raw(LocationValueType::Unknown),
                                }),
                            )?
                        },
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

pub(crate) fn process_static_resource_yaml(contents: String, yaml_path: &PathBuf) -> Result<Vec<DiscoveredCryptoObect>> {
    Ok(
        yaml_crawl::crawl_yaml((&serde_yaml::from_str::<Value>(contents.as_str())?).clone())?
            .iter()
            .map(yaml_crawl::decode_yaml_value)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|opt| opt.context("failed to decode yaml"))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|(yaml_location, decoded_yaml_value)| {
                process_yaml_value(
                    decoded_yaml_value,
                    &Location::file_yaml(&yaml_path.to_string_lossy().to_string(), &yaml_location),
                )
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>(),
    )
}
