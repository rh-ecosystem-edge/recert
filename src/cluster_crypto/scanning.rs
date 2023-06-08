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
) -> Vec<DiscoveredCryptoObect> {
    let discovered_etcd_objects = tokio::spawn(async move { scan_etcd_resources(in_memory_etcd_client).await });

    let discovered_filesystem_objects = tokio::spawn(async move {
        join_all(
            static_dirs
                .into_iter()
                .map(|static_dir| {
                    tokio::spawn(async move {
                        scan_filesystem_directory(&static_dir).await
                    })
                })
                .collect::<Vec<_>>(),
        )
        .await
        .into_iter()
        .flatten()
        .flatten()
        .collect::<Vec<_>>()
    });

    let discovered_crypto_objects = discovered_etcd_objects.await.unwrap();
    let discovered_filesystem_objects = discovered_filesystem_objects.await.unwrap();

    // If we have a kubeconfig, we can also process that
    let kubeconfig_crypto_objects = if let Some(kubeconfig_path) = kubeconfig {
        process_static_resource_yaml(read_file_to_string(kubeconfig_path.clone()).await, &kubeconfig_path)
    } else {
        vec![]
    };

    discovered_crypto_objects
        .into_iter()
        .chain(discovered_filesystem_objects)
        .chain(kubeconfig_crypto_objects)
        .collect::<Vec<_>>()
}

/// Read all relevant resources from etcd, scan them for cryptographic objects and record them
/// in the appropriate data structures.
pub(crate) async fn scan_etcd_resources(etcd_client: Arc<InMemoryK8sEtcd>) -> Vec<DiscoveredCryptoObect> {
    let key_lists = {
        let etcd_client = &etcd_client;
        [
            &(etcd_client.list_keys("secrets").await),
            &(etcd_client.list_keys("configmaps").await),
            &(etcd_client.list_keys("validatingwebhookconfigurations").await),
            &(etcd_client.list_keys("apiregistration.k8s.io/apiservices").await),
            &(etcd_client.list_keys("machineconfiguration.openshift.io/machineconfigs").await),
        ]
    };

    let all_keys = key_lists.into_iter().flatten();

    join_all(
        all_keys
            .into_iter()
            .map(|key| {
                let key = key.clone();
                let etcd_client = Arc::clone(&etcd_client);
                tokio::spawn(async move {
                    let etcd_result = etcd_client.get(key).await;
                    let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice()).expect("failed to parse yaml");
                    let k8s_resource_location = K8sResourceLocation::from(&value);

                    // Ensure our as_etcd_key function knows to generates the expected key, while we still
                    // have the key. TODO: Find a more robust way to generate etcd keys, kubernetes is
                    // doing it weirdly which is why as_etcd_key is so complicated. Couldn't find
                    // documentation on how it should be done properly
                    assert_eq!(etcd_result.key, k8s_resource_location.as_etcd_key());

                    let decoded_yaml_values = yaml_crawl::crawl_yaml(value)
                        .iter()
                        .map(yaml_crawl::decode_yaml_value)
                        .collect::<Vec<_>>();

                    decoded_yaml_values
                        .into_iter()
                        .flatten()
                        .map(|(yaml_location, yaml_value)| {
                            process_yaml_value(yaml_value, &Location::k8s_yaml(&k8s_resource_location, &yaml_location))
                        })
                        .flatten()
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>(),
    )
    .await
    .into_iter()
    .flatten()
    .flatten()
    .collect::<Vec<DiscoveredCryptoObect>>()
}

/// Recursively scans a directoy for files which exclusively contain a PEM bundle (as opposed
/// to being embedded in a YAML file) and records them in the appropriate data structures.
pub(crate) async fn scan_filesystem_directory(dir: &Path) -> Vec<DiscoveredCryptoObect> {
    join_all(
        file_utils::globvec(dir, "**/*.pem")
            .into_iter()
            .chain(file_utils::globvec(dir, "**/*.crt").into_iter())
            .chain(file_utils::globvec(dir, "**/*.key").into_iter())
            .chain(file_utils::globvec(dir, "**/*.pub").into_iter())
            // Also scan for the .mcdorig versions of the above files, which are sometimes created
            // by machine-config-daemon
            .chain(file_utils::globvec(dir, "**/*.crt.mcdorig").into_iter())
            .chain(file_utils::globvec(dir, "**/*.key.mcdorig").into_iter())
            .chain(file_utils::globvec(dir, "**/*.pub.mcdorig").into_iter())
            .map(|file_path| {
                tokio::spawn(async move {
                    let contents = read_file_to_string(file_path.clone()).await;

                    if String::from_utf8_lossy(file_path.file_name().unwrap().as_bytes()).ends_with("kubeconfig")
                        || String::from_utf8_lossy(file_path.file_name().unwrap().as_bytes()) == "currentconfig"
                    {
                        process_static_resource_yaml(contents, &file_path)
                    } else {
                        crypto_objects::process_pem_bundle(
                            &contents,
                            &Location::Filesystem(FileLocation {
                                path: file_path.to_string_lossy().to_string(),
                                content_location: FileContentLocation::Raw(LocationValueType::Unknown),
                            }),
                        )
                    }
                })
            })
            .collect::<Vec<_>>(),
    )
    .await
    .into_iter()
    .flatten()
    .flatten()
    .collect::<Vec<DiscoveredCryptoObect>>()
}

pub(crate) fn process_static_resource_yaml(contents: String, yaml_path: &PathBuf) -> Vec<DiscoveredCryptoObect> {
    yaml_crawl::crawl_yaml((&serde_yaml::from_str::<Value>(contents.as_str()).ok().unwrap()).clone())
        .iter()
        .map(yaml_crawl::decode_yaml_value)
        .map(|result| result.unwrap())
        .map(|(yaml_location, decoded_yaml_value)| {
            process_yaml_value(
                decoded_yaml_value,
                &Location::file_yaml(&yaml_path.to_string_lossy().to_string(), &yaml_location),
            )
        })
        .flatten()
        .collect::<Vec<_>>()
}
