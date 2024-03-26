use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    file_utils,
    k8s_etcd::{get_etcd_json, InMemoryK8sEtcd},
};
use anyhow::{Context, Result};
use serde_json::Value;

pub(crate) fn fix_machineconfig(machineconfig: &mut Value, additional_trust_bundle: &str) -> Result<()> {
    let pointer_mut = machineconfig.pointer_mut("/spec/config/storage/files");
    if pointer_mut.is_none() {
        // Not all machineconfigs have files to look at and that's ok
        return Ok(());
    };

    let find_map = pointer_mut
        .context("no /spec/config/storage/files")?
        .as_array_mut()
        .context("files not an array")?
        .iter_mut()
        .find_map(|file| {
            (file.pointer("/path")? == "/etc/pki/ca-trust/source/anchors/openshift-config-user-ca-bundle.crt").then_some(file)
        });

    if find_map.is_none() {
        // Not all machineconfigs have the file we're looking for and that's ok
        return Ok(());
    };

    let file_contents = find_map
        .context("no /etc/kubernetes/apiserver-url.env file in machineconfig")?
        .pointer_mut("/contents")
        .context("no .contents")?
        .as_object_mut()
        .context("annotations not an object")?;

    file_contents.insert(
        "source".to_string(),
        serde_json::Value::String(file_utils::dataurl_encode(additional_trust_bundle)),
    );

    Ok(())
}

pub(crate) async fn get_merged_bundle(etcd_client: &InMemoryK8sEtcd) -> Result<String> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-config-managed"), "ConfigMap", "trusted-ca-bundle", "v1");

    let config = get_etcd_json(etcd_client, &k8s_resource_location)
        .await
        .context("failed to get trusted-ca-bundle configmap")?
        .context("could not find trusted-ca-bundle configmap")?;

    let data = config
        .pointer("/data/ca-bundle.crt")
        .context("no ca-bundle.crt in trusted-ca-bundle configmap")?
        .as_str()
        .context("ca-bundle.crt not a string")?;

    Ok(data.to_string())
}

/// There's no place where we can get just the system certificates, that don't already contain the
/// seed's additional trust bundle, so we have to derive it ourselves by taking the entire merged
/// bundle and removing from it just the certs that also appear in the seed's additional trust
/// bundle. What's left after removal should be just the seed's system certs
pub(crate) fn derive_system_certs_from_merged_bundle(original_additional_trust_bundle: String, merged_bundle: String) -> Result<String> {
    let last_original_cert = pem::parse_many(original_additional_trust_bundle.as_bytes())
        .context("failed to parse original additional trust bundle")?
        .into_iter()
        .last()
        .context("no certs in original additional trust bundle")?;

    let last_original_cert_encoded =
        pem::encode_config(&last_original_cert, pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF)).to_string();
    let position_of_last_original_cert = merged_bundle
        .find(&last_original_cert_encoded)
        .context("last original cert not found in merged bundle")?;

    let system_certs = merged_bundle
        .get(position_of_last_original_cert + last_original_cert_encoded.len()..)
        .context("failed to get system certs")?;

    Ok(system_certs.to_string())
}

pub(crate) fn merge_bundles(additional_trust_bundle: &str, system_certs: &str) -> String {
    format!("{}{}", additional_trust_bundle, system_certs)
}
