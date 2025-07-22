use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
};
use anyhow::{Context, Result};
use serde_json::Value;

pub(crate) async fn fix_configmap(
    etcd_client: &InMemoryK8sEtcd,
    machine_config_network: &str,
    k8s_resource_location: K8sResourceLocation,
) -> Result<()> {
    let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("could not find configmap")?;

    let data = &mut configmap
        .pointer_mut("/data")
        .context("no /data")?
        .as_object_mut()
        .context("data not an object")?;

    let install_config_bytes = data["install-config"].as_str().context("install-config not a string")?.to_string();

    let mut install_config_value: Value =
        serde_yaml::from_slice(install_config_bytes.as_bytes()).context("deserializing install-config")?;

    let machine_network = &mut install_config_value
        .pointer_mut("/networking/machineNetwork")
        .context("no machineNetwork")?
        .as_array_mut()
        .context("machineNetwork not an array")?;

    // For dual stack clusters, preserve all existing entries and just replace them with new network
    // If machine_config_network contains commas, split into multiple networks for dual stack
    let new_networks: Vec<_> = machine_config_network
        .split(',')
        .map(|cidr| serde_json::json!({"cidr": cidr.trim()}))
        .collect();

    machine_network.clear();
    machine_network.extend(new_networks);

    data.insert(
        "install-config".to_string(),
        serde_json::Value::String(serde_yaml::to_string(&install_config_value).context("serializing install-config")?),
    )
    .context("could not find original install-config")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}
