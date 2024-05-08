use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
};
use anyhow::{ensure, Context, Result};
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

    ensure!(
        machine_network.len() == 1,
        "machineNetwork has more than one entry, dual stack clusters are not currently supported"
    );

    machine_network.remove(0);
    machine_network.push(serde_json::Value::String(machine_config_network.to_string()));

    data.insert(
        "install-config".to_string(),
        serde_json::Value::String(serde_yaml::to_string(&install_config_value).context("serializing install-config")?),
    )
    .context("could not find original install-config")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}
