use super::{args::Proxy, utils::fix_machineconfig};
use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
};
use anyhow::{Context, Result};
use futures_util::future::join_all;
use serde_json::Value;
use std::sync::Arc;

pub(crate) async fn fix_machineconfigs(etcd_client: &Arc<InMemoryK8sEtcd>, proxy: &Proxy) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("machineconfiguration.openshift.io/machineconfigs")
            .await?
            .into_iter()
            .map(|key| async move {
                let etcd_result = etcd_client
                    .get(key.clone())
                    .await
                    .with_context(|| format!("getting key {:?}", key))?
                    .context("key disappeared")?;
                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;
                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut machineconfig = get_etcd_json(etcd_client, &k8s_resource_location)
                    .await?
                    .context("no machineconfig")?;

                fix_machineconfig(&mut machineconfig, proxy).context("fixing machineconfig")?;

                put_etcd_yaml(etcd_client, &k8s_resource_location, machineconfig).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_proxy(etcd_client: &InMemoryK8sEtcd, proxy: &Proxy) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("config.openshift.io/proxies/cluster")
            .await?
            .into_iter()
            .map(|key| async move {
                let etcd_result = etcd_client
                    .get(key.clone())
                    .await
                    .with_context(|| format!("getting key {:?}", key))?
                    .context("key disappeared")?;

                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;

                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut cluster_proxy = get_etcd_json(etcd_client, &k8s_resource_location).await?.context("no proxy")?;

                let spec = cluster_proxy
                    .pointer_mut("/spec")
                    .context("no /spec")?
                    .as_object_mut()
                    .context("spec not an object")?;

                spec.insert("httpProxy".to_string(), Value::String(proxy.spec_proxy.http_proxy.clone()));
                spec.insert("httpsProxy".to_string(), Value::String(proxy.spec_proxy.https_proxy.clone()));
                spec.insert("noProxy".to_string(), Value::String(proxy.spec_proxy.no_proxy.clone()));

                let status = cluster_proxy
                    .pointer_mut("/status")
                    .context("no /status")?
                    .as_object_mut()
                    .context("status not an object")?;

                status.insert("httpProxy".to_string(), Value::String(proxy.status_proxy.http_proxy.clone()));
                status.insert("httpsProxy".to_string(), Value::String(proxy.status_proxy.https_proxy.clone()));
                status.insert("noProxy".to_string(), Value::String(proxy.status_proxy.no_proxy.clone()));

                put_etcd_yaml(etcd_client, &k8s_resource_location, cluster_proxy).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_controllerconfigs(etcd_client: &InMemoryK8sEtcd, proxy: &Proxy) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("machineconfiguration.openshift.io/controllerconfigs/machine-config-controller")
            .await?
            .into_iter()
            .map(|key| async move {
                let etcd_result = etcd_client
                    .get(key.clone())
                    .await
                    .with_context(|| format!("getting key {:?}", key))?
                    .context("key disappeared")?;

                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;

                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut cluster_proxy = get_etcd_json(etcd_client, &k8s_resource_location)
                    .await?
                    .context("no controllerconfig")?;

                let object_mut = cluster_proxy.pointer_mut("/spec/proxy").context("no /spec/proxy")?.as_object_mut();

                match object_mut {
                    None => {
                        // This is simply null when the proxy is not set
                        return Ok(());
                    }
                    Some(spec_proxy) => {
                        spec_proxy.insert("httpProxy".to_string(), Value::String(proxy.status_proxy.http_proxy.clone()));
                        spec_proxy.insert("httpsProxy".to_string(), Value::String(proxy.status_proxy.https_proxy.clone()));
                        spec_proxy.insert("noProxy".to_string(), Value::String(proxy.status_proxy.no_proxy.clone()));

                        put_etcd_yaml(etcd_client, &k8s_resource_location, cluster_proxy).await?;
                    }
                }

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_containers(etcd_client: &InMemoryK8sEtcd, proxy: &Proxy) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("deployments/")
            .await?
            .into_iter()
            .chain(etcd_client.list_keys("statefulsets/").await?.into_iter())
            .chain(etcd_client.list_keys("daemonsets/").await?.into_iter())
            .chain(etcd_client.list_keys("jobs/").await?.into_iter())
            .chain(etcd_client.list_keys("cronjobs/").await?.into_iter())
            .chain(etcd_client.list_keys("monitoring.coreos.com/alertmanagers/").await?.into_iter())
            .chain(etcd_client.list_keys("monitoring.coreos.com/prometheuses/").await?.into_iter())
            .chain(etcd_client.list_keys("controllerrevisions/").await?.into_iter())
            .map(|key| async move {
                let etcd_result = etcd_client
                    .get(key.clone())
                    .await
                    .with_context(|| format!("getting key {:?}", key))?
                    .context("key disappeared")?;

                let value: Value = serde_json::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;

                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut workload = get_etcd_json(etcd_client, &k8s_resource_location)
                    .await?
                    .context(format!("no workload for {:?}", k8s_resource_location.as_etcd_key()))?;

                let kind = &workload.pointer("/kind");

                let kind = match kind {
                    Some(kind) => kind,
                    None => return Ok(()),
                }
                .as_str()
                .context("kind not a string")?;

                let prefix = match kind {
                    "Deployment" | "DaemonSet" | "StatefulSet" | "Job" | "CronJob" | "ControllerRevision" => "/spec/template/spec",
                    "Pod" | "Alertmanager" | "Prometheus" => "/spec",
                    _ => return Ok(()),
                };

                if kind != "ControllerRevision" {
                    super::utils::fix_containers(&mut workload, proxy, prefix).context("fixing containers")?;
                } else {
                    // ControllerRevision has a special format, it has a field called data, which
                    // is a JSON array of numbers, which represent bytes. We need to convert this
                    // array of numbers to a string, then parse it as JSON, then fix the containers
                    // in the JSON, then convert it back to a string, then convert it back to a JSON
                    // array of numbers, then put it back in the ControllerRevision.
                    let workload_data = workload
                        .pointer_mut("/data")
                        .context("no /data")?
                        .as_object_mut()
                        .context("data not an object")?;

                    let data_string = &String::from_utf8(
                        workload_data
                            .get("raw")
                            .context("no data")?
                            .as_array()
                            .context("data not an array")?
                            .iter()
                            .map(|v| v.as_u64().context("fieldsV1 not a number"))
                            .collect::<Result<Vec<_>>>()
                            .context("parsing byte array")?
                            .into_iter()
                            .map(|v| v as u8)
                            .collect::<Vec<_>>(),
                    )
                    .context("data not utf8")?;

                    let mut data_json = serde_json::from_str(data_string).context("parsing data")?;

                    super::utils::fix_containers(&mut data_json, proxy, prefix).context("fixing containers")?;

                    workload_data.insert(
                        "raw".to_string(),
                        serde_json::to_string(&data_json)
                            .context("serializing data")?
                            .bytes()
                            .map(|b| Value::Number(b.into()))
                            .collect(),
                    );
                };

                put_etcd_yaml(etcd_client, &k8s_resource_location, workload).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_storages(etcd_client: &InMemoryK8sEtcd, proxy: &Proxy) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "Storage", "cluster", "operator.openshift.io/v1");

    let mut storage = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context(format!("no {:?}", k8s_resource_location.as_etcd_key()))?;

    let spec = storage
        .pointer_mut("/spec/observedConfig/targetconfig/proxy")
        .context("no proxy")?
        .as_object_mut()
        .context("proxy not an object")?;

    generic_proxy_fix(spec, proxy);

    put_etcd_yaml(etcd_client, &k8s_resource_location, storage).await?;

    Ok(())
}

fn generic_proxy_fix(spec: &mut serde_json::Map<String, Value>, proxy: &Proxy) {
    spec.insert("HTTPS_PROXY".to_string(), Value::String(proxy.status_proxy.http_proxy.clone()));
    spec.insert("HTTP_PROXY".to_string(), Value::String(proxy.status_proxy.https_proxy.clone()));
    spec.insert("NO_PROXY".to_string(), Value::String(proxy.status_proxy.no_proxy.clone()));
}

pub(crate) async fn fix_openshiftapiserver(etcd_client: &InMemoryK8sEtcd, proxy: &Proxy) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "OpenShiftAPIServer", "cluster", "operator.openshift.io/v1");

    let mut cluster_proxy = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context(format!("no {:?}", k8s_resource_location.as_etcd_key()))?;

    let spec = cluster_proxy
        .pointer_mut("/spec/observedConfig/workloadcontroller/proxy")
        .context("no proxy")?
        .as_object_mut()
        .context("proxy not an object")?;

    generic_proxy_fix(spec, proxy);

    put_etcd_yaml(etcd_client, &k8s_resource_location, cluster_proxy).await?;

    Ok(())
}

pub(crate) async fn fix_kubeapiserver(etcd_client: &InMemoryK8sEtcd, proxy: &Proxy) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "KubeAPIServer", "cluster", "operator.openshift.io/v1");

    let mut cluster_proxy = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("no kubeapiserver")?;

    let spec = cluster_proxy
        .pointer_mut("/spec/observedConfig/targetconfigcontroller/proxy")
        .context("no proxy")?
        .as_object_mut()
        .context("proxy not an object")?;

    generic_proxy_fix(spec, proxy);

    put_etcd_yaml(etcd_client, &k8s_resource_location, cluster_proxy).await?;

    Ok(())
}

pub(crate) async fn fix_kubecontrollermanager(etcd_client: &InMemoryK8sEtcd, proxy: &Proxy) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "KubeControllerManager", "cluster", "operator.openshift.io/v1");

    let mut cluster_proxy = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("no kubecontrollermanager")?;

    let spec = cluster_proxy
        .pointer_mut("/spec/observedConfig/targetconfigcontroller/proxy")
        .context("no proxy")?
        .as_object_mut()
        .context("proxy not an object")?;

    generic_proxy_fix(spec, proxy);

    put_etcd_yaml(etcd_client, &k8s_resource_location, cluster_proxy).await?;

    Ok(())
}

pub(crate) async fn fix_configmap_pods(etcd_client: &InMemoryK8sEtcd, proxy: &Proxy) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("configmaps/openshift-kube-apiserver/kube-apiserver-pod")
            .await?
            .into_iter()
            .chain(
                etcd_client
                    .list_keys("configmaps/openshift-kube-controller-manager/kube-controller-manager-pod")
                    .await?
                    .into_iter(),
            )
            .map(|key| async move {
                let etcd_result = etcd_client
                    .get(key.clone())
                    .await
                    .with_context(|| format!("getting key {:?}", key))?
                    .context("key disappeared")?;

                let value: Value = serde_json::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;

                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location).await?.context("no configmap")?;

                let data = configmap
                    .pointer_mut("/data")
                    .context("no /data")?
                    .as_object_mut()
                    .context("data not an object")?;

                let pod_json = data
                    .get("pod.yaml")
                    .context("no pod.yaml")?
                    .as_str()
                    .context("pod.yaml not a string")?;

                let mut pod = serde_json::from_str(pod_json).context("parsing pod.yaml")?;

                super::utils::fix_containers(&mut pod, proxy, "/spec").context("fixing containers")?;

                data.insert(
                    "pod.yaml".to_string(),
                    Value::String(serde_json::to_string(&pod).context("serializing pod")?),
                );

                put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}
