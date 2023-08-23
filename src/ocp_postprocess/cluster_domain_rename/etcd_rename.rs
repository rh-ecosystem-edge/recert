use super::{
    rename_utils::fix_api_server_arguments, rename_utils::fix_apiserver_url_file, rename_utils::fix_kcm_extended_args,
    rename_utils::fix_kcm_pod, rename_utils::fix_kubeconfig, rename_utils::fix_oauth_metadata, rename_utils::fix_pod,
};
use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    k8s_etcd::{get_etcd_yaml, put_etcd_yaml, InMemoryK8sEtcd},
};
use anyhow::{bail, Context, Result};
use futures_util::future::join_all;
use serde_json::Value;
use std::{io::BufRead, sync::Arc};

/// Some resources can just be deleted and they'll be reconciled fast enough, no need for
/// any adjustments.
pub(crate) async fn delete_resources(etcd_client: &Arc<InMemoryK8sEtcd>) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("controllerrevisions/")
            .await?
            .into_iter()
            .filter(|key| {
                vec![
                    "openshift-machine-config-operator/machine-config-server-",
                    "openshift-monitoring/alertmanager-main-",
                    "openshift-monitoring/prometheus-k8s-",
                    "openshift-multus/multus-additional-cni-plugins-",
                    "openshift-multus/multus-",
                    "openshift-ovn-kubernetes/ovnkube-node-",
                ]
                .into_iter()
                .any(|prefix| key.contains(prefix))
            })
            .chain(
                etcd_client
                    .list_keys("controlplane.operator.openshift.io/podnetworkconnectivitychecks/")
                    .await?
                    .into_iter(),
            )
            .chain(etcd_client.list_keys("apiserver.openshift.io/apirequestcounts/").await?.into_iter())
            .map(|key| async move {
                etcd_client.delete(&key).await.context(format!("deleting {}", key))?;
                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_router_certs(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    cluster_domain: &str,
    k8s_resource_location: K8sResourceLocation,
) -> Result<()> {
    let mut secret = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let data = &mut secret
        .pointer_mut("/data")
        .context("no /data")?
        .as_object_mut()
        .context("data not an object")?;
    let (existing_apps_domain_key, existing_apps_domain_value) = data
        .into_iter()
        .filter(|(k, _v)| k.starts_with("apps."))
        .map(|(k, v)| (k.clone(), v.clone()))
        .next()
        .context("no apps.* key")?
        .clone();
    data.insert(format!("apps.{}", cluster_domain), existing_apps_domain_value);
    data.remove(&existing_apps_domain_key);

    let metadata = &mut secret
        .pointer_mut("/metadata")
        .context("no /metadata")?
        .as_object_mut()
        .context("data not an object")?;

    let managed_fields = metadata
        .get_mut("managedFields")
        .context("no managedFields")?
        .as_array_mut()
        .context("managedFields not an array")?;

    managed_fields.iter_mut().try_for_each(|mf| {
        let managed_data = mf
            .pointer_mut("/fieldsV1/f:data")
            .context("no /fieldsV1/f:data")?
            .as_object_mut()
            .context("data not an object")?;

        let (existing_apps_domain_key, existing_apps_domain_value) = managed_data
            .into_iter()
            .filter(|(k, _v)| k.starts_with("f:apps."))
            .map(|(k, v)| (k.clone(), v.clone()))
            .next()
            .context("no apps.* key")?
            .clone();

        managed_data.insert(format!("f:apps.{}", cluster_domain), existing_apps_domain_value);
        managed_data.remove(&existing_apps_domain_key);

        anyhow::Ok(())
    })?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, secret).await?;
    Ok(())
}

pub(crate) async fn fix_loadbalancer_serving_certkey(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    cluster_domain: &str,
    prefix: &str,
    name: &str,
) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-kube-apiserver"), "Secret", name, "v1");
    let mut secret = get_etcd_yaml(etcd_client, &k8s_resource_location)
        .await
        .context(format!("getting {} from etcd", name))?;
    secret
        .pointer_mut("/metadata/annotations")
        .context("no /metadata/annotations")?
        .as_object_mut()
        .context("annotations not an object")?
        .insert(
            "auth.openshift.io/certificate-hostnames".to_string(),
            serde_json::Value::String(format!("{}.{}", prefix, cluster_domain)),
        )
        .context("could not find original annotation")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, secret).await?;
    Ok(())
}

pub(crate) async fn fix_machineconfigs(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("machineconfiguration.openshift.io/machineconfigs")
            .await?
            .into_iter()
            .map(|key| async move {
                let etcd_result = etcd_client
                    .get(key.clone())
                    .await
                    .with_context(|| format!("getting key {:?}", key))?;
                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;
                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut machineconfig = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;

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
                    .find_map(|file| (file.pointer("/path")? == "/etc/kubernetes/apiserver-url.env").then_some(file));

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

                let original_data = file_contents["source"].as_str().context("source not a string")?;

                let (decoded, _fragment) = data_url::DataUrl::process(original_data)
                    .ok()
                    .context("dataurl processing")?
                    .decode_to_vec()
                    .ok()
                    .context("dataurl decoding")?;

                let new = fix_apiserver_url_file(decoded, cluster_domain)?;

                let mut url = dataurl::DataUrl::new();
                url.set_data(new.as_bytes());
                file_contents.insert("source".to_string(), serde_json::Value::String(url.to_string()));

                put_etcd_yaml(etcd_client, &k8s_resource_location, machineconfig).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_apiserver_config(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-apiserver"), "Configmap", "config", "v1");
    let mut configmap = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let data = &mut configmap
        .pointer_mut("/data")
        .context("no /data")?
        .as_object_mut()
        .context("data not an object")?;

    let mut config: Value = serde_yaml::from_slice(data["config.yaml"].as_str().context("config.yaml not a string")?.as_bytes())
        .context("deserializing config.yaml")?;

    config
        .pointer_mut("/routingConfig")
        .context("routingConfig not found")?
        .as_object_mut()
        .context("routingConfig not an object")?
        .insert(
            "subdomain".to_string(),
            serde_json::Value::String(format!("apps.{}", cluster_domain)),
        )
        .context("missing subdomain")?;

    // NOTE: If we ever stop using a fake internal IP, we need to change .storageConfig.urls[0] to be the new IP here

    data.insert(
        "config.yaml".to_string(),
        serde_json::Value::String(serde_json::to_string(&config).context("serializing config.yaml")?),
    )
    .context("could not find original config.yaml")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}

pub(crate) async fn fix_authentication_config(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location =
        K8sResourceLocation::new(Some("openshift-authentication"), "Configmap", "v4-0-config-system-cliconfig", "v1");
    let mut configmap = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let data = &mut configmap
        .pointer_mut("/data")
        .context("no /data")?
        .as_object_mut()
        .context("data not an object")?;

    let mut config: Value = serde_yaml::from_slice(
        data["v4-0-config-system-cliconfig"]
            .as_str()
            .context("v4-0-config-system-cliconfig not a string")?
            .as_bytes(),
    )
    .context("deserializing v4-0-config-system-cliconfig")?;

    let oauth_config = &mut config
        .pointer_mut("/oauthConfig")
        .context("oauthConfig not found")?
        .as_object_mut()
        .context("oauthConfig not an object")?;

    oauth_config
        .insert(
            "assetPublicURL".to_string(),
            serde_json::Value::String(format!("https://console-openshift-console.apps.{cluster_domain}")),
        )
        .context("missing assetPublicURL")?;

    oauth_config
        .insert(
            "loginURL".to_string(),
            serde_json::Value::String(format!("https://api.{cluster_domain}:6443")),
        )
        .context("missing loginURL")?;

    oauth_config
        .insert(
            "masterPublicURL".to_string(),
            serde_json::Value::String(format!("https://oauth-openshift.apps.{cluster_domain}")),
        )
        .context("missing masterPublicURL")?;

    let serving_info = &mut config
        .pointer_mut("/servingInfo")
        .context("servingInfo not found")?
        .as_object_mut()
        .context("servingInfo not an object")?;

    serving_info
        .insert(
            "namedCertificates".to_string(),
            serde_json::Value::Array(vec![serde_json::json!({
                "certFile": format!("/var/config/system/secrets/v4-0-config-system-router-certs/apps.{cluster_domain}"),
                "keyFile": format!("/var/config/system/secrets/v4-0-config-system-router-certs/apps.{cluster_domain}"),
                "names": vec![format!("*.apps.{}", cluster_domain)],
            })]),
        )
        .context("missing namedCertificates")?;

    data.insert(
        "v4-0-config-system-cliconfig".to_string(),
        serde_json::Value::String(serde_json::to_string(&config).context("v4-0-config-system-cliconfig")?),
    )
    .context("could not find original v4-0-config-system-cliconfig")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}

pub(crate) async fn fix_authentication_system_metadata(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    cluster_domain: &str,
    k8s_resource_location: K8sResourceLocation,
) -> Result<()> {
    let mut configmap = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;

    let data = &mut configmap.pointer_mut("/data").context("no /data")?;

    let mut config: Value = serde_yaml::from_slice(
        data.pointer_mut("/oauthMetadata")
            .context("no /oauthMetadata")?
            .as_str()
            .context("oauthMeatadata not a string")?
            .as_bytes(),
    )
    .context("deserializing oauthMeatadata")?;

    let oauth_metadata = &mut config.pointer_mut("").context("no root")?;

    fix_oauth_metadata(oauth_metadata, cluster_domain)?;

    data.as_object_mut()
        .context("data not an object")?
        .insert(
            "oauthMetadata".to_string(),
            serde_json::Value::String(serde_json::to_string(&config).context("serializing config.yaml")?),
        )
        .context("could not find original oauthMetadata")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}

pub(crate) async fn fix_monitoring_config(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-config-managed"), "Configmap", "monitoring-shared-config", "v1");
    let mut configmap = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let data = &mut configmap
        .pointer_mut("/data")
        .context("no /data")?
        .as_object_mut()
        .context("data not an object")?;

    data.insert(
        "alertmanagerPublicURL".to_string(),
        serde_json::Value::String(format!("https://alertmanager-main-openshift-monitoring.apps.{cluster_domain}")),
    )
    .context("could not find original alertmanagerPublicURL")?;

    data.insert(
        "alertmanagerTenancyHost".to_string(),
        serde_json::Value::String("alertmanager-main.openshift-monitoring.svc:9092".to_string()),
    )
    .context("could not find original alertmanagerTenancyHost")?;

    data.insert(
        "alertmanagerUserWorkloadHost".to_string(),
        serde_json::Value::String("alertmanager-main.openshift-monitoring.svc:9094".to_string()),
    )
    .context("could not find original alertmanagerUserWorkloadHost")?;

    data.insert(
        "prometheusPublicURL".to_string(),
        serde_json::Value::String(format!("https://prometheus-k8s-openshift-monitoring.apps.{cluster_domain}")),
    )
    .context("could not find original prometheusPublicURL")?;

    data.insert(
        "thanosPublicURL".to_string(),
        serde_json::Value::String(format!("https://thanos-querier-openshift-monitoring.apps.{cluster_domain}")),
    )
    .context("could not find original thanosPublicURL")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}

pub(crate) async fn fix_console_config(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-console"), "Configmap", "console-config", "v1");
    let mut configmap = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let data = &mut configmap
        .pointer_mut("/data")
        .context("no /data")?
        .as_object_mut()
        .context("data not an object")?;

    let mut config: Value = serde_yaml::from_slice(
        data["console-config.yaml"]
            .as_str()
            .context("console-config.yaml not a string")?
            .as_bytes(),
    )
    .context("deserializing console-config.yaml")?;

    let cluster_info = &mut config
        .pointer_mut("/clusterInfo")
        .context("no clusterInfo")?
        .as_object_mut()
        .context("configmap not an object")?;

    cluster_info
        .insert(
            "consoleBaseAddress".to_string(),
            serde_json::Value::String(format!("https://console-openshift-console.apps.{cluster_domain}")),
        )
        .context("missing consoleBaseAddress")?;

    cluster_info
        .insert(
            "masterPublicURL".to_string(),
            serde_json::Value::String(format!("https://api.{cluster_domain}:6443")),
        )
        .context("missing masterPublicURL")?;

    data.insert(
        "console-config.yaml".to_string(),
        serde_json::Value::String(serde_yaml::to_string(&config).context("serializing console-config.yaml")?),
    )
    .context("could not find original console-config.yaml")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}

pub(crate) async fn fix_console_public_config(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-config-managed"), "Configmap", "console-public", "v1");
    let mut configmap = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let data = &mut configmap
        .pointer_mut("/data")
        .context("no /data")?
        .as_object_mut()
        .context("data not an object")?;

    data.insert(
        "consoleURL".to_string(),
        serde_json::Value::String(format!("https://console-openshift-console.apps.{cluster_domain}")),
    )
    .context("could not find original consoleURL")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}

pub(crate) async fn fix_console_cluster_config(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "Console", "cluster", "config.openshift.io");
    let mut config = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let status = &mut config
        .pointer_mut("/status")
        .context("no /status")?
        .as_object_mut()
        .context("status not an object")?;

    status
        .insert(
            "consoleURL".to_string(),
            serde_json::Value::String(format!("https://console-openshift-console.apps.{cluster_domain}")),
        )
        .context("could not find original consoleURL")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, config).await?;

    Ok(())
}

pub(crate) async fn fix_dns_cluster_config(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "Dns", "cluster", "config.openshift.io");
    let mut config = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let spec = &mut config
        .pointer_mut("/spec")
        .context("no /spec")?
        .as_object_mut()
        .context("spec not an object")?;

    spec.insert("baseDomain".to_string(), serde_json::Value::String(cluster_domain.to_string()))
        .context("could not find original baseDomain")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, config).await?;

    Ok(())
}

pub(crate) async fn fix_console_cli_downloads(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "ConsoleCLIDownload", "oc-cli-downloads", "console.openshift.io");
    let mut consoleclidownload = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let spec = &mut consoleclidownload
        .pointer_mut("/spec")
        .context("no /spec")?
        .as_object_mut()
        .context("spec not an object")?;

    let new_links = spec
        .get("links")
        .context("no links")?
        .as_array()
        .context("links not an array")?
        .iter()
        .map(|link| {
            let link = &mut link.as_object().context("link not an object")?;
            let mut new_link = link.clone();

            // Change the hostname of the href URL
            let mut url =
                url::Url::parse(link.get("href").context("no href")?.as_str().context("href not a string")?).context("parsing href")?;
            url.set_host(Some(&format!("downloads-openshift-console.apps.{}", cluster_domain)))
                .context("setting host")?;

            new_link.insert("href".to_string(), serde_json::Value::String(url.to_string()));

            Ok(serde_json::Value::Object(new_link))
        })
        .collect::<Result<Vec<_>>>()
        .context("iterating over links")?;

    spec.insert("links".to_string(), serde_json::Value::Array(new_links))
        .context("could not find original links")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, consoleclidownload).await?;

    Ok(())
}

pub(crate) async fn fix_ingresses_cluster_config(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "Ingress", "cluster", "config.openshift.io");
    let mut config = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let spec = &mut config
        .pointer_mut("/spec")
        .context("no /spec")?
        .as_object_mut()
        .context("spec not an object")?;

    spec.insert("domain".to_string(), serde_json::Value::String(format!("apps.{cluster_domain}")))
        .context("could not find original domain")?;

    let status_component_routes = &mut config
        .pointer_mut("/status/componentRoutes")
        .context("no /status/componentRoutes")?
        .as_array_mut()
        .context("componentRoutes not an object")?;

    let oauth_component_route = status_component_routes
        .iter_mut()
        .find_map(|route| (route.get("name")? == "oauth-openshift").then_some(route))
        .context("could not find oauth-openshift route")?;

    let route_object = &mut oauth_component_route
        .as_object_mut()
        .context("oauth-openshift route not an object")?;

    route_object.insert(
        "currentHostnames".to_string(),
        serde_json::Value::Array(vec![serde_json::Value::String(format!("oauth-openshift.apps.{cluster_domain}"))]),
    );

    route_object.insert(
        "defaultHostname".to_string(),
        serde_json::Value::String(format!("oauth-openshift.apps.{cluster_domain}")),
    );

    put_etcd_yaml(etcd_client, &k8s_resource_location, config).await?;

    Ok(())
}

pub(crate) async fn fix_infrastructure_cluster_config(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    cluster_domain: &str,
    infra_id: &str,
) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "Infrastructure", "cluster", "config.openshift.io");
    let mut config = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let status = &mut config
        .pointer_mut("/status")
        .context("no /status")?
        .as_object_mut()
        .context("status not an object")?;

    status
        .insert(
            "apiServerInternalURI".to_string(),
            serde_json::Value::String(format!("https://api-int.{cluster_domain}:6443")),
        )
        .context("could not find original apiServerInternalURI")?;

    status
        .insert(
            "apiServerURL".to_string(),
            serde_json::Value::String(format!("https://api.{cluster_domain}:6443")),
        )
        .context("could not find original apiServerURL")?;

    status
        .insert("infrastructureName".to_string(), serde_json::Value::String(infra_id.to_string()))
        .context("could not find original baseDomain")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, config).await?;

    Ok(())
}

pub(crate) async fn fix_kube_apiserver_configs(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("configmaps/openshift-kube-apiserver/config")
            .await?
            .into_iter()
            .map(|key| async move {
                let etcd_result = etcd_client
                    .get(key.clone())
                    .await
                    .with_context(|| format!("getting key {:?}", key))?;
                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;
                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut configmap = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;

                let data = &mut configmap
                    .pointer_mut("/data")
                    .context("no /data")?
                    .as_object_mut()
                    .context("data not an object")?;

                let mut config: Value =
                    serde_yaml::from_slice(data["config.yaml"].as_str().context("config.yaml not a string")?.as_bytes())
                        .context("deserializing config.yaml")?;

                fix_api_server_arguments(&mut config, cluster_domain)?;

                data.insert(
                    "config.yaml".to_string(),
                    serde_json::Value::String(serde_json::to_string(&config).context("serializing config.yaml")?),
                )
                .context("could not find original config.yaml")?;

                put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_oauth_metadata_configmap(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("configmaps/openshift-kube-apiserver/oauth-metadata")
            .await?
            .into_iter()
            .map(|key| async move {
                let etcd_result = etcd_client
                    .get(key.clone())
                    .await
                    .with_context(|| format!("getting key {:?}", key))?;
                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;
                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                fix_authentication_system_metadata(etcd_client, cluster_domain, k8s_resource_location).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_kcm_config(etcd_client: &Arc<InMemoryK8sEtcd>, infra_id: &str) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("configmaps/openshift-kube-controller-manager/config")
            .await?
            .into_iter()
            .map(|key| async move {
                let etcd_result = etcd_client
                    .get(key.clone())
                    .await
                    .with_context(|| format!("getting key {:?}", key))?;
                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;
                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut configmap = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;

                let data = &mut configmap
                    .pointer_mut("/data")
                    .context("no /data")?
                    .as_object_mut()
                    .context("data not an object")?;

                let mut config: Value =
                    serde_yaml::from_slice(data["config.yaml"].as_str().context("config.yaml not a string")?.as_bytes())
                        .context("deserializing config.yaml")?;

                fix_kcm_extended_args(&mut config, infra_id)?;

                data.insert(
                    "config.yaml".to_string(),
                    serde_json::Value::String(serde_json::to_string(&config).context("serializing config.yaml")?),
                )
                .context("could not find original config.yaml")?;

                put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_kcm_kubeconfig(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("configmaps/openshift-kube-controller-manager/controller-manager-kubeconfig")
            .await?
            .into_iter()
            .chain(
                etcd_client
                    .list_keys("configmaps/openshift-kube-scheduler/scheduler-kubeconfig")
                    .await?
                    .into_iter(),
            )
            .map(|key| async move {
                let etcd_result = etcd_client
                    .get(key.clone())
                    .await
                    .with_context(|| format!("getting key {:?}", key))?;
                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;
                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut configmap = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;

                let data = &mut configmap
                    .pointer_mut("/data")
                    .context("no /data")?
                    .as_object_mut()
                    .context("data not an object")?;

                let mut config: Value = serde_yaml::from_slice(data["kubeconfig"].as_str().context("kubeconfig not a string")?.as_bytes())
                    .context("deserializing kubeconfig")?;

                fix_kubeconfig(cluster_domain, &mut config).await?;

                data.insert(
                    "kubeconfig".to_string(),
                    serde_json::Value::String(serde_yaml::to_string(&config).context("serializing kubeconfig")?),
                )
                .context("could not find original kubeconfig")?;

                put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_ovnkube_config(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-ovn-kubernetes"), "Configmap", "ovnkube-config", "v1");
    let mut configmap = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;

    let data = &mut configmap.pointer_mut("/data").context("no /data")?;

    let config = data
        .pointer_mut("/ovnkube.conf")
        .context("ovnkube.conf not found")?
        .as_str()
        .context("ovnkube.conf not a string")?
        .to_string()
        .bytes()
        .collect::<Vec<_>>();

    let mut found = false;

    let new = config
        .lines()
        .collect::<Result<Vec<_>, _>>()
        .context("parsing ovnkube.conf into lines")?
        .into_iter()
        .map(|line| {
            if line.starts_with("apiserver=\"https://api-int.") {
                found = true;
                format!("apiserver=\"https://api-int.{}:6443\"", cluster_domain)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    if !found {
        bail!("could not find line starting with apiserver=\"https://api-int. in ovnkube.conf");
    }

    data.as_object_mut()
        .context("data not an object")?
        .insert("ovnkube.conf".to_string(), serde_json::Value::String(new))
        .context("could not find original ovnkube.conf")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}

pub(crate) async fn fix_install_config(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    cluster_name: &str,
    cluster_base_domain: &str,
    k8s_resource_location: K8sResourceLocation,
) -> Result<()> {
    let mut configmap = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;

    let data = &mut configmap
        .pointer_mut("/data")
        .context("no /data")?
        .as_object_mut()
        .context("data not an object")?;

    let install_config_bytes = data["install-config"].as_str().context("install-config not a string")?.to_string();

    let mut install_config_value: Value =
        serde_yaml::from_slice(install_config_bytes.as_bytes()).context("deserializing install-config")?;

    let install_config = &mut install_config_value
        .pointer_mut("")
        .context("no root")?
        .as_object_mut()
        .context("configmap not an object")?;

    install_config
        .insert("baseDomain".to_string(), serde_json::Value::String(cluster_base_domain.to_string()))
        .context("missing baseDomain")?;

    let metadata = &mut install_config_value
        .pointer_mut("/metadata")
        .context("metadata not found")?
        .as_object_mut()
        .context("metadata not an object")?;

    metadata
        .insert("name".to_string(), serde_json::Value::String(cluster_name.to_string()))
        .context("missing name")?;

    data.insert(
        "install-config".to_string(),
        serde_json::Value::String(serde_yaml::to_string(&install_config_value).context("serializing install-config")?),
    )
    .context("could not find original install-config")?;

    // TODO: We should probably keep the old one around but then it confuses scripts
    // which scan for no leftover old cluster name in the manifests
    // data.insert(
    //     "install-config-proto-cluster".to_string(),
    //     serde_json::Value::String(install_config_bytes.to_string()),
    // );

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}

pub(crate) async fn fix_kcm_pods(etcd_client: &Arc<InMemoryK8sEtcd>, generated_infra_id: &str) -> Result<()> {
    join_all(
        etcd_client
            .list_keys("configmaps/openshift-kube-controller-manager/kube-controller-manager-pod")
            .await?
            .into_iter()
            .map(|key| async move {
                let etcd_result = etcd_client
                    .get(key.clone())
                    .await
                    .with_context(|| format!("getting key {:?}", key))?;
                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;
                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut configmap = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;

                let data = &mut configmap.pointer_mut("/data").context("no /data")?;

                let mut pod: Value = serde_yaml::from_slice(
                    data.pointer("/pod.yaml")
                        .context("pod.yaml not found")?
                        .as_str()
                        .context("pod.yaml not a string")?
                        .as_bytes(),
                )
                .context("deserializing pod.yaml")?;

                fix_kcm_pod(&mut pod, generated_infra_id).context("fixing kcm pod")?;

                data.as_object_mut()
                    .context("data not an object")?
                    .insert(
                        "pod.yaml".to_string(),
                        serde_json::Value::String(serde_json::to_string(&pod).context("serializing pod.yaml")?),
                    )
                    .context("could not find original pod.yaml")?;

                put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_cvo_deployment(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(
        Some("openshift-cluster-version"),
        "Deployment",
        "cluster-version-operator",
        "apps/v1",
    );
    let mut deployment = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let pod = &mut deployment.pointer_mut("/spec/template").context("no /spec/template")?;
    fix_pod(
        pod,
        format!("api-int.{cluster_domain}").as_str(),
        "cluster-version-operator",
        "KUBERNETES_SERVICE_HOST",
    )
    .context("fixing pod")?;
    put_etcd_yaml(etcd_client, &k8s_resource_location, deployment).await?;

    Ok(())
}

pub(crate) async fn fix_multus_daemonsets(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-multus"), "DaemonSet", "multus", "apps/v1");
    let mut daemonset = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let pod = &mut daemonset.pointer_mut("/spec/template").context("no /spec/template")?;
    fix_pod(
        pod,
        format!("api-int.{cluster_domain}").as_str(),
        "kube-multus",
        "KUBERNETES_SERVICE_HOST",
    )
    .context("fixing pod")?;
    put_etcd_yaml(etcd_client, &k8s_resource_location, daemonset).await?;

    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-multus"), "DaemonSet", "multus-additional-cni-plugins", "apps/v1");
    let mut daemonset = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let pod = &mut daemonset.pointer_mut("/spec/template").context("no /spec/template")?;
    fix_pod(
        pod,
        format!("api-int.{cluster_domain}").as_str(),
        "whereabouts-cni",
        "KUBERNETES_SERVICE_HOST",
    )
    .context("fixing pod")?;
    put_etcd_yaml(etcd_client, &k8s_resource_location, daemonset).await?;

    Ok(())
}

pub(crate) async fn fix_ovn_daemonset(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-ovn-kubernetes"), "DaemonSet", "ovnkube-node", "apps/v1");
    let mut daemonset = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let pod = &mut daemonset.pointer_mut("/spec/template").context("no /spec/template")?;
    fix_pod(
        pod,
        format!("api-int.{cluster_domain}").as_str(),
        "ovnkube-node",
        "KUBERNETES_SERVICE_HOST",
    )
    .context("fixing pod")?;
    put_etcd_yaml(etcd_client, &k8s_resource_location, daemonset).await?;

    Ok(())
}

pub(crate) async fn fix_router_default(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-ingress"), "Deployment", "router-default", "apps/v1");
    let mut deployment = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let pod = &mut deployment.pointer_mut("/spec/template").context("no /spec/template")?;
    fix_pod(
        pod,
        format!("router-default.apps.{cluster_domain}").as_str(),
        "router",
        "ROUTER_CANONICAL_HOSTNAME",
    )
    .context("fixing pod")?;
    fix_pod(pod, format!("apps.{cluster_domain}").as_str(), "router", "ROUTER_DOMAIN").context("fixing pod")?;
    put_etcd_yaml(etcd_client, &k8s_resource_location, deployment).await?;

    Ok(())
}

pub(crate) async fn fix_routes(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    fix_route(
        etcd_client,
        K8sResourceLocation::new(Some("openshift-ingress-canary"), "Route", "canary", "route.openshift.io/v1"),
        format!("canary-openshift-ingress-canary.apps.{cluster_domain}"),
    )
    .await?;

    fix_route(
        etcd_client,
        K8sResourceLocation::new(Some("openshift-monitoring"), "Route", "alertmanager-main", "route.openshift.io/v1"),
        format!("alertmanager-main-openshift-monitoring.apps.{cluster_domain}"),
    )
    .await?;

    fix_route(
        etcd_client,
        K8sResourceLocation::new(Some("openshift-monitoring"), "Route", "prometheus-k8s", "route.openshift.io/v1"),
        format!("prometheus-k8s-openshift-monitoring.apps.{cluster_domain}"),
    )
    .await?;

    fix_route(
        etcd_client,
        K8sResourceLocation::new(
            Some("openshift-monitoring"),
            "Route",
            "prometheus-k8s-federate",
            "route.openshift.io/v1",
        ),
        format!("prometheus-k8s-federate-openshift-monitoring.apps.{cluster_domain}"),
    )
    .await?;

    fix_route(
        etcd_client,
        K8sResourceLocation::new(Some("openshift-monitoring"), "Route", "thanos-querier", "route.openshift.io/v1"),
        format!("thanos-querier-openshift-monitoring.apps.{cluster_domain}"),
    )
    .await?;

    Ok(())
}

async fn fix_route(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    k8s_resource_location: K8sResourceLocation,
    new_host: String,
) -> Result<(), anyhow::Error> {
    let mut route = get_etcd_yaml(etcd_client, &k8s_resource_location).await?;
    let spec = &mut route
        .pointer_mut("/spec")
        .context("no /spec")?
        .as_object_mut()
        .context("spec is not an object")?;
    spec.insert("host".to_string(), serde_json::Value::String(new_host))
        .context("missing host")?;
    route.as_object_mut().context("route is not an object")?.remove("status");
    put_etcd_yaml(etcd_client, &k8s_resource_location, route).await?;
    Ok(())
}
