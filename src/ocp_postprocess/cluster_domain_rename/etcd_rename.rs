use super::rename_utils::{
    self, fix_api_server_arguments, fix_kcm_extended_args, fix_kcm_pod, fix_machineconfig, fix_oauth_metadata, fix_pod_container_env,
};
use crate::{
    cluster_crypto::locations::K8sResourceLocation,
    k8s_etcd::{get_etcd_json, put_etcd_yaml, InMemoryK8sEtcd},
};
use anyhow::{bail, ensure, Context, Result};
use fn_error_context::context;
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
            .chain(
                etcd_client
                    .list_keys("configmaps/openshift-kube-controller-manager/cluster-policy-controller-lock")
                    .await?
                    .into_iter(),
            )
            .chain(etcd_client.list_keys("apiserver.openshift.io/apirequestcounts/").await?.into_iter())
            .chain(
                etcd_client
                    .list_keys("operator.openshift.io/ingresscontrollers/openshift-ingress-operator/default")
                    .await?
                    .into_iter(),
            )
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
    let mut secret = get_etcd_json(etcd_client, &k8s_resource_location).await?.context("no secret")?;
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

    managed_fields.iter_mut().try_for_each(|managed_field| {
        let fields_v1_raw_byte_array = managed_field
            .pointer("/fieldsV1/raw")
            .context("no /fieldsV1/raw")?
            .as_array()
            .context("/fieldsV1/raw not an array")?;

        let mut fields_v1_raw_parsed: Value = serde_json::from_str(
            &String::from_utf8(
                fields_v1_raw_byte_array
                    .iter()
                    .map(|v| v.as_u64().context("fieldsV1 not a number"))
                    .collect::<Result<Vec<_>>>()
                    .context("parsing byte array")?
                    .into_iter()
                    .map(|v| v as u8)
                    .collect::<Vec<_>>(),
            )
            .context("fieldsV1 not valid utf8")?,
        )
        .context("deserializing fieldsV1")?;

        let fields_data = fields_v1_raw_parsed
            .pointer_mut("/f:data")
            .context("no /f:data")?
            .as_object_mut()
            .context("data not an object")?;

        let (existing_apps_domain_key, existing_apps_domain_value) = fields_data
            .into_iter()
            .filter(|(k, _v)| k.starts_with("f:apps."))
            .map(|(k, v)| (k.clone(), v.clone()))
            .next()
            .context("no apps.* key")?
            .clone();

        fields_data.insert(format!("f:apps.{}", cluster_domain), existing_apps_domain_value);
        fields_data.remove(&existing_apps_domain_key);

        let serialized = serde_json::Value::String(serde_json::to_string(&fields_v1_raw_parsed).context("serializing fieldsV1")?);

        let byte_array = serde_json::Value::Array(
            serialized
                .as_str()
                .context("serialized not a string")?
                .as_bytes()
                .iter()
                .map(|b| serde_json::Value::Number(serde_json::Number::from(*b)))
                .collect(),
        );

        managed_field
            .pointer_mut("/fieldsV1")
            .context("no /fieldsV1")?
            .as_object_mut()
            .context("/fieldsV1 not an object")?
            .insert("raw".to_string(), byte_array);

        anyhow::Ok(())
    })?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, secret).await?;
    Ok(())
}

pub(crate) async fn fix_oauth_client(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    cluster_domain: &str,
    k8s_resource_location: K8sResourceLocation,
) -> Result<()> {
    let mut oauth_client = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context(format!("{} not found", k8s_resource_location.as_etcd_key()))?;

    let existing_uris = &mut oauth_client
        .pointer_mut("/redirectUrIs")
        .context("no /redirectUrIs")?
        .as_array_mut()
        .context("data not an object")?;

    ensure!(
        existing_uris.len() == 1,
        "expected exactly one redirectURI, found {}",
        existing_uris.len()
    );

    let existing_uri_value = &existing_uris.remove(0);
    let existing_uri = existing_uri_value.as_str().context("redirectURI not a string")?;

    ensure!(
        existing_uri.starts_with("https://oauth-openshift.apps."),
        "expected redirectURI to start with https://oauth-openshift.apps., found {}",
        existing_uri
    );

    let existing_uri_path = url::Url::parse(existing_uri)?.path().to_string();
    let existing_uri_path = existing_uri_path.trim_start_matches('/');
    let new_uri = format!("https://oauth-openshift.apps.{cluster_domain}/{existing_uri_path}");
    existing_uris.push(serde_json::Value::String(new_uri.clone()));

    let metadata = &mut oauth_client
        .pointer_mut("/metadata")
        .context("no /metadata")?
        .as_object_mut()
        .context("data not an object")?;

    let managed_fields = metadata
        .get_mut("managedFields")
        .context("no managedFields")?
        .as_array_mut()
        .context("managedFields not an array")?;

    managed_fields.iter_mut().try_for_each(|managed_field| {
        let fields_v1_raw_byte_array = managed_field
            .pointer("/fieldsV1/raw")
            .context("no /fieldsV1/raw")?
            .as_array()
            .context("/fieldsV1/raw not an array")?;

        let mut fields_v1_raw_parsed: Value = serde_json::from_str(
            &String::from_utf8(
                fields_v1_raw_byte_array
                    .iter()
                    .map(|v| v.as_u64().context("fieldsV1 not a number"))
                    .collect::<Result<Vec<_>>>()
                    .context("parsing byte array")?
                    .into_iter()
                    .map(|v| v as u8)
                    .collect::<Vec<_>>(),
            )
            .context("fieldsV1 not valid utf8")?,
        )
        .context("deserializing fieldsV1")?;

        let fields_redirect_uris = fields_v1_raw_parsed
            .pointer_mut("/f:redirectURIs")
            .context("no /f:redirectURIs")?
            .as_object_mut()
            .context("redirectURIs not an object")?;

        fields_redirect_uris
            .remove(&(format!("v:\"{}\"", existing_uri)))
            .context("could not find original managed field")?;

        fields_redirect_uris.insert(format!("v:\"{}\"", &new_uri), serde_json::Value::Object(serde_json::Map::new()));

        let serialized = serde_json::Value::String(serde_json::to_string(&fields_v1_raw_parsed).context("serializing fieldsV1")?);

        let byte_array = serde_json::Value::Array(
            serialized
                .as_str()
                .context("serialized not a string")?
                .as_bytes()
                .iter()
                .map(|b| serde_json::Value::Number(serde_json::Number::from(*b)))
                .collect(),
        );

        managed_field
            .pointer_mut("/fieldsV1")
            .context("no /fieldsV1")?
            .as_object_mut()
            .context("/fieldsV1 not an object")?
            .insert("raw".to_string(), byte_array);

        anyhow::Ok(())
    })?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, oauth_client).await?;
    Ok(())
}

pub(crate) async fn fix_loadbalancer_serving_certkey(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    cluster_domain: &str,
    prefix: &str,
    name: &str,
) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-kube-apiserver"), "Secret", name, "v1");
    let mut secret = get_etcd_json(etcd_client, &k8s_resource_location)
        .await
        .context(format!("getting {} from etcd", name))?
        .context("no secret")?;
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
                    .with_context(|| format!("getting key {:?}", key))?
                    .context("key disappeared")?;
                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;
                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut machineconfig = get_etcd_json(etcd_client, &k8s_resource_location)
                    .await?
                    .context("no machineconfig")?;

                fix_machineconfig(&mut machineconfig, cluster_domain).context("fixing machineconfig")?;

                put_etcd_yaml(etcd_client, &k8s_resource_location, machineconfig).await?;

                Ok(())
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;

    Ok(())
}

pub(crate) async fn fix_openshift_apiserver_configmap(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-apiserver"), "Configmap", "config", "v1");
    let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("getting configmap")?;
    let data = &mut configmap
        .pointer_mut("/data")
        .context("no /data")?
        .as_object_mut()
        .context("data not an object")?;

    let mut config: Value = serde_yaml::from_slice(data["config.yaml"].as_str().context("config.yaml not a string")?.as_bytes())
        .context("deserializing config.yaml")?;

    fix_openshift_apiserver_config(&mut config, cluster_domain).context("fixing config")?;

    data.insert(
        "config.yaml".to_string(),
        serde_json::Value::String(serde_json::to_string(&config).context("serializing config.yaml")?),
    )
    .context("could not find original config.yaml")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}

pub(crate) async fn fix_openshift_apiserver_openshiftapiserver(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "OpenShiftAPIServer", "cluster", "operator.openshift.io/v1");

    let mut openshiftapiserver = get_etcd_json(etcd_client, &k8s_resource_location)
        .await
        .context("getting openshiftapiserver")?
        .context(format!("{} not found", k8s_resource_location.as_etcd_key()))?;

    let config = &mut openshiftapiserver
        .pointer_mut("/spec/observedConfig")
        .context("no /spec/observedConfig")?;

    fix_openshift_apiserver_config(config, cluster_domain).context("fixing config")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, openshiftapiserver).await?;

    Ok(())
}

pub(crate) async fn fix_kube_apiserver_kubeapiserver(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "KubeAPIServer", "cluster", "operator.openshift.io/v1");

    let mut kubeapiserver = get_etcd_json(etcd_client, &k8s_resource_location)
        .await
        .context("getting kubeapiserver")?
        .context(format!("{} not found", k8s_resource_location.as_etcd_key()))?;

    let config = &mut kubeapiserver
        .pointer_mut("/spec/observedConfig")
        .context("no /spec/observedConfig")?;

    fix_api_server_arguments(config, cluster_domain).context("fixing config")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, kubeapiserver).await?;

    Ok(())
}

pub(crate) async fn fix_kubecontrollermanager(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "KubeControllerManager", "cluster", "operator.openshift.io/v1");

    let mut kubecontrollermanager = get_etcd_json(etcd_client, &k8s_resource_location)
        .await
        .context("getting kubecontrollermanager")?
        .context(format!("{} not found", k8s_resource_location.as_etcd_key()))?;

    let config = &mut kubecontrollermanager
        .pointer_mut("/spec/observedConfig")
        .context("no /spec/observedConfig")?;

    fix_kcm_extended_args(config, cluster_domain).context("fixing config")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, kubecontrollermanager).await?;

    Ok(())
}

pub(crate) async fn fix_authentication(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "Authentication", "cluster", "operator.openshift.io/v1");

    let mut authentication = get_etcd_json(etcd_client, &k8s_resource_location)
        .await
        .context("getting authentication")?
        .context(format!("{} not found", k8s_resource_location.as_etcd_key()))?;

    let config = &mut authentication
        .pointer_mut("/spec/observedConfig/oauthServer")
        .context("no /spec/observedConfig/oauthServer")?;

    fix_oauth_server_authentication_config(config, cluster_domain).context("fixing config")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, authentication).await?;

    Ok(())
}

pub(crate) fn fix_openshift_apiserver_config(config: &mut Value, cluster_domain: &str) -> Result<()> {
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

    // TODO: If we ever stop using a fake internal IP, we need to change .storageConfig.urls[0] to be the new IP here

    Ok(())
}

pub(crate) async fn fix_authentication_config(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location =
        K8sResourceLocation::new(Some("openshift-authentication"), "Configmap", "v4-0-config-system-cliconfig", "v1");
    let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location).await?.context("no configmap")?;
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

    fix_oauth_server_authentication_config(&mut config, cluster_domain)?;

    data.insert(
        "v4-0-config-system-cliconfig".to_string(),
        serde_json::Value::String(serde_json::to_string(&config).context("v4-0-config-system-cliconfig")?),
    )
    .context("could not find original v4-0-config-system-cliconfig")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}

fn fix_oauth_server_authentication_config(config: &mut Value, cluster_domain: &str) -> Result<()> {
    let oauth_config = &mut config
        .pointer_mut("/oauthConfig")
        .context("oauthConfig not found")?
        .as_object_mut()
        .context("oauthConfig not an object")?;

    oauth_config
        .insert(
            "loginURL".to_string(),
            serde_json::Value::String(format!("https://api.{cluster_domain}:6443")),
        )
        .context("missing loginURL")?;

    // Don't simply insert as sometimes this is empty (when console is disabled) and we don't want
    // to introduce it
    if let Some(asset_public_url) = oauth_config.get("assetPublicURL") {
        if asset_public_url
            .as_str()
            .context("assetPublicURL not a string")?
            .starts_with("https://console-openshift-console.apps.")
        {
            oauth_config
                .insert(
                    "assetPublicURL".to_string(),
                    serde_json::Value::String(format!("https://console-openshift-console.apps.{cluster_domain}")),
                )
                .context("missing assetPublicURL")?;
        }
    }

    // The operator.openshift.io/v1 Authentication resource observedConfig doesn't have this key
    if oauth_config.get("masterPublicURL").is_some() {
        oauth_config
            .insert(
                "masterPublicURL".to_string(),
                serde_json::Value::String(format!("https://oauth-openshift.apps.{cluster_domain}")),
            )
            .context("missing masterPublicURL")?;
    }

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
    Ok(())
}

pub(crate) async fn fix_authentication_system_metadata(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    cluster_domain: &str,
    k8s_resource_location: K8sResourceLocation,
) -> Result<()> {
    let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location).await?.context("no configmap")?;

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
            serde_json::Value::String(serde_json::to_string_pretty(&config).context("serializing config.yaml")?),
        )
        .context("could not find original oauthMetadata")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;

    Ok(())
}

pub(crate) async fn fix_monitoring_config(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-config-managed"), "Configmap", "monitoring-shared-config", "v1");
    let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("could not find monitoring-shared-config")?;
    let data = &mut configmap
        .pointer_mut("/data")
        .context("no /data")?
        .as_object_mut()
        .context("data not an object")?;

    if data.contains_key("alertmanagerPublicURL") {
        data.insert(
            "alertmanagerPublicURL".to_string(),
            serde_json::Value::String(format!("https://alertmanager-main-openshift-monitoring.apps.{cluster_domain}")),
        )
        .context("could not find original alertmanagerPublicURL")?;
    }

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
    let configmap = get_etcd_json(etcd_client, &k8s_resource_location).await?;

    if let Some(mut configmap) = configmap {
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
    }

    Ok(())
}

pub(crate) async fn fix_console_public_config(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-config-managed"), "Configmap", "console-public", "v1");

    // Some clusters have console disabled, and the entire configmap is missing, not just the
    // consoleURL key
    if let Some(mut configmap) = get_etcd_json(etcd_client, &k8s_resource_location).await? {
        let data = &mut configmap.pointer_mut("/data");

        if let Some(data) = data {
            let data = data.as_object_mut().context("data not an object")?;

            // Some clusters have console disabled, so there's nothing to replace
            if data.contains_key("consoleURL") {
                data.insert(
                    "consoleURL".to_string(),
                    serde_json::Value::String(format!("https://console-openshift-console.apps.{cluster_domain}")),
                )
                .context("could not find original consoleURL")?;

                put_etcd_yaml(etcd_client, &k8s_resource_location, configmap).await?;
            }
        }
    }

    Ok(())
}

pub(crate) async fn fix_console_cluster_config(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "Console", "cluster", "config.openshift.io");
    let mut config = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("could not find console cluster config")?;

    let status_value = config.pointer_mut("/status");

    if let Some(status) = status_value {
        let status_object = &mut status.as_object_mut().context("status not an object")?;

        status_object
            .insert(
                "consoleURL".to_string(),
                serde_json::Value::String(format!("https://console-openshift-console.apps.{cluster_domain}")),
            )
            .context("could not find original consoleURL")?;

        put_etcd_yaml(etcd_client, &k8s_resource_location, config).await?;
    }

    Ok(())
}

pub(crate) async fn fix_dns_cluster_config(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "Dns", "cluster", "config.openshift.io");
    let mut config = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("could not find dns cluster config")?;

    fix_dns(&mut config, cluster_domain)?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, config).await?;

    Ok(())
}

fn fix_dns(config: &mut Value, cluster_domain: &str) -> Result<(), anyhow::Error> {
    let spec = &mut config
        .pointer_mut("/spec")
        .context("no /spec")?
        .as_object_mut()
        .context("spec not an object")?;
    spec.insert("baseDomain".to_string(), serde_json::Value::String(cluster_domain.to_string()))
        .context("could not find original baseDomain")?;
    Ok(())
}

pub(crate) async fn fix_console_cli_downloads(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "ConsoleCLIDownload", "oc-cli-downloads", "console.openshift.io");
    let consoleclidownload = get_etcd_json(etcd_client, &k8s_resource_location).await?;

    if let Some(mut consoleclidownload) = consoleclidownload {
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
    }

    Ok(())
}

pub(crate) async fn fix_ingresses_cluster_config(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(None, "Ingress", "cluster", "config.openshift.io");
    let mut config = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("could not find ingress cluster config")?;
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
    let mut config = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("could not find infrastructure cluster config")?;

    fix_infra(&mut config, infra_id, cluster_domain)?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, config).await?;

    Ok(())
}

fn fix_infra(config: &mut Value, infra_id: &str, cluster_domain: &str) -> Result<(), anyhow::Error> {
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
                    .with_context(|| format!("getting key {:?}", key))?
                    .context("key disappeared")?;
                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;
                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location)
                    .await?
                    .context("could not find configmap")?;

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
                    .with_context(|| format!("getting key {:?}", key))?
                    .context("key disappeared")?;
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
                    .with_context(|| format!("getting key {:?}", key))?
                    .context("key disappeared")?;
                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;
                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location)
                    .await?
                    .context("could not find configmap")?;

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

pub(crate) async fn fix_kcm_kubeconfig(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str, _cluster_name: &str) -> Result<()> {
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
                    .with_context(|| format!("getting key {:?}", key))?
                    .context("key disappeared")?;
                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;
                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location)
                    .await?
                    .context("could not find configmap")?;

                let data = &mut configmap
                    .pointer_mut("/data")
                    .context("no /data")?
                    .as_object_mut()
                    .context("data not an object")?;

                let kubeconfig = data["kubeconfig"].as_str().context("kubeconfig not a string")?;

                // We can't use this until https://github.com/openshift/cluster-kube-scheduler-operator/pull/523 is fixed
                // fix_kubeconfig(_cluster_name, cluster_domain, &mut config)
                //     .await
                //     .context(format!("fixing kubeconfig for {:?}", k8s_resource_location))?;

                // Do it manually for now
                let kubeconfig = regex::Regex::new(r"(?P<prefix>server: https://api-int)\.(?P<cluster_domain>.+):(?P<port>\d+)")
                    .context("compiling regex")?
                    .replace_all(kubeconfig, format!("$prefix.{cluster_domain}:$port").as_str());

                data.insert(
                    "kubeconfig".to_string(),
                    serde_json::Value::String(serde_yaml::to_string(&kubeconfig).context("serializing kubeconfig")?),
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
    let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("could not find configmap")?;

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
                    .with_context(|| format!("getting key {:?}", key))?
                    .context("key disappeared")?;
                let value: Value = serde_yaml::from_slice(etcd_result.value.as_slice())
                    .with_context(|| format!("deserializing value of key {:?}", key,))?;
                let k8s_resource_location = K8sResourceLocation::try_from(&value)?;

                let mut configmap = get_etcd_json(etcd_client, &k8s_resource_location)
                    .await?
                    .context("could not find configmap")?;

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

                // Note that there's a newline at the end, without it we get a rollout that we wish to avoid
                data.as_object_mut()
                    .context("data not an object")?
                    .insert(
                        "pod.yaml".to_string(),
                        serde_json::Value::String(format!("{}\n", serde_json::to_string(&pod).context("serializing pod.yaml")?)),
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
    let mut deployment = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("could not find deployment")?;
    let pod = &mut deployment.pointer_mut("/spec/template").context("no /spec/template")?;
    fix_pod_container_env(
        pod,
        format!("api-int.{cluster_domain}").as_str(),
        "cluster-version-operator",
        "KUBERNETES_SERVICE_HOST",
        false,
    )
    .context("fixing pod")?;
    put_etcd_yaml(etcd_client, &k8s_resource_location, deployment).await?;

    Ok(())
}

pub(crate) async fn fix_multus_daemonsets(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-multus"), "DaemonSet", "multus", "apps/v1");
    let mut daemonset = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("could not find daemonset")?;
    let pod = &mut daemonset.pointer_mut("/spec/template").context("no /spec/template")?;
    fix_pod_container_env(
        pod,
        format!("api-int.{cluster_domain}").as_str(),
        "kube-multus",
        "KUBERNETES_SERVICE_HOST",
        false,
    )
    .context("fixing pod")?;
    put_etcd_yaml(etcd_client, &k8s_resource_location, daemonset).await?;

    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-multus"), "DaemonSet", "multus-additional-cni-plugins", "apps/v1");
    let mut daemonset = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("could not find daemonset")?;
    let pod = &mut daemonset.pointer_mut("/spec/template").context("no /spec/template")?;
    fix_pod_container_env(
        pod,
        format!("api-int.{cluster_domain}").as_str(),
        "whereabouts-cni",
        "KUBERNETES_SERVICE_HOST",
        true,
    )
    .context("fixing pod")?;
    put_etcd_yaml(etcd_client, &k8s_resource_location, daemonset).await?;

    Ok(())
}

pub(crate) async fn fix_router_default(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(Some("openshift-ingress"), "Deployment", "router-default", "apps/v1");
    let mut deployment = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("could not find deployment")?;
    let pod = &mut deployment.pointer_mut("/spec/template").context("no /spec/template")?;
    fix_pod_container_env(
        pod,
        format!("router-default.apps.{cluster_domain}").as_str(),
        "router",
        "ROUTER_CANONICAL_HOSTNAME",
        false,
    )
    .context("fixing pod")?;
    fix_pod_container_env(pod, format!("apps.{cluster_domain}").as_str(), "router", "ROUTER_DOMAIN", false).context("fixing pod")?;
    put_etcd_yaml(etcd_client, &k8s_resource_location, deployment).await?;

    Ok(())
}

pub(crate) async fn fix_controller_config(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    generated_infra_id: &str,
    cluster_domain: &str,
) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(
        None,
        "ControllerConfig",
        "machine-config-controller",
        "machineconfiguration.openshift.io/v1",
    );

    let mut controller_config = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("could not find controller config")?;

    let dns = &mut controller_config.pointer_mut("/spec/dns").context("no /spec/dns")?;
    fix_dns(dns, cluster_domain).context("fixing dns")?;

    let infra = &mut controller_config.pointer_mut("/spec/infra").context("no /spec/infra")?;
    fix_infra(infra, generated_infra_id, cluster_domain).context("fixing infra")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, controller_config).await?;

    Ok(())
}

pub(crate) async fn fix_routes(etcd_client: &Arc<InMemoryK8sEtcd>, cluster_domain: &str) -> Result<()> {
    fix_route(
        etcd_client,
        K8sResourceLocation::new(Some("openshift-ingress-canary"), "Route", "canary", "route.openshift.io/v1"),
        format!("canary-openshift-ingress-canary.apps.{cluster_domain}"),
        false,
    )
    .await?;

    fix_route(
        etcd_client,
        K8sResourceLocation::new(Some("openshift-monitoring"), "Route", "alertmanager-main", "route.openshift.io/v1"),
        format!("alertmanager-main-openshift-monitoring.apps.{cluster_domain}"),
        // The alertmanager route is not always present in some cluster configurations
        true,
    )
    .await?;

    fix_route(
        etcd_client,
        K8sResourceLocation::new(Some("openshift-monitoring"), "Route", "prometheus-k8s", "route.openshift.io/v1"),
        format!("prometheus-k8s-openshift-monitoring.apps.{cluster_domain}"),
        false,
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
        false,
    )
    .await?;

    fix_route(
        etcd_client,
        K8sResourceLocation::new(Some("openshift-monitoring"), "Route", "thanos-querier", "route.openshift.io/v1"),
        format!("thanos-querier-openshift-monitoring.apps.{cluster_domain}"),
        false,
    )
    .await?;

    fix_route(
        etcd_client,
        K8sResourceLocation::new(
            Some("openshift-authentication"),
            "Route",
            "oauth-openshift",
            "route.openshift.io/v1",
        ),
        format!("oauth-openshift.apps.{cluster_domain}"),
        false,
    )
    .await?;

    Ok(())
}

#[context["fixing route {}", k8s_resource_location]]
async fn fix_route(
    etcd_client: &Arc<InMemoryK8sEtcd>,
    k8s_resource_location: K8sResourceLocation,
    new_host: String,
    optional: bool,
) -> Result<()> {
    let route = get_etcd_json(etcd_client, &k8s_resource_location).await?;

    if let Some(route) = route {
        let mut route = route;
        let spec = &mut route
            .pointer_mut("/spec")
            .context("no /spec")?
            .as_object_mut()
            .context("spec is not an object")?;
        spec.insert("host".to_string(), serde_json::Value::String(new_host))
            .context("missing host")?;
        route.as_object_mut().context("route is not an object")?.remove("status");
        put_etcd_yaml(etcd_client, &k8s_resource_location, route).await?;
    } else if !optional {
        bail!("could not find route");
    }

    Ok(())
}

pub(crate) async fn fix_mcs_daemonset(etcd_client: &InMemoryK8sEtcd, cluster_domain: &str) -> Result<()> {
    let k8s_resource_location = K8sResourceLocation::new(
        Some("openshift-machine-config-operator"),
        "DaemonSet",
        "machine-config-server",
        "apps/v1",
    );
    let mut daemonset = get_etcd_json(etcd_client, &k8s_resource_location)
        .await?
        .context("could not find daemonset")?;

    let pod = &mut daemonset.pointer_mut("/spec/template").context("no /spec/template")?;

    rename_utils::fix_mcd_pod_container_args(pod, cluster_domain, "machine-config-server").context("fixing pod")?;

    put_etcd_yaml(etcd_client, &k8s_resource_location, daemonset).await?;

    Ok(())
}
