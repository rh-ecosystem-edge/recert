use lazy_regex::{regex, Lazy};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;

lazy_static! {
    pub(crate) static ref IGNORE_LIST_CONFIGMAP: HashSet<String> = vec![
        "verifier-public-key-redhat",
        // "service-account-001.pub",
        // "service-account-002.pub",
        // "ca-bundle.crt"
    ]
        .into_iter()
        .map(str::to_string)
        .collect();

    pub(crate) static ref IGNORE_LIST_SECRET: HashSet<String> = vec![
        "prometheus.yaml.gz",
        "alertmanager.yaml.gz",
        "entitlement.pem",
        "entitlement-key.pem",
        "encryption.apiserver.operator.openshift.io-key",
    ]
        .into_iter()
        .map(str::to_string)
        .collect();

    // It's okay for some certs to not have a private key, as it's used to sign a few certs and
    // then dropped by its creator. For us it just means we still have to temporarily recreate them
    // in order to regenerate their signees, we just don't have to record them back to the
    // filesystem or etcd because they were never there in the first place. These are rare so we
    // explicitly record them here and any time we encounter a cert without a matching private key
    // we check if it's in this list and error if it's not, as it means we might have a bug in our
    // code.
    pub(crate) static ref KNOWN_MISSING_PRIVATE_KEY_CERTS: Vec<&'static Lazy<Regex>> = vec![
        // This is a self-signed cert trusted by the kube-apiserver and its private key is used to
        // sign just the admin kubeconfig client cert once and then drops it because there will
        // always ever be only one admin kubeconfig
        regex!("CN=admin-kubeconfig-signer, OU=openshift"),
        // TODO: Unknown why it's missing
        regex!("CN=kubelet-bootstrap-kubeconfig-signer, OU=openshift"),
        // TODO: Unknown why it's missing
        regex!("CN=root-ca, OU=openshift"),
        // As of OCP 4.14 you can see the private key being dropped here:
        // https://github.com/operator-framework/operator-lifecycle-manager/blob/9ced412f3e263b8827680dc0ad3477327cd9a508/pkg/controller/install/certresources.go#L295
        regex!("CN=olm-selfsigned-[0-9a-f]{10,32}, O=Red Hat, Inc."),
    ].into_iter().collect();
}
