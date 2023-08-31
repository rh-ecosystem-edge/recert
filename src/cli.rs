use std::path::PathBuf;

use clap::Parser;

/// A program to regenerate cluster certificates, keys and tokens
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Cli {
    // etcd endpoint to recertify
    #[arg(long)]
    pub(crate) etcd_endpoint: String,

    /// Directory to recertify, such as /var/lib/kubelet, /etc/kubernetes and /etc/machine-config-daemon. Can specify multiple times
    #[arg(long)]
    pub(crate) static_dir: Vec<PathBuf>,

    /// A list of strings to replace in the subject name of all certificates. Can specify multiple.
    /// Must come in pairs of old and new values, separated by a space. For example:
    /// --cn-san-replace "foo bar" --cn-san-replace "baz qux" will replace all instances of "foo"
    /// with "bar" and all instances of "baz" with "qux" in the CN/SAN of all certificates.
    #[arg(long)]
    pub(crate) cn_san_replace: Vec<String>,

    /// Comma separated cluster name and cluster base domain.
    /// If given, many resources will be modified to use this new information
    #[arg(long)]
    pub(crate) cluster_rename: Option<String>,

    /// A list of CNs and the private keys to use for their certs. By default, new keys will be
    /// generated for all regenerated certificates, this option allows you to use existing keys
    /// instead. Must come in pairs of CN and private key file path, separated by a space. For
    /// example: --use-key "foo /etc/foo.key" --use-key "bar /etc/bar.key" will use the key in
    /// /etc/foo.key for certs with CN "foo" and the key in /etc/bar.key for certs with CN "bar".
    /// If more than one cert has the same CN, an error will occur and no certs will be
    /// regenerated.
    #[arg(long)]
    pub(crate) use_key: Vec<String>,

    /// Same as --use-key, but for when a cert needs to be replaced in its entirety, rather than
    /// just being re-signed with a known private key. Certs replaced in this manner must not have
    /// any children, as no private key is available to re-sign them. This is useful for certs that
    /// we don't have the private key for, such admin-kubeconfig-signer.
    #[arg(long)]
    pub(crate) use_cert: Vec<String>,

    /// Extend expiration of all certificates to (original_expiration + (now - issue date)), and
    /// change their issue date to now.
    #[arg(long, default_value_t = false)]
    pub(crate) extend_expiration: bool,

    /// Deprecated
    #[arg(long)]
    pub(crate) kubeconfig: Option<String>,
}
