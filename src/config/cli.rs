use crate::{
    cnsanreplace::CnSanReplace, ocp_postprocess::cluster_domain_rename::params::ClusterRenameParameters, use_cert::UseCert, use_key::UseKey,
};
use clap::Parser;
use clio::ClioPath;

/// A program to regenerate cluster certificates, keys and tokens
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Cli {
    /// etcd endpoint of etcd instance to recertify
    #[clap(long)]
    pub(crate) etcd_endpoint: Option<String>,

    /// Directory to recertify, such as /var/lib/kubelet, /etc/kubernetes and
    /// /etc/machine-config-daemon. Can specify multiple times
    #[clap(long, value_parser = clap::value_parser!(ClioPath).exists().is_dir())]
    pub(crate) static_dir: Vec<ClioPath>,

    /// A file to recertify, such as /etc/mcs-machine-config-content.json. Can specify multiple
    /// times
    #[clap(long, value_parser = clap::value_parser!(ClioPath).exists().is_file())]
    pub(crate) static_file: Vec<ClioPath>,

    /// A list of strings to replace in the subject name of all certificates. Can specify multiple.
    /// --cn-san-replace foo:bar --cn-san-replace baz:qux will replace all instances of "foo" with
    /// "bar" and all instances of "baz" with "qux" in the CN/SAN of all certificates.
    #[clap(long, value_parser = CnSanReplace::cli_parse)]
    pub(crate) cn_san_replace: Vec<CnSanReplace>,

    /// Experimental feature. Colon separated cluster name and cluster base domain. If given, many
    /// cluster resources which refer to a cluster name / cluster base domain (typically through
    /// URLs which they happen to contian) will be modified to use this cluster name and base
    /// domain instead.
    #[clap(long, value_parser = ClusterRenameParameters::cli_parse)]
    pub(crate) cluster_rename: Option<ClusterRenameParameters>,

    /// If given, the cluster resources that include the hostname will be modified to use this one
    /// instead.
    #[clap(long)]
    pub(crate) hostname: Option<String>,

    /// A list of CNs and the private keys to use for their certs. By default, new keys will be
    /// generated for all regenerated certificates, this option allows you to use existing keys
    /// instead. Must come in pairs of CN and private key file path, separated by a space. For
    /// example: --use-key foo:/etc/foo.key --use-key bar:/etc/bar.key will use the key in
    /// /etc/foo.key for certs with CN "foo" and the key in /etc/bar.key for certs with CN "bar".
    /// If more than one cert has the same CN, an error will occur and no certs will be
    /// regenerated.
    #[clap(long, value_parser = UseKey::cli_parse)]
    pub(crate) use_key: Vec<UseKey>,

    /// Same as --use-key, but for when a cert needs to be replaced in its entirety, rather than
    /// just being re-signed with a known private key. Only the cert path is needed, CN is implied
    /// by the cert itself. This is useful for certs that we don't have the private key for, such
    /// admin-kubeconfig-signer. Certs replaced in this manner must not have any children, as no
    /// private key is available to re-sign them. Their expiration will not be extended even when
    /// the --extend-expiration flag is used.
    #[clap(long, value_parser = UseCert::cli_parse)]
    pub(crate) use_cert: Vec<UseCert>,

    /// Extend expiration of all certificates to (original_expiration + (now - issue date)), and
    /// change their issue date to now.
    #[clap(long, default_value_t = false, groups = &["expiration", "dry"])]
    pub(crate) extend_expiration: bool,

    /// Threads to use for parallel processing. Defaults to using as many threads as there are
    /// logical CPUs
    #[clap(long)]
    pub(crate) threads: Option<usize>,

    /// Regenerate server SSH keys and write to this directory
    #[clap(long, group = "dry", value_parser = clap::value_parser!(ClioPath).exists().is_dir())]
    pub(crate) regenerate_server_ssh_keys: Option<ClioPath>,

    /// Generate a summary
    #[clap(long, value_parser = clap::value_parser!(ClioPath))]
    pub(crate) summary_file: Option<ClioPath>,

    /// Generate a summary without sensitive data (private keys and JWTs removed)
    #[clap(long, value_parser = clap::value_parser!(ClioPath))]
    pub(crate) summary_file_clean: Option<ClioPath>,

    /// Don't actually commit anything to etcd/disk. Useful for validating that a cluster can be
    /// recertified error-free before turning it into a seed image.
    /// Note: the act of reading from etcd might sometimes cause changes to etcd
    #[clap(long, group = "dry")]
    pub(crate) dry_run: bool,

    /// Intentionally give all certificates an expiration date in the past. Useful to run before
    /// creating a seed image to make sure that this seed image will not be accidentally used
    /// as-is. That is, the seed image would have to be recertified with --extend-expiration to fix
    /// those intentionally expired dates.
    #[clap(long, groups = &["dry", "expiration"])]
    pub(crate) force_expire: bool,
}
