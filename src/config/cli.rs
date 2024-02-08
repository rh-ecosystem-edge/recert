use crate::{
    cnsanreplace::CnSanReplace,
    ocp_postprocess::{cluster_domain_rename::params::ClusterNamesRename, proxy_rename::args::Proxy},
    use_cert::UseCert,
    use_key::UseKey,
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

    // DEPRECATED: Use --crypto-dir and --cluster-customization-dir instead. This option will be
    // removed in a future release. Cannot be used with --crypto-dir or --cluster-customization-dir
    // or --additional-trust-bundle
    #[clap(long, value_parser = clap::value_parser!(ClioPath).exists().is_dir(), groups = &["crypto_dir_paths", "cluster_customization_dir_paths", "adt_dirs"])]
    pub(crate) static_dir: Vec<ClioPath>,

    /// DEPRECATED: Use --crypto-file and --cluster-customization-file instead. This option will be
    /// removed in a future release. Cannot be used with --crypto-file or
    /// --cluster-customization-file or --additional-trust-bundle
    #[clap(long, value_parser = clap::value_parser!(ClioPath).exists().is_file(), groups = &["crypto_file_paths", "cluster_customization_file_paths", "adt_files"])]
    pub(crate) static_file: Vec<ClioPath>,

    /// Directory to recertify, such as /var/lib/kubelet, /etc/kubernetes and
    /// /etc/machine-config-daemon. Can specify multiple times
    #[clap(long, value_parser = clap::value_parser!(ClioPath).exists().is_dir(), group = "crypto_dir_paths")]
    pub(crate) crypto_dir: Vec<ClioPath>,

    /// A file to recertify, such as /etc/mcs-machine-config-content.json. Can specify multiple
    /// times
    #[clap(long, value_parser = clap::value_parser!(ClioPath).exists().is_file(), group = "crypto_file_paths")]
    pub(crate) crypto_file: Vec<ClioPath>,

    /// Directory containing files involved in cluster customization, such as /var/lib/kubelet,
    /// /etc/kubernetes, /etc/pki/ca-trust, etc. Can specify multiple.
    #[clap(long, value_parser = clap::value_parser!(ClioPath).exists().is_dir(), group = "cluster_customization_dir_paths")]
    pub(crate) cluster_customization_dir: Vec<ClioPath>,

    /// File involved in cluster customization, such as /etc/mcs-machine-config-content.json. Can
    /// specify multiple.
    #[clap(long, value_parser = clap::value_parser!(ClioPath).exists().is_file(), group = "cluster_customization_file_paths")]
    pub(crate) cluster_customization_file: Vec<ClioPath>,

    /// A list of strings to replace in the subject name of all certificates. Can specify multiple.
    /// --cn-san-replace foo:bar --cn-san-replace baz:qux will replace all instances of "foo" with
    /// "bar" and all instances of "baz" with "qux" in the CN/SAN of all certificates.
    #[clap(long, value_parser = CnSanReplace::parse)]
    pub(crate) cn_san_replace: Vec<CnSanReplace>,

    /// Experimental feature. Colon separated cluster name and cluster base domain. If given, many
    /// cluster resources which refer to a cluster name / cluster base domain (typically through
    /// URLs which they happen to contian) will be modified to use this cluster name and base
    /// domain instead.
    #[clap(long, value_parser = ClusterNamesRename::parse)]
    pub(crate) cluster_rename: Option<ClusterNamesRename>,

    /// If given, the cluster resources that include the hostname will be modified to use this one
    /// instead.
    #[clap(long)]
    pub(crate) hostname: Option<String>,

    /// If given, the cluster resources that include the IP address will be modified to use this
    /// one instead.
    #[clap(long)]
    pub(crate) ip: Option<String>,

    /// If given, the cluster's HTTP proxy configuration will be modified to use this one instead.
    #[clap(long, value_parser = Proxy::parse)]
    pub(crate) proxy: Option<Proxy>,

    /// If given, the cluster's install-config configmaps be modified to have this value.
    #[clap(long)]
    pub(crate) install_config: Option<String>,

    /// Modify the OCP kubeadmin password secret hash. If given but empty, the kubeadmin password
    /// secret will be deleted (thus disabling password login). If given and non-empty, the secret
    /// will be updated with the given password hash, unless no existing kubeadmin secret resource
    /// is found, in that case it will cause an error, as creating an entire secret is beyond the
    /// scope of this tool. The hash's validaity will not be checked.
    ///
    // NOTE: This functionality is part of recert because it's important to change the seed's
    // kubeadmin password before the cluster API server is started, otherwise the API server will
    // start with a possibly compromised seed password, which is undesirable even if for a very
    // short time. Recert is already modifying secrets in etcd, so might as well do this here too.
    #[clap(long)]
    pub(crate) kubeadmin_password_hash: Option<String>,

    /// If given, the cluster resources that include the pull secret will be modified to use this
    /// one instead.
    #[clap(long)]
    pub(crate) pull_secret: Option<String>,

    /// Change a cluster's trust bundle. Changes all locations where the trust bundle is stored in
    /// the cluster. If an existing trust bundle is not found, this will cause an error, as
    /// creating the relevant resources is beyond the scope of this tool. The trust bundle's
    /// validity will not be checked. When using a RECERT_CONFIG file, raw PEMS can be used instead
    /// of paths to trust bundle files. When using this option it is recommended to also run
    /// update-ca-trust after running recert to ensure that the trust bundle is properly updated in
    /// all locations.
    #[clap(long, value_parser = super::parse_additional_trust_bundle, groups = &["adt_dirs", "adt_files"])]
    pub(crate) additional_trust_bundle: Option<String>,

    /// A list of CNs and the private keys to use for their certs. By default, new keys will be
    /// generated for all regenerated certificates, this option allows you to use existing keys
    /// instead. Must come in pairs of CN and private key file path, separated by a space. For
    /// example: --use-key foo:/etc/foo.key --use-key bar:/etc/bar.key will use the key in
    /// /etc/foo.key for certs with CN "foo" and the key in /etc/bar.key for certs with CN "bar".
    /// If more than one cert has the same CN, an error will occur and no certs will be
    /// regenerated.
    ///
    /// When using a RECERT_CONFIG file, raw PEMS can be used instead of paths to key files.
    #[clap(long, value_parser = UseKey::parse)]
    pub(crate) use_key: Vec<UseKey>,

    /// Same as --use-key, but for when a cert needs to be replaced in its entirety, rather than
    /// just being re-signed with a known private key. Only the cert path is needed, CN is implied
    /// by the cert itself. This is useful for certs that we don't have the private key for, such
    /// admin-kubeconfig-signer. Certs replaced in this manner must not have any children, as no
    /// private key is available to re-sign them. Their expiration will not be extended even when
    /// the --extend-expiration flag is used.
    ///
    /// When using a RECERT_CONFIG file, raw PEMS can be used instead of paths to cert files.
    #[clap(long, value_parser = UseCert::parse)]
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
