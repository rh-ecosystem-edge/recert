use super::*;

#[tokio::test]
async fn test_init() -> Result<()> {
    let args = cli::Cli {
        etcd_endpoint: "http://localhost:2379".to_string(),
        static_dir: vec![
            PathBuf::from("./cluster-files/kubernetes"),
            PathBuf::from("./cluster-files/machine-config-daemon"),
            PathBuf::from("./cluster-files/kubelet"),
        ],
        cn_san_replace: vec![
            "api-int.test-cluster.redhat.com api-int.new-name.foo.com".to_string(),
            "api.test-cluster.redhat.com api.new-name.foo.com".to_string(),
            "*.apps.test-cluster.redhat.com *.apps.new-name.foo.com".to_string(),
        ],
        cluster_rename: Some("test-cluster,new-name".to_string()),
        use_key: vec![],
        kubeconfig: None,
    };

    main_internal(args).await
}
