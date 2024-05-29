use crate::{
    file_utils::{self, commit_file, read_file_to_string},
    ocp_postprocess::rename_utils,
};
use anyhow::{self, Context, Result};
use futures_util::future::join_all;
use std::path::Path;

pub(crate) async fn fix_filesystem_ip(original_ip: &str, ip: &str, dir: &Path) -> Result<()> {
    join_all(
        file_utils::globvec(dir, "**/etcd-pod.yaml")?
            .into_iter()
            .chain(file_utils::globvec(dir, "**/*etcd-pod/pod.yaml")?)
            .into_iter()
            .chain(file_utils::globvec(dir, "**/etcd-scripts/etcd.env")?)
            .into_iter()
            .chain(file_utils::globvec(dir, "**/etcd-endpoints/*")?)
            .into_iter()
            .chain(file_utils::globvec(dir, "**/kube-apiserver-pod-*/configmaps/config/config.yaml")?)
            .into_iter()
            .map(|file_path| {
                let path = file_path.clone();
                let original_ip = original_ip.to_string();
                let ip = ip.to_string();
                tokio::spawn(async move {
                    let cloned_path = file_path.clone();
                    async move {
                        let contents = read_file_to_string(&file_path)
                            .await
                            .context(format!("reading {:?}", cloned_path))?;

                        commit_file(
                            file_path,
                            rename_utils::fix_ip(&contents, &original_ip, &ip).context(format!("fixing {:?}", cloned_path))?,
                        )
                        .await
                        .context(format!("writing {:?}", cloned_path))?;

                        anyhow::Ok(())
                    }
                    .await
                    .context(format!("fixing {:?}", path))
                })
            }),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    Ok(())
}
