use crate::config::EncryptionCustomizations;
use crate::file_utils::{self, commit_file};
use anyhow::{self, Context, Result};
use futures_util::future::join_all;
use std::path::Path;

pub(crate) async fn fix_filesystem_kas_pods(encryption_customizations: &EncryptionCustomizations, dir: &Path) -> Result<()> {
    if let Some(kube_encryption_config) = &encryption_customizations.kube_encryption_config {
        join_all(
            file_utils::globvec(dir, "**/kube-apiserver-pod-*/secrets/encryption-config/encryption-config")?
                .into_iter()
                .map(|file_path| {
                    let path = file_path.clone();
                    let kube_encryption_config = kube_encryption_config.clone();
                    tokio::spawn(async move {
                        let cloned_path = file_path.clone();
                        async move {
                            commit_file(file_path, format!("{}\n", serde_json::to_string(&kube_encryption_config.config)?))
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
    }

    Ok(())
}
