//! tokio::fs-backed `FsPort` adapter.

use async_trait::async_trait;

use tuntun_core::ports::{FsPath, FsPort};
use tuntun_core::{Error, Result};

#[derive(Debug, Default)]
pub struct TokioFs;

#[async_trait]
impl FsPort for TokioFs {
    async fn write_file(&self, path: &FsPath, contents: &[u8]) -> Result<()> {
        tokio::fs::write(path.as_str(), contents)
            .await
            .map_err(|e| Error::port("fs", format!("write {}: {e}", path.as_str())))
    }

    async fn read_file(&self, path: &FsPath) -> Result<Vec<u8>> {
        tokio::fs::read(path.as_str())
            .await
            .map_err(|e| Error::port("fs", format!("read {}: {e}", path.as_str())))
    }

    async fn ensure_dir(&self, path: &FsPath) -> Result<()> {
        tokio::fs::create_dir_all(path.as_str())
            .await
            .map_err(|e| Error::port("fs", format!("mkdir {}: {e}", path.as_str())))
    }

    async fn remove_file(&self, path: &FsPath) -> Result<()> {
        tokio::fs::remove_file(path.as_str())
            .await
            .map_err(|e| Error::port("fs", format!("rm {}: {e}", path.as_str())))
    }

    async fn rename(&self, from: &FsPath, to: &FsPath) -> Result<()> {
        tokio::fs::rename(from.as_str(), to.as_str())
            .await
            .map_err(|e| {
                Error::port(
                    "fs",
                    format!("rename {} -> {}: {e}", from.as_str(), to.as_str()),
                )
            })
    }
}
