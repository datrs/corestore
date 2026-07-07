use std::{
    fs::{read_dir, write},
    path::{Path, PathBuf},
};

use hypercore::{Hypercore, HypercoreBuilder, PartialKeypair, Storage, VerifyingKey};
use hypercore_protocol::discovery_key;
use rand::{rngs::OsRng, RngCore};
use tracing::error;

use crate::{Error, PrimaryKey, Result, CORES_DIR_NAME, PRIMARY_KEY_FILE_NAME};

pub(crate) fn get_storage_root<T: Into<StorageId>>(to_id: T) -> PathBuf {
    let id: StorageId = to_id.into();

    format!(
        "{CORES_DIR_NAME}/{}/{}/{}",
        &id.0[0..2],
        &id.0[2..4],
        id.0
    )
    .into()
}

fn generate_primary_key() -> PrimaryKey {
    let mut csprng = OsRng;
    let mut primary_key = [0u8; 32];
    csprng.fill_bytes(&mut primary_key);
    primary_key
}

/// Get all dirs within the given path, log errors
fn permissive_get_dirs<P: AsRef<Path> + std::fmt::Debug + Clone>(path: P) -> Vec<Result<PathBuf>> {
    let entries = match read_dir(&path) {
        Ok(x) => x,
        Err(e) => {
            return vec![Err(Error::ReadDirError(e))];
        }
    };

    let mut out = vec![];

    for entry in entries {
        match entry {
            Ok(x) => {
                if x.path().is_dir() {
                    out.push(Ok(x.path()));
                }
            }
            Err(e) => {
                error!("Could not ready entry, got error [{e:?}]");
                out.push(Err(Error::ReadDirError(e)));
            }
        }
    }
    out
}

/// get all core diretories, they are stored 2 levels deep like:
/// cores/ab/cd/abcdefgh/
fn get_all_core_dirs<P: AsRef<Path> + std::fmt::Debug + Clone>(
    path_to_cores_dir: P,
) -> Vec<PathBuf> {
    let mut out = vec![];
    for level1 in permissive_get_dirs(path_to_cores_dir) {
        let Ok(level1) = level1 else {
            continue;
        };
        for level2 in permissive_get_dirs(level1) {
            let Ok(level2) = level2 else {
                continue;
            };
            for core_dir in permissive_get_dirs(level2) {
                let Ok(core_dir) = core_dir else {
                    continue;
                };
                out.push(core_dir);
            }
        }
    }
    out
}

pub(crate) struct StorageId(String);

impl From<&VerifyingKey> for StorageId {
    fn from(value: &VerifyingKey) -> Self {
        let dk = discovery_key(value.as_bytes());
        StorageId(data_encoding::HEXLOWER.encode(&dk))
    }
}

impl From<&PartialKeypair> for StorageId {
    fn from(value: &PartialKeypair) -> Self {
        (&value.public).into()
    }
}

#[derive(Debug)]
/// The kind of [`Storage`] backing the [`Corestore`]
pub enum StorageKind {
    /// Use RAM
    Mem,
    /// Use the disk at the provided path
    Disk(PathBuf),
}

impl StorageKind {
    /// New [`StorageKind`] using disk at the provided `prefix`
    pub fn new_disk(prefix: impl AsRef<Path>) -> Self {
        Self::Disk(prefix.as_ref().to_path_buf())
    }

    /// New [`StorageKind`] using RAM
    pub fn new_mem() -> Self {
        StorageKind::Mem
    }

    /// Gets or create a core.
    /// The core is writable if the provide `PartialKeypair.secret.is_some()`.
    /// NB: A core should be controlled by only **one** store. This is insured by [`Corestore`]
    /// acceses this. Maybe we should also add a lock file.
    pub async fn get_core_from_key_pair(&self, kp: PartialKeypair) -> Result<Hypercore> {
        match self {
            StorageKind::Mem => {
                let s = Storage::new_memory().await?;
                let hc = HypercoreBuilder::new(s).key_pair(kp).build().await?;
                Ok(hc)
            }
            StorageKind::Disk(path) => {
                let path_to_storage = get_storage_root(&kp);
                let full_path = path.join(path_to_storage);
                let s = Storage::new_disk(&full_path, false).await?;
                let hc = HypercoreBuilder::new(s).key_pair(kp).build().await?;
                Ok(hc)
            }
        }
    }

    /// Get or create the primary key. This gets a slightly complicated:
    /// For Mem: if `pk` provided, use it. Otherwise generate new one
    /// For Disk:
    /// if primary_key file exists:
    ///    if `pk` is provided, then error
    ///    else load primary key file
    ///if no primary_key file:
    ///  if `pk` provided, write it to disk
    ///  else generate new primary key and write to disk
    ///
    ///
    pub fn get_or_create_primary_key(&self, pk: &Option<PrimaryKey>) -> Result<PrimaryKey> {
        Ok(match self {
            // Mem: use provided primary key or generate a new one
            StorageKind::Mem => pk.unwrap_or_else(generate_primary_key),
            StorageKind::Disk(ref path) => {
                let pk_path = path.join(PRIMARY_KEY_FILE_NAME);
                // key file exists on disk
                if pk_path.exists() {
                    // but `primary_key` argument provided, error
                    if pk.is_some() {
                        return Err(Error::PrimaryKeyConflict(pk_path.display().to_string()));
                    }
                    std::fs::read(pk_path)?
                        .try_into()
                        // Fail if key on disk is invalid
                        .map_err(|_| Error::InvalidPrimaryKey)?
                } else {
                    // No existing key on disk, create one
                    let pk = pk.unwrap_or_else(generate_primary_key);
                    write(pk_path, pk)?;
                    pk
                }
            }
        })
    }

    pub async fn load_existing_cores(&self) -> Result<Vec<Hypercore>> {
        match self {
            StorageKind::Mem => Ok(vec![]),
            StorageKind::Disk(path) => {
                let mut out = vec![];
                let cores_dir_path = path.join(CORES_DIR_NAME);
                for core_path in get_all_core_dirs(cores_dir_path) {
                    let s = Storage::new_disk(&core_path, false).await?;
                    let hc = HypercoreBuilder::new(s).build().await?;
                    out.push(hc);
                }
                Ok(out)
            }
        }
    }
}
#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn get_storage_dir_matches_js() {
        let id = StorageId("helloworld".to_string());
        assert_eq!(get_storage_root(id).as_os_str(), "cores/he/ll/helloworld");
    }
}
