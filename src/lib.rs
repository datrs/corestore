//! [`Corestore`] provides a way to manage a related group of [`hypercore::Hypercore`]s.
//! Intended to be fully compatible with the [JavaScrpt `corestore`
//! library](https://github.com/holepunchto/corestore).
#![warn(
    missing_debug_implementations,
    missing_docs,
    redundant_lifetimes,
    //unsafe_code,
    non_local_definitions
)]

mod builder;
mod keys;
mod storage;
use delegate::delegate;
use hypercore_protocol::{discovery_key, DiscoveryKey};
use std::{collections::HashMap, sync::Arc};
use storage::StorageKind;
use tokio::sync::RwLock;

use hypercore::{replication::CoreMethodsError, Hypercore, HypercoreError, VerifyingKey};

pub use builder::{CorestoreBuilder, CorestoreBuilderError};

static MAX_EVENT_QUEUE_CAPACITY: usize = 32;
const CORES_DIR_NAME: &str = "cores";
const PRIMARY_KEY_FILE_NAME: &str = "primary-key";

/// The key [`Corestore`] uses for deriving keys for it's [`hypercore::Hypercore`]s.
pub type PrimaryKey = [u8; 32];
/// Used to prefix names of names of [`hypercore::Hypercore`] to create namespaces
pub type Namespace = [u8; 32];

/// Corestore's Errors
#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
#[allow(missing_docs)]
pub enum Error {
    #[error("error from hypercore: {0}")]
    Hypercore(#[from] HypercoreError),
    #[error("error from hypercore CoreMethods: {0}")]
    CoreMethods(#[from] CoreMethodsError),
    #[error("Signature error")]
    Signature(#[from] signature::Error),
    #[error("Fs error")]
    FsError(#[from] std::io::Error),
    #[error("Invalid primary key")]
    InvalidPrimaryKey,
    #[error("Fs error")]
    BuilderError(#[from] CorestoreBuilderError),
    #[error("Could not build corestore because a primary key value was provided, but one already exists on disk at [{0}]")]
    PrimaryKeyConflict(String),
    #[error("libsodium's generichash function did not return `0`. Got: {0}")]
    LibSodiumGenericHashError(i32),
    #[error("libsodium's sign_seed_keypair function did not return `0`. Got: {0}")]
    LibSodiumSignSeedKeypair(i32),
    #[error("error reading dirs {0}")]
    ReadDirError(std::io::Error),
}

type Result<T> = std::result::Result<T, Error>;

mod events {
    #![allow(unused)]

    use super::{Result, MAX_EVENT_QUEUE_CAPACITY};
    use hypercore::VerifyingKey;
    use hypercore_protocol::DiscoveryKey;
    use tokio::sync::{broadcast, BarrierWaitResult};

    #[derive(Debug, Clone)]
    /// Coresstore events
    pub enum Event {
        /// A new core was added
        CoreAdded(VerifyingKey),
        /// Corestore is shutting down
        Shutdown,
    }

    #[derive(Debug)]
    /// Event bus for Corestore
    pub struct Events {
        channel: broadcast::Sender<Event>,
    }

    impl Events {
        fn new() -> Self {
            Self {
                channel: broadcast::channel(MAX_EVENT_QUEUE_CAPACITY).0,
            }
        }

        pub fn send(&self, evt: Event) -> Result<()> {
            let _ = self.channel.send(evt);
            Ok(())
        }

        pub fn subscribe(&self) -> broadcast::Receiver<Event> {
            self.channel.subscribe()
        }
    }
    impl Default for Events {
        fn default() -> Self {
            Events::new()
        }
    }
}

pub use events::Event as CorestoreEvents;

#[derive(Debug, Default)]
struct CoreCache {
    verifying_key_to_cores: HashMap<VerifyingKey, Hypercore>,
}

impl CoreCache {
    // get the dk from a name
    fn insert(&mut self, verifying_key: &VerifyingKey, core: Hypercore) -> Option<Hypercore> {
        self.verifying_key_to_cores.insert(*verifying_key, core)
    }

    fn verifying_keys(&self) -> Vec<&VerifyingKey> {
        self.verifying_key_to_cores.keys().collect()
    }
    fn get(&self, verifying_key: &VerifyingKey) -> Option<Hypercore> {
        self.verifying_key_to_cores.get(verifying_key).cloned()
    }

    /// TODO make this O(1) by storing a dk -> vk map
    fn verifying_key_from_discovery_key(&self, dk: &DiscoveryKey) -> Option<VerifyingKey> {
        for vk in self.verifying_key_to_cores.keys() {
            if dk == &discovery_key(vk.as_bytes()) {
                return Some(*vk);
            }
        }
        None
    }
}

/// Container for managing groups of related [`hypercore::Hypercore`]s. It should match the behavior of the
/// [JavaScript version](https://github.com/holepunchto/corestore?tab=readme-ov-file#api).
#[derive(Debug, Clone)]
pub struct Corestore {
    ///  shared ref to corestore
    corestore: Arc<RwLock<builder::InnerCorstore>>,
}

impl Corestore {
    delegate! {
        to self.corestore.read().await {
            #[await(false)]
            /// Get the [`VerifyingKey`] key that corresponds to a [`DiscoveryKey`]
            pub async fn verifying_key_from_discovery_key(&self, dk: &DiscoveryKey) -> Option<VerifyingKey>;
        }
        to self.corestore.write().await {
            /// Get a core from it's [`VerifyingKey`].
            pub async fn get_from_verifying_key(&self, vk: &VerifyingKey) -> Result<Hypercore>;
            /// Get a hypercore by name. If the core does not exist, create it.
            pub async fn get_from_name(&self, name: &str) -> Result<Hypercore>;
        }
    }
    /// Create a new [`Corestore`] that stores it data in RAM
    pub async fn new_mem() -> Corestore {
        CorestoreBuilder::default()
            .storage(StorageKind::new_mem())
            .build()
            .await
            .expect("should always work")
    }

    // TODO: multi-core replication (multiplexing several Hypercores' channels over one
    // connection, as JS corestore's `.replicate()` does) is not implemented yet. It needs to be
    // rebuilt on top of `core/`'s native `hypercore_protocol`-based replication rather than the
    // old `replicator` crate's `ReplicatingCore`/`ProtoMethods` model.
}

#[cfg(test)]
mod test {
    use super::{storage::get_storage_root, *};

    const TEST_PK: PrimaryKey = [
        124, 229, 174, 223, 232, 201, 160, 10, 235, 143, 37, 249, 107, 92, 35, 125, 68, 246, 2,
        197, 41, 248, 234, 65, 9, 222, 77, 144, 50, 243, 222, 65,
    ];

    #[tokio::test]
    async fn disk_core_by_name() -> Result<()> {
        // initialize CS with a fixed primary key
        // check it producets the expected fixed file path
        let storage_dir = tempfile::tempdir().unwrap();
        let mut pk = TEST_PK;
        pk[0] = 0;

        let cs = CorestoreBuilder::default()
            .primary_key(pk)
            .storage(StorageKind::new_disk(storage_dir.path()))
            .build()
            .await?;

        let hc = cs.get_from_name("foo").await?;
        hc.append(b"hello").await?;
        assert_eq!(hc.get(0).await?, Some(b"hello".to_vec()));
        let vk = hc.key_pair().public;

        let core_path = storage_dir.path().join(get_storage_root(&vk));
        assert!(core_path.exists());

        let hc2 = cs.get_from_verifying_key(&vk).await?;
        assert_eq!(hc2.get(0).await?, Some(b"hello".to_vec()));
        Ok(())
    }

    #[tokio::test]
    async fn primary_key_cstore_dir_gets_used() -> Result<()> {
        let storage_dir = tempfile::tempdir().unwrap();
        let mut pk = TEST_PK;
        pk[0] = 1;

        {
            let cs = CorestoreBuilder::default()
                .primary_key(pk)
                .storage(StorageKind::new_disk(storage_dir.path()))
                .build()
                .await?;

            let hc = cs.get_from_name("foo").await?;
            hc.append(b"hello").await?;
        }
        {
            // corestore uses pk in directory if it exists already
            let cs = CorestoreBuilder::default()
                .storage(StorageKind::new_disk(storage_dir.path()))
                .build()
                .await?;
            let hc = cs.get_from_name("foo").await?;
            assert_eq!(hc.get(0).await?, Some(b"hello".to_vec()));
        }
        {
            // providing a pk while there is one on disk is err
            assert!(matches!(
                CorestoreBuilder::default()
                    .storage(StorageKind::new_disk(storage_dir.path()))
                    .primary_key(pk)
                    .build()
                    .await,
                Err(Error::PrimaryKeyConflict(_))
            ));
        }

        Ok(())
    }
}
