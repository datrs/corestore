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
mod replicate;
mod storage;
use delegate::delegate;
use hypercore_protocol::{discovery_key, DiscoveryKey};
use std::{collections::HashMap, sync::Arc};
use storage::StorageKind;
use tokio::sync::RwLock;

use hypercore::{replication::CoreMethodsError, Hypercore, HypercoreError, VerifyingKey};
use hypercore_handshake::CipherTrait;

pub use builder::{CorestoreBuilder, CorestoreBuilderError};
pub use replicate::CorestoreConnection;

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

    fn verifying_keys(&self) -> Vec<VerifyingKey> {
        self.verifying_key_to_cores.keys().copied().collect()
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

    /// Create a new [`Corestore`] that stores its data on disk under `path`, creating the
    /// directory if it does not exist. Reopening the same `path` restores the store's primary
    /// key and every core previously written there, so named cores keep their identity across
    /// restarts.
    ///
    /// Unlike [`Corestore::new_mem`] this can fail, because it touches the filesystem.
    pub async fn new_disk(path: impl AsRef<std::path::Path>) -> Result<Corestore> {
        let path = path.as_ref();
        // Creating a store at a path that does not exist yet is the common case, and the
        // primary-key write below fails with a bare `NotFound` without this.
        std::fs::create_dir_all(path).map_err(hypercore::HypercoreError::from)?;
        CorestoreBuilder::default()
            .storage(StorageKind::new_disk(path))
            .build()
            .await
    }

    /// Non-blocking snapshot of all currently known verifying keys. Returns an empty `Vec`
    /// if the store is momentarily locked. Used by [`CorestoreConnection`] to
    /// opportunistically attach cores added to the store after it was created.
    pub(crate) fn try_verifying_keys(&self) -> Vec<VerifyingKey> {
        self.corestore
            .try_read()
            .map(|guard| guard.verifying_keys())
            .unwrap_or_default()
    }

    /// Non-blocking lookup of the [`VerifyingKey`] for a [`DiscoveryKey`]. See
    /// [`Corestore::verifying_key_from_discovery_key`] for the async version.
    pub(crate) fn try_verifying_key_from_discovery_key(
        &self,
        dk: &DiscoveryKey,
    ) -> Option<VerifyingKey> {
        self.corestore
            .try_read()
            .ok()
            .and_then(|guard| guard.verifying_key_from_discovery_key(dk))
    }

    /// Non-blocking subscription to [`CorestoreEvents::CoreAdded`], used by
    /// [`CorestoreConnection`] to wake itself and re-check for newly-opened cores rather
    /// than relying entirely on incidental protocol activity to trigger another poll.
    /// Returns `None` if the store is momentarily locked; the caller retries later.
    pub(crate) fn try_subscribe(&self) -> Option<tokio::sync::broadcast::Receiver<CorestoreEvents>> {
        self.corestore.try_read().ok().map(|guard| guard.subscribe())
    }

    /// Start replicating every core in this store over `stream`, multiplexed via one
    /// `hypercore_protocol` connection — mirrors JS corestore's `.replicate()`
    /// (`corestore/index.js:481`). Poll (or `.await`) the returned [`CorestoreConnection`]
    /// to drive it. Cores opened in this store *after* this is called are still attached
    /// automatically, the next time the connection is polled.
    pub fn replicate(&self, stream: impl CipherTrait + 'static) -> CorestoreConnection {
        CorestoreConnection::new(self.clone(), stream)
    }
}

#[cfg(test)]
mod test {
    use super::{storage::get_storage_root, *};
    use hypercore_handshake::{
        state_machine::{hc_specific::generate_keypair, SecStream},
        Cipher,
    };
    use std::time::Duration;
    use tokio::time::sleep;
    use tokio_util::compat::TokioAsyncReadCompatExt;
    use uint24le_framing::Uint24LELengthPrefixedFraming;

    /// A disk-backed store reopened from the same path keeps its primary key, so a named
    /// core resolves to the same public key and its data is still there. This is the whole
    /// point of `new_disk`, and it is what lets a publisher keep its feed id across restarts.
    #[tokio::test]
    async fn new_disk_round_trips_a_named_core() -> Result<()> {
        let tmp = tempfile::tempdir().expect("tempdir");
        // A path that does not exist yet: the usual case for a fresh store.
        let dir = tmp.path().join("store");

        let key = {
            let store = Corestore::new_disk(&dir).await?;
            let core = store.get_from_name("feed").await?;
            core.append(b"hello").await?;
            core.key_pair().public
        };

        let store = Corestore::new_disk(&dir).await?;
        let core = store.get_from_name("feed").await?;
        assert_eq!(core.key_pair().public, key, "named core changed identity");
        assert_eq!(core.get(0).await?.as_deref(), Some(&b"hello"[..]));
        Ok(())
    }

    /// Create a pair of connected in-memory encrypted streams, mirroring the same helper in
    /// `bee`/`hrss`'s tests.
    fn create_connected_streams() -> (impl CipherTrait + 'static, impl CipherTrait + 'static) {
        let (a_b, b_a) = tokio::io::duplex(64 * 1024);
        let a_b = Uint24LELengthPrefixedFraming::new(a_b.compat());
        let b_a = Uint24LELengthPrefixedFraming::new(b_a.compat());
        let keypair = generate_keypair().unwrap();
        let initiator = Cipher::new(
            Some(Box::new(a_b)),
            SecStream::new_initiator_xx(&[]).unwrap().into(),
        );
        let responder = Cipher::new(
            Some(Box::new(b_a)),
            SecStream::new_responder_xx(&keypair, &[]).unwrap().into(),
        );
        (initiator, responder)
    }

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

    #[tokio::test]
    async fn prexisting_cores_replicate() -> Result<()> {
        let (cs_a, cs_b) = (Corestore::new_mem().await, Corestore::new_mem().await);
        let (a, b) = create_connected_streams();
        let name = "foo";
        let core_a = cs_a.get_from_name(name).await?;
        let vk = core_a.key_pair().public;
        let core_b = cs_b.get_from_verifying_key(&vk).await?;

        core_a.append(b"hello").await?;
        assert!(core_b.get(0).await?.is_none());

        tokio::spawn(cs_a.replicate(a));
        tokio::spawn(cs_b.replicate(b));

        loop {
            if core_b.get(0).await?.is_some() {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
        Ok(())
    }

    #[tokio::test]
    async fn new_cores_replicate() -> Result<()> {
        let (cs_a, cs_b) = (Corestore::new_mem().await, Corestore::new_mem().await);
        let (a, b) = create_connected_streams();

        // No cores exist in either store yet: this proves cores opened *after* replicate()
        // is called still get attached (`CorestoreConnection::open_new_cores`), not just
        // ones that existed up front.
        tokio::spawn(cs_a.replicate(a));
        tokio::spawn(cs_b.replicate(b));

        let name = "foo";
        let core_a = cs_a.get_from_name(name).await?;
        core_a.append(b"hello").await?;

        let vk = core_a.key_pair().public;
        let core_b = cs_b.get_from_verifying_key(&vk).await?;

        core_a.append(b"world").await?;
        loop {
            if let Some(x) = core_b.get(0).await? {
                assert_eq!(x, b"hello");
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
        loop {
            if let Some(x) = core_b.get(1).await? {
                assert_eq!(x, b"world");
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
        Ok(())
    }

    #[tokio::test]
    async fn multiple_cores_multiplex_over_one_connection() -> Result<()> {
        let (cs_a, cs_b) = (Corestore::new_mem().await, Corestore::new_mem().await);
        let (a, b) = create_connected_streams();

        let foo_a = cs_a.get_from_name("foo").await?;
        let bar_a = cs_a.get_from_name("bar").await?;
        foo_a.append(b"foo hello").await?;
        bar_a.append(b"bar hello").await?;

        let foo_b = cs_b.get_from_verifying_key(&foo_a.key_pair().public).await?;
        let bar_b = cs_b.get_from_verifying_key(&bar_a.key_pair().public).await?;

        // Only one connection for both cores.
        tokio::spawn(cs_a.replicate(a));
        tokio::spawn(cs_b.replicate(b));

        loop {
            if foo_b.get(0).await?.is_some() && bar_b.get(0).await?.is_some() {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(foo_b.get(0).await?, Some(b"foo hello".to_vec()));
        assert_eq!(bar_b.get(0).await?, Some(b"bar hello".to_vec()));
        Ok(())
    }
}
