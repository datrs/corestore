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
use futures::future::{BoxFuture, FutureExt, Shared};
use hypercore_protocol::{discovery_key, DiscoveryKey};
use keys::{key_pair_from_name, DEFAULT_NAMESPACE};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};
use storage::StorageKind;

use hypercore::{
    replication::CoreMethodsError, Hypercore, HypercoreError, PartialKeypair, VerifyingKey,
};
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
    /// Opening a core failed. Everyone who asked for the core while it was opening gets the
    /// same error, so it is shared.
    #[error("error opening core: {0}")]
    Opening(Arc<Error>),
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

    #[derive(Debug, Clone)]
    /// Event bus for Corestore. Clones send to the same subscribers.
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

/// A core being created, shared by everyone who asks for it before it is ready.
type OpeningCore = Shared<BoxFuture<'static, std::result::Result<Hypercore, Arc<Error>>>>;

#[derive(Clone)]
enum CachedCore {
    Ready(Hypercore),
    Opening(OpeningCore),
}

impl std::fmt::Debug for CachedCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CachedCore::Ready(core) => f.debug_tuple("Ready").field(core).finish(),
            CachedCore::Opening(_) => write!(f, "Opening"),
        }
    }
}

#[derive(Debug, Default)]
struct CoreCache {
    verifying_key_to_cores: HashMap<VerifyingKey, CachedCore>,
}

impl CoreCache {
    fn get(&self, verifying_key: &VerifyingKey) -> Option<CachedCore> {
        self.verifying_key_to_cores.get(verifying_key).cloned()
    }

    fn insert_ready(&mut self, verifying_key: VerifyingKey, core: Hypercore) {
        self.verifying_key_to_cores
            .insert(verifying_key, CachedCore::Ready(core));
    }

    fn insert_opening(&mut self, verifying_key: VerifyingKey, opening: OpeningCore) {
        self.verifying_key_to_cores
            .insert(verifying_key, CachedCore::Opening(opening));
    }

    fn remove(&mut self, verifying_key: &VerifyingKey) {
        self.verifying_key_to_cores.remove(verifying_key);
    }

    /// The keys of every core that has finished opening.
    fn verifying_keys(&self) -> Vec<VerifyingKey> {
        self.verifying_key_to_cores
            .iter()
            .filter(|(_, cached)| matches!(cached, CachedCore::Ready(_)))
            .map(|(vk, _)| *vk)
            .collect()
    }

    /// TODO make this O(1) by storing a dk -> vk map
    fn verifying_key_from_discovery_key(&self, dk: &DiscoveryKey) -> Option<VerifyingKey> {
        self.verifying_keys()
            .into_iter()
            .find(|vk| dk == &discovery_key(vk.as_bytes()))
    }
}

/// Container for managing groups of related [`hypercore::Hypercore`]s. It should match the behavior of the
/// [JavaScript version](https://github.com/holepunchto/corestore?tab=readme-ov-file#api).
#[derive(Debug, Clone)]
pub struct Corestore {
    ///  shared ref to corestore
    corestore: Arc<RwLock<builder::InnerCorstore>>,
    /// The same event bus the inner store sends on, kept outside its lock so subscribing never
    /// waits for, or misses events because of, a store operation in progress.
    events: events::Events,
}

impl Corestore {
    fn read(&self) -> RwLockReadGuard<'_, builder::InnerCorstore> {
        self.corestore.read().expect("corestore lock poisoned")
    }

    fn write(&self) -> RwLockWriteGuard<'_, builder::InnerCorstore> {
        self.corestore.write().expect("corestore lock poisoned")
    }

    /// Get the [`VerifyingKey`] that corresponds to a [`DiscoveryKey`], among the cores that
    /// have finished opening.
    pub fn verifying_key_from_discovery_key(&self, dk: &DiscoveryKey) -> Option<VerifyingKey> {
        self.read().verifying_key_from_discovery_key(dk)
    }

    /// The [`VerifyingKey`]s of every core that has finished opening.
    pub(crate) fn verifying_keys(&self) -> Vec<VerifyingKey> {
        self.read().verifying_keys()
    }

    /// Get a hypercore by name. If the core does not exist, create it.
    pub async fn get_from_name(&self, name: &str) -> Result<Hypercore> {
        let primary_key = self.read().primary_key();
        let key_pair = key_pair_from_name(primary_key, &DEFAULT_NAMESPACE, name)?;
        self.get_core(key_pair).await
    }

    /// Get a core from its [`VerifyingKey`]. With no secret key, it is read-only.
    pub async fn get_from_verifying_key(&self, verifying_key: &VerifyingKey) -> Result<Hypercore> {
        self.get_core(PartialKeypair {
            public: *verifying_key,
            secret: None,
        })
        .await
    }

    /// Get the core for `key_pair`, creating it if needed. Callers asking for a core that is
    /// already being created wait on that same creation, so a key never gets two cores, and
    /// the lock is never held while a core is being created.
    async fn get_core(&self, key_pair: PartialKeypair) -> Result<Hypercore> {
        let verifying_key = key_pair.public;
        let opening = {
            let mut inner = self.write();
            match inner.core_cache.get(&verifying_key) {
                Some(CachedCore::Ready(core)) => return Ok(core),
                Some(CachedCore::Opening(opening)) => opening,
                None => {
                    let storage = inner.storage().clone();
                    let opening = async move {
                        storage
                            .get_core_from_key_pair(key_pair)
                            .await
                            .map_err(Arc::new)
                    }
                    .boxed()
                    .shared();
                    inner
                        .core_cache
                        .insert_opening(verifying_key, opening.clone());
                    opening
                }
            }
        };

        let opened = opening.clone().await;

        // Whoever finishes first settles the entry. Leave it alone if it has already changed.
        let newly_ready = {
            let mut inner = self.write();
            let still_opening = matches!(
                inner.core_cache.get(&verifying_key),
                Some(CachedCore::Opening(current)) if current.ptr_eq(&opening)
            );
            match &opened {
                Ok(core) if still_opening => {
                    inner.core_cache.insert_ready(verifying_key, core.clone());
                    true
                }
                // Forget the failure, so asking again retries.
                Err(_) if still_opening => {
                    inner.core_cache.remove(&verifying_key);
                    false
                }
                _ => false,
            }
        };
        if newly_ready {
            let _ = self.events.send(CorestoreEvents::CoreAdded(verifying_key));
        }
        opened.map_err(Error::Opening)
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

    /// Subscribe to [`CorestoreEvents`], such as a core being added. Never waits on the store.
    pub(crate) fn subscribe(&self) -> tokio::sync::broadcast::Receiver<CorestoreEvents> {
        self.events.subscribe()
    }

    /// Start replicating every core in this store over `stream`, multiplexed via one
    /// `hypercore_protocol` connection — mirrors JS corestore's `.replicate()`
    /// (`corestore/index.js:481`). Poll (or `.await`) the returned [`CorestoreConnection`]
    /// to drive it. Cores opened in this store *after* this is called are attached as soon as
    /// they are added.
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
        // is called still get attached (from their `CoreAdded` events), not just
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

    /// `hrss`'s reader opens its feed cores after the connection is running and quiet, once it
    /// has read their keys from a bootstrap core. The connection used to wake on `CoreAdded`
    /// while the store was still locked, find nothing with its non-blocking lookups, and never
    /// be woken again, so the core never got a channel. That can't happen now, since the event
    /// carries the key and lookups don't fail, but the scenario is what has to keep working.
    #[tokio::test]
    async fn a_core_opened_after_the_connection_goes_quiet_replicates() -> Result<()> {
        let (cs_a, cs_b) = (Corestore::new_mem().await, Corestore::new_mem().await);
        let (a, b) = create_connected_streams();

        // A core both sides have from the start, standing in for `hrss`'s keys core.
        let bootstrap_a = cs_a.get_from_name("bootstrap").await?;
        bootstrap_a.append(b"bootstrap").await?;
        let bootstrap_b = cs_b
            .get_from_verifying_key(&bootstrap_a.key_pair().public)
            .await?;
        let late_a = cs_a.get_from_name("late").await?;
        late_a.append(b"late hello").await?;

        tokio::spawn(cs_a.replicate(a));
        tokio::spawn(cs_b.replicate(b));
        tokio::time::timeout(Duration::from_secs(5), async {
            while bootstrap_b.get(0).await?.is_none() {
                sleep(Duration::from_millis(25)).await;
            }
            Ok::<(), Error>(())
        })
        .await
        .expect("the bootstrap core should replicate")?;

        let late_b = cs_b
            .get_from_verifying_key(&late_a.key_pair().public)
            .await?;

        let replicated = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(block) = late_b.get(0).await? {
                    return Ok::<_, Error>(block);
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("a core opened late should still get a channel")?;
        assert_eq!(replicated, b"late hello");
        Ok(())
    }

    /// Two callers opening the same new key at once must share one core. Two cores for one
    /// key would mean two writers on the same storage. On disk, because creating an in-memory
    /// core never yields, so two opens of one would never overlap.
    #[tokio::test]
    async fn concurrent_opens_of_one_key_share_one_core() -> Result<()> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = Corestore::new_disk(tmp.path()).await?;

        let (first, second) =
            tokio::join!(store.get_from_name("feed"), store.get_from_name("feed"));
        let (first, second) = (first?, second?);
        first.append(b"hello").await?;

        assert_eq!(second.info().length, 1, "both handles are the same core");
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_opens_announce_the_core_once() -> Result<()> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = Corestore::new_disk(tmp.path()).await?;
        let mut events = store.subscribe();

        let (first, second) =
            tokio::join!(store.get_from_name("feed"), store.get_from_name("feed"));
        let vk = first?.key_pair().public;
        second?;

        assert!(matches!(events.try_recv(), Ok(CorestoreEvents::CoreAdded(added)) if added == vk));
        assert!(events.try_recv().is_err(), "announced only once");
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_open_can_be_retried() -> Result<()> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = Corestore::new_disk(tmp.path()).await?;
        let key_pair = key_pair_from_name(store.read().primary_key(), &DEFAULT_NAMESPACE, "feed")?;
        // A file where the core's storage directory should go.
        let blocker = tmp.path().join(get_storage_root(&key_pair));
        std::fs::create_dir_all(blocker.parent().unwrap()).unwrap();
        std::fs::write(&blocker, b"not a directory").unwrap();

        assert!(matches!(
            store.get_from_name("feed").await,
            Err(Error::Opening(_))
        ));
        assert!(
            store.read().core_cache.get(&key_pair.public).is_none(),
            "a failure is not cached"
        );

        std::fs::remove_file(&blocker).unwrap();
        let core = store.get_from_name("feed").await?;
        assert_eq!(core.key_pair().public, key_pair.public);
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
