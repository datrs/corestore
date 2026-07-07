use delegate::delegate;
use hypercore::Hypercore;
use hypercore_protocol::DiscoveryKey;
use std::sync::Arc;

use crate::{
    events::{Event, Events},
    keys::{key_pair_from_name, DEFAULT_NAMESPACE},
    storage::StorageKind,
    CoreCache, Corestore, Error, PrimaryKey, Result,
};
use hypercore::{PartialKeypair, VerifyingKey};
use tokio::sync::{broadcast::Receiver, RwLock};

#[derive(Debug, derive_builder::Builder)]
#[builder(
    pattern = "owned",
    build_fn(skip),
    derive(Debug),
    name = "CorestoreBuilder"
)]
/// This holds all of [`Corestore`]s data. It gets wrappped with `Arc<Mutex<..>>` to make `Corestore` `Send` & `Sync`.
pub struct InnerCorstore {
    /// The [`PrimaryKey`] used to deterministically derive keys for cores owned by this
    /// [`Corestore`]
    primary_key: PrimaryKey,
    /// The kind of storage that [`Corestore`] will use to store it's data.
    storage: StorageKind,
    #[builder(default = "Default::default()")]
    /// The place we keep active cores
    core_cache: CoreCache,
    /// Emits store events for replication
    #[builder(default = "Default::default()")]
    events: Events,
}

impl CorestoreBuilder {
    /// Build the [`Corestore`]
    pub async fn build(self) -> std::result::Result<Corestore, Error> {
        let Some(storage) = self.storage else {
            return Err(CorestoreBuilderError::UninitializedField("storage").into());
        };
        // Somewhat complicated primary key logic
        let primary_key: PrimaryKey = storage.get_or_create_primary_key(&self.primary_key)?;
        let mut cs = InnerCorstore {
            primary_key,
            storage,
            core_cache: self.core_cache.unwrap_or_default(),
            events: Default::default(),
        };
        for existing_core in cs.storage.load_existing_cores().await? {
            let vk = existing_core.key_pair().public;
            cs.insert_core_into_cache(vk, existing_core);
        }
        Ok(Corestore {
            corestore: Arc::new(RwLock::new(cs)),
        })
    }
}

impl InnerCorstore {
    delegate! {
        to self.core_cache {
            pub fn verifying_key_from_discovery_key(&self, dk: &DiscoveryKey) -> Option<VerifyingKey>;
            pub fn verifying_keys(&self) -> Vec<&VerifyingKey>;
        }
        to self.events {
            pub fn subscribe(&self) -> Receiver<Event>;
        }
    }

    fn insert_core_into_cache(
        &mut self,
        vk: VerifyingKey,
        core: Hypercore,
    ) -> Option<Hypercore> {
        self.core_cache.insert(&vk, core.clone())
    }

    /// Get a hypercore by name. If the core does not exist, create it.
    /// This does... not? work if there is no verifying key.
    /// Or, maybe, all cores get a primary key, but only writable cores use this?
    /// This would imply that a corestore instance could have mixed readable and writable keys...
    pub async fn get_from_name(&mut self, name: &str) -> Result<Hypercore> {
        let kp = key_pair_from_name(self.primary_key, &DEFAULT_NAMESPACE, name)?;

        if let Some(core) = self.core_cache.get(&kp.public) {
            return Ok(core);
        };
        let core = self.storage.get_core_from_key_pair(kp.clone()).await?;
        self.core_cache.insert(&kp.public, core.clone());
        let _ = self.events.send(Event::CoreAdded(kp.public));
        Ok(core)
    }

    /// Get a core from it's [`VerifyingKey`].
    /// Since the core only has a verifyin key (and no [`SigningKey`]). It is read-only.
    pub async fn get_from_verifying_key(
        &mut self,
        verifying_key: &VerifyingKey,
    ) -> Result<Hypercore> {
        if let Some(core) = self.core_cache.get(verifying_key) {
            return Ok(core);
        };
        let kp = PartialKeypair {
            public: *verifying_key,
            secret: None,
        };
        let core = self.storage.get_core_from_key_pair(kp.clone()).await?;
        self.core_cache.insert(&kp.public, core.clone());
        // TODO dry this
        let _ = self.events.send(Event::CoreAdded(kp.public));
        Ok(core)
    }
}
