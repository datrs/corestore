use delegate::delegate;
use hypercore::Hypercore;
use hypercore_protocol::DiscoveryKey;
use std::sync::Arc;

use crate::{events::Events, storage::StorageKind, CoreCache, Corestore, Error, PrimaryKey};
use hypercore::VerifyingKey;
use std::sync::RwLock;

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
    pub(crate) core_cache: CoreCache,
}

impl CorestoreBuilder {
    /// Build the [`Corestore`]
    pub async fn build(self) -> std::result::Result<Corestore, Error> {
        let Some(storage) = self.storage else {
            return Err(CorestoreBuilderError::UninitializedField("storage").into());
        };
        // Somewhat complicated primary key logic
        let primary_key: PrimaryKey = storage.get_or_create_primary_key(&self.primary_key)?;
        let events = Events::default();
        let mut cs = InnerCorstore {
            primary_key,
            storage,
            core_cache: self.core_cache.unwrap_or_default(),
        };
        for existing_core in cs.storage.load_existing_cores().await? {
            let vk = existing_core.key_pair().public;
            cs.insert_core_into_cache(vk, existing_core);
        }
        Ok(Corestore {
            corestore: Arc::new(RwLock::new(cs)),
            events,
        })
    }
}

impl InnerCorstore {
    delegate! {
        to self.core_cache {
            pub fn verifying_key_from_discovery_key(&self, dk: &DiscoveryKey) -> Option<VerifyingKey>;
            pub fn verifying_keys(&self) -> Vec<VerifyingKey>;
        }
    }

    fn insert_core_into_cache(&mut self, vk: VerifyingKey, core: Hypercore) {
        self.core_cache.insert_ready(vk, core)
    }

    pub(crate) fn primary_key(&self) -> PrimaryKey {
        self.primary_key
    }

    pub(crate) fn storage(&self) -> &StorageKind {
        &self.storage
    }
}
