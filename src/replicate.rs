//! Multiplexed replication: many [`Hypercore`](hypercore::Hypercore)s over one connection.
//!
//! Mirrors JS corestore's `replicate()` (`js/corestore/index.js:481`): one
//! [`hypercore_protocol::Protocol`] (the muxer) is shared by every core in the store, each
//! core running its own replication session on its own channel of that muxer. This is what
//! lets a [`crate::Corestore`] replicate an arbitrary number of cores over a single physical
//! connection instead of needing one connection per core.

use std::{
    collections::HashSet,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{stream::FuturesUnordered, Stream};
use hypercore::VerifyingKey;
use hypercore_handshake::CipherTrait;
use hypercore_protocol::{Event, Protocol};
use tokio_stream::wrappers::{errors::BroadcastStreamRecvError, BroadcastStream};
use tracing::{trace, warn};

use crate::{Corestore, CorestoreEvents, Error};

type BoxIoFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
type BoxAttachFuture = Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;
type BoxKeysFuture = Pin<Box<dyn Future<Output = Vec<VerifyingKey>> + Send>>;

/// Drives replication for every core in a [`Corestore`] over one physical connection.
///
/// Every core in the store is attached once the handshake completes. Cores opened later (via
/// [`Corestore::get_from_name`]/[`Corestore::get_from_verifying_key`]) are attached as soon as
/// they are added, and a core the *remote* peer opens that we also have locally as soon as its
/// `DiscoveryKey` announcement arrives. Resolves once the underlying connection closes.
///
/// Nothing here gives up on a locked store: every lookup waits for the lock. Skipping a lookup
/// while a core was being added used to lose that core for good, since the wakeup that would
/// have retried it had already been used.
pub struct CorestoreConnection {
    store: Corestore,
    protocol: Protocol,
    handshake_done: bool,
    opened: HashSet<VerifyingKey>,
    pending_opens: FuturesUnordered<BoxIoFuture>,
    active: FuturesUnordered<BoxAttachFuture>,
    /// Lookups in the store for keys to open on this connection.
    key_lookups: FuturesUnordered<BoxKeysFuture>,
    /// The store's events, subscribed to as soon as this connection exists.
    store_events: BroadcastStream<CorestoreEvents>,
}

impl std::fmt::Debug for CorestoreConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CorestoreConnection")
            .field("opened_count", &self.opened.len())
            .field("active_count", &self.active.len())
            .finish_non_exhaustive()
    }
}

impl CorestoreConnection {
    pub(crate) fn new(store: Corestore, stream: impl CipherTrait + 'static) -> Self {
        let store_events = BroadcastStream::new(store.subscribe());
        Self {
            store,
            protocol: Protocol::new(Box::new(stream)),
            handshake_done: false,
            opened: HashSet::new(),
            pending_opens: FuturesUnordered::new(),
            active: FuturesUnordered::new(),
            key_lookups: FuturesUnordered::new(),
            store_events,
        }
    }

    /// Open a channel for the core with this key, unless this connection already has one.
    fn open_core(&mut self, vk: VerifyingKey) {
        if self.opened.insert(vk) {
            trace!(?vk, "corestore: opening channel for core");
            self.pending_opens
                .push(Box::pin(self.protocol.open(vk.to_bytes())));
        }
    }

    /// Look up every core in the store and open the ones this connection doesn't have yet.
    fn open_every_core(&mut self) {
        let store = self.store.clone();
        self.key_lookups
            .push(Box::pin(async move { store.verifying_keys().await }));
    }

    fn on_store_event(&mut self, event: Result<CorestoreEvents, BroadcastStreamRecvError>) {
        // Before the handshake there is nothing to open on; the handshake opens every core.
        if !self.handshake_done {
            return;
        }
        match event {
            Ok(CorestoreEvents::CoreAdded(vk)) => self.open_core(vk),
            Ok(CorestoreEvents::Shutdown) => {}
            Err(BroadcastStreamRecvError::Lagged(missed)) => {
                warn!(
                    missed,
                    "corestore: missed store events, rechecking every core"
                );
                self.open_every_core();
            }
        }
    }

    fn on_event(&mut self, event: Event) {
        match event {
            Event::Handshake(_) => {
                self.handshake_done = true;
                self.open_every_core();
            }
            Event::DiscoveryKey(dk) => {
                // The remote opened a channel for a core we may have locally but haven't
                // opened on this connection yet (e.g. we only just learned this key
                // ourselves via a `keys`-core-style discovery flow).
                let store = self.store.clone();
                self.key_lookups.push(Box::pin(async move {
                    store
                        .verifying_key_from_discovery_key(&dk)
                        .await
                        .into_iter()
                        .collect()
                }));
            }
            Event::Channel(channel) => {
                let dk = *channel.discovery_key();
                let store = self.store.clone();
                self.active.push(Box::pin(async move {
                    let Some(vk) = store.verifying_key_from_discovery_key(&dk).await else {
                        warn!("channel opened for a discovery key with no matching core");
                        return Ok(());
                    };
                    let core = store.get_from_verifying_key(&vk).await?;
                    Ok(core.attach_channel(channel).await?)
                }));
            }
            Event::Close(_) | Event::LocalSignal(_) => {}
            _ => {}
        }
    }
}

impl Future for CorestoreConnection {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        // Run repeated passes over every stage until a full pass makes no progress.
        // A single one-shot pass isn't enough: handling a protocol event (e.g.
        // `Handshake`) can push a new future into `pending_opens`, which a prior,
        // already-completed pass over `pending_opens` would never come back to poll
        // in this same wakeup — stranding it unsent until some unrelated event wakes
        // this task again (which may never happen, deadlocking both peers).
        loop {
            let mut progressed = false;

            // This connection's `Corestore` holds a sender, so the stream never ends.
            while let Poll::Ready(Some(event)) = Pin::new(&mut this.store_events).poll_next(cx) {
                this.on_store_event(event);
                progressed = true;
            }

            while let Poll::Ready(Some(keys)) = Pin::new(&mut this.key_lookups).poll_next(cx) {
                for vk in keys {
                    this.open_core(vk);
                }
                progressed = true;
            }

            loop {
                match Pin::new(&mut this.pending_opens).poll_next(cx) {
                    Poll::Ready(Some(Ok(()))) => progressed = true,
                    Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e.into())),
                    Poll::Ready(None) | Poll::Pending => break,
                }
            }

            loop {
                match Pin::new(&mut this.protocol).poll_next(cx) {
                    Poll::Ready(Some(Ok(event))) => {
                        this.on_event(event);
                        progressed = true;
                    }
                    Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e.into())),
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => break,
                }
            }

            loop {
                match Pin::new(&mut this.active).poll_next(cx) {
                    Poll::Ready(Some(Ok(()))) => progressed = true,
                    Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                    Poll::Ready(None) | Poll::Pending => break,
                }
            }

            if !progressed {
                return Poll::Pending;
            }
        }
    }
}
