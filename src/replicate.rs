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

use futures::{Stream, stream::FuturesUnordered};
use hypercore::VerifyingKey;
use hypercore_handshake::CipherTrait;
use hypercore_protocol::{Event, Protocol};
use tokio_stream::wrappers::BroadcastStream;
use tracing::{trace, warn};

use crate::{Corestore, CorestoreEvents, Error};

type BoxIoFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
type BoxAttachFuture = Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;

/// Drives replication for every core in a [`Corestore`] over one physical connection.
///
/// Every core currently in the store is attached up front. Cores opened later (via
/// [`Corestore::get_from_name`]/[`Corestore::get_from_verifying_key`]) are attached the next
/// time this is polled; a core the *remote* peer opens that we also have locally is attached
/// as soon as its `DiscoveryKey` announcement arrives. Resolves once the underlying
/// connection closes.
pub struct CorestoreConnection {
    store: Corestore,
    protocol: Protocol,
    handshake_done: bool,
    opened: HashSet<VerifyingKey>,
    pending_opens: FuturesUnordered<BoxIoFuture>,
    active: FuturesUnordered<BoxAttachFuture>,
    core_added: Option<BroadcastStream<CorestoreEvents>>,
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
        Self {
            store,
            protocol: Protocol::new(Box::new(stream)),
            handshake_done: false,
            opened: HashSet::new(),
            pending_opens: FuturesUnordered::new(),
            active: FuturesUnordered::new(),
            core_added: None,
        }
    }

    /// Subscribe to the store's `CoreAdded` events if not already subscribed, so a core opened
    /// well after this connection is running (e.g. once a caller learns a key via some other
    /// bootstrap core) wakes this task immediately instead of waiting for incidental protocol
    /// activity to trigger another poll. Retries later if the store is momentarily locked.
    fn ensure_subscribed(&mut self) {
        if self.core_added.is_none() {
            self.core_added = self.store.try_subscribe().map(BroadcastStream::new);
        }
    }

    /// Call `protocol.open()` for every core in the store we haven't already opened on this
    /// connection. Non-blocking: skips cores if the store is momentarily locked, and picks
    /// them up on a later poll instead. A no-op until the handshake completes — `Protocol`
    /// can't send `Open` messages before then (mirrors `core/`'s `ConnectionReplicator`,
    /// which only calls `.open()` in reaction to `Handshake`/`DiscoveryKey` events).
    fn open_new_cores(&mut self) {
        if !self.handshake_done {
            return;
        }
        for vk in self.store.try_verifying_keys() {
            if self.opened.insert(vk) {
                trace!(?vk, "corestore: opening channel for core");
                self.pending_opens.push(Box::pin(self.protocol.open(vk.to_bytes())));
            }
        }
    }

    fn on_event(&mut self, event: Event) {
        match event {
            Event::Handshake(_) => {
                self.handshake_done = true;
                self.open_new_cores();
            }
            Event::DiscoveryKey(dk) => {
                // The remote opened a channel for a core we may have locally but haven't
                // opened on this connection yet (e.g. we only just learned this key
                // ourselves via a `keys`-core-style discovery flow).
                if let Some(vk) = self.store.try_verifying_key_from_discovery_key(&dk) {
                    if self.opened.insert(vk) {
                        self.pending_opens.push(Box::pin(self.protocol.open(vk.to_bytes())));
                    }
                }
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

            this.ensure_subscribed();

            // Opportunistically attach any core opened in the store since we last checked.
            this.open_new_cores();

            // Drain `CoreAdded` notifications. We don't need the event's contents — just
            // draining wakes this task promptly when a new core appears (rather than only on
            // incidental protocol activity), and `open_new_cores` above/next pass does the
            // actual attaching.
            if let Some(rx) = &mut this.core_added {
                loop {
                    match Pin::new(&mut *rx).poll_next(cx) {
                        Poll::Ready(Some(_)) => progressed = true,
                        Poll::Ready(None) => {
                            this.core_added = None;
                            break;
                        }
                        Poll::Pending => break,
                    }
                }
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
