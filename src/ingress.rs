//! Bounded per-connection packet mailboxes, separate from real-time PCM exchange.

use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::{collections::HashMap, num::NonZeroUsize, time::Instant};
use tokio::sync::Notify;
use tokio::sync::mpsc::{self, Receiver, Sender, error::TrySendError};

/// Maximum UDP payload retained by one queued IAX datagram.
pub const MAX_DATAGRAM_SIZE: usize = 1500;

/// Why a producer-owner ingress queue could not be created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressError {
    /// A bounded queue must have at least one slot.
    ZeroCapacity,
}

/// Why a datagram could not be queued by one ingress producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressPushError {
    /// The sole connection owner has gone away; no more work can be admitted.
    Closed,
    /// The datagram is larger than the fixed packet storage.
    DatagramTooLarge {
        /// Number of bytes in the rejected datagram.
        length: usize,
    },
    /// The bounded queue is full; the new datagram was not accepted.
    Full,
}

/// Why a bounded network-owner ingress route could not be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerIngressRouterError {
    /// The per-peer queue configuration is invalid.
    Ingress(IngressError),
    /// A peer address already has a route.
    DuplicatePeer,
    /// A call route contains a zero or out-of-range 15-bit call number.
    InvalidCallNumbers,
    /// Bookkeeping could not be reserved; existing routes are unchanged.
    Allocation,
    /// No route is registered for this packet source.
    UnknownPeer,
    /// A mini frame matches more than one call for this UDP endpoint.
    AmbiguousCall,
    /// The datagram is larger than fixed packet storage.
    DatagramTooLarge {
        /// Number of bytes in the rejected datagram.
        length: usize,
    },
    /// The peer's bounded queue is full; the new datagram was dropped.
    Full,
}

/// Observable occupancy and drop count for one routed peer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IngressStats {
    /// Number of packets waiting for the peer owner.
    pub queued_packets: usize,
    /// Number of packets rejected because its queue was full.
    pub dropped_packets: u64,
    /// Maximum number of packets retained by this queue.
    pub capacity_packets: usize,
}

/// One copied datagram handed to a peer's serialized media owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundDatagram {
    generation: u64,
    arrived_at: Instant,
    remote: SocketAddr,
    length: usize,
    payload: [u8; MAX_DATAGRAM_SIZE],
}

impl InboundDatagram {
    /// Monotonic socket-receipt time, retained independently of executor delay.
    pub const fn arrived_at(&self) -> Instant {
        self.arrived_at
    }

    /// Peer/session generation assigned when this producer-owner pair was created.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// UDP source address associated with this packet.
    pub const fn remote(&self) -> SocketAddr {
        self.remote
    }

    /// Borrow the received datagram bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.length]
    }
}

/// Cloneable packet admission handle; all clones feed the same exclusive owner.
#[derive(Clone)]
pub struct IngressProducer {
    queue: Sender<InboundDatagram>,
    generation: u64,
    wake: IngressWake,
}

impl IngressProducer {
    /// Publish a terminal socket failure without waiting for packet-queue capacity.
    pub fn fail(&self) {
        self.wake.0.failed.store(true, Ordering::Release);
        self.wake.0.ready.notify_one();
    }

    /// Admit a datagram immediately, recording receipt at this call.
    pub fn try_push(&mut self, remote: SocketAddr, payload: &[u8]) -> Result<(), IngressPushError> {
        self.try_push_at(remote, payload, Instant::now())
    }

    /// Copy a socket-received datagram without waiting for queue space.
    ///
    /// This non-audio mailbox may allocate Tokio queue blocks. Admission order
    /// is preserved; receive timestamps prevent executor batching from becoming
    /// apparent network jitter. PCM consumers never enter this mailbox.
    pub fn try_push_at(
        &mut self,
        remote: SocketAddr,
        payload: &[u8],
        arrived_at: Instant,
    ) -> Result<(), IngressPushError> {
        if payload.len() > MAX_DATAGRAM_SIZE {
            return Err(IngressPushError::DatagramTooLarge {
                length: payload.len(),
            });
        }
        let mut packet = InboundDatagram {
            generation: self.generation,
            arrived_at,
            remote,
            length: payload.len(),
            payload: [0; MAX_DATAGRAM_SIZE],
        };
        packet.payload[..payload.len()].copy_from_slice(payload);
        // Increment before publication: the consumer may remove the packet immediately.
        self.wake.0.pending.fetch_add(1, Ordering::AcqRel);
        self.queue.try_send(packet).map_err(|error| {
            self.wake.0.pending.fetch_sub(1, Ordering::AcqRel);
            match error {
                TrySendError::Full(_) => {
                    let _ = self.wake.0.dropped.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |count| Some(count.saturating_add(1)),
                    );
                    IngressPushError::Full
                }
                TrySendError::Closed(_) => IngressPushError::Closed,
            }
        })?;
        self.wake.0.ready.notify_one();
        Ok(())
    }

    /// Number of slots currently available to this producer.
    pub fn available_slots(&self) -> usize {
        self.queue.capacity()
    }

    fn stats(&self) -> IngressStats {
        IngressStats {
            queued_packets: self.queue.max_capacity() - self.queue.capacity(),
            dropped_packets: self.wake.0.dropped.load(Ordering::Relaxed),
            capacity_packets: self.queue.max_capacity(),
        }
    }
}

/// The sole peer-owner consumer handle for one bounded packet queue.
pub struct IngressConsumer {
    queue: Receiver<InboundDatagram>,
    wake: IngressWake,
}

/// Readiness only; cloning this handle never grants packet-consumer ownership.
#[derive(Clone, Default)]
pub struct IngressWake(Arc<IngressReadiness>);

#[derive(Default)]
struct IngressReadiness {
    ready: Notify,
    pending: AtomicUsize,
    failed: AtomicBool,
    dropped: AtomicU64,
}

impl IngressWake {
    /// Wait for a successful enqueue, retaining a notification received before this wait.
    pub async fn notified(&self) {
        self.0.ready.notified().await;
    }

    /// Remaining work after a bounded drain; coalesced notifications do not lose backlog.
    pub fn pending(&self) -> usize {
        self.0.pending.load(Ordering::Acquire)
    }
}

struct PeerRoute {
    generation: u64,
    producer: IngressProducer,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum PeerRouteKey {
    Address(SocketAddr),
    Call {
        remote: SocketAddr,
        local_call: u16,
        remote_call: u16,
    },
}

/// Nonblocking datagram dispatcher owned by the network receive context.
///
/// Registration allocates one bounded queue per peer. Packet routing only
/// looks up the source and attempts admission without waiting for queue space.
pub struct PeerIngressRouter {
    routes: HashMap<PeerRouteKey, PeerRoute>,
    queue_capacity: NonZeroUsize,
    #[cfg(test)]
    pub(crate) fail_next_reserve: bool,
}

impl PeerIngressRouter {
    /// Create a resource-scaled router with a fixed per-peer packet limit.
    pub fn new(queue_capacity: usize) -> Result<Self, PeerIngressRouterError> {
        let queue_capacity = NonZeroUsize::new(queue_capacity)
            .ok_or(PeerIngressRouterError::Ingress(IngressError::ZeroCapacity))?;
        Ok(Self {
            routes: HashMap::new(),
            queue_capacity,
            #[cfg(test)]
            fail_next_reserve: false,
        })
    }

    /// Register one source address and return its sole consumer handle.
    pub fn register(
        &mut self,
        remote: SocketAddr,
        generation: u64,
    ) -> Result<IngressConsumer, PeerIngressRouterError> {
        self.register_route(PeerRouteKey::Address(remote), generation)
    }

    /// Register one IAX call from a remote endpoint and return its sole consumer.
    pub fn register_call(
        &mut self,
        remote: SocketAddr,
        local_call: u16,
        remote_call: u16,
        generation: u64,
    ) -> Result<IngressConsumer, PeerIngressRouterError> {
        if local_call == 0 || local_call > 0x7fff || remote_call == 0 || remote_call > 0x7fff {
            return Err(PeerIngressRouterError::InvalidCallNumbers);
        }
        self.register_route(
            PeerRouteKey::Call {
                remote,
                local_call,
                remote_call,
            },
            generation,
        )
    }

    /// Remove one established call route after its terminal datagram was queued.
    pub fn remove_call(&mut self, remote: SocketAddr, local_call: u16, remote_call: u16) -> bool {
        self.routes
            .remove(&PeerRouteKey::Call {
                remote,
                local_call,
                remote_call,
            })
            .is_some()
    }

    /// Whether any current peer owns this local call number.
    pub fn contains_local_call(&self, local_call: u16) -> bool {
        self.routes.keys().any(
            |key| matches!(key, PeerRouteKey::Call { local_call: call, .. } if *call == local_call),
        )
    }

    fn register_route(
        &mut self,
        key: PeerRouteKey,
        generation: u64,
    ) -> Result<IngressConsumer, PeerIngressRouterError> {
        if self.routes.contains_key(&key) {
            return Err(PeerIngressRouterError::DuplicatePeer);
        }
        let reserved = self.routes.try_reserve(1).is_ok();
        #[cfg(test)]
        let reserved = reserved && !std::mem::take(&mut self.fail_next_reserve);
        if !reserved {
            return Err(PeerIngressRouterError::Allocation);
        }
        let (producer, consumer) = new_ingress(self.queue_capacity, generation);
        self.routes.insert(
            key,
            PeerRoute {
                generation,
                producer,
            },
        );
        Ok(consumer)
    }

    /// Route one received datagram without waiting for queue space.
    pub fn route(
        &mut self,
        remote: SocketAddr,
        payload: &[u8],
    ) -> Result<(), PeerIngressRouterError> {
        self.route_key(
            PeerRouteKey::Address(remote),
            remote,
            payload,
            Instant::now(),
        )
    }

    /// Route a datagram to the exact local/remote call pair for one endpoint.
    pub fn route_call(
        &mut self,
        remote: SocketAddr,
        local_call: u16,
        remote_call: u16,
        payload: &[u8],
    ) -> Result<(), PeerIngressRouterError> {
        self.route_call_at(remote, local_call, remote_call, payload, Instant::now())
    }

    /// Route a full frame while preserving its original socket-receipt time.
    pub fn route_call_at(
        &mut self,
        remote: SocketAddr,
        local_call: u16,
        remote_call: u16,
        payload: &[u8],
        arrived_at: Instant,
    ) -> Result<(), PeerIngressRouterError> {
        let key = PeerRouteKey::Call {
            remote,
            local_call,
            remote_call,
        };
        if self.routes.contains_key(&key) {
            return self.route_key(key, remote, payload, arrived_at);
        }
        if self.has_call_routes(remote) {
            Err(PeerIngressRouterError::UnknownPeer)
        } else {
            self.route_key(PeerRouteKey::Address(remote), remote, payload, arrived_at)
        }
    }

    /// Route a mini frame by endpoint and its only call identifier.
    pub fn route_remote_call(
        &mut self,
        remote: SocketAddr,
        remote_call: u16,
        payload: &[u8],
    ) -> Result<(), PeerIngressRouterError> {
        self.route_remote_call_at(remote, remote_call, payload, Instant::now())
    }

    /// Route a mini frame while preserving its original socket-receipt time.
    pub fn route_remote_call_at(
        &mut self,
        remote: SocketAddr,
        remote_call: u16,
        payload: &[u8],
        arrived_at: Instant,
    ) -> Result<(), PeerIngressRouterError> {
        let mut matching_key = None;
        for key in self.routes.keys() {
            if matches!(key, PeerRouteKey::Call { remote: address, remote_call: number, .. } if *address == remote && *number == remote_call)
            {
                if matching_key.is_some() {
                    return Err(PeerIngressRouterError::AmbiguousCall);
                }
                matching_key = Some(*key);
            }
        }
        if let Some(key) = matching_key {
            return self.route_key(key, remote, payload, arrived_at);
        }
        if self.has_call_routes(remote) {
            Err(PeerIngressRouterError::UnknownPeer)
        } else {
            self.route_key(PeerRouteKey::Address(remote), remote, payload, arrived_at)
        }
    }

    fn has_call_routes(&self, remote: SocketAddr) -> bool {
        self.routes.keys().any(
            |key| matches!(key, PeerRouteKey::Call { remote: address, .. } if *address == remote),
        )
    }

    fn route_key(
        &mut self,
        key: PeerRouteKey,
        remote: SocketAddr,
        payload: &[u8],
        arrived_at: Instant,
    ) -> Result<(), PeerIngressRouterError> {
        let route = self
            .routes
            .get_mut(&key)
            .ok_or(PeerIngressRouterError::UnknownPeer)?;
        match route.producer.try_push_at(remote, payload, arrived_at) {
            Ok(()) => Ok(()),
            Err(IngressPushError::Closed) => Err(PeerIngressRouterError::UnknownPeer),
            Err(IngressPushError::Full) => Err(PeerIngressRouterError::Full),
            Err(IngressPushError::DatagramTooLarge { length }) => {
                Err(PeerIngressRouterError::DatagramTooLarge { length })
            }
        }
    }

    pub(crate) fn fail_all(&self) {
        for route in self.routes.values() {
            route.producer.fail();
        }
    }

    pub(crate) fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Remove a peer route only when the caller still owns its generation.
    pub fn unregister(&mut self, remote: SocketAddr, generation: u64) -> bool {
        self.unregister_route(PeerRouteKey::Address(remote), generation)
    }

    /// Remove a call route only when the caller still owns its generation.
    pub fn unregister_call(
        &mut self,
        remote: SocketAddr,
        local_call: u16,
        remote_call: u16,
        generation: u64,
    ) -> bool {
        self.unregister_route(
            PeerRouteKey::Call {
                remote,
                local_call,
                remote_call,
            },
            generation,
        )
    }

    fn unregister_route(&mut self, key: PeerRouteKey, generation: u64) -> bool {
        if self
            .routes
            .get(&key)
            .is_some_and(|route| route.generation == generation)
        {
            self.routes.remove(&key);
            true
        } else {
            false
        }
    }

    /// Return current queue occupancy and rejected-full-packet count.
    pub fn stats(&self, remote: SocketAddr) -> Option<IngressStats> {
        self.stats_route(PeerRouteKey::Address(remote))
    }

    /// Return current occupancy and full-queue drops for one IAX call.
    pub fn call_stats(
        &self,
        remote: SocketAddr,
        local_call: u16,
        remote_call: u16,
    ) -> Option<IngressStats> {
        self.stats_route(PeerRouteKey::Call {
            remote,
            local_call,
            remote_call,
        })
    }

    fn stats_route(&self, key: PeerRouteKey) -> Option<IngressStats> {
        let route = self.routes.get(&key)?;
        Some(route.producer.stats())
    }
}

impl IngressConsumer {
    /// Snapshot actual queue occupancy/capacity and all producers' full-queue drops.
    /// Fields are sampled independently while producers may still be active.
    pub fn stats(&self) -> IngressStats {
        IngressStats {
            queued_packets: self.queue.len(),
            dropped_packets: self.wake.0.dropped.load(Ordering::Relaxed),
            capacity_packets: self.queue.max_capacity(),
        }
    }

    /// Whether the receive owner reported a terminal transport failure.
    pub fn failed(&self) -> bool {
        self.wake.0.failed.load(Ordering::Acquire)
    }

    /// Borrow readiness independently from the unique peer-owned packet consumer.
    pub fn wake(&self) -> IngressWake {
        self.wake.clone()
    }

    /// Suspend only this connection owner until its next packet or final sender closes.
    pub async fn receive(&mut self) -> Option<InboundDatagram> {
        let packet = self.queue.recv().await?;
        self.wake.0.pending.fetch_sub(1, Ordering::AcqRel);
        Some(packet)
    }

    /// Remove the oldest packet, or return `None` when the queue is empty.
    pub fn try_pop(&mut self) -> Option<InboundDatagram> {
        let packet = self.queue.try_recv().ok()?;
        self.wake.0.pending.fetch_sub(1, Ordering::AcqRel);
        Some(packet)
    }
}

/// Allocate a bounded packet mailbox for one exclusively owned connection.
///
/// Producers may be cloned; the consumer remains unique. Old producers cannot
/// reach a replacement mailbox after a session generation is retired. This is
/// non-audio work; the shared PCM ring keeps its independent lock-free boundary.
pub fn producer_ingress(
    capacity: usize,
    peer_generation: u64,
) -> Result<(IngressProducer, IngressConsumer), IngressError> {
    let capacity = NonZeroUsize::new(capacity).ok_or(IngressError::ZeroCapacity)?;
    Ok(new_ingress(capacity, peer_generation))
}

fn new_ingress(capacity: NonZeroUsize, peer_generation: u64) -> (IngressProducer, IngressConsumer) {
    let (producer, consumer) = mpsc::channel(capacity.get());
    let wake = IngressWake::default();
    (
        IngressProducer {
            queue: producer,
            generation: peer_generation,
            wake: wake.clone(),
        },
        IngressConsumer {
            queue: consumer,
            wake,
        },
    )
}
