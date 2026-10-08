//! Fixed-storage SPSC handoff for one ingress-producer-to-peer-owner pair.

use rtrb::{Consumer, Producer, PushError, RingBuffer};
use std::net::SocketAddr;
use std::{collections::HashMap, num::NonZeroUsize};

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
    /// A router must be configured to admit at least one peer.
    ZeroPeerLimit,
    /// The per-peer queue configuration is invalid.
    Ingress(IngressError),
    /// A peer address already has a route.
    DuplicatePeer,
    /// A call route contains a zero or out-of-range 15-bit call number.
    InvalidCallNumbers,
    /// The configured peer limit has been reached.
    PeerLimit,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngressStats {
    /// Number of packets waiting for the peer owner.
    pub queued_packets: usize,
    /// Number of packets rejected because its queue was full.
    pub dropped_packets: u64,
}

/// One copied datagram handed to a peer's serialized media owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundDatagram {
    generation: u64,
    remote: SocketAddr,
    length: usize,
    payload: [u8; MAX_DATAGRAM_SIZE],
}

impl InboundDatagram {
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

/// The sole producer handle for one bounded packet queue.
pub struct IngressProducer {
    queue: Producer<InboundDatagram>,
    generation: u64,
}

impl IngressProducer {
    /// Copy one datagram into the queue without blocking or allocating.
    pub fn try_push(&mut self, remote: SocketAddr, payload: &[u8]) -> Result<(), IngressPushError> {
        if payload.len() > MAX_DATAGRAM_SIZE {
            return Err(IngressPushError::DatagramTooLarge {
                length: payload.len(),
            });
        }
        let mut packet = InboundDatagram {
            generation: self.generation,
            remote,
            length: payload.len(),
            payload: [0; MAX_DATAGRAM_SIZE],
        };
        packet.payload[..payload.len()].copy_from_slice(payload);
        self.queue
            .push(packet)
            .map_err(|PushError::Full(_)| IngressPushError::Full)
    }

    /// Number of slots currently available to this producer.
    pub fn available_slots(&self) -> usize {
        self.queue.slots()
    }
}

/// The sole peer-owner consumer handle for one bounded packet queue.
pub struct IngressConsumer {
    queue: Consumer<InboundDatagram>,
}

struct PeerRoute {
    generation: u64,
    producer: IngressProducer,
    dropped_packets: u64,
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
/// looks up the source and pushes into that peer's SPSC queue.
pub struct PeerIngressRouter {
    routes: HashMap<PeerRouteKey, PeerRoute>,
    peer_limit: usize,
    queue_capacity: NonZeroUsize,
}

impl PeerIngressRouter {
    /// Create a router with fixed peer and per-peer packet limits.
    pub fn new(peer_limit: usize, queue_capacity: usize) -> Result<Self, PeerIngressRouterError> {
        if peer_limit == 0 {
            return Err(PeerIngressRouterError::ZeroPeerLimit);
        }
        let queue_capacity = NonZeroUsize::new(queue_capacity)
            .ok_or(PeerIngressRouterError::Ingress(IngressError::ZeroCapacity))?;
        Ok(Self {
            routes: HashMap::with_capacity(peer_limit),
            peer_limit,
            queue_capacity,
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
        if self.routes.len() == self.peer_limit {
            return Err(PeerIngressRouterError::PeerLimit);
        }
        let (producer, consumer) = new_ingress(self.queue_capacity, generation);
        self.routes.insert(
            key,
            PeerRoute {
                generation,
                producer,
                dropped_packets: 0,
            },
        );
        Ok(consumer)
    }

    /// Route one received datagram without waiting or allocating.
    pub fn route(
        &mut self,
        remote: SocketAddr,
        payload: &[u8],
    ) -> Result<(), PeerIngressRouterError> {
        self.route_key(PeerRouteKey::Address(remote), remote, payload)
    }

    /// Route a datagram to the exact local/remote call pair for one endpoint.
    pub fn route_call(
        &mut self,
        remote: SocketAddr,
        local_call: u16,
        remote_call: u16,
        payload: &[u8],
    ) -> Result<(), PeerIngressRouterError> {
        let key = PeerRouteKey::Call {
            remote,
            local_call,
            remote_call,
        };
        if self.routes.contains_key(&key) {
            return self.route_key(key, remote, payload);
        }
        if self.has_call_routes(remote) {
            Err(PeerIngressRouterError::UnknownPeer)
        } else {
            self.route(remote, payload)
        }
    }

    /// Route a mini frame by endpoint and its only call identifier.
    pub fn route_remote_call(
        &mut self,
        remote: SocketAddr,
        remote_call: u16,
        payload: &[u8],
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
            return self.route_key(key, remote, payload);
        }
        if self.has_call_routes(remote) {
            Err(PeerIngressRouterError::UnknownPeer)
        } else {
            self.route(remote, payload)
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
    ) -> Result<(), PeerIngressRouterError> {
        let route = self
            .routes
            .get_mut(&key)
            .ok_or(PeerIngressRouterError::UnknownPeer)?;
        match route.producer.try_push(remote, payload) {
            Ok(()) => Ok(()),
            Err(IngressPushError::Full) => {
                route.dropped_packets = route.dropped_packets.saturating_add(1);
                Err(PeerIngressRouterError::Full)
            }
            Err(IngressPushError::DatagramTooLarge { length }) => {
                Err(PeerIngressRouterError::DatagramTooLarge { length })
            }
        }
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
        Some(IngressStats {
            queued_packets: self.queue_capacity.get() - route.producer.available_slots(),
            dropped_packets: route.dropped_packets,
        })
    }
}

impl IngressConsumer {
    /// Remove the oldest packet, or return `None` when the queue is empty.
    pub fn try_pop(&mut self) -> Option<InboundDatagram> {
        self.queue.pop().ok()
    }
}

/// Allocate a fixed-capacity wait-free SPSC queue for one producer-owner pair.
///
/// Create a separate queue for each producer assigned to the peer owner. The
/// producer and consumer handles are unique execution-context capabilities;
/// never share either handle between threads. The peer generation is copied
/// into every packet so owners can reject stale work after slot reuse.
pub fn producer_ingress(
    capacity: usize,
    peer_generation: u64,
) -> Result<(IngressProducer, IngressConsumer), IngressError> {
    let capacity = NonZeroUsize::new(capacity).ok_or(IngressError::ZeroCapacity)?;
    Ok(new_ingress(capacity, peer_generation))
}

fn new_ingress(capacity: NonZeroUsize, peer_generation: u64) -> (IngressProducer, IngressConsumer) {
    let (producer, consumer) = RingBuffer::new(capacity.get());
    (
        IngressProducer {
            queue: producer,
            generation: peer_generation,
        },
        IngressConsumer { queue: consumer },
    )
}
