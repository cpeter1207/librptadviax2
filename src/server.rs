//! Serialized inbound IAX2 call admission over one bound UDP endpoint.

use crate::{
    call_token::CallTokenAuthority,
    client::{DialError, IaxPeer},
    information_elements::parse_information_elements,
    ingress::{PeerIngressRouter, PeerIngressRouterError},
    network::UdpEndpoint,
    protocol::{parse_full_frame_packet, parse_mini_frame},
    session::{InboundNewAction, process_inbound_new},
};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Instant,
};

#[path = "server_async.rs"]
mod async_ingress;
use async_ingress::ListenerIngress;

static NEXT_INBOUND_CALL: AtomicU32 = AtomicU32::new(0);

/// One inbound ASL-compatible peer accepted after call-token and product policy checks.
pub struct InboundPeer {
    /// Local node number addressed by the incoming call.
    pub local_node: String,
    /// Numeric remote AllStarLink node number.
    pub remote_node: String,
    /// UDP endpoint from which the call arrived.
    pub remote: SocketAddr,
    /// Local nonzero 15-bit call number assigned by this process.
    pub local_call: u16,
    /// Remote nonzero 15-bit call number from the initial NEW.
    pub remote_call: u16,
    /// Negotiated IAX codec-format bit.
    pub format: u64,
    peer: IaxPeer,
}

impl InboundPeer {
    /// Transfer the established peer session to its sole product owner.
    pub fn into_peer(self) -> IaxPeer {
        self.peer
    }
}

/// One result from polling the inbound endpoint.
pub enum ListenerEvent {
    /// A valid call passed token validation and product admission; ACCEPT and ANSWER were sent.
    Accepted(Box<InboundPeer>),
    /// A challenge, reject, or protocol reply was sent; no peer was admitted.
    Replied,
    /// A malformed or unrelated datagram was safely ignored.
    Ignored,
    /// No datagram was waiting.
    None,
}

/// Independently sampled listener admission and live-route occupancy counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerIngressStats {
    /// NEW queue occupancy, capacity, and cumulative full-queue drops; zero for synchronous receive.
    pub admission: crate::ingress::IngressStats,
    /// Number of established routes currently owned by the socket router.
    pub active_routes: usize,
}

/// Failure from the standalone IAX2 listener.
#[derive(Debug)]
pub enum ListenerError {
    /// Socket binding, send, or receive failed.
    Network(io::Error),
    /// A malformed initial frame could not be classified safely.
    InvalidFrame,
    /// The response packet could not be sent completely.
    ShortSend,
}

impl std::fmt::Display for ListenerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(error) => write!(formatter, "IAX2 listener network error: {error}"),
            Self::InvalidFrame => formatter.write_str("invalid inbound IAX2 frame"),
            Self::ShortSend => formatter.write_str("incomplete inbound IAX2 response send"),
        }
    }
}

impl std::error::Error for ListenerError {}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

/// One bound, nonblocking IAX2 socket and stateless call-token authority.
///
/// A single non-audio owner must call [`poll`](Self::poll) and authorize new peers. The listener
/// does not own linked-session state or codec/media processing; admitted peers are returned to
/// the product owner for those operations.
pub struct InboundIaxListener {
    endpoint: UdpEndpoint,
    local_nodes: Vec<String>,
    tokens: CallTokenAuthority,
    router: PeerIngressRouter,
    routes: Vec<InboundRoute>,
    generation: u64,
    async_ingress: Option<ListenerIngress>,
    catalog: Option<Arc<crate::formats::FormatCatalog>>,
    #[cfg(test)]
    fail_next_poll: bool,
    #[cfg(test)]
    fail_next_reserve: bool,
}

struct InboundRoute {
    remote: SocketAddr,
    local_call: u16,
    remote_call: u16,
    generation: u64,
    released: Arc<AtomicBool>,
}

impl InboundIaxListener {
    /// Bind the configured UDP address and initialize a process-private call-token key.
    pub fn bind(local: SocketAddr, local_node: &str) -> Result<Self, ListenerError> {
        Self::bind_many(local, &[local_node.to_owned()])
    }

    /// Bind one UDP endpoint that accepts calls addressed to any configured local node.
    pub fn bind_many(local: SocketAddr, local_nodes: &[String]) -> Result<Self, ListenerError> {
        Self::bind_composed(local, local_nodes, None)
    }

    /// Retain one composition catalog for all authorized incoming calls.
    pub fn bind_with_catalog(
        local: SocketAddr,
        local_nodes: &[String],
        catalog: Arc<crate::formats::FormatCatalog>,
    ) -> Result<Self, ListenerError> {
        Self::bind_composed(local, local_nodes, Some(catalog))
    }
    fn bind_composed(
        local: SocketAddr,
        local_nodes: &[String],
        catalog: Option<Arc<crate::formats::FormatCatalog>>,
    ) -> Result<Self, ListenerError> {
        if !valid_local_nodes(local_nodes) {
            return Err(ListenerError::InvalidFrame);
        }
        let tokens = make_call_token_authority(|random| {
            getrandom::getrandom(random).map_err(|_| io::Error::other("random source failed"))
        })?;
        Ok(Self {
            endpoint: UdpEndpoint::bind(local).map_err(ListenerError::Network)?,
            local_nodes: local_nodes.to_vec(),
            tokens,
            router: PeerIngressRouter::new(16).map_err(|_| ListenerError::InvalidFrame)?,
            routes: Vec::new(),
            generation: 0,
            async_ingress: None,
            catalog,
            #[cfg(test)]
            fail_next_poll: false,
            #[cfg(test)]
            fail_next_reserve: false,
        })
    }

    /// Transfer socket receive and established routing to the shared runtime.
    ///
    /// Call off-executor, with exclusive listener ownership; repeated enable is
    /// a no-op success. Poll continues
    /// to authorize only bounded queued NEW calls; slow policy never holds up
    /// established traffic. Drop this listener off-executor before unloading its
    /// DSO. The listener retains the runtime until its socket task has joined.
    pub fn enable_async(
        &mut self,
        runtime: Arc<tokio::runtime::Runtime>,
    ) -> Result<(), ListenerError> {
        if self.async_ingress.is_some() {
            return Ok(());
        }
        let socket = self
            .endpoint
            .shared_socket()
            .register(runtime.handle())
            .map_err(ListenerError::Network)?;
        // No fallible work remains before the sole router moves into its task.
        let empty = PeerIngressRouter::new(1).expect("nonzero placeholder limits");
        let router = std::mem::replace(&mut self.router, empty);
        self.async_ingress = Some(ListenerIngress::start(runtime, socket, router));
        Ok(())
    }

    /// Snapshot bounded admission and route counters without waiting on the socket task.
    pub fn ingress_stats(&self) -> ListenerIngressStats {
        self.async_ingress.as_ref().map_or_else(
            || ListenerIngressStats {
                admission: crate::ingress::IngressStats::default(),
                active_routes: self.router.route_count(),
            },
            ListenerIngress::stats,
        )
    }

    #[cfg(test)]
    pub(crate) fn force_poll_error(&mut self) {
        self.fail_next_poll = true;
    }

    /// Replace local identities for future calls; established peer routes remain active.
    pub fn set_local_nodes(&mut self, local_nodes: &[String]) -> Result<(), ListenerError> {
        if !valid_local_nodes(local_nodes) {
            return Err(ListenerError::InvalidFrame);
        }
        self.local_nodes = local_nodes.to_vec();
        Ok(())
    }

    /// Return the actual bound endpoint, including an OS-assigned port when requested.
    pub fn local_addr(&self) -> Result<SocketAddr, ListenerError> {
        self.endpoint.local_addr().map_err(ListenerError::Network)
    }

    /// Handle one datagram, replying to challenges/rejections and returning authorized NEW calls.
    pub fn poll(
        &mut self,
        now_seconds: u32,
        mut authorize: impl FnMut(&str) -> bool,
    ) -> Result<ListenerEvent, ListenerError> {
        self.poll_with_identity(now_seconds, |_, remote, _| authorize(remote))
    }

    /// Poll one datagram and expose both local and remote identities to product policy.
    pub fn poll_with_identity(
        &mut self,
        now_seconds: u32,
        mut authorize: impl FnMut(&str, &str, SocketAddr) -> bool,
    ) -> Result<ListenerEvent, ListenerError> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_poll) {
            return Err(ListenerError::Network(io::Error::other(
                "injected poll failure",
            )));
        }
        self.reap_released_routes()?;
        let mut packet = [0_u8; crate::ingress::MAX_DATAGRAM_SIZE + 1];
        let (length, remote) = if let Some(ingress) = &mut self.async_ingress {
            let Some(received) = ingress.try_receive().map_err(ListenerError::Network)? else {
                return Ok(ListenerEvent::None);
            };
            let length = received.payload().len();
            packet[..length].copy_from_slice(received.payload());
            (length, received.remote())
        } else {
            let Some((length, remote)) = self
                .endpoint
                .try_receive(&mut packet)
                .map_err(ListenerError::Network)?
            else {
                return Ok(ListenerEvent::None);
            };
            if self.route_existing(remote, &packet[..length]) {
                return Ok(ListenerEvent::None);
            }
            (length, remote)
        };
        let bytes = &packet[..length];
        if length > crate::ingress::MAX_DATAGRAM_SIZE {
            return Ok(ListenerEvent::Ignored);
        }
        let Ok(request) = parse_full_frame_packet(bytes) else {
            return Ok(ListenerEvent::Ignored);
        };
        let Some(local_call) = self.next_available_call() else {
            return self.reject_new(bytes, remote);
        };
        let local_node = called_node(bytes)
            .filter(|called| self.local_nodes.iter().any(|node| node == called))
            .unwrap_or(&self.local_nodes[0])
            .to_owned();
        let remote_address = remote;
        let action = match process_inbound_new(
            &self.tokens,
            remote,
            bytes,
            (&local_node, local_call),
            now_seconds,
            self.catalog.as_deref(),
            &mut |remote: &str| authorize(&local_node, remote, remote_address),
        ) {
            Ok(action) => action,
            Err(_) => return Ok(ListenerEvent::Ignored),
        };
        match action {
            InboundNewAction::Reply(reply) => {
                send_reply(&self.endpoint, &reply, remote)?;
                Ok(ListenerEvent::Replied)
            }
            InboundNewAction::Accept(accepted) => {
                // Reserve before a router or peer can retain the new call identity.
                let reserved = self.routes.try_reserve(1).is_ok();
                #[cfg(test)]
                let reserved = reserved && !std::mem::take(&mut self.fail_next_reserve);
                if !reserved {
                    return self.reject_new(bytes, remote);
                }
                self.generation = self.generation.wrapping_add(1).max(1);
                let ingress = if let Some(ingress) = &self.async_ingress {
                    ingress
                        .register(
                            remote,
                            local_call,
                            request.header.source_call_number,
                            self.generation,
                        )
                        .map_err(ListenerError::Network)?
                } else {
                    self.router.register_call(
                        remote,
                        local_call,
                        request.header.source_call_number,
                        self.generation,
                    )
                };
                let Ok(ingress) = ingress else {
                    return self.reject_new(bytes, remote);
                };
                let local = self.endpoint.local_addr().map_err(ListenerError::Network)?;
                let (mut peer, released) = IaxPeer::from_inbound(
                    self.endpoint.shared_socket(),
                    ingress,
                    local,
                    remote,
                    local_call,
                    request.header.source_call_number,
                    accepted.format,
                )
                .map_err(|_| ListenerError::InvalidFrame)?;
                if let Some(catalog) = &self.catalog {
                    peer.compose_codec(catalog)
                        .map_err(|_| ListenerError::InvalidFrame)?;
                }
                self.routes.push(InboundRoute {
                    remote,
                    local_call,
                    remote_call: request.header.source_call_number,
                    generation: self.generation,
                    released,
                });
                peer.accept_inbound(accepted.packet)
                    .map_err(map_inbound_peer_error)?;
                Ok(ListenerEvent::Accepted(Box::new(InboundPeer {
                    local_node,
                    remote_node: accepted.remote_node,
                    remote,
                    local_call,
                    remote_call: request.header.source_call_number,
                    format: accepted.format,
                    peer,
                })))
            }
        }
    }

    fn reap_released_routes(&mut self) -> Result<(), ListenerError> {
        let mut index = 0;
        while index < self.routes.len() {
            if self.routes[index]
                .released
                .load(std::sync::atomic::Ordering::Acquire)
            {
                let route = self.routes.swap_remove(index);
                if let Some(ingress) = &self.async_ingress {
                    ingress
                        .unregister(
                            route.remote,
                            route.local_call,
                            route.remote_call,
                            route.generation,
                        )
                        .map_err(ListenerError::Network)?;
                } else {
                    self.router.unregister_call(
                        route.remote,
                        route.local_call,
                        route.remote_call,
                        route.generation,
                    );
                }
            } else {
                index += 1;
            }
        }
        Ok(())
    }

    fn reject_new(&self, bytes: &[u8], remote: SocketAddr) -> Result<ListenerEvent, ListenerError> {
        let Ok(reject) = self.tokens.reject_initial_new(bytes) else {
            return Ok(ListenerEvent::Ignored);
        };
        send_reply(&self.endpoint, &reject, remote)?;
        Ok(ListenerEvent::Replied)
    }

    fn next_available_call(&self) -> Option<u16> {
        // One starting point, then a complete local scan. Concurrent listeners
        // must not make each other's atomic strides skip a free call number.
        let start = u32::from(next_call_number()) - 16_384;
        (0..16_384)
            .map(|offset| (16_384 + (start + offset) % 16_384) as u16)
            .find(|call| {
                if self.async_ingress.is_some() {
                    !self.routes.iter().any(|route| route.local_call == *call)
                } else {
                    !self.router.contains_local_call(*call)
                }
            })
    }

    fn route_existing(&mut self, remote: SocketAddr, packet: &[u8]) -> bool {
        route_established(&mut self.router, remote, packet, Instant::now())
    }
}

fn route_established(
    router: &mut PeerIngressRouter,
    remote: SocketAddr,
    packet: &[u8],
    arrived_at: Instant,
) -> bool {
    if packet.first().is_some_and(|first| first & 0x80 != 0) {
        let Ok(frame) = parse_full_frame_packet(packet) else {
            return false;
        };
        let local_call = frame.header.destination_call_number;
        let remote_call = frame.header.source_call_number;
        match router.route_call_at(remote, local_call, remote_call, packet, arrived_at) {
            // Admission is not protocol validation: even HANGUP may be dropped
            // or rejected by its peer. Only released-generation reaping retires a route.
            Ok(()) | Err(PeerIngressRouterError::Full) => true,
            Err(PeerIngressRouterError::UnknownPeer) => false,
            Err(_) => true,
        }
    } else {
        let Ok(frame) = parse_mini_frame(packet) else {
            return false;
        };
        match router.route_remote_call_at(
            remote,
            frame.header.source_call_number,
            packet,
            arrived_at,
        ) {
            Ok(()) | Err(PeerIngressRouterError::Full) => true,
            Err(PeerIngressRouterError::UnknownPeer) => false,
            Err(_) => true,
        }
    }
}

fn valid_local_nodes(nodes: &[String]) -> bool {
    !nodes.is_empty()
        && !nodes
            .iter()
            .any(|node| node.is_empty() || !node.bytes().all(|byte| byte.is_ascii_digit()))
        && !nodes
            .iter()
            .enumerate()
            .any(|(index, node)| nodes[..index].contains(node))
}

fn called_node(packet: &[u8]) -> Option<&str> {
    let frame = parse_full_frame_packet(packet).ok()?;
    let elements = parse_information_elements(frame.payload).ok()?;
    let mut called = elements.iter().filter(|element| element.kind == 1);
    let value = called.next()?.data;
    (called.next().is_none() && !value.is_empty() && value.iter().all(u8::is_ascii_digit))
        .then(|| std::str::from_utf8(value).ok())
        .flatten()
}

fn send_reply(
    endpoint: &UdpEndpoint,
    packet: &[u8],
    remote: SocketAddr,
) -> Result<(), ListenerError> {
    check_reply_send(endpoint.send_to(packet, remote), packet.len())
}

fn map_inbound_peer_error(error: DialError) -> ListenerError {
    match error {
        DialError::Network(error) => ListenerError::Network(error),
        _ => ListenerError::InvalidFrame,
    }
}

fn make_call_token_authority(
    fill_random: impl FnOnce(&mut [u8]) -> io::Result<()>,
) -> Result<CallTokenAuthority, ListenerError> {
    let mut random = [0_u8; 4];
    fill_random(&mut random).map_err(|_| {
        ListenerError::Network(io::Error::other("secure call-token seed unavailable"))
    })?;
    Ok(CallTokenAuthority::new(i32::from_ne_bytes(random)))
}

fn check_reply_send(sent: io::Result<usize>, expected: usize) -> Result<(), ListenerError> {
    let sent = sent.map_err(ListenerError::Network)?;
    if sent != expected {
        return Err(ListenerError::ShortSend);
    }
    Ok(())
}

fn next_call_number() -> u16 {
    let offset = NEXT_INBOUND_CALL.fetch_add(1, Ordering::Relaxed) % 16_384;
    (16_384 + offset) as u16
}
