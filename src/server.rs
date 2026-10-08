//! Serialized inbound IAX2 call admission over one bound UDP endpoint.

use crate::{
    call_token::CallTokenAuthority,
    client::IaxPeer,
    information_elements::parse_information_elements,
    ingress::{PeerIngressRouter, PeerIngressRouterError},
    network::UdpEndpoint,
    protocol::{IaxCommand, decode_iax_command, parse_full_frame_packet, parse_mini_frame},
    session::{InboundNewAction, process_inbound_ulaw_new},
};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};

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
    pub format: u32,
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
    /// A valid call passed token validation and product admission, and ACCEPT was sent.
    Accepted(Box<InboundPeer>),
    /// A challenge, reject, or protocol reply was sent; no peer was admitted.
    Replied,
    /// A malformed or unrelated datagram was safely ignored.
    Ignored,
    /// No datagram was waiting.
    None,
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
    #[cfg(test)]
    fail_next_poll: bool,
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
            router: PeerIngressRouter::new(1024, 16).map_err(|_| ListenerError::InvalidFrame)?,
            routes: Vec::with_capacity(1024),
            generation: 0,
            #[cfg(test)]
            fail_next_poll: false,
        })
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
        self.reap_released_routes();
        let mut packet = [0_u8; crate::ingress::MAX_DATAGRAM_SIZE];
        let Some((length, remote)) = self
            .endpoint
            .try_receive(&mut packet)
            .map_err(ListenerError::Network)?
        else {
            return Ok(ListenerEvent::None);
        };
        let bytes = &packet[..length];
        if self.route_existing(remote, bytes) {
            return Ok(ListenerEvent::None);
        }
        let Ok(request) = parse_full_frame_packet(bytes) else {
            return Ok(ListenerEvent::Ignored);
        };
        let local_call = self.next_available_call();
        let local_node = called_node(bytes)
            .filter(|called| self.local_nodes.iter().any(|node| node == called))
            .unwrap_or(&self.local_nodes[0])
            .to_owned();
        let remote_address = remote;
        let action = match process_inbound_ulaw_new(
            &self.tokens,
            remote,
            bytes,
            &local_node,
            local_call,
            now_seconds,
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
                self.generation = self.generation.wrapping_add(1).max(1);
                let Ok(ingress) = self.router.register_call(
                    remote,
                    local_call,
                    request.header.source_call_number,
                    self.generation,
                ) else {
                    let reject = self
                        .tokens
                        .reject_initial_new(bytes)
                        .map_err(|_| ListenerError::InvalidFrame)?;
                    send_reply(&self.endpoint, &reject, remote)?;
                    return Ok(ListenerEvent::Replied);
                };
                let local = self.endpoint.local_addr().map_err(ListenerError::Network)?;
                let (peer, released) = IaxPeer::from_inbound(
                    self.endpoint.shared_socket(),
                    ingress,
                    local,
                    remote,
                    local_call,
                    request.header.source_call_number,
                    accepted.format,
                )
                .map_err(|_| ListenerError::InvalidFrame)?;
                self.routes.push(InboundRoute {
                    remote,
                    local_call,
                    remote_call: request.header.source_call_number,
                    generation: self.generation,
                    released,
                });
                send_reply(&self.endpoint, &accepted.packet, remote)?;
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

    fn reap_released_routes(&mut self) {
        let mut index = 0;
        while index < self.routes.len() {
            if self.routes[index]
                .released
                .load(std::sync::atomic::Ordering::Acquire)
            {
                let route = self.routes.swap_remove(index);
                self.router.unregister_call(
                    route.remote,
                    route.local_call,
                    route.remote_call,
                    route.generation,
                );
            } else {
                index += 1;
            }
        }
    }

    fn remove_route(&mut self, remote: SocketAddr, local_call: u16, remote_call: u16) {
        if let Some(index) = self.routes.iter().position(|route| {
            route.remote == remote
                && route.local_call == local_call
                && route.remote_call == remote_call
        }) {
            let route = self.routes.swap_remove(index);
            self.router
                .unregister_call(remote, local_call, remote_call, route.generation);
        }
    }

    fn next_available_call(&self) -> u16 {
        (0..16_384)
            .map(|_| next_call_number())
            .find(|call| !self.router.contains_local_call(*call))
            .expect("inbound peer limit is below the available local call-number space")
    }

    fn route_existing(&mut self, remote: SocketAddr, packet: &[u8]) -> bool {
        if packet.first().is_some_and(|first| first & 0x80 != 0) {
            let Ok(frame) = parse_full_frame_packet(packet) else {
                return false;
            };
            let local_call = frame.header.destination_call_number;
            let remote_call = frame.header.source_call_number;
            match self
                .router
                .route_call(remote, local_call, remote_call, packet)
            {
                Ok(()) | Err(PeerIngressRouterError::Full) => {
                    if decode_iax_command(&frame.header) == Ok(Some(IaxCommand::Hangup)) {
                        self.remove_route(remote, local_call, remote_call);
                    }
                    true
                }
                Err(PeerIngressRouterError::UnknownPeer) => false,
                Err(_) => true,
            }
        } else {
            let Ok(frame) = parse_mini_frame(packet) else {
                return false;
            };
            match self
                .router
                .route_remote_call(remote, frame.header.source_call_number, packet)
            {
                Ok(()) | Err(PeerIngressRouterError::Full) => true,
                Err(PeerIngressRouterError::UnknownPeer) => false,
                Err(_) => true,
            }
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
