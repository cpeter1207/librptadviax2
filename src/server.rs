//! Serialized inbound IAX2 call admission over one bound UDP endpoint.

use crate::{
    call_token::CallTokenAuthority,
    client::{DialError, IaxPeer},
    information_elements::parse_information_elements,
    ingress::{PeerIngressRouter, PeerIngressRouterError},
    network::{SharedSocket, UdpEndpoint},
    protocol::{parse_full_frame_packet, parse_mini_frame},
    provider::{
        Account, AccountConfig, AccountError, DialRequest, Life, MAX_ACCOUNTS, Ownership,
        PreparedDial, PreparedRegistration, RegistrationRequest,
    },
    session::{InboundNewAction, process_inbound_new},
};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering},
    },
    time::Instant,
};

#[path = "server_async.rs"]
mod async_ingress;
pub(crate) use async_ingress::ListenerControl;
use async_ingress::ListenerIngress;
#[path = "server_provider.rs"]
mod provider_admission;
pub use provider_admission::{CompletedPoll, PreparedPoll};

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
    /// An authenticated configured provider call, never a numeric ASL identity.
    Provider(Box<crate::provider::ProviderCall>),
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
    /// A configured provider/control operation failed without admitting a peer.
    Provider(AccountError),
}

impl std::fmt::Display for ListenerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(error) => write!(formatter, "IAX2 listener network error: {error}"),
            Self::InvalidFrame => formatter.write_str("invalid inbound IAX2 frame"),
            Self::ShortSend => formatter.write_str("incomplete inbound IAX2 response send"),
            Self::Provider(error) => write!(formatter, "{error}"),
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
    accounts: Vec<Arc<Account>>,
    life: Arc<Life>,
    legacy_admission: Arc<Life>,
    pending_provider: Vec<provider_admission::PendingIncoming>,
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
    cleanup: Arc<AtomicU8>,
    provider: bool,
    new_call: Option<u16>,
}

pub(crate) struct PreparedRoute {
    socket: Arc<SharedSocket>,
    control: Option<ListenerControl>,
    remote: SocketAddr,
    pub(crate) local_call: u16,
    pub(crate) generation: u64,
    pub(crate) ownership: Ownership,
    released: Arc<AtomicBool>,
    ingress: Option<crate::ingress::IngressConsumer>,
    transferred: bool,
}

impl PreparedRoute {
    pub(crate) fn install(&mut self, deadline: Instant) -> Result<(), AccountError> {
        self.ownership.check()?;
        if self.ingress.is_some() {
            return Ok(());
        }
        self.ingress = Some(
            self.control
                .as_ref()
                .ok_or(AccountError::AsyncRequired)?
                .register_pending(
                    self.remote,
                    self.local_call,
                    self.generation,
                    self.ownership.clone(),
                    deadline,
                )?,
        );
        Ok(())
    }
    fn promote(&self, remote_call: u16, deadline: Instant) -> Result<(), AccountError> {
        match &self.control {
            Some(control) => control.promote(
                (self.remote, self.local_call, remote_call, self.generation),
                self.ownership.clone(),
                deadline,
            ),
            None => Ok(()), // Synchronous admission installed its exact call under listener control.
        }
    }
    pub(crate) fn send(&self, bytes: &[u8], deadline: Instant) -> Result<(), AccountError> {
        if let Some(control) = &self.control {
            control.send(&self.socket, self.remote, bytes, &self.ownership, deadline)
        } else {
            self.ownership
                .with_live(|| self.socket.send_to(bytes, self.remote))?
                .map(|_| ())
                .map_err(AccountError::Network)
        }
    }
    pub(crate) fn try_receive(
        &mut self,
    ) -> Result<Option<crate::ingress::InboundDatagram>, AccountError> {
        self.ownership.check()?;
        let ingress = self
            .ingress
            .as_mut()
            .expect("installed transaction retains its ingress");
        match ingress.try_pop() {
            Some(packet) => Ok(Some(packet)),
            None if ingress.failed() => Err(AccountError::Retired),
            None => Ok(None),
        }
    }

    pub(crate) fn dial(
        &mut self,
        options: crate::client::CallRequest<'_>,
        elements: &[crate::information_elements::InformationElement<'_>],
        catalog: Arc<crate::formats::FormatCatalog>,
        deadline: Instant,
    ) -> Result<IaxPeer, AccountError> {
        self.install(deadline)?;
        let control = self.control.clone().ok_or(AccountError::AsyncRequired)?;
        let shared = crate::client::SharedDial {
            control: control.clone(),
            socket: self.socket.clone(),
            ingress: self.ingress.take().expect("installed setup route"),
            local: self.socket.local_addr().map_err(AccountError::Network)?,
            released: self.released.clone(),
            ownership: self.ownership.clone(),
            deadline,
        };
        let ownership = self.ownership.clone();
        let identity = (self.remote, self.local_call, self.generation);
        let mut peer = crate::client::dial_new_transport(
            options,
            elements,
            Some(catalog),
            Some(shared),
            |remote_call| {
                control
                    .promote(
                        (identity.0, identity.1, remote_call, identity.2),
                        ownership.clone(),
                        deadline,
                    )
                    .map_err(AccountError::into_call)
            },
        )
        .map_err(AccountError::Call)?;
        #[cfg(test)]
        tests::dial_checkpoint(&self.ownership);
        if let Err(error) = self.ownership.check() {
            let _ = peer.hangup();
            return Err(error);
        }
        self.transferred = true;
        Ok(peer)
    }
}

impl Drop for PreparedRoute {
    fn drop(&mut self) {
        if !self.transferred {
            self.ownership.operation.retire();
            self.released.store(true, Ordering::Release);
        }
    }
}

impl InboundIaxListener {
    /// Bind the configured UDP address and initialize a process-private call-token key.
    pub fn bind(local: SocketAddr, local_node: &str) -> Result<Self, ListenerError> {
        Self::bind_many(local, &[local_node.to_owned()])
    }

    /// Bind one UDP endpoint that accepts calls addressed to any configured local node.
    pub fn bind_many(local: SocketAddr, local_nodes: &[String]) -> Result<Self, ListenerError> {
        Self::bind_composed(local, local_nodes, None, &[])
    }

    /// Retain one composition catalog for all authorized incoming calls.
    pub fn bind_with_catalog(
        local: SocketAddr,
        local_nodes: &[String],
        catalog: Arc<crate::formats::FormatCatalog>,
    ) -> Result<Self, ListenerError> {
        Self::bind_composed(local, local_nodes, Some(catalog), &[])
    }

    /// Bind mixed numeric and configured provider admission on one UDP endpoint.
    /// Empty numeric nodes are valid only when at least one account is configured.
    pub fn bind_accounts(
        local: SocketAddr,
        local_nodes: &[String],
        accounts: &[AccountConfig],
        catalog: Option<Arc<crate::formats::FormatCatalog>>,
    ) -> Result<Self, ListenerError> {
        Self::bind_composed(local, local_nodes, catalog, accounts)
    }

    fn bind_composed(
        local: SocketAddr,
        local_nodes: &[String],
        catalog: Option<Arc<crate::formats::FormatCatalog>>,
        accounts: &[AccountConfig],
    ) -> Result<Self, ListenerError> {
        if (!local_nodes.is_empty() && !valid_local_nodes(local_nodes))
            || (local_nodes.is_empty() && accounts.is_empty())
            || !valid_accounts(accounts)
        {
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
            accounts: accounts
                .iter()
                .cloned()
                .map(|config| {
                    Arc::new(Account {
                        config,
                        life: Life::new(),
                    })
                })
                .collect(),
            life: Life::new(),
            legacy_admission: Life::new(),
            pending_provider: Vec::with_capacity(MAX_ACCOUNTS),
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
        if !(valid_local_nodes(local_nodes) || local_nodes.is_empty() && !self.accounts.is_empty())
        {
            return Err(ListenerError::InvalidFrame);
        }
        if self.local_nodes != local_nodes {
            self.legacy_admission.retire();
            self.legacy_admission = Life::new();
            self.local_nodes = local_nodes.to_vec();
        }
        Ok(())
    }

    /// Atomically replace validated copied accounts, retiring each changed owner.
    /// Established provider peers retain their resources but become unusable
    /// when their exact account retires; the product must close/destroy them.
    pub fn configure_accounts(&mut self, configs: &[AccountConfig]) -> Result<(), AccountError> {
        if !valid_accounts(configs)
            || configs.iter().any(|config| {
                self.accounts.iter().any(|old| {
                    old.config.id == config.id
                        && old.config.generation == config.generation
                        && old.config != *config
                })
            })
        {
            return Err(AccountError::InvalidOptions);
        }
        let mut next = Vec::new();
        next.try_reserve(configs.len())
            .map_err(|_| AccountError::Busy)?;
        for config in configs {
            next.push(
                self.accounts
                    .iter()
                    .find(|old| old.config == *config)
                    .cloned()
                    .unwrap_or_else(|| {
                        Arc::new(Account {
                            config: config.clone(),
                            life: Life::new(),
                        })
                    }),
            );
        }
        for old in &self.accounts {
            if !next.iter().any(|new| Arc::ptr_eq(old, new)) {
                old.life.retire();
            }
        }
        self.accounts = next;
        Ok(())
    }

    /// Snapshot an exact configured account and reserve a listener-local route.
    /// Execute the returned owner after releasing all product/control locks.
    pub fn prepare_registration(
        &mut self,
        account: &str,
        generation: u64,
        request: RegistrationRequest,
    ) -> Result<PreparedRegistration, AccountError> {
        if request.refresh == 0
            || request.timeout.is_zero()
            || Instant::now().checked_add(request.timeout).is_none()
        {
            return Err(AccountError::InvalidOptions);
        }
        let account = self
            .accounts
            .iter()
            .find(|entry| entry.config.id == account && entry.config.generation == generation)
            .cloned()
            .ok_or(AccountError::InvalidOptions)?;
        let route = self.prepare_account_route(&account)?;
        Ok(PreparedRegistration::new(route, account, request))
    }

    /// Snapshot configured credentials and reserve a call on this listener port.
    /// No network wait or foreign callback occurs while borrowing the listener.
    pub fn prepare_dial(
        &mut self,
        id: &str,
        generation: u64,
        request: DialRequest,
    ) -> Result<PreparedDial, AccountError> {
        if !request.valid() {
            return Err(AccountError::InvalidOptions);
        }
        let account = self
            .accounts
            .iter()
            .find(|account| account.config.id == id && account.config.generation == generation)
            .cloned()
            .ok_or(AccountError::InvalidOptions)?;
        let catalog = self.catalog.as_ref().ok_or(AccountError::InvalidOptions)?;
        let phone = catalog.phone().ok_or_else(|| {
            AccountError::Call(DialError::UnsupportedFormat(catalog.advertised_mask()))
        })?;
        let catalog = Arc::new(phone);
        let route = self.prepare_account_route(&account)?;
        Ok(PreparedDial {
            route,
            account,
            request,
            catalog,
            started: false,
        })
    }

    fn prepare_account_route(
        &mut self,
        account: &Arc<Account>,
    ) -> Result<PreparedRoute, AccountError> {
        if self.async_ingress.is_none() {
            return Err(AccountError::AsyncRequired);
        }
        self.reserve_route(account.config.remote, None, account.life.clone(), true)
    }

    fn reserve_route(
        &mut self,
        remote: SocketAddr,
        remote_call: Option<u16>,
        admission: Arc<Life>,
        provider: bool,
    ) -> Result<PreparedRoute, AccountError> {
        self.routes
            .retain(|route| route.cleanup.load(Ordering::Acquire) != 2);
        if provider && self.routes.iter().filter(|route| route.provider).count() >= MAX_ACCOUNTS {
            return Err(AccountError::Busy);
        }
        let local_call = self.next_available_call().ok_or(AccountError::Busy)?;
        let generation = self.generation.checked_add(1).ok_or(AccountError::Busy)?;
        let reserved = self.routes.try_reserve(1).is_ok();
        #[cfg(test)]
        let reserved = reserved && !std::mem::take(&mut self.fail_next_reserve);
        if !reserved {
            return Err(AccountError::Busy);
        }
        let released = Arc::new(AtomicBool::new(false));
        let ownership = Ownership {
            server: self.life.clone(),
            account: admission,
            operation: Life::new(),
        };
        ownership.check()?;
        let control = self.async_ingress.as_ref().map(ListenerIngress::control);
        let ingress = if control.is_none() {
            Some(
                self.router
                    .register_call(
                        remote,
                        local_call,
                        remote_call.ok_or(AccountError::AsyncRequired)?,
                        generation,
                    )
                    .map_err(|_| AccountError::Busy)?,
            )
        } else {
            None
        };
        self.generation = generation;
        self.routes.push(InboundRoute {
            remote,
            local_call,
            remote_call: if control.is_none() {
                remote_call.expect("synchronous exact route")
            } else {
                0
            },
            generation,
            released: released.clone(),
            cleanup: Arc::new(AtomicU8::new(0)),
            provider,
            new_call: remote_call,
        });
        Ok(PreparedRoute {
            socket: self.endpoint.shared_socket(),
            control,
            remote,
            local_call,
            generation,
            ownership,
            released,
            ingress,
            transferred: false,
        })
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
        authorize: impl FnMut(&str, &str, SocketAddr) -> bool,
    ) -> Result<ListenerEvent, ListenerError> {
        self.poll_accounts(now_seconds, authorize, |_| false)
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

fn valid_accounts(accounts: &[AccountConfig]) -> bool {
    accounts.len() <= MAX_ACCOUNTS
        && accounts.iter().enumerate().all(|(index, account)| {
            account.valid()
                && !accounts[..index].iter().any(|previous| {
                    previous.id == account.id
                        || (previous.remote == account.remote
                            && previous.username == account.username)
                })
        })
}

impl Drop for InboundIaxListener {
    fn drop(&mut self) {
        self.life.retire();
        for account in &self.accounts {
            account.life.retire();
        }
    }
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
    endpoint: &SharedSocket,
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
