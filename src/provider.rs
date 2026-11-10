//! Configured provider identity and same-listener registration ownership.
//!
//! Provider caller fields never identify an AllStarLink node. Account credentials
//! authenticate the transport; mailbox/PIN authorization belongs to the product.

use crate::{
    authentication::{AUTH_METHOD_MD5, md5_result, parse_auth_request},
    information_elements::{
        InformationElement, parse_information_elements, serialize_information_elements,
    },
    protocol::{
        FullFrameHeader, IaxCommand, decode_iax_command, parse_full_frame_packet,
        serialize_full_frame,
    },
    server::PreparedRoute,
};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

/// Maximum configured accounts retained by one listener.
pub const MAX_ACCOUNTS: usize = 64;

/// Owned provider configuration. Deliberately has no Debug implementation.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountConfig {
    /// Opaque, nonempty account label, at most64 UTF-8 bytes without controls.
    pub id: String,
    /// Nonzero host configuration generation; changed settings require a new value.
    pub generation: u64,
    /// Copied local admission binding, at most63 bytes; not a remote caller identity.
    pub local_binding: String,
    /// Exact resolved provider endpoint. Resolution belongs to the product.
    pub remote: SocketAddr,
    /// Account login, independent of caller number and display name.
    pub username: String,
    /// MD5 challenge secret, copied for the configuration/call lifetime only.
    pub secret: String,
    /// Nonzero total incoming authentication lifetime, including delayed polling.
    pub pending_auth_timeout: Duration,
}

impl AccountConfig {
    pub(crate) fn valid(&self) -> bool {
        valid_text(&self.id, 64, false)
            && self.generation != 0
            && valid_text(&self.local_binding, 63, false)
            && valid_text(&self.username, 255, false)
            && valid_text(&self.secret, 255, false)
            && self.remote.port() != 0
            && !self.remote.ip().is_unspecified()
            && !self.pending_auth_timeout.is_zero()
            && Instant::now()
                .checked_add(self.pending_auth_timeout)
                .is_some()
    }
}

pub(crate) fn valid_text(value: &str, maximum: usize, empty: bool) -> bool {
    (empty || !value.is_empty()) && value.len() <= maximum && !value.chars().any(char::is_control)
}

/// Failure of a configured provider operation; messages contain no credentials.
#[derive(Debug)]
pub enum AccountError {
    /// Invalid configuration, missing account/generation, or invalid operation.
    InvalidOptions,
    /// Same-listener operations require the existing asynchronous receiver.
    AsyncRequired,
    /// A bounded control queue or the call-number space has no capacity.
    Busy,
    /// This exact server, account, or operation owner has retired.
    Retired,
    /// The total monotonic deadline expired; this is not a teardown receipt.
    Timeout,
    /// The registrar rejected the request.
    Rejected,
    /// Malformed, unsupported, or incorrectly sequenced protocol data.
    Protocol,
    /// An actual socket/control transport failure.
    Network(io::Error),
    /// The common call/session/codec owner rejected outgoing setup.
    Call(crate::client::DialError),
}

impl std::fmt::Display for AccountError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOptions => output.write_str("invalid IAX provider operation"),
            Self::AsyncRequired => output.write_str("IAX provider requires asynchronous listener"),
            Self::Busy => output.write_str("IAX provider capacity unavailable"),
            Self::Retired => output.write_str("IAX provider owner retired"),
            Self::Timeout => output.write_str("IAX provider operation timed out"),
            Self::Rejected => output.write_str("IAX registrar rejected operation"),
            Self::Protocol => output.write_str("invalid IAX provider response"),
            Self::Network(error) => write!(output, "IAX provider network failure: {error}"),
            Self::Call(_) => output.write_str("IAX provider call setup failed"),
        }
    }
}
impl std::error::Error for AccountError {}
impl AccountError {
    /// Preserve actual transport/deadline failures at the common call boundary.
    pub(crate) fn into_call(self) -> crate::client::DialError {
        use crate::{client::DialError, session::CallSetupError};
        match self {
            Self::Network(error) => DialError::Network(error),
            Self::Timeout => DialError::Timeout,
            _ => DialError::Protocol(CallSetupError::CallFinished),
        }
    }
}

pub(crate) struct Life(Mutex<bool>);
impl Life {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(true)))
    }
    pub(crate) fn retire(&self) {
        *self.0.lock().unwrap_or_else(|error| error.into_inner()) = false;
    }
}

pub(crate) struct Account {
    pub(crate) config: AccountConfig,
    pub(crate) life: Arc<Life>,
}

/// Three concrete owners fence publication; no foreign callback runs under these guards.
#[derive(Clone)]
pub(crate) struct Ownership {
    pub(crate) server: Arc<Life>,
    pub(crate) account: Arc<Life>,
    pub(crate) operation: Arc<Life>,
}
impl Ownership {
    pub(crate) fn with_live<T>(&self, action: impl FnOnce() -> T) -> Result<T, AccountError> {
        let server = self.server.0.lock().map_err(|_| AccountError::Retired)?;
        let account = self.account.0.lock().map_err(|_| AccountError::Retired)?;
        let operation = self.operation.0.lock().map_err(|_| AccountError::Retired)?;
        if !*server || !*account || !*operation {
            return Err(AccountError::Retired);
        }
        Ok(action())
    }
    pub(crate) fn check(&self) -> Result<(), AccountError> {
        self.with_live(|| ())
    }
}

/// Caller-driven register, refresh, or authenticated release request.
#[derive(Clone, Copy)]
pub struct RegistrationRequest {
    /// Requested registration interval in seconds; nonzero even for release.
    pub refresh: u16,
    /// Send REGREL instead of REGREQ; challenges retain that operation.
    pub release: bool,
    /// Nonzero total control deadline, checked for overflow.
    pub timeout: Duration,
}

/// Registrar result. No automatic refresh is performed by the library.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationReceipt {
    /// Granted interval; absent REFRESH uses the RFC5456 default60seconds.
    pub refresh: u16,
    /// Registrar-supplied apparent endpoint, if present and correctly formed.
    pub apparent: Option<SocketAddr>,
}

/// Copied fields for a call through the configured provider; no replacement credentials.
#[derive(Clone)]
pub struct DialRequest {
    /// Provider destination, including telephone-menu symbols.
    pub destination: String,
    /// Optional untrusted caller number, independent of account identity.
    pub caller_number: String,
    /// Optional untrusted display name.
    pub caller_name: String,
    /// Optional requested provider context.
    pub context: String,
    /// Checked total setup/answer timeout.
    pub timeout: Duration,
}
impl DialRequest {
    pub(crate) fn valid(&self) -> bool {
        valid_text(&self.destination, 255, false)
            && [&self.caller_number, &self.caller_name, &self.context]
                .iter()
                .all(|text| valid_text(text, 255, true))
            && !self.timeout.is_zero()
            && Instant::now().checked_add(self.timeout).is_some()
    }
}

/// Copied transport admission metadata, never mailbox or RF authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCallMetadata {
    /// Configured opaque provider account.
    pub account: String,
    /// Exact host configuration generation selected for this call.
    pub account_generation: u64,
    /// Configured local admission binding, not derived from caller fields.
    pub local_binding: String,
    /// Listener-local nonzero call ownership generation.
    pub call_generation: u64,
    /// Actual resolved UDP peer endpoint.
    pub remote: SocketAddr,
    /// Actual bound listener endpoint, including its source port.
    pub local: SocketAddr,
    /// Local protocol call identifier.
    pub local_call: u16,
    /// Remote protocol call identifier.
    pub remote_call: u16,
    /// Selected common codec format.
    pub format: u64,
    /// Provider username from the authenticated/configured transport.
    pub username: String,
    /// Untrusted called number.
    pub called: String,
    /// Untrusted caller number; not an ASL node identity.
    pub caller_number: String,
    /// Untrusted display name.
    pub caller_name: String,
    /// Untrusted context.
    pub context: String,
    /// True for a provider-originated incoming call.
    pub incoming: bool,
}

/// One established provider call using the existing sole media/session owner.
pub struct ProviderCall {
    /// Copied identity and protocol receipt.
    pub metadata: ProviderCallMetadata,
    pub(crate) peer: crate::client::IaxPeer,
}
impl ProviderCall {
    /// Transfer the actual peer, retaining its exact account/server lifetime fence.
    pub fn into_peer(self) -> crate::client::IaxPeer {
        self.peer
    }
}

/// An outgoing account snapshot and exact route reservation. Execute off-executor.
pub struct PreparedDial {
    pub(crate) route: PreparedRoute,
    pub(crate) account: Arc<Account>,
    pub(crate) request: DialRequest,
    pub(crate) catalog: Arc<crate::formats::FormatCatalog>,
    pub(crate) started: bool,
}
impl PreparedDial {
    /// Run once through the common NEW/CALLTOKEN/MD5/ACCEPT/ANSWER implementation.
    pub fn run(&mut self) -> Result<ProviderCall, AccountError> {
        if self.started {
            return Err(AccountError::InvalidOptions);
        }
        self.started = true;
        let deadline = Instant::now()
            .checked_add(self.request.timeout)
            .ok_or(AccountError::InvalidOptions)?;
        let version = 2_u16.to_be_bytes();
        let elements = [
            InformationElement {
                kind: 6,
                data: self.account.config.username.as_bytes(),
            },
            InformationElement {
                kind: 1,
                data: self.request.destination.as_bytes(),
            },
            InformationElement {
                kind: 2,
                data: self.request.caller_number.as_bytes(),
            },
            InformationElement {
                kind: 4,
                data: self.request.caller_name.as_bytes(),
            },
            InformationElement {
                kind: 5,
                data: self.request.context.as_bytes(),
            },
            InformationElement {
                kind: 11,
                data: &version,
            },
        ];
        let peer = self.route.dial(
            crate::client::CallRequest {
                remote: self.account.config.remote,
                local_call: self.route.local_call,
                secret: &self.account.config.secret,
                timeout: self.request.timeout,
            },
            &elements,
            self.catalog.clone(),
            deadline,
        )?;
        let metadata = ProviderCallMetadata {
            account: self.account.config.id.clone(),
            account_generation: self.account.config.generation,
            local_binding: self.account.config.local_binding.clone(),
            call_generation: self.route.generation,
            remote: peer.remote_addr(),
            local: peer.local_addr().map_err(AccountError::Call)?,
            local_call: peer.local_call_number(),
            remote_call: peer.remote_call_number(),
            format: peer.format(),
            username: self.account.config.username.clone(),
            called: self.request.destination.clone(),
            caller_number: self.request.caller_number.clone(),
            caller_name: self.request.caller_name.clone(),
            context: self.request.context.clone(),
            incoming: false,
        };
        Ok(ProviderCall { metadata, peer })
    }
}

/// Owned operation prepared under listener control, executed off-executor without its borrow.
///
/// `run` is called once. Success or timeout retains this owner and its socket
/// until drop. Drop marks its exact route released; the listener's next poll
/// reaps that generation, or listener destruction joins its receiver. Timeout
/// alone does not acknowledge protocol completion or socket teardown.
pub struct PreparedRegistration {
    pub(crate) route: PreparedRoute,
    pub(crate) account: Arc<Account>,
    pub(crate) request: RegistrationRequest,
    started: bool,
}

impl PreparedRegistration {
    pub(crate) fn new(
        route: PreparedRoute,
        account: Arc<Account>,
        request: RegistrationRequest,
    ) -> Self {
        Self {
            route,
            account,
            request,
            started: false,
        }
    }

    /// Run one bounded transaction on the listener's actual source socket.
    pub fn run(&mut self) -> Result<RegistrationReceipt, AccountError> {
        if self.started {
            return Err(AccountError::InvalidOptions);
        }
        self.started = true;
        let started = Instant::now();
        let deadline = started
            .checked_add(self.request.timeout)
            .ok_or(AccountError::InvalidOptions)?;
        self.route.install(deadline)?;
        let command = if self.request.release {
            IaxCommand::RegRel
        } else {
            IaxCommand::RegReq
        };
        let mut remote_call = 0;
        let mut next_incoming = 0_u8;
        let mut next_outgoing = 1_u8;
        let mut pending = registration_packet(
            &self.account.config,
            registration_header(self.route.local_call, 0, command, (0, 0), 0),
            self.request.refresh,
            None,
        )?;
        let initial = pending.clone();
        self.route.send(&pending, deadline)?;
        let mut interval = Duration::from_millis(100);
        let mut retry_at = started + interval;
        let mut transmissions = 1;
        let mut acknowledged = false;
        let mut challenge_receipt: Option<(u32, Vec<u8>)> = None;
        while Instant::now() < deadline {
            self.route.ownership.check()?;
            let Some(received) = self.route.try_receive()? else {
                let now = Instant::now();
                if !acknowledged && now >= retry_at {
                    if transmissions == 4 {
                        return Err(AccountError::Timeout);
                    }
                    let packet =
                        parse_full_frame_packet(&pending).map_err(|_| AccountError::Protocol)?;
                    let mut header = packet.header;
                    header.retransmission = true;
                    header.incoming_sequence = next_incoming;
                    pending = serialize_full_frame(&header, packet.payload)
                        .map_err(|_| AccountError::Protocol)?;
                    self.route.send(&pending, deadline)?;
                    transmissions += 1;
                    interval = (interval * 10).min(Duration::from_secs(10));
                    retry_at = now + interval;
                }
                thread::sleep(Duration::from_millis(2));
                continue;
            };
            let packet =
                parse_full_frame_packet(received.payload()).map_err(|_| AccountError::Protocol)?;
            let header = packet.header;
            // The private pending route dispatches only this exact local
            // destination; source-call validation remains wire protocol work.
            if header.source_call_number == 0
                || (remote_call != 0 && header.source_call_number != remote_call)
            {
                return Err(AccountError::Protocol);
            }
            let response = decode_iax_command(&header).map_err(|_| AccountError::Protocol)?;
            if response == Some(IaxCommand::CallToken) && remote_call == 0 {
                pending = crate::call_token::retry_registration_with_token(
                    &initial,
                    received.payload(),
                    started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32,
                )
                .map_err(|_| AccountError::Protocol)?;
                self.route.send(&pending, deadline)?;
                acknowledged = false;
                transmissions = 1;
                interval = Duration::from_millis(100);
                retry_at = Instant::now() + interval;
                continue;
            }
            // A retained challenge exists only after the first REGAUTH;
            // that state has next_incoming=1 until this transaction returns.
            if header.outgoing_sequence == 0
                && response == Some(IaxCommand::RegAuth)
                && challenge_receipt
                    .as_ref()
                    .is_some_and(|(timestamp, payload)| {
                        *timestamp == header.timestamp && payload == packet.payload
                    })
            {
                // Duplicates preserve the original registrar acknowledgment,
                // which precedes the already committed authenticated request.
                self.route.send(&pending, deadline)?;
                continue;
            }
            if header.incoming_sequence != next_outgoing {
                return Err(AccountError::Protocol);
            }
            if response == Some(IaxCommand::Ack) {
                if header.outgoing_sequence != next_incoming {
                    return Err(AccountError::Protocol);
                }
                acknowledged = true;
                continue;
            }
            if header.outgoing_sequence != next_incoming {
                return Err(AccountError::Protocol);
            }
            remote_call = header.source_call_number;
            next_incoming = next_incoming.wrapping_add(1);
            match response {
                Some(IaxCommand::RegAuth) if next_outgoing == 1 => {
                    let auth =
                        parse_auth_request(packet.payload).map_err(|_| AccountError::Protocol)?;
                    let elements = parse_information_elements(packet.payload)
                        .map_err(|_| AccountError::Protocol)?;
                    if auth.methods & AUTH_METHOD_MD5 == 0
                        || auth.challenge.is_empty()
                        || unique(&elements, 6)? != Some(self.account.config.username.as_bytes())
                    {
                        return Err(AccountError::Protocol);
                    }
                    let digest = md5_result(auth.challenge, &self.account.config.secret);
                    challenge_receipt = Some((header.timestamp, packet.payload.to_vec()));
                    pending = registration_packet(
                        &self.account.config,
                        registration_header(
                            self.route.local_call,
                            remote_call,
                            command,
                            (next_outgoing, next_incoming),
                            started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32,
                        ),
                        self.request.refresh,
                        Some(&digest),
                    )?;
                    next_outgoing = next_outgoing.wrapping_add(1);
                    self.route.send(&pending, deadline)?;
                    acknowledged = false;
                    transmissions = 1;
                    interval = Duration::from_millis(100);
                    retry_at = Instant::now() + interval;
                }
                Some(IaxCommand::RegAck | IaxCommand::RegRej) => {
                    let acknowledgement = serialize_full_frame(
                        &FullFrameHeader {
                            source_call_number: self.route.local_call,
                            destination_call_number: remote_call,
                            retransmission: false,
                            timestamp: header.timestamp,
                            outgoing_sequence: next_outgoing,
                            incoming_sequence: next_incoming,
                            frame_type: 6,
                            subclass: 4,
                            subclass_is_log: false,
                        },
                        &[],
                    )
                    .map_err(|_| AccountError::Protocol)?;
                    self.route.send(&acknowledgement, deadline)?;
                    if response == Some(IaxCommand::RegRej) {
                        return Err(AccountError::Rejected);
                    }
                    let elements = parse_information_elements(packet.payload)
                        .map_err(|_| AccountError::Protocol)?;
                    if unique(&elements, 6)?
                        .is_some_and(|name| name != self.account.config.username.as_bytes())
                    {
                        return Err(AccountError::Protocol);
                    }
                    let refresh = match unique(&elements, 19)? {
                        None => 60,
                        Some([a, b]) => u16::from_be_bytes([*a, *b]),
                        _ => return Err(AccountError::Protocol),
                    };
                    let apparent = unique(&elements, 18)?.map(parse_apparent).transpose()?;
                    return Ok(RegistrationReceipt { refresh, apparent });
                }
                _ => return Err(AccountError::Protocol),
            }
        }
        Err(AccountError::Timeout)
    }
}

pub(crate) fn unique<'a>(
    elements: &[InformationElement<'a>],
    kind: u8,
) -> Result<Option<&'a [u8]>, AccountError> {
    let mut found = elements.iter().filter(|element| element.kind == kind);
    let result = found.next().map(|element| element.data);
    if found.next().is_some() {
        return Err(AccountError::Protocol);
    }
    Ok(result)
}

fn registration_packet(
    config: &AccountConfig,
    header: FullFrameHeader,
    refresh: u16,
    digest: Option<&[u8]>,
) -> Result<Vec<u8>, AccountError> {
    let refresh = refresh.to_be_bytes();
    let mut elements = vec![
        InformationElement {
            kind: 6,
            data: config.username.as_bytes(),
        },
        InformationElement {
            kind: 19,
            data: &refresh,
        },
    ];
    if let Some(digest) = digest {
        elements.push(InformationElement {
            kind: 16,
            data: digest,
        });
    }
    // Asterisk applies its stateless call-token gate to REGREQ/REGREL as
    // well as NEW. Its own registrar client also keeps this final IE on auth.
    elements.push(InformationElement {
        kind: 54,
        data: &[],
    });
    let payload = serialize_information_elements(&elements).map_err(|_| AccountError::Protocol)?;
    serialize_full_frame(&header, &payload).map_err(|_| AccountError::Protocol)
}

fn registration_header(
    local: u16,
    remote: u16,
    command: IaxCommand,
    sequence: (u8, u8),
    timestamp: u32,
) -> FullFrameHeader {
    FullFrameHeader {
        source_call_number: local,
        destination_call_number: remote,
        retransmission: false,
        timestamp,
        outgoing_sequence: sequence.0,
        incoming_sequence: sequence.1,
        frame_type: 6,
        subclass: command.subclass_value() as u8,
        subclass_is_log: false,
    }
}

fn parse_apparent(bytes: &[u8]) -> Result<SocketAddr, AccountError> {
    // RFC5456 and pinned Asterisk iax_ie_append_addr send native Linux sockaddr
    // records. Supported amd64/arm64 targets are little-endian, with network port.
    match bytes {
        [2, 0, high, low, a, b, c, d, ..] if bytes.len() == 16 => Ok(SocketAddr::from((
            Ipv4Addr::new(*a, *b, *c, *d),
            u16::from_be_bytes([*high, *low]),
        ))),
        [10, 0, high, low, rest @ ..] if bytes.len() == 28 => {
            let flow = u32::from_be_bytes(rest[..4].try_into().expect("IPv6 flow field"));
            let ip =
                Ipv6Addr::from(<[u8; 16]>::try_from(&rest[4..20]).expect("IPv6 address field"));
            let scope =
                u32::from_le_bytes(rest[20..24].try_into().expect("IPv6 native scope field"));
            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be_bytes([*high, *low]),
                flow,
                scope,
            )))
        }
        _ => Err(AccountError::Protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_tests::{account, runtime};

    #[test]
    fn actual_lifetime_lock_poisoning_rejects_work_and_retirement_stays_safe() {
        for stage in 0..3 {
            let remote = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut listener = crate::server::InboundIaxListener::bind_accounts(
                "127.0.0.1:0".parse().unwrap(),
                &[],
                &[account(remote.local_addr().unwrap())],
                None,
            )
            .unwrap();
            listener.enable_async(runtime()).unwrap();
            let mut prepared = listener
                .prepare_registration(
                    "provider-one",
                    7,
                    RegistrationRequest {
                        refresh: 60,
                        release: false,
                        timeout: Duration::from_secs(1),
                    },
                )
                .unwrap();
            let ownership = prepared.route.ownership.clone();
            let life = match stage {
                0 => ownership.server.clone(),
                1 => ownership.account.clone(),
                _ => ownership.operation.clone(),
            };
            // Ordinary Rust unwind is caught within this test. No process-global
            // hook changes and no unwind crosses an extern-C frame.
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _guard = life.0.lock().unwrap();
                    panic!("isolated owned lifetime failure");
                }))
                .is_err()
            );
            let error = prepared.run().expect_err("poison must retire work");
            assert!(matches!(error, AccountError::Retired));
            assert_eq!(error.to_string(), "IAX provider owner retired");
            remote.set_nonblocking(true).unwrap();
            assert_eq!(
                remote.recv_from(&mut [0; 2048]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            drop(prepared);
            listener
                .poll_accounts(100, |_, _, _| false, |_| false)
                .unwrap();
            drop(listener);
            life.retire();
            assert!(matches!(ownership.check(), Err(AccountError::Retired)));
        }
    }

    #[test]
    fn retained_lifetime_receipts_cannot_be_used_after_actual_operation_or_server_drop() {
        let remote = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut listener = crate::server::InboundIaxListener::bind_accounts(
            "127.0.0.1:0".parse().unwrap(),
            &[],
            &[account(remote.local_addr().unwrap())],
            None,
        )
        .unwrap();
        listener.enable_async(runtime()).unwrap();
        let request = RegistrationRequest {
            refresh: 60,
            release: false,
            timeout: Duration::from_secs(1),
        };
        let prepared = listener
            .prepare_registration("provider-one", 7, request)
            .unwrap();
        let receipt = prepared.route.ownership.clone();
        drop(prepared);
        assert!(matches!(receipt.check(), Err(AccountError::Retired)));
        listener
            .poll_accounts(100, |_, _, _| false, |_| false)
            .unwrap();
        let mut retained = listener
            .prepare_registration("provider-one", 7, request)
            .unwrap();
        let local = listener.local_addr().unwrap();
        drop(listener);
        let retired = retained
            .run()
            .expect_err("actual listener drop retires its retained operation");
        assert!(matches!(
            retired.into_call(),
            crate::client::DialError::Protocol(crate::session::CallSetupError::CallFinished)
        ));
        // The retained actual operation still owns this socket; retirement did
        // not fabricate an early local teardown receipt.
        assert_eq!(
            std::net::UdpSocket::bind(local).unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        drop(retained);
    }

    #[test]
    fn registration_send_waits_for_actual_initial_socket_writability() {
        for retire in [false, true] {
            let runtime = Arc::new(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build()
                    .unwrap(),
            );
            let (entered, active) = std::sync::mpsc::channel();
            let (release, held) = std::sync::mpsc::channel();
            runtime.spawn(async move {
                entered.send(()).unwrap();
                held.recv().unwrap();
            });
            active.recv_timeout(Duration::from_secs(2)).unwrap();
            // Registration on this held real reactor has no cached writable
            // event yet. No socket options, readiness state or authority is faked.
            let remote = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            remote
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let config = account(remote.local_addr().unwrap());
            let mut listener = crate::server::InboundIaxListener::bind_accounts(
                "127.0.0.1:0".parse().unwrap(),
                &[],
                &[config.clone()],
                None,
            )
            .unwrap();
            listener.enable_async(runtime).unwrap();
            let operation = listener
                .prepare_registration(
                    "provider-one",
                    7,
                    RegistrationRequest {
                        refresh: 60,
                        release: false,
                        timeout: Duration::from_secs(2),
                    },
                )
                .unwrap();
            let packet = registration_packet(
                &config,
                registration_header(operation.route.local_call, 0, IaxCommand::RegReq, (0, 0), 0),
                60,
                None,
            )
            .unwrap();
            let expected = packet.clone();
            let (completed, result) = std::sync::mpsc::channel();
            let sender = std::thread::spawn(move || {
                let sent = operation
                    .route
                    .send(&packet, Instant::now() + Duration::from_secs(2));
                completed.send(sent).unwrap();
                operation
            });
            let early = result.recv_timeout(Duration::from_millis(200));
            if retire {
                listener.configure_accounts(&[]).unwrap();
            }
            release.send(()).unwrap();
            let operation = sender.join().unwrap();
            assert!(
                matches!(early, Err(std::sync::mpsc::RecvTimeoutError::Timeout)),
                "send completed before actual reactor writability: {early:?}"
            );
            let sent = result.recv_timeout(Duration::from_secs(2)).unwrap();
            if retire {
                assert!(matches!(sent, Err(AccountError::Retired)));
                remote.set_nonblocking(true).unwrap();
                assert_eq!(
                    remote.recv_from(&mut [0; 2048]).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
            } else {
                sent.unwrap();
                let mut bytes = [0; 2048];
                let (length, source) = remote.recv_from(&mut bytes).unwrap();
                assert_eq!(source, listener.local_addr().unwrap());
                assert_eq!(&bytes[..length], expected);
            }
            drop(operation);
            listener
                .poll_accounts(1000, |_, _, _| false, |_| false)
                .unwrap();
            assert_eq!(listener.ingress_stats().active_routes, 0);
        }
    }
}
