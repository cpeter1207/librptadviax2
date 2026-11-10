//! Owned inbound work. Listener mutation never spans a callback or route acknowledgment.

use super::*;
use crate::{
    authentication::{AUTH_METHOD_MD5, md5_result},
    call_token::InitialNewDisposition,
    formats::{FormatOffer, IaxFormat, append_formats},
    information_elements::{InformationElement, serialize_information_elements},
    protocol::{FullFrameHeader, IaxCommand, decode_iax_command, serialize_full_frame},
    provider::{ProviderCall, ProviderCallMetadata, unique, valid_text},
};
use std::time::Duration;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);

/// Owned poll work. Execute after releasing the listener/control mutex.
pub struct PreparedPoll {
    task: PollTask,
}

enum PollTask {
    Idle,
    Ignored,
    Reply {
        route: ReplyOwner,
        bytes: Vec<u8>,
    },
    Cleanup(Cleanup),
    Legacy {
        route: PreparedRoute,
        accepted: crate::session::InboundCallAccepted,
        local: String,
        reject: Vec<u8>,
        catalog: Option<Arc<crate::formats::FormatCatalog>>,
    },
    Provider(PendingIncoming),
}

/// Completed owned work, returned to its listener to publish pending authentication
/// or transfer the peer. Abandonment sends best-effort HANGUP before local release;
/// it does not claim a remote acknowledgment or protocol teardown receipt.
pub struct CompletedPoll {
    event: ListenerEvent,
    pending: Option<PendingIncoming>,
    ownership: Option<Ownership>,
}
impl CompletedPoll {
    fn event(event: ListenerEvent) -> Self {
        Self {
            event,
            pending: None,
            ownership: None,
        }
    }
}

impl Drop for CompletedPoll {
    fn drop(&mut self) {
        match &mut self.event {
            ListenerEvent::Accepted(call) => {
                let _ = call.peer.hangup();
            }
            ListenerEvent::Provider(call) => {
                let _ = call.peer.hangup();
            }
            _ => {}
        }
    }
}

struct ReplyOwner {
    socket: Arc<SharedSocket>,
    remote: SocketAddr,
    ownership: Ownership,
}
impl ReplyOwner {
    fn send(&self, bytes: &[u8]) -> Result<(), ListenerError> {
        self.ownership
            .with_live(|| send_reply(&self.socket, bytes, self.remote))
            .map_err(ListenerError::Provider)?
    }
}

struct Cleanup {
    control: ListenerControl,
    identity: (SocketAddr, u16, u16, u64),
    receipt: Arc<AtomicU8>,
}
impl Cleanup {
    fn run(&self) -> Result<(), AccountError> {
        self.control
            .unregister(self.identity, Instant::now() + CONTROL_TIMEOUT)?;
        self.receipt.store(2, Ordering::Release);
        Ok(())
    }
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self
            .receipt
            .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire);
    }
}

impl PreparedPoll {
    /// Drive one owned task and synchronous policy callback, never while borrowing
    /// its listener. Both callback families receive their actual identity only.
    pub fn run(
        self,
        mut authorize_legacy: impl FnMut(&str, &str, SocketAddr) -> bool,
        mut authorize_provider: impl FnMut(&ProviderCallMetadata) -> bool,
    ) -> Result<CompletedPoll, ListenerError> {
        match self.task {
            PollTask::Idle => Ok(CompletedPoll::event(ListenerEvent::None)),
            PollTask::Ignored => Ok(CompletedPoll::event(ListenerEvent::Ignored)),
            PollTask::Reply { route, bytes } => {
                route.send(&bytes)?;
                Ok(CompletedPoll::event(ListenerEvent::Replied))
            }
            PollTask::Cleanup(cleanup) => {
                cleanup.run().map_err(ListenerError::Provider)?;
                Ok(CompletedPoll::event(ListenerEvent::None))
            }
            PollTask::Legacy {
                mut route,
                accepted,
                local,
                reject,
                catalog,
            } => {
                if !authorize_legacy(&local, &accepted.remote_node, route.remote) {
                    route
                        .send(&reject, Instant::now() + CONTROL_TIMEOUT)
                        .map_err(ListenerError::Provider)?;
                    return Ok(CompletedPoll::event(ListenerEvent::Replied));
                }
                let remote_call = parse_full_frame_packet(&accepted.packet)
                    .expect("owned ACCEPT frame")
                    .header
                    .destination_call_number;
                let ownership = route.ownership.clone();
                let peer = route
                    .accept(
                        remote_call,
                        accepted.format,
                        accepted.packet,
                        catalog.as_deref(),
                        None,
                    )
                    .map_err(|error| match error {
                        AccountError::Call(error) => map_inbound_peer_error(error),
                        other => ListenerError::Provider(other),
                    })?;
                Ok(CompletedPoll {
                    event: ListenerEvent::Accepted(Box::new(InboundPeer {
                        local_node: local,
                        remote_node: accepted.remote_node,
                        remote: route.remote,
                        local_call: route.local_call,
                        remote_call,
                        format: accepted.format,
                        peer,
                    })),
                    pending: None,
                    ownership: Some(ownership),
                })
            }
            PollTask::Provider(mut pending) => match pending.advance() {
                Ok(false) => Ok(CompletedPoll {
                    event: if pending.just_started {
                        ListenerEvent::Replied
                    } else {
                        ListenerEvent::None
                    },
                    pending: Some(pending),
                    ownership: None,
                }),
                Ok(true) => {
                    let authorized = authorize_provider(&pending.metadata);
                    if !authorized || Instant::now() >= pending.deadline {
                        pending.reject().map_err(ListenerError::Provider)?;
                        return Ok(CompletedPoll::event(ListenerEvent::Replied));
                    }
                    let ownership = pending.route.ownership.clone();
                    let mut payload = Vec::new();
                    append_formats(&mut payload, pending.metadata.format, None);
                    let packet =
                        serialize_full_frame(&pending.header(IaxCommand::Accept, 1, 2), &payload)
                            .expect("validated owned ACCEPT header");
                    let peer = pending
                        .route
                        .accept(
                            pending.metadata.remote_call,
                            pending.metadata.format,
                            packet,
                            Some(&pending.catalog),
                            Some(pending.deadline),
                        )
                        .map_err(ListenerError::Provider)?;
                    Ok(CompletedPoll {
                        event: ListenerEvent::Provider(Box::new(ProviderCall {
                            metadata: pending.metadata.clone(),
                            peer,
                        })),
                        pending: None,
                        ownership: Some(ownership),
                    })
                }
                Err(AccountError::Protocol | AccountError::Timeout | AccountError::Rejected) => {
                    pending.reject().map_err(ListenerError::Provider)?;
                    Ok(CompletedPoll::event(ListenerEvent::Replied))
                }
                Err(AccountError::Retired) => Ok(CompletedPoll::event(ListenerEvent::Ignored)),
                Err(error) => Err(ListenerError::Provider(error)),
            },
        }
    }
}

impl PreparedRoute {
    fn accept(
        &mut self,
        remote_call: u16,
        format: u64,
        packet: Vec<u8>,
        catalog: Option<&crate::formats::FormatCatalog>,
        authentication_deadline: Option<Instant>,
    ) -> Result<IaxPeer, AccountError> {
        let authenticated = authentication_deadline.is_some();
        #[cfg(test)]
        tests::accept_checkpoint(self.local_call, 0, authentication_deadline);
        let deadline = authentication_deadline.map_or(Instant::now() + CONTROL_TIMEOUT, |auth| {
            auth.min(Instant::now() + CONTROL_TIMEOUT)
        });
        if Instant::now() >= deadline {
            return Err(AccountError::Timeout);
        }
        self.install(deadline)?;
        self.promote(remote_call, deadline)?;
        let local = self.socket.local_addr().map_err(AccountError::Network)?;
        let (mut peer, _) = IaxPeer::from_inbound(
            self.socket.clone(),
            self.ingress.take().expect("installed inbound route"),
            local,
            self.remote,
            self.local_call,
            remote_call,
            format,
        )
        .map_err(AccountError::Call)?;
        if authenticated {
            peer.authenticated_inbound().map_err(AccountError::Call)?;
        }
        if let Some(catalog) = catalog {
            peer.compose_codec(catalog).map_err(AccountError::Call)?;
        }
        let ownership = self.ownership.clone();
        #[cfg(test)]
        tests::accept_checkpoint(self.local_call, 1, authentication_deadline);
        ownership
            .with_live(|| {
                if Instant::now() >= deadline {
                    return Err(DialError::Timeout);
                }
                peer.accept_inbound(packet)?;
                peer.retain_route(
                    self.released.clone(),
                    authenticated.then(|| ownership.clone()),
                );
                self.transferred = true;
                Ok(())
            })?
            .map_err(AccountError::Call)?;
        Ok(peer)
    }
}

pub(super) struct PendingIncoming {
    route: PreparedRoute,
    account: Arc<Account>,
    metadata: ProviderCallMetadata,
    catalog: Arc<crate::formats::FormatCatalog>,
    challenge: String,
    packet: Vec<u8>,
    deadline: Instant,
    retry_at: Instant,
    interval: Duration,
    transmissions: u8,
    acknowledged: bool,
    just_started: bool,
    next_incoming: u8,
}

impl PendingIncoming {
    fn new(
        route: PreparedRoute,
        account: Arc<Account>,
        frame: crate::protocol::FullFramePacket<'_>,
        catalog: Arc<crate::formats::FormatCatalog>,
        arrived: Instant,
    ) -> Result<Self, AccountError> {
        let deadline = arrived
            .checked_add(account.config.pending_auth_timeout)
            .filter(|deadline| *deadline > Instant::now())
            .ok_or(AccountError::Timeout)?;
        let elements =
            parse_information_elements(frame.payload).map_err(|_| AccountError::Protocol)?;
        let format = catalog
            .select(FormatOffer::parse(&elements).supported())
            .map(IaxFormat::for_profile)
            .map_err(|_| AccountError::Protocol)?
            .0;
        let text = |kind| -> Result<String, AccountError> {
            let bytes = unique(&elements, kind)?.unwrap_or_default();
            let text = std::str::from_utf8(bytes).map_err(|_| AccountError::Protocol)?;
            if !valid_text(text, 255, true) {
                return Err(AccountError::Protocol);
            }
            Ok(text.to_owned())
        };
        let metadata = ProviderCallMetadata {
            account: account.config.id.clone(),
            account_generation: account.config.generation,
            local_binding: account.config.local_binding.clone(),
            call_generation: route.generation,
            remote: route.remote,
            local: route.socket.local_addr().map_err(AccountError::Network)?,
            local_call: route.local_call,
            remote_call: frame.header.source_call_number,
            format,
            username: text(6)?,
            called: text(1)?,
            caller_number: text(2)?,
            caller_name: text(4)?,
            context: text(5)?,
            incoming: true,
        };
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).map_err(|_| {
            AccountError::Network(io::Error::other("authentication nonce unavailable"))
        })?;
        let challenge = random
            .into_iter()
            .flat_map(|byte| {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                [
                    char::from(HEX[usize::from(byte >> 4)]),
                    char::from(HEX[usize::from(byte & 15)]),
                ]
            })
            .collect::<String>();
        let payload = serialize_information_elements(&[
            InformationElement {
                kind: 6,
                data: account.config.username.as_bytes(),
            },
            InformationElement {
                kind: 14,
                data: &AUTH_METHOD_MD5.to_be_bytes(),
            },
            InformationElement {
                kind: 15,
                data: challenge.as_bytes(),
            },
        ])
        .expect("bounded AUTHREQ information elements");
        let mut pending = Self {
            route,
            account,
            metadata,
            catalog,
            challenge,
            packet: Vec::new(),
            deadline,
            retry_at: arrived,
            interval: Duration::from_millis(100),
            transmissions: 0,
            acknowledged: false,
            just_started: false,
            next_incoming: 1,
        };
        pending.packet = serialize_full_frame(&pending.header(IaxCommand::AuthReq, 0, 1), &payload)
            .expect("validated AUTHREQ header");
        Ok(pending)
    }

    fn header(&self, command: IaxCommand, outgoing: u8, incoming: u8) -> FullFrameHeader {
        FullFrameHeader {
            source_call_number: self.metadata.local_call,
            destination_call_number: self.metadata.remote_call,
            retransmission: false,
            timestamp: 0,
            outgoing_sequence: outgoing,
            incoming_sequence: incoming,
            frame_type: 6,
            subclass: command.subclass_value() as u8,
            subclass_is_log: false,
        }
    }

    fn ready(&self) -> bool {
        let ingress = self
            .route
            .ingress
            .as_ref()
            .expect("retained authentication installed its ingress");
        self.route.ownership.check().is_err()
            || Instant::now() >= self.deadline
            || (!self.acknowledged && Instant::now() >= self.retry_at)
            || ingress.failed()
            || ingress.stats().queued_packets != 0
    }

    fn advance(&mut self) -> Result<bool, AccountError> {
        self.just_started = self.transmissions == 0;
        self.route.ownership.check()?;
        let now = Instant::now();
        if now >= self.deadline {
            return Err(AccountError::Timeout);
        }
        if self.transmissions == 0 {
            self.route.install(self.deadline)?;
        }
        if !self.acknowledged && now >= self.retry_at {
            if self.transmissions == 4 {
                return Err(AccountError::Timeout);
            }
            let mut header = parse_full_frame_packet(&self.packet)
                .expect("owned AUTHREQ packet")
                .header;
            header.retransmission = self.transmissions != 0;
            let payload = parse_full_frame_packet(&self.packet)
                .expect("owned AUTHREQ packet")
                .payload;
            self.route.send(
                &serialize_full_frame(&header, payload).expect("owned AUTHREQ retry"),
                self.deadline,
            )?;
            if self.transmissions != 0 {
                self.interval = (self.interval * 10).min(Duration::from_secs(10));
            }
            self.transmissions += 1;
            self.retry_at = Instant::now() + self.interval;
        }
        let Some(received) = self.route.try_receive()? else {
            return Ok(false);
        };
        let frame =
            parse_full_frame_packet(received.payload()).map_err(|_| AccountError::Protocol)?;
        // The private pending router already matched the exact local call.
        if frame.header.source_call_number != self.metadata.remote_call
            || frame.header.outgoing_sequence != 1
            || frame.header.incoming_sequence != 1
        {
            return Err(AccountError::Protocol);
        }
        match decode_iax_command(&frame.header).map_err(|_| AccountError::Protocol)? {
            Some(IaxCommand::Ack) if frame.payload.is_empty() => {
                self.acknowledged = true;
                Ok(false)
            }
            Some(IaxCommand::AuthRep) => {
                let elements = parse_information_elements(frame.payload)
                    .map_err(|_| AccountError::Protocol)?;
                let response = unique(&elements, 16)?.ok_or(AccountError::Protocol)?;
                if response.len() != 32 {
                    return Err(AccountError::Protocol);
                }
                self.next_incoming = 2;
                // A configured provider secret is literal. ASL's historical
                // semicolon-separated alternatives do not apply to this login.
                if !md5_result(&self.challenge, &self.account.config.secret)
                    .eq_ignore_ascii_case(response)
                {
                    return Err(AccountError::Rejected);
                }
                Ok(true)
            }
            _ => Err(AccountError::Protocol),
        }
    }

    fn reject(&self) -> Result<(), AccountError> {
        let packet =
            serialize_full_frame(&self.header(IaxCommand::Reject, 1, self.next_incoming), &[])
                .expect("owned reject header");
        // Authentication has ended. This independent cleanup send never
        // extends its admission deadline or permits media publication.
        self.route.send(&packet, Instant::now() + CONTROL_TIMEOUT)
    }
}

impl InboundIaxListener {
    /// Prepare one bounded work item without policy callbacks, route waits, or cleanup acknowledgments.
    /// The returned owner must run outside any listener/control mutex.
    pub fn prepare_poll(&mut self, now_seconds: u32) -> Result<PreparedPoll, ListenerError> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_poll) {
            return Err(ListenerError::Network(io::Error::other(
                "injected poll failure",
            )));
        }
        self.routes
            .retain(|route| route.cleanup.load(Ordering::Acquire) != 2);
        for route in &self.routes {
            if !route.released.load(Ordering::Acquire) {
                continue;
            }
            if let Some(ingress) = &self.async_ingress {
                if route
                    .cleanup
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return Ok(PreparedPoll {
                        task: PollTask::Cleanup(Cleanup {
                            control: ingress.control(),
                            identity: (
                                route.remote,
                                route.local_call,
                                route.remote_call,
                                route.generation,
                            ),
                            receipt: route.cleanup.clone(),
                        }),
                    });
                }
            } else {
                self.router.unregister_call(
                    route.remote,
                    route.local_call,
                    route.remote_call,
                    route.generation,
                );
                route.cleanup.store(2, Ordering::Release);
            }
        }
        self.routes
            .retain(|route| route.cleanup.load(Ordering::Acquire) != 2);
        if let Some(index) = self
            .pending_provider
            .iter()
            .position(PendingIncoming::ready)
        {
            return Ok(PreparedPoll {
                task: PollTask::Provider(self.pending_provider.swap_remove(index)),
            });
        }
        let mut bytes = [0; crate::ingress::MAX_DATAGRAM_SIZE + 1];
        let (length, remote, arrived) = if let Some(ingress) = &mut self.async_ingress {
            let Some(received) = ingress.try_receive().map_err(ListenerError::Network)? else {
                return Ok(PreparedPoll {
                    task: PollTask::Idle,
                });
            };
            bytes[..received.payload().len()].copy_from_slice(received.payload());
            (
                received.payload().len(),
                received.remote(),
                received.arrived_at(),
            )
        } else {
            let Some((length, remote)) = self
                .endpoint
                .try_receive(&mut bytes)
                .map_err(ListenerError::Network)?
            else {
                return Ok(PreparedPoll {
                    task: PollTask::Idle,
                });
            };
            if self.route_existing(remote, &bytes[..length]) {
                return Ok(PreparedPoll {
                    task: PollTask::Idle,
                });
            }
            (length, remote, Instant::now())
        };
        if length > crate::ingress::MAX_DATAGRAM_SIZE {
            return Ok(PreparedPoll {
                task: PollTask::Ignored,
            });
        }
        let bytes = &bytes[..length];
        let Ok(frame) = parse_full_frame_packet(bytes) else {
            return Ok(PreparedPoll {
                task: PollTask::Ignored,
            });
        };
        // Preserve legacy overload behavior: a full listener rejects initial
        // admission before issuing another stateless challenge.
        if self.next_available_call().is_none() {
            return self.reject_work(remote, bytes);
        }
        let disposition = match self.tokens.handle_initial_new(remote, bytes, now_seconds) {
            Ok(disposition) => disposition,
            Err(_) => {
                return Ok(PreparedPoll {
                    task: PollTask::Ignored,
                });
            }
        };
        if let InitialNewDisposition::Challenge(reply) | InitialNewDisposition::Reject(reply) =
            disposition
        {
            return Ok(self.reply_work(remote, reply));
        }
        let elements =
            parse_information_elements(frame.payload).expect("token-validated IE framing");
        let username = unique(&elements, 6).ok().flatten();
        let account = self
            .accounts
            .iter()
            .find(|account| {
                account.config.remote == remote
                    && Some(account.config.username.as_bytes()) == username
            })
            .cloned();
        if let Some(account) = account {
            if self.routes.iter().any(|route| {
                route.remote == remote && route.new_call == Some(frame.header.source_call_number)
            }) {
                if let Some(pending) = self.pending_provider.iter().find(|pending| {
                    pending.metadata.remote == remote
                        && pending.metadata.remote_call == frame.header.source_call_number
                }) {
                    return Ok(PreparedPoll {
                        task: PollTask::Reply {
                            route: ReplyOwner {
                                socket: self.endpoint.shared_socket(),
                                remote,
                                ownership: pending.route.ownership.clone(),
                            },
                            bytes: pending.packet.clone(),
                        },
                    });
                }
                return Ok(PreparedPoll {
                    task: PollTask::Ignored,
                });
            }
            let Some(catalog) = self
                .catalog
                .as_ref()
                .and_then(|catalog| catalog.phone())
                .map(Arc::new)
            else {
                return self.reject_work(remote, bytes);
            };
            self.pending_provider
                .try_reserve(1)
                .map_err(|_| ListenerError::Provider(AccountError::Busy))?;
            let Ok(route) = self.reserve_route(
                remote,
                Some(frame.header.source_call_number),
                account.life.clone(),
                true,
            ) else {
                return self.reject_work(remote, bytes);
            };
            return match PendingIncoming::new(route, account, frame, catalog, arrived) {
                Ok(pending) => Ok(PreparedPoll {
                    task: PollTask::Provider(pending),
                }),
                Err(_) => self.reject_work(remote, bytes),
            };
        }
        // A matched configured account never reaches this numeric path, even
        // after a rejected/expired MD5 response. Non-radio usernames have no fallback.
        if username != Some(b"radio") || self.local_nodes.is_empty() {
            return self.reject_work(remote, bytes);
        }
        let local = called_node(bytes)
            .filter(|called| self.local_nodes.iter().any(|node| node == called))
            .unwrap_or(&self.local_nodes[0])
            .to_owned();
        let local_call = self
            .next_available_call()
            .expect("serialized admission retains the earlier free call number");
        let action = process_inbound_new(
            &self.tokens,
            remote,
            bytes,
            (&local, local_call),
            now_seconds,
            self.catalog.as_deref(),
            |_| true,
        )
        .expect("same immutable request/source/time passed the token gate above");
        match action {
            InboundNewAction::Reply(reply) => Ok(self.reply_work(remote, reply)),
            InboundNewAction::Accept(mut accepted) => {
                let Ok(route) = self.reserve_route(
                    remote,
                    Some(frame.header.source_call_number),
                    self.legacy_admission.clone(),
                    false,
                ) else {
                    return self.reject_work(remote, bytes);
                };
                let parsed = parse_full_frame_packet(&accepted.packet).expect("owned ACCEPT frame");
                let mut header = parsed.header;
                header.source_call_number = route.local_call;
                accepted.packet = serialize_full_frame(&header, parsed.payload)
                    .expect("reserved ACCEPT call number");
                let reject = self
                    .tokens
                    .reject_initial_new(bytes)
                    .expect("validated initial NEW");
                Ok(PreparedPoll {
                    task: PollTask::Legacy {
                        route,
                        accepted,
                        local,
                        reject,
                        catalog: self.catalog.clone(),
                    },
                })
            }
        }
    }

    fn reply_work(&self, remote: SocketAddr, bytes: Vec<u8>) -> PreparedPoll {
        PreparedPoll {
            task: PollTask::Reply {
                route: ReplyOwner {
                    socket: self.endpoint.shared_socket(),
                    remote,
                    ownership: Ownership {
                        server: self.life.clone(),
                        account: Life::new(),
                        operation: Life::new(),
                    },
                },
                bytes,
            },
        }
    }

    fn reject_work(&self, remote: SocketAddr, bytes: &[u8]) -> Result<PreparedPoll, ListenerError> {
        Ok(match self.tokens.reject_initial_new(bytes) {
            Ok(reply) => self.reply_work(remote, reply),
            Err(_) => PreparedPoll {
                task: PollTask::Ignored,
            },
        })
    }

    /// Return owned work to this listener. Retired snapshots cannot publish late calls.
    pub fn finish_poll(
        &mut self,
        mut completed: CompletedPoll,
    ) -> Result<ListenerEvent, ListenerError> {
        if completed
            .ownership
            .as_ref()
            .is_some_and(|owner| owner.check().is_err())
        {
            return Ok(ListenerEvent::Ignored);
        }
        if let Some(pending) = completed.pending.take() {
            if pending.route.ownership.check().is_ok() {
                self.pending_provider.push(pending);
            }
        }
        self.routes
            .retain(|route| route.cleanup.load(Ordering::Acquire) != 2);
        Ok(std::mem::replace(&mut completed.event, ListenerEvent::None))
    }

    /// Drive mixed listener admission on its serialized control owner. Provider
    /// callbacks occur only after configured-account MD5 verification.
    pub fn poll_accounts(
        &mut self,
        now_seconds: u32,
        authorize_legacy: impl FnMut(&str, &str, SocketAddr) -> bool,
        authorize_provider: impl FnMut(&ProviderCallMetadata) -> bool,
    ) -> Result<ListenerEvent, ListenerError> {
        let work = self.prepare_poll(now_seconds)?;
        let completed = work.run(authorize_legacy, authorize_provider)?;
        self.finish_poll(completed)
    }
}

#[cfg(test)]
#[path = "server_provider_tests.rs"]
mod tests;
