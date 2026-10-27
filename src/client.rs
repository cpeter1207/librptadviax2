//! Outbound IAX2 call establishment over the separate UDP transport.

use crate::{
    codec::{CodecAdapter, CodecError, G711Ulaw, IAX_FORMAT_ULAW, ULAW_SAMPLE_RATE_HZ},
    formats::{FormatCatalog, IaxFormat, append_formats},
    information_elements::{
        InformationElement, parse_information_elements, serialize_information_elements,
    },
    ingress::IngressConsumer,
    media::{VoiceFrame, VoiceFrameEncodeError, VoiceFrameError, parse_voice_frame},
    network::{SharedSocket, UdpEndpoint},
    playout::Playout,
    protocol::{IaxCommand, decode_iax_command, parse_full_frame_packet},
    session::{CallSetupError, LinkedCallResponse, OutboundCallSetup, OutboundSetupResponse},
};
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    thread,
    time::{Duration, Instant},
};

const IE_CALLED_NUMBER: u8 = 1;
const IE_CALLING_NUMBER: u8 = 2;
const IE_CALLING_ANI: u8 = 3;
const IE_USERNAME: u8 = 6;
const IE_VERSION: u8 = 11;
const INITIAL_RETRY: Duration = Duration::from_millis(100);
const MAX_RETRY: Duration = Duration::from_secs(10);
const MAX_TRANSMISSIONS: u8 = 4;
const LINK_INITIAL_RETRY: Duration = Duration::from_secs(2);
const MAX_RELIABLE_RETRIES: u8 = 4;
const MAX_RELIABLE_WINDOW: usize = 64;
const MAX_PACKET_SIZE: usize = crate::ingress::MAX_DATAGRAM_SIZE + 1;
const MAX_EARLY_EVENTS: usize = 64;

struct PendingEvent {
    event: IaxPeerEvent,
    pcm: Vec<f32>,
    text: Vec<u8>,
}

struct PendingReliableFrame {
    packet: Vec<u8>,
    outgoing_sequence: u8,
    next_retry: Instant,
    retry_interval: Duration,
    retries: u8,
    sent: bool,
    expires_at: Instant,
}

/// Ownership of one outgoing encoded media item after a nonblocking send.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaSend {
    /// Sent, or committed to the provider's bounded reliable window.
    Accepted,
    /// No sequence was consumed; the caller retains the item and its age.
    WouldBlock,
}

/// Inputs required to establish a direct outbound AllStarLink-compatible call.
pub struct DialOptions<'a> {
    /// Resolved remote IAX2 address.
    pub remote: SocketAddr,
    /// Locally unique nonzero 15-bit IAX call number.
    pub local_call: u16,
    /// Local node number sent as the IAX caller identity.
    pub local_node: &'a str,
    /// Requested remote node number.
    pub remote_node: &'a str,
    /// Local node secret used only if the peer challenges with MD5.
    pub secret: &'a str,
    /// Maximum duration for call setup.
    pub timeout: Duration,
}

/// Failure while resolving and establishing an outbound IAX call.
#[derive(Debug)]
pub enum DialError {
    /// The call number, node number, or timeout is invalid.
    InvalidOptions,
    /// UDP socket setup or send/receive failed.
    Network(io::Error),
    /// The peer did not complete the handshake before the timeout.
    Timeout,
    /// The peer rejected the call.
    Rejected,
    /// The bounded outgoing reliable-frame window is full.
    ReliableWindowFull,
    /// Too many application events arrived before the peer answered.
    EarlyEventsFull,
    /// The peer cleanly ended an established call.
    Hangup,
    /// IAX2 setup state rejected a malformed or unexpected response.
    Protocol(CallSetupError),
    /// The peer negotiated a codec other than G.711 μ-law.
    UnsupportedFormat(u64),
    /// A media packet was malformed or addressed to another call.
    Voice(VoiceFrameError),
    /// Caller-owned PCM or packet storage is too small for one media frame.
    Encode(VoiceFrameEncodeError),
    /// Decoded μ-law PCM does not fit in caller-owned storage.
    Decode(CodecError),
    /// A retained neutral provider rejected preparation or media processing.
    Provider(crate::codec::providers::Error),
    /// The composed jitter capability rejected an operation or returned invalid media.
    Jitter,
}

/// Established call metadata retained with its private UDP endpoint.
pub struct IaxPeer {
    endpoint: PeerEndpoint,
    remote: SocketAddr,
    local_call: u16,
    remote_call: u16,
    format: u64,
    codecs: Option<crate::codec::stream::Stream>,
    connected_at: Instant,
    setup: OutboundCallSetup,
    pending_reliable: VecDeque<PendingReliableFrame>,
    pending_replies: VecDeque<Vec<u8>>,
    pending_events: VecDeque<PendingEvent>,
    answered: bool,
    voice_epoch: Option<u32>,
    // Last automatic send time and next 8 kHz sample position within its burst.
    voice_clock: Option<(u32, u64)>,
    release_on_drop: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    async_attached: bool,
    // None preserves polling for callers that never supply scheduling deadlines.
    product_deadline: Option<Option<Instant>>,
    send_stats: SendStatistics,
    playout: Option<Playout>,
    // First terminal polling cause reported, or explicitly suppressed by local hangup.
    pub(crate) poll_failure_reported: bool,
}

/// Exclusive peer-owner counters; send helpers borrow only the cell-backed fields.
#[derive(Default)]
struct SendStatistics {
    blocked: std::cell::Cell<bool>,
    datagrams: std::cell::Cell<u64>,
    would_block: std::cell::Cell<u64>,
    retries: u64,
}

enum PeerEndpoint {
    Dedicated(UdpEndpoint),
    Shared {
        socket: std::sync::Arc<SharedSocket>,
        ingress: IngressConsumer,
        local: SocketAddr,
    },
}

/// Receive ownership transferred once from a dedicated socket to its Tokio pump.
type SocketIngress = (
    std::sync::Arc<tokio::net::UdpSocket>,
    crate::ingress::IngressProducer,
);

impl PeerEndpoint {
    fn send_to(&self, packet: &[u8], remote: SocketAddr) -> io::Result<usize> {
        #[cfg(test)]
        unit_tests::send_fault(remote)?;
        match self {
            Self::Dedicated(endpoint) => endpoint.send_to(packet, remote),
            Self::Shared { socket, .. } => socket.send_to(packet, remote),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Dedicated(endpoint) => endpoint.local_addr(),
            Self::Shared { local, .. } => Ok(*local),
        }
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<(usize, SocketAddr, Instant)>> {
        match self {
            Self::Dedicated(endpoint) => endpoint
                .try_receive(buffer)
                .map(|packet| packet.map(|(length, address)| (length, address, Instant::now()))),
            Self::Shared { ingress, .. } => {
                let Some(datagram) = ingress.try_pop() else {
                    if ingress.failed() {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "IAX receive task failed",
                        ));
                    }
                    return Ok(None);
                };
                let payload = datagram.payload();
                if payload.len() > buffer.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "IAX packet too large",
                    ));
                }
                buffer[..payload.len()].copy_from_slice(payload);
                Ok(Some((
                    payload.len(),
                    datagram.remote(),
                    datagram.arrived_at(),
                )))
            }
        }
    }
}

/// One received event from an established ULAW peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IaxPeerEvent {
    /// No datagram was waiting, or a control frame was handled internally.
    None,
    /// Decoded audio samples were written to the supplied PCM buffer.
    Audio(usize),
    /// Ordered missing/inserted 8kHz source samples; the receiver's PCM ring owns PLC.
    Gap(usize),
    /// A reliable ASL text message was copied to the supplied byte buffer.
    Text(usize),
    /// One decoded DTMF digit was acknowledged.
    Digit(u8),
    /// The remote radio asserted receive.
    RadioKey,
    /// The remote radio released receive.
    RadioUnkey,
    /// The peer cleanly ended the call.
    Hangup,
}

/// ABI1 owner-thread diagnostics. Durations use 8kHz source samples, not ring units.
/// Gauges are current; counters are cumulative for the connection lifetime.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IaxPeerObservation {
    /// Complete record size, currently 144 bytes; the original prefix is 112 bytes.
    pub struct_size: u32,
    /// Record revision, currently one.
    pub abi_version: u32,
    /// Opaque packets retained by jitter.
    pub jitter_queued_packets: u32,
    /// Current packet delay in source samples.
    pub jitter_delay_samples: u32,
    /// Sum of retained packet spans, including overlap.
    pub jitter_buffered_span_samples: u64,
    /// Duplicate packet drops.
    pub jitter_duplicate_drops: u64,
    /// Late packet drops.
    pub jitter_late_drops: u64,
    /// Jitter-capacity packet drops.
    pub jitter_full_drops: u64,
    /// Ordered missing source samples released.
    pub jitter_missing_samples: u64,
    /// Source samples inserted to increase delay.
    pub jitter_insertion_samples: u64,
    /// Source samples skipped to reduce delay.
    pub jitter_skipped_samples: u64,
    /// Resets caused by the maximum delay bound.
    pub jitter_limit_resets: u64,
    /// Queued packets discarded by maximum-delay resets.
    pub jitter_overload_drops: u64,
    /// Sum of packet spans discarded by maximum-delay resets.
    pub jitter_overload_span_samples: u64,
    /// Datagrams rejected by a full ingress mailbox.
    pub ingress_overflow_drops: u64,
    /// Current mailbox depth.
    pub ingress_queued_packets: u32,
    /// Fixed mailbox capacity.
    pub ingress_capacity_packets: u32,
    /// Datagrams accepted by the local socket, not proof of remote delivery.
    pub egress_datagrams: u64,
    /// Actual socket WouldBlock results across media, replies, and reliable frames.
    pub egress_would_block: u64,
    /// Previously transmitted reliable frames sent again successfully.
    pub egress_reliable_retries: u64,
    /// Current committed reliable window occupancy.
    pub egress_reliable_pending: u32,
    /// Current bounded best-effort reply queue occupancy.
    pub egress_reply_pending: u32,
}

impl IaxPeer {
    pub(crate) fn begin_turn(&self) {
        // An expired uncommitted item must not leave stale writable interest.
        self.send_stats.blocked.set(false);
    }

    pub(crate) fn wait_state(&self) -> crate::async_driver::PeerWait {
        let now = tokio::time::Instant::now().into_std();
        let blocked = self.send_stats.blocked.get();
        let protocol = self
            .pending_reliable
            .iter()
            .map(|frame| {
                if blocked {
                    frame.expires_at
                } else {
                    frame.next_retry.min(frame.expires_at)
                }
            })
            .min();
        let playout = self
            .playout
            .as_ref()
            .and_then(|playout| playout.deadline(now));
        // A due provider item left unconsumed by the bounded product turn means
        // inbound PCM backpressure, not idle work. Retry that work at 10 ms.
        let provider = protocol.into_iter().chain(playout).min().map(|deadline| {
            if deadline <= now {
                now + crate::async_driver::TIMER_INTERVAL
            } else {
                deadline
            }
        });
        let product = self
            .product_deadline
            .unwrap_or(Some(now + crate::async_driver::TIMER_INTERVAL));
        let writable = if blocked {
            match &self.endpoint {
                PeerEndpoint::Shared { socket, .. } => socket.registered(),
                PeerEndpoint::Dedicated(_) => None,
            }
        } else {
            None
        };
        crate::async_driver::PeerWait {
            deadline: provider.into_iter().chain(product).min(),
            writable,
        }
    }

    pub(crate) fn set_product_deadline(&mut self, after_ns: u64) -> Result<(), DialError> {
        let deadline = if after_ns == u64::MAX {
            None
        } else {
            Some(
                tokio::time::Instant::now()
                    .into_std()
                    .checked_add(Duration::from_nanos(after_ns))
                    .ok_or(DialError::InvalidOptions)?,
            )
        };
        self.product_deadline = Some(deadline);
        Ok(())
    }
    /// Read only on the exclusive callback owner or after it is quiesced.
    /// Requires composed jitter and queue-backed ingress; never call from audio.
    pub fn observe(&self) -> Result<IaxPeerObservation, DialError> {
        let PeerEndpoint::Shared { ingress, .. } = &self.endpoint else {
            return Err(DialError::InvalidOptions);
        };
        let jitter = self
            .playout
            .as_ref()
            .ok_or(DialError::InvalidOptions)?
            .observe()?;
        let ingress = ingress.stats();
        Ok(IaxPeerObservation {
            struct_size: std::mem::size_of::<IaxPeerObservation>() as u32,
            abi_version: 1,
            jitter_queued_packets: jitter.queued_packets,
            jitter_delay_samples: jitter.delay,
            jitter_buffered_span_samples: jitter.buffered_span,
            jitter_duplicate_drops: jitter.duplicate_drops,
            jitter_late_drops: jitter.late_drops,
            jitter_full_drops: jitter.full_drops,
            jitter_missing_samples: jitter.missing_span,
            jitter_insertion_samples: jitter.insertion_span,
            jitter_skipped_samples: jitter.skipped_span,
            jitter_limit_resets: jitter.limit_resets,
            jitter_overload_drops: jitter.overload_drops,
            jitter_overload_span_samples: jitter.overload_span,
            ingress_overflow_drops: ingress.dropped_packets,
            ingress_queued_packets: ingress.queued_packets as u32,
            ingress_capacity_packets: ingress.capacity_packets as u32,
            egress_datagrams: self.send_stats.datagrams.get(),
            egress_would_block: self.send_stats.would_block.get(),
            egress_reliable_retries: self.send_stats.retries,
            egress_reliable_pending: self.pending_reliable.len() as u32,
            egress_reply_pending: self.pending_replies.len() as u32,
        })
    }

    /// Compose optional packet jitter before attaching the exclusive async owner.
    ///
    /// # Safety
    /// The descriptor must be readable for its declared size and its DSO must
    /// remain loaded until this peer is destroyed, after async-owner quiescence.
    pub unsafe fn configure_jitter(
        &mut self,
        descriptor: *const std::ffi::c_void,
    ) -> Result<(), DialError> {
        if self.async_attached || self.playout.is_some() {
            return Err(DialError::InvalidOptions);
        }
        let rate = self.sample_rate_hz();
        let loss_unit = self
            .codecs
            .as_ref()
            .map_or(rate / 100, |codecs| codecs.loss_unit);
        let jitter = unsafe { crate::jitter::Jitter::new_at_rate(descriptor, rate, loss_unit) }
            .map_err(|_| DialError::InvalidOptions)?;
        self.playout = Some(Playout::new_at_rate(jitter, self.connected_at, rate));
        Ok(())
    }

    /// Prepare one queue-backed receive owner before its retained callback starts.
    /// Dedicated sockets transfer receive ownership to the returned async pump.
    pub(crate) fn prepare_async_ingress(
        &mut self,
        runtime: &tokio::runtime::Handle,
    ) -> io::Result<(crate::ingress::IngressWake, Option<SocketIngress>)> {
        if self.async_attached {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "peer async attachment is one-shot",
            ));
        }
        let shared = match &self.endpoint {
            PeerEndpoint::Shared {
                socket, ingress, ..
            } => {
                socket.register(runtime)?;
                self.async_attached = true;
                return Ok((ingress.wake(), None));
            }
            PeerEndpoint::Dedicated(endpoint) => endpoint.shared_socket(),
        };
        let socket = shared.register(runtime)?;
        let local = shared.local_addr()?;
        // Each retired endpoint keeps its own queue; reusing call numbers cannot reuse it.
        let (producer, ingress) = crate::ingress::producer_ingress(64, u64::from(self.local_call))
            .map_err(|_| io::Error::other("invalid IAX ingress capacity"))?;
        let wake = ingress.wake();
        self.endpoint = PeerEndpoint::Shared {
            socket: shared,
            ingress,
            local,
        };
        self.async_attached = true;
        Ok((wake, Some((socket, producer))))
    }

    pub(crate) fn from_inbound(
        socket: std::sync::Arc<SharedSocket>,
        ingress: IngressConsumer,
        local: SocketAddr,
        remote: SocketAddr,
        local_call: u16,
        remote_call: u16,
        format: u64,
    ) -> Result<(Self, std::sync::Arc<std::sync::atomic::AtomicBool>), DialError> {
        let setup = OutboundCallSetup::for_inbound_call(local_call, remote_call)
            .map_err(DialError::Protocol)?;
        let released = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let peer = Self {
            endpoint: PeerEndpoint::Shared {
                socket,
                ingress,
                local,
            },
            remote,
            local_call,
            remote_call,
            format,
            codecs: None,
            connected_at: Instant::now(),
            setup,
            pending_reliable: VecDeque::new(),
            pending_replies: VecDeque::new(),
            pending_events: VecDeque::new(),
            answered: true,
            voice_epoch: None,
            voice_clock: None,
            release_on_drop: Some(std::sync::Arc::clone(&released)),
            async_attached: false,
            product_deadline: None,
            send_stats: SendStatistics::default(),
            playout: None,
            poll_failure_reported: false,
        };
        Ok((peer, released))
    }

    /// Prepare the accepted format's directional contexts before sending ACCEPT.
    pub(crate) fn compose_codec(&mut self, catalog: &FormatCatalog) -> Result<(), DialError> {
        let profile = IaxFormat(self.format)
            .profile()
            .ok_or(DialError::UnsupportedFormat(self.format))?;
        self.codecs = Some(
            crate::codec::stream::Stream::open(catalog.codecs(), profile)
                .map_err(DialError::Provider)?,
        );
        Ok(())
    }

    /// Send an authorized inbound ACCEPT and ANSWER through the normal reliable window.
    pub(crate) fn accept_inbound(&mut self, accept: Vec<u8>) -> Result<(), DialError> {
        let answer = self
            .setup
            .send_answer(self.elapsed_ms())
            .map_err(DialError::Protocol)?;
        self.send_reliable(accept)?;
        self.send_reliable(answer)
    }

    /// Negotiated IAX codec-format bit.
    pub const fn format(&self) -> u64 {
        self.format
    }

    /// Required decoded linear-PCM samplerate.
    pub const fn sample_rate_hz(&self) -> u32 {
        match &self.codecs {
            Some(codecs) => codecs.rate,
            None => ULAW_SAMPLE_RATE_HZ,
        }
    }

    /// Local IAX call number assigned to this peer.
    pub const fn local_call_number(&self) -> u16 {
        self.local_call
    }

    /// Remote IAX call number returned by the peer.
    pub const fn remote_call_number(&self) -> u16 {
        self.remote_call
    }

    /// Local UDP source address selected for this outbound call.
    pub fn local_addr(&self) -> Result<SocketAddr, DialError> {
        self.endpoint.local_addr().map_err(DialError::Network)
    }

    /// Remote UDP destination for this outbound call.
    pub const fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    /// Milliseconds elapsed since the remote acknowledged the call.
    pub fn elapsed_ms(&self) -> u32 {
        self.connected_at
            .elapsed()
            .as_millis()
            .min(u128::from(u32::MAX)) as u32
    }

    /// Timestamp continuous PCM by sample count, not executor wakeup time.
    /// Empty audio ends the burst. A gap over Asterisk's 160 ms timestamp-skew
    /// allowance also reanchors callers that do not send an explicit idle marker.
    /// Only successful sends advance the clock; fractional milliseconds are retained.
    pub(crate) fn send_audio(&mut self, pcm: &[f32]) -> Result<(), DialError> {
        let now = self.elapsed_ms();
        let sample = self
            .voice_clock
            .filter(|(sent, _)| now.wrapping_sub(*sent) <= 160)
            .map_or(u64::from(now) * 8, |(_, next)| next);
        self.send_ulaw(pcm, (sample / 8) as u32)?;
        self.voice_clock = (!pcm.is_empty()).then_some((now, sample + pcm.len() as u64));
        Ok(())
    }

    /// Establish codec and timestamp epoch with full voice; use mini frames within that epoch.
    pub fn send_ulaw(&mut self, pcm: &[f32], timestamp_ms: u32) -> Result<(), DialError> {
        let mut payload = [0_u8; MAX_PACKET_SIZE - 12];
        let length = G711Ulaw
            .encode(pcm, &mut payload)
            .map_err(|error| DialError::Encode(VoiceFrameEncodeError::Codec(error)))?;
        match self.send_encoded_ulaw(&payload[..length], timestamp_ms)? {
            MediaSend::Accepted => Ok(()),
            MediaSend::WouldBlock => Err(DialError::Network(io::ErrorKind::WouldBlock.into())),
        }
    }

    /// Submit caller-encoded ULAW at its source timestamp. A committed full frame
    /// survives congestion; a blocked mini remains with the caller for expiry.
    /// Empty payloads carry the end-of-burst marker under the same ordering rules.
    pub fn send_prepared_ulaw(
        &mut self,
        payload: &[u8],
        timestamp_ms: u32,
    ) -> Result<MediaSend, DialError> {
        self.send_encoded_ulaw(payload, timestamp_ms)
    }

    /// Accept source PCM once, retaining incomplete coding units in the peer's
    /// independent encoder. Byte count, real span and wire frames are distinct.
    pub fn prepare_audio(
        &mut self,
        pcm: &[f32],
        encoded: &mut [u8],
        flush: bool,
    ) -> Result<crate::codec::providers::EncodeResult, DialError> {
        self.codecs
            .as_mut()
            .ok_or(DialError::InvalidOptions)?
            .encoder
            .encode(pcm, encoded, flush)
            .map_err(DialError::Provider)
    }

    /// Deliberately abandon expired/discontinuous encoder input, never a retry.
    pub fn reset_encoder(&mut self) -> Result<(), DialError> {
        self.codecs
            .as_mut()
            .ok_or(DialError::InvalidOptions)?
            .encoder
            .reset()
            .map_err(DialError::Provider)
    }

    /// Submit one previously prepared packet without encoding again. A blocked
    /// send leaves bytes, timestamp and original media age with its caller.
    pub fn send_prepared_audio(
        &mut self,
        payload: &[u8],
        packet_frames: u32,
        timestamp_ms: u32,
    ) -> Result<MediaSend, DialError> {
        let codecs = self.codecs.as_ref().ok_or(DialError::InvalidOptions)?;
        let span = if payload.is_empty() {
            0
        } else {
            codecs
                .decoder
                .inspect(payload)
                .map_err(DialError::Provider)?
                .frames
        };
        if span != packet_frames {
            return Err(DialError::InvalidOptions);
        }
        self.send_encoded_ulaw(payload, timestamp_ms)
    }

    fn send_encoded_ulaw(
        &mut self,
        payload: &[u8],
        timestamp_ms: u32,
    ) -> Result<MediaSend, DialError> {
        if payload.len() > self.maximum_datagram() - 12 {
            return Err(DialError::InvalidOptions);
        }
        // An epoch's full voice and earlier signaling must reach the socket first.
        if self.pending_reliable.iter().any(|frame| !frame.sent) {
            return Ok(MediaSend::WouldBlock);
        }
        let epoch = timestamp_ms >> 16;
        if self.voice_epoch != Some(epoch) {
            self.ensure_reliable_capacity()?;
            let full = self
                .setup
                .send_voice_frame(payload, timestamp_ms, self.format)
                .map_err(DialError::Protocol)?;
            self.send_reliable(full)?;
            self.voice_epoch = Some(epoch);
            return Ok(MediaSend::Accepted);
        }
        let mut packet = [0_u8; MAX_PACKET_SIZE];
        packet[..2].copy_from_slice(&self.local_call.to_be_bytes());
        packet[2..4].copy_from_slice(&(timestamp_ms as u16).to_be_bytes());
        packet[4..4 + payload.len()].copy_from_slice(payload);
        send_media(
            &self.endpoint,
            &packet[..4 + payload.len()],
            self.remote,
            &self.send_stats,
        )
    }

    /// Send one ASL text payload as a sequenced IAX full frame.
    ///
    /// The peer retains the frame until a cumulative IAX ACK covers its sequence number and
    /// retransmits it using the bounded Asterisk-compatible retry schedule if the ACK is lost.
    pub fn send_text(&mut self, payload: &[u8]) -> Result<(), DialError> {
        self.ensure_reliable_capacity()?;
        if payload.len() > self.maximum_datagram() - 12 {
            return Err(DialError::InvalidOptions);
        }
        let packet = self
            .setup
            .send_text_frame(payload, self.elapsed_ms())
            .map_err(DialError::Protocol)?;
        self.send_reliable(packet)
    }

    fn maximum_datagram(&self) -> usize {
        if self.remote.is_ipv4() {
            65_507
        } else {
            crate::ingress::MAX_DATAGRAM_SIZE
        }
    }

    /// Send one completed DTMF digit as a sequenced IAX full frame and retain it until ACKed.
    pub fn send_dtmf(&mut self, digit: u8) -> Result<(), DialError> {
        self.ensure_reliable_capacity()?;
        let packet = self
            .setup
            .send_dtmf(digit, self.elapsed_ms())
            .map_err(DialError::Protocol)?;
        self.send_reliable(packet)
    }

    /// Send and retain a reliable HANGUP frame until the peer acknowledges it.
    pub fn hangup(&mut self) -> Result<(), DialError> {
        self.ensure_reliable_capacity()?;
        let packet = self
            .setup
            .send_hangup(self.elapsed_ms())
            .map_err(DialError::Protocol)?;
        self.send_reliable(packet)
    }

    /// Poll one datagram and expose audio or ASL text through caller-owned storage.
    ///
    /// This also advances retries for established reliable frames and applies cumulative ACKs
    /// from received full frames. Text/control acknowledgements are emitted internally.
    /// Valid header-only voice frames retain their ACK/sequence semantics but deliver no
    /// audio, jitter-buffer input, or receive-activity change. Old full frames
    /// are acknowledged without delivery; sequence gaps request retransmission.
    pub fn poll_event(
        &mut self,
        pcm: &mut [f32],
        text: &mut [u8],
    ) -> Result<IaxPeerEvent, DialError> {
        if let Some(pending) = self.pending_events.front() {
            if pending.pcm.len() > pcm.len()
                || pending.text.len() > text.len()
                || (matches!(pending.event, IaxPeerEvent::Digit(_)) && text.is_empty())
            {
                return Err(DialError::InvalidOptions);
            }
            pcm[..pending.pcm.len()].copy_from_slice(&pending.pcm);
            text[..pending.text.len()].copy_from_slice(&pending.text);
            return Ok(self.pending_events.pop_front().expect("front exists").event);
        }
        self.poll_transport_event(pcm, text)
    }

    fn wait_answer(&mut self, deadline: Instant) -> Result<(), DialError> {
        let mut pcm = [0.0; MAX_PACKET_SIZE];
        let mut text = [0; MAX_PACKET_SIZE];
        while Instant::now() < deadline {
            let event = self.poll_transport_event(&mut pcm, &mut text)?;
            if self.answered {
                return Ok(());
            }
            match event {
                IaxPeerEvent::None => thread::sleep(Duration::from_millis(2)),
                IaxPeerEvent::Hangup => return Err(DialError::Hangup),
                _ => {
                    if self.pending_events.len() == MAX_EARLY_EVENTS {
                        return Err(DialError::EarlyEventsFull);
                    }
                    self.pending_events.push_back(PendingEvent {
                        event,
                        pcm: match event {
                            IaxPeerEvent::Audio(count) => pcm[..count].to_vec(),
                            _ => Vec::new(),
                        },
                        text: match event {
                            IaxPeerEvent::Text(count) => text[..count].to_vec(),
                            _ => Vec::new(),
                        },
                    });
                }
            }
        }
        Err(DialError::Timeout)
    }

    fn poll_transport_event(
        &mut self,
        pcm: &mut [f32],
        text: &mut [u8],
    ) -> Result<IaxPeerEvent, DialError> {
        self.retry_reliable_frames()?;
        self.flush_replies()?;
        // Admit the bounded receive batch before advancing packet time. Otherwise
        // executor batching would masquerade as network loss in already due media.
        for _ in 0..MAX_RELIABLE_WINDOW {
            if self.playout.as_ref().is_some_and(Playout::blocks_transport) {
                break;
            }
            let mut packet = [0_u8; MAX_PACKET_SIZE];
            let Some((length, address, arrived_at)) = self
                .endpoint
                .receive(&mut packet)
                .map_err(DialError::Network)?
            else {
                break;
            };
            let event = if address == self.remote {
                self.receive_event(&packet[..length], arrived_at, pcm, text)?
            } else {
                IaxPeerEvent::None
            };
            if self.playout.is_none() || event != IaxPeerEvent::None {
                return Ok(event);
            }
        }
        match &mut self.playout {
            Some(playout) => playout.poll_with_codec(
                Instant::now(),
                pcm,
                self.codecs.as_mut().map(|codecs| &mut codecs.decoder),
            ),
            None => Ok(IaxPeerEvent::None),
        }
    }

    fn receive_event(
        &mut self,
        bytes: &[u8],
        arrived_at: Instant,
        pcm: &mut [f32],
        text: &mut [u8],
    ) -> Result<IaxPeerEvent, DialError> {
        if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
            let frame = parse_full_frame_packet(bytes)
                .map_err(|_| DialError::Protocol(CallSetupError::InvalidFrame))?;
            if frame.header.frame_type == 1 && text.is_empty() {
                return Err(DialError::InvalidOptions);
            }
            if matches!(frame.header.frame_type, 1 | 4 | 6 | 7 | 10) {
                // ACK credit is independent of the received frame's sequence.
                // Validate identity first, and free sent slots before a reliable reply.
                self.setup
                    .validate_call_ids(&frame.header)
                    .map_err(DialError::Protocol)?;
                if decode_iax_command(&frame.header) == Ok(Some(IaxCommand::Vnak)) {
                    self.setup
                        .validate_peer_acknowledgement(&frame.header)
                        .map_err(DialError::Protocol)?;
                    if !frame.payload.is_empty() {
                        return Err(DialError::Protocol(CallSetupError::InvalidFrame));
                    }
                    self.acknowledge_reliable_frames(frame.header.incoming_sequence);
                    // VNAK is unsequenced. Replay only already-sent retained
                    // frames, without spending/resetting their timed retry budget.
                    let packets = self
                        .pending_reliable
                        .iter()
                        .filter(|pending| {
                            pending.sent
                                && pending
                                    .outgoing_sequence
                                    .wrapping_sub(frame.header.incoming_sequence)
                                    < 128
                        })
                        .map(|pending| self.setup.retransmit(&pending.packet))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(DialError::Protocol)?;
                    for packet in packets {
                        self.send_reply(packet)?;
                    }
                    return Ok(IaxPeerEvent::None);
                }
                // ACK itself is unsequenced; its OSeq never classifies its credit as old.
                let old = decode_iax_command(&frame.header) != Ok(Some(IaxCommand::Ack))
                    && self.setup.is_old_frame(&frame.header);
                if !old {
                    self.acknowledge_reliable_frames(frame.header.incoming_sequence);
                }
                // PING/LAGRQ replies consume a sequence. Leave the request for
                // retransmission if the reliable window cannot retain that reply.
                if !old
                    && frame.header.frame_type == 6
                    && matches!(frame.header.subclass, 2 | 11)
                    && self.ensure_reliable_capacity().is_err()
                {
                    return Ok(IaxPeerEvent::None);
                }
                let response = self
                    .setup
                    .receive_linked(bytes)
                    .map_err(DialError::Protocol)?;
                let reply = match response {
                    LinkedCallResponse::SendReliable(packet) => {
                        self.send_reliable(packet)?;
                        return Ok(IaxPeerEvent::None);
                    }
                    LinkedCallResponse::Send(packet) => {
                        self.send_reply(packet)?;
                        return Ok(IaxPeerEvent::None);
                    }
                    LinkedCallResponse::PongAcknowledged {
                        acknowledgement, ..
                    } => acknowledgement,
                    LinkedCallResponse::Answered { acknowledgement } => {
                        self.answered = true;
                        acknowledgement
                    }
                    LinkedCallResponse::Ended { acknowledgement } => {
                        self.send_reply(acknowledgement)?;
                        return Ok(IaxPeerEvent::Hangup);
                    }
                    LinkedCallResponse::Text {
                        text: received,
                        acknowledgement,
                    } => {
                        self.send_reply(acknowledgement)?;
                        if received.len() > text.len() {
                            return Err(DialError::InvalidOptions);
                        }
                        text[..received.len()].copy_from_slice(&received);
                        return Ok(IaxPeerEvent::Text(received.len()));
                    }
                    LinkedCallResponse::Digit {
                        digit,
                        acknowledgement,
                    } => {
                        self.send_reply(acknowledgement)?;
                        return Ok(IaxPeerEvent::Digit(digit));
                    }
                    LinkedCallResponse::RadioKey { acknowledgement } => {
                        self.send_reply(acknowledgement)?;
                        if let Some(playout) = &mut self.playout {
                            if !playout.key(frame.header.timestamp)? {
                                return Ok(IaxPeerEvent::None);
                            }
                        }
                        return Ok(IaxPeerEvent::RadioKey);
                    }
                    LinkedCallResponse::RadioUnkey { acknowledgement } => {
                        self.send_reply(acknowledgement)?;
                        if let Some(playout) = &mut self.playout {
                            playout.unkey();
                            return Ok(IaxPeerEvent::None);
                        }
                        return Ok(IaxPeerEvent::RadioUnkey);
                    }
                    LinkedCallResponse::NoAction => return Ok(IaxPeerEvent::None),
                };
                self.send_reply(reply)?;
                return Ok(IaxPeerEvent::None);
            }
        }

        let voice = parse_voice_frame(bytes, self.format).map_err(DialError::Voice)?;
        let (payload, timestamp, mini) = match voice {
            VoiceFrame::Full {
                header,
                format,
                payload,
            } if header.source_call_number == self.remote_call
                && header.destination_call_number == self.local_call
                && format == self.format =>
            {
                let old = self.setup.is_old_frame(&header);
                let (deliver, acknowledgement) = if self.playout.is_some() {
                    self.setup.receive_media_reordered(&header)
                } else {
                    self.setup.receive_media(&header)
                }
                .map_err(DialError::Protocol)?;
                if !old {
                    self.acknowledge_reliable_frames(header.incoming_sequence);
                }
                self.send_reply(acknowledgement)?;
                if !deliver {
                    return Ok(IaxPeerEvent::None);
                }
                (payload, header.timestamp, false)
            }
            VoiceFrame::Mini {
                header, payload, ..
            } if header.source_call_number == self.remote_call => {
                (payload, u32::from(header.timestamp), true)
            }
            _ => return Err(DialError::Voice(VoiceFrameError::NotVoiceFrame)),
        };
        // Header-only voice marks idle media. Full-frame sequence/ACK handling
        // above still applies, but no samples or jitter time may be published.
        if payload.is_empty() {
            return Ok(IaxPeerEvent::None);
        }
        if let Some(playout) = &mut self.playout {
            playout.put_with_codec(
                timestamp,
                mini,
                arrived_at,
                payload,
                self.codecs.as_ref().map(|codecs| &codecs.decoder),
            )?;
            return Ok(IaxPeerEvent::None);
        }
        match &mut self.codecs {
            Some(codecs) => match codecs.decoder.inspect(payload) {
                Err(error) if error.status == crate::codec::providers::Status::Malformed => {
                    Ok(IaxPeerEvent::None)
                }
                Err(error) => Err(DialError::Provider(error)),
                Ok(info) => match codecs
                    .decoder
                    .decode_recovering(payload, pcm)
                    .map_err(DialError::Provider)?
                {
                    0 => Ok(IaxPeerEvent::Gap(info.frames as usize)),
                    frames => Ok(IaxPeerEvent::Audio(frames)),
                },
            },
            None => G711Ulaw
                .decode(payload, pcm)
                .map(IaxPeerEvent::Audio)
                .map_err(DialError::Decode),
        }
    }

    fn ensure_reliable_capacity(&self) -> Result<(), DialError> {
        if self.pending_reliable.len() == MAX_RELIABLE_WINDOW {
            Err(DialError::ReliableWindowFull)
        } else {
            Ok(())
        }
    }

    fn send_reply(&mut self, packet: Vec<u8>) -> Result<(), DialError> {
        // These are cumulative ACKs or duplicate cached replies, never a newly
        // committed sequence. Retain recent replies without letting an ACK flood
        // grow memory or prevent ingress. Committed frames have their own window.
        if self.pending_replies.len() == MAX_RELIABLE_WINDOW {
            self.pending_replies.pop_front();
        }
        self.pending_replies.push_back(packet);
        self.flush_replies()
    }

    fn flush_replies(&mut self) -> Result<(), DialError> {
        while let Some(packet) = self.pending_replies.front() {
            if send_media(&self.endpoint, packet, self.remote, &self.send_stats)?
                == MediaSend::WouldBlock
            {
                break;
            }
            self.pending_replies.pop_front();
        }
        Ok(())
    }

    fn send_reliable(&mut self, packet: Vec<u8>) -> Result<(), DialError> {
        self.ensure_reliable_capacity()?;
        let header = parse_full_frame_packet(&packet)
            .map_err(|_| DialError::Protocol(CallSetupError::InvalidFrame))?
            .header;
        let now = Instant::now();
        // Retain bytes before touching UDP. Sequencing is already committed.
        self.pending_reliable.push_back(PendingReliableFrame {
            packet,
            outgoing_sequence: header.outgoing_sequence,
            next_retry: now,
            retry_interval: LINK_INITIAL_RETRY,
            retries: 0,
            sent: false,
            expires_at: now + LINK_INITIAL_RETRY + MAX_RETRY * u32::from(MAX_RELIABLE_RETRIES),
        });
        self.retry_reliable_frames()
    }

    fn acknowledge_reliable_frames(&mut self, next_sequence: u8) {
        acknowledge_reliable_frames(&mut self.pending_reliable, next_sequence);
    }

    fn retry_reliable_frames(&mut self) -> Result<(), DialError> {
        let now = Instant::now();
        for frame in &mut self.pending_reliable {
            if now >= frame.expires_at {
                return Err(DialError::Timeout);
            }
            if now < frame.next_retry {
                continue;
            }
            if frame.retries == MAX_RELIABLE_RETRIES {
                return Err(DialError::Timeout);
            }
            let retry;
            let packet = if frame.sent {
                retry = self
                    .setup
                    .retransmit(&frame.packet)
                    .map_err(DialError::Protocol)?;
                &retry
            } else {
                &frame.packet
            };
            if send_media(&self.endpoint, packet, self.remote, &self.send_stats)?
                == MediaSend::WouldBlock
            {
                break; // Still process inbound ACKs and control while the socket is full.
            }
            if frame.sent {
                self.send_stats.retries = self.send_stats.retries.saturating_add(1);
                frame.retries += 1;
                frame.retry_interval = (frame.retry_interval * 10).min(MAX_RETRY);
            } else {
                frame.sent = true;
                frame.expires_at =
                    now + LINK_INITIAL_RETRY + MAX_RETRY * u32::from(MAX_RELIABLE_RETRIES);
            }
            frame.next_retry = now + frame.retry_interval;
        }
        Ok(())
    }

    /// Legacy audio-only polling without composed jitter; use `poll_event` for ordered gaps.
    pub fn poll_ulaw(&mut self, pcm: &mut [f32]) -> Result<Option<usize>, DialError> {
        if self.playout.is_some() {
            return Err(DialError::InvalidOptions);
        }
        let mut text = [0_u8; 1500];
        match self.poll_event(pcm, &mut text)? {
            IaxPeerEvent::Audio(count) => Ok(Some(count)),
            IaxPeerEvent::Hangup => Err(DialError::Hangup),
            IaxPeerEvent::None
            | IaxPeerEvent::Gap(_)
            | IaxPeerEvent::Text(_)
            | IaxPeerEvent::Digit(_)
            | IaxPeerEvent::RadioKey
            | IaxPeerEvent::RadioUnkey => Ok(None),
        }
    }
}

fn acknowledge_reliable_frames(pending: &mut VecDeque<PendingReliableFrame>, next_sequence: u8) {
    let Some(first) = pending.front() else {
        return;
    };
    let acknowledged = usize::from(next_sequence.wrapping_sub(first.outgoing_sequence));
    if acknowledged <= pending.len() && pending.iter().take(acknowledged).all(|frame| frame.sent) {
        pending.drain(..acknowledged);
    }
}

fn send_media(
    endpoint: &PeerEndpoint,
    packet: &[u8],
    remote: SocketAddr,
    stats: &SendStatistics,
) -> Result<MediaSend, DialError> {
    match endpoint.send_to(packet, remote) {
        Ok(_) => {
            stats.datagrams.set(stats.datagrams.get().saturating_add(1));
            Ok(MediaSend::Accepted)
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            stats.blocked.set(true);
            stats
                .would_block
                .set(stats.would_block.get().saturating_add(1));
            Ok(MediaSend::WouldBlock)
        }
        Err(error) => Err(DialError::Network(error)),
    }
}

impl Drop for IaxPeer {
    fn drop(&mut self) {
        if let Some(released) = &self.release_on_drop {
            released.store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

#[cfg(test)]
#[path = "client_unit_tests.rs"]
mod unit_tests;

/// Establish one direct ULAW-only IAX2 call.
///
/// The network operation is bounded by `timeout`; it runs on the caller's
/// control/network owner, never an audio callback. This initial slice owns
/// call-token, MD5 challenge, ACCEPT, ANSWER, and ACK processing. Application
/// events received before ANSWER are retained in a bounded queue for polling.
/// It deliberately
/// advertises no codec other than 8 kHz G.711 μ-law. Reliable setup frames use
/// Asterisk's default 100 ms initial retry, tenfold backoff, and four total
/// transmissions unless the caller's timeout expires first.
pub fn dial_ulaw(options: DialOptions<'_>) -> Result<IaxPeer, DialError> {
    dial_composed(options, None)
}

/// Establish a provider-backed call advertising only the retained verified catalog.
pub fn dial(
    options: DialOptions<'_>,
    catalog: std::sync::Arc<FormatCatalog>,
) -> Result<IaxPeer, DialError> {
    dial_composed(options, Some(catalog))
}

fn dial_composed(
    options: DialOptions<'_>,
    catalog: Option<std::sync::Arc<FormatCatalog>>,
) -> Result<IaxPeer, DialError> {
    if options.local_call == 0
        || options.local_call > 0x7fff
        || !valid_node(options.local_node)
        || !valid_node(options.remote_node)
        || options.timeout.is_zero()
    {
        return Err(DialError::InvalidOptions);
    }

    let endpoint =
        UdpEndpoint::bind(wildcard_for(options.remote.ip())).map_err(DialError::Network)?;
    let version = 2_u16.to_be_bytes();
    let elements = [
        InformationElement {
            kind: IE_USERNAME,
            data: b"radio",
        },
        InformationElement {
            kind: IE_CALLED_NUMBER,
            data: options.remote_node.as_bytes(),
        },
        InformationElement {
            kind: IE_CALLING_NUMBER,
            data: options.local_node.as_bytes(),
        },
        InformationElement {
            kind: IE_CALLING_ANI,
            data: options.local_node.as_bytes(),
        },
        InformationElement {
            kind: IE_VERSION,
            data: &version,
        },
    ];
    let mut payload = serialize_information_elements(&elements)
        .map_err(|error| DialError::Protocol(CallSetupError::InformationElements(error)))?;
    let capability = catalog
        .as_ref()
        .map_or(IAX_FORMAT_ULAW, |catalog| catalog.advertised_mask());
    let preferred = catalog.as_ref().map_or(IAX_FORMAT_ULAW, |catalog| {
        IaxFormat::for_profile(
            catalog
                .select(capability)
                .expect("validated nonempty catalog"),
        )
        .0
    });
    append_formats(&mut payload, preferred, Some(capability));
    let elements = parse_information_elements(&payload)
        .map_err(|error| DialError::Protocol(CallSetupError::InformationElements(error)))?;
    let started = Instant::now();
    let mut setup =
        OutboundCallSetup::new(options.local_call, 0, &elements).map_err(DialError::Protocol)?;
    let mut pending_packet = setup.initial_packet().to_vec();
    send(&endpoint, &pending_packet, options.remote)?;

    let deadline = started + options.timeout;
    let mut retry_interval = INITIAL_RETRY;
    let mut retry_at = Instant::now() + retry_interval;
    let mut transmissions = 1;
    let mut acknowledged = false;
    let mut packet = [0_u8; MAX_PACKET_SIZE];
    while Instant::now() < deadline {
        let Some((length, address)) = endpoint
            .try_receive(&mut packet)
            .map_err(DialError::Network)?
        else {
            let now = Instant::now();
            if !acknowledged && now >= retry_at {
                if transmissions >= MAX_TRANSMISSIONS {
                    return Err(DialError::Timeout);
                }
                pending_packet = setup
                    .retransmit(&pending_packet)
                    .map_err(DialError::Protocol)?;
                send(&endpoint, &pending_packet, options.remote)?;
                transmissions += 1;
                retry_interval = (retry_interval * 10).min(MAX_RETRY);
                retry_at = now + retry_interval;
            }
            thread::sleep(Duration::from_millis(2));
            continue;
        };
        if address != options.remote {
            continue;
        }
        let bytes = &packet[..length];
        let timestamp = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
        match setup
            .receive_setup(bytes, timestamp, options.secret)
            .map_err(DialError::Protocol)?
        {
            OutboundSetupResponse::NoAction => acknowledged = true,
            OutboundSetupResponse::Send(response) => {
                acknowledged = false;
                send(&endpoint, &response, options.remote)?;
                pending_packet = response;
                retry_interval = INITIAL_RETRY;
                retry_at = Instant::now() + retry_interval;
                transmissions = 1;
            }
            OutboundSetupResponse::Accepted {
                remote_call,
                format,
                acknowledgement,
            } => {
                send(&endpoint, &acknowledgement, options.remote)?;
                if catalog.is_none() && format != IAX_FORMAT_ULAW {
                    return Err(DialError::UnsupportedFormat(format));
                }
                let codecs = catalog
                    .as_ref()
                    .map(|catalog| {
                        crate::codec::stream::Stream::open(
                            catalog.codecs(),
                            IaxFormat(format)
                                .profile()
                                .expect("selected verified format"),
                        )
                    })
                    .transpose()
                    .map_err(DialError::Provider)?;
                let mut peer = IaxPeer {
                    endpoint: PeerEndpoint::Dedicated(endpoint),
                    remote: options.remote,
                    local_call: options.local_call,
                    remote_call,
                    format,
                    codecs,
                    connected_at: Instant::now(),
                    setup,
                    pending_reliable: VecDeque::new(),
                    pending_replies: VecDeque::new(),
                    pending_events: VecDeque::new(),
                    answered: false,
                    voice_epoch: None,
                    voice_clock: None,
                    release_on_drop: None,
                    async_attached: false,
                    product_deadline: None,
                    send_stats: SendStatistics::default(),
                    playout: None,
                    poll_failure_reported: false,
                };
                peer.wait_answer(deadline)?;
                return Ok(peer);
            }
            OutboundSetupResponse::Rejected { acknowledgement } => {
                send(&endpoint, &acknowledgement, options.remote)?;
                return Err(DialError::Rejected);
            }
        }
    }
    Err(DialError::Timeout)
}

fn valid_node(node: &str) -> bool {
    !node.is_empty() && node.len() <= 31 && node.bytes().all(|byte| byte.is_ascii_digit())
}

fn wildcard_for(address: IpAddr) -> SocketAddr {
    SocketAddr::new(
        if address.is_ipv4() {
            IpAddr::from([0, 0, 0, 0])
        } else {
            IpAddr::from([0_u16; 8])
        },
        0,
    )
}

fn send(endpoint: &UdpEndpoint, packet: &[u8], remote: SocketAddr) -> Result<(), DialError> {
    endpoint
        .send_to(packet, remote)
        .map(|_| ())
        .map_err(DialError::Network)
}
