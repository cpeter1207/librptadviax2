//! Outbound IAX2 call establishment over the separate UDP transport.

use crate::{
    codec::{CodecAdapter, CodecError, G711Ulaw, IAX_FORMAT_ULAW, ULAW_SAMPLE_RATE_HZ},
    information_elements::InformationElement,
    ingress::IngressConsumer,
    media::{
        VoiceFrame, VoiceFrameEncodeError, VoiceFrameError, encode_mini_voice_frame,
        parse_voice_frame,
    },
    network::UdpEndpoint,
    protocol::{MiniFrameHeader, parse_full_frame_packet},
    session::{CallSetupError, LinkedCallResponse, OutboundCallSetup, OutboundSetupResponse},
};
use std::{
    collections::VecDeque,
    io,
    net::UdpSocket,
    net::{IpAddr, SocketAddr},
    thread,
    time::{Duration, Instant},
};

const IE_CALLED_NUMBER: u8 = 1;
const IE_CALLING_NUMBER: u8 = 2;
const IE_CALLING_ANI: u8 = 3;
const IE_USERNAME: u8 = 6;
const IE_CAPABILITY: u8 = 8;
const IE_FORMAT: u8 = 9;
const IE_VERSION: u8 = 11;
const INITIAL_RETRY: Duration = Duration::from_millis(100);
const MAX_RETRY: Duration = Duration::from_secs(10);
const MAX_TRANSMISSIONS: u8 = 4;
const LINK_INITIAL_RETRY: Duration = Duration::from_secs(2);
const MAX_RELIABLE_RETRIES: u8 = 4;
const MAX_RELIABLE_WINDOW: usize = 64;
const MAX_PACKET_SIZE: usize = 1500;
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
    UnsupportedFormat(u32),
    /// A media packet was malformed or addressed to another call.
    Voice(VoiceFrameError),
    /// Caller-owned PCM or packet storage is too small for one media frame.
    Encode(VoiceFrameEncodeError),
    /// Decoded μ-law PCM does not fit in caller-owned storage.
    Decode(CodecError),
}

/// Established call metadata retained with its private UDP endpoint.
pub struct IaxPeer {
    endpoint: PeerEndpoint,
    remote: SocketAddr,
    local_call: u16,
    remote_call: u16,
    format: u32,
    connected_at: Instant,
    setup: OutboundCallSetup,
    pending_reliable: VecDeque<PendingReliableFrame>,
    pending_events: VecDeque<PendingEvent>,
    answered: bool,
    voice_epoch: Option<u32>,
    release_on_drop: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

enum PeerEndpoint {
    Dedicated(UdpEndpoint),
    Shared {
        socket: std::sync::Arc<UdpSocket>,
        ingress: IngressConsumer,
        local: SocketAddr,
    },
}

impl PeerEndpoint {
    fn send_to(&self, packet: &[u8], remote: SocketAddr) -> io::Result<usize> {
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

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
        match self {
            Self::Dedicated(endpoint) => endpoint.try_receive(buffer),
            Self::Shared { ingress, .. } => {
                let Some(datagram) = ingress.try_pop() else {
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
                Ok(Some((payload.len(), datagram.remote())))
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

impl IaxPeer {
    pub(crate) fn from_inbound(
        socket: std::sync::Arc<UdpSocket>,
        ingress: IngressConsumer,
        local: SocketAddr,
        remote: SocketAddr,
        local_call: u16,
        remote_call: u16,
        format: u32,
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
            connected_at: Instant::now(),
            setup,
            pending_reliable: VecDeque::new(),
            pending_events: VecDeque::new(),
            answered: true,
            voice_epoch: None,
            release_on_drop: Some(std::sync::Arc::clone(&released)),
        };
        Ok((peer, released))
    }

    /// Negotiated IAX codec-format bit.
    pub const fn format(&self) -> u32 {
        self.format
    }

    /// Required decoded linear-PCM samplerate.
    pub const fn sample_rate_hz(&self) -> u32 {
        ULAW_SAMPLE_RATE_HZ
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

    /// Establish codec and timestamp epoch with full voice; use mini frames within that epoch.
    pub fn send_ulaw(&mut self, pcm: &[f32], timestamp_ms: u32) -> Result<(), DialError> {
        let mut packet = [0_u8; 1500];
        let epoch = timestamp_ms >> 16;
        if self.voice_epoch != Some(epoch) {
            self.ensure_reliable_capacity()?;
            let length = G711Ulaw
                .encode(pcm, &mut packet[12..])
                .map_err(|error| DialError::Encode(VoiceFrameEncodeError::Codec(error)))?;
            let full = self
                .setup
                .send_ulaw_frame(&packet[12..12 + length], timestamp_ms)
                .map_err(DialError::Protocol)?;
            self.send_reliable(full)?;
            self.voice_epoch = Some(epoch);
            return Ok(());
        }
        let length = encode_mini_voice_frame(
            &G711Ulaw,
            MiniFrameHeader {
                source_call_number: self.local_call,
                timestamp: timestamp_ms as u16,
            },
            pcm,
            &mut packet,
        )
        .map_err(DialError::Encode)?;
        self.endpoint
            .send_to(&packet[..length], self.remote)
            .map(|_| ())
            .map_err(DialError::Network)
    }

    /// Send one ASL text payload as a sequenced IAX full frame.
    ///
    /// The peer retains the frame until a cumulative IAX ACK covers its sequence number and
    /// retransmits it using the bounded Asterisk-compatible retry schedule if the ACK is lost.
    pub fn send_text(&mut self, payload: &[u8]) -> Result<(), DialError> {
        self.ensure_reliable_capacity()?;
        if payload.len() + 12 > MAX_PACKET_SIZE {
            return Err(DialError::InvalidOptions);
        }
        let packet = self
            .setup
            .send_text_frame(payload, self.elapsed_ms())
            .map_err(DialError::Protocol)?;
        self.send_reliable(packet)
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
        let mut packet = [0_u8; 1500];
        let Some((length, address)) = self
            .endpoint
            .receive(&mut packet)
            .map_err(DialError::Network)?
        else {
            return Ok(IaxPeerEvent::None);
        };
        if address != self.remote {
            return Ok(IaxPeerEvent::None);
        }
        let bytes = &packet[..length];
        if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
            let frame = parse_full_frame_packet(bytes)
                .map_err(|_| DialError::Protocol(CallSetupError::InvalidFrame))?;
            if frame.header.frame_type == 1 && text.is_empty() {
                return Err(DialError::InvalidOptions);
            }
            if matches!(frame.header.frame_type, 1 | 4 | 6 | 7) {
                let response = self
                    .setup
                    .receive_linked(bytes)
                    .map_err(DialError::Protocol)?;
                self.acknowledge_reliable_frames(frame.header.incoming_sequence);
                let reply = match response {
                    LinkedCallResponse::SendReliable(packet) => {
                        self.send_reliable(packet)?;
                        return Ok(IaxPeerEvent::None);
                    }
                    LinkedCallResponse::Send(packet) => {
                        self.endpoint
                            .send_to(&packet, self.remote)
                            .map_err(DialError::Network)?;
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
                        self.endpoint
                            .send_to(&acknowledgement, self.remote)
                            .map_err(DialError::Network)?;
                        return Ok(IaxPeerEvent::Hangup);
                    }
                    LinkedCallResponse::Text {
                        text: received,
                        acknowledgement,
                    } => {
                        self.endpoint
                            .send_to(&acknowledgement, self.remote)
                            .map_err(DialError::Network)?;
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
                        self.endpoint
                            .send_to(&acknowledgement, self.remote)
                            .map_err(DialError::Network)?;
                        return Ok(IaxPeerEvent::Digit(digit));
                    }
                    LinkedCallResponse::RadioKey { acknowledgement } => {
                        self.endpoint
                            .send_to(&acknowledgement, self.remote)
                            .map_err(DialError::Network)?;
                        return Ok(IaxPeerEvent::RadioKey);
                    }
                    LinkedCallResponse::RadioUnkey { acknowledgement } => {
                        self.endpoint
                            .send_to(&acknowledgement, self.remote)
                            .map_err(DialError::Network)?;
                        return Ok(IaxPeerEvent::RadioUnkey);
                    }
                    LinkedCallResponse::NoAction => return Ok(IaxPeerEvent::None),
                };
                self.endpoint
                    .send_to(&reply, self.remote)
                    .map_err(DialError::Network)?;
                return Ok(IaxPeerEvent::None);
            }
        }

        let voice = parse_voice_frame(bytes, self.format).map_err(DialError::Voice)?;
        let payload = match voice {
            VoiceFrame::Full {
                header,
                format,
                payload,
            } if header.source_call_number == self.remote_call
                && header.destination_call_number == self.local_call
                && format == self.format =>
            {
                let (deliver, acknowledgement) = self
                    .setup
                    .receive_voice(&header)
                    .map_err(DialError::Protocol)?;
                self.acknowledge_reliable_frames(header.incoming_sequence);
                self.endpoint
                    .send_to(&acknowledgement, self.remote)
                    .map_err(DialError::Network)?;
                if !deliver {
                    return Ok(IaxPeerEvent::None);
                }
                payload
            }
            VoiceFrame::Mini {
                header, payload, ..
            } if header.source_call_number == self.remote_call => payload,
            _ => return Err(DialError::Voice(VoiceFrameError::NotVoiceFrame)),
        };
        G711Ulaw
            .decode(payload, pcm)
            .map(IaxPeerEvent::Audio)
            .map_err(DialError::Decode)
    }

    fn ensure_reliable_capacity(&self) -> Result<(), DialError> {
        if self.pending_reliable.len() == MAX_RELIABLE_WINDOW {
            Err(DialError::ReliableWindowFull)
        } else {
            Ok(())
        }
    }

    fn send_reliable(&mut self, packet: Vec<u8>) -> Result<(), DialError> {
        self.ensure_reliable_capacity()?;
        let header = parse_full_frame_packet(&packet)
            .map_err(|_| DialError::Protocol(CallSetupError::InvalidFrame))?
            .header;
        self.endpoint
            .send_to(&packet, self.remote)
            .map_err(DialError::Network)?;
        self.pending_reliable.push_back(PendingReliableFrame {
            packet,
            outgoing_sequence: header.outgoing_sequence,
            next_retry: Instant::now() + LINK_INITIAL_RETRY,
            retry_interval: LINK_INITIAL_RETRY,
            retries: 0,
        });
        Ok(())
    }

    fn acknowledge_reliable_frames(&mut self, next_sequence: u8) {
        acknowledge_reliable_frames(&mut self.pending_reliable, next_sequence);
    }

    fn retry_reliable_frames(&mut self) -> Result<(), DialError> {
        let now = Instant::now();
        for frame in &mut self.pending_reliable {
            if now < frame.next_retry {
                continue;
            }
            if frame.retries == MAX_RELIABLE_RETRIES {
                return Err(DialError::Timeout);
            }
            let packet = self
                .setup
                .retransmit(&frame.packet)
                .map_err(DialError::Protocol)?;
            self.endpoint
                .send_to(&packet, self.remote)
                .map_err(DialError::Network)?;
            frame.retries += 1;
            frame.retry_interval = (frame.retry_interval * 10).min(MAX_RETRY);
            frame.next_retry = now + frame.retry_interval;
        }
        Ok(())
    }

    /// Poll one datagram and decode only audio; text/control events are handled internally.
    pub fn poll_ulaw(&mut self, pcm: &mut [f32]) -> Result<Option<usize>, DialError> {
        let mut text = [0_u8; 1500];
        match self.poll_event(pcm, &mut text)? {
            IaxPeerEvent::Audio(count) => Ok(Some(count)),
            IaxPeerEvent::Hangup => Err(DialError::Hangup),
            IaxPeerEvent::None
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
    if acknowledged <= pending.len() {
        pending.drain(..acknowledged);
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
    let format = IAX_FORMAT_ULAW.to_be_bytes();
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
            kind: IE_CAPABILITY,
            data: &format,
        },
        InformationElement {
            kind: IE_FORMAT,
            data: &format,
        },
        InformationElement {
            kind: IE_VERSION,
            data: &version,
        },
    ];
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
    let mut packet = [0_u8; 1500];
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
                if format != IAX_FORMAT_ULAW {
                    return Err(DialError::UnsupportedFormat(format));
                }
                let mut peer = IaxPeer {
                    endpoint: PeerEndpoint::Dedicated(endpoint),
                    remote: options.remote,
                    local_call: options.local_call,
                    remote_call,
                    format,
                    connected_at: Instant::now(),
                    setup,
                    pending_reliable: VecDeque::new(),
                    pending_events: VecDeque::new(),
                    answered: false,
                    voice_epoch: None,
                    release_on_drop: None,
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
