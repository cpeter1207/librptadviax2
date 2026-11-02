//! Outbound IAX2 call setup through authentication and ACCEPT.

use crate::authentication::{
    AUTH_METHOD_MD5, AuthenticationRequestError, build_md5_authrep, parse_auth_request,
};
use crate::call_token::{
    CallTokenAuthority, CallTokenRequestError, CallTokenRetryError, InitialNewDisposition,
    InitialNewError, build_initial_new, retry_new_call_with_token,
};
use crate::codec::IAX_FORMAT_ULAW;
use crate::formats::{FormatCatalog, FormatOffer, IaxFormat, append_formats};
use crate::information_elements::{
    InformationElement, InformationElementError, parse_information_elements,
};
use crate::protocol::{
    FrameEncodeError, FullFrameHeader, IaxCommand, decode_iax_command, decode_subclass,
    parse_full_frame_packet, serialize_full_frame,
};
use crate::text::parse_text_frame;

const IAX_FRAME_TYPE: u8 = 6;
const USERNAME_IE: u8 = 6;
const CALLED_NUMBER_IE: u8 = 1;
const CALLING_NUMBER_IE: u8 = 2;
const CAPABILITY_IE: u8 = 8;
#[cfg(test)]
const FORMAT_IE: u8 = 9;
const ACK_SUBCLASS: u8 = 4;

/// Incoming call accepted after the listener has validated its call token and access policy.
#[derive(Debug, Eq, PartialEq)]
pub struct InboundCallAccepted {
    /// Numeric node identifier supplied by the remote `CALLING_NUMBER` IE.
    pub remote_node: String,
    /// Negotiated codec format.
    pub format: u64,
    /// IAX2 `ACCEPT` frame to send to the peer.
    pub packet: Vec<u8>,
}

/// Result of applying call-token validation, identity checks, and node access policy to NEW.
#[derive(Debug, Eq, PartialEq)]
pub enum InboundNewAction {
    /// Send a stateless CALLTOKEN challenge or REJECT response.
    Reply(Vec<u8>),
    /// Send this ACCEPT and create a session only after caller-owned policy allowed the peer.
    Accept(InboundCallAccepted),
}

/// Failure to parse or apply the stateless inbound call-token gate.
#[derive(Debug, Eq, PartialEq)]
pub enum InboundAdmissionError {
    /// The request was not a valid initial IAX NEW frame.
    CallToken(CallTokenRequestError),
}

/// Apply token validation, codec/identity checks, and caller-owned access policy in order.
///
/// The authorization callback runs only for a source-bound, token-valid node identity. This
/// helper owns no socket or persistent call state and must run on a serialized non-audio owner.
pub fn process_inbound_ulaw_new(
    tokens: &CallTokenAuthority,
    source: std::net::SocketAddr,
    packet: &[u8],
    local_node: &str,
    local_call: u16,
    now_seconds: u32,
    authorize: impl FnMut(&str) -> bool,
) -> Result<InboundNewAction, InboundAdmissionError> {
    process_inbound_new(
        tokens,
        source,
        packet,
        (local_node, local_call),
        now_seconds,
        None,
        authorize,
    )
}

/// Apply the existing token/authorization gate with a verified codec catalog.
/// The identity pair contains the addressed local node and allocated call ID.
pub fn process_inbound_new(
    tokens: &CallTokenAuthority,
    source: std::net::SocketAddr,
    packet: &[u8],
    identity: (&str, u16),
    now_seconds: u32,
    catalog: Option<&FormatCatalog>,
    mut authorize: impl FnMut(&str) -> bool,
) -> Result<InboundNewAction, InboundAdmissionError> {
    let (local_node, local_call) = identity;
    match tokens
        .handle_initial_new(source, packet, now_seconds)
        .map_err(InboundAdmissionError::CallToken)?
    {
        InitialNewDisposition::Challenge(reply) | InitialNewDisposition::Reject(reply) => {
            Ok(InboundNewAction::Reply(reply))
        }
        InitialNewDisposition::Continue => {
            let accepted = match catalog {
                Some(catalog) => accept_inbound_new(packet, local_node, local_call, catalog),
                None => accept_inbound_ulaw_new(packet, local_node, local_call),
            };
            let Ok(accepted) = accepted else {
                return tokens
                    .reject_initial_new(packet)
                    .map(InboundNewAction::Reply)
                    .map_err(InboundAdmissionError::CallToken);
            };
            if authorize(&accepted.remote_node) {
                Ok(InboundNewAction::Accept(accepted))
            } else {
                tokens
                    .reject_initial_new(packet)
                    .map(InboundNewAction::Reply)
                    .map_err(InboundAdmissionError::CallToken)
            }
        }
    }
}

/// Why a token-validated incoming IAX `NEW` cannot be accepted for the standalone radio node.
#[derive(Debug, Eq, PartialEq)]
pub enum InboundNewError {
    /// The datagram is not a complete full-frame packet.
    InvalidFrame,
    /// The packet is not an initial IAX `NEW` addressed to call zero.
    NotInitialNew,
    /// Required identity or codec information elements are missing, duplicated, or malformed.
    InvalidInformationElements,
    /// The username, destination node, or numeric source node is not accepted.
    InvalidIdentity,
    /// The peer does not advertise the supported u-law format.
    UnsupportedFormat,
    /// The `ACCEPT` frame could not be encoded.
    Frame(FrameEncodeError),
}

/// Negotiate an incoming ASL-style `radio` call using the initial u-law codec.
///
/// The caller must validate CALLTOKEN and authorization before calling this
/// low-level helper. It allocates no persistent call state; the caller owns the
/// returned peer identity and ACCEPT frame. Prefer [`process_inbound_ulaw_new`]
/// when admission, token handling, and product policy need one ordered operation.
pub fn accept_inbound_ulaw_new(
    packet: &[u8],
    local_node: &str,
    local_call: u16,
) -> Result<InboundCallAccepted, InboundNewError> {
    accept_inbound_selected(packet, local_node, local_call, |offer| {
        (offer & IAX_FORMAT_ULAW != 0).then_some(IAX_FORMAT_ULAW)
    })
}

/// Select an inbound format using the same verified catalog as outgoing offers.
/// Token validation and authorization remain with the listener's admission path.
pub fn accept_inbound_new(
    packet: &[u8],
    local_node: &str,
    local_call: u16,
    catalog: &FormatCatalog,
) -> Result<InboundCallAccepted, InboundNewError> {
    accept_inbound_selected(packet, local_node, local_call, |offer| {
        catalog
            .select(offer)
            .ok()
            .map(|id| IaxFormat::for_profile(id).0)
    })
}

fn accept_inbound_selected(
    packet: &[u8],
    local_node: &str,
    local_call: u16,
    select: impl FnOnce(u64) -> Option<u64>,
) -> Result<InboundCallAccepted, InboundNewError> {
    let request = parse_full_frame_packet(packet).map_err(|_| InboundNewError::InvalidFrame)?;
    if local_call == 0
        || request.header.source_call_number == 0
        || request.header.destination_call_number != 0
        || request.header.outgoing_sequence != 0
        || request.header.incoming_sequence != 0
        || request.header.frame_type != IAX_FRAME_TYPE
        || request.header.subclass_is_log
        || decode_iax_command(&request.header) != Ok(Some(IaxCommand::New))
    {
        return Err(InboundNewError::NotInitialNew);
    }

    let elements = parse_information_elements(request.payload)
        .map_err(|_| InboundNewError::InvalidInformationElements)?;
    let username = unique_ie(&elements, USERNAME_IE)?;
    let called = unique_ie(&elements, CALLED_NUMBER_IE)?;
    let calling = unique_ie(&elements, CALLING_NUMBER_IE)?;
    if username != b"radio"
        || called != local_node.as_bytes()
        || calling.is_empty()
        || !calling.iter().all(u8::is_ascii_digit)
    {
        return Err(InboundNewError::InvalidIdentity);
    }
    let capability = FormatOffer::parse(&elements).supported();
    let format = select(capability).ok_or(InboundNewError::UnsupportedFormat)?;

    let mut response_payload = Vec::with_capacity(17);
    append_formats(&mut response_payload, format, None);
    let response = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: local_call,
            retransmission: false,
            destination_call_number: request.header.source_call_number,
            timestamp: 0,
            outgoing_sequence: 0,
            incoming_sequence: request.header.outgoing_sequence.wrapping_add(1),
            frame_type: IAX_FRAME_TYPE,
            subclass: IaxCommand::Accept.subclass_value() as u8,
            subclass_is_log: false,
        },
        &response_payload,
    )
    .map_err(InboundNewError::Frame)?;

    let remote_node = calling.iter().map(|byte| char::from(*byte)).collect();
    Ok(InboundCallAccepted {
        remote_node,
        format,
        packet: response,
    })
}

fn unique_ie<'a>(
    elements: &[InformationElement<'a>],
    kind: u8,
) -> Result<&'a [u8], InboundNewError> {
    let mut matches = elements.iter().filter(|element| element.kind == kind);
    let data = matches
        .next()
        .ok_or(InboundNewError::InvalidInformationElements)?
        .data;
    if matches.next().is_some() {
        return Err(InboundNewError::InvalidInformationElements);
    }
    Ok(data)
}

#[cfg(test)]
#[path = "session_unit_tests.rs"]
mod unit_tests;

#[cfg(test)]
#[path = "session_setup_tests.rs"]
mod setup_tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    AwaitingResponse,
    AwaitingAccept,
    Linked,
    Rejected,
    Ended,
}

#[derive(Debug)]
struct LastReliableResponse {
    command: Option<IaxCommand>,
    frame_type: u8,
    subclass: u8,
    source_call: u16,
    outgoing_sequence: u8,
    payload: Vec<u8>,
    response: Vec<u8>,
}

/// Why an outbound IAX2 call could not be started or advanced.
#[derive(Debug, Eq, PartialEq)]
pub enum CallSetupError {
    /// An inbound linked session uses an unrepresentable local or remote call number.
    InvalidCallNumbers,
    /// The initial NEW packet or its fields are invalid.
    InitialNew(InitialNewError),
    /// The initial NEW does not contain a usable single preferred FORMAT.
    InitialFormat,
    /// The initial NEW has a malformed or empty CAPABILITY IE.
    InitialCapability,
    /// A response is truncated or is not a full frame.
    InvalidFrame,
    /// The packet is not an IAX control frame.
    NotIaxFrame {
        /// Actual full-frame type.
        frame_type: u8,
    },
    /// The peer addressed a different local call number.
    WrongDestinationCall {
        /// Destination call number received.
        actual: u16,
    },
    /// A normal response has an invalid or unexpected peer call number.
    WrongSourceCall {
        /// Source call number received.
        actual: u16,
    },
    /// The reliable frame sequence does not match the current call state.
    SequenceMismatch {
        /// Expected next peer OSeqno.
        expected_outgoing: u8,
        /// Received peer OSeqno.
        actual_outgoing: u8,
        /// Expected peer ISeqno acknowledging our next OSeqno.
        expected_incoming: u8,
        /// Received peer ISeqno.
        actual_incoming: u8,
    },
    /// A command is not valid in the current setup state.
    UnexpectedCommand {
        /// IAX command received.
        command: IaxCommand,
    },
    /// The peer and initial NEW share no MD5 authentication method.
    UnsupportedAuthentication,
    /// A call has not reached the linked state required by this operation.
    NotLinked,
    /// A DTMF digit is outside the IAX2 digit alphabet.
    InvalidDtmfDigit(u8),
    /// The AUTHREQ payload is malformed or incomplete.
    Authentication(AuthenticationRequestError),
    /// The ACCEPT payload has malformed information elements.
    InformationElements(InformationElementError),
    /// ACCEPT omitted a usable nonzero legacy/extended FORMAT.
    InvalidAcceptedFormat,
    /// The peer selected a format not offered by the initial NEW.
    UnacceptedFormat {
        /// Peer format bit field.
        format: u64,
    },
    /// The outbound call is already terminal.
    CallFinished,
    /// A keepalive probe is already waiting for a matching PONG.
    PingPending,
    /// A response could not be encoded as a full frame.
    Frame(FrameEncodeError),
    /// A CALLTOKEN response could not be used to retry NEW.
    CallToken(CallTokenRetryError),
}

/// Result of processing a peer frame during outbound setup or a linked call.
#[derive(Debug, Eq, PartialEq)]
pub enum CallSetupResponse {
    /// Send this reliable protocol packet to the peer.
    Send(Vec<u8>),
    /// The call is linked and the ACCEPT acknowledgement must be sent.
    Accepted {
        /// Codec format selected by the peer.
        format: u64,
        /// IAX2 ACK packet for the peer's ACCEPT.
        acknowledgement: Vec<u8>,
    },
    /// The call was rejected and its reliable REJECT frame was acknowledged.
    Rejected {
        /// IAX2 ACK packet for the peer's REJECT.
        acknowledgement: Vec<u8>,
    },
    /// A PONG was acknowledged; `matched_probe` indicates whether it answered our outstanding PING.
    PongAcknowledged {
        /// IAX2 ACK packet for the peer's PONG.
        acknowledgement: Vec<u8>,
        /// Whether its timestamp matched the pending probe.
        matched_probe: bool,
    },
    /// The linked peer ended the call; the reliable frame must be acknowledged.
    Ended {
        /// IAX2 ACK packet for the peer's HANGUP.
        acknowledgement: Vec<u8>,
    },
    /// The peer sent reliable ASL text; deliver the bytes and send its ACK.
    Text {
        /// UTF-8 text payload copied from the received frame.
        text: Vec<u8>,
        /// IAX2 ACK for the reliable text frame.
        acknowledgement: Vec<u8>,
    },
    /// The peer sent one reliable DTMF digit and its ACK must be sent.
    Digit {
        /// ASCII DTMF digit from the frame subclass.
        digit: u8,
        /// IAX2 ACK for the reliable DTMF frame.
        acknowledgement: Vec<u8>,
    },
    /// The peer asserted radio receive; the reliable frame must be acknowledged.
    RadioKey {
        /// IAX2 ACK for the peer's radio-key frame.
        acknowledgement: Vec<u8>,
    },
    /// The peer released radio receive; the reliable frame must be acknowledged.
    RadioUnkey {
        /// IAX2 ACK for the peer's radio-unkey frame.
        acknowledgement: Vec<u8>,
    },
    /// No response is required; used for a valid ACK received from the peer.
    NoAction,
}

/// Response possible before an outbound call has reached the linked state.
pub(crate) enum OutboundSetupResponse {
    /// The current setup transmission was acknowledged; await the next response.
    NoAction,
    /// Send the next setup packet.
    Send(Vec<u8>),
    /// The peer accepted the call.
    Accepted {
        /// Remote call number from the already validated ACCEPT header.
        remote_call: u16,
        format: u64,
        acknowledgement: Vec<u8>,
    },
    /// The peer rejected the call.
    Rejected { acknowledgement: Vec<u8> },
}

/// Response possible after an outbound call has reached the linked state.
pub(crate) enum LinkedCallResponse {
    /// The peer answered the accepted call.
    Answered {
        acknowledgement: Vec<u8>,
    },
    /// Send and retain a newly sequenced reliable reply.
    SendReliable(Vec<u8>),
    /// Send the next protocol packet.
    Send(Vec<u8>),
    /// A PONG was acknowledged.
    PongAcknowledged {
        acknowledgement: Vec<u8>,
        matched_probe: bool,
    },
    /// The peer ended the call.
    Ended {
        acknowledgement: Vec<u8>,
    },
    /// The peer sent ASL text.
    Text {
        text: Vec<u8>,
        acknowledgement: Vec<u8>,
    },
    /// The peer sent one reliable DTMF digit.
    Digit {
        digit: u8,
        acknowledgement: Vec<u8>,
    },
    RadioKey {
        acknowledgement: Vec<u8>,
    },
    RadioUnkey {
        acknowledgement: Vec<u8>,
    },
    /// The valid frame requires no response.
    NoAction,
}

impl From<OutboundSetupResponse> for CallSetupResponse {
    fn from(response: OutboundSetupResponse) -> Self {
        match response {
            OutboundSetupResponse::NoAction => Self::NoAction,
            OutboundSetupResponse::Send(packet) => Self::Send(packet),
            OutboundSetupResponse::Accepted {
                format,
                acknowledgement,
                ..
            } => Self::Accepted {
                format,
                acknowledgement,
            },
            OutboundSetupResponse::Rejected { acknowledgement } => {
                Self::Rejected { acknowledgement }
            }
        }
    }
}

impl From<LinkedCallResponse> for CallSetupResponse {
    fn from(response: LinkedCallResponse) -> Self {
        match response {
            LinkedCallResponse::Send(packet) | LinkedCallResponse::SendReliable(packet) => {
                Self::Send(packet)
            }
            LinkedCallResponse::Answered { acknowledgement } => Self::Send(acknowledgement),
            LinkedCallResponse::PongAcknowledged {
                acknowledgement,
                matched_probe,
            } => Self::PongAcknowledged {
                acknowledgement,
                matched_probe,
            },
            LinkedCallResponse::Ended { acknowledgement } => Self::Ended { acknowledgement },
            LinkedCallResponse::Text {
                text,
                acknowledgement,
            } => Self::Text {
                text,
                acknowledgement,
            },
            LinkedCallResponse::Digit {
                digit,
                acknowledgement,
            } => Self::Digit {
                digit,
                acknowledgement,
            },
            LinkedCallResponse::RadioKey { acknowledgement } => Self::RadioKey { acknowledgement },
            LinkedCallResponse::RadioUnkey { acknowledgement } => {
                Self::RadioUnkey { acknowledgement }
            }
            LinkedCallResponse::NoAction => Self::NoAction,
        }
    }
}

/// Single-owner outbound call handshake state.
///
/// The caller owns the clock and socket. The object is not internally
/// synchronized; one control-plane owner advances a call at a time.
#[derive(Debug)]
pub struct OutboundCallSetup {
    local_call: u16,
    remote_call: Option<u16>,
    offered_formats: u64,
    next_outgoing: u8,
    next_incoming: u8,
    received_media: u64,
    initial_new: Vec<u8>,
    state: State,
    last_reliable_response: Option<LastReliableResponse>,
    pending_ping_timestamp: Option<u32>,
}

impl OutboundCallSetup {
    /// Create linked session state after this endpoint sends an inbound ACCEPT.
    ///
    /// IAX call numbers are nonzero 15-bit values. The initial NEW and ACCEPT
    /// each consume one sequence position, so the next peer and local sequence
    /// numbers are both one.
    pub fn for_inbound_call(local_call: u16, remote_call: u16) -> Result<Self, CallSetupError> {
        if local_call == 0 || local_call > 0x7fff || remote_call == 0 || remote_call > 0x7fff {
            return Err(CallSetupError::InvalidCallNumbers);
        }
        Ok(Self {
            local_call,
            remote_call: Some(remote_call),
            offered_formats: IAX_FORMAT_ULAW,
            next_outgoing: 1,
            next_incoming: 1,
            received_media: 0,
            initial_new: Vec::new(),
            state: State::Linked,
            last_reliable_response: None,
            pending_ping_timestamp: None,
        })
    }

    /// Construct setup state and its initial NEW packet.
    pub fn new(
        local_call: u16,
        timestamp_ms: u32,
        elements: &[InformationElement<'_>],
    ) -> Result<Self, CallSetupError> {
        let offered_formats = offered_formats(elements)?;
        let initial_new = build_initial_new(local_call, timestamp_ms, elements)
            .map_err(CallSetupError::InitialNew)?;

        Ok(Self {
            local_call,
            remote_call: None,
            offered_formats,
            next_outgoing: 1,
            next_incoming: 0,
            received_media: 0,
            initial_new,
            state: State::AwaitingResponse,
            last_reliable_response: None,
            pending_ping_timestamp: None,
        })
    }

    /// Return the initial NEW packet, to be sent unchanged by the network adapter.
    pub fn initial_packet(&self) -> &[u8] {
        &self.initial_new
    }

    /// Mark one pending setup frame for retransmission and refresh its ACK sequence.
    pub(crate) fn retransmit(&self, packet: &[u8]) -> Result<Vec<u8>, CallSetupError> {
        let parsed = parse_full_frame_packet(packet).map_err(|_| CallSetupError::InvalidFrame)?;
        let mut header = parsed.header;
        header.retransmission = true;
        header.incoming_sequence = self.next_incoming;
        serialize_full_frame(&header, parsed.payload).map_err(CallSetupError::Frame)
    }

    /// Whether the peer has accepted and linked this call.
    pub const fn is_linked(&self) -> bool {
        matches!(self.state, State::Linked)
    }

    /// Build a PING for an established call using the caller's relative timestamp.
    pub fn send_ping(&mut self, timestamp_ms: u32) -> Result<Vec<u8>, CallSetupError> {
        if self.state != State::Linked {
            return Err(CallSetupError::UnexpectedCommand {
                command: IaxCommand::Ping,
            });
        }
        if self.pending_ping_timestamp.is_some() {
            return Err(CallSetupError::PingPending);
        }

        let remote_call = self.remote_call.ok_or(CallSetupError::CallFinished)?;
        let packet = serialize_full_frame(
            &self.outgoing_header(
                remote_call,
                timestamp_ms,
                self.next_incoming,
                IaxCommand::Ping.subclass_value() as u8,
            ),
            &[],
        )
        .map_err(CallSetupError::Frame)?;
        self.next_outgoing = self.next_outgoing.wrapping_add(1);
        self.pending_ping_timestamp = Some(timestamp_ms);
        Ok(packet)
    }

    /// Build one sequenced IAX text frame after the peer accepts the call.
    pub fn send_text_frame(
        &mut self,
        payload: &[u8],
        timestamp_ms: u32,
    ) -> Result<Vec<u8>, CallSetupError> {
        if self.state != State::Linked {
            return Err(CallSetupError::CallFinished);
        }
        let remote_call = self.remote_call.ok_or(CallSetupError::CallFinished)?;
        let mut header = self.outgoing_header(remote_call, timestamp_ms, self.next_incoming, 0);
        header.frame_type = 7;
        let packet = serialize_full_frame(&header, payload).map_err(CallSetupError::Frame)?;
        self.next_outgoing = self.next_outgoing.wrapping_add(1);
        Ok(packet)
    }

    /// Sequence complete media with the negotiated 64-bit format subclass.
    pub(crate) fn send_voice_frame(
        &mut self,
        payload: &[u8],
        timestamp_ms: u32,
        format: u64,
    ) -> Result<Vec<u8>, CallSetupError> {
        if self.state != State::Linked {
            return Err(CallSetupError::NotLinked);
        }
        let remote_call = self.remote_call.ok_or(CallSetupError::CallFinished)?;
        if IaxFormat(format).profile().is_none() {
            return Err(CallSetupError::InvalidAcceptedFormat);
        }
        let subclass =
            crate::protocol::encode_subclass(format as i64).expect("verified single-bit profile");
        let mut header = self.outgoing_header(
            remote_call,
            timestamp_ms,
            self.next_incoming,
            subclass & 0x7f,
        );
        header.subclass_is_log = subclass & 0x80 != 0;
        header.frame_type = 2;
        let packet = serialize_full_frame(&header, payload).map_err(CallSetupError::Frame)?;
        self.next_outgoing = self.next_outgoing.wrapping_add(1);
        Ok(packet)
    }

    /// Sequence a validated full media frame and suppress duplicate delivery.
    pub(crate) fn receive_media(
        &mut self,
        header: &FullFrameHeader,
    ) -> Result<(bool, Vec<u8>), CallSetupError> {
        self.validate_call_ids(header)?;
        if self.is_old_frame(header) {
            return Ok((false, self.acknowledgement(header, self.next_incoming)?));
        }
        self.validate_peer_acknowledgement(header)?;
        if header.outgoing_sequence != self.next_incoming {
            return Ok((false, self.out_of_order_reply(header)?));
        }
        let next_incoming = self.next_incoming.wrapping_add(1);
        let acknowledgement = self.acknowledgement(header, next_incoming)?;
        self.consume_incoming(next_incoming);
        Ok((true, acknowledgement))
    }

    /// Admit bounded out-of-order full voice without relaxing reliable control ordering.
    pub(crate) fn receive_media_reordered(
        &mut self,
        header: &FullFrameHeader,
    ) -> Result<(bool, Vec<u8>), CallSetupError> {
        // Old packets carry old ACKs too; do not validate or apply that credit.
        self.validate_call_ids(header)?;
        if self.is_old_frame(header) {
            return Ok((false, self.acknowledgement(header, self.next_incoming)?));
        }
        self.validate_peer_acknowledgement(header)?;
        let distance = header.outgoing_sequence.wrapping_sub(self.next_incoming);
        if distance >= 64 {
            return Ok((false, self.out_of_order_reply(header)?));
        }
        let bit = 1u64 << distance;
        let deliver = self.received_media & bit == 0;
        self.received_media |= bit;
        self.consume_incoming(self.next_incoming);
        Ok((deliver, self.acknowledgement(header, self.next_incoming)?))
    }

    fn advanced_incoming(&self, next: u8) -> u8 {
        let shift = u32::from(next.wrapping_sub(self.next_incoming));
        let pending = self.received_media.checked_shr(shift).unwrap_or(0);
        next.wrapping_add(pending.trailing_ones() as u8)
    }

    fn consume_incoming(&mut self, next: u8) {
        let next = self.advanced_incoming(next);
        self.received_media = self
            .received_media
            .checked_shr(u32::from(next.wrapping_sub(self.next_incoming)))
            .unwrap_or(0);
        self.next_incoming = next;
    }

    /// Build one sequenced IAX DTMF full frame for a linked call.
    pub fn send_dtmf(&mut self, digit: u8, timestamp_ms: u32) -> Result<Vec<u8>, CallSetupError> {
        if self.state != State::Linked {
            return Err(CallSetupError::NotLinked);
        }
        if !matches!(digit, b'0'..=b'9' | b'A'..=b'D' | b'*' | b'#') {
            return Err(CallSetupError::InvalidDtmfDigit(digit));
        }

        let remote_call = self.remote_call.ok_or(CallSetupError::CallFinished)?;
        let mut header = self.outgoing_header(remote_call, timestamp_ms, self.next_incoming, digit);
        header.frame_type = 1;
        let packet = serialize_full_frame(&header, &[]).map_err(CallSetupError::Frame)?;
        self.next_outgoing = self.next_outgoing.wrapping_add(1);
        Ok(packet)
    }

    /// Answer an authorized inbound call using its next reliable sequence position.
    pub(crate) fn send_answer(&mut self, timestamp_ms: u32) -> Result<Vec<u8>, CallSetupError> {
        if self.state != State::Linked {
            return Err(CallSetupError::NotLinked);
        }
        let remote_call = self.remote_call.ok_or(CallSetupError::CallFinished)?;
        let mut header = self.outgoing_header(remote_call, timestamp_ms, self.next_incoming, 4);
        header.frame_type = 4;
        let packet = serialize_full_frame(&header, &[]).map_err(CallSetupError::Frame)?;
        self.next_outgoing = self.next_outgoing.wrapping_add(1);
        Ok(packet)
    }

    /// Build one reliable HANGUP frame and end the local call state.
    pub fn send_hangup(&mut self, timestamp_ms: u32) -> Result<Vec<u8>, CallSetupError> {
        if self.state != State::Linked {
            return Err(CallSetupError::CallFinished);
        }
        let remote_call = self.remote_call.ok_or(CallSetupError::CallFinished)?;
        let packet = serialize_full_frame(
            &self.outgoing_header(
                remote_call,
                timestamp_ms,
                self.next_incoming,
                IaxCommand::Hangup.subclass_value() as u8,
            ),
            &[],
        )
        .map_err(CallSetupError::Frame)?;
        self.next_outgoing = self.next_outgoing.wrapping_add(1);
        self.state = State::Ended;
        Ok(packet)
    }

    /// Process a peer call frame and return any packet required by the protocol.
    ///
    /// `timestamp_ms` is the caller's elapsed-call timestamp for a new
    /// AUTHREP. ACK timestamps echo the reliable peer frame being acknowledged.
    pub fn receive(
        &mut self,
        packet: &[u8],
        timestamp_ms: u32,
        secret: &str,
    ) -> Result<CallSetupResponse, CallSetupError> {
        if self.state == State::Linked {
            return self.receive_linked(packet).map(Into::into);
        }
        self.receive_setup(packet, timestamp_ms, secret)
            .map(Into::into)
    }

    /// Process one response while the call is still in setup.
    pub(crate) fn receive_setup(
        &mut self,
        packet: &[u8],
        timestamp_ms: u32,
        secret: &str,
    ) -> Result<OutboundSetupResponse, CallSetupError> {
        let frame = parse_full_frame_packet(packet).map_err(|_| CallSetupError::InvalidFrame)?;
        if frame.header.frame_type == 7 {
            return Err(CallSetupError::NotLinked);
        }
        if frame.header.frame_type != IAX_FRAME_TYPE {
            return Err(CallSetupError::NotIaxFrame {
                frame_type: frame.header.frame_type,
            });
        }
        let command = decode_iax_command(&frame.header)
            .map_err(|_| CallSetupError::InvalidFrame)?
            .expect("IAX frame type was checked");

        if command == IaxCommand::CallToken {
            if self.state != State::AwaitingResponse {
                return Err(CallSetupError::UnexpectedCommand { command });
            }
            let retry = retry_new_call_with_token(&self.initial_new, packet, timestamp_ms)
                .map_err(CallSetupError::CallToken)?;
            return Ok(OutboundSetupResponse::Send(retry));
        }

        if let Some(response) =
            self.duplicate_response(&frame.header, Some(command), frame.payload)?
        {
            return Ok(OutboundSetupResponse::Send(response));
        }
        if matches!(self.state, State::Rejected | State::Ended) {
            return Err(CallSetupError::CallFinished);
        }

        self.validate_peer_header(&frame.header)?;
        match command {
            IaxCommand::Ack => {
                self.remote_call = Some(frame.header.source_call_number);
                Ok(OutboundSetupResponse::NoAction)
            }
            IaxCommand::AuthReq if self.state == State::AwaitingResponse => {
                let auth =
                    parse_auth_request(frame.payload).map_err(CallSetupError::Authentication)?;
                if auth.methods & AUTH_METHOD_MD5 == 0 {
                    return Err(CallSetupError::UnsupportedAuthentication);
                }

                let incoming = self.next_incoming.wrapping_add(1);
                let authrep = build_md5_authrep(
                    &self.outgoing_header(
                        frame.header.source_call_number,
                        timestamp_ms,
                        incoming,
                        9,
                    ),
                    auth.challenge,
                    secret,
                )
                .map_err(CallSetupError::Frame)?;
                self.remote_call = Some(frame.header.source_call_number);
                self.next_outgoing = self.next_outgoing.wrapping_add(1);
                self.next_incoming = incoming;
                self.state = State::AwaitingAccept;
                self.remember_response(
                    Some(command),
                    &frame.header,
                    frame.payload,
                    authrep.clone(),
                );
                Ok(OutboundSetupResponse::Send(authrep))
            }
            IaxCommand::Accept => self.accept(&frame.header, frame.payload),
            IaxCommand::Reject => self.reject(&frame.header, frame.payload),
            _ => Err(CallSetupError::UnexpectedCommand { command }),
        }
    }

    /// Whether a full frame belongs to the consumed modular half-range.
    pub(crate) fn is_old_frame(&self, header: &FullFrameHeader) -> bool {
        (1..128).contains(&self.next_incoming.wrapping_sub(header.outgoing_sequence))
    }

    /// Validate call identity and cumulative ACK without requiring arrival order.
    pub(crate) fn validate_peer_acknowledgement(
        &self,
        header: &FullFrameHeader,
    ) -> Result<(), CallSetupError> {
        self.validate_call_ids(header)?;
        let valid_ack = if self.state == State::Linked {
            // ACK datagrams may overtake earlier voice/control. Accept bounded
            // stale cumulative ACKs; the network send window alone retires frames.
            self.next_outgoing.wrapping_sub(header.incoming_sequence) <= 64
        } else {
            header.incoming_sequence == self.next_outgoing
        };
        if !valid_ack {
            return Err(self.sequence_mismatch(header));
        }
        Ok(())
    }

    fn validate_peer_header(&self, header: &FullFrameHeader) -> Result<(), CallSetupError> {
        self.validate_peer_acknowledgement(header)?;
        if header.outgoing_sequence != self.next_incoming {
            return Err(self.sequence_mismatch(header));
        }
        Ok(())
    }

    /// Preserve the actual received header in terminal sequence diagnostics.
    fn sequence_mismatch(&self, header: &FullFrameHeader) -> CallSetupError {
        CallSetupError::SequenceMismatch {
            expected_outgoing: self.next_incoming,
            actual_outgoing: header.outgoing_sequence,
            expected_incoming: self.next_outgoing,
            actual_incoming: header.incoming_sequence,
        }
    }

    pub(crate) fn validate_call_ids(&self, header: &FullFrameHeader) -> Result<(), CallSetupError> {
        if header.destination_call_number != self.local_call {
            return Err(CallSetupError::WrongDestinationCall {
                actual: header.destination_call_number,
            });
        }
        if header.source_call_number == 0
            || self
                .remote_call
                .is_some_and(|call| call != header.source_call_number)
        {
            return Err(CallSetupError::WrongSourceCall {
                actual: header.source_call_number,
            });
        }
        Ok(())
    }

    /// Process one frame from a call that is already linked.
    pub(crate) fn receive_linked(
        &mut self,
        packet: &[u8],
    ) -> Result<LinkedCallResponse, CallSetupError> {
        let frame = parse_full_frame_packet(packet).map_err(|_| CallSetupError::InvalidFrame)?;
        if frame.header.frame_type == 1 {
            return self.receive_dtmf(&frame.header, frame.payload);
        }
        if frame.header.frame_type == 7 {
            return self.receive_text(packet);
        }
        if frame.header.frame_type == 4 {
            return self.receive_radio_control(&frame.header, frame.payload);
        }
        if frame.header.frame_type == 10 {
            // RFC 5456 CNG has no payload. ACK its sequence without creating
            // audio or changing radio key state when a peer finishes speaking.
            if !frame.payload.is_empty() {
                return Err(CallSetupError::InvalidFrame);
            }
            let (_, acknowledgement) = self.receive_media(&frame.header)?;
            return Ok(LinkedCallResponse::Send(acknowledgement));
        }
        if frame.header.frame_type != IAX_FRAME_TYPE {
            return Err(CallSetupError::NotIaxFrame {
                frame_type: frame.header.frame_type,
            });
        }
        let command = decode_iax_command(&frame.header)
            .map_err(|_| CallSetupError::InvalidFrame)?
            .expect("IAX frame type was checked");
        if command == IaxCommand::CallToken {
            return Err(CallSetupError::UnexpectedCommand { command });
        }
        if let Some(response) =
            self.duplicate_response(&frame.header, Some(command), frame.payload)?
        {
            return Ok(LinkedCallResponse::Send(response));
        }
        self.receive_established(&frame.header, command, frame.payload)
    }

    fn receive_radio_control(
        &mut self,
        header: &FullFrameHeader,
        payload: &[u8],
    ) -> Result<LinkedCallResponse, CallSetupError> {
        if !payload.is_empty() {
            return Err(CallSetupError::InvalidFrame);
        }
        let subclass = (u8::from(header.subclass_is_log) << 7) | header.subclass;
        let subclass = decode_subclass(subclass).map_err(|_| CallSetupError::InvalidFrame)?;
        if let Some(response) = self.duplicate_response(header, None, payload)? {
            return Ok(LinkedCallResponse::Send(response));
        }
        self.validate_peer_header(header)?;
        let next_incoming = self.next_incoming.wrapping_add(1);
        let acknowledgement = self.acknowledgement(header, next_incoming)?;
        self.consume_incoming(next_incoming);
        self.remember_response(None, header, payload, acknowledgement.clone());
        Ok(match subclass {
            4 => LinkedCallResponse::Answered { acknowledgement },
            12 => LinkedCallResponse::RadioKey { acknowledgement },
            13 => LinkedCallResponse::RadioUnkey { acknowledgement },
            _ => LinkedCallResponse::Send(acknowledgement),
        })
    }

    fn receive_established(
        &mut self,
        header: &FullFrameHeader,
        command: IaxCommand,
        payload: &[u8],
    ) -> Result<LinkedCallResponse, CallSetupError> {
        if command == IaxCommand::Ack {
            self.validate_call_ids(header)?;
            return Ok(LinkedCallResponse::NoAction);
        }
        self.validate_peer_header(header)?;
        match command {
            IaxCommand::Ping | IaxCommand::LagRq => {
                let next_incoming = self.next_incoming.wrapping_add(1);
                let reply = if command == IaxCommand::Ping {
                    IaxCommand::Pong
                } else {
                    IaxCommand::LagRp
                };
                let pong = serialize_full_frame(
                    &self.outgoing_header(
                        header.source_call_number,
                        header.timestamp,
                        next_incoming,
                        reply.subclass_value() as u8,
                    ),
                    &[],
                )
                .map_err(CallSetupError::Frame)?;
                self.next_outgoing = self.next_outgoing.wrapping_add(1);
                self.consume_incoming(next_incoming);
                self.remember_response(Some(command), header, payload, pong.clone());
                Ok(LinkedCallResponse::SendReliable(pong))
            }
            IaxCommand::Pong => {
                let next_incoming = self.next_incoming.wrapping_add(1);
                let acknowledgement = self.acknowledgement(header, next_incoming)?;
                let matched_probe = self.pending_ping_timestamp == Some(header.timestamp);
                if matched_probe {
                    self.pending_ping_timestamp = None;
                }
                self.consume_incoming(next_incoming);
                self.remember_response(Some(command), header, payload, acknowledgement.clone());
                Ok(LinkedCallResponse::PongAcknowledged {
                    acknowledgement,
                    matched_probe,
                })
            }
            IaxCommand::Hangup | IaxCommand::LagRp => {
                let next_incoming = self.next_incoming.wrapping_add(1);
                let acknowledgement = self.acknowledgement(header, next_incoming)?;
                self.consume_incoming(next_incoming);
                self.remember_response(Some(command), header, payload, acknowledgement.clone());
                if command == IaxCommand::LagRp {
                    return Ok(LinkedCallResponse::Send(acknowledgement));
                }
                self.state = State::Ended;
                Ok(LinkedCallResponse::Ended { acknowledgement })
            }
            _ => Err(CallSetupError::UnexpectedCommand { command }),
        }
    }

    fn receive_text(&mut self, packet: &[u8]) -> Result<LinkedCallResponse, CallSetupError> {
        let text = parse_text_frame(packet).map_err(|_| CallSetupError::InvalidFrame)?;
        if let Some(acknowledgement) =
            self.duplicate_response(&text.header, None, text.text.as_bytes())?
        {
            return Ok(LinkedCallResponse::Send(acknowledgement));
        }
        self.validate_peer_header(&text.header)?;
        let next_incoming = self.next_incoming.wrapping_add(1);
        let acknowledgement = self.acknowledgement(&text.header, next_incoming)?;
        self.consume_incoming(next_incoming);
        self.remember_response(
            None,
            &text.header,
            text.text.as_bytes(),
            acknowledgement.clone(),
        );
        Ok(LinkedCallResponse::Text {
            text: text.text.as_bytes().to_vec(),
            acknowledgement,
        })
    }

    fn receive_dtmf(
        &mut self,
        header: &FullFrameHeader,
        payload: &[u8],
    ) -> Result<LinkedCallResponse, CallSetupError> {
        if !matches!(header.subclass, b'0'..=b'9' | b'A'..=b'D' | b'*' | b'#') {
            return Err(CallSetupError::InvalidDtmfDigit(header.subclass));
        }
        if !payload.is_empty() {
            return Err(CallSetupError::InvalidFrame);
        }
        if let Some(response) = self.duplicate_response(header, None, payload)? {
            return Ok(LinkedCallResponse::Send(response));
        }
        self.validate_peer_header(header)?;
        let next_incoming = self.next_incoming.wrapping_add(1);
        let acknowledgement = self.acknowledgement(header, next_incoming)?;
        self.consume_incoming(next_incoming);
        self.remember_response(None, header, payload, acknowledgement.clone());
        Ok(LinkedCallResponse::Digit {
            digit: header.subclass,
            acknowledgement,
        })
    }

    /// Replay a setup/reliable reply or recover linked sequence reordering.
    ///
    /// Intervening frames replace the one-entry reply cache, but do not make
    /// an already consumed sequence new again. Unmarked old packets are also
    /// ACKed; future control requests retransmission without advancing state.
    fn duplicate_response(
        &self,
        header: &FullFrameHeader,
        command: Option<IaxCommand>,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, CallSetupError> {
        if self.state == State::Linked {
            self.validate_call_ids(header)?;
            if command == Some(IaxCommand::Ack) {
                return Ok(None);
            }
            if self.is_old_frame(header) {
                if !header.retransmission {
                    return self.out_of_order_reply(header).map(Some);
                }
            } else {
                self.validate_peer_acknowledgement(header)?;
                if header.outgoing_sequence == self.next_incoming {
                    // A fresh packet can reuse a cached sequence after wraparound.
                    return Ok(None);
                }
                return self.out_of_order_reply(header).map(Some);
            }
        } else if !header.retransmission {
            return Ok(None);
        }
        if let Some(last) = self.last_reliable_response.as_ref().filter(|last| {
            header.destination_call_number == self.local_call
                && header.source_call_number == last.source_call
                && header.outgoing_sequence == last.outgoing_sequence
                && command == last.command
                && header.frame_type == last.frame_type
                && header.subclass == last.subclass
                && payload == last.payload
        }) {
            // Setup replies and PONG/LAGRP must retain their original sequence.
            return Ok(Some(last.response.clone()));
        }
        if self.state == State::Linked {
            return self.out_of_order_reply(header).map(Some);
        }
        Ok(None)
    }

    /// Recover a non-current sequence after validating its call identity.
    ///
    /// Use IAX's modular half-range to distinguish consumed packets from gaps.
    /// ACK old frames, or VNAK the first missing position; neither consumes a
    /// sequence or delivers an event. Only future frames need current ACK
    /// validation; old frames also carry obsolete ACKs. The ambiguous half-range
    /// requests recovery.
    fn out_of_order_reply(&self, header: &FullFrameHeader) -> Result<Vec<u8>, CallSetupError> {
        if self.next_incoming.wrapping_sub(header.outgoing_sequence) < 128 {
            return self.acknowledgement(header, self.next_incoming);
        }
        let mut reply = self.outgoing_header(
            header.source_call_number,
            header.timestamp,
            self.next_incoming,
            IaxCommand::Vnak.subclass_value() as u8,
        );
        // ASL3/Asterisk's unsequenced VNAK carries the missing position in both fields.
        reply.outgoing_sequence = self.next_incoming;
        serialize_full_frame(&reply, &[]).map_err(CallSetupError::Frame)
    }

    fn remember_response(
        &mut self,
        command: Option<IaxCommand>,
        header: &FullFrameHeader,
        payload: &[u8],
        response: Vec<u8>,
    ) {
        self.last_reliable_response = Some(LastReliableResponse {
            command,
            frame_type: header.frame_type,
            subclass: header.subclass,
            source_call: header.source_call_number,
            outgoing_sequence: header.outgoing_sequence,
            payload: payload.to_vec(),
            response,
        });
    }

    fn accept(
        &mut self,
        header: &FullFrameHeader,
        payload: &[u8],
    ) -> Result<OutboundSetupResponse, CallSetupError> {
        let format = accepted_format(payload)?;
        if !format.is_power_of_two() || format & self.offered_formats == 0 {
            return Err(CallSetupError::UnacceptedFormat { format });
        }

        let next_incoming = self.next_incoming.wrapping_add(1);
        let acknowledgement = self.acknowledgement(header, next_incoming)?;
        self.remember_response(
            Some(IaxCommand::Accept),
            header,
            payload,
            acknowledgement.clone(),
        );
        self.remote_call = Some(header.source_call_number);
        self.consume_incoming(next_incoming);
        self.state = State::Linked;
        Ok(OutboundSetupResponse::Accepted {
            remote_call: header.source_call_number,
            format,
            acknowledgement,
        })
    }

    fn reject(
        &mut self,
        header: &FullFrameHeader,
        payload: &[u8],
    ) -> Result<OutboundSetupResponse, CallSetupError> {
        let next_incoming = self.next_incoming.wrapping_add(1);
        let acknowledgement = self.acknowledgement(header, next_incoming)?;
        self.remember_response(
            Some(IaxCommand::Reject),
            header,
            payload,
            acknowledgement.clone(),
        );
        self.remote_call = Some(header.source_call_number);
        self.consume_incoming(next_incoming);
        self.state = State::Rejected;
        Ok(OutboundSetupResponse::Rejected { acknowledgement })
    }

    fn acknowledgement(
        &self,
        peer_header: &FullFrameHeader,
        incoming_sequence: u8,
    ) -> Result<Vec<u8>, CallSetupError> {
        let incoming_sequence = self.advanced_incoming(incoming_sequence);
        serialize_full_frame(
            &FullFrameHeader {
                source_call_number: self.local_call,
                retransmission: false,
                destination_call_number: peer_header.source_call_number,
                timestamp: peer_header.timestamp,
                outgoing_sequence: peer_header.incoming_sequence,
                incoming_sequence,
                frame_type: IAX_FRAME_TYPE,
                subclass: ACK_SUBCLASS,
                subclass_is_log: false,
            },
            &[],
        )
        .map_err(CallSetupError::Frame)
    }

    fn outgoing_header(
        &self,
        remote_call: u16,
        timestamp_ms: u32,
        incoming_sequence: u8,
        subclass: u8,
    ) -> FullFrameHeader {
        let incoming_sequence = self.advanced_incoming(incoming_sequence);
        FullFrameHeader {
            source_call_number: self.local_call,
            retransmission: false,
            destination_call_number: remote_call,
            timestamp: timestamp_ms,
            outgoing_sequence: self.next_outgoing,
            incoming_sequence,
            frame_type: IAX_FRAME_TYPE,
            subclass,
            subclass_is_log: false,
        }
    }
}

fn offered_formats(elements: &[InformationElement<'_>]) -> Result<u64, CallSetupError> {
    let offer = FormatOffer::parse(elements);
    if !offer.format.is_power_of_two() {
        return Err(CallSetupError::InitialFormat);
    }
    // Local construction remains strict. Peer parsing uses Asterisk's fallback.
    if offer.capability == 0
        && elements
            .iter()
            .any(|element| matches!(element.kind, CAPABILITY_IE | 55))
    {
        return Err(CallSetupError::InitialCapability);
    }
    Ok(offer.supported())
}

fn accepted_format(payload: &[u8]) -> Result<u64, CallSetupError> {
    let elements =
        parse_information_elements(payload).map_err(CallSetupError::InformationElements)?;
    let format = FormatOffer::parse(&elements).format;
    if format == 0 {
        return Err(CallSetupError::InvalidAcceptedFormat);
    }
    Ok(format)
}

#[cfg(test)]
#[path = "session_media_tests.rs"]
mod media_tests;
