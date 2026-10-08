//! Outbound IAX2 call setup through authentication and ACCEPT.

use crate::authentication::{
    AUTH_METHOD_MD5, AuthenticationRequestError, build_md5_authrep, parse_auth_request,
};
use crate::call_token::{
    CallTokenAuthority, CallTokenRequestError, CallTokenRetryError, InitialNewDisposition,
    InitialNewError, build_initial_new, retry_new_call_with_token,
};
use crate::codec::IAX_FORMAT_ULAW;
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
const FORMAT_IE: u8 = 9;
const FORMAT2_IE: u8 = 56;
const ACK_SUBCLASS: u8 = 4;

/// Incoming call accepted after the listener has validated its call token and access policy.
#[derive(Debug, Eq, PartialEq)]
pub struct InboundCallAccepted {
    /// Numeric node identifier supplied by the remote `CALLING_NUMBER` IE.
    pub remote_node: String,
    /// Negotiated codec format.
    pub format: u32,
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
    mut authorize: impl FnMut(&str) -> bool,
) -> Result<InboundNewAction, InboundAdmissionError> {
    match tokens
        .handle_initial_new(source, packet, now_seconds)
        .map_err(InboundAdmissionError::CallToken)?
    {
        InitialNewDisposition::Challenge(reply) | InitialNewDisposition::Reject(reply) => {
            Ok(InboundNewAction::Reply(reply))
        }
        InitialNewDisposition::Continue => {
            let Ok(accepted) = accept_inbound_ulaw_new(packet, local_node, local_call) else {
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
    let format = unique_ie(&elements, FORMAT_IE)?;
    let capability = unique_ie(&elements, CAPABILITY_IE)?;
    if username != b"radio"
        || called != local_node.as_bytes()
        || calling.is_empty()
        || !calling.iter().all(u8::is_ascii_digit)
    {
        return Err(InboundNewError::InvalidIdentity);
    }
    if format.len() != 4 || capability.len() != 4 {
        return Err(InboundNewError::InvalidInformationElements);
    }
    let capability =
        u32::from_be_bytes([capability[0], capability[1], capability[2], capability[3]]);
    if capability & IAX_FORMAT_ULAW == 0 {
        return Err(InboundNewError::UnsupportedFormat);
    }

    let format_bytes = IAX_FORMAT_ULAW.to_be_bytes();
    let format2_bytes = u64::from(IAX_FORMAT_ULAW).to_be_bytes();
    let mut format2 = [0; 9];
    format2[1..].copy_from_slice(&format2_bytes);
    let mut response_payload = Vec::with_capacity(17);
    response_payload.extend_from_slice(&[FORMAT_IE, format_bytes.len() as u8]);
    response_payload.extend_from_slice(&format_bytes);
    response_payload.extend_from_slice(&[FORMAT2_IE, format2.len() as u8]);
    response_payload.extend_from_slice(&format2);
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
        format: IAX_FORMAT_ULAW,
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
    /// The initial NEW does not contain a usable legacy FORMAT IE.
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
    /// ACCEPT omitted FORMAT or encoded it with the wrong size.
    InvalidAcceptedFormat,
    /// The peer selected a format not offered by the initial NEW.
    UnacceptedFormat {
        /// Peer format bit field.
        format: u32,
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
        format: u32,
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
    /// Send the next setup packet.
    Send(Vec<u8>),
    /// The peer accepted the call.
    Accepted {
        /// Remote call number from the already validated ACCEPT header.
        remote_call: u16,
        format: u32,
        acknowledgement: Vec<u8>,
    },
    /// The peer rejected the call.
    Rejected { acknowledgement: Vec<u8> },
}

/// Response possible after an outbound call has reached the linked state.
pub(crate) enum LinkedCallResponse {
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
            LinkedCallResponse::Send(packet) => Self::Send(packet),
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
    offered_formats: u32,
    next_outgoing: u8,
    next_incoming: u8,
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

        if let Some(response) = self.duplicate_response(&frame.header, Some(command), frame.payload)
        {
            return Ok(OutboundSetupResponse::Send(response));
        }
        if matches!(self.state, State::Rejected | State::Ended) {
            return Err(CallSetupError::CallFinished);
        }

        self.validate_peer_header(&frame.header)?;
        match command {
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

    fn validate_peer_header(&self, header: &FullFrameHeader) -> Result<(), CallSetupError> {
        self.validate_call_ids(header)?;
        if header.outgoing_sequence != self.next_incoming
            || header.incoming_sequence != self.next_outgoing
        {
            return Err(CallSetupError::SequenceMismatch {
                expected_outgoing: self.next_incoming,
                actual_outgoing: header.outgoing_sequence,
                expected_incoming: self.next_outgoing,
                actual_incoming: header.incoming_sequence,
            });
        }
        Ok(())
    }

    fn validate_call_ids(&self, header: &FullFrameHeader) -> Result<(), CallSetupError> {
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
        if let Some(response) = self.duplicate_response(&frame.header, Some(command), frame.payload)
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
        if let Some(response) = self.duplicate_response(header, None, payload) {
            return Ok(LinkedCallResponse::Send(response));
        }
        self.validate_peer_header(header)?;
        let next_incoming = self.next_incoming.wrapping_add(1);
        let acknowledgement = self.acknowledgement(header, next_incoming)?;
        self.next_incoming = next_incoming;
        self.remember_response(None, header, payload, acknowledgement.clone());
        Ok(match subclass {
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
            IaxCommand::Ping => {
                let next_incoming = self.next_incoming.wrapping_add(1);
                let pong = serialize_full_frame(
                    &self.outgoing_header(
                        header.source_call_number,
                        header.timestamp,
                        next_incoming,
                        IaxCommand::Pong.subclass_value() as u8,
                    ),
                    &[],
                )
                .map_err(CallSetupError::Frame)?;
                self.next_outgoing = self.next_outgoing.wrapping_add(1);
                self.next_incoming = next_incoming;
                self.remember_response(Some(command), header, payload, pong.clone());
                Ok(LinkedCallResponse::Send(pong))
            }
            IaxCommand::Pong => {
                let next_incoming = self.next_incoming.wrapping_add(1);
                let acknowledgement = self.acknowledgement(header, next_incoming)?;
                let matched_probe = self.pending_ping_timestamp == Some(header.timestamp);
                if matched_probe {
                    self.pending_ping_timestamp = None;
                }
                self.next_incoming = next_incoming;
                self.remember_response(Some(command), header, payload, acknowledgement.clone());
                Ok(LinkedCallResponse::PongAcknowledged {
                    acknowledgement,
                    matched_probe,
                })
            }
            IaxCommand::Hangup => {
                let next_incoming = self.next_incoming.wrapping_add(1);
                let acknowledgement = self.acknowledgement(header, next_incoming)?;
                self.next_incoming = next_incoming;
                self.state = State::Ended;
                self.remember_response(Some(command), header, payload, acknowledgement.clone());
                Ok(LinkedCallResponse::Ended { acknowledgement })
            }
            _ => Err(CallSetupError::UnexpectedCommand { command }),
        }
    }

    fn receive_text(&mut self, packet: &[u8]) -> Result<LinkedCallResponse, CallSetupError> {
        let text = parse_text_frame(packet).map_err(|_| CallSetupError::InvalidFrame)?;
        if let Some(acknowledgement) =
            self.duplicate_response(&text.header, None, text.text.as_bytes())
        {
            return Ok(LinkedCallResponse::Send(acknowledgement));
        }
        self.validate_peer_header(&text.header)?;
        let next_incoming = self.next_incoming.wrapping_add(1);
        let acknowledgement = self.acknowledgement(&text.header, next_incoming)?;
        self.next_incoming = next_incoming;
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
        if let Some(response) = self.duplicate_response(header, None, payload) {
            return Ok(LinkedCallResponse::Send(response));
        }
        self.validate_peer_header(header)?;
        let next_incoming = self.next_incoming.wrapping_add(1);
        let acknowledgement = self.acknowledgement(header, next_incoming)?;
        self.next_incoming = next_incoming;
        self.remember_response(None, header, payload, acknowledgement.clone());
        Ok(LinkedCallResponse::Digit {
            digit: header.subclass,
            acknowledgement,
        })
    }

    fn duplicate_response(
        &self,
        header: &FullFrameHeader,
        command: Option<IaxCommand>,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let last = self.last_reliable_response.as_ref()?;
        (header.retransmission
            && header.destination_call_number == self.local_call
            && header.source_call_number == last.source_call
            && header.outgoing_sequence == last.outgoing_sequence
            && command == last.command
            && header.frame_type == last.frame_type
            && header.subclass == last.subclass
            && payload == last.payload)
            .then(|| last.response.clone())
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
        if format == 0 || format & self.offered_formats == 0 {
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
        self.next_incoming = next_incoming;
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
        self.next_incoming = next_incoming;
        self.state = State::Rejected;
        Ok(OutboundSetupResponse::Rejected { acknowledgement })
    }

    fn acknowledgement(
        &self,
        peer_header: &FullFrameHeader,
        incoming_sequence: u8,
    ) -> Result<Vec<u8>, CallSetupError> {
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

fn offered_formats(elements: &[InformationElement<'_>]) -> Result<u32, CallSetupError> {
    let Some(format) = elements
        .iter()
        .rev()
        .find(|element| element.kind == FORMAT_IE)
    else {
        return Err(CallSetupError::InitialFormat);
    };
    if format.data.len() != 4 {
        return Err(CallSetupError::InitialFormat);
    }
    let preferred = u32::from_be_bytes(format.data.try_into().expect("length checked"));
    if preferred == 0 {
        return Err(CallSetupError::InitialFormat);
    }

    let Some(capability) = elements
        .iter()
        .rev()
        .find(|element| element.kind == CAPABILITY_IE)
    else {
        return Ok(preferred);
    };
    if capability.data.len() != 4 {
        return Err(CallSetupError::InitialCapability);
    }
    let capability = u32::from_be_bytes(capability.data.try_into().expect("length checked"));
    if capability == 0 {
        return Err(CallSetupError::InitialCapability);
    }
    Ok(capability)
}

fn accepted_format(payload: &[u8]) -> Result<u32, CallSetupError> {
    let mut format = None;
    for element in
        parse_information_elements(payload).map_err(CallSetupError::InformationElements)?
    {
        if element.kind == FORMAT_IE {
            if element.data.len() != 4 {
                return Err(CallSetupError::InvalidAcceptedFormat);
            }
            format = Some(u32::from_be_bytes(
                element.data.try_into().expect("length checked"),
            ));
        }
    }
    format.ok_or(CallSetupError::InvalidAcceptedFormat)
}
