//! IAX2 call-token retry payload handling.

use crate::information_elements::{
    InformationElement, InformationElementError, parse_information_elements,
    serialize_information_elements,
};
use crate::protocol::{
    FrameEncodeError, FullFrameHeader, IaxCommand, decode_iax_command, parse_full_frame_packet,
    serialize_full_frame,
};
use sha1::{Digest, Sha1};
use std::net::SocketAddr;

const CALL_TOKEN_IE: u8 = 54;
const IAX_FRAME_TYPE: u8 = 6;
const NEW_SUBCLASS: u8 = 1;
const CALL_TOKEN_LIFETIME_SECONDS: u32 = 10;
const REPLY_CALL_NUMBER: u16 = 1;

/// Action for a valid initial IAX `NEW` packet.
#[derive(Debug, Eq, PartialEq)]
pub enum InitialNewDisposition {
    /// Send this stateless CALLTOKEN challenge before allocating a call.
    Challenge(Vec<u8>),
    /// The supplied token is valid; the caller may continue call admission.
    Continue,
    /// Send this stateless REJECT because the token is absent or invalid.
    Reject(Vec<u8>),
}

/// Issues and validates source-bound IAX call tokens for one server lifetime.
///
/// Asterisk's token is SHA-1 of the source address, timestamp, and a private
/// per-process random integer. This mirrors the wire format; the integer must
/// be unpredictable and remain stable until the server stops.
pub struct CallTokenAuthority {
    random_data: i32,
}

impl CallTokenAuthority {
    /// Create an authority with a private per-process random value.
    pub const fn new(random_data: i32) -> Self {
        Self { random_data }
    }

    /// Return the Asterisk-compatible `timestamp?sha1` token for one endpoint.
    pub fn issue(&self, source: SocketAddr, timestamp_seconds: u32) -> String {
        format!(
            "{timestamp_seconds}?{}",
            self.digest(source, timestamp_seconds)
        )
    }

    /// Validate syntax, source binding, timestamp, and the ten-second lifetime.
    pub fn validate(&self, source: SocketAddr, token: &str, now_seconds: u32) -> bool {
        let Some((timestamp, digest)) = token.split_once('?') else {
            return false;
        };
        if digest.len() != 40 || digest.contains('?') {
            return false;
        }
        let Ok(timestamp) = timestamp.parse::<u32>() else {
            return false;
        };
        now_seconds >= timestamp
            && now_seconds - timestamp < CALL_TOKEN_LIFETIME_SECONDS
            && digest == self.digest(source, timestamp)
    }

    /// Apply Asterisk's call-token gate to an initial inbound `NEW` frame.
    ///
    /// An empty CALLTOKEN IE receives a stateless challenge. A valid token
    /// continues without a reply; missing, duplicate, malformed, expired, or
    /// source-mismatched tokens receive a stateless REJECT. No call state is
    /// allocated here.
    pub fn handle_initial_new(
        &self,
        source: SocketAddr,
        packet: &[u8],
        now_seconds: u32,
    ) -> Result<InitialNewDisposition, CallTokenRequestError> {
        let request =
            parse_full_frame_packet(packet).map_err(|_| CallTokenRequestError::InvalidFrame)?;
        validate_initial_new(&request.header)?;

        let mut token = None;
        for element in parse_information_elements(request.payload)
            .map_err(CallTokenRequestError::MalformedInformationElements)?
        {
            if element.kind != CALL_TOKEN_IE {
                continue;
            }
            if token.is_some() {
                return Ok(InitialNewDisposition::Reject(build_token_reply(
                    &request.header,
                    IaxCommand::Reject,
                    &[],
                )));
            }
            token = Some(element.data);
        }

        match token {
            Some([]) => {
                let token = self.issue(source, now_seconds);
                let mut payload = Vec::with_capacity(token.len() + 2);
                payload.extend_from_slice(&[CALL_TOKEN_IE, token.len() as u8]);
                payload.extend_from_slice(token.as_bytes());
                Ok(InitialNewDisposition::Challenge(build_token_reply(
                    &request.header,
                    IaxCommand::CallToken,
                    &payload,
                )))
            }
            Some(token)
                if std::str::from_utf8(token)
                    .is_ok_and(|token| self.validate(source, token, now_seconds)) =>
            {
                Ok(InitialNewDisposition::Continue)
            }
            _ => Ok(InitialNewDisposition::Reject(build_token_reply(
                &request.header,
                IaxCommand::Reject,
                &[],
            ))),
        }
    }

    /// Build a stateless REJECT for a valid initial NEW after product policy denies it.
    pub fn reject_initial_new(&self, packet: &[u8]) -> Result<Vec<u8>, CallTokenRequestError> {
        let request =
            parse_full_frame_packet(packet).map_err(|_| CallTokenRequestError::InvalidFrame)?;
        validate_initial_new(&request.header)?;
        Ok(build_token_reply(&request.header, IaxCommand::Reject, &[]))
    }

    fn digest(&self, source: SocketAddr, timestamp_seconds: u32) -> String {
        let material = format!("{source}{timestamp_seconds}{}", self.random_data);
        format!("{:x}", Sha1::digest(material.as_bytes()))
    }
}

#[cfg(test)]
#[path = "call_token_tests.rs"]
mod tests;

fn validate_initial_new(header: &FullFrameHeader) -> Result<(), CallTokenRequestError> {
    if header.source_call_number == 0
        || header.destination_call_number != 0
        || decode_iax_command(header) != Ok(Some(IaxCommand::New))
    {
        return Err(CallTokenRequestError::NotInitialNew);
    }
    Ok(())
}

/// Why an inbound call-token request could not be handled.
#[derive(Debug, Eq, PartialEq)]
pub enum CallTokenRequestError {
    /// The datagram is not a complete full-frame packet.
    InvalidFrame,
    /// The packet is not an initial IAX NEW with destination call zero.
    NotInitialNew,
    /// The packet's information elements are malformed.
    MalformedInformationElements(InformationElementError),
}

fn build_token_reply(request: &FullFrameHeader, command: IaxCommand, payload: &[u8]) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: REPLY_CALL_NUMBER,
            retransmission: false,
            destination_call_number: request.source_call_number,
            timestamp: request.timestamp,
            outgoing_sequence: 0,
            incoming_sequence: request.incoming_sequence.wrapping_add(1),
            frame_type: IAX_FRAME_TYPE,
            subclass: command.subclass_value() as u8,
            subclass_is_log: false,
        },
        payload,
    )
    .expect("parsed call number and bounded token payload fit the IAX2 wire format")
}

/// Why an initial NEW packet could not be constructed.
#[derive(Debug, Eq, PartialEq)]
pub enum InitialNewError {
    /// Information elements are malformed for the one-byte IAX length field.
    InformationElements(InformationElementError),
    /// The caller supplied CALLTOKEN; this builder appends the initial empty IE.
    CallTokenAlreadyPresent,
    /// The source call number cannot be represented in an IAX2 full frame.
    Frame(FrameEncodeError),
}

/// Build an initial NEW packet with its final empty CALLTOKEN information element.
///
/// New-call sequence numbers and destination are zero. The call number and
/// timestamp are supplied by the session owner; wire framing stays here.
pub fn build_initial_new(
    source_call_number: u16,
    timestamp_ms: u32,
    elements: &[InformationElement<'_>],
) -> Result<Vec<u8>, InitialNewError> {
    if elements.iter().any(|element| element.kind == CALL_TOKEN_IE) {
        return Err(InitialNewError::CallTokenAlreadyPresent);
    }

    let mut payload =
        serialize_information_elements(elements).map_err(InitialNewError::InformationElements)?;
    payload.extend_from_slice(&[CALL_TOKEN_IE, 0]);

    serialize_full_frame(
        &FullFrameHeader {
            source_call_number,
            retransmission: false,
            destination_call_number: 0,
            timestamp: timestamp_ms,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: IAX_FRAME_TYPE,
            subclass: NEW_SUBCLASS,
            subclass_is_log: false,
        },
        &payload,
    )
    .map_err(InitialNewError::Frame)
}

/// Why an initial call-token IE could not be replaced.
#[derive(Debug, Eq, PartialEq)]
pub enum CallTokenError {
    /// The initial payload contains malformed information elements.
    MalformedInformationElements(InformationElementError),
    /// The final element is not the empty CALLTOKEN IE required on an initial NEW.
    MissingEmptyCallToken,
    /// A peer returned an empty token value.
    EmptyReturnedToken,
    /// A token does not fit in the IE's one-octet length.
    TokenTooLong {
        /// Supplied token length in bytes.
        length: usize,
    },
}

/// Why an IAX call-token exchange could not produce a NEW retry packet.
#[derive(Debug, Eq, PartialEq)]
pub enum CallTokenRetryError {
    /// One packet does not contain a valid full-frame header.
    InvalidFrame,
    /// The packets do not form an unambiguous NEW/CALLTOKEN exchange.
    InvalidExchange,
    /// The peer's token response contains malformed information elements.
    MalformedInformationElements(InformationElementError),
    /// The initial NEW does not end with an empty CALLTOKEN element or
    /// the returned token cannot be represented in that element.
    InvalidInitialPayload(CallTokenError),
}

/// Replace Asterisk's final empty CALLTOKEN IE with the opaque peer token.
pub fn replace_empty_call_token(payload: &[u8], token: &[u8]) -> Result<Vec<u8>, CallTokenError> {
    let elements = parse_information_elements(payload)
        .map_err(CallTokenError::MalformedInformationElements)?;
    if !matches!(elements.last(), Some(last) if last.kind == CALL_TOKEN_IE && last.data.is_empty())
    {
        return Err(CallTokenError::MissingEmptyCallToken);
    }
    if token.is_empty() {
        return Err(CallTokenError::EmptyReturnedToken);
    }
    if token.len() > usize::from(u8::MAX) {
        return Err(CallTokenError::TokenTooLong {
            length: token.len(),
        });
    }

    let prefix_length = payload.len() - 2;
    let mut replacement = Vec::with_capacity(prefix_length + token.len() + 2);
    replacement.extend_from_slice(&payload[..prefix_length]);
    replacement.extend_from_slice(&[CALL_TOKEN_IE, token.len() as u8]);
    replacement.extend_from_slice(token);
    Ok(replacement)
}

/// Build the Asterisk-compatible NEW retry after receiving a CALLTOKEN frame.
///
/// The caller supplies the current relative-millisecond timestamp so the
/// protocol module does not own a clock or network socket. Asterisk restarts
/// the initial full-frame sequence state at zero after replacing the last IE.
pub fn retry_new_call_with_token(
    initial_frame: &[u8],
    response_frame: &[u8],
    timestamp_ms: u32,
) -> Result<Vec<u8>, CallTokenRetryError> {
    let initial =
        parse_full_frame_packet(initial_frame).map_err(|_| CallTokenRetryError::InvalidFrame)?;
    let response =
        parse_full_frame_packet(response_frame).map_err(|_| CallTokenRetryError::InvalidFrame)?;

    if initial.header.source_call_number == 0
        || initial.header.destination_call_number != 0
        || decode_iax_command(&initial.header) != Ok(Some(IaxCommand::New))
        || response.header.destination_call_number != initial.header.source_call_number
        || decode_iax_command(&response.header) != Ok(Some(IaxCommand::CallToken))
    {
        return Err(CallTokenRetryError::InvalidExchange);
    }

    let elements = parse_information_elements(response.payload)
        .map_err(CallTokenRetryError::MalformedInformationElements)?;
    let mut token = None;
    for element in elements {
        if element.kind == CALL_TOKEN_IE {
            if token.is_some() {
                return Err(CallTokenRetryError::InvalidExchange);
            }
            token = Some(element.data);
        }
    }
    let token = token.ok_or(CallTokenRetryError::InvalidExchange)?;

    let payload = replace_empty_call_token(initial.payload, token)
        .map_err(CallTokenRetryError::InvalidInitialPayload)?;
    let mut retry = Vec::with_capacity(12 + payload.len());
    retry.extend_from_slice(&initial_frame[..12]);
    retry[4..8].copy_from_slice(&timestamp_ms.to_be_bytes());
    retry[8] = 0;
    retry[9] = 0;
    retry.extend_from_slice(&payload);
    Ok(retry)
}
