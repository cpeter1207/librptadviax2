//! IAX2 authentication response packet construction.

use md5::{Digest, Md5};

use crate::information_elements::{InformationElementError, parse_information_elements};
use crate::protocol::{FrameEncodeError, FullFrameHeader, serialize_full_frame};

const IAX_FRAME_TYPE: u8 = 6;
const AUTHREP_SUBCLASS: u8 = 9;
const AUTHMETHODS_IE: u8 = 14;
const CHALLENGE_IE: u8 = 15;
const MD5_RESULT_IE: u8 = 16;
const MD5_HEX_LENGTH: usize = 32;

/// IAX2 AUTHMETHODS bit indicating MD5 challenge-response support.
pub const AUTH_METHOD_MD5: u16 = 1 << 1;

/// Parsed authentication methods and challenge from an AUTHREQ payload.
#[derive(Debug, Eq, PartialEq)]
pub struct AuthenticationRequest<'a> {
    /// Bit field from the AUTHMETHODS IE.
    pub methods: u16,
    /// Challenge string from the CHALLENGE IE.
    pub challenge: &'a str,
}

/// Why an IAX2 authentication request payload is invalid.
#[derive(Debug, Eq, PartialEq)]
pub enum AuthenticationRequestError {
    /// The payload contains malformed length-delimited information elements.
    InformationElements(InformationElementError),
    /// The AUTHMETHODS IE is absent.
    MissingMethods,
    /// The AUTHMETHODS IE does not contain exactly two bytes.
    InvalidMethodsLength {
        /// Actual AUTHMETHODS value length in bytes.
        length: usize,
    },
    /// The CHALLENGE IE is absent.
    MissingChallenge,
    /// The CHALLENGE IE is not valid UTF-8.
    InvalidChallengeEncoding,
}

/// Parse AUTHMETHODS and CHALLENGE from an IAX2 AUTHREQ payload.
///
/// Unknown information elements are ignored. If either known IE appears more
/// than once, the final value is used, matching Asterisk's IE parser behavior.
pub fn parse_auth_request(
    payload: &[u8],
) -> Result<AuthenticationRequest<'_>, AuthenticationRequestError> {
    let mut methods = None;
    let mut challenge = None;
    for element in parse_information_elements(payload)
        .map_err(AuthenticationRequestError::InformationElements)?
    {
        match element.kind {
            AUTHMETHODS_IE if element.data.len() == 2 => {
                methods = Some(u16::from_be_bytes([element.data[0], element.data[1]]));
            }
            AUTHMETHODS_IE => {
                return Err(AuthenticationRequestError::InvalidMethodsLength {
                    length: element.data.len(),
                });
            }
            CHALLENGE_IE => {
                challenge = Some(
                    std::str::from_utf8(element.data)
                        .map_err(|_| AuthenticationRequestError::InvalidChallengeEncoding)?,
                );
            }
            _ => {}
        }
    }

    Ok(AuthenticationRequest {
        methods: methods.ok_or(AuthenticationRequestError::MissingMethods)?,
        challenge: challenge.ok_or(AuthenticationRequestError::MissingChallenge)?,
    })
}

/// Build an Asterisk-compatible AUTHREP packet using IAX2 MD5 authentication.
///
/// Asterisk hashes the challenge directly followed by the secret and sends the
/// lowercase hexadecimal digest as the `MD5_RESULT` IE. The frame sequencing,
/// call numbers, timestamp, and retransmission flag come from `header`.
pub fn build_md5_authrep(
    header: &FullFrameHeader,
    challenge: &str,
    secret: &str,
) -> Result<Vec<u8>, FrameEncodeError> {
    let result = md5_result(challenge, secret);

    let mut payload = [0; MD5_HEX_LENGTH + 2];
    payload[..2].copy_from_slice(&[MD5_RESULT_IE, MD5_HEX_LENGTH as u8]);
    payload[2..].copy_from_slice(&result);
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: header.source_call_number,
            retransmission: header.retransmission,
            destination_call_number: header.destination_call_number,
            timestamp: header.timestamp,
            outgoing_sequence: header.outgoing_sequence,
            incoming_sequence: header.incoming_sequence,
            frame_type: IAX_FRAME_TYPE,
            subclass: AUTHREP_SUBCLASS,
            subclass_is_log: false,
        },
        &payload,
    )
}

/// Verify an Asterisk-compatible MD5 AUTHREP result against semicolon-separated secrets.
///
/// Asterisk accepts any configured secret alternative and compares the hexadecimal
/// result without regard to letter case. Parsing the AUTHREP packet and selecting
/// the challenge remain responsibilities of the session layer.
pub fn verify_md5_authrep(challenge: &str, secrets: &str, response: &[u8]) -> bool {
    secrets
        .split(';')
        .any(|secret| md5_result(challenge, secret).eq_ignore_ascii_case(response))
}

fn md5_result(challenge: &str, secret: &str) -> [u8; MD5_HEX_LENGTH] {
    let mut hasher = Md5::new();
    hasher.update(challenge.as_bytes());
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();

    let mut result = [0; MD5_HEX_LENGTH];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in digest.iter().enumerate() {
        result[index * 2] = HEX[usize::from(byte >> 4)];
        result[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    result
}

#[cfg(test)]
mod tests;
