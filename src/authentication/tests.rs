//! Authentication tests colocated with production code for accurate coverage.

use super::{
    AUTH_METHOD_MD5, AuthenticationRequest, AuthenticationRequestError, build_md5_authrep,
    parse_auth_request, verify_md5_authrep,
};
use crate::information_elements::{
    InformationElement, InformationElementError, serialize_information_elements,
};
use crate::protocol::{
    FrameEncodeError, FullFrameHeader, IaxCommand, decode_iax_command, parse_full_frame_packet,
};

#[test]
fn builds_asterisk_compatible_md5_authrep_packet() {
    let header = FullFrameHeader {
        source_call_number: 1,
        retransmission: false,
        destination_call_number: 2,
        timestamp: 0x0102_0304,
        outgoing_sequence: 5,
        incoming_sequence: 6,
        frame_type: 0,
        subclass: 0,
        subclass_is_log: false,
    };

    let packet = build_md5_authrep(&header, "challenge", "-secret").unwrap();

    assert_eq!(
        packet,
        [
            0x80, 0x01, 0x00, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x06, 0x09, 0x10, 0x20,
            b'f', b'6', b'f', b'2', b'1', b'1', b'f', b'c', b'd', b'7', b'3', b'1', b'a', b'4',
            b'5', b'5', b'4', b'0', b'e', b'3', b'b', b'e', b'8', b'3', b'2', b'e', b'5', b'e',
            b'b', b'9', b'f', b'7',
        ]
    );

    let parsed = parse_full_frame_packet(&packet).unwrap();
    assert_eq!(
        decode_iax_command(&parsed.header),
        Ok(Some(IaxCommand::AuthRep))
    );
    assert_eq!(parsed.payload[0..2], [16, 32]);
}

#[test]
fn rejects_invalid_call_numbers_in_authrep_header() {
    let header = FullFrameHeader {
        source_call_number: 0x8000,
        retransmission: false,
        destination_call_number: 2,
        timestamp: 0,
        outgoing_sequence: 0,
        incoming_sequence: 0,
        frame_type: 0,
        subclass: 0,
        subclass_is_log: false,
    };

    assert_eq!(
        build_md5_authrep(&header, "challenge", "secret"),
        Err(FrameEncodeError::CallNumberOutOfRange {
            field: "source",
            value: 0x8000,
        })
    );
}

#[test]
fn verifies_asterisk_md5_response_against_secret_list_case_insensitively() {
    let response = b"f6f211fcd731a45540e3be832e5eb9f7";

    assert!(verify_md5_authrep(
        "challenge",
        "old-secret;-secret",
        response
    ));
    assert!(verify_md5_authrep(
        "challenge",
        "-secret",
        b"F6F211FCD731A45540E3BE832E5EB9F7"
    ));
    assert!(!verify_md5_authrep("challenge", "wrong-secret", response));
    assert!(!verify_md5_authrep("challenge", "-secret", b"wrong"));
}

#[test]
fn parses_authreq_methods_and_challenge_from_information_elements() {
    let elements = [
        InformationElement {
            kind: 14,
            data: &[0, 2],
        },
        InformationElement {
            kind: 15,
            data: b"challenge",
        },
    ];
    let payload = serialize_information_elements(&elements).unwrap();

    assert_eq!(
        parse_auth_request(&payload),
        Ok(AuthenticationRequest {
            methods: AUTH_METHOD_MD5,
            challenge: "challenge",
        })
    );
}

#[test]
fn rejects_malformed_or_incomplete_authreq_information_elements() {
    assert_eq!(
        parse_auth_request(&[14]),
        Err(AuthenticationRequestError::InformationElements(
            InformationElementError::MissingLength { offset: 0 }
        ))
    );
    assert_eq!(
        parse_auth_request(&[15, 1, b'x']),
        Err(AuthenticationRequestError::MissingMethods)
    );
    assert_eq!(
        parse_auth_request(&[14, 2, 0, 2]),
        Err(AuthenticationRequestError::MissingChallenge)
    );
    assert_eq!(
        parse_auth_request(&[14, 1, 2, 15, 1, b'x']),
        Err(AuthenticationRequestError::InvalidMethodsLength { length: 1 })
    );
    assert_eq!(
        parse_auth_request(&[14, 3, 0, 2, 0, 15, 1, b'x']),
        Err(AuthenticationRequestError::InvalidMethodsLength { length: 3 })
    );
    assert_eq!(
        parse_auth_request(&[14, 2, 0, 2, 15, 1, 0xff]),
        Err(AuthenticationRequestError::InvalidChallengeEncoding)
    );
}

#[test]
fn uses_the_last_known_authreq_elements_and_ignores_unknown_elements() {
    let elements = [
        InformationElement {
            kind: 14,
            data: &[0, 1],
        },
        InformationElement {
            kind: 15,
            data: b"first",
        },
        InformationElement {
            kind: 254,
            data: b"ignored",
        },
        InformationElement {
            kind: 14,
            data: &[0, 2],
        },
        InformationElement {
            kind: 15,
            data: b"last",
        },
    ];
    let payload = serialize_information_elements(&elements).unwrap();

    assert_eq!(
        parse_auth_request(&payload),
        Ok(AuthenticationRequest {
            methods: 2,
            challenge: "last",
        })
    );
}
