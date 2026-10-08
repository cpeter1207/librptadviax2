use crate::{
    call_token::CallTokenAuthority,
    codec::IAX_FORMAT_ULAW,
    information_elements::{InformationElement, serialize_information_elements},
    protocol::{FullFrameHeader, IaxCommand, parse_full_frame_packet, serialize_full_frame},
};
use std::{cell::Cell, net::SocketAddr};

const USERNAME: u8 = 6;
const CALLED_NUMBER: u8 = 1;
const CALLING_NUMBER: u8 = 2;
const CAPABILITY: u8 = 8;
const FORMAT: u8 = 9;

fn incoming_new(local: &str, remote: &str, format: u32, capability: u32) -> Vec<u8> {
    incoming_new_with_username(b"radio", local, remote, format, capability)
}

fn incoming_new_with_username(
    username: &[u8],
    local: &str,
    remote: &str,
    format: u32,
    capability: u32,
) -> Vec<u8> {
    let format_bytes = format.to_be_bytes();
    let capability_bytes = capability.to_be_bytes();
    let payload = serialize_information_elements(&[
        InformationElement {
            kind: USERNAME,
            data: username,
        },
        InformationElement {
            kind: CALLED_NUMBER,
            data: local.as_bytes(),
        },
        InformationElement {
            kind: CALLING_NUMBER,
            data: remote.as_bytes(),
        },
        InformationElement {
            kind: FORMAT,
            data: &format_bytes,
        },
        InformationElement {
            kind: CAPABILITY,
            data: &capability_bytes,
        },
    ])
    .unwrap();
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 0x123,
            retransmission: false,
            destination_call_number: 0,
            timestamp: 900,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 6,
            subclass: IaxCommand::New.subclass_value() as u8,
            subclass_is_log: false,
        },
        &payload,
    )
    .unwrap()
}

#[test]
fn accepts_standard_ulaw_incoming_new_for_configured_local_node() {
    let request = incoming_new("524950", "506315", IAX_FORMAT_ULAW, IAX_FORMAT_ULAW);
    let accepted = crate::session::accept_inbound_ulaw_new(&request, "524950", 42).unwrap();

    assert_eq!(accepted.remote_node, "506315");
    assert_eq!(accepted.format, IAX_FORMAT_ULAW);
    let response = parse_full_frame_packet(&accepted.packet).unwrap();
    assert_eq!(response.header.source_call_number, 42);
    assert_eq!(response.header.destination_call_number, 0x123);
    assert_eq!(response.header.timestamp, 0);
    assert_eq!(response.header.outgoing_sequence, 0);
    assert_eq!(response.header.incoming_sequence, 1);
    assert_eq!(response.header.frame_type, 6);
    assert_eq!(
        response.header.subclass,
        IaxCommand::Accept.subclass_value() as u8
    );
    assert_eq!(
        response.payload,
        [9, 4, 0, 0, 0, 4, 56, 9, 0, 0, 0, 0, 0, 0, 0, 0, 4]
    );
}

#[test]
fn rejects_unexpected_identity_target_call_numbers_and_codec() {
    let valid = incoming_new("524950", "506315", IAX_FORMAT_ULAW, IAX_FORMAT_ULAW);
    assert!(crate::session::accept_inbound_ulaw_new(&valid, "524951", 42).is_err());
    assert!(crate::session::accept_inbound_ulaw_new(&valid, "524950", 0).is_err());

    for packet in [
        incoming_new_with_username(
            b"wrong",
            "524950",
            "506315",
            IAX_FORMAT_ULAW,
            IAX_FORMAT_ULAW,
        ),
        incoming_new("524950", "not-a-node", IAX_FORMAT_ULAW, IAX_FORMAT_ULAW),
        incoming_new("524950", "", IAX_FORMAT_ULAW, IAX_FORMAT_ULAW),
        incoming_new("524950", "506315", 1, 1),
    ] {
        assert!(crate::session::accept_inbound_ulaw_new(&packet, "524950", 42).is_err());
    }
}

#[test]
fn rejects_format_and_capability_information_elements_with_wrong_lengths() {
    let format = IAX_FORMAT_ULAW.to_be_bytes();
    let capability = IAX_FORMAT_ULAW.to_be_bytes();
    let payload = serialize_information_elements(&[
        InformationElement {
            kind: USERNAME,
            data: b"radio",
        },
        InformationElement {
            kind: CALLED_NUMBER,
            data: b"524950",
        },
        InformationElement {
            kind: CALLING_NUMBER,
            data: b"506315",
        },
        InformationElement {
            kind: FORMAT,
            data: &format[..3],
        },
        InformationElement {
            kind: CAPABILITY,
            data: &capability,
        },
    ])
    .unwrap();
    let malformed_format = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 0x123,
            retransmission: false,
            destination_call_number: 0,
            timestamp: 0,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 6,
            subclass: IaxCommand::New.subclass_value() as u8,
            subclass_is_log: false,
        },
        &payload,
    )
    .unwrap();
    assert_eq!(
        crate::session::accept_inbound_ulaw_new(&malformed_format, "524950", 42),
        Err(crate::session::InboundNewError::InvalidInformationElements)
    );

    let payload = serialize_information_elements(&[
        InformationElement {
            kind: USERNAME,
            data: b"radio",
        },
        InformationElement {
            kind: CALLED_NUMBER,
            data: b"524950",
        },
        InformationElement {
            kind: CALLING_NUMBER,
            data: b"506315",
        },
        InformationElement {
            kind: FORMAT,
            data: &format,
        },
        InformationElement {
            kind: CAPABILITY,
            data: &capability[..3],
        },
    ])
    .unwrap();
    let malformed_capability = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 0x123,
            retransmission: false,
            destination_call_number: 0,
            timestamp: 0,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 6,
            subclass: IaxCommand::New.subclass_value() as u8,
            subclass_is_log: false,
        },
        &payload,
    )
    .unwrap();
    assert_eq!(
        crate::session::accept_inbound_ulaw_new(&malformed_capability, "524950", 42),
        Err(crate::session::InboundNewError::InvalidInformationElements)
    );
}

#[test]
fn rejects_non_initial_and_malformed_new_frames() {
    let valid = incoming_new("524950", "506315", IAX_FORMAT_ULAW, IAX_FORMAT_ULAW);
    assert!(crate::session::accept_inbound_ulaw_new(&[], "524950", 42).is_err());

    let mut wrong_destination = valid.clone();
    wrong_destination[2] = 0;
    wrong_destination[3] = 1;
    assert!(crate::session::accept_inbound_ulaw_new(&wrong_destination, "524950", 42).is_err());

    let mut wrong_type = valid.clone();
    wrong_type[10] = 4;
    assert!(crate::session::accept_inbound_ulaw_new(&wrong_type, "524950", 42).is_err());

    let mut wrong_command = valid.clone();
    wrong_command[11] = IaxCommand::Hangup.subclass_value() as u8;
    assert!(crate::session::accept_inbound_ulaw_new(&wrong_command, "524950", 42).is_err());

    let mut zero_source = valid.clone();
    zero_source[0] = 0x80;
    zero_source[1] = 0;
    assert!(crate::session::accept_inbound_ulaw_new(&zero_source, "524950", 42).is_err());

    let mut logged_subclass = valid.clone();
    logged_subclass[11] |= 0x80;
    assert!(crate::session::accept_inbound_ulaw_new(&logged_subclass, "524950", 42).is_err());

    let mut sequenced_new = valid.clone();
    sequenced_new[8] = 1;
    assert!(crate::session::accept_inbound_ulaw_new(&sequenced_new, "524950", 42).is_err());

    let mut duplicate_username = valid.clone();
    duplicate_username.extend_from_slice(&[USERNAME, 5, b'r', b'a', b'd', b'i', b'o']);
    assert!(crate::session::accept_inbound_ulaw_new(&duplicate_username, "524950", 42).is_err());

    let mut duplicate_capability = valid.clone();
    duplicate_capability.extend_from_slice(&[CAPABILITY, 4, 0, 0, 0, 4]);
    assert!(crate::session::accept_inbound_ulaw_new(&duplicate_capability, "524950", 42).is_err());

    let mut missing_capability = valid.clone();
    missing_capability.truncate(missing_capability.len() - 6);
    assert!(crate::session::accept_inbound_ulaw_new(&missing_capability, "524950", 42).is_err());

    let mut malformed_ie = valid.clone();
    malformed_ie.push(0xfe);
    assert!(crate::session::accept_inbound_ulaw_new(&malformed_ie, "524950", 42).is_err());

    assert!(crate::session::accept_inbound_ulaw_new(&valid, "524950", 32768).is_err());
}

#[test]
fn inbound_admission_challenges_before_calling_product_policy() {
    let source: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    let authority = CallTokenAuthority::new(23);
    let request = with_token(
        incoming_new("524950", "506315", IAX_FORMAT_ULAW, IAX_FORMAT_ULAW),
        &[],
    );
    let policy_called = Cell::new(false);

    let action = crate::session::process_inbound_ulaw_new(
        &authority,
        source,
        &request,
        "524950",
        42,
        100,
        |_| {
            policy_called.set(true);
            true
        },
    )
    .unwrap();

    let crate::session::InboundNewAction::Reply(packet) = action else {
        panic!("initial NEW must receive a call-token challenge")
    };
    let challenge = parse_full_frame_packet(&packet).unwrap();
    assert_eq!(
        challenge.header.subclass,
        IaxCommand::CallToken.subclass_value() as u8
    );
    assert!(!policy_called.get());
}

#[test]
fn inbound_accept_requires_a_valid_token_and_product_authorization() {
    let source: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    let authority = CallTokenAuthority::new(23);
    let token = authority.issue(source, 100);
    let request = with_token(
        incoming_new("524950", "506315", IAX_FORMAT_ULAW, IAX_FORMAT_ULAW),
        token.as_bytes(),
    );

    let denied = crate::session::process_inbound_ulaw_new(
        &authority,
        source,
        &request,
        "524950",
        42,
        100,
        |remote| remote == "508422",
    )
    .unwrap();
    let crate::session::InboundNewAction::Reply(packet) = denied else {
        panic!("unauthorized node must receive a reject")
    };
    assert_eq!(
        parse_full_frame_packet(&packet).unwrap().header.subclass,
        IaxCommand::Reject.subclass_value() as u8
    );

    let accepted = crate::session::process_inbound_ulaw_new(
        &authority,
        source,
        &request,
        "524950",
        42,
        100,
        |remote| remote == "506315",
    )
    .unwrap();
    assert!(matches!(
        accepted,
        crate::session::InboundNewAction::Accept(call)
            if call.remote_node == "506315" && call.format == IAX_FORMAT_ULAW
    ));
}

#[test]
fn inbound_admission_rejects_bad_tokens_and_identities_before_policy() {
    let source: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    let authority = CallTokenAuthority::new(23);
    let packet = incoming_new("524950", "506315", IAX_FORMAT_ULAW, IAX_FORMAT_ULAW);
    let invalid_token = with_token(packet.clone(), b"expired?invalid");
    let called = Cell::new(false);

    let rejected = crate::session::process_inbound_ulaw_new(
        &authority,
        source,
        &invalid_token,
        "524950",
        42,
        100,
        |_| {
            called.set(true);
            true
        },
    )
    .unwrap();
    assert!(matches!(
        rejected,
        crate::session::InboundNewAction::Reply(ref reply)
            if parse_full_frame_packet(reply).unwrap().header.subclass
                == IaxCommand::Reject.subclass_value() as u8
    ));

    let valid = authority.issue(source, 100);
    let wrong_node = with_token(
        incoming_new("524951", "506315", IAX_FORMAT_ULAW, IAX_FORMAT_ULAW),
        valid.as_bytes(),
    );
    let rejected = crate::session::process_inbound_ulaw_new(
        &authority,
        source,
        &wrong_node,
        "524950",
        42,
        100,
        |_| {
            called.set(true);
            true
        },
    )
    .unwrap();
    assert!(matches!(
        rejected,
        crate::session::InboundNewAction::Reply(_)
    ));
    assert!(!called.get());

    assert!(
        crate::session::process_inbound_ulaw_new(
            &authority,
            source,
            &[],
            "524950",
            42,
            100,
            |_| true,
        )
        .is_err()
    );
}

fn with_token(packet: Vec<u8>, token: &[u8]) -> Vec<u8> {
    let frame = parse_full_frame_packet(&packet).unwrap();
    let mut payload = frame.payload.to_vec();
    payload.extend_from_slice(&[54, token.len() as u8]);
    payload.extend_from_slice(token);
    serialize_full_frame(&frame.header, &payload).unwrap()
}
