use crate::{
    call_token::{CallTokenAuthority, InitialNewDisposition},
    information_elements::{InformationElement, parse_information_elements},
    protocol::{
        FullFrameHeader, IaxCommand, decode_iax_command, parse_full_frame_packet,
        serialize_full_frame,
    },
};
use std::net::SocketAddr;

const CLIENT: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
    std::net::Ipv4Addr::new(127, 0, 0, 1),
    4569,
));

#[test]
fn issues_asterisk_compatible_token_and_validates_only_same_source_within_ten_seconds() {
    let authority = CallTokenAuthority::new(42);

    let token = authority.issue(CLIENT, 1_700_000_000);

    assert_eq!(token, "1700000000?1ace7d876f3cfc56bc40248b15454273892633f9");
    assert!(authority.validate(CLIENT, &token, 1_700_000_009));
    assert!(!authority.validate("127.0.0.2:4569".parse().unwrap(), &token, 1_700_000_001));
    assert!(!authority.validate(CLIENT, &token, 1_700_000_010));
    assert!(!authority.validate(CLIENT, &token, 1_699_999_999));
}

#[test]
fn rejects_malformed_tokens_without_panicking() {
    let authority = CallTokenAuthority::new(42);

    for token in ["", "no separator", "1700000000?", "?hash", "1?bad?hash"] {
        assert!(!authority.validate(CLIENT, token, 1_700_000_001));
    }

    assert!(!authority.validate(
        CLIENT,
        "not-a-timestamp?1ace7d876f3cfc56bc40248b15454273892633f9",
        1_700_000_001,
    ));

    let embedded_separator = format!("1?{}?", "a".repeat(39));
    assert_eq!(embedded_separator.split_once('?').unwrap().1.len(), 40);
    assert!(!authority.validate(CLIENT, &embedded_separator, 1_700_000_001));
}

#[test]
fn initial_new_with_empty_token_gets_asterisk_compatible_challenge() {
    let authority = CallTokenAuthority::new(42);
    let request = initial_new(&[InformationElement {
        kind: 54,
        data: &[],
    }]);

    let InitialNewDisposition::Challenge(response) = authority
        .handle_initial_new(CLIENT, &request, 1_700_000_000)
        .unwrap()
    else {
        panic!("empty token must be challenged");
    };
    let response = parse_full_frame_packet(&response).unwrap();
    assert_eq!(response.header.source_call_number, 1);
    assert_eq!(response.header.destination_call_number, 23);
    assert_eq!(response.header.timestamp, 400);
    assert_eq!(response.header.outgoing_sequence, 0);
    assert_eq!(response.header.incoming_sequence, 1);
    assert_eq!(response.header.frame_type, 6);
    assert_eq!(
        IaxCommand::CallToken.subclass_value(),
        i64::from(response.header.subclass)
    );
    let elements = parse_information_elements(response.payload).unwrap();
    assert_eq!(elements.len(), 1);
    assert_eq!(elements[0].kind, 54);
    assert_eq!(
        elements[0].data,
        b"1700000000?1ace7d876f3cfc56bc40248b15454273892633f9"
    );
}

#[test]
fn valid_source_bound_token_continues_without_response() {
    let authority = CallTokenAuthority::new(42);
    let token = authority.issue(CLIENT, 1_700_000_000);
    let request = initial_new(&[InformationElement {
        kind: 54,
        data: token.as_bytes(),
    }]);

    assert_eq!(
        authority
            .handle_initial_new(CLIENT, &request, 1_700_000_009)
            .unwrap(),
        InitialNewDisposition::Continue
    );
}

#[test]
fn invalid_or_absent_token_is_rejected_without_allocating_a_call() {
    let authority = CallTokenAuthority::new(42);
    let valid = authority.issue(CLIENT, 1_700_000_000);
    let invalid = initial_new(&[InformationElement {
        kind: 54,
        data: valid.replace("1ace", "0ace").as_bytes(),
    }]);
    let absent = initial_new(&[]);

    for request in [invalid, absent] {
        let InitialNewDisposition::Reject(response) = authority
            .handle_initial_new(CLIENT, &request, 1_700_000_001)
            .unwrap()
        else {
            panic!("invalid or missing token must be rejected");
        };
        let response = parse_full_frame_packet(&response).unwrap();
        assert_eq!(response.header.frame_type, 6);
        assert_eq!(
            response.header.subclass,
            IaxCommand::Reject.subclass_value() as u8
        );
        assert_eq!(response.header.source_call_number, 1);
        assert_eq!(response.header.destination_call_number, 23);
        assert!(response.payload.is_empty());
    }
}

#[test]
fn duplicate_calltoken_information_elements_are_rejected() {
    let authority = CallTokenAuthority::new(42);
    let request = initial_new(&[
        InformationElement {
            kind: 54,
            data: &[],
        },
        InformationElement {
            kind: 54,
            data: b"duplicate",
        },
    ]);

    let InitialNewDisposition::Reject(response) = authority
        .handle_initial_new(CLIENT, &request, 1_700_000_000)
        .unwrap()
    else {
        panic!("duplicate CALLTOKEN elements must be rejected");
    };
    let response = parse_full_frame_packet(&response).unwrap();
    assert_eq!(
        decode_iax_command(&response.header),
        Ok(Some(IaxCommand::Reject))
    );
    assert_eq!(response.header.destination_call_number, 23);
    assert!(response.payload.is_empty());
}

#[test]
fn malformed_and_non_initial_packets_do_not_enter_admission() {
    let authority = CallTokenAuthority::new(42);
    let malformed = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 23,
            retransmission: false,
            destination_call_number: 0,
            timestamp: 400,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 6,
            subclass: IaxCommand::New.subclass_value() as u8,
            subclass_is_log: false,
        },
        &[54],
    )
    .unwrap();
    let wrong_destination = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 23,
            retransmission: false,
            destination_call_number: 1,
            timestamp: 400,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 6,
            subclass: IaxCommand::New.subclass_value() as u8,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap();
    let not_new = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 23,
            retransmission: false,
            destination_call_number: 0,
            timestamp: 400,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 6,
            subclass: IaxCommand::Ping.subclass_value() as u8,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap();
    let zero_source = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 0,
            retransmission: false,
            destination_call_number: 0,
            timestamp: 400,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 6,
            subclass: IaxCommand::New.subclass_value() as u8,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap();

    assert!(
        authority
            .handle_initial_new(CLIENT, &[0; 2], 1_700_000_000)
            .is_err()
    );
    assert!(
        authority
            .handle_initial_new(CLIENT, &malformed, 1_700_000_000)
            .is_err()
    );
    assert!(
        authority
            .handle_initial_new(CLIENT, &wrong_destination, 1_700_000_000)
            .is_err()
    );
    assert!(
        authority
            .handle_initial_new(CLIENT, &not_new, 1_700_000_000)
            .is_err()
    );
    assert!(
        authority
            .handle_initial_new(CLIENT, &zero_source, 1_700_000_000)
            .is_err()
    );
    assert!(authority.reject_initial_new(&[0; 2]).is_err());
    assert!(authority.reject_initial_new(&not_new).is_err());
}

fn initial_new(elements: &[InformationElement<'_>]) -> Vec<u8> {
    let payload = crate::information_elements::serialize_information_elements(elements).unwrap();
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 23,
            retransmission: false,
            destination_call_number: 0,
            timestamp: 400,
            outgoing_sequence: 7,
            incoming_sequence: 0,
            frame_type: 6,
            subclass: IaxCommand::New.subclass_value() as u8,
            subclass_is_log: false,
        },
        &payload,
    )
    .unwrap()
}
