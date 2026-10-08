use crate::authentication::AUTH_METHOD_MD5;
use crate::codec::IAX_FORMAT_ULAW;
use crate::information_elements::{InformationElement, serialize_information_elements};
use crate::protocol::{
    FullFrameHeader, IaxCommand, decode_iax_command, parse_full_frame_packet, serialize_full_frame,
};
use crate::session::{
    CallSetupError, CallSetupResponse, InboundNewError, OutboundCallSetup, accept_inbound_ulaw_new,
};

const LOCAL_CALL: u16 = 1;
const REMOTE_CALL: u16 = 77;
const OFFERED_FORMAT: u32 = IAX_FORMAT_ULAW;
const OFFERED_FORMAT_BYTES: [u8; 4] = OFFERED_FORMAT.to_be_bytes();

fn initial_elements() -> [InformationElement<'static>; 2] {
    [
        InformationElement {
            kind: 9,
            data: &OFFERED_FORMAT_BYTES,
        },
        InformationElement {
            kind: 1,
            data: b"555",
        },
    ]
}

#[test]
fn inbound_new_with_nonzero_incoming_sequence_is_not_initial() {
    let packet = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 77,
            retransmission: false,
            destination_call_number: 0,
            timestamp: 25,
            outgoing_sequence: 0,
            incoming_sequence: 1,
            frame_type: 6,
            subclass: IaxCommand::New.subclass_value() as u8,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap();

    assert_eq!(
        accept_inbound_ulaw_new(&packet, "524950", LOCAL_CALL),
        Err(InboundNewError::NotInitialNew)
    );
}

fn incoming(command: IaxCommand, outgoing: u8, incoming: u8, payload: &[u8]) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: REMOTE_CALL,
            retransmission: false,
            destination_call_number: LOCAL_CALL,
            timestamp: 25,
            outgoing_sequence: outgoing,
            incoming_sequence: incoming,
            frame_type: 6,
            subclass: command.subclass_value() as u8,
            subclass_is_log: false,
        },
        payload,
    )
    .unwrap()
}

fn incoming_text(outgoing: u8, incoming: u8, text: &[u8]) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: REMOTE_CALL,
            retransmission: false,
            destination_call_number: LOCAL_CALL,
            timestamp: 25,
            outgoing_sequence: outgoing,
            incoming_sequence: incoming,
            frame_type: 7,
            subclass: 0,
            subclass_is_log: false,
        },
        text,
    )
    .unwrap()
}

fn incoming_dtmf(outgoing: u8, incoming: u8, digit: u8) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: REMOTE_CALL,
            retransmission: false,
            destination_call_number: LOCAL_CALL,
            timestamp: 25,
            outgoing_sequence: outgoing,
            incoming_sequence: incoming,
            frame_type: 1,
            subclass: digit,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap()
}

fn incoming_radio_control(
    outgoing: u8,
    incoming: u8,
    subclass: u8,
    subclass_is_log: bool,
    payload: &[u8],
) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: REMOTE_CALL,
            retransmission: false,
            destination_call_number: LOCAL_CALL,
            timestamp: 25,
            outgoing_sequence: outgoing,
            incoming_sequence: incoming,
            frame_type: 4,
            subclass,
            subclass_is_log,
        },
        payload,
    )
    .unwrap()
}

fn reframe(packet: &[u8], payload: &[u8], update: impl FnOnce(&mut FullFrameHeader)) -> Vec<u8> {
    let mut header = parse_full_frame_packet(packet).unwrap().header;
    update(&mut header);
    serialize_full_frame(&header, payload).unwrap()
}

fn fixture(name: &str) -> Vec<u8> {
    let text = match name {
        "calltoken-response.hex" => include_str!("../tests/fixtures/iax2/calltoken-response.hex"),
        _ => panic!("unknown fixture"),
    };
    text.split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

#[test]
fn sequences_calltoken_authentication_and_accept_with_the_peer() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let initial = setup.initial_packet().to_vec();
    assert_eq!(
        decode_iax_command(&parse_full_frame_packet(&initial).unwrap().header),
        Ok(Some(IaxCommand::New))
    );

    let token_retry = setup
        .receive(&fixture("calltoken-response.hex"), 10, "secret")
        .unwrap();
    let CallSetupResponse::Send(new_retry) = token_retry else {
        panic!("CALLTOKEN should cause a NEW retry");
    };
    let retry = parse_full_frame_packet(&new_retry).unwrap();
    assert_eq!(decode_iax_command(&retry.header), Ok(Some(IaxCommand::New)));
    assert_eq!(retry.header.timestamp, 10);
    assert_eq!(retry.header.outgoing_sequence, 0);
    assert_eq!(retry.header.incoming_sequence, 0);

    let auth_payload = serialize_information_elements(&[
        InformationElement {
            kind: 14,
            data: &AUTH_METHOD_MD5.to_be_bytes(),
        },
        InformationElement {
            kind: 15,
            data: b"challenge",
        },
    ])
    .unwrap();
    let authreq = incoming(IaxCommand::AuthReq, 0, 1, &auth_payload);
    let response = setup.receive(&authreq, 20, "secret").unwrap();
    let CallSetupResponse::Send(authrep) = response else {
        panic!("AUTHREQ should cause AUTHREP");
    };
    let authrep_packet = authrep;
    let authrep = parse_full_frame_packet(&authrep_packet).unwrap();
    assert_eq!(
        decode_iax_command(&authrep.header),
        Ok(Some(IaxCommand::AuthRep))
    );
    assert_eq!(authrep.header.source_call_number, LOCAL_CALL);
    assert_eq!(authrep.header.destination_call_number, REMOTE_CALL);
    assert_eq!(
        (
            authrep.header.outgoing_sequence,
            authrep.header.incoming_sequence
        ),
        (1, 1)
    );
    assert_eq!(authrep.header.timestamp, 20);
    assert_eq!(&authrep.payload[2..], b"3956ed0865d1cd94c99f8e01c3988788");

    let mut repeated_authreq = authreq;
    repeated_authreq[2] |= 0x80;
    assert_eq!(
        setup.receive(&repeated_authreq, 21, "unused"),
        Ok(CallSetupResponse::Send(authrep_packet))
    );

    let accept_payload = serialize_information_elements(&[InformationElement {
        kind: 9,
        data: &OFFERED_FORMAT_BYTES,
    }])
    .unwrap();
    let accept = incoming(IaxCommand::Accept, 1, 2, &accept_payload);
    let response = setup.receive(&accept, 30, "secret").unwrap();
    let CallSetupResponse::Accepted {
        format,
        acknowledgement,
    } = response
    else {
        panic!("ACCEPT should link the call and produce an ACK");
    };
    assert_eq!(format, OFFERED_FORMAT);
    let ack = parse_full_frame_packet(&acknowledgement).unwrap();
    assert_eq!(decode_iax_command(&ack.header), Ok(Some(IaxCommand::Ack)));
    assert_eq!(ack.header.timestamp, 25);
    assert_eq!(ack.header.source_call_number, LOCAL_CALL);
    assert_eq!(ack.header.destination_call_number, REMOTE_CALL);
    assert_eq!(
        (ack.header.outgoing_sequence, ack.header.incoming_sequence),
        (2, 2)
    );
    let mut repeated_accept = accept;
    repeated_accept[2] |= 0x80;
    assert_eq!(
        setup.receive(&repeated_accept, 31, "unused"),
        Ok(CallSetupResponse::Send(acknowledgement))
    );
    assert!(setup.is_linked());
}

#[test]
fn accepts_an_unauthenticated_peer_directly_after_new() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let payload = serialize_information_elements(&[InformationElement {
        kind: 9,
        data: &OFFERED_FORMAT_BYTES,
    }])
    .unwrap();

    let response = setup
        .receive(&incoming(IaxCommand::Accept, 0, 1, &payload), 10, "unused")
        .unwrap();

    assert!(matches!(
        response,
        CallSetupResponse::Accepted {
            format: OFFERED_FORMAT,
            ..
        }
    ));
}

#[test]
fn rejects_link_only_operations_before_acceptance() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();

    assert!(matches!(
        setup.send_ping(10),
        Err(CallSetupError::UnexpectedCommand {
            command: IaxCommand::Ping
        })
    ));
    assert!(matches!(
        setup.send_text_frame(b"status", 10),
        Err(CallSetupError::CallFinished)
    ));
    assert!(matches!(
        setup.send_hangup(10),
        Err(CallSetupError::CallFinished)
    ));
    assert!(matches!(
        setup.receive(&incoming_text(0, 1, b"!KEY! 1000 2000 1"), 10, ""),
        Err(CallSetupError::NotLinked)
    ));
}

#[test]
fn linked_session_rejects_media_control_and_calltoken_frames() {
    let accept_payload = serialize_information_elements(&[InformationElement {
        kind: 9,
        data: &OFFERED_FORMAT_BYTES,
    }])
    .unwrap();
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    setup
        .receive(
            &incoming(IaxCommand::Accept, 0, 1, &accept_payload),
            10,
            "unused",
        )
        .unwrap();
    let media = reframe(
        &incoming(IaxCommand::Accept, 0, 1, &accept_payload),
        &[],
        |header| header.frame_type = 2,
    );
    assert_eq!(
        setup.receive(&media, 20, ""),
        Err(CallSetupError::NotIaxFrame { frame_type: 2 })
    );

    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    setup
        .receive(
            &incoming(IaxCommand::Accept, 0, 1, &accept_payload),
            10,
            "unused",
        )
        .unwrap();
    let calltoken = incoming(IaxCommand::CallToken, 0, 1, &[]);
    assert_eq!(
        setup.receive(&calltoken, 20, ""),
        Err(CallSetupError::UnexpectedCommand {
            command: IaxCommand::CallToken
        })
    );
}

#[test]
fn linked_session_rejects_malformed_text_frame() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let payload = serialize_information_elements(&[InformationElement {
        kind: 9,
        data: &OFFERED_FORMAT_BYTES,
    }])
    .unwrap();
    setup
        .receive(&incoming(IaxCommand::Accept, 0, 1, &payload), 10, "unused")
        .unwrap();

    let malformed = incoming_text(1, 1, &[0xff]);
    assert!(matches!(
        setup.receive(&malformed, 20, ""),
        Err(CallSetupError::InvalidFrame)
    ));
}

#[test]
fn linked_session_replays_ack_for_duplicate_text() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let accepted = incoming(
        IaxCommand::Accept,
        0,
        1,
        &serialize_information_elements(&[InformationElement {
            kind: 9,
            data: &OFFERED_FORMAT_BYTES,
        }])
        .unwrap(),
    );
    assert!(matches!(
        setup.receive(&accepted, 1, ""),
        Ok(CallSetupResponse::Accepted { .. })
    ));

    let text = incoming_text(1, 1, b"!KEY! 555 1");
    let CallSetupResponse::Text {
        acknowledgement, ..
    } = setup.receive(&text, 2, "").unwrap()
    else {
        panic!("new linked text should be delivered");
    };

    let mut retransmission = text;
    retransmission[2] |= 0x80;
    assert_eq!(
        setup.receive(&retransmission, 3, ""),
        Ok(CallSetupResponse::Send(acknowledgement))
    );
}

#[test]
fn linked_session_acknowledges_and_delivers_remote_dtmf() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let accepted = incoming(
        IaxCommand::Accept,
        0,
        1,
        &serialize_information_elements(&[InformationElement {
            kind: 9,
            data: &OFFERED_FORMAT_BYTES,
        }])
        .unwrap(),
    );
    assert!(matches!(
        setup.receive(&accepted, 1, ""),
        Ok(CallSetupResponse::Accepted { .. })
    ));

    let dtmf = incoming_dtmf(1, 1, b'*');
    let CallSetupResponse::Digit {
        digit,
        acknowledgement,
    } = setup.receive(&dtmf, 2, "").unwrap()
    else {
        panic!("a linked DTMF frame should be acknowledged and delivered");
    };
    assert_eq!(digit, b'*');
    let ack = parse_full_frame_packet(&acknowledgement).unwrap();
    assert_eq!(decode_iax_command(&ack.header), Ok(Some(IaxCommand::Ack)));
    assert_eq!(ack.header.outgoing_sequence, 1);
    assert_eq!(ack.header.incoming_sequence, 2);

    let mut retransmission = dtmf;
    retransmission[2] |= 0x80;
    assert_eq!(
        setup.receive(&retransmission, 3, ""),
        Ok(CallSetupResponse::Send(acknowledgement))
    );
}

#[test]
fn duplicate_cache_does_not_match_different_frame_type_or_digit() {
    let accept = incoming(
        IaxCommand::Accept,
        0,
        1,
        &serialize_information_elements(&[InformationElement {
            kind: 9,
            data: &OFFERED_FORMAT_BYTES,
        }])
        .unwrap(),
    );
    let mut text_then_digit = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    text_then_digit.receive(&accept, 1, "").unwrap();
    text_then_digit
        .receive(&incoming_text(1, 1, b""), 2, "")
        .unwrap();
    let mut different_frame = incoming_dtmf(1, 1, b'7');
    different_frame[2] |= 0x80;
    assert!(matches!(
        text_then_digit.receive(&different_frame, 3, ""),
        Err(CallSetupError::SequenceMismatch { .. })
    ));

    let mut digit_then_other_digit =
        OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    digit_then_other_digit.receive(&accept, 1, "").unwrap();
    digit_then_other_digit
        .receive(&incoming_dtmf(1, 1, b'7'), 2, "")
        .unwrap();
    let mut different_subclass = incoming_dtmf(1, 1, b'8');
    different_subclass[2] |= 0x80;
    assert!(matches!(
        digit_then_other_digit.receive(&different_subclass, 3, ""),
        Err(CallSetupError::SequenceMismatch { .. })
    ));
}

#[test]
fn linked_session_rejects_invalid_remote_dtmf_digit() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let accepted = incoming(
        IaxCommand::Accept,
        0,
        1,
        &serialize_information_elements(&[InformationElement {
            kind: 9,
            data: &OFFERED_FORMAT_BYTES,
        }])
        .unwrap(),
    );
    setup.receive(&accepted, 1, "").unwrap();

    assert_eq!(
        setup.receive(&incoming_dtmf(1, 1, b'Z'), 2, ""),
        Err(CallSetupError::InvalidDtmfDigit(b'Z'))
    );
}

#[test]
fn linked_radio_key_unkey_are_mapped_and_duplicates_are_acknowledged() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let accepted = incoming(
        IaxCommand::Accept,
        0,
        1,
        &serialize_information_elements(&[InformationElement {
            kind: 9,
            data: &OFFERED_FORMAT_BYTES,
        }])
        .unwrap(),
    );
    setup.receive(&accepted, 1, "").unwrap();

    let key = incoming_radio_control(1, 1, 12, false, &[]);
    let CallSetupResponse::RadioKey {
        acknowledgement: key_ack,
    } = setup.receive(&key, 2, "").unwrap()
    else {
        panic!("radio key must be delivered as an edge event");
    };
    let mut duplicate = key;
    duplicate[2] |= 0x80;
    assert_eq!(
        setup.receive(&duplicate, 3, ""),
        Ok(CallSetupResponse::Send(key_ack))
    );

    assert!(matches!(
        setup.receive(&incoming_radio_control(2, 1, 13, false, &[]), 4, ""),
        Ok(CallSetupResponse::RadioUnkey { .. })
    ));
    assert!(matches!(
        setup.receive(&incoming_radio_control(3, 1, 99, false, &[]), 5, ""),
        Ok(CallSetupResponse::Send(_))
    ));
    assert_eq!(
        setup.receive(&incoming_radio_control(4, 1, 64, true, &[]), 6, ""),
        Err(CallSetupError::InvalidFrame)
    );
}

#[test]
fn linked_radio_and_dtmf_controls_reject_payloads() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let accepted = incoming(
        IaxCommand::Accept,
        0,
        1,
        &serialize_information_elements(&[InformationElement {
            kind: 9,
            data: &OFFERED_FORMAT_BYTES,
        }])
        .unwrap(),
    );
    setup.receive(&accepted, 1, "").unwrap();

    assert_eq!(
        setup.receive(
            &incoming_radio_control(1, 1, 12, false, b"unexpected"),
            2,
            ""
        ),
        Err(CallSetupError::InvalidFrame)
    );
    let dtmf = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: REMOTE_CALL,
            retransmission: false,
            destination_call_number: LOCAL_CALL,
            timestamp: 25,
            outgoing_sequence: 1,
            incoming_sequence: 1,
            frame_type: 1,
            subclass: b'5',
            subclass_is_log: false,
        },
        b"unexpected",
    )
    .unwrap();
    assert_eq!(
        setup.receive(&dtmf, 3, ""),
        Err(CallSetupError::InvalidFrame)
    );
}

#[test]
fn acknowledges_remote_hangup_and_marks_the_call_ended() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let payload = serialize_information_elements(&[InformationElement {
        kind: 9,
        data: &OFFERED_FORMAT_BYTES,
    }])
    .unwrap();
    setup
        .receive(&incoming(IaxCommand::Accept, 0, 1, &payload), 10, "unused")
        .unwrap();

    let response = setup.receive(&incoming(IaxCommand::Hangup, 1, 1, &[]), 20, "unused");
    assert!(
        response.is_ok(),
        "a linked peer's hangup should be acknowledged"
    );
    let CallSetupResponse::Ended { acknowledgement } = response.unwrap() else {
        panic!("remote hangup should produce an ACK");
    };
    let ack = parse_full_frame_packet(&acknowledgement).unwrap();
    assert_eq!(decode_iax_command(&ack.header), Ok(Some(IaxCommand::Ack)));
    assert_eq!(ack.header.source_call_number, LOCAL_CALL);
    assert_eq!(ack.header.destination_call_number, REMOTE_CALL);
    assert!(!setup.is_linked());
}

#[test]
fn sends_local_hangup_and_marks_the_call_ended() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let payload = serialize_information_elements(&[InformationElement {
        kind: 9,
        data: &OFFERED_FORMAT_BYTES,
    }])
    .unwrap();
    setup
        .receive(&incoming(IaxCommand::Accept, 0, 1, &payload), 10, "unused")
        .unwrap();

    let packet = setup.send_hangup(20).unwrap();
    let frame = parse_full_frame_packet(&packet).unwrap();
    assert_eq!(
        decode_iax_command(&frame.header),
        Ok(Some(IaxCommand::Hangup))
    );
    assert_eq!(frame.header.source_call_number, LOCAL_CALL);
    assert_eq!(frame.header.destination_call_number, REMOTE_CALL);
    assert_eq!(frame.header.outgoing_sequence, 1);
    assert_eq!(frame.header.incoming_sequence, 1);
    assert!(!setup.is_linked());
    assert_eq!(setup.send_hangup(21), Err(CallSetupError::CallFinished));
}

#[test]
fn sends_asl_text_as_a_sequenced_full_text_frame_after_accept() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let payload = serialize_information_elements(&[InformationElement {
        kind: 9,
        data: &OFFERED_FORMAT_BYTES,
    }])
    .unwrap();
    setup
        .receive(&incoming(IaxCommand::Accept, 0, 1, &payload), 10, "unused")
        .unwrap();

    let packet = setup.send_text_frame(b"!NEWKEY1!", 20).unwrap();
    let frame = parse_full_frame_packet(&packet).unwrap();
    assert_eq!(frame.header.frame_type, 7);
    assert_eq!(frame.header.subclass, 0);
    assert_eq!(frame.header.source_call_number, LOCAL_CALL);
    assert_eq!(frame.header.destination_call_number, REMOTE_CALL);
    assert_eq!(
        (
            frame.header.outgoing_sequence,
            frame.header.incoming_sequence
        ),
        (1, 1)
    );
    assert_eq!(frame.header.timestamp, 20);
    assert_eq!(frame.payload, b"!NEWKEY1!");
}

#[test]
fn receives_asl_text_and_acknowledges_the_reliable_frame() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let payload = serialize_information_elements(&[InformationElement {
        kind: 9,
        data: &OFFERED_FORMAT_BYTES,
    }])
    .unwrap();
    setup
        .receive(&incoming(IaxCommand::Accept, 0, 1, &payload), 10, "unused")
        .unwrap();

    let response = setup.receive(&incoming_text(1, 1, b"!KEY! 506315 524950 1"), 20, "unused");
    assert!(
        response.is_ok(),
        "a linked peer's text frame should be accepted"
    );
    assert!(setup.is_linked());
}

#[test]
fn accepts_any_format_advertised_in_new_capability() {
    const CAPABILITY_BYTES: [u8; 4] = 12_u32.to_be_bytes();
    const OTHER_FORMAT_BYTES: [u8; 4] = 8_u32.to_be_bytes();
    let elements = [
        InformationElement {
            kind: 9,
            data: &OFFERED_FORMAT_BYTES,
        },
        InformationElement {
            kind: 8,
            data: &CAPABILITY_BYTES,
        },
    ];
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &elements).unwrap();
    let payload = serialize_information_elements(&[InformationElement {
        kind: 9,
        data: &OTHER_FORMAT_BYTES,
    }])
    .unwrap();

    let response = setup
        .receive(&incoming(IaxCommand::Accept, 0, 1, &payload), 10, "unused")
        .unwrap();

    assert!(matches!(
        response,
        CallSetupResponse::Accepted { format: 8, .. }
    ));
}

#[test]
fn rejects_authentication_and_acceptance_that_do_not_match_the_setup() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    assert_eq!(
        setup.receive(&[0; 12], 1, "secret"),
        Err(CallSetupError::InvalidFrame)
    );

    let unsupported = serialize_information_elements(&[
        InformationElement {
            kind: 14,
            data: &1_u16.to_be_bytes(),
        },
        InformationElement {
            kind: 15,
            data: b"challenge",
        },
    ])
    .unwrap();
    assert_eq!(
        setup.receive(
            &incoming(IaxCommand::AuthReq, 0, 1, &unsupported),
            1,
            "secret"
        ),
        Err(CallSetupError::UnsupportedAuthentication)
    );

    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let unoffered = serialize_information_elements(&[InformationElement {
        kind: 9,
        data: &8_u32.to_be_bytes(),
    }])
    .unwrap();
    assert_eq!(
        setup.receive(&incoming(IaxCommand::Accept, 0, 1, &unoffered), 1, "secret"),
        Err(CallSetupError::UnacceptedFormat { format: 8 })
    );

    let mut wrong_sequence = incoming(IaxCommand::Accept, 1, 1, &[]);
    wrong_sequence[9] = 0;
    assert!(matches!(
        setup.receive(&wrong_sequence, 1, "secret"),
        Err(CallSetupError::SequenceMismatch { .. })
    ));

    let mut wrong_call = incoming(IaxCommand::Accept, 1, 2, &[]);
    wrong_call[3] = 2;
    assert_eq!(
        setup.receive(&wrong_call, 1, "secret"),
        Err(CallSetupError::WrongDestinationCall { actual: 2 })
    );
}

#[test]
fn reports_invalid_calltoken_exchange_without_changing_setup_state() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    assert_eq!(
        setup.receive(&[0; 12], 1, "secret"),
        Err(CallSetupError::InvalidFrame)
    );
    assert!(!setup.is_linked());
}

#[test]
fn rejects_calltoken_retry_after_authentication_has_started() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let auth_payload = serialize_information_elements(&[
        InformationElement {
            kind: 14,
            data: &AUTH_METHOD_MD5.to_be_bytes(),
        },
        InformationElement {
            kind: 15,
            data: b"challenge",
        },
    ])
    .unwrap();
    setup
        .receive(
            &incoming(IaxCommand::AuthReq, 0, 1, &auth_payload),
            10,
            "secret",
        )
        .unwrap();

    assert_eq!(
        setup.receive(&incoming(IaxCommand::CallToken, 1, 1, &[]), 11, "secret"),
        Err(CallSetupError::UnexpectedCommand {
            command: IaxCommand::CallToken
        })
    );
}

#[test]
fn validates_each_peer_sequence_field_and_duplicate_identity() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let auth_payload = serialize_information_elements(&[
        InformationElement {
            kind: 14,
            data: &AUTH_METHOD_MD5.to_be_bytes(),
        },
        InformationElement {
            kind: 15,
            data: b"challenge",
        },
    ])
    .unwrap();
    let authreq = incoming(IaxCommand::AuthReq, 0, 1, &auth_payload);
    setup.receive(&authreq, 10, "secret").unwrap();

    let mut not_retransmitted = parse_full_frame_packet(&authreq).unwrap().header;
    not_retransmitted.retransmission = false;
    assert!(matches!(
        setup.receive(
            &serialize_full_frame(&not_retransmitted, &auth_payload).unwrap(),
            11,
            "secret"
        ),
        Err(CallSetupError::SequenceMismatch { .. })
    ));

    for (source_call, destination_call, outgoing_sequence, payload) in [
        (REMOTE_CALL, 2, 0, auth_payload.as_slice()),
        (REMOTE_CALL + 1, LOCAL_CALL, 0, auth_payload.as_slice()),
        (REMOTE_CALL, LOCAL_CALL, 1, auth_payload.as_slice()),
        (REMOTE_CALL, LOCAL_CALL, 0, &[1, 0][..]),
    ] {
        let packet = reframe(&authreq, payload, |header| {
            header.retransmission = true;
            header.source_call_number = source_call;
            header.destination_call_number = destination_call;
            header.outgoing_sequence = outgoing_sequence;
            header.incoming_sequence = if outgoing_sequence == 1 { 2 } else { 1 };
        });
        assert!(setup.receive(&packet, 11, "secret").is_err());
    }

    let different_command = reframe(&authreq, &auth_payload, |header| {
        header.retransmission = true;
        header.subclass = IaxCommand::Accept.subclass_value() as u8;
    });
    assert!(matches!(
        setup.receive(&different_command, 11, "secret"),
        Err(CallSetupError::SequenceMismatch { .. })
    ));

    let second_authreq = incoming(IaxCommand::AuthReq, 1, 2, &auth_payload);
    assert_eq!(
        setup.receive(&second_authreq, 11, "secret"),
        Err(CallSetupError::UnexpectedCommand {
            command: IaxCommand::AuthReq
        })
    );

    let accept_payload = serialize_information_elements(&[InformationElement {
        kind: 9,
        data: &OFFERED_FORMAT_BYTES,
    }])
    .unwrap();
    let repeated_accept = reframe(
        &incoming(IaxCommand::Accept, 1, 2, &accept_payload),
        &accept_payload,
        |header| header.retransmission = true,
    );
    assert!(matches!(
        setup.receive(&repeated_accept, 11, "secret"),
        Ok(CallSetupResponse::Accepted { .. })
    ));
}

#[test]
fn validates_both_incoming_and_outgoing_sequence_numbers() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    assert!(matches!(
        setup.receive(&incoming(IaxCommand::Accept, 0, 0, &[]), 1, "secret"),
        Err(CallSetupError::SequenceMismatch { .. })
    ));
}

#[test]
fn established_session_answers_peer_ping_with_timestamp_echoing_pong() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let accept_payload = serialize_information_elements(&[InformationElement {
        kind: 9,
        data: &OFFERED_FORMAT_BYTES,
    }])
    .unwrap();
    setup
        .receive(
            &incoming(IaxCommand::Accept, 0, 1, &accept_payload),
            10,
            "unused",
        )
        .unwrap();

    let ping = incoming(IaxCommand::Ping, 1, 1, &[]);
    let response = setup.receive(&ping, 20, "unused").unwrap();
    let CallSetupResponse::Send(pong) = response else {
        panic!("a PING must be answered with PONG");
    };
    let pong = parse_full_frame_packet(&pong).unwrap();
    assert_eq!(decode_iax_command(&pong.header), Ok(Some(IaxCommand::Pong)));
    assert_eq!(pong.header.timestamp, 25);
    assert_eq!(pong.header.outgoing_sequence, 1);
    assert_eq!(pong.header.incoming_sequence, 2);

    let mut retry = ping;
    retry[2] |= 0x80;
    assert_eq!(
        setup.receive(&retry, 21, "unused"),
        Ok(CallSetupResponse::Send(pong_packet(&pong.header, &[])))
    );
}

#[test]
fn established_session_pings_and_acknowledges_only_matching_pong() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let accept_payload = serialize_information_elements(&[InformationElement {
        kind: 9,
        data: &OFFERED_FORMAT_BYTES,
    }])
    .unwrap();
    setup
        .receive(
            &incoming(IaxCommand::Accept, 0, 1, &accept_payload),
            10,
            "unused",
        )
        .unwrap();

    let ping = setup.send_ping(40).unwrap();
    let ping_frame = parse_full_frame_packet(&ping).unwrap();
    assert_eq!(
        decode_iax_command(&ping_frame.header),
        Ok(Some(IaxCommand::Ping))
    );
    assert_eq!(ping_frame.header.timestamp, 40);
    assert_eq!(
        (
            ping_frame.header.outgoing_sequence,
            ping_frame.header.incoming_sequence
        ),
        (1, 1)
    );
    assert_eq!(setup.send_ping(50), Err(CallSetupError::PingPending));

    let wrong_timestamp = reframe(&incoming(IaxCommand::Pong, 1, 2, &[]), &[], |header| {
        header.timestamp = 41
    });
    let response = setup.receive(&wrong_timestamp, 50, "unused").unwrap();
    let CallSetupResponse::PongAcknowledged {
        acknowledgement: wrong_ack,
        matched_probe: false,
    } = response
    else {
        panic!("a valid PONG must be acknowledged without matching the probe");
    };
    let wrong_ack = parse_full_frame_packet(&wrong_ack).unwrap();
    assert_eq!(
        decode_iax_command(&wrong_ack.header),
        Ok(Some(IaxCommand::Ack))
    );
    assert_eq!(wrong_ack.header.timestamp, 41);
    assert_eq!(
        (
            wrong_ack.header.outgoing_sequence,
            wrong_ack.header.incoming_sequence
        ),
        (2, 2)
    );

    let pong = reframe(&wrong_timestamp, &[], |header| {
        header.outgoing_sequence = 2;
        header.timestamp = 40;
    });
    let response = setup.receive(&pong, 51, "unused").unwrap();
    let CallSetupResponse::PongAcknowledged {
        acknowledgement,
        matched_probe: true,
    } = response
    else {
        panic!("a PONG must be acknowledged");
    };
    let ack = parse_full_frame_packet(&acknowledgement).unwrap();
    assert_eq!(decode_iax_command(&ack.header), Ok(Some(IaxCommand::Ack)));
    assert_eq!(ack.header.timestamp, 40);
    assert_eq!(
        (ack.header.outgoing_sequence, ack.header.incoming_sequence),
        (2, 3)
    );

    let mut retry = pong;
    retry[2] |= 0x80;
    assert_eq!(
        setup.receive(&retry, 52, "unused"),
        Ok(CallSetupResponse::Send(acknowledgement))
    );
    let response = setup
        .receive(&incoming(IaxCommand::Pong, 3, 2, &[]), 53, "unused")
        .unwrap();
    let CallSetupResponse::PongAcknowledged {
        acknowledgement,
        matched_probe: false,
    } = response
    else {
        panic!("an unsolicited PONG must be acknowledged but not match a probe");
    };
    let ack = parse_full_frame_packet(&acknowledgement).unwrap();
    assert_eq!(decode_iax_command(&ack.header), Ok(Some(IaxCommand::Ack)));
}

#[test]
fn established_session_ignores_ack_without_advancing_sequence_state() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let accept_payload = serialize_information_elements(&[InformationElement {
        kind: 9,
        data: &OFFERED_FORMAT_BYTES,
    }])
    .unwrap();
    setup
        .receive(
            &incoming(IaxCommand::Accept, 0, 1, &accept_payload),
            10,
            "unused",
        )
        .unwrap();

    let ping = incoming(IaxCommand::Ping, 1, 1, &[]);
    let response = setup.receive(&ping, 20, "unused").unwrap();
    let CallSetupResponse::Send(pong) = response else {
        panic!("a PING must be answered with PONG");
    };
    let pong = parse_full_frame_packet(&pong).unwrap();
    let acknowledgement = reframe(&incoming(IaxCommand::Ack, 1, 2, &[]), &[], |header| {
        header.timestamp = pong.header.timestamp;
    });

    assert_eq!(
        setup.receive(&acknowledgement, 21, "unused"),
        Ok(CallSetupResponse::NoAction)
    );
    let response = setup
        .receive(&incoming(IaxCommand::Ping, 2, 2, &[]), 22, "unused")
        .unwrap();
    let CallSetupResponse::Send(next_pong) = response else {
        panic!("the next PING must be answered");
    };
    let next_pong = parse_full_frame_packet(&next_pong).unwrap();
    assert_eq!(
        decode_iax_command(&next_pong.header),
        Ok(Some(IaxCommand::Pong))
    );
    assert_eq!(
        (
            next_pong.header.outgoing_sequence,
            next_pong.header.incoming_sequence
        ),
        (2, 3)
    );
}

#[test]
fn cannot_send_keepalive_before_the_call_is_linked() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    assert_eq!(
        setup.send_ping(40),
        Err(CallSetupError::UnexpectedCommand {
            command: IaxCommand::Ping,
        })
    );
}

#[test]
fn linked_session_rejects_a_second_accept_without_losing_link_state() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let accept_payload = serialize_information_elements(&[InformationElement {
        kind: 9,
        data: &OFFERED_FORMAT_BYTES,
    }])
    .unwrap();
    setup
        .receive(
            &incoming(IaxCommand::Accept, 0, 1, &accept_payload),
            10,
            "unused",
        )
        .unwrap();

    assert_eq!(
        setup.receive(&incoming(IaxCommand::Accept, 1, 1, &[]), 20, "unused"),
        Err(CallSetupError::UnexpectedCommand {
            command: IaxCommand::Accept,
        })
    );
    assert!(matches!(
        setup.receive(&incoming(IaxCommand::Ping, 1, 1, &[]), 21, "unused"),
        Ok(CallSetupResponse::Send(_))
    ));
}

fn pong_packet(header: &FullFrameHeader, payload: &[u8]) -> Vec<u8> {
    serialize_full_frame(header, payload).unwrap()
}

#[test]
fn validates_peer_frame_identity_and_setup_commands() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let mut not_iax = incoming(IaxCommand::Accept, 0, 1, &[]);
    not_iax[10] = 2;
    assert_eq!(
        setup.receive(&not_iax, 1, "secret"),
        Err(CallSetupError::NotIaxFrame { frame_type: 2 })
    );

    let mut bad_subclass = incoming(IaxCommand::Accept, 0, 1, &[]);
    bad_subclass[11] = 0xc0;
    assert_eq!(
        setup.receive(&bad_subclass, 1, "secret"),
        Err(CallSetupError::InvalidFrame)
    );

    assert!(matches!(
        setup.receive(&incoming(IaxCommand::Ping, 0, 1, &[]), 1, "secret"),
        Err(CallSetupError::UnexpectedCommand {
            command: IaxCommand::Ping
        })
    ));

    let mut zero_source = incoming(IaxCommand::Accept, 0, 1, &[]);
    zero_source[0] = 0x80;
    zero_source[1] = 0;
    assert_eq!(
        setup.receive(&zero_source, 1, "secret"),
        Err(CallSetupError::WrongSourceCall { actual: 0 })
    );
}

#[test]
fn acknowledges_reject_and_returns_the_same_ack_for_its_retransmission() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let reject = incoming(IaxCommand::Reject, 0, 1, &[1, 1, b'x']);
    let response = setup.receive(&reject, 1, "secret").unwrap();
    let CallSetupResponse::Rejected { acknowledgement } = response else {
        panic!("REJECT should be acknowledged");
    };
    let ack = parse_full_frame_packet(&acknowledgement).unwrap();
    assert_eq!(decode_iax_command(&ack.header), Ok(Some(IaxCommand::Ack)));
    assert_eq!(
        (ack.header.outgoing_sequence, ack.header.incoming_sequence),
        (1, 1)
    );

    let mut retry = reject;
    retry[2] |= 0x80;
    assert_eq!(
        setup.receive(&retry, 2, "unused"),
        Ok(CallSetupResponse::Send(acknowledgement))
    );
    assert_eq!(
        setup.receive(&incoming(IaxCommand::Ping, 1, 1, &[]), 2, "secret"),
        Err(CallSetupError::CallFinished)
    );
}

#[test]
fn rejects_incomplete_or_malformed_format_advertisements() {
    assert_eq!(
        OutboundCallSetup::new(LOCAL_CALL, 0, &[]).map(|_| ()),
        Err(CallSetupError::InitialFormat)
    );
    for data in [&[0, 0, 0][..], &[0, 0, 0, 0][..]] {
        let elements = [InformationElement { kind: 9, data }];
        assert_eq!(
            OutboundCallSetup::new(LOCAL_CALL, 0, &elements).map(|_| ()),
            Err(CallSetupError::InitialFormat)
        );
    }
    let elements = [
        InformationElement {
            kind: 9,
            data: &OFFERED_FORMAT_BYTES,
        },
        InformationElement {
            kind: 8,
            data: &[0, 0],
        },
    ];
    assert_eq!(
        OutboundCallSetup::new(LOCAL_CALL, 0, &elements).map(|_| ()),
        Err(CallSetupError::InitialCapability)
    );
    let elements = [
        InformationElement {
            kind: 9,
            data: &OFFERED_FORMAT_BYTES,
        },
        InformationElement {
            kind: 8,
            data: &[0, 0, 0, 0],
        },
    ];
    assert_eq!(
        OutboundCallSetup::new(LOCAL_CALL, 0, &elements).map(|_| ()),
        Err(CallSetupError::InitialCapability)
    );
    assert!(matches!(
        OutboundCallSetup::new(0x8000, 0, &initial_elements()),
        Err(CallSetupError::InitialNew(_))
    ));
}

#[test]
fn rejects_malformed_or_zero_accept_format_and_md5_authreq() {
    let mut setup = OutboundCallSetup::new(LOCAL_CALL, 0, &initial_elements()).unwrap();
    let malformed_format = incoming(IaxCommand::Accept, 0, 1, &[9, 3, 0, 0, 4]);
    assert_eq!(
        setup.receive(&malformed_format, 1, "secret"),
        Err(CallSetupError::InvalidAcceptedFormat)
    );
    let no_format = incoming(IaxCommand::Accept, 0, 1, &[1, 0]);
    assert_eq!(
        setup.receive(&no_format, 1, "secret"),
        Err(CallSetupError::InvalidAcceptedFormat)
    );
    let zero_format = incoming(IaxCommand::Accept, 0, 1, &[9, 4, 0, 0, 0, 0]);
    assert_eq!(
        setup.receive(&zero_format, 1, "secret"),
        Err(CallSetupError::UnacceptedFormat { format: 0 })
    );
    assert!(matches!(
        setup.receive(
            &incoming(IaxCommand::AuthReq, 0, 1, &[14, 1, 2]),
            1,
            "secret"
        ),
        Err(CallSetupError::Authentication(_))
    ));
}
