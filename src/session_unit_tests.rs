use super::*;
use crate::codec::IAX_FORMAT_ULAW;
use crate::information_elements::serialize_information_elements;

fn setup() -> OutboundCallSetup {
    let format = (IAX_FORMAT_ULAW as u32).to_be_bytes();
    OutboundCallSetup::new(
        1,
        0,
        &[
            InformationElement {
                kind: FORMAT_IE,
                data: &format,
            },
            InformationElement {
                kind: CAPABILITY_IE,
                data: &format,
            },
        ],
    )
    .unwrap()
}

#[test]
fn inbound_accept_creates_a_linked_session_with_server_sequence_state() {
    let mut session = OutboundCallSetup::for_inbound_call(42, 0x123).unwrap();

    let packet = session.send_dtmf(b'7', 25).unwrap();
    let frame = parse_full_frame_packet(&packet).unwrap();

    assert_eq!(frame.header.source_call_number, 42);
    assert_eq!(frame.header.destination_call_number, 0x123);
    assert_eq!(frame.header.outgoing_sequence, 1);
    assert_eq!(frame.header.incoming_sequence, 1);
    assert_eq!(frame.header.frame_type, 1);
    assert_eq!(frame.header.subclass, b'7');
}

#[test]
fn inbound_accept_rejects_unrepresentable_call_numbers() {
    assert!(OutboundCallSetup::for_inbound_call(0, 0x123).is_err());
    assert!(OutboundCallSetup::for_inbound_call(0x8000, 0x123).is_err());
    assert!(OutboundCallSetup::for_inbound_call(42, 0).is_err());
    assert!(OutboundCallSetup::for_inbound_call(42, 0x8000).is_err());
}

#[test]
fn send_dtmf_serializes_a_single_digit_as_a_full_frame() {
    let mut setup = setup();
    setup.receive(&accept_packet(), 1, "").unwrap();

    let packet = setup.send_dtmf(b'7', 25).unwrap();
    let frame = parse_full_frame_packet(&packet).unwrap();

    assert_eq!(frame.header.source_call_number, 1);
    assert_eq!(frame.header.destination_call_number, 77);
    assert_eq!(frame.header.timestamp, 25);
    assert_eq!(frame.header.outgoing_sequence, 1);
    assert_eq!(frame.header.incoming_sequence, 1);
    assert_eq!(frame.header.frame_type, 1);
    assert_eq!(frame.header.subclass, b'7');
    assert!(!frame.header.subclass_is_log);
    assert!(frame.payload.is_empty());
}

#[test]
fn send_dtmf_rejects_invalid_digits_and_unlinked_calls() {
    let mut setup = setup();
    assert_eq!(setup.send_dtmf(b'7', 25), Err(CallSetupError::NotLinked));
    setup.receive(&accept_packet(), 1, "").unwrap();
    assert_eq!(
        setup.send_dtmf(b'E', 25),
        Err(CallSetupError::InvalidDtmfDigit(b'E'))
    );
}

#[test]
fn send_voice_frame_rejects_unlinked_calls() {
    assert_eq!(
        setup().send_voice_frame(&[0xff], 25, IAX_FORMAT_ULAW),
        Err(CallSetupError::NotLinked)
    );
}

#[test]
fn linked_voice_rejects_unknown_formats_without_consuming_sequence() {
    let mut session = OutboundCallSetup::for_inbound_call(42, 123).unwrap();
    let sequence = session.next_outgoing;
    assert_eq!(
        session.send_voice_frame(&[0], 20, 1_u64 << 63),
        Err(CallSetupError::InvalidAcceptedFormat)
    );
    assert_eq!(session.next_outgoing, sequence);
}

fn accept_packet() -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 77,
            retransmission: false,
            destination_call_number: 1,
            timestamp: 0,
            outgoing_sequence: 0,
            incoming_sequence: 1,
            frame_type: IAX_FRAME_TYPE,
            subclass: IaxCommand::Accept.subclass_value() as u8,
            subclass_is_log: false,
        },
        &[FORMAT_IE, 4, 0, 0, 0, IAX_FORMAT_ULAW as u8],
    )
    .unwrap()
}

#[test]
fn public_receive_maps_setup_accept_and_linked_ack_responses() {
    let mut setup = setup();
    assert!(matches!(
        setup.receive(&accept_packet(), 1, ""),
        Ok(CallSetupResponse::Accepted {
            format: IAX_FORMAT_ULAW,
            ..
        })
    ));
    assert!(setup.is_linked());

    let acknowledgement = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 77,
            retransmission: false,
            destination_call_number: 1,
            timestamp: 0,
            outgoing_sequence: 0,
            incoming_sequence: 1,
            frame_type: IAX_FRAME_TYPE,
            subclass: ACK_SUBCLASS,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap();
    assert_eq!(
        setup.receive(&acknowledgement, 2, ""),
        Ok(CallSetupResponse::NoAction)
    );
}

#[test]
fn public_receive_maps_setup_ack_without_linking() {
    let mut call = setup();
    assert_eq!(
        call.receive(&control_frame(IaxCommand::Ack, 0, 1, 1), 1, ""),
        Ok(CallSetupResponse::NoAction)
    );
    assert!(!call.is_linked());
}

#[test]
fn public_receive_acknowledges_linked_answer() {
    let mut call = setup();
    call.receive(&accept_packet(), 1, "").unwrap();
    let answer = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 77,
            retransmission: false,
            destination_call_number: 1,
            timestamp: 2,
            outgoing_sequence: 1,
            incoming_sequence: 1,
            frame_type: 4,
            subclass: 4,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap();
    let CallSetupResponse::Send(acknowledgement) = call.receive(&answer, 2, "").unwrap() else {
        panic!("linked ANSWER must be acknowledged");
    };
    let ack = parse_full_frame_packet(&acknowledgement).unwrap();
    assert_eq!(decode_iax_command(&ack.header), Ok(Some(IaxCommand::Ack)));
    assert_eq!(ack.header.incoming_sequence, 2);
}

#[test]
fn public_receive_rejects_an_invalid_logged_iax_subclass() {
    let mut linked = setup();
    linked.receive(&accept_packet(), 1, "").unwrap();
    let invalid_subclass = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 77,
            retransmission: false,
            destination_call_number: 1,
            timestamp: 2,
            outgoing_sequence: 1,
            incoming_sequence: 2,
            frame_type: IAX_FRAME_TYPE,
            subclass: 64,
            subclass_is_log: true,
        },
        &[],
    )
    .unwrap();

    assert_eq!(
        linked.receive(&invalid_subclass, 2, ""),
        Err(CallSetupError::InvalidFrame)
    );
}

#[test]
fn public_receive_rejects_a_truncated_frame_after_linking() {
    let mut linked = setup();
    linked.receive(&accept_packet(), 1, "").unwrap();

    assert_eq!(
        linked.receive(&[0; 5], 2, ""),
        Err(CallSetupError::InvalidFrame)
    );
}

#[test]
fn public_receive_maps_all_setup_and_linked_response_kinds() {
    let methods = crate::authentication::AUTH_METHOD_MD5.to_be_bytes();
    let auth_payload = serialize_information_elements(&[
        InformationElement {
            kind: 14,
            data: &methods,
        },
        InformationElement {
            kind: 15,
            data: b"challenge",
        },
    ])
    .unwrap();
    let auth = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 77,
            retransmission: false,
            destination_call_number: 1,
            timestamp: 1,
            outgoing_sequence: 0,
            incoming_sequence: 1,
            frame_type: IAX_FRAME_TYPE,
            subclass: IaxCommand::AuthReq.subclass_value() as u8,
            subclass_is_log: false,
        },
        &auth_payload,
    )
    .unwrap();
    assert!(matches!(
        setup().receive(&auth, 1, "secret"),
        Ok(CallSetupResponse::Send(_))
    ));

    let rejected = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 77,
            retransmission: false,
            destination_call_number: 1,
            timestamp: 1,
            outgoing_sequence: 0,
            incoming_sequence: 1,
            frame_type: IAX_FRAME_TYPE,
            subclass: IaxCommand::Reject.subclass_value() as u8,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap();
    assert!(matches!(
        setup().receive(&rejected, 1, ""),
        Ok(CallSetupResponse::Rejected { .. })
    ));

    let mut linked = setup();
    linked.receive(&accept_packet(), 1, "").unwrap();
    let ping = control_frame(IaxCommand::Ping, 1, 1, 2);
    assert!(matches!(
        linked.receive(&ping, 2, ""),
        Ok(CallSetupResponse::Send(_))
    ));
    linked.send_ping(3).unwrap();
    let pong = control_frame(IaxCommand::Pong, 2, 3, 3);
    assert!(matches!(
        linked.receive(&pong, 3, ""),
        Ok(CallSetupResponse::PongAcknowledged {
            matched_probe: true,
            ..
        })
    ));

    let text = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 77,
            retransmission: false,
            destination_call_number: 1,
            timestamp: 4,
            outgoing_sequence: 3,
            incoming_sequence: 3,
            frame_type: 7,
            subclass: 0,
            subclass_is_log: false,
        },
        b"status",
    )
    .unwrap();
    assert!(matches!(
        linked.receive(&text, 4, ""),
        Ok(CallSetupResponse::Text { .. })
    ));
    let hangup = control_frame(IaxCommand::Hangup, 4, 3, 5);
    assert!(matches!(
        linked.receive(&hangup, 5, ""),
        Ok(CallSetupResponse::Ended { .. })
    ));
}

fn control_frame(command: IaxCommand, outgoing: u8, incoming: u8, timestamp: u32) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 77,
            retransmission: false,
            destination_call_number: 1,
            timestamp,
            outgoing_sequence: outgoing,
            incoming_sequence: incoming,
            frame_type: IAX_FRAME_TYPE,
            subclass: command.subclass_value() as u8,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap()
}

#[test]
fn delayed_retries_preserve_events_and_sequences_across_wraparound() {
    for first_sequence in [128_u8, 254] {
        for (frame_type, subclass, payload) in [
            (7, 0, &b"!KEY!"[..]),
            (1, b'7', &b""[..]),
            (4, 12, &b""[..]),
            (6, IaxCommand::Ping.subclass_value() as u8, &b""[..]),
            (6, IaxCommand::Pong.subclass_value() as u8, &b""[..]),
            (6, IaxCommand::LagRq.subclass_value() as u8, &b""[..]),
            (6, IaxCommand::LagRp.subclass_value() as u8, &b""[..]),
        ] {
            let mut session = OutboundCallSetup::for_inbound_call(1, 77).unwrap();
            session.next_incoming = first_sequence;
            let mut header = FullFrameHeader {
                source_call_number: 77,
                destination_call_number: 1,
                retransmission: false,
                timestamp: 28403,
                outgoing_sequence: first_sequence,
                incoming_sequence: 1,
                frame_type,
                subclass,
                subclass_is_log: false,
            };
            let initial = session
                .receive_linked(&serialize_full_frame(&header, payload).unwrap())
                .unwrap();
            header.retransmission = true;
            let retry = serialize_full_frame(&header, payload).unwrap();
            if let LinkedCallResponse::SendReliable(reply) = initial {
                let LinkedCallResponse::Send(repeated) = session.receive_linked(&retry).unwrap()
                else {
                    panic!("an immediate probe retry must replay its response");
                };
                assert_eq!(repeated, reply);
            }
            // Three accepted frames evict the response cache, including across
            // the 255 -> 0 boundary. None makes the original event new again.
            header.retransmission = false;
            header.frame_type = 7;
            header.subclass = 0;
            header.incoming_sequence = session.next_outgoing;
            for offset in 1..=3 {
                header.outgoing_sequence = first_sequence.wrapping_add(offset);
                assert!(matches!(
                    session.receive_linked(&serialize_full_frame(&header, b"L ").unwrap()),
                    Ok(LinkedCallResponse::Text { .. })
                ));
            }
            let LinkedCallResponse::Send(ack) = session.receive_linked(&retry).unwrap() else {
                panic!("an old retry must only acknowledge, never replay its event");
            };
            let ack = parse_full_frame_packet(&ack).unwrap().header;
            assert_eq!(decode_iax_command(&ack).unwrap(), Some(IaxCommand::Ack));
            assert_eq!(ack.incoming_sequence, first_sequence.wrapping_add(4));
            assert_eq!(ack.timestamp, 28403);
            header.outgoing_sequence = first_sequence.wrapping_add(4);
            assert!(matches!(
                session.receive_linked(&serialize_full_frame(&header, b"fresh").unwrap()),
                Ok(LinkedCallResponse::Text { .. })
            ));
        }
    }
}

#[test]
fn delayed_retry_window_preserves_validation_and_never_acknowledges_ack() {
    let mut session = OutboundCallSetup::for_inbound_call(1, 77).unwrap();
    session.next_incoming = 65;
    let header = FullFrameHeader {
        source_call_number: 77,
        destination_call_number: 1,
        retransmission: true,
        timestamp: 100,
        outgoing_sequence: 1,
        incoming_sequence: 1,
        frame_type: 7,
        subclass: 0,
        subclass_is_log: false,
    };
    // No cached response is needed for the oldest accepted retry in the window.
    let LinkedCallResponse::Send(ack) = session
        .receive_linked(&serialize_full_frame(&header, b"old").unwrap())
        .unwrap()
    else {
        panic!("the oldest retry in the window must be acknowledged");
    };
    assert_eq!(
        parse_full_frame_packet(&ack)
            .unwrap()
            .header
            .incoming_sequence,
        65
    );
    for (source, destination) in [(78, 1), (77, 2)] {
        let invalid = FullFrameHeader {
            source_call_number: source,
            destination_call_number: destination,
            ..header
        };
        assert!(
            session
                .receive_linked(&serialize_full_frame(&invalid, b"old").unwrap())
                .is_err()
        );
    }
    let ack = FullFrameHeader {
        frame_type: IAX_FRAME_TYPE,
        subclass: ACK_SUBCLASS,
        ..header
    };
    assert!(matches!(
        session.receive_linked(&serialize_full_frame(&ack, &[]).unwrap()),
        Ok(LinkedCallResponse::NoAction)
    ));
    assert_eq!(session.next_incoming, 65);
}
