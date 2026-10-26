use super::*;

fn media(sequence: u8) -> FullFrameHeader {
    FullFrameHeader {
        source_call_number: 5678,
        retransmission: false,
        destination_call_number: 1234,
        timestamp: u32::from(sequence) * 20,
        outgoing_sequence: sequence,
        incoming_sequence: 1,
        frame_type: 2,
        subclass: 4,
        subclass_is_log: false,
    }
}

#[test]
fn late_linked_control_is_acked_without_replaying_events_or_closing_the_call() {
    for (next, late, following) in [
        (12, 9, 13),
        (12, 204, 13),
        (12, 141, 13),
        (1, 254, 2),
        (0, 129, 1),
    ] {
        for retransmission in [false, true] {
            for (frame_type, subclass) in [
                (1, b'7'),
                (4, 12),
                (4, 13),
                (6, 2),
                (6, 3),
                (6, 5),
                (6, 11),
                (6, 12),
                (7, 0),
            ] {
                let mut session = OutboundCallSetup::for_inbound_call(1234, 5678).unwrap();
                session.next_incoming = next;
                session.next_outgoing = 11;
                let header = FullFrameHeader {
                    outgoing_sequence: late,
                    incoming_sequence: 9,
                    frame_type,
                    subclass,
                    retransmission,
                    ..media(late)
                };
                let payload = if frame_type == 7 {
                    b"L T2002".as_slice()
                } else {
                    &[]
                };
                let packet = serialize_full_frame(&header, payload).unwrap();
                let LinkedCallResponse::Send(ack) = session.receive_linked(&packet).unwrap() else {
                    panic!("late control must only be acknowledged");
                };
                let ack = parse_full_frame_packet(&ack).unwrap();
                assert_eq!(decode_iax_command(&ack.header), Ok(Some(IaxCommand::Ack)));
                assert_eq!(ack.header.incoming_sequence, next);

                let current = FullFrameHeader {
                    outgoing_sequence: next,
                    frame_type: 4,
                    subclass: 13,
                    ..media(next)
                };
                let LinkedCallResponse::RadioUnkey { acknowledgement } = session
                    .receive_linked(&serialize_full_frame(&current, &[]).unwrap())
                    .unwrap()
                else {
                    panic!("current control must still be delivered");
                };
                assert_eq!(
                    parse_full_frame_packet(&acknowledgement)
                        .unwrap()
                        .header
                        .incoming_sequence,
                    following
                );
            }
        }
    }
}

#[test]
fn old_frames_ignore_acknowledgements_outside_the_current_send_window() {
    for incoming_sequence in [35, 101] {
        for kind in 0..3 {
            let mut session = OutboundCallSetup::for_inbound_call(1234, 5678).unwrap();
            session.next_incoming = 12;
            session.next_outgoing = 100;
            let mut header = media(9);
            header.incoming_sequence = incoming_sequence;
            let acknowledgement = if kind == 0 {
                header.frame_type = 4;
                header.subclass = 13;
                let response = session
                    .receive_linked(&serialize_full_frame(&header, &[]).unwrap())
                    .unwrap();
                let LinkedCallResponse::Send(acknowledgement) = response else {
                    panic!("consumed control must not deliver its event again");
                };
                acknowledgement
            } else {
                let (deliver, acknowledgement) = if kind == 1 {
                    session.receive_media(&header)
                } else {
                    session.receive_media_reordered(&header)
                }
                .unwrap();
                assert!(!deliver);
                acknowledgement
            };
            let acknowledgement = parse_full_frame_packet(&acknowledgement).unwrap();
            assert_eq!(
                decode_iax_command(&acknowledgement.header),
                Ok(Some(IaxCommand::Ack))
            );
            assert_eq!(acknowledgement.header.incoming_sequence, 12);
            assert_eq!(session.next_incoming, 12);
            assert_eq!(session.next_outgoing, 100);
            assert_eq!(session.state, State::Linked);
        }
    }
}

#[test]
fn future_linked_control_requests_the_missing_sequence_without_delivering_or_advancing() {
    for next in [248_u8, 198, 255, 0] {
        for distance in [1, 63, 64, 127, 128] {
            for (frame_type, subclass) in [(1, b'7'), (4, 13), (6, 5), (7, 0), (10, 0)] {
                let mut session = OutboundCallSetup::for_inbound_call(1234, 5678).unwrap();
                session.next_incoming = next;
                let future = FullFrameHeader {
                    frame_type,
                    subclass,
                    ..media(next.wrapping_add(distance))
                };
                let payload = if frame_type == 7 {
                    b"L T2002".as_slice()
                } else {
                    &[]
                };
                let packet = serialize_full_frame(&future, payload).unwrap();
                let LinkedCallResponse::Send(reply) = session.receive_linked(&packet).unwrap()
                else {
                    panic!("future control must only request retransmission");
                };
                let reply = parse_full_frame_packet(&reply).unwrap();
                assert_eq!(
                    decode_iax_command(&reply.header),
                    Ok(Some(IaxCommand::Vnak))
                );
                assert_eq!(reply.header.incoming_sequence, next);
                assert_eq!(session.next_incoming, next);
                assert_eq!(session.next_outgoing, 1);
                assert_eq!(session.state, State::Linked);

                session.receive_media(&media(next)).unwrap();
                if distance == 1 {
                    assert!(
                        !matches!(
                            session.receive_linked(&packet).unwrap(),
                            LinkedCallResponse::Send(_)
                        ) || frame_type == 10
                    );
                }
            }
        }
    }
}

#[test]
fn out_of_order_control_still_validates_call_identity_and_acknowledgement() {
    let mut session = OutboundCallSetup::for_inbound_call(1234, 5678).unwrap();
    session.next_incoming = 12;
    for sequence in [9, 13] {
        for (source, destination, ack) in [(5679, 1234, 1), (5678, 1235, 1), (5678, 1234, 2)] {
            let header = FullFrameHeader {
                source_call_number: source,
                destination_call_number: destination,
                incoming_sequence: ack,
                frame_type: 4,
                subclass: 13,
                retransmission: true,
                ..media(sequence)
            };
            let result = session.receive_linked(&serialize_full_frame(&header, &[]).unwrap());
            if sequence == 9 && source == 5678 && destination == 1234 {
                assert!(matches!(result, Ok(LinkedCallResponse::Send(_))));
            } else {
                assert!(result.is_err());
            }
            assert_eq!(session.next_incoming, 12);
            assert_eq!(session.state, State::Linked);
        }
    }
}

#[test]
fn fresh_control_after_sequence_wrap_does_not_replay_a_stale_cached_response() {
    let mut session = OutboundCallSetup::for_inbound_call(1234, 5678).unwrap();
    let mut key = media(1);
    key.frame_type = 4;
    key.subclass = 12;
    assert!(matches!(
        session.receive_linked(&serialize_full_frame(&key, &[]).unwrap()),
        Ok(LinkedCallResponse::RadioKey { .. })
    ));
    for offset in 0..255_u8 {
        session
            .receive_media(&media(2_u8.wrapping_add(offset)))
            .unwrap();
    }
    key.timestamp = 100_000;
    assert!(matches!(
        session.receive_linked(&serialize_full_frame(&key, &[]).unwrap()),
        Ok(LinkedCallResponse::RadioKey { .. })
    ));
}

#[test]
fn answer_requires_linked_state_without_advancing_reliable_sequence() {
    let mut session = OutboundCallSetup::for_inbound_call(1234, 5678).unwrap();
    for state in [State::AwaitingResponse, State::Ended] {
        session.state = state;
        let before = session.next_outgoing;
        assert_eq!(session.send_answer(20), Err(CallSetupError::NotLinked));
        assert_eq!(session.next_outgoing, before);
    }
}

#[test]
fn reordered_voice_is_delivered_once_but_ack_waits_for_the_sequence_hole() {
    let mut session = OutboundCallSetup::for_inbound_call(1234, 5678).unwrap();
    for (sequence, delivered, next) in [(2, true, 1), (2, false, 1), (1, true, 3), (1, false, 3)] {
        let (actual, acknowledgement) = session.receive_media_reordered(&media(sequence)).unwrap();
        assert_eq!(actual, delivered);
        let ack = parse_full_frame_packet(&acknowledgement).unwrap();
        assert_eq!(
            (ack.header.incoming_sequence, ack.header.timestamp),
            (next, u32::from(sequence) * 20)
        );
    }
}

#[test]
fn ordered_control_closes_a_voice_hole_without_reordering_its_event() {
    let mut session = OutboundCallSetup::for_inbound_call(1234, 5678).unwrap();
    session.receive_media_reordered(&media(2)).unwrap();
    let mut control = media(3);
    control.frame_type = 4;
    control.subclass = 12;
    let LinkedCallResponse::Send(reply) = session
        .receive_linked(&serialize_full_frame(&control, &[]).unwrap())
        .unwrap()
    else {
        panic!("missing control must be requested")
    };
    assert_eq!(
        decode_iax_command(&parse_full_frame_packet(&reply).unwrap().header),
        Ok(Some(IaxCommand::Vnak))
    );
    control.outgoing_sequence = 1;
    let LinkedCallResponse::RadioKey { acknowledgement } = session
        .receive_linked(&serialize_full_frame(&control, &[]).unwrap())
        .unwrap()
    else {
        panic!("in-order key must be delivered")
    };
    assert_eq!(
        parse_full_frame_packet(&acknowledgement)
            .unwrap()
            .header
            .incoming_sequence,
        3
    );
    control.outgoing_sequence = 3;
    control.subclass = 13;
    assert!(matches!(
        session.receive_linked(&serialize_full_frame(&control, &[]).unwrap()),
        Ok(LinkedCallResponse::RadioUnkey { .. })
    ));
}

#[test]
fn media_sequence_wrap_and_bounded_window_do_not_accept_invalid_acknowledgements() {
    let mut session = OutboundCallSetup::for_inbound_call(1234, 5678).unwrap();
    session.next_incoming = 255;
    let (_, ack) = session.receive_media_reordered(&media(0)).unwrap();
    assert_eq!(
        parse_full_frame_packet(&ack)
            .unwrap()
            .header
            .incoming_sequence,
        255
    );
    let (_, ack) = session.receive_media_reordered(&media(255)).unwrap();
    assert_eq!(
        parse_full_frame_packet(&ack)
            .unwrap()
            .header
            .incoming_sequence,
        1
    );
    let mut invalid = media(2);
    invalid.incoming_sequence = 2;
    assert!(matches!(
        session.receive_media_reordered(&invalid),
        Err(CallSetupError::SequenceMismatch { .. })
    ));
    let (delivered, reply) = session.receive_media_reordered(&media(65)).unwrap();
    assert!(!delivered);
    assert_eq!(
        decode_iax_command(&parse_full_frame_packet(&reply).unwrap().header),
        Ok(Some(IaxCommand::Vnak))
    );
}

#[test]
fn reliable_ping_reply_acknowledges_media_that_closed_the_sequence_hole() {
    let mut session = OutboundCallSetup::for_inbound_call(1234, 5678).unwrap();
    session.receive_media_reordered(&media(2)).unwrap();
    let mut ping = media(1);
    ping.frame_type = IAX_FRAME_TYPE;
    ping.subclass = IaxCommand::Ping.subclass_value() as u8;
    let LinkedCallResponse::SendReliable(reply) = session
        .receive_linked(&serialize_full_frame(&ping, &[]).unwrap())
        .unwrap()
    else {
        panic!("reliable pong expected")
    };
    assert_eq!(
        parse_full_frame_packet(&reply)
            .unwrap()
            .header
            .incoming_sequence,
        3
    );
}
