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
    assert!(matches!(
        session.receive_linked(&serialize_full_frame(&control, &[]).unwrap()),
        Err(CallSetupError::SequenceMismatch { .. })
    ));
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
    assert!(matches!(
        session.receive_media_reordered(&media(65)),
        Err(CallSetupError::SequenceMismatch { .. })
    ));
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
