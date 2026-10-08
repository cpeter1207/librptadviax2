use crate::{
    client::{DialError, DialOptions, IaxPeerEvent, dial_ulaw},
    codec::{CodecAdapter, G711Ulaw, IAX_FORMAT_ULAW, ULAW_SAMPLE_RATE_HZ},
    ffi::{
        RPTADV_IAX2_CLIENT_ABI_VERSION, RPTADV_IAX2_EVENT_AUDIO, RPTADV_IAX2_EVENT_NONE,
        RPTADV_IAX2_EVENT_TEXT, rptadv_iax2_client_descriptor_v1, rptadv_iax2_dial_options_v1,
    },
    information_elements::{InformationElement, serialize_information_elements},
    media::{VoiceFrame, parse_voice_frame},
    protocol::{
        FullFrameHeader, IaxCommand, decode_iax_command, encode_subclass, parse_full_frame_packet,
        serialize_full_frame,
    },
};
use std::{ffi::c_void, net::UdpSocket, ptr, thread, time::Duration};

const LOCAL_CALL: u16 = 1234;
const REMOTE_CALL: u16 = 5678;
const ULAW: u32 = 0x4;

fn frame(
    source: u16,
    destination: u16,
    oseq: u8,
    iseq: u8,
    command: IaxCommand,
    payload: &[u8],
) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: source,
            retransmission: false,
            destination_call_number: destination,
            timestamp: 0,
            outgoing_sequence: oseq,
            incoming_sequence: iseq,
            frame_type: 6,
            subclass: encode_subclass(command.subclass_value()).unwrap(),
            subclass_is_log: false,
        },
        payload,
    )
    .unwrap()
}

fn send_ie(
    socket: &UdpSocket,
    peer: std::net::SocketAddr,
    header: (u16, u16, u8, u8, IaxCommand),
    ies: &[InformationElement<'_>],
) {
    let payload = serialize_information_elements(ies).unwrap();
    socket
        .send_to(
            &frame(header.0, header.1, header.2, header.3, header.4, &payload),
            peer,
        )
        .unwrap();
}

fn make_full_voice(source: u16, destination: u16, format: u8, payload: &[u8]) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: source,
            retransmission: false,
            destination_call_number: destination,
            timestamp: 20,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 2,
            subclass: format,
            subclass_is_log: false,
        },
        payload,
    )
    .unwrap()
}

#[test]
fn retries_new_as_retransmission_when_setup_response_is_lost() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let remote = server.local_addr().unwrap();
    let responder = thread::spawn(move || {
        let mut bytes = [0_u8; 1500];
        let (length, client) = server.recv_from(&mut bytes).unwrap();
        let first = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(
            decode_iax_command(&first.header).unwrap(),
            Some(IaxCommand::New)
        );
        assert!(!first.header.retransmission);
        let first_header = first.header;
        let first_payload = first.payload.to_vec();

        let (length, _) = server.recv_from(&mut bytes).unwrap();
        let retry = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert!(retry.header.retransmission);
        assert_eq!(
            retry.header.source_call_number,
            first_header.source_call_number
        );
        assert_eq!(
            retry.header.destination_call_number,
            first_header.destination_call_number
        );
        assert_eq!(
            retry.header.outgoing_sequence,
            first_header.outgoing_sequence
        );
        assert_eq!(retry.header.incoming_sequence, 0);
        assert_eq!(retry.payload, first_payload);

        let rejected = frame(REMOTE_CALL, LOCAL_CALL, 0, 1, IaxCommand::Reject, &[]);
        server.send_to(&rejected, client).unwrap();
        let (length, _) = server.recv_from(&mut bytes).unwrap();
        let acknowledgement = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(
            decode_iax_command(&acknowledgement.header).unwrap(),
            Some(IaxCommand::Ack)
        );
    });

    let result = dial_ulaw(DialOptions {
        remote,
        local_call: LOCAL_CALL,
        local_node: "524950",
        remote_node: "506315",
        secret: "",
        timeout: Duration::from_millis(800),
    });
    assert!(matches!(result, Err(DialError::Rejected)));
    responder.join().unwrap();
}

#[test]
fn retries_linked_text_as_retransmission_when_ack_is_lost() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_millis(25)))
        .unwrap();
    let address = server.local_addr().unwrap();
    let handshake = server.try_clone().unwrap();
    let responder = thread::spawn(move || {
        let mut bytes = [0_u8; 1500];
        let (length, client) = handshake.recv_from(&mut bytes).unwrap();
        let initial = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(
            decode_iax_command(&initial.header).unwrap(),
            Some(IaxCommand::New)
        );
        let format = ULAW.to_be_bytes();
        send_ie(
            &handshake,
            client,
            (REMOTE_CALL, LOCAL_CALL, 0, 1, IaxCommand::Accept),
            &[InformationElement {
                kind: 9,
                data: &format,
            }],
        );
        let (length, _) = handshake.recv_from(&mut bytes).unwrap();
        assert_eq!(
            decode_iax_command(&parse_full_frame_packet(&bytes[..length]).unwrap().header).unwrap(),
            Some(IaxCommand::Ack)
        );
    });

    let mut peer = dial_ulaw(DialOptions {
        remote: address,
        local_call: LOCAL_CALL,
        local_node: "524950",
        remote_node: "506315",
        secret: "",
        timeout: Duration::from_secs(1),
    })
    .unwrap();
    responder.join().unwrap();
    peer.send_text(b"status").unwrap();

    let mut bytes = [0_u8; 1500];
    let (length, client) = server.recv_from(&mut bytes).unwrap();
    let original = parse_full_frame_packet(&bytes[..length]).unwrap();
    let original_header = original.header;
    let original_payload = original.payload.to_vec();
    assert_eq!(original_header.frame_type, 7);
    assert!(!original_header.retransmission);
    assert_eq!(original_payload, b"status");

    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut retried = None;
    while std::time::Instant::now() < deadline {
        assert_eq!(
            peer.poll_event(&mut [], &mut []).unwrap(),
            IaxPeerEvent::None
        );
        match server.recv_from(&mut bytes) {
            Ok((length, _)) => {
                retried = Some(parse_full_frame_packet(&bytes[..length]).unwrap());
                break;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("unexpected UDP receive failure: {error}"),
        }
    }

    let retry = retried.expect("linked text must be retransmitted after a lost ACK");
    assert!(retry.header.retransmission);
    assert_eq!(
        retry.header.outgoing_sequence,
        original_header.outgoing_sequence
    );
    assert_eq!(retry.payload, original_payload);

    let acknowledgement = frame(
        REMOTE_CALL,
        LOCAL_CALL,
        1,
        original_header.outgoing_sequence.wrapping_add(1),
        IaxCommand::Ack,
        &[],
    );
    server.send_to(&acknowledgement, client).unwrap();
    assert_eq!(
        peer.poll_event(&mut [], &mut []).unwrap(),
        IaxPeerEvent::None
    );

    let deadline = std::time::Instant::now() + Duration::from_millis(2200);
    while std::time::Instant::now() < deadline {
        assert_eq!(
            peer.poll_event(&mut [], &mut []).unwrap(),
            IaxPeerEvent::None
        );
        match server.recv_from(&mut bytes) {
            Ok(_) => panic!("acknowledged text must not be retransmitted"),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("unexpected UDP receive failure: {error}"),
        }
    }
}

#[test]
fn dials_an_8khz_ulaw_call_through_calltoken_and_md5_authentication() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let address = server.local_addr().unwrap();
    let responder = thread::spawn(move || {
        let mut bytes = [0_u8; 1500];
        let (length, client) = server.recv_from(&mut bytes).unwrap();
        let initial = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(
            decode_iax_command(&initial.header).unwrap(),
            Some(IaxCommand::New)
        );
        let initial_ies =
            crate::information_elements::parse_information_elements(initial.payload).unwrap();
        assert!(
            initial_ies
                .iter()
                .any(|ie| ie.kind == 9 && ie.data == ULAW.to_be_bytes())
        );
        assert!(
            initial_ies
                .iter()
                .any(|ie| ie.kind == 8 && ie.data == ULAW.to_be_bytes())
        );
        assert!(
            initial_ies
                .iter()
                .any(|ie| ie.kind == 6 && ie.data == b"radio")
        );

        let unexpected_sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        unexpected_sender.send_to(b"noise", client).unwrap();

        // Modern ASL endpoints first return a call token for the empty CALLTOKEN IE.
        let methods = 2_u16.to_be_bytes();
        send_ie(
            &server,
            client,
            (0, LOCAL_CALL, 0, 0, IaxCommand::CallToken),
            &[InformationElement {
                kind: 54,
                data: b"token-123",
            }],
        );
        let (length, _) = server.recv_from(&mut bytes).unwrap();
        let retried = parse_full_frame_packet(&bytes[..length]).unwrap();
        let retried_ies =
            crate::information_elements::parse_information_elements(retried.payload).unwrap();
        assert!(
            retried_ies
                .iter()
                .any(|ie| ie.kind == 54 && ie.data == b"token-123")
        );

        send_ie(
            &server,
            client,
            (REMOTE_CALL, LOCAL_CALL, 0, 1, IaxCommand::AuthReq),
            &[
                InformationElement {
                    kind: 14,
                    data: &methods,
                },
                InformationElement {
                    kind: 15,
                    data: b"challenge",
                },
            ],
        );
        let (length, _) = server.recv_from(&mut bytes).unwrap();
        let auth = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(
            decode_iax_command(&auth.header).unwrap(),
            Some(IaxCommand::AuthRep)
        );
        let auth_payload = auth.payload.to_vec();
        let auth_outgoing_sequence = auth.header.outgoing_sequence;
        let auth_incoming_sequence = auth.header.incoming_sequence;

        let (length, _) = server.recv_from(&mut bytes).unwrap();
        let auth_retry = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert!(auth_retry.header.retransmission);
        assert_eq!(auth_retry.header.outgoing_sequence, auth_outgoing_sequence);
        assert_eq!(auth_retry.header.incoming_sequence, auth_incoming_sequence);
        assert_eq!(auth_retry.header.incoming_sequence, 1);
        assert_eq!(auth_retry.payload, auth_payload);

        let accepted_format = ULAW.to_be_bytes();
        send_ie(
            &server,
            client,
            (REMOTE_CALL, LOCAL_CALL, 1, 2, IaxCommand::Accept),
            &[InformationElement {
                kind: 9,
                data: &accepted_format,
            }],
        );
        let (length, _) = server.recv_from(&mut bytes).unwrap();
        let ack = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(
            decode_iax_command(&ack.header).unwrap(),
            Some(IaxCommand::Ack)
        );
        assert_eq!(ack.header.source_call_number, LOCAL_CALL);
        assert_eq!(ack.header.destination_call_number, REMOTE_CALL);

        let (length, _) = server.recv_from(&mut bytes).unwrap();
        let outbound = parse_voice_frame(&bytes[..length], ULAW).unwrap();
        let VoiceFrame::Mini {
            header, payload, ..
        } = outbound
        else {
            panic!("outbound audio must use an IAX mini voice frame");
        };
        assert_eq!(header.source_call_number, LOCAL_CALL);
        let mut decoded = [0.0; 160];
        assert_eq!(
            G711Ulaw.decode(payload, &mut decoded).unwrap(),
            decoded.len()
        );
        assert!(decoded.iter().all(|sample| (*sample - 0.25).abs() < 0.02));

        let remote_pcm = [0.125_f32; 160];
        let mut encoded = [0; 160];
        G711Ulaw.encode(&remote_pcm, &mut encoded).unwrap();
        let mut voice = [0; 164];
        voice[..2].copy_from_slice(&REMOTE_CALL.to_be_bytes());
        voice[2..4].copy_from_slice(&20_u16.to_be_bytes());
        voice[4..].copy_from_slice(&encoded);
        let unexpected_sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        unexpected_sender.send_to(b"noise", client).unwrap();
        server.send_to(&voice, client).unwrap();

        let mut text_header = parse_full_frame_packet(&frame(
            REMOTE_CALL,
            LOCAL_CALL,
            2,
            2,
            IaxCommand::Accept,
            &[],
        ))
        .unwrap()
        .header;
        text_header.frame_type = 7;
        text_header.subclass = 0;
        text_header.subclass_is_log = false;
        let text_frame = serialize_full_frame(&text_header, b"!KEY! 506315 524950 1").unwrap();
        server.send_to(&text_frame, client).unwrap();
        let (length, _) = server.recv_from(&mut bytes).unwrap();
        let ack = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(
            decode_iax_command(&ack.header).unwrap(),
            Some(IaxCommand::Ack)
        );
        assert_eq!(
            (ack.header.outgoing_sequence, ack.header.incoming_sequence),
            (2, 3)
        );

        let (length, _) = server.recv_from(&mut bytes).unwrap();
        let sent_text = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(sent_text.header.frame_type, 7);
        assert_eq!(sent_text.payload, b"!KEY! 524950 506315 1");

        let (length, _) = server.recv_from(&mut bytes).unwrap();
        let sent_digit = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(sent_digit.header.frame_type, 1);
        assert_eq!(sent_digit.header.subclass, b'7');
        assert!(sent_digit.payload.is_empty());

        let (length, _) = server.recv_from(&mut bytes).unwrap();
        let hangup = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(
            decode_iax_command(&hangup.header).unwrap(),
            Some(IaxCommand::Hangup)
        );
    });

    let remote_address = address.to_string();
    let local_node = b"524950";
    let remote_node = b"506315";
    let secret = b"test-secret";
    let options = rptadv_iax2_dial_options_v1 {
        struct_size: std::mem::size_of::<rptadv_iax2_dial_options_v1>() as u32,
        abi_version: RPTADV_IAX2_CLIENT_ABI_VERSION,
        remote_address: remote_address.as_ptr(),
        remote_address_length: remote_address.len(),
        local_call_number: LOCAL_CALL,
        reserved: 0,
        local_node: local_node.as_ptr(),
        local_node_length: local_node.len(),
        remote_node: remote_node.as_ptr(),
        remote_node_length: remote_node.len(),
        secret: secret.as_ptr(),
        secret_length: secret.len(),
        timeout_ms: 1000,
    };
    let descriptor = unsafe { &*rptadv_iax2_client_descriptor_v1() };
    let mut peer: *mut c_void = ptr::null_mut();
    assert_eq!(unsafe { descriptor.dial.unwrap()(&options, &mut peer) }, 0);
    assert!(!peer.is_null());
    assert_eq!(unsafe { descriptor.sample_rate_hz.unwrap()(peer) }, 8_000);

    let outbound = [0.25_f32; 160];
    assert_eq!(
        unsafe { descriptor.send_audio.unwrap()(peer, outbound.as_ptr(), outbound.len()) },
        0
    );
    let mut received = [0.0; 160];
    let mut text = [0; 64];
    let mut event_kind = RPTADV_IAX2_EVENT_NONE;
    let mut event_length = 0;
    while event_kind == RPTADV_IAX2_EVENT_NONE {
        assert_eq!(
            unsafe {
                descriptor.poll.unwrap()(
                    peer,
                    received.as_mut_ptr(),
                    received.len(),
                    text.as_mut_ptr(),
                    text.len(),
                    &mut event_kind,
                    &mut event_length,
                )
            },
            0
        );
        if event_kind == RPTADV_IAX2_EVENT_NONE {
            thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(event_kind, RPTADV_IAX2_EVENT_AUDIO);
    assert_eq!(event_length, received.len());
    assert!(
        received
            .iter()
            .all(|sample| (*sample - 0.125_f32).abs() < 0.02)
    );

    event_kind = RPTADV_IAX2_EVENT_NONE;
    while event_kind == RPTADV_IAX2_EVENT_NONE {
        assert_eq!(
            unsafe {
                descriptor.poll.unwrap()(
                    peer,
                    received.as_mut_ptr(),
                    received.len(),
                    text.as_mut_ptr(),
                    text.len(),
                    &mut event_kind,
                    &mut event_length,
                )
            },
            0
        );
        if event_kind == RPTADV_IAX2_EVENT_NONE {
            thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(event_kind, RPTADV_IAX2_EVENT_TEXT);
    assert_eq!(&text[..event_length], b"!KEY! 506315 524950 1");
    let sent_text = b"!KEY! 524950 506315 1";
    assert_eq!(
        unsafe { descriptor.send_text.unwrap()(peer, sent_text.as_ptr(), sent_text.len()) },
        0
    );
    assert_eq!(unsafe { descriptor.send_digit.unwrap()(peer, b'7') }, 0);
    assert_eq!(unsafe { descriptor.hangup.unwrap()(peer) }, 0);
    unsafe { descriptor.destroy.unwrap()(peer) };
    responder.join().unwrap();
}

#[test]
fn direct_peer_api_reports_metadata_and_sends_ulaw() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let address = server.local_addr().unwrap();
    let responder = thread::spawn(move || {
        let mut bytes = [0_u8; 1500];
        let (length, client_addr) = server.recv_from(&mut bytes).unwrap();
        let initial = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(
            decode_iax_command(&initial.header).unwrap(),
            Some(IaxCommand::New)
        );

        let format = IAX_FORMAT_ULAW.to_be_bytes();
        send_ie(
            &server,
            client_addr,
            (REMOTE_CALL, LOCAL_CALL, 0, 1, IaxCommand::Accept),
            &[InformationElement {
                kind: 9,
                data: &format,
            }],
        );
        let (length, _) = server.recv_from(&mut bytes).unwrap();
        let acknowledgement = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(
            decode_iax_command(&acknowledgement.header).unwrap(),
            Some(IaxCommand::Ack)
        );

        let (length, audio_source) = server.recv_from(&mut bytes).unwrap();
        assert_eq!(audio_source, client_addr);
        let outbound = parse_voice_frame(&bytes[..length], IAX_FORMAT_ULAW).unwrap();
        let VoiceFrame::Mini { payload, .. } = outbound else {
            panic!("direct ULAW client should transmit a mini voice frame");
        };
        let mut decoded = [0.0; 160];
        G711Ulaw.decode(payload, &mut decoded).unwrap();
        assert!(decoded.iter().all(|sample| (*sample - 0.25).abs() < 0.02));

        send_ie(
            &server,
            client_addr,
            (REMOTE_CALL, LOCAL_CALL, 1, 1, IaxCommand::Ack),
            &[],
        );
        send_ie(
            &server,
            client_addr,
            (REMOTE_CALL, LOCAL_CALL, 1, 1, IaxCommand::Ping),
            &[],
        );
        let (length, _) = server.recv_from(&mut bytes).unwrap();
        assert_eq!(
            decode_iax_command(&parse_full_frame_packet(&bytes[..length]).unwrap().header).unwrap(),
            Some(IaxCommand::Pong)
        );

        let pong = frame(REMOTE_CALL, LOCAL_CALL, 2, 2, IaxCommand::Pong, &[]);
        let mut duplicate_pong_header = parse_full_frame_packet(&pong).unwrap().header;
        duplicate_pong_header.retransmission = true;
        let duplicate_pong = serialize_full_frame(&duplicate_pong_header, &[]).unwrap();
        server.send_to(&pong, client_addr).unwrap();
        let (length, _) = server.recv_from(&mut bytes).unwrap();
        assert_eq!(
            decode_iax_command(&parse_full_frame_packet(&bytes[..length]).unwrap().header).unwrap(),
            Some(IaxCommand::Ack)
        );
        server.send_to(&duplicate_pong, client_addr).unwrap();
        let (length, _) = server.recv_from(&mut bytes).unwrap();
        assert_eq!(
            decode_iax_command(&parse_full_frame_packet(&bytes[..length]).unwrap().header).unwrap(),
            Some(IaxCommand::Ack)
        );

        let mut text_header = parse_full_frame_packet(&frame(
            REMOTE_CALL,
            LOCAL_CALL,
            3,
            2,
            IaxCommand::Accept,
            &[],
        ))
        .unwrap()
        .header;
        text_header.frame_type = 7;
        text_header.subclass = 0;
        text_header.subclass_is_log = false;
        let text_frame = serialize_full_frame(&text_header, b"ok").unwrap();
        let mut duplicate_text_header = parse_full_frame_packet(&text_frame).unwrap().header;
        duplicate_text_header.retransmission = true;
        let duplicate_text = serialize_full_frame(&duplicate_text_header, b"ok").unwrap();
        server.send_to(&text_frame, client_addr).unwrap();
        let (length, _) = server.recv_from(&mut bytes).unwrap();
        assert_eq!(
            decode_iax_command(&parse_full_frame_packet(&bytes[..length]).unwrap().header).unwrap(),
            Some(IaxCommand::Ack)
        );
        server.send_to(&duplicate_text, client_addr).unwrap();
        let (length, _) = server.recv_from(&mut bytes).unwrap();
        assert_eq!(
            decode_iax_command(&parse_full_frame_packet(&bytes[..length]).unwrap().header).unwrap(),
            Some(IaxCommand::Ack)
        );
        text_header.outgoing_sequence = 4;
        let oversized_text = serialize_full_frame(&text_header, b"too large").unwrap();
        server.send_to(&oversized_text, client_addr).unwrap();
        let (length, _) = server.recv_from(&mut bytes).unwrap();
        assert_eq!(
            decode_iax_command(&parse_full_frame_packet(&bytes[..length]).unwrap().header).unwrap(),
            Some(IaxCommand::Ack)
        );

        let encoded = {
            let mut encoded = [0; 160];
            G711Ulaw.encode(&[0.125; 160], &mut encoded).unwrap();
            encoded
        };
        let full_voice = serialize_full_frame(
            &FullFrameHeader {
                source_call_number: REMOTE_CALL,
                retransmission: false,
                destination_call_number: LOCAL_CALL,
                timestamp: 40,
                outgoing_sequence: 1,
                incoming_sequence: 2,
                frame_type: 2,
                subclass: ULAW as u8,
                subclass_is_log: false,
            },
            &encoded,
        )
        .unwrap();
        server.send_to(&full_voice, client_addr).unwrap();

        let wrong_full_source = make_full_voice(REMOTE_CALL + 1, LOCAL_CALL, ULAW as u8, &encoded);
        server.send_to(&wrong_full_source, client_addr).unwrap();
        let wrong_full_destination =
            make_full_voice(REMOTE_CALL, LOCAL_CALL + 1, ULAW as u8, &encoded);
        server
            .send_to(&wrong_full_destination, client_addr)
            .unwrap();
        let wrong_full_format = make_full_voice(REMOTE_CALL, LOCAL_CALL, 0x08, &encoded);
        server.send_to(&wrong_full_format, client_addr).unwrap();
        let wrong_mini_source = crate::protocol::serialize_mini_frame(
            &crate::protocol::MiniFrameHeader {
                source_call_number: REMOTE_CALL + 1,
                timestamp: 60,
            },
            &encoded,
        )
        .unwrap();
        server.send_to(&wrong_mini_source, client_addr).unwrap();

        send_ie(
            &server,
            client_addr,
            (REMOTE_CALL, LOCAL_CALL, 5, 2, IaxCommand::Hangup),
            &[],
        );
        let (length, _) = server.recv_from(&mut bytes).unwrap();
        let acknowledgement = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(
            decode_iax_command(&acknowledgement.header).unwrap(),
            Some(IaxCommand::Ack)
        );
    });

    let local_node = "524950";
    let remote_node = "506315";
    let mut peer = dial_ulaw(DialOptions {
        remote: address,
        local_call: LOCAL_CALL,
        local_node,
        remote_node,
        secret: "",
        timeout: Duration::from_secs(1),
    })
    .unwrap();
    assert_eq!(peer.format(), IAX_FORMAT_ULAW);
    assert_eq!(peer.sample_rate_hz(), ULAW_SAMPLE_RATE_HZ);
    assert_eq!(peer.local_call_number(), LOCAL_CALL);
    assert_eq!(peer.remote_call_number(), REMOTE_CALL);
    assert_eq!(peer.remote_addr(), address);
    assert!(peer.local_addr().unwrap().port() != 0);
    let _ = peer.elapsed_ms();

    let mut incoming = [0.0; 160];
    assert_eq!(
        peer.poll_event(&mut incoming, &mut []).unwrap(),
        IaxPeerEvent::None
    );

    let pcm = [0.25_f32; 160];
    peer.send_ulaw(&pcm, 20).unwrap();

    assert_eq!(peer.poll_ulaw(&mut incoming).unwrap(), None);

    let mut text = [0; 2];
    let mut event = IaxPeerEvent::None;
    while event == IaxPeerEvent::None {
        event = peer.poll_event(&mut incoming, &mut text).unwrap();
        if event == IaxPeerEvent::None {
            thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(event, IaxPeerEvent::Text(2));
    assert_eq!(&text, b"ok");
    assert_eq!(
        peer.poll_event(&mut incoming, &mut text).unwrap(),
        IaxPeerEvent::None
    );
    loop {
        match peer.poll_event(&mut incoming, &mut [0]) {
            Err(crate::client::DialError::InvalidOptions) => break,
            Ok(IaxPeerEvent::None) => thread::sleep(Duration::from_millis(1)),
            other => panic!("oversized text should fail, got {other:?}"),
        }
    }

    let decoded = loop {
        match peer.poll_ulaw(&mut incoming) {
            Ok(Some(count)) => break count,
            Ok(None) => thread::sleep(Duration::from_millis(1)),
            Err(error) => panic!("unexpected ULAW receive error: {error:?}"),
        }
    };
    assert_eq!(decoded, incoming.len());
    assert!(incoming.iter().all(|sample| (*sample - 0.125).abs() < 0.02));

    for _ in 0..4 {
        assert!(matches!(
            peer.poll_ulaw(&mut incoming),
            Err(DialError::Voice(
                crate::media::VoiceFrameError::NotVoiceFrame
            ))
        ));
    }

    assert!(matches!(
        peer.send_ulaw(&vec![0.25; 1500], 80),
        Err(crate::client::DialError::Encode(_))
    ));
    assert!(matches!(
        peer.poll_ulaw(&mut incoming),
        Err(DialError::Hangup)
    ));
    assert!(matches!(
        peer.send_text(b"late"),
        Err(crate::client::DialError::Protocol(_))
    ));
    responder.join().unwrap();
}

#[test]
fn direct_peer_reports_radio_key_control_frames() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let address = server.local_addr().unwrap();
    let responder = server.try_clone().unwrap();
    let setup = thread::spawn(move || {
        let mut bytes = [0_u8; 1500];
        let (length, client) = responder.recv_from(&mut bytes).unwrap();
        let new = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(
            decode_iax_command(&new.header).unwrap(),
            Some(IaxCommand::New)
        );
        let format = IAX_FORMAT_ULAW.to_be_bytes();
        send_ie(
            &responder,
            client,
            (REMOTE_CALL, LOCAL_CALL, 0, 1, IaxCommand::Accept),
            &[InformationElement {
                kind: 9,
                data: &format,
            }],
        );
        let (length, _) = responder.recv_from(&mut bytes).unwrap();
        assert_eq!(
            decode_iax_command(&parse_full_frame_packet(&bytes[..length]).unwrap().header).unwrap(),
            Some(IaxCommand::Ack)
        );
        client
    });
    let mut peer = dial_ulaw(DialOptions {
        remote: address,
        local_call: LOCAL_CALL,
        local_node: "524950",
        remote_node: "506315",
        secret: "",
        timeout: Duration::from_secs(1),
    })
    .unwrap();
    let client = setup.join().unwrap();
    let control = |subclass, outgoing_sequence| {
        serialize_full_frame(
            &FullFrameHeader {
                source_call_number: REMOTE_CALL,
                retransmission: false,
                destination_call_number: LOCAL_CALL,
                timestamp: 20,
                outgoing_sequence,
                incoming_sequence: 1,
                frame_type: 4,
                subclass,
                subclass_is_log: false,
            },
            &[],
        )
        .unwrap()
    };
    let mut samples = [0.0; 160];
    for (subclass, expected, sequence) in [(12, "RadioKey", 1), (13, "RadioUnkey", 2)] {
        server
            .send_to(&control(subclass, sequence), client)
            .unwrap();
        assert_eq!(
            format!("{:?}", peer.poll_event(&mut samples, &mut [])),
            format!("Ok({expected})")
        );
    }
}

#[test]
fn dial_rejects_each_invalid_option_without_opening_a_socket() {
    let remote = "127.0.0.1:4569".parse().unwrap();
    let too_long = "1".repeat(32);
    for (local_call, local_node, remote_node, timeout) in [
        (0, "524950", "506315", Duration::from_millis(1)),
        (0x8000, "524950", "506315", Duration::from_millis(1)),
        (1, "", "506315", Duration::from_millis(1)),
        (1, "52A950", "506315", Duration::from_millis(1)),
        (1, too_long.as_str(), "506315", Duration::from_millis(1)),
        (1, "524950", "", Duration::from_millis(1)),
        (1, "524950", "50631X", Duration::from_millis(1)),
        (1, "524950", too_long.as_str(), Duration::from_millis(1)),
        (1, "524950", "506315", Duration::ZERO),
    ] {
        assert!(matches!(
            dial_ulaw(DialOptions {
                remote,
                local_call,
                local_node,
                remote_node,
                secret: "",
                timeout,
            }),
            Err(DialError::InvalidOptions)
        ));
    }
}

#[test]
fn dial_times_out_when_the_peer_does_not_answer() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let remote = server.local_addr().unwrap();
    let responder = thread::spawn(move || {
        let mut packet = [0; 1500];
        assert!(server.recv_from(&mut packet).is_ok());
    });

    assert!(matches!(
        dial_ulaw(DialOptions {
            remote,
            local_call: LOCAL_CALL,
            local_node: "524950",
            remote_node: "506315",
            secret: "",
            timeout: Duration::from_millis(10),
        }),
        Err(DialError::Timeout)
    ));
    responder.join().unwrap();
}

#[test]
fn dial_stops_retransmitting_after_the_transmission_limit() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let remote = server.local_addr().unwrap();
    assert!(matches!(
        dial_ulaw(DialOptions {
            remote,
            local_call: LOCAL_CALL,
            local_node: "524950",
            remote_node: "506315",
            secret: "",
            timeout: Duration::from_secs(60),
        }),
        Err(DialError::Timeout)
    ));

    server.set_nonblocking(true).unwrap();
    let mut packet = [0; 1500];
    let mut transmissions = 0;
    while server.recv_from(&mut packet).is_ok() {
        transmissions += 1;
    }
    assert_eq!(transmissions, 4);
}

#[test]
fn dial_acks_but_rejects_a_non_ulaw_accepted_format() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let remote = server.local_addr().unwrap();
    let responder = thread::spawn(move || {
        let mut packet = [0; 1500];
        let (length, client) = server.recv_from(&mut packet).unwrap();
        let new = parse_full_frame_packet(&packet[..length]).unwrap();
        assert_eq!(
            decode_iax_command(&new.header).unwrap(),
            Some(IaxCommand::New)
        );
        send_ie(
            &server,
            client,
            (REMOTE_CALL, LOCAL_CALL, 0, 1, IaxCommand::Accept),
            &[InformationElement {
                kind: 9,
                data: &(ULAW | 0x08).to_be_bytes(),
            }],
        );
        let (length, _) = server.recv_from(&mut packet).unwrap();
        assert_eq!(
            decode_iax_command(&parse_full_frame_packet(&packet[..length]).unwrap().header)
                .unwrap(),
            Some(IaxCommand::Ack)
        );
    });

    assert!(matches!(
        dial_ulaw(DialOptions {
            remote,
            local_call: LOCAL_CALL,
            local_node: "524950",
            remote_node: "506315",
            secret: "",
            timeout: Duration::from_secs(1),
        }),
        Err(DialError::UnsupportedFormat(12))
    ));
    responder.join().unwrap();
}

#[test]
fn dial_acknowledges_a_rejected_call() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let remote = server.local_addr().unwrap();
    let responder = thread::spawn(move || {
        let mut packet = [0; 1500];
        let (length, client) = server.recv_from(&mut packet).unwrap();
        let new = parse_full_frame_packet(&packet[..length]).unwrap();
        assert_eq!(
            decode_iax_command(&new.header).unwrap(),
            Some(IaxCommand::New)
        );
        send_ie(
            &server,
            client,
            (REMOTE_CALL, LOCAL_CALL, 0, 1, IaxCommand::Reject),
            &[],
        );
        let (length, _) = server.recv_from(&mut packet).unwrap();
        assert_eq!(
            decode_iax_command(&parse_full_frame_packet(&packet[..length]).unwrap().header)
                .unwrap(),
            Some(IaxCommand::Ack)
        );
    });

    assert!(matches!(
        dial_ulaw(DialOptions {
            remote,
            local_call: LOCAL_CALL,
            local_node: "524950",
            remote_node: "506315",
            secret: "",
            timeout: Duration::from_secs(1),
        }),
        Err(DialError::Rejected)
    ));
    responder.join().unwrap();
}
