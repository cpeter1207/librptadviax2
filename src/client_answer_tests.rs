use crate::{
    client::{DialError, DialOptions, IaxPeer, IaxPeerEvent, dial_ulaw},
    codec::{CodecAdapter, G711Ulaw},
    protocol::{FullFrameHeader, IaxCommand, parse_full_frame_packet, serialize_full_frame},
};
use std::{net::UdpSocket, sync::mpsc, thread, time::Duration};

const LOCAL_CALL: u16 = 1234;
const REMOTE_CALL: u16 = 5678;

fn packet(sequence: u8, frame_type: u8, subclass: u8, payload: &[u8]) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: REMOTE_CALL,
            destination_call_number: LOCAL_CALL,
            retransmission: false,
            timestamp: u32::from(sequence) * 20,
            outgoing_sequence: sequence,
            incoming_sequence: 1,
            frame_type,
            subclass_is_log: false,
            subclass,
        },
        payload,
    )
    .unwrap()
}

fn dialing(
    timeout: Duration,
) -> (
    UdpSocket,
    std::net::SocketAddr,
    mpsc::Receiver<Result<IaxPeer, DialError>>,
) {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let remote = server.local_addr().unwrap();
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        sender
            .send(dial_ulaw(DialOptions {
                remote,
                local_call: LOCAL_CALL,
                local_node: "524950",
                remote_node: "506315",
                secret: "",
                timeout,
            }))
            .ok();
    });
    let (_, client) = server.recv_from(&mut [0; 1500]).unwrap();
    (server, client, receiver)
}

fn send_acked(server: &UdpSocket, client: std::net::SocketAddr, bytes: &[u8]) {
    server.send_to(bytes, client).unwrap();
    let mut received = [0; 1500];
    let (length, _) = server.recv_from(&mut received).unwrap();
    let ack = parse_full_frame_packet(&received[..length]).unwrap();
    assert_eq!(ack.header.frame_type, 6);
    assert_eq!(ack.header.subclass, IaxCommand::Ack.subclass_value() as u8);
    assert_eq!(ack.header.incoming_sequence, bytes[8].wrapping_add(1));
}

fn accept() -> Vec<u8> {
    packet(
        0,
        6,
        IaxCommand::Accept.subclass_value() as u8,
        &[9, 4, 0, 0, 0, 4],
    )
}

#[test]
fn dial_waits_for_answer_and_replays_early_events_in_order() {
    let (server, client, result) = dialing(Duration::from_secs(1));
    send_acked(&server, client, &accept());
    assert!(
        matches!(
            result.recv_timeout(Duration::from_millis(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "ACCEPT must not expose a dial handle"
    );
    send_acked(&server, client, &packet(1, 7, 0, b"!NEWKEY1!"));
    send_acked(&server, client, &packet(2, 2, 4, &[0x80, 0xff, 0x00]));
    send_acked(&server, client, &packet(3, 7, 0, b"after audio"));
    send_acked(&server, client, &packet(4, 4, 12, &[]));
    send_acked(&server, client, &packet(5, 4, 13, &[]));
    send_acked(&server, client, &packet(6, 1, b'5', &[]));
    assert!(matches!(result.try_recv(), Err(mpsc::TryRecvError::Empty)));
    send_acked(&server, client, &packet(7, 4, 4, &[]));
    let mut peer = result
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap();
    let mut pcm = [0.0; 160];
    let mut text = [0; 1500];
    assert!(matches!(
        peer.poll_event(&mut pcm, &mut [0; 8]),
        Err(DialError::InvalidOptions)
    ));
    assert_eq!(
        peer.poll_event(&mut pcm, &mut text).unwrap(),
        IaxPeerEvent::Text(9)
    );
    assert_eq!(&text[..9], b"!NEWKEY1!");
    assert!(matches!(
        peer.poll_event(&mut [0.0; 2], &mut text),
        Err(DialError::InvalidOptions)
    ));
    assert_eq!(
        peer.poll_event(&mut pcm, &mut text).unwrap(),
        IaxPeerEvent::Audio(3)
    );
    let mut expected = [0.0; 3];
    G711Ulaw.decode(&[0x80, 0xff, 0x00], &mut expected).unwrap();
    assert_eq!(&pcm[..3], &expected);
    assert_eq!(
        peer.poll_event(&mut pcm, &mut text).unwrap(),
        IaxPeerEvent::Text(11)
    );
    assert_eq!(&text[..11], b"after audio");
    assert_eq!(
        peer.poll_event(&mut pcm, &mut text).unwrap(),
        IaxPeerEvent::RadioKey
    );
    assert_eq!(
        peer.poll_event(&mut pcm, &mut text).unwrap(),
        IaxPeerEvent::RadioUnkey
    );
    assert!(matches!(
        peer.poll_event(&mut pcm, &mut []),
        Err(DialError::InvalidOptions)
    ));
    assert_eq!(
        peer.poll_event(&mut pcm, &mut text).unwrap(),
        IaxPeerEvent::Digit(b'5')
    );
    assert_eq!(
        peer.poll_event(&mut pcm, &mut text).unwrap(),
        IaxPeerEvent::None
    );
}

#[test]
fn accepted_call_without_answer_times_out() {
    let (server, client, result) = dialing(Duration::from_millis(100));
    send_acked(&server, client, &accept());
    assert!(matches!(
        result.recv_timeout(Duration::from_secs(1)).unwrap(),
        Err(DialError::Timeout)
    ));
}

#[test]
fn hangup_before_answer_never_returns_a_peer() {
    let (server, client, result) = dialing(Duration::from_secs(1));
    send_acked(&server, client, &accept());
    server
        .send_to(
            &packet(1, 6, IaxCommand::Hangup.subclass_value() as u8, &[]),
            client,
        )
        .unwrap();
    assert!(matches!(
        result.recv_timeout(Duration::from_secs(1)).unwrap(),
        Err(DialError::Hangup)
    ));
}

#[test]
fn reject_never_returns_a_peer() {
    let (server, client, result) = dialing(Duration::from_secs(1));
    send_acked(
        &server,
        client,
        &packet(0, 6, IaxCommand::Reject.subclass_value() as u8, &[]),
    );
    assert!(matches!(
        result.recv_timeout(Duration::from_secs(1)).unwrap(),
        Err(DialError::Rejected)
    ));
}

#[test]
fn too_many_events_before_answer_fails_with_a_bounded_queue() {
    let (server, client, result) = dialing(Duration::from_secs(2));
    send_acked(&server, client, &accept());
    for sequence in 1..=65 {
        send_acked(&server, client, &packet(sequence, 7, 0, b"early"));
    }
    assert!(matches!(
        result.recv_timeout(Duration::from_secs(1)).unwrap(),
        Err(DialError::EarlyEventsFull)
    ));
}

#[test]
fn unsequenced_answer_never_returns_a_peer() {
    let (server, client, result) = dialing(Duration::from_secs(1));
    send_acked(&server, client, &accept());
    server.send_to(&packet(2, 4, 4, &[]), client).unwrap();
    assert!(matches!(
        result.recv_timeout(Duration::from_secs(1)).unwrap(),
        Err(DialError::Protocol(
            crate::session::CallSetupError::SequenceMismatch { .. }
        ))
    ));
}
