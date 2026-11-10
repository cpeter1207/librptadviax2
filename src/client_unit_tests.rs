use super::{
    DialError, DialOptions, IaxPeer, PeerEndpoint, PendingReliableFrame,
    acknowledge_reliable_frames, dial_ulaw, valid_node, wildcard_for,
};
use crate::{
    codec::IAX_FORMAT_ULAW,
    ingress::PeerIngressRouter,
    network::{SharedSocket, UdpEndpoint},
    protocol::{FullFrameHeader, serialize_full_frame},
    session::OutboundCallSetup,
};
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::Arc,
    time::{Duration, Instant},
};

thread_local! {
    static SEND_FAULT: std::cell::Cell<Option<(SocketAddr, std::io::ErrorKind)>> = const { std::cell::Cell::new(None) };
}

struct TimedCommitGate {
    remote: SocketAddr,
    timestamp: u32,
    reached: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}
static TIMED_COMMIT_GATE: std::sync::Mutex<Option<TimedCommitGate>> = std::sync::Mutex::new(None);
pub(super) fn timed_egress_commit_checkpoint(remote: SocketAddr, timestamp: u32) {
    let gate = {
        let mut slot = TIMED_COMMIT_GATE.lock().unwrap();
        if slot
            .as_ref()
            .is_some_and(|gate| gate.remote == remote && gate.timestamp == timestamp)
        {
            slot.take()
        } else {
            None
        }
    };
    if let Some(gate) = gate {
        gate.reached.send(()).unwrap();
        gate.release.recv_timeout(Duration::from_secs(2)).unwrap();
    }
}

/// Inject only the UDP send boundary; sequencing and received bytes remain real.
pub(super) fn send_fault(remote: SocketAddr) -> std::io::Result<()> {
    match SEND_FAULT.get() {
        Some((address, kind)) if address == remote => Err(kind.into()),
        _ => Ok(()),
    }
}

struct SendFault;

impl SendFault {
    fn set(remote: SocketAddr, kind: std::io::ErrorKind) -> Self {
        SEND_FAULT.set(Some((remote, kind)));
        Self
    }
}

impl Drop for SendFault {
    fn drop(&mut self) {
        SEND_FAULT.set(None);
    }
}

#[test]
fn egress_transport_observation_counts_actual_sends_and_backpressure() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = remote.local_addr().unwrap();
    let (mut peer, _producer) = shared_peer(address);
    let fixture = crate::jitter::fixture::Fixture::new();
    unsafe { peer.configure_jitter(fixture.descriptor()) }.unwrap();
    let fault = SendFault::set(address, std::io::ErrorKind::WouldBlock);
    assert_eq!(
        peer.send_prepared_ulaw(&[0xff; 160], 100).unwrap(),
        super::MediaSend::Accepted
    );
    peer.retry_reliable_frames().unwrap();
    let stats = peer.observe().unwrap();
    assert_eq!(
        (
            stats.egress_datagrams,
            stats.egress_would_block,
            stats.egress_reliable_retries,
            stats.egress_reliable_pending
        ),
        (0, 2, 0, 1)
    );
    drop(fault);
    peer.retry_reliable_frames().unwrap();
    peer.pending_reliable[0].next_retry = Instant::now();
    peer.retry_reliable_frames().unwrap();
    peer.acknowledge_reliable_frames(2);
    let stats = peer.observe().unwrap();
    assert_eq!(
        (
            stats.egress_datagrams,
            stats.egress_would_block,
            stats.egress_reliable_retries,
            stats.egress_reliable_pending
        ),
        (2, 2, 1, 0)
    );
    // The original observation prefix remains writable without touching a caller guard.
    let mut prefix = [0xa5u64; 15];
    let words = prefix.as_mut_ptr().cast::<u32>();
    unsafe {
        words.write(112);
        words.add(1).write(1);
    }
    let api = unsafe { &*crate::async_ffi::rptadv_iax2_async_descriptor_v1() };
    assert_eq!(
        unsafe {
            (api.peer_observe)(
                (&mut peer as *mut IaxPeer).cast(),
                prefix.as_mut_ptr().cast(),
            )
        },
        0
    );
    assert_eq!(prefix[14], 0xa5);
    assert_eq!(unsafe { words.read() }, 112);
}

#[test]
fn egress_congestion_preserves_sequence_and_epoch() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let address = remote.local_addr().unwrap();
    let mut peer = linked_peer(address);
    let mut bytes = [0; 1500];
    // Reach outgoing sequence 255 using real committed/acknowledged frames.
    for sequence in 1..255u8 {
        peer.send_text(b"L").unwrap();
        remote.recv_from(&mut bytes).unwrap();
        peer.acknowledge_reliable_frames(sequence.wrapping_add(1));
    }
    for (timestamp, sequence) in [(65_520, 255), (65_540, 0)] {
        let fault = SendFault::set(address, std::io::ErrorKind::WouldBlock);
        assert!(
            peer.send_ulaw(&[0.25; 160], timestamp).is_ok(),
            "committed full voice must survive WouldBlock"
        );
        assert_eq!(peer.pending_reliable.len(), 1);
        let retained = peer.pending_reliable[0].packet.clone();
        assert_eq!(
            peer.send_prepared_ulaw(&[0xff; 160], timestamp + 1)
                .unwrap(),
            super::MediaSend::WouldBlock
        );
        assert_eq!(peer.pending_reliable.len(), 1);
        assert_eq!(
            crate::protocol::parse_full_frame_packet(&retained)
                .unwrap()
                .header
                .outgoing_sequence,
            sequence
        );
        drop(fault);
        peer.retry_reliable_frames().unwrap();
        let count = remote.recv_from(&mut bytes).unwrap().0;
        assert_eq!(
            &bytes[..count],
            retained,
            "first successful send must not rebuild or retransmit the frame"
        );
        peer.acknowledge_reliable_frames(sequence.wrapping_add(1));
        assert!(peer.pending_reliable.is_empty());
    }
}

#[test]
fn egress_ack_cannot_retire_unsent_frame() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let _fault = SendFault::set(remote.local_addr().unwrap(), std::io::ErrorKind::WouldBlock);
    assert!(peer.send_text(b"L").is_ok());
    peer.acknowledge_reliable_frames(2);
    assert_eq!(
        peer.pending_reliable.len(),
        1,
        "ACK cannot cover a frame the socket has never accepted"
    );
}

#[test]
fn egress_abi2_encoder_retains_partial_input_and_preserves_a_short_g711_tail() {
    use crate::codec::providers::EncodeResultRaw;
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let api = unsafe { &*crate::ffi::rptadv_iax2_client_descriptor_v2() };
    let handle = (&mut peer as *mut IaxPeer).cast();
    let mut encoded = [0x55; 160];
    let mut result = EncodeResultRaw {
        struct_size: std::mem::size_of::<EncodeResultRaw>() as u32,
        ..Default::default()
    };
    for (input, capacity, flush, status, consumed, bytes, start, real) in [
        (37, 160, 0, 1, 37, 0, 0, 0),
        (123, 159, 0, 2, 0, 0, 0, 0),
        (123, 160, 0, 0, 123, 160, 0, 160),
        (3, 160, 0, 1, 3, 0, 0, 0),
        (0, 160, 1, 0, 0, 3, 160, 3),
    ] {
        let pcm = vec![0.25; input];
        assert_eq!(
            unsafe {
                api.prepare_audio.unwrap()(
                    handle,
                    pcm.as_ptr(),
                    pcm.len(),
                    encoded.as_mut_ptr(),
                    capacity,
                    flush,
                    &mut result,
                )
            },
            status
        );
        assert_eq!(result.status, status as u32);
        assert_eq!(
            (result.consumed_frames, result.encoded_bytes),
            (consumed, bytes)
        );
        if bytes != 0 {
            assert_eq!(
                (
                    result.source_start_frames,
                    result.source_frames,
                    result.packet_frames
                ),
                (start, real, bytes as u32)
            );
        }
    }
    assert_eq!(unsafe { api.reset_encoder.unwrap()(handle) }, 0);
    assert_eq!(
        unsafe {
            api.prepare_audio.unwrap()(
                handle,
                [0.25; 160].as_ptr(),
                160,
                encoded.as_mut_ptr(),
                160,
                0,
                &mut result,
            )
        },
        0
    );
    assert_eq!(result.source_start_frames, 0);
    for (flush, struct_size) in [
        (2, std::mem::size_of::<EncodeResultRaw>() as u32),
        (1, std::mem::size_of::<EncodeResultRaw>() as u32 - 1),
    ] {
        result.struct_size = struct_size;
        assert_eq!(
            unsafe {
                api.prepare_audio.unwrap()(
                    handle,
                    [].as_ptr(),
                    0,
                    encoded.as_mut_ptr(),
                    160,
                    flush,
                    &mut result,
                )
            },
            -1
        );
    }
    result.struct_size = std::mem::size_of::<EncodeResultRaw>() as u32;
    result.status = 99;
    peer.codecs = None;
    assert_eq!(
        unsafe {
            api.prepare_audio.unwrap()(
                handle,
                [].as_ptr(),
                0,
                encoded.as_mut_ptr(),
                160,
                1,
                &mut result,
            )
        },
        -1
    );
    assert_eq!(result.status, 99);
}

#[test]
fn egress_idle_marker_waits_for_full_voice_and_socket_recovery() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let address = remote.local_addr().unwrap();
    let mut peer = linked_peer(address);
    let api = unsafe { &*crate::ffi::rptadv_iax2_client_descriptor_v2() };
    let send = api.send_prepared_audio.unwrap();
    let handle = (&mut peer as *mut IaxPeer).cast();
    let payload = [0xff; 160];
    let fault = SendFault::set(address, std::io::ErrorKind::WouldBlock);
    assert_eq!(
        unsafe { send(handle, payload.as_ptr(), payload.len(), 160, 100) },
        0
    );
    assert_eq!(unsafe { send(handle, payload.as_ptr(), 0, 0, 120) }, 1);
    assert_eq!(peer.pending_reliable.len(), 1);

    let healthy = UdpSocket::bind("127.0.0.1:0").unwrap();
    healthy
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    linked_peer(healthy.local_addr().unwrap())
        .send_ulaw(&[0.25; 160], 100)
        .unwrap();
    let mut bytes = [0; 1500];
    assert!(healthy.recv_from(&mut bytes).unwrap().0 > 12);
    drop(fault);

    peer.retry_reliable_frames().unwrap();
    let count = remote.recv_from(&mut bytes).unwrap().0;
    assert_eq!(
        crate::protocol::parse_full_frame_packet(&bytes[..count])
            .unwrap()
            .payload,
        payload
    );
    let fault = SendFault::set(address, std::io::ErrorKind::WouldBlock);
    assert_eq!(unsafe { send(handle, payload.as_ptr(), 0, 0, 120) }, 1);
    drop(fault);
    assert_eq!(unsafe { send(handle, payload.as_ptr(), 0, 0, 120) }, 0);
    let count = remote.recv_from(&mut bytes).unwrap().0;
    assert_eq!(&bytes[..count], &[4, 210, 0, 120]);
}

#[test]
fn egress_mini_would_block_is_uncommitted() {
    use super::MediaSend;
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let address = remote.local_addr().unwrap();
    let mut peer = linked_peer(address);
    let mut bytes = [0; 1500];
    assert_eq!(
        peer.send_prepared_ulaw(&[0xff; 160], 100).unwrap(),
        MediaSend::Accepted
    );
    remote.recv_from(&mut bytes).unwrap();
    peer.acknowledge_reliable_frames(2);
    let fault = SendFault::set(address, std::io::ErrorKind::WouldBlock);
    assert!(matches!(
        peer.send_ulaw(&[0.25; 160], 120),
        Err(DialError::Network(error)) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    assert!(peer.wait_state().writable.is_none());
    assert_eq!(
        peer.send_prepared_ulaw(&[0x80; 160], 120).unwrap(),
        MediaSend::WouldBlock
    );
    assert_eq!(peer.voice_epoch, Some(0));
    assert!(peer.pending_reliable.is_empty());
    drop(fault);
    assert_eq!(
        peer.send_prepared_ulaw(&[0x80; 160], 120).unwrap(),
        MediaSend::Accepted
    );
    let count = remote.recv_from(&mut bytes).unwrap().0;
    assert_eq!(&bytes[..4], &[4, 210, 0, 120]);
    assert_eq!(&bytes[4..count], &[0x80; 160]);
    let _fault = SendFault::set(address, std::io::ErrorKind::PermissionDenied);
    assert!(
        matches!(peer.send_prepared_ulaw(&[0xff; 160], 140), Err(DialError::Network(error)) if error.kind() == std::io::ErrorKind::PermissionDenied)
    );
    let healthy = UdpSocket::bind("127.0.0.1:0").unwrap();
    linked_peer(healthy.local_addr().unwrap())
        .send_ulaw(&[0.0; 160], 140)
        .unwrap();
}

#[test]
fn egress_blocked_ack_does_not_prevent_inbound_delivery() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let address = remote.local_addr().unwrap();
    let mut peer = linked_peer(address);
    let incoming = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 5678,
            destination_call_number: 1234,
            retransmission: false,
            timestamp: 100,
            outgoing_sequence: 1,
            incoming_sequence: 1,
            frame_type: 7,
            subclass: 0,
            subclass_is_log: false,
        },
        b"L",
    )
    .unwrap();
    let fault = SendFault::set(address, std::io::ErrorKind::WouldBlock);
    let mut text = [0; 32];
    assert_eq!(
        peer.receive_event(&incoming, Instant::now(), &mut [], &mut text)
            .unwrap(),
        super::IaxPeerEvent::Text(1)
    );
    assert_eq!(text[0], b'L');
    drop(fault);
    peer.poll_event(&mut [], &mut text).unwrap();
    let mut bytes = [0; 1500];
    let count = remote.recv_from(&mut bytes).unwrap().0;
    let frame = crate::protocol::parse_full_frame_packet(&bytes[..count]).unwrap();
    assert_eq!(
        (
            frame.header.frame_type,
            frame.header.subclass,
            frame.header.incoming_sequence
        ),
        (6, 4, 2)
    );
}

#[test]
fn egress_full_window_ping_can_ack_before_committing_its_reply() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    for _ in 0..super::MAX_RELIABLE_WINDOW {
        peer.send_text(b"L").unwrap();
    }
    let mut ping = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 5678,
            destination_call_number: 1234,
            retransmission: false,
            timestamp: 100,
            outgoing_sequence: 1,
            incoming_sequence: 65,
            frame_type: 6,
            subclass: 2,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap();
    // Without ACK credit, neither PING nor LAGRQ may consume a sequence.
    for subclass in [2, 11] {
        ping[9] = 1;
        ping[11] = subclass;
        assert_eq!(
            peer.receive_event(&ping, Instant::now(), &mut [], &mut [])
                .unwrap(),
            super::IaxPeerEvent::None
        );
        assert_eq!(peer.pending_reliable.len(), super::MAX_RELIABLE_WINDOW);
    }
    ping[9] = 65;
    ping[11] = 2;
    peer.receive_event(&ping, Instant::now(), &mut [], &mut [])
        .unwrap();
    assert_eq!(peer.pending_reliable.len(), 1);
    let pong = crate::protocol::parse_full_frame_packet(&peer.pending_reliable[0].packet).unwrap();
    assert_eq!(
        (pong.header.subclass, pong.header.outgoing_sequence),
        (3, 65)
    );
}

#[test]
fn egress_prepared_oversize_is_rejected_before_committing_protocol_state() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote.set_nonblocking(true).unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let api = unsafe { &*crate::ffi::rptadv_iax2_client_descriptor_v2() };
    let payload = vec![0xff; super::MAX_PACKET_SIZE];
    assert_eq!(
        unsafe {
            api.send_prepared_audio.unwrap()(
                (&mut peer as *mut IaxPeer).cast(),
                payload.as_ptr(),
                payload.len(),
                payload.len() as u32,
                100,
            )
        },
        -1
    );
    assert!(peer.pending_reliable.is_empty());
    assert!(peer.voice_epoch.is_none());
    assert_eq!(
        remote.recv_from(&mut [0; 1500]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn egress_ack_flood_retains_recent_replies_and_delivers_every_text() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let address = remote.local_addr().unwrap();
    let mut peer = linked_peer(address);
    let fault = SendFault::set(address, std::io::ErrorKind::WouldBlock);
    for sequence in 1..=65 {
        let text = serialize_full_frame(
            &FullFrameHeader {
                source_call_number: 5678,
                destination_call_number: 1234,
                retransmission: false,
                timestamp: u32::from(sequence),
                outgoing_sequence: sequence,
                incoming_sequence: 1,
                frame_type: 7,
                subclass: 0,
                subclass_is_log: false,
            },
            &[sequence],
        )
        .unwrap();
        let mut received = [0];
        assert_eq!(
            peer.receive_event(&text, Instant::now(), &mut [], &mut received)
                .unwrap(),
            super::IaxPeerEvent::Text(1)
        );
        assert_eq!(received, [sequence]);
    }
    assert_eq!(peer.pending_replies.len(), 64);
    assert!(peer.pending_reliable.is_empty());
    drop(fault);
    peer.flush_replies().unwrap();
    for sequence in 3..=66 {
        let mut packet = [0; 1500];
        let count = remote.recv_from(&mut packet).unwrap().0;
        let ack = crate::protocol::parse_full_frame_packet(&packet[..count]).unwrap();
        assert_eq!(
            (ack.header.subclass, ack.header.incoming_sequence),
            (4, sequence)
        );
    }
    assert!(peer.pending_replies.is_empty());
}

#[test]
fn egress_blocked_send_has_a_bounded_unchanging_failure_deadline() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let _fault = SendFault::set(remote.local_addr().unwrap(), std::io::ErrorKind::WouldBlock);
    peer.send_text(b"L").unwrap();
    let deadline = peer.pending_reliable[0].expires_at;
    for _ in 0..3 {
        peer.retry_reliable_frames().unwrap();
        assert_eq!(peer.pending_reliable[0].expires_at, deadline);
        assert_eq!(peer.pending_reliable[0].retries, 0);
    }
    peer.pending_reliable[0].expires_at = Instant::now();
    assert!(matches!(
        peer.retry_reliable_frames(),
        Err(DialError::Timeout)
    ));
}

#[test]
fn vnak_rejects_invalid_identity_ack_or_payload_before_retiring_frames() {
    for (source, destination, acknowledgement, payload, error) in [
        (5679, 1234_u16, 2, &b""[..], 0),
        (5678, 1235, 2, &b""[..], 1),
        (5678, 1234, 3, &b""[..], 2),
        (5678, 1234, 193, &b""[..], 2),
        (5678, 1234, 2, &b"invalid"[..], 3),
    ] {
        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut peer = linked_peer(remote.local_addr().unwrap());
        peer.send_text(b"retained").unwrap();
        remote.recv_from(&mut [0; 1500]).unwrap();
        let original = &peer.pending_reliable[0];
        let state = (original.next_retry, original.expires_at, original.retries);
        let mut request = vnak_packet(acknowledgement);
        request[..2].copy_from_slice(&(0x8000_u16 | source).to_be_bytes());
        request[2..4].copy_from_slice(&destination.to_be_bytes());
        request.extend_from_slice(payload);
        let Err(DialError::Protocol(actual)) =
            peer.receive_event(&request, Instant::now(), &mut [], &mut [])
        else {
            panic!("invalid VNAK must be rejected before changing the send window");
        };
        use crate::session::CallSetupError;
        assert!(matches!(
            (error, actual),
            (0, CallSetupError::WrongSourceCall { .. })
                | (1, CallSetupError::WrongDestinationCall { .. })
                | (2, CallSetupError::SequenceMismatch { .. })
                | (3, CallSetupError::InvalidFrame)
        ));
        assert_eq!(peer.pending_reliable.len(), 1);
        let retained = &peer.pending_reliable[0];
        assert_eq!(
            (retained.next_retry, retained.expires_at, retained.retries),
            state
        );
        assert!(peer.pending_replies.is_empty());
    }
}

#[test]
fn vnak_backpressure_bounds_replay_copies_without_changing_reliable_state() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let address = remote.local_addr().unwrap();
    let mut peer = linked_peer(address);
    let mut bytes = [0; 1500];
    for payload in [b"first".as_slice(), b"second"] {
        peer.send_text(payload).unwrap();
        remote.recv_from(&mut bytes).unwrap();
    }
    for pending in &mut peer.pending_reliable {
        pending.next_retry = Instant::now();
    }
    peer.retry_reliable_frames().unwrap();
    for _ in 0..2 {
        remote.recv_from(&mut bytes).unwrap();
    }
    let fault = SendFault::set(address, std::io::ErrorKind::WouldBlock);
    peer.send_text(b"unsent third").unwrap();
    let before: Vec<_> = peer
        .pending_reliable
        .iter()
        .map(|frame| {
            (
                frame.next_retry,
                frame.expires_at,
                frame.retry_interval,
                frame.retries,
                frame.sent,
            )
        })
        .collect();
    // This valid-width but impossible ACK cannot retire the unsent third frame.
    // Its request must also not replay the earlier, already-sent positions.
    assert_eq!(
        peer.receive_event(&vnak_packet(4), Instant::now(), &mut [], &mut [])
            .unwrap(),
        super::IaxPeerEvent::None
    );
    assert_eq!(peer.pending_reliable.len(), 3);
    assert!(peer.pending_replies.is_empty());
    for _ in 0..=super::MAX_RELIABLE_WINDOW {
        assert_eq!(
            peer.receive_event(&vnak_packet(2), Instant::now(), &mut [], &mut [])
                .unwrap(),
            super::IaxPeerEvent::None
        );
    }
    assert_eq!(peer.pending_replies.len(), super::MAX_RELIABLE_WINDOW);
    assert_eq!(peer.pending_reliable.len(), 2);
    for (retained, original) in peer.pending_reliable.iter().zip(&before[1..]) {
        assert_eq!(
            (
                retained.next_retry,
                retained.expires_at,
                retained.retry_interval,
                retained.retries,
                retained.sent
            ),
            *original
        );
    }
    drop(fault);
    peer.flush_replies().unwrap();
    assert!(peer.pending_replies.is_empty());
    for _ in 0..super::MAX_RELIABLE_WINDOW {
        let length = remote.recv_from(&mut bytes).unwrap().0;
        let packet = crate::protocol::parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(packet.header.outgoing_sequence, 2);
        assert!(packet.header.retransmission);
        assert_eq!(packet.payload, b"second");
    }
    peer.retry_reliable_frames().unwrap();
    let length = remote.recv_from(&mut bytes).unwrap().0;
    let packet = crate::protocol::parse_full_frame_packet(&bytes[..length]).unwrap();
    assert_eq!(packet.header.outgoing_sequence, 3);
    assert!(!packet.header.retransmission);
    assert_eq!(packet.payload, b"unsent third");
}

fn vnak_packet(incoming_sequence: u8) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 5678,
            retransmission: false,
            destination_call_number: 1234,
            timestamp: 100,
            outgoing_sequence: 42,
            incoming_sequence,
            frame_type: 6,
            subclass: 18,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap()
}

fn linked_peer(remote: SocketAddr) -> IaxPeer {
    let mut peer = IaxPeer {
        endpoint: PeerEndpoint::Dedicated(UdpEndpoint::bind(wildcard_for(remote.ip())).unwrap()),
        remote,
        local_call: 1234,
        remote_call: 5678,
        format: IAX_FORMAT_ULAW,
        codecs: None,
        connected_at: Instant::now(),
        setup: OutboundCallSetup::for_inbound_call(1234, 5678).unwrap(),
        pending_reliable: VecDeque::new(),
        pending_replies: VecDeque::new(),
        pending_events: VecDeque::new(),
        direct_pcm: super::PacketPcm::default(),
        incoming_receipt: None,
        timed: super::timed::State::default(),
        egress: super::egress::State::default(),
        answered: true,
        voice_epoch: None,
        release_on_drop: None,
        provider_ownership: None,
        async_attached: false,
        product_deadline: None,
        send_stats: super::SendStatistics::default(),
        playout: None,
        poll_failure_reported: false,
    };
    peer.compose_codec(crate::ffi::test_peer_catalog()).unwrap();
    peer
}

fn shared_peer(remote: SocketAddr) -> (IaxPeer, crate::ingress::IngressProducer) {
    let socket = Arc::new(SharedSocket::new(UdpSocket::bind("127.0.0.1:0").unwrap()));
    let (producer, ingress) = crate::ingress::producer_ingress(64, 1).unwrap();
    let (peer, _) = IaxPeer::from_inbound(
        Arc::clone(&socket),
        ingress,
        socket.local_addr().unwrap(),
        remote,
        1234,
        5678,
        IAX_FORMAT_ULAW,
    )
    .unwrap();
    (peer, producer)
}

#[test]
fn timed_poll_retains_one_original_birth_across_partial_pcm_and_requires_exact_epoch_ack() {
    use super::{IaxPeerEvent, SourceTimeInput, TimedPeerEvent};
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let input = SourceTimeInput {
        host_clock_epoch: 7,
        reference_now_ns: 5_000_000_000,
        acknowledged_media_epoch: 0,
    };
    let first = peer.poll_timed(&mut [0.0; 40], &mut [], input).unwrap();
    assert!(first.discontinuity);
    assert_eq!(first.media_epoch, 1);
    let mut input = SourceTimeInput {
        acknowledged_media_epoch: 1,
        ..input
    };
    // Establish genuine RX timestamp availability with wire probes; no fabricated receipt.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let packet = crate::protocol::serialize_mini_frame(
            &crate::protocol::MiniFrameHeader {
                source_call_number: 5678,
                timestamp: 20,
            },
            &[0xff; 160],
        )
        .unwrap();
        remote.send_to(&packet, peer.local_addr().unwrap()).unwrap();
        let event = peer.poll_timed(&mut [0.0; 160], &mut [], input).unwrap();
        if event.discontinuity {
            assert_eq!(event.event, IaxPeerEvent::None);
            input.acknowledged_media_epoch = event.media_epoch;
        }
        if event.born_ns.is_some() {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    let packet = crate::protocol::serialize_mini_frame(
        &crate::protocol::MiniFrameHeader {
            source_call_number: 5678,
            timestamp: 40,
        },
        &[0x80; 160],
    )
    .unwrap();
    remote.send_to(&packet, peer.local_addr().unwrap()).unwrap();
    std::thread::sleep(Duration::from_millis(25));
    let first: TimedPeerEvent = peer.poll_timed(&mut [0.0; 40], &mut [], input).unwrap();
    assert_eq!(first.event, IaxPeerEvent::Audio(40));
    let birth = first
        .born_ns
        .expect("genuine kernel receipt survives decode");
    assert!(birth < input.reference_now_ns - 25_000_000);
    for suffix in 1..4 {
        let event = peer
            .poll_timed(
                &mut [0.0; 40],
                &mut [],
                SourceTimeInput {
                    reference_now_ns: input.reference_now_ns + 50_000_000,
                    ..input
                },
            )
            .unwrap();
        assert_eq!(event.event, IaxPeerEvent::Audio(40));
        assert_eq!(event.born_ns, Some(birth));
        assert_eq!(event.source_start, first.source_start + suffix * 40);
    }
    let changed = SourceTimeInput {
        host_clock_epoch: 8,
        ..input
    };
    let reset = peer.poll_timed(&mut [0.0; 160], &mut [], changed).unwrap();
    assert!(reset.discontinuity);
    assert_eq!(reset.media_epoch, input.acknowledged_media_epoch + 1);
    assert!(
        peer.poll_timed(&mut [0.0; 160], &mut [], changed)
            .unwrap()
            .discontinuity,
        "stale ack1 cannot acknowledge target2"
    );
    assert!(
        !peer
            .poll_timed(
                &mut [0.0; 160],
                &mut [],
                SourceTimeInput {
                    acknowledged_media_epoch: reset.media_epoch,
                    ..changed
                }
            )
            .unwrap()
            .discontinuity
    );
}

#[test]
fn caller_supplied_ingress_instant_never_qualifies_timed_audio() {
    use super::{IaxPeerEvent, SourceTimeInput};
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (mut peer, mut producer) = shared_peer(remote.local_addr().unwrap());
    let input = SourceTimeInput {
        host_clock_epoch: 1,
        reference_now_ns: u64::MAX,
        acknowledged_media_epoch: 0,
    };
    assert!(
        peer.poll_timed(&mut [], &mut [], input)
            .unwrap()
            .discontinuity
    );
    let packet = crate::protocol::serialize_mini_frame(
        &crate::protocol::MiniFrameHeader {
            source_call_number: 5678,
            timestamp: 20,
        },
        &[0xff; 160],
    )
    .unwrap();
    producer
        .try_push_at(remote.local_addr().unwrap(), &packet, Instant::now())
        .unwrap();
    let event = peer
        .poll_timed(
            &mut [0.0; 160],
            &mut [],
            SourceTimeInput {
                acknowledged_media_epoch: 1,
                ..input
            },
        )
        .unwrap();
    assert_eq!(event.event, IaxPeerEvent::Audio(160));
    assert_eq!(event.born_ns, None);
    assert!(matches!(
        peer.poll_event(&mut [], &mut []),
        Err(DialError::InvalidOptions)
    ));
    assert!(
        peer.poll_timed(
            &mut [],
            &mut [],
            super::SourceTimeInput {
                host_clock_epoch: 2,
                ..input
            }
        )
        .unwrap()
        .discontinuity
    );
}

#[test]
fn actual_clock_loss_before_or_after_decode_retires_media_and_preserves_private_untimed_control() {
    const CHILD: &str = "RPTADV_IAX_PEER_CLOCK_CHILD";
    let Some(selection) = std::env::var_os(CHILD) else {
        let (path, _library) = crate::source_time::tests::fault_library();
        for selection in ["before", "publish"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "client::unit_tests::actual_clock_loss_before_or_after_decode_retires_media_and_preserves_private_untimed_control", "--nocapture"])
                .env(CHILD, selection).env("LD_PRELOAD", &path).output().unwrap();
            assert!(
                output.status.success(),
                "{selection}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    };
    let _probe = crate::source_time::tests::timestamp_probe();
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let input = super::SourceTimeInput {
        host_clock_epoch: 1,
        reference_now_ns: 5_000_000_000,
        acknowledged_media_epoch: 0,
    };
    assert!(
        peer.poll_timed(&mut [], &mut [], input)
            .unwrap()
            .discontinuity
    );
    let input = super::SourceTimeInput {
        acknowledged_media_epoch: 1,
        ..input
    };
    let packet = crate::protocol::serialize_mini_frame(
        &crate::protocol::MiniFrameHeader {
            source_call_number: 5678,
            timestamp: 20,
        },
        &[0x80; 160],
    )
    .unwrap();
    remote.send_to(&packet, peer.local_addr().unwrap()).unwrap();
    let mut first_pcm = vec![0.0; if selection == "before" { 40 } else { 160 }];
    let first = peer.poll_timed(&mut first_pcm, &mut [], input).unwrap();
    assert!(first.born_ns.is_some());
    let library =
        unsafe { libloading::Library::new(std::env::var_os("LD_PRELOAD").unwrap()) }.unwrap();
    if selection == "before" {
        let fd = match &peer.endpoint {
            PeerEndpoint::Dedicated(endpoint) => {
                endpoint.shared_socket().source_clock.monitor_fd().unwrap()
            }
            _ => unreachable!(),
        };
        let cancel = unsafe {
            library.get::<unsafe extern "C" fn(i32) -> i32>(b"rptadv_test_cancel_timerfd\0")
        }
        .unwrap();
        assert_eq!(unsafe { cancel(fd) }, 0);
    } else {
        // pre-poll check, RX map pre-check, RX map post-check succeed; the
        // fourth actual realtime read fails at the final publication fence.
        let fail = unsafe {
            library.get::<unsafe extern "C" fn(u32)>(b"rptadv_test_fail_realtime_after\0")
        }
        .unwrap();
        unsafe { fail(3) };
    }
    if selection == "publish" {
        remote.send_to(&packet, peer.local_addr().unwrap()).unwrap();
    } else {
        assert_eq!(peer.direct_pcm.remaining(), 120);
    }
    let reset = peer.poll_timed(&mut [0.0; 40], &mut [], input).unwrap();
    assert_eq!(
        (reset.media_epoch, reset.event, reset.born_ns),
        (2, super::IaxPeerEvent::None, None)
    );
    assert!(reset.discontinuity);
    assert_eq!(peer.direct_pcm.remaining(), 0);
    assert!(
        peer.poll_timed(&mut [], &mut [], input)
            .unwrap()
            .discontinuity
    );
    let acknowledged = super::SourceTimeInput {
        acknowledged_media_epoch: 2,
        ..input
    };
    let _ = peer
        .poll_timed(&mut [0.0; 160], &mut [], acknowledged)
        .unwrap();
    remote.send_to(&packet, peer.local_addr().unwrap()).unwrap();
    let private = peer
        .poll_timed(&mut [0.0; 160], &mut [], acknowledged)
        .unwrap();
    assert_eq!(
        (private.event, private.born_ns, private.discontinuity),
        (super::IaxPeerEvent::Audio(160), None, false)
    );
    let digit = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 5678,
            destination_call_number: 1234,
            retransmission: false,
            timestamp: 40,
            outgoing_sequence: 1,
            incoming_sequence: 1,
            frame_type: 1,
            subclass_is_log: false,
            subclass: b'5',
        },
        &[],
    )
    .unwrap();
    remote.send_to(&digit, peer.local_addr().unwrap()).unwrap();
    let digit = peer.poll_timed(&mut [], &mut [0; 1], acknowledged).unwrap();
    assert_eq!(
        (digit.event, digit.born_ns),
        (super::IaxPeerEvent::Digit(b'5'), None)
    );
}

#[test]
fn actual_retained_pcm_and_kernel_queue_expiry_retire_epochs_without_relabeling_old_audio() {
    use super::{IaxPeerEvent, SourceTimeInput};
    for retain_pcm in [false, true] {
        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut peer = linked_peer(remote.local_addr().unwrap());
        let input = SourceTimeInput {
            host_clock_epoch: 1,
            reference_now_ns: 5_000_000_000,
            acknowledged_media_epoch: 0,
        };
        assert!(
            peer.poll_timed(&mut [], &mut [], input)
                .unwrap()
                .discontinuity
        );
        let mut input = SourceTimeInput {
            acknowledged_media_epoch: 1,
            ..input
        };
        let packet = crate::protocol::serialize_mini_frame(
            &crate::protocol::MiniFrameHeader {
                source_call_number: 5678,
                timestamp: 20,
            },
            &[0x80; 160],
        )
        .unwrap();
        // Prime actual kernel stamp activation before this distinct retained packet.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            remote.send_to(&packet, peer.local_addr().unwrap()).unwrap();
            let event = peer.poll_timed(&mut [0.0; 160], &mut [], input).unwrap();
            if event.discontinuity {
                assert_eq!(event.event, IaxPeerEvent::None);
                input.acknowledged_media_epoch = event.media_epoch;
            }
            if event.born_ns.is_some() {
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        remote.send_to(&packet, peer.local_addr().unwrap()).unwrap();
        if retain_pcm {
            assert_eq!(
                peer.poll_timed(&mut [0.0; 40], &mut [], input)
                    .unwrap()
                    .event,
                IaxPeerEvent::Audio(40)
            );
            assert_eq!(peer.direct_pcm.remaining(), 120);
        }
        std::thread::sleep(Duration::from_millis(510));
        let mut untouched = [0.25; 160];
        let reset = peer.poll_timed(&mut untouched, &mut [], input).unwrap();
        assert!(reset.discontinuity);
        assert_eq!(
            (reset.media_epoch, reset.event, reset.born_ns),
            (input.acknowledged_media_epoch + 1, IaxPeerEvent::None, None)
        );
        assert_eq!(untouched, [0.25; 160]);
        assert_eq!(peer.direct_pcm.remaining(), 0);
        assert!(
            peer.poll_timed(&mut untouched, &mut [], input)
                .unwrap()
                .discontinuity
        );
        assert!(
            !peer
                .poll_timed(
                    &mut untouched,
                    &mut [],
                    SourceTimeInput {
                        acknowledged_media_epoch: reset.media_epoch,
                        ..input
                    }
                )
                .unwrap()
                .discontinuity
        );
    }
}

#[test]
fn async_timed_owner_wakes_for_original_history_expiry_after_real_jitter_goes_quiet() {
    let _probe = crate::source_time::tests::timestamp_probe();
    let runtime = crate::provider_tests::runtime();
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let local = peer.local_addr().unwrap();
    let paths = std::fs::read_dir("/usr/lib")
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| {
            entry
                .path()
                .join("rpt_advanced/librptadv_jitter_adapter.so.1")
        })
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 1);
    let library = unsafe { libloading::Library::new(&paths[0]) }.unwrap();
    let entry = unsafe {
        library.get::<unsafe extern "C" fn() -> *const std::ffi::c_void>(
            b"rptadv_jitter_adapter_descriptor_v1\0",
        )
    }
    .unwrap();
    unsafe { peer.configure_jitter(entry()) }.unwrap();
    peer.set_product_deadline(u64::MAX).unwrap();
    let (wake, ingress) = peer.prepare_async_ingress(runtime.handle()).unwrap();
    let (socket, producer, owner) = ingress.unwrap();
    let pump = crate::async_driver::DatagramPump::from_socket(
        runtime.handle(),
        socket,
        remote.local_addr().unwrap(),
        producer,
        Some(owner),
    );
    let (sender, events) = std::sync::mpsc::channel();
    let started = Instant::now();
    let mut acknowledged = 0;
    let driver = crate::async_driver::PeerDriver::attach(runtime.handle(), wake, move || {
        let input = super::SourceTimeInput {
            host_clock_epoch: 1,
            reference_now_ns: 1_000_000_000 + started.elapsed().as_nanos() as u64,
            acknowledged_media_epoch: acknowledged,
        };
        let event = peer
            .poll_timed(&mut [0.0; 160], &mut [0; 1], input)
            .unwrap();
        if event.discontinuity || event.event != super::IaxPeerEvent::None {
            sender.send(event).unwrap();
        }
        if event.discontinuity {
            acknowledged = event.media_epoch;
        }
        Some(peer.wait_state())
    });
    let initial = events.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(initial.discontinuity);
    assert_eq!(initial.media_epoch, 1);
    let packet = crate::protocol::serialize_mini_frame(
        &crate::protocol::MiniFrameHeader {
            source_call_number: 5678,
            timestamp: 20,
        },
        &[0xff; 160],
    )
    .unwrap();
    remote.send_to(&packet, local).unwrap();
    let audio = events.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(audio.event, super::IaxPeerEvent::Audio(160));
    assert!(audio.born_ns.is_some());
    let expired = events.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        (expired.media_epoch, expired.event, expired.discontinuity),
        (2, super::IaxPeerEvent::None, true)
    );
    driver.stop();
    driver.detach();
    pump.detach();
    drop(library);
}

#[test]
fn real_routed_old_receipts_are_rejected_at_ingress_or_after_a_host_epoch_retirement() {
    let _probe = crate::source_time::tests::timestamp_probe();
    for expired in [true, false] {
        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (mut peer, mut producer) = shared_peer(remote.local_addr().unwrap());
        let input = super::SourceTimeInput {
            host_clock_epoch: 1,
            reference_now_ns: 5_000_000_000,
            acknowledged_media_epoch: 0,
        };
        assert!(
            peer.poll_timed(&mut [], &mut [], input)
                .unwrap()
                .discontinuity
        );
        let packet = crate::protocol::serialize_mini_frame(
            &crate::protocol::MiniFrameHeader {
                source_call_number: 5678,
                timestamp: 20,
            },
            &[0xff; 160],
        )
        .unwrap();
        remote.send_to(&packet, peer.local_addr().unwrap()).unwrap();
        let mut bytes = [0; 256];
        let (count, source, receipt) = match &peer.endpoint {
            PeerEndpoint::Shared { socket, .. } => {
                socket.receive_timed(&mut bytes).unwrap().unwrap()
            }
            _ => unreachable!(),
        };
        assert!(receipt.is_some());
        if expired {
            std::thread::sleep(Duration::from_millis(510));
        }
        producer
            .try_push_received(source, &bytes[..count], receipt.unwrap().instant, receipt)
            .unwrap();
        let input = super::SourceTimeInput {
            host_clock_epoch: if expired { 1 } else { 2 },
            acknowledged_media_epoch: 1,
            ..input
        };
        let event = peer.poll_timed(&mut [0.0; 160], &mut [], input).unwrap();
        assert_eq!(
            (
                event.media_epoch,
                event.event,
                event.born_ns,
                event.discontinuity
            ),
            (2, super::IaxPeerEvent::None, None, true)
        );
    }
}

#[test]
fn actual_unknown_and_kernel_qualified_source_history_transitions_require_new_retirement_targets() {
    let _probe = crate::source_time::tests::timestamp_probe();
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (mut peer, mut producer) = shared_peer(remote.local_addr().unwrap());
    let mut input = super::SourceTimeInput {
        host_clock_epoch: 1,
        reference_now_ns: 5_000_000_000,
        acknowledged_media_epoch: 1,
    };
    let packet = crate::protocol::serialize_mini_frame(
        &crate::protocol::MiniFrameHeader {
            source_call_number: 5678,
            timestamp: 20,
        },
        &[0xff; 160],
    )
    .unwrap();
    producer
        .try_push_at(remote.local_addr().unwrap(), &packet, Instant::now())
        .unwrap();
    let unknown = peer.poll_timed(&mut [0.0; 160], &mut [], input).unwrap();
    assert_eq!(
        (unknown.event, unknown.born_ns),
        (super::IaxPeerEvent::Audio(160), None)
    );
    for step in 0..2 {
        remote.send_to(&packet, peer.local_addr().unwrap()).unwrap();
        let mut bytes = [0; 256];
        let (count, source, receipt) = match &peer.endpoint {
            PeerEndpoint::Shared { socket, .. } => {
                socket.receive_timed(&mut bytes).unwrap().unwrap()
            }
            _ => unreachable!(),
        };
        let receipt = receipt.unwrap();
        producer
            .try_push_received(source, &bytes[..count], receipt.instant, Some(receipt))
            .unwrap();
        let event = peer.poll_timed(&mut [0.0; 160], &mut [], input).unwrap();
        if step == 0 {
            assert_eq!(
                (event.media_epoch, event.event, event.discontinuity),
                (2, super::IaxPeerEvent::None, true)
            );
            input.acknowledged_media_epoch = 2;
        } else {
            assert!(event.born_ns.is_some());
        }
    }
    producer
        .try_push_at(remote.local_addr().unwrap(), &packet, Instant::now())
        .unwrap();
    let reset = peer.poll_timed(&mut [0.0; 160], &mut [], input).unwrap();
    assert_eq!(
        (reset.media_epoch, reset.event, reset.discontinuity),
        (3, super::IaxPeerEvent::None, true)
    );
}

#[test]
fn timed_egress_requires_activation_complete_retirement_and_supported_twenty_millisecond_shape() {
    use super::{EgressRetirement, EgressTime};
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let time = EgressTime {
        epoch: 0,
        deadline_ms: 500,
    };
    assert!(matches!(
        peer.send_prepared_audio_timed(&[0xff; 160], 160, 0, time),
        Err(DialError::InvalidOptions)
    ));
    peer.send_prepared_audio(&[0xff; 160], 160, 0).unwrap();
    assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Pending);
    assert!(matches!(
        peer.send_prepared_audio_timed(&[0xff; 160], 160, 0, time),
        Err(DialError::InvalidOptions)
    ));
    let mut fresh = linked_peer(remote.local_addr().unwrap());
    let EgressRetirement::Complete(epoch) = fresh.retire_egress().unwrap() else {
        panic!("fresh");
    };
    assert!(matches!(
        fresh.send_prepared_audio_timed(
            &[0xff; 80],
            160,
            0,
            EgressTime {
                epoch,
                deadline_ms: 500
            }
        ),
        Err(DialError::InvalidOptions)
    ));
}

#[test]
fn real_jitter_retained_packet_expires_before_decode_and_resets_its_actual_queue() {
    let _probe = crate::source_time::tests::timestamp_probe();
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let paths = std::fs::read_dir("/usr/lib")
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| {
            entry
                .path()
                .join("rpt_advanced/librptadv_jitter_adapter.so.1")
        })
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 1);
    let library = unsafe { libloading::Library::new(&paths[0]) }.unwrap();
    let entry = unsafe {
        library.get::<unsafe extern "C" fn() -> *const std::ffi::c_void>(
            b"rptadv_jitter_adapter_descriptor_v1\0",
        )
    }
    .unwrap();
    unsafe { peer.configure_jitter(entry()) }.unwrap();
    let input = super::SourceTimeInput {
        host_clock_epoch: 1,
        reference_now_ns: 5_000_000_000,
        acknowledged_media_epoch: 1,
    };
    let packet = crate::protocol::serialize_mini_frame(
        &crate::protocol::MiniFrameHeader {
            source_call_number: 5678,
            timestamp: 20,
        },
        &[0xff; 160],
    )
    .unwrap();
    remote.send_to(&packet, peer.local_addr().unwrap()).unwrap();
    assert_eq!(
        peer.poll_timed(&mut [0.0; 160], &mut [], input)
            .unwrap()
            .event,
        super::IaxPeerEvent::None
    );
    assert_eq!(
        peer.playout
            .as_ref()
            .unwrap()
            .observe()
            .unwrap()
            .queued_packets,
        1
    );
    std::thread::sleep(Duration::from_millis(510));
    let reset = peer.poll_timed(&mut [0.0; 160], &mut [], input).unwrap();
    assert_eq!(
        (reset.media_epoch, reset.event, reset.discontinuity),
        (2, super::IaxPeerEvent::None, true)
    );
    assert_eq!(
        peer.playout
            .as_ref()
            .unwrap()
            .observe()
            .unwrap()
            .queued_packets,
        0
    );
    drop(peer);
    drop(library);
}

#[test]
fn ingress_large_direct_codec_packet_is_decoded_once_and_drained_in_caller_chunks() {
    use super::IaxPeerEvent;
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let voice = crate::protocol::serialize_mini_frame(
        &crate::protocol::MiniFrameHeader {
            source_call_number: 5678,
            timestamp: 20,
        },
        &[0x80; 2000],
    )
    .unwrap();
    let mut pcm = [0.0; 160];
    assert_eq!(
        peer.receive_event(&voice, Instant::now(), &mut pcm, &mut [])
            .unwrap(),
        IaxPeerEvent::Audio(160)
    );
    let mut total = 160;
    while let IaxPeerEvent::Audio(count) = peer.poll_event(&mut pcm, &mut []).unwrap() {
        assert!(count <= pcm.len());
        assert!(pcm[..count].iter().all(|sample| *sample > 0.9));
        total += count;
    }
    assert_eq!(total, 2000);
}

#[test]
fn ingress_pending_early_audio_can_be_read_with_smaller_buffers() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    peer.pending_events.push_back(super::PendingEvent {
        event: super::IaxPeerEvent::Audio(480),
        pcm: super::PacketPcm {
            samples: vec![0.25; 480],
            position: 0,
            span: crate::source_time::Span::default(),
        },
        text: Vec::new(),
    });
    assert!(
        matches!(peer.poll_event(&mut [], &mut []), Err(DialError::Provider(error)) if error.required_capacity == 1)
    );
    assert_eq!(peer.pending_events.len(), 1);
    for _ in 0..3 {
        let mut pcm = [0.0; 160];
        assert_eq!(
            peer.poll_event(&mut pcm, &mut []).unwrap(),
            super::IaxPeerEvent::Audio(160)
        );
        assert_eq!(pcm, [0.25; 160]);
    }
    assert!(peer.pending_events.is_empty());
    assert_eq!(
        peer.poll_event(&mut [0.0; 160], &mut []).unwrap(),
        super::IaxPeerEvent::None
    );
}

#[test]
fn empty_voice_preserves_sequence_without_entering_media_playout() {
    use super::IaxPeerEvent;
    use crate::protocol::{MiniFrameHeader, parse_full_frame_packet, serialize_mini_frame};

    for jitter in [true, false] {
        for full in [true, false] {
            let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
            remote.set_nonblocking(true).unwrap();
            let mut peer = linked_peer(remote.local_addr().unwrap());
            let fixture = crate::jitter::fixture::Fixture::new();
            let origin = Instant::now();
            let mut pcm = [42.0; 160];
            let mut text = [42; 32];
            let timestamp = (0x1_0000_0000 + 1000) * 8;
            if jitter {
                unsafe { peer.configure_jitter(fixture.descriptor()) }.unwrap();
                let playout = peer.playout.as_mut().unwrap();
                playout.unkey();
                assert_eq!(
                    playout.poll(origin, &mut pcm).unwrap(),
                    IaxPeerEvent::RadioUnkey
                );
                fixture.packet(0, timestamp, &[0x80; 160], 0);
                // The real jitter provider rejects zero-span packets.
                fixture.admission(-1);
            }
            let mut header = FullFrameHeader {
                source_call_number: 5678,
                destination_call_number: 1234,
                retransmission: false,
                timestamp: 0xffff_0000,
                outgoing_sequence: 1,
                incoming_sequence: 1,
                frame_type: 2,
                subclass: 4,
                subclass_is_log: false,
            };
            let marker = if full {
                serialize_full_frame(&header, &[]).unwrap()
            } else {
                serialize_mini_frame(
                    &MiniFrameHeader {
                        source_call_number: 5678,
                        timestamp: 0xffff,
                    },
                    &[],
                )
                .unwrap()
            };
            assert_eq!(
                peer.receive_event(&marker, origin, &mut pcm, &mut text)
                    .unwrap(),
                IaxPeerEvent::None,
                "empty voice is not media: jitter={jitter} full={full}"
            );
            assert_eq!(pcm, [42.0; 160]);
            assert_eq!(text, [42; 32]);
            assert!(fixture.puts().is_empty());
            assert_eq!(
                peer.poll_event(&mut pcm, &mut text).unwrap(),
                IaxPeerEvent::None
            );
            assert!(
                fixture.advances().is_empty(),
                "idle marker must not reactivate playout"
            );

            let mut reply = [0; 1500];
            let next = if full {
                let length = remote.recv_from(&mut reply).unwrap().0;
                let ack = parse_full_frame_packet(&reply[..length]).unwrap();
                assert_eq!(
                    (
                        ack.header.frame_type,
                        ack.header.subclass,
                        ack.header.incoming_sequence
                    ),
                    (6, 4, 2)
                );
                2
            } else {
                assert_eq!(
                    remote.recv_from(&mut reply).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                1
            };
            fixture.admission(0);
            header.timestamp = 1000;
            header.outgoing_sequence = next;
            let voice = serialize_full_frame(&header, &[0x80; 160]).unwrap();
            let event = peer
                .receive_event(&voice, origin, &mut pcm, &mut text)
                .unwrap();
            if jitter {
                assert_eq!(event, IaxPeerEvent::None);
                assert_eq!(
                    peer.poll_event(&mut pcm, &mut text).unwrap(),
                    IaxPeerEvent::Audio(160)
                );
                let puts = fixture.puts();
                assert_eq!(puts.len(), 1);
                assert_eq!((puts[0].0, puts[0].1), (timestamp, 160));
            } else {
                assert_eq!(event, IaxPeerEvent::Audio(160));
            }
            assert!(pcm.iter().all(|value| *value > 0.9));
            header.outgoing_sequence += 1;
            header.frame_type = 7;
            header.subclass = 0;
            let control = serialize_full_frame(&header, b"L").unwrap();
            assert_eq!(
                peer.receive_event(&control, origin, &mut pcm, &mut text)
                    .unwrap(),
                IaxPeerEvent::Text(1)
            );
            assert_eq!(text[0], b'L');
        }
    }
}

#[test]
fn egress_blocked_readiness_does_not_spin_on_an_expired_retry_timer() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (mut peer, _producer) = shared_peer(remote.local_addr().unwrap());
    peer.prepare_async_ingress(runtime.handle()).unwrap();
    peer.set_product_deadline(u64::MAX).unwrap();
    assert!(peer.wait_state().deadline.is_none());
    peer.begin_turn();
    let fault = SendFault::set(remote.local_addr().unwrap(), std::io::ErrorKind::WouldBlock);
    assert_eq!(
        peer.send_prepared_ulaw(&[0x80], 1000).unwrap(),
        super::MediaSend::Accepted
    );
    let wait = peer.wait_state();
    assert!(wait.writable.is_some());
    assert_eq!(
        wait.deadline,
        Some(peer.pending_reliable.front().unwrap().expires_at)
    );
    drop(fault);
    peer.begin_turn();
    assert!(
        peer.wait_state().writable.is_none(),
        "no stale interest after product expiry"
    );
}

#[test]
fn failed_shared_ingress_is_terminal_and_dedicated_observation_is_rejected() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dedicated = linked_peer(remote.local_addr().unwrap());
    assert!(matches!(
        dedicated.observe(),
        Err(DialError::InvalidOptions)
    ));
    let (mut peer, producer) = shared_peer(remote.local_addr().unwrap());
    producer.fail();
    assert!(matches!(
        peer.poll_event(&mut [0.0; 160], &mut [0; 1500]),
        Err(DialError::Network(error)) if error.kind() == std::io::ErrorKind::ConnectionAborted
    ));
}

#[test]
fn composed_controls_hold_next_burst_transport_until_prior_tail_and_unkey() {
    use super::IaxPeerEvent;

    let remote_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let remote = remote_socket.local_addr().unwrap();
    let (mut peer, mut producer) = shared_peer(remote);
    let fixture = crate::jitter::fixture::Fixture::new();
    let origin = Instant::now();
    peer.connected_at = origin;
    unsafe { peer.configure_jitter(fixture.descriptor()) }.unwrap();
    let first = (0x1_0000_0000 + 1000) * 8;
    fixture.packet(0, first, &[0x80; 160], 0);
    for (sequence, timestamp, frame_type, subclass, payload) in [
        (1, 1000, 4, 12, &[][..]),
        (2, 1000, 2, 4, &[0xff; 160][..]),
        (3, 1020, 4, 13, &[][..]),
        (4, 1040, 4, 12, &[][..]),
        (5, 1040, 7, 0, &b"next"[..]),
    ] {
        let packet = serialize_full_frame(
            &FullFrameHeader {
                source_call_number: 5678,
                retransmission: false,
                destination_call_number: 1234,
                timestamp,
                outgoing_sequence: sequence,
                incoming_sequence: 1,
                frame_type,
                subclass,
                subclass_is_log: false,
            },
            payload,
        )
        .unwrap();
        producer.try_push_at(remote, &packet, origin).unwrap();
    }
    let mut pcm = [0.0; 160];
    let mut text = [0; 1500];
    assert_eq!(
        peer.poll_event(&mut pcm, &mut text).unwrap(),
        IaxPeerEvent::RadioKey
    );
    assert_eq!(
        peer.poll_event(&mut pcm, &mut text).unwrap(),
        IaxPeerEvent::Audio(160)
    );
    assert!(pcm.iter().all(|value| *value > 0.9));
    for expected in [IaxPeerEvent::RadioUnkey, IaxPeerEvent::RadioKey] {
        assert_eq!(peer.observe().unwrap().ingress_queued_packets, 1);
        assert_eq!(peer.poll_event(&mut pcm, &mut text).unwrap(), expected);
    }
    assert_eq!(
        peer.poll_event(&mut pcm, &mut text).unwrap(),
        IaxPeerEvent::Text(4)
    );
    assert_eq!(&text[..4], b"next");
    assert_eq!(peer.observe().unwrap().ingress_queued_packets, 0);
}

#[test]
fn ffi_gap_is_a_sample_count_without_pcm_or_text_writes() {
    let mut peer = linked_peer("127.0.0.1:4567".parse().unwrap());
    let fixture = crate::jitter::fixture::Fixture::new();
    unsafe { peer.configure_jitter(fixture.descriptor()) }.unwrap();
    fixture.packet(0, 1000, &[0x80; 80], 20);
    let descriptor = unsafe { &*crate::ffi::rptadv_iax2_client_descriptor_v2() };
    let mut pcm = [42.0; 160];
    let mut text = [42; 32];
    let mut kind = u32::MAX;
    let mut length = usize::MAX;
    for expected in [
        (crate::ffi::RPTADV_IAX2_EVENT_GAP, 20),
        (crate::ffi::RPTADV_IAX2_EVENT_AUDIO, 80),
    ] {
        assert_eq!(
            unsafe {
                descriptor.poll.unwrap()(
                    (&mut peer as *mut IaxPeer).cast(),
                    pcm.as_mut_ptr(),
                    pcm.len(),
                    text.as_mut_ptr(),
                    text.len(),
                    &mut kind,
                    &mut length,
                )
            },
            0
        );
        assert_eq!((kind, length), expected);
        assert_eq!(text, [42; 32]);
        if kind == crate::ffi::RPTADV_IAX2_EVENT_GAP {
            assert_eq!(pcm, [42.0; 160]);
        } else {
            assert!(pcm[..80].iter().all(|value| *value > 0.9));
            assert_eq!(pcm[80..], [42.0; 80]);
        }
    }
}

#[test]
fn async_ingress_transfers_dedicated_receive_ownership_only_once() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut peer = linked_peer("127.0.0.1:4569".parse().unwrap());
    let (_, source) = peer.prepare_async_ingress(runtime.handle()).unwrap();
    assert!(source.is_some());
    assert!(matches!(peer.endpoint, PeerEndpoint::Shared { .. }));
    assert!(matches!(peer.prepare_async_ingress(runtime.handle()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists));
}

#[test]
fn async_descriptor_attaches_and_stops_the_existing_dedicated_peer_fixture() {
    use std::{ffi::c_void, ptr};
    unsafe extern "C" fn step(_: *mut c_void) -> i32 {
        0
    }
    let mut peer = linked_peer("127.0.0.1:4569".parse().unwrap());
    let api = unsafe { &*crate::async_ffi::rptadv_iax2_async_descriptor_v1() };
    let mut runtime = ptr::null_mut();
    let mut registration = ptr::null_mut();
    unsafe {
        assert_eq!((api.runtime_create)(&mut runtime), 0);
        assert_eq!(
            (api.peer_attach)(
                runtime,
                (&mut peer as *mut IaxPeer).cast(),
                Some(step),
                ptr::null_mut(),
                &mut registration
            ),
            0
        );
        (api.peer_stop)(registration);
        (api.peer_detach)(registration);
        (api.runtime_destroy)(runtime);
    }
}

#[test]
fn composed_jitter_admits_a_receive_batch_before_fetching_due_media() {
    let fixture = crate::jitter::fixture::Fixture::new();
    let origin = Instant::now() - Duration::from_millis(100);
    let first = (0x1_0000_0000 + 1000) * 8;
    fixture.packet(60_000_000, first, &[0x80; 160], 0);
    let socket = Arc::new(SharedSocket::new(UdpSocket::bind("127.0.0.1:0").unwrap()));
    let remote = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let (mut producer, ingress) = crate::ingress::producer_ingress(64, 1).unwrap();
    let (mut peer, _) = IaxPeer::from_inbound(
        Arc::clone(&socket),
        ingress,
        socket.local_addr().unwrap(),
        remote,
        1234,
        5678,
        IAX_FORMAT_ULAW,
    )
    .unwrap();
    peer.connected_at = origin;
    unsafe { peer.configure_jitter(fixture.descriptor()) }.unwrap();
    let full = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 5678,
            retransmission: false,
            destination_call_number: 1234,
            timestamp: 1000,
            outgoing_sequence: 1,
            incoming_sequence: 1,
            frame_type: 2,
            subclass: 4,
            subclass_is_log: false,
        },
        &[0xff; 160],
    )
    .unwrap();
    producer.try_push_at(remote, &full, origin).unwrap();
    for (timestamp, arrival) in [(1040u16, 20), (1020, 30)] {
        let mut packet = Vec::from(5678u16.to_be_bytes());
        packet.extend_from_slice(&timestamp.to_be_bytes());
        packet.extend_from_slice(&[0; 160]);
        producer
            .try_push_at(remote, &packet, origin + Duration::from_millis(arrival))
            .unwrap();
    }
    let mut pcm = [0.0; 160];
    assert_eq!(
        peer.poll_event(&mut pcm, &mut [0; 1500]).unwrap(),
        super::IaxPeerEvent::Audio(160)
    );
    assert!(pcm.iter().all(|value| *value > 0.9));
    assert_eq!(
        fixture
            .puts()
            .iter()
            .map(|put| (put.0, put.2))
            .collect::<Vec<_>>(),
        [
            (first, 0),
            (first + 320, 20_000_000),
            (first + 160, 30_000_000)
        ]
    );
}

#[test]
fn jitter_composition_is_once_before_attach_and_requires_gap_aware_polling() {
    let mut peer = linked_peer("127.0.0.1:4567".parse().unwrap());
    assert!(matches!(
        unsafe { peer.configure_jitter(std::ptr::null()) },
        Err(DialError::InvalidOptions)
    ));
    let fixture = crate::jitter::fixture::Fixture::new();
    unsafe { peer.configure_jitter(fixture.descriptor()) }.unwrap();
    assert_eq!(
        fixture.policy(),
        (1280, 1440, 4000, crate::jitter::MAX_PAYLOAD as u32)
    );
    assert!(matches!(
        unsafe { peer.configure_jitter(std::ptr::null()) },
        Err(DialError::InvalidOptions)
    ));
    assert!(matches!(
        peer.poll_ulaw(&mut [0.0; 160]),
        Err(DialError::InvalidOptions)
    ));
    let mut attached = linked_peer("127.0.0.1:4567".parse().unwrap());
    attached.async_attached = true;
    assert!(matches!(
        unsafe { attached.configure_jitter(fixture.descriptor()) },
        Err(DialError::InvalidOptions)
    ));
    assert!(attached.playout.is_none());
}

#[test]
fn wildcard_bind_matches_remote_address_family() {
    assert_eq!(
        wildcard_for(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    );
    assert_eq!(
        wildcard_for(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    );
}

#[test]
fn node_numbers_are_decimal_and_limited_to_31_bytes() {
    assert!(valid_node("1"));
    assert!(valid_node("1234567890123456789012345678901"));
    assert!(!valid_node(""));
    assert!(!valid_node("12345678901234567890123456789012"));
    assert!(!valid_node("12a"));
}

#[test]
fn dial_reports_udp_broadcast_send_failure() {
    assert!(matches!(
        dial_ulaw(DialOptions {
            remote: "255.255.255.255:4569".parse().unwrap(),
            local_call: 1,
            local_node: "524950",
            remote_node: "506315",
            secret: "",
            timeout: Duration::from_secs(1),
        }),
        Err(DialError::Network(_))
    ));
}

#[test]
fn cumulative_acknowledgements_handle_wrap_and_ignore_future_sequences() {
    let now = Instant::now();
    let mut pending = [254, 255, 0, 1]
        .map(|outgoing_sequence| PendingReliableFrame {
            packet: Vec::new(),
            outgoing_sequence,
            next_retry: now,
            retry_interval: Duration::from_secs(2),
            retries: 0,
            sent: true,
            expires_at: now + Duration::from_secs(42),
        })
        .into();

    acknowledge_reliable_frames(&mut pending, 0);
    assert_eq!(
        pending
            .iter()
            .map(|frame| frame.outgoing_sequence)
            .collect::<Vec<_>>(),
        [0, 1]
    );

    acknowledge_reliable_frames(&mut pending, 4);
    assert_eq!(pending.len(), 2);

    acknowledge_reliable_frames(&mut pending, 2);
    assert!(pending.is_empty());
}

#[test]
fn timed_egress_announces_only_empty_reliable_markers_and_never_replays_expired_pcm() {
    use super::{EgressRetirement, EgressTime, TimedMediaSend};
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let EgressRetirement::Complete(epoch) = peer.retire_egress().unwrap() else {
        panic!("new call owns no old PCM");
    };
    let time = EgressTime {
        epoch,
        deadline_ms: peer.elapsed_ms() + 100,
    };
    assert_eq!(
        peer.send_prepared_audio_timed(&[0xff; 160], 160, 100, time)
            .unwrap(),
        TimedMediaSend::Accepted
    );
    let mut bytes = [0; 2048];
    let (count, _) = remote.recv_from(&mut bytes).unwrap();
    let marker = crate::protocol::parse_full_frame_packet(&bytes[..count]).unwrap();
    assert_eq!(
        (
            marker.header.frame_type,
            marker.header.timestamp,
            marker.header.outgoing_sequence,
            marker.payload.len()
        ),
        (2, 100, 1, 0)
    );
    let (count, _) = remote.recv_from(&mut bytes).unwrap();
    assert_eq!(&bytes[4..count], &[0xff; 160]);
    assert_eq!(peer.pending_reliable.len(), 1);
    assert_eq!(peer.pending_reliable[0].packet.len(), 12);
    std::thread::sleep(Duration::from_millis(110));
    assert_eq!(
        peer.send_prepared_audio_timed(&[0xff; 160], 160, 100, time)
            .unwrap(),
        TimedMediaSend::Expired
    );
    assert_eq!(
        remote.recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let EgressRetirement::Complete(next) = peer.retire_egress().unwrap() else {
        panic!("empty marker is protocol, not retained PCM");
    };
    assert_eq!(next, epoch + 1);
    let stale = EgressTime {
        epoch,
        deadline_ms: peer.elapsed_ms() + 100,
    };
    assert_eq!(
        peer.send_prepared_audio_timed(&[0xff; 160], 160, 120, stale)
            .unwrap(),
        TimedMediaSend::Expired
    );
    assert!(matches!(
        peer.send_prepared_audio(&[0xff; 160], 160, 120),
        Err(DialError::InvalidOptions)
    ));
    assert_eq!(
        remote.recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn timed_egress_reannounces_after_a_long_silence_when_initial_pcm_never_committed() {
    use super::{EgressRetirement, EgressTime, TimedMediaSend};
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let EgressRetirement::Complete(epoch) = peer.retire_egress().unwrap() else {
        panic!("initial");
    };
    let time = EgressTime {
        epoch,
        deadline_ms: peer.elapsed_ms() + 500,
    };
    let fault = SendFault::set(remote.local_addr().unwrap(), std::io::ErrorKind::WouldBlock);
    assert_eq!(
        peer.send_prepared_audio_timed(&[0xff; 160], 160, 100, time)
            .unwrap(),
        TimedMediaSend::WouldBlock
    );
    drop(fault);
    std::thread::sleep(Duration::from_millis(505));
    peer.poll_event(&mut [], &mut []).unwrap();
    assert_eq!(
        peer.send_prepared_audio_timed(&[0xff; 160], 160, 100, time)
            .unwrap(),
        TimedMediaSend::Expired
    );
    let mut bytes = [0; 2048];
    let (count, _) = remote.recv_from(&mut bytes).unwrap();
    assert!(
        crate::protocol::parse_full_frame_packet(&bytes[..count])
            .unwrap()
            .payload
            .is_empty()
    );
    assert_eq!(
        peer.send_prepared_audio_timed(
            &[0xff; 160],
            160,
            40000,
            EgressTime {
                epoch,
                deadline_ms: peer.elapsed_ms() + 500
            }
        )
        .unwrap(),
        TimedMediaSend::Accepted
    );
    let (count, _) = remote.recv_from(&mut bytes).unwrap();
    let marker = crate::protocol::parse_full_frame_packet(&bytes[..count])
        .expect("fresh long-gap PCM needs a new full marker even without earlier accepted PCM");
    assert_eq!((marker.header.timestamp, marker.payload.len()), (40000, 0));
    assert_eq!(remote.recv_from(&mut bytes).unwrap().0, 164);
}

#[test]
fn timed_egress_wouldblock_retains_deadline_and_legacy_pcm_is_an_actual_ack_barrier() {
    use super::{EgressRetirement, EgressTime, TimedMediaSend};
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let address = remote.local_addr().unwrap();
    let mut peer = linked_peer(address);
    let EgressRetirement::Complete(epoch) = peer.retire_egress().unwrap() else {
        panic!("initial retirement");
    };
    let time = EgressTime {
        epoch,
        deadline_ms: peer.elapsed_ms() + 500,
    };
    let fault = SendFault::set(address, std::io::ErrorKind::WouldBlock);
    assert_eq!(
        peer.send_prepared_audio_timed(&[0xff; 160], 160, 0, time)
            .unwrap(),
        TimedMediaSend::WouldBlock
    );
    assert_eq!(
        peer.send_prepared_audio_timed(&[0xff; 160], 160, 0, time)
            .unwrap(),
        TimedMediaSend::WouldBlock
    );
    assert_eq!(peer.pending_reliable.len(), 1);
    drop(fault);
    std::thread::sleep(Duration::from_millis(505));
    peer.poll_event(&mut [], &mut []).unwrap();
    assert_eq!(
        peer.send_prepared_audio_timed(&[0xff; 160], 160, 0, time)
            .unwrap(),
        TimedMediaSend::Expired
    );
    let mut bytes = [0; 2048];
    let (count, _) = remote.recv_from(&mut bytes).unwrap();
    assert!(
        crate::protocol::parse_full_frame_packet(&bytes[..count])
            .unwrap()
            .payload
            .is_empty()
    );
    assert_eq!(
        remote.recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );

    let mut legacy = linked_peer(address);
    legacy.send_prepared_audio(&[0xff; 160], 160, 0).unwrap();
    remote.recv_from(&mut bytes).unwrap();
    assert_eq!(legacy.retire_egress().unwrap(), EgressRetirement::Pending);
    assert_eq!(legacy.retire_egress().unwrap(), EgressRetirement::Pending);
    legacy.send_text(b"control still reliable").unwrap();
    let (count, _) = remote.recv_from(&mut bytes).unwrap();
    assert_eq!(
        crate::protocol::parse_full_frame_packet(&bytes[..count])
            .unwrap()
            .payload,
        b"control still reliable"
    );
    let ack = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 5678,
            destination_call_number: 1234,
            retransmission: false,
            timestamp: 0,
            outgoing_sequence: 1,
            incoming_sequence: 3,
            frame_type: 6,
            subclass: crate::protocol::IaxCommand::Ack.subclass_value() as u8,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap();
    remote.send_to(&ack, legacy.local_addr().unwrap()).unwrap();
    legacy.poll_event(&mut [], &mut []).unwrap();
    assert_eq!(
        legacy.retire_egress().unwrap(),
        EgressRetirement::Complete(2)
    );
}

#[test]
fn timed_mini_commit_rechecks_actual_expiry_and_ffi_reports_wouldblock_without_renewal() {
    use super::{EgressRetirement, EgressTime, TimedMediaSend};
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let address = remote.local_addr().unwrap();
    let mut peer = linked_peer(address);
    let EgressRetirement::Complete(epoch) = peer.retire_egress().unwrap() else {
        panic!("initial retirement");
    };
    let time = EgressTime {
        epoch,
        deadline_ms: peer.elapsed_ms() + 50,
    };
    let (reached, ready) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    *TIMED_COMMIT_GATE.lock().unwrap() = Some(TimedCommitGate {
        remote: address,
        timestamp: 100,
        reached,
        release: wait,
    });
    let job = std::thread::spawn(move || {
        let result = peer.send_prepared_audio_timed(&[0xff; 160], 160, 100, time);
        (peer, result)
    });
    ready.recv_timeout(Duration::from_secs(2)).unwrap();
    std::thread::sleep(Duration::from_millis(60));
    release.send(()).unwrap();
    let (mut peer, result) = job.join().unwrap();
    assert_eq!(result.unwrap(), TimedMediaSend::Expired);
    let mut bytes = [0; 2048];
    let (count, _) = remote.recv_from(&mut bytes).unwrap();
    assert!(
        crate::protocol::parse_full_frame_packet(&bytes[..count])
            .unwrap()
            .payload
            .is_empty()
    );
    assert_eq!(
        remote.recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let api = unsafe { &*crate::ffi::rptadv_iax2_client_descriptor_v2() };
    let time = crate::ffi::rptadv_iax2_timed_send_v1 {
        struct_size: std::mem::size_of::<crate::ffi::rptadv_iax2_timed_send_v1>() as u32,
        abi_version: 1,
        egress_epoch: epoch,
        deadline_ms: peer.elapsed_ms() + 500,
        reserved: 0,
    };
    let fault = SendFault::set(address, std::io::ErrorKind::WouldBlock);
    assert_eq!(
        unsafe {
            api.send_prepared_audio_timed.unwrap()(
                (&mut peer as *mut IaxPeer).cast(),
                [0xff; 160].as_ptr(),
                160,
                160,
                120,
                &time,
            )
        },
        1
    );
    drop(fault);
    assert_eq!(
        unsafe {
            api.send_prepared_audio_timed.unwrap()(
                (&mut peer as *mut IaxPeer).cast(),
                [0xff; 160].as_ptr(),
                160,
                160,
                120,
                &time,
            )
        },
        0
    );
    let (count, _) = remote.recv_from(&mut bytes).unwrap();
    assert_eq!(count, 164);
    let fault = SendFault::set(address, std::io::ErrorKind::ConnectionReset);
    assert!(
        matches!(peer.send_prepared_audio_timed(&[0xff;160],160,140,EgressTime { epoch, deadline_ms: time.deadline_ms }), Err(DialError::Network(error)) if error.kind() == std::io::ErrorKind::ConnectionReset)
    );
    drop(fault);
}

#[test]
fn actual_legacy_vnak_pcm_staging_is_retired_without_erasing_control_or_sequence_ownership() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let address = remote.local_addr().unwrap();
    let mut peer = linked_peer(address);
    let local = peer.local_addr().unwrap();
    peer.send_prepared_audio(&[0xff; 160], 160, 0).unwrap();
    let mut bytes = [0; 2048];
    remote.recv_from(&mut bytes).unwrap();
    let vnak = vnak_packet(1);
    remote.send_to(&vnak, local).unwrap();
    let fault = SendFault::set(address, std::io::ErrorKind::WouldBlock);
    peer.poll_event(&mut [], &mut []).unwrap();
    assert_eq!(peer.pending_replies.len(), 1);
    assert_eq!(&peer.pending_replies[0][12..], &[0xff; 160]);
    drop(fault);
    assert_eq!(
        peer.retire_egress().unwrap(),
        super::EgressRetirement::Pending
    );
    assert!(peer.pending_replies.is_empty());
    assert_eq!(&peer.pending_reliable[0].packet[12..], &[0xff; 160]);
    peer.begin_turn();
    peer.set_product_deadline(u64::MAX).unwrap();
    assert_eq!(
        peer.wait_state().deadline,
        Some(peer.pending_reliable[0].expires_at)
    );
    assert!(matches!(
        peer.prepare_audio(&[0.0; 160], &mut [0; 160], false),
        Err(DialError::InvalidOptions)
    ));
    peer.send_text(b"control").unwrap();
    remote.recv_from(&mut bytes).unwrap();
    remote.send_to(&vnak, local).unwrap();
    peer.poll_event(&mut [], &mut []).unwrap();
    let (count, _) = remote.recv_from(&mut bytes).unwrap();
    let frame = crate::protocol::parse_full_frame_packet(&bytes[..count]).unwrap();
    assert_eq!(
        (
            frame.header.frame_type,
            frame.header.retransmission,
            frame.payload
        ),
        (7, true, &b"control"[..])
    );
    assert_eq!(
        remote.recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(peer.pending_reliable.len(), 2);
    assert_eq!(
        peer.retire_egress().unwrap(),
        super::EgressRetirement::Pending
    );
}

#[test]
fn timed_egress_reannounces_wrap_silence_and_timestamp_discontinuity_without_pcm_in_markers() {
    use super::{EgressRetirement, EgressTime, TimedMediaSend};
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let EgressRetirement::Complete(epoch) = peer.retire_egress().unwrap() else {
        panic!("initial retirement");
    };
    let mut bytes = [0; 2048];
    let mut next_marker = 1;
    for (timestamp, announce) in [
        (100, true),
        (120, false),
        (40_000, true),
        (39_000, true),
        (65_520, false),
        (65_540, true),
    ] {
        let time = EgressTime {
            epoch,
            deadline_ms: peer.elapsed_ms() + 500,
        };
        assert_eq!(
            peer.send_prepared_audio_timed(&[0xff; 160], 160, timestamp, time)
                .unwrap(),
            TimedMediaSend::Accepted
        );
        if announce {
            let (count, _) = remote.recv_from(&mut bytes).unwrap();
            let frame = crate::protocol::parse_full_frame_packet(&bytes[..count]).unwrap();
            assert_eq!(
                (
                    frame.header.frame_type,
                    frame.header.timestamp,
                    frame.header.outgoing_sequence
                ),
                (2, timestamp, next_marker)
            );
            assert!(frame.payload.is_empty());
            next_marker += 1;
        }
        let (count, _) = remote.recv_from(&mut bytes).unwrap();
        assert_eq!(count, 164);
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), timestamp as u16);
        assert_eq!(&bytes[4..count], &[0xff; 160]);
    }
    assert_eq!(next_marker, 5);
    assert!(
        peer.pending_reliable
            .iter()
            .all(|frame| frame.packet.len() == 12)
    );
    assert_eq!(
        remote.recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let time = EgressTime {
        epoch,
        deadline_ms: peer.elapsed_ms() + 500,
    };
    let fault = SendFault::set(remote.local_addr().unwrap(), std::io::ErrorKind::WouldBlock);
    assert_eq!(
        peer.send_prepared_audio_timed(&[0xff; 160], 160, 65000, time)
            .unwrap(),
        TimedMediaSend::WouldBlock
    );
    drop(fault);
    peer.poll_event(&mut [], &mut []).unwrap();
    let (count, _) = remote.recv_from(&mut bytes).unwrap();
    let marker = crate::protocol::parse_full_frame_packet(&bytes[..count]).unwrap();
    assert_eq!((marker.header.timestamp, marker.payload.len()), (65000, 0));
    assert_eq!(
        peer.send_prepared_audio_timed(&[0xff; 160], 160, 65000, time)
            .unwrap(),
        TimedMediaSend::Accepted
    );
    assert_eq!(remote.recv_from(&mut bytes).unwrap().0, 164);
    peer.begin_turn();
    peer.set_product_deadline(u64::MAX).unwrap();
    assert_eq!(
        peer.wait_state().deadline,
        Some(peer.pending_reliable[0].next_retry)
    );
}

#[test]
fn shared_endpoint_routes_sends_and_rejects_packets_larger_than_output_storage() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let remote_address = remote.local_addr().unwrap();
    let socket = Arc::new(SharedSocket::new(UdpSocket::bind("127.0.0.1:0").unwrap()));
    let local = socket.local_addr().unwrap();
    let mut router = PeerIngressRouter::new(2).unwrap();
    let ingress = router.register_call(remote_address, 1234, 5678, 1).unwrap();
    let mut endpoint = PeerEndpoint::Shared {
        socket: Arc::clone(&socket),
        ingress,
        local,
    };

    assert_eq!(endpoint.local_addr().unwrap(), local);
    assert!(endpoint.receive(&mut [0; 2]).unwrap().is_none());
    router
        .route_call(remote_address, 1234, 5678, &[1, 2, 3])
        .unwrap();
    assert_eq!(
        endpoint.receive(&mut [0; 2]).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    router
        .route_call(remote_address, 1234, 5678, &[4, 5])
        .unwrap();
    assert_eq!(
        endpoint
            .receive(&mut [0; 2])
            .unwrap()
            .map(|(count, remote, _, _)| (count, remote)),
        Some((2, remote_address))
    );

    endpoint.send_to(&[6, 7], remote_address).unwrap();
    let mut packet = [0; 2];
    assert_eq!(remote.recv_from(&mut packet).unwrap().0, 2);
    assert_eq!(packet, [6, 7]);
}

#[test]
fn reliable_capacity_and_text_size_are_bounded_before_sending() {
    let remote: SocketAddr = "127.0.0.1:4569".parse().unwrap();
    let mut peer = linked_peer(remote);
    assert!(matches!(
        peer.send_text(&vec![0; super::MAX_PACKET_SIZE]),
        Err(DialError::InvalidOptions)
    ));
    assert!(matches!(
        peer.send_prepared_audio(&[0xff], 2, 0),
        Err(DialError::InvalidOptions)
    ));
    assert!(matches!(
        peer.send_prepared_ulaw(&vec![0; 65_507 - 12 + 1], 0),
        Err(DialError::InvalidOptions)
    ));
    assert_eq!(peer.maximum_datagram(), 65_507);
    peer.remote = "[::1]:4569".parse().unwrap();
    assert_eq!(peer.maximum_datagram(), crate::ingress::MAX_DATAGRAM_SIZE);

    let now = Instant::now();
    peer.pending_reliable = (0..super::MAX_RELIABLE_WINDOW)
        .map(|_| PendingReliableFrame {
            packet: Vec::new(),
            outgoing_sequence: 0,
            next_retry: now,
            retry_interval: Duration::from_secs(2),
            retries: super::MAX_RELIABLE_RETRIES,
            sent: true,
            expires_at: now + Duration::from_secs(42),
        })
        .collect();
    assert!(matches!(
        peer.send_text(b"full"),
        Err(DialError::ReliableWindowFull)
    ));
    peer.pending_reliable.pop_front();
    assert!(matches!(
        peer.retry_reliable_frames(),
        Err(DialError::Timeout)
    ));
}

#[test]
fn digit_poll_requires_caller_text_storage() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let remote_address = remote.local_addr().unwrap();
    let mut peer = linked_peer(remote_address);
    let local = peer.local_addr().unwrap();
    let local = SocketAddr::from(([127, 0, 0, 1], local.port()));
    let digit = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: peer.remote_call,
            retransmission: false,
            destination_call_number: peer.local_call,
            timestamp: 0,
            outgoing_sequence: 1,
            incoming_sequence: 1,
            frame_type: 1,
            subclass: b'5',
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap();
    remote.send_to(&digit, local).unwrap();

    assert!(matches!(
        peer.poll_event(&mut [], &mut []),
        Err(DialError::InvalidOptions)
    ));
}

#[test]
fn inbound_accept_and_answer_retransmit_until_their_cumulative_ack() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let accept = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 1234,
            destination_call_number: 5678,
            retransmission: false,
            timestamp: 0,
            outgoing_sequence: 0,
            incoming_sequence: 1,
            frame_type: 6,
            subclass: 7,
            subclass_is_log: false,
        },
        &[9, 4, 0, 0, 0, 4],
    )
    .unwrap();
    peer.accept_inbound(accept).unwrap();
    let mut bytes = [0; 1500];
    for retransmission in [false, true] {
        for (sequence, kind, subclass) in [(0, 6, 7), (1, 4, 4)] {
            let (length, _) = remote.recv_from(&mut bytes).unwrap();
            let frame = crate::protocol::parse_full_frame_packet(&bytes[..length]).unwrap();
            assert_eq!(
                (
                    frame.header.outgoing_sequence,
                    frame.header.frame_type,
                    frame.header.subclass
                ),
                (sequence, kind, subclass)
            );
            assert_eq!(frame.header.incoming_sequence, 1);
            assert_eq!(frame.header.retransmission, retransmission);
        }
        if !retransmission {
            for pending in &mut peer.pending_reliable {
                pending.next_retry = Instant::now();
            }
            peer.retry_reliable_frames().unwrap();
        }
    }
    for incoming_sequence in [1, 2] {
        let ack = serialize_full_frame(
            &FullFrameHeader {
                source_call_number: 5678,
                destination_call_number: 1234,
                retransmission: false,
                timestamp: 0,
                outgoing_sequence: 1,
                incoming_sequence,
                frame_type: 6,
                subclass: 4,
                subclass_is_log: false,
            },
            &[],
        )
        .unwrap();
        peer.receive_event(&ack, Instant::now(), &mut [], &mut [])
            .unwrap();
        assert_eq!(
            peer.pending_reliable.len(),
            usize::from(2 - incoming_sequence)
        );
    }
    peer.send_text(b"next").unwrap();
    let (length, _) = remote.recv_from(&mut bytes).unwrap();
    let text = crate::protocol::parse_full_frame_packet(&bytes[..length]).unwrap();
    assert_eq!(text.header.outgoing_sequence, 2);
    assert_eq!(text.payload, b"next");
}
