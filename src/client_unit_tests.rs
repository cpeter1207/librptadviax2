use super::{
    DialError, DialOptions, IaxPeer, PeerEndpoint, PendingReliableFrame,
    acknowledge_reliable_frames, dial_ulaw, valid_node, wildcard_for,
};
use crate::{
    codec::IAX_FORMAT_ULAW,
    ingress::PeerIngressRouter,
    network::UdpEndpoint,
    protocol::{FullFrameHeader, serialize_full_frame},
    session::OutboundCallSetup,
};
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::Arc,
    time::{Duration, Instant},
};

fn linked_peer(remote: SocketAddr) -> IaxPeer {
    IaxPeer {
        endpoint: PeerEndpoint::Dedicated(UdpEndpoint::bind(wildcard_for(remote.ip())).unwrap()),
        remote,
        local_call: 1234,
        remote_call: 5678,
        format: IAX_FORMAT_ULAW,
        connected_at: Instant::now(),
        setup: OutboundCallSetup::for_inbound_call(1234, 5678).unwrap(),
        pending_reliable: VecDeque::new(),
        pending_events: VecDeque::new(),
        answered: true,
        voice_epoch: None,
        release_on_drop: None,
        async_attached: false,
        playout: None,
    }
}

fn shared_peer(remote: SocketAddr) -> (IaxPeer, crate::ingress::IngressProducer) {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
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
    let descriptor = unsafe { &*crate::ffi::rptadv_iax2_client_descriptor_v1() };
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
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
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
fn interop_ffi_preserves_delayed_first_voice_and_silent_gap_timestamp_epochs() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let descriptor = unsafe { &*crate::ffi::rptadv_iax2_client_descriptor_v1() };
    let samples = [0.0; 160];
    let mut packet = [0; 1500];
    for elapsed in [70020, 140040] {
        peer.connected_at = Instant::now() - Duration::from_millis(elapsed);
        assert_eq!(
            unsafe {
                descriptor.send_audio.unwrap()(
                    (&mut peer as *mut IaxPeer).cast(),
                    samples.as_ptr(),
                    samples.len(),
                )
            },
            0
        );
        let (length, _) = remote.recv_from(&mut packet).unwrap();
        let voice = crate::protocol::parse_full_frame_packet(&packet[..length])
            .expect("new epoch requires full voice");
        assert!(
            (elapsed..elapsed + 1000).contains(&u64::from(voice.header.timestamp)),
            "full voice must retain elapsed epoch"
        );
    }
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
fn shared_endpoint_routes_sends_and_rejects_packets_larger_than_output_storage() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let remote_address = remote.local_addr().unwrap();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let local = socket.local_addr().unwrap();
    let mut router = PeerIngressRouter::new(1, 2).unwrap();
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
            .map(|(count, remote, _)| (count, remote)),
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
        peer.send_text(&vec![0; 1489]),
        Err(DialError::InvalidOptions)
    ));

    let now = Instant::now();
    peer.pending_reliable = (0..super::MAX_RELIABLE_WINDOW)
        .map(|_| PendingReliableFrame {
            packet: Vec::new(),
            outgoing_sequence: 0,
            next_retry: now,
            retry_interval: Duration::from_secs(2),
            retries: super::MAX_RELIABLE_RETRIES,
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
