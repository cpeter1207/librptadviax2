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
    }
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
        endpoint.receive(&mut [0; 2]).unwrap(),
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
