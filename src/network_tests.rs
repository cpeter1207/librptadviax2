use super::{NetworkIngressError, UdpEndpoint, configure_socket, receive_result, route_received};
use crate::{
    ingress::{PeerIngressRouter, PeerIngressRouterError},
    protocol::{FullFrameHeader, MiniFrameHeader, serialize_full_frame, serialize_mini_frame},
};
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

fn loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

#[test]
fn binds_nonblocking_loopback_endpoints() {
    let endpoint = UdpEndpoint::bind(loopback());
    assert!(endpoint.is_ok());
    let endpoint = endpoint.unwrap();
    assert_ne!(endpoint.local_addr().unwrap().port(), 0);
    assert_eq!(endpoint.try_receive(&mut [0; 32]).unwrap(), None);
}

#[test]
fn propagates_bind_and_nonblocking_configuration_errors() {
    let unassigned = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 0);
    assert!(UdpEndpoint::bind(unassigned).is_err());

    let socket = UdpSocket::bind(loopback()).unwrap();
    let configured = configure_socket(socket, |_| {
        Err(Error::new(ErrorKind::PermissionDenied, "injected failure"))
    });
    assert_eq!(
        configured.err().unwrap().kind(),
        ErrorKind::PermissionDenied
    );
}

#[test]
fn propagates_send_and_non_would_block_receive_errors() {
    let endpoint = UdpEndpoint::bind(loopback()).unwrap();
    let ipv6_destination = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9);
    assert!(endpoint.send_to(&[1], ipv6_destination).is_err());

    let receive = receive_result(Err(Error::new(
        ErrorKind::PermissionDenied,
        "injected receive failure",
    )));
    assert_eq!(receive.unwrap_err().kind(), ErrorKind::PermissionDenied);

    assert!(matches!(
        NetworkIngressError::from(Error::new(ErrorKind::PermissionDenied, "injected route error")),
        NetworkIngressError::Io(error) if error.kind() == ErrorKind::PermissionDenied
    ));
}

#[test]
fn routed_receive_preserves_socket_errors() {
    let mut router = PeerIngressRouter::new(1, 1).unwrap();
    let error = Error::new(ErrorKind::PermissionDenied, "injected receive error");
    assert!(matches!(
        route_received(Err(error), &mut router, &[0; 1500]),
        Err(NetworkIngressError::Io(error)) if error.kind() == ErrorKind::PermissionDenied
    ));
}

#[test]
fn sends_and_receives_one_unmodified_datagram() {
    let sender = UdpEndpoint::bind(loopback()).unwrap();
    let receiver = UdpEndpoint::bind(loopback()).unwrap();
    let destination = receiver.local_addr().unwrap();
    let payload = [0, 0x80, 1, 0xff];

    assert_eq!(
        sender.send_to(&payload, destination).unwrap(),
        payload.len()
    );

    let deadline = Instant::now() + Duration::from_secs(1);
    let mut buffer = [0; 16];
    loop {
        if let Some((length, source)) = receiver.try_receive(&mut buffer).unwrap() {
            assert_eq!(&buffer[..length], payload);
            assert_eq!(source, sender.local_addr().unwrap());
            break;
        }
        assert!(Instant::now() < deadline, "loopback datagram timed out");
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn endpoint_routes_received_datagrams_to_peer_owner_queue() {
    let sender = UdpEndpoint::bind(loopback()).unwrap();
    let endpoint = UdpEndpoint::bind(loopback()).unwrap();
    let mut router = PeerIngressRouter::new(1, 2).unwrap();
    let mut owner = router.register(sender.local_addr().unwrap(), 42).unwrap();
    let destination = endpoint.local_addr().unwrap();
    let mut buffer = [0; 1500];
    assert!(matches!(
        endpoint.try_receive_routed(&mut router, &mut buffer),
        Ok(None)
    ));
    sender.send_to(&[0, 0x80, 1], destination).unwrap();

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if endpoint
            .try_receive_routed(&mut router, &mut buffer)
            .unwrap()
            .is_some()
        {
            break;
        }
        assert!(Instant::now() < deadline, "loopback datagram timed out");
        thread::sleep(Duration::from_millis(1));
    }

    let packet = owner.try_pop().unwrap();
    assert_eq!(packet.generation(), 42);
    assert_eq!(packet.payload(), [0, 0x80, 1]);
}

#[test]
fn endpoint_demultiplexes_full_and_mini_frames_by_call() {
    let sender = UdpEndpoint::bind(loopback()).unwrap();
    let endpoint = UdpEndpoint::bind(loopback()).unwrap();
    let remote = sender.local_addr().unwrap();
    let mut router = PeerIngressRouter::new(2, 2).unwrap();
    let mut first = router.register_call(remote, 100, 200, 11).unwrap();
    let mut second = router.register_call(remote, 101, 201, 22).unwrap();
    let destination = endpoint.local_addr().unwrap();
    let mut buffer = [0; 1500];
    let first_frame = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 200,
            retransmission: false,
            destination_call_number: 100,
            timestamp: 20,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 2,
            subclass: 4,
            subclass_is_log: false,
        },
        &[1, 2],
    )
    .unwrap();
    let second_frame = serialize_mini_frame(
        &MiniFrameHeader {
            source_call_number: 201,
            timestamp: 40,
        },
        &[3, 4],
    )
    .unwrap();
    sender.send_to(&first_frame, destination).unwrap();
    assert!(matches!(
        receive_routed_until_ready(&endpoint, &mut router, &mut buffer),
        Ok(Some(source)) if source == remote
    ));
    sender.send_to(&second_frame, destination).unwrap();
    assert!(matches!(
        receive_routed_until_ready(&endpoint, &mut router, &mut buffer),
        Ok(Some(source)) if source == remote
    ));

    assert_eq!(first.try_pop().unwrap().payload(), first_frame);
    assert_eq!(second.try_pop().unwrap().payload(), second_frame);
    assert!(first.try_pop().is_none());
    assert!(second.try_pop().is_none());
}

#[test]
fn endpoint_rejects_malformed_and_unknown_call_frames() {
    let sender = UdpEndpoint::bind(loopback()).unwrap();
    let endpoint = UdpEndpoint::bind(loopback()).unwrap();
    let remote = sender.local_addr().unwrap();
    let mut router = PeerIngressRouter::new(1, 1).unwrap();
    let mut owner = router.register_call(remote, 100, 200, 1).unwrap();
    let destination = endpoint.local_addr().unwrap();
    let mut buffer = [0; 1500];

    sender.send_to(&[0x80], destination).unwrap();
    assert!(matches!(
        receive_routed_until_ready(&endpoint, &mut router, &mut buffer),
        Err(NetworkIngressError::MalformedPacket)
    ));

    let unknown_full = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 201,
            retransmission: false,
            destination_call_number: 101,
            timestamp: 0,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 2,
            subclass: 4,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap();
    sender.send_to(&unknown_full, destination).unwrap();
    assert!(matches!(
        receive_routed_until_ready(&endpoint, &mut router, &mut buffer),
        Err(NetworkIngressError::Unrouted { .. })
    ));

    sender
        .send_to(
            &serialize_mini_frame(
                &MiniFrameHeader {
                    source_call_number: 201,
                    timestamp: 1,
                },
                &[],
            )
            .unwrap(),
            destination,
        )
        .unwrap();
    assert!(matches!(
        receive_routed_until_ready(&endpoint, &mut router, &mut buffer),
        Err(NetworkIngressError::Unrouted { .. })
    ));
    assert!(owner.try_pop().is_none());
}

#[test]
fn endpoint_returns_unknown_full_frame_length_for_inbound_admission() {
    let sender = UdpEndpoint::bind(loopback()).unwrap();
    let endpoint = UdpEndpoint::bind(loopback()).unwrap();
    let mut router = PeerIngressRouter::new(1, 1).unwrap();
    let destination = endpoint.local_addr().unwrap();
    let packet = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 200,
            retransmission: false,
            destination_call_number: 0,
            timestamp: 0,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 6,
            subclass: 1,
            subclass_is_log: false,
        },
        &[6, 5, b'r', b'a', b'd', b'i', b'o'],
    )
    .unwrap();
    sender.send_to(&packet, destination).unwrap();
    let mut buffer = [0; 1500];
    let result = receive_routed_until_ready(&endpoint, &mut router, &mut buffer);

    assert!(matches!(
        result,
        Err(NetworkIngressError::Unrouted { remote, length })
            if remote == sender.local_addr().unwrap() && length == packet.len()
    ));
    assert_eq!(&buffer[..packet.len()], packet);
}

#[test]
fn endpoint_keeps_address_only_routes_for_existing_callers() {
    let sender = UdpEndpoint::bind(loopback()).unwrap();
    let endpoint = UdpEndpoint::bind(loopback()).unwrap();
    let remote = sender.local_addr().unwrap();
    let mut router = PeerIngressRouter::new(1, 1).unwrap();
    let mut owner = router.register(remote, 9).unwrap();
    let destination = endpoint.local_addr().unwrap();
    let frame = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 200,
            retransmission: false,
            destination_call_number: 100,
            timestamp: 0,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 2,
            subclass: 4,
            subclass_is_log: false,
        },
        &[1],
    )
    .unwrap();
    let mut buffer = [0; 1500];
    sender.send_to(&frame, destination).unwrap();

    assert!(matches!(
        receive_routed_until_ready(&endpoint, &mut router, &mut buffer),
        Ok(Some(source)) if source == remote
    ));
    assert_eq!(owner.try_pop().unwrap().payload(), frame);
}

#[test]
fn endpoint_surfaces_unknown_peer_and_full_queue_route_errors() {
    let sender = UdpEndpoint::bind(loopback()).unwrap();
    let endpoint = UdpEndpoint::bind(loopback()).unwrap();
    let mut router = PeerIngressRouter::new(1, 1).unwrap();
    let mut owner = router
        .register(SocketAddr::from(([127, 0, 0, 1], 9)), 7)
        .unwrap();
    let destination = endpoint.local_addr().unwrap();
    let mut buffer = [0; 1500];

    sender.send_to(&[1], destination).unwrap();
    assert!(matches!(
        receive_routed_until_ready(&endpoint, &mut router, &mut buffer),
        Err(NetworkIngressError::Unrouted { .. })
    ));

    let sender_address = sender.local_addr().unwrap();
    router.unregister(SocketAddr::from(([127, 0, 0, 1], 9)), 7);
    let _owner = router.register(sender_address, 8).unwrap();
    router.route(sender_address, &[2]).unwrap();
    sender.send_to(&[3], destination).unwrap();
    assert!(matches!(
        receive_routed_until_ready(&endpoint, &mut router, &mut buffer),
        Err(NetworkIngressError::Route(PeerIngressRouterError::Full))
    ));
    assert_eq!(router.stats(sender_address).unwrap().dropped_packets, 1);
    owner.try_pop();
}

fn receive_routed_until_ready(
    endpoint: &UdpEndpoint,
    router: &mut PeerIngressRouter,
    buffer: &mut [u8; 1500],
) -> Result<Option<SocketAddr>, NetworkIngressError> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(source) = endpoint.try_receive_routed(router, buffer)? {
            return Ok(Some(source));
        }
        assert!(Instant::now() < deadline, "loopback datagram timed out");
        thread::sleep(Duration::from_millis(1));
    }
}
