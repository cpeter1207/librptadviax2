use crate::{
    call_token::retry_new_call_with_token,
    codec::G711Ulaw,
    information_elements::{InformationElement, serialize_information_elements},
    ingress::PeerIngressRouter,
    media::encode_mini_voice_frame,
    network::UdpEndpoint,
    protocol::{
        FullFrameHeader, IaxCommand, MiniFrameHeader, decode_iax_command, parse_full_frame_packet,
        serialize_full_frame, serialize_mini_frame,
    },
    server::{
        InboundIaxListener, InboundRoute, ListenerError, ListenerEvent, called_node,
        check_reply_send, make_call_token_authority, valid_local_nodes,
    },
    session::OutboundCallSetup,
};
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, atomic::AtomicBool},
    thread,
    time::Duration,
};

#[test]
fn local_node_configuration_requires_unique_decimal_nodes() {
    assert!(valid_local_nodes(&[
        "524950".to_owned(),
        "508422".to_owned()
    ]));
    for nodes in [
        Vec::new(),
        vec![String::new()],
        vec!["52x950".to_owned()],
        vec!["524950".to_owned(), "524950".to_owned()],
    ] {
        assert!(!valid_local_nodes(&nodes));
    }
    assert!(matches!(
        InboundIaxListener::bind_many("127.0.0.1:0".parse().unwrap(), &[]),
        Err(ListenerError::InvalidFrame)
    ));
}

#[test]
fn listener_errors_have_actionable_messages() {
    assert_eq!(
        ListenerError::Network(io::Error::other("offline")).to_string(),
        "IAX2 listener network error: offline"
    );
    assert_eq!(
        ListenerError::InvalidFrame.to_string(),
        "invalid inbound IAX2 frame"
    );
    assert_eq!(
        ListenerError::ShortSend.to_string(),
        "incomplete inbound IAX2 response send"
    );
    let Err(error) = make_call_token_authority(|_| Err(io::Error::other("random source failed")))
    else {
        panic!("failed random source must prevent listener startup");
    };
    assert_eq!(
        error.to_string(),
        "IAX2 listener network error: secure call-token seed unavailable"
    );
    assert!(check_reply_send(Ok(4), 4).is_ok());
    assert!(matches!(
        check_reply_send(Ok(3), 4),
        Err(ListenerError::ShortSend)
    ));
    assert_eq!(
        check_reply_send(Err(io::Error::other("send failed")), 4)
            .unwrap_err()
            .to_string(),
        "IAX2 listener network error: send failed"
    );
}

#[test]
fn listener_updates_local_nodes_and_returns_none_when_socket_is_empty() {
    let mut listener = InboundIaxListener::bind("127.0.0.1:0".parse().unwrap(), "524950").unwrap();
    assert!(listener.set_local_nodes(&["508422".to_owned()]).is_ok());
    assert_eq!(listener.local_nodes, ["508422"]);
    assert!(matches!(
        listener.poll(0, |_| true),
        Ok(ListenerEvent::None)
    ));

    let invalid = ["508422".to_owned(), "508422".to_owned()];
    assert!(matches!(
        listener.set_local_nodes(&invalid),
        Err(ListenerError::InvalidFrame)
    ));
    assert_eq!(listener.local_nodes, ["508422"]);
}

#[test]
fn called_node_accepts_only_a_single_numeric_called_number() {
    let (_client, packet) = initial_new(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:9".parse().unwrap(),
    );
    assert_eq!(called_node(&packet), Some("524950"));
    assert_eq!(called_node(&[]), None);
}

#[test]
fn called_node_rejects_duplicate_empty_and_nonnumeric_called_elements() {
    let encode = |values: &[&[u8]]| {
        let elements = values
            .iter()
            .map(|value| InformationElement {
                kind: 1,
                data: value,
            })
            .collect::<Vec<_>>();
        let payload = serialize_information_elements(&elements).unwrap();
        serialize_full_frame(
            &FullFrameHeader {
                source_call_number: 42,
                retransmission: false,
                destination_call_number: 0,
                timestamp: 20,
                outgoing_sequence: 0,
                incoming_sequence: 0,
                frame_type: 6,
                subclass: IaxCommand::New.subclass_value() as u8,
                subclass_is_log: false,
            },
            &payload,
        )
        .unwrap()
    };

    assert_eq!(called_node(&encode(&[b"524950", b"508422"])), None);
    assert_eq!(called_node(&encode(&[b""])), None);
    assert_eq!(called_node(&encode(&[b"52x950"])), None);
}

#[test]
fn removing_an_unknown_route_leaves_existing_call_routes_untouched() {
    let remote = "127.0.0.1:4568".parse().unwrap();
    let mut listener = InboundIaxListener::bind("127.0.0.1:0".parse().unwrap(), "524950").unwrap();
    let _consumer = listener.router.register_call(remote, 22, 42, 7).unwrap();
    listener.routes.push(InboundRoute {
        remote,
        local_call: 22,
        remote_call: 42,
        generation: 7,
        released: Arc::new(AtomicBool::new(false)),
    });

    listener.remove_route("127.0.0.1:4569".parse().unwrap(), 22, 42);
    listener.remove_route(remote, 23, 42);
    listener.remove_route(remote, 22, 43);

    assert_eq!(listener.routes.len(), 1);
    assert!(listener.router.call_stats(remote, 22, 42).is_some());
}

#[test]
fn poll_routes_established_frames_before_new_call_admission() {
    let mut listener = InboundIaxListener::bind("127.0.0.1:0".parse().unwrap(), "524950").unwrap();
    let client = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let remote = client.local_addr().unwrap();
    let mut owner = listener.router.register_call(remote, 22, 42, 7).unwrap();
    listener.routes.push(InboundRoute {
        remote,
        local_call: 22,
        remote_call: 42,
        generation: 7,
        released: Arc::new(AtomicBool::new(false)),
    });
    client
        .send_to(
            &full_packet(42, 22, IaxCommand::Ack.subclass_value() as u8),
            listener.local_addr().unwrap(),
        )
        .unwrap();

    for _ in 0..100 {
        assert!(matches!(
            listener.poll(1, |_| panic!("existing calls need no authorization")),
            Ok(ListenerEvent::None)
        ));
        if let Some(packet) = owner.try_pop() {
            assert_eq!(packet.payload(), full_packet(42, 22, 4));
            return;
        }
        thread::sleep(Duration::from_millis(1));
    }
    panic!("listener did not route the established frame");
}

#[test]
fn listener_rejects_a_new_call_when_the_peer_limit_is_full() {
    let mut listener = InboundIaxListener::bind("127.0.0.1:0".parse().unwrap(), "524950").unwrap();
    listener.router = PeerIngressRouter::new(1, 16).unwrap();
    let server = listener.local_addr().unwrap();

    let (first_client, first_initial) = initial_new("127.0.0.1:0".parse().unwrap(), server);
    let first = finish_inbound_handshake(&mut listener, &first_client, &first_initial, server);
    let (second_client, second_initial) = initial_new("127.0.0.1:0".parse().unwrap(), server);
    assert!(matches!(
        finish_inbound_handshake(&mut listener, &second_client, &second_initial, server),
        ListenerEvent::Replied
    ));
    let mut response = [0_u8; 1500];
    let (length, _) = send_until_event(|| second_client.try_receive(&mut response).unwrap());
    assert_eq!(
        decode_iax_command(&parse_full_frame_packet(&response[..length]).unwrap().header),
        Ok(Some(IaxCommand::Reject))
    );
    drop(first);
}

fn finish_inbound_handshake(
    listener: &mut InboundIaxListener,
    client: &UdpEndpoint,
    initial: &[u8],
    server: SocketAddr,
) -> ListenerEvent {
    assert!(matches!(
        send_until_event(|| match listener.poll(100, |_| true).unwrap() {
            ListenerEvent::None => None,
            event => Some(event),
        }),
        ListenerEvent::Replied
    ));
    let mut response = [0_u8; 1500];
    let (length, _) = send_until_event(|| client.try_receive(&mut response).unwrap());
    let retry = retry_new_call_with_token(initial, &response[..length], 8).unwrap();
    client.send_to(&retry, server).unwrap();
    send_until_event(|| match listener.poll(100, |_| true).unwrap() {
        ListenerEvent::None => None,
        event => Some(event),
    })
}

fn full_packet(source: u16, destination: u16, subclass: u8) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: source,
            retransmission: false,
            destination_call_number: destination,
            timestamp: 30,
            outgoing_sequence: 1,
            incoming_sequence: 1,
            frame_type: 6,
            subclass,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap()
}

fn mini_packet(source: u16) -> Vec<u8> {
    serialize_mini_frame(
        &MiniFrameHeader {
            source_call_number: source,
            timestamp: 5,
        },
        &[1],
    )
    .unwrap()
}

fn malformed_new_packet(payload: &[u8]) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 42,
            retransmission: false,
            destination_call_number: 0,
            timestamp: 20,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 6,
            subclass: IaxCommand::New.subclass_value() as u8,
            subclass_is_log: false,
        },
        payload,
    )
    .unwrap()
}

#[test]
fn listener_ignores_malformed_full_frames_and_new_information_elements() {
    let mut listener = InboundIaxListener::bind("127.0.0.1:0".parse().unwrap(), "524950").unwrap();
    let server = listener.local_addr().unwrap();
    let client = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();

    for packet in [&[0x80, 0][..], &malformed_new_packet(&[1])] {
        client.send_to(packet, server).unwrap();
        assert!(matches!(
            send_until_event(|| match listener.poll(1, |_| true).unwrap() {
                ListenerEvent::None => None,
                event => Some(event),
            }),
            ListenerEvent::Ignored
        ));
    }
}

#[test]
fn existing_full_frame_routes_and_hangup_releases_its_exact_call() {
    let remote: SocketAddr = "127.0.0.1:4568".parse().unwrap();
    let mut listener = InboundIaxListener::bind("127.0.0.1:0".parse().unwrap(), "524950").unwrap();
    let mut consumer = listener.router.register_call(remote, 22, 42, 7).unwrap();
    listener.routes.push(InboundRoute {
        remote,
        local_call: 22,
        remote_call: 42,
        generation: 7,
        released: Arc::new(AtomicBool::new(false)),
    });

    let ack = full_packet(42, 22, IaxCommand::Ack.subclass_value() as u8);
    assert!(listener.route_existing(remote, &ack));
    assert_eq!(consumer.try_pop().unwrap().payload(), ack);

    let hangup = full_packet(42, 22, IaxCommand::Hangup.subclass_value() as u8);
    assert!(listener.route_existing(remote, &hangup));
    assert!(listener.routes.is_empty());
    assert!(listener.router.call_stats(remote, 22, 42).is_none());
}

#[test]
fn existing_routes_ignore_malformed_and_unknown_call_frames() {
    let remote: SocketAddr = "127.0.0.1:4568".parse().unwrap();
    let mut listener = InboundIaxListener::bind("127.0.0.1:0".parse().unwrap(), "524950").unwrap();
    assert!(!listener.route_existing(remote, &[0x80, 0x01]));
    assert!(!listener.route_existing(remote, &full_packet(42, 22, 4)));
    let mut oversized = full_packet(42, 22, 4);
    oversized.resize(1501, 0);
    let mut routed = InboundIaxListener::bind("127.0.0.1:0".parse().unwrap(), "524950").unwrap();
    let _consumer = routed.router.register_call(remote, 22, 42, 7).unwrap();
    assert!(routed.route_existing(remote, &oversized));
    assert!(!listener.route_existing(remote, &mini_packet(42)));
    assert!(!listener.route_existing(remote, &[0, 0]));
}

#[test]
fn existing_mini_frame_routes_only_unique_call_identity() {
    let remote: SocketAddr = "127.0.0.1:4568".parse().unwrap();
    let mut listener = InboundIaxListener::bind("127.0.0.1:0".parse().unwrap(), "524950").unwrap();
    let mut consumer = listener.router.register_call(remote, 22, 42, 7).unwrap();
    let packet = mini_packet(42);
    assert!(listener.route_existing(remote, &packet));
    assert_eq!(consumer.try_pop().unwrap().payload(), packet);

    let mut ambiguous = InboundIaxListener::bind("127.0.0.1:0".parse().unwrap(), "524950").unwrap();
    let _first = ambiguous.router.register_call(remote, 22, 42, 7).unwrap();
    let _second = ambiguous.router.register_call(remote, 23, 42, 8).unwrap();
    assert!(ambiguous.route_existing(remote, &packet));
}

#[test]
fn full_ingress_queue_keeps_existing_full_call_routed() {
    let remote: SocketAddr = "127.0.0.1:4568".parse().unwrap();
    let mut listener = InboundIaxListener::bind("127.0.0.1:0".parse().unwrap(), "524950").unwrap();
    listener.router = PeerIngressRouter::new(1, 1).unwrap();
    let _consumer = listener.router.register_call(remote, 22, 42, 7).unwrap();
    let ack = full_packet(42, 22, IaxCommand::Ack.subclass_value() as u8);
    assert!(listener.router.route_call(remote, 22, 42, &ack).is_ok());

    assert!(listener.route_existing(remote, &ack));
    assert_eq!(
        listener
            .router
            .call_stats(remote, 22, 42)
            .unwrap()
            .dropped_packets,
        1
    );
}

fn send_until_event<T>(mut poll: impl FnMut() -> Option<T>) -> T {
    for _ in 0..100 {
        if let Some(event) = poll() {
            return event;
        }
        thread::sleep(Duration::from_millis(1));
    }
    panic!("listener did not produce the expected event");
}

fn initial_new_for_node(
    called_node: &str,
    local: SocketAddr,
    remote: SocketAddr,
) -> (UdpEndpoint, Vec<u8>) {
    let source_call = 42;
    let setup = OutboundCallSetup::new(
        source_call,
        7,
        &[
            InformationElement {
                kind: 6,
                data: b"radio",
            },
            InformationElement {
                kind: 1,
                data: called_node.as_bytes(),
            },
            InformationElement {
                kind: 2,
                data: b"506315",
            },
            InformationElement {
                kind: 8,
                data: &4_u32.to_be_bytes(),
            },
            InformationElement {
                kind: 9,
                data: &4_u32.to_be_bytes(),
            },
        ],
    )
    .unwrap();
    let client = UdpEndpoint::bind(local).unwrap();
    client.send_to(setup.initial_packet(), remote).unwrap();
    (client, setup.initial_packet().to_vec())
}

fn initial_new(local: SocketAddr, remote: SocketAddr) -> (UdpEndpoint, Vec<u8>) {
    initial_new_for_node("524950", local, remote)
}

#[test]
fn one_listener_dispatches_inbound_calls_to_any_configured_local_node() {
    let mut listener = InboundIaxListener::bind_many(
        "127.0.0.1:0".parse().unwrap(),
        &["524950".to_owned(), "508422".to_owned()],
    )
    .unwrap();
    let server = listener.local_addr().unwrap();
    let (client, initial) = initial_new_for_node("508422", "127.0.0.1:0".parse().unwrap(), server);
    let mut response = [0_u8; 1500];
    assert!(matches!(
        send_until_event(|| match listener.poll(100, |_| true).unwrap() {
            ListenerEvent::None => None,
            event => Some(event),
        }),
        ListenerEvent::Replied
    ));
    let (length, _) = send_until_event(|| client.try_receive(&mut response).unwrap());
    let retry = retry_new_call_with_token(&initial, &response[..length], 8).unwrap();
    client.send_to(&retry, server).unwrap();
    let accepted =
        match send_until_event(|| match listener.poll(100, |remote| remote == "506315") {
            Ok(ListenerEvent::None) => None,
            Ok(event) => Some(event),
            Err(error) => panic!("listener failed: {error}"),
        }) {
            ListenerEvent::Accepted(peer) => peer,
            _ => panic!("call for second local node was not accepted"),
        };
    assert_eq!(accepted.local_node, "508422");
}

#[test]
fn inbound_listener_challenges_then_accepts_authorized_ulaw_call() {
    let mut listener = InboundIaxListener::bind("127.0.0.1:0".parse().unwrap(), "524950").unwrap();
    let server = listener.local_addr().unwrap();
    let (client, initial) = initial_new("127.0.0.1:0".parse().unwrap(), server);
    let remote = client.local_addr().unwrap();

    assert!(matches!(
        send_until_event(|| {
            match listener
                .poll(100, |_| panic!("authorization before token validation"))
                .unwrap()
            {
                ListenerEvent::None => None,
                event => Some(event),
            }
        }),
        ListenerEvent::Replied
    ));
    let mut challenge_buffer = [0_u8; 1500];
    let (length, address) = send_until_event(|| client.try_receive(&mut challenge_buffer).unwrap());
    assert_eq!(address, server);
    let challenge = &challenge_buffer[..length];
    assert_eq!(
        decode_iax_command(&parse_full_frame_packet(challenge).unwrap().header),
        Ok(Some(IaxCommand::CallToken))
    );
    let retry = retry_new_call_with_token(&initial, challenge, 8).unwrap();
    client.send_to(&retry, server).unwrap();

    let accepted = match send_until_event(|| match listener.poll(100, |node| node == "506315") {
        Ok(ListenerEvent::None) => None,
        Ok(event) => Some(event),
        Err(error) => panic!("listener failed: {error}"),
    }) {
        ListenerEvent::Accepted(peer) => peer,
        _ => panic!("authorized call was not accepted"),
    };
    assert_eq!(accepted.remote_node, "506315");
    assert_eq!(accepted.remote, remote);
    let (length, address) = send_until_event(|| client.try_receive(&mut challenge_buffer).unwrap());
    assert_eq!(address, server);
    let accept = parse_full_frame_packet(&challenge_buffer[..length]).unwrap();
    assert_eq!(
        decode_iax_command(&accept.header),
        Ok(Some(IaxCommand::Accept))
    );
    assert_eq!(accept.header.source_call_number, accepted.local_call);

    let local_call = accepted.local_call;
    let mut peer = (*accepted).into_peer();
    let mut audio_packet = [0_u8; 256];
    let length = encode_mini_voice_frame(
        &G711Ulaw,
        MiniFrameHeader {
            source_call_number: 42,
            timestamp: 20,
        },
        &[0.25; 80],
        &mut audio_packet,
    )
    .unwrap();
    client.send_to(&audio_packet[..length], server).unwrap();
    let mut samples = [0.0; 80];
    let mut text = [0_u8; 32];
    let mut audio_count = None;
    for _ in 0..100 {
        listener.poll(100, |_| true).unwrap();
        if let crate::client::IaxPeerEvent::Audio(count) =
            peer.poll_event(&mut samples, &mut text).unwrap()
        {
            audio_count = Some(count);
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(audio_count, Some(80));
    assert!(samples.iter().all(|sample| *sample > 0.0));
    assert_eq!(peer.local_call_number(), local_call);
}

#[test]
fn inbound_listener_rejects_a_token_valid_call_denied_by_product_policy() {
    let mut listener = InboundIaxListener::bind("127.0.0.1:0".parse().unwrap(), "524950").unwrap();
    let server = listener.local_addr().unwrap();
    let (client, initial) = initial_new("127.0.0.1:0".parse().unwrap(), server);
    let mut response = [0_u8; 1500];
    assert!(matches!(
        send_until_event(|| match listener.poll(100, |_| true).unwrap() {
            ListenerEvent::None => None,
            event => Some(event),
        }),
        ListenerEvent::Replied
    ));
    let (length, _) = send_until_event(|| client.try_receive(&mut response).unwrap());
    let retry = retry_new_call_with_token(&initial, &response[..length], 8).unwrap();
    client.send_to(&retry, server).unwrap();

    assert!(matches!(
        send_until_event(|| match listener.poll(100, |_| false).unwrap() {
            ListenerEvent::None => None,
            event => Some(event),
        }),
        ListenerEvent::Replied
    ));
    let (length, address) = send_until_event(|| client.try_receive(&mut response).unwrap());
    assert_eq!(address, server);
    assert_eq!(
        decode_iax_command(&parse_full_frame_packet(&response[..length]).unwrap().header),
        Ok(Some(IaxCommand::Reject))
    );
}

#[test]
fn inbound_listener_reuses_peer_capacity_after_session_drop() {
    let mut listener = InboundIaxListener::bind("127.0.0.1:0".parse().unwrap(), "524950").unwrap();
    listener.router = PeerIngressRouter::new(1, 16).unwrap();
    let server = listener.local_addr().unwrap();
    let (client, initial) = initial_new("127.0.0.1:0".parse().unwrap(), server);
    let mut response = [0_u8; 1500];

    assert!(matches!(
        send_until_event(|| match listener.poll(100, |_| true).unwrap() {
            ListenerEvent::None => None,
            event => Some(event),
        }),
        ListenerEvent::Replied
    ));
    let (length, _) = send_until_event(|| client.try_receive(&mut response).unwrap());
    let retry = retry_new_call_with_token(&initial, &response[..length], 8).unwrap();
    client.send_to(&retry, server).unwrap();
    let first = match send_until_event(|| match listener.poll(100, |_| true).unwrap() {
        ListenerEvent::None => None,
        event => Some(event),
    }) {
        ListenerEvent::Accepted(peer) => peer,
        _ => panic!("first authorized call was not accepted"),
    };
    let (length, address) = send_until_event(|| client.try_receive(&mut response).unwrap());
    assert_eq!(address, server);
    assert_eq!(
        decode_iax_command(&parse_full_frame_packet(&response[..length]).unwrap().header),
        Ok(Some(IaxCommand::Accept))
    );
    drop((*first).into_peer());

    let setup = OutboundCallSetup::new(
        43,
        8,
        &[
            InformationElement {
                kind: 6,
                data: b"radio",
            },
            InformationElement {
                kind: 1,
                data: b"524950",
            },
            InformationElement {
                kind: 2,
                data: b"506315",
            },
            InformationElement {
                kind: 8,
                data: &4_u32.to_be_bytes(),
            },
            InformationElement {
                kind: 9,
                data: &4_u32.to_be_bytes(),
            },
        ],
    )
    .unwrap();
    let second_initial = setup.initial_packet().to_vec();
    client.send_to(&second_initial, server).unwrap();
    assert!(matches!(
        send_until_event(|| match listener.poll(101, |_| true).unwrap() {
            ListenerEvent::None => None,
            event => Some(event),
        }),
        ListenerEvent::Replied
    ));
    let (length, _) = send_until_event(|| client.try_receive(&mut response).unwrap());
    let retry = retry_new_call_with_token(&second_initial, &response[..length], 8).unwrap();
    client.send_to(&retry, server).unwrap();

    assert!(matches!(
        send_until_event(|| match listener.poll(101, |_| true).unwrap() {
            ListenerEvent::None => None,
            event => Some(event),
        }),
        ListenerEvent::Accepted(_)
    ));
}

#[test]
fn listener_rejects_authorized_new_when_ingress_peer_limit_is_full() {
    let mut listener = InboundIaxListener::bind("127.0.0.1:0".parse().unwrap(), "524950").unwrap();
    listener.router = PeerIngressRouter::new(1, 16).unwrap();
    listener
        .router
        .register_call("127.0.0.1:4568".parse().unwrap(), 22, 42, 1)
        .unwrap();
    let server = listener.local_addr().unwrap();
    let (client, initial) = initial_new("127.0.0.1:0".parse().unwrap(), server);
    let mut response = [0_u8; 1500];

    assert!(matches!(
        send_until_event(|| match listener.poll(100, |_| true).unwrap() {
            ListenerEvent::None => None,
            event => Some(event),
        }),
        ListenerEvent::Replied
    ));
    let (length, _) = send_until_event(|| client.try_receive(&mut response).unwrap());
    let retry = retry_new_call_with_token(&initial, &response[..length], 8).unwrap();
    client.send_to(&retry, server).unwrap();

    assert!(matches!(
        send_until_event(|| match listener.poll(100, |_| true).unwrap() {
            ListenerEvent::None => None,
            event => Some(event),
        }),
        ListenerEvent::Replied
    ));
    let (length, _) = send_until_event(|| client.try_receive(&mut response).unwrap());
    assert_eq!(
        decode_iax_command(&parse_full_frame_packet(&response[..length]).unwrap().header),
        Ok(Some(IaxCommand::Reject))
    );
}
