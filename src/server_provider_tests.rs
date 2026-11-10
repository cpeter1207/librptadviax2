fn acknowledge_pending(listener: &mut InboundIaxListener, socket: &UdpSocket, request: &[u8]) {
    let header = parse_full_frame_packet(request).unwrap().header;
    let ack = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 77,
            destination_call_number: header.source_call_number,
            outgoing_sequence: 1,
            incoming_sequence: 1,
            subclass: IaxCommand::Ack.subclass_value() as u8,
            ..header
        },
        &[],
    )
    .unwrap();
    socket
        .send_to(&ack, listener.local_addr().unwrap())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !listener
        .pending_provider
        .iter()
        .find(|pending| pending.metadata.remote == socket.local_addr().unwrap())
        .unwrap()
        .acknowledged
    {
        listener
            .poll_accounts(1000, |_, _, _| false, |_| false)
            .unwrap();
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
}
use super::*;
use crate::provider_tests::{account, catalog, pending_incoming, poll_reply, runtime};
use std::net::UdpSocket;

fn fixture() -> (InboundIaxListener, UdpSocket) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut listener = InboundIaxListener::bind_accounts(
        "127.0.0.1:0".parse().unwrap(),
        &[],
        &[account(socket.local_addr().unwrap())],
        Some(catalog()),
    )
    .unwrap();
    listener.enable_async(runtime()).unwrap();
    (listener, socket)
}
fn completion(listener: &mut InboundIaxListener) -> CompletedPoll {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let work = listener.prepare_poll(1000).unwrap();
        let done = work
            .run(|_, _, _| panic!("phone reached numeric policy"), |_| true)
            .unwrap();
        if matches!(done.event, ListenerEvent::Provider(_)) {
            return done;
        }
        listener.finish_poll(done).unwrap();
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
}
fn receive(socket: &UdpSocket) -> Vec<u8> {
    let mut bytes = [0; 2048];
    let (length, _) = socket.recv_from(&mut bytes).unwrap();
    bytes[..length].to_vec()
}

#[test]
fn duplicate_new_preserves_the_real_acknowledged_auth_request_and_never_readmits_a_live_call() {
    let (mut listener, socket) = fixture();
    let other = UdpSocket::bind("127.0.0.1:0").unwrap();
    other
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut other_account = account(other.local_addr().unwrap());
    other_account.id = "provider-other".into();
    listener
        .configure_accounts(&[account(socket.local_addr().unwrap()), other_account])
        .unwrap();
    let (_, _, other_request, _) = pending_incoming(&mut listener, &other);
    acknowledge_pending(&mut listener, &other, &other_request);
    let (_, retry, request, response) = pending_incoming(&mut listener, &socket);
    acknowledge_pending(&mut listener, &socket, &request);
    socket
        .send_to(&retry, listener.local_addr().unwrap())
        .unwrap();
    poll_reply(&mut listener);
    assert_eq!(receive(&socket), request);
    socket
        .send_to(&response, listener.local_addr().unwrap())
        .unwrap();
    let done = completion(&mut listener);
    let ListenerEvent::Provider(mut call) = listener.finish_poll(done).unwrap() else {
        panic!("missing provider")
    };
    assert_eq!(
        decode_iax_command(&parse_full_frame_packet(&receive(&socket)).unwrap().header),
        Ok(Some(IaxCommand::Accept))
    );
    let answer = receive(&socket);
    assert_eq!(
        parse_full_frame_packet(&answer).unwrap().header.frame_type,
        4
    );
    socket
        .send_to(&retry, listener.local_addr().unwrap())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let event = listener
            .poll_accounts(
                1000,
                |_, _, _| panic!("phone reached numeric policy"),
                |_| panic!("duplicate authenticated call admitted twice"),
            )
            .unwrap();
        if matches!(event, ListenerEvent::Ignored) {
            break;
        }
        assert!(matches!(event, ListenerEvent::None));
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    call.peer.hangup().unwrap();
    drop(call);
    listener.configure_accounts(&[]).unwrap();
    for _ in 0..5 {
        listener
            .poll_accounts(1000, |_, _, _| false, |_| false)
            .unwrap();
    }
    assert!(listener.routes.is_empty());
}

#[test]
fn abandoned_or_retired_answered_provider_completion_sends_hangup_before_route_cleanup() {
    for retire in [false, true] {
        let (mut listener, socket) = fixture();
        let (_, _, _, response) = pending_incoming(&mut listener, &socket);
        socket
            .send_to(&response, listener.local_addr().unwrap())
            .unwrap();
        let done = completion(&mut listener);
        if retire {
            listener.configure_accounts(&[]).unwrap();
            assert!(matches!(
                listener.finish_poll(done).unwrap(),
                ListenerEvent::Ignored
            ));
        } else {
            drop(done);
        }
        for (sequence, kind) in [
            (1, Some(IaxCommand::Accept)),
            (2, None),
            (3, Some(IaxCommand::Hangup)),
        ] {
            let bytes = receive(&socket);
            let frame = parse_full_frame_packet(&bytes).unwrap();
            assert_eq!(frame.header.outgoing_sequence, sequence);
            assert_eq!(decode_iax_command(&frame.header).unwrap(), kind);
            if kind.is_none() {
                assert_eq!((frame.header.frame_type, frame.header.subclass), (4, 4));
            }
        }
        // Best-effort HANGUP is distinct from the acknowledged local route removal.
        listener
            .poll_accounts(1000, |_, _, _| false, |_| false)
            .unwrap();
        assert!(listener.routes.is_empty());
        assert_eq!(listener.ingress_stats().active_routes, 0);
    }
}

#[test]
fn actual_pending_account_retirement_prevents_authentication_and_admission() {
    let (mut listener, socket) = fixture();
    let (_, _, _, response) = pending_incoming(&mut listener, &socket);
    listener.configure_accounts(&[]).unwrap();
    socket
        .send_to(&response, listener.local_addr().unwrap())
        .unwrap();
    assert!(matches!(
        listener
            .poll_accounts(
                1000,
                |_, _, _| panic!("numeric fallback"),
                |_| panic!("retired admission")
            )
            .unwrap(),
        ListenerEvent::Ignored
    ));
    listener
        .poll_accounts(1000, |_, _, _| false, |_| false)
        .unwrap();
    assert!(listener.routes.is_empty());
    assert_eq!(listener.ingress_stats().active_routes, 0);
}

#[test]
fn malformed_authentication_wire_fields_reject_without_a_policy_callback() {
    for variant in 0..8 {
        let (mut listener, socket) = fixture();
        let (_, _, request, response) = pending_incoming(&mut listener, &socket);
        let original = parse_full_frame_packet(&response).unwrap();
        let mut header = original.header;
        let mut payload = original.payload.to_vec();
        match variant {
            0 => header.source_call_number = 88,
            1 => header.outgoing_sequence = 0,
            2 => header.incoming_sequence = 0,
            3 => {
                payload = vec![16, 31];
                payload.extend_from_slice(&[b'x'; 31]);
            }
            4 => payload.clear(),
            5 => payload.extend_from_slice(original.payload),
            6 => header.subclass = IaxCommand::Ping.subclass_value() as u8,
            _ => {
                header.subclass = IaxCommand::Ack.subclass_value() as u8;
                payload = vec![1];
            }
        }
        let wire = serialize_full_frame(&header, &payload).unwrap();
        socket
            .send_to(&wire, listener.local_addr().unwrap())
            .unwrap();
        poll_reply(&mut listener);
        let reject = receive(&socket);
        let frame = parse_full_frame_packet(&reject).unwrap();
        assert_eq!(
            decode_iax_command(&frame.header),
            Ok(Some(IaxCommand::Reject))
        );
        assert_eq!(frame.header.incoming_sequence, 1);
        assert_eq!(
            frame.header.destination_call_number,
            parse_full_frame_packet(&request)
                .unwrap()
                .header
                .destination_call_number
        );
        listener
            .poll_accounts(1000, |_, _, _| false, |_| false)
            .unwrap();
        assert_eq!(listener.ingress_stats().active_routes, 0);
    }
}

#[test]
fn authentication_retries_preserve_challenge_and_original_deadline_until_real_timer_expiry() {
    for (timeout, transmissions) in [
        (Duration::from_millis(160), 2usize),
        (Duration::from_secs(30), 4),
    ] {
        let (mut listener, socket) = fixture();
        let mut configured = account(socket.local_addr().unwrap());
        configured.generation = 8;
        configured.pending_auth_timeout = timeout;
        listener.configure_accounts(&[configured]).unwrap();
        let (_, _, request, _) = pending_incoming(&mut listener, &socket);
        let original = parse_full_frame_packet(&request).unwrap();
        let mut received = 1;
        socket.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(35);
        loop {
            listener
                .poll_accounts(
                    1000,
                    |_, _, _| panic!("numeric fallback"),
                    |_| panic!("unverified timer admitted"),
                )
                .unwrap();
            let mut bytes = [0; 2048];
            match socket.recv_from(&mut bytes) {
                Ok((length, _)) => {
                    let frame = parse_full_frame_packet(&bytes[..length]).unwrap();
                    match decode_iax_command(&frame.header).unwrap() {
                        Some(IaxCommand::AuthReq) => {
                            received += 1;
                            assert!(frame.header.retransmission);
                            assert_eq!(
                                (
                                    frame.header.outgoing_sequence,
                                    frame.header.incoming_sequence
                                ),
                                (0, 1)
                            );
                            assert_eq!(frame.payload, original.payload);
                        }
                        Some(IaxCommand::Reject) => {
                            assert_eq!(frame.header.incoming_sequence, 1);
                            break;
                        }
                        other => panic!("unexpected authentication timer reply: {other:?}"),
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("timer wire receive failed: {error}"),
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(received, transmissions);
        listener
            .poll_accounts(1000, |_, _, _| false, |_| false)
            .unwrap();
        assert!(listener.routes.is_empty());
        assert_eq!(listener.ingress_stats().active_routes, 0);
    }
}

type AcceptPause = Box<dyn FnOnce(Instant)>;
thread_local! { static ACCEPT_PAUSE:std::cell::RefCell<Option<(u16,u8,AcceptPause)>>=const {std::cell::RefCell::new(None)}; }
pub(super) fn accept_checkpoint(local_call: u16, stage: u8, deadline: Option<Instant>) {
    let pause = ACCEPT_PAUSE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .is_some_and(|(call, at, _)| *call == local_call && *at == stage)
        {
            slot.take().map(|(_, _, pause)| pause)
        } else {
            None
        }
    });
    if let Some(pause) = pause {
        pause(deadline.expect("matched authenticated call"));
    }
}
#[test]
fn original_auth_deadline_survives_real_preemption_before_route_or_final_commit() {
    for stage in [0, 1] {
        let (mut listener, socket) = fixture();
        let mut configured = account(socket.local_addr().unwrap());
        configured.generation = 8;
        configured.pending_auth_timeout = Duration::from_secs(1);
        listener.configure_accounts(&[configured]).unwrap();
        let (_, _, request, response) = pending_incoming(&mut listener, &socket);
        let local_call = parse_full_frame_packet(&request)
            .unwrap()
            .header
            .source_call_number;
        ACCEPT_PAUSE.with(|slot| {
            *slot.borrow_mut() = Some((
                local_call,
                stage,
                Box::new(|deadline| {
                    std::thread::sleep(
                        deadline.saturating_duration_since(Instant::now())
                            + Duration::from_millis(1),
                    );
                }),
            ))
        });
        socket
            .send_to(&response, listener.local_addr().unwrap())
            .unwrap();
        let guard_deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let work = listener.prepare_poll(1000).unwrap();
            match work.run(|_, _, _| panic!("numeric fallback"), |_| true) {
                Err(ListenerError::Provider(error)) => {
                    if stage == 0 {
                        assert!(matches!(error, AccountError::Timeout));
                    } else {
                        assert!(matches!(error, AccountError::Call(DialError::Timeout)));
                    }
                    break;
                }
                Ok(done) => {
                    assert!(!matches!(done.event, ListenerEvent::Provider(_)));
                    listener.finish_poll(done).unwrap();
                }
                Err(other) => panic!("wrong deadline failure: {other:?}"),
            }
            assert!(Instant::now() < guard_deadline);
            std::thread::yield_now();
        }
        assert!(ACCEPT_PAUSE.with(|slot| slot.borrow().is_none()));
        socket.set_nonblocking(true).unwrap();
        assert_eq!(
            socket.recv_from(&mut [0; 2048]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        listener
            .poll_accounts(1000, |_, _, _| false, |_| false)
            .unwrap();
        assert_eq!(listener.ingress_stats().active_routes, 0);
    }
}

fn initial_retry(
    listener: &mut InboundIaxListener,
    socket: &UdpSocket,
    username: &[u8],
    caller: &[u8],
) -> (crate::session::OutboundCallSetup, Vec<u8>) {
    use crate::{
        information_elements::InformationElement,
        session::{CallSetupResponse, OutboundCallSetup},
    };
    let mut setup = OutboundCallSetup::new(
        77,
        0,
        &[
            InformationElement {
                kind: 6,
                data: username,
            },
            InformationElement {
                kind: 1,
                data: b"1234",
            },
            InformationElement {
                kind: 2,
                data: caller,
            },
            InformationElement {
                kind: 9,
                data: &[0, 0, 0, 4],
            },
        ],
    )
    .unwrap();
    socket
        .send_to(setup.initial_packet(), listener.local_addr().unwrap())
        .unwrap();
    poll_reply(listener);
    let challenge = receive(socket);
    let CallSetupResponse::Send(retry) = setup.receive(&challenge, 0, "fixture-secret").unwrap()
    else {
        panic!("missing challenge")
    };
    (setup, retry)
}
#[test]
fn admission_rejects_control_text_missing_catalog_capacity_and_unconfigured_numeric_path() {
    for variant in 0..6 {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let nodes = if variant == 3 {
            vec![]
        } else {
            vec!["1234".into()]
        };
        let selected = if variant == 1 { None } else { Some(catalog()) };
        let mut listener = InboundIaxListener::bind_accounts(
            "127.0.0.1:0".parse().unwrap(),
            &nodes,
            &[account(socket.local_addr().unwrap())],
            selected,
        )
        .unwrap();
        listener.enable_async(runtime()).unwrap();
        let mut owners = Vec::new();
        if variant == 2 {
            for _ in 0..crate::provider::MAX_ACCOUNTS {
                owners.push(
                    listener
                        .prepare_registration(
                            "provider-one",
                            7,
                            crate::provider::RegistrationRequest {
                                refresh: 60,
                                release: false,
                                timeout: Duration::from_secs(1),
                            },
                        )
                        .unwrap(),
                );
            }
        }
        let username = if variant == 5 {
            &b"unknown-login"[..]
        } else if variant >= 3 {
            &b"radio"[..]
        } else {
            &b"telephone-login"[..]
        };
        let caller = if variant == 0 {
            &b"bad\ncaller"[..]
        } else {
            &b"KG0BP"[..]
        };
        let (mut setup, retry) = initial_retry(&mut listener, &socket, username, caller);
        socket
            .send_to(&retry, listener.local_addr().unwrap())
            .unwrap();
        poll_reply(&mut listener);
        let rejected = receive(&socket);
        assert!(matches!(
            setup.receive(&rejected, 0, "fixture-secret"),
            Ok(crate::session::CallSetupResponse::Rejected { .. })
        ));
        drop(owners);
        for _ in 0..crate::provider::MAX_ACCOUNTS {
            listener
                .poll_accounts(1000, |_, _, _| false, |_| false)
                .unwrap();
        }
        assert_eq!(listener.ingress_stats().active_routes, 0);
    }
}
#[test]
fn prepared_cleanup_and_pending_publication_retain_their_actual_owner_receipts() {
    let (mut listener, socket) = fixture();
    let owner = listener
        .prepare_registration(
            "provider-one",
            7,
            crate::provider::RegistrationRequest {
                refresh: 60,
                release: false,
                timeout: Duration::from_secs(1),
            },
        )
        .unwrap();
    drop(owner);
    let cleanup = listener.prepare_poll(1000).unwrap();
    let second = listener
        .prepare_poll(1000)
        .unwrap()
        .run(|_, _, _| false, |_| false)
        .unwrap();
    assert!(matches!(
        listener.finish_poll(second).unwrap(),
        ListenerEvent::None
    ));
    assert_eq!(listener.routes.len(), 1);
    drop(cleanup); // Unacknowledged claim becomes retryable, not falsely retired.
    listener
        .poll_accounts(1000, |_, _, _| false, |_| false)
        .unwrap();
    assert!(listener.routes.is_empty());
    let (_, retry) = initial_retry(&mut listener, &socket, b"telephone-login", b"KG0BP");
    socket
        .send_to(&retry, listener.local_addr().unwrap())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let pending = loop {
        let done = listener
            .prepare_poll(1000)
            .unwrap()
            .run(|_, _, _| false, |_| false)
            .unwrap();
        if done.pending.is_some() {
            break done;
        }
        listener.finish_poll(done).unwrap();
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    };
    listener.configure_accounts(&[]).unwrap();
    assert!(matches!(
        listener.finish_poll(pending).unwrap(),
        ListenerEvent::Replied
    ));
    assert!(listener.pending_provider.is_empty());
    listener
        .poll_accounts(1000, |_, _, _| false, |_| false)
        .unwrap();
    assert!(listener.routes.is_empty());
    assert_eq!(listener.ingress_stats().active_routes, 0);
}

#[test]
fn real_socket_receive_failure_revokes_pending_ingress_without_fabricated_lifetime_flags() {
    let (mut listener, socket) = fixture();
    let (_, _, request, _) = pending_incoming(&mut listener, &socket);
    acknowledge_pending(&mut listener, &socket, &request);
    crate::network::inject_receive(
        listener.local_addr().unwrap(),
        Err(io::ErrorKind::ConnectionReset.into()),
    );
    socket
        .send_to(
            b"wake actual owned receiver",
            listener.local_addr().unwrap(),
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match listener.poll_accounts(
            1000,
            |_, _, _| panic!("numeric fallback"),
            |_| panic!("failed ingress admission"),
        ) {
            Ok(ListenerEvent::Ignored) => break,
            Ok(ListenerEvent::None | ListenerEvent::Replied) => {}
            other => panic!(
                "unexpected failed receive result: {}",
                match other {
                    Err(error) => error.to_string(),
                    _ => "admitted".into(),
                }
            ),
        }
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while listener.ingress_stats().active_routes != 0 {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    // The failed receiver owns no live routes. Drop joins that actual owner;
    // it does not report a cleanup acknowledgment from its closed channel.
    drop(listener);
}
