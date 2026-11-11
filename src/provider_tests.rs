use crate::{
    information_elements::{
        InformationElement, parse_information_elements, serialize_information_elements,
    },
    protocol::{
        FullFrameHeader, IaxCommand, decode_iax_command, parse_full_frame_packet,
        serialize_full_frame,
    },
    provider::{AccountConfig, AccountError, DialRequest, RegistrationRequest},
    server::InboundIaxListener,
};
use std::{
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    thread,
    time::Duration,
};

pub(crate) fn account(remote: SocketAddr) -> AccountConfig {
    AccountConfig {
        id: "provider-one".into(),
        generation: 7,
        local_binding: "operator-west".into(),
        remote,
        username: "telephone-login".into(),
        secret: "fixture-secret".into(),
        pending_auth_timeout: Duration::from_secs(2),
    }
}

pub(crate) fn runtime() -> Arc<tokio::runtime::Runtime> {
    Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap(),
    )
}

#[test]
fn matched_radio_account_with_bad_literal_secret_never_falls_back_to_numeric_admission() {
    use crate::session::{CallSetupResponse, OutboundCallSetup};
    for configured_secret in ["fixture-secret", "literal;with-semicolon"] {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut config = account(socket.local_addr().unwrap());
        config.username = "radio".into();
        config.secret = configured_secret.into();
        let mut listener = InboundIaxListener::bind_accounts(
            "127.0.0.1:0".parse().unwrap(),
            &["1234".into()],
            &[config],
            Some(catalog()),
        )
        .unwrap();
        listener.enable_async(runtime()).unwrap();
        let bound = listener.local_addr().unwrap();
        let (done, finished) = std::sync::mpsc::channel();
        let remote = thread::spawn(move || {
            let mut setup = OutboundCallSetup::new(
                77,
                0,
                &[
                    InformationElement {
                        kind: 6,
                        data: b"radio",
                    },
                    InformationElement {
                        kind: 1,
                        data: b"1234",
                    },
                    InformationElement {
                        kind: 2,
                        data: b"9999",
                    },
                    InformationElement {
                        kind: 9,
                        data: &[0, 0, 0, 4],
                    },
                ],
            )
            .unwrap();
            socket.send_to(setup.initial_packet(), bound).unwrap();
            let mut bytes = [0; 2048];
            loop {
                let (length, _) = socket.recv_from(&mut bytes).unwrap();
                match setup.receive(&bytes[..length], 0, "literal").unwrap() {
                    CallSetupResponse::Send(packet) => {
                        socket.send_to(&packet, bound).unwrap();
                    }
                    CallSetupResponse::Rejected { acknowledgement } => {
                        socket.send_to(&acknowledgement, bound).unwrap();
                        done.send(()).unwrap();
                        return;
                    }
                    other => panic!("bad provider secret reached acceptance: {other:?}"),
                }
            }
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let event = listener
                .poll_accounts(
                    1000,
                    |_, _, _| panic!("matched account reached numeric policy"),
                    |_| panic!("bad secret reached provider policy"),
                )
                .unwrap();
            assert!(!matches!(
                event,
                crate::server::ListenerEvent::Accepted(_)
                    | crate::server::ListenerEvent::Provider(_)
            ));
            if finished.try_recv().is_ok() {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            thread::yield_now();
        }
        remote.join().unwrap();
        listener
            .poll_accounts(1000, |_, _, _| false, |_| false)
            .unwrap();
        assert_eq!(listener.ingress_stats().active_routes, 0);
    }
}

#[test]
fn provider_authorization_cannot_renew_the_original_pending_authentication_deadline() {
    use crate::session::{CallSetupResponse, OutboundCallSetup};
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut config = account(socket.local_addr().unwrap());
    config.pending_auth_timeout = Duration::from_secs(1);
    let mut listener = InboundIaxListener::bind_accounts(
        "127.0.0.1:0".parse().unwrap(),
        &[],
        &[config],
        Some(catalog()),
    )
    .unwrap();
    listener.enable_async(runtime()).unwrap();
    let bound = listener.local_addr().unwrap();
    let (done, finished) = std::sync::mpsc::channel();
    let remote = thread::spawn(move || {
        let mut setup = OutboundCallSetup::new(
            77,
            0,
            &[
                InformationElement {
                    kind: 6,
                    data: b"telephone-login",
                },
                InformationElement {
                    kind: 1,
                    data: b"incoming",
                },
                InformationElement {
                    kind: 9,
                    data: &[0, 0, 0, 4],
                },
            ],
        )
        .unwrap();
        socket.send_to(setup.initial_packet(), bound).unwrap();
        let mut bytes = [0; 2048];
        loop {
            let (length, _) = socket.recv_from(&mut bytes).unwrap();
            match setup
                .receive(&bytes[..length], 0, "fixture-secret")
                .unwrap()
            {
                CallSetupResponse::Send(packet) => {
                    socket.send_to(&packet, bound).unwrap();
                }
                CallSetupResponse::Rejected { acknowledgement } => {
                    socket.send_to(&acknowledgement, bound).unwrap();
                    done.send(()).unwrap();
                    return;
                }
                other => panic!("expired authentication must reject, got {other:?}"),
            }
        }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut authorized = 0;
    loop {
        let event = listener
            .poll_accounts(
                1000,
                |_, _, _| false,
                |_| {
                    authorized += 1;
                    // A legal slow foreign policy callback cannot grant a fresh protocol
                    // lifetime after the NEW's original authentication deadline expires.
                    thread::sleep(Duration::from_secs(1));
                    true
                },
            )
            .unwrap();
        assert!(!matches!(event, crate::server::ListenerEvent::Provider(_)));
        if finished.try_recv().is_ok() {
            break;
        }
        assert!(std::time::Instant::now() < deadline);
        thread::yield_now();
    }
    remote.join().unwrap();
    assert_eq!(authorized, 1);
}

pub(crate) fn catalog() -> Arc<crate::formats::FormatCatalog> {
    use crate::codec::providers::{CodecCatalog, ProfileId, ProviderSelection};
    let directory =
        std::path::PathBuf::from(std::env::var_os("RPTADV_CODEC_DIR").unwrap_or_default());
    let codecs = CodecCatalog::load(&[ProviderSelection {
        path: directory.join("librptadv_codec_g711.so.1"),
        profiles: vec![ProfileId::G711Mu],
    }])
    .unwrap();
    Arc::new(crate::formats::FormatCatalog::new(Arc::new(codecs), &[ProfileId::G711Mu]).unwrap())
}

#[test]
fn configured_provider_dial_uses_the_listener_and_retirement_fences_retained_media() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let remote = socket.local_addr().unwrap();
    let mut listener = InboundIaxListener::bind_accounts(
        "127.0.0.1:0".parse().unwrap(),
        &[],
        &[account(remote)],
        Some(catalog()),
    )
    .unwrap();
    listener.enable_async(runtime()).unwrap();
    let bound = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut bytes = [0; 2048];
        let (length, source) = socket.recv_from(&mut bytes).unwrap();
        assert_eq!(source, bound);
        let initial = parse_full_frame_packet(&bytes[..length]).unwrap();
        let local_call = initial.header.source_call_number;
        let elements = parse_information_elements(initial.payload).unwrap();
        for (kind, text) in [
            (6, "telephone-login"),
            (1, "*99#"),
            (2, "KG0BP"),
            (5, "outgoing"),
        ] {
            assert_eq!(
                elements.iter().find(|ie| ie.kind == kind).unwrap().data,
                text.as_bytes()
            );
        }
        let auth = serialize_information_elements(&[
            InformationElement {
                kind: 14,
                data: &[0, 2],
            },
            InformationElement {
                kind: 15,
                data: b"dial-nonce",
            },
        ])
        .unwrap();
        reply(
            &socket,
            source,
            local_call,
            IaxCommand::AuthReq,
            0,
            1,
            &auth,
        );
        let (length, _) = socket.recv_from(&mut bytes).unwrap();
        let authenticated = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(
            decode_iax_command(&authenticated.header),
            Ok(Some(IaxCommand::AuthRep))
        );
        let elements = parse_information_elements(authenticated.payload).unwrap();
        assert!(crate::authentication::verify_md5_authrep(
            "dial-nonce",
            "fixture-secret",
            elements.iter().find(|ie| ie.kind == 16).unwrap().data
        ));
        reply(
            &socket,
            source,
            local_call,
            IaxCommand::Accept,
            1,
            2,
            &[9, 4, 0, 0, 0, 4],
        );
        let (length, _) = socket.recv_from(&mut bytes).unwrap();
        assert_eq!(
            decode_iax_command(&parse_full_frame_packet(&bytes[..length]).unwrap().header),
            Ok(Some(IaxCommand::Ack))
        );
        let mut answer = serialize_full_frame(
            &FullFrameHeader {
                source_call_number: 77,
                destination_call_number: local_call,
                retransmission: false,
                timestamp: 124,
                outgoing_sequence: 2,
                incoming_sequence: 2,
                frame_type: 4,
                subclass: 4,
                subclass_is_log: false,
            },
            &[],
        )
        .unwrap();
        socket.send_to(&answer, source).unwrap();
        let (length, _) = socket.recv_from(&mut bytes).unwrap();
        assert_eq!(
            decode_iax_command(&parse_full_frame_packet(&bytes[..length]).unwrap().header),
            Ok(Some(IaxCommand::Ack))
        );
        // This queued digit belongs to the soon-to-be-retired exact account.
        answer[8] = 3;
        answer[10] = 1;
        answer[11] = b'5';
        socket.send_to(&answer, source).unwrap();
        let (length, _) = socket.recv_from(&mut bytes).unwrap();
        let idle = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(idle.header.frame_type, 2);
        assert!(idle.payload.is_empty());
    });
    let mut prepared = listener
        .prepare_dial(
            "provider-one",
            7,
            DialRequest {
                destination: "*99#".into(),
                caller_number: "KG0BP".into(),
                caller_name: "Operator".into(),
                context: "outgoing".into(),
                timeout: Duration::from_secs(2),
            },
        )
        .unwrap();
    let call = prepared.run().unwrap();
    assert!(matches!(prepared.run(), Err(AccountError::InvalidOptions)));
    assert_eq!(call.metadata.account, "provider-one");
    assert_eq!(call.metadata.account_generation, 7);
    assert_eq!(call.metadata.local_binding, "operator-west");
    let mut peer = call.into_peer();
    assert_eq!(peer.local_addr().unwrap(), bound);
    assert_eq!(peer.format(), 4);
    assert!(matches!(peer.send_prepared_audio(&[0xff; 80], 80, 0),
        Err(crate::client::DialError::Provider(error)) if error.status == crate::codec::providers::Status::Malformed));
    let jitter = crate::jitter::fixture::Fixture::new();
    unsafe { peer.configure_jitter(jitter.descriptor()) }.unwrap();
    assert_eq!(jitter.policy(), (160, 320, 800, 160));
    assert_eq!(
        peer.send_prepared_audio(&[], 0, 0).unwrap(),
        crate::client::MediaSend::Accepted
    );
    server.join().unwrap();
    listener.configure_accounts(&[]).unwrap();
    assert!(matches!(
        peer.poll_event(&mut [0.0; 160], &mut [0; 255]),
        Err(crate::client::DialError::Protocol(
            crate::session::CallSetupError::CallFinished
        ))
    ));
    assert!(
        peer.prepare_audio(&[0.0; 160], &mut [0; 160], false)
            .is_err()
    );
    assert!(peer.send_dtmf(b'9').is_err());
    // Local protocol cleanup remains available after admission/media retirement.
    peer.hangup().unwrap();
    drop(peer);
    drop(prepared);
    listener.poll(1, |_| false).unwrap();
    assert_eq!(listener.ingress_stats().active_routes, 0);
}

#[test]
fn provider_incoming_authenticates_nonnumeric_caller_then_uses_the_common_dynamic_media_owner() {
    use crate::server::ListenerEvent;
    use crate::session::{CallSetupResponse, OutboundCallSetup};
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let remote = socket.local_addr().unwrap();
    let mut config = account(remote);
    config.local_binding = "n".repeat(63);
    let mut listener = InboundIaxListener::bind_accounts(
        "127.0.0.1:0".parse().unwrap(),
        &[],
        &[config],
        Some(catalog()),
    )
    .unwrap();
    listener.enable_async(runtime()).unwrap();
    let bound = listener.local_addr().unwrap();
    let remote_owner = thread::spawn(move || {
        let mut setup = OutboundCallSetup::new(
            77,
            0,
            &[
                InformationElement {
                    kind: 6,
                    data: b"telephone-login",
                },
                InformationElement {
                    kind: 1,
                    data: b"incoming-extension",
                },
                InformationElement {
                    kind: 2,
                    data: b"KG0BP",
                },
                InformationElement {
                    kind: 4,
                    data: b"Untrusted display",
                },
                InformationElement {
                    kind: 5,
                    data: b"untrusted-context",
                },
                InformationElement {
                    kind: 9,
                    data: &[0, 0, 0, 4],
                },
                InformationElement {
                    kind: 8,
                    data: &[0, 0, 0, 4],
                },
            ],
        )
        .unwrap();
        socket.send_to(setup.initial_packet(), bound).unwrap();
        let mut bytes = [0; 2048];
        loop {
            let (length, source) = socket.recv_from(&mut bytes).unwrap();
            assert_eq!(source, bound);
            let packet = parse_full_frame_packet(&bytes[..length]).unwrap();
            let answered = packet.header.frame_type == 4 && packet.header.subclass == 4;
            if decode_iax_command(&packet.header) == Ok(Some(IaxCommand::Accept)) {
                assert_eq!(
                    (
                        packet.header.outgoing_sequence,
                        packet.header.incoming_sequence
                    ),
                    (1, 2)
                );
            }
            match setup
                .receive(&bytes[..length], 0, "fixture-secret")
                .unwrap()
            {
                CallSetupResponse::Send(bytes) => {
                    socket.send_to(&bytes, bound).unwrap();
                }
                CallSetupResponse::Accepted {
                    format,
                    acknowledgement,
                } => {
                    assert_eq!(format, 4);
                    socket.send_to(&acknowledgement, bound).unwrap();
                }
                other => panic!("unexpected incoming setup response: {other:?}"),
            }
            if answered {
                break;
            }
        }
        socket
            .send_to(&setup.send_voice_frame(&[0xff; 160], 20, 4).unwrap(), bound)
            .unwrap();
        let (length, _) = socket.recv_from(&mut bytes).unwrap();
        setup
            .receive(&bytes[..length], 20, "fixture-secret")
            .unwrap();
        socket
            .send_to(&setup.send_dtmf(b'5', 40).unwrap(), bound)
            .unwrap();
        let (length, _) = socket.recv_from(&mut bytes).unwrap();
        setup
            .receive(&bytes[..length], 40, "fixture-secret")
            .unwrap();
        let mut short = Vec::from(77u16.to_be_bytes());
        short.extend_from_slice(&60u16.to_be_bytes());
        short.extend_from_slice(&[0xff; 80]);
        socket.send_to(&short, bound).unwrap();
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut authorized = 0;
    let mut authorized_route = None;
    let assert_metadata = |metadata: &crate::provider::ProviderCallMetadata| {
        assert_eq!(metadata.account, "provider-one");
        assert_eq!(metadata.account_generation, 7);
        assert_eq!(metadata.local_binding, "n".repeat(63));
        assert_eq!(metadata.username, "telephone-login");
        assert_eq!(metadata.caller_number, "KG0BP");
        assert_eq!(metadata.called, "incoming-extension");
        assert_eq!(metadata.caller_name, "Untrusted display");
        assert_eq!(metadata.context, "untrusted-context");
        assert_eq!(metadata.remote, remote);
        assert_eq!(metadata.local, bound);
        assert_eq!(metadata.remote_call, 77);
        assert_eq!(metadata.format, 4);
        assert!(metadata.incoming && metadata.call_generation != 0 && metadata.local_call != 0);
    };
    let call = loop {
        match listener
            .poll_accounts(
                1000,
                |_, _, _| panic!("provider reached numeric policy"),
                |metadata| {
                    authorized += 1;
                    assert_metadata(metadata);
                    authorized_route = Some((metadata.call_generation, metadata.local_call));
                    metadata.incoming
                },
            )
            .unwrap()
        {
            ListenerEvent::Provider(call) => break call,
            _ => assert!(
                std::time::Instant::now() < deadline,
                "incoming setup deadline"
            ),
        }
        thread::yield_now();
    };
    assert_eq!(authorized, 1);
    assert_metadata(&call.metadata);
    assert_eq!(
        authorized_route,
        Some((call.metadata.call_generation, call.metadata.local_call))
    );
    let mut peer = call.into_peer();
    let mut pcm = [1.0; 160];
    let mut audio = false;
    let mut digit = false;
    while !(audio && digit) {
        match peer.poll_event(&mut pcm, &mut [0; 255]).unwrap() {
            crate::client::IaxPeerEvent::Audio(count) => {
                assert_eq!(count, 160);
                assert!(pcm.iter().all(|sample| *sample == 0.0));
                audio = true;
            }
            crate::client::IaxPeerEvent::Digit(value) => {
                assert_eq!(value, b'5');
                digit = true;
            }
            _ => assert!(
                std::time::Instant::now() < deadline,
                "incoming media deadline"
            ),
        }
        thread::yield_now();
    }
    remote_owner.join().unwrap();
    loop {
        match peer.poll_event(&mut pcm, &mut [0; 255]) {
            Err(crate::client::DialError::Provider(error)) => {
                assert_eq!(error.status, crate::codec::providers::Status::Malformed);
                assert_eq!(
                    error.operation,
                    "phone profile requires PCMU/PCMA 8 kHz 20 ms packets"
                );
                break;
            }
            Ok(crate::client::IaxPeerEvent::None) => assert!(std::time::Instant::now() < deadline),
            other => panic!("short phone packet reached media admission: {other:?}"),
        }
        thread::yield_now();
    }
    peer.hangup().unwrap();
    drop(peer);
    listener
        .poll_accounts(1000, |_, _, _| false, |_| false)
        .unwrap();
    assert_eq!(listener.ingress_stats().active_routes, 0);
}

pub(crate) fn reply(
    socket: &UdpSocket,
    remote: SocketAddr,
    local_call: u16,
    command: IaxCommand,
    sequence: u8,
    incoming: u8,
    payload: &[u8],
) {
    socket
        .send_to(
            &serialize_full_frame(
                &FullFrameHeader {
                    source_call_number: 77,
                    destination_call_number: local_call,
                    retransmission: false,
                    timestamp: 123,
                    outgoing_sequence: sequence,
                    incoming_sequence: incoming,
                    frame_type: 6,
                    subclass: command.subclass_value() as u8,
                    subclass_is_log: false,
                },
                payload,
            )
            .unwrap(),
            remote,
        )
        .unwrap();
}

#[test]
fn provider_registration_refresh_and_authenticated_release_share_the_listener_port() {
    let registrar = UdpSocket::bind("127.0.0.1:0").unwrap();
    registrar
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let remote = registrar.local_addr().unwrap();
    let mut listener = InboundIaxListener::bind_accounts(
        "127.0.0.1:0".parse().unwrap(),
        &[],
        &[account(remote)],
        None,
    )
    .unwrap();
    listener.enable_async(runtime()).unwrap();
    let bound = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut bytes = [0; 2048];
        for release in [false, false, true] {
            let (length, source) = registrar.recv_from(&mut bytes).unwrap();
            assert_eq!(source, bound);
            let initial = parse_full_frame_packet(&bytes[..length]).unwrap();
            let command = if release {
                IaxCommand::RegRel
            } else {
                IaxCommand::RegReq
            };
            assert_eq!(decode_iax_command(&initial.header), Ok(Some(command)));
            assert_eq!(
                (
                    initial.header.outgoing_sequence,
                    initial.header.incoming_sequence
                ),
                (0, 0)
            );
            assert_eq!(initial.header.destination_call_number, 0);
            let local_call = initial.header.source_call_number;
            let elements = parse_information_elements(initial.payload).unwrap();
            assert_eq!(
                elements.iter().find(|ie| ie.kind == 6).unwrap().data,
                b"telephone-login"
            );
            assert!(!elements.iter().any(|ie| ie.kind == 16));
            let token = b"opaque-registrar-token";
            let payload = serialize_information_elements(&[InformationElement {
                kind: 54,
                data: token,
            }])
            .unwrap();
            reply(
                &registrar,
                source,
                local_call,
                IaxCommand::CallToken,
                0,
                0,
                &payload,
            );
            let (length, repeated_source) = registrar.recv_from(&mut bytes).unwrap();
            assert_eq!(repeated_source, source);
            let retried = parse_full_frame_packet(&bytes[..length]).unwrap();
            assert_eq!(decode_iax_command(&retried.header), Ok(Some(command)));
            assert_eq!(
                (
                    retried.header.destination_call_number,
                    retried.header.outgoing_sequence,
                    retried.header.incoming_sequence
                ),
                (0, 0, 0)
            );
            assert_eq!(
                parse_information_elements(retried.payload)
                    .unwrap()
                    .last()
                    .unwrap()
                    .data,
                token
            );
            let methods = 2_u16.to_be_bytes();
            let auth = serialize_information_elements(&[
                InformationElement {
                    kind: 6,
                    data: b"telephone-login",
                },
                InformationElement {
                    kind: 14,
                    data: &methods,
                },
                InformationElement {
                    kind: 15,
                    data: b"nonce-123",
                },
            ])
            .unwrap();
            reply(
                &registrar,
                source,
                local_call,
                IaxCommand::RegAuth,
                0,
                1,
                &auth,
            );
            let (length, source) = registrar.recv_from(&mut bytes).unwrap();
            let authenticated = parse_full_frame_packet(&bytes[..length]).unwrap();
            assert_eq!(decode_iax_command(&authenticated.header), Ok(Some(command)));
            assert_eq!(
                (
                    authenticated.header.outgoing_sequence,
                    authenticated.header.incoming_sequence
                ),
                (1, 1)
            );
            assert_eq!(authenticated.header.destination_call_number, 77);
            let elements = parse_information_elements(authenticated.payload).unwrap();
            assert!(crate::authentication::verify_md5_authrep(
                "nonce-123",
                "fixture-secret",
                elements.iter().find(|ie| ie.kind == 16).unwrap().data
            ));
            let original_response = bytes[..length].to_vec();
            // Lost request acknowledgment may repeat the original challenge,
            // including its old ISeqno. It must not consume another sequence.
            reply(
                &registrar,
                source,
                local_call,
                IaxCommand::RegAuth,
                0,
                1,
                &auth,
            );
            let (length, _) = registrar.recv_from(&mut bytes).unwrap();
            assert_eq!(&bytes[..length], original_response);
            let refresh = 42_u16.to_be_bytes();
            let payload = serialize_information_elements(&[
                InformationElement {
                    kind: 6,
                    data: b"telephone-login",
                },
                InformationElement {
                    kind: 19,
                    data: &refresh,
                },
            ])
            .unwrap();
            reply(
                &registrar,
                source,
                local_call,
                IaxCommand::RegAck,
                1,
                2,
                &payload,
            );
            let (length, source) = registrar.recv_from(&mut bytes).unwrap();
            assert_eq!(source, bound);
            let ack = parse_full_frame_packet(&bytes[..length]).unwrap();
            assert_eq!(decode_iax_command(&ack.header), Ok(Some(IaxCommand::Ack)));
            assert_eq!(
                (ack.header.outgoing_sequence, ack.header.incoming_sequence),
                (2, 2)
            );
            assert_eq!(ack.header.timestamp, 123);
        }
    });
    for release in [false, false, true] {
        let mut prepared = listener
            .prepare_registration(
                "provider-one",
                7,
                RegistrationRequest {
                    refresh: 60,
                    release,
                    timeout: Duration::from_secs(2),
                },
            )
            .unwrap();
        assert_eq!(prepared.run().unwrap().refresh, 42);
        drop(prepared);
        listener.poll(1, |_| false).unwrap();
    }
    server.join().unwrap();
}

#[test]
fn retired_account_cannot_install_a_prepared_registration_route() {
    let registrar = UdpSocket::bind("127.0.0.1:0").unwrap();
    registrar.set_nonblocking(true).unwrap();
    let mut listener = InboundIaxListener::bind_accounts(
        "127.0.0.1:0".parse().unwrap(),
        &[],
        &[account(registrar.local_addr().unwrap())],
        None,
    )
    .unwrap();
    listener.enable_async(runtime()).unwrap();
    let mut prepared = listener
        .prepare_registration(
            "provider-one",
            7,
            RegistrationRequest {
                refresh: 60,
                release: false,
                timeout: Duration::from_secs(1),
            },
        )
        .unwrap();
    listener.configure_accounts(&[]).unwrap();
    assert!(matches!(prepared.run(), Err(AccountError::Retired)));
    let mut bytes = [0; 2048];
    assert_eq!(
        registrar.recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(prepared);
    listener.poll(1, |_| false).unwrap();
    assert_eq!(listener.ingress_stats().active_routes, 0);
}

#[test]
fn phone_catalog_preserves_selected_g711_and_rejects_other_real_provider_profiles() {
    use crate::codec::providers::{CodecCatalog, ProfileId, ProviderSelection};
    use crate::formats::FormatCatalog;
    let codecs = Arc::new(
        CodecCatalog::load(&[
            ProviderSelection {
                path: "librptadv_codec_g711.so.1".into(),
                profiles: vec![ProfileId::G711Mu, ProfileId::G711A],
            },
            ProviderSelection {
                path: "librptadv_codec_pcm.so.1".into(),
                profiles: vec![ProfileId::Pcm8],
            },
        ])
        .unwrap(),
    );
    let generic = FormatCatalog::new(
        codecs.clone(),
        &[ProfileId::Pcm8, ProfileId::G711A, ProfileId::G711Mu],
    )
    .unwrap();
    assert_eq!(generic.advertised_mask(), 4 | 8 | 64);
    let phone = generic.phone().unwrap();
    assert_eq!(phone.advertised_mask(), 4 | 8);
    assert_eq!(phone.select(8), Ok(ProfileId::G711A));
    assert_eq!(phone.select(4 | 8), Ok(ProfileId::G711Mu));
    assert_eq!(generic.advertised_mask(), 4 | 8 | 64);
    let unsupported = Arc::new(FormatCatalog::new(codecs, &[ProfileId::Pcm8]).unwrap());
    assert!(unsupported.phone().is_none());
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote.set_nonblocking(true).unwrap();
    let mut listener = InboundIaxListener::bind_accounts(
        "127.0.0.1:0".parse().unwrap(),
        &[],
        &[account(remote.local_addr().unwrap())],
        Some(unsupported),
    )
    .unwrap();
    listener.enable_async(runtime()).unwrap();
    assert!(matches!(
        listener.prepare_dial(
            "provider-one",
            7,
            DialRequest {
                destination: "extension".into(),
                caller_number: "".into(),
                caller_name: "".into(),
                context: "".into(),
                timeout: Duration::from_secs(1)
            }
        ),
        Err(AccountError::Call(
            crate::client::DialError::UnsupportedFormat(64)
        ))
    ));
    assert_eq!(listener.ingress_stats().active_routes, 0);
    assert_eq!(
        remote.recv_from(&mut [0; 2048]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn phone_provider_rejects_non_g711_offer_before_authentication_or_numeric_fallback() {
    use crate::session::{CallSetupResponse, OutboundCallSetup};
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut listener = InboundIaxListener::bind_accounts(
        "127.0.0.1:0".parse().unwrap(),
        &["1234".into()],
        &[account(socket.local_addr().unwrap())],
        Some(catalog()),
    )
    .unwrap();
    listener.enable_async(runtime()).unwrap();
    let bound = listener.local_addr().unwrap();
    let remote = thread::spawn(move || {
        let mut setup = OutboundCallSetup::new(
            77,
            0,
            &[
                InformationElement {
                    kind: 6,
                    data: b"telephone-login",
                },
                InformationElement {
                    kind: 1,
                    data: b"1234",
                },
                InformationElement {
                    kind: 9,
                    data: &[0, 0, 0, 64],
                },
            ],
        )
        .unwrap();
        socket.send_to(setup.initial_packet(), bound).unwrap();
        let mut bytes = [0; 2048];
        let (length, _) = socket.recv_from(&mut bytes).unwrap();
        let CallSetupResponse::Send(token_retry) = setup
            .receive(&bytes[..length], 0, "fixture-secret")
            .unwrap()
        else {
            panic!("missing stateless challenge")
        };
        socket.send_to(&token_retry, bound).unwrap();
        let (length, _) = socket.recv_from(&mut bytes).unwrap();
        assert!(matches!(
            setup.receive(&bytes[..length], 0, "fixture-secret"),
            Ok(CallSetupResponse::Rejected { .. })
        ));
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !remote.is_finished() {
        listener
            .poll_accounts(
                1000,
                |_, _, _| panic!("phone account reached numeric admission"),
                |_| panic!("unsupported codec reached authentication admission"),
            )
            .unwrap();
        assert!(std::time::Instant::now() < deadline);
        thread::yield_now();
    }
    remote.join().unwrap();
    listener
        .poll_accounts(1000, |_, _, _| false, |_| false)
        .unwrap();
    assert_eq!(listener.ingress_stats().active_routes, 0);
}

/// A real registrar response on the listener's actual pending route. A response
/// failure retains ownership until drop; cleanup must acknowledge that exact route.
fn registration_response(
    command: IaxCommand,
    outgoing: u8,
    incoming: u8,
    payload: Vec<u8>,
) -> Result<crate::provider::RegistrationReceipt, AccountError> {
    registration_exchange(move |socket, source, local_call| {
        reply(
            &socket, source, local_call, command, outgoing, incoming, &payload,
        )
    })
}
fn registration_exchange(
    action: impl FnOnce(UdpSocket, SocketAddr, u16) + Send + 'static,
) -> Result<crate::provider::RegistrationReceipt, AccountError> {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    let mut listener = InboundIaxListener::bind_accounts(
        "127.0.0.1:0".parse().unwrap(),
        &[],
        &[account(socket.local_addr().unwrap())],
        None,
    )
    .unwrap();
    listener.enable_async(runtime()).unwrap();
    let server = thread::spawn(move || {
        let mut bytes = [0; 2048];
        let (length, source) = socket.recv_from(&mut bytes).unwrap();
        let local_call = parse_full_frame_packet(&bytes[..length])
            .unwrap()
            .header
            .source_call_number;
        action(socket, source, local_call);
    });
    let mut operation = listener
        .prepare_registration(
            "provider-one",
            7,
            RegistrationRequest {
                refresh: 60,
                release: false,
                timeout: Duration::from_secs(5),
            },
        )
        .unwrap();
    let result = operation.run();
    assert!(matches!(operation.run(), Err(AccountError::InvalidOptions)));
    assert!(
        server.join().is_ok(),
        "registrar did not receive initial request; actual operation result: {result:?}"
    );
    assert_eq!(listener.ingress_stats().active_routes, 1);
    drop(operation);
    listener
        .poll_accounts(1000, |_, _, _| false, |_| false)
        .unwrap();
    assert_eq!(listener.ingress_stats().active_routes, 0);
    result
}

#[test]
fn registration_validates_wire_sequences_methods_unique_fields_and_native_addresses() {
    let payload = |elements: &[(u8, &[u8])]| {
        serialize_information_elements(
            &elements
                .iter()
                .map(|(kind, data)| InformationElement { kind: *kind, data })
                .collect::<Vec<_>>(),
        )
        .unwrap()
    };
    let receipt = registration_response(IaxCommand::RegAck, 0, 1, Vec::new()).unwrap();
    assert_eq!(receipt.refresh, 60);
    assert_eq!(receipt.apparent, None);
    let mut v6 = vec![10, 0, 0x11, 0x99];
    v6.extend_from_slice(&0x12345678u32.to_be_bytes());
    v6.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
    v6.extend_from_slice(&7u32.to_le_bytes());
    let receipt = registration_response(
        IaxCommand::RegAck,
        0,
        1,
        payload(&[(18, &v6), (19, &[0, 42])]),
    )
    .unwrap();
    assert_eq!(receipt.refresh, 42);
    assert_eq!(
        receipt.apparent,
        Some(SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::LOCALHOST,
            4505,
            0x12345678,
            7
        )))
    );
    for invalid in [
        vec![2, 0],
        vec![1; 16],
        vec![10; 27],
        vec![10; 28],
        vec![2, 0, 0, 1, 127, 0, 0, 1],
        vec![10, 0, 0, 1],
    ] {
        assert!(matches!(
            registration_response(IaxCommand::RegAck, 0, 1, payload(&[(18, &invalid)])),
            Err(AccountError::Protocol)
        ));
    }
    for elements in [
        vec![(6, &b"other-login"[..])],
        vec![(6, &b"telephone-login"[..]), (6, &b"telephone-login"[..])],
        vec![(19, &b"x"[..])],
        vec![(19, &b"xy"[..]), (19, &b"xy"[..])],
    ] {
        assert!(matches!(
            registration_response(IaxCommand::RegAck, 0, 1, payload(&elements)),
            Err(AccountError::Protocol)
        ));
    }
    for (outgoing, incoming) in [(1, 1), (0, 0)] {
        assert!(matches!(
            registration_response(IaxCommand::RegAck, outgoing, incoming, Vec::new()),
            Err(AccountError::Protocol)
        ));
    }
    assert!(matches!(
        registration_response(IaxCommand::Ack, 1, 1, Vec::new()),
        Err(AccountError::Protocol)
    ));
    assert!(matches!(
        registration_response(IaxCommand::Ack, 0, 1, Vec::new()),
        Err(AccountError::Timeout)
    ));
    assert!(matches!(
        registration_response(IaxCommand::Ping, 0, 1, Vec::new()),
        Err(AccountError::Protocol)
    ));
    assert!(matches!(
        registration_response(IaxCommand::RegRej, 0, 1, Vec::new()),
        Err(AccountError::Rejected)
    ));
    for elements in [
        vec![
            (6, &b"telephone-login"[..]),
            (14, &b"\x00\x01"[..]),
            (15, &b"nonce"[..]),
        ],
        vec![
            (6, &b"telephone-login"[..]),
            (14, &b"\x00\x02"[..]),
            (15, &b""[..]),
        ],
        vec![
            (6, &b"wrong"[..]),
            (14, &b"\x00\x02"[..]),
            (15, &b"nonce"[..]),
        ],
        vec![(14, &b"\x00\x02"[..]), (15, &b"nonce"[..])],
        vec![
            (6, &b"telephone-login"[..]),
            (6, &b"telephone-login"[..]),
            (14, &b"\x00\x02"[..]),
            (15, &b"nonce"[..]),
        ],
    ] {
        assert!(matches!(
            registration_response(IaxCommand::RegAuth, 0, 1, payload(&elements)),
            Err(AccountError::Protocol)
        ));
    }
}

#[test]
fn registration_retries_exact_committed_request_then_times_out_without_releasing_ownership() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(25)))
        .unwrap();
    let mut listener = InboundIaxListener::bind_accounts(
        "127.0.0.1:0".parse().unwrap(),
        &[],
        &[account(socket.local_addr().unwrap())],
        None,
    )
    .unwrap();
    listener.enable_async(runtime()).unwrap();
    let bound = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut bytes = [0; 2048];
        let (length, source) = socket.recv_from(&mut bytes).unwrap();
        assert_eq!(source, bound);
        let first = parse_full_frame_packet(&bytes[..length]).unwrap();
        let original = first.payload.to_vec();
        assert!(!first.header.retransmission);
        for _ in 0..3 {
            let (length, repeated_source) = socket.recv_from(&mut bytes).unwrap();
            assert_eq!(repeated_source, source);
            let retry = parse_full_frame_packet(&bytes[..length]).unwrap();
            assert!(retry.header.retransmission);
            assert_eq!(
                (
                    retry.header.outgoing_sequence,
                    retry.header.incoming_sequence
                ),
                (0, 0)
            );
            assert_eq!(retry.payload, original);
        }
    });
    let mut operation = listener
        .prepare_registration(
            "provider-one",
            7,
            RegistrationRequest {
                refresh: 60,
                release: false,
                timeout: Duration::from_secs(25),
            },
        )
        .unwrap();
    assert!(matches!(operation.run(), Err(AccountError::Timeout)));
    server.join().unwrap();
    assert_eq!(listener.ingress_stats().active_routes, 1);
    drop(operation);
    listener
        .poll_accounts(1000, |_, _, _| false, |_| false)
        .unwrap();
    assert_eq!(listener.ingress_stats().active_routes, 0);
}

#[test]
fn provider_errors_describe_failure_without_credentials() {
    for (error, expected) in [
        (
            AccountError::InvalidOptions,
            "invalid IAX provider operation",
        ),
        (
            AccountError::AsyncRequired,
            "IAX provider requires asynchronous listener",
        ),
        (AccountError::Busy, "IAX provider capacity unavailable"),
        (AccountError::Retired, "IAX provider owner retired"),
        (AccountError::Timeout, "IAX provider operation timed out"),
        (AccountError::Rejected, "IAX registrar rejected operation"),
        (AccountError::Protocol, "invalid IAX provider response"),
        (
            AccountError::Network(std::io::ErrorKind::ConnectionReset.into()),
            "IAX provider network failure: connection reset",
        ),
        (
            AccountError::Call(crate::client::DialError::Rejected),
            "IAX provider call setup failed",
        ),
    ] {
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn provider_capacity_uses_real_reserved_owners_and_releases_only_after_cleanup() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let config = account(remote.local_addr().unwrap());
    let mut listener = InboundIaxListener::bind_accounts(
        "127.0.0.1:0".parse().unwrap(),
        &[],
        &[config.clone()],
        Some(catalog()),
    )
    .unwrap();
    listener.enable_async(runtime()).unwrap();
    let request = || RegistrationRequest {
        refresh: 60,
        release: false,
        timeout: Duration::from_secs(1),
    };
    let mut owners = Vec::new();
    for _ in 0..crate::provider::MAX_ACCOUNTS {
        owners.push(
            listener
                .prepare_registration("provider-one", 7, request())
                .unwrap(),
        );
    }
    assert!(matches!(
        listener.prepare_registration("provider-one", 7, request()),
        Err(AccountError::Busy)
    ));
    drop(owners.pop());
    // Drop requests retirement; it is not the receiver's cleanup acknowledgment.
    assert!(matches!(
        listener.prepare_registration("provider-one", 7, request()),
        Err(AccountError::Busy)
    ));
    listener
        .poll_accounts(1000, |_, _, _| false, |_| false)
        .unwrap();
    let replacement = listener
        .prepare_registration("provider-one", 7, request())
        .unwrap();
    let mut invalid = config.clone();
    invalid.pending_auth_timeout = Duration::MAX;
    assert!(matches!(
        listener.configure_accounts(&[invalid]),
        Err(AccountError::InvalidOptions)
    ));
    assert!(matches!(
        listener.prepare_registration("provider-one", 7, request()),
        Err(AccountError::Busy)
    ));
    drop(replacement);
    drop(owners);
    for _ in 0..crate::provider::MAX_ACCOUNTS {
        listener
            .poll_accounts(1000, |_, _, _| false, |_| false)
            .unwrap();
    }
    assert_eq!(listener.ingress_stats().active_routes, 0);
    let operation = listener
        .prepare_registration("provider-one", 7, request())
        .unwrap();
    drop(operation);
}

pub(crate) fn pending_incoming(
    listener: &mut InboundIaxListener,
    socket: &UdpSocket,
) -> (crate::session::OutboundCallSetup, Vec<u8>, Vec<u8>, Vec<u8>) {
    use crate::session::{CallSetupResponse, OutboundCallSetup};
    let bound = listener.local_addr().unwrap();
    let mut setup = OutboundCallSetup::new(
        77,
        0,
        &[
            InformationElement {
                kind: 6,
                data: b"telephone-login",
            },
            InformationElement {
                kind: 1,
                data: b"incoming-extension",
            },
            InformationElement {
                kind: 2,
                data: b"KG0BP",
            },
            InformationElement {
                kind: 9,
                data: &[0, 0, 0, 4],
            },
        ],
    )
    .unwrap();
    socket.send_to(setup.initial_packet(), bound).unwrap();
    poll_reply(listener);
    let mut bytes = [0; 2048];
    let (length, _) = socket.recv_from(&mut bytes).unwrap();
    let CallSetupResponse::Send(retry) = setup
        .receive(&bytes[..length], 0, "fixture-secret")
        .unwrap()
    else {
        panic!("missing call-token challenge")
    };
    socket.send_to(&retry, bound).unwrap();
    poll_reply(listener);
    let (length, _) = socket.recv_from(&mut bytes).unwrap();
    let request = bytes[..length].to_vec();
    let CallSetupResponse::Send(response) = setup.receive(&request, 0, "fixture-secret").unwrap()
    else {
        panic!("missing MD5 challenge")
    };
    (setup, retry, request, response)
}

pub(crate) fn poll_reply(listener: &mut InboundIaxListener) {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        match listener
            .poll_accounts(
                1000,
                |_, _, _| panic!("phone reached numeric policy"),
                |_| panic!("unverified call reached admission"),
            )
            .unwrap()
        {
            crate::server::ListenerEvent::Replied => return,
            crate::server::ListenerEvent::None | crate::server::ListenerEvent::Ignored => {
                assert!(std::time::Instant::now() < deadline)
            }
            _ => panic!("unverified call admitted"),
        }
        thread::yield_now();
    }
}

#[test]
fn registration_fences_zero_or_changed_call_and_does_not_accept_changed_or_late_challenges() {
    for variant in 0..6 {
        let result = registration_exchange(move |socket, source, local_call| {
            let auth = serialize_information_elements(&[
                InformationElement {
                    kind: 6,
                    data: b"telephone-login",
                },
                InformationElement {
                    kind: 14,
                    data: &[0, 2],
                },
                InformationElement {
                    kind: 15,
                    data: b"first-nonce",
                },
            ])
            .unwrap();
            if variant != 0 {
                reply(
                    &socket,
                    source,
                    local_call,
                    IaxCommand::RegAuth,
                    0,
                    1,
                    &auth,
                );
                let mut bytes = [0; 2048];
                let (length, _) = socket.recv_from(&mut bytes).unwrap();
                let frame = parse_full_frame_packet(&bytes[..length]).unwrap();
                assert_eq!(frame.header.outgoing_sequence, 1);
                assert_eq!(
                    decode_iax_command(&frame.header),
                    Ok(Some(IaxCommand::RegReq))
                );
            }
            let mut payload = auth;
            if variant == 3 {
                payload.extend_from_slice(&[99, 0]);
            }
            let packet = serialize_full_frame(
                &FullFrameHeader {
                    source_call_number: if variant == 0 {
                        0
                    } else if variant == 1 {
                        88
                    } else {
                        77
                    },
                    destination_call_number: local_call,
                    retransmission: false,
                    timestamp: if variant == 2 { 124 } else { 123 },
                    outgoing_sequence: if variant >= 4 { 1 } else { 0 },
                    incoming_sequence: if variant >= 4 { 2 } else { 1 },
                    frame_type: 6,
                    subclass: if variant == 0 {
                        IaxCommand::RegAck
                    } else if variant == 4 {
                        IaxCommand::CallToken
                    } else {
                        IaxCommand::RegAuth
                    }
                    .subclass_value() as u8,
                    subclass_is_log: false,
                },
                &payload,
            )
            .unwrap();
            socket.send_to(&packet, source).unwrap();
        });
        assert!(
            matches!(result, Err(AccountError::Protocol)),
            "mutation{variant}: {result:?}"
        );
    }
}

pub(crate) fn answer_outgoing(
    socket: UdpSocket,
) -> (
    thread::JoinHandle<UdpSocket>,
    Arc<std::sync::atomic::AtomicU16>,
) {
    let observed = Arc::new(std::sync::atomic::AtomicU16::new(0));
    let source = observed.clone();
    let task = thread::spawn(move || {
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut bytes = [0; 2048];
        let (length, remote) = socket.recv_from(&mut bytes).unwrap();
        let initial = parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(
            decode_iax_command(&initial.header),
            Ok(Some(IaxCommand::New))
        );
        let local = initial.header.source_call_number;
        source.store(local, std::sync::atomic::Ordering::Release);
        reply(
            &socket,
            remote,
            local,
            IaxCommand::Accept,
            0,
            1,
            &[9, 4, 0, 0, 0, 4],
        );
        let (length, _) = socket.recv_from(&mut bytes).unwrap();
        assert_eq!(
            decode_iax_command(&parse_full_frame_packet(&bytes[..length]).unwrap().header),
            Ok(Some(IaxCommand::Ack))
        );
        let answer = serialize_full_frame(
            &FullFrameHeader {
                source_call_number: 77,
                destination_call_number: local,
                retransmission: false,
                timestamp: 1,
                outgoing_sequence: 1,
                incoming_sequence: 1,
                frame_type: 4,
                subclass: 4,
                subclass_is_log: false,
            },
            &[],
        )
        .unwrap();
        socket.send_to(&answer, remote).unwrap();
        let (length, _) = socket.recv_from(&mut bytes).unwrap();
        assert_eq!(
            decode_iax_command(&parse_full_frame_packet(&bytes[..length]).unwrap().header),
            Ok(Some(IaxCommand::Ack))
        );
        socket
    });
    (task, observed)
}

#[test]
fn configured_account_boundaries_preserve_distinct_logins_same_endpoint_and_reject_invalid_bindings()
 {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut config = account(remote.local_addr().unwrap());
    let mut listener = InboundIaxListener::bind_accounts(
        "127.0.0.1:0".parse().unwrap(),
        &[],
        std::slice::from_ref(&config),
        None,
    )
    .unwrap();
    listener.enable_async(runtime()).unwrap();
    listener
        .configure_accounts(std::slice::from_ref(&config))
        .unwrap();
    listener.set_local_nodes(&["1234".into()]).unwrap();
    listener.set_local_nodes(&[]).unwrap();
    let mut second = config.clone();
    second.id = "provider-two".into();
    second.username = "other-login".into();
    listener
        .configure_accounts(&[config.clone(), second.clone()])
        .unwrap();
    second.username = config.username.clone();
    assert!(matches!(
        listener.configure_accounts(&[config.clone(), second]),
        Err(AccountError::InvalidOptions)
    ));
    for binding in ["".to_owned(), "bad\nname".into(), "x".repeat(64)] {
        let mut invalid = config.clone();
        invalid.local_binding = binding;
        assert!(matches!(
            InboundIaxListener::bind_accounts(
                "127.0.0.1:0".parse().unwrap(),
                &["1234".into()],
                &[invalid],
                None
            ),
            Err(crate::server::ListenerError::InvalidFrame)
        ));
    }
    assert!(matches!(
        listener.prepare_registration(
            "provider-one",
            7,
            RegistrationRequest {
                refresh: 60,
                release: false,
                timeout: Duration::MAX
            }
        ),
        Err(AccountError::InvalidOptions)
    ));
    let dial = || DialRequest {
        destination: "999".into(),
        caller_number: "".into(),
        caller_name: "".into(),
        context: "".into(),
        timeout: Duration::from_secs(1),
    };
    assert!(matches!(
        listener.prepare_dial("missing-account", 7, dial()),
        Err(AccountError::InvalidOptions)
    ));
    assert!(matches!(
        listener.prepare_dial("provider-one", 7, dial()),
        Err(AccountError::InvalidOptions)
    ));
    let too_many: Vec<_> = (0..=crate::provider::MAX_ACCOUNTS)
        .map(|n| {
            let mut item = config.clone();
            item.id = format!("account-{n}");
            item.username = format!("login-{n}");
            item
        })
        .collect();
    assert!(matches!(
        listener.configure_accounts(&too_many),
        Err(AccountError::InvalidOptions)
    ));
    let another = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut different = config.clone();
    different.id = "different-endpoint".into();
    different.remote = another.local_addr().unwrap();
    listener
        .configure_accounts(&[config.clone(), different])
        .unwrap();
    config.id = "replacement".into();
    config.generation = 8;
    listener.configure_accounts(&[config]).unwrap();
}
