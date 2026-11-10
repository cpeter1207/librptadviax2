use super::*;

#[test]
fn server_account_operations_extend_the_released_table_prefix() {
    let descriptor = unsafe { &*rptadv_iax2_server_descriptor_v2() };
    assert_eq!(descriptor.struct_size as usize, 88);
    assert_eq!(
        std::mem::offset_of!(rptadv_iax2_server_descriptor_v2, bind),
        24
    );
    assert_eq!(
        std::mem::offset_of!(rptadv_iax2_server_descriptor_v2, destroy),
        48
    );
    assert_eq!(descriptor.abi_version, 2);
    assert_eq!(DESCRIPTOR.struct_size as usize, 136);
    assert_eq!(size_of::<rptadv_iax2_server_options_v2>(), 64);
    assert!(descriptor.configure_accounts.is_some());
    assert!(descriptor.register_account.is_some());
    assert!(descriptor.poll_accounts.is_some());
    assert!(descriptor.dial_provider_account.is_some());
}

#[test]
fn released_48byte_bind_options_remain_readable_and_partial_account_tails_reject() {
    #[repr(C)]
    struct Released {
        size: u32,
        version: u32,
        address: *const u8,
        address_len: usize,
        nodes: *const u8,
        nodes_len: usize,
        catalog: *const c_void,
    }
    let released = Released {
        size: 48,
        version: 2,
        address: b"127.0.0.1:0".as_ptr(),
        address_len: 11,
        nodes: b"524950".as_ptr(),
        nodes_len: 6,
        catalog: test_catalog(),
    };
    assert_eq!(size_of::<Released>(), 48);
    let mut handle = ptr::dangling_mut::<c_void>();
    assert_eq!(
        unsafe { server_bind(ptr::from_ref(&released).cast(), &mut handle) },
        0
    );
    unsafe { server_destroy(handle) };
    for size in 49..64 {
        let mut options = server_options(b"127.0.0.1:0", b"524950");
        options.struct_size = size;
        handle = ptr::dangling_mut::<c_void>();
        assert_eq!(unsafe { server_bind(&options, &mut handle) }, -1);
        assert!(handle.is_null());
    }
}

fn byte_span(value: &[u8]) -> rptadv_iax2_bytes_v1 {
    rptadv_iax2_bytes_v1 {
        data: value.as_ptr(),
        length: value.len(),
    }
}

#[test]
fn legacy_policy_can_reconfigure_its_listener_without_deadlock_or_late_acceptance() {
    struct State {
        handle: *mut c_void,
        authorized: usize,
        accepted: usize,
    }
    unsafe extern "C" fn reconfigure(
        context: *mut c_void,
        _: *const u8,
        _: usize,
        _: *const u8,
        _: usize,
        _: *const u8,
        _: usize,
    ) -> i32 {
        let state = unsafe { &mut *context.cast::<State>() };
        state.authorized += 1;
        unsafe { server_set_local_nodes(state.handle, b"524951".as_ptr(), 6) }
    }
    unsafe extern "C" fn accepted(
        context: *mut c_void,
        _: *const u8,
        _: usize,
        _: *const u8,
        _: usize,
        _: *const u8,
        _: usize,
        peer: *mut c_void,
    ) -> i32 {
        unsafe { &mut *context.cast::<State>() }.accepted += 1;
        unsafe { destroy(peer) };
        0
    }
    let options = server_options(b"127.0.0.1:0", b"524950");
    let mut handle = ptr::null_mut();
    assert_eq!(unsafe { server_bind(&options, &mut handle) }, 0);
    let address = unsafe { &*handle.cast::<ServerHandle>() }
        .0
        .lock()
        .unwrap()
        .local_addr()
        .unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let setup = inbound_setup(42);
    client.send_to(setup.initial_packet(), address).unwrap();
    assert_eq!(
        unsafe { server_poll(handle, 100, None, None, ptr::null_mut()) },
        1
    );
    let mut bytes = [0; 2048];
    let (length, _) = client.recv_from(&mut bytes).unwrap();
    let retry = retry_new_call_with_token(setup.initial_packet(), &bytes[..length], 0).unwrap();
    client.send_to(&retry, address).unwrap();
    let mut state = State {
        handle,
        authorized: 0,
        accepted: 0,
    };
    assert_eq!(
        unsafe {
            server_poll(
                handle,
                100,
                Some(reconfigure),
                Some(accepted),
                ptr::from_mut(&mut state).cast(),
            )
        },
        -1
    );
    assert_eq!((state.authorized, state.accepted), (1, 0));
    client.set_nonblocking(true).unwrap();
    assert_eq!(
        client.recv_from(&mut bytes).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        unsafe { server_poll(handle, 100, None, None, ptr::null_mut()) },
        0
    );
    assert_eq!(
        unsafe { &*handle.cast::<ServerHandle>() }
            .0
            .lock()
            .unwrap()
            .ingress_stats()
            .active_routes,
        0
    );
    unsafe { server_destroy(handle) };
}

#[test]
fn provider_registration_copies_credentials_and_releases_control_for_concurrent_poll() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let address = socket.local_addr().unwrap().to_string();
    let mut login = b"provider-login".to_vec();
    let mut secret = b"fixture-secret".to_vec();
    let account = rptadv_iax2_provider_account_v1 {
        struct_size: size_of::<rptadv_iax2_provider_account_v1>() as u32,
        abi_version: 1,
        generation: 7,
        account: byte_span(b"provider-one"),
        local_binding: byte_span(b"operator-west"),
        remote_address: byte_span(address.as_bytes()),
        username: byte_span(&login),
        secret: byte_span(&secret),
        authentication_timeout_ms: 1000,
        reserved: 0,
    };
    let mut options = server_options(b"127.0.0.1:0", b"");
    options.accounts = &account;
    options.account_count = 1;
    let mut handle = ptr::null_mut();
    assert_eq!(unsafe { server_bind(&options, &mut handle) }, 0);
    let bound = unsafe { &*handle.cast::<ServerHandle>() }
        .0
        .lock()
        .unwrap()
        .local_addr()
        .unwrap();
    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap(),
    );
    assert_eq!(unsafe { server_enable_async(handle, runtime) }, 0);
    login.fill(b'X');
    secret.fill(b'Y');
    drop(login);
    drop(secret);
    drop(address);
    let (received, waiting) = std::sync::mpsc::channel();
    let (continue_reply, permit_reply) = std::sync::mpsc::channel();
    let registrar = thread::spawn(move || {
        let mut bytes = [0; 2048];
        let (length, source) = socket.recv_from(&mut bytes).unwrap();
        assert_eq!(source, bound);
        let first = crate::protocol::parse_full_frame_packet(&bytes[..length]).unwrap();
        let local_call = first.header.source_call_number;
        let ies = crate::information_elements::parse_information_elements(first.payload).unwrap();
        assert_eq!(
            ies.iter().find(|ie| ie.kind == 6).unwrap().data,
            b"provider-login"
        );
        received.send(()).unwrap();
        permit_reply.recv_timeout(Duration::from_secs(1)).unwrap();
        let auth = crate::information_elements::serialize_information_elements(&[
            InformationElement {
                kind: 6,
                data: b"provider-login",
            },
            InformationElement {
                kind: 14,
                data: &[0, 2],
            },
            InformationElement {
                kind: 15,
                data: b"nonce",
            },
        ])
        .unwrap();
        let header = FullFrameHeader {
            source_call_number: 77,
            destination_call_number: local_call,
            retransmission: false,
            timestamp: 0,
            outgoing_sequence: 0,
            incoming_sequence: 1,
            frame_type: 6,
            subclass: 14,
            subclass_is_log: false,
        };
        socket
            .send_to(&serialize_full_frame(&header, &auth).unwrap(), source)
            .unwrap();
        let (length, _) = socket.recv_from(&mut bytes).unwrap();
        let packet = crate::protocol::parse_full_frame_packet(&bytes[..length]).unwrap();
        let ies = crate::information_elements::parse_information_elements(packet.payload).unwrap();
        assert!(crate::authentication::verify_md5_authrep(
            "nonce",
            "fixture-secret",
            ies.iter().find(|ie| ie.kind == 16).unwrap().data
        ));
        let header = FullFrameHeader {
            outgoing_sequence: 1,
            incoming_sequence: 2,
            subclass: 15,
            ..header
        };
        socket
            .send_to(
                &serialize_full_frame(&header, &[19, 2, 0, 42]).unwrap(),
                source,
            )
            .unwrap();
        socket.recv_from(&mut bytes).unwrap();
    });
    let shared_handle = handle as usize;
    let registration = thread::spawn(move || {
        let request = rptadv_iax2_registration_options_v1 {
            struct_size: size_of::<rptadv_iax2_registration_options_v1>() as u32,
            abi_version: 1,
            account: byte_span(b"provider-one"),
            generation: 7,
            refresh: 60,
            release: 0,
            timeout_ms: 2000,
        };
        let mut result = rptadv_iax2_registration_result_v1 {
            struct_size: size_of::<rptadv_iax2_registration_result_v1>() as u32,
            ..Default::default()
        };
        let code = unsafe {
            SERVER_DESCRIPTOR.register_account.unwrap()(
                shared_handle as *mut c_void,
                &request,
                &mut result,
            )
        };
        (code, result.refresh, result.local.port)
    });
    waiting.recv_timeout(Duration::from_secs(1)).unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        unsafe { server_poll(handle, 100, None, None, ptr::null_mut()) },
        0
    );
    assert!(started.elapsed() < Duration::from_millis(500));
    continue_reply.send(()).unwrap();
    assert_eq!(registration.join().unwrap(), (0, 42, bound.port()));
    registrar.join().unwrap();
    assert_eq!(
        unsafe { server_poll(handle, 100, None, None, ptr::null_mut()) },
        0
    );
    assert_eq!(
        unsafe { &*handle.cast::<ServerHandle>() }
            .0
            .lock()
            .unwrap()
            .ingress_stats()
            .active_routes,
        0
    );
    unsafe { server_destroy(handle) };
}
use crate::{
    call_token::retry_new_call_with_token,
    codec::CodecError,
    information_elements::InformationElement,
    media::{VoiceFrameEncodeError, VoiceFrameError},
    protocol::{FullFrameHeader, encode_subclass, serialize_full_frame, serialize_mini_frame},
    session::{CallSetupError, OutboundCallSetup},
};
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    ptr, thread,
    time::Duration,
};

const LOCAL_CALL: u16 = 1234;
const REMOTE_CALL: u16 = 5678;

thread_local! {
    static ERROR_LOGS: std::cell::RefCell<Vec<(i32, String)>> = const { std::cell::RefCell::new(Vec::new()) };
}

pub(super) fn record_error(priority: i32, message: &str) {
    ERROR_LOGS.with_borrow_mut(|logs| logs.push((priority, message.to_owned())));
}

#[test]
fn unexpected_poll_failure_logs_the_actual_sequence_error_without_payloads() {
    let (peer, server, client) = establish();
    ERROR_LOGS.with_borrow_mut(Vec::clear);
    let packet = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: REMOTE_CALL,
            retransmission: false,
            destination_call_number: LOCAL_CALL,
            timestamp: 20,
            outgoing_sequence: 17,
            incoming_sequence: 2,
            frame_type: 7,
            subclass: 0,
            subclass_is_log: false,
        },
        b"private text that must never be logged",
    )
    .unwrap();
    server.send_to(&packet, client).unwrap();
    let mut pcm = [0.0; 160];
    let mut text = [0; 1500];
    let (mut event, mut length) = (0, 0);
    assert_eq!(
        unsafe {
            poll(
                peer,
                pcm.as_mut_ptr(),
                pcm.len(),
                text.as_mut_ptr(),
                text.len(),
                &mut event,
                &mut length,
            )
        },
        -1
    );
    let logs = ERROR_LOGS.with_borrow(|logs| logs.clone());
    assert_eq!(
        logs.len(),
        1,
        "terminal polling failure needs an error record before ABI detail is lost"
    );
    assert_eq!(logs[0].0, 3);
    for detail in [
        "local_call=1234",
        "remote_call=5678",
        "SequenceMismatch",
        "expected_outgoing",
        "actual_outgoing: 17",
        "expected_incoming",
        "actual_incoming",
    ] {
        assert!(
            logs[0].1.contains(detail),
            "missing diagnostic {detail}: {}",
            logs[0].1
        );
    }
    assert!(!logs[0].1.contains("private text"));
    // A successful idle poll must not erase the first failure's diagnostic latch.
    assert_eq!(
        unsafe {
            poll(
                peer,
                pcm.as_mut_ptr(),
                pcm.len(),
                text.as_mut_ptr(),
                text.len(),
                &mut event,
                &mut length,
            )
        },
        0
    );
    server.send_to(&packet, client).unwrap();
    assert_eq!(
        unsafe {
            poll(
                peer,
                pcm.as_mut_ptr(),
                pcm.len(),
                text.as_mut_ptr(),
                text.len(),
                &mut event,
                &mut length,
            )
        },
        -1
    );
    assert_eq!(ERROR_LOGS.with_borrow(|logs| logs.clone()), logs);
    unsafe { destroy(peer) };
}

#[test]
fn network_poll_error_logs_metadata_without_custom_error_text() {
    let (peer, _server, _) = establish();
    ERROR_LOGS.with_borrow_mut(Vec::clear);
    report_poll_error(
        unsafe { &mut *peer.cast::<IaxPeer>() },
        &DialError::Network(std::io::Error::other("private network credentials")),
    );
    let logs = ERROR_LOGS.with_borrow(|logs| logs.clone());
    assert_eq!(logs.len(), 1);
    assert!(logs[0].1.contains("kind: Other"));
    assert!(logs[0].1.contains("os_error: None"));
    assert!(!logs[0].1.contains("private network"));
    unsafe { destroy(peer) };
}

#[test]
fn remote_hangup_is_logged_but_requested_close_is_not() {
    for requested in [false, true] {
        let (peer, server, client) = establish();
        ERROR_LOGS.with_borrow_mut(Vec::clear);
        if requested {
            assert_eq!(unsafe { hangup(peer) }, 0);
        }
        let packet = serialize_full_frame(
            &FullFrameHeader {
                source_call_number: REMOTE_CALL,
                destination_call_number: LOCAL_CALL,
                retransmission: false,
                timestamp: 20,
                outgoing_sequence: 2,
                // A local HANGUP consumes our next reliable sequence position.
                incoming_sequence: if requested { 2 } else { 1 },
                frame_type: 6,
                subclass: 5,
                subclass_is_log: false,
            },
            &[],
        )
        .unwrap();
        server.send_to(&packet, client).unwrap();
        let (mut event, mut length) = (0, 0);
        assert_eq!(
            unsafe {
                poll(
                    peer,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    0,
                    &mut event,
                    &mut length,
                )
            },
            0
        );
        assert_eq!(event, RPTADV_IAX2_EVENT_HANGUP);
        unsafe { destroy(peer) };
        let logs = ERROR_LOGS.with_borrow(|logs| logs.clone());
        assert_eq!(logs.len(), usize::from(!requested));
        if !requested {
            assert_eq!(logs[0].0, 3);
            assert!(logs[0].1.contains("poll_error=Hangup"));
        }
    }
}

#[test]
fn async_enable_status_preserves_success_and_network_failure() {
    assert_eq!(async_enable_status(Ok(())), 0);
    assert_eq!(
        async_enable_status(Err(crate::server::ListenerError::Network(
            io::Error::other("socket registration failed")
        ))),
        -1
    );
}

fn options<'a>(
    remote: &'a [u8],
    local: &'a [u8],
    destination: &'a [u8],
    secret: &'a [u8],
) -> rptadv_iax2_dial_options_v2 {
    rptadv_iax2_dial_options_v2 {
        struct_size: size_of::<rptadv_iax2_dial_options_v2>() as u32,
        abi_version: RPTADV_IAX2_CLIENT_ABI_VERSION,
        remote_address: remote.as_ptr(),
        remote_address_length: remote.len(),
        local_call_number: LOCAL_CALL,
        reserved: 0,
        local_node: local.as_ptr(),
        local_node_length: local.len(),
        remote_node: destination.as_ptr(),
        remote_node_length: destination.len(),
        secret: secret.as_ptr(),
        secret_length: secret.len(),
        timeout_ms: 100,
        catalog: test_catalog(),
    }
}

fn server_options<'a>(address: &'a [u8], local_nodes: &'a [u8]) -> rptadv_iax2_server_options_v2 {
    rptadv_iax2_server_options_v2 {
        struct_size: size_of::<rptadv_iax2_server_options_v2>() as u32,
        abi_version: RPTADV_IAX2_SERVER_ABI_VERSION,
        bind_address: address.as_ptr(),
        bind_address_length: address.len(),
        local_nodes: local_nodes.as_ptr(),
        local_nodes_length: local_nodes.len(),
        catalog: test_catalog(),
        accounts: ptr::null(),
        account_count: 0,
    }
}

pub(crate) fn inbound_setup(local_call: u16) -> OutboundCallSetup {
    OutboundCallSetup::new(
        local_call,
        7,
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
    .unwrap()
}

fn establish() -> (*mut c_void, UdpSocket, SocketAddr) {
    establish_profile(ProfileId::G711Mu)
}

fn establish_profile(profile: ProfileId) -> (*mut c_void, UdpSocket, SocketAddr) {
    establish_kind(profile, false)
}

fn establish_kind(profile: ProfileId, account: bool) -> (*mut c_void, UdpSocket, SocketAddr) {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let address = server.local_addr().unwrap();
    let responder = thread::spawn(move || {
        let mut packet = [0; 1500];
        let (length, client) = server.recv_from(&mut packet).unwrap();
        assert!(length > 12);
        let mut formats = Vec::new();
        crate::formats::append_formats(
            &mut formats,
            crate::formats::IaxFormat::for_profile(profile).0,
            None,
        );
        let accept = serialize_full_frame(
            &FullFrameHeader {
                source_call_number: REMOTE_CALL,
                retransmission: false,
                destination_call_number: LOCAL_CALL,
                timestamp: 0,
                outgoing_sequence: 0,
                incoming_sequence: 1,
                frame_type: 6,
                subclass: encode_subclass(crate::protocol::IaxCommand::Accept.subclass_value())
                    .unwrap(),
                subclass_is_log: false,
            },
            &formats,
        )
        .unwrap();
        server.send_to(&accept, client).unwrap();
        let _ = server.recv_from(&mut packet).unwrap(); // ACK.
        let mut answer = accept[..12].to_vec();
        answer[8] = 1;
        answer[10] = 4;
        answer[11] = 4;
        server.send_to(&answer, client).unwrap();
        let _ = server.recv_from(&mut packet).unwrap(); // ANSWER ACK.
        (server, client)
    });

    let remote = address.to_string();
    let local = b"524950";
    let destination = b"506315";
    let secret = b"";
    let directory = PathBuf::from(std::env::var_os("RPTADV_CODEC_DIR").unwrap_or_default());
    let backend = if profile == ProfileId::Opus {
        "opus"
    } else {
        "g711"
    };
    let catalog = Arc::new(
        FormatCatalog::new(
            Arc::new(
                CodecCatalog::load(&[ProviderSelection {
                    path: directory.join(format!("librptadv_codec_{backend}.so.1")),
                    profiles: vec![profile],
                }])
                .unwrap(),
            ),
            &[profile],
        )
        .unwrap(),
    );
    let mut dial_options = options(remote.as_bytes(), local, destination, secret);
    dial_options.catalog = ptr::from_ref(&catalog).cast();
    let mut peer = ptr::null_mut();
    if account {
        let mut account_options = account_options(remote.as_bytes());
        account_options.catalog = dial_options.catalog;
        assert_eq!(unsafe { dial_account(&account_options, &mut peer) }, 0);
    } else {
        assert_eq!(unsafe { dial(&dial_options, &mut peer) }, 0);
    }
    let (server, client) = responder.join().unwrap();
    (peer, server, client)
}

fn account_options(remote: &[u8]) -> rptadv_iax2_account_dial_options_v1 {
    rptadv_iax2_account_dial_options_v1 {
        struct_size: size_of::<rptadv_iax2_account_dial_options_v1>() as u32,
        abi_version: 1,
        remote_address: remote.as_ptr(),
        remote_address_length: remote.len(),
        local_call_number: LOCAL_CALL,
        reserved: 0,
        username: b"club-account".as_ptr(),
        username_length: 12,
        destination: b"999".as_ptr(),
        destination_length: 3,
        caller_number: ptr::null(),
        caller_number_length: 0,
        caller_name: ptr::null(),
        caller_name_length: 0,
        context: ptr::null(),
        context_length: 0,
        secret: ptr::null(),
        secret_length: 0,
        timeout_ms: 1000,
        catalog: test_catalog(),
    }
}

#[test]
fn provider_dial_uses_existing_peer_media_and_lifetime_operations() {
    let (peer, server, _) = establish_kind(ProfileId::G711Mu, true);
    assert_eq!(unsafe { sample_rate_hz(peer) }, 8000);
    assert_eq!(unsafe { send_digit(peer, b'#') }, 0);
    let mut bytes = [0; 1500];
    let (length, _) = server.recv_from(&mut bytes).unwrap();
    let packet = crate::protocol::parse_full_frame_packet(&bytes[..length]).unwrap();
    assert_eq!(
        (packet.header.frame_type, packet.header.subclass),
        (1, b'#')
    );
    assert_eq!(unsafe { hangup(peer) }, 0);
    unsafe { destroy(peer) };
}

#[test]
fn provider_dial_rejects_invalid_records_and_clears_output() {
    assert_eq!(unsafe { dial_account(ptr::null(), ptr::null_mut()) }, -1);
    let mut peer = ptr::dangling_mut();
    assert_eq!(unsafe { dial_account(ptr::null(), &mut peer) }, -1);
    assert!(peer.is_null());
    for invalid in 0..18 {
        let mut options = account_options(b"127.0.0.1:9");
        match invalid {
            0 => options.struct_size -= 1,
            1 => options.abi_version = 2,
            2 => options.reserved = 1,
            3 => options.catalog = ptr::null(),
            4 => options.remote_address = ptr::null(),
            5 => options.remote_address_length = 1,
            6 => {
                options.remote_address = b"\xff".as_ptr();
                options.remote_address_length = 1;
            }
            7 => {
                options.username = b"\xff".as_ptr();
                options.username_length = 1;
            }
            8 => {
                options.destination = b"\xff".as_ptr();
                options.destination_length = 1;
            }
            9 => {
                options.caller_number = b"\xff".as_ptr();
                options.caller_number_length = 1;
            }
            10 => {
                options.caller_name = b"\xff".as_ptr();
                options.caller_name_length = 1;
            }
            11 => {
                options.context = b"\xff".as_ptr();
                options.context_length = 1;
            }
            12 => {
                options.secret = b"\xff".as_ptr();
                options.secret_length = 1;
            }
            13 => options.local_call_number = 0,
            14 => options.timeout_ms = 0,
            15 => options.username_length = 0,
            16 => options.destination_length = 0,
            17 => {
                options.context = b"\n".as_ptr();
                options.context_length = 1;
            }
            _ => unreachable!(),
        }
        peer = ptr::dangling_mut();
        assert_eq!(
            unsafe { dial_account(&options, &mut peer) },
            -1,
            "case {invalid}"
        );
        assert!(peer.is_null(), "case {invalid}");
    }
}

struct InboundObservation {
    source: String,
}

unsafe extern "C" fn observe_inbound(
    context: *mut c_void,
    _: *const u8,
    _: usize,
    _: *const u8,
    _: usize,
    source: *const u8,
    source_length: usize,
) -> i32 {
    let context = unsafe { &mut *context.cast::<InboundObservation>() };
    let source = unsafe { std::slice::from_raw_parts(source, source_length) };
    context.source = String::from_utf8(source.to_vec()).unwrap();
    0
}

unsafe extern "C" fn reject_after_observation(
    context: *mut c_void,
    _: *const u8,
    _: usize,
    _: *const u8,
    _: usize,
    source: *const u8,
    source_length: usize,
    _: *mut c_void,
) -> i32 {
    let context = unsafe { &mut *context.cast::<InboundObservation>() };
    let source = unsafe { std::slice::from_raw_parts(source, source_length) };
    context.source = String::from_utf8(source.to_vec()).unwrap();
    -1
}

unsafe extern "C" fn accept_and_destroy(
    context: *mut c_void,
    _: *const u8,
    _: usize,
    _: *const u8,
    _: usize,
    _: *const u8,
    _: usize,
    peer: *mut c_void,
) -> i32 {
    let context = unsafe { &mut *context.cast::<InboundObservation>() };
    context.source = "accepted".to_owned();
    unsafe { destroy(peer) };
    0
}

#[test]
fn inbound_product_callbacks_receive_source_ip_without_udp_port() {
    let bind_address = b"127.0.0.1:0";
    let local_nodes = b"524950";
    let options = rptadv_iax2_server_options_v2 {
        struct_size: size_of::<rptadv_iax2_server_options_v2>() as u32,
        abi_version: RPTADV_IAX2_SERVER_ABI_VERSION,
        bind_address: bind_address.as_ptr(),
        bind_address_length: bind_address.len(),
        local_nodes: local_nodes.as_ptr(),
        local_nodes_length: local_nodes.len(),
        catalog: test_catalog(),
        accounts: ptr::null(),
        account_count: 0,
    };
    let mut handle = ptr::null_mut();
    assert_eq!(unsafe { server_bind(&options, &mut handle) }, 0);
    let server = unsafe { &mut *handle.cast::<ServerHandle>() };
    let server_address = server.0.lock().unwrap().local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let setup = inbound_setup(42);
    client
        .send_to(setup.initial_packet(), server_address)
        .unwrap();
    assert_eq!(
        unsafe { server_poll(handle, 100, None, None, ptr::null_mut()) },
        1
    );
    let mut response = [0_u8; 1500];
    let (length, _) = client.recv_from(&mut response).unwrap();
    let retry =
        retry_new_call_with_token(setup.initial_packet(), &response[..length], 100).unwrap();
    client.send_to(&retry, server_address).unwrap();
    let mut observation = InboundObservation {
        source: String::new(),
    };
    let result = unsafe {
        server_poll(
            handle,
            100,
            Some(observe_inbound),
            Some(reject_after_observation),
            ptr::from_mut(&mut observation).cast(),
        )
    };
    assert_eq!(result, 1);
    assert_eq!(observation.source, "127.0.0.1");

    let unauthorized_client = UdpSocket::bind("127.0.0.1:0").unwrap();
    unauthorized_client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let unauthorized_setup = inbound_setup(43);
    unauthorized_client
        .send_to(unauthorized_setup.initial_packet(), server_address)
        .unwrap();
    assert_eq!(
        unsafe { server_poll(handle, 100, None, Some(accept_and_destroy), ptr::null_mut()) },
        1
    );
    let (challenge_length, _) = unauthorized_client.recv_from(&mut response).unwrap();
    let retry = retry_new_call_with_token(
        unauthorized_setup.initial_packet(),
        &response[..challenge_length],
        100,
    )
    .unwrap();
    unauthorized_client.send_to(&retry, server_address).unwrap();
    assert_eq!(
        unsafe { server_poll(handle, 100, None, Some(accept_and_destroy), ptr::null_mut()) },
        1
    );
    assert_ne!(
        unauthorized_client.recv_from(&mut response).unwrap().0,
        0,
        "missing authorization callback must reject the inbound call"
    );

    let accepted_client = UdpSocket::bind("127.0.0.1:0").unwrap();
    accepted_client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let accepted_setup = inbound_setup(44);
    let mut accepted_observation = InboundObservation {
        source: String::new(),
    };
    accepted_client
        .send_to(accepted_setup.initial_packet(), server_address)
        .unwrap();
    assert_eq!(
        unsafe {
            server_poll(
                handle,
                100,
                Some(observe_inbound),
                Some(accept_and_destroy),
                ptr::from_mut(&mut accepted_observation).cast(),
            )
        },
        1
    );
    let (challenge_length, _) = accepted_client.recv_from(&mut response).unwrap();
    let retry = retry_new_call_with_token(
        accepted_setup.initial_packet(),
        &response[..challenge_length],
        100,
    )
    .unwrap();
    accepted_client.send_to(&retry, server_address).unwrap();
    assert_eq!(
        unsafe {
            server_poll(
                handle,
                100,
                Some(observe_inbound),
                Some(accept_and_destroy),
                ptr::from_mut(&mut accepted_observation).cast(),
            )
        },
        1
    );
    assert_eq!(accepted_observation.source, "accepted");
    unsafe { server_destroy(handle) };
}

#[test]
fn descriptor_and_null_handles_have_stable_results() {
    let descriptor = unsafe { &*rptadv_iax2_client_descriptor_v2() };
    assert_eq!(descriptor.abi_version, RPTADV_IAX2_CLIENT_ABI_VERSION);
    assert_eq!(descriptor.capability, RPTADV_IAX2_CLIENT_CAPABILITY);
    let server_descriptor = unsafe { &*rptadv_iax2_server_descriptor_v2() };
    assert_eq!(
        server_descriptor.abi_version,
        RPTADV_IAX2_SERVER_ABI_VERSION
    );
    assert_eq!(server_descriptor.capability, RPTADV_IAX2_SERVER_CAPABILITY);
    assert!(server_descriptor.bind.is_some());
    assert!(server_descriptor.poll.is_some());
    assert!(server_descriptor.set_local_nodes.is_some());
    assert!(server_descriptor.destroy.is_some());
    assert_eq!(unsafe { sample_rate_hz(ptr::null()) }, 0);
    assert_eq!(unsafe { reset_encoder(ptr::null_mut()) }, -1);
    assert_eq!(unsafe { send_text(ptr::null_mut(), ptr::null(), 0) }, -1);
    assert_eq!(unsafe { send_digit(ptr::null_mut(), b'7') }, -1);
    assert_eq!(unsafe { hangup(ptr::null_mut()) }, -1);
    unsafe { destroy(ptr::null_mut()) };

    let mut output = std::ptr::dangling_mut::<c_void>();
    assert_eq!(unsafe { dial(ptr::null(), &mut output) }, -1);
    assert!(output.is_null());
    assert_eq!(unsafe { dial(ptr::null(), ptr::null_mut()) }, -1);
    assert_eq!(
        unsafe {
            poll(
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        },
        -1
    );
    assert_eq!(
        unsafe { server_poll(ptr::null_mut(), 0, None, None, ptr::null_mut()) },
        -1
    );
    assert_eq!(
        unsafe { server_set_local_nodes(ptr::null_mut(), ptr::null(), 0) },
        -1
    );
    assert_eq!(unsafe { server_bind(ptr::null(), ptr::null_mut()) }, -1);
    let mut server_output = std::ptr::dangling_mut::<c_void>();
    assert_eq!(unsafe { server_bind(ptr::null(), &mut server_output) }, -1);
    unsafe { server_destroy(ptr::null_mut()) };
}

#[test]
fn server_bind_and_local_node_updates_reject_invalid_values() {
    let mut output = std::ptr::dangling_mut::<c_void>();
    for invalid in [
        {
            let mut value = server_options(b"127.0.0.1:0", b"524950");
            value.abi_version += 1;
            value
        },
        {
            let mut value = server_options(b"127.0.0.1:0", b"524950");
            value.struct_size -= 1;
            value
        },
        server_options(b"not-an-address", b"524950"),
        server_options(b"127.0.0.1:0", b""),
        server_options(b"127.0.0.1:0", b"invalid-node"),
        server_options(b"127.0.0.1:0", b"524950,524950"),
    ] {
        output = std::ptr::dangling_mut::<c_void>();
        assert_eq!(unsafe { server_bind(&invalid, &mut output) }, -1);
        assert!(output.is_null());
    }

    let invalid_utf8 = [0xff];
    for invalid in [
        server_options(&invalid_utf8, b"524950"),
        server_options(b"127.0.0.1:0", &invalid_utf8),
    ] {
        output = std::ptr::dangling_mut::<c_void>();
        assert_eq!(unsafe { server_bind(&invalid, &mut output) }, -1);
        assert!(output.is_null());
    }

    let occupied = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = occupied.local_addr().unwrap().to_string();
    let conflict = server_options(address.as_bytes(), b"524950");
    assert_eq!(unsafe { server_bind(&conflict, &mut output) }, -1);
    assert!(output.is_null());

    let valid = server_options(b"127.0.0.1:0", b"524950");
    assert_eq!(unsafe { server_bind(&valid, &mut output) }, 0);
    let nodes = b"524950,508422";
    assert_eq!(
        unsafe { server_set_local_nodes(output, nodes.as_ptr(), nodes.len()) },
        0
    );
    assert_eq!(
        unsafe { server_set_local_nodes(output, ptr::null(), 1) },
        -1
    );
    assert_eq!(
        unsafe { server_set_local_nodes(output, &invalid_utf8 as *const _ as *const u8, 1) },
        -1
    );
    for invalid_nodes in [b"".as_slice(), b"abc", b"524950,524950"] {
        assert_eq!(
            unsafe { server_set_local_nodes(output, invalid_nodes.as_ptr(), invalid_nodes.len()) },
            -1
        );
    }
    unsafe { server_destroy(output) };
}

#[test]
fn server_poll_reports_listener_errors_to_the_caller() {
    let options = server_options(b"127.0.0.1:0", b"524950");
    let mut handle = ptr::null_mut();
    assert_eq!(unsafe { server_bind(&options, &mut handle) }, 0);
    let server = unsafe { &mut *handle.cast::<ServerHandle>() };
    server.0.lock().unwrap().force_poll_error();
    assert_eq!(
        unsafe { server_poll(handle, 0, None, None, ptr::null_mut()) },
        -1
    );
    unsafe { server_destroy(handle) };
}

#[test]
fn dial_rejects_incompatible_abi_and_invalid_byte_fields() {
    let remote = b"127.0.0.1:4569";
    let local = b"524950";
    let destination = b"506315";
    let secret = b"secret";
    let mut output = std::ptr::dangling_mut::<c_void>();

    for invalid in [
        {
            let mut value = options(remote, local, destination, secret);
            value.abi_version += 1;
            value
        },
        {
            let mut value = options(remote, local, destination, secret);
            value.struct_size -= 1;
            value
        },
        {
            let mut value = options(remote, local, destination, secret);
            value.reserved = 1;
            value
        },
        options(b"not-an-address", local, destination, secret),
        {
            let mut value = options(remote, local, destination, secret);
            value.remote_address = ptr::null();
            value.remote_address_length = 1;
            value
        },
        {
            let mut value = options(remote, local, destination, secret);
            value.local_node = ptr::null();
            value.local_node_length = 1;
            value
        },
        {
            let mut value = options(remote, local, destination, secret);
            value.remote_node = ptr::null();
            value.remote_node_length = 1;
            value
        },
        {
            let mut value = options(remote, local, destination, secret);
            value.secret = ptr::null();
            value.secret_length = 1;
            value
        },
    ] {
        output = std::ptr::dangling_mut::<c_void>();
        assert_eq!(unsafe { dial(&invalid, &mut output) }, -1);
        assert!(output.is_null());
    }

    let invalid_utf8 = [0xff];
    let mut dial_options = options(&invalid_utf8, local, destination, secret);
    assert_eq!(unsafe { dial(&dial_options, &mut output) }, -1);
    dial_options = options(remote, &invalid_utf8, destination, secret);
    assert_eq!(unsafe { dial(&dial_options, &mut output) }, -1);
    dial_options = options(remote, local, &invalid_utf8, secret);
    assert_eq!(unsafe { dial(&dial_options, &mut output) }, -1);
    dial_options = options(remote, local, destination, &invalid_utf8);
    assert_eq!(unsafe { dial(&dial_options, &mut output) }, -1);

    dial_options = options(remote, local, destination, secret);
    dial_options.local_call_number = 0;
    assert_eq!(unsafe { dial(&dial_options, &mut output) }, -1);
}

#[test]
fn dial_error_codes_and_slice_boundaries_are_explicit() {
    assert_eq!(dial_error_code(DialError::InvalidOptions), -1);
    assert_eq!(
        dial_error_code(DialError::Network(io::Error::other("network"))),
        -2
    );
    assert_eq!(dial_error_code(DialError::Timeout), -3);
    assert_eq!(dial_error_code(DialError::Rejected), -4);
    assert_eq!(dial_error_code(DialError::UnsupportedFormat(8)), -5);
    assert_eq!(dial_error_code(DialError::Hangup), -6);
    assert_eq!(dial_error_code(DialError::ReliableWindowFull), -6);
    assert_eq!(dial_error_code(DialError::EarlyEventsFull), -6);
    assert_eq!(
        dial_error_code(DialError::Protocol(CallSetupError::NotLinked)),
        -6
    );
    assert_eq!(
        dial_error_code(DialError::Voice(VoiceFrameError::NotVoiceFrame)),
        -6
    );
    assert_eq!(
        dial_error_code(DialError::Encode(VoiceFrameEncodeError::BufferTooSmall {
            required: 4,
            available: 0,
        })),
        -6
    );
    assert_eq!(
        dial_error_code(DialError::Decode(CodecError {
            required: 1,
            available: 0,
        })),
        -6
    );

    let bytes = [1_u8];
    assert_eq!(unsafe { input_slice(ptr::null::<u8>(), 0) }, Some(&[][..]));
    assert!(unsafe { input_slice::<u8>(ptr::null(), 1) }.is_none());
    assert_eq!(unsafe { input_slice(bytes.as_ptr(), 1) }, Some(&bytes[..]));
    assert!(unsafe { output_slice::<u8>(ptr::null_mut(), 1) }.is_none());
    let mut output = [0_u8; 1];
    assert_eq!(
        unsafe { output_slice(output.as_mut_ptr(), 1) }
            .unwrap()
            .len(),
        1
    );
    assert_eq!(boundary(7, || 8), 8);
    assert_eq!(boundary(7, || panic!("caught at C boundary")), 7);
}

#[test]
fn c_peer_api_reports_events_and_rejects_invalid_buffers() {
    let (peer, server, client) = establish();
    assert_eq!(unsafe { sample_rate_hz(peer) }, 8_000);
    assert_eq!(
        unsafe { send_prepared_audio(peer, ptr::null(), 1, 1, 0) },
        -1
    );
    let oversized_pcm = vec![0xff; crate::ingress::MAX_DATAGRAM_SIZE + 1];
    assert_eq!(
        unsafe {
            send_prepared_audio(
                peer,
                oversized_pcm.as_ptr(),
                oversized_pcm.len(),
                oversized_pcm.len() as u32,
                0,
            )
        },
        -1
    );
    assert_eq!(unsafe { send_text(peer, ptr::null(), 1) }, -1);

    let mut event = u32::MAX;
    let mut length = usize::MAX;
    assert_eq!(
        unsafe {
            poll(
                peer,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                &mut event,
                &mut length,
            )
        },
        0
    );
    assert_eq!((event, length), (RPTADV_IAX2_EVENT_NONE, 0));
    assert_eq!(
        unsafe {
            poll(
                peer,
                ptr::null_mut(),
                1,
                ptr::null_mut(),
                0,
                &mut event,
                &mut length,
            )
        },
        -1
    );
    assert_eq!(
        unsafe {
            poll(
                peer,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut length,
            )
        },
        -1
    );
    assert_eq!(
        unsafe {
            poll(
                peer,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                &mut event,
                ptr::null_mut(),
            )
        },
        -1
    );

    server.send_to(b"\x80", client).unwrap();
    let mut pcm = [0.0_f32; 160];
    let mut text = [0_u8; 32];
    assert_eq!(
        unsafe {
            poll(
                peer,
                pcm.as_mut_ptr(),
                pcm.len(),
                text.as_mut_ptr(),
                text.len(),
                &mut event,
                &mut length,
            )
        },
        -1
    );
    assert_eq!((event, length), (RPTADV_IAX2_EVENT_NONE, 0));

    let mini = serialize_mini_frame(
        &crate::protocol::MiniFrameHeader {
            source_call_number: REMOTE_CALL,
            timestamp: 20,
        },
        &[0xff; 160],
    )
    .unwrap();
    server.send_to(&mini, client).unwrap();
    assert_eq!(
        unsafe {
            poll(
                peer,
                pcm.as_mut_ptr(),
                pcm.len(),
                text.as_mut_ptr(),
                text.len(),
                &mut event,
                &mut length,
            )
        },
        0
    );
    assert_eq!((event, length), (RPTADV_IAX2_EVENT_AUDIO, pcm.len()));

    let text_frame = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: REMOTE_CALL,
            retransmission: false,
            destination_call_number: LOCAL_CALL,
            timestamp: 25,
            outgoing_sequence: 2,
            incoming_sequence: 1,
            frame_type: 7,
            subclass: 0,
            subclass_is_log: false,
        },
        b"status",
    )
    .unwrap();
    server.send_to(&text_frame, client).unwrap();
    assert_eq!(
        unsafe {
            poll(
                peer,
                pcm.as_mut_ptr(),
                pcm.len(),
                text.as_mut_ptr(),
                text.len(),
                &mut event,
                &mut length,
            )
        },
        0
    );
    assert_eq!((event, length), (RPTADV_IAX2_EVENT_TEXT, 6));
    assert_eq!(&text[..length], b"status");
    let mut ack = [0; 1500];
    assert!(server.recv_from(&mut ack).is_ok());

    let dtmf = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: REMOTE_CALL,
            retransmission: false,
            destination_call_number: LOCAL_CALL,
            timestamp: 26,
            outgoing_sequence: 3,
            incoming_sequence: 1,
            frame_type: 1,
            subclass: b'5',
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap();
    server.send_to(&dtmf, client).unwrap();
    assert_eq!(
        unsafe {
            poll(
                peer,
                pcm.as_mut_ptr(),
                pcm.len(),
                text.as_mut_ptr(),
                text.len(),
                &mut event,
                &mut length,
            )
        },
        0
    );
    assert_eq!((event, length, text[0]), (RPTADV_IAX2_EVENT_DIGIT, 1, b'5'));
    assert!(server.recv_from(&mut ack).is_ok());

    for (subclass, expected, sequence) in [
        (12, RPTADV_IAX2_EVENT_RADIO_KEY, 4),
        (13, RPTADV_IAX2_EVENT_RADIO_UNKEY, 5),
    ] {
        let control = serialize_full_frame(
            &FullFrameHeader {
                source_call_number: REMOTE_CALL,
                retransmission: false,
                destination_call_number: LOCAL_CALL,
                timestamp: 28,
                outgoing_sequence: sequence,
                incoming_sequence: 1,
                frame_type: 4,
                subclass,
                subclass_is_log: false,
            },
            &[],
        )
        .unwrap();
        server.send_to(&control, client).unwrap();
        assert_eq!(
            unsafe {
                poll(
                    peer,
                    pcm.as_mut_ptr(),
                    pcm.len(),
                    text.as_mut_ptr(),
                    text.len(),
                    &mut event,
                    &mut length,
                )
            },
            0
        );
        assert_eq!((event, length), (expected, 0));
        assert!(server.recv_from(&mut ack).is_ok());
    }

    let hangup_frame = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: REMOTE_CALL,
            retransmission: false,
            destination_call_number: LOCAL_CALL,
            timestamp: 30,
            outgoing_sequence: 6,
            incoming_sequence: 1,
            frame_type: 6,
            subclass: encode_subclass(crate::protocol::IaxCommand::Hangup.subclass_value())
                .unwrap(),
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap();
    server.send_to(&hangup_frame, client).unwrap();
    assert_eq!(
        unsafe {
            poll(
                peer,
                pcm.as_mut_ptr(),
                pcm.len(),
                text.as_mut_ptr(),
                text.len(),
                &mut event,
                &mut length,
            )
        },
        0
    );
    assert_eq!((event, length), (RPTADV_IAX2_EVENT_HANGUP, 0));
    assert_eq!(unsafe { hangup(peer) }, -1);
    assert_eq!(unsafe { send_text(peer, b"after".as_ptr(), 5) }, -1);
    unsafe { destroy(peer) };
}

#[test]
fn c_peer_api_rejects_dtmf_without_text_storage() {
    let (peer, server, client) = establish();
    let digit = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: REMOTE_CALL,
            retransmission: false,
            destination_call_number: LOCAL_CALL,
            timestamp: 1,
            outgoing_sequence: 2,
            incoming_sequence: 1,
            frame_type: 1,
            subclass: b'5',
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap();
    server.send_to(&digit, client).unwrap();

    let mut samples = [0.0; 160];
    let mut event = u32::MAX;
    let mut length = usize::MAX;
    assert_eq!(
        unsafe {
            poll(
                peer,
                samples.as_mut_ptr(),
                samples.len(),
                ptr::null_mut(),
                0,
                &mut event,
                &mut length,
            )
        },
        -1
    );
    assert_eq!((event, length), (RPTADV_IAX2_EVENT_NONE, 0));
    unsafe { destroy(peer) };
}
#[test]
fn native_plc_output_capacity_is_retryable_not_a_peer_failure() {
    let (handle, _server, _) = establish_profile(ProfileId::Opus);
    let peer = unsafe { &mut *handle.cast::<IaxPeer>() };
    let fixture = crate::jitter::fixture::Fixture::new();
    fixture.gap(0, 48000, 960, false);
    unsafe { peer.configure_jitter(fixture.descriptor()) }.unwrap();
    let (mut event, mut length) = (99, 99);
    let mut pcm = [0.75; 960];
    ERROR_LOGS.with_borrow_mut(Vec::clear);
    unsafe {
        assert_eq!(
            poll(
                handle,
                pcm.as_mut_ptr(),
                959,
                ptr::null_mut(),
                0,
                &mut event,
                &mut length
            ),
            1
        );
        assert_eq!((event, length), (RPTADV_IAX2_EVENT_NONE, 960));
        assert_eq!(pcm, [0.75; 960]);
        assert!(fixture.advances().is_empty());
        assert_eq!(
            poll(
                handle,
                pcm.as_mut_ptr(),
                960,
                ptr::null_mut(),
                0,
                &mut event,
                &mut length
            ),
            0
        );
        assert_eq!((event, length), (RPTADV_IAX2_EVENT_AUDIO, 960));
        assert_eq!(fixture.advances().len(), 1);
        assert!(ERROR_LOGS.with_borrow(|logs| logs.is_empty()));
        fixture.packet(0, 48000 + 960, &[0x03], 0);
        fixture.last_packet_span(960);
        assert_eq!(
            poll(
                handle,
                pcm.as_mut_ptr(),
                960,
                ptr::null_mut(),
                0,
                &mut event,
                &mut length
            ),
            -1
        );
        assert_eq!(ERROR_LOGS.with_borrow(Vec::len), 1);
        destroy(handle);
    }
}

#[test]
fn egress_abi2_layout_and_prepared_codec() {
    let api = unsafe { &*super::rptadv_iax2_client_descriptor_v2() };
    assert_eq!(api.struct_size as usize, 24 + 14 * size_of::<usize>());
    assert_eq!(
        std::mem::offset_of!(rptadv_iax2_client_descriptor_v2, dial_account),
        24 + 13 * size_of::<usize>()
    );
    assert_eq!(api.abi_version, 2);
    let (peer, _server, _) = establish();
    let prepare = api.prepare_audio.unwrap();
    let pcm = [-1.0, 0.0, 1.0];
    let mut encoded = [42; 5];
    let mut result = EncodeResultRaw {
        struct_size: size_of::<EncodeResultRaw>() as u32,
        ..Default::default()
    };
    unsafe {
        assert_eq!(
            prepare(
                peer,
                pcm.as_ptr(),
                3,
                encoded.as_mut_ptr(),
                2,
                1,
                &mut result
            ),
            2
        );
        assert_eq!(result.required_capacity, 3);
        assert_eq!(result.consumed_frames, 0);
        assert_eq!(encoded, [42; 5]);
        assert_eq!(
            prepare(
                peer,
                ptr::null(),
                1,
                encoded.as_mut_ptr(),
                5,
                1,
                &mut result
            ),
            -1
        );
        assert_eq!(
            prepare(peer, pcm.as_ptr(), 3, ptr::null_mut(), 5, 1, &mut result),
            -1
        );
        assert_eq!(
            prepare(
                peer,
                pcm.as_ptr(),
                3,
                encoded.as_mut_ptr(),
                5,
                1,
                ptr::null_mut()
            ),
            -1
        );
        assert_eq!(
            prepare(
                peer,
                pcm.as_ptr(),
                3,
                encoded.as_mut_ptr(),
                5,
                1,
                &mut result
            ),
            0
        );
        assert_eq!(encoded, [0x00, 0xff, 0x80, 42, 42]);
        assert_eq!(
            (
                result.source_start_frames,
                result.source_frames,
                result.packet_frames
            ),
            (0, 3, 3)
        );
        assert_eq!(
            prepare(peer, ptr::null(), 0, ptr::null_mut(), 0, 1, &mut result),
            0
        );
        assert_eq!(result.encoded_bytes, 0);
        assert_eq!(api.elapsed_ms.unwrap()(ptr::null()), 0);
        destroy(peer);
    }
}
