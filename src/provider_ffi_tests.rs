use super::*;

type PublicationAction = Box<dyn FnOnce(&ProviderCallMetadata)>;
thread_local! {
    static PUBLICATION_HOOK: std::cell::RefCell<Option<(String,u64,PublicationAction)>> = const { std::cell::RefCell::new(None) };
}
pub(super) fn publication_checkpoint(metadata: &ProviderCallMetadata) {
    let action = PUBLICATION_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(id, generation, _)| {
            id == &metadata.account && *generation == metadata.account_generation
        }) {
            slot.take().map(|(_, _, action)| action)
        } else {
            None
        }
    });
    if let Some(action) = action {
        action(metadata);
    }
}

struct Fixture {
    handle: *mut c_void,
    address: String,
    _remote: std::net::UdpSocket,
}
impl Fixture {
    fn new() -> Self {
        let remote = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut fixture = Self {
            handle: ptr::null_mut(),
            address: remote.local_addr().unwrap().to_string(),
            _remote: remote,
        };
        let account = fixture.account();
        let options = rptadv_iax2_server_options_v2 {
            struct_size: size_of::<rptadv_iax2_server_options_v2>() as u32,
            abi_version: 2,
            bind_address: b"127.0.0.1:0".as_ptr(),
            bind_address_length: 11,
            local_nodes: ptr::null(),
            local_nodes_length: 0,
            catalog: test_catalog(),
            accounts: &account,
            account_count: 1,
        };
        assert_eq!(unsafe { server_bind(&options, &mut fixture.handle) }, 0);
        fixture
    }
    fn account(&self) -> rptadv_iax2_provider_account_v1 {
        rptadv_iax2_provider_account_v1 {
            struct_size: size_of::<rptadv_iax2_provider_account_v1>() as u32,
            abi_version: 1,
            generation: 7,
            account: rptadv_iax2_bytes_v1::view("provider-one"),
            local_binding: rptadv_iax2_bytes_v1::view("operator-west"),
            remote_address: rptadv_iax2_bytes_v1::view(&self.address),
            username: rptadv_iax2_bytes_v1::view("provider-login"),
            secret: rptadv_iax2_bytes_v1::view("literal;secret"),
            authentication_timeout_ms: 1000,
            reserved: 0,
        }
    }
    fn registration(&self) -> rptadv_iax2_registration_options_v1 {
        rptadv_iax2_registration_options_v1 {
            struct_size: size_of::<rptadv_iax2_registration_options_v1>() as u32,
            abi_version: 1,
            account: rptadv_iax2_bytes_v1::view("provider-one"),
            generation: 7,
            refresh: 60,
            release: 0,
            timeout_ms: 1000,
        }
    }
    fn registration_result(&self) -> rptadv_iax2_registration_result_v1 {
        rptadv_iax2_registration_result_v1 {
            struct_size: size_of::<rptadv_iax2_registration_result_v1>() as u32,
            refresh: 123,
            local: rptadv_iax2_endpoint_v1 {
                family: 4,
                port: 123,
                ..Default::default()
            },
            ..Default::default()
        }
    }
    fn assert_account_preserved(&self) {
        let mut result = self.registration_result();
        // A configured account reaches the async prerequisite. A removed or
        // partially replaced account instead reports invalid selection.
        assert_eq!(
            unsafe { register_account(self.handle, &self.registration(), &mut result) },
            -6
        );
        assert_eq!(
            (result.refresh, result.local.family, result.abi_version),
            (0, 0, 1)
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        unsafe { server_destroy(self.handle) };
    }
}

#[test]
fn invalid_account_replacements_preserve_the_live_copied_selection() {
    let fixture = Fixture::new();
    let oversized = "x".repeat(256);
    for invalid in 0..17 {
        let mut record = fixture.account();
        match invalid {
            0 => record.struct_size -= 1,
            1 => record.abi_version = 2,
            2 => record.reserved = 1,
            3 => record.generation = 0,
            4 => record.account = rptadv_iax2_bytes_v1::view(""),
            5 => record.account = rptadv_iax2_bytes_v1::view(&oversized[..65]),
            6 => record.local_binding = rptadv_iax2_bytes_v1::view(&oversized[..64]),
            7 => record.username = rptadv_iax2_bytes_v1::view(""),
            8 => record.secret = rptadv_iax2_bytes_v1::view(""),
            9 => record.remote_address = rptadv_iax2_bytes_v1::view("0.0.0.0:4569"),
            10 => record.remote_address = rptadv_iax2_bytes_v1::view("127.0.0.1:0"),
            11 => record.authentication_timeout_ms = 0,
            12 => record.secret = rptadv_iax2_bytes_v1::view("bad\nsecret"),
            13 => {
                record.username = rptadv_iax2_bytes_v1 {
                    data: ptr::null(),
                    length: 1,
                }
            }
            14 => {
                record.account = rptadv_iax2_bytes_v1 {
                    data: b"\xff".as_ptr(),
                    length: 1,
                }
            }
            15 => record.remote_address = rptadv_iax2_bytes_v1::view("not an endpoint"),
            _ => record.username = rptadv_iax2_bytes_v1::view(&oversized),
        }
        assert_eq!(
            unsafe { configure_accounts(fixture.handle, &record, 1) },
            -1,
            "case {invalid}"
        );
        fixture.assert_account_preserved();
    }
    assert_eq!(
        unsafe { configure_accounts(fixture.handle, ptr::null(), 1) },
        -1
    );
    assert_eq!(
        unsafe { configure_accounts(fixture.handle, ptr::null(), MAX_ACCOUNTS + 1) },
        -1
    );
    assert_eq!(
        unsafe { configure_accounts(ptr::null_mut(), ptr::null(), 0) },
        -1
    );
    let mut duplicate = [fixture.account(), fixture.account()];
    assert_eq!(
        unsafe { configure_accounts(fixture.handle, duplicate.as_ptr(), 2) },
        -1
    );
    duplicate[1].account = rptadv_iax2_bytes_v1::view("another-id");
    assert_eq!(
        unsafe { configure_accounts(fixture.handle, duplicate.as_ptr(), 2) },
        -1
    );
    let mut changed = fixture.account();
    changed.secret = rptadv_iax2_bytes_v1::view("changed-with-same-generation");
    assert_eq!(
        unsafe { configure_accounts(fixture.handle, &changed, 1) },
        -1
    );
    fixture.assert_account_preserved();
    assert_eq!(
        unsafe { configure_accounts(fixture.handle, ptr::null(), 0) },
        0
    );
    let mut result = fixture.registration_result();
    assert_eq!(
        unsafe { register_account(fixture.handle, &fixture.registration(), &mut result) },
        -1
    );
}

#[test]
fn registration_boundary_rejects_short_records_and_clears_valid_outputs_on_failure() {
    let fixture = Fixture::new();
    let mut result = fixture.registration_result();
    assert_eq!(
        unsafe { register_account(fixture.handle, &fixture.registration(), ptr::null_mut()) },
        -1
    );
    result.struct_size = 4;
    assert_eq!(
        unsafe { register_account(fixture.handle, &fixture.registration(), &mut result) },
        -1
    );
    assert_eq!(result.refresh, 123);
    let large = "x".repeat(65);
    for invalid in 0..8 {
        let mut request = fixture.registration();
        match invalid {
            0 => request.struct_size -= 1,
            1 => request.abi_version = 2,
            2 => request.release = 2,
            3 => request.refresh = 0,
            4 => request.timeout_ms = 0,
            5 => request.generation = 8,
            6 => request.account = rptadv_iax2_bytes_v1::view(&large),
            _ => request.account = rptadv_iax2_bytes_v1::view("missing"),
        }
        result = fixture.registration_result();
        assert_eq!(
            unsafe { register_account(fixture.handle, &request, &mut result) },
            -1
        );
        assert_eq!(
            (result.refresh, result.local.family, result.apparent.family),
            (0, 0, 0)
        );
    }
    result = fixture.registration_result();
    assert_eq!(
        unsafe { register_account(ptr::null_mut(), &fixture.registration(), &mut result) },
        -1
    );
    assert_eq!(
        unsafe { register_account(fixture.handle, ptr::null(), &mut result) },
        -1
    );
    fixture.assert_account_preserved();
}

#[test]
fn endpoint_value_preserves_ipv6_scope_flow_and_network_octets() {
    let value = SocketAddr::V6(std::net::SocketAddrV6::new(
        "fe80::1234".parse().unwrap(),
        4569,
        123,
        7,
    ));
    let endpoint: rptadv_iax2_endpoint_v1 = value.into();
    assert_eq!(
        (
            endpoint.family,
            endpoint.port,
            endpoint.flowinfo,
            endpoint.scope_id
        ),
        (6, 4569, 123, 7)
    );
    assert_eq!(
        endpoint.address,
        value
            .ip()
            .to_string()
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
    );
}

#[test]
fn configured_dial_boundary_clears_peer_and_receipt_before_invalid_or_unavailable_setup() {
    let fixture = Fixture::new();
    let request = || rptadv_iax2_provider_dial_options_v1 {
        struct_size: size_of::<rptadv_iax2_provider_dial_options_v1>() as u32,
        abi_version: 1,
        generation: 7,
        account: rptadv_iax2_bytes_v1::view("provider-one"),
        destination: rptadv_iax2_bytes_v1::view("*99#"),
        caller_number: rptadv_iax2_bytes_v1::view("KG0BP"),
        caller_name: rptadv_iax2_bytes_v1::view("Operator"),
        context: rptadv_iax2_bytes_v1::view("outgoing"),
        timeout_ms: 1000,
        reserved: 0,
    };
    let result = || rptadv_iax2_provider_call_receipt_v1 {
        struct_size: size_of::<rptadv_iax2_provider_call_receipt_v1>() as u32,
        call_generation: 99,
        format: 4,
        ..Default::default()
    };
    let oversized = "x".repeat(256);
    for invalid in 0..10 {
        let mut options = request();
        match invalid {
            0 => options.struct_size -= 1,
            1 => options.abi_version = 2,
            2 => options.reserved = 1,
            3 => options.destination = rptadv_iax2_bytes_v1::view(""),
            4 => options.destination = rptadv_iax2_bytes_v1::view(&oversized),
            5 => options.caller_name = rptadv_iax2_bytes_v1::view("bad\nname"),
            6 => options.generation = 8,
            7 => options.timeout_ms = 0,
            8 => options.account = rptadv_iax2_bytes_v1::view(&oversized[..65]),
            _ => {
                options.account = rptadv_iax2_bytes_v1 {
                    data: ptr::null(),
                    length: 1,
                }
            }
        }
        let mut receipt = result();
        let mut peer = ptr::dangling_mut::<c_void>();
        assert_eq!(
            unsafe { dial_provider_account(fixture.handle, &options, &mut peer, &mut receipt) },
            -1
        );
        assert!(peer.is_null());
        assert_eq!(
            (receipt.call_generation, receipt.format, receipt.abi_version),
            (0, 0, 1)
        );
    }
    let mut receipt = result();
    let mut peer = ptr::dangling_mut::<c_void>();
    assert_eq!(
        unsafe { dial_provider_account(fixture.handle, &request(), &mut peer, &mut receipt) },
        -6
    );
    assert!(peer.is_null());
    assert_eq!(receipt.call_generation, 0);
    assert_eq!(
        unsafe { dial_provider_account(fixture.handle, &request(), ptr::null_mut(), &mut receipt) },
        -1
    );
    assert_eq!(
        unsafe { dial_provider_account(fixture.handle, &request(), &mut peer, ptr::null_mut()) },
        -1
    );
    receipt = result();
    receipt.struct_size = 4;
    assert_eq!(
        unsafe { dial_provider_account(fixture.handle, &request(), &mut peer, &mut receipt) },
        -1
    );
    assert_eq!(receipt.call_generation, 99);
    receipt = result();
    assert_eq!(
        unsafe { dial_provider_account(ptr::null_mut(), &request(), &mut peer, &mut receipt) },
        -1
    );
    assert_eq!(
        unsafe { dial_provider_account(fixture.handle, ptr::null(), &mut peer, &mut receipt) },
        -1
    );
    assert_eq!(
        unsafe {
            poll_accounts(
                ptr::null_mut(),
                100,
                None,
                None,
                None,
                None,
                ptr::null_mut(),
            )
        },
        -1
    );
    assert_eq!(
        unsafe { poll_accounts(fixture.handle, 100, None, None, None, None, ptr::null_mut()) },
        0
    );
    fixture._remote.set_nonblocking(true).unwrap();
    assert_eq!(
        fixture
            ._remote
            .recv_from(&mut [0; 2048])
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn poisoned_actual_control_mutex_fails_closed_through_every_ffi_entry() {
    let fixture = Fixture::new();
    let server = unsafe { &*fixture.handle.cast::<ServerHandle>() };
    // Caught entirely in Rust: no hook mutation and no unwind crosses FFI.
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = server.0.lock().unwrap();
            panic!("isolated control-owner failure");
        }))
        .is_err()
    );
    assert_eq!(
        unsafe { configure_accounts(fixture.handle, &fixture.account(), 1) },
        -1
    );
    let mut result = fixture.registration_result();
    assert_eq!(
        unsafe { register_account(fixture.handle, &fixture.registration(), &mut result) },
        -1
    );
    assert_eq!((result.refresh, result.local.family), (0, 0));
    let request = rptadv_iax2_provider_dial_options_v1 {
        struct_size: size_of::<rptadv_iax2_provider_dial_options_v1>() as u32,
        abi_version: 1,
        generation: 7,
        account: rptadv_iax2_bytes_v1::view("provider-one"),
        destination: rptadv_iax2_bytes_v1::view("999"),
        caller_number: rptadv_iax2_bytes_v1::view(""),
        caller_name: rptadv_iax2_bytes_v1::view(""),
        context: rptadv_iax2_bytes_v1::view(""),
        timeout_ms: 1000,
        reserved: 0,
    };
    let mut receipt = rptadv_iax2_provider_call_receipt_v1 {
        struct_size: size_of::<rptadv_iax2_provider_call_receipt_v1>() as u32,
        call_generation: 99,
        ..Default::default()
    };
    let mut peer = ptr::dangling_mut::<c_void>();
    assert_eq!(
        unsafe { dial_provider_account(fixture.handle, &request, &mut peer, &mut receipt) },
        -1
    );
    assert!(peer.is_null());
    assert_eq!(receipt.call_generation, 0);
    assert_eq!(
        unsafe { poll_accounts(fixture.handle, 100, None, None, None, None, ptr::null_mut()) },
        -1
    );
    assert_eq!(
        unsafe { server_set_local_nodes(fixture.handle, b"1234".as_ptr(), 4) },
        -1
    );
    assert_eq!(
        unsafe { server_enable_async(fixture.handle, crate::provider_tests::runtime()) },
        -1
    );
}

#[test]
fn control_failure_after_foreign_policy_rolls_back_answer_without_transferring_peer() {
    struct State {
        handle: *mut c_void,
        poisoned: bool,
        accepted: usize,
    }
    unsafe extern "C" fn poison(
        context: *mut c_void,
        _: *const u8,
        _: usize,
        _: *const u8,
        _: usize,
        _: *const u8,
        _: usize,
    ) -> i32 {
        let state = unsafe { &mut *context.cast::<State>() };
        let server = unsafe { &*state.handle.cast::<ServerHandle>() };
        // Catch entirely inside Rust before returning through extern-C.
        state.poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = server.0.lock().unwrap();
            panic!("isolated late control failure");
        }))
        .is_err();
        0
    }
    unsafe extern "C" fn accept(
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
    let fixture = Fixture::new();
    assert_eq!(
        unsafe { server_set_local_nodes(fixture.handle, b"524950".as_ptr(), 6) },
        0
    );
    let local = unsafe { &*fixture.handle.cast::<ServerHandle>() }
        .0
        .lock()
        .unwrap()
        .local_addr()
        .unwrap();
    let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let setup = crate::ffi::tests::inbound_setup(42);
    client.send_to(setup.initial_packet(), local).unwrap();
    assert_eq!(
        unsafe { server_poll(fixture.handle, 100, None, None, ptr::null_mut()) },
        1
    );
    let mut bytes = [0; 2048];
    let (length, _) = client.recv_from(&mut bytes).unwrap();
    let retry =
        crate::call_token::retry_new_call_with_token(setup.initial_packet(), &bytes[..length], 0)
            .unwrap();
    client.send_to(&retry, local).unwrap();
    let mut state = State {
        handle: fixture.handle,
        poisoned: false,
        accepted: 0,
    };
    assert_eq!(
        unsafe {
            server_poll(
                fixture.handle,
                100,
                Some(poison),
                Some(accept),
                ptr::from_mut(&mut state).cast(),
            )
        },
        -1
    );
    assert!(state.poisoned);
    assert_eq!(state.accepted, 0);
    for (sequence, kind, subclass) in [(0, 6, 7), (1, 4, 4), (2, 6, 5)] {
        let (length, _) = client.recv_from(&mut bytes).unwrap();
        let frame = crate::protocol::parse_full_frame_packet(&bytes[..length]).unwrap();
        assert_eq!(
            (
                frame.header.outgoing_sequence,
                frame.header.frame_type,
                frame.header.subclass
            ),
            (sequence, kind, subclass)
        );
    }
    client.set_nonblocking(true).unwrap();
    assert_eq!(
        client.recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn bind_rejects_invalid_account_tail_and_oversized_prefixes_before_dereferencing_bytes() {
    let fixture = Fixture::new();
    let request = || rptadv_iax2_server_options_v2 {
        struct_size: size_of::<rptadv_iax2_server_options_v2>() as u32,
        abi_version: 2,
        bind_address: b"127.0.0.1:0".as_ptr(),
        bind_address_length: 11,
        local_nodes: ptr::null(),
        local_nodes_length: 0,
        catalog: test_catalog(),
        accounts: ptr::null(),
        account_count: 1,
    };
    for variant in 0..3 {
        let mut options = request();
        match variant {
            0 => {}
            1 => {
                options.account_count = 0;
                options.bind_address_length = 65;
            }
            _ => {
                options.account_count = 0;
                options.local_nodes_length = 65_536;
            }
        }
        let mut output = ptr::dangling_mut::<c_void>();
        assert_eq!(unsafe { server_bind(&options, &mut output) }, -1);
        assert!(output.is_null());
    }
    assert_eq!(
        crate::server::ListenerError::Provider(AccountError::Busy).to_string(),
        "IAX provider capacity unavailable"
    );
    fixture.assert_account_preserved();
}

#[test]
fn rejected_provider_accept_sends_actual_hangup_and_missing_callback_never_admits() {
    struct State {
        authorized: usize,
        accepted: usize,
        reject_policy: bool,
        retire_before_accept: bool,
        handle: *mut c_void,
    }
    unsafe extern "C" fn authorize(
        context: *mut c_void,
        record: *const rptadv_iax2_provider_incoming_v1,
    ) -> i32 {
        let state = unsafe { &mut *context.cast::<State>() };
        let record = unsafe { &*record };
        assert_eq!(record.receipt.account_generation, 8);
        state.authorized += 1;
        if state.retire_before_accept {
            let handle = state.handle;
            let exact_generation = record.receipt.call_generation;
            PUBLICATION_HOOK.with(|slot| {
                *slot.borrow_mut() = Some((
                    "provider-one".into(),
                    8,
                    Box::new(move |metadata| {
                        assert_eq!(metadata.call_generation, exact_generation);
                        // Actual public account retirement at the real post-finish,
                        // pre-transfer boundary; no authority/result is replaced.
                        assert_eq!(unsafe { configure_accounts(handle, ptr::null(), 0) }, 0);
                    }),
                ))
            });
        }
        if state.reject_policy { -1 } else { 0 }
    }
    unsafe extern "C" fn reject(
        context: *mut c_void,
        _: *const rptadv_iax2_provider_incoming_v1,
        _: *mut c_void,
    ) -> i32 {
        unsafe { &mut *context.cast::<State>() }.accepted += 1;
        -1 // Never takes ownership of the unique peer.
    }
    for variant in 0..4 {
        let fixture = Fixture::new();
        fixture
            ._remote
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut configured = fixture.account();
        configured.generation = 8;
        configured.username = rptadv_iax2_bytes_v1::view("telephone-login");
        configured.secret = rptadv_iax2_bytes_v1::view("fixture-secret");
        configured.authentication_timeout_ms = 10_000;
        assert_eq!(
            unsafe { configure_accounts(fixture.handle, &configured, 1) },
            0
        );
        assert_eq!(
            unsafe { server_enable_async(fixture.handle, crate::provider_tests::runtime()) },
            0
        );
        let server = unsafe { &*fixture.handle.cast::<ServerHandle>() };
        let (bound, response) = {
            let mut owner = server.0.lock().unwrap();
            let (_, _, _, response) =
                crate::provider_tests::pending_incoming(&mut owner, &fixture._remote);
            (owner.local_addr().unwrap(), response)
        };
        fixture._remote.send_to(&response, bound).unwrap();
        let mut state = State {
            authorized: 0,
            accepted: 0,
            reject_policy: variant == 1,
            retire_before_accept: variant == 3,
            handle: fixture.handle,
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            let result = unsafe {
                poll_accounts(
                    fixture.handle,
                    1000,
                    None,
                    None,
                    Some(authorize),
                    if variant == 2 { None } else { Some(reject) },
                    ptr::from_mut(&mut state).cast(),
                )
            };
            assert!(result >= 0);
            if result == 1 {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_eq!(state.authorized, usize::from(variant != 2));
        assert_eq!(state.accepted, usize::from(variant == 0));
        let expected: &[(u8, u8, u8)] = if variant == 0 || variant == 3 {
            &[(1, 6, 7), (2, 4, 4), (3, 6, 5)]
        } else {
            &[(1, 6, 6)]
        };
        for &(sequence, kind, subclass) in expected {
            let mut bytes = [0; 2048];
            let (length, _) = fixture
                ._remote
                .recv_from(&mut bytes)
                .expect("answered provider rejection must send HANGUP before releasing its owner");
            let frame = crate::protocol::parse_full_frame_packet(&bytes[..length]).unwrap();
            assert_eq!(
                (
                    frame.header.outgoing_sequence,
                    frame.header.frame_type,
                    frame.header.subclass
                ),
                (sequence, kind, subclass)
            );
        }
        assert_eq!(
            unsafe {
                poll_accounts(
                    fixture.handle,
                    1000,
                    None,
                    None,
                    None,
                    None,
                    ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(server.0.lock().unwrap().ingress_stats().active_routes, 0);
    }
}

#[test]
fn real_ffi_registration_and_dial_transport_errors_preserve_cleared_outputs() {
    for network_error in [false, true] {
        let fixture = Fixture::new();
        let mut account = fixture.account();
        if network_error {
            account.generation = 8;
            account.remote_address = rptadv_iax2_bytes_v1::view("[::1]:9");
        }
        assert_eq!(
            unsafe { configure_accounts(fixture.handle, &account, 1) },
            0
        );
        assert_eq!(
            unsafe { server_enable_async(fixture.handle, crate::provider_tests::runtime()) },
            0
        );
        let mut request = fixture.registration();
        request.generation = account.generation;
        request.timeout_ms = 30;
        let mut result = fixture.registration_result();
        let expected = if network_error { -2 } else { -3 };
        assert_eq!(
            unsafe { register_account(fixture.handle, &request, &mut result) },
            expected
        );
        assert_eq!(
            (result.abi_version, result.refresh, result.local.family),
            (1, 0, 0)
        );
        let dial = rptadv_iax2_provider_dial_options_v1 {
            struct_size: size_of::<rptadv_iax2_provider_dial_options_v1>() as u32,
            abi_version: 1,
            generation: account.generation,
            account: rptadv_iax2_bytes_v1::view("provider-one"),
            destination: rptadv_iax2_bytes_v1::view("999"),
            caller_number: rptadv_iax2_bytes_v1::view("KG0BP"),
            caller_name: rptadv_iax2_bytes_v1::view(""),
            context: rptadv_iax2_bytes_v1::view(""),
            timeout_ms: 30,
            reserved: 0,
        };
        let mut receipt = rptadv_iax2_provider_call_receipt_v1 {
            struct_size: size_of::<rptadv_iax2_provider_call_receipt_v1>() as u32,
            ..Default::default()
        };
        let mut peer = ptr::dangling_mut::<c_void>();
        assert_eq!(
            unsafe { dial_provider_account(fixture.handle, &dial, &mut peer, &mut receipt) },
            expected
        );
        assert!(peer.is_null());
        assert_eq!(
            (receipt.abi_version, receipt.call_generation, receipt.format),
            (1, 0, 0)
        );
        for _ in 0..2 {
            assert_eq!(
                unsafe {
                    poll_accounts(
                        fixture.handle,
                        1000,
                        None,
                        None,
                        None,
                        None,
                        ptr::null_mut(),
                    )
                },
                0
            );
        }
        assert_eq!(
            unsafe { &*fixture.handle.cast::<ServerHandle>() }
                .0
                .lock()
                .unwrap()
                .ingress_stats()
                .active_routes,
            0
        );
    }
}

#[test]
fn actual_kernel_failures_reject_nonce_or_local_address_without_admitting_or_leaking_owner() {
    const CHILD: &str = "RPTADV_IAX_KERNEL_FAILURE_CHILD";
    let Some(selection) = std::env::var_os(CHILD) else {
        for selection in ["0", "1", "2"] {
            let output=std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "ffi::provider::tests::actual_kernel_failures_reject_nonce_or_local_address_without_admitting_or_leaking_owner", "--nocapture"])
                .env(CHILD,selection).output().unwrap();
            assert!(
                output.status.success(),
                "child{selection}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    };
    let fixture = Fixture::new();
    fixture
        ._remote
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut account = fixture.account();
    account.generation = 8;
    account.username = rptadv_iax2_bytes_v1::view("telephone-login");
    account.secret = rptadv_iax2_bytes_v1::view("fixture-secret");
    assert_eq!(
        unsafe { configure_accounts(fixture.handle, &account, 1) },
        0
    );
    assert_eq!(
        unsafe { server_enable_async(fixture.handle, crate::provider_tests::runtime()) },
        0
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::create_dir_all(root.join("target")).unwrap();
    let path = root
        .join("target")
        .join(format!("os-fault-{}.so", std::process::id()));
    assert!(
        std::process::Command::new("cc")
            .args([
                "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC"
            ])
            .arg(root.join("tests/os_fault_fixture.c"))
            .arg("-o")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let library = unsafe { libloading::Library::new(&path) }.unwrap();
    let install =
        unsafe { library.get::<unsafe extern "C" fn(u32) -> i32>(b"rptadv_test_fail_syscall\0") }
            .unwrap();
    let selection = selection.to_str().unwrap().parse::<u32>().unwrap();
    let server = unsafe { &*fixture.handle.cast::<ServerHandle>() };
    let bound = server.0.lock().unwrap().local_addr().unwrap();
    if selection != 2 {
        assert_eq!(unsafe { install(selection) }, 0);
    }
    if selection == 1 {
        let mut request = fixture.registration();
        request.generation = 8;
        let mut output = fixture.registration_result();
        assert_eq!(
            unsafe { register_account(fixture.handle, &request, &mut output) },
            -2
        );
        assert_eq!(
            (output.abi_version, output.refresh, output.local.family),
            (1, 0, 0)
        );
    } else {
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
        fixture
            ._remote
            .send_to(setup.initial_packet(), bound)
            .unwrap();
        {
            let mut listener = server.0.lock().unwrap();
            crate::provider_tests::poll_reply(&mut listener);
        }
        let mut bytes = [0; 2048];
        let (length, _) = fixture._remote.recv_from(&mut bytes).unwrap();
        let CallSetupResponse::Send(retry) = setup
            .receive(&bytes[..length], 0, "fixture-secret")
            .unwrap()
        else {
            panic!("missing token")
        };
        fixture._remote.send_to(&retry, bound).unwrap();
        if selection == 2 {
            assert_eq!(unsafe { install(selection) }, 0);
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            loop {
                let result =
                    server
                        .0
                        .lock()
                        .unwrap()
                        .poll_accounts(1000, |_, _, _| false, |_| false);
                match result {
                    Err(crate::server::ListenerError::Provider(AccountError::Network(error))) => {
                        assert_eq!(error.raw_os_error(), Some(5));
                        break;
                    }
                    Ok(
                        crate::server::ListenerEvent::None | crate::server::ListenerEvent::Ignored,
                    ) => {}
                    _ => panic!("actual EIO send must fail provider admission"),
                }
                assert!(std::time::Instant::now() < deadline);
                std::thread::yield_now();
            }
        } else {
            {
                let mut listener = server.0.lock().unwrap();
                crate::provider_tests::poll_reply(&mut listener);
            }
            let (length, _) = fixture._remote.recv_from(&mut bytes).unwrap();
            assert!(matches!(
                setup.receive(&bytes[..length], 0, "fixture-secret"),
                Ok(CallSetupResponse::Rejected { .. })
            ));
        }
    }
    assert_eq!(
        unsafe {
            poll_accounts(
                fixture.handle,
                1000,
                None,
                None,
                None,
                None,
                ptr::null_mut(),
            )
        },
        0
    );
    assert_eq!(server.0.lock().unwrap().ingress_stats().active_routes, 0);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn exact_outgoing_account_retirement_at_final_publication_never_transfers_the_answered_peer() {
    let fixture = Fixture::new();
    let mut configured = fixture.account();
    configured.generation = 8;
    assert_eq!(
        unsafe { configure_accounts(fixture.handle, &configured, 1) },
        0
    );
    assert_eq!(
        unsafe { server_enable_async(fixture.handle, crate::provider_tests::runtime()) },
        0
    );
    let (answered, wire_local) =
        crate::provider_tests::answer_outgoing(fixture._remote.try_clone().unwrap());
    let handle = fixture.handle;
    PUBLICATION_HOOK.with(|slot| {
        *slot.borrow_mut() = Some((
            "provider-one".into(),
            8,
            Box::new(move |metadata| {
                assert_eq!(
                    metadata.local_call,
                    wire_local.load(std::sync::atomic::Ordering::Acquire)
                );
                assert!(!metadata.incoming);
                assert_eq!(unsafe { configure_accounts(handle, ptr::null(), 0) }, 0);
            }),
        ))
    });
    let options = rptadv_iax2_provider_dial_options_v1 {
        struct_size: size_of::<rptadv_iax2_provider_dial_options_v1>() as u32,
        abi_version: 1,
        generation: 8,
        account: rptadv_iax2_bytes_v1::view("provider-one"),
        destination: rptadv_iax2_bytes_v1::view("999"),
        caller_number: rptadv_iax2_bytes_v1::view(""),
        caller_name: rptadv_iax2_bytes_v1::view(""),
        context: rptadv_iax2_bytes_v1::view(""),
        timeout_ms: 3000,
        reserved: 0,
    };
    let mut receipt = rptadv_iax2_provider_call_receipt_v1 {
        struct_size: size_of::<rptadv_iax2_provider_call_receipt_v1>() as u32,
        ..Default::default()
    };
    let mut peer = ptr::dangling_mut::<c_void>();
    assert_eq!(
        unsafe { dial_provider_account(fixture.handle, &options, &mut peer, &mut receipt) },
        -6
    );
    assert!(peer.is_null());
    assert_eq!(
        (receipt.abi_version, receipt.call_generation, receipt.format),
        (1, 0, 0)
    );
    let socket = answered.join().unwrap();
    let mut bytes = [0; 2048];
    let (length, _) = socket.recv_from(&mut bytes).unwrap();
    let frame = crate::protocol::parse_full_frame_packet(&bytes[..length]).unwrap();
    assert_eq!(
        crate::protocol::decode_iax_command(&frame.header),
        Ok(Some(crate::protocol::IaxCommand::Hangup))
    );
    assert_eq!(
        unsafe {
            poll_accounts(
                fixture.handle,
                1000,
                None,
                None,
                None,
                None,
                ptr::null_mut(),
            )
        },
        0
    );
    assert_eq!(
        unsafe { &*fixture.handle.cast::<ServerHandle>() }
            .0
            .lock()
            .unwrap()
            .ingress_stats()
            .active_routes,
        0
    );
}

#[path = "configuration_ffi_tests.rs"]
mod configuration;
