use super::*;
use crate::{
    call_token::retry_new_call_with_token,
    codec::{CodecError, IAX_FORMAT_ULAW},
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

fn options<'a>(
    remote: &'a [u8],
    local: &'a [u8],
    destination: &'a [u8],
    secret: &'a [u8],
) -> rptadv_iax2_dial_options_v1 {
    rptadv_iax2_dial_options_v1 {
        struct_size: size_of::<rptadv_iax2_dial_options_v1>() as u32,
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
    }
}

fn server_options<'a>(address: &'a [u8], local_nodes: &'a [u8]) -> rptadv_iax2_server_options_v1 {
    rptadv_iax2_server_options_v1 {
        struct_size: size_of::<rptadv_iax2_server_options_v1>() as u32,
        abi_version: RPTADV_IAX2_SERVER_ABI_VERSION,
        bind_address: address.as_ptr(),
        bind_address_length: address.len(),
        local_nodes: local_nodes.as_ptr(),
        local_nodes_length: local_nodes.len(),
    }
}

fn inbound_setup(local_call: u16) -> OutboundCallSetup {
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
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let address = server.local_addr().unwrap();
    let responder = thread::spawn(move || {
        let mut packet = [0; 1500];
        let (length, client) = server.recv_from(&mut packet).unwrap();
        assert!(length > 12);
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
            &[9, 4, 0, 0, 0, IAX_FORMAT_ULAW as u8],
        )
        .unwrap();
        server.send_to(&accept, client).unwrap();
        let _ = server.recv_from(&mut packet).unwrap(); // ACK.
        (server, client)
    });

    let remote = address.to_string();
    let local = b"524950";
    let destination = b"506315";
    let secret = b"";
    let dial_options = options(remote.as_bytes(), local, destination, secret);
    let mut peer = ptr::null_mut();
    assert_eq!(unsafe { dial(&dial_options, &mut peer) }, 0);
    let (server, client) = responder.join().unwrap();
    (peer, server, client)
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
    let options = rptadv_iax2_server_options_v1 {
        struct_size: size_of::<rptadv_iax2_server_options_v1>() as u32,
        abi_version: RPTADV_IAX2_SERVER_ABI_VERSION,
        bind_address: bind_address.as_ptr(),
        bind_address_length: bind_address.len(),
        local_nodes: local_nodes.as_ptr(),
        local_nodes_length: local_nodes.len(),
    };
    let mut handle = ptr::null_mut();
    assert_eq!(unsafe { server_bind(&options, &mut handle) }, 0);
    let server = unsafe { &mut *handle.cast::<ServerHandle>() };
    let server_address = server.0.local_addr().unwrap();
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
    let descriptor = unsafe { &*rptadv_iax2_client_descriptor_v1() };
    assert_eq!(descriptor.abi_version, RPTADV_IAX2_CLIENT_ABI_VERSION);
    assert_eq!(descriptor.capability, RPTADV_IAX2_CLIENT_CAPABILITY);
    let server_descriptor = unsafe { &*rptadv_iax2_server_descriptor_v1() };
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
    assert_eq!(unsafe { send_audio(ptr::null_mut(), ptr::null(), 0) }, -1);
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
    server.0.force_poll_error();
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
    assert_eq!(unsafe { send_audio(peer, ptr::null(), 1) }, -1);
    let oversized_pcm = [0.0_f32; 1500];
    assert_eq!(
        unsafe { send_audio(peer, oversized_pcm.as_ptr(), oversized_pcm.len()) },
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
            outgoing_sequence: 1,
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
            outgoing_sequence: 2,
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
        (12, RPTADV_IAX2_EVENT_RADIO_KEY, 3),
        (13, RPTADV_IAX2_EVENT_RADIO_UNKEY, 4),
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
            outgoing_sequence: 5,
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
            outgoing_sequence: 0,
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
