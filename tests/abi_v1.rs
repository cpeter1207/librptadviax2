use rptadviax2::ffi::{
    RPTADV_IAX2_CLIENT_ABI_VERSION, RPTADV_IAX2_CLIENT_CAPABILITY, RPTADV_IAX2_SERVER_ABI_VERSION,
    RPTADV_IAX2_SERVER_CAPABILITY, rptadv_iax2_client_descriptor_v1, rptadv_iax2_dial_options_v1,
    rptadv_iax2_server_descriptor_v1,
};
use std::mem::size_of;

#[test]
fn descriptor_v1_exposes_dial_and_media_operations() {
    let descriptor = rptadv_iax2_client_descriptor_v1();
    assert!(!descriptor.is_null());

    let descriptor = unsafe { &*descriptor };
    assert_eq!(
        descriptor.struct_size as usize,
        std::mem::size_of_val(descriptor)
    );
    assert_eq!(descriptor.abi_version, RPTADV_IAX2_CLIENT_ABI_VERSION);
    assert_eq!(descriptor.capability, RPTADV_IAX2_CLIENT_CAPABILITY);
    assert!(descriptor.dial.is_some());
    assert!(descriptor.sample_rate_hz.is_some());
    assert!(descriptor.send_audio.is_some());
    assert!(descriptor.send_text.is_some());
    assert!(descriptor.poll.is_some());
    assert!(descriptor.hangup.is_some());
    assert!(descriptor.destroy.is_some());
    assert!(descriptor.send_digit.is_some());
}

#[test]
fn server_descriptor_v1_exposes_listener_operations() {
    let descriptor = rptadv_iax2_server_descriptor_v1();
    assert!(!descriptor.is_null());

    let descriptor = unsafe { &*descriptor };
    assert_eq!(descriptor.abi_version, RPTADV_IAX2_SERVER_ABI_VERSION);
    assert_eq!(descriptor.capability, RPTADV_IAX2_SERVER_CAPABILITY);
    assert!(descriptor.bind.is_some());
    assert!(descriptor.poll.is_some());
    assert!(descriptor.set_local_nodes.is_some());
    assert!(descriptor.destroy.is_some());
}

#[test]
fn dial_rejects_invalid_options_and_clears_output_handle() {
    let descriptor = unsafe { &*rptadv_iax2_client_descriptor_v1() };
    let dial = descriptor.dial.unwrap();
    let mut options = rptadv_iax2_dial_options_v1 {
        struct_size: size_of::<rptadv_iax2_dial_options_v1>() as u32,
        abi_version: RPTADV_IAX2_CLIENT_ABI_VERSION,
        remote_address: std::ptr::null(),
        remote_address_length: 0,
        local_call_number: 0,
        reserved: 0,
        local_node: std::ptr::null(),
        local_node_length: 0,
        remote_node: std::ptr::null(),
        remote_node_length: 0,
        secret: std::ptr::null(),
        secret_length: 0,
        timeout_ms: 0,
    };
    let mut peer = std::ptr::dangling_mut::<std::ffi::c_void>();

    assert_eq!(unsafe { dial(&options, &mut peer) }, -1);
    assert!(peer.is_null());

    options.abi_version += 1;
    peer = std::ptr::dangling_mut::<std::ffi::c_void>();
    assert_eq!(unsafe { dial(&options, &mut peer) }, -1);
    assert!(peer.is_null());
}
