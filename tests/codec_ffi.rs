//! The external synchronous ABI retains selected providers independently of callers.
use rptadviax2::ffi::{
    rptadv_iax2_client_descriptor_v2, rptadv_iax2_codec_selection_v2,
    rptadv_iax2_server_descriptor_v2, rptadv_iax2_server_options_v2,
};
use std::{ffi::CString, mem::size_of, path::PathBuf, ptr};

#[test]
fn catalog_v2_lifetime_and_listener_reject_old_options() {
    let client = unsafe { &*rptadv_iax2_client_descriptor_v2() };
    let server = unsafe { &*rptadv_iax2_server_descriptor_v2() };
    assert_eq!(client.abi_version, 2);
    assert_eq!(server.abi_version, 2);
    assert!(client.prepare_audio.is_some());
    assert!(client.send_prepared_audio.is_some());
    assert!(client.reset_encoder.is_some());
    let directory = PathBuf::from(std::env::var_os("RPTADV_CODEC_DIR").unwrap_or_default());
    let path = CString::new(
        directory
            .join("librptadv_codec_g711.so.1")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let mut selection = rptadv_iax2_codec_selection_v2 {
        struct_size: size_of::<rptadv_iax2_codec_selection_v2>() as u32,
        profile_id: 1,
        provider_path: path.as_ptr(),
    };
    let mut catalog = ptr::dangling_mut::<std::ffi::c_void>();
    unsafe {
        assert_eq!(
            (client.open_catalog.unwrap())(ptr::null(), 0, &mut catalog),
            -1
        );
        assert!(catalog.is_null());
        selection.profile_id = 99;
        assert_eq!(
            (client.open_catalog.unwrap())(&selection, 1, &mut catalog),
            -1
        );
        assert!(catalog.is_null());
        selection.profile_id = 1;
        assert_eq!(
            (client.open_catalog.unwrap())(&selection, 1, &mut catalog),
            0
        );
        assert!(!catalog.is_null());
    }
    drop(path);
    let mut options = rptadv_iax2_server_options_v2 {
        struct_size: size_of::<rptadv_iax2_server_options_v2>() as u32,
        abi_version: 1,
        bind_address: b"127.0.0.1:0".as_ptr(),
        bind_address_length: 11,
        local_nodes: b"524950".as_ptr(),
        local_nodes_length: 6,
        catalog,
    };
    let mut listener = ptr::dangling_mut::<std::ffi::c_void>();
    unsafe {
        assert_eq!((server.bind.unwrap())(&options, &mut listener), -1);
        assert!(listener.is_null());
        options.abi_version = 2;
        assert_eq!((server.bind.unwrap())(&options, &mut listener), 0);
        assert!(!listener.is_null());
        (client.close_catalog.unwrap())(catalog);
        assert_eq!(
            (server.poll.unwrap())(listener, 0, None, None, ptr::null_mut()),
            0
        );
        (server.destroy.unwrap())(listener);
        (client.close_catalog.unwrap())(ptr::null_mut());
    }
}
