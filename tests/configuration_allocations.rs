//! Prove that reserved commit/abort need no allocations, and prepare fails safely.
use rptadviax2::ffi::*;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    ffi::{CString, c_void},
    mem::size_of,
    ptr,
};

thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static FAIL_NEXT: Cell<bool> = const { Cell::new(false) };
}

struct Allocator;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACK.try_with(Cell::get).unwrap_or(false) {
            ALLOCATIONS.with(|count| count.set(count.get() + 1));
        }
        if FAIL_NEXT
            .try_with(|fail| fail.replace(false))
            .unwrap_or(false)
        {
            ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn bytes(value: &str) -> rptadv_iax2_bytes_v1 {
    rptadv_iax2_bytes_v1 {
        data: value.as_ptr(),
        length: value.len(),
    }
}
fn account(generation: u64) -> rptadv_iax2_provider_account_v1 {
    rptadv_iax2_provider_account_v1 {
        struct_size: size_of::<rptadv_iax2_provider_account_v1>() as u32,
        abi_version: 1,
        generation,
        account: bytes("phone"),
        local_binding: bytes("local-binding"),
        remote_address: bytes("127.0.0.1:4569"),
        username: bytes("login"),
        secret: bytes("fixture-only"),
        authentication_timeout_ms: 1000,
        reserved: 0,
    }
}

struct Listener(*mut c_void);
impl Listener {
    fn new() -> Self {
        let client = unsafe { &*rptadv_iax2_client_descriptor_v2() };
        let path = CString::new("librptadv_codec_g711.so.1").unwrap();
        let selection = rptadv_iax2_codec_selection_v2 {
            struct_size: size_of::<rptadv_iax2_codec_selection_v2>() as u32,
            profile_id: 1,
            provider_path: path.as_ptr(),
        };
        let mut catalog = ptr::null_mut();
        assert_eq!(
            unsafe { client.open_catalog.unwrap()(&selection, 1, &mut catalog) },
            0
        );
        let account = account(7);
        let options = rptadv_iax2_server_options_v2 {
            struct_size: size_of::<rptadv_iax2_server_options_v2>() as u32,
            abi_version: 2,
            bind_address: b"127.0.0.1:0".as_ptr(),
            bind_address_length: 11,
            local_nodes: b"524950".as_ptr(),
            local_nodes_length: 6,
            catalog,
            accounts: &account,
            account_count: 1,
        };
        let mut listener = ptr::null_mut();
        assert_eq!(unsafe { api().bind.unwrap()(&options, &mut listener) }, 0);
        unsafe { client.close_catalog.unwrap()(catalog) };
        Self(listener)
    }
    fn entry(
        &self,
        account: &rptadv_iax2_provider_account_v1,
    ) -> rptadv_iax2_configuration_entry_v1 {
        rptadv_iax2_configuration_entry_v1 {
            struct_size: size_of::<rptadv_iax2_configuration_entry_v1>() as u32,
            abi_version: 1,
            listener: self.0,
            local_nodes: bytes("524951"),
            accounts: account,
            account_count: 1,
        }
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        unsafe { api().destroy.unwrap()(self.0) };
    }
}
fn api() -> &'static rptadv_iax2_server_descriptor_v2 {
    unsafe { &*rptadv_iax2_server_descriptor_v2() }
}

#[test]
fn prepared_commit_and_abort_allocate_nothing() {
    for commit in [true, false] {
        let first = Listener::new();
        let second = Listener::new();
        let next = account(8);
        let entries = [first.entry(&next), second.entry(&next)];
        let mut token = ptr::null_mut();
        assert_eq!(
            unsafe {
                api().prepare_configuration_batch.unwrap()(
                    entries.as_ptr(),
                    entries.len(),
                    &mut token,
                )
            },
            0
        );
        ALLOCATIONS.set(0);
        TRACK.set(true);
        unsafe {
            if commit {
                api().commit_configuration_batch.unwrap()(token);
            } else {
                api().destroy_configuration_batch.unwrap()(token);
            }
        }
        TRACK.set(false);
        assert_eq!(ALLOCATIONS.get(), 0);
        // Both paths consume their reservations; this is not merely a no-op token.
        assert_eq!(
            unsafe { api().set_local_nodes.unwrap()(first.0, b"524950".as_ptr(), 6) },
            0
        );
        assert_eq!(
            unsafe { api().set_local_nodes.unwrap()(second.0, b"524950".as_ptr(), 6) },
            0
        );
    }
}

#[test]
fn failed_preparation_allocation_leaves_listener_unreserved() {
    let listener = Listener::new();
    let next = account(8);
    let entry = listener.entry(&next);
    let mut token = ptr::dangling_mut::<c_void>();
    FAIL_NEXT.set(true);
    let status = unsafe { api().prepare_configuration_batch.unwrap()(&entry, 1, &mut token) };
    let unused = FAIL_NEXT.replace(false);
    assert!(!unused, "prepare did not exercise its first allocation");
    assert_eq!(status, -6);
    assert!(token.is_null());
    assert_eq!(
        unsafe { api().configure_accounts.unwrap()(listener.0, &account(7), 1) },
        0
    );
}
