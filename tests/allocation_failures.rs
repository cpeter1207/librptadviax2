//! Actual recoverable allocation failure, isolated to this integration-test process.
use rptadviax2::{
    provider::{AccountConfig, AccountError, RegistrationRequest},
    server::InboundIaxListener,
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

thread_local! { static FAIL_NEXT: Cell<bool> = const { Cell::new(false) }; }
static FAILURES: AtomicUsize = AtomicUsize::new(0);
struct Allocator;
// Only this separate test executable selects the allocator. The single failure
// is armed around the public transaction, not a fabricated listener state.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if FAIL_NEXT
            .try_with(|fail| fail.replace(false))
            .unwrap_or(false)
        {
            FAILURES.fetch_add(1, Ordering::Relaxed);
            std::ptr::null_mut()
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

#[test]
fn failed_account_table_reservation_preserves_the_configured_owner_and_socket() {
    let remote = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let config = AccountConfig {
        id: "provider".into(),
        generation: 7,
        local_binding: "operator-west".into(),
        remote: remote.local_addr().unwrap(),
        username: "login".into(),
        secret: "fixture-secret".into(),
        pending_auth_timeout: Duration::from_secs(1),
    };
    let mut listener = InboundIaxListener::bind_accounts(
        "127.0.0.1:0".parse().unwrap(),
        &[],
        std::slice::from_ref(&config),
        None,
    )
    .unwrap();
    let local = listener.local_addr().unwrap();
    FAIL_NEXT.with(|fail| fail.set(true));
    let failed = listener.configure_accounts(std::slice::from_ref(&config));
    FAIL_NEXT.with(|fail| {
        assert!(
            !fail.replace(false),
            "transaction did not exercise its allocation"
        )
    });
    assert!(matches!(failed, Err(AccountError::Busy)));
    assert_eq!(FAILURES.load(Ordering::Relaxed), 1);
    assert_eq!(listener.local_addr().unwrap(), local);
    assert!(matches!(
        listener.prepare_registration(
            "provider",
            7,
            RegistrationRequest {
                refresh: 60,
                release: false,
                timeout: Duration::from_secs(1)
            }
        ),
        Err(AccountError::AsyncRequired)
    ));
    listener
        .configure_accounts(std::slice::from_ref(&config))
        .unwrap();
    remote.set_nonblocking(true).unwrap();
    assert_eq!(
        remote.recv_from(&mut [0; 2048]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
