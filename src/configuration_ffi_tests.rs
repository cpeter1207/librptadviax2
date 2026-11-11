//! Exercise reservations through the real public listener descriptors.
use super::*;
use crate::server::configuration_test_support::{Snapshot, snapshot};

fn snapshot_fixture(fixture: &Fixture) -> Snapshot {
    let server = unsafe { &*fixture.handle.cast::<ServerHandle>() };
    snapshot(&server.0.lock().unwrap_or_else(|error| error.into_inner()))
}

fn entry(
    fixture: &Fixture,
    account: &rptadv_iax2_provider_account_v1,
) -> rptadv_iax2_configuration_entry_v1 {
    rptadv_iax2_configuration_entry_v1 {
        struct_size: size_of::<rptadv_iax2_configuration_entry_v1>() as u32,
        abi_version: 1,
        listener: fixture.handle,
        local_nodes: rptadv_iax2_bytes_v1::view("524950"),
        accounts: account,
        account_count: 1,
    }
}

fn api() -> &'static rptadv_iax2_server_descriptor_v2 {
    unsafe { &*rptadv_iax2_server_descriptor_v2() }
}

fn prepare_entries(entries: &[rptadv_iax2_configuration_entry_v1]) -> *mut c_void {
    let mut token = ptr::null_mut();
    assert_eq!(
        unsafe {
            api().prepare_configuration_batch.unwrap()(entries.as_ptr(), entries.len(), &mut token)
        },
        0
    );
    assert!(!token.is_null());
    token
}

#[test]
fn prepared_configuration_abort_preserves_old_lifetimes_and_releases_reservations() {
    let first = Fixture::new();
    let second = Fixture::new();
    let old_first = snapshot_fixture(&first);
    let old_second = snapshot_fixture(&second);
    let mut first_next = first.account();
    first_next.generation = 8;
    let mut second_next = second.account();
    second_next.generation = 8;
    let token = prepare_entries(&[entry(&first, &first_next), entry(&second, &second_next)]);
    for fixture in [&first, &second] {
        fixture.assert_account_preserved();
        assert_eq!(
            unsafe { configure_accounts(fixture.handle, &fixture.account(), 1) },
            -6
        );
        assert_eq!(
            unsafe { server_set_local_nodes(fixture.handle, b"999".as_ptr(), 3) },
            -1
        );
        assert_eq!(
            unsafe { server_poll(fixture.handle, 0, None, None, ptr::null_mut()) },
            0
        );
    }
    assert!(old_first.account_live(0) && old_first.numeric_live());
    assert!(old_second.account_live(0) && old_second.numeric_live());
    unsafe { api().destroy_configuration_batch.unwrap()(token) };
    for (fixture, old) in [(&first, old_first), (&second, old_second)] {
        let active = snapshot_fixture(fixture);
        assert!(Arc::ptr_eq(&old.accounts[0], &active.accounts[0]));
        assert!(Arc::ptr_eq(&old.legacy, &active.legacy));
        assert!(active.nodes.is_empty());
        assert_eq!(
            unsafe { configure_accounts(fixture.handle, &fixture.account(), 1) },
            0
        );
    }
}

#[test]
fn prepared_configuration_commit_changes_all_listeners_without_retiring_unchanged_accounts() {
    let first = Fixture::new();
    let second = Fixture::new();
    let old_first = snapshot_fixture(&first);
    let old_second = snapshot_fixture(&second);
    let mut changed = first.account();
    changed.generation = 8;
    let unchanged = second.account();
    let token = prepare_entries(&[entry(&second, &unchanged), entry(&first, &changed)]);
    assert!(old_first.account_live(0));
    unsafe { api().commit_configuration_batch.unwrap()(token) };
    let first_active = snapshot_fixture(&first);
    let second_active = snapshot_fixture(&second);
    assert!(!old_first.account_live(0));
    assert!(!old_first.numeric_live() && !old_second.numeric_live());
    assert_eq!(first_active.accounts[0].config.generation, 8);
    assert_eq!(first_active.nodes, ["524950"]);
    assert_eq!(second_active.nodes, ["524950"]);
    assert!(Arc::ptr_eq(
        &old_second.accounts[0],
        &second_active.accounts[0]
    ));
    assert!(old_second.account_live(0));
    assert_eq!(unsafe { configure_accounts(first.handle, &changed, 1) }, 0);
    assert_eq!(
        unsafe { server_set_local_nodes(second.handle, b"999".as_ptr(), 3) },
        0
    );
}

#[test]
fn prepared_configuration_unchanged_numeric_admission_keeps_its_existing_lifetime() {
    let fixture = Fixture::new();
    assert_eq!(
        unsafe { server_set_local_nodes(fixture.handle, b"524950".as_ptr(), 6) },
        0
    );
    let old = snapshot_fixture(&fixture);
    let account = fixture.account();
    let token = prepare_entries(&[entry(&fixture, &account)]);
    unsafe { api().commit_configuration_batch.unwrap()(token) };
    let active = snapshot_fixture(&fixture);
    assert!(Arc::ptr_eq(&old.legacy, &active.legacy));
    assert!(Arc::ptr_eq(&old.accounts[0], &active.accounts[0]));
    assert!(old.numeric_live() && old.account_live(0));
}

#[test]
fn prepared_configuration_last_entry_failure_preserves_all_owners_and_leaves_no_reservations() {
    let lower = Fixture::new();
    let higher = Fixture::new();
    let (first, second) = if lower.handle.addr() < higher.handle.addr() {
        (&lower, &higher)
    } else {
        (&higher, &lower)
    };
    let old_first = snapshot_fixture(first);
    let old_second = snapshot_fixture(second);
    let mut changed = first.account();
    changed.generation = 8;
    let mut invalid = second.account();
    invalid.secret = rptadv_iax2_bytes_v1::view("changed-without-new-generation");
    let entries = [entry(first, &changed), entry(second, &invalid)];
    let mut token = ptr::dangling_mut::<c_void>();
    assert_eq!(
        unsafe { api().prepare_configuration_batch.unwrap()(entries.as_ptr(), 2, &mut token) },
        -1
    );
    assert!(token.is_null());
    for (fixture, old) in [(first, old_first), (second, old_second)] {
        let active = snapshot_fixture(fixture);
        assert!(Arc::ptr_eq(&old.accounts[0], &active.accounts[0]));
        assert!(old.account_live(0) && old.numeric_live());
        assert!(active.nodes.is_empty());
        assert_eq!(
            unsafe { configure_accounts(fixture.handle, &fixture.account(), 1) },
            0
        );
    }
}

#[test]
fn prepared_configuration_overlapping_batches_fail_without_releasing_original_reservation() {
    let fixture = Fixture::new();
    let account = fixture.account();
    let record = entry(&fixture, &account);
    let token = prepare_entries(&[record]);
    let mut second = ptr::dangling_mut::<c_void>();
    assert_eq!(
        unsafe { api().prepare_configuration_batch.unwrap()(&record, 1, &mut second) },
        -6
    );
    assert!(second.is_null());
    assert_eq!(
        unsafe { configure_accounts(fixture.handle, &account, 1) },
        -6
    );
    unsafe { api().destroy_configuration_batch.unwrap()(token) };
    assert_eq!(
        unsafe { configure_accounts(fixture.handle, &account, 1) },
        0
    );
}

#[test]
fn prepared_configuration_rejects_invalid_batch_inputs_before_reserving_any_listener() {
    let fixture = Fixture::new();
    let account = fixture.account();
    let record = entry(&fixture, &account);
    let mut output = ptr::dangling_mut::<c_void>();
    assert_eq!(
        unsafe { api().prepare_configuration_batch.unwrap()(&record, 1, ptr::null_mut()) },
        -1
    );
    for (input, count) in [
        (ptr::null(), 1),
        (&record as *const _, 0),
        (&record as *const _, usize::MAX),
    ] {
        assert_eq!(
            unsafe { api().prepare_configuration_batch.unwrap()(input, count, &mut output) },
            -1
        );
        assert!(output.is_null());
    }
    let duplicates = [record, record];
    assert_eq!(
        unsafe { api().prepare_configuration_batch.unwrap()(duplicates.as_ptr(), 2, &mut output) },
        -1
    );
    for kind in 0..9 {
        let mut invalid = record;
        match kind {
            0 => invalid.struct_size -= 1,
            1 => invalid.abi_version = 2,
            2 => invalid.listener = ptr::null_mut(),
            3 => invalid.local_nodes = rptadv_iax2_bytes_v1::view("not-numeric"),
            4 => invalid.local_nodes = rptadv_iax2_bytes_v1::view("524950,524950"),
            5 => invalid.accounts = ptr::null(),
            6 => invalid.account_count = 65,
            7 => invalid.local_nodes.length = usize::MAX,
            _ => invalid.local_nodes.data = ptr::null(),
        }
        assert_eq!(
            unsafe { api().prepare_configuration_batch.unwrap()(&invalid, 1, &mut output) },
            -1,
            "case {kind}"
        );
        assert!(output.is_null());
    }
    assert_eq!(
        unsafe { configure_accounts(fixture.handle, &account, 1) },
        0
    );
    unsafe {
        api().commit_configuration_batch.unwrap()(ptr::null_mut());
        api().destroy_configuration_batch.unwrap()(ptr::null_mut());
    }
}

#[test]
fn prepared_configuration_disabled_listener_retires_all_admission_before_socket_cleanup() {
    let fixture = Fixture::new();
    assert_eq!(
        unsafe { server_set_local_nodes(fixture.handle, b"524950".as_ptr(), 6) },
        0
    );
    let old = snapshot_fixture(&fixture);
    let account = fixture.account();
    let mut disabled = entry(&fixture, &account);
    disabled.local_nodes = rptadv_iax2_bytes_v1::view("");
    disabled.accounts = ptr::null();
    disabled.account_count = 0;
    let token = prepare_entries(&[disabled]);
    assert!(old.account_live(0) && old.numeric_live());
    unsafe { api().commit_configuration_batch.unwrap()(token) };
    let active = snapshot_fixture(&fixture);
    assert!(active.accounts.is_empty() && active.nodes.is_empty());
    assert!(!old.account_live(0) && !old.numeric_live());
    assert_eq!(
        unsafe { server_poll(fixture.handle, 0, None, None, ptr::null_mut()) },
        0
    );
}

#[test]
fn prepared_configuration_commit_recovers_a_poisoned_listener_without_partial_failure() {
    let first = Fixture::new();
    let second = Fixture::new();
    let mut first_next = first.account();
    first_next.generation = 8;
    let mut second_next = second.account();
    second_next.generation = 8;
    let old_first = snapshot_fixture(&first);
    let old_second = snapshot_fixture(&second);
    let token = prepare_entries(&[entry(&first, &first_next), entry(&second, &second_next)]);
    let server = unsafe { &*second.handle.cast::<ServerHandle>() };
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = server.0.lock().unwrap();
        panic!("fixture poisons a reserved listener without changing configuration");
    }));
    assert!(poisoned.is_err());
    unsafe { api().commit_configuration_batch.unwrap()(token) };
    assert!(!old_first.account_live(0) && !old_second.account_live(0));
    assert_eq!(snapshot_fixture(&first).accounts[0].config.generation, 8);
    assert_eq!(snapshot_fixture(&second).accounts[0].config.generation, 8);
}
