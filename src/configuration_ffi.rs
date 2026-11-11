//! Reserved, control-only preparation of complete listener configurations.
//!
//! Alpha11's immediate per-listener replacement cannot roll back retired call
//! generations if a later listener or product preparation fails. The optional
//! batch tail therefore reserves all validated replacements before publication.
//! It preserves ABI2 and SONAME2, including the released 88-byte server prefix.
//! Consumers must require the first released package containing this full tail
//! and all three slots; sequential mutation is not a compatibility fallback.
//! This guarantees listener-cohort commit, not atomic publication of an external
//! product runtime or its other independently owned resources.

use super::*;
use crate::{
    provider::AccountError,
    server::{InboundIaxListener, PreparedConfiguration},
};
use std::{ptr::NonNull, sync::MutexGuard};

type ListenerGuard<'a> = MutexGuard<'a, InboundIaxListener>;

/// Only empty guard storage crosses C. Listener ownership remains with the caller.
struct PreparedBatch {
    listeners: Vec<NonNull<ServerHandle>>,
    replacements: Vec<PreparedConfiguration>,
    lock_storage: Vec<ListenerGuard<'static>>,
}

/// Borrow exactly for this handle-list lifetime; the C caller retains every listener.
fn listener_ref(pointer: &NonNull<ServerHandle>) -> &ServerHandle {
    // SAFETY: successful preparation requires live handles through token consumption.
    unsafe { pointer.as_ref() }
}

/// Lifetime shortening is ordinary covariance, never an extended or transmuted guard.
/// Every returned guard is dropped before the enclosing C operation returns.
fn lock_all<'a>(
    listeners: &'a [NonNull<ServerHandle>],
    storage: Vec<ListenerGuard<'static>>,
) -> Vec<ListenerGuard<'a>> {
    let mut guards: Vec<ListenerGuard<'a>> = storage;
    for listener in listeners {
        guards.push(
            listener_ref(listener)
                .0
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
        );
    }
    guards
}

/// Reserve vector storage while preparation can still fail without publishing anything.
fn reserved<T>(count: usize) -> Result<Vec<T>, AccountError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| AccountError::Busy)?;
    Ok(values)
}

/// Borrowed whole-listener replacement, copied during prepare.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct rptadv_iax2_configuration_entry_v1 {
    /// Exact ABI1 record size and array stride.
    pub struct_size: u32,
    /// Exactly one.
    pub abi_version: u32,
    /// Live listener retained until its transaction token is consumed.
    pub listener: *mut c_void,
    /// Comma-separated numeric ASL bindings; empty accounts and nodes disable admission.
    pub local_nodes: rptadv_iax2_bytes_v1,
    /// Exact ABI1 copied account array.
    pub accounts: *const rptadv_iax2_provider_account_v1,
    /// Count of account records.
    pub account_count: usize,
}

/// Validate all borrowed input before installing a reservation on any listener.
unsafe fn prepare_batch(
    entries: *const rptadv_iax2_configuration_entry_v1,
    count: usize,
) -> Result<Box<PreparedBatch>, AccountError> {
    if count == 0 || count > isize::MAX as usize / size_of::<rptadv_iax2_configuration_entry_v1>() {
        return Err(AccountError::InvalidOptions);
    }
    let input = unsafe { input_slice(entries, count) }.ok_or(AccountError::InvalidOptions)?;
    let mut entries = reserved(count)?;
    entries.extend_from_slice(input);
    entries.sort_unstable_by_key(|entry| entry.listener.addr());
    let mut listeners = reserved(count)?;
    for entry in &entries {
        if entry.struct_size as usize != size_of::<rptadv_iax2_configuration_entry_v1>()
            || entry.abi_version != 1
            || entry.local_nodes.length > isize::MAX as usize
        {
            return Err(AccountError::InvalidOptions);
        }
        let pointer = NonNull::new(entry.listener.cast::<ServerHandle>())
            .ok_or(AccountError::InvalidOptions)?;
        if listeners.last() == Some(&pointer) {
            return Err(AccountError::InvalidOptions);
        }
        listeners.push(pointer);
    }
    let lock_storage = reserved(count)?;
    let mut replacements = reserved(count)?;
    let mut guards = lock_all(&listeners, reserved(count)?);
    for (entry, listener) in entries.iter().zip(&guards) {
        let nodes = unsafe { utf8(entry.local_nodes.data, entry.local_nodes.length) }
            .ok_or(AccountError::InvalidOptions)?;
        let nodes = if nodes.is_empty() {
            Vec::new()
        } else {
            nodes.split(',').map(str::to_owned).collect()
        };
        let accounts = unsafe { provider::copy_accounts(entry.accounts, entry.account_count) }
            .ok_or(AccountError::InvalidOptions)?;
        replacements.push(listener.prepare_configuration(nodes, accounts)?);
    }
    // Allocate the token before reserving. Only moves and lock release remain afterward.
    let mut batch = Box::new(PreparedBatch {
        listeners: Vec::new(),
        replacements,
        lock_storage,
    });
    for listener in &mut guards {
        listener.reserve_configuration();
    }
    drop(guards);
    batch.listeners = listeners;
    Ok(batch)
}

pub(super) unsafe extern "C" fn prepare(
    entries: *const rptadv_iax2_configuration_entry_v1,
    count: usize,
    output: *mut *mut c_void,
) -> i32 {
    boundary(-1, || {
        let Some(output) = (unsafe { output.as_mut() }) else {
            return -1;
        };
        *output = ptr::null_mut();
        match unsafe { prepare_batch(entries, count) } {
            Ok(batch) => {
                *output = Box::into_raw(batch).cast();
                0
            }
            Err(error) => provider::status(error),
        }
    })
}

/// Consume a valid token, retaining every listener lock through the last publication.
unsafe fn finish(token: *mut c_void, commit: bool) {
    if token.is_null() {
        return;
    }
    // SAFETY: this exact unique token is consumed once, with all listeners still retained.
    let PreparedBatch {
        listeners,
        replacements,
        lock_storage,
    } = unsafe { *Box::from_raw(token.cast::<PreparedBatch>()) };
    let mut guards = lock_all(&listeners, lock_storage);
    for (listener, replacement) in guards.iter_mut().zip(replacements) {
        listener.finish_configuration(commit.then_some(replacement));
    }
}

pub(super) unsafe extern "C" fn commit(token: *mut c_void) {
    boundary((), || unsafe { finish(token, true) });
}

pub(super) unsafe extern "C" fn destroy(token: *mut c_void) {
    boundary((), || unsafe { finish(token, false) });
}
