//! Optional retained readiness executor; synchronous IAX client/server ABIs stay unchanged.

use crate::{
    async_driver::{DatagramPump, PeerDriver},
    client::{IaxPeer, IaxPeerObservation},
};
use std::{ffi::c_void, mem::size_of, ptr, sync::Arc};
use tokio::runtime::Runtime;

/// Bounded serialized peer turn. Zero continues; negative stops future turns.
pub type Step = unsafe extern "C" fn(*mut c_void) -> i32;

/// C-compatible asynchronous scheduling capability, version 1.
#[repr(C)]
pub struct AsyncDescriptor {
    /// Complete readable table size.
    pub struct_size: u32,
    /// Exact ABI identity, one.
    pub abi_version: u32,
    /// NUL-padded rptadv.iaxasync.
    pub capability: [u8; 16],
    /// Create one shared runtime for all connection tasks.
    pub runtime_create: unsafe extern "C" fn(*mut *mut c_void) -> i32,
    /// Release the control owner; registrations and listeners retain their own runtime owners.
    pub runtime_destroy: unsafe extern "C" fn(*mut c_void),
    /// Retain a stable callback context and exclusive peer use, once per peer.
    pub peer_attach: unsafe extern "C" fn(
        *mut c_void,
        *mut c_void,
        Option<Step>,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    /// Request stop without blocking, including from a callback.
    pub peer_stop: unsafe extern "C" fn(*mut c_void),
    /// Wait off-executor for final callback and receive-task completion.
    pub peer_detach: unsafe extern "C" fn(*mut c_void),
    /// Configure borrowed jitter capability once, before peer attachment.
    pub peer_configure_jitter: unsafe extern "C" fn(*mut c_void, *const c_void) -> i32,
    /// Enable independent listener routing on its off-executor control owner; repeat is a no-op.
    pub server_enable: unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32,
    /// Copy diagnostics on the exclusive peer owner, never concurrently with media operations.
    pub peer_observe: unsafe extern "C" fn(*mut c_void, *mut IaxPeerObservation) -> i32,
    /// Signal-only wake; caller keeps the registration alive until return.
    pub peer_wake: unsafe extern "C" fn(*mut c_void),
    /// Owner-only relative deadline; u64::MAX clears, zero makes the next turn due.
    pub peer_set_deadline: unsafe extern "C" fn(*mut c_void, u64) -> i32,
}

static API: AsyncDescriptor = AsyncDescriptor {
    struct_size: size_of::<AsyncDescriptor>() as u32,
    abi_version: 1,
    capability: *b"rptadv.iaxasync\0",
    runtime_create,
    runtime_destroy,
    peer_attach,
    peer_stop,
    peer_detach,
    peer_configure_jitter,
    server_enable,
    peer_observe,
    peer_wake,
    peer_set_deadline,
};

/// Return the immutable optional table. Retain this DSO through every detach.
#[unsafe(no_mangle)]
pub extern "C" fn rptadv_iax2_async_descriptor_v1() -> *const AsyncDescriptor {
    &API
}

struct Registration {
    // Declaration order keeps the runtime alive through both task destructors.
    driver: PeerDriver,
    pump: Option<DatagramPump>,
    _runtime: Arc<Runtime>,
}

impl Registration {
    fn stop(&self) {
        self.driver.stop();
        if let Some(pump) = &self.pump {
            pump.stop();
        }
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.stop();
    }
}

unsafe extern "C" fn runtime_create(output: *mut *mut c_void) -> i32 {
    let Some(output) = (unsafe { output.as_mut() }) else {
        return -1;
    };
    publish_runtime(
        output,
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("rpt-iax")
            .build(),
    )
}

fn publish_runtime(output: &mut *mut c_void, runtime: std::io::Result<Runtime>) -> i32 {
    *output = ptr::null_mut();
    let Ok(runtime) = runtime else {
        return -1;
    };
    *output = Box::into_raw(Box::new(Arc::new(runtime))).cast();
    0
}

unsafe extern "C" fn runtime_destroy(runtime: *mut c_void) {
    if !runtime.is_null() {
        unsafe {
            drop(Box::from_raw(runtime.cast::<Arc<Runtime>>()));
        }
    }
}

unsafe extern "C" fn peer_attach(
    runtime: *mut c_void,
    peer: *mut c_void,
    step: Option<Step>,
    context: *mut c_void,
    output: *mut *mut c_void,
) -> i32 {
    let Some(output) = (unsafe { output.as_mut() }) else {
        return -1;
    };
    *output = ptr::null_mut();
    let (Some(runtime), Some(step)) = (unsafe { runtime.cast::<Arc<Runtime>>().as_ref() }, step)
    else {
        return -1;
    };
    // This borrow ends before spawning: the callback owns all later peer access.
    let (wake, pump) = {
        let Some(peer) = (unsafe { peer.cast::<IaxPeer>().as_mut() }) else {
            return -1;
        };
        let remote = peer.remote_addr();
        let Ok((wake, source)) = peer.prepare_async_ingress(runtime.handle()) else {
            return -1;
        };
        (
            wake,
            source.map(|(socket, producer)| {
                DatagramPump::from_socket(runtime.handle(), socket, remote, producer)
            }),
        )
    };
    let context = context as usize;
    let peer = peer as usize;
    let driver = PeerDriver::attach(runtime.handle(), wake, move || {
        // The host promises stable context and one registered owner through detach.
        // End each peer borrow before calling product code, which re-enters its API.
        unsafe { (*(peer as *const IaxPeer)).begin_turn() };
        if unsafe { step(context as *mut c_void) } < 0 {
            None
        } else {
            Some(unsafe { (*(peer as *const IaxPeer)).wait_state() })
        }
    });
    *output = Box::into_raw(Box::new(Registration {
        driver,
        pump,
        _runtime: Arc::clone(runtime),
    }))
    .cast();
    0
}

unsafe extern "C" fn peer_stop(registration: *mut c_void) {
    if let Some(registration) = unsafe { registration.cast::<Registration>().as_ref() } {
        registration.stop();
    }
}

unsafe extern "C" fn peer_wake(registration: *mut c_void) {
    if let Some(registration) = unsafe { registration.cast::<Registration>().as_ref() } {
        registration.driver.wake();
    }
}

unsafe extern "C" fn peer_set_deadline(peer: *mut c_void, wake_after_ns: u64) -> i32 {
    let Some(peer) = (unsafe { peer.cast::<IaxPeer>().as_mut() }) else {
        return -1;
    };
    peer.set_product_deadline(wake_after_ns).map_or(-1, |_| 0)
}

unsafe extern "C" fn peer_detach(registration: *mut c_void) {
    if let Some(active) = unsafe { registration.cast::<Registration>().as_ref() } {
        // Keep shared ownership while a callback may reenter peer_stop. Creating
        // the Box (and its exclusive destructor borrow) must wait for quiescence.
        active.stop();
        active.driver.wait();
        unsafe {
            drop(Box::from_raw(registration.cast::<Registration>()));
        }
    }
}

unsafe extern "C" fn peer_configure_jitter(peer: *mut c_void, descriptor: *const c_void) -> i32 {
    let Some(peer) = (unsafe { peer.cast::<IaxPeer>().as_mut() }) else {
        return -1;
    };
    match unsafe { peer.configure_jitter(descriptor) } {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

unsafe extern "C" fn server_enable(runtime: *mut c_void, server: *mut c_void) -> i32 {
    let Some(runtime) = (unsafe { runtime.cast::<Arc<Runtime>>().as_ref() }) else {
        return -1;
    };
    unsafe { crate::ffi::server_enable_async(server, Arc::clone(runtime)) }
}

unsafe extern "C" fn peer_observe(peer: *mut c_void, output: *mut IaxPeerObservation) -> i32 {
    // Validate only the advertised prefix before constructing/writing a full record.
    if output.is_null()
        || unsafe { output.cast::<u32>().read() } < size_of::<IaxPeerObservation>() as u32
        || unsafe { output.cast::<u32>().add(1).read() } != 1
    {
        return -1;
    }
    let Some(peer) = (unsafe { peer.cast::<IaxPeer>().as_ref() }) else {
        return -1;
    };
    match peer.observe() {
        Ok(observation) => {
            unsafe {
                output.write(observation);
            }
            0
        }
        Err(_) => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_creation_failure_clears_output_without_publishing_an_owner() {
        let mut output = ptr::dangling_mut::<c_void>();
        assert_eq!(
            publish_runtime(
                &mut output,
                Err(std::io::Error::other("thread creation failed"))
            ),
            -1
        );
        assert!(output.is_null());
    }
}
