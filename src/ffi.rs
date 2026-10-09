//! Versioned C boundary for the standalone ULAW IAX2 client.

use crate::client::{DialError, DialOptions, IaxPeer, IaxPeerEvent, dial_ulaw};
use std::{
    ffi::c_void,
    mem::size_of,
    net::SocketAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice, str,
    time::Duration,
};

/// Exact C-client ABI revision.
pub const RPTADV_IAX2_CLIENT_ABI_VERSION: u32 = 1;
/// Fixed-width capability identifier returned by the C descriptor.
pub const RPTADV_IAX2_CLIENT_CAPABILITY: [u8; 16] = *b"rptadv.iax2.v1\0\0";
/// Exact C-server ABI revision.
pub const RPTADV_IAX2_SERVER_ABI_VERSION: u32 = 1;
/// Fixed-width capability identifier returned by the inbound server descriptor.
pub const RPTADV_IAX2_SERVER_CAPABILITY: [u8; 16] = *b"rptadv.iaxsrv1\0\0";

/// No event is available from a nonblocking poll.
pub const RPTADV_IAX2_EVENT_NONE: u32 = 0;
/// A decoded mono F32 ULAW media block is available.
pub const RPTADV_IAX2_EVENT_AUDIO: u32 = 1;
/// A reliable ASL text message is available.
pub const RPTADV_IAX2_EVENT_TEXT: u32 = 2;
/// The remote peer has ended the call.
pub const RPTADV_IAX2_EVENT_HANGUP: u32 = 3;
/// One acknowledged remote DTMF digit is available in the text output buffer.
pub const RPTADV_IAX2_EVENT_DIGIT: u32 = 4;
/// The remote radio asserted receive; event length is zero.
pub const RPTADV_IAX2_EVENT_RADIO_KEY: u32 = 5;
/// The remote radio released receive; event length is zero.
pub const RPTADV_IAX2_EVENT_RADIO_UNKEY: u32 = 6;

/// Caller-owned parameters for one outbound ULAW IAX2 call.
#[repr(C)]
pub struct rptadv_iax2_dial_options_v1 {
    /// Complete readable structure size.
    pub struct_size: u32,
    /// Exact [`RPTADV_IAX2_CLIENT_ABI_VERSION`].
    pub abi_version: u32,
    /// Numeric `IP:port` or `[IPv6]:port`; name resolution belongs to the caller.
    pub remote_address: *const u8,
    /// Remote-address byte count.
    pub remote_address_length: usize,
    /// Locally unique nonzero 15-bit IAX call number.
    pub local_call_number: u16,
    /// Reserved; initialize to zero.
    pub reserved: u16,
    /// Local node number as UTF-8 decimal digits.
    pub local_node: *const u8,
    /// Local-node byte count.
    pub local_node_length: usize,
    /// Requested remote node number as UTF-8 decimal digits.
    pub remote_node: *const u8,
    /// Remote-node byte count.
    pub remote_node_length: usize,
    /// Local IAX secret as UTF-8; it is used only for MD5 challenge response.
    pub secret: *const u8,
    /// Secret byte count.
    pub secret_length: usize,
    /// Maximum call-setup time in milliseconds; zero is invalid.
    pub timeout_ms: u32,
}

/// Versioned function table for one-owner outbound ULAW peer sessions.
#[repr(C)]
pub struct rptadv_iax2_client_descriptor_v1 {
    /// Complete readable descriptor size.
    pub struct_size: u32,
    /// Exact [`RPTADV_IAX2_CLIENT_ABI_VERSION`].
    pub abi_version: u32,
    /// NUL-padded [`RPTADV_IAX2_CLIENT_CAPABILITY`].
    pub capability: [u8; 16],
    /// Establish one outbound call. Success returns a uniquely owned peer handle.
    pub dial: Option<
        unsafe extern "C" fn(
            options: *const rptadv_iax2_dial_options_v1,
            peer: *mut *mut c_void,
        ) -> i32,
    >,
    /// Return the negotiated peer's linear PCM rate in samples per second.
    pub sample_rate_hz: Option<unsafe extern "C" fn(peer: *const c_void) -> u32>,
    /// Encode and send one mono F32 ULAW media block.
    pub send_audio: Option<
        unsafe extern "C" fn(peer: *mut c_void, samples: *const f32, sample_count: usize) -> i32,
    >,
    /// Send one ASL text payload.
    pub send_text:
        Option<unsafe extern "C" fn(peer: *mut c_void, bytes: *const u8, length: usize) -> i32>,
    /// Poll one datagram and write audio/text/digit into caller-provided buffers.
    pub poll: Option<
        unsafe extern "C" fn(
            peer: *mut c_void,
            samples: *mut f32,
            sample_capacity: usize,
            text: *mut u8,
            text_capacity: usize,
            event_kind: *mut u32,
            event_length: *mut usize,
        ) -> i32,
    >,
    /// Send HANGUP and end the local call state.
    pub hangup: Option<unsafe extern "C" fn(peer: *mut c_void) -> i32>,
    /// Send best-effort HANGUP and destroy one uniquely owned peer handle.
    pub destroy: Option<unsafe extern "C" fn(peer: *mut c_void)>,
    /// Send one completed DTMF digit.
    pub send_digit: Option<unsafe extern "C" fn(peer: *mut c_void, digit: u8) -> i32>,
}

/// Caller-owned options for a single UDP endpoint serving configured local nodes.
#[repr(C)]
pub struct rptadv_iax2_server_options_v1 {
    /// Complete readable structure size.
    pub struct_size: u32,
    /// Exact [`RPTADV_IAX2_SERVER_ABI_VERSION`].
    pub abi_version: u32,
    /// Numeric IPv4/IPv6 address and port to bind.
    pub bind_address: *const u8,
    /// Bind-address byte count.
    pub bind_address_length: usize,
    /// Comma-separated decimal local node numbers served on this socket.
    pub local_nodes: *const u8,
    /// Local-node list byte count.
    pub local_nodes_length: usize,
}

/// Product callback allowing one authenticated inbound node/source pair.
pub type RptadvIax2AuthorizeV1 = unsafe extern "C" fn(
    context: *mut c_void,
    local: *const u8,
    local_length: usize,
    remote: *const u8,
    remote_length: usize,
    source: *const u8,
    source_length: usize,
) -> i32;

/// Product callback accepting ownership of an established peer handle on success.
pub type RptadvIax2AcceptV1 = unsafe extern "C" fn(
    context: *mut c_void,
    local: *const u8,
    local_length: usize,
    remote: *const u8,
    remote_length: usize,
    source: *const u8,
    source_length: usize,
    peer: *mut c_void,
) -> i32;

/// Versioned inbound UDP listener descriptor, separate from protocol session ownership.
#[repr(C)]
pub struct rptadv_iax2_server_descriptor_v1 {
    /// Complete readable descriptor size.
    pub struct_size: u32,
    /// Exact [`RPTADV_IAX2_SERVER_ABI_VERSION`].
    pub abi_version: u32,
    /// NUL-padded [`RPTADV_IAX2_SERVER_CAPABILITY`].
    pub capability: [u8; 16],
    /// Bind one endpoint and return a uniquely owned listener.
    pub bind:
        Option<unsafe extern "C" fn(*const rptadv_iax2_server_options_v1, *mut *mut c_void) -> i32>,
    /// Poll at most one datagram; product callbacks run synchronously on this control owner.
    pub poll: Option<
        unsafe extern "C" fn(
            *mut c_void,
            u32,
            Option<RptadvIax2AuthorizeV1>,
            Option<RptadvIax2AcceptV1>,
            *mut c_void,
        ) -> i32,
    >,
    /// Replace the local-node set without dropping established calls.
    pub set_local_nodes: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
    /// Destroy one uniquely owned listener.
    pub destroy: Option<unsafe extern "C" fn(*mut c_void)>,
}

const DESCRIPTOR: rptadv_iax2_client_descriptor_v1 = rptadv_iax2_client_descriptor_v1 {
    struct_size: size_of::<rptadv_iax2_client_descriptor_v1>() as u32,
    abi_version: RPTADV_IAX2_CLIENT_ABI_VERSION,
    capability: RPTADV_IAX2_CLIENT_CAPABILITY,
    dial: Some(dial),
    sample_rate_hz: Some(sample_rate_hz),
    send_audio: Some(send_audio),
    send_text: Some(send_text),
    poll: Some(poll),
    hangup: Some(hangup),
    destroy: Some(destroy),
    send_digit: Some(send_digit),
};

const SERVER_DESCRIPTOR: rptadv_iax2_server_descriptor_v1 = rptadv_iax2_server_descriptor_v1 {
    struct_size: size_of::<rptadv_iax2_server_descriptor_v1>() as u32,
    abi_version: RPTADV_IAX2_SERVER_ABI_VERSION,
    capability: RPTADV_IAX2_SERVER_CAPABILITY,
    bind: Some(server_bind),
    poll: Some(server_poll),
    set_local_nodes: Some(server_set_local_nodes),
    destroy: Some(server_destroy),
};

#[cfg(test)]
#[path = "ffi_tests.rs"]
mod tests;

/// Return the immutable process-lifetime ULAW client descriptor.
#[unsafe(no_mangle)]
pub extern "C" fn rptadv_iax2_client_descriptor_v1() -> *const rptadv_iax2_client_descriptor_v1 {
    &DESCRIPTOR
}

/// Return the immutable process-lifetime inbound UDP listener descriptor.
#[unsafe(no_mangle)]
pub extern "C" fn rptadv_iax2_server_descriptor_v1() -> *const rptadv_iax2_server_descriptor_v1 {
    &SERVER_DESCRIPTOR
}

struct ServerHandle(crate::server::InboundIaxListener);

unsafe extern "C" fn server_bind(
    options: *const rptadv_iax2_server_options_v1,
    output: *mut *mut c_void,
) -> i32 {
    boundary(-1, || {
        let (Some(options), Some(output)) =
            (unsafe { options.as_ref() }, unsafe { output.as_mut() })
        else {
            return -1;
        };
        *output = ptr::null_mut();
        if options.abi_version != RPTADV_IAX2_SERVER_ABI_VERSION
            || options.struct_size < size_of::<rptadv_iax2_server_options_v1>() as u32
        {
            return -1;
        }
        let (Some(address), Some(nodes)) = (
            unsafe { utf8(options.bind_address, options.bind_address_length) }
                .and_then(|text| text.parse::<SocketAddr>().ok()),
            unsafe { utf8(options.local_nodes, options.local_nodes_length) },
        ) else {
            return -1;
        };
        let local_nodes = nodes.split(',').map(str::to_owned).collect::<Vec<_>>();
        match crate::server::InboundIaxListener::bind_many(address, &local_nodes) {
            Ok(listener) => {
                *output = Box::into_raw(Box::new(ServerHandle(listener))).cast();
                0
            }
            Err(_) => -1,
        }
    })
}

unsafe extern "C" fn server_poll(
    handle: *mut c_void,
    now_seconds: u32,
    authorize: Option<RptadvIax2AuthorizeV1>,
    accept: Option<RptadvIax2AcceptV1>,
    context: *mut c_void,
) -> i32 {
    boundary(-1, || {
        let Some(server) = (unsafe { handle.cast::<ServerHandle>().as_mut() }) else {
            return -1;
        };
        let accepted = accept.is_some();
        let event = server
            .0
            .poll_with_identity(now_seconds, |local, remote, remote_address| {
                let Some(authorize) = authorize.filter(|_| accepted) else {
                    return false;
                };
                let source = remote_address.ip().to_string();
                unsafe {
                    authorize(
                        context,
                        local.as_ptr(),
                        local.len(),
                        remote.as_ptr(),
                        remote.len(),
                        source.as_ptr(),
                        source.len(),
                    ) == 0
                }
            });
        let Ok(event) = event else {
            return -1;
        };
        let had_datagram = !matches!(&event, crate::server::ListenerEvent::None);
        if let crate::server::ListenerEvent::Accepted(peer) = event {
            let accept = accept.expect("admission requires an accept callback");
            let local = peer.local_node.clone();
            let remote = peer.remote_node.clone();
            let source = peer.remote.ip().to_string();
            let peer = Box::into_raw(Box::new((*peer).into_peer())).cast();
            let result = unsafe {
                accept(
                    context,
                    local.as_ptr(),
                    local.len(),
                    remote.as_ptr(),
                    remote.len(),
                    source.as_ptr(),
                    source.len(),
                    peer,
                )
            };
            if result != 0 {
                unsafe { drop(Box::from_raw(peer.cast::<IaxPeer>())) };
            }
        }
        i32::from(had_datagram)
    })
}

unsafe extern "C" fn server_destroy(handle: *mut c_void) {
    boundary((), || {
        if !handle.is_null() {
            unsafe { drop(Box::from_raw(handle.cast::<ServerHandle>())) };
        }
    });
}

unsafe extern "C" fn server_set_local_nodes(
    handle: *mut c_void,
    nodes: *const u8,
    length: usize,
) -> i32 {
    boundary(-1, || {
        let (Some(server), Some(nodes)) =
            (unsafe { handle.cast::<ServerHandle>().as_mut() }, unsafe {
                utf8(nodes, length)
            })
        else {
            return -1;
        };
        let nodes = nodes.split(',').map(str::to_owned).collect::<Vec<_>>();
        server.0.set_local_nodes(&nodes).map_or_else(|_| -1, |_| 0)
    })
}

unsafe extern "C" fn dial(
    options: *const rptadv_iax2_dial_options_v1,
    output: *mut *mut c_void,
) -> i32 {
    boundary(-1, || {
        let Some(output) = (unsafe { output.as_mut() }) else {
            return -1;
        };
        *output = ptr::null_mut();
        let Some(options) = (unsafe { options.as_ref() }) else {
            return -1;
        };
        if options.abi_version != RPTADV_IAX2_CLIENT_ABI_VERSION
            || options.struct_size < size_of::<rptadv_iax2_dial_options_v1>() as u32
            || options.reserved != 0
        {
            return -1;
        }
        let Some(remote) = (unsafe { utf8(options.remote_address, options.remote_address_length) })
            .and_then(|value| value.parse::<SocketAddr>().ok())
        else {
            return -1;
        };
        let Some(local_node) = (unsafe { utf8(options.local_node, options.local_node_length) })
        else {
            return -1;
        };
        let Some(remote_node) = (unsafe { utf8(options.remote_node, options.remote_node_length) })
        else {
            return -1;
        };
        let Some(secret) = (unsafe { utf8(options.secret, options.secret_length) }) else {
            return -1;
        };
        match dial_ulaw(DialOptions {
            remote,
            local_call: options.local_call_number,
            local_node,
            remote_node,
            secret,
            timeout: Duration::from_millis(u64::from(options.timeout_ms)),
        }) {
            Ok(peer) => {
                *output = Box::into_raw(Box::new(peer)).cast();
                0
            }
            Err(error) => dial_error_code(error),
        }
    })
}

unsafe extern "C" fn send_audio(peer: *mut c_void, samples: *const f32, count: usize) -> i32 {
    boundary(-1, || {
        let (Some(peer), Some(samples)) = (unsafe { peer.cast::<IaxPeer>().as_mut() }, unsafe {
            input_slice(samples, count)
        }) else {
            return -1;
        };
        peer.send_ulaw(samples, peer.elapsed_ms())
            .map_or_else(|_| -1, |_| 0)
    })
}

unsafe extern "C" fn sample_rate_hz(peer: *const c_void) -> u32 {
    boundary(0, || {
        unsafe { peer.cast::<IaxPeer>().as_ref() }.map_or(0, IaxPeer::sample_rate_hz)
    })
}

unsafe extern "C" fn send_text(peer: *mut c_void, bytes: *const u8, length: usize) -> i32 {
    boundary(-1, || {
        let (Some(peer), Some(bytes)) = (unsafe { peer.cast::<IaxPeer>().as_mut() }, unsafe {
            input_slice(bytes, length)
        }) else {
            return -1;
        };
        peer.send_text(bytes).map_or_else(|_| -1, |_| 0)
    })
}

unsafe extern "C" fn send_digit(peer: *mut c_void, digit: u8) -> i32 {
    boundary(-1, || {
        let Some(peer) = (unsafe { peer.cast::<IaxPeer>().as_mut() }) else {
            return -1;
        };
        peer.send_dtmf(digit).map_or_else(|_| -1, |_| 0)
    })
}

unsafe extern "C" fn poll(
    peer: *mut c_void,
    samples: *mut f32,
    sample_capacity: usize,
    text: *mut u8,
    text_capacity: usize,
    event_kind: *mut u32,
    event_length: *mut usize,
) -> i32 {
    boundary(-1, || {
        let (Some(peer), Some(event_kind), Some(event_length)) = (
            unsafe { peer.cast::<IaxPeer>().as_mut() },
            unsafe { event_kind.as_mut() },
            unsafe { event_length.as_mut() },
        ) else {
            return -1;
        };
        *event_kind = RPTADV_IAX2_EVENT_NONE;
        *event_length = 0;
        let (Some(samples), Some(text)) =
            (unsafe { output_slice(samples, sample_capacity) }, unsafe {
                output_slice(text, text_capacity)
            })
        else {
            return -1;
        };
        match peer.poll_event(samples, text) {
            Ok(IaxPeerEvent::None) => 0,
            Ok(IaxPeerEvent::Audio(count)) => {
                *event_kind = RPTADV_IAX2_EVENT_AUDIO;
                *event_length = count;
                0
            }
            Ok(IaxPeerEvent::Text(count)) => {
                *event_kind = RPTADV_IAX2_EVENT_TEXT;
                *event_length = count;
                0
            }
            Ok(IaxPeerEvent::Digit(digit)) => {
                *text
                    .first_mut()
                    .expect("IAX peer only returns digits when text storage is available") = digit;
                *event_kind = RPTADV_IAX2_EVENT_DIGIT;
                *event_length = 1;
                0
            }
            Ok(IaxPeerEvent::Hangup) => {
                *event_kind = RPTADV_IAX2_EVENT_HANGUP;
                0
            }
            Ok(IaxPeerEvent::RadioKey) => {
                *event_kind = RPTADV_IAX2_EVENT_RADIO_KEY;
                0
            }
            Ok(IaxPeerEvent::RadioUnkey) => {
                *event_kind = RPTADV_IAX2_EVENT_RADIO_UNKEY;
                0
            }
            Err(_) => -1,
        }
    })
}

unsafe extern "C" fn hangup(peer: *mut c_void) -> i32 {
    boundary(-1, || {
        let Some(peer) = (unsafe { peer.cast::<IaxPeer>().as_mut() }) else {
            return -1;
        };
        peer.hangup().map_or_else(|_| -1, |_| 0)
    })
}

unsafe extern "C" fn destroy(peer: *mut c_void) {
    boundary((), || {
        if !peer.is_null() {
            let mut peer = unsafe { Box::from_raw(peer.cast::<IaxPeer>()) };
            let _ = peer.hangup();
            drop(peer);
        }
    });
}

fn dial_error_code(error: DialError) -> i32 {
    match error {
        DialError::InvalidOptions => -1,
        DialError::Network(_) => -2,
        DialError::Timeout => -3,
        DialError::Rejected => -4,
        DialError::UnsupportedFormat(_) => -5,
        DialError::Hangup
        | DialError::EarlyEventsFull
        | DialError::ReliableWindowFull
        | DialError::Protocol(_)
        | DialError::Voice(_)
        | DialError::Encode(_)
        | DialError::Decode(_) => -6,
    }
}

unsafe fn utf8<'a>(pointer: *const u8, length: usize) -> Option<&'a str> {
    let bytes = unsafe { input_slice(pointer, length) }?;
    str::from_utf8(bytes).ok()
}

unsafe fn input_slice<'a, T>(pointer: *const T, length: usize) -> Option<&'a [T]> {
    if pointer.is_null() {
        return (length == 0).then_some(&[]);
    }
    Some(unsafe { slice::from_raw_parts(pointer, length) })
}

unsafe fn output_slice<'a, T>(pointer: *mut T, length: usize) -> Option<&'a mut [T]> {
    if pointer.is_null() {
        return (length == 0).then_some(&mut []);
    }
    Some(unsafe { slice::from_raw_parts_mut(pointer, length) })
}

fn boundary<T>(fallback: T, operation: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(fallback)
}
