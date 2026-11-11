//! Optional server ABI2 tails for copied configured provider identity.

use super::*;
use crate::provider::{
    AccountConfig, AccountError, DialRequest, MAX_ACCOUNTS, ProviderCallMetadata,
    RegistrationRequest,
};

/// Borrowed UTF-8 byte span, without a terminating NUL. No pointer is retained.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct rptadv_iax2_bytes_v1 {
    /// Pointer to exactly length readable bytes; NULL only when length is zero.
    pub data: *const u8,
    /// Readable byte count.
    pub length: usize,
}
impl rptadv_iax2_bytes_v1 {
    fn view(value: &str) -> Self {
        Self {
            data: value.as_ptr(),
            length: value.len(),
        }
    }
    unsafe fn copy(self, maximum: usize) -> Option<String> {
        if self.length > maximum {
            return None;
        }
        unsafe { utf8(self.data, self.length) }.map(str::to_owned)
    }
}

/// Fixed-width address record. Family0 means absent;4/6 mean IPv4/IPv6.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct rptadv_iax2_endpoint_v1 {
    /// Address family0,4 or6, independent of platform AF_* constants.
    pub family: u16,
    /// Host-order UDP port.
    pub port: u16,
    /// Raw network-order IPv4 first4 octets or IPv6 all16 octets.
    pub address: [u8; 16],
    /// IPv6 flow information, otherwise zero.
    pub flowinfo: u32,
    /// IPv6 interface scope, otherwise zero.
    pub scope_id: u32,
}
impl From<SocketAddr> for rptadv_iax2_endpoint_v1 {
    fn from(value: SocketAddr) -> Self {
        let mut endpoint = Self {
            port: value.port(),
            ..Self::default()
        };
        match value {
            SocketAddr::V4(value) => {
                endpoint.family = 4;
                endpoint.address[..4].copy_from_slice(&value.ip().octets());
            }
            SocketAddr::V6(value) => {
                endpoint.family = 6;
                endpoint.address = value.ip().octets();
                endpoint.flowinfo = value.flowinfo();
                endpoint.scope_id = value.scope_id();
            }
        }
        endpoint
    }
}

/// ABI1 copied configuration record. Arrays use this exact ABI1 record stride.
#[repr(C)]
pub struct rptadv_iax2_provider_account_v1 {
    /// Exact readable ABI1 record size.
    pub struct_size: u32,
    /// Exact record ABI1.
    pub abi_version: u32,
    /// Nonzero configuration generation; changed settings require a new value.
    pub generation: u64,
    /// Opaque nonempty account label, at most64 bytes.
    pub account: rptadv_iax2_bytes_v1,
    /// Configured local admission binding, at most63 bytes; need not be numeric.
    pub local_binding: rptadv_iax2_bytes_v1,
    /// Numeric resolved provider endpoint, at most64 bytes.
    pub remote_address: rptadv_iax2_bytes_v1,
    /// Nonempty provider login, at most255 bytes.
    pub username: rptadv_iax2_bytes_v1,
    /// Nonempty literal MD5 secret, at most255 bytes. Never logged or returned.
    pub secret: rptadv_iax2_bytes_v1,
    /// Nonzero total incoming authentication lifetime in milliseconds.
    pub authentication_timeout_ms: u32,
    /// Must be zero.
    pub reserved: u32,
}

/// ABI1 explicit registration/refresh/release request.
#[repr(C)]
pub struct rptadv_iax2_registration_options_v1 {
    /// Complete readable size.
    pub struct_size: u32,
    /// Exact ABI1.
    pub abi_version: u32,
    /// Exact configured account label.
    pub account: rptadv_iax2_bytes_v1,
    /// Exact configured generation.
    pub generation: u64,
    /// Nonzero requested refresh interval in seconds.
    pub refresh: u16,
    /// Zero register/refresh; one authenticated REGREL.
    pub release: u16,
    /// Nonzero total operation deadline in milliseconds.
    pub timeout_ms: u32,
}

/// Caller-sized registration result. Cleared on every failure after size validation.
#[repr(C)]
#[derive(Default)]
pub struct rptadv_iax2_registration_result_v1 {
    /// Complete readable/writable size supplied by the caller.
    pub struct_size: u32,
    /// Exact ABI1, filled by the provider.
    pub abi_version: u32,
    /// Granted interval; absent registrar REFRESH means60seconds.
    pub refresh: u16,
    /// Zero.
    pub reserved: u16,
    /// Bound listener endpoint; registration uses this socket and port.
    pub local: rptadv_iax2_endpoint_v1,
    /// Registrar-supplied apparent endpoint, or family0 when absent.
    pub apparent: rptadv_iax2_endpoint_v1,
}

/// ABI1 outgoing request selecting copied configured identity and credentials.
#[repr(C)]
pub struct rptadv_iax2_provider_dial_options_v1 {
    /// Complete readable size.
    pub struct_size: u32,
    /// Exact ABI1.
    pub abi_version: u32,
    /// Exact configured generation.
    pub generation: u64,
    /// Configured account label, at most64 bytes.
    pub account: rptadv_iax2_bytes_v1,
    /// Nonempty provider destination, at most255 bytes.
    pub destination: rptadv_iax2_bytes_v1,
    /// Optional untrusted caller number, at most255 bytes.
    pub caller_number: rptadv_iax2_bytes_v1,
    /// Optional untrusted display name, at most255 bytes.
    pub caller_name: rptadv_iax2_bytes_v1,
    /// Optional provider context, at most255 bytes.
    pub context: rptadv_iax2_bytes_v1,
    /// Nonzero total setup/answer deadline in milliseconds.
    pub timeout_ms: u32,
    /// Must be zero.
    pub reserved: u32,
}

/// ABI1 owned-value call receipt; contains no borrowed strings.
#[repr(C)]
#[derive(Default)]
pub struct rptadv_iax2_provider_call_receipt_v1 {
    /// Complete readable/writable size.
    pub struct_size: u32,
    /// Exact ABI1.
    pub abi_version: u32,
    /// Exact configured account generation.
    pub account_generation: u64,
    /// Nonzero listener-local call ownership generation.
    pub call_generation: u64,
    /// Negotiated IAX media format.
    pub format: u64,
    /// Local15-bit protocol call ID.
    pub local_call: u16,
    /// Remote15-bit protocol call ID.
    pub remote_call: u16,
    /// Zero.
    pub reserved: u32,
    /// Actual bound listener endpoint.
    pub local: rptadv_iax2_endpoint_v1,
    /// Actual resolved remote endpoint.
    pub remote: rptadv_iax2_endpoint_v1,
}
impl From<&ProviderCallMetadata> for rptadv_iax2_provider_call_receipt_v1 {
    fn from(value: &ProviderCallMetadata) -> Self {
        Self {
            struct_size: size_of::<Self>() as u32,
            abi_version: 1,
            account_generation: value.account_generation,
            call_generation: value.call_generation,
            format: value.format,
            local_call: value.local_call,
            remote_call: value.remote_call,
            reserved: 0,
            local: value.local.into(),
            remote: value.remote.into(),
        }
    }
}

/// ABI1 provider incoming metadata. All spans are borrowed only during callbacks.
#[repr(C)]
pub struct rptadv_iax2_provider_incoming_v1 {
    /// Complete readable size.
    pub struct_size: u32,
    /// Exact ABI1.
    pub abi_version: u32,
    /// Exact account/call/protocol ownership receipt.
    pub receipt: rptadv_iax2_provider_call_receipt_v1,
    /// Configured opaque account, not caller input.
    pub account: rptadv_iax2_bytes_v1,
    /// Configured local admission binding, not called-number inference.
    pub local_binding: rptadv_iax2_bytes_v1,
    /// Verified configured transport username; not mailbox authorization.
    pub username: rptadv_iax2_bytes_v1,
    /// Untrusted called number.
    pub called: rptadv_iax2_bytes_v1,
    /// Untrusted caller number, never an ASL identity.
    pub caller_number: rptadv_iax2_bytes_v1,
    /// Untrusted display name.
    pub caller_name: rptadv_iax2_bytes_v1,
    /// Untrusted context.
    pub context: rptadv_iax2_bytes_v1,
}
impl From<&ProviderCallMetadata> for rptadv_iax2_provider_incoming_v1 {
    fn from(value: &ProviderCallMetadata) -> Self {
        Self {
            struct_size: size_of::<Self>() as u32,
            abi_version: 1,
            receipt: value.into(),
            account: rptadv_iax2_bytes_v1::view(&value.account),
            local_binding: rptadv_iax2_bytes_v1::view(&value.local_binding),
            username: rptadv_iax2_bytes_v1::view(&value.username),
            called: rptadv_iax2_bytes_v1::view(&value.called),
            caller_number: rptadv_iax2_bytes_v1::view(&value.caller_number),
            caller_name: rptadv_iax2_bytes_v1::view(&value.caller_name),
            context: rptadv_iax2_bytes_v1::view(&value.context),
        }
    }
}

/// Authorize a transport-authenticated provider call; zero permits admission.
pub type RptadvIax2ProviderAuthorizeV1 =
    unsafe extern "C" fn(*mut c_void, *const rptadv_iax2_provider_incoming_v1) -> i32;
/// Zero transfers the unique established peer. Nonzero leaves provider ownership.
pub type RptadvIax2ProviderAcceptV1 =
    unsafe extern "C" fn(*mut c_void, *const rptadv_iax2_provider_incoming_v1, *mut c_void) -> i32;

/// Mixed listener poll entrypoint, with separate numeric and provider callbacks.
pub type RptadvIax2PollAccountsV1 = unsafe extern "C" fn(
    *mut c_void,
    u32,
    Option<RptadvIax2AuthorizeV1>,
    Option<RptadvIax2AcceptV1>,
    Option<RptadvIax2ProviderAuthorizeV1>,
    Option<RptadvIax2ProviderAcceptV1>,
    *mut c_void,
) -> i32;

#[repr(C)]
struct ServerPrefix {
    struct_size: u32,
    abi_version: u32,
    bind_address: *const u8,
    bind_address_length: usize,
    local_nodes: *const u8,
    local_nodes_length: usize,
    catalog: *const c_void,
}

pub(super) unsafe fn bind(
    options: *const rptadv_iax2_server_options_v2,
    output: *mut *mut c_void,
) -> i32 {
    let Some(output) = (unsafe { output.as_mut() }) else {
        return -1;
    };
    *output = ptr::null_mut();
    // Never form a new64byte reference when an old48byte caller supplied only
    // its released prefix. A partial account tail is rejected without reading it.
    let Some(prefix) = (unsafe { sized_ref(options.cast::<ServerPrefix>()) }) else {
        return -1;
    };
    if prefix.abi_version != 2
        || (prefix.struct_size as usize > size_of::<ServerPrefix>()
            && (prefix.struct_size as usize) < size_of::<rptadv_iax2_server_options_v2>())
    {
        return -1;
    }
    let accounts = if prefix.struct_size as usize >= size_of::<rptadv_iax2_server_options_v2>() {
        let options = unsafe { &*options };
        let Some(accounts) = (unsafe { copy_accounts(options.accounts, options.account_count) })
        else {
            return -1;
        };
        accounts
    } else {
        Vec::new()
    };
    let Some(catalog) = (unsafe { clone_catalog(prefix.catalog) }) else {
        return -1;
    };
    if prefix.bind_address_length > 64 || prefix.local_nodes_length > 65_535 {
        return -1;
    }
    let (Some(address), Some(nodes)) = (
        unsafe { utf8(prefix.bind_address, prefix.bind_address_length) }
            .and_then(|text| text.parse::<SocketAddr>().ok()),
        unsafe { utf8(prefix.local_nodes, prefix.local_nodes_length) },
    ) else {
        return -1;
    };
    let nodes = if nodes.is_empty() {
        Vec::new()
    } else {
        nodes.split(',').map(str::to_owned).collect()
    };
    match crate::server::InboundIaxListener::bind_accounts(
        address,
        &nodes,
        &accounts,
        Some(catalog),
    ) {
        Ok(listener) => {
            *output = Box::into_raw(Box::new(ServerHandle(Mutex::new(listener)))).cast();
            0
        }
        Err(_) => -1,
    }
}

pub(super) unsafe fn copy_accounts(
    records: *const rptadv_iax2_provider_account_v1,
    count: usize,
) -> Option<Vec<AccountConfig>> {
    if count > MAX_ACCOUNTS {
        return None;
    }
    let records = unsafe { input_slice(records, count) }?;
    let mut accounts = Vec::new();
    accounts.try_reserve(count).ok()?;
    for record in records {
        if record.struct_size as usize != size_of::<rptadv_iax2_provider_account_v1>()
            || record.abi_version != 1
            || record.reserved != 0
        {
            return None;
        }
        accounts.push(AccountConfig {
            id: unsafe { record.account.copy(64) }?,
            generation: record.generation,
            local_binding: unsafe { record.local_binding.copy(63) }?,
            remote: unsafe { record.remote_address.copy(64) }?.parse().ok()?,
            username: unsafe { record.username.copy(255) }?,
            secret: unsafe { record.secret.copy(255) }?,
            pending_auth_timeout: Duration::from_millis(u64::from(
                record.authentication_timeout_ms,
            )),
        });
    }
    Some(accounts)
}

pub(super) unsafe extern "C" fn configure_accounts(
    handle: *mut c_void,
    records: *const rptadv_iax2_provider_account_v1,
    count: usize,
) -> i32 {
    boundary(-1, || {
        let (Some(server), Some(accounts)) =
            (unsafe { handle.cast::<ServerHandle>().as_ref() }, unsafe {
                copy_accounts(records, count)
            })
        else {
            return -1;
        };
        server.0.lock().map_or(-1, |mut listener| {
            listener
                .configure_accounts(&accounts)
                .map_or_else(status, |_| 0)
        })
    })
}

pub(super) unsafe extern "C" fn register_account(
    handle: *mut c_void,
    options: *const rptadv_iax2_registration_options_v1,
    output: *mut rptadv_iax2_registration_result_v1,
) -> i32 {
    boundary(-1, || {
        if unsafe { sized_ref(output.cast_const()) }.is_none() {
            return -1;
        }
        let output = unsafe { &mut *output };
        *output = rptadv_iax2_registration_result_v1 {
            struct_size: size_of::<rptadv_iax2_registration_result_v1>() as u32,
            abi_version: 1,
            ..Default::default()
        };
        let (Some(server), Some(options)) =
            (unsafe { handle.cast::<ServerHandle>().as_ref() }, unsafe {
                sized_ref(options)
            })
        else {
            return -1;
        };
        if options.abi_version != 1 || options.release > 1 {
            return -1;
        }
        let Some(id) = (unsafe { options.account.copy(64) }) else {
            return -1;
        };
        let (mut prepared, local) = {
            let Ok(mut listener) = server.0.lock() else {
                return -1;
            };
            let prepared = match listener.prepare_registration(
                &id,
                options.generation,
                RegistrationRequest {
                    refresh: options.refresh,
                    release: options.release == 1,
                    timeout: Duration::from_millis(u64::from(options.timeout_ms)),
                },
            ) {
                Ok(prepared) => prepared,
                Err(error) => return status(error),
            };
            let Ok(local) = listener.local_addr() else {
                return -2;
            };
            (prepared, local)
        };
        match prepared.run() {
            Ok(receipt) => {
                output.refresh = receipt.refresh;
                output.local = local.into();
                output.apparent = receipt.apparent.map(Into::into).unwrap_or_default();
                0
            }
            Err(error) => status(error),
        }
    })
}

pub(super) unsafe extern "C" fn dial_provider_account(
    handle: *mut c_void,
    options: *const rptadv_iax2_provider_dial_options_v1,
    peer: *mut *mut c_void,
    receipt: *mut rptadv_iax2_provider_call_receipt_v1,
) -> i32 {
    boundary(-1, || {
        let Some(peer) = (unsafe { peer.as_mut() }) else {
            return -1;
        };
        *peer = ptr::null_mut();
        if unsafe { sized_ref(receipt.cast_const()) }.is_none() {
            return -1;
        }
        let receipt = unsafe { &mut *receipt };
        *receipt = rptadv_iax2_provider_call_receipt_v1 {
            struct_size: size_of::<rptadv_iax2_provider_call_receipt_v1>() as u32,
            abi_version: 1,
            ..Default::default()
        };
        let (Some(server), Some(options)) =
            (unsafe { handle.cast::<ServerHandle>().as_ref() }, unsafe {
                sized_ref(options)
            })
        else {
            return -1;
        };
        if options.abi_version != 1 || options.reserved != 0 {
            return -1;
        }
        let (Some(id), Some(destination), Some(caller_number), Some(caller_name), Some(context)) = (
            unsafe { options.account.copy(64) },
            unsafe { options.destination.copy(255) },
            unsafe { options.caller_number.copy(255) },
            unsafe { options.caller_name.copy(255) },
            unsafe { options.context.copy(255) },
        ) else {
            return -1;
        };
        let mut prepared = {
            let Ok(mut listener) = server.0.lock() else {
                return -1;
            };
            match listener.prepare_dial(
                &id,
                options.generation,
                DialRequest {
                    destination,
                    caller_number,
                    caller_name,
                    context,
                    timeout: Duration::from_millis(u64::from(options.timeout_ms)),
                },
            ) {
                Ok(prepared) => prepared,
                Err(error) => return status(error),
            }
        };
        match prepared.run() {
            Ok(mut call) => {
                #[cfg(test)]
                tests::publication_checkpoint(&call.metadata);
                if call.peer.ensure_provider_live().is_err() {
                    let _ = call.peer.hangup();
                    return -6;
                }
                *receipt = (&call.metadata).into();
                *peer = Box::into_raw(Box::new(call.into_peer())).cast();
                0
            }
            Err(error) => status(error),
        }
    })
}

pub(super) unsafe extern "C" fn poll_accounts(
    handle: *mut c_void,
    now: u32,
    authorize: Option<RptadvIax2AuthorizeV1>,
    accept: Option<RptadvIax2AcceptV1>,
    provider_authorize: Option<RptadvIax2ProviderAuthorizeV1>,
    provider_accept: Option<RptadvIax2ProviderAcceptV1>,
    context: *mut c_void,
) -> i32 {
    boundary(-1, || {
        let Some(server) = (unsafe { handle.cast::<ServerHandle>().as_ref() }) else {
            return -1;
        };
        let work = {
            let Ok(mut listener) = server.0.lock() else {
                return -1;
            };
            match listener.prepare_poll(now) {
                Ok(work) => work,
                Err(_) => return -1,
            }
        };
        let completed = work.run(
            |local, remote, address| {
                let Some(authorize) = authorize.filter(|_| accept.is_some()) else {
                    return false;
                };
                let source = address.ip().to_string();
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
            },
            |metadata| {
                let Some(authorize) = provider_authorize.filter(|_| provider_accept.is_some())
                else {
                    return false;
                };
                unsafe { authorize(context, &metadata.into()) == 0 }
            },
        );
        let Ok(completed) = completed else {
            return -1;
        };
        let event = {
            let Ok(mut listener) = server.0.lock() else {
                return -1;
            };
            listener
                .finish_poll(completed)
                .expect("finishing completed owned work returns an event, including retirement")
        };
        let had_datagram = !matches!(event, crate::server::ListenerEvent::None);
        match event {
            crate::server::ListenerEvent::Accepted(call) => {
                let accept = accept.expect("legacy admission requires accept callback");
                let local = call.local_node.clone();
                let remote = call.remote_node.clone();
                let source = call.remote.ip().to_string();
                let peer = Box::into_raw(Box::new(call.into_peer())).cast();
                if unsafe {
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
                } != 0
                {
                    unsafe { drop(Box::from_raw(peer.cast::<IaxPeer>())) };
                }
            }
            crate::server::ListenerEvent::Provider(mut call) => {
                let accept = provider_accept.expect("provider admission requires accept callback");
                #[cfg(test)]
                tests::publication_checkpoint(&call.metadata);
                if call.peer.ensure_provider_live().is_err() {
                    let _ = call.peer.hangup();
                    return 1;
                }
                let crate::provider::ProviderCall { metadata, peer } = *call;
                let peer = Box::into_raw(Box::new(peer)).cast();
                // Zero transfers ownership even if control retirement races the
                // callback. The transferred peer retains its actual lifetime fence.
                if unsafe { accept(context, &(&metadata).into(), peer) } != 0 {
                    // The callback declined ownership after ACCEPT/ANSWER. Use
                    // ordinary best-effort protocol cleanup before local release.
                    unsafe { destroy(peer) };
                }
            }
            _ => {}
        }
        i32::from(had_datagram)
    })
}

pub(super) fn status(error: AccountError) -> i32 {
    match error {
        AccountError::InvalidOptions => -1,
        AccountError::Network(_) => -2,
        AccountError::Timeout => -3,
        AccountError::Rejected => -4,
        AccountError::Call(error) => dial_error_code(error),
        AccountError::AsyncRequired
        | AccountError::Busy
        | AccountError::Retired
        | AccountError::Protocol => -6,
    }
}

#[cfg(test)]
#[path = "provider_ffi_tests.rs"]
mod tests;
