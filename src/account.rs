//! Ordinary provider account identity, separate from numeric AllStarLink nodes.

use crate::{
    client::{CallRequest, DialError, IaxPeer, dial_new},
    formats::FormatCatalog,
    information_elements::InformationElement,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};

/// Borrowed inputs for a provider call; no destination-number policy is imposed.
/// Identity fields enter NEW; the secret is borrowed only for challenges during
/// this synchronous, off-audio call. No input reference survives setup.
pub struct DialOptions<'a> {
    /// Resolved provider endpoint; DNS and account selection belong to the host.
    pub remote: SocketAddr,
    /// Unique nonzero 15-bit call number.
    pub local_call: u16,
    /// Provider account username, independent of caller identity.
    pub username: &'a str,
    /// Provider destination, including short numbers and telephone-menu symbols.
    pub destination: &'a str,
    /// Optional caller number, not an authenticated node identity.
    pub caller_number: &'a str,
    /// Optional display name, not an authenticated node identity.
    pub caller_name: &'a str,
    /// Optional provider dial context.
    pub context: &'a str,
    /// Challenge-response secret; never included in NEW or diagnostics.
    pub secret: &'a str,
    /// Nonzero total setup and answer timeout.
    pub timeout: Duration,
}

/// Establish a provider call using the existing codec, session and media owner.
pub fn dial(options: DialOptions<'_>, catalog: Arc<FormatCatalog>) -> Result<IaxPeer, DialError> {
    if options.username.is_empty()
        || options.destination.is_empty()
        || [
            options.username,
            options.destination,
            options.caller_number,
            options.caller_name,
            options.context,
        ]
        .iter()
        .any(|value| value.len() > 255 || value.chars().any(char::is_control))
    {
        return Err(DialError::InvalidOptions);
    }
    let version = 2_u16.to_be_bytes();
    let elements = [
        InformationElement {
            kind: 6,
            data: options.username.as_bytes(),
        },
        InformationElement {
            kind: 1,
            data: options.destination.as_bytes(),
        },
        InformationElement {
            kind: 2,
            data: options.caller_number.as_bytes(),
        },
        InformationElement {
            kind: 4,
            data: options.caller_name.as_bytes(),
        },
        InformationElement {
            kind: 5,
            data: options.context.as_bytes(),
        },
        InformationElement {
            kind: 11,
            data: &version,
        },
    ];
    dial_new(
        CallRequest {
            remote: options.remote,
            local_call: options.local_call,
            secret: options.secret,
            timeout: options.timeout,
        },
        &elements,
        Some(catalog),
    )
}

#[cfg(test)]
mod tests;
