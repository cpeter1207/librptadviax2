//! IAX2 protocol and transport components for the standalone controller.
#![deny(missing_docs)]

pub mod authentication;
pub mod call_token;
pub mod client;
pub mod codec;
pub mod ffi;
pub mod information_elements;
pub mod ingress;
#[cfg(test)]
mod ingress_tests;
pub mod media;
pub mod network;
pub mod protocol;
pub mod server;
pub mod session;
pub mod text;

#[cfg(test)]
mod call_token_server_tests;
#[cfg(test)]
mod client_answer_tests;
#[cfg(test)]
mod client_tests;
#[cfg(test)]
mod inbound_tests;
