//! Nonblocking UDP datagram I/O, separate from IAX2 packet parsing.

use crate::ingress::{MAX_DATAGRAM_SIZE, PeerIngressRouter, PeerIngressRouterError};
use crate::protocol::{parse_full_frame_packet, parse_mini_frame};
use std::net::{SocketAddr, UdpSocket};
use std::{
    io::{self, ErrorKind},
    sync::{Arc, OnceLock},
};

/// Failure while receiving a datagram for peer-owner dispatch.
#[derive(Debug)]
pub enum NetworkIngressError {
    /// UDP receive failed.
    Io(io::Error),
    /// The source was unknown or its bounded ingress queue rejected the packet.
    Route(PeerIngressRouterError),
    /// A valid datagram has no registered call owner and remains in the caller's buffer for
    /// serialized inbound admission (for example, validating an initial `NEW`).
    Unrouted {
        /// UDP source address for the initial or otherwise unknown call.
        remote: SocketAddr,
        /// Number of bytes retained in the caller's receive buffer.
        length: usize,
    },
    /// A packet marked as IAX2 did not contain a valid frame header.
    MalformedPacket,
}

impl From<io::Error> for NetworkIngressError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// A nonblocking UDP endpoint for one network-owner thread.
pub struct UdpEndpoint {
    socket: Arc<SharedSocket>,
}

/// One OS socket and one readiness registration, shared by listener and peers.
pub(crate) struct SharedSocket {
    socket: UdpSocket,
    registered: OnceLock<Arc<tokio::net::UdpSocket>>,
}

impl SharedSocket {
    pub(crate) fn new(socket: UdpSocket) -> Self {
        Self {
            socket,
            registered: OnceLock::new(),
        }
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub(crate) fn register(
        &self,
        runtime: &tokio::runtime::Handle,
    ) -> io::Result<Arc<tokio::net::UdpSocket>> {
        if let Some(socket) = self.registered.get() {
            return Ok(Arc::clone(socket));
        }
        let _entered = runtime.enter();
        let socket = self.socket.try_clone()?;
        socket.set_nonblocking(true)?;
        let registered = Arc::new(tokio::net::UdpSocket::from_std(socket)?);
        // Peers can attach concurrently; retain only the winning registration.
        let _ = self.registered.set(registered);
        Ok(Arc::clone(
            self.registered.get().expect("registered socket"),
        ))
    }

    pub(crate) fn send_to(&self, payload: &[u8], remote: SocketAddr) -> io::Result<usize> {
        match self.registered.get() {
            Some(socket) => socket.try_send_to(payload, remote),
            None => self.socket.send_to(payload, remote),
        }
    }

    pub(crate) fn registered(&self) -> Option<Arc<tokio::net::UdpSocket>> {
        self.registered.get().map(Arc::clone)
    }
}

impl UdpEndpoint {
    /// Bind an endpoint to a concrete local address.
    pub fn bind(local: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(local)?;
        configure_socket(socket, |socket| socket.set_nonblocking(true))
    }

    /// Return the address selected by the operating system.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Send one datagram to a previously resolved peer address.
    pub fn send_to(&self, payload: &[u8], remote: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(payload, remote)
    }

    pub(crate) fn shared_socket(&self) -> Arc<SharedSocket> {
        Arc::clone(&self.socket)
    }

    /// Try to receive one datagram; `None` means the socket would block. Protocol
    /// parsers provide MAX_DATAGRAM_SIZE+1 bytes to distinguish guard overflow.
    pub fn try_receive(&self, buffer: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
        receive_result(self.socket.socket.recv_from(buffer))
    }

    /// Receive one UDP payload and enqueue it for its registered peer owner.
    pub fn try_receive_routed(
        &self,
        router: &mut PeerIngressRouter,
        buffer: &mut [u8; MAX_DATAGRAM_SIZE + 1],
    ) -> Result<Option<SocketAddr>, NetworkIngressError> {
        route_received(self.try_receive(buffer), router, buffer)
    }
}

fn route_received(
    received: io::Result<Option<(usize, SocketAddr)>>,
    router: &mut PeerIngressRouter,
    buffer: &[u8],
) -> Result<Option<SocketAddr>, NetworkIngressError> {
    let Some((length, remote)) = received.map_err(NetworkIngressError::Io)? else {
        return Ok(None);
    };
    if length > MAX_DATAGRAM_SIZE || length > buffer.len() {
        return Err(NetworkIngressError::MalformedPacket);
    }
    let payload = &buffer[..length];
    if payload.first().is_some_and(|first| first & 0x80 != 0) {
        let frame =
            parse_full_frame_packet(payload).map_err(|_| NetworkIngressError::MalformedPacket)?;
        if let Err(error) = router.route_call(
            remote,
            frame.header.destination_call_number,
            frame.header.source_call_number,
            payload,
        ) {
            return Err(unrouted_or_route(error, remote, length));
        }
    } else if length >= 4 {
        let frame = parse_mini_frame(payload).map_err(|_| NetworkIngressError::MalformedPacket)?;
        if let Err(error) =
            router.route_remote_call(remote, frame.header.source_call_number, payload)
        {
            return Err(unrouted_or_route(error, remote, length));
        }
    } else if let Err(error) = router.route(remote, payload) {
        return Err(unrouted_or_route(error, remote, length));
    }
    Ok(Some(remote))
}

fn unrouted_or_route(
    error: PeerIngressRouterError,
    remote: SocketAddr,
    length: usize,
) -> NetworkIngressError {
    if error == PeerIngressRouterError::UnknownPeer {
        NetworkIngressError::Unrouted { remote, length }
    } else {
        NetworkIngressError::Route(error)
    }
}

fn configure_socket(
    socket: UdpSocket,
    configure_nonblocking: impl FnOnce(&UdpSocket) -> io::Result<()>,
) -> io::Result<UdpEndpoint> {
    configure_nonblocking(&socket)?;
    Ok(UdpEndpoint {
        socket: Arc::new(SharedSocket::new(socket)),
    })
}

fn receive_result(
    result: io::Result<(usize, SocketAddr)>,
) -> io::Result<Option<(usize, SocketAddr)>> {
    match result {
        Ok(datagram) => Ok(Some(datagram)),
        Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "network_tests.rs"]
mod tests;
