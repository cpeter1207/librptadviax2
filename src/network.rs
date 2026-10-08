//! Nonblocking UDP datagram I/O, separate from IAX2 packet parsing.

use crate::ingress::{MAX_DATAGRAM_SIZE, PeerIngressRouter, PeerIngressRouterError};
use crate::protocol::{parse_full_frame_packet, parse_mini_frame};
use std::net::{SocketAddr, UdpSocket};
use std::{
    io::{self, ErrorKind},
    sync::Arc,
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
    socket: Arc<UdpSocket>,
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

    pub(crate) fn shared_socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Try to receive one datagram; `None` means the socket would block.
    pub fn try_receive(&self, buffer: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
        receive_result(self.socket.recv_from(buffer))
    }

    /// Receive one UDP payload and enqueue it for its registered peer owner.
    pub fn try_receive_routed(
        &self,
        router: &mut PeerIngressRouter,
        buffer: &mut [u8; MAX_DATAGRAM_SIZE],
    ) -> Result<Option<SocketAddr>, NetworkIngressError> {
        route_received(self.try_receive(buffer), router, buffer)
    }
}

fn route_received(
    received: io::Result<Option<(usize, SocketAddr)>>,
    router: &mut PeerIngressRouter,
    buffer: &[u8; MAX_DATAGRAM_SIZE],
) -> Result<Option<SocketAddr>, NetworkIngressError> {
    let Some((length, remote)) = received.map_err(NetworkIngressError::Io)? else {
        return Ok(None);
    };
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
        socket: Arc::new(socket),
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
