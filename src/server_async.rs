//! One socket/router owner; control policy consumes a separate bounded NEW queue.

use super::{ListenerIngressStats, route_established};
use crate::{
    ingress::{
        InboundDatagram, IngressConsumer, MAX_DATAGRAM_SIZE, PeerIngressRouter,
        PeerIngressRouterError, producer_ingress,
    },
    protocol::{IaxCommand, decode_iax_command, parse_full_frame_packet},
};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};
use tokio::{
    net::UdpSocket,
    runtime::Runtime,
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};

enum RouteCommand {
    Register {
        remote: SocketAddr,
        local_call: u16,
        remote_call: u16,
        generation: u64,
        reply: oneshot::Sender<Result<IngressConsumer, PeerIngressRouterError>>,
    },
    Unregister {
        remote: SocketAddr,
        local_call: u16,
        remote_call: u16,
        generation: u64,
    },
}

pub(super) struct ListenerIngress {
    runtime: Arc<Runtime>,
    commands: mpsc::Sender<RouteCommand>,
    admission: IngressConsumer,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
    active_routes: Arc<AtomicUsize>,
}

impl ListenerIngress {
    pub(super) fn start(
        runtime: Arc<Runtime>,
        socket: UdpSocket,
        mut router: PeerIngressRouter,
    ) -> Self {
        let (commands, mut updates) = mpsc::channel(64);
        let (mut pending, admission) = producer_ingress(64, 0).expect("nonzero NEW queue capacity");
        let (stop, mut stopping) = watch::channel(false);
        let active_routes = Arc::new(AtomicUsize::new(router.route_count()));
        let route_count = active_routes.clone();
        let task = runtime.spawn(async move {
            let mut bytes = [0; MAX_DATAGRAM_SIZE + 1];
            while !*stopping.borrow() {
                tokio::select! {
                    _ = stopping.changed() => break,
                    // The owner retains this sender until its task is joined.
                    Some(command) = updates.recv() => match command {
                        RouteCommand::Register { remote, local_call, remote_call, generation, reply } => {
                            let registered = router.register_call(remote, local_call, remote_call, generation);
                            route_count.store(router.route_count(), Ordering::Relaxed);
                            let _ = reply.send(registered);
                        }
                        RouteCommand::Unregister { remote, local_call, remote_call, generation } => {
                            router.unregister_call(remote, local_call, remote_call, generation);
                            route_count.store(router.route_count(), Ordering::Relaxed);
                        }
                    },
                    received = crate::async_driver::receive_datagram(&socket, &mut bytes) => {
                        let arrived_at = Instant::now();
                        let Ok((length, remote)) = received else { break; };
                        if length > MAX_DATAGRAM_SIZE { continue; }
                        let packet = &bytes[..length];
                        if route_established(&mut router, remote, packet, arrived_at) {
                            route_count.store(router.route_count(), Ordering::Relaxed);
                            continue;
                        }
                        if let Ok(frame) = parse_full_frame_packet(packet) {
                            if frame.header.destination_call_number == 0
                                && decode_iax_command(&frame.header) == Ok(Some(IaxCommand::New)) {
                                // Queue overflow drops only new admission work, never an established peer.
                                let _ = pending.try_push_at(remote, packet, arrived_at);
                            }
                        }
                    }
                }
            }
            router.fail_all();
            route_count.store(0, Ordering::Relaxed);
            pending.fail();
        });
        Self {
            runtime,
            commands,
            admission,
            stop,
            task,
            active_routes,
        }
    }

    pub(super) fn register(
        &self,
        remote: SocketAddr,
        local_call: u16,
        remote_call: u16,
        generation: u64,
    ) -> io::Result<Result<IngressConsumer, PeerIngressRouterError>> {
        let (reply, response) = oneshot::channel();
        self.commands
            .blocking_send(RouteCommand::Register {
                remote,
                local_call,
                remote_call,
                generation,
                reply,
            })
            .map_err(|_| stopped())?;
        response.blocking_recv().map_err(|_| stopped())
    }

    pub(super) fn unregister(
        &self,
        remote: SocketAddr,
        local_call: u16,
        remote_call: u16,
        generation: u64,
    ) -> io::Result<()> {
        self.commands
            .blocking_send(RouteCommand::Unregister {
                remote,
                local_call,
                remote_call,
                generation,
            })
            .map_err(|_| stopped())
    }

    pub(super) fn try_receive(&mut self) -> io::Result<Option<InboundDatagram>> {
        match self.admission.try_pop() {
            Some(packet) => Ok(Some(packet)),
            None if self.admission.failed() => Err(stopped()),
            None => Ok(None),
        }
    }

    pub(super) fn stats(&self) -> ListenerIngressStats {
        ListenerIngressStats {
            admission: self.admission.stats(),
            active_routes: self.active_routes.load(Ordering::Relaxed),
        }
    }
}

fn stopped() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "IAX listener receive task stopped",
    )
}

impl Drop for ListenerIngress {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        let _ = self.runtime.block_on(&mut self.task);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{FullFrameHeader, serialize_full_frame};
    use std::{thread, time::Duration};

    #[test]
    fn stopped_before_first_poll_fails_admission_and_established_peers() {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let socket = runtime.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap();
        let mut router = PeerIngressRouter::new(1, 1).unwrap();
        let peer = router
            .register_call("127.0.0.1:4569".parse().unwrap(), 22, 42, 7)
            .unwrap();
        let mut pump = ListenerIngress::start(runtime.clone(), socket, router);
        pump.stop.send_replace(true);

        assert!(runtime.block_on(pump.admission.receive()).is_none());
        assert!(peer.failed());
        assert_eq!(pump.stats().active_routes, 0);
        assert_eq!(
            pump.try_receive().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    #[test]
    fn full_admission_queue_does_not_block_established_routing_and_shutdown_wakes_all() {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap(),
        );
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let address = receiver.local_addr().unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote = sender.local_addr().unwrap();
        let socket = {
            let _entered = runtime.enter();
            UdpSocket::from_std(receiver).unwrap()
        };
        let mut router = PeerIngressRouter::new(1, 4).unwrap();
        let mut peer = router.register_call(remote, 22, 42, 7).unwrap();
        let mut pump = ListenerIngress::start(runtime.clone(), socket, router);
        let packet = |destination, command: IaxCommand| {
            serialize_full_frame(
                &FullFrameHeader {
                    source_call_number: 42,
                    retransmission: false,
                    destination_call_number: destination,
                    timestamp: 0,
                    outgoing_sequence: 0,
                    incoming_sequence: 0,
                    frame_type: 6,
                    subclass: command.subclass_value() as u8,
                    subclass_is_log: false,
                },
                &[],
            )
            .unwrap()
        };
        for _ in 0..128 {
            sender
                .send_to(&packet(0, IaxCommand::New), address)
                .unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while pump.stats().admission.queued_packets < 64 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        // Readiness includes a producer's pre-publication reservation; queue
        // occupancy is the bounded-storage contract observed here.
        assert_eq!(pump.stats().admission.queued_packets, 64);
        let deadline = Instant::now() + Duration::from_secs(2);
        while pump.stats().admission.dropped_packets < 64 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(pump.stats().admission.dropped_packets, 64);
        assert_eq!(pump.stats().admission.capacity_packets, 64);
        assert_eq!(pump.stats().active_routes, 1);
        sender
            .send_to(&[0; MAX_DATAGRAM_SIZE + 1], address)
            .unwrap();
        sender.send_to(&[0x80, 0], address).unwrap();
        sender
            .send_to(&packet(23, IaxCommand::Ack), address)
            .unwrap();
        sender
            .send_to(&packet(0, IaxCommand::Ping), address)
            .unwrap();
        let ack = packet(22, IaxCommand::Ack);
        sender.send_to(&ack, address).unwrap();
        let received = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), peer.receive())
                .await
                .unwrap()
                .unwrap()
        });
        assert_eq!(received.payload(), ack);
        pump.stop.send_replace(true);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !pump.task.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(peer.failed());
        assert_eq!(pump.stats().active_routes, 0);
        for _ in 0..64 {
            assert!(pump.try_receive().unwrap().is_some());
        }
        assert_eq!(
            pump.try_receive().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(pump.register(remote, 23, 43, 8).is_err());
        assert!(pump.unregister(remote, 22, 42, 7).is_err());
    }

    #[test]
    fn socket_receive_error_fails_admission_and_every_established_peer() {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap(),
        );
        let remote = "127.0.0.1:4569".parse().unwrap();
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        crate::async_driver::fail_next_receive(receiver.local_addr().unwrap());
        let socket = {
            let _entered = runtime.enter();
            UdpSocket::from_std(receiver).unwrap()
        };
        let mut router = PeerIngressRouter::new(1, 1).unwrap();
        let peer = router.register_call(remote, 22, 42, 7).unwrap();
        let mut pump = ListenerIngress::start(runtime.clone(), socket, router);
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), pump.admission.wake().notified())
                .await
                .unwrap();
        });
        assert!(peer.failed());
        assert_eq!(pump.stats().active_routes, 0);
        assert_eq!(
            pump.try_receive().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }
}
