//! One socket/router owner; control policy consumes a separate bounded NEW queue.

use super::{ListenerIngressStats, route_established};
use crate::{
    ingress::{
        InboundDatagram, IngressConsumer, MAX_DATAGRAM_SIZE, PeerIngressRouter, producer_ingress,
    },
    protocol::{IaxCommand, decode_iax_command, parse_full_frame_packet},
    provider::{AccountError, Ownership},
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
    Promote {
        remote: SocketAddr,
        local_call: u16,
        remote_call: u16,
        generation: u64,
        ownership: Ownership,
        reply: oneshot::Sender<Result<(), AccountError>>,
    },
    Pending {
        remote: SocketAddr,
        local_call: u16,
        generation: u64,
        ownership: Ownership,
        reply: oneshot::Sender<Result<IngressConsumer, AccountError>>,
    },
    Unregister {
        remote: SocketAddr,
        local_call: u16,
        remote_call: u16,
        generation: u64,
        reply: oneshot::Sender<()>,
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

#[derive(Clone)]
pub(crate) struct ListenerControl {
    runtime: Arc<Runtime>,
    commands: mpsc::Sender<RouteCommand>,
}

impl ListenerControl {
    pub(crate) fn send(
        &self,
        socket: &crate::network::SharedSocket,
        remote: SocketAddr,
        bytes: &[u8],
        ownership: &Ownership,
        deadline: Instant,
    ) -> Result<(), AccountError> {
        let socket = socket
            .register(self.runtime.handle())
            .map_err(AccountError::Network)?;
        self.runtime.block_on(async {
            tokio::time::timeout_at(deadline.into(), async {
                loop {
                    if Instant::now() >= deadline {
                        return Err(AccountError::Timeout);
                    }
                    // The short life guards end before readiness is awaited.
                    // Recheck the exact owner on every nonblocking commit.
                    match ownership.with_live(|| socket.try_send_to(bytes, remote))? {
                        Ok(_) => return Ok(()),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            socket.writable().await.map_err(AccountError::Network)?;
                        }
                        Err(error) => return Err(AccountError::Network(error)),
                    }
                }
            })
            .await
            .map_err(|_| AccountError::Timeout)?
        })
    }
    pub(super) fn unregister(
        &self,
        identity: (SocketAddr, u16, u16, u64),
        deadline: Instant,
    ) -> Result<(), AccountError> {
        let (reply, response) = oneshot::channel();
        let (remote, local_call, remote_call, generation) = identity;
        self.runtime.block_on(async {
            tokio::time::timeout_at(deadline.into(), async {
                self.commands
                    .send(RouteCommand::Unregister {
                        remote,
                        local_call,
                        remote_call,
                        generation,
                        reply,
                    })
                    .await
                    .map_err(|_| AccountError::Retired)?;
                response.await.map_err(|_| AccountError::Retired)
            })
            .await
            .map_err(|_| AccountError::Timeout)?
        })
    }
    pub(super) fn promote(
        &self,
        identity: (SocketAddr, u16, u16, u64),
        ownership: Ownership,
        deadline: Instant,
    ) -> Result<(), AccountError> {
        let (reply, response) = oneshot::channel();
        let (remote, local_call, remote_call, generation) = identity;
        self.runtime.block_on(async {
            tokio::time::timeout_at(deadline.into(), async {
                self.commands
                    .send(RouteCommand::Promote {
                        remote,
                        local_call,
                        remote_call,
                        generation,
                        ownership,
                        reply,
                    })
                    .await
                    .map_err(|_| AccountError::Retired)?;
                response.await.map_err(|_| AccountError::Retired)?
            })
            .await
            .map_err(|_| AccountError::Timeout)?
        })
    }
    pub(super) fn register_pending(
        &self,
        remote: SocketAddr,
        local_call: u16,
        generation: u64,
        ownership: Ownership,
        deadline: Instant,
    ) -> Result<IngressConsumer, AccountError> {
        let (reply, response) = oneshot::channel();
        self.runtime.block_on(async {
            tokio::time::timeout_at(deadline.into(), async {
                self.commands
                    .send(RouteCommand::Pending {
                        remote,
                        local_call,
                        generation,
                        ownership,
                        reply,
                    })
                    .await
                    .map_err(|_| AccountError::Retired)?;
                response.await.map_err(|_| AccountError::Retired)?
            })
            .await
            .map_err(|_| AccountError::Timeout)?
        })
    }
}

impl ListenerIngress {
    pub(super) fn start(
        runtime: Arc<Runtime>,
        socket: Arc<UdpSocket>,
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
                        RouteCommand::Promote { remote, local_call, remote_call, generation, ownership, reply } => {
                            let promoted = ownership.with_live(|| router.promote_pending_call(remote, local_call, remote_call, generation));
                            let promoted = match promoted {
                                Ok(Ok(())) => Ok(()),
                                Ok(Err(_)) => Err(AccountError::Retired),
                                Err(error) => Err(error),
                            };
                            if reply.send(promoted).is_err() {
                                router.unregister_setup_call(remote, local_call, generation);
                            }
                            route_count.store(router.route_count(), Ordering::Relaxed);
                        }
                        RouteCommand::Pending { remote, local_call, generation, ownership, reply } => {
                            let registered = ownership.with_live(|| router.register_pending_call(remote, local_call, generation));
                            let registered = match registered {
                                Ok(Ok(ingress)) => Ok(ingress),
                                Ok(Err(_)) => Err(AccountError::Busy),
                                Err(error) => Err(error),
                            };
                            // A timed-out control caller cannot leave a late installed route.
                            if reply.send(registered).is_err() {
                                router.unregister_setup_call(remote, local_call, generation);
                            }
                            route_count.store(router.route_count(), Ordering::Relaxed);
                        }
                        RouteCommand::Unregister { remote, local_call, remote_call, generation, reply } => {
                            if remote_call == 0 {
                                router.unregister_setup_call(remote, local_call, generation);
                            } else {
                                router.unregister_call(remote, local_call, remote_call, generation);
                            }
                            route_count.store(router.route_count(), Ordering::Relaxed);
                            let _ = reply.send(());
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

    pub(super) fn control(&self) -> ListenerControl {
        ListenerControl {
            runtime: self.runtime.clone(),
            commands: self.commands.clone(),
        }
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

    fn account_listener(
        runtime: Arc<Runtime>,
        fail_allocation: bool,
    ) -> (crate::server::InboundIaxListener, std::net::UdpSocket) {
        let remote = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let account = crate::provider::AccountConfig {
            id: "provider".into(),
            generation: 7,
            local_binding: "operator-west".into(),
            remote: remote.local_addr().unwrap(),
            username: "login".into(),
            secret: "fixture-secret".into(),
            pending_auth_timeout: Duration::from_secs(1),
        };
        let mut listener = crate::server::InboundIaxListener::bind_accounts(
            "127.0.0.1:0".parse().unwrap(),
            &[],
            &[account],
            None,
        )
        .unwrap();
        listener.router.fail_next_reserve = fail_allocation;
        listener.enable_async(runtime).unwrap();
        (listener, remote)
    }

    fn request() -> crate::provider::RegistrationRequest {
        crate::provider::RegistrationRequest {
            refresh: 60,
            release: false,
            timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn queued_pending_route_rechecks_actual_account_retirement_before_installing() {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let (mut listener, _remote) = account_listener(runtime.clone(), false);
        let prepared = listener
            .prepare_registration("provider", 7, request())
            .unwrap();
        let control = prepared.route.control.as_ref().unwrap().clone();
        let (reply, response) = oneshot::channel();
        control
            .commands
            .try_send(RouteCommand::Pending {
                remote: prepared.route.remote,
                local_call: prepared.route.local_call,
                generation: prepared.route.generation,
                ownership: prepared.route.ownership.clone(),
                reply,
            })
            .unwrap_or_else(|_| panic!("owned empty control queue"));
        // This current-thread executor has not driven the real queued command yet.
        listener.configure_accounts(&[]).unwrap();
        assert!(matches!(
            runtime.block_on(response).unwrap(),
            Err(AccountError::Retired)
        ));
        assert_eq!(listener.ingress_stats().active_routes, 0);
        drop(prepared);
        listener
            .poll_accounts(100, |_, _, _| false, |_| false)
            .unwrap();
        assert!(listener.routes.is_empty());
    }

    #[test]
    fn canceled_pending_and_promotion_results_remove_only_their_actual_route() {
        for promote in [false, true] {
            let runtime = Arc::new(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap(),
            );
            let (mut listener, _remote) = account_listener(runtime, false);
            let mut prepared = listener
                .prepare_registration("provider", 7, request())
                .unwrap();
            let route = &mut prepared.route;
            let control = route.control.as_ref().unwrap().clone();
            if promote {
                route
                    .install(Instant::now() + Duration::from_secs(1))
                    .unwrap();
                let (reply, response) = oneshot::channel();
                drop(response);
                control
                    .commands
                    .try_send(RouteCommand::Promote {
                        remote: route.remote,
                        local_call: route.local_call,
                        remote_call: 77,
                        generation: route.generation,
                        ownership: route.ownership.clone(),
                        reply,
                    })
                    .unwrap_or_else(|_| panic!("owned empty control queue"));
            } else {
                let (reply, response) = oneshot::channel();
                drop(response);
                control
                    .commands
                    .try_send(RouteCommand::Pending {
                        remote: route.remote,
                        local_call: route.local_call,
                        generation: route.generation,
                        ownership: route.ownership.clone(),
                        reply,
                    })
                    .unwrap_or_else(|_| panic!("owned empty control queue"));
            }
            // Its acknowledged FIFO successor proves the canceled command was
            // processed, rather than sampling zero before admission happened.
            control
                .unregister(
                    (route.remote, route.local_call, 0, route.generation),
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap();
            assert_eq!(listener.ingress_stats().active_routes, 0);
            drop(prepared);
            listener
                .poll_accounts(100, |_, _, _| false, |_| false)
                .unwrap();
            assert!(listener.routes.is_empty());
        }
    }

    #[test]
    fn actual_router_allocation_failure_returns_no_consumer_or_registration_datagram() {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let (mut listener, remote) = account_listener(runtime, true);
        let mut prepared = listener
            .prepare_registration("provider", 7, request())
            .unwrap();
        assert!(matches!(prepared.run(), Err(AccountError::Busy)));
        assert_eq!(listener.ingress_stats().active_routes, 0);
        remote.set_nonblocking(true).unwrap();
        assert_eq!(
            remote.recv_from(&mut [0; 2048]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(prepared);
        listener
            .poll_accounts(100, |_, _, _| false, |_| false)
            .unwrap();
        assert!(listener.routes.is_empty());
    }

    #[test]
    fn oversized_receive_does_not_stop_other_peers_or_admission() {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let receiver = runtime.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap();
        let local = receiver.local_addr().unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote = sender.local_addr().unwrap();
        crate::network::inject_receive(local, Ok((MAX_DATAGRAM_SIZE + 1, remote)));
        let mut router = PeerIngressRouter::new(1).unwrap();
        let mut peer = router.register_call(remote, 22, 42, 7).unwrap();
        let mut pump = ListenerIngress::start(runtime.clone(), Arc::new(receiver), router);
        let packet = serialize_full_frame(
            &FullFrameHeader {
                source_call_number: 42,
                destination_call_number: 22,
                retransmission: false,
                timestamp: 0,
                outgoing_sequence: 0,
                incoming_sequence: 0,
                frame_type: 6,
                subclass: IaxCommand::Ack.subclass_value() as u8,
                subclass_is_log: false,
            },
            &[],
        )
        .unwrap();
        sender.send_to(&packet, local).unwrap();
        let received = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), peer.receive())
                .await
                .unwrap()
                .unwrap()
        });
        assert_eq!(received.payload(), packet);
        assert!(!peer.failed());
        assert_eq!(pump.stats().active_routes, 1);
        assert!(pump.try_receive().unwrap().is_none());
    }

    #[test]
    fn stopped_before_first_poll_fails_admission_and_established_peers() {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let socket = runtime.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap();
        let mut router = PeerIngressRouter::new(1).unwrap();
        let peer = router
            .register_call("127.0.0.1:4569".parse().unwrap(), 22, 42, 7)
            .unwrap();
        let mut pump = ListenerIngress::start(runtime.clone(), Arc::new(socket), router);
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
        let mut router = PeerIngressRouter::new(4).unwrap();
        let mut peer = router.register_call(remote, 22, 42, 7).unwrap();
        let mut pump = ListenerIngress::start(runtime.clone(), Arc::new(socket), router);
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
        sender.send_to(&[0; 65_507], address).unwrap();
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
        let ownership = Ownership {
            server: crate::provider::Life::new(),
            account: crate::provider::Life::new(),
            operation: crate::provider::Life::new(),
        };
        assert!(matches!(
            pump.control().register_pending(
                remote,
                23,
                8,
                ownership,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(AccountError::Retired)
        ));
        assert!(matches!(
            pump.control()
                .unregister((remote, 22, 42, 7), Instant::now() + Duration::from_secs(1)),
            Err(AccountError::Retired)
        ));
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
        let mut router = PeerIngressRouter::new(1).unwrap();
        let peer = router.register_call(remote, 22, 42, 7).unwrap();
        let mut pump = ListenerIngress::start(runtime.clone(), Arc::new(socket), router);
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
    #[test]
    fn real_pending_promotion_rejects_stale_generation_and_queued_retirement_without_reusing_route()
    {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let (mut listener, _remote) = account_listener(runtime.clone(), false);
        let mut prepared = listener
            .prepare_registration("provider", 7, request())
            .unwrap();
        prepared
            .route
            .install(Instant::now() + Duration::from_secs(1))
            .unwrap();
        let route = &prepared.route;
        let control = route.control.as_ref().unwrap().clone();
        assert!(matches!(
            control.promote(
                (route.remote, route.local_call, 77, route.generation + 1),
                route.ownership.clone(),
                Instant::now() + Duration::from_secs(1)
            ),
            Err(AccountError::Retired)
        ));
        assert_eq!(listener.ingress_stats().active_routes, 1);
        let expired = route
            .send(
                b"never committed after its deadline",
                Instant::now() - Duration::from_secs(1),
            )
            .expect_err("the original deadline is already past");
        assert!(matches!(
            expired.into_call(),
            crate::client::DialError::Timeout
        ));
        let (reply, response) = oneshot::channel();
        control
            .commands
            .try_send(RouteCommand::Promote {
                remote: route.remote,
                local_call: route.local_call,
                remote_call: 77,
                generation: route.generation,
                ownership: route.ownership.clone(),
                reply,
            })
            .unwrap_or_else(|_| panic!("owned empty queue"));
        listener.configure_accounts(&[]).unwrap();
        assert!(matches!(
            runtime.block_on(response).unwrap(),
            Err(AccountError::Retired)
        ));
        assert_eq!(listener.ingress_stats().active_routes, 1);
        drop(prepared);
        listener
            .poll_accounts(1000, |_, _, _| false, |_| false)
            .unwrap();
        assert_eq!(listener.ingress_stats().active_routes, 0);
    }
}
