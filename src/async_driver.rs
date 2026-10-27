//! Serialized non-audio peer callbacks scheduled by packet readiness and media deadlines.

use crate::ingress::{IngressProducer, IngressWake, MAX_DATAGRAM_SIZE};
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    runtime::Handle,
    sync::{Notify, watch},
    task::JoinHandle,
};

// Pending inbound PCM and clients without deadline support need bounded retries.
pub(crate) const TIMER_INTERVAL: Duration = Duration::from_millis(10);

#[cfg(test)]
thread_local! {
    pub(crate) static WRITABLE_TEST_SIGNAL: std::cell::RefCell<Option<Arc<Notify>>> = const { std::cell::RefCell::new(None) };
}

async fn writable(socket: &tokio::net::UdpSocket) -> io::Result<()> {
    #[cfg(test)]
    if let Some(signal) = WRITABLE_TEST_SIGNAL.with_borrow(Clone::clone) {
        signal.notified().await;
        return Ok(());
    }
    socket.writable().await
}

#[cfg(test)]
pub(crate) fn fail_next_receive(local: SocketAddr) {
    crate::network::inject_receive(
        local,
        Err(io::Error::other("injected socket receive failure")),
    );
}

/// Socket read boundary shared by dedicated and listener receive tasks.
pub(crate) async fn receive_datagram(
    socket: &tokio::net::UdpSocket,
    bytes: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    #[cfg(test)]
    if let Some(result) = crate::network::injected_receive(socket.local_addr()?) {
        return result;
    }
    socket.recv_from(bytes).await
}

/// Retains one callback until off-executor detach has observed its final completion.
///
/// The runtime must outlive this owner. Callbacks must be bounded and nonblocking,
/// and may use their uniquely owned peer: the scheduler holds no peer borrow.
/// Destroy/detach on a control thread, never from a Tokio task or this callback.
pub struct PeerDriver {
    runtime: Handle,
    stop: watch::Sender<bool>,
    task: Mutex<Option<JoinHandle<()>>>,
    notify: Arc<ProductWake>,
}

struct ProductWake {
    notify: Notify,
    pending: AtomicBool,
}

/// Copied after an exclusive peer turn; no session borrow survives an await.
pub struct PeerWait {
    /// Next actual protocol, media, or playout deadline; none parks indefinitely.
    pub deadline: Option<Instant>,
    /// Present only after a send returned WouldBlock in this turn.
    pub writable: Option<Arc<tokio::net::UdpSocket>>,
}

impl PeerDriver {
    /// Start one exclusive callback, then wait for its work or actual deadline.
    /// Returning None ends the callback; unrelated peers keep running.
    pub fn attach(
        runtime: &Handle,
        wake: IngressWake,
        mut step: impl FnMut() -> Option<PeerWait> + Send + 'static,
    ) -> Self {
        let (stop, mut stopping) = watch::channel(false);
        let notify = Arc::new(ProductWake {
            notify: Notify::new(),
            pending: AtomicBool::new(false),
        });
        let notified = Arc::clone(&notify);
        let task = runtime.spawn(async move {
            while !*stopping.borrow() {
                notified.pending.store(false, Ordering::Release);
                let before = wake.pending();
                let Some(wait) = step() else {
                    break;
                };
                let after = wake.pending();
                if after != 0 && after < before {
                    // Bounded product steps drain backlog without monopolizing a worker.
                    tokio::task::yield_now().await;
                    continue;
                }
                // Retained PCM/backpressure may prevent packet consumption. A
                // nonempty but unchanged queue is not a reason to busy-spin.
                tokio::select! {
                    _ = stopping.changed() => (),
                    _ = wake.notified() => (),
                    _ = notified.notify.notified() => (),
                    _ = async {
                        match wait.deadline {
                            Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                            None => std::future::pending().await,
                        }
                    } => (),
                    ready = async {
                        match wait.writable {
                            Some(socket) => writable(&socket).await,
                            None => std::future::pending().await,
                        }
                    } => { if ready.is_err() { break; } },
                }
            }
        });
        Self {
            runtime: runtime.clone(),
            stop,
            task: Mutex::new(Some(task)),
            notify,
        }
    }

    /// Out-of-band stop; does not wait for an already executing callback.
    pub fn stop(&self) {
        self.stop.send_replace(true);
    }

    /// Coalesce an off-audio product wake without waiting for the peer owner.
    pub fn wake(&self) {
        if !self.notify.pending.swap(true, Ordering::AcqRel) {
            self.notify.notify.notify_one();
        }
    }

    /// Whether the task has returned, including all callback-owned cleanup.
    pub fn is_finished(&self) -> bool {
        self.task
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(JoinHandle::is_finished)
    }

    /// Join through shared access so an executing callback may still call stop.
    pub(crate) fn wait(&self) {
        self.stop();
        let mut task = self.task.lock().unwrap();
        if let Some(task) = task.take() {
            let _ = self.runtime.block_on(task);
        }
    }

    /// Stop and wait off-executor before freeing callback context or unloading its DSO.
    pub fn detach(self) {}
}

impl Drop for PeerDriver {
    fn drop(&mut self) {
        self.wait();
    }
}

/// Sole readiness-driven receiver for a dedicated outbound socket.
/// Stop and detach off-executor before destroying the associated peer.
pub struct DatagramPump {
    runtime: Handle,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl DatagramPump {
    /// Transfer receive ownership while preserving the existing socket for sends.
    pub fn start(
        runtime: &Handle,
        socket: UdpSocket,
        remote: SocketAddr,
        producer: IngressProducer,
    ) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        let _entered = runtime.enter();
        let socket = tokio::net::UdpSocket::from_std(socket)?;
        Ok(Self::from_socket(
            runtime,
            Arc::new(socket),
            remote,
            producer,
        ))
    }

    pub(crate) fn from_socket(
        runtime: &Handle,
        socket: Arc<tokio::net::UdpSocket>,
        remote: SocketAddr,
        mut producer: IngressProducer,
    ) -> Self {
        let (stop, mut stopping) = watch::channel(false);
        let task = runtime.spawn(async move {
            // One extra byte detects truncated oversized datagrams before admission.
            let mut bytes = [0; MAX_DATAGRAM_SIZE + 1];
            while !*stopping.borrow() {
                tokio::select! {
                    _ = stopping.changed() => break,
                    received = receive_datagram(&socket, &mut bytes) => {
                        let arrived_at = Instant::now();
                        match received {
                            Ok((length, source)) if source == remote => {
                                let _ = producer.try_push_at(source, &bytes[..length], arrived_at);
                            }
                            Ok(_) => (),
                            Err(_) => { producer.fail(); break; }
                        }
                    }
                }
            }
        });
        Self {
            runtime: runtime.clone(),
            stop,
            task,
        }
    }

    /// Stop admission without waiting for the executor.
    pub fn stop(&self) {
        self.stop.send_replace(true);
    }

    /// Wait for the socket reader to release its producer, off the executor.
    pub fn detach(self) {}
}

impl Drop for DatagramPump {
    fn drop(&mut self) {
        self.stop();
        let _ = self.runtime.block_on(&mut self.task);
    }
}
