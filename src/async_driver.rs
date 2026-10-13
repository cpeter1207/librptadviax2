//! Serialized non-audio peer callbacks scheduled by packet readiness and media deadlines.

use crate::ingress::{IngressProducer, IngressWake, MAX_DATAGRAM_SIZE};
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::{runtime::Handle, sync::watch, task::JoinHandle};

// Empty ingress still needs playout turns at the smallest missing-media quantum.
pub(crate) const TIMER_INTERVAL: Duration = Duration::from_nanos(
    1_000_000_000 * crate::jitter::CONCEALMENT_SPAN as u64 / crate::jitter::CLOCK_RATE_HZ as u64,
);

#[cfg(test)]
static RECEIVE_FAILURES: Mutex<Vec<SocketAddr>> = Mutex::new(Vec::new());

#[cfg(test)]
pub(crate) fn fail_next_receive(local: SocketAddr) {
    RECEIVE_FAILURES.lock().unwrap().push(local);
}

/// Socket read boundary shared by dedicated and listener receive tasks.
pub(crate) async fn receive_datagram(
    socket: &tokio::net::UdpSocket,
    bytes: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    #[cfg(test)]
    {
        let local = socket.local_addr()?;
        let mut failures = RECEIVE_FAILURES.lock().unwrap();
        if let Some(index) = failures.iter().position(|address| *address == local) {
            failures.swap_remove(index);
            return Err(io::Error::other("injected socket receive failure"));
        }
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
}

impl PeerDriver {
    /// Start one exclusive callback, then wake for queued packets or every 10 ms.
    /// Returning false ends the callback; unrelated peers keep running.
    pub fn attach(
        runtime: &Handle,
        wake: IngressWake,
        mut step: impl FnMut() -> bool + Send + 'static,
    ) -> Self {
        let (stop, mut stopping) = watch::channel(false);
        let task = runtime.spawn(async move {
            while !*stopping.borrow() {
                let before = wake.pending();
                if !step() {
                    break;
                }
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
                    _ = tokio::time::sleep(TIMER_INTERVAL) => (),
                }
            }
        });
        Self {
            runtime: runtime.clone(),
            stop,
            task: Mutex::new(Some(task)),
        }
    }

    /// Out-of-band stop; does not wait for an already executing callback.
    pub fn stop(&self) {
        self.stop.send_replace(true);
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
        Ok(Self::from_socket(runtime, socket, remote, producer))
    }

    pub(crate) fn from_socket(
        runtime: &Handle,
        socket: tokio::net::UdpSocket,
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
