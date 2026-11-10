//! Genuine Linux UDP receipt mapping; caller-supplied ingress times grant no qualification.

use std::{
    io,
    mem::{size_of, zeroed},
    net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

pub(crate) const UNCERTAINTY: Duration = Duration::from_millis(5);
pub(crate) const MAXIMUM_AGE: Duration = Duration::from_millis(500);
// Native Linux ktime is signed64 nanoseconds. This absolute2262 deadline fits;
// expiration is terminal, never rearmed across an unmonitored clock interval.
const DEADLINE_SECONDS: i64 = 9_223_372_035;
const _: () = assert!(DEADLINE_SECONDS.checked_mul(1_000_000_000).is_some());
const _: () = assert!(size_of::<libc::time_t>() == 8);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Receipt {
    pub(crate) instant: Instant,
}
impl Receipt {
    pub(crate) fn expired(self, now: Instant) -> bool {
        now.checked_duration_since(self.instant)
            .is_none_or(|age| age > MAXIMUM_AGE)
    }
}

type MappedBirth = Arc<OnceLock<(u64, Option<u64>)>>;

#[derive(Clone, Debug, Default)]
pub(crate) struct Span {
    pub(crate) receipt: Option<Receipt>,
    // Some stores even a failed mapping: later retries must not renew the age.
    mapped: Option<MappedBirth>,
}
impl Span {
    pub(crate) fn new(receipt: Option<Receipt>) -> Self {
        Self {
            receipt,
            mapped: receipt.map(|_| Arc::new(OnceLock::new())),
        }
    }
    pub(crate) fn birth(&self, host_epoch: u64, reference: u64, exposed: Instant) -> Option<u64> {
        if host_epoch == 0 {
            return None;
        }
        let (epoch, birth) = *self.mapped.as_ref()?.get_or_init(|| {
            let birth = self.receipt.and_then(|receipt| {
                let age = exposed.checked_duration_since(receipt.instant)?;
                if age > MAXIMUM_AGE {
                    return None;
                }
                let age = u64::try_from(age.checked_add(UNCERTAINTY)?.as_nanos()).ok()?;
                reference.checked_sub(age)
            });
            (host_epoch, birth)
        });
        (epoch == host_epoch).then_some(birth).flatten()
    }
    pub(crate) fn expired(&self, now: Instant) -> bool {
        self.receipt.is_some_and(|receipt| receipt.expired(now))
    }
}

struct Anchor {
    instant: Instant,
    realtime: i128,
    monitor: OwnedFd,
}
struct State {
    anchor: Option<Anchor>,
    revoked: bool,
}
pub(crate) struct SourceClock(Mutex<State>);
impl SourceClock {
    #[cfg(test)]
    pub(crate) fn monitor_fd(&self) -> Option<libc::c_int> {
        self.0
            .lock()
            .unwrap()
            .anchor
            .as_ref()
            .map(|anchor| anchor.monitor.as_raw_fd())
    }
    pub(crate) fn new() -> Self {
        let anchor = monitor().and_then(|monitor| {
            let instant = Instant::now();
            Some(Anchor {
                instant,
                realtime: realtime().ok()?,
                monitor,
            })
        });
        Self(Mutex::new(State {
            anchor,
            revoked: false,
        }))
    }
    pub(crate) fn revoked(&self) -> bool {
        let mut state = self
            .0
            .lock()
            .expect("source clock is never locked over foreign code");
        state.check();
        state.revoked
    }
    pub(crate) fn enable(&self, socket: &UdpSocket) -> io::Result<()> {
        // No SO_TIMESTAMPNS: it may manufacture a timestamp for an unstamped skb.
        let flags =
            (libc::SOF_TIMESTAMPING_RX_SOFTWARE | libc::SOF_TIMESTAMPING_SOFTWARE) as libc::c_int;
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPING,
                ptr::from_ref(&flags).cast(),
                size_of_val(&flags) as libc::socklen_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    pub(crate) fn receive(
        &self,
        socket: &UdpSocket,
        bytes: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<Receipt>)> {
        self.receive_fd(socket.as_raw_fd(), socket.local_addr()?.is_ipv6(), bytes)
    }
    pub(crate) fn receive_fd(
        &self,
        fd: libc::c_int,
        ipv6: bool,
        bytes: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<Receipt>)> {
        let (length, remote, stamp) = receive(fd, bytes, ipv6)?;
        let mut state = self
            .0
            .lock()
            .expect("source clock is never locked over foreign code");
        state.check();
        let receipt = if state.revoked {
            None
        } else {
            state.anchor.as_ref().and_then(|anchor| {
                let stamp = stamp?;
                let now = Instant::now();
                let received = i128::from(stamp.tv_sec) * 1_000_000_000 + i128::from(stamp.tv_nsec);
                let offset = u64::try_from(received - anchor.realtime).ok()?;
                let instant = anchor.instant.checked_add(Duration::from_nanos(offset))?;
                (instant <= now).then_some(Receipt { instant })
            })
        };
        state.check();
        Ok((length, remote, if state.revoked { None } else { receipt }))
    }
}
impl State {
    fn check(&mut self) {
        if self.revoked {
            return;
        }
        if let Some(anchor) = &self.anchor {
            let now = Instant::now();
            let expected = anchor.realtime + now.duration_since(anchor.instant).as_nanos() as i128;
            if !pending(&anchor.monitor)
                || match realtime() {
                    Ok(wall) => (wall - expected).abs() > UNCERTAINTY.as_nanos() as i128,
                    Err(_) => true,
                }
            {
                self.revoked = true;
            }
        }
    }
}
fn monitor() -> Option<OwnedFd> {
    let fd = unsafe {
        libc::timerfd_create(libc::CLOCK_REALTIME, libc::TFD_NONBLOCK | libc::TFD_CLOEXEC)
    };
    if fd < 0 {
        return None;
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let timer = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: DEADLINE_SECONDS,
            tv_nsec: 0,
        },
    };
    (unsafe {
        libc::timerfd_settime(
            fd.as_raw_fd(),
            libc::TFD_TIMER_ABSTIME | libc::TFD_TIMER_CANCEL_ON_SET,
            &timer,
            ptr::null_mut(),
        )
    } == 0
        && pending(&fd))
    .then_some(fd)
}
fn pending(fd: &OwnedFd) -> bool {
    let mut count = 0_u64;
    let result = unsafe {
        libc::read(
            fd.as_raw_fd(),
            ptr::from_mut(&mut count).cast(),
            size_of_val(&count),
        )
    };
    result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock
}
fn realtime() -> io::Result<i128> {
    let mut value: libc::timespec = unsafe { zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(i128::from(value.tv_sec) * 1_000_000_000 + i128::from(value.tv_nsec))
}
// Exclusive immutable ancillary subscription on this owned Internet UDP socket:
// no ERRQUEUE, no other timestamps/options. Linux __sock_recv_timestamp emits
// SCM_TIMESTAMPING with exactly3 timespecs only when genuine software ts0 exists.
#[repr(C)]
struct Timestamp {
    _header: libc::cmsghdr,
    values: [libc::timespec; 3],
}
fn receive(
    fd: libc::c_int,
    bytes: &mut [u8],
    ipv6: bool,
) -> io::Result<(usize, SocketAddr, Option<libc::timespec>)> {
    let mut address: libc::sockaddr_storage = unsafe { zeroed() };
    let mut control: Timestamp = unsafe { zeroed() };
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_name = ptr::from_mut(&mut address).cast();
    message.msg_namelen = size_of_val(&address) as libc::socklen_t;
    message.msg_iov = ptr::from_mut(&mut vector);
    message.msg_iovlen = 1;
    message.msg_control = ptr::from_mut(&mut control).cast();
    message.msg_controllen = size_of_val(&control);
    let count = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_DONTWAIT) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    // Drop truncated datagrams, never admit a partial control/media packet.
    if message.msg_flags & libc::MSG_TRUNC != 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let stamp = (message.msg_flags & libc::MSG_CTRUNC == 0
        && message.msg_controllen >= size_of_val(&control))
    .then_some(control.values[0]);
    let remote = if ipv6 {
        let value =
            unsafe { ptr::read_unaligned(ptr::from_ref(&address).cast::<libc::sockaddr_in6>()) };
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(value.sin6_addr.s6_addr),
            u16::from_be(value.sin6_port),
            u32::from_be(value.sin6_flowinfo),
            value.sin6_scope_id,
        ))
    } else {
        let value =
            unsafe { ptr::read_unaligned(ptr::from_ref(&address).cast::<libc::sockaddr_in>()) };
        SocketAddr::from((
            value.sin_addr.s_addr.to_ne_bytes(),
            u16::from_be(value.sin_port),
        ))
    };
    Ok((count as usize, remote, stamp))
}

#[cfg(test)]
#[path = "source_time_tests.rs"]
pub(crate) mod tests;
