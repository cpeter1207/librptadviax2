use super::*;
use std::{
    net::UdpSocket,
    thread,
    time::{Duration, Instant},
};

fn qualify(
    clock: &SourceClock,
    receiver: &UdpSocket,
    sender: &UdpSocket,
    destination: std::net::SocketAddr,
) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        sender.send_to(b"qualification probe", destination).unwrap();
        match clock.receive(receiver, &mut [0; 64]) {
            Ok((_, _, Some(_))) => return,
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(error) => panic!("{error}"),
        }
        assert!(
            Instant::now() < deadline,
            "kernel RX timestamps never became available"
        );
        thread::yield_now();
    }
}

pub(crate) fn timestamp_probe() -> (SourceClock, UdpSocket, UdpSocket) {
    let clock = SourceClock::new();
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    clock.enable(&receiver).unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    qualify(&clock, &receiver, &sender, receiver.local_addr().unwrap());
    (clock, receiver, sender)
}

#[test]
fn genuinely_retained_receipt_cannot_map_expired_pcm_to_a_fresh_birth() {
    let (clock, receiver, sender) = timestamp_probe();
    sender
        .send_to(b"hold original", receiver.local_addr().unwrap())
        .unwrap();
    let receipt = clock.receive(&receiver, &mut [0; 32]).unwrap().2.unwrap();
    let span = Span::new(Some(receipt));
    thread::sleep(Duration::from_millis(510));
    assert!(span.expired(Instant::now()));
    assert_eq!(span.birth(1, u64::MAX, Instant::now()), None);
    assert_eq!(span.birth(1, u64::MAX, Instant::now()), None);
}

#[test]
fn actual_socket_option_and_monitor_arm_errors_leave_no_qualified_clock_or_stamp() {
    const CHILD: &str = "RPTADV_IAX_SOURCE_SOCKET_CHILD";
    let Some(selection) = std::env::var_os(CHILD) else {
        for selection in ["4", "5", "6"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "source_time::tests::actual_socket_option_and_monitor_arm_errors_leave_no_qualified_clock_or_stamp", "--nocapture"])
                .env(CHILD, selection).output().unwrap();
            assert!(
                output.status.success(),
                "{selection}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    };
    let (_path, library) = fault_library();
    let selection = selection.to_str().unwrap().parse::<u32>().unwrap();
    let install =
        unsafe { library.get::<unsafe extern "C" fn(u32) -> i32>(b"rptadv_test_fail_syscall\0") }
            .unwrap();
    let socket = crate::network::UdpEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    assert_eq!(unsafe { install(selection) }, 0);
    if selection == 4 {
        let clock = SourceClock::new();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(
            clock.enable(&receiver).unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );
    } else if selection == 5 {
        let clock = SourceClock::new();
        assert!(clock.monitor_fd().is_none());
        assert!(!clock.revoked());
    } else {
        assert_eq!(
            socket
                .shared_socket()
                .receive_timed(&mut [0; 32])
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EIO)
        );
    }
}

#[test]
fn kernel_receipt_precedes_delayed_dequeue_and_birth_is_cached_for_all_suffixes() {
    let clock = SourceClock::new();
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    clock.enable(&receiver).unwrap();
    receiver.set_nonblocking(true).unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    qualify(&clock, &receiver, &sender, receiver.local_addr().unwrap());
    let before = Instant::now();
    sender
        .send_to(b"original", receiver.local_addr().unwrap())
        .unwrap();
    thread::sleep(Duration::from_millis(25));
    let (length, remote, receipt) = clock.receive(&receiver, &mut [0; 32]).unwrap();
    assert_eq!(length, 8);
    assert_eq!(remote, sender.local_addr().unwrap());
    let receipt = receipt.expect("actual kernel software RX stamp");
    assert!(receipt.instant >= before);
    assert!(receipt.instant.elapsed() >= Duration::from_millis(20));
    let span = Span::new(Some(receipt));
    let reference = 1_000_000_000;
    let first = span.birth(7, reference, Instant::now()).unwrap();
    assert!(first < reference - 25_000_000);
    thread::sleep(Duration::from_millis(3));
    assert_eq!(
        span.birth(7, reference + 1_000_000, Instant::now()),
        Some(first)
    );
    assert_eq!(span.birth(8, reference + 1_000_000, Instant::now()), None);
}

#[test]
fn untrusted_receipt_and_clock_underflow_never_become_fresh_zero() {
    assert_eq!(Span::new(None).birth(1, u64::MAX, Instant::now()), None);
    let clock = SourceClock::new();
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    clock.enable(&receiver).unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    qualify(&clock, &receiver, &sender, receiver.local_addr().unwrap());
    sender
        .send_to(b"x", receiver.local_addr().unwrap())
        .unwrap();
    let receipt = clock.receive(&receiver, &mut [0; 32]).unwrap().2.unwrap();
    let span = Span::new(Some(receipt));
    assert_eq!(span.birth(0, u64::MAX, Instant::now()), None);
    assert_eq!(span.birth(1, 1, Instant::now()), None);
    assert_eq!(
        span.birth(1, u64::MAX, Instant::now()),
        None,
        "first underflow stays unqualified"
    );
}

#[test]
fn recvmsg_preserves_owned_ipv6_and_mapped_socket_families() {
    for (bind, target) in [("[::1]:0", "[::1]:0"), ("[::]:0", "127.0.0.1:0")] {
        let clock = SourceClock::new();
        let receiver = UdpSocket::bind(bind).unwrap();
        clock.enable(&receiver).unwrap();
        let sender = UdpSocket::bind(target).unwrap();
        let destination = if target.starts_with('[') {
            receiver.local_addr().unwrap()
        } else {
            std::net::SocketAddr::from(([127, 0, 0, 1], receiver.local_addr().unwrap().port()))
        };
        qualify(&clock, &receiver, &sender, destination);
        sender.send_to(b"v6", destination).unwrap();
        let (_, remote, receipt) = clock.receive(&receiver, &mut [0; 32]).unwrap();
        assert!(remote.is_ipv6());
        assert_eq!(remote.port(), sender.local_addr().unwrap().port());
        assert!(receipt.is_some());
    }
}

pub(crate) fn fault_library() -> (std::path::PathBuf, libloading::Library) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::create_dir_all(root.join("target")).unwrap();
    let path = root.join("target").join(format!(
        "source-clock-fault-{}-{}.so",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    assert!(
        std::process::Command::new("cc")
            .args([
                "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC"
            ])
            .arg(root.join("tests/os_fault_fixture.c"))
            .arg("-o")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let library = unsafe { libloading::Library::new(&path) }.unwrap();
    (path, library)
}

pub(crate) fn run_child(mut command: std::process::Command) -> std::process::Output {
    use std::process::Stdio;
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "owned fault child exceeded10s: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(5));
    }
}

pub(crate) fn fault_child(name: &str) -> Option<libloading::Library> {
    const CHILD: &str = "RPTADV_IAX_ONESHOT_SOCKET_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let (path, _library) = fault_library();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", name, "--nocapture"])
            .env(CHILD, "1")
            .env("LD_PRELOAD", &path);
        let output = run_child(command);
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
            "exact child filter matched no test: {name}"
        );
        assert!(
            output.status.success(),
            "{name}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        None
    } else {
        Some(unsafe { libloading::Library::new(std::env::var_os("LD_PRELOAD").unwrap()) }.unwrap())
    }
}

#[test]
fn actual_kernel_ancillary_truncation_never_qualifies_original_time() {
    let Some(library) = fault_child(
        "source_time::tests::actual_kernel_ancillary_truncation_never_qualifies_original_time",
    ) else {
        return;
    };
    let (clock, receiver, sender) = timestamp_probe();
    let truncate =
        unsafe { library.get::<unsafe extern "C" fn(i32)>(b"rptadv_test_truncate_receive\0") }
            .unwrap();
    unsafe { truncate(1) };
    sender
        .send_to(
            b"still a complete private datagram",
            receiver.local_addr().unwrap(),
        )
        .unwrap();
    let (count, _, receipt) = clock.receive(&receiver, &mut [0; 64]).unwrap();
    assert_eq!(count, 33);
    assert_eq!(receipt, None);
}

#[test]
fn actual_owned_clock_unavailability_cancellation_and_expiration_are_sticky_without_host_clock_changes()
 {
    const CHILD: &str = "RPTADV_IAX_SOURCE_CLOCK_CHILD";
    let Some(selection) = std::env::var_os(CHILD) else {
        let (path, _library) = fault_library();
        for selection in [
            "unavailable",
            "cancel",
            "expire",
            "initial-realtime",
            "lost-realtime",
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "source_time::tests::actual_owned_clock_unavailability_cancellation_and_expiration_are_sticky_without_host_clock_changes", "--nocapture"])
                .env(CHILD, selection).env("LD_PRELOAD", &path).output().unwrap();
            assert!(
                output.status.success(),
                "{selection}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    };
    let preload = std::path::PathBuf::from(std::env::var_os("LD_PRELOAD").unwrap());
    let library = unsafe { libloading::Library::new(preload) }.unwrap();
    let initial = selection == "unavailable" || selection == "initial-realtime";
    if selection == "unavailable" {
        let fail = unsafe {
            library.get::<unsafe extern "C" fn(u32) -> i32>(b"rptadv_test_fail_syscall\0")
        }
        .unwrap();
        assert_eq!(unsafe { fail(3) }, 0);
    }
    if selection == "initial-realtime" {
        let fail = unsafe { library.get::<unsafe extern "C" fn()>(b"rptadv_test_fail_realtime\0") }
            .unwrap();
        unsafe { fail() };
    }
    let clock = SourceClock::new();
    assert_eq!(clock.monitor_fd().is_none(), initial);
    if selection == "cancel" {
        let cancel = unsafe {
            library.get::<unsafe extern "C" fn(libc::c_int) -> i32>(b"rptadv_test_cancel_timerfd\0")
        }
        .unwrap();
        assert_eq!(unsafe { cancel(clock.monitor_fd().unwrap()) }, 0);
    } else if selection == "expire" {
        let timer = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: 1,
                tv_nsec: 0,
            },
        };
        assert_eq!(
            unsafe {
                libc::timerfd_settime(
                    clock.monitor_fd().unwrap(),
                    libc::TFD_TIMER_ABSTIME | libc::TFD_TIMER_CANCEL_ON_SET,
                    &timer,
                    std::ptr::null_mut(),
                )
            },
            0
        );
    } else if selection == "lost-realtime" {
        let fail = unsafe { library.get::<unsafe extern "C" fn()>(b"rptadv_test_fail_realtime\0") }
            .unwrap();
        unsafe { fail() };
    }
    assert_eq!(clock.revoked(), !initial);
    assert_eq!(clock.revoked(), !initial);
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    clock.enable(&receiver).unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(
            b"private control remains available",
            receiver.local_addr().unwrap(),
        )
        .unwrap();
    let mut bytes = [0; 128];
    let (count, remote, receipt) = clock.receive(&receiver, &mut bytes).unwrap();
    assert_eq!(&bytes[..count], b"private control remains available");
    assert_eq!(remote, sender.local_addr().unwrap());
    assert_eq!(receipt, None);
}

#[test]
fn missing_timestamp_and_actual_truncation_never_supply_receipt_authority() {
    let clock = SourceClock::new();
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"unstamped", receiver.local_addr().unwrap())
        .unwrap();
    assert_eq!(clock.receive(&receiver, &mut [0; 32]).unwrap().2, None);
    clock.enable(&receiver).unwrap();
    sender
        .send_to(b"truncated", receiver.local_addr().unwrap())
        .unwrap();
    assert_eq!(
        clock.receive(&receiver, &mut [0; 1]).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    receiver.set_nonblocking(true).unwrap();
    assert_eq!(
        clock.receive(&receiver, &mut [0; 32]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
