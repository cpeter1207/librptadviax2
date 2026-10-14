use crate::{async_driver::PeerDriver, ingress::producer_ingress};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;

#[test]
fn datagram_pump_configures_blocking_socket_and_stops_before_queue_release() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = receiver.local_addr().unwrap();
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let unrelated = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let (producer, mut consumer) = producer_ingress(2, 3).unwrap();
    let before = std::time::Instant::now();
    let pump = crate::async_driver::DatagramPump::start(
        runtime.handle(),
        receiver,
        sender.local_addr().unwrap(),
        producer,
    )
    .unwrap();
    unrelated.send_to(&[9], address).unwrap();
    sender.send_to(&[1, 2, 3], address).unwrap();
    let packet = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), consumer.receive())
            .await
            .unwrap()
            .unwrap()
    });
    assert_eq!(packet.payload(), &[1, 2, 3]);
    assert_eq!(packet.generation(), 3);
    assert!(packet.arrived_at() >= before);
    pump.detach();
    assert!(runtime.block_on(consumer.receive()).is_none());
}

#[test]
fn datagram_pump_stopped_before_first_poll_releases_its_mailbox() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let (producer, mut consumer) = producer_ingress(1, 1).unwrap();
    let pump = crate::async_driver::DatagramPump::start(
        runtime.handle(),
        socket,
        "127.0.0.1:4569".parse().unwrap(),
        producer,
    )
    .unwrap();
    pump.stop();
    runtime.block_on(async { tokio::task::yield_now().await });
    pump.detach();
    assert!(runtime.block_on(consumer.receive()).is_none());
}

#[test]
fn datagram_pump_receive_error_marks_its_mailbox_failed() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    crate::async_driver::fail_next_receive(socket.local_addr().unwrap());
    let (producer, mut consumer) = producer_ingress(1, 1).unwrap();
    let pump = crate::async_driver::DatagramPump::start(
        runtime.handle(),
        socket,
        "127.0.0.1:4569".parse().unwrap(),
        producer,
    )
    .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), consumer.wake().notified())
            .await
            .unwrap();
    });
    assert!(consumer.failed());
    assert!(runtime.block_on(consumer.receive()).is_none());
    pump.detach();
}

#[test]
fn async_descriptor_invalid_arguments_never_retain_callback_context() {
    use std::{ffi::c_void, ptr};
    unsafe extern "C" fn forbidden(_: *mut c_void) -> i32 {
        panic!("invalid attach invoked callback")
    }
    let api = unsafe { &*crate::async_ffi::rptadv_iax2_async_descriptor_v1() };
    let (mut peer, _producer) = inbound_peer();
    let peer = (&mut *peer as *mut crate::client::IaxPeer).cast();
    let mut runtime = ptr::null_mut();
    unsafe {
        assert_eq!((api.runtime_create)(ptr::null_mut()), -1);
        assert_eq!((api.runtime_create)(&mut runtime), 0);
        (api.runtime_destroy)(ptr::null_mut());
        (api.peer_stop)(ptr::null_mut());
        (api.peer_detach)(ptr::null_mut());
        assert_eq!(
            (api.peer_attach)(
                runtime,
                peer,
                Some(forbidden),
                ptr::null_mut(),
                ptr::null_mut()
            ),
            -1
        );
        for (owner, handle, step) in [
            (
                ptr::null_mut(),
                peer,
                Some(forbidden as crate::async_ffi::Step),
            ),
            (runtime, peer, None),
            (
                runtime,
                ptr::null_mut(),
                Some(forbidden as crate::async_ffi::Step),
            ),
        ] {
            let mut registration = std::ptr::dangling_mut::<c_void>();
            assert_eq!(
                (api.peer_attach)(owner, handle, step, ptr::null_mut(), &mut registration),
                -1
            );
            assert!(registration.is_null());
        }
        assert_eq!((api.peer_configure_jitter)(peer, ptr::null()), -1);
        (api.runtime_destroy)(runtime);
    }
}

fn inbound_peer() -> (Box<crate::client::IaxPeer>, crate::ingress::IngressProducer) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let local = socket.local_addr().unwrap();
    let (producer, consumer) = producer_ingress(8, 9).unwrap();
    let (peer, _) = crate::client::IaxPeer::from_inbound(
        Arc::new(socket),
        consumer,
        local,
        "127.0.0.1:4569".parse().unwrap(),
        9,
        10,
        crate::codec::IAX_FORMAT_ULAW,
    )
    .unwrap();
    (Box::new(peer), producer)
}

#[test]
fn async_descriptor_enables_server_idempotently_and_retains_its_runtime() {
    use crate::{async_ffi::AsyncDescriptor, ffi};
    use std::{
        ffi::c_void,
        mem::{offset_of, size_of},
        ptr,
    };
    let api = unsafe { &*crate::async_ffi::rptadv_iax2_async_descriptor_v1() };
    assert_eq!(api.struct_size as usize, size_of::<AsyncDescriptor>());
    assert_eq!(
        offset_of!(AsyncDescriptor, peer_configure_jitter),
        24 + 5 * size_of::<usize>()
    );
    assert_eq!(
        offset_of!(AsyncDescriptor, server_enable),
        24 + 6 * size_of::<usize>()
    );
    let server_api = unsafe { &*ffi::rptadv_iax2_server_descriptor_v1() };
    let address = b"127.0.0.1:0";
    let nodes = b"524950";
    let options = ffi::rptadv_iax2_server_options_v1 {
        struct_size: size_of::<ffi::rptadv_iax2_server_options_v1>() as u32,
        abi_version: ffi::RPTADV_IAX2_SERVER_ABI_VERSION,
        bind_address: address.as_ptr(),
        bind_address_length: address.len(),
        local_nodes: nodes.as_ptr(),
        local_nodes_length: nodes.len(),
    };
    let mut runtime = ptr::null_mut();
    let mut server = ptr::null_mut();
    unsafe {
        assert_eq!((api.runtime_create)(&mut runtime), 0);
        assert_eq!(server_api.bind.unwrap()(&options, &mut server), 0);
        assert_eq!((api.server_enable)(ptr::null_mut(), server), -1);
        assert_eq!((api.server_enable)(runtime, ptr::null_mut()), -1);
        assert_eq!(
            (api.peer_configure_jitter)(ptr::null_mut(), ptr::null::<c_void>()),
            -1
        );
        assert_eq!((api.server_enable)(runtime, server), 0);
        assert_eq!((api.server_enable)(runtime, server), 0);
        (api.runtime_destroy)(runtime);
        server_api.destroy.unwrap()(server);
    }
}

#[test]
fn peer_observation_validates_only_output_prefix_before_touching_the_record() {
    use crate::{async_ffi::AsyncDescriptor, client::IaxPeerObservation};
    use std::{
        ffi::c_void,
        mem::{offset_of, size_of},
        ptr,
    };
    let api = unsafe { &*crate::async_ffi::rptadv_iax2_async_descriptor_v1() };
    assert_eq!(size_of::<IaxPeerObservation>(), 112);
    assert_eq!(
        offset_of!(AsyncDescriptor, peer_observe),
        24 + 7 * size_of::<usize>()
    );
    let (mut peer, _producer) = inbound_peer();
    let peer = (&mut *peer as *mut crate::client::IaxPeer).cast::<c_void>();
    let mut short = [8_u32, 1];
    let mut wrong_abi = [112_u32, 2];
    let mut output = [0_u64; 14];
    output[0] = (1_u64 << 32) | 112;
    let before = output;
    unsafe {
        assert_eq!((api.peer_observe)(peer, ptr::null_mut()), -1);
        assert_eq!((api.peer_observe)(peer, short.as_mut_ptr().cast()), -1);
        assert_eq!((api.peer_observe)(peer, wrong_abi.as_mut_ptr().cast()), -1);
        assert_eq!(
            (api.peer_observe)(ptr::null_mut(), output.as_mut_ptr().cast()),
            -1
        );
        assert_eq!((api.peer_observe)(peer, output.as_mut_ptr().cast()), -1);
    }
    assert_eq!(short, [8, 1]);
    assert_eq!(wrong_abi, [112, 2]);
    assert_eq!(output, before);
}

#[test]
fn peer_observation_copies_real_shared_mailbox_overflow_counts() {
    use crate::client::IaxPeerObservation;
    let fixture = crate::jitter::fixture::Fixture::new();
    let api = unsafe { &*crate::async_ffi::rptadv_iax2_async_descriptor_v1() };
    let (mut peer, mut producer) = inbound_peer();
    let peer_pointer = (&mut *peer as *mut crate::client::IaxPeer).cast();
    assert_eq!(
        unsafe { (api.peer_configure_jitter)(peer_pointer, fixture.descriptor()) },
        0
    );
    for _ in 0..8 {
        producer
            .try_push("127.0.0.1:4569".parse().unwrap(), &[1])
            .unwrap();
    }
    for _ in 0..3 {
        assert_eq!(
            producer.try_push("127.0.0.1:4569".parse().unwrap(), &[1]),
            Err(crate::ingress::IngressPushError::Full)
        );
    }
    let mut output: IaxPeerObservation = unsafe { std::mem::zeroed() };
    output.struct_size = std::mem::size_of::<IaxPeerObservation>() as u32;
    output.abi_version = 1;
    assert_eq!(unsafe { (api.peer_observe)(peer_pointer, &mut output) }, 0);
    assert_eq!(output.ingress_queued_packets, 8);
    assert_eq!(output.ingress_capacity_packets, 8);
    assert_eq!(output.ingress_overflow_drops, 3);
}

#[test]
fn async_peer_rejects_reattachment_after_detach_without_retaining_context() {
    use std::{ffi::c_void, ptr};
    unsafe extern "C" fn step(context: *mut c_void) -> i32 {
        unsafe { &*context.cast::<AtomicUsize>() }.fetch_add(1, Ordering::Relaxed);
        -1
    }
    let api = unsafe { &*crate::async_ffi::rptadv_iax2_async_descriptor_v1() };
    let (mut peer, _producer) = inbound_peer();
    let calls = AtomicUsize::new(0);
    let mut runtime = ptr::null_mut();
    let mut registration = ptr::null_mut();
    unsafe {
        assert_eq!((api.runtime_create)(&mut runtime), 0);
        assert_eq!(
            (api.peer_attach)(
                runtime,
                (&mut *peer as *mut crate::client::IaxPeer).cast(),
                Some(step),
                (&calls as *const AtomicUsize).cast_mut().cast(),
                &mut registration
            ),
            0
        );
        (api.peer_detach)(registration);
        let before = calls.load(Ordering::Relaxed);
        let result = (api.peer_attach)(
            runtime,
            (&mut *peer as *mut crate::client::IaxPeer).cast(),
            Some(step),
            (&calls as *const AtomicUsize).cast_mut().cast(),
            &mut registration,
        );
        if !registration.is_null() {
            (api.peer_detach)(registration);
        }
        (api.runtime_destroy)(runtime);
        assert_eq!(result, -1, "async attachment is one-shot per peer");
        assert!(registration.is_null());
        assert_eq!(calls.load(Ordering::Relaxed), before);
    }
}

#[test]
fn detach_waits_for_callback_safe_stop_after_runtime_owner_is_released() {
    use std::{ffi::c_void, ptr, sync::atomic::AtomicPtr};

    struct Context {
        registration: AtomicPtr<c_void>,
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
        stopped: mpsc::SyncSender<()>,
        calls: AtomicUsize,
    }

    unsafe extern "C" fn step(context: *mut c_void) -> i32 {
        let context = unsafe { &*context.cast::<Context>() };
        context.calls.fetch_add(1, Ordering::Relaxed);
        if context.entered.send(()).is_err()
            || context
                .release
                .recv_timeout(Duration::from_secs(2))
                .is_err()
        {
            return -1;
        }
        let api = unsafe { &*crate::async_ffi::rptadv_iax2_async_descriptor_v1() };
        unsafe { (api.peer_stop)(context.registration.load(Ordering::Acquire)) };
        let _ = context.stopped.send(());
        0
    }

    let api = unsafe { &*crate::async_ffi::rptadv_iax2_async_descriptor_v1() };
    let (mut peer, _producer) = inbound_peer();
    let (entered, waiting) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let (stopped, stopping) = mpsc::sync_channel(1);
    let context = Context {
        registration: AtomicPtr::new(ptr::null_mut()),
        entered,
        release: released,
        stopped,
        calls: AtomicUsize::new(0),
    };
    let mut runtime = ptr::null_mut();
    let mut registration = ptr::null_mut();
    unsafe {
        assert_eq!((api.runtime_create)(&mut runtime), 0);
        assert_eq!(
            (api.peer_attach)(
                runtime,
                (&mut *peer as *mut crate::client::IaxPeer).cast(),
                Some(step),
                (&context as *const Context).cast_mut().cast(),
                &mut registration
            ),
            0
        );
        context.registration.store(registration, Ordering::Release);
        waiting.recv_timeout(Duration::from_secs(2)).unwrap();
        // The registration retains its own runtime owner through the final join.
        (api.runtime_destroy)(runtime);
    }
    let registration = registration as usize;
    let (detaching, detach_started) = mpsc::sync_channel(1);
    let (detached, detach_finished) = mpsc::sync_channel(1);
    let control = std::thread::spawn(move || {
        detaching.send(()).unwrap();
        unsafe { (api.peer_detach)(registration as *mut c_void) };
        detached.send(()).unwrap();
    });
    detach_started.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(
        detach_finished
            .recv_timeout(Duration::from_millis(20))
            .is_err()
    );
    release.send(()).unwrap();
    stopping.recv_timeout(Duration::from_secs(2)).unwrap();
    detach_finished
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    control.join().unwrap();
    assert_eq!(context.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn peer_driver_drains_coalesced_work_without_overlapping_callbacks() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (mut producer, mut consumer) = producer_ingress(128, 1).unwrap();
    let wake = consumer.wake();
    let (sent, received) = mpsc::channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let driver = PeerDriver::attach(runtime.handle(), wake, move || {
        calls.fetch_add(1, Ordering::Relaxed);
        if let Some(packet) = consumer.try_pop() {
            sent.send(packet.payload()[0]).unwrap();
        }
        true
    });
    for value in 0..100 {
        producer
            .try_push("127.0.0.1:4569".parse().unwrap(), &[value])
            .unwrap();
    }
    for value in 0..100 {
        assert_eq!(
            received.recv_timeout(Duration::from_secs(2)).unwrap(),
            value
        );
    }
    driver.detach();
    let stopped = observed.load(Ordering::Acquire);
    producer
        .try_push("127.0.0.1:4569".parse().unwrap(), &[100])
        .unwrap_err();
    assert_eq!(observed.load(Ordering::Acquire), stopped);
}

#[test]
fn stalled_peer_does_not_serialize_another_peer_and_detach_waits() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (_producer_a, consumer_a) = producer_ingress(1, 1).unwrap();
    let (_producer_b, consumer_b) = producer_ingress(1, 2).unwrap();
    let (entered, waiting) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let driver_a = PeerDriver::attach(runtime.handle(), consumer_a.wake(), move || {
        entered.send(()).unwrap();
        released.recv().unwrap();
        false
    });
    waiting.recv_timeout(Duration::from_secs(2)).unwrap();
    let (progress, progressed) = mpsc::sync_channel(1);
    let driver_b = PeerDriver::attach(runtime.handle(), consumer_b.wake(), move || {
        progress.send(()).unwrap();
        false
    });
    progressed.recv_timeout(Duration::from_secs(2)).unwrap();
    driver_b.detach();
    driver_a.stop();
    assert!(
        !driver_a.is_finished(),
        "stop does not pretend an active callback finished"
    );
    release.send(()).unwrap();
    driver_a.detach();
}

#[test]
fn pending_mailbox_without_callback_progress_waits_for_timer_instead_of_spinning() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (mut producer, consumer) = producer_ingress(2, 1).unwrap();
    producer
        .try_push("127.0.0.1:4569".parse().unwrap(), &[1])
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let (entered, waiting) = mpsc::sync_channel(1);
    let started = std::time::Instant::now();
    let driver = PeerDriver::attach(runtime.handle(), consumer.wake(), move || {
        if calls.fetch_add(1, Ordering::Relaxed) == 0 {
            entered.send(()).unwrap();
        }
        // Downstream PCM backpressure prevents this step from consuming ingress.
        true
    });
    waiting.recv_timeout(Duration::from_secs(2)).unwrap();
    std::thread::sleep(Duration::from_millis(80));
    driver.detach();
    let timer_turns = started.elapsed().as_nanos() / crate::async_driver::TIMER_INTERVAL.as_nanos();
    let count = observed.load(Ordering::Relaxed);
    assert!(
        count as u128 <= timer_turns + 3,
        "no-progress callback spun {count} times over {timer_turns} timer periods"
    );
    assert_eq!(consumer.wake().pending(), 1);
}

#[test]
fn future_media_deadline_wakes_without_ingress_at_the_concealment_cadence() {
    let quantum = Duration::from_nanos(
        1_000_000_000 * u64::from(crate::jitter::CONCEALMENT_SPAN)
            / u64::from(crate::jitter::CLOCK_RATE_HZ),
    );
    assert_eq!(quantum, Duration::from_millis(10));
    assert!(crate::async_driver::TIMER_INTERVAL <= quantum);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (_producer, consumer) = producer_ingress(1, 1).unwrap();
    let (progress, progressed) = mpsc::sync_channel(1);
    let deadline = std::time::Instant::now() + quantum;
    let driver = PeerDriver::attach(runtime.handle(), consumer.wake(), move || {
        let now = std::time::Instant::now();
        if now < deadline {
            return true;
        }
        progress.send(now).unwrap();
        false
    });
    let delivered = progressed.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(delivered >= deadline, "future media is not delivered early");
    driver.detach();
}

#[test]
fn peer_scaling_100_and_1000_keeps_fixed_workers_and_isolates_stalled_flood() {
    fn resident_kib() -> Option<usize> {
        std::fs::read_to_string("/proc/self/status")
            .ok()?
            .lines()
            .find_map(|line| {
                line.strip_prefix("VmRSS:")?
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()
            })
    }
    for peer_count in [100, 1000] {
        let workers = Arc::new(AtomicUsize::new(0));
        let started_workers = workers.clone();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .on_thread_start(move || {
                started_workers.fetch_add(1, Ordering::Relaxed);
            })
            .enable_all()
            .build()
            .unwrap();
        let started = std::time::Instant::now();
        let rss_before = resident_kib();
        let (progress, progressed) = mpsc::channel();
        let (entered, waiting) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let mut released = Some(released);
        let mut drivers = Vec::with_capacity(peer_count);
        let mut producers = Vec::with_capacity(peer_count);
        for peer in 0..peer_count {
            let (producer, mut consumer) = producer_ingress(4, peer as u64).unwrap();
            let progress = progress.clone();
            let entered = entered.clone();
            let mut block = if peer == 0 { released.take() } else { None };
            let driver = PeerDriver::attach(runtime.handle(), consumer.wake(), move || {
                if let Some(release) = block.take() {
                    entered.send(()).unwrap();
                    release.recv_timeout(Duration::from_secs(20)).unwrap();
                }
                if let Some(packet) = consumer.try_pop() {
                    assert_eq!(packet.payload(), [1]);
                    progress.send(peer).unwrap();
                    false
                } else {
                    true
                }
            });
            producers.push(producer);
            drivers.push(driver);
        }
        waiting.recv_timeout(Duration::from_secs(20)).unwrap();
        let rss_attached = resident_kib();
        let remote = "127.0.0.1:4569".parse().unwrap();
        let mut dropped = 0;
        for _ in 0..10_000 {
            match producers[0].try_push(remote, &[1]) {
                Ok(()) => (),
                Err(crate::ingress::IngressPushError::Full) => dropped += 1,
                Err(error) => panic!("unexpected admission failure: {error:?}"),
            }
        }
        assert_eq!(producers[0].available_slots(), 0);
        assert_eq!(dropped, 9_996);
        for producer in &mut producers[1..] {
            producer.try_push(remote, &[1]).unwrap();
        }
        let mut seen = vec![false; peer_count];
        for _ in 1..peer_count {
            let peer = progressed.recv_timeout(Duration::from_secs(20)).unwrap();
            assert_ne!(
                peer, 0,
                "stalled peer must remain parked during healthy progress"
            );
            assert!(!std::mem::replace(&mut seen[peer], true));
        }
        assert!(seen[1..].iter().all(|seen| *seen));
        release.send(()).unwrap();
        assert_eq!(progressed.recv_timeout(Duration::from_secs(20)).unwrap(), 0);
        for driver in drivers {
            driver.detach();
        }
        assert_eq!(workers.load(Ordering::Relaxed), 4);
        println!(
            "peer-scaling peers={peer_count} workers=4 capacity_per_peer=4 healthy_progress={} flood_dropped={dropped} rss_before_kib={rss_before:?} rss_attached_kib={rss_attached:?} elapsed_ms={}",
            peer_count - 1,
            started.elapsed().as_millis()
        );
    }
}
