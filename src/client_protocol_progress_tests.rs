//! Proposed protocol-only request exercised through the real owner and UDP.
use super::*;
use crate::client::{EgressRetirement, IaxPeerEvent, SourceTimeInput, TimedPeerEvent};
use crate::protocol::parse_full_frame_packet;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};

/// The new request is represented locally so this test compiles against alpha12.
#[repr(C)]
struct ServiceRequest {
    prefix: crate::ffi::rptadv_iax2_timed_event_v1,
    request_flags: u32,
    reserved: u32,
}

#[derive(Debug)]
enum Report {
    Service {
        status: i32,
        event_kind: u32,
        source_start: u64,
        retirement: Option<EgressRetirement>,
        held: TimedPeerEvent,
    },
    Delivered(TimedPeerEvent, Vec<f32>),
    Failed(String),
    Finished,
}

fn digit(sequence: u8, symbol: u8) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 5678,
            destination_call_number: 1234,
            retransmission: false,
            timestamp: 20,
            outgoing_sequence: sequence,
            incoming_sequence: 1,
            frame_type: 1,
            subclass: symbol,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap()
}

/// Removing protocol service, consuming a later source event, or synthesizing
/// ACK credit must fail this test. The only artificial input is sink refusal.
#[test]
fn refused_digit_keeps_real_ack_progress_and_later_source_order() {
    let _timestamp_probe = crate::source_time::tests::timestamp_probe();
    let runtime = crate::provider_tests::runtime();
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let local = peer.local_addr().unwrap();
    let origin = Instant::now();
    let input = SourceTimeInput {
        host_clock_epoch: 7,
        reference_now_ns: 5_000_000_000,
        acknowledged_media_epoch: 1,
    };
    remote.send_to(&digit(1, b'5'), local).unwrap();
    let held = loop {
        let event = peer.poll_timed(&mut [], &mut [0; 1], input).unwrap();
        if event.event != IaxPeerEvent::None {
            break event;
        }
        assert!(origin.elapsed() < Duration::from_secs(2));
        std::thread::yield_now();
    };
    assert_eq!(held.event, IaxPeerEvent::Digit(b'5'));
    assert_eq!(
        (held.media_epoch, held.source_start, held.born_ns),
        (1, 0, None)
    );
    assert!(!held.discontinuity);

    peer.send_prepared_audio(&[0xff; 160], 160, 0).unwrap();
    let mut bytes = [0; 2048];
    loop {
        let (count, _) = remote.recv_from(&mut bytes).unwrap();
        let frame = crate::protocol::parse_full_frame_packet(&bytes[..count]).unwrap();
        if frame.header.frame_type == 2 {
            assert_eq!(frame.payload, &[0xff; 160]);
            assert_eq!(frame.header.outgoing_sequence, 1);
            break;
        }
    }
    assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Pending);
    remote.send_to(&digit(2, b'6'), local).unwrap();

    let (wake, ingress) = peer.prepare_async_ingress(runtime.handle()).unwrap();
    let (socket, producer, owner) = ingress.unwrap();
    let pump = crate::async_driver::DatagramPump::from_socket(
        runtime.handle(),
        socket,
        remote.local_addr().unwrap(),
        producer,
        Some(owner),
    );
    let permit = Arc::new(AtomicBool::new(false));
    let may_accept = Arc::clone(&permit);
    let (sender, reports) = mpsc::channel();
    let mut held_pending = true;
    let mut delivered = 0;
    let mut completed = None;
    let api = unsafe { &*crate::ffi::rptadv_iax2_client_descriptor_v2() };
    let driver = crate::async_driver::PeerDriver::attach(runtime.handle(), wake, move || {
        peer.begin_turn();
        let reference = 5_000_000_000 + origin.elapsed().as_nanos() as u64;
        let mut request = ServiceRequest {
            prefix: crate::ffi::rptadv_iax2_timed_event_v1 {
                struct_size: std::mem::size_of::<ServiceRequest>() as u32,
                abi_version: 2,
                host_clock_epoch: 7,
                reference_now_ns: reference,
                acknowledged_media_epoch: 1,
                ..Default::default()
            },
            request_flags: 1,
            reserved: 0,
        };
        let status = unsafe {
            api.poll_timed.unwrap()(
                (&mut peer as *mut IaxPeer).cast(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::from_mut(&mut request).cast(),
            )
        };
        let retirement = if status == 0 {
            completed.or_else(|| peer.retire_egress().ok())
        } else {
            None
        };
        if matches!(retirement, Some(EgressRetirement::Complete(_))) {
            completed = retirement;
        }
        sender
            .send(Report::Service {
                status,
                event_kind: request.prefix.event_kind,
                source_start: request.prefix.source_start,
                retirement,
                held,
            })
            .ok()?;
        if status != 0 || retirement.is_none() {
            return None;
        }
        if may_accept.load(Ordering::Acquire) {
            if held_pending {
                sender.send(Report::Delivered(held, Vec::new())).ok()?;
                held_pending = false;
                delivered += 1;
            }
            let mut pcm = [0.0; 160];
            let event = match peer.poll_timed(
                &mut pcm,
                &mut [0; 1],
                SourceTimeInput {
                    reference_now_ns: reference,
                    ..input
                },
            ) {
                Ok(event) => event,
                Err(error) => {
                    sender.send(Report::Failed(format!("{error:?}"))).ok()?;
                    return None;
                }
            };
            if event.event != IaxPeerEvent::None {
                let count = match event.event {
                    IaxPeerEvent::Audio(count) => count,
                    _ => 0,
                };
                sender
                    .send(Report::Delivered(event, pcm[..count].to_vec()))
                    .ok()?;
                delivered += 1;
            }
            if delivered == 4 {
                match peer.poll_timed(&mut pcm, &mut [0; 1], input) {
                    Ok(extra) if extra.event == IaxPeerEvent::None => {
                        sender.send(Report::Finished).ok()?;
                    }
                    other => {
                        sender
                            .send(Report::Failed(format!(
                                "source delivered more than once: {other:?}"
                            )))
                            .ok()?;
                    }
                }
                return None;
            }
        }
        peer.set_product_deadline(10_000_000).ok()?;
        Some(peer.wait_state())
    });

    // Always quiesce the retained owner/pump before any assertion unwinds.
    let deadline = Instant::now() + Duration::from_secs(2);
    let next = || {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| "absolute owner regression deadline expired".to_owned())?;
        reports
            .recv_timeout(remaining)
            .map_err(|error| error.to_string())
    };
    let result = (|| -> Result<Vec<(TimedPeerEvent, Vec<f32>)>, String> {
        for _ in 0..3 {
            match next()? {
                Report::Service {
                    status: 0,
                    event_kind: crate::ffi::RPTADV_IAX2_EVENT_NONE,
                    source_start: 0,
                    retirement: Some(EgressRetirement::Pending),
                    held: same,
                } if same == held => (),
                report => {
                    return Err(format!(
                        "SERVICE_ONLY must preserve refusal and service protocol: {report:?}"
                    ));
                }
            }
        }
        let ack = serialize_full_frame(
            &FullFrameHeader {
                source_call_number: 5678,
                destination_call_number: 1234,
                retransmission: false,
                timestamp: 0,
                outgoing_sequence: 99,
                incoming_sequence: 2,
                frame_type: 6,
                subclass: crate::protocol::IaxCommand::Ack.subclass_value() as u8,
                subclass_is_log: false,
            },
            &[],
        )
        .unwrap();
        remote.send_to(&ack, local).map_err(|e| e.to_string())?;
        let voice = crate::protocol::serialize_mini_frame(
            &crate::protocol::MiniFrameHeader {
                source_call_number: 5678,
                timestamp: 40,
            },
            &[0x80; 160],
        )
        .unwrap();
        remote.send_to(&voice, local).map_err(|e| e.to_string())?;
        remote
            .send_to(&digit(3, b'7'), local)
            .map_err(|e| e.to_string())?;

        loop {
            match next()? {
                Report::Service {
                    status: 0,
                    event_kind: crate::ffi::RPTADV_IAX2_EVENT_NONE,
                    source_start: 0,
                    retirement: Some(retirement),
                    held: same,
                } if same == held => match retirement {
                    EgressRetirement::Pending => (),
                    EgressRetirement::Complete(2) => break,
                    other => return Err(format!("unexpected real retirement receipt: {other:?}")),
                },
                report => {
                    return Err(format!(
                        "refused source changed before real ACK retirement: {report:?}"
                    ));
                }
            }
        }
        permit.store(true, Ordering::Release);
        driver.wake();
        let mut events = Vec::new();
        let mut finished = false;
        while !finished {
            match next()? {
                Report::Delivered(event, pcm) => events.push((event, pcm)),
                Report::Service {
                    status: 0,
                    event_kind: crate::ffi::RPTADV_IAX2_EVENT_NONE,
                    ..
                } => (),
                Report::Failed(error) => return Err(error),
                Report::Finished => finished = true,
                report => return Err(format!("source release failed: {report:?}")),
            }
        }
        if events.len() != 4 {
            return Err(format!(
                "expected four source items, received {}",
                events.len()
            ));
        }
        Ok(events)
    })();
    driver.detach();
    pump.detach();

    let events = result.expect("real ACK progress must not depend on source acceptance");
    assert_eq!(
        events
            .iter()
            .map(|(event, _)| event.event)
            .collect::<Vec<_>>(),
        [
            IaxPeerEvent::Digit(b'5'),
            IaxPeerEvent::Digit(b'6'),
            IaxPeerEvent::Audio(160),
            IaxPeerEvent::Digit(b'7'),
        ]
    );
    assert_eq!(events[0].0, held);
    assert_eq!(
        events
            .iter()
            .map(|(event, _)| event.source_start)
            .collect::<Vec<_>>(),
        [0, 0, 0, 160]
    );
    assert_eq!(events[2].1.len(), 160);
    assert!(
        events[2].0.born_ns.is_some(),
        "genuine original UDP receipt must survive staging"
    );
}

/// Rejected request shapes must not enter timed mode or consume real ACK credit.
#[test]
fn invalid_service_request_leaves_protocol_and_source_state_unchanged() {
    for (size, version, flags, reserved) in [
        (72, 2, 1, 0),
        (80, u32::MAX, 1, 0),
        (80, 2, 2, 0),
        (80, 2, 1, 1),
    ] {
        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        remote
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut peer = linked_peer(remote.local_addr().unwrap());
        peer.send_prepared_audio(&[0xff; 160], 160, 0).unwrap();
        remote.recv_from(&mut [0; 2048]).unwrap();
        assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Pending);
        let ack = serialize_full_frame(
            &FullFrameHeader {
                source_call_number: 5678,
                destination_call_number: 1234,
                retransmission: false,
                timestamp: 0,
                outgoing_sequence: 99,
                incoming_sequence: 2,
                frame_type: 6,
                subclass: crate::protocol::IaxCommand::Ack.subclass_value() as u8,
                subclass_is_log: false,
            },
            &[],
        )
        .unwrap();
        remote.send_to(&ack, peer.local_addr().unwrap()).unwrap();
        let mut request = ServiceRequest {
            prefix: crate::ffi::rptadv_iax2_timed_event_v1 {
                struct_size: size,
                abi_version: version,
                host_clock_epoch: 7,
                reference_now_ns: 5_000_000_000,
                acknowledged_media_epoch: 1,
                ..Default::default()
            },
            request_flags: flags,
            reserved,
        };
        let api = unsafe { &*crate::ffi::rptadv_iax2_client_descriptor_v2() };
        assert_eq!(
            unsafe {
                api.poll_timed.unwrap()(
                    (&mut peer as *mut IaxPeer).cast(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::from_mut(&mut request).cast(),
                )
            },
            -1
        );
        assert_eq!(
            (
                request.prefix.host_clock_epoch,
                request.prefix.reference_now_ns,
                request.prefix.acknowledged_media_epoch,
                request.request_flags,
                request.reserved,
            ),
            (7, 5_000_000_000, 1, flags, reserved)
        );
        assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Pending);
        assert_eq!(
            peer.poll_event(&mut [], &mut []).unwrap(),
            IaxPeerEvent::None
        );
        assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Complete(2));
    }
}

fn input() -> SourceTimeInput {
    SourceTimeInput {
        host_clock_epoch: 7,
        reference_now_ns: 5_000_000_000,
        acknowledged_media_epoch: 1,
    }
}

fn service(peer: &mut IaxPeer) -> Result<TimedPeerEvent, DialError> {
    peer.poll_timed_private(
        &mut [],
        &mut [],
        input(),
        crate::client::SourceDelivery::ServiceOnly,
    )
}

fn control(sequence: u8, acknowledgement: u8, command: crate::protocol::IaxCommand) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 5678,
            destination_call_number: 1234,
            retransmission: false,
            timestamp: 0,
            outgoing_sequence: sequence,
            incoming_sequence: acknowledgement,
            frame_type: 6,
            subclass: command.subclass_value() as u8,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap()
}

fn mini(timestamp: u16, value: u8) -> Vec<u8> {
    crate::protocol::serialize_mini_frame(
        &crate::protocol::MiniFrameHeader {
            source_call_number: 5678,
            timestamp,
        },
        &[value; 160],
    )
    .unwrap()
}

fn full_voice(sequence: u8, acknowledgement: u8, timestamp: u32, value: u8) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 5678,
            destination_call_number: 1234,
            retransmission: false,
            timestamp,
            outgoing_sequence: sequence,
            incoming_sequence: acknowledgement,
            frame_type: 2,
            subclass: 4,
            subclass_is_log: false,
        },
        &[value; 160],
    )
    .unwrap()
}

fn next_source(peer: &mut IaxPeer, pcm: &mut [f32]) -> TimedPeerEvent {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let event = peer.poll_timed(pcm, &mut [0; 1], input()).unwrap();
        if event.event != IaxPeerEvent::None {
            return event;
        }
        assert!(
            Instant::now() < deadline,
            "no source before absolute deadline"
        );
        std::thread::yield_now();
    }
}

#[test]
fn service_preserves_host_and_provider_pcm_suffix_birth_until_real_ack_retirement() {
    let _probe = crate::source_time::tests::timestamp_probe();
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let local = peer.local_addr().unwrap();
    remote.send_to(&mini(20, 0x80), local).unwrap();
    let mut held = [0.0; 40];
    let first = next_source(&mut peer, &mut held);
    assert_eq!(first.event, IaxPeerEvent::Audio(40));
    assert_eq!(first.source_start, 0);
    let birth = first.born_ns.expect("original Linux receipt");
    let retained = held;
    // A host accepted20; the exact remaining20 stays outside the provider.
    let accepted = 20;
    peer.send_prepared_audio(&[0xff; 160], 160, 0).unwrap();
    assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Pending);
    remote.send_to(&digit(1, b'5'), local).unwrap();
    remote
        .send_to(&control(99, 2, crate::protocol::IaxCommand::Ack), local)
        .unwrap();
    remote.send_to(&mini(40, 0xff), local).unwrap();
    for _ in 0..3 {
        let progress = service(&mut peer).unwrap();
        assert_eq!(
            (progress.event, progress.source_start),
            (IaxPeerEvent::None, 40)
        );
        assert_eq!((held, accepted), (retained, 20));
        assert_eq!(peer.direct_pcm.remaining(), 120);
        assert_eq!(
            peer.direct_pcm
                .span
                .birth(7, 99_000_000_000, Instant::now()),
            Some(birth)
        );
    }
    assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Complete(2));
    let mut released = retained.to_vec();
    for source_start in [40, 80, 120] {
        let mut suffix = [0.0; 40];
        let event = next_source(&mut peer, &mut suffix);
        assert_eq!(
            (event.event, event.source_start, event.born_ns),
            (IaxPeerEvent::Audio(40), source_start, Some(birth))
        );
        released.extend_from_slice(&suffix);
    }
    assert_eq!(released.len(), 160);
    assert!(released.iter().all(|sample| *sample == retained[0]));
    let digit = next_source(&mut peer, &mut [0.0; 160]);
    assert_eq!(
        (digit.event, digit.source_start),
        (IaxPeerEvent::Digit(b'5'), 160)
    );
    let later = next_source(&mut peer, &mut [0.0; 160]);
    assert_eq!(
        (later.event, later.source_start),
        (IaxPeerEvent::Audio(160), 160)
    );
}

#[test]
fn full_source_queue_services_real_ack_then_fails_before_accepting_sixty_fifth_digit() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote.set_nonblocking(true).unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let local = peer.local_addr().unwrap();
    peer.send_prepared_audio(&[0xff; 160], 160, 0).unwrap();
    assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Pending);
    for sequence in 1..=64 {
        remote.send_to(&digit(sequence, b'5'), local).unwrap();
    }
    service(&mut peer).unwrap();
    assert_eq!(peer.pending_events.len(), 64);
    assert_eq!(peer.pending_events.capacity(), 64);
    remote
        .send_to(&control(99, 2, crate::protocol::IaxCommand::Ack), local)
        .unwrap();
    remote.send_to(&digit(64, b'5'), local).unwrap();
    service(&mut peer).unwrap();
    assert_eq!(peer.pending_events.len(), 64);
    assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Complete(2));
    while remote.recv_from(&mut [0; 2048]).is_ok() {}
    remote.send_to(&digit(65, b'6'), local).unwrap();
    assert!(matches!(
        service(&mut peer),
        Err(DialError::EarlyEventsFull)
    ));
    assert_eq!(
        peer.pending_events.len(),
        64,
        "accepted control is not evicted"
    );
    assert_eq!(
        remote.recv_from(&mut [0; 2048]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(
        peer.poll_timed(&mut [0.0; 160], &mut [0; 1], input())
            .is_err()
    );
    assert!(
        peer.prepare_audio(&[0.0; 160], &mut [0; 160], false)
            .is_err()
    );
    assert!(peer.reset_encoder().is_err());
    assert!(peer.send_prepared_audio(&[0xff; 160], 160, 20).is_err());
    assert!(peer.send_text(b"must not escape").is_err());
    assert!(peer.send_dtmf(b'5').is_err());
    assert!(
        peer.retire_egress().is_err(),
        "terminal invalidation is not a TX receipt"
    );
}

#[test]
fn service_timeout_and_real_remote_hangup_fence_source_and_tx_retirement() {
    for hangup in [false, true] {
        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut peer = linked_peer(remote.local_addr().unwrap());
        peer.send_prepared_audio(&[0xff; 160], 160, 0).unwrap();
        assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Pending);
        remote
            .send_to(&digit(1, b'5'), peer.local_addr().unwrap())
            .unwrap();
        service(&mut peer).unwrap();
        if hangup {
            remote
                .send_to(
                    &control(2, 1, crate::protocol::IaxCommand::Hangup),
                    peer.local_addr().unwrap(),
                )
                .unwrap();
            assert!(matches!(service(&mut peer), Err(DialError::Hangup)));
        } else {
            // Shorten only the existing test frame's retry deadline, never source age
            // or ACK state. Let the real clock expire it before the owner services it.
            peer.pending_reliable[0].expires_at = Instant::now() + Duration::from_millis(5);
            std::thread::sleep(Duration::from_millis(10));
            assert!(matches!(service(&mut peer), Err(DialError::Timeout)));
        }
        assert_eq!(peer.pending_events.len(), 1);
        assert!(peer.retire_egress().is_err());
        assert!(
            peer.prepare_audio(&[0.0; 160], &mut [0; 160], false)
                .is_err()
        );
        assert!(peer.send_dtmf(b'5').is_err());
        assert!(service(&mut peer).is_err());
    }
}

#[test]
fn deferred_original_receipt_expires_media_without_erasing_queued_digit() {
    for received_before_wait in [false, true] {
        let _probe = crate::source_time::tests::timestamp_probe();
        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut peer = linked_peer(remote.local_addr().unwrap());
        remote
            .send_to(&mini(20, 0x80), peer.local_addr().unwrap())
            .unwrap();
        remote
            .send_to(&digit(1, b'5'), peer.local_addr().unwrap())
            .unwrap();
        if received_before_wait {
            let first = service(&mut peer).unwrap();
            assert_eq!(first.event, IaxPeerEvent::None);
            assert_eq!(peer.pending_events.len(), 2);
            assert!(peer.pending_events.front().unwrap().receipt().is_some());
        } else {
            assert!(peer.pending_events.is_empty());
        }
        std::thread::sleep(Duration::from_millis(510));
        let expired = service(&mut peer).unwrap();
        assert!(expired.discontinuity);
        assert_eq!((expired.media_epoch, expired.source_start), (2, 0));
        assert_eq!(peer.pending_events.len(), 1);
        let digit = next_source(&mut peer, &mut [0.0; 160]);
        assert_eq!(digit.event, IaxPeerEvent::Digit(b'5'));
        assert!(digit.discontinuity);
        assert_eq!(digit.born_ns, None);
        assert_eq!(
            peer.poll_timed(&mut [0.0; 160], &mut [0; 1], input())
                .unwrap()
                .event,
            IaxPeerEvent::None
        );
    }
}

#[test]
fn invalid_private_activation_keeps_early_text_and_existing_source_mode_unchanged() {
    for early_pcm in [false, true] {
        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut peer = linked_peer(remote.local_addr().unwrap());
        // Neither direct nor accepted early generic PCM becomes20ms phone media.
        let pcm = super::super::PacketPcm {
            samples: vec![0.5; 320],
            position: 20,
            span: crate::source_time::Span::default(),
        };
        peer.pending_events
            .push_back(super::super::PendingSource::Ready(
                super::super::PendingEvent {
                    event: IaxPeerEvent::Text(4),
                    pcm: super::super::PacketPcm::default(),
                    text: b"kept".to_vec(),
                },
            ));
        if early_pcm {
            peer.pending_events
                .push_back(super::super::PendingSource::Ready(
                    super::super::PendingEvent {
                        event: IaxPeerEvent::Audio(320),
                        pcm,
                        text: Vec::new(),
                    },
                ));
        } else {
            peer.direct_pcm = pcm;
        }
        assert!(matches!(service(&mut peer), Err(DialError::InvalidOptions)));
        assert!(!peer.service.active);
        if early_pcm {
            let super::super::PendingSource::Ready(pending) = &peer.pending_events[1] else {
                unreachable!()
            };
            assert_eq!(pending.pcm.remaining(), 300);
        } else {
            assert_eq!(peer.direct_pcm.remaining(), 300);
        }
        let mut text = [0; 4];
        assert_eq!(
            peer.poll_event(&mut [], &mut text).unwrap(),
            IaxPeerEvent::Text(4)
        );
        assert_eq!(&text, b"kept");
        let mut output = [0.0; 40];
        assert_eq!(
            peer.poll_event(&mut output, &mut []).unwrap(),
            IaxPeerEvent::Audio(40)
        );
        assert_eq!(output, [0.5; 40]);
    }
}

fn installed_jitter() -> libloading::Library {
    let paths = std::fs::read_dir("/usr/lib")
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| {
            entry
                .path()
                .join("rpt_advanced/librptadv_jitter_adapter.so.1")
        })
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 1);
    unsafe { libloading::Library::new(&paths[0]) }.unwrap()
}

fn configure_installed_jitter(peer: &mut IaxPeer, library: &libloading::Library) {
    let descriptor = unsafe {
        library.get::<unsafe extern "C" fn() -> *const std::ffi::c_void>(
            b"rptadv_jitter_adapter_descriptor_v1\0",
        )
    }
    .unwrap();
    unsafe { peer.configure_jitter(descriptor()) }.unwrap();
}

fn radio(sequence: u8, subclass: u8) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 5678,
            destination_call_number: 1234,
            retransmission: false,
            timestamp: 80,
            outgoing_sequence: sequence,
            incoming_sequence: 1,
            frame_type: 4,
            subclass,
            subclass_is_log: false,
        },
        &[],
    )
    .unwrap()
}

#[test]
fn installed_jitter_selected_suffix_stays_before_deferred_radio_effects_and_digit() {
    let _probe = crate::source_time::tests::timestamp_probe();
    let library = installed_jitter();
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    configure_installed_jitter(&mut peer, &library);
    service(&mut peer).unwrap();
    let local = peer.local_addr().unwrap();
    remote.send_to(&mini(20, 0x80), local).unwrap();
    let first = next_source(&mut peer, &mut [0.0; 40]);
    assert_eq!(first.event, IaxPeerEvent::Audio(40));
    let birth = first
        .born_ns
        .expect("installed jitter retains real original receipt");
    peer.send_prepared_audio(&[0xff; 160], 160, 0).unwrap();
    assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Pending);
    remote.send_to(&radio(1, 13), local).unwrap();
    remote.send_to(&radio(2, 12), local).unwrap();
    remote.send_to(&digit(3, b'5'), local).unwrap();
    remote
        .send_to(&control(99, 2, crate::protocol::IaxCommand::Ack), local)
        .unwrap();
    for _ in 0..3 {
        assert_eq!(service(&mut peer).unwrap().event, IaxPeerEvent::None);
    }
    assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Complete(2));
    for offset in [40, 80, 120] {
        let suffix = next_source(&mut peer, &mut [0.0; 40]);
        assert_eq!(
            (suffix.event, suffix.source_start, suffix.born_ns),
            (
                IaxPeerEvent::Audio(40),
                first.source_start + offset,
                Some(birth)
            )
        );
    }
    let remaining = (0..3)
        .map(|_| next_source(&mut peer, &mut [0.0; 160]).event)
        .collect::<Vec<_>>();
    assert_eq!(
        remaining,
        [
            IaxPeerEvent::RadioUnkey,
            IaxPeerEvent::RadioKey,
            IaxPeerEvent::Digit(b'5')
        ]
    );
}

#[test]
fn installed_jitter_unselected_voice_preserves_ordinary_not_due_control_order() {
    for reordered_full in [false, true] {
        let library = installed_jitter();
        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut peer = linked_peer(remote.local_addr().unwrap());
        configure_installed_jitter(&mut peer, &library);
        service(&mut peer).unwrap();
        let packet = if reordered_full {
            peer.send_prepared_audio(&[0xff; 160], 160, 0).unwrap();
            assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Pending);
            // Real future media owns sequence2 while the following digit closes1.
            full_voice(2, 2, 20, 0x80)
        } else {
            mini(20, 0x80)
        };
        let local = peer.local_addr().unwrap();
        remote.send_to(&packet, local).unwrap();
        remote.send_to(&digit(1, b'5'), local).unwrap();
        if reordered_full {
            // The identical retransmission must not create a second source owner.
            remote.send_to(&packet, local).unwrap();
        }
        service(&mut peer).unwrap();
        assert_eq!(peer.pending_events.len(), 2);
        if reordered_full {
            assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Complete(2));
        }
        let control = next_source(&mut peer, &mut [0.0; 160]);
        assert_eq!(
            (control.event, control.source_start),
            (IaxPeerEvent::Digit(b'5'), 0)
        );
        let mut samples = [0.0; 160];
        let media = next_source(&mut peer, &mut samples);
        assert_eq!(
            (media.event, media.source_start),
            (IaxPeerEvent::Audio(160), 0)
        );
        assert!(samples.iter().all(|sample| *sample > 0.9));
        assert!(peer.pending_events.is_empty());
    }
}

#[test]
fn private_source_queue_moves_owned_payloads_without_new_phone_allocations() {
    let state_bytes = std::mem::size_of::<super::super::service::State>();
    assert_eq!(state_bytes, 4);
    eprintln!("ACTUAL_PHONE_STATE bytes={state_bytes} prior_state_bytes=3 early_counter_bytes=1");
    for (full, early) in [(false, 0), (true, 0), (false, 32), (true, 32), (false, 64)] {
        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = remote.local_addr().unwrap();
        let (mut peer, mut producer) = shared_peer(address);
        peer.compose_codec(crate::ffi::test_peer_catalog()).unwrap();
        peer.pending_events.reserve(64);
        peer.pending_replies.reserve(64);
        for _ in 0..early {
            peer.pending_events
                .push_back(super::super::PendingSource::Ready(
                    super::super::PendingEvent {
                        event: IaxPeerEvent::Audio(160),
                        pcm: super::super::PacketPcm {
                            samples: vec![0.25; 160],
                            position: 0,
                            span: crate::source_time::Span::default(),
                        },
                        text: Vec::new(),
                    },
                ));
        }
        let early_pointers = peer
            .pending_events
            .iter()
            .map(|event| {
                let super::super::PendingSource::Ready(event) = event else {
                    unreachable!()
                };
                event.pcm.samples.as_ptr() as usize
            })
            .collect::<Vec<_>>();
        service(&mut peer).unwrap();
        assert_eq!(usize::from(peer.service.early_remaining), early);
        for sequence in 1..=(64 - early) as u8 {
            let bytes = if full {
                full_voice(sequence, 1, u32::from(sequence) * 20, 0x80)
            } else {
                mini(u16::from(sequence) * 20, 0x80)
            };
            producer.try_push(address, &bytes).unwrap();
        }
        let (result, allocations, payload_allocations) =
            crate::allocation_test_support::measure_phone_payload_allocations(|| {
                service(&mut peer)
            });
        result.unwrap();
        assert_eq!(
            payload_allocations, 0,
            "shared ingress must not allocate a second phone payload"
        );
        if !full {
            assert_eq!(
                allocations, 0,
                "reserved mini admission needs no allocation"
            );
        }
        assert_eq!(peer.pending_events.len(), 64);
        assert_eq!(peer.pending_events.capacity(), 64);
        assert_eq!(usize::from(peer.service.early_remaining), early);
        for (source, pointer) in peer.pending_events.iter().zip(early_pointers) {
            let super::super::PendingSource::Ready(event) = source else {
                panic!("early owner moved")
            };
            assert_eq!(event.pcm.samples.as_ptr() as usize, pointer);
            assert_eq!(event.pcm.position, 0);
            assert_eq!(event.pcm.samples, [0.25; 160]);
        }
        let bytes = super::super::service::retained_payload_bytes(&peer);
        assert_eq!(
            bytes,
            early * 640 + (64 - early) * if full { 172 } else { 164 }
        );
        let slot = std::mem::size_of::<super::super::PendingSource>();
        assert_eq!(slot, std::mem::size_of::<super::super::PendingEvent>());
        eprintln!(
            "ACTUAL_PHONE_QUEUE full={full} early={early} slots=64 slot_bytes={slot} metadata={} payload={bytes} allocations={allocations} payload_allocations={payload_allocations}",
            64 * slot
        );
    }
}

#[test]
fn successful_private_activation_persists_through_abi1_and_rust_delivery() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    service(&mut peer).unwrap();
    for sequence in 1..=2 {
        let text = serialize_full_frame(
            &FullFrameHeader {
                source_call_number: 5678,
                destination_call_number: 1234,
                retransmission: false,
                timestamp: 20,
                outgoing_sequence: sequence,
                incoming_sequence: 1,
                frame_type: 7,
                subclass: 0,
                subclass_is_log: false,
            },
            &vec![b'x'; 4096],
        )
        .unwrap();
        remote.send_to(&text, peer.local_addr().unwrap()).unwrap();
        let mut untouched = [0xa5; 8];
        if sequence == 1 {
            assert_eq!(
                peer.poll_timed(&mut [], &mut untouched, input())
                    .unwrap()
                    .event,
                IaxPeerEvent::None
            );
        } else {
            let api = unsafe { &*crate::ffi::rptadv_iax2_client_descriptor_v2() };
            let mut record = crate::ffi::rptadv_iax2_timed_event_v1 {
                struct_size: 72,
                abi_version: 1,
                host_clock_epoch: 7,
                reference_now_ns: 5_000_000_000,
                acknowledged_media_epoch: 1,
                ..Default::default()
            };
            assert_eq!(
                unsafe {
                    api.poll_timed.unwrap()(
                        (&mut peer as *mut IaxPeer).cast(),
                        std::ptr::null_mut(),
                        0,
                        untouched.as_mut_ptr(),
                        untouched.len(),
                        &mut record,
                    )
                },
                0
            );
            assert_eq!(record.event_kind, crate::ffi::RPTADV_IAX2_EVENT_NONE);
        }
        assert_eq!(untouched, [0xa5; 8]);
        assert!(peer.pending_events.is_empty());
        assert!(peer.service.active);
    }
}

#[test]
fn oversized_private_voice_cannot_spend_incoming_ack_credit_or_sequence() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote.set_nonblocking(true).unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    peer.send_prepared_audio(&[0xff; 160], 160, 0).unwrap();
    service(&mut peer).unwrap();
    let malformed = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 5678,
            destination_call_number: 1234,
            retransmission: false,
            timestamp: 20,
            outgoing_sequence: 1,
            incoming_sequence: 2,
            frame_type: 2,
            subclass: 4,
            subclass_is_log: false,
        },
        &[0x80; 161],
    )
    .unwrap();
    while remote.recv_from(&mut [0; 2048]).is_ok() {}
    remote
        .send_to(&malformed, peer.local_addr().unwrap())
        .unwrap();
    assert!(matches!(service(&mut peer), Err(DialError::Provider(error))
        if error.status == crate::codec::providers::Status::Malformed));
    assert_eq!(
        peer.pending_reliable.len(),
        1,
        "malformed input grants no ACK credit"
    );
    assert!(peer.pending_events.is_empty());
    assert_eq!(
        remote.recv_from(&mut [0; 2048]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(peer.retire_egress().is_err());
}

/// A failed release must establish the selected source barrier before returning.
#[test]
fn output_full_deferred_voice_stays_before_later_digit() {
    let _probe = crate::source_time::tests::timestamp_probe();
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    service(&mut peer).unwrap();
    remote
        .send_to(&mini(20, 0x80), peer.local_addr().unwrap())
        .unwrap();
    remote
        .send_to(&digit(1, b'5'), peer.local_addr().unwrap())
        .unwrap();
    service(&mut peer).unwrap();
    assert!(matches!(peer.poll_timed(&mut [], &mut [0; 1], input()),
        Err(DialError::Provider(error)) if error.status == crate::codec::providers::Status::OutputFull));
    let mut output = [0.0; 160];
    let first = next_source(&mut peer, &mut output);
    assert_eq!(
        first.event,
        IaxPeerEvent::Audio(160),
        "digit must not overtake retained voice A"
    );
    assert_eq!(first.source_start, 0);
    assert!(first.born_ns.is_some());
    assert!(output.iter().all(|sample| *sample > 0.9));
    let digit = next_source(&mut peer, &mut output);
    assert_eq!(
        (digit.event, digit.source_start),
        (IaxPeerEvent::Digit(b'5'), 160)
    );
}

/// This independent case catches overwrite even when no digit repairs the barrier.
#[test]
fn output_full_deferred_voice_cannot_be_overwritten_by_later_voice() {
    let _probe = crate::source_time::tests::timestamp_probe();
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    service(&mut peer).unwrap();
    remote
        .send_to(&mini(20, 0x80), peer.local_addr().unwrap())
        .unwrap();
    remote
        .send_to(&mini(40, 0xff), peer.local_addr().unwrap())
        .unwrap();
    service(&mut peer).unwrap();
    assert!(matches!(peer.poll_timed(&mut [], &mut [0; 1], input()),
        Err(DialError::Provider(error)) if error.status == crate::codec::providers::Status::OutputFull));
    let mut output = [0.0; 160];
    let first = next_source(&mut peer, &mut output);
    assert_eq!(
        (first.event, first.source_start),
        (IaxPeerEvent::Audio(160), 0)
    );
    assert!(
        output.iter().all(|sample| *sample > 0.9),
        "voice B must not overwrite voice A"
    );
    let second = next_source(&mut peer, &mut output);
    assert_eq!(
        (second.event, second.source_start),
        (IaxPeerEvent::Audio(160), 160)
    );
    assert_eq!(output, [0.0; 160]);
}

#[test]
fn activation_preserves_early_prefix_before_later_selected_media() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    peer.pending_events
        .push_back(super::super::PendingSource::Ready(
            super::super::PendingEvent {
                event: IaxPeerEvent::Digit(b'5'),
                pcm: super::super::PacketPcm::default(),
                text: Vec::new(),
            },
        ));
    peer.pending_events
        .push_back(super::super::PendingSource::Ready(
            super::super::PendingEvent {
                event: IaxPeerEvent::Audio(40),
                pcm: super::super::PacketPcm {
                    samples: vec![0.25; 40],
                    position: 0,
                    span: crate::source_time::Span::default(),
                },
                text: Vec::new(),
            },
        ));
    peer.direct_pcm.samples = vec![0.75; 160];
    peer.direct_pcm.position = 40;
    service(&mut peer).unwrap();
    assert_eq!(
        next_source(&mut peer, &mut [0.0; 160]).event,
        IaxPeerEvent::Digit(b'5')
    );
    for start in [0, 20] {
        let mut output = [0.0; 20];
        let early = next_source(&mut peer, &mut output);
        assert_eq!(
            (early.event, early.source_start),
            (IaxPeerEvent::Audio(20), start)
        );
        assert_eq!(
            output, [0.25; 20],
            "later selected PCM must not pass either early suffix"
        );
    }
    let mut output = [0.0; 160];
    let selected = next_source(&mut peer, &mut output);
    assert_eq!(
        (selected.event, selected.source_start),
        (IaxPeerEvent::Audio(120), 40)
    );
    assert_eq!(&output[..120], &[0.75; 120]);
}

#[test]
fn pre_reset_real_udp_voice_does_not_fill_new_epoch_source_capacity() {
    let _probe = crate::source_time::tests::timestamp_probe();
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    service(&mut peer).unwrap();
    peer.send_prepared_audio(&[0xff; 160], 160, 0).unwrap();
    assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Pending);
    let local = peer.local_addr().unwrap();
    for index in 0..65 {
        remote.send_to(&mini(20 + index * 20, 0x80), local).unwrap();
    }
    remote
        .send_to(&control(99, 2, crate::protocol::IaxCommand::Ack), local)
        .unwrap();
    std::thread::sleep(Duration::from_millis(5));
    let changed = SourceTimeInput {
        host_clock_epoch: 8,
        ..input()
    };
    for _ in 0..2 {
        let reset = peer
            .poll_timed_private(
                &mut [],
                &mut [],
                changed,
                crate::client::SourceDelivery::ServiceOnly,
            )
            .unwrap();
        assert_eq!((reset.media_epoch, reset.source_start), (2, 0));
        assert!(reset.discontinuity);
        assert_eq!(reset.event, IaxPeerEvent::None);
        assert!(
            peer.pending_events.is_empty(),
            "already retired receipts must not occupy source slots"
        );
    }
    assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Complete(2));
}

/// Sizes describe the actual caller allocation; invalid records never touch peer.
#[test]
fn ffi_timed_request_respects_exact_prefix_tail_and_caller_guards() {
    use crate::ffi::rptadv_iax2_timed_event_v1 as Prefix;
    #[repr(C)]
    struct Guarded {
        request: ServiceRequest,
        guard: [u64; 2],
    }
    let api = unsafe { &*crate::ffi::rptadv_iax2_client_descriptor_v2() };
    let poll = api.poll_timed.unwrap();
    assert_eq!(std::mem::size_of::<Prefix>(), 72);
    assert_eq!(std::mem::size_of::<ServiceRequest>(), 80);
    for (version, flags) in [(1, u32::MAX), (2, 0), (2, 1)] {
        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut peer = linked_peer(remote.local_addr().unwrap());
        let reserved = if version == 1 { u32::MAX } else { 0 };
        let mut guarded = Guarded {
            request: ServiceRequest {
                prefix: Prefix {
                    struct_size: 80,
                    abi_version: version,
                    host_clock_epoch: 7,
                    reference_now_ns: 5_000_000_000,
                    acknowledged_media_epoch: 1,
                    ..Default::default()
                },
                request_flags: flags,
                reserved,
            },
            guard: [0x1234_5678_90ab_cdef; 2],
        };
        remote
            .send_to(&digit(1, b'5'), peer.local_addr().unwrap())
            .unwrap();
        let mut text = [0xa5; 1];
        assert_eq!(
            unsafe {
                poll(
                    std::ptr::from_mut(&mut peer).cast(),
                    std::ptr::null_mut(),
                    0,
                    text.as_mut_ptr(),
                    text.len(),
                    std::ptr::from_mut(&mut guarded).cast(),
                )
            },
            0
        );
        assert_eq!(guarded.request.prefix.host_clock_epoch, 7);
        assert_eq!(guarded.request.prefix.reference_now_ns, 5_000_000_000);
        assert_eq!(guarded.request.prefix.acknowledged_media_epoch, 1);
        assert_eq!(guarded.request.request_flags, flags);
        assert_eq!(guarded.request.reserved, reserved);
        assert_eq!(guarded.guard, [0x1234_5678_90ab_cdef; 2]);
        assert_eq!(peer.service.active, version == 2);
        if flags == 1 {
            assert_eq!(
                guarded.request.prefix.event_kind,
                crate::ffi::RPTADV_IAX2_EVENT_NONE
            );
            assert_eq!(text, [0xa5]);
            assert_eq!(peer.pending_events.len(), 1);
            guarded.request.request_flags = 0;
            assert_eq!(
                unsafe {
                    poll(
                        std::ptr::from_mut(&mut peer).cast(),
                        std::ptr::null_mut(),
                        0,
                        text.as_mut_ptr(),
                        text.len(),
                        std::ptr::from_mut(&mut guarded).cast(),
                    )
                },
                0
            );
        }
        assert_eq!(
            guarded.request.prefix.event_kind,
            crate::ffi::RPTADV_IAX2_EVENT_DIGIT
        );
        assert_eq!(guarded.request.prefix.event_length, 1);
        assert_eq!(guarded.request.prefix.source_start, 0);
        assert_eq!(text, [b'5']);
        assert!(peer.pending_events.is_empty());
        assert_eq!(guarded.guard, [0x1234_5678_90ab_cdef; 2]);
    }
    // The actual allocation stops at byte72. ABI2 must reject before reading tail.
    let mut short = Prefix {
        struct_size: 72,
        abi_version: 2,
        event_kind: u32::MAX,
        flags: u32::MAX,
        event_length: usize::MAX,
        media_epoch: u64::MAX,
        source_start: u64::MAX,
        born_ns: u64::MAX,
        ..Default::default()
    };
    assert_eq!(
        unsafe {
            poll(
                std::ptr::dangling_mut::<std::ffi::c_void>(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::from_mut(&mut short),
            )
        },
        -1
    );
    assert_eq!(
        (
            short.event_kind,
            short.flags,
            short.event_length,
            short.media_epoch,
            short.source_start,
            short.born_ns
        ),
        (0, 0, 0, 0, 0, 0)
    );
    // Only the size prefix physically exists: no full-record reference is valid.
    let mut tiny = 4_u32;
    assert_eq!(
        unsafe {
            poll(
                std::ptr::dangling_mut::<std::ffi::c_void>(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::from_mut(&mut tiny).cast(),
            )
        },
        -1
    );
    assert_eq!(tiny, 4);
}

#[test]
fn retired_full_voice_still_advances_real_protocol_sequence_and_ack() {
    let _probe = crate::source_time::tests::timestamp_probe();
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    service(&mut peer).unwrap();
    peer.send_prepared_audio(&[0xff; 160], 160, 0).unwrap();
    assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Pending);
    let packet = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 5678,
            destination_call_number: 1234,
            retransmission: false,
            timestamp: 20,
            outgoing_sequence: 1,
            incoming_sequence: 2,
            frame_type: 2,
            subclass: 4,
            subclass_is_log: false,
        },
        &[0x80; 160],
    )
    .unwrap();
    remote.send_to(&packet, peer.local_addr().unwrap()).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    let changed = SourceTimeInput {
        host_clock_epoch: 8,
        ..input()
    };
    let reset = peer
        .poll_timed_private(
            &mut [],
            &mut [],
            changed,
            crate::client::SourceDelivery::ServiceOnly,
        )
        .unwrap();
    assert_eq!((reset.media_epoch, reset.source_start), (2, 0));
    assert!(reset.discontinuity);
    assert!(peer.pending_events.is_empty());
    assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Complete(2));
    remote
        .send_to(&digit(2, b'6'), peer.local_addr().unwrap())
        .unwrap();
    let next = peer
        .poll_timed(
            &mut [0.0; 160],
            &mut [0; 1],
            SourceTimeInput {
                acknowledged_media_epoch: 2,
                ..changed
            },
        )
        .unwrap();
    assert_eq!(
        (next.event, next.media_epoch, next.source_start),
        (IaxPeerEvent::Digit(b'6'), 2, 0)
    );
    assert!(!next.discontinuity);
}

#[test]
fn recoverable_source_reservation_failure_precedes_ack_and_preserves_accepted_control() {
    let slot = std::mem::size_of::<super::super::PendingSource>();
    for (capacity, failed_size) in [(4, 8 * slot), (64, 172)] {
        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        remote.set_nonblocking(true).unwrap();
        let mut peer = linked_peer(remote.local_addr().unwrap());
        service(&mut peer).unwrap();
        peer.pending_events.reserve(capacity);
        let local = peer.local_addr().unwrap();
        for sequence in 1..=4 {
            remote
                .send_to(&digit(sequence, b'0' + sequence), local)
                .unwrap();
        }
        service(&mut peer).unwrap();
        assert_eq!(peer.pending_events.len(), 4);
        assert_eq!(peer.pending_events.capacity(), capacity);
        peer.send_prepared_audio(&[0xff; 160], 160, 0).unwrap();
        assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Pending);
        let mut scratch = [0; 2048];
        while remote.recv_from(&mut scratch).is_ok() {}
        // This valid full voice would carry real ACK credit if acceptance ran.
        remote.send_to(&full_voice(5, 2, 20, 0x80), local).unwrap();
        let (result, failures) =
            crate::allocation_test_support::fail_once_with_size(failed_size, || service(&mut peer));
        assert_eq!(failures, 1, "must exercise the real recoverable allocation");
        assert!(matches!(result, Err(DialError::EarlyEventsFull)));
        assert_eq!(peer.pending_events.capacity(), capacity);
        assert_eq!(peer.pending_events.len(), 4);
        for (index, event) in peer.pending_events.iter().enumerate() {
            let super::super::PendingSource::Ready(event) = event else {
                panic!("lost control owner")
            };
            assert_eq!(event.event, IaxPeerEvent::Digit(b'1' + index as u8));
        }
        assert_eq!(
            peer.pending_reliable.len(),
            1,
            "rejected source spent ACK credit"
        );
        assert_eq!(
            remote.recv_from(&mut scratch).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(peer.retire_egress().is_err());
        assert!(peer.send_prepared_audio(&[0xff; 160], 160, 40).is_err());
        assert!(
            peer.poll_timed(&mut [0.0; 160], &mut [0; 1], input())
                .is_err()
        );
    }
}

#[test]
fn private_service_rejects_malformed_source_and_ignores_foreign_datagrams() {
    let mut packets = vec![(vec![0x80], true)];
    for (frame_type, subclass, subclass_is_log, payload, rejected) in [
        (1, 5, true, vec![], true),
        (4, 12, true, vec![], false),
        (1, b'5', false, vec![1], true),
        (1, b'!', false, vec![], true),
        (2, 8, false, vec![0xff; 160], true),
    ] {
        packets.push((
            serialize_full_frame(
                &FullFrameHeader {
                    source_call_number: 5678,
                    destination_call_number: 1234,
                    retransmission: false,
                    timestamp: 20,
                    outgoing_sequence: 1,
                    incoming_sequence: 1,
                    frame_type,
                    subclass,
                    subclass_is_log,
                },
                &payload,
            )
            .unwrap(),
            rejected,
        ));
    }
    for (source, destination) in [(5679, 1234), (5678, 1235)] {
        let packet = full_voice(1, 1, 20, 0xff);
        let mut header = parse_full_frame_packet(&packet).unwrap().header;
        header.source_call_number = source;
        header.destination_call_number = destination;
        packets.push((serialize_full_frame(&header, &[0xff; 160]).unwrap(), true));
    }
    let mut foreign_call = mini(20, 0xff);
    foreign_call[..2].copy_from_slice(&5679_u16.to_be_bytes());
    packets.push((foreign_call, true));
    for (packet, rejected) in packets {
        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut peer = linked_peer(remote.local_addr().unwrap());
        service(&mut peer).unwrap();
        remote.send_to(&packet, peer.local_addr().unwrap()).unwrap();
        let result = service(&mut peer);
        assert!(peer.pending_events.is_empty());
        if rejected {
            assert!(
                matches!(result, Err(DialError::Protocol(_) | DialError::Voice(_))),
                "malformed source must not be staged: {packet:?}"
            );
            assert!(peer.service.terminal);
            assert!(peer.retire_egress().is_err());
        } else {
            // Log subclass12 means4096, an unknown radio control. Ordinary IAX
            // acknowledges and ignores it; it must never become RADIO_KEY.
            assert_eq!(result.unwrap().event, IaxPeerEvent::None);
            assert!(!peer.service.terminal);
            remote
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut bytes = [0; 128];
            let (length, _) = remote.recv_from(&mut bytes).unwrap();
            let acknowledgement = parse_full_frame_packet(&bytes[..length]).unwrap();
            assert_eq!(
                crate::protocol::decode_iax_command(&acknowledgement.header).unwrap(),
                Some(crate::protocol::IaxCommand::Ack)
            );
            assert_eq!(acknowledgement.header.incoming_sequence, 2);
            remote
                .send_to(&digit(2, b'6'), peer.local_addr().unwrap())
                .unwrap();
            assert_eq!(
                next_source(&mut peer, &mut []).event,
                IaxPeerEvent::Digit(b'6')
            );
        }
    }

    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let foreign = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    service(&mut peer).unwrap();
    foreign
        .send_to(&digit(1, b'9'), peer.local_addr().unwrap())
        .unwrap();
    remote
        .send_to(&digit(1, b'5'), peer.local_addr().unwrap())
        .unwrap();
    service(&mut peer).unwrap();
    assert_eq!(
        next_source(&mut peer, &mut []).event,
        IaxPeerEvent::Digit(b'5')
    );
    assert!(peer.pending_events.is_empty());
    assert!(!peer.service.terminal);
}

#[test]
fn empty_voice_marker_and_radio_receipts_preserve_short_digit_retry() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    let local = peer.local_addr().unwrap();
    let marker = full_voice(1, 1, 0, 0xff);
    remote.send_to(&marker[..12], local).unwrap();
    remote.send_to(&radio(2, 12), local).unwrap();
    remote.send_to(&radio(3, 13), local).unwrap();
    remote.send_to(&digit(4, b'5'), local).unwrap();
    service(&mut peer).unwrap();
    assert_eq!(peer.pending_events.len(), 3);
    assert_eq!(
        peer.timed_deadline(),
        None,
        "radio controls carry no source age"
    );
    assert_eq!(
        next_source(&mut peer, &mut []).event,
        IaxPeerEvent::RadioKey
    );
    assert_eq!(
        next_source(&mut peer, &mut []).event,
        IaxPeerEvent::RadioUnkey
    );
    assert!(matches!(
        peer.poll_timed(&mut [], &mut [], input()),
        Err(DialError::InvalidOptions)
    ));
    assert_eq!(peer.pending_events.len(), 1);
    assert!(!peer.service.terminal);
    let delivered = next_source(&mut peer, &mut []);
    assert_eq!(delivered.event, IaxPeerEvent::Digit(b'5'));
    assert_eq!((delivered.source_start, delivered.born_ns), (0, None));
    assert!(peer.pending_events.is_empty());
}

#[test]
fn failed_private_ingress_fences_source_but_allows_clean_hangup() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (mut peer, producer) = shared_peer(remote.local_addr().unwrap());
    peer.compose_codec(crate::ffi::test_peer_catalog()).unwrap();
    service(&mut peer).unwrap();
    peer.send_dtmf(b'5').unwrap();
    assert_eq!(peer.pending_reliable.len(), 1);
    producer.fail();
    assert!(matches!(
        service(&mut peer),
        Err(DialError::Network(error)) if error.kind() == std::io::ErrorKind::ConnectionAborted
    ));
    assert!(peer.service.terminal);
    assert!(peer.send_dtmf(b'6').is_err());
    assert!(peer.retire_egress().is_err());
    peer.hangup().unwrap();
    assert_eq!(peer.pending_reliable.len(), 1);
    let frame = parse_full_frame_packet(&peer.pending_reliable[0].packet).unwrap();
    assert_eq!(
        crate::protocol::decode_iax_command(&frame.header).unwrap(),
        Some(crate::protocol::IaxCommand::Hangup)
    );
}

#[test]
fn private_activation_rejects_uncomposed_codec_and_unqualified_jitter_backlog() {
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let socket = Arc::new(SharedSocket::new(UdpSocket::bind("127.0.0.1:0").unwrap()));
    let (_producer, ingress) = crate::ingress::producer_ingress(64, 1).unwrap();
    let (mut generic, _released) = IaxPeer::from_inbound(
        Arc::clone(&socket),
        ingress,
        socket.local_addr().unwrap(),
        remote.local_addr().unwrap(),
        1234,
        5678,
        crate::formats::IaxFormat::for_profile(crate::codec::providers::ProfileId::GsmFr).0,
    )
    .unwrap();
    assert!(matches!(
        service(&mut generic),
        Err(DialError::InvalidOptions)
    ));
    assert_eq!(
        generic.format(),
        crate::formats::IaxFormat::for_profile(crate::codec::providers::ProfileId::GsmFr).0
    );
    assert!(!generic.service.active);
    assert!(!generic.timed.enabled);
    let (mut peer, _producer) = shared_peer(remote.local_addr().unwrap());
    assert!(matches!(service(&mut peer), Err(DialError::InvalidOptions)));
    assert!(!peer.service.active);
    assert!(!peer.timed.enabled);
    peer.compose_codec(crate::ffi::test_peer_catalog()).unwrap();
    let fixture = crate::jitter::fixture::Fixture::new();
    unsafe { peer.configure_jitter(fixture.descriptor()) }.unwrap();
    fixture.observation(crate::jitter::Observation {
        queued_packets: 1,
        ..Default::default()
    });
    assert!(matches!(service(&mut peer), Err(DialError::InvalidOptions)));
    assert!(!peer.service.active);
    assert!(!peer.timed.enabled);
    fixture.observation(crate::jitter::Observation::default());
    service(&mut peer).unwrap();
    assert!(peer.service.active);
}

#[test]
fn private_selected_key_waits_for_real_jitter_tail_before_later_digit() {
    let fixture = crate::jitter::fixture::Fixture::new();
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut peer = linked_peer(remote.local_addr().unwrap());
    unsafe { peer.configure_jitter(fixture.descriptor()) }.unwrap();
    service(&mut peer).unwrap();
    let timestamp = (0x1_0000_0000 + 20) * 8;
    fixture.packet(u64::MAX, timestamp, &[0x80; 160], 0);
    let local = peer.local_addr().unwrap();
    remote.send_to(&full_voice(1, 1, 20, 0x80), local).unwrap();
    remote.send_to(&radio(2, 13), local).unwrap();
    remote.send_to(&radio(3, 12), local).unwrap();
    remote.send_to(&digit(4, b'5'), local).unwrap();
    service(&mut peer).unwrap();
    let not_due = peer
        .poll_timed(&mut [0.0; 160], &mut [0; 1], input())
        .unwrap();
    assert_eq!(not_due.event, IaxPeerEvent::None);
    assert!(peer.service.selected);
    assert_eq!(
        peer.pending_events.len(),
        1,
        "later digit stays behind selected key"
    );
    assert_eq!(fixture.puts().len(), 1);
    fixture.release_next();
    let events = (0..4)
        .map(|_| next_source(&mut peer, &mut [0.0; 160]).event)
        .collect::<Vec<_>>();
    assert_eq!(
        events,
        [
            IaxPeerEvent::Audio(160),
            IaxPeerEvent::RadioUnkey,
            IaxPeerEvent::RadioKey,
            IaxPeerEvent::Digit(b'5'),
        ]
    );
    assert!(peer.pending_events.is_empty());
    assert!(!peer.service.selected);
}
