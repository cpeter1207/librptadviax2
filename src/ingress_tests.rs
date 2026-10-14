use crate::ingress::{
    IngressError, IngressPushError, PeerIngressRouter, PeerIngressRouterError, producer_ingress,
};
use std::net::SocketAddr;

fn address(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[test]
fn queued_datagram_retains_observed_arrival_time() {
    let (mut producer, mut owner) = producer_ingress(2, 77).unwrap();
    let arrival = std::time::Instant::now();
    producer.try_push_at(address(1), &[9], arrival).unwrap();
    let packet = owner.try_pop().unwrap();
    assert_eq!(packet.arrived_at(), arrival);
    assert_eq!((packet.generation(), packet.payload()), (77, &[9][..]));
}

#[test]
fn call_routes_preserve_captured_arrival_and_publish_terminal_failure() {
    let mut router = PeerIngressRouter::new(4).unwrap();
    let mut full = router.register_call(address(1), 22, 42, 7).unwrap();
    let mut fallback = router.register(address(2), 8).unwrap();
    let arrival = std::time::Instant::now() - std::time::Duration::from_secs(1);
    router
        .route_call_at(address(1), 22, 42, &[1], arrival)
        .unwrap();
    router
        .route_remote_call_at(address(1), 42, &[2], arrival)
        .unwrap();
    router
        .route_call_at(address(2), 22, 42, &[3], arrival)
        .unwrap();
    router
        .route_remote_call_at(address(2), 42, &[4], arrival)
        .unwrap();
    for value in [1, 2] {
        let packet = full.try_pop().unwrap();
        assert_eq!(packet.payload(), [value]);
        assert_eq!(packet.arrived_at(), arrival);
    }
    for value in [3, 4] {
        let packet = fallback.try_pop().unwrap();
        assert_eq!(packet.payload(), [value]);
        assert_eq!(packet.arrived_at(), arrival);
    }
    router.fail_all();
    assert!(full.failed());
    assert!(fallback.failed());
}

#[test]
fn closed_peer_owner_rejects_every_router_admission_form() {
    for call_route in [false, true] {
        let mut router = PeerIngressRouter::new(1).unwrap();
        let owner = if call_route {
            router.register_call(address(1), 22, 42, 1).unwrap()
        } else {
            router.register(address(1), 1).unwrap()
        };
        drop(owner);
        for result in [
            router.route_call(address(1), 22, 42, &[1]),
            router.route_remote_call(address(1), 42, &[2]),
            router.route(address(1), &[3]),
        ] {
            assert_eq!(result, Err(PeerIngressRouterError::UnknownPeer));
        }
    }
}

#[test]
fn cloned_ingress_producers_share_one_bounded_owner() {
    let (mut producer, mut owner) = producer_ingress(2, 19).unwrap();
    let mut other = producer.clone();
    producer.try_push(address(1), &[1]).unwrap();
    other.try_push(address(1), &[2]).unwrap();
    assert_eq!(
        producer.try_push(address(1), &[3]),
        Err(IngressPushError::Full)
    );
    assert_eq!(owner.stats().queued_packets, 2);
    assert_eq!(owner.stats().capacity_packets, 2);
    assert_eq!(owner.stats().dropped_packets, 1);
    assert_eq!(owner.try_pop().unwrap().payload(), [1]);
    assert_eq!(owner.stats().queued_packets, 1);
    assert_eq!(owner.stats().dropped_packets, 1);
    assert_eq!(owner.try_pop().unwrap().payload(), [2]);
    drop(owner);
    assert_eq!(
        other.try_push(address(1), &[4]),
        Err(IngressPushError::Closed)
    );
}

#[test]
fn stalled_peer_does_not_block_other_peers() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (mut blocked, mut blocked_owner) = producer_ingress(1, 1).unwrap();
        let (mut ready, mut ready_owner) = producer_ingress(1, 2).unwrap();
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = tokio::sync::oneshot::channel();
        let blocked_task = tokio::spawn(async move {
            let first = blocked_owner.receive().await.unwrap();
            entered.send(()).unwrap();
            release_rx.await.unwrap();
            (first, blocked_owner.receive().await.unwrap())
        });
        blocked.try_push(address(1), &[1]).unwrap();
        entered_rx.await.unwrap();
        blocked.try_push(address(1), &[2]).unwrap();
        assert_eq!(
            blocked.try_push(address(1), &[3]),
            Err(IngressPushError::Full)
        );
        ready.try_push(address(2), &[4]).unwrap();
        assert_eq!(ready_owner.receive().await.unwrap().payload(), [4]);
        release.send(()).unwrap();
        let (first, second) = blocked_task.await.unwrap();
        assert_eq!(first.payload(), [1]);
        assert_eq!(second.payload(), [2]);
    });
}

#[test]
fn retired_generation_cannot_publish_after_slot_reuse() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (mut old, retired) = producer_ingress(1, 10).unwrap();
        drop(retired);
        let (mut current, mut owner) = producer_ingress(1, 11).unwrap();
        assert_eq!(
            old.try_push(address(1), &[1]),
            Err(IngressPushError::Closed)
        );
        current.try_push(address(1), &[2]).unwrap();
        let packet = owner.receive().await.unwrap();
        assert_eq!((packet.generation(), packet.payload()), (11, &[2][..]));
        drop(current);
        assert!(owner.receive().await.is_none());
    });
}

#[test]
fn producer_queue_preserves_order_and_peer_generation() {
    let (mut producer, mut owner) = producer_ingress(2, 77).unwrap();
    assert_eq!(producer.available_slots(), 2);
    producer.try_push(address(1), &[1]).unwrap();
    assert_eq!(producer.available_slots(), 1);
    producer.try_push(address(2), &[2]).unwrap();
    assert_eq!(producer.available_slots(), 0);

    let first = owner.try_pop().unwrap();
    let second = owner.try_pop().unwrap();
    assert_eq!(first.generation(), 77);
    assert_eq!(first.remote(), address(1));
    assert_eq!(first.payload(), [1]);
    assert_eq!(second.generation(), 77);
    assert_eq!(second.remote(), address(2));
    assert_eq!(second.payload(), [2]);
    assert!(owner.try_pop().is_none());
    assert_eq!(producer.available_slots(), 2);
}

#[test]
fn full_producer_queue_rejects_without_waiting() {
    let (mut producer, mut owner) = producer_ingress(1, 7).unwrap();
    producer.try_push(address(1), &[1]).unwrap();

    assert_eq!(
        producer.try_push(address(2), &[2]).unwrap_err(),
        IngressPushError::Full
    );
    assert_eq!(owner.try_pop().unwrap().payload(), [1]);
}

#[test]
fn independent_producer_queues_do_not_wait_for_each_other() {
    let (mut stalled_producer, mut stalled_owner) = producer_ingress(1, 4).unwrap();
    let (mut ready_producer, mut ready_owner) = producer_ingress(1, 4).unwrap();
    stalled_producer.try_push(address(1), &[1]).unwrap();
    ready_producer.try_push(address(2), &[2]).unwrap();

    assert_eq!(ready_owner.try_pop().unwrap().payload(), [2]);
    assert_eq!(stalled_owner.try_pop().unwrap().payload(), [1]);
}

#[test]
fn rejects_zero_capacity_and_oversized_datagrams() {
    assert_eq!(
        producer_ingress(0, 1).err().unwrap(),
        IngressError::ZeroCapacity
    );
    let (mut producer, mut owner) = producer_ingress(1, 1).unwrap();
    let oversized = vec![0; 1501];
    assert_eq!(
        producer.try_push(address(1), &oversized).unwrap_err(),
        IngressPushError::DatagramTooLarge { length: 1501 }
    );
    assert!(owner.try_pop().is_none());
}

#[test]
fn router_routes_each_peer_to_its_own_generation_tagged_queue() {
    let mut router = PeerIngressRouter::new(2).unwrap();
    let mut first_owner = router.register(address(1), 11).unwrap();
    let mut second_owner = router.register(address(2), 22).unwrap();

    router.route(address(2), &[2]).unwrap();
    router.route(address(1), &[1]).unwrap();

    let first = first_owner.try_pop().unwrap();
    let second = second_owner.try_pop().unwrap();
    assert_eq!(
        (first.generation(), first.remote(), first.payload()),
        (11, address(1), &[1][..])
    );
    assert_eq!(
        (second.generation(), second.remote(), second.payload()),
        (22, address(2), &[2][..])
    );
    assert!(first_owner.try_pop().is_none());
    assert!(second_owner.try_pop().is_none());
}

#[test]
fn router_separates_calls_from_the_same_udp_source() {
    let mut router = PeerIngressRouter::new(2).unwrap();
    let mut first = router.register_call(address(10), 100, 200, 11).unwrap();
    let mut second = router.register_call(address(10), 101, 201, 22).unwrap();

    router.route_call(address(10), 100, 200, &[1]).unwrap();
    router.route_call(address(10), 101, 201, &[2]).unwrap();

    let first_packet = first.try_pop().unwrap();
    assert_eq!(first_packet.generation(), 11);
    assert_eq!(first_packet.payload(), [1]);
    let second_packet = second.try_pop().unwrap();
    assert_eq!(second_packet.generation(), 22);
    assert_eq!(second_packet.payload(), [2]);
    assert!(first.try_pop().is_none());
    assert!(second.try_pop().is_none());
}

#[test]
fn call_router_reports_present_local_calls_and_rejects_nonmatching_remote_calls() {
    let mut router = PeerIngressRouter::new(1).unwrap();
    let remote = address(10);
    let _owner = router.register_call(remote, 100, 200, 11).unwrap();

    assert!(router.contains_local_call(100));
    assert!(!router.contains_local_call(101));
    assert_eq!(
        router.route_remote_call(address(11), 200, &[1]),
        Err(PeerIngressRouterError::UnknownPeer)
    );
    assert_eq!(
        router.route_remote_call(remote, 201, &[1]),
        Err(PeerIngressRouterError::UnknownPeer)
    );
}

#[test]
fn egress_admission_failure_keeps_existing_peers() {
    let mut router = PeerIngressRouter::new(1).unwrap();
    let mut existing = router.register_call(address(10), 10, 20, 1).unwrap();
    router.fail_next_reserve = true;
    assert!(router.register_call(address(10), 11, 21, 2).is_err());
    assert!(!router.contains_local_call(11));
    router.route_call(address(10), 10, 20, &[7]).unwrap();
    assert_eq!(existing.try_pop().unwrap().payload(), [7]);
    let _replacement = router.register_call(address(10), 11, 21, 3).unwrap();
}

#[test]
fn egress_admission_above_1024() {
    let mut router = PeerIngressRouter::new(1).unwrap();
    let mut owners = Vec::new();
    for call in 1..=2000 {
        let owner = router
            .register_call(address(10), call, call, u64::from(call))
            .unwrap();
        owners.push(owner);
        router
            .route_call(address(10), call, call, &call.to_be_bytes())
            .unwrap();
        assert_eq!(
            router.route_call(address(10), call, call, &[0]),
            Err(PeerIngressRouterError::Full)
        );
    }
    for (index, owner) in owners.iter_mut().enumerate() {
        assert_eq!(
            owner.try_pop().unwrap().payload(),
            ((index + 1) as u16).to_be_bytes()
        );
    }
    assert!(router.unregister_call(address(10), 1000, 1000, 1000));
    let mut replacement = router.register_call(address(10), 1000, 1000, 3000).unwrap();
    router.route_call(address(10), 1000, 1000, &[9]).unwrap();
    assert_eq!(replacement.try_pop().unwrap().generation(), 3000);
    assert!(owners[999].try_pop().is_none());
}

#[test]
fn router_rejects_ambiguous_mini_frame_call_ids() {
    let mut router = PeerIngressRouter::new(1).unwrap();
    let mut first = router.register_call(address(10), 100, 200, 11).unwrap();
    let mut second = router.register_call(address(10), 101, 200, 22).unwrap();

    assert_eq!(
        router.route_remote_call(address(10), 200, &[1]),
        Err(PeerIngressRouterError::AmbiguousCall)
    );
    assert!(first.try_pop().is_none());
    assert!(second.try_pop().is_none());
}

#[test]
fn call_routes_validate_ids_track_drops_and_retire_by_generation() {
    let mut router = PeerIngressRouter::new(1).unwrap();
    for (local_call, remote_call) in [(0, 200), (100, 0), (0x8000, 200), (100, 0x8000)] {
        assert_eq!(
            router
                .register_call(address(10), local_call, remote_call, 1)
                .err()
                .unwrap(),
            PeerIngressRouterError::InvalidCallNumbers
        );
    }
    let mut owner = router.register_call(address(10), 100, 200, 7).unwrap();
    assert_eq!(
        router
            .register_call(address(10), 100, 200, 8)
            .err()
            .unwrap(),
        PeerIngressRouterError::DuplicatePeer
    );
    assert_eq!(
        router.route_call(address(10), 101, 200, &[1]),
        Err(PeerIngressRouterError::UnknownPeer)
    );
    assert_eq!(
        router.route_call(address(10), 100, 200, &[0; 1501]),
        Err(PeerIngressRouterError::DatagramTooLarge { length: 1501 })
    );

    router.route_call(address(10), 100, 200, &[1]).unwrap();
    assert_eq!(
        router.route_call(address(10), 100, 200, &[2]),
        Err(PeerIngressRouterError::Full)
    );
    assert_eq!(
        router.call_stats(address(10), 100, 200).unwrap(),
        crate::ingress::IngressStats {
            queued_packets: 1,
            dropped_packets: 1,
            capacity_packets: 1,
        }
    );
    assert!(!router.unregister_call(address(10), 100, 200, 8));
    assert!(router.unregister_call(address(10), 100, 200, 7));
    assert!(router.call_stats(address(10), 100, 200).is_none());
    assert_eq!(owner.try_pop().unwrap().payload(), [1]);
}

#[test]
fn remove_call_retires_only_the_exact_call_route() {
    let mut router = PeerIngressRouter::new(1).unwrap();
    let remote = address(10);
    let _owner = router.register_call(remote, 100, 200, 7).unwrap();

    assert!(!router.remove_call(remote, 100, 201));
    assert!(router.remove_call(remote, 100, 200));
    assert!(!router.remove_call(remote, 100, 200));
}

#[test]
fn router_rejects_unknown_sources_and_keeps_known_queues_live() {
    let mut router = PeerIngressRouter::new(1).unwrap();
    let mut owner = router.register(address(1), 9).unwrap();
    assert_eq!(
        router.route(address(2), &[2]),
        Err(PeerIngressRouterError::UnknownPeer)
    );
    router.route(address(1), &[1]).unwrap();
    assert_eq!(owner.try_pop().unwrap().payload(), [1]);
    assert_eq!(
        router.route(address(1), &vec![0; 1501]),
        Err(PeerIngressRouterError::DatagramTooLarge { length: 1501 })
    );
}

#[test]
fn router_counts_full_queue_drops_and_reports_occupancy() {
    let mut router = PeerIngressRouter::new(1).unwrap();
    let mut owner = router.register(address(1), 1).unwrap();
    router.route(address(1), &[1]).unwrap();
    assert_eq!(
        router.route(address(1), &[2]),
        Err(PeerIngressRouterError::Full)
    );
    assert_eq!(router.stats(address(1)).unwrap().queued_packets, 1);
    assert_eq!(router.stats(address(1)).unwrap().dropped_packets, 1);
    owner.try_pop().unwrap();
    assert_eq!(router.stats(address(1)).unwrap().queued_packets, 0);
    assert_eq!(router.stats(address(1)).unwrap().dropped_packets, 1);
}

#[test]
fn router_rejects_duplicate_addresses_and_zero_queue_capacity() {
    assert_eq!(
        PeerIngressRouter::new(0).err().unwrap(),
        PeerIngressRouterError::Ingress(IngressError::ZeroCapacity)
    );

    let mut router = PeerIngressRouter::new(1).unwrap();
    let _owner = router.register(address(1), 1).unwrap();
    assert!(!router.contains_local_call(1));
    assert_eq!(
        router.register(address(1), 2).err().unwrap(),
        PeerIngressRouterError::DuplicatePeer
    );
    assert!(router.register(address(2), 2).is_ok());
}

#[test]
fn router_removes_only_the_matching_generation_before_address_reuse() {
    let mut router = PeerIngressRouter::new(1).unwrap();
    let mut old_owner = router.register(address(1), 1).unwrap();
    router.route(address(1), &[1]).unwrap();
    assert!(!router.unregister(address(1), 2));
    assert!(router.unregister(address(1), 1));

    let mut new_owner = router.register(address(1), 2).unwrap();
    router.route(address(1), &[2]).unwrap();
    assert_eq!(old_owner.try_pop().unwrap().generation(), 1);
    let packet = new_owner.try_pop().unwrap();
    assert_eq!(packet.generation(), 2);
    assert_eq!(packet.payload(), [2]);
    assert_eq!(router.stats(address(3)), None);
}
#[tokio::test]
async fn wake_retains_backlog_after_coalesced_notifications() {
    let (mut producer, mut consumer) = producer_ingress(2, 1).unwrap();
    let wake = consumer.wake();
    assert_eq!(wake.pending(), 0);
    producer.try_push(address(1), &[1]).unwrap();
    producer.try_push(address(1), &[2]).unwrap();
    assert_eq!(
        producer.try_push(address(1), &[3]),
        Err(IngressPushError::Full)
    );
    wake.notified().await;
    assert_eq!(wake.pending(), 2);
    assert_eq!(consumer.try_pop().unwrap().payload(), [1]);
    assert_eq!(wake.pending(), 1, "a bounded drain must be rescheduled");
    assert_eq!(consumer.receive().await.unwrap().payload(), [2]);
    assert_eq!(wake.pending(), 0);
}
