use super::*;
use crate::jitter::fixture::Fixture;
use std::time::Duration;

fn provider_decoder(
    backend: &str,
    id: crate::codec::providers::ProfileId,
) -> crate::codec::stream::Stream {
    use crate::codec::providers::{CodecCatalog, ProviderSelection};
    let directory =
        std::path::PathBuf::from(std::env::var_os("RPTADV_CODEC_DIR").unwrap_or_default());
    let catalog = CodecCatalog::load(&[ProviderSelection {
        path: directory.join(format!("librptadv_codec_{backend}.so.1")),
        profiles: vec![id],
    }])
    .unwrap();
    crate::codec::stream::Stream::open(&catalog, id).unwrap()
}

#[test]
fn playout_codec_native_plc_precedes_ring_fallback_and_never_double_conceals() {
    let mut stream = provider_decoder("speex", crate::codec::providers::ProfileId::Speex);
    let mut encoded = [0; 1024];
    let result = stream
        .encoder
        .encode(&[0.1; 160], &mut encoded, false)
        .unwrap();
    let payload = &encoded[..result.encoded_bytes];
    let fixture = Fixture::new();
    let origin = Instant::now();
    let timestamp = (0x1_0000_0000 + 1000) * 8;
    fixture.packet(60_000_000, timestamp, payload, 0);
    fixture.last_packet_span(160);
    fixture.gap(80_000_000, timestamp + 160, 160, false);
    fixture.gap(100_000_000, timestamp + 320, 160, true);
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    playout
        .put_with_codec(1000, false, origin, payload, Some(&stream.decoder))
        .unwrap();
    playout
        .put_with_codec(1040, false, origin, payload, Some(&stream.decoder))
        .unwrap();
    assert_eq!(fixture.puts()[0].1, 160);
    let mut pcm = [0.75; 160];
    for millis in [60, 80] {
        assert_eq!(
            playout
                .poll_with_codec(
                    origin + Duration::from_millis(millis),
                    &mut pcm,
                    Some(&mut stream.decoder)
                )
                .unwrap(),
            IaxPeerEvent::Audio(160)
        );
        assert_ne!(pcm, [0.75; 160]);
        pcm.fill(0.75);
    }
    assert_eq!(
        playout
            .poll_with_codec(
                origin + Duration::from_millis(100),
                &mut pcm,
                Some(&mut stream.decoder)
            )
            .unwrap(),
        IaxPeerEvent::Gap(160)
    );
    assert_eq!(pcm, [0.75; 160]);
}

#[test]
fn playout_compressed_overlap_is_trimmed_only_after_whole_decode() {
    let mut stream = provider_decoder("gsm", crate::codec::providers::ProfileId::GsmFr);
    let mut encoded = [0; 33];
    stream
        .encoder
        .encode(&[0.1; 160], &mut encoded, false)
        .unwrap();
    let mut reference = provider_decoder("gsm", crate::codec::providers::ProfileId::GsmFr);
    let mut expected = [0.0; 160];
    reference.decoder.decode(&encoded, &mut expected).unwrap();
    let fixture = Fixture::new();
    fixture.packet(0, 8000, &encoded, -80);
    fixture.last_packet_span(160);
    let origin = Instant::now();
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    let mut pcm = [0.0; 160];
    assert_eq!(
        playout
            .poll_with_codec(origin, &mut pcm, Some(&mut stream.decoder))
            .unwrap(),
        IaxPeerEvent::Audio(80)
    );
    assert_eq!(pcm[..80], expected[80..]);
}

#[test]
fn playout_source_clock_and_native_gap_retry_preserve_the_prefix() {
    let mut stream = provider_decoder("opus", crate::codec::providers::ProfileId::Opus);
    let mut encoded = [0; 4000];
    let result = stream
        .encoder
        .encode(&[0.1; 960], &mut encoded, false)
        .unwrap();
    let payload = &encoded[..result.encoded_bytes];
    let fixture = Fixture::new();
    let origin = Instant::now();
    let timestamp = (0x1_0000_0000 + 1000) * 48;
    fixture.packet(0, timestamp, payload, 960);
    fixture.last_packet_span(960);
    let mut playout = Playout::new_at_rate(
        unsafe { Jitter::new_at_rate(fixture.descriptor(), 48000, 480) }.unwrap(),
        origin,
        48000,
    );
    playout
        .put_with_codec(1000, false, origin, payload, Some(&stream.decoder))
        .unwrap();
    assert_eq!((fixture.puts()[0].0, fixture.puts()[0].1), (timestamp, 960));
    assert!(matches!(
        playout.poll_with_codec(origin, &mut [0.75; 959], Some(&mut stream.decoder)),
        Err(DialError::Provider(_))
    ));
    assert!(fixture.advances().is_empty());
    let mut pcm = [0.75; 960];
    assert_eq!(
        playout
            .poll_with_codec(origin, &mut pcm, Some(&mut stream.decoder))
            .unwrap(),
        IaxPeerEvent::Audio(960)
    );
    assert!(fixture.advances().is_empty());
    assert_eq!(
        playout
            .poll_with_codec(origin, &mut pcm, Some(&mut stream.decoder))
            .unwrap(),
        IaxPeerEvent::Audio(960)
    );
    assert_eq!(fixture.advances().len(), 1);
}

#[test]
fn playout_aggregated_packet_decodes_once_and_releases_bounded_pcm_chunks() {
    let mut stream = provider_decoder("gsm", crate::codec::providers::ProfileId::GsmFr);
    let mut packet = Vec::new();
    let mut unit = [0; 33];
    for _ in 0..30 {
        stream
            .encoder
            .encode(&[0.1; 160], &mut unit, false)
            .unwrap();
        packet.extend_from_slice(&unit);
    }
    let mut reference = provider_decoder("gsm", crate::codec::providers::ProfileId::GsmFr);
    let mut expected = vec![0.0; 4800];
    reference.decoder.decode(&packet, &mut expected).unwrap();
    let fixture = Fixture::new();
    fixture.packet(0, 8000, &packet, 0);
    fixture.last_packet_span(4800);
    let origin = Instant::now();
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    let mut pcm = [0.0; 160];
    for part in expected.chunks_exact(160) {
        assert_eq!(
            playout
                .poll_with_codec(origin, &mut pcm, Some(&mut stream.decoder))
                .unwrap(),
            IaxPeerEvent::Audio(160)
        );
        assert_eq!(pcm, part);
    }
    assert_eq!(fixture.advances().len(), 1);
    assert!(!playout.blocks_transport());
}

#[test]
fn key_does_not_discard_voice_that_arrived_ahead_of_its_control_sequence() {
    let fixture = Fixture::new();
    let origin = Instant::now();
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    playout.put(1020, false, origin, &[0x80; 160]).unwrap();
    fixture.packet(60_000_000, (0x1_0000_0000 + 1020) * 8, &[0x80; 160], 0);
    assert!(playout.key(1000).unwrap());
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(60), &mut [0.0; 160])
            .unwrap(),
        IaxPeerEvent::Audio(160)
    );
}

#[test]
fn packet_is_decoded_only_when_due_and_keeps_original_receive_time() {
    let fixture = Fixture::new();
    fixture.packet(60_000_000, (0x1_0000_0000 + 1000) * 8, &[0x80, 0x00], 0);
    let origin = Instant::now();
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    playout
        .put(
            1000,
            false,
            origin + Duration::from_millis(3),
            &[0x80, 0x00],
        )
        .unwrap();
    let mut pcm = [9.0; 160];
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(59), &mut pcm)
            .unwrap(),
        IaxPeerEvent::None
    );
    assert_eq!(pcm, [9.0; 160]);
    assert_eq!(
        playout.deadline(origin),
        Some(origin + Duration::from_millis(60))
    );
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(60), &mut pcm)
            .unwrap(),
        IaxPeerEvent::Audio(2)
    );
    assert_eq!(&pcm[..2], &[32124.0 / 32768.0, -32124.0 / 32768.0]);
    assert_eq!(
        playout.deadline(origin),
        Some(origin + Duration::from_millis(120))
    );
    assert_eq!(
        fixture.puts(),
        vec![((0x1_0000_0000 + 1000) * 8, 2, 3_000_000, vec![0x80, 0x00])]
    );
    assert_eq!(fixture.advances(), vec![(60_000_000, 0)]);
}

#[test]
fn missing_and_insertion_keep_gap_position_and_never_write_silence_into_pcm() {
    for insertion in [false, true] {
        let fixture = Fixture::new();
        fixture.packet(60_000_000, 8000, &[0x80; 160], 0);
        fixture.gap(80_000_000, 8160, 160, insertion);
        fixture.packet(
            100_000_000,
            if insertion { 8160 } else { 8320 },
            &[0x00; 160],
            0,
        );
        let origin = Instant::now();
        let mut playout = Playout::new(
            unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
            origin,
        );
        let mut pcm = [9.0; 160];
        assert_eq!(
            playout
                .poll(origin + Duration::from_millis(60), &mut pcm)
                .unwrap(),
            IaxPeerEvent::Audio(160)
        );
        assert!(pcm.iter().all(|sample| *sample > 0.9));
        assert_eq!(
            playout
                .poll(origin + Duration::from_millis(80), &mut pcm)
                .unwrap(),
            IaxPeerEvent::Gap(160)
        );
        assert!(pcm.iter().all(|sample| *sample > 0.9));
        assert_eq!(
            playout
                .poll(origin + Duration::from_millis(100), &mut pcm)
                .unwrap(),
            IaxPeerEvent::Audio(160)
        );
        assert!(pcm.iter().all(|sample| *sample < -0.9));
        assert_eq!(fixture.advances().len(), 3);
    }
}

#[test]
fn signed_partial_offsets_deliver_prefix_gap_before_audio_and_skip_overlap() {
    let fixture = Fixture::new();
    fixture.packet(60_000_000, 8000, &[0x80, 0x00], 40);
    fixture.packet(80_000_000, 8001, &[0x80, 0x00], -1);
    let origin = Instant::now();
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    let mut pcm = [9.0; 160];
    let now = origin + Duration::from_millis(60);
    assert_eq!(playout.poll(now, &mut pcm).unwrap(), IaxPeerEvent::Gap(40));
    assert_eq!(playout.deadline(now), Some(now));
    assert_eq!(pcm, [9.0; 160]);
    assert!(fixture.advances().is_empty());
    assert_eq!(playout.poll(now, &mut pcm).unwrap(), IaxPeerEvent::Audio(2));
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(80), &mut pcm)
            .unwrap(),
        IaxPeerEvent::Audio(1)
    );
    assert_eq!(pcm[0], -32124.0 / 32768.0);
    assert_eq!(fixture.advances().len(), 2);
}

#[test]
fn egress_unkey_deadline_drains_accepted_tail_before_releasing_control() {
    for with_tail in [false, true] {
        let fixture = Fixture::new();
        let origin = Instant::now();
        let mut playout = Playout::new(
            unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
            origin,
        );
        if with_tail {
            playout.put(1000, false, origin, &[0x80; 160]).unwrap();
            fixture.packet(60_000_000, (0x1_0000_0000 + 1000) * 8, &[0x80; 160], 0);
            assert_eq!(
                playout.poll(origin, &mut [0.0; 160]).unwrap(),
                IaxPeerEvent::None
            );
        }
        playout.unkey();
        let due = origin + Duration::from_millis(60);
        if with_tail {
            assert_eq!(playout.deadline(origin), Some(due));
            assert_eq!(
                playout.poll(due, &mut [0.0; 160]).unwrap(),
                IaxPeerEvent::Audio(160)
            );
        }
        assert_eq!(playout.deadline(due), Some(due));
        assert_eq!(
            playout.poll(due, &mut []).unwrap(),
            IaxPeerEvent::RadioUnkey
        );
        assert_eq!(playout.deadline(due), None);
    }
}

#[test]
fn full_and_mini_timestamps_unwrap_without_reversing_reference_on_reordering() {
    let fixture = Fixture::new();
    let origin = Instant::now();
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    for (timestamp, mini) in [
        (0xffff_fff0, false),
        (4, true),
        (16, false),
        (0xfff8, true),
        (20, true),
    ] {
        playout.put(timestamp, mini, origin, &[0xff; 160]).unwrap();
    }
    assert_eq!(
        fixture.puts().iter().map(|put| put.0).collect::<Vec<_>>(),
        [
            0x1_ffff_fff0 * 8,
            0x2_0000_0004 * 8,
            0x2_0000_0010 * 8,
            0x1_ffff_fff8 * 8,
            0x2_0000_0014 * 8
        ]
    );
}

#[test]
fn unkey_drains_valid_tail_before_a_deferred_next_key_and_cannot_leak_old_audio() {
    let fixture = Fixture::new();
    let origin = Instant::now();
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    let first = (0x1_0000_0000 + 1000) * 8;
    fixture.packet(60_000_000, first, &[0x80; 160], 0);
    fixture.packet(80_000_000, first + 160, &[0x00; 160], 0);
    playout.put(1000, false, origin, &[0x80; 160]).unwrap();
    playout
        .put(1020, true, origin + Duration::from_millis(20), &[0x00; 160])
        .unwrap();
    playout.unkey();
    assert!(!playout.key(1040).unwrap());
    assert!(playout.blocks_transport());
    let mut pcm = [0.0; 160];
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(60), &mut pcm)
            .unwrap(),
        IaxPeerEvent::Audio(160)
    );
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(79), &mut pcm)
            .unwrap(),
        IaxPeerEvent::None
    );
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(80), &mut pcm)
            .unwrap(),
        IaxPeerEvent::Audio(160)
    );
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(80), &mut pcm)
            .unwrap(),
        IaxPeerEvent::RadioUnkey
    );
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(80), &mut pcm)
            .unwrap(),
        IaxPeerEvent::RadioKey
    );
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(200), &mut pcm)
            .unwrap(),
        IaxPeerEvent::None
    );
    assert!(!playout.blocks_transport());
}

#[test]
fn short_pcm_output_preserves_the_fetched_packet_until_retry() {
    let fixture = Fixture::new();
    fixture.packet(60_000_000, 8000, &[0x80, 0x00], 0);
    let origin = Instant::now();
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    let now = origin + Duration::from_millis(60);
    assert!(matches!(
        playout.poll(now, &mut [9.0]),
        Err(DialError::Decode(_))
    ));
    assert!(fixture.advances().is_empty());
    assert!(playout.blocks_transport());
    assert_eq!(
        playout.poll(now, &mut [0.0; 2]).unwrap(),
        IaxPeerEvent::Audio(2)
    );
    assert_eq!(fixture.advances(), [(60_000_000, 0)]);
}

#[test]
fn empty_unkey_releases_without_manufacturing_gap() {
    let fixture = Fixture::new();
    let origin = Instant::now();
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    playout.unkey();
    assert_eq!(
        playout.poll(origin, &mut []).unwrap(),
        IaxPeerEvent::RadioUnkey
    );
    assert_eq!(
        playout
            .poll(origin + Duration::from_secs(1), &mut [])
            .unwrap(),
        IaxPeerEvent::None
    );
}

#[test]
fn voice_after_unkey_resumes_without_requiring_another_radio_key() {
    for (mini, delayed_key) in [(false, false), (false, true), (true, false), (true, true)] {
        let fixture = Fixture::new();
        let origin = Instant::now();
        let mut playout = Playout::new(
            unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
            origin,
        );
        playout.unkey();
        assert_eq!(
            playout.poll(origin, &mut []).unwrap(),
            IaxPeerEvent::RadioUnkey
        );
        // ASL media can continue after UNKEY without another explicit KEY.
        playout.put(1000, mini, origin, &[0x80; 160]).unwrap();
        assert_eq!(fixture.puts().len(), 1);
        fixture.packet(60_000_000, (0x1_0000_0000 + 1000) * 8, &[0x80; 160], 0);
        if delayed_key {
            assert!(playout.key(1000).unwrap());
        }
        let mut pcm = [0.0; 160];
        assert_eq!(
            playout
                .poll(origin + Duration::from_millis(60), &mut pcm)
                .unwrap(),
            IaxPeerEvent::Audio(160)
        );
        assert!(pcm.iter().all(|sample| *sample == 32124.0 / 32768.0));
    }
}

#[test]
fn pcm_only_quiet_tail_stops_missing_and_restarts_with_a_fresh_arrival_epoch() {
    let fixture = Fixture::new();
    let origin = Instant::now();
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    let first = (0x1_0000_0000 + 1000) * 8;
    playout.put(1000, false, origin, &[0x80; 160]).unwrap();
    fixture.packet(60_000_000, first, &[0x80; 160], 0);
    fixture.gap(80_000_000, first + 160, 80, false);
    let mut pcm = [0.0; 160];
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(60), &mut pcm)
            .unwrap(),
        IaxPeerEvent::Audio(160)
    );
    for milliseconds in [80, 120, 1000] {
        assert_eq!(
            playout
                .poll(origin + Duration::from_millis(milliseconds), &mut pcm)
                .unwrap(),
            IaxPeerEvent::None
        );
    }
    playout
        .put(
            3000,
            false,
            origin + Duration::from_millis(2000),
            &[0x00; 160],
        )
        .unwrap();
    fixture.packet(2_060_000_000, first + 16000, &[0x00; 160], 0);
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(2059), &mut pcm)
            .unwrap(),
        IaxPeerEvent::None
    );
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(2060), &mut pcm)
            .unwrap(),
        IaxPeerEvent::Audio(160)
    );
    assert_eq!(fixture.advances().len(), 2);
}

#[test]
fn captured_arrival_before_quiet_deadline_preserves_tail_despite_late_handler() {
    let fixture = Fixture::new();
    let origin = Instant::now();
    let first = (0x1_0000_0000 + 1000) * 8;
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    playout.put(1000, false, origin, &[0x80; 160]).unwrap();
    fixture.packet(60_000_000, first, &[0x80; 160], 0);
    let mut pcm = [0.0; 160];
    playout
        .poll(origin + Duration::from_millis(60), &mut pcm)
        .unwrap();
    fixture.packet(80_000_000, first + 160, &[0x00; 160], 0);
    playout
        .put(
            1020,
            true,
            origin + Duration::from_millis(100),
            &[0x00; 160],
        )
        .unwrap();
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(500), &mut pcm)
            .unwrap(),
        IaxPeerEvent::Audio(160)
    );
    assert_eq!(fixture.advances().len(), 2);
}

#[test]
fn accepted_future_tail_prevents_quiet_reset_before_its_deadline() {
    let fixture = Fixture::new();
    let origin = Instant::now();
    let first = (0x1_0000_0000 + 1000) * 8;
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    for timestamp in [1000, 1020] {
        playout.put(timestamp, false, origin, &[0x80; 160]).unwrap();
    }
    fixture.packet(60_000_000, first, &[0x80; 160], 0);
    fixture.packet(500_000_000, first + 160, &[0x00; 160], 0);
    let mut pcm = [0.0; 160];
    playout
        .poll(origin + Duration::from_millis(60), &mut pcm)
        .unwrap();
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(200), &mut pcm)
            .unwrap(),
        IaxPeerEvent::None
    );
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(500), &mut pcm)
            .unwrap(),
        IaxPeerEvent::Audio(160)
    );
}

#[test]
fn resumed_packet_after_true_quiet_expiry_resets_before_admission_without_a_timer_poll() {
    let fixture = Fixture::new();
    let origin = Instant::now();
    let first = (0x1_0000_0000 + 1000) * 8;
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    playout.put(1000, false, origin, &[0x80; 160]).unwrap();
    fixture.packet(60_000_000, first, &[0x80; 160], 0);
    let mut pcm = [0.0; 160];
    playout
        .poll(origin + Duration::from_millis(60), &mut pcm)
        .unwrap();
    fixture.gap(80_000_000, first + 160, 80, false);
    playout
        .put(
            3000,
            false,
            origin + Duration::from_millis(2000),
            &[0x00; 160],
        )
        .unwrap();
    fixture.packet(2_060_000_000, first + 16000, &[0x00; 160], 0);
    assert_eq!(
        playout
            .poll(origin + Duration::from_millis(2060), &mut pcm)
            .unwrap(),
        IaxPeerEvent::Audio(160)
    );
}

#[test]
fn observations_preserve_cumulative_counters_across_burst_resets_not_old_gauges() {
    let fixture = Fixture::new();
    let origin = Instant::now();
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    fixture.observation(Observation {
        queued_packets: 2,
        buffered_span: 320,
        duplicate_drops: 1,
        late_drops: 2,
        full_drops: 3,
        missing_span: 4,
        insertion_span: 5,
        skipped_span: 6,
        limit_resets: 7,
        overload_drops: 8,
        overload_span: 9,
        ..Observation::default()
    });
    playout.unkey();
    assert_eq!(
        playout.poll(origin, &mut []).unwrap(),
        IaxPeerEvent::RadioUnkey
    );
    fixture.observation(Observation {
        duplicate_drops: 10,
        ..Observation::default()
    });
    for _ in 0..2 {
        let observation = playout.observe().unwrap();
        assert_eq!(
            (observation.queued_packets, observation.buffered_span),
            (0, 0)
        );
        assert_eq!(
            [
                observation.duplicate_drops,
                observation.late_drops,
                observation.full_drops,
                observation.missing_span,
                observation.insertion_span,
                observation.skipped_span,
                observation.limit_resets,
                observation.overload_drops,
                observation.overload_span
            ],
            [11, 2, 3, 4, 5, 6, 7, 8, 9]
        );
    }
}

#[test]
fn rejected_late_tail_cannot_extend_unkey_drainage() {
    for admission in [1, 2, 3] {
        let fixture = Fixture::new();
        let origin = Instant::now();
        let first = (0x1_0000_0000 + 1000) * 8;
        let mut playout = Playout::new(
            unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
            origin,
        );
        playout.put(1000, false, origin, &[0x80; 160]).unwrap();
        fixture.packet(60_000_000, first, &[0x80; 160], 0);
        let now = origin + Duration::from_millis(60);
        assert_eq!(
            playout.poll(now, &mut [0.0; 160]).unwrap(),
            IaxPeerEvent::Audio(160)
        );
        playout.unkey();
        fixture.admission(admission);
        playout.put(1020, false, now, &[0x00; 160]).unwrap();
        assert_eq!(
            playout.poll(now, &mut []).unwrap(),
            IaxPeerEvent::RadioUnkey
        );
        assert_eq!(fixture.advances(), [(60_000_000, 0)]);
    }
}

#[test]
fn overload_empty_timeline_completes_unkey_without_a_fabricated_gap() {
    let fixture = Fixture::new();
    let origin = Instant::now();
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    playout.put(1000, false, origin, &[0x80; 160]).unwrap();
    fixture.observation(Observation {
        limit_resets: 1,
        overload_drops: 1,
        overload_span: 160,
        ..Observation::default()
    });
    playout.unkey();
    assert_eq!(
        playout.poll(origin, &mut []).unwrap(),
        IaxPeerEvent::RadioUnkey
    );
    assert!(fixture.advances().is_empty());
    assert_eq!(playout.observe().unwrap().overload_span, 160);
}

#[test]
fn packet_span_must_match_the_ulaw_payload_before_decode() {
    let fixture = Fixture::new();
    let origin = Instant::now();
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    fixture.packet(0, 8000, &[0x80; 160], 0);
    fixture.last_packet_span(80);
    let mut pcm = [9.0; 160];
    assert!(matches!(
        playout.poll(origin, &mut pcm),
        Err(DialError::Jitter)
    ));
    assert_eq!(pcm, [9.0; 160]);
    assert!(fixture.advances().is_empty());
}

#[test]
fn unkey_keeps_missing_media_before_tail_but_never_emits_gaps_past_it() {
    for insertion in [false, true] {
        let fixture = Fixture::new();
        let origin = Instant::now();
        let first = (0x1_0000_0000 + 1000) * 8;
        let mut playout = Playout::new(
            unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
            origin,
        );
        playout.put(1000, false, origin, &[0x80; 160]).unwrap();
        fixture.gap(0, first, 80, insertion);
        fixture.gap(0, first + 160, 80, insertion);
        playout.unkey();
        let mut pcm = [9.0; 160];
        assert_eq!(
            playout.poll(origin, &mut pcm).unwrap(),
            IaxPeerEvent::Gap(80)
        );
        assert_eq!(
            playout.poll(origin, &mut pcm).unwrap(),
            IaxPeerEvent::RadioUnkey
        );
        assert_eq!(pcm, [9.0; 160]);
        assert_eq!(fixture.advances(), [(0, 0)]);
    }
}
