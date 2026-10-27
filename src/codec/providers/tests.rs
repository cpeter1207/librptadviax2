//! Reject invalid descriptors before any operation/context can be advertised.
use super::*;
use std::cell::RefCell;

fn catalog() -> CodecCatalog {
    CodecCatalog::load(&[ProviderSelection {
        path: PathBuf::from(std::env::var_os("RPTADV_CODEC_DIR").unwrap())
            .join("librptadv_codec_g711.so"),
        profiles: vec![ProfileId::G711Mu],
    }])
    .unwrap()
}

fn api(catalog: &mut CodecCatalog) -> &mut RawDescriptor {
    &mut Arc::get_mut(
        &mut catalog
            .selected
            .get_mut(&ProfileId::G711Mu)
            .unwrap()
            .provider,
    )
    .unwrap()
    .api
}

#[derive(Default)]
struct Script {
    code: i32,
    encoded: RawEncoded,
    frames: usize,
    decode_code: i32,
    inspect_code: i32,
    conceal_code: i32,
    calls: Vec<&'static str>,
}
thread_local! { static SCRIPT: RefCell<Script> = RefCell::new(Script::default()); }

unsafe extern "C" fn encode_return(
    _: *mut c_void,
    _: *const f32,
    _: usize,
    _: *mut u8,
    _: usize,
    _: u32,
    out: *mut RawEncoded,
) -> i32 {
    SCRIPT.with_borrow_mut(|script| {
        unsafe { out.write(script.encoded) };
        script.code
    })
}
unsafe extern "C" fn decode_return(
    _: *mut c_void,
    _: *const u8,
    _: usize,
    _: *mut f32,
    _: usize,
    frames: *mut usize,
) -> i32 {
    SCRIPT.with_borrow_mut(|script| {
        script.calls.push("decode");
        unsafe { frames.write(script.frames) };
        script.decode_code
    })
}
unsafe extern "C" fn inspect_return(
    _: *mut c_void,
    _: *const u8,
    _: usize,
    out: *mut RawPacket,
) -> i32 {
    SCRIPT.with_borrow_mut(|script| {
        script.calls.push("inspect");
        unsafe {
            (*out).frames = 160;
            (*out).required_capacity = 123;
        };
        script.inspect_code
    })
}
unsafe extern "C" fn conceal_return(
    _: *mut c_void,
    requested: u32,
    _: *mut f32,
    _: usize,
    frames: *mut usize,
) -> i32 {
    assert_eq!(requested, 160);
    SCRIPT.with_borrow_mut(|script| {
        script.calls.push("conceal");
        unsafe { frames.write(script.frames) };
        script.conceal_code
    })
}
unsafe extern "C" fn open_return(_: *const RawConfig, _: *mut *mut c_void) -> i32 {
    SCRIPT.with_borrow(|script| script.code)
}
unsafe extern "C" fn failed_reset(_: *mut c_void) -> i32 {
    5
}

#[test]
fn directional_open_failures_and_null_contexts_do_not_become_live_owners() {
    let mut owner = catalog();
    let table = api(&mut owner);
    table.open_encoder = Some(open_return);
    table.open_decoder = Some(open_return);
    for code in [0, 5] {
        SCRIPT.set(Script {
            code,
            ..Default::default()
        });
        assert!(owner.encoder(ProfileId::G711Mu, 0, 160, 160).is_err());
        assert!(owner.decoder(ProfileId::G711Mu, 0, 160, 160).is_err());
    }
}

#[test]
fn encoder_rejects_each_invalid_native_result_without_exposing_bytes() {
    let mut owner = catalog();
    api(&mut owner).encode = Some(encode_return);
    api(&mut owner).reset = Some(failed_reset);
    let mut encoder = owner.encoder(ProfileId::G711Mu, 0, 160, 160).unwrap();
    let valid = RawEncoded {
        struct_size: size_of::<RawEncoded>() as u32,
        consumed_frames: 1,
        encoded_bytes: 1,
        source_frames: 1,
        packet_frames: 1,
        ..Default::default()
    };
    let mutations: &[fn(&mut RawEncoded)] = &[
        |raw| raw.status = 1,
        |raw| raw.consumed_frames = 2,
        |raw| raw.encoded_bytes = 2,
        |raw| raw.source_frames = 2,
        |raw| {
            raw.source_frames = 0;
            raw.packet_frames = 0;
        },
    ];
    for mutate in mutations {
        let mut encoded = valid;
        mutate(&mut encoded);
        SCRIPT.set(Script {
            encoded,
            ..Default::default()
        });
        assert_eq!(
            encoder
                .encode(&[0.0], &mut [0], false)
                .unwrap_err()
                .operation,
            "provider encode result"
        );
    }
    SCRIPT.set(Script {
        encoded: valid,
        ..Default::default()
    });
    assert_eq!(
        encoder
            .encode(&[0.0], &mut [0], false)
            .unwrap()
            .encoded_bytes,
        1
    );
    SCRIPT.set(Script {
        code: 1,
        encoded: RawEncoded {
            status: 1,
            ..Default::default()
        },
        ..Default::default()
    });
    assert_eq!(
        encoder.encode(&[], &mut [0], false).unwrap().status,
        Status::NeedInput
    );
    SCRIPT.set(Script {
        code: 2,
        encoded: RawEncoded {
            required_capacity: 123,
            ..Default::default()
        },
        ..Default::default()
    });
    assert_eq!(
        encoder
            .encode(&[], &mut [], false)
            .unwrap_err()
            .required_capacity,
        123
    );
    assert_eq!(encoder.reset().unwrap_err().status, Status::Failed);
}

#[test]
fn decoder_validates_native_counts_and_recovers_only_malformed_packets_once() {
    let mut owner = catalog();
    let table = api(&mut owner);
    table.decode = Some(decode_return);
    table.inspect = Some(inspect_return);
    table.conceal = Some(conceal_return);
    let mut decoder = owner.decoder(ProfileId::G711Mu, 0, 160, 160).unwrap();
    for (decode_code, inspect_code, conceal_code, frames, expected, calls) in [
        (0, 0, 0, 1, Ok(1), vec!["decode"]),
        (5, 0, 0, 0, Err(Status::Failed), vec!["decode"]),
        (3, 5, 0, 0, Err(Status::Failed), vec!["decode", "inspect"]),
        (3, 0, 0, 160, Ok(160), vec!["decode", "inspect", "conceal"]),
        (3, 0, 4, 0, Ok(0), vec!["decode", "inspect", "conceal"]),
        (
            3,
            0,
            5,
            0,
            Err(Status::Failed),
            vec!["decode", "inspect", "conceal"],
        ),
    ] {
        SCRIPT.set(Script {
            decode_code,
            inspect_code,
            conceal_code,
            frames,
            ..Default::default()
        });
        let result = decoder
            .decode_recovering(&[0], &mut [0.0; 160])
            .map_err(|error| error.status);
        assert_eq!(result, expected);
        SCRIPT.with_borrow(|script| assert_eq!(script.calls, calls));
    }
    for (conceal_code, frames, capacity, status) in [
        (4, 1, 160, Status::Unsupported),
        (0, 159, 160, Status::Failed),
        (0, 160, 159, Status::Failed),
    ] {
        SCRIPT.set(Script {
            conceal_code,
            frames,
            ..Default::default()
        });
        assert_eq!(
            decoder
                .conceal(160, &mut vec![0.0; capacity])
                .unwrap_err()
                .status,
            status
        );
    }
    SCRIPT.set(Script {
        frames: 161,
        ..Default::default()
    });
    assert_eq!(
        decoder.decode(&[0], &mut [0.0; 160]).unwrap_err().operation,
        "provider decode result"
    );
    SCRIPT.set(Script {
        inspect_code: 2,
        ..Default::default()
    });
    assert_eq!(decoder.inspect(&[0]).unwrap_err().required_capacity, 123);
}

#[test]
fn playout_preserves_provider_errors_and_orders_unrecoverable_media_as_a_gap() {
    use crate::{client::IaxPeerEvent, jitter::Jitter, playout::Playout};
    let mut owner = catalog();
    let table = api(&mut owner);
    table.decode = Some(decode_return);
    table.inspect = Some(inspect_return);
    table.conceal = Some(conceal_return);
    let mut decoder = owner.decoder(ProfileId::G711Mu, 0, 160, 160).unwrap();
    let fixture = crate::jitter::fixture::Fixture::new();
    let origin = std::time::Instant::now();
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    SCRIPT.set(Script {
        inspect_code: 5,
        ..Default::default()
    });
    assert!(
        matches!(playout.put_with_codec(0, false, origin, &[0], Some(&decoder)), Err(crate::client::DialError::Provider(error)) if error.status == Status::Failed)
    );
    assert!(fixture.advances().is_empty());
    SCRIPT.set(Script {
        decode_code: 3,
        conceal_code: 4,
        ..Default::default()
    });
    fixture.packet(0, 8000, &[0], 0);
    fixture.last_packet_span(160);
    let mut pcm = [0.75; 160];
    assert_eq!(
        playout
            .poll_with_codec(origin, &mut pcm, Some(&mut decoder))
            .unwrap(),
        IaxPeerEvent::Gap(160)
    );
    assert_eq!(pcm, [0.75; 160]);
    assert_eq!(fixture.advances().len(), 1);
    SCRIPT.with_borrow(|script| {
        assert_eq!(script.calls, ["inspect", "decode", "inspect", "conceal"])
    });
}

#[test]
fn direct_receive_ignores_malformed_framing_but_preserves_provider_failure_and_loss() {
    use crate::{
        client::{DialError, IaxPeer, IaxPeerEvent},
        formats::FormatCatalog,
        network::SharedSocket,
    };
    let mut owner = catalog();
    let table = api(&mut owner);
    table.decode = Some(decode_return);
    table.inspect = Some(inspect_return);
    table.conceal = Some(conceal_return);
    let formats = FormatCatalog::new(Arc::new(owner), &[ProfileId::G711Mu]).unwrap();
    let remote = "127.0.0.1:4569".parse().unwrap();
    let socket = Arc::new(SharedSocket::new(
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
    ));
    let (mut producer, ingress) = crate::ingress::producer_ingress(4, 1).unwrap();
    let (mut peer, _) = IaxPeer::from_inbound(
        socket.clone(),
        ingress,
        socket.local_addr().unwrap(),
        remote,
        1234,
        5678,
        crate::codec::IAX_FORMAT_ULAW,
    )
    .unwrap();
    peer.compose_codec(&formats).unwrap();
    let packet = crate::protocol::serialize_mini_frame(
        &crate::protocol::MiniFrameHeader {
            source_call_number: 5678,
            timestamp: 20,
        },
        &[0],
    )
    .unwrap();
    for inspect_code in [3, 5, 0] {
        SCRIPT.set(Script {
            inspect_code,
            decode_code: 3,
            conceal_code: 4,
            ..Default::default()
        });
        producer.try_push(remote, &packet).unwrap();
        let mut pcm = [0.75; 160];
        let result = peer.poll_event(&mut pcm, &mut []);
        match inspect_code {
            3 => assert_eq!(result.unwrap(), IaxPeerEvent::None),
            5 => assert!(
                matches!(result, Err(DialError::Provider(error)) if error.status == Status::Failed)
            ),
            _ => assert_eq!(result.unwrap(), IaxPeerEvent::Gap(160)),
        }
        assert_eq!(pcm, [0.75; 160]);
        assert_eq!(
            peer.poll_event(&mut pcm, &mut []).unwrap(),
            IaxPeerEvent::None
        );
    }
}

#[test]
fn provider_status_codes_preserve_known_results_and_reject_unknown_values() {
    for (code, status) in [
        (0, Status::Complete),
        (1, Status::NeedInput),
        (2, Status::OutputFull),
        (3, Status::Malformed),
        (4, Status::Unsupported),
        (5, Status::Failed),
    ] {
        assert_eq!(status.as_raw(), code as u32);
        assert_eq!(Status::from_raw(code), status);
    }
    for unknown in [-1, 6] {
        assert_eq!(Status::from_raw(unknown), Status::Failed);
    }
}

#[test]
fn contract_rejects_bad_tables_and_unknown_profiles() {
    assert!(unsafe { table(std::ptr::null()) }.is_err());
    assert!(unsafe { table(std::ptr::dangling::<u8>().cast()) }.is_err());
    let mut raw = RawDescriptor::default();
    assert!(unsafe { table(&raw) }.is_err());
    let owner = catalog();
    let valid = owner.selected[&ProfileId::G711Mu].provider.api;
    assert!(unsafe { table(&valid) }.is_ok());
    let mutations: &[fn(&mut RawDescriptor)] = &[
        |raw| raw.abi_version = 999,
        |raw| raw.capability[0] = 0,
        |raw| raw.profile_count = None,
        |raw| raw.profile_at = None,
        |raw| raw.open_encoder = None,
        |raw| raw.open_decoder = None,
        |raw| raw.inspect = None,
        |raw| raw.encode = None,
        |raw| raw.decode = None,
        |raw| raw.reset = None,
        |raw| raw.destroy = None,
        |raw| raw.conceal = None,
    ];
    for mutate in mutations {
        let mut bad = valid;
        mutate(&mut bad);
        assert!(unsafe { table(&bad) }.is_err());
    }
    raw.struct_size = size_of::<RawDescriptor>() as u32;
    raw.abi_version = 1;
    raw.capability = *b"rptadv.codec.v1\0";
    assert!(unsafe { table(&raw) }.is_err());
    assert_eq!(ProfileId::from_raw(0), None);
    assert_eq!(ProfileId::from_raw(17), None);
    for id in 1..=16 {
        assert_eq!(ProfileId::from_raw(id).unwrap() as u32, id);
    }
}

#[test]
fn contract_profile_copies_modes_and_rejects_invalid_metadata() {
    let mode = RawMode {
        struct_size: size_of::<RawMode>() as u32,
        id: 0,
        bitrate_bps: 64000,
        frame_samples: 1,
        frame_bytes: 1,
    };
    let mut raw = RawProfile {
        struct_size: size_of::<RawProfile>() as u32,
        id: 1,
        sample_rate_hz: 8000,
        channels: 1,
        directions: 3,
        lookahead_frames: 0,
        maximum_frame_samples: 1,
        maximum_frame_bytes: 1,
        mode_count: 1,
        modes: &mode,
    };
    assert_eq!(
        unsafe { copy_profile(&raw) }.unwrap().modes[0].frame_samples,
        1
    );
    raw.directions = 1;
    assert!(unsafe { copy_profile(&raw) }.is_err());
    raw.directions = 3;
    raw.sample_rate_hz = 16000;
    assert!(unsafe { copy_profile(&raw) }.is_err());
    raw.sample_rate_hz = 8000;
    let valid = raw;
    let mutations: &[fn(&mut RawProfile)] = &[
        |raw| raw.id = 999,
        |raw| raw.struct_size = 4,
        |raw| raw.channels = 2,
        |raw| raw.directions = 1,
        |raw| raw.sample_rate_hz = 44100,
        |raw| raw.maximum_frame_samples = 0,
        |raw| raw.maximum_frame_bytes = 0,
        |raw| raw.mode_count = 0,
        |raw| raw.mode_count = 17,
        |raw| raw.modes = std::ptr::null(),
        |raw| raw.modes = std::ptr::dangling::<u8>().cast(),
    ];
    for mutate in mutations {
        let mut bad = valid;
        mutate(&mut bad);
        assert!(unsafe { copy_profile(&bad) }.is_err());
    }
    let mutations: &[fn(&mut RawMode)] = &[
        |mode| mode.struct_size = 4,
        |mode| mode.frame_samples = 0,
        |mode| mode.frame_samples = 2,
        |mode| mode.frame_bytes = 2,
    ];
    for mutate in mutations {
        let mut bad_mode = mode;
        mutate(&mut bad_mode);
        let bad = RawProfile {
            modes: &bad_mode,
            ..valid
        };
        assert!(unsafe { copy_profile(&bad) }.is_err());
    }
    let mut modes = [mode, RawMode { id: 1, ..mode }];
    let pair = RawProfile {
        mode_count: 2,
        modes: modes.as_ptr(),
        ..valid
    };
    assert_eq!(unsafe { copy_profile(&pair) }.unwrap().modes.len(), 2);
    modes[1].id = 0;
    assert!(unsafe { copy_profile(&pair) }.is_err());
}

#[test]
fn selected_provider_lists_reject_empty_missing_and_duplicate_profiles() {
    let path = PathBuf::from(std::env::var_os("RPTADV_CODEC_DIR").unwrap())
        .join("librptadv_codec_g711.so");
    for (profiles, operation) in [
        (vec![], "empty provider selection"),
        (vec![ProfileId::GsmFr], "selected profile missing"),
        (vec![ProfileId::G711Mu; 2], "duplicate selected profile"),
    ] {
        let error = CodecCatalog::load(&[ProviderSelection {
            path: path.clone(),
            profiles,
        }])
        .err()
        .unwrap();
        assert_eq!(error.operation, operation);
    }
    let error = CodecCatalog::load(&[ProviderSelection {
        path: PathBuf::from("libc.so.6"),
        profiles: vec![ProfileId::G711Mu],
    }])
    .err()
    .unwrap();
    assert_eq!(error.operation, "provider symbol");
}

#[test]
fn loaded_provider_metadata_failures_do_not_advertise_partial_catalogs() {
    let owner = catalog();
    let real = owner.selected[&ProfileId::G711Mu].provider.api;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output = root.join(format!(
        "target/codec-loader-fixture-{}.so",
        std::process::id()
    ));
    let include = std::env::var_os("RPTADV_CODEC_INCLUDE")
        .unwrap_or_else(|| "/usr/include/rptadv-codec".into());
    assert!(
        std::process::Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()))
            .args([
                "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", "-I"
            ])
            .arg(include)
            .arg(root.join("tests/codec_loader_fixture.c"))
            .arg("-o")
            .arg(&output)
            .status()
            .unwrap()
            .success()
    );
    {
        let fixture = unsafe { Library::new(&output) }.unwrap();
        let configure = unsafe {
            fixture
                .get::<unsafe extern "C" fn(*const RawDescriptor, i32)>(b"rptadv_test_configure\0")
        }
        .unwrap();
        for (fault, operation) in [
            (1, "provider profile count"),
            (2, "provider profile count"),
            (3, "codec operation"),
            (4, "duplicate provider profile"),
        ] {
            unsafe { configure(&real, fault) };
            let error = CodecCatalog::load(&[ProviderSelection {
                path: output.clone(),
                profiles: vec![ProfileId::G711Mu],
            }])
            .err()
            .unwrap();
            assert_eq!(error.operation, operation);
        }
    }
    std::fs::remove_file(output).unwrap();
}
