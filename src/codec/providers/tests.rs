//! IAX receive/playout behavior uses the moved loader through a test-only DSO.
use super::*;
use libloading::Library;
use std::{ffi::CString, path::PathBuf, sync::Arc};

#[derive(Default)]
struct Script {
    inspect_code: i32,
    decode_code: i32,
    conceal_code: i32,
    frames: usize,
}
struct MediaFixture {
    library: Library,
    path: PathBuf,
}
impl MediaFixture {
    fn resets(&self) -> u32 {
        unsafe {
            self.library
                .get::<unsafe extern "C" fn() -> u32>(b"rptadv_test_resets\0")
                .unwrap()()
        }
    }
    fn reset_result(&self, result: i32) {
        unsafe {
            self.library
                .get::<unsafe extern "C" fn(i32)>(b"rptadv_test_reset_result\0")
                .unwrap()(result)
        }
    }
    fn new(name: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        std::fs::create_dir_all(root.join("target")).unwrap();
        let path = root.join("target").join(format!(
            "codec-media-{}-{}.so",
            std::process::id(),
            name.replace(':', "_")
        ));
        let include = std::env::var_os("RPTADV_CODEC_INCLUDE")
            .unwrap_or_else(|| "/usr/include/rptadv-codec".into());
        assert!(
            std::process::Command::new("cc")
                .args([
                    "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", "-I"
                ])
                .arg(include)
                .arg(root.join("tests/codec_media_fixture.c"))
                .arg("-ldl")
                .arg("-o")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let library = unsafe { Library::new(&path) }.unwrap();
        let provider = PathBuf::from(std::env::var_os("RPTADV_CODEC_DIR").unwrap())
            .join("librptadv_codec_g711.so");
        let provider = CString::new(provider.to_str().unwrap()).unwrap();
        let open = unsafe {
            library
                .get::<unsafe extern "C" fn(*const std::ffi::c_char) -> i32>(b"rptadv_test_open\0")
        }
        .unwrap();
        assert_eq!(unsafe { open(provider.as_ptr()) }, 0);
        Self { library, path }
    }
    fn catalog(&self) -> CodecCatalog {
        CodecCatalog::load(&[ProviderSelection {
            path: self.path.clone(),
            profiles: vec![ProfileId::G711Mu],
        }])
        .unwrap()
    }
    fn set(&self, script: Script) {
        let set = unsafe {
            self.library
                .get::<unsafe extern "C" fn(i32, i32, i32, usize)>(b"rptadv_test_results\0")
        }
        .unwrap();
        unsafe {
            set(
                script.inspect_code,
                script.decode_code,
                script.conceal_code,
                script.frames,
            )
        };
    }
    fn frame_unit(&self, unit: u32) {
        let set = unsafe {
            self.library
                .get::<unsafe extern "C" fn(u32)>(b"rptadv_test_frame_unit\0")
        }
        .unwrap();
        unsafe { set(unit) };
    }
    fn fail_decoder(&self) {
        let fail = unsafe {
            self.library
                .get::<unsafe extern "C" fn(i32)>(b"rptadv_test_fail_decoder\0")
        }
        .unwrap();
        unsafe { fail(1) };
    }
    fn context_counts(&self) -> (u32, u32) {
        let counts = unsafe {
            self.library
                .get::<unsafe extern "C" fn() -> u64>(b"rptadv_test_context_counts\0")
        }
        .unwrap();
        let counts = unsafe { counts() };
        ((counts >> 32) as u32, counts as u32)
    }
    fn calls(&self) -> u32 {
        let calls = unsafe {
            self.library
                .get::<unsafe extern "C" fn() -> u32>(b"rptadv_test_calls\0")
        }
        .unwrap();
        unsafe { calls() }
    }
}

#[test]
fn timed_epoch_retirement_resets_actual_codec_and_jitter_and_native_failure_stays_closed_until_drop()
 {
    use crate::{
        client::{IaxPeer, SourceTimeInput},
        formats::FormatCatalog,
        network::SharedSocket,
    };
    let media = MediaFixture::new(std::thread::current().name().unwrap());
    let formats = FormatCatalog::new(Arc::new(media.catalog()), &[ProfileId::G711Mu]).unwrap();
    let socket = Arc::new(SharedSocket::new(
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
    ));
    let (_producer, ingress) = crate::ingress::producer_ingress(4, 1).unwrap();
    let (mut peer, _) = IaxPeer::from_inbound(
        socket.clone(),
        ingress,
        socket.local_addr().unwrap(),
        "127.0.0.1:9".parse().unwrap(),
        1234,
        5678,
        crate::codec::IAX_FORMAT_ULAW,
    )
    .unwrap();
    peer.compose_codec(&formats).unwrap();
    let jitter = crate::jitter::fixture::Fixture::new();
    unsafe { peer.configure_jitter(jitter.descriptor()) }.unwrap();
    let input = SourceTimeInput {
        host_clock_epoch: 1,
        reference_now_ns: 1_000_000_000,
        acknowledged_media_epoch: 0,
    };
    assert_eq!(
        peer.poll_timed(&mut [], &mut [], input)
            .unwrap()
            .media_epoch,
        1
    );
    let reset = peer
        .poll_timed(
            &mut [],
            &mut [],
            SourceTimeInput {
                host_clock_epoch: 2,
                acknowledged_media_epoch: 1,
                ..input
            },
        )
        .unwrap();
    assert!(reset.discontinuity);
    assert_eq!(reset.media_epoch, 2);
    assert_eq!((media.resets(), jitter.resets()), (1, 1));
    media.reset_result(5);
    assert!(
        matches!(peer.poll_timed(&mut [], &mut [], SourceTimeInput { host_clock_epoch: 3, ..input }), Err(crate::client::DialError::Provider(error)) if error.status == Status::Failed)
    );
    assert_eq!((media.resets(), jitter.resets()), (2, 2));
    assert!(matches!(
        peer.poll_timed(&mut [], &mut [], input),
        Err(crate::client::DialError::Jitter)
    ));
    assert_eq!(media.context_counts(), (4, 2));
    drop(peer);
    assert_eq!(media.context_counts(), (4, 4));
}
impl Drop for MediaFixture {
    fn drop(&mut self) {
        std::fs::remove_file(&self.path).unwrap();
    }
}

#[test]
fn playout_preserves_provider_errors_and_orders_unrecoverable_media_as_a_gap() {
    use crate::{client::IaxPeerEvent, jitter::Jitter, playout::Playout};
    let media = MediaFixture::new(std::thread::current().name().unwrap());
    let owner = media.catalog();
    let mut decoder = owner.decoder(ProfileId::G711Mu, 0, 160, 160).unwrap();
    let fixture = crate::jitter::fixture::Fixture::new();
    let origin = std::time::Instant::now();
    let mut playout = Playout::new(
        unsafe { Jitter::new(fixture.descriptor()) }.unwrap(),
        origin,
    );
    media.set(Script {
        inspect_code: 5,
        ..Default::default()
    });
    assert!(
        matches!(playout.put_with_codec(0, false, origin, &[0], Some(&decoder)), Err(crate::client::DialError::Provider(error)) if error.status == Status::Failed)
    );
    assert!(fixture.advances().is_empty());
    media.set(Script {
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
    assert_eq!(media.calls(), 2123);
}

#[test]
fn direct_receive_ignores_malformed_framing_but_preserves_provider_failure_and_loss() {
    use crate::{
        client::{DialError, IaxPeer, IaxPeerEvent},
        formats::FormatCatalog,
        network::SharedSocket,
    };
    let media = MediaFixture::new(std::thread::current().name().unwrap());
    let owner = media.catalog();
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
        media.set(Script {
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
fn phone_catalog_rejects_valid_dynamic_coding_units_that_cannot_make_twenty_milliseconds() {
    let media = MediaFixture::new(std::thread::current().name().unwrap());
    media.frame_unit(81);
    let generic =
        crate::formats::FormatCatalog::new(Arc::new(media.catalog()), &[ProfileId::G711Mu])
            .unwrap();
    assert_eq!(generic.advertised_mask(), 4);
    assert!(
        generic.phone().is_none(),
        "a162sample native packet must not enter the160sample phone profile"
    );
    media.frame_unit(80);
    let accepted =
        crate::formats::FormatCatalog::new(Arc::new(media.catalog()), &[ProfileId::G711Mu])
            .unwrap();
    assert_eq!(accepted.phone().unwrap().advertised_mask(), 4);
}

#[test]
fn actual_per_call_codec_open_failure_retires_partial_context_without_answering_legacy_call() {
    use crate::{
        information_elements::InformationElement,
        server::{InboundIaxListener, ListenerError, ListenerEvent},
        session::{CallSetupResponse, OutboundCallSetup},
    };
    use std::{
        net::UdpSocket,
        time::{Duration, Instant},
    };
    let media = MediaFixture::new(std::thread::current().name().unwrap());
    let catalog = Arc::new(
        crate::formats::FormatCatalog::new(Arc::new(media.catalog()), &[ProfileId::G711Mu])
            .unwrap(),
    );
    assert_eq!(media.context_counts(), (2, 2));
    media.fail_decoder();
    let mut listener = InboundIaxListener::bind_with_catalog(
        "127.0.0.1:0".parse().unwrap(),
        &["1234".into()],
        catalog,
    )
    .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut setup = OutboundCallSetup::new(
        77,
        0,
        &[
            InformationElement {
                kind: 6,
                data: b"radio",
            },
            InformationElement {
                kind: 1,
                data: b"1234",
            },
            InformationElement {
                kind: 2,
                data: b"3000",
            },
            InformationElement {
                kind: 9,
                data: &[0, 0, 0, 4],
            },
        ],
    )
    .unwrap();
    socket
        .send_to(setup.initial_packet(), listener.local_addr().unwrap())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if matches!(
            listener.poll(1000, |_| true).unwrap(),
            ListenerEvent::Replied
        ) {
            break;
        }
        assert!(Instant::now() < deadline);
    }
    let mut bytes = [0; 2048];
    let (length, _) = socket.recv_from(&mut bytes).unwrap();
    let CallSetupResponse::Send(retry) = setup.receive(&bytes[..length], 0, "").unwrap() else {
        panic!("missing token")
    };
    socket
        .send_to(&retry, listener.local_addr().unwrap())
        .unwrap();
    loop {
        match listener.poll(1000, |_| true) {
            Err(ListenerError::InvalidFrame) => break,
            Ok(ListenerEvent::None) => assert!(Instant::now() < deadline),
            _ => panic!("codec creation failure must prevent ACCEPT/ANSWER"),
        }
        std::thread::yield_now();
    }
    assert_eq!(media.context_counts(), (3, 3));
    socket.set_nonblocking(true).unwrap();
    assert_eq!(
        socket.recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    listener.poll(1000, |_| false).unwrap();
    assert_eq!(listener.ingress_stats().active_routes, 0);
    drop(listener);
}

#[test]
fn timed_egress_native_encoder_reset_failure_keeps_media_closed_and_destroys_all_owned_contexts() {
    use crate::{
        client::{EgressRetirement, EgressTime, IaxPeer},
        formats::FormatCatalog,
        network::SharedSocket,
    };
    let media = MediaFixture::new(std::thread::current().name().unwrap());
    let formats = FormatCatalog::new(Arc::new(media.catalog()), &[ProfileId::G711Mu]).unwrap();
    let socket = Arc::new(SharedSocket::new(
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
    ));
    let (_producer, ingress) = crate::ingress::producer_ingress(4, 1).unwrap();
    let (mut peer, _) = IaxPeer::from_inbound(
        socket.clone(),
        ingress,
        socket.local_addr().unwrap(),
        "127.0.0.1:9".parse().unwrap(),
        1234,
        5678,
        crate::codec::IAX_FORMAT_ULAW,
    )
    .unwrap();
    peer.compose_codec(&formats).unwrap();
    assert_eq!(peer.retire_egress().unwrap(), EgressRetirement::Complete(2));
    assert_eq!(media.resets(), 1);
    media.reset_result(5);
    assert!(
        matches!(peer.retire_egress(),Err(crate::client::DialError::Provider(error)) if error.status == Status::Failed)
    );
    assert_eq!(media.resets(), 2);
    assert!(matches!(
        peer.retire_egress(),
        Err(crate::client::DialError::InvalidOptions)
    ));
    assert!(matches!(
        peer.prepare_audio(&[0.0; 160], &mut [0; 160], false),
        Err(crate::client::DialError::InvalidOptions)
    ));
    assert!(matches!(
        peer.send_prepared_audio_timed(
            &[0xff; 160],
            160,
            0,
            EgressTime {
                epoch: 2,
                deadline_ms: 500
            }
        ),
        Err(crate::client::DialError::InvalidOptions)
    ));
    let api = unsafe { &*crate::ffi::rptadv_iax2_client_descriptor_v2() };
    let mut output = 99;
    assert_eq!(
        unsafe { api.retire_egress.unwrap()((&mut peer as *mut IaxPeer).cast(), &mut output) },
        -1
    );
    assert_eq!(output, 0);
    assert_eq!(media.context_counts(), (4, 2));
    drop(peer);
    assert_eq!(media.context_counts(), (4, 4));
}
