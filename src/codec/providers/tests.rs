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
    fn new(name: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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
    fn calls(&self) -> u32 {
        let calls = unsafe {
            self.library
                .get::<unsafe extern "C" fn() -> u32>(b"rptadv_test_calls\0")
        }
        .unwrap();
        unsafe { calls() }
    }
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
