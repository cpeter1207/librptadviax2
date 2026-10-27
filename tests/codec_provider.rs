//! Load the real neutral descriptor rather than a duplicate codec implementation.
use rptadviax2::codec::providers::{CodecCatalog, ProfileId, ProviderSelection, Status};
use rptadviax2::formats::{FormatCatalog, IaxFormat, NegotiationError};
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn contract_peer_stream_prefers_native_plc_without_double_concealment() {
    use rptadviax2::codec::stream::Stream;
    let directory = PathBuf::from(std::env::var_os("RPTADV_CODEC_DIR").unwrap_or_default());
    let catalog = CodecCatalog::load(&[
        ProviderSelection {
            path: directory.join("librptadv_codec_g711.so.1"),
            profiles: vec![ProfileId::G711Mu],
        },
        ProviderSelection {
            path: directory.join("librptadv_codec_opus.so.1"),
            profiles: vec![ProfileId::Opus],
        },
    ])
    .unwrap();
    let mut opus = Stream::open(&catalog, ProfileId::Opus).unwrap();
    let mut ulaw = Stream::open(&catalog, ProfileId::G711Mu).unwrap();
    assert_eq!((opus.rate, opus.packet_frames), (48000, 960));
    assert_eq!((ulaw.rate, ulaw.packet_frames), (8000, 160));
    let mut pcm = [0.75; 960];
    assert_eq!(opus.decoder.conceal(960, &mut pcm).unwrap(), 960);
    assert_ne!(pcm, [0.75; 960]);
    pcm.fill(0.75);
    assert_eq!(ulaw.decoder.conceal(160, &mut pcm).unwrap(), 0);
    assert_eq!(pcm, [0.75; 960]);
}

#[test]
fn formats_both_call_directions_use_the_verified_catalog() {
    use rptadviax2::{
        formats::{FormatOffer, append_formats},
        information_elements::parse_information_elements,
        protocol::{FullFrameHeader, IaxCommand, parse_full_frame_packet, serialize_full_frame},
        session::accept_inbound_new,
    };
    let directory = PathBuf::from(std::env::var_os("RPTADV_CODEC_DIR").unwrap_or_default());
    let codecs = Arc::new(
        CodecCatalog::load(&[
            ProviderSelection {
                path: directory.join("librptadv_codec_g711.so.1"),
                profiles: vec![ProfileId::G711Mu],
            },
            ProviderSelection {
                path: directory.join("librptadv_codec_opus.so.1"),
                profiles: vec![ProfileId::Opus],
            },
        ])
        .unwrap(),
    );
    let catalog = FormatCatalog::new(codecs, &[ProfileId::Opus, ProfileId::G711Mu]).unwrap();
    for (mask, expected) in [(catalog.advertised_mask(), 4), (1u64 << 34, 1u64 << 34)] {
        let mut payload = b"\x06\x05radio\x01\x06524950\x02\x06506316".to_vec();
        append_formats(&mut payload, expected, Some(mask));
        let request = serialize_full_frame(
            &FullFrameHeader {
                source_call_number: 123,
                retransmission: false,
                destination_call_number: 0,
                timestamp: 0,
                outgoing_sequence: 0,
                incoming_sequence: 0,
                frame_type: 6,
                subclass: IaxCommand::New.subclass_value() as u8,
                subclass_is_log: false,
            },
            &payload,
        )
        .unwrap();
        let accepted = accept_inbound_new(&request, "524950", 124, &catalog).unwrap();
        assert_eq!(accepted.format, expected);
        assert_eq!(
            IaxFormat::for_profile(catalog.select(mask).unwrap()).0,
            expected
        );
        let response = parse_full_frame_packet(&accepted.packet).unwrap();
        assert_eq!(
            FormatOffer::parse(&parse_information_elements(response.payload).unwrap()).format,
            expected
        );
    }
}

#[test]
fn contract_missing_provider_is_not_a_silent_ulaw_fallback() {
    assert!(
        CodecCatalog::load(&[ProviderSelection {
            path: PathBuf::from("/missing/rptadv-codec-provider.so"),
            profiles: vec![ProfileId::G711Mu],
        }])
        .is_err()
    );
}

#[test]
fn contract_g711_counts_state_and_library_lifetime() {
    let directory = std::env::var_os("RPTADV_CODEC_DIR").unwrap_or_default();
    let catalog = CodecCatalog::load(&[ProviderSelection {
        path: PathBuf::from(directory).join("librptadv_codec_g711.so.1"),
        profiles: vec![ProfileId::G711Mu, ProfileId::G711A],
    }])
    .unwrap();
    assert_eq!(catalog.profiles().count(), 2);
    assert_eq!(
        catalog.profile(ProfileId::G711Mu).unwrap().sample_rate_hz,
        8000
    );
    let mut encoder = catalog.encoder(ProfileId::G711Mu, 0, 160, 65503).unwrap();
    let mut decoder = catalog.decoder(ProfileId::G711Mu, 0, 160, 65503).unwrap();
    // Contexts retain the DSO even after composition/catalog destruction.
    drop(catalog);
    let mut encoded = [0xa5; 160];
    let first = encoder.encode(&[0.0; 37], &mut encoded, false).unwrap();
    assert_eq!(
        (first.status, first.consumed_frames, first.encoded_bytes),
        (Status::NeedInput, 37, 0)
    );
    assert_eq!(
        encoder
            .encode(&[0.0; 123], &mut encoded[..159], false)
            .unwrap_err()
            .required_capacity,
        160
    );
    let packet = encoder.encode(&[0.0; 123], &mut encoded, false).unwrap();
    assert_eq!(
        (
            packet.encoded_bytes,
            packet.source_start_frames,
            packet.source_frames,
            packet.packet_frames
        ),
        (160, 0, 160, 160)
    );
    assert_eq!(encoded, [0xff; 160]);
    assert_eq!(decoder.inspect(&encoded).unwrap().frames, 160);
    let mut pcm = [0.0; 160];
    assert_eq!(
        decoder
            .decode(&encoded, &mut pcm[..159])
            .unwrap_err()
            .required_capacity,
        160
    );
    assert_eq!(decoder.decode(&encoded, &mut pcm).unwrap(), 160);
    assert_eq!(pcm, [0.0; 160]);
    encoder.reset().unwrap();
    decoder.reset().unwrap();
    assert_eq!(
        encoder
            .encode(&[], &mut encoded, true)
            .unwrap()
            .encoded_bytes,
        0
    );
}

#[test]
fn contract_all_selected_profiles_open_independent_directions() {
    let directory = PathBuf::from(std::env::var_os("RPTADV_CODEC_DIR").unwrap_or_default());
    let selections = [
        ("g711", vec![ProfileId::G711Mu, ProfileId::G711A]),
        ("pcm", vec![ProfileId::Pcm8, ProfileId::Pcm16]),
        ("gsm", vec![ProfileId::GsmFr]),
        ("speex", vec![ProfileId::Speex, ProfileId::Speex16]),
        ("opus", vec![ProfileId::Opus]),
        (
            "spandsp",
            vec![
                ProfileId::G726Aal2,
                ProfileId::G726,
                ProfileId::G722,
                ProfileId::Lpc10,
            ],
        ),
        ("ffmpeg", vec![ProfileId::G723]),
        ("bcg729", vec![ProfileId::G729]),
        ("ilbc", vec![ProfileId::Ilbc]),
        ("dialogic", vec![ProfileId::Dialogic]),
    ]
    .into_iter()
    .map(|(backend, profiles)| ProviderSelection {
        path: directory.join(format!("librptadv_codec_{backend}.so.1")),
        profiles,
    })
    .collect::<Vec<_>>();
    let catalog = CodecCatalog::load(&selections).unwrap();
    assert_eq!(catalog.profiles().count(), 16);
    for profile in catalog.profiles() {
        let mode = &profile.modes[0];
        let packet =
            (profile.sample_rate_hz / 50).div_ceil(mode.frame_samples) * mode.frame_samples;
        let _encoder = catalog.encoder(profile.id, mode.id, packet, 65503).unwrap();
        let _decoder = catalog.decoder(profile.id, mode.id, packet, 65503).unwrap();
    }
    assert_eq!(catalog.profile(ProfileId::Ilbc).unwrap().modes[0].id, 30);
}

#[test]
fn formats_catalog_offers_only_verified_profiles_and_prefers_ulaw() {
    let directory = PathBuf::from(std::env::var_os("RPTADV_CODEC_DIR").unwrap_or_default());
    let codecs = Arc::new(
        CodecCatalog::load(&[
            ProviderSelection {
                path: directory.join("librptadv_codec_g711.so.1"),
                profiles: vec![ProfileId::G711Mu],
            },
            ProviderSelection {
                path: directory.join("librptadv_codec_opus.so.1"),
                profiles: vec![ProfileId::Opus],
            },
        ])
        .unwrap(),
    );
    let catalog =
        FormatCatalog::new(Arc::clone(&codecs), &[ProfileId::Opus, ProfileId::G711Mu]).unwrap();
    let opus = IaxFormat::for_profile(ProfileId::Opus).0;
    assert_eq!(catalog.advertised_mask(), 4 | opus);
    assert_eq!(catalog.select(4 | opus), Ok(ProfileId::G711Mu));
    assert_eq!(catalog.select(opus), Ok(ProfileId::Opus));
    assert_eq!(
        catalog.select(1u64 << 13),
        Err(NegotiationError::NoCommonFormat)
    );
    assert!(matches!(
        FormatCatalog::new(Arc::clone(&codecs), &[]),
        Err(NegotiationError::Empty)
    ));
    assert!(matches!(
        FormatCatalog::new(Arc::clone(&codecs), &[ProfileId::G711A]),
        Err(NegotiationError::Missing(ProfileId::G711A))
    ));
    assert!(matches!(
        FormatCatalog::new(codecs, &[ProfileId::Opus, ProfileId::Opus]),
        Err(NegotiationError::Duplicate(ProfileId::Opus))
    ));
}
