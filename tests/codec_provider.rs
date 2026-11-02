//! Load the real neutral descriptor rather than a duplicate codec implementation.
use rptadviax2::codec::providers::{CodecCatalog, ProfileId, ProviderSelection};
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
