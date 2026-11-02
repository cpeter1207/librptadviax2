//! Byte fixtures follow Asterisk 20.21 iax2/parser.c and format_compatibility.h.
use rptadviax2::{
    codec::providers::ProfileId,
    formats::{FormatOffer, IaxFormat, append_formats},
    information_elements::parse_information_elements,
};

#[test]
fn formats_extended_precedence_and_versions() {
    // Legacy ulaw, then version-0 extended Opus.
    let wire = [8, 4, 0, 0, 0, 4, 55, 9, 0, 0, 0, 0, 4, 0, 0, 0, 0];
    let mut offer = FormatOffer::parse(&parse_information_elements(&wire).unwrap());
    assert_eq!(offer.capability, 1u64 << 34);
    let mut wire = wire.to_vec();
    wire.extend_from_slice(&[8, 4, 0, 0, 0, 8]);
    offer = FormatOffer::parse(&parse_information_elements(&wire).unwrap());
    assert_eq!(offer.capability, 1u64 << 34);
    // Unknown extended version and malformed known-size IEs are ignored.
    wire[8] = 1;
    assert_eq!(
        FormatOffer::parse(&parse_information_elements(&wire).unwrap()).capability,
        4
    );
    assert_eq!(
        FormatOffer::parse(&parse_information_elements(&[8, 1, 4]).unwrap()).capability,
        0
    );
    // An extended zero can be replaced by a later legacy IE, like Asterisk.
    let zero_then_legacy = [55, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 4, 0, 0, 0, 8];
    assert_eq!(
        FormatOffer::parse(&parse_information_elements(&zero_then_legacy).unwrap()).capability,
        8
    );
}

#[test]
fn formats_wire_pairs_include_high_bits_without_advertising_deferred_formats() {
    assert_eq!(IaxFormat::for_profile(ProfileId::Opus).0, 1u64 << 34);
    assert_eq!(IaxFormat::for_profile(ProfileId::Speex16).0, 1u64 << 33);
    assert_eq!(IaxFormat::for_profile(ProfileId::Pcm16).0, 1u64 << 15);
    let mask = (1..=16)
        .map(|id| IaxFormat::for_profile(ProfileId::from_raw(id).unwrap()).0)
        .fold(0, |all, value| all | value);
    assert_eq!(mask & ((1u64 << 13) | (1u64 << 14) | (1u64 << 32)), 0);
    let mut wire = Vec::new();
    append_formats(
        &mut wire,
        IaxFormat::for_profile(ProfileId::Opus).0,
        Some(mask),
    );
    let offer = FormatOffer::parse(&parse_information_elements(&wire).unwrap());
    assert_eq!((offer.format, offer.capability), (1u64 << 34, mask));
    let mut accept = Vec::new();
    append_formats(&mut accept, 1u64 << 34, None);
    let accepted = FormatOffer::parse(&parse_information_elements(&accept).unwrap());
    assert_eq!(accepted.supported(), 1u64 << 34);
    assert_eq!(IaxFormat(1u64 << 34).profile(), Some(ProfileId::Opus));
    assert_eq!(IaxFormat(3).profile(), None);
}
