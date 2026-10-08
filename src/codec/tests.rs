//! Codec tests colocated with production code for accurate coverage.

use super::{CodecAdapter, CodecError, G711Ulaw, IAX_FORMAT_ULAW, ULAW_SAMPLE_RATE_HZ};

#[test]
fn ulaw_uses_the_iax_capability_bit_and_narrowband_rate() {
    let codec = G711Ulaw;

    assert_eq!(codec.iax_format(), IAX_FORMAT_ULAW);
    assert_eq!(codec.iax_format(), 0x0000_0004);
    assert_eq!(codec.sample_rate_hz(), ULAW_SAMPLE_RATE_HZ);
    assert_eq!(codec.sample_rate_hz(), 8_000);
}

#[test]
fn decodes_g711_ulaw_to_normalized_float_pcm() {
    let codec = G711Ulaw;
    let mut pcm = [0.0; 4];

    assert_eq!(codec.decode(&[0x00, 0x80, 0xff, 0x7f], &mut pcm), Ok(4));
    assert_eq!(pcm, [-32124.0 / 32768.0, 32124.0 / 32768.0, 0.0, 0.0]);
}

#[test]
fn encodes_normalized_float_pcm_to_g711_ulaw() {
    let codec = G711Ulaw;
    let pcm = [-1.0, 0.0, 1.0];
    let mut encoded = [0; 3];

    assert_eq!(codec.encode(&pcm, &mut encoded), Ok(3));
    assert_eq!(encoded, [0x00, 0xff, 0x80]);
}

#[test]
fn encoder_clips_full_scale_and_encodes_nan_as_silence() {
    let codec = G711Ulaw;
    let mut encoded = [0; 4];

    assert_eq!(
        codec.encode(&[f32::NEG_INFINITY, -1.0, 1.0, f32::NAN], &mut encoded),
        Ok(4)
    );
    assert_eq!(encoded, [0x00, 0x00, 0x80, 0xff]);
}

#[test]
fn codec_conversion_rejects_short_output_without_partial_writes() {
    let codec = G711Ulaw;
    let mut decoded = [0.25; 1];
    assert_eq!(
        codec.decode(&[0xff, 0xff], &mut decoded),
        Err(CodecError {
            required: 2,
            available: 1,
        })
    );
    assert_eq!(decoded, [0.25]);

    let mut encoded = [0xa5; 1];
    assert_eq!(
        codec.encode(&[0.0, 0.0], &mut encoded),
        Err(CodecError {
            required: 2,
            available: 1,
        })
    );
    assert_eq!(encoded, [0xa5]);
}
