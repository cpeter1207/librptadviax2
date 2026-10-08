//! Media tests colocated with production code for accurate coverage.

use super::{
    VoiceFrame, VoiceFrameEncodeError, VoiceFrameError, encode_mini_voice_frame, parse_voice_frame,
};
use crate::codec::{CodecAdapter, G711Ulaw, IAX_FORMAT_ULAW};
use crate::protocol::{
    FullFrameHeader, HeaderParseError, MiniFrameHeader, MiniFrameParseError, SubclassDecodeError,
    serialize_full_frame, serialize_mini_frame,
};

fn full_voice(format: u8, frame_type: u8, payload: &[u8]) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 77,
            retransmission: false,
            destination_call_number: 2,
            timestamp: 320,
            outgoing_sequence: 3,
            incoming_sequence: 4,
            frame_type,
            subclass: format,
            subclass_is_log: false,
        },
        payload,
    )
    .unwrap()
}

#[test]
fn parses_full_voice_codec_format_and_borrows_payload() {
    let packet = full_voice(IAX_FORMAT_ULAW as u8, 2, &[0x00, 0xff]);

    assert_eq!(
        parse_voice_frame(&packet, IAX_FORMAT_ULAW),
        Ok(VoiceFrame::Full {
            header: FullFrameHeader {
                source_call_number: 77,
                retransmission: false,
                destination_call_number: 2,
                timestamp: 320,
                outgoing_sequence: 3,
                incoming_sequence: 4,
                frame_type: 2,
                subclass: IAX_FORMAT_ULAW as u8,
                subclass_is_log: false,
            },
            format: IAX_FORMAT_ULAW,
            payload: &[0x00, 0xff],
        })
    );
}

#[test]
fn parses_mini_voice_using_the_negotiated_format_then_decodes() {
    let packet = serialize_mini_frame(
        &MiniFrameHeader {
            source_call_number: 77,
            timestamp: 480,
        },
        &[0x00, 0x80, 0xff],
    )
    .unwrap();

    let frame = parse_voice_frame(&packet, IAX_FORMAT_ULAW).unwrap();
    let VoiceFrame::Mini {
        format, payload, ..
    } = frame
    else {
        panic!("mini frame should be classified as voice");
    };
    assert_eq!(format, IAX_FORMAT_ULAW);

    let mut pcm = [0.0; 3];
    assert_eq!(G711Ulaw.decode(payload, &mut pcm), Ok(3));
    assert_eq!(pcm, [-32124.0 / 32768.0, 32124.0 / 32768.0, 0.0]);
}

#[test]
fn rejects_non_voice_and_invalid_negotiated_formats() {
    assert_eq!(
        parse_voice_frame(&full_voice(4, 6, &[]), IAX_FORMAT_ULAW),
        Err(VoiceFrameError::NotVoiceFrame)
    );
    let mini = serialize_mini_frame(
        &MiniFrameHeader {
            source_call_number: 1,
            timestamp: 0,
        },
        &[],
    )
    .unwrap();
    for format in [0, 5] {
        assert_eq!(
            parse_voice_frame(&mini, format),
            Err(VoiceFrameError::InvalidFormat {
                value: i64::from(format),
            })
        );
    }
}

#[test]
fn reports_short_meta_and_malformed_voice_packets() {
    assert_eq!(
        parse_voice_frame(&[], IAX_FORMAT_ULAW),
        Err(VoiceFrameError::Truncated { actual_length: 0 })
    );
    assert_eq!(
        parse_voice_frame(&[0x80], IAX_FORMAT_ULAW),
        Err(VoiceFrameError::Truncated { actual_length: 1 })
    );
    assert_eq!(
        parse_voice_frame(&[0x80, 1], IAX_FORMAT_ULAW),
        Err(VoiceFrameError::FullFrame(HeaderParseError::Truncated {
            actual_length: 2,
        }))
    );
    assert_eq!(
        parse_voice_frame(&[0, 0, 0, 0], IAX_FORMAT_ULAW),
        Err(VoiceFrameError::NotVoiceFrame)
    );
    assert_eq!(
        parse_voice_frame(&[0, 1], IAX_FORMAT_ULAW),
        Err(VoiceFrameError::MiniFrame(MiniFrameParseError::Truncated {
            actual_length: 2,
        }))
    );
}

#[test]
fn rejects_unrepresentable_subclass_format_values() {
    assert_eq!(
        parse_voice_frame(&full_voice(5, 2, &[]), IAX_FORMAT_ULAW),
        Err(VoiceFrameError::InvalidFormat { value: 5 })
    );

    let negative_format = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 7,
            retransmission: false,
            destination_call_number: 2,
            timestamp: 0,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 2,
            subclass: 0x7f,
            subclass_is_log: true,
        },
        &[],
    )
    .unwrap();
    assert_eq!(
        parse_voice_frame(&negative_format, IAX_FORMAT_ULAW),
        Err(VoiceFrameError::InvalidFormat { value: -1 })
    );

    let invalid_exponent = serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 7,
            retransmission: false,
            destination_call_number: 2,
            timestamp: 0,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 2,
            subclass: 0x40,
            subclass_is_log: true,
        },
        &[],
    )
    .unwrap();
    assert_eq!(
        parse_voice_frame(&invalid_exponent, IAX_FORMAT_ULAW),
        Err(VoiceFrameError::Subclass(
            SubclassDecodeError::ExponentOutOfRange { exponent: 64 }
        ))
    );
}

#[test]
fn encodes_pcm_directly_to_a_caller_owned_mini_frame_buffer() {
    let mut packet = [0xa5; 7];
    let written = encode_mini_voice_frame(
        &G711Ulaw,
        MiniFrameHeader {
            source_call_number: 7,
            timestamp: 160,
        },
        &[-1.0, 0.0, 1.0],
        &mut packet,
    )
    .unwrap();

    assert_eq!(written, packet.len());
    assert_eq!(packet, [0x00, 0x07, 0x00, 0xa0, 0x00, 0xff, 0x80]);
}

#[test]
fn mini_frame_encoder_rejects_short_buffer_without_partial_writes() {
    let mut packet = [0xa5; 6];
    assert_eq!(
        encode_mini_voice_frame(
            &G711Ulaw,
            MiniFrameHeader {
                source_call_number: 7,
                timestamp: 0,
            },
            &[0.0, 0.0, 0.0],
            &mut packet,
        ),
        Err(VoiceFrameEncodeError::Codec(crate::codec::CodecError {
            required: 3,
            available: 2,
        }))
    );
    assert_eq!(packet, [0xa5; 6]);
}

#[test]
fn mini_frame_encoder_rejects_invalid_call_number_without_writing() {
    let mut packet = [0xa5; 4];
    for value in [0, 0x8000] {
        assert_eq!(
            encode_mini_voice_frame(
                &G711Ulaw,
                MiniFrameHeader {
                    source_call_number: value,
                    timestamp: 0,
                },
                &[],
                &mut packet,
            ),
            Err(VoiceFrameEncodeError::InvalidSourceCallNumber { value })
        );
        assert_eq!(packet, [0xa5; 4]);
    }
}

#[test]
fn mini_frame_encoder_rejects_short_header_without_writing() {
    let mut packet = [0xa5; 3];
    assert_eq!(
        encode_mini_voice_frame(
            &G711Ulaw,
            MiniFrameHeader {
                source_call_number: 1,
                timestamp: 0,
            },
            &[],
            &mut packet,
        ),
        Err(VoiceFrameEncodeError::BufferTooSmall {
            required: 4,
            available: 3,
        })
    );
    assert_eq!(packet, [0xa5; 3]);
}
