//! Text-frame tests colocated with production code for accurate coverage.

use super::{TextFrameEncodeError, TextFrameParseError, parse_text_frame, serialize_text_frame};
use crate::protocol::{FullFrameHeader, HeaderParseError};

fn key_query_fixture() -> Vec<u8> {
    include_str!("../../tests/fixtures/iax2/key-query.hex")
        .split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

#[test]
fn parses_app_rpt_key_query_fixture() {
    let bytes = key_query_fixture();
    let parsed = parse_text_frame(&bytes).unwrap();

    assert_eq!(parsed.text, "K? * 524950 0 0");
    assert_eq!(parsed.header.frame_type, 7);
    assert_eq!(parsed.header.subclass, 0);
}

#[test]
fn serializes_app_rpt_key_query_fixture_exactly() {
    let bytes = key_query_fixture();
    let parsed = parse_text_frame(&bytes).unwrap();

    assert_eq!(
        serialize_text_frame(&parsed.header, parsed.text).unwrap(),
        bytes
    );
}

#[test]
fn rejects_non_text_frames_and_nonzero_subclasses() {
    let mut bytes = key_query_fixture();
    bytes[10] = 2;
    assert_eq!(
        parse_text_frame(&bytes),
        Err(TextFrameParseError::NotTextFrame { frame_type: 2 })
    );

    let mut bytes = key_query_fixture();
    bytes[11] = 1;
    assert_eq!(
        parse_text_frame(&bytes),
        Err(TextFrameParseError::InvalidSubclass { encoded: 1 })
    );
}

#[test]
fn rejects_invalid_utf8_and_truncated_packets() {
    let mut bytes = key_query_fixture();
    bytes[12] = 0xff;
    assert!(matches!(
        parse_text_frame(&bytes),
        Err(TextFrameParseError::InvalidUtf8 { .. })
    ));
    assert_eq!(
        parse_text_frame(&[0x80, 0x01]),
        Err(TextFrameParseError::Header(HeaderParseError::Truncated {
            actual_length: 2
        }))
    );
}

#[test]
fn serializer_rejects_invalid_text_header() {
    let header = FullFrameHeader {
        source_call_number: 1,
        retransmission: false,
        destination_call_number: 2,
        timestamp: 3,
        outgoing_sequence: 4,
        incoming_sequence: 5,
        frame_type: 2,
        subclass: 0,
        subclass_is_log: false,
    };
    assert_eq!(
        serialize_text_frame(&header, "K? * 524950 0 0"),
        Err(TextFrameEncodeError::NotTextFrame { frame_type: 2 })
    );

    let header = FullFrameHeader {
        frame_type: 7,
        subclass: 1,
        ..header
    };
    assert_eq!(
        serialize_text_frame(&header, "K? * 524950 0 0"),
        Err(TextFrameEncodeError::InvalidSubclass { encoded: 1 })
    );
}

#[test]
fn serializer_reports_invalid_full_frame_header() {
    let header = FullFrameHeader {
        source_call_number: 0x8000,
        retransmission: false,
        destination_call_number: 2,
        timestamp: 3,
        outgoing_sequence: 4,
        incoming_sequence: 5,
        frame_type: 7,
        subclass: 0,
        subclass_is_log: false,
    };

    assert_eq!(
        serialize_text_frame(&header, "status"),
        Err(TextFrameEncodeError::Frame(
            crate::protocol::FrameEncodeError::CallNumberOutOfRange {
                field: "source",
                value: 0x8000,
            }
        ))
    );
}
