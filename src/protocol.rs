//! Byte-level IAX2 protocol primitives. This module owns no sockets or codecs.

/// Fields present in an IAX2 full-frame header.
#[derive(Debug, Eq, PartialEq)]
pub struct FullFrameHeader {
    /// Source call number with its full-frame flag removed.
    pub source_call_number: u16,
    /// Whether this full frame is marked as a retransmission.
    pub retransmission: bool,
    /// Destination call number with its retransmission flag removed.
    pub destination_call_number: u16,
    /// Timestamp in network byte order converted to host order.
    pub timestamp: u32,
    /// Outgoing sequence number.
    pub outgoing_sequence: u8,
    /// Incoming sequence number.
    pub incoming_sequence: u8,
    /// IAX2 frame type.
    pub frame_type: u8,
    /// Seven-bit subclass field, an exponent when `subclass_is_log` is set.
    pub subclass: u8,
    /// Whether the subclass field is encoded as a power-of-two exponent.
    pub subclass_is_log: bool,
}

/// A parsed full frame whose payload borrows from the received packet.
#[derive(Debug, Eq, PartialEq)]
pub struct FullFramePacket<'a> {
    /// The decoded fixed header.
    pub header: FullFrameHeader,
    /// Payload bytes following the 12-byte full-frame header.
    pub payload: &'a [u8],
}

/// Fields in an IAX2 mini-frame header.
#[derive(Debug, Eq, PartialEq)]
pub struct MiniFrameHeader {
    /// Nonzero 15-bit source call number.
    pub source_call_number: u16,
    /// Low 16 bits of the per-call millisecond timestamp.
    pub timestamp: u16,
}

/// A parsed mini frame borrowing its media payload.
#[derive(Debug, Eq, PartialEq)]
pub struct MiniFramePacket<'a> {
    /// Decoded fixed header.
    pub header: MiniFrameHeader,
    /// Payload after the four-octet mini-frame header.
    pub payload: &'a [u8],
}

/// Why an IAX2 mini frame could not be parsed.
#[derive(Debug, Eq, PartialEq)]
pub enum MiniFrameParseError {
    /// The packet is shorter than the fixed four-byte header.
    Truncated {
        /// Number of bytes received.
        actual_length: usize,
    },
    /// The packet has a full-frame flag or reserved zero call number.
    NotMiniFrame,
}

/// Why an IAX2 mini frame could not be serialized.
#[derive(Debug, Eq, PartialEq)]
pub enum MiniFrameEncodeError {
    /// Mini-frame source call numbers must be nonzero and fit in 15 bits.
    InvalidSourceCallNumber {
        /// Supplied source call number.
        value: u16,
    },
}

/// Why an IAX2 full-frame header could not be parsed.
#[derive(Debug, Eq, PartialEq)]
pub enum HeaderParseError {
    /// The packet is shorter than the fixed 12-byte header.
    Truncated {
        /// Number of bytes received.
        actual_length: usize,
    },
    /// The first call-number field does not mark a full frame.
    NotFullFrame,
}

/// Why an IAX2 full frame could not be serialized.
#[derive(Debug, Eq, PartialEq)]
pub enum FrameEncodeError {
    /// A call number exceeds the 15 bits available on the wire.
    CallNumberOutOfRange {
        /// Header field that contains the invalid number.
        field: &'static str,
        /// Supplied call number.
        value: u16,
    },
    /// A subclass exceeds the 7 bits available beside the `C` flag.
    SubclassOutOfRange {
        /// Supplied subclass value.
        value: u8,
    },
}

/// Why an encoded full-frame subclass could not be expanded.
#[derive(Debug, Eq, PartialEq)]
pub enum SubclassDecodeError {
    /// The exponent exceeds Asterisk's 63-bit subclass shift range.
    ExponentOutOfRange {
        /// Encoded seven-bit exponent.
        exponent: u8,
    },
}

/// Why a subclass value could not be represented by the IAX2 wire encoding.
#[derive(Debug, Eq, PartialEq)]
pub enum SubclassEncodeError {
    /// The value is not representable by Asterisk's canonical encoding.
    ValueOutOfRange {
        /// Subclass value that cannot be encoded.
        value: i64,
    },
}

/// Expand a full-frame subclass according to its C bit.
pub fn decode_subclass(encoded: u8) -> Result<i64, SubclassDecodeError> {
    let subclass = encoded & 0x7f;
    if encoded & 0x80 == 0 {
        return Ok(i64::from(subclass));
    }
    if encoded == 0xff {
        return Ok(-1);
    }
    if subclass > 63 {
        return Err(SubclassDecodeError::ExponentOutOfRange { exponent: subclass });
    }
    Ok(1_i64 << subclass)
}

/// Encode a subclass using Asterisk's canonical full-frame representation.
pub fn encode_subclass(value: i64) -> Result<u8, SubclassEncodeError> {
    if value == -1 {
        return Ok(0xff);
    }
    if (0..=0x7f).contains(&value) {
        return Ok(value as u8);
    }
    let bits = value as u64;
    if bits.is_power_of_two() && bits.trailing_zeros() < 63 {
        return Ok(0x80 | bits.trailing_zeros() as u8);
    }
    Err(SubclassEncodeError::ValueOutOfRange { value })
}

/// IAX control commands used by current ASL3 call and link sessions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IaxCommand {
    /// Initiate a call.
    New,
    /// Probe a live call.
    Ping,
    /// Reply to a ping.
    Pong,
    /// Acknowledge a full frame.
    Ack,
    /// End a call.
    Hangup,
    /// Reject a call or request.
    Reject,
    /// Accept a call and select media formats.
    Accept,
    /// Request peer authentication.
    AuthReq,
    /// Reply to an authentication request.
    AuthRep,
    /// Report an invalid call or frame.
    Inval,
    /// Request lag measurement.
    LagRq,
    /// Reply to lag measurement.
    LagRp,
    /// Request voice retransmission after a sequence gap.
    Vnak,
    /// Probe a peer without establishing a call.
    Poke,
    /// Report an unsupported command.
    Unsupport,
    /// Provide a call token for a retried initial request.
    CallToken,
    /// Preserve an IAX command not handled by this implementation.
    Unknown(i64),
}

impl IaxCommand {
    /// Return the Asterisk IAX command subclass value.
    pub const fn subclass_value(self) -> i64 {
        match self {
            Self::New => 1,
            Self::Ping => 2,
            Self::Pong => 3,
            Self::Ack => 4,
            Self::Hangup => 5,
            Self::Reject => 6,
            Self::Accept => 7,
            Self::AuthReq => 8,
            Self::AuthRep => 9,
            Self::Inval => 10,
            Self::LagRq => 11,
            Self::LagRp => 12,
            Self::Vnak => 18,
            Self::Poke => 30,
            Self::Unsupport => 33,
            Self::CallToken => 40,
            Self::Unknown(value) => value,
        }
    }
}

/// Decode a full-frame IAX command, leaving other frame types unclassified.
pub fn decode_iax_command(
    header: &FullFrameHeader,
) -> Result<Option<IaxCommand>, SubclassDecodeError> {
    if header.frame_type != 6 {
        return Ok(None);
    }
    let encoded = (u8::from(header.subclass_is_log) << 7) | header.subclass;
    let command = match decode_subclass(encoded)? {
        1 => IaxCommand::New,
        2 => IaxCommand::Ping,
        3 => IaxCommand::Pong,
        4 => IaxCommand::Ack,
        5 => IaxCommand::Hangup,
        6 => IaxCommand::Reject,
        7 => IaxCommand::Accept,
        8 => IaxCommand::AuthReq,
        9 => IaxCommand::AuthRep,
        10 => IaxCommand::Inval,
        11 => IaxCommand::LagRq,
        12 => IaxCommand::LagRp,
        18 => IaxCommand::Vnak,
        30 => IaxCommand::Poke,
        33 => IaxCommand::Unsupport,
        40 => IaxCommand::CallToken,
        value => IaxCommand::Unknown(value),
    };
    Ok(Some(command))
}

/// Parse the fixed IAX2 full-frame header, without interpreting its payload.
pub fn parse_full_frame_header(packet: &[u8]) -> Result<FullFrameHeader, HeaderParseError> {
    if packet.len() < 12 {
        return Err(HeaderParseError::Truncated {
            actual_length: packet.len(),
        });
    }

    let source = u16::from_be_bytes([packet[0], packet[1]]);
    if source & 0x8000 == 0 {
        return Err(HeaderParseError::NotFullFrame);
    }

    let destination = u16::from_be_bytes([packet[2], packet[3]]);
    let subclass = packet[11];

    Ok(FullFrameHeader {
        source_call_number: source & 0x7fff,
        retransmission: destination & 0x8000 != 0,
        destination_call_number: destination & 0x7fff,
        timestamp: u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
        outgoing_sequence: packet[8],
        incoming_sequence: packet[9],
        frame_type: packet[10],
        subclass: subclass & 0x7f,
        subclass_is_log: subclass & 0x80 != 0,
    })
}

/// Parse a full frame and borrow its uninterpreted payload.
pub fn parse_full_frame_packet(packet: &[u8]) -> Result<FullFramePacket<'_>, HeaderParseError> {
    let header = parse_full_frame_header(packet)?;
    let payload = &packet[12..];
    Ok(FullFramePacket { header, payload })
}

/// Serialize one full frame into network byte order.
pub fn serialize_full_frame(
    header: &FullFrameHeader,
    payload: &[u8],
) -> Result<Vec<u8>, FrameEncodeError> {
    if header.source_call_number > 0x7fff {
        return Err(FrameEncodeError::CallNumberOutOfRange {
            field: "source",
            value: header.source_call_number,
        });
    }
    if header.destination_call_number > 0x7fff {
        return Err(FrameEncodeError::CallNumberOutOfRange {
            field: "destination",
            value: header.destination_call_number,
        });
    }
    if header.subclass > 0x7f {
        return Err(FrameEncodeError::SubclassOutOfRange {
            value: header.subclass,
        });
    }

    let source = 0x8000 | header.source_call_number;
    let destination = (u16::from(header.retransmission) << 15) | header.destination_call_number;
    let subclass = (u8::from(header.subclass_is_log) << 7) | header.subclass;
    let mut packet = Vec::with_capacity(12 + payload.len());
    packet.extend_from_slice(&source.to_be_bytes());
    packet.extend_from_slice(&destination.to_be_bytes());
    packet.extend_from_slice(&header.timestamp.to_be_bytes());
    packet.extend_from_slice(&[
        header.outgoing_sequence,
        header.incoming_sequence,
        header.frame_type,
        subclass,
    ]);
    packet.extend_from_slice(payload);
    Ok(packet)
}

/// Parse one IAX2 mini frame and borrow its media payload.
pub fn parse_mini_frame(packet: &[u8]) -> Result<MiniFramePacket<'_>, MiniFrameParseError> {
    if packet.len() < 4 {
        return Err(MiniFrameParseError::Truncated {
            actual_length: packet.len(),
        });
    }

    let source = u16::from_be_bytes([packet[0], packet[1]]);
    if source & 0x8000 != 0 || source == 0 {
        return Err(MiniFrameParseError::NotMiniFrame);
    }

    Ok(MiniFramePacket {
        header: MiniFrameHeader {
            source_call_number: source,
            timestamp: u16::from_be_bytes([packet[2], packet[3]]),
        },
        payload: &packet[4..],
    })
}

/// Serialize one IAX2 mini frame into network byte order.
pub fn serialize_mini_frame(
    header: &MiniFrameHeader,
    payload: &[u8],
) -> Result<Vec<u8>, MiniFrameEncodeError> {
    if header.source_call_number == 0 || header.source_call_number > 0x7fff {
        return Err(MiniFrameEncodeError::InvalidSourceCallNumber {
            value: header.source_call_number,
        });
    }

    let mut packet = Vec::with_capacity(4 + payload.len());
    packet.extend_from_slice(&header.source_call_number.to_be_bytes());
    packet.extend_from_slice(&header.timestamp.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::{
        FrameEncodeError, FullFrameHeader, FullFramePacket, HeaderParseError, IaxCommand,
        MiniFrameEncodeError, MiniFrameHeader, MiniFramePacket, MiniFrameParseError,
        SubclassDecodeError, SubclassEncodeError, decode_iax_command, decode_subclass,
        encode_subclass, parse_full_frame_header, parse_full_frame_packet, parse_mini_frame,
        serialize_full_frame, serialize_mini_frame,
    };

    #[test]
    fn parses_all_full_frame_header_fields() {
        let packet = [
            0x80, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x04, 0x05, 0x06, 0x87,
        ];

        assert_eq!(
            parse_full_frame_header(&packet),
            Ok(FullFrameHeader {
                source_call_number: 1,
                retransmission: false,
                destination_call_number: 2,
                timestamp: 3,
                outgoing_sequence: 4,
                incoming_sequence: 5,
                frame_type: 6,
                subclass: 7,
                subclass_is_log: true,
            })
        );
    }

    #[test]
    fn rejects_packets_shorter_than_fixed_header() {
        for actual_length in 0..12 {
            assert_eq!(
                parse_full_frame_header(&[0; 11][..actual_length]),
                Err(HeaderParseError::Truncated { actual_length })
            );
        }
    }

    #[test]
    fn rejects_mini_frames() {
        let mut packet = [0_u8; 12];
        packet[1] = 1;

        assert_eq!(
            parse_full_frame_header(&packet),
            Err(HeaderParseError::NotFullFrame)
        );
    }

    #[test]
    fn parses_mini_frame_timestamp_and_borrowed_payload() {
        let packet = [0x12, 0x34, 0xab, 0xcd, 0xde, 0xad];

        assert_eq!(
            parse_mini_frame(&packet),
            Ok(MiniFramePacket {
                header: MiniFrameHeader {
                    source_call_number: 0x1234,
                    timestamp: 0xabcd,
                },
                payload: &[0xde, 0xad],
            })
        );
    }

    #[test]
    fn rejects_short_and_non_mini_frames() {
        for actual_length in 0..4 {
            assert_eq!(
                parse_mini_frame(&[0; 3][..actual_length]),
                Err(MiniFrameParseError::Truncated { actual_length })
            );
        }
        assert_eq!(
            parse_mini_frame(&[0x80, 1, 0, 0]),
            Err(MiniFrameParseError::NotMiniFrame)
        );
        assert_eq!(
            parse_mini_frame(&[0, 0, 0, 0]),
            Err(MiniFrameParseError::NotMiniFrame)
        );
    }

    #[test]
    fn serializes_mini_frame_exactly_and_round_trips() {
        let header = MiniFrameHeader {
            source_call_number: 0x1234,
            timestamp: 0xabcd,
        };
        let packet = serialize_mini_frame(&header, &[0xde, 0xad]).unwrap();

        assert_eq!(packet, [0x12, 0x34, 0xab, 0xcd, 0xde, 0xad]);
        assert_eq!(
            parse_mini_frame(&packet),
            Ok(MiniFramePacket {
                header,
                payload: &[0xde, 0xad],
            })
        );
    }

    #[test]
    fn validates_mini_frame_call_number_boundaries() {
        for value in [0, 0x8000] {
            assert_eq!(
                serialize_mini_frame(
                    &MiniFrameHeader {
                        source_call_number: value,
                        timestamp: 0,
                    },
                    &[]
                ),
                Err(MiniFrameEncodeError::InvalidSourceCallNumber { value })
            );
        }

        let maximum = MiniFrameHeader {
            source_call_number: 0x7fff,
            timestamp: u16::MAX,
        };
        let packet = serialize_mini_frame(&maximum, &[]).unwrap();
        assert_eq!(packet, [0x7f, 0xff, 0xff, 0xff]);
        assert_eq!(
            parse_mini_frame(&packet),
            Ok(MiniFramePacket {
                header: maximum,
                payload: &[],
            })
        );
    }

    #[test]
    fn parses_packet_payload_without_copying_or_decoding_it() {
        let packet = [
            0x80, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0xde, 0xad,
        ];

        assert_eq!(
            parse_full_frame_packet(&packet),
            Ok(FullFramePacket {
                header: FullFrameHeader {
                    source_call_number: 1,
                    retransmission: false,
                    destination_call_number: 2,
                    timestamp: 3,
                    outgoing_sequence: 4,
                    incoming_sequence: 5,
                    frame_type: 6,
                    subclass: 7,
                    subclass_is_log: false,
                },
                payload: &[0xde, 0xad],
            })
        );
    }

    #[test]
    fn propagates_header_errors_when_parsing_full_packet() {
        assert_eq!(
            parse_full_frame_packet(&[0x80, 0x01]),
            Err(HeaderParseError::Truncated { actual_length: 2 })
        );
    }

    #[test]
    fn masks_call_numbers_and_subclass_encoding_bit_without_losing_values() {
        let packet = [
            0xff, 0xff, 0xff, 0xff, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0x7f,
        ];

        let parsed = parse_full_frame_header(&packet).unwrap();

        assert_eq!(parsed.source_call_number, 0x7fff);
        assert_eq!(parsed.destination_call_number, 0x7fff);
        assert_eq!(parsed.timestamp, 0x1234_5678);
        assert!(parsed.retransmission);
        assert!(!parsed.subclass_is_log);
        assert_eq!(parsed.subclass, 0x7f);
    }

    #[test]
    fn serializes_full_frame_against_wire_fixture() {
        let header = FullFrameHeader {
            source_call_number: 0x0123,
            retransmission: true,
            destination_call_number: 0x0456,
            timestamp: 0x0123_4567,
            outgoing_sequence: 0x89,
            incoming_sequence: 0xab,
            frame_type: 0xcd,
            subclass: 0x20,
            subclass_is_log: false,
        };

        let encoded = serialize_full_frame(&header, &[0xde, 0xad]).unwrap();
        assert_eq!(
            encoded,
            [
                0x81, 0x23, 0x84, 0x56, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0x20, 0xde, 0xad,
            ]
        );
        let decoded = parse_full_frame_packet(&encoded).unwrap();
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.payload, [0xde, 0xad]);
    }

    #[test]
    fn encodes_retransmission_and_subclass_encoding_bit_independently() {
        let mut header = FullFrameHeader {
            source_call_number: 1,
            retransmission: false,
            destination_call_number: 2,
            timestamp: 0,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 0,
            subclass: 0x20,
            subclass_is_log: false,
        };

        for (retransmission, subclass_is_log, expected_subclass) in [
            (false, false, 0x20),
            (false, true, 0xa0),
            (true, false, 0x20),
            (true, true, 0xa0),
        ] {
            header.retransmission = retransmission;
            header.subclass_is_log = subclass_is_log;
            let packet = serialize_full_frame(&header, &[]).unwrap();

            assert_eq!(packet[2] & 0x80 != 0, retransmission);
            assert_eq!(packet[11], expected_subclass);
        }
    }

    #[test]
    fn rejects_out_of_range_call_numbers_before_serializing() {
        let header = FullFrameHeader {
            source_call_number: 0x8000,
            retransmission: false,
            destination_call_number: 2,
            timestamp: 0,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 0,
            subclass: 0,
            subclass_is_log: false,
        };

        assert_eq!(
            serialize_full_frame(&header, &[]),
            Err(FrameEncodeError::CallNumberOutOfRange {
                field: "source",
                value: 0x8000,
            })
        );

        let header = FullFrameHeader {
            source_call_number: 1,
            destination_call_number: 0x8000,
            ..header
        };
        assert_eq!(
            serialize_full_frame(&header, &[]),
            Err(FrameEncodeError::CallNumberOutOfRange {
                field: "destination",
                value: 0x8000,
            })
        );
    }

    #[test]
    fn rejects_subclass_values_that_overlap_the_encoding_flag() {
        let header = FullFrameHeader {
            source_call_number: 1,
            retransmission: false,
            destination_call_number: 2,
            timestamp: 0,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 0,
            subclass: 0x80,
            subclass_is_log: false,
        };

        assert_eq!(
            serialize_full_frame(&header, &[]),
            Err(FrameEncodeError::SubclassOutOfRange { value: 0x80 })
        );
    }

    #[test]
    fn decodes_iax_log_subclasses_as_powers_of_two() {
        for (wire, value) in [(0x87, 128), (0x88, 256), (0xbf, i64::MIN), (0xff, -1)] {
            assert_eq!(decode_subclass(wire), Ok(value));
        }
    }

    #[test]
    fn decodes_plain_subclasses_without_power_expansion() {
        for value in [0, 1, 2, 3, 40, 64, 127] {
            assert_eq!(decode_subclass(value), Ok(i64::from(value)));
        }
    }

    #[test]
    fn encodes_asterisk_canonical_subclasses() {
        for (value, wire) in [(128, 0x87), (256, 0x88), (1_i64 << 62, 0xbe), (-1, 0xff)] {
            assert_eq!(encode_subclass(value), Ok(wire));
        }
        for value in [0_i64, 1, 2, 3, 40, 64, 127] {
            assert_eq!(encode_subclass(value), Ok(value as u8));
        }
    }

    #[test]
    fn rejects_subclass_values_not_representable_on_wire() {
        assert_eq!(
            decode_subclass(0xc0),
            Err(SubclassDecodeError::ExponentOutOfRange { exponent: 64 })
        );
        assert_eq!(
            encode_subclass(129),
            Err(SubclassEncodeError::ValueOutOfRange { value: 129 })
        );
        assert_eq!(
            encode_subclass(i64::MIN),
            Err(SubclassEncodeError::ValueOutOfRange { value: i64::MIN })
        );
    }

    #[test]
    fn decodes_supported_asterisk_iax_link_commands() {
        for (value, command) in [
            (1, IaxCommand::New),
            (2, IaxCommand::Ping),
            (3, IaxCommand::Pong),
            (4, IaxCommand::Ack),
            (5, IaxCommand::Hangup),
            (6, IaxCommand::Reject),
            (7, IaxCommand::Accept),
            (8, IaxCommand::AuthReq),
            (9, IaxCommand::AuthRep),
            (10, IaxCommand::Inval),
            (11, IaxCommand::LagRq),
            (12, IaxCommand::LagRp),
            (18, IaxCommand::Vnak),
            (30, IaxCommand::Poke),
            (33, IaxCommand::Unsupport),
            (40, IaxCommand::CallToken),
        ] {
            let header = FullFrameHeader {
                source_call_number: 1,
                retransmission: false,
                destination_call_number: 2,
                timestamp: 0,
                outgoing_sequence: 0,
                incoming_sequence: 0,
                frame_type: 6,
                subclass: value,
                subclass_is_log: false,
            };
            assert_eq!(decode_iax_command(&header), Ok(Some(command)));
            assert_eq!(command.subclass_value(), i64::from(value));
        }
    }

    #[test]
    fn leaves_other_frame_types_and_unknown_commands_unclassified() {
        let mut header = FullFrameHeader {
            source_call_number: 1,
            retransmission: false,
            destination_call_number: 2,
            timestamp: 0,
            outgoing_sequence: 0,
            incoming_sequence: 0,
            frame_type: 7,
            subclass: 0,
            subclass_is_log: false,
        };
        assert_eq!(decode_iax_command(&header), Ok(None));

        header.frame_type = 6;
        header.subclass = 41;
        assert_eq!(
            decode_iax_command(&header),
            Ok(Some(IaxCommand::Unknown(41)))
        );
        assert_eq!(IaxCommand::Unknown(41).subclass_value(), 41);
    }
}
