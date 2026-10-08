//! IAX voice-frame classification without codec decoding or network I/O.

use crate::codec::{CodecAdapter, CodecError};
use crate::protocol::{
    FullFrameHeader, HeaderParseError, MiniFrameHeader, MiniFrameParseError, SubclassDecodeError,
    decode_subclass, parse_full_frame_packet, parse_mini_frame,
};

/// A parsed IAX voice frame with payload still encoded in its negotiated codec.
#[derive(Debug, Eq, PartialEq)]
pub enum VoiceFrame<'a> {
    /// Full voice frame; the subclass supplies its codec format bit.
    Full {
        /// IAX full-frame header.
        header: FullFrameHeader,
        /// Codec format bit carried by the full-frame subclass.
        format: u32,
        /// Borrowed encoded audio payload.
        payload: &'a [u8],
    },
    /// Mini voice frame; its codec format is inherited from call negotiation.
    Mini {
        /// IAX mini-frame header.
        header: MiniFrameHeader,
        /// Codec format bit selected when the call was accepted.
        format: u32,
        /// Borrowed encoded audio payload.
        payload: &'a [u8],
    },
}

/// Why an IAX datagram is not a usable voice frame.
#[derive(Debug, Eq, PartialEq)]
pub enum VoiceFrameError {
    /// Fewer than two bytes are present to classify the IAX frame.
    Truncated {
        /// Number of bytes received.
        actual_length: usize,
    },
    /// The datagram is not a voice frame or mini voice frame.
    NotVoiceFrame,
    /// A full-frame header could not be parsed.
    FullFrame(HeaderParseError),
    /// A mini-frame header could not be parsed.
    MiniFrame(MiniFrameParseError),
    /// The full-frame codec subclass could not be decoded.
    Subclass(SubclassDecodeError),
    /// Codec format is zero or names more than one format.
    InvalidFormat {
        /// Invalid format value.
        value: i64,
    },
}

/// Why a voice mini-frame could not be encoded into the caller's buffer.
#[derive(Debug, Eq, PartialEq)]
pub enum VoiceFrameEncodeError {
    /// The IAX source call number is zero or outside the 15-bit range.
    InvalidSourceCallNumber {
        /// Invalid source call number.
        value: u16,
    },
    /// The output buffer cannot contain the four-byte mini-frame header.
    BufferTooSmall {
        /// Minimum buffer size required for the header.
        required: usize,
        /// Output-buffer size provided by the caller.
        available: usize,
    },
    /// The codec could not encode the PCM payload into the remaining buffer.
    Codec(CodecError),
}

/// Encode one negotiated-codec media frame into caller-owned storage.
///
/// The payload is encoded after the four-byte mini-frame header area has been
/// capacity-checked. The header is written only after codec success, so an
/// error never leaves a packet that looks partially valid on the wire.
pub fn encode_mini_voice_frame(
    codec: &impl CodecAdapter,
    header: MiniFrameHeader,
    pcm: &[f32],
    output: &mut [u8],
) -> Result<usize, VoiceFrameEncodeError> {
    if header.source_call_number == 0 || header.source_call_number > 0x7fff {
        return Err(VoiceFrameEncodeError::InvalidSourceCallNumber {
            value: header.source_call_number,
        });
    }
    if output.len() < 4 {
        return Err(VoiceFrameEncodeError::BufferTooSmall {
            required: 4,
            available: output.len(),
        });
    }

    let payload_length = codec
        .encode(pcm, &mut output[4..])
        .map_err(VoiceFrameEncodeError::Codec)?;
    output[..2].copy_from_slice(&header.source_call_number.to_be_bytes());
    output[2..4].copy_from_slice(&header.timestamp.to_be_bytes());
    Ok(4 + payload_length)
}

/// Parse a full or mini voice frame while leaving encoded media untouched.
///
/// Mini frames do not carry a format field, so their codec comes from the
/// caller's already-negotiated call state.
pub fn parse_voice_frame(
    packet: &[u8],
    negotiated_format: u32,
) -> Result<VoiceFrame<'_>, VoiceFrameError> {
    if packet.len() < 2 {
        return Err(VoiceFrameError::Truncated {
            actual_length: packet.len(),
        });
    }

    let source = u16::from_be_bytes([packet[0], packet[1]]);
    if source & 0x8000 != 0 {
        parse_full_voice_frame(packet)
    } else if source == 0 {
        Err(VoiceFrameError::NotVoiceFrame)
    } else {
        parse_mini_voice_frame(packet, negotiated_format)
    }
}

fn parse_full_voice_frame(packet: &[u8]) -> Result<VoiceFrame<'_>, VoiceFrameError> {
    let frame = parse_full_frame_packet(packet).map_err(VoiceFrameError::FullFrame)?;
    if frame.header.frame_type != 2 {
        return Err(VoiceFrameError::NotVoiceFrame);
    }

    let encoded_subclass = (u8::from(frame.header.subclass_is_log) << 7) | frame.header.subclass;
    let format = decode_subclass(encoded_subclass).map_err(VoiceFrameError::Subclass)?;
    let format =
        u32::try_from(format).map_err(|_| VoiceFrameError::InvalidFormat { value: format })?;
    validate_format(format)?;

    Ok(VoiceFrame::Full {
        header: frame.header,
        format,
        payload: frame.payload,
    })
}

fn parse_mini_voice_frame(
    packet: &[u8],
    negotiated_format: u32,
) -> Result<VoiceFrame<'_>, VoiceFrameError> {
    validate_format(negotiated_format)?;
    let frame = parse_mini_frame(packet).map_err(VoiceFrameError::MiniFrame)?;
    Ok(VoiceFrame::Mini {
        header: frame.header,
        format: negotiated_format,
        payload: frame.payload,
    })
}

fn validate_format(format: u32) -> Result<(), VoiceFrameError> {
    if !format.is_power_of_two() {
        return Err(VoiceFrameError::InvalidFormat {
            value: i64::from(format),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
