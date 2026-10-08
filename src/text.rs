//! IAX2 UTF-8 text-frame parsing and serialization.

use crate::protocol::{
    FrameEncodeError, FullFrameHeader, HeaderParseError, parse_full_frame_packet,
    serialize_full_frame,
};

const TEXT_FRAME_TYPE: u8 = 7;

/// A validated text frame borrowing text from the received packet.
#[derive(Debug, Eq, PartialEq)]
pub struct IaxTextFrame<'a> {
    /// The fixed header of the received full frame.
    pub header: FullFrameHeader,
    /// UTF-8 text carried after the fixed header.
    pub text: &'a str,
}

/// Why an IAX2 text frame could not be parsed.
#[derive(Debug, Eq, PartialEq)]
pub enum TextFrameParseError {
    /// The fixed full-frame header was invalid.
    Header(HeaderParseError),
    /// The frame type is not IAX2 text (7).
    NotTextFrame {
        /// Received frame type.
        frame_type: u8,
    },
    /// Text frames must use subclass zero without exponent encoding.
    InvalidSubclass {
        /// Received subclass octet including the C bit.
        encoded: u8,
    },
    /// The text payload is not valid UTF-8.
    InvalidUtf8 {
        /// Byte offset of the first invalid sequence.
        valid_up_to: usize,
    },
}

/// Why a text frame could not be serialized.
#[derive(Debug, Eq, PartialEq)]
pub enum TextFrameEncodeError {
    /// The supplied header does not describe a text frame.
    NotTextFrame {
        /// Supplied frame type.
        frame_type: u8,
    },
    /// The supplied header has a nonzero or exponent-encoded subclass.
    InvalidSubclass {
        /// Supplied subclass octet including the C bit.
        encoded: u8,
    },
    /// The common full-frame serializer rejected a header field.
    Frame(FrameEncodeError),
}

/// Parse a full frame as an IAX2 UTF-8 text frame.
pub fn parse_text_frame(packet: &[u8]) -> Result<IaxTextFrame<'_>, TextFrameParseError> {
    let parsed = parse_full_frame_packet(packet).map_err(TextFrameParseError::Header)?;
    if parsed.header.frame_type != TEXT_FRAME_TYPE {
        return Err(TextFrameParseError::NotTextFrame {
            frame_type: parsed.header.frame_type,
        });
    }

    let subclass = (u8::from(parsed.header.subclass_is_log) << 7) | parsed.header.subclass;
    if subclass != 0 {
        return Err(TextFrameParseError::InvalidSubclass { encoded: subclass });
    }

    let text =
        std::str::from_utf8(parsed.payload).map_err(|error| TextFrameParseError::InvalidUtf8 {
            valid_up_to: error.valid_up_to(),
        })?;

    Ok(IaxTextFrame {
        header: parsed.header,
        text,
    })
}

/// Serialize UTF-8 text using the supplied full-frame sequencing fields.
pub fn serialize_text_frame(
    header: &FullFrameHeader,
    text: &str,
) -> Result<Vec<u8>, TextFrameEncodeError> {
    if header.frame_type != TEXT_FRAME_TYPE {
        return Err(TextFrameEncodeError::NotTextFrame {
            frame_type: header.frame_type,
        });
    }

    let subclass = (u8::from(header.subclass_is_log) << 7) | header.subclass;
    if subclass != 0 {
        return Err(TextFrameEncodeError::InvalidSubclass { encoded: subclass });
    }

    serialize_full_frame(header, text.as_bytes()).map_err(TextFrameEncodeError::Frame)
}

#[cfg(test)]
mod tests;
