//! Released codec adapters for IAX2-negotiated media formats.

use audio_codec_algorithms::{decode_ulaw as decode_sample, encode_ulaw as encode_sample};

/// IAX format bit for G.711 μ-law (RFC 5456, §8.7).
pub const IAX_FORMAT_ULAW: u32 = 0x0000_0004;

/// G.711 μ-law's required narrowband sample rate.
pub const ULAW_SAMPLE_RATE_HZ: u32 = 8_000;

/// Output storage was too small for a complete codec frame.
#[derive(Debug, Eq, PartialEq)]
pub struct CodecError {
    /// Number of output samples or bytes required.
    pub required: usize,
    /// Number of output samples or bytes supplied.
    pub available: usize,
}

/// Codec conversion boundary kept independent of IAX packet and socket code.
pub trait CodecAdapter {
    /// IAX capability/format bit for this codec.
    fn iax_format(&self) -> u32;

    /// Required PCM sample rate for this codec.
    fn sample_rate_hz(&self) -> u32;

    /// Decode one payload into normalized mono `f32` PCM without allocating.
    /// If `pcm` is too small, return an error without modifying it.
    fn decode(&self, encoded: &[u8], pcm: &mut [f32]) -> Result<usize, CodecError>;

    /// Encode normalized mono `f32` PCM without allocating.
    /// If `encoded` is too small, return an error without modifying it.
    fn encode(&self, pcm: &[f32], encoded: &mut [u8]) -> Result<usize, CodecError>;
}

/// G.711 μ-law adapter backed by the released `audio-codec-algorithms` crate.
#[derive(Clone, Copy, Debug, Default)]
pub struct G711Ulaw;

impl CodecAdapter for G711Ulaw {
    fn iax_format(&self) -> u32 {
        IAX_FORMAT_ULAW
    }

    fn sample_rate_hz(&self) -> u32 {
        ULAW_SAMPLE_RATE_HZ
    }

    fn decode(&self, encoded: &[u8], pcm: &mut [f32]) -> Result<usize, CodecError> {
        require_capacity(pcm.len(), encoded.len())?;
        for (output, &sample) in pcm.iter_mut().zip(encoded) {
            *output = f32::from(decode_sample(sample)) / 32768.0;
        }
        Ok(encoded.len())
    }

    fn encode(&self, pcm: &[f32], encoded: &mut [u8]) -> Result<usize, CodecError> {
        require_capacity(encoded.len(), pcm.len())?;
        for (output, &sample) in encoded.iter_mut().zip(pcm) {
            let linear = (sample.clamp(-1.0, 1.0) * 32768.0) as i16;
            *output = encode_sample(linear);
        }
        Ok(pcm.len())
    }
}

fn require_capacity(available: usize, required: usize) -> Result<(), CodecError> {
    if available < required {
        return Err(CodecError {
            required,
            available,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
