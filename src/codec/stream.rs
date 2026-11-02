//! One peer's retained codec owners, prepared outside the audio callbacks.
use super::providers::{CodecCatalog, Decoder, Encoder, Error, ProfileId, Status};

/// Independent directional contexts and their actual linear PCM clock.
pub struct Stream {
    /// Selected source clock; no conversion occurs in the codec provider.
    pub rate: u32,
    /// Default complete-unit outgoing packet duration.
    pub packet_frames: u32,
    /// Natural loss request granularity, at least the jitter adapter's 10 ms step.
    pub loss_unit: u32,
    /// Stateful outgoing owner.
    pub encoder: Encoder,
    /// Stateful incoming owner, including native concealment history.
    pub decoder: Decoder,
}
impl Stream {
    /// Open the preferred explicit mode. Stream codecs use 20 ms; longer
    /// coding units retain their natural duration instead of being truncated.
    pub fn open(catalog: &CodecCatalog, id: ProfileId) -> Result<Self, Error> {
        let profile = catalog.profile(id).ok_or(Error {
            status: Status::Failed,
            required_capacity: 0,
            operation: "unselected stream profile",
        })?;
        let mode = &profile.modes[0];
        let packet_frames =
            (profile.sample_rate_hz / 50 / mode.frame_samples).max(1) * mode.frame_samples;
        Ok(Self {
            rate: profile.sample_rate_hz,
            packet_frames,
            loss_unit: mode.frame_samples.max(profile.sample_rate_hz / 100),
            encoder: catalog.encoder(id, mode.id, packet_frames, 65503)?,
            decoder: catalog.decoder(id, mode.id, packet_frames, 65503)?,
        })
    }
}
