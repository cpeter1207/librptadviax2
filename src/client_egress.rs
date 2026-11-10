//! Opt-in bounded phone PCM transmission; reliable protocol markers contain no PCM.
use super::{DialError, IaxPeer};
use std::io;

/// Immutable qualification retained with one prepared packet across every retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressTime {
    /// Exact token returned by completed local egress retirement; not mailbox authority.
    pub epoch: u64,
    /// Absolute expiry in this peer's elapsed millisecond clock, never refreshed.
    pub deadline_ms: u32,
}
/// Ownership outcome for a timed prepared PCM packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimedMediaSend {
    /// The actual Mini datagram reached UDP. This is not remote delivery/ACK.
    Accepted,
    /// No PCM was committed; retain the exact packet/deadline/epoch for retry.
    WouldBlock,
    /// Expired, stale epoch, or unrepresentable/saturated clock; abandon this item.
    Expired,
}
/// Serial local retirement receipt; receive-source epochs are independent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressRetirement {
    /// Old local PCM eligibility and encoder history retired; new token returned.
    /// Successful prior UDP sends cannot be recalled; no remote ACK is claimed.
    Complete(u64),
    /// A committed legacy PCM full-frame still needs actual ACK/teardown. Its
    /// OSeq hole is retained, but PCM retries are suppressed; control stays reliable.
    Pending,
}
pub(super) struct State {
    pub active: bool,
    pending: bool,
    failed: bool,
    epoch: u64,
    last_timestamp: Option<u32>,
    announced: Option<u32>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            active: false,
            pending: false,
            failed: false,
            epoch: 1,
            last_timestamp: None,
            announced: None,
        }
    }
}

pub(super) fn payload_voice(packet: &[u8]) -> bool {
    // These private vectors are full frames constructed by OutboundCallSetup;
    // the12-byte header and frame type are independent of opaque codec bytes.
    packet.len() > 12 && packet[10] == 2
}
fn expired(elapsed_ms: u32, deadline_ms: u32) -> bool {
    elapsed_ms == u32::MAX || deadline_ms <= elapsed_ms || deadline_ms - elapsed_ms > 500
}

impl IaxPeer {
    pub(super) fn ensure_egress_preparation(&self) -> Result<(), DialError> {
        if self.egress.failed || self.egress.pending {
            Err(DialError::InvalidOptions)
        } else {
            Ok(())
        }
    }

    /// Retire local egress media on the exclusive serial owner, never audio.
    /// Retry Pending with the same owner while polling actual protocol ACKs.
    pub fn retire_egress(&mut self) -> Result<EgressRetirement, DialError> {
        self.ensure_provider_live()?;
        if self.egress.failed {
            return Err(DialError::InvalidOptions);
        }
        if !self.egress.pending {
            self.egress.failed = true;
            self.egress.epoch = self
                .egress
                .epoch
                .checked_add(1)
                .ok_or(DialError::InvalidOptions)?;
            self.egress.active = true;
            self.egress.pending = true;
            self.egress.last_timestamp = None;
            self.egress.announced = None;
            self.voice_epoch = None;
            // VNAK can have staged a copy of a legacy voice retry as a reply.
            self.pending_replies.retain(|packet| !payload_voice(packet));
            self.reset_encoder()?;
            self.egress.failed = false;
        }
        if self
            .pending_reliable
            .iter()
            .any(|frame| payload_voice(&frame.packet))
        {
            return Ok(EgressRetirement::Pending);
        }
        self.egress.pending = false;
        Ok(EgressRetirement::Complete(self.egress.epoch))
    }

    /// Send supported PCMU/PCMA8k20ms PCM only as an expiring Mini datagram.
    /// Reliable full Voice markers announce codec/timestamp, with ZERO PCM.
    /// Initial marker loss is ordinary media loss until its reliable retry.
    pub fn send_prepared_audio_timed(
        &mut self,
        payload: &[u8],
        packet_frames: u32,
        timestamp_ms: u32,
        time: EgressTime,
    ) -> Result<TimedMediaSend, DialError> {
        self.ensure_provider_live()?;
        if self.egress.failed || !self.egress.active || self.egress.pending {
            return Err(DialError::InvalidOptions);
        }
        if time.epoch != self.egress.epoch || expired(self.elapsed_ms(), time.deadline_ms) {
            return Ok(TimedMediaSend::Expired);
        }
        if !matches!(
            crate::formats::IaxFormat(self.format).profile(),
            Some(
                crate::codec::providers::ProfileId::G711Mu
                    | crate::codec::providers::ProfileId::G711A
            )
        ) || packet_frames != 160
            || payload.len() != 160
        {
            return Err(DialError::InvalidOptions);
        }
        // Completed retirement retained/reset its Stream. The catalog verifies
        // G.711's8kHz clock; every byte is one valid sample. Exact160-byte/160-frame
        // validation needs no compressed-codec inspection. The generic sender
        // keeps its existing inspector for variable codecs and packet spans.
        if self.pending_reliable.iter().any(|frame| !frame.sent) {
            return Ok(TimedMediaSend::WouldBlock);
        }
        let epoch = timestamp_ms >> 16;
        let discontinuous = self
            .egress
            .last_timestamp
            // A marker can succeed while all of its PCM expires. It still
            // establishes the remote timestamp anchor for a later silence.
            .or(self.egress.announced)
            .is_some_and(|prior| timestamp_ms < prior || timestamp_ms - prior >= 32_768);
        if self.voice_epoch != Some(epoch)
            || (discontinuous && self.egress.announced != Some(timestamp_ms))
        {
            self.ensure_reliable_capacity()?;
            let marker = self
                .setup
                .send_voice_frame(&[], timestamp_ms, self.format)
                .map_err(DialError::Protocol)?;
            self.send_reliable(marker)?;
            self.voice_epoch = Some(epoch);
            self.egress.announced = Some(timestamp_ms);
            if self.pending_reliable.iter().any(|frame| !frame.sent) {
                return Ok(TimedMediaSend::WouldBlock);
            }
        }
        let mut packet = [0_u8; 164];
        packet[..2].copy_from_slice(&self.local_call.to_be_bytes());
        packet[2..4].copy_from_slice(&(timestamp_ms as u16).to_be_bytes());
        packet[4..164].copy_from_slice(payload);
        #[cfg(test)]
        super::unit_tests::timed_egress_commit_checkpoint(self.remote, timestamp_ms);
        let commit = || {
            // Check within the exact account's short lifetime guard, immediately
            // before the nonblocking UDP commit; no age-then-schedulable restamp.
            if expired(self.elapsed_ms(), time.deadline_ms) {
                return Ok(TimedMediaSend::Expired);
            }
            match self.endpoint.send_to(&packet[..164], self.remote) {
                Ok(_) => {
                    self.send_stats
                        .datagrams
                        .set(self.send_stats.datagrams.get().saturating_add(1));
                    Ok(TimedMediaSend::Accepted)
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.send_stats.blocked.set(true);
                    self.send_stats
                        .would_block
                        .set(self.send_stats.would_block.get().saturating_add(1));
                    Ok(TimedMediaSend::WouldBlock)
                }
                Err(error) => Err(DialError::Network(error)),
            }
        };
        let result = match &self.provider_ownership {
            Some(owner) => owner
                .with_live(commit)
                .map_err(|_| DialError::Protocol(crate::session::CallSetupError::CallFinished))?,
            None => commit(),
        }?;
        if result == TimedMediaSend::Accepted {
            self.egress.last_timestamp = Some(timestamp_ms);
            self.egress.announced = None;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_deadline_saturation_and_oversized_future_window_never_qualify() {
        for (now, deadline) in [(u32::MAX, u32::MAX), (10, 10), (10, 9), (10, 511)] {
            assert!(expired(now, deadline));
        }
        assert!(!expired(10, 510));
        assert!(!expired(10, 11));
    }
}
