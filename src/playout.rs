//! IAX timestamp translation and ordered codec/gap delivery around the jitter capability.

use crate::{
    client::{DialError, IaxPeerEvent},
    codec::{CodecAdapter, G711Ulaw},
    jitter::{Admission, Decision, Jitter, Kind, MAX_PAYLOAD, Observation},
};
use std::time::Instant;

/// One connection's exclusive packet-release state; no PCM queue or PLC lives here.
pub(crate) struct Playout {
    jitter: Jitter,
    origin: Instant,
    highest_ms: Option<u64>,
    encoded: [u8; MAX_PAYLOAD],
    pending: Option<Decision>,
    tail_end: Option<u64>,
    released_to: u64,
    skipped_span: u64,
    last_release: Option<Instant>,
    active: bool,
    ending: bool,
    next_key: Option<u32>,
    completed: Observation,
}

impl Playout {
    pub(crate) fn observe(&self) -> Result<Observation, DialError> {
        let mut current = self.jitter.observe().map_err(|_| DialError::Jitter)?;
        let completed = &self.completed;
        for (value, prior) in [
            (&mut current.duplicate_drops, completed.duplicate_drops),
            (&mut current.late_drops, completed.late_drops),
            (&mut current.full_drops, completed.full_drops),
            (&mut current.missing_span, completed.missing_span),
            (&mut current.insertion_span, completed.insertion_span),
            (&mut current.skipped_span, completed.skipped_span),
            (&mut current.limit_resets, completed.limit_resets),
            (&mut current.overload_drops, completed.overload_drops),
            (&mut current.overload_span, completed.overload_span),
        ] {
            *value = value.saturating_add(prior);
        }
        Ok(current)
    }

    pub(crate) fn new(jitter: Jitter, origin: Instant) -> Self {
        Self {
            jitter,
            origin,
            highest_ms: None,
            encoded: [0; MAX_PAYLOAD],
            pending: None,
            tail_end: None,
            released_to: 0,
            skipped_span: 0,
            last_release: None,
            active: true,
            ending: false,
            next_key: None,
            completed: Observation::default(),
        }
    }
    pub(crate) fn put(
        &mut self,
        timestamp: u32,
        mini: bool,
        arrived_at: Instant,
        payload: &[u8],
    ) -> Result<(), DialError> {
        // ASL peers can send valid voice after UNKEY without another KEY. Media
        // resumes playout; the controller still owns receive/PTT qualification.
        self.active = true;
        self.expire_quiet(arrived_at)?;
        let timestamp = self.unwrap_ms(timestamp, mini) * 8;
        let admission = self
            .jitter
            .put(
                timestamp,
                payload.len() as u32,
                self.ns(arrived_at),
                payload,
            )
            .map_err(|_| DialError::Jitter)?;
        if admission == Admission::Accepted {
            self.tail_end = Some(
                self.tail_end
                    .unwrap_or(0)
                    .max(timestamp + payload.len() as u64),
            );
        }
        Ok(())
    }
    pub(crate) fn poll(
        &mut self,
        now: Instant,
        pcm: &mut [f32],
    ) -> Result<IaxPeerEvent, DialError> {
        if self.pending.is_some() {
            return self.decode_pending(now, pcm);
        }
        if !self.active {
            return if let Some(timestamp) = self.next_key.take() {
                self.key(timestamp)?;
                Ok(IaxPeerEvent::RadioKey)
            } else {
                Ok(IaxPeerEvent::None)
            };
        }
        if self.ending && self.tail_end.is_none_or(|end| self.released_to >= end) {
            return self.finish();
        }
        if self.tail_end.is_some_and(|end| self.released_to >= end) {
            self.expire_quiet(now)?;
            // With no accepted future media, the ring alone supplies shortfall
            // concealment and its existing 60ms receive-activity fallback.
            return Ok(IaxPeerEvent::None);
        }
        let decision = self
            .jitter
            .get(self.ns(now), 160, &mut self.encoded)
            .map_err(|_| DialError::Jitter)?;
        match decision.kind {
            Kind::NotDue => {
                // A genuine overload reset has no remaining native timeline.
                if self.ending && decision.deadline_ns == 0 {
                    self.finish()
                } else {
                    Ok(IaxPeerEvent::None)
                }
            }
            Kind::Packet => {
                if decision.span as usize != decision.length {
                    return Err(DialError::Jitter);
                }
                let offset = decision.start_offset;
                self.pending = Some(decision);
                if offset > 0 {
                    Ok(IaxPeerEvent::Gap(offset as usize))
                } else {
                    self.decode_pending(now, pcm)
                }
            }
            Kind::Missing | Kind::Insertion => {
                if self.ending && self.tail_end.is_some_and(|end| decision.timestamp >= end) {
                    return self.finish();
                }
                let count = decision.span as usize;
                self.commit(now, &decision)?;
                Ok(IaxPeerEvent::Gap(count))
            }
        }
    }
    pub(crate) fn key(&mut self, timestamp: u32) -> Result<bool, DialError> {
        if self.ending {
            self.next_key = Some(timestamp);
            return Ok(false);
        }
        // Voice may have arrived ahead of this reliable key. Only completed
        // unkey resets the previous epoch, never the key closing a sequence hole.
        self.unwrap_ms(timestamp, false);
        self.active = true;
        Ok(true)
    }
    pub(crate) fn unkey(&mut self) {
        self.ending = true;
    }
    pub(crate) fn blocks_transport(&self) -> bool {
        self.pending.is_some() || self.next_key.is_some()
    }

    fn ns(&self, instant: Instant) -> u64 {
        instant
            .saturating_duration_since(self.origin)
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64
    }

    /// Keep the nearest full/mini epoch while reordered packets cannot rewind the reference.
    fn unwrap_ms(&mut self, timestamp: u32, mini: bool) -> u64 {
        let period = if mini { 1u64 << 16 } else { 1u64 << 32 };
        let reference = self
            .highest_ms
            .unwrap_or((1u64 << 32) + u64::from(timestamp));
        let mut candidate = (reference & !(period - 1)) | (u64::from(timestamp) & (period - 1));
        if candidate + period / 2 < reference {
            candidate += period;
        } else if candidate > reference + period / 2 {
            candidate -= period;
        }
        self.highest_ms = Some(reference.max(candidate));
        candidate
    }

    fn decode_pending(&mut self, now: Instant, pcm: &mut [f32]) -> Result<IaxPeerEvent, DialError> {
        let decision = self.pending.as_ref().expect("pending packet");
        let skip = decision.start_offset.saturating_neg().max(0) as usize;
        let count = G711Ulaw
            .decode(&self.encoded[skip..decision.length], pcm)
            .map_err(DialError::Decode)?;
        let decision = self.pending.take().expect("decoded packet");
        self.commit(now, &decision)?;
        self.last_release = Some(now);
        Ok(IaxPeerEvent::Audio(count))
    }

    fn commit(&mut self, now: Instant, decision: &Decision) -> Result<(), DialError> {
        // The caller accepts this whole event before polling again. Ring reserve is
        // deliberately not fed back as a second packet-delay controller.
        self.jitter
            .advance(self.ns(now), 0)
            .map_err(|_| DialError::Jitter)?;
        let observation = self.jitter.observe().map_err(|_| DialError::Jitter)?;
        let media_span = if decision.kind == Kind::Insertion {
            0
        } else {
            u64::from(decision.span)
        };
        self.released_to = decision.timestamp
            + media_span
            + observation.skipped_span.saturating_sub(self.skipped_span);
        self.skipped_span = observation.skipped_span;
        Ok(())
    }

    fn clear(&mut self) -> Result<(), DialError> {
        self.completed = self.observe()?;
        self.jitter.reset().map_err(|_| DialError::Jitter)?;
        self.pending = None;
        self.tail_end = None;
        self.released_to = 0;
        self.skipped_span = 0;
        self.last_release = None;
        self.ending = false;
        Ok(())
    }

    fn expire_quiet(&mut self, now: Instant) -> Result<(), DialError> {
        if !self.ending
            && self.tail_end.is_some_and(|end| self.released_to >= end)
            && self.last_release.is_some_and(|released| {
                now.saturating_duration_since(released) >= std::time::Duration::from_millis(60)
            })
        {
            self.clear()?;
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<IaxPeerEvent, DialError> {
        self.clear()?;
        self.active = false;
        Ok(IaxPeerEvent::RadioUnkey)
    }
}

#[cfg(test)]
#[path = "playout_tests.rs"]
mod tests;
