//! IAX timestamp translation and ordered codec/gap delivery around the jitter capability.

use crate::{
    client::{DialError, IaxPeerEvent},
    codec::{
        CodecAdapter, G711Ulaw,
        providers::{Decoder, Status},
    },
    jitter::{Admission, Decision, Jitter, Kind, MAX_PAYLOAD, Observation},
};
use std::time::Instant;

/// One connection's exclusive packet-release state; no PCM queue or PLC lives here.
pub(crate) struct Playout {
    jitter: Jitter,
    origin: Instant,
    highest_ms: Option<u64>,
    source_origin: Option<u64>,
    encoded: [u8; MAX_PAYLOAD],
    pending: Option<Decision>,
    pending_prefix: u32,
    rate: u32,
    decoded: Vec<f32>,
    decoded_position: usize,
    decoded_count: usize,
    tail_end: Option<u64>,
    released_to: u64,
    skipped_span: u64,
    last_release: Option<Instant>,
    active: bool,
    ending: bool,
    next_key: Option<u32>,
    completed: Observation,
    release_deadline: Option<Instant>,
}

impl Playout {
    pub(crate) fn deadline(&self, now: Instant) -> Option<Instant> {
        if self.blocks_transport()
            || (self.ending && self.tail_end.is_none_or(|end| self.released_to >= end))
        {
            return Some(now);
        }
        if self.tail_end.is_some_and(|end| self.released_to >= end) {
            return self
                .last_release
                .map(|last| last + std::time::Duration::from_millis(60));
        }
        self.release_deadline.or_else(|| self.tail_end.map(|_| now))
    }
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

    #[cfg(test)]
    pub(crate) fn new(jitter: Jitter, origin: Instant) -> Self {
        Self::new_at_rate(jitter, origin, 8000)
    }
    pub(crate) fn new_at_rate(jitter: Jitter, origin: Instant, rate: u32) -> Self {
        Self {
            jitter,
            origin,
            highest_ms: None,
            source_origin: None,
            encoded: [0; MAX_PAYLOAD],
            pending: None,
            pending_prefix: 0,
            rate,
            decoded: Vec::new(),
            decoded_position: 0,
            decoded_count: 0,
            tail_end: None,
            released_to: 0,
            skipped_span: 0,
            last_release: None,
            active: true,
            ending: false,
            next_key: None,
            completed: Observation::default(),
            release_deadline: None,
        }
    }
    #[cfg(test)]
    pub(crate) fn put(
        &mut self,
        timestamp: u32,
        mini: bool,
        arrived_at: Instant,
        payload: &[u8],
    ) -> Result<(), DialError> {
        self.put_with_codec(timestamp, mini, arrived_at, payload, None)
    }
    pub(crate) fn put_with_codec(
        &mut self,
        timestamp: u32,
        mini: bool,
        arrived_at: Instant,
        payload: &[u8],
        decoder: Option<&Decoder>,
    ) -> Result<(), DialError> {
        let span = match decoder {
            Some(decoder) => match decoder.inspect(payload) {
                Ok(info) => info.frames,
                Err(error) if error.status == Status::Malformed => return Ok(()),
                Err(error) => return Err(DialError::Provider(error)),
            },
            None => payload.len() as u32,
        };
        // Invalid framing must not revive a burst or move its timestamp epoch.
        // Valid ASL voice may resume after UNKEY without another KEY; receive/PTT
        // qualification remains the controller's responsibility.
        self.active = true;
        self.expire_quiet(arrived_at)?;
        let mut timestamp = self.unwrap_ms(timestamp, mini) * u64::from(self.rate) / 1000;
        let quantum = self.jitter.release_span();
        if quantum * 1000 % self.rate != 0 {
            // IAX milliseconds cannot represent LPC10's 22.5 ms coding grid.
            // Recover whole-unit positions instead of trimming four valid
            // samples from alternating, otherwise contiguous packets.
            let origin = *self.source_origin.get_or_insert(timestamp);
            let offset = i128::from(timestamp) - i128::from(origin);
            let unit = i128::from(quantum);
            timestamp = (i128::from(origin) + (offset + unit / 2).div_euclid(unit) * unit)
                .clamp(0, i128::from(u64::MAX)) as u64;
        }
        let arrival_ns = self.ns(arrived_at);
        let admission = self
            .jitter
            .put(timestamp, span, arrival_ns, payload)
            .map_err(|_| DialError::Jitter)?;
        if admission == Admission::Accepted {
            self.tail_end = Some(self.tail_end.unwrap_or(0).max(timestamp + u64::from(span)));
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn poll(
        &mut self,
        now: Instant,
        pcm: &mut [f32],
    ) -> Result<IaxPeerEvent, DialError> {
        self.poll_with_codec(now, pcm, None)
    }
    pub(crate) fn poll_with_codec(
        &mut self,
        now: Instant,
        pcm: &mut [f32],
        decoder: Option<&mut Decoder>,
    ) -> Result<IaxPeerEvent, DialError> {
        self.release_deadline = None;
        if self.pending.is_some() {
            return self.decode_pending(now, pcm, decoder);
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
        let now_ns = self.ns(now);
        let release_span = self.jitter.release_span();
        let decision = self
            .jitter
            .get(now_ns, release_span, &mut self.encoded)
            .map_err(|_| DialError::Jitter)?;
        match decision.kind {
            Kind::NotDue => {
                if decision.deadline_ns != 0 {
                    self.release_deadline = self
                        .origin
                        .checked_add(std::time::Duration::from_nanos(decision.deadline_ns));
                }
                // A genuine overload reset has no remaining native timeline.
                if self.ending && decision.deadline_ns == 0 {
                    self.finish()
                } else {
                    Ok(IaxPeerEvent::None)
                }
            }
            Kind::Packet => {
                let frames = match &decoder {
                    Some(decoder) => {
                        decoder
                            .inspect(&self.encoded[..decision.length])
                            .map_err(DialError::Provider)?
                            .frames
                    }
                    None => decision.length as u32,
                };
                if decision.span != frames {
                    return Err(DialError::Jitter);
                }
                self.pending_prefix = decision.start_offset.max(0) as u32;
                self.pending = Some(decision);
                self.decode_pending(now, pcm, decoder)
            }
            Kind::Missing | Kind::Insertion => {
                if self.ending && self.tail_end.is_some_and(|end| decision.timestamp >= end) {
                    return self.finish();
                }
                self.pending = Some(decision);
                self.decode_pending(now, pcm, decoder)
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

    fn decode_pending(
        &mut self,
        now: Instant,
        pcm: &mut [f32],
        decoder: Option<&mut Decoder>,
    ) -> Result<IaxPeerEvent, DialError> {
        if self.pending_prefix != 0 {
            let event = Self::gap_event(self.pending_prefix, pcm, decoder)?;
            self.pending_prefix = 0;
            return Ok(event);
        }
        let decision = self.pending.as_ref().expect("pending packet");
        if decision.kind != Kind::Packet {
            // An adaptive delay insertion is not missing source audio: do not
            // advance codec history. Only actual loss requests native PLC.
            let event = Self::gap_event(
                decision.span,
                pcm,
                if decision.kind == Kind::Missing {
                    decoder
                } else {
                    None
                },
            )?;
            let decision = self.pending.take().expect("rendered gap");
            self.commit(now, &decision)?;
            return Ok(event);
        }
        let skip = decision.start_offset.saturating_neg().max(0) as usize;
        let count = match decoder {
            Some(decoder) => {
                if pcm.is_empty() {
                    return Err(DialError::Decode(crate::codec::CodecError {
                        required: 1,
                        available: 0,
                    }));
                }
                if self.decoded_count == 0 {
                    // One packet's source PCM, not another timing queue. Allocation
                    // and the whole compressed decode stay on this network owner.
                    let required = decision.span as usize;
                    self.decoded
                        .try_reserve(required.saturating_sub(self.decoded.len()))
                        .map_err(|_| DialError::InvalidOptions)?;
                    self.decoded.resize(required, 0.0);
                    self.decoded_count = decoder
                        .decode_recovering(&self.encoded[..decision.length], &mut self.decoded)
                        .map_err(DialError::Provider)?;
                    if self.decoded_count == 0 {
                        let count = decision.span as usize - skip;
                        let decision = self.pending.take().expect("unrecoverable media span");
                        self.commit(now, &decision)?;
                        return Ok(IaxPeerEvent::Gap(count));
                    }
                    self.decoded_position = skip.min(self.decoded_count);
                }
                let count = (self.decoded_count - self.decoded_position).min(pcm.len());
                pcm[..count].copy_from_slice(
                    &self.decoded[self.decoded_position..self.decoded_position + count],
                );
                self.decoded_position += count;
                if self.decoded_position < self.decoded_count {
                    self.last_release = Some(now);
                    return Ok(IaxPeerEvent::Audio(count));
                }
                self.decoded_count = 0;
                self.decoded_position = 0;
                count
            }
            None => G711Ulaw
                .decode(&self.encoded[skip..decision.length], pcm)
                .map_err(DialError::Decode)?,
        };
        let decision = self.pending.take().expect("decoded packet");
        self.commit(now, &decision)?;
        self.last_release = Some(now);
        Ok(IaxPeerEvent::Audio(count))
    }

    fn gap_event(
        span: u32,
        pcm: &mut [f32],
        decoder: Option<&mut Decoder>,
    ) -> Result<IaxPeerEvent, DialError> {
        if let Some(decoder) = decoder {
            let frames = decoder.conceal(span, pcm).map_err(DialError::Provider)?;
            if frames != 0 {
                return Ok(IaxPeerEvent::Audio(frames));
            }
        }
        Ok(IaxPeerEvent::Gap(span as usize))
    }

    fn commit(&mut self, now: Instant, decision: &Decision) -> Result<(), DialError> {
        // The caller accepts this whole event before polling again. Ring reserve is
        // deliberately not fed back as a second packet-delay controller.
        let now_ns = self.ns(now);
        self.jitter
            .advance(now_ns, 0)
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
        self.source_origin = None;
        self.pending = None;
        self.pending_prefix = 0;
        self.decoded_count = 0;
        self.decoded_position = 0;
        self.release_deadline = None;
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
