//! Opt-in source provenance for the existing exclusive peer/media owner.
use super::{DialError, IaxPeer, IaxPeerEvent, SourceDelivery};
use crate::source_time::Span;
use std::time::Instant;

/// Product clock snapshot taken BEFORE entering the provider; never resampled here.
#[derive(Clone, Copy, Debug)]
pub struct SourceTimeInput {
    /// Stable nonzero product Host clock identity.
    pub host_clock_epoch: u64,
    /// Nanoseconds in that clock, captured before this call.
    pub reference_now_ns: u64,
    /// TARGET epoch whose previous downstream ring/DSP/RF owners actually retired.
    pub acknowledged_media_epoch: u64,
}
/// One existing event with optional genuine original source provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimedPeerEvent {
    /// The ordinary private/control/media event. Digits remain untimed IAX digits.
    pub event: IaxPeerEvent,
    /// Checked per-call media epoch; target of any pending retirement.
    pub media_epoch: u64,
    /// Monotonic playout PCM position in this epoch, including counted gaps/insertion.
    /// This is NOT a claimed wire timestamp or a DTMF interval.
    pub source_start: u64,
    /// Conservatively mapped original kernel receipt including5ms uncertainty.
    /// None never qualifies RF, including legacy/injected ingress and PLC/gaps.
    pub born_ns: Option<u64>,
    /// Previous media ownership must retire before acknowledging media_epoch.
    /// No Audio/Gap is returned while this remains true; private control may continue.
    pub discontinuity: bool,
}

pub(super) struct State {
    pub enabled: bool,
    pub last_span: Span,
    epoch: u64,
    pending: bool,
    clock_revoked: bool,
    host_epoch: Option<u64>,
    cursor: u64,
    cutoff: Option<Instant>,
    failed: bool,
    history_qualified: Option<bool>,
    history_receipt: Option<crate::source_time::Receipt>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            enabled: false,
            last_span: Span::default(),
            epoch: 1,
            pending: true,
            clock_revoked: false,
            host_epoch: None,
            cursor: 0,
            cutoff: None,
            failed: false,
            history_qualified: None,
            history_receipt: None,
        }
    }
}
impl IaxPeer {
    /// Poll using actual Linux RX provenance, preserving one mapped birth for
    /// every partial/suffix/retry of an original packet. Use this OR poll_event
    /// for this peer, never alternate modes after timed polling starts.
    pub fn poll_timed(
        &mut self,
        pcm: &mut [f32],
        text: &mut [u8],
        input: SourceTimeInput,
    ) -> Result<TimedPeerEvent, DialError> {
        self.poll_timed_mode(pcm, text, input, SourceDelivery::Deliver)
    }

    /// Opt into the fixed private G.711/20 ms source profile. Rejection before
    /// activation leaves all peer state unchanged. The profile then persists.
    pub fn poll_timed_private(
        &mut self,
        pcm: &mut [f32],
        text: &mut [u8],
        input: SourceTimeInput,
        delivery: SourceDelivery,
    ) -> Result<TimedPeerEvent, DialError> {
        self.activate_private_source()?;
        self.poll_timed_mode(pcm, text, input, delivery)
    }

    fn poll_timed_mode(
        &mut self,
        pcm: &mut [f32],
        text: &mut [u8],
        input: SourceTimeInput,
        delivery: SourceDelivery,
    ) -> Result<TimedPeerEvent, DialError> {
        let result = self.poll_timed_inner(pcm, text, input, delivery);
        if self.service.active
            && matches!(
                &result,
                Err(DialError::Network(_)
                    | DialError::Timeout
                    | DialError::Hangup
                    | DialError::EarlyEventsFull
                    | DialError::Protocol(_)
                    | DialError::Voice(_)
                    | DialError::Jitter)
            )
        {
            self.service.terminal = true;
        }
        if self.service.active
            && matches!(&result, Err(DialError::Provider(error))
            if error.status != crate::codec::providers::Status::OutputFull)
        {
            self.service.terminal = true;
        }
        result
    }

    fn poll_timed_inner(
        &mut self,
        pcm: &mut [f32],
        text: &mut [u8],
        input: SourceTimeInput,
        delivery: SourceDelivery,
    ) -> Result<TimedPeerEvent, DialError> {
        self.ensure_provider_live()?;
        if self.timed.failed {
            return Err(DialError::Jitter);
        }
        self.timed.enabled = true;
        if self.timed.pending && input.acknowledged_media_epoch == self.timed.epoch {
            self.timed.pending = false;
        }
        let revoked = self.endpoint.clock_revoked();
        let changed_host = self
            .timed
            .host_epoch
            .is_some_and(|epoch| epoch != input.host_clock_epoch);
        if changed_host || (revoked && !self.timed.clock_revoked) {
            self.retire_timed_media()?;
        }
        self.timed.host_epoch = Some(input.host_clock_epoch);
        self.timed.clock_revoked |= revoked;
        if self.timed_media_expired(Instant::now()) {
            self.retire_timed_media()?;
        }
        let mut event = match delivery {
            SourceDelivery::Deliver => self.poll_event_inner(pcm, text)?,
            SourceDelivery::ServiceOnly => {
                self.service_private()?;
                IaxPeerEvent::None
            }
        };
        if self.timed_media_expired(Instant::now()) {
            self.retire_timed_media()?;
        }
        if matches!(event, IaxPeerEvent::Audio(_)) {
            // Native jitter can become quiet/clear while codec history remains.
            // Retain its real original receipt independently until actual reset.
            if let Some(receipt) = self.timed.last_span.receipt {
                self.timed.history_receipt = Some(receipt);
            }
        }
        // Recheck the actual clock after receive/decode and before publication.
        if self.endpoint.clock_revoked() && !self.timed.clock_revoked {
            self.timed.clock_revoked = true;
            self.retire_timed_media()?;
        }
        if self.timed.pending && matches!(event, IaxPeerEvent::Audio(_) | IaxPeerEvent::Gap(_)) {
            event = IaxPeerEvent::None;
        }
        let source_start = self.timed.cursor;
        let born_ns = if let IaxPeerEvent::Audio(_) = event {
            if self.timed.clock_revoked {
                None
            } else {
                self.timed.last_span.birth(
                    input.host_clock_epoch,
                    input.reference_now_ns,
                    Instant::now(),
                )
            }
        } else {
            None
        };
        if let IaxPeerEvent::Audio(count) | IaxPeerEvent::Gap(count) = event {
            self.timed.cursor = self
                .timed
                .cursor
                .checked_add(count as u64)
                .ok_or(DialError::Jitter)?;
        }
        Ok(TimedPeerEvent {
            event,
            media_epoch: self.timed.epoch,
            source_start,
            born_ns,
            discontinuity: self.timed.pending,
        })
    }

    fn timed_media_expired(&self, now: Instant) -> bool {
        self.timed
            .history_receipt
            .is_some_and(|receipt| receipt.expired(now))
            || self.direct_pcm.span.expired(now)
            || self.pending_events.iter().any(|event| {
                event.is_media() && event.receipt().is_some_and(|receipt| receipt.expired(now))
            })
            || self
                .playout
                .as_ref()
                .is_some_and(|playout| playout.retained_expired(now))
    }

    pub(super) fn retire_timed_media(&mut self) -> Result<(), DialError> {
        // Mark failure first: a failed native reset must never publish more PCM.
        self.timed.failed = true;
        self.timed.epoch = self.timed.epoch.checked_add(1).ok_or(DialError::Jitter)?;
        self.timed.pending = true;
        self.timed.cursor = 0;
        self.timed.cutoff = Some(Instant::now());
        self.direct_pcm = super::PacketPcm::default();
        self.service.early_remaining = self
            .pending_events
            .iter()
            .take(usize::from(self.service.early_remaining))
            .filter(|event| !event.is_media())
            .count() as u8;
        self.pending_events.retain(|event| !event.is_media());
        self.service.selected = false;
        self.timed.last_span = Span::default();
        self.timed.history_qualified = None;
        self.timed.history_receipt = None;
        if let Some(playout) = &mut self.playout {
            playout.retire_media()?;
        }
        if let Some(codecs) = &mut self.codecs {
            codecs.decoder.reset().map_err(DialError::Provider)?;
        }
        self.timed.failed = false;
        Ok(())
    }

    pub(super) fn timed_deadline(&self) -> Option<Instant> {
        if !self.timed.enabled {
            return None;
        }
        self.direct_pcm
            .span
            .receipt
            .into_iter()
            .chain(
                self.pending_events
                    .iter()
                    .filter_map(super::PendingSource::receipt),
            )
            .map(|receipt| receipt.instant)
            .chain(self.timed.history_receipt.map(|receipt| receipt.instant))
            .chain(
                self.playout
                    .as_ref()
                    .and_then(|playout| playout.original_deadline()),
            )
            .min()
            .and_then(|instant| instant.checked_add(crate::source_time::MAXIMUM_AGE))
    }

    pub(super) fn receipt_before_timed_cutoff(
        &self,
        receipt: Option<crate::source_time::Receipt>,
    ) -> bool {
        self.timed.enabled
            && receipt.is_some_and(|receipt| {
                self.timed
                    .cutoff
                    .is_some_and(|cutoff| receipt.instant < cutoff)
            })
    }

    pub(super) fn accept_timed_receipt(&mut self) -> Result<bool, DialError> {
        if !self.timed.enabled {
            return Ok(true);
        }
        let qualified = self.incoming_receipt.is_some() && !self.timed.clock_revoked;
        if self
            .timed
            .history_qualified
            .is_some_and(|old| old != qualified)
        {
            self.retire_timed_media()?;
            self.timed.history_qualified = Some(qualified);
            return Ok(false);
        }
        self.timed.history_qualified = Some(qualified);
        let Some(receipt) = self.incoming_receipt else {
            return Ok(true);
        };
        if self.receipt_before_timed_cutoff(Some(receipt)) {
            return Ok(false);
        }
        if Span::new(Some(receipt)).expired(Instant::now()) {
            self.retire_timed_media()?;
            return Ok(false);
        }
        Ok(true)
    }
}
