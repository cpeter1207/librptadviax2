//! Explicit private-phone protocol service without advancing source delivery.
use super::{
    DialError, IaxPeer, IaxPeerEvent, MAX_EARLY_EVENTS, MAX_PACKET_SIZE, MAX_RELIABLE_WINDOW,
    PacketPcm, PeerEndpoint, PendingEvent,
};
use crate::{
    media::{VoiceFrame, VoiceFrameError, parse_voice_frame},
    protocol::parse_full_frame_packet,
    source_time::Receipt,
};
use std::{borrow::Cow, io, time::Instant};

/// Whether this serialized timed call may release another source item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceDelivery {
    /// Release one ordered source item through caller-owned buffers.
    Deliver,
    /// Service protocol and retirement only; source ownership stays unchanged.
    ServiceOnly,
}

#[derive(Default)]
pub(super) struct State {
    pub active: bool,
    pub terminal: bool,
    // Only a selected direct/jitter item, not unselected jitter packets.
    pub selected: bool,
    // Accepted early events precede any selected direct/jitter remainder.
    pub early_remaining: u8,
}

#[derive(Clone, Copy)]
pub(super) struct VoiceInput {
    pub timestamp: u32,
    pub offset: u16,
    pub length: u16,
    pub mini: bool,
}

pub(super) struct DeferredVoice {
    bytes: Box<[u8]>,
    arrived_at: Instant,
    receipt: Option<Receipt>,
    voice: VoiceInput,
}

pub(super) enum PendingSource {
    Ready(PendingEvent),
    Voice(DeferredVoice),
    RadioKey(u32),
    RadioUnkey,
}
impl PendingSource {
    pub fn receipt(&self) -> Option<Receipt> {
        match self {
            Self::Ready(event) => event.pcm.span.receipt,
            Self::Voice(voice) => voice.receipt,
            Self::RadioKey(_) | Self::RadioUnkey => None,
        }
    }

    pub fn is_media(&self) -> bool {
        match self {
            Self::Ready(event) => {
                matches!(event.event, IaxPeerEvent::Audio(_) | IaxPeerEvent::Gap(_))
            }
            Self::Voice(_) => true,
            Self::RadioKey(_) | Self::RadioUnkey => false,
        }
    }
}

pub(super) enum ReceivedEvent {
    Event(IaxPeerEvent),
    Voice(VoiceInput),
    RadioKey(u32),
    RadioUnkey,
}

struct Input<'a> {
    bytes: Cow<'a, [u8]>,
    address: std::net::SocketAddr,
    arrived_at: Instant,
    receipt: Option<Receipt>,
}

impl PeerEndpoint {
    fn receive_private<'a>(&mut self, scratch: &'a mut [u8]) -> io::Result<Option<Input<'a>>> {
        if let Self::Shared { ingress, .. } = self {
            let Some(packet) = ingress.try_pop() else {
                return if ingress.failed() {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "IAX receive task failed",
                    ))
                } else {
                    Ok(None)
                };
            };
            let address = packet.remote();
            let arrived_at = packet.arrived_at();
            let receipt = packet.receipt();
            return Ok(Some(Input {
                bytes: Cow::Owned(packet.into_payload().into_vec()),
                address,
                arrived_at,
                receipt,
            }));
        }
        self.receive(scratch).map(|received| {
            received.map(|(length, address, arrived_at, receipt)| Input {
                bytes: Cow::Borrowed(&scratch[..length]),
                address,
                arrived_at,
                receipt,
            })
        })
    }
}

impl IaxPeer {
    /// Atomically validate and latch the explicit private G.711/20 ms profile.
    pub(super) fn activate_private_source(&mut self) -> Result<(), DialError> {
        self.ensure_provider_live()?;
        if self.service.active {
            return Ok(());
        }
        // Only accepted early Ready entries exist before the first activation.
        if !matches!(
            crate::formats::IaxFormat(self.format).profile(),
            Some(
                crate::codec::providers::ProfileId::G711Mu
                    | crate::codec::providers::ProfileId::G711A
            )
        ) || self.codecs.is_none()
            || self.direct_pcm.samples.capacity() > 160
            || self.pending_events.iter().any(|event| {
                matches!(event, PendingSource::Ready(event)
                    if event.pcm.samples.capacity() > 160)
            })
            || self.playout.as_ref().is_some_and(|playout| {
                !playout.private_profile_ready(self.provider_ownership.is_some())
            })
        {
            return Err(DialError::InvalidOptions);
        }
        // Validation above cannot drain accepted input or partially opt in.
        self.pending_events.retain(|event| {
            !matches!(
                event,
                PendingSource::Ready(PendingEvent {
                    event: IaxPeerEvent::Text(_),
                    ..
                })
            )
        });
        self.service.active = true;
        self.service.early_remaining = self.pending_events.len() as u8;
        self.service.selected = self.selected_source_pending();
        Ok(())
    }

    fn selected_source_pending(&self) -> bool {
        self.direct_pcm.remaining() != 0
            || self
                .playout
                .as_ref()
                .is_some_and(crate::playout::Playout::blocks_transport)
    }

    /// Identify ownership before the normal session parser can consume sequence
    /// or emit ACK. Pure ACKs and duplicate source frames need no queue slot.
    fn source_storage(&self, bytes: &[u8]) -> Result<Option<bool>, DialError> {
        if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
            let frame = parse_full_frame_packet(bytes)
                .map_err(|_| DialError::Protocol(crate::session::CallSetupError::InvalidFrame))?;
            // Every constructed peer has linked, immutable call IDs. This
            // canonical full-frame check also covers the voice match below.
            self.setup
                .validate_call_ids(&frame.header)
                .map_err(DialError::Protocol)?;
            if frame.header.frame_type != 2 {
                let scalar = (frame.header.frame_type == 1
                    && !frame.header.subclass_is_log
                    && matches!(frame.header.subclass, b'0'..=b'9' | b'A'..=b'D' | b'*' | b'#'))
                    || (frame.header.frame_type == 4
                        && !frame.header.subclass_is_log
                        && matches!(frame.header.subclass, 12 | 13));
                return Ok((scalar
                    && frame.payload.is_empty()
                    && self.setup.admits_source(&frame.header, false))
                .then_some(false));
            }
        }
        let voice = parse_voice_frame(bytes, self.format).map_err(DialError::Voice)?;
        let (payload, new) = match voice {
            VoiceFrame::Full {
                header,
                format,
                payload,
            } if format == self.format => (
                payload,
                self.setup.admits_source(&header, self.playout.is_some()),
            ),
            VoiceFrame::Mini {
                header, payload, ..
            } if header.source_call_number == self.remote_call => (payload, true),
            _ => return Err(DialError::Voice(VoiceFrameError::NotVoiceFrame)),
        };
        self.validate_phone_payload(payload)?;
        Ok((new && !payload.is_empty()).then_some(true))
    }

    /// Bounded protocol admission, never source decode or jitter advancement.
    pub(super) fn service_private(&mut self) -> Result<(), DialError> {
        self.ensure_provider_live()?;
        self.retry_reliable_frames()?;
        self.flush_replies()?;
        for _ in 0..MAX_RELIABLE_WINDOW {
            let mut scratch = [0; MAX_PACKET_SIZE];
            let Some(mut input) = self
                .endpoint
                .receive_private(&mut scratch)
                .map_err(DialError::Network)?
            else {
                break;
            };
            if input.address != self.remote {
                continue;
            }
            let storage = self.source_storage(&input.bytes)?;
            let retired_voice =
                storage == Some(true) && self.receipt_before_timed_cutoff(input.receipt);
            if let Some(voice) = storage.filter(|_| !retired_voice) {
                if self.pending_events.len() == MAX_EARLY_EVENTS {
                    return Err(DialError::EarlyEventsFull);
                }
                self.pending_events
                    .try_reserve(1)
                    .map_err(|_| DialError::EarlyEventsFull)?;
                if voice {
                    if let Cow::Borrowed(bytes) = input.bytes {
                        // Dedicated sockets have only transient receive storage.
                        let mut owned = Vec::new();
                        owned
                            .try_reserve_exact(bytes.len())
                            .map_err(|_| DialError::EarlyEventsFull)?;
                        owned.extend_from_slice(bytes);
                        input.bytes = Cow::Owned(owned);
                    }
                }
            }
            self.incoming_receipt = input.receipt;
            match self.admit_event(&input.bytes, &mut [])? {
                ReceivedEvent::Event(IaxPeerEvent::None) => (),
                ReceivedEvent::Event(IaxPeerEvent::Hangup) => return Err(DialError::Hangup),
                ReceivedEvent::Event(event) => {
                    self.pending_events
                        .push_back(PendingSource::Ready(PendingEvent {
                            event,
                            pcm: PacketPcm::default(),
                            text: Vec::new(),
                        }))
                }
                ReceivedEvent::RadioKey(timestamp) => self
                    .pending_events
                    .push_back(PendingSource::RadioKey(timestamp)),
                ReceivedEvent::RadioUnkey => {
                    self.pending_events.push_back(PendingSource::RadioUnkey)
                }
                ReceivedEvent::Voice(voice) if voice.length != 0 && !retired_voice => {
                    self.pending_events
                        .push_back(PendingSource::Voice(DeferredVoice {
                            bytes: input.bytes.into_owned().into_boxed_slice(),
                            arrived_at: input.arrived_at,
                            receipt: input.receipt,
                            voice,
                        }));
                }
                ReceivedEvent::Voice(_) => (),
            }
        }
        Ok(())
    }

    fn poll_selected_source(&mut self, pcm: &mut [f32]) -> Result<IaxPeerEvent, DialError> {
        self.timed.last_span = self.direct_pcm.span.clone();
        let result = (|| match self.direct_pcm.render(pcm)? {
            Some(count) => Ok(IaxPeerEvent::Audio(count)),
            None => match &mut self.playout {
                Some(playout) => {
                    let event = playout.poll_with_codec(
                        Instant::now(),
                        pcm,
                        self.codecs.as_mut().map(|codecs| &mut codecs.decoder),
                    )?;
                    self.timed.last_span = playout.last_span().clone();
                    Ok(event)
                }
                None => Ok(IaxPeerEvent::None),
            },
        })();
        // A retryable render error can still select a packet. Preserve its
        // ownership barrier before returning the error to the caller.
        self.service.selected = self.selected_source_pending();
        result
    }

    pub(super) fn release_radio_key(&mut self, timestamp: u32) -> Result<IaxPeerEvent, DialError> {
        if let Some(playout) = &mut self.playout {
            if !playout.key(timestamp)? {
                return Ok(IaxPeerEvent::None);
            }
        }
        Ok(IaxPeerEvent::RadioKey)
    }

    pub(super) fn release_radio_unkey(&mut self) -> Result<IaxPeerEvent, DialError> {
        if let Some(playout) = &mut self.playout {
            playout.unkey();
            return Ok(IaxPeerEvent::None);
        }
        Ok(IaxPeerEvent::RadioUnkey)
    }

    pub(super) fn poll_private_source(
        &mut self,
        pcm: &mut [f32],
        text: &mut [u8],
    ) -> Result<IaxPeerEvent, DialError> {
        self.service_private()?;
        for _ in 0..MAX_EARLY_EVENTS {
            if self.service.early_remaining == 0 && self.service.selected {
                // Selected PCM or a deferred key owns this turn, including
                // NotDue. Retirement clears that ownership before this loop.
                return self.poll_selected_source(pcm);
            }
            if let Some(PendingSource::Ready(pending)) = self.pending_events.front_mut() {
                self.timed.last_span = pending.pcm.span.clone();
                if let Some(count) = pending.pcm.render(pcm)? {
                    if pending.pcm.remaining() == 0 {
                        self.pending_events.pop_front();
                        self.service.early_remaining =
                            self.service.early_remaining.saturating_sub(1);
                    }
                    return Ok(IaxPeerEvent::Audio(count));
                }
                if matches!(pending.event, IaxPeerEvent::Digit(_)) && text.is_empty() {
                    return Err(DialError::InvalidOptions);
                }
            }
            let Some(pending) = self.pending_events.pop_front() else {
                break;
            };
            self.service.early_remaining = self.service.early_remaining.saturating_sub(1);
            let result = match pending {
                PendingSource::Ready(pending) => Ok(pending.event),
                PendingSource::Voice(voice) => {
                    self.incoming_receipt = voice.receipt;
                    self.release_voice(&voice.bytes, voice.arrived_at, voice.voice, pcm)
                }
                PendingSource::RadioKey(timestamp) => self.release_radio_key(timestamp),
                PendingSource::RadioUnkey => self.release_radio_unkey(),
            };
            // release_voice may install direct PCM and then return OutputFull.
            // Latch its barrier even on that retryable error, before another
            // event can be released or another voice can overwrite the packet.
            self.service.selected = self.selected_source_pending();
            let event = result?;
            if event != IaxPeerEvent::None {
                return Ok(event);
            }
        }
        self.poll_selected_source(pcm)
    }
}

#[cfg(test)]
pub(super) fn retained_payload_bytes(peer: &IaxPeer) -> usize {
    peer.pending_events
        .iter()
        .map(|source| match source {
            PendingSource::Ready(event) => {
                event.pcm.samples.capacity() * std::mem::size_of::<f32>() + event.text.capacity()
            }
            PendingSource::Voice(voice) => voice.bytes.len(),
            PendingSource::RadioKey(_) | PendingSource::RadioUnkey => 0,
        })
        .sum()
}
