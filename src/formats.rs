//! IAX format bits and Asterisk-compatible legacy/extended information elements.
use crate::{
    codec::providers::{CodecCatalog, ProfileId},
    information_elements::InformationElement,
};
use std::sync::Arc;

const FORMATS: [(ProfileId, u8); 16] = [
    (ProfileId::G723, 0),
    (ProfileId::GsmFr, 1),
    (ProfileId::G711Mu, 2),
    (ProfileId::G711A, 3),
    (ProfileId::G726Aal2, 4),
    (ProfileId::Dialogic, 5),
    (ProfileId::Pcm8, 6),
    (ProfileId::Lpc10, 7),
    (ProfileId::G729, 8),
    (ProfileId::Speex, 9),
    (ProfileId::Ilbc, 10),
    (ProfileId::G726, 11),
    (ProfileId::G722, 12),
    (ProfileId::Pcm16, 15),
    (ProfileId::Speex16, 33),
    (ProfileId::Opus, 34),
];

/// Protocol format bits, not neutral codec IDs. Deferred formats have no mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IaxFormat(
    /// IAX 64-bit audio format mask or a selected single bit.
    pub u64,
);
impl IaxFormat {
    /// Map a verified neutral profile only at the IAX protocol boundary.
    pub fn for_profile(profile: ProfileId) -> Self {
        Self(
            1u64 << FORMATS
                .iter()
                .find(|entry| entry.0 == profile)
                .expect("all neutral profiles mapped")
                .1,
        )
    }
    /// A single supported format, never an arbitrary multibit/unknown offer.
    pub fn profile(self) -> Option<ProfileId> {
        FORMATS
            .iter()
            .find(|entry| self.0 == 1u64 << entry.1)
            .map(|entry| entry.0)
    }
}

/// Peer format/capability, preserving Asterisk's exact nonzero precedence.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct FormatOffer {
    /// Preferred or accepted single format.
    pub format: u64,
    /// Advertised supported set, possibly absent/zero in NEW.
    pub capability: u64,
}
impl FormatOffer {
    /// Ignore malformed/unknown-version format IEs like Asterisk's parser.
    /// Version-0 extended values replace the current value; legacy only fills zero.
    pub fn parse(elements: &[InformationElement<'_>]) -> Self {
        let mut offer = Self::default();
        for element in elements {
            let target = match element.kind {
                8 | 55 => &mut offer.capability,
                9 | 56 => &mut offer.format,
                _ => continue,
            };
            match (element.kind, element.data) {
                (8 | 9, [a, b, c, d]) if *target == 0 => {
                    *target = u64::from(u32::from_be_bytes([*a, *b, *c, *d]))
                }
                (55 | 56, [0, a, b, c, d, e, f, g, h]) => {
                    *target = u64::from_be_bytes([*a, *b, *c, *d, *e, *f, *g, *h])
                }
                _ => {}
            }
        }
        offer
    }
    /// Incoming NEW falls back to FORMAT when CAPABILITY is absent/zero.
    pub fn supported(self) -> u64 {
        if self.capability == 0 {
            self.format
        } else {
            self.capability
        }
    }
}

/// Append both legacy and version-0 extended IEs. ACCEPT omits capability.
pub fn append_formats(payload: &mut Vec<u8>, format: u64, capability: Option<u64>) {
    fn append(payload: &mut Vec<u8>, legacy: u8, extended: u8, value: u64) {
        payload.extend_from_slice(&[legacy, 4]);
        payload.extend_from_slice(&(value as u32).to_be_bytes());
        payload.extend_from_slice(&[extended, 9, 0]);
        payload.extend_from_slice(&value.to_be_bytes());
    }
    append(payload, 9, 56, format);
    if let Some(mask) = capability {
        append(payload, 8, 55, mask);
    }
}

/// A composition/negotiation error never silently broadens an offer.
#[derive(Debug, PartialEq, Eq)]
pub enum NegotiationError {
    /// The composition has no usable selected profiles.
    Empty,
    /// A requested profile was not verified by its provider catalog.
    Missing(ProfileId),
    /// A profile appears twice in host preference order.
    Duplicate(ProfileId),
    /// Peer and host have no selected format in common.
    NoCommonFormat,
}
/// Host-ordered, bidirectional profile policy backed by retained dynamic providers.
pub struct FormatCatalog {
    codecs: Arc<CodecCatalog>,
    preference: Vec<ProfileId>,
}
impl FormatCatalog {
    /// Validate host policy off audio, retaining mu-law first when selected.
    pub fn new(codecs: Arc<CodecCatalog>, order: &[ProfileId]) -> Result<Self, NegotiationError> {
        if order.is_empty() {
            return Err(NegotiationError::Empty);
        }
        let mut preference = Vec::with_capacity(order.len());
        for &id in order {
            if codecs.profile(id).is_none() {
                return Err(NegotiationError::Missing(id));
            }
            if preference.contains(&id) {
                return Err(NegotiationError::Duplicate(id));
            }
            preference.push(id);
        }
        preference.sort_by_key(|id| *id != ProfileId::G711Mu);
        Ok(Self { codecs, preference })
    }
    /// Retained neutral provider catalog; codec state remains per connection.
    pub fn codecs(&self) -> &CodecCatalog {
        &self.codecs
    }
    /// Only explicitly selected verified profiles, without deferred bits.
    pub fn advertised_mask(&self) -> u64 {
        self.preference
            .iter()
            .fold(0, |mask, &id| mask | IaxFormat::for_profile(id).0)
    }
    /// Select in host preference order, identically for incoming/outgoing calls.
    pub fn select(&self, offered: u64) -> Result<ProfileId, NegotiationError> {
        self.preference
            .iter()
            .find(|&&id| offered & IaxFormat::for_profile(id).0 != 0)
            .copied()
            .ok_or(NegotiationError::NoCommonFormat)
    }
}
