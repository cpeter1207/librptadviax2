//! IAX source-clock policy over the shared dynamic jitter descriptor client.
pub(crate) use rptadv_jitter_client::{Admission, Decision, Error, Kind, Observation};
use std::{
    ffi::c_void,
    ops::{Deref, DerefMut},
};

/// IAX full-frame header leaves four bytes outside its encoded-payload budget.
pub(crate) const MAX_PAYLOAD: usize = crate::ingress::MAX_DATAGRAM_SIZE - 4;
#[cfg(test)]
pub(crate) const CLOCK_RATE_HZ: u32 = 8000;
#[cfg(test)]
pub(crate) const CONCEALMENT_SPAN: u32 = 80;

/// Exclusive source-clock state; the host retains the implementing dynamic library.
pub(crate) struct Jitter(rptadv_jitter_client::Jitter);
impl Jitter {
    /// Use the retained IAX defaults for existing 8 kHz test fixtures.
    /// # Safety
    /// The descriptor and implementing DSO must remain valid through this context's drop.
    #[cfg(test)]
    pub(crate) unsafe fn new(descriptor: *const c_void) -> Result<Self, Error> {
        unsafe { Self::new_at_rate(descriptor, CLOCK_RATE_HZ, CONCEALMENT_SPAN) }
    }

    /// Apply the unchanged 160/180/500 ms policy and IAX-specific payload budget.
    /// # Safety
    /// The descriptor and implementing DSO must remain valid through this context's drop.
    pub(crate) unsafe fn new_at_rate(
        descriptor: *const c_void,
        rate: u32,
        loss_unit: u32,
    ) -> Result<Self, Error> {
        unsafe {
            rptadv_jitter_client::Jitter::new_at_rate(descriptor, rate, loss_unit, MAX_PAYLOAD)
        }
        .map(Self)
    }
}
impl Deref for Jitter {
    type Target = rptadv_jitter_client::Jitter;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for Jitter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// Handwritten scripted-backend fixtures remain test-only, using the shared ABI records.
#[cfg(test)]
use rptadv_jitter_client::abi::{Config, Descriptor, Packet, RawDecision};
#[cfg(test)]
use std::{mem::size_of, ptr};
#[cfg(test)]
const CAPABILITY: [u8; 16] = *b"rptadv.jitter\0\0\0";
#[cfg(test)]
#[path = "jitter_fixture_tests.rs"]
pub(crate) mod fixture;
