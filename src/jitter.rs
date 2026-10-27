//! Client of the composed, codec-neutral jitter ABI. No jitter implementation lives here.

use std::{
    ffi::c_void,
    mem::size_of,
    ptr::{self, NonNull},
};

const CAPABILITY: [u8; 16] = *b"rptadv.jitter\0\0\0";
/// Maximum opaque datagram payload accepted by the composed jitter capability.
pub(crate) const MAX_PAYLOAD: usize = crate::ingress::MAX_DATAGRAM_SIZE - 4;
/// Source clock used by the negotiated ULAW media stream.
#[cfg(test)]
pub(crate) const CLOCK_RATE_HZ: u32 = 8000;
/// Smallest missing/insertion span emitted by the composed jitter capability.
#[cfg(test)]
pub(crate) const CONCEALMENT_SPAN: u32 = 80;

#[repr(C)]
#[derive(Clone, Copy)]
struct Config {
    struct_size: u32,
    abi_version: u32,
    clock_rate_hz: u32,
    minimum_delay: u32,
    initial_delay: u32,
    maximum_delay: u32,
    adjustment_step: u32,
    concealment_span: u32,
    maximum_packets: u32,
    maximum_payload_bytes: u32,
}

#[repr(C)]
struct Packet {
    struct_size: u32,
    timestamp: u64,
    span: u32,
    arrival_ns: u64,
    payload: *const u8,
    length: usize,
}

#[repr(C)]
#[derive(Default)]
struct RawDecision {
    struct_size: u32,
    kind: u32,
    timestamp: u64,
    span: u32,
    start_offset: i32,
    length: usize,
    deadline_ns: u64,
}

/// Owner-task diagnostics copied from the neutral capability.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct Observation {
    pub(crate) struct_size: u32,
    pub(crate) queued_packets: u32,
    pub(crate) delay: u32,
    pub(crate) buffered_span: u64,
    pub(crate) duplicate_drops: u64,
    pub(crate) late_drops: u64,
    pub(crate) full_drops: u64,
    pub(crate) missing_span: u64,
    pub(crate) insertion_span: u64,
    pub(crate) skipped_span: u64,
    pub(crate) limit_resets: u64,
    pub(crate) overload_drops: u64,
    pub(crate) overload_span: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Descriptor {
    struct_size: u32,
    abi_version: u32,
    capability: [u8; 16],
    create: Option<unsafe extern "C" fn(*const Config, *mut *mut c_void) -> i32>,
    destroy: Option<unsafe extern "C" fn(*mut c_void)>,
    reset: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    put: Option<unsafe extern "C" fn(*mut c_void, *const Packet) -> i32>,
    get: Option<
        unsafe extern "C" fn(*mut c_void, u64, u32, *mut u8, usize, *mut RawDecision) -> i32,
    >,
    advance: Option<unsafe extern "C" fn(*mut c_void, u64, u32) -> i32>,
    observe: Option<unsafe extern "C" fn(*const c_void, *mut Observation) -> i32>,
}

/// Invalid capability contract or an unsuccessful capability operation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    InvalidDescriptor,
    OperationFailed,
}

/// Admission outcome; rejected packets are already counted by the capability.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    Accepted,
    Duplicate,
    Late,
    Full,
}

/// Packet delivery, media loss, delay insertion, or a future playout deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Packet,
    Missing,
    Insertion,
    NotDue,
}

/// One codec-neutral playout decision; spans and signed offsets are 8kHz ticks.
#[derive(Debug)]
pub(crate) struct Decision {
    pub(crate) kind: Kind,
    pub(crate) timestamp: u64,
    pub(crate) span: u32,
    pub(crate) start_offset: i32,
    pub(crate) length: usize,
    pub(crate) deadline_ns: u64,
}

/// One exclusive handler's jitter context; composition retains the descriptor's DSO.
pub(crate) struct Jitter {
    api: Descriptor,
    context: NonNull<c_void>,
}

// The capability contract permits thread migration and forbids simultaneous calls.
// Jitter is Send, not Sync: its sole owning async task may move among runtime workers.
unsafe impl Send for Jitter {}

impl Jitter {
    /// Validate a readable descriptor and create the approved 160/180/500ms context.
    ///
    /// # Safety
    /// `descriptor` must be readable for its declared size, and its implementing
    /// DSO must remain loaded until this context is dropped. Functions must obey ABI1.
    #[cfg(test)]
    pub(crate) unsafe fn new(descriptor: *const c_void) -> Result<Self, Error> {
        unsafe { Self::new_at_rate(descriptor, CLOCK_RATE_HZ, CONCEALMENT_SPAN) }
    }
    /// Compose the same millisecond delay policy at the selected source clock.
    /// # Safety
    /// The descriptor must be readable for its declared size and its DSO must
    /// remain loaded until this exclusive context is destroyed.
    pub(crate) unsafe fn new_at_rate(
        descriptor: *const c_void,
        rate: u32,
        loss_unit: u32,
    ) -> Result<Self, Error> {
        if !matches!(rate, 8000 | 16000 | 48000) || loss_unit == 0 || loss_unit > rate / 2 {
            return Err(Error::InvalidDescriptor);
        }
        if descriptor.is_null() {
            return Err(Error::InvalidDescriptor);
        }
        // Read only the fixed prefix until the provider proves the full table exists.
        let prefix = unsafe { ptr::read_unaligned(descriptor.cast::<[u32; 2]>()) };
        if prefix[0] < size_of::<Descriptor>() as u32 || prefix[1] != 1 {
            return Err(Error::InvalidDescriptor);
        }
        let api = unsafe { ptr::read_unaligned(descriptor.cast::<Descriptor>()) };
        if api.capability != CAPABILITY
            || ![
                api.create.is_some(),
                api.destroy.is_some(),
                api.reset.is_some(),
                api.put.is_some(),
                api.get.is_some(),
                api.advance.is_some(),
                api.observe.is_some(),
            ]
            .into_iter()
            .all(|present| present)
        {
            return Err(Error::InvalidDescriptor);
        }
        let options = Config {
            struct_size: size_of::<Config>() as u32,
            abi_version: 1,
            clock_rate_hz: rate,
            minimum_delay: rate * 160 / 1000,
            initial_delay: rate * 180 / 1000,
            maximum_delay: rate / 2,
            adjustment_step: rate / 100,
            concealment_span: loss_unit,
            maximum_packets: 64,
            maximum_payload_bytes: MAX_PAYLOAD as u32,
        };
        let mut context = ptr::null_mut();
        if unsafe { api.create.unwrap()(&options, &mut context) } != 0 {
            return Err(Error::OperationFailed);
        }
        Ok(Self {
            api,
            context: NonNull::new(context).ok_or(Error::OperationFailed)?,
        })
    }

    /// Start a new timestamp/receive epoch, discarding old buffered media.
    pub(crate) fn reset(&mut self) -> Result<(), Error> {
        status(unsafe { self.api.reset.unwrap()(self.context.as_ptr()) })
    }

    /// Copy an encoded packet with its original receive timestamp, not handler time.
    pub(crate) fn put(
        &mut self,
        timestamp: u64,
        span: u32,
        arrival_ns: u64,
        payload: &[u8],
    ) -> Result<Admission, Error> {
        let packet = Packet {
            struct_size: size_of::<Packet>() as u32,
            timestamp,
            span,
            arrival_ns,
            payload: payload.as_ptr(),
            length: payload.len(),
        };
        match unsafe { self.api.put.unwrap()(self.context.as_ptr(), &packet) } {
            0 => Ok(Admission::Accepted),
            1 => Ok(Admission::Duplicate),
            2 => Ok(Admission::Late),
            3 => Ok(Admission::Full),
            _ => Err(Error::OperationFailed),
        }
    }

    /// Fetch a due decision; honor actual span/offset, including short missing spans.
    pub(crate) fn get(
        &mut self,
        now_ns: u64,
        desired_span: u32,
        payload: &mut [u8],
    ) -> Result<Decision, Error> {
        let mut result = RawDecision {
            struct_size: size_of::<RawDecision>() as u32,
            ..RawDecision::default()
        };
        status(unsafe {
            self.api.get.unwrap()(
                self.context.as_ptr(),
                now_ns,
                desired_span,
                payload.as_mut_ptr(),
                payload.len(),
                &mut result,
            )
        })?;
        let kind = match result.kind {
            0 => Kind::Packet,
            1 => Kind::Missing,
            2 => Kind::Insertion,
            3 => Kind::NotDue,
            _ => return Err(Error::OperationFailed),
        };
        if result.struct_size < size_of::<RawDecision>() as u32
            || result.length > payload.len()
            || (kind != Kind::Packet && result.length != 0)
            || (kind != Kind::NotDue
                && (result.span == 0
                    || i64::from(result.span) + i64::from(result.start_offset) <= 0))
        {
            return Err(Error::OperationFailed);
        }
        Ok(Decision {
            kind,
            timestamp: result.timestamp,
            span: result.span,
            start_offset: result.start_offset,
            length: result.length,
            deadline_ns: result.deadline_ns,
        })
    }

    /// Commit one decision. Pass zero when the whole output was published to the ring.
    pub(crate) fn advance(&mut self, now_ns: u64, retained_span: u32) -> Result<(), Error> {
        status(unsafe { self.api.advance.unwrap()(self.context.as_ptr(), now_ns, retained_span) })
    }

    /// Read diagnostics on the owning handler, never on an audio callback.
    pub(crate) fn observe(&self) -> Result<Observation, Error> {
        let mut result = Observation {
            struct_size: size_of::<Observation>() as u32,
            ..Observation::default()
        };
        status(unsafe { self.api.observe.unwrap()(self.context.as_ptr(), &mut result) })?;
        if result.struct_size < size_of::<Observation>() as u32 {
            return Err(Error::OperationFailed);
        }
        Ok(result)
    }
}

impl Drop for Jitter {
    fn drop(&mut self) {
        unsafe { self.api.destroy.unwrap()(self.context.as_ptr()) };
    }
}

fn status(value: i32) -> Result<(), Error> {
    if value == 0 {
        Ok(())
    } else {
        Err(Error::OperationFailed)
    }
}

#[cfg(test)]
#[path = "jitter_fixture.rs"]
pub(crate) mod fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct State {
        config: Config,
        destroyed: Arc<AtomicUsize>,
        puts: usize,
        admission: i32,
        kind: u32,
        decision: Option<RawDecision>,
    }

    unsafe extern "C" fn create(config: *const Config, context: *mut *mut c_void) -> i32 {
        let config = unsafe { &*config };
        unsafe {
            *context = Box::into_raw(Box::new(State {
                config: *config,
                destroyed: Arc::new(AtomicUsize::new(0)),
                puts: 0,
                admission: 0,
                kind: 0,
                decision: None,
            }))
            .cast()
        };
        0
    }
    unsafe extern "C" fn destroy(context: *mut c_void) {
        let state = unsafe { Box::from_raw(context.cast::<State>()) };
        state.destroyed.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn reset(_: *mut c_void) -> i32 {
        0
    }
    unsafe extern "C" fn put(context: *mut c_void, packet: *const Packet) -> i32 {
        let packet = unsafe { &*packet };
        assert_eq!(
            (
                packet.timestamp,
                packet.span,
                packet.arrival_ns,
                packet.length
            ),
            (1000, 160, 20_000_000, 2)
        );
        assert_eq!(
            unsafe { std::slice::from_raw_parts(packet.payload, packet.length) },
            [1, 2]
        );
        unsafe { (*context.cast::<State>()).puts += 1 };
        unsafe { (*context.cast::<State>()).admission }
    }
    unsafe extern "C" fn get(
        context: *mut c_void,
        now: u64,
        desired: u32,
        payload: *mut u8,
        capacity: usize,
        result: *mut RawDecision,
    ) -> i32 {
        assert_eq!((now, desired, capacity), (80_000_000, 160, MAX_PAYLOAD));
        unsafe {
            *payload = 9;
            let state = &mut *context.cast::<State>();
            let kind = state.kind;
            *result = state.decision.take().unwrap_or(RawDecision {
                struct_size: size_of::<RawDecision>() as u32,
                kind,
                timestamp: 1000,
                span: 160,
                start_offset: -40,
                length: usize::from(kind == 0),
                deadline_ns: 80_000_000,
            });
        }
        0
    }
    unsafe extern "C" fn advance(_: *mut c_void, now: u64, tail: u32) -> i32 {
        assert_eq!((now, tail), (80_000_000, 0));
        0
    }
    unsafe extern "C" fn observe(_: *const c_void, result: *mut Observation) -> i32 {
        unsafe { (*result).delay = 480 };
        0
    }

    fn descriptor() -> Descriptor {
        Descriptor {
            struct_size: size_of::<Descriptor>() as u32,
            abi_version: 1,
            capability: CAPABILITY,
            create: Some(create),
            destroy: Some(destroy),
            reset: Some(reset),
            put: Some(put),
            get: Some(get),
            advance: Some(advance),
            observe: Some(observe),
        }
    }

    #[test]
    fn composed_context_uses_approved_bounds_and_destroys_once() {
        let descriptor = descriptor();
        let mut jitter = unsafe { Jitter::new(ptr::from_ref(&descriptor).cast()) }.unwrap();
        let config = unsafe { &*jitter.context.as_ptr().cast::<State>() }.config;
        assert_eq!(
            (
                config.clock_rate_hz,
                config.minimum_delay,
                config.initial_delay,
                config.maximum_delay,
                config.adjustment_step,
                config.concealment_span,
                config.maximum_packets,
                config.maximum_payload_bytes
            ),
            (8000, 1280, 1440, 4000, 80, 80, 64, MAX_PAYLOAD as u32)
        );
        let destroyed = unsafe { &*jitter.context.as_ptr().cast::<State>() }
            .destroyed
            .clone();
        assert_eq!(
            jitter.put(1000, 160, 20_000_000, &[1, 2]),
            Ok(Admission::Accepted)
        );
        assert_eq!(unsafe { &*jitter.context.as_ptr().cast::<State>() }.puts, 1);
        let mut output = [0; MAX_PAYLOAD];
        let result = jitter.get(80_000_000, 160, &mut output).unwrap();
        assert_eq!(
            (
                result.kind,
                result.timestamp,
                result.span,
                result.start_offset,
                result.length,
                result.deadline_ns,
                output[0]
            ),
            (Kind::Packet, 1000, 160, -40, 1, 80_000_000, 9)
        );
        jitter.advance(80_000_000, 0).unwrap();
        assert_eq!(jitter.observe().unwrap().delay, 480);
        jitter.reset().unwrap();
        drop(jitter);
        assert_eq!(destroyed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn incompatible_or_incomplete_tables_fail_before_creating_context() {
        assert!(matches!(
            unsafe { Jitter::new(ptr::null()) },
            Err(Error::InvalidDescriptor)
        ));
        let prefix = [8u32, 1];
        assert!(matches!(
            unsafe { Jitter::new(prefix.as_ptr().cast()) },
            Err(Error::InvalidDescriptor)
        ));
        let mutations: &[fn(&mut Descriptor)] = &[
            |d| d.abi_version = 2,
            |d| d.capability[0] = b'x',
            |d| d.create = None,
            |d| d.destroy = None,
            |d| d.reset = None,
            |d| d.put = None,
            |d| d.get = None,
            |d| d.advance = None,
            |d| d.observe = None,
        ];
        for mutate in mutations {
            let mut api = descriptor();
            mutate(&mut api);
            assert!(matches!(
                unsafe { Jitter::new(ptr::from_ref(&api).cast()) },
                Err(Error::InvalidDescriptor)
            ));
        }
    }

    #[test]
    fn layouts_match_the_neutral_header_on_supported_64_bit_targets() {
        assert_eq!(
            (
                size_of::<Config>(),
                size_of::<Packet>(),
                size_of::<RawDecision>(),
                size_of::<Observation>(),
                size_of::<Descriptor>()
            ),
            (40, 48, 40, 96, 80)
        );
        assert_eq!(std::mem::offset_of!(Packet, arrival_ns), 24);
        assert_eq!(std::mem::offset_of!(RawDecision, deadline_ns), 32);
        assert_eq!(std::mem::offset_of!(Descriptor, create), 24);
        assert_eq!(std::mem::offset_of!(Observation, overload_drops), 80);
    }

    #[test]
    fn admission_and_decision_variants_are_translated_without_codec_work() {
        let api = descriptor();
        let mut jitter = unsafe { Jitter::new(ptr::from_ref(&api).cast()) }.unwrap();
        for (value, expected) in [
            (1, Ok(Admission::Duplicate)),
            (2, Ok(Admission::Late)),
            (3, Ok(Admission::Full)),
            (-1, Err(Error::OperationFailed)),
            (4, Err(Error::OperationFailed)),
        ] {
            unsafe { (*jitter.context.as_ptr().cast::<State>()).admission = value };
            assert_eq!(jitter.put(1000, 160, 20_000_000, &[1, 2]), expected);
        }
        let mut output = [0; MAX_PAYLOAD];
        for (value, expected) in [(1, Kind::Missing), (2, Kind::Insertion), (3, Kind::NotDue)] {
            unsafe { (*jitter.context.as_ptr().cast::<State>()).kind = value };
            assert_eq!(
                jitter.get(80_000_000, 160, &mut output).unwrap().kind,
                expected
            );
        }
        unsafe { (*jitter.context.as_ptr().cast::<State>()).kind = 4 };
        assert!(matches!(
            jitter.get(80_000_000, 160, &mut output),
            Err(Error::OperationFailed)
        ));
    }

    #[test]
    fn unsuccessful_or_null_creation_is_not_an_owned_context() {
        unsafe extern "C" fn failed(_: *const Config, _: *mut *mut c_void) -> i32 {
            -1
        }
        unsafe extern "C" fn null(_: *const Config, _: *mut *mut c_void) -> i32 {
            0
        }
        for callback in [failed as unsafe extern "C" fn(_, _) -> _, null] {
            let mut api = descriptor();
            api.create = Some(callback);
            assert!(matches!(
                unsafe { Jitter::new(ptr::from_ref(&api).cast()) },
                Err(Error::OperationFailed)
            ));
        }
    }

    #[test]
    fn malformed_decisions_are_rejected_before_exposing_payload_or_timing() {
        let api = descriptor();
        let mut jitter = unsafe { Jitter::new(ptr::from_ref(&api).cast()) }.unwrap();
        let corrupt: &[fn(&mut RawDecision)] = &[
            |decision| decision.struct_size -= 1,
            |decision| decision.length = MAX_PAYLOAD + 1,
            |decision| decision.kind = 1,
            |decision| decision.span = 0,
            |decision| decision.start_offset = -160,
            |decision| decision.start_offset = -161,
        ];
        for corrupt in corrupt {
            let mut decision = RawDecision {
                struct_size: size_of::<RawDecision>() as u32,
                kind: 0,
                span: 160,
                length: 1,
                ..RawDecision::default()
            };
            corrupt(&mut decision);
            unsafe { (*jitter.context.as_ptr().cast::<State>()).decision = Some(decision) };
            assert!(matches!(
                jitter.get(80_000_000, 160, &mut [0; MAX_PAYLOAD]),
                Err(Error::OperationFailed)
            ));
        }
    }

    #[test]
    fn failed_operations_and_truncated_observations_do_not_look_successful() {
        unsafe extern "C" fn failed(_: *mut c_void) -> i32 {
            -1
        }
        unsafe extern "C" fn truncated(_: *const c_void, output: *mut Observation) -> i32 {
            unsafe { (*output).struct_size -= 1 };
            0
        }
        let mut api = descriptor();
        api.reset = Some(failed);
        api.observe = Some(truncated);
        let mut jitter = unsafe { Jitter::new(ptr::from_ref(&api).cast()) }.unwrap();
        assert_eq!(jitter.reset(), Err(Error::OperationFailed));
        assert!(matches!(jitter.observe(), Err(Error::OperationFailed)));
    }
}
