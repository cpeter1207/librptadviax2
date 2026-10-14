//! Strict descriptor fixture: scripted backend decisions, never a second jitter algorithm.
use super::*;
use std::{
    cell::RefCell,
    collections::VecDeque,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct State {
    puts: Vec<(u64, u32, u64, Vec<u8>)>,
    admission: i32,
    decisions: VecDeque<(RawDecision, Vec<u8>)>,
    advances: Vec<(u64, u32)>,
    observation: Observation,
}
thread_local! { static NEXT: RefCell<Option<Arc<Mutex<State>>>> = const { RefCell::new(None) }; }
pub(crate) struct Fixture(Arc<Mutex<State>>);
impl Fixture {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(State::default())))
    }
    pub(crate) fn descriptor(&self) -> *const c_void {
        NEXT.with(|next| *next.borrow_mut() = Some(Arc::clone(&self.0)));
        ptr::from_ref(&DESCRIPTOR).cast()
    }
    pub(crate) fn packet(&self, deadline_ns: u64, timestamp: u64, payload: &[u8], offset: i32) {
        self.0.lock().unwrap().decisions.push_back((
            RawDecision {
                struct_size: size_of::<RawDecision>() as u32,
                kind: 0,
                timestamp,
                span: payload.len() as u32,
                start_offset: offset,
                length: payload.len(),
                deadline_ns,
            },
            payload.to_vec(),
        ));
    }
    pub(crate) fn puts(&self) -> Vec<(u64, u32, u64, Vec<u8>)> {
        self.0.lock().unwrap().puts.clone()
    }
    pub(crate) fn admission(&self, status: i32) {
        self.0.lock().unwrap().admission = status;
    }
    pub(crate) fn last_packet_span(&self, span: u32) {
        self.0.lock().unwrap().decisions.back_mut().unwrap().0.span = span;
    }
    pub(crate) fn gap(&self, deadline_ns: u64, timestamp: u64, span: u32, insertion: bool) {
        self.0.lock().unwrap().decisions.push_back((
            RawDecision {
                struct_size: size_of::<RawDecision>() as u32,
                kind: if insertion { 2 } else { 1 },
                timestamp,
                span,
                start_offset: 0,
                length: 0,
                deadline_ns,
            },
            Vec::new(),
        ));
    }
    pub(crate) fn advances(&self) -> Vec<(u64, u32)> {
        self.0.lock().unwrap().advances.clone()
    }
    pub(crate) fn observation(&self, observation: Observation) {
        self.0.lock().unwrap().observation = observation;
    }
}
unsafe extern "C" fn create(_: *const Config, output: *mut *mut c_void) -> i32 {
    let state = NEXT.with(|next| next.borrow_mut().take()).unwrap();
    unsafe { *output = Box::into_raw(Box::new(state)).cast() };
    0
}
unsafe extern "C" fn destroy(context: *mut c_void) {
    unsafe { drop(Box::from_raw(context.cast::<Arc<Mutex<State>>>())) };
}
unsafe extern "C" fn reset(context: *mut c_void) -> i32 {
    let mut state = unsafe { &*context.cast::<Arc<Mutex<State>>>() }
        .lock()
        .unwrap();
    state.decisions.clear();
    state.observation = Observation::default();
    0
}
unsafe extern "C" fn put(context: *mut c_void, packet: *const Packet) -> i32 {
    let packet = unsafe { &*packet };
    let payload = unsafe { std::slice::from_raw_parts(packet.payload, packet.length) }.to_vec();
    let mut state = unsafe { &*context.cast::<Arc<Mutex<State>>>() }
        .lock()
        .unwrap();
    state
        .puts
        .push((packet.timestamp, packet.span, packet.arrival_ns, payload));
    state.admission
}
unsafe extern "C" fn get(
    context: *mut c_void,
    now: u64,
    desired: u32,
    payload: *mut u8,
    capacity: usize,
    output: *mut RawDecision,
) -> i32 {
    assert_eq!(desired, 160);
    assert_eq!(capacity, MAX_PAYLOAD);
    let mut state = unsafe { &*context.cast::<Arc<Mutex<State>>>() }
        .lock()
        .unwrap();
    let output = unsafe { &mut *output };
    if state
        .decisions
        .front()
        .is_none_or(|(decision, _)| now < decision.deadline_ns)
    {
        *output = RawDecision {
            struct_size: size_of::<RawDecision>() as u32,
            kind: 3,
            deadline_ns: state
                .decisions
                .front()
                .map_or(0, |(decision, _)| decision.deadline_ns),
            ..RawDecision::default()
        };
    } else {
        let (decision, bytes) = state.decisions.pop_front().unwrap();
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), payload, bytes.len()) };
        *output = decision;
    }
    0
}
unsafe extern "C" fn advance(context: *mut c_void, now: u64, tail: u32) -> i32 {
    unsafe { &*context.cast::<Arc<Mutex<State>>>() }
        .lock()
        .unwrap()
        .advances
        .push((now, tail));
    0
}
unsafe extern "C" fn observe(context: *const c_void, output: *mut Observation) -> i32 {
    let mut observation = unsafe { &*context.cast::<Arc<Mutex<State>>>() }
        .lock()
        .unwrap()
        .observation;
    observation.struct_size = size_of::<Observation>() as u32;
    observation.delay = 480;
    unsafe { *output = observation };
    0
}
static DESCRIPTOR: Descriptor = Descriptor {
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
};
