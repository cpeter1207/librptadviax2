//! Thread-local real allocation accounting, used only by native unit fixtures.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static COUNT: Cell<usize> = const { Cell::new(0) };
    static IDENTITY_COPIES: Cell<usize> = const { Cell::new(0) };
    static PHONE_PAYLOAD_COPIES: Cell<usize> = const { Cell::new(0) };
}
struct Allocator;
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACK.try_with(Cell::get).unwrap_or(false) {
            COUNT.with(|count| count.set(count.get() + 1));
            if matches!(layout.size(), 164 | 172) {
                PHONE_PAYLOAD_COPIES.with(|count| count.set(count.get() + 1));
            }
            if matches!(layout.size(), 43 | 47 | 53) {
                IDENTITY_COPIES.with(|count| count.set(count.get() + 1));
            }
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }
}
pub(crate) fn measure<T>(work: impl FnOnce() -> T) -> (T, usize, usize) {
    struct Stop;
    impl Drop for Stop {
        fn drop(&mut self) {
            TRACK.set(false);
        }
    }
    COUNT.set(0);
    IDENTITY_COPIES.set(0);
    PHONE_PAYLOAD_COPIES.set(0);
    TRACK.set(true);
    let stop = Stop;
    let result = work();
    drop(stop);
    (result, COUNT.get(), IDENTITY_COPIES.get())
}

/// Count exact phone datagram allocations after ingress already owns its bytes.
pub(crate) fn measure_phone_payload<T>(work: impl FnOnce() -> T) -> (T, usize, usize) {
    let (result, total, _) = measure(work);
    (result, total, PHONE_PAYLOAD_COPIES.get())
}
