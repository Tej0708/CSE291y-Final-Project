//! Plain baseline for `RingBuffer`: identical decoding and calls, no oracle.
#![no_main]

use arbitrary::Unstructured;
use kernel::collections::queue::Queue;
use kernel::collections::ring_buffer::RingBuffer;
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{ring_case, sink, RingOp, RING_MAX_LEN};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let (n, ops) = ring_case(&mut u);
    let mut storage = [0u8; RING_MAX_LEN];
    let mut rb = RingBuffer::new(&mut storage[..n]);
    let value = |v: Option<u8>| v.map_or(usize::MAX, usize::from);

    for op in ops {
        match op {
            RingOp::Enqueue(v) => sink(rb.enqueue(v) as usize),
            RingOp::Push(v) => sink(value(rb.push(v))),
            RingOp::Dequeue => sink(value(rb.dequeue())),
            RingOp::Empty => rb.empty(),
        }
        sink(rb.has_elements() as usize);
        sink(rb.is_full() as usize);
        sink(rb.len());
    }
});
