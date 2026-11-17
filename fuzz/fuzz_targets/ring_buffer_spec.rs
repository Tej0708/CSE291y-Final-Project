//! Spec harness for `RingBuffer` (`new`, `enqueue`, `push`, `dequeue`, `empty`
//! plus the `has_elements` / `is_full` / `len` observers).
//! Flux specs (tock-flux/kernel/src/collections/ring_buffer.rs), with
//! full(rb) = hd == (tl + 1) % ring_len and empty(rb) = hd == tl:
//!   new:      -> RingBuffer[ring_len, 0, 0]
//!   enqueue:  full(old) => unchanged;  !full(old) => tl = next(tl)
//!   push:     full(old) => hd = next(hd), tl = next(tl);  !full(old) => tl = next(tl)
//!   dequeue:  empty(old) => unchanged;  !empty(old) => hd = next(hd)
//!   empty:    -> [ring_len, 0, 0]
//!   has_elements -> bool[!empty(rb)];  is_full -> bool[full(rb)];  len -> {r < ring_len}
//! `head`/`tail` are private, so the harness evolves ghost (hd, tl) by the
//! ensures clauses and checks the observers against it after every step.
//! Oracle:
//!   L2: observers agree with the ghost state; len < ring_len.
//!   L3: exact len; return values (enqueue success, push eviction, dequeued
//!       value) match a FIFO reference model. The spec leaves these unrefined.
#![no_main]

use arbitrary::Unstructured;
use kernel::collections::queue::Queue;
use kernel::collections::ring_buffer::RingBuffer;
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;
use ticktock_spec_fuzz::{check, ring_case, RingOp, RING_MAX_LEN};

struct Ghost {
    n: usize,
    hd: usize,
    tl: usize,
}

impl Ghost {
    fn next(&self, x: usize) -> usize {
        (x + 1) % self.n
    }
    fn empty(&self) -> bool {
        self.hd == self.tl
    }
    fn full(&self) -> bool {
        self.hd == self.next(self.tl)
    }
}

fn check_observers(rb: &RingBuffer<'_, u8>, g: &Ghost, model: &VecDeque<u8>) {
    let (has, full, len) = (rb.has_elements(), rb.is_full(), rb.len());
    check!(2, has == !g.empty(), "has_elements = {has}, ghost (hd={}, tl={}) empty = {}", g.hd, g.tl, g.empty());
    check!(2, full == g.full(), "is_full = {full}, ghost (hd={}, tl={}) full = {}", g.hd, g.tl, g.full());
    check!(2, len < g.n, "len = {len} >= ring_len = {}", g.n);
    check!(3, len == (g.tl + g.n - g.hd) % g.n, "len = {len}, ghost (hd={}, tl={}, n={})", g.hd, g.tl, g.n);
    check!(3, len == model.len(), "len = {len}, reference model holds {}", model.len());
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let (n, ops) = ring_case(&mut u);
    let mut storage = [0u8; RING_MAX_LEN];
    let mut rb = RingBuffer::new(&mut storage[..n]);
    let mut g = Ghost { n, hd: 0, tl: 0 };
    let mut model = VecDeque::new();
    check_observers(&rb, &g, &model);

    for op in ops {
        let (full, empty) = (g.full(), g.empty());
        match op {
            RingOp::Enqueue(v) => {
                let ok = rb.enqueue(v);
                if !full {
                    g.tl = g.next(g.tl);
                    model.push_back(v);
                }
                check!(3, ok == !full, "enqueue returned {ok} with full = {full}");
            }
            RingOp::Push(v) => {
                let evicted = rb.push(v);
                let expected = if full {
                    g.hd = g.next(g.hd);
                    model.pop_front()
                } else {
                    None
                };
                g.tl = g.next(g.tl);
                model.push_back(v);
                check!(3, evicted == expected, "push evicted {evicted:?}, expected {expected:?}");
            }
            RingOp::Dequeue => {
                let out = rb.dequeue();
                if !empty {
                    g.hd = g.next(g.hd);
                }
                let expected = model.pop_front();
                check!(3, out == expected, "dequeue returned {out:?}, expected {expected:?}");
            }
            RingOp::Empty => {
                rb.empty();
                g.hd = 0;
                g.tl = 0;
                model.clear();
            }
        }
        check_observers(&rb, &g, &model);
    }
});
