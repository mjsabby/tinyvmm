//! Global allocator shim that mirrors every Rust heap operation to ETW.
//!
//! Wrapping the system allocator lets an xperf/WPR capture observe *every*
//! dynamic allocation the VMM makes — and, with stack-walking enabled on the
//! provider, the call stack that triggered it. That is how we hunt down
//! avoidable allocations on the hot benchmark paths.
//!
//! ## Recursion safety
//! The emit path (`diag::etw::trace_*`) is entirely stack-resident: it builds a
//! fixed-size `Event` on the stack and hands it to `EventWriteTransfer`, never
//! calling back into Rust's `alloc`. So a logged allocation cannot re-enter this
//! hook. When no ETW session is listening, the `trace_*` helpers bail after a
//! single relaxed atomic load, so the allocator fast path stays cheap.
//!
//! ## Capture
//! ```text
//! xperf -start tinyheap -on {0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d}:0x800:5:'stack' -f heap.etl
//! ...run the workload...
//! xperf -stop tinyheap
//! ```
//! `0x800` is `etw::kw::HEAP`, `5` is `VERBOSE`, `:'stack'` requests a walked
//! call stack per event. A debug build (which ships a PDB) symbolicates the
//! stacks.

use std::alloc::{GlobalAlloc, Layout, System};

use crate::diag::etw;

/// `System` allocator wrapper that emits an ETW event per heap operation.
///
/// `alloc_zeroed` and `realloc` are overridden (rather than relying on the
/// `GlobalAlloc` default impls) so they delegate straight to `System` — keeping
/// `System`'s efficient `HeapAlloc(HEAP_ZERO_MEMORY)` / `HeapReAlloc` (in-place
/// growth) behaviour intact — while still logging.
pub struct TracingAllocator;

unsafe impl GlobalAlloc for TracingAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe {
            let ptr = System.alloc(layout);
            etw::trace_alloc(ptr, layout.size());
            ptr
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe {
            let ptr = System.alloc_zeroed(layout);
            etw::trace_alloc(ptr, layout.size());
            ptr
        }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe {
            let new_ptr = System.realloc(ptr, layout, new_size);
            etw::trace_realloc(ptr, new_ptr, new_size);
            new_ptr
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            etw::trace_free(ptr, layout.size());
            System.dealloc(ptr, layout);
        }
    }
}

#[global_allocator]
static GLOBAL: TracingAllocator = TracingAllocator;
