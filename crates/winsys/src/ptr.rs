//! `SharedPtr<T>` — a raw pointer explicitly asserted safe to share across
//! threads, so the ONE `!Send`/`!Sync` field of a struct can be wrapped here
//! and the struct itself AUTO-derives `Send`/`Sync` (compiler-checked) instead
//! of carrying a blanket `unsafe impl`.
//!
//! Why this is the better pattern than `unsafe impl Send for BigStruct {}`:
//!   * The unsafe assertion is localized to exactly the field that needs it.
//!   * Every *other* field stays compiler-checked — if someone later adds an
//!     `Rc` or another genuinely thread-hostile field, the build breaks loudly
//!     instead of a blanket impl silently vouching for it.
//!
//! Use only when the pointee's cross-thread access is governed by an external
//! invariant (an OS-owned region like guest RAM, or serialized by a Mutex/the
//! single-owner handoff discipline), NOT by Rust's aliasing rules.

/// A `*mut T` asserted safe to send + share across threads. See module docs.
#[repr(transparent)]
pub struct SharedPtr<T>(pub *mut T);

// Manual Copy/Clone WITHOUT a `T: Copy` bound: a raw pointer is always Copy
// regardless of its pointee (the `#[derive]`d impls would wrongly require
// `T: Copy`, breaking e.g. `SharedPtr<c_void>`).
impl<T> Clone for SharedPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for SharedPtr<T> {}

// SAFETY: callers only wrap pointers whose pointee is thread-safe by an external
// invariant (OS-owned memory / serialized access). The wrapper carries no
// aliasing guarantee of its own; it just stops the raw pointer from infecting
// the containing struct's auto-derived Send/Sync.
unsafe impl<T> Send for SharedPtr<T> {}
unsafe impl<T> Sync for SharedPtr<T> {}

impl<T> SharedPtr<T> {
    #[inline]
    pub fn new(p: *mut T) -> Self {
        SharedPtr(p)
    }
    #[inline]
    pub fn get(self) -> *mut T {
        self.0
    }
    #[inline]
    pub fn is_null(self) -> bool {
        self.0.is_null()
    }
}
