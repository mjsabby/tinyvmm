// SPDX-License-Identifier: MIT
//
// tinyvmm -- RAII helpers for tcp-sans-io's in-place TCB allocation.
//
// `tcp-sans-io` exposes a runtime-queried (size, align) for its
// TcpStreamHandle and asks the caller to allocate with
// `_aligned_malloc(size, align)`. After `tcp_init` succeeds the
// caller is responsible for `tcp_destroy` + `_aligned_free` in
// that order. This header wraps both phases in unique_ptr deleters
// so error paths cannot leak.

#pragma once

#include "tcp_sans_io.h"

#include <malloc.h>

#include <memory>

namespace tinyvmm::net {

// Deleter for raw aligned memory (pre-tcp_init phase). Frees the
// allocation but does NOT call tcp_destroy -- the storage was
// allocated but never successfully `tcp_init`'d.
struct AlignedFree {
    void operator()(void* p) const noexcept {
        if (p) ::_aligned_free(p);
    }
};
using RawAlignedBuf = std::unique_ptr<void, AlignedFree>;

// Deleter for an initialized TCB. Calls tcp_destroy then _aligned_free
// in the order required by tcp-sans-io.
struct TcbDeleter {
    void operator()(TcpStreamHandle* h) const noexcept {
        if (!h) return;
        ::tcp_destroy(h);
        ::_aligned_free(h);
    }
};
using TcbHandle = std::unique_ptr<TcpStreamHandle, TcbDeleter>;

// Convenience: allocate raw aligned storage of the runtime-queried
// TCB size/alignment. Caller initializes via `tcp_init(raw.get(),
// ...)` and promotes ownership to TcbHandle on success.
inline RawAlignedBuf AllocateTcbStorage() {
    return RawAlignedBuf(
        ::_aligned_malloc(::tcp_handle_size(), ::tcp_handle_align()));
}

}  // namespace tinyvmm::net
