#pragma once

// tcp-sans-io build-time / link-time / runtime sanity (M34.0, M34.2).
//
// The Rust crate `tcp-sans-io` (vendored in-place; path set via
// TINYVMM_TCP_SANS_IO_DIR CMake cache var, default C:/tcp-sans-io) is
// built as a `--release` staticlib by CMake on every build and linked
// into tinyvmm. The functions declared here form the minimum surface
// we exercise to:
//
//   1. Force the linker to keep at least one tcp-sans-io symbol so a
//      missing/misbuilt staticlib fails at link time, not at runtime.
//   2. Confirm at startup that the ABI version reported by the crate
//      matches the version we built against.
//   3. Round-trip the per-TCB lifecycle (init / listen / abort /
//      extract / destroy) so a header drift surfaces as a hard
//      runtime failure with a clear message.
//
// Anything richer than this lives in the actual TSI-backed TCP plumbing
// in src/virtio/net_usernet.cpp (M34.3+).

#include <cstdint>

namespace tinyvmm::net {

// ABI version the linked tcp-sans-io reports at runtime. Currently 2
// (M34.2 added tcp_abort + tcp_max_packet on top of v1).
std::uint32_t TsiAbiVersion();

// The ABI version this build was compiled against. Bump in lockstep
// with `tcp_abi_version()` in src/ffi.rs whenever the C surface
// changes shape.
constexpr std::uint32_t kTsiExpectedAbiVersion = 2u;

// End-to-end smoke: ABI version, sizing helpers, per-TCB
// init/listen/abort/destroy lifecycle. Returns 0 on PASS, non-zero
// (with a [tsi-smoke] FAIL line on stderr) on any failure. The exit
// code identifies the failure site for debugging.
int TsiSelfTest();

}  // namespace tinyvmm::net
