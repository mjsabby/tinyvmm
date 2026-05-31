#include "tsi_sanity.h"

#include "tsi_handle.h"

// The hand-rolled C header for the Rust staticlib. Lives under
// `${TINYVMM_TCP_SANS_IO_DIR}/include`; that path is added to the
// `tinyvmm` target's include directories by CMakeLists.txt.
#include "tcp_sans_io.h"

#include <cstdio>
#include <cstdint>
#include <vector>

namespace tinyvmm::net {

std::uint32_t TsiAbiVersion() {
    return tcp_abi_version();
}

int TsiSelfTest() {
    const std::uint32_t got = TsiAbiVersion();
    const std::uint32_t want = kTsiExpectedAbiVersion;
    std::printf("[tsi-smoke] tcp_abi_version()  = %u (expected %u)\n", got, want);
    if (got != want) {
        std::fprintf(stderr,
                     "[tsi-smoke] FAIL: ABI version mismatch (got %u, want %u)\n",
                     got, want);
        return 2;
    }

    const std::size_t hsize = tcp_handle_size();
    const std::size_t halign = tcp_handle_align();
    const std::size_t mpkt = tcp_max_packet();
    std::printf("[tsi-smoke] tcp_handle_size()  = %zu bytes\n", hsize);
    std::printf("[tsi-smoke] tcp_handle_align() = %zu bytes\n", halign);
    std::printf("[tsi-smoke] tcp_max_packet()   = %zu bytes\n", mpkt);
    if (mpkt != 1500u) {
        std::fprintf(stderr,
                     "[tsi-smoke] FAIL: tcp_max_packet expected 1500, got %zu\n",
                     mpkt);
        return 3;
    }

    // Allocate properly-aligned storage for one TCB and exercise the
    // init -> listen -> abort -> extract -> destroy cycle.
    RawAlignedBuf raw = AllocateTcbStorage();
    if (!raw) {
        std::fprintf(stderr, "[tsi-smoke] FAIL: _aligned_malloc returned null\n");
        return 4;
    }

    // Synthetic endpoints: gateway 10.0.0.1:8080 <-> guest 10.0.0.2:35472.
    // tcp_init takes ports as numeric u16 (host byte order), NOT network
    // byte order. Burn this lesson in early -- the existing
    // UsernetBackend stores ports as _be and the M34.3+ shim will need
    // to ntohs at the boundary.
    const std::uint8_t local_ip[4]  = {10, 0, 0, 1};
    const std::uint8_t remote_ip[4] = {10, 0, 0, 2};
    const std::uint16_t local_port  = 8080;
    const std::uint16_t remote_port = 35472;
    const std::uint32_t iss = 0xCAFEBABEu;
    const std::uint64_t now_ms = 1u;

    int32_t rc = tcp_init(static_cast<TcpStreamHandle*>(raw.get()),
                          local_ip, local_port, remote_ip, remote_port,
                          iss, /*initial_rto_ms=*/1000u);
    if (rc != 0) {
        std::fprintf(stderr, "[tsi-smoke] FAIL: tcp_init rc=%d\n", rc);
        // raw deleter frees memory (no tcp_destroy on un-init'd TCB).
        return 5;
    }
    // Promote to TcbHandle so every subsequent error path is auto-cleaned.
    TcbHandle handle(static_cast<TcpStreamHandle*>(raw.release()));

    if (tcp_state(handle.get()) != TCP_STATE_CLOSED) {
        std::fprintf(stderr,
                     "[tsi-smoke] FAIL: fresh handle state=%u, expected %u (CLOSED)\n",
                     tcp_state(handle.get()), TCP_STATE_CLOSED);
        return 6;
    }

    rc = tcp_listen(handle.get(), now_ms);
    if (rc != 0) {
        std::fprintf(stderr, "[tsi-smoke] FAIL: tcp_listen rc=%d\n", rc);
        return 7;
    }
    if (tcp_state(handle.get()) != TCP_STATE_LISTEN) {
        std::fprintf(stderr,
                     "[tsi-smoke] FAIL: after listen state=%u, expected %u (LISTEN)\n",
                     tcp_state(handle.get()), TCP_STATE_LISTEN);
        return 8;
    }

    // Abort from LISTEN is a local-only transition (no peer-known
    // seq); no RST is queued. State should land at CLOSED.
    rc = tcp_abort(handle.get(), now_ms + 1);
    if (rc != 0) {
        std::fprintf(stderr, "[tsi-smoke] FAIL: tcp_abort(listen) rc=%d\n", rc);
        return 9;
    }
    if (tcp_state(handle.get()) != TCP_STATE_CLOSED) {
        std::fprintf(stderr,
                     "[tsi-smoke] FAIL: after abort state=%u, expected %u (CLOSED)\n",
                     tcp_state(handle.get()), TCP_STATE_CLOSED);
        return 10;
    }
    // No wire packet expected (LISTEN has no peer-known seq).
    std::vector<std::uint8_t> scratch(mpkt);
    std::size_t out_written = 0;
    rc = tcp_extract_packet(handle.get(), scratch.data(), scratch.size(), &out_written);
    if (rc != 0 || out_written != 0) {
        std::fprintf(stderr,
                     "[tsi-smoke] FAIL: extract after listen-abort: rc=%d wrote=%zu\n",
                     rc, out_written);
        return 11;
    }

    // handle deleter calls tcp_destroy + _aligned_free at scope exit.
    std::puts("[tsi-smoke] OK (abi + lifecycle + abort + destroy)");
    return 0;
}

}  // namespace tinyvmm::net
