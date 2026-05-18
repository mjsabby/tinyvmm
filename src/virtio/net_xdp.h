#pragma once

// XdpNetBackend (M15).
//
// AF_XDP backend for virtio-net. Pumps frames between the guest virtqueues
// and the wire via an XDP-for-Windows XSK socket bound to a host NIC
// queue.
//
// **Zero-copy contract**: the XSK UMEM is registered against the entire
// guest RAM region (`mem.host_base()` ... `mem.host_base() + mem.size()`)
// with a chunk size of one page (4 KiB). A guest GPA G encodes as
//      XSK_BUFFER_ADDRESS { BaseAddress = G & ~0xFFFULL,
//                           Offset      = G &  0xFFF      }.
// The NIC DMAs directly into / out of guest memory. The only per-packet
// copy we incur is writing the 12-byte virtio_net_hdr into the
// guest-provided hdr-desc on RX (where we synthesize the header,
// because XDP doesn't supply one).
//
// Threading: a single worker thread waits on
//     [stop_event, tx_doorbell, rx_doorbell, xsk_async_event]
// and pumps both directions. The doorbells are installed via
// PciTransport::InstallQueueDoorbell once BAR0 is mapped.
//
// Failure modes:
//   * XDP-for-Windows service not installed → XskCreate returns
//     ERROR_FILE_NOT_FOUND; Start() flips ready()==false and logs.
//   * Native (zero-copy) bind unsupported on the NIC → if
//     `Options::require_native` is set, fail; otherwise fall back to
//     GENERIC mode (still works, but the kernel TCP/IP path may double
//     up on RX paths).

#include "common.h"
#include "whp/memory.h"
#include "net_backend.h"

#include <cstdint>
#include <memory>
#include <string>

namespace tinyvmm::virtio {

class NetDevice;

class XdpNetBackend : public NetBackend {
public:
    struct Options {
        std::uint32_t if_index   = 0;
        std::uint32_t queue_id   = 0;
        std::uint32_t ring_size  = 256;
        bool require_native      = false;   // XSK_BIND_FLAG_NATIVE (ZC)
        bool install_xdp_program = true;    // create the XDP program

        // When `debug` is true, the worker thread logs a stats line every
        // 2 seconds (iters, tx_pops/sub/done, rx_done, drop counters,
        // inflight). Off by default; enable via `--xdp-debug` to diagnose
        // a wedged data path.
        bool debug = false;
    };

    XdpNetBackend(NetDevice& net,
                  whp::GuestMemory& mem,
                  const Options& opts);
    ~XdpNetBackend() override;

    void Start(whp::Partition& partition, PciTransport& transport) override;
    void Stop() override;
    void OnQueueNotify(std::uint32_t qidx) override;

    bool ready() const noexcept;
    std::uint64_t tx_packets() const noexcept;
    std::uint64_t rx_packets() const noexcept;
    std::uint64_t tx_dropped() const noexcept;
    std::uint64_t rx_dropped() const noexcept;

    // The HRESULT from the last failed setup step, plus a short label
    // ("XskCreate", "UMEM_REG", "XskBind", ...). S_OK if Start succeeded.
    long last_setup_error() const noexcept;
    const std::string& last_setup_phase() const noexcept;

private:
    struct State;
    std::unique_ptr<State> state_;
};

}  // namespace tinyvmm::virtio
