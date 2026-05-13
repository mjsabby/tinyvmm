#pragma once

// virtio-net backend abstraction (M15).
//
// A NetBackend is the data-plane peer of a virtio NetDevice. It pumps
// packets between the guest virtqueues and an external transport:
//
//   * LoopbackNetBackend   — TX echoes back as RX (test/CI fixture).
//   * XdpNetBackend        — XDP-for-Windows AF_XDP socket (real wire).
//   * SlirpNetBackend (M16) — libslirp user-mode TCP/IP stack.
//
// Ownership:
//   NetDevice owns the backend (via SetBackend / unique_ptr). The backend
//   is started by PciTransport once the device's BAR has been mapped by
//   the guest, and stopped on device destruction / explicit Stop().
//
// Threading contract:
//   * Start()/Stop() run on the host thread that constructed the device
//     (or, for Start, on whichever vcpu thread was first to write
//     COMMAND.MEM_SPACE — i.e. PciBus's config-write handler).
//   * OnQueueNotify() runs in vcpu-thread context (an MMIO notify write
//     just took an EPT fault; we are between WHvRunVirtualProcessor
//     returns). Backends MUST NOT block here — either short-circuit
//     drain immediately (LoopbackNetBackend) or kick a worker thread
//     (XdpNetBackend).
//   * Worker threads owned by the backend are free to call
//     PciTransport::RaiseQueueInterrupt at any time; that path is
//     designed to be invocable from any thread.

#include "../common.h"

#include <cstdint>

namespace tinyvmm::whp { class Partition; }

namespace tinyvmm::virtio {

class PciTransport;

class NetBackend {
public:
    virtual ~NetBackend() = default;

    virtual void Start(whp::Partition& partition, PciTransport& transport) = 0;

    virtual void Stop() = 0;

    virtual void OnQueueNotify(std::uint32_t qidx) { (void)qidx; }
};

}  // namespace tinyvmm::virtio
