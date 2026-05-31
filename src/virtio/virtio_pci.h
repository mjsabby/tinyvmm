#pragma once

// virtio-PCI "modern" transport (virtio spec §4.1).
//
// Builds on PciDevice (M10) + MsiX (M11) to expose any virtio::Device over a
// PCI Type-0 function with the standard virtio-pci-modern capability chain.
// The driver-visible state machine matches MmioTransport bit-for-bit; only
// the wire encoding (BAR-MMIO layout + cfg-space capability descriptors)
// differs.
//
// BAR0 layout (16 KiB, MMIO64 prefetchable):
//     0x0000  COMMON_CFG  (virtio_pci_common_cfg, 56 bytes used)
//     0x0040  ISR status  (1 byte, padded to 4)
//     0x1000  NOTIFY      (notify_off_multiplier=4 -> queue i at +i*4)
//     0x2000  DEVICE_CFG  (device-specific, up to 256 bytes)
//     0x3000  MSI-X TABLE
//     0x3800  MSI-X PBA
//
// Capability chain (in cfg space):
//     +0x40  virtio_pci_cap (COMMON_CFG)
//     +0x50  virtio_pci_notify_cap
//     +0x64  virtio_pci_cap (ISR_CFG)
//     +0x74  virtio_pci_cap (DEVICE_CFG)
//     +0x84  MSI-X cap (12 bytes)
//
// IRQ delivery:
//   * MSI-X is the only supported path. Each queue and the config-change
//     event has a 16-bit vector index field in COMMON_CFG (queue_msix_vector
//     / msix_config). A value of 0xFFFF means "no vector" -- such events are
//     latched in ISR but never delivered (we don't emulate INTx).
//   * Triggering goes through the MsiX helper, which honours MSI-X-Enable,
//     FunctionMask, and per-vector mask + PBA replay.

#include "common.h"
#include "devices/mmio_bus.h"
#include "pci/msix.h"
#include "pci/pci_device.h"
#include "whp/notification_port.h"
#include "whp/partition.h"
#include "virtio.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace tinyvmm::virtio {

class Virtqueue;

class PciTransport : public pci::PciDevice {
public:
    struct Options {
        // Device-id strategy. Virtio spec assigns device_id = 0x1040 + N for
        // transitional-modern devices (N = virtio device id; e.g. 1 = net,
        // 2 = blk). For unit-tests using virtio::kDeviceIdReserved+0xFE we
        // still use 0x1040 + that, which Linux just treats as "unknown".
        std::uint16_t vendor_id = 0x1AF4;       // Red Hat
        std::uint16_t subsys_vendor_id = 0x1AF4;
        std::uint16_t subsys_id = 0;            // virtio device id

        std::uint16_t num_msix_vectors = 4;
        std::uint8_t  pci_class = 0x02;         // 0x02 Network for net
        std::uint8_t  pci_subclass = 0x00;
    };

    PciTransport(Device& device,
                 const Options& opts,
                 devices::MmioBus& mmio_bus,
                 pci::MsiX::InjectFn inject);

    const char* name() const override { return name_.c_str(); }
    void set_name(std::string n) { name_ = std::move(n); }

    Device& device() noexcept { return dev_; }
    pci::MsiX& msix() noexcept { return msix_; }

    // Diagnostics.
    std::uint64_t reads()        const noexcept {
        return reads_.load(std::memory_order_relaxed);
    }
    std::uint64_t writes()       const noexcept {
        return writes_.load(std::memory_order_relaxed);
    }
    std::uint64_t notify_count() const noexcept {
        return notify_count_.load(std::memory_order_relaxed);
    }
    std::uint8_t  status()       const noexcept {
        std::lock_guard<std::mutex> lk(cfg_mu_);
        return status_;
    }
    std::uint32_t isr()          const noexcept {
        return isr_status_.load(std::memory_order_relaxed);
    }

    // ---- Device -> transport interrupt signals.
    // RaiseQueueInterrupt: indicates the device added to qidx's used ring.
    // If the queue has an MSI-X vector configured, fire it. Always sets ISR
    // bit 0 (queue interrupt) for software that reads ISR even with MSI-X.
    void RaiseQueueInterrupt(std::uint32_t qidx);

    // RaiseConfigChangeInterrupt: indicates device-config changed.
    void RaiseConfigChangeInterrupt();

    // M8 fast-path: install a partition-wide MMIO doorbell on the notify
    // address for queue `qidx`. Returns the event handle the worker thread
    // waits on. Matches on the 16-bit qidx value -- standard Linux
    // virtio-pci-modern writes that exact value.
    HANDLE InstallQueueDoorbell(whp::Partition& partition,
                                std::uint32_t qidx);

    // M15: invoked once when BAR0 is mapped (guest sets COMMAND.MEM_SPACE).
    // This is the right hook for "install partition doorbells + start
    // backend workers", because the notify-cfg GPA isn't known until
    // BAR is mapped. The transport guarantees `bar_mapped_ == true` and
    // bar_gpa_ is valid when the callback fires. Fires at most once per
    // map event; OnBarUnmapped does NOT call back (we just stop being
    // ready to inject).
    using OnBarMappedFn = std::function<void()>;
    void SetOnBarMappedCallback(OnBarMappedFn fn) {
        on_bar_mapped_cb_ = std::move(fn);
    }

    bool bar_mapped() const noexcept { return bar_mapped_; }
    std::uint64_t bar_gpa() const noexcept { return bar_gpa_; }

    // Constants exposed for tests.
    static constexpr std::uint32_t kBarSize           = 0x4000;
    static constexpr std::uint32_t kOffCommonCfg      = 0x0000;
    static constexpr std::uint32_t kLenCommonCfg      = 0x0040;
    static constexpr std::uint32_t kOffIsr            = 0x0040;
    static constexpr std::uint32_t kLenIsr            = 0x0004;
    static constexpr std::uint32_t kOffNotify         = 0x1000;
    static constexpr std::uint32_t kLenNotify         = 0x1000;
    static constexpr std::uint32_t kNotifyMultiplier  = 4;
    static constexpr std::uint32_t kOffDeviceCfg      = 0x2000;
    static constexpr std::uint32_t kLenDeviceCfg      = 0x0100;
    static constexpr std::uint32_t kOffMsixTable      = 0x3000;
    static constexpr std::uint32_t kOffMsixPba        = 0x3800;

    // ----- M33.4 save/restore -------------------------------------------
    //
    // Captures all per-instance transport state. The constructor-time
    // configuration (num_msix_vectors, device topology, etc.) is
    // reconstructed by the restore code re-running the constructor with
    // identical Options + Device. ApplyState fills in the runtime state
    // and, if `bar_mapped` was true at capture, re-registers the four
    // MMIO regions via the private InstallBarHandlers_ helper. It
    // deliberately does NOT invoke the user-supplied
    // on_bar_mapped_cb_() (which is the cold-boot path's hook to install
    // partition doorbells + start worker threads); restore-time devices
    // have no worker waiting on a doorbell so installing one would
    // swallow guest notify-MMIO writes silently.
    struct QueueState {
        std::uint16_t msix_vector = 0xFFFF;
        std::uint16_t enable      = 0;
        std::uint64_t desc        = 0;
        std::uint64_t driver      = 0;
        std::uint64_t device      = 0;
        std::uint16_t size        = 0;
    };
    struct State {
        std::uint32_t device_feature_select = 0;
        std::uint32_t driver_feature_select = 0;
        std::uint64_t driver_features       = 0;
        std::uint16_t msix_config           = 0xFFFF;
        std::uint8_t  status                = 0;
        std::uint8_t  config_generation     = 0;
        std::uint16_t queue_select          = 0;
        std::uint8_t  bar_mapped            = 0;
        std::uint64_t bar_gpa               = 0;
        std::uint32_t isr_status            = 0;
        std::vector<QueueState> queues;
    };

    // Encoded payload size: 40-byte fixed header + 32*num_queues.
    static constexpr std::size_t kEncodedHeaderSize = 40;
    static std::size_t EncodedSize(std::size_t num_queues) noexcept {
        return kEncodedHeaderSize + 32ull * num_queues;
    }

    State CaptureState() const;
    void  ApplyState(const State& s);

    static std::size_t EncodeState(const State& s,
                                   std::vector<std::uint8_t>& out);
    static State       DecodeState(std::span<const std::uint8_t> bytes);

protected:
    void OnBarMapped(int idx, std::uint64_t gpa,
                     std::uint32_t size) override;
    void OnBarUnmapped(int idx) override;

private:
    void HandleCommonCfg(devices::MmioAccess& access);
    void HandleIsr      (devices::MmioAccess& access);
    void HandleNotify   (devices::MmioAccess& access);
    void HandleDeviceCfg(devices::MmioAccess& access);

    std::uint32_t ReadCommonCfg32 (std::uint32_t off);
    void          WriteCommonCfg32(std::uint32_t off, std::uint32_t value);

    void ApplyStatusWrite(std::uint8_t new_status);

    // Registers the four BAR0 MMIO regions (COMMON_CFG, ISR, NOTIFY,
    // DEVICE_CFG) and calls msix_.Install(). Used by both the regular
    // OnBarMapped cold-boot path and PciTransport::ApplyState restore
    // path. Does NOT invoke on_bar_mapped_cb_ or install partition
    // doorbells — both of those are the cold-boot path's responsibility.
    // Caller must hold no PciTransport lock and must have already set
    // bar_gpa_ = gpa, bar_mapped_ = true.
    void InstallBarHandlers_(std::uint64_t gpa);

    Device& dev_;
    Options opts_;
    devices::MmioBus& mmio_bus_;
    pci::MsiX msix_;

    std::string name_ = "virtio-pci";
    std::uint64_t bar_gpa_ = 0;
    bool bar_mapped_ = false;

    // virtio_pci_common_cfg state.
    std::uint32_t device_feature_select_ = 0;
    std::uint32_t driver_feature_select_ = 0;
    std::uint64_t driver_features_       = 0;
    std::uint16_t msix_config_           = 0xFFFF;
    std::uint8_t  status_                = 0;
    std::uint8_t  config_generation_     = 0;
    std::uint16_t queue_select_          = 0;

    // Per-queue stub state. Public type lives in the State struct above so
    // CaptureState / ApplyState can round-trip it directly.
    std::vector<QueueState> queues_;

    // Atomic across N vCPU + worker threads. ISR is read-and-clear from a
    // single guest reader, and OR'd by RaiseQueueInterrupt /
    // RaiseConfigChangeInterrupt on worker threads.
    std::atomic<std::uint32_t> isr_status_{0};
    std::atomic<std::uint64_t> reads_{0};
    std::atomic<std::uint64_t> writes_{0};
    std::atomic<std::uint64_t> notify_count_{0};

    // Serializes COMMON_CFG state mutations + reads from RaiseQueueInterrupt /
    // RaiseConfigChangeInterrupt. Held briefly to snapshot a single field;
    // never held across calls into Device callbacks or msix_.Trigger() to
    // avoid deadlock (Device IRQ callbacks re-enter RaiseQueueInterrupt).
    mutable std::mutex cfg_mu_;

    std::vector<std::unique_ptr<whp::NotificationPort>> doorbells_;
    OnBarMappedFn on_bar_mapped_cb_;
};

}  // namespace tinyvmm::virtio
