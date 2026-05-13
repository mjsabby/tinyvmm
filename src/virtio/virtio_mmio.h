#pragma once

// virtio-mmio "modern" (Version=2) transport (spec §4.2).

#include "../common.h"
#include "../devices/mmio_bus.h"
#include "../whp/notification_port.h"
#include "../whp/partition.h"
#include "virtio.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace tinyvmm::virtio {

class MmioTransport {
public:
    MmioTransport(std::uint64_t base, Device& device);

    void Attach(devices::MmioBus& bus, std::string name);

    std::uint64_t reads() const noexcept { return reads_; }
    std::uint64_t writes() const noexcept { return writes_; }
    std::uint64_t notify_count() const noexcept { return notify_count_; }
    std::uint8_t status() const noexcept { return status_; }
    std::uint64_t base() const noexcept { return base_; }

    using IrqInjector = std::function<void()>;
    void SetIrqInjector(IrqInjector fn) { irq_inject_ = std::move(fn); }

    // Set bit(s) in InterruptStatus and fire the IRQ injector if any.
    void RaiseInterrupt(std::uint32_t status_bits);

    // M8: Install a doorbell on the QueueNotify register that fires when the
    // guest writes `qidx` (matching value + length=4). Returns the event
    // handle that worker threads can wait on; the transport keeps the
    // NotificationPort alive for its lifetime.
    //
    // Once a doorbell is installed for a given qidx, MMIO writes to
    // QueueNotify with that exact value will NOT take a VM exit -- the
    // event is signaled in the hypervisor instead.
    HANDLE InstallQueueDoorbell(whp::Partition& partition,
                                std::uint32_t qidx);

private:
    void HandleAccess(devices::MmioAccess& access);
    std::uint32_t Read32(std::uint32_t off);
    void Write32(std::uint32_t off, std::uint32_t value);
    static void ProgramQueueLow(std::uint64_t& gpa, std::uint32_t low);
    static void ProgramQueueHigh(std::uint64_t& gpa, std::uint32_t high);

    Device& dev_;
    std::uint64_t base_;
    std::string name_ = "virtio-mmio";

    std::uint32_t device_features_sel_ = 0;
    std::uint32_t driver_features_sel_ = 0;
    std::uint64_t driver_features_ = 0;

    std::uint32_t queue_sel_ = 0;
    std::uint8_t status_ = 0;
    std::uint32_t interrupt_status_ = 0;
    std::uint32_t config_generation_ = 0;

    std::uint64_t queue_desc_gpa_staged_ = 0;
    std::uint64_t queue_avail_gpa_staged_ = 0;
    std::uint64_t queue_used_gpa_staged_ = 0;

    std::uint64_t reads_ = 0;
    std::uint64_t writes_ = 0;
    std::uint64_t notify_count_ = 0;

    IrqInjector irq_inject_;

    std::vector<std::unique_ptr<whp::NotificationPort>> doorbells_;
};

}  // namespace tinyvmm::virtio

