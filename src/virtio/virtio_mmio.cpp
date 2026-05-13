#include "virtio_mmio.h"

#include "virtqueue.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace tinyvmm::virtio {

namespace {

// Spec §4.2.2 register offsets. Modern (Version=2) layout only.
constexpr std::uint32_t kRegMagic = 0x000;
constexpr std::uint32_t kRegVersion = 0x004;
constexpr std::uint32_t kRegDeviceId = 0x008;
constexpr std::uint32_t kRegVendorId = 0x00C;
constexpr std::uint32_t kRegDeviceFeatures = 0x010;
constexpr std::uint32_t kRegDeviceFeaturesSel = 0x014;
constexpr std::uint32_t kRegDriverFeatures = 0x020;
constexpr std::uint32_t kRegDriverFeaturesSel = 0x024;
constexpr std::uint32_t kRegQueueSel = 0x030;
constexpr std::uint32_t kRegQueueNumMax = 0x034;
constexpr std::uint32_t kRegQueueNum = 0x038;
constexpr std::uint32_t kRegQueueReady = 0x044;
constexpr std::uint32_t kRegQueueNotify = 0x050;
constexpr std::uint32_t kRegInterruptStatus = 0x060;
constexpr std::uint32_t kRegInterruptAck = 0x064;
constexpr std::uint32_t kRegStatus = 0x070;
constexpr std::uint32_t kRegQueueDescLow = 0x080;
constexpr std::uint32_t kRegQueueDescHigh = 0x084;
constexpr std::uint32_t kRegQueueDriverLow = 0x090;   // == QueueAvailLow
constexpr std::uint32_t kRegQueueDriverHigh = 0x094;
constexpr std::uint32_t kRegQueueDeviceLow = 0x0A0;   // == QueueUsedLow
constexpr std::uint32_t kRegQueueDeviceHigh = 0x0A4;
constexpr std::uint32_t kRegConfigGeneration = 0x0FC;
constexpr std::uint32_t kRegConfigBase = 0x100;

}  // namespace

MmioTransport::MmioTransport(std::uint64_t base, Device& device)
    : dev_(device), base_(base) {}

void MmioTransport::Attach(devices::MmioBus& bus, std::string name) {
    name_ = std::move(name);
    bus.Register(base_, /*size=*/0x200, name_,
                 [this](devices::MmioAccess& a) { HandleAccess(a); });
}

void MmioTransport::RaiseInterrupt(std::uint32_t status_bits) {
    interrupt_status_ |= status_bits;
    if (irq_inject_) irq_inject_();
}

HANDLE MmioTransport::InstallQueueDoorbell(whp::Partition& partition,
                                           std::uint32_t qidx) {
    // Match a 4-byte write of `qidx` to base+0x50 (kRegQueueNotify).
    auto port = whp::NotificationPort::CreateMmioDoorbell(
        partition,
        /*gpa=*/base_ + 0x050,
        /*value=*/qidx,
        /*length=*/4);
    HANDLE evt = port->event();
    doorbells_.push_back(std::move(port));
    return evt;
}

void MmioTransport::ProgramQueueLow(std::uint64_t& gpa, std::uint32_t low) {
    gpa = (gpa & 0xFFFFFFFF00000000ULL) | low;
}
void MmioTransport::ProgramQueueHigh(std::uint64_t& gpa, std::uint32_t high) {
    gpa = (gpa & 0x00000000FFFFFFFFULL) |
          (static_cast<std::uint64_t>(high) << 32);
}

std::uint32_t MmioTransport::Read32(std::uint32_t off) {
    if (off >= kRegConfigBase) {
        return dev_.ReadConfig(off - kRegConfigBase, 4);
    }
    switch (off) {
        case kRegMagic: return kMagicValue;
        case kRegVersion: return kVersionModern;
        case kRegDeviceId: return dev_.DeviceId();
        case kRegVendorId: return kVendorId;
        case kRegDeviceFeatures: {
            std::uint64_t f = dev_.DeviceFeatures();
            return (device_features_sel_ == 0)
                       ? static_cast<std::uint32_t>(f & 0xFFFFFFFF)
                       : static_cast<std::uint32_t>(f >> 32);
        }
        case kRegQueueNumMax: return dev_.QueueMax(queue_sel_);
        case kRegQueueReady: {
            Virtqueue* q = dev_.GetQueue(queue_sel_);
            return (q && q->ready()) ? 1u : 0u;
        }
        case kRegInterruptStatus: return interrupt_status_;
        case kRegStatus: return status_;
        case kRegConfigGeneration: return config_generation_;
        default: return 0;
    }
}

void MmioTransport::Write32(std::uint32_t off, std::uint32_t value) {
    if (off >= kRegConfigBase) {
        dev_.WriteConfig(off - kRegConfigBase, 4, value);
        config_generation_++;
        return;
    }
    switch (off) {
        case kRegDeviceFeaturesSel:
            device_features_sel_ = value; return;
        case kRegDriverFeaturesSel:
            driver_features_sel_ = value; return;
        case kRegDriverFeatures: {
            std::uint64_t mask = (driver_features_sel_ == 0)
                                     ? 0x00000000FFFFFFFFULL
                                     : 0xFFFFFFFF00000000ULL;
            std::uint64_t shifted = (driver_features_sel_ == 0)
                                        ? static_cast<std::uint64_t>(value)
                                        : (static_cast<std::uint64_t>(value) << 32);
            driver_features_ = (driver_features_ & ~mask) | shifted;
            return;
        }
        case kRegQueueSel:
            queue_sel_ = value;
            if (Virtqueue* q = dev_.GetQueue(queue_sel_)) {
                queue_desc_gpa_staged_ = q->desc_gpa();
                queue_avail_gpa_staged_ = q->avail_gpa();
                queue_used_gpa_staged_ = q->used_gpa();
            }
            return;
        case kRegQueueNum:
            if (Virtqueue* q = dev_.GetQueue(queue_sel_)) {
                std::uint32_t max = dev_.QueueMax(queue_sel_);
                if (value <= max) q->SetSize(value);
            }
            return;
        case kRegQueueReady:
            if (Virtqueue* q = dev_.GetQueue(queue_sel_)) {
                q->SetDescGpa(queue_desc_gpa_staged_);
                q->SetAvailGpa(queue_avail_gpa_staged_);
                q->SetUsedGpa(queue_used_gpa_staged_);
                q->SetEventIdxEnabled(
                    (driver_features_ & kFeatureRingEventIdx) != 0);
                q->SetReady(value != 0);
            }
            return;
        case kRegQueueNotify:
            notify_count_++;
            dev_.NotifyQueue(value);
            return;
        case kRegInterruptAck:
            interrupt_status_ &= ~value; return;
        case kRegStatus: {
            std::uint8_t new_status = static_cast<std::uint8_t>(value & 0xFF);
            if (new_status == 0) {
                status_ = 0;
                interrupt_status_ = 0;
                queue_sel_ = 0;
                device_features_sel_ = 0;
                driver_features_sel_ = 0;
                driver_features_ = 0;
                queue_desc_gpa_staged_ = 0;
                queue_avail_gpa_staged_ = 0;
                queue_used_gpa_staged_ = 0;
                for (std::uint32_t i = 0; i < dev_.QueueCount(); ++i) {
                    if (Virtqueue* q = dev_.GetQueue(i)) q->Reset();
                }
                dev_.Reset();
                return;
            }
            std::uint8_t prev = status_;
            std::uint8_t adding = new_status & ~prev;
            if (adding & kStatusFeaturesOk) {
                if (!dev_.SetDriverFeatures(driver_features_)) {
                    new_status &= ~kStatusFeaturesOk;
                    new_status |= kStatusNeedsReset;
                }
            }
            status_ = new_status;
            if (adding & kStatusDriverOk) {
                dev_.DriverOk();
            }
            return;
        }
        case kRegQueueDescLow:    ProgramQueueLow(queue_desc_gpa_staged_, value);  return;
        case kRegQueueDescHigh:   ProgramQueueHigh(queue_desc_gpa_staged_, value); return;
        case kRegQueueDriverLow:  ProgramQueueLow(queue_avail_gpa_staged_, value); return;
        case kRegQueueDriverHigh: ProgramQueueHigh(queue_avail_gpa_staged_, value);return;
        case kRegQueueDeviceLow:  ProgramQueueLow(queue_used_gpa_staged_, value);  return;
        case kRegQueueDeviceHigh: ProgramQueueHigh(queue_used_gpa_staged_, value); return;
        default:
            return;
    }
}

void MmioTransport::HandleAccess(devices::MmioAccess& access) {
    std::uint32_t off = static_cast<std::uint32_t>(access.gpa - base_);

    if (access.is_write) {
        writes_++;
        std::uint32_t v = 0;
        std::memcpy(&v, access.data,
                    std::min<std::size_t>(access.access_size, 4));
        Write32(off & ~3u, v);
        return;
    }

    reads_++;
    std::uint32_t v = Read32(off & ~3u);
    std::uint32_t shift = (off & 3u) * 8;
    v >>= shift;
    std::memset(access.data, 0, sizeof(access.data));
    std::memcpy(access.data, &v,
                std::min<std::size_t>(access.access_size, 4));
}

}  // namespace tinyvmm::virtio
