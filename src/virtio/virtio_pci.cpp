#include "virtio_pci.h"

#include "pci/pci.h"
#include "virtqueue.h"
#include "whp/snapshot_file.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace tinyvmm::virtio {

namespace {

// virtio-pci modern capability config types (spec §4.1.4).
constexpr std::uint8_t kVirtioPciCapCommonCfg = 1;
constexpr std::uint8_t kVirtioPciCapNotifyCfg = 2;
constexpr std::uint8_t kVirtioPciCapIsrCfg    = 3;
constexpr std::uint8_t kVirtioPciCapDeviceCfg = 4;
// We do not advertise PCI_CFG (5); modern Linux uses MMIO directly.

// virtio_pci_common_cfg field offsets (spec §4.1.4.3, 56 bytes total).
constexpr std::uint32_t kCcDeviceFeatureSelect = 0x00;
constexpr std::uint32_t kCcDeviceFeature       = 0x04;
constexpr std::uint32_t kCcDriverFeatureSelect = 0x08;
constexpr std::uint32_t kCcDriverFeature       = 0x0C;
constexpr std::uint32_t kCcMsixConfig          = 0x10;
constexpr std::uint32_t kCcNumQueues           = 0x12;
constexpr std::uint32_t kCcDeviceStatus        = 0x14;
constexpr std::uint32_t kCcConfigGeneration    = 0x15;
constexpr std::uint32_t kCcQueueSelect         = 0x16;
constexpr std::uint32_t kCcQueueSize           = 0x18;
constexpr std::uint32_t kCcQueueMsixVector     = 0x1A;
constexpr std::uint32_t kCcQueueEnable         = 0x1C;
constexpr std::uint32_t kCcQueueNotifyOff      = 0x1E;
constexpr std::uint32_t kCcQueueDesc           = 0x20;
constexpr std::uint32_t kCcQueueDriver         = 0x28;
constexpr std::uint32_t kCcQueueDevice         = 0x30;

// Our MMIO dispatcher works on 32-bit-aligned lanes and unpacks the
// sub-fields by hand. The static_asserts below pin the spec offsets so
// that if anyone "fixes" a constant or restructures the lanes, the
// build breaks instead of silently desynchronising from the virtio
// spec.
static_assert(kCcMsixConfig + 2 == kCcNumQueues,
              "num_queues must follow msix_config in the 0x10 lane");
static_assert(kCcDeviceStatus + 1 == kCcConfigGeneration,
              "config_generation must follow device_status");
static_assert(kCcDeviceStatus + 2 == kCcQueueSelect,
              "queue_select must sit at +2 in the 0x14 lane");
static_assert(kCcQueueSize + 2 == kCcQueueMsixVector,
              "queue_msix_vector must follow queue_size in the 0x18 lane");
static_assert(kCcQueueEnable + 2 == kCcQueueNotifyOff,
              "queue_notify_off must follow queue_enable in the 0x1C lane");

constexpr std::uint8_t kIsrQueueBit  = 1 << 0;
constexpr std::uint8_t kIsrConfigBit = 1 << 1;

// Append a virtio_pci_cap (16 bytes) or virtio_pci_notify_cap (20 bytes).
// Returns the cap header offset in cfg space. Notify caps are distinguished
// by passing `multiplier != 0`.
std::uint32_t AppendVirtioCap(pci::PciDevice& dev, std::uint8_t cfg_type,
                              std::uint8_t bar, std::uint32_t offset,
                              std::uint32_t length,
                              std::uint32_t multiplier = 0) {
    const std::uint8_t cap_len = static_cast<std::uint8_t>(
        multiplier ? 20 : 16);
    const std::uint32_t off = dev.AppendCapability(pci::kCapIdVendor,
                                                   /*payload=*/cap_len);
    std::uint8_t* p = dev.mut_cfg_ptr(off);
    // p[0]=cap_id, p[1]=cap_next already written by AppendCapability.
    p[2] = cap_len;
    p[3] = cfg_type;
    p[4] = bar;
    p[5] = 0;            // id (multi-instance)
    p[6] = 0; p[7] = 0;  // padding
    p[8]  = static_cast<std::uint8_t>(offset & 0xFF);
    p[9]  = static_cast<std::uint8_t>((offset >> 8)  & 0xFF);
    p[10] = static_cast<std::uint8_t>((offset >> 16) & 0xFF);
    p[11] = static_cast<std::uint8_t>((offset >> 24) & 0xFF);
    p[12] = static_cast<std::uint8_t>(length & 0xFF);
    p[13] = static_cast<std::uint8_t>((length >> 8)  & 0xFF);
    p[14] = static_cast<std::uint8_t>((length >> 16) & 0xFF);
    p[15] = static_cast<std::uint8_t>((length >> 24) & 0xFF);
    if (multiplier) {
        p[16] = static_cast<std::uint8_t>(multiplier & 0xFF);
        p[17] = static_cast<std::uint8_t>((multiplier >> 8)  & 0xFF);
        p[18] = static_cast<std::uint8_t>((multiplier >> 16) & 0xFF);
        p[19] = static_cast<std::uint8_t>((multiplier >> 24) & 0xFF);
    }
    return off;
}

}  // namespace

PciTransport::PciTransport(Device& device, const Options& opts,
                            devices::MmioBus& mmio_bus,
                            pci::MsiX::InjectFn inject)
    : dev_(device),
      opts_(opts),
      mmio_bus_(mmio_bus),
      msix_(opts.num_msix_vectors, std::move(inject)),
      queues_(device.QueueCount()) {
    if (opts_.num_msix_vectors == 0) {
        Fatal("virtio-pci: num_msix_vectors must be >= 1");
    }
    const std::uint16_t did = static_cast<std::uint16_t>(0x1040 + dev_.DeviceId());

    set_ids(opts_.vendor_id, did, opts_.subsys_vendor_id,
            opts_.subsys_id ? opts_.subsys_id
                            : static_cast<std::uint16_t>(dev_.DeviceId()));
    set_class(opts_.pci_class, opts_.pci_subclass);
    set_interrupt_pin(0);   // MSI-X only

    DeclareMmio64Bar(/*idx=*/0, /*size=*/kBarSize, /*prefetchable=*/true);

    // Capability chain in the order COMMON / NOTIFY / ISR / DEVICE / MSI-X.
    AppendVirtioCap(*this, kVirtioPciCapCommonCfg, 0, kOffCommonCfg,
                    kLenCommonCfg);
    AppendVirtioCap(*this, kVirtioPciCapNotifyCfg, 0, kOffNotify,
                    kLenNotify, kNotifyMultiplier);
    AppendVirtioCap(*this, kVirtioPciCapIsrCfg,   0, kOffIsr,   kLenIsr);
    AppendVirtioCap(*this, kVirtioPciCapDeviceCfg, 0, kOffDeviceCfg,
                    kLenDeviceCfg);
    msix_.AddCapability(*this, /*bar_idx=*/0,
                        /*table_offset=*/kOffMsixTable,
                        /*pba_offset=*/kOffMsixPba);
}

void PciTransport::OnBarMapped(int idx, std::uint64_t gpa,
                                std::uint32_t /*size*/) {
    if (idx != 0) return;
    bar_gpa_ = gpa;
    bar_mapped_ = true;
    InstallBarHandlers_(gpa);
    if (on_bar_mapped_cb_) on_bar_mapped_cb_();
}

void PciTransport::InstallBarHandlers_(std::uint64_t gpa) {
    // Registers the four BAR0 MMIO regions and the MSI-X table+PBA. Used
    // by both the cold-boot OnBarMapped path and the M33.4 restore path.
    // Does NOT install partition doorbells (restore-time devices have no
    // worker thread waiting on them) and does NOT invoke
    // on_bar_mapped_cb_.
    mmio_bus_.Register(gpa + kOffCommonCfg, kLenCommonCfg,
                       name_ + ":common",
                       [this](devices::MmioAccess& a) { HandleCommonCfg(a); });
    mmio_bus_.Register(gpa + kOffIsr, kLenIsr,
                       name_ + ":isr",
                       [this](devices::MmioAccess& a) { HandleIsr(a); });
    mmio_bus_.Register(gpa + kOffNotify, kLenNotify,
                       name_ + ":notify",
                       [this](devices::MmioAccess& a) { HandleNotify(a); });
    mmio_bus_.Register(gpa + kOffDeviceCfg, kLenDeviceCfg,
                       name_ + ":device-cfg",
                       [this](devices::MmioAccess& a) { HandleDeviceCfg(a); });
    msix_.Install(mmio_bus_, gpa);
}

void PciTransport::OnBarUnmapped(int idx) {
    if (idx != 0 || !bar_mapped_) return;
    mmio_bus_.Unregister(bar_gpa_ + kOffCommonCfg);
    mmio_bus_.Unregister(bar_gpa_ + kOffIsr);
    mmio_bus_.Unregister(bar_gpa_ + kOffNotify);
    mmio_bus_.Unregister(bar_gpa_ + kOffDeviceCfg);
    msix_.Uninstall(mmio_bus_);
    bar_mapped_ = false;
}

HANDLE PciTransport::InstallQueueDoorbell(whp::Partition& partition,
                                          std::uint32_t qidx) {
    if (!bar_mapped_) {
        Fatal("virtio-pci: InstallQueueDoorbell before BAR mapped");
    }
    // notify_off = qidx (we chose multiplier=4 and queue_notify_off = qidx).
    const std::uint64_t notify_gpa =
        bar_gpa_ + kOffNotify + (qidx * kNotifyMultiplier);
    auto port = whp::NotificationPort::CreateMmioDoorbell(
        partition, notify_gpa,
        /*value=*/qidx,
        /*length=*/2);
    HANDLE evt = port->event();
    doorbells_.push_back(std::move(port));
    return evt;
}

void PciTransport::RaiseQueueInterrupt(std::uint32_t qidx) {
    isr_status_.fetch_or(kIsrQueueBit, std::memory_order_relaxed);
    std::uint16_t v = 0xFFFF;
    {
        std::lock_guard<std::mutex> lk(cfg_mu_);
        if (qidx < queues_.size()) v = queues_[qidx].msix_vector;
    }
    if (v != 0xFFFF) msix_.Trigger(v);
}

void PciTransport::RaiseConfigChangeInterrupt() {
    isr_status_.fetch_or(kIsrConfigBit, std::memory_order_relaxed);
    std::uint16_t cfg_vec = 0xFFFF;
    {
        std::lock_guard<std::mutex> lk(cfg_mu_);
        ++config_generation_;
        cfg_vec = msix_config_;
    }
    if (cfg_vec != 0xFFFF) msix_.Trigger(cfg_vec);
}

// ---- COMMON_CFG handler. Driver accesses are well-formed: aligned reads /
// writes of natural-width fields (1, 2, 4, 8 bytes). Sub-dword reads/writes
// route through Read/Write of an aligned 32-bit chunk + shift/mask, mirroring
// the MMIO transport.
//
// Thread-safety: the common-cfg state machine is touched both by N concurrent
// vCPU threads (this handler) and by worker threads via
// `RaiseQueueInterrupt`/`RaiseConfigChangeInterrupt` which sample
// queue_msix_vector / msix_config under `cfg_mu_`. We take cfg_mu_ for the
// duration of one MMIO transaction (very short -- a couple of memory writes).
// The deadlock risk is `ApplyStatusWrite` -> device callbacks
// (`SetDriverFeatures`, `Reset`, `DriverOk`); none of those re-enter the
// transport (they only touch their own device state), so holding cfg_mu_
// across them is safe.
void PciTransport::HandleCommonCfg(devices::MmioAccess& access) {
    std::lock_guard<std::mutex> lk(cfg_mu_);
    const std::uint32_t off =
        static_cast<std::uint32_t>(access.gpa - (bar_gpa_ + kOffCommonCfg));

    if (access.is_write) {
        writes_.fetch_add(1, std::memory_order_relaxed);
        // Special-case 8-byte writes (the queue_desc/driver/device fields).
        if (access.access_size == 8 && (off & 0x7u) == 0) {
            std::uint64_t v = 0;
            std::memcpy(&v, access.data, 8);
            WriteCommonCfg32(off,
                             static_cast<std::uint32_t>(v & 0xFFFFFFFFu));
            WriteCommonCfg32(off + 4,
                             static_cast<std::uint32_t>(v >> 32));
            return;
        }
        std::uint32_t v = 0;
        std::memcpy(&v, access.data,
                    std::min<std::size_t>(access.access_size, 4));
        const std::uint32_t aligned = off & ~0x3u;
        const std::uint32_t shift   = (off & 0x3u) * 8;
        if (access.access_size < 4) {
            const std::uint32_t mask =
                (access.access_size == 1) ? 0xFFu :
                (access.access_size == 2) ? 0xFFFFu : 0xFFFFFFFFu;
            std::uint32_t cur = ReadCommonCfg32(aligned);
            cur &= ~(mask << shift);
            cur |= (v & mask) << shift;
            WriteCommonCfg32(aligned, cur);
        } else {
            WriteCommonCfg32(aligned, v);
        }
        return;
    }

    reads_.fetch_add(1, std::memory_order_relaxed);
    if (access.access_size == 8 && (off & 0x7u) == 0) {
        const std::uint64_t lo = ReadCommonCfg32(off);
        const std::uint64_t hi = ReadCommonCfg32(off + 4);
        const std::uint64_t v = lo | (hi << 32);
        std::memset(access.data, 0, sizeof(access.data));
        std::memcpy(access.data, &v, 8);
        return;
    }
    const std::uint32_t aligned = off & ~0x3u;
    const std::uint32_t shift   = (off & 0x3u) * 8;
    std::uint32_t v = ReadCommonCfg32(aligned);
    v >>= shift;
    std::memset(access.data, 0, sizeof(access.data));
    std::memcpy(access.data, &v,
                std::min<std::size_t>(access.access_size, 4));
}

std::uint32_t PciTransport::ReadCommonCfg32(std::uint32_t off) {
    switch (off) {
      case kCcDeviceFeatureSelect: return device_feature_select_;
      case kCcDeviceFeature: {
          const std::uint64_t f = dev_.DeviceFeatures();
          if (device_feature_select_ == 0)
              return static_cast<std::uint32_t>(f & 0xFFFFFFFFu);
          if (device_feature_select_ == 1)
              return static_cast<std::uint32_t>(f >> 32);
          // Selects >= 2 cover the extended (>=64) feature space which we
          // don't advertise. Spec-compliant response: read as 0.
          return 0;
      }
      case kCcDriverFeatureSelect: return driver_feature_select_;
      case kCcDriverFeature:
          if (driver_feature_select_ == 0)
              return static_cast<std::uint32_t>(driver_features_ & 0xFFFFFFFFu);
          if (driver_feature_select_ == 1)
              return static_cast<std::uint32_t>(driver_features_ >> 32);
          return 0;
      case kCcMsixConfig:  // [0x10] msix_config | [0x12] num_queues
          return static_cast<std::uint32_t>(msix_config_) |
                 (static_cast<std::uint32_t>(dev_.QueueCount()) << 16);
      case kCcDeviceStatus:  // [0x14] status | [0x15] config_generation
                              // | [0x16] queue_select
          return static_cast<std::uint32_t>(status_) |
                 (static_cast<std::uint32_t>(config_generation_) << 8) |
                 (static_cast<std::uint32_t>(queue_select_)      << 16);
      case kCcQueueSize: {
          std::uint16_t sz = 0;
          if (queue_select_ < queues_.size()) {
              sz = static_cast<std::uint16_t>(
                  queues_[queue_select_].size != 0
                      ? queues_[queue_select_].size
                      : dev_.QueueMax(queue_select_));
          }
          std::uint16_t vec = 0xFFFF;
          if (queue_select_ < queues_.size()) {
              vec = queues_[queue_select_].msix_vector;
          }
          return static_cast<std::uint32_t>(sz) |
                 (static_cast<std::uint32_t>(vec) << 16);
      }
      case kCcQueueEnable: {
          std::uint16_t en = 0;
          if (queue_select_ < queues_.size()) {
              en = queues_[queue_select_].enable;
          }
          // queue_notify_off at +0x1E: we use qidx directly.
          return static_cast<std::uint32_t>(en) |
                 (static_cast<std::uint32_t>(queue_select_) << 16);
      }
      case kCcQueueDesc:
      case kCcQueueDesc + 4:
      case kCcQueueDriver:
      case kCcQueueDriver + 4:
      case kCcQueueDevice:
      case kCcQueueDevice + 4: {
          if (queue_select_ >= queues_.size()) return 0;
          const QueueState& q = queues_[queue_select_];
          std::uint64_t v = 0;
          if      (off == kCcQueueDesc)         v = q.desc;
          else if (off == kCcQueueDesc + 4)     v = q.desc   >> 32;
          else if (off == kCcQueueDriver)       v = q.driver;
          else if (off == kCcQueueDriver + 4)   v = q.driver >> 32;
          else if (off == kCcQueueDevice)       v = q.device;
          else if (off == kCcQueueDevice + 4)   v = q.device >> 32;
          return static_cast<std::uint32_t>(v & 0xFFFFFFFFu);
      }
      default:
        return 0;
    }
}

void PciTransport::WriteCommonCfg32(std::uint32_t off, std::uint32_t value) {
    switch (off) {
      case kCcDeviceFeatureSelect:
        device_feature_select_ = value;
        return;
      case kCcDeviceFeature:
        // RO; ignore.
        return;
      case kCcDriverFeatureSelect:
        driver_feature_select_ = value;
        return;
      case kCcDriverFeature: {
        // Only selects 0 (bits 0..31) and 1 (bits 32..63) map onto our 64-bit
        // driver_features_. Higher selects belong to the extended-features
        // region (Linux v6.x vp_modern_*_extended_features API); we don't
        // advertise any feature in that range, so writes there must be NOPs
        // -- otherwise the driver's "write 0 to acknowledge nothing" sweep
        // would wipe out feature bits we have negotiated.
        if (driver_feature_select_ > 1) {
            return;
        }
        const std::uint64_t mask = (driver_feature_select_ == 0)
                                       ? 0x00000000FFFFFFFFULL
                                       : 0xFFFFFFFF00000000ULL;
        const std::uint64_t shifted = (driver_feature_select_ == 0)
                                          ? static_cast<std::uint64_t>(value)
                                          : (static_cast<std::uint64_t>(value)
                                             << 32);
        driver_features_ = (driver_features_ & ~mask) | shifted;
        return;
      }
      case kCcMsixConfig:
        // Writes hit msix_config (low 16) and num_queues (high 16, RO).
        msix_config_ = static_cast<std::uint16_t>(value & 0xFFFFu);
        return;
      case kCcDeviceStatus: {
        // Low byte = device_status; mid byte = config_generation (RO);
        // high word = queue_select (writable).
        const std::uint8_t new_status =
            static_cast<std::uint8_t>(value & 0xFFu);
        if (new_status != status_) ApplyStatusWrite(new_status);
        const std::uint16_t new_qsel =
            static_cast<std::uint16_t>((value >> 16) & 0xFFFFu);
        queue_select_ = new_qsel;
        return;
      }
      case kCcQueueSize: {
        // Low 16 = queue_size; high 16 = queue_msix_vector.
        if (queue_select_ < queues_.size()) {
            const std::uint16_t qs =
                static_cast<std::uint16_t>(value & 0xFFFFu);
            const std::uint32_t max = dev_.QueueMax(queue_select_);
            if (qs <= max) queues_[queue_select_].size = qs;
            queues_[queue_select_].msix_vector =
                static_cast<std::uint16_t>((value >> 16) & 0xFFFFu);
        }
        return;
      }
      case kCcQueueEnable: {
        // Low 16 = queue_enable; high 16 = queue_notify_off (RO).
        const std::uint16_t en = static_cast<std::uint16_t>(value & 0xFFFFu);
        if (queue_select_ < queues_.size()) {
            QueueState& q = queues_[queue_select_];
            q.enable = en;
            if (en && q.size != 0) {
                if (Virtqueue* vq = dev_.GetQueue(queue_select_)) {
                    vq->SetDescGpa (q.desc);
                    vq->SetAvailGpa(q.driver);
                    vq->SetUsedGpa (q.device);
                    vq->SetSize    (q.size);
                    vq->SetEventIdxEnabled(
                        (driver_features_ & kFeatureRingEventIdx) != 0);
                    vq->SetReady(true);
                }
            } else if (!en) {
                if (Virtqueue* vq = dev_.GetQueue(queue_select_)) {
                    vq->SetReady(false);
                }
            }
        }
        return;
      }
      case kCcQueueDesc:
        if (queue_select_ < queues_.size()) {
            queues_[queue_select_].desc =
                (queues_[queue_select_].desc & 0xFFFFFFFF00000000ULL) | value;
        }
        return;
      case kCcQueueDesc + 4:
        if (queue_select_ < queues_.size()) {
            queues_[queue_select_].desc =
                (queues_[queue_select_].desc & 0x00000000FFFFFFFFULL) |
                (static_cast<std::uint64_t>(value) << 32);
        }
        return;
      case kCcQueueDriver:
        if (queue_select_ < queues_.size()) {
            queues_[queue_select_].driver =
                (queues_[queue_select_].driver & 0xFFFFFFFF00000000ULL) | value;
        }
        return;
      case kCcQueueDriver + 4:
        if (queue_select_ < queues_.size()) {
            queues_[queue_select_].driver =
                (queues_[queue_select_].driver & 0x00000000FFFFFFFFULL) |
                (static_cast<std::uint64_t>(value) << 32);
        }
        return;
      case kCcQueueDevice:
        if (queue_select_ < queues_.size()) {
            queues_[queue_select_].device =
                (queues_[queue_select_].device & 0xFFFFFFFF00000000ULL) | value;
        }
        return;
      case kCcQueueDevice + 4:
        if (queue_select_ < queues_.size()) {
            queues_[queue_select_].device =
                (queues_[queue_select_].device & 0x00000000FFFFFFFFULL) |
                (static_cast<std::uint64_t>(value) << 32);
        }
        return;
      default:
        return;
    }
}

void PciTransport::ApplyStatusWrite(std::uint8_t new_status) {
    if (new_status == 0) {
        // Reset.
        status_ = 0;
        isr_status_.store(0, std::memory_order_relaxed);
        device_feature_select_ = 0;
        driver_feature_select_ = 0;
        driver_features_ = 0;
        msix_config_ = 0xFFFF;
        queue_select_ = 0;
        for (auto& qs : queues_) qs = QueueState{};
        for (std::uint32_t i = 0; i < dev_.QueueCount(); ++i) {
            if (Virtqueue* q = dev_.GetQueue(i)) q->Reset();
        }
        dev_.Reset();
        return;
    }
    const std::uint8_t prev = status_;
    const std::uint8_t adding = new_status & ~prev;
    std::uint8_t effective = new_status;
    if (adding & kStatusFeaturesOk) {
        if (!dev_.SetDriverFeatures(driver_features_)) {
            effective &= ~kStatusFeaturesOk;
            effective |= kStatusNeedsReset;
        }
    }
    status_ = effective;
    if (adding & kStatusDriverOk) {
        dev_.DriverOk();
    }
}

void PciTransport::HandleIsr(devices::MmioAccess& access) {
    if (access.is_write) {
        // Spec: ISR writes ignored.
        writes_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    reads_.fetch_add(1, std::memory_order_relaxed);
    // Read-and-clear: atomic exchange snapshots+clears in one step.
    const std::uint32_t snap =
        isr_status_.exchange(0, std::memory_order_acq_rel);
    std::memset(access.data, 0, sizeof(access.data));
    std::memcpy(access.data, &snap,
                std::min<std::size_t>(access.access_size, 4));
}

void PciTransport::HandleNotify(devices::MmioAccess& access) {
    if (!access.is_write) {
        // Reads of notify region return 0.
        reads_.fetch_add(1, std::memory_order_relaxed);
        std::memset(access.data, 0, sizeof(access.data));
        return;
    }
    writes_.fetch_add(1, std::memory_order_relaxed);
    notify_count_.fetch_add(1, std::memory_order_relaxed);
    const std::uint32_t off =
        static_cast<std::uint32_t>(access.gpa - (bar_gpa_ + kOffNotify));
    // Without VIRTIO_F_NOTIFICATION_DATA, the value is the queue index. We
    // also prefer the static offset-derived index when possible -- it
    // guarantees correctness even if the driver writes garbage data.
    const std::uint32_t qidx_from_off = off / kNotifyMultiplier;
    std::uint32_t qidx = qidx_from_off;
    if (access.access_size == 2) {
        std::uint16_t v = 0;
        std::memcpy(&v, access.data, 2);
        qidx = v;
    } else if (access.access_size == 4) {
        std::uint32_t v = 0;
        std::memcpy(&v, access.data, 4);
        qidx = v;
    }
    // Deliberately NOT holding cfg_mu_: the device's NotifyQueue may call
    // back into RaiseQueueInterrupt which acquires cfg_mu_.
    dev_.NotifyQueue(qidx);
}

void PciTransport::HandleDeviceCfg(devices::MmioAccess& access) {
    const std::uint32_t off =
        static_cast<std::uint32_t>(access.gpa - (bar_gpa_ + kOffDeviceCfg));
    if (access.is_write) {
        writes_.fetch_add(1, std::memory_order_relaxed);
        std::uint32_t v = 0;
        std::memcpy(&v, access.data,
                    std::min<std::size_t>(access.access_size, 4));
        dev_.WriteConfig(off, access.access_size, v);
        return;
    }
    reads_.fetch_add(1, std::memory_order_relaxed);
    const std::uint32_t v = dev_.ReadConfig(off, access.access_size);
    std::memset(access.data, 0, sizeof(access.data));
    std::memcpy(access.data, &v,
                std::min<std::size_t>(access.access_size, 4));
}

// ----------------------- M33.4 save/restore ---------------------------

PciTransport::State PciTransport::CaptureState() const {
    State s;
    std::lock_guard<std::mutex> lk(cfg_mu_);
    s.device_feature_select = device_feature_select_;
    s.driver_feature_select = driver_feature_select_;
    s.driver_features       = driver_features_;
    s.msix_config           = msix_config_;
    s.status                = status_;
    s.config_generation     = config_generation_;
    s.queue_select          = queue_select_;
    s.bar_mapped            = bar_mapped_ ? 1u : 0u;
    s.bar_gpa               = bar_gpa_;
    s.isr_status            = isr_status_.load(std::memory_order_relaxed);
    s.queues                = queues_;
    return s;
}

void PciTransport::ApplyState(const State& s) {
    {
        std::lock_guard<std::mutex> lk(cfg_mu_);
        if (s.queues.size() != queues_.size()) {
            throw std::runtime_error(
                "PciTransport::ApplyState: queue count mismatch");
        }
        device_feature_select_ = s.device_feature_select;
        driver_feature_select_ = s.driver_feature_select;
        driver_features_       = s.driver_features;
        msix_config_           = s.msix_config;
        status_                = s.status;
        config_generation_     = s.config_generation;
        queue_select_          = s.queue_select;
        queues_                = s.queues;
        bar_mapped_            = s.bar_mapped != 0;
        bar_gpa_               = s.bar_gpa;
        isr_status_.store(s.isr_status, std::memory_order_relaxed);
    }
    // After unlocking, register MMIO handlers if the BAR was mapped at
    // capture time. InstallBarHandlers_ doesn't touch any field this
    // function locked, but it does call into mmio_bus_/msix_ which take
    // their own locks; we avoid holding cfg_mu_ across those calls.
    if (s.bar_mapped) {
        InstallBarHandlers_(s.bar_gpa);
    }
}

std::size_t PciTransport::EncodeState(const State& s,
                                      std::vector<std::uint8_t>& out) {
    using namespace tinyvmm::whp::snapshot;
    const std::size_t want = EncodedSize(s.queues.size());
    const std::size_t start = out.size();
    out.resize(start + want, 0);
    std::uint8_t* p = out.data() + start;
    WriteLe32(p +  0, s.device_feature_select);
    WriteLe32(p +  4, s.driver_feature_select);
    WriteLe64(p +  8, s.driver_features);
    // p[16..17] u16 msix_config
    p[16] = static_cast<std::uint8_t>(s.msix_config        & 0xFF);
    p[17] = static_cast<std::uint8_t>((s.msix_config >> 8) & 0xFF);
    p[18] = s.status;
    p[19] = s.config_generation;
    // p[20..21] u16 queue_select
    p[20] = static_cast<std::uint8_t>(s.queue_select        & 0xFF);
    p[21] = static_cast<std::uint8_t>((s.queue_select >> 8) & 0xFF);
    p[22] = s.bar_mapped;
    // p[23] u8 pad
    WriteLe64(p + 24, s.bar_gpa);
    WriteLe32(p + 32, s.isr_status);
    WriteLe32(p + 36,
              static_cast<std::uint32_t>(s.queues.size()));   // num_queues
    std::size_t off = kEncodedHeaderSize;
    for (const auto& q : s.queues) {
        // Layout per queue (32 bytes total):
        //   +0  u16 msix_vector
        //   +2  u16 enable
        //   +4  u16 size
        //   +6  u16 pad
        //   +8  u64 desc
        //  +16  u64 driver
        //  +24  u64 device
        p[off + 0] = static_cast<std::uint8_t>(q.msix_vector        & 0xFF);
        p[off + 1] = static_cast<std::uint8_t>((q.msix_vector >> 8) & 0xFF);
        p[off + 2] = static_cast<std::uint8_t>(q.enable        & 0xFF);
        p[off + 3] = static_cast<std::uint8_t>((q.enable >> 8) & 0xFF);
        p[off + 4] = static_cast<std::uint8_t>(q.size        & 0xFF);
        p[off + 5] = static_cast<std::uint8_t>((q.size >> 8) & 0xFF);
        // p[off+6..7] u16 pad (already zero from resize)
        WriteLe64(p + off +  8, q.desc);
        WriteLe64(p + off + 16, q.driver);
        WriteLe64(p + off + 24, q.device);
        off += 32;
    }
    return want;
}

PciTransport::State PciTransport::DecodeState(
    std::span<const std::uint8_t> bytes) {
    using namespace tinyvmm::whp::snapshot;
    if (bytes.size() < kEncodedHeaderSize) {
        throw std::runtime_error(
            "PciTransport::DecodeState: payload smaller than header");
    }
    const std::uint8_t* p = bytes.data();
    State s;
    s.device_feature_select = ReadLe32(p +  0);
    s.driver_feature_select = ReadLe32(p +  4);
    s.driver_features       = ReadLe64(p +  8);
    s.msix_config = static_cast<std::uint16_t>(p[16] | (p[17] << 8));
    s.status                = p[18];
    s.config_generation     = p[19];
    s.queue_select = static_cast<std::uint16_t>(p[20] | (p[21] << 8));
    s.bar_mapped            = p[22];
    if (p[23] != 0) {
        throw std::runtime_error(
            "PciTransport::DecodeState: nonzero pad@23");
    }
    s.bar_gpa               = ReadLe64(p + 24);
    s.isr_status            = ReadLe32(p + 32);
    const std::uint32_t nq  = ReadLe32(p + 36);
    const std::size_t want = EncodedSize(nq);
    if (bytes.size() < want) {
        throw std::runtime_error(
            "PciTransport::DecodeState: payload truncated for num_queues");
    }
    s.queues.resize(nq);
    std::size_t off = kEncodedHeaderSize;
    for (std::uint32_t i = 0; i < nq; ++i) {
        QueueState& q = s.queues[i];
        q.msix_vector = static_cast<std::uint16_t>(
            p[off + 0] | (p[off + 1] << 8));
        q.enable      = static_cast<std::uint16_t>(
            p[off + 2] | (p[off + 3] << 8));
        q.size        = static_cast<std::uint16_t>(
            p[off + 4] | (p[off + 5] << 8));
        if (p[off + 6] != 0 || p[off + 7] != 0) {
            throw std::runtime_error(
                "PciTransport::DecodeState: nonzero pad in queue");
        }
        q.desc        = ReadLe64(p + off +  8);
        q.driver      = ReadLe64(p + off + 16);
        q.device      = ReadLe64(p + off + 24);
        off += 32;
    }
    return s;
}

}  // namespace tinyvmm::virtio
