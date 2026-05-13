#include "pci_bus.h"

#include <cstdio>
#include <cstring>
#include <utility>

namespace tinyvmm::pci {

namespace {

// CFG #1 supports 1/2/4-byte access through 0xCFC..0xCFF. Decode (port,
// access_size) into (dword_offset, byte_within_dword, byte_size).
struct DataSlot {
    std::uint32_t byte_offset_in_dword;  // 0..3
    std::uint32_t size;                  // 1, 2, or 4
};

DataSlot DecodeDataPort(std::uint16_t port, std::uint16_t access_size) {
    DataSlot s{};
    s.byte_offset_in_dword =
        static_cast<std::uint32_t>(port - kConfigDataPort);
    s.size = access_size;
    return s;
}

}  // namespace

PciBus::PciBus() = default;

void PciBus::AssignBars(PciDevice& dev) {
    for (int i = 0; i < 6; ++i) {
        const Bar& b = dev.bar(i);
        switch (b.type) {
          case BarType::None:
            break;
          case BarType::Io: {
            std::uint16_t base = io_next_;
            // Align up to size.
            const std::uint16_t mask = static_cast<std::uint16_t>(b.size - 1);
            base = static_cast<std::uint16_t>((base + mask) & ~mask);
            if (static_cast<std::uint32_t>(base) + b.size > kIoWindowEnd) {
                Fatal("PciBus: ran out of IO BAR window");
            }
            dev.SetBarBase(i, base);
            io_next_ = static_cast<std::uint16_t>(base + b.size);
            break;
          }
          case BarType::Mmio32:
          case BarType::Mmio64: {
            std::uint64_t base = mmio_next_;
            const std::uint64_t mask = b.size - 1;
            base = (base + mask) & ~mask;
            if (base + b.size > kMmioWindowEnd) {
                Fatal("PciBus: ran out of MMIO BAR window");
            }
            dev.SetBarBase(i, base);
            mmio_next_ = base + b.size;
            break;
          }
        }
    }
}

Bdf PciBus::AddDevice(std::unique_ptr<PciDevice> dev) {
    // Find the next free device slot on bus 0, function 0.
    Bdf bdf{};
    for (std::uint8_t d = 0; d < 32; ++d) {
        Bdf cand{0, d, 0};
        if (Find(cand) == nullptr) {
            bdf = cand;
            break;
        }
    }
    if (bdf.bus == 0 && bdf.device == 0 && bdf.function == 0 &&
        !devices_.empty()) {
        // Wrap-around: no free slot.
        Fatal("PciBus: bus 0 is full");
    }
    return AddDeviceAt(bdf, std::move(dev));
}

Bdf PciBus::AddDeviceAt(Bdf bdf, std::unique_ptr<PciDevice> dev) {
    if (Find(bdf) != nullptr) {
        Fatal("PciBus::AddDeviceAt: BDF already in use");
    }
    AssignBars(*dev);
    devices_.push_back({bdf, std::move(dev)});
    return bdf;
}

PciDevice* PciBus::Find(Bdf bdf) const {
    for (const auto& s : devices_) {
        if (s.bdf.bus == bdf.bus && s.bdf.device == bdf.device &&
            s.bdf.function == bdf.function) {
            return s.dev.get();
        }
    }
    return nullptr;
}

void PciBus::AttachIoBus(devices::IoBus& io_bus) {
    io_bus.Register(kConfigAddressPort, /*size=*/4, "pci-cfg-addr",
                    [this](devices::IoAccess& a) { HandleAddress(a); });
    io_bus.Register(kConfigDataPort, /*size=*/4, "pci-cfg-data",
                    [this](devices::IoAccess& a) { HandleData(a); });
}

void PciBus::HandleAddress(devices::IoAccess& access) {
    // CONFIG_ADDRESS is a 32-bit register; sub-dword accesses are valid but
    // rare. Linux uses 32-bit IN/OUT exclusively.
    if (access.is_write) {
        if (access.access_size == 4) {
            config_address_ = access.value;
        } else {
            // Merge in the bytes at the right offset.
            const std::uint32_t byte_off =
                static_cast<std::uint32_t>(access.port - kConfigAddressPort);
            const std::uint32_t mask =
                ((access.access_size == 4) ? 0xFFFFFFFFu :
                 ((1u << (8 * access.access_size)) - 1)) << (8 * byte_off);
            config_address_ = (config_address_ & ~mask) |
                              ((access.value << (8 * byte_off)) & mask);
        }
    } else {
        const std::uint32_t byte_off =
            static_cast<std::uint32_t>(access.port - kConfigAddressPort);
        access.value = (config_address_ >> (8 * byte_off));
        if (access.access_size != 4) {
            access.value &= (1u << (8 * access.access_size)) - 1;
        }
    }
}

void PciBus::HandleData(devices::IoAccess& access) {
    const DecodedAddress dec = DecodeConfigAddress(config_address_);
    if (!dec.enable) {
        if (!access.is_write) access.value = 0xFFFFFFFFu;
        return;
    }
    PciDevice* dev = Find(Bdf{dec.bus, dec.dev, dec.fn});
    if (dev == nullptr) {
        // Master abort: reads return all-ones, writes are dropped.
        if (!access.is_write) access.value = 0xFFFFFFFFu;
        return;
    }
    const DataSlot s = DecodeDataPort(access.port, access.access_size);
    const std::uint32_t reg_offset =
        static_cast<std::uint32_t>(dec.reg) + s.byte_offset_in_dword;
    if (access.is_write) {
        ++cfg_writes_;
        dev->ConfigWrite(reg_offset, s.size, access.value);
    } else {
        ++cfg_reads_;
        access.value = dev->ConfigRead(reg_offset, s.size);
    }
}

}  // namespace tinyvmm::pci
