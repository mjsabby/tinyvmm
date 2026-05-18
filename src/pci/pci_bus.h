#pragma once

// PCI host bridge: turns the 0xCF8/0xCFC port pair into Type-0 config-space
// access on a list of devices. Owns the pre-assigned BAR base layout so the
// guest's PCI allocator can take what we give it without realloc.
//
// Usage:
//   PciBus bus;
//   bus.AddDevice(std::make_unique<VirtioPciNet>(...));
//   bus.AddDevice(std::make_unique<VirtioPciBlk>(...));
//   bus.AttachIoBus(io_bus);   // registers 0xCF8/0xCFC handlers
//
// The bus pre-assigns BAR base addresses out of an internal MMIO/IO pool
// during AddDevice, then exposes them through standard config reads. Linux's
// PCI scan walks bus 0 (we report device-not-present for any BDF without a
// registered device), reads BAR sizes via the write-all-1s protocol, and
// usually accepts our pre-assignment.

#include "common.h"
#include "devices/io_bus.h"
#include "pci.h"
#include "pci_device.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace tinyvmm::pci {

// Default GPA windows for pre-assigned BARs. Chosen below the LAPIC window
// (0xFEE00000) and above typical guest RAM (we boot small kernels in low
// memory, so 0xE000_0000 is comfortably out of the way).
inline constexpr std::uint64_t kMmioWindowBase = 0x0000'0000'E000'0000ULL;
inline constexpr std::uint64_t kMmioWindowEnd  = 0x0000'0000'FEC0'0000ULL;

inline constexpr std::uint16_t kIoWindowBase = 0xC000;
inline constexpr std::uint16_t kIoWindowEnd  = 0xFFFE;  // leave 0xCF8/0xCFC

class PciBus {
public:
    PciBus();
    ~PciBus() = default;

    PciBus(const PciBus&) = delete;
    PciBus& operator=(const PciBus&) = delete;

    // Add a device on bus 0 at the lowest free device slot (function 0).
    // Pre-assigns its BAR base addresses out of the bus's MMIO / IO pool.
    // Returns the (bus, dev, fn) triple it was placed at.
    Bdf AddDevice(std::unique_ptr<PciDevice> dev);

    // Add a device at a specific BDF (must be unique). Same semantics.
    Bdf AddDeviceAt(Bdf bdf, std::unique_ptr<PciDevice> dev);

    // Register the 0xCF8/0xCFC handlers on the IO bus. Must be called once.
    void AttachIoBus(devices::IoBus& io_bus);

    // Look up a device by BDF. Returns nullptr if absent. For tests only.
    PciDevice* Find(Bdf bdf) const;

    // Diagnostics.
    std::uint64_t cfg_reads()  const noexcept { return cfg_reads_; }
    std::uint64_t cfg_writes() const noexcept { return cfg_writes_; }
    std::size_t   device_count() const noexcept { return devices_.size(); }

private:
    struct Slot {
        Bdf                          bdf;
        std::unique_ptr<PciDevice>   dev;
    };

    // Place pre-computed BAR bases into the device's BAR cells.
    void AssignBars(PciDevice& dev);

    void HandleAddress(devices::IoAccess& access);
    void HandleData   (devices::IoAccess& access);

    std::uint32_t       config_address_ = 0;
    std::vector<Slot>   devices_;
    std::uint64_t       cfg_reads_  = 0;
    std::uint64_t       cfg_writes_ = 0;

    // Serializes 0xCF8 (CONFIG_ADDRESS) writes against 0xCFC (CONFIG_DATA)
    // accesses on multi-vCPU partitions. Linux already takes its own pci
    // lock on the guest side so contention is essentially zero in practice;
    // this guards against torn reads/writes of config_address_ and against
    // concurrent ConfigRead/ConfigWrite delivery if the guest ever races us.
    std::mutex          mu_;

    // Bump-pointer allocators for pre-assigned BAR layout.
    std::uint64_t       mmio_next_ = kMmioWindowBase;
    std::uint16_t       io_next_   = kIoWindowBase;
};

}  // namespace tinyvmm::pci
