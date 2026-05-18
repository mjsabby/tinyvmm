#pragma once

#include "common.h"

#include <functional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace tinyvmm::devices {

// One in-flight MMIO access. Bridged from WHV_EMULATOR_MEMORY_ACCESS_INFO by
// the run loop. `data` holds little-endian bytes: for writes, what the guest
// stored; for reads, what the handler should return.
struct MmioAccess {
    std::uint64_t gpa;
    std::uint8_t access_size;  // 1, 2, 4, or 8 bytes
    bool is_write;
    std::uint8_t data[8];
};

// Routes MMIO accesses to device handlers by GPA range. Same shape as IoBus
// but 64-bit and with byte-buffer payload.
//
// Thread-safety: Dispatch() is invoked concurrently by N vCPU threads while
// Register()/Unregister() may be invoked from a vCPU's PCI config-write path
// (BAR map/unmap). We use a shared_mutex: Dispatch takes a shared lock so
// concurrent reads scale on N vCPUs; Register/Unregister take an exclusive
// lock. BAR map/unmap is a cold event (once per device at boot), so the
// exclusive-lock cost is paid only on cold boot.
class MmioBus {
public:
    using Handler = std::function<void(MmioAccess&)>;

    void Register(std::uint64_t base, std::uint64_t size, std::string name,
                  Handler handler);

    // Remove the range whose base is exactly `base`. Returns true if a range
    // was found and removed. Used by PCI BARs that get remapped when the
    // guest writes a new base or flips COMMAND.MEM_SPACE.
    bool Unregister(std::uint64_t base);

    // Returns true if a handler claimed it. Unmapped reads return zero-filled
    // bytes (we don't pretend to be a real ISA bus here -- surprising guest
    // values during bring-up are worse than zero).
    bool Dispatch(MmioAccess& access);

    std::size_t size() const noexcept {
        std::shared_lock<std::shared_mutex> lk(mu_);
        return entries_.size();
    }

private:
    struct Entry {
        std::uint64_t base;
        std::uint64_t size;
        std::string name;
        Handler handler;
    };

    mutable std::shared_mutex mu_;
    std::vector<Entry> entries_;
};

}  // namespace tinyvmm::devices
