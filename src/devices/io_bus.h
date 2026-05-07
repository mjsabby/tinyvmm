#pragma once

#include "../common.h"

#include <functional>
#include <string>
#include <vector>

namespace tinyvmm::devices {

// One in-flight port-IO access. Bridged from WHV_EMULATOR_IO_ACCESS_INFO by the
// run loop; handlers see a flat plain-old-data view.
//
// `Direction == 1` is OUT (guest -> device), `0` is IN (device -> guest).
//
// `value` carries the data: for OUT, the guest's payload (already
// zero-extended into 32 bits by the emulator); for IN, the handler stores its
// reply there before returning.
struct IoAccess {
    std::uint16_t port;
    std::uint16_t access_size;  // 1, 2, or 4 bytes
    bool is_write;              // true == OUT
    std::uint32_t value;
};

// Routes port-IO accesses to device handlers by port range.
//
// Lookup is a linear scan: with <10 devices this beats a map by cache locality
// and we get insertion-ordered iteration for diagnostics.
class IoBus {
public:
    using Handler = std::function<void(IoAccess&)>;

    // Register `handler` for the inclusive port range [base, base+size).
    // Ranges may not overlap. `name` is used for diagnostic messages only.
    void Register(std::uint16_t base, std::uint16_t size, std::string name,
                  Handler handler);

    // Dispatch one access. Returns true if a handler claimed it. Reads to
    // unmapped ports return all-ones (ISA bus pull-up convention) and writes
    // are dropped, matching how real hardware behaves on a floating bus.
    bool Dispatch(IoAccess& access);

    // Number of registered ranges. For tests / diagnostics.
    std::size_t size() const noexcept { return entries_.size(); }

private:
    struct Entry {
        std::uint16_t base;
        std::uint16_t size;
        std::string name;
        Handler handler;
    };

    std::vector<Entry> entries_;
};

}  // namespace tinyvmm::devices
