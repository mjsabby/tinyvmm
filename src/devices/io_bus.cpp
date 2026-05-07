#include "io_bus.h"

#include <cstdio>
#include <utility>

namespace tinyvmm::devices {

namespace {

bool RangesOverlap(std::uint32_t a_base, std::uint32_t a_size,
                   std::uint32_t b_base, std::uint32_t b_size) {
    return a_base < b_base + b_size && b_base < a_base + a_size;
}

}  // namespace

void IoBus::Register(std::uint16_t base, std::uint16_t size, std::string name,
                     Handler handler) {
    if (size == 0) {
        Fatal("IoBus::Register: size must be > 0");
    }
    if (static_cast<std::uint32_t>(base) + size > 0x10000u) {
        Fatal("IoBus::Register: range exceeds 16-bit IO space");
    }
    for (const auto& e : entries_) {
        if (RangesOverlap(base, size, e.base, e.size)) {
            std::fprintf(
                stderr,
                "IoBus::Register: range [%04x..%04x) for '%s' overlaps '%s' "
                "[%04x..%04x)\n",
                base, base + size, name.c_str(), e.name.c_str(), e.base,
                e.base + e.size);
            Fatal("IoBus::Register: overlapping range");
        }
    }
    entries_.push_back(
        {base, size, std::move(name), std::move(handler)});
}

bool IoBus::Dispatch(IoAccess& access) {
    for (const auto& e : entries_) {
        if (access.port >= e.base && access.port < e.base + e.size) {
            e.handler(access);
            return true;
        }
    }
    if (!access.is_write) {
        // Floating-bus convention: unmapped reads see all-ones.
        access.value = 0xFFFFFFFFu;
    }
    return false;
}

}  // namespace tinyvmm::devices
