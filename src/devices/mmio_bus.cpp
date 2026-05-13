#include "mmio_bus.h"

#include <cstdio>
#include <cstring>
#include <utility>

namespace tinyvmm::devices {

namespace {

bool RangesOverlap(std::uint64_t a_base, std::uint64_t a_size,
                   std::uint64_t b_base, std::uint64_t b_size) {
    return a_base < b_base + b_size && b_base < a_base + a_size;
}

}  // namespace

void MmioBus::Register(std::uint64_t base, std::uint64_t size, std::string name,
                       Handler handler) {
    if (size == 0) {
        Fatal("MmioBus::Register: size must be > 0");
    }
    for (const auto& e : entries_) {
        if (RangesOverlap(base, size, e.base, e.size)) {
            std::fprintf(stderr,
                         "MmioBus::Register: range [%llx..%llx) for '%s' "
                         "overlaps '%s' [%llx..%llx)\n",
                         static_cast<unsigned long long>(base),
                         static_cast<unsigned long long>(base + size),
                         name.c_str(), e.name.c_str(),
                         static_cast<unsigned long long>(e.base),
                         static_cast<unsigned long long>(e.base + e.size));
            Fatal("MmioBus::Register: overlapping range");
        }
    }
    entries_.push_back(
        {base, size, std::move(name), std::move(handler)});
}

bool MmioBus::Unregister(std::uint64_t base) {
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if (it->base == base) {
            entries_.erase(it);
            return true;
        }
    }
    return false;
}

bool MmioBus::Dispatch(MmioAccess& access) {
    for (const auto& e : entries_) {
        if (access.gpa >= e.base && access.gpa < e.base + e.size) {
            e.handler(access);
            return true;
        }
    }
    if (!access.is_write) {
        std::memset(access.data, 0, sizeof(access.data));
    }
    return false;
}

}  // namespace tinyvmm::devices
