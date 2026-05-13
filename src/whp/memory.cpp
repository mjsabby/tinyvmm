#include "memory.h"

#include "../host/privilege.h"

#include <cstdio>
#include <cstring>

namespace tinyvmm::whp {

namespace {

void* TryAlloc(std::size_t size_bytes, bool large) {
    DWORD type = MEM_COMMIT | MEM_RESERVE;
    if (large) {
        type |= MEM_LARGE_PAGES;
    }
    return ::VirtualAlloc(nullptr, size_bytes, type, PAGE_READWRITE);
}

}  // namespace

GuestMemory::GuestMemory(Partition& partition,
                         std::uint64_t gpa,
                         std::size_t size_bytes,
                         bool executable,
                         PagePolicy page_policy)
    : partition_(partition), gpa_(gpa) {
    if (size_bytes == 0 || (gpa_ & kPageMask) != 0) {
        Fatal("GuestMemory: gpa must be 4 KiB aligned and size non-zero");
    }

    const bool want_large = (page_policy == PagePolicy::LargeIfAvailable);
    const std::size_t lp = host::LargePageSize();
    const std::size_t alloc_size =
        want_large ? AlignUp(size_bytes, lp) : AlignUp(size_bytes, kPageSize);

    if (want_large && (gpa_ % lp) != 0) {
        Fatal("GuestMemory: gpa must be large-page aligned for large-page "
              "policy (use PagePolicy::Small for non-aligned regions)");
    }

    if (want_large) {
        host_base_ = TryAlloc(alloc_size, /*large=*/true);
        if (host_base_ != nullptr) {
            large_pages_ = true;
        } else {
            DWORD err = ::GetLastError();
            const char* reason = "VirtualAlloc(MEM_LARGE_PAGES) failed";
            if (err == ERROR_PRIVILEGE_NOT_HELD) {
                reason =
                    "SeLockMemoryPrivilege not held (grant via gpedit.msc -> "
                    "User Rights Assignment -> 'Lock pages in memory')";
            }
            std::fprintf(stderr,
                         "[mem] WARN: large-page alloc failed (err=%lu, %s); "
                         "falling back to 4 KiB pages\n",
                         err, reason);
        }
    }

    if (host_base_ == nullptr) {
        host_base_ = TryAlloc(alloc_size, /*large=*/false);
        if (host_base_ == nullptr) {
            DWORD err = ::GetLastError();
            // VirtualAlloc returned nullptr -- ensure we always throw even
            // if GetLastError() happens to be 0 (so the static analyzer can
            // prove host_base_ is non-null after this branch).
            throw HrError(
                HRESULT_FROM_WIN32(err == 0 ? ERROR_NOT_ENOUGH_MEMORY : err),
                "VirtualAlloc(guest RAM)");
        }
    }

    size_ = alloc_size;

    WHV_MAP_GPA_RANGE_FLAGS flags =
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite;
    if (executable) {
        flags = static_cast<WHV_MAP_GPA_RANGE_FLAGS>(
            flags | WHvMapGpaRangeFlagExecute);
    }

    HRESULT hr = WHvMapGpaRange(partition_.handle(), host_base_, gpa_, size_,
                                flags);
    if (FAILED(hr)) {
        ::VirtualFree(host_base_, 0, MEM_RELEASE);
        host_base_ = nullptr;
        ThrowIfFailed(hr, "WHvMapGpaRange");
    }
}

GuestMemory::~GuestMemory() {
    if (host_base_ != nullptr) {
        WHvUnmapGpaRange(partition_.handle(), gpa_, size_);
        ::VirtualFree(host_base_, 0, MEM_RELEASE);
    }
}

void* GuestMemory::HostPointer(std::uint64_t guest_phys) const noexcept {
    if (guest_phys < gpa_ || guest_phys >= gpa_ + size_) {
        return nullptr;
    }
    return static_cast<std::uint8_t*>(host_base_) + (guest_phys - gpa_);
}

void GuestMemory::WriteAt(std::uint64_t guest_phys, const void* src,
                          std::size_t n) {
    void* dst = HostPointer(guest_phys);
    if (dst == nullptr || guest_phys + n > gpa_ + size_) {
        Fatal("GuestMemory::WriteAt out of range");
    }
    std::memcpy(dst, src, n);
}

}  // namespace tinyvmm::whp
