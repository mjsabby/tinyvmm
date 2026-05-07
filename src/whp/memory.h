#pragma once

#include "../common.h"
#include "partition.h"

#include <vector>

namespace tinyvmm::whp {

// Backing-page policy for a guest memory region.
enum class PagePolicy {
    // Try MEM_LARGE_PAGES (2 MiB on x86_64). If SeLockMemoryPrivilege is not
    // held, fall back to 4 KiB pages and emit a warning. Size is rounded up
    // to the large-page minimum either way.
    LargeIfAvailable,

    // Force 4 KiB pages.
    Small,
};

// One contiguous slab of guest physical memory. Backed by a host VirtualAlloc
// region and mapped into the partition at a fixed GPA. Owning RAII type.
class GuestMemory {
public:
    GuestMemory(Partition& partition,
                std::uint64_t gpa,
                std::size_t size_bytes,
                bool executable = true,
                PagePolicy page_policy = PagePolicy::LargeIfAvailable);
    ~GuestMemory();

    GuestMemory(const GuestMemory&) = delete;
    GuestMemory& operator=(const GuestMemory&) = delete;

    // Host-virtual base of the backing memory. Valid host pointer for
    // bulk-copying initial guest contents (kernel image, etc.) before the vCPU
    // runs.
    void* host_base() const noexcept { return host_base_; }
    std::uint64_t gpa() const noexcept { return gpa_; }

    // Actual size of the mapping. May be larger than the size_bytes the caller
    // requested if rounded up to the large-page boundary.
    std::size_t size() const noexcept { return size_; }

    // True if the backing memory was actually allocated with MEM_LARGE_PAGES.
    bool large_pages() const noexcept { return large_pages_; }

    // Translate a guest physical address inside this region to its host
    // pointer; returns nullptr if out of range. Callers using this for hot-path
    // virtq access should cache the offset themselves.
    void* HostPointer(std::uint64_t guest_phys) const noexcept;

    // Convenience for staging boot artifacts.
    void WriteAt(std::uint64_t guest_phys, const void* src, std::size_t n);

private:
    Partition& partition_;
    void* host_base_ = nullptr;
    std::uint64_t gpa_ = 0;
    std::size_t size_ = 0;
    bool large_pages_ = false;
};

}  // namespace tinyvmm::whp
