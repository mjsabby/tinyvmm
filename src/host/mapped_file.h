#pragma once

// Win32 file mapping RAII wrapper.
//
// Mostly used by the PVH loader to bring vmlinux / initramfs into the address
// space without the std::ifstream read+copy overhead. On modern Windows
// CreateFileMapping + MapViewOfFile lets us hand the pages straight to a
// memcpy into guest RAM, which costs roughly 1/3 of what `ifstream::read`
// into a `std::vector` does for tens-of-MB files.
//
// Read-only view by design: we never need to write back to the source file.
// Mapping is shared-read-shared-write at the OS handle level so the user can
// continue to overwrite the file on disk while the VMM is running (the view
// stays consistent for the lifetime of this object).

#include "common.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>

namespace tinyvmm::host {

class MappedFile {
public:
    // Opens `path` for read and maps the entire file. Throws HrError on any
    // failure (file missing, GetFileSizeEx, CreateFileMapping, MapViewOfFile).
    // Zero-byte files map as an empty view (data == nullptr, size == 0).
    explicit MappedFile(const std::filesystem::path& path);
    ~MappedFile();

    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    MappedFile(MappedFile&& other) noexcept;
    MappedFile& operator=(MappedFile&& other) noexcept;

    [[nodiscard]] const std::uint8_t* data() const noexcept { return base_; }
    [[nodiscard]] std::size_t          size() const noexcept { return size_; }
    [[nodiscard]] bool                 empty() const noexcept { return size_ == 0; }

    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept {
        return {base_, size_};
    }

private:
    void Close() noexcept;

    HANDLE         file_    = INVALID_HANDLE_VALUE;
    HANDLE         mapping_ = nullptr;
    std::uint8_t*  base_    = nullptr;
    std::size_t    size_    = 0;
};

}  // namespace tinyvmm::host
