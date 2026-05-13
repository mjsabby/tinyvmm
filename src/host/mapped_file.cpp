#include "mapped_file.h"

#include <cstdio>
#include <limits>
#include <utility>

namespace tinyvmm::host {

MappedFile::MappedFile(const std::filesystem::path& path) {
    file_ = ::CreateFileW(path.c_str(), GENERIC_READ,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          /*sa=*/nullptr, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                          /*tmpl=*/nullptr);
    if (file_ == INVALID_HANDLE_VALUE) {
        const DWORD err = ::GetLastError();
        char msg[320];
        std::snprintf(msg, sizeof(msg),
                      "MappedFile: failed to open %s (Win32 error %lu)",
                      path.string().c_str(), static_cast<unsigned long>(err));
        throw HrError(HRESULT_FROM_WIN32(err), msg);
    }

    LARGE_INTEGER li{};
    if (!::GetFileSizeEx(file_, &li)) {
        const DWORD err = ::GetLastError();
        Close();
        char msg[256];
        std::snprintf(msg, sizeof(msg),
                      "MappedFile: GetFileSizeEx failed for %s (Win32 error %lu)",
                      path.string().c_str(), static_cast<unsigned long>(err));
        throw HrError(HRESULT_FROM_WIN32(err), msg);
    }
    const std::uint64_t bytes64 = static_cast<std::uint64_t>(li.QuadPart);
    if (bytes64 > (std::numeric_limits<std::size_t>::max)()) {
        Close();
        throw HrError(E_FAIL, "MappedFile: file does not fit in size_t");
    }
    size_ = static_cast<std::size_t>(bytes64);

    // Zero-byte file: nothing to map. CreateFileMappingW with size 0 means
    // "the size of the file" and fails on a zero-length file with
    // ERROR_FILE_INVALID, so we handle that case directly.
    if (size_ == 0) {
        return;
    }

    mapping_ = ::CreateFileMappingW(file_, /*sa=*/nullptr, PAGE_READONLY,
                                    /*hi=*/0, /*lo=*/0, /*name=*/nullptr);
    if (!mapping_) {
        const DWORD err = ::GetLastError();
        Close();
        char msg[256];
        std::snprintf(msg, sizeof(msg),
                      "MappedFile: CreateFileMapping failed for %s "
                      "(Win32 error %lu)",
                      path.string().c_str(), static_cast<unsigned long>(err));
        throw HrError(HRESULT_FROM_WIN32(err), msg);
    }

    void* view = ::MapViewOfFile(mapping_, FILE_MAP_READ, /*hi=*/0,
                                 /*lo=*/0, /*bytes=*/0);
    if (!view) {
        const DWORD err = ::GetLastError();
        Close();
        char msg[256];
        std::snprintf(msg, sizeof(msg),
                      "MappedFile: MapViewOfFile failed for %s "
                      "(Win32 error %lu)",
                      path.string().c_str(), static_cast<unsigned long>(err));
        throw HrError(HRESULT_FROM_WIN32(err), msg);
    }
    base_ = static_cast<std::uint8_t*>(view);
}

MappedFile::~MappedFile() {
    Close();
}

MappedFile::MappedFile(MappedFile&& other) noexcept
    : file_(std::exchange(other.file_, INVALID_HANDLE_VALUE)),
      mapping_(std::exchange(other.mapping_, nullptr)),
      base_(std::exchange(other.base_, nullptr)),
      size_(std::exchange(other.size_, 0)) {}

MappedFile& MappedFile::operator=(MappedFile&& other) noexcept {
    if (this != &other) {
        Close();
        file_    = std::exchange(other.file_, INVALID_HANDLE_VALUE);
        mapping_ = std::exchange(other.mapping_, nullptr);
        base_    = std::exchange(other.base_, nullptr);
        size_    = std::exchange(other.size_, 0);
    }
    return *this;
}

void MappedFile::Close() noexcept {
    if (base_) {
        ::UnmapViewOfFile(base_);
        base_ = nullptr;
    }
    if (mapping_) {
        ::CloseHandle(mapping_);
        mapping_ = nullptr;
    }
    if (file_ != INVALID_HANDLE_VALUE) {
        ::CloseHandle(file_);
        file_ = INVALID_HANDLE_VALUE;
    }
    size_ = 0;
}

}  // namespace tinyvmm::host
