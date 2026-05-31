#include "block_file.h"

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <mutex>

#include <winioctl.h>

namespace tinyvmm::host {

BlockFile::BlockFile(const std::wstring& path, bool readonly)
    : path_(path), readonly_(readonly) {
    const DWORD access = readonly_ ? GENERIC_READ
                                    : (GENERIC_READ | GENERIC_WRITE);
    const DWORD share = readonly_ ? FILE_SHARE_READ
                                   : (FILE_SHARE_READ | FILE_SHARE_WRITE);
    handle_ = CreateFileW(path_.c_str(), access, share, /*sa=*/nullptr,
                          OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
                          /*tmpl=*/nullptr);
    if (handle_ == INVALID_HANDLE_VALUE) {
        open_hr_ = HRESULT_FROM_WIN32(GetLastError());
        return;
    }
    LARGE_INTEGER li{};
    if (!GetFileSizeEx(handle_, &li)) {
        open_hr_ = HRESULT_FROM_WIN32(GetLastError());
        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
        return;
    }
    size_ = static_cast<std::uint64_t>(li.QuadPart);
}

BlockFile::~BlockFile() {
    Stop();
    if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
    if (iocp_) CloseHandle(iocp_);}

void BlockFile::Start() {
    if (handle_ == INVALID_HANDLE_VALUE) {
        Fatal("BlockFile::Start on closed file");
    }
    if (worker_.joinable()) return;
    iocp_ = CreateIoCompletionPort(handle_, /*existing=*/nullptr,
                                   /*key=*/0, /*threads=*/1);
    if (!iocp_) {
        Fatal("BlockFile: CreateIoCompletionPort failed");
    }
    stop_.store(false);
    worker_ = std::thread([this]() { WorkerLoop(); });
}

void BlockFile::Stop() {
    if (!worker_.joinable()) return;
    stop_.store(true);
    PostQueuedCompletionStatus(iocp_, 0, kShutdownKey, /*ovl=*/nullptr);
    worker_.join();
}

bool BlockFile::ZeroRange(std::uint64_t offset, std::uint64_t length) {
    if (readonly_ || handle_ == INVALID_HANDLE_VALUE) return false;
    if (length == 0) return true;
    // Bounds: refuse if the range escapes the file. (Caller should have
    // already bounds-checked, but a defensive 2nd check is cheap.)
    if (offset > size_ || length > size_ - offset) return false;

    // Mark the file sparse on first use so SET_ZERO_DATA actually
    // deallocates clusters instead of writing physical zeros.
    // FSCTL_SET_SPARSE on a non-NTFS volume (e.g. FAT32) fails with
    // ERROR_INVALID_FUNCTION; we treat that as a soft failure and
    // continue -- SET_ZERO_DATA still works, it just writes zeros.
    std::call_once(sparse_once_, [this]() {
        FILE_SET_SPARSE_BUFFER sb{};
        sb.SetSparse = TRUE;
        DWORD ret = 0;
        BOOL ok = DeviceIoControl(handle_, FSCTL_SET_SPARSE,
                                   &sb, sizeof(sb), nullptr, 0,
                                   &ret, /*lpOverlapped=*/nullptr);
        sparse_ok_.store(ok == TRUE, std::memory_order_release);
    });

    FILE_ZERO_DATA_INFORMATION zd{};
    zd.FileOffset.QuadPart      = static_cast<LONGLONG>(offset);
    zd.BeyondFinalZero.QuadPart = static_cast<LONGLONG>(offset + length);
    DWORD ret = 0;
    BOOL ok = DeviceIoControl(handle_, FSCTL_SET_ZERO_DATA,
                               &zd, sizeof(zd), nullptr, 0,
                               &ret, /*lpOverlapped=*/nullptr);
    return ok == TRUE;
}

bool BlockFile::Submit(Request* req) {
    if (!req) return false;
    submitted_.fetch_add(1);
    req->ok = false;

    // Track high-water mark of outstanding requests. This is the bound
    // on virtio-blk queue depth actually reached against this disk; the
    // blk-test asserts max_inflight > 1 to prove its parallel writers
    // were actually parallel from the backend's point of view.
    const std::uint64_t cur = inflight_.fetch_add(1) + 1;
    std::uint64_t prev = max_inflight_.load(std::memory_order_relaxed);
    while (cur > prev &&
           !max_inflight_.compare_exchange_weak(prev, cur,
                                                std::memory_order_relaxed)) {
        // prev was updated by compare_exchange_weak; retry until cur <= prev
        // or the CAS sticks.
    }

    if (req->op == Request::OpFlush) {
        // Defer the (sync) FlushFileBuffers to the worker thread so we don't
        // stall the vCPU. PostQueuedCompletionStatus with the dedicated
        // kFlushKey lets the worker recognise the op without inspecting the
        // OVERLAPPED.
        std::memset(&req->ovl, 0, sizeof(OVERLAPPED));
        if (!PostQueuedCompletionStatus(iocp_, /*bytes=*/0,
                                         kFlushKey, &req->ovl)) {
            inflight_.fetch_sub(1);
            errors_.fetch_add(1);
            return false;
        }
        return true;
    }

    std::memset(&req->ovl, 0, sizeof(OVERLAPPED));
    req->ovl.Offset     = static_cast<DWORD>(req->file_offset & 0xFFFFFFFFu);
    req->ovl.OffsetHigh = static_cast<DWORD>(req->file_offset >> 32);

    BOOL started = FALSE;
    if (req->op == Request::OpRead) {
        started = ReadFile(handle_, req->buf, req->bytes, /*read=*/nullptr,
                            &req->ovl);
    } else {
        if (readonly_) {
            inflight_.fetch_sub(1);
            errors_.fetch_add(1);
            return false;
        }
        started = WriteFile(handle_, req->buf, req->bytes, /*written=*/nullptr,
                             &req->ovl);
    }
    if (!started) {
        const DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            inflight_.fetch_sub(1);
            errors_.fetch_add(1);
            return false;
        }
    }
    return true;
}

void BlockFile::WorkerLoop() {
    while (true) {
        DWORD bytes = 0;
        ULONG_PTR key = 0;
        OVERLAPPED* ovl = nullptr;
        const BOOL ok = GetQueuedCompletionStatus(iocp_, &bytes, &key, &ovl,
                                                   INFINITE);

        if (key == kShutdownKey) return;
        if (!ovl) {
            // Spurious wakeup (shouldn't happen with INFINITE) -- loop.
            continue;
        }
        // The SDK's CONTAINING_RECORD macro uses the `&((T*)0)->field`
        // idiom, which is a member-access through a null pointer and
        // trips UBSan even though it works on every real compiler.
        // Use standard `offsetof` for the same effect without the UB.
        Request* req = reinterpret_cast<Request*>(
            reinterpret_cast<char*>(ovl) - offsetof(Request, ovl));
        if (key == kFlushKey || req->op == Request::OpFlush) {
            req->ok = (FlushFileBuffers(handle_) != FALSE);
        } else {
            req->ok = (ok != FALSE && bytes == req->bytes);
        }
        if (!req->ok) errors_.fetch_add(1);
        completed_.fetch_add(1);
        inflight_.fetch_sub(1);
        if (complete_) complete_(req);
    }
}

}  // namespace tinyvmm::host
