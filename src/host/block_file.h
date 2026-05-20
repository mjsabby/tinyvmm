#pragma once

// Async block-file backend for virtio-blk.
//
// Wraps a Win32 file handle opened with FILE_FLAG_OVERLAPPED and binds it to
// a per-file IOCP. A single worker thread drains the IOCP and dispatches
// completions through a user-supplied callback. The callback runs on the
// worker thread; the caller is responsible for any synchronisation with the
// vCPU thread.
//
// The callback signature passes back the same Request* that was submitted,
// so callers can extend Request with their own state via aggregation (the
// request struct embeds an OVERLAPPED as its first member so CONTAINING_RECORD
// works inside the dispatcher).
//
// We deliberately do NOT use FILE_FLAG_NO_BUFFERING: that requires
// sector-aligned host buffers and lengths, which guest descriptor chains
// don't guarantee. The OS cache is fine for our scale. A FLUSH op forces
// FlushFileBuffers on the worker thread.

#include "common.h"

#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace tinyvmm::host {

class BlockFile {
public:
    struct Request {
        // OVERLAPPED MUST be the first member so the worker can recover the
        // surrounding Request* via CONTAINING_RECORD.
        OVERLAPPED ovl{};

        enum Op : std::uint8_t { OpRead, OpWrite, OpFlush };
        Op  op = OpRead;
        bool ok = false;       // set by worker on completion

        std::uint64_t file_offset = 0;
        void*         buf = nullptr;
        std::uint32_t bytes = 0;

        // Free-form caller bookkeeping. Not touched by BlockFile.
        void* user = nullptr;
    };

    using CompleteFn = std::function<void(Request* req)>;

    BlockFile(const std::wstring& path, bool readonly);
    ~BlockFile();

    BlockFile(const BlockFile&) = delete;
    BlockFile& operator=(const BlockFile&) = delete;

    bool          open()      const { return handle_ != INVALID_HANDLE_VALUE; }
    std::uint64_t size()      const { return size_; }
    bool          readonly()  const { return readonly_; }
    HRESULT       open_hr()   const { return open_hr_; }

    void SetCompletionCallback(CompleteFn fn) { complete_ = std::move(fn); }

    // Spin up the IOCP worker. Must be called before Submit.
    void Start();

    // Stop the IOCP worker (signals + joins). Any in-flight ops are NOT
    // cancelled; the caller is responsible for quiescing the device first.
    void Stop();

    // Submit one async op. Request must remain alive (and the OVERLAPPED
    // untouched) until the completion callback fires. Returns false on
    // synchronous submission failure (req->ok = false, errors_++).
    bool Submit(Request* req);

    std::uint64_t submitted() const { return submitted_.load(); }
    std::uint64_t completed() const { return completed_.load(); }
    std::uint64_t errors()    const { return errors_.load(); }
    std::uint64_t max_inflight() const { return max_inflight_.load(); }

private:
    void WorkerLoop();

    static constexpr ULONG_PTR kShutdownKey = 0x1;
    static constexpr ULONG_PTR kFlushKey    = 0x2;

    HANDLE        handle_   = INVALID_HANDLE_VALUE;
    HANDLE        iocp_     = nullptr;
    std::wstring  path_;
    bool          readonly_ = false;
    std::uint64_t size_     = 0;
    HRESULT       open_hr_  = S_OK;

    CompleteFn    complete_;
    std::thread   worker_;
    std::atomic<bool> stop_{false};

    std::atomic<std::uint64_t> submitted_{0};
    std::atomic<std::uint64_t> completed_{0};
    std::atomic<std::uint64_t> errors_{0};
    std::atomic<std::uint64_t> inflight_{0};       // currently outstanding
    std::atomic<std::uint64_t> max_inflight_{0};   // high-water mark
};

}  // namespace tinyvmm::host
