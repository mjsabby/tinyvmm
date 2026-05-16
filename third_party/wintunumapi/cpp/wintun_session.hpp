// SPDX-License-Identifier: MIT
//
// Clean-room user-mode wintun session for C++20.
// Implements only the runtime (non-admin) protocol: TUN_IOCTL_REGISTER_RINGS
// (0xCA6CE5C0) plus ring-buffer producer/consumer access.
//
// The wintun driver itself is unaffiliated with this code; this file
// implements an interoperable client of its published shared-memory ABI.

#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <string_view>
#include <system_error>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace wintun {

inline constexpr std::uint32_t min_ring_capacity  = 0x00020000;  // 128 KiB
inline constexpr std::uint32_t max_ring_capacity  = 0x04000000;  // 64 MiB
inline constexpr std::uint32_t max_ip_packet_size = 0x0000FFFF;

// Distinct status returned from the non-throwing send/recv methods.
enum class status : std::uint32_t {
    ok               = 0,
    empty            = ERROR_NO_MORE_ITEMS,
    full             = ERROR_BUFFER_OVERFLOW,
    eof              = ERROR_HANDLE_EOF,
    invalid_data     = ERROR_INVALID_DATA,
};

// Parameters for `session::adopt`. The three HANDLEs MUST be valid in the
// current process (typically produced by `DuplicateHandle` from a more
// privileged service). All four offsets/sizes describe a section laid out
// exactly the way `wintun.sys` expects: two `TUN_RING` regions back-to-back
// in the same section, each `ring_size = sizeof(TUN_RING)+capacity+0x10000`.
//
// Ownership: on success, `session` takes ownership of `section`,
// `send_tail_moved`, and `recv_tail_moved` and will `CloseHandle` them on
// destruction. The caller MUST NOT close them after a successful `adopt`.
// On failure (`adopt` throws), the caller retains ownership.
struct adopt_params {
    HANDLE        section;            // file-mapping section (mappable r/w)
    HANDLE        send_tail_moved;    // auto-reset event, signalled on send tail advance
    HANDLE        recv_tail_moved;    // auto-reset event, signalled on recv tail advance
    std::uint32_t capacity;           // ring capacity in bytes (power of two)
    std::uint32_t ring_size;          // per-ring byte size = 12 + capacity + 0x10000
    std::uint32_t send_ring_offset;   // bytes from section base to send ring (== 0)
    std::uint32_t recv_ring_offset;   // bytes from section base to recv ring (== ring_size)
    std::uint64_t total_size;         // bytes mapped from section (== 2 * ring_size)
};

class session {
public:
    // Opens the wintun device at `device_path` and registers a fresh pair of
    // rings. Throws std::system_error on any failure (bad capacity, device
    // not found, IOCTL rejected, etc.).
    //
    // `capacity` must be a power of two in [min_ring_capacity, max_ring_capacity].
    static session open(std::wstring_view device_path, std::uint32_t capacity);

    // Adopt rings that some other (typically more privileged) process
    // already registered with `wintun.sys`. Maps the section into our
    // address space; performs NO `CreateFileW` or `DeviceIoControl` calls.
    //
    // This is the path that lets an unelevated client drive Wintun rings
    // when the privileged `TUN_IOCTL_REGISTER_RINGS` has already been
    // performed on its behalf (see `WintunSvc`).
    //
    // Throws `std::system_error` on `MapViewOfFile` failure or bad
    // capacity. On throw, the caller retains the input HANDLEs.
    static session adopt(const adopt_params& params);

    ~session() noexcept;

    session(const session&)            = delete;
    session& operator=(const session&) = delete;
    session(session&& other) noexcept;
    session& operator=(session&& other) noexcept;

    // Reserve `size` bytes in the outgoing ring and return a writable span you
    // fill with the layer-3 packet. Follow up with send_packet(packet) when
    // done. Returns an empty span and sets `st` on failure.
    [[nodiscard]] std::span<std::byte>
    allocate_send_packet(std::uint32_t size, status& st) noexcept;

    // Commit a buffer previously returned by allocate_send_packet().
    // Thread-safe with respect to other allocate/send pairs (slots are
    // released to the driver in allocation order).
    void send_packet(std::span<std::byte> packet) noexcept;

    // Try to dequeue one incoming packet. Returns an empty span and sets `st`
    // when nothing is available (st == empty), the adapter is shutting down
    // (st == eof), or the ring is corrupt (st == invalid_data).
    [[nodiscard]] std::span<const std::byte>
    receive_packet(status& st) noexcept;

    // Release a buffer obtained from receive_packet(). Thread-safe.
    void release_receive_packet(std::span<const std::byte> packet) noexcept;

    // Auto-reset event the driver signals when the Send ring's Tail moves
    // (i.e. new incoming data is available). Wait on it after receive_packet
    // returns `status::empty`. The handle is owned by the session.
    [[nodiscard]] HANDLE read_wait_event() const noexcept;

private:
    struct impl;
    impl* _p = nullptr;

    explicit session(impl* p) noexcept : _p(p) {}
};

} // namespace wintun
