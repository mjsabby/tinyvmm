// SPDX-License-Identifier: MIT
//
// Clean-room C++20 wintun session client. See wintun_session.hpp for API.

#include "wintun_session.hpp"

#include <atomic>
#include <cstring>
#include <mutex>
#include <memory>

#include <winioctl.h>

namespace wintun {
namespace {

// CTL_CODE(0xCA6C, 0x970, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA).
inline constexpr DWORD ioctl_register_rings = 0xCA6CE5C0u;

inline constexpr std::uint32_t alignment    = sizeof(std::uint32_t);
inline constexpr std::uint32_t release_flag = 0x80000000u;
inline constexpr DWORD         spin_count   = 0x10000;

constexpr std::uint32_t align_up(std::uint32_t x) noexcept {
    return (x + alignment - 1) & ~(alignment - 1);
}
constexpr std::uint32_t ring_wrap(std::uint32_t v, std::uint32_t cap) noexcept {
    return v & (cap - 1);
}
constexpr bool is_pow2(std::uint32_t x) noexcept {
    return x != 0 && (x & (x - 1)) == 0;
}

// 12-byte header followed by Data[Capacity + slack].
struct ring_header {
    std::atomic<std::uint32_t> head;
    std::atomic<std::uint32_t> tail;
    std::atomic<std::int32_t>  alertable;
    // followed by `unsigned char data[]`
};
static_assert(sizeof(ring_header) == 12, "TUN_RING header must be 12 bytes");

constexpr std::uint32_t max_packet_size = align_up(sizeof(std::uint32_t) + max_ip_packet_size);
constexpr std::uint32_t ring_slack      = max_packet_size - alignment;     // 0x10000

constexpr std::uint32_t ring_buffer_bytes(std::uint32_t cap) noexcept {
    return static_cast<std::uint32_t>(sizeof(ring_header)) + cap + ring_slack;
}

// Layout passed by IOCTL. Matches driver expectation.
struct register_rings {
    struct descriptor {
        std::uint32_t ring_size;
        std::uint32_t _pad;            // implicit 8-byte alignment
        ring_header*  ring;
        HANDLE        tail_moved;
    } send, receive;
};

inline std::uint8_t* ring_data(ring_header* r) noexcept {
    return reinterpret_cast<std::uint8_t*>(r) + sizeof(ring_header);
}

// Per-packet header inside the ring; size may carry the top-bit release flag.
struct packet_header {
    std::atomic<std::uint32_t> size;
};
static_assert(sizeof(packet_header) == 4, "TUN_PACKET header must be 4 bytes");

inline std::uint8_t* packet_data(packet_header* p) noexcept {
    return reinterpret_cast<std::uint8_t*>(p) + sizeof(packet_header);
}
inline packet_header* packet_from_data(const std::uint8_t* data) noexcept {
    return reinterpret_cast<packet_header*>(
        const_cast<std::uint8_t*>(data) - sizeof(packet_header));
}

[[noreturn]] void throw_last_error(const char* what) {
    DWORD e = GetLastError();
    throw std::system_error(static_cast<int>(e), std::system_category(), what);
}

} // namespace

struct session::impl {
    std::uint32_t  capacity = 0;
    register_rings rings    = {};
    HANDLE         device   = INVALID_HANDLE_VALUE;
    void*          region   = nullptr;

    // For sessions created via `adopt`: the file-mapping section we mapped
    // and the fact that `region` must be released with `UnmapViewOfFile`
    // rather than `VirtualFree`. For sessions created via `open`,
    // `adopted` is false and `section` stays null.
    bool   adopted = false;
    HANDLE section = nullptr;

    // Producer side (Receive ring): client -> driver.
    std::mutex    send_lock;
    std::uint32_t tail            = 0;
    std::uint32_t tail_release    = 0;
    std::uint32_t send_in_flight  = 0;

    // Consumer side (Send ring): driver -> client.
    std::mutex    recv_lock;
    std::uint32_t head            = 0;
    std::uint32_t head_release    = 0;
    std::uint32_t recv_in_flight  = 0;
};

session::session(session&& other) noexcept : _p(other._p) { other._p = nullptr; }
session& session::operator=(session&& other) noexcept {
    if (this != &other) {
        this->~session();
        _p = other._p;
        other._p = nullptr;
    }
    return *this;
}

session::~session() noexcept {
    if (!_p) return;
    // For `open`-created sessions we own:
    //   device (CloseHandle), send/recv tail_moved (CloseHandle),
    //   region (VirtualFree).
    // For `adopt`-created sessions we own:
    //   send/recv tail_moved (duplicated to us; CloseHandle),
    //   region (mapped view; UnmapViewOfFile),
    //   section (duplicated to us; CloseHandle).
    if (_p->adopted) {
        if (_p->rings.send.tail_moved)    ::CloseHandle(_p->rings.send.tail_moved);
        if (_p->rings.receive.tail_moved) ::CloseHandle(_p->rings.receive.tail_moved);
        if (_p->region)                   ::UnmapViewOfFile(_p->region);
        if (_p->section)                  ::CloseHandle(_p->section);
    } else {
        if (_p->device != INVALID_HANDLE_VALUE) ::CloseHandle(_p->device);
        if (_p->rings.send.tail_moved)         ::CloseHandle(_p->rings.send.tail_moved);
        if (_p->rings.receive.tail_moved)      ::CloseHandle(_p->rings.receive.tail_moved);
        if (_p->region)                        ::VirtualFree(_p->region, 0, MEM_RELEASE);
    }
    delete _p;
    _p = nullptr;
}

session session::open(std::wstring_view device_path, std::uint32_t capacity) {
    if (capacity < min_ring_capacity || capacity > max_ring_capacity || !is_pow2(capacity))
        throw std::system_error(ERROR_INVALID_PARAMETER, std::system_category(),
                                "wintun::session::open: bad capacity");

    auto p = std::make_unique<impl>();
    p->capacity = capacity;

    const std::uint32_t ring_bytes = ring_buffer_bytes(capacity);

    p->region = ::VirtualAlloc(nullptr, static_cast<SIZE_T>(ring_bytes) * 2,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p->region) throw_last_error("VirtualAlloc");

    auto* send_ring    = reinterpret_cast<ring_header*>(p->region);
    auto* receive_ring = reinterpret_cast<ring_header*>(
        static_cast<std::uint8_t*>(p->region) + ring_bytes);

    p->rings.send.ring_size       = ring_bytes;
    p->rings.send.ring            = send_ring;
    p->rings.send.tail_moved      = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!p->rings.send.tail_moved) throw_last_error("CreateEventW(send)");

    p->rings.receive.ring_size    = ring_bytes;
    p->rings.receive.ring         = receive_ring;
    p->rings.receive.tail_moved   = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!p->rings.receive.tail_moved) throw_last_error("CreateEventW(receive)");

    std::wstring path(device_path);
    p->device = ::CreateFileW(path.c_str(),
                              GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, 0, nullptr);
    if (p->device == INVALID_HANDLE_VALUE) throw_last_error("CreateFileW");

    DWORD returned = 0;
    if (!::DeviceIoControl(p->device, ioctl_register_rings,
                           &p->rings, sizeof(p->rings),
                           nullptr, 0, &returned, nullptr))
        throw_last_error("DeviceIoControl(TUN_IOCTL_REGISTER_RINGS)");

    (void)spin_count;
    return session{p.release()};
}

session session::adopt(const adopt_params& params) {
    if (params.capacity < min_ring_capacity ||
        params.capacity > max_ring_capacity ||
        !is_pow2(params.capacity)) {
        throw std::system_error(ERROR_INVALID_PARAMETER, std::system_category(),
                                "wintun::session::adopt: bad capacity");
    }
    const std::uint32_t expected_ring = ring_buffer_bytes(params.capacity);
    if (params.ring_size != expected_ring) {
        throw std::system_error(ERROR_INVALID_PARAMETER, std::system_category(),
                                "wintun::session::adopt: ring_size mismatch");
    }
    if (params.send_ring_offset != 0 ||
        params.recv_ring_offset != expected_ring ||
        params.total_size != static_cast<std::uint64_t>(expected_ring) * 2) {
        throw std::system_error(ERROR_INVALID_PARAMETER, std::system_category(),
                                "wintun::session::adopt: layout mismatch");
    }
    if (!params.section || !params.send_tail_moved || !params.recv_tail_moved) {
        throw std::system_error(ERROR_INVALID_HANDLE, std::system_category(),
                                "wintun::session::adopt: null handle");
    }

    auto p = std::make_unique<impl>();
    p->capacity = params.capacity;
    p->adopted  = true;
    p->section  = params.section;

    void* base = ::MapViewOfFile(params.section,
                                 FILE_MAP_READ | FILE_MAP_WRITE,
                                 0, 0, 0);
    if (!base) throw_last_error("MapViewOfFile (adopt)");
    p->region = base;

    auto* send_ring = reinterpret_cast<ring_header*>(
        static_cast<std::uint8_t*>(base) + params.send_ring_offset);
    auto* recv_ring = reinterpret_cast<ring_header*>(
        static_cast<std::uint8_t*>(base) + params.recv_ring_offset);

    p->rings.send.ring_size       = params.ring_size;
    p->rings.send.ring            = send_ring;
    p->rings.send.tail_moved      = params.send_tail_moved;

    p->rings.receive.ring_size    = params.ring_size;
    p->rings.receive.ring         = recv_ring;
    p->rings.receive.tail_moved   = params.recv_tail_moved;

    // The service has already performed REGISTER_RINGS, which is what
    // makes the ring atomics start tracking driver activity. We don't
    // touch the headers from this side; they're already live.
    return session{p.release()};
}

HANDLE session::read_wait_event() const noexcept {
    return _p->rings.send.tail_moved;
}

std::span<std::byte>
session::allocate_send_packet(std::uint32_t size, status& st) noexcept {
    if (size == 0 || size > max_ip_packet_size) {
        st = status::invalid_data;
        return {};
    }
    auto* r = _p->rings.receive.ring;

    std::lock_guard<std::mutex> g(_p->send_lock);

    if (_p->tail >= _p->capacity) { st = status::eof; return {}; }
    const std::uint32_t aligned  = align_up(static_cast<std::uint32_t>(sizeof(packet_header)) + size);
    const std::uint32_t buf_head = r->head.load(std::memory_order_acquire);
    if (buf_head >= _p->capacity) { st = status::eof; return {}; }

    const std::uint32_t space = ring_wrap(buf_head - _p->tail - alignment, _p->capacity);
    if (aligned > space) { st = status::full; return {}; }

    auto* hdr = reinterpret_cast<packet_header*>(ring_data(r) + _p->tail);
    hdr->size.store(size | release_flag, std::memory_order_relaxed);
    auto* data = packet_data(hdr);

    _p->tail = ring_wrap(_p->tail + aligned, _p->capacity);
    ++_p->send_in_flight;

    st = status::ok;
    return { reinterpret_cast<std::byte*>(data), size };
}

void session::send_packet(std::span<std::byte> packet) noexcept {
    if (packet.empty()) return;
    auto* r = _p->rings.receive.ring;

    std::lock_guard<std::mutex> g(_p->send_lock);

    auto* released = packet_from_data(
        reinterpret_cast<const std::uint8_t*>(packet.data()));
    released->size.fetch_and(~release_flag, std::memory_order_relaxed);

    while (_p->send_in_flight) {
        auto* peek = reinterpret_cast<packet_header*>(
            ring_data(r) + _p->tail_release);
        std::uint32_t sz = peek->size.load(std::memory_order_relaxed);
        if (sz & release_flag) break;
        _p->tail_release = ring_wrap(
            _p->tail_release + align_up(static_cast<std::uint32_t>(sizeof(packet_header)) + sz),
            _p->capacity);
        --_p->send_in_flight;
    }

    if (r->tail.load(std::memory_order_relaxed) != _p->tail_release) {
        r->tail.store(_p->tail_release, std::memory_order_release);
        // Mandatory StoreLoad fence between publishing Tail and inspecting Alertable.
        std::atomic_thread_fence(std::memory_order_seq_cst);
        if (r->alertable.load(std::memory_order_acquire))
            ::SetEvent(_p->rings.receive.tail_moved);
    }
}

std::span<const std::byte>
session::receive_packet(status& st) noexcept {
    auto* r = _p->rings.send.ring;

    std::lock_guard<std::mutex> g(_p->recv_lock);

    if (_p->head >= _p->capacity) { st = status::eof; return {}; }
    const std::uint32_t buf_tail = r->tail.load(std::memory_order_acquire);
    if (buf_tail >= _p->capacity) { st = status::eof; return {}; }    // driver shutdown sentinel
    if (_p->head == buf_tail)    { st = status::empty; return {}; }

    const std::uint32_t content = ring_wrap(buf_tail - _p->head, _p->capacity);
    if (content < sizeof(packet_header)) { st = status::invalid_data; return {}; }

    auto* hdr = reinterpret_cast<packet_header*>(ring_data(r) + _p->head);
    const std::uint32_t size = hdr->size.load(std::memory_order_relaxed);
    if (size > max_ip_packet_size) { st = status::invalid_data; return {}; }

    const std::uint32_t aligned = align_up(static_cast<std::uint32_t>(sizeof(packet_header)) + size);
    if (aligned > content) { st = status::invalid_data; return {}; }

    auto* data = packet_data(hdr);
    _p->head = ring_wrap(_p->head + aligned, _p->capacity);
    ++_p->recv_in_flight;

    st = status::ok;
    return { reinterpret_cast<const std::byte*>(data), size };
}

void session::release_receive_packet(std::span<const std::byte> packet) noexcept {
    if (packet.empty()) return;
    auto* r = _p->rings.send.ring;

    std::lock_guard<std::mutex> g(_p->recv_lock);

    auto* released = packet_from_data(
        reinterpret_cast<const std::uint8_t*>(packet.data()));
    released->size.fetch_or(release_flag, std::memory_order_relaxed);

    while (_p->recv_in_flight) {
        auto* peek = reinterpret_cast<packet_header*>(
            ring_data(r) + _p->head_release);
        std::uint32_t sz = peek->size.load(std::memory_order_relaxed);
        if ((sz & release_flag) == 0) break;
        _p->head_release = ring_wrap(
            _p->head_release + align_up(static_cast<std::uint32_t>(sizeof(packet_header)) + (sz & ~release_flag)),
            _p->capacity);
        --_p->recv_in_flight;
    }
    r->head.store(_p->head_release, std::memory_order_release);
}

} // namespace wintun
