#pragma once

// Shared L2 / ARP helpers for virtio-net backends.
//
// Multiple virtio-net backends (wintun, usernet, ...) terminate the
// guest's Ethernet at tinyvmm and originate/inspect IP packets on the
// host side. They share the same wire-format POD types, big-endian
// helpers, and chain-of-readable-buffers utilities, all collected here
// for reuse.

#include "common.h"
#include "virtqueue.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <span>

namespace tinyvmm::virtio::net_l2 {

constexpr std::size_t kVirtioNetHdrSize = 12;
constexpr std::size_t kEthHdrSize       = 14;

constexpr std::uint16_t kEthTypeIp4     = 0x0800;
constexpr std::uint16_t kEthTypeArp     = 0x0806;

constexpr std::uint16_t kArpHardwareEth = 1;
constexpr std::uint16_t kArpOpRequest   = 1;
constexpr std::uint16_t kArpOpReply     = 2;

#pragma pack(push, 1)
// Ethernet II header. `ether_type` is BE on the wire.
struct EthHeader {
    std::uint8_t dst[6];
    std::uint8_t src[6];
    std::uint8_t ether_type_be[2];
};
static_assert(sizeof(EthHeader) == 14);

// RFC 826 IPv4-over-Ethernet ARP. All multi-byte fields BE on wire.
struct ArpIpv4 {
    std::uint8_t htype_be[2];   // 1 = Ethernet
    std::uint8_t ptype_be[2];   // 0x0800 = IPv4
    std::uint8_t hlen;          // 6
    std::uint8_t plen;          // 4
    std::uint8_t opcode_be[2];  // 1 = request, 2 = reply
    std::uint8_t sha[6];        // sender MAC
    std::uint8_t spa[4];        // sender IPv4
    std::uint8_t tha[6];        // target MAC
    std::uint8_t tpa[4];        // target IPv4
};
static_assert(sizeof(ArpIpv4) == 28);
#pragma pack(pop)

constexpr std::uint16_t Be16(std::span<const std::uint8_t, 2> p) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}
constexpr void Wr16Be(std::span<std::uint8_t, 2> p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v & 0xFF);
}
constexpr std::uint32_t Be32(std::span<const std::uint8_t, 4> p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) <<  8) |
            static_cast<std::uint32_t>(p[3]);
}
constexpr void Wr32Be(std::span<std::uint8_t, 4> p, std::uint32_t v) {
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >>  8);
    p[3] = static_cast<std::uint8_t>(v & 0xFF);
}

// Walk the readable buffers of a chain, summing total bytes and
// copying up to `peek.size()` prefix bytes into `peek`. Used to
// classify a TX frame by EtherType without materialising it.
struct ReadableSummary { std::size_t total; std::size_t peeked; };
inline ReadableSummary SummarizeReadable(const PoppedChain& chain,
                                          std::span<std::uint8_t> peek) {
    ReadableSummary s{};
    for (const auto& b : chain.bufs) {
        if (b.write) continue;
        const auto sz = b.bytes.size();
        if (s.peeked < peek.size()) {
            const std::size_t take = std::min(peek.size() - s.peeked, sz);
            std::memcpy(peek.data() + s.peeked, b.bytes.data(), take);
            s.peeked += take;
        }
        s.total += sz;
    }
    return s;
}

// Concatenate the readable buffers of a chain starting at logical
// offset `skip` into `dst`. Returns bytes copied (clamped to
// dst.size()).
inline std::size_t CopyReadable(const PoppedChain& chain,
                                 std::size_t skip,
                                 std::span<std::uint8_t> dst) {
    std::size_t logical = 0;
    std::size_t written = 0;
    for (const auto& b : chain.bufs) {
        if (b.write) continue;
        const auto sz = b.bytes.size();
        if (logical + sz <= skip) {
            logical += sz;
            continue;
        }
        const std::size_t src_off = (skip > logical) ? (skip - logical) : 0;
        const std::size_t avail   = sz - src_off;
        const std::size_t take    = std::min(avail, dst.size() - written);
        std::memcpy(dst.data() + written, b.bytes.data() + src_off, take);
        written += take;
        logical += sz;
        if (written == dst.size()) break;
    }
    return written;
}

}  // namespace tinyvmm::virtio::net_l2
