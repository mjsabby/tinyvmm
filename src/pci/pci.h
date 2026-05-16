#pragma once

// PCI Local Bus Specification 3.0 constants. Just the bits tinyvmm needs --
// no PCIe Extended Config, no segments, single bus 0.

#include "common.h"

#include <cstdint>

namespace tinyvmm::pci {

// Configuration Mechanism #1 port pair.
inline constexpr std::uint16_t kConfigAddressPort = 0xCF8;
inline constexpr std::uint16_t kConfigDataPort    = 0xCFC;

// CONFIG_ADDRESS layout (spec §3.2.2.3.2): bit 31 = enable, 23:16 = bus,
// 15:11 = device, 10:8 = function, 7:2 = dword index. Bits 1:0 are r/o 0
// (CONFIG_DATA inside the dword is selected by the IO access byte address).
inline constexpr std::uint32_t kConfigAddressEnable = 0x80000000u;

// Type 0 header standard register offsets (spec §6.1).
inline constexpr std::uint8_t kCfgVendorId        = 0x00;  // 2
inline constexpr std::uint8_t kCfgDeviceId        = 0x02;  // 2
inline constexpr std::uint8_t kCfgCommand         = 0x04;  // 2
inline constexpr std::uint8_t kCfgStatus          = 0x06;  // 2
inline constexpr std::uint8_t kCfgRevisionId      = 0x08;  // 1
inline constexpr std::uint8_t kCfgProgIf          = 0x09;  // 1
inline constexpr std::uint8_t kCfgSubclass        = 0x0A;  // 1
inline constexpr std::uint8_t kCfgClassCode       = 0x0B;  // 1
inline constexpr std::uint8_t kCfgCacheLineSize   = 0x0C;  // 1
inline constexpr std::uint8_t kCfgLatencyTimer    = 0x0D;  // 1
inline constexpr std::uint8_t kCfgHeaderType      = 0x0E;  // 1
inline constexpr std::uint8_t kCfgBist            = 0x0F;  // 1
inline constexpr std::uint8_t kCfgBar0            = 0x10;  // 4 each, 6 BARs
inline constexpr std::uint8_t kCfgCardbusCisPtr   = 0x28;  // 4
inline constexpr std::uint8_t kCfgSubsysVendorId  = 0x2C;  // 2
inline constexpr std::uint8_t kCfgSubsysId        = 0x2E;  // 2
inline constexpr std::uint8_t kCfgExpansionRom    = 0x30;  // 4
inline constexpr std::uint8_t kCfgCapPtr          = 0x34;  // 1
inline constexpr std::uint8_t kCfgInterruptLine   = 0x3C;  // 1
inline constexpr std::uint8_t kCfgInterruptPin    = 0x3D;  // 1
inline constexpr std::uint8_t kCfgMinGrant        = 0x3E;  // 1
inline constexpr std::uint8_t kCfgMaxLatency      = 0x3F;  // 1

inline constexpr std::uint16_t kCfgSpaceSize      = 0x100;  // legacy 256 B

// Where the capabilities list starts. Standard convention; the first 0x40
// bytes are the header proper.
inline constexpr std::uint8_t kCapListStart       = 0x40;

// COMMAND register bits (spec §6.2.2).
inline constexpr std::uint16_t kCmdIoSpace        = 1u << 0;
inline constexpr std::uint16_t kCmdMemorySpace    = 1u << 1;
inline constexpr std::uint16_t kCmdBusMaster      = 1u << 2;
inline constexpr std::uint16_t kCmdParityErrResp  = 1u << 6;
inline constexpr std::uint16_t kCmdSerrEnable     = 1u << 8;
inline constexpr std::uint16_t kCmdIntxDisable    = 1u << 10;

// STATUS register bits (spec §6.2.3).
inline constexpr std::uint16_t kStatusInterrupt   = 1u << 3;
inline constexpr std::uint16_t kStatusCapList     = 1u << 4;
inline constexpr std::uint16_t kStatus66Mhz       = 1u << 5;

// HEADER_TYPE values.
inline constexpr std::uint8_t kHeaderTypeNormal   = 0x00;
inline constexpr std::uint8_t kHeaderTypeBridge   = 0x01;
inline constexpr std::uint8_t kHeaderTypeMultiFn  = 0x80;  // OR'd in

// BAR type-encoding (low 4 bits of MMIO BAR, low 2 bits of IO BAR).
inline constexpr std::uint32_t kBarIoMarker       = 1u << 0;  // bit0 = 1 => IO
inline constexpr std::uint32_t kBarMmio64         = 2u << 1;  // bits[2:1] = 10
inline constexpr std::uint32_t kBarPrefetchable   = 1u << 3;

// Capability IDs we use (PCI Local Bus 3.0, §6.7).
inline constexpr std::uint8_t kCapIdVendor        = 0x09;     // virtio uses
inline constexpr std::uint8_t kCapIdMsiX          = 0x11;

// Identifier triple. We're single-bus, so callers usually omit bus.
struct Bdf {
    std::uint8_t bus      = 0;
    std::uint8_t device   = 0;
    std::uint8_t function = 0;

    constexpr std::uint16_t Encode() const {
        return static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(bus) << 8) |
            (static_cast<std::uint16_t>(device & 0x1Fu) << 3) |
            (static_cast<std::uint16_t>(function & 0x07u)));
    }
};

// Pull a (bus, dev, fn, reg) tuple out of a CONFIG_ADDRESS value.
struct DecodedAddress {
    bool enable = false;
    std::uint8_t  bus  = 0;
    std::uint8_t  dev  = 0;
    std::uint8_t  fn   = 0;
    std::uint8_t  reg  = 0;  // dword-aligned register offset
};

constexpr DecodedAddress DecodeConfigAddress(std::uint32_t addr) {
    DecodedAddress d{};
    d.enable = (addr & kConfigAddressEnable) != 0;
    d.bus    = static_cast<std::uint8_t>((addr >> 16) & 0xFFu);
    d.dev    = static_cast<std::uint8_t>((addr >> 11) & 0x1Fu);
    d.fn     = static_cast<std::uint8_t>((addr >>  8) & 0x07u);
    // Bottom 2 bits of CONFIG_ADDRESS are reserved 0; the byte offset comes
    // from the IO access port (0xCFC + 0..3).
    d.reg    = static_cast<std::uint8_t>(addr & 0xFCu);
    return d;
}

}  // namespace tinyvmm::pci
