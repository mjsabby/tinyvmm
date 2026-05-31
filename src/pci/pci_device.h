#pragma once

// PCI device base class. Owns a 256-byte configuration space buffer plus a
// table of 6 BAR descriptors. Subclasses populate identity / BAR shape /
// capabilities in their constructor; the bus calls ConfigRead / ConfigWrite
// for guest-side accesses.
//
// Lifecycle:
//   1. Subclass ctor calls set_ids/set_class/DeclareXxxBar/AppendCapability.
//   2. PciBus::AddDevice(...) pre-assigns BAR base addresses from its own GPA
//      pool. Linux's PCI allocator usually keeps pre-assigned BARs as-is.
//   3. Guest probes BAR sizes via the write-all-1s protocol.
//   4. Guest writes COMMAND with MEMORY_SPACE -> bus calls OnBarMapped for
//      every MMIO BAR with a sane base. (And OnBarUnmapped on the way out.)
//   5. Subclass installs / removes its MMIO handlers in those hooks.

#include "common.h"
#include "pci.h"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace tinyvmm::pci {

class PciBus;  // forward

enum class BarType : std::uint8_t {
    None    = 0,
    Io      = 1,
    Mmio32  = 2,  // 32-bit, non-prefetchable
    Mmio64  = 3,  // 64-bit -- occupies BAR[i] (low) + BAR[i+1] (high)
};

struct Bar {
    BarType type        = BarType::None;
    bool    prefetchable = false;
    std::uint32_t size  = 0;  // bytes; power of two; >= 16 for IO, >= 128 MMIO

    // The (writable) value programmed into the BAR by software. Low size-mask
    // bits always read back as zero; the type-encoding bits in [3:0] (MMIO)
    // or [1:0] (IO) are OR'd in on read.
    std::uint32_t value_lo = 0;
    std::uint32_t value_hi = 0;  // Mmio64 only

    bool          mapped     = false;       // currently visible to guest?
    std::uint64_t mapped_gpa = 0;           // current decode base
};

class PciDevice {
public:
    virtual ~PciDevice() = default;

    PciDevice(const PciDevice&) = delete;
    PciDevice& operator=(const PciDevice&) = delete;

    virtual const char* name() const = 0;

    // Sized access from the bus. offset is byte offset within 256-byte config
    // space; size is 1/2/4 bytes (CFG #1 supports byte granularity through
    // 0xCFC+0..3). Returns the read value in [0..2^(8*size)), or accepts the
    // write side effect (BAR sizing, COMMAND.MEM_SPACE, etc.).
    std::uint32_t ConfigRead(std::uint32_t offset, std::uint32_t size);
    void          ConfigWrite(std::uint32_t offset, std::uint32_t size,
                              std::uint32_t value);

    const Bar& bar(int idx) const { return bars_[idx]; }
    Bar&       mut_bar(int idx)   { return bars_[idx]; }
    std::uint16_t command() const;
    std::uint16_t status()  const;

    // Read raw config bytes (no side effects). For host-side tests only.
    std::uint32_t cfg_read32(std::uint32_t offset) const;
    std::uint16_t cfg_read16(std::uint32_t offset) const;
    std::uint8_t  cfg_read8 (std::uint32_t offset) const;

    // For PciBus to drive pre-assignment + remap-on-COMMAND.
    void SetBarBase(int idx, std::uint64_t gpa);

    // -- Setup helpers usable by external capability helpers (e.g. MsiX).
    //
    // These are declared public so an MSI-X / virtio cap helper can install
    // itself into an arbitrary PciDevice without becoming a subclass. They
    // are intended for ctor-time use; calling them after the guest has
    // booted is undefined.
    std::uint32_t AppendCapability(std::uint8_t cap_id,
                                   std::uint32_t payload_size);
    std::uint8_t* mut_cfg_ptr(std::uint32_t offset) { return &cfg_[offset]; }
    // OR `mask` into the writable-bit mask at `offset` (1 bit = software-
    // writable). Used by cap helpers to mark cap-control registers writable.
    void set_writable_byte(std::uint32_t offset, std::uint8_t mask) {
        writable_mask_[offset] |= mask;
    }

    // ----- M33.4 save/restore -------------------------------------------
    //
    // Persists the 256-byte cfg buffer, the per-byte writable mask, all 6
    // BAR descriptors, and the capability allocation pointer. ApplyState
    // writes fields DIRECTLY into bars_[] without invoking the
    // OnBarMapped / OnBarUnmapped hooks (the subclass-specific
    // installation of MMIO handlers is the subclass's responsibility, and
    // for virtio-pci it happens via PciTransport::InstallBarHandlers_
    // called from PciTransport::ApplyState).
    struct BarState {
        std::uint8_t  type         = 0;   // BarType
        std::uint8_t  prefetchable = 0;
        std::uint32_t size         = 0;
        std::uint32_t value_lo     = 0;
        std::uint32_t value_hi     = 0;
        std::uint8_t  mapped       = 0;
        std::uint64_t mapped_gpa   = 0;
    };
    struct State {
        std::uint8_t  cfg[kCfgSpaceSize]            = {};
        std::uint8_t  writable_mask[kCfgSpaceSize]  = {};
        std::array<BarState, 6> bars{};
        std::uint32_t cap_next_alloc                = 0;
    };

    // Encoded payload size: 256 + 256 + 6*32 + 4 = 708 bytes.
    static constexpr std::size_t kEncodedSize =
        kCfgSpaceSize + kCfgSpaceSize + 6u * 32u + 4u;

    State CaptureState() const;
    void  ApplyState(const State& s);

    static std::size_t EncodeState(const State& s,
                                   std::vector<std::uint8_t>& out);
    static State       DecodeState(std::span<const std::uint8_t> bytes);

protected:
    PciDevice() = default;

    // Subclass setup helpers. Call these in the constructor.
    void set_ids(std::uint16_t vendor_id, std::uint16_t device_id,
                 std::uint16_t subsys_vendor_id = 0,
                 std::uint16_t subsys_id = 0);
    void set_class(std::uint8_t class_code, std::uint8_t subclass,
                   std::uint8_t prog_if = 0, std::uint8_t revision = 0);
    void set_interrupt_pin(std::uint8_t pin);  // 0 = none, 1 = INTA, ...

    // Declare a BAR. `size` must be a power of two. For 64-bit MMIO, occupies
    // BAR[idx] (low half) and BAR[idx+1] (high half).
    void DeclareIoBar     (int idx, std::uint32_t size);
    void DeclareMmio32Bar (int idx, std::uint32_t size,
                           bool prefetchable = false);
    void DeclareMmio64Bar (int idx, std::uint32_t size,
                           bool prefetchable = true);

    // Hooks invoked by ConfigWrite when a BAR becomes (or stops being)
    // visible. Subclass overrides to install / remove its MMIO handlers.
    // `size` matches Bar::size for the BAR being mapped (full 64-bit size
    // is reported on the low half of a 64-bit pair; the high half does not
    // receive its own OnBarMapped call).
    virtual void OnBarMapped  (int /*idx*/, std::uint64_t /*gpa*/,
                                std::uint32_t /*size*/) {}
    virtual void OnBarUnmapped(int /*idx*/) {}

    // Subclasses with custom register semantics (config_generation, ISR
    // status read-clear, etc.) override these. The default just bytes-in /
    // bytes-out against cfg_, honoring write-mask + BAR/COMMAND side effects.
    virtual std::uint32_t ReadConfigImpl (std::uint32_t offset,
                                          std::uint32_t size);
    virtual void          WriteConfigImpl(std::uint32_t offset,
                                          std::uint32_t size,
                                          std::uint32_t value);

private:
    // Centralised BAR-read/write logic: applies the size-mask, OR's in
    // type bits on read.
    std::uint32_t ReadBarDword (int idx) const;
    void          WriteBarDword(int idx, std::uint32_t value);

    // Apply COMMAND.MEMORY_SPACE / IO_SPACE transitions: walks all BARs and
    // (un)maps as needed. Called on every COMMAND write.
    void RecomputeMappings(std::uint16_t old_cmd, std::uint16_t new_cmd);

    // Per-byte read/write into cfg_ with the per-byte writable mask applied.
    void WriteByte(std::uint32_t offset, std::uint8_t value);
    std::uint8_t ReadByte(std::uint32_t offset) const;

    // Compute the read-back size-mask for a given BAR.
    static std::uint32_t BarSizeMaskLow (const Bar& b);
    static std::uint32_t BarSizeMaskHigh(const Bar& b);  // Mmio64 only

    // 256-byte config-space buffer. The default ReadConfigImpl returns bytes
    // directly from here for any register without dedicated logic.
    std::uint8_t cfg_[kCfgSpaceSize] = {};

    // Per-byte writable mask. 0 = read-only, 1 = software-writable.
    // (Both VID/DID and class/header type get 0; COMMAND, INTERRUPT_LINE,
    // and the BAR cells get 0xFF, then we re-mask BAR writes through
    // WriteBarDword for the size-mask treatment.)
    std::uint8_t writable_mask_[kCfgSpaceSize] = {};

    std::array<Bar, 6> bars_{};

    std::uint32_t cap_next_alloc_ = kCapListStart;
};

}  // namespace tinyvmm::pci
