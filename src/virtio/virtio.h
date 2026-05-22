#pragma once

// Common virtio constants and the device-side interface that the MMIO
// transport calls back into. Keeping this header stand-alone (no transport
// types) lets us build a stub device for unit testing without dragging in
// the run-loop machinery.
//
// Spec references throughout are to "Virtual I/O Device (VIRTIO) Version 1.2,
// Committee Specification 01, 1 July 2022".

#include "common.h"

#include <cstdint>

namespace tinyvmm::virtio {

inline constexpr std::uint32_t kMagicValue = 0x74726976;       // "virt" LE
inline constexpr std::uint32_t kVersionModern = 2;             // legacy=1
inline constexpr std::uint32_t kVendorId = 0x54564D4D;         // "TVMM"

// Device IDs (spec §5).
inline constexpr std::uint32_t kDeviceIdReserved = 0;
inline constexpr std::uint32_t kDeviceIdNet = 1;
inline constexpr std::uint32_t kDeviceIdBlk = 2;
inline constexpr std::uint32_t kDeviceIdConsole = 3;
inline constexpr std::uint32_t kDeviceIdRng = 4;
inline constexpr std::uint32_t kDeviceIdP9 = 9;

// Status field bits (spec §2.1).
inline constexpr std::uint8_t kStatusAcknowledge = 1;
inline constexpr std::uint8_t kStatusDriver = 2;
inline constexpr std::uint8_t kStatusDriverOk = 4;
inline constexpr std::uint8_t kStatusFeaturesOk = 8;
inline constexpr std::uint8_t kStatusNeedsReset = 0x40;
inline constexpr std::uint8_t kStatusFailed = 0x80;

// Transport feature bits (spec §6, §2.7.10).
inline constexpr std::uint64_t kFeatureRingIndirectDesc = 1ULL << 28;
inline constexpr std::uint64_t kFeatureRingEventIdx = 1ULL << 29;
inline constexpr std::uint64_t kFeatureVersion1 = 1ULL << 32;

// Descriptor flags (spec §2.7.5).
inline constexpr std::uint16_t kVringDescFNext = 1;
inline constexpr std::uint16_t kVringDescFWrite = 2;
inline constexpr std::uint16_t kVringDescFIndirect = 4;

class Virtqueue;  // virtqueue.h

// Implemented by each virtio device (net, blk, ...). The MMIO transport
// owns the register state machine; the device sees feature negotiation,
// queue lifecycle hooks, and queue-notify kicks.
class Device {
public:
    virtual ~Device() = default;

    virtual std::uint32_t DeviceId() const = 0;
    virtual std::uint64_t DeviceFeatures() const = 0;

    // Returns false if the negotiated subset is unworkable. The transport
    // then refuses FEATURES_OK so the driver can retry / fail.
    virtual bool SetDriverFeatures(std::uint64_t acked) = 0;

    virtual std::uint32_t QueueCount() const = 0;
    virtual std::uint32_t QueueMax(std::uint32_t idx) const = 0;
    virtual Virtqueue* GetQueue(std::uint32_t idx) = 0;

    // Driver kicked QueueNotify with `idx`. Called on the vCPU thread; do
    // not block.
    virtual void NotifyQueue(std::uint32_t idx) = 0;

    virtual void DriverOk() {}
    virtual void Reset() {}

    // Device-specific config space at MMIO offset 0x100.
    virtual std::uint32_t ReadConfig(std::uint32_t offset,
                                     std::uint32_t size) {
        (void)offset; (void)size; return 0;
    }
    virtual void WriteConfig(std::uint32_t offset, std::uint32_t size,
                             std::uint32_t value) {
        (void)offset; (void)size; (void)value;
    }
};

}  // namespace tinyvmm::virtio
