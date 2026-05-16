#pragma once

// MSI message -> WHvRequestInterrupt translator.
//
// On x86 the MSI "transaction" is just a 32-bit memory write to a magic
// address in the LAPIC redirection window (0xFEE00000-0xFEEFFFFF). The
// hypervisor's APIC emulation already turns guest-side writes into vector
// deliveries; for *host*-side injection we need to mint the same effect via
// WHvRequestInterrupt. This header documents and implements that mapping.

#include "common.h"

#include <Windows.h>
#include <WinHvPlatform.h>
#include <WinHvPlatformDefs.h>

#include <cstdint>

namespace tinyvmm::whp {

// Decode an x86 MSI message and submit it to the partition's interrupt
// controller. `address` carries the destination + delivery flags, `data`
// carries the vector + delivery mode + trigger mode. Format references:
//
//   Intel SDM Vol 3 §10.11 (MSI compatibility format):
//   Address[31:20] = 0xFEE
//   Address[19:12] = Destination ID (LAPIC ID, physical mode; group, logical)
//   Address[3]     = Redirection Hint (ignored by us; lowest-priority steers
//                    delivery)
//   Address[2]     = Destination Mode (0=physical, 1=logical)
//   Data[7:0]      = Vector
//   Data[10:8]     = Delivery Mode (0=Fixed, 1=LowestPri, 4=NMI, 5=INIT)
//   Data[14]       = Level (assert/deassert, only matters for level)
//   Data[15]       = Trigger Mode (0=edge, 1=level)
//
// With WHP's in-hypervisor x2APIC the interrupt is queued at the destination
// vCPU's LAPIC and delivered on the next VM entry; if IF=0 the hypervisor
// holds it without surfacing a host VM exit.
HRESULT InjectMsi(WHV_PARTITION_HANDLE partition,
                  std::uint64_t address,
                  std::uint32_t data);

// Monotonic count of successful InjectMsi calls; useful as a hot-path
// telemetry signal (1 MSI per RX/TX completion in steady state).
std::uint64_t MsiInjectCount() noexcept;

}  // namespace tinyvmm::whp
