#pragma once
//
// ETW (Event Tracing for Windows) instrumentation for tinyvmm.
//
// Uses the modern TraceLogging API (manifest-free). Capture with e.g.:
//
//   wpr -start C:\tinyvmm\tools\tinyvmm.wprp -filemode
//   ... run tinyvmm ...
//   wpr -stop trace.etl
//
// Or quickly with tracelog/PerfView:
//
//   tracelog -start tinyvmm -guid #0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d -f trace.etl -level 5 -matchanykw 0xFFFF
//   ... run ...
//   tracelog -stop tinyvmm
//   tracerpt trace.etl -of csv -o trace.csv
//
// Open trace.etl in Windows Performance Analyzer (WPA) or PerfView for
// timeline visualization.
//
// Provider GUID: {0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d}
// Provider name: "Tinyvmm-Core"

#include "common.h"

#include <TraceLoggingProvider.h>
#include <evntrace.h>

#include <cstdint>

namespace tinyvmm::diag {

// Forward decl of the global provider handle. Defined (TRACELOGGING_DEFINE_*)
// in etw.cpp.
TRACELOGGING_DECLARE_PROVIDER(g_etw_provider);

// One-shot init/teardown. Safe to call multiple times.
void EtwRegister();
void EtwUnregister();

// ETW keywords for filtering high-volume categories. Subscribers pass a
// 64-bit MatchAnyKeyword bitmask when starting a session; only events
// whose keyword bits intersect the mask are emitted. This is the
// recommended way to disable high-volume categories (VmExit, Mmio, Io)
// without losing the ability to capture lifecycle / error events.
//
// Convention: keyword 0 means "always emit when the level threshold is
// met" (use sparingly; lifecycle-style events only). Every hot-path
// event MUST set at least one keyword from the table below so users can
// silence it.
namespace kw {

// Per WHV vCPU exit. Fires once per VM exit; can be ~1 M/s on
// MMIO-heavy workloads. Default capture profile leaves this OFF.
inline constexpr std::uint64_t VmExit    = 0x0000'0001;

// Virtio doorbell signaling (host -> guest IRQ and guest -> host
// notification). One event per doorbell crossing; can be high volume
// on busy queues.
inline constexpr std::uint64_t Doorbell  = 0x0000'0002;

// Virtqueue pop / push / IRQ raise. Useful for measuring batching
// behavior. Volume ~= packet rate.
inline constexpr std::uint64_t Virtio    = 0x0000'0004;

// Virtio-net packet ingress / egress on any backend (loopback / wintun
// / xdp). One event per packet.
inline constexpr std::uint64_t Net       = 0x0000'0008;

// Every MMIO access (read / write). Volume scales with guest device
// driver activity; HIGH for boot.
inline constexpr std::uint64_t Mmio      = 0x0000'0010;

// Every IO-port access (read / write). Volume HIGH during boot when
// the 8250 UART is in use; near-zero in steady state once virtio is
// negotiated.
inline constexpr std::uint64_t Io        = 0x0000'0020;

// BootTimer marks. Low volume.
inline constexpr std::uint64_t Boot      = 0x0000'0040;

// VM / vCPU / backend lifecycle (create, destroy, start, stop, fatal
// error). Low volume; always interesting.
inline constexpr std::uint64_t Lifecycle = 0x0000'0080;

// Virtio-blk request submitted / completed. Volume = block IOPS.
inline constexpr std::uint64_t Block     = 0x0000'0100;

// CPUID leaf service. Volume HIGH during early guest boot; ~0 once the
// kernel is past identification.
inline constexpr std::uint64_t Cpuid     = 0x0000'0200;

// MSI-X interrupt injection. Volume = injection rate; usually moderate.
inline constexpr std::uint64_t Msi       = 0x0000'0400;

}  // namespace kw

}  // namespace tinyvmm::diag

// Macro shorthands so call sites stay readable. Each event has a unique
// name; arguments use TraceLogging field types.
//
// Examples:
//   TINYVMM_ETW_INFO("VmStart", TraceLoggingString(path, "path"),
//                               TraceLoggingUInt64(ram_mb, "ram_mb"));
//   TINYVMM_ETW_VERBOSE_KW("VmExit", kw::VmExit,
//                          TraceLoggingUInt32(reason, "reason"),
//                          TraceLoggingUInt64(rip, "rip"));
//
// Levels (per ETW convention):
//   CRITICAL=1, ERROR=2, WARN=3, INFO=4, VERBOSE=5
//
// Plain (no-keyword) macros default to the Lifecycle keyword so users
// cannot accidentally fire something high-volume without explicit
// opt-in. New hot-path call sites MUST use the *_KW form.
#define TINYVMM_ETW_INFO(name, ...) \
    TraceLoggingWrite(::tinyvmm::diag::g_etw_provider, name, \
        TraceLoggingLevel(TRACE_LEVEL_INFORMATION), \
        TraceLoggingKeyword(::tinyvmm::diag::kw::Lifecycle), \
        __VA_ARGS__)

#define TINYVMM_ETW_VERBOSE(name, ...) \
    TraceLoggingWrite(::tinyvmm::diag::g_etw_provider, name, \
        TraceLoggingLevel(TRACE_LEVEL_VERBOSE), \
        TraceLoggingKeyword(::tinyvmm::diag::kw::Lifecycle), \
        __VA_ARGS__)

#define TINYVMM_ETW_WARN(name, ...) \
    TraceLoggingWrite(::tinyvmm::diag::g_etw_provider, name, \
        TraceLoggingLevel(TRACE_LEVEL_WARNING), \
        TraceLoggingKeyword(::tinyvmm::diag::kw::Lifecycle), \
        __VA_ARGS__)

#define TINYVMM_ETW_ERROR(name, ...) \
    TraceLoggingWrite(::tinyvmm::diag::g_etw_provider, name, \
        TraceLoggingLevel(TRACE_LEVEL_ERROR), \
        TraceLoggingKeyword(::tinyvmm::diag::kw::Lifecycle), \
        __VA_ARGS__)

// Keyword-tagged variants. Prefer these for any event that could fire
// faster than ~1 Hz so users can filter independently.
#define TINYVMM_ETW_INFO_KW(name, keyword, ...) \
    TraceLoggingWrite(::tinyvmm::diag::g_etw_provider, name, \
        TraceLoggingLevel(TRACE_LEVEL_INFORMATION), \
        TraceLoggingKeyword(keyword), __VA_ARGS__)

#define TINYVMM_ETW_VERBOSE_KW(name, keyword, ...) \
    TraceLoggingWrite(::tinyvmm::diag::g_etw_provider, name, \
        TraceLoggingLevel(TRACE_LEVEL_VERBOSE), \
        TraceLoggingKeyword(keyword), __VA_ARGS__)

#define TINYVMM_ETW_WARN_KW(name, keyword, ...) \
    TraceLoggingWrite(::tinyvmm::diag::g_etw_provider, name, \
        TraceLoggingLevel(TRACE_LEVEL_WARNING), \
        TraceLoggingKeyword(keyword), __VA_ARGS__)

#define TINYVMM_ETW_ERROR_KW(name, keyword, ...) \
    TraceLoggingWrite(::tinyvmm::diag::g_etw_provider, name, \
        TraceLoggingLevel(TRACE_LEVEL_ERROR), \
        TraceLoggingKeyword(keyword), __VA_ARGS__)

// Cheap (~1 ns) inline check for "is anyone listening at this level
// with at least one of these keywords?". Wrap with this when the
// arguments to a TraceLogging call are expensive to compute (e.g.
// snprintf into a buffer). The macros above already short-circuit, but
// they evaluate every argument first.
#define TINYVMM_ETW_ENABLED(level, keyword) \
    TraceLoggingProviderEnabled(::tinyvmm::diag::g_etw_provider, \
                                level, keyword)

