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
//   tracelog -start tinyvmm -guid #0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d -f trace.etl -level 5
//   ... run ...
//   tracelog -stop tinyvmm
//   tracerpt trace.etl -of csv -o trace.csv
//
// Open trace.etl in Windows Performance Analyzer (WPA) or PerfView for
// timeline visualization.
//
// Provider GUID: {0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d}
// Provider name: "Tinyvmm-Core"

#include "../common.h"

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

}  // namespace tinyvmm::diag

// Macro shorthands so call sites stay readable. Each event has a unique
// name; arguments use TraceLogging field types.
//
// Examples:
//   TINYVMM_ETW_INFO("VmStart", TraceLoggingString(path, "path"),
//                               TraceLoggingUInt64(ram_mb, "ram_mb"));
//   TINYVMM_ETW_INFO("NetTx",   TraceLoggingUInt32(qidx, "qidx"),
//                               TraceLoggingUInt32(bytes, "bytes"));
//
// Levels (per ETW convention):
//   CRITICAL=1, ERROR=2, WARN=3, INFO=4, VERBOSE=5
#define TINYVMM_ETW_INFO(name, ...) \
    TraceLoggingWrite(::tinyvmm::diag::g_etw_provider, name, \
        TraceLoggingLevel(TRACE_LEVEL_INFORMATION), __VA_ARGS__)

#define TINYVMM_ETW_VERBOSE(name, ...) \
    TraceLoggingWrite(::tinyvmm::diag::g_etw_provider, name, \
        TraceLoggingLevel(TRACE_LEVEL_VERBOSE), __VA_ARGS__)

#define TINYVMM_ETW_WARN(name, ...) \
    TraceLoggingWrite(::tinyvmm::diag::g_etw_provider, name, \
        TraceLoggingLevel(TRACE_LEVEL_WARNING), __VA_ARGS__)

#define TINYVMM_ETW_ERROR(name, ...) \
    TraceLoggingWrite(::tinyvmm::diag::g_etw_provider, name, \
        TraceLoggingLevel(TRACE_LEVEL_ERROR), __VA_ARGS__)
