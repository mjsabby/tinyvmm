#include "etw.h"

namespace tinyvmm::diag {

// Define the global TraceLogging provider.
// Provider GUID {0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d}
TRACELOGGING_DEFINE_PROVIDER(
    g_etw_provider,
    "Tinyvmm-Core",
    (0x0fb6c4d5, 0x9b9b, 0x4e1f, 0x9d, 0x5a, 0x7a, 0x6d, 0x8a, 0x9b, 0x3c, 0x4d));

namespace {
bool g_registered = false;
}  // namespace

void EtwRegister() {
    if (g_registered) return;
    HRESULT hr = TraceLoggingRegister(g_etw_provider);
    g_registered = SUCCEEDED(hr);
}

void EtwUnregister() {
    if (!g_registered) return;
    TraceLoggingUnregister(g_etw_provider);
    g_registered = false;
}

}  // namespace tinyvmm::diag
