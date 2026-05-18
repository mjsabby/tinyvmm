#pragma once

#include <Windows.h>

#include <cstdint>
#include <string_view>
#include <vector>

namespace tinyvmm::whp {

// CPU affinity policy applied to the BSP and every AP thread just before its
// run loop starts. On hybrid Intel hosts (Alder Lake / Raptor Lake / ...),
// vCPU threads bouncing across P-core and E-core boundaries trip Linux's
// `clocksource_watchdog` into marking TSC unstable, which silently demotes
// `clock_gettime` to a slower clocksource for the rest of the boot. Pinning
// all vCPU threads to either the P-core set OR the E-core set keeps RDTSC
// values consistent across vCPUs without giving up cross-core scheduling
// within that set.
enum class AffinityMode {
    All,            // No pinning. Default.
    PCore,          // All P-core logical processors (including SMT siblings).
    PCorePhysical,  // P-cores, one logical processor per core (no SMT).
    ECore,          // All E-core logical processors. E-cores have no SMT.
};

// Topology summary derived from `GetSystemCpuSetInformation`. Cached.
struct HostTopology {
    unsigned total_logical = 0;
    unsigned p_logical     = 0;
    unsigned p_physical    = 0;
    unsigned e_logical     = 0;
    bool     hybrid        = false;  // any two cores differ in EfficiencyClass
};

// Lazily-cached lookup of host topology. Returns a zero-filled struct if
// `GetSystemCpuSetInformation` fails (very old Windows; tinyvmm itself needs
// W10 1709+ already, so this is effectively never).
const HostTopology& GetTopology();

// Resolve the CPU-set IDs corresponding to `mode`. Returns empty for
// `AffinityMode::All` (sentinel for "no pinning"). On a non-hybrid host
// (e.g. server SKU), `PCore` resolves to every logical processor and
// `ECore` returns empty (no E-cores to pin to -- caller should treat as
// a user error or fall back to All).
std::vector<ULONG> ResolveCpuSetIds(AffinityMode mode);

// Pin the calling thread to the given CPU-set IDs via
// `SetThreadSelectedCpuSets` (W10 1709+). Returns true on success or on
// empty input. Logs to stderr on Win32 failure.
bool PinCurrentThread(const std::vector<ULONG>& cpu_set_ids);

// Parse the value of `--cpu-affinity`. Accepts: "all", "p", "e",
// "p-physical". Returns true on success. Case-insensitive.
bool ParseAffinityMode(std::string_view s, AffinityMode& out);

// Stable text name (matches what `--cpu-affinity` accepts) for logging.
const char* AffinityModeName(AffinityMode m);

}  // namespace tinyvmm::whp
