#include "snapshot.h"

namespace tinyvmm::whp::snapshot {

// Function-local static gives us guaranteed-once construction without a
// global ctor ordering hazard, and the `inline` helpers in the header avoid
// any per-call function pointer indirection for the common
// `IsArmed()`/`WasRequested()` paths.
SnapshotState& State() noexcept {
    static SnapshotState s;
    return s;
}

}  // namespace tinyvmm::whp::snapshot
