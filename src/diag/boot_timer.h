#pragma once
//
// BootTimer: minimal QPC-based phase timing for tinyvmm boot.
//
// Records a sequence of named waypoints from VM start. Prints elapsed
// milliseconds (vs T0, the BootTimer constructor) and per-phase deltas.
//
// Also pushes an ETW event for each Mark() so the timeline shows up in
// Windows Performance Analyzer alongside system events.

#include "etw.h"

#include <Windows.h>

#include <cstdio>
#include <string>
#include <vector>

namespace tinyvmm::diag {

class BootTimer {
public:
    BootTimer() {
        ::QueryPerformanceFrequency(&freq_);
        ::QueryPerformanceCounter(&t0_);
        last_ = t0_;
    }

    // Record a phase boundary. Emits ETW event "BootMark" and (optionally)
    // a [boot] line on stderr.
    void Mark(const char* phase, bool print = true) {
        LARGE_INTEGER now;
        ::QueryPerformanceCounter(&now);
        const double total_ms = static_cast<double>(now.QuadPart - t0_.QuadPart) *
                                1000.0 / static_cast<double>(freq_.QuadPart);
        const double delta_ms = static_cast<double>(now.QuadPart - last_.QuadPart) *
                                1000.0 / static_cast<double>(freq_.QuadPart);
        last_ = now;
        if (print) {
            std::fprintf(stderr, "[boot] %8.3f ms (+%7.3f ms) %s\n",
                         total_ms, delta_ms, phase);
        }
        TINYVMM_ETW_INFO("BootMark",
            TraceLoggingString(phase, "phase"),
            TraceLoggingFloat64(total_ms, "total_ms"),
            TraceLoggingFloat64(delta_ms, "delta_ms"));
    }

    // Milliseconds since construction.
    double ElapsedMs() const {
        LARGE_INTEGER now;
        ::QueryPerformanceCounter(&now);
        return static_cast<double>(now.QuadPart - t0_.QuadPart) *
               1000.0 / static_cast<double>(freq_.QuadPart);
    }

private:
    LARGE_INTEGER freq_{};
    LARGE_INTEGER t0_{};
    LARGE_INTEGER last_{};
};

}  // namespace tinyvmm::diag
