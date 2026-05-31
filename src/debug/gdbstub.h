// SPDX-License-Identifier: MIT
//
// tinyvmm -- GDB Remote Serial Protocol (RSP) stub (M35).
//
// Lets a host-side GDB connect via TCP and debug the guest kernel:
//   tinyvmm --pvh-run --gdb-port 1234 vmlinux
//   ; gdb vmlinux
//   ; (gdb) target remote :1234
//   ; (gdb) break start_kernel
//   ; (gdb) continue
//
// Architecture: x86_64 only. Single-vCPU only (--vcpus 1 enforced when
// --gdb-port is set). Linux PVH kernel only (we walk CR3 page tables
// for VA->PA translation, which assumes the guest kernel is using
// 4-level 64-bit paging).
//
// Threading model:
//   * stub I/O thread (started by Start()): owns the TCP socket. Parses
//     RSP packets. Translates them into commands serviced under the
//     stub mutex. Watches the socket for the raw 0x03 byte (Ctrl-C);
//     on receipt, sets the pending-stop flag and calls
//     WHvCancelRunVirtualProcessor.
//   * vCPU thread (existing whp::RunLoop): runs WHvRunVirtualProcessor.
//     Before each iteration, checks the stub's "pending stop" flag; if
//     set, calls ReportStop and blocks for the next command. On
//     exception exit (#DB / #BP), routes to ReportStop.
//
// Tools/state ownership:
//   * Software breakpoints: stub owns a refcounted map keyed by guest
//     virtual address. Insert writes 0xCC after saving the original
//     byte; remove restores. Resume-over-bp dance (restore, set TF,
//     step, re-poke) is handled internally on c/s.
//   * Registers: read/written through whp::Vcpu APIs.
//   * Memory: read/written through whp::GuestMemory after VA->PA walk
//     via the guest's current CR3 4-level page tables.

#pragma once

#include "common.h"
#include "whp/partition.h"
#include "whp/vcpu.h"
#include "whp/memory.h"

#include <atomic>
#include <cstdint>
#include <memory>

namespace tinyvmm::debug {

class GdbStub {
public:
    // Bind 127.0.0.1:port and prepare for the run loop to start.
    // Does NOT block on the TCP accept yet; that happens in
    // WaitForFirstConnection. Construction is fail-fast: throws on
    // socket / WSAStartup / bind / listen errors.
    GdbStub(whp::Partition& part, whp::Vcpu& vcpu,
            whp::GuestMemory& mem, std::uint16_t port);

    ~GdbStub();

    GdbStub(const GdbStub&) = delete;
    GdbStub& operator=(const GdbStub&) = delete;

    // Block until a GDB client connects and the initial handshake
    // completes. Spawns the stub I/O thread that services subsequent
    // RSP packets. Called from RunPvhRun BEFORE entering the run loop
    // so the user can set breakpoints before the first guest
    // instruction executes.
    void WaitForFirstConnection();

    // What the stub wants the run loop to do next. Distinct from
    // RunLoop::StopReason because StopReason::Cancelled terminates the
    // VM; we want pause-then-resume.
    enum class Action : std::uint8_t {
        Continue,   // resume free-running until next exception/stop
        Step,       // single-step one instruction (set RFLAGS.TF)
        Shutdown,   // GDB sent 'D' (detach) or 'k' (kill); tear down
    };

    // Called by the run loop after an exception exit (#DB / #BP) or
    // after a debugger-requested pause. Reports the stop to GDB,
    // blocks until GDB issues the next action, returns it.
    //
    // exception_vec = the IDT vector that fired (1 for #DB, 3 for #BP,
    // 0 for "no exception, debugger asked us to stop").
    Action ReportStop(std::uint8_t exception_vec, std::uint64_t rip);

    // Top-of-run-loop check: returns true if Ctrl-C was received and
    // we should report a SIGINT stop without running. The run loop
    // should call ReportStop(0, current_rip) if this returns true.
    bool PendingDebuggerStop() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace tinyvmm::debug
