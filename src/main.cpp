#include "common.h"
#include "devices/io_bus.h"
#include "devices/mmio_bus.h"
#include "devices/serial8250.h"
#include "host/privilege.h"
#include "whp/memory.h"
#include "whp/partition.h"
#include "whp/run_loop.h"
#include "whp/vcpu.h"

#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

void PrintUsage() {
    std::puts(
        "tinyvmm - tiny WHP-based virtual machine monitor\n"
        "\n"
        "Usage:\n"
        "  tinyvmm --smoke         Run the WHP smoke test (HLT in real mode)\n"
        "  tinyvmm --loop-test     Exercise the run loop (IO + HLT)\n"
        "  tinyvmm --uart-test     Drive the 8250 UART from real-mode guest\n"
        "  tinyvmm --help          Show this help\n");
}

// Probe whether WHP is actually present and enabled on this host.
void CheckWhpAvailable() {
    WHV_CAPABILITY cap = {};
    UINT32 written = 0;
    HRESULT hr = WHvGetCapability(WHvCapabilityCodeHypervisorPresent, &cap,
                                  sizeof(cap), &written);
    tinyvmm::ThrowIfFailed(hr, "WHvGetCapability(HypervisorPresent)");
    if (!cap.HypervisorPresent) {
        throw tinyvmm::HrError(
            E_FAIL,
            "Windows Hypervisor Platform reports no hypervisor. Enable the "
            "'Windows Hypervisor Platform' Windows Feature and reboot");
    }
}

void ReportHostCapabilities() {
    using namespace tinyvmm;

    const bool lock_priv = host::EnableLockMemoryPrivilege();
    std::printf("[host] SeLockMemoryPrivilege: %s\n",
                lock_priv ? "enabled" : "not held (large pages will fall back)");
    std::printf("[host] large-page minimum:    0x%zx bytes\n",
                host::LargePageSize());
}

// M0 smoke test: bring up a partition, map 2 MiB of guest RAM at GPA 0 (so we
// actually exercise the large-page path), drop a HLT (0xF4) at GPA 0x1000, set
// CS:IP so the linear address is 0x1000, run. Expect WHvRunVpExitReasonX64Halt.
int RunSmoke() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;

    CheckWhpAvailable();
    std::puts("[smoke] WHP available");
    ReportHostCapabilities();

    Partition part(/*vcpu_count=*/1);
    part.Setup();
    std::puts("[smoke] partition created and set up");

    const std::size_t kRamSize = host::LargePageSize();  // 2 MiB on x86_64
    GuestMemory ram(part, /*gpa=*/0, kRamSize, /*executable=*/true);
    std::printf("[smoke] guest RAM: 0x%zx bytes at GPA 0 (host=%p, %s)\n",
                ram.size(), ram.host_base(),
                ram.large_pages() ? "MEM_LARGE_PAGES" : "4 KiB pages");

    // Place HLT at GPA 0x1000.
    constexpr std::uint64_t kCodeGpa = 0x1000;
    const std::uint8_t hlt[] = {0xF4};
    ram.WriteAt(kCodeGpa, hlt, sizeof(hlt));

    Vcpu vp(part, 0);
    vp.SetupRealMode(/*cs_base=*/kCodeGpa);

    // CS base = 0x1000, so CS:IP=cs:0 is linear 0x1000 == kCodeGpa.
    WHV_REGISTER_VALUE rip = {};
    rip.Reg64 = 0;
    vp.SetRegister(WHvX64RegisterRip, rip);

    std::puts("[smoke] running vCPU until next exit...");
    WHV_RUN_VP_EXIT_CONTEXT exit = {};
    vp.Run(exit);

    std::printf("[smoke] exit reason = 0x%08x  RIP=0x%llx  CS.Base=0x%llx\n",
                static_cast<unsigned int>(exit.ExitReason),
                static_cast<unsigned long long>(exit.VpContext.Rip),
                static_cast<unsigned long long>(exit.VpContext.Cs.Base));

    if (exit.ExitReason != WHvRunVpExitReasonX64Halt) {
        std::fprintf(stderr,
                     "[smoke] FAIL: expected X64Halt (0x%x), got 0x%x\n",
                     static_cast<unsigned int>(WHvRunVpExitReasonX64Halt),
                     static_cast<unsigned int>(exit.ExitReason));
        return 2;
    }

    std::puts("[smoke] PASS");
    return 0;
}

// M1 loop test: prove the run-loop + WHvEmulator + IoBus pipeline. We program
// real-mode code that does two `OUT 0x3F8, AL` instructions and then HLT.
// Expect: two IO exits routed to a stub UART that captures "HI", then a halt
// exit that ends the loop.
//
// Real-mode encoding at GPA 0x1000, with CS.Base=0x1000 / IP=0:
//   BA F8 03      mov dx, 0x3F8
//   B0 48         mov al, 'H'
//   EE            out dx, al
//   B0 49         mov al, 'I'
//   EE            out dx, al
//   F4            hlt
int RunLoopTest() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;

    CheckWhpAvailable();
    std::puts("[loop-test] WHP available");
    ReportHostCapabilities();

    Partition part(/*vcpu_count=*/1);
    part.Setup();

    const std::size_t kRamSize = host::LargePageSize();
    GuestMemory ram(part, /*gpa=*/0, kRamSize, /*executable=*/true);
    std::printf("[loop-test] guest RAM: 0x%zx bytes (%s)\n", ram.size(),
                ram.large_pages() ? "MEM_LARGE_PAGES" : "4 KiB pages");

    constexpr std::uint64_t kCodeGpa = 0x1000;
    const std::uint8_t code[] = {
        0xBA, 0xF8, 0x03,  // mov dx, 0x3F8
        0xB0, 0x48,        // mov al, 'H'
        0xEE,              // out dx, al
        0xB0, 0x49,        // mov al, 'I'
        0xEE,              // out dx, al
        0xF4,              // hlt
    };
    ram.WriteAt(kCodeGpa, code, sizeof(code));

    Vcpu vp(part, 0);
    vp.SetupRealMode(/*cs_base=*/kCodeGpa);
    WHV_REGISTER_VALUE rip = {};
    rip.Reg64 = 0;
    vp.SetRegister(WHvX64RegisterRip, rip);

    devices::IoBus io_bus;
    devices::MmioBus mmio_bus;

    std::string captured;
    io_bus.Register(0x3F8, 8, "stub-uart",
                    [&captured](devices::IoAccess& acc) {
                        if (acc.is_write && acc.port == 0x3F8 &&
                            acc.access_size == 1) {
                            captured.push_back(static_cast<char>(acc.value));
                        } else if (!acc.is_write) {
                            // LSR (0x3FD) read: report TX-empty so a real
                            // driver wouldn't busy-wait.
                            acc.value = (acc.port == 0x3FD) ? 0x60u : 0u;
                        }
                    });

    RunLoop loop(vp, io_bus, mmio_bus);
    std::puts("[loop-test] running...");
    StopReason stop = loop.Run();

    std::printf("[loop-test] stop=%d  io_exits=%llu mmio_exits=%llu "
                "halt_exits=%llu  captured=\"%s\"\n",
                static_cast<int>(stop),
                static_cast<unsigned long long>(loop.io_exits()),
                static_cast<unsigned long long>(loop.mmio_exits()),
                static_cast<unsigned long long>(loop.halt_exits()),
                captured.c_str());

    if (stop != StopReason::GuestHalted) {
        std::fprintf(stderr,
                     "[loop-test] FAIL: expected GuestHalted, got stop=%d\n",
                     static_cast<int>(stop));
        return 2;
    }
    if (captured != "HI") {
        std::fprintf(
            stderr,
            "[loop-test] FAIL: expected captured=\"HI\", got \"%s\"\n",
            captured.c_str());
        return 2;
    }
    if (loop.io_exits() != 2 || loop.halt_exits() != 1) {
        std::fprintf(stderr,
                     "[loop-test] FAIL: counter mismatch (io=%llu halt=%llu)\n",
                     static_cast<unsigned long long>(loop.io_exits()),
                     static_cast<unsigned long long>(loop.halt_exits()));
        return 2;
    }

    std::puts("[loop-test] PASS");
    return 0;
}

// M2 UART test: real-mode loop emits a NUL-terminated string to COM1 (0x3F8)
// one byte at a time, then HLTs. Verifies that:
//   - The 8250 model captures every byte the guest writes.
//   - DS:SI reads from low memory work through the emulator path is fine
//     (we don't actually read MMIO here; just confirms the IO write side end-
//     to-end through Serial8250).
//
// Hand-assembled at GPA 0x1000 (CS.Base=0x1000, IP=0):
//
//      BE 00 20         mov  si, 0x2000        ; ds:si -> message buffer
//      BA F8 03         mov  dx, 0x3F8         ; COM1 THR
//   loop:
//      8A 04            mov  al, [si]
//      46               inc  si
//      84 C0            test al, al
//      74 03            jz   done              ; -> hlt
//      EE               out  dx, al
//      EB F6            jmp  short loop
//   done:
//      F4               hlt
int RunUartTest() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;

    CheckWhpAvailable();
    std::puts("[uart-test] WHP available");
    ReportHostCapabilities();

    Partition part(/*vcpu_count=*/1);
    part.Setup();

    const std::size_t kRamSize = host::LargePageSize();
    GuestMemory ram(part, /*gpa=*/0, kRamSize, /*executable=*/true);

    constexpr std::uint64_t kCodeGpa = 0x1000;
    constexpr std::uint64_t kMsgGpa = 0x2000;

    const std::uint8_t code[] = {
        0xBE, 0x00, 0x20,        // mov si, 0x2000
        0xBA, 0xF8, 0x03,        // mov dx, 0x3F8
        0x8A, 0x04,              // mov al, [si]
        0x46,                    // inc si
        0x84, 0xC0,              // test al, al
        0x74, 0x03,              // jz done (+3)
        0xEE,                    // out dx, al
        0xEB, 0xF6,              // jmp short loop (-10)
        0xF4,                    // hlt
    };
    ram.WriteAt(kCodeGpa, code, sizeof(code));

    const char kMsg[] = "tinyvmm UART ok\n";
    ram.WriteAt(kMsgGpa, kMsg, sizeof(kMsg));  // includes trailing NUL

    Vcpu vp(part, 0);
    vp.SetupRealMode(/*cs_base=*/kCodeGpa);
    WHV_REGISTER_VALUE rip = {};
    rip.Reg64 = 0;
    vp.SetRegister(WHvX64RegisterRip, rip);

    devices::IoBus io_bus;
    devices::MmioBus mmio_bus;

    // Sink to stdout AND capture, so we can both eyeball and assert.
    devices::Serial8250 com1(0x3F8, stdout);
    com1.EnableStringCapture();
    com1.Attach(io_bus);

    RunLoop loop(vp, io_bus, mmio_bus);
    std::puts("[uart-test] running...");
    StopReason stop = loop.Run();
    const std::string captured = com1.DrainCapture();

    std::printf(
        "[uart-test] stop=%d  io_exits=%llu halt_exits=%llu  "
        "captured(%zu)=\"%s\"\n",
        static_cast<int>(stop),
        static_cast<unsigned long long>(loop.io_exits()),
        static_cast<unsigned long long>(loop.halt_exits()),
        captured.size(), captured.c_str());

    if (stop != StopReason::GuestHalted) {
        std::fprintf(stderr,
                     "[uart-test] FAIL: expected GuestHalted, got stop=%d\n",
                     static_cast<int>(stop));
        return 2;
    }
    if (captured != std::string(kMsg, sizeof(kMsg) - 1)) {
        std::fprintf(stderr,
                     "[uart-test] FAIL: captured mismatch.\n  want: \"%s\"\n  "
                     "got:  \"%s\"\n",
                     kMsg, captured.c_str());
        return 2;
    }

    std::puts("[uart-test] PASS");
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::string_view cmd(argv[1]);
    try {
        if (cmd == "--smoke") {
            return RunSmoke();
        }
        if (cmd == "--loop-test") {
            return RunLoopTest();
        }
        if (cmd == "--uart-test") {
            return RunUartTest();
        }
        if (cmd == "--help" || cmd == "-h") {
            PrintUsage();
            return 0;
        }
    } catch (const tinyvmm::HrError& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 3;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 3;
    }

    PrintUsage();
    return 1;
}
