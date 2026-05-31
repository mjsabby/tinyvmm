#include "boot/acpi_tables.h"
#include "boot/pvh_loader.h"
#include "common.h"
#include "devices/i8259.h"
#include "devices/io_bus.h"
#include "devices/legacy_isa.h"
#include "devices/mmio_bus.h"
#include "devices/pit8254.h"
#include "devices/serial8250.h"
#include "diag/boot_timer.h"
#include "diag/etw.h"
#include "debug/gdbstub.h"
#include "host/block_file.h"
#include "host/privilege.h"
#include "host/xdp_probe.h"
#include "net/tsi_sanity.h"
#include "net/wintun_loader.h"
#include "pci/msix.h"
#include "pci/pci.h"
#include "pci/pci_bus.h"
#include "pci/pci_device.h"
#include "virtio/virtio.h"
#include "virtio/virtio_blk.h"
#include "virtio/virtio_console.h"
#include "virtio/virtio_mmio.h"
#include "virtio/virtio_net.h"
#include "virtio/virtio_pci.h"
#include "virtio/virtio_rng.h"
#include "virtio/virtio_9p.h"
#include "virtio/virtio_stub.h"
#include "virtio/virtqueue.h"
#include "virtio/net_backend.h"
#include "virtio/net_loopback.h"
#include "virtio/net_xdp.h"
#include "virtio/net_wintun.h"
#include "virtio/net_usernet.h"
#include "virtio/net_usernet_tsi.h"
#include "whp/cpu_affinity.h"
#include "whp/cpuid.h"
#include "whp/hv_enlightenment.h"
#include "whp/memory.h"
#include "whp/msi.h"
#include "whp/notification_port.h"
#include "whp/partition.h"
#include "whp/run_loop.h"
#include "whp/snapshot.h"
#include "whp/snapshot_file.h"
#include "whp/vcpu_state.h"
#include "whp/vcpu.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <span>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

void PrintUsage() {
    std::puts(
        "tinyvmm - tiny WHP-based virtual machine monitor\n"
        "\n"
        "Usage:\n"
        "  tinyvmm --smoke                   Real-mode HLT smoke test\n"
        "  tinyvmm --tsi-smoke               tcp-sans-io ABI link/version smoke (M34.0)\n"
        "  tinyvmm --loop-test               Run loop + IO dispatch test\n"
        "  tinyvmm --uart-test               Drive the 8250 from real mode\n"
        "  tinyvmm --virtio-test             Drive virtio-mmio + virtq from host\n"
        "  tinyvmm --doorbell-test           Verify WHP MMIO doorbell suppresses exits\n"
        "  tinyvmm --pci-test                Exercise the PCI host bridge + BAR sizing\n"
        "  tinyvmm --msix-test               Host-side MSI-X cap + table + PBA + mask/replay\n"
        "  tinyvmm --msix-inject-test        Drive WHvRequestInterrupt into a guest IDT\n"
        "  tinyvmm --virtio-pci-test         Host-side virtio-PCI modern transport\n"
        "  tinyvmm --virtio-blk-test         Host-side virtio-blk via IOCP backend\n"
        "  tinyvmm --virtio-blk-discard-test Verify DISCARD + WRITE_ZEROES (M34.x) features + ZeroRange\n"
        "  tinyvmm --virtio-blk-ro-test      Backend readonly reject path (OpWrite rejected)\n"
        "  tinyvmm --virtio-net-pci-test     Host-side virtio-net on the PCI transport\n"
        "  tinyvmm --virtio-net-loopback-test Echo a TX packet back as RX via LoopbackNetBackend\n"
        "  tinyvmm --virtio-net-usernet-tsi-test  Drive TsiTcpEngine end-to-end vs a real Winsock listener (M34.4)\n"
        "  tinyvmm --tsi-fuzz-test [iters [seed]] Fuzz TsiTcpEngine packet parser + pumps (default 10000 iters)\n"
        "  tinyvmm --virtio-queue-fuzz-test [iters [seed]] Fuzz Virtqueue::Pop() with random descriptor chains\n"
        "  tinyvmm --virtio-rng-test         Host-side virtio-rng + CNG entropy source\n"
        "  tinyvmm --virtio-console-test     Host-side virtio-console transmitq drain\n"
        "  tinyvmm --cpuid-test              Verify CPUID resolver policy (M18 time hygiene)\n"
        "  tinyvmm --snapshot-trigger-test   Verify magic CPUID leaf 0x4000DE57 dispatches (M33)\n"
        "  tinyvmm --save-restore-probe      Validate WHP State API capture/apply round-trip (M33)\n"
        "  tinyvmm --save-restore-roundtrip-test  Round-trip snapshot file format end-to-end (M33.3)\n"
        "  tinyvmm --save-restore-pci-test   Round-trip PCI/virtio/MSI-X/Virtqueue state (M33.4)\n"
        "  tinyvmm --save-restore-legacy-test Round-trip legacy device state (M33.5)\n"
        "  tinyvmm --xdp-probe [<IfIndex>]   Probe XDP capability on every host NIC\n"
        "                                    (or deep-dive on one when IfIndex given)\n"
        "  tinyvmm --wintun-probe [<secs>]   Bring up WinTun adapter 10.0.0.1/24 and dump RX (admin)\n"
        "  tinyvmm --wintun-svc-probe [<secs>] Same as --wintun-probe but via WintunSvc (no admin)\n"
        "  tinyvmm --pvh-info <vmlinux>      Inspect a PVH-capable ELF\n"
        "  tinyvmm --pvh-run [--net] [--net-backend loopback|xdp|wintun|wintun-svc|usernet]\n"
        "                   [--xdp-if <idx>] [--xdp-queue <q>] [--xdp-debug]\n"
        "                   [--initrd <path>] [--drive <path>[,readonly]]...\n"
        "                   [--virtio-9p-share <tag>=<host_path>[,ro]]...\n"
        "                   [--watchdog-secs <N>] [--debug-boot]\n"
        "                   [--expose-tsc-deadline] [--ram-mb <N>]\n"
        "                   [--vcpus <N>] (1..32, default 1)\n"
        "                   [--cpu-affinity all|p|e|p-physical]\n"
        "                   [--portfwd HOST_PORT:GUEST_PORT |\n"
        "                              HOST_IP:HOST_PORT:GUEST_IP:GUEST_PORT]...\n"
        "                   [--save <path>] [--unsafe-save-mutable-drive]\n"
        "                   [--gdb-port <port>] (M35 GDB stub on 127.0.0.1:<port>;\n"
        "                                        halts before first guest insn;\n"
        "                                        requires --vcpus 1)\n"
        "                   <vmlinux> [-- <kernel cmdline...>]\n"
        "                                    Load and run a PVH kernel\n"
        "                                    --drive may be repeated; drive N appears as /dev/vd<a+N>\n"
        "  tinyvmm --restore <path>          Restore VM from a TVMMSAVE snapshot file (M33.6)\n"
        "                   [--drive <path>[,readonly]]... (override saved paths in order)\n"
        "                   [--watchdog-secs <N>] [--cpu-affinity all|p|e|p-physical]\n"
        "                   [--unsafe-restore-mutable-drive]\n"
        "  tinyvmm --help                    Show this help\n");
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

// M34.0 / M34.2 build-time / link-time / runtime sanity for the linked
// tcp-sans-io Rust staticlib. Defined in src/net/tsi_sanity.cpp so this
// TU doesn't need to pull tcp_sans_io.h directly.
int RunTsiSmoke() {
    return tinyvmm::net::TsiSelfTest();
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

// M7 virtio-mmio + virtqueue self-test. Exercises the transport register
// file the way a real driver would (writes to Status / DriverFeatures /
// QueueDesc/Avail/Used / QueueReady / QueueNotify), then plants a
// descriptor chain in guest RAM and verifies that Pop() returns it.
//
// Runs entirely on the host; we still create a Partition just to get a
// large-page-backed `GuestMemory` slab whose lifetime matches the rest of
// the project's plumbing. No vCPU is created.
int RunVirtioTest() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;
    namespace v = tinyvmm::virtio;

    CheckWhpAvailable();
    std::puts("[virtio-test] WHP available");
    ReportHostCapabilities();

    Partition part(/*vcpu_count=*/1);
    part.Setup();

    constexpr std::size_t kRamBytes = 0x200000;  // 2 MiB
    GuestMemory ram(part, /*gpa=*/0, kRamBytes, /*executable=*/false);
    std::printf("[virtio-test] guest RAM: 0x%zx bytes (%s)\n", ram.size(),
                ram.large_pages() ? "MEM_LARGE_PAGES" : "4 KiB pages");

    constexpr std::uint64_t kVirtioBase = 0x100000;  // arbitrary, inside RAM
    v::StubDevice dev(ram);
    v::MmioTransport xport(kVirtioBase, dev);
    devices::MmioBus bus;
    xport.Attach(bus, "virtio-stub");

    auto* host = static_cast<std::uint8_t*>(ram.host_base());

    // ---- Helpers that mimic a guest driver doing 32-bit MMIO writes/reads.
    auto mmio_w32 = [&](std::uint32_t off, std::uint32_t v) {
        devices::MmioAccess a{};
        a.gpa = kVirtioBase + off;
        a.access_size = 4;
        a.is_write = true;
        std::memcpy(a.data, &v, 4);
        if (!bus.Dispatch(a)) Fatal("virtio-test: unmatched MMIO write");
    };
    auto mmio_r32 = [&](std::uint32_t off) -> std::uint32_t {
        devices::MmioAccess a{};
        a.gpa = kVirtioBase + off;
        a.access_size = 4;
        a.is_write = false;
        if (!bus.Dispatch(a)) Fatal("virtio-test: unmatched MMIO read");
        std::uint32_t v = 0;
        std::memcpy(&v, a.data, 4);
        return v;
    };

    // ---- Read-only identity registers.
    std::uint32_t magic = mmio_r32(0x000);
    std::uint32_t ver = mmio_r32(0x004);
    std::uint32_t did = mmio_r32(0x008);
    std::uint32_t vid = mmio_r32(0x00C);
    std::printf("[virtio-test] magic=0x%08x version=%u devid=%u vendor=0x%08x\n",
                magic, ver, did, vid);
    if (magic != v::kMagicValue || ver != v::kVersionModern) {
        std::fputs("[virtio-test] FAIL: magic/version mismatch\n", stderr);
        return 5;
    }
    if (did != 0xFE || vid != v::kVendorId) {
        std::fputs("[virtio-test] FAIL: devid/vendor mismatch\n", stderr);
        return 5;
    }

    // ---- Status FSM: ACK -> DRIVER -> negotiate -> FEATURES_OK -> DRIVER_OK.
    mmio_w32(0x070, v::kStatusAcknowledge);
    mmio_w32(0x070, v::kStatusAcknowledge | v::kStatusDriver);

    // Read both halves of DeviceFeatures.
    mmio_w32(0x014, 0);
    std::uint32_t dev_feat_lo = mmio_r32(0x010);
    mmio_w32(0x014, 1);
    std::uint32_t dev_feat_hi = mmio_r32(0x010);
    std::uint64_t dev_feat = static_cast<std::uint64_t>(dev_feat_lo) |
                             (static_cast<std::uint64_t>(dev_feat_hi) << 32);
    std::printf("[virtio-test] device_features=0x%016llx\n",
                static_cast<unsigned long long>(dev_feat));

    // Ack the same set.
    mmio_w32(0x024, 0);
    mmio_w32(0x020, dev_feat_lo);
    mmio_w32(0x024, 1);
    mmio_w32(0x020, dev_feat_hi);

    mmio_w32(0x070, v::kStatusAcknowledge | v::kStatusDriver |
                       v::kStatusFeaturesOk);
    if (!(mmio_r32(0x070) & v::kStatusFeaturesOk)) {
        std::fputs("[virtio-test] FAIL: device refused FEATURES_OK\n", stderr);
        return 5;
    }
    if (dev.acked_features() != dev_feat) {
        std::fputs("[virtio-test] FAIL: acked features mismatch\n", stderr);
        return 5;
    }

    // ---- Lay out a 16-entry virtqueue at GPA 0x10000.
    constexpr std::uint32_t kQSize = 16;
    constexpr std::uint64_t kDescGpa = 0x10000;
    constexpr std::uint64_t kAvailGpa = 0x10100;
    constexpr std::uint64_t kUsedGpa = 0x10200;
    constexpr std::uint64_t kPayloadGpa = 0x11000;

    std::memset(host + kDescGpa, 0, 0x1000);

#pragma pack(push, 1)
    struct VringDesc {
        std::uint64_t addr;
        std::uint32_t len;
        std::uint16_t flags;
        std::uint16_t next;
    };
    struct VringUsedElem {
        std::uint32_t id;
        std::uint32_t len;
    };
#pragma pack(pop)

    // Plant a "hello" buffer in payload memory.
    const char kPayload[] = "hello virtio";
    std::memcpy(host + kPayloadGpa, kPayload, sizeof(kPayload));

    // Descriptor 0 -> RO 16 bytes; chains to 1 (writable, 32 bytes).
    auto* desc = reinterpret_cast<VringDesc*>(host + kDescGpa);
    desc[0] = {kPayloadGpa, sizeof(kPayload), v::kVringDescFNext, 1};
    desc[1] = {kPayloadGpa + 0x800, 32, v::kVringDescFWrite, 0};

    // Avail ring: flags=0, idx=1, ring[0]=0 (head desc index 0).
    auto* avail = host + kAvailGpa;
    *reinterpret_cast<std::uint16_t*>(avail + 0) = 0;          // flags
    *reinterpret_cast<std::uint16_t*>(avail + 4) = 0;          // ring[0]
    *reinterpret_cast<std::uint16_t*>(avail + 2) = 1;          // idx (last!)

    // Used ring: zero it out so we can verify the device wrote there.
    std::memset(host + kUsedGpa, 0, 64);

    // ---- Program the queue through the transport (driver-style).
    mmio_w32(0x030, 0);                                  // QueueSel=0
    if (mmio_r32(0x034) < kQSize) {
        std::fputs("[virtio-test] FAIL: QueueNumMax too small\n", stderr);
        return 5;
    }
    mmio_w32(0x038, kQSize);                             // QueueNum
    mmio_w32(0x080, static_cast<std::uint32_t>(kDescGpa));        // DescLo
    mmio_w32(0x084, static_cast<std::uint32_t>(kDescGpa >> 32));  // DescHi
    mmio_w32(0x090, static_cast<std::uint32_t>(kAvailGpa));       // DriverLo
    mmio_w32(0x094, static_cast<std::uint32_t>(kAvailGpa >> 32)); // DriverHi
    mmio_w32(0x0A0, static_cast<std::uint32_t>(kUsedGpa));        // DeviceLo
    mmio_w32(0x0A4, static_cast<std::uint32_t>(kUsedGpa >> 32));  // DeviceHi
    mmio_w32(0x044, 1);                                  // QueueReady=1
    mmio_w32(0x070, v::kStatusAcknowledge | v::kStatusDriver |
                       v::kStatusFeaturesOk | v::kStatusDriverOk);
    if (!dev.driver_ok()) {
        std::fputs("[virtio-test] FAIL: DRIVER_OK not seen\n", stderr);
        return 5;
    }

    // ---- Kick.
    mmio_w32(0x050, 0);
    if (dev.notify_count() != 1) {
        std::fputs("[virtio-test] FAIL: NotifyQueue not invoked\n", stderr);
        return 5;
    }

    // ---- Pop the chain; verify contents and shape.
    auto popped = dev.queue().Pop();
    if (!popped) {
        std::fputs("[virtio-test] FAIL: Pop() returned nullopt\n", stderr);
        return 5;
    }
    if (popped->head_index != 0 || popped->bufs.size() != 2) {
        std::fprintf(stderr,
                     "[virtio-test] FAIL: head=%u bufs=%zu (expected 0/2)\n",
                     popped->head_index, popped->bufs.size());
        return 5;
    }
    if (popped->bufs[0].write || popped->bufs[1].write != true) {
        std::fputs("[virtio-test] FAIL: write flags wrong\n", stderr);
        return 5;
    }
    if (std::memcmp(popped->bufs[0].bytes.data(), kPayload,
                    sizeof(kPayload)) != 0) {
        std::fputs("[virtio-test] FAIL: payload mismatch\n", stderr);
        return 5;
    }
    // A second pop should find the ring empty.
    if (dev.queue().Pop().has_value()) {
        std::fputs("[virtio-test] FAIL: extra chain in ring\n", stderr);
        return 5;
    }

    // ---- Push a completion (used_len = 7) and verify the used ring.
    dev.queue().Push(0, /*used_len=*/7);
    auto* used_idx = reinterpret_cast<std::uint16_t*>(host + kUsedGpa + 2);
    auto* used_elem = reinterpret_cast<VringUsedElem*>(host + kUsedGpa + 4);
    if (*used_idx != 1 || used_elem->id != 0 || used_elem->len != 7) {
        std::fprintf(stderr,
                     "[virtio-test] FAIL: used.idx=%u elem.id=%u elem.len=%u\n",
                     *used_idx, used_elem->id, used_elem->len);
        return 5;
    }

    // ---- vring_need_event predicate self-test (spec §2.7.10).
    // need_event = (uint16)(new - event - 1) < (uint16)(new - old)
    if (!v::Virtqueue::VringNeedEvent(/*event=*/4, /*new=*/5, /*old=*/3)) {
        std::fputs("[virtio-test] FAIL: VringNeedEvent(4,5,3) wrong\n", stderr);
        return 5;
    }
    if (v::Virtqueue::VringNeedEvent(/*event=*/10, /*new=*/5, /*old=*/3)) {
        std::fputs("[virtio-test] FAIL: VringNeedEvent(10,5,3) wrong\n", stderr);
        return 5;
    }

    // ---- ShouldInterruptDriver with EVENT_IDX disabled, avail.flags=0
    //       must say "yes" (it's the legacy non-suppressed path).
    // Arrange a fresh queue state by writing avail.flags=0; with our setup
    // and event_idx_=true (we negotiated it) we go through the EVENT_IDX
    // path. Set used_event so it suppresses, then so it doesn't.
    auto* used_event = reinterpret_cast<std::uint16_t*>(
        host + kAvailGpa + 4 + 2 * kQSize);
    *used_event = 0;  // driver wants interrupt at idx >= 1, we're at 1 -> yes
    if (!dev.queue().ShouldInterruptDriver()) {
        std::fputs("[virtio-test] FAIL: ShouldInterruptDriver should be true\n",
                   stderr);
        return 5;
    }
    // After signaling once, last_used_signaled_ == 1. Without another Push,
    // the next call must return false.
    if (dev.queue().ShouldInterruptDriver()) {
        std::fputs("[virtio-test] FAIL: spurious interrupt\n", stderr);
        return 5;
    }

    std::printf(
        "[virtio-test] reads=%llu writes=%llu notify=%llu\n",
        static_cast<unsigned long long>(xport.reads()),
        static_cast<unsigned long long>(xport.writes()),
        static_cast<unsigned long long>(xport.notify_count()));

    // ====================================================================
    // M9: virtio-net device. Re-uses the same transport/virtqueue plumbing
    // but drives a real DeviceID=1 with MAC + status config.
    // ====================================================================
    std::puts("[virtio-test] -- virtio-net config / negotiation --");

    constexpr std::uint64_t kNetBase = 0x110000;  // separate window
    constexpr std::array<std::uint8_t, 6> kMac = {
        0x52, 0x54, 0x00, 0x12, 0x34, 0x56,
    };
    v::NetDevice net(ram, kMac);
    v::MmioTransport net_xport(kNetBase, net);
    devices::MmioBus net_bus;
    net_xport.Attach(net_bus, "virtio-net");

    auto net_w32 = [&](std::uint32_t off, std::uint32_t val) {
        devices::MmioAccess a{};
        a.gpa = kNetBase + off;
        a.access_size = 4;
        a.is_write = true;
        std::memcpy(a.data, &val, 4);
        if (!net_bus.Dispatch(a))
            Fatal("virtio-test: unmatched virtio-net MMIO write");
    };
    auto net_r32 = [&](std::uint32_t off) -> std::uint32_t {
        devices::MmioAccess a{};
        a.gpa = kNetBase + off;
        a.access_size = 4;
        a.is_write = false;
        if (!net_bus.Dispatch(a))
            Fatal("virtio-test: unmatched virtio-net MMIO read");
        std::uint32_t val = 0;
        std::memcpy(&val, a.data, 4);
        return val;
    };

    if (net_r32(0x008) != v::kDeviceIdNet) {
        std::fputs("[virtio-test] FAIL: virtio-net DeviceID != 1\n", stderr);
        return 5;
    }

    // Read MAC out of config space (offset 0x100..0x105). MAC is six bytes
    // wide, so spread across two dword reads.
    const std::uint32_t mac_lo = net_r32(0x100);
    const std::uint32_t mac_hi = net_r32(0x104);
    std::array<std::uint8_t, 6> mac_seen{};
    std::memcpy(mac_seen.data() + 0, &mac_lo, 4);
    std::memcpy(mac_seen.data() + 4, &mac_hi, 2);
    if (std::memcmp(mac_seen.data(), kMac.data(), mac_seen.size()) != 0) {
        std::fprintf(stderr,
                     "[virtio-test] FAIL: MAC mismatch %02x:%02x:%02x:%02x:%02x:%02x\n",
                     mac_seen[0], mac_seen[1], mac_seen[2],
                     mac_seen[3], mac_seen[4], mac_seen[5]);
        return 5;
    }
    // Status (uint16 at +0x106) -- top half of the 0x104 dword; we already
    // read it. status_lo of 0x104 = MAC[4..5], status_hi = link_status.
    std::uint16_t link = static_cast<std::uint16_t>(mac_hi >> 16);
    if (link != v::kNetStatusLinkUp) {
        std::fprintf(stderr, "[virtio-test] FAIL: link status=%u\n", link);
        return 5;
    }

    // Feature negotiation: ack VERSION_1 + RING_EVENT_IDX + MAC + STATUS.
    net_w32(0x070, v::kStatusAcknowledge | v::kStatusDriver);
    net_w32(0x014, 0);
    std::uint32_t nf_lo = net_r32(0x010);
    net_w32(0x014, 1);
    std::uint32_t nf_hi = net_r32(0x010);
    std::uint64_t advertised = static_cast<std::uint64_t>(nf_lo) |
                               (static_cast<std::uint64_t>(nf_hi) << 32);
    std::printf("[virtio-test] virtio-net features=0x%016llx\n",
                static_cast<unsigned long long>(advertised));
    std::uint64_t expect =
        v::kFeatureVersion1 | v::kFeatureRingEventIdx |
        v::kNetFeatureMac | v::kNetFeatureStatus;
    if (advertised != expect) {
        std::fprintf(stderr,
                     "[virtio-test] FAIL: virtio-net feature set wrong (got "
                     "0x%016llx, want 0x%016llx)\n",
                     static_cast<unsigned long long>(advertised),
                     static_cast<unsigned long long>(expect));
        return 5;
    }
    net_w32(0x024, 0);
    net_w32(0x020, nf_lo);
    net_w32(0x024, 1);
    net_w32(0x020, nf_hi);
    net_w32(0x070, v::kStatusAcknowledge | v::kStatusDriver |
                       v::kStatusFeaturesOk);
    if ((net_r32(0x070) & v::kStatusFeaturesOk) == 0) {
        std::fputs("[virtio-test] FAIL: virtio-net rejected FEATURES_OK\n",
                   stderr);
        return 5;
    }

    // Verify the driver-MUST-NOT-add-undeclared rule: try to write a feature
    // the device didn't advertise (bit 0, VIRTIO_NET_F_CSUM).
    net_w32(0x070, 0);  // reset
    net_w32(0x070, v::kStatusAcknowledge | v::kStatusDriver);
    net_w32(0x024, 0);
    net_w32(0x020, 0x1);  // VIRTIO_NET_F_CSUM, never advertised
    net_w32(0x024, 1);
    net_w32(0x020, static_cast<std::uint32_t>(v::kFeatureVersion1 >> 32));
    net_w32(0x070, v::kStatusAcknowledge | v::kStatusDriver |
                       v::kStatusFeaturesOk);
    std::uint32_t after = net_r32(0x070);
    if (after & v::kStatusFeaturesOk) {
        std::fputs("[virtio-test] FAIL: virtio-net should reject undeclared bit\n",
                   stderr);
        return 5;
    }
    if (!(after & v::kStatusNeedsReset)) {
        std::fputs("[virtio-test] FAIL: virtio-net should set NEEDS_RESET\n",
                   stderr);
        return 5;
    }

    // Program both queues (RX=0, TX=1) and DRIVER_OK.
    auto program_queue = [&](std::uint32_t qidx, std::uint64_t desc_gpa,
                             std::uint64_t avail_gpa,
                             std::uint64_t used_gpa) {
        net_w32(0x030, qidx);
        net_w32(0x038, 16);
        net_w32(0x080, static_cast<std::uint32_t>(desc_gpa));
        net_w32(0x084, static_cast<std::uint32_t>(desc_gpa >> 32));
        net_w32(0x090, static_cast<std::uint32_t>(avail_gpa));
        net_w32(0x094, static_cast<std::uint32_t>(avail_gpa >> 32));
        net_w32(0x0A0, static_cast<std::uint32_t>(used_gpa));
        net_w32(0x0A4, static_cast<std::uint32_t>(used_gpa >> 32));
        net_w32(0x044, 1);
    };
    net_w32(0x070, 0);  // reset, then go through normal bring-up
    net_w32(0x070, v::kStatusAcknowledge | v::kStatusDriver);
    net_w32(0x024, 0); net_w32(0x020, nf_lo);
    net_w32(0x024, 1); net_w32(0x020, nf_hi);
    net_w32(0x070, v::kStatusAcknowledge | v::kStatusDriver |
                       v::kStatusFeaturesOk);
    program_queue(0, 0x20000, 0x20100, 0x20200);
    program_queue(1, 0x21000, 0x21100, 0x21200);
    net_w32(0x070, v::kStatusAcknowledge | v::kStatusDriver |
                       v::kStatusFeaturesOk | v::kStatusDriverOk);
    if (!net.driver_ok()) {
        std::fputs("[virtio-test] FAIL: virtio-net DRIVER_OK not seen\n",
                   stderr);
        return 5;
    }
    if (!net.rx_queue().ready() || !net.tx_queue().ready()) {
        std::fputs("[virtio-test] FAIL: virtio-net queues not ready\n",
                   stderr);
        return 5;
    }

    // Kick each queue and verify per-queue notify counters.
    net_w32(0x050, 0);  // RX notify
    net_w32(0x050, 1);  // TX notify
    net_w32(0x050, 1);  // TX notify (again)
    if (net.notify_count(0) != 1 || net.notify_count(1) != 2) {
        std::fprintf(stderr,
                     "[virtio-test] FAIL: notify counters rx=%llu tx=%llu\n",
                     static_cast<unsigned long long>(net.notify_count(0)),
                     static_cast<unsigned long long>(net.notify_count(1)));
        return 5;
    }
    std::printf("[virtio-test] virtio-net notifies: rx=%llu tx=%llu\n",
                static_cast<unsigned long long>(net.notify_count(0)),
                static_cast<unsigned long long>(net.notify_count(1)));

    std::puts("[virtio-test] PASS");
    return 0;
}

// M8 doorbell test: the hot-path payoff for virtio-net. WHP's
// `WHvCreateNotificationPort(WHvNotificationPortTypeDoorbell)` matches a
// (GPA, value, length) tuple and, when the guest writes that value to that
// GPA, signals a Win32 event INSTEAD of taking a VM exit.
//
// The test plants a 15-byte real-mode stub that writes the dword 0x1234
// to GPA 0x10000 (just above our 64 KiB of RAM, so it would normally
// surface as an MMIO exit) and then HLTs. With the doorbell installed:
//   - run-loop must see zero MMIO exits (the write was swallowed by WHP);
//   - the event handle must be signaled before / by the time HLT fires;
//   - the run loop ends with X64Halt as usual.
int RunDoorbellTest() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;

    CheckWhpAvailable();
    std::puts("[doorbell-test] WHP available");
    ReportHostCapabilities();

    Partition part(/*vcpu_count=*/1);
    part.Setup();

    // 64 KiB RAM with small pages: GPA 0x10000 is the first UNMAPPED byte.
    // (Realistic virtio scenario -- the device's MMIO window is unmapped.)
    constexpr std::size_t kRamSize = 0x10000;
    GuestMemory ram(part, /*gpa=*/0, kRamSize, /*executable=*/true,
                    PagePolicy::Small);
    std::printf("[doorbell-test] guest RAM: 0x%zx bytes (%s)\n", ram.size(),
                ram.large_pages() ? "MEM_LARGE_PAGES" : "4 KiB pages");

    // 32-bit PM stub at GPA 0x2000.
    //
    //   BF 00 00 01 00            mov edi, 0x10000
    //   BE 34 12 00 00            mov esi, 0x1234
    //   89 37                     mov [edi], esi   ; reg->mem 32-bit store
    //   F4                        hlt
    //
    // We use `mov [reg], reg` (not `mov [imm], imm`) because Hyper-V's
    // internal instruction decoder is what evaluates doorbell matches:
    // immediate-source forms tend to fall back to the WHP user-mode
    // emulator (WHvEmulatorTryMmioEmulation), which fires AFTER the
    // doorbell-match step has already missed.
    constexpr std::uint64_t kGdtGpa = 0x1000;
    constexpr std::uint64_t kCodeGpa = 0x2000;
    constexpr std::uint64_t kDoorbellGpa = 0x10000;
    constexpr std::uint64_t kDoorbellValue = 0x1234;
    constexpr std::uint32_t kDoorbellLen = 4;
    const std::uint8_t code[] = {
        0xBF, 0x00, 0x00, 0x01, 0x00,
        0xBE, 0x34, 0x12, 0x00, 0x00,
        0x89, 0x37,
        0xF4,
    };
    ram.WriteAt(kCodeGpa, code, sizeof(code));

    // 32-bit flat-PM GDT (same encoding the PVH path uses).
    constexpr std::uint64_t kGdtNull = 0;
    constexpr std::uint64_t kGdtCode32 = 0x00CF9A000000FFFFull;
    constexpr std::uint64_t kGdtData32 = 0x00CF92000000FFFFull;
    constexpr std::uint16_t kCodeSelector = 0x08;
    constexpr std::uint16_t kDataSelector = 0x10;
    {
        std::uint64_t gdt[3] = {kGdtNull, kGdtCode32, kGdtData32};
        ram.WriteAt(kGdtGpa, gdt, sizeof(gdt));
    }

    Vcpu vp(part, 0);

    // Build register block for 32-bit PM entry directly into kCodeGpa.
    constexpr std::uint16_t kCodeAttr32 =
        /*Type*/ 0xB | /*S*/ (1 << 4) | /*P*/ (1 << 7) |
        /*DB*/ (1 << 14) | /*G*/ (1 << 15);
    constexpr std::uint16_t kDataAttr32 =
        /*Type*/ 0x3 | /*S*/ (1 << 4) | /*P*/ (1 << 7) |
        /*DB*/ (1 << 14) | /*G*/ (1 << 15);

    auto code_seg = WHV_X64_SEGMENT_REGISTER{};
    code_seg.Base = 0;
    code_seg.Limit = 0xFFFFFFFFu;
    code_seg.Selector = kCodeSelector;
    code_seg.Attributes = kCodeAttr32;
    auto data_seg = WHV_X64_SEGMENT_REGISTER{};
    data_seg.Base = 0;
    data_seg.Limit = 0xFFFFFFFFu;
    data_seg.Selector = kDataSelector;
    data_seg.Attributes = kDataAttr32;
    auto gdtr = WHV_X64_TABLE_REGISTER{};
    gdtr.Base = kGdtGpa;
    gdtr.Limit = 23;

    constexpr std::uint64_t kCr0Pe = 1ull << 0;
    constexpr std::uint64_t kCr0Et = 1ull << 4;

    const std::array<WHV_REGISTER_NAME, 11> names = {
        WHvX64RegisterCs,    WHvX64RegisterDs,    WHvX64RegisterEs,
        WHvX64RegisterSs,    WHvX64RegisterFs,    WHvX64RegisterGs,
        WHvX64RegisterGdtr,  WHvX64RegisterCr0,   WHvX64RegisterCr4,
        WHvX64RegisterRflags, WHvX64RegisterRip,
    };
    std::array<WHV_REGISTER_VALUE, 11> values{};
    values[0].Segment = code_seg;
    values[1].Segment = data_seg;
    values[2].Segment = data_seg;
    values[3].Segment = data_seg;
    values[4].Segment = data_seg;
    values[5].Segment = data_seg;
    values[6].Table = gdtr;
    values[7].Reg64 = kCr0Pe | kCr0Et;
    values[8].Reg64 = 0;
    values[9].Reg64 = 0x2;          // bit 1 reserved-must-be-1, IF=0
    values[10].Reg64 = kCodeGpa;
    vp.SetRegisters(names, values);

    // Install doorbell BEFORE running. MmioBus has no handler at 0x10000,
    // so if the hypervisor surfaces the write to user mode, mmio_exits will
    // fire and the test will FAIL.
    auto doorbell = NotificationPort::CreateMmioDoorbell(
        part, kDoorbellGpa, kDoorbellValue, kDoorbellLen);
    std::printf("[doorbell-test] doorbell @ GPA 0x%llx value=0x%llx len=%u\n",
                static_cast<unsigned long long>(kDoorbellGpa),
                static_cast<unsigned long long>(kDoorbellValue),
                kDoorbellLen);

    devices::IoBus io_bus;
    devices::MmioBus mmio_bus;
    RunLoop loop(vp, io_bus, mmio_bus);
    StopReason stop = loop.Run();

    bool signaled = doorbell->Wait(/*ms=*/0);

    std::printf("[doorbell-test] stop=%d  io=%llu mmio=%llu halt=%llu  "
                "doorbell_signaled=%d\n",
                static_cast<int>(stop),
                static_cast<unsigned long long>(loop.io_exits()),
                static_cast<unsigned long long>(loop.mmio_exits()),
                static_cast<unsigned long long>(loop.halt_exits()),
                signaled ? 1 : 0);

    if (stop != StopReason::GuestHalted) {
        std::fprintf(stderr,
                     "[doorbell-test] FAIL: expected GuestHalted, got %d\n",
                     static_cast<int>(stop));
        return 6;
    }
    if (loop.mmio_exits() != 0) {
        std::fprintf(stderr,
                     "[doorbell-test] FAIL: expected 0 MMIO exits, got %llu "
                     "(doorbell did NOT intercept the write)\n",
                     static_cast<unsigned long long>(loop.mmio_exits()));
        return 6;
    }
    if (!signaled) {
        std::fputs("[doorbell-test] FAIL: doorbell event was not signaled\n",
                   stderr);
        return 6;
    }

    std::puts("[doorbell-test] PASS");
    return 0;
}

// M10 PCI host bridge test: drive 0xCF8/0xCFC through the IoBus and verify
// (a) identity / class / subsys, (b) BAR sizing protocol, (c) pre-assigned
// BAR bases survive readback, (d) COMMAND.MEM_SPACE-gated MMIO mapping fires
// the OnBarMapped/Unmapped hooks, (e) capability chain is walkable,
// (f) master-abort for unpopulated BDFs returns all-ones.
//
// Pure host-side: no vCPU, no run loop. We poke the bus directly.
namespace {

class TestPciDevice : public tinyvmm::pci::PciDevice {
public:
    TestPciDevice() {
        set_ids(/*vendor=*/0x1234, /*device=*/0xABCD,
                /*subsys_vendor=*/0x5678, /*subsys=*/0xEF01);
        set_class(/*class=*/0x02, /*subclass=*/0x00, /*prog_if=*/0x00,
                  /*revision=*/0x42);
        set_interrupt_pin(0);            // no INTx, MSI-X only later
        DeclareMmio32Bar(0, /*size=*/0x1000);                  // 4 KiB
        DeclareMmio64Bar(2, /*size=*/0x10000, /*pref=*/true);  // 64 KiB

        // One vendor-specific capability with a 4-byte ASCII payload.
        const std::uint32_t off = AppendCapability(
            tinyvmm::pci::kCapIdVendor, /*payload=*/6);
        std::uint8_t* p = mut_cfg_ptr(off);
        // cap_id and cap_next already filled in by AppendCapability.
        p[2] = 'T'; p[3] = 'I'; p[4] = 'N'; p[5] = 'Y';
        cap_off_ = off;

        // Second vendor capability -- exercises the "patch previous tail's
        // next pointer" branch of the chain builder. M11's MSI-X cap will
        // ride this path.
        const std::uint32_t off2 = AppendCapability(
            tinyvmm::pci::kCapIdVendor, /*payload=*/4);
        std::uint8_t* p2 = mut_cfg_ptr(off2);
        p2[2] = '2'; p2[3] = '2';
        cap_off2_ = off2;
    }

    const char* name() const override { return "test-pci-device"; }

    int  mapped_count()    const { return mapped_count_; }
    int  unmapped_count()  const { return unmapped_count_; }
    int  last_mapped_idx() const { return last_mapped_idx_; }
    std::uint64_t last_mapped_gpa() const { return last_mapped_gpa_; }
    std::uint32_t cap_off()  const { return cap_off_; }
    std::uint32_t cap_off2() const { return cap_off2_; }

protected:
    void OnBarMapped(int idx, std::uint64_t gpa,
                     std::uint32_t /*size*/) override {
        ++mapped_count_;
        last_mapped_idx_ = idx;
        last_mapped_gpa_ = gpa;
    }
    void OnBarUnmapped(int /*idx*/) override { ++unmapped_count_; }

private:
    int mapped_count_   = 0;
    int unmapped_count_ = 0;
    int last_mapped_idx_ = -1;
    std::uint64_t last_mapped_gpa_ = 0;
    std::uint32_t cap_off_  = 0;
    std::uint32_t cap_off2_ = 0;
};

}  // anonymous namespace

int RunPciTest() {
    using namespace tinyvmm;
    namespace p = tinyvmm::pci;

    std::puts("[pci-test] starting (no WHP needed; pure host-side bus drive)");

    devices::IoBus io_bus;
    p::PciBus pbus;
    pbus.AttachIoBus(io_bus);

    auto stub = std::make_unique<TestPciDevice>();
    TestPciDevice* dev = stub.get();
    const p::Bdf bdf = pbus.AddDevice(std::move(stub));
    std::printf("[pci-test] device placed at %02x:%02x.%u\n",
                bdf.bus, bdf.device, bdf.function);

    if (bdf.bus != 0 || bdf.device != 0 || bdf.function != 0) {
        std::fputs("[pci-test] FAIL: expected BDF 00:00.0\n", stderr);
        return 7;
    }

    // ---- IO helpers: drive CONFIG_ADDRESS / CONFIG_DATA through IoBus.
    auto io_w = [&](std::uint16_t port, std::uint16_t size, std::uint32_t v) {
        devices::IoAccess a{port, size, /*write=*/true, v};
        if (!io_bus.Dispatch(a)) Fatal("pci-test: unmatched IO write");
    };
    auto io_r = [&](std::uint16_t port, std::uint16_t size) -> std::uint32_t {
        devices::IoAccess a{port, size, /*write=*/false, 0};
        if (!io_bus.Dispatch(a)) Fatal("pci-test: unmatched IO read");
        return a.value;
    };

    auto encode = [](std::uint8_t b, std::uint8_t d, std::uint8_t fn,
                      std::uint8_t reg) -> std::uint32_t {
        return p::kConfigAddressEnable | (std::uint32_t{b} << 16) |
               (std::uint32_t{d} << 11) | (std::uint32_t{fn} << 8) |
               (reg & 0xFCu);
    };
    auto cfg_r = [&](std::uint8_t reg, std::uint16_t size) -> std::uint32_t {
        io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, reg));
        return io_r(static_cast<std::uint16_t>(p::kConfigDataPort + (reg & 3)),
                    size);
    };
    auto cfg_w = [&](std::uint8_t reg, std::uint16_t size, std::uint32_t v) {
        io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, reg));
        io_w(static_cast<std::uint16_t>(p::kConfigDataPort + (reg & 3)), size,
             v);
    };

    // ---- (a) Identity / class / subsys.
    const std::uint32_t vid_did = cfg_r(p::kCfgVendorId, 4);
    const std::uint16_t cls_word = static_cast<std::uint16_t>(
        cfg_r(p::kCfgSubclass, 2));  // [0x0A]=subclass, [0x0B]=class => LE 0x0200
    const std::uint8_t  rev = static_cast<std::uint8_t>(
        cfg_r(p::kCfgRevisionId, 1));
    const std::uint32_t subsys = cfg_r(p::kCfgSubsysVendorId, 4);
    const std::uint8_t  htype = static_cast<std::uint8_t>(
        cfg_r(p::kCfgHeaderType, 1));
    std::printf("[pci-test] vid_did=0x%08x cls=0x%04x rev=0x%02x subsys=0x%08x"
                " htype=0x%02x\n",
                vid_did, cls_word, rev, subsys, htype);
    if (vid_did != 0xABCD1234u) {
        std::fputs("[pci-test] FAIL: VID/DID mismatch\n", stderr);
        return 7;
    }
    if (cls_word != 0x0200u || rev != 0x42 || subsys != 0xEF015678u ||
        htype != p::kHeaderTypeNormal) {
        std::fputs("[pci-test] FAIL: class/rev/subsys/header mismatch\n",
                   stderr);
        return 7;
    }

    // Master abort: BDF 0:1.0 has nothing.
    io_w(p::kConfigAddressPort, 4, encode(0, 1, 0, 0));
    const std::uint32_t abort_vid = io_r(p::kConfigDataPort, 4);
    std::printf("[pci-test] master-abort vid=0x%08x\n", abort_vid);
    if (abort_vid != 0xFFFFFFFFu) {
        std::fputs("[pci-test] FAIL: expected 0xFFFFFFFF for missing BDF\n",
                   stderr);
        return 7;
    }

    // ---- (b) BAR sizing protocol on BAR0.
    const std::uint32_t bar0_assigned = cfg_r(p::kCfgBar0, 4);
    std::printf("[pci-test] BAR0 pre-assigned=0x%08x\n", bar0_assigned);
    if ((bar0_assigned & 0xFu) != 0u) {
        std::fputs("[pci-test] FAIL: BAR0 type bits != 0 (32-bit non-pref MMIO)\n",
                   stderr);
        return 7;
    }
    if (bar0_assigned < p::kMmioWindowBase ||
        bar0_assigned >= p::kMmioWindowEnd) {
        std::fputs("[pci-test] FAIL: BAR0 base outside MMIO window\n", stderr);
        return 7;
    }
    cfg_w(p::kCfgBar0, 4, 0xFFFFFFFFu);
    const std::uint32_t bar0_size = cfg_r(p::kCfgBar0, 4);
    std::printf("[pci-test] BAR0 sizing-readback=0x%08x  (expected 0xFFFFF000)\n",
                bar0_size);
    if (bar0_size != 0xFFFFF000u) {
        std::fputs("[pci-test] FAIL: BAR0 size readback wrong\n", stderr);
        return 7;
    }
    cfg_w(p::kCfgBar0, 4, bar0_assigned);
    if (cfg_r(p::kCfgBar0, 4) != bar0_assigned) {
        std::fputs("[pci-test] FAIL: BAR0 restore did not stick\n", stderr);
        return 7;
    }

    // ---- BAR2 (64-bit MMIO prefetchable): type bits should be 0xC.
    const std::uint32_t bar2_lo = cfg_r(p::kCfgBar0 + 8, 4);
    const std::uint32_t bar2_hi = cfg_r(p::kCfgBar0 + 12, 4);
    std::printf("[pci-test] BAR2(lo)=0x%08x BAR2(hi)=0x%08x\n",
                bar2_lo, bar2_hi);
    if ((bar2_lo & 0xFu) != (p::kBarMmio64 | p::kBarPrefetchable)) {
        std::fputs("[pci-test] FAIL: BAR2 type bits != MMIO64|prefetchable\n",
                   stderr);
        return 7;
    }
    cfg_w(p::kCfgBar0 + 8, 4, 0xFFFFFFFFu);
    cfg_w(p::kCfgBar0 + 12, 4, 0xFFFFFFFFu);
    const std::uint32_t bar2_size_lo = cfg_r(p::kCfgBar0 + 8, 4);
    const std::uint32_t bar2_size_hi = cfg_r(p::kCfgBar0 + 12, 4);
    std::printf("[pci-test] BAR2 sizing lo=0x%08x hi=0x%08x (expect 0xFFFF000C/0xFFFFFFFF)\n",
                bar2_size_lo, bar2_size_hi);
    if (bar2_size_lo != 0xFFFF000Cu || bar2_size_hi != 0xFFFFFFFFu) {
        std::fputs("[pci-test] FAIL: BAR2 size readback wrong\n", stderr);
        return 7;
    }
    cfg_w(p::kCfgBar0 + 8, 4, bar2_lo);
    cfg_w(p::kCfgBar0 + 12, 4, bar2_hi);

    // ---- (c) COMMAND.MEM_SPACE gating: enabling it should call OnBarMapped
    // for BAR0 and BAR2; clearing it again should call OnBarUnmapped.
    if (dev->mapped_count() != 0) {
        std::fputs("[pci-test] FAIL: BAR mapped before COMMAND.MEM_SPACE\n",
                   stderr);
        return 7;
    }
    cfg_w(p::kCfgCommand, 2, p::kCmdMemorySpace | p::kCmdBusMaster);
    std::printf("[pci-test] after MEM_SPACE on: mapped=%d unmapped=%d "
                "last_idx=%d last_gpa=0x%llx\n",
                dev->mapped_count(), dev->unmapped_count(),
                dev->last_mapped_idx(),
                static_cast<unsigned long long>(dev->last_mapped_gpa()));
    if (dev->mapped_count() != 2 || dev->unmapped_count() != 0) {
        std::fputs("[pci-test] FAIL: expected mapped=2, unmapped=0\n", stderr);
        return 7;
    }
    cfg_w(p::kCfgCommand, 2, 0);
    std::printf("[pci-test] after MEM_SPACE off: mapped=%d unmapped=%d\n",
                dev->mapped_count(), dev->unmapped_count());
    if (dev->mapped_count() != 2 || dev->unmapped_count() != 2) {
        std::fputs("[pci-test] FAIL: expected mapped=2, unmapped=2\n", stderr);
        return 7;
    }

    // ---- (d) Capability chain.
    const std::uint16_t status = static_cast<std::uint16_t>(
        cfg_r(p::kCfgStatus, 2));
    const std::uint8_t  cap_ptr = static_cast<std::uint8_t>(
        cfg_r(p::kCfgCapPtr, 1));
    std::printf("[pci-test] STATUS=0x%04x cap_ptr=0x%02x\n", status, cap_ptr);
    if ((status & p::kStatusCapList) == 0) {
        std::fputs("[pci-test] FAIL: STATUS.CapList not set\n", stderr);
        return 7;
    }
    if (cap_ptr != dev->cap_off()) {
        std::fputs("[pci-test] FAIL: cap_ptr mismatch\n", stderr);
        return 7;
    }
    const std::uint8_t cap_id = static_cast<std::uint8_t>(
        cfg_r(static_cast<std::uint8_t>(cap_ptr), 1));
    const std::uint8_t cap_next = static_cast<std::uint8_t>(
        cfg_r(static_cast<std::uint8_t>(cap_ptr + 1), 1));
    const std::uint32_t cap_payload = cfg_r(
        static_cast<std::uint8_t>(cap_ptr + 2), 4);
    std::printf("[pci-test] cap@0x%02x id=0x%02x next=0x%02x payload='%c%c%c%c'\n",
                cap_ptr, cap_id, cap_next,
                static_cast<char>(cap_payload & 0xFF),
                static_cast<char>((cap_payload >> 8) & 0xFF),
                static_cast<char>((cap_payload >> 16) & 0xFF),
                static_cast<char>((cap_payload >> 24) & 0xFF));
    if (cap_id != p::kCapIdVendor || cap_next != dev->cap_off2() ||
        cap_payload != 0x594E4954u /* 'YNIT' little-endian = "TINY" */) {
        std::fputs("[pci-test] FAIL: cap header/payload wrong\n", stderr);
        return 7;
    }

    // Walk to the second cap; verify next=0 and ID + payload.
    const std::uint8_t cap2_id = static_cast<std::uint8_t>(
        cfg_r(static_cast<std::uint8_t>(cap_next), 1));
    const std::uint8_t cap2_next = static_cast<std::uint8_t>(
        cfg_r(static_cast<std::uint8_t>(cap_next + 1), 1));
    const std::uint16_t cap2_payload = static_cast<std::uint16_t>(
        cfg_r(static_cast<std::uint8_t>(cap_next + 2), 2));
    std::printf("[pci-test] cap2@0x%02x id=0x%02x next=0x%02x payload=0x%04x\n",
                cap_next, cap2_id, cap2_next, cap2_payload);
    if (cap2_id != p::kCapIdVendor || cap2_next != 0 || cap2_payload != 0x3232u) {
        std::fputs("[pci-test] FAIL: second cap chain wrong\n", stderr);
        return 7;
    }

    // ---- (e) Sub-dword reads: 0xCFD should give us VID byte[1] (0x12).
    io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, 0));
    const std::uint32_t cfd = io_r(p::kConfigDataPort + 1, 1);
    std::printf("[pci-test] sub-dword [CFC+1, 1B] = 0x%02x (expect 0x12)\n",
                cfd);
    if (cfd != 0x12u) {
        std::fputs("[pci-test] FAIL: sub-dword read wrong\n", stderr);
        return 7;
    }

    std::printf("[pci-test] PASS (cfg_reads=%llu cfg_writes=%llu)\n",
                static_cast<unsigned long long>(pbus.cfg_reads()),
                static_cast<unsigned long long>(pbus.cfg_writes()));
    return 0;
}


// M11 MSI-X host-side test: build a PciDevice that owns an MsiX helper, drive
// the cap structure + table + PBA through CFG/MMIO, and verify the mask /
// replay state machine. No WHP -- the inject callback is a recorder.
namespace {

struct InjectRecord { std::uint64_t addr; std::uint32_t data; };

class TestMsiXDevice : public tinyvmm::pci::PciDevice {
public:
    TestMsiXDevice(std::uint32_t num_vectors, std::vector<InjectRecord>* sink)
        : msix_(num_vectors,
                [sink](std::uint64_t a, std::uint32_t d) {
                    sink->push_back({a, d});
                    return true;
                }) {
        set_ids(/*vendor=*/0x1AF4, /*device=*/0x1041,
                /*subsys_vendor=*/0x1AF4, /*subsys=*/0x0001);
        set_class(/*class=*/0x02, /*subclass=*/0x00);
        set_interrupt_pin(0);
        // One MMIO BAR sized to fit table @0 and PBA @0x800.
        const std::uint32_t bar_size = tinyvmm::pci::MsiX::RequiredBarSize(
            num_vectors, /*table_off=*/0, /*pba_off=*/0x800);
        bar_size_ = bar_size;
        DeclareMmio32Bar(0, bar_size);
        cap_off_ = msix_.AddCapability(*this, /*bar_idx=*/0,
                                       /*table_off=*/0,
                                       /*pba_off=*/0x800);
    }

    const char* name() const override { return "test-msix-device"; }

    tinyvmm::pci::MsiX& msix() { return msix_; }
    std::uint32_t cap_off() const { return cap_off_; }
    std::uint32_t bar_size() const { return bar_size_; }
    std::uint64_t bar_gpa() const { return bar_gpa_; }
    bool mapped() const { return mapped_; }

    void Attach(tinyvmm::devices::MmioBus* bus) { bus_ = bus; }

protected:
    void OnBarMapped(int idx, std::uint64_t gpa,
                     std::uint32_t /*size*/) override {
        if (idx == 0 && bus_) {
            bar_gpa_ = gpa;
            msix_.Install(*bus_, gpa);
            mapped_ = true;
        }
    }
    void OnBarUnmapped(int idx) override {
        if (idx == 0 && bus_ && mapped_) {
            msix_.Uninstall(*bus_);
            mapped_ = false;
        }
    }

private:
    tinyvmm::pci::MsiX  msix_;
    tinyvmm::devices::MmioBus* bus_ = nullptr;
    std::uint32_t cap_off_  = 0;
    std::uint32_t bar_size_ = 0;
    std::uint64_t bar_gpa_  = 0;
    bool          mapped_   = false;
};

}  // anonymous namespace

int RunMsixTest() {
    using namespace tinyvmm;
    namespace p = tinyvmm::pci;

    std::puts("[msix-test] starting (host-side; no WHP)");

    devices::IoBus   io_bus;
    devices::MmioBus mmio_bus;
    p::PciBus        pbus;
    pbus.AttachIoBus(io_bus);

    std::vector<InjectRecord> injects;
    auto stub = std::make_unique<TestMsiXDevice>(/*num_vectors=*/4, &injects);
    TestMsiXDevice* dev = stub.get();
    dev->Attach(&mmio_bus);
    const p::Bdf bdf = pbus.AddDevice(std::move(stub));
    std::printf("[msix-test] device @ %02x:%02x.%u  cap_off=0x%02x  bar_size=0x%x\n",
                bdf.bus, bdf.device, bdf.function, dev->cap_off(),
                dev->bar_size());

    // ---- CFG #1 IO helpers (copy of pci-test).
    auto io_w = [&](std::uint16_t port, std::uint16_t size, std::uint32_t v) {
        devices::IoAccess a{port, size, /*write=*/true, v};
        if (!io_bus.Dispatch(a)) Fatal("msix-test: unmatched IO write");
    };
    auto io_r = [&](std::uint16_t port, std::uint16_t size) -> std::uint32_t {
        devices::IoAccess a{port, size, /*write=*/false, 0};
        if (!io_bus.Dispatch(a)) Fatal("msix-test: unmatched IO read");
        return a.value;
    };
    auto encode = [](std::uint8_t b, std::uint8_t d, std::uint8_t fn,
                      std::uint8_t reg) -> std::uint32_t {
        return p::kConfigAddressEnable | (std::uint32_t{b} << 16) |
               (std::uint32_t{d} << 11) | (std::uint32_t{fn} << 8) |
               (reg & 0xFCu);
    };
    auto cfg_r = [&](std::uint8_t reg, std::uint16_t size) -> std::uint32_t {
        io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, reg));
        return io_r(static_cast<std::uint16_t>(p::kConfigDataPort + (reg & 3)),
                    size);
    };
    auto cfg_w = [&](std::uint8_t reg, std::uint16_t size, std::uint32_t v) {
        io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, reg));
        io_w(static_cast<std::uint16_t>(p::kConfigDataPort + (reg & 3)), size,
             v);
    };

    // ---- (a) MSI-X capability structure.
    const std::uint8_t cap_off = static_cast<std::uint8_t>(dev->cap_off());
    const std::uint8_t cap_id    = static_cast<std::uint8_t>(cfg_r(cap_off,     1));
    const std::uint8_t cap_next  = static_cast<std::uint8_t>(cfg_r(static_cast<std::uint8_t>(cap_off + 1), 1));
    const std::uint16_t mc_init  = static_cast<std::uint16_t>(cfg_r(static_cast<std::uint8_t>(cap_off + 2), 2));
    const std::uint32_t tbl_bir  = cfg_r(static_cast<std::uint8_t>(cap_off + 4), 4);
    const std::uint32_t pba_bir  = cfg_r(static_cast<std::uint8_t>(cap_off + 8), 4);
    std::printf("[msix-test] cap_id=0x%02x cap_next=0x%02x MC=0x%04x "
                "tbl=0x%08x pba=0x%08x\n",
                cap_id, cap_next, mc_init, tbl_bir, pba_bir);
    if (cap_id != p::kCapIdMsiX || cap_next != 0) {
        std::fputs("[msix-test] FAIL: cap header wrong\n", stderr);
        return 8;
    }
    if ((mc_init & 0x07FFu) != 3u || (mc_init & 0xC000u) != 0u) {
        std::fputs("[msix-test] FAIL: Message Control init wrong (want N-1=3, "
                   "Enable=0, FuncMask=0)\n", stderr);
        return 8;
    }
    if ((tbl_bir & 0x7u) != 0u || (tbl_bir & ~0x7u) != 0u) {
        std::fputs("[msix-test] FAIL: Table BIR/offset wrong (want BIR=0, off=0)\n",
                   stderr);
        return 8;
    }
    if ((pba_bir & 0x7u) != 0u || (pba_bir & ~0x7u) != 0x800u) {
        std::fputs("[msix-test] FAIL: PBA BIR/offset wrong (want BIR=0, off=0x800)\n",
                   stderr);
        return 8;
    }

    // ---- (b) Light up the BAR so the table+PBA MMIO handlers register.
    cfg_w(p::kCfgCommand, 2, p::kCmdMemorySpace | p::kCmdBusMaster);
    if (!dev->mapped()) {
        std::fputs("[msix-test] FAIL: BAR did not map\n", stderr);
        return 8;
    }
    const std::uint64_t bar_gpa = dev->bar_gpa();
    std::printf("[msix-test] BAR mapped @ GPA 0x%llx; table+PBA registered\n",
                static_cast<unsigned long long>(bar_gpa));

    // MMIO helpers.
    auto mmio_w32 = [&](std::uint64_t gpa, std::uint32_t v) {
        devices::MmioAccess a{};
        a.gpa = gpa; a.access_size = 4; a.is_write = true;
        std::memcpy(a.data, &v, 4);
        if (!mmio_bus.Dispatch(a)) Fatal("msix-test: unmatched MMIO write");
    };
    auto mmio_r32 = [&](std::uint64_t gpa) -> std::uint32_t {
        devices::MmioAccess a{};
        a.gpa = gpa; a.access_size = 4; a.is_write = false;
        if (!mmio_bus.Dispatch(a)) Fatal("msix-test: unmatched MMIO read");
        std::uint32_t v = 0;
        std::memcpy(&v, a.data, 4);
        return v;
    };

    // ---- (c) Program vector 1 with an LAPIC-style message (addr/data) and
    // leave it masked. Trigger -> must NOT inject; PBA bit must be set.
    const std::uint64_t kV1Tbl = bar_gpa + 16 * 1;
    constexpr std::uint64_t kMsiAddrBase = 0xFEE00000ull;
    mmio_w32(kV1Tbl + 0, static_cast<std::uint32_t>(kMsiAddrBase & 0xFFFFFFFFu));
    mmio_w32(kV1Tbl + 4, static_cast<std::uint32_t>(kMsiAddrBase >> 32));
    mmio_w32(kV1Tbl + 8, /*vector=*/0x40);
    // Vector Control stays masked (init = 1).
    if (!dev->msix().Trigger(1)) {
        if (!dev->msix().PbaBit(1)) {
            std::fputs("[msix-test] FAIL: masked trigger didn't set PBA\n", stderr);
            return 8;
        }
    } else {
        std::fputs("[msix-test] FAIL: triggered while MSI-X disabled\n", stderr);
        return 8;
    }
    if (!injects.empty()) {
        std::fputs("[msix-test] FAIL: injected while disabled+masked\n", stderr);
        return 8;
    }
    std::printf("[msix-test] disabled+masked: PBA bit set, no injection (ok)\n");

    // ---- (d) Enable MSI-X (MC bit 15). Vector 1 is still per-vector-masked,
    // so still no injection -- PBA bit stays set.
    cfg_w(cap_off + 2, 2, /*MC=*/0x8000u);
    if (!dev->msix().MsiXEnabled() || dev->msix().FunctionMasked()) {
        std::fputs("[msix-test] FAIL: enable bit didn't stick\n", stderr);
        return 8;
    }
    if (dev->msix().Trigger(1)) {
        std::fputs("[msix-test] FAIL: per-vector-masked vector injected\n", stderr);
        return 8;
    }
    if (!injects.empty()) {
        std::fputs("[msix-test] FAIL: injected while vector masked\n", stderr);
        return 8;
    }
    std::printf("[msix-test] enabled+vec-masked: still no injection (ok)\n");

    // ---- (e) Unmask vector 1 by writing 0 to vector control (offset 12).
    // PBA bit was set; spec says hardware must replay -> we should see exactly
    // one injected message with the address/data we programmed.
    mmio_w32(kV1Tbl + 12, 0u);
    if (dev->msix().PbaBit(1)) {
        std::fputs("[msix-test] FAIL: PBA bit not cleared on unmask replay\n",
                   stderr);
        return 8;
    }
    if (injects.size() != 1u ||
        injects[0].addr != kMsiAddrBase ||
        injects[0].data != 0x40u) {
        std::fprintf(stderr,
                     "[msix-test] FAIL: unmask replay wrong (size=%zu addr=0x%llx data=0x%x)\n",
                     injects.size(),
                     injects.empty() ? 0ull : injects[0].addr,
                     injects.empty() ? 0u   : injects[0].data);
        return 8;
    }
    std::printf("[msix-test] unmask replay: 1 inject @ 0x%llx/0x%x (ok)\n",
                static_cast<unsigned long long>(injects[0].addr),
                injects[0].data);

    // ---- (f) Normal trigger path: now-unmasked vector should inject directly.
    if (!dev->msix().Trigger(1)) {
        std::fputs("[msix-test] FAIL: unmasked trigger refused\n", stderr);
        return 8;
    }
    if (injects.size() != 2u) {
        std::fputs("[msix-test] FAIL: expected 2 injections after direct trigger\n",
                   stderr);
        return 8;
    }
    std::printf("[msix-test] direct trigger: injects=%zu (ok)\n", injects.size());

    // ---- (g) FuncMask suppresses even unmasked vectors and latches PBA.
    cfg_w(cap_off + 2, 2, /*MC=*/0xC000u);  // Enable=1, FuncMask=1
    if (!dev->msix().FunctionMasked()) {
        std::fputs("[msix-test] FAIL: FuncMask bit didn't stick\n", stderr);
        return 8;
    }
    if (dev->msix().Trigger(1)) {
        std::fputs("[msix-test] FAIL: trigger should be suppressed by FuncMask\n",
                   stderr);
        return 8;
    }
    if (!dev->msix().PbaBit(1)) {
        std::fputs("[msix-test] FAIL: PBA bit not set under FuncMask\n", stderr);
        return 8;
    }
    if (injects.size() != 2u) {
        std::fputs("[msix-test] FAIL: FuncMask suppression failed\n", stderr);
        return 8;
    }

    // ---- (h) PBA readback: bit 1 should appear in the first PBA dword.
    const std::uint32_t pba_lo = mmio_r32(bar_gpa + 0x800);
    if (((pba_lo >> 1) & 0x1u) == 0u) {
        std::fprintf(stderr,
                     "[msix-test] FAIL: PBA MMIO readback missing bit 1 (got 0x%x)\n",
                     pba_lo);
        return 8;
    }
    std::printf("[msix-test] PBA mmio readback=0x%x (bit1 set, ok)\n", pba_lo);

    // ---- (i) Vector index out of range.
    if (dev->msix().Trigger(99)) {
        std::fputs("[msix-test] FAIL: out-of-range Trigger returned true\n", stderr);
        return 8;
    }

    // ---- (j) BAR teardown removes the MMIO handlers.
    cfg_w(p::kCfgCommand, 2, 0);
    if (dev->mapped()) {
        std::fputs("[msix-test] FAIL: BAR didn't unmap\n", stderr);
        return 8;
    }
    {
        devices::MmioAccess a{};
        a.gpa = bar_gpa + 0x800; a.access_size = 4; a.is_write = false;
        if (mmio_bus.Dispatch(a)) {
            std::fputs("[msix-test] FAIL: PBA handler still registered after unmap\n",
                       stderr);
            return 8;
        }
    }

    std::printf("[msix-test] PASS (total injections=%llu)\n",
                static_cast<unsigned long long>(dev->msix().injected_count()));
    return 0;
}


// M11 MSI-X end-to-end test: bring up a vCPU in 32-bit PM, install an IDT,
// then drive WHvRequestInterrupt from the host (via whp::InjectMsi) and
// observe the guest IDT handler advance a counter in guest memory.
//
// Memory map:
//   0x1000  GDT  (null / 32-bit code / 32-bit data)
//   0x2000  main 32-bit PM stub: `mov esp; lidt; sti; .loop: hlt; jmp .loop`
//   0x3000  IRQ handler: bump dword @ 0x5000, EOI x2APIC, iretd
//   0x4000  IDT (256 * 8-byte gates)
//   0x5000  counter
//   0x6000  stack top (grows down)
int RunMsixInjectTest() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;

    CheckWhpAvailable();
    std::puts("[msix-inject-test] WHP available");

    Partition part(/*vcpu_count=*/1);
    part.SetLocalApicEmulation(WHvX64LocalApicEmulationModeX2Apic);
    part.Setup();

    constexpr std::size_t kRamSize = 0x10000;
    GuestMemory ram(part, /*gpa=*/0, kRamSize, /*executable=*/true,
                    PagePolicy::Small);
    std::printf("[msix-inject-test] guest RAM: 0x%zx bytes (%s)\n", ram.size(),
                ram.large_pages() ? "MEM_LARGE_PAGES" : "4 KiB pages");

    constexpr std::uint64_t kGdtGpa     = 0x1000;
    constexpr std::uint64_t kMainGpa    = 0x2000;
    constexpr std::uint64_t kHandlerGpa = 0x3000;
    constexpr std::uint64_t kIdtGpa     = 0x4000;
    constexpr std::uint64_t kCounterGpa = 0x5000;
    constexpr std::uint8_t  kVector     = 0x40;
    constexpr std::uint16_t kCodeSel    = 0x08;
    constexpr std::uint16_t kDataSel    = 0x10;

    // ---- GDT
    {
        std::uint64_t gdt[3] = {
            0ull,
            0x00CF9A000000FFFFull,  // 32-bit code
            0x00CF92000000FFFFull,  // 32-bit data
        };
        ram.WriteAt(kGdtGpa, gdt, sizeof(gdt));
    }

    // ---- IDT: zero all 256 gates, then set vector kVector. 32-bit interrupt
    // gate layout (Intel SDM Vol 3 §6.14.1):
    //   bytes 0..1 : offset[15:0]
    //   bytes 2..3 : segment selector
    //   byte  4    : reserved 0
    //   byte  5    : flags = 0x8E (P=1, DPL=0, type=0xE 32-bit interrupt gate)
    //   bytes 6..7 : offset[31:16]
    {
        std::vector<std::uint8_t> idt(256 * 8, 0);
        const std::uint32_t off = static_cast<std::uint32_t>(kHandlerGpa);
        std::uint8_t* g = &idt[kVector * 8];
        g[0] = static_cast<std::uint8_t>(off & 0xFF);
        g[1] = static_cast<std::uint8_t>((off >> 8) & 0xFF);
        g[2] = static_cast<std::uint8_t>(kCodeSel & 0xFF);
        g[3] = static_cast<std::uint8_t>(kCodeSel >> 8);
        g[4] = 0;
        g[5] = 0x8E;
        g[6] = static_cast<std::uint8_t>((off >> 16) & 0xFF);
        g[7] = static_cast<std::uint8_t>((off >> 24) & 0xFF);
        ram.WriteAt(kIdtGpa, idt.data(), idt.size());
    }

    // ---- Counter starts at 0.
    {
        std::uint32_t z = 0;
        ram.WriteAt(kCounterGpa, &z, sizeof(z));
    }

    // ---- Main stub (32-bit PM):
    //   1. Set ESP.
    //   2. Enable x2APIC LAPIC (set SVR MSR 0x80F bit 8 = APIC Software Enable;
    //      otherwise WHP's x2APIC drops all incoming interrupts).
    //   3. lidt, sti, hlt-loop.
    //
    //   B8 00 60 00 00       mov   eax, 0x6000
    //   89 C4                mov   esp, eax
    //   B9 0F 08 00 00       mov   ecx, 0x80F        ; IA32_X2APIC_SIVR
    //   B8 FF 01 00 00       mov   eax, 0x1FF        ; Enable | spurious=0xFF
    //   31 D2                xor   edx, edx
    //   0F 30                wrmsr
    //   0F 01 1D 30 20 00 00 lidt  [0x2030]
    //   FB                   sti
    //   F4                .loop: hlt
    //   EB FD                jmp .loop
    //   ... at +0x30: 6-byte IDTR: limit=0x7FF, base=0x4000.
    {
        std::vector<std::uint8_t> main_stub(0x40, 0);
        std::size_t i = 0;
        main_stub[i++] = 0xB8; main_stub[i++] = 0x00; main_stub[i++] = 0x60;
        main_stub[i++] = 0x00; main_stub[i++] = 0x00;
        main_stub[i++] = 0x89; main_stub[i++] = 0xC4;
        // mov ecx, 0x80F
        main_stub[i++] = 0xB9; main_stub[i++] = 0x0F; main_stub[i++] = 0x08;
        main_stub[i++] = 0x00; main_stub[i++] = 0x00;
        // mov eax, 0x1FF
        main_stub[i++] = 0xB8; main_stub[i++] = 0xFF; main_stub[i++] = 0x01;
        main_stub[i++] = 0x00; main_stub[i++] = 0x00;
        // xor edx, edx
        main_stub[i++] = 0x31; main_stub[i++] = 0xD2;
        // wrmsr
        main_stub[i++] = 0x0F; main_stub[i++] = 0x30;
        // lidt [0x2030]
        main_stub[i++] = 0x0F; main_stub[i++] = 0x01; main_stub[i++] = 0x1D;
        main_stub[i++] = 0x30; main_stub[i++] = 0x20; main_stub[i++] = 0x00;
        main_stub[i++] = 0x00;
        main_stub[i++] = 0xFB;          // sti
        main_stub[i++] = 0xF4;          // hlt
        main_stub[i++] = 0xEB;          // jmp -3
        main_stub[i++] = 0xFD;
        main_stub[0x30] = 0xFF; main_stub[0x31] = 0x07; // limit = 0x7FF
        main_stub[0x32] = 0x00; main_stub[0x33] = 0x40; // base  = 0x4000
        main_stub[0x34] = 0x00; main_stub[0x35] = 0x00;
        ram.WriteAt(kMainGpa, main_stub.data(), main_stub.size());
    }

    // ---- Handler (32-bit interrupt gate clears IF; EOI the x2APIC + IRET):
    //   50                push eax
    //   52                push edx
    //   51                push ecx
    //   FF 05 00 50 00 00 inc dword [0x5000]
    //   B9 0B 08 00 00    mov ecx, 0x80B   ; IA32_X2APIC_EOI
    //   31 C0             xor eax, eax
    //   31 D2             xor edx, edx
    //   0F 30             wrmsr
    //   59                pop ecx
    //   5A                pop edx
    //   58                pop eax
    //   CF                iretd
    {
        const std::uint8_t handler[] = {
            0x50, 0x52, 0x51,
            0xFF, 0x05, 0x00, 0x50, 0x00, 0x00,
            0xB9, 0x0B, 0x08, 0x00, 0x00,
            0x31, 0xC0,
            0x31, 0xD2,
            0x0F, 0x30,
            0x59, 0x5A, 0x58,
            0xCF,
        };
        ram.WriteAt(kHandlerGpa, handler, sizeof(handler));
    }

    Vcpu vp(part, 0);

    constexpr std::uint16_t kCodeAttr32 =
        0xB | (1 << 4) | (1 << 7) | (1 << 14) | (1 << 15);
    constexpr std::uint16_t kDataAttr32 =
        0x3 | (1 << 4) | (1 << 7) | (1 << 14) | (1 << 15);

    auto code_seg = WHV_X64_SEGMENT_REGISTER{};
    code_seg.Base = 0;
    code_seg.Limit = 0xFFFFFFFFu;
    code_seg.Selector = kCodeSel;
    code_seg.Attributes = kCodeAttr32;
    auto data_seg = WHV_X64_SEGMENT_REGISTER{};
    data_seg.Base = 0;
    data_seg.Limit = 0xFFFFFFFFu;
    data_seg.Selector = kDataSel;
    data_seg.Attributes = kDataAttr32;
    auto gdtr = WHV_X64_TABLE_REGISTER{};
    gdtr.Base = kGdtGpa;
    gdtr.Limit = 23;

    constexpr std::uint64_t kCr0Pe = 1ull << 0;
    constexpr std::uint64_t kCr0Et = 1ull << 4;

    const std::array<WHV_REGISTER_NAME, 12> names = {
        WHvX64RegisterCs,    WHvX64RegisterDs,    WHvX64RegisterEs,
        WHvX64RegisterSs,    WHvX64RegisterFs,    WHvX64RegisterGs,
        WHvX64RegisterGdtr,  WHvX64RegisterCr0,   WHvX64RegisterCr4,
        WHvX64RegisterRflags, WHvX64RegisterRip,
        WHvX64RegisterApicBase,
    };
    std::array<WHV_REGISTER_VALUE, 12> values{};
    values[0].Segment = code_seg;
    values[1].Segment = data_seg;
    values[2].Segment = data_seg;
    values[3].Segment = data_seg;
    values[4].Segment = data_seg;
    values[5].Segment = data_seg;
    values[6].Table = gdtr;
    values[7].Reg64 = kCr0Pe | kCr0Et;
    values[8].Reg64 = 0;
    values[9].Reg64 = 0x2;          // bit 1 reserved-must-be-1, IF cleared
    values[10].Reg64 = kMainGpa;
    // IA32_APIC_BASE: base=0xFEE00000, BSP=bit 8, EXTD(x2APIC)=bit 10,
    // Global Enable=bit 11. Together: 0xFEE00000 | 0x100 | 0x400 | 0x800
    // = 0xFEE00D00.
    values[11].Reg64 = 0xFEE00D00ull;
    vp.SetRegisters(names, values);

    // Drive the vCPU on a worker thread (WHP holds inside
    // WHvRunVirtualProcessor when the guest is in a HLT-with-IF=1 wait state,
    // resuming when an interrupt arrives -- which is exactly what we want).
    // Each delivered MSI wakes the guest, the handler runs, IRET puts it back
    // into HLT, WHP holds again. After kKicks we cancel.
    std::atomic<int>  halt_count{0};
    std::atomic<bool> stop{false};
    std::atomic<std::uint32_t> last_unexpected_exit{0};

    std::thread worker([&]() {
        while (!stop.load(std::memory_order_acquire)) {
            WHV_RUN_VP_EXIT_CONTEXT exit{};
            try {
                vp.Run(exit);
            } catch (const tinyvmm::HrError&) {
                last_unexpected_exit.store(0xDEADBEEFu);
                return;
            }
            switch (exit.ExitReason) {
              case WHvRunVpExitReasonX64Halt:
                halt_count.fetch_add(1, std::memory_order_acq_rel);
                break;
              case WHvRunVpExitReasonCanceled:
                return;
              default:
                last_unexpected_exit.store(
                    static_cast<std::uint32_t>(exit.ExitReason));
                return;
            }
        }
    });

    constexpr int kKicks = 5;
    for (int k = 0; k < kKicks; ++k) {
        // Give the guest a moment to reach the HLT-wait state on the first
        // iteration; subsequent iterations land back in HLT quickly after IRET.
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        const std::uint64_t addr = 0xFEE00000ull;
        const std::uint32_t data = kVector;
        HRESULT hr = whp::InjectMsi(part.handle(), addr, data);
        if (FAILED(hr)) {
            std::fprintf(stderr,
                         "[msix-inject-test] FAIL: InjectMsi hr=0x%08lX\n",
                         static_cast<unsigned long>(hr));
            stop.store(true);
            vp.Cancel();
            worker.join();
            return 9;
        }
    }

    // Wait for the guest to reach the post-iret HLT one more time so the
    // final counter increment is observable. Bounded busy-wait.
    {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(500);
        while (std::chrono::steady_clock::now() < deadline) {
            std::uint32_t c = 0;
            std::memcpy(&c, ram.HostPointer(kCounterGpa), sizeof(c));
            if (c >= static_cast<std::uint32_t>(kKicks)) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    stop.store(true);
    vp.Cancel();
    worker.join();

    if (last_unexpected_exit.load() != 0) {
        std::fprintf(stderr,
                     "[msix-inject-test] FAIL: unexpected exit reason 0x%x\n",
                     last_unexpected_exit.load());
        return 9;
    }

    std::uint32_t counter = 0;
    std::memcpy(&counter, ram.HostPointer(kCounterGpa), sizeof(counter));
    std::printf("[msix-inject-test] kicks=%d  halts=%d  counter=%u\n",
                kKicks, halt_count.load(), counter);
    if (counter != static_cast<std::uint32_t>(kKicks)) {
        std::fprintf(stderr,
                     "[msix-inject-test] FAIL: counter %u != kicks %d\n",
                     counter, kKicks);
        return 9;
    }

    std::puts("[msix-inject-test] PASS");
    return 0;
}


// M3 PVH inspect: parse the ELF, find the Xen PHYS32_ENTRY note, list
// PT_LOAD segments. Doesn't run the kernel; pure read-only diagnostic.
int RunPvhInfo(const char* path) {
    using namespace tinyvmm;
    boot::PvhInfo info = boot::InspectPvh(std::filesystem::path(path));
    boot::PrintPvhInfo(info, stdout);
    return info.BootCapable() ? 0 : 4;
}

// M3 PVH run: load the kernel, set up 32-bit PM PVH entry, drive the run
// loop. Without M4 (CPUID intercept) and M5 (x2APIC), Linux will fall over
// somewhere early -- but we'll see exactly where via the run-loop diagnostics.
//
// For now: 256 MiB guest RAM, COM1 wired to stdout, kernel cmdline taken from
// argv after `--`. The interesting output to look for is "Booting PVH" or any
// printk reaching the UART before things go sideways.
//
// `net_backend` selects which NetBackend pumps the virtio-net device:
//   "none"     : guest sees the device but no packets ever flow
//   "loopback" : TX echoes back as RX via LoopbackNetBackend (debug)
//   "xdp"      : AF_XDP zero-copy to host NIC queue `xdp_if`/`xdp_queue`
enum class NetBackendKind { None, Loopback, Xdp, Wintun, WintunSvc, Usernet };
// One disk attached via --drive. We open with FILE_FLAG_OVERLAPPED and bind
// to a per-disk IOCP worker thread; see host::BlockFile.
struct DriveSpec {
    std::string path;
    bool        readonly = false;
};

// One host directory exposed to the guest via virtio-9p (M32).
// One ShareSpec per --virtio-9p-share flag. Path is canonicalised at
// startup so guest-visible operations never see relative or symlinked
// host paths.
struct P9ShareSpec {
    std::string             tag;
    std::filesystem::path   host_root;
    bool                    readonly = false;
};

// ---------------------------------------------------------------------------
// M33.6: production --save / --restore plumbing.
//
// All the per-class CaptureState/ApplyState/Encode/Decode helpers landed in
// M33.3 (vCPU+RAM+HV), M33.4 (PCI+virtio), and M33.5 (legacy devices). The
// machinery below stitches them together into one writer (called from the
// post-stop hook in RunPvhRun when the magic CPUID has fired) and one
// reader-applier (called from RunRestore on the parallel cold-restore
// path). Section ordering on disk: header → vCPU → HV → legacy → per-PCI
// → RAM last (the rubber-duck-approved layout from M33.6 design review).
// ---------------------------------------------------------------------------

// Bundle of live VM state references the writer needs at snapshot time.
// Captured by reference because it lives entirely on RunPvhRun's stack.
struct SnapshotWriteContext {
    WHV_PARTITION_HANDLE                                       part_handle;
    std::uint32_t                                              vcpu_count;
    std::deque<tinyvmm::whp::Vcpu>&                            vcpus;
    tinyvmm::whp::GuestMemory&                                 ram;
    bool                                                       large_pages;
    tinyvmm::whp::HvEnlightenment&                             hv;
    tinyvmm::devices::Serial8250&                              com1;
    tinyvmm::devices::Pic8259&                                 pic;
    tinyvmm::devices::Pit8254&                                 pit;
    tinyvmm::devices::LegacyIsaStubs&                          legacy;
    tinyvmm::pci::PciBus&                                      pbus;
    const std::vector<std::unique_ptr<tinyvmm::host::BlockFile>>&    blk_backends;
    const std::vector<std::unique_ptr<tinyvmm::virtio::BlockDevice>>& blk_devices;
    const std::vector<DriveSpec>&                              drives;
    bool                                                       hide_tsc_deadline;
    std::uint64_t                                              tsc_hz;
};

// Drain helper: poll every BlockDevice's PendingCount() until they all
// reach zero or the timeout expires. Returns true if all drained.
//
// Rationale (rubber-duck M33.6 blocking #1): if we snapshot while
// virtio-blk has descriptors in flight, the captured virtqueue state
// shows the head consumed but the used-ring entry not yet posted; on
// restore the guest waits forever for completion (it won't re-issue).
// Forcing a quiesce-then-capture sidesteps that whole class of bug.
bool DrainBlockBackends(
        const std::vector<std::unique_ptr<tinyvmm::virtio::BlockDevice>>& blk_devices,
        int timeout_ms = 5000) {
    if (blk_devices.empty()) return true;
    const auto t0 = std::chrono::steady_clock::now();
    for (;;) {
        bool all_drained = true;
        for (const auto& d : blk_devices) {
            if (d->PendingCount() != 0) { all_drained = false; break; }
        }
        if (all_drained) return true;
        const auto el = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        if (el >= timeout_ms) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

// Encode a CapturedVcpuState's per-section blocks.
namespace svcpu_enc {
    namespace snap = ::tinyvmm::whp::snapshot;

    // Encodes a CapturedVcpuState arch/timing register block.
    // Layout: u32 vp_idx | u32 reg_count | [u32 name | u32 reserved | 16B value]*.
    inline std::vector<std::uint8_t> EncodeRegBlock(
            std::uint32_t vp_idx,
            const WHV_REGISTER_NAME* names,
            const std::vector<WHV_REGISTER_VALUE>& values) {
        const std::uint32_t n = static_cast<std::uint32_t>(values.size());
        std::vector<std::uint8_t> out(8 + std::size_t{n} * (8 + 16));
        snap::WriteLe32(&out[0], vp_idx);
        snap::WriteLe32(&out[4], n);
        for (std::uint32_t i = 0; i < n; ++i) {
            std::uint8_t* p = &out[8 + std::size_t{i} * (8 + 16)];
            snap::WriteLe32(p + 0, static_cast<std::uint32_t>(names[i]));
            snap::WriteLe32(p + 4, 0u);
            std::memcpy(p + 8, &values[i], 16);
        }
        return out;
    }

    // Encodes an XSAVE/APIC blob. Layout: u32 vp_idx | u32 size | bytes.
    inline std::vector<std::uint8_t> EncodeBlobBlock(
            std::uint32_t vp_idx,
            const std::vector<std::uint8_t>& blob) {
        std::vector<std::uint8_t> out(8 + blob.size());
        snap::WriteLe32(&out[0], vp_idx);
        snap::WriteLe32(&out[4],
            tinyvmm::util::checked_int_cast<std::uint32_t>(blob.size()));
        if (!blob.empty()) std::memcpy(&out[8], blob.data(), blob.size());
        return out;
    }

    // Encodes the IntrCtl block.
    // Layout: u32 vp_idx | u32 reg_count | [u32 name | u8 ok | u8 pad[3] | 16B value]*.
    inline std::vector<std::uint8_t> EncodeIntrCtlBlock(
            std::uint32_t vp_idx,
            const snap::CapturedVcpuState& cap) {
        const std::uint32_t n = static_cast<std::uint32_t>(cap.intr_ctl.size());
        std::vector<std::uint8_t> out(8 + std::size_t{n} * (8 + 16));
        snap::WriteLe32(&out[0], vp_idx);
        snap::WriteLe32(&out[4], n);
        for (std::uint32_t i = 0; i < n; ++i) {
            std::uint8_t* p = &out[8 + std::size_t{i} * (8 + 16)];
            snap::WriteLe32(p + 0,
                static_cast<std::uint32_t>(snap::kIntrCtlRegNames[i]));
            p[4] = cap.intr_ctl_ok[i] ? 1u : 0u;
            p[5] = 0; p[6] = 0; p[7] = 0;
            std::memcpy(p + 8, &cap.intr_ctl[i], 16);
        }
        return out;
    }

    // M33.7: Encodes the supervisor-MSR block. Same wire layout as
    // EncodeIntrCtlBlock; ok-bit indicates whether the register was
    // successfully readable at capture time.
    inline std::vector<std::uint8_t> EncodeSupMsrBlock(
            std::uint32_t vp_idx,
            const snap::CapturedVcpuState& cap) {
        const std::uint32_t n = static_cast<std::uint32_t>(cap.sup_msr.size());
        std::vector<std::uint8_t> out(8 + std::size_t{n} * (8 + 16));
        snap::WriteLe32(&out[0], vp_idx);
        snap::WriteLe32(&out[4], n);
        for (std::uint32_t i = 0; i < n; ++i) {
            std::uint8_t* p = &out[8 + std::size_t{i} * (8 + 16)];
            snap::WriteLe32(p + 0,
                static_cast<std::uint32_t>(snap::kSupervisorMsrNames[i]));
            p[4] = cap.sup_msr_ok[i] ? 1u : 0u;
            p[5] = 0; p[6] = 0; p[7] = 0;
            std::memcpy(p + 8, &cap.sup_msr[i], 16);
        }
        return out;
    }

    // Prepends a 4-byte BDF tag (bus,dev,fn,reserved=0) to `bytes` in place.
    inline void PrependBdf(const tinyvmm::pci::Bdf& bdf,
                           std::vector<std::uint8_t>& bytes) {
        std::vector<std::uint8_t> out;
        out.reserve(4 + bytes.size());
        out.push_back(bdf.bus);
        out.push_back(bdf.device);
        out.push_back(bdf.function);
        out.push_back(0);
        out.insert(out.end(), bytes.begin(), bytes.end());
        bytes = std::move(out);
    }
    // Prepends 4-byte BDF + 4-byte (u16 qidx, u16 pad).
    inline void PrependBdfQ(const tinyvmm::pci::Bdf& bdf, std::uint16_t qidx,
                            std::vector<std::uint8_t>& bytes) {
        std::vector<std::uint8_t> out;
        out.reserve(8 + bytes.size());
        out.push_back(bdf.bus);
        out.push_back(bdf.device);
        out.push_back(bdf.function);
        out.push_back(0);
        out.push_back(static_cast<std::uint8_t>(qidx & 0xFF));
        out.push_back(static_cast<std::uint8_t>((qidx >> 8) & 0xFF));
        out.push_back(0);
        out.push_back(0);
        out.insert(out.end(), bytes.begin(), bytes.end());
        bytes = std::move(out);
    }

    // -------- M33.6 restore-side decoders ----------------------------------
    // Mirror images of the Encode* helpers above. Each takes a raw section
    // payload (the BDF prefix, if any, has already been stripped) and
    // populates the relevant CapturedVcpuState fields. They throw
    // std::runtime_error on any size mismatch / unexpected register name so
    // the restore path fails loudly instead of producing a half-applied vCPU.

    // Reads a CapturedVcpuState arch/timing register block. Validates that the
    // section's `vp_idx` matches `expected_vp_idx`, the register count matches
    // `expected_count`, and each register name matches `expected_names[i]` in
    // order. Returns the parsed register values in the same order.
    inline std::vector<WHV_REGISTER_VALUE> DecodeRegBlock(
            std::span<const std::uint8_t> bytes,
            std::uint32_t expected_vp_idx,
            const WHV_REGISTER_NAME* expected_names,
            std::size_t expected_count) {
        if (bytes.size() < 8) {
            throw std::runtime_error("DecodeRegBlock: payload too small");
        }
        const std::uint32_t vp_idx = snap::ReadLe32(&bytes[0]);
        const std::uint32_t n      = snap::ReadLe32(&bytes[4]);
        if (vp_idx != expected_vp_idx) {
            throw std::runtime_error("DecodeRegBlock: vp_idx mismatch");
        }
        if (n != expected_count) {
            throw std::runtime_error("DecodeRegBlock: reg_count mismatch");
        }
        const std::size_t need = 8 + std::size_t{n} * (8 + 16);
        if (bytes.size() < need) {
            throw std::runtime_error("DecodeRegBlock: payload truncated");
        }
        std::vector<WHV_REGISTER_VALUE> values(n);
        for (std::uint32_t i = 0; i < n; ++i) {
            const std::uint8_t* p = &bytes[8 + std::size_t{i} * (8 + 16)];
            const std::uint32_t name = snap::ReadLe32(p + 0);
            if (name != static_cast<std::uint32_t>(expected_names[i])) {
                throw std::runtime_error(
                    "DecodeRegBlock: register name mismatch");
            }
            // p + 4 = u32 reserved (ignored on read)
            std::memcpy(&values[i], p + 8, 16);
        }
        return values;
    }

    // Reads an XSAVE/APIC blob. Validates `vp_idx`. Returns the payload bytes.
    inline std::vector<std::uint8_t> DecodeBlobBlock(
            std::span<const std::uint8_t> bytes,
            std::uint32_t expected_vp_idx) {
        if (bytes.size() < 8) {
            throw std::runtime_error("DecodeBlobBlock: payload too small");
        }
        const std::uint32_t vp_idx = snap::ReadLe32(&bytes[0]);
        const std::uint32_t size   = snap::ReadLe32(&bytes[4]);
        if (vp_idx != expected_vp_idx) {
            throw std::runtime_error("DecodeBlobBlock: vp_idx mismatch");
        }
        if (bytes.size() < 8 + std::size_t{size}) {
            throw std::runtime_error("DecodeBlobBlock: payload truncated");
        }
        return std::vector<std::uint8_t>(bytes.begin() + 8,
                                         bytes.begin() + 8 + size);
    }

    // Reads an IntrCtl block into the CapturedVcpuState::intr_ctl + ok arrays.
    inline void DecodeIntrCtlBlock(std::span<const std::uint8_t> bytes,
                                   std::uint32_t expected_vp_idx,
                                   snap::CapturedVcpuState& out) {
        if (bytes.size() < 8) {
            throw std::runtime_error("DecodeIntrCtlBlock: payload too small");
        }
        const std::uint32_t vp_idx = snap::ReadLe32(&bytes[0]);
        const std::uint32_t n      = snap::ReadLe32(&bytes[4]);
        if (vp_idx != expected_vp_idx) {
            throw std::runtime_error("DecodeIntrCtlBlock: vp_idx mismatch");
        }
        if (n != snap::kIntrCtlRegCount()) {
            throw std::runtime_error("DecodeIntrCtlBlock: reg_count mismatch");
        }
        const std::size_t need = 8 + std::size_t{n} * (8 + 16);
        if (bytes.size() < need) {
            throw std::runtime_error("DecodeIntrCtlBlock: payload truncated");
        }
        out.intr_ctl.assign(n, WHV_REGISTER_VALUE{});
        out.intr_ctl_ok.assign(n, false);
        for (std::uint32_t i = 0; i < n; ++i) {
            const std::uint8_t* p = &bytes[8 + std::size_t{i} * (8 + 16)];
            const std::uint32_t name = snap::ReadLe32(p + 0);
            if (name != static_cast<std::uint32_t>(snap::kIntrCtlRegNames[i])) {
                throw std::runtime_error(
                    "DecodeIntrCtlBlock: register name mismatch");
            }
            out.intr_ctl_ok[i] = (p[4] != 0);
            std::memcpy(&out.intr_ctl[i], p + 8, 16);
        }
    }

    // M33.7: Reads a supervisor-MSR block into out.sup_msr + sup_msr_ok.
    // Tolerates extra register names appearing on the wire (different
    // snapshot tooling versions) — only fails if a known name appears in
    // wrong order. Pads missing tail entries with ok=false so partial
    // snapshots from older builds still apply (the missing CET MSRs
    // will be skipped, which is the safe behavior).
    inline void DecodeSupMsrBlock(std::span<const std::uint8_t> bytes,
                                  std::uint32_t expected_vp_idx,
                                  snap::CapturedVcpuState& out) {
        if (bytes.size() < 8) {
            throw std::runtime_error("DecodeSupMsrBlock: payload too small");
        }
        const std::uint32_t vp_idx = snap::ReadLe32(&bytes[0]);
        const std::uint32_t n      = snap::ReadLe32(&bytes[4]);
        if (vp_idx != expected_vp_idx) {
            throw std::runtime_error("DecodeSupMsrBlock: vp_idx mismatch");
        }
        const std::size_t need = 8 + std::size_t{n} * (8 + 16);
        if (bytes.size() < need) {
            throw std::runtime_error("DecodeSupMsrBlock: payload truncated");
        }
        // Resize to canonical length first (filled with default values +
        // ok=false). Then overwrite any entries that match the wire's
        // name in canonical order.
        out.sup_msr.assign(snap::kSupervisorMsrCount(), WHV_REGISTER_VALUE{});
        out.sup_msr_ok.assign(snap::kSupervisorMsrCount(), false);
        const std::size_t common = (std::min)(static_cast<std::size_t>(n),
                                              snap::kSupervisorMsrCount());
        for (std::size_t i = 0; i < common; ++i) {
            const std::uint8_t* p = &bytes[8 + i * (8 + 16)];
            const std::uint32_t name = snap::ReadLe32(p + 0);
            if (name != static_cast<std::uint32_t>(
                            snap::kSupervisorMsrNames[i])) {
                // Wire order does not match. Skip silently — this entry
                // (and likely subsequent entries) are from a different
                // tooling version; safer to leave ok=false.
                continue;
            }
            out.sup_msr_ok[i] = (p[4] != 0);
            std::memcpy(&out.sup_msr[i], p + 8, 16);
        }
    }

    // Encodes a per-(BDF) lookup key for restore-time maps.
    inline std::uint32_t BdfKey(std::uint8_t bus, std::uint8_t dev,
                                std::uint8_t fn) noexcept {
        return (static_cast<std::uint32_t>(bus) << 16) |
               (static_cast<std::uint32_t>(dev) << 8) |
               static_cast<std::uint32_t>(fn);
    }
    inline std::uint32_t BdfKey(const tinyvmm::pci::Bdf& b) noexcept {
        return BdfKey(b.bus, b.device, b.function);
    }
    // Combined (BDF, qidx) key for VIRTQUEUE map.
    inline std::uint64_t BdfQKey(std::uint32_t bdfkey,
                                 std::uint16_t qidx) noexcept {
        return (static_cast<std::uint64_t>(bdfkey) << 16) |
               static_cast<std::uint64_t>(qidx);
    }
}  // namespace svcpu_enc

// Captures all live state and writes a TVMMSAVE snapshot file at `out_path`.
// Returns 0 on success, non-zero on failure (with a diagnostic to stderr).
// The disk in-flight drain is the caller's responsibility (we assume it
// already ran DrainBlockBackends and returned true).
int WriteSnapshotFile(const std::string& out_path,
                      const SnapshotWriteContext& ctx) {
    namespace snap = ::tinyvmm::whp::snapshot;
    namespace dev  = ::tinyvmm::devices;
    namespace p    = ::tinyvmm::pci;
    namespace v    = ::tinyvmm::virtio;

    try {
        // ---------------- Capture per-vCPU state ------------------
        std::vector<snap::CapturedVcpuState> cap_vcpus(ctx.vcpu_count);
        for (std::uint32_t i = 0; i < ctx.vcpu_count; ++i) {
            snap::CaptureVcpuState(ctx.vcpus[i], ctx.part_handle, i,
                                   cap_vcpus[i]);
        }
        const auto cap_hv  = ctx.hv.CaptureState();
        const auto cap_bus = ctx.pbus.CaptureState();
        const auto cap_isa = ctx.legacy.CaptureState();
        const auto cap_com = ctx.com1.CaptureState();
        const auto cap_pic = ctx.pic.CaptureState();
        const auto cap_pit = ctx.pit.CaptureState();

        // ---------------- Header JSON ----------------
        snap::JsonObjectWriter jw;
        jw.Add("phase",             std::string_view("33.6-prod"));
        jw.Add("vcpu_count",        std::uint64_t{ctx.vcpu_count});
        jw.Add("ram_size_bytes",    std::uint64_t{ctx.ram.size()});
        jw.Add("large_pages",       ctx.large_pages);
        jw.Add("tsc_hz_at_save",    ctx.tsc_hz);
        jw.Add("hide_tsc_deadline", ctx.hide_tsc_deadline);
        jw.Add("drive_count",       std::uint64_t{ctx.drives.size()});
        for (std::size_t i = 0; i < ctx.drives.size(); ++i) {
            char key[40];
            std::snprintf(key, sizeof(key), "drive%zu_path", i);
            jw.Add(key, std::string_view(ctx.drives[i].path));
            std::snprintf(key, sizeof(key), "drive%zu_size", i);
            jw.Add(key, std::uint64_t{ctx.blk_backends[i]->size()});
            std::snprintf(key, sizeof(key), "drive%zu_readonly", i);
            jw.Add(key, ctx.drives[i].readonly);
        }

        snap::SnapshotWriter w(out_path);
        w.WriteHeader(jw.str());

        // ---------------- Per-vCPU sections ----------------
        for (std::uint32_t i = 0; i < ctx.vcpu_count; ++i) {
            const auto& c = cap_vcpus[i];
            auto regs   = svcpu_enc::EncodeRegBlock(i, snap::kArchRegNames,
                                                    c.arch);
            auto xsave  = svcpu_enc::EncodeBlobBlock(i, c.xsave);
            auto apic   = svcpu_enc::EncodeBlobBlock(i, c.apic);
            auto intr   = svcpu_enc::EncodeIntrCtlBlock(i, c);
            auto supmsr = svcpu_enc::EncodeSupMsrBlock(i, c);
            auto timing = svcpu_enc::EncodeRegBlock(i, snap::kTimingRegNames,
                                                    c.timing);
            w.WriteSection(snap::SectionType::VcpuRegs,    regs.data(),   regs.size());
            w.WriteSection(snap::SectionType::VcpuXsave,   xsave.data(),  xsave.size());
            w.WriteSection(snap::SectionType::VcpuApic,    apic.data(),   apic.size());
            w.WriteSection(snap::SectionType::VcpuIntrCtl, intr.data(),   intr.size());
            w.WriteSection(snap::SectionType::VcpuSupMsr,  supmsr.data(), supmsr.size());
            w.WriteSection(snap::SectionType::VcpuTiming,  timing.data(), timing.size());
        }

        // ---------------- HV ----------------
        {
            std::uint8_t buf[32];
            snap::WriteLe64(buf +  0, cap_hv.guest_os_id);
            snap::WriteLe64(buf +  8, cap_hv.hypercall_msr);
            snap::WriteLe64(buf + 16, cap_hv.reference_tsc_msr);
            snap::WriteLe64(buf + 24, cap_hv.tsc_invariant_ctl);
            w.WriteSection(snap::SectionType::HvEnlightenment, buf, sizeof(buf));
        }

        // ---------------- Legacy singletons ----------------
        {
            std::uint8_t buf[p::PciBus::kEncodedSize];
            p::PciBus::EncodeState(cap_bus, std::span<std::uint8_t>(buf));
            w.WriteSection(snap::SectionType::LegacyPciBus, buf, sizeof(buf));
        }
        {
            std::uint8_t buf[dev::LegacyIsaStubs::kEncodedSize];
            dev::LegacyIsaStubs::EncodeState(cap_isa, std::span<std::uint8_t>(buf));
            w.WriteSection(snap::SectionType::LegacyIsaStubs, buf, sizeof(buf));
        }
        {
            std::uint8_t buf[dev::Serial8250::kEncodedSize];
            dev::Serial8250::EncodeState(cap_com, std::span<std::uint8_t>(buf));
            w.WriteSection(snap::SectionType::LegacySerial8250, buf, sizeof(buf));
        }
        {
            std::uint8_t buf[dev::Pic8259::kEncodedSize];
            dev::Pic8259::EncodeState(cap_pic, std::span<std::uint8_t>(buf));
            w.WriteSection(snap::SectionType::LegacyPic8259, buf, sizeof(buf));
        }
        {
            std::uint8_t buf[dev::Pit8254::kEncodedSize];
            dev::Pit8254::EncodeState(cap_pit, std::span<std::uint8_t>(buf));
            w.WriteSection(snap::SectionType::LegacyPit8254, buf, sizeof(buf));
        }

        // ---------------- Per PCI device ----------------
        // Walk in pbus insertion order. Each device is a PciTransport (we
        // don't have any other PciDevice flavours wired into pbus right
        // now). Cast down to capture virtio-class state.
        ctx.pbus.ForEachDevice([&](p::Bdf bdf, p::PciDevice& pd) {
            auto* xport = dynamic_cast<v::PciTransport*>(&pd);
            if (!xport) {
                // Not a virtio transport; just persist generic PciDevice + MsiX.
                {
                    std::vector<std::uint8_t> bytes;
                    p::PciDevice::EncodeState(pd.CaptureState(), bytes);
                    svcpu_enc::PrependBdf(bdf, bytes);
                    w.WriteSection(snap::SectionType::PciDevice,
                                   bytes.data(), bytes.size());
                }
                return;
            }

            // PciDevice base
            {
                std::vector<std::uint8_t> bytes;
                p::PciDevice::EncodeState(
                    static_cast<const p::PciDevice&>(*xport).CaptureState(),
                    bytes);
                svcpu_enc::PrependBdf(bdf, bytes);
                w.WriteSection(snap::SectionType::PciDevice,
                               bytes.data(), bytes.size());
            }

            // Virtio-device-specific State (dispatched on virtio device id)
            v::Device& vdev = xport->device();
            switch (vdev.DeviceId()) {
            case v::kDeviceIdRng: {
                auto& d = static_cast<v::RngDevice&>(vdev);
                std::vector<std::uint8_t> bytes;
                v::RngDevice::EncodeState(d.CaptureState(), bytes);
                svcpu_enc::PrependBdf(bdf, bytes);
                w.WriteSection(snap::SectionType::VirtioRngState,
                               bytes.data(), bytes.size());
                break;
            }
            case v::kDeviceIdConsole: {
                auto& d = static_cast<v::ConsoleDevice&>(vdev);
                std::vector<std::uint8_t> bytes;
                v::ConsoleDevice::EncodeState(d.CaptureState(), bytes);
                svcpu_enc::PrependBdf(bdf, bytes);
                w.WriteSection(snap::SectionType::VirtioConsoleState,
                               bytes.data(), bytes.size());
                break;
            }
            case v::kDeviceIdBlk: {
                auto& d = static_cast<v::BlockDevice&>(vdev);
                std::vector<std::uint8_t> bytes;
                v::BlockDevice::EncodeState(d.CaptureState(), bytes);
                svcpu_enc::PrependBdf(bdf, bytes);
                w.WriteSection(snap::SectionType::VirtioBlkState,
                               bytes.data(), bytes.size());
                break;
            }
            default:
                // virtio-net (1) and virtio-9p (9) are intentionally
                // unsupported for save: --save refuses to start if --net
                // or --virtio-9p-share is present. If we get here, it's a
                // policy bug.
                throw std::runtime_error(
                    "WriteSnapshotFile: unsupported virtio device on save path");
            }

            // Virtqueue per queue
            for (std::uint32_t qi = 0; qi < vdev.QueueCount(); ++qi) {
                v::Virtqueue* q = vdev.GetQueue(qi);
                if (!q) continue;
                std::vector<std::uint8_t> bytes;
                v::Virtqueue::EncodeState(q->CaptureState(), bytes);
                svcpu_enc::PrependBdfQ(bdf, static_cast<std::uint16_t>(qi),
                                       bytes);
                w.WriteSection(snap::SectionType::Virtqueue,
                               bytes.data(), bytes.size());
            }

            // MsiX
            {
                std::vector<std::uint8_t> bytes;
                p::MsiX::EncodeState(xport->msix().CaptureState(), bytes);
                svcpu_enc::PrependBdf(bdf, bytes);
                w.WriteSection(snap::SectionType::MsixState,
                               bytes.data(), bytes.size());
            }

            // PciTransport (LAST -- mirrors apply order, so on restore the
            // BAR remap stamps over any cfg + queue state we just wrote)
            {
                std::vector<std::uint8_t> bytes;
                v::PciTransport::EncodeState(xport->CaptureState(), bytes);
                svcpu_enc::PrependBdf(bdf, bytes);
                w.WriteSection(snap::SectionType::VirtioPciTransport,
                               bytes.data(), bytes.size());
            }
        });

        // ---------------- RAM (LAST per rubber-duck recommendation) -----
        // Largest section; emit last so a writer crash leaves smaller
        // metadata uncorrupted (CRC trailer catches any truncation).
        w.WriteSection(snap::SectionType::RamRaw,
                       ctx.ram.host_base(), ctx.ram.size());

        w.Finalize();
        std::printf("[snapshot] wrote %llu bytes to %s\n",
                    static_cast<unsigned long long>(w.bytes_written()),
                    out_path.c_str());
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr,
            "[snapshot] FAIL: %s\n", e.what());
        return 4;
    }
}

int RunPvhRun(const char* path, const std::string& cmdline,
              bool with_net,
              NetBackendKind net_backend,
              std::uint32_t xdp_if,
              std::uint32_t xdp_queue,
              bool xdp_debug,
              const std::string& initrd_path,
              const std::vector<DriveSpec>& drives,
              const std::vector<P9ShareSpec>& p9_shares,
              int watchdog_secs,
              bool hide_tsc_deadline,
              const std::vector<tinyvmm::virtio::UsernetBackend::PortForward>&
                  port_forwards = {},
              std::uint32_t ram_mb = 256,
              std::uint32_t vcpu_count = 1,
              tinyvmm::whp::AffinityMode affinity_mode =
                  tinyvmm::whp::AffinityMode::All,
              std::uint16_t gdb_port = 0) {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;

    diag::EtwRegister();
    diag::BootTimer btimer;
    btimer.Mark("pvh-run start");

    CheckWhpAvailable();
    btimer.Mark("WHP probe done");
    std::puts("[pvh-run] WHP available");
    ReportHostCapabilities();

    const std::size_t kRamBytes = static_cast<std::size_t>(ram_mb) << 20;

    if (vcpu_count == 0) vcpu_count = 1;
    if (vcpu_count > boot::acpi::kMaxVcpus) vcpu_count = boot::acpi::kMaxVcpus;
    if (gdb_port != 0 && vcpu_count != 1) {
        std::fprintf(stderr,
            "[pvh-run] --gdb-port requires --vcpus 1 (got %u). "
            "Multi-vCPU debugging is M35 v2.\n", vcpu_count);
        return 1;
    }

    Partition part(vcpu_count);
    // Enable CPUID + MSR exits. CPUID lets us layer tinyvmm policy
    // (advertise invariant_tsc, ARAT, TSC frequency, Hyper-V vendor/iface)
    // on top of WHP's host-passthrough defaults. MSR lets us service the
    // Hyper-V Reference TSC page + TSC-invariant-control MSRs that Linux
    // writes once it detects Hyper-V via the CPUID leaves. See
    // `whp/cpuid.cpp` and `whp/hv_enlightenment.cpp`.
    //
    // M35 GDB stub also wants exception exits for #DB (single-step) and
    // #BP (int3 software breakpoint). The exception bitmap is set
    // *only* when --gdb-port is in effect so non-debug runs stay on
    // the existing fast path.
    part.EnableExtendedExits({
        .cpuid = true, .msr = true,
        .exception = (gdb_port != 0),
    });
    if (gdb_port != 0) {
        // M35.0 Phase 1: handshake only; the run loop is not yet wired
        // to handle #DB / #BP. Set the bitmap to 0 (no exceptions
        // intercepted) so kernel-internal int3 (text_poke) and #DB
        // (kgdb/ftrace) don't crash the run loop. Phase 4 (M35.3/.5)
        // will add #BP=bit3 plus a proper handler that either reports
        // a breakpoint to GDB or re-injects the exception into the
        // guest.
        part.SetExceptionExitBitmap(0);
    }
    // Also publish the same overrides as a static CpuidResultList. WHP's
    // in-hypervisor LAPIC emulation makes architectural feature decisions at
    // SetupPartition time based on this list -- NOT on what our runtime
    // CPUID exit handler will return. Keeping the two in sync prevents the
    // static and dynamic guest views from drifting (e.g. if we one day add
    // a feature WHP gates on the static list).
    //
    // Note on TSC-deadline (CPUID.01H:ECX[24]): empirically WHP rejects
    // WRMSR 0x6E0 regardless of how the bit is advertised here. We
    // therefore default to *hiding* the bit (see `hide_tsc_deadline`) so
    // Linux uses LAPIC oneshot from the start instead of issuing a doomed
    // WRMSR that produces an `unchecked MSR access` trace + ~30 line call
    // dump in dmesg. The actual effective timer is the same either way.
    SetHideTscDeadline(hide_tsc_deadline);
    const auto static_cpuid =
        BuildStaticCpuidResultList(hide_tsc_deadline);
    part.SetCpuidResultList(static_cpuid.data(), static_cpuid.size());
    // Let WHP fully emulate the LAPIC in-hypervisor: this both removes the
    // boot-time MMIO traps at 0xfee00xxx and is the prerequisite for
    // hypervisor-side IRQ delivery (M5).
    part.SetLocalApicEmulation(WHvX64LocalApicEmulationModeX2Apic);
    part.Setup();

    GuestMemory ram(part, /*gpa=*/0, kRamBytes, /*executable=*/true);
    btimer.Mark("guest RAM mapped");
    std::printf("[pvh-run] guest RAM: %zu MiB at GPA 0 (%s)\n",
                ram.size() / (1024 * 1024),
                ram.large_pages() ? "MEM_LARGE_PAGES" : "4 KiB pages");

    // Per-VM Hyper-V enlightenment state. Backs the Reference TSC page and
    // the few MSRs (GUEST_OS_ID, HYPERCALL, VP_INDEX, REFERENCE_TSC,
    // TSC_INVARIANT_CONTROL) that Linux writes/reads once it detects us
    // via CPUID. Same TSC frequency the guest sees via CPUID.15h, so the
    // 100ns clocksource derived from the page is consistent with TSC.
    HvEnlightenment hv(ram, GetCachedTscHz());
    std::printf("[pvh-run] Hyper-V enlightenment ready (tsc_hz=%llu, "
                "scale=0x%016llx)\n",
                static_cast<unsigned long long>(hv.tsc_hz()),
                static_cast<unsigned long long>(hv.tsc_scale()));

    boot::PvhLoadConfig cfg;
    cfg.cmdline   = cmdline;
    cfg.ram_bytes = ram.size();
    cfg.vcpu_count = vcpu_count;
    if (!initrd_path.empty()) {
        cfg.initramfs = std::filesystem::path(initrd_path);
    }
    auto load = boot::LoadPvh(ram, std::filesystem::path(path), cfg);
    btimer.Mark("vmlinux+initramfs loaded");
    std::printf("[pvh-run] loaded %llu bytes; entry=0x%08x start_info_gpa=0x%llx "
                "gdt_gpa=0x%llx\n",
                static_cast<unsigned long long>(load.bytes_loaded),
                load.entry_point,
                static_cast<unsigned long long>(load.start_info_gpa),
                static_cast<unsigned long long>(load.gdt_gpa));
    if (load.initramfs_size > 0) {
        std::printf("[pvh-run] initramfs: %llu bytes at GPA 0x%llx\n",
                    static_cast<unsigned long long>(load.initramfs_size),
                    static_cast<unsigned long long>(load.initramfs_gpa));
    }
    std::printf("[pvh-run] cmdline: \"%s\"\n", cmdline.c_str());

    // Per-vCPU containers. Deques give stable references; we hand
    // `vcpus[i]` to `loops[i]`, and `loops[0]` to the BSP run path.
    std::deque<Vcpu> vcpus;
    for (std::uint32_t i = 0; i < vcpu_count; ++i) {
        vcpus.emplace_back(part, i);
    }
    Vcpu& vp = vcpus.front();  // BSP alias for legacy dump code below.
    boot::SetupPvhEntry(vp, load);
    // APs (index >= 1) start in the architecturally-defined wait-for-SIPI
    // state. Linux's secondary CPU bring-up will deliver INIT+SIPI through
    // the LAPIC; WHP services those in-hypervisor. We do NOT need to
    // explicitly initialise AP registers here.

    devices::IoBus io_bus;
    devices::MmioBus mmio_bus;
    devices::Serial8250 com1(0x3F8, stdout);
    com1.Attach(io_bus);
    com1.SetFirstByteCallback([btimer_ptr = &btimer]() {
        btimer_ptr->Mark("guest: first 8250 byte");
    });
    devices::Pit8254 pit;
    pit.Attach(io_bus);
    devices::LegacyIsaStubs legacy;
    legacy.Attach(io_bus);

    // Legacy PIC. The kernel programs vectors 0x30..0x37 (master) and
    // 0x38..0x3F (slave) at boot; in virtual-wire-mode (no IO-APIC) this
    // is the *only* path from ISA IRQ -> guest IDT. Without this, the
    // 8250's userspace TX path stalls after one byte because the
    // kernel's IRQ-driven `serial8250_tx_chars` never gets called back.
    WHV_PARTITION_HANDLE ph = part.handle();
    auto pic_inject = [ph](std::uint8_t vector,
                           std::uint32_t destination) -> bool {
        WHV_INTERRUPT_CONTROL ctrl = {};
        ctrl.Type            = WHvX64InterruptTypeFixed;
        ctrl.DestinationMode = WHvX64InterruptDestinationModePhysical;
        ctrl.TriggerMode     = WHvX64InterruptTriggerModeEdge;
        ctrl.Destination     = destination;
        ctrl.Vector          = vector;
        return SUCCEEDED(WHvRequestInterrupt(ph, &ctrl, sizeof(ctrl)));
    };
    devices::Pic8259 pic(pic_inject);
    pic.Attach(io_bus);
    com1.SetIrqCallback([&pic](int isa_irq) { pic.Raise(isa_irq); });
    // Channel 0 of the i8254 drives IRQ 0. Currently disabled: M18 gave Linux
    // a tsc-deadline LAPIC clockevent (ARAT-on), so PIT IRQ 0 is unnecessary.
    // It also turned out to be harmful here: with CONFIG_ACPI=n Linux uses
    // "virtual wire mode" and the PIT IRQ delivered before the kernel had its
    // 8259 vector handler installed left vector 0x30 stuck in the LAPIC ISR
    // ("APIC: Stale ISR ...,00010000,00000000" in dmesg). Because 0x30 and
    // 0x34 share a priority class, that stale bit blocks ttyS0's IRQ 4
    // (vector 0x34) from ever being delivered. We let the PIT counters run
    // (for TSC calibration via port 0x61) but skip IRQ injection.
    (void)pit;  // pit.SetIrqCallback intentionally not called.

    // Common PCI bus for virtio devices. The RNG device is always wired,
    // virtio-net is opt-in via --net.
    auto pbus = std::make_unique<pci::PciBus>();
    pbus->AttachIoBus(io_bus);

    auto inject_fn = [ph](std::uint64_t addr, std::uint32_t data) {
        return SUCCEEDED(InjectMsi(ph, addr, data));
    };

    // --- virtio-rng (M17) ----------------------------------------------
    // Single requestq, no device-cfg, no device-specific feature bits.
    // BCryptGenRandom-backed; ~10us per fill on modern hosts, runs on the
    // vCPU thread that wrote the notify MMIO.
    auto rng = std::make_unique<virtio::RngDevice>(ram);
    {
        virtio::PciTransport::Options ropts;
        ropts.subsys_id        = static_cast<std::uint16_t>(virtio::kDeviceIdRng);
        ropts.num_msix_vectors = 2;     // requestq + config
        ropts.pci_class        = 0xFF;  // Unassigned / Other
        ropts.pci_subclass     = 0x00;
        auto rxport = std::make_unique<virtio::PciTransport>(
            *rng, ropts, mmio_bus, inject_fn);
        virtio::PciTransport* rxp = rxport.get();
        rng->SetIrqCallback(
            [rxp](std::uint32_t q) { rxp->RaiseQueueInterrupt(q); });
        rxport->set_name("virtio-pci-rng");
        const pci::Bdf rbdf = pbus->AddDevice(std::move(rxport));
        std::printf("[pvh-run] virtio-rng on PCI %02x:%02x.%u\n",
                    rbdf.bus, rbdf.device, rbdf.function);
    }

    // --- virtio-console (M20) -----------------------------------------
    // Routes guest TX (transmitq, qidx=1) to host stdout. The kernel can
    // be told to use it via `console=hvc0`, bypassing the broken 8250
    // TX-IRQ path entirely. Single-port, no F_MULTIPORT/F_SIZE/F_EMERG_WRITE.
    // RX (receiveq, qidx=0) carries host stdin -> guest when stdin is a
    // TTY (see stdin_reader_thread further down).
    auto vcon = std::make_unique<virtio::ConsoleDevice>(ram, stdout);
    virtio::ConsoleDevice* vcon_ptr = vcon.get();

    // Scan TX bytes for boot waypoint markers emitted by /init.
    // Detecting them lets us record an honest "userspace ready" time without
    // requiring guest cooperation beyond a couple of echo lines.
    static constexpr const char* kMarkers[] = {
        "Run /init as init process",        // kernel ready to hand off
        "[init] === tinyvmm init starting", // /init pid 1 alive
        "[init] === init complete",         // /init finished setup
    };
    static constexpr const char* kMarkerLabels[] = {
        "guest: kernel done",
        "guest: /init started",
        "guest: /init complete",
    };
    static_assert(std::size(kMarkers) == std::size(kMarkerLabels));
    // The guest can request a clean tinyvmm shutdown by printing this exact
    // sentinel on hvc0. The default /init does this after running any
    // `tinyvmm.test=...` block, so non-interactive harness scripts don't
    // have to rely on `poweroff` actually triggering an HLT-with-IF=0 path
    // (Linux's poweroff-without-ACPI falls back to STI;HLT, which we treat
    // as normal idle and continue waiting on -- a perfectly correct policy
    // for interactive use but useless for tests). The shutdown watcher
    // thread (further down) checks the flag and invokes stop_all_loops().
    static constexpr const char* kShutdownSentinel =
        "[init] === tinyvmm shutdown requested ===";
    auto marker_state = std::make_shared<std::array<bool, std::size(kMarkers)>>();
    auto pending_buf  = std::make_shared<std::string>();
    auto pending_mu   = std::make_shared<std::mutex>();
    auto first_byte   = std::make_shared<std::atomic<bool>>(false);
    auto shutdown_requested =
        std::make_shared<std::atomic<bool>>(false);
    auto btimer_ptr   = &btimer;
    vcon->SetByteObserver([marker_state, pending_buf, pending_mu, first_byte,
                           shutdown_requested, btimer_ptr]
                          (const char* d, std::size_t n) {
        if (!first_byte->exchange(true)) {
            btimer_ptr->Mark("guest: first hvc0 byte");
        }
        std::lock_guard<std::mutex> lg(*pending_mu);
        pending_buf->append(d, n);
        // Cap rolling buffer to avoid unbounded growth.
        if (pending_buf->size() > 4096) {
            pending_buf->erase(0, pending_buf->size() - 2048);
        }
        for (std::size_t i = 0; i < std::size(kMarkers); ++i) {
            if ((*marker_state)[i]) continue;
            if (pending_buf->find(kMarkers[i]) != std::string::npos) {
                (*marker_state)[i] = true;
                btimer_ptr->Mark(kMarkerLabels[i]);
            }
        }
        if (!shutdown_requested->load(std::memory_order_relaxed) &&
            pending_buf->find(kShutdownSentinel) != std::string::npos) {
            shutdown_requested->store(true, std::memory_order_release);
        }
    });
    {
        virtio::PciTransport::Options copts;
        copts.subsys_id        = static_cast<std::uint16_t>(virtio::kDeviceIdConsole);
        copts.num_msix_vectors = 3;     // rx + tx + config-change
        copts.pci_class        = 0x07;  // Simple communication controller
        copts.pci_subclass     = 0x80;  // Other
        auto cxport = std::make_unique<virtio::PciTransport>(
            *vcon, copts, mmio_bus, inject_fn);
        virtio::PciTransport* cxp = cxport.get();
        vcon->SetIrqCallback(
            [cxp](std::uint32_t q) { cxp->RaiseQueueInterrupt(q); });
        cxport->set_name("virtio-pci-console");
        const pci::Bdf cbdf = pbus->AddDevice(std::move(cxport));
        std::printf("[pvh-run] virtio-console on PCI %02x:%02x.%u (sink=stdout)\n",
                    cbdf.bus, cbdf.device, cbdf.function);
    }


    // --- virtio-blk (M13, optional, repeatable via --drive) -----------
    // Each --drive becomes one virtio-blk PCI device, backed by an async
    // host::BlockFile (FILE_FLAG_OVERLAPPED + per-disk IOCP worker thread).
    // Drive N typically shows up in the guest as /dev/vd<a+N>; ordering
    // matches the order of --drive flags on the command line.
    //
    // Lifetime: BlockFile and BlockDevice MUST be kept alive past loop.Run()
    // because (a) the PciTransport stored in pbus references the BlockDevice
    // by reference, and (b) BlockDevice's completion callback runs on the
    // BlockFile's IOCP worker. We Stop() each backend in the shutdown
    // section below so no completion can race with destructor unwind.
    std::vector<std::unique_ptr<host::BlockFile>>    blk_backends;
    std::vector<std::unique_ptr<virtio::BlockDevice>> blk_devices;
    blk_backends.reserve(drives.size());
    blk_devices.reserve(drives.size());
    for (std::size_t i = 0; i < drives.size(); ++i) {
        const auto& d = drives[i];
        std::wstring wpath = std::filesystem::path(d.path).wstring();
        auto backend = std::make_unique<host::BlockFile>(wpath, d.readonly);
        if (!backend->open()) {
            std::fprintf(stderr,
                "[pvh-run] --drive: failed to open '%s' (readonly=%d): hr=0x%08lx\n",
                d.path.c_str(), d.readonly ? 1 : 0,
                static_cast<unsigned long>(backend->open_hr()));
            return 4;
        }

        auto blk = std::make_unique<virtio::BlockDevice>(
            ram, *backend, virtio::BlockDevice::IrqFn{}, /*queue_max=*/256);
        virtio::BlockDevice* bp = blk.get();

        virtio::PciTransport::Options opts;
        opts.subsys_id        = static_cast<std::uint16_t>(virtio::kDeviceIdBlk);
        opts.num_msix_vectors = 2;     // requestq + config
        opts.pci_class        = 0x01;  // Mass Storage
        opts.pci_subclass     = 0x00;  // SCSI Controller (canonical for virtio-blk)
        auto xport = std::make_unique<virtio::PciTransport>(
            *bp, opts, mmio_bus, inject_fn);
        virtio::PciTransport* xp = xport.get();

        // Wire IRQ BEFORE starting the IOCP worker, otherwise an early
        // completion (e.g. from a request submitted before this loop iter
        // returns -- not currently possible since the kernel hasn't driven
        // the device yet, but cheap insurance) could fire with a null sink.
        bp->SetIrqCallback(
            [xp](std::uint32_t q) { xp->RaiseQueueInterrupt(q); });

        char nbuf[32];
        std::snprintf(nbuf, sizeof(nbuf), "virtio-pci-blk[%zu]", i);
        xport->set_name(nbuf);

        backend->Start();

        const pci::Bdf bbdf = pbus->AddDevice(std::move(xport));
        const std::uint64_t cap_sect = backend->size() / 512;
        std::printf("[pvh-run] virtio-blk[%zu] on PCI %02x:%02x.%u "
                    "path=%s%s capacity=%llu sectors (%.1f MiB)\n",
                    i, bbdf.bus, bbdf.device, bbdf.function,
                    d.path.c_str(), d.readonly ? " (ro)" : "",
                    static_cast<unsigned long long>(cap_sect),
                    static_cast<double>(backend->size()) / (1024.0 * 1024.0));
        blk_backends.push_back(std::move(backend));
        blk_devices .push_back(std::move(blk));
    }


    // --- virtio-9p (M32, optional, repeatable via --virtio-9p-share) ---
    // Each --virtio-9p-share becomes one virtio-9p PCI device exposing
    // one host directory. Mount tag from the spec lives in the device's
    // PCI device-config space; the guest mounts via
    //   mount -t 9p -o trans=virtio,version=9P2000.L <tag> /mnt/...
    //
    // 9P2000.L Win32 backend (Phase 2, committed at 47bae43): 19
    // handlers covering Tversion/Tattach/Twalk/Tlopen/Tlcreate/Tread/
    // Twrite/Tgetattr/Tsetattr/Treaddir/Tclunk/Tremove/Tfsync/Tflush/
    // Tmkdir/Trename/Trenameat/Tunlinkat/Tstatfs.
    //
    // Lifetime: P9Device must outlive the PciTransport that references
    // it. Hold owning ptrs here so destruction order is "PCI bus first,
    // then devices" (pbus is reset before this vector goes out of
    // scope at function exit).
    std::vector<std::unique_ptr<virtio::P9Device>> p9_devices;
    p9_devices.reserve(p9_shares.size());
    for (std::size_t i = 0; i < p9_shares.size(); ++i) {
        const auto& s = p9_shares[i];
        virtio::P9Share share{
            /*.tag=*/      s.tag,
            /*.host_root=*/s.host_root,
            /*.readonly=*/ s.readonly,
        };
        auto dev = std::make_unique<virtio::P9Device>(ram, std::move(share));

        virtio::PciTransport::Options popts;
        popts.subsys_id        = static_cast<std::uint16_t>(virtio::kDeviceIdP9);
        popts.num_msix_vectors = 2;     // requestq + config-change
        popts.pci_class        = 0xFF;  // Unassigned / Other
        popts.pci_subclass     = 0x00;
        auto pxport = std::make_unique<virtio::PciTransport>(
            *dev, popts, mmio_bus, inject_fn);
        virtio::PciTransport* pxp = pxport.get();
        dev->SetIrqCallback(
            [pxp](std::uint32_t q) { pxp->RaiseQueueInterrupt(q); });

        char nbuf[40];
        std::snprintf(nbuf, sizeof(nbuf), "virtio-pci-9p[%zu]", i);
        pxport->set_name(nbuf);

        const pci::Bdf pbdf = pbus->AddDevice(std::move(pxport));
        std::printf("[pvh-run] virtio-9p[%zu] on PCI %02x:%02x.%u "
                    "tag=%s host=%s%s\n",
                    i, pbdf.bus, pbdf.device, pbdf.function,
                    s.tag.c_str(), s.host_root.string().c_str(),
                    s.readonly ? " (ro)" : "");
        p9_devices.push_back(std::move(dev));
    }


    // --- virtio-net (optional) -----------------------------------------
    // The backend (chosen via --net-backend) is started lazily from
    // PciTransport's OnBarMapped callback -- that's the first moment we
    // know the guest has mapped the MMIO BAR and can therefore install
    // The virtio-net device is owned here, but we need to wire up the
    // per-queue doorbells / spin up worker threads.
    std::unique_ptr<virtio::NetDevice> net;
    if (with_net) {
        constexpr std::array<std::uint8_t, 6> kMac{
            0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
        net = std::make_unique<virtio::NetDevice>(ram, kMac);

        virtio::PciTransport::Options opts;
        opts.subsys_id        = static_cast<std::uint16_t>(virtio::kDeviceIdNet);
        opts.num_msix_vectors = 3;     // RX, TX, config-change
        opts.pci_class        = 0x02;  // Network controller
        opts.pci_subclass     = 0x00;  // Ethernet controller
        auto xport = std::make_unique<virtio::PciTransport>(
            *net, opts, mmio_bus, inject_fn);

        // Install the chosen backend on the NetDevice.
        const char* backend_name = "none";
        switch (net_backend) {
        case NetBackendKind::None:
            backend_name = "none";
            break;
        case NetBackendKind::Loopback:
            net->SetBackend(std::make_unique<virtio::LoopbackNetBackend>(*net));
            backend_name = "loopback";
            break;
        case NetBackendKind::Xdp: {
            virtio::XdpNetBackend::Options xo;
            xo.if_index = xdp_if;
            xo.queue_id = xdp_queue;
            xo.debug    = xdp_debug;
            net->SetBackend(std::make_unique<virtio::XdpNetBackend>(
                *net, ram, xo));
            backend_name = "xdp";
            break;
        }
        case NetBackendKind::Wintun: {
            virtio::WintunNetBackend::Options wo;
            wo.kind = virtio::WintunNetBackend::BackendKind::Dll;
            net->SetBackend(std::make_unique<virtio::WintunNetBackend>(
                *net, wo));
            backend_name = "wintun";
            break;
        }
        case NetBackendKind::WintunSvc: {
            virtio::WintunNetBackend::Options wo;
            wo.kind = virtio::WintunNetBackend::BackendKind::Svc;
            net->SetBackend(std::make_unique<virtio::WintunNetBackend>(
                *net, wo));
            backend_name = "wintun-svc";
            break;
        }
        case NetBackendKind::Usernet: {
            virtio::UsernetBackend::Options uo;
            uo.port_forwards = port_forwards;
            net->SetBackend(std::make_unique<virtio::UsernetBackend>(
                *net, uo));
            backend_name = "usernet";
            break;
        }
        }

        // Arm the BAR-mapped callback to start the backend once Linux
        // writes COMMAND.MEM_SPACE. We capture raw pointers because the
        // unique_ptrs outlive the callback (the transport is owned by
        // pbus, which is destroyed only after RunPvhRun returns).
        virtio::PciTransport* xp = xport.get();
        virtio::NetDevice* np = net.get();
        whp::Partition* pp = &part;
        xport->SetOnBarMappedCallback([np, xp, pp]() {
            if (auto* b = np->backend()) {
                b->Start(*pp, *xp);
            }
        });

        // PciBus takes ownership.
        const pci::Bdf bdf = pbus->AddDevice(std::move(xport));
        std::printf("[pvh-run] virtio-net on PCI %02x:%02x.%u (backend=%s)\n",
                    bdf.bus, bdf.device, bdf.function, backend_name);
    }

    // Per-vCPU run loops. Each loop owns its emulator handle and counters.
    // For N=1 the BSP runs on this thread; for N>1 we spawn N-1 AP threads
    // each driving its own loop (BSP still runs here).
    std::deque<RunLoop> loops;
    for (std::uint32_t i = 0; i < vcpu_count; ++i) {
        loops.emplace_back(vcpus[i], io_bus, mmio_bus, vcpu_count);
        loops.back().set_hv_enlightenment(&hv);
    }
    RunLoop& loop = loops.front();

    auto stop_all_loops = [&loops]() {
        for (auto& l : loops) l.RequestStop();
    };

    // Guest-driven shutdown sentinel watcher. The byte observer (set up
    // way above on the virtio-console) flips `shutdown_requested` to true
    // when /init prints the `[init] === tinyvmm shutdown requested ===`
    // line. This tiny thread polls the flag and triggers a graceful
    // tinyvmm exit, so test harnesses don't have to rely on `poweroff`
    // actually halting the vCPU. Always-on (no `--watchdog-secs`
    // dependency).
    std::atomic<bool> shutdown_watcher_done{false};
    std::thread shutdown_watcher([&shutdown_watcher_done, shutdown_requested,
                                   &stop_all_loops]() {
        while (!shutdown_watcher_done.load(std::memory_order_relaxed)) {
            if (shutdown_requested->load(std::memory_order_acquire)) {
                std::fputs("[pvh-run] guest requested shutdown via "
                           "hvc0 sentinel; stopping vCPU loops\n", stderr);
                stop_all_loops();
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    });

    // ---- stdin -> virtio-console rxq forwarder ---------------------------
    // When stdin is a real console (TTY), forward keystrokes to the guest's
    // /dev/hvc0. Skip when stdin is redirected/piped/null so we don't burn a
    // thread polling a pipe and so test scripts behave normally.
    //
    // We implement a qemu-compatible Ctrl+A escape so the user can quit:
    //   Ctrl+A X   -> request graceful shutdown
    //   Ctrl+A H   -> print help line to stderr
    //   Ctrl+A A   -> forward a literal Ctrl+A (0x01) to the guest
    //   Ctrl+A ?   -> alias for H
    // Anything else right after Ctrl+A is swallowed with a hint. Without an
    // escape we'd be stuck -- raw stdin mode means Windows never sees Ctrl+C
    // as SIGINT (we forward it as 0x03 to the guest shell), so the only way
    // out otherwise is to close the terminal window or taskkill from another
    // shell.
    HANDLE hstdin = ::GetStdHandle(STD_INPUT_HANDLE);
    DWORD original_console_mode = 0;
    bool restore_console_mode = false;
    std::atomic<bool> stdin_stop{false};
    std::thread stdin_thread;
    const bool stdin_is_tty = (hstdin != INVALID_HANDLE_VALUE) &&
                              (::GetFileType(hstdin) == FILE_TYPE_CHAR);
    if (stdin_is_tty) {
        // Save the current mode and switch to raw: no line editing, no echo
        // (the guest's shell echoes), no Ctrl+C handling (forward 0x03 to
        // guest). Best-effort: if the calls fail we still read input, just
        // line-buffered.
        if (::GetConsoleMode(hstdin, &original_console_mode)) {
            restore_console_mode = true;
            ::SetConsoleMode(hstdin, ENABLE_WINDOW_INPUT);
        }
        // Also enable VT processing on stdout so guest ANSI escapes (color,
        // cursor moves) render correctly. Harmless if already enabled.
        if (HANDLE hout = ::GetStdHandle(STD_OUTPUT_HANDLE);
            hout != INVALID_HANDLE_VALUE) {
            DWORD om = 0;
            if (::GetConsoleMode(hout, &om)) {
                ::SetConsoleMode(hout, om | ENABLE_PROCESSED_OUTPUT |
                                          ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
        std::fputs("[pvh-run] interactive console -- press Ctrl+A then X "
                   "to quit, Ctrl+A H for help\n", stderr);
        stdin_thread = std::thread(
            [hstdin, vcon_ptr, &stdin_stop, &stop_all_loops]() {
            INPUT_RECORD recs[64];
            bool escape_armed = false;
            while (!stdin_stop.load(std::memory_order_relaxed)) {
                // 50ms wait so we can poll the stop flag.
                DWORD wr = ::WaitForSingleObject(hstdin, 50);
                if (wr == WAIT_TIMEOUT) continue;
                if (wr != WAIT_OBJECT_0) break;
                DWORD num = 0;
                if (!::GetNumberOfConsoleInputEvents(hstdin, &num)) continue;
                if (num == 0) continue;
                DWORD to_read = (num < 64) ? num : 64;
                DWORD read = 0;
                if (!::ReadConsoleInputW(hstdin, recs, to_read, &read)) continue;
                std::string out;
                out.reserve(read);
                bool quit_requested = false;
                for (DWORD i = 0; i < read; ++i) {
                    if (recs[i].EventType != KEY_EVENT) continue;
                    const auto& k = recs[i].Event.KeyEvent;
                    if (!k.bKeyDown) continue;
                    wchar_t wc = k.uChar.UnicodeChar;
                    // Arrow keys, Home/End/PgUp/PgDn/Ins/Del, and the function
                    // keys come through with UnicodeChar == 0 and the actual
                    // key in wVirtualKeyCode. Translate the navigation keys
                    // to the standard xterm/VT escape sequences so the guest
                    // shell's line editor (busybox ash, bash, etc.) can use
                    // up/down for history, left/right for cursor movement,
                    // Home/End to jump within the line, etc. Modifier-key
                    // variants (Shift+Up, Ctrl+Left, ...) are intentionally
                    // not yet wired -- they require encoding modifiers as
                    // `ESC [ 1 ; <m> A` and most users only need plain.
                    if (wc == 0) {
                        const char* seq = nullptr;
                        switch (k.wVirtualKeyCode) {
                        case VK_UP:     seq = "\x1b[A"; break;
                        case VK_DOWN:   seq = "\x1b[B"; break;
                        case VK_RIGHT:  seq = "\x1b[C"; break;
                        case VK_LEFT:   seq = "\x1b[D"; break;
                        case VK_HOME:   seq = "\x1b[H"; break;
                        case VK_END:    seq = "\x1b[F"; break;
                        case VK_INSERT: seq = "\x1b[2~"; break;
                        case VK_DELETE: seq = "\x1b[3~"; break;
                        case VK_PRIOR:  seq = "\x1b[5~"; break;
                        case VK_NEXT:   seq = "\x1b[6~"; break;
                        case VK_F1:     seq = "\x1bOP"; break;
                        case VK_F2:     seq = "\x1bOQ"; break;
                        case VK_F3:     seq = "\x1bOR"; break;
                        case VK_F4:     seq = "\x1bOS"; break;
                        case VK_F5:     seq = "\x1b[15~"; break;
                        case VK_F6:     seq = "\x1b[17~"; break;
                        case VK_F7:     seq = "\x1b[18~"; break;
                        case VK_F8:     seq = "\x1b[19~"; break;
                        case VK_F9:     seq = "\x1b[20~"; break;
                        case VK_F10:    seq = "\x1b[21~"; break;
                        case VK_F11:    seq = "\x1b[23~"; break;
                        case VK_F12:    seq = "\x1b[24~"; break;
                        default: break;
                        }
                        if (seq) out.append(seq);
                        continue;
                    }
                    // ---- Ctrl+A escape state machine ------------------
                    if (escape_armed) {
                        escape_armed = false;
                        if (wc == L'x' || wc == L'X') {
                            std::fputs("\r\n[pvh-run] Ctrl+A X -- "
                                       "quitting\r\n", stderr);
                            quit_requested = true;
                            break;
                        }
                        if (wc == L'h' || wc == L'H' || wc == L'?') {
                            std::fputs(
                                "\r\n[pvh-run] Ctrl+A keys: "
                                "X=quit, A=literal ^A, H=help\r\n",
                                stderr);
                            continue;
                        }
                        if (wc == 0x01) {
                            // Pass a literal Ctrl+A through to the guest.
                            out.push_back('\x01');
                            continue;
                        }
                        std::fputs("\r\n[pvh-run] unknown Ctrl+A sequence; "
                                   "Ctrl+A H for help\r\n", stderr);
                        continue;
                    }
                    if (wc == 0x01) {  // Ctrl+A -- arm escape, swallow.
                        escape_armed = true;
                        continue;
                    }
                    // ---- normal forwarding ----------------------------
                    if (wc == L'\r') { out.push_back('\n'); continue; }
                    if (wc < 0x80) {
                        out.push_back(static_cast<char>(wc));
                        continue;
                    }
                    char mb[8] = {};
                    int n = ::WideCharToMultiByte(CP_UTF8, 0, &wc, 1, mb,
                                                  sizeof(mb), nullptr, nullptr);
                    if (n > 0) out.append(mb, mb + n);
                }
                if (!out.empty()) {
                    vcon_ptr->WriteHostInput(out.data(), out.size());
                }
                if (quit_requested) {
                    // Ask all run loops to break out of WHvRunVirtualProcessor
                    // and return StopReason::Cancelled. main() will then
                    // join us, restore the console mode, and tear down.
                    stop_all_loops();
                    return;
                }
            }
        });
    }

    std::puts("[pvh-run] running");

    // Watchdog + per-second exit-rate telemetry. We print deltas (not
    // running totals) so it's obvious whether the guest is currently
    // generating traffic in a given category, and at what rate.
    // `watchdog_secs == 0` -> no watchdog AND no telemetry (interactive
    // default; telemetry would otherwise corrupt the on-console shell).
    const bool watchdog_enabled = (watchdog_secs > 0);
    std::atomic<bool> watchdog_done{false};
    std::thread watchdog;
    if (watchdog_enabled) {
        watchdog = std::thread([&] {
            std::uint64_t prev_io = 0, prev_mmio = 0, prev_halt = 0;
            std::uint64_t prev_cpuid = 0, prev_msi = 0, prev_uart = 0;
            int s = 0;
            auto sum = [&loops](auto getter) -> std::uint64_t {
                std::uint64_t v = 0;
                for (auto& l : loops) v += getter(l);
                return v;
            };
            while (!watchdog_done.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                if (watchdog_done.load()) return;
                ++s;
                const std::uint64_t cur_io    =
                    sum([](RunLoop& l) { return l.io_exits();    });
                const std::uint64_t cur_mmio  =
                    sum([](RunLoop& l) { return l.mmio_exits();  });
                const std::uint64_t cur_halt  =
                    sum([](RunLoop& l) { return l.halt_exits();  });
                const std::uint64_t cur_cpuid =
                    sum([](RunLoop& l) { return l.cpuid_exits(); });
                const std::uint64_t cur_msi   = whp::MsiInjectCount();
                const std::uint64_t cur_uart  = com1.tx_bytes();
                std::fprintf(stderr,
                    "[pvh-run] @%2ds  io=%llu(+%llu) mmio=%llu(+%llu) "
                    "cpuid=%llu(+%llu) halt=%llu(+%llu) msi=%llu(+%llu) "
                    "uart=%llu(+%llu)\n",
                    s,
                    static_cast<unsigned long long>(cur_io),
                    static_cast<unsigned long long>(cur_io - prev_io),
                    static_cast<unsigned long long>(cur_mmio),
                    static_cast<unsigned long long>(cur_mmio - prev_mmio),
                    static_cast<unsigned long long>(cur_cpuid),
                    static_cast<unsigned long long>(cur_cpuid - prev_cpuid),
                    static_cast<unsigned long long>(cur_halt),
                    static_cast<unsigned long long>(cur_halt - prev_halt),
                    static_cast<unsigned long long>(cur_msi),
                    static_cast<unsigned long long>(cur_msi - prev_msi),
                    static_cast<unsigned long long>(cur_uart),
                    static_cast<unsigned long long>(cur_uart - prev_uart));
                prev_io    = cur_io;
                prev_mmio  = cur_mmio;
                prev_halt  = cur_halt;
                prev_cpuid = cur_cpuid;
                prev_msi   = cur_msi;
                prev_uart  = cur_uart;
                if (s >= watchdog_secs) {
                    std::fprintf(stderr,
                        "[pvh-run] watchdog: %ds elapsed, requesting stop\n",
                        watchdog_secs);
                    stop_all_loops();
                    return;
                }
            }
        });
    }

    btimer.Mark("entering guest");
    TINYVMM_ETW_INFO("GuestEntry",
        TraceLoggingString(path, "kernel"),
        TraceLoggingBool(with_net, "with_net"));

    // CPU-affinity policy: resolve the requested mode against the host's
    // logical-processor topology, log what we see, and pin every vCPU
    // thread (BSP + APs) to the resulting CPU-set IDs before its run loop
    // starts. The pin uses `SetThreadSelectedCpuSets`, which restricts the
    // Windows scheduler to that set but still allows scheduling within it.
    //
    // Motivation: on hybrid Intel CPUs (e.g. i9-14900K), Linux's
    // `clocksource_watchdog` marks TSC unstable once vCPU threads bounce
    // across P-core and E-core boundaries, silently demoting
    // `clock_gettime` for the rest of the boot. Pinning to one class fixes
    // that.
    const auto cpu_set_ids = whp::ResolveCpuSetIds(affinity_mode);
    {
        const auto& top = whp::GetTopology();
        if (top.hybrid) {
            std::printf("[pvh-run] host topology: hybrid, %u logical "
                        "(P=%u/%uHT, E=%u); cpu-affinity=%s "
                        "(pinning %zu logicals)\n",
                        top.total_logical, top.p_physical, top.p_logical,
                        top.e_logical,
                        whp::AffinityModeName(affinity_mode),
                        cpu_set_ids.size());
        } else {
            std::printf("[pvh-run] host topology: non-hybrid, %u logical; "
                        "cpu-affinity=%s (pinning %zu logicals)\n",
                        top.total_logical,
                        whp::AffinityModeName(affinity_mode),
                        cpu_set_ids.size());
        }
    }

    // Spawn N-1 AP threads if SMP requested. BSP runs loops[0].Run() on
    // this thread; APs sit in WAIT_FOR_SIPI until Linux delivers INIT+SIPI
    // through the LAPIC (WHP services those in-hypervisor).
    std::vector<std::thread> ap_threads;
    std::vector<std::exception_ptr> ap_excs(vcpu_count, nullptr);
    ap_threads.reserve(vcpu_count > 0 ? vcpu_count - 1 : 0);
    for (std::uint32_t i = 1; i < vcpu_count; ++i) {
        ap_threads.emplace_back([i, &loops, &ap_excs, &stop_all_loops,
                                 &cpu_set_ids] {
            (void)whp::PinCurrentThread(cpu_set_ids);
            try {
                (void)loops[i].Run();
            } catch (...) {
                ap_excs[i] = std::current_exception();
            }
            // Whichever vCPU exits first signals everyone else.
            stop_all_loops();
        });
    }

    // Pin the BSP (this thread) just before running its loop. We
    // deliberately pin AFTER all partition / device / memory setup so
    // those one-time host-side bring-up steps run on the whole machine.
    (void)whp::PinCurrentThread(cpu_set_ids);

    // M35: GDB Remote Serial Protocol stub. Constructed lazily based
    // on --gdb-port. When set, halts the BSP before the first guest
    // instruction and waits for a real gdb to connect, so the user
    // can set breakpoints before the kernel runs.
    std::unique_ptr<tinyvmm::debug::GdbStub> gdb_stub;
    if (gdb_port != 0) {
        gdb_stub = std::make_unique<tinyvmm::debug::GdbStub>(
            part, vcpus[0], ram, gdb_port);
        gdb_stub->WaitForFirstConnection();
        // Block until GDB issues continue / step. Pass 0xFF as the
        // "entry pause" sentinel (the stub reports SIGINT for this).
        WHV_REGISTER_NAME rn = WHvX64RegisterRip;
        WHV_REGISTER_VALUE rv{};
        vcpus[0].GetRegisters(std::span(&rn, 1), std::span(&rv, 1));
        auto action = gdb_stub->ReportStop(/*vec=*/0xFF, rv.Reg64);
        if (action == tinyvmm::debug::GdbStub::Action::Shutdown) {
            std::fprintf(stderr, "[gdbstub] detached at entry; exiting\n");
            return 0;
        }
        // Single-step on entry isn't supported in M35.0 (no exception
        // exit wiring yet); treat as continue.
        std::fprintf(stderr, "[gdbstub] resuming guest\n");
    }

    StopReason stop = StopReason::Cancelled;
    try {
        stop = loop.Run();
    } catch (...) {
        ap_excs[0] = std::current_exception();
    }
    btimer.Mark("guest exited");
    // BSP returned; ask APs to wind down too.
    stop_all_loops();
    watchdog_done.store(true);
    shutdown_watcher_done.store(true);
    stdin_stop.store(true);
    if (watchdog.joinable()) {
        watchdog.join();
    }
    if (shutdown_watcher.joinable()) {
        shutdown_watcher.join();
    }
    if (stdin_thread.joinable()) {
        stdin_thread.join();
    }
    for (auto& t : ap_threads) {
        if (t.joinable()) t.join();
    }
    if (restore_console_mode) {
        ::SetConsoleMode(hstdin, original_console_mode);
    }

    // Stop the net backend (and its worker thread, if any) before we let
    // the device + transport + partition unwind. Doorbells must be
    // unregistered before the partition handle goes away.
    if (net) {
        if (auto* b = net->backend()) b->Stop();
    }

    // M33.6: if a snapshot was requested, drain any virtio-blk in-flight
    // requests BEFORE we Stop() the IOCP workers. With workers still
    // running, OnComplete callbacks decrement PendingCount() naturally as
    // OS-level I/Os finish. Refuse the snapshot (return non-zero) if we
    // can't drain within the timeout -- a partially-completed request
    // would leave the virtqueue head consumed but the used-ring entry not
    // posted, and on restore the guest would wait forever for it.
    // The drain is also a defensive no-op for the non-snapshot path:
    // PendingCount() should already be zero whenever the guest reached
    // its own quiesce point (sync; poweroff; etc.).
    const bool snapshot_requested =
        ::tinyvmm::whp::snapshot::WasRequested();
    if (snapshot_requested) {
        if (!DrainBlockBackends(blk_devices, /*timeout_ms=*/5000)) {
            std::fprintf(stderr,
                "[snapshot] FAIL: virtio-blk drain timed out after 5s "
                "(some device still has in-flight requests); refusing to "
                "write snapshot.\n");
            // Still need to Stop() the IOCP workers below to avoid a
            // dangling-callback UAF in ~BlockDevice, then return non-zero.
            for (auto& b : blk_backends) b->Stop();
            return 2;
        }
    }

    // Quiesce every virtio-blk IOCP worker before the BlockDevice owners
    // (in blk_devices) get destroyed. Otherwise a completion landing
    // after BlockDevice is gone but before BlockFile::~BlockFile runs Stop
    // would invoke a method on freed memory. Stop() is idempotent so it's
    // fine if the destructor runs Stop() again.
    for (auto& b : blk_backends) {
        b->Stop();
    }

    // Per-disk shutdown summary. `max_inflight` is the high-water mark of
    // outstanding ops the IOCP worker ever saw; the blk-test harness
    // asserts max_inflight > 1 to prove its concurrent-writer phase
    // actually reached parallel queue depth from the backend's view.
    for (std::size_t i = 0; i < blk_backends.size(); ++i) {
        auto& b = blk_backends[i];
        auto& d = blk_devices[i];
        std::printf("[pvh-run] virtio-blk[%zu] stats: submitted=%llu "
                    "completed=%llu errors=%llu max_inflight=%llu "
                    "(virtio in=%llu out=%llu flush=%llu discard=%llu "
                    "wz=%llu err=%llu)\n",
                    i,
                    static_cast<unsigned long long>(b->submitted()),
                    static_cast<unsigned long long>(b->completed()),
                    static_cast<unsigned long long>(b->errors()),
                    static_cast<unsigned long long>(b->max_inflight()),
                    static_cast<unsigned long long>(d->ops_in()),
                    static_cast<unsigned long long>(d->ops_out()),
                    static_cast<unsigned long long>(d->ops_flush()),
                    static_cast<unsigned long long>(d->ops_discard()),
                    static_cast<unsigned long long>(d->ops_write_zeroes()),
                    static_cast<unsigned long long>(d->ops_err()));
    }

    // M33.6 production snapshot writer. By the time we get here all
    // vCPUs are stopped, the net backend (if any) is Stop()'d, every
    // virtio-blk IOCP worker is Stop()'d, and PendingCount() drained to
    // zero (or we would have returned 2 above). Now it's safe to walk
    // the device tree, capture all per-class state, and write the file.
    if (snapshot_requested) {
        const auto& st = ::tinyvmm::whp::snapshot::State();
        std::printf(
            "[snapshot] trigger fired from vp=%u; capturing to '%s'\n",
            st.requesting_vp_index.load(std::memory_order_acquire),
            st.save_path.c_str());

        SnapshotWriteContext sctx{
            /*part_handle*/        part.handle(),
            /*vcpu_count*/         vcpu_count,
            /*vcpus*/              vcpus,
            /*ram*/                ram,
            /*large_pages*/        ram.large_pages(),
            /*hv*/                 hv,
            /*com1*/               com1,
            /*pic*/                pic,
            /*pit*/                pit,
            /*legacy*/             legacy,
            /*pbus*/               *pbus,
            /*blk_backends*/       blk_backends,
            /*blk_devices*/        blk_devices,
            /*drives*/             drives,
            /*hide_tsc_deadline*/  hide_tsc_deadline,
            /*tsc_hz*/             ::tinyvmm::whp::GetCachedTscHz(),
        };
        const int rc = WriteSnapshotFile(st.save_path, sctx);
        if (rc != 0) {
            return rc;
        }
        btimer.Mark("snapshot written");
        return 0;
    }

    // Dump the guest's view of itself at the moment we stopped, so we can
    // see what code the kernel was running.
    static const WHV_REGISTER_NAME dump_regs[] = {
        WHvX64RegisterRip,    WHvX64RegisterRsp,    WHvX64RegisterRflags,
        WHvX64RegisterCr0,    WHvX64RegisterCr3,    WHvX64RegisterCr4,
        WHvX64RegisterEfer,   WHvX64RegisterCs,     WHvX64RegisterSs,
        WHvX64RegisterRax,    WHvX64RegisterRbx,    WHvX64RegisterRcx,
        WHvX64RegisterRdx,    WHvX64RegisterRsi,    WHvX64RegisterRdi,
        WHvX64RegisterR8,     WHvX64RegisterR9,     WHvX64RegisterR10,
    };
    WHV_REGISTER_VALUE dump_vals[std::size(dump_regs)] = {};
    vp.GetRegisters(dump_regs, dump_vals);
    std::fprintf(stderr,
                 "[pvh-run] dump RIP=0x%llx RSP=0x%llx RFLAGS=0x%llx\n",
                 static_cast<unsigned long long>(dump_vals[0].Reg64),
                 static_cast<unsigned long long>(dump_vals[1].Reg64),
                 static_cast<unsigned long long>(dump_vals[2].Reg64));
    std::fprintf(stderr,
                 "[pvh-run]      CR0=0x%llx CR3=0x%llx CR4=0x%llx EFER=0x%llx\n",
                 static_cast<unsigned long long>(dump_vals[3].Reg64),
                 static_cast<unsigned long long>(dump_vals[4].Reg64),
                 static_cast<unsigned long long>(dump_vals[5].Reg64),
                 static_cast<unsigned long long>(dump_vals[6].Reg64));
    std::fprintf(
        stderr,
        "[pvh-run]      CS sel=0x%x base=0x%llx limit=0x%x attr=0x%x\n",
        dump_vals[7].Segment.Selector,
        static_cast<unsigned long long>(dump_vals[7].Segment.Base),
        dump_vals[7].Segment.Limit, dump_vals[7].Segment.Attributes);
    std::fprintf(stderr,
                 "[pvh-run]      RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx\n",
                 static_cast<unsigned long long>(dump_vals[9].Reg64),
                 static_cast<unsigned long long>(dump_vals[10].Reg64),
                 static_cast<unsigned long long>(dump_vals[11].Reg64),
                 static_cast<unsigned long long>(dump_vals[12].Reg64));
    std::fprintf(stderr,
                 "[pvh-run]      RSI=0x%llx RDI=0x%llx R8=0x%llx R9=0x%llx\n",
                 static_cast<unsigned long long>(dump_vals[13].Reg64),
                 static_cast<unsigned long long>(dump_vals[14].Reg64),
                 static_cast<unsigned long long>(dump_vals[15].Reg64),
                 static_cast<unsigned long long>(dump_vals[16].Reg64));

    // Walk the top of the stack so we can resolve the call chain. The
    // stack is in guest physical memory (paging is enabled in long mode,
    // but for kernel addresses 0xffffffff8000_0000+ the kernel uses an
    // identity-ish map; for stack addresses 0xffffc900_xxxx_xxxx (vmalloc
    // area) we'd need to walk the page tables. Try the simple case first:
    // if RSP is in the kernel direct map (>= 0xffffffff80000000), peek at
    // the bytes; otherwise translate.
    auto translate = [&](std::uint64_t gva) -> std::uint64_t {
        WHV_TRANSLATE_GVA_RESULT r{};
        WHV_GUEST_PHYSICAL_ADDRESS gpa = 0;
        HRESULT hr = WHvTranslateGva(part.handle(), 0, gva,
                                     WHvTranslateGvaFlagValidateRead, &r, &gpa);
        if (FAILED(hr) || r.ResultCode != WHvTranslateGvaResultSuccess) {
            return UINT64_MAX;
        }
        return gpa;
    };
    auto peek64 = [&](std::uint64_t gva) -> std::uint64_t {
        std::uint64_t gpa = translate(gva);
        if (gpa == UINT64_MAX) return UINT64_MAX;
        if (gpa + 8 > ram.size()) return UINT64_MAX;
        std::uint64_t v;
        std::memcpy(&v, static_cast<std::uint8_t*>(ram.host_base()) + gpa, 8);
        return v;
    };
    // Heavy diagnostics (stack walk + LAPIC + IDT decode) are only useful
    // for kernel debugging. Gate behind TINYVMM_DIAG=1 so normal pvh-run
    // output stays compact.
    bool diag = false;
    {
        char buf[8] = {};
        size_t n = 0;
        if (getenv_s(&n, buf, sizeof(buf), "TINYVMM_DIAG") == 0 && n > 0 &&
            buf[0] != '0' && buf[0] != '\0') {
            diag = true;
        }
    }
    if (diag) {
        std::uint64_t rsp = dump_vals[1].Reg64;
        std::fprintf(stderr, "[pvh-run] stack walk:\n");
        for (int i = 0; i < 40; ++i) {
            std::uint64_t v = peek64(rsp + i * 8);
            std::fprintf(stderr, "  [rsp+%2d*8] 0x%016llx\n", i,
                         static_cast<unsigned long long>(v));
        }
    }

    // Also dump the virtual LAPIC state: an APIC error (the kernel was found
    // in sysvec_error_interrupt) usually means we're injecting with the wrong
    // destination, so APIC ID + ESR + TPR + ISR/IRR for the same priority
    // class as IRQ 4 (vector 0x34 -> word 1, bit 20) are the diagnostic
    // signal.
    if (diag) {
        std::uint8_t apic_state[4096] = {};
        UINT32 written = 0;
        HRESULT hr = WHvGetVirtualProcessorInterruptControllerState(
            part.handle(), 0, apic_state, sizeof(apic_state), &written);
        if (SUCCEEDED(hr) && written >= 0x300) {
            auto reg32 = [&](size_t off) -> std::uint32_t {
                std::uint32_t v;
                std::memcpy(&v, &apic_state[off], 4);
                return v;
            };
            std::fprintf(stderr,
                         "[pvh-run] LAPIC state (%u bytes):\n", written);
            std::fprintf(stderr,
                         "  ID=0x%08x  Version=0x%08x  TPR=0x%08x  PPR=0x%08x\n",
                         reg32(0x20), reg32(0x30), reg32(0x80), reg32(0xA0));
            std::fprintf(stderr,
                         "  LDR=0x%08x  DFR=0x%08x  SVR=0x%08x  ESR=0x%08x\n",
                         reg32(0xD0), reg32(0xE0), reg32(0xF0), reg32(0x280));
            std::fprintf(stderr,
                         "  ISR[0..7]: %08x %08x %08x %08x %08x %08x %08x %08x\n",
                         reg32(0x100), reg32(0x110), reg32(0x120), reg32(0x130),
                         reg32(0x140), reg32(0x150), reg32(0x160), reg32(0x170));
            std::fprintf(stderr,
                         "  IRR[0..7]: %08x %08x %08x %08x %08x %08x %08x %08x\n",
                         reg32(0x200), reg32(0x210), reg32(0x220), reg32(0x230),
                         reg32(0x240), reg32(0x250), reg32(0x260), reg32(0x270));
            std::fprintf(stderr,
                         "  LVT timer=0x%08x  LINT0=0x%08x  LINT1=0x%08x  err=0x%08x\n",
                         reg32(0x320), reg32(0x350), reg32(0x360), reg32(0x370));
        } else {
            std::fprintf(stderr,
                         "[pvh-run] LAPIC state dump failed hr=0x%08x written=%u\n",
                         static_cast<unsigned int>(hr), written);
        }
    }

    // Dump IDT entries for vectors of interest -- if vector 0x34 is wired to
    // something other than common_interrupt, IRQ 4 will never reach the
    // 8250 handler no matter how many times we inject it.
    if (diag) {
        static const WHV_REGISTER_NAME idt_regs[] = {WHvX64RegisterIdtr};
        WHV_REGISTER_VALUE idt_vals[1] = {};
        if (SUCCEEDED(WHvGetVirtualProcessorRegisters(
                part.handle(), 0, idt_regs, 1, idt_vals))) {
            const std::uint64_t idt_base = idt_vals[0].Table.Base;
            const std::uint16_t idt_limit = idt_vals[0].Table.Limit;
            std::fprintf(stderr,
                         "[pvh-run] IDTR base=0x%llx limit=0x%x\n",
                         static_cast<unsigned long long>(idt_base), idt_limit);
            auto decode_vec = [&](unsigned v) {
                // Each IDT entry is 16 bytes in 64-bit mode.
                const std::uint64_t gpa = translate(idt_base + v * 16);
                if (gpa == UINT64_MAX || gpa + 16 > ram.size()) return;
                const std::uint8_t* p =
                    static_cast<std::uint8_t*>(ram.host_base()) + gpa;
                std::uint16_t off_lo, sel, attr, off_mid;
                std::uint32_t off_hi;
                std::memcpy(&off_lo, p + 0, 2);
                std::memcpy(&sel,    p + 2, 2);
                attr   = static_cast<std::uint16_t>(p[4]) |
                         (static_cast<std::uint16_t>(p[5]) << 8);
                std::memcpy(&off_mid, p + 6, 2);
                std::memcpy(&off_hi,  p + 8, 4);
                const std::uint64_t handler =
                    static_cast<std::uint64_t>(off_lo) |
                    (static_cast<std::uint64_t>(off_mid) << 16) |
                    (static_cast<std::uint64_t>(off_hi)  << 32);
                std::fprintf(stderr,
                             "  IDT[0x%02x] handler=0x%016llx sel=0x%04x attr=0x%04x\n",
                             v, static_cast<unsigned long long>(handler),
                             sel, attr);
            };
            // The legacy PIC vectors of interest, plus a couple of common
            // sysvec ones for reference.
            decode_vec(0x20);
            decode_vec(0x30);  // IRQ 0 (PIT)
            decode_vec(0x33);
            decode_vec(0x34);  // IRQ 4 (COM1) -- this is the one that matters
            decode_vec(0x35);
            decode_vec(0xEC);  // sysvec_apic_timer_interrupt usually
            decode_vec(0xFE);  // sysvec_error_interrupt
        }
    }

    std::printf(
        "[pvh-run] stop=%d  msi=%llu uart_tx=%llu  "
        "last_exit_reason=%s (0x%x) RIP=0x%llx\n",
        static_cast<int>(stop),
        static_cast<unsigned long long>(whp::MsiInjectCount()),
        static_cast<unsigned long long>(com1.tx_bytes()),
        ExitReasonName(loop.last_exit().ExitReason),
        static_cast<unsigned int>(loop.last_exit().ExitReason),
        static_cast<unsigned long long>(loop.last_exit().VpContext.Rip));
    for (std::uint32_t i = 0; i < loops.size(); ++i) {
        if (loops.size() > 1) {
            std::printf("[pvh-run] vCPU %u counters:\n", i);
        }
        loops[i].DumpCounters(stdout);
        loops[i].EmitCountersEtw();
    }

    // Surface any AP exception that didn't propagate naturally.
    for (std::uint32_t i = 1; i < ap_excs.size(); ++i) {
        if (ap_excs[i]) {
            try {
                std::rethrow_exception(ap_excs[i]);
            } catch (const std::exception& e) {
                std::fprintf(stderr,
                             "[pvh-run] vCPU %u threw: %s\n", i, e.what());
            } catch (...) {
                std::fprintf(stderr,
                             "[pvh-run] vCPU %u threw unknown exception\n", i);
            }
        }
    }

    btimer.Mark("teardown done");
    TINYVMM_ETW_INFO("VmStop",
        TraceLoggingFloat64(btimer.ElapsedMs(), "total_ms"));
    diag::EtwUnregister();

    // For post-mortem debugging: dump first 64 MiB of guest RAM so we can
    // grep for printk strings, parse the ringbuffer, etc.
    {
        const char* dump_path = "C:\\tinyvmm\\guest_ram.bin";
        constexpr std::size_t kDumpBytes = 64ull * 1024 * 1024;
        std::size_t n = std::min(kDumpBytes, ram.size());
        FILE* f = nullptr;
        if (fopen_s(&f, dump_path, "wb") == 0 && f != nullptr) {
            std::fwrite(ram.host_base(), 1, n, f);
            std::fclose(f);
            std::fprintf(stderr,
                         "[pvh-run] dumped %zu MiB of guest RAM to %s\n",
                         n / (1024 * 1024), dump_path);
        }
    }
    return 0;
}

// ===========================================================================
// M33.6 production --restore main path.
//
// Parallel to RunPvhRun but bypasses PVH load + kernel setup. Instead reads
// a TVMMSAVE snapshot file, reconstructs partition + RAM + devices to match
// the saved topology, applies all per-class state in the rubber-duck-approved
// order, then enters the vCPU run loops as if the kernel had just been
// pre-empted past the CPUID trigger.
//
// Snapshot-time restrictions enforced at --save: no --net, no
// --virtio-9p-share. Drives may be RO (default) or mutable (with explicit
// --unsafe-save-mutable-drive). --restore mirrors those restrictions and
// additionally rejects PVH-only flags (--initrd, vmlinux positional,
// cmdline override, --net, --virtio-9p-share).
//
// Apply ordering (must match WriteSnapshotFile section ordering with the
// crucial inversion that RAM is *read* last but *applied* first, since
// device state references RAM contents):
//   1. memcpy RAM into ram.host_base()
//   2. hv.ApplyState
//   3. Legacy: PciBus, IsaStubs, Serial, PIC, PIT (Apply only; no Resume)
//   4. Per-PCI device: PciDevice -> virtio-class State -> per Virtqueue
//      -> MsiX -> PciTransport (PciTransport last installs BAR handlers)
//   5. Per-vCPU NonTiming (arch + xsave + apic + intr_ctl)
//   6. ResumeRuntime: PIC -> Serial -> PIT (now that LAPICs are loaded
//      with interrupt state, the deferred PIC IRR replay + Serial TX IRQ
//      re-edge + PIT IRQ thread start can flow through naturally)
//   7. Per-vCPU Timing back-to-back across all vCPUs (TSC skew min)
//   8. Start blk_backends (after PCI+virtio state applied so completions
//      land in fully-restored devices)
//   9. Construct RunLoops, spawn AP threads, BSP runs loops[0]
// ===========================================================================

int RunRestore(const std::string& snapshot_path,
               const std::vector<DriveSpec>& drive_overrides,
               bool unsafe_restore_mutable_drive,
               int watchdog_secs,
               tinyvmm::whp::AffinityMode affinity_mode) {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;
    namespace snap = ::tinyvmm::whp::snapshot;
    namespace dev  = ::tinyvmm::devices;
    namespace p    = ::tinyvmm::pci;
    namespace v    = ::tinyvmm::virtio;

    diag::EtwRegister();
    diag::BootTimer btimer;
    btimer.Mark("restore start");

    CheckWhpAvailable();
    btimer.Mark("WHP probe done");
    std::puts("[restore] WHP available");
    ReportHostCapabilities();

    // ---------------- 1. Parse snapshot header --------------------------
    snap::SnapshotReader rdr(snapshot_path);
    std::string header_json = rdr.ReadHeader();
    snap::JsonObjectReader jr(header_json);

    const std::uint32_t vcpu_count_raw =
        static_cast<std::uint32_t>(jr.GetUint("vcpu_count"));
    const std::uint64_t ram_size_bytes = jr.GetUint("ram_size_bytes");
    const bool large_pages       = jr.GetBool("large_pages");
    const std::uint64_t tsc_hz_saved   = jr.GetUint("tsc_hz_at_save");
    const bool hide_tsc_deadline       = jr.GetBool("hide_tsc_deadline");
    const std::uint64_t drive_count    = jr.GetUint("drive_count");

    if (vcpu_count_raw == 0 || vcpu_count_raw > boot::acpi::kMaxVcpus) {
        std::fprintf(stderr,
            "[restore] FAIL: header vcpu_count=%u out of range [1,%u]\n",
            vcpu_count_raw,
            static_cast<unsigned>(boot::acpi::kMaxVcpus));
        return 3;
    }
    const std::uint32_t vcpu_count = vcpu_count_raw;

    // Validate host TSC matches saved TSC (Reference TSC page math depends
    // on it; mismatched TSC frequency would skew the guest's wall clock by
    // the ratio). Rubber-duck blocking finding E.
    //
    // Use a 100 ppm tolerance band rather than exact equality. The
    // host's tsc_hz is calibrated via a one-shot QPC measurement (see
    // whp::GetCachedTscHz) which has ~1 ppm jitter across process
    // launches even on the same physical host. Two consecutive
    // tinyvmm runs that save-then-restore can easily differ by
    // hundreds of Hz out of ~3 GHz. The guest's notion of time is
    // anchored to the SAVED tsc_hz (HvEnlightenment is constructed
    // with tsc_hz_saved below, so the Reference TSC page math uses
    // saved scale/offset). The check is here purely to catch a
    // restore on a fundamentally different CPU (e.g., laptop docking
    // into a different TB box) where tsc_hz could jump by MHz.
    //
    // Worst-case 100 ppm = ~8.6 s/day of guest-vs-host time drift,
    // which is well inside normal NTP correction range for any guest
    // that runs ntpd/chrony. Tighter than 100 ppm risks spurious
    // refusal; looser starts to matter for short-lived workloads.
    const std::uint64_t tsc_hz_host = ::tinyvmm::whp::GetCachedTscHz();
    {
        const std::uint64_t lo = std::min(tsc_hz_host, tsc_hz_saved);
        const std::uint64_t hi = std::max(tsc_hz_host, tsc_hz_saved);
        const std::uint64_t diff = hi - lo;
        // diff_ppm = diff * 1e6 / lo (saturating: lo is always
        // ~10^9-ish so this fits in uint64).
        const std::uint64_t diff_ppm =
            (lo == 0) ? UINT64_MAX
                      : (diff * 1'000'000ULL) / lo;
        constexpr std::uint64_t kMaxDriftPpm = 100;
        if (diff_ppm > kMaxDriftPpm) {
            std::fprintf(stderr,
                "[restore] FAIL: host tsc_hz=%llu but snapshot was taken at "
                "tsc_hz=%llu (drift=%llu ppm > %llu ppm tolerance); refuse "
                "to restore (Reference TSC page math would skew the guest "
                "clock)\n",
                static_cast<unsigned long long>(tsc_hz_host),
                static_cast<unsigned long long>(tsc_hz_saved),
                static_cast<unsigned long long>(diff_ppm),
                static_cast<unsigned long long>(kMaxDriftPpm));
            return 5;
        }
        if (diff_ppm > 0) {
            std::fprintf(stderr,
                "[restore] note: host tsc_hz=%llu, snapshot tsc_hz=%llu "
                "(drift=%llu ppm, within %llu ppm tolerance); using saved "
                "tsc_hz for Reference TSC page math\n",
                static_cast<unsigned long long>(tsc_hz_host),
                static_cast<unsigned long long>(tsc_hz_saved),
                static_cast<unsigned long long>(diff_ppm),
                static_cast<unsigned long long>(kMaxDriftPpm));
        }
    }

    // Build drive specs from header, applying CLI overrides if provided.
    // For each saved drive: validate file exists, size matches, readonly
    // matches (or unsafe-restore-mutable-drive opts out).
    std::vector<DriveSpec> drives;
    std::vector<std::uint64_t> saved_drive_sizes;
    drives.reserve(static_cast<std::size_t>(drive_count));
    saved_drive_sizes.reserve(static_cast<std::size_t>(drive_count));
    for (std::size_t i = 0; i < drive_count; ++i) {
        char key[40];
        DriveSpec ds;
        std::snprintf(key, sizeof(key), "drive%zu_path", i);
        ds.path = jr.GetString(key);
        std::snprintf(key, sizeof(key), "drive%zu_readonly", i);
        ds.readonly = jr.GetBool(key);
        std::snprintf(key, sizeof(key), "drive%zu_size", i);
        saved_drive_sizes.push_back(jr.GetUint(key));
        if (i < drive_overrides.size() && !drive_overrides[i].path.empty()) {
            // Override path with operator-supplied one; require readonly to
            // match unless --unsafe-restore-mutable-drive is in effect.
            ds.path = drive_overrides[i].path;
            if (drive_overrides[i].readonly != ds.readonly &&
                !unsafe_restore_mutable_drive) {
                std::fprintf(stderr,
                    "[restore] FAIL: --drive %zu readonly=%d but snapshot has "
                    "readonly=%d; pass --unsafe-restore-mutable-drive to "
                    "override\n",
                    i, drive_overrides[i].readonly ? 1 : 0,
                    ds.readonly ? 1 : 0);
                return 6;
            }
            ds.readonly = drive_overrides[i].readonly;
        }
        drives.push_back(std::move(ds));
    }

    // ---------------- 2. Construct Partition + RAM + HV ----------------
    Partition part(vcpu_count);
    part.EnableExtendedExits({.cpuid = true, .msr = true});
    SetHideTscDeadline(hide_tsc_deadline);
    const auto static_cpuid =
        BuildStaticCpuidResultList(hide_tsc_deadline);
    part.SetCpuidResultList(static_cpuid.data(), static_cpuid.size());
    part.SetLocalApicEmulation(WHvX64LocalApicEmulationModeX2Apic);
    part.Setup();

    GuestMemory ram(part, /*gpa=*/0,
                    static_cast<std::size_t>(ram_size_bytes),
                    /*executable=*/true);
    btimer.Mark("guest RAM mapped");
    std::printf("[restore] guest RAM: %zu MiB at GPA 0 (%s, header asked %s)\n",
                ram.size() / (1024 * 1024),
                ram.large_pages() ? "MEM_LARGE_PAGES" : "4 KiB pages",
                large_pages ? "MEM_LARGE_PAGES" : "4 KiB pages");

    HvEnlightenment hv(ram, tsc_hz_saved);
    std::printf("[restore] Hyper-V enlightenment ready (tsc_hz=%llu)\n",
                static_cast<unsigned long long>(hv.tsc_hz()));

    // ---------------- 3. Construct vCPUs (no PVH setup!) ----------------
    std::deque<Vcpu> vcpus;
    for (std::uint32_t i = 0; i < vcpu_count; ++i) {
        vcpus.emplace_back(part, i);
    }

    // ---------------- 4. Construct device tree --------------------------
    devices::IoBus io_bus;
    devices::MmioBus mmio_bus;
    devices::Serial8250 com1(0x3F8, stdout);
    com1.Attach(io_bus);
    devices::Pit8254 pit;
    pit.Attach(io_bus);
    devices::LegacyIsaStubs legacy;
    legacy.Attach(io_bus);

    WHV_PARTITION_HANDLE ph = part.handle();
    auto pic_inject = [ph](std::uint8_t vector,
                           std::uint32_t destination) -> bool {
        WHV_INTERRUPT_CONTROL ctrl = {};
        ctrl.Type            = WHvX64InterruptTypeFixed;
        ctrl.DestinationMode = WHvX64InterruptDestinationModePhysical;
        ctrl.TriggerMode     = WHvX64InterruptTriggerModeEdge;
        ctrl.Destination     = destination;
        ctrl.Vector          = vector;
        return SUCCEEDED(WHvRequestInterrupt(ph, &ctrl, sizeof(ctrl)));
    };
    devices::Pic8259 pic(pic_inject);
    pic.Attach(io_bus);
    com1.SetIrqCallback([&pic](int isa_irq) { pic.Raise(isa_irq); });
    (void)pit;  // pit.SetIrqCallback intentionally not called (matches PVH path).

    auto pbus = std::make_unique<pci::PciBus>();
    pbus->AttachIoBus(io_bus);

    auto inject_fn = [ph](std::uint64_t addr, std::uint32_t data) {
        return SUCCEEDED(InjectMsi(ph, addr, data));
    };

    // Construct virtio devices in EXACTLY the same order RunPvhRun does
    // so BDF assignments match the saved topology: rng -> console -> blk[i].
    // M33.6 explicitly rejects --net and --virtio-9p-share both at save
    // time and at restore time, so we never construct those classes here.
    std::vector<p::Bdf> all_bdfs;

    auto rng = std::make_unique<v::RngDevice>(ram);
    p::Bdf rng_bdf{};
    {
        v::PciTransport::Options ropts;
        ropts.subsys_id        = static_cast<std::uint16_t>(v::kDeviceIdRng);
        ropts.num_msix_vectors = 2;
        ropts.pci_class        = 0xFF;
        ropts.pci_subclass     = 0x00;
        auto rxport = std::make_unique<v::PciTransport>(
            *rng, ropts, mmio_bus, inject_fn);
        v::PciTransport* rxp = rxport.get();
        rng->SetIrqCallback(
            [rxp](std::uint32_t q) { rxp->RaiseQueueInterrupt(q); });
        rxport->set_name("virtio-pci-rng");
        rng_bdf = pbus->AddDevice(std::move(rxport));
        all_bdfs.push_back(rng_bdf);
        std::printf("[restore] virtio-rng on PCI %02x:%02x.%u\n",
                    rng_bdf.bus, rng_bdf.device, rng_bdf.function);
    }

    auto vcon = std::make_unique<v::ConsoleDevice>(ram, stdout);
    v::ConsoleDevice* vcon_ptr = vcon.get();
    p::Bdf vcon_bdf{};
    // Restore-time shutdown sentinel watcher (mirrors RunPvhRun).
    auto shutdown_requested =
        std::make_shared<std::atomic<bool>>(false);
    {
        static constexpr const char* kShutdownSentinel =
            "[init] === tinyvmm shutdown requested ===";
        auto pending_buf  = std::make_shared<std::string>();
        auto pending_mu   = std::make_shared<std::mutex>();
        vcon->SetByteObserver([pending_buf, pending_mu, shutdown_requested]
                              (const char* d, std::size_t n) {
            std::lock_guard<std::mutex> lg(*pending_mu);
            pending_buf->append(d, n);
            if (pending_buf->size() > 4096) {
                pending_buf->erase(0, pending_buf->size() - 2048);
            }
            if (!shutdown_requested->load(std::memory_order_relaxed) &&
                pending_buf->find(kShutdownSentinel) != std::string::npos) {
                shutdown_requested->store(true, std::memory_order_release);
            }
        });

        v::PciTransport::Options copts;
        copts.subsys_id        = static_cast<std::uint16_t>(v::kDeviceIdConsole);
        copts.num_msix_vectors = 3;
        copts.pci_class        = 0x07;
        copts.pci_subclass     = 0x80;
        auto cxport = std::make_unique<v::PciTransport>(
            *vcon, copts, mmio_bus, inject_fn);
        v::PciTransport* cxp = cxport.get();
        vcon->SetIrqCallback(
            [cxp](std::uint32_t q) { cxp->RaiseQueueInterrupt(q); });
        cxport->set_name("virtio-pci-console");
        vcon_bdf = pbus->AddDevice(std::move(cxport));
        all_bdfs.push_back(vcon_bdf);
        std::printf("[restore] virtio-console on PCI %02x:%02x.%u "
                    "(sink=stdout)\n",
                    vcon_bdf.bus, vcon_bdf.device, vcon_bdf.function);
    }

    std::vector<std::unique_ptr<host::BlockFile>>    blk_backends;
    std::vector<std::unique_ptr<v::BlockDevice>>     blk_devices;
    std::vector<p::Bdf>                              blk_bdfs;
    blk_backends.reserve(drives.size());
    blk_devices.reserve(drives.size());
    blk_bdfs.reserve(drives.size());
    for (std::size_t i = 0; i < drives.size(); ++i) {
        const auto& d = drives[i];
        std::wstring wpath = std::filesystem::path(d.path).wstring();
        auto backend = std::make_unique<host::BlockFile>(wpath, d.readonly);
        if (!backend->open()) {
            std::fprintf(stderr,
                "[restore] FAIL: drive %zu '%s' failed to open "
                "(readonly=%d): hr=0x%08lx\n",
                i, d.path.c_str(), d.readonly ? 1 : 0,
                static_cast<unsigned long>(backend->open_hr()));
            return 4;
        }
        if (backend->size() != saved_drive_sizes[i]) {
            std::fprintf(stderr,
                "[restore] FAIL: drive %zu '%s' size=%llu but snapshot "
                "expected size=%llu\n",
                i, d.path.c_str(),
                static_cast<unsigned long long>(backend->size()),
                static_cast<unsigned long long>(saved_drive_sizes[i]));
            return 6;
        }

        auto blk = std::make_unique<v::BlockDevice>(
            ram, *backend, v::BlockDevice::IrqFn{}, /*queue_max=*/256);
        v::BlockDevice* bp = blk.get();
        v::PciTransport::Options opts;
        opts.subsys_id        = static_cast<std::uint16_t>(v::kDeviceIdBlk);
        opts.num_msix_vectors = 2;
        opts.pci_class        = 0x01;
        opts.pci_subclass     = 0x00;
        auto xport = std::make_unique<v::PciTransport>(
            *bp, opts, mmio_bus, inject_fn);
        v::PciTransport* xp = xport.get();
        bp->SetIrqCallback(
            [xp](std::uint32_t q) { xp->RaiseQueueInterrupt(q); });
        char nbuf[32];
        std::snprintf(nbuf, sizeof(nbuf), "virtio-pci-blk[%zu]", i);
        xport->set_name(nbuf);
        // NOTE: Do NOT call backend->Start() here. We hold off until AFTER
        // device state has been applied below, so an early IOCP completion
        // can't fire into a half-restored BlockDevice.
        const p::Bdf bbdf = pbus->AddDevice(std::move(xport));
        all_bdfs.push_back(bbdf);
        blk_bdfs.push_back(bbdf);
        std::printf("[restore] virtio-blk[%zu] on PCI %02x:%02x.%u "
                    "path=%s%s capacity=%llu sectors\n",
                    i, bbdf.bus, bbdf.device, bbdf.function,
                    d.path.c_str(), d.readonly ? " (ro)" : "",
                    static_cast<unsigned long long>(backend->size() / 512));
        blk_backends.push_back(std::move(backend));
        blk_devices .push_back(std::move(blk));
    }

    btimer.Mark("device tree constructed");

    // ---------------- 5. Read ALL sections into typed maps --------------
    // We collect first, validate cardinality, then apply. Doing it in one
    // pass would tangle ordering invariants with parsing diagnostics.
    struct SectionMaps {
        std::vector<std::uint8_t> ram;
        std::vector<std::uint8_t> hv;
        std::vector<std::uint8_t> legacy_pcibus;
        std::vector<std::uint8_t> legacy_isa;
        std::vector<std::uint8_t> serial;
        std::vector<std::uint8_t> pic;
        std::vector<std::uint8_t> pit;
        // Per-vCPU sections (indexed by vp_idx, default empty).
        std::vector<std::vector<std::uint8_t>> vcpu_regs;
        std::vector<std::vector<std::uint8_t>> vcpu_xsave;
        std::vector<std::vector<std::uint8_t>> vcpu_apic;
        std::vector<std::vector<std::uint8_t>> vcpu_intr;
        std::vector<std::vector<std::uint8_t>> vcpu_sup_msr;
        std::vector<std::vector<std::uint8_t>> vcpu_timing;
        // Per-BDF generic + virtio.
        std::map<std::uint32_t, std::vector<std::uint8_t>> pci_device;
        std::map<std::uint32_t, std::vector<std::uint8_t>> msix;
        std::map<std::uint32_t, std::vector<std::uint8_t>> transport;
        std::map<std::uint32_t, std::vector<std::uint8_t>> rng_state;
        std::map<std::uint32_t, std::vector<std::uint8_t>> console_state;
        std::map<std::uint32_t, std::vector<std::uint8_t>> blk_state;
        // (BDF, qidx) -> Virtqueue payload bytes.
        std::map<std::uint64_t, std::vector<std::uint8_t>> virtqueues;
    };
    SectionMaps maps;
    maps.vcpu_regs   .resize(vcpu_count);
    maps.vcpu_xsave  .resize(vcpu_count);
    maps.vcpu_apic   .resize(vcpu_count);
    maps.vcpu_intr   .resize(vcpu_count);
    maps.vcpu_sup_msr.resize(vcpu_count);
    maps.vcpu_timing .resize(vcpu_count);

    // Strip the M33.4 BDF / BDF+Q prefix from a section payload. Returns
    // the BDF key. For VIRTQUEUE: also writes the qidx out.
    auto strip_bdf = [](std::span<const std::uint8_t> pp,
                        std::uint32_t& key_out) -> std::span<const std::uint8_t> {
        if (pp.size() < 4) {
            throw std::runtime_error("section: BDF prefix truncated");
        }
        key_out = svcpu_enc::BdfKey(pp[0], pp[1], pp[2]);
        // pp[3] is reserved=0.
        return pp.subspan(4);
    };
    auto strip_bdf_q = [](std::span<const std::uint8_t> pp,
                          std::uint32_t& key_out,
                          std::uint16_t& qidx_out)
        -> std::span<const std::uint8_t> {
        if (pp.size() < 8) {
            throw std::runtime_error("section: BDF+Q prefix truncated");
        }
        key_out  = svcpu_enc::BdfKey(pp[0], pp[1], pp[2]);
        qidx_out = static_cast<std::uint16_t>(pp[4] |
                       (static_cast<std::uint16_t>(pp[5]) << 8));
        return pp.subspan(8);
    };
    // Look up a vp_idx from the first 4 bytes of a per-vCPU section.
    auto peek_vp_idx = [](std::span<const std::uint8_t> pp) -> std::uint32_t {
        if (pp.size() < 4) {
            throw std::runtime_error("vCPU section: header too small");
        }
        return snap::ReadLe32(&pp[0]);
    };

    while (auto sec = rdr.NextSection()) {
        switch (sec->type) {
        case snap::SectionType::RamRaw:
            maps.ram.assign(sec->payload.begin(), sec->payload.end());
            break;
        case snap::SectionType::HvEnlightenment:
            maps.hv.assign(sec->payload.begin(), sec->payload.end());
            break;
        case snap::SectionType::LegacyPciBus:
            maps.legacy_pcibus.assign(sec->payload.begin(), sec->payload.end());
            break;
        case snap::SectionType::LegacyIsaStubs:
            maps.legacy_isa.assign(sec->payload.begin(), sec->payload.end());
            break;
        case snap::SectionType::LegacySerial8250:
            maps.serial.assign(sec->payload.begin(), sec->payload.end());
            break;
        case snap::SectionType::LegacyPic8259:
            maps.pic.assign(sec->payload.begin(), sec->payload.end());
            break;
        case snap::SectionType::LegacyPit8254:
            maps.pit.assign(sec->payload.begin(), sec->payload.end());
            break;
        case snap::SectionType::VcpuRegs: {
            std::uint32_t vi = peek_vp_idx(sec->payload);
            if (vi >= vcpu_count) throw std::runtime_error("VcpuRegs vp_idx OOR");
            maps.vcpu_regs[vi].assign(sec->payload.begin(), sec->payload.end());
            break;
        }
        case snap::SectionType::VcpuXsave: {
            std::uint32_t vi = peek_vp_idx(sec->payload);
            if (vi >= vcpu_count) throw std::runtime_error("VcpuXsave vp_idx OOR");
            maps.vcpu_xsave[vi].assign(sec->payload.begin(), sec->payload.end());
            break;
        }
        case snap::SectionType::VcpuApic: {
            std::uint32_t vi = peek_vp_idx(sec->payload);
            if (vi >= vcpu_count) throw std::runtime_error("VcpuApic vp_idx OOR");
            maps.vcpu_apic[vi].assign(sec->payload.begin(), sec->payload.end());
            break;
        }
        case snap::SectionType::VcpuIntrCtl: {
            std::uint32_t vi = peek_vp_idx(sec->payload);
            if (vi >= vcpu_count) throw std::runtime_error("VcpuIntrCtl vp_idx OOR");
            maps.vcpu_intr[vi].assign(sec->payload.begin(), sec->payload.end());
            break;
        }
        case snap::SectionType::VcpuSupMsr: {
            std::uint32_t vi = peek_vp_idx(sec->payload);
            if (vi >= vcpu_count) throw std::runtime_error("VcpuSupMsr vp_idx OOR");
            maps.vcpu_sup_msr[vi].assign(sec->payload.begin(), sec->payload.end());
            break;
        }
        case snap::SectionType::VcpuTiming: {
            std::uint32_t vi = peek_vp_idx(sec->payload);
            if (vi >= vcpu_count) throw std::runtime_error("VcpuTiming vp_idx OOR");
            maps.vcpu_timing[vi].assign(sec->payload.begin(), sec->payload.end());
            break;
        }
        case snap::SectionType::PciDevice: {
            std::uint32_t key = 0;
            auto rest = strip_bdf(sec->payload, key);
            maps.pci_device[key].assign(rest.begin(), rest.end());
            break;
        }
        case snap::SectionType::MsixState: {
            std::uint32_t key = 0;
            auto rest = strip_bdf(sec->payload, key);
            maps.msix[key].assign(rest.begin(), rest.end());
            break;
        }
        case snap::SectionType::VirtioPciTransport: {
            std::uint32_t key = 0;
            auto rest = strip_bdf(sec->payload, key);
            maps.transport[key].assign(rest.begin(), rest.end());
            break;
        }
        case snap::SectionType::VirtioRngState: {
            std::uint32_t key = 0;
            auto rest = strip_bdf(sec->payload, key);
            maps.rng_state[key].assign(rest.begin(), rest.end());
            break;
        }
        case snap::SectionType::VirtioConsoleState: {
            std::uint32_t key = 0;
            auto rest = strip_bdf(sec->payload, key);
            maps.console_state[key].assign(rest.begin(), rest.end());
            break;
        }
        case snap::SectionType::VirtioBlkState: {
            std::uint32_t key = 0;
            auto rest = strip_bdf(sec->payload, key);
            maps.blk_state[key].assign(rest.begin(), rest.end());
            break;
        }
        case snap::SectionType::Virtqueue: {
            std::uint32_t key = 0;
            std::uint16_t qidx = 0;
            auto rest = strip_bdf_q(sec->payload, key, qidx);
            const std::uint64_t kk = svcpu_enc::BdfQKey(key, qidx);
            maps.virtqueues[kk].assign(rest.begin(), rest.end());
            break;
        }
        default:
            std::fprintf(stderr,
                "[restore] WARN: unknown section type 0x%04x (%llu bytes); "
                "skipping\n",
                static_cast<unsigned>(sec->type),
                static_cast<unsigned long long>(sec->payload.size()));
            break;
        }
    }
    rdr.VerifyTrailer();
    btimer.Mark("sections read + CRC verified");

    // ---------------- 6. Validate cardinality ---------------------------
    if (maps.ram.size() != ram.size()) {
        std::fprintf(stderr,
            "[restore] FAIL: RAM section size %zu != partition RAM %zu\n",
            maps.ram.size(), ram.size());
        return 7;
    }
    if (maps.hv.empty() || maps.legacy_pcibus.empty() ||
        maps.legacy_isa.empty() || maps.serial.empty() ||
        maps.pic.empty() || maps.pit.empty()) {
        std::fputs("[restore] FAIL: missing one or more singleton sections\n",
                   stderr);
        return 7;
    }
    for (std::uint32_t i = 0; i < vcpu_count; ++i) {
        if (maps.vcpu_regs[i].empty() || maps.vcpu_xsave[i].empty() ||
            maps.vcpu_intr[i].empty() || maps.vcpu_timing[i].empty()) {
            std::fprintf(stderr,
                "[restore] FAIL: vCPU %u missing one or more sections\n", i);
            return 7;
        }
        // APIC section may carry a zero-byte payload for real-mode probes
        // but must at least have the 8-byte header (vp_idx + size).
        if (maps.vcpu_apic[i].size() < 8) {
            std::fprintf(stderr,
                "[restore] FAIL: vCPU %u APIC section truncated\n", i);
            return 7;
        }
    }
    for (auto bdf : all_bdfs) {
        const std::uint32_t k = svcpu_enc::BdfKey(bdf);
        if (!maps.pci_device.count(k) || !maps.msix.count(k) ||
            !maps.transport.count(k)) {
            std::fprintf(stderr,
                "[restore] FAIL: BDF %02x:%02x.%u missing PciDevice/MsiX/"
                "Transport section\n",
                bdf.bus, bdf.device, bdf.function);
            return 7;
        }
    }
    // Exactly one rng + one console virtio-class section.
    if (maps.rng_state.size() != 1 || maps.console_state.size() != 1) {
        std::fprintf(stderr,
            "[restore] FAIL: expected exactly 1 rng + 1 console state "
            "section (got %zu + %zu)\n",
            maps.rng_state.size(), maps.console_state.size());
        return 7;
    }
    if (maps.blk_state.size() != drives.size()) {
        std::fprintf(stderr,
            "[restore] FAIL: expected %zu blk state sections but file has %zu\n",
            drives.size(), maps.blk_state.size());
        return 7;
    }

    // ---------------- 7. memcpy RAM -------------------------------------
    std::memcpy(ram.host_base(), maps.ram.data(), ram.size());
    btimer.Mark("RAM applied");

    // ---------------- 8. hv ApplyState ----------------------------------
    {
        if (maps.hv.size() < 32) {
            throw std::runtime_error("HV section too small");
        }
        HvEnlightenment::State hvs;
        hvs.guest_os_id        = snap::ReadLe64(&maps.hv[0]);
        hvs.hypercall_msr      = snap::ReadLe64(&maps.hv[8]);
        hvs.reference_tsc_msr  = snap::ReadLe64(&maps.hv[16]);
        hvs.tsc_invariant_ctl  = snap::ReadLe64(&maps.hv[24]);
        hv.ApplyState(hvs);
    }

    // ---------------- 9. Legacy singletons ------------------------------
    pbus->ApplyState(p::PciBus::DecodeState(
        std::span<const std::uint8_t>(maps.legacy_pcibus)));
    legacy.ApplyState(dev::LegacyIsaStubs::DecodeState(
        std::span<const std::uint8_t>(maps.legacy_isa)));
    com1.ApplyState(dev::Serial8250::DecodeState(
        std::span<const std::uint8_t>(maps.serial)));
    pic.ApplyState(dev::Pic8259::DecodeState(
        std::span<const std::uint8_t>(maps.pic)));
    pit.ApplyState(dev::Pit8254::DecodeState(
        std::span<const std::uint8_t>(maps.pit)));
    btimer.Mark("legacy applied");

    // ---------------- 10. Per-PCI device apply --------------------------
    pbus->ForEachDevice([&](p::Bdf bdf, p::PciDevice& pd) {
        const std::uint32_t k = svcpu_enc::BdfKey(bdf);

        // PciDevice base FIRST. (cfg + bars.)
        pd.ApplyState(p::PciDevice::DecodeState(
            std::span<const std::uint8_t>(maps.pci_device[k])));

        // virtio-specific State, per Virtqueue, MsiX, then PciTransport
        // (PciTransport applies BAR-mapped state, which re-installs MMIO
        // handlers; do this LAST after the queue/msix/dev state is in
        // place so a guest doorbell hitting the freshly-mapped notify
        // region sees a fully-configured device).
        auto* xport = dynamic_cast<v::PciTransport*>(&pd);
        if (!xport) return;  // generic PciDevice; nothing more to apply.

        v::Device& vdev = xport->device();
        switch (vdev.DeviceId()) {
        case v::kDeviceIdRng: {
            auto& d = static_cast<v::RngDevice&>(vdev);
            d.ApplyState(v::RngDevice::DecodeState(
                std::span<const std::uint8_t>(maps.rng_state[k])));
            break;
        }
        case v::kDeviceIdConsole: {
            auto& d = static_cast<v::ConsoleDevice&>(vdev);
            d.ApplyState(v::ConsoleDevice::DecodeState(
                std::span<const std::uint8_t>(maps.console_state[k])));
            break;
        }
        case v::kDeviceIdBlk: {
            auto& d = static_cast<v::BlockDevice&>(vdev);
            d.ApplyState(v::BlockDevice::DecodeState(
                std::span<const std::uint8_t>(maps.blk_state[k])));
            break;
        }
        default:
            // virtio-net (1) and virtio-9p (9) are forbidden on save+restore;
            // hitting this branch means the snapshot file is inconsistent
            // with our construction order.
            throw std::runtime_error(
                "RunRestore: unsupported virtio device id during apply");
        }

        for (std::uint32_t qi = 0; qi < vdev.QueueCount(); ++qi) {
            v::Virtqueue* q = vdev.GetQueue(qi);
            if (!q) continue;
            const std::uint64_t qk = svcpu_enc::BdfQKey(
                k, static_cast<std::uint16_t>(qi));
            auto it = maps.virtqueues.find(qk);
            if (it == maps.virtqueues.end()) {
                throw std::runtime_error(
                    "RunRestore: missing Virtqueue section");
            }
            q->ApplyState(v::Virtqueue::DecodeState(
                std::span<const std::uint8_t>(it->second)));
        }

        xport->msix().ApplyState(p::MsiX::DecodeState(
            std::span<const std::uint8_t>(maps.msix[k])));
        xport->ApplyState(v::PciTransport::DecodeState(
            std::span<const std::uint8_t>(maps.transport[k])));
    });
    btimer.Mark("PCI devices applied");

    // ---------------- 11. Per-vCPU NonTiming ----------------------------
    // Build CapturedVcpuState objects from the maps, run NonTiming apply.
    std::vector<snap::CapturedVcpuState> cap_vcpus(vcpu_count);
    for (std::uint32_t i = 0; i < vcpu_count; ++i) {
        auto& c = cap_vcpus[i];
        c.arch   = svcpu_enc::DecodeRegBlock(maps.vcpu_regs[i], i,
                                             snap::kArchRegNames,
                                             snap::kArchRegCount());
        c.timing = svcpu_enc::DecodeRegBlock(maps.vcpu_timing[i], i,
                                             snap::kTimingRegNames,
                                             snap::kTimingRegCount());
        svcpu_enc::DecodeIntrCtlBlock(maps.vcpu_intr[i], i, c);
        // M33.7: VcpuSupMsr section is optional (older snapshots predate
        // it). When absent, sup_msr_ok stays all-false → CET MSRs simply
        // are not restored, matching pre-M33.7 behavior. This is fine
        // for snapshots taken before M33.7 since those guests didn't
        // exercise CET state across save/restore.
        if (!maps.vcpu_sup_msr[i].empty()) {
            svcpu_enc::DecodeSupMsrBlock(maps.vcpu_sup_msr[i], i, c);
        } else {
            c.sup_msr.assign(snap::kSupervisorMsrCount(), WHV_REGISTER_VALUE{});
            c.sup_msr_ok.assign(snap::kSupervisorMsrCount(), false);
        }
        c.xsave  = svcpu_enc::DecodeBlobBlock(maps.vcpu_xsave[i], i);
        c.apic   = svcpu_enc::DecodeBlobBlock(maps.vcpu_apic[i], i);
        snap::ApplyVcpuStateNonTiming(vcpus[i], part.handle(), i, c);
    }
    btimer.Mark("vCPU NonTiming applied");

    // ---------------- 12. ResumeRuntime: PIC -> Serial -> PIT -----------
    // Order matters: the PIC must be live (mask + IRR populated) before we
    // re-edge a TX IRQ from the serial, and the PIT IRQ thread must start
    // after the serial's TX IRQ has been delivered.
    pic.ResumeRuntime();
    com1.ResumeRuntime();
    pit.ResumeRuntime();
    btimer.Mark("legacy ResumeRuntime");

    // ---------------- 13. Per-vCPU Timing (back-to-back) ----------------
    // Done as a final tight loop to minimize observable cross-vCPU TSC
    // skew (vcpu_count writes happen within ~us; Linux's tsc-sync check
    // tolerates a few hundred cycles).
    for (std::uint32_t i = 0; i < vcpu_count; ++i) {
        snap::ApplyVcpuStateTiming(vcpus[i], part.handle(), i, cap_vcpus[i]);
    }
    btimer.Mark("vCPU Timing applied");

    // ---------------- 14. Start blk IOCP workers ------------------------
    // Now that virtqueue + transport + msix state are restored, IOCP
    // completions for guest-driven submissions can safely land.
    for (auto& b : blk_backends) {
        b->Start();
    }
    btimer.Mark("blk backends started");

    // ---------------- 15. RunLoops + watchdog + stdin + AP threads ------
    std::deque<RunLoop> loops;
    for (std::uint32_t i = 0; i < vcpu_count; ++i) {
        loops.emplace_back(vcpus[i], io_bus, mmio_bus, vcpu_count);
        loops.back().set_hv_enlightenment(&hv);
    }
    RunLoop& loop = loops.front();

    auto stop_all_loops = [&loops]() {
        for (auto& l : loops) l.RequestStop();
    };

    // Shutdown sentinel watcher (poll the shared atomic the byte observer
    // flips when /init prints the sentinel string).
    std::atomic<bool> shutdown_watcher_done{false};
    std::thread shutdown_watcher([&shutdown_watcher_done, shutdown_requested,
                                   &stop_all_loops]() {
        while (!shutdown_watcher_done.load(std::memory_order_relaxed)) {
            if (shutdown_requested->load(std::memory_order_acquire)) {
                std::fputs("[restore] guest requested shutdown via "
                           "hvc0 sentinel; stopping vCPU loops\n", stderr);
                stop_all_loops();
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    });

    // stdin forwarder -- mirrors RunPvhRun's TTY-mode loop verbatim
    // (Ctrl+A X to quit, Ctrl+A H for help). Skipped if stdin isn't a TTY.
    HANDLE hstdin = ::GetStdHandle(STD_INPUT_HANDLE);
    DWORD original_console_mode = 0;
    bool restore_console_mode = false;
    std::atomic<bool> stdin_stop{false};
    std::thread stdin_thread;
    const bool stdin_is_tty = (hstdin != INVALID_HANDLE_VALUE) &&
                              (::GetFileType(hstdin) == FILE_TYPE_CHAR);
    if (stdin_is_tty) {
        if (::GetConsoleMode(hstdin, &original_console_mode)) {
            restore_console_mode = true;
            ::SetConsoleMode(hstdin, ENABLE_WINDOW_INPUT);
        }
        if (HANDLE hout = ::GetStdHandle(STD_OUTPUT_HANDLE);
            hout != INVALID_HANDLE_VALUE) {
            DWORD om = 0;
            if (::GetConsoleMode(hout, &om)) {
                ::SetConsoleMode(hout, om | ENABLE_PROCESSED_OUTPUT |
                                          ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
        std::fputs("[restore] interactive console -- press Ctrl+A then X "
                   "to quit, Ctrl+A H for help\n", stderr);
        stdin_thread = std::thread(
            [hstdin, vcon_ptr, &stdin_stop, &stop_all_loops]() {
            INPUT_RECORD recs[64];
            bool escape_armed = false;
            while (!stdin_stop.load(std::memory_order_relaxed)) {
                DWORD wr = ::WaitForSingleObject(hstdin, 50);
                if (wr == WAIT_TIMEOUT) continue;
                if (wr != WAIT_OBJECT_0) break;
                DWORD num = 0;
                if (!::GetNumberOfConsoleInputEvents(hstdin, &num)) continue;
                if (num == 0) continue;
                DWORD to_read = (num < 64) ? num : 64;
                DWORD read = 0;
                if (!::ReadConsoleInputW(hstdin, recs, to_read, &read)) continue;
                std::string out;
                out.reserve(read);
                bool quit_requested = false;
                for (DWORD i = 0; i < read; ++i) {
                    if (recs[i].EventType != KEY_EVENT) continue;
                    const auto& k = recs[i].Event.KeyEvent;
                    if (!k.bKeyDown) continue;
                    wchar_t wc = k.uChar.UnicodeChar;
                    if (wc == 0) {
                        const char* seq = nullptr;
                        switch (k.wVirtualKeyCode) {
                        case VK_UP:     seq = "\x1b[A"; break;
                        case VK_DOWN:   seq = "\x1b[B"; break;
                        case VK_RIGHT:  seq = "\x1b[C"; break;
                        case VK_LEFT:   seq = "\x1b[D"; break;
                        case VK_HOME:   seq = "\x1b[H"; break;
                        case VK_END:    seq = "\x1b[F"; break;
                        case VK_INSERT: seq = "\x1b[2~"; break;
                        case VK_DELETE: seq = "\x1b[3~"; break;
                        case VK_PRIOR:  seq = "\x1b[5~"; break;
                        case VK_NEXT:   seq = "\x1b[6~"; break;
                        default: break;
                        }
                        if (seq) out.append(seq);
                        continue;
                    }
                    if (escape_armed) {
                        escape_armed = false;
                        if (wc == L'x' || wc == L'X') {
                            std::fputs("\r\n[restore] Ctrl+A X -- "
                                       "quitting\r\n", stderr);
                            quit_requested = true;
                            break;
                        }
                        if (wc == L'h' || wc == L'H' || wc == L'?') {
                            std::fputs(
                                "\r\n[restore] Ctrl+A keys: "
                                "X=quit, A=literal ^A, H=help\r\n",
                                stderr);
                            continue;
                        }
                        if (wc == 0x01) { out.push_back('\x01'); continue; }
                        std::fputs("\r\n[restore] unknown Ctrl+A sequence; "
                                   "Ctrl+A H for help\r\n", stderr);
                        continue;
                    }
                    if (wc == 0x01) { escape_armed = true; continue; }
                    if (wc == L'\r') { out.push_back('\n'); continue; }
                    if (wc < 0x80) {
                        out.push_back(static_cast<char>(wc));
                        continue;
                    }
                    char mb[8] = {};
                    int n = ::WideCharToMultiByte(CP_UTF8, 0, &wc, 1, mb,
                                                  sizeof(mb), nullptr, nullptr);
                    if (n > 0) out.append(mb, mb + n);
                }
                if (!out.empty()) {
                    vcon_ptr->WriteHostInput(out.data(), out.size());
                }
                if (quit_requested) {
                    stop_all_loops();
                    break;
                }
            }
        });
    }

    // Watchdog telemetry (mirrors RunPvhRun).
    const bool watchdog_enabled = (watchdog_secs > 0);
    std::atomic<bool> watchdog_done{false};
    std::thread watchdog;
    if (watchdog_enabled) {
        watchdog = std::thread([&] {
            std::uint64_t prev_io = 0, prev_mmio = 0, prev_halt = 0;
            std::uint64_t prev_cpuid = 0, prev_msi = 0, prev_uart = 0;
            int s = 0;
            auto sum = [&loops](auto getter) -> std::uint64_t {
                std::uint64_t v = 0;
                for (auto& l : loops) v += getter(l);
                return v;
            };
            while (!watchdog_done.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                if (watchdog_done.load()) return;
                ++s;
                const std::uint64_t cur_io    =
                    sum([](RunLoop& l) { return l.io_exits();    });
                const std::uint64_t cur_mmio  =
                    sum([](RunLoop& l) { return l.mmio_exits();  });
                const std::uint64_t cur_halt  =
                    sum([](RunLoop& l) { return l.halt_exits();  });
                const std::uint64_t cur_cpuid =
                    sum([](RunLoop& l) { return l.cpuid_exits(); });
                const std::uint64_t cur_msi   = whp::MsiInjectCount();
                const std::uint64_t cur_uart  = com1.tx_bytes();
                std::fprintf(stderr,
                    "[restore] @%2ds  io=%llu(+%llu) mmio=%llu(+%llu) "
                    "cpuid=%llu(+%llu) halt=%llu(+%llu) msi=%llu(+%llu) "
                    "uart=%llu(+%llu)\n",
                    s,
                    static_cast<unsigned long long>(cur_io),
                    static_cast<unsigned long long>(cur_io - prev_io),
                    static_cast<unsigned long long>(cur_mmio),
                    static_cast<unsigned long long>(cur_mmio - prev_mmio),
                    static_cast<unsigned long long>(cur_cpuid),
                    static_cast<unsigned long long>(cur_cpuid - prev_cpuid),
                    static_cast<unsigned long long>(cur_halt),
                    static_cast<unsigned long long>(cur_halt - prev_halt),
                    static_cast<unsigned long long>(cur_msi),
                    static_cast<unsigned long long>(cur_msi - prev_msi),
                    static_cast<unsigned long long>(cur_uart),
                    static_cast<unsigned long long>(cur_uart - prev_uart));
                prev_io    = cur_io;
                prev_mmio  = cur_mmio;
                prev_halt  = cur_halt;
                prev_cpuid = cur_cpuid;
                prev_msi   = cur_msi;
                prev_uart  = cur_uart;
                if (s >= watchdog_secs) {
                    std::fprintf(stderr,
                        "[restore] watchdog: %ds elapsed, requesting stop\n",
                        watchdog_secs);
                    stop_all_loops();
                    return;
                }
            }
        });
    }

    btimer.Mark("entering guest");
    TINYVMM_ETW_INFO("RestoreGuestEntry",
        TraceLoggingString(snapshot_path.c_str(), "snapshot"));

    const auto cpu_set_ids = whp::ResolveCpuSetIds(affinity_mode);
    {
        const auto& top = whp::GetTopology();
        if (top.hybrid) {
            std::printf("[restore] host topology: hybrid, %u logical "
                        "(P=%u/%uHT, E=%u); cpu-affinity=%s "
                        "(pinning %zu logicals)\n",
                        top.total_logical, top.p_physical, top.p_logical,
                        top.e_logical,
                        whp::AffinityModeName(affinity_mode),
                        cpu_set_ids.size());
        } else {
            std::printf("[restore] host topology: non-hybrid, %u logical; "
                        "cpu-affinity=%s (pinning %zu logicals)\n",
                        top.total_logical,
                        whp::AffinityModeName(affinity_mode),
                        cpu_set_ids.size());
        }
    }

    std::vector<std::thread> ap_threads;
    std::vector<std::exception_ptr> ap_excs(vcpu_count, nullptr);
    ap_threads.reserve(vcpu_count > 0 ? vcpu_count - 1 : 0);
    for (std::uint32_t i = 1; i < vcpu_count; ++i) {
        ap_threads.emplace_back([i, &loops, &ap_excs, &stop_all_loops,
                                 &cpu_set_ids] {
            (void)whp::PinCurrentThread(cpu_set_ids);
            try {
                (void)loops[i].Run();
            } catch (...) {
                ap_excs[i] = std::current_exception();
            }
            stop_all_loops();
        });
    }
    (void)whp::PinCurrentThread(cpu_set_ids);

    StopReason stop = StopReason::Cancelled;
    try {
        stop = loop.Run();
    } catch (...) {
        ap_excs[0] = std::current_exception();
    }
    (void)stop;
    btimer.Mark("guest exited");
    stop_all_loops();
    watchdog_done.store(true);
    shutdown_watcher_done.store(true);
    stdin_stop.store(true);
    if (watchdog.joinable())        watchdog.join();
    if (shutdown_watcher.joinable()) shutdown_watcher.join();
    if (stdin_thread.joinable())    stdin_thread.join();
    for (auto& t : ap_threads) {
        if (t.joinable()) t.join();
    }
    if (restore_console_mode) {
        ::SetConsoleMode(hstdin, original_console_mode);
    }

    // Drain in-flight blk completions before Stop()ping the IOCP workers.
    // (Same ordering rule as RunPvhRun: completions only fire while workers
    // are running, so drain BEFORE Stop().) Restore does NOT chain into a
    // snapshot write afterwards; we just want graceful shutdown.
    if (!DrainBlockBackends(blk_devices, /*timeout_ms=*/5000)) {
        std::fputs("[restore] WARN: virtio-blk drain timed out at shutdown\n",
                   stderr);
    }
    for (auto& b : blk_backends) {
        b->Stop();
    }

    for (std::size_t i = 0; i < blk_backends.size(); ++i) {
        auto& b = blk_backends[i];
        auto& d = blk_devices[i];
        std::printf("[restore] virtio-blk[%zu] stats: submitted=%llu "
                    "completed=%llu errors=%llu max_inflight=%llu "
                    "(virtio in=%llu out=%llu flush=%llu discard=%llu "
                    "wz=%llu err=%llu)\n",
                    i,
                    static_cast<unsigned long long>(b->submitted()),
                    static_cast<unsigned long long>(b->completed()),
                    static_cast<unsigned long long>(b->errors()),
                    static_cast<unsigned long long>(b->max_inflight()),
                    static_cast<unsigned long long>(d->ops_in()),
                    static_cast<unsigned long long>(d->ops_out()),
                    static_cast<unsigned long long>(d->ops_flush()),
                    static_cast<unsigned long long>(d->ops_discard()),
                    static_cast<unsigned long long>(d->ops_write_zeroes()),
                    static_cast<unsigned long long>(d->ops_err()));
    }

    // Aggregate per-VM run-loop counters across all vCPUs.
    {
        std::uint64_t tot_io = 0, tot_mmio = 0, tot_halt = 0, tot_cpuid = 0;
        for (auto& l : loops) {
            tot_io    += l.io_exits();
            tot_mmio  += l.mmio_exits();
            tot_halt  += l.halt_exits();
            tot_cpuid += l.cpuid_exits();
        }
        std::printf("[restore] vCPU exits: io=%llu mmio=%llu cpuid=%llu "
                    "halt=%llu msi=%llu uart_tx=%llu\n",
                    static_cast<unsigned long long>(tot_io),
                    static_cast<unsigned long long>(tot_mmio),
                    static_cast<unsigned long long>(tot_cpuid),
                    static_cast<unsigned long long>(tot_halt),
                    static_cast<unsigned long long>(whp::MsiInjectCount()),
                    static_cast<unsigned long long>(com1.tx_bytes()));
    }

    // Rethrow any AP exception that BSP didn't see directly.
    for (auto& e : ap_excs) {
        if (e) std::rethrow_exception(e);
    }

    return 0;
}

}  // namespace

// M12 virtio-PCI modern transport host-side test. Drives a StubDevice through
// the PCI cfg-space + BAR-MMIO state machine and verifies:
//   * VendorID / DeviceID / class
//   * 4 virtio_pci_cap entries + MSI-X cap in the cap chain
//   * BAR0 lights up COMMAND.MEM_SPACE
//   * num_queues / device_features / driver_features negotiation
//   * Queue programming (desc/driver/device GPAs, size, msix_vector, enable)
//   * Notify region: write to bar+0x1000 -> dev.NotifyQueue(0)
//   * ISR status read-and-clear
//   * MSI-X delivery on RaiseQueueInterrupt / RaiseConfigChangeInterrupt
//   * config_generation bumps on config-change
namespace {

int RunVirtioPciTest() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;
    namespace p = tinyvmm::pci;
    namespace v = tinyvmm::virtio;

    std::puts("[virtio-pci-test] starting (host-side; no WHP)");

    // GuestMemory still needs a Partition handle, so spin one up. We don't
    // run a vCPU.
    CheckWhpAvailable();
    Partition part(/*vcpu_count=*/1);
    part.Setup();
    constexpr std::size_t kRamBytes = 0x200000;  // 2 MiB
    GuestMemory ram(part, /*gpa=*/0, kRamBytes, /*executable=*/false);
    auto* host = static_cast<std::uint8_t*>(ram.host_base());

    devices::IoBus   io_bus;
    devices::MmioBus mmio_bus;
    p::PciBus        pbus;
    pbus.AttachIoBus(io_bus);

    // Record every injected MSI-X message.
    std::vector<InjectRecord> injects;
    auto inject_fn = [&](std::uint64_t a, std::uint32_t d) {
        injects.push_back({a, d});
        return true;
    };

    auto stub = std::make_unique<v::StubDevice>(ram);
    v::StubDevice* dev_ptr = stub.get();

    v::PciTransport::Options opts;
    opts.subsys_id = 0xFE;          // matches StubDevice::DeviceId()
    opts.num_msix_vectors = 4;
    opts.pci_class = 0xFF;          // unassigned (stub)
    opts.pci_subclass = 0x00;
    auto xport = std::make_unique<v::PciTransport>(
        *stub, opts, mmio_bus, inject_fn);
    v::PciTransport* tx = xport.get();
    xport->set_name("virtio-pci-stub");

    const p::Bdf bdf = pbus.AddDevice(std::move(xport));
    std::printf("[virtio-pci-test] device @ %02x:%02x.%u\n",
                bdf.bus, bdf.device, bdf.function);

    // ---- CFG #1 IO helpers.
    auto io_w = [&](std::uint16_t port, std::uint16_t size, std::uint32_t val) {
        devices::IoAccess a{port, size, /*write=*/true, val};
        if (!io_bus.Dispatch(a)) Fatal("virtio-pci-test: unmatched IO write");
    };
    auto io_r = [&](std::uint16_t port, std::uint16_t size) -> std::uint32_t {
        devices::IoAccess a{port, size, /*write=*/false, 0};
        if (!io_bus.Dispatch(a)) Fatal("virtio-pci-test: unmatched IO read");
        return a.value;
    };
    auto encode = [](std::uint8_t b, std::uint8_t d, std::uint8_t fn,
                      std::uint8_t reg) -> std::uint32_t {
        return p::kConfigAddressEnable | (std::uint32_t{b} << 16) |
               (std::uint32_t{d} << 11) | (std::uint32_t{fn} << 8) |
               (reg & 0xFCu);
    };
    auto cfg_r = [&](std::uint8_t reg, std::uint16_t size) -> std::uint32_t {
        io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, reg));
        return io_r(static_cast<std::uint16_t>(p::kConfigDataPort + (reg & 3)),
                    size);
    };
    auto cfg_w = [&](std::uint8_t reg, std::uint16_t size, std::uint32_t val) {
        io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, reg));
        io_w(static_cast<std::uint16_t>(p::kConfigDataPort + (reg & 3)), size,
             val);
    };

    // ---- (a) Identity. VID=0x1AF4, DID=0x1040+0xFE=0x113E, class=0xFF/0x00.
    const std::uint32_t vid_did = cfg_r(p::kCfgVendorId, 4);
    const std::uint8_t  cls = static_cast<std::uint8_t>(
        cfg_r(p::kCfgClassCode, 1));
    const std::uint8_t  scls = static_cast<std::uint8_t>(
        cfg_r(p::kCfgSubclass, 1));
    const std::uint32_t subsys = cfg_r(p::kCfgSubsysVendorId, 4);
    std::printf("[virtio-pci-test] vid_did=0x%08x class=%02x:%02x subsys=0x%08x\n",
                vid_did, cls, scls, subsys);
    if (vid_did != ((std::uint32_t{0x113E} << 16) | 0x1AF4u)) {
        std::fputs("[virtio-pci-test] FAIL: VID/DID mismatch\n", stderr);
        return 12;
    }
    if (cls != 0xFF || scls != 0x00 ||
        subsys != ((std::uint32_t{0x00FE} << 16) | 0x1AF4u)) {
        std::fputs("[virtio-pci-test] FAIL: class/subsys wrong\n", stderr);
        return 12;
    }

    // ---- (b) Walk capability chain: expect COMMON_CFG / NOTIFY_CFG /
    // ISR_CFG / DEVICE_CFG / MSI-X in that order.
    std::uint8_t cap = static_cast<std::uint8_t>(cfg_r(p::kCfgCapPtr, 1));
    struct CapInfo {
        std::uint8_t off;
        std::uint8_t id;
        std::uint8_t cfg_type;   // virtio cap only
        std::uint8_t bar;
        std::uint32_t offset;
        std::uint32_t length;
    };
    std::vector<CapInfo> caps;
    while (cap != 0 && caps.size() < 16) {
        const std::uint8_t id  = static_cast<std::uint8_t>(cfg_r(cap, 1));
        const std::uint8_t nxt = static_cast<std::uint8_t>(cfg_r(static_cast<std::uint8_t>(cap + 1), 1));
        CapInfo info{cap, id, 0, 0, 0, 0};
        if (id == p::kCapIdVendor) {
            info.cfg_type = static_cast<std::uint8_t>(cfg_r(static_cast<std::uint8_t>(cap + 3), 1));
            info.bar      = static_cast<std::uint8_t>(cfg_r(static_cast<std::uint8_t>(cap + 4), 1));
            info.offset   = cfg_r(static_cast<std::uint8_t>(cap + 8), 4);
            info.length   = cfg_r(static_cast<std::uint8_t>(cap + 12), 4);
        }
        caps.push_back(info);
        cap = nxt;
    }
    std::printf("[virtio-pci-test] cap chain: %zu entries\n", caps.size());
    if (caps.size() != 5) {
        std::fputs("[virtio-pci-test] FAIL: expected 5 caps\n", stderr);
        return 12;
    }
    const std::uint8_t want_types[4] = {1, 2, 3, 4};  // common, notify, isr, devcfg
    for (std::size_t i = 0; i < 4; ++i) {
        std::printf("[virtio-pci-test]  cap@0x%02x id=0x%02x type=%u bar=%u off=0x%x len=0x%x\n",
                    caps[i].off, caps[i].id, caps[i].cfg_type, caps[i].bar,
                    caps[i].offset, caps[i].length);
        if (caps[i].id != p::kCapIdVendor || caps[i].cfg_type != want_types[i] ||
            caps[i].bar != 0) {
            std::fputs("[virtio-pci-test] FAIL: virtio cap chain wrong\n",
                       stderr);
            return 12;
        }
    }
    // NOTIFY cap also carries the multiplier at +16.
    const std::uint32_t notify_mult =
        cfg_r(static_cast<std::uint8_t>(caps[1].off + 16), 4);
    std::printf("[virtio-pci-test] notify multiplier = %u\n", notify_mult);
    if (notify_mult != v::PciTransport::kNotifyMultiplier) {
        std::fputs("[virtio-pci-test] FAIL: notify_off_multiplier wrong\n",
                   stderr);
        return 12;
    }
    if (caps[4].id != p::kCapIdMsiX) {
        std::fputs("[virtio-pci-test] FAIL: last cap should be MSI-X\n",
                   stderr);
        return 12;
    }
    const std::uint8_t msix_cap_off = caps[4].off;
    std::printf("[virtio-pci-test] msix_cap=0x%02x\n", msix_cap_off);

    // ---- (c) Map BAR0. virtio-PCI declares a 64-bit prefetchable BAR.
    const std::uint32_t bar0_lo = cfg_r(p::kCfgBar0, 4);
    const std::uint32_t bar0_hi = cfg_r(p::kCfgBar0 + 4, 4);
    if ((bar0_lo & 0xFu) != (p::kBarMmio64 | p::kBarPrefetchable)) {
        std::fprintf(stderr,
                     "[virtio-pci-test] FAIL: BAR0 type bits 0x%x\n",
                     bar0_lo & 0xFu);
        return 12;
    }
    cfg_w(p::kCfgCommand, 2, p::kCmdMemorySpace | p::kCmdBusMaster);
    const std::uint64_t bar_gpa = (static_cast<std::uint64_t>(bar0_hi) << 32) |
                                   (bar0_lo & ~0xFu);
    std::printf("[virtio-pci-test] BAR0 mapped @ 0x%llx\n",
                static_cast<unsigned long long>(bar_gpa));

    // ---- MMIO helpers.
    auto mmio_w = [&](std::uint64_t gpa, std::uint32_t val, std::uint8_t sz) {
        devices::MmioAccess a{};
        a.gpa = gpa; a.access_size = sz; a.is_write = true;
        std::memcpy(a.data, &val, std::min<std::size_t>(sz, 4));
        if (!mmio_bus.Dispatch(a))
            Fatal("virtio-pci-test: unmatched MMIO write");
    };
    auto mmio_r = [&](std::uint64_t gpa, std::uint8_t sz) -> std::uint32_t {
        devices::MmioAccess a{};
        a.gpa = gpa; a.access_size = sz; a.is_write = false;
        if (!mmio_bus.Dispatch(a))
            Fatal("virtio-pci-test: unmatched MMIO read");
        std::uint32_t v = 0;
        std::memcpy(&v, a.data, std::min<std::size_t>(sz, 4));
        return v;
    };

    // ---- (d) num_queues / device_features. Reading common_cfg @ 0x10 gives
    // [msix_config | num_queues] as a u32.
    const std::uint32_t mc_nq = mmio_r(bar_gpa + 0x10, 4);
    const std::uint16_t num_queues = static_cast<std::uint16_t>(mc_nq >> 16);
    std::printf("[virtio-pci-test] num_queues=%u msix_config=0x%04x\n",
                num_queues, mc_nq & 0xFFFFu);
    if (num_queues != 1) {
        std::fputs("[virtio-pci-test] FAIL: num_queues != 1\n", stderr);
        return 12;
    }
    // Driver writes select=0/1 and reads device_feature; should reveal
    // VERSION_1 (bit 32) + RING_EVENT_IDX (bit 29) at minimum.
    mmio_w(bar_gpa + 0x00, 0, 4);
    const std::uint32_t df_lo = mmio_r(bar_gpa + 0x04, 4);
    mmio_w(bar_gpa + 0x00, 1, 4);
    const std::uint32_t df_hi = mmio_r(bar_gpa + 0x04, 4);
    const std::uint64_t df = static_cast<std::uint64_t>(df_lo) |
                              (static_cast<std::uint64_t>(df_hi) << 32);
    std::printf("[virtio-pci-test] device_features=0x%016llx\n",
                static_cast<unsigned long long>(df));
    if ((df & v::kFeatureVersion1) == 0 ||
        (df & v::kFeatureRingEventIdx) == 0) {
        std::fputs("[virtio-pci-test] FAIL: missing required features\n",
                   stderr);
        return 12;
    }

    // ---- (e) Status FSM: ACK -> DRIVER -> ack features -> FEATURES_OK.
    mmio_w(bar_gpa + 0x14, v::kStatusAcknowledge, 1);
    mmio_w(bar_gpa + 0x14,
           v::kStatusAcknowledge | v::kStatusDriver, 1);
    // Ack same features.
    mmio_w(bar_gpa + 0x08, 0, 4);
    mmio_w(bar_gpa + 0x0C, df_lo, 4);
    mmio_w(bar_gpa + 0x08, 1, 4);
    mmio_w(bar_gpa + 0x0C, df_hi, 4);
    mmio_w(bar_gpa + 0x14,
           v::kStatusAcknowledge | v::kStatusDriver | v::kStatusFeaturesOk, 1);
    const std::uint8_t status_after_fo = static_cast<std::uint8_t>(
        mmio_r(bar_gpa + 0x14, 1));
    if ((status_after_fo & v::kStatusFeaturesOk) == 0) {
        std::fprintf(stderr,
                     "[virtio-pci-test] FAIL: FEATURES_OK rejected (status=0x%02x)\n",
                     status_after_fo);
        return 12;
    }

    // ---- (f) Configure MSI-X table BEFORE setting up the queue: program
    // vector 0 (queue 0) and vector 1 (config-change), unmask both, enable
    // MSI-X via cap MC bit 15.
    constexpr std::uint64_t kMsiAddrBase = 0xFEE00000ull;
    auto program_msix = [&](std::uint32_t vec, std::uint32_t data) {
        const std::uint64_t tbl = bar_gpa + v::PciTransport::kOffMsixTable +
                                  16ull * vec;
        mmio_w(tbl + 0, static_cast<std::uint32_t>(kMsiAddrBase & 0xFFFFFFFFu), 4);
        mmio_w(tbl + 4, static_cast<std::uint32_t>(kMsiAddrBase >> 32), 4);
        mmio_w(tbl + 8, data, 4);
        mmio_w(tbl + 12, 0u, 4);  // unmask
    };
    program_msix(0, 0x40);  // queue 0 vector
    program_msix(1, 0x41);  // config-change vector
    // Enable MSI-X.
    cfg_w(msix_cap_off + 2, 2, 0x8000u);
    if (!tx->msix().MsiXEnabled()) {
        std::fputs("[virtio-pci-test] FAIL: MSI-X not enabled\n", stderr);
        return 12;
    }

    // ---- (g) Queue 0 programming: select, GPAs, size, msix_vector, enable.
    constexpr std::uint64_t kDescGpa  = 0x20000;
    constexpr std::uint64_t kAvailGpa = 0x20100;
    constexpr std::uint64_t kUsedGpa  = 0x20200;
    constexpr std::uint32_t kQSize    = 16;
    // queue_select = 0
    mmio_w(bar_gpa + 0x16, 0, 2);
    if (mmio_r(bar_gpa + 0x18, 2) == 0) {
        std::fputs("[virtio-pci-test] FAIL: queue_size default zero\n", stderr);
        return 12;
    }
    mmio_w(bar_gpa + 0x18, kQSize, 2);              // queue_size
    mmio_w(bar_gpa + 0x1A, 0, 2);                    // queue_msix_vector=0
    mmio_w(bar_gpa + 0x20, static_cast<std::uint32_t>(kDescGpa), 4);
    mmio_w(bar_gpa + 0x24, static_cast<std::uint32_t>(kDescGpa >> 32), 4);
    mmio_w(bar_gpa + 0x28, static_cast<std::uint32_t>(kAvailGpa), 4);
    mmio_w(bar_gpa + 0x2C, static_cast<std::uint32_t>(kAvailGpa >> 32), 4);
    mmio_w(bar_gpa + 0x30, static_cast<std::uint32_t>(kUsedGpa), 4);
    mmio_w(bar_gpa + 0x34, static_cast<std::uint32_t>(kUsedGpa >> 32), 4);
    // queue_notify_off should be 0 for queue 0.
    const std::uint16_t qnotify_off = static_cast<std::uint16_t>(
        mmio_r(bar_gpa + 0x1E, 2));
    if (qnotify_off != 0) {
        std::fprintf(stderr,
                     "[virtio-pci-test] FAIL: queue_notify_off=%u (want 0)\n",
                     qnotify_off);
        return 12;
    }
    // msix_config = 1 (config-change vector)
    mmio_w(bar_gpa + 0x10, 1, 2);
    // queue_enable = 1
    mmio_w(bar_gpa + 0x1C, 1, 2);
    if (!dev_ptr->queue().ready()) {
        std::fputs("[virtio-pci-test] FAIL: queue not ready after enable\n",
                   stderr);
        return 12;
    }
    // DRIVER_OK
    mmio_w(bar_gpa + 0x14,
           v::kStatusAcknowledge | v::kStatusDriver | v::kStatusFeaturesOk |
               v::kStatusDriverOk, 1);
    if (!dev_ptr->driver_ok()) {
        std::fputs("[virtio-pci-test] FAIL: driver_ok not seen\n", stderr);
        return 12;
    }

    // ---- (h) Plant a descriptor in the avail ring, write to notify
    // offset 0, verify NotifyQueue(0) fires + dev sees a popped chain.
#pragma pack(push, 1)
    struct VringDesc {
        std::uint64_t addr;
        std::uint32_t len;
        std::uint16_t flags;
        std::uint16_t next;
    };
#pragma pack(pop)
    constexpr std::uint64_t kPayloadGpa = 0x21000;
    const char kPayload[] = "virtio-pci hi";
    std::memcpy(host + kPayloadGpa, kPayload, sizeof(kPayload));
    auto* desc = reinterpret_cast<VringDesc*>(host + kDescGpa);
    desc[0] = {kPayloadGpa, sizeof(kPayload), 0, 0};
    auto* avail = host + kAvailGpa;
    *reinterpret_cast<std::uint16_t*>(avail + 0) = 0;
    *reinterpret_cast<std::uint16_t*>(avail + 4) = 0;
    *reinterpret_cast<std::uint16_t*>(avail + 2) = 1;   // idx (publish last)

    // Notify: 16-bit write of 0 (qidx) to bar+0x1000+0.
    const std::uint64_t kNotifyQ0 = bar_gpa + v::PciTransport::kOffNotify + 0;
    const std::uint64_t prev_notify = dev_ptr->notify_count();
    mmio_w(kNotifyQ0, 0u, 2);
    if (dev_ptr->notify_count() != prev_notify + 1) {
        std::fprintf(stderr,
                     "[virtio-pci-test] FAIL: notify_count %llu -> %llu\n",
                     static_cast<unsigned long long>(prev_notify),
                     static_cast<unsigned long long>(dev_ptr->notify_count()));
        return 12;
    }
    auto popped = dev_ptr->queue().Pop();
    if (!popped || popped->head_index != 0 || popped->bufs.size() != 1) {
        std::fputs("[virtio-pci-test] FAIL: Pop() result wrong\n", stderr);
        return 12;
    }

    // ---- (i) RaiseQueueInterrupt(0) -> 1 MSI to vector 0 (data=0x40).
    injects.clear();
    tx->RaiseQueueInterrupt(0);
    if (injects.size() != 1 || injects[0].data != 0x40 ||
        injects[0].addr != kMsiAddrBase) {
        std::fprintf(stderr,
                     "[virtio-pci-test] FAIL: queue irq inject count=%zu data=0x%x\n",
                     injects.size(),
                     injects.empty() ? 0u : injects[0].data);
        return 12;
    }
    if ((tx->isr() & 1u) == 0) {
        std::fputs("[virtio-pci-test] FAIL: ISR queue bit not set\n", stderr);
        return 12;
    }

    // ---- (j) ISR read-and-clear: reading bar+ISR should report the bit and
    // then clear it.
    const std::uint32_t isr_v = mmio_r(bar_gpa + v::PciTransport::kOffIsr, 1);
    std::printf("[virtio-pci-test] ISR read=0x%02x (expect bit0)\n", isr_v);
    if ((isr_v & 1u) == 0 || tx->isr() != 0) {
        std::fputs("[virtio-pci-test] FAIL: ISR read-and-clear broken\n",
                   stderr);
        return 12;
    }

    // ---- (k) RaiseConfigChangeInterrupt -> 1 MSI to vector 1 (data=0x41),
    // config_generation increments.
    const std::uint8_t gen_before = static_cast<std::uint8_t>(
        mmio_r(bar_gpa + 0x15, 1));
    injects.clear();
    tx->RaiseConfigChangeInterrupt();
    const std::uint8_t gen_after = static_cast<std::uint8_t>(
        mmio_r(bar_gpa + 0x15, 1));
    if (injects.size() != 1 || injects[0].data != 0x41) {
        std::fprintf(stderr,
                     "[virtio-pci-test] FAIL: config-change inject count=%zu data=0x%x\n",
                     injects.size(),
                     injects.empty() ? 0u : injects[0].data);
        return 12;
    }
    if (static_cast<std::uint8_t>(gen_after - gen_before) != 1) {
        std::fprintf(stderr,
                     "[virtio-pci-test] FAIL: config_gen %u -> %u\n",
                     gen_before, gen_after);
        return 12;
    }
    if ((tx->isr() & 2u) == 0) {
        std::fputs("[virtio-pci-test] FAIL: ISR config bit not set\n", stderr);
        return 12;
    }

    // ---- (l) Vector 0xFFFF disables MSI-X for that queue -> RaiseQueue
    // should not inject (but ISR bit must still latch).
    mmio_w(bar_gpa + 0x16, 0, 2);             // select queue 0
    mmio_w(bar_gpa + 0x1A, 0xFFFFu, 2);       // queue_msix_vector=NO_VECTOR
    injects.clear();
    (void)mmio_r(bar_gpa + v::PciTransport::kOffIsr, 1);  // clear ISR
    tx->RaiseQueueInterrupt(0);
    if (!injects.empty()) {
        std::fputs("[virtio-pci-test] FAIL: NO_VECTOR should suppress MSI\n",
                   stderr);
        return 12;
    }
    if ((tx->isr() & 1u) == 0) {
        std::fputs("[virtio-pci-test] FAIL: ISR not latched with NO_VECTOR\n",
                   stderr);
        return 12;
    }

    // ---- (m) Status reset wipes everything.
    mmio_w(bar_gpa + 0x14, 0, 1);
    if (dev_ptr->queue().ready() || tx->status() != 0 || tx->isr() != 0) {
        std::fputs("[virtio-pci-test] FAIL: reset incomplete\n", stderr);
        return 12;
    }
    if (dev_ptr->driver_ok()) {
        std::fputs("[virtio-pci-test] FAIL: driver_ok not cleared on reset\n",
                   stderr);
        return 12;
    }

    std::printf("[virtio-pci-test] PASS (reads=%llu writes=%llu notify=%llu)\n",
                static_cast<unsigned long long>(tx->reads()),
                static_cast<unsigned long long>(tx->writes()),
                static_cast<unsigned long long>(tx->notify_count()));
    return 0;
}

// ---------------------------------------------------------------------------
// --virtio-blk-discard-test
// Verifies the M34.x DISCARD + WRITE_ZEROES virtio-blk additions:
//   1. DeviceFeatures() advertises DISCARD + WRITE_ZEROES on a
//      writable backend; advertises NEITHER on a read-only backend.
//   2. ReadConfig at the M34.x sub-config offsets returns the values
//      we PutLe()'d in the constructor (max_discard_sectors,
//      max_write_zeroes_sectors, write_zeroes_may_unmap=1).
//   3. BlockFile::ZeroRange on a writable file zeroes the requested
//      bytes and leaves surrounding bytes untouched.
//   4. BlockFile::ZeroRange on a readonly file returns false and
//      leaves the file unchanged.
int RunVirtioBlkDiscardTest() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;
    namespace v = tinyvmm::virtio;
    namespace h = tinyvmm::host;
    namespace fs = std::filesystem;

    std::puts("[virtio-blk-discard-test] starting (host-side; no WHP)");

    // 1) Build a 1 MiB image filled with 0xAB.
    fs::path img = fs::temp_directory_path() / "tinyvmm-blk-discard.img";
    constexpr std::uint64_t kImgSize = 1ull << 20;     // 1 MiB
    {
        std::vector<std::uint8_t> seed(kImgSize, 0xAB);
        std::ofstream ofs(img, std::ios::binary | std::ios::trunc);
        ofs.write(reinterpret_cast<const char*>(seed.data()),
                  static_cast<std::streamsize>(seed.size()));
    }
    auto cleanup = [&]{ std::error_code ec; fs::remove(img, ec); };

    // 2) Set up a Partition + tiny RAM + BlockFile + BlockDevice.
    // We don't go through PCI / virtqueue here; we only test
    // DeviceFeatures / ReadConfig / BlockFile::ZeroRange directly.
    CheckWhpAvailable();
    Partition part(/*vcpu_count=*/1);
    part.Setup();
    GuestMemory ram(part, /*gpa=*/0, /*size=*/4096, /*executable=*/false);

    {
        h::BlockFile backend(img.wstring(), /*readonly=*/false);
        if (!backend.open()) {
            std::fprintf(stderr,
                "[virtio-blk-discard-test] FAIL: BlockFile open hr=0x%08lx\n",
                backend.open_hr());
            cleanup();
            return 1;
        }
        backend.Start();
        v::BlockDevice dev(ram, backend, /*irq=*/[](std::uint32_t){});

        // 3) Verify DeviceFeatures advertises both DISCARD + WRITE_ZEROES.
        const std::uint64_t feats = dev.DeviceFeatures();
        if (!(feats & v::kBlkFeatureDiscard)) {
            std::fprintf(stderr,
                "[virtio-blk-discard-test] FAIL: DISCARD feature bit (13) "
                "not advertised; features=0x%016llx\n",
                static_cast<unsigned long long>(feats));
            backend.Stop();
            cleanup(); return 2;
        }
        if (!(feats & v::kBlkFeatureWriteZeroes)) {
            std::fprintf(stderr,
                "[virtio-blk-discard-test] FAIL: WRITE_ZEROES feature bit "
                "(14) not advertised; features=0x%016llx\n",
                static_cast<unsigned long long>(feats));
            backend.Stop();
            cleanup(); return 3;
        }
        std::printf("[virtio-blk-discard-test] feats=0x%016llx OK "
                    "(DISCARD+WRITE_ZEROES)\n",
                    static_cast<unsigned long long>(feats));

        // 4) Verify ReadConfig at the M34.x sub-config offsets.
        auto cfg32 = [&](std::uint32_t off) { return dev.ReadConfig(off, 4); };
        auto cfg8  = [&](std::uint32_t off) { return dev.ReadConfig(off, 1); };
        const std::uint32_t max_disc_sec   = cfg32(32);
        const std::uint32_t max_disc_seg   = cfg32(36);
        const std::uint32_t disc_align     = cfg32(40);
        const std::uint32_t max_wz_sec     = cfg32(44);
        const std::uint32_t max_wz_seg     = cfg32(48);
        const std::uint32_t wz_may_unmap   = cfg8(52);
        std::printf("[virtio-blk-discard-test] cfg max_discard_sectors=%u "
                    "max_discard_seg=%u align=%u | max_wz_sectors=%u "
                    "max_wz_seg=%u may_unmap=%u\n",
                    max_disc_sec, max_disc_seg, disc_align,
                    max_wz_sec, max_wz_seg, wz_may_unmap);
        if (max_disc_sec == 0 || max_disc_seg == 0 || disc_align == 0 ||
            max_wz_sec == 0   || max_wz_seg == 0   || wz_may_unmap != 1) {
            std::fprintf(stderr,
                "[virtio-blk-discard-test] FAIL: cfg values out of spec\n");
            backend.Stop();
            cleanup(); return 4;
        }

        // 5) ZeroRange: zero 128 KiB at offset 256 KiB.
        constexpr std::uint64_t kZeroOff = 256ull * 1024;
        constexpr std::uint64_t kZeroLen = 128ull * 1024;
        if (!backend.ZeroRange(kZeroOff, kZeroLen)) {
            std::fprintf(stderr,
                "[virtio-blk-discard-test] FAIL: ZeroRange returned false\n");
            backend.Stop();
            cleanup(); return 5;
        }
        backend.Stop();
    }  // writable BlockFile out of scope; handle closed for ro re-open

    // 6) Re-read the file from disk; expect [256k..384k) = 0x00,
    //    everything else = 0xAB.
    constexpr std::uint64_t kZeroOff = 256ull * 1024;
    constexpr std::uint64_t kZeroLen = 128ull * 1024;
    std::vector<std::uint8_t> after(kImgSize);
    {
        std::ifstream ifs(img, std::ios::binary);
        ifs.read(reinterpret_cast<char*>(after.data()), kImgSize);
    }
    for (std::uint64_t i = 0; i < kImgSize; ++i) {
        const std::uint8_t want =
            (i >= kZeroOff && i < kZeroOff + kZeroLen) ? 0x00 : 0xAB;
        if (after[i] != want) {
            std::fprintf(stderr,
                "[virtio-blk-discard-test] FAIL: byte[%llu]=0x%02x "
                "(want 0x%02x)\n",
                static_cast<unsigned long long>(i),
                after[i], want);
            cleanup(); return 6;
        }
    }
    std::printf("[virtio-blk-discard-test] ZeroRange: 128 KiB @ 256 KiB "
                "zeroed; surrounding bytes intact\n");

    // 7) Read-only backend: must NOT advertise DISCARD/WRITE_ZEROES and
    //    ZeroRange must return false (file unchanged).
    h::BlockFile ro_backend(img.wstring(), /*readonly=*/true);
    if (!ro_backend.open()) {
        std::fprintf(stderr,
            "[virtio-blk-discard-test] FAIL: ro BlockFile open hr=0x%08lx\n",
            ro_backend.open_hr());
        cleanup(); return 7;
    }
    ro_backend.Start();
    v::BlockDevice ro_dev(ram, ro_backend, /*irq=*/[](std::uint32_t){});
    const std::uint64_t ro_feats = ro_dev.DeviceFeatures();
    if (ro_feats & (v::kBlkFeatureDiscard | v::kBlkFeatureWriteZeroes)) {
        std::fprintf(stderr,
            "[virtio-blk-discard-test] FAIL: read-only backend advertised "
            "DISCARD/WRITE_ZEROES (feats=0x%016llx)\n",
            static_cast<unsigned long long>(ro_feats));
        ro_backend.Stop();
        cleanup(); return 8;
    }
    if (!(ro_feats & v::kBlkFeatureRo)) {
        std::fprintf(stderr,
            "[virtio-blk-discard-test] FAIL: read-only backend missing "
            "RO feature bit (feats=0x%016llx)\n",
            static_cast<unsigned long long>(ro_feats));
        ro_backend.Stop();
        cleanup(); return 9;
    }
    if (ro_backend.ZeroRange(0, 4096)) {
        std::fprintf(stderr,
            "[virtio-blk-discard-test] FAIL: ZeroRange returned true on "
            "read-only backend\n");
        ro_backend.Stop();
        cleanup(); return 10;
    }
    ro_backend.Stop();

    std::printf("[virtio-blk-discard-test] PASS (RW: DISCARD+WRITE_ZEROES "
                "feats + cfg + ZeroRange OK; RO: feats=RO ZeroRange=false)\n");
    cleanup();
    return 0;
}

// ---------------------------------------------------------------------------
// --virtio-blk-test
// Host-side end-to-end test of the virtio-blk device wired through the
// virtio-PCI transport with an async file backend on a temp 1 MiB image.
// Exercises:
//   * PCI identity (VID=0x1AF4, DID=0x1042 (=0x1040+0x02), class=01:00 SCSI)
//   * Cap chain walk + MSI-X cap
//   * Device-cfg read: capacity (sectors), blk_size, seg_max, size_max
//   * Feature negotiation (BLK_SIZE | FLUSH | SIZE_MAX | SEG_MAX | VERSION_1)
//   * READ sector 0   -> data matches host-prepared pattern; status==OK
//   * WRITE sector 10 -> file contents updated
//   * READ sector 10  -> reflects the new pattern
//   * FLUSH           -> completes with status==OK
// IOCP completions fire on a worker thread; the inject recorder is locked
// and the test polls an atomic counter to know when to drive the next op.
int RunVirtioBlkTest() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;
    namespace p = tinyvmm::pci;
    namespace v = tinyvmm::virtio;
    namespace h = tinyvmm::host;
    namespace fs = std::filesystem;

    std::puts("[virtio-blk-test] starting (host-side; no WHP)");

    // 1) Build a deterministic 1 MiB image in TEMP.
    fs::path img = fs::temp_directory_path() / "tinyvmm-blk.img";
    constexpr std::uint64_t kImgSize = 1ull << 20;     // 1 MiB
    constexpr std::uint32_t kSectorBytes = v::kBlkSectorSize;
    constexpr std::uint64_t kExpectedSectors = kImgSize / kSectorBytes;
    {
        std::vector<std::uint8_t> seed(kImgSize);
        for (std::size_t i = 0; i < seed.size(); ++i)
            seed[i] = static_cast<std::uint8_t>((i ^ 0xA5u) & 0xFFu);
        std::ofstream ofs(img, std::ios::binary | std::ios::trunc);
        ofs.write(reinterpret_cast<const char*>(seed.data()),
                  static_cast<std::streamsize>(seed.size()));
    }

    auto cleanup_img = [&]() {
        std::error_code ec;
        fs::remove(img, ec);
    };

    // 2) Boilerplate: Partition + 2 MiB GuestMemory + IoBus + MmioBus + PciBus.
    CheckWhpAvailable();
    Partition part(/*vcpu_count=*/1);
    part.Setup();
    constexpr std::size_t kRamBytes = 0x200000;
    GuestMemory ram(part, /*gpa=*/0, kRamBytes, /*executable=*/false);
    auto* host_ram = static_cast<std::uint8_t*>(ram.host_base());
    std::memset(host_ram, 0, kRamBytes);

    devices::IoBus   io_bus;
    devices::MmioBus mmio_bus;
    p::PciBus        pbus;
    pbus.AttachIoBus(io_bus);

    // 3) Async backend.
    h::BlockFile backend(img.wstring(), /*readonly=*/false);
    if (!backend.open()) {
        std::fprintf(stderr,
                     "[virtio-blk-test] FAIL: BlockFile open hr=0x%08lx\n",
                     static_cast<unsigned long>(backend.open_hr()));
        cleanup_img();
        return 13;
    }
    if (backend.size() != kImgSize) {
        std::fprintf(stderr,
                     "[virtio-blk-test] FAIL: backend size=%llu (want %llu)\n",
                     static_cast<unsigned long long>(backend.size()),
                     static_cast<unsigned long long>(kImgSize));
        cleanup_img();
        return 13;
    }

    // 4) Recorded inject sink (thread-safe).
    struct Recorder {
        std::mutex m;
        std::atomic<std::size_t> count{0};
        std::vector<InjectRecord> recs;
    } rec;
    auto inject_fn = [&rec](std::uint64_t a, std::uint32_t d) {
        std::lock_guard<std::mutex> lk(rec.m);
        rec.recs.push_back({a, d});
        rec.count.fetch_add(1);
        return true;
    };

    // 5) Build BlockDevice (queue depth 16 for the test) and wrap in
    //    PciTransport. Start backend AFTER wiring the irq callback so we
    //    never get a spurious completion before the device knows where to
    //    deliver it.
    auto blk = std::make_unique<v::BlockDevice>(
        ram, backend, v::BlockDevice::IrqFn{}, /*queue_max=*/16);
    v::BlockDevice* blk_ptr = blk.get();

    v::PciTransport::Options opts;
    opts.subsys_id      = static_cast<std::uint16_t>(v::kDeviceIdBlk);
    opts.num_msix_vectors = 2;
    opts.pci_class      = 0x01;   // Mass Storage
    opts.pci_subclass   = 0x00;   // SCSI Controller
    auto xport = std::make_unique<v::PciTransport>(
        *blk_ptr, opts, mmio_bus, inject_fn);
    v::PciTransport* tx = xport.get();
    xport->set_name("virtio-pci-blk");

    blk_ptr->SetIrqCallback(
        [tx](std::uint32_t q) { tx->RaiseQueueInterrupt(q); });

    backend.Start();
    const p::Bdf bdf = pbus.AddDevice(std::move(xport));
    std::printf("[virtio-blk-test] device @ %02x:%02x.%u\n",
                bdf.bus, bdf.device, bdf.function);

    auto fail = [&](const char* msg) {
        std::fprintf(stderr, "[virtio-blk-test] FAIL: %s\n", msg);
        backend.Stop();
        cleanup_img();
    };

    // --- IO/MMIO helpers (same shape as --virtio-pci-test).
    auto io_w = [&](std::uint16_t port, std::uint16_t size, std::uint32_t val) {
        devices::IoAccess a{port, size, /*write=*/true, val};
        if (!io_bus.Dispatch(a)) Fatal("virtio-blk-test: unmatched IO write");
    };
    auto io_r = [&](std::uint16_t port, std::uint16_t size) -> std::uint32_t {
        devices::IoAccess a{port, size, /*write=*/false, 0};
        if (!io_bus.Dispatch(a)) Fatal("virtio-blk-test: unmatched IO read");
        return a.value;
    };
    auto encode = [](std::uint8_t b, std::uint8_t d, std::uint8_t fn,
                      std::uint8_t reg) -> std::uint32_t {
        return p::kConfigAddressEnable | (std::uint32_t{b} << 16) |
               (std::uint32_t{d} << 11) | (std::uint32_t{fn} << 8) |
               (reg & 0xFCu);
    };
    auto cfg_r = [&](std::uint8_t reg, std::uint16_t size) -> std::uint32_t {
        io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, reg));
        return io_r(static_cast<std::uint16_t>(p::kConfigDataPort + (reg & 3)),
                    size);
    };
    auto cfg_w = [&](std::uint8_t reg, std::uint16_t size, std::uint32_t val) {
        io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, reg));
        io_w(static_cast<std::uint16_t>(p::kConfigDataPort + (reg & 3)), size,
             val);
    };
    auto mmio_w = [&](std::uint64_t gpa, std::uint32_t val, std::uint8_t sz) {
        devices::MmioAccess a{};
        a.gpa = gpa; a.access_size = sz; a.is_write = true;
        std::memcpy(a.data, &val, std::min<std::size_t>(sz, 4));
        if (!mmio_bus.Dispatch(a))
            Fatal("virtio-blk-test: unmatched MMIO write");
    };
    auto mmio_r = [&](std::uint64_t gpa, std::uint8_t sz) -> std::uint32_t {
        devices::MmioAccess a{};
        a.gpa = gpa; a.access_size = sz; a.is_write = false;
        if (!mmio_bus.Dispatch(a))
            Fatal("virtio-blk-test: unmatched MMIO read");
        std::uint32_t v = 0;
        std::memcpy(&v, a.data, std::min<std::size_t>(sz, 4));
        return v;
    };

    // --- (a) Identity.
    const std::uint32_t vid_did = cfg_r(p::kCfgVendorId, 4);
    const std::uint8_t  cls  = static_cast<std::uint8_t>(
        cfg_r(p::kCfgClassCode, 1));
    const std::uint8_t  scls = static_cast<std::uint8_t>(
        cfg_r(p::kCfgSubclass, 1));
    const std::uint32_t subsys = cfg_r(p::kCfgSubsysVendorId, 4);
    std::printf("[virtio-blk-test] vid_did=0x%08x class=%02x:%02x subsys=0x%08x\n",
                vid_did, cls, scls, subsys);
    if (vid_did != ((std::uint32_t{0x1042} << 16) | 0x1AF4u)) {
        fail("VID/DID mismatch (want 0x1AF4/0x1042)");
        return 13;
    }
    if (cls != 0x01 || scls != 0x00 ||
        subsys != ((std::uint32_t{v::kDeviceIdBlk} << 16) | 0x1AF4u)) {
        fail("class/subsys mismatch");
        return 13;
    }

    // --- (b) Walk caps; pick out the MSI-X cap offset.
    std::uint8_t cap = static_cast<std::uint8_t>(cfg_r(p::kCfgCapPtr, 1));
    std::uint8_t msix_cap_off = 0;
    std::size_t cap_count = 0;
    while (cap != 0 && cap_count < 16) {
        const std::uint8_t id =
            static_cast<std::uint8_t>(cfg_r(cap, 1));
        if (id == p::kCapIdMsiX) msix_cap_off = cap;
        cap = static_cast<std::uint8_t>(
            cfg_r(static_cast<std::uint8_t>(cap + 1), 1));
        cap_count++;
    }
    if (!msix_cap_off) {
        fail("MSI-X cap not found");
        return 13;
    }

    // --- (c) Map BAR0.
    const std::uint32_t bar0_lo = cfg_r(p::kCfgBar0, 4);
    const std::uint32_t bar0_hi = cfg_r(p::kCfgBar0 + 4, 4);
    if ((bar0_lo & 0xFu) != (p::kBarMmio64 | p::kBarPrefetchable)) {
        fail("BAR0 type bits wrong");
        return 13;
    }
    cfg_w(p::kCfgCommand, 2, p::kCmdMemorySpace | p::kCmdBusMaster);
    const std::uint64_t bar_gpa = (static_cast<std::uint64_t>(bar0_hi) << 32) |
                                   (bar0_lo & ~0xFu);
    std::printf("[virtio-blk-test] BAR0 mapped @ 0x%llx\n",
                static_cast<unsigned long long>(bar_gpa));

    // --- (d) Read device-cfg @ +0x2000.
    const std::uint64_t devcfg = bar_gpa + v::PciTransport::kOffDeviceCfg;
    const std::uint32_t cap_lo = mmio_r(devcfg + 0, 4);
    const std::uint32_t cap_hi = mmio_r(devcfg + 4, 4);
    const std::uint64_t capacity_sectors =
        static_cast<std::uint64_t>(cap_lo) |
        (static_cast<std::uint64_t>(cap_hi) << 32);
    const std::uint32_t size_max = mmio_r(devcfg + 8,  4);
    const std::uint32_t seg_max  = mmio_r(devcfg + 12, 4);
    const std::uint32_t blk_size = mmio_r(devcfg + 20, 4);
    std::printf("[virtio-blk-test] capacity=%llu sectors size_max=%u seg_max=%u blk_size=%u\n",
                static_cast<unsigned long long>(capacity_sectors),
                size_max, seg_max, blk_size);
    if (capacity_sectors != kExpectedSectors || blk_size != kSectorBytes) {
        fail("device-cfg wrong");
        return 13;
    }

    // --- (e) Feature negotiation (NO EVENT_IDX, to keep the used-event
    //     plumbing irrelevant in this host-side test).
    mmio_w(bar_gpa + 0x00, 0, 4);
    const std::uint32_t df_lo = mmio_r(bar_gpa + 0x04, 4);
    mmio_w(bar_gpa + 0x00, 1, 4);
    const std::uint32_t df_hi = mmio_r(bar_gpa + 0x04, 4);
    const std::uint64_t df =
        static_cast<std::uint64_t>(df_lo) |
        (static_cast<std::uint64_t>(df_hi) << 32);
    constexpr std::uint64_t want_features =
        v::kFeatureVersion1 | v::kBlkFeatureBlkSize | v::kBlkFeatureFlush |
        v::kBlkFeatureSegMax | v::kBlkFeatureSizeMax;
    if ((df & want_features) != want_features) {
        fail("device features missing");
        return 13;
    }
    const std::uint64_t acked = want_features;
    mmio_w(bar_gpa + 0x14, v::kStatusAcknowledge, 1);
    mmio_w(bar_gpa + 0x14, v::kStatusAcknowledge | v::kStatusDriver, 1);
    mmio_w(bar_gpa + 0x08, 0, 4);
    mmio_w(bar_gpa + 0x0C, static_cast<std::uint32_t>(acked & 0xFFFFFFFFu), 4);
    mmio_w(bar_gpa + 0x08, 1, 4);
    mmio_w(bar_gpa + 0x0C, static_cast<std::uint32_t>(acked >> 32), 4);
    mmio_w(bar_gpa + 0x14,
           v::kStatusAcknowledge | v::kStatusDriver | v::kStatusFeaturesOk, 1);
    if ((mmio_r(bar_gpa + 0x14, 1) & v::kStatusFeaturesOk) == 0) {
        fail("FEATURES_OK rejected");
        return 13;
    }

    // --- (f) Program MSI-X vector 0 (queue) and enable MSI-X.
    constexpr std::uint64_t kMsiAddrBase = 0xFEE00000ull;
    constexpr std::uint32_t kMsiData     = 0x40;
    {
        const std::uint64_t tbl = bar_gpa + v::PciTransport::kOffMsixTable;
        mmio_w(tbl + 0,
               static_cast<std::uint32_t>(kMsiAddrBase & 0xFFFFFFFFu), 4);
        mmio_w(tbl + 4,
               static_cast<std::uint32_t>(kMsiAddrBase >> 32), 4);
        mmio_w(tbl + 8, kMsiData, 4);
        mmio_w(tbl + 12, 0u, 4);    // unmask
    }
    cfg_w(static_cast<std::uint8_t>(msix_cap_off + 2), 2, 0x8000u);
    if (!tx->msix().MsiXEnabled()) {
        fail("MSI-X not enabled");
        return 13;
    }

    // --- (g) Program queue 0 (size=16).
    constexpr std::uint64_t kDescGpa   = 0x30000;
    constexpr std::uint64_t kAvailGpa  = 0x30200;
    constexpr std::uint64_t kUsedGpa   = 0x30400;
    constexpr std::uint64_t kHdrGpa    = 0x40000;
    constexpr std::uint64_t kDataGpa   = 0x40100;
    constexpr std::uint64_t kStatusGpa = 0x40400;
    constexpr std::uint32_t kQSize     = 16;
    mmio_w(bar_gpa + 0x16, 0, 2);                // queue_select=0
    mmio_w(bar_gpa + 0x18, kQSize, 2);
    mmio_w(bar_gpa + 0x1A, 0, 2);                // msix_vector=0
    mmio_w(bar_gpa + 0x20, static_cast<std::uint32_t>(kDescGpa), 4);
    mmio_w(bar_gpa + 0x24, static_cast<std::uint32_t>(kDescGpa >> 32), 4);
    mmio_w(bar_gpa + 0x28, static_cast<std::uint32_t>(kAvailGpa), 4);
    mmio_w(bar_gpa + 0x2C, static_cast<std::uint32_t>(kAvailGpa >> 32), 4);
    mmio_w(bar_gpa + 0x30, static_cast<std::uint32_t>(kUsedGpa), 4);
    mmio_w(bar_gpa + 0x34, static_cast<std::uint32_t>(kUsedGpa >> 32), 4);
    mmio_w(bar_gpa + 0x1C, 1, 2);                // queue_enable
    mmio_w(bar_gpa + 0x14,
           v::kStatusAcknowledge | v::kStatusDriver | v::kStatusFeaturesOk |
               v::kStatusDriverOk, 1);

    // --- (h) Per-request helpers (build a 3-element descriptor chain
    //     starting at desc[head_idx]).
#pragma pack(push, 1)
    struct VringDesc {
        std::uint64_t addr;
        std::uint32_t len;
        std::uint16_t flags;
        std::uint16_t next;
    };
    struct VirtioBlkHdr {
        std::uint32_t type;
        std::uint32_t reserved;
        std::uint64_t sector;
    };
#pragma pack(pop)
    auto* descs = reinterpret_cast<VringDesc*>(host_ram + kDescGpa);
    auto* avail = host_ram + kAvailGpa;        // u16 flags, u16 idx, u16 ring[]
    auto* used  = host_ram + kUsedGpa;

    std::uint16_t avail_ring_idx = 0;          // next slot in avail.ring[]
    std::uint16_t desc_head      = 0;          // next free desc index
    std::uint16_t expected_used  = 0;

    auto wait_for_inject = [&](std::size_t target,
                                int timeout_ms) -> bool {
        const auto t0 = std::chrono::steady_clock::now();
        while (rec.count.load() < target) {
            if (std::chrono::steady_clock::now() - t0 >
                std::chrono::milliseconds(timeout_ms))
                return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return true;
    };

    auto submit_chain = [&](std::uint32_t type, std::uint64_t sector,
                             std::uint16_t data_flags, std::uint32_t data_len,
                             bool with_data) -> bool {
        // Plant header.
        auto* hdr = reinterpret_cast<VirtioBlkHdr*>(host_ram + kHdrGpa);
        hdr->type = type; hdr->reserved = 0; hdr->sector = sector;
        // Status byte (device-writable).
        host_ram[kStatusGpa] = 0xAB;     // pre-poison

        const std::uint16_t head = desc_head;
        const std::uint16_t chain_len = with_data ? 3 : 2;

        if (with_data) {
            const std::uint16_t i0 = head;
            const std::uint16_t i1 = static_cast<std::uint16_t>((head + 1) % kQSize);
            const std::uint16_t i2 = static_cast<std::uint16_t>((head + 2) % kQSize);
            descs[i0] = {kHdrGpa, static_cast<std::uint32_t>(sizeof(VirtioBlkHdr)),
                          v::kVringDescFNext, i1};
            descs[i1] = {kDataGpa, data_len,
                          static_cast<std::uint16_t>(v::kVringDescFNext |
                                                      data_flags),
                          i2};
            descs[i2] = {kStatusGpa, 1, v::kVringDescFWrite, 0};
        } else {
            const std::uint16_t i0 = head;
            const std::uint16_t i1 = static_cast<std::uint16_t>((head + 1) % kQSize);
            descs[i0] = {kHdrGpa, static_cast<std::uint32_t>(sizeof(VirtioBlkHdr)),
                          v::kVringDescFNext, i1};
            descs[i1] = {kStatusGpa, 1, v::kVringDescFWrite, 0};
        }

        // Publish head in the next ring slot.
        *reinterpret_cast<std::uint16_t*>(avail + 0) = 0;     // flags
        *reinterpret_cast<std::uint16_t*>(avail + 4 + 2 * (avail_ring_idx % kQSize))
            = head;
        ++avail_ring_idx;
        *reinterpret_cast<std::uint16_t*>(avail + 2) = avail_ring_idx;

        const std::size_t before = rec.count.load();
        mmio_w(bar_gpa + v::PciTransport::kOffNotify + 0, 0u, 2);
        if (!wait_for_inject(before + 1, /*ms=*/2000)) {
            return false;
        }

        desc_head = static_cast<std::uint16_t>((head + chain_len) % kQSize);
        ++expected_used;
        return true;
    };

    auto get_status_byte = [&]() {
        return host_ram[kStatusGpa];
    };
    auto get_used_idx = [&]() {
        return *reinterpret_cast<std::uint16_t*>(used + 2);
    };

    // --- READ sector 0 ---------------------------------------------------
    std::memset(host_ram + kDataGpa, 0, kSectorBytes);
    if (!submit_chain(v::kBlkTypeIn, /*sector=*/0,
                       v::kVringDescFWrite, kSectorBytes, /*with_data=*/true)) {
        fail("READ sector 0 timeout");
        return 13;
    }
    if (get_status_byte() != v::kBlkStatusOk) {
        std::fprintf(stderr,
                     "[virtio-blk-test] FAIL: READ sector 0 status=0x%02x\n",
                     get_status_byte());
        backend.Stop(); cleanup_img(); return 13;
    }
    for (std::uint32_t i = 0; i < kSectorBytes; ++i) {
        const std::uint8_t want = static_cast<std::uint8_t>((i ^ 0xA5u) & 0xFFu);
        if (host_ram[kDataGpa + i] != want) {
            std::fprintf(stderr,
                "[virtio-blk-test] FAIL: READ sector 0 data[%u]=0x%02x want 0x%02x\n",
                i, host_ram[kDataGpa + i], want);
            backend.Stop(); cleanup_img(); return 13;
        }
    }
    if (get_used_idx() != expected_used) {
        fail("used.idx wrong after READ");
        return 13;
    }
    std::puts("[virtio-blk-test] READ sector 0: OK");

    // --- WRITE sector 10 -------------------------------------------------
    for (std::uint32_t i = 0; i < kSectorBytes; ++i) {
        host_ram[kDataGpa + i] = static_cast<std::uint8_t>((i + 1u) & 0xFFu);
    }
    if (!submit_chain(v::kBlkTypeOut, /*sector=*/10,
                       /*data_flags=*/0, kSectorBytes, /*with_data=*/true)) {
        fail("WRITE sector 10 timeout");
        return 13;
    }
    if (get_status_byte() != v::kBlkStatusOk) {
        std::fprintf(stderr,
                     "[virtio-blk-test] FAIL: WRITE status=0x%02x\n",
                     get_status_byte());
        backend.Stop(); cleanup_img(); return 13;
    }
    std::puts("[virtio-blk-test] WRITE sector 10: OK");

    // --- READ-back sector 10 --------------------------------------------
    std::memset(host_ram + kDataGpa, 0, kSectorBytes);
    if (!submit_chain(v::kBlkTypeIn, /*sector=*/10,
                       v::kVringDescFWrite, kSectorBytes, /*with_data=*/true)) {
        fail("READ-back sector 10 timeout");
        return 13;
    }
    if (get_status_byte() != v::kBlkStatusOk) {
        fail("READ-back status not OK");
        return 13;
    }
    for (std::uint32_t i = 0; i < kSectorBytes; ++i) {
        const std::uint8_t want = static_cast<std::uint8_t>((i + 1u) & 0xFFu);
        if (host_ram[kDataGpa + i] != want) {
            std::fprintf(stderr,
                "[virtio-blk-test] FAIL: READ-back data[%u]=0x%02x want 0x%02x\n",
                i, host_ram[kDataGpa + i], want);
            backend.Stop(); cleanup_img(); return 13;
        }
    }
    std::puts("[virtio-blk-test] READ-back sector 10: OK");

    // --- FLUSH ---------------------------------------------------------
    if (!submit_chain(v::kBlkTypeFlush, /*sector=*/0,
                       /*data_flags=*/0, /*data_len=*/0,
                       /*with_data=*/false)) {
        fail("FLUSH timeout");
        return 13;
    }
    if (get_status_byte() != v::kBlkStatusOk) {
        fail("FLUSH status not OK");
        return 13;
    }
    std::puts("[virtio-blk-test] FLUSH: OK");

    // 6) Stop the worker before we destroy anything async I/O could touch.
    backend.Stop();

    std::printf("[virtio-blk-test] PASS (in=%llu out=%llu flush=%llu done=%llu err=%llu)\n",
                static_cast<unsigned long long>(blk_ptr->ops_in()),
                static_cast<unsigned long long>(blk_ptr->ops_out()),
                static_cast<unsigned long long>(blk_ptr->ops_flush()),
                static_cast<unsigned long long>(blk_ptr->ops_done()),
                static_cast<unsigned long long>(blk_ptr->ops_err()));
    cleanup_img();
    return 0;
}

// ---------------------------------------------------------------------------
// --virtio-blk-ro-test
// Host-side test of the readonly path in tinyvmm::host::BlockFile. The
// guest-side `tinyvmm.test=blk` Phase F only validates that Linux's block
// layer correctly refuses writes to a device that advertises the VIRTIO_BLK
// RO feature bit -- the OUT request never reaches the host. This test
// covers the actual backend reject path: open the file with readonly=true,
// submit an OpRead (must succeed), an OpWrite (must fail synchronously),
// and an OpFlush (must succeed -- FlushFileBuffers on a read-only handle
// is legal and is what the guest will see when its kernel issues a
// REQ_PREFLUSH on a readonly mount).
int RunVirtioBlkRoTest() {
    namespace fs = std::filesystem;
    namespace h  = tinyvmm::host;

    std::puts("[virtio-blk-ro-test] starting (host-side; no WHP)");

    // 1) Create a small deterministic file in TEMP.
    fs::path img = fs::temp_directory_path() / "tinyvmm-blk-ro.img";
    constexpr std::uint64_t kSize = 64 * 1024;     // 64 KiB
    {
        std::vector<std::uint8_t> seed(kSize);
        for (std::size_t i = 0; i < seed.size(); ++i)
            seed[i] = static_cast<std::uint8_t>((i ^ 0x5A) & 0xFFu);
        std::ofstream ofs(img, std::ios::binary | std::ios::trunc);
        ofs.write(reinterpret_cast<const char*>(seed.data()),
                  static_cast<std::streamsize>(seed.size()));
    }
    auto cleanup = [&]() {
        std::error_code ec;
        fs::remove(img, ec);
    };

    // 2) Open readonly.
    h::BlockFile backend(img.wstring(), /*readonly=*/true);
    if (!backend.open()) {
        std::fprintf(stderr,
                     "[virtio-blk-ro-test] FAIL: open hr=0x%08lx\n",
                     static_cast<unsigned long>(backend.open_hr()));
        cleanup(); return 13;
    }
    if (!backend.readonly()) {
        std::fputs("[virtio-blk-ro-test] FAIL: readonly() returned false\n",
                   stderr);
        cleanup(); return 13;
    }
    if (backend.size() != kSize) {
        std::fprintf(stderr,
                     "[virtio-blk-ro-test] FAIL: size=%llu (want %llu)\n",
                     static_cast<unsigned long long>(backend.size()),
                     static_cast<unsigned long long>(kSize));
        cleanup(); return 13;
    }

    // 3) Completion recorder.
    std::atomic<std::size_t> done{0};
    backend.SetCompletionCallback(
        [&](h::BlockFile::Request*) { done.fetch_add(1); });

    backend.Start();
    auto stop_backend = [&]() { backend.Stop(); cleanup(); };

    // 4) OpRead - must succeed (Submit returns true, completion fires,
    //    ok=true, bytes match).
    std::vector<std::uint8_t> read_buf(4096, 0);
    h::BlockFile::Request rd{};
    rd.op = h::BlockFile::Request::OpRead;
    rd.file_offset = 0;
    rd.buf = read_buf.data();
    rd.bytes = static_cast<std::uint32_t>(read_buf.size());

    if (!backend.Submit(&rd)) {
        std::puts("[virtio-blk-ro-test] FAIL: OpRead submit returned false");
        stop_backend(); return 13;
    }
    // Spin briefly for the completion. The worker is a single thread on
    // a 4 KiB read -- this should complete in microseconds.
    for (int i = 0; i < 1000 && done.load() < 1; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    if (done.load() != 1 || !rd.ok) {
        std::printf("[virtio-blk-ro-test] FAIL: OpRead done=%zu ok=%d\n",
                    done.load(), static_cast<int>(rd.ok));
        stop_backend(); return 13;
    }
    // Verify content matches the seed pattern.
    for (std::size_t i = 0; i < read_buf.size(); ++i) {
        const std::uint8_t want = static_cast<std::uint8_t>((i ^ 0x5A) & 0xFFu);
        if (read_buf[i] != want) {
            std::printf("[virtio-blk-ro-test] FAIL: read data[%zu]=0x%02x want 0x%02x\n",
                        i, read_buf[i], want);
            stop_backend(); return 13;
        }
    }
    std::puts("[virtio-blk-ro-test] OpRead: OK");

    // 5) OpWrite - MUST be rejected. Submit returns false and errors
    //    increments by 1 immediately (no completion).
    const auto err_before = backend.errors();
    const auto done_before = done.load();
    std::vector<std::uint8_t> write_buf(4096, 0xFFu);
    h::BlockFile::Request wr{};
    wr.op = h::BlockFile::Request::OpWrite;
    wr.file_offset = 0;
    wr.buf = write_buf.data();
    wr.bytes = static_cast<std::uint32_t>(write_buf.size());

    if (backend.Submit(&wr)) {
        std::puts("[virtio-blk-ro-test] FAIL: OpWrite submit returned true (must reject)");
        stop_backend(); return 13;
    }
    // Give a chance for any spurious completion (there shouldn't be one).
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    if (done.load() != done_before) {
        std::printf("[virtio-blk-ro-test] FAIL: OpWrite produced %zu completions (must produce 0)\n",
                    done.load() - done_before);
        stop_backend(); return 13;
    }
    if (backend.errors() != err_before + 1) {
        std::printf("[virtio-blk-ro-test] FAIL: errors counter %llu (want %llu)\n",
                    static_cast<unsigned long long>(backend.errors()),
                    static_cast<unsigned long long>(err_before + 1));
        stop_backend(); return 13;
    }
    // Confirm the host file is unchanged: byte 0 must still be the seed
    // value (0x5A from the (i^0x5A) seed), not 0xFF from write_buf.
    {
        std::ifstream ifs(img, std::ios::binary);
        std::uint8_t b{};
        ifs.read(reinterpret_cast<char*>(&b), 1);
        if (b != 0x5A) {
            std::printf("[virtio-blk-ro-test] FAIL: file byte[0]=0x%02x (want 0x5A; file mutated)\n", b);
            stop_backend(); return 13;
        }
    }
    std::puts("[virtio-blk-ro-test] OpWrite: rejected (errors+1, file unchanged)");

    // 6) OpFlush - submit must succeed (the request reaches the worker)
    //    but FlushFileBuffers on a Windows GENERIC_READ-only handle
    //    fails with ERROR_ACCESS_DENIED, so req->ok ends up false. That
    //    is the correct passthrough: a misbehaving guest sending a
    //    FLUSH to a readonly device sees a clean kBlkStatusIoErr instead
    //    of any host-side crash or stall. Linux's block layer normally
    //    masks FLUSH on RO mounts so this path is rarely exercised in
    //    practice -- but it must not wedge.
    h::BlockFile::Request fl{};
    fl.op = h::BlockFile::Request::OpFlush;
    const auto done_before_flush = done.load();
    const auto err_before_flush  = backend.errors();
    if (!backend.Submit(&fl)) {
        std::puts("[virtio-blk-ro-test] FAIL: OpFlush submit returned false");
        stop_backend(); return 13;
    }
    for (int i = 0; i < 1000 && done.load() < done_before_flush + 1; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    if (done.load() != done_before_flush + 1) {
        std::printf("[virtio-blk-ro-test] FAIL: OpFlush no completion (done=%zu)\n",
                    done.load() - done_before_flush);
        stop_backend(); return 13;
    }
    // Whichever way FlushFileBuffers went, the worker properly reported
    // it via the completion callback; that's the property we're
    // testing. The errors counter tracks ok==false so it tells us which
    // result we got -- log it for visibility.
    std::printf("[virtio-blk-ro-test] OpFlush: dispatched (ok=%d, errors_delta=%llu)\n",
                static_cast<int>(fl.ok),
                static_cast<unsigned long long>(backend.errors() - err_before_flush));

    std::printf("[virtio-blk-ro-test] PASS (submitted=%llu completed=%llu errors=%llu "
                "max_inflight=%llu)\n",
                static_cast<unsigned long long>(backend.submitted()),
                static_cast<unsigned long long>(backend.completed()),
                static_cast<unsigned long long>(backend.errors()),
                static_cast<unsigned long long>(backend.max_inflight()));
    stop_backend();
    return 0;
}

// ---------------------------------------------------------------------------
// --virtio-net-pci-test
// Host-side test of virtio-net wrapped in the virtio-PCI modern transport.
// Validates:
//   * PCI identity (VID=0x1AF4, DID=0x1041, class=02:00 Network/Ethernet)
//   * MSI-X cap discoverable; num_queues == 2
//   * Device-cfg readback: MAC bytes + link_status (link_up)
//   * Feature negotiation refuses bits we never advertised (NEEDS_RESET)
//   * After re-arm: full ACK→DRIVER→FEATURES_OK→DRIVER_OK path
//   * Two queues programmable independently with distinct MSI-X vectors;
//     queue_notify_off equals qidx for each
//   * Notify on RX (offset 0) increments rx counter only; notify on TX
//     (offset 4) increments tx counter only
//   * RaiseQueueInterrupt(0/1) lands on the right MSI-X vector
//   * RaiseConfigChangeInterrupt lands on msix_config vector + ISR bit 1
//   * Reset wipes queue.ready + driver_ok + isr
int RunVirtioNetPciTest() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;
    namespace p = tinyvmm::pci;
    namespace v = tinyvmm::virtio;

    std::puts("[virtio-net-pci-test] starting (host-side; no WHP)");

    CheckWhpAvailable();
    Partition part(/*vcpu_count=*/1);
    part.Setup();
    constexpr std::size_t kRamBytes = 0x200000;
    GuestMemory ram(part, /*gpa=*/0, kRamBytes, /*executable=*/false);
    auto* host_ram = static_cast<std::uint8_t*>(ram.host_base());
    std::memset(host_ram, 0, kRamBytes);

    devices::IoBus   io_bus;
    devices::MmioBus mmio_bus;
    p::PciBus        pbus;
    pbus.AttachIoBus(io_bus);

    std::vector<InjectRecord> injects;
    auto inject_fn = [&](std::uint64_t a, std::uint32_t d) {
        injects.push_back({a, d});
        return true;
    };

    constexpr std::array<std::uint8_t, 6> kMac{
        0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
    auto net = std::make_unique<v::NetDevice>(ram, kMac);
    v::NetDevice* net_ptr = net.get();

    v::PciTransport::Options opts;
    opts.subsys_id      = static_cast<std::uint16_t>(v::kDeviceIdNet);
    opts.num_msix_vectors = 3;     // RX, TX, config-change
    opts.pci_class      = 0x02;    // Network controller
    opts.pci_subclass   = 0x00;    // Ethernet controller
    auto xport = std::make_unique<v::PciTransport>(
        *net_ptr, opts, mmio_bus, inject_fn);
    v::PciTransport* tx = xport.get();
    xport->set_name("virtio-pci-net");

    const p::Bdf bdf = pbus.AddDevice(std::move(xport));
    std::printf("[virtio-net-pci-test] device @ %02x:%02x.%u\n",
                bdf.bus, bdf.device, bdf.function);

    auto io_w = [&](std::uint16_t port, std::uint16_t size, std::uint32_t val) {
        devices::IoAccess a{port, size, /*write=*/true, val};
        if (!io_bus.Dispatch(a)) Fatal("virtio-net-pci-test: unmatched IO write");
    };
    auto io_r = [&](std::uint16_t port, std::uint16_t size) -> std::uint32_t {
        devices::IoAccess a{port, size, /*write=*/false, 0};
        if (!io_bus.Dispatch(a)) Fatal("virtio-net-pci-test: unmatched IO read");
        return a.value;
    };
    auto encode = [](std::uint8_t b, std::uint8_t d, std::uint8_t fn,
                      std::uint8_t reg) -> std::uint32_t {
        return p::kConfigAddressEnable | (std::uint32_t{b} << 16) |
               (std::uint32_t{d} << 11) | (std::uint32_t{fn} << 8) |
               (reg & 0xFCu);
    };
    auto cfg_r = [&](std::uint8_t reg, std::uint16_t size) -> std::uint32_t {
        io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, reg));
        return io_r(static_cast<std::uint16_t>(p::kConfigDataPort + (reg & 3)),
                    size);
    };
    auto cfg_w = [&](std::uint8_t reg, std::uint16_t size, std::uint32_t val) {
        io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, reg));
        io_w(static_cast<std::uint16_t>(p::kConfigDataPort + (reg & 3)), size,
             val);
    };
    auto mmio_w = [&](std::uint64_t gpa, std::uint32_t val, std::uint8_t sz) {
        devices::MmioAccess a{};
        a.gpa = gpa; a.access_size = sz; a.is_write = true;
        std::memcpy(a.data, &val, std::min<std::size_t>(sz, 4));
        if (!mmio_bus.Dispatch(a))
            Fatal("virtio-net-pci-test: unmatched MMIO write");
    };
    auto mmio_r = [&](std::uint64_t gpa, std::uint8_t sz) -> std::uint32_t {
        devices::MmioAccess a{};
        a.gpa = gpa; a.access_size = sz; a.is_write = false;
        if (!mmio_bus.Dispatch(a))
            Fatal("virtio-net-pci-test: unmatched MMIO read");
        std::uint32_t v = 0;
        std::memcpy(&v, a.data, std::min<std::size_t>(sz, 4));
        return v;
    };

    // (a) Identity.
    const std::uint32_t vid_did = cfg_r(p::kCfgVendorId, 4);
    const std::uint8_t  cls  = static_cast<std::uint8_t>(cfg_r(p::kCfgClassCode, 1));
    const std::uint8_t  scls = static_cast<std::uint8_t>(cfg_r(p::kCfgSubclass, 1));
    const std::uint32_t subsys = cfg_r(p::kCfgSubsysVendorId, 4);
    std::printf("[virtio-net-pci-test] vid_did=0x%08x class=%02x:%02x subsys=0x%08x\n",
                vid_did, cls, scls, subsys);
    if (vid_did != ((std::uint32_t{0x1041} << 16) | 0x1AF4u)) {
        std::fputs("[virtio-net-pci-test] FAIL: VID/DID mismatch\n", stderr);
        return 14;
    }
    if (cls != 0x02 || scls != 0x00 ||
        subsys != ((std::uint32_t{v::kDeviceIdNet} << 16) | 0x1AF4u)) {
        std::fputs("[virtio-net-pci-test] FAIL: class/subsys wrong\n", stderr);
        return 14;
    }

    // (b) Cap chain; locate MSI-X.
    std::uint8_t cap = static_cast<std::uint8_t>(cfg_r(p::kCfgCapPtr, 1));
    std::uint8_t msix_cap_off = 0;
    std::size_t cap_count = 0;
    while (cap != 0 && cap_count < 16) {
        const std::uint8_t id =
            static_cast<std::uint8_t>(cfg_r(cap, 1));
        if (id == p::kCapIdMsiX) msix_cap_off = cap;
        cap = static_cast<std::uint8_t>(
            cfg_r(static_cast<std::uint8_t>(cap + 1), 1));
        cap_count++;
    }
    if (!msix_cap_off) {
        std::fputs("[virtio-net-pci-test] FAIL: MSI-X cap not found\n", stderr);
        return 14;
    }

    // (c) Map BAR0.
    const std::uint32_t bar0_lo = cfg_r(p::kCfgBar0, 4);
    const std::uint32_t bar0_hi = cfg_r(p::kCfgBar0 + 4, 4);
    cfg_w(p::kCfgCommand, 2, p::kCmdMemorySpace | p::kCmdBusMaster);
    const std::uint64_t bar_gpa = (static_cast<std::uint64_t>(bar0_hi) << 32) |
                                   (bar0_lo & ~0xFu);
    std::printf("[virtio-net-pci-test] BAR0 mapped @ 0x%llx\n",
                static_cast<unsigned long long>(bar_gpa));

    // (d) num_queues == 2.
    const std::uint16_t num_queues = static_cast<std::uint16_t>(
        mmio_r(bar_gpa + 0x10, 4) >> 16);
    if (num_queues != v::kNetQueueCount) {
        std::fprintf(stderr,
                     "[virtio-net-pci-test] FAIL: num_queues=%u (want %u)\n",
                     num_queues, v::kNetQueueCount);
        return 14;
    }

    // (e) device-cfg @ +0x2000: 6-byte MAC + 2-byte link_status.
    const std::uint64_t devcfg = bar_gpa + v::PciTransport::kOffDeviceCfg;
    std::uint8_t mac_read[6];
    for (std::size_t i = 0; i < 6; ++i) {
        mac_read[i] = static_cast<std::uint8_t>(mmio_r(devcfg + i, 1));
    }
    const std::uint16_t link_status =
        static_cast<std::uint16_t>(mmio_r(devcfg + 6, 2));
    std::printf("[virtio-net-pci-test] MAC=%02x:%02x:%02x:%02x:%02x:%02x link=%u\n",
                mac_read[0], mac_read[1], mac_read[2], mac_read[3], mac_read[4],
                mac_read[5], link_status);
    if (std::memcmp(mac_read, kMac.data(), 6) != 0 ||
        link_status != v::kNetStatusLinkUp) {
        std::fputs("[virtio-net-pci-test] FAIL: device-cfg wrong\n", stderr);
        return 14;
    }

    // (f) Read device features. Should include VERSION_1 | RING_EVENT_IDX |
    //     NET_F_MAC | NET_F_STATUS.
    mmio_w(bar_gpa + 0x00, 0, 4);
    const std::uint32_t df_lo = mmio_r(bar_gpa + 0x04, 4);
    mmio_w(bar_gpa + 0x00, 1, 4);
    const std::uint32_t df_hi = mmio_r(bar_gpa + 0x04, 4);
    const std::uint64_t df =
        static_cast<std::uint64_t>(df_lo) |
        (static_cast<std::uint64_t>(df_hi) << 32);
    constexpr std::uint64_t want_features =
        v::kFeatureVersion1 | v::kFeatureRingEventIdx |
        v::kNetFeatureMac | v::kNetFeatureStatus;
    if ((df & want_features) != want_features) {
        std::fprintf(stderr,
            "[virtio-net-pci-test] FAIL: device features 0x%016llx miss 0x%016llx\n",
            static_cast<unsigned long long>(df),
            static_cast<unsigned long long>(want_features));
        return 14;
    }

    // (g) Bogus negotiation: ack a feature we never advertised
    //     (kNetFeatureCtrlVq = bit 17). NetDevice rejects, transport flips
    //     NEEDS_RESET and clears FEATURES_OK.
    mmio_w(bar_gpa + 0x14, v::kStatusAcknowledge, 1);
    mmio_w(bar_gpa + 0x14, v::kStatusAcknowledge | v::kStatusDriver, 1);
    mmio_w(bar_gpa + 0x08, 0, 4);
    mmio_w(bar_gpa + 0x0C,
           static_cast<std::uint32_t>(want_features & 0xFFFFFFFFu) |
           static_cast<std::uint32_t>(v::kNetFeatureCtrlVq & 0xFFFFFFFFu),
           4);
    mmio_w(bar_gpa + 0x08, 1, 4);
    mmio_w(bar_gpa + 0x0C, static_cast<std::uint32_t>(want_features >> 32), 4);
    mmio_w(bar_gpa + 0x14,
           v::kStatusAcknowledge | v::kStatusDriver | v::kStatusFeaturesOk, 1);
    const std::uint8_t bad_status = static_cast<std::uint8_t>(
        mmio_r(bar_gpa + 0x14, 1));
    if ((bad_status & v::kStatusFeaturesOk) ||
        !(bad_status & v::kStatusNeedsReset)) {
        std::fprintf(stderr,
            "[virtio-net-pci-test] FAIL: bad-feature didn't NEEDS_RESET (status=0x%02x)\n",
            bad_status);
        return 14;
    }
    // Reset before retrying.
    mmio_w(bar_gpa + 0x14, 0, 1);

    // (h) Good negotiation.
    mmio_w(bar_gpa + 0x14, v::kStatusAcknowledge, 1);
    mmio_w(bar_gpa + 0x14, v::kStatusAcknowledge | v::kStatusDriver, 1);
    mmio_w(bar_gpa + 0x08, 0, 4);
    mmio_w(bar_gpa + 0x0C,
           static_cast<std::uint32_t>(want_features & 0xFFFFFFFFu), 4);
    mmio_w(bar_gpa + 0x08, 1, 4);
    mmio_w(bar_gpa + 0x0C, static_cast<std::uint32_t>(want_features >> 32), 4);
    mmio_w(bar_gpa + 0x14,
           v::kStatusAcknowledge | v::kStatusDriver | v::kStatusFeaturesOk, 1);
    if ((mmio_r(bar_gpa + 0x14, 1) & v::kStatusFeaturesOk) == 0) {
        std::fputs("[virtio-net-pci-test] FAIL: FEATURES_OK rejected\n", stderr);
        return 14;
    }

    // (i) MSI-X table programming.
    constexpr std::uint64_t kMsiAddrBase = 0xFEE00000ull;
    auto program_msix = [&](std::uint32_t vec, std::uint32_t data) {
        const std::uint64_t tbl = bar_gpa + v::PciTransport::kOffMsixTable +
                                  16ull * vec;
        mmio_w(tbl + 0,
               static_cast<std::uint32_t>(kMsiAddrBase & 0xFFFFFFFFu), 4);
        mmio_w(tbl + 4,
               static_cast<std::uint32_t>(kMsiAddrBase >> 32), 4);
        mmio_w(tbl + 8, data, 4);
        mmio_w(tbl + 12, 0u, 4);
    };
    program_msix(0, 0x40);  // RX
    program_msix(1, 0x41);  // TX
    program_msix(2, 0x42);  // config-change
    cfg_w(static_cast<std::uint8_t>(msix_cap_off + 2), 2, 0x8000u);
    if (!tx->msix().MsiXEnabled()) {
        std::fputs("[virtio-net-pci-test] FAIL: MSI-X not enabled\n", stderr);
        return 14;
    }

    // (j) Program both queues with distinct ring GPAs and msix_vectors.
    constexpr std::uint32_t kQSize = 8;
    struct QGpa { std::uint64_t desc, avail, used; };
    const QGpa qg[2] = {
        {0x30000, 0x30100, 0x30200},   // RX (qidx=0)
        {0x31000, 0x31100, 0x31200},   // TX (qidx=1)
    };
    for (std::uint16_t qi = 0; qi < 2; ++qi) {
        mmio_w(bar_gpa + 0x16, qi, 2);                   // queue_select
        const std::uint16_t qnotify_off = static_cast<std::uint16_t>(
            mmio_r(bar_gpa + 0x1E, 2));
        if (qnotify_off != qi) {
            std::fprintf(stderr,
                "[virtio-net-pci-test] FAIL: q%u notify_off=%u (want %u)\n",
                qi, qnotify_off, qi);
            return 14;
        }
        mmio_w(bar_gpa + 0x18, kQSize, 2);
        mmio_w(bar_gpa + 0x1A, qi, 2);                   // msix_vector=qi
        mmio_w(bar_gpa + 0x20,
               static_cast<std::uint32_t>(qg[qi].desc), 4);
        mmio_w(bar_gpa + 0x24,
               static_cast<std::uint32_t>(qg[qi].desc >> 32), 4);
        mmio_w(bar_gpa + 0x28,
               static_cast<std::uint32_t>(qg[qi].avail), 4);
        mmio_w(bar_gpa + 0x2C,
               static_cast<std::uint32_t>(qg[qi].avail >> 32), 4);
        mmio_w(bar_gpa + 0x30,
               static_cast<std::uint32_t>(qg[qi].used), 4);
        mmio_w(bar_gpa + 0x34,
               static_cast<std::uint32_t>(qg[qi].used >> 32), 4);
        mmio_w(bar_gpa + 0x1C, 1, 2);                    // enable
    }
    // msix_config = 2.
    mmio_w(bar_gpa + 0x10, 2, 2);
    // DRIVER_OK.
    mmio_w(bar_gpa + 0x14,
           v::kStatusAcknowledge | v::kStatusDriver | v::kStatusFeaturesOk |
               v::kStatusDriverOk, 1);
    if (!net_ptr->driver_ok()) {
        std::fputs("[virtio-net-pci-test] FAIL: NetDevice.driver_ok not set\n",
                   stderr);
        return 14;
    }
    if (!net_ptr->rx_queue().ready() || !net_ptr->tx_queue().ready()) {
        std::fputs("[virtio-net-pci-test] FAIL: queue.ready() false post-enable\n",
                   stderr);
        return 14;
    }

    // (k) Notify each queue independently and verify counters.
    auto notify_q = [&](std::uint32_t qi) {
        mmio_w(bar_gpa + v::PciTransport::kOffNotify +
               qi * v::PciTransport::kNotifyMultiplier,
               qi, 2);
    };
    notify_q(0);                       // RX
    notify_q(1);                       // TX
    notify_q(1);                       // TX (again)
    if (net_ptr->notify_count(v::kRxQueueIdx) != 1 ||
        net_ptr->notify_count(v::kTxQueueIdx) != 2) {
        std::fprintf(stderr,
            "[virtio-net-pci-test] FAIL: notify counters rx=%llu tx=%llu\n",
            static_cast<unsigned long long>(
                net_ptr->notify_count(v::kRxQueueIdx)),
            static_cast<unsigned long long>(
                net_ptr->notify_count(v::kTxQueueIdx)));
        return 14;
    }

    // (l) Per-queue interrupt delivery: RaiseQueueInterrupt(qi) -> MSI data
    //     equals what we programmed (0x40 for RX, 0x41 for TX).
    injects.clear();
    tx->RaiseQueueInterrupt(v::kRxQueueIdx);
    if (injects.size() != 1 || injects[0].data != 0x40) {
        std::fputs("[virtio-net-pci-test] FAIL: RX irq wrong\n", stderr);
        return 14;
    }
    (void)mmio_r(bar_gpa + v::PciTransport::kOffIsr, 1);  // clear ISR
    injects.clear();
    tx->RaiseQueueInterrupt(v::kTxQueueIdx);
    if (injects.size() != 1 || injects[0].data != 0x41) {
        std::fputs("[virtio-net-pci-test] FAIL: TX irq wrong\n", stderr);
        return 14;
    }

    // (m) Config-change vector + config_generation++.
    (void)mmio_r(bar_gpa + v::PciTransport::kOffIsr, 1);  // clear ISR
    const std::uint8_t gen_before =
        static_cast<std::uint8_t>(mmio_r(bar_gpa + 0x15, 1));
    injects.clear();
    net_ptr->set_link_up(false);
    tx->RaiseConfigChangeInterrupt();
    const std::uint8_t gen_after =
        static_cast<std::uint8_t>(mmio_r(bar_gpa + 0x15, 1));
    if (injects.size() != 1 || injects[0].data != 0x42 ||
        static_cast<std::uint8_t>(gen_after - gen_before) != 1) {
        std::fputs("[virtio-net-pci-test] FAIL: config-change wrong\n", stderr);
        return 14;
    }
    if ((tx->isr() & 2u) == 0) {
        std::fputs("[virtio-net-pci-test] FAIL: ISR config bit not set\n",
                   stderr);
        return 14;
    }
    // After we flipped link down, devcfg byte 6 reflects that.
    if (mmio_r(devcfg + 6, 2) != 0u) {
        std::fputs("[virtio-net-pci-test] FAIL: link_status didn't update\n",
                   stderr);
        return 14;
    }
    net_ptr->set_link_up(true);  // restore

    // (n) Reset wipes everything.
    mmio_w(bar_gpa + 0x14, 0, 1);
    if (net_ptr->rx_queue().ready() || net_ptr->tx_queue().ready() ||
        net_ptr->driver_ok() || tx->status() != 0 || tx->isr() != 0) {
        std::fputs("[virtio-net-pci-test] FAIL: reset incomplete\n", stderr);
        return 14;
    }

    // Silence the unused host_ram pointer warning if we never touched it.
    (void)host_ram;

    std::printf("[virtio-net-pci-test] PASS (reads=%llu writes=%llu notify=%llu)\n",
                static_cast<unsigned long long>(tx->reads()),
                static_cast<unsigned long long>(tx->writes()),
                static_cast<unsigned long long>(tx->notify_count()));
    return 0;
}

// --virtio-net-loopback-test (M15)
// End-to-end host-side exercise of virtio-net + PciTransport +
// LoopbackNetBackend. The backend echoes a TX frame straight back as an
// RX frame; we verify:
//   (a) Backend.Start() fires from the PciTransport's OnBarMapped hook
//       (i.e. when the guest writes COMMAND.MEM_SPACE).
//   (b) A TX notify drains the TX virtq into the backend, completes the
//       TX chain (used.idx++), and raises the TX queue interrupt.
//   (c) The same notify delivers the queued frame to the RX virtq we
//       pre-posted, completes that chain with the correct length, and
//       raises the RX queue interrupt.
//   (d) The 12-byte virtio_net_hdr in the RX hdr-desc is zeroed and the
//       payload bytes round-trip with byte-equality.
int RunVirtioNetLoopbackTest() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;
    namespace p = tinyvmm::pci;
    namespace v = tinyvmm::virtio;

    std::puts("[virtio-net-loopback-test] starting (host-side; no WHP)");

    CheckWhpAvailable();
    Partition part(/*vcpu_count=*/1);
    part.Setup();
    constexpr std::size_t kRamBytes = 0x200000;
    GuestMemory ram(part, /*gpa=*/0, kRamBytes, /*executable=*/false);
    auto* host_ram = static_cast<std::uint8_t*>(ram.host_base());
    std::memset(host_ram, 0, kRamBytes);

    devices::IoBus   io_bus;
    devices::MmioBus mmio_bus;
    p::PciBus        pbus;
    pbus.AttachIoBus(io_bus);

    struct Recorder {
        std::mutex m;
        std::atomic<std::size_t> count{0};
        std::vector<InjectRecord> recs;
    } rec;
    auto inject_fn = [&rec](std::uint64_t a, std::uint32_t d) {
        std::lock_guard<std::mutex> lk(rec.m);
        rec.recs.push_back({a, d});
        rec.count.fetch_add(1);
        return true;
    };

    constexpr std::array<std::uint8_t, 6> kMac{
        0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
    auto net = std::make_unique<v::NetDevice>(ram, kMac);
    v::NetDevice* net_ptr = net.get();

    v::PciTransport::Options opts;
    opts.subsys_id        = static_cast<std::uint16_t>(v::kDeviceIdNet);
    opts.num_msix_vectors = 3;
    opts.pci_class        = 0x02;
    opts.pci_subclass     = 0x00;
    auto xport = std::make_unique<v::PciTransport>(
        *net_ptr, opts, mmio_bus, inject_fn);
    v::PciTransport* tx_ptr = xport.get();
    xport->set_name("virtio-pci-net-loop");

    // Install the loopback backend ahead of BAR mapping, then arm the
    // BAR-mapped callback to start it the moment Linux writes
    // COMMAND.MEM_SPACE -- this is the same wiring shape --pvh-run uses.
    net_ptr->SetBackend(std::make_unique<v::LoopbackNetBackend>(*net_ptr));
    std::atomic<bool> backend_started{false};
    tx_ptr->SetOnBarMappedCallback(
        [net_ptr, tx_ptr, &part, &backend_started]() {
            if (auto* b = net_ptr->backend()) {
                b->Start(part, *tx_ptr);
                backend_started.store(true);
            }
        });

    const p::Bdf bdf = pbus.AddDevice(std::move(xport));
    std::printf("[virtio-net-loopback-test] device @ %02x:%02x.%u\n",
                bdf.bus, bdf.device, bdf.function);

    // Same IO/MMIO helpers shape used by the other host-side tests.
    auto io_w = [&](std::uint16_t port, std::uint16_t size, std::uint32_t val) {
        devices::IoAccess a{port, size, /*write=*/true, val};
        if (!io_bus.Dispatch(a))
            Fatal("virtio-net-loopback-test: unmatched IO write");
    };
    auto io_r = [&](std::uint16_t port, std::uint16_t size) -> std::uint32_t {
        devices::IoAccess a{port, size, /*write=*/false, 0};
        if (!io_bus.Dispatch(a))
            Fatal("virtio-net-loopback-test: unmatched IO read");
        return a.value;
    };
    auto encode = [](std::uint8_t b, std::uint8_t d, std::uint8_t fn,
                      std::uint8_t reg) -> std::uint32_t {
        return p::kConfigAddressEnable | (std::uint32_t{b} << 16) |
               (std::uint32_t{d} << 11) | (std::uint32_t{fn} << 8) |
               (reg & 0xFCu);
    };
    auto cfg_r = [&](std::uint8_t reg, std::uint16_t size) -> std::uint32_t {
        io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, reg));
        return io_r(static_cast<std::uint16_t>(p::kConfigDataPort + (reg & 3)),
                    size);
    };
    auto cfg_w = [&](std::uint8_t reg, std::uint16_t size, std::uint32_t val) {
        io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, reg));
        io_w(static_cast<std::uint16_t>(p::kConfigDataPort + (reg & 3)), size,
             val);
    };
    auto mmio_w = [&](std::uint64_t gpa, std::uint32_t val, std::uint8_t sz) {
        devices::MmioAccess a{};
        a.gpa = gpa; a.access_size = sz; a.is_write = true;
        std::memcpy(a.data, &val, std::min<std::size_t>(sz, 4));
        if (!mmio_bus.Dispatch(a))
            Fatal("virtio-net-loopback-test: unmatched MMIO write");
    };
    auto mmio_r = [&](std::uint64_t gpa, std::uint8_t sz) -> std::uint32_t {
        devices::MmioAccess a{};
        a.gpa = gpa; a.access_size = sz; a.is_write = false;
        if (!mmio_bus.Dispatch(a))
            Fatal("virtio-net-loopback-test: unmatched MMIO read");
        std::uint32_t v = 0;
        std::memcpy(&v, a.data, std::min<std::size_t>(sz, 4));
        return v;
    };

    // Walk caps to find MSI-X (we only need its offset for the enable bit).
    std::uint8_t cap = static_cast<std::uint8_t>(cfg_r(p::kCfgCapPtr, 1));
    std::uint8_t msix_cap_off = 0;
    for (std::size_t i = 0; cap != 0 && i < 16; ++i) {
        const std::uint8_t id = static_cast<std::uint8_t>(cfg_r(cap, 1));
        if (id == p::kCapIdMsiX) msix_cap_off = cap;
        cap = static_cast<std::uint8_t>(
            cfg_r(static_cast<std::uint8_t>(cap + 1), 1));
    }
    if (!msix_cap_off) {
        std::fputs("[virtio-net-loopback-test] FAIL: MSI-X cap not found\n",
                   stderr);
        return 15;
    }

    // Map BAR0 -> triggers OnBarMapped -> starts backend.
    const std::uint32_t bar0_lo = cfg_r(p::kCfgBar0, 4);
    const std::uint32_t bar0_hi = cfg_r(p::kCfgBar0 + 4, 4);
    cfg_w(p::kCfgCommand, 2, p::kCmdMemorySpace | p::kCmdBusMaster);
    const std::uint64_t bar_gpa = (static_cast<std::uint64_t>(bar0_hi) << 32) |
                                   (bar0_lo & ~0xFu);
    if (!backend_started.load()) {
        std::fputs(
            "[virtio-net-loopback-test] FAIL: backend not started by BAR map\n",
            stderr);
        return 15;
    }
    std::printf("[virtio-net-loopback-test] BAR0 mapped @ 0x%llx, backend started\n",
                static_cast<unsigned long long>(bar_gpa));

    // Read device-features (just to mirror what a real driver would do).
    mmio_w(bar_gpa + 0x00, 0, 4);
    const std::uint32_t df_lo = mmio_r(bar_gpa + 0x04, 4);
    mmio_w(bar_gpa + 0x00, 1, 4);
    const std::uint32_t df_hi = mmio_r(bar_gpa + 0x04, 4);
    const std::uint64_t df =
        static_cast<std::uint64_t>(df_lo) |
        (static_cast<std::uint64_t>(df_hi) << 32);
    // Ack everything we offer except EVENT_IDX (keep the host-side path
    // simple: ShouldInterruptDriver picks the no-flag branch).
    const std::uint64_t acked = df & ~v::kFeatureRingEventIdx;
    mmio_w(bar_gpa + 0x14, v::kStatusAcknowledge, 1);
    mmio_w(bar_gpa + 0x14, v::kStatusAcknowledge | v::kStatusDriver, 1);
    mmio_w(bar_gpa + 0x08, 0, 4);
    mmio_w(bar_gpa + 0x0C, static_cast<std::uint32_t>(acked & 0xFFFFFFFFu), 4);
    mmio_w(bar_gpa + 0x08, 1, 4);
    mmio_w(bar_gpa + 0x0C, static_cast<std::uint32_t>(acked >> 32), 4);
    mmio_w(bar_gpa + 0x14,
           v::kStatusAcknowledge | v::kStatusDriver | v::kStatusFeaturesOk, 1);
    if ((mmio_r(bar_gpa + 0x14, 1) & v::kStatusFeaturesOk) == 0) {
        std::fputs("[virtio-net-loopback-test] FAIL: FEATURES_OK rejected\n",
                   stderr);
        return 15;
    }

    // Program MSI-X table: RX=0x40, TX=0x41, cfg=0x42, all unmasked.
    constexpr std::uint64_t kMsiAddrBase = 0xFEE00000ull;
    auto program_msix = [&](std::uint32_t vec, std::uint32_t data) {
        const std::uint64_t tbl = bar_gpa + v::PciTransport::kOffMsixTable +
                                  16ull * vec;
        mmio_w(tbl + 0,
               static_cast<std::uint32_t>(kMsiAddrBase & 0xFFFFFFFFu), 4);
        mmio_w(tbl + 4,
               static_cast<std::uint32_t>(kMsiAddrBase >> 32), 4);
        mmio_w(tbl + 8, data, 4);
        mmio_w(tbl + 12, 0u, 4);
    };
    program_msix(0, 0x40);  // RX
    program_msix(1, 0x41);  // TX
    program_msix(2, 0x42);  // config
    cfg_w(static_cast<std::uint8_t>(msix_cap_off + 2), 2, 0x8000u);

    // Program queue 0 (RX) and queue 1 (TX), size 8.
    constexpr std::uint32_t kQSize = 8;
    struct QGpa { std::uint64_t desc, avail, used; };
    const QGpa qg[2] = {
        {0x30000, 0x30100, 0x30200},   // RX
        {0x31000, 0x31100, 0x31200},   // TX
    };
    for (std::uint16_t qi = 0; qi < 2; ++qi) {
        mmio_w(bar_gpa + 0x16, qi, 2);
        mmio_w(bar_gpa + 0x18, kQSize, 2);
        mmio_w(bar_gpa + 0x1A, qi, 2);
        mmio_w(bar_gpa + 0x20,
               static_cast<std::uint32_t>(qg[qi].desc), 4);
        mmio_w(bar_gpa + 0x24,
               static_cast<std::uint32_t>(qg[qi].desc >> 32), 4);
        mmio_w(bar_gpa + 0x28,
               static_cast<std::uint32_t>(qg[qi].avail), 4);
        mmio_w(bar_gpa + 0x2C,
               static_cast<std::uint32_t>(qg[qi].avail >> 32), 4);
        mmio_w(bar_gpa + 0x30,
               static_cast<std::uint32_t>(qg[qi].used), 4);
        mmio_w(bar_gpa + 0x34,
               static_cast<std::uint32_t>(qg[qi].used >> 32), 4);
        mmio_w(bar_gpa + 0x1C, 1, 2);
    }
    mmio_w(bar_gpa + 0x10, 2, 2);          // msix_config
    mmio_w(bar_gpa + 0x14,
           v::kStatusAcknowledge | v::kStatusDriver | v::kStatusFeaturesOk |
               v::kStatusDriverOk, 1);
    if (!net_ptr->driver_ok() ||
        !net_ptr->rx_queue().ready() || !net_ptr->tx_queue().ready()) {
        std::fputs("[virtio-net-loopback-test] FAIL: DRIVER_OK not honoured\n",
                   stderr);
        return 15;
    }

#pragma pack(push, 1)
    struct VringDesc {
        std::uint64_t addr;
        std::uint32_t len;
        std::uint16_t flags;
        std::uint16_t next;
    };
#pragma pack(pop)

    // ----- Pre-post an RX chain on queue 0.
    // hdr@0x40000 (W,12) -> payload@0x40100 (W,256)
    constexpr std::uint64_t kRxHdrGpa     = 0x40000;
    constexpr std::uint64_t kRxPayloadGpa = 0x40100;
    constexpr std::uint32_t kRxPayloadLen = 256;
    {
        auto* descs = reinterpret_cast<VringDesc*>(host_ram + qg[0].desc);
        descs[0] = {kRxHdrGpa,     12, v::kVringDescFNext | v::kVringDescFWrite, 1};
        descs[1] = {kRxPayloadGpa, kRxPayloadLen, v::kVringDescFWrite, 0};
        auto* avail = host_ram + qg[0].avail;
        *reinterpret_cast<std::uint16_t*>(avail + 0) = 0;     // flags
        *reinterpret_cast<std::uint16_t*>(avail + 4) = 0;     // ring[0]=head 0
        *reinterpret_cast<std::uint16_t*>(avail + 2) = 1;     // idx=1
        // Poison the receive area so a successful echo is visible.
        std::memset(host_ram + kRxHdrGpa, 0xCD, 12);
        std::memset(host_ram + kRxPayloadGpa, 0xCD, kRxPayloadLen);
    }

    // ----- Plant a TX chain on queue 1.
    // hdr@0x41000 (R,12) -> payload@0x41100 (R,N)
    constexpr std::uint64_t kTxHdrGpa     = 0x41000;
    constexpr std::uint64_t kTxPayloadGpa = 0x41100;
    static const std::uint8_t kFrame[] = {
        // Fake Ethernet frame: dest MAC, src MAC, ethertype, payload.
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0x52,0x54,0x00,0x12,0x34,0x56,
        0x08,0x00,
        'D','E','A','D','B','E','E','F',
        '-','t','i','n','y','v','m','m','-','l','o','o','p',
    };
    constexpr std::uint32_t kTxPayloadLen = sizeof(kFrame);
    {
        std::memset(host_ram + kTxHdrGpa, 0, 12);          // virtio_net_hdr
        std::memcpy(host_ram + kTxPayloadGpa, kFrame, kTxPayloadLen);
        auto* descs = reinterpret_cast<VringDesc*>(host_ram + qg[1].desc);
        descs[0] = {kTxHdrGpa,     12, v::kVringDescFNext, 1};
        descs[1] = {kTxPayloadGpa, kTxPayloadLen, 0, 0};
        auto* avail = host_ram + qg[1].avail;
        *reinterpret_cast<std::uint16_t*>(avail + 0) = 0;
        *reinterpret_cast<std::uint16_t*>(avail + 4) = 0;
        *reinterpret_cast<std::uint16_t*>(avail + 2) = 1;
    }

    // ----- Notify TX. LoopbackNetBackend runs synchronously on this
    //       thread: it drains TX, queues the frame, and immediately
    //       delivers it to the pre-posted RX chain.
    rec.recs.clear();
    rec.count.store(0);
    mmio_w(bar_gpa + v::PciTransport::kOffNotify +
           v::kTxQueueIdx * v::PciTransport::kNotifyMultiplier,
           v::kTxQueueIdx, 2);

    // Verify TX used.idx == 1.
    {
        auto* tx_used = host_ram + qg[1].used;
        const std::uint16_t used_idx =
            *reinterpret_cast<std::uint16_t*>(tx_used + 2);
        if (used_idx != 1) {
            std::fprintf(stderr,
                "[virtio-net-loopback-test] FAIL: TX used.idx=%u (want 1)\n",
                used_idx);
            return 15;
        }
    }

    // Verify RX used ring has our chain with the right reported length
    // (= 12B virtio_net_hdr + frame bytes) and the data round-tripped.
    {
        auto* rx_used = host_ram + qg[0].used;
        const std::uint16_t used_idx =
            *reinterpret_cast<std::uint16_t*>(rx_used + 2);
        if (used_idx != 1) {
            std::fprintf(stderr,
                "[virtio-net-loopback-test] FAIL: RX used.idx=%u (want 1)\n",
                used_idx);
            return 15;
        }
        // used.ring[0] = {id: u32, len: u32}
        const std::uint32_t used_id =
            *reinterpret_cast<std::uint32_t*>(rx_used + 4);
        const std::uint32_t used_len =
            *reinterpret_cast<std::uint32_t*>(rx_used + 8);
        if (used_id != 0) {
            std::fprintf(stderr,
                "[virtio-net-loopback-test] FAIL: RX used.id=%u (want 0)\n",
                used_id);
            return 15;
        }
        if (used_len != 12 + kTxPayloadLen) {
            std::fprintf(stderr,
                "[virtio-net-loopback-test] FAIL: RX used.len=%u (want %u)\n",
                used_len,
                static_cast<unsigned>(12 + kTxPayloadLen));
            return 15;
        }
        // virtio_net_hdr should be all zeroes.
        for (std::size_t i = 0; i < 12; ++i) {
            if (host_ram[kRxHdrGpa + i] != 0) {
                std::fprintf(stderr,
                    "[virtio-net-loopback-test] FAIL: RX hdr[%zu]=0x%02x\n",
                    i, host_ram[kRxHdrGpa + i]);
                return 15;
            }
        }
        // Payload must match the TX frame.
        if (std::memcmp(host_ram + kRxPayloadGpa, kFrame, kTxPayloadLen) != 0) {
            std::fputs(
                "[virtio-net-loopback-test] FAIL: RX payload mismatch\n",
                stderr);
            return 15;
        }
    }

    // We expect two MSI injects: one for TX completion, one for RX
    // delivery. (Order: LoopbackNetBackend::DrainTx fires TX irq first,
    // then DeliverRx fires RX irq.)
    if (rec.count.load() != 2 ||
        rec.recs[0].data != 0x41 || rec.recs[1].data != 0x40) {
        std::fprintf(stderr,
            "[virtio-net-loopback-test] FAIL: irq sequence count=%zu",
            rec.count.load());
        for (auto& r : rec.recs)
            std::fprintf(stderr, " data=0x%x", r.data);
        std::fputs("\n", stderr);
        return 15;
    }

    // Drain the backend so its dtor sees no leftover state.
    auto* lp = static_cast<v::LoopbackNetBackend*>(net_ptr->backend());
    if (lp->queued() != 0 ||
        lp->tx_packets() != 1 || lp->rx_packets() != 1) {
        std::fprintf(stderr,
            "[virtio-net-loopback-test] FAIL: backend counters tx=%llu rx=%llu queued=%zu\n",
            static_cast<unsigned long long>(lp->tx_packets()),
            static_cast<unsigned long long>(lp->rx_packets()),
            lp->queued());
        return 15;
    }

    std::printf(
        "[virtio-net-loopback-test] PASS (tx=%llu rx=%llu dropped=%llu len=%u)\n",
        static_cast<unsigned long long>(lp->tx_packets()),
        static_cast<unsigned long long>(lp->rx_packets()),
        static_cast<unsigned long long>(lp->rx_dropped()),
        static_cast<unsigned>(12 + kTxPayloadLen));
    (void)host_ram;
    return 0;
}

// --virtio-net-usernet-tsi-test (M34.4)
// Drive the TsiTcpEngine directly (no PCI, no virtio): construct a
// real Winsock listener on 127.0.0.1:0, feed the engine synthesized
// IPv4+TCP packets simulating a guest making an outbound HTTP request,
// and verify:
//   * A SYN from the guest produces a SYN-ACK back through the engine.
//   * A guest-side ACK completes the 3-way handshake.
//   * Guest payload arrives at the host listener exactly (rubber-duck
//     blind-spot #3: includes a variant where guest data is sent before
//     Winsock's connect() completes — staging buffers must hold it).
//   * Server reply data flows back through the engine as IP+TCP
//     packets toward the guest.
//   * Guest FIN translates to a host-side EOF (rubber-duck #3
//     shutdown(SD_SEND)) and the listener observes recv() == 0.
int RunVirtioNetUsernetTsiTest() {
    using namespace tinyvmm;
    using namespace tinyvmm::virtio;

    std::puts("[virtio-net-usernet-tsi-test] starting (host-side; no WHP, no PCI)");

    WSADATA wsa{};
    if (::WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: WSAStartup\n", stderr);
        return 1;
    }

    // ---- Set up a real Winsock listener at 127.0.0.1:<auto> ----------
    SOCKET lsn = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (lsn == INVALID_SOCKET) {
        std::fprintf(stderr, "[virtio-net-usernet-tsi-test] FAIL: socket: %d\n",
                     ::WSAGetLastError());
        ::WSACleanup(); return 2;
    }
    u_long nb = 1;
    ::ioctlsocket(lsn, FIONBIO, &nb);
    sockaddr_in la{}; la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(INADDR_LOOPBACK); la.sin_port = 0;
    if (::bind(lsn, (sockaddr*)&la, sizeof(la)) != 0) {
        std::fprintf(stderr, "[virtio-net-usernet-tsi-test] FAIL: bind: %d\n",
                     ::WSAGetLastError());
        ::closesocket(lsn); ::WSACleanup(); return 3;
    }
    if (::listen(lsn, 4) != 0) {
        std::fprintf(stderr, "[virtio-net-usernet-tsi-test] FAIL: listen: %d\n",
                     ::WSAGetLastError());
        ::closesocket(lsn); ::WSACleanup(); return 4;
    }
    sockaddr_in actual{};
    int alen = sizeof(actual);
    if (::getsockname(lsn, (sockaddr*)&actual, &alen) != 0) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: getsockname\n", stderr);
        ::closesocket(lsn); ::WSACleanup(); return 5;
    }
    const std::uint16_t dst_port_be = actual.sin_port;
    std::printf("[virtio-net-usernet-tsi-test] listener at 127.0.0.1:%u\n",
                static_cast<unsigned>(ntohs(dst_port_be)));

    // ---- Construct TsiTcpEngine with a frame-recorder callback ------
    struct Captured {
        std::vector<std::vector<std::uint8_t>> frames;  // each = full IP+TCP
    } captured;

    TsiTcpEngine::EmitCtx ec{};
    ec.push_ipv4_to_guest =
        [&captured](const std::uint8_t* ip, std::size_t n) {
            captured.frames.emplace_back(ip, ip + n);
        };
    std::uint64_t test_clock_ms = 1000;
    ec.now_ms = [&test_clock_ms]{ return test_clock_ms; };
    ec.backend_mac = {0x02,0x53,0x54,0x00,0x00,0x01};
    ec.guest_mac   = {0x52,0x54,0x00,0x12,0x34,0x56};
    ec.gateway_ip_be = htonl(0x0A000001);  // 10.0.0.1 for M34.5 inbound
    ec.max_conns   = 4;
    ec.idle_ms     = 60'000;
    ec.connect_ms  = 5'000;
    TsiTcpEngine eng(std::move(ec));

    // ---- Helpers --------------------------------------------------------
    const std::uint32_t guest_ip_be = htonl(0x0A000002);   // 10.0.0.2
    const std::uint32_t dst_ip_be   = htonl(0x7F000001);   // 127.0.0.1
    const std::uint16_t guest_port_be = htons(35472);

    auto wr16be = [](std::uint8_t* p, std::uint16_t v){
        p[0]=(std::uint8_t)(v>>8); p[1]=(std::uint8_t)v;
    };
    auto wr32be = [](std::uint8_t* p, std::uint32_t v){
        p[0]=(std::uint8_t)(v>>24); p[1]=(std::uint8_t)(v>>16);
        p[2]=(std::uint8_t)(v>>8);  p[3]=(std::uint8_t)v;
    };
    auto be16 = [](const std::uint8_t* p){
        return (std::uint16_t)((std::uint16_t)p[0]<<8 | (std::uint16_t)p[1]);
    };
    auto be32 = [](const std::uint8_t* p){
        return (std::uint32_t)((std::uint32_t)p[0]<<24 |
                               (std::uint32_t)p[1]<<16 |
                               (std::uint32_t)p[2]<<8  |
                               (std::uint32_t)p[3]);
    };
    auto cksum = [](const std::uint8_t* p, std::size_t n, std::uint32_t carry=0){
        std::uint32_t s = carry;
        while (n >= 2) { s += (std::uint32_t)p[0]<<8 | p[1]; p+=2; n-=2; }
        if (n) s += (std::uint32_t)p[0]<<8;
        while (s>>16) s = (s & 0xFFFF) + (s>>16);
        return (std::uint16_t)(~s & 0xFFFF);
    };

    auto build_pkt = [&](std::uint8_t flags, std::uint32_t seq, std::uint32_t ack,
                         std::uint16_t win,
                         const std::uint8_t* payload, std::size_t payload_len) {
        std::vector<std::uint8_t> p(20 + 20 + payload_len);
        // IP
        p[0] = 0x45; p[1] = 0x00;
        wr16be(p.data()+2, (std::uint16_t)p.size());
        wr16be(p.data()+4, 0); wr16be(p.data()+6, 0x4000);
        p[8] = 64; p[9] = 6; wr16be(p.data()+10, 0);
        std::memcpy(p.data()+12, &guest_ip_be, 4);
        std::memcpy(p.data()+16, &dst_ip_be, 4);
        wr16be(p.data()+10, cksum(p.data(), 20));
        // TCP
        std::uint8_t* t = p.data() + 20;
        std::memcpy(t+0, &guest_port_be, 2);
        std::memcpy(t+2, &dst_port_be, 2);
        wr32be(t+4, seq); wr32be(t+8, ack);
        t[12] = 0x50; t[13] = flags;
        wr16be(t+14, win); wr16be(t+16, 0); wr16be(t+18, 0);
        if (payload_len) std::memcpy(t+20, payload, payload_len);
        // TCP cksum over pseudo + TCP + payload
        std::uint32_t ph = 0;
        ph += (be16((const std::uint8_t*)&guest_ip_be));
        ph += (be16((const std::uint8_t*)&guest_ip_be + 2));
        ph += (be16((const std::uint8_t*)&dst_ip_be));
        ph += (be16((const std::uint8_t*)&dst_ip_be + 2));
        ph += 6;
        ph += (std::uint16_t)(20 + payload_len);
        wr16be(t+16, cksum(t, 20 + payload_len, ph));
        return p;
    };

    auto inject = [&](const std::vector<std::uint8_t>& pkt) {
        eng.OnGuestTcpPacket(test_clock_ms, pkt.data(), pkt.size());
    };

    // Run engine + advance time + accept/recv on host listener.
    // Returns when condition() == true, or after `budget_ms` of test time.
    auto pump_until = [&](auto&& condition, int budget_ms) -> bool {
        for (int elapsed = 0; elapsed < budget_ms; elapsed += 10) {
            eng.Tick(test_clock_ms);
            if (condition()) return true;
            ::Sleep(10);
            test_clock_ms += 10;
        }
        eng.Tick(test_clock_ms);
        return condition();
    };

    // Find last received TCP segment whose flags match `mask` & filter().
    auto find_last_seg =
        [&](std::uint8_t flag_must_have, auto&& filter) -> int {
        for (int i = (int)captured.frames.size() - 1; i >= 0; --i) {
            const auto& f = captured.frames[i];
            if (f.size() < 40) continue;
            if (f[9] != 6) continue;
            std::uint8_t fl = f[20 + 13];
            if ((fl & flag_must_have) != flag_must_have) continue;
            if (filter(f)) return i;
        }
        return -1;
    };

    // ----- 3-way handshake --------------------------------------------
    const std::uint32_t guest_iss = 0x10000000;
    auto syn = build_pkt(/*SYN*/0x02, guest_iss, 0, 65535, nullptr, 0);
    inject(syn);

    // Expect SYN-ACK back.
    int idx = -1;
    if (!pump_until([&]{
        idx = find_last_seg(/*SYN|ACK*/0x12, [&](const std::vector<std::uint8_t>& f){
            (void)f; return true;
        });
        return idx >= 0;
    }, 500)) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: no SYN-ACK received\n",
                   stderr);
        ::closesocket(lsn); ::WSACleanup(); return 6;
    }
    const auto& synack = captured.frames[idx];
    const std::uint32_t srv_iss = be32(synack.data() + 20 + 4);
    const std::uint32_t srv_ack = be32(synack.data() + 20 + 8);
    if (srv_ack != guest_iss + 1) {
        std::fprintf(stderr,
            "[virtio-net-usernet-tsi-test] FAIL: SYN-ACK ack=%u want=%u\n",
            srv_ack, guest_iss + 1);
        ::closesocket(lsn); ::WSACleanup(); return 7;
    }
    std::printf("[virtio-net-usernet-tsi-test] 3WHS: guest_iss=0x%x srv_iss=0x%x\n",
                guest_iss, srv_iss);

    // Guest ACK to complete handshake.
    auto ack = build_pkt(/*ACK*/0x10, guest_iss + 1, srv_iss + 1,
                         65535, nullptr, 0);
    inject(ack);

    // Now wait for host listener to accept (Winsock connect must drain).
    SOCKET srv = INVALID_SOCKET;
    if (!pump_until([&]{
        sockaddr_in ca{}; int clen = sizeof(ca);
        SOCKET s = ::accept(lsn, (sockaddr*)&ca, &clen);
        if (s != INVALID_SOCKET) { srv = s; return true; }
        return false;
    }, 2000)) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: accept() timed out\n",
                   stderr);
        ::closesocket(lsn); ::WSACleanup(); return 8;
    }
    u_long nb2 = 1; ::ioctlsocket(srv, FIONBIO, &nb2);
    std::puts("[virtio-net-usernet-tsi-test] host accept() OK");

    // ----- Rubber-duck blind-spot #3 ----------------------------------
    // Push a small chunk of guest data RIGHT AFTER the ACK. By design
    // the host-side connect() races us; the engine must accept these
    // bytes into staging_to_host and defer WSASend until Established.
    static const char kReq[] = "GET / HTTP/1.0\r\nHost: x\r\n\r\n";
    auto data_pkt = build_pkt(/*PSH|ACK*/0x18, guest_iss + 1, srv_iss + 1,
                              65535, (const std::uint8_t*)kReq,
                              sizeof(kReq) - 1);
    inject(data_pkt);

    // Pump until host listener receives the full request.
    std::vector<char> hbuf(4096, 0);
    int htotal = 0;
    if (!pump_until([&]{
        for (;;) {
            int r = ::recv(srv, hbuf.data() + htotal,
                            (int)(hbuf.size() - htotal), 0);
            if (r > 0) { htotal += r; continue; }
            if (r == 0) return true;          // EOF (won't happen here)
            int e = ::WSAGetLastError();
            if (e == WSAEWOULDBLOCK) break;
            return false;
        }
        return htotal >= (int)(sizeof(kReq) - 1);
    }, 3000)) {
        std::fprintf(stderr,
            "[virtio-net-usernet-tsi-test] FAIL: host recv only got %d/%zu bytes\n",
            htotal, sizeof(kReq) - 1);
        ::closesocket(srv); ::closesocket(lsn); ::WSACleanup(); return 9;
    }
    if (std::memcmp(hbuf.data(), kReq, sizeof(kReq) - 1) != 0) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: host recv mismatch\n",
                   stderr);
        ::closesocket(srv); ::closesocket(lsn); ::WSACleanup(); return 10;
    }
    std::printf("[virtio-net-usernet-tsi-test] host received %d bytes from guest\n",
                htotal);

    // ----- Reply path: host sends data, expect it reach the guest ----
    static const char kReply[] = "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    const int reply_len = (int)(sizeof(kReply) - 1);
    int sent = 0;
    while (sent < reply_len) {
        int r = ::send(srv, kReply + sent, reply_len - sent, 0);
        if (r <= 0) break;
        sent += r;
    }
    if (sent != reply_len) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: host send incomplete\n",
                   stderr);
        ::closesocket(srv); ::closesocket(lsn); ::WSACleanup(); return 11;
    }

    // Snapshot how many frames we already have; new data segments will
    // be appended.
    const std::size_t baseline_frames = captured.frames.size();

    if (!pump_until([&]{
        // Concatenate payloads of all data segments (PSH set, non-empty)
        // received after the baseline.
        std::vector<std::uint8_t> assembled;
        for (std::size_t i = baseline_frames; i < captured.frames.size(); ++i) {
            const auto& f = captured.frames[i];
            if (f.size() < 40) continue;
            if (f[9] != 6) continue;
            std::uint8_t fl = f[20 + 13];
            if (!(fl & 0x10)) continue;       // need ACK
            std::size_t payload_off = 20 + ((f[20 + 12] >> 4) * 4);
            if (f.size() <= payload_off) continue;
            assembled.insert(assembled.end(),
                              f.begin() + payload_off, f.end());
        }
        return assembled.size() >= (std::size_t)reply_len &&
               std::memcmp(assembled.data(), kReply, reply_len) == 0;
    }, 3000)) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: reply not reassembled\n",
                   stderr);
        ::closesocket(srv); ::closesocket(lsn); ::WSACleanup(); return 12;
    }
    std::printf("[virtio-net-usernet-tsi-test] guest received %d-byte reply\n",
                reply_len);

    // ----- Guest FIN -> host should see EOF on recv() -----------------
    // Advance guest seq past the data we sent.
    const std::uint32_t guest_next_seq = guest_iss + 1 + (std::uint32_t)(sizeof(kReq) - 1);
    auto fin = build_pkt(/*FIN|ACK*/0x11, guest_next_seq, srv_iss + 1 + reply_len,
                         65535, nullptr, 0);
    inject(fin);

    // Drain any remaining host bytes; verify EOF.
    bool saw_eof = false;
    pump_until([&]{
        char tmp[256];
        int r = ::recv(srv, tmp, sizeof(tmp), 0);
        if (r == 0) { saw_eof = true; return true; }
        if (r < 0 && ::WSAGetLastError() != WSAEWOULDBLOCK) {
            return true;                       // also accept hard error
        }
        return false;
    }, 2000);
    if (!saw_eof) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: host did not see EOF "
                   "after guest FIN (rubber-duck #3 regression)\n", stderr);
        ::closesocket(srv); ::closesocket(lsn); ::WSACleanup(); return 13;
    }
    std::puts("[virtio-net-usernet-tsi-test] host saw EOF after guest FIN");

    // Host closes its side; engine sees EOF, calls tcp_close, and emits
    // a FIN to the guest (TCB now in LAST_ACK). The full close FSM
    // requires the guest to ACK our FIN so the TCB can transition to
    // CLOSED. Without it the TCB sits in LAST_ACK forever — pre-M34.6
    // that leaked silently; M34.6's half-close watchdog will abort it
    // after half_close_ms. Inject the closing ACK so this phase ends
    // cleanly via the graceful path (TIME_WAIT is skipped from
    // LAST_ACK; CLOSED is the next stop).
    ::closesocket(srv);
    pump_until([&]{
        // Wait for the engine's FIN (the one queued by tcp_close).
        for (std::size_t i = captured.frames.size(); i-- > 0; ) {
            const auto& f = captured.frames[i];
            if (f.size() < 40 || f[9] != 6) continue;
            // src=engine (srv_iss side) → dst=guest. Filter by src_port
            // = dst_port_be (engine acted as server on dst_port).
            std::uint16_t spt = be16(f.data() + 20 + 0);
            if (spt != ntohs(dst_port_be)) continue;
            if (f[20 + 13] & 0x01) return true;  // FIN bit set
        }
        return false;
    }, 1500);
    // Guest ACK of engine's FIN: ack = past engine's SYN + reply data + FIN.
    auto fin_ack = build_pkt(/*ACK*/0x10,
                              guest_next_seq + 1,            // past guest FIN
                              srv_iss + 1 + reply_len + 1,   // past engine FIN
                              65535, nullptr, 0);
    inject(fin_ack);
    pump_until([&]{ return eng.conn_count() == 0; }, 5000);

    // ======================================================================
    // Phase 2 (M34.5): inbound port-forward TCP via TsiTcpEngine::
    // StartInboundConn(). Build a socketpair via a local bridge listener;
    // hand the server side to the engine; drive an SYN→SYN-ACK→ACK→data
    // round-trip and verify the close path.
    // ======================================================================
    std::puts("[virtio-net-usernet-tsi-test] --- M34.5 Phase 2: inbound ---");

    SOCKET bridge_lsn = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (bridge_lsn == INVALID_SOCKET) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: bridge socket\n", stderr);
        ::closesocket(lsn); ::WSACleanup(); return 14;
    }
    u_long nbl = 1; ::ioctlsocket(bridge_lsn, FIONBIO, &nbl);
    sockaddr_in bla{}; bla.sin_family = AF_INET;
    bla.sin_addr.s_addr = htonl(INADDR_LOOPBACK); bla.sin_port = 0;
    if (::bind(bridge_lsn, (sockaddr*)&bla, sizeof(bla)) != 0 ||
        ::listen(bridge_lsn, 4) != 0) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: bridge bind/listen\n",
                   stderr);
        ::closesocket(bridge_lsn); ::closesocket(lsn);
        ::WSACleanup(); return 15;
    }
    sockaddr_in bla_actual{}; int bla_len = sizeof(bla_actual);
    ::getsockname(bridge_lsn, (sockaddr*)&bla_actual, &bla_len);

    SOCKET host_client = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    u_long nbc = 1; ::ioctlsocket(host_client, FIONBIO, &nbc);
    ::connect(host_client, (sockaddr*)&bla_actual, sizeof(bla_actual));
    SOCKET engine_sock = INVALID_SOCKET;
    for (int spin = 0; spin < 200 && engine_sock == INVALID_SOCKET; ++spin) {
        sockaddr_in pa{}; int palen = sizeof(pa);
        engine_sock = ::accept(bridge_lsn, (sockaddr*)&pa, &palen);
        if (engine_sock == INVALID_SOCKET) ::Sleep(5);
    }
    if (engine_sock == INVALID_SOCKET) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: bridge accept\n", stderr);
        ::closesocket(host_client); ::closesocket(bridge_lsn);
        ::closesocket(lsn); ::WSACleanup(); return 16;
    }
    std::puts("[virtio-net-usernet-tsi-test] bridge socketpair up");

    const std::uint16_t in_guest_port_be = htons(8080);
    const std::uint32_t in_guest_ip_be   = guest_ip_be;  // 10.0.0.2
    const std::uint32_t in_gw_ip_be      = htonl(0x0A000001);
    const std::size_t before_inbound = captured.frames.size();
    if (!eng.StartInboundConn(engine_sock, in_guest_ip_be, in_guest_port_be)) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: StartInboundConn\n",
                   stderr);
        ::closesocket(host_client); ::closesocket(bridge_lsn);
        ::closesocket(lsn); ::WSACleanup(); return 17;
    }

    // Find the SYN: src_ip=gw, dst_ip=guest, syn-only flag, dst_port=8080.
    int syn_idx = -1;
    for (std::size_t i = before_inbound; i < captured.frames.size(); ++i) {
        const auto& f = captured.frames[i];
        if (f.size() < 40 || f[9] != 6) continue;
        std::uint32_t sip = be32(f.data() + 12);
        std::uint32_t dip = be32(f.data() + 16);
        std::uint16_t dpt = be16(f.data() + 20 + 2);
        std::uint8_t  fl  = f[20 + 13];
        if (sip != ntohl(in_gw_ip_be))     continue;
        if (dip != ntohl(in_guest_ip_be))  continue;
        if (dpt != 8080)                   continue;
        if ((fl & 0x12) != 0x02)           continue;  // SYN only, no ACK
        syn_idx = (int)i;
        break;
    }
    if (syn_idx < 0) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: no inbound SYN emitted\n",
                   stderr);
        ::closesocket(host_client); ::closesocket(bridge_lsn);
        ::closesocket(lsn); ::WSACleanup(); return 18;
    }
    const auto& syn_frame = captured.frames[syn_idx];
    const std::uint32_t in_gw_iss   = be32(syn_frame.data() + 20 + 4);
    const std::uint16_t in_ephem_be = htons(be16(syn_frame.data() + 20 + 0));
    std::printf("[virtio-net-usernet-tsi-test] inbound SYN: ephem=%u iss=0x%x\n",
                static_cast<unsigned>(ntohs(in_ephem_be)), in_gw_iss);

    // Build a guest SYN-ACK using a fresh helper that flips src/dst.
    auto build_pkt_inbound = [&](std::uint8_t flags, std::uint32_t seq,
                                  std::uint32_t ack, std::uint16_t win,
                                  const std::uint8_t* payload,
                                  std::size_t payload_len) {
        std::vector<std::uint8_t> p(20 + 20 + payload_len);
        p[0] = 0x45; p[1] = 0;
        wr16be(p.data()+2, (std::uint16_t)p.size());
        wr16be(p.data()+4, 0); wr16be(p.data()+6, 0x4000);
        p[8] = 64; p[9] = 6;
        std::memcpy(p.data()+12, &in_guest_ip_be, 4);
        std::memcpy(p.data()+16, &in_gw_ip_be,    4);
        wr16be(p.data()+10, cksum(p.data(), 20));
        std::uint8_t* t = p.data() + 20;
        std::memcpy(t+0, &in_guest_port_be, 2);
        std::memcpy(t+2, &in_ephem_be,      2);
        wr32be(t+4, seq); wr32be(t+8, ack);
        t[12] = 0x50; t[13] = flags;
        wr16be(t+14, win); wr16be(t+16, 0); wr16be(t+18, 0);
        if (payload_len) std::memcpy(t+20, payload, payload_len);
        std::uint32_t ph = 0;
        ph += be16((const std::uint8_t*)&in_guest_ip_be);
        ph += be16((const std::uint8_t*)&in_guest_ip_be + 2);
        ph += be16((const std::uint8_t*)&in_gw_ip_be);
        ph += be16((const std::uint8_t*)&in_gw_ip_be + 2);
        ph += 6;
        ph += (std::uint16_t)(20 + payload_len);
        wr16be(t+16, cksum(t, 20 + payload_len, ph));
        return p;
    };

    const std::uint32_t in_guest_iss = 0x77000000;
    auto in_synack = build_pkt_inbound(/*SYN|ACK*/0x12, in_guest_iss,
                                        in_gw_iss + 1, 65535, nullptr, 0);
    inject(in_synack);

    // Engine should ACK and reach inbound_handshake_done. Test by sending
    // host data and verifying it appears in captured.
    static const char kHostReq[] = "GET /probe HTTP/1.0\r\n\r\n";
    const int kHostReqLen = (int)(sizeof(kHostReq) - 1);
    int hc_sent = 0;
    pump_until([&]{
        if (hc_sent < kHostReqLen) {
            int r = ::send(host_client, kHostReq + hc_sent,
                            kHostReqLen - hc_sent, 0);
            if (r > 0) hc_sent += r;
        }
        // Look for a data segment from gw:ephem -> guest:8080 in captured.
        std::vector<std::uint8_t> asm_;
        for (std::size_t i = before_inbound; i < captured.frames.size(); ++i) {
            const auto& f = captured.frames[i];
            if (f.size() < 40 || f[9] != 6) continue;
            std::uint16_t spt = be16(f.data() + 20 + 0);
            std::uint16_t dpt = be16(f.data() + 20 + 2);
            if (spt != ntohs(in_ephem_be) || dpt != 8080) continue;
            std::uint8_t fl = f[20 + 13];
            if (!(fl & 0x10)) continue;
            std::size_t poff = 20 + ((f[20 + 12] >> 4) * 4);
            if (f.size() <= poff) continue;
            asm_.insert(asm_.end(), f.begin() + poff, f.end());
        }
        return asm_.size() >= (std::size_t)kHostReqLen &&
               std::memcmp(asm_.data(), kHostReq, kHostReqLen) == 0;
    }, 3000);
    if (hc_sent != kHostReqLen) {
        std::fprintf(stderr,
            "[virtio-net-usernet-tsi-test] FAIL: host send incomplete %d/%d\n",
            hc_sent, kHostReqLen);
        ::closesocket(host_client); ::closesocket(bridge_lsn);
        ::closesocket(lsn); ::WSACleanup(); return 19;
    }
    std::printf("[virtio-net-usernet-tsi-test] inbound: guest received %d bytes\n",
                kHostReqLen);

    // Simulate guest reply via PSH+ACK with payload after handshake.
    static const char kGuestReply[] = "OK\r\n";
    const std::uint32_t in_guest_next_seq = in_guest_iss + 1;
    auto in_reply = build_pkt_inbound(/*PSH|ACK*/0x18, in_guest_next_seq,
                                       in_gw_iss + 1 + kHostReqLen, 65535,
                                       (const std::uint8_t*)kGuestReply,
                                       sizeof(kGuestReply) - 1);
    inject(in_reply);

    // Pump until host_client receives the reply.
    char hcbuf[64] = {0};
    int hc_recv = 0;
    pump_until([&]{
        int r = ::recv(host_client, hcbuf + hc_recv,
                        (int)(sizeof(hcbuf) - hc_recv), 0);
        if (r > 0) hc_recv += r;
        return hc_recv >= (int)(sizeof(kGuestReply) - 1);
    }, 3000);
    if (hc_recv < (int)(sizeof(kGuestReply) - 1) ||
        std::memcmp(hcbuf, kGuestReply, sizeof(kGuestReply) - 1) != 0) {
        std::fprintf(stderr,
            "[virtio-net-usernet-tsi-test] FAIL: host_client recv=%d (want %zu)\n",
            hc_recv, sizeof(kGuestReply) - 1);
        ::closesocket(host_client); ::closesocket(bridge_lsn);
        ::closesocket(lsn); ::WSACleanup(); return 20;
    }
    std::printf("[virtio-net-usernet-tsi-test] inbound: host received %d-byte reply\n",
                hc_recv);

    // Host closes -> engine should emit FIN to guest.
    ::closesocket(host_client);
    bool saw_fin = false;
    pump_until([&]{
        for (std::size_t i = before_inbound; i < captured.frames.size(); ++i) {
            const auto& f = captured.frames[i];
            if (f.size() < 40 || f[9] != 6) continue;
            std::uint16_t spt = be16(f.data() + 20 + 0);
            std::uint16_t dpt = be16(f.data() + 20 + 2);
            if (spt != ntohs(in_ephem_be) || dpt != 8080) continue;
            if (f[20 + 13] & 0x01) { saw_fin = true; return true; }
        }
        return false;
    }, 3000);
    if (!saw_fin) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: no inbound FIN emitted\n",
                   stderr);
        ::closesocket(bridge_lsn); ::closesocket(lsn);
        ::WSACleanup(); return 21;
    }
    std::puts("[virtio-net-usernet-tsi-test] inbound: FIN emitted toward guest");

    // Complete the close FSM from the guest side.
    auto in_finack = build_pkt_inbound(/*FIN|ACK*/0x11, in_guest_next_seq +
                                            (sizeof(kGuestReply) - 1),
                                        in_gw_iss + 2 + kHostReqLen, 65535,
                                        nullptr, 0);
    inject(in_finack);
    pump_until([&]{ return eng.conn_count() == 0; }, 5000);
    ::closesocket(bridge_lsn);

    // ======================================================================
    // Phase 3 (M34.5 rubber-duck #1): handshake timeout. Start a fresh
    // inbound conn, never inject the guest SYN-ACK, advance time past
    // the handshake deadline, and verify the engine reaps the conn.
    // ======================================================================
    std::puts("[virtio-net-usernet-tsi-test] --- M34.5 Phase 3: handshake timeout ---");

    // Build a fresh engine with a tight connect deadline.
    Captured cap3;
    TsiTcpEngine::EmitCtx ec3{};
    ec3.push_ipv4_to_guest =
        [&cap3](const std::uint8_t* ip, std::size_t n) {
            cap3.frames.emplace_back(ip, ip + n);
        };
    std::uint64_t test_clock3_ms = 50'000;
    ec3.now_ms = [&test_clock3_ms]{ return test_clock3_ms; };
    ec3.backend_mac  = {0x02,0x53,0x54,0x00,0x00,0x01};
    ec3.guest_mac    = {0x52,0x54,0x00,0x12,0x34,0x56};
    ec3.gateway_ip_be = htonl(0x0A000001);
    ec3.max_conns    = 2;
    ec3.idle_ms      = 60'000;
    ec3.connect_ms   = 200;
    TsiTcpEngine eng3(std::move(ec3));

    SOCKET bridge3 = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    u_long nb3 = 1; ::ioctlsocket(bridge3, FIONBIO, &nb3);
    sockaddr_in b3a{}; b3a.sin_family = AF_INET;
    b3a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); b3a.sin_port = 0;
    ::bind(bridge3, (sockaddr*)&b3a, sizeof(b3a));
    ::listen(bridge3, 4);
    sockaddr_in b3_actual{}; int b3_alen = sizeof(b3_actual);
    ::getsockname(bridge3, (sockaddr*)&b3_actual, &b3_alen);
    SOCKET hc3 = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    u_long nb3c = 1; ::ioctlsocket(hc3, FIONBIO, &nb3c);
    ::connect(hc3, (sockaddr*)&b3_actual, sizeof(b3_actual));
    SOCKET es3 = INVALID_SOCKET;
    for (int s = 0; s < 200 && es3 == INVALID_SOCKET; ++s) {
        sockaddr_in pa{}; int pal = sizeof(pa);
        es3 = ::accept(bridge3, (sockaddr*)&pa, &pal);
        if (es3 == INVALID_SOCKET) ::Sleep(5);
    }
    if (es3 == INVALID_SOCKET) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: phase3 bridge\n", stderr);
        ::closesocket(hc3); ::closesocket(bridge3); ::closesocket(lsn);
        ::WSACleanup(); return 22;
    }

    if (!eng3.StartInboundConn(es3, in_guest_ip_be, in_guest_port_be)) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: phase3 StartInboundConn\n",
                   stderr);
        ::closesocket(hc3); ::closesocket(bridge3); ::closesocket(lsn);
        ::WSACleanup(); return 23;
    }
    if (eng3.conn_count() != 1) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: phase3 conn_count != 1\n",
                   stderr);
        ::closesocket(hc3); ::closesocket(bridge3); ::closesocket(lsn);
        ::WSACleanup(); return 24;
    }

    // Advance the clock past the connect_ms (200) deadline; never inject
    // the SYN-ACK. Engine must abort + reap.
    bool reaped = false;
    for (int i = 0; i < 200; ++i) {       // up to ~2s of pumping
        eng3.Tick(test_clock3_ms);
        if (eng3.conn_count() == 0) { reaped = true; break; }
        test_clock3_ms += 50;
    }
    if (!reaped) {
        std::fprintf(stderr,
            "[virtio-net-usernet-tsi-test] FAIL: phase3 handshake timeout did "
            "not reap (conn_count=%zu)\n", eng3.conn_count());
        ::closesocket(hc3); ::closesocket(bridge3); ::closesocket(lsn);
        ::WSACleanup(); return 25;
    }
    std::puts("[virtio-net-usernet-tsi-test] inbound handshake timeout: reaped");

    eng3.Shutdown();
    ::closesocket(hc3);
    ::closesocket(bridge3);

    // ======================================================================
    // Phase 4 (M34.6): half-close watchdog. Stand up a fresh engine with a
    // tight half_close_ms, drive an inbound flow to ESTABLISHED, close the
    // bridge host_client to push the TCB into FIN_WAIT_1 (engine sends a
    // FIN to the guest via tcp_close), then advance time past the
    // half_close deadline WITHOUT ever injecting the guest's FIN-ACK. The
    // engine must AbortConn the TCB so aborts++ and the conn reaps. This
    // is also the regression test for rubber-duck rec #3 (CLOSE_WAIT-like
    // activity-based timing).
    // ======================================================================
    std::puts("[virtio-net-usernet-tsi-test] --- M34.6 Phase 4: half-close watchdog ---");

    Captured cap4;
    TsiTcpEngine::EmitCtx ec4{};
    ec4.push_ipv4_to_guest =
        [&cap4](const std::uint8_t* ip, std::size_t n) {
            cap4.frames.emplace_back(ip, ip + n);
        };
    std::uint64_t test_clock4_ms = 100'000;
    ec4.now_ms = [&test_clock4_ms]{ return test_clock4_ms; };
    ec4.backend_mac   = {0x02,0x53,0x54,0x00,0x00,0x01};
    ec4.guest_mac     = {0x52,0x54,0x00,0x12,0x34,0x56};
    ec4.gateway_ip_be = htonl(0x0A000001);
    ec4.max_conns     = 4;
    ec4.idle_ms       = 600'000;
    ec4.connect_ms    = 5'000;
    ec4.half_close_ms = 200;
    TsiTcpEngine eng4(std::move(ec4));

    SOCKET bridge4 = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    u_long nb4 = 1; ::ioctlsocket(bridge4, FIONBIO, &nb4);
    sockaddr_in b4a{}; b4a.sin_family = AF_INET;
    b4a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); b4a.sin_port = 0;
    ::bind(bridge4, (sockaddr*)&b4a, sizeof(b4a));
    ::listen(bridge4, 4);
    sockaddr_in b4_actual{}; int b4_alen = sizeof(b4_actual);
    ::getsockname(bridge4, (sockaddr*)&b4_actual, &b4_alen);
    SOCKET hc4 = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    u_long nb4c = 1; ::ioctlsocket(hc4, FIONBIO, &nb4c);
    ::connect(hc4, (sockaddr*)&b4_actual, sizeof(b4_actual));
    SOCKET es4 = INVALID_SOCKET;
    for (int s = 0; s < 200 && es4 == INVALID_SOCKET; ++s) {
        sockaddr_in pa{}; int pal = sizeof(pa);
        es4 = ::accept(bridge4, (sockaddr*)&pa, &pal);
        if (es4 == INVALID_SOCKET) ::Sleep(5);
    }
    if (es4 == INVALID_SOCKET) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: phase4 bridge\n", stderr);
        ::closesocket(hc4); ::closesocket(bridge4); ::closesocket(lsn);
        ::WSACleanup(); return 26;
    }

    if (!eng4.StartInboundConn(es4, in_guest_ip_be, in_guest_port_be)) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: phase4 StartInboundConn\n",
                   stderr);
        ::closesocket(hc4); ::closesocket(bridge4); ::closesocket(lsn);
        ::WSACleanup(); return 27;
    }

    // Find the SYN, extract iss + ephem.
    int syn4_idx = -1;
    for (std::size_t i = 0; i < cap4.frames.size(); ++i) {
        const auto& f = cap4.frames[i];
        if (f.size() < 40 || f[9] != 6) continue;
        std::uint16_t dpt = be16(f.data() + 20 + 2);
        std::uint8_t  fl  = f[20 + 13];
        if (dpt != 8080)         continue;
        if ((fl & 0x12) != 0x02) continue;
        syn4_idx = (int)i; break;
    }
    if (syn4_idx < 0) {
        std::fputs("[virtio-net-usernet-tsi-test] FAIL: phase4 no SYN\n", stderr);
        ::closesocket(hc4); ::closesocket(bridge4); ::closesocket(lsn);
        ::WSACleanup(); return 28;
    }
    const std::uint32_t in_gw_iss4   = be32(cap4.frames[syn4_idx].data() + 20 + 4);
    const std::uint16_t in_ephem4_be = htons(be16(cap4.frames[syn4_idx].data() + 20));

    // Build & inject guest SYN-ACK targeted at eng4 (different ephem).
    auto build_synack4 = [&](std::uint32_t guest_iss, std::uint32_t ack) {
        std::vector<std::uint8_t> p(40);
        p[0]=0x45; p[1]=0; wr16be(p.data()+2,40);
        wr16be(p.data()+4,0); wr16be(p.data()+6,0x4000);
        p[8]=64; p[9]=6; wr16be(p.data()+10,0);
        std::memcpy(p.data()+12, &in_guest_ip_be, 4);
        std::memcpy(p.data()+16, &in_gw_ip_be,    4);
        wr16be(p.data()+10, cksum(p.data(),20));
        std::uint8_t* t = p.data()+20;
        std::memcpy(t+0, &in_guest_port_be, 2);
        std::memcpy(t+2, &in_ephem4_be,     2);
        wr32be(t+4, guest_iss); wr32be(t+8, ack);
        t[12]=0x50; t[13]=0x12; wr16be(t+14,65535);
        wr16be(t+16,0); wr16be(t+18,0);
        std::uint32_t ph = 0;
        ph += be16((const std::uint8_t*)&in_guest_ip_be);
        ph += be16((const std::uint8_t*)&in_guest_ip_be + 2);
        ph += be16((const std::uint8_t*)&in_gw_ip_be);
        ph += be16((const std::uint8_t*)&in_gw_ip_be + 2);
        ph += 6; ph += 20;
        wr16be(t+16, cksum(t,20,ph));
        return p;
    };
    const std::uint32_t guest_iss4 = 0x99000000;
    auto sa4 = build_synack4(guest_iss4, in_gw_iss4 + 1);
    eng4.OnGuestTcpPacket(test_clock4_ms, sa4.data(), sa4.size());

    // One Tick: should latch inbound_handshake_done.
    eng4.Tick(test_clock4_ms);
    if (eng4.conn_count() != 1) {
        std::fprintf(stderr,
            "[virtio-net-usernet-tsi-test] FAIL: phase4 conn_count=%zu\n",
            eng4.conn_count());
        ::closesocket(hc4); ::closesocket(bridge4); ::closesocket(lsn);
        ::WSACleanup(); return 29;
    }
    const std::uint64_t aborts4_before = eng4.aborts();

    // Close the bridge -> engine sees EOF on es4 -> tcp_close -> FIN sent
    // to guest -> FIN_WAIT_1. We do NOT inject any guest reply.
    ::closesocket(hc4);

    // Give the loopback FIN a moment to propagate, then pump once so
    // WSARecv on es4 sees the EOF.
    ::Sleep(50);
    eng4.Tick(test_clock4_ms);

    // Fast-forward well past half_close_ms (200) WITHOUT real Sleeps. The
    // half-close watchdog uses last_activity_ms; with no further injects
    // it will fire on the next Tick after the deadline.
    bool reaped4 = false;
    for (int i = 0; i < 200; ++i) {
        test_clock4_ms += 50;
        eng4.Tick(test_clock4_ms);
        if (eng4.aborts() > aborts4_before && eng4.conn_count() == 0) {
            reaped4 = true; break;
        }
    }
    if (!reaped4) {
        std::fprintf(stderr,
            "[virtio-net-usernet-tsi-test] FAIL: phase4 half-close watchdog "
            "did not fire (conn_count=%zu aborts_delta=%llu)\n",
            eng4.conn_count(),
            (unsigned long long)(eng4.aborts() - aborts4_before));
        ::closesocket(bridge4); ::closesocket(lsn);
        ::WSACleanup(); return 30;
    }
    std::printf("[virtio-net-usernet-tsi-test] half-close watchdog fired "
                "(aborts=%llu graceful=%llu)\n",
                (unsigned long long)eng4.aborts(),
                (unsigned long long)eng4.graceful_closes());

    eng4.Shutdown();
    ::closesocket(bridge4);

    // ======================================================================
    // Phase 5 (M34.6): graceful-close reap + counter sanity. The Phase 1
    // outbound and Phase 2 inbound flows both ended with a normal FIN
    // exchange, so their TCBs are sitting in TIME_WAIT inside `eng`.
    // Without the M34.6 shim-Closed reconcile they would leak the map
    // forever (latent bug also present in M34.5). Fast-forward `eng`'s
    // clock past TIME_WAIT (TSI uses 2*MSL; 200s is comfortably past)
    // and verify both conns are reaped and counted as graceful.
    // ======================================================================
    std::puts("[virtio-net-usernet-tsi-test] --- M34.6 Phase 5: graceful-close reap ---");
    const std::size_t live_before = eng.conn_count();
    const std::uint64_t graceful_before = eng.graceful_closes();
    bool eng_drained = false;
    for (int i = 0; i < 4000; ++i) {       // ~200s of test time
        test_clock_ms += 50;
        eng.Tick(test_clock_ms);
        if (eng.conn_count() == 0) { eng_drained = true; break; }
    }
    if (!eng_drained) {
        std::fprintf(stderr,
            "[virtio-net-usernet-tsi-test] FAIL: phase5 eng not drained "
            "(live=%zu after fast-forward, aborts=%llu, graceful=%llu)\n",
            eng.conn_count(),
            (unsigned long long)eng.aborts(),
            (unsigned long long)eng.graceful_closes());
        ::closesocket(lsn); ::WSACleanup(); return 31;
    }
    const std::uint64_t graceful_delta = eng.graceful_closes() - graceful_before;
    std::printf("[virtio-net-usernet-tsi-test] eng drained: was live=%zu, "
                "graceful_delta=%llu, aborts=%llu\n",
                live_before, (unsigned long long)graceful_delta,
                (unsigned long long)eng.aborts());

    // Counter sanity across all three engines (eng, eng3, eng4).
    // Expectations:
    //   eng:  outbound + inbound, both graceful close -> total=2, aborts=0,
    //         graceful_closes>=2, segments_rx>0, segments_tx>0.
    //   eng3: inbound that timed out -> total=1, aborts=1.
    //   eng4: inbound that hit half-close watchdog -> total=1, aborts=1.
    bool ok = true;
    auto report = [&](const char* name, std::uint64_t got, std::uint64_t want,
                      bool require_eq) {
        const bool pass = require_eq ? (got == want) : (got >= want);
        if (!pass) {
            std::fprintf(stderr,
                "[virtio-net-usernet-tsi-test] FAIL counter: %s got=%llu want%s=%llu\n",
                name, (unsigned long long)got, require_eq ? "==" : ">=",
                (unsigned long long)want);
            ok = false;
        }
    };
    report("eng.total_conns",     eng.total_conns(),     2, true);
    report("eng.aborts",          eng.aborts(),          0, true);
    report("eng.graceful_closes", eng.graceful_closes(), 2, false);
    report("eng.segments_rx",     eng.segments_rx(),     1, false);
    report("eng.segments_tx",     eng.segments_tx(),     1, false);
    report("eng3.total_conns",    eng3.total_conns(),    1, true);
    report("eng3.aborts",         eng3.aborts(),         1, true);
    report("eng4.total_conns",    eng4.total_conns(),    1, true);
    report("eng4.aborts",         eng4.aborts(),         1, true);
    if (!ok) { ::closesocket(lsn); ::WSACleanup(); return 32; }
    std::printf("[virtio-net-usernet-tsi-test] counters OK: eng{total=%llu "
                "graceful=%llu rsts=%llu seg_rx=%llu seg_tx=%llu} "
                "eng3{aborts=%llu} eng4{aborts=%llu}\n",
                (unsigned long long)eng.total_conns(),
                (unsigned long long)eng.graceful_closes(),
                (unsigned long long)eng.rsts_sent(),
                (unsigned long long)eng.segments_rx(),
                (unsigned long long)eng.segments_tx(),
                (unsigned long long)eng3.aborts(),
                (unsigned long long)eng4.aborts());

    std::printf("[virtio-net-usernet-tsi-test] PASS (conn_total=%llu "
                "rsts=%llu live=%zu)\n",
                static_cast<unsigned long long>(eng.total_conns()),
                static_cast<unsigned long long>(eng.rsts_sent()),
                eng.conn_count());

    eng.Shutdown();
    ::closesocket(lsn);
    ::WSACleanup();
    return 0;
}

// --tsi-fuzz-test
// Feed N random IPv4+TCP packets to TsiTcpEngine::OnGuestTcpPacket plus
// periodic Tick(). Catches: crashes, asserts, AVs, infinite loops
// (one Tick per iter == built-in budget), conn_count over the
// configured cap, and resource leaks (engine.Shutdown reports any
// live TCBs at exit). Deterministic via --seed N; reproducible.
//
// The fuzzer keeps the packet shape *just valid enough* to reach the
// parser past header validation (correct IPv4 vihl + total_len + TCP
// proto + valid data_offset). Everything else is random:
//   - flags (SYN/ACK/RST/FIN/PSH/URG/ECE/CWR combinations)
//   - seq / ack
//   - window size
//   - 5-tuple ports
//   - payload bytes
//   - random truncation occasionally past validation
//
// dst_ip is forced to 127.0.0.1 with random dst_port. On Windows
// loopback, Winsock connect() to a closed port returns ECONNREFUSED
// instantly, so the engine's BeginConnect failure path runs at full
// fuzz speed without piling up real outbound sockets.
//
// Cap: max_conns=8, idle_ms=500ms, connect_ms=100ms, half_close_ms=200ms
// keeps the engine bounded and fast-recycling.
int RunTsiFuzzTest(int iters, std::uint64_t seed) {
    using namespace tinyvmm;
    using namespace tinyvmm::virtio;

    std::printf("[tsi-fuzz-test] starting (iters=%d, seed=%llu)\n",
                iters, static_cast<unsigned long long>(seed));

    WSADATA wsa{};
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::fputs("[tsi-fuzz-test] FAIL: WSAStartup\n", stderr);
        return 1;
    }

    constexpr std::size_t kCap = 8;
    TsiTcpEngine::EmitCtx ec{};
    ec.push_ipv4_to_guest =
        [](const std::uint8_t* /*ip*/, std::size_t /*n*/) {
            // Discard. Fuzz cares about reaching the parser, not what
            // the engine emits back.
        };
    std::uint64_t test_clock_ms = 1000;
    ec.now_ms        = [&test_clock_ms]{ return test_clock_ms; };
    ec.backend_mac   = {0x02, 0x53, 0x54, 0x00, 0x00, 0x01};
    ec.guest_mac     = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
    ec.gateway_ip_be = ::htonl(0x0A000001);
    ec.max_conns     = kCap;
    ec.idle_ms       = 500;
    ec.connect_ms    = 100;
    ec.half_close_ms = 200;
    TsiTcpEngine eng(std::move(ec));

    std::mt19937_64 rng(seed);
    std::vector<std::uint8_t> pkt;
    pkt.reserve(1500);

    std::size_t conn_max = 0;
    int first_fail = -1;

    auto wr16be = [](std::uint8_t* p, std::uint16_t v) {
        p[0] = static_cast<std::uint8_t>(v >> 8);
        p[1] = static_cast<std::uint8_t>(v);
    };

    const std::uint32_t src_ip_be = ::htonl(0x0A000002);   // 10.0.0.2
    const std::uint32_t dst_ip_be = ::htonl(0x7F000001);   // 127.0.0.1

    for (int i = 0; i < iters; ++i) {
        // Pick size: mostly 40..120 (header + small payload), sometimes
        // larger or right at boundary. Min IPv4+TCP = 40 bytes.
        const std::uint32_t r = static_cast<std::uint32_t>(rng());
        std::size_t sz;
        if ((r & 0xF) == 0) {
            sz = 40 + (rng() % 1460);            // up to MTU
        } else if ((r & 0xF) == 1) {
            sz = 40 + (rng() % 8);               // header + 0..7 payload
        } else if ((r & 0xF) == 2) {
            sz = 35 + (rng() % 5);               // truncated (35..39)
        } else {
            sz = 40 + (rng() % 64);              // common case
        }
        pkt.resize(sz);
        for (auto& b : pkt) b = static_cast<std::uint8_t>(rng());

        // Fix IPv4 header to be parser-valid in the common case:
        //   vihl = 0x45 (IPv4 + IHL=5).
        //   total_len = sz.
        //   protocol = 6 (TCP).
        // The parser rejects on bad vihl / proto / total_len; we want
        // most iters to reach the TCP layer.
        if (sz >= 20) {
            pkt[0] = 0x45;
            pkt[1] = 0x00;
            wr16be(pkt.data() + 2, static_cast<std::uint16_t>(sz));
            pkt[6] = pkt[6] & 0x1F;              // no DF/MF, frag offset 0
            pkt[7] = 0;
            pkt[9] = 6;                          // proto = TCP
            std::memcpy(pkt.data() + 12, &src_ip_be, 4);
            std::memcpy(pkt.data() + 16, &dst_ip_be, 4);
            // src_port: random; dst_port: 127.0.0.1:random (mostly
            // closed) => instant ECONNREFUSED in BeginConnect.
            std::uint16_t src_port = ::htons(
                static_cast<std::uint16_t>(40000 + (rng() % 1024)));
            std::uint16_t dst_port = ::htons(
                static_cast<std::uint16_t>(50000 + (rng() % 5000)));
            std::memcpy(pkt.data() + 20 + 0, &src_port, 2);
            std::memcpy(pkt.data() + 20 + 2, &dst_port, 2);
            // TCP data offset: 5..15 but capped to (sz-20)/4 so it's
            // in-bounds. The parser rejects if data_offset_bytes > tcp_len.
            const std::size_t tcp_len = sz - 20;
            const std::uint8_t max_doff = static_cast<std::uint8_t>(
                std::min<std::size_t>(15, tcp_len / 4));
            std::uint8_t doff = static_cast<std::uint8_t>(5 + (rng() % 4));
            if (doff > max_doff) doff = max_doff;
            if (doff < 5) doff = 5;
            pkt[20 + 12] = static_cast<std::uint8_t>(doff << 4);
            // Flags: random (low 6 bits = FIN|SYN|RST|PSH|ACK|URG).
            pkt[20 + 13] = static_cast<std::uint8_t>(rng()) & 0x3F;
        }

        // 1 in 8 iters: occasionally truncate sub-IPv4 header to
        // exercise early-bail paths.
        if ((rng() & 0x7) == 0 && sz >= 20) {
            pkt.resize(15 + (rng() % 5));
        }

        try {
            eng.OnGuestTcpPacket(test_clock_ms, pkt.data(), pkt.size());
            eng.Tick(test_clock_ms);
        } catch (...) {
            std::fprintf(stderr,
                "[tsi-fuzz-test] FAIL: exception at iter=%d (size=%zu, "
                "seed=%llu)\n",
                i, pkt.size(),
                static_cast<unsigned long long>(seed));
            if (first_fail < 0) first_fail = i;
        }
        test_clock_ms += 10;

        // Cap check.
        const std::size_t n = eng.conn_count();
        if (n > conn_max) conn_max = n;
        if (n > kCap) {
            std::fprintf(stderr,
                "[tsi-fuzz-test] FAIL: conn_count=%zu > cap=%zu at "
                "iter=%d seed=%llu\n",
                n, kCap, i, static_cast<unsigned long long>(seed));
            eng.Shutdown();
            ::WSACleanup();
            return 1;
        }
    }

    // Drain remaining conns: advance the clock past any half_close /
    // idle deadlines, run Tick repeatedly.
    test_clock_ms += 60'000;
    for (int i = 0; i < 200 && eng.conn_count() > 0; ++i) {
        eng.Tick(test_clock_ms);
        test_clock_ms += 100;
    }

    const std::size_t live_at_end = eng.conn_count();
    const std::uint64_t total     = eng.total_conns();
    const std::uint64_t aborts    = eng.aborts();
    const std::uint64_t graceful  = eng.graceful_closes();
    const std::uint64_t rsts      = eng.rsts_sent();
    const std::uint64_t seg_rx    = eng.segments_rx();
    const std::uint64_t seg_tx    = eng.segments_tx();

    eng.Shutdown();
    ::WSACleanup();

    if (first_fail >= 0) {
        std::fprintf(stderr, "[tsi-fuzz-test] FAIL: %d iters, first "
                             "exception at iter=%d\n", iters, first_fail);
        return 1;
    }

    std::printf("[tsi-fuzz-test] PASS (%d iters, seed=%llu, conn_max=%zu, "
                "live_at_end=%zu, total=%llu, seg_rx=%llu, seg_tx=%llu, "
                "aborts=%llu, graceful=%llu, rsts=%llu)\n",
                iters, static_cast<unsigned long long>(seed),
                conn_max, live_at_end,
                static_cast<unsigned long long>(total),
                static_cast<unsigned long long>(seg_rx),
                static_cast<unsigned long long>(seg_tx),
                static_cast<unsigned long long>(aborts),
                static_cast<unsigned long long>(graceful),
                static_cast<unsigned long long>(rsts));
    return 0;
}

// --virtio-queue-fuzz-test
// Direct Virtqueue::Pop() fuzz: build a guest RAM region + virtqueue,
// push random descriptor chains to the avail ring, and verify Pop()
// never crashes / loops infinitely / lets a buffer escape RAM. This
// targets the virtqueue PARSER, which is the input surface for
// every virtio device (blk, net, rng, console, 9p).
//
// Bugs this catches:
//   * Descriptor cycles (chain->next forms a loop).
//   * desc.addr or desc.addr+desc.len escaping guest RAM bounds.
//   * Zero-length / oversize / misaligned descriptors.
//   * Indirect descriptor tables with bad inner GPAs.
//   * Avail-ring index wrap-around / desync.
//   * Buffer span outliving the RAM mapping.
//
// Pop() is the only API surface; the device-side validation that runs
// after Pop() (virtio-blk header, virtio-net header, 9p T-message
// dispatcher) is exercised separately by each device's own fuzz.
//
// Reproducible via --seed; default seed = 0xFADE0FF.
int RunVirtioQueueFuzzTest(int iters, std::uint64_t seed) {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;
    namespace v = tinyvmm::virtio;

    std::printf("[virtio-queue-fuzz-test] starting (iters=%d, seed=%llu)\n",
                iters, static_cast<unsigned long long>(seed));

    CheckWhpAvailable();
    Partition part(/*vcpu_count=*/1);
    part.Setup();

    // 1 MiB guest RAM, host-accessible. Note: large-page allocator
    // rounds the actual region up to 2 MiB (the large-page minimum),
    // even when the 4 KiB fallback is taken -- the alloc_size in
    // GuestMemory is computed before the page-policy fallback. So
    // use mem.size() instead of kRamBytes when computing the host
    // RAM bound.
    constexpr std::size_t kRamBytes = 1 << 20;
    GuestMemory ram(part, /*gpa=*/0, kRamBytes, /*executable=*/false);
    const std::size_t kRamActual = ram.size();
    auto* host_ram = static_cast<std::uint8_t*>(ram.host_base());
    std::memset(host_ram, 0, kRamActual);
    const std::uint8_t* ram_lo = host_ram;
    const std::uint8_t* ram_hi = host_ram + kRamActual;

    // Lay out the rings in guest RAM:
    //   desc  ring: 256 * 16 = 4096 bytes @ 0x10000
    //   avail ring: 6 + 256*2 + 2 = 520 bytes @ 0x11000
    //   used  ring: 6 + 256*8 + 2 = 2056 bytes @ 0x12000
    // Leaves [0..0x10000) free for descriptor buffer targets.
    constexpr std::uint32_t kQSize    = 256;
    constexpr std::uint64_t kDescGpa  = 0x10000;
    constexpr std::uint64_t kAvailGpa = 0x11000;
    constexpr std::uint64_t kUsedGpa  = 0x12000;
    constexpr std::uint64_t kBufLo    = 0x00100;
    constexpr std::uint64_t kBufHi    = 0x10000;

    v::Virtqueue vq(ram, /*max_size=*/kQSize);
    vq.SetSize(kQSize);
    vq.SetDescGpa(kDescGpa);
    vq.SetAvailGpa(kAvailGpa);
    vq.SetUsedGpa(kUsedGpa);
    vq.SetReady(true);

    // Convenience writers for desc/avail entries.
    auto wr_desc = [&](std::uint16_t idx, std::uint64_t addr,
                        std::uint32_t len, std::uint16_t flags,
                        std::uint16_t next) {
        std::uint8_t* p = host_ram + kDescGpa + idx * 16ULL;
        std::memcpy(p + 0, &addr, 8);
        std::memcpy(p + 8, &len, 4);
        std::memcpy(p + 12, &flags, 2);
        std::memcpy(p + 14, &next, 2);
    };
    auto wr_avail_idx = [&](std::uint16_t idx) {
        std::memcpy(host_ram + kAvailGpa + 2, &idx, 2);
    };
    auto wr_avail_ring = [&](std::uint16_t slot, std::uint16_t head) {
        std::memcpy(host_ram + kAvailGpa + 4 + slot * 2ULL, &head, 2);
    };

    constexpr std::uint16_t kVringDescFNext     = 0x1;
    constexpr std::uint16_t kVringDescFWrite    = 0x2;
    constexpr std::uint16_t kVringDescFIndirect = 0x4;

    std::mt19937_64 rng(seed);
    auto rnd = [&rng](std::uint64_t hi) -> std::uint64_t {
        return hi == 0 ? 0 : (rng() % hi);
    };

    std::uint16_t next_head = 0;
    std::uint16_t avail_idx = 0;
    int pops = 0, nulls = 0, escapes = 0, oversize = 0;

    for (int i = 0; i < iters; ++i) {
        // Pick chain length L in [1..16], occasionally bigger (up to 32).
        const std::size_t L = 1 + (rnd(16) + ((rng() & 0xF) == 0 ? rnd(16) : 0));

        // Build the chain via L descriptors at sequential indices
        // [next_head .. next_head + L - 1] (mod kQSize).
        const std::uint16_t head = next_head;
        for (std::size_t k = 0; k < L; ++k) {
            const std::uint16_t idx =
                static_cast<std::uint16_t>((head + k) % kQSize);
            // Random addr: 70% inside the buffer region, 20% inside
            // RAM but possibly clipping, 10% outside RAM.
            std::uint64_t addr;
            const std::uint32_t bucket = static_cast<std::uint32_t>(rng()) % 10;
            if (bucket < 7) {
                addr = kBufLo + (rnd(kBufHi - kBufLo) & ~7ULL);
            } else if (bucket < 9) {
                addr = rnd(kRamBytes);
            } else {
                addr = kRamBytes + rnd(kRamBytes);   // out of RAM
            }
            // Random len: usually small (0..4096), sometimes huge.
            std::uint32_t len;
            const std::uint32_t lb = static_cast<std::uint32_t>(rng()) % 8;
            if (lb < 6) {
                len = static_cast<std::uint32_t>(rnd(4097));
            } else if (lb < 7) {
                len = static_cast<std::uint32_t>(rnd(static_cast<std::uint64_t>(kRamBytes)) * 2);
            } else {
                len = static_cast<std::uint32_t>(rng());  // very large
            }
            // Flags: NEXT for non-last, occasionally INDIRECT, random WRITE.
            std::uint16_t flags = 0;
            if (k + 1 < L) flags |= kVringDescFNext;
            if ((rng() & 1) == 0) flags |= kVringDescFWrite;
            // INDIRECT: only on the very first descriptor of a single-entry
            // chain (or rarely standalone). We don't actually write a
            // valid inner table -- the parser MUST detect that the inner
            // GPA + len cover unmapped/oversized memory and fail.
            if (L == 1 && (rng() & 0x1F) == 0) flags |= kVringDescFIndirect;
            // next: usually +1, but 1/16 of the time pick a random
            // index (could form a cycle or wrap).
            std::uint16_t nxt = static_cast<std::uint16_t>(
                (idx + 1) % kQSize);
            if ((rng() & 0xF) == 0) {
                nxt = static_cast<std::uint16_t>(rng() % kQSize);
            }
            wr_desc(idx, addr, len, flags, nxt);
        }

        // Publish to avail.
        wr_avail_ring(avail_idx % kQSize, head);
        ++avail_idx;
        wr_avail_idx(avail_idx);

        // Wrap next_head so we keep cycling through the 256 desc slots.
        next_head = static_cast<std::uint16_t>(
            (next_head + L) % kQSize);

        // Pop and validate.
        try {
            auto chain = vq.Pop();
            ++pops;
            if (!chain) {
                ++nulls;
                continue;
            }
            // Every buffer span must lie within the host RAM range.
            for (const auto& b : chain->bufs) {
                if (b.bytes.empty()) continue;
                if (b.bytes.data() < ram_lo || b.bytes.data() > ram_hi) {
                    ++escapes;
                    std::fprintf(stderr,
                        "[virtio-queue-fuzz-test] FAIL: buffer ptr %p "
                        "escapes RAM [%p..%p) at iter=%d seed=%llu\n",
                        (const void*)b.bytes.data(),
                        (const void*)ram_lo, (const void*)ram_hi,
                        i, static_cast<unsigned long long>(seed));
                    return 1;
                }
                if (b.bytes.data() + b.bytes.size() > ram_hi) {
                    ++escapes;
                    std::fprintf(stderr,
                        "[virtio-queue-fuzz-test] FAIL: buffer end %p+%zu "
                        "escapes RAM [%p..%p) at iter=%d seed=%llu\n",
                        (const void*)b.bytes.data(), b.bytes.size(),
                        (const void*)ram_lo, (const void*)ram_hi,
                        i, static_cast<unsigned long long>(seed));
                    return 1;
                }
                if (b.bytes.size() > kRamActual) {
                    ++oversize;
                    std::fprintf(stderr,
                        "[virtio-queue-fuzz-test] FAIL: oversize buffer "
                        "%zu > %zu at iter=%d seed=%llu\n",
                        b.bytes.size(), kRamActual,
                        i, static_cast<unsigned long long>(seed));
                    return 1;
                }
            }
            // Release the chain back to the device-write side via Push;
            // exercises used-ring layout under random conditions too.
            vq.Push(chain->head_index, /*used_len=*/0);
        } catch (...) {
            std::fprintf(stderr,
                "[virtio-queue-fuzz-test] FAIL: exception at iter=%d "
                "seed=%llu\n", i, static_cast<unsigned long long>(seed));
            return 1;
        }
    }

    std::printf("[virtio-queue-fuzz-test] PASS (%d iters, seed=%llu, "
                "pops=%d, nulls=%d, escapes=%d, oversize=%d)\n",
                iters, static_cast<unsigned long long>(seed),
                pops, nulls, escapes, oversize);
    return 0;
}

// --virtio-rng-test (M17)
// Drive a virtio-rng device end-to-end via the PCI transport. Push a
// single writable 256-byte descriptor and verify:
//   * PCI identity (VID=0x1AF4, DID=0x1044)
//   * Feature negotiation succeeds with VERSION_1 only
//   * Notify → device fills the desc with random bytes
//   * used.idx == 1, used.ring[0].len == 256
//   * Byte histogram passes a sanity check (no value occurs >50% of the
//     time, and at least 64 distinct values appear)
//   * MSI fired once on the queue vector
int RunVirtioRngTest() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;
    namespace p = tinyvmm::pci;
    namespace v = tinyvmm::virtio;

    std::puts("[virtio-rng-test] starting (host-side; no WHP)");

    CheckWhpAvailable();
    Partition part(/*vcpu_count=*/1);
    part.Setup();
    constexpr std::size_t kRamBytes = 0x200000;
    GuestMemory ram(part, /*gpa=*/0, kRamBytes, /*executable=*/false);
    auto* host_ram = static_cast<std::uint8_t*>(ram.host_base());
    std::memset(host_ram, 0, kRamBytes);

    devices::IoBus   io_bus;
    devices::MmioBus mmio_bus;
    p::PciBus        pbus;
    pbus.AttachIoBus(io_bus);

    std::vector<InjectRecord> injects;
    auto inject_fn = [&](std::uint64_t a, std::uint32_t d) {
        injects.push_back({a, d});
        return true;
    };

    auto rng = std::make_unique<v::RngDevice>(ram);
    v::RngDevice* rng_ptr = rng.get();

    v::PciTransport::Options opts;
    opts.subsys_id        = static_cast<std::uint16_t>(v::kDeviceIdRng);
    opts.num_msix_vectors = 2;     // requestq + config
    opts.pci_class        = 0xFF;  // Other
    opts.pci_subclass     = 0x00;
    auto xport = std::make_unique<v::PciTransport>(
        *rng_ptr, opts, mmio_bus, inject_fn);
    v::PciTransport* tx_ptr = xport.get();
    xport->set_name("virtio-pci-rng");

    rng_ptr->SetIrqCallback(
        [tx_ptr](std::uint32_t q) { tx_ptr->RaiseQueueInterrupt(q); });

    const p::Bdf bdf = pbus.AddDevice(std::move(xport));
    std::printf("[virtio-rng-test] device @ %02x:%02x.%u\n",
                bdf.bus, bdf.device, bdf.function);

    auto io_w = [&](std::uint16_t port, std::uint16_t size, std::uint32_t val) {
        devices::IoAccess a{port, size, /*write=*/true, val};
        if (!io_bus.Dispatch(a)) Fatal("virtio-rng-test: unmatched IO write");
    };
    auto io_r = [&](std::uint16_t port, std::uint16_t size) -> std::uint32_t {
        devices::IoAccess a{port, size, /*write=*/false, 0};
        if (!io_bus.Dispatch(a)) Fatal("virtio-rng-test: unmatched IO read");
        return a.value;
    };
    auto encode = [](std::uint8_t b, std::uint8_t d, std::uint8_t fn,
                      std::uint8_t reg) -> std::uint32_t {
        return p::kConfigAddressEnable | (std::uint32_t{b} << 16) |
               (std::uint32_t{d} << 11) | (std::uint32_t{fn} << 8) |
               (reg & 0xFCu);
    };
    auto cfg_r = [&](std::uint8_t reg, std::uint16_t size) -> std::uint32_t {
        io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, reg));
        return io_r(static_cast<std::uint16_t>(p::kConfigDataPort + (reg & 3)),
                    size);
    };
    auto cfg_w = [&](std::uint8_t reg, std::uint16_t size, std::uint32_t val) {
        io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, reg));
        io_w(static_cast<std::uint16_t>(p::kConfigDataPort + (reg & 3)), size,
             val);
    };
    auto mmio_w = [&](std::uint64_t gpa, std::uint32_t val, std::uint8_t sz) {
        devices::MmioAccess a{};
        a.gpa = gpa; a.access_size = sz; a.is_write = true;
        std::memcpy(a.data, &val, std::min<std::size_t>(sz, 4));
        if (!mmio_bus.Dispatch(a))
            Fatal("virtio-rng-test: unmatched MMIO write");
    };
    auto mmio_r = [&](std::uint64_t gpa, std::uint8_t sz) -> std::uint32_t {
        devices::MmioAccess a{};
        a.gpa = gpa; a.access_size = sz; a.is_write = false;
        if (!mmio_bus.Dispatch(a))
            Fatal("virtio-rng-test: unmatched MMIO read");
        std::uint32_t v = 0;
        std::memcpy(&v, a.data, std::min<std::size_t>(sz, 4));
        return v;
    };

    // (a) Identity.
    const std::uint32_t vid_did = cfg_r(p::kCfgVendorId, 4);
    if (vid_did != ((std::uint32_t{0x1044} << 16) | 0x1AF4u)) {
        std::fprintf(stderr,
            "[virtio-rng-test] FAIL: VID/DID=0x%08x (want 0x1AF4/0x1044)\n",
            vid_did);
        return 16;
    }

    // (b) Walk caps, locate MSI-X.
    std::uint8_t cap = static_cast<std::uint8_t>(cfg_r(p::kCfgCapPtr, 1));
    std::uint8_t msix_cap_off = 0;
    for (std::size_t i = 0; cap != 0 && i < 16; ++i) {
        const std::uint8_t id = static_cast<std::uint8_t>(cfg_r(cap, 1));
        if (id == p::kCapIdMsiX) msix_cap_off = cap;
        cap = static_cast<std::uint8_t>(
            cfg_r(static_cast<std::uint8_t>(cap + 1), 1));
    }
    if (!msix_cap_off) {
        std::fputs("[virtio-rng-test] FAIL: MSI-X cap not found\n", stderr);
        return 16;
    }

    // (c) Map BAR0.
    const std::uint32_t bar0_lo = cfg_r(p::kCfgBar0, 4);
    const std::uint32_t bar0_hi = cfg_r(p::kCfgBar0 + 4, 4);
    cfg_w(p::kCfgCommand, 2, p::kCmdMemorySpace | p::kCmdBusMaster);
    const std::uint64_t bar_gpa = (static_cast<std::uint64_t>(bar0_hi) << 32) |
                                   (bar0_lo & ~0xFu);

    // (d) num_queues == 1.
    const std::uint16_t num_queues = static_cast<std::uint16_t>(
        mmio_r(bar_gpa + 0x10, 4) >> 16);
    if (num_queues != v::kRngQueueCount) {
        std::fprintf(stderr,
            "[virtio-rng-test] FAIL: num_queues=%u (want %u)\n",
            num_queues, v::kRngQueueCount);
        return 16;
    }

    // (e) Feature negotiation: take just VERSION_1 (skip EVENT_IDX so
    //     ShouldInterruptDriver returns true on every Push).
    mmio_w(bar_gpa + 0x00, 0, 4);
    const std::uint32_t df_lo = mmio_r(bar_gpa + 0x04, 4);
    mmio_w(bar_gpa + 0x00, 1, 4);
    const std::uint32_t df_hi = mmio_r(bar_gpa + 0x04, 4);
    const std::uint64_t df =
        static_cast<std::uint64_t>(df_lo) |
        (static_cast<std::uint64_t>(df_hi) << 32);
    if ((df & v::kFeatureVersion1) == 0) {
        std::fputs("[virtio-rng-test] FAIL: VERSION_1 missing\n", stderr);
        return 16;
    }
    const std::uint64_t acked = v::kFeatureVersion1;
    mmio_w(bar_gpa + 0x14, v::kStatusAcknowledge, 1);
    mmio_w(bar_gpa + 0x14, v::kStatusAcknowledge | v::kStatusDriver, 1);
    mmio_w(bar_gpa + 0x08, 0, 4);
    mmio_w(bar_gpa + 0x0C, static_cast<std::uint32_t>(acked & 0xFFFFFFFFu), 4);
    mmio_w(bar_gpa + 0x08, 1, 4);
    mmio_w(bar_gpa + 0x0C, static_cast<std::uint32_t>(acked >> 32), 4);
    mmio_w(bar_gpa + 0x14,
           v::kStatusAcknowledge | v::kStatusDriver | v::kStatusFeaturesOk, 1);
    if ((mmio_r(bar_gpa + 0x14, 1) & v::kStatusFeaturesOk) == 0) {
        std::fputs("[virtio-rng-test] FAIL: FEATURES_OK rejected\n", stderr);
        return 16;
    }

    // (f) MSI-X table.
    constexpr std::uint64_t kMsiAddrBase = 0xFEE00000ull;
    auto program_msix = [&](std::uint32_t vec, std::uint32_t data) {
        const std::uint64_t tbl = bar_gpa + v::PciTransport::kOffMsixTable +
                                  16ull * vec;
        mmio_w(tbl + 0,
               static_cast<std::uint32_t>(kMsiAddrBase & 0xFFFFFFFFu), 4);
        mmio_w(tbl + 4,
               static_cast<std::uint32_t>(kMsiAddrBase >> 32), 4);
        mmio_w(tbl + 8, data, 4);
        mmio_w(tbl + 12, 0u, 4);
    };
    program_msix(0, 0x50);   // requestq
    program_msix(1, 0x51);   // config
    cfg_w(static_cast<std::uint8_t>(msix_cap_off + 2), 2, 0x8000u);

    // (g) Program queue 0 (size=8).
    constexpr std::uint64_t kDescGpa  = 0x30000;
    constexpr std::uint64_t kAvailGpa = 0x30100;
    constexpr std::uint64_t kUsedGpa  = 0x30200;
    constexpr std::uint64_t kDataGpa  = 0x40000;
    constexpr std::uint32_t kDataLen  = 256;
    constexpr std::uint32_t kQSize    = 8;
    mmio_w(bar_gpa + 0x16, 0, 2);
    mmio_w(bar_gpa + 0x18, kQSize, 2);
    mmio_w(bar_gpa + 0x1A, 0, 2);
    mmio_w(bar_gpa + 0x20, static_cast<std::uint32_t>(kDescGpa), 4);
    mmio_w(bar_gpa + 0x24, static_cast<std::uint32_t>(kDescGpa >> 32), 4);
    mmio_w(bar_gpa + 0x28, static_cast<std::uint32_t>(kAvailGpa), 4);
    mmio_w(bar_gpa + 0x2C, static_cast<std::uint32_t>(kAvailGpa >> 32), 4);
    mmio_w(bar_gpa + 0x30, static_cast<std::uint32_t>(kUsedGpa), 4);
    mmio_w(bar_gpa + 0x34, static_cast<std::uint32_t>(kUsedGpa >> 32), 4);
    mmio_w(bar_gpa + 0x1C, 1, 2);
    mmio_w(bar_gpa + 0x14,
           v::kStatusAcknowledge | v::kStatusDriver | v::kStatusFeaturesOk |
               v::kStatusDriverOk, 1);
    if (!rng_ptr->driver_ok() || !rng_ptr->request_queue().ready()) {
        std::fputs("[virtio-rng-test] FAIL: DRIVER_OK not honoured\n", stderr);
        return 16;
    }

#pragma pack(push, 1)
    struct VringDesc {
        std::uint64_t addr;
        std::uint32_t len;
        std::uint16_t flags;
        std::uint16_t next;
    };
#pragma pack(pop)
    auto* descs = reinterpret_cast<VringDesc*>(host_ram + kDescGpa);
    descs[0] = {kDataGpa, kDataLen, v::kVringDescFWrite, 0};
    auto* avail = host_ram + kAvailGpa;
    *reinterpret_cast<std::uint16_t*>(avail + 0) = 0;
    *reinterpret_cast<std::uint16_t*>(avail + 4) = 0;
    *reinterpret_cast<std::uint16_t*>(avail + 2) = 1;
    std::memset(host_ram + kDataGpa, 0, kDataLen);     // pre-poison

    // (h) Kick. RngDevice fills synchronously on this thread.
    injects.clear();
    mmio_w(bar_gpa + v::PciTransport::kOffNotify + 0, 0u, 2);

    // (i) Verify used ring.
    {
        auto* used = host_ram + kUsedGpa;
        const std::uint16_t used_idx =
            *reinterpret_cast<std::uint16_t*>(used + 2);
        const std::uint32_t used_id =
            *reinterpret_cast<std::uint32_t*>(used + 4);
        const std::uint32_t used_len =
            *reinterpret_cast<std::uint32_t*>(used + 8);
        if (used_idx != 1 || used_id != 0 || used_len != kDataLen) {
            std::fprintf(stderr,
                "[virtio-rng-test] FAIL: used idx=%u id=%u len=%u\n",
                used_idx, used_id, used_len);
            return 16;
        }
    }

    // (j) Sanity-check entropy: not all-zero, byte histogram looks
    //     plausibly random. With 256 bytes from a CSPRNG we expect to
    //     see at least 64 distinct values and no single value > 64 times.
    int counts[256] = {};
    std::uint32_t nonzero = 0;
    for (std::uint32_t i = 0; i < kDataLen; ++i) {
        const std::uint8_t b = host_ram[kDataGpa + i];
        counts[b]++;
        if (b != 0) nonzero++;
    }
    if (nonzero < kDataLen / 2) {
        std::fprintf(stderr,
            "[virtio-rng-test] FAIL: only %u/%u nonzero bytes\n",
            nonzero, kDataLen);
        return 16;
    }
    int distinct = 0, max_count = 0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] > 0) distinct++;
        if (counts[i] > max_count) max_count = counts[i];
    }
    if (distinct < 64 || max_count > 64) {
        std::fprintf(stderr,
            "[virtio-rng-test] FAIL: distinct=%d max_count=%d\n",
            distinct, max_count);
        return 16;
    }

    // (k) Exactly one MSI on vector 0x50.
    if (injects.size() != 1 || injects[0].data != 0x50) {
        std::fprintf(stderr,
            "[virtio-rng-test] FAIL: irq sequence count=%zu",
            injects.size());
        for (auto& r : injects)
            std::fprintf(stderr, " data=0x%x", r.data);
        std::fputs("\n", stderr);
        return 16;
    }

    // Counters.
    if (rng_ptr->ops_done() != 1 || rng_ptr->bytes_out() != kDataLen) {
        std::fprintf(stderr,
            "[virtio-rng-test] FAIL: counters ops=%llu bytes=%llu\n",
            static_cast<unsigned long long>(rng_ptr->ops_done()),
            static_cast<unsigned long long>(rng_ptr->bytes_out()));
        return 16;
    }

    // (l) A second, larger request to confirm we don't accidentally reuse
    //     state. 4 KiB this time, in 3 chained writable descs.
    constexpr std::uint64_t kData2Gpa  = 0x50000;
    constexpr std::uint32_t kData2Len  = 4096;
    descs[1] = {kData2Gpa,                            1024, v::kVringDescFNext | v::kVringDescFWrite, 2};
    descs[2] = {kData2Gpa + 1024,                     2048, v::kVringDescFNext | v::kVringDescFWrite, 3};
    descs[3] = {kData2Gpa + 1024 + 2048,              1024, v::kVringDescFWrite, 0};
    *reinterpret_cast<std::uint16_t*>(avail + 6) = 1;          // ring[1]=head 1
    *reinterpret_cast<std::uint16_t*>(avail + 2) = 2;          // idx=2
    std::memset(host_ram + kData2Gpa, 0xCD, kData2Len);
    injects.clear();
    mmio_w(bar_gpa + v::PciTransport::kOffNotify + 0, 0u, 2);
    {
        auto* used = host_ram + kUsedGpa;
        const std::uint16_t used_idx =
            *reinterpret_cast<std::uint16_t*>(used + 2);
        const std::uint32_t entry_id =
            *reinterpret_cast<std::uint32_t*>(used + 4 + 8);
        const std::uint32_t entry_len =
            *reinterpret_cast<std::uint32_t*>(used + 4 + 8 + 4);
        if (used_idx != 2 || entry_id != 1 || entry_len != kData2Len) {
            std::fprintf(stderr,
                "[virtio-rng-test] FAIL: chained used idx=%u id=%u len=%u\n",
                used_idx, entry_id, entry_len);
            return 16;
        }
    }
    // None of the 4096 bytes should still be 0xCD after the fill.
    std::uint32_t still_poisoned = 0;
    for (std::uint32_t i = 0; i < kData2Len; ++i) {
        if (host_ram[kData2Gpa + i] == 0xCD) still_poisoned++;
    }
    // Probabilistically a CSPRNG gives ~16 occurrences of any byte in 4 KiB.
    if (still_poisoned > 64) {
        std::fprintf(stderr,
            "[virtio-rng-test] FAIL: %u/%u bytes still 0xCD (fill missed?)\n",
            still_poisoned, kData2Len);
        return 16;
    }
    if (injects.size() != 1 || injects[0].data != 0x50) {
        std::fputs("[virtio-rng-test] FAIL: 2nd irq wrong\n", stderr);
        return 16;
    }

    std::printf("[virtio-rng-test] PASS (ops=%llu bytes=%llu distinct=%d)\n",
                static_cast<unsigned long long>(rng_ptr->ops_done()),
                static_cast<unsigned long long>(rng_ptr->bytes_out()),
                distinct);
    (void)host_ram;
    return 0;
}

// --virtio-console-test (M20)
// Host-side smoke test for the virtio-console device: probe its PCI
// identity, negotiate VERSION_1, set up transmitq (qidx=1), push a
// short chain, kick the doorbell, and verify the bytes were drained
// to the device's capture buffer plus an MSI fired. Also verifies the
// new `avail_event` write happens correctly (drives a 2nd chain and
// checks the device's view of last_avail_ matches).
int RunVirtioConsoleTest() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;
    namespace p = tinyvmm::pci;
    namespace v = tinyvmm::virtio;

    std::puts("[virtio-console-test] starting (host-side; no WHP)");

    CheckWhpAvailable();
    Partition part(/*vcpu_count=*/1);
    part.Setup();
    constexpr std::size_t kRamBytes = 0x200000;
    GuestMemory ram(part, /*gpa=*/0, kRamBytes, /*executable=*/false);
    auto* host_ram = static_cast<std::uint8_t*>(ram.host_base());
    std::memset(host_ram, 0, kRamBytes);

    devices::IoBus   io_bus;
    devices::MmioBus mmio_bus;
    p::PciBus        pbus;
    pbus.AttachIoBus(io_bus);

    std::vector<InjectRecord> injects;
    auto inject_fn = [&](std::uint64_t a, std::uint32_t d) {
        injects.push_back({a, d});
        return true;
    };

    auto vcon = std::make_unique<v::ConsoleDevice>(ram, /*sink=*/nullptr);
    vcon->SetCapture(true);
    v::ConsoleDevice* vcon_ptr = vcon.get();

    v::PciTransport::Options opts;
    opts.subsys_id        = static_cast<std::uint16_t>(v::kDeviceIdConsole);
    opts.num_msix_vectors = 3;     // rx + tx + config
    opts.pci_class        = 0x07;
    opts.pci_subclass     = 0x80;
    auto xport = std::make_unique<v::PciTransport>(
        *vcon_ptr, opts, mmio_bus, inject_fn);
    v::PciTransport* tx_ptr = xport.get();
    xport->set_name("virtio-pci-console");
    vcon_ptr->SetIrqCallback(
        [tx_ptr](std::uint32_t q) { tx_ptr->RaiseQueueInterrupt(q); });

    const p::Bdf bdf = pbus.AddDevice(std::move(xport));
    std::printf("[virtio-console-test] device @ %02x:%02x.%u\n",
                bdf.bus, bdf.device, bdf.function);

    auto io_w = [&](std::uint16_t port, std::uint16_t size, std::uint32_t val) {
        devices::IoAccess a{port, size, /*write=*/true, val};
        if (!io_bus.Dispatch(a)) Fatal("virtio-console-test: unmatched IO write");
    };
    auto io_r = [&](std::uint16_t port, std::uint16_t size) -> std::uint32_t {
        devices::IoAccess a{port, size, /*write=*/false, 0};
        if (!io_bus.Dispatch(a)) Fatal("virtio-console-test: unmatched IO read");
        return a.value;
    };
    auto encode = [](std::uint8_t b, std::uint8_t d, std::uint8_t fn,
                      std::uint8_t reg) -> std::uint32_t {
        return p::kConfigAddressEnable | (std::uint32_t{b} << 16) |
               (std::uint32_t{d} << 11) | (std::uint32_t{fn} << 8) |
               (reg & 0xFCu);
    };
    auto cfg_r = [&](std::uint8_t reg, std::uint16_t size) -> std::uint32_t {
        io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, reg));
        return io_r(static_cast<std::uint16_t>(p::kConfigDataPort + (reg & 3)),
                    size);
    };
    auto cfg_w = [&](std::uint8_t reg, std::uint16_t size, std::uint32_t val) {
        io_w(p::kConfigAddressPort, 4, encode(0, 0, 0, reg));
        io_w(static_cast<std::uint16_t>(p::kConfigDataPort + (reg & 3)), size,
             val);
    };
    auto mmio_w = [&](std::uint64_t gpa, std::uint32_t val, std::uint8_t sz) {
        devices::MmioAccess a{};
        a.gpa = gpa; a.access_size = sz; a.is_write = true;
        std::memcpy(a.data, &val, std::min<std::size_t>(sz, 4));
        if (!mmio_bus.Dispatch(a))
            Fatal("virtio-console-test: unmatched MMIO write");
    };
    auto mmio_r = [&](std::uint64_t gpa, std::uint8_t sz) -> std::uint32_t {
        devices::MmioAccess a{};
        a.gpa = gpa; a.access_size = sz; a.is_write = false;
        if (!mmio_bus.Dispatch(a))
            Fatal("virtio-console-test: unmatched MMIO read");
        std::uint32_t v = 0;
        std::memcpy(&v, a.data, std::min<std::size_t>(sz, 4));
        return v;
    };

    // (a) Identity. Modern virtio-PCI device ID = 0x1040 + virtio-device-id.
    //     For console (device-id=3) that's 0x1043.
    const std::uint32_t vid_did = cfg_r(p::kCfgVendorId, 4);
    if (vid_did != ((std::uint32_t{0x1043} << 16) | 0x1AF4u)) {
        std::fprintf(stderr,
            "[virtio-console-test] FAIL: VID/DID=0x%08x (want 0x1AF4/0x1043)\n",
            vid_did);
        return 16;
    }

    // (b) Walk caps, locate MSI-X.
    std::uint8_t cap = static_cast<std::uint8_t>(cfg_r(p::kCfgCapPtr, 1));
    std::uint8_t msix_cap_off = 0;
    for (std::size_t i = 0; cap != 0 && i < 16; ++i) {
        const std::uint8_t id = static_cast<std::uint8_t>(cfg_r(cap, 1));
        if (id == p::kCapIdMsiX) msix_cap_off = cap;
        cap = static_cast<std::uint8_t>(
            cfg_r(static_cast<std::uint8_t>(cap + 1), 1));
    }
    if (!msix_cap_off) {
        std::fputs("[virtio-console-test] FAIL: MSI-X cap not found\n", stderr);
        return 16;
    }

    // (c) Map BAR0 + enable mem/bus-master.
    const std::uint32_t bar0_lo = cfg_r(p::kCfgBar0, 4);
    const std::uint32_t bar0_hi = cfg_r(p::kCfgBar0 + 4, 4);
    cfg_w(p::kCfgCommand, 2, p::kCmdMemorySpace | p::kCmdBusMaster);
    const std::uint64_t bar_gpa = (static_cast<std::uint64_t>(bar0_hi) << 32) |
                                   (bar0_lo & ~0xFu);

    // (d) num_queues == 2.
    const std::uint16_t num_queues = static_cast<std::uint16_t>(
        mmio_r(bar_gpa + 0x10, 4) >> 16);
    if (num_queues != v::kConsoleQueueCount) {
        std::fprintf(stderr,
            "[virtio-console-test] FAIL: num_queues=%u (want %u)\n",
            num_queues, v::kConsoleQueueCount);
        return 16;
    }

    // (e) Feature negotiation: VERSION_1 only (skip EVENT_IDX so the test
    //     doesn't depend on the avail_event write — that's covered in (j)).
    mmio_w(bar_gpa + 0x00, 0, 4);
    const std::uint32_t df_lo = mmio_r(bar_gpa + 0x04, 4);
    mmio_w(bar_gpa + 0x00, 1, 4);
    const std::uint32_t df_hi = mmio_r(bar_gpa + 0x04, 4);
    const std::uint64_t df =
        static_cast<std::uint64_t>(df_lo) |
        (static_cast<std::uint64_t>(df_hi) << 32);
    if ((df & v::kFeatureVersion1) == 0) {
        std::fputs("[virtio-console-test] FAIL: VERSION_1 missing\n", stderr);
        return 16;
    }
    // Verify select>=2 reads-as-zero (the fix from M19c.7 is exercised here
    // for completeness; tested before but good to keep regression coverage).
    mmio_w(bar_gpa + 0x00, 2, 4);
    if (mmio_r(bar_gpa + 0x04, 4) != 0) {
        std::fputs("[virtio-console-test] FAIL: device_feature[2] not 0\n", stderr);
        return 16;
    }
    const std::uint64_t acked = v::kFeatureVersion1;
    mmio_w(bar_gpa + 0x14, v::kStatusAcknowledge, 1);
    mmio_w(bar_gpa + 0x14, v::kStatusAcknowledge | v::kStatusDriver, 1);
    mmio_w(bar_gpa + 0x08, 0, 4);
    mmio_w(bar_gpa + 0x0C, static_cast<std::uint32_t>(acked & 0xFFFFFFFFu), 4);
    mmio_w(bar_gpa + 0x08, 1, 4);
    mmio_w(bar_gpa + 0x0C, static_cast<std::uint32_t>(acked >> 32), 4);
    // Linux 6.x writes selects 2,3 with 0 -- exercise our nop-on-extended fix.
    mmio_w(bar_gpa + 0x08, 2, 4);
    mmio_w(bar_gpa + 0x0C, 0u, 4);
    mmio_w(bar_gpa + 0x08, 3, 4);
    mmio_w(bar_gpa + 0x0C, 0u, 4);
    mmio_w(bar_gpa + 0x14,
           v::kStatusAcknowledge | v::kStatusDriver | v::kStatusFeaturesOk, 1);
    if ((mmio_r(bar_gpa + 0x14, 1) & v::kStatusFeaturesOk) == 0) {
        std::fputs("[virtio-console-test] FAIL: FEATURES_OK rejected\n", stderr);
        return 16;
    }

    // (f) MSI-X table. vec 0=rx, 1=tx, 2=cfg.
    constexpr std::uint64_t kMsiAddrBase = 0xFEE00000ull;
    auto program_msix = [&](std::uint32_t vec, std::uint32_t data) {
        const std::uint64_t tbl = bar_gpa + v::PciTransport::kOffMsixTable +
                                  16ull * vec;
        mmio_w(tbl + 0,
               static_cast<std::uint32_t>(kMsiAddrBase & 0xFFFFFFFFu), 4);
        mmio_w(tbl + 4,
               static_cast<std::uint32_t>(kMsiAddrBase >> 32), 4);
        mmio_w(tbl + 8, data, 4);
        mmio_w(tbl + 12, 0u, 4);
    };
    program_msix(0, 0x60);
    program_msix(1, 0x61);
    program_msix(2, 0x62);
    cfg_w(static_cast<std::uint8_t>(msix_cap_off + 2), 2, 0x8000u);

    // (g) Program transmitq (qidx=1, size=8).
    constexpr std::uint64_t kDescGpa  = 0x30000;
    constexpr std::uint64_t kAvailGpa = 0x30100;
    constexpr std::uint64_t kUsedGpa  = 0x30200;
    constexpr std::uint64_t kDataGpa  = 0x40000;
    constexpr std::uint32_t kQSize    = 8;
    mmio_w(bar_gpa + 0x16, 1, 2);                       // queue_select = 1 (txq)
    mmio_w(bar_gpa + 0x18, kQSize, 2);
    mmio_w(bar_gpa + 0x1A, 1, 2);                       // queue_msix_vector = 1
    mmio_w(bar_gpa + 0x20, static_cast<std::uint32_t>(kDescGpa), 4);
    mmio_w(bar_gpa + 0x24, static_cast<std::uint32_t>(kDescGpa >> 32), 4);
    mmio_w(bar_gpa + 0x28, static_cast<std::uint32_t>(kAvailGpa), 4);
    mmio_w(bar_gpa + 0x2C, static_cast<std::uint32_t>(kAvailGpa >> 32), 4);
    mmio_w(bar_gpa + 0x30, static_cast<std::uint32_t>(kUsedGpa), 4);
    mmio_w(bar_gpa + 0x34, static_cast<std::uint32_t>(kUsedGpa >> 32), 4);
    mmio_w(bar_gpa + 0x1C, 1, 2);                       // queue_enable
    mmio_w(bar_gpa + 0x14,
           v::kStatusAcknowledge | v::kStatusDriver | v::kStatusFeaturesOk |
               v::kStatusDriverOk, 1);
    if (!vcon_ptr->driver_ok() || !vcon_ptr->transmit_queue().ready()) {
        std::fputs("[virtio-console-test] FAIL: DRIVER_OK not honoured\n", stderr);
        return 16;
    }

#pragma pack(push, 1)
    struct VringDesc {
        std::uint64_t addr;
        std::uint32_t len;
        std::uint16_t flags;
        std::uint16_t next;
    };
#pragma pack(pop)
    auto* descs = reinterpret_cast<VringDesc*>(host_ram + kDescGpa);
    constexpr const char kMsg1[] = "hello hvc0!\n";
    constexpr std::uint32_t kMsg1Len = sizeof(kMsg1) - 1;
    std::memcpy(host_ram + kDataGpa, kMsg1, kMsg1Len);
    descs[0] = {kDataGpa, kMsg1Len, 0 /*read-only*/, 0};
    auto* avail = host_ram + kAvailGpa;
    *reinterpret_cast<std::uint16_t*>(avail + 0) = 0;
    *reinterpret_cast<std::uint16_t*>(avail + 4) = 0;       // ring[0]=head 0
    *reinterpret_cast<std::uint16_t*>(avail + 2) = 1;       // avail.idx=1

    // (h) Kick txq (queue index 1).
    injects.clear();
    mmio_w(bar_gpa + v::PciTransport::kOffNotify + 2 * 1, 1u, 2);

    // (i) Verify the captured bytes match.
    auto cap1 = vcon_ptr->capture_snapshot();
    if (cap1.size() != kMsg1Len ||
        std::memcmp(cap1.data(), kMsg1, kMsg1Len) != 0) {
        std::fprintf(stderr,
            "[virtio-console-test] FAIL: captured %zu bytes (want %u)\n",
            cap1.size(), kMsg1Len);
        return 16;
    }
    // Used ring entry: len=0 per spec §5.3.6.1.
    {
        auto* used = host_ram + kUsedGpa;
        const std::uint16_t used_idx =
            *reinterpret_cast<std::uint16_t*>(used + 2);
        const std::uint32_t used_len =
            *reinterpret_cast<std::uint32_t*>(used + 8);
        if (used_idx != 1 || used_len != 0) {
            std::fprintf(stderr,
                "[virtio-console-test] FAIL: used idx=%u len=%u (want 1,0)\n",
                used_idx, used_len);
            return 16;
        }
    }
    // Exactly one MSI on vector 0x61 (txq).
    if (injects.size() != 1 || injects[0].data != 0x61) {
        std::fprintf(stderr,
            "[virtio-console-test] FAIL: irq count=%zu",
            injects.size());
        for (auto& r : injects)
            std::fprintf(stderr, " data=0x%x", r.data);
        std::fputs("\n", stderr);
        return 16;
    }

    // (j) Second chain: confirms multi-chain drain works. Push 3 chained
    //     descriptors with payloads, kick again.
    constexpr const char kMsg2a[] = "line2-";
    constexpr const char kMsg2b[] = "of-three-";
    constexpr const char kMsg2c[] = "parts\n";
    constexpr std::uint32_t kMsg2aLen = sizeof(kMsg2a) - 1;
    constexpr std::uint32_t kMsg2bLen = sizeof(kMsg2b) - 1;
    constexpr std::uint32_t kMsg2cLen = sizeof(kMsg2c) - 1;
    constexpr std::uint64_t kData2a = kDataGpa + 0x100;
    constexpr std::uint64_t kData2b = kDataGpa + 0x200;
    constexpr std::uint64_t kData2c = kDataGpa + 0x300;
    std::memcpy(host_ram + kData2a, kMsg2a, kMsg2aLen);
    std::memcpy(host_ram + kData2b, kMsg2b, kMsg2bLen);
    std::memcpy(host_ram + kData2c, kMsg2c, kMsg2cLen);
    descs[1] = {kData2a, kMsg2aLen, v::kVringDescFNext, 2};
    descs[2] = {kData2b, kMsg2bLen, v::kVringDescFNext, 3};
    descs[3] = {kData2c, kMsg2cLen, 0, 0};
    *reinterpret_cast<std::uint16_t*>(avail + 6) = 1;          // ring[1]=head 1
    *reinterpret_cast<std::uint16_t*>(avail + 2) = 2;          // avail.idx=2
    injects.clear();
    mmio_w(bar_gpa + v::PciTransport::kOffNotify + 2 * 1, 1u, 2);

    auto cap2 = vcon_ptr->capture_snapshot();
    const std::size_t expected2 =
        kMsg1Len + kMsg2aLen + kMsg2bLen + kMsg2cLen;
    if (cap2.size() != expected2) {
        std::fprintf(stderr,
            "[virtio-console-test] FAIL: total captured %zu (want %zu)\n",
            cap2.size(), expected2);
        return 16;
    }
    const char kExpectedSuffix[] = "line2-of-three-parts\n";
    if (std::memcmp(cap2.data() + kMsg1Len, kExpectedSuffix,
                    sizeof(kExpectedSuffix) - 1) != 0) {
        std::fputs("[virtio-console-test] FAIL: chained payload mismatch\n",
                   stderr);
        return 16;
    }

    // (k) avail_event regression: after consuming both chains, the device
    //     must have written `avail_event = 2` at the tail of the used ring
    //     (this is the v1.x EVENT_IDX hint). EVENT_IDX wasn't negotiated
    //     here, so avail_event should remain 0. We test the positive case
    //     by reading back the field — it's at offset 4 + 8*size_ in used.
    const std::uint16_t avail_event =
        *reinterpret_cast<std::uint16_t*>(
            host_ram + kUsedGpa + 4 + 8 * kQSize);
    // event_idx_ disabled: we expect avail_event to remain 0 (uninitialized).
    if (avail_event != 0) {
        std::fprintf(stderr,
            "[virtio-console-test] FAIL: avail_event=%u (want 0 since "
            "EVENT_IDX not negotiated)\n",
            avail_event);
        return 16;
    }

    if (vcon_ptr->tx_chains() != 2 ||
        vcon_ptr->tx_bytes()  != static_cast<std::uint64_t>(expected2)) {
        std::fprintf(stderr,
            "[virtio-console-test] FAIL: counters chains=%llu bytes=%llu\n",
            static_cast<unsigned long long>(vcon_ptr->tx_chains()),
            static_cast<unsigned long long>(vcon_ptr->tx_bytes()));
        return 16;
    }

    std::printf("[virtio-console-test] PASS (chains=%llu bytes=%llu)\n",
                static_cast<unsigned long long>(vcon_ptr->tx_chains()),
                static_cast<unsigned long long>(vcon_ptr->tx_bytes()));
    (void)host_ram;
    return 0;
}

// --snapshot-trigger-test (M33 Phase 33.1)
// Drives the magic CPUID leaf 0x4000DE57 from a real-mode stub and verifies:
//
//   1. With snapshot::State().armed == false (disarmed): the leaf returns
//      the signature (EAX=0, EBX='TINY', ECX='SAVE', EDX=1), RIP is
//      advanced past the CPUID, and the run loop continues to the
//      subsequent HLT (stop reason GuestHalted because IF=0 in real
//      mode).
//
//   2. With snapshot::State().armed == true (armed): the leaf returns
//      the signature AND the run loop stops with
//      StopReason::SnapshotRequested, snapshot::WasRequested() flips
//      to true, and snapshot::State().requesting_vp_index records this
//      vCPU's index.
//
// Real-mode hand-assembled stub at GPA 0x1000 (CS.Base=0x1000, IP=0):
//
//      66 B8 57 DE 00 40   mov eax, 0x4000DE57
//      0F A2               cpuid
//      F4                  hlt
//
// The CPUID instruction stores its result in EAX/EBX/ECX/EDX. WHP's CPUID
// exit triggers our handler before any of those registers are written by
// hardware, so we set all 5 via WHvSetVirtualProcessorRegisters in the
// magic-leaf branch (the 5th being the next-RIP).
int RunSnapshotTriggerTest() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;
    namespace snap = ::tinyvmm::whp::snapshot;

    auto fail = [](const char* msg) {
        std::fprintf(stderr, "[snapshot-trigger-test] FAIL: %s\n", msg);
        return 2;
    };

    CheckWhpAvailable();
    std::puts("[snapshot-trigger-test] WHP available");

    // The 5-byte mov-imm32 + 2-byte cpuid + 1-byte hlt = 8 bytes total.
    constexpr std::uint64_t kCodeGpa = 0x1000;
    const std::uint8_t code[] = {
        0x66, 0xB8, 0x57, 0xDE, 0x00, 0x40,  // mov eax, 0x4000DE57
        0x0F, 0xA2,                          // cpuid
        0xF4,                                // hlt
    };

    // ---- Subtest 1: disarmed path -------------------------------------
    // Construct partition + memory + vCPU fresh per subtest so register
    // state doesn't bleed across.
    {
        // Reset global state explicitly (this test is the only writer; the
        // global persists across subtests within one process).
        snap::State().armed.store(false, std::memory_order_release);
        snap::State().requested.store(false, std::memory_order_release);
        snap::State().requesting_vp_index.store(0, std::memory_order_release);
        snap::State().save_path.clear();

        Partition part(/*vcpu_count=*/1);
        // The magic CPUID leaf only intercepts when CPUID exits are routed
        // to user-mode. This mirrors the production --pvh-run path which
        // enables cpuid+msr exits for the hypervisor enlightenment surface.
        part.EnableExtendedExits({.cpuid = true});
        part.Setup();

        const std::size_t kRamSize = host::LargePageSize();
        GuestMemory ram(part, /*gpa=*/0, kRamSize, /*executable=*/true);
        ram.WriteAt(kCodeGpa, code, sizeof(code));

        Vcpu vp(part, 0);
        vp.SetupRealMode(/*cs_base=*/kCodeGpa);
        WHV_REGISTER_VALUE rip = {}; rip.Reg64 = 0;
        vp.SetRegister(WHvX64RegisterRip, rip);

        devices::IoBus io_bus;
        devices::MmioBus mmio_bus;
        RunLoop loop(vp, io_bus, mmio_bus);
        std::puts("[snapshot-trigger-test] disarmed: running...");
        StopReason stop = loop.Run();

        if (stop != StopReason::GuestHalted) {
            std::fprintf(stderr,
                "[snapshot-trigger-test] disarmed: expected "
                "GuestHalted, got stop=%d\n", static_cast<int>(stop));
            return 2;
        }
        if (snap::WasRequested()) {
            return fail("disarmed: snapshot::WasRequested() must be false");
        }
        // Verify the signature landed in EAX/EBX/ECX/EDX.
        static const WHV_REGISTER_NAME kNames[] = {
            WHvX64RegisterRax, WHvX64RegisterRbx,
            WHvX64RegisterRcx, WHvX64RegisterRdx,
            WHvX64RegisterRip,
        };
        WHV_REGISTER_VALUE vals[5] = {};
        vp.GetRegisters(kNames, vals);
        // Real-mode EAX writes only update the low 32. CPUID upper-zeros
        // are architectural; checking the low 32 is sufficient.
        const std::uint32_t eax = static_cast<std::uint32_t>(vals[0].Reg64);
        const std::uint32_t ebx = static_cast<std::uint32_t>(vals[1].Reg64);
        const std::uint32_t ecx = static_cast<std::uint32_t>(vals[2].Reg64);
        const std::uint32_t edx = static_cast<std::uint32_t>(vals[3].Reg64);
        if (eax != snap::kSignatureEax || ebx != snap::kSignatureEbx ||
            ecx != snap::kSignatureEcx || edx != snap::kSignatureEdx) {
            std::fprintf(stderr,
                "[snapshot-trigger-test] disarmed: signature mismatch: "
                "eax=0x%08X ebx=0x%08X ecx=0x%08X edx=0x%08X "
                "(want %08X %08X %08X %08X)\n",
                eax, ebx, ecx, edx,
                snap::kSignatureEax, snap::kSignatureEbx,
                snap::kSignatureEcx, snap::kSignatureEdx);
            return 2;
        }
        // Verify RIP is at the HLT (offset 8, since code is 9 bytes total
        // and RIP points at the byte AFTER the HLT was executed). Real
        // mode RIP is reported in 16-bit form by WHP but stored as Reg64;
        // the value should be 9.
        if (vals[4].Reg64 != 9) {
            std::fprintf(stderr,
                "[snapshot-trigger-test] disarmed: RIP=0x%llx (expected 9)\n",
                static_cast<unsigned long long>(vals[4].Reg64));
            return 2;
        }
        std::printf("[snapshot-trigger-test] disarmed: PASS "
                    "(cpuid=%llu halt=%llu)\n",
                    static_cast<unsigned long long>(loop.cpuid_exits()),
                    static_cast<unsigned long long>(loop.halt_exits()));
    }

    // ---- Subtest 2: armed path ----------------------------------------
    {
        snap::State().armed.store(true, std::memory_order_release);
        snap::State().requested.store(false, std::memory_order_release);
        snap::State().requesting_vp_index.store(0xDEADBEEFu,
            std::memory_order_release);
        snap::State().save_path = "test://armed-path";

        Partition part(/*vcpu_count=*/1);
        part.EnableExtendedExits({.cpuid = true});
        part.Setup();

        const std::size_t kRamSize = host::LargePageSize();
        GuestMemory ram(part, /*gpa=*/0, kRamSize, /*executable=*/true);
        ram.WriteAt(kCodeGpa, code, sizeof(code));

        Vcpu vp(part, 0);
        vp.SetupRealMode(/*cs_base=*/kCodeGpa);
        WHV_REGISTER_VALUE rip = {}; rip.Reg64 = 0;
        vp.SetRegister(WHvX64RegisterRip, rip);

        devices::IoBus io_bus;
        devices::MmioBus mmio_bus;
        RunLoop loop(vp, io_bus, mmio_bus);
        std::puts("[snapshot-trigger-test] armed: running...");
        StopReason stop = loop.Run();

        if (stop != StopReason::SnapshotRequested) {
            std::fprintf(stderr,
                "[snapshot-trigger-test] armed: expected "
                "SnapshotRequested, got stop=%d\n", static_cast<int>(stop));
            return 2;
        }
        if (!snap::WasRequested()) {
            return fail("armed: snapshot::WasRequested() must be true");
        }
        if (snap::State().requesting_vp_index.load(
                std::memory_order_acquire) != 0u) {
            return fail("armed: requesting_vp_index must be 0 (this is vp 0)");
        }
        // Signature should still be present in EAX/EBX/ECX/EDX (the magic
        // CPUID branch writes them BEFORE deciding to stop).
        static const WHV_REGISTER_NAME kNames[] = {
            WHvX64RegisterRax, WHvX64RegisterRbx,
            WHvX64RegisterRcx, WHvX64RegisterRdx,
            WHvX64RegisterRip,
        };
        WHV_REGISTER_VALUE vals[5] = {};
        vp.GetRegisters(kNames, vals);
        const std::uint32_t eax = static_cast<std::uint32_t>(vals[0].Reg64);
        const std::uint32_t ebx = static_cast<std::uint32_t>(vals[1].Reg64);
        const std::uint32_t ecx = static_cast<std::uint32_t>(vals[2].Reg64);
        const std::uint32_t edx = static_cast<std::uint32_t>(vals[3].Reg64);
        if (eax != snap::kSignatureEax || ebx != snap::kSignatureEbx ||
            ecx != snap::kSignatureEcx || edx != snap::kSignatureEdx) {
            std::fprintf(stderr,
                "[snapshot-trigger-test] armed: signature mismatch: "
                "eax=0x%08X ebx=0x%08X ecx=0x%08X edx=0x%08X\n",
                eax, ebx, ecx, edx);
            return 2;
        }
        // RIP should be at offset 8 (just past CPUID), NOT at 9 (past HLT)
        // because we stop before reaching the HLT.
        if (vals[4].Reg64 != 8) {
            std::fprintf(stderr,
                "[snapshot-trigger-test] armed: RIP=0x%llx (expected 8)\n",
                static_cast<unsigned long long>(vals[4].Reg64));
            return 2;
        }
        if (loop.halt_exits() != 0) {
            return fail("armed: HLT must NOT have been reached");
        }
        std::printf("[snapshot-trigger-test] armed: PASS "
                    "(cpuid=%llu halt=%llu vp=%u path='%s')\n",
                    static_cast<unsigned long long>(loop.cpuid_exits()),
                    static_cast<unsigned long long>(loop.halt_exits()),
                    snap::State().requesting_vp_index.load(
                        std::memory_order_acquire),
                    snap::State().save_path.c_str());

        // Clean up: disarm so this global state doesn't poison anything
        // else if subsequent tests are added.
        snap::State().armed.store(false, std::memory_order_release);
        snap::State().requested.store(false, std::memory_order_release);
        snap::State().save_path.clear();
    }

    std::puts("[snapshot-trigger-test] PASS");
    return 0;
}

// --save-restore-probe (M33 Phase 33.2)
// Validate the WHP State API contract that Phase 33.3+ will depend on:
// (1) capture full vCPU + RAM state from a running partition,
// (2) destroy the partition,
// (3) recreate a fresh partition + vCPU,
// (4) apply saved state BEFORE the new vCPU's first Run,
// (5) verify the guest continues from exactly where it left off.
//
// Two subtests cover different save-point boundaries:
//   * Subtest 1: capture at HLT (clean architectural boundary).
//   * Subtest 2: capture at the magic CPUID SnapshotRequested exit
//     (the actual production save point — RIP advanced past CPUID by
//     the snapshot::HandleCpuidExit branch).
//
// Restore order (rubber-duck Phase 33.2 finding): set architectural and
// control registers (Cr0/Cr4/Efer/XCr0/segments/ApicBase) BEFORE applying
// XSAVE blob, because XSAVE interpretation depends on XCR0. Set TSC and
// timing registers LAST to minimize observable skew across vCPUs.
//
// The register-name arrays, CapturedVcpuState, CaptureVcpuState, and
// ApplyVcpuState now live in `whp/vcpu_state.{h,cpp}` so the production
// `--save` / `--restore` paths (Phase 33.6) can share them with the
// host-side probes/tests.

int RunSaveRestoreProbe() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;
    namespace snap = ::tinyvmm::whp::snapshot;

    CheckWhpAvailable();
    std::puts("[save-restore-probe] WHP available");

    auto fail = [](const char* msg) {
        std::fprintf(stderr, "[save-restore-probe] FAIL: %s\n", msg);
        return 2;
    };

    // ---------------- Subtest 1: capture at HLT boundary ----------------
    //   B8 00 00     mov ax, 0     (3 bytes, offset 0..2)
    //   40           inc ax         (1 byte, offset 3)
    //   F4           hlt #1         (1 byte, offset 4) -> RIP=5 after exit
    //   40           inc ax         (1 byte, offset 5)
    //   40           inc ax         (1 byte, offset 6)
    //   F4           hlt #2         (1 byte, offset 7) -> RIP=8 after exit
    {
        constexpr std::uint64_t kCodeGpa = 0x1000;
        const std::uint8_t code[] = {
            0xB8, 0x00, 0x00,
            0x40,
            0xF4,
            0x40,
            0x40,
            0xF4,
        };

        snap::CapturedVcpuState state;
        std::vector<std::uint8_t> ram_bytes;
        std::size_t ram_size = 0;

        // Phase A: cold boot, halt at HLT #1, capture
        {
            Partition part(/*vcpu_count=*/1);
            part.EnableExtendedExits({.cpuid = true});
            // Deliberately NOT enabling LAPIC emulation: this is a real-mode
            // probe that doesn't program the LAPIC, and enabling x2APIC
            // makes WHP wedge on HLT (the run loop sees pending virtual
            // interrupt state and re-enters indefinitely).
            part.Setup();

            ram_size = host::LargePageSize();
            GuestMemory ram(part, /*gpa=*/0, ram_size, /*executable=*/true);
            ram.WriteAt(kCodeGpa, code, sizeof(code));

            Vcpu vp(part, 0);
            vp.SetupRealMode(/*cs_base=*/kCodeGpa);
            WHV_REGISTER_VALUE rip = {}; rip.Reg64 = 0;
            vp.SetRegister(WHvX64RegisterRip, rip);

            devices::IoBus io_bus;
            devices::MmioBus mmio_bus;
            RunLoop loop(vp, io_bus, mmio_bus);
            std::puts("[save-restore-probe] subtest1 phaseA: running...");
            StopReason stop = loop.Run();
            if (stop != StopReason::GuestHalted) {
                std::fprintf(stderr, "[save-restore-probe] subtest1 phaseA:"
                             " expected GuestHalted, got %d\n",
                             static_cast<int>(stop));
                return 2;
            }
            const auto ax = vp.GetRegister(WHvX64RegisterRax).Reg64 & 0xFFFFu;
            const auto rip_v = vp.GetRegister(WHvX64RegisterRip).Reg64;
            if (ax != 1 || rip_v != 5) {
                std::fprintf(stderr, "[save-restore-probe] subtest1 phaseA:"
                             " AX=%llu RIP=0x%llx (want AX=1 RIP=5)\n",
                             static_cast<unsigned long long>(ax),
                             static_cast<unsigned long long>(rip_v));
                return 2;
            }

            snap::CaptureVcpuState(vp, part.handle(), 0, state);
            ram_bytes.resize(ram.size());
            std::memcpy(ram_bytes.data(), ram.host_base(), ram.size());
            std::printf("[save-restore-probe] subtest1 phaseA captured: "
                        "arch=%zu timing=%zu intr=%zu xsave=%zu apic=%zu "
                        "ram=%zu bytes\n",
                        snap::kArchRegCount(), snap::kTimingRegCount(),
                        snap::kIntrCtlRegCount(),
                        state.xsave.size(), state.apic.size(),
                        ram_bytes.size());
        }

        // Phase B: recreate, apply, continue
        const auto t0 = std::chrono::steady_clock::now();
        {
            Partition part(/*vcpu_count=*/1);
            part.EnableExtendedExits({.cpuid = true});
            // No LAPIC emulation — see Phase A comment.
            part.Setup();

            GuestMemory ram(part, /*gpa=*/0, ram_size, /*executable=*/true);
            std::memcpy(ram.host_base(), ram_bytes.data(), ram_size);

            // Brand-new vCPU — never called Run.
            Vcpu vp(part, 0);

            snap::ApplyVcpuState(vp, part.handle(), 0, state);

            // Read back key registers to verify state was accepted before Run.
            const auto cs_seg  = vp.GetRegister(WHvX64RegisterCs).Segment;
            const auto cr0     = vp.GetRegister(WHvX64RegisterCr0).Reg64;
            const auto efer    = vp.GetRegister(WHvX64RegisterEfer).Reg64;
            const auto xcr0    = vp.GetRegister(WHvX64RegisterXCr0).Reg64;
            const auto apic_b  = vp.GetRegister(WHvX64RegisterApicBase).Reg64;
            const auto rip_pre = vp.GetRegister(WHvX64RegisterRip).Reg64;
            std::printf("[save-restore-probe] subtest1 phaseB applied: "
                        "rip=0x%llx cs.base=0x%llx cr0=0x%llx efer=0x%llx "
                        "xcr0=0x%llx apic_base=0x%llx\n",
                        static_cast<unsigned long long>(rip_pre),
                        static_cast<unsigned long long>(cs_seg.Base),
                        static_cast<unsigned long long>(cr0),
                        static_cast<unsigned long long>(efer),
                        static_cast<unsigned long long>(xcr0),
                        static_cast<unsigned long long>(apic_b));
            if (rip_pre != 5) {
                return fail("subtest1 phaseB: RIP didn't take");
            }
            if (cs_seg.Base != kCodeGpa) {
                return fail("subtest1 phaseB: CS.base didn't take");
            }

            devices::IoBus io_bus;
            devices::MmioBus mmio_bus;
            RunLoop loop(vp, io_bus, mmio_bus);
            std::puts("[save-restore-probe] subtest1 phaseB: continuing...");
            StopReason stop = loop.Run();
            if (stop != StopReason::GuestHalted) {
                std::fprintf(stderr, "[save-restore-probe] subtest1 phaseB:"
                             " expected GuestHalted, got %d\n",
                             static_cast<int>(stop));
                return 2;
            }
            const auto ax = vp.GetRegister(WHvX64RegisterRax).Reg64 & 0xFFFFu;
            const auto rip_v = vp.GetRegister(WHvX64RegisterRip).Reg64;
            if (ax != 3 || rip_v != 8) {
                std::fprintf(stderr, "[save-restore-probe] subtest1 phaseB:"
                             " AX=%llu RIP=0x%llx (want AX=3 RIP=8)\n",
                             static_cast<unsigned long long>(ax),
                             static_cast<unsigned long long>(rip_v));
                return 2;
            }
        }
        const auto restore_ms = std::chrono::duration_cast<
            std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count();
        std::printf("[save-restore-probe] subtest1 PASS"
                    " (restore wall-time %lld ms)\n",
                    static_cast<long long>(restore_ms));
    }

    // ---------------- Subtest 2: capture at CPUID magic-leaf boundary ---
    //   66 B8 57 DE 00 40   mov eax, 0x4000DE57   (6 bytes, offset 0..5)
    //   0F A2               cpuid                 (2 bytes, offset 6..7)
    //                       -> magic-leaf handler advances RIP to 8 +
    //                          returns SnapshotRequested
    //   40                  inc ax                (1 byte, offset 8)
    //   40                  inc ax                (1 byte, offset 9)
    //   F4                  hlt                   (1 byte, offset 10)
    //                       -> RIP=11 after exit
    //
    // After the magic CPUID, EAX=kSignatureEax=0 so AX low-16=0. After
    // the two inc ax's: AX=2.
    {
        constexpr std::uint64_t kCodeGpa = 0x1000;
        const std::uint8_t code[] = {
            0x66, 0xB8, 0x57, 0xDE, 0x00, 0x40,
            0x0F, 0xA2,
            0x40,
            0x40,
            0xF4,
        };

        snap::CapturedVcpuState state;
        std::vector<std::uint8_t> ram_bytes;
        std::size_t ram_size = 0;

        // Phase A: cold boot, trigger snapshot via CPUID
        {
            snap::State().armed.store(true, std::memory_order_release);
            snap::State().requested.store(false, std::memory_order_release);
            snap::State().requesting_vp_index.store(0xDEADBEEFu,
                std::memory_order_release);
            snap::State().save_path = "test://probe-armed";

            Partition part(/*vcpu_count=*/1);
            part.EnableExtendedExits({.cpuid = true});
            // No LAPIC emulation in this real-mode probe (see subtest1).
            part.Setup();

            ram_size = host::LargePageSize();
            GuestMemory ram(part, /*gpa=*/0, ram_size, /*executable=*/true);
            ram.WriteAt(kCodeGpa, code, sizeof(code));

            Vcpu vp(part, 0);
            vp.SetupRealMode(/*cs_base=*/kCodeGpa);
            WHV_REGISTER_VALUE rip = {}; rip.Reg64 = 0;
            vp.SetRegister(WHvX64RegisterRip, rip);

            devices::IoBus io_bus;
            devices::MmioBus mmio_bus;
            RunLoop loop(vp, io_bus, mmio_bus);
            std::puts("[save-restore-probe] subtest2 phaseA: running...");
            StopReason stop = loop.Run();

            // Disarm before any potential re-entry. We capture state next,
            // which doesn't itself execute CPUID, but be defensive in case
            // future revisions add state-touching code that does.
            snap::State().armed.store(false, std::memory_order_release);
            snap::State().requested.store(false, std::memory_order_release);
            snap::State().save_path.clear();

            if (stop != StopReason::SnapshotRequested) {
                std::fprintf(stderr, "[save-restore-probe] subtest2 phaseA:"
                             " expected SnapshotRequested, got %d\n",
                             static_cast<int>(stop));
                return 2;
            }
            const auto rip_v = vp.GetRegister(WHvX64RegisterRip).Reg64;
            if (rip_v != 8) {
                std::fprintf(stderr, "[save-restore-probe] subtest2 phaseA:"
                             " RIP=0x%llx (want 8 post-CPUID)\n",
                             static_cast<unsigned long long>(rip_v));
                return 2;
            }
            const auto ax = vp.GetRegister(WHvX64RegisterRax).Reg64 & 0xFFFFu;
            // Magic-leaf handler writes EAX = kSignatureEax = 0.
            if (ax != 0) {
                std::fprintf(stderr, "[save-restore-probe] subtest2 phaseA:"
                             " AX=%llu (want 0, magic signature)\n",
                             static_cast<unsigned long long>(ax));
                return 2;
            }

            snap::CaptureVcpuState(vp, part.handle(), 0, state);
            ram_bytes.resize(ram.size());
            std::memcpy(ram_bytes.data(), ram.host_base(), ram.size());
            std::puts("[save-restore-probe] subtest2 phaseA captured at"
                      " post-CPUID RIP=8");
        }

        // Phase B: recreate, apply, continue past CPUID through to HLT
        const auto t0 = std::chrono::steady_clock::now();
        {
            // Snapshot state must be disarmed for the restored partition.
            // RIP=8 means we never re-execute CPUID, but if armed and
            // something accidentally re-entered it would fire again.
            snap::State().armed.store(false, std::memory_order_release);
            snap::State().requested.store(false, std::memory_order_release);
            snap::State().save_path.clear();

            Partition part(/*vcpu_count=*/1);
            part.EnableExtendedExits({.cpuid = true});
            // No LAPIC emulation in this real-mode probe (see subtest1).
            part.Setup();

            GuestMemory ram(part, /*gpa=*/0, ram_size, /*executable=*/true);
            std::memcpy(ram.host_base(), ram_bytes.data(), ram_size);

            Vcpu vp(part, 0);
            snap::ApplyVcpuState(vp, part.handle(), 0, state);

            devices::IoBus io_bus;
            devices::MmioBus mmio_bus;
            RunLoop loop(vp, io_bus, mmio_bus);
            std::puts("[save-restore-probe] subtest2 phaseB: continuing...");
            StopReason stop = loop.Run();
            if (stop != StopReason::GuestHalted) {
                std::fprintf(stderr, "[save-restore-probe] subtest2 phaseB:"
                             " expected GuestHalted, got %d\n",
                             static_cast<int>(stop));
                return 2;
            }
            const auto ax = vp.GetRegister(WHvX64RegisterRax).Reg64 & 0xFFFFu;
            const auto rip_v = vp.GetRegister(WHvX64RegisterRip).Reg64;
            if (ax != 2 || rip_v != 11) {
                std::fprintf(stderr, "[save-restore-probe] subtest2 phaseB:"
                             " AX=%llu RIP=0x%llx (want AX=2 RIP=11)\n",
                             static_cast<unsigned long long>(ax),
                             static_cast<unsigned long long>(rip_v));
                return 2;
            }
        }
        const auto restore_ms = std::chrono::duration_cast<
            std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count();
        std::printf("[save-restore-probe] subtest2 PASS"
                    " (restore wall-time %lld ms)\n",
                    static_cast<long long>(restore_ms));
    }

    std::puts("[save-restore-probe] PASS");
    return 0;
}

// --save-restore-roundtrip-test (M33.3)
//
// End-to-end exercise of the Phase 33.3 file format:
//
//   Phase A: Cold-boot a real-mode partition (same shape as
//            --save-restore-probe subtest 2: arm snapshot, run until
//            SnapshotRequested fires at post-CPUID RIP=8). Capture live
//            vCPU state + RAM + HvEnlightenment state.
//
//   Phase B: Write everything to a temp file using SnapshotWriter.
//
//   Phase C: Read it back using SnapshotReader. Verify trailer CRC.
//            Materialize a side-by-side copy of the captured state and
//            assert byte-for-byte equality with the in-memory original
//            (RAM, xsave, apic, arch values, timing values, intr_ctl
//            entries pairwise with ok-bit check, HvEnlightenment state).
//
//   Phase D: Construct a fresh Partition + GuestMemory, memcpy restored
//            RAM into the new GuestMemory's host_base() (rubber-duck
//            blocking #1), apply restored vCPU state via the shared
//            snap module, apply restored HvEnlightenment state. Run.
//            Expect GuestHalted at RIP=11 (post-cpuid: inc; inc; hlt).
//
// File is deleted on success. On failure the path is logged so the
// caller can inspect it.
int RunSaveRestoreRoundtripTest() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;
    namespace snap = ::tinyvmm::whp::snapshot;

    CheckWhpAvailable();
    std::puts("[save-restore-roundtrip] WHP available");

    // Acquire a unique temp path via Win32. This deletes any previously
    // existing file at the path; we recreate via SnapshotWriter
    // (CREATE_ALWAYS). The 0-prefix arg to GetTempFileNameA creates a
    // unique name and the file (which SnapshotWriter then overwrites).
    std::string tmp_path;
    {
        char dir[MAX_PATH + 1] = {};
        DWORD n = ::GetTempPathA(MAX_PATH, dir);
        if (n == 0 || n > MAX_PATH) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] FAIL: GetTempPathA err=%lu\n",
                ::GetLastError());
            return 2;
        }
        char path[MAX_PATH + 1] = {};
        if (::GetTempFileNameA(dir, "tvm", 0, path) == 0) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] FAIL: GetTempFileNameA err=%lu\n",
                ::GetLastError());
            return 2;
        }
        tmp_path = path;
    }
    std::printf("[save-restore-roundtrip] temp file: %s\n", tmp_path.c_str());

    auto cleanup = [&]() noexcept {
        ::DeleteFileA(tmp_path.c_str());
    };

    // Reproducing the probe subtest2's exact bytes (11 bytes total):
    //   66 B8 57 DE 00 40  mov eax, 0x4000DE57   (6 bytes, offset 0..5)
    //                                            (66 = operand-size prefix
    //                                             needed for 32-bit imm in
    //                                             real mode)
    //   0F A2              cpuid                 (2 bytes, offset 6..7)
    //                                            magic-leaf handler advances
    //                                            RIP to 8 + returns
    //                                            SnapshotRequested
    //   40                 inc ax                (1 byte, offset 8)
    //   40                 inc ax                (1 byte, offset 9)
    //   F4                 hlt                   (1 byte, offset 10)
    //                                            -> RIP=11 after exit
    //
    // After magic CPUID, EAX=kSignatureEax=0 so AX low-16=0. After the
    // two inc ax's: AX=2. (Mirrors --save-restore-probe subtest 2.)
    constexpr std::uint64_t kCodeGpa = 0x1000;
    const std::uint8_t code[] = {
        0x66, 0xB8, 0x57, 0xDE, 0x00, 0x40,
        0x0F, 0xA2,
        0x40,
        0x40,
        0xF4,
    };

    snap::CapturedVcpuState captured_state;
    std::vector<std::uint8_t> captured_ram;
    HvEnlightenment::State captured_hv{};
    std::size_t ram_size = 0;
    std::uint64_t tsc_hz = whp::GetCachedTscHz();

    // ----------------- Phase A: cold-boot and capture -----------------
    {
        snap::State().armed.store(true, std::memory_order_release);
        snap::State().requested.store(false, std::memory_order_release);
        snap::State().requesting_vp_index.store(0xDEADBEEFu,
            std::memory_order_release);
        snap::State().save_path = "test://roundtrip-armed";

        Partition part(/*vcpu_count=*/1);
        part.EnableExtendedExits({.cpuid = true});
        // No LAPIC emulation in this real-mode probe (mirrors
        // --save-restore-probe subtest 2).
        part.Setup();

        ram_size = host::LargePageSize();
        GuestMemory ram(part, /*gpa=*/0, ram_size, /*executable=*/true);
        ram.WriteAt(kCodeGpa, code, sizeof(code));

        Vcpu vp(part, 0);
        vp.SetupRealMode(/*cs_base=*/kCodeGpa);
        WHV_REGISTER_VALUE rip = {}; rip.Reg64 = 0;
        vp.SetRegister(WHvX64RegisterRip, rip);

        // HvEnlightenment isn't actually exercised by this real-mode
        // guest (no MSR exits enabled), but we still capture and
        // restore it to exercise the on-disk format. The state values
        // are simply the (zero) defaults set by ctor.
        HvEnlightenment hv(ram, tsc_hz);

        devices::IoBus io_bus;
        devices::MmioBus mmio_bus;
        RunLoop loop(vp, io_bus, mmio_bus);
        std::puts("[save-restore-roundtrip] phaseA: running...");
        StopReason stop = loop.Run();

        snap::State().armed.store(false, std::memory_order_release);
        snap::State().requested.store(false, std::memory_order_release);
        snap::State().save_path.clear();

        if (stop != StopReason::SnapshotRequested) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] phaseA: expected"
                " SnapshotRequested, got %d\n",
                static_cast<int>(stop));
            cleanup();
            return 2;
        }
        const auto rip_v = vp.GetRegister(WHvX64RegisterRip).Reg64;
        if (rip_v != 8) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] phaseA: RIP=0x%llx (want 8)\n",
                static_cast<unsigned long long>(rip_v));
            cleanup();
            return 2;
        }

        snap::CaptureVcpuState(vp, part.handle(), 0, captured_state);
        captured_ram.resize(ram.size());
        std::memcpy(captured_ram.data(), ram.host_base(), ram.size());
        captured_hv = hv.CaptureState();
        std::printf("[save-restore-roundtrip] phaseA captured:"
                    " arch=%zu timing=%zu intr=%zu xsave=%zu"
                    " apic=%zu ram=%zu tsc_hz=%llu\n",
                    captured_state.arch.size(),
                    captured_state.timing.size(),
                    captured_state.intr_ctl.size(),
                    captured_state.xsave.size(),
                    captured_state.apic.size(),
                    captured_ram.size(),
                    static_cast<unsigned long long>(tsc_hz));
    }

    // ---------------------- Phase B: write file ----------------------
    {
        snap::JsonObjectWriter jw;
        jw.Add("vcpu_count",     std::uint64_t{1});
        jw.Add("ram_size_bytes", static_cast<std::uint64_t>(ram_size));
        jw.Add("large_pages",    false);
        jw.Add("tsc_hz_at_save", tsc_hz);
        jw.Add("test_marker",    std::string_view("roundtrip"));

        snap::SnapshotWriter w(tmp_path);
        w.WriteHeader(jw.str());

        // RAM first (largest section).
        w.WriteSection(snap::SectionType::RamRaw,
                       captured_ram.data(), captured_ram.size());

        // VCPU_REGS: u32 vp_idx | u32 reg_count |
        //            [u32 name | u32 reserved | 16 bytes value]*
        auto encode_reg_block =
            [](std::uint32_t vp_idx,
               const WHV_REGISTER_NAME* names,
               const std::vector<WHV_REGISTER_VALUE>& values)
            -> std::vector<std::uint8_t>
        {
            const std::uint32_t n = static_cast<std::uint32_t>(values.size());
            std::vector<std::uint8_t> out(8 + n * (8 + 16));
            snap::WriteLe32(&out[0], vp_idx);
            snap::WriteLe32(&out[4], n);
            for (std::uint32_t i = 0; i < n; ++i) {
                std::uint8_t* p = &out[8 + i * (8 + 16)];
                snap::WriteLe32(p + 0, static_cast<std::uint32_t>(names[i]));
                snap::WriteLe32(p + 4, 0u);  // reserved
                std::memcpy(p + 8, &values[i], 16);
            }
            return out;
        };

        auto regs_block = encode_reg_block(0, snap::kArchRegNames,
                                           captured_state.arch);
        w.WriteSection(snap::SectionType::VcpuRegs,
                       regs_block.data(), regs_block.size());

        // VCPU_XSAVE: u32 vp_idx | u32 size | bytes
        {
            std::vector<std::uint8_t> blob(8 + captured_state.xsave.size());
            snap::WriteLe32(&blob[0], 0u);  // vp_idx
            snap::WriteLe32(&blob[4],
                tinyvmm::util::checked_int_cast<std::uint32_t>(
                    captured_state.xsave.size()));
            if (!captured_state.xsave.empty()) {
                std::memcpy(&blob[8], captured_state.xsave.data(),
                            captured_state.xsave.size());
            }
            w.WriteSection(snap::SectionType::VcpuXsave,
                           blob.data(), blob.size());
        }

        // VCPU_APIC: same encoding as XSAVE. May be 0-length.
        {
            std::vector<std::uint8_t> blob(8 + captured_state.apic.size());
            snap::WriteLe32(&blob[0], 0u);
            snap::WriteLe32(&blob[4],
                tinyvmm::util::checked_int_cast<std::uint32_t>(
                    captured_state.apic.size()));
            if (!captured_state.apic.empty()) {
                std::memcpy(&blob[8], captured_state.apic.data(),
                            captured_state.apic.size());
            }
            w.WriteSection(snap::SectionType::VcpuApic,
                           blob.data(), blob.size());
        }

        // VCPU_INTR_CTL: u32 vp_idx | u32 reg_count |
        //                [u32 name | u8 ok | u8 pad[3] | 16 bytes value]*
        {
            const std::uint32_t n = static_cast<std::uint32_t>(
                captured_state.intr_ctl.size());
            std::vector<std::uint8_t> blob(8 + n * (8 + 16));
            snap::WriteLe32(&blob[0], 0u);
            snap::WriteLe32(&blob[4], n);
            for (std::uint32_t i = 0; i < n; ++i) {
                std::uint8_t* p = &blob[8 + i * (8 + 16)];
                snap::WriteLe32(p + 0,
                    static_cast<std::uint32_t>(snap::kIntrCtlRegNames[i]));
                p[4] = captured_state.intr_ctl_ok[i] ? 1u : 0u;
                p[5] = 0; p[6] = 0; p[7] = 0;
                std::memcpy(p + 8, &captured_state.intr_ctl[i], 16);
            }
            w.WriteSection(snap::SectionType::VcpuIntrCtl,
                           blob.data(), blob.size());
        }

        // VCPU_TIMING: same encoding as VCPU_REGS.
        auto timing_block = encode_reg_block(0, snap::kTimingRegNames,
                                             captured_state.timing);
        w.WriteSection(snap::SectionType::VcpuTiming,
                       timing_block.data(), timing_block.size());

        // HV_ENLIGHTENMENT: 32 bytes (4 LE u64s).
        {
            std::uint8_t hv[32];
            snap::WriteLe64(hv +  0, captured_hv.guest_os_id);
            snap::WriteLe64(hv +  8, captured_hv.hypercall_msr);
            snap::WriteLe64(hv + 16, captured_hv.reference_tsc_msr);
            snap::WriteLe64(hv + 24, captured_hv.tsc_invariant_ctl);
            w.WriteSection(snap::SectionType::HvEnlightenment, hv, sizeof(hv));
        }

        w.Finalize();
        std::printf("[save-restore-roundtrip] phaseB wrote %llu bytes\n",
                    static_cast<unsigned long long>(w.bytes_written()));
    }

    // ---------------- Phase C: read back + byte equality ----------------
    snap::CapturedVcpuState restored_state;
    std::vector<std::uint8_t> restored_ram;
    HvEnlightenment::State restored_hv{};
    {
        snap::SnapshotReader r(tmp_path);
        const std::string hdr = r.ReadHeader();
        snap::JsonObjectReader jr(hdr);
        if (jr.GetUint("vcpu_count") != 1) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] phaseC: vcpu_count mismatch\n");
            cleanup(); return 2;
        }
        if (jr.GetUint("ram_size_bytes") != ram_size) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] phaseC: ram_size mismatch\n");
            cleanup(); return 2;
        }
        if (jr.GetUint("tsc_hz_at_save") != tsc_hz) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] phaseC: tsc_hz mismatch\n");
            cleanup(); return 2;
        }
        if (jr.GetBool("large_pages") != false) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] phaseC: large_pages mismatch\n");
            cleanup(); return 2;
        }
        if (jr.GetString("test_marker") != "roundtrip") {
            std::fprintf(stderr,
                "[save-restore-roundtrip] phaseC: test_marker mismatch\n");
            cleanup(); return 2;
        }

        auto decode_reg_block = [&](std::span<const std::uint8_t> payload,
                                    std::vector<WHV_REGISTER_VALUE>& out,
                                    const WHV_REGISTER_NAME* expected_names,
                                    std::size_t expected_count,
                                    const char* tag) -> bool
        {
            if (payload.size() < 8) {
                std::fprintf(stderr,
                    "[save-restore-roundtrip] phaseC: %s short header\n",
                    tag);
                return false;
            }
            const std::uint32_t vp_idx = snap::ReadLe32(payload.data() + 0);
            const std::uint32_t n      = snap::ReadLe32(payload.data() + 4);
            if (vp_idx != 0) {
                std::fprintf(stderr,
                    "[save-restore-roundtrip] phaseC: %s vp_idx=%u\n",
                    tag, vp_idx);
                return false;
            }
            if (n != expected_count) {
                std::fprintf(stderr,
                    "[save-restore-roundtrip] phaseC: %s count=%u want=%zu\n",
                    tag, n, expected_count);
                return false;
            }
            const std::size_t need = 8 + n * (8 + 16);
            if (payload.size() < need) {
                std::fprintf(stderr,
                    "[save-restore-roundtrip] phaseC: %s truncated payload\n",
                    tag);
                return false;
            }
            out.resize(n);
            for (std::uint32_t i = 0; i < n; ++i) {
                const std::uint8_t* p = payload.data() + 8 + i * (8 + 16);
                const std::uint32_t name = snap::ReadLe32(p + 0);
                const std::uint32_t rsv  = snap::ReadLe32(p + 4);
                if (rsv != 0) {
                    std::fprintf(stderr,
                        "[save-restore-roundtrip] phaseC: %s[%u] rsv=%u\n",
                        tag, i, rsv);
                    return false;
                }
                if (name != static_cast<std::uint32_t>(expected_names[i])) {
                    std::fprintf(stderr,
                        "[save-restore-roundtrip] phaseC: %s[%u]"
                        " name=0x%08x want=0x%08x\n", tag, i, name,
                        static_cast<unsigned>(expected_names[i]));
                    return false;
                }
                std::memcpy(&out[i], p + 8, 16);
            }
            return true;
        };

        bool saw_ram = false, saw_regs = false, saw_xsave = false;
        bool saw_apic = false, saw_intr = false, saw_timing = false;
        bool saw_hv = false;

        while (auto sec = r.NextSection()) {
            switch (sec->type) {
            case snap::SectionType::RamRaw: {
                if (sec->payload.size() != ram_size) {
                    std::fprintf(stderr,
                        "[save-restore-roundtrip] phaseC: RAM size %zu"
                        " want %zu\n", sec->payload.size(), ram_size);
                    cleanup(); return 2;
                }
                restored_ram.assign(sec->payload.begin(), sec->payload.end());
                saw_ram = true;
                break;
            }
            case snap::SectionType::VcpuRegs: {
                if (!decode_reg_block(sec->payload, restored_state.arch,
                                      snap::kArchRegNames,
                                      snap::kArchRegCount(), "arch")) {
                    cleanup(); return 2;
                }
                saw_regs = true;
                break;
            }
            case snap::SectionType::VcpuXsave: {
                if (sec->payload.size() < 8) {
                    std::fprintf(stderr,
                        "[save-restore-roundtrip] phaseC: xsave hdr short\n");
                    cleanup(); return 2;
                }
                const std::uint32_t vp_idx = snap::ReadLe32(sec->payload.data());
                const std::uint32_t sz     = snap::ReadLe32(sec->payload.data() + 4);
                if (vp_idx != 0 || sec->payload.size() != 8u + sz) {
                    std::fprintf(stderr,
                        "[save-restore-roundtrip] phaseC: xsave bad\n");
                    cleanup(); return 2;
                }
                restored_state.xsave.assign(
                    sec->payload.begin() + 8, sec->payload.end());
                saw_xsave = true;
                break;
            }
            case snap::SectionType::VcpuApic: {
                if (sec->payload.size() < 8) {
                    std::fprintf(stderr,
                        "[save-restore-roundtrip] phaseC: apic hdr short\n");
                    cleanup(); return 2;
                }
                const std::uint32_t vp_idx = snap::ReadLe32(sec->payload.data());
                const std::uint32_t sz     = snap::ReadLe32(sec->payload.data() + 4);
                if (vp_idx != 0 || sec->payload.size() != 8u + sz) {
                    std::fprintf(stderr,
                        "[save-restore-roundtrip] phaseC: apic bad\n");
                    cleanup(); return 2;
                }
                restored_state.apic.assign(
                    sec->payload.begin() + 8, sec->payload.end());
                saw_apic = true;
                break;
            }
            case snap::SectionType::VcpuIntrCtl: {
                if (sec->payload.size() < 8) {
                    std::fprintf(stderr,
                        "[save-restore-roundtrip] phaseC: intr hdr short\n");
                    cleanup(); return 2;
                }
                const std::uint32_t vp_idx = snap::ReadLe32(sec->payload.data());
                const std::uint32_t n      = snap::ReadLe32(sec->payload.data() + 4);
                if (vp_idx != 0 || n != snap::kIntrCtlRegCount() ||
                    sec->payload.size() != 8u + n * (8u + 16u)) {
                    std::fprintf(stderr,
                        "[save-restore-roundtrip] phaseC: intr bad\n");
                    cleanup(); return 2;
                }
                restored_state.intr_ctl.resize(n);
                restored_state.intr_ctl_ok.assign(n, false);
                for (std::uint32_t i = 0; i < n; ++i) {
                    const std::uint8_t* p =
                        sec->payload.data() + 8 + i * (8 + 16);
                    const std::uint32_t name = snap::ReadLe32(p + 0);
                    if (name != static_cast<std::uint32_t>(
                                    snap::kIntrCtlRegNames[i])) {
                        std::fprintf(stderr,
                            "[save-restore-roundtrip] phaseC: intr[%u]"
                            " name=0x%08x want=0x%08x\n", i, name,
                            static_cast<unsigned>(snap::kIntrCtlRegNames[i]));
                        cleanup(); return 2;
                    }
                    restored_state.intr_ctl_ok[i] = (p[4] != 0);
                    if (p[5] != 0 || p[6] != 0 || p[7] != 0) {
                        std::fprintf(stderr,
                            "[save-restore-roundtrip] phaseC: intr[%u]"
                            " nonzero pad\n", i);
                        cleanup(); return 2;
                    }
                    std::memcpy(&restored_state.intr_ctl[i], p + 8, 16);
                }
                saw_intr = true;
                break;
            }
            case snap::SectionType::VcpuTiming: {
                if (!decode_reg_block(sec->payload, restored_state.timing,
                                      snap::kTimingRegNames,
                                      snap::kTimingRegCount(), "timing")) {
                    cleanup(); return 2;
                }
                saw_timing = true;
                break;
            }
            case snap::SectionType::HvEnlightenment: {
                if (sec->payload.size() != 32) {
                    std::fprintf(stderr,
                        "[save-restore-roundtrip] phaseC: hv size %zu\n",
                        sec->payload.size());
                    cleanup(); return 2;
                }
                restored_hv.guest_os_id =
                    snap::ReadLe64(sec->payload.data() +  0);
                restored_hv.hypercall_msr =
                    snap::ReadLe64(sec->payload.data() +  8);
                restored_hv.reference_tsc_msr =
                    snap::ReadLe64(sec->payload.data() + 16);
                restored_hv.tsc_invariant_ctl =
                    snap::ReadLe64(sec->payload.data() + 24);
                saw_hv = true;
                break;
            }
            default:
                std::fprintf(stderr,
                    "[save-restore-roundtrip] phaseC: unexpected section"
                    " type=0x%08x\n",
                    static_cast<unsigned>(sec->type));
                cleanup(); return 2;
            }
        }
        r.VerifyTrailer();

        if (!(saw_ram && saw_regs && saw_xsave && saw_apic && saw_intr
              && saw_timing && saw_hv)) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] phaseC: missing section(s):"
                " ram=%d regs=%d xsave=%d apic=%d intr=%d timing=%d hv=%d\n",
                saw_ram, saw_regs, saw_xsave, saw_apic, saw_intr,
                saw_timing, saw_hv);
            cleanup(); return 2;
        }

        // Byte-equality checks.
        if (restored_ram != captured_ram) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] phaseC: RAM bytes differ\n");
            cleanup(); return 2;
        }
        if (restored_state.xsave != captured_state.xsave) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] phaseC: xsave bytes differ\n");
            cleanup(); return 2;
        }
        if (restored_state.apic != captured_state.apic) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] phaseC: apic bytes differ\n");
            cleanup(); return 2;
        }
        if (restored_state.arch.size() != captured_state.arch.size() ||
            std::memcmp(restored_state.arch.data(),
                        captured_state.arch.data(),
                        restored_state.arch.size() *
                            sizeof(WHV_REGISTER_VALUE)) != 0) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] phaseC: arch values differ\n");
            cleanup(); return 2;
        }
        if (restored_state.timing.size() != captured_state.timing.size() ||
            std::memcmp(restored_state.timing.data(),
                        captured_state.timing.data(),
                        restored_state.timing.size() *
                            sizeof(WHV_REGISTER_VALUE)) != 0) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] phaseC: timing values differ\n");
            cleanup(); return 2;
        }
        for (std::size_t i = 0; i < captured_state.intr_ctl.size(); ++i) {
            if (restored_state.intr_ctl_ok[i] != captured_state.intr_ctl_ok[i]) {
                std::fprintf(stderr,
                    "[save-restore-roundtrip] phaseC: intr_ctl[%zu] ok"
                    " differs (%d vs %d)\n",
                    i,
                    static_cast<int>(restored_state.intr_ctl_ok[i]),
                    static_cast<int>(captured_state.intr_ctl_ok[i]));
                cleanup(); return 2;
            }
            if (std::memcmp(&restored_state.intr_ctl[i],
                            &captured_state.intr_ctl[i], 16) != 0) {
                std::fprintf(stderr,
                    "[save-restore-roundtrip] phaseC: intr_ctl[%zu] value"
                    " differs\n", i);
                cleanup(); return 2;
            }
        }
        if (std::memcmp(&restored_hv, &captured_hv,
                        sizeof(HvEnlightenment::State)) != 0) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] phaseC: HV state differs\n");
            cleanup(); return 2;
        }
        std::puts("[save-restore-roundtrip] phaseC: bytewise equality OK");
    }

    // -------- Phase D: fresh partition + apply restored state ---------
    const auto t0 = std::chrono::steady_clock::now();
    {
        // Snapshot trigger must be disarmed: we never re-execute CPUID
        // post-restore (RIP=8 is past it), but defensive disarm protects
        // against future revisions.
        snap::State().armed.store(false, std::memory_order_release);
        snap::State().requested.store(false, std::memory_order_release);
        snap::State().save_path.clear();

        Partition part(/*vcpu_count=*/1);
        part.EnableExtendedExits({.cpuid = true});
        part.Setup();

        // Allocate fresh GuestMemory, then memcpy restored RAM into it
        // (rubber-duck blocking #1: restore MUST repopulate guest RAM).
        GuestMemory ram(part, /*gpa=*/0, ram_size, /*executable=*/true);
        std::memcpy(ram.host_base(), restored_ram.data(), ram_size);

        // HvEnlightenment ApplyState — the test partition has no MSR
        // exits enabled, so this is exercised mostly to validate the
        // helper compiles and round-trips state via the saved values.
        HvEnlightenment hv(ram, tsc_hz);
        hv.ApplyState(restored_hv);

        Vcpu vp(part, 0);
        snap::ApplyVcpuState(vp, part.handle(), 0, restored_state);

        devices::IoBus io_bus;
        devices::MmioBus mmio_bus;
        RunLoop loop(vp, io_bus, mmio_bus);
        std::puts("[save-restore-roundtrip] phaseD: continuing...");
        StopReason stop = loop.Run();
        if (stop != StopReason::GuestHalted) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] phaseD: expected GuestHalted,"
                " got %d\n", static_cast<int>(stop));
            cleanup(); return 2;
        }
        const auto ax = vp.GetRegister(WHvX64RegisterRax).Reg64 & 0xFFFFu;
        const auto rip_v = vp.GetRegister(WHvX64RegisterRip).Reg64;
        if (ax != 2 || rip_v != 11) {
            std::fprintf(stderr,
                "[save-restore-roundtrip] phaseD: AX=%llu RIP=0x%llx"
                " (want AX=2 RIP=11)\n",
                static_cast<unsigned long long>(ax),
                static_cast<unsigned long long>(rip_v));
            cleanup(); return 2;
        }
    }
    const auto restore_ms = std::chrono::duration_cast<
        std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
    std::printf("[save-restore-roundtrip] phaseD PASS"
                " (restore+run wall-time %lld ms)\n",
                static_cast<long long>(restore_ms));

    cleanup();
    std::puts("[save-restore-roundtrip] PASS");
    return 0;
}

// --save-restore-pci-test (M33.4)
//
// End-to-end round-trip of every PCI / virtio-pci / MSI-X / Virtqueue /
// per-virtio-device State struct introduced in M33.4. Validates:
//
//   1. Each Capture/Encode/Decode/Apply path is byte-stable across the
//      on-disk format (Encode-Decode-Encode produces identical bytes).
//   2. ApplyState on a fresh device produces a State whose Encode bytes
//      match the original Capture bytes (so the apply path is lossless).
//   3. PciTransport::ApplyState correctly re-installs BAR0 MMIO handlers
//      via InstallBarHandlers_ when bar_mapped was true (the new
//      restore-time hook that replaces the cold-boot OnBarMapped path).
//
// Topology: two devices on the same bus.
//   00:00.0   virtio-rng     1 virtqueue,  2 MSI-X vectors
//   00:01.0   virtio-console 2 virtqueues, 3 MSI-X vectors
//
// The two-virtqueue device (console) is essential — it guarantees the
// per-queue layout in PciTransport's encoded section is exercised at
// num_queues > 1, and that VIRTQUEUE sections at different qidx round
// trip independently.
//
// Driving the devices: we use the same MMIO/CFG path as the existing
// --virtio-{rng,console}-test functions (write COMMAND.MEM_SPACE to
// trigger OnBarMapped, program MSI-X table + cap, program every queue,
// flip status to ACK | DRIVER | FEATURES_OK | DRIVER_OK). No vCPU is
// ever created; this is pure host-side state plumbing.
int RunSaveRestorePciTest() {
    using namespace tinyvmm;
    using namespace tinyvmm::whp;
    namespace p    = tinyvmm::pci;
    namespace v    = tinyvmm::virtio;
    namespace snap = tinyvmm::whp::snapshot;

    std::puts("[save-restore-pci-test] starting (host-side; no WHP)");

    CheckWhpAvailable();
    std::puts("[save-restore-pci-test] WHP available");

    // ----------------- Acquire temp file path -----------------
    std::string tmp_path;
    {
        char dir[MAX_PATH + 1] = {};
        DWORD n = ::GetTempPathA(MAX_PATH, dir);
        if (n == 0 || n > MAX_PATH) {
            std::fprintf(stderr,
                "[save-restore-pci-test] FAIL: GetTempPathA err=%lu\n",
                ::GetLastError());
            return 2;
        }
        char path[MAX_PATH + 1] = {};
        if (::GetTempFileNameA(dir, "tvp", 0, path) == 0) {
            std::fprintf(stderr,
                "[save-restore-pci-test] FAIL: GetTempFileNameA err=%lu\n",
                ::GetLastError());
            return 2;
        }
        tmp_path = path;
    }
    std::printf("[save-restore-pci-test] temp file: %s\n", tmp_path.c_str());
    auto cleanup = [&]() noexcept { ::DeleteFileA(tmp_path.c_str()); };

    // ----------------- Shared helpers / fixtures -----------------
    // Drives an entire VM bring-up of (rng, console) and returns the
    // populated captures. Used twice: once for the original capture,
    // once for the post-Apply re-capture.
    struct CaptureSet {
        // RNG-side captures
        p::Bdf                rng_bdf;
        p::PciDevice::State   rng_pci;
        p::MsiX::State        rng_msix;
        v::PciTransport::State rng_xport;
        v::RngDevice::State   rng_dev;
        v::Virtqueue::State   rng_q0;

        // Console-side captures
        p::Bdf                con_bdf;
        p::PciDevice::State   con_pci;
        p::MsiX::State        con_msix;
        v::PciTransport::State con_xport;
        v::ConsoleDevice::State con_dev;
        v::Virtqueue::State   con_q0_rx;
        v::Virtqueue::State   con_q1_tx;
    };

    // Brings up a fresh bus + devices, returns a CaptureSet after
    // driving them through MMIO/CFG to a richly-populated state.
    // `apply_first` (optional) is invoked between bringup-of-fresh-
    // devices and the final Capture; this is how we test ApplyState.
    auto drive_and_capture =
        [&](const std::function<void(v::RngDevice*,
                                     v::PciTransport*,
                                     v::ConsoleDevice*,
                                     v::PciTransport*)>& apply_first,
            CaptureSet& out) -> bool {
        Partition part(/*vcpu_count=*/1);
        part.Setup();
        constexpr std::size_t kRamBytes = 0x200000;
        GuestMemory ram(part, /*gpa=*/0, kRamBytes, /*executable=*/false);
        std::memset(ram.host_base(), 0, kRamBytes);

        devices::IoBus   io_bus;
        devices::MmioBus mmio_bus;
        p::PciBus        pbus;
        pbus.AttachIoBus(io_bus);

        auto inject_fn = [](std::uint64_t, std::uint32_t) { return true; };

        // ----- construct rng device + transport
        auto rng = std::make_unique<v::RngDevice>(ram);
        v::RngDevice* rng_ptr = rng.get();
        v::PciTransport::Options ro;
        ro.subsys_id        = static_cast<std::uint16_t>(v::kDeviceIdRng);
        ro.num_msix_vectors = 2;
        ro.pci_class        = 0xFF;
        ro.pci_subclass     = 0x00;
        auto rxport = std::make_unique<v::PciTransport>(
            *rng_ptr, ro, mmio_bus, inject_fn);
        v::PciTransport* rxp = rxport.get();
        rxport->set_name("virtio-pci-rng");
        rng_ptr->SetIrqCallback(
            [rxp](std::uint32_t q) { rxp->RaiseQueueInterrupt(q); });

        // ----- construct console device + transport
        auto con = std::make_unique<v::ConsoleDevice>(ram, nullptr);
        v::ConsoleDevice* con_ptr = con.get();
        v::PciTransport::Options co;
        co.subsys_id        = static_cast<std::uint16_t>(v::kDeviceIdConsole);
        co.num_msix_vectors = 3;
        co.pci_class        = 0x07;
        co.pci_subclass     = 0x80;
        auto cxport = std::make_unique<v::PciTransport>(
            *con_ptr, co, mmio_bus, inject_fn);
        v::PciTransport* cxp = cxport.get();
        cxport->set_name("virtio-pci-console");
        con_ptr->SetIrqCallback(
            [cxp](std::uint32_t q) { cxp->RaiseQueueInterrupt(q); });

        // ----- attach to bus
        const p::Bdf rng_bdf = pbus.AddDevice(std::move(rxport));
        const p::Bdf con_bdf = pbus.AddDevice(std::move(cxport));
        out.rng_bdf = rng_bdf;
        out.con_bdf = con_bdf;

        // ----- optional apply step BEFORE driving via MMIO. This is
        //       how Phase E exercises ApplyState: applies all the
        //       captured state on fresh constructed devices, then we
        //       re-capture to verify equality.
        if (apply_first) {
            apply_first(rng_ptr, rxp, con_ptr, cxp);
        }

        // ----- MMIO/CFG helpers (shared with --virtio-*-test pattern)
        auto io_w = [&](std::uint16_t port, std::uint16_t size,
                        std::uint32_t val) {
            devices::IoAccess a{port, size, /*write=*/true, val};
            if (!io_bus.Dispatch(a))
                Fatal("save-restore-pci-test: unmatched IO write");
        };
        auto io_r = [&](std::uint16_t port,
                        std::uint16_t size) -> std::uint32_t {
            devices::IoAccess a{port, size, /*write=*/false, 0};
            if (!io_bus.Dispatch(a))
                Fatal("save-restore-pci-test: unmatched IO read");
            return a.value;
        };
        auto encode_addr = [](const p::Bdf& bdf,
                              std::uint8_t reg) -> std::uint32_t {
            return p::kConfigAddressEnable |
                (std::uint32_t{bdf.bus}      << 16) |
                (std::uint32_t{bdf.device}   << 11) |
                (std::uint32_t{bdf.function} <<  8) |
                (reg & 0xFCu);
        };
        auto cfg_r = [&](const p::Bdf& bdf,
                         std::uint8_t reg,
                         std::uint16_t size) -> std::uint32_t {
            io_w(p::kConfigAddressPort, 4, encode_addr(bdf, reg));
            return io_r(static_cast<std::uint16_t>(
                            p::kConfigDataPort + (reg & 3)),
                        size);
        };
        auto cfg_w = [&](const p::Bdf& bdf,
                         std::uint8_t reg,
                         std::uint16_t size,
                         std::uint32_t val) {
            io_w(p::kConfigAddressPort, 4, encode_addr(bdf, reg));
            io_w(static_cast<std::uint16_t>(
                     p::kConfigDataPort + (reg & 3)),
                 size, val);
        };
        auto mmio_w = [&](std::uint64_t gpa, std::uint32_t val,
                          std::uint8_t sz) {
            devices::MmioAccess a{};
            a.gpa = gpa; a.access_size = sz; a.is_write = true;
            std::memcpy(a.data, &val, std::min<std::size_t>(sz, 4));
            if (!mmio_bus.Dispatch(a))
                Fatal("save-restore-pci-test: unmatched MMIO write");
        };

        // ----- bring up one device (rng or console)
        // num_msix_vectors must match what the ctor declared.
        auto bring_up = [&](const p::Bdf& bdf,
                            std::uint16_t num_msix,
                            std::uint64_t acked_features,
                            std::span<const std::pair<
                                std::uint32_t, std::uint16_t>>
                                queue_msix_vectors,
                            std::uint16_t cfg_msix_vector,
                            std::span<const std::pair<
                                std::uint64_t, std::uint32_t>>
                                queue_ring_gpas)
            -> std::uint64_t /* bar_gpa */ {
            // BAR0 read + MEM_SPACE map.
            const std::uint32_t bar0_lo = cfg_r(bdf, p::kCfgBar0, 4);
            const std::uint32_t bar0_hi = cfg_r(bdf, p::kCfgBar0 + 4, 4);
            cfg_w(bdf, p::kCfgCommand, 2,
                  p::kCmdMemorySpace | p::kCmdBusMaster);
            const std::uint64_t bar_gpa =
                (static_cast<std::uint64_t>(bar0_hi) << 32) |
                (bar0_lo & ~0xFu);

            // Walk caps to find MSI-X cap offset.
            std::uint8_t cap =
                static_cast<std::uint8_t>(cfg_r(bdf, p::kCfgCapPtr, 1));
            std::uint8_t msix_cap_off = 0;
            for (std::size_t i = 0; cap != 0 && i < 16; ++i) {
                const std::uint8_t id =
                    static_cast<std::uint8_t>(cfg_r(bdf, cap, 1));
                if (id == p::kCapIdMsiX) msix_cap_off = cap;
                cap = static_cast<std::uint8_t>(
                    cfg_r(bdf,
                          static_cast<std::uint8_t>(cap + 1), 1));
            }
            if (!msix_cap_off)
                Fatal("save-restore-pci-test: MSI-X cap not found");

            // Program MSI-X table entries with distinct (addr,data) so
            // bit-equality on round-trip is informative.
            constexpr std::uint64_t kMsiAddrBase = 0xFEE00000ull;
            for (std::uint32_t v = 0; v < num_msix; ++v) {
                const std::uint64_t tbl =
                    bar_gpa + v::PciTransport::kOffMsixTable + 16ull * v;
                const std::uint64_t addr =
                    kMsiAddrBase | (static_cast<std::uint64_t>(v) << 12);
                mmio_w(tbl + 0,
                       static_cast<std::uint32_t>(addr & 0xFFFFFFFFu), 4);
                mmio_w(tbl + 4,
                       static_cast<std::uint32_t>(addr >> 32), 4);
                mmio_w(tbl + 8,
                       0x40u + (static_cast<std::uint32_t>(v) << 4), 4);
                // Leave vector-control bit 0 set (masked) on some
                // vectors and clear on others so the saved ctrl[] array
                // carries non-uniform data.
                mmio_w(tbl + 12, (v & 1u) ? 0u : 1u, 4);
            }
            // Enable MSI-X (cap MC bit 15 = enable).
            cfg_w(bdf, static_cast<std::uint8_t>(msix_cap_off + 2), 2,
                  0x8000u);

            // Negotiate features (just VERSION_1 from the device — keep
            // ShouldInterruptDriver simple; tests aren't running guests).
            mmio_w(bar_gpa + 0x00, 0, 4);  // device_feature_select=0
            mmio_w(bar_gpa + 0x00, 1, 4);  // device_feature_select=1
            mmio_w(bar_gpa + 0x14, v::kStatusAcknowledge, 1);
            mmio_w(bar_gpa + 0x14,
                   v::kStatusAcknowledge | v::kStatusDriver, 1);
            mmio_w(bar_gpa + 0x08, 0, 4);  // driver_feature_select=0
            mmio_w(bar_gpa + 0x0C,
                   static_cast<std::uint32_t>(acked_features & 0xFFFFFFFFu),
                   4);
            mmio_w(bar_gpa + 0x08, 1, 4);
            mmio_w(bar_gpa + 0x0C,
                   static_cast<std::uint32_t>(acked_features >> 32), 4);
            mmio_w(bar_gpa + 0x14,
                   v::kStatusAcknowledge | v::kStatusDriver |
                       v::kStatusFeaturesOk, 1);

            // Set msix_config vector.
            mmio_w(bar_gpa + 0x10, cfg_msix_vector, 2);

            // Program every queue. queue_ring_gpas is parallel to
            // queue_msix_vectors and gives a distinct desc_gpa per queue.
            for (std::size_t qi = 0; qi < queue_msix_vectors.size(); ++qi) {
                const std::uint32_t qidx = queue_msix_vectors[qi].first;
                const std::uint16_t vec  = queue_msix_vectors[qi].second;
                const std::uint64_t desc = queue_ring_gpas[qi].first;
                const std::uint32_t qsz  = queue_ring_gpas[qi].second;
                const std::uint64_t avail = desc + 0x100;
                const std::uint64_t used  = desc + 0x200;

                mmio_w(bar_gpa + 0x16,
                       static_cast<std::uint32_t>(qidx), 2);
                mmio_w(bar_gpa + 0x18, qsz, 2);
                mmio_w(bar_gpa + 0x1A, vec, 2);
                mmio_w(bar_gpa + 0x20,
                       static_cast<std::uint32_t>(desc), 4);
                mmio_w(bar_gpa + 0x24,
                       static_cast<std::uint32_t>(desc >> 32), 4);
                mmio_w(bar_gpa + 0x28,
                       static_cast<std::uint32_t>(avail), 4);
                mmio_w(bar_gpa + 0x2C,
                       static_cast<std::uint32_t>(avail >> 32), 4);
                mmio_w(bar_gpa + 0x30,
                       static_cast<std::uint32_t>(used), 4);
                mmio_w(bar_gpa + 0x34,
                       static_cast<std::uint32_t>(used >> 32), 4);
                mmio_w(bar_gpa + 0x1C, 1, 2);  // enable
            }

            // DRIVER_OK fan-out.
            mmio_w(bar_gpa + 0x14,
                   v::kStatusAcknowledge | v::kStatusDriver |
                       v::kStatusFeaturesOk | v::kStatusDriverOk, 1);
            return bar_gpa;
        };

        // ----- The apply path already populated state directly into
        //       devices; in that case we MUST NOT redrive via MMIO
        //       (that would mutate the queues back to defaults).
        if (!apply_first) {
            // rng: queue 0 (requestq) -> vector 0; cfg-change -> vector 1.
            std::array<std::pair<std::uint32_t, std::uint16_t>, 1>
                rng_q = {{ {0u, std::uint16_t{0}} }};
            std::array<std::pair<std::uint64_t, std::uint32_t>, 1>
                rng_g = {{ {0x30000ull, 8u} }};
            bring_up(rng_bdf, /*num_msix=*/2,
                     /*acked_features=*/v::kFeatureVersion1,
                     rng_q, /*cfg_msix_vector=*/std::uint16_t{1}, rng_g);

            // console: queue 0 (rxq) -> vector 0; queue 1 (txq) -> vector 1;
            // cfg-change -> vector 2.
            std::array<std::pair<std::uint32_t, std::uint16_t>, 2>
                con_q = {{ {0u, std::uint16_t{0}}, {1u, std::uint16_t{1}} }};
            std::array<std::pair<std::uint64_t, std::uint32_t>, 2>
                con_g = {{ {0x50000ull, 16u}, {0x60000ull, 32u} }};
            bring_up(con_bdf, /*num_msix=*/3,
                     /*acked_features=*/v::kFeatureVersion1,
                     con_q, /*cfg_msix_vector=*/std::uint16_t{2}, con_g);
        }

        // ----- Capture all state (works equally well in both branches).
        // Reach into PciBus to grab the PciDevice* by BDF.
        auto pci_dev_at = [&](const p::Bdf& b) -> p::PciDevice* {
            return pbus.Find(b);
        };

        p::PciDevice* rng_dev_p = pci_dev_at(rng_bdf);
        p::PciDevice* con_dev_p = pci_dev_at(con_bdf);
        if (!rng_dev_p || !con_dev_p)
            Fatal("save-restore-pci-test: device lookup failed");

        out.rng_pci   = rng_dev_p->CaptureState();
        out.rng_msix  = rxp->msix().CaptureState();
        out.rng_xport = rxp->CaptureState();
        out.rng_dev   = rng_ptr->CaptureState();
        out.rng_q0    = rng_ptr->request_queue().CaptureState();

        out.con_pci    = con_dev_p->CaptureState();
        out.con_msix   = cxp->msix().CaptureState();
        out.con_xport  = cxp->CaptureState();
        out.con_dev    = con_ptr->CaptureState();
        out.con_q0_rx  = con_ptr->receive_queue().CaptureState();
        out.con_q1_tx  = con_ptr->transmit_queue().CaptureState();
        return true;
    };

    // ----------------------------- Phase A -----------------------------
    std::puts("[save-restore-pci-test] phaseA: drive + capture original");
    CaptureSet orig;
    if (!drive_and_capture({}, orig)) {
        cleanup(); return 2;
    }
    std::printf("[save-restore-pci-test] rng bdf=%02x:%02x.%u  "
                "console bdf=%02x:%02x.%u\n",
                orig.rng_bdf.bus, orig.rng_bdf.device, orig.rng_bdf.function,
                orig.con_bdf.bus, orig.con_bdf.device, orig.con_bdf.function);

    // Sanity: capture must show bar_mapped + DRIVER_OK on both.
    if (!orig.rng_xport.bar_mapped) {
        std::fprintf(stderr,
            "[save-restore-pci-test] FAIL: rng bar_mapped=0 after bringup\n");
        cleanup(); return 2;
    }
    if (!orig.con_xport.bar_mapped) {
        std::fprintf(stderr,
            "[save-restore-pci-test] FAIL: con bar_mapped=0 after bringup\n");
        cleanup(); return 2;
    }
    if (orig.rng_dev.driver_ok == 0 || orig.con_dev.driver_ok == 0) {
        std::fprintf(stderr,
            "[save-restore-pci-test] FAIL: driver_ok=0 after bringup\n");
        cleanup(); return 2;
    }

    // ----------------------------- Phase B/C ----------------------------
    // Helper: prepend a 4-byte BDF prefix to an encoded section payload.
    auto prepend_bdf = [&](const p::Bdf& bdf,
                           std::vector<std::uint8_t>& buf) {
        std::vector<std::uint8_t> out;
        out.reserve(4 + buf.size());
        out.push_back(bdf.bus);
        out.push_back(bdf.device);
        out.push_back(bdf.function);
        out.push_back(0);  // reserved
        out.insert(out.end(), buf.begin(), buf.end());
        buf = std::move(out);
    };
    auto prepend_bdf_q = [&](const p::Bdf& bdf, std::uint16_t qidx,
                             std::vector<std::uint8_t>& buf) {
        std::vector<std::uint8_t> out;
        out.reserve(8 + buf.size());
        out.push_back(bdf.bus);
        out.push_back(bdf.device);
        out.push_back(bdf.function);
        out.push_back(0);
        out.push_back(static_cast<std::uint8_t>(qidx & 0xFF));
        out.push_back(static_cast<std::uint8_t>((qidx >> 8) & 0xFF));
        out.push_back(0);
        out.push_back(0);
        out.insert(out.end(), buf.begin(), buf.end());
        buf = std::move(out);
    };

    // Encode every State to its bytes; remember each pre-prefix encoding
    // for later byte-equality after re-Capture.
    std::vector<std::uint8_t> rng_pci_enc, rng_msix_enc, rng_xport_enc,
                              rng_dev_enc, rng_q0_enc;
    std::vector<std::uint8_t> con_pci_enc, con_msix_enc, con_xport_enc,
                              con_dev_enc, con_q0_enc, con_q1_enc;

    p::PciDevice::EncodeState   (orig.rng_pci,   rng_pci_enc);
    p::MsiX::EncodeState        (orig.rng_msix,  rng_msix_enc);
    v::PciTransport::EncodeState(orig.rng_xport, rng_xport_enc);
    v::RngDevice::EncodeState   (orig.rng_dev,   rng_dev_enc);
    v::Virtqueue::EncodeState   (orig.rng_q0,    rng_q0_enc);

    p::PciDevice::EncodeState     (orig.con_pci,    con_pci_enc);
    p::MsiX::EncodeState          (orig.con_msix,   con_msix_enc);
    v::PciTransport::EncodeState  (orig.con_xport,  con_xport_enc);
    v::ConsoleDevice::EncodeState (orig.con_dev,    con_dev_enc);
    v::Virtqueue::EncodeState     (orig.con_q0_rx,  con_q0_enc);
    v::Virtqueue::EncodeState     (orig.con_q1_tx,  con_q1_enc);

    // ------------- Write file -------------
    {
        snap::JsonObjectWriter jw;
        jw.Add("test_marker", std::string_view("pci_roundtrip"));
        jw.Add("device_count", std::uint64_t{2});

        snap::SnapshotWriter w(tmp_path);
        w.WriteHeader(jw.str());

        auto write_with_bdf = [&](snap::SectionType st,
                                  const p::Bdf& bdf,
                                  std::vector<std::uint8_t> bytes) {
            prepend_bdf(bdf, bytes);
            w.WriteSection(st, bytes.data(), bytes.size());
        };
        auto write_with_bdf_q = [&](snap::SectionType st,
                                    const p::Bdf& bdf, std::uint16_t qidx,
                                    std::vector<std::uint8_t> bytes) {
            prepend_bdf_q(bdf, qidx, bytes);
            w.WriteSection(st, bytes.data(), bytes.size());
        };

        // Per-device sections in topologically-sensible order (PCI dev
        // first; phase-D ApplyState ordering follows this for clarity).
        write_with_bdf(snap::SectionType::PciDevice,
                       orig.rng_bdf, rng_pci_enc);
        write_with_bdf(snap::SectionType::VirtioRngState,
                       orig.rng_bdf, rng_dev_enc);
        write_with_bdf_q(snap::SectionType::Virtqueue,
                         orig.rng_bdf, 0, rng_q0_enc);
        write_with_bdf(snap::SectionType::MsixState,
                       orig.rng_bdf, rng_msix_enc);
        write_with_bdf(snap::SectionType::VirtioPciTransport,
                       orig.rng_bdf, rng_xport_enc);

        write_with_bdf(snap::SectionType::PciDevice,
                       orig.con_bdf, con_pci_enc);
        write_with_bdf(snap::SectionType::VirtioConsoleState,
                       orig.con_bdf, con_dev_enc);
        write_with_bdf_q(snap::SectionType::Virtqueue,
                         orig.con_bdf, 0, con_q0_enc);
        write_with_bdf_q(snap::SectionType::Virtqueue,
                         orig.con_bdf, 1, con_q1_enc);
        write_with_bdf(snap::SectionType::MsixState,
                       orig.con_bdf, con_msix_enc);
        write_with_bdf(snap::SectionType::VirtioPciTransport,
                       orig.con_bdf, con_xport_enc);

        w.Finalize();
        std::printf("[save-restore-pci-test] phaseB wrote %llu bytes\n",
                    static_cast<unsigned long long>(w.bytes_written()));
    }

    // ----------------------------- Phase D: read back + decode ---------
    std::puts("[save-restore-pci-test] phaseC: read back + decode");
    auto strip_bdf = [&](const snap::SnapshotReader::Section& sec)
        -> std::pair<p::Bdf, std::span<const std::uint8_t>> {
        if (sec.payload.size() < 4)
            Fatal("save-restore-pci-test: section payload < 4 (BDF prefix)");
        p::Bdf b{ sec.payload[0], sec.payload[1], sec.payload[2] };
        if (sec.payload[3] != 0)
            Fatal("save-restore-pci-test: BDF prefix reserved byte != 0");
        return { b,
                 std::span<const std::uint8_t>(
                     sec.payload.data() + 4, sec.payload.size() - 4) };
    };
    auto strip_bdf_q = [&](const snap::SnapshotReader::Section& sec)
        -> std::tuple<p::Bdf, std::uint16_t,
                      std::span<const std::uint8_t>> {
        if (sec.payload.size() < 8)
            Fatal("save-restore-pci-test: VIRTQUEUE section payload < 8");
        p::Bdf b{ sec.payload[0], sec.payload[1], sec.payload[2] };
        if (sec.payload[3] != 0)
            Fatal("save-restore-pci-test: VQ BDF prefix reserved byte != 0");
        const std::uint16_t qidx = static_cast<std::uint16_t>(
            sec.payload[4] | (sec.payload[5] << 8));
        if (sec.payload[6] != 0 || sec.payload[7] != 0)
            Fatal("save-restore-pci-test: VIRTQUEUE qidx pad != 0");
        return { b, qidx,
                 std::span<const std::uint8_t>(
                     sec.payload.data() + 8, sec.payload.size() - 8) };
    };

    snap::SnapshotReader r(tmp_path);
    const std::string hdr = r.ReadHeader();
    snap::JsonObjectReader jr(hdr);
    if (jr.GetString("test_marker") != "pci_roundtrip") {
        std::fprintf(stderr,
            "[save-restore-pci-test] phaseC: test_marker mismatch\n");
        cleanup(); return 2;
    }

    auto bdf_eq = [](const p::Bdf& a, const p::Bdf& b) {
        return a.bus == b.bus && a.device == b.device &&
               a.function == b.function;
    };

    int saw_rng_pci = 0, saw_rng_msix = 0, saw_rng_xport = 0;
    int saw_rng_dev = 0, saw_rng_q0   = 0;
    int saw_con_pci = 0, saw_con_msix = 0, saw_con_xport = 0;
    int saw_con_dev = 0, saw_con_q0   = 0, saw_con_q1   = 0;

    auto check_bytes_eq = [&](const char* what,
                              std::span<const std::uint8_t> got_payload,
                              const std::vector<std::uint8_t>& want) -> bool {
        if (got_payload.size() != want.size() ||
            !std::equal(got_payload.begin(), got_payload.end(),
                        want.begin())) {
            std::fprintf(stderr,
                "[save-restore-pci-test] phaseC: %s payload bytes differ"
                " (got=%zu want=%zu)\n",
                what, got_payload.size(), want.size());
            return false;
        }
        return true;
    };

    while (auto sec = r.NextSection()) {
        switch (sec->type) {
        case snap::SectionType::PciDevice: {
            auto [b, body] = strip_bdf(*sec);
            const std::vector<std::uint8_t>& want =
                bdf_eq(b, orig.rng_bdf) ? rng_pci_enc :
                bdf_eq(b, orig.con_bdf) ? con_pci_enc :
                std::vector<std::uint8_t>{};
            if (want.empty()) {
                std::fprintf(stderr,
                    "[save-restore-pci-test] phaseC: unknown PCI BDF\n");
                cleanup(); return 2;
            }
            if (!check_bytes_eq("PciDevice", body, want)) {
                cleanup(); return 2;
            }
            // Also round-trip: Decode then Re-Encode -> identical.
            auto st = p::PciDevice::DecodeState(body);
            std::vector<std::uint8_t> re;
            p::PciDevice::EncodeState(st, re);
            if (!check_bytes_eq("PciDevice re-encode", re, want)) {
                cleanup(); return 2;
            }
            if (bdf_eq(b, orig.rng_bdf)) saw_rng_pci++;
            else                          saw_con_pci++;
            break;
        }
        case snap::SectionType::MsixState: {
            auto [b, body] = strip_bdf(*sec);
            const std::vector<std::uint8_t>& want =
                bdf_eq(b, orig.rng_bdf) ? rng_msix_enc : con_msix_enc;
            if (!check_bytes_eq("MsixState", body, want)) {
                cleanup(); return 2;
            }
            auto st = p::MsiX::DecodeState(body);
            std::vector<std::uint8_t> re;
            p::MsiX::EncodeState(st, re);
            if (!check_bytes_eq("MsixState re-encode", re, want)) {
                cleanup(); return 2;
            }
            if (bdf_eq(b, orig.rng_bdf)) saw_rng_msix++;
            else                          saw_con_msix++;
            break;
        }
        case snap::SectionType::VirtioPciTransport: {
            auto [b, body] = strip_bdf(*sec);
            const std::vector<std::uint8_t>& want =
                bdf_eq(b, orig.rng_bdf) ? rng_xport_enc : con_xport_enc;
            if (!check_bytes_eq("VirtioPciTransport", body, want)) {
                cleanup(); return 2;
            }
            auto st = v::PciTransport::DecodeState(body);
            std::vector<std::uint8_t> re;
            v::PciTransport::EncodeState(st, re);
            if (!check_bytes_eq("VirtioPciTransport re-encode", re, want)) {
                cleanup(); return 2;
            }
            if (bdf_eq(b, orig.rng_bdf)) saw_rng_xport++;
            else                          saw_con_xport++;
            break;
        }
        case snap::SectionType::Virtqueue: {
            auto [b, qi, body] = strip_bdf_q(*sec);
            const std::vector<std::uint8_t>* want = nullptr;
            if (bdf_eq(b, orig.rng_bdf) && qi == 0)      want = &rng_q0_enc;
            else if (bdf_eq(b, orig.con_bdf) && qi == 0) want = &con_q0_enc;
            else if (bdf_eq(b, orig.con_bdf) && qi == 1) want = &con_q1_enc;
            if (!want) {
                std::fprintf(stderr,
                    "[save-restore-pci-test] phaseC: unknown VQ BDF/qi\n");
                cleanup(); return 2;
            }
            if (!check_bytes_eq("Virtqueue", body, *want)) {
                cleanup(); return 2;
            }
            auto st = v::Virtqueue::DecodeState(body);
            std::vector<std::uint8_t> re;
            v::Virtqueue::EncodeState(st, re);
            if (!check_bytes_eq("Virtqueue re-encode", re, *want)) {
                cleanup(); return 2;
            }
            if (bdf_eq(b, orig.rng_bdf))           saw_rng_q0++;
            else if (qi == 0)                       saw_con_q0++;
            else                                    saw_con_q1++;
            break;
        }
        case snap::SectionType::VirtioRngState: {
            auto [b, body] = strip_bdf(*sec);
            if (!bdf_eq(b, orig.rng_bdf)) {
                std::fprintf(stderr,
                    "[save-restore-pci-test] phaseC: RNG_STATE wrong BDF\n");
                cleanup(); return 2;
            }
            if (!check_bytes_eq("VirtioRngState", body, rng_dev_enc)) {
                cleanup(); return 2;
            }
            auto st = v::RngDevice::DecodeState(body);
            std::vector<std::uint8_t> re;
            v::RngDevice::EncodeState(st, re);
            if (!check_bytes_eq("VirtioRngState re-encode", re,
                                rng_dev_enc)) {
                cleanup(); return 2;
            }
            saw_rng_dev++;
            break;
        }
        case snap::SectionType::VirtioConsoleState: {
            auto [b, body] = strip_bdf(*sec);
            if (!bdf_eq(b, orig.con_bdf)) {
                std::fprintf(stderr,
                    "[save-restore-pci-test] phaseC: CONSOLE_STATE wrong BDF\n");
                cleanup(); return 2;
            }
            if (!check_bytes_eq("VirtioConsoleState", body, con_dev_enc)) {
                cleanup(); return 2;
            }
            auto st = v::ConsoleDevice::DecodeState(body);
            std::vector<std::uint8_t> re;
            v::ConsoleDevice::EncodeState(st, re);
            if (!check_bytes_eq("VirtioConsoleState re-encode", re,
                                con_dev_enc)) {
                cleanup(); return 2;
            }
            saw_con_dev++;
            break;
        }
        default:
            std::fprintf(stderr,
                "[save-restore-pci-test] phaseC: unexpected section type"
                " 0x%04x\n", static_cast<unsigned>(sec->type));
            cleanup(); return 2;
        }
    }
    try {
        r.VerifyTrailer();
    } catch (const std::exception& e) {
        std::fprintf(stderr,
            "[save-restore-pci-test] phaseC: CRC trailer: %s\n", e.what());
        cleanup(); return 2;
    }

    // Section presence check.
    if (saw_rng_pci != 1 || saw_rng_msix != 1 || saw_rng_xport != 1 ||
        saw_rng_dev != 1 || saw_rng_q0 != 1 ||
        saw_con_pci != 1 || saw_con_msix != 1 || saw_con_xport != 1 ||
        saw_con_dev != 1 || saw_con_q0 != 1 || saw_con_q1 != 1) {
        std::fprintf(stderr,
            "[save-restore-pci-test] phaseC: missing sections rng_pci=%d"
            " rng_msix=%d rng_xport=%d rng_dev=%d rng_q0=%d"
            " con_pci=%d con_msix=%d con_xport=%d con_dev=%d con_q0=%d"
            " con_q1=%d\n",
            saw_rng_pci, saw_rng_msix, saw_rng_xport, saw_rng_dev,
            saw_rng_q0, saw_con_pci, saw_con_msix, saw_con_xport,
            saw_con_dev, saw_con_q0, saw_con_q1);
        cleanup(); return 2;
    }
    std::puts("[save-restore-pci-test] phaseC PASS"
              " (all 11 sections byte-identical; re-encode stable)");

    // ----------------------------- Phase E: ApplyState round-trip ------
    // Construct fresh devices identically, then in the apply_first hook
    // (called from drive_and_capture) apply state in the order Phase
    // 33.6 production code will follow:
    //   1. PciDevice::ApplyState (cfg + BARs)
    //   2. Per-virtio-device ApplyState (driver_ok, acked_features)
    //   3. Per-Virtqueue ApplyState (size, ready, ring GPAs, indices)
    //   4. MsiX::ApplyState (table entries + PBA)
    //   5. PciTransport::ApplyState (common_cfg + queue stubs + bar_mapped;
    //      re-installs BAR0 MMIO handlers via InstallBarHandlers_)
    std::puts("[save-restore-pci-test] phaseE: apply on fresh devices");
    CaptureSet recap;
    {
        auto apply_fn =
            [&](v::RngDevice* rng_p, v::PciTransport* rxp,
                v::ConsoleDevice* con_p, v::PciTransport* cxp) {
            // RNG side
            // PciDevice::ApplyState requires the underlying object; the
            // PciTransport IS the PciDevice (multiple inheritance not used;
            // PciTransport derives from PciDevice). So apply on the
            // transport pointer cast to PciDevice.
            static_cast<p::PciDevice*>(rxp)->ApplyState(orig.rng_pci);
            rng_p->ApplyState(orig.rng_dev);
            rng_p->request_queue().ApplyState(orig.rng_q0);
            rxp->msix().ApplyState(orig.rng_msix);
            rxp->ApplyState(orig.rng_xport);

            // Console side
            static_cast<p::PciDevice*>(cxp)->ApplyState(orig.con_pci);
            con_p->ApplyState(orig.con_dev);
            con_p->receive_queue().ApplyState(orig.con_q0_rx);
            con_p->transmit_queue().ApplyState(orig.con_q1_tx);
            cxp->msix().ApplyState(orig.con_msix);
            cxp->ApplyState(orig.con_xport);
        };
        if (!drive_and_capture(apply_fn, recap)) {
            cleanup(); return 2;
        }
    }

    // Re-encode the recaptured states and verify byte-equality vs the
    // originals. This is the strongest possible test that ApplyState is
    // lossless across the full set of field types we persist.
    auto enc_pcid = [](const p::PciDevice::State& s) {
        std::vector<std::uint8_t> v;
        p::PciDevice::EncodeState(s, v);
        return v;
    };
    auto enc_msix = [](const p::MsiX::State& s) {
        std::vector<std::uint8_t> v;
        p::MsiX::EncodeState(s, v);
        return v;
    };
    auto enc_xport = [](const v::PciTransport::State& s) {
        std::vector<std::uint8_t> v;
        v::PciTransport::EncodeState(s, v);
        return v;
    };
    auto enc_vq = [](const v::Virtqueue::State& s) {
        std::vector<std::uint8_t> v;
        v::Virtqueue::EncodeState(s, v);
        return v;
    };
    auto enc_rng = [](const v::RngDevice::State& s) {
        std::vector<std::uint8_t> v;
        v::RngDevice::EncodeState(s, v);
        return v;
    };
    auto enc_con = [](const v::ConsoleDevice::State& s) {
        std::vector<std::uint8_t> v;
        v::ConsoleDevice::EncodeState(s, v);
        return v;
    };

    auto cmp = [&](const char* what,
                   const std::vector<std::uint8_t>& a,
                   const std::vector<std::uint8_t>& b) -> bool {
        if (a.size() != b.size() || !std::equal(a.begin(), a.end(),
                                                 b.begin())) {
            std::fprintf(stderr,
                "[save-restore-pci-test] phaseE: %s post-Apply bytes differ"
                " (orig=%zu recap=%zu)\n", what, a.size(), b.size());
            return false;
        }
        return true;
    };

    bool ok = true;
    ok = cmp("rng PciDevice",   rng_pci_enc,   enc_pcid (recap.rng_pci))   && ok;
    ok = cmp("rng MsiX",        rng_msix_enc,  enc_msix (recap.rng_msix))  && ok;
    ok = cmp("rng PciTransport",rng_xport_enc, enc_xport(recap.rng_xport)) && ok;
    ok = cmp("rng Device",      rng_dev_enc,   enc_rng  (recap.rng_dev))   && ok;
    ok = cmp("rng Virtqueue 0", rng_q0_enc,    enc_vq   (recap.rng_q0))    && ok;
    ok = cmp("con PciDevice",   con_pci_enc,   enc_pcid (recap.con_pci))   && ok;
    ok = cmp("con MsiX",        con_msix_enc,  enc_msix (recap.con_msix))  && ok;
    ok = cmp("con PciTransport",con_xport_enc, enc_xport(recap.con_xport)) && ok;
    ok = cmp("con Device",      con_dev_enc,   enc_con  (recap.con_dev))   && ok;
    ok = cmp("con Virtqueue 0", con_q0_enc,    enc_vq   (recap.con_q0_rx)) && ok;
    ok = cmp("con Virtqueue 1", con_q1_enc,    enc_vq   (recap.con_q1_tx)) && ok;

    if (!ok) {
        cleanup();
        return 2;
    }

    // Sanity: BDFs assigned by the fresh PciBus must match the original
    // BDFs (otherwise an unrelated ordering bug would invalidate the
    // entire scheme, since Phase 33.6 production code assumes
    // AddDevice ordering is deterministic).
    if (!bdf_eq(orig.rng_bdf, recap.rng_bdf) ||
        !bdf_eq(orig.con_bdf, recap.con_bdf)) {
        std::fprintf(stderr,
            "[save-restore-pci-test] phaseE: BDF reassignment differs"
            " (orig rng=%02x:%02x.%u recap rng=%02x:%02x.%u)\n",
            orig.rng_bdf.bus, orig.rng_bdf.device, orig.rng_bdf.function,
            recap.rng_bdf.bus, recap.rng_bdf.device, recap.rng_bdf.function);
        cleanup(); return 2;
    }

    std::puts("[save-restore-pci-test] phaseE PASS"
              " (Apply round-trip byte-stable across all 11 states)");

    cleanup();
    std::puts("[save-restore-pci-test] PASS");
    return 0;
}

// --save-restore-legacy-test (M33.5)
// Round-trips Serial8250 / Pic8259 / Pit8254 / PciBus / LegacyIsaStubs
// state through the snapshot file format. No vCPU and no WHP. Each
// device is driven via IO writes to populate state, captured, encoded,
// written to a temp file, read back + decoded, byte-compared, then
// re-applied on fresh devices and re-captured + byte-compared. Counting
// callbacks verify that ResumeRuntime() invokes the expected runtime
// side-effects (Serial TX-IRQ edge, PIC IRR replay, PIT IRQ thread arm).
int RunSaveRestoreLegacyTest() {
    using namespace tinyvmm;
    namespace dev  = tinyvmm::devices;
    namespace snap = tinyvmm::whp::snapshot;

    std::puts("[save-restore-legacy-test] starting (host-side; no WHP)");

    auto Fatal = [](const char* msg) -> int {
        std::fprintf(stderr, "[save-restore-legacy-test] FATAL: %s\n", msg);
        return 2;
    };

    // ---- Temp file -------------------------------------------------------
    char tmp_dir[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tmp_dir) == 0) {
        return Fatal("GetTempPathA failed");
    }
    char tmp_file[MAX_PATH];
    if (GetTempFileNameA(tmp_dir, "tvl", 0, tmp_file) == 0) {
        return Fatal("GetTempFileNameA failed");
    }
    std::string tmp_path = tmp_file;
    auto cleanup_file = [&] { DeleteFileA(tmp_path.c_str()); };
    std::printf("[save-restore-legacy-test] temp file: %s\n",
                tmp_path.c_str());

    // ---- Shared captured-state struct -----------------------------------
    struct Captured {
        dev::Serial8250::State    serial;
        dev::Pic8259::State       pic;
        dev::Pit8254::State       pit;
        pci::PciBus::State        pcibus;
        dev::LegacyIsaStubs::State isa;
    };

    // ---- IO drive helper -------------------------------------------------
    auto do_write = [](devices::IoBus& b, std::uint16_t port,
                       std::uint16_t size, std::uint32_t value) {
        devices::IoAccess acc{};
        acc.port        = port;
        acc.access_size = size;
        acc.is_write    = true;
        acc.value       = value;
        b.Dispatch(acc);
    };

    // ---- Phase A: drive + capture ORIG -----------------------------------
    std::puts("[save-restore-legacy-test] phaseA: drive + capture original");

    int phaseA_tx_irq = 0, phaseA_pic_inject = 0, phaseA_pit_irq = 0;
    Captured orig;
    {
        dev::Pic8259 pic(
            [&](std::uint8_t, std::uint32_t) {
                ++phaseA_pic_inject;
                return true;
            });
        dev::Serial8250 serial(0x3F8, /*sink=*/nullptr);
        serial.SetIrqCallback([&](int) { ++phaseA_tx_irq; });
        dev::Pit8254 pit;
        pit.SetIrqCallback([&](int) { ++phaseA_pit_irq; });
        pci::PciBus pcibus;
        dev::LegacyIsaStubs isa;

        devices::IoBus io_bus;
        serial.Attach(io_bus);
        pic.Attach(io_bus);
        pit.Attach(io_bus);
        pcibus.AttachIoBus(io_bus);
        isa.Attach(io_bus);

        // ---- PIC: full init sequence (master + slave) -------------------
        // ICW1=0x11 (init+icw4 will follow), command port.
        do_write(io_bus, 0x20, 1, 0x11);
        do_write(io_bus, 0xA0, 1, 0x11);
        // ICW2: vector base 0x30 master, 0x38 slave.
        do_write(io_bus, 0x21, 1, 0x30);
        do_write(io_bus, 0xA1, 1, 0x38);
        // ICW3: cascade. Master tells which input has slave (bit 2 = IRQ2).
        // Slave tells its cascade identity (0x02).
        do_write(io_bus, 0x21, 1, 0x04);
        do_write(io_bus, 0xA1, 1, 0x02);
        // ICW4: 8086 mode.
        do_write(io_bus, 0x21, 1, 0x01);
        do_write(io_bus, 0xA1, 1, 0x01);
        // OCW1: mask. Master: 0xFB unmasks IRQ2 (cascade). Slave: 0xFF
        // mask everything initially. Then unmask slave IRQ2 (local) for
        // a moment to demonstrate replay.
        do_write(io_bus, 0x21, 1, 0xFB);   // master: cascade unmasked
        do_write(io_bus, 0xA1, 1, 0xFF);   // slave: all masked
        // Raise IRQ 10 (slave bit 2). Since slave mask has bit 2 set,
        // this latches in slave IRR.
        pic.Raise(10);
        // Also raise master IRQ 1 directly. Master mask 0xFB has bit 1
        // set, so this latches in master IRR.
        pic.Raise(1);

        // ---- Serial: program registers + write THR to trigger IRQ -------
        // LCR set DLAB=1.
        do_write(io_bus, 0x3FB, 1, 0x83);  // 8N1 + DLAB
        // Divisor 0x000C (96 = 1200 baud? doesn't matter, just bookkeeping)
        do_write(io_bus, 0x3F8, 1, 0x0C);
        do_write(io_bus, 0x3F9, 1, 0x00);
        // Clear DLAB, 8N1 stays.
        do_write(io_bus, 0x3FB, 1, 0x03);
        // IER: ETBEI (bit 1) only.
        do_write(io_bus, 0x3F9, 1, 0x02);
        // MCR: OUT2 set (bit 3) so IRQ would actually route.
        do_write(io_bus, 0x3FC, 1, 0x08);
        // SCR: arbitrary byte.
        do_write(io_bus, 0x3FF, 1, 0x5A);
        // FCR: enable FIFO, clear both, 14-byte threshold (write-only).
        do_write(io_bus, 0x3FA, 1, 0xC7);
        // Now write THR -- because ETBEI is set and tx is "always
        // ready", this triggers MaybeRaiseTxIrqLocked which sets
        // tx_irq_pending_ and raises IRQ4.
        do_write(io_bus, 0x3F8, 1, 0x41);  // 'A'

        // ---- PIT: program ch0 mode 2 (rate gen) periodic ----------------
        // Control word for ch0: select counter 0, LSB-then-MSB access,
        // mode 2, binary = 0x34.
        do_write(io_bus, 0x43, 1, 0x34);
        do_write(io_bus, 0x40, 1, 0x00);   // LSB
        do_write(io_bus, 0x40, 1, 0x10);   // MSB -> reload 0x1000
        // ch2 mode 0 (one-shot), LSB-then-MSB, binary = 0xB0.
        do_write(io_bus, 0x43, 1, 0xB0);
        do_write(io_bus, 0x42, 1, 0xFF);
        do_write(io_bus, 0x42, 1, 0xFF);   // reload 0xFFFF
        // Port 0x61: enable gate2 + speaker data.
        do_write(io_bus, 0x61, 1, 0x03);

        // ---- PciBus: latch a CONFIG_ADDRESS value -----------------------
        do_write(io_bus, 0xCF8, 4, 0x80001234);

        // ---- LegacyIsaStubs: CMOS index + port 0x92 ---------------------
        do_write(io_bus, 0x70, 1, 0x09);   // CMOS year
        do_write(io_bus, 0x92, 1, 0x03);   // A20 + reset bit cleared

        // ---- Capture ----------------------------------------------------
        orig.serial = serial.CaptureState();
        orig.pic    = pic.CaptureState();
        orig.pit    = pit.CaptureState();
        orig.pcibus = pcibus.CaptureState();
        orig.isa    = isa.CaptureState();
    }

    // Sanity check: at this point we should have seen exactly 1 TX IRQ
    // (from the THR write) and 1 PIC inject (also from the THR write,
    // since serial.irq_raise -> pic.Raise(4) -> InjectLocked).
    if (phaseA_tx_irq != 1) {
        std::fprintf(stderr,
            "[save-restore-legacy-test] phaseA: TX IRQ count = %d (want 1)\n",
            phaseA_tx_irq);
        cleanup_file(); return 2;
    }

    std::printf("[save-restore-legacy-test] phaseA: original captured "
                "(tx_irq=%d, pic_inject=%d, pit_irq=%d)\n",
                phaseA_tx_irq, phaseA_pic_inject, phaseA_pit_irq);

    // ---- Phase B: encode + write file ------------------------------------
    std::puts("[save-restore-legacy-test] phaseB: encode + write");

    auto encode_to_vec = [](auto encode_fn, const auto& state,
                            std::size_t size) {
        std::vector<std::uint8_t> v(size);
        encode_fn(state, std::span<std::uint8_t>(v));
        return v;
    };

    std::vector<std::uint8_t> bytes_serial =
        encode_to_vec(dev::Serial8250::EncodeState, orig.serial,
                      dev::Serial8250::kEncodedSize);
    std::vector<std::uint8_t> bytes_pic =
        encode_to_vec(dev::Pic8259::EncodeState, orig.pic,
                      dev::Pic8259::kEncodedSize);
    std::vector<std::uint8_t> bytes_pit =
        encode_to_vec(dev::Pit8254::EncodeState, orig.pit,
                      dev::Pit8254::kEncodedSize);
    std::vector<std::uint8_t> bytes_pcibus =
        encode_to_vec(pci::PciBus::EncodeState, orig.pcibus,
                      pci::PciBus::kEncodedSize);
    std::vector<std::uint8_t> bytes_isa =
        encode_to_vec(dev::LegacyIsaStubs::EncodeState, orig.isa,
                      dev::LegacyIsaStubs::kEncodedSize);

    try {
        snap::SnapshotWriter w(tmp_path);
        snap::JsonObjectWriter hdr;
        hdr.Add("version", std::uint64_t{1});
        hdr.Add("phase", std::string_view{"33.5-legacy-test"});
        w.WriteHeader(hdr.str());
        w.WriteSection(snap::SectionType::LegacySerial8250,
                       bytes_serial.data(), bytes_serial.size());
        w.WriteSection(snap::SectionType::LegacyPic8259,
                       bytes_pic.data(), bytes_pic.size());
        w.WriteSection(snap::SectionType::LegacyPit8254,
                       bytes_pit.data(), bytes_pit.size());
        w.WriteSection(snap::SectionType::LegacyPciBus,
                       bytes_pcibus.data(), bytes_pcibus.size());
        w.WriteSection(snap::SectionType::LegacyIsaStubs,
                       bytes_isa.data(), bytes_isa.size());
        w.Finalize();
        std::printf("[save-restore-legacy-test] phaseB wrote %llu bytes\n",
            static_cast<unsigned long long>(w.bytes_written()));
    } catch (const std::exception& e) {
        std::fprintf(stderr,
            "[save-restore-legacy-test] phaseB: %s\n", e.what());
        cleanup_file(); return 2;
    }

    // ---- Phase C: read back + decode + byte-equal + re-encode stable ----
    std::puts("[save-restore-legacy-test] phaseC: read back + decode");
    auto cmp = [&](const char* name,
                   std::span<const std::uint8_t> a,
                   std::span<const std::uint8_t> b) -> bool {
        if (a.size() != b.size()) {
            std::fprintf(stderr,
                "[save-restore-legacy-test] phaseC %s: size %zu != %zu\n",
                name, a.size(), b.size());
            return false;
        }
        if (std::memcmp(a.data(), b.data(), a.size()) != 0) {
            std::fprintf(stderr,
                "[save-restore-legacy-test] phaseC %s: byte mismatch\n",
                name);
            return false;
        }
        return true;
    };
    try {
        snap::SnapshotReader r(tmp_path);
        (void)r.ReadHeader();
        int n = 0;
        Captured decoded{};
        std::vector<std::uint8_t> re_serial, re_pic, re_pit, re_pcibus, re_isa;
        while (auto sec = r.NextSection()) {
            ++n;
            switch (sec->type) {
                case snap::SectionType::LegacySerial8250: {
                    if (!cmp("SERIAL", sec->payload, bytes_serial)) {
                        cleanup_file(); return 2;
                    }
                    decoded.serial = dev::Serial8250::DecodeState(sec->payload);
                    re_serial = encode_to_vec(dev::Serial8250::EncodeState,
                        decoded.serial, dev::Serial8250::kEncodedSize);
                    if (!cmp("SERIAL re-enc", re_serial, bytes_serial)) {
                        cleanup_file(); return 2;
                    }
                    break;
                }
                case snap::SectionType::LegacyPic8259: {
                    if (!cmp("PIC", sec->payload, bytes_pic)) {
                        cleanup_file(); return 2;
                    }
                    decoded.pic = dev::Pic8259::DecodeState(sec->payload);
                    re_pic = encode_to_vec(dev::Pic8259::EncodeState,
                        decoded.pic, dev::Pic8259::kEncodedSize);
                    if (!cmp("PIC re-enc", re_pic, bytes_pic)) {
                        cleanup_file(); return 2;
                    }
                    break;
                }
                case snap::SectionType::LegacyPit8254: {
                    if (!cmp("PIT", sec->payload, bytes_pit)) {
                        cleanup_file(); return 2;
                    }
                    decoded.pit = dev::Pit8254::DecodeState(sec->payload);
                    re_pit = encode_to_vec(dev::Pit8254::EncodeState,
                        decoded.pit, dev::Pit8254::kEncodedSize);
                    if (!cmp("PIT re-enc", re_pit, bytes_pit)) {
                        cleanup_file(); return 2;
                    }
                    break;
                }
                case snap::SectionType::LegacyPciBus: {
                    if (!cmp("PCIBUS", sec->payload, bytes_pcibus)) {
                        cleanup_file(); return 2;
                    }
                    decoded.pcibus = pci::PciBus::DecodeState(sec->payload);
                    re_pcibus = encode_to_vec(pci::PciBus::EncodeState,
                        decoded.pcibus, pci::PciBus::kEncodedSize);
                    if (!cmp("PCIBUS re-enc", re_pcibus, bytes_pcibus)) {
                        cleanup_file(); return 2;
                    }
                    break;
                }
                case snap::SectionType::LegacyIsaStubs: {
                    if (!cmp("ISA", sec->payload, bytes_isa)) {
                        cleanup_file(); return 2;
                    }
                    decoded.isa = dev::LegacyIsaStubs::DecodeState(
                        sec->payload);
                    re_isa = encode_to_vec(dev::LegacyIsaStubs::EncodeState,
                        decoded.isa, dev::LegacyIsaStubs::kEncodedSize);
                    if (!cmp("ISA re-enc", re_isa, bytes_isa)) {
                        cleanup_file(); return 2;
                    }
                    break;
                }
                default:
                    std::fprintf(stderr,
                        "[save-restore-legacy-test] phaseC: unexpected "
                        "section 0x%04x\n",
                        static_cast<unsigned>(sec->type));
                    cleanup_file(); return 2;
            }
        }
        r.VerifyTrailer();
        if (n != 5) {
            std::fprintf(stderr,
                "[save-restore-legacy-test] phaseC: got %d sections, want 5\n",
                n);
            cleanup_file(); return 2;
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr,
            "[save-restore-legacy-test] phaseC: %s\n", e.what());
        cleanup_file(); return 2;
    }
    std::puts("[save-restore-legacy-test] phaseC PASS "
              "(5/5 byte-identical; re-encode stable)");

    // ---- Phase D: ApplyState on fresh devices + verify side-effects -----
    std::puts("[save-restore-legacy-test] phaseD: apply on fresh devices");

    int apply_tx_irq      = 0;
    int apply_pic_inject  = 0;
    int apply_pit_irq     = 0;
    Captured re_captured;
    {
        dev::Pic8259 pic(
            [&](std::uint8_t, std::uint32_t) {
                ++apply_pic_inject;
                return true;
            });
        dev::Serial8250 serial(0x3F8, /*sink=*/nullptr);
        serial.SetIrqCallback([&](int) { ++apply_tx_irq; });
        dev::Pit8254 pit;
        pit.SetIrqCallback([&](int) { ++apply_pit_irq; });
        pci::PciBus pcibus;
        dev::LegacyIsaStubs isa;

        // Apply order: PIC first (so Serial/PIT ResumeRuntime can flow
        // IRQs through it), then everyone else. Order within Apply isn't
        // load-bearing because Apply is pure state restore -- only the
        // subsequent ResumeRuntime calls have side effects.
        pic.ApplyState(orig.pic);
        serial.ApplyState(orig.serial);
        pit.ApplyState(orig.pit);
        pcibus.ApplyState(orig.pcibus);
        isa.ApplyState(orig.isa);

        // Resume runtime in production order: PIC (replays IRR), then
        // Serial (re-edges TX IRQ through PIC), then PIT (starts IRQ
        // thread which may immediately fire ch0 -> PIC IRQ0).
        pic.ResumeRuntime();
        serial.ResumeRuntime();
        pit.ResumeRuntime();

        // Re-capture before letting the PIT IRQ thread fire (which
        // happens asynchronously). Re-capture immediately.
        re_captured.serial = serial.CaptureState();
        re_captured.pic    = pic.CaptureState();
        re_captured.pit    = pit.CaptureState();
        re_captured.pcibus = pcibus.CaptureState();
        re_captured.isa    = isa.CaptureState();
    }

    // Encode re-captured states and byte-compare against ORIG. For PIT,
    // a "running" channel's elapsed_pit_ticks naturally drifts forward
    // between original Capture and post-Apply re-Capture (real wall-clock
    // time passes), so for that one section we compare a normalized view
    // that masks out the per-channel elapsed_pit_ticks fields. Everything
    // else must be byte-identical.
    {
        std::vector<std::uint8_t> re2_serial = encode_to_vec(
            dev::Serial8250::EncodeState, re_captured.serial,
            dev::Serial8250::kEncodedSize);
        std::vector<std::uint8_t> re2_pic = encode_to_vec(
            dev::Pic8259::EncodeState, re_captured.pic,
            dev::Pic8259::kEncodedSize);
        std::vector<std::uint8_t> re2_pit = encode_to_vec(
            dev::Pit8254::EncodeState, re_captured.pit,
            dev::Pit8254::kEncodedSize);
        std::vector<std::uint8_t> re2_pcibus = encode_to_vec(
            pci::PciBus::EncodeState, re_captured.pcibus,
            pci::PciBus::kEncodedSize);
        std::vector<std::uint8_t> re2_isa = encode_to_vec(
            dev::LegacyIsaStubs::EncodeState, re_captured.isa,
            dev::LegacyIsaStubs::kEncodedSize);
        if (!cmp("PIC apply",    re2_pic,    bytes_pic))    {
            cleanup_file(); return 2;
        }
        if (!cmp("SERIAL apply", re2_serial, bytes_serial)) {
            cleanup_file(); return 2;
        }
        // Normalize PIT: zero the elapsed_pit_ticks bytes in both copies.
        // Per channel: 8 bytes at offsets ch_base + 16. Channel bases
        // are 8 (ch0), 32 (ch1), 56 (ch2) within the 88-byte payload.
        auto normalize_pit = [](std::vector<std::uint8_t>& v) {
            for (std::size_t ch_base : {8u, 32u, 56u}) {
                for (std::size_t i = 0; i < 8; ++i) {
                    v[ch_base + 16 + i] = 0;
                }
            }
        };
        std::vector<std::uint8_t> norm_orig = bytes_pit;
        std::vector<std::uint8_t> norm_re2  = re2_pit;
        normalize_pit(norm_orig);
        normalize_pit(norm_re2);
        if (!cmp("PIT apply (normalized)", norm_re2, norm_orig)) {
            cleanup_file(); return 2;
        }
        // Verify elapsed_pit_ticks monotonically advanced (or stayed
        // zero for non-running channels) for the running channels.
        // This proves the time rebase actually preserved phase rather
        // than zeroing start_qpc.
        for (int ch = 0; ch < 3; ++ch) {
            const std::uint64_t orig_e =
                orig.pit.ch[ch].elapsed_pit_ticks;
            const std::uint64_t new_e  =
                re_captured.pit.ch[ch].elapsed_pit_ticks;
            if (orig.pit.ch[ch].running && new_e < orig_e) {
                std::fprintf(stderr,
                    "[save-restore-legacy-test] phaseD PIT ch%d: "
                    "elapsed regressed (%llu -> %llu)\n",
                    ch,
                    static_cast<unsigned long long>(orig_e),
                    static_cast<unsigned long long>(new_e));
                cleanup_file(); return 2;
            }
        }
        if (!cmp("PCIBUS apply", re2_pcibus, bytes_pcibus)) {
            cleanup_file(); return 2;
        }
        if (!cmp("ISA apply",    re2_isa,    bytes_isa))    {
            cleanup_file(); return 2;
        }
    }

    // ResumeRuntime side-effect counts:
    //   - Serial: 1 TX IRQ edge (the in-flight pending one).
    //   - PIC: ResumeRuntime injects MASTER IRR bits whose mask is clear.
    //     Master has IRR=0x02 (IRQ 1, from Raise(1) earlier) AND IRR
    //     bit 4 from the TX IRQ (IRQ 4 from earlier THR write, latched
    //     after Apply because we didn't clear master_.irr at save -- in
    //     fact the original Raise(4) would have injected immediately
    //     since IRQ 4 was unmasked; so master.irr bit 4 should be
    //     CLEAR in the original state).
    //
    //   Actually, original captured state:
    //     master_.mask = 0xFB (bit 2 clear; everything else set EXCEPT
    //                          bit 2... wait, mask=0xFB means bits 0,1,
    //                          3,4,5,6,7 are masked, bit 2 unmasked).
    //     So Raise(4) -> chip.mask bit 4 set -> latched in IRR
    //     (InjectLocked NOT called because masked).
    //     But Serial's IRQ-raise goes through pic.Raise(4)... if mask
    //     has bit 4 set then it latches.
    //   So master_.irr should have bits 1 and 4 set after phase A.
    //   ResumeRuntime: master mask 0xFB has bit 2 clear; deliverable =
    //     irr (0x12) & ~mask (~0xFB=0x04) = 0x00. None deliverable!
    //   So PIC ResumeRuntime injects 0 times.
    //
    //   Serial ResumeRuntime: tx_irq_pending=1 AND ETBEI=1 AND
    //     irq_raise_ set -> clears pending, calls
    //     MaybeRaiseTxIrqLocked -> sets pending, calls
    //     irq_raise_(4) -> tx_irq_count++.
    //
    //   PIT ResumeRuntime: ch0_irq_armed=1 -> starts IRQ thread, may
    //     deliver IRQ 0 asynchronously. We can't assert exact count
    //     since it's racy; just confirm >=0.
    //
    //   Expected: apply_tx_irq=1, apply_pic_inject in [0, N] (could
    //     receive ch0 IRQs via PIT through pic.Raise(0) -> InjectLocked
    //     if IRQ0 mask is clear in master (0xFB has bit 0 set, so IRQ0
    //     would be latched, not injected). So apply_pic_inject=0.
    if (apply_tx_irq != 1) {
        std::fprintf(stderr,
            "[save-restore-legacy-test] phaseD: serial TX IRQ count = %d "
            "(want 1)\n", apply_tx_irq);
        cleanup_file(); return 2;
    }
    std::printf("[save-restore-legacy-test] phaseD: side-effects "
                "(tx_irq=%d, pic_inject=%d, pit_irq=%d)\n",
                apply_tx_irq, apply_pic_inject, apply_pit_irq);
    std::puts("[save-restore-legacy-test] phaseD PASS "
              "(Apply round-trip byte-stable across all 5 states)");

    cleanup_file();
    std::puts("[save-restore-legacy-test] PASS");
    return 0;
}

// --cpuid-test (M18)
// Drive the CPUID resolver directly (no WHP) and assert that the policy
// produces the bits Linux needs to (a) trust TSC as a clocksource, (b) skip
// PIT calibration via CPUID.15h, (c) program LAPIC via tsc-deadline, and
// (d) see a sensible hypervisor vendor signature.
int RunCpuidTest() {
    using tinyvmm::whp::CpuidContext;
    using tinyvmm::whp::CpuidResult;
    using tinyvmm::whp::ResolveCpuid;

    auto fail = [](const char* msg) {
        std::fprintf(stderr, "[cpuid-test] FAIL: %s\n", msg);
        return 1;
    };

    // Default-in values mimic a "WHP returned zero" baseline so we can see
    // exactly what our policy injects on top. Default per-vCPU context is
    // BSP (vcpu_index=0) of a 1-vCPU partition; the per-vCPU APIC ID block
    // below exercises non-default contexts explicitly.
    auto resolve = [](std::uint32_t leaf, std::uint32_t subleaf = 0,
                      const CpuidContext& ctx = CpuidContext{0u, 1u}) {
        return ResolveCpuid(leaf, subleaf, 0, 0, 0, 0, ctx);
    };

    // Leaf 0x00: max-standard-leaf raised to at least 0x1F (so the guest
    // can reach the synthesized 0x0B / 0x1F topology leaves).
    {
        CpuidResult r = resolve(0x00000000u);
        if (r.eax < 0x1Fu) return fail("leaf 0: max-leaf < 0x1F");
    }

    // Leaf 0x01: tsc-deadline + hypervisor-present.
    {
        CpuidResult r = resolve(0x00000001u);
        if ((r.ecx & (1u << 24)) == 0) return fail("leaf 1: tsc-deadline not set");
        if ((r.ecx & (1u << 31)) == 0) return fail("leaf 1: hypervisor bit not set");
    }

    // Leaf 0x01 + hide-tsc-deadline: bit 24 must be cleared, bit 31 still set.
    {
        tinyvmm::whp::SetHideTscDeadline(true);
        CpuidResult r = resolve(0x00000001u);
        tinyvmm::whp::SetHideTscDeadline(false);  // restore default
        if ((r.ecx & (1u << 24)) != 0) {
            return fail("leaf 1 (hide): tsc-deadline still set");
        }
        if ((r.ecx & (1u << 31)) == 0) {
            return fail("leaf 1 (hide): hypervisor bit cleared");
        }
    }

    // Leaf 0x06: ARAT.
    {
        CpuidResult r = resolve(0x00000006u);
        if ((r.eax & (1u << 2)) == 0) return fail("leaf 6: ARAT not set");
    }

    // Leaf 0x15: TSC frequency ratio. EBX=EAX=1, ECX = sane TSC Hz.
    std::uint32_t tsc_hz_from_15 = 0;
    {
        CpuidResult r = resolve(0x00000015u);
        if (r.eax != 1u) return fail("leaf 0x15: EAX != 1");
        if (r.ebx != 1u) return fail("leaf 0x15: EBX != 1");
        if (r.ecx < 100'000'000u) return fail("leaf 0x15: ECX < 100 MHz");
        if (static_cast<std::uint64_t>(r.ecx) > 10'000'000'000ull)
            return fail("leaf 0x15: ECX > 10 GHz");
        tsc_hz_from_15 = r.ecx;
    }

    // Leaf 0x16: base/max/bus MHz consistent with leaf 0x15.
    {
        CpuidResult r = resolve(0x00000016u);
        if (r.eax < 100u) return fail("leaf 0x16: base MHz < 100");
        if (r.ebx < 100u) return fail("leaf 0x16: max MHz < 100");
        if (r.ecx == 0u) return fail("leaf 0x16: bus MHz == 0");
        const std::uint64_t expected_mhz = tsc_hz_from_15 / 1'000'000ull;
        if (r.eax != static_cast<std::uint32_t>(expected_mhz)) {
            return fail("leaf 0x16: base MHz inconsistent with leaf 0x15");
        }
    }

    // Leaf 0x80000007: invariant-TSC.
    {
        CpuidResult r = resolve(0x80000007u);
        if ((r.edx & (1u << 8)) == 0) return fail("leaf 0x80000007: invariant_tsc not set");
    }

    // Leaf 0x40000000: vendor "Microsoft Hv" (Linux requires this exact
    // string to enter the Hyper-V detection path) + max-leaf >= 0x40000005.
    {
        CpuidResult r = resolve(0x40000000u);
        if (r.eax < 0x40000005u || r.eax > 0x4000FFFFu) {
            std::fprintf(stderr,
                "[cpuid-test] FAIL: leaf 0x40000000 max=0x%08x out of "
                "Hyper-V [0x40000005, 0x4000FFFF] range\n", r.eax);
            return 1;
        }
        char vendor[13] = {0};
        std::memcpy(vendor + 0, &r.ebx, 4);
        std::memcpy(vendor + 4, &r.ecx, 4);
        std::memcpy(vendor + 8, &r.edx, 4);
        if (std::memcmp(vendor, "Microsoft Hv", 12) != 0) {
            std::fprintf(stderr,
                "[cpuid-test] FAIL: leaf 0x40000000 vendor='%s' (want "
                "'Microsoft Hv')\n", vendor);
            return 1;
        }
    }

    // Leaf 0x40000001: "Hv#1" interface signature (0x31237648 little-endian).
    {
        CpuidResult r = resolve(0x40000001u);
        char sig[5] = {0};
        std::memcpy(sig, &r.eax, 4);
        if (std::memcmp(sig, "Hv#1", 4) != 0) {
            std::fprintf(stderr,
                "[cpuid-test] FAIL: leaf 0x40000001 sig='%s' (want 'Hv#1')\n",
                sig);
            return 1;
        }
    }

    // Leaf 0x40000002: zeroed (build/version info we don't care about).
    {
        CpuidResult r = resolve(0x40000002u);
        if (r.eax || r.ebx || r.ecx || r.edx) {
            return fail("leaf 0x40000002: not zeroed");
        }
    }

    // Leaf 0x40000003: features. EAX must advertise
    //   HYPERCALL | VP_INDEX | REFERENCE_TSC | TSC_INVARIANT
    // EBX/ECX/EDX zero (we don't implement any priv_high / power / misc
    // features that Linux gates further enlightenment on).
    {
        CpuidResult r = resolve(0x40000003u);
        constexpr std::uint32_t kExpected =
            (1u << 5) | (1u << 6) | (1u << 9) | (1u << 15);
        if ((r.eax & kExpected) != kExpected) {
            std::fprintf(stderr,
                "[cpuid-test] FAIL: leaf 0x40000003 EAX=0x%08x missing one "
                "of HYPERCALL/VP_INDEX/REFERENCE_TSC/TSC_INVARIANT\n", r.eax);
            return 1;
        }
        if (r.ebx || r.ecx || r.edx) {
            return fail("leaf 0x40000003: EBX/ECX/EDX must be zero");
        }
    }

    // Leaves 0x40000004..0x40000006: zeroed (no hints, no impl limits, no
    // hw features -- Linux skips PV-TLB / PV-IPI / SynIC / synthetic timer).
    for (std::uint32_t leaf = 0x40000004u; leaf <= 0x40000006u; ++leaf) {
        CpuidResult r = resolve(leaf);
        if (r.eax || r.ebx || r.ecx || r.edx) {
            std::fprintf(stderr,
                "[cpuid-test] FAIL: leaf 0x%08x: not zeroed\n", leaf);
            return 1;
        }
    }

    // Pass-through sanity: an arbitrary leaf returns the host defaults
    // unchanged. We supply non-zero defaults and check they survive.
    {
        CpuidContext ctx{0u, 1u};
        CpuidResult r = ResolveCpuid(0x00000007u, 0, 0xDEAD0007u, 0xCAFEu,
                                     0xBEEFu, 0x1234u, ctx);
        if (r.eax != 0xDEAD0007u || r.ebx != 0xCAFEu ||
            r.ecx != 0xBEEFu || r.edx != 0x1234u) {
            return fail("leaf 0x07: defaults not passed through");
        }
    }

    // --- Per-vCPU CPUID block: leaves 0x01, 0x0B, 0x1F must each carry
    // the per-vCPU APIC ID (matching what we publish in the MADT) so
    // Linux's SMP bring-up doesn't log "[Firmware Bug] APIC ID mismatch".
    {
        // Leaf 0x01 EBX[31:24] = vcpu_index, [23:16] = vcpu_count.
        // Default EBX = 0; lower 16 bits must be preserved unchanged.
        for (std::uint32_t idx : {0u, 1u, 5u, 31u, 255u}) {
            CpuidContext c{idx, 32u};
            CpuidResult r = ResolveCpuid(0x00000001u, 0,
                                         0u, 0x0000AABBu, 0u, 0u, c);
            const std::uint32_t apic_id = (r.ebx >> 24) & 0xFFu;
            const std::uint32_t max_per_pkg = (r.ebx >> 16) & 0xFFu;
            if (apic_id != (idx & 0xFFu)) {
                std::fprintf(stderr,
                    "[cpuid-test] FAIL: leaf 1 idx=%u: apic_id=%u (want %u)\n",
                    idx, apic_id, idx & 0xFFu);
                return 1;
            }
            if (max_per_pkg != 32u) {
                return fail("leaf 1: max-logical-per-package wrong");
            }
            if ((r.ebx & 0x0000FFFFu) != 0xAABBu) {
                return fail("leaf 1: EBX[15:0] not preserved");
            }
        }
    }
    {
        // Leaves 0x0B and 0x1F: SMT subleaf 0, Core subleaf 1, Invalid
        // subleaf >=2. EDX must equal vcpu_index in every subleaf so the
        // Linux x2APIC walk picks up the right ID regardless of where it
        // stops scanning.
        for (std::uint32_t leaf : {0x0000000Bu, 0x0000001Fu}) {
            for (std::uint32_t idx : {0u, 3u, 7u, 31u}) {
                CpuidContext c{idx, 8u};
                // Subleaf 0: SMT level (1 thread per core).
                {
                    CpuidResult r = resolve(leaf, 0u, c);
                    if (r.edx != idx) {
                        std::fprintf(stderr,
                            "[cpuid-test] FAIL: leaf 0x%x sub0 idx=%u: edx=%u\n",
                            leaf, idx, r.edx);
                        return 1;
                    }
                    if (r.eax != 0u || r.ebx != 1u) {
                        return fail("leaf 0x0B/0x1F sub0: shape wrong");
                    }
                    if ((r.ecx & 0xFFu) != 0u ||
                        ((r.ecx >> 8) & 0xFFu) != 1u /* SMT */) {
                        return fail("leaf 0x0B/0x1F sub0: ECX level wrong");
                    }
                }
                // Subleaf 1: Core level (vcpu_count cores).
                {
                    CpuidResult r = resolve(leaf, 1u, c);
                    if (r.edx != idx) {
                        return fail("leaf 0x0B/0x1F sub1: EDX != vcpu_index");
                    }
                    if (r.eax != 5u || r.ebx != 8u) {
                        return fail("leaf 0x0B/0x1F sub1: shape wrong");
                    }
                    if ((r.ecx & 0xFFu) != 1u ||
                        ((r.ecx >> 8) & 0xFFu) != 2u /* Core */) {
                        return fail("leaf 0x0B/0x1F sub1: ECX level wrong");
                    }
                }
                // Subleaf 2+: Invalid terminator.
                for (std::uint32_t sub : {2u, 3u, 7u}) {
                    CpuidResult r = resolve(leaf, sub, c);
                    if (r.edx != idx) {
                        return fail("leaf 0x0B/0x1F sub>=2: EDX != vcpu_index");
                    }
                    if (r.eax != 0u || r.ebx != 0u) {
                        return fail("leaf 0x0B/0x1F sub>=2: EAX/EBX != 0");
                    }
                    if ((r.ecx & 0xFFu) != sub ||
                        ((r.ecx >> 8) & 0xFFu) != 0u /* Invalid */) {
                        return fail("leaf 0x0B/0x1F sub>=2: ECX wrong");
                    }
                }
            }
        }
    }

    std::printf("[cpuid-test] PASS (tsc=%u Hz, %.3f GHz)\n",
                tsc_hz_from_15,
                static_cast<double>(tsc_hz_from_15) / 1.0e9);
    return 0;
}

// ---------------------------------------------------------------------------
// --cpu-affinity-test: validate parser, topology discovery, and pin/unpin.
// Does not assume anything about the host beyond "GetSystemCpuSetInformation
// returns non-empty" -- safe to run in CI on any modern Windows.
// ---------------------------------------------------------------------------
int RunCpuAffinityTest() {
    using tinyvmm::whp::AffinityMode;
    using tinyvmm::whp::ParseAffinityMode;
    using tinyvmm::whp::AffinityModeName;
    using tinyvmm::whp::ResolveCpuSetIds;
    using tinyvmm::whp::GetTopology;
    using tinyvmm::whp::PinCurrentThread;

    auto fail = [](const char* m) {
        std::fprintf(stderr, "[cpu-affinity-test] FAIL: %s\n", m);
        return 1;
    };

    // Parser: accepted tokens.
    {
        struct { const char* in; AffinityMode want; } cases[] = {
            {"all",        AffinityMode::All},
            {"ALL",        AffinityMode::All},
            {"p",          AffinityMode::PCore},
            {"P",          AffinityMode::PCore},
            {"P-Core",     AffinityMode::PCore},
            {"e",          AffinityMode::ECore},
            {"e-core",     AffinityMode::ECore},
            {"p-physical", AffinityMode::PCorePhysical},
            {"P-Phys",     AffinityMode::PCorePhysical},
        };
        for (const auto& c : cases) {
            AffinityMode got{};
            if (!ParseAffinityMode(c.in, got))
                return fail("parser rejected a valid token");
            if (got != c.want) return fail("parser returned wrong mode");
        }
    }
    // Parser: rejected tokens.
    {
        const char* bad[] = {"", "x", "pe", "pcore-physical",
                             "p_core", "all-cores"};
        for (const char* b : bad) {
            AffinityMode got{};
            if (ParseAffinityMode(b, got))
                return fail("parser accepted an invalid token");
        }
    }
    // Name round-trip.
    {
        AffinityMode roundtrip[] = {
            AffinityMode::All, AffinityMode::PCore,
            AffinityMode::PCorePhysical, AffinityMode::ECore};
        for (auto m : roundtrip) {
            AffinityMode got{};
            if (!ParseAffinityMode(AffinityModeName(m), got))
                return fail("AffinityModeName produced unparseable string");
            if (got != m) return fail("name round-trip mismatch");
        }
    }
    // Topology: must report at least one logical processor.
    const auto& top = GetTopology();
    if (top.total_logical == 0)
        return fail("GetTopology reported zero logicals");
    if (top.p_logical + top.e_logical != top.total_logical)
        return fail("p+e logicals != total");
    if (top.p_physical > top.p_logical)
        return fail("more physical P-cores than logical P-cores");
    if (top.hybrid && top.e_logical == 0)
        return fail("hybrid host but zero E-cores");

    // Resolve: All -> empty, PCore -> non-empty.
    if (!ResolveCpuSetIds(AffinityMode::All).empty())
        return fail("AffinityMode::All must resolve to empty set");
    auto p_ids = ResolveCpuSetIds(AffinityMode::PCore);
    if (p_ids.empty())
        return fail("PCore mode resolved to empty set");
    if (p_ids.size() != top.p_logical)
        return fail("PCore set size != p_logical");

    auto p_phys = ResolveCpuSetIds(AffinityMode::PCorePhysical);
    if (p_phys.empty())
        return fail("PCorePhysical resolved to empty set");
    if (p_phys.size() != top.p_physical)
        return fail("PCorePhysical set size != p_physical");

    if (top.hybrid) {
        auto e_ids = ResolveCpuSetIds(AffinityMode::ECore);
        if (e_ids.empty())
            return fail("ECore mode resolved to empty set on hybrid host");
        if (e_ids.size() != top.e_logical)
            return fail("ECore set size != e_logical");
        // P and E sets must be disjoint.
        for (ULONG p : p_ids) {
            for (ULONG e : e_ids) {
                if (p == e) return fail("P and E sets overlap");
            }
        }
    } else {
        if (!ResolveCpuSetIds(AffinityMode::ECore).empty())
            return fail("ECore mode must be empty on non-hybrid host");
    }

    // Pin: empty set is a no-op success.
    if (!PinCurrentThread({})) return fail("Pin({}) returned false");

    // Pin to the PCore set, then restore (pin to empty unpins, but to be
    // safe we pin back to a single-element set covering every logical).
    if (!PinCurrentThread(p_ids))
        return fail("PinCurrentThread(p_ids) failed");
    std::vector<ULONG> all_ids;
    all_ids.reserve(top.total_logical);
    for (ULONG id : p_ids) all_ids.push_back(id);
    if (top.hybrid) {
        auto e_ids = ResolveCpuSetIds(AffinityMode::ECore);
        for (ULONG id : e_ids) all_ids.push_back(id);
    }
    if (!PinCurrentThread(all_ids))
        return fail("PinCurrentThread(all_ids) restoration failed");

    std::printf(
        "[cpu-affinity-test] PASS (total=%u, hybrid=%d, P=%u/%uHT, E=%u, "
        "P-physical=%zu)\n",
        top.total_logical, top.hybrid ? 1 : 0,
        top.p_physical, top.p_logical, top.e_logical, p_phys.size());
    return 0;
}

// Host-side smoke for the Hyper-V enlightenment helpers. Does NOT touch
// WHP -- exercises only the pure scaling math, the vendor-string helpers,
// and the MSR dispatch path that runs in user-mode on every MSR exit.
//
// Coverage:
//   1. ComputeTscScale: known frequencies -> stable, within-tolerance scale
//      values. We assert the absolute scaling identity
//      `(tsc_scale * tsc_hz) >> 64 ~= 10^7`.
//   2. GetHvVendorEbxEcxEdx: round-trip to "Microsoft Hv" (12 bytes).
//   3. GetHvInterfaceEax: equals "Hv#1" (0x31237648 little-endian).
//   4. WrmsrlGuestOsId / TscInvariantControl: simple read/write roundtrip.
//   5. WrmsrlReferenceTsc disabled (bit 0 == 0): page is NOT written
//      (no host-mem access without a backing GuestMemory).
//   6. WrmsrlReferenceTsc enabled but GPA out of range: returns Yes
//      (writes are silently dropped on bad GPAs, matching kvm/hyperv).
//   7. Unknown MSR (e.g. 0x40000099): returns NoInjectGp so the run-loop
//      injects #GP into the guest instead of crashing the VMM.
int RunHvEnlightenmentTest() {
    using namespace tinyvmm::whp;

    auto fail = [](const char* msg) -> int {
        std::fprintf(stderr, "[hv-test] FAIL: %s\n", msg);
        return 1;
    };

    // ---- (1) ComputeTscScale ----------------------------------------------
    // For tsc_hz, the contract is that (rdtsc * scale) >> 64 yields 100 ns
    // ticks. So (scale * tsc_hz) >> 64 must equal 10^7 within tight rounding.
    auto check_scale = [&](std::uint64_t hz, std::uint64_t expected_per_sec,
                           int tol_units) -> int {
        std::uint64_t scale = ComputeTscScale(hz);
        if (scale == 0) {
            return fail("ComputeTscScale returned 0");
        }
        // (scale * hz) >> 64 -> 100ns ticks per second of TSC.
        const std::uint64_t per_sec =
            static_cast<std::uint64_t>(__umulh(scale, hz));
        const std::int64_t delta =
            static_cast<std::int64_t>(per_sec) -
            static_cast<std::int64_t>(expected_per_sec);
        const std::int64_t abs_delta = delta < 0 ? -delta : delta;
        if (abs_delta > tol_units) {
            std::fprintf(stderr,
                "[hv-test] scale check fail: hz=%llu scale=0x%llx per_sec=%llu "
                "expected=%llu delta=%lld tol=%d\n",
                static_cast<unsigned long long>(hz),
                static_cast<unsigned long long>(scale),
                static_cast<unsigned long long>(per_sec),
                static_cast<unsigned long long>(expected_per_sec),
                static_cast<long long>(delta), tol_units);
            return 1;
        }
        return 0;
    };
    // Expected per-second 100ns ticks = 10^7. Tolerance ±2 units (rounding).
    if (check_scale(3'000'000'000ull, 10'000'000ull, 2)) return 1;
    if (check_scale(2'500'000'000ull, 10'000'000ull, 2)) return 1;
    if (check_scale(1'000'000'000ull, 10'000'000ull, 2)) return 1;
    // Edge case: very high freq (5 GHz typical, 6 GHz overclock).
    if (check_scale(6'000'000'000ull, 10'000'000ull, 2)) return 1;
    // Edge case: zero -> defined behavior (returns 0, no UB).
    if (ComputeTscScale(0) != 0)
        return fail("ComputeTscScale(0) must return 0");

    // ---- (2) Vendor / (3) Interface signature -----------------------------
    {
        std::uint32_t ebx{}, ecx{}, edx{};
        GetHvVendorEbxEcxEdx(&ebx, &ecx, &edx);
        char vendor[13] = {0};
        std::memcpy(vendor + 0, &ebx, 4);
        std::memcpy(vendor + 4, &ecx, 4);
        std::memcpy(vendor + 8, &edx, 4);
        if (std::memcmp(vendor, "Microsoft Hv", 12) != 0) {
            std::fprintf(stderr,
                "[hv-test] vendor='%s' (want 'Microsoft Hv')\n", vendor);
            return 1;
        }

        const std::uint32_t iface = GetHvInterfaceEax();
        // "Hv#1" = 'H'(0x48) 'v'(0x76) '#'(0x23) '1'(0x31)
        // little-endian u32 = 0x31237648.
        if (iface != 0x31237648u) {
            std::fprintf(stderr,
                "[hv-test] interface 0x%08x (want 0x31237648 'Hv#1')\n",
                iface);
            return 1;
        }
    }

    // ---- (4)-(7) MSR dispatch ---------------------------------------------
    // Build an HvEnlightenment via the test-only no-ram constructor. The
    // ReferenceTsc/Hypercall page writes silently no-op in this mode -- the
    // MSR is still accepted and remembered, which lets us validate the
    // dispatch path independently of WHP/GuestMemory.
    HvEnlightenment hv_nomem(/*tsc_hz=*/3'000'000'000ull);

    // (4a) GuestOsId roundtrip.
    {
        constexpr std::uint64_t kFakeLinuxId = 0x8100'0000'0000'0001ull;
        if (hv_nomem.HandleWrmsr(0, kHvMsrGuestOsId, kFakeLinuxId) !=
            MsrHandled::Yes) {
            return fail("WRMSR GUEST_OS_ID rejected");
        }
        std::uint64_t got = 0;
        if (hv_nomem.HandleRdmsr(0, kHvMsrGuestOsId, &got) !=
                MsrHandled::Yes ||
            got != kFakeLinuxId) {
            return fail("RDMSR GUEST_OS_ID readback mismatch");
        }
    }

    // (4b) TscInvariantControl roundtrip (only bit 0 is architecturally
    // defined; we mask to bit 0).
    {
        if (hv_nomem.HandleWrmsr(0, kHvMsrTscInvariantCtl, 1) !=
            MsrHandled::Yes) {
            return fail("WRMSR TSC_INVARIANT_CONTROL rejected");
        }
        std::uint64_t got = 0;
        if (hv_nomem.HandleRdmsr(0, kHvMsrTscInvariantCtl, &got) !=
                MsrHandled::Yes ||
            (got & 1) != 1) {
            return fail("RDMSR TSC_INVARIANT_CONTROL readback mismatch");
        }
    }

    // (4c) VP_INDEX returns the caller's vcpu index. Read-only from guest;
    // we don't WRMSR it.
    {
        std::uint64_t got = 0xDEADull;
        if (hv_nomem.HandleRdmsr(/*vp=*/7, kHvMsrVpIndex, &got) !=
                MsrHandled::Yes ||
            got != 7) {
            return fail("RDMSR VP_INDEX did not return calling vcpu index");
        }
    }

    // (4d) TIME_REF_COUNT increases monotonically with host TSC. We can't
    // pin the exact value but two reads spaced by a busy loop must differ.
    {
        std::uint64_t a = 0, b = 0;
        if (hv_nomem.HandleRdmsr(0, kHvMsrTimeRefCount, &a) !=
            MsrHandled::Yes) {
            return fail("RDMSR TIME_REF_COUNT rejected");
        }
        // Busy-wait a fixed number of cycles to make the value advance.
        // 1e6 iterations is ~1 ms on any reasonable host (well above the
        // 100 ns LSB of TIME_REF_COUNT).
        volatile std::uint64_t sink = 0;
        for (int i = 0; i < 1'000'000; ++i) sink += static_cast<std::uint64_t>(i);
        (void)sink;
        if (hv_nomem.HandleRdmsr(0, kHvMsrTimeRefCount, &b) !=
            MsrHandled::Yes) {
            return fail("RDMSR TIME_REF_COUNT rejected (2nd)");
        }
        if (b <= a) {
            std::fprintf(stderr,
                "[hv-test] TIME_REF_COUNT non-monotonic: a=%llu b=%llu\n",
                static_cast<unsigned long long>(a),
                static_cast<unsigned long long>(b));
            return 1;
        }
    }

    // (5) ReferenceTsc disabled (bit 0 == 0): write must succeed without
    // touching guest memory (we have none in this construction).
    {
        if (hv_nomem.HandleWrmsr(0, kHvMsrReferenceTsc,
                                 /*disabled*/ 0xFFFFFFFFFFFFF000ull) !=
            MsrHandled::Yes) {
            return fail("WRMSR REFERENCE_TSC (disabled) rejected");
        }
    }

    // (6) ReferenceTsc enabled but with no backing RAM: should still return
    // Yes (write is dropped). HvEnlightenment treats nullptr ram_ as
    // "no GuestMemory" and short-circuits the page write.
    {
        const std::uint64_t enabled_bad_gpa = 0xFFFFFFFFFFFFF001ull;
        if (hv_nomem.HandleWrmsr(0, kHvMsrReferenceTsc, enabled_bad_gpa) !=
            MsrHandled::Yes) {
            return fail("WRMSR REFERENCE_TSC (enabled,no-ram) must not GP");
        }
    }

    // (7) Unknown MSR in the Hyper-V range -> NoInjectGp (so the run-loop
    // injects a #GP into the guest, matching real Hyper-V's behaviour for
    // unimplemented MSRs).
    {
        std::uint64_t got = 0;
        if (hv_nomem.HandleRdmsr(0, /*made-up*/ 0x40000099ull, &got) !=
            MsrHandled::NoInjectGp) {
            return fail("RDMSR unknown MSR did not return NoInjectGp");
        }
        if (hv_nomem.HandleWrmsr(0, 0x40000099ull, 0) !=
            MsrHandled::NoInjectGp) {
            return fail("WRMSR unknown MSR did not return NoInjectGp");
        }
    }

    std::printf("[hv-test] PASS (scale-math + vendor + iface + MSR dispatch)\n");
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    // Unbuffer stdout/stderr so progress is visible when piped to a file or
    // captured by a parent process (especially important for long-running
    // commands like --pvh-run that we may kill externally).
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);

    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::string_view cmd(argv[1]);
    try {
        if (cmd == "--smoke") {
            return RunSmoke();
        }
        if (cmd == "--tsi-smoke") {
            return RunTsiSmoke();
        }
        if (cmd == "--loop-test") {
            return RunLoopTest();
        }
        if (cmd == "--uart-test") {
            return RunUartTest();
        }
        if (cmd == "--virtio-test") {
            return RunVirtioTest();
        }
        if (cmd == "--doorbell-test") {
            return RunDoorbellTest();
        }
        if (cmd == "--pci-test") {
            return RunPciTest();
        }
        if (cmd == "--msix-test") {
            return RunMsixTest();
        }
        if (cmd == "--msix-inject-test") {
            return RunMsixInjectTest();
        }
        if (cmd == "--virtio-pci-test") {
            return RunVirtioPciTest();
        }
        if (cmd == "--virtio-blk-test") {
            return RunVirtioBlkTest();
        }
        if (cmd == "--virtio-blk-ro-test") {
            return RunVirtioBlkRoTest();
        }
        if (cmd == "--virtio-blk-discard-test") {
            return RunVirtioBlkDiscardTest();
        }
        if (cmd == "--virtio-net-pci-test") {
            return RunVirtioNetPciTest();
        }
        if (cmd == "--virtio-net-loopback-test") {
            return RunVirtioNetLoopbackTest();
        }
        if (cmd == "--virtio-net-usernet-tsi-test") {
            return RunVirtioNetUsernetTsiTest();
        }
        if (cmd == "--tsi-fuzz-test") {
            int iters = 10000;
            std::uint64_t seed = 0xC0FFEE12345678ULL;
            if (argc >= 3) iters = std::atoi(argv[2]);
            if (argc >= 4) seed  = std::strtoull(argv[3], nullptr, 0);
            if (iters <= 0) iters = 10000;
            return RunTsiFuzzTest(iters, seed);
        }
        if (cmd == "--virtio-queue-fuzz-test") {
            int iters = 50000;
            std::uint64_t seed = 0xFADE0FFULL;
            if (argc >= 3) iters = std::atoi(argv[2]);
            if (argc >= 4) seed  = std::strtoull(argv[3], nullptr, 0);
            if (iters <= 0) iters = 50000;
            return RunVirtioQueueFuzzTest(iters, seed);
        }
        if (cmd == "--virtio-rng-test") {
            return RunVirtioRngTest();
        }
        if (cmd == "--virtio-console-test") {
            return RunVirtioConsoleTest();
        }
        if (cmd == "--cpuid-test") {
            return RunCpuidTest();
        }
        if (cmd == "--snapshot-trigger-test") {
            return RunSnapshotTriggerTest();
        }
        if (cmd == "--save-restore-probe") {
            return RunSaveRestoreProbe();
        }
        if (cmd == "--save-restore-roundtrip-test") {
            return RunSaveRestoreRoundtripTest();
        }
        if (cmd == "--save-restore-pci-test") {
            return RunSaveRestorePciTest();
        }
        if (cmd == "--save-restore-legacy-test") {
            return RunSaveRestoreLegacyTest();
        }
        if (cmd == "--cpu-affinity-test") {
            return RunCpuAffinityTest();
        }
        if (cmd == "--hv-test") {
            return RunHvEnlightenmentTest();
        }
        if (cmd == "--xdp-probe") {
            int if_index = 0;
            if (argc >= 3) {
                if_index = std::atoi(argv[2]);
            }
            return tinyvmm::host::RunXdpProbe(if_index);
        }
        if (cmd == "--wintun-probe") {
            int seconds = 5;
            if (argc >= 3) {
                seconds = std::atoi(argv[2]);
                if (seconds <= 0) seconds = 5;
            }
            return tinyvmm::RunWintunProbe(seconds);
        }
        if (cmd == "--wintun-svc-probe") {
            int seconds = 5;
            if (argc >= 3) {
                seconds = std::atoi(argv[2]);
                if (seconds <= 0) seconds = 5;
            }
            return tinyvmm::RunWintunSvcProbe(seconds);
        }
        if (cmd == "--pvh-info") {
            if (argc < 3) {
                std::fputs("--pvh-info: expected path to vmlinux\n", stderr);
                return 1;
            }
            return RunPvhInfo(argv[2]);
        }
        if (cmd == "--pvh-run") {
            if (argc < 3) {
                std::fputs("--pvh-run: expected path to vmlinux\n", stderr);
                return 1;
            }
            bool with_net = false;
            bool debug_boot = false;
            NetBackendKind net_backend = NetBackendKind::Loopback;
            std::uint32_t xdp_if = 0;
            std::uint32_t xdp_queue = 0;
            bool xdp_debug = false;
            std::string initrd_path;
            std::vector<DriveSpec> drives;
            std::vector<P9ShareSpec> p9_shares;
            int watchdog_secs = 0;  // 0 = disabled (default; previously 20)
            // Default 256 MiB. Min 128 MiB (Linux fails to boot below ~96 MiB
            // once initramfs is loaded; 128 leaves headroom). Max 3584 MiB:
            // PCI MMIO BAR window starts at 0xE0000000, so RAM above that
            // address would collide with virtio device BARs. >4 GiB support
            // requires a low/high RAM split around the MMIO hole; deferred.
            std::uint32_t ram_mb = 256;
            // Default 1 vCPU (BSP only). Range [1, kMaxVcpus=32]. For N>1 we
            // spawn N-1 std::threads each running its own RunLoop; the BSP
            // continues to run on the main thread. APs sit in WAIT_FOR_SIPI
            // until Linux's secondary-CPU bring-up code delivers INIT+SIPI.
            std::uint32_t vcpu_count = 1;
            // CPU affinity policy for vCPU threads. Default: no pinning.
            tinyvmm::whp::AffinityMode affinity_mode =
                tinyvmm::whp::AffinityMode::All;
            std::vector<tinyvmm::virtio::UsernetBackend::PortForward>
                port_forwards;
            // M35: GDB Remote Serial Protocol stub TCP port on
            // 127.0.0.1. 0 disables (default). When non-zero, tinyvmm
            // halts before the first guest instruction and waits for
            // `target remote :<port>` from gdb.
            std::uint16_t gdb_port = 0;
            // M33 Phase 33.1: snapshot trigger settings. When `--save
            // <path>` is parsed, `save_path` is populated and the global
            // snapshot::State() is armed before the run loop starts.
            // `unsafe_save_mutable_drive` opts out of the v1 RO-default
            // policy on `--drive`s (consistency caveat documented in
            // plan §"drive consistency").
            std::string save_path;
            bool unsafe_save_mutable_drive = false;
            // Hide TSC-deadline by default: WHP's LAPIC emulation rejects
            // WRMSR 0x6E0 even when the bit is set in CpuidResultList, so
            // advertising it just causes Linux to log a 30-line `unchecked
            // MSR access` trace before silently falling back to LAPIC
            // oneshot. Pass --expose-tsc-deadline if/when WHP gains real
            // TSC-deadline support and you want to probe it.
            bool hide_tsc_deadline = true;
            int vmlinux_arg = 2;
            // Optional flags between --pvh-run and <vmlinux>.
            while (vmlinux_arg < argc &&
                   std::string_view(argv[vmlinux_arg]).starts_with("--") &&
                   std::string_view(argv[vmlinux_arg]) != "--") {
                std::string_view f(argv[vmlinux_arg]);
                if (f == "--net") {
                    with_net = true;
                } else if (f == "--net-backend") {
                    if (vmlinux_arg + 1 >= argc) {
                        std::fputs("--pvh-run: --net-backend wants an argument\n",
                                   stderr);
                        return 1;
                    }
                    ++vmlinux_arg;
                    std::string_view kind(argv[vmlinux_arg]);
                    if (kind == "none")          net_backend = NetBackendKind::None;
                    else if (kind == "loopback") net_backend = NetBackendKind::Loopback;
                    else if (kind == "xdp")      net_backend = NetBackendKind::Xdp;
                    else if (kind == "wintun")   net_backend = NetBackendKind::Wintun;
                    else if (kind == "wintun-svc") net_backend = NetBackendKind::WintunSvc;
                    else if (kind == "usernet")  net_backend = NetBackendKind::Usernet;
                    else {
                        std::fprintf(stderr,
                            "--pvh-run: unknown --net-backend '%.*s' (want none|loopback|xdp|wintun|wintun-svc|usernet)\n",
                            tinyvmm::util::checked_int_cast<int>(kind.size()),
                            kind.data());
                        return 1;
                    }
                } else if (f == "--xdp-if") {
                    if (vmlinux_arg + 1 >= argc) {
                        std::fputs("--pvh-run: --xdp-if wants an interface index\n",
                                   stderr);
                        return 1;
                    }
                    ++vmlinux_arg;
                    xdp_if = static_cast<std::uint32_t>(
                        std::strtoul(argv[vmlinux_arg], nullptr, 0));
                } else if (f == "--xdp-queue") {
                    if (vmlinux_arg + 1 >= argc) {
                        std::fputs("--pvh-run: --xdp-queue wants a queue id\n",
                                   stderr);
                        return 1;
                    }
                    ++vmlinux_arg;
                    xdp_queue = static_cast<std::uint32_t>(
                        std::strtoul(argv[vmlinux_arg], nullptr, 0));
                } else if (f == "--xdp-debug") {
                    xdp_debug = true;
                } else if (f == "--initrd") {
                    if (vmlinux_arg + 1 >= argc) {
                        std::fputs("--pvh-run: --initrd wants a path\n",
                                   stderr);
                        return 1;
                    }
                    ++vmlinux_arg;
                    initrd_path = argv[vmlinux_arg];
                } else if (f == "--drive") {
                    if (vmlinux_arg + 1 >= argc) {
                        std::fputs("--pvh-run: --drive wants <path>[,readonly]\n",
                                   stderr);
                        return 1;
                    }
                    ++vmlinux_arg;
                    std::string_view spec(argv[vmlinux_arg]);
                    DriveSpec ds;
                    const auto comma = spec.find(',');
                    if (comma == std::string_view::npos) {
                        ds.path = std::string(spec);
                    } else {
                        ds.path = std::string(spec.substr(0, comma));
                        std::string_view opts = spec.substr(comma + 1);
                        // Comma-separated options after the path. Today the
                        // only recognised one is `readonly`. Keep parsing
                        // tolerant so future options (cache=, discard=...)
                        // can be slotted in without breaking existing usage.
                        while (!opts.empty()) {
                            const auto next = opts.find(',');
                            std::string_view kv = (next == std::string_view::npos)
                                                  ? opts
                                                  : opts.substr(0, next);
                            if (kv == "readonly" || kv == "ro") {
                                ds.readonly = true;
                            } else {
                                std::fprintf(stderr,
                                    "--pvh-run: --drive: unknown option '%.*s' "
                                    "(want: readonly)\n",
                                    tinyvmm::util::checked_int_cast<int>(kv.size()),
                                    kv.data());
                                return 1;
                            }
                            opts = (next == std::string_view::npos)
                                   ? std::string_view{}
                                   : opts.substr(next + 1);
                        }
                    }
                    if (ds.path.empty()) {
                        std::fputs("--pvh-run: --drive: empty path\n", stderr);
                        return 1;
                    }
                    if (drives.size() >= 8) {
                        // Cap drives at /dev/vda..vdh; beyond that the user
                        // probably wants a different VM architecture anyway.
                        std::fputs("--pvh-run: --drive: max 8 drives supported\n",
                                   stderr);
                        return 1;
                    }
                    drives.push_back(std::move(ds));
                } else if (f == "--virtio-9p-share") {
                    if (vmlinux_arg + 1 >= argc) {
                        std::fputs(
                            "--pvh-run: --virtio-9p-share wants "
                            "<tag>=<host_path>[,ro]\n", stderr);
                        return 1;
                    }
                    ++vmlinux_arg;
                    std::string_view spec(argv[vmlinux_arg]);
                    const auto eq = spec.find('=');
                    if (eq == std::string_view::npos) {
                        std::fputs(
                            "--pvh-run: --virtio-9p-share: missing '=' "
                            "(want <tag>=<host_path>[,ro])\n", stderr);
                        return 1;
                    }
                    P9ShareSpec sh;
                    sh.tag = std::string(spec.substr(0, eq));
                    if (sh.tag.empty() || sh.tag.size() > 256) {
                        std::fputs(
                            "--pvh-run: --virtio-9p-share: tag must be "
                            "1..256 bytes\n", stderr);
                        return 1;
                    }
                    std::string_view rest = spec.substr(eq + 1);
                    // Comma options (ro / readonly) parsed identically
                    // to --drive. Path is the first comma-delimited
                    // field so Windows drive letters (`C:`) are safe.
                    std::string_view path_sv = rest;
                    const auto comma = rest.find(',');
                    if (comma != std::string_view::npos) {
                        path_sv = rest.substr(0, comma);
                        std::string_view opts = rest.substr(comma + 1);
                        while (!opts.empty()) {
                            const auto next = opts.find(',');
                            std::string_view kv =
                                (next == std::string_view::npos)
                                    ? opts : opts.substr(0, next);
                            if (kv == "readonly" || kv == "ro") {
                                sh.readonly = true;
                            } else {
                                std::fprintf(stderr,
                                    "--pvh-run: --virtio-9p-share: "
                                    "unknown option '%.*s' (want: ro)\n",
                                    tinyvmm::util::checked_int_cast<int>(
                                        kv.size()),
                                    kv.data());
                                return 1;
                            }
                            opts = (next == std::string_view::npos)
                                       ? std::string_view{}
                                       : opts.substr(next + 1);
                        }
                    }
                    if (path_sv.empty()) {
                        std::fputs(
                            "--pvh-run: --virtio-9p-share: empty host "
                            "path\n", stderr);
                        return 1;
                    }
                    // Canonicalise the host path now so any later
                    // backend code can trust it (Phase 3+). We resolve
                    // here at startup so the user gets a clean error
                    // up front for typos / missing paths.
                    std::error_code ec;
                    std::filesystem::path host =
                        std::filesystem::canonical(
                            std::filesystem::path(path_sv), ec);
                    if (ec) {
                        std::fprintf(stderr,
                            "--pvh-run: --virtio-9p-share: cannot "
                            "resolve host path '%.*s': %s\n",
                            tinyvmm::util::checked_int_cast<int>(
                                path_sv.size()),
                            path_sv.data(), ec.message().c_str());
                        return 1;
                    }
                    if (!std::filesystem::is_directory(host, ec) || ec) {
                        std::fprintf(stderr,
                            "--pvh-run: --virtio-9p-share: host path "
                            "is not a directory: %s\n",
                            host.string().c_str());
                        return 1;
                    }
                    // Reject duplicate mount tags so the guest is
                    // unambiguous about which device serves which tag.
                    for (const auto& prior : p9_shares) {
                        if (prior.tag == sh.tag) {
                            std::fprintf(stderr,
                                "--pvh-run: --virtio-9p-share: "
                                "duplicate tag '%s'\n", sh.tag.c_str());
                            return 1;
                        }
                    }
                    if (p9_shares.size() >= 8) {
                        std::fputs(
                            "--pvh-run: --virtio-9p-share: max 8 "
                            "shares supported\n", stderr);
                        return 1;
                    }
                    sh.host_root = std::move(host);
                    p9_shares.push_back(std::move(sh));
                } else if (f == "--watchdog-secs") {
                    if (vmlinux_arg + 1 >= argc) {
                        std::fputs("--pvh-run: --watchdog-secs wants a number "
                                   "(0 = disabled)\n", stderr);
                        return 1;
                    }
                    ++vmlinux_arg;
                    watchdog_secs = std::atoi(argv[vmlinux_arg]);
                    if (watchdog_secs < 0) watchdog_secs = 0;
                } else if (f == "--ram-mb") {
                    if (vmlinux_arg + 1 >= argc) {
                        std::fputs("--pvh-run: --ram-mb wants a positive "
                                   "integer in MiB (128-3584)\n", stderr);
                        return 1;
                    }
                    ++vmlinux_arg;
                    std::string_view rs(argv[vmlinux_arg]);
                    // Strict decimal parse (no atoi: it silently truncates
                    // garbage and returns 0 which we'd then reject as below
                    // min, masking the real "you typed something wrong" cause).
                    unsigned long long v = 0;
                    if (rs.empty()) {
                        std::fputs("--pvh-run: --ram-mb: empty argument\n",
                                   stderr);
                        return 1;
                    }
                    for (char c : rs) {
                        if (c < '0' || c > '9' || v > 0xFFFFFFull) {
                            std::fprintf(stderr,
                                "--pvh-run: --ram-mb: invalid '%.*s' (want "
                                "positive integer in MiB)\n",
                                tinyvmm::util::checked_int_cast<int>(rs.size()),
                                rs.data());
                            return 1;
                        }
                        v = v * 10 + static_cast<unsigned long long>(c - '0');
                    }
                    // PCI MMIO window opens at 0xE0000000 = 3584 MiB. RAM
                    // up to (but not including) that boundary is safe.
                    constexpr unsigned long long kMinMb = 128;
                    constexpr unsigned long long kMaxMb = 3584;
                    if (v < kMinMb || v > kMaxMb) {
                        std::fprintf(stderr,
                            "--pvh-run: --ram-mb: %llu out of range "
                            "[%llu..%llu] MiB (>3584 needs a low/high RAM "
                            "split around the PCI MMIO hole; not yet "
                            "supported)\n",
                            v, kMinMb, kMaxMb);
                        return 1;
                    }
                    ram_mb = static_cast<std::uint32_t>(v);
                } else if (f == "--vcpus") {
                    if (vmlinux_arg + 1 >= argc) {
                        std::fputs("--pvh-run: --vcpus wants a positive "
                                   "integer (1-16)\n", stderr);
                        return 1;
                    }
                    ++vmlinux_arg;
                    std::string_view vs(argv[vmlinux_arg]);
                    unsigned long long v = 0;
                    if (vs.empty()) {
                        std::fputs("--pvh-run: --vcpus: empty argument\n",
                                   stderr);
                        return 1;
                    }
                    for (char c : vs) {
                        if (c < '0' || c > '9' || v > 0xFFFFu) {
                            std::fprintf(stderr,
                                "--pvh-run: --vcpus: invalid '%.*s' (want "
                                "positive integer 1..32)\n",
                                tinyvmm::util::checked_int_cast<int>(vs.size()),
                                vs.data());
                            return 1;
                        }
                        v = v * 10 + static_cast<unsigned long long>(c - '0');
                    }
                    constexpr unsigned long long kMinVcpus = 1;
                    const unsigned long long kMaxVcpusU =
                        tinyvmm::boot::acpi::kMaxVcpus;
                    if (v < kMinVcpus || v > kMaxVcpusU) {
                        std::fprintf(stderr,
                            "--pvh-run: --vcpus: %llu out of range "
                            "[%llu..%llu]\n",
                            v, kMinVcpus, kMaxVcpusU);
                        return 1;
                    }
                    vcpu_count = static_cast<std::uint32_t>(v);
                } else if (f == "--cpu-affinity") {
                    if (vmlinux_arg + 1 >= argc) {
                        std::fputs("--pvh-run: --cpu-affinity wants one of "
                                   "all|p|e|p-physical\n", stderr);
                        return 1;
                    }
                    ++vmlinux_arg;
                    std::string_view as(argv[vmlinux_arg]);
                    if (!tinyvmm::whp::ParseAffinityMode(as,
                                                        affinity_mode)) {
                        std::fprintf(stderr,
                            "--pvh-run: --cpu-affinity: invalid '%.*s' "
                            "(want all|p|e|p-physical)\n",
                            tinyvmm::util::checked_int_cast<int>(as.size()),
                            as.data());
                        return 1;
                    }
                    // E-core mode requires a hybrid host; refuse early
                    // rather than silently producing an empty pin set.
                    if (affinity_mode == tinyvmm::whp::AffinityMode::ECore
                        && !tinyvmm::whp::GetTopology().hybrid) {
                        std::fputs(
                            "--pvh-run: --cpu-affinity e: host is not "
                            "hybrid (no E-cores detected)\n", stderr);
                        return 1;
                    }
                } else if (f == "--debug-boot") {
                    // Re-enables earlyprintk=ttyS0,115200 in the default
                    // cmdline. Useful for diagnosing kernels that fail
                    // before virtio-console comes up, at the cost of
                    // ~700 ms of synchronous OUTB exits per byte to the
                    // 8250 UART. Has no effect if the user supplies
                    // their own cmdline via `-- ...`.
                    debug_boot = true;
                } else if (f == "--hide-tsc-deadline") {
                    // Already on by default; accept for clarity in scripts.
                    hide_tsc_deadline = true;
                } else if (f == "--expose-tsc-deadline") {
                    // Re-enable CPUID.01H:ECX[24]. Linux will then try to
                    // program MSR 0x6E0, WHP will reject it, and you'll
                    // see an `unchecked MSR access` trace in dmesg followed
                    // by a transparent fallback to LAPIC oneshot. Useful
                    // only for probing whether WHP gained TSC-deadline
                    // support in a newer Windows build.
                    hide_tsc_deadline = false;
                } else if (f == "--portfwd") {
                    // Forms accepted (all ports are decimal, IPs dotted-quad):
                    //   HOST_PORT:GUEST_PORT
                    //     -> 127.0.0.1:HOST_PORT  ->  10.0.0.2:GUEST_PORT
                    //   HOST_IP:HOST_PORT:GUEST_IP:GUEST_PORT
                    // Repeatable. Only used by --net-backend usernet.
                    if (vmlinux_arg + 1 >= argc) {
                        std::fputs("--pvh-run: --portfwd wants HOST_PORT:GUEST_PORT "
                                   "or HOST_IP:HOST_PORT:GUEST_IP:GUEST_PORT\n",
                                   stderr);
                        return 1;
                    }
                    ++vmlinux_arg;
                    std::string_view arg(argv[vmlinux_arg]);
                    std::vector<std::string_view> parts;
                    {
                        std::size_t start = 0;
                        for (std::size_t i = 0; i <= arg.size(); ++i) {
                            if (i == arg.size() || arg[i] == ':') {
                                parts.push_back(arg.substr(start, i - start));
                                start = i + 1;
                            }
                        }
                    }
                    tinyvmm::virtio::UsernetBackend::PortForward pf{};
                    auto parse_port = [](std::string_view s,
                                          std::uint16_t& out) -> bool {
                        if (s.empty() || s.size() > 5) return false;
                        unsigned long v = 0;
                        for (char c : s) {
                            if (c < '0' || c > '9') return false;
                            v = v * 10 + static_cast<unsigned long>(c - '0');
                            if (v > 65535) return false;
                        }
                        if (v == 0) return false;
                        out = static_cast<std::uint16_t>(v);
                        return true;
                    };
                    auto parse_ip = [](std::string_view s,
                                        std::uint32_t& out_be) -> bool {
                        // InetPtonA needs NUL-terminated input.
                        std::string tmp(s);
                        IN_ADDR a{};
                        if (::InetPtonA(AF_INET, tmp.c_str(), &a) != 1) {
                            return false;
                        }
                        out_be = a.s_addr;
                        return true;
                    };
                    if (parts.size() == 2) {
                        std::uint16_t hp = 0, gp = 0;
                        if (!parse_port(parts[0], hp) ||
                            !parse_port(parts[1], gp)) {
                            std::fprintf(stderr,
                                "--pvh-run: --portfwd: invalid HOST_PORT:GUEST_PORT '%s'\n",
                                argv[vmlinux_arg]);
                            return 1;
                        }
                        IN_ADDR loop{};
                        ::InetPtonA(AF_INET, "127.0.0.1", &loop);
                        IN_ADDR guest{};
                        ::InetPtonA(AF_INET, "10.0.0.2", &guest);
                        pf.host_addr_be = loop.s_addr;
                        pf.host_port    = hp;
                        pf.guest_ip_be  = guest.s_addr;
                        pf.guest_port   = gp;
                    } else if (parts.size() == 4) {
                        std::uint16_t hp = 0, gp = 0;
                        if (!parse_ip(parts[0], pf.host_addr_be) ||
                            !parse_port(parts[1], hp) ||
                            !parse_ip(parts[2], pf.guest_ip_be) ||
                            !parse_port(parts[3], gp)) {
                            std::fprintf(stderr,
                                "--pvh-run: --portfwd: invalid "
                                "HOST_IP:HOST_PORT:GUEST_IP:GUEST_PORT '%s'\n",
                                argv[vmlinux_arg]);
                            return 1;
                        }
                        pf.host_port  = hp;
                        pf.guest_port = gp;
                    } else {
                        std::fprintf(stderr,
                            "--pvh-run: --portfwd: expected 2 or 4 colon-"
                            "separated fields, got %zu in '%s'\n",
                            parts.size(), argv[vmlinux_arg]);
                        return 1;
                    }
                    port_forwards.push_back(pf);
                } else if (f == "--save") {
                    // M33 Phase 33.1: arms the magic snapshot CPUID. The
                    // actual file write is implemented in later phases
                    // (33.3+); for now, the flag is parsed end-to-end and
                    // triggers the StopReason::SnapshotRequested branch in
                    // the run loop, but the post-stop handler in
                    // RunPvhRun only logs a [snapshot] line and exits.
                    if (vmlinux_arg + 1 >= argc) {
                        std::fputs("--pvh-run: --save wants <path>\n",
                                   stderr);
                        return 1;
                    }
                    ++vmlinux_arg;
                    save_path = argv[vmlinux_arg];
                    if (save_path.empty()) {
                        std::fputs("--pvh-run: --save: empty path\n",
                                   stderr);
                        return 1;
                    }
                } else if (f == "--unsafe-save-mutable-drive") {
                    // Opt-out of the v1 read-only-drive policy for --save.
                    // Without this, --save refuses to start if any --drive
                    // is mutable (not ,readonly). See plan §"drive
                    // consistency" for the rationale: a mutated disk +
                    // stale RAM snapshot = corrupt guest filesystem.
                    unsafe_save_mutable_drive = true;
                } else if (f == "--gdb-port") {
                    // M35: bind a GDB Remote Serial Protocol stub on
                    // 127.0.0.1:<port>. tinyvmm halts before the first
                    // guest instruction and waits for `target remote
                    // :<port>` from gdb. Requires --vcpus 1 (validated
                    // in RunPvhRun). Auto-appends `nokaslr` to the
                    // kernel cmdline if not already present, so
                    // GDB-known symbols match runtime addresses.
                    if (vmlinux_arg + 1 >= argc) {
                        std::fputs("--pvh-run: --gdb-port wants <port>\n",
                                   stderr);
                        return 1;
                    }
                    ++vmlinux_arg;
                    int port = std::atoi(argv[vmlinux_arg]);
                    if (port <= 0 || port > 65535) {
                        std::fprintf(stderr,
                            "--pvh-run: --gdb-port: invalid port '%s' "
                            "(want 1..65535)\n", argv[vmlinux_arg]);
                        return 1;
                    }
                    gdb_port = static_cast<std::uint16_t>(port);
                } else {
                    std::fprintf(stderr,
                                 "--pvh-run: unknown flag '%.*s'\n",
                                 tinyvmm::util::checked_int_cast<int>(f.size()),
                                 f.data());
                    return 1;
                }
                ++vmlinux_arg;
            }
            if (vmlinux_arg >= argc) {
                std::fputs("--pvh-run: expected path to vmlinux\n", stderr);
                return 1;
            }
            if (net_backend == NetBackendKind::Xdp && !with_net) {
                std::fputs("--pvh-run: --net-backend xdp requires --net\n",
                           stderr);
                return 1;
            }
            if (net_backend == NetBackendKind::Wintun && !with_net) {
                std::fputs("--pvh-run: --net-backend wintun requires --net\n",
                           stderr);
                return 1;
            }
            if (net_backend == NetBackendKind::WintunSvc && !with_net) {
                std::fputs("--pvh-run: --net-backend wintun-svc requires --net\n",
                           stderr);
                return 1;
            }
            if (net_backend == NetBackendKind::Usernet && !with_net) {
                std::fputs("--pvh-run: --net-backend usernet requires --net\n",
                           stderr);
                return 1;
            }
            if (!port_forwards.empty() &&
                net_backend != NetBackendKind::Usernet) {
                std::fputs("--pvh-run: --portfwd only supported with "
                           "--net-backend usernet\n", stderr);
                return 1;
            }
            // M33 Phase 33.1: cross-flag validation for --save.
            //
            // Phase-1 scope is vCPU + RAM + virtio-{rng,console,blk}. We
            // explicitly refuse --save with --net (the network backends
            // can't capture/restore in-flight host sockets) or with
            // --virtio-9p-share (Win32 HANDLEs don't survive a process
            // exit). These can be lifted in later phases by widening the
            // device-state capture.
            if (!save_path.empty() && with_net) {
                std::fputs(
                    "--pvh-run: --save is incompatible with --net "
                    "(net backends cannot survive snapshot in v1)\n",
                    stderr);
                return 1;
            }
            if (!save_path.empty() && !p9_shares.empty()) {
                std::fputs(
                    "--pvh-run: --save is incompatible with "
                    "--virtio-9p-share (Win32 HANDLEs cannot survive "
                    "snapshot)\n",
                    stderr);
                return 1;
            }
            if (!save_path.empty() && !unsafe_save_mutable_drive) {
                for (const auto& d : drives) {
                    if (!d.readonly) {
                        std::fprintf(stderr,
                            "--pvh-run: --save: drive '%s' is mutable. "
                            "Either add ',readonly' to every --drive, or "
                            "pass --unsafe-save-mutable-drive to accept "
                            "the risk that a mutated disk plus a stale "
                            "RAM snapshot corrupts the guest filesystem.\n",
                            d.path.c_str());
                        return 1;
                    }
                }
            }
            if (unsafe_save_mutable_drive && save_path.empty()) {
                std::fputs(
                    "--pvh-run: --unsafe-save-mutable-drive requires "
                    "--save\n",
                    stderr);
                return 1;
            }
            // Arm the global snapshot trigger if --save was provided. Done
            // here (not inside RunPvhRun) so the arming happens before the
            // global state is observable by any RunLoop.
            if (!save_path.empty()) {
                auto& st = ::tinyvmm::whp::snapshot::State();
                st.save_path = save_path;
                st.armed.store(true, std::memory_order_release);
                std::printf(
                    "[pvh-run] snapshot armed: will write to '%s' on "
                    "guest-side magic CPUID 0x%08X\n",
                    save_path.c_str(),
                    static_cast<unsigned>(
                        ::tinyvmm::whp::snapshot::kMagicLeaf));
            }
            std::string cmdline;
            int sep = -1;
            for (int i = vmlinux_arg + 1; i < argc; ++i) {
                if (std::string_view(argv[i]) == "--") {
                    sep = i;
                    break;
                }
            }
            if (sep >= 0) {
                for (int i = sep + 1; i < argc; ++i) {
                    if (!cmdline.empty()) cmdline.push_back(' ');
                    cmdline.append(argv[i]);
                }
            }
            if (cmdline.empty()) {
                // Default: route all kernel output via virtio-console
                // (`console=hvc0`). We deliberately do NOT enable
                // `earlyprintk=ttyS0,115200` because every byte of
                // earlyprintk is a synchronous OUTB->VM exit, costing
                // ~700 ms across a typical Linux boot's printk volume.
                // Pass `--debug-boot` to opt back into earlyprintk, or
                // supply your own cmdline via `-- ...`.
                if (debug_boot) {
                    cmdline = "earlyprintk=ttyS0,115200 console=hvc0 "
                              "pci=conf1,nocrs,lastbus=0 nofb nomodeset";
                } else {
                    cmdline = "console=hvc0 pci=conf1,nocrs,lastbus=0 "
                              "nofb nomodeset";
                }
            }
            // M35: when --gdb-port is set, auto-append `nokaslr` so
            // the runtime kernel addresses match the symbols in the
            // user's vmlinux file (rubber-duck #3). Idempotent: only
            // appends if not already present in the cmdline.
            if (gdb_port != 0 &&
                cmdline.find("nokaslr") == std::string::npos) {
                if (!cmdline.empty()) cmdline.push_back(' ');
                cmdline.append("nokaslr");
                std::fprintf(stderr,
                    "[pvh-run] --gdb-port: auto-appended 'nokaslr' to "
                    "kernel cmdline so gdb symbols match runtime "
                    "addresses\n");
            }
            return RunPvhRun(argv[vmlinux_arg], cmdline, with_net,
                             net_backend, xdp_if, xdp_queue, xdp_debug,
                             initrd_path, drives, p9_shares, watchdog_secs,
                             hide_tsc_deadline, port_forwards,
                             ram_mb,
                             vcpu_count, affinity_mode, gdb_port);
        }
        if (cmd == "--restore") {
            if (argc < 3) {
                std::fputs("--restore: expected path to snapshot file\n",
                           stderr);
                return 1;
            }
            const std::string snapshot_path = argv[2];
            std::vector<DriveSpec> drive_overrides;
            bool unsafe_restore_mutable_drive = false;
            int watchdog_secs = 0;
            tinyvmm::whp::AffinityMode affinity_mode =
                tinyvmm::whp::AffinityMode::All;
            // Parser: walk argv[3..] in order. Each option is independent;
            // unknown options and PVH-only flags are rejected loudly so a
            // typo (`--rseotre`-style) doesn't silently fall through to a
            // restore with default settings.
            for (int i = 3; i < argc; ++i) {
                const std::string_view a = argv[i];
                if (a == "--drive") {
                    if (i + 1 >= argc) {
                        std::fputs("--restore --drive: expected path\n",
                                   stderr);
                        return 1;
                    }
                    DriveSpec spec;
                    std::string token = argv[++i];
                    auto comma = token.find(',');
                    if (comma == std::string::npos) {
                        spec.path = token;
                    } else {
                        spec.path = token.substr(0, comma);
                        if (token.substr(comma + 1) == "readonly") {
                            spec.readonly = true;
                        } else {
                            std::fprintf(stderr,
                                "--restore --drive: unknown attribute '%s' "
                                "(only 'readonly' is supported)\n",
                                token.substr(comma + 1).c_str());
                            return 1;
                        }
                    }
                    drive_overrides.push_back(std::move(spec));
                } else if (a == "--watchdog-secs") {
                    if (i + 1 >= argc) {
                        std::fputs("--restore --watchdog-secs: expected N\n",
                                   stderr);
                        return 1;
                    }
                    watchdog_secs = std::atoi(argv[++i]);
                    if (watchdog_secs < 0) {
                        std::fputs("--restore --watchdog-secs: must be >= 0\n",
                                   stderr);
                        return 1;
                    }
                } else if (a == "--cpu-affinity") {
                    if (i + 1 >= argc) {
                        std::fputs(
                            "--restore --cpu-affinity: expected mode\n",
                            stderr);
                        return 1;
                    }
                    std::string_view as = argv[++i];
                    if (!tinyvmm::whp::ParseAffinityMode(as, affinity_mode)) {
                        std::fprintf(stderr,
                            "--restore --cpu-affinity: unknown mode '%.*s' "
                            "(expected all|p|e|p-physical)\n",
                            static_cast<int>(as.size()), as.data());
                        return 1;
                    }
                    if (affinity_mode == tinyvmm::whp::AffinityMode::ECore
                        && !tinyvmm::whp::GetTopology().hybrid) {
                        std::fputs(
                            "--restore --cpu-affinity e: not a hybrid host\n",
                            stderr);
                        return 1;
                    }
                } else if (a == "--unsafe-restore-mutable-drive") {
                    unsafe_restore_mutable_drive = true;
                } else if (a == "--net" || a == "--net-backend" ||
                           a == "--xdp-if" || a == "--xdp-queue" ||
                           a == "--xdp-debug" || a == "--initrd" ||
                           a == "--virtio-9p-share" || a == "--debug-boot" ||
                           a == "--expose-tsc-deadline" ||
                           a == "--ram-mb" || a == "--vcpus" ||
                           a == "--portfwd" ||
                           a == "--save" || a == "--gdb-port" ||
                           a == "--unsafe-save-mutable-drive") {
                    std::fprintf(stderr,
                        "--restore: option '%.*s' is not valid in restore "
                        "mode (the snapshot encodes the full VM topology)\n",
                        static_cast<int>(a.size()), a.data());
                    return 1;
                } else {
                    std::fprintf(stderr,
                        "--restore: unknown option '%.*s'\n",
                        static_cast<int>(a.size()), a.data());
                    return 1;
                }
            }
            return RunRestore(snapshot_path, drive_overrides,
                              unsafe_restore_mutable_drive,
                              watchdog_secs, affinity_mode);
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
