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
#include "host/block_file.h"
#include "host/privilege.h"
#include "host/xdp_probe.h"
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
#include "whp/cpu_affinity.h"
#include "whp/cpuid.h"
#include "whp/hv_enlightenment.h"
#include "whp/memory.h"
#include "whp/msi.h"
#include "whp/notification_port.h"
#include "whp/partition.h"
#include "whp/run_loop.h"
#include "whp/vcpu.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <span>
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
        "  tinyvmm --loop-test               Run loop + IO dispatch test\n"
        "  tinyvmm --uart-test               Drive the 8250 from real mode\n"
        "  tinyvmm --virtio-test             Drive virtio-mmio + virtq from host\n"
        "  tinyvmm --doorbell-test           Verify WHP MMIO doorbell suppresses exits\n"
        "  tinyvmm --pci-test                Exercise the PCI host bridge + BAR sizing\n"
        "  tinyvmm --msix-test               Host-side MSI-X cap + table + PBA + mask/replay\n"
        "  tinyvmm --msix-inject-test        Drive WHvRequestInterrupt into a guest IDT\n"
        "  tinyvmm --virtio-pci-test         Host-side virtio-PCI modern transport\n"
        "  tinyvmm --virtio-blk-test         Host-side virtio-blk via IOCP backend\n"
        "  tinyvmm --virtio-blk-ro-test      Backend readonly reject path (OpWrite rejected)\n"
        "  tinyvmm --virtio-net-pci-test     Host-side virtio-net on the PCI transport\n"
        "  tinyvmm --virtio-net-loopback-test Echo a TX packet back as RX via LoopbackNetBackend\n"
        "  tinyvmm --virtio-rng-test         Host-side virtio-rng + CNG entropy source\n"
        "  tinyvmm --virtio-console-test     Host-side virtio-console transmitq drain\n"
        "  tinyvmm --cpuid-test              Verify CPUID resolver policy (M18 time hygiene)\n"
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
        "                   <vmlinux> [-- <kernel cmdline...>]\n"
        "                                    Load and run a PVH kernel\n"
        "                                    --drive may be repeated; drive N appears as /dev/vd<a+N>\n"
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
                  tinyvmm::whp::AffinityMode::All) {
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

    Partition part(vcpu_count);
    // Enable CPUID + MSR exits. CPUID lets us layer tinyvmm policy
    // (advertise invariant_tsc, ARAT, TSC frequency, Hyper-V vendor/iface)
    // on top of WHP's host-passthrough defaults. MSR lets us service the
    // Hyper-V Reference TSC page + TSC-invariant-control MSRs that Linux
    // writes once it detects Hyper-V via the CPUID leaves. See
    // `whp/cpuid.cpp` and `whp/hv_enlightenment.cpp`.
    part.EnableExtendedExits({.cpuid = true, .msr = true});
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
    // Phase 1: Tversion + Tattach implemented; everything else returns
    // Rlerror(ENOSYS). Phase 2+ will implement the file ops.
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
                    "(virtio in=%llu out=%llu flush=%llu err=%llu)\n",
                    i,
                    static_cast<unsigned long long>(b->submitted()),
                    static_cast<unsigned long long>(b->completed()),
                    static_cast<unsigned long long>(b->errors()),
                    static_cast<unsigned long long>(b->max_inflight()),
                    static_cast<unsigned long long>(d->ops_in()),
                    static_cast<unsigned long long>(d->ops_out()),
                    static_cast<unsigned long long>(d->ops_flush()),
                    static_cast<unsigned long long>(d->ops_err()));
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
        if (cmd == "--virtio-net-pci-test") {
            return RunVirtioNetPciTest();
        }
        if (cmd == "--virtio-net-loopback-test") {
            return RunVirtioNetLoopbackTest();
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
            return RunPvhRun(argv[vmlinux_arg], cmdline, with_net,
                             net_backend, xdp_if, xdp_queue, xdp_debug,
                             initrd_path, drives, p9_shares, watchdog_secs,
                             hide_tsc_deadline, port_forwards, ram_mb,
                             vcpu_count, affinity_mode);
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
