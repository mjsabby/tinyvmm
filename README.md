# tinyvmm

A tiny user-mode virtual machine monitor on Windows that runs 64-bit Linux
kernels using the **Windows Hypervisor Platform** APIs and **XDP for Windows**
as the network back-end.

## Status

M0 (in progress): partition bring-up, vCPU lifecycle, real-mode HLT smoke test.

See [docs design notes / VM-exit hot-path analysis] in the session plan.

## Build prerequisites

- Windows 11 / Windows Server 2022 with the **Hyper-V Platform** Windows
  feature enabled (`Add-WindowsCapability -Online -Name Microsoft-Hyper-V`
  on Server, "Windows Hypervisor Platform" in *Turn Windows Features On or
  Off* on client).
- **Visual Studio 2022** (build tools or Community).
- **Windows SDK 10.0.26100** or newer (for `WinHvPlatform.h`).
- **CMake 3.20+** (any generator; Ninja recommended).
- **XDP for Windows** public headers are vendored under
  `third_party/xdp-for-windows/published/external` (see that directory's
  `README.md` for provenance / refresh recipe). Override `-DXDP_ROOT=...`
  to build against a different checkout.

### Recommended (large pages)

Guest RAM is allocated with `MEM_LARGE_PAGES` (2 MiB) when possible. This lets
Hyper-V back the EPT/SLAT mappings with 2 MiB super-pages, which reduces TLB
pressure and second-level page-walk cost on the hot networking path. To enable:

1. `gpedit.msc` -> Computer Configuration -> Windows Settings -> Security
   Settings -> Local Policies -> User Rights Assignment ->
   **"Lock pages in memory"** -> add your user account.
2. Sign out and back in (privileges attach at logon).
3. Run `tinyvmm --smoke`; the output should report `MEM_LARGE_PAGES` instead of
   `4 KiB pages`.

If the privilege is not held, tinyvmm falls back to 4 KiB pages with a warning
on stderr. Functional but slower.

### Guest RAM size (`--ram-mb`)

`--pvh-run --ram-mb <N>` sizes guest RAM in MiB (default 256, min 128, max
3584). The upper bound is hard: the PCI MMIO BAR window opens at `0xE0000000`
(3584 MiB), so any larger contiguous region would collide with virtio
device registers. Guests larger than 3584 MiB require a low/high RAM split
around the MMIO hole, which tinyvmm does not yet implement.

```cmd
.\build\bin\tinyvmm.exe --pvh-run --ram-mb 2048 ^
    --initrd initramfs.cpio vmlinux
```

### Multi-vCPU (`--vcpus`)

`--pvh-run --vcpus <N>` allocates `N` virtual CPUs (default 1, max 32).
The BSP (vCPU 0) always runs on the main thread; each AP (vCPU 1..N-1)
runs on its own host thread so vCPUs execute concurrently.

```cmd
.\build\bin\tinyvmm.exe --pvh-run --vcpus 4 ^
    --initrd initramfs.cpio vmlinux
```

At startup the VMM publishes an ACPI MADT with one Type-9 x2APIC entry
per vCPU (Local APIC ID == vCPU index). APs are created in WAIT_FOR_SIPI
state; Linux's SMP bring-up sends INIT+SIPI through the LAPIC and the
WHP in-hypervisor LAPIC services it without bubbling up.

**N=1 startup cost is unchanged**: when `--vcpus 1` (the default) no AP
threads are spawned. Per-component mutexes added for AP safety are
uncontested at N=1 and cost ~10-20 ns each. Measured boot time
(entering guest → /init complete) is **298 ms ± 5 ms at N=1, N=2,
and N=4** on this box -- all three within noise of each other.

**Guest kernel must be SMP-aware to actually use the APs.** Required
kernel config:

```
CONFIG_SMP=y
CONFIG_NR_CPUS=32             # or whatever upper bound you need
CONFIG_ACPI=y                 # tinyvmm uses ACPI MADT to advertise APs
CONFIG_X86_X2APIC=y           # recommended (MADT emits Type-9 x2APIC only).
```

Without `CONFIG_SMP=y` Linux ignores everything past CPU 0 and APs sit
idle in WAIT_FOR_SIPI. Without `CONFIG_ACPI=y` Linux logs
`APIC: ACPI MADT or MP tables are not detected` and falls back to
virtual-wire / uniprocessor mode. (tinyvmm emits ACPI tables only, not
Intel MP-Spec floating tables, so ACPI is the only discovery path.)

### CPU affinity (`--cpu-affinity`)

`--pvh-run --cpu-affinity {all|p|e|p-physical}` restricts every vCPU
thread (BSP + APs) to a subset of the host's logical processors via
`SetThreadSelectedCpuSets`. Default: `all` (no pinning).

| Mode | What gets included |
|------|--------------------|
| `all` | No pinning. Windows scheduler is free to use any logical CPU. |
| `p` | All P-core logical processors, **including SMT siblings**. |
| `p-physical` | One logical per P-core (drops SMT siblings). Lowest contention; highest single-thread perf. |
| `e` | All E-core logical processors. Refused on non-hybrid hosts. |

On hybrid Intel CPUs (Alder/Raptor Lake) detection uses
`GetSystemCpuSetInformation`'s `EfficiencyClass` (`0` = E, `≥1` = P).
On non-hybrid hosts `p` resolves to every logical CPU, `e` is refused,
and `p-physical` drops SMT siblings.

```cmd
.\build\bin\tinyvmm.exe --pvh-run --vcpus 8 --cpu-affinity p ^
    --initrd initramfs.cpio vmlinux
```

**Why pin?** On hybrid CPUs Linux's `clocksource_watchdog` historically
marked TSC unstable once vCPU threads bounced across P-core and E-core
boundaries. tinyvmm now exposes itself as a Hyper-V guest and implements
the TSC-invariant + Reference-TSC-page enlightenment (see "Time
enlightenment" below), which silences the watchdog under any vCPU
scheduling pattern -- pinning is no longer required for clock stability.
It remains useful for predictable performance (avoiding cross-class
latency jitter) and for keeping vCPU threads off any logicals already
under load.

### Time enlightenment

RDTSC is **not** intercepted and runs natively on the host TSC. tinyvmm
additionally advertises a Hyper-V CPUID interface ("Microsoft Hv" /
"Hv#1") and implements four MSRs that Linux uses for time-keeping:

- `HV_X64_MSR_REFERENCE_TSC` (`0x40000021`): publishes a 4 KiB Reference
  TSC page filled with `tsc_scale = (10^7 << 64) / tsc_hz` so Linux's
  `read_hv_clock_tsc()` reads 100 ns ticks from the host TSC with one
  multiply-and-shift -- no exits.
- `HV_X64_MSR_TSC_INVARIANT_CONTROL` (`0x40000118`): driving this triggers
  Linux's `setup_force_cpu_cap(X86_FEATURE_TSC_RELIABLE)`, which disables
  the clocksource watchdog for TSC entirely. With this in place Linux
  keeps `current_clocksource=tsc` even under heavy multi-vCPU load,
  including N=32 vCPUs each spinning a busy loop for 20+ seconds.
- `HV_X64_MSR_TIME_REF_COUNT` (`0x40000020`): served live from
  `(rdtsc * tsc_scale) >> 64` as the fallback path when the Reference
  TSC page's sequence number reads zero.
- `HV_X64_MSR_VP_INDEX` (`0x40000002`): per-vCPU index for percpu-init.
- `HV_X64_MSR_GUEST_OS_ID` (`0x40000000`) and `HV_X64_MSR_HYPERCALL`
  (`0x40000001`) are accepted; the hypercall page is filled with a
  6-byte `mov eax, 2; ret` stub so any never-quite-issued hypercall
  returns `HV_STATUS_INVALID_HYPERCALL_CODE` instead of executing
  garbage. We deliberately do not implement any actual hypercalls.

No `tsc=reliable` kernel cmdline workaround is needed. Verified on Linux
7.0 with `CONFIG_SMP=y` + `CONFIG_HYPERVISOR_GUEST=y` (the only kernel
flag required -- enabled by default on virtually every distro).

## Build

```powershell
cmake -S . -B build -G "Ninja Multi-Config"
cmake --build build --config RelWithDebInfo
.\build\bin\tinyvmm.exe --smoke
```

The `--smoke` flag runs a minimal test: create a partition, map 1 MiB of guest
RAM at GPA 0, drop a `HLT` opcode at the reset vector, run the vCPU and verify
we get a `WHvRunVpExitReasonX64Halt` exit. Useful for confirming the WHP stack
is functional on the host.

## Booting unmodified Ubuntu (live-server ISO)

tinyvmm is PVH-only — there is no BIOS, no UEFI, and no boot-sector code
path. Distro install ISOs assume GRUB and a firmware/disk boot, so they
won't boot directly. The `tools/ubuntu_iso_boot.py` helper adapts the
Ubuntu live-server amd64 ISO into a PVH-friendly shape and launches
tinyvmm:

```powershell
# Subiquity (text TUI installer) over hvc0.
python tools\ubuntu_iso_boot.py `
    --iso .\ubuntu-24.04.3-live-server-amd64.iso `
    --disk .\install.img --disk-size-gb 16 `
    --ram-mb 3072 --vcpus 2
```

What it does:

1. Mounts the ISO via PowerShell `Mount-DiskImage` (no admin needed).
2. Copies `casper/vmlinuz` + `casper/initrd` to a workspace under
   `%TEMP%`.
3. Dismounts the ISO.
4. Decompresses the bzImage to the raw inner ELF (the kernel build
   embeds the compressed vmlinux behind a small setup header; we
   scan for `gzip`/`xz`/`bz2`/`zstd`/`lzma-alone` frame magic and
   stream-decompress at each match — Ubuntu 22.04+ uses zstd in
   streaming mode without `Frame_Content_Size`, so we use the
   streaming decompressor class).
5. Creates the target disk as a genuinely sparse NTFS file (logical
   size = `--disk-size-gb`, on-disk usage starts at zero and grows
   only as the installer writes).
6. Launches tinyvmm with two virtio-blk drives — the ISO mounted
   read-only as `/dev/vda` (so casper finds its
   `casper/filesystem.squashfs`) and the install target as
   `/dev/vdb` — plus a virtio-net backend (default `usernet` so
   the installer can fetch apt mirrors without any host network
   config) and a cmdline of `console=hvc0 boot=casper
   live-media=/dev/vda pci=conf1,nocrs,lastbus=0 nofb nomodeset
   fsck.mode=skip ipv6.disable=1`.

The subiquity TUI lands on hvc0 via the virtio-console device; host
stdin is forwarded as the keyboard. RAM defaults to 3 GiB because
subiquity + snap + squashfs overlay needs ~2 GiB minimum.

For an unattended install with cloud-init `user-data`, pass the
extra cmdline through:

```powershell
python tools\ubuntu_iso_boot.py --iso ... --disk ... `
    --cmdline-extra "autoinstall ds=nocloud;s=http://10.0.2.2/"
```

(seeding the cloud-init source is the user's responsibility.)

## Observability

tinyvmm emits **ETW TraceLogging** events plus a per-shutdown summary of
WHV exit counters. There is no manifest registration step; events are
captured by GUID.

### Provider

| Field | Value |
|-------|-------|
| Name  | `Tinyvmm-Core` |
| GUID  | `{0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d}` |

### Keyword taxonomy

Each event is tagged with one keyword bit. Use the bitmask to enable only
the volume you need; pass it as the `-matchanykw` argument to
`tracelog`, the `-Keywords` argument to `wpr`/`logman`, or the equivalent
field in any other ETW controller.

| Bit       | Name        | Approx. volume               | Examples |
|-----------|-------------|------------------------------|----------|
| `0x0001`  | `VmExit`    | very high (per WHV exit)     | `VmExit` |
| `0x0002`  | `Doorbell`  | medium                       | (reserved for doorbell-latency events) |
| `0x0004`  | `Virtio`    | medium                       | (reserved for queue pop/push) |
| `0x0008`  | `Net`       | per-packet                   | `NetTx`, `NetRx`, `NetTxDrop` |
| `0x0010`  | `Mmio`      | high                         | `Mmio` |
| `0x0020`  | `Io`        | high                         | `Io` |
| `0x0040`  | `Boot`      | one-shot                     | `BootMark` |
| `0x0080`  | `Lifecycle` | very low                     | `VmStart`, `VmStop`, `NetBackendStart`, `NetBackendStop` |
| `0x0100`  | `Block`     | per virtio-blk request       | `BlkSubmit`, `BlkComplete` |
| `0x0200`  | `Cpuid`     | one per CPUID exit           | `Cpuid` |
| `0x0400`  | `Msi`       | per MSI inject               | `MsiInject` |

To capture only lifecycle + boot events:
`-matchanykw 0xC0` (Boot `0x40` | Lifecycle `0x80`).

### Capture recipes

**`tracelog` one-shot capture** — Boot + Lifecycle + Net at verbose:

```cmd
tracelog -start tinyvmm -guid #0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d ^
         -level 5 -matchanykw 0xC8 -f tinyvmm.etl
.\build\bin\tinyvmm.exe --pvh-run --net --net-backend usernet .\vmlinux
tracelog -stop tinyvmm
tracerpt tinyvmm.etl -o tinyvmm.csv -of CSV
```

**WPR** with a recording profile (`tools/tinyvmm.wprp`):

```cmd
wpr -start tools\tinyvmm.wprp -filemode
... run workload ...
wpr -stop tinyvmm.etl
```

**PerfView** with a stack-walk hint over every Net event:

```cmd
PerfView /providers="*Tinyvmm-Core:0xC8:5" ^
         /onlyproviders /buffersize=4096 /stackcompression=on ^
         collect tinyvmm.etl
```

Replace `0xC8` with the keyword mask you need. Set the level (`5` =
verbose) lower to drop per-exit chatter while keeping warnings/errors.

### Exit counters

Every `--pvh-run` shutdown prints a one-line summary covering all
twelve WHV exit reasons (and emits a `RunLoopStats` ETW event):

```
[loop] exits: total=2431 io=1551 mmio=413 halt=0 cpuid=466 ...
```

Useful for spotting which exits dominate a workload without an ETW
capture.

### Suggested next instrumentation hooks

These call sites are intentionally not yet wired so that the default
event mix stays compact; add them as needed during specific
investigations:

- Doorbell signal/wake latency (TSC ticks)
- Virtio queue depth (avail head - last_used distance)
- Virtio-blk per-request latency (submit → complete)
- Wintun ring fill level
- XDP ring fill level when the XDP backend is active
- Guest console bytes in/out

## Diagnostics

The binary exposes a few zero-VM diagnostic subcommands. Most need
admin privileges (XDP and Wintun device handles are SDDL-protected).

```text
tinyvmm --xdp-probe              # probe every host NIC: native/generic/RSS caps
tinyvmm --xdp-probe <IfIndex>    # verbose deep dive on one NIC
tinyvmm --wintun-probe [secs]    # bring up a Wintun adapter and tail packets
tinyvmm --wintun-svc-probe [secs] # same via the elevated wintunsvc helper
```

## Network backends

`--pvh-run --net --net-backend <kind>` selects one of:

| Backend     | Admin? | Status               | Notes                                          |
|-------------|--------|----------------------|------------------------------------------------|
| `loopback`  | no     | working              | Echoes TX back as RX. Diagnostic only.         |
| `usernet`   | no     | **recommended**      | User-mode slirp: NAT through Winsock + iphlpapi. No driver/admin. |
| `wintun`    | yes    | working              | Creates `tinyvmm` TUN adapter via wintun.dll.  |
| `wintun-svc`| no¹    | working              | Same data plane, control via `WintunSvc`.      |
| `xdp`       | yes    | working (xdpfnmp/xdpmp) | AF\_XDP zero-copy to a chosen NIC queue.   |

¹ `wintun-svc` itself runs unprivileged; the one-time
`Install-WintunSvc.ps1` and a manual outbound NAT rule
(`New-NetNat -InternalIPInterfaceAddressPrefix 10.0.0.0/24`)
still need admin.

For day-to-day use, `--net-backend usernet` is the
recommended path. It needs no kernel driver, no admin token,
and no host network configuration — outbound UDP/TCP/ICMP
flow through the host's normal Winsock + `IcmpSendEcho2`
APIs, identical to any other user-mode application's
traffic. Guest sees `10.0.0.2/24` with gateway `10.0.0.1`;
the gateway is a synthetic L3 endpoint inside tinyvmm that
terminates the guest's IP stack at L4 and proxies each
flow as a per-tuple host socket. TCP options advertise
`MSS=1460` plus `WScale=7` (when the guest negotiates it),
clamp the guest's effective MSS to 1460 on inbound SYN, and
honour wrap-safe RFC 793 §3.7 window updates.

### Inbound TCP port-forward (`--portfwd`)

`--portfwd` (repeatable; only valid with `--net-backend usernet`)
opens a TCP listener on the host and proxies each accepted
connection through to a chosen guest IP/port. Accepted forms:

```text
HOST_PORT:GUEST_PORT
    -> listens on 127.0.0.1:HOST_PORT, forwards to 10.0.0.2:GUEST_PORT
HOST_IP:HOST_PORT:GUEST_IP:GUEST_PORT
    -> full control over both endpoints
```

Example: RDP into the guest from the host:

```cmd
tinyvmm.exe --pvh-run --net --net-backend usernet --portfwd 3389:3389 ^
            --initrd initramfs.cpio vmlinux
mstsc /v:127.0.0.1:3389
```

For each accepted host-side connection, tinyvmm originates a
SYN toward the guest from the gateway (`10.0.0.1`) with a
randomly chosen ephemeral source port and a separate
sequence-number space. Listeners use `SO_EXCLUSIVEADDRUSE`
on Windows so collisions surface as a bind error rather than
silently sharing the port. Teardown (guest RST or handshake
timeout) is abortive on the host socket
(`SO_LINGER {1, 0}`) so host clients observe a real TCP RST
instead of a half-open hang.

`--xdp-probe` (no arg) walks `GetAdaptersAddresses`, opens each NIC
via `XdpInterfaceOpen`, queries `XdpRssGetCapabilities` (RSS queue
count + supported hash types), then attempts `XskBind` on queue 0
with both `XSK_BIND_FLAG_NATIVE` and `XSK_BIND_FLAG_GENERIC` to
report which attach modes the driver supports. Loopback adapters are
skipped. The bind never calls `XskActivate`, so the data path stays
inactive and the probe is safe on a NIC carrying live traffic.

