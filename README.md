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
- **XDP for Windows** source tree at `C:\xdp-for-windows`, or override with
  `-DXDP_ROOT=...`.

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

### Time enlightenment

RDTSC is **not** intercepted by tinyvmm and runs natively on the host TSC with
a Hyper-V-supplied offset (and TSC scaling on capable hardware). No host code
runs on time queries. A future milestone will add the Hyper-V Reference TSC
page (`HV_X64_MSR_REFERENCE_TSC`) for a fully migration-safe paravirt clock.

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
.\build\bin\tinyvmm.exe --pvh-run --net --net-backend wintun-svc .\vmlinux
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

