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
