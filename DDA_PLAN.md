

\# tinyvmm: wire WHP DDA (`--device`) into the live VM



\## Context / what already exists (do NOT rebuild)

\- `crates/whpsys/src/vpci.rs` — complete FFI: `VpciResource::new(pnp)`, `VpciDevice`

&#x20; (`hardware\_ids`, `probed\_bars`, `set\_power\_on`, `map\_mmio\_ranges`/`unmap\_mmio\_ranges`,

&#x20; `read\_register`/`write\_register`, `read\_config\_dword`/`write\_config\_dword`,

&#x20; `map\_interrupt`/`unmap\_interrupt`/`retarget\_interrupt`/`request\_interrupt`,

&#x20; `get\_notification`), `decode\_probed\_bars` + `ProbedBar`.

\- `crates/whpsys/src/partition.rs:76` — `Partition::set\_allow\_device\_assignment(bool)`

&#x20; (MUST be called before `setup()`).

\- `src/pci/passthrough.rs` — `AssignedBars` (BAR shadow, unit-tested) + `decode\_msi`.

\- `src/main.rs:3706 run\_dda\_probe` (`--dda-probe`) — allocates resource, creates device,

&#x20; dumps IDs/BARs/caps, AND tests `WHvMapGpaRange2(deviceMMIO -> guest GPA)`.

\- `src/pci/{mod.rs,bus.rs,config.rs}` — `PciFunction` trait, `PciBus` (CF8/CFC + auto BAR

&#x20; base assignment), `BarKind`.

\- `src/devices/mmio\_bus.rs` — `MmioBus` (GPA-range routed handlers).

\- `src/virtio/transport.rs:764` — `PciTransport` is the reference `PciFunction` impl

&#x20; (maps/unmaps MMIO handlers on a command MemoryEnable event; syncs MSI-X control).

\- Reference impl to mirror: OpenVMM `vmm\_core/virt\_whp/src/device.rs` `AssignedPciDevice`.



\## Memory map facts

\- `src/mem\_layout.rs`: `MMIO\_WINDOW\_BASE=0xE000\_0000`, `MMIO\_WINDOW\_END=0xFEC0\_0000`

&#x20; (\~478 MiB low BAR window), `HIGH\_RAM\_BASE=0x1\_0000\_0000`. There is \*\*no high MMIO

&#x20; window above RAM\*\* yet → large GPU/NVMe BARs won't fit. Needed for big-BAR devices.

\- Boot path = `--pvh-run`: `parse\_pvh\_args` (src/main.rs:603), run body \~963.

&#x20; Partition built at 963-969: `new` -> `enable\_extended\_exits` -> `set\_cpuid\_result\_list`

&#x20; -> `setup()`. `pci\_bus`/`mmio\_bus` at 1054/1116; `attach\_io\_bus` at 1436.



\## Phase 1 — `AssignedDevice` PciFunction (new file `src/pci/assigned.rs`)

Mirror OpenVMM `AssignedPciDevice`. Struct holds: `Arc<VpciDevice>`, `Mutex<AssignedBars>`,

mmio mappings from `map\_mmio\_ranges` (host VA + bar/offset/size + R/W flags), power-cap

offset (probe config like OpenVMM `probe\_power\_register`), `power\_state`, `command` shadow,

`mmio\_enabled`, `Arc<MmioBus>`, partition handle, and the chosen MMIO strategy flag.

Implement `PciFunction`:

\- `config\_read`: BAR dwords 0x10..0x24 -> `AssignedBars::read\_dword`; everything else ->

&#x20; `read\_config\_dword(offset)` passthrough; if `offset==power\_cap`, splice live power\_state.

\- `config\_write`:

&#x20; - command reg (0x04): decode MemoryEnable. On enable: if no power cap \& power!=D0 ->

&#x20;   `set\_power\_on(true)`; then `enable\_mmio()`. On disable: `disable\_mmio()`; optional D3.

&#x20;   Always `write\_config\_dword(0x04, value)` and update `command` shadow.

&#x20; - BAR dwords -> `AssignedBars::write\_dword`.

&#x20; - `power\_cap` offset -> `set\_power\_on(power\_state==0)` + enable/disable mmio accordingly.

&#x20; - default -> `write\_config\_dword`.

\- `bar\_layout`: synthesize `\[(BarKind,size);6]` from `probed\_bars`/`decode\_probed\_bars`

&#x20; (ProbedBar.is\_io -> Io, is\_64bit -> Mmio64 else Mmio32; size from probe). Lets `PciBus`

&#x20; reserve GPA windows + program the shadow via `assign\_bar\_base`.

\- `assign\_bar\_base(idx,gpa)`: feed `AssignedBars` shadow (`write\_dword` low/high halves).



\## Phase 2 — MMIO mapping (two strategies, pick per-machine via the probe)

`enable\_mmio()` calls `dev.map\_mmio\_ranges()` then, per `AssignedBars::mappings()` BAR base:

\- FAST (zero-exit): for each mapped region, `WHvMapGpaRange2(hostVA -> barBaseGPA+off, size)`.

&#x20; Use only if `--dda-probe` reported MapGpaRange2 success on this host. \*\*Exclude the MSI-X

&#x20; table page\*\* (keep it trapped — see Phase 3). Add a `whpsys::memory` (or vpci) helper

&#x20; `map\_device\_mmio(part, host\_va, gpa, size)` / `unmap` wrapping `WHvMapGpaRange2`/`WHvUnmapGpaRange`.

\- FALLBACK (trap-and-forward, always correct — mirror OpenVMM): register each BAR range on

&#x20; `MmioBus`; handler memcpys guest<->host VA for ranges with a R/W host mapping, and for

&#x20; offsets WITHOUT a host mapping forwards via

&#x20; `read\_register/write\_register(WHV\_VPCI\_DEVICE\_REGISTER\_SPACE(bar), off, data)`.

`disable\_mmio()`: unmap SLAT ranges (or unregister MmioBus handlers) + `unmap\_mmio\_ranges()`.

Note: DMA is always native (IOMMU); only CPU->BAR MMIO is the fast/slow question.



\## Phase 3 — Interrupts: MSI-X (NVMe) + MSI (GPU)

\*\*MSI-X (cap 0x11 — NVMe, some GPUs):\*\* PhysicallyBacked VPCI ⇒ WHP virtualizes the real

MSI-X table. Route the MSI-X table sub-region of the BAR to \*\*trap-and-forward\*\* via

`read/write\_register(WHV\_VPCI\_DEVICE\_REGISTER\_SPACE(bar), off, data)` and let WHP remap.

\*\*Never SLAT-map that page.\*\* Find table BAR+offset from the MSI-X cap via `read\_config\_dword`

in `new()`.

\*\*MSI (cap 0x05 — many GPUs):\*\* the Message Address/Data live in \*config space\*, not a BAR.

Forward those config writes via `write\_config\_dword`/`write\_register(ConfigSpace)` and let WHP

remap (PhysicallyBacked). Parse the cap in `new()` to know its offsets.

\*\*Plan-B (manual remap, if IRQs don't arrive for either):\*\* `decode\_msi` the guest entry →

`map\_interrupt(index, count, target{vector,vp})` → write the returned opaque (addr,data) back

into the device (table for MSI-X, cap for MSI). `decode\_msi` already exists in passthrough.rs.



\## Phase 4 — CLI + boot wiring (`src/main.rs`)

\- `parse\_pvh\_args` (line 603): add repeatable `"--device" => { i+=1; devices.push(args\[i]) }`

&#x20; (Vec<String> of PnP instance ids), like `--net`. Add `devices` to the pvh cfg struct.

\- Partition build (963-969): if `!cfg.devices.is\_empty()` call

&#x20; `part.set\_allow\_device\_assignment(true)?` \*\*before\*\* `part.setup()`.

\- After `pci\_bus`/`mmio\_bus` exist and before `attach\_io\_bus` (1436): for each id (assign a

&#x20; unique `device\_id`): `VpciResource::new(id)?` -> `VpciDevice::new(part\_handle, id, res)?`

&#x20; -> `AssignedDevice::new(dev, mmio\_bus.clone(), part\_handle, slat\_ok)?` ->

&#x20; `pci\_bus.add\_device(Arc::new(assigned))`. Hold the Arcs for teardown.

\- main(): no new top-level subcommand — `--device` is an option of `--pvh-run`.



\## Scope: ONLY NVMe + GPU

Bring up in this order — NVMe is the easy win, GPU is the hard one.



\### NVMe (do first — validates the whole pipeline)

\- Typically 1 MMIO BAR (BAR0, 16 KiB–few MiB) → fits the low window; no Phase 5 needed.

\- MSI-X only (cap 0x11) → Phase 3 simple path applies directly.

\- Trap-and-forward (Phase 2 FALLBACK) is fine perf-wise (BAR0 = doorbells/regs, low traffic;

&#x20; DMA is native). SLAT fast-path is a nice-to-have, not required.

\- DMA-heavy → Phase 6 pinning matters. This is the reference bring-up; get IRQs + I/O working.



\### GPU (after NVMe works)

\- \*\*Phase 5 high MMIO window is MANDATORY\*\* — GPUs expose a huge 64-bit prefetchable VRAM

&#x20; aperture (256 MiB to 16+ GiB with Resizable BAR) that cannot fit `\[E000\_0000,FEC0\_0000)`.

\- \*\*SLAT fast-path (Phase 2 FAST) is effectively REQUIRED\*\* — trapping every GPU MMIO/VRAM

&#x20; access is unusably slow. Gate on `--dda-probe` reporting `WHvMapGpaRange2` success; if it

&#x20; fails on this host, GPU passthrough is not performant here (NVMe still works via fallback).

\- \*\*MSI (cap 0x05), not just MSI-X\*\* — many GPUs use legacy MSI. Handle both (see Phase 3).

\- GPU-specific gotchas (call out, don't silently skip):

&#x20; - \*\*Expansion ROM BAR (config 0x30 / VBIOS):\*\* not in `WHV\_VPCI\_PROBED\_BARS` (6 std BARs

&#x20;   only). Guest GPU drivers may need the VBIOS. Pass 0x30 through and/or surface the ROM;

&#x20;   if the driver can't find a VBIOS, supply the device's ROM image. Known passthrough gap.

&#x20; - \*\*Resizable BAR (PCIe ext cap 0x15):\*\* simplest is to NOT advertise resize (keep current

&#x20;   size) so the guest doesn't try to grow the aperture; size the high window to the current

&#x20;   BAR size. Revisit only if a driver demands rebar.

&#x20; - \*\*Reset/FLR:\*\* GPUs often mis-reset (AMD reset bug). On teardown do D3 + delete; expect a

&#x20;   host re-mount may be needed before reuse. Document; don't assume clean re-assign.

&#x20; - \*\*IOMMU group siblings:\*\* the GPU's HDMI-audio function (`.1`) is usually in the same

&#x20;   group — it must also be dismounted from the host (assign it too or the group won't bind).



\## Phase 5 — High MMIO window (MANDATORY for GPU)

\- Add a high-MMIO region above `HIGH\_RAM\_BASE + ram` (e.g. base `0x10\_0000\_0000`), sized for

&#x20; the GPU's VRAM aperture (read actual size from `probed\_bars`), and thread it into the

&#x20; `PciBus` BAR allocator (`bus.rs mmio\_next` only walks the low window today) so 64-bit BARs

&#x20; that don't fit `\[E000\_0000,FEC0\_0000)` land high. NVMe stays in the low window.

\- Advertise it to the guest (PVH memmap reserved entry + host-bridge ACPI `\_CRS`) so Linux's

&#x20; PCI core programs BARs there. Without this the probe's "exceeds sub-4GiB window" warning

&#x20; becomes a real allocation failure for the GPU.



\## Phase 6 — pinning, teardown, tests

\- Pinning: with AllowDeviceAssignment WHP pins all mapped guest RAM. For big guests bump the

&#x20; process working set (`SetProcessWorkingSetSize`) or use `large\_pages` (already supported),

&#x20; else map/create may fail. Verify on first large-RAM run.

\- Teardown order: stop vCPUs -> `disable\_mmio` (unmap SLAT/MmioBus) -> drop `VpciDevice`

&#x20; (Drop calls `WHvDeleteVpciDevice`). Document host re-mount (Mount-VMHostAssignableDevice /

&#x20; Enable-PnpDevice) — probe already prints this.

\- Tests: extend `passthrough.rs` units (bar\_layout synthesis from probed; command

&#x20; enable/disable map/unmap transitions using a fake VpciDevice trait if needed). Live bring-up:

&#x20; assign an NVMe first (simplest: 1 BAR, MSI-X, no high window) before attempting a GPU.



\## Validation

`cargo build`, `cargo test -p tinyvmm` (passthrough units), then:

`tinyvmm --dda-probe <pnp-id>` (confirm SLAT result) ->

`tinyvmm --pvh-run ... --device <pnp-id>` and check guest `lspci -v` + driver bind + IRQs.

Host prep per device: `Disable-PnpDevice -InstanceId <id>`;

`Dismount-VMHostAssignableDevice -Force -LocationPath <loc>`; IOMMU on; if alloc fails with

0x80070032: `bcdedit /set hypervisordmaremap on` + reboot, VT-d in BIOS.



