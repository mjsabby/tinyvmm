#requires -RunAsAdministrator
<#
.SYNOPSIS
  xperf capture harness for tinyvmm. One invocation = one baseline trace.

.DESCRIPTION
  Starts kernel + Tinyvmm-Core ETW sessions, launches tinyvmm with the device
  set appropriate for the chosen workload, waits for you to run the in-guest
  benchmark (or for -DurationSec to elapse), then stops + merges to
  out\<env>-<workload>-<tag>.etl.

  Run once per workload on each box (nested + bare-metal). Analyse in WPA;
  the script also dumps a top-20 sampled-stack summary via xperf -a.

.EXAMPLE
  .\tools\profile.ps1 -Workload idle  -Kernel C:\images\vmlinux -Initrd C:\images\initramfs.cpio -DurationSec 30
  .\tools\profile.ps1 -Workload net   -Kernel C:\images\vmlinux -Initrd C:\images\initramfs.cpio -DurationSec 60
  .\tools\profile.ps1 -Workload blk   -Kernel C:\images\vmlinux -Initrd C:\images\initramfs.cpio -Disk C:\images\disk.img -DurationSec 60
  .\tools\profile.ps1 -Workload p9    -Kernel C:\images\vmlinux -Initrd C:\images\initramfs.cpio -Share C:\share -DurationSec 60
#>
param(
  [Parameter(Mandatory)][ValidateSet('idle','net','blk','p9')] [string] $Workload,
  [Parameter(Mandatory)] [string] $Kernel,
  [string] $Initrd,
  [string] $Disk,
  [string] $Share,
  [int]    $RamMb       = 1024,
  [int]    $DurationSec = 60,
  [string] $Tag         = 'baseline',
  [string] $Exe         = "$PSScriptRoot\..\target\release\tinyvmm.exe",
  # Kernel cmdline appended after `--`. Per-workload defaults below auto-run the
  # benchmark when the initramfs honours `tinyvmm.autorun=` (ours does).
  [string] $Cmdline
)

$ErrorActionPreference = 'Stop'
$ProviderGuid = '{0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d}'   # Tinyvmm-Core (diag/etw.rs)

# ---- environment tag: nested vs bare-metal --------------------------------
$cs  = Get-CimInstance Win32_ComputerSystem
$Env = if ($cs.Model -match 'Virtual') { 'nested' } else { 'baremetal' }
$Out = Join-Path $PSScriptRoot "..\out"
New-Item -ItemType Directory -Force $Out | Out-Null
$Etl = Join-Path $Out "$Env-$Workload-$Tag.etl"
$Sum = Join-Path $Out "$Env-$Workload-$Tag.summary.txt"

# ---- per-workload device set + default in-guest command -------------------
$devFlags = @()
$auto     = ''
switch ($Workload) {
  'idle' { $auto = 'sh' }                                           # boot to shell, sit idle
  'net'  { $devFlags += '--net','--net-backend','nat'
           $auto = 'iperf3 -c 10.0.0.1 -t 40 -R; iperf3 -c 10.0.0.1 -t 40' }
  'blk'  { if (-not $Disk) { throw "-Disk required for blk workload" }
           $devFlags += '--drive', $Disk
           $auto = 'fio --name=r --filename=/dev/vda --rw=randread --bs=4k --iodepth=32 --runtime=40 --time_based --ioengine=libaio --direct=1' }
  'p9'   { if (-not $Share) { throw "-Share required for p9 workload" }
           $devFlags += '--9p', "host:$Share"
           $auto = 'mount -t 9p -o trans=virtio host /mnt && find /mnt -type f | head -50000 | xargs -n64 stat >/dev/null' }
}
if (-not $Cmdline) {
  $Cmdline = "console=hvc0 tinyvmm.autorun=`"$auto`""
}

# ---- assemble tinyvmm argv ------------------------------------------------
# Order matters: `--pvh-run [flags...] <vmlinux> [-- <cmdline>]` — kernel path
# AFTER all flags (parse_pvh_args stops at the first non-`--` arg).
$argv = @('--pvh-run', '--ram-mb', $RamMb)
if ($Initrd) { $argv += '--initrd', $Initrd }
$argv += '--rng', '--debug-boot'       # debug-boot routes earlyprintk to ttyS0
$argv += $devFlags
$argv += $Kernel
$argv += '--', $Cmdline

Write-Host "== tinyvmm profile capture ==" -ForegroundColor Cyan
Write-Host "  env      : $Env"
Write-Host "  workload : $Workload"
Write-Host "  tag      : $Tag"
Write-Host "  etl      : $Etl"
Write-Host "  exe      : $Exe"
Write-Host "  argv     : $($argv -join ' ')"
Write-Host ""

# ---- xperf start ----------------------------------------------------------
# Kernel: PROFILE (1ms CPU sampling) + CSWITCH (blocked-time) + SYSCALL (WHv* cost
# attribution) + FILE_IO/DISK_IO (blk/9p backend). Stackwalk on the lot.
# User : Tinyvmm-Core at level 5 (VERBOSE), all keywords, with stacks — gives
#        per-exit-reason VmExit events and per-device markers to slice by.
xperf -on PROC_THREAD+LOADER+PROFILE+CSWITCH+DISPATCHER+SYSCALL+DISK_IO+FILE_IO+FILE_IO_INIT `
      -stackwalk Profile+CSwitch+ReadyThread+SyscallEnter `
      -BufferSize 1024 -MinBuffers 256 -MaxBuffers 1024
xperf -start tinyvmm -on "$ProviderGuid:0xFFFFFFFFFFFFFFFF:5:'stack'" `
      -BufferSize 1024 -MinBuffers 64 -MaxBuffers 256

# ---- run guest ------------------------------------------------------------
$proc = Start-Process -FilePath $Exe -ArgumentList $argv -PassThru -NoNewWindow
try {
  Write-Host ">> guest running; capturing for $DurationSec s (run the in-guest workload now if not auto)..." -ForegroundColor Yellow
  Start-Sleep -Seconds $DurationSec
} finally {
  if (-not $proc.HasExited) {
    # Ctrl+C equivalent: tinyvmm's stop path is the console handler / request_stop.
    # Safest from outside is a graceful kill; in-flight WHP run is cancelled on handle close.
    Stop-Process -Id $proc.Id -Force
  }
  # ---- xperf stop + merge ----
  xperf -stop tinyvmm -stop -d $Etl
}

# ---- quick-look summary (top sampled stacks in tinyvmm.exe) ---------------
# Full analysis in WPA; this is the smoke test that P1/P2/P3 show up where expected.
Write-Host ">> summarising top sampled stacks -> $Sum" -ForegroundColor Cyan
xperf -i $Etl -symbols -o $Sum -a cpudisk
xperf -i $Etl -symbols -a profile -process tinyvmm.exe -stacktree | Select-Object -First 120 | Tee-Object -Append -FilePath $Sum

Write-Host ""
Write-Host "done: $Etl" -ForegroundColor Green
Write-Host "open in WPA:  wpa $Etl"
Write-Host "  - CPU Usage (Sampled), filter Process=tinyvmm.exe, stack by Module!Function"
Write-Host "  - expect on NESTED idle:  vid.sys / WinHvp!WinHvGetVpRegisters under deliver_interrupts  (P1)"
Write-Host "  - expect on net RX:       tinyvmm!write_frame_to_rx self-time                            (P3)"
Write-Host "  - expect on any MMIO:     tinyvmm!MmioBus::dispatch -> ntdll!RtlAcquireSRWLockShared      (P2)"
