param(
    [Parameter(Mandatory)][string]$Kernel,
    [Parameter(Mandatory)][string]$Bootstrap,
    [string[]]$Shares = @(),
    [string]$Rootfs,
    [int]$SshPort = 10022,
    [int]$Vcpus = 2,
    [int]$RamMb = 1024
)
$ErrorActionPreference = 'Stop'
$out = Join-Path $PSScriptRoot 'out'
New-Item -ItemType Directory -Force $out | Out-Null
$kernelCopy = Join-Path $out 'vmlinux'
$kernelSource = (Resolve-Path -LiteralPath $Kernel).ProviderPath
if ($kernelSource -ne $kernelCopy) { Copy-Item -LiteralPath $kernelSource -Destination $kernelCopy -Force }
$initrd = Join-Path $out 'initrd.cpio'
$pack = @((Join-Path $PSScriptRoot 'make-initrd.py'), '--out', $initrd)
if ($Rootfs) { $pack += @('--rootfs', $Rootfs) }
& python @pack
if ($LASTEXITCODE -ne 0) { throw 'initramfs packaging failed' }
$vmm = Join-Path $PSScriptRoot '..\target\release\tinyvmm.exe'
if (-not (Test-Path $vmm)) { throw 'Build tinyvmm first: cargo build --release' }
$vmArgs = @(
    '--pvh-run', '--vcpus', "$Vcpus", '--ram-mb', "$RamMb", '--rng',
    '--net', '--portfwd', "${SshPort}:22",
    '--virtio-9p-share', "bootstrap=$((Resolve-Path $Bootstrap).Path),ro"
)
foreach ($share in $Shares) { $vmArgs += @('--virtio-9p-share', $share) }
$vmArgs += @('--initrd', $initrd, $kernelCopy, '--', 'console=hvc0', 'pci=conf1,nocrs,lastbus=0', 'idle=halt',
    "tinyinit.epoch=$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())")
& $vmm @vmArgs
if ($LASTEXITCODE -ne 0) { throw "tinyvmm exited with code $LASTEXITCODE" }
