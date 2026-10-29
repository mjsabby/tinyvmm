param(
    [switch]$Tests,
    [string]$RootfsImage,
    [switch]$UpdateRootfs,
    [switch]$NoRootfs
)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $rootfsArgs = @('.\fetch-rootfs.py')
    if ($RootfsImage) { $rootfsArgs += @('--image', $RootfsImage) }
    if ($UpdateRootfs) { $rootfsArgs += '--update' }
    if (-not $NoRootfs -or $RootfsImage -or $UpdateRootfs) {
        & python @rootfsArgs
        if ($LASTEXITCODE -ne 0) { throw 'Rootfs preparation failed.' }
    }
    Write-Output "tinyinit build: step=rootfs duration_ms=$($timer.Elapsed.TotalMilliseconds.ToString('F1'))"
    $timer.Restart()
    $buildArgs = @('zigbuild', '--locked', '--release', '--target', 'x86_64-unknown-linux-musl')
    if ($Tests) { $buildArgs += '--tests' }
    if ($NoRootfs) { $buildArgs += '--no-default-features' }
    & cargo @buildArgs
    if ($LASTEXITCODE -ne 0) { throw 'Cross-build failed. See README.md for one-time toolchain setup.' }
    Write-Output "tinyinit build: step=cross-build duration_ms=$($timer.Elapsed.TotalMilliseconds.ToString('F1'))"
    if (-not $Tests) {
        Write-Output "Linux binary: $PSScriptRoot\target\x86_64-unknown-linux-musl\release\tinyinit"
    }
} finally {
    Pop-Location
}
