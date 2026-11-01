# Build tinyvmm_gvisor.dll (gVisor's netstack for `--net-backend gvisor`)
# next to tinyvmm.exe. Needs Go and a cgo C compiler: a MinGW-w64 gcc on
# PATH, or pass -CC "zig cc -target x86_64-windows-gnu".
param(
    [string]$Out = (Join-Path $PSScriptRoot '..\target\release\tinyvmm_gvisor.dll'),
    [string]$CC = $(if ($env:CC) { $env:CC } else { 'gcc' })
)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $env:CGO_ENABLED = '1'
    $env:CC = $CC
    go build -buildmode=c-shared -trimpath -ldflags '-s -w' -o $Out .
    if ($LASTEXITCODE -ne 0) { throw "go build failed ($LASTEXITCODE)" }
    # The cgo header the build drops alongside isn't needed.
    Remove-Item -ErrorAction SilentlyContinue ([IO.Path]::ChangeExtension($Out, '.h'))
    Write-Host "built $((Resolve-Path $Out).Path)"
} finally {
    Pop-Location
}
