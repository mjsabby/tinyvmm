param(
    [ValidateSet('plain', 'init', 'dotnet', 'all')][string]$Flavor = 'all',
    [string]$Kernel,
    [string]$RootfsImage,
    [switch]$UpdateRootfs
)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
$previousKernel = $env:TINYVMM_KERNEL
$previousInitrd = $env:TINYVMM_INITRD
try {
    $out = Join-Path $PSScriptRoot 'out\deploy'
    New-Item -ItemType Directory -Force $out | Out-Null
    $flavors = if ($Flavor -eq 'all') { @('init', 'dotnet', 'plain') } else { @($Flavor) }
    foreach ($selected in $flavors) {
        $buildArgs = @('build', '--release', '--no-default-features')
        $name = 'tinyvmm'
        if ($selected -ne 'plain') {
            if (-not $Kernel) { throw '-Kernel must name a PVH vmlinux for embedded builds.' }
            $env:TINYVMM_KERNEL = (Resolve-Path -LiteralPath $Kernel).ProviderPath
            $initArgs = @{}
            if ($selected -eq 'init') { $initArgs.NoRootfs = $true }
            if ($RootfsImage) { $initArgs.RootfsImage = $RootfsImage }
            if ($UpdateRootfs) { $initArgs.UpdateRootfs = $true }
            & .\tinyinit\build.ps1 @initArgs
            $initrd = Join-Path $out "tinyvmm-$selected.cpio"
            & python .\tinyinit\make-initrd.py --out $initrd
            if ($LASTEXITCODE -ne 0) { throw 'Initramfs packaging failed.' }
            $env:TINYVMM_INITRD = $initrd
            $buildArgs += @('--features', "embedded-$selected")
            $name = "tinyvmm-$selected"
        }
        & cargo @buildArgs
        if ($LASTEXITCODE -ne 0) { throw "Windows $selected build failed." }
        Copy-Item -LiteralPath .\target\release\tinyvmm.exe -Destination (Join-Path $out "$name.exe") -Force
        if (Test-Path .\target\release\tinyvmm.pdb) {
            Copy-Item -LiteralPath .\target\release\tinyvmm.pdb -Destination (Join-Path $out "$name.pdb") -Force
        }
        Write-Output "Deployment: $out\$name.exe"
    }
} finally {
    $env:TINYVMM_KERNEL = $previousKernel
    $env:TINYVMM_INITRD = $previousInitrd
    Pop-Location
}
