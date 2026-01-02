# Build Rustyjack for 32-bit ARM (Pi Zero 2 W on 32-bit Pi OS) inside the arm32 container.
# Requires Docker Desktop with binfmt/qemu enabled.

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

Set-Location $RepoRoot

Write-Host "Building ARM32 (armv7) target using Docker..." -ForegroundColor Cyan

# Build the Docker image and run cargo build
& "$RepoRoot\docker\arm32\run.ps1" env CARGO_TARGET_DIR=/work/target-32 cargo build --target armv7-unknown-linux-gnueabihf -p rustyjack-ui -p rustyjack-core -p rustyjack-daemon

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nBuild successful. Copying binaries to prebuilt\\arm32..." -ForegroundColor Green

    $TargetDir = Join-Path $RepoRoot "target-32\armv7-unknown-linux-gnueabihf\debug"
    $PrebuiltDir = Join-Path $RepoRoot "prebuilt\arm32"
    $Bins = @("rustyjack-ui", "rustyjack-core", "rustyjackd")

    New-Item -ItemType Directory -Force -Path $PrebuiltDir | Out-Null
    foreach ($bin in $Bins) {
        $src = Join-Path $TargetDir $bin
        $dst = Join-Path $PrebuiltDir $bin
        if (Test-Path $src) {
            Copy-Item $src $dst -Force
        }
    }

    $missing = @()
    foreach ($bin in $Bins) {
        if (-not (Test-Path (Join-Path $PrebuiltDir $bin))) {
            $missing += $bin
        }
    }
    if ($missing.Count -eq 0) {
        Write-Host "Prebuilt binaries placed at prebuilt\\arm32: $($Bins -join ', ')" -ForegroundColor Green
    } else {
        Write-Host "Warning: built binaries not found to copy: $($missing -join ', ')" -ForegroundColor Yellow
    }
} else {
    Write-Host "`nBuild failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}
