# Build Rustyjack for 64-bit ARM (Pi Zero 2 W on 64-bit Pi OS / other ARM64 Pis) inside the arm64 container.
# Requires Docker Desktop with binfmt/qemu enabled.

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

Set-Location $RepoRoot

Write-Host "Building ARM64 (aarch64) target using Docker..." -ForegroundColor Cyan

# Build the Docker image and run cargo build
& "$RepoRoot\docker\arm64\run.ps1" env CARGO_TARGET_DIR=/work/target-64 cargo build --target aarch64-unknown-linux-gnu -p rustyjack-ui -p rustyjack-core -p rustyjack-daemon

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nBuild successful. Copying binaries to prebuilt\\arm64..." -ForegroundColor Green

    $TargetDir = Join-Path $RepoRoot "target-64\aarch64-unknown-linux-gnu\debug"
    $PrebuiltDir = Join-Path $RepoRoot "prebuilt\arm64"
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
        Write-Host "Prebuilt binaries placed at prebuilt\\arm64: $($Bins -join ', ')" -ForegroundColor Green
    } else {
        Write-Host "Warning: built binaries not found to copy: $($missing -join ', ')" -ForegroundColor Yellow
    }
} else {
    Write-Host "`nBuild failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}
