#!/usr/bin/env pwsh
# ARM32 cross-compilation build script for Windows
# Builds rustyjack binaries for Raspberry Pi (armv7)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..") | Select-Object -ExpandProperty Path
$DockerDir = Join-Path $RepoRoot "docker\arm32"
$Target = "armv7-unknown-linux-gnueabihf"
$TargetDir = "/work/target-32"
$HostTargetDir = Join-Path $RepoRoot "target-32"
$ImageName = "rustyjack/arm32-dev"

# Build docker image
Write-Host "Building Docker image..." -ForegroundColor Cyan
docker build --pull --platform linux/arm/v7 -t $ImageName $DockerDir
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker build failed" -ForegroundColor Red
    exit $LASTEXITCODE
}

# Ensure tmp directory exists
$TmpDir = Join-Path $RepoRoot "tmp"
if (-not (Test-Path $TmpDir)) {
    New-Item -ItemType Directory -Path $TmpDir | Out-Null
}

# Build command - single line to avoid Windows CRLF issues
$BuildCmd = "set -euo pipefail; export PATH=/usr/local/cargo/bin:`$PATH; export CARGO_TARGET_DIR=$TargetDir; cargo build --target $Target -p rustyjack-ui; cargo build --target $Target -p rustyjack-daemon; cargo build --target $Target -p rustyjack-portal; cargo build --target $Target -p rustyjack-core --bin rustyjack --features rustyjack-core/cli"

Write-Host "Running cargo build in Docker..." -ForegroundColor Cyan
# Note: No -it flag for non-interactive build
docker run --rm --platform linux/arm/v7 `
    -v "${RepoRoot}:/work" -w /work `
    -e TMPDIR=/work/tmp `
    $ImageName `
    bash -c $BuildCmd

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed" -ForegroundColor Red
    exit $LASTEXITCODE
}

# Copy binaries to prebuilt directory
$DestDir = Join-Path $RepoRoot "prebuilt\arm32"
if (-not (Test-Path $DestDir)) {
    New-Item -ItemType Directory -Path $DestDir | Out-Null
}

$Bins = @("rustyjack-ui", "rustyjackd", "rustyjack-portal", "rustyjack")
foreach ($bin in $Bins) {
    $Src = Join-Path $HostTargetDir "$Target\debug\$bin"
    if (-not (Test-Path $Src)) {
        Write-Host "Missing binary: $Src" -ForegroundColor Red
        exit 1
    }
    Copy-Item -Force $Src (Join-Path $DestDir $bin)
}

Write-Host "Copied binaries to $DestDir" -ForegroundColor Green
exit 0
