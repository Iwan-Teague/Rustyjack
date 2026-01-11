#!/usr/bin/env pwsh
# ARM32 cross-compilation build script for Windows
# Builds rustyjack binaries for Raspberry Pi (armv7)
# Always performs a complete fresh build - no caching

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..") | Select-Object -ExpandProperty Path
$DockerDir = Join-Path $RepoRoot "docker\arm32"
$Target = "armv7-unknown-linux-gnueabihf"
$TargetDir = "/work/target-32"
$HostTargetDir = Join-Path $RepoRoot "target-32"
$ImageName = "rustyjack/arm32-dev"

# Step 1: Clean everything
Write-Host "=== CLEAN BUILD ===" -ForegroundColor Cyan
Write-Host "Removing existing target directory to ensure fresh build..." -ForegroundColor Yellow

if (Test-Path $HostTargetDir) {
    Remove-Item -Recurse -Force $HostTargetDir
    Write-Host "Cleaned target directory: $HostTargetDir" -ForegroundColor Green
}

# Step 2: Stop any containers using the image and remove it
Write-Host "Stopping any containers using the image..." -ForegroundColor Yellow
$containers = docker ps -aq --filter "ancestor=$ImageName" 2>$null
if ($containers) {
    docker stop $containers 2>$null
    docker rm $containers 2>$null
}
Write-Host "Removing old Docker image..." -ForegroundColor Yellow
docker rmi -f $ImageName 2>$null
Write-Host "Building Docker image from scratch (no cache)..." -ForegroundColor Cyan

docker build --no-cache --platform linux/arm/v7 -t $ImageName $DockerDir
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker build failed" -ForegroundColor Red
    exit $LASTEXITCODE
}
Write-Host "Docker image built successfully" -ForegroundColor Green

# Step 3: Ensure directories exist
$TmpDir = Join-Path $RepoRoot "tmp"
if (-not (Test-Path $TmpDir)) {
    New-Item -ItemType Directory -Path $TmpDir | Out-Null
}

if (-not (Test-Path $HostTargetDir)) {
    New-Item -ItemType Directory -Path $HostTargetDir | Out-Null
}

# Step 4: Build all packages
Write-Host "Building all packages..." -ForegroundColor Cyan

$BuildCmd = "export PATH=/usr/local/cargo/bin:`$PATH && export CARGO_TARGET_DIR=$TargetDir && echo 'Building rustyjack-ui...' && cargo build --target $Target -p rustyjack-ui && echo 'Building rustyjackd...' && cargo build --target $Target -p rustyjack-daemon && echo 'Building rustyjack-portal...' && cargo build --target $Target -p rustyjack-portal && echo 'Building rustyjack CLI...' && cargo build --target $Target -p rustyjack-core --bin rustyjack --features rustyjack-core/cli"

# Pass cargo target cache volume to docker run script
$env:DOCKER_VOLUMES_EXTRA = "$HostTargetDir`:$TargetDir"
& "$RepoRoot\docker\arm32\run.ps1" bash -c $BuildCmd

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "Build completed successfully" -ForegroundColor Green

# Step 5: Copy binaries to prebuilt directory
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
    Write-Host "Copied $bin" -ForegroundColor Green
}

Write-Host "=== BUILD COMPLETE ===" -ForegroundColor Cyan
Write-Host "Binaries copied to $DestDir" -ForegroundColor Green
exit 0
