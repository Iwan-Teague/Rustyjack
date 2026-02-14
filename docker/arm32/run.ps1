#!/usr/bin/env pwsh
# PowerShell wrapper for running Docker container for ARM32 cross-compilation
# Usage: ./run.ps1 [command args...]
# If no args, starts interactive bash shell
# Supports DOCKER_VOLUMES_EXTRA environment variable for additional volume mounts

$ErrorActionPreference = "Stop"

$ImageName = "rustyjack/arm32-dev"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..") | Select-Object -ExpandProperty Path
$DockerfilePath = Join-Path $ScriptDir "Dockerfile"

# Smart docker image build: only rebuild if Dockerfile changed or image doesn't exist
Write-Host "Checking Docker image status..." -ForegroundColor Cyan

$DockerfileChanged = $false
$ImageExists = $false

# Check if image exists (temporarily allow errors so stderr from docker doesn't terminate)
$prevPref = $ErrorActionPreference
$ErrorActionPreference = "Continue"
docker image inspect $ImageName >$null 2>&1
$ErrorActionPreference = $prevPref
if ($LASTEXITCODE -eq 0) {
    $ImageExists = $true

    # Check if Dockerfile was modified since image was created
    $ImageCreatedRaw = docker inspect $ImageName --format='{{.Created}}'
    $FileLastWrite = (Get-Item $DockerfilePath).LastWriteTime

    try {
        $ImageCreated = [DateTime]::Parse($ImageCreatedRaw)
        if ($FileLastWrite -gt $ImageCreated) {
            $DockerfileChanged = $true
            Write-Host "Dockerfile has been modified since image was created" -ForegroundColor Yellow
        } else {
            Write-Host "Docker image is up-to-date (no rebuild needed)" -ForegroundColor Green
        }
    } catch {
        # If datetime parsing fails, rebuild to be safe
        $DockerfileChanged = $true
    }
} else {
    Write-Host "Docker image doesn't exist - building..." -ForegroundColor Yellow
}

# Rebuild only if necessary
if (-not $ImageExists -or $DockerfileChanged) {
    Write-Host "Building Docker image..." -ForegroundColor Cyan
    docker build --platform linux/arm/v7 -t $ImageName $ScriptDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Docker build failed" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

# Ensure tmp directory exists
$TmpDir = Join-Path $RepoRoot "tmp"
if (-not (Test-Path $TmpDir)) {
    New-Item -ItemType Directory -Path $TmpDir | Out-Null
}

# Parse volume mounts from environment variable (format: "host_path:container_path")
$DockerVolumes = @()
if ($env:DOCKER_VOLUMES_EXTRA) {
    # Split on newline if multiple volumes, otherwise treat as single volume
    $volumes = $env:DOCKER_VOLUMES_EXTRA -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
    foreach ($vol in $volumes) {
        # Each volume should be in format "host:container"
        if ($vol.IndexOf(":") -ge 0) {
            # Windows path format: split on first colon to separate host and container paths
            $colonIndex = $vol.IndexOf(":")
            $hostPath = $vol.Substring(0, $colonIndex)
            $containerPath = $vol.Substring($colonIndex + 1)
            $DockerVolumes += "-v"
            $DockerVolumes += "$hostPath`:$containerPath"
        }
    }
}

# Run docker with provided args or default to bash
if ($args.Count -eq 0) {
    docker run --rm -it --platform linux/arm/v7 `
        -v "${RepoRoot}:/work" -w /work `
        -e TMPDIR=/work/tmp `
        $DockerVolumes `
        $ImageName `
        bash
} else {
    docker run --rm -it --platform linux/arm/v7 `
        -v "${RepoRoot}:/work" -w /work `
        -e TMPDIR=/work/tmp `
        $DockerVolumes `
        $ImageName `
        @args
}

exit $LASTEXITCODE
