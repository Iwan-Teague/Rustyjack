#!/usr/bin/env pwsh
# PowerShell wrapper for running Docker container for ARM32 cross-compilation
# Usage: ./run.ps1 [command args...]
# If no args, starts interactive bash shell

$ErrorActionPreference = "Stop"

$ImageName = "rustyjack/arm32-dev"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..") | Select-Object -ExpandProperty Path

# Build the docker image
docker build --pull --platform linux/arm/v7 -t $ImageName $ScriptDir
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Ensure tmp directory exists
$TmpDir = Join-Path $RepoRoot "tmp"
if (-not (Test-Path $TmpDir)) {
    New-Item -ItemType Directory -Path $TmpDir | Out-Null
}

# Run docker with provided args or default to bash
if ($args.Count -eq 0) {
    docker run --rm -it --platform linux/arm/v7 `
        -v "${RepoRoot}:/work" -w /work `
        -e TMPDIR=/work/tmp `
        $ImageName `
        bash
} else {
    docker run --rm -it --platform linux/arm/v7 `
        -v "${RepoRoot}:/work" -w /work `
        -e TMPDIR=/work/tmp `
        $ImageName `
        @args
}

exit $LASTEXITCODE
