#!/usr/bin/env pwsh
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..") | Select-Object -ExpandProperty Path

$gitInside = & git -C $RepoRoot rev-parse --is-inside-work-tree 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Not inside a git work tree: $RepoRoot"
    exit 1
}

$currentHooks = & git -C $RepoRoot config --local --get core.hooksPath 2>$null
if ($LASTEXITCODE -eq 0 -and $currentHooks -and $currentHooks.Trim() -eq ".githooks") {
    exit 0
}

& git -C $RepoRoot config core.hooksPath .githooks
Write-Host "Configured git to use .githooks for this repository." -ForegroundColor Green
