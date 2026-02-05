#!/usr/bin/env pwsh
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..") | Select-Object -ExpandProperty Path

$Mode = "staged"
$BumpAll = $false
$DryRun = $false

function Show-Usage {
    Write-Host "Usage: $($MyInvocation.MyCommand.Name) [--staged] [--all] [--dry-run]" -ForegroundColor Yellow
}

foreach ($arg in $args) {
    switch ($arg) {
        "--staged" { $Mode = "staged" }
        "--all" { $BumpAll = $true }
        "--dry-run" { $DryRun = $true }
        "-h" { Show-Usage; exit 0 }
        "--help" { Show-Usage; exit 0 }
        default {
            Write-Host "Unknown option: $arg" -ForegroundColor Red
            Show-Usage
            exit 1
        }
    }
}

$gitInside = & git -C $RepoRoot rev-parse --is-inside-work-tree 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Not inside a git work tree: $RepoRoot"
    exit 1
}

$Crates = New-Object System.Collections.Generic.List[string]

if ($BumpAll) {
    Get-ChildItem -Path (Join-Path $RepoRoot "crates") -Directory | Sort-Object Name | ForEach-Object {
        $Crates.Add($_.Name) | Out-Null
    }
} else {
    $files = & git -C $RepoRoot diff --name-only --cached 2>$null
    if (-not $files) {
        Write-Host "No staged changes detected; skipping version bump." -ForegroundColor Yellow
        exit 0
    }

    $seen = @{}
    foreach ($f in ($files -split "`n")) {
        $path = $f.Trim()
        if (-not $path) { continue }
        $path = $path.Replace("\\", "/")
        if ($path -like "crates/*/*") {
            $crate = $path.Substring("crates/".Length)
            $crate = $crate.Split("/")[0]
            if ($path -eq "crates/$crate/Cargo.toml") { continue }
            $seen[$crate] = $true
        }
    }

    foreach ($key in $seen.Keys) {
        $Crates.Add($key) | Out-Null
    }
}

if ($Crates.Count -eq 0) {
    Write-Host "No crate changes detected; skipping version bump." -ForegroundColor Yellow
    exit 0
}

function Bump-VersionInCargoToml {
    param(
        [string]$Path,
        [bool]$Dry
    )

    if (-not (Test-Path $Path)) {
        Write-Host "Skipping missing Cargo.toml: $Path" -ForegroundColor Yellow
        return $false
    }

    $raw = Get-Content -Path $Path -Raw
    $lines = $raw -split "`n"

    $inPackage = $false
    $oldVersion = $null
    $newVersion = $null
    $index = -1

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $trim = $line.Trim()
        if ($trim.StartsWith("[") -and $trim.EndsWith("]")) {
            $inPackage = $trim -eq "[package]"
            continue
        }
        if ($inPackage -and $trim -match '^version\s*=\s*"([^"]+)"\s*$') {
            $oldVersion = $Matches[1]
            if ($oldVersion -notmatch '^(\d+)\.(\d+)\.(\d+)(.*)$') {
                throw "Unsupported version format: $oldVersion"
            }
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            $patch = [int]$Matches[3]
            $suffix = $Matches[4]
            $newVersion = "$major.$minor.$($patch + 1)$suffix"
            $lines[$i] = [regex]::Replace($line, '"[^"]+"', '"' + $newVersion + '"', 1)
            $index = $i
            break
        }
    }

    if (-not $oldVersion -or $index -lt 0) {
        throw "No [package] version found in $Path"
    }

    if (-not $Dry) {
        $newText = ($lines -join "`n")
        if ($raw.EndsWith("`n")) {
            $newText += "`n"
        }
        Set-Content -Path $Path -Value $newText
    }

    Write-Host "$Path $oldVersion -> $newVersion" -ForegroundColor Cyan
    return $true
}

$BumpedAny = $false
foreach ($crate in $Crates) {
    $cargoToml = Join-Path $RepoRoot "crates\$crate\Cargo.toml"
    $didBump = Bump-VersionInCargoToml -Path $cargoToml -Dry:$DryRun
    if ($didBump) { $BumpedAny = $true }
    if (-not $DryRun -and $Mode -eq "staged") {
        & git -C $RepoRoot add $cargoToml | Out-Null
    }
}

if (-not $BumpedAny) {
    Write-Host "No versions bumped." -ForegroundColor Yellow
}
