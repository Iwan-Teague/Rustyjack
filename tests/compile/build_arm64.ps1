#!/usr/bin/env pwsh
# ARM64 cross-compilation build script for Windows
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..") | Select-Object -ExpandProperty Path
$Target = "aarch64-unknown-linux-gnu"
$TargetDir = "/work/target-64"
$HostTargetDir = Join-Path $RepoRoot "target-64"
$DefaultBuild = $false

if ($args.Count -gt 0) {
    $ContainerArgs = $args
} else {
    $DefaultBuild = $true

    $Packages = @(
        @{name="rustyjack-ui"; cmd="cargo build --target $Target -p rustyjack-ui"; dir="rustyjack-ui"},
        @{name="rustyjackd"; cmd="cargo build --target $Target -p rustyjack-daemon"; dir="rustyjack-daemon"},
        @{name="rustyjack-portal"; cmd="cargo build --target $Target -p rustyjack-portal"; dir="rustyjack-portal"},
        @{name="rustyjack"; cmd="cargo build --target $Target -p rustyjack-core --bin rustyjack --features rustyjack-core/cli"; dir="rustyjack-core"}
    )

    $changed = @()

    # include working-tree changes (staged/unstaged)
    $por = git status --porcelain 2>$null
    if ($LASTEXITCODE -eq 0 -and $por) {
        $por -split "`n" | ForEach-Object {
            $line = $_.Trim()
            if ($line.Length -gt 3) {
                $f = $line.Substring(3)
                $changed += $f
            }
        }
    }

    # include committed diffs against upstream if available, otherwise last commit
    $upstream = git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>$null
    if ($LASTEXITCODE -eq 0 -and $upstream) {
        $diff = git diff --name-only "$upstream...HEAD" 2>$null
    } else {
        $diff = git diff --name-only HEAD~1..HEAD 2>$null
    }
    if ($diff) {
        $diff -split "`n" | ForEach-Object { $changed += $_.Trim() }
    }

    $changed = $changed | Where-Object { $_ -ne "" } | Select-Object -Unique

    $BuildParts = @()

    if ($changed.Count -eq 0) {
        Write-Host "No changed files detected via git; falling back to artifact existence check." -ForegroundColor Yellow
        foreach ($entry in $Packages) {
            $bin = $entry.name
            $srcPath = Join-Path $HostTargetDir "$Target\debug\$bin"
            if (Test-Path $srcPath) {
                Write-Host "Found existing target binary for $bin at $srcPath - skipping rebuild" -ForegroundColor Yellow
            } else {
                $BuildParts += $entry.cmd
            }
        }
        if ($BuildParts.Count -eq 0) {
            Write-Host "All target binaries exist - skipping docker build." -ForegroundColor Green
        } else {
            $BuildCmd = "set -euo pipefail; export PATH=/usr/local/cargo/bin:`$PATH; export CARGO_TARGET_DIR=$TargetDir; " + ($BuildParts -join "; ")
        }
    } else {
        # If workspace-level files changed, rebuild everything
        $workspaceChanged = $changed | Where-Object { $_ -match '(^|/)(Cargo.lock|Cargo.toml)$' }
        if ($workspaceChanged) {
            Write-Host "Workspace Cargo files changed; rebuilding all packages" -ForegroundColor Yellow
            $BuildParts = $Packages | ForEach-Object { $_.cmd }
            $BuildCmd = "set -euo pipefail; export PATH=/usr/local/cargo/bin:`$PATH; export CARGO_TARGET_DIR=$TargetDir; " + ($BuildParts -join "; ")
        } else {
            foreach ($entry in $Packages) {
                $dir = $entry.dir
                foreach ($f in $changed) {
                    if ($f -like "$dir/*" -or $f -like "$dir\*" -or $f -like "$dir/*" -or $f -like "*/$dir/*") {
                        $BuildParts += $entry.cmd
                        break
                    }
                }
            }
            $BuildParts = $BuildParts | Select-Object -Unique
            if ($BuildParts.Count -eq 0) {
                Write-Host "No package-specific changes detected; skipping docker build." -ForegroundColor Green
            } else {
                $BuildCmd = "set -euo pipefail; export PATH=/usr/local/cargo/bin:`$PATH; export CARGO_TARGET_DIR=$TargetDir; " + ($BuildParts -join "; ")
            }
        }
    }

    if ($BuildParts.Count -gt 0) {
        $ContainerArgs = @("bash", "-c", $BuildCmd)
    }
}

if ($args.Count -gt 0) {
    & "$RepoRoot\docker\arm64\run.ps1" @ContainerArgs
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
} elseif ($DefaultBuild) {
    if ($BuildParts.Count -gt 0) {
        Write-Host "Running build in Docker container..." -ForegroundColor Cyan
        Write-Host "Building: $($BuildParts.Count) package(s)" -ForegroundColor Yellow
        & "$RepoRoot\docker\arm64\run.ps1" @ContainerArgs
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    } else {
        Write-Host "Skipping build - no changes detected" -ForegroundColor Green
    }
}

if ($DefaultBuild) {
    $DestDir = Join-Path $RepoRoot "prebuilt\arm64"
    if (-not (Test-Path $DestDir)) {
        New-Item -ItemType Directory -Path $DestDir | Out-Null
    }

    $Bins = @("rustyjack-ui", "rustyjackd", "rustyjack-portal", "rustyjack")
    foreach ($bin in $Bins) {
        $Src = Join-Path $RepoRoot "target-64\$Target\debug\$bin"
        if (-not (Test-Path $Src)) {
            Write-Error "Missing binary: $Src"
            exit 1
        }
        Copy-Item -Force $Src (Join-Path $DestDir $bin)
    }
    Write-Host "Copied binaries to $DestDir"
}
exit 0
