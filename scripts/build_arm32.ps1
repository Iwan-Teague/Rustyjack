#!/usr/bin/env pwsh
# ARM32 cross-compilation build script for Windows
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..") | Select-Object -ExpandProperty Path
$Target = "armv7-unknown-linux-gnueabihf"
$TargetDir = "/work/target-32"
$HostTargetDir = Join-Path $RepoRoot "target-32"
$DockerRun = Join-Path $RepoRoot "docker\arm32\run.ps1"
$BuildMode = "debug"
$BuildProfileFlag = ""
$DefaultBuild = $false
$ContainerArgs = @()
$BuildRan = $false
$LastBuildStamp = Join-Path $HostTargetDir ".last_build_stamp"

$BuildInfoReady = $false
$BuildInfoEpoch = ""
$BuildInfoIso = ""
$BuildInfoGitHash = "unknown"
$BuildInfoGitDirty = "0"
$BuildInfoVariant = "development"
$BuildInfoProfile = "debug"
$BuildInfoEnv = ""

# USB export: set by Prompt-UsbExportEarly; empty string means skip
$UsbExportDrive = ""
$UsbAutoEject = $false

function Test-DockerRunning {
    try {
        $null = docker ps 2>$null
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

function Start-DockerDesktop {
    $DockerPaths = @(
        "C:\Program Files\Docker\Docker\Docker Desktop.exe",
        "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
        "${env:ProgramFiles(x86)}\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Programs\Docker\Docker Desktop.exe"
    )

    $DockerExe = $null
    foreach ($path in $DockerPaths) {
        if (Test-Path $path) {
            $DockerExe = $path
            break
        }
    }

    if (-not $DockerExe) {
        Write-Host "Docker Desktop executable not found. Please install Docker Desktop from:" -ForegroundColor Red
        Write-Host "https://www.docker.com/products/docker-desktop/" -ForegroundColor Yellow
        exit 1
    }

    Write-Host "Starting Docker Desktop..." -ForegroundColor Yellow
    Start-Process -FilePath $DockerExe

    Write-Host "Waiting for Docker Desktop to be ready..." -ForegroundColor Yellow
    $timeout = 120
    $elapsed = 0
    while (-not (Test-DockerRunning)) {
        Start-Sleep -Seconds 2
        $elapsed += 2
        if ($elapsed % 10 -eq 0) {
            Write-Host "Still waiting... ($elapsed seconds)" -ForegroundColor Gray
        }
        if ($elapsed -ge $timeout) {
            Write-Host "Docker Desktop did not start within $timeout seconds." -ForegroundColor Red
            Write-Host "Please start Docker Desktop manually and try again." -ForegroundColor Yellow
            exit 1
        }
    }
    Write-Host "Docker Desktop is ready!" -ForegroundColor Green
}

if (-not (Test-DockerRunning)) {
    Write-Host "Docker Desktop is not running." -ForegroundColor Yellow
    Start-DockerDesktop
} else {
    Write-Host "Docker Desktop is already running." -ForegroundColor Green
}

# Ensure target directory exists on host (for docker volume mount)
if (-not (Test-Path $HostTargetDir)) {
    New-Item -ItemType Directory -Path $HostTargetDir | Out-Null
}

function Ensure-GitHooks {
    if ($env:RUSTYJACK_SKIP_HOOKS -eq "1") { return }
    $gitInside = & git -C $RepoRoot rev-parse --is-inside-work-tree 2>$null
    if ($LASTEXITCODE -ne 0) { return }
    $hookScript = Join-Path $RepoRoot "scripts\\install_git_hooks.ps1"
    $currentHooks = & git -C $RepoRoot config --local --get core.hooksPath 2>$null
    $hooksPath = Join-Path $RepoRoot ".githooks"
    if ($LASTEXITCODE -eq 0 -and $currentHooks -and $currentHooks.Trim() -eq ".githooks") {
        Write-Host "Git hooks already configured (path: $hooksPath)." -ForegroundColor Green
        return
    }
    if (Test-Path $hookScript) {
        Write-Host "Configuring git hooks (path: $hooksPath)..." -ForegroundColor Yellow
        & $hookScript
    }
}

Ensure-GitHooks

function Test-Interactive {
    try {
        return [Environment]::UserInteractive -and $Host.UI -and $Host.UI.RawUI
    } catch {
        return $false
    }
}

function Prompt-BuildMode {
    while ($true) {
        $reply = Read-Host "Build release or dev binaries? [r/b]"
        if (-not $reply) { $reply = "b" }
        switch -Regex ($reply) {
            "^(r|R|release|RELEASE)$" {
                $script:BuildMode = "release"
                $script:BuildProfileFlag = "--release"
                return
            }
            "^(b|B|dev|DEV|debug|DEBUG)$" {
                $script:BuildMode = "debug"
                $script:BuildProfileFlag = ""
                return
            }
        }
        Write-Host "Please answer r (release) or b (dev)." -ForegroundColor Yellow
    }
}

function Compute-BuildInfo {
    if ($script:BuildInfoReady) { return }
    $script:BuildInfoReady = $true
    $now = [DateTimeOffset]::UtcNow
    $script:BuildInfoEpoch = $now.ToUnixTimeSeconds().ToString()
    $script:BuildInfoIso = $now.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $script:BuildInfoGitHash = "unknown"
    $script:BuildInfoGitDirty = "0"

    $gitInside = & git rev-parse --is-inside-work-tree 2>$null
    if ($LASTEXITCODE -eq 0) {
        $hash = & git rev-parse --short=12 HEAD 2>$null
        if ($LASTEXITCODE -eq 0 -and $hash) {
            $script:BuildInfoGitHash = $hash.Trim()
        }
        $por = & git status --porcelain 2>$null
        if ($LASTEXITCODE -eq 0 -and $por) {
            $script:BuildInfoGitDirty = "1"
        }
    }

    $script:BuildInfoProfile = $script:BuildMode
    if ($script:BuildMode -eq "release") {
        $script:BuildInfoVariant = "release"
    } else {
        $script:BuildInfoVariant = "development"
    }

    $script:BuildInfoEnv = "export RUSTYJACK_BUILD_EPOCH='$script:BuildInfoEpoch'; " +
        "export RUSTYJACK_BUILD_ISO='$script:BuildInfoIso'; " +
        "export RUSTYJACK_GIT_HASH='$script:BuildInfoGitHash'; " +
        "export RUSTYJACK_GIT_DIRTY='$script:BuildInfoGitDirty'; " +
        "export RUSTYJACK_BUILD_PROFILE='$script:BuildInfoProfile'; " +
        "export RUSTYJACK_BUILD_VARIANT='$script:BuildInfoVariant'; " +
        "export RUSTYJACK_BUILD_TARGET='$Target'; " +
        "export RUSTYJACK_BUILD_ARCH='arm32';"
}

function Test-FileNewerThanStamp {
    param(
        [string]$Path,
        [DateTime]$StampTime
    )
    if (-not (Test-Path $Path)) { return $false }
    $fileTime = (Get-Item $Path).LastWriteTime
    return $fileTime -gt $StampTime
}

function Test-DirNewerThanStamp {
    param(
        [string]$Path,
        [DateTime]$StampTime
    )
    if (-not (Test-Path $Path)) { return $false }
    $hit = Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $StampTime } | Select-Object -First 1
    return $null -ne $hit
}

function Get-FileEpoch {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    try {
        $time = (Get-Item $Path).LastWriteTimeUtc
        return ([DateTimeOffset]::new($time)).ToUnixTimeSeconds()
    } catch {
        return 0
    }
}

function Get-LatestSourceEpoch {
    $maxEpoch = 0
    $gitInside = & git -C $RepoRoot rev-parse --is-inside-work-tree 2>$null
    if ($LASTEXITCODE -ne 0) { return 0 }
    $raw = & git -C $RepoRoot ls-files -z 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $raw) { return 0 }
    $files = $raw -split "`0"
    foreach ($file in $files) {
        if (-not $file) { continue }
        $normalized = $file.Replace("\\", "/")
        if (-not ($normalized -eq "Cargo.toml" -or $normalized -eq "Cargo.lock" -or $normalized -eq ".cargo/config" -or $normalized -eq ".cargo/config.toml" -or $normalized -like "crates/*")) {
            continue
        }
        $path = Join-Path $RepoRoot $normalized
        if (-not (Test-Path $path)) { continue }
        $epoch = Get-FileEpoch -Path $path
        if ($epoch -gt $maxEpoch) {
            $maxEpoch = $epoch
        }
    }
    return $maxEpoch
}

function Get-SelectedBuildEpoch {
    $info = Join-Path $HostTargetDir "$Target\$BuildMode\build_info.txt"
    if (Test-Path $info) {
        $line = Get-Content $info | Where-Object { $_ -match "^build_epoch=" } | Select-Object -First 1
        if ($line) {
            $value = $line -replace "^build_epoch=", ""
            $parsed = 0L
            if ([long]::TryParse($value, [ref]$parsed)) {
                return $parsed
            }
        }
    }

    $bins = @("rustyjack-ui", "rustyjackd", "rustyjack-hotplugd", "rustyjack-shellops", "rustyjack-portal", "rustyjack")
    $minEpoch = 0
    foreach ($bin in $bins) {
        $path = Join-Path $HostTargetDir "$Target\$BuildMode\$bin"
        if (-not (Test-Path $path)) { return 0 }
        $epoch = Get-FileEpoch -Path $path
        if ($epoch -le 0) { continue }
        if ($minEpoch -eq 0 -or $epoch -lt $minEpoch) {
            $minEpoch = $epoch
        }
    }
    return $minEpoch
}

function Test-SelectedBinariesUpToDate {
    $sourceEpoch = Get-LatestSourceEpoch
    if ($sourceEpoch -le 0) {
        Write-Host "WARN: unable to determine latest source timestamp; skipping freshness check." -ForegroundColor Yellow
        return $true
    }
    $buildEpoch = Get-SelectedBuildEpoch
    if ($buildEpoch -le 0) { return $false }
    if ($buildEpoch -lt $sourceEpoch) { return $false }
    return $true
}

if ($args.Count -gt 0) {
    $ContainerArgs = $args
} else {
    $DefaultBuild = $true
    if (Test-Interactive) {
        Prompt-BuildMode
        $UsbVariant = if ($BuildMode -eq "release") { "release" } else { "development" }
        Prompt-UsbExportEarly -Arch "arm32" -Variant $UsbVariant
    } else {
        Write-Host "Non-interactive shell detected; defaulting to dev build." -ForegroundColor Yellow
    }

    $Packages = @(
        @{name="rustyjack-ui"; cmd="cargo build $BuildProfileFlag --target $Target -p rustyjack-ui"; dir="crates/rustyjack-ui"},
        @{name="rustyjackd"; cmd="cargo build $BuildProfileFlag --target $Target -p rustyjack-daemon"; dir="crates/rustyjack-daemon"},
        @{name="rustyjack-hotplugd"; cmd="cargo build $BuildProfileFlag --target $Target -p rustyjack-daemon --bin rustyjack-hotplugd"; dir="crates/rustyjack-daemon"},
        @{name="rustyjack-shellops"; cmd="cargo build $BuildProfileFlag --target $Target -p rustyjack-daemon --bin rustyjack-shellops"; dir="crates/rustyjack-daemon"},
        @{name="rustyjack-portal"; cmd="cargo build $BuildProfileFlag --target $Target -p rustyjack-portal"; dir="crates/rustyjack-portal"},
        @{name="rustyjack"; cmd="cargo build $BuildProfileFlag --target $Target -p rustyjack-core --bin rustyjack --features rustyjack-core/cli"; dir="crates/rustyjack-core"}
    )

    $changed = @()
    $por = & git status --porcelain 2>$null
    if ($LASTEXITCODE -eq 0 -and $por) {
        $por -split "`n" | ForEach-Object {
            $line = $_.Trim()
            if ($line.Length -gt 3) {
                $f = $line.Substring(3)
                if ($f -match " -> ") {
                    $f = $f.Split(" -> ")[-1]
                }
                $changed += $f
            }
        }
    }

    $changed = $changed | Where-Object { $_ -ne "" } | ForEach-Object { $_.Replace("\\", "/") } | Select-Object -Unique

    $BuildParts = @()
    $BuildCmds = @()

    $workspaceChanged = $false
    $stampTime = $null

    if (-not (Test-Path $LastBuildStamp)) {
        Write-Host "No build stamp found; rebuilding all packages." -ForegroundColor Yellow
        $workspaceChanged = $true
    } else {
        $stampTime = (Get-Item $LastBuildStamp).LastWriteTime
        $cargoFiles = @("Cargo.toml", "Cargo.lock", ".cargo/config.toml", ".cargo/config")
        foreach ($f in $cargoFiles) {
            $path = Join-Path $RepoRoot $f
            if (Test-FileNewerThanStamp -Path $path -StampTime $stampTime) {
                $workspaceChanged = $true
                break
            }
        }

        if (-not $workspaceChanged) {
            $cratesRoot = Join-Path $RepoRoot "crates"
            if (Test-Path $cratesRoot) {
                foreach ($dir in Get-ChildItem -Path $cratesRoot -Directory) {
                    switch ($dir.Name) {
                        "rustyjack-ui" { continue }
                        "rustyjack-daemon" { continue }
                        "rustyjack-portal" { continue }
                        default {
                            if (Test-DirNewerThanStamp -Path $dir.FullName -StampTime $stampTime) {
                                $workspaceChanged = $true
                                break
                            }
                        }
                    }
                }
            }
        }
    }

    if ($changed.Count -eq 0 -and -not $workspaceChanged) {
        Write-Host "No local changes detected; falling back to artifact existence check." -ForegroundColor Yellow
        foreach ($entry in $Packages) {
            $bin = $entry.name
            $srcPath = Join-Path $HostTargetDir "$Target\$BuildMode\$bin"
            if (Test-Path $srcPath) {
                Write-Host "Found existing target binary for $bin at $srcPath - skipping rebuild" -ForegroundColor Yellow
            } else {
                $BuildParts += $entry.cmd
                $BuildCmds += $entry.cmd
            }
        }
        if ($BuildParts.Count -eq 0) {
            Write-Host "All target binaries exist - skipping docker build." -ForegroundColor Green
        }
    } else {
        if ($workspaceChanged) {
            Write-Host "Workspace changes detected; rebuilding all packages" -ForegroundColor Yellow
            foreach ($entry in $Packages) {
                $BuildParts += $entry.cmd
                $BuildCmds += $entry.cmd
            }
        } else {
            foreach ($entry in $Packages) {
                $dir = $entry.dir
                $dirPath = Join-Path $RepoRoot $dir
                $shouldBuild = $false

                if ($stampTime -ne $null -and (Test-DirNewerThanStamp -Path $dirPath -StampTime $stampTime)) {
                    $shouldBuild = $true
                } else {
                    foreach ($f in $changed) {
                        if ($f -like "$dir/*" -or $f -like "*/$dir/*") {
                            $shouldBuild = $true
                            break
                        }
                    }
                }

                if ($shouldBuild) {
                    $BuildParts += $entry.cmd
                    $BuildCmds += $entry.cmd
                }
            }
        }

        $BuildParts = $BuildParts | Select-Object -Unique
        $BuildCmds = $BuildCmds | Select-Object -Unique

        if ($BuildParts.Count -eq 0) {
            Write-Host "No package-specific changes detected; skipping docker build." -ForegroundColor Green
        }
    }

    if ($BuildParts.Count -gt 0) {
        Compute-BuildInfo
        $BuildCmd = "set -euo pipefail; export PATH=/usr/local/cargo/bin:`$PATH; export CARGO_TARGET_DIR=$TargetDir; $BuildInfoEnv " + ($BuildCmds -join "; ")
        $ContainerArgs = @("bash", "-c", $BuildCmd)
    }

    if ($DefaultBuild -and $BuildParts.Count -eq 0) {
        if (Test-SelectedBinariesUpToDate) {
            Write-Host "Selected $BuildMode binaries appear up-to-date." -ForegroundColor Green
        } else {
            Write-Host "Selected $BuildMode binaries are older than source; rebuilding." -ForegroundColor Yellow
            $BuildParts = @()
            $BuildCmds = @()
            foreach ($entry in $Packages) {
                $BuildParts += $entry.cmd
                $BuildCmds += $entry.cmd
            }
            Compute-BuildInfo
            $BuildCmd = "set -euo pipefail; export PATH=/usr/local/cargo/bin:`$PATH; export CARGO_TARGET_DIR=$TargetDir; $BuildInfoEnv " + ($BuildCmds -join "; ")
            $ContainerArgs = @("bash", "-c", $BuildCmd)
        }
    }
}

if ($args.Count -gt 0) {
    $env:DOCKER_VOLUMES_EXTRA = "$HostTargetDir`:$TargetDir"
    & $DockerRun @ContainerArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} elseif ($DefaultBuild) {
    if ($BuildParts.Count -gt 0) {
        Write-Host "Running build in Docker container..." -ForegroundColor Cyan
        Write-Host "Building: $($BuildParts.Count) package(s)" -ForegroundColor Yellow
        $BuildRan = $true
        $env:DOCKER_VOLUMES_EXTRA = "$HostTargetDir`:$TargetDir"
        & $DockerRun @ContainerArgs
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } else {
        Write-Host "Skipping build - no changes detected" -ForegroundColor Green
    }
}

if ($DefaultBuild) {
    $Bins = @("rustyjack-ui", "rustyjackd", "rustyjack-hotplugd", "rustyjack-shellops", "rustyjack-portal", "rustyjack")
    $MissingBinaries = @()
    foreach ($bin in $Bins) {
        $Src = Join-Path $HostTargetDir "$Target\$BuildMode\$bin"
        if (-not (Test-Path $Src)) {
            $MissingBinaries += $bin
        }
    }

    if ($MissingBinaries.Count -gt 0 -and $BuildParts.Count -eq 0) {
        Write-Host "WARNING: Expected binaries missing but no build was triggered" -ForegroundColor Yellow
        Write-Host "Building all packages as fallback..." -ForegroundColor Yellow

        Compute-BuildInfo
        $AllPackageCmds = $Packages | ForEach-Object { $_.cmd }
        $BuildCmd = "set -euo pipefail; export PATH=/usr/local/cargo/bin:`$PATH; export CARGO_TARGET_DIR=$TargetDir; $BuildInfoEnv " + ($AllPackageCmds -join "; ")
        $ContainerArgs = @("bash", "-c", $BuildCmd)

        $env:DOCKER_VOLUMES_EXTRA = "$HostTargetDir`:$TargetDir"
        $BuildRan = $true
        & $DockerRun @ContainerArgs

        if ($LASTEXITCODE -ne 0) {
            Write-Host "Fallback build failed" -ForegroundColor Red
            exit $LASTEXITCODE
        }

        Write-Host "Fallback build completed successfully" -ForegroundColor Green
    }

    if ($BuildRan) {
        Set-Content -Path $LastBuildStamp -Value $BuildInfoEpoch
        $BuildInfoFile = Join-Path $HostTargetDir "$Target\$BuildMode\build_info.txt"
        $BuildInfoDir = Split-Path -Parent $BuildInfoFile
        if (-not (Test-Path $BuildInfoDir)) {
            New-Item -ItemType Directory -Path $BuildInfoDir | Out-Null
        }
        @(
            "build_epoch=$BuildInfoEpoch",
            "build_iso=$BuildInfoIso",
            "git_hash=$BuildInfoGitHash",
            "git_dirty=$BuildInfoGitDirty",
            "build_profile=$BuildInfoProfile",
            "build_variant=$BuildInfoVariant",
            "target=$Target",
            "arch=arm32"
        ) | Set-Content -Path $BuildInfoFile
    }

    $PrebuiltVariant = if ($BuildMode -eq "release") { "release" } else { "development" }
    $DestDir = Join-Path $RepoRoot "prebuilt\arm32\$PrebuiltVariant"
    if (-not (Test-Path $DestDir)) {
        New-Item -ItemType Directory -Path $DestDir | Out-Null
    }

    foreach ($bin in $Bins) {
        $Src = Join-Path $HostTargetDir "$Target\$BuildMode\$bin"
        if (-not (Test-Path $Src)) {
            Write-Error "Missing binary: $Src"
            exit 1
        }
        Copy-Item -Force $Src (Join-Path $DestDir $bin)
    }

    $BuildInfoFile = Join-Path $HostTargetDir "$Target\$BuildMode\build_info.txt"
    if (Test-Path $BuildInfoFile) {
        Copy-Item -Force $BuildInfoFile (Join-Path $DestDir "build_info.txt")
    } else {
        Write-Host "WARNING: build_info.txt not found in target directory" -ForegroundColor Yellow
    }

    Write-Host "Copied binaries to $DestDir" -ForegroundColor Green

    # --- USB export (drive selected at startup) ---
    Invoke-UsbExport -Arch "arm32" -Variant $PrebuiltVariant -SourceDir $DestDir
}

function Get-UsbVolumes {
    $usbs = @()
    try {
        $removableDisks = Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.BusType -eq "USB" }
        foreach ($disk in $removableDisks) {
            $partitions = Get-Partition -DiskNumber $disk.DiskNumber -ErrorAction SilentlyContinue
            foreach ($part in $partitions) {
                $vol = Get-Volume -Partition $part -ErrorAction SilentlyContinue
                if ($vol -and $vol.DriveLetter) {
                    $label = if ($vol.FileSystemLabel) { $vol.FileSystemLabel } else { "No Label" }
                    $sizeMB = [math]::Round($vol.Size / 1MB)
                    $usbs += [PSCustomObject]@{
                        DriveLetter = "$($vol.DriveLetter):"
                        Label       = $label
                        SizeMB      = $sizeMB
                        FileSystem  = $vol.FileSystem
                    }
                }
            }
        }
    } catch {
        # Fall back to WMI if Get-Disk is unavailable
        try {
            $wmiVols = Get-WmiObject Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 2 }
            foreach ($v in $wmiVols) {
                $label = if ($v.VolumeName) { $v.VolumeName } else { "No Label" }
                $sizeMB = [math]::Round($v.Size / 1MB)
                $usbs += [PSCustomObject]@{
                    DriveLetter = $v.DeviceID
                    Label       = $label
                    SizeMB      = $sizeMB
                    FileSystem  = $v.FileSystem
                }
            }
        } catch {}
    }
    return $usbs
}

# Called at startup: ask the user upfront and store the chosen drive letter.
# Sets $script:UsbExportDrive to the chosen drive (e.g. "E:") or "" to skip.
function Prompt-UsbExportEarly {
    param([string]$Arch, [string]$Variant)

    $reply = Read-Host "Copy prebuilt binaries to a USB drive after build? [y/N]"
    if ($reply -notmatch "^(y|Y|yes|YES)$") {
        Write-Host "USB export skipped." -ForegroundColor Gray
        $script:UsbExportDrive = ""
        return
    }

    $usbs = Get-UsbVolumes
    if ($usbs.Count -eq 0) {
        Write-Host "No USB drives detected. USB export will be skipped." -ForegroundColor Yellow
        $script:UsbExportDrive = ""
        return
    }

    Write-Host ""
    Write-Host "Detected USB drives:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $usbs.Count; $i++) {
        $u = $usbs[$i]
        Write-Host "  [$($i + 1)] $($u.DriveLetter)  $($u.Label)  ($($u.SizeMB) MB, $($u.FileSystem))" -ForegroundColor White
    }
    Write-Host ""

    $selection = $null
    while ($null -eq $selection) {
        $input = Read-Host "Select a drive [1-$($usbs.Count)]"
        $parsed = 0
        if ([int]::TryParse($input, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le $usbs.Count) {
            $selection = $usbs[$parsed - 1]
        } else {
            Write-Host "Invalid selection. Please enter a number between 1 and $($usbs.Count)." -ForegroundColor Yellow
        }
    }

    $script:UsbExportDrive = $selection.DriveLetter
    Write-Host "Will copy binaries to $($script:UsbExportDrive)\rustyjack\prebuilt\$Arch\$Variant after build." -ForegroundColor Cyan
    
    $ejectReply = Read-Host "Automatically eject USB after successful copy? [Y/n]"
    if ($ejectReply -match "^(n|N|no|NO)$") {
        $script:UsbAutoEject = $false
    } else {
        $script:UsbAutoEject = $true
    }
}

# Called after a successful build: performs the actual file copy.
function Invoke-UsbExport {
    param([string]$Arch, [string]$Variant, [string]$SourceDir)

    if (-not $script:UsbExportDrive) { return }

    $UsbDest = Join-Path $script:UsbExportDrive "rustyjack\prebuilt\$Arch\$Variant"
    Write-Host "Copying binaries to $UsbDest ..." -ForegroundColor Cyan

    try {
        if (Test-Path $UsbDest) {
            Write-Host "Removing existing files in $UsbDest ..." -ForegroundColor Gray
            Get-ChildItem -Path $UsbDest -File | Remove-Item -Force
        } else {
            New-Item -ItemType Directory -Path $UsbDest -Force | Out-Null
        }
        
        $files = Get-ChildItem -Path $SourceDir -File
        $totalFiles = $files.Count
        $currentFileNum = 0
        
        foreach ($file in $files) {
            $currentFileNum++
            $destPath = Join-Path $UsbDest $file.Name
            $fileSize = $file.Length
            $bufferSize = 64KB
            
            Write-Host "  [$currentFileNum/$totalFiles] $($file.Name) ($([math]::Round($fileSize / 1MB, 2)) MB)" -ForegroundColor White
            
            try {
                $sourceStream = [System.IO.File]::OpenRead($file.FullName)
                $destStream = [System.IO.File]::Create($destPath)
                $buffer = New-Object byte[] $bufferSize
                $totalBytesRead = 0
                
                $barLength = 50
                while (($bytesRead = $sourceStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $destStream.Write($buffer, 0, $bytesRead)
                    $totalBytesRead += $bytesRead
                    
                    $progressPercent = [math]::Round(($totalBytesRead / $fileSize) * 100)
                    $filledLength = [math]::Round(($progressPercent / 100) * $barLength)
                    $bar = ('#' * $filledLength) + ('-' * ($barLength - $filledLength))
                    
                    $mbCopied = [math]::Round($totalBytesRead / 1MB, 2)
                    $mbTotal = [math]::Round($fileSize / 1MB, 2)
                    Write-Host "`r    [$bar] $progressPercent% ($mbCopied/$mbTotal MB)" -NoNewline -ForegroundColor Cyan
                }
                
                Write-Host ""
                
                $destStream.Close()
                $sourceStream.Close()
            } catch {
                if ($sourceStream) { $sourceStream.Close() }
                if ($destStream) { $destStream.Close() }
                throw
            }
        }
        
        Write-Host ""
        Write-Host "USB export complete: $UsbDest" -ForegroundColor Green
        
        if ($script:UsbAutoEject) {
            Write-Host "Ejecting USB drive $($script:UsbExportDrive) ..." -ForegroundColor Yellow
            try {
                # Flush file system buffers first (requires admin on some systems)
                $driveLetter = $script:UsbExportDrive.TrimEnd(':')
                try {
                    Write-VolumeCache -DriveLetter $driveLetter -ErrorAction Stop | Out-Null
                } catch {
                    # Write-VolumeCache might fail without admin; try sync via .NET
                    [System.IO.File]::WriteAllBytes("$($script:UsbExportDrive)\.flush", @())
                    Remove-Item "$($script:UsbExportDrive)\.flush" -ErrorAction SilentlyContinue
                }
                Start-Sleep -Milliseconds 500
                
                # Build WMI filter with proper escaping
                $driveLetterWithColon = $script:UsbExportDrive
                $driveObj = Get-WmiObject Win32_Volume -Filter "DriveLetter = '$driveLetterWithColon'" -ErrorAction SilentlyContinue
                if ($driveObj) {
                    $result = $driveObj.Dismount($false, $false)
                    if ($result.ReturnValue -eq 0) {
                        Write-Host "USB drive ejected successfully. Safe to remove." -ForegroundColor Green
                    } else {
                        Write-Host "Failed to eject USB drive (error code: $($result.ReturnValue)). Please eject manually." -ForegroundColor Yellow
                        Write-Host "You may need to close any programs accessing the drive." -ForegroundColor Gray
                    }
                } else {
                    Write-Host "Could not find USB drive to eject. Please eject manually." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Failed to eject USB: $_" -ForegroundColor Yellow
                Write-Host "Please eject the USB drive manually." -ForegroundColor Yellow
            }
        } else {
            Write-Host "Remember to eject the USB drive before removing it." -ForegroundColor Yellow
        }
    } catch {
        Write-Host ""
        Write-Host "ERROR: Failed to copy to USB: $_" -ForegroundColor Red
    }
}

exit 0
