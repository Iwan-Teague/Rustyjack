# Deploy and Install Rustyjack on Pi Zero W 2
# Connects via SSH and runs installation commands

$piHost = "192.168.0.48"
$piUser = "rustyjack"
$piPassword = "Beakyblue123"

Write-Host "Deploying to Pi at $piHost..." -ForegroundColor Green
Write-Host ""

# Create SSH command script (run sequentially and check exit-codes)
$sshCommands = @'
#!/bin/bash
set -e

echo "==> CD to project"
cd /home/rustyjack/Rustyjack || { echo "ERROR: cannot cd to /home/rustyjack/Rustyjack"; exit 10; }

echo "==> git pull"
git pull || { echo "ERROR: git pull failed"; exit 11; }

echo "==> chmod +x install_rustyjack.sh"
chmod +x install_rustyjack.sh || { echo "ERROR: chmod failed"; exit 12; }

echo "==> running installer"
./install_rustyjack.sh || { echo "ERROR: installer failed"; exit 13; }

echo "\nAll done — dropping to interactive shell"
exec bash -l
'@

# Save commands to temporary file
$tempFile = [System.IO.Path]::GetTempFileName()
$sshCommands | Out-File -FilePath $tempFile -Encoding ASCII

Write-Host "Commands to execute:" -ForegroundColor Yellow
Write-Host $sshCommands
Write-Host ""
Write-Host "Connecting to Pi..." -ForegroundColor Cyan

# Basic preflight checks: ping and port 22 availability (helps diagnose immediate failures)
if (-not (Test-Connection -Count 1 -Quiet -ComputerName $piHost)) {
    Write-Host "WARNING: Host $piHost did not respond to ping. Network issue or host is down." -ForegroundColor Yellow
    Write-Host "Press Enter to continue anyway or Ctrl+C to abort." -ForegroundColor Yellow
    Read-Host | Out-Null
}

if (Get-Command Test-NetConnection -ErrorAction SilentlyContinue) {
    $portCheck = Test-NetConnection -ComputerName $piHost -Port 22 -WarningAction SilentlyContinue
    if (-not $portCheck.TcpTestSucceeded) {
        Write-Host "WARNING: Port 22 (SSH) on $piHost is not open/accepting. Remote SSH may be blocked or service stopped." -ForegroundColor Yellow
        Write-Host "Press Enter to continue anyway or Ctrl+C to abort." -ForegroundColor Yellow
        Read-Host | Out-Null
    }
}

# Try to run remote script; capture exit codes and provide clear diagnostics
try {
    $sshExit = 99

    # Use plink (PuTTY) if available
    if (Get-Command plink -ErrorAction SilentlyContinue) {
        Write-Host "Using plink (PuTTY) to run remote script..." -ForegroundColor Gray
        plink -ssh -pw $piPassword ${piUser}@${piHost} -m $tempFile -t
        $sshExit = $LASTEXITCODE
    }
    else {
        # Try OpenSSH with sshpass (unattended password), otherwise interactive ssh
        if (Get-Command sshpass -ErrorAction SilentlyContinue) {
                Write-Host "Using OpenSSH + sshpass to run remote script..." -ForegroundColor Gray
                # use Get-Content + pipeline instead of shell redirection so this is valid in PowerShell
                Get-Content -Raw $tempFile | sshpass -p $piPassword ssh -o StrictHostKeyChecking=no -t ${piUser}@${piHost} "bash -s"
                $sshExit = $LASTEXITCODE
        }
        else {
            # Check if ssh exists — if not, warn user and bail
            if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
                Write-Host "ERROR: No suitable SSH client found (ssh, sshpass, or plink). Please install OpenSSH (Windows feature) or PuTTY (plink)." -ForegroundColor Red
                $sshExit = 2
            }
            else {
                Write-Host "No sshpass found, falling back to interactive OpenSSH. You will be prompted for the password." -ForegroundColor Yellow
                # Feed script to single SSH session so commands run sequentially and then exec into interactive shell
                Get-Content -Raw $tempFile | ssh -t ${piUser}@${piHost} "bash -s"
                $sshExit = $LASTEXITCODE
            }
        }
    }

    if ($sshExit -ne 0) {
        Write-Host "\nERROR: Remote deployment or connection returned non-zero exit code: $sshExit" -ForegroundColor Red
        Write-Host "Please check the remote host logs and verify credentials/keys. If you need to run interactively, use PuTTY/plink or an OpenSSH client." -ForegroundColor Yellow
    }
    else {
        Write-Host "\nRemote commands completed successfully." -ForegroundColor Green
    }
}
catch {
    Write-Host "EXCEPTION while running remote commands: $($_.Exception.Message)" -ForegroundColor Red
}

# Cleanup
Remove-Item $tempFile -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Script complete. Press Enter to close this window." -ForegroundColor Green
try {
    # Read-Host is more robust than RawUI.ReadKey and works in more hosts (PowerShell, pwsh, and most run modes)
    Read-Host -Prompt 'Press Enter to close'
}
catch {
    # If Read-Host fails for some reason, fallback to a short sleep so the user has time to see console output
    Write-Host "(Read-Host unavailable; waiting 10 seconds before exit...)" -ForegroundColor Yellow
    Start-Sleep -Seconds 10
}
