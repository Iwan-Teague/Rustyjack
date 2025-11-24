# Simple Deploy Script for Rustyjack on Pi
# This version keeps an interactive SSH session open

$piHost = "192.168.0.48"
$piUser = "rustyjack"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  Rustyjack Deployment Script" -ForegroundColor Green
Write-Host "  Target: $piUser@$piHost" -ForegroundColor Yellow
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Password: Beakyblue123" -ForegroundColor Yellow
Write-Host ""
Write-Host "This script will:" -ForegroundColor White
Write-Host "  1. Connect to the Pi via SSH" -ForegroundColor Gray
Write-Host "  2. Switch to root user" -ForegroundColor Gray
Write-Host "  3. Navigate to Rustyjack directory" -ForegroundColor Gray
Write-Host "  4. Pull latest changes from git" -ForegroundColor Gray
Write-Host "  5. Run installation script" -ForegroundColor Gray
Write-Host "  6. Keep terminal alive for you" -ForegroundColor Gray
Write-Host ""
Write-Host "Press any key to continue or Ctrl+C to cancel..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""

# Build a temporary script that will run each command sequentially on the Pi
$remoteScript = @'
#!/bin/bash
set -e

echo "==> Changing to Rustyjack directory"
cd /home/rustyjack/Rustyjack || { echo "ERROR: cannot cd to /home/rustyjack/Rustyjack"; exit 10; }

echo "==> Pulling latest changes (git pull)"
git pull || { echo "ERROR: git pull failed"; exit 11; }

echo "==> Setting executable flag on installer"
chmod +x install_rustyjack.sh || { echo "ERROR: chmod failed"; exit 12; }

echo "==> Running installer: ./install_rustyjack.sh"
./install_rustyjack.sh || { echo "ERROR: installer failed"; exit 13; }

echo "\nAll commands finished successfully. Dropping to an interactive shell..." 
exec bash -l
'@

# Save script to a temp file and run it over one SSH connection so the commands run sequentially
$tmp = [System.IO.Path]::GetTempFileName()
$remoteScript | Out-File -FilePath $tmp -Encoding ASCII

Write-Host "Connecting to Pi..." -ForegroundColor Green
Write-Host "Please enter password when prompted: Beakyblue123" -ForegroundColor Yellow
Write-Host ""

# Copy the script into ssh stdin and run it on the remote side. Using one SSH connection keeps a single password prompt
ssh -t ${piUser}@${piHost} "bash -s" < $tmp

# Clean up
Remove-Item $tmp -ErrorAction SilentlyContinue
