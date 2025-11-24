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
Write-Host "Press Enter to continue or Ctrl+C to cancel..." -ForegroundColor Cyan
try { Read-Host -Prompt 'Press Enter to continue or Ctrl+C to cancel' } catch { Start-Sleep -Seconds 1 }
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

try {
	# Save script to a temp file and run it over one SSH connection so the commands run sequentially
	$tmp = [System.IO.Path]::GetTempFileName()
	$remoteScript | Out-File -FilePath $tmp -Encoding ASCII

	Write-Host "Connecting to Pi..." -ForegroundColor Green
	Write-Host "Please enter password when prompted: Beakyblue123" -ForegroundColor Yellow
	Write-Host ""

	# Preflight network checks — ping and SSH port
	if (-not (Test-Connection -Count 1 -Quiet -ComputerName $piHost)) {
		Write-Host "WARNING: Host $piHost did not respond to ping. Host may be offline or unreachable." -ForegroundColor Yellow
		Write-Host "Press Enter to continue anyway or Ctrl+C to abort." -ForegroundColor Yellow
		Read-Host | Out-Null
	}

	if (Get-Command Test-NetConnection -ErrorAction SilentlyContinue) {
		$portCheck = Test-NetConnection -ComputerName $piHost -Port 22 -WarningAction SilentlyContinue
		if (-not $portCheck.TcpTestSucceeded) {
			Write-Host "WARNING: Port 22 (SSH) on $piHost is not responding. Remote SSH may not be available." -ForegroundColor Yellow
			Write-Host "Press Enter to continue anyway or Ctrl+C to abort." -ForegroundColor Yellow
			Read-Host | Out-Null
		}
	}

	# Stream local script into ssh stdin in a PowerShell-friendly way
	if (Get-Command ssh -ErrorAction SilentlyContinue) {
		Write-Host "Detected SSH client: $((Get-Command ssh).Path)" -ForegroundColor Gray
		Get-Content -Raw $tmp | ssh -t ${piUser}@${piHost} "bash -s"
		$sshExit = $LASTEXITCODE
	} else {
		Write-Host "ERROR: 'ssh' command not found on this machine. Please install OpenSSH client or use plink." -ForegroundColor Red
		$sshExit = 1
	}

	if ($sshExit -ne 0) {
		Write-Host "Remote connection or command failed (exit code: $sshExit)" -ForegroundColor Red
	} else {
		Write-Host "Remote commands completed — interactive shell should be open." -ForegroundColor Green
	}
}
catch {
	Write-Host "EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
	# Clean up
	if (Test-Path $tmp) { Remove-Item $tmp -ErrorAction SilentlyContinue }
	Write-Host "\nScript complete. Press Enter to close this window." -ForegroundColor Cyan
	try { Read-Host -Prompt 'Press Enter to close' } catch { Start-Sleep -Seconds 10 }
}
