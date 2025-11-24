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

# Use plink (PuTTY) if available, otherwise use OpenSSH
if (Get-Command plink -ErrorAction SilentlyContinue) {
    # Using PuTTY's plink
    Write-Host "Using plink (PuTTY)..." -ForegroundColor Gray
    # Run the script file via plink (-m feeds the remote commands). plink will execute the temp script sequentially.
    plink -ssh -pw $piPassword ${piUser}@${piHost} -m $tempFile -t
} else {
    # Using OpenSSH with sshpass (if available) or manual password entry
    if (Get-Command sshpass -ErrorAction SilentlyContinue) {
        Write-Host "Using OpenSSH with sshpass..." -ForegroundColor Gray
        # sshpass with provided password runs the script sequentially (-T to read script from file)
        sshpass -p $piPassword ssh -o StrictHostKeyChecking=no -t ${piUser}@${piHost} "bash -s" < $tempFile
    } else {
        # Manual password entry required
        Write-Host "Please enter password when prompted: $piPassword" -ForegroundColor Yellow
        Write-Host ""
        # interactive mode: feed the temp script to a single SSH session so commands execute sequentially then drop to shell
        ssh -t ${piUser}@${piHost} "bash -s" < $tempFile
    }
}

# Cleanup
Remove-Item $tempFile -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Green
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
