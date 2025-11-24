@echo off
REM Wrapper that launches the deploy_to_pi_simple.ps1 in a PowerShell window and keeps the window open.
REM Double-click this file to run the script and keep the shell visible.

SET SCRIPT_PATH=%~dp0deploy_to_pi_simple.ps1
powershell -NoProfile -NoExit -ExecutionPolicy Bypass -File "%SCRIPT_PATH%"
pause
