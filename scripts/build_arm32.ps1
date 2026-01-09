#!/usr/bin/env pwsh
# Wrapper script - delegates to tests/compile/build_arm32.ps1
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
& "$RepoRoot\tests\compile\build_arm32.ps1"
