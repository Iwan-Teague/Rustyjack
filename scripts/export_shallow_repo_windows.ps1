Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Command {
  param([string]$Name)
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "$Name not found in PATH."
  }
}

Assert-Command git

$repoRoot = (& git rev-parse --show-toplevel).Trim()
if (-not $repoRoot) {
  throw "Not inside a git repository."
}

$repoName = Split-Path -Path $repoRoot -Leaf
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("rustyjack_shallow_" + $timestamp)
$cloneDir = Join-Path $workDir $repoName
$zipPath = Join-Path $repoRoot ("{0}_shallow_{1}.zip" -f $repoName, $timestamp)

New-Item -ItemType Directory -Path $workDir | Out-Null

& git clone --depth 1 --no-tags --no-local $repoRoot $cloneDir | Out-Null

Remove-Item -Recurse -Force (Join-Path $cloneDir ".git")

# Blacklist-only export model:
# keep repository content as-is, excluding git metadata and build/binary artifacts.
$excludeDirs = @("target", "build", "prebuilt", "bin")
$excludeDirPrefixes = @("target-", "build-")
$excludeFileGlobs = @(
  "*.o", "*.obj", "*.a", "*.so", "*.so.*", "*.dylib", "*.dll", "*.exe",
  "*.rlib", "*.rmeta", "*.d", "*.pdb", "*.zip"
)

foreach ($name in $excludeDirs) {
  Get-ChildItem -Path $cloneDir -Recurse -Directory -Force |
    Where-Object { $_.Name -ieq $name } |
    ForEach-Object { Remove-Item -Recurse -Force $_.FullName }
}

foreach ($prefix in $excludeDirPrefixes) {
  Get-ChildItem -Path $cloneDir -Recurse -Directory -Force |
    Where-Object { $_.Name -like "$prefix*" } |
    ForEach-Object { Remove-Item -Recurse -Force $_.FullName }
}

foreach ($glob in $excludeFileGlobs) {
  Get-ChildItem -Path $cloneDir -Recurse -File -Filter $glob -Force |
    ForEach-Object { Remove-Item -Force $_.FullName }
}

if (Test-Path $zipPath) {
  Remove-Item -Force $zipPath
}

Compress-Archive -Path $cloneDir -DestinationPath $zipPath -Force

Remove-Item -Recurse -Force $workDir

Write-Output "Wrote $zipPath"
