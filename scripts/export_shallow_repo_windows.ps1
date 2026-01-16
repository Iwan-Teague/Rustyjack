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

$allowedExtensions = @(".rs", ".toml", ".lock", ".md", ".txt", ".service", ".socket")
$allowedNamePatterns = @("LICENSE*", "COPYING*", "NOTICE*")

Get-ChildItem -Path $cloneDir -Recurse -File | ForEach-Object {
  $ext = $_.Extension.ToLowerInvariant()
  $name = $_.Name
  $allow = $allowedExtensions -contains $ext
  if (-not $allow) {
    foreach ($pattern in $allowedNamePatterns) {
      if ($name -like $pattern) {
        $allow = $true
        break
      }
    }
  }
  if (-not $allow) {
    Remove-Item -Force $_.FullName
  }
}

Get-ChildItem -Path $cloneDir -Recurse -Directory |
  Sort-Object FullName -Descending |
  Where-Object { -not (Get-ChildItem -Path $_.FullName -Force) } |
  Remove-Item -Force

if (Test-Path $zipPath) {
  Remove-Item -Force $zipPath
}

Compress-Archive -Path $cloneDir -DestinationPath $zipPath -Force

Remove-Item -Recurse -Force $workDir

Write-Output "Wrote $zipPath"
