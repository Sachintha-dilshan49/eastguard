# Packages production JARs into dist/ (excluding demo and test code)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root

if (-not (Test-Path (Join-Path $root 'out\eastguard'))) {
    Write-Output "No build found in out\. Building first..."
    & (Join-Path $PSScriptRoot 'sources.ps1')
    javac --release 21 -d out "@sources.txt"
}

$dist = Join-Path $root 'dist'
if (-not (Test-Path $dist)) { New-Item -ItemType Directory -Path $dist | Out-Null }

jar --create --file (Join-Path $dist 'eastguard-dashboard.jar') --main-class eastguard.dashboard.DashboardApp `
    -C out eastguard/dashboard `
    -C out eastguard/control `
    -C out eastguard/common `
    -C out eastguard/handlers

jar --create --file (Join-Path $dist 'eastguard-server.jar') `
    -C out eastguard/gateway `
    -C out eastguard/control `
    -C out eastguard/tokensvc `
    -C out eastguard/detector `
    -C out eastguard/bus `
    -C out eastguard/common `
    -C out eastguard/client `
    -C out eastguard/handlers

jar --create --file (Join-Path $dist 'eastguard-client.jar') `
    -C out eastguard/client `
    -C out eastguard/common

Write-Output "Production packages created in dist\:"
Get-ChildItem -Path $dist -Filter *.jar | Format-Table Name, Length, LastWriteTime
