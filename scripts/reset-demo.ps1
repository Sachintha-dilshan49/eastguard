<#
.SYNOPSIS
  Resets the EastGuard end-to-end demo: deletes the demo journal and logs\, then bootstraps a fresh journal.

.DESCRIPTION
  Run from anywhere:  .\scripts\reset-demo.ps1

  1. Refuses while a demo control plane holds the journal (stop run-demo.ps1 first, Ctrl+C).
  2. Deletes journal\demo-control.journal and everything under logs\.
  3. Runs the explicit administrator bootstrap (spec section 9.1):
       ControlPlaneImpl bootstrap --config config/demo-control.properties.example
                                  --state  config/demo-bootstrap.properties.example
     which writes revision 1: services app-02 and app-03, approved edges web-01>app-02 and web-01>app-03,
     ENFORCE, deny by default.

  Only the demo journal is touched; journal\control.journal of a hand-started control plane is left alone.
  Needs a build (out\) and keys\ (gen-certs.ps1, gen-credentials.ps1).

.PARAMETER KeepLogs
  Keep logs\ (only the journal is reset).
#>
param([switch]$KeepLogs)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$root = Split-Path -Parent $PSScriptRoot
$journal = Join-Path $root 'journal\demo-control.journal'
$logs = Join-Path $root 'logs'

$java = Get-Command java -ErrorAction SilentlyContinue
if (-not $java) { throw 'java not found on PATH: install JDK 21 and open a new terminal' }
if (-not (Test-Path -LiteralPath (Join-Path $root 'out\eastguard\control\ControlPlaneImpl.class'))) {
    throw 'out\ has no build: run .\scripts\sources.ps1 and  javac --release 21 -d out "@sources.txt"  first'
}
foreach ($f in @('keys\lease-k1.cer', 'keys\control-k1.cer', 'keys\control-credentials.properties')) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $f))) {
        throw "$f not found: run .\scripts\gen-certs.ps1 and .\scripts\gen-credentials.ps1 first"
    }
}

# A running control plane keeps the journal open (and locked); opening it without sharing then fails.
if (Test-Path -LiteralPath $journal) {
    try {
        $fs = [IO.File]::Open($journal, 'Open', 'ReadWrite', 'None')
        $fs.Dispose()
    } catch {
        throw "the demo journal is in use: stop run-demo.ps1 (Ctrl+C) before resetting"
    }
    Remove-Item -LiteralPath $journal -Force
    Write-Output "deleted journal\demo-control.journal"
}
if (-not $KeepLogs -and (Test-Path -LiteralPath $logs)) {
    Get-ChildItem -LiteralPath $logs -Force | Remove-Item -Recurse -Force
    Write-Output "cleared logs\"
}

Push-Location $root
try {
    # The JVM logs to stderr; under a redirected caller, Windows PowerShell 5.1 would turn that into errors.
    $ErrorActionPreference = 'Continue'
    & $java.Source -cp out eastguard.control.ControlPlaneImpl bootstrap `
        --config config/demo-control.properties.example `
        --state config/demo-bootstrap.properties.example `
        --actor admin --reason 'demo reset: deny-by-default policy for app-02 and app-03'
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($code -ne 0) { throw "bootstrap failed with exit code $code" }
} finally {
    Pop-Location
}
