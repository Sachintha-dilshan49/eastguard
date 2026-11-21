<#
.SYNOPSIS
  Provisions EastGuard control-plane API credentials (spec §7.1): one high-entropy secret per principal.

.DESCRIPTION
  Run from anywhere:  .\scripts\gen-credentials.ps1

  For each principal it writes, under -OutDir (default <project>\keys, git-ignored):
    api\<principal>.secret            32 random bytes, base64url, readable by the current user only.
                                      The component that acts as this principal reads it (control.secretFile).
    control-credentials.properties    principal list, role, and SHA-256 digests of the secrets.
                                      Only the control plane reads it (credentials.file); it never holds secrets.

  The control plane reloads the credentials file when it changes, so rotation and revocation need no restart.
  Secrets are never printed and never passed on a command line.

.PARAMETER Principals
  name:ROLE pairs. Roles: VIEWER, OPERATOR, ADMIN, GATEWAY, ISSUER, DETECTOR.
.PARAMETER Add
  name:ROLE pairs to add to an existing credentials file, e.g.
  -Add console-viewer:VIEWER,console-operator:OPERATOR,console-admin:ADMIN
  Existing principals, digests and secret files are kept; a name that already exists is refused.
.PARAMETER Force
  Replace all existing credentials.
.PARAMETER Rotate
  Issue a new secret for one principal and keep its old digest as well, so clients can switch over. Run with
  -Retire later to drop the old digest.
.PARAMETER Retire
  Keep only the newest digest of one principal (end of a rotation).
.PARAMETER TelemetryKeys
  Only create the UDP telemetry HMAC keys (one per producer, keys\telemetry\<producer>.key, 32 random bytes,
  base64url). Existing keys are kept unless -Force is given. A full run creates them as well.
.PARAMETER TelemetryProducers
  Telemetry producers that get a key: each gateway and the token service.
.PARAMETER Revoke
  Disable one principal (enabled=false). Its secret file is deleted.
#>
param(
    [string]$OutDir,
    [string[]]$Principals = @('admin:ADMIN', 'operator:OPERATOR', 'viewer:VIEWER', 'gw-app-02:GATEWAY',
        'tokensvc:ISSUER', 'detector:DETECTOR', 'console-viewer:VIEWER', 'console-operator:OPERATOR',
        'console-admin:ADMIN'),
    [string[]]$Add,
    [switch]$Force,
    [string]$Rotate,
    [string]$Retire,
    [string]$Revoke,
    [switch]$TelemetryKeys,
    [string[]]$TelemetryProducers = @('gw-app-02', 'tokensvc')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$root = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $root 'keys' }
$OutDir = [IO.Path]::GetFullPath($OutDir)
$apiDir = Join-Path $OutDir 'api'
$credFile = Join-Path $OutDir 'control-credentials.properties'
$telemetryDir = Join-Path $OutDir 'telemetry'
$roles = @('VIEWER', 'OPERATOR', 'ADMIN', 'GATEWAY', 'ISSUER', 'DETECTOR')
$idPattern = '^[a-z0-9][a-z0-9._-]{0,63}$'

function Protect-File([string]$Path) {
    try {
        # A fresh DACL-only descriptor: current user only, no inheritance. (Set-Acl with Get-Acl's object also
        # rewrites the audit section, which needs SeSecurityPrivilege once the file is already protected.)
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = New-Object Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'Allow')))
        [IO.File]::SetAccessControl($Path, $acl)
    } catch {
        Write-Warning "could not restrict access to $(Split-Path -Leaf $Path): $($_.Exception.Message)"
    }
}

function Write-Text([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding $false))
    Protect-File $Path
}

# Creates a new secret file for $Name and returns the lowercase hex SHA-256 of the raw secret bytes.
function New-Secret([string]$Name) {
    $raw = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($raw) } finally { $rng.Dispose() }
    $b64 = [Convert]::ToBase64String($raw).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    Write-Text (Join-Path $apiDir "$Name.secret") $b64
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digest = $sha.ComputeHash($raw) } finally { $sha.Dispose(); [Array]::Clear($raw, 0, $raw.Length) }
    return (($digest | ForEach-Object { $_.ToString('x2') }) -join '')
}

# Ordered principal table: name -> @{ role; digests (newest first); enabled }
function Read-Credentials {
    $t = [ordered]@{}
    if (-not (Test-Path -LiteralPath $credFile)) { return $t }
    $props = @{}
    foreach ($line in [IO.File]::ReadAllLines($credFile)) {
        if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
        $k, $v = $line -split '=', 2
        $props[$k.Trim()] = $v.Trim()
    }
    foreach ($name in ($props['principals'] -split ',' | Where-Object { $_ })) {
        $t[$name] = @{
            role    = $props["principal.$name.role"]
            digests = @($props["principal.$name.sha256"] -split ',' | Where-Object { $_ })
            enabled = ($props["principal.$name.enabled"] -ne 'false')
        }
    }
    return $t
}

function Write-Credentials($t) {
    $lines = @('# EastGuard control-plane API credentials: SHA-256 digests only, never secrets.',
        '# Generated by scripts/gen-credentials.ps1. Reloaded by the control plane when it changes.',
        "principals=$($t.Keys -join ',')")
    foreach ($name in $t.Keys) {
        $p = $t[$name]
        $lines += "principal.$name.role=$($p.role)"
        $lines += "principal.$name.sha256=$($p.digests -join ',')"
        $lines += "principal.$name.enabled=$(if ($p.enabled) { 'true' } else { 'false' })"
    }
    Write-Text $credFile (($lines -join "`n") + "`n")
}

function Require-Known($t, [string]$Name) {
    if (-not $t.Contains($Name)) { throw "unknown principal '$Name' in $credFile" }
}

# Creates keys\telemetry\<name>.key: this producer's own HMAC-SHA256 key for flow telemetry (spec §5.3). The
# producer (telemetry.keyFile) and the detector (producer.<name>.keyFile) read the same file.
function New-TelemetryKey([string]$Name) {
    if ($Name -notmatch $idPattern) { throw "invalid producer name '$Name'" }
    New-Item -ItemType Directory -Force -Path $telemetryDir | Out-Null
    $path = Join-Path $telemetryDir "$Name.key"
    if ((Test-Path -LiteralPath $path) -and -not $Force) {
        Write-Output "  telemetry\$Name.key exists (kept; -Force replaces it)"
        return
    }
    $raw = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($raw) } finally { $rng.Dispose() }
    Write-Text $path ([Convert]::ToBase64String($raw).TrimEnd('=').Replace('+', '-').Replace('/', '_'))
    [Array]::Clear($raw, 0, $raw.Length)
    Write-Output "  telemetry\$Name.key"
}

New-Item -ItemType Directory -Force -Path $apiDir | Out-Null
$table = Read-Credentials

if ($TelemetryKeys) {
    foreach ($p in $TelemetryProducers) { New-TelemetryKey $p }
    exit 0
}

if ($Add) {
    if ($table.Count -eq 0) { throw "$credFile does not exist; run this script without -Add first" }
    $new = [ordered]@{}
    # "-Add a:B,c:D" arrives as one string through powershell -File; split it either way.
    foreach ($entry in @($Add | ForEach-Object { $_ -split ',' } | Where-Object { $_ })) {
        $name, $role = $entry -split ':', 2
        if ($name -notmatch $idPattern) { throw "invalid principal name '$name'" }
        if ($roles -notcontains $role) { throw "invalid role '$role' for $name (one of $($roles -join ', '))" }
        if ($table.Contains($name) -or $new.Contains($name)) { throw "principal $name already exists (use -Rotate)" }
        $new[$name] = $role
    }
    foreach ($name in $new.Keys) {   # validated all first: nothing is written for a bad list
        $table[$name] = @{ role = $new[$name]; digests = @(New-Secret $name); enabled = $true }
        Write-Output "  api\$name.secret  ($($new[$name]))"
    }
    Write-Credentials $table
    Write-Output "added $($new.Count) principal(s) to $credFile"
    exit 0
}
if ($Rotate) {
    Require-Known $table $Rotate
    $table[$Rotate].digests = @(New-Secret $Rotate) + $table[$Rotate].digests
    $table[$Rotate].enabled = $true
    Write-Credentials $table
    Write-Output "rotated ${Rotate}: new secret in api\$Rotate.secret; the old digest stays valid until -Retire $Rotate"
    exit 0
}
if ($Retire) {
    Require-Known $table $Retire
    $table[$Retire].digests = @($table[$Retire].digests[0])
    Write-Credentials $table
    Write-Output "retired the old digest(s) of $Retire"
    exit 0
}
if ($Revoke) {
    Require-Known $table $Revoke
    $table[$Revoke].enabled = $false
    Write-Credentials $table
    $secret = Join-Path $apiDir "$Revoke.secret"
    if (Test-Path -LiteralPath $secret) { Remove-Item -LiteralPath $secret -Force }
    Write-Output "revoked $Revoke"
    exit 0
}

if ($table.Count -gt 0 -and -not $Force) {
    throw "$credFile already exists. Use -Force to replace everything, or -Rotate/-Retire/-Revoke <principal>."
}
$table = [ordered]@{}
foreach ($entry in $Principals) {
    $name, $role = $entry -split ':', 2
    if ($name -notmatch $idPattern) { throw "invalid principal name '$name'" }
    if ($roles -notcontains $role) { throw "invalid role '$role' for $name (one of $($roles -join ', '))" }
    if ($table.Contains($name)) { throw "principal $name listed twice" }
    $table[$name] = @{ role = $role; digests = @(New-Secret $name); enabled = $true }
    Write-Output "  api\$name.secret  ($role)"
}
Write-Credentials $table
foreach ($p in $TelemetryProducers) { New-TelemetryKey $p }
Write-Output "wrote $credFile"
