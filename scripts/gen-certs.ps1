<#
.SYNOPSIS
  Generates the EastGuard demo PKI and lease-signing key with JDK keytool only.

.DESCRIPTION
  Run from anywhere:  .\scripts\gen-certs.ps1   (writes keys\ under the project root; keys\ is git-ignored)

  Creates, under -OutDir:
    ca\ca.p12               demo CA private key. Only this script uses it; no runtime process loads it.
    ca\untrusted-ca.p12     a second CA that nothing trusts, for negative tests
    ca.cer                  demo CA certificate (public)
    truststore.p12          trusts only the demo CA
    tokensvc.p12            token service   SAN dns:localhost, ip:127.0.0.1, uri:urn:eastguard:component:tokensvc
    gateway-app-02.p12      gateway app-02  SAN dns:localhost, ip:127.0.0.1, uri:urn:eastguard:component:gateway-app-02
    control.p12             control plane   SAN dns:localhost, ip:127.0.0.1, uri:urn:eastguard:component:control
    detector.p12            threat detector SAN dns:localhost, ip:127.0.0.1, uri:urn:eastguard:component:detector
    workload-web-01.p12     workload        SAN uri:urn:eastguard:workload:web-01
    workload-api-01.p12     workload        SAN uri:urn:eastguard:workload:api-01
    untrusted-web-01.p12    workload web-01 issued by the untrusted CA (must fail the TLS handshake)
    lease-signer.p12        Ed25519 lease-signing key, alias lease-k1
    lease-k1.cer            certificate carrying the lease verification public key
  With -TestFixtures, also:
    workload-nosan.p12      CN=web-01 and no SAN (the CN must never be used as an identity)
    workload-twosan.p12     two workload URI SANs (ambiguous identity)

  Server certificates carry serverAuth+clientAuth (they are also RMI clients from Task 6); workload
  certificates carry clientAuth only. All TLS keys are EC P-256.

  Passwords are never printed and never passed on a command line (keytool reads them with :env):
    runtime TLS stores   $env:EASTGUARD_STORE_PASS   else <OutDir>\store.pass
    lease signer store   $env:EASTGUARD_SIGNER_PASS  else <OutDir>\signer.pass
    CA stores            $env:EASTGUARD_CA_PASS      else <OutDir>\ca\ca.pass
  A missing password file is created with 32 random bytes (base64url) and its ACL is restricted to the
  current user. Keep -OutDir inside a git-ignored directory.

.PARAMETER OutDir
  Output directory. Default: <project>\keys
.PARAMETER ValidityDays
  Leaf certificate validity. The CAs get 30 extra days.
.PARAMETER TestFixtures
  Also create the negative-test workload certificates.
.PARAMETER AddComponent
  Issue only one more component certificate (serverAuth+clientAuth, SAN uri:urn:eastguard:component:<name>)
  from the existing demo CA, e.g. -AddComponent detector after upgrading from an older key set.
.PARAMETER Force
  Replace existing keystores and certificates. Existing password files are kept and reused.
#>
param(
    [string]$OutDir,
    [ValidateRange(1, 3650)][int]$ValidityDays = 365,
    [switch]$TestFixtures,
    [switch]$Force,
    [string]$AddComponent
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$root = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $root 'keys' }
$OutDir = [IO.Path]::GetFullPath($OutDir)
$caDir = Join-Path $OutDir 'ca'
$work = Join-Path $OutDir '.work'

function Find-Keytool {
    if ($env:JAVA_HOME) {
        $p = Join-Path $env:JAVA_HOME 'bin\keytool.exe'
        if (Test-Path $p) { return $p }
    }
    $cmd = Get-Command keytool -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # Oracle's javapath shim exposes java but not keytool: ask the active JVM for its home.
    $java = Get-Command java -ErrorAction SilentlyContinue
    if ($java) {
        $ErrorActionPreference = 'Continue'   # -XshowSettings writes to stderr
        $line = & $java.Source -XshowSettings:properties -version 2>&1 |
            ForEach-Object { "$_" } | Where-Object { $_ -match '^\s*java\.home\s*=' } | Select-Object -First 1
        if ($line) {
            $p = Join-Path ($line -replace '^\s*java\.home\s*=\s*', '').Trim() 'bin\keytool.exe'
            if (Test-Path $p) { return $p }
        }
    }
    throw 'keytool not found: set JAVA_HOME to a JDK 21+ installation'
}

function Protect-File([string]$Path) {
    try {
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'Allow')))
        Set-Acl -LiteralPath $Path -AclObject $acl
    } catch {
        Write-Warning "could not restrict access to $(Split-Path -Leaf $Path): $($_.Exception.Message)"
    }
}

# Returns the secret from the environment variable, else from the file, else creates the file.
function Get-Secret([string]$EnvName, [string]$File) {
    $v = [Environment]::GetEnvironmentVariable($EnvName)
    if ($v) { return $v }
    if (Test-Path -LiteralPath $File) {
        $v = ([IO.File]::ReadAllText($File)).TrimEnd("`r", "`n", ' ')
        if ($v.Length -lt 8) { throw "password file $File is shorter than 8 characters" }
        return $v
    }
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $v = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    [IO.File]::WriteAllText($File, $v, (New-Object Text.UTF8Encoding $false))
    Protect-File $File
    Write-Host "created password file $File"   # Write-Output would become part of the return value
    return $v
}

function Invoke-Keytool([string[]]$KtArgs) {
    $ErrorActionPreference = 'Continue'   # keytool reports progress on stderr
    $out = & $script:Keytool @KtArgs 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) {
        $out | ForEach-Object { Write-Host "  keytool: $_" }
        throw "keytool $($KtArgs[0]) failed with exit code $LASTEXITCODE"
    }
}

function New-Ca([string]$Store, [string]$DName, [string]$CerOut) {
    $s = @('-storetype', 'PKCS12', '-keystore', $Store, '-storepass:env', 'EG_GEN_CA')
    Invoke-Keytool (@('-genkeypair') + $s + @('-keypass:env', 'EG_GEN_CA', '-alias', 'ca',
            '-keyalg', 'EC', '-groupname', 'secp256r1', '-sigalg', 'SHA256withECDSA',
            '-dname', $DName, '-validity', "$($ValidityDays + 30)",
            '-ext', 'bc:c=ca:true,pathlen:0', '-ext', 'ku:c=keyCertSign,cRLSign'))
    Invoke-Keytool (@('-exportcert', '-rfc') + $s + @('-alias', 'ca', '-file', $CerOut))
}

# Leaf key in its own PKCS#12 store, certified by the given CA. The store ends with exactly one entry: the
# private key with its chain (leaf, CA).
function New-Leaf([string]$Name, [string]$DName, [string[]]$Ext, [string]$CaStore, [string]$CaCer) {
    $store = Join-Path $OutDir "$Name.p12"
    $csr = Join-Path $work "$Name.csr"
    $cer = Join-Path $work "$Name.cer"
    $s = @('-storetype', 'PKCS12', '-keystore', $store, '-storepass:env', 'EG_GEN_STORE')
    Invoke-Keytool (@('-genkeypair') + $s + @('-keypass:env', 'EG_GEN_STORE', '-alias', $Name,
            '-keyalg', 'EC', '-groupname', 'secp256r1', '-sigalg', 'SHA256withECDSA',
            '-dname', $DName, '-validity', '1'))
    Invoke-Keytool (@('-certreq') + $s + @('-alias', $Name, '-file', $csr))
    $gen = @('-gencert', '-rfc', '-storetype', 'PKCS12', '-keystore', $CaStore, '-storepass:env', 'EG_GEN_CA',
        '-alias', 'ca', '-infile', $csr, '-outfile', $cer, '-sigalg', 'SHA256withECDSA',
        '-validity', "$ValidityDays", '-ext', 'ku:c=digitalSignature')
    foreach ($e in $Ext) { $gen += @('-ext', $e) }
    Invoke-Keytool $gen
    Invoke-Keytool (@('-importcert', '-noprompt') + $s + @('-alias', 'issuing-ca', '-file', $CaCer))
    Invoke-Keytool (@('-importcert', '-noprompt') + $s + @('-alias', $Name, '-file', $cer))
    Invoke-Keytool (@('-delete') + $s + @('-alias', 'issuing-ca'))
    Write-Output "  $Name.p12"
}

function New-Server([string]$Name, [string]$Component) {
    New-Leaf $Name "CN=$Name, O=EastGuard Demo" `
        @("san=dns:localhost,ip:127.0.0.1,uri:urn:eastguard:component:$Component", 'eku=serverAuth,clientAuth') `
        $caStore $caCer
}

function New-Workload([string]$Name, [string]$San, [string]$CaStore, [string]$CaCer, [string]$Cn) {
    $ext = @('eku=clientAuth')
    if ($San) { $ext += "san=$San" }
    New-Leaf $Name "CN=$Cn, O=EastGuard Demo" $ext $CaStore $CaCer
}

# ---- main ----

$script:Keytool = Find-Keytool

if ($AddComponent) {
    # One more component certificate from the existing demo CA; nothing else is touched.
    if ($AddComponent -notmatch '^[a-z0-9][a-z0-9._-]{0,63}$') { throw "invalid component name '$AddComponent'" }
    $caStore = Join-Path $caDir 'ca.p12'
    $caCer = Join-Path $OutDir 'ca.cer'
    if (-not (Test-Path -LiteralPath $caStore) -or -not (Test-Path -LiteralPath $caCer)) {
        throw "no demo CA under $OutDir; run this script without -AddComponent first"
    }
    $target = Join-Path $OutDir "$AddComponent.p12"
    if (Test-Path -LiteralPath $target) {
        if (-not $Force) { throw "$target already exists (use -Force to replace it)" }
        Remove-Item -LiteralPath $target -Force
    }
    $env:EG_GEN_STORE = Get-Secret 'EASTGUARD_STORE_PASS' (Join-Path $OutDir 'store.pass')
    $env:EG_GEN_CA = Get-Secret 'EASTGUARD_CA_PASS' (Join-Path $caDir 'ca.pass')
    try {
        New-Item -ItemType Directory -Force -Path $work | Out-Null
        New-Server $AddComponent $AddComponent
        Protect-File $target
    } finally {
        Remove-Item Env:EG_GEN_STORE, Env:EG_GEN_CA -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    }
    exit 0
}
New-Item -ItemType Directory -Force -Path $OutDir, $caDir | Out-Null

$existing = @(Get-ChildItem -LiteralPath $OutDir, $caDir -File |
        Where-Object { $_.Extension -eq '.p12' -or $_.Extension -eq '.cer' })
if ($existing.Count -gt 0) {
    if (-not $Force) {
        throw "keystores already exist in $OutDir. Re-run with -Force to replace them (issued leases and copies of the old CA stop working)."
    }
    $existing | Remove-Item -Force
}

$env:EG_GEN_STORE = Get-Secret 'EASTGUARD_STORE_PASS' (Join-Path $OutDir 'store.pass')
$env:EG_GEN_SIGNER = Get-Secret 'EASTGUARD_SIGNER_PASS' (Join-Path $OutDir 'signer.pass')
$env:EG_GEN_CA = Get-Secret 'EASTGUARD_CA_PASS' (Join-Path $caDir 'ca.pass')
try {
    New-Item -ItemType Directory -Force -Path $work | Out-Null

    Write-Output "keytool: $script:Keytool"
    Write-Output "writing to $OutDir"
    $caStore = Join-Path $caDir 'ca.p12'
    $caCer = Join-Path $OutDir 'ca.cer'
    New-Ca $caStore 'CN=EastGuard Demo CA, O=EastGuard Demo' $caCer
    Invoke-Keytool @('-importcert', '-noprompt', '-storetype', 'PKCS12', '-keystore', (Join-Path $OutDir 'truststore.p12'),
        '-storepass:env', 'EG_GEN_STORE', '-alias', 'eastguard-demo-ca', '-file', $caCer)
    Write-Output '  ca\ca.p12, ca.cer, truststore.p12'

    $badStore = Join-Path $caDir 'untrusted-ca.p12'
    $badCer = Join-Path $work 'untrusted-ca.cer'
    New-Ca $badStore 'CN=Untrusted CA, O=Not EastGuard' $badCer
    Write-Output '  ca\untrusted-ca.p12'

    New-Server 'tokensvc' 'tokensvc'
    New-Server 'gateway-app-02' 'gateway-app-02'
    New-Server 'control' 'control'
    New-Server 'detector' 'detector'
    New-Workload 'workload-web-01' 'uri:urn:eastguard:workload:web-01' $caStore $caCer 'web-01'
    New-Workload 'workload-api-01' 'uri:urn:eastguard:workload:api-01' $caStore $caCer 'api-01'
    New-Workload 'untrusted-web-01' 'uri:urn:eastguard:workload:web-01' $badStore $badCer 'web-01'
    if ($TestFixtures) {
        New-Workload 'workload-nosan' '' $caStore $caCer 'web-01'
        New-Workload 'workload-twosan' 'uri:urn:eastguard:workload:web-01,uri:urn:eastguard:workload:api-01' `
            $caStore $caCer 'web-01'
    }

    $signer = Join-Path $OutDir 'lease-signer.p12'
    $ss = @('-storetype', 'PKCS12', '-keystore', $signer, '-storepass:env', 'EG_GEN_SIGNER')
    Invoke-Keytool (@('-genkeypair') + $ss + @('-keypass:env', 'EG_GEN_SIGNER', '-alias', 'lease-k1',
            '-keyalg', 'Ed25519', '-dname', 'CN=EastGuard lease signer lease-k1, O=EastGuard Demo',
            '-validity', "$ValidityDays"))
    Invoke-Keytool (@('-exportcert', '-rfc') + $ss + @('-alias', 'lease-k1', '-file', (Join-Path $OutDir 'lease-k1.cer')))
    Write-Output '  lease-signer.p12, lease-k1.cer'

    Get-ChildItem -LiteralPath $OutDir, $caDir -File -Filter *.p12 | ForEach-Object { Protect-File $_.FullName }
    Write-Output 'done'
} finally {
    Remove-Item Env:EG_GEN_STORE, Env:EG_GEN_SIGNER, Env:EG_GEN_CA -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
