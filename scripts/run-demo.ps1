<#
.SYNOPSIS
  Starts the EastGuard end-to-end demo: every component as its own JVM process, in the spec section 9.2 order.

.DESCRIPTION
  Run from anywhere:  .\scripts\run-demo.ps1

  Order, each one ready before the next starts:
    control          ControlPlaneImpl  RMI 127.0.0.1:1099/1100, HTTPS audit 127.0.0.1:9443
                                       ready = GET /health/ready -> 200 with the console certificate
    detector         ThreatDetector    UDP telemetry 127.0.0.1:5514        ready = "threat detector started"
    tokensvc         TokenServer       mTLS 127.0.0.1:8443                 ready = first enforcement snapshot installed
    backend-7002     EchoBackend       127.0.0.1:7002 (private, app-02)    ready = listening
    gateway-app-02   NioGateway        127.0.0.1:9002, decoy 127.0.0.1:9003 ready = first snapshot installed
    backend-7003     EchoBackend       127.0.0.1:7003 (private, app-03)    ready = listening
    gateway-app-03   NioGateway        127.0.0.1:9004                      ready = first snapshot installed

  The control plane starts only after the explicit bootstrap: if journal\demo-control.journal does not exist
  (or with -Reset) reset-demo.ps1 runs first. Configs: config\demo-*.properties.example, the shipped token and
  gateway-app-02 examples, and gateway-app-03.properties.example. All of them hold no secrets.

  Logs go to logs\<component>.log (java.util.logging, stderr) and logs\<component>.out.log (stdout); logs\ is
  git-ignored. Then run the scripted final demo in a second terminal:
      java -cp out eastguard.demos.DemoFinal
  or pass -RunFinal to run it here and stop everything afterwards.

  Ctrl+C, a component that exits, or a component that is not ready in time stops every started component:
  each one is wrapped by eastguard.demos.Launch, which exits through the normal JVM shutdown hooks when its
  stop file (logs\<component>.stop) appears or when this script's process ends. Components still running 10 s
  later are killed. Components are stopped in reverse start order (gateways first, control plane last).

.PARAMETER Reset
  Run reset-demo.ps1 first: delete the demo journal and logs\ and bootstrap again.
.PARAMETER RunFinal
  When every component is ready, run eastguard.demos.DemoFinal in this terminal (output also written to
  logs\demofinal.out.log), then stop everything. The exit code is DemoFinal's.
.PARAMETER FinalArgs
  Arguments for DemoFinal with -RunFinal, e.g. -FinalArgs '--measure','20'.
.PARAMETER ReadySeconds
  How long to wait for each component to become ready.
#>
param(
    [switch]$Reset,
    [switch]$RunFinal,
    [string[]]$FinalArgs = @(),
    [ValidateRange(5, 600)][int]$ReadySeconds = 60
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$root = Split-Path -Parent $PSScriptRoot
$logs = Join-Path $root 'logs'
$journal = Join-Path $root 'journal\demo-control.journal'
$script:started = New-Object System.Collections.ArrayList

$components = @(
    @{ Name = 'control'; Class = 'eastguard.control.ControlPlaneImpl'
       Args = @('--config', 'config/demo-control.properties.example'); Health = 'https://127.0.0.1:9443/health/ready'
       Shows = 'RMI 127.0.0.1:1099/1100, audit https://127.0.0.1:9443' },
    @{ Name = 'detector'; Class = 'eastguard.detector.ThreatDetector'
       Args = @('--config', 'config/demo-detector.properties.example'); Log = 'threat detector started'
       Shows = 'UDP 127.0.0.1:5514' },
    @{ Name = 'tokensvc'; Class = 'eastguard.tokensvc.TokenServer'
       Args = @('--config', 'config/token.properties.example'); Log = 'installed enforcement revision'
       Shows = 'mTLS 127.0.0.1:8443' },
    @{ Name = 'backend-7002'; Class = 'eastguard.demos.EchoBackend'
       Args = @('127.0.0.1:7002'); Out = 'echo backend listening'; Shows = 'private backend of app-02' },
    @{ Name = 'gateway-app-02'; Class = 'eastguard.gateway.NioGateway'
       Args = @('--config', 'config/gateway-app-02.properties.example'); Log = 'installed enforcement revision'
       Shows = 'mTLS 127.0.0.1:9002, decoy 127.0.0.1:9003' },
    @{ Name = 'backend-7003'; Class = 'eastguard.demos.EchoBackend'
       Args = @('127.0.0.1:7003'); Out = 'echo backend listening'; Shows = 'private backend of app-03' },
    @{ Name = 'gateway-app-03'; Class = 'eastguard.gateway.NioGateway'
       Args = @('--config', 'config/gateway-app-03.properties.example'); Log = 'installed enforcement revision'
       Shows = 'mTLS 127.0.0.1:9004' }
)
$tcpPorts = @(1099, 1100, 9443, 8443, 7002, 9002, 9003, 7003, 9004)
$udpPorts = @(5514)

function Get-Java {
    $cmd = Get-Command java -ErrorAction SilentlyContinue
    if (-not $cmd) { throw 'java not found on PATH: install JDK 21 and open a new terminal' }
    $ErrorActionPreference = 'Continue'   # java -version writes to stderr
    $line = & $cmd.Source -version 2>&1 | ForEach-Object { "$_" } | Select-Object -First 1
    if ($line -notmatch 'version "(\d+)') { throw "cannot read the Java version from: $line" }
    if ([int]$Matches[1] -lt 21) { throw "JDK 21 or newer required, found: $line" }
    return $cmd.Source
}

function Assert-Prerequisites {
    $missing = @()
    foreach ($f in @('out\eastguard\demos\Launch.class', 'out\eastguard\demos\DemoFinal.class',
            'out\eastguard\demos\HealthProbe.class')) {
        if (-not (Test-Path -LiteralPath (Join-Path $root $f))) {
            throw "$f not found: build first (.\scripts\sources.ps1, then  javac --release 21 -d out `"@sources.txt`")"
        }
    }
    foreach ($f in @('truststore.p12', 'control.p12', 'detector.p12', 'tokensvc.p12', 'gateway-app-02.p12',
            'gateway-app-03.p12', 'console.p12', 'workload-web-01.p12', 'workload-api-01.p12', 'lease-signer.p12',
            'control-signer.p12', 'lease-k1.cer', 'control-k1.cer', 'control-credentials.properties',
            'api\admin.secret', 'api\operator.secret', 'api\viewer.secret', 'api\tokensvc.secret',
            'api\detector.secret', 'api\gw-app-02.secret', 'api\gw-app-03.secret',
            'telemetry\gw-app-02.key', 'telemetry\gw-app-03.key', 'telemetry\tokensvc.key')) {
        if (-not (Test-Path -LiteralPath (Join-Path $root "keys\$f"))) { $missing += "keys\$f" }
    }
    if ($missing.Count -gt 0) {
        $msg = "missing: $($missing -join ', ').`n  On a fresh machine run  .\scripts\gen-certs.ps1  and  .\scripts\gen-credentials.ps1."
        if (@($missing | Where-Object { $_ -match 'app-03' }).Count -eq $missing.Count) {
            $msg += "`n  On a key set made before the second gateway existed, add only its material:" +
                "`n    .\scripts\gen-certs.ps1 -AddComponent gateway-app-03" +
                "`n    .\scripts\gen-credentials.ps1 -Add gw-app-03:GATEWAY" +
                "`n    .\scripts\gen-credentials.ps1 -TelemetryKeys -TelemetryProducers gw-app-03"
        }
        throw $msg
    }
    $busy = @()
    foreach ($port in $tcpPorts) {
        $l = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $port)
        try { $l.Start() } catch { $busy += "tcp/$port" } finally { try { $l.Stop() } catch { } }
    }
    foreach ($port in $udpPorts) {
        try { (New-Object Net.Sockets.UdpClient(New-Object Net.IPEndPoint([Net.IPAddress]::Loopback, $port))).Close() }
        catch { $busy += "udp/$port" }
    }
    if ($busy.Count -gt 0) {
        throw "ports already in use: $($busy -join ', '). Is another demo or a DemoM* still running?"
    }
}

function Write-LoggingConfig {
    $text = @(
        '# Written by scripts\run-demo.ps1 for the demo JVMs: one line per record, on stderr (logs\<component>.log).',
        'handlers=java.util.logging.ConsoleHandler',
        '.level=INFO',
        'java.util.logging.ConsoleHandler.level=INFO',
        'java.util.logging.ConsoleHandler.formatter=java.util.logging.SimpleFormatter',
        'java.util.logging.SimpleFormatter.format=%1$tH:%1$tM:%1$tS.%1$tL %4$-7s %3$s - %5$s%6$s%n'
    ) -join "`n"
    [IO.File]::WriteAllText((Join-Path $logs 'logging.properties'), $text + "`n", (New-Object Text.UTF8Encoding $false))
}

function Start-Component($c) {
    $stop = Join-Path $logs "$($c.Name).stop"
    if (Test-Path -LiteralPath $stop) { Remove-Item -LiteralPath $stop -Force }
    # Relative paths only: the working directory is the project root, and Start-Process does not quote arguments.
    $argList = @('-cp', 'out', '-Djava.util.logging.config.file=logs/logging.properties',
        'eastguard.demos.Launch', '--stop-file', "logs/$($c.Name).stop", '--watch-pid', "$PID", $c.Class) + $c.Args
    $p = Start-Process -FilePath $script:java -ArgumentList $argList -WorkingDirectory $root -NoNewWindow -PassThru `
        -RedirectStandardOutput (Join-Path $logs "$($c.Name).out.log") `
        -RedirectStandardError (Join-Path $logs "$($c.Name).log")
    $null = $p.Handle   # keeps ExitCode readable after the process ends
    [void]$script:started.Add([pscustomobject]@{ Name = $c.Name; Process = $p; Shows = $c.Shows })
    return $p
}

function Test-LogLine([string]$File, [string]$Text) {
    $path = Join-Path $logs $File
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    return [bool](Select-String -LiteralPath $path -SimpleMatch -Pattern $Text -Quiet)
}

function Test-Health([string]$Url) {
    $ErrorActionPreference = 'Continue'
    & $script:java -cp out eastguard.demos.HealthProbe $Url *> $null
    return ($LASTEXITCODE -eq 0)
}

function Show-Tail([string]$Name) {
    foreach ($f in @("$Name.log", "$Name.out.log")) {
        $path = Join-Path $logs $f
        if ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -gt 0) {
            Write-Host "---- last lines of logs\$f"
            Get-Content -LiteralPath $path -Tail 15 | ForEach-Object { Write-Host "  $_" }
        }
    }
}

function Wait-Ready($c, $p) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $ReadySeconds) {
        if ($p.HasExited) {
            Show-Tail $c.Name
            throw "$($c.Name) exited with code $($p.ExitCode) during startup"
        }
        $ready = if ($c.ContainsKey('Health')) { Test-Health $c.Health }
                 elseif ($c.ContainsKey('Out')) { Test-LogLine "$($c.Name).out.log" $c.Out }
                 else { Test-LogLine "$($c.Name).log" $c.Log }
        if ($ready) { return $sw.Elapsed.TotalSeconds }
        Start-Sleep -Milliseconds 200
    }
    Show-Tail $c.Name
    throw "$($c.Name) not ready after $ReadySeconds s"
}

function Stop-All {
    if ($script:started.Count -eq 0) { return }
    Write-Host ''
    Write-Host 'stopping the demo components (reverse start order)...'
    $list = @($script:started)
    [array]::Reverse($list)
    foreach ($e in $list) {
        if (-not $e.Process.HasExited) {
            New-Item -ItemType File -Force -Path (Join-Path $logs "$($e.Name).stop") | Out-Null
            [void]$e.Process.WaitForExit(10000)
        }
        if (-not $e.Process.HasExited) {
            # Kill the whole tree: with Oracle's javapath shim on PATH the JVM is a child of the started process.
            & taskkill.exe /PID $e.Process.Id /T /F *> $null
            Write-Host ("  {0,-15} did not stop within 10 s: killed" -f $e.Name)
        } else {
            Write-Host ("  {0,-15} stopped (exit code {1})" -f $e.Name, $e.Process.ExitCode)
        }
        Remove-Item -LiteralPath (Join-Path $logs "$($e.Name).stop") -Force -ErrorAction SilentlyContinue
    }
    $script:started.Clear()
}

$exitCode = 0
Push-Location $root
try {
    $script:java = Get-Java
    if ($Reset -or -not (Test-Path -LiteralPath $journal)) {
        & (Join-Path $PSScriptRoot 'reset-demo.ps1')
    }
    Assert-Prerequisites
    New-Item -ItemType Directory -Force -Path $logs | Out-Null
    Write-LoggingConfig

    Write-Host "starting the EastGuard demo from $root (logs in logs\)"
    $detectorClock = $null
    foreach ($c in $components) {
        $p = Start-Component $c
        if ($c.Name -eq 'detector') { $detectorClock = [Diagnostics.Stopwatch]::StartNew() }
        $secs = Wait-Ready $c $p
        Write-Host ("  {0,-15} pid {1,-6} ready in {2,4:N1} s   {3}" -f $c.Name, $p.Id, $secs, $c.Shows)
    }
    # The detector proposes nothing for telemetry.acceptanceMillis after it starts (restart guard, spec 6.1).
    # Wait it out so the final demo's decoy step is not suppressed.
    $guardLine = Select-String -LiteralPath 'config\demo-detector.properties.example' -Pattern '^telemetry\.acceptanceMillis=(\d+)'
    $guardMs = if ($guardLine) { [int]$guardLine.Matches[0].Groups[1].Value } else { 30000 }
    $left = $guardMs + 500 - $detectorClock.ElapsedMilliseconds
    if ($left -gt 0) {
        Write-Host ("  waiting {0:N1} s for the detector's restart guard ({1} ms after its start) to end" -f ($left / 1000), $guardMs)
        Start-Sleep -Milliseconds $left
    }
    Write-Host ''
    Write-Host 'demo is ready.'
    if ($RunFinal) {
        $ErrorActionPreference = 'Continue'
        & $script:java -cp out eastguard.demos.DemoFinal @FinalArgs | Tee-Object -FilePath (Join-Path $logs 'demofinal.out.log')
        $exitCode = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
    } else {
        Write-Host '  final demo:  java -cp out eastguard.demos.DemoFinal       (in a second terminal, project root)'
        Write-Host '  dashboard:   java -cp out eastguard.dashboard.DashboardApp --config config/dashboard.properties.example'
        Write-Host 'Press Ctrl+C to stop every component.'
        while ($true) {
            foreach ($e in $script:started) {
                if ($e.Process.HasExited) {
                    Show-Tail $e.Name
                    throw "$($e.Name) exited unexpectedly with code $($e.Process.ExitCode)"
                }
            }
            Start-Sleep -Milliseconds 500
        }
    }
} catch {
    Write-Host "run-demo: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
} finally {
    Stop-All
    Pop-Location
}
exit $exitCode
