# EastGuard

Zero-trust east-west TCP access control. A workload gets a short-lived, Ed25519-signed lease from a token service
over mutual TLS, presents it to an NIO gateway over mutual TLS, and the gateway relays bytes to one fixed private
backend only after authorization. Gateways report HMAC-authenticated UDP telemetry to a threat detector. The
detector proposes containment to an RMI control plane, which journals every change and multicasts signed
quarantine notices. A Swing console, an HTTPS audit export and a `ztp://` URL handler sit on top.

Java 21, JDK only: no Maven, Gradle or external libraries. Full specification: [`docs/EASTGUARD.md`](docs/EASTGUARD.md).

| Document | What it holds |
|----------|---------------|
| [`docs/EASTGUARD.md`](docs/EASTGUARD.md) | the specification |
| [`docs/DEVIATIONS.md`](docs/DEVIATIONS.md) | every deliberate simplification, why, and what would remove it |
| [`docs/TEST-COVERAGE.md`](docs/TEST-COVERAGE.md) | each spec §10 failure scenario → the tests that cover it → result; what cannot be tested locally |
| [`docs/RESULTS.md`](docs/RESULTS.md) | measured numbers (admission, sessions and threads, containment, control-plane loss), the machine, the limits |

## Architecture

```
                 mTLS (TLS 1.3, client cert)             RMI over mTLS + per-call API credential
  workload  ------------------------------>  token service  <------------------------------+
  web-01      lease request / signed lease   (issues leases)        sync (poll 1 s)        |
     |                                                                                     |
     | mTLS + preamble(lease)                                                              |
     v                                                                                     |
  NIO gateway app-02  -- plain TCP, only after ALLOW -->  private backend 127.0.0.1:7002   |
  NIO gateway app-03  -- plain TCP, only after ALLOW -->  private backend 127.0.0.1:7003   |
     |       ^                                                                             |
     |       +---- signed EGC1 multicast notices 239.20.20.20:4446 ----+                   |
     | UDP telemetry (HMAC-SHA256)                                     |                   |
     v                                                                 |                   |
  threat detector  -- proposeAction / recordObservations (RMI) -->  control plane  --------+
  (10 s window, scores, decoys, learning)                       (journal, single writer,
                                                                 audit, HTTPS export)
                                                                       ^
                                             Swing console (RMI) ------+------ ztp://policy/<service>
```

- **Identity** is the single `urn:eastguard:workload:<id>` URI SAN of a client certificate from the demo CA.
- **Leases** (60 s, `EGT1`) are bound to the certificate's SHA-256, the source IP, the audience service and the
  enforcement revision they were issued at.
- **The gateway** is one selector thread with an explicit per-connection state machine. It connects the backend
  only after the lease verifies and policy allows it, and sends `ALLOW` only after the backend connect succeeded.
- **The control plane** is authoritative. Every mutation is journaled and forced to disk before it is
  acknowledged. Enforcement points fail closed when their state is older than 5 s.
- **Containment**: a committed quarantine is multicast at once and closes matching sessions at every gateway. A
  release writes a watermark, so leases issued before it are refused and a fresh lease is needed.
- **Learning**: in LEARN mode, pilot-scope admissions outside the approved graph become candidates. An admin
  reviews the exact diff and freezes it into the ENFORCE allow-list in one journaled change.

Code layout (spec §8): `src/eastguard/{common,client,gateway,tokensvc,detector,bus,control,dashboard,handlers,demos}`,
tests in `test/eastguard/test`.

## Run guide (Windows & Linux)

Scripts are organized into platform-specific subdirectories:
- **Linux / macOS (Bash)**: `./scripts/linux/<script>.sh`
- **Windows (PowerShell)**: `.\scripts\windows\<script>.ps1`

Steps 1–5 are needed once; step 3 again after pulling changes.

### 1. Check the JDK

```powershell
java -version        # must say version "21" or newer
javac -version       # a JDK, not only a JRE
```

Install a JDK 21+ (for example Eclipse Temurin 21 or Oracle JDK 21) if either is missing, then open a **new**
terminal. The scripts find `keytool` through `JAVA_HOME`, then `PATH`, then the active `java`. If PowerShell
refuses to run scripts, allow them for this terminal only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### 2. Get the code

```powershell
git clone https://github.com/Sachintha-dilshan49/eastguard.git
cd eastguard
```

### 3. Build

**Windows (PowerShell):**
```powershell
.\scripts\windows\sources.ps1              # writes sources.txt: every .java under src and test
javac --release 21 -d out "@sources.txt"   # quote "@sources.txt": unquoted, PowerShell splats it
```

**Linux / macOS (Bash):**
```bash
./scripts/linux/sources.sh
javac --release 21 -d out "@sources.txt"
```

### 4. Demo keys and certificates

**Windows (PowerShell):**
```powershell
.\scripts\windows\gen-certs.ps1          # demo CA, component/workload/console certificates, lease and notice signers -> keys\
.\scripts\windows\gen-credentials.ps1    # per-principal API secrets (keys\api\), their digests, telemetry HMAC keys
```

**Linux / macOS (Bash):**
```bash
./scripts/linux/gen-certs.sh
./scripts/linux/gen-credentials.sh
```

Both use JDK tools only and write to `keys\`, which is git-ignored. Passwords and secrets are generated, kept in
files readable only by the current user, and never printed or passed on a command line. Details:
"Demo keys and certificates" below.

### 5. Bootstrap the demo journal

**Windows (PowerShell):**
```powershell
.\scripts\windows\reset-demo.ps1
```

**Linux / macOS (Bash):**
```bash
./scripts/linux/reset-demo.sh
```

This is the explicit administrator bootstrap (spec §9.1). It writes revision 1 of `journal\demo-control.journal`:
services `app-02` and `app-03`, approved edges `web-01 -> app-02` and `web-01 -> app-03`, ENFORCE, deny by default.
Run it again at any time to start over; it refuses while a demo control plane is running. (`run-demo` runs it
by itself when the journal does not exist.)

### 6. Run all tests

```powershell
java -ea -cp out eastguard.test.AllTests          # expect "357 passed, 0 failed", exit code 0
java -ea -cp out eastguard.test.AllTests Gateway  # only classes whose name contains "Gateway"
```

Run step 4 first: two `TokenConfigTest` tests parse the shipped bootstrap example, which reads the public
certificates `keys\lease-k1.cer` and `keys\control-k1.cer`. Every other test uses its own throwaway test PKI:
the first run builds it in `out\test-pki` with
`gen-certs.ps1 -TestFixtures` (about 20 s); later runs reuse it. A full run takes about 1.5–2 minutes. Add
`-Deastguard.testLog=true` to see server logs.

### 7. The five concept demos

Each one prints numbered steps with `[ok]` / `[FAIL]` lines and exits 0 only when every check passes. Run them
one at a time, and **not while `run-demo.ps1` is running**: they use the same fixed ports (7002, 1099/1100,
9443, 4446).

```powershell
java -cp out eastguard.demos.DemoM1_Nio          # NIO gateway: 500 concurrent sessions (arg: count, e.g. 1000), threads, backpressure, decoy
java -cp out eastguard.demos.DemoM2_Tls          # TLS: lease over mTLS, untrusted certificate fails, tampered leases denied
java -cp out eastguard.demos.DemoM3_Udp          # UDP: labelled fixture stream -> exact scores, CIDR classes, forged/duplicate ignored
java -cp out eastguard.demos.DemoM4_Multicast    # multicast: 3 receivers apply a commit, duplicates/drops/late notices converge
java -cp out eastguard.demos.DemoM5_Rmi          # RMI: audited edit, conflict, idempotent retry, release, typed ztp:// read, audit export
```

`DemoM3_Udp` needs nothing from `keys\`; the others need step 4. Measured numbers for these runs are in
[`docs/RESULTS.md`](docs/RESULTS.md).

### 8. End-to-end: separate processes and the final demo

Terminal 1 starts every component as its own JVM in the spec §9.2 order and waits until each one is ready:

**Windows (PowerShell):**
```powershell
.\scripts\windows\run-demo.ps1            # add -Reset to start from a fresh journal
```

**Linux / macOS (Bash):**
```bash
./scripts/linux/run-demo.sh               # add --reset to start from a fresh journal
```

```
  control         pid 21452  ready in  1.7 s   RMI 127.0.0.1:1099/1100, audit https://127.0.0.1:9443
  detector        pid 11864  ready in  0.9 s   UDP 127.0.0.1:5514
  tokensvc        pid 26300  ready in  1.5 s   mTLS 127.0.0.1:8443
  backend-7002    pid 18912  ready in  0.2 s   private backend of app-02
  gateway-app-02  pid 3600   ready in  1.1 s   mTLS 127.0.0.1:9002, decoy 127.0.0.1:9003
  backend-7003    pid 25328  ready in  0.4 s   private backend of app-03
  gateway-app-03  pid 12228  ready in  1.3 s   mTLS 127.0.0.1:9004
  waiting 4.8 s for the detector's restart guard (10000 ms after its start) to end

demo is ready.
```

Terminal 2 (project root) runs the scripted final demo (spec §11) against those processes:

```powershell
java -cp out eastguard.demos.DemoFinal
```

1. **Approved flow**: `web-01` gets a lease and reaches `app-02`, and `app-03` through the second gateway.
2. **Unapproved flow**: `api-01 -> app-02` is refused by the token service (`POLICY_DENY`) and by the gateway
   (replayed lease, `IDENTITY_MISMATCH`).
3. **Learning**: admin switches to LEARN with pilot `api-01 -> app-02`. The pilot connection is admitted, the
   detector reports it, the draft shows the candidate, and the reviewed diff `[+api-01->app-02]` is frozen. The
   edge then works in ENFORCE, while the unscoped `api-01 -> app-03` stays denied.
4. **Detector fixture**: one labelled TCP touch of the owned decoy listener → CRITICAL alert → detector proposal →
   committed quarantine → live sessions closed at **both** gateways (about 80 ms here).
5. **Release**: the old lease is rejected by the release watermark (`LEASE_SUPERSEDED`), and a fresh lease
   reconnects at both gateways.

The server-side reason for each step is read from `logs\`. `DemoFinal --measure 20` also times containment and
connects across the processes. Or let terminal 1 do it all and stop afterwards:

**Windows (PowerShell):**
```powershell
.\scripts\windows\run-demo.ps1 -Reset -RunFinal                              # exit code = DemoFinal's
.\scripts\windows\run-demo.ps1 -Reset -RunFinal -FinalArgs '--measure','20'
```

**Linux / macOS (Bash):**
```bash
./scripts/linux/run-demo.sh --reset --run-final
```

`DemoFinal` needs a fresh state: to run it again, press **Ctrl+C** in terminal 1 and start
`.\scripts\windows\run-demo.ps1 -Reset` (or `./scripts/linux/run-demo.sh --reset`). Ctrl+C (or any component failing to start or exiting) stops every component
through its shutdown hooks, in reverse order. Logs stay in `logs\` (git-ignored) until the next reset.

### 9. Open the dashboard

With `run-demo` running, in another terminal:

```powershell
java -cp out eastguard.dashboard.DashboardApp --config config/dashboard.properties.example
```

The console connects as `console-operator` (quarantine and release). To review and freeze a learning draft,
copy the example to `config\dashboard.properties` (git-ignored), set `control.principal=console-admin` and
`control.secretFile=keys/api/console-admin.secret`, and start it with that file. `--demo` instead of `--config ...`
shows labelled fixture scenarios with no network.

### Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ports already in use: ...` from `run-demo` | another demo, a `DemoM*` or a leftover component still runs. Find it with `Get-NetTCPConnection -LocalPort 9002` / `Get-NetUDPEndpoint -LocalPort 5514` |
| `missing: keys\gateway-app-03.p12, ...` | a key set from before the second gateway: run the three commands `run-demo` prints |
| `the demo state is not fresh` from `DemoFinal` | Ctrl+C in terminal 1, then restart with `-Reset` |
| `javac: no source files` | `"@sources.txt"` was not quoted, or sources script was not run |
| a script "cannot be loaded because running scripts is disabled" | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| step 4 says the detector suppressed the proposal | the detector's restart guard (10 s) or 60 s cooldown; `run-demo` waits out the guard, a reset clears the cooldown |

---

# Component reference

## Demo keys and certificates

```powershell
.\scripts\windows\gen-certs.ps1            # writes keys\ (git-ignored); -Force to regenerate
```

This uses JDK `keytool` only. It finds keytool via `JAVA_HOME`, then PATH, then the active `java`. It creates a
demo CA, a separate untrusted CA, PKCS#12 stores for the token service, gateways `app-02` and `app-03`, the control plane, the
threat detector, and workloads `web-01` / `api-01` (URI SAN `urn:eastguard:workload:<id>`), a `web-01`
look-alike signed by the
untrusted CA, the Ed25519 lease-signing key `lease-k1`, and a separate Ed25519 control-plane notice signer
`control-k1` (`keys\control-signer.p12`, public key `keys\control-k1.cer`, published in the snapshot through
`bootstrap.controlKeys`).

On a key set made before Task 8, add only the notice signer; nothing else is touched:

```powershell
.\scripts\windows\gen-certs.ps1 -AddControlSigner     # refuses to replace an existing signer without -Force
```

Passwords never appear on a command line or in the output:

| Store | Environment variable | Fallback file (created if missing) |
|-------|----------------------|------------------------------------|
| Runtime TLS stores + trust store | `EASTGUARD_STORE_PASS` | `keys\store.pass` |
| Lease signer | `EASTGUARD_SIGNER_PASS` | `keys\signer.pass` |
| Control-plane notice signer | `EASTGUARD_CONTROL_SIGNER_PASS` | `keys\control-signer.pass` |
| CA stores (`keys\ca\`, used only by the script) | `EASTGUARD_CA_PASS` | `keys\ca\ca.pass` |

## Token service and M2 demo

```powershell
java -cp out eastguard.demos.DemoM2_Tls
java -cp out eastguard.tokensvc.TokenServer --config config/token.properties.example
```

`DemoM2_Tls` starts its own token service on an ephemeral port. It shows `web-01` getting a lease bound to its
certificate and IP, `api-01` being denied (no approved edge), the untrusted-CA certificate failing the TLS
handshake, and tampered leases being rejected by the gateway's verifier. It exits 0 when every check passes.

`DemoM2_Tls` uses `config/bootstrap.properties.example` as a fixed fixture. A standalone token service gets its state
from the control plane (see "Control plane and M5 demo").

## NIO gateway and M1 demo

```powershell
java -cp out eastguard.demos.DemoM1_Nio          # optional arg: session count (default 500)

# Or run the pieces by hand (backend first):
java -cp out eastguard.demos.EchoBackend 127.0.0.1:7002
java -cp out eastguard.gateway.NioGateway --config config/gateway-app-02.properties.example
```

`DemoM1_Nio` starts the echo backend on its fixed port `127.0.0.1:7002` (it fails if that port is busy), and a
token service and gateway `app-02` on ephemeral ports. It then:

1. opens 500 concurrent `web-01` sessions on one lease and prints the gateway-owned thread count (one selector
   plus two TLS task threads) and admission latency;
2. shows `api-01` (no approved edge) refused by the token service, then refused by the gateway when it presents a
   validly signed lease or replays `web-01`'s lease;
3. pushes 16 MiB through a slow reader, printing in-flight bytes, gateway queue and read pauses;
4. touches the decoy port.

It exits 0 when every check passes.

The gateway is one selector thread with an explicit per-connection state machine
(`TLS_HANDSHAKE → READ_PREAMBLE → AUTHORIZE → CONNECT_BACKEND → WRITE_REPLY → RELAY → CLOSED`). It sends ALLOW
only after the backend connect succeeds and a second authorization check passes. Deadlines and limits are the
`limits.*` keys in the gateway config, with spec §9.1 defaults. `DemoM1_Nio` uses the bootstrap file as a fixed
fixture; a standalone gateway syncs its state from the control plane. See `docs/DEVIATIONS.md` (Task 5).

## Control plane and M5 demo

```powershell
.\scripts\windows\gen-credentials.ps1      # once: per-principal API secrets in keys\api\, digests in keys\control-credentials.properties
java -cp out eastguard.demos.DemoM5_Rmi
```

`DemoM5_Rmi` runs every component in one JVM with the production wiring and the example configs. The control
plane listens on 127.0.0.1:1099/1100 with a fresh journal under `out\demo-m5`. The token service and gateway
`app-02` sync over RMI, and the echo backend listens on 127.0.0.1:7002. The demo then:

1. makes an audited policy edit (`api-01` → `app-02`);
2. sends a stale edit, which gets CONFLICT;
3. retries a request whose reply was "lost" (no duplicate commit), and reuses its ID with a different payload (INVALID);
4. quarantines `web-01`, which closes its live session through sync while `api-01`'s session continues;
5. releases `web-01`: the old lease fails on its watermark and a fresh lease works;
6. reads `ztp://policy/app-02` as a typed `PolicyView` through the explicit URL handler, and shows that URLs naming
   another host, a port, a query or a path are rejected;
7. reads the HTTPS audit export page by page with `HttpsURLConnection` and the console certificate (normal
   hostname verification), and shows a workload certificate getting 403;
8. stops the control plane: sessions close and issuance and admission stop when the 5 s freshness runs out.

It exits 0 when every check passes.

Running the pieces by hand (all configs are the shipped examples):

```powershell
# One-time explicit bootstrap of the deny-by-default policy into the journal (journal\ is git-ignored)
java -cp out eastguard.control.ControlPlaneImpl bootstrap --config config/control.properties.example `
     --state config/bootstrap.properties.example --reason "initial deny-by-default policy"
java -cp out eastguard.control.ControlPlaneImpl --config config/control.properties.example
java -cp out eastguard.tokensvc.TokenServer --config config/token.properties.example
java -cp out eastguard.demos.EchoBackend 127.0.0.1:7002
java -cp out eastguard.gateway.NioGateway --config config/gateway-app-02.properties.example
```

The control plane commits every change to an append-only journal and forces it to disk before replying. It
replays the journal at startup and refuses to start on a corrupt record or a revision gap. RMI uses TLS 1.3 with
client certificates on both the registry and the object port. Every call carries a per-principal API
credential, checked against a role (VIEWER, OPERATOR, ADMIN, GATEWAY, ISSUER, DETECTOR).

Rotate or revoke a credential with `.\scripts\windows\gen-credentials.ps1 -Rotate <name>` / `-Retire <name>` /
`-Revoke <name>`; the control plane reloads the file without a restart.

Gateways and the token service admit nothing until their first successful sync, and treat state as stale 5 s
after the last successful sync started. See `docs/DEVIATIONS.md` (Task 6).

## Telemetry, threat detector and M3 demo

```powershell
java -cp out eastguard.demos.DemoM3_Udp          # self-contained: in-memory keys, journal under out\demo-m3
```

`DemoM3_Udp` sends a labelled fixture stream of telemetry datagrams over real UDP to a `ThreatDetector`, which
calls a control plane in the same JVM. It shows CIDR classification, the restart guard, learning candidates
(pilot vs. unscoped), the score transitions clean 30 → 40 → alert at 50 (a lease reduction that shortens only
newly issued `web-01` leases to 10 s) → critical at 110 (quarantine), decoy hits (a managed IP is quarantined;
shared NAT and protected infrastructure only alert), and forged, duplicate, out-of-scope and oversized datagrams
that leave every score unchanged. It exits 0 when every check passes.

Running the detector for real needs its certificate and the per-producer HMAC keys:

```powershell
.\scripts\windows\gen-certs.ps1 -AddComponent detector   # keys\detector.p12 from the existing demo CA
.\scripts\windows\gen-credentials.ps1 -TelemetryKeys     # keys\telemetry\gw-app-02.key, tokensvc.key (kept if present)
java -cp out eastguard.detector.ThreatDetector --config config/detector.properties.example
```

Gateways and the token service send telemetry when `telemetry.collector` is set (it is in the example configs).
Sending never blocks: a full queue drops events and counts them, and the sequence gap shows the loss to the
detector. Automation is off in both `detector.properties.example` and `control.properties.example`
(alert-only). Turn on `automation.leaseReduction` / `automation.quarantine` in **both** files to let the
detector propose actions and the control plane commit them. See `docs/DEVIATIONS.md` (Task 7).

## Multicast quarantine bus and M4 demo

```powershell
java -cp out eastguard.demos.DemoM4_Multicast            # real multicast 239.20.20.20:4446 on 127.0.0.1
java -cp out eastguard.demos.DemoM4_Multicast --memory   # in-memory transport instead
```

After a quarantine or release is committed and forced to the journal, the control plane multicasts the same
Ed25519-signed EGC1 notice three times (`multicast.*` and `notice.*` in `control.properties.example`). Gateways
and the token service join the group before their first sync and verify the cluster, the control key published
in the snapshot, the signature, the bounds and a ±30 s timestamp. A newer QUARANTINE blocks at once and closes
matching gateway sessions; any newer notice triggers an immediate sync, and new issuance and admissions pause until
it arrives. A RELEASE only triggers a sync: blocks are cleared by a covering snapshot, never by a notice.

`DemoM4_Multicast` runs three gateways and the token service as receivers. It measures commit → matching
session closed over 20 quarantines (spec target p95 < 100 ms; about 3 ms on loopback here), then shows that
duplicates are applied once, a dropped notice still converges through sync, a late old notice does not roll
state back, a RELEASE clears nothing until the snapshot arrives, and the released workload's old lease is
rejected by the watermark while a new lease works. It exits 0 when every check passes. It needs `keys\` from
`gen-certs.ps1` (including the notice signer) and uses ports 7002 (backend) and 4446 (multicast). See
`docs/DEVIATIONS.md` (Task 8), including the multicast qualification status.

## Operator console, audit export and `ztp://`

The console has its own client certificate and API credentials. Both scripts add them without touching
existing keys:

```powershell
.\scripts\windows\gen-certs.ps1 -AddConsole      # keys\console.p12: clientAuth only, SAN urn:eastguard:console:dashboard
.\scripts\windows\gen-credentials.ps1 -Add console-viewer:VIEWER,console-operator:OPERATOR,console-admin:ADMIN
```

A fresh `gen-certs.ps1` / `gen-credentials.ps1` run creates them as well.

```powershell
# Live: against the running control plane (control.principal picks the role; console-operator by default)
java -cp out eastguard.dashboard.DashboardApp --config config/dashboard.properties.example
# Demo profile: labeled, read-only fixture scenarios; no network, no actions
java -cp out eastguard.dashboard.DashboardApp --demo
```

The console has five tabs. **Topology** shows workloads, services, approved edges, candidates, denials,
quarantine overlays and a quarantined identity's *potential blast radius*, each with a symbol and a text label
as well as a colour. **Alerts** separates committed actions from refused proposals. **Policy and learning**
shows the mode and revisions and lets you review the draft, preview the exact edge diff and freeze it.
**Quarantine** lists selector type, reason, expiry and overlaps, and quarantine and release both ask for a
reason and a confirmation. **Audit** lists the audit trail.

All RMI runs on one background thread with at most one poll outstanding. When the control plane is slow or
gone, a banner marks the view STALE or DISCONNECTED and every edit is disabled. Buttons the console's role may
not use are disabled too, and the control plane still checks the role on every call.

The control plane serves `https://127.0.0.1:9443` (`audit.*` in `control.properties.example`) with `/audit`
(paginated: `?limit=1..200&cursor=<revision>`), `/metrics`, `/health/live` and `/health/ready`. It is
read-only and requires a client certificate whose URI SAN is in `audit.allowedClients`.

`ztp://policy/<serviceId>` is read with an explicit handler and never registered globally:
`URL.of(URI.create("ztp://policy/app-02"), new ZtpUrlHandler(client::getPolicy)).getContent()` returns a typed
`eastguard.handlers.PolicyView`. See `docs/DEVIATIONS.md` (Task 9).

## Writing tests

Tests use a JDK-only runner, no JUnit.

1. Create a class in `test/eastguard/test/` with a public no-arg constructor.
2. Add public instance methods named `test*`. Each runs on a fresh instance.
3. Use the helpers in `eastguard.test.Assert` (`assertEquals`, `assertTrue`, `assertThrows`, ...).
4. Register the class in `AllTests.TEST_CLASSES`, then regenerate `sources.txt` and rebuild.

See `SmokeTest` for a minimal example. Use deterministic `Clock`s in tests, never wall time.
