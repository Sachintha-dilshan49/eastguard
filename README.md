# EastGuard

Zero-trust east-west TCP access control: Ed25519-signed short-lived leases over mTLS, an NIO gateway
that relays only after authorization, UDP telemetry to a threat detector, RMI control plane, and signed
multicast quarantine notices. Full specification: [`docs/EASTGUARD.md`](docs/EASTGUARD.md).

Java 21, JDK only. No Maven, Gradle, or external libraries.

## Build and test (PowerShell)

Run from the project root (`D:\projects\eastguard`). Needs a JDK 21 or newer `javac`/`java` on PATH;
`--release 21` pins the language level and API.

```powershell
# 1. Regenerate the javac argument file after adding/removing .java files
.\scripts\sources.ps1

# 2. Compile everything (src + test) into out\
javac --release 21 -d out "@sources.txt"

# 3. Run all tests (exit code 0 = all passed, 1 = any failure or no tests ran)
java -ea -cp out eastguard.test.AllTests

# Run only test classes whose simple name contains a filter
java -ea -cp out eastguard.test.AllTests Wire
```

Notes:

- Quote `"@sources.txt"`. Unquoted, PowerShell treats `@sources` as array splatting and javac gets no files.
- If the execution policy blocks the script, run
  `powershell -ExecutionPolicy Bypass -File scripts\sources.ps1`.
- Clean build: `Remove-Item -Recurse -Force out` then repeat steps 2–3.

The first test run also generates a throwaway test PKI by running `scripts\gen-certs.ps1 -TestFixtures`
into `out\test-pki` (about 20 s). Later runs reuse it until `out\` is deleted or the certificates are near
expiry. Pass `-Deastguard.testLog=true` to `java` to see server logs during tests.

## Demo keys and certificates

```powershell
.\scripts\gen-certs.ps1            # writes keys\ (git-ignored); -Force to regenerate
```

This uses JDK `keytool` only. It finds keytool via `JAVA_HOME`, then PATH, then the active `java`. It creates a
demo CA, a separate untrusted CA, PKCS#12 stores for the token service, gateway `app-02`, the control plane, the
threat detector, and workloads `web-01` / `api-01` (URI SAN `urn:eastguard:workload:<id>`), a `web-01`
look-alike signed by the
untrusted CA, and the Ed25519 lease-signing key `lease-k1`.

Passwords never appear on a command line or in the output:

| Store | Environment variable | Fallback file (created if missing) |
|-------|----------------------|------------------------------------|
| Runtime TLS stores + trust store | `EASTGUARD_STORE_PASS` | `keys\store.pass` |
| Lease signer | `EASTGUARD_SIGNER_PASS` | `keys\signer.pass` |
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
.\scripts\gen-credentials.ps1      # once: per-principal API secrets in keys\api\, digests in keys\control-credentials.properties
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
6. stops the control plane: sessions close and issuance and admission stop when the 5 s freshness runs out.

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

Rotate or revoke a credential with `.\scripts\gen-credentials.ps1 -Rotate <name>` / `-Retire <name>` /
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
.\scripts\gen-certs.ps1 -AddComponent detector   # keys\detector.p12 from the existing demo CA
.\scripts\gen-credentials.ps1 -TelemetryKeys     # keys\telemetry\gw-app-02.key, tokensvc.key (kept if present)
java -cp out eastguard.detector.ThreatDetector --config config/detector.properties.example
```

Gateways and the token service send telemetry when `telemetry.collector` is set (it is in the example configs).
Sending never blocks: a full queue drops events and counts them, and the sequence gap shows the loss to the
detector. Automation is off in both `detector.properties.example` and `control.properties.example`
(alert-only). Turn on `automation.leaseReduction` / `automation.quarantine` in **both** files to let the
detector propose actions and the control plane commit them. See `docs/DEVIATIONS.md` (Task 7).

## Writing tests

Tests use a JDK-only runner, no JUnit.

1. Create a class in `test/eastguard/test/` with a public no-arg constructor.
2. Add public instance methods named `test*`. Each runs on a fresh instance.
3. Use the helpers in `eastguard.test.Assert` (`assertEquals`, `assertTrue`, `assertThrows`, ...).
4. Register the class in `AllTests.TEST_CLASSES`, then regenerate `sources.txt` and rebuild.

See `SmokeTest` for a minimal example. Use deterministic `Clock`s in tests, never wall time.
