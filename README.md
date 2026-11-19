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
demo CA, a separate untrusted CA, PKCS#12 stores for the token service, gateway `app-02`, the control plane, and
workloads `web-01` / `api-01` (URI SAN `urn:eastguard:workload:<id>`), a `web-01` look-alike signed by the
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

Until the control plane exists (Task 6), the token service reads its policy from the `bootstrap.*` keys of its
config file. See `docs/DEVIATIONS.md`.

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
`limits.*` keys in the gateway config, with spec §9.1 defaults. Until Task 6, the gateway reads the token
service's bootstrap state through `bootstrap.file`. See `docs/DEVIATIONS.md` (Task 5).

## Writing tests

Tests use a JDK-only runner, no JUnit.

1. Create a class in `test/eastguard/test/` with a public no-arg constructor.
2. Add public instance methods named `test*`. Each runs on a fresh instance.
3. Use the helpers in `eastguard.test.Assert` (`assertEquals`, `assertTrue`, `assertThrows`, ...).
4. Register the class in `AllTests.TEST_CLASSES`, then regenerate `sources.txt` and rebuild.

See `SmokeTest` for a minimal example. Use deterministic `Clock`s in tests, never wall time.
