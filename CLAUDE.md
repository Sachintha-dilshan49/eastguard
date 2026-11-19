# EastGuard — Claude Code project guide

Network Programming module (FIT, University of Moratuwa), Assignment 02. Group of 5. Deadline: 26 Nov 2026.
Full specification: `docs/EASTGUARD.md` (read the relevant section before implementing anything).

## What this is
Zero-trust east-west TCP access control. A Java client gets a short-lived Ed25519-signed lease from a
Token Service over mTLS, presents it to an NIO Gateway over mTLS, and the gateway relays bytes to a fixed
private backend only after authorization. Gateways send HMAC-authenticated UDP telemetry to a Threat
Detector; the detector proposes quarantine to the Control Plane (RMI); the Control Plane commits it to a
journal and broadcasts signed multicast notices. Swing dashboard + HTTPS audit export + `ztp://` URL handler.

## Hard rules
- Java 21, JDK only. No Maven/Gradle dependencies, no frameworks, no external libraries.
- Build: `javac --release 21 -d out @sources.txt`; tests: `java -ea -cp out eastguard.test.AllTests`.
- Regenerate `sources.txt` after adding files (see README).
- Package root `eastguard`. Layout follows spec §8 (common, client, gateway, tokensvc, detector, bus,
  control, dashboard, handlers, demos; tests under `test/eastguard/test`).
- Big-endian binary wire formats exactly as in spec §5. Never Java serialization on data plane or UDP.
- Immutable records for state/DTOs; defensively copy arrays and collections.
- Inject `Clock` for wall time; use `System.nanoTime()` for durations.
- `java.util.logging` only. Never log tokens, keys, credentials, or payloads.
- Default deny everywhere. Fail closed when state is stale.
- Never commit keys, keystores (*.p12), or real properties files — only `*.properties.example`.

## Ownership (spec §11)
| Member | Packages | Demo |
|---|---|---|
| M1 | gateway (NIO, SSLEngine, relay, decoy) | `DemoM1_Nio` |
| M2 | tokensvc, client, lease codec, TLS setup | `DemoM2_Tls` |
| M3 | detector, telemetry codec, Cidr | `DemoM3_Udp` |
| M4 | bus (multicast), snapshot freshness/overlays | `DemoM4_Multicast` |
| M5 | control (RMI, journal, HTTPS audit), dashboard, handlers | `DemoM5_Rmi` |
`common` is shared — change its contracts only with team agreement.

## Build order
1. `common`: records, codecs (lease, preamble, telemetry, notice), Ed25519/HMAC helpers, `PolicyEvaluator`, `Cidr` + unit tests.
2. Happy path: mTLS issuer → client → NIO gateway → local backend.
3. Control plane + journal + sync + fail-closed freshness.
4. Telemetry, detector, multicast quarantine, release watermarks.
5. Dashboard, audit export, learning freeze.
6. Failure tests (spec §10).

## Working style for Claude
- Work in small, compiling steps. After every change: compile, run AllTests.
- Write a unit test with each codec/evaluator. Use a deterministic clock in tests.
- Keep each class focused; prefer explicit code over abstractions.
- If the spec is ambiguous or too large for the deadline, propose a simplification and ask before diverging.
