# EastGuard — Claude Code project guide

Network Programming module (FIT, University of Moratuwa), Assignment 02. Deadline: 26 Nov 2026.
Implemented by one developer (Sachintha) covering all five concept areas: NIO, TLS, UDP, multicast, RMI/HTTPS/URL handlers.
Full specification: `docs/EASTGUARD.md` — read the relevant section before implementing anything.

## What this is
Zero-trust east-west TCP access control. A Java client gets a short-lived Ed25519-signed lease from a
Token Service over mTLS, presents it to an NIO Gateway over mTLS, and the gateway relays bytes to a fixed
private backend only after authorization. Gateways send HMAC-authenticated UDP telemetry to a Threat
Detector; the detector proposes quarantine to the Control Plane (RMI); the Control Plane commits it to a
journal and broadcasts signed multicast notices. Swing dashboard + HTTPS audit export + `ztp://` URL handler.

## Environment
- Windows + PowerShell, project at `D:\projects\eastguard`. Write helper scripts as `.ps1`, never bash.
- JDK 21 on PATH. No Maven/Gradle.
- Regenerate sources: `.\scripts\sources.ps1` (writes `sources.txt` from all `*.java` under `src` and `test`).
- Build: `javac --release 21 -d out "@sources.txt"`
- Test: `java -ea -cp out eastguard.test.AllTests`
- Demo keys: `.\scripts\gen-certs.ps1` (keytool only) into `keys\` (git-ignored).

## Hard rules
- Java 21, JDK only. No external libraries, no frameworks.
- Package root `eastguard`. Layout per spec §8 (common, client, gateway, tokensvc, detector, bus,
  control, dashboard, handlers, demos; tests in `test/eastguard/test`).
- Big-endian binary wire formats exactly as spec §5. Never Java serialization on data plane or UDP.
- Immutable records for state/DTOs; defensively copy arrays and collections.
- Inject `Clock` for wall time; `System.nanoTime()` for durations.
- `java.util.logging` only. Never log tokens, keys, credentials, or payloads.
- Default deny. Fail closed when state is stale.
- Never commit keys, keystores (*.p12), or real `.properties` files — only `*.properties.example`.

## Task plan (one task per Claude Code session; commit after each)
1. Tooling: `scripts/sources.ps1`, JDK-only test runner `AllTests`, README build section.
2. `common`: domain records, `Cidr`, `ReasonCode`, wire codecs (lease, preamble, telemetry, notice), Ed25519 + HMAC helpers, `PolicyEvaluator` + tests.
3. TLS: `scripts/gen-certs.ps1`, `TlsContextFactory`, SAN → workload identity mapping.
4. Token service + `EastGuardClient` issuance (blocking SSLServerSocket, virtual threads) → `DemoM2_Tls`.
5. NIO gateway: Selector + SSLEngine state machine, preamble, backend connect, relay, decoy listener → `DemoM1_Nio`.
6. Control plane: journal, single writer, snapshots, secured RMI `sync` + mutations, fail-closed freshness in gateway/issuer → `DemoM5_Rmi`.
7. UDP telemetry + threat detector (sliding window, scoring, proposals) → `DemoM3_Udp`.
8. Multicast quarantine bus, overlays, release watermarks → `DemoM4_Multicast`.
9. Swing dashboard, HTTPS audit export, `ztp://` URL/content handlers, learning freeze.
10. Spec §10 failure tests, end-to-end demo script, README run guide.

Scope note: deadline is tight. Prioritise a working end-to-end demo (spec §11 "Final demo") and the five
concept demos. Hardening (key rotation, load tests, crash drills) may be simplified — record each
simplification in `docs/DEVIATIONS.md`.

## Working style for Claude
- Small, compiling steps. After every change: regenerate sources, compile, run AllTests.
- Write tests alongside each codec/evaluator. Deterministic clock in tests.
- Focused classes; explicit code over abstractions.
- If the spec is ambiguous or too large for the deadline, propose a simplification and ask before diverging.
- At the end of a task, summarise what was built, what was simplified, and the suggested commit message.
