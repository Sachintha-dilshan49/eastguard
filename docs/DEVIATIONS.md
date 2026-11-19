# Deviations from the specification

Each entry records a deliberate simplification, why it was made, and what would remove it.

## Task 3 — TLS and identity

| # | Spec | Simplification | Reason / removal |
|---|------|----------------|------------------|
| 3.1 | §9.1 "protected paths for PKCS#12 files … RPC credentials" | All runtime TLS stores (token service, gateway, control plane, workloads, trust store) share one demo password (`EASTGUARD_STORE_PASS` / `keys\store.pass`). The lease signer and the CA stores have their own passwords. | One password per process role is the production setup. The demo runs every role on one machine as one user. Remove it by adding per-role `*.passwordEnv`/`*.passwordFile` settings (the config keys already exist per component). |
| 3.2 | §9.1 "Do not put secrets in … command-line arguments" | Followed. keytool reads passwords with `-storepass:env`. When no env var is set, the password lives in a git-ignored file with a current-user-only ACL. | — |
| 3.3 | §4.1 certificate revocation | No CRL/OCSP. A revoked certificate is expressed as a leaf fingerprint in `Workload.revokedCertificates` in the enforcement snapshot, and `WorkloadIdentity`/`PolicyEvaluator` check it on every connection. | Matches the spec's snapshot-based revocation; PKIX revocation checking would need a CRL distribution point the demo CA does not run. |
| 3.4 | §4.1 session resumption | TLS session resumption is left on. The identity, revocation and validity checks run on every connection against the current state, including resumed sessions, so resumption cannot bypass them. | — |
| 3.5 | `ReasonCode` | Appended `BAD_IDENTITY(18)` for "no single approved workload URI SAN / certificate outside validity", distinct from `IDENTITY_DISABLED`. | Append-only, as the enum's wire contract allows. |

## Task 4 — Token service and client

| # | Spec | Simplification | Reason / removal |
|---|------|----------------|------------------|
| 4.1 | §6.2 freshness, §9.1 "load policy from the control-plane journal" | The token service runs on a **static bootstrap snapshot** read from `bootstrap.*` keys in its properties file, and treats it as always fresh. | No control plane exists yet. Task 6 replaces the `Supplier<EnforcementView>` passed to `TokenServer` with a synced view that becomes unusable after `state.maxAgeMillis`. |
| 4.2 | §4.2 "per-client limits" | Fixed one-second window per authenticated identity (`IssueLimiter`), default 20 requests/s. The map is capped at 10 000 identities and fails closed when full. | Good enough to stop a single workload from hammering the signer. A token bucket would smooth bursts. |
| 4.3 | §1 "selected token-service denials" telemetry | Not emitted yet. Denials are logged (identity, service, reason, never the token) and counted in `TokenServer.Stats`. | Task 7 adds the UDP telemetry producer. |
| 4.4 | §4.1 / §10 "Untrusted certificate … TLS fails" | Met on the server side, which is the authoritative signal. With TLS 1.3 the **client** finishes its handshake before the server rejects its certificate, so the client sees the failure on its first read: as an `SSLException`, or on Windows often as a `SocketException` (connection reset) because the reset discards the server's alert. The demo and tests assert the server-side handshake failure and that no application reply was sent. | Inherent to TLS 1.3 client authentication. |
