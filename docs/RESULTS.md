# Measured results

All numbers were measured on 21–22 Nov 2026 on one development laptop. They are measurements on this machine,
not guarantees, and not the "declared hardware" release load test that spec §10 asks for (see "Limits").

## Machine

| | |
|---|---|
| CPU | 12th Gen Intel Core i7-12700H (14 cores / 20 threads, 2.3 GHz base) |
| RAM | 15.6 GiB |
| OS | Windows 11 Home Single Language 10.0.26200 (64-bit), power plan "Balanced", on mains power |
| JDK | Oracle Java SE 25 (build 25+37-LTS-3491), HotSpot 64-bit Server VM; compiled with `javac --release 21`. No JDK 21 runtime is installed on this machine, so the runs below are on JDK 25. |
| Network | everything on `127.0.0.1`; multicast `239.20.20.20:4446` on the loopback interface (`loopback_0`), TTL 1 |
| JVM flags | none (default heap and GC); default `java.util.logging` at INFO |

## Summary against the spec §10 targets

| Target (spec §10) | Measured | Source | Met here? |
|---|---|---|---|
| 500+ sessions in the live NIO demo | **1,000** concurrent relay sessions, each echoed twice while all were open | `DemoM1_Nio 1000` | yes |
| 1,000 concurrent sessions with fewer than 10 gateway-owned platform threads; bounded memory | **3** gateway-owned platform threads (selector + 2 TLS task threads); 39 JVM platform threads in total; **94.4 MiB** of the 256 MiB buffer budget reserved (96 KiB per connection, fixed at accept) | `DemoM1_Nio 1000` | yes |
| Admission p95 < 5 ms, preamble → flushed ALLOW, warmed gateway, local backend (incl. verification and backend connect) | warmed, sequential, 200 samples: **p50 1.30 ms, p95 1.73 ms, p99 2.22 ms**, 0 errors | `DemoM1_Nio 1000` (gateway-side timer) | yes |
| ... same, under a burst | 1,000 samples with 64 concurrent connects and client crypto in the same JVM: p50 62.7 ms, **p95 134.7 ms, p99 196.5 ms** (time queued behind other handshakes on the one selector) | `DemoM1_Nio 1000` | no (see Limits) |
| Cold TLS and lease acquisition, measured separately | client-observed connect (TCP + TLS 1.3 handshake with client certificate + preamble + admission + ALLOW), warmed, sequential, 200 samples, three runs: **p50 12.5–13.7 ms, p95 17.5–18.5 ms, p99 18.7–19.8 ms** | `DemoFinal --measure 50` (separate JVMs) | reported |
| Containment p95 < 100 ms, quarantine commit → matching session closed | **in one JVM**, 3 gateways × 20 quarantines, three runs: p50 3.6 ms, **p95 4.9–6.8 ms**, max 19.9–39.2 ms. **Across separate JVM processes**, 2 gateway processes × 50 quarantines, three runs: commit acknowledged → session EOF **p50 4.7–4.9 ms, p95 6.5–7.4 ms, p99 7.8–19.0 ms**; operator call start → EOF (adds the RMI call and journal force) p50 9.9–10.0 ms, p95 13.1–26.2 ms, p99 22.3–69.4 ms | `DemoM4_Multicast`, `DemoFinal --measure 50` | yes |
| Decoy event → closure < 500 ms with automation enabled | TCP touch of the decoy listener → DECOY telemetry → detector CRITICAL → proposal → control-plane commit → multicast → live sessions closed at **both** gateway processes, three runs: **77–87 ms** | `DemoFinal` step 4 | yes |
| Convergence when multicast is deliberately dropped | all three copies dropped: sessions closed after the next poll, **904–1,085 ms** after the commit (poll 1 s ± 20 %) | `DemoM4_Multicast` step 3 | yes |
| Control-plane loss: deny and close after the freshness deadline | live sessions closed **4,746 ms** after the control plane stopped (5 s freshness, measured from the start of the last successful sync); issuance and admission then answer UNAVAILABLE | `DemoM5_Rmi` step 8 | yes |
| Quarantine via polling only (no notice sender) | 727 ms commit → closure | `DemoM5_Rmi` step 4 | reported |
| Security-critical negative tests, recovery drills, resource limits, isolation check | **357 tests, 0 failures** in `AllTests`; §10 scenario-by-scenario mapping in [`TEST-COVERAGE.md`](TEST-COVERAGE.md) | `java -ea -cp out eastguard.test.AllTests` | yes, with the isolation limits stated there |

## How to reproduce

```powershell
java -cp out eastguard.demos.DemoM1_Nio 1000        # sessions, threads, admission latency, buffers
java -cp out eastguard.demos.DemoM4_Multicast       # in-JVM containment, dropped/duplicate/late notices
java -cp out eastguard.demos.DemoM5_Rmi             # poll-path quarantine, control-plane loss closure
.\scripts\run-demo.ps1 -Reset -RunFinal -FinalArgs '--measure','50'   # separate JVMs: decoy, containment, connect
java -ea -cp out eastguard.test.AllTests            # test count
```

Each demo prints its own percentiles. Percentiles are nearest-rank over the listed samples. Nothing else heavy
was running during the measurements; the build and test suite were not running at the same time.

## Operational checks (by hand, this machine)

| Check | Outcome |
|---|---|
| `run-demo.ps1` start order and readiness (§9.2) | control plane (`/health/ready` 200 with the console certificate) → detector → token service → backend 7002 → gateway app-02 → backend 7003 → gateway app-03, each 0.2–3.1 s; then the detector's 10 s restart guard is waited out |
| Clean stop | every component exits through its shutdown hooks with exit code 0, in reverse start order |
| A component dies | gateway app-03 force-killed while running: the launcher reported "exited unexpectedly", stopped the other six cleanly and exited 1 |
| The launcher dies (window closed) | the launcher's PowerShell process force-killed: all 14 `java.exe` (7 `javapath` shims + 7 JVMs) gone within 4 s; each JVM logged "launcher process … ended" |
| Control-plane crash during commits | control plane force-killed while `DemoFinal --measure` was committing quarantine/release pairs; last commit logged before the kill: revision 15. Restart replayed 15 records to revision 15, no corrupt or torn record, `/health/ready` 200: no acknowledged commit lost |
| Port preflight | a stale `ThreatDetector` from an earlier session holding UDP 5514 was reported before anything started ("ports already in use: udp/5514") |

## Behaviour worth knowing, found while building the final demo

- **The detector quarantines retry storms.** An early `DemoFinal` retried a refused `api-01` lease every 150 ms
  while the token service had not yet polled a mode change. Five authenticated `POLICY_DENY` events in under a
  second reached score 100, and the detector's automatic quarantine of `identity:api-01` was committed. That is
  the specified behaviour. The demo now waits one poll interval (policy edits are polled, not multicast) and keeps
  each workload below 100.
- **Poll skew between enforcement points.** Right after a policy commit, the token service can issue a lease at
  the new revision while a gateway still has the previous one. The gateway then fails closed (`NOT_READY`) until
  its own next poll, up to about 1.2 s. Quarantine and release do not have this gap, because their notice
  triggers an immediate sync everywhere.

## Limits

- **One laptop, loopback only.** No multi-host segment, physical switch, IGMP snooping or packet loss on a real
  network. Containment numbers are loopback numbers. Real multicast across hosts is not qualified (DEVIATIONS 8.8).
- **Client and server share the machine.** In `DemoM1_Nio` the 1,000 clients run in the gateway's JVM, and in
  `DemoFinal` all seven components and the client share 20 hardware threads, so TLS work competes for the same
  CPU. The burst admission p95 (135 ms) is dominated by queueing behind concurrent handshakes on the single
  selector thread and by client-side crypto. The < 5 ms target is met warmed and sequential, not under a
  64-connection burst. Handshakes do not run on the selector (they use the 2-thread TLS task pool), but the
  selector serializes record processing for every connection.
- **Not a declared-hardware release load test.** No sustained-throughput run, no soak test, no GC tuning, no
  memory profile beyond the fixed buffer reservation. Heap and GC are defaults.
- **JDK 25, not 21.** Compiled with `--release 21` (language level and API pinned) but run on a JDK 25 runtime;
  a JDK 21 runtime was not available on this machine.
- **Variance.** Laptop with a Balanced power plan: run-to-run spread is visible above (e.g. p99 of operator call
  → EOF 22–69 ms). Single runs of `DemoM1_Nio` and `DemoM5_Rmi` are reported, not distributions.
- **Containment start point.** "Commit acknowledged → EOF" starts when the RMI reply reaches the client, after the
  journal force. The notice can leave before that reply arrives, so a few samples are 0 (clamped). The upper
  bound "call start → EOF" is reported next to it.
