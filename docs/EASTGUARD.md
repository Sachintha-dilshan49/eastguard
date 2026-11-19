# EastGuard --- Production V1 Engineering Specification

**File:** `EASTGUARD.md`\
**Stack:** Java 21 and the JDK only. Java networking and security APIs
for the backend, Swing for the frontend.\
**Deployment target:** One managed network segment, with a gateway in
front of each protected service.

## 1. What to build

EastGuard controls east-west TCP access between workloads. A Java client
obtains a short-lived lease over mutual TLS, presents it to the target
service's gateway, and relays application bytes only after the gateway
authorizes the connection. Gateways report connection decisions to a
detector. The detector can propose quarantine; the control plane commits
the decision and notifies enforcement components.

The first release has **one control plane, one token service, one
detector, and multiple gateways**. It does not need a database server,
web frontend, message broker, or distributed consensus.

  -----------------------------------------------------------------------
  Requirement                         V1 behavior
  ----------------------------------- -----------------------------------
  Authenticate                        Identify workloads by an approved
                                      certificate SAN, both when issuing
                                      a lease and when connecting to a
                                      gateway.

  Authorize                           Require a valid lease for the exact
                                      identity, certificate, source IP,
                                      and destination service. Evaluate
                                      current policy at both issuance and
                                      admission. Default deny.

  Relay                               Forward TCP bytes to one fixed
                                      backend per gateway. Never forward
                                      application bytes before
                                      authorization.

  Observe                             Emit authenticated, best-effort UDP
                                      events for gateway decisions and
                                      selected token-service denials. Do
                                      not collect application payloads.

  Learn                               Collect candidate edges during an
                                      explicitly scoped pilot. Operators
                                      review candidates before they
                                      become an allow-list.

  Detect                              Score observed events in bounded
                                      sliding windows. Alert first;
                                      enable automatic quarantine only
                                      for approved scopes.

  Contain                             Refuse new leases and connections
                                      for quarantined selectors and close
                                      matching live gateway sessions.

  Recover                             Support audited release and expiry.
                                      A released workload needs a newly
                                      issued lease.

  Operate                             Provide a Swing dashboard,
                                      read-only HTTPS audit export,
                                      configuration validation, health
                                      checks, and documented recovery.
  -----------------------------------------------------------------------

**Non-goals:** Transparent support for unmodified clients, packet
capture, inspection of application payloads, visibility into arbitrary
closed ports, routed multicast, and highly available control-plane
writes. The demo uses deterministic fixtures for suspicious behavior,
not a network scanner, credential-replay tool, or pivot tool.

### Production changes from the prototype

-   **Use mTLS at the gateway, not just at the token service.**
    Application TLS inside the relay does not itself protect a token
    preamble sent before that application handshake.
-   **Sign leases and control notices with Ed25519.** Gateways receive
    public verification keys, not secrets that let them issue leases or
    quarantine orders.
-   **Multicast makes restrictions fast; it does not authorize
    release.** Only a fresh authoritative snapshot can remove an
    enforcement block.
-   **A cached policy is valid for a bounded time.** An unreachable
    control plane is not instant global lockdown, but an expired
    snapshot is never used to admit or continue traffic.
-   **A decoy hit is a high-confidence signal, not proof of
    compromise.** Misconfiguration and shared source addresses can
    produce false positives.

## 2. Architecture and trust boundaries

``` text
Java workload
  |-- mTLS: request lease ----------------------> Token Service
  |
  `-- mTLS: lease preamble, then payload -------> NIO Gateway
                                                    |
                                                    `-- fixed private backend
                                                        in the same isolation boundary

Gateway / Token Service -- authenticated UDP ---> Threat Detector
Threat Detector --------- secured RMI ----------> Control Plane
Dashboard --------------- secured RMI ----------> Control Plane
Gateways / Token Service - secured RMI ---------> authoritative state sync

Control Plane -- signed multicast notices ------> Gateways / Token Service
Control Plane -- restricted HTTPS --------------> audit and metrics readers
```

  -----------------------------------------------------------------------
  Endpoint                Example                 Boundary
  ----------------------- ----------------------- -----------------------
  Gateway data listener   TCP `9002`              Workload network; mTLS
                                                  required.

  Protected backend       `127.0.0.1:7002`        Private to the
                                                  gateway/backend
                                                  deployment boundary.

  Token service           TCP `8443`              Workload-facing
                                                  issuance endpoint; mTLS
                                                  required.

  Flow telemetry          UDP `5514`              Management network;
                                                  authenticated producer
                                                  records.

  Quarantine bus          UDP `239.20.20.20:4446` Explicit interface,
                                                  multicast TTL 1; signed
                                                  notices.

  RMI                     TCP `1099` registry,    Management network;
                          `1100` remote object    both endpoints use TLS
                                                  with client
                                                  authentication.

  Audit export            TCP `9443`              Management network;
                                                  HTTPS, read-only,
                                                  authenticated.
  -----------------------------------------------------------------------

**Deployment invariant:** A workload must not be able to reach the
backend directly. Loopback is sufficient only if untrusted workloads
cannot enter that network namespace or otherwise reach the listener.
Verify this at deployment time. V1 supports a colocated backend; a
remote backend needs a separate design for authenticated transport and
network enforcement.

**Threat model:** An untrusted workload may connect to listeners, submit
malformed data, or operate with its own valid workload credentials. A
compromised workload can still exercise permissions it legitimately
holds until enforcement changes. EastGuard does not prevent misuse
inside an allowed application session, recall already delivered bytes,
or protect a backend from a compromised gateway host. The internal CA,
token signer, and control-plane signer are privileged assets.

## 3. State, policy, and learning

### 3.1 Domain model

  -----------------------------------------------------------------------
  Entity                              Minimum fields
  ----------------------------------- -----------------------------------
  `Workload`                          Stable identity, enabled/disabled
                                      status, credential restrictions,
                                      optional managed IP zone.

  `Service`                           Unique service ID, gateway ID,
                                      advertised listener and TLS server
                                      name, fixed backend endpoint. Give
                                      different protected listeners
                                      different service IDs.

  `Edge`                              `(sourceIdentity, serviceId)`. The
                                      service ID determines the port and
                                      backend; the caller cannot choose a
                                      relay destination.

  `Policy`                            Mode, approved edges, explicit
                                      pilot scope, policy revision,
                                      default lease length.

  `LearningDraft`                     Candidate edges, first/last
                                      observation, observation count,
                                      draft version.

  `Restriction`                       Typed selector (`IDENTITY` or
                                      `IP`), reason, actor, start,
                                      expiry, commit revision.

  `EnforcementSnapshot`               Cluster ID, enforcement revision,
                                      effective policy, active
                                      restrictions, lease reductions,
                                      release watermarks, token
                                      verification keys, and
                                      credential/key revocations.

  `Alert`                             Trusted source attribution,
                                      contributing signals, score, action
                                      status, and evidence references.
  -----------------------------------------------------------------------

Use immutable records for state and DTOs. Defensively copy arrays and
collections; a Java record does not make their contents immutable. Use a
separate enforcement revision from the learning-draft version so a new
observation does not invalidate every gateway's snapshot.

### 3.2 Policy rules

-   **ENFORCE:** Admit only an explicit approved edge. A valid
    certificate, a private address, or presence in the same CIDR never
    grants access by itself.
-   **LEARN:** Admit approved edges and authenticated traffic within an
    explicitly configured pilot scope. Keep all lease, certificate, IP,
    and quarantine checks. Unscoped traffic remains denied.
-   Record successful pilot admissions as **candidate** edges. Build the
    draft from validated telemetry, in bounded batches. UDP loss may
    omit candidates; it must not create permissions.
-   **Freeze baseline:** Show additions, removals, and observations that
    may be incomplete. Submit the exact reviewed edge set with the
    expected policy and draft versions. Commit the new allow-list and
    switch to ENFORCE in one mutation. A version conflict requires a
    reload and review.
-   Lease duration may be lowered by policy or risk state. A lease
    length change affects **new issuance**, not already established
    sessions. Use quarantine, identity disablement, or policy removal
    for active containment.

Use one shared `PolicyEvaluator` in the issuer and gateway. The issuer's
decision does not substitute for the gateway's decision.

## 4. Identity, leases, and gateway data path

### 4.1 TLS and workload identity

-   Use TLS 1.3 with separate `SSLContext` configuration per role. Use
    PKCS#12 for TLS key and trust stores. Do not use trust-all managers
    or disable server name checks.
-   Map one approved URI SAN, for example
    `urn:eastguard:workload:web-01`, to a registered workload ID. Reject
    missing, ambiguous, disabled, or revoked identities. Do not use the
    certificate CN as a workload ID.
-   Workload clients validate the configured issuer or gateway DNS/IP
    SAN. Servers require client authentication and validate the client
    chain and certificate purpose.
-   Check the current credential restrictions even on TLS session
    resumption. If a verified peer certificate is unavailable or no
    longer valid, deny.
-   Read the peer IP from the accepted socket. Never use a
    caller-supplied forwarded address. Normalize IPv4-mapped IPv6
    consistently and compare address bytes. V1 requires the issuer and
    gateway to see the same source address; do not silently fall back to
    identity-only checks behind NAT or a proxy.

### 4.2 Issuance and admission

1.  **Issue.** The token service authenticates the client, checks fresh
    state, quarantine, policy, and per-client limits, then signs a lease
    for one service. Default lifetime: **60 seconds**. Risk step-up can
    shorten new leases to **10 seconds**; this is a lease reduction, not
    MFA.
2.  **Connect.** `EastGuardClient` opens an mTLS connection to the
    configured gateway, sends the lease preamble, and waits for the
    reply. It exposes application streams only after `ALLOW`.
3.  **Verify.** The gateway checks the signature, cluster, audience,
    issue and expiry times, and state revision. It compares the token
    identity and leaf-certificate fingerprint with the TLS peer, and the
    token IP with the socket peer. It checks credential revocation,
    quarantine, and the effective policy.
4.  **Connect backend.** Start a non-blocking connection to the
    configured backend. On `finishConnect()`, recheck authorization,
    lease expiry, and state freshness. Send `ALLOW` only after the
    backend connection succeeds.
5.  **Relay.** Flush the reply before sending backend bytes to the
    client. Never forward early client data before admission. An expired
    lease cannot open a new connection; an admitted session has its own
    idle and absolute lifetime limits.
6.  **Terminate.** Close both legs on quarantine, a policy change
    removing the edge, credential/key revocation affecting the session,
    or expiration of the gateway's state freshness. Closing cannot undo
    bytes already delivered.

A lease is reusable within its short lifetime by the same authenticated
certificate and IP. `jti` is a correlation ID, not a one-time nonce. A
renewal that changes the client certificate fingerprint requires a new
lease.

### 4.3 NIO implementation

``` text
ACCEPT -> TLS_HANDSHAKE -> READ_PREAMBLE -> AUTHORIZE
       -> CONNECT_BACKEND -> WRITE_REPLY -> RELAY -> CLOSE

Any state can terminate on timeout, revocation, shutdown, or I/O failure.
```

-   One `Selector` owns channel state, interest sets, session indexes,
    and state installation. Other threads post bounded commands and call
    `selector.wakeup()`.
-   Use `SSLEngine` on client-facing gateway channels. Run delegated TLS
    tasks on a bounded executor and return completion to the selector.
    Do not operate on an engine concurrently. No RMI, DNS lookup,
    blocking I/O, or disk writes on the selector.
-   Handle fragmented frames, partial writes, `SSLEngine`
    underflow/overflow, and non-blocking connects. Bound encrypted and
    plaintext buffers and enforce a total buffer budget. Pause reads at
    a high-water mark, resume at a low-water mark, and enable `OP_WRITE`
    only while bytes are pending.
-   Use separate handshake, preamble, backend-connect, idle, and
    absolute-session deadlines. Use monotonic time for durations. Limit
    work per selected key and track global and per-peer connection
    limits.
-   On normal EOF, drain pending bytes and propagate output closure
    where supported. Treat unexpected TLS truncation as an error. On
    quarantine, cancel both legs immediately rather than draining queued
    payload.
-   Index live sessions by verified identity and peer IP. Retain signing
    key ID and certificate fingerprint for revocation checks. Include
    pending admissions in the checks so a slow backend connect cannot
    race past a quarantine.

The Java token service can use a blocking `SSLServerSocket` with virtual
threads. Bound concurrent handshakes and requests with a semaphore,
enforce total deadlines, and accept one framed request per connection.

## 5. Wire contracts

All integers are big-endian. `id` means `u8 length` followed by 1--64
ASCII bytes matching `[a-z0-9][a-z0-9._-]{0,63}`. `optId` allows length
zero. `ip` means `u8 length` of 4 or 16 followed by raw address bytes.
Timestamps are `i64` Unix milliseconds; revisions and sequences are
nonnegative `i64`. Reject unknown versions, invalid lengths, unsupported
enum values, trailing bytes, and arithmetic overflow. Do not use Java
serialization on the data plane or UDP.

### 5.1 Token request and gateway preamble

``` text
Issuer request:  ASCII "EGI1" | targetService:id
Issuer reply:    status:u8   | tokenLength:u16 | tokenBytes

Gateway request: magic:u16 = 0x455A | version:u8 = 1
               | tokenLength:u16  | tokenBytes
Gateway reply:   status:u8
```

Both exchanges are **inside mTLS**. Token length is `1..2048` on success
and zero in an unsuccessful issuer reply. Status values: `0` success,
`1` deny, `2` quarantined, `3` temporarily unavailable. TLS handshake
failures have no application reply. Detailed failure reasons stay in
internal telemetry. The client waits for the gateway reply before
sending payload and does not automatically retry application data.

### 5.2 Lease format

``` text
token = base64url(body) + "." + base64url(signature)   // no padding

body = ASCII "EGT1" | cluster:id | keyId:id | sub:id | aud:id | srcIp:ip
     | leafSha256:32 bytes | iat:i64 | exp:i64 | jti:16 random bytes
     | issuedAtRevision:i64

signature = Ed25519.sign(body)
```

The format fixes the algorithm; no caller-controlled algorithm
negotiation. Verify with the public key named in the trusted key set.
Require `0 < exp - iat <= 60 seconds`, reject when `now >= exp`, and
allow at most two seconds of future issue-time skew. If a verified lease
references a revision newer than the gateway's installed state, request
a sync and return temporarily unavailable rather than granting on older
state.

### 5.3 Flow telemetry

``` text
"EGF1" | cluster:id | producerId:id | keyId:id | bootId:16 bytes
       | seq:i64 | eventAt:i64 | policyRevision:i64
       | sourceIdentity:optId | sourceIp:ip
       | service:id | dstIp:ip | dstPort:u16
       | verdict:u8 | reason:u8 | flags:u8 | mac:32 bytes
```

-   `verdict`: `0 ALLOW`, `1 DENY`, `2 DECOY`.
-   Define stable reason codes in `common`, including `OK`,
    `INVALID_TOKEN`, `EXPIRED`, `WRONG_AUDIENCE`, `IDENTITY_MISMATCH`,
    `IP_MISMATCH`, `POLICY_DENY`, `QUARANTINED`, `NOT_READY`,
    `BACKEND_UNAVAILABLE`, `THROTTLED`, and `DECOY_TOUCH`.
-   Flag bit 0 marks an edge outside the approved graph; other bits are
    reserved and zero in V1. Successful pilot edges carrying this flag
    are learning observations, not enforcement violations.
-   HMAC-SHA256 covers all preceding bytes. Use a distinct key per
    producer and compare the MAC with `MessageDigest.isEqual`. Check
    producer-to-listener scope against trusted inventory. Only report an
    identity established by TLS; do not attribute an invalid token's
    claimed identity.
-   Cap the **entire datagram** at 1,200 bytes and detect oversize input
    rather than parsing a truncated packet. Enqueue from the gateway
    without blocking. Track drops and sequence gaps. A collector outage
    does not bypass the gateway's authorization rules.

### 5.4 Multicast notices

``` text
"EGC1" | cluster:id | keyId:id | revision:i64 | sentAt:i64
       | nonce:16 bytes | operation:u8 | expiresAt:i64
       | selectorCount:u8 | selectors... | reason:u8 | signature:64 bytes

selector = type:u8 | identity:id OR ip:ip
```

`operation`: `1 QUARANTINE`, `2 RELEASE`. Selector types: `1 IDENTITY`,
`2 IP`. Allow 1--8 selectors in one notice; `expiresAt` is the absolute
deadline for quarantine and zero for release. The signature covers all
preceding bytes. Verify cluster, trusted control key, signature, bounds,
and timestamp within ±30 seconds. The nonce is useful for correlation;
**durable revisions and idempotent application** prevent old messages
from rolling state back. This traffic is authenticated, not encrypted.
Keep it on the management segment.

## 6. Detection, containment, and release

### 6.1 Detector behavior

Verify and deduplicate telemetry before scoring it. Use a bounded
sequence window per `(producerId, bootId)`, tolerate limited reordering,
and reject old events. Retain deduplication state for at least the event
acceptance window. After a detector restart, suppress automatic action
until pre-restart datagrams have aged out. Use monotonic receipt time
for scoring windows.

  -----------------------------------------------------------------------
  Signal                                                    Default score
  ------------------------------ ----------------------------------------
  Authenticated attempt denied                                        +30
  for an edge outside the        
  approved policy                

  Security-related denial                                             +10

  More than 10 distinct managed       +50 once while that condition holds
  listener endpoints observed in 
  5 seconds                      

  Source IP mismatch on an                                            +60
  otherwise valid, correctly     
  attributed lease               

  Accepted TCP connection on a                           +100 immediately
  decoy listener                 
  -----------------------------------------------------------------------

Aggregate per verified identity when available, otherwise per canonical
peer IP, over a 10-second window. Add applicable signals but count each
event only once per signal. Do not score infrastructure failures,
throttling, ordinary lease expiration, or healthy pilot discovery. The
issuer can report a policy denial for a known service that was blocked
**before** a gateway connection; count distinct destinations for the
scan signal only from gateway observations. EastGuard cannot observe a
probe that never reaches one of its listeners.

-   **50--99:** Alert and propose a temporary lease reduction.
-   **100+:** Raise a critical alert and, if enabled, propose
    quarantine.
-   Start in **alert-only** mode. Use per-selector cooldowns and
    control-plane limits on automated action count and duration. An
    existing quarantine is not extended by repeated evidence. Do not
    automatically quarantine shared or ambiguous IPs or protected
    infrastructure.
-   Bound actor counts and event histories. Report overload and suspend
    automation when input quality is degraded; absence of telemetry is
    not evidence that a workload is safe.

**Decoys:** Configure an extra accept-and-close listener, with no
backend, no fake credentials, and no payload collection. Record a single
`DECOY` verdict per accepted connection, subject to resource limits. A
hit without an authenticated identity is IP-only evidence. Test it with
a fixed listener in the isolated demo.

### 6.2 Authoritative state and freshness

The control plane alone commits restrictions. A detector proposal
carries evidence references, a bounded expiry, and an idempotency ID; it
never signs or broadcasts an order.

1.  **Commit first.** Persist the mutation and audit record with a new
    enforcement revision. After commit, send the same signed notice
    three times. A send failure does not undo the commit.
2.  **Fast restrict.** On a valid `QUARANTINE` newer than the installed
    snapshot, apply a restrictive overlay for its selectors, refuse new
    matching operations, and close matching sessions. Coalesce
    duplicates. Do not discard a quarantine for one selector just
    because a newer notice for a different selector arrived first.
3.  **Reconcile.** Join multicast before the first sync. Poll
    authoritative state about once per second with jitter and request an
    immediate sync on a newer notice. A sync returns either a full
    immutable snapshot or an authenticated unchanged response for the
    exact installed revision. Do not renew freshness from a response
    older than the newest verified notice. While catching up to a known
    newer notice, pause new issuance and admissions; existing unrelated
    sessions may continue only within the current freshness window.
4.  **Fail closed.** Start with no admissions until the first valid
    sync. Only a successful authoritative sync renews freshness, for at
    most **5 seconds measured from request start**. If that deadline
    passes, stop issuance and admissions and close live relay sessions.
    A missed multicast packet therefore cannot keep a stale allow
    decision alive indefinitely.
5.  **Clear from authoritative state only.** A `RELEASE` notice prompts
    a sync; it never clears a block by itself. Replace covered overlays
    only when a fresh snapshot includes their revisions. Quarantine TTL
    is an authoritative expiry: the control plane commits expiry as a
    state transition, and receivers do not independently unblock on a
    local wall-clock timer.

`IDENTITY` and `IP` are independent selectors. A match on **any** active
selector denies access. A release for one does not cancel the other. The
issuer applies the same restriction and freshness checks as the gateway.

### 6.3 Fresh lease after release

For each released or expired selector, persist a watermark
`minTokenRevision = releaseRevision`. Reject a matching lease with
`issuedAtRevision` below that watermark. This also handles an issuer
that has not yet observed the release. Retain watermarks longer than the
maximum snapshot staleness plus the maximum lease lifetime and clock
uncertainty; two minutes is sufficient with the documented defaults.
Preserve them across restarts.

An operator should verify remediation before releasing a compromised
workload. If the credential remains unsafe, disable the identity or
revoke the certificate instead of relying on a temporary quarantine.

## 7. Control plane, persistence, and frontend

### 7.1 RMI API and authorization

  -------------------------------------------------------------------------------
  Operation                       Authorized callers      Notes
  ------------------------------- ----------------------- -----------------------
  `sync(knownRevision)`           Gateway, issuer         Return complete
                                                          enforcement state or an
                                                          exact revision
                                                          acknowledgement. Never
                                                          truncate a snapshot.

  `getDashboard(cursor, limit)` / Viewer, operator,       Page recent events and
  `getPolicy(serviceId)`          administrator           alerts. No secrets or
                                                          private keys in
                                                          responses.

  `recordObservations(batch)` /   Detector                Bounded, validated
  `proposeAction(request)`                                inputs. Recheck pilot
                                                          scope for observations
                                                          and automation rules
                                                          for actions. No
                                                          detector release
                                                          permission.

  `quarantine(request)` /         Operator, administrator Typed selectors, TTL
  `release(request)`                                      where applicable,
                                                          reason, and request ID.
                                                          Audit the result.

  `replacePolicy(...)` /          Administrator           Validate input and
  `freezeBaseline(...)` /                                 expected version.
  `setMode(...)` /                                        Return a conflict
  `setLeaseDefaults(...)`                                 instead of overwriting
                                                          newer state.
  -------------------------------------------------------------------------------

Use typed DTOs and explicit error codes such as `INVALID`,
`UNAUTHORIZED`, `CONFLICT`, and `UNAVAILABLE`. Every mutation has a
request ID scoped to its caller. Return the prior result on an identical
retry; reject reuse with a different payload. This matters when a write
commits but its reply is lost.

**RMI hardening:**

-   Use fixed registry and object ports. Use TLS socket factories with
    client authentication, server endpoint verification, and
    connect/read deadlines. Verify both registry and remote object
    connections, including the advertised stub host. Do not trust an
    unexpected endpoint merely because it appears in a stub.
-   JRMP does not reliably expose the TLS client principal to an
    ordinary remote method. Use independently provisioned, high-entropy
    per-principal API credentials over mTLS and check the credential and
    role on **every** call. Do not authorize from a supplied username or
    `getClientHost()`. Store credential digests, support rotation and
    revocation, and never log credentials.
-   Use narrow `ObjectInputFilter` limits for allowed DTO/JDK types,
    object graph depth, references, array lengths, and bytes. Test the
    actual registry, stub, server, and client paths. Disable remote
    class loading. Do not accept arbitrary `Serializable` payloads.
-   Keep RMI off the data path. Synchronize state in a background task
    and publish a validated immutable snapshot.

### 7.2 Durable state and audit

Use one writer and an append-only, length-framed local journal. The
control plane holds an exclusive process lock. Include a record checksum
and enforce maximum frame sizes. For an enforcement mutation, the same
journal record contains the state change and audit metadata. Force the
record to durable storage before publishing state, sending a notice, or
reporting success.

Replay the journal at startup to reconstruct state and request outcomes.
An incomplete trailing frame can be recovered under a documented
procedure; a corrupt complete record or inconsistent revision fails
readiness. If a write or force fails, stop acknowledging mutations and
do not advertise uncertain state as fresh. Back up the journal and
required key material, and test restoration. Never automatically restore
an older revision over newer live state; if the latest trusted revision
cannot be recovered, fence the deployment and perform a controlled
rebootstrap before reopening traffic.

Audit fields: timestamp, actor and role, operation, selectors or policy
version, reason, request ID, outcome, enforcement revision, and evidence
references where applicable. Batch distinct learning candidates; do not
append every UDP packet to the journal. Restrict file permissions and
retention. A local checksum detects corruption, not malicious rewriting;
send audit exports or anchored digests to independently protected
storage if tamper evidence is required.

### 7.3 Swing dashboard and URL handlers

-   **Topology:** Show services, approved edges, candidate edges,
    denials, and quarantine overlays. Use labels or icons as well as
    colors.
-   **Alerts:** Show the signal, score, trusted identity or IP, action
    outcome, and timestamp. Distinguish proposed, committed, and locally
    observed application of restrictions where that data exists.
-   **Policy editor:** Preview the exact edge diff before freezing. Show
    the active mode and revision; reload after conflicts.
-   **Quarantine panel:** Show selector type, reason, expiry, and
    overlapping restrictions. Confirm mutations and require a reason.
    Highlight **direct destinations allowed by policy** for a
    quarantined identity as its potential blast radius; do not present
    those edges as observed compromise.
-   **Threading:** Do network calls in a bounded background worker.
    Permit only one outstanding poll, update components on the Event
    Dispatch Thread, and mark stale views explicitly. Disable mutations
    when disconnected or when the role lacks permission.
-   **Demo controls:** Load labeled fixture scenarios in the demo
    profile. Do not include live attack actions or production
    fixture-ingestion endpoints.

Use `jdk.httpserver`'s `HttpsServer` for restricted read-only `/audit`,
`/metrics`, and health endpoints on the control plane. Paginate audit
reads and require an authorized client certificate. Demonstrate Java URL
connections using `HttpsURLConnection` with normal hostname
verification.

For the syllabus handler, use
`URL.of(URI.create("ztp://policy/app-02"), handler)`. An explicit
`URLStreamHandler` creates a read-only `URLConnection`; a
`ContentHandler` returns a typed `PolicyView` from the configured
control-plane client. Accept only the fixed authority `policy` and a
valid service ID. The URL is not allowed to choose an RMI host,
filesystem path, or arbitrary network endpoint.

## 8. Code organization and design patterns

``` text
src/eastguard/
  common/       Domain records, Cidr, codecs, signature/MAC helpers, PolicyEvaluator
  client/       EastGuardClient, issuance and gateway client adapters
  gateway/      NioGateway, ChannelPair, TlsChannel, SessionIndex, DecoyListener
  tokensvc/     TokenServer, LeaseIssuer, TlsContextFactory
  detector/     FlowReceiver, TelemetryVerifier, RiskEngine, SlidingWindow
  bus/          QuarantineSender, QuarantineListener, notice codec
  control/      ControlPlane, ControlPlaneImpl, Journal, SnapshotService, AuditHttpServer
  dashboard/    DashboardApp, TopologyPanel, AlertTable, PolicyEditor
  handlers/     ZtpUrlHandler, PolicyURLConnection, PolicyContentHandler
  demos/        DemoM1_Nio through DemoM5_Rmi, owned local fixtures and legit clients
test/eastguard/
  test/         AllTests, unit and integration test entry points
config/
  *.properties.example
sources.txt     Source paths for javac, including tests for the development build
```

  -----------------------------------------------------------------------
  Pattern                             Use
  ----------------------------------- -----------------------------------
  Reactor                             One gateway selector dispatches
                                      channel events.

  State machine                       Gateway connection lifecycle and
                                      framed decoders have explicit
                                      transitions.

  Single writer + immutable snapshots Serialize control-plane mutations;
                                      make enforcement reads predictable.

  Strategy / pure evaluator           Evaluate policy and risk
                                      independently of sockets and Swing.
                                      Inject time for tests.

  Adapter                             Put RMI, UDP, TLS, and URL handling
                                      behind small interfaces where tests
                                      need substitutes.

  MVC                                 Keep dashboard models, action
                                      controllers, and Swing views
                                      separate.
  -----------------------------------------------------------------------

Use constructor wiring, `java.util.logging`, and JDK collections. Prefer
a small number of explicit classes over frameworks or a generic plug-in
system. Use `Clock` for wall time, monotonic time for elapsed deadlines,
and numeric address bytes in `Cidr`. Test both IP families, including
`/0` and full-width prefixes.

## 9. Configuration, build, and operations

### 9.1 Starting configuration

Use validated `.properties` files for bootstrap configuration. Load
policy from the control-plane journal after an explicit administrator
bootstrap. Deploy with deny-by-default state, not with a permissive
sample policy.

  -----------------------------------------------------------------------
  Setting                             Starting value or rule
  ----------------------------------- -----------------------------------
  `cluster.id`                        Unique per deployment; bound into
                                      signed records.

  Gateway config                      Fixed service ID, listener and
                                      backend host/port, IP limits,
                                      control endpoint and credentials.

  `state.pollMillis` /                `1000` with jitter / `5000`.
  `state.maxAgeMillis`                

  `lease.defaultSeconds` /            `60` / `10`.
  `lease.stepUpSeconds`               

  Handshake / preamble /              `5 s` / `2 s` / `2 s` to start;
  backend-connect timeout             tune against measurements.

  Idle / maximum established session  `60 s` / `5 min` to start; select
  duration                            values appropriate for the
                                      protected protocol.

  `multicast.group`, `port`,          `239.20.20.20`, `4446`, explicit
  `interface`, `ttl`                  interface, `1`.

  Detection                           Alert-only on first rollout.
                                      Default automatic quarantine TTL
                                      when enabled: `5 min`, capped by
                                      control policy.

  Resource limits                     Configure handshake concurrency,
                                      active connections, total relay
                                      buffers, telemetry queue, tracked
                                      sources, policy size, and RMI
                                      page/request sizes. Reject excess;
                                      do not create unbounded queues.

  Stores and keys                     Configure protected paths for
                                      PKCS#12 files, signing keys, UDP
                                      producer keys, and RPC credentials.
                                      Do not put secrets in sample files
                                      or command-line arguments.
  -----------------------------------------------------------------------

Use `MulticastSocket.joinGroup(SocketAddress, NetworkInterface)` and
select the sending interface explicitly. Verify interface support and
multi-receiver binding on each deployment OS. Multicast TTL is not a
security boundary; filter management ports at the network boundary.
Maintain host time synchronization and alert on skew. A large clock jump
should make time-based enforcement unready until time and state are
validated.

### 9.2 Local build and start

``` bash
javac --release 21 -d out @sources.txt
java -ea -cp out eastguard.test.AllTests

java -cp out eastguard.control.ControlPlaneImpl --config config/control.properties
java -cp out eastguard.detector.ThreatDetector --config config/detector.properties
java -cp out eastguard.tokensvc.TokenServer --config config/token.properties
# Start the configured local backend before its gateway.
java -cp out eastguard.gateway.NioGateway --config config/gateway-app02.properties
java -cp out eastguard.dashboard.DashboardApp --config config/dashboard.properties
```

Use JDK `keytool` for demo CA, server, and workload certificates. Issue
demo and production credentials from separate trust roots. Keep CA
private keys out of runtime processes. Use local endpoints on
`127.0.0.1` with distinct ports for ordinary demos; use address fixtures
to test IP mismatch instead of relying on OS-specific loopback aliases.
If local multicast is unavailable, still test loss and reordering
through a test transport, then qualify real multicast on the deployment
interface.

### 9.3 Operational checklist

-   **First rollout:** Verify backend isolation and TLS identities.
    Start with a minimal approved policy, a narrow learning pilot, and
    alert-only detection. Review the graph and measured false positives
    before enabling enforcement changes or automatic quarantine.
-   **Key rotation:** Publish a new lease verification key before the
    issuer uses it. Keep the previous verification key for the
    outstanding lease lifetime plus freshness and skew margin. Normal
    retirement affects new validation; emergency revocation must also
    close affected sessions. Stage control signing public keys
    independently before switching signers. Rotate telemetry secrets per
    producer.
-   **Incident response:** Use the audited quarantine action for
    containment, then verify application across gateways. Revoke unsafe
    credentials, remove unnecessary edges, and release only after
    validation. If the control plane is unavailable, repair it; do not
    bypass gateway enforcement or widen backend reachability.
-   **Updates and shutdown:** Version all contracts. Introduce
    compatible readers before writers; reject unknown formats rather
    than guessing. On gateway shutdown, stop admitting, drain only
    allowed sessions for a bounded interval, then close. Back up and
    verify state before upgrading the singleton control plane.
-   **Health and monitoring:** Distinguish liveness from readiness.
    Track state age/revision, sync failures, active sessions, TLS and
    admission outcomes, buffer use, UDP drops and duplicates, detector
    lag, commit failures, quarantine apply latency, disk space, and
    certificate expiry. Never log tokens, private keys, RPC credentials,
    or payloads.

The singleton control plane is a deliberate availability tradeoff: an
outage beyond the freshness budget interrupts protected traffic. If the
deployment cannot accept that tradeoff, high availability is a separate
release requirement, not a reason to serve indefinitely from stale
policy.

## 10. Verification and release gates

Use a JDK-only test runner, deterministic clocks, ephemeral ports where
practical, bounded waits, and owned local test services. Separate pure
unit tests, local integration tests, real multicast qualification, and
load tests.

  -----------------------------------------------------------------------
  Scenario                            Required result
  ----------------------------------- -----------------------------------
  Fragmented or oversized preamble,   Reject within limits; no backend
  unsupported format, TLS timeout     connection or leaked buffers.

  Untrusted certificate or wrong      TLS fails.
  server name                         

  Invalid signature, expired lease,   Deny before forwarding. Use
  wrong audience, mismatched          validator fixtures for the IP and
  certificate or peer IP              certificate permutations.

  Backend refuses connection or       No false `ALLOW`; backpressure and
  becomes slow                        timeouts bound memory.

  Pilot edge versus unscoped edge     Pilot success becomes a candidate;
                                      unscoped traffic stays denied.
                                      Freeze applies only the reviewed
                                      set.

  Concurrent policy edit and freeze   One commits; stale expected version
                                      returns a conflict.

  Detector window and step-up         Known fixture events produce exact
                                      scores, age out, and shorten only
                                      new issuance. Untrusted or
                                      duplicate UDP does not inflate
                                      scores.

  Decoy event fixture or fixed local  Critical alert. Automation, if
  listener                            enabled, acts only for eligible
                                      selectors.

  Quarantine during pending backend   No new admission; matching live
  connect or live relay               sessions close; unrelated sessions
                                      are not torn down by the targeted
                                      action.

  Duplicate notice, out-of-order      No state rollback; a fresh snapshot
  notice, lost multicast, receiver    converges; release cannot clear an
  restart                             uncovered block.

  Release or expiry with an old lease Old lease denied by watermark. A
                                      newly issued lease can succeed if
                                      policy and other restrictions
                                      permit.

  Control-plane loss or stale reply   Never renew freshness from cache or
                                      an old response. After the
                                      deadline, deny and close relay
                                      sessions.

  Journal crash, disk full, invalid   No undurable success. Recover
  record, lost mutation reply         safely or fail readiness;
                                      idempotent retry does not duplicate
                                      a commit.

  Key rotation or revocation          Planned overlap preserves valid
                                      admission. Emergency revocation
                                      rejects affected credentials and
                                      closes affected sessions.

  Slow or unavailable RMI from Swing  UI stays responsive, marks data
                                      stale, and prevents unsafe edits.

  Deployment isolation                An unauthorized workload cannot
                                      reach the protected backend except
                                      through its gateway.
  -----------------------------------------------------------------------

**Initial acceptance targets, measured on declared hardware and test
settings:**

-   **Concurrency:** 500+ sessions in the live NIO demo; 1,000
    concurrent legitimate sessions in the release load test with fewer
    than 10 gateway-owned platform threads and bounded memory. Report
    JVM system threads separately.
-   **Admission:** Target p95 under 5 ms from complete lease preamble to
    flushed `ALLOW` on a warmed gateway with a local backend. This
    includes verification and backend connect; measure cold TLS and
    lease acquisition separately. Report p99 and errors, not just the
    average.
-   **Containment:** On a healthy single segment, target p95 under 100
    ms from quarantine commit to matching gateway session closure, and
    under 500 ms from a qualifying decoy event to closure with
    automation enabled. Verify convergence when multicast is
    deliberately dropped. These are measured targets, not guarantees
    across partitions.
-   **Correctness:** Security-critical negative tests, restart/recovery
    drills, resource-limit tests, and the deployment isolation check
    must pass before enabling automatic quarantine.

## 11. Team delivery and demo

  -----------------------------------------------------------------------
  Member                  Owns                    Standalone Java demo
  ----------------------- ----------------------- -----------------------
  M1                      Selector gateway, TLS   `DemoM1_Nio`:
                          channel handling,       concurrent legitimate
                          relay, decoy listeners  sessions, fixed
                                                  selector thread count,
                                                  controlled
                                                  backpressure.

  M2                      TLS provisioning guide, `DemoM2_Tls`: trusted
                          issuer, token codec,    client obtains a lease;
                          Java client             untrusted certificate
                                                  fails; invalid lease
                                                  fixture is denied.

  M3                      UDP telemetry, CIDR,    `DemoM3_Udp`: bounded
                          detector and learning   fixture stream produces
                          observations            expected risk
                                                  transitions and CIDR
                                                  classification.

  M4                      Multicast adapter,      `DemoM4_Multicast`:
                          revisions, freshness    three receivers apply a
                          and overlay             committed restriction;
                          reconciliation          duplicate and lost
                                                  delivery tests converge
                                                  correctly.

  M5                      RMI, journal,           `DemoM5_Rmi`: audited
                          dashboard, HTTPS        policy edit, conflict
                          export, ZTP handler     handling, release, and
                                                  typed `ztp://` policy
                                                  read.
  -----------------------------------------------------------------------

**Build order:**\
1. Agree on codecs, DTOs, policy semantics, and trust configuration.\
2. Demonstrate one mTLS issuer → Java client → NIO gateway → private
backend path.\
3. Add durable policy, authoritative sync, and fail-closed behavior.\
4. Add validated telemetry, detector proposals, multicast, and release
watermarks.\
5. Add dashboard, audit export, and reviewed learning freeze.\
6. Run failure drills, security checks, and load tests; document the
measured limits.

**Final demo:** Show an approved flow and an unapproved flow, review and
freeze a learning draft, run a labeled detector fixture, show a
committed restriction closing an owned test session at multiple
gateways, then release and reconnect using a fresh lease. The project is
complete when this flow works end to end **and** the failure cases above
behave as specified.
