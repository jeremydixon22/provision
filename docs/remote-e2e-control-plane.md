# Remote End-to-End Encrypted Control Plane

## Status and decision

This document defines Provision's future remote-control shape. It is a design
target, not an enabled feature. Provision must not expose its existing web UI
or proxy directly to the Internet while this work is incomplete.

The remote path will use the Hushwire project only after its
production-readiness gates pass. Hushwire will provide end-to-end encryption
between a Provision host agent and a paired remote client. Cloudflare will
provide Internet-facing TLS, connection routing, rendezvous, rate limiting, and
availability controls, but is not trusted with plaintext, Provision
credentials, session history, or authorization decisions.

The first supported remote client will be a Node-based Provision Companion.
Hushwire's current hybrid v2 surface is Node-only and development-only; a
browser client is deferred until Hushwire has a reviewed browser/WASM
cryptographic provider with wire-compatible vectors and persistent-state
support. A browser dashboard may later talk to a local Companion over loopback,
but must never terminate a weaker browser-specific crypto protocol.

## Current implementation status

Provision now contains the daemon-side foundation for this design, but remote
control is **not enabled**. The current work deliberately stops below a relay
or E2E transport:

- `src/provision/remote.py` converts local state into opaque-ID, bounded
  session snapshots and replayable typed deltas. It does not reuse the
  dashboard control-plane payload and cannot include transcript bodies,
  `search_text`, HTML, quota payloads, or credentials in normal state sync.
- Discussion and explicit message expansion are bounded, cursor-authenticated
  operations. Live Discussion changes are stable-ID `message_append`,
  `message_replace`, and `message_remove` deltas; there is no browser or HTTP
  route for them.
- The experimental generic Connector ABI can be explicitly enabled over a
  mode-`0600` Unix socket under the Provision home. It checks the same local
  UID and a distinct connector capability; it does not use the dashboard/proxy
  token. Its `provision.remote/v1` lane adapts this bounded contract for a
  trusted local connector process, while transport, peer identity, pairing,
  and encryption remain outside Provision. Provision does not start that
  socket by default. This is a local daemon-to-connector boundary, not a
  remotely reachable service.
- Device metadata, explicit capabilities, action leases, a redacted audit log,
  and a mode-`0600` idempotency journal now have daemon-side implementations.
  The journal writes a pending reservation before a PTY mutation, so a crash
  cannot make a retry silently duplicate a prompt; an unresolved reservation
  is reported as indeterminate. It retains every live reservation for its
  short action-expiry window instead of evicting a still-retryable key. A
  device begins with `read_state` and `read_discussion` only. Mutating actions
  remain unavailable until a local grant is made, and only prompt/interrupt
  primitives with an existing PTY implementation are currently wired.

There is no Companion, Hushwire session, pairing UI, Cloudflare Tunnel/Worker,
or command that enables direct network access. `provision connector enable`
starts only a same-user local Unix socket for a user-supplied connector; it
does not create an Internet listener or expose `/ui`, `/api/status`, the
dashboard WebSocket, or the local proxy through Cloudflare. Those remain
separate later milestones and cannot be enabled until the gates below pass.

## Readiness assessment (2026-07-18)

The Provision-side foundation is ready for integration testing only after a
production-approved transport is available: session discovery is complete but
paged and bounded; routine state, Discussion, and action results have hard
byte limits; and the daemon does not start a remote listener by default.

The adjacent Hushwire worktree was inspected read-only for this assessment. Its
README still labels the Node v2 profile a development implementation. Its
2026-07-16 internal security review also records open high release/deployment
blockers: independently generated interoperability/KAT vectors, provider
pinning and review, a tested anti-rollback production state authority, and
operational identity/revocation policy. Browser support remains separately
deferred pending an audited WASM provider and cross-runtime vectors.

No Cloudflare Worker, Durable Object, Tunnel configuration, relay route, or
agent process exists in this repository. The correct release decision is
therefore **no remote-hosted alpha yet**. The next integration milestone starts
only after the Hushwire gates are closed, with a local in-memory hostile-relay
test harness before any Cloudflare deployment.

| Required capability | Current evidence | Release status |
| --- | --- | --- |
| Bounded session discovery, delta replay, and paged Discussion | `remote.py` plus daemon integration; automated Provision tests cover byte caps, cursors, expiry, overflow fallback, and typed turn/message deltas. | Complete locally. |
| Capability checks, action serialization, idempotency, and redacted audit | Local daemon implementation with a same-UID/token Unix-socket boundary and crash-safe action reservations. | Complete locally; dormant by default. |
| Hushwire host identity, pairing, safety-code verification, and ratchet persistence | No agent or paired client exists; Hushwire's own review explicitly withholds production approval. | Blocked externally. |
| Node Companion and local browser shell | No implementation. | Not started; depends on the Hushwire gate. |
| Opaque Cloudflare relay and outbound host connection | No implementation or deployment configuration. | Not started; depends on the Hushwire gate. |
| Hostile-relay, interoperability, recovery, pairing, and external-security acceptance tests | No E2E transport exists to exercise. | Blocked externally. |

## Why this is necessary

Before the local snapshot bounding work, on 2026-07-16 a live Provision daemon with 21 observed sessions produced a
7.23 MiB initial dashboard WebSocket frame. The control-plane portion was
6.98 MiB, including 6.79 MiB of transcript JSON. A transcript/control-plane
update could resend that control-plane shape, and the UI safety snapshot did so
every 60 seconds. The local dashboard now bounds each session's initial and
safety-snapshot transcript window and fetches older observed turns on demand;
the remote protocol remains independently bounded and does not reuse the local
dashboard payload.

The remote protocol therefore has a separate, bounded sync model. It does not
proxy the existing dashboard WebSocket and does not send search_text, full
history, raw quota payloads, or local proxy tokens to a remote peer.

## Goals

- Give a paired owner a responsive remote view of Provision-managed sessions,
  Discussion, quota/context summaries, and approved control actions.
- Keep Cloudflare, a relay operator, and network observers unable to read or
  modify Provision application data without detection.
- Make steady-state traffic proportional to an individual change, not to all
  retained sessions or transcript history.
- Preserve Provision's local-first operation: a local daemon and terminal
  continue to work when the Internet, Cloudflare, or a remote client is absent.
- Support explicit device pairing, safety-code verification, revocation, and
  least-privilege remote actions.

## Non-goals

- No public unauthenticated dashboard, remote shell, terminal video stream, or
  direct exposure of Codex/OpenAI credentials.
- No claim that endpoint compromise is solved. The paired client and Provision
  host agent necessarily see plaintext; Cloudflare does not.
- No silent downgrade from Hushwire's selected production suite or identity
  verification requirements.
- No transfer of complete Codex history merely to populate a remote UI.

## Architecture

~~~text
Provision daemon -- loopback/Unix socket -- Provision Remote Agent
                                              | plaintext only here
                                              | Hushwire E2E channel
                                              v
                                   Cloudflare opaque relay/tunnel
                                              ^
                                              | Hushwire E2E channel
                                              | plaintext only here
                                  Provision Companion (Node)
                                              | loopback only
                                              v
                                 optional local browser dashboard
~~~

### Host agent

provision-remote-agent is a separate local process, supervised by Provision
but not embedded in the public HTTP handler. It:

- connects outward to the Cloudflare relay; it opens no public listening port;
- authenticates locally to Provision through a dedicated loopback or Unix
  socket capability, not the dashboard's proxy token;
- owns the Hushwire responder identity, pre-keys, ratchet state, and paired
  device allowlist using Hushwire's sealed, revision-checked persistent state;
- translates bounded Provision Remote Protocol messages to and from Provision;
  and
- enforces remote authorization, action serialization, byte limits, and audit
  logging before any request reaches the daemon.

The agent never forwards the daemon's /ui, /api/status, or existing UI
WebSocket byte-for-byte. Provision remains bound to loopback by default;
Cloudflare sees only the agent's encrypted relay traffic.

### Cloudflare relay

Cloudflare Tunnel and a Worker/Durable Object-style rendezvous service carry
two outbound WebSocket streams: one from the host agent and one from the
Companion. The relay matches a short-lived pairing or device route and forwards
opaque binary frames only.

The relay may enforce connection, frame-size, rate, and abuse limits. It may
retain short-lived ciphertext only when needed for reconnect delivery, subject
to a small fixed TTL. It must not decrypt, inspect, index, log application
payloads, or hold Hushwire private keys. Cloudflare Access may add outer
admission control, but the Hushwire peer identity remains authoritative.

Cloudflare can still observe client and host IP addresses, connection timing,
packet count, and padded frame sizes. Hushwire padding and optional cover
traffic mitigate some size leakage but do not hide timing or endpoint metadata.

### Remote Companion

The Companion is the first-class paired endpoint. It owns the initiator
identity, verifies the host identity, persists ratchet state, and presents the
remote UI. It may expose a loopback-only local web server for a browser shell;
the browser is never given Hushwire private keys or a Cloudflare relay token.

Remote browser support is a later transport replacement, not a shortcut around
Hushwire's current Node constraint. It requires an audited browser/WASM
provider, exact cross-runtime test vectors, secure persistent state, and the
same identity/pairing semantics before it can replace the Companion.

## Pairing and identity

1. The host agent creates a long-term Hushwire identity and a bounded pool of
   signed one-time pre-key bundles. Private material stays on the host.
2. A local Provision user explicitly starts pairing. The agent creates a
   single-use, short-lived rendezvous ID and displays a QR code containing the
   relay URL, expected host identity fingerprint, expiry, and pairing nonce.
3. The Companion scans the QR code, obtains the signed host bundle through the
   opaque relay, and starts Hushwire's production-approved hybrid handshake.
4. Both devices display Hushwire's safety code. The user verifies it through a
   second channel or direct physical comparison before granting any capability.
5. The responder atomically consumes the referenced one-time pre-key and
   persists the provisional session state before application data is accepted.
6. The host records a device ID, pinned public identity, capabilities, and
   creation/revocation timestamps. Pairing tokens expire after first use or
   fifteen minutes, whichever comes first.

Identity changes, invalid signatures, state rollback, a failed ratchet
transition, or a suite mismatch fail closed. Recovery requires an explicit
local re-pair; no automatic identity replacement or suite downgrade is allowed.

## Provision Remote Protocol

Every application message is a binary payload inside one Hushwire protected
record. The payload uses a small versioned binary frame:

~~~text
version | type | device sequence | request/reply ID | body length | UTF-8 JSON body
~~~

The frame is binary at the Hushwire boundary; JSON is an encrypted application
body, never relay-visible transport data. Associated data binds the protocol
version, host identity, device identity, direction, and logical lane:

~~~text
provision.remote/v1/<host-identity>/<device-id>/<direction>/<lane>
~~~

The protocol has four lanes, each with independent sequence and flow-control
state: state, discussion, history, and action. A valid Hushwire record on one
lane cannot be replayed as a different lane or operation.

### Bounded state model

The initial remote state contains session summaries only: session ID, display
label, liveness, selected profile label, context summary, compact quota
summary, current turn ID, and unread revision. It contains no transcript
entries. The target is a <=100 KiB initial state at normal account scale.
When the index exceeds that byte or entry budget, the response carries an
authenticated opaque continuation cursor. The client obtains additional
bounded pages instead of losing access to omitted sessions. A session-index
generation binds a cursor to a stable ordering; a structural session change
expires an old cursor and requires a fresh first page, while ordinary
Discussion updates do not interrupt an in-progress page walk.

Subsequent state messages are typed deltas:

- session_upsert or session_remove affects one session;
- session_metrics carries only changed counters, context, and quota fields;
- turn_started, turn_completed, and message_append affect one turn;
- message_replace updates a streamed or completed message by stable ID; and
- message_remove evicts a locally trimmed message by stable ID.

The host maintains a per-device revision cursor and a bounded replay buffer of
the latest 500 deltas. A reconnect resumes from the cursor when possible. If
the cursor is outside that buffer, the host sends a fresh bounded session index,
not a full control-plane snapshot.

search_text is server-only and never crosses this protocol. full_text is also
excluded from normal deltas. A remote client receives the same display text
limit used locally, and requests full text only with an explicit message_expand
request. Expansion has a 256 KiB hard response limit; larger content is
returned as a bounded, user-requested page sequence rather than one unlimited
record.

Discussion/history pagination uses at most 40 entries and 64 KiB of display
body per response. The host returns a continuation cursor, not an offset into
unbounded state. Historical search indexes carry metadata and bounded previews;
historical bodies remain on-demand. The Companion is limited to 32 cached pages
and evicts least-recently-used pages before accepting more.

No implicit compression is used on E2E plaintext. It can create
attacker-controlled compression side channels and is unnecessary once payloads
are bounded. Hushwire's production padding policy applies to every protected
record; application pagination keeps records below the chosen transport frame
limit.

### Control actions

All remote actions require both a paired-device capability and a local
Provision authorization check. Initial capabilities are:

| Capability | Initial policy |
| --- | --- |
| read_state | Granted after verified pairing. |
| read_discussion | Granted after verified pairing. |
| send_prompt | Explicit local grant; PTY-managed sessions only. |
| interrupt_turn | Explicit local grant and confirmation in the Companion. |
| resume_or_fork | Explicit local grant. |
| switch_profile | Disabled initially; add only after an explicit confirmation and switch-safety review. |
| manage_devices | Local host only. |

Each action includes an idempotency key, expected session revision and turn ID,
and
expiry. The agent serializes mutating actions per session, rejects stale
revisions, and returns a typed result delta. It never forwards a remote command
to a shell, changes daemon bind settings, or exposes account credential files.

## Availability, persistence, and failure handling

- The host and Companion persist Hushwire state after every ratchet transition
  using sealed, monotonic-revision records. Concurrent writers fail closed.
- An agent restart reconnects and resumes the existing Hushwire session; it
  does not silently create a new identity or discard the peer pin.
- Relay loss pauses remote sync. The local Provision daemon and terminal keep
  operating. Retries use bounded exponential backoff with no busy loop.
- Hushwire authentication failures, replay, malformed frames, oversized
  payloads, sequence gaps beyond the configured window, and state-store
  conflicts terminate only the affected remote session and create a local
  audit event without plaintext payloads.
- Read clients may coexist. A per-session control lease prevents conflicting
  mutating actions from multiple paired devices; the local terminal always
  remains authoritative and can supersede a remote lease.

## Security and production gates

Remote work may begin only after all of the following are true.

### Hushwire gates

- Hybrid v2 is no longer labeled development-only and its security-review
  blockers are resolved.
- An independent security review covers the selected identity suite, hybrid
  handshake, sealed headers, padding, state persistence, replay handling,
  pre-key exhaustion, and denial-of-service bounds.
- The exact production Node/provider version is pinned and exercised in CI.
- State storage has atomic pre-key consumption, monotonic revisions, backup
  and restore rollback detection, and tested device revocation.
- If browser support is proposed, an audited WASM provider and cross-runtime
  interoperability/vector suite pass before any browser endpoint is shipped.

### Provision gates

- The local control plane exposes a typed, capability-scoped local API for the
  agent; it does not reuse the public dashboard token or HTML endpoints.
- Normal UI state is converted to bounded, stable-ID deltas; no full transcript
  is included in a routine remote state message.
- search_text is retained only where server-side search needs it and has its
  own byte cap; it is never serialized to remote clients.
- Remote audit logs redact prompts, assistant text, tool arguments, and tokens.
- The daemon binds locally by default. A remote agent uses an outbound tunnel;
  direct 0.0.0.0 dashboard operation is unsupported.

### Cloudflare gates

- The relay's current WebSocket, Durable Object, Tunnel, frame-size, timeout,
  and retention limits are validated against load tests before deployment.
- Relay logs contain route/device pseudonyms and operational metadata only; no
  decrypted application payload or long-lived pairing secret is logged.
- Cloudflare Access/WAF/rate controls are configured as defense in depth, not
  as a replacement for Hushwire pairing or E2E authentication.

## Test and acceptance plan

1. Unit-test every message type, byte limit, cursor, revision transition, and
   authorization failure in both Provision and the Companion.
2. Run Hushwire interoperability, tamper, replay, out-of-order, dropped-frame,
   ratchet-restart, and state-rollback tests through the actual agent framing.
3. Run a hostile-relay integration test that records and mutates all relay
   frames. It must prove that plaintext, local proxy tokens, and credential
   material never reach the relay and that mutations fail closed.
4. Load-test 25 sessions, active streaming, reconnects, and two read clients.
   Verify <=100 KiB initial state, <=16 KiB typical state delta, <=64 KiB
   bounded response pages, and no periodic full-state transfer.
5. Verify pairing/revocation with lost, replaced, and restored devices,
   including explicit safety-code mismatch handling.
6. Perform an external security review before enabling any non-local relay
   route. Start with opt-in read-only alpha access, then separately gate each
   mutating capability.

## Rollout sequence

1. Refactor Provision's local dashboard data model into bounded snapshots and
   append/update deltas; ship this locally first.
2. Production-ready Hushwire and build the Node host agent/Companion against a
   local in-memory relay test harness.
3. Add the Cloudflare opaque relay and outbound-only agent connection; enable
   verified-pair, read-only alpha testing.
4. Add paged Discussion/history and reconnect cursors while measuring actual
   wire bytes, latency, and recovery behavior.
5. Add narrowly scoped mutating actions behind local grants and explicit
   Companion confirmation.
6. Consider a browser endpoint only after the browser/WASM gate is complete;
   it must use the same pairing, protocol, and bounded-sync semantics.
