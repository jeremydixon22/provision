# Connector ABI

Status: experimental, version 1. The Connector ABI is a generic local boundary
for carrying Provision frames through a trusted connector process. It is not a
relay protocol, encryption scheme, hosted service, or public network API.

## Model

The shape is intentionally closer to an IRC or peer-to-peer link than to a web
API:

- A **connector** is a local process selected by the user. It can route frames
  locally, make a direct peer connection, or use a relay.
- A **link** is an opaque connector-selected identifier for a peer or route.
- A **lane** is a versioned named service carried over a link.
- A **frame** contains bounded opaque bytes. Provision only interprets a frame
  after it reaches one of its registered local lanes.

This lets a future connector use a tunnel, a direct peer transport, a relay, or
an entirely local route without making any of those choices part of Provision's
proxy or dashboard.

## Lifecycle

The daemon does not create a Connector socket or token during ordinary startup.
Inspect the stable contract with:

```bash
provision connector abi
```

Explicitly create the same-user local endpoint only when a trusted connector is
ready to use it:

```bash
provision connector enable
provision connector status
provision connector disable
```

The socket and its separate capability are mode `0600` under the Provision
home. The endpoint accepts only processes owned by the same operating-system
user. A connector that can read that capability is part of the local trusted
computing base; it must protect its own process environment, logs, transport,
and peer authentication.

## Framing

The local socket uses newline-delimited JSON (`jsonl`). Every message includes
`"abi": 1`. The connector first sends:

```json
{
  "type": "hello",
  "abi": 1,
  "token": "local connector capability",
  "connector_id": "example-connector",
  "lanes": ["provision.echo/v1"]
}
```

The daemon replies with `hello_ack` and the subset of requested lanes it
supports. A connector then sends a `frame` with a connector-chosen `link_id`, a
lane, optional `message_id`, and a URL-safe-base64 payload. The daemon replies
with a `frame_ack`; if the lane produced bytes, they are in its base64 payload.
That request/reply exchange is deliberately independent of how the connector
obtained the frame or delivers the response to its link.

Version 1 caps a decoded frame at 256 KiB and one JSON message at 384 KiB. A
connector must split, order, retry, encrypt, and authenticate any larger or
network-carried application stream itself.

## Current lanes

| Lane | Purpose |
| --- | --- |
| `provision.echo/v1` | Local loopback/reference lane for connector development and health checks. |
| `provision.remote/v1` | Adapts Provision's bounded remote state, Discussion, and capability-gated action contract for a trusted local connector. |

`provision.remote/v1` does not authenticate a network peer. A connector must
complete cryptographic pairing or another suitable identity check before it
submits a device request. The daemon then applies its own paired-device
capability checks and action idempotency rules.

## Non-goals

- No listener is exposed on TCP, HTTP, WebSocket, Cloudflare, or the dashboard.
- No OpenAI credentials, dashboard token, full transcript dump, or raw quota
  payload is carried by the ABI.
- No bundled connector, relay, pairing UX, or cryptographic transport exists.
- The ABI does not grant a connector permission to route arbitrary shell or
  proxy traffic.

A connector may be local-only, direct-peer, self-hosted, or part of a hosted
service. The ABI is explicitly experimental until those shapes have real-world
validation.
