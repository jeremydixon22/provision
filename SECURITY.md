# Security Policy

Provision stores and forwards local CLI credentials. Please do not report
credential leaks, token exposure, authentication bypasses, or proxy isolation
issues in a public issue.

## Deployment boundary

**Never expose the Provision daemon port directly to a LAN, the Internet, or an
unauthenticated reverse proxy.** The daemon is a single-user, capability-bearing
control plane, not a network security boundary.

Provision binds to loopback by default and refuses non-loopback binds unless the
operator explicitly passes `--allow-non-loopback` or sets
`PROVISION_ALLOW_NON_LOOPBACK=1`. That override is only appropriate when a
separate authenticated and encrypted boundary protects the entire connection.
The override does not add multi-user authorization.

When bound to loopback, dashboard routes reject non-loopback `Host` headers to
reduce browser DNS-rebinding exposure. An SSH local port forward naturally
preserves a loopback browser origin. A reverse proxy that needs a public origin
should use the explicit non-loopback deployment boundary and must supply its own
authentication, encryption, and request-host policy.

Dashboard mutations use an ephemeral HttpOnly, same-origin session cookie. The
durable proxy capability remains available to trusted local CLI/launcher
processes and is deliberately not embedded in dashboard HTML or JavaScript.
`provision token` prints that durable capability: treat its output like a local
credential, do not share it, put it in a URL, record it in logs, or copy it to a
remote service.

Browser approval routing is disabled by default and must be enabled for each
supported managed session. A dashboard client that can resolve a permission
request is as trusted as one that can send terminal input: an untrusted client
could approve a shell command or file change. Provider hooks reach the daemon
through the launcher's mode-restricted Unix socket and a bounded, loopback-only
authenticated endpoint. Pending approvals fall back to the native terminal on
timeout or when the last dashboard client disconnects, and approval state is
not exposed through the Connector ABI or remote projection.

## Reporting

Use GitHub's private vulnerability reporting for this repository when available.
If private reporting is not enabled, contact the repository owner privately
through GitHub before publishing details.

Please include:

- The affected Provision version or commit.
- The platform and Codex version.
- A concise reproduction path.
- Whether any real credentials, tokens, or account identifiers were exposed.

## Supported Versions

Security fixes are currently made against the latest `main` branch until formal
release branches exist.
