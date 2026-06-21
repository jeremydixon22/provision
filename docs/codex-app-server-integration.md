# Codex CLI App-Server Integration Notes

Provision currently uses Codex CLI's normal TUI/exec surfaces and observes the
traffic that Codex CLI sends through Provision's local proxy. Codex CLI `0.141.0`
also exposes an experimental app-server protocol that can supplement some of
Provision's inferred traffic parsing.

This note records the current shape so the next integration step can be
intentional rather than tied to chat history.

## Useful Protocol Surface

Generated locally with:

```bash
codex app-server generate-json-schema --experimental --out <dir>
```

The current app-server protocol includes first-class methods and notifications
for:

- Account state: `account/read`, `account/updated`, `account/login/start`,
  `account/login/completed`, and `account/logout`.
- Quota, usage, and credits: `account/rateLimits/read`,
  `account/rateLimits/updated`, `account/usage/read`, and
  `account/rateLimitResetCredit/consume`.
- Model metadata: `model/list`, `model/rerouted`,
  `modelProvider/capabilities/read`, and `model/verification`.
- Thread state: `thread/list`, `thread/read`, `thread/resume`,
  `thread/settings/update`, `thread/settings/updated`,
  `thread/status/changed`, and `thread/tokenUsage/updated`.
- Turn lifecycle: `turn/start`, `turn/started`, `turn/completed`,
  `turn/interrupt`, and `turn/steer`.
- Remote-control management: `remoteControl/status/read`,
  `remoteControl/enable`, `remoteControl/disable`, `remoteControl/pairing/start`,
  and client list/revoke operations.

## Near-Term Fit

These pieces map cleanly to current Provision features:

- Replace or supplement proxy-observed active request tracking with
  `thread/status/changed`, `turn/started`, and `turn/completed`.
- Replace WebSocket token scraping with `thread/tokenUsage/updated` where the
  app-server is available.
- Replace the current `codex debug models --bundled` model-catalog probe with
  `model/list` if Provision adopts an app-server client.
- Use `account/rateLimits/read` and `account/rateLimits/updated` as a cleaner
  source for quota buckets and credits.
- Use `account/usage/read` to mirror Codex CLI `/usage` token summaries and
  daily buckets.
- Use `account/rateLimitResetCredit/consume` to expose available reset credits
  with explicit user confirmation and idempotent redemption.
- Use `thread/settings/update` to explore per-session model and reasoning
  changes without relying solely on request rewriting.

## Current Provision Integration

Provision now uses the app-server in a narrow, optional path:

- `provision app-server-probe` generates the local app-server JSON schema and
  reports whether usage, rate-limit, reset-credit, and control-plane methods are
  present. The control-plane report is grouped into account, model, thread,
  turn, token-usage, and remote-control readiness so downstream UI work can be
  feature-gated.
- `provision app-server-probe --read-account` starts a short-lived app-server
  against the current stock Codex CLI login and reads account usage/rate-limit
  data for diagnostics.
- Normal quota refreshes still use the ChatGPT backend usage endpoint as their
  primary source. Provision merges only recent cached app-server rate-limit
  data into that payload, then schedules a per-profile background app-server
  refresh when the installed Codex CLI supports `account/rateLimits/read`.
- App-server quota enrichment is throttled and failure-backed-off per profile.
  Slow app-server startups, schema drift, or read failures are logged but do not
  block the primary quota/status display.
- Rate-limit reset credits are surfaced in the dashboard when
  `account/rateLimits/read` reports available credits. Redemption requires an
  explicit confirmation and calls `account/rateLimitResetCredit/consume` with an
  idempotency key. This is intentionally synchronous because the user requested
  the action and needs to see the outcome.
- Profile-scoped app-server calls run in a temporary `CODEX_HOME` seeded with
  the selected Provision profile's `auth.json`. Any refreshed auth file is
  imported back into the profile after the app-server exits.
- Reset-credit redemption attempts are appended to
  `~/.provision/codex/reset-credit-events.jsonl` and the general stats log.

This keeps the existing proxy and launcher path authoritative for routing,
resume compatibility, session pins, and switch safety. The dashboard does not
require the app-server to render or route normal Codex CLI traffic, and
Provision does not yet use app-server methods to start, steer, or interrupt
turns.

## Credential Injection Research

The generated schema includes `chatgptAuthTokens` login parameters and a
`ChatgptAuthTokensRefreshParams`/`Response` shape. That maps closely to
Provision's desired profile-owned credential injection:

- Provision could supply an access token and `chatgptAccountId`.
- Codex can request refresh after an upstream `401 Unauthorized`.
- The refresh request includes `previousAccountId`, which is compatible with
Provision's multi-profile store.

The schema labels this mode unstable/internal. Treat it as a research path, not
as a release dependency, until the upstream surface is documented or proves
stable enough in practice.

## Recommended Sequence

1. Keep the app-server schema probe visible in `provision status`,
   `provision doctor`, and dashboard compatibility state.
2. Expand the reset-credit path only after more real-world response shapes are
   observed across accounts with and without credits.
3. Mirror app-server thread/turn/token events into Provision's existing stats
   model without changing switching behavior.
4. Add a read-only dashboard view for app-server thread state before adding any
   user input path.
5. Use app-server quota/model metadata more broadly as an optional source and
   keep the current proxy/debug fallbacks.
6. Only after those steps, experiment with `chatgptAuthTokens` in an isolated
   profile and feature-flag any credential-injection path.

## Non-Goals For Now

- Do not make the dashboard require Codex CLI's app-server.
- Do not replace the resume-compatible launcher path until app-server-backed
  resume and TUI behavior are proven.
- Do not depend on `chatgptAuthTokens` for normal profile switching while it is
  labeled unstable/internal upstream.
