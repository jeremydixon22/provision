# Provision 0.156.1: Codex compatibility and quota freshness

Reviewed September 22, 2026 (America/New_York), against Provision 0.155.1 and
the installed `codex-cli 0.156.1`. The running Provision process started with
Codex 0.155.1 and still reports that version through its cached startup probe.
Installing a new CLI does not reload Provision's Python code or that probe.

## Quota findings

The default profile's dashboard showed `Included usage blocked` with a recently
updated percentage timestamp. That timestamp did not establish permission
freshness: numeric usage observations refreshed it while preserving an earlier
`ordinary_usage_allowed: false` value.

At 03:00 UTC on September 23, a read-only `/wham/usage` request for that profile
returned `rate_limit.allowed: true`, `limit_reached: false`, and 1% weekly usage.
The response account matched the stored profile. One normal dashboard refresh at
03:01 UTC, including a new app-server permission read, changed the dashboard to
`Available; weekly 99%`. Recovery was verified by fresh permission data, not
inferred from the percentage. No reset credit was consumed.

The retained statistics contained 3,501 `usage_fetch` events from 21:12:48 UTC
through 02:49:04 UTC, a median interval of 5.62 seconds. There were 66 app-server
rate-limit updates over approximately the same interval, with a median interval
of 304.67 seconds. The ordinary HTTP usage cache had a one-second lifetime, so
native polling repeatedly passed through to the backend. The separate hourly
background refresh did not limit those requests.

This establishes excessive polling and stale presentation of a denial. It does
not establish why the backend originally denied usage, or that quota reads
consumed model allowance or caused that denial. Other profiles' existing billing
errors are separate from this recovered profile.

## Provision 0.156.1 changes

- Preserve the existing change that distinguishes account identity from rotating
  credentials. Include the JWT subject when available so users within one shared
  workspace do not share an account-cache generation.
- Cache ordinary usage reads for five minutes. Manual and reset-verification
  reads retain the existing one-second minimum interval. Failed ordinary reads
  back off for five minutes, or one day for billing failures; manual refresh can
  retry. Concurrent reads still coalesce.
- Track permission freshness separately. Only an explicit permission observation
  renews it. Dashboard snapshots show unknown availability after five minutes,
  or when no permission timestamp exists. Percentage-only updates cannot turn a
  denial into approval or make an old permission look freshly checked.
- Schedule app-server permission checks independently of full usage reads, using
  the existing five-minute success interval, fifteen-minute failure backoff, and
  in-flight guard. Skip profiles marked as requiring login or billing. Keep a
  separate full-usage timestamp so these checks cannot postpone hourly reads or
  reset verification indefinitely.
- Import a temporary app-server credential refresh only if the stored credential
  material still matches the copy used to start that client. A newer same-account
  refresh wins. The final comparison/import shares the in-process refresh lock.
  This is not a cross-process transaction with independent login programs.
- Add GPT-6-Sol and GPT-6-Luna to the degraded-mode model picker with the
  efforts and Fast-tier metadata reported by Codex 0.156.1.
- Give Codex 0.156.0 and newer an HTTPS workspace backend on a separate
  loopback-only listener. Provision creates a private CA and server certificate,
  verifies and reuses them, and adds the CA to a per-process Codex trust bundle
  alongside existing public and custom roots using
  [Codex's documented custom CA setting](https://learn.chatgpt.com/docs/auth#custom-ca-bundles).
  No system trust store is changed. The server certificate lasts ten years and
  renews under the same CA when fewer than 120 days remain, including during a
  running daemon's hourly check. Startup also checks the 20-year CA. The CA
  signing key is kept in the user-private certificate directory for leaf renewal.
  Earlier Codex versions retain the existing HTTP path. A protocol change makes
  the launcher restart an older Provision daemon before using the new listener.

The live dashboard recovery above used the previously running process; the new
polling behavior requires a Provision daemon restart after upgrading.

## Codex changes and Provision impact

The comparison used locally generated schemas and bundled model catalogs for
0.155.1 and 0.156.1. The schema file count changed from 437 to 436. All 34
app-server methods probed by Provision remain available. An isolated,
unauthenticated app-server smoke test initialized and listed models and threads.

| Local evidence | Impact on Provision |
| --- | --- |
| `GetAccountRateLimitsResponse` and `NullableGetAccountRateLimitsParams` are unchanged. | No new quota permission semantics explain this incident. Continue preserving explicit true, false, and unknown values; percentages do not prove permission. |
| Catalog adds `gpt-6-sol` and `gpt-6-luna`, both with medium default effort. Existing models remain. | Catalog discovery accepts them. Sol advertises efforts through ultra, Luna through max, and both advertise Fast at 1.5×. The degraded-mode catalog now includes both. |
| `account/read` adds optional `workspaceRouting`, including backend origin and account routing override. | The new origin validator rejects Provision's old HTTP backend and prevents TUI bootstrap. The HTTPS listener resolves this for the tested account. Regional/managed workspace routing still needs dedicated validation; no regional-account test was performed. |
| `ThreadRollbackParams/Response` are removed; `RolloutCompressResponse` is added. | Provision does not call rollback. Native history still reads plain JSONL, so compressed rollout support remains a known gap. |
| Model discovery adds optional access-program metadata; personality support is deprecated. | Existing normalization tolerates extra fields. Provision does not expose those access programs or depend on personality selection. |
| Installed CLI exposes `--no-daemon`; app-server retains stdio transport. | Provision's isolated metadata/quota clients still start stdio app servers. The interactive launcher passes proxy settings, process-scoped CA trust, and an `OPENAI_PROJECT` session identity. Reuse of a shared Codex daemon needs an end-to-end pinning/routing check; an environment-inheritance failure was not reproduced here. |

## HTTPS bootstrap regression

A newly launched Codex 0.156.1 TUI failed at `account/read` with “workspace
backend must use an HTTPS origin without credentials.” An isolated app-server
probe reproduced the error with Provision's previous HTTP `chatgpt_base_url`
override; the same account read succeeded with the direct backend. The account
response returned through Provision matched the direct backend response, so the
problem was the configured local origin, not an account-response rewrite.

A loopback HTTPS listener using the same Provision request handler succeeded in
an integrated probe. Codex required a proper CA-signed server certificate: a
self-signed leaf certificate failed TLS verification even when included in the
custom CA bundle. The final probe initialized Codex 0.156.1, completed
`account/read` through an isolated Provision server, returned an HTTPS
`workspaceRouting.backendOrigin`, and matched the selected profile's account.
The certificate and key are user-private. The HTTPS listener binds only
`127.0.0.1`, even if an administrator explicitly binds Provision's ordinary
HTTP interface more broadly. The normal proxy authorization and session pinning
checks are shared by both listeners. This probe did not run a model turn or test
regional workspace routing.

The official [Codex changelog](https://learn.chatgpt.com/docs/changelog) currently
describes the 0.156.0 release family, without a separate 0.156.1 entry. It adds
daemon update/bypass controls, enables worktrees by default, and adds usage
analytics, voice, and optional fullscreen terminal UI. Provision's existing
worktree identity handling remains relevant. Native terminal features remain
owned by Codex; their appearance does not imply new Provision dashboard features.
The changelog also records stricter managed-provider enforcement, so managed
installations need proxy-override compatibility testing.

## Validation

Regression coverage includes repeated native polling, manual refresh and error
backoff, permission expiry despite fresh percentages, independent permission
scheduling, preservation of full-usage deadlines, same-workspace user changes,
and concurrent credential refreshes. Existing tests cover account replacement,
reset-credit verification, model rewriting, and worktree continuity.

Validation passed: 325 Python tests, 72 UI checks, Ruff lint and formatting,
strict mypy checks for 12 modules, package build and metadata checks, and a
clean wheel install. A real 0.156.1 `account/read` succeeded against an
isolated Provision server. The HTTPS regression tests check the private file
modes, more than three months of validity at startup, continued trust after
server-certificate renewal, and rejection by default system trust.

Generated schemas, model catalogs, the sanitized live usage summary, the initial
patch backup, and test logs are under the ignored
`.agent-artifacts/quota-investigation-20260922/` directory. No credentials or full
account responses are included in this document.
