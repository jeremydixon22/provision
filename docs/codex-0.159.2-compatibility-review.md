# Codex 0.159.2 compatibility review

Reviewed September 29, 2026 (America/New_York), against Provision 0.156.1 (commit `c400acb`)
and the installed `codex-cli 0.159.2`. The findings and fixes are included in
Provision 0.159.2.

## Findings and changes

Codex 0.157.0 enabled automatic attachment of eligible interactive sessions to
a shared app-server. [Codex's daemon documentation](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/app-server-daemon/README.md)
states that attached clients use the daemon's startup environment and have no
per-client environment isolation. Provision supplies `CODEX_CA_CERTIFICATE` for
its private HTTPS backend and `OPENAI_PROJECT` for session routing at launch.
A shared daemon started outside Provision cannot reliably inherit those values;
one started through Provision could retain them for unrelated clients. Provision
now adds Codex's supported `--no-daemon` flag for interactive, resume, and fork
sessions on CLI 0.156.0 and newer, leaving older CLIs and non-interactive and
administrative commands' invocation unchanged. This keeps these sessions on an
embedded app-server with their own launch environment. They do not participate
in Codex's shared daemon session management.

[Codex's changelog](https://learn.chatgpt.com/docs/changelog) makes GPT-6.1 Sol
the new default model in 0.159.1. The 0.159.2 bundled catalog advertises low
default reasoning, efforts through ultra, and Fast at 2×. Provision's healthy
CLI catalog discovery already exposes it. The degraded fallback picker now
includes it too. Provision does not rewrite saved model choices. For profiles
without a saved choice or an explicit stock Codex model, Provision now selects
the highest-priority visible bundled model rather than the first JSON entry.
This matches Codex's new Sol default. If catalog discovery fails, it retains
the existing Astra default to avoid choosing a model an older CLI may not
support.

The generated experimental app-server schema grew from 436 to 440 files. All 34
methods Provision probes remain available. `GetAccountRateLimitsResponse`,
`GetAccountTokenUsageResponse`, and `GetAccountResponse` are unchanged. The new
`thread/items/list` anchor cursor is additive; its existing string cursor
remains accepted, so Provision's pagination continues to work. Added item
timestamps and error/plan enum values do not require parser changes. The
bundled catalog removes the older GPT-5.4 entry; a profile pinned to an absent
model will receive Provision's existing unavailable-model notice.

Codex also exposes native `agents` and `queue` commands for the shared daemon,
and `migrate-rollouts` for local history. These are separate from Provision's
profile-routed launch path; use the native `codex` CLI for shared-daemon
management. The migration can replace a legacy rollout at the same JSONL path
with paginated history. Provision still reads JSONL directly, so deeper history
page completeness remains unverified. Eight recent local files were already
marked paginated, and Provision's reader recovered turns and transcript entries
from each; this review did not reproduce a history-reading failure.

Codex's [TUI rate-limit source](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/tui/src/chatwidget/rate_limits.rs)
still polls every 5–60 seconds according to usage. The `account/read` and
rate-limit schema comparison found no new origin marker separating a user
`/status` request from periodic refreshes. Provision preserves one-second freshness for native
TUI reads while keeping Provision's own hourly full-usage schedule. Frequent
Codex-originated reads remain a limitation; neither the prior incident nor this
review establishes that quota checks consume model allowance.

## Validation

The 0.159.2 app-server initialized and listed models and threads in an isolated
Codex home. An isolated Provision HTTPS listener returned a successful
`account/read` with the selected profile's account and HTTPS backend origin.
A ten-second TUI smoke test using `--no-daemon` reached that proxy without an
`account/read` bootstrap error; no model turn or `/status` interaction was run.
The shared Codex daemon was left running and the live Provision daemon was not
restarted during review. The dashboard logo was resized to 166 × 33 px across
breakpoints. The release tree passed 329 Python tests, 72 UI checks, Ruff lint
and format checks, CI's strict mypy boundary checks, and source/wheel builds
with a clean wheel install. Generated schema/model
snapshots and the disposable smoke-test script are under ignored
`.agent-artifacts/codex-0.159.2-review/`.
