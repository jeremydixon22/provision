# Codex 0.162.1 compatibility review

Reviewed October 12, 2026 (America/New_York), against Provision 0.159.2 and the
installed Codex CLI and shared app-server, both 0.162.1. This carries forward
the October 1 review of 0.160.0 and October 7 review of 0.161.0. The fixes below
are included in Provision 0.162.1; the Codex minimum remains 0.144.0.

## Findings and changes

Codex now gates Fast and Ultrafast independently when the server supports it.
Provision previously rewrote an explicit `service_tier="ultrafast"` to
`"priority"` whenever the profile's Fast toggle was enabled. Both HTTP and
WebSocket request rewriting now preserve that native selection, with Fast
enabled or disabled. Ordinary Fast behavior is unchanged. This preserves a
native selection; it does not add an Ultrafast selector to Provision or grant
account eligibility. See Codex's
[service-tier policy](https://github.com/openai/codex/blob/rust-v0.162.1/codex-rs/tui/src/service_tier_resolution.rs).

The pending discussion fix addresses a Provision cache bug. After the first
detail fetch, the merged session contained transcript and turn arrays. The UI
mistook those cached arrays for a complete static discussion and skipped later
revision checks. It now compares cached detail with the latest session revision
and clears pending detail requests on WebSocket reconnect. Streaming edits and
later turns advance without reloading the page; static demo discussions still
render without fetching.

Other reviewed changes from the
[0.162.0 release](https://github.com/openai/codex/releases/tag/rust-v0.162.0)
and [0.162.1 release](https://github.com/openai/codex/releases/tag/rust-v0.162.1):

| Upstream change | Provision impact |
| --- | --- |
| Consolidated command output in `aggregatedOutput` / `aggregated_output`; removed separate output fields | The existing command-card parser already prefers these fields. Regression coverage verifies output and exit status without legacy fields. |
| New `partialAnswer` / `partial_answer` message phase | Completed partial messages are already visible. Regression coverage ensures they are not mistaken for a final-answer completion fallback. |
| Server-owned model and reasoning defaults, narrower shared-daemon startup compatibility checks | Provision still supplies its explicit provider/model choices and uses `--no-daemon` for interactive, resume, and fork launches, preserving per-process HTTPS trust and routing. |
| Additional tool definitions and base instructions represented as Responses input messages | Model rewriting preserves unrelated input items. History parsing continues to exclude system/developer instructions from user discussion. |
| Removed `namespaceTools` fields; added turn lineage, attachment ownership, and extension metadata | Provision neither sends the removed fields nor requires the additions. Capability discovery does not depend on the removed capability property. |
| Shared-server managed worktrees, task pinning, clipboard and TUI interaction changes | These do not require changes to Provision's embedded launch path. |

The generated experimental schema has 447 files, up from 440 at the last
Provision release and 445 in 0.161.0. All 34 methods Provision probes remain.
The account, rate-limit, and token-usage response schemas equal the 0.161.0
baseline. The bundled catalog changed model instructions, but its normalized
Provision picker metadata is unchanged; GPT-6.1 Sol remains the bundled default.
Saved model choices are preserved.

Quota scheduling also remains unchanged: Codex's TUI still polls every 5–60
seconds depending on usage, without an origin marker distinguishing `/status`
from automatic reads. Provision retains one-second freshness for native TUI
reads and its hourly full-usage schedule. Frequent native reads remain a
limitation; this review does not establish that reads consume model allowance.

The release also incorporates the reviewed coverage, mypy, and Ruff dependency
PRs (#22–24), including resolution of their overlapping requirement edits.

## Validation and limits

The release tree passed 332 Python tests, 82 UI checks, Ruff lint and formatting,
strict mypy checks across 12 typed boundaries, and source/wheel builds with a
clean wheel install verifying both entry points and the packaged fixes. A real isolated Provision
WebSocket plus Chromium test fetched three discussion revisions and displayed
both a streaming edit and a subsequent turn without a browser refresh.

Using a disposable copy of current native credentials, Codex 0.162.1 initialized
through an isolated Provision HTTPS listener, returned the selected account's
HTTPS workspace routing, listed models, and started an ephemeral thread with
the OpenAI provider and GPT-6.1 Sol. A ten-second embedded TUI smoke reached the
Codex banner without an account/read bootstrap error or sign-in prompt. A
separate attempt with expired saved-profile credentials returned no account;
that attempt is not counted as a successful authenticated routing check.

No model turn or interactive `/status` invocation was run. Full paginated
history completeness remains unverified. The live Provision daemon was stopped
and the native shared Codex daemon was left running. Reproducible schema/source
snapshots are under `/scratch/cache/provision/codex-0.162.1-review/`; private
smoke logs and Develish progress are in ignored local agent storage.
