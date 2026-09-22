# Codex 0.155.1 compatibility review

Reviewed on September 21, 2026, against the installed `codex-cli 0.155.1` and
cached `0.153.4` baseline. Provision 0.155.1 keeps the existing Codex 0.144.0
minimum; newer capabilities are handled when present.

## Implemented changes

| Codex change or exposed gap | Provision behavior |
| --- | --- |
| Astra in-history `configuration_update` reasoning controls | Preserves the original request-level reasoning prefix and earlier controls, then sets the selected effort for the next response. A pending final control is replaced instead of duplicated. HTTP and WebSocket paths share the policy. |
| Incremental response chains | Retains observed control mode per credential generation, profile, session, and thread, including WebSocket continuations that omit repeated thread metadata. Contexts are bounded to 1,024 entries. |
| Controls unsupported by other models, priority/flex tiers, or standalone compaction | Removes supplied Astra-only controls and uses the selected request-level effort on those requests. |
| `ordinaryUsageAllowed` account permission | Preserves true, false, unknown, and omitted states. Explicit denial or unknown availability remains visible in full quota cards, compact session meters, and CLI summaries regardless of percentages or reset timestamps. Percentage-only updates cannot clear a known denial. |
| `normalModelSlug` quota aliases | Retains model metadata while treating an alias as its own bucket. A reserve alias does not replace the normal model's included-usage display. |
| Worktree transitions | Uses current turn metadata for the working directory while retaining the launcher session key, profile pin, and PTY controls. Heartbeats cannot revert the directory. Keeps up to 16 previously observed directories available for native history and resume lookup. A new launcher process resets this directory history. |
| Account replacement during background work | Model, rate-limit, and usage caches belong to a credential generation. Delayed results from old credentials are discarded. HTTP/WebSocket quota observations also carry their credential owner. A temporary app-server refresh checks the source credentials before importing refreshed credentials. |
| Streamed compaction progress | Reads available upstream HTTP data without waiting for a 64 KiB buffer to fill, then flushes it downstream. |
| Catalog changes | Removes GPT-5.2, GPT-5.4, and GPT-5.4-mini from both fallback pickers. Live discovery remains authoritative. Saved selections remain explicit, with guidance when absent from the current catalog. |
| Removed `codex mcp-server` command | Removes the obsolete launcher passthrough classification. Provision continues to use `codex app-server`. |

## Evidence and validation

The local 0.155.1 catalog reports Astra, Sol, Terra, Luna, and GPT-5.5. All 34
app-server methods probed by Provision remain present. An isolated, unauthenticated
app-server smoke test successfully initialized and returned model and thread
lists. No live account requests or reset-credit consumption were used to validate
this release.

Regression tests cover history-preserving reasoning changes, incremental
WebSocket traffic over real local sockets, compaction and tier compatibility,
quota permission transitions and aliases, worktree moves and native rollout
history, reauthentication races, late quota observations, and delivery of the
first HTTP stream event before the upstream response finishes. Existing suites
continue to cover the supported legacy protocol shapes.

The release also incorporates the reviewed development dependency updates from
[PR #19](https://github.com/jeremydixon22/provision/pull/19) and
[PR #20](https://github.com/jeremydixon22/provision/pull/20).

## Scope and limits

Control-mode tracking is in memory. Provision cannot inspect control items
stored only behind an unknown `previous_response_id`, for example after a daemon
restart or context eviction. A native request containing full conversation
history reestablishes the mode. Switching models or tiers in a chain whose
incompatible controls exist only server-side still depends on Codex submitting
compatible history; Provision cannot rewrite hidden upstream history.

Credential changes, including token rotation, conservatively invalidate cached
account data. A refresh overlapping that change can be discarded and retried.
The temporary-auth check detects replacements during the app-server request; it
is not a cross-process filesystem transaction with independently running login
programs.

Native asynchronous questions, voice mode, and worktree creation remain owned by
Codex. Provision's terminal integration remains the interaction surface; this
release does not implement a second app-server question-response client or
activate Luna reserve fallback. Native history lookup still reads plain JSONL
rollouts; compressed rollouts require a separate reader.

## Upstream references

- [Codex changelog](https://learn.chatgpt.com/docs/changelog)
- [Changing reasoning during a conversation](https://developers.openai.com/api/docs/guides/reasoning#change-reasoning-mid-conversation)
- [Codex model lifecycle](https://learn.chatgpt.com/docs/models#deprecated-codex-models)
- [App-server user-input requests](https://learn.chatgpt.com/docs/app-server#toolrequestuserinput)

Generated schemas and bundled catalogs were compared locally. Schema artifacts
and test logs stay under the ignored `.agent-artifacts/` directory.
