# CLI Credential Isolation Analysis

Research date: 2026-05-18.

Versions checked:

- Codex CLI: local `@openai/codex` / `codex-cli 0.130.0`.
- Gemini CLI: npm `@google/gemini-cli 0.42.0`.
- Claude Code: npm `@anthropic-ai/claude-code 2.1.143`.

## Executive Summary

The most reliable shape is process-level isolation: start each CLI with a
profile-specific config/home directory and profile-specific environment. Do not
hot-swap the credential file under an active process unless the CLI explicitly
supports a dynamic credential provider.

| CLI | Independent environments | Dynamic credentials | External hot swap while running |
| --- | --- | --- | --- |
| Codex | Yes: `CODEX_HOME`, preferably with file-backed auth. | Yes for custom providers via `model_providers.<id>.auth.command`; built-in OpenAI login mainly supports cached auth plus token refresh. | Not a supported identity-switch mechanism. Start a new process for a different account. |
| Gemini | Yes: `GEMINI_CLI_HOME`, with caveats for keychain-backed saved API keys. | Limited: environment variables and stored auth are selected at launch; no general model-auth helper equivalent was found. | Not reliable. Interactive `/auth` exists, but external file/env swaps are not a supported live switch. |
| Claude | Yes on Linux/Windows: `CLAUDE_CONFIG_DIR`. macOS credentials use Keychain, so use env tokens, a separate OS user/keychain, or explicit reauth for strict separation. | Yes: `apiKeyHelper`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY`, and `CLAUDE_CODE_OAUTH_TOKEN`; `apiKeyHelper` refreshes on an interval or HTTP 401. | Helper-based rotation works. Editing credential files or parent env does not reliably change an already-running process. |

## Recommended Profile Shape

Use directories outside the repo:

```text
~/.ai-cli-profiles/
  codex/work/
    config.toml
    auth.json
  gemini/work/
    .gemini/
      settings.json
      oauth_creds.json
      .env
  claude/work/
    settings.json
    .credentials.json
```

Recommended launch approach:

```bash
CODEX_HOME="$HOME/.ai-cli-profiles/codex/work" codex
GEMINI_CLI_HOME="$HOME/.ai-cli-profiles/gemini/work" GEMINI_FORCE_FILE_STORAGE=true gemini
CLAUDE_CONFIG_DIR="$HOME/.ai-cli-profiles/claude/work" claude
```

Treat profile directories as secrets. Do not commit them, sync them casually, or
share them between simultaneous processes unless the tool documents safe
concurrent access.

## Codex

Codex supports ChatGPT login, API-key login, and enterprise access tokens. The
CLI and IDE extension share cached login details. OpenAI documents that cached
login details live in either a plaintext `auth.json` under `CODEX_HOME`
(`~/.codex` by default) or in the OS credential store. The setting is:

```toml
cli_auth_credentials_store = "file" # file | keyring | auto
```

For profile isolation, prefer `file`; keyring storage may be shared outside the
profile directory depending on the OS credential store implementation.

Codex also supports command-backed bearer tokens for custom model providers:

```toml
[model_providers.proxy.auth]
command = "/usr/local/bin/get-token"
args = ["codex-proxy"]
refresh_interval_ms = 300000
```

That is the clean dynamic-credential path for proxy/custom provider use. For
the built-in OpenAI provider, docs guarantee normal cached login reuse and
ChatGPT token refresh during use, not arbitrary account switching by replacing
`auth.json`.

Already-running instance assessment:

- Changing `CODEX_HOME` only affects new child processes launched with that
  environment.
- Editing or symlink-swapping `auth.json` under a running process is not a
  documented live-switch path and can race with token refresh writes.
- Use a new process for a different profile/account.
- Use `model_providers.<id>.auth.command` when the requirement is live token
  rotation for a custom provider.

## Gemini

Gemini CLI supports Sign in with Google, Gemini API keys, and Vertex AI.
Official docs state:

- Sign in with Google caches credentials locally.
- API-key mode can use `GEMINI_API_KEY`.
- Vertex AI can use ADC, `GOOGLE_APPLICATION_CREDENTIALS`, or `GOOGLE_API_KEY`
  with `GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_LOCATION`.
- `GEMINI_CLI_HOME` changes the root for user-level config/storage; Gemini
  creates a `.gemini` directory inside it.
- `.env` files are loaded from the first matching location; they are not merged.

Source inspection of `@google/gemini-cli@0.42.0` found:

- Default Google OAuth cache path: `$GEMINI_CLI_HOME/.gemini/oauth_creds.json`
  or `~/.gemini/oauth_creds.json`, mode `0600`.
- `GEMINI_FORCE_ENCRYPTED_FILE_STORAGE=true` moves OAuth storage through
  Gemini's hybrid token storage.
- Native keychain is preferred where available; `GEMINI_FORCE_FILE_STORAGE=true`
  forces the encrypted file fallback, stored as `gemini-credentials.json` under
  the Gemini home.
- Saved API keys use the same hybrid token storage service name
  `gemini-cli-api-key`; direct `GEMINI_API_KEY` per process is the simpler
  isolation path.

Already-running instance assessment:

- Parent shell env changes cannot affect an already-running process.
- Gemini caches OAuth clients in process and has an API-key cache, so changing
  files underneath a running instance is not a reliable account switch.
- `/auth` opens a dialog to change auth method, but that is an interactive
  reauth flow and some auth changes require restart.
- Use a new `GEMINI_CLI_HOME` process for account isolation.

## Claude

Anthropic's current Claude Code docs are explicit about storage:

- macOS: encrypted macOS Keychain.
- Linux: `~/.claude/.credentials.json` with mode `0600`.
- Windows: `%USERPROFILE%\.claude\.credentials.json`.
- On Linux/Windows, `CLAUDE_CONFIG_DIR` moves `.credentials.json` under that
  directory.

Claude Code auth precedence is:

1. Cloud-provider credentials when `CLAUDE_CODE_USE_BEDROCK`,
   `CLAUDE_CODE_USE_VERTEX`, or `CLAUDE_CODE_USE_FOUNDRY` is set.
2. `ANTHROPIC_AUTH_TOKEN`.
3. `ANTHROPIC_API_KEY`.
4. `apiKeyHelper`.
5. `CLAUDE_CODE_OAUTH_TOKEN`.
6. Subscription OAuth credentials from `/login`.

For dynamic credentials, `apiKeyHelper` is the best-documented mechanism. It can
return an API key from a vault or token service and is refreshed by default after
5 minutes or on HTTP 401. The interval is controlled by
`CLAUDE_CODE_API_KEY_HELPER_TTL_MS`.

Already-running instance assessment:

- `apiKeyHelper` supports credential rotation during a running process.
- `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, and `CLAUDE_CODE_OAUTH_TOKEN`
  are process environment values; changing the parent shell after launch does
  not update the running process.
- `/logout` and login flows can reauthenticate interactively, but external file
  replacement is not a safe live-switch strategy.

## Practical Guidance

Use these rules:

1. Prefer new process per account/profile. This is robust for all three CLIs.
2. Prefer per-process env for API keys/tokens instead of saved keychain entries
   when you need deterministic isolation.
3. Force file-backed storage when keychain storage would collapse profiles into
   one OS account.
4. Use dynamic helpers only where supported:
   - Codex custom providers: `model_providers.<id>.auth.command`.
   - Claude: `apiKeyHelper`.
   - Gemini: no general equivalent found for model auth; use new processes.
5. Avoid symlink flips or overwriting credential files under running processes.
   They can be stale, ignored, or overwritten by refresh logic.

## Sources

- OpenAI Codex authentication: https://developers.openai.com/codex/auth
- OpenAI Codex config reference: https://developers.openai.com/codex/config-reference
- Gemini CLI authentication: https://geminicli.com/docs/get-started/authentication/
- Gemini CLI configuration: https://geminicli.com/docs/reference/configuration/
- Gemini CLI commands: `@google/gemini-cli@0.42.0` bundled docs, `docs/reference/commands.md`
- Anthropic Claude Code authentication: https://code.claude.com/docs/en/authentication
- Anthropic Claude Code settings: https://code.claude.com/docs/en/settings
- Anthropic Claude Code environment variables: https://code.claude.com/docs/en/env-vars
