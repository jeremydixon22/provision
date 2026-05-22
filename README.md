<p align="center">
  <img src="src/provision/assets/provision.png" alt="Provision logo" width="700">
</p>

Provision is a local profile manager and proxy for Codex. It lets you run
`provision` instead of `codex`, keep Codex's normal terminal UX and resume
history, and switch between Provision-managed upstream credentials.

The first supported target is Codex with ChatGPT login profiles. Provision now
has the core pieces needed for daily use: profile enrollment, daemon startup,
credential injection, WebSocket proxying, `/status` quota labeling, a localhost
profile UI with live state updates, and safe profile switching while requests
are idle.

The earlier cross-CLI credential research is still available in
[docs/cli-credential-isolation.md](docs/cli-credential-isolation.md).

## Requirements

- Codex CLI `0.132.0` or newer is required for the full current path.
- Python 3.11+ is recommended.
- The labeled `/status` quota display depends on Codex's multi-bucket
  ChatGPT-backend usage payload support (`additional_rate_limits` surfaced as
  per-limit status rows). Older Codex versions may still route model traffic
  through Provision, but quota labeling and multiple quota sections may be
  missing or misleading.

## Quick Start

From this repo:

```bash
./bin/provision import-default
./bin/provision login <profile_name> [--device-auth]
./bin/provision profiles
./bin/provision ui
./bin/provision
```

For example:

```bash
./bin/provision login work --device-auth
```

For normal command usage, put `bin/provision` on PATH or install editable:

```bash
python3 -m pip install -e .
```

Arguments that are not Provision commands pass through to Codex. Model-running
Codex subcommands receive the proxy config in the position Codex expects:

```bash
provision
provision resume --last
provision debug models
provision exec "Say hello"
```

Help is available from the top level and from each subcommand:

```bash
provision --help
provision help
provision login --help
```

## How It Works

Provision starts a local daemon when needed, points Codex's built-in `openai`
provider at that daemon, and uses a local `OPENAI_PROJECT` sentinel to
authenticate Codex to the proxy. The daemon removes that sentinel before
forwarding and injects the active upstream profile's real credentials.

This keeps Codex-compatible behavior intact:

- Codex session history remains in the normal Codex home, so `codex resume` and
  `provision resume` see the same transcripts.
- Codex continues to record local thread metadata as `model_provider=openai`,
  avoiding resume-picker fragmentation between stock Codex and Provision runs.
- Responses WebSocket traffic is tunneled through the proxy; HTTP/SSE remains
  available for paths that do not use WebSockets.
- Profile switches are refused while the proxy has active upstream requests, so
  a request cannot change accounts mid-turn.

## Profiles

The current `~/.codex/auth.json` can be imported as the `default` Provision
profile:

```bash
provision import-default
```

Rerunning `import-default` leaves an existing profile unchanged. Use
`--overwrite` when you intentionally want to replace the stored profile from the
current stock Codex login.

Additional ChatGPT login profiles are captured through a separate temporary
`CODEX_HOME`, so Provision does not need to intercept Codex `/logout`:

```bash
provision login work --device-auth
provision login personal
```

Switch profiles from the CLI or localhost UI:

```bash
provision profiles
provision use work
provision ui
```

## Status And Quota

Codex `/status` receives usage data for the active Provision profile. Provision
adds a timestamped quota label such as `Provision (work - updated 15:36 on 22
May)` so it is clear when the displayed quota was last fetched.

When the active profile is not `default`, Provision also appends the stored
Provision `default` profile's quota as separate non-`codex` status rows when
available. Additional quota buckets reported by ChatGPT, such as plan- or
model-specific limits, are copied dynamically for whichever profile reports
them.

ChatGPT usage lookups are cached per profile, with upstream refreshes paced to
at most one per second across the daemon. The web UI shows the current daemon's
last-known quota per profile, formats supported quota buckets as bars, and has a
per-profile `Refresh quota` action. The UI uses a localhost WebSocket control
channel so active request counts, switch availability, and cached quota state can
update without a full page refresh. It follows the browser's system light/dark
mode preference.

## Ports

The daemon prefers stable localhost port `4888`. If that default is unavailable,
Provision falls back to a dynamic port and records the selected port in
`~/.provision/daemon.json`.

To choose a specific port, use `PROVISION_PORT` or start the daemon explicitly:

```bash
PROVISION_PORT=4888 provision
provision start --port 4888
provision ui --port 4888
```

## Storage

Provision state is outside the repo:

```text
~/.provision/
  proxy-token
  daemon.json
  daemon.log
  codex/
    active-profile
    profiles/<name>/
      auth.json
      metadata.json
```

These files include credentials. Do not commit or sync them casually.

## Common Commands

| Command | Purpose |
| --- | --- |
| `provision` | Launch Codex through the active Provision profile. |
| `provision import-default [--name <profile_name>] [--overwrite]` | Import the current `~/.codex/auth.json` as a Provision profile. Defaults to `default`; existing profiles are left unchanged unless `--overwrite` is set. |
| `provision login <profile_name> [--device-auth]` | Capture a new ChatGPT login into an isolated Provision profile. |
| `provision profiles` | List enrolled profiles and show which one is active. |
| `provision use <profile_name>` | Switch the active profile when the daemon is idle. |
| `provision ui [--port <port>]` | Start the daemon if needed and print the localhost UI URL. |
| `provision status` | Print JSON status for Provision home, daemon, active profile, profiles, and UI URL. |
| `provision start [--port <port>]` | Start the local proxy daemon without launching Codex. |
| `provision stop` | Stop the running daemon. |
| `provision doctor` | Run basic local environment checks. |
| `provision --help`, `provision <command> --help` | Show top-level or command-specific help. |

## Verification

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
PYTHONPATH=src python3 -m compileall -q src tests
provision exec --ephemeral -s read-only -c 'approval_policy="never"' 'Reply with exactly: provision-ok'
```

The `exec` banner should report `provider: openai`, and the active Provision
profile should be the account that answers upstream.

## Security

Provision stores and forwards local CLI credentials. Do not open a public issue
for credential leaks, token exposure, authentication bypasses, or proxy
isolation issues. See [SECURITY.md](SECURITY.md).

## Limitations

- The web UI is localhost-only. It is intended for a single local user, not as a
  remote multi-user control plane.
- Provision keeps Codex's built-in `openai` provider identity for resume
  compatibility. Native Codex account identity can therefore reflect the stock
  `~/.codex/auth.json`; Provision's status labels, `provision status`, and
  `~/.provision/daemon.log` show the profile actually used by the proxy.
- The appended `Provision profile (default)` quota section is the stored
  Provision `default` profile. It is not re-read from stock Codex auth after
  later stock logins.
- Quota sections are shaped from the upstream usage payload. If a profile or
  plan does not report a bucket, Provision does not invent one.
- Codex still applies its normal current-working-directory filter in the resume
  picker. Use `provision resume --all` when launching from a different directory
  than the sessions you want to see.

## Roadmap

- First-class API-key profile enrollment, so users can store and switch named
  OpenAI API keys without relying on shell-level `OPENAI_API_KEY` changes.
- API-key-aware status output, including clear `Provision API key (<profile>)`
  labeling when ChatGPT subscription quota data does not apply.
- API billing and rate-limit visibility for API-key profiles if suitable
  upstream billing, usage, or limits endpoints can be integrated cleanly.
- Optional policy controls such as workspace defaults, spend guardrails, audit
  logs, and key rotation metadata.

## License

Provision is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
