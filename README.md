<p align="center">
  <img src="src/provision/assets/provision.png" alt="Provision logo" width="700">
</p>

Provision is a local profile-switching proxy and dashboard for Codex CLI. Run
`provision` instead of `codex` to keep Codex CLI's normal terminal workflow,
resume history, and built-in login flow while Provision manages upstream
credentials and session-aware switching.

Provision is useful even when you only use one account: it gives Codex CLI a
localhost dashboard for active requests, live tunnels, observed working
directories, per-account quota, and quota reset timing. With multiple accounts,
it adds named ChatGPT login profiles, safe profile switching, and session pins
so one Codex CLI session can stay tied to an account while another session uses
a different profile.

The current implementation targets Codex CLI with ChatGPT login profiles. It is
not a desktop Codex client or a remote control plane.

The earlier cross-CLI credential research is still available in
[docs/cli-credential-isolation.md](docs/cli-credential-isolation.md).

## Requirements

- Codex CLI `0.132.0` or newer is required for the full current path.
- Python 3.11+ is recommended.
- The richest quota display depends on Codex CLI and the ChatGPT backend
  reporting multi-bucket usage data. Older Codex CLI versions may still route
  model traffic through Provision, but status labeling or extra quota buckets
  may be incomplete.

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
./bin/provision use work
./bin/provision resume --last
```

For normal command usage, put `bin/provision` on PATH or install editable:

```bash
python3 -m pip install -e .
```

Arguments that are not Provision commands pass through to Codex CLI. Model
commands receive the proxy config in the position Codex CLI expects:

```bash
provision
provision resume --last
provision debug models
provision exec "Say hello"
```

Help is available from the top level and from subcommands:

```bash
provision --help
provision help
provision login --help
```

## What Provision Adds

- Named Codex CLI ChatGPT login profiles captured through isolated temporary
  `CODEX_HOME` directories.
- A localhost dashboard with profile state, active request counts, WebSocket
  tunnel state, observed working directories, session pins, and quota bars.
- Session-aware switching: unpinned Codex CLI activity blocks account changes,
  while pinned sessions can remain active without blocking switches for other
  sessions.
- Per-profile quota caching, manual refresh, automatic hourly refresh, and
  refreshes shortly after detected quota reset times.
- Timestamped `/status` quota labels so Codex CLI can show which Provision
  profile supplied the displayed quota.
- Resume-compatible launching that keeps Codex CLI's native transcript history
  and `model_provider=openai` session identity intact.

## How It Works

Provision starts a local daemon when needed, points Codex CLI's built-in
`openai` provider at that daemon, and passes a local `OPENAI_PROJECT` sentinel
to identify the calling working directory. The daemon removes that sentinel
before forwarding upstream and injects the selected Provision profile's real
credentials.

This keeps Codex CLI-compatible behavior intact:

- `codex resume` and `provision resume` see the same local transcripts.
- Codex CLI continues to record sessions as `model_provider=openai`, avoiding
  resume-picker fragmentation between stock Codex CLI and Provision runs.
- Responses WebSocket traffic is tunneled through Provision; HTTP and backend
  usage requests are proxied through the same account-selection layer.
- Profile switches are refused while unpinned upstream work is active, with a
  short idle grace period before switching becomes available.

## Profiles

Import the current stock Codex CLI login as the `default` Provision profile:

```bash
provision import-default
```

Rerunning `import-default` leaves an existing profile unchanged. Use
`--overwrite` only when you intentionally want to replace the stored profile
from the current stock Codex CLI `~/.codex/auth.json`.

Capture additional ChatGPT login profiles without using Codex CLI `/logout`:

```bash
provision login work --device-auth
provision login personal
```

Switch profiles from the CLI or dashboard:

```bash
provision profiles
provision use work
provision ui
```

## Dashboard

Open the dashboard URL with:

```bash
provision ui
```

The dashboard is localhost-only and shows:

- Active profile, active requests, active tunnels, and live idle/busy state.
- All enrolled profiles and their last-known quota.
- Stacked quota bars for short-window and weekly limits, including reset times.
- Extra quota buckets when the upstream account reports them.
- Observed Codex CLI working directories and session pins.
- Light/dark mode following the system preference, with a manual toggle.

If the daemon restarts while the page is open, the page reloads so local
development and daemon upgrades do not leave stale UI code running in-place.

## Session Pins

Provision observes Codex CLI working directories when launched through
`provision`. A working directory can be pinned to a profile from the dashboard.

Pinned sessions are useful when you want one project to keep using a specific
account while other projects switch accounts. Active pinned sessions still show
in the dashboard's Requests, Tunnels, and Live indicators, but they do not block
switching for unpinned sessions.

Pins persist in Provision state. The observed session list itself is not
persisted; working directories reappear after Provision observes them again.

## Status And Quota

Codex CLI `/status` receives usage data for the active Provision profile.
Provision labels the quota section with a timestamp such as:

```text
Provision (work - updated 15:36 on 22 May)
```

When the active profile is not `default`, Provision can also append the stored
Provision `default` profile's quota as separate non-`codex` status rows. This is
the stored Provision profile named `default`; it is not necessarily the account
currently logged in through stock Codex CLI.

Quota is cached per profile. Provision refreshes politely:

- At most one upstream usage refresh per second across the daemon.
- At least once per hour per account, based on that account's last successful
  update.
- One minute after detected reset times, unless a newer refresh already happened.
- Opportunistically from WebSocket quota events and relevant response headers.

## Ports

The daemon prefers stable localhost port `4888`. If that port is unavailable,
Provision falls back to a dynamic port and records the selected port in
`~/.provision/daemon.json`.

Choose a specific port with `PROVISION_PORT` or explicit daemon startup:

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
    session-pins.json
    profiles/<name>/
      auth.json
      metadata.json
```

These files include credentials. Do not commit or sync them casually.

## Common Commands

| Command | Purpose |
| --- | --- |
| `provision` | Launch Codex CLI through the active Provision profile. |
| `provision import-default [--name <profile_name>] [--overwrite]` | Import the current stock Codex CLI `~/.codex/auth.json` as a Provision profile. Defaults to `default`; existing profiles are left unchanged unless `--overwrite` is set. |
| `provision login <profile_name> [--device-auth]` | Capture a new Codex CLI ChatGPT login into an isolated Provision profile. |
| `provision profiles` | List enrolled profiles and show which one is active. |
| `provision use <profile_name>` | Switch the active profile when unpinned proxy work is idle. |
| `provision ui [--port <port>]` | Start the daemon if needed and print the localhost dashboard URL. |
| `provision status` | Print JSON status for Provision home, daemon, active profile, profiles, and dashboard URL. |
| `provision start [--port <port>]` | Start the local proxy daemon without launching Codex CLI. |
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

- Provision targets Codex CLI. It does not currently manage desktop Codex apps.
- The dashboard is localhost-only. It is intended for a single local user, not a
  remote multi-user control plane.
- Provision keeps Codex CLI's built-in `openai` provider identity for resume
  compatibility. Native Codex CLI account identity can therefore reflect the
  stock `~/.codex/auth.json`; Provision status labels, `provision status`, and
  `~/.provision/daemon.log` show the profile actually used by the proxy.
- Quota sections are shaped from upstream usage payloads. If a profile or plan
  does not report a bucket, Provision does not invent one.
- Codex CLI still applies its normal current-working-directory filter in the
  resume picker. Use `provision resume --all` when launching from a different
  directory than the sessions you want to see.

## Roadmap

- First-class API-key profile enrollment, so users can store and switch named
  OpenAI API keys without relying on shell-level `OPENAI_API_KEY` changes.
- API-key-aware dashboard and status output when ChatGPT subscription quota does
  not apply.
- API billing and rate-limit visibility for API-key profiles if suitable
  upstream billing, usage, or limits endpoints can be integrated cleanly.
- Optional policy controls such as workspace defaults, spend guardrails, audit
  logs, and key rotation metadata.

## License

Provision is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
