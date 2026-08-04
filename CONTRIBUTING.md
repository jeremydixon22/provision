# Contributing

Provision is a local credential proxy and session control plane. Keep changes
small, preserve the native CLI workflow, and fail closed at credential or
network boundaries.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
ruff check src tests tools
ruff format --check src tests tools
mypy src/provision/paths.py src/provision/daemon_host.py \
  src/provision/daemon_logging.py src/provision/providers.py \
  src/provision/proxy_policy.py \
  src/provision/permissions.py \
  src/provision/provider_sessions.py src/provision/ui_assets.py \
  src/provision/connector.py src/provision/remote.py
coverage run -m unittest discover -s tests
coverage report
```

## Repository map

| Change | Start here |
| --- | --- |
| CLI parsing and command output | `src/provision/cli.py` |
| Process launch, PTY, and daemon lifecycle | `src/provision/launcher.py` |
| Profile persistence and file modes | `src/provision/store.py` |
| Codex authentication and client-id discovery | `src/provision/auth.py` |
| Provider registry and native profile roots | `src/provision/providers.py` |
| Provider-owned session streams | `src/provision/provider_sessions.py` |
| Dashboard HTML, CSS, and JavaScript | `src/provision/ui/` |
| Packaged dashboard assets | `src/provision/ui_assets.py` |
| Host/bind policy and log rotation | `src/provision/daemon_host.py`, `src/provision/daemon_logging.py` |
| Bounded provider permission hook payloads | `src/provision/permissions.py` |
| Proxy header, URL, and token-redaction policy | `src/provision/proxy_policy.py` |
| Generic Connector ABI and dormant remote primitives | `src/provision/connector.py`, `src/provision/remote.py` |
| Proxy, quota, and control-plane orchestration | `src/provision/daemon.py` |

The daemon is still the largest orchestration boundary. Prefer extracting a
cohesive, typed module when adding an independent domain instead of expanding
the handler further. Keep compatibility re-exports when callers already import
a public helper from `provision.daemon`.

Tests use stdlib `unittest`. Cross-domain integration coverage lives in
`tests/test_integration.py`; new focused modules should sit beside it (for
example dashboard security and daemon boundaries) so their ownership is clear.

## Dashboard and demo media

Edit `src/provision/ui/index.html`, `styles.css`, and `app.js` directly. Keep the
bootstrap object small and never render durable credentials into it. Regenerate
sanitized README media with:

```bash
python tools/render_demo_assets.py
```

Do not use real account names, paths, tokens, usage, or discussion content in
fixtures or screenshots.

## Security-sensitive changes

Add targeted tests for token validation, same-origin behavior, header stripping,
upstream URL construction, bounded payloads, and restrictive file modes. Never
make non-loopback binding implicit. Follow the private reporting guidance in
`SECURITY.md` for suspected vulnerabilities.
