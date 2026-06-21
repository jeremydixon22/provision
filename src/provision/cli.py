from __future__ import annotations

import argparse
import http.client
import json
import os
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Sequence

from . import __version__
from .daemon import (
    CodexAppServerClient,
    CodexAppServerError,
    codex_app_server_schema_probe,
    codex_compatibility_payload,
    daemon_bind_address,
    daemon_running,
    daemon_url_host,
    serve,
    usage_payload_from_app_server_rate_limits_response,
)
from .launcher import configured_daemon_host, configured_daemon_port, ensure_daemon, launch_codex
from .paths import Paths, default_codex_home
from .store import Store, StoreError


def ui_url(host: object | None, port: object) -> str:
    return f"http://{daemon_url_host(str(host) if host else None)}:{port}/ui"


COMMANDS = {
    "app-server-probe",
    "daemon",
    "doctor",
    "help",
    "import-default",
    "login",
    "profiles",
    "start",
    "status",
    "stop",
    "token",
    "ui",
    "use",
    "version",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="provision",
        description="Run Codex CLI through a local profile-switching proxy and dashboard.",
    )
    parser.add_argument("--version", action="store_true", help="show Provision version")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("help", help="show Provision help")
    app_server_probe = subparsers.add_parser("app-server-probe", help="inspect Codex CLI app-server capabilities")
    app_server_probe.add_argument("--read-account", action="store_true", help="read current account usage and rate limits")

    daemon = subparsers.add_parser("daemon", help="run the local proxy daemon")
    daemon.add_argument("--port", type=int, default=None)
    daemon.add_argument("--host", default=None)

    import_default = subparsers.add_parser("import-default", help="import the current Codex CLI auth.json as a profile")
    import_default.add_argument("--name", default="default")
    import_default.add_argument("--source", type=Path, default=None)
    import_default.add_argument("--overwrite", action="store_true")

    login = subparsers.add_parser("login", help="capture a new Codex CLI login into a Provision profile")
    login.add_argument("name", metavar="profile_name")
    login.add_argument("--device-auth", action="store_true")
    login.add_argument("--overwrite", action="store_true")
    login.add_argument("--keep-capture", action="store_true")

    subparsers.add_parser("profiles", help="list enrolled profiles")
    start = subparsers.add_parser("start", help="start the local proxy daemon")
    start.add_argument("--port", type=int, default=None)
    start.add_argument("--host", default=None)
    ui = subparsers.add_parser("ui", help="start the daemon and print the web UI URL")
    ui.add_argument("--port", type=int, default=None)
    ui.add_argument("--host", default=None)

    use = subparsers.add_parser("use", help="switch the active profile when the proxy is idle")
    use.add_argument("name", metavar="profile_name")

    subparsers.add_parser("status", help="show proxy and active-profile status")
    subparsers.add_parser("stop", help="stop the local proxy daemon")
    subparsers.add_parser("token", help="print the local proxy bearer token")
    subparsers.add_parser("doctor", help="run basic local checks")
    subparsers.add_parser("version", help="show Provision version")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("-h", "--help"):
        build_parser().print_help()
        return 0
    if argv and argv[0] == "--version":
        print(__version__)
        return 0
    if argv and argv[0] not in COMMANDS:
        return launch_codex(argv)
    if not argv:
        return launch_codex([])
    if argv[0] == "help":
        build_parser().print_help()
        return 0
    parser = build_parser()
    args, remainder = parser.parse_known_args(argv)
    if args.version:
        print(__version__)
        return 0
    if remainder:
        parser.error(f"unrecognized arguments: {' '.join(remainder)}")

    paths = Paths()
    store = Store(paths)
    try:
        if args.command == "daemon":
            serve(args.port, args.host if args.host is not None else configured_daemon_host())
            return 0
        if args.command == "app-server-probe":
            return cmd_app_server_probe(args)
        if args.command == "import-default":
            return cmd_import_default(store, args)
        if args.command == "login":
            return cmd_login(store, args)
        if args.command == "profiles":
            return cmd_profiles(store)
        if args.command == "start":
            return cmd_start(
                paths,
                args.port if args.port is not None else configured_daemon_port(),
                args.host if args.host is not None else configured_daemon_host(),
            )
        if args.command == "ui":
            return cmd_ui(
                paths,
                args.port if args.port is not None else configured_daemon_port(),
                args.host if args.host is not None else configured_daemon_host(),
            )
        if args.command == "use":
            return cmd_use(store, args.name)
        if args.command == "status":
            return cmd_status(paths, store)
        if args.command == "stop":
            return cmd_stop(paths)
        if args.command == "token":
            print(store.proxy_token())
            return 0
        if args.command == "doctor":
            return cmd_doctor(paths, store)
        if args.command == "version":
            print(__version__)
            return 0
    except StoreError as exc:
        print(f"provision: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"provision: {exc}", file=sys.stderr)
        return 1

    parser.print_help()
    return 0


def cmd_import_default(store: Store, args: argparse.Namespace) -> int:
    source = args.source or (default_codex_home() / "auth.json")
    if store.profile_exists(args.name) and not args.overwrite:
        print(f"profile already exists: {args.name} (use --overwrite to replace it)")
        return 0
    metadata = store.import_auth_file(
        args.name,
        source,
        overwrite=args.overwrite,
        set_active=True,
    )
    label = metadata.get("email") or metadata.get("account_id") or metadata.get("kind")
    print(f"imported profile {args.name}: {label}")
    return 0


def cmd_login(store: Store, args: argparse.Namespace) -> int:
    if store.profile_exists(args.name) and not args.overwrite:
        raise StoreError(f"profile already exists: {args.name}")

    capture = store.paths.capture / f"{args.name}-{int(time.time())}"
    capture.mkdir(parents=True, exist_ok=False)
    capture.chmod(0o700)
    config = capture / "config.toml"
    config.write_text('cli_auth_credentials_store = "file"\n', encoding="utf-8")
    config.chmod(0o600)

    env = os.environ.copy()
    env["CODEX_HOME"] = str(capture)
    cmd = ["codex", "login"]
    if args.device_auth:
        cmd.append("--device-auth")
    result = subprocess.run(cmd, env=env)
    if result.returncode != 0:
        if not args.keep_capture:
            store.delete_capture(capture)
        return result.returncode

    auth_path = capture / "auth.json"
    metadata = store.import_auth_file(
        args.name,
        auth_path,
        overwrite=args.overwrite,
        set_active=True,
    )
    if not args.keep_capture:
        store.delete_capture(capture)
    label = metadata.get("email") or metadata.get("account_id") or metadata.get("kind")
    print(f"captured profile {args.name}: {label}")
    return 0


def cmd_profiles(store: Store) -> int:
    profiles = store.list_profiles()
    if not profiles:
        print("no profiles enrolled")
        return 1
    for profile in profiles:
        marker = "*" if profile.get("active") else " "
        name = profile.get("name") or ""
        label = profile.get("email") or profile.get("account_id") or profile.get("kind") or ""
        plan = profile.get("plan_type") or ""
        print(f"{marker} {name:16} {label} {plan}".rstrip())
    return 0


def cmd_app_server_probe(args: argparse.Namespace) -> int:
    payload: dict[str, object] = {
        "schema": codex_app_server_schema_probe(),
    }
    exit_code = 0
    if args.read_account:
        try:
            with CodexAppServerClient() as client:
                rate_limits = client.read_account_rate_limits()
                payload["account"] = {
                    "ok": True,
                    "rate_limits": rate_limits,
                    "usage": client.read_account_usage(),
                    "quota_payload": usage_payload_from_app_server_rate_limits_response(rate_limits),
                }
        except CodexAppServerError as exc:
            payload["account"] = {"ok": False, "error": str(exc)}
            exit_code = 1
    print(json.dumps(payload, indent=2))
    return exit_code


def cmd_start(paths: Paths, port: int | None = None, host: str | None = None) -> int:
    status = ensure_daemon(paths, port, host)
    bind_host = status.get("host") or host
    local_ui = ui_url(bind_host, status["port"])
    local_address = local_ui.removesuffix("/ui").removeprefix("http://")
    bind_address = daemon_bind_address(str(bind_host) if bind_host else None, status["port"])
    if bind_address == local_address:
        print(f"daemon running: pid {status['pid']} on {local_ui.removesuffix('/ui')}")
    else:
        print(f"daemon running: pid {status['pid']} bound to {bind_address}; local UI {local_ui}")
    return 0


def cmd_ui(paths: Paths, port: int | None = None, host: str | None = None) -> int:
    status = ensure_daemon(paths, port, host)
    print(ui_url(status.get("host") or host, status["port"]))
    return 0


def cmd_use(store: Store, name: str) -> int:
    paths = store.paths
    status = daemon_running(paths)
    if status:
        block_reason = status.get("switch_block_reason")
        if isinstance(block_reason, str) and block_reason:
            raise RuntimeError(f"proxy is busy; {block_reason}")
        blocking_requests = status.get("blocking_active_requests", status.get("active_requests"))
        if blocking_requests:
            raise RuntimeError("proxy is busy; switch after active requests finish")
        port = status.get("port")
        if isinstance(port, int):
            daemon_switch_profile(store, name, port, str(status.get("host") or ""))
            print(f"active profile: {name}")
            return 0
    store.set_active_profile(name)
    print(f"active profile: {name}")
    return 0


def daemon_switch_profile(store: Store, name: str, port: int, host: str | None = None) -> None:
    body = urllib.parse.urlencode(
        {
            "token": store.proxy_token(),
            "profile": name,
        }
    )
    conn = http.client.HTTPConnection(daemon_url_host(host), port, timeout=5)
    try:
        conn.request(
            "POST",
            "/api/switch",
            body=body,
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        response = conn.getresponse()
        payload = response.read()
    finally:
        conn.close()
    if response.status in (200, 303):
        return
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        data = {}
    error = data.get("error") if isinstance(data, dict) else None
    raise RuntimeError(str(error or f"daemon switch failed with HTTP {response.status}"))


def cmd_status(paths: Paths, store: Store) -> int:
    status = daemon_running(paths)
    payload = {
        "home": str(paths.home),
        "active_profile": store.active_profile(required=False),
        "codex": codex_compatibility_payload(),
        "daemon": status or {"ok": False},
        "profiles": store.list_profiles(),
        "ui": ui_url(status.get("host"), status["port"]) if status else None,
    }
    print(json.dumps(payload, indent=2))
    return 0


def cmd_stop(paths: Paths) -> int:
    status = daemon_running(paths)
    if not status:
        print("daemon is not running")
        return 0
    pid = status.get("pid")
    if not isinstance(pid, int):
        raise RuntimeError("daemon status did not include a pid")
    os.kill(pid, 15)
    print(f"stopped daemon pid {pid}")
    return 0


def cmd_doctor(paths: Paths, store: Store) -> int:
    codex = codex_compatibility_payload()
    codex_cli = codex.get("cli") if isinstance(codex.get("cli"), dict) else {}
    catalog = codex.get("model_catalog") if isinstance(codex.get("model_catalog"), dict) else {}
    checks = []
    codex_version = codex_cli.get("version")
    codex_label = f"codex on PATH ({codex_version})" if codex_version else "codex on PATH"
    checks.append((codex_label, bool(codex_cli.get("available"))))
    catalog_source = catalog.get("source") or "unknown"
    catalog_count = catalog.get("count") or 0
    catalog_label = f"Codex model catalog readable ({catalog_count} models from {catalog_source})"
    checks.append((catalog_label, catalog_source == "codex"))
    app_server = codex.get("app_server") if isinstance(codex.get("app_server"), dict) else None
    if app_server is not None:
        methods = app_server.get("methods") if isinstance(app_server.get("methods"), dict) else {}
        reset_credit_ok = bool(methods.get("rate_limit_reset_credit_consume"))
        app_server_label = "Codex app-server usage/reset-credit schema readable"
        checks.append((app_server_label, bool(app_server.get("available")) and reset_credit_ok))
        control_plane = app_server.get("control_plane") if isinstance(app_server.get("control_plane"), dict) else {}
        checks.append(
            (
                "Codex app-server read-only control-plane schema readable",
                bool(control_plane.get("read_only")),
            )
        )
    checks.append(("Provision home writable", os.access(paths.home, os.W_OK)))
    checks.append(("proxy token present", bool(store.proxy_token())))
    checks.append(("active profile present", store.active_profile(required=False) is not None))
    state = daemon_running(paths)
    checks.append(("daemon reachable", state is not None))

    failed = False
    for label, ok in checks:
        status = "ok" if ok else "fail"
        print(f"{status:4} {label}")
        failed = failed or not ok
    if state:
        print(f"ui   {ui_url(state.get('host'), state['port'])}")
    return 1 if failed else 0
