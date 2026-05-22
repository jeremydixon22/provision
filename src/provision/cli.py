from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Sequence

from . import __version__
from .daemon import daemon_running, serve
from .launcher import configured_daemon_port, ensure_daemon, launch_codex
from .paths import Paths, default_codex_home
from .store import Store, StoreError


COMMANDS = {
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
        description="Run Codex through a local profile-switching proxy.",
    )
    parser.add_argument("--version", action="store_true", help="show Provision version")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("help", help="show Provision help")
    subparsers.add_parser("daemon", help="run the local proxy daemon").add_argument("--port", type=int, default=None)

    import_default = subparsers.add_parser("import-default", help="import the current Codex auth.json as a profile")
    import_default.add_argument("--name", default="default")
    import_default.add_argument("--source", type=Path, default=None)
    import_default.add_argument("--overwrite", action="store_true")

    login = subparsers.add_parser("login", help="capture a new Codex login into a Provision profile")
    login.add_argument("name", metavar="profile_name")
    login.add_argument("--device-auth", action="store_true")
    login.add_argument("--overwrite", action="store_true")
    login.add_argument("--keep-capture", action="store_true")

    subparsers.add_parser("profiles", help="list enrolled profiles")
    start = subparsers.add_parser("start", help="start the local proxy daemon")
    start.add_argument("--port", type=int, default=None)
    ui = subparsers.add_parser("ui", help="start the daemon and print the web UI URL")
    ui.add_argument("--port", type=int, default=None)

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
            serve(args.port)
            return 0
        if args.command == "import-default":
            return cmd_import_default(store, args)
        if args.command == "login":
            return cmd_login(store, args)
        if args.command == "profiles":
            return cmd_profiles(store)
        if args.command == "start":
            return cmd_start(paths, args.port if args.port is not None else configured_daemon_port())
        if args.command == "ui":
            return cmd_ui(paths, args.port if args.port is not None else configured_daemon_port())
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


def cmd_start(paths: Paths, port: int | None = None) -> int:
    status = ensure_daemon(paths, port)
    print(f"daemon running: pid {status['pid']} on http://127.0.0.1:{status['port']}")
    return 0


def cmd_ui(paths: Paths, port: int | None = None) -> int:
    status = ensure_daemon(paths, port)
    print(f"http://127.0.0.1:{status['port']}/ui")
    return 0


def cmd_use(store: Store, name: str) -> int:
    paths = store.paths
    status = daemon_running(paths)
    if status and status.get("active_requests"):
        raise RuntimeError("proxy is busy; switch after active requests finish")
    store.set_active_profile(name)
    print(f"active profile: {name}")
    return 0


def cmd_status(paths: Paths, store: Store) -> int:
    status = daemon_running(paths)
    payload = {
        "home": str(paths.home),
        "active_profile": store.active_profile(required=False),
        "daemon": status or {"ok": False},
        "profiles": store.list_profiles(),
        "ui": f"http://127.0.0.1:{status['port']}/ui" if status else None,
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
    checks = []
    checks.append(("codex on PATH", shutil.which("codex") is not None))
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
        print(f"ui   http://127.0.0.1:{state['port']}/ui")
    return 1 if failed else 0
