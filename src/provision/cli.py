from __future__ import annotations

import argparse
import http.client
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Sequence

from . import __version__
from .auth import AuthError, codex_client_id
from .connector import LocalConnectorClient, connector_abi_payload
from .daemon import (
    CodexAppServerClient,
    CodexAppServerError,
    codex_app_server_schema_probe,
    codex_compatibility_payload,
    codex_restart_requirement,
    daemon_running,
    daemon_url_host,
    serve,
    usage_payload_from_app_server_rate_limits_response,
)
from .daemon_host import daemon_bind_address
from .launcher import (
    configured_allow_non_loopback,
    configured_daemon_host,
    configured_daemon_port,
    ensure_daemon,
    launch_native_provider,
)
from .paths import Paths, default_codex_home
from .permissions import run_permission_hook
from .providers import (
    ProviderError,
    provider_alias,
    provider_environment,
    provider_rows,
    provider_spec,
)
from .store import Store, StoreError


def ui_url(host: object | None, port: object) -> str:
    return f"http://{daemon_url_host(str(host) if host else None)}:{port}/ui"


COMMANDS = {
    "app-server-probe",
    "connector",
    "daemon",
    "doctor",
    "help",
    "import-default",
    "login",
    "permission-hook",
    "profiles",
    "provider",
    "providers",
    "remote",
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
        description="Run supported AI coding CLIs through Provision's local dashboard and profile controls.",
    )
    parser.add_argument("--version", action="store_true", help="show Provision version")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("help", help="show Provision help")
    app_server_probe = subparsers.add_parser(
        "app-server-probe", help="inspect Codex CLI app-server capabilities"
    )
    app_server_probe.add_argument(
        "--read-account",
        action="store_true",
        help="read current account usage and rate limits",
    )

    connector = subparsers.add_parser(
        "connector",
        help="inspect or explicitly enable the local generic Connector ABI socket",
    )
    connector.add_argument(
        "action",
        nargs="?",
        choices=("abi", "status", "enable", "disable"),
        default="status",
    )

    remote = subparsers.add_parser(
        "remote",
        help="manage host-local paired-device grants through the generic Connector ABI",
    )
    remote.add_argument(
        "action",
        nargs="?",
        choices=("status", "devices", "enroll", "grant", "revoke"),
        default="status",
    )
    remote.add_argument("device_id", nargs="?")
    remote.add_argument(
        "--fingerprint",
        default="",
        help="verified remote-device identity fingerprint for enrollment",
    )
    remote.add_argument(
        "--capability",
        action="append",
        default=[],
        help="capability to grant; repeat for each additional capability",
    )

    daemon = subparsers.add_parser("daemon", help="run the local proxy daemon")
    daemon.add_argument("--port", type=int, default=None)
    daemon.add_argument("--host", default=None)
    daemon.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="allow an explicitly configured non-loopback bind (unsafe without a secure boundary)",
    )

    import_default = subparsers.add_parser(
        "import-default", help="import the current Codex CLI auth.json as a profile"
    )
    import_default.add_argument("--name", default="default")
    import_default.add_argument("--source", type=Path, default=None)
    import_default.add_argument("--overwrite", action="store_true")

    login = subparsers.add_parser(
        "login", help="capture a new Codex CLI login into a Provision profile"
    )
    login.add_argument("name", metavar="profile_name")
    login.add_argument("--device-auth", action="store_true")
    login.add_argument("--overwrite", action="store_true")
    login.add_argument("--keep-capture", action="store_true")

    permission_hook = subparsers.add_parser(
        "permission-hook",
        help="internal synchronous permission bridge for managed provider sessions",
    )
    permission_hook.add_argument("--provider", choices=("codex", "claude"), required=True)

    subparsers.add_parser("profiles", help="list enrolled profiles")
    provider = subparsers.add_parser(
        "provider",
        help="list providers, choose the default, or manage a provider's native login profile",
    )
    provider.add_argument(
        "action",
        nargs="?",
        choices=("list", "show", "use", "profiles", "use-profile", "login"),
        default="show",
    )
    provider.add_argument(
        "provider",
        nargs="?",
        help="provider name (codex, claude, grok, or antigravity)",
    )
    provider.add_argument("profile", nargs="?", help="provider-native profile name")
    subparsers.add_parser("providers", help="alias for `provision provider list`")
    start = subparsers.add_parser("start", help="start the local proxy daemon")
    start.add_argument("--port", type=int, default=None)
    start.add_argument("--host", default=None)
    start.add_argument("--allow-non-loopback", action="store_true")
    ui = subparsers.add_parser("ui", help="start the daemon and print the web UI URL")
    ui.add_argument("--port", type=int, default=None)
    ui.add_argument("--host", default=None)
    ui.add_argument("--allow-non-loopback", action="store_true")
    ui.add_argument("--open", action="store_true", help="open the UI in a browser")

    use = subparsers.add_parser("use", help="switch the active profile when the proxy is idle")
    use.add_argument("name", metavar="profile_name")

    subparsers.add_parser("status", help="show proxy and active-profile status")
    subparsers.add_parser("stop", help="stop the local proxy daemon")
    subparsers.add_parser(
        "token",
        help="print the sensitive local proxy capability (do not share it)",
    )
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
    if argv:
        selected_provider = provider_alias(argv[0])
        if selected_provider:
            try:
                provider_args, profile = provider_launch_arguments(argv[1:])
                return launch_native_provider(selected_provider, provider_args, profile=profile)
            except (RuntimeError, StoreError) as exc:
                print(f"provision: {exc}", file=sys.stderr)
                return 1
    if not argv:
        try:
            return launch_default_provider([])
        except (RuntimeError, StoreError) as exc:
            print(f"provision: {exc}", file=sys.stderr)
            return 1
    command = argv[0].lower()
    if command not in COMMANDS:
        try:
            return launch_default_provider(argv)
        except (RuntimeError, StoreError) as exc:
            print(f"provision: {exc}", file=sys.stderr)
            return 1
    argv[0] = command
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

    if args.command == "permission-hook":
        return run_permission_hook(
            args.provider,
            stdin=sys.stdin,
            stdout=sys.stdout,
        )

    paths = Paths()
    store = Store(paths)
    try:
        if args.command == "daemon":
            serve(
                args.port,
                args.host if args.host is not None else configured_daemon_host(),
                allow_non_loopback=(args.allow_non_loopback or configured_allow_non_loopback()),
            )
            return 0
        if args.command == "app-server-probe":
            return cmd_app_server_probe(args)
        if args.command == "connector":
            return cmd_connector(paths, store, args)
        if args.command == "remote":
            return cmd_remote(paths, store, args)
        if args.command == "import-default":
            return cmd_import_default(store, args)
        if args.command == "login":
            return cmd_login(store, args)
        if args.command == "profiles":
            return cmd_profiles(store)
        if args.command == "provider":
            return cmd_provider(store, args)
        if args.command == "providers":
            return cmd_provider(
                store, argparse.Namespace(action="list", provider=None, profile=None)
            )
        if args.command == "start":
            return cmd_start(
                paths,
                args.port if args.port is not None else configured_daemon_port(),
                args.host if args.host is not None else configured_daemon_host(),
                allow_non_loopback=(args.allow_non_loopback or configured_allow_non_loopback()),
            )
        if args.command == "ui":
            return cmd_ui(
                paths,
                args.port if args.port is not None else configured_daemon_port(),
                args.host if args.host is not None else configured_daemon_host(),
                allow_non_loopback=(args.allow_non_loopback or configured_allow_non_loopback()),
                open_browser=args.open,
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


def provider_launch_arguments(argv: Sequence[str]) -> tuple[list[str], str | None]:
    """Strip Provision's explicit provider-profile flag from vendor arguments."""
    forwarded: list[str] = []
    profile: str | None = None
    index = 0
    while index < len(argv):
        value = str(argv[index])
        if value == "--provision-profile":
            if index + 1 >= len(argv):
                raise RuntimeError("--provision-profile requires a profile name")
            if profile is not None:
                raise RuntimeError("--provision-profile may be supplied only once")
            profile = str(argv[index + 1])
            index += 2
            continue
        if value.startswith("--provision-profile="):
            if profile is not None:
                raise RuntimeError("--provision-profile may be supplied only once")
            profile = value.partition("=")[2]
            if not profile:
                raise RuntimeError("--provision-profile requires a profile name")
            index += 1
            continue
        forwarded.append(value)
        index += 1
    return forwarded, profile


def launch_default_provider(argv: list[str]) -> int:
    store = Store(Paths())
    return launch_native_provider(store.default_provider(), argv)


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


def cmd_provider(store: Store, args: argparse.Namespace) -> int:
    action = str(getattr(args, "action", "show") or "show")
    provider_value = str(getattr(args, "provider", "") or "")
    profile = str(getattr(args, "profile", "") or "")

    if action == "list":
        default = store.default_provider()
        for spec in provider_rows():
            marker = "*" if spec.name == default else " "
            installed = shutil.which(spec.executable) is not None
            profile_status = (
                "managed profiles" if spec.supports_managed_profiles else "native profile only"
            )
            print(
                f"{marker} {spec.name:12} {spec.executable:8} {'installed' if installed else 'not found':9} {profile_status}"
            )
        return 0

    if action == "show":
        if provider_value:
            try:
                spec = provider_spec(provider_value)
            except ProviderError as exc:
                raise StoreError(str(exc)) from exc
            active_profile = store.active_provider_profile(spec.name)
            print(
                json.dumps(
                    {
                        "provider": spec.name,
                        "executable": spec.executable,
                        "installed": shutil.which(spec.executable) is not None,
                        "default": store.default_provider() == spec.name,
                        "managed_profiles": spec.supports_managed_profiles,
                        "active_profile": active_profile,
                    },
                    indent=2,
                )
            )
            return 0
        print(store.default_provider())
        return 0

    if action == "use":
        if not provider_value or profile:
            raise StoreError("usage: provision provider use <provider>")
        print(f"default provider: {store.set_default_provider(provider_value)}")
        return 0

    if action == "profiles":
        if not provider_value or profile:
            raise StoreError("usage: provision provider profiles <provider>")
        try:
            spec = provider_spec(provider_value)
        except ProviderError as exc:
            raise StoreError(str(exc)) from exc
        if not spec.supports_managed_profiles:
            print(
                f"{spec.name} has no verified Provision-managed profile root; use its native login."
            )
            return 0
        active = store.active_provider_profile(spec.name)
        names = store.provider_profile_names(spec.name)
        if not names:
            print(
                f"no {spec.name} profiles enrolled; run `provision provider login {spec.name} <name>`"
            )
            return 1
        for name in names:
            print(f"{'*' if name == active else ' '} {name}")
        return 0

    if action == "use-profile":
        if not provider_value or not profile:
            raise StoreError("usage: provision provider use-profile <provider> <profile>")
        try:
            spec = provider_spec(provider_value)
        except ProviderError as exc:
            raise StoreError(str(exc)) from exc
        store.set_active_provider_profile(spec.name, profile)
        print(f"active {spec.name} profile: {profile}")
        return 0

    if action == "login":
        if not provider_value or not profile:
            raise StoreError("usage: provision provider login <provider> <profile>")
        try:
            spec = provider_spec(provider_value)
        except ProviderError as exc:
            raise StoreError(str(exc)) from exc
        if not spec.supports_managed_profiles:
            raise StoreError(
                f"{spec.name} does not yet have a verified Provision-managed profile root; use its native login"
            )
        executable = shutil.which(spec.executable)
        if not executable:
            raise StoreError(
                f"{spec.name} CLI is not installed or not on PATH (expected `{spec.executable}`)"
            )
        root = store.ensure_provider_profile(spec.name, profile, set_active=False)
        env = os.environ.copy()
        try:
            env.update(provider_environment(store.paths.home, spec.name, profile))
        except ProviderError as exc:
            raise StoreError(str(exc)) from exc
        result = subprocess.run([executable, *spec.login_args], env=env, check=False)
        if result.returncode == 0:
            store.set_active_provider_profile(spec.name, profile)
            print(f"active {spec.name} profile: {profile} ({root})")
        return result.returncode

    raise StoreError(f"unsupported provider action: {action}")


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
                    "quota_payload": usage_payload_from_app_server_rate_limits_response(
                        rate_limits
                    ),
                }
        except CodexAppServerError as exc:
            payload["account"] = {"ok": False, "error": str(exc)}
            exit_code = 1
    print(json.dumps(payload, indent=2))
    return exit_code


def connector_daemon_action(
    store: Store,
    action: str,
    port: int,
    host: str | None = None,
) -> dict[str, object]:
    body = urllib.parse.urlencode({"token": store.proxy_token(), "action": action})
    conn = http.client.HTTPConnection(daemon_url_host(host), port, timeout=5)
    try:
        conn.request(
            "POST",
            "/api/connector",
            body=body,
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        response = conn.getresponse()
        payload = response.read()
    finally:
        conn.close()
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        data = {}
    if response.status != 200 or not isinstance(data, dict) or not data.get("ok"):
        error = data.get("error") if isinstance(data, dict) else None
        raise RuntimeError(str(error or f"connector control failed with HTTP {response.status}"))
    connector = data.get("connector")
    return connector if isinstance(connector, dict) else {}


def cmd_connector(paths: Paths, store: Store, args: argparse.Namespace) -> int:
    action = str(args.action or "status")
    if action == "abi":
        print(json.dumps(connector_abi_payload(), indent=2))
        return 0

    status = daemon_running(paths)
    if action == "enable":
        status = ensure_daemon(paths, configured_daemon_port(), configured_daemon_host())
    if not status:
        print(json.dumps({"enabled": False, "reason": "daemon is not running"}, indent=2))
        return 1 if action == "status" else 0
    port = status.get("port")
    if not isinstance(port, int):
        raise RuntimeError("daemon status did not include a port")
    connector = connector_daemon_action(store, action, port, str(status.get("host") or ""))
    print(json.dumps(connector, indent=2))
    return 0


def remote_admin_request(
    paths: Paths, store: Store, request: dict[str, object]
) -> dict[str, object]:
    """Send one host-local device-management operation through Connector ABI."""
    status = ensure_daemon(paths, configured_daemon_port(), configured_daemon_host())
    port = status.get("port")
    if not isinstance(port, int):
        raise RuntimeError("daemon status did not include a port")
    connector = connector_daemon_action(store, "enable", port, str(status.get("host") or ""))
    lanes = connector.get("lanes") if isinstance(connector, dict) else None
    if not isinstance(lanes, list) or "provision.remote-admin/v1" not in lanes:
        raise RuntimeError(
            "the running Provision daemon does not support host-local remote device management; "
            "restart it after updating Provision"
        )
    with LocalConnectorClient(
        paths.connector_socket,
        store.connector_token(),
        connector_id="provision-remote-cli",
        lanes=["provision.remote-admin/v1"],
    ) as client:
        response = client.request(
            link_id="provision-local-admin",
            lane="provision.remote-admin/v1",
            payload=json.dumps(request, separators=(",", ":")).encode("utf-8"),
            message_id="remote-admin-request",
        )
    if response is None:
        raise RuntimeError("remote device management returned no response")
    try:
        payload = json.loads(response.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("invalid remote device management response") from exc
    if not isinstance(payload, dict) or not payload.get("ok"):
        error = payload.get("error") if isinstance(payload, dict) else None
        raise RuntimeError(str(error or "remote device management failed"))
    result = payload.get("result")
    return result if isinstance(result, dict) else {}


def cmd_remote(paths: Paths, store: Store, args: argparse.Namespace) -> int:
    action = str(args.action or "status")
    if action == "status":
        status = daemon_running(paths)
        if not status:
            print(json.dumps({"enabled": False, "reason": "daemon is not running"}, indent=2))
            return 1
        port = status.get("port")
        if not isinstance(port, int):
            raise RuntimeError("daemon status did not include a port")
        connector = connector_daemon_action(store, "status", port, str(status.get("host") or ""))
        print(json.dumps({"daemon": True, "connector": connector}, indent=2))
        return 0

    device_id = str(args.device_id or "")
    if action == "devices":
        result = remote_admin_request(paths, store, {"operation": "device_list"})
    elif action == "enroll":
        fingerprint = str(args.fingerprint or "")
        if not device_id or not fingerprint:
            raise RuntimeError("remote enrollment requires a device ID and --fingerprint")
        result = remote_admin_request(
            paths,
            store,
            {
                "operation": "device_enroll",
                "device_id": device_id,
                "identity_fingerprint": fingerprint,
            },
        )
    elif action == "grant":
        requested = [str(capability) for capability in args.capability if str(capability)]
        if not device_id or not requested:
            raise RuntimeError("remote grant requires a device ID and at least one --capability")
        listed = remote_admin_request(paths, store, {"operation": "device_list"})
        devices = listed.get("devices")
        current = (
            next(
                (
                    item
                    for item in devices
                    if isinstance(item, dict) and item.get("device_id") == device_id
                ),
                None,
            )
            if isinstance(devices, list)
            else None
        )
        if not isinstance(current, dict):
            raise RuntimeError("unknown remote device")
        existing = current.get("capabilities")
        capabilities = sorted(
            {
                *(
                    (str(capability) for capability in existing if isinstance(capability, str))
                    if isinstance(existing, list)
                    else ()
                ),
                *requested,
            }
        )
        result = remote_admin_request(
            paths,
            store,
            {
                "operation": "device_set_capabilities",
                "device_id": device_id,
                "capabilities": capabilities,
            },
        )
    elif action == "revoke":
        if not device_id:
            raise RuntimeError("remote revoke requires a device ID")
        result = remote_admin_request(
            paths, store, {"operation": "device_revoke", "device_id": device_id}
        )
    else:
        raise RuntimeError("unsupported remote command")
    print(json.dumps(result, indent=2))
    return 0


def cmd_start(
    paths: Paths,
    port: int | None = None,
    host: str | None = None,
    *,
    allow_non_loopback: bool = False,
) -> int:
    status = ensure_daemon(paths, port, host, allow_non_loopback=allow_non_loopback)
    bind_host = status.get("host") or host
    local_ui = ui_url(bind_host, status["port"])
    local_address = local_ui.removesuffix("/ui").removeprefix("http://")
    bind_address = daemon_bind_address(str(bind_host) if bind_host else None, status["port"])
    if bind_address == local_address:
        print(f"daemon running: pid {status['pid']} on {local_ui.removesuffix('/ui')}")
    else:
        print(f"daemon running: pid {status['pid']} bound to {bind_address}; local UI {local_ui}")
    return 0


def cmd_ui(
    paths: Paths,
    port: int | None = None,
    host: str | None = None,
    *,
    allow_non_loopback: bool = False,
    open_browser: bool = False,
) -> int:
    status = ensure_daemon(paths, port, host, allow_non_loopback=allow_non_loopback)
    url = ui_url(status.get("host") or host, status["port"])
    print(url)
    if open_browser:
        webbrowser.open(url)
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
    codex = codex_compatibility_payload()
    daemon_codex = (
        status.get("codex")
        if isinstance(status, dict) and isinstance(status.get("codex"), dict)
        else {}
    )
    daemon_restart = (
        daemon_codex.get("restart_required")
        if isinstance(daemon_codex.get("restart_required"), dict)
        else {"required": False}
    )
    daemon_cli = daemon_codex.get("cli") if isinstance(daemon_codex.get("cli"), dict) else {}
    current_cli = codex.get("cli") if isinstance(codex.get("cli"), dict) else {}
    if not daemon_restart.get("required") and daemon_cli:
        daemon_restart = codex_restart_requirement(daemon_cli, current_cli)
    payload = {
        "home": str(paths.home),
        "default_provider": store.default_provider(),
        "active_profile": store.active_profile(required=False),
        "codex": codex,
        "daemon": status or {"ok": False},
        "daemon_restart_required": daemon_restart,
        "profiles": store.list_profiles(),
        "provider_clients": [
            {
                "provider": spec.name,
                "executable": spec.executable,
                "installed": shutil.which(spec.executable) is not None,
                "managed_profiles": spec.supports_managed_profiles,
                "active_profile": store.active_provider_profile(spec.name),
            }
            for spec in provider_rows()
        ],
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
    default_provider = store.default_provider()
    default_spec = provider_spec(default_provider)
    checks: list[tuple[str, bool, bool]] = []
    if default_provider != "codex":
        checks.append(
            (
                f"default provider {default_spec.name} on PATH ({default_spec.executable})",
                shutil.which(default_spec.executable) is not None,
                True,
            )
        )
    codex_version = codex_cli.get("version")
    codex_label = f"codex on PATH ({codex_version})" if codex_version else "codex on PATH"
    checks.append((codex_label, bool(codex_cli.get("available")), default_provider == "codex"))
    client_id_error = ""
    client_id_ok = False
    if codex_cli.get("available"):
        try:
            client_id_ok = bool(codex_client_id())
        except AuthError as exc:
            client_id_error = str(exc)
    client_id_label = "Codex OAuth client-id discovery"
    if client_id_error:
        client_id_label += f" ({client_id_error})"
    checks.append((client_id_label, client_id_ok, default_provider == "codex"))
    catalog_source = catalog.get("source") or "unknown"
    catalog_count = catalog.get("count") or 0
    catalog_label = f"Codex model catalog readable ({catalog_count} models from {catalog_source})"
    checks.append((catalog_label, catalog_source == "codex", default_provider == "codex"))
    app_server = codex.get("app_server") if isinstance(codex.get("app_server"), dict) else None
    if app_server is not None:
        methods = app_server.get("methods") if isinstance(app_server.get("methods"), dict) else {}
        reset_credit_ok = bool(methods.get("rate_limit_reset_credit_consume"))
        app_server_label = "Codex app-server usage/reset-credit schema readable"
        checks.append(
            (
                app_server_label,
                bool(app_server.get("available")) and reset_credit_ok,
                default_provider == "codex",
            )
        )
        control_plane = (
            app_server.get("control_plane")
            if isinstance(app_server.get("control_plane"), dict)
            else {}
        )
        checks.append(
            (
                "Codex app-server read-only control-plane schema readable",
                bool(control_plane.get("read_only")),
                default_provider == "codex",
            )
        )
    checks.append(("Provision home writable", os.access(paths.home, os.W_OK), True))
    checks.append(("proxy token present", bool(store.proxy_token()), True))
    checks.append(
        (
            "active Codex profile present",
            store.active_profile(required=False) is not None,
            default_provider == "codex",
        )
    )
    state = daemon_running(paths)
    checks.append(("daemon reachable", state is not None, True))
    daemon_codex = (
        state.get("codex")
        if isinstance(state, dict) and isinstance(state.get("codex"), dict)
        else {}
    )
    restart_state = daemon_codex.get("restart_required") if isinstance(daemon_codex, dict) else None
    if not isinstance(restart_state, dict) or not restart_state.get("required"):
        daemon_cli = daemon_codex.get("cli") if isinstance(daemon_codex.get("cli"), dict) else {}
        restart_state = (
            codex_restart_requirement(daemon_cli, codex_cli) if daemon_cli else restart_state
        )
    if isinstance(restart_state, dict) and restart_state.get("required"):
        checks.append(
            (
                str(restart_state.get("reason") or "Provision daemon restart required"),
                False,
                default_provider == "codex",
            )
        )

    failed = False
    for label, ok, required in checks:
        status = "ok" if ok else ("fail" if required else "warn")
        print(f"{status:4} {label}")
        failed = failed or (required and not ok)
    if state:
        print(f"ui   {ui_url(state.get('host'), state['port'])}")
    return 1 if failed else 0
