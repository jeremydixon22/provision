from __future__ import annotations

import http.client
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

from .daemon import (
    DEFAULT_DAEMON_HOST,
    PROTOCOL_VERSION,
    daemon_running,
    daemon_url_host,
    health,
    project_session_sentinel,
    wait_until_running,
)
from .paths import Paths, launcher_path, source_root
from .store import Store


PROVIDER_ID = "provision"
CODEX_MODEL_COMMANDS = {"debug", "e", "exec", "fork", "resume", "review"}
CODEX_PASSTHROUGH_COMMANDS = {
    "app-server",
    "apply",
    "archive",
    "cloud",
    "completion",
    "delete",
    "doctor",
    "exec-server",
    "features",
    "help",
    "login",
    "logout",
    "mcp",
    "mcp-server",
    "plugin",
    "remote-control",
    "sandbox",
    "unarchive",
    "update",
}


def toml_string(value: str) -> str:
    return json.dumps(value)


def provider_override(port: int, host: str | None = None) -> str:
    launcher = provision_command()
    base_url = f"http://{daemon_url_host(host)}:{port}/v1"
    return (
        f"model_providers.{PROVIDER_ID}={{ "
        f"name = \"Provision\", "
        f"base_url = {toml_string(base_url)}, "
        f"wire_api = \"responses\", "
        f"supports_websockets = false, "
        f"auth = {{ command = {toml_string(launcher)}, args = [\"token\"], timeout_ms = 5000, refresh_interval_ms = 0 }} "
        f"}}"
    )


def openai_base_url_override(port: int, host: str | None = None) -> str:
    return f"openai_base_url={toml_string(f'http://{daemon_url_host(host)}:{port}/v1')}"


def chatgpt_base_url_override(port: int, proxy_token: str, host: str | None = None) -> str:
    base_url = f"http://{daemon_url_host(host)}:{port}/backend-api/provision"
    return f"chatgpt_base_url={toml_string(base_url)}"


def provision_command() -> str:
    invoked = Path(sys.argv[0])
    if invoked.exists() and os.access(invoked, os.X_OK) and invoked.name != "__main__.py":
        return str(invoked.resolve())
    repo_launcher = launcher_path()
    if repo_launcher.exists():
        return str(repo_launcher)
    found = shutil.which("provision")
    if found:
        return found
    return str(repo_launcher)


def configured_daemon_port() -> int | None:
    raw = os.environ.get("PROVISION_PORT")
    if raw is None or raw == "":
        return None
    try:
        port = int(raw)
    except ValueError:
        raise RuntimeError(f"invalid PROVISION_PORT: {raw}") from None
    if port < 0 or port > 65535:
        raise RuntimeError(f"invalid PROVISION_PORT: {raw}")
    return port


def configured_daemon_host() -> str | None:
    raw = os.environ.get("PROVISION_HOST")
    if raw is None or raw.strip() == "":
        return None
    return raw.strip()


def ensure_daemon(paths: Paths, port: int | None = None, host: str | None = None) -> dict[str, Any]:
    status = daemon_running(paths)
    specific_port = port not in (None, 0)
    requested_host = host or None
    specific_host = requested_host is not None
    if (
        status
        and status.get("provision_protocol") == PROTOCOL_VERSION
        and (not specific_port or status.get("port") == port)
        and (not specific_host or status.get("host") == requested_host)
    ):
        return status
    if status:
        stop_incompatible_daemon(status)

    env = os.environ.copy()
    src = str(source_root())
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = src if not existing else src + os.pathsep + existing
    paths.log.parent.mkdir(parents=True, exist_ok=True)
    log = paths.log.open("ab")
    argv = [sys.executable, "-m", "provision", "daemon"]
    if port is not None:
        argv.extend(["--port", str(port)])
    if requested_host is not None:
        argv.extend(["--host", requested_host])
    subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=log,
        start_new_session=True,
        env=env,
    )
    return wait_until_running(paths)


def stop_incompatible_daemon(status: dict[str, Any]) -> None:
    pid = status.get("pid")
    port = status.get("port")
    if not isinstance(pid, int):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return
    if not isinstance(port, int):
        return
    host = str(status.get("host") or DEFAULT_DAEMON_HOST)
    deadline = time.time() + 2
    while time.time() < deadline:
        if health(port, timeout=0.2, host=host) is None:
            return
        time.sleep(0.05)


def register_session(port: int, proxy_token: str, cwd: str, host: str | None = None) -> None:
    body = urllib.parse.urlencode(
        {
            "token": proxy_token,
            "cwd": cwd,
        }
    )
    conn = http.client.HTTPConnection(daemon_url_host(host), port, timeout=0.5)
    try:
        conn.request(
            "POST",
            "/api/session",
            body=body,
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        conn.getresponse().read()
    except OSError:
        return
    finally:
        conn.close()


def launch_codex(codex_args: list[str]) -> int:
    paths = Paths()
    store = Store(paths)
    store.import_default_if_available()
    store.active_profile()
    status = ensure_daemon(paths, configured_daemon_port(), configured_daemon_host())
    port = int(status["port"])
    host = str(status.get("host") or DEFAULT_DAEMON_HOST)
    proxy_token = store.proxy_token()
    cwd = os.getcwd()
    register_session(port, proxy_token, cwd, host)

    provider_args = [
        "-c",
        openai_base_url_override(port, host),
        "-c",
        chatgpt_base_url_override(port, proxy_token, host),
        "-c",
        f"model_provider={toml_string('openai')}",
    ]
    if codex_args and codex_args[0] in CODEX_MODEL_COMMANDS:
        argv = ["codex", codex_args[0], *provider_args, *codex_args[1:]]
    elif codex_args and codex_args[0] in CODEX_PASSTHROUGH_COMMANDS:
        argv = ["codex", *codex_args]
    else:
        argv = ["codex", *provider_args, *codex_args]
    env = os.environ.copy()
    env["OPENAI_PROJECT"] = project_session_sentinel(proxy_token, cwd)
    os.execvpe("codex", argv, env)
    return 127
