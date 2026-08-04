from __future__ import annotations

import base64
import http.client
import json
import os
import select
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any

if os.name == "posix":
    import fcntl
    import pty
    import termios
    import tty
else:
    fcntl = None  # type: ignore[assignment]
    pty = None  # type: ignore[assignment]
    termios = None  # type: ignore[assignment]
    tty = None  # type: ignore[assignment]

from .daemon import (
    DEFAULT_DAEMON_HOST,
    PROTOCOL_VERSION,
    bridge_codex_history_into_app_home,
    daemon_host_is_loopback,
    daemon_running,
    daemon_url_host,
    health,
    project_session_sentinel,
    wait_until_running,
)
from .daemon_logging import (
    DAEMON_LOG_BACKUP_COUNT,
    DAEMON_LOG_MAX_BYTES,
    rotate_daemon_log,
)
from .paths import Paths, default_codex_home, launcher_path, source_root
from .permissions import PERMISSION_CONTROL_MAX_BYTES, PERMISSION_HOOK_SOCKET_ENV
from .providers import ProviderError, provider_environment, provider_spec
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
CODEX_PTY_BYPASS_COMMANDS = CODEX_PASSTHROUGH_COMMANDS | {"e", "exec"}
LAUNCHER_SESSION_HEARTBEAT_SECONDS = 5.0
PTY_TERMINAL_CAPTURE_MAX_BYTES = 128 * 1024
PTY_TERMINAL_SNAPSHOT_MAX_BYTES = 16 * 1024
PERMISSION_BRIDGE_HTTP_TIMEOUT_SECONDS = 70.0


class TerminalCapture:
    """A bounded, in-memory tail of a Provision-owned terminal stream."""

    def __init__(self, limit: int = PTY_TERMINAL_CAPTURE_MAX_BYTES) -> None:
        self.limit = limit
        self._data = bytearray()
        self._dropped = False
        self._lock = threading.Lock()

    def append(self, data: bytes) -> None:
        if not data:
            return
        with self._lock:
            self._data.extend(data)
            if len(self._data) > self.limit:
                del self._data[: len(self._data) - self.limit]
                self._dropped = True

    def snapshot(self, limit: int = PTY_TERMINAL_SNAPSHOT_MAX_BYTES) -> tuple[bytes, bool]:
        with self._lock:
            data = bytes(self._data[-limit:])
            truncated = self._dropped or len(self._data) > len(data)
        return data, truncated


def toml_string(value: str) -> str:
    return json.dumps(value)


def provider_override(port: int, host: str | None = None) -> str:
    launcher = provision_command()
    base_url = f"http://{daemon_url_host(host)}:{port}/v1"
    return (
        f"model_providers.{PROVIDER_ID}={{ "
        f'name = "Provision", '
        f"base_url = {toml_string(base_url)}, "
        f'wire_api = "responses", '
        f"supports_websockets = false, "
        f'auth = {{ command = {toml_string(launcher)}, args = ["token"], timeout_ms = 5000, refresh_interval_ms = 0 }} '
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


def configured_allow_non_loopback() -> bool:
    return os.environ.get("PROVISION_ALLOW_NON_LOOPBACK", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def ensure_daemon(
    paths: Paths,
    port: int | None = None,
    host: str | None = None,
    *,
    allow_non_loopback: bool | None = None,
) -> dict[str, Any]:
    if allow_non_loopback is None:
        allow_non_loopback = configured_allow_non_loopback()
    status = daemon_running(paths)
    specific_port = port not in (None, 0)
    requested_host = host or None
    if requested_host and not daemon_host_is_loopback(requested_host) and not allow_non_loopback:
        raise RuntimeError(
            f"refusing non-loopback daemon bind {requested_host!r}; "
            "pass --allow-non-loopback or set PROVISION_ALLOW_NON_LOOPBACK=1 only behind "
            "an authenticated, encrypted boundary"
        )
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
    rotate_daemon_log(
        paths.log,
        max_bytes=DAEMON_LOG_MAX_BYTES,
        backup_count=DAEMON_LOG_BACKUP_COUNT,
    )
    env["PROVISION_DAEMON_LOG"] = str(paths.log)
    argv = [sys.executable, "-m", "provision", "daemon"]
    if port is not None:
        argv.extend(["--port", str(port)])
    if requested_host is not None:
        argv.extend(["--host", requested_host])
    if allow_non_loopback:
        argv.append("--allow-non-loopback")
    # Popen duplicates the descriptor for the daemon. Closing the parent's copy
    # immediately avoids retaining a log descriptor for the caller's lifetime.
    with paths.log.open("ab") as log:
        paths.log.chmod(0o600)
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


def register_session(
    port: int,
    proxy_token: str,
    cwd: str,
    host: str | None = None,
    *,
    session_key: str | None = None,
    control_path: str | None = None,
    launcher_pid: int | None = None,
    pty_managed: bool = False,
    provider: str = "codex",
    provider_profile: str | None = None,
    provider_pid: int | None = None,
    provider_state_root: str | None = None,
    permission_bridge: str | None = None,
) -> None:
    fields: dict[str, str] = {
        "token": proxy_token,
        "cwd": cwd,
        "provider": provider,
    }
    if session_key:
        fields["session_key"] = session_key
    if control_path:
        fields["control_path"] = control_path
    if launcher_pid is not None:
        fields["launcher_pid"] = str(launcher_pid)
    if pty_managed:
        fields["pty_managed"] = "1"
    if provider_profile:
        fields["provider_profile"] = provider_profile
    if provider_pid is not None:
        fields["provider_pid"] = str(provider_pid)
    if provider_state_root:
        fields["provider_state_root"] = provider_state_root
    if permission_bridge:
        fields["permission_bridge"] = permission_bridge
    body = urllib.parse.urlencode(fields)
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


def register_pty_session(
    port: int,
    proxy_token: str,
    cwd: str,
    host: str | None,
    *,
    session_key: str | None,
    control_path: Path,
    provider: str = "codex",
    provider_profile: str | None = None,
    provider_pid: int | None = None,
    provider_state_root: str | None = None,
    permission_bridge: str | None = None,
) -> None:
    register_session(
        port,
        proxy_token,
        cwd,
        host,
        session_key=session_key,
        control_path=str(control_path),
        launcher_pid=os.getpid(),
        pty_managed=True,
        provider=provider,
        provider_profile=provider_profile,
        provider_pid=provider_pid,
        provider_state_root=provider_state_root,
        permission_bridge=permission_bridge,
    )


def should_use_pty(
    command_args: list[str],
    *,
    bypass_commands: tuple[str, ...] = (),
    bypass_options: tuple[str, ...] = (),
) -> bool:
    if os.environ.get("PROVISION_DISABLE_PTY"):
        return False
    if os.name != "posix":
        return False
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return False
    if command_args and command_args[0].lower() in {
        "-h",
        "--help",
        "-v",
        "--version",
        "help",
        "version",
    }:
        return False
    if command_args and command_args[0].lower() in set(bypass_commands):
        return False
    option_set = set(bypass_options)
    if any(argument.split("=", 1)[0].lower() in option_set for argument in command_args):
        return False
    return True


def launcher_control_path(paths: Paths) -> Path:
    paths.ensure_base()
    return paths.launchers / f"provision-{os.getpid()}-{uuid.uuid4().hex}.sock"


def terminal_size(fd: int) -> bytes:
    try:
        return fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\0" * 8)
    except OSError:
        return struct.pack("HHHH", 24, 80, 0, 0)


def resize_pty(master_fd: int, stdin_fd: int, child_pid: int) -> None:
    try:
        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, terminal_size(stdin_fd))
        os.kill(child_pid, signal.SIGWINCH)
    except OSError:
        return


def encode_terminal_prompt(text: str) -> bytes:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return ("\x1b[200~" + normalized + "\x1b[201~\r").encode("utf-8")


def permission_hook_command(provider: str) -> str:
    return shlex.join([provision_command(), "permission-hook", "--provider", provider])


def provider_permission_bridge_argv(provider: str, argv: list[str]) -> tuple[list[str], str | None]:
    """Add a session-only native hook without editing vendor configuration."""
    if provider != "claude":
        return argv, None
    if any(argument == "--settings" or argument.startswith("--settings=") for argument in argv[1:]):
        # Replacing an explicit settings overlay could discard user policy.
        return argv, None
    settings = {
        "hooks": {
            "PermissionRequest": [
                {
                    "matcher": "",
                    "hooks": [
                        {
                            "type": "command",
                            "command": permission_hook_command(provider),
                            "timeout": 65,
                            "statusMessage": "Waiting for Provision approval",
                        }
                    ],
                }
            ]
        }
    }
    return [
        argv[0],
        "--settings",
        json.dumps(settings, separators=(",", ":")),
        *argv[1:],
    ], "claude-permission-hook-v1"


def forward_permission_request(
    *,
    port: int,
    host: str,
    proxy_token: str,
    session_key: str,
    provider: str,
    request: dict[str, Any],
) -> dict[str, Any]:
    body = json.dumps(
        {
            "token": proxy_token,
            "session_key": session_key,
            "provider": provider,
            "request": request,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    if len(body) > PERMISSION_CONTROL_MAX_BYTES:
        return {"ok": True, "decision": "terminal"}
    connection = http.client.HTTPConnection(
        daemon_url_host(host),
        port,
        timeout=PERMISSION_BRIDGE_HTTP_TIMEOUT_SECONDS,
    )
    try:
        connection.request(
            "POST",
            "/api/permission-request",
            body=body,
            headers={"content-type": "application/json"},
        )
        response = connection.getresponse()
        raw = response.read(PERMISSION_CONTROL_MAX_BYTES + 1)
        if response.status != 200 or len(raw) > PERMISSION_CONTROL_MAX_BYTES:
            return {"ok": True, "decision": "terminal"}
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {"ok": True, "decision": "terminal"}
    finally:
        connection.close()
    return value if isinstance(value, dict) else {"ok": True, "decision": "terminal"}


def handle_control_connection(
    conn: socket.socket,
    *,
    master_fd: int,
    capture: TerminalCapture | None,
    port: int,
    host: str,
    proxy_token: str,
    session_key: str,
    provider: str,
) -> None:
    with conn:
        try:
            raw_buffer = bytearray()
            while len(raw_buffer) <= PERMISSION_CONTROL_MAX_BYTES:
                chunk = conn.recv(min(8192, PERMISSION_CONTROL_MAX_BYTES + 1 - len(raw_buffer)))
                if not chunk:
                    break
                raw_buffer.extend(chunk)
                candidate = bytes(raw_buffer).split(b"\n", 1)[0]
                if b"\n" in raw_buffer:
                    break
                try:
                    json.loads(candidate.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                break
            raw = bytes(raw_buffer)
            if len(raw) > PERMISSION_CONTROL_MAX_BYTES:
                conn.sendall(b'{"ok":false,"error":"control message too large"}\n')
                return
            payload = json.loads(raw.split(b"\n", 1)[0].decode("utf-8"))
            if not isinstance(payload, dict):
                conn.sendall(b'{"ok":false,"error":"unsupported action"}\n')
                return
            action = payload.get("action")
            if action == "permission_request":
                request = payload.get("request")
                if not isinstance(request, dict):
                    conn.sendall(b'{"ok":true,"decision":"terminal"}\n')
                    return
                response = forward_permission_request(
                    port=port,
                    host=host,
                    proxy_token=proxy_token,
                    session_key=session_key,
                    provider=provider,
                    request=request,
                )
                conn.sendall(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n")
                return
            if action == "terminal_snapshot":
                if capture is None:
                    conn.sendall(b'{"ok":false,"error":"terminal capture unavailable"}\n')
                    return
                output, truncated = capture.snapshot()
                response = {
                    "ok": True,
                    "encoding": "base64",
                    "output": base64.b64encode(output).decode("ascii"),
                    "truncated": truncated,
                }
                conn.sendall(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n")
                return
            if action == "send_escape":
                os.write(master_fd, b"\x1b")
                conn.sendall(b'{"ok":true}\n')
                return
            if action != "send_text":
                conn.sendall(b'{"ok":false,"error":"unsupported action"}\n')
                return
            text = payload.get("text")
            if not isinstance(text, str) or not text.strip():
                conn.sendall(b'{"ok":false,"error":"empty text"}\n')
                return
            os.write(master_fd, encode_terminal_prompt(text))
            conn.sendall(b'{"ok":true}\n')
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            try:
                conn.sendall(json.dumps({"ok": False, "error": str(exc)}).encode("utf-8") + b"\n")
            except OSError:
                pass


def control_server(
    control_path: Path,
    master_fd: int,
    stop: threading.Event,
    capture: TerminalCapture | None = None,
    *,
    port: int,
    host: str,
    proxy_token: str,
    session_key: str,
    provider: str,
) -> None:
    try:
        if control_path.exists():
            control_path.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(control_path))
        control_path.chmod(0o600)
        server.listen(8)
        server.settimeout(0.2)
    except OSError:
        return
    try:
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=handle_control_connection,
                kwargs={
                    "conn": conn,
                    "master_fd": master_fd,
                    "capture": capture,
                    "port": port,
                    "host": host,
                    "proxy_token": proxy_token,
                    "session_key": session_key,
                    "provider": provider,
                },
                name="provision-pty-control-client",
                daemon=True,
            ).start()
    finally:
        server.close()
        try:
            control_path.unlink()
        except OSError:
            pass


def wait_status_to_exit_code(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 1


def run_managed_pty(
    executable: str,
    argv: list[str],
    env: dict[str, str],
    *,
    control_path: Path,
    port: int,
    proxy_token: str,
    cwd: str,
    host: str,
    session_key: str | None = None,
    provider: str = "codex",
    provider_profile: str | None = None,
    provider_state_root: str | None = None,
) -> int:
    stdin_fd = sys.stdin.fileno()
    stdout_fd = sys.stdout.fileno()
    argv, permission_bridge = provider_permission_bridge_argv(provider, argv)
    if permission_bridge:
        permission_bridge = f"{permission_bridge}:{uuid.uuid4().hex}"
    child_env = dict(env)
    if permission_bridge:
        child_env[PERMISSION_HOOK_SOCKET_ENV] = str(control_path)
    child_pid, master_fd = pty.fork()
    if child_pid == 0:
        os.execvpe(executable, argv, child_env)

    stop = threading.Event()
    capture = TerminalCapture()
    control_thread = threading.Thread(
        target=control_server,
        args=(control_path, master_fd, stop, capture),
        kwargs={
            "port": port,
            "host": host,
            "proxy_token": proxy_token,
            "session_key": session_key or cwd,
            "provider": provider,
        },
        name="provision-pty-control",
        daemon=True,
    )
    control_thread.start()
    deadline = time.monotonic() + 0.5
    while not control_path.exists() and time.monotonic() < deadline and not stop.is_set():
        time.sleep(0.01)
    register_pty_session(
        port,
        proxy_token,
        cwd,
        host,
        session_key=session_key,
        control_path=control_path,
        provider=provider,
        provider_profile=provider_profile,
        provider_pid=child_pid,
        provider_state_root=provider_state_root,
        permission_bridge=permission_bridge,
    )

    old_attrs = termios.tcgetattr(stdin_fd)
    old_winch = signal.getsignal(signal.SIGWINCH)

    def on_winch(_signum: int, _frame: object) -> None:
        resize_pty(master_fd, stdin_fd, child_pid)

    try:
        tty.setraw(stdin_fd)
        signal.signal(signal.SIGWINCH, on_winch)
        resize_pty(master_fd, stdin_fd, child_pid)
        next_heartbeat = time.monotonic() + LAUNCHER_SESSION_HEARTBEAT_SECONDS
        while True:
            try:
                timeout = max(0.0, min(0.5, next_heartbeat - time.monotonic()))
                readable, _, _ = select.select([stdin_fd, master_fd], [], [], timeout)
            except OSError:
                break
            now = time.monotonic()
            if now >= next_heartbeat:
                if control_path.exists():
                    register_pty_session(
                        port,
                        proxy_token,
                        cwd,
                        host,
                        session_key=session_key,
                        control_path=control_path,
                        provider=provider,
                        provider_profile=provider_profile,
                        provider_pid=child_pid,
                        provider_state_root=provider_state_root,
                        permission_bridge=permission_bridge,
                    )
                next_heartbeat = now + LAUNCHER_SESSION_HEARTBEAT_SECONDS
            if not readable:
                continue
            if stdin_fd in readable:
                try:
                    data = os.read(stdin_fd, 4096)
                except OSError:
                    data = b""
                if not data:
                    break
                os.write(master_fd, data)
            if master_fd in readable:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                capture.append(data)
                os.write(stdout_fd, data)
    finally:
        stop.set()
        try:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_attrs)
        except OSError:
            pass
        try:
            signal.signal(signal.SIGWINCH, old_winch)
        except (OSError, TypeError, ValueError):
            pass
        try:
            os.close(master_fd)
        except OSError:
            pass
        try:
            control_path.unlink()
        except OSError:
            pass

    _, status = os.waitpid(child_pid, 0)
    return wait_status_to_exit_code(status)


def run_codex_pty(
    argv: list[str],
    env: dict[str, str],
    *,
    control_path: Path,
    port: int,
    proxy_token: str,
    cwd: str,
    host: str,
    session_key: str | None = None,
) -> int:
    """Backward-compatible Codex wrapper around the generic managed PTY."""
    return run_managed_pty(
        "codex",
        argv,
        env,
        control_path=control_path,
        port=port,
        proxy_token=proxy_token,
        cwd=cwd,
        host=host,
        session_key=session_key,
        provider="codex",
    )


def launch_codex(codex_args: list[str]) -> int:
    paths = Paths()
    store = Store(paths)
    store.import_default_if_available()
    active_profile = store.active_profile()
    status = ensure_daemon(paths, configured_daemon_port(), configured_daemon_host())
    port = int(status["port"])
    host = str(status.get("host") or DEFAULT_DAEMON_HOST)
    proxy_token = store.proxy_token()
    cwd = os.getcwd()
    session_key = os.environ.get("PROVISION_SESSION_KEY") or None

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
    env["OPENAI_PROJECT"] = project_session_sentinel(proxy_token, cwd, session_key=session_key)
    if should_use_pty(codex_args, bypass_commands=tuple(CODEX_PTY_BYPASS_COMMANDS)):
        return run_codex_pty(
            argv,
            env,
            control_path=launcher_control_path(paths),
            port=port,
            proxy_token=proxy_token,
            cwd=cwd,
            host=host,
            session_key=session_key,
        )
    register_session(port, proxy_token, cwd, host, session_key=session_key)
    if codex_args and codex_args[0] in CODEX_PASSTHROUGH_COMMANDS:
        return run_profiled_passthrough_codex(
            store,
            str(active_profile),
            argv,
            env,
            command=codex_args[0],
        )
    os.execvpe("codex", argv, env)
    return 127


def launch_native_provider(
    provider: str, provider_args: list[str], *, profile: str | None = None
) -> int:
    """Launch a non-Codex vendor CLI without proxying its upstream traffic.

    A terminal session Provision launches is owned through the same local PTY
    bridge used by Codex.  This lets the dashboard send input to that exact
    terminal while the vendor binary, its native login, and its upstream
    connection remain authoritative.  Non-interactive management commands are
    passed through directly and never start the Provision daemon.
    """
    try:
        spec = provider_spec(provider)
    except ProviderError as exc:
        raise RuntimeError(str(exc)) from exc
    if spec.name == "codex":
        if profile:
            raise RuntimeError("use `provision use <profile>` to choose a Codex profile")
        return launch_codex(provider_args)
    if not shutil.which(spec.executable):
        raise RuntimeError(
            f"{spec.name} CLI is not installed or not on PATH (expected `{spec.executable}`)"
        )

    paths = Paths()
    store = Store(paths)
    selected_profile = profile or store.active_provider_profile(spec.name)
    if profile and not store.provider_profile_exists(spec.name, profile):
        raise RuntimeError(
            f"{spec.name} profile does not exist: {profile}; "
            f"run `provision provider login {spec.name} {profile}` first"
        )
    env = os.environ.copy()
    try:
        env.update(provider_environment(paths.home, spec.name, selected_profile))
    except ProviderError as exc:
        raise RuntimeError(str(exc)) from exc
    argv = [spec.executable, *provider_args]
    if not should_use_pty(
        provider_args,
        bypass_commands=spec.pty_bypass_commands,
        bypass_options=spec.pty_bypass_options,
    ):
        os.execvpe(spec.executable, argv, env)
        return 127

    status = ensure_daemon(paths, configured_daemon_port(), configured_daemon_host())
    port = int(status["port"])
    host = str(status.get("host") or DEFAULT_DAEMON_HOST)
    cwd = os.getcwd()
    inherited_session_key = os.environ.get("PROVISION_SESSION_KEY") or ""
    session_key = inherited_session_key or f"{spec.name}::{os.path.abspath(cwd)}"
    return run_managed_pty(
        spec.executable,
        argv,
        env,
        control_path=launcher_control_path(paths),
        port=port,
        proxy_token=store.proxy_token(),
        cwd=cwd,
        host=host,
        session_key=session_key,
        provider=spec.name,
        provider_profile=selected_profile,
        provider_state_root=(
            env.get(spec.profile_environment) if spec.profile_environment else None
        )
        or (
            str(Path.home() / (".grok" if spec.name == "grok" else ".claude"))
            if spec.name in {"grok", "claude"}
            else None
        ),
    )


def run_profiled_passthrough_codex(
    store: Store,
    profile: str,
    argv: list[str],
    env: dict[str, str],
    *,
    command: str,
) -> int:
    """Run a non-proxy Codex command with the selected profile's credentials.

    App-server and remote-control commands do not use Provision's HTTP provider
    override. A short-lived Codex home gives those commands the active profile
    while preserving the normal CLI configuration and shared session state.
    """
    auth_source = store.auth_path(profile)
    with tempfile.TemporaryDirectory(prefix=f"provision-codex-{profile}-") as temp:
        codex_home = Path(temp)
        bridge_codex_history_into_app_home(codex_home)
        auth_target = codex_home / "auth.json"
        shutil.copy2(auth_source, auth_target)
        auth_target.chmod(0o600)
        config = codex_home / "config.toml"
        source_config = default_codex_home() / "config.toml"
        try:
            source_config_text = source_config.read_text(encoding="utf-8")
        except OSError:
            source_config_text = ""
        runtime_config_text = source_config_text
        if "cli_auth_credentials_store" not in runtime_config_text:
            runtime_config_text = (
                runtime_config_text.rstrip() + '\ncli_auth_credentials_store = "file"\n'
            )
        config.write_text(runtime_config_text, encoding="utf-8")
        config.chmod(0o600)
        profiled_env = dict(env)
        profiled_env["CODEX_HOME"] = str(codex_home)
        result = subprocess.run(argv, env=profiled_env, check=False)
        if auth_target.exists():
            store.import_auth_file(profile, auth_target, overwrite=True, set_active=False)
        elif command == "logout":
            store.remove_profile(profile)
        try:
            updated_config = config.read_text(encoding="utf-8")
        except OSError:
            updated_config = runtime_config_text
        if "cli_auth_credentials_store" not in source_config_text:
            updated_config = "\n".join(
                line
                for line in updated_config.splitlines()
                if not line.lstrip().startswith("cli_auth_credentials_store")
            ).rstrip()
            if updated_config:
                updated_config += "\n"
        if updated_config != source_config_text:
            source_config.parent.mkdir(parents=True, exist_ok=True)
            source_config.write_text(updated_config, encoding="utf-8")
            source_config.chmod(0o600)
        return result.returncode
