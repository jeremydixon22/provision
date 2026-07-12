from __future__ import annotations

import http.client
import json
import os
import shutil
import signal
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
import threading
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
    daemon_running,
    daemon_url_host,
    health,
    project_session_sentinel,
    wait_until_running,
)
from .paths import Paths, default_codex_home, launcher_path, source_root
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
    argv = [sys.executable, "-m", "provision", "daemon"]
    if port is not None:
        argv.extend(["--port", str(port)])
    if requested_host is not None:
        argv.extend(["--host", requested_host])
    # Popen duplicates the descriptor for the daemon. Closing the parent's copy
    # immediately avoids retaining a log descriptor for the caller's lifetime.
    with paths.log.open("ab") as log:
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
) -> None:
    fields: dict[str, str] = {
        "token": proxy_token,
        "cwd": cwd,
    }
    if session_key:
        fields["session_key"] = session_key
    if control_path:
        fields["control_path"] = control_path
    if launcher_pid is not None:
        fields["launcher_pid"] = str(launcher_pid)
    if pty_managed:
        fields["pty_managed"] = "1"
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
    )


def should_use_pty(codex_args: list[str]) -> bool:
    if os.environ.get("PROVISION_DISABLE_PTY"):
        return False
    if os.name != "posix":
        return False
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return False
    if codex_args and codex_args[0] in CODEX_PTY_BYPASS_COMMANDS:
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


def control_server(control_path: Path, master_fd: int, stop: threading.Event) -> None:
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
            with conn:
                try:
                    raw = conn.recv(1024 * 1024)
                    payload = json.loads(raw.decode("utf-8"))
                    if not isinstance(payload, dict):
                        conn.sendall(b'{"ok":false,"error":"unsupported action"}')
                        continue
                    action = payload.get("action")
                    if action == "send_escape":
                        os.write(master_fd, b"\x1b")
                        conn.sendall(b'{"ok":true}')
                        continue
                    if action != "send_text":
                        conn.sendall(b'{"ok":false,"error":"unsupported action"}')
                        continue
                    text = payload.get("text")
                    if not isinstance(text, str) or not text.strip():
                        conn.sendall(b'{"ok":false,"error":"empty text"}')
                        continue
                    os.write(master_fd, encode_terminal_prompt(text))
                    conn.sendall(b'{"ok":true}')
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    try:
                        conn.sendall(json.dumps({"ok": False, "error": str(exc)}).encode("utf-8"))
                    except OSError:
                        pass
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
    stdin_fd = sys.stdin.fileno()
    stdout_fd = sys.stdout.fileno()
    child_pid, master_fd = pty.fork()
    if child_pid == 0:
        os.execvpe("codex", argv, env)

    stop = threading.Event()
    control_thread = threading.Thread(
        target=control_server,
        args=(control_path, master_fd, stop),
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
    if should_use_pty(codex_args):
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
            runtime_config_text = runtime_config_text.rstrip() + '\ncli_auth_credentials_store = "file"\n'
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
