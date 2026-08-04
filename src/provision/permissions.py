"""Bounded provider-neutral permission request and hook helpers."""

from __future__ import annotations

import json
import os
import re
import socket
from pathlib import Path
from typing import Any, Mapping, TextIO

PERMISSION_CONTROL_MAX_BYTES = 64 * 1024
PERMISSION_PREVIEW_MAX_CHARS = 4096
PERMISSION_REASON_MAX_CHARS = 1000
PERMISSION_ID_MAX_CHARS = 256
PERMISSION_PATH_MAX_CHARS = 2048
PERMISSION_HOOK_SOCKET_ENV = "PROVISION_PERMISSION_SOCKET"
PERMISSION_SECRET_KEYS = (
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "credential",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "token",
)
PERMISSION_INLINE_SECRET_RE = re.compile(
    r"(?i)\b(access[_-]?token|api[_-]?key|authorization|bearer|credential|password|"
    r"private[_-]?key|refresh[_-]?token|secret|token)\b(\s*[:=]\s*|\s+)([^\s,;&]+)"
)
PERMISSION_OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")


def bounded_permission_text(value: object, limit: int) -> str:
    text = str(value or "").replace("\x00", "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def permission_key_is_sensitive(value: object) -> bool:
    normalized = str(value or "").lower().replace("-", "_")
    return any(secret in normalized for secret in PERMISSION_SECRET_KEYS)


def redact_permission_text(value: object) -> str:
    text = str(value or "")
    text = PERMISSION_INLINE_SECRET_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[redacted]", text
    )
    return PERMISSION_OPENAI_KEY_RE.sub("[redacted]", text)


def sanitized_permission_value(value: Any, *, depth: int = 0) -> Any:
    """Return bounded display-only data with obviously sensitive fields removed."""
    if depth >= 4:
        return "…"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for index, (key, child) in enumerate(value.items()):
            if index >= 40:
                result["…"] = "additional fields omitted"
                break
            name = bounded_permission_text(key, 120)
            result[name] = (
                "[redacted]"
                if permission_key_is_sensitive(name)
                else sanitized_permission_value(child, depth=depth + 1)
            )
        return result
    if isinstance(value, (list, tuple)):
        items = [sanitized_permission_value(item, depth=depth + 1) for item in value[:40]]
        if len(value) > 40:
            items.append("…")
        return items
    if isinstance(value, str):
        return bounded_permission_text(redact_permission_text(value), PERMISSION_PREVIEW_MAX_CHARS)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return bounded_permission_text(value, 500)


def permission_category(tool_name: str, tool_input: Mapping[str, Any]) -> str:
    normalized = tool_name.strip().lower()
    if "mcp" in normalized or "__" in normalized:
        return "mcp"
    if normalized in {"apply_patch", "edit", "write", "multiedit", "search_replace"}:
        return "patch"
    if normalized in {"bash", "shell", "exec", "exec_command", "run_terminal_command"}:
        return "shell"
    if normalized in {"read", "read_file", "write_file", "list_dir", "glob", "grep"}:
        return "filesystem"
    if normalized in {"webfetch", "websearch", "web_fetch", "web_search"}:
        return "network"
    if any(key in tool_input for key in ("host", "hostname", "url")):
        return "network"
    if any(key in tool_input for key in ("path", "file_path", "directory")):
        return "filesystem"
    return "tool"


def permission_preview(tool_name: str, tool_input: Mapping[str, Any]) -> str:
    normalized = tool_name.strip().lower()
    for key in ("command", "cmd", "patch"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            prefix = (
                "Patch"
                if normalized in {"apply_patch", "edit", "write", "multiedit"}
                else "Command"
            )
            return bounded_permission_text(
                redact_permission_text(f"{prefix}: {value}"),
                PERMISSION_PREVIEW_MAX_CHARS,
            )
    safe = sanitized_permission_value(dict(tool_input))
    try:
        rendered = json.dumps(safe, ensure_ascii=False, indent=2, sort_keys=True)
    except (TypeError, ValueError):
        rendered = str(safe)
    return bounded_permission_text(rendered, PERMISSION_PREVIEW_MAX_CHARS)


def normalize_permission_hook_request(value: Any, provider: str) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    event_name = str(value.get("hook_event_name") or value.get("hookEventName") or "")
    if event_name.lower().replace("_", "") != "permissionrequest":
        return {}
    raw_input = value.get("tool_input")
    if not isinstance(raw_input, dict):
        raw_input = value.get("toolInput")
    tool_input = raw_input if isinstance(raw_input, dict) else {}
    tool_name = bounded_permission_text(
        value.get("tool_name") or value.get("toolName") or "Tool",
        160,
    )
    reason = redact_permission_text(tool_input.get("description") or value.get("reason") or "")
    return {
        "provider": bounded_permission_text(provider, 32).lower(),
        "native_session_id": bounded_permission_text(
            value.get("session_id") or value.get("sessionId"), PERMISSION_ID_MAX_CHARS
        ),
        "turn_id": bounded_permission_text(
            value.get("turn_id") or value.get("turnId"), PERMISSION_ID_MAX_CHARS
        ),
        "tool_name": tool_name,
        "category": permission_category(tool_name, tool_input),
        "reason": bounded_permission_text(reason, PERMISSION_REASON_MAX_CHARS),
        "preview": permission_preview(tool_name, tool_input),
        "cwd": bounded_permission_text(value.get("cwd"), PERMISSION_PATH_MAX_CHARS),
    }


def provider_permission_hook_output(provider: str, decision: str, message: str = "") -> str:
    """Map one normalized decision to the shared Codex/Claude hook response."""
    if decision not in {"allow", "deny"} or provider not in {"codex", "claude"}:
        return ""
    resolved: dict[str, str] = {"behavior": decision}
    if decision == "deny":
        resolved["message"] = bounded_permission_text(
            message or "Denied in Provision.", PERMISSION_REASON_MAX_CHARS
        )
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": resolved,
            }
        },
        separators=(",", ":"),
    )


def permission_socket_request(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > PERMISSION_CONTROL_MAX_BYTES:
        return {}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(75.0)
            client.connect(str(path))
            client.sendall(encoded)
            response = bytearray()
            while len(response) <= PERMISSION_CONTROL_MAX_BYTES:
                chunk = client.recv(min(8192, PERMISSION_CONTROL_MAX_BYTES + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
                if b"\n" in response:
                    break
    except OSError:
        return {}
    if len(response) > PERMISSION_CONTROL_MAX_BYTES:
        return {}
    try:
        result = json.loads(bytes(response).split(b"\n", 1)[0].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return result if isinstance(result, dict) else {}


def run_permission_hook(
    provider: str,
    *,
    stdin: TextIO,
    stdout: TextIO,
    environ: Mapping[str, str] | None = None,
) -> int:
    """Forward one native hook request; every bridge failure falls back to the TUI."""
    environment = os.environ if environ is None else environ
    socket_path = str(environment.get(PERMISSION_HOOK_SOCKET_ENV) or "")
    if provider not in {"codex", "claude"} or not socket_path:
        return 0
    try:
        raw = stdin.read(PERMISSION_CONTROL_MAX_BYTES + 1)
    except OSError:
        return 0
    if len(raw.encode("utf-8", errors="replace")) > PERMISSION_CONTROL_MAX_BYTES:
        return 0
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return 0
    request = normalize_permission_hook_request(value, provider)
    if not request:
        return 0
    response = permission_socket_request(
        Path(socket_path),
        {"action": "permission_request", "request": request},
    )
    output = provider_permission_hook_output(
        provider,
        str(response.get("decision") or ""),
        str(response.get("message") or ""),
    )
    if output:
        stdout.write(output + "\n")
        stdout.flush()
    return 0
