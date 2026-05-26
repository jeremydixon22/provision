from __future__ import annotations

import base64
import binascii
import hashlib
import html
import importlib.resources as package_resources
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .auth import (
    AuthError,
    ensure_fresh_chatgpt_auth,
    force_refresh_chatgpt_auth,
    upstream_auth_headers,
    upstream_base_url,
    upstream_chatgpt_backend_base_url,
)
from .paths import Paths
from .store import Store, StoreError


REQUEST_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "authorization",
}

RESPONSE_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

UPSTREAM_IDENTITY_HEADERS = {
    "authorization",
    "chatgpt-account-id",
    "openai-organization",
    "openai-project",
    "x-openai-fedramp",
}

PROTOCOL_VERSION = 25
DEFAULT_DAEMON_PORT = 4888
CHATGPT_USAGE_PATH = "/wham/usage"
CHATGPT_ANALYTICS_EVENTS_PATH = "/codex/analytics-events/events"
USAGE_CACHE_MIN_INTERVAL_SECONDS = 1.0
USAGE_CACHE_WAIT_SECONDS = 5.0
USAGE_AUTO_REFRESH_SECONDS = 3600.0
USAGE_AUTO_REFRESH_POLL_SECONDS = 30.0
USAGE_AUTO_REFRESH_ERROR_BACKOFF_SECONDS = 300.0
USAGE_RESET_REFRESH_DELAY_SECONDS = 60.0
WEBSOCKET_SWITCH_IDLE_SECONDS = 10.0
WEBSOCKET_COMPLETION_FALLBACK_SECONDS = 180.0
WEBSOCKET_TOOL_COMPLETION_FALLBACK_SECONDS = 600.0
WEBSOCKET_APPLICATION_OPCODES = {0x0, 0x1, 0x2}
WEBSOCKET_RESPONSE_START_EVENT_TYPES = {
    "response.create",
}
WEBSOCKET_TERMINAL_EVENT_TYPES = {
    "error",
    "response.cancelled",
    "response.canceled",
    "response.completed",
    "response.done",
    "response.failed",
    "response.incomplete",
}
WEBSOCKET_TERMINAL_STATUSES = {
    "cancelled",
    "canceled",
    "completed",
    "failed",
    "incomplete",
}
WEBSOCKET_RESPONSE_COMPLETED_EVENT_TYPES = {
    "response.completed",
    "response.done",
}
WEBSOCKET_RESPONSE_CLEAR_EVENT_TYPES = (
    WEBSOCKET_TERMINAL_EVENT_TYPES - WEBSOCKET_RESPONSE_COMPLETED_EVENT_TYPES
)
WEBSOCKET_RESPONSE_CLEAR_STATUSES = WEBSOCKET_TERMINAL_STATUSES - {"completed"}
WEBSOCKET_TOOL_OUTPUT_TYPES = {
    "apply_patch_call",
    "code_interpreter_call",
    "computer_call",
    "custom_tool_call",
    "file_search_call",
    "function_call",
    "local_shell_call",
    "mcp_call",
    "shell_call",
    "tool_call",
    "web_search_call",
}
ANALYTICS_TURN_EVENT_TYPE = "codex_turn_event"
ANALYTICS_TURN_TERMINAL_STATUSES = {
    "cancelled",
    "canceled",
    "completed",
    "failed",
    "interrupted",
}
DEFAULT_PROFILE_CODEX_LIMIT_ID = "provision_default_codex"
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
X_CODEX_TURN_METADATA_HEADER = "x-codex-turn-metadata"
PIN_ICON_SVG = (
    '<svg class="pin-icon" viewBox="0 0 16 16" fill="none" aria-hidden="true">'
    '<path d="M5.2 2.2h5.6l-.8 3.2 2.2 2.2-1.4 1.4-2.2-2.2-3.2.8V2.2Z" '
    'stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>'
    '<path d="M7 7 3 11" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>'
    "</svg>"
)


class UpstreamRoute:
    CODEX_API = "codex-api"
    CHATGPT_BACKEND = "chatgpt-backend"


class WebSocketHandshakeRejected(RuntimeError):
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.status_code = websocket_handshake_status(response)
        status_line = response.split(b"\r\n", 1)[0].decode(
            "iso-8859-1",
            errors="replace",
        )
        super().__init__(status_line)


class WebSocketClosed(RuntimeError):
    pass


def should_forward_incoming_header(name: str) -> bool:
    lower = name.lower()
    return lower not in REQUEST_HOP_BY_HOP_HEADERS and lower not in UPSTREAM_IDENTITY_HEADERS


def backend_proxy_prefix(proxy_token: str | None = None) -> str:
    if proxy_token:
        return f"/backend-api/provision-{proxy_token}"
    return "/backend-api/provision"


def backend_upstream_path(path: str, proxy_token: str) -> str:
    for prefix in (backend_proxy_prefix(proxy_token), backend_proxy_prefix()):
        if path == prefix:
            return ""
        if path.startswith(prefix + "/"):
            return path[len(prefix):]
    raise AuthError("invalid ChatGPT backend proxy path token")


def redact_proxy_token(text: str, proxy_token: str) -> str:
    if not proxy_token:
        return text
    return text.replace(f"provision-{proxy_token}", "provision-<redacted>").replace(
        proxy_token,
        "<redacted>",
    )


def project_sentinel(proxy_token: str) -> str:
    return f"provision-{proxy_token}"


def project_session_sentinel(proxy_token: str, cwd: str) -> str:
    payload = json.dumps({"cwd": cwd}, separators=(",", ":")).encode("utf-8")
    encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return f"{project_sentinel(proxy_token)}.{encoded}"


def decode_project_session_sentinel(value: str, proxy_token: str) -> dict[str, str] | None:
    sentinel = project_sentinel(proxy_token)
    if value == sentinel:
        return {}
    prefix = sentinel + "."
    if not value.startswith(prefix):
        return None
    raw = value[len(prefix):]
    try:
        decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8")
        payload = json.loads(decoded)
    except (binascii.Error, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    cwd = payload.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        return {}
    key = normalize_session_key(cwd)
    return {"key": key, "cwd": cwd} if key else {}


def normalize_session_key(cwd: str) -> str:
    path = cwd.strip()
    if not path:
        return ""
    return os.path.normpath(path)


def compact_session_path(cwd: str) -> str:
    home = str(Path.home())
    normalized = os.path.normpath(cwd)
    if normalized == home:
        return "~"
    if normalized.startswith(home + os.sep):
        return "~" + normalized[len(home):]
    return normalized


def session_display_name(cwd: str) -> str:
    compact = compact_session_path(cwd)
    name = Path(cwd).name
    return name or compact


def websocket_accept_key(key: str) -> str:
    digest = hashlib.sha1((key.strip() + WEBSOCKET_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def websocket_handshake_status(response: bytes) -> int | None:
    status_line = response.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    parts = status_line.split()
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def websocket_chunk_has_application_data(data: bytes) -> bool:
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            return False
        first = data[offset]
        second = data[offset + 1]
        opcode = first & 0x0F
        if opcode in WEBSOCKET_APPLICATION_OPCODES:
            return True

        length = second & 0x7F
        header_length = 2
        if length == 126:
            if offset + 4 > len(data):
                return False
            length = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            header_length = 4
        elif length == 127:
            if offset + 10 > len(data):
                return False
            length = struct.unpack("!Q", data[offset + 2:offset + 10])[0]
            header_length = 10
        if second & 0x80:
            header_length += 4
        frame_length = header_length + length
        if frame_length <= 0 or offset + frame_length > len(data):
            return False
        offset += frame_length
    return False


class WebSocketMessageTracker:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.fragment_opcode: int | None = None
        self.fragment_parts: list[bytes] = []

    def feed(self, data: bytes) -> list[tuple[int, bytes]]:
        self.buffer.extend(data)
        messages: list[tuple[int, bytes]] = []
        offset = 0

        while True:
            parsed = self._parse_frame_at(offset)
            if parsed is None:
                break
            frame_length, fin, opcode, payload = parsed
            offset += frame_length
            if opcode in (0x1, 0x2):
                if fin:
                    messages.append((opcode, payload))
                    continue
                self.fragment_opcode = opcode
                self.fragment_parts = [payload]
                continue
            if opcode == 0x0 and self.fragment_opcode is not None:
                self.fragment_parts.append(payload)
                if fin:
                    messages.append((self.fragment_opcode, b"".join(self.fragment_parts)))
                    self.fragment_opcode = None
                    self.fragment_parts = []

        if offset:
            del self.buffer[:offset]
        return messages

    def _parse_frame_at(self, offset: int) -> tuple[int, bool, int, bytes] | None:
        if len(self.buffer) - offset < 2:
            return None
        first = self.buffer[offset]
        second = self.buffer[offset + 1]
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        cursor = offset + 2

        if length == 126:
            if len(self.buffer) - cursor < 2:
                return None
            length = struct.unpack("!H", self.buffer[cursor:cursor + 2])[0]
            cursor += 2
        elif length == 127:
            if len(self.buffer) - cursor < 8:
                return None
            length = struct.unpack("!Q", self.buffer[cursor:cursor + 8])[0]
            cursor += 8

        mask = b""
        if masked:
            if len(self.buffer) - cursor < 4:
                return None
            mask = bytes(self.buffer[cursor:cursor + 4])
            cursor += 4

        if len(self.buffer) - cursor < length:
            return None

        payload = bytes(self.buffer[cursor:cursor + length])
        if mask:
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        return cursor + length - offset, fin, opcode, payload


def websocket_message_json(opcode: int, payload: bytes) -> Any | None:
    if opcode != 0x1:
        return None
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def json_value_event_type(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    for key in ("type", "event"):
        event = value.get(key)
        if isinstance(event, str):
            return event.lower()
    return None


def json_value_has_event_type(value: Any, event_types: set[str]) -> bool:
    if isinstance(value, list):
        return any(json_value_has_event_type(item, event_types) for item in value)
    if not isinstance(value, dict):
        return False

    event = json_value_event_type(value)
    if event in event_types:
        return True
    return any(json_value_has_event_type(item, event_types) for item in value.values())


def json_top_level_has_event_type(value: Any, event_types: set[str]) -> bool:
    if isinstance(value, list):
        return any(json_top_level_has_event_type(item, event_types) for item in value)
    return json_value_event_type(value) in event_types


def json_value_has_response_status(value: Any, statuses: set[str]) -> bool:
    if isinstance(value, list):
        return any(json_value_has_response_status(item, statuses) for item in value)
    if not isinstance(value, dict):
        return False

    status = value.get("status")
    if isinstance(status, str) and status.lower() in statuses:
        object_type = value.get("object")
        identifier = value.get("id")
        if (
            object_type == "response"
            or (isinstance(identifier, str) and identifier.startswith("resp_"))
            or "output" in value
        ):
            return True

    return any(json_value_has_response_status(item, statuses) for item in value.values())


def websocket_message_starts_response(opcode: int, payload: bytes) -> bool:
    value = websocket_message_json(opcode, payload)
    if value is None:
        return False
    return response_create_payload_starts_turn(value)


def response_create_payload_starts_turn(value: Any) -> bool:
    if isinstance(value, list):
        return any(response_create_payload_starts_turn(item) for item in value)
    if not isinstance(value, dict):
        return False
    if json_value_event_type(value) not in WEBSOCKET_RESPONSE_START_EVENT_TYPES:
        return False
    return value.get("generate") is not False


def websocket_message_turn_id(opcode: int, payload: bytes) -> str | None:
    value = websocket_message_json(opcode, payload)
    if value is None:
        return None
    return response_create_payload_turn_id(value)


def response_create_payload_turn_id(value: Any) -> str | None:
    metadata = response_create_payload_metadata(value)
    if not metadata:
        return None
    turn_id = metadata.get("turn_id")
    return turn_id if isinstance(turn_id, str) and turn_id else None


def response_create_payload_metadata(value: Any) -> dict[str, Any] | None:
    if isinstance(value, list):
        for item in value:
            metadata = response_create_payload_metadata(item)
            if metadata:
                return metadata
        return None
    if not response_create_payload_starts_turn(value):
        return None
    if not isinstance(value, dict):
        return None
    client_metadata = value.get("client_metadata")
    if not isinstance(client_metadata, dict):
        return None
    raw_metadata = client_metadata.get(X_CODEX_TURN_METADATA_HEADER)
    if not isinstance(raw_metadata, str):
        return None
    try:
        metadata = json.loads(raw_metadata)
    except json.JSONDecodeError:
        return None
    if not isinstance(metadata, dict):
        return None
    return metadata


def response_create_payload_session(value: Any) -> dict[str, str] | None:
    metadata = response_create_payload_metadata(value)
    if not metadata:
        return None
    for key in ("cwd", "working_directory", "working_dir", "current_dir"):
        cwd = metadata.get(key)
        if isinstance(cwd, str) and cwd:
            session_key = normalize_session_key(cwd)
            return {"key": session_key, "cwd": cwd} if session_key else None
    workspaces = metadata.get("workspaces")
    if isinstance(workspaces, dict):
        for cwd in workspaces.keys():
            if isinstance(cwd, str) and cwd:
                session_key = normalize_session_key(cwd)
                return {"key": session_key, "cwd": cwd} if session_key else None
    return None


def request_body_session(body: bytes | None) -> dict[str, str] | None:
    if not body:
        return None
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return response_create_payload_session(value)


def json_value_has_tool_output(value: Any) -> bool:
    if isinstance(value, list):
        return any(json_value_has_tool_output(item) for item in value)
    if not isinstance(value, dict):
        return False

    item_type = value.get("type")
    if isinstance(item_type, str):
        normalized = item_type.lower()
        if (
            normalized in WEBSOCKET_TOOL_OUTPUT_TYPES
            or normalized.endswith("_call")
            or "tool_call" in normalized
        ):
            return True

    return any(json_value_has_tool_output(item) for item in value.values())


def websocket_terminal_event_keeps_work_pending(opcode: int, payload: bytes) -> bool:
    value = websocket_message_json(opcode, payload)
    if value is None:
        return False
    return (
        json_value_has_event_type(value, WEBSOCKET_RESPONSE_COMPLETED_EVENT_TYPES)
        or json_value_has_response_status(value, {"completed"})
    ) and json_value_has_tool_output(value)


def websocket_message_completion_action(opcode: int, payload: bytes) -> str | None:
    value = websocket_message_json(opcode, payload)
    if value is None:
        return None

    if json_value_has_event_type(
        value,
        WEBSOCKET_RESPONSE_CLEAR_EVENT_TYPES,
    ) or json_value_has_response_status(value, WEBSOCKET_RESPONSE_CLEAR_STATUSES):
        return "clear"

    if json_value_has_event_type(
        value,
        WEBSOCKET_RESPONSE_COMPLETED_EVENT_TYPES,
    ) or json_value_has_response_status(value, {"completed"}):
        if json_value_has_tool_output(value):
            return "keep"
        return "complete"

    return None


def websocket_message_has_tool_output(opcode: int, payload: bytes) -> bool:
    value = websocket_message_json(opcode, payload)
    if value is None:
        return False
    return json_value_has_tool_output(value)


def analytics_completed_turn_ids(payload: bytes | None) -> list[str]:
    turn_ids = analytics_turn_ids(payload, terminal_only=True)
    return turn_ids


def analytics_turn_ids(payload: bytes | None, *, terminal_only: bool = False) -> list[str]:
    if not payload:
        return []
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(value, dict):
        return []
    events = value.get("events")
    if not isinstance(events, list):
        return []

    turn_ids: list[str] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("event_type") != ANALYTICS_TURN_EVENT_TYPE:
            continue
        params = event.get("event_params")
        if not isinstance(params, dict):
            continue
        status = params.get("status")
        turn_id = params.get("turn_id")
        if not isinstance(turn_id, str) or not turn_id:
            continue
        if not terminal_only:
            turn_ids.append(turn_id)
            continue
        if (
            isinstance(status, str)
            and status.lower() in ANALYTICS_TURN_TERMINAL_STATUSES
        ):
            turn_ids.append(turn_id)
    return turn_ids


def websocket_message_has_terminal_event(opcode: int, payload: bytes) -> bool:
    value = websocket_message_json(opcode, payload)
    if value is None:
        return False
    return json_value_has_terminal_event(value)


def json_value_has_terminal_event(value: Any) -> bool:
    return json_value_has_event_type(
        value,
        WEBSOCKET_TERMINAL_EVENT_TYPES,
    ) or json_value_has_response_status(value, WEBSOCKET_TERMINAL_STATUSES)


def logo_asset_bytes(name: str = "provision.png") -> bytes | None:
    if name not in {"provision.png", "provision-wordmark.png"}:
        return None
    try:
        return package_resources.files("provision").joinpath(f"assets/{name}").read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return None


def format_status_updated_at(updated_at: datetime) -> str:
    local = updated_at.astimezone() if updated_at.tzinfo else updated_at
    return f"{local:%H:%M} on {local.day} {local:%b}"


def format_quota_reset_at(reset_at: datetime) -> str:
    local = reset_at.astimezone() if reset_at.tzinfo else reset_at
    now = datetime.now().astimezone()
    if local.date() == now.date():
        return f"Resets {local:%H:%M}"
    return f"Resets {local:%H:%M} {local.day} {local:%b}"


def parse_reset_datetime(value: Any) -> datetime | None:
    if isinstance(value, (int, float)):
        timestamp = float(value)
        if timestamp > 10_000_000_000:
            timestamp = timestamp / 1000
        try:
            return datetime.fromtimestamp(timestamp).astimezone()
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(value, str) and value.strip():
        raw = value.strip()
        try:
            return parse_reset_datetime(float(raw))
        except ValueError:
            pass
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone()
        except ValueError:
            return None
    return None


def quota_window_reset_datetime(
    window: Any,
    relative_to: datetime | None = None,
) -> datetime | None:
    if not isinstance(window, dict):
        return None
    for key in (
        "reset_at",
        "resets_at",
        "reset_time",
        "reset_timestamp",
        "reset_epoch_seconds",
        "reset_epoch",
    ):
        reset_at = parse_reset_datetime(window.get(key))
        if reset_at is not None:
            return reset_at

    for key in (
        "reset_after_seconds",
        "resets_after_seconds",
        "reset_in_seconds",
        "seconds_until_reset",
        "reset_after",
    ):
        seconds = window.get(key)
        if isinstance(seconds, (int, float)):
            base = relative_to.astimezone() if relative_to else datetime.now().astimezone()
            return base + timedelta(seconds=float(seconds))
    return None


def quota_reset_label(window: dict[str, Any]) -> str:
    reset_at = quota_window_reset_datetime(window)
    if reset_at is not None:
        return format_quota_reset_at(reset_at)
    return ""


def normalize_rate_limit_id(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return "codex"
    return value.strip().lower().replace("-", "_")


def header_value(headers: Any, name: str) -> str | None:
    try:
        value = headers.get(name)
    except AttributeError:
        value = None
    if value is None:
        try:
            value = headers.get(name.lower())
        except AttributeError:
            value = None
    if value is None:
        return None
    return str(value).strip()


def header_float(headers: Any, name: str) -> float | None:
    value = header_value(headers, name)
    if not value:
        return None
    try:
        parsed = float(value)
    except ValueError:
        return None
    return parsed if parsed == parsed and parsed not in (float("inf"), float("-inf")) else None


def header_int(headers: Any, name: str) -> int | None:
    value = header_value(headers, name)
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def header_bool(headers: Any, name: str) -> bool | None:
    value = header_value(headers, name)
    if value is None:
        return None
    lowered = value.lower()
    if lowered in {"true", "1"}:
        return True
    if lowered in {"false", "0"}:
        return False
    return None


def rate_limit_header_names(headers: Any) -> list[str]:
    try:
        return [str(name).lower() for name in headers.keys()]
    except AttributeError:
        try:
            return [str(name).lower() for name, _value in headers.items()]
        except AttributeError:
            return []


def raw_http_response_headers(response: bytes) -> dict[str, str]:
    header_block = response.split(b"\r\n\r\n", 1)[0]
    lines = header_block.split(b"\r\n")[1:]
    headers: dict[str, str] = {}
    for line in lines:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        headers[name.decode("iso-8859-1", errors="ignore").strip().lower()] = value.decode(
            "iso-8859-1",
            errors="ignore",
        ).strip()
    return headers


def header_limit_ids(headers: Any) -> list[str]:
    ids = {"codex"}
    suffix = "-primary-used-percent"
    for name in rate_limit_header_names(headers):
        if not name.endswith(suffix) or not name.startswith("x-"):
            continue
        ids.add(normalize_rate_limit_id(name[2:-len(suffix)]))
    return sorted(ids, key=lambda item: (item != "codex", item))


def rate_limit_window_from_headers(headers: Any, prefix: str, window_name: str) -> dict[str, Any] | None:
    used_percent = header_float(headers, f"{prefix}-{window_name}-used-percent")
    if used_percent is None:
        return None
    window_minutes = header_int(headers, f"{prefix}-{window_name}-window-minutes")
    reset_at = header_int(headers, f"{prefix}-{window_name}-reset-at")
    window: dict[str, Any] = {"used_percent": used_percent}
    if window_minutes is not None:
        window["limit_window_seconds"] = window_minutes * 60
    if reset_at is not None:
        window["reset_at"] = reset_at
    if used_percent == 0.0 and not window_minutes and reset_at is None:
        return None
    return window


def rate_limit_from_headers(headers: Any, limit_id: str) -> dict[str, Any] | None:
    prefix = "x-" + limit_id.replace("_", "-")
    primary = rate_limit_window_from_headers(headers, prefix, "primary")
    secondary = rate_limit_window_from_headers(headers, prefix, "secondary")
    if primary is None and secondary is None:
        return None
    rate_limit: dict[str, Any] = {}
    if primary is not None:
        rate_limit["primary_window"] = primary
    if secondary is not None:
        rate_limit["secondary_window"] = secondary
    return rate_limit


def usage_payload_from_rate_limit_headers(headers: Any) -> dict[str, Any] | None:
    payload: dict[str, Any] = {}
    additional: list[dict[str, Any]] = []
    for limit_id in header_limit_ids(headers):
        rate_limit = rate_limit_from_headers(headers, limit_id)
        if rate_limit is None:
            continue
        limit_name = header_value(headers, f"x-{limit_id.replace('_', '-')}-limit-name")
        if limit_id == "codex":
            payload["rate_limit"] = rate_limit
        else:
            additional.append(
                {
                    "limit_name": limit_name or limit_id,
                    "metered_feature": limit_id,
                    "rate_limit": rate_limit,
                }
            )

    has_credits = header_bool(headers, "x-codex-credits-has-credits")
    unlimited = header_bool(headers, "x-codex-credits-unlimited")
    if has_credits is not None and unlimited is not None:
        credits: dict[str, Any] = {
            "has_credits": has_credits,
            "unlimited": unlimited,
        }
        balance = header_value(headers, "x-codex-credits-balance")
        if balance:
            credits["balance"] = balance
        payload["credits"] = credits

    if additional:
        payload["additional_rate_limits"] = additional
    return payload if payload.get("rate_limit") or additional or payload.get("credits") else None


def event_window_to_usage_window(window: Any) -> dict[str, Any] | None:
    if not isinstance(window, dict):
        return None
    used_percent = window.get("used_percent")
    if not isinstance(used_percent, (int, float)):
        return None
    usage_window: dict[str, Any] = {"used_percent": float(used_percent)}
    window_minutes = window.get("window_minutes")
    if isinstance(window_minutes, (int, float)):
        usage_window["limit_window_seconds"] = int(window_minutes * 60)
    reset_at = window.get("reset_at")
    if isinstance(reset_at, (int, float, str)):
        usage_window["reset_at"] = reset_at
    return usage_window


def usage_payload_from_rate_limit_event(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or json_value_event_type(value) != "codex.rate_limits":
        return None
    details = value.get("rate_limits")
    if not isinstance(details, dict):
        return None
    rate_limit: dict[str, Any] = {}
    primary = event_window_to_usage_window(details.get("primary"))
    secondary = event_window_to_usage_window(details.get("secondary"))
    if primary is not None:
        rate_limit["primary_window"] = primary
    if secondary is not None:
        rate_limit["secondary_window"] = secondary
    if not rate_limit:
        return None

    limit_id = normalize_rate_limit_id(
        value.get("metered_limit_name") or value.get("limit_id") or value.get("limit_name")
    )
    payload: dict[str, Any] = {}
    credits = value.get("credits")
    if isinstance(credits, dict):
        payload["credits"] = {
            key: credits[key]
            for key in ("has_credits", "unlimited", "balance")
            if key in credits
        }
    if isinstance(value.get("plan_type"), str):
        payload["plan_type"] = value["plan_type"]
    if limit_id == "codex":
        payload["rate_limit"] = rate_limit
    else:
        payload["additional_rate_limits"] = [
            {
                "limit_name": str(value.get("limit_name") or limit_id),
                "metered_feature": limit_id,
                "rate_limit": rate_limit,
            }
        ]
    return payload


def usage_payload_from_websocket_message(opcode: int, payload: bytes) -> dict[str, Any] | None:
    value = websocket_message_json(opcode, payload)
    return usage_payload_from_rate_limit_event(value)


def merge_rate_limit(existing: Any, update: Any) -> dict[str, Any]:
    merged = dict(existing) if isinstance(existing, dict) else {}
    if not isinstance(update, dict):
        return merged
    for key, value in update.items():
        if key in {"primary_window", "secondary_window"} and isinstance(value, dict):
            previous = merged.get(key)
            merged[key] = {**previous, **value} if isinstance(previous, dict) else dict(value)
        else:
            merged[key] = value
    return merged


def merge_usage_payload(existing: Any, update: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing) if isinstance(existing, dict) else {}
    if isinstance(update.get("rate_limit"), dict):
        merged["rate_limit"] = merge_rate_limit(merged.get("rate_limit"), update["rate_limit"])
    if isinstance(update.get("credits"), dict):
        credits = merged.get("credits")
        merged["credits"] = {**credits, **update["credits"]} if isinstance(credits, dict) else dict(update["credits"])
    if isinstance(update.get("plan_type"), str):
        merged["plan_type"] = update["plan_type"]

    existing_additional = merged.get("additional_rate_limits")
    additional = (
        [dict(row) for row in existing_additional if isinstance(row, dict)]
        if isinstance(existing_additional, list)
        else []
    )
    update_additional = update.get("additional_rate_limits")
    rows = update_additional if isinstance(update_additional, list) else []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("rate_limit"), dict):
            continue
        feature = str(row.get("metered_feature") or "")
        if not feature:
            continue
        replaced = False
        for index, existing_row in enumerate(additional):
            if existing_row.get("metered_feature") != feature:
                continue
            existing_row["rate_limit"] = merge_rate_limit(
                existing_row.get("rate_limit"),
                row.get("rate_limit"),
            )
            if row.get("limit_name"):
                existing_row["limit_name"] = row["limit_name"]
            additional[index] = existing_row
            replaced = True
            break
        if not replaced:
            additional.append(dict(row))
    if additional:
        merged["additional_rate_limits"] = additional
    return merged


def provision_limit_name(active_profile: str, updated_at: datetime | None) -> str:
    if updated_at is None:
        return f"Provision ({active_profile})"
    return f"Provision ({active_profile} - updated {format_status_updated_at(updated_at)})"


def additional_rate_limit(
    *,
    limit_name: str,
    metered_feature: str,
    rate_limit: Any,
) -> dict[str, Any] | None:
    if not isinstance(rate_limit, dict):
        return None
    return {
        "limit_name": limit_name,
        "metered_feature": metered_feature,
        "rate_limit": rate_limit,
    }


def upsert_additional_rate_limit(
    additional_rate_limits: Any,
    item: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    existing = additional_rate_limits if isinstance(additional_rate_limits, list) else []
    rows = [dict(row) for row in existing if isinstance(row, dict)]
    if item is None:
        return rows
    metered_feature = item.get("metered_feature")
    rows = [row for row in rows if row.get("metered_feature") != metered_feature]
    rows.append(item)
    return rows


def label_usage_payload(
    payload: dict[str, Any],
    *,
    active_profile: str,
    updated_at: datetime | None = None,
    default_profile: str | None = None,
    default_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    labeled = dict(payload)
    additional = upsert_additional_rate_limit(
        labeled.get("additional_rate_limits"),
        additional_rate_limit(
            limit_name=provision_limit_name(active_profile, updated_at),
            metered_feature="codex",
            rate_limit=labeled.get("rate_limit"),
        ),
    )

    if default_profile and default_payload:
        additional = upsert_additional_rate_limit(
            additional,
            additional_rate_limit(
                limit_name=f"Provision profile ({default_profile})",
                metered_feature=DEFAULT_PROFILE_CODEX_LIMIT_ID,
                rate_limit=default_payload.get("rate_limit"),
            ),
        )
        default_additional = default_payload.get("additional_rate_limits")
        if isinstance(default_additional, list):
            for row in default_additional:
                if not isinstance(row, dict):
                    continue
                metered_feature = row.get("metered_feature")
                limit_name = row.get("limit_name")
                if not isinstance(metered_feature, str) or not isinstance(limit_name, str):
                    continue
                additional = upsert_additional_rate_limit(
                    additional,
                    additional_rate_limit(
                        limit_name=f"Provision profile ({default_profile}): {limit_name}",
                        metered_feature=f"provision_default_{metered_feature}",
                        rate_limit=row.get("rate_limit"),
                    ),
                )

    labeled["additional_rate_limits"] = additional
    return labeled


def format_window_seconds(seconds: Any, fallback: str) -> str:
    if not isinstance(seconds, (int, float)) or seconds <= 0:
        return fallback
    if seconds % 604800 == 0:
        weeks = int(seconds // 604800)
        return "weekly" if weeks == 1 else f"{weeks}w"
    if seconds % 86400 == 0:
        days = int(seconds // 86400)
        return "daily" if days == 1 else f"{days}d"
    if seconds % 3600 == 0:
        hours = int(seconds // 3600)
        return f"{hours}h"
    if seconds % 60 == 0:
        minutes = int(seconds // 60)
        return f"{minutes}m"
    return f"{int(seconds)}s"


def usage_window_summary(window: Any, fallback: str) -> str | None:
    if not isinstance(window, dict):
        return None
    label = format_window_seconds(window.get("limit_window_seconds"), fallback)
    used_percent = window.get("used_percent")
    if isinstance(used_percent, (int, float)):
        remaining = max(0.0, 100.0 - float(used_percent))
        return f"{label} {remaining:.0f}%"
    remaining_count = window.get("remaining")
    if isinstance(remaining_count, (int, float)):
        return f"{label} {remaining_count:g} remaining"
    return None


def usage_rate_limit_summary(rate_limit: Any) -> str:
    if not isinstance(rate_limit, dict):
        return "quota payload has no rate limit"
    pieces = [
        summary
        for summary in (
            usage_window_summary(rate_limit.get("primary_window"), "primary"),
            usage_window_summary(rate_limit.get("secondary_window"), "secondary"),
        )
        if summary
    ]
    if not pieces:
        allowed = rate_limit.get("allowed")
        if isinstance(allowed, bool):
            return "allowed" if allowed else "not allowed"
        return "quota details cached"
    return "; ".join(pieces)


def usage_cache_summary(entry: dict[str, Any] | None) -> str:
    if not entry:
        return "No quota cached"
    payload = entry.get("payload")
    fetched_at = entry.get("fetched_at")
    error = entry.get("error")
    if not isinstance(payload, dict):
        return f"Refresh failed: {error}" if error else "No quota cached"
    prefix = "Updated"
    if isinstance(fetched_at, datetime):
        prefix = f"Updated {format_status_updated_at(fetched_at)}"
    summary = usage_rate_limit_summary(payload.get("rate_limit"))
    additional = payload.get("additional_rate_limits")
    extra = ""
    if isinstance(additional, list) and additional:
        bucket_count = len([row for row in additional if isinstance(row, dict)])
        if bucket_count:
            extra = f"; {bucket_count} extra bucket{'s' if bucket_count != 1 else ''}"
    suffix = f"; last refresh failed: {error}" if error else ""
    return f"{prefix}; {summary}{extra}{suffix}"


def quota_bucket_rows(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []

    buckets: list[dict[str, Any]] = []
    if isinstance(payload.get("rate_limit"), dict):
        buckets.append(
            {
                "name": "Codex",
                "metered_feature": "codex",
                "rate_limit": payload["rate_limit"],
            }
        )

    additional = payload.get("additional_rate_limits")
    if isinstance(additional, list):
        for index, row in enumerate(additional, start=1):
            if not isinstance(row, dict) or not isinstance(row.get("rate_limit"), dict):
                continue
            name = row.get("limit_name") or row.get("metered_feature") or f"Bucket {index}"
            buckets.append(
                {
                    "name": str(name),
                    "metered_feature": str(row.get("metered_feature") or ""),
                    "rate_limit": row["rate_limit"],
                }
            )
    return buckets


def usage_payload_reset_datetimes(
    payload: Any,
    relative_to: datetime | None = None,
) -> list[datetime]:
    resets: list[datetime] = []
    for bucket in quota_bucket_rows(payload):
        rate_limit = bucket.get("rate_limit")
        if not isinstance(rate_limit, dict):
            continue
        for key in ("primary_window", "secondary_window"):
            reset_at = quota_window_reset_datetime(rate_limit.get(key), relative_to)
            if reset_at is not None:
                resets.append(reset_at)
    return resets


def usage_refresh_due_at(
    entry: dict[str, Any] | None,
    now: datetime | None = None,
) -> datetime:
    now = now.astimezone() if now else datetime.now().astimezone()
    if not isinstance(entry, dict):
        return now
    fetched_at = entry.get("fetched_at")
    if not isinstance(fetched_at, datetime):
        return now
    fetched_at = fetched_at.astimezone()

    due_times = [fetched_at + timedelta(seconds=USAGE_AUTO_REFRESH_SECONDS)]
    payload = entry.get("payload")
    if isinstance(payload, dict):
        for reset_at in usage_payload_reset_datetimes(payload, fetched_at):
            due_at = reset_at + timedelta(seconds=USAGE_RESET_REFRESH_DELAY_SECONDS)
            if fetched_at < due_at:
                due_times.append(due_at)
    return min(due_times)


def percent_value(value: Any) -> float | None:
    if not isinstance(value, (int, float)):
        return None
    return max(0.0, min(100.0, float(value)))


def quota_window_remaining_percent(window: Any) -> float | None:
    if not isinstance(window, dict):
        return None
    used_percent = percent_value(window.get("used_percent"))
    if used_percent is None:
        return None
    return max(0.0, 100.0 - used_percent)


def quota_bucket_state(rate_limit: dict[str, Any]) -> tuple[str, str]:
    remaining_values = [
        value
        for value in (
            quota_window_remaining_percent(rate_limit.get("primary_window")),
            quota_window_remaining_percent(rate_limit.get("secondary_window")),
        )
        if value is not None
    ]
    if remaining_values:
        remaining = min(remaining_values)
        if remaining <= 0:
            return "Exhausted", "exhausted"
        if remaining <= 10:
            return "Limited", "limited"
        if remaining <= 25:
            return "Reduced", "reduced"
        return "Available", "ok"

    for key in ("primary_window", "secondary_window"):
        window = rate_limit.get(key)
        if isinstance(window, dict):
            remaining = window.get("remaining")
            if isinstance(remaining, (int, float)) and remaining <= 0:
                return "Exhausted", "exhausted"

    allowed = rate_limit.get("allowed")
    if isinstance(allowed, bool):
        return ("Available", "ok") if allowed else ("Exhausted", "exhausted")
    return "", ""


def quota_percent_text(value: float | None) -> str:
    return f"{value:.0f}%" if value is not None else ""


def quota_window_label(window: Any, fallback: str) -> str:
    if not isinstance(window, dict):
        return fallback
    label = format_window_seconds(window.get("limit_window_seconds"), fallback)
    return "Weekly" if label == "weekly" else label


def lowercase_reset_label(reset: str) -> str:
    if not reset:
        return ""
    return reset[:1].lower() + reset[1:]


def quota_status_text(label: str, window: Any) -> str:
    reset = quota_reset_label(window) if isinstance(window, dict) else ""
    return f"{label} ({reset})" if reset else label


def render_quota_window(window: Any, fallback: str) -> str:
    if not isinstance(window, dict):
        return ""
    label = html.escape(format_window_seconds(window.get("limit_window_seconds"), fallback))
    reset = quota_reset_label(window)
    reset_html = f'<span class="quota-reset">{html.escape(reset)}</span>' if reset else ""
    remaining_percent = quota_window_remaining_percent(window)
    remaining = window.get("remaining")
    if remaining_percent is not None:
        level = "low" if remaining_percent <= 10 else "warn" if remaining_percent <= 25 else "good"
        value = f"{remaining_percent:.0f}% left"
        return f"""
          <div class="quota-window">
            <div class="quota-window-main">
              <div class="quota-window-top">
                <span>{label}</span>
                <strong>{html.escape(value)}</strong>
              </div>
              <div class="quota-bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="{remaining_percent:.0f}" aria-label="{label} quota {html.escape(value)}">
                <span class="quota-fill {level}" style="width: {remaining_percent:.2f}%"></span>
              </div>
            </div>
            {reset_html}
          </div>
        """
    if isinstance(remaining, (int, float)):
        return f"""
          <div class="quota-window count-only">
            <div class="quota-window-main">
              <div class="quota-window-top">
                <span>{label}</span>
                <strong>{remaining:g} remaining</strong>
              </div>
            </div>
            {reset_html}
          </div>
        """
    allowed = window.get("allowed")
    if isinstance(allowed, bool):
        value = "available" if allowed else "not available"
        return f"""
          <div class="quota-window count-only">
            <div class="quota-window-main">
              <div class="quota-window-top">
                <span>{label}</span>
                <strong>{value}</strong>
              </div>
            </div>
            {reset_html}
          </div>
        """
    return ""


def render_quota_count_window(window: Any, fallback: str) -> str:
    if not isinstance(window, dict):
        return ""
    label = html.escape(quota_window_label(window, fallback))
    reset = quota_reset_label(window)
    reset_html = f' <span class="quota-count-reset">({html.escape(reset)})</span>' if reset else ""
    remaining = window.get("remaining")
    if isinstance(remaining, (int, float)):
        return f'<div class="quota-count-line"><span>{label}</span><strong>{remaining:g}</strong>{reset_html}</div>'
    allowed = window.get("allowed")
    if isinstance(allowed, bool):
        value = "available" if allowed else "not available"
        return f'<div class="quota-count-line"><span>{label}</span><strong>{value}</strong>{reset_html}</div>'
    return ""


def quota_stack_context(rate_limit: dict[str, Any]) -> dict[str, Any]:
    primary = rate_limit.get("primary_window")
    secondary = rate_limit.get("secondary_window")
    primary_percent = quota_window_remaining_percent(primary)
    weekly_percent = quota_window_remaining_percent(secondary)
    primary_label = quota_window_label(primary, "5h")
    weekly_label = quota_window_label(secondary, "Weekly")

    if primary_percent is None and weekly_percent is None:
        count_rows = [
            render_quota_count_window(primary, "5h"),
            render_quota_count_window(secondary, "Weekly"),
        ]
        count_html = "".join(row for row in count_rows if row)
        return {
            "count_html": count_html or '<div class="quota-muted">No window details</div>',
        }

    primary_visual = primary_percent
    if primary_visual is not None and weekly_percent is not None and weekly_percent <= 0:
        primary_visual = 0.0

    primary_reset_text = quota_status_text(primary_label, primary)
    if (
        primary_visual is not None
        and weekly_percent is not None
        and weekly_percent <= 0
        and isinstance(secondary, dict)
    ):
        weekly_reset = quota_reset_label(secondary)
        primary_reset_text = (
            f"{primary_label} (Weekly {lowercase_reset_label(weekly_reset)})"
            if weekly_reset
            else f"{primary_label} (Weekly exhausted)"
        )

    weekly_status = quota_status_text(weekly_label, secondary)
    weekly_style = weekly_percent if weekly_percent is not None else 100.0
    primary_style = primary_visual if primary_visual is not None else 0.0
    primary_text = quota_percent_text(primary_visual)
    weekly_text = quota_percent_text(weekly_percent)
    primary_empty = " empty" if primary_style <= 0 else ""
    aria = " / ".join(
        piece
        for piece in (
            f"{primary_label} {primary_text}" if primary_text else "",
            f"{weekly_label} {weekly_text}" if weekly_text else "",
        )
        if piece
    )

    return {
        "primary_reset_text": primary_reset_text,
        "weekly_status": weekly_status,
        "primary_style": primary_style,
        "weekly_style": weekly_style,
        "primary_text": primary_text,
        "weekly_text": weekly_text,
        "primary_empty": primary_empty,
        "aria": aria,
    }


def render_quota_horizons(context: dict[str, Any]) -> str:
    if context.get("count_html"):
        return ""
    weekly_status = str(context.get("weekly_status") or "")
    weekly_html = (
        f'<span class="quota-horizon weekly">{html.escape(weekly_status)}</span>'
        if weekly_status
        else ""
    )
    return f"""
      <div class="quota-horizons">
        <span class="quota-horizon primary">{html.escape(str(context.get("primary_reset_text") or ""))}</span>
        {weekly_html}
      </div>
    """


def render_quota_stack(context: dict[str, Any]) -> str:
    count_html = context.get("count_html")
    if isinstance(count_html, str) and count_html:
        return count_html

    primary_style = float(context.get("primary_style") or 0.0)
    weekly_style = float(context.get("weekly_style") or 0.0)
    primary_text = str(context.get("primary_text") or "")
    weekly_text = str(context.get("weekly_text") or "")
    primary_empty = str(context.get("primary_empty") or "")
    aria = str(context.get("aria") or "")
    weekly_label_html = (
        f'<span class="quota-weekly-label">{html.escape(weekly_text)}</span>'
        if weekly_text
        else ""
    )

    return f"""
      <div class="quota-stack">
        <div class="quota-stack-row">
          <div class="quota-stack-bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="{primary_style:.0f}" aria-label="{html.escape(aria)}">
            <span class="quota-weekly-fill" style="width: {weekly_style:.2f}%"></span>
            <span class="quota-primary-fill{primary_empty}" style="width: {primary_style:.2f}%">
              <span class="quota-primary-label">{html.escape(primary_text)}</span>
            </span>
          </div>
          {weekly_label_html}
        </div>
      </div>
    """


def render_quota_bucket(bucket: dict[str, Any]) -> str:
    name = html.escape(str(bucket.get("name") or "Quota bucket"))
    feature = html.escape(str(bucket.get("metered_feature") or ""))
    rate_limit = bucket.get("rate_limit")
    if not isinstance(rate_limit, dict):
        return ""

    feature_html = f'<span class="quota-feature">{feature}</span>' if feature and feature != "codex" else ""
    context = quota_stack_context(rate_limit)
    stack_html = render_quota_stack(context)
    horizons_html = render_quota_horizons(context)
    return f"""
      <div class="quota-bucket">
        <div class="quota-title">
          <span class="quota-bucket-name">{name}</span>
          {feature_html}
          {horizons_html}
        </div>
        {stack_html}
      </div>
    """


def render_quota_refresh_control(profile: str | None, token: str | None) -> str:
    if not profile or not token:
        return '<span class="quota-refresh-spacer"></span>'
    escaped_profile = html.escape(profile)
    return f"""
      <form method="post" action="/api/refresh-quota" class="quota-refresh-form" data-action="refresh_quota" data-profile="{escaped_profile}">
        <input type="hidden" name="token" value="{html.escape(token)}">
        <input type="hidden" name="profile" value="{escaped_profile}">
        <button class="quota-refresh-icon" aria-label="Refresh quota" title="Refresh quota">
          <svg class="quota-refresh-glyph" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M20 12a8 8 0 1 1-2.34-5.66"></path>
            <path d="M20 4v5h-5"></path>
          </svg>
        </button>
      </form>
    """


def render_quota_panel(
    body_html: str,
    updated_label: str,
    *,
    profile: str | None = None,
    token: str | None = None,
    error_html: str = "",
) -> str:
    label = updated_label or "No quota cached"
    return f"""
      <div class="quota-panel">
        <div class="quota-panel-head">
          {render_quota_refresh_control(profile, token)}
          <span class="quota-updated">{html.escape(label)}</span>
        </div>
        {body_html}
        {error_html}
      </div>
    """


def render_quota_html(
    entry: dict[str, Any] | None,
    updated_label: str | None = None,
    profile: str | None = None,
    token: str | None = None,
) -> str:
    if not entry:
        return render_quota_panel(
            '<div class="quota-empty">No quota cached</div>',
            updated_label or "",
            profile=profile,
            token=token,
        )
    payload = entry.get("payload")
    error = entry.get("error")
    if not isinstance(payload, dict):
        if error:
            return render_quota_panel(
                f'<div class="quota-empty error">Refresh failed: {html.escape(str(error))}</div>',
                updated_label or "",
                profile=profile,
                token=token,
            )
        return render_quota_panel(
            '<div class="quota-empty">No quota cached</div>',
            updated_label or "",
            profile=profile,
            token=token,
        )

    buckets = quota_bucket_rows(payload)
    if updated_label is None:
        updated_label = quota_updated_label(entry)
    if buckets:
        bucket_html = "".join(render_quota_bucket(bucket) for bucket in buckets)
    else:
        bucket_html = '<div class="quota-muted">Quota payload has no bucket details</div>'
    error_html = (
        f'<div class="quota-refresh-error">Last refresh failed: {html.escape(str(error))}</div>'
        if error
        else ""
    )
    return render_quota_panel(
        bucket_html,
        updated_label or "",
        profile=profile,
        token=token,
        error_html=error_html,
    )


def quota_updated_label(entry: dict[str, Any] | None) -> str:
    if not entry:
        return ""
    payload = entry.get("payload")
    fetched_at = entry.get("fetched_at")
    if isinstance(payload, dict) and isinstance(fetched_at, datetime):
        return f"Updated {format_status_updated_at(fetched_at)}"
    return ""


class ProvisionServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], paths: Paths) -> None:
        super().__init__(server_address, Handler)
        self.paths = paths
        self.store = Store(paths)
        self.proxy_token = self.store.proxy_token()
        self.active_requests: dict[int, dict[str, Any]] = {}
        self.active_websockets: dict[int, dict[str, Any]] = {}
        self.active_lock = threading.Lock()
        self.next_request_id = 0
        self.next_websocket_id = 0
        self.observed_sessions: dict[str, dict[str, Any]] = {}
        self.pinned_sessions: dict[str, str] = self.load_pinned_sessions()
        self.usage_cache: dict[str, dict[str, Any]] = {}
        self.usage_cache_lock = threading.Lock()
        self.usage_refresh_lock = threading.Lock()
        self.last_usage_refresh_monotonic = 0.0
        self.usage_auto_refresh_stop = threading.Event()
        self.usage_auto_refresh_thread: threading.Thread | None = None

    def load_pinned_sessions(self) -> dict[str, str]:
        try:
            with self.paths.session_pins.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(payload, dict):
            return {}
        pins: dict[str, str] = {}
        for raw_key, raw_profile in payload.items():
            if not isinstance(raw_key, str) or not isinstance(raw_profile, str):
                continue
            key = normalize_session_key(raw_key)
            if key and self.store.profile_exists(raw_profile):
                pins[key] = raw_profile
        return pins

    def save_pinned_sessions_locked(self) -> None:
        try:
            self.paths.session_pins.parent.mkdir(parents=True, exist_ok=True)
            temp = self.paths.session_pins.with_suffix(self.paths.session_pins.suffix + ".tmp")
            encoded = json.dumps(dict(sorted(self.pinned_sessions.items())), indent=2) + "\n"
            with temp.open("w", encoding="utf-8") as handle:
                handle.write(encoded)
            temp.chmod(0o600)
            temp.replace(self.paths.session_pins)
            self.paths.session_pins.chmod(0o600)
        except OSError as exc:
            raise StoreError(f"failed to save session pins: {exc}") from exc

    def observe_session(self, cwd: str, profile: str | None = None) -> str:
        key = normalize_session_key(cwd)
        if not key:
            return ""
        with self.active_lock:
            self.observe_session_locked(key, cwd, profile)
        return key

    def observe_session_locked(self, key: str, cwd: str, profile: str | None = None) -> None:
        now = time.monotonic()
        record = self.observed_sessions.setdefault(
            key,
            {
                "key": key,
                "cwd": cwd,
                "display": compact_session_path(cwd),
                "name": session_display_name(cwd),
                "first_seen_monotonic": now,
            },
        )
        record["cwd"] = cwd
        record["display"] = compact_session_path(cwd)
        record["name"] = session_display_name(cwd)
        record["last_seen_monotonic"] = now
        record["last_seen_at"] = datetime.now().astimezone()
        if profile:
            record["last_profile"] = profile

    def session_pinned_locked(self, session_key: str | None) -> bool:
        return bool(session_key and session_key in self.pinned_sessions)

    def pinned_profile_for_session(self, session_key: str | None) -> str | None:
        if not session_key:
            return None
        with self.active_lock:
            profile = self.pinned_sessions.get(session_key)
        if profile and self.store.profile_exists(profile):
            return profile
        return None

    def profile_for_session(self, session_key: str | None) -> str:
        pinned_profile = self.pinned_profile_for_session(session_key)
        if pinned_profile:
            return pinned_profile
        profile = self.store.active_profile()
        assert profile is not None
        return profile

    def pin_session(self, session_key: str, profile: str) -> None:
        if not self.store.profile_exists(profile):
            raise StoreError(f"unknown profile: {profile}")
        with self.active_lock:
            record = self.observed_sessions.get(session_key)
            if record is None:
                raise StoreError("unknown session")
            active_profile = self.active_profile_for_session_locked(session_key)
            if active_profile and active_profile != profile:
                raise StoreError(
                    f"session is active under profile {active_profile}; pin it after it becomes idle"
                )
            self.pinned_sessions[session_key] = profile
            record["pinned_profile"] = profile
            record["last_seen_monotonic"] = time.monotonic()
            record["last_seen_at"] = datetime.now().astimezone()
            self.save_pinned_sessions_locked()

    def unpin_session(self, session_key: str, profile: str | None = None) -> None:
        with self.active_lock:
            pinned = self.pinned_sessions.get(session_key)
            if profile and pinned and pinned != profile:
                raise StoreError(f"session is pinned to profile {pinned}")
            self.pinned_sessions.pop(session_key, None)
            record = self.observed_sessions.get(session_key)
            if record is not None:
                record.pop("pinned_profile", None)
                record["last_seen_monotonic"] = time.monotonic()
                record["last_seen_at"] = datetime.now().astimezone()
            self.save_pinned_sessions_locked()

    def active_profile_for_session_locked(self, session_key: str) -> str | None:
        self.expire_websocket_work_locked()
        for request in self.active_requests.values():
            if request.get("session_key") == session_key:
                return str(request.get("profile") or "")
        now = time.monotonic()
        for tunnel in self.active_websockets.values():
            if tunnel.get("session_key") != session_key:
                continue
            if int(tunnel.get("pending_work") or 0) > 0:
                return str(tunnel.get("profile") or "")
            last_data = float(tunnel.get("last_data_activity_monotonic") or 0.0)
            if now - last_data < WEBSOCKET_SWITCH_IDLE_SECONDS:
                return str(tunnel.get("profile") or "")
        return None

    def begin_request(self, profile: str, session_key: str | None = None) -> int:
        with self.active_lock:
            self.next_request_id += 1
            request_id = self.next_request_id
            self.active_requests[request_id] = {
                "profile": profile,
                "session_key": session_key,
                "started_monotonic": time.monotonic(),
            }
            return request_id

    def end_request(self, request_id: int | None) -> None:
        with self.active_lock:
            if request_id is not None:
                self.active_requests.pop(request_id, None)

    def request_count(self, *, blocking_only: bool = False) -> int:
        with self.active_lock:
            return sum(
                1
                for request in self.active_requests.values()
                if not blocking_only or not self.session_pinned_locked(request.get("session_key"))
            )

    def begin_websocket(
        self,
        profile: str,
        downstream: socket.socket,
        session_key: str | None = None,
    ) -> int:
        with self.active_lock:
            self.next_websocket_id += 1
            tunnel_id = self.next_websocket_id
            now = time.monotonic()
            self.active_websockets[tunnel_id] = {
                "profile": profile,
                "session_key": session_key,
                "downstream": downstream,
                "upstream": None,
                "pending_work": 0,
                "turn_id": None,
                "saw_tool_output": False,
                "completion_deadline_monotonic": None,
                "started_monotonic": now,
                "last_data_activity_monotonic": 0.0,
            }
            return tunnel_id

    def attach_websocket_session(
        self,
        tunnel_id: int,
        session_key: str,
        cwd: str,
        profile: str | None = None,
    ) -> None:
        with self.active_lock:
            tunnel = self.active_websockets.get(tunnel_id)
            if tunnel is not None:
                tunnel["session_key"] = session_key
                profile = profile or str(tunnel.get("profile") or "")
            self.observe_session_locked(session_key, cwd, profile)

    def attach_websocket_upstream(self, tunnel_id: int, upstream: socket.socket) -> None:
        with self.active_lock:
            tunnel = self.active_websockets.get(tunnel_id)
            if tunnel is not None:
                tunnel["upstream"] = upstream

    def touch_websocket_data(self, tunnel_id: int) -> None:
        with self.active_lock:
            tunnel = self.active_websockets.get(tunnel_id)
            if tunnel is not None:
                tunnel["last_data_activity_monotonic"] = time.monotonic()

    def begin_websocket_work(self, tunnel_id: int, turn_id: str | None = None) -> None:
        with self.active_lock:
            tunnel = self.active_websockets.get(tunnel_id)
            if tunnel is not None:
                tunnel["pending_work"] = 1
                tunnel["turn_id"] = turn_id
                tunnel["saw_tool_output"] = False
                tunnel["completion_deadline_monotonic"] = None
                tunnel["last_data_activity_monotonic"] = time.monotonic()

    def mark_websocket_tool_output(self, tunnel_id: int) -> None:
        with self.active_lock:
            tunnel = self.active_websockets.get(tunnel_id)
            if tunnel is not None and int(tunnel.get("pending_work") or 0) > 0:
                tunnel["saw_tool_output"] = True
                tunnel["last_data_activity_monotonic"] = time.monotonic()

    def complete_websocket_response(
        self,
        tunnel_id: int,
        *,
        saw_tool_output: bool = False,
    ) -> None:
        with self.active_lock:
            tunnel = self.active_websockets.get(tunnel_id)
            if tunnel is None or int(tunnel.get("pending_work") or 0) <= 0:
                return
            now = time.monotonic()
            has_tool_output = saw_tool_output or bool(tunnel.get("saw_tool_output"))
            fallback = (
                WEBSOCKET_TOOL_COMPLETION_FALLBACK_SECONDS
                if has_tool_output
                else WEBSOCKET_COMPLETION_FALLBACK_SECONDS
            )
            tunnel["pending_work"] = 1
            tunnel["saw_tool_output"] = has_tool_output
            tunnel["completion_deadline_monotonic"] = now + fallback
            tunnel["last_data_activity_monotonic"] = now

    def finish_websocket_work(self, tunnel_id: int) -> None:
        with self.active_lock:
            tunnel = self.active_websockets.get(tunnel_id)
            if tunnel is not None:
                tunnel["pending_work"] = 0
                tunnel["turn_id"] = None
                tunnel["saw_tool_output"] = False
                tunnel["completion_deadline_monotonic"] = None
                tunnel["last_data_activity_monotonic"] = time.monotonic()

    def finish_websocket_work_for_turn(self, turn_id: str) -> int:
        finished = 0
        with self.active_lock:
            for tunnel in self.active_websockets.values():
                if tunnel.get("turn_id") != turn_id:
                    continue
                tunnel["pending_work"] = 0
                tunnel["turn_id"] = None
                tunnel["saw_tool_output"] = False
                tunnel["completion_deadline_monotonic"] = None
                tunnel["last_data_activity_monotonic"] = time.monotonic()
                finished += 1
        return finished

    def session_for_turn_ids(self, turn_ids: list[str]) -> dict[str, str] | None:
        wanted = {turn_id for turn_id in turn_ids if turn_id}
        if not wanted:
            return None
        with self.active_lock:
            for tunnel in self.active_websockets.values():
                if tunnel.get("turn_id") not in wanted:
                    continue
                session_key = str(tunnel.get("session_key") or "")
                if not session_key:
                    continue
                record = self.observed_sessions.get(session_key)
                cwd = str(record.get("cwd") or session_key) if isinstance(record, dict) else session_key
                return {"key": session_key, "cwd": cwd}
        return None

    def expire_websocket_work_locked(self) -> None:
        now = time.monotonic()
        for tunnel in self.active_websockets.values():
            if int(tunnel.get("pending_work") or 0) <= 0:
                continue
            deadline = tunnel.get("completion_deadline_monotonic")
            if isinstance(deadline, (int, float)) and now >= float(deadline):
                tunnel["pending_work"] = 0
                tunnel["turn_id"] = None
                tunnel["saw_tool_output"] = False
                tunnel["completion_deadline_monotonic"] = None

    def end_websocket(self, tunnel_id: int) -> None:
        with self.active_lock:
            self.active_websockets.pop(tunnel_id, None)

    def websocket_count(self, *, blocking_only: bool = False) -> int:
        with self.active_lock:
            return sum(
                1
                for tunnel in self.active_websockets.values()
                if not blocking_only or not self.session_pinned_locked(tunnel.get("session_key"))
            )

    def active_websocket_work_count(self, *, blocking_only: bool = False) -> int:
        with self.active_lock:
            self.expire_websocket_work_locked()
            return sum(
                1
                for tunnel in self.active_websockets.values()
                if int(tunnel.get("pending_work") or 0) > 0
                and (not blocking_only or not self.session_pinned_locked(tunnel.get("session_key")))
            )

    def pending_websocket_work_count(self, *, blocking_only: bool = False) -> int:
        with self.active_lock:
            self.expire_websocket_work_locked()
            return sum(
                1
                for tunnel in self.active_websockets.values()
                if int(tunnel.get("pending_work") or 0) > 0
                and (not blocking_only or not self.session_pinned_locked(tunnel.get("session_key")))
            )

    def recent_websocket_data_activity_count(
        self,
        seconds: float = WEBSOCKET_SWITCH_IDLE_SECONDS,
        *,
        blocking_only: bool = False,
    ) -> int:
        now = time.monotonic()
        with self.active_lock:
            return sum(
                1
                for tunnel in self.active_websockets.values()
                if now - float(tunnel.get("last_data_activity_monotonic") or 0.0) < seconds
                and (not blocking_only or not self.session_pinned_locked(tunnel.get("session_key")))
            )

    def switch_block_reason(self) -> str | None:
        active_requests = self.request_count(blocking_only=True)
        if active_requests > 0:
            return f"{active_requests} upstream request(s) are active"
        active_tunnels = self.active_websocket_work_count(blocking_only=True)
        if active_tunnels > 0:
            return f"{active_tunnels} Codex CLI response tunnel(s) have pending work"
        return None

    def close_websocket_tunnels(self, *, blocking_only: bool = False) -> int:
        sockets: list[socket.socket] = []
        with self.active_lock:
            tunnels = [
                tunnel
                for tunnel in self.active_websockets.values()
                if not blocking_only or not self.session_pinned_locked(tunnel.get("session_key"))
            ]
            count = len(tunnels)
            for tunnel in tunnels:
                for key in ("downstream", "upstream"):
                    value = tunnel.get(key)
                    if isinstance(value, socket.socket):
                        sockets.append(value)
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        return count

    def session_snapshots(self) -> list[dict[str, Any]]:
        with self.active_lock:
            self.expire_websocket_work_locked()
            now = time.monotonic()
            snapshots = []
            for key, record in self.observed_sessions.items():
                active_requests = sum(
                    1 for request in self.active_requests.values() if request.get("session_key") == key
                )
                active_tunnels = sum(
                    1 for tunnel in self.active_websockets.values() if tunnel.get("session_key") == key
                )
                pending_work = sum(
                    1
                    for tunnel in self.active_websockets.values()
                    if tunnel.get("session_key") == key and int(tunnel.get("pending_work") or 0) > 0
                )
                recent_activity = sum(
                    1
                    for tunnel in self.active_websockets.values()
                    if tunnel.get("session_key") == key
                    and now - float(tunnel.get("last_data_activity_monotonic") or 0.0)
                    < WEBSOCKET_SWITCH_IDLE_SECONDS
                )
                pinned_profile = self.pinned_sessions.get(key)
                snapshots.append(
                    {
                        "key": key,
                        "cwd": str(record.get("cwd") or key),
                        "display": str(record.get("display") or compact_session_path(key)),
                        "name": str(record.get("name") or session_display_name(key)),
                        "last_profile": record.get("last_profile"),
                        "pinned_profile": pinned_profile,
                        "active_requests": active_requests,
                        "active_tunnels": active_tunnels,
                        "pending_websocket_work": pending_work,
                        "recent_websocket_activity": recent_activity,
                        "active": active_requests > 0 or pending_work > 0 or recent_activity > 0,
                        "last_seen_monotonic": record.get("last_seen_monotonic") or 0.0,
                    }
                )
        snapshots.sort(key=lambda item: float(item.get("last_seen_monotonic") or 0.0), reverse=True)
        return snapshots

    def pinned_sessions_for_profile(self, profile: str) -> list[dict[str, Any]]:
        return [
            session
            for session in self.session_snapshots()
            if session.get("pinned_profile") == profile
        ]

    def profile_has_active_sessions(self, profile: str, *, pinned_only: bool = False) -> bool:
        with self.active_lock:
            self.expire_websocket_work_locked()
            now = time.monotonic()
            for request in self.active_requests.values():
                if request.get("profile") != profile:
                    continue
                pinned = self.session_pinned_locked(request.get("session_key"))
                if not pinned_only or pinned:
                    return True
            for tunnel in self.active_websockets.values():
                if tunnel.get("profile") != profile:
                    continue
                pinned = self.session_pinned_locked(tunnel.get("session_key"))
                if pinned_only and not pinned:
                    continue
                if int(tunnel.get("pending_work") or 0) > 0:
                    return True
                last_data = float(tunnel.get("last_data_activity_monotonic") or 0.0)
                if now - last_data < WEBSOCKET_SWITCH_IDLE_SECONDS:
                    return True
        return False

    def cached_usage_payload(
        self,
        profile: str,
        fetcher: Callable[[], dict[str, Any] | None],
        *,
        force: bool = False,
    ) -> tuple[dict[str, Any], datetime | None, str]:
        now = time.monotonic()
        should_fetch = False
        fetch_event: threading.Event | None = None
        with self.usage_cache_lock:
            entry = self.usage_cache.setdefault(profile, {})
            payload = entry.get("payload")
            fetched_monotonic = entry.get("fetched_monotonic")
            if (
                isinstance(payload, dict)
                and isinstance(fetched_monotonic, (float, int))
                and now - fetched_monotonic < USAGE_CACHE_MIN_INTERVAL_SECONDS
            ):
                return payload, entry.get("fetched_at"), "cached"
            event = entry.get("event")
            if isinstance(event, threading.Event):
                fetch_event = event
            else:
                fetch_event = threading.Event()
                entry["event"] = fetch_event
                entry["force"] = force
                should_fetch = True

        if not should_fetch:
            assert fetch_event is not None
            fetch_event.wait(USAGE_CACHE_WAIT_SECONDS)
            with self.usage_cache_lock:
                entry = self.usage_cache.get(profile, {})
                payload = entry.get("payload")
                if isinstance(payload, dict):
                    return payload, entry.get("fetched_at"), "cached"
                error = entry.get("error") or "usage refresh did not complete"
            raise AuthError(str(error))

        assert fetch_event is not None
        try:
            self.wait_for_usage_refresh_slot()
            payload = fetcher()
            if not isinstance(payload, dict):
                raise AuthError("usage response was not a JSON object")
            fetched_at = datetime.now().astimezone()
        except Exception as exc:
            with self.usage_cache_lock:
                entry = self.usage_cache.setdefault(profile, {})
                entry["error"] = str(exc)
                entry["event"] = None
                stale_payload = entry.get("payload")
                stale_fetched_at = entry.get("fetched_at")
                fetch_event.set()
            if isinstance(stale_payload, dict):
                return stale_payload, stale_fetched_at, "stale"
            raise

        with self.usage_cache_lock:
            entry = self.usage_cache.setdefault(profile, {})
            entry["payload"] = payload
            entry["fetched_at"] = fetched_at
            entry["fetched_monotonic"] = time.monotonic()
            entry["error"] = None
            entry["event"] = None
            fetch_event.set()
        return payload, fetched_at, "fresh"

    def update_usage_cache_from_observation(
        self,
        profile: str,
        payload_update: dict[str, Any] | None,
        *,
        source: str,
    ) -> bool:
        if not profile or not isinstance(payload_update, dict):
            return False
        fetched_at = datetime.now().astimezone()
        with self.usage_cache_lock:
            entry = self.usage_cache.setdefault(profile, {})
            entry["payload"] = merge_usage_payload(entry.get("payload"), payload_update)
            entry["fetched_at"] = fetched_at
            entry["fetched_monotonic"] = time.monotonic()
            entry["error"] = None
            entry["source"] = source
        return True

    def update_usage_cache_from_rate_limit_headers(self, profile: str, headers: Any) -> bool:
        return self.update_usage_cache_from_observation(
            profile,
            usage_payload_from_rate_limit_headers(headers),
            source="response_headers",
        )

    def update_usage_cache_from_websocket_message(
        self,
        profile: str,
        opcode: int,
        payload: bytes,
    ) -> bool:
        return self.update_usage_cache_from_observation(
            profile,
            usage_payload_from_websocket_message(opcode, payload),
            source="websocket_event",
        )

    def usage_cache_snapshot(self, profile: str) -> dict[str, Any] | None:
        with self.usage_cache_lock:
            entry = self.usage_cache.get(profile)
            return dict(entry) if entry else None

    def usage_payload_for_profile(
        self,
        profile: str,
        *,
        force: bool = False,
    ) -> tuple[dict[str, Any], datetime | None, str]:
        return self.cached_usage_payload(
            profile,
            lambda: self.fetch_usage_payload_uncached(profile),
            force=force,
        )

    def fetch_usage_payload_uncached(
        self,
        profile: str,
        *,
        retry_on_401: bool = True,
    ) -> dict[str, Any] | None:
        auth_path = self.store.auth_path(profile)
        auth = ensure_fresh_chatgpt_auth(auth_path)
        url = upstream_chatgpt_backend_base_url(auth).rstrip("/") + CHATGPT_USAGE_PATH
        request = urllib.request.Request(
            url,
            headers={
                "accept-encoding": "identity",
                **upstream_auth_headers(auth),
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if retry_on_401 and exc.code == 401 and self.is_chatgpt_profile(auth_path):
                force_refresh_chatgpt_auth(auth_path)
                return self.fetch_usage_payload_uncached(profile, retry_on_401=False)
            raise
        return payload if isinstance(payload, dict) else None

    def is_chatgpt_profile(self, auth_path: Path) -> bool:
        try:
            with auth_path.open("r", encoding="utf-8") as handle:
                auth = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return False
        return isinstance(auth.get("tokens"), dict)

    def usage_auto_refresh_due_profiles(self, now: datetime | None = None) -> list[str]:
        now = now.astimezone() if now else datetime.now().astimezone()
        monotonic_now = time.monotonic()
        due_profiles: list[str] = []
        profiles = self.store.profile_names()
        with self.usage_cache_lock:
            for profile in profiles:
                entry = self.usage_cache.get(profile)
                if usage_refresh_due_at(entry, now) > now:
                    continue
                attempted = entry.get("auto_refresh_attempted_monotonic") if isinstance(entry, dict) else None
                if (
                    isinstance(attempted, (float, int))
                    and monotonic_now - float(attempted) < USAGE_AUTO_REFRESH_ERROR_BACKOFF_SECONDS
                ):
                    continue
                due_profiles.append(profile)
        return due_profiles

    def mark_usage_auto_refresh_attempt(self, profile: str) -> None:
        with self.usage_cache_lock:
            entry = self.usage_cache.setdefault(profile, {})
            entry["auto_refresh_attempted_monotonic"] = time.monotonic()

    def refresh_due_usage_profiles(self) -> None:
        for profile in self.usage_auto_refresh_due_profiles():
            if self.usage_auto_refresh_stop.is_set():
                return
            self.mark_usage_auto_refresh_attempt(profile)
            try:
                self.usage_payload_for_profile(profile, force=True)
            except (
                AuthError,
                urllib.error.URLError,
                TimeoutError,
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ) as exc:
                sys.stderr.write(f"usage auto-refresh for profile {profile} failed: {exc}\n")

    def usage_auto_refresh_loop(self) -> None:
        while not self.usage_auto_refresh_stop.is_set():
            self.refresh_due_usage_profiles()
            self.usage_auto_refresh_stop.wait(USAGE_AUTO_REFRESH_POLL_SECONDS)

    def start_usage_auto_refresh(self) -> None:
        if self.usage_auto_refresh_thread and self.usage_auto_refresh_thread.is_alive():
            return
        self.usage_auto_refresh_stop.clear()
        self.usage_auto_refresh_thread = threading.Thread(
            target=self.usage_auto_refresh_loop,
            name="provision-usage-auto-refresh",
            daemon=True,
        )
        self.usage_auto_refresh_thread.start()

    def stop_usage_auto_refresh(self) -> None:
        self.usage_auto_refresh_stop.set()
        if self.usage_auto_refresh_thread:
            self.usage_auto_refresh_thread.join(timeout=2)

    def wait_for_usage_refresh_slot(self) -> None:
        with self.usage_refresh_lock:
            now = time.monotonic()
            delay = USAGE_CACHE_MIN_INTERVAL_SECONDS - (now - self.last_usage_refresh_monotonic)
            if delay > 0:
                time.sleep(delay)
            self.last_usage_refresh_monotonic = time.monotonic()


class Handler(BaseHTTPRequestHandler):
    server: ProvisionServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        message = format % args
        message = redact_proxy_token(message, self.server.proxy_token)
        sys.stderr.write(
            "%s %s\n"
            % (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                message,
            )
        )

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/health":
            self.send_json(self.status_payload())
            return
        if parsed.path in ("/", "/ui"):
            self.send_html(self.render_ui())
            return
        if parsed.path in (
            "/assets/provision.png",
            "/assets/provision-wordmark.png",
        ):
            self.send_logo_asset(parsed.path.rsplit("/", 1)[-1])
            return
        if parsed.path == "/api/status":
            self.send_json(self.status_payload(include_profiles=True))
            return
        if parsed.path == "/api/ui-ws":
            self.handle_ui_websocket(parsed)
            return
        if parsed.path == "/v1/models":
            self.proxy_to_upstream("GET", parsed)
            return
        if parsed.path == "/v1/responses":
            self.proxy_websocket(parsed)
            return
        if self.is_chatgpt_backend_proxy_path(parsed.path):
            self.proxy_to_upstream("GET", parsed, route=UpstreamRoute.CHATGPT_BACKEND)
            return
        if parsed.path.startswith("/backend-api/"):
            self.send_json({"error": "invalid ChatGPT backend proxy path token"}, status=401)
            return
        self.send_error(404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/switch":
            self.handle_switch()
            return
        if parsed.path == "/api/refresh-quota":
            self.handle_refresh_quota()
            return
        if parsed.path == "/api/session":
            self.handle_observe_session()
            return
        if parsed.path == "/api/pin-session":
            self.handle_pin_session()
            return
        if parsed.path in ("/v1/responses", "/v1/responses/compact"):
            self.proxy_to_upstream("POST", parsed)
            return
        if self.is_chatgpt_backend_proxy_path(parsed.path):
            self.proxy_to_upstream("POST", parsed, route=UpstreamRoute.CHATGPT_BACKEND)
            return
        if parsed.path.startswith("/backend-api/"):
            self.send_json({"error": "invalid ChatGPT backend proxy path token"}, status=401)
            return
        self.send_error(404)

    def handle_switch(self) -> None:
        try:
            data = self.read_post_fields()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        profile = data.get("profile")
        token = data.get("token")

        if token != self.server.proxy_token:
            self.send_json({"error": "invalid switch token"}, status=401)
            return
        block_reason = self.server.switch_block_reason()
        if block_reason:
            self.send_json({"error": f"proxy is busy; {block_reason}"}, status=409)
            return
        try:
            self.server.store.set_active_profile(str(profile))
        except StoreError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        self.server.close_websocket_tunnels(blocking_only=True)
        self.redirect_ui()

    def handle_refresh_quota(self) -> None:
        try:
            data = self.read_post_fields()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        profile = str(data.get("profile") or "")
        token = data.get("token")
        if token != self.server.proxy_token:
            self.send_json({"error": "invalid UI token"}, status=401)
            return
        if not self.server.store.profile_exists(profile):
            self.send_json({"error": f"unknown profile: {profile}"}, status=400)
            return
        try:
            self.usage_payload_for_profile(profile, force=True)
        except (
            AuthError,
            urllib.error.URLError,
            TimeoutError,
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            self.log_message("usage refresh for profile %s failed: %s", profile, exc)
        self.redirect_ui()

    def handle_observe_session(self) -> None:
        try:
            data = self.read_post_fields()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        token = data.get("token")
        cwd = str(data.get("cwd") or "")
        if token != self.server.proxy_token:
            self.send_json({"error": "invalid UI token"}, status=401)
            return
        session_key = normalize_session_key(cwd)
        profile = self.server.profile_for_session(session_key)
        session_key = self.server.observe_session(cwd, profile)
        self.send_json({"ok": True, "session_key": session_key})

    def handle_pin_session(self) -> None:
        try:
            data = self.read_post_fields()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        token = data.get("token")
        if token != self.server.proxy_token:
            self.send_json({"error": "invalid UI token"}, status=401)
            return
        profile = str(data.get("profile") or "")
        session_key = str(data.get("session_key") or "")
        action = str(data.get("action") or "pin_session")
        try:
            if action == "unpin_session":
                self.server.unpin_session(session_key, profile or None)
            else:
                self.server.pin_session(session_key, profile)
        except StoreError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        self.redirect_ui()

    def read_post_fields(self) -> dict[str, Any]:
        content_type = self.headers.get("content-type", "")
        raw = self.rfile.read(int(self.headers.get("content-length", "0") or "0"))
        if "application/json" in content_type:
            try:
                data = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                raise ValueError("invalid JSON") from None
            return data if isinstance(data, dict) else {}
        form = urllib.parse.parse_qs(raw.decode("utf-8"))
        return {
            key: values[0]
            for key, values in form.items()
            if values
        }

    def redirect_ui(self) -> None:
        self.send_response(303)
        self.send_header("location", "/ui")
        self.send_header("content-length", "0")
        self.end_headers()

    def handle_ui_websocket(self, parsed: urllib.parse.ParseResult) -> None:
        if self.headers.get("upgrade", "").lower() != "websocket":
            self.send_error(426)
            return
        query = urllib.parse.parse_qs(parsed.query)
        token = query.get("token", [""])[0]
        if token != self.server.proxy_token:
            self.send_json({"error": "invalid UI token"}, status=401)
            return
        key = self.headers.get("sec-websocket-key", "")
        if not key:
            self.send_json({"error": "missing websocket key"}, status=400)
            return

        self.accept_websocket(key)
        self.close_connection = True
        self.connection.settimeout(1.0)
        self.send_ui_state()
        try:
            while True:
                try:
                    message = self.read_websocket_json()
                except socket.timeout:
                    self.send_ui_state()
                    continue
                if message is None:
                    self.send_ui_state()
                    continue
                self.handle_ui_websocket_action(message)
        except WebSocketClosed:
            return
        except (BrokenPipeError, ConnectionResetError, OSError) as exc:
            self.log_message("ui websocket closed: %s", exc)

    def accept_websocket(self, key: str) -> None:
        self.send_response(101)
        self.send_header("upgrade", "websocket")
        self.send_header("connection", "Upgrade")
        self.send_header("sec-websocket-accept", websocket_accept_key(key))
        self.end_headers()

    def handle_ui_websocket_action(self, message: dict[str, Any]) -> None:
        if message.get("token") != self.server.proxy_token:
            self.send_ui_state(message="Invalid UI token")
            return
        profile = str(message.get("profile") or "")
        action = message.get("action")
        if action == "switch":
            block_reason = self.server.switch_block_reason()
            if block_reason:
                self.send_ui_state()
                return
            try:
                self.server.store.set_active_profile(profile)
            except StoreError as exc:
                self.send_ui_state(message=str(exc))
                return
            self.server.close_websocket_tunnels(blocking_only=True)
            self.send_ui_state()
            return
        if action == "refresh_quota":
            if not self.server.store.profile_exists(profile):
                self.send_ui_state(message=f"unknown profile: {profile}")
                return
            self.send_ui_state(
                pending_action="refresh_quota",
                pending_profile=profile,
            )
            try:
                self.usage_payload_for_profile(profile, force=True)
            except (
                AuthError,
                urllib.error.URLError,
                TimeoutError,
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ) as exc:
                self.log_message("usage refresh for profile %s failed: %s", profile, exc)
                self.send_ui_state(message=f"Quota refresh failed for {profile}: {exc}")
                return
            self.send_ui_state()
            return
        if action in {"pin_session", "unpin_session"}:
            session_key = str(message.get("session_key") or "")
            try:
                if action == "unpin_session":
                    self.server.unpin_session(session_key, profile or None)
                else:
                    self.server.pin_session(session_key, profile)
            except StoreError as exc:
                self.send_ui_state(message=str(exc))
                return
            self.send_ui_state()
            return
        self.send_ui_state(message=f"Unknown action: {action}")

    def send_ui_state(
        self,
        *,
        message: str | None = None,
        pending_action: str | None = None,
        pending_profile: str | None = None,
    ) -> None:
        self.send_websocket_json(
            {
                "type": "state",
                "message": message,
                "pending_action": pending_action,
                "pending_profile": pending_profile,
                "status": self.ui_status_payload(),
            }
        )

    def read_websocket_json(self) -> dict[str, Any] | None:
        frame = self.read_websocket_frame()
        if frame is None:
            return None
        opcode, payload = frame
        if opcode == 0x8:
            raise WebSocketClosed()
        if opcode == 0x9:
            self.send_websocket_frame(0xA, payload)
            return None
        if opcode != 0x1:
            return None
        try:
            data = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"action": "invalid"}
        return data if isinstance(data, dict) else None

    def read_websocket_frame(self) -> tuple[int, bytes] | None:
        header = self.recv_exact(2, allow_timeout=True)
        if header is None:
            return None
        first, second = header
        opcode = first & 0x0F
        length = second & 0x7F
        if length == 126:
            extended = self.recv_exact(2)
            length = struct.unpack("!H", extended)[0]
        elif length == 127:
            extended = self.recv_exact(8)
            length = struct.unpack("!Q", extended)[0]
        mask = b""
        if second & 0x80:
            mask = self.recv_exact(4)
        payload = self.recv_exact(length) if length else b""
        if mask:
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        return opcode, payload

    def recv_exact(self, length: int, *, allow_timeout: bool = False) -> bytes | None:
        chunks = bytearray()
        while len(chunks) < length:
            try:
                chunk = self.connection.recv(length - len(chunks))
            except socket.timeout:
                if allow_timeout and not chunks:
                    return None
                raise
            if not chunk:
                raise WebSocketClosed()
            chunks.extend(chunk)
        return bytes(chunks)

    def send_websocket_json(self, data: dict[str, Any]) -> None:
        payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
        self.send_websocket_frame(0x1, payload)

    def send_websocket_frame(self, opcode: int, payload: bytes) -> None:
        length = len(payload)
        if length < 126:
            header = struct.pack("!BB", 0x80 | opcode, length)
        elif length <= 0xFFFF:
            header = struct.pack("!BBH", 0x80 | opcode, 126, length)
        else:
            header = struct.pack("!BBQ", 0x80 | opcode, 127, length)
        self.connection.sendall(header + payload)

    def proxy_to_upstream(
        self,
        method: str,
        parsed: urllib.parse.ParseResult,
        *,
        route: str = UpstreamRoute.CODEX_API,
    ) -> None:
        if route == UpstreamRoute.CODEX_API and not self.authorized_proxy_request():
            self.send_json({"error": "invalid proxy bearer token"}, status=401)
            return
        body = None
        if method != "GET":
            length = int(self.headers.get("content-length", "0") or "0")
            body = self.rfile.read(length)
        upstream_path = self.upstream_path(route, parsed)
        session = self.request_session(
            body,
            route=route,
            method=method,
            upstream_path=upstream_path,
        )
        session_key = session.get("key") if session else None
        profile = self.server.profile_for_session(session_key)
        if session and session_key and session.get("cwd"):
            self.server.observe_session(str(session["cwd"]), profile)
        request_id = self.server.begin_request(profile, session_key)
        started = time.monotonic()
        status_code: int | None = None
        try:
            status_code = self._proxy_to_upstream_once(
                method,
                parsed,
                body=body,
                retry_on_401=True,
                route=route,
                profile=profile,
            )
        finally:
            elapsed = time.monotonic() - started
            self.log_message(
                "http proxy %s %s for profile %s completed status=%s duration=%.3fs",
                method,
                parsed.path,
                profile,
                status_code if status_code is not None else "unknown",
                elapsed,
            )
            self.server.end_request(request_id)

    def _proxy_to_upstream_once(
        self,
        method: str,
        parsed: urllib.parse.ParseResult,
        *,
        body: bytes | None,
        retry_on_401: bool,
        route: str,
        profile: str,
    ) -> int:
        upstream_path = self.upstream_path(route, parsed)
        self.monitor_analytics_events(route, method, upstream_path, body)
        if self.should_label_usage_request(route, method, upstream_path):
            try:
                payload, updated_at, cache_state = self.usage_payload_for_profile(profile)
                labeled = self.label_usage_payload_for_profile(payload, profile, updated_at)
            except (
                AuthError,
                urllib.error.URLError,
                TimeoutError,
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ) as exc:
                self.send_json({"error": str(exc)}, status=502)
                return 502
            self.log_message(
                "usage response for profile %s served from %s cache",
                profile,
                cache_state,
            )
            self.send_json(labeled)
            return 200

        auth_path = self.server.store.auth_path(profile)
        auth = ensure_fresh_chatgpt_auth(auth_path)

        url = self.upstream_url(route, parsed, auth, upstream_path=upstream_path)
        if parsed.query:
            url += "?" + parsed.query

        headers = self.forward_headers()
        headers.update(upstream_auth_headers(auth))

        self.log_message("http upstream %s %s for profile %s", method, parsed.path, profile)
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=600) as response:
                if self.server.update_usage_cache_from_rate_limit_headers(profile, response.headers):
                    self.log_message(
                        "quota cache for profile %s updated from response headers",
                        profile,
                    )
                if self.should_label_usage_response(route, method, upstream_path, response.headers):
                    payload = response.read()
                    labeled = self.label_usage_response(payload, profile, datetime.now().astimezone())
                    if labeled is not None:
                        self.send_json(labeled, status=response.status)
                        return response.status
                    self.send_response_bytes(response.status, response.headers, payload)
                    return response.status

                self.send_response(response.status)
                self.forward_response_headers(response.headers)
                self.prepare_close_delimited_response(response.headers)
                self.end_headers()
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    if not self.write_downstream(chunk):
                        return response.status
                return response.status
        except urllib.error.HTTPError as exc:
            if retry_on_401 and exc.code == 401 and self.is_chatgpt_profile(auth_path):
                try:
                    force_refresh_chatgpt_auth(auth_path)
                except AuthError as refresh_exc:
                    self.send_json({"error": str(refresh_exc)}, status=401)
                    return 401
                return self._proxy_to_upstream_once(
                    method,
                    parsed,
                    body=body,
                    retry_on_401=False,
                    route=route,
                    profile=profile,
                )
            self.send_response(exc.code)
            if self.server.update_usage_cache_from_rate_limit_headers(profile, exc.headers):
                self.log_message(
                    "quota cache for profile %s updated from error response headers",
                    profile,
                )
            self.forward_response_headers(exc.headers)
            self.prepare_close_delimited_response(exc.headers)
            self.end_headers()
            detail = exc.read()
            if detail:
                self.write_downstream(detail)
            return exc.code
        except (urllib.error.URLError, TimeoutError, AuthError) as exc:
            self.send_json({"error": str(exc)}, status=502)
            return 502

    def proxy_websocket(self, parsed: urllib.parse.ParseResult) -> None:
        if self.headers.get("upgrade", "").lower() != "websocket":
            self.send_error(426)
            return
        if not self.authorized_proxy_request():
            self.send_json({"error": "invalid proxy bearer token"}, status=401)
            return

        self.close_connection = True
        upstream = None
        tunnel_id: int | None = None
        profile = "unknown"
        try:
            session = self.request_session()
            session_key = session.get("key") if session else None
            profile = self.server.profile_for_session(session_key)
            if session and session_key and session.get("cwd"):
                self.server.observe_session(str(session["cwd"]), profile)
            tunnel_id = self.server.begin_websocket(profile, self.connection, session_key)
            auth_path = self.server.store.auth_path(profile)
            auth = ensure_fresh_chatgpt_auth(auth_path)
            try:
                upstream = self.open_upstream_websocket(parsed, auth, profile=profile)
            except WebSocketHandshakeRejected as exc:
                if exc.status_code != 401 or not self.is_chatgpt_profile(auth_path):
                    raise
                self.log_message(
                    "websocket handshake for profile %s returned 401; refreshing auth and retrying",
                    profile,
                )
                auth = force_refresh_chatgpt_auth(auth_path)
                upstream = self.open_upstream_websocket(parsed, auth, profile=profile)
            self.server.attach_websocket_upstream(tunnel_id, upstream)
            self.log_message("websocket tunnel established for profile %s", profile)
            self.relay_websocket(upstream, tunnel_id, profile)
        except WebSocketHandshakeRejected as exc:
            self.log_message(
                "websocket handshake rejected for profile %s: %s",
                profile,
                exc,
            )
            try:
                self.connection.sendall(exc.response)
            except OSError:
                pass
        except AuthError as exc:
            self.log_message("websocket auth error: %s", exc)
            self.send_json({"error": str(exc)}, status=502)
        except OSError as exc:
            self.log_message("websocket tunnel error: %s", exc)
            try:
                self.send_json({"error": str(exc)}, status=502)
            except OSError:
                pass
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass
            if tunnel_id is not None:
                self.server.end_websocket(tunnel_id)

    def is_chatgpt_backend_proxy_path(self, path: str) -> bool:
        prefixes = (backend_proxy_prefix(self.server.proxy_token), backend_proxy_prefix())
        return any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)

    def upstream_url(
        self,
        route: str,
        parsed: urllib.parse.ParseResult,
        auth: dict[str, Any],
        *,
        upstream_path: str | None = None,
    ) -> str:
        upstream_path = upstream_path if upstream_path is not None else self.upstream_path(route, parsed)
        if route == UpstreamRoute.CODEX_API:
            return upstream_base_url(auth).rstrip("/") + upstream_path
        if route == UpstreamRoute.CHATGPT_BACKEND:
            return upstream_chatgpt_backend_base_url(auth).rstrip("/") + upstream_path
        raise AuthError(f"unknown upstream route: {route}")

    def upstream_path(self, route: str, parsed: urllib.parse.ParseResult) -> str:
        if route == UpstreamRoute.CODEX_API:
            return parsed.path.removeprefix("/v1")
        if route == UpstreamRoute.CHATGPT_BACKEND:
            return backend_upstream_path(parsed.path, self.server.proxy_token)
        raise AuthError(f"unknown upstream route: {route}")

    def should_label_usage_response(
        self,
        route: str,
        method: str,
        upstream_path: str,
        headers: Any,
    ) -> bool:
        if not self.should_label_usage_request(route, method, upstream_path):
            return False
        content_type = headers.get("content-type", "")
        return "application/json" in content_type.lower()

    def should_label_usage_request(self, route: str, method: str, upstream_path: str) -> bool:
        return (
            route == UpstreamRoute.CHATGPT_BACKEND
            and method == "GET"
            and upstream_path == CHATGPT_USAGE_PATH
        )

    def monitor_analytics_events(
        self,
        route: str,
        method: str,
        upstream_path: str,
        body: bytes | None,
    ) -> None:
        if (
            route != UpstreamRoute.CHATGPT_BACKEND
            or method != "POST"
            or upstream_path != CHATGPT_ANALYTICS_EVENTS_PATH
        ):
            return
        for turn_id in analytics_completed_turn_ids(body):
            finished = self.server.finish_websocket_work_for_turn(turn_id)
            if finished:
                self.log_message(
                    "analytics completed turn %s cleared %s websocket tunnel(s)",
                    turn_id,
                    finished,
                )

    def label_usage_response(
        self,
        payload: bytes,
        active_profile: str,
        updated_at: datetime | None = None,
    ) -> dict[str, Any] | None:
        try:
            data = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(data, dict):
            return None
        return self.label_usage_payload_for_profile(data, active_profile, updated_at)

    def label_usage_payload_for_profile(
        self,
        data: dict[str, Any],
        active_profile: str,
        updated_at: datetime | None,
    ) -> dict[str, Any]:
        default_payload = None
        default_profile = "default" if active_profile != "default" else None
        if default_profile and self.server.store.profile_exists(default_profile):
            try:
                default_payload, _, _ = self.usage_payload_for_profile(default_profile)
            except (
                AuthError,
                urllib.error.URLError,
                TimeoutError,
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ) as exc:
                self.log_message(
                    "default profile usage lookup for profile %s failed: %s",
                    default_profile,
                    exc,
                )

        return label_usage_payload(
            data,
            active_profile=active_profile,
            updated_at=updated_at,
            default_profile=default_profile if default_payload else None,
            default_payload=default_payload,
        )

    def usage_payload_for_profile(
        self,
        profile: str,
        *,
        force: bool = False,
    ) -> tuple[dict[str, Any], datetime | None, str]:
        return self.server.usage_payload_for_profile(profile, force=force)

    def fetch_usage_payload_uncached(self, profile: str, *, retry_on_401: bool = True) -> dict[str, Any] | None:
        return self.server.fetch_usage_payload_uncached(profile, retry_on_401=retry_on_401)

    def open_upstream_websocket(
        self,
        parsed: urllib.parse.ParseResult,
        auth: dict[str, Any],
        *,
        profile: str | None = None,
    ) -> ssl.SSLSocket | socket.socket:
        base = urllib.parse.urlparse(upstream_base_url(auth))
        if base.scheme != "https":
            raise OSError(f"websocket upstream requires HTTPS: {upstream_base_url(auth)}")
        host = base.hostname
        if not host:
            raise OSError(f"invalid upstream base URL: {upstream_base_url(auth)}")
        port = base.port or 443
        upstream_path = base.path.rstrip("/") + parsed.path.removeprefix("/v1")
        if parsed.query:
            upstream_path += "?" + parsed.query

        raw = socket.create_connection((host, port), timeout=30)
        upstream: ssl.SSLSocket | socket.socket = ssl.create_default_context().wrap_socket(
            raw,
            server_hostname=host,
        )
        upstream.settimeout(30)

        request = self.websocket_handshake_request(host, upstream_path, auth)
        upstream.sendall(request)
        response = self.read_websocket_handshake_response(upstream)
        if profile and self.server.update_usage_cache_from_rate_limit_headers(
            profile,
            raw_http_response_headers(response),
        ):
            self.log_message(
                "quota cache for profile %s updated from websocket handshake headers",
                profile,
            )
        if websocket_handshake_status(response) != 101:
            try:
                upstream.close()
            except OSError:
                pass
            raise WebSocketHandshakeRejected(response)
        self.connection.sendall(response)
        return upstream

    def websocket_handshake_request(
        self,
        host: str,
        upstream_path: str,
        auth: dict[str, Any],
    ) -> bytes:
        headers = {
            "Host": host,
            "Connection": "Upgrade",
            "Upgrade": "websocket",
        }
        for key, value in self.headers.items():
            lower = key.lower()
            if (
                lower in {"host", "connection", "upgrade", "sec-websocket-extensions"}
                or lower in UPSTREAM_IDENTITY_HEADERS
            ):
                continue
            headers[key] = value
        headers.update(upstream_auth_headers(auth))

        lines = [f"GET {upstream_path} HTTP/1.1"]
        lines.extend(f"{key}: {value}" for key, value in headers.items())
        lines.extend(["", ""])
        return "\r\n".join(lines).encode("iso-8859-1")

    def read_websocket_handshake_response(self, upstream: socket.socket) -> bytes:
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = upstream.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > 65536:
                raise OSError("upstream websocket handshake response is too large")
        if not response:
            raise OSError("upstream websocket handshake returned no response")
        return bytes(response)

    def relay_websocket(self, upstream: socket.socket, tunnel_id: int, profile: str) -> None:
        downstream = self.connection
        upstream.settimeout(None)
        downstream.settimeout(None)
        stop = threading.Event()
        downstream_tracker = WebSocketMessageTracker()
        upstream_tracker = WebSocketMessageTracker()

        def shutdown() -> None:
            stop.set()
            for sock in (upstream, downstream):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        def pipe(
            source: socket.socket,
            target: socket.socket,
            *,
            tracker: WebSocketMessageTracker,
            from_downstream: bool,
        ) -> None:
            try:
                while not stop.is_set():
                    data = source.recv(65536)
                    if not data:
                        return
                    messages = tracker.feed(data)
                    if messages:
                        self.server.touch_websocket_data(tunnel_id)
                    if from_downstream:
                        for opcode, payload in messages:
                            session = response_create_payload_session(
                                websocket_message_json(opcode, payload)
                            )
                            if session and session.get("key") and session.get("cwd"):
                                self.server.attach_websocket_session(
                                    tunnel_id,
                                    str(session["key"]),
                                    str(session["cwd"]),
                                )
                            if websocket_message_starts_response(opcode, payload):
                                self.server.begin_websocket_work(
                                    tunnel_id,
                                    websocket_message_turn_id(opcode, payload),
                                )
                    else:
                        for opcode, payload in messages:
                            if self.server.update_usage_cache_from_websocket_message(
                                profile,
                                opcode,
                                payload,
                            ):
                                self.log_message(
                                    "quota cache for profile %s updated from websocket event",
                                    profile,
                                )
                            saw_tool_output = websocket_message_has_tool_output(opcode, payload)
                            if saw_tool_output:
                                self.server.mark_websocket_tool_output(tunnel_id)
                            action = websocket_message_completion_action(opcode, payload)
                            if action == "clear":
                                self.server.finish_websocket_work(tunnel_id)
                            elif action == "complete":
                                self.server.complete_websocket_response(
                                    tunnel_id,
                                    saw_tool_output=saw_tool_output,
                                )
                            elif action == "keep":
                                self.server.complete_websocket_response(
                                    tunnel_id,
                                    saw_tool_output=True,
                                )
                    target.sendall(data)
            except OSError:
                return
            finally:
                shutdown()

        threads = [
            threading.Thread(
                target=pipe,
                args=(downstream, upstream),
                kwargs={"tracker": downstream_tracker, "from_downstream": True},
                daemon=True,
            ),
            threading.Thread(
                target=pipe,
                args=(upstream, downstream),
                kwargs={"tracker": upstream_tracker, "from_downstream": False},
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()
        stop.wait()
        for thread in threads:
            thread.join(timeout=1)

    def is_chatgpt_profile(self, auth_path: Path) -> bool:
        return self.server.is_chatgpt_profile(auth_path)

    def authorized_proxy_request(self) -> bool:
        auth = self.headers.get("authorization", "")
        if auth == f"Bearer {self.server.proxy_token}":
            return True
        return decode_project_session_sentinel(
            self.headers.get("openai-project", ""),
            self.server.proxy_token,
        ) is not None

    def local_project_sentinel(self) -> str:
        return project_sentinel(self.server.proxy_token)

    def request_session(
        self,
        body: bytes | None = None,
        *,
        route: str | None = None,
        method: str | None = None,
        upstream_path: str | None = None,
    ) -> dict[str, str] | None:
        from_header = decode_project_session_sentinel(
            self.headers.get("openai-project", ""),
            self.server.proxy_token,
        )
        if from_header and from_header.get("key"):
            return from_header
        from_body = request_body_session(body)
        if from_body and from_body.get("key"):
            return from_body
        if (
            route == UpstreamRoute.CHATGPT_BACKEND
            and method == "POST"
            and upstream_path == CHATGPT_ANALYTICS_EVENTS_PATH
        ):
            from_turn = self.server.session_for_turn_ids(analytics_turn_ids(body))
            if from_turn and from_turn.get("key"):
                return from_turn
        return None

    def forward_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"accept-encoding": "identity"}
        for key, value in self.headers.items():
            if not should_forward_incoming_header(key):
                continue
            headers[key] = value
        return headers

    def forward_response_headers(self, headers: Any) -> None:
        for key, value in headers.items():
            lower = key.lower()
            if lower in RESPONSE_HOP_BY_HOP_HEADERS:
                continue
            self.send_header(key, value)

    def prepare_close_delimited_response(self, headers: Any) -> None:
        if headers.get("content-length") is None:
            self.send_header("connection", "close")
            self.close_connection = True

    def write_downstream(self, chunk: bytes) -> bool:
        try:
            self.wfile.write(chunk)
            self.wfile.flush()
            return True
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
            return False

    def status_payload(self, *, include_profiles: bool = False) -> dict[str, Any]:
        active_requests = self.server.request_count()
        active_websockets = self.server.websocket_count()
        pending_work = self.server.pending_websocket_work_count()
        recent_activity = self.server.recent_websocket_data_activity_count()
        blocking_requests = self.server.request_count(blocking_only=True)
        blocking_pending_work = self.server.pending_websocket_work_count(blocking_only=True)
        payload: dict[str, Any] = {
            "ok": True,
            "pid": os.getpid(),
            "port": self.server.server_address[1],
            "provision_protocol": PROTOCOL_VERSION,
            "active_profile": self.server.store.active_profile(required=False),
            "active_requests": active_requests,
            "blocking_active_requests": blocking_requests,
            "active_websockets": active_websockets,
            "blocking_active_websockets": self.server.websocket_count(blocking_only=True),
            "active_websocket_work": self.server.active_websocket_work_count(),
            "blocking_active_websocket_work": self.server.active_websocket_work_count(blocking_only=True),
            "pending_websocket_work": pending_work,
            "blocking_pending_websocket_work": blocking_pending_work,
            "recent_websocket_activity": recent_activity,
            "recent_websocket_data_activity": recent_activity,
            "live_busy": active_requests > 0 or pending_work > 0 or recent_activity > 0,
            "switch_block_reason": self.server.switch_block_reason(),
        }
        if include_profiles:
            payload["sessions"] = self.server.session_snapshots()
            profiles = []
            for profile in self.server.store.list_profiles():
                item = dict(profile)
                name = item.get("name")
                item["quota_summary"] = usage_cache_summary(
                    self.server.usage_cache_snapshot(str(name)) if name else None
                )
                profiles.append(item)
            payload["profiles"] = profiles
        return payload

    def ui_status_payload(self) -> dict[str, Any]:
        status = self.status_payload(include_profiles=True)
        for profile in status["profiles"]:
            name = str(profile.get("name") or "")
            snapshot = self.server.usage_cache_snapshot(name) if name else None
            payload = snapshot.get("payload") if isinstance(snapshot, dict) else None
            profile["quota_summary"] = usage_cache_summary(snapshot)
            profile["quota_updated"] = quota_updated_label(snapshot)
            profile["quota_has_payload"] = isinstance(payload, dict)
            profile["quota_refresh_error"] = (
                str(snapshot.get("error") or "") if isinstance(snapshot, dict) else ""
            )
            profile["quota_html"] = render_quota_html(
                snapshot,
                profile["quota_updated"],
                name,
                self.server.proxy_token,
            )
            profile["switch_disabled_reason"] = self.switch_disabled_reason(profile, status)
            profile["switch_button_label"] = self.switch_button_label(profile, status)
            profile["pinned_sessions"] = self.server.pinned_sessions_for_profile(name)
            profile["has_active_sessions"] = self.server.profile_has_active_sessions(name)
            profile["has_active_pinned_sessions"] = self.server.profile_has_active_sessions(
                name,
                pinned_only=True,
            )
            profile["pin_menu_html"] = self.render_pin_menu(profile, status)
            profile["pinned_sessions_html"] = self.render_pinned_sessions(profile)
        return status

    def switch_disabled_reason(self, profile: dict[str, Any], status: dict[str, Any]) -> str:
        if profile.get("active"):
            return "Current profile"
        block_reason = status.get("switch_block_reason")
        if isinstance(block_reason, str) and block_reason:
            return f"Disabled while {block_reason}"
        return ""

    def switch_button_label(self, profile: dict[str, Any], status: dict[str, Any]) -> str:
        if profile.get("active"):
            return "Current"
        active_requests = status.get("blocking_active_requests")
        if isinstance(active_requests, int) and active_requests > 0:
            return f"{active_requests} request{'s' if active_requests != 1 else ''} pending"
        pending_work = status.get("blocking_pending_websocket_work")
        if isinstance(pending_work, int) and pending_work > 0:
            return f"{pending_work} turn{'s' if pending_work != 1 else ''} pending"
        return "Use"

    def render_pin_menu(self, profile: dict[str, Any], status: dict[str, Any]) -> str:
        profile_name = str(profile.get("name") or "")
        token = html.escape(self.server.proxy_token)
        sessions = status.get("sessions")
        if not isinstance(sessions, list) or not sessions:
            return f"""
              <details class="pin-menu profile-pin-menu" data-profile="{html.escape(profile_name)}">
                <summary class="pin-summary">{PIN_ICON_SVG}<span>Session Pins</span></summary>
                <div class="pin-menu-panel"><div class="pin-menu-empty">No sessions observed</div></div>
              </details>
            """

        items: list[str] = []
        for session in sessions:
            if not isinstance(session, dict):
                continue
            session_key = str(session.get("key") or "")
            if not session_key:
                continue
            name = html.escape(str(session.get("name") or "Session"))
            display = html.escape(str(session.get("display") or session_key))
            pinned_profile = str(session.get("pinned_profile") or "")
            active = bool(session.get("active"))
            action = "unpin_session" if pinned_profile == profile_name else "pin_session"
            verb = "Unpin" if action == "unpin_session" else "Pin"
            status_bits = []
            if active:
                status_bits.append("active")
            if pinned_profile:
                status_bits.append(f"pinned to {pinned_profile}")
            status_text = " · ".join(status_bits) if status_bits else "idle"
            items.append(
                f"""
                <form method="post" action="/api/pin-session" data-action="{action}" data-profile="{html.escape(profile_name)}">
                  <input type="hidden" name="token" value="{token}">
                  <input type="hidden" name="action" value="{action}">
                  <input type="hidden" name="profile" value="{html.escape(profile_name)}">
                  <input type="hidden" name="session_key" value="{html.escape(session_key)}">
                  <button class="pin-menu-item">
                    <span class="pin-menu-name">{verb} {name}</span>
                    <span class="pin-menu-path" title="{html.escape(str(session.get("cwd") or display))}">{display}</span>
                    <span class="pin-menu-status">{html.escape(status_text)}</span>
                  </button>
                </form>
                """
            )

        active_class = " session-active-action" if profile.get("has_active_pinned_sessions") else ""
        return f"""
          <details class="pin-menu profile-pin-menu" data-profile="{html.escape(profile_name)}">
            <summary class="pin-summary{active_class}">{PIN_ICON_SVG}<span>Session Pins</span></summary>
            <div class="pin-menu-panel">{''.join(items)}</div>
          </details>
        """

    def render_pinned_sessions(self, profile: dict[str, Any]) -> str:
        sessions = profile.get("pinned_sessions")
        if not isinstance(sessions, list) or not sessions:
            return ""
        chips: list[str] = []
        for session in sessions:
            if not isinstance(session, dict):
                continue
            active_class = " active" if session.get("active") else ""
            cwd = str(session.get("cwd") or session.get("display") or "")
            display = str(session.get("display") or cwd)
            chips.append(
                f"""
                <span class="session-chip{active_class}" title="{html.escape(cwd)}">
                  <span class="session-chip-path">{html.escape(display)}</span>
                </span>
                """
            )
        if not chips:
            return ""
        return f"""
          <div class="pinned-sessions">
            <div class="session-chips">{''.join(chips)}</div>
          </div>
        """

    def render_profile_rows(self, status: dict[str, Any]) -> str:
        rows = []
        for profile in status.get("profiles", []):
            rows.append(self.render_profile_row(profile))
        return "".join(rows)

    def render_profile_row(self, profile: dict[str, Any]) -> str:
        profile_name = str(profile.get("name") or "")
        name = html.escape(profile_name)
        email = html.escape(profile.get("email") or profile.get("account_id") or "")
        plan = html.escape(profile.get("plan_type") or "unknown")
        quota = profile.get("quota_html") or '<div class="quota-empty">No quota cached</div>'
        active = " active" if profile.get("active") else ""
        badge = '<span class="badge active-badge">Active</span>' if profile.get("active") else ""
        switch_reason = str(profile.get("switch_disabled_reason") or "")
        switch_label = html.escape(str(profile.get("switch_button_label") or "Use"))
        switch_class = "primary-action current-action" if profile.get("active") else "primary-action"
        if profile.get("active") and profile.get("has_active_sessions"):
            switch_class += " session-active-action"
        disabled = "disabled" if switch_reason else ""
        pin_menu = str(profile.get("pin_menu_html") or "")
        pinned_sessions = str(profile.get("pinned_sessions_html") or "")
        token = html.escape(self.server.proxy_token)
        return f"""
          <tr class="profile-row{active}" data-profile="{name}">
            <td class="profile-cell">
              <div class="profile-name">{name}{badge}</div>
              <div class="profile-email">{email}</div>
              {pin_menu}
              {pinned_sessions}
            </td>
            <td class="plan-cell">{plan}</td>
            <td class="quota-cell">{quota}</td>
            <td class="actions">
              <form method="post" action="/api/switch" data-action="switch" data-profile="{name}">
                <input type="hidden" name="token" value="{token}">
                <input type="hidden" name="profile" value="{name}">
                <button class="{switch_class}" {disabled} title="{html.escape(switch_reason)}">{switch_label}</button>
              </form>
            </td>
          </tr>
        """

    def render_ui(self) -> str:
        status = self.ui_status_payload()
        rows = self.render_profile_rows(status)
        active_profile = html.escape(str(status.get("active_profile") or "none"))
        active_requests = int(status.get("active_requests") or 0)
        active_websockets = int(status.get("active_websockets") or 0)
        busy = "busy" if status.get("live_busy") else "idle"
        initial_json = json.dumps(
            {"type": "state", "status": status, "message": None},
            separators=(",", ":"),
        ).replace("</", "<\\/")
        token_json = json.dumps(self.server.proxy_token)
        return """
<!doctype html>
<html>
	<head>
		  <meta charset="utf-8">
		  <meta name="viewport" content="width=device-width, initial-scale=1">
		  <title>Provision</title>
		  <script>
		    (function() {
		      try {
		        const theme = localStorage.getItem("provision-theme");
		        if (theme === "light" || theme === "dark") {
		          document.documentElement.dataset.theme = theme;
		        }
		      } catch {
		      }
		    })();
		  </script>
		  <style>
	    :root {
	      color-scheme: light dark;
	      --ink: #171717;
	      --muted: #65676f;
	      --line: #d9d9df;
	      --surface: #ffffff;
	      --page: #f6f4f1;
	      --soft: #f0eeea;
	      --subtle: #fafafa;
	      --active-row: #fffafa;
	      --button-bg: #ffffff;
	      --button-hover: #fafafa;
	      --button-disabled-bg: #f1f1f3;
	      --button-disabled-ink: #8d9098;
	      --bar-bg: #e8e8ed;
	      --notice-bg: #fff1f0;
	      --notice-border: #efc8c4;
	      --notice-ink: #641e16;
	      --message-bg: #fff8e5;
	      --message-border: #e5d4a9;
	      --message-ink: #5f410a;
	      --badge-bg: #fff0f0;
	      --badge-border: #f0b5b5;
	      --red: #d83434;
	      --red-dark: #9f2424;
	      --green: #198754;
	      --blue: #2563eb;
	      --amber: #b7791f;
	      --amber-dark: #8a5a12;
	      --danger: #b42318;
	      --shadow: 0 12px 30px rgba(23, 23, 23, 0.08);
	    }
		    @media (prefers-color-scheme: dark) {
		      :root {
	        --ink: #f1f3f7;
	        --muted: #a5adba;
	        --line: #343946;
	        --surface: #151821;
	        --page: #0b0d12;
	        --soft: #1e222d;
	        --subtle: #1a1e27;
	        --active-row: #21171a;
	        --button-bg: #1a1e27;
	        --button-hover: #232938;
	        --button-disabled-bg: #161a22;
	        --button-disabled-ink: #707887;
	        --bar-bg: #303642;
	        --notice-bg: #2a1616;
	        --notice-border: #603030;
	        --notice-ink: #ffd7d4;
	        --message-bg: #2a2414;
	        --message-border: #5f4a19;
	        --message-ink: #ffe2a3;
	        --badge-bg: #2a171a;
	        --badge-border: #6b3438;
	        --red: #f05252;
	        --red-dark: #c83a3a;
	        --green: #35b779;
	        --blue: #60a5fa;
	        --amber: #d79a2b;
	        --amber-dark: #a86f16;
	        --danger: #ff6b63;
		        --shadow: 0 14px 34px rgba(0, 0, 0, 0.34);
		      }
		    }
		    :root[data-theme="light"] {
		      color-scheme: light;
		      --ink: #171717;
		      --muted: #65676f;
		      --line: #d9d9df;
		      --surface: #ffffff;
		      --page: #f6f4f1;
		      --soft: #f0eeea;
		      --subtle: #fafafa;
		      --active-row: #fffafa;
		      --button-bg: #ffffff;
		      --button-hover: #fafafa;
		      --button-disabled-bg: #f1f1f3;
		      --button-disabled-ink: #8d9098;
		      --bar-bg: #e8e8ed;
		      --notice-bg: #fff1f0;
		      --notice-border: #efc8c4;
		      --notice-ink: #641e16;
		      --message-bg: #fff8e5;
		      --message-border: #e5d4a9;
		      --message-ink: #5f410a;
		      --badge-bg: #fff0f0;
		      --badge-border: #f0b5b5;
		      --red: #d83434;
		      --red-dark: #9f2424;
		      --green: #198754;
		      --blue: #2563eb;
		      --amber: #b7791f;
		      --amber-dark: #8a5a12;
		      --danger: #b42318;
		      --shadow: 0 12px 30px rgba(23, 23, 23, 0.08);
		    }
		    :root[data-theme="dark"] {
		      color-scheme: dark;
		      --ink: #f1f3f7;
		      --muted: #a5adba;
		      --line: #343946;
		      --surface: #151821;
		      --page: #0b0d12;
		      --soft: #1e222d;
		      --subtle: #1a1e27;
		      --active-row: #21171a;
		      --button-bg: #1a1e27;
		      --button-hover: #232938;
		      --button-disabled-bg: #161a22;
		      --button-disabled-ink: #707887;
		      --bar-bg: #303642;
		      --notice-bg: #2a1616;
		      --notice-border: #603030;
		      --notice-ink: #ffd7d4;
		      --message-bg: #2a2414;
		      --message-border: #5f4a19;
		      --message-ink: #ffe2a3;
		      --badge-bg: #2a171a;
		      --badge-border: #6b3438;
		      --red: #f05252;
		      --red-dark: #c83a3a;
		      --green: #35b779;
		      --blue: #60a5fa;
		      --amber: #d79a2b;
		      --amber-dark: #a86f16;
		      --danger: #ff6b63;
		      --shadow: 0 14px 34px rgba(0, 0, 0, 0.34);
		    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--page);
      color: var(--ink);
      font: 14px/1.45 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .shell {
      width: min(1240px, calc(100vw - 32px));
      margin: 24px auto 40px;
    }
		    .topbar {
		      display: flex;
		      align-items: center;
		      flex-wrap: wrap;
		      gap: 16px;
		      padding: 10px 14px;
	      background: var(--surface);
	      border: 1px solid var(--line);
	      box-shadow: var(--shadow);
	      border-radius: 8px;
	    }
		    .logo {
		      width: 218px;
		      height: 44px;
		      object-fit: contain;
		      border-radius: 6px;
		      flex: 0 0 auto;
		    }
	    .top-meta {
	      display: flex;
	      flex-wrap: wrap;
	      gap: 10px;
	      color: var(--muted);
	      font-size: 13px;
	      flex: 1 1 300px;
	    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      min-height: 24px;
	      padding: 2px 8px;
	      border: 1px solid var(--line);
	      border-radius: 999px;
	      background: var(--subtle);
	      color: var(--ink);
	      white-space: nowrap;
	    }
    .dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--green);
      display: inline-block;
    }
	    .dot.busy { background: var(--amber); }
	    .dot.disconnected { background: var(--danger); }
		    .top-actions {
		      margin-left: auto;
		      display: flex;
		      align-items: flex-end;
		      justify-content: center;
		    }
		    .theme-toggle {
		      width: 30px;
		      min-height: 30px;
		      padding: 0;
		      display: inline-flex;
		      align-items: center;
		      justify-content: center;
		      border-radius: 999px;
		    }
		    .theme-toggle svg {
		      width: 16px;
		      height: 16px;
		      stroke: currentColor;
		    }
	    .notice, .message {
	      margin-top: 14px;
	      padding: 10px 12px;
	      border: 1px solid var(--notice-border);
	      border-left: 4px solid var(--danger);
	      border-radius: 6px;
	      background: var(--notice-bg);
	      color: var(--notice-ink);
	    }
	    .notice:empty { display: none; }
	    .message {
	      display: none;
	      border-color: var(--message-border);
	      border-left-color: var(--amber);
	      background: var(--message-bg);
	      color: var(--message-ink);
	    }
    .message.visible { display: block; }
    .profiles {
      margin-top: 18px;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: visible;
      box-shadow: var(--shadow);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }
	    .profile-col { width: 250px; }
	    .plan-col { width: 86px; }
	    .actions-col { width: 160px; }
    th {
      padding: 11px 14px;
      text-align: left;
      font-size: 12px;
      text-transform: uppercase;
      color: var(--muted);
      background: var(--soft);
      border-bottom: 1px solid var(--line);
    }
    td {
      padding: 14px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }
    tbody tr:last-child td { border-bottom: 0; }
	    .profile-row.active { background: var(--active-row); }
	    .profile-cell { min-width: 0; }
	    .plan-cell { color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
	    .actions { width: 160px; }
	    .quota-cell { min-width: 0; overflow: hidden; }
    .profile-name {
      display: flex;
      align-items: center;
      gap: 8px;
      font-weight: 700;
      min-width: 0;
      overflow-wrap: anywhere;
    }
    .profile-email {
      color: var(--muted);
      margin-top: 3px;
      overflow-wrap: anywhere;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      min-height: 20px;
      padding: 1px 7px;
      border-radius: 999px;
      font-size: 11px;
	      font-weight: 700;
	      color: var(--red);
	      border: 1px solid var(--badge-border);
	      background: var(--badge-bg);
	    }
    button {
      width: 100%;
	      min-height: 32px;
	      padding: 4px 8px;
	      border-radius: 6px;
	      border: 1px solid var(--line);
	      background: var(--button-bg);
	      color: var(--ink);
      font-weight: 650;
      cursor: pointer;
      white-space: nowrap;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
	    button:hover:not(:disabled) { border-color: var(--muted); background: var(--button-hover); }
	    button:disabled { color: var(--button-disabled-ink); background: var(--button-disabled-bg); cursor: not-allowed; }
    .primary-action {
      background: var(--red);
      border-color: var(--red);
      color: #fff;
    }
    .primary-action:hover:not(:disabled) { background: var(--red-dark); border-color: var(--red-dark); }
    .current-action,
    .current-action:disabled {
      background: var(--green);
      border-color: var(--green);
      color: #fff;
      opacity: 1;
    }
    .primary-action.session-active-action,
    .primary-action.session-active-action:disabled {
      background: var(--amber);
      border-color: var(--amber);
      color: #fff;
      opacity: 1;
    }
    .primary-action.session-active-action:hover:not(:disabled) {
      background: var(--amber-dark);
      border-color: var(--amber-dark);
    }
    form { margin: 0 0 7px; }
    form:last-child { margin-bottom: 0; }
    .action-note {
      margin: -2px 0 7px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.3;
    }
		    .quota-panel { display: grid; gap: 8px; }
    .quota-panel-head {
      display: flex;
      align-items: center;
      gap: 7px;
      min-width: 0;
    }
    .quota-refresh-form { margin: 0; }
    .quota-refresh-icon {
      width: 24px;
      height: 24px;
      min-width: 24px;
      min-height: 24px;
      flex: 0 0 24px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0;
      border-radius: 999px;
      color: var(--muted);
      background: var(--button-bg);
    }
    .quota-refresh-glyph {
      width: 14px;
      height: 14px;
      stroke: currentColor;
      stroke-width: 2;
      stroke-linecap: round;
      stroke-linejoin: round;
      flex: 0 0 auto;
    }
    .quota-refresh-icon.disabled {
      pointer-events: none;
      color: var(--button-disabled-ink);
      background: var(--button-disabled-bg);
    }
    .quota-spinner-small {
      width: 13px;
      height: 13px;
      border-width: 2px;
      border-top-color: var(--red);
    }
    .quota-updated {
      color: var(--muted);
      font-size: 12px;
      font-weight: 650;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .quota-bucket {
	      border: 1px solid var(--line);
	      border-radius: 6px;
	      padding: 8px 10px;
	      background: var(--surface);
	      max-width: 100%;
	      overflow: hidden;
	    }
	    .quota-title {
	      display: flex;
	      align-items: center;
	      gap: 8px;
	      flex-wrap: wrap;
	      min-width: 0;
      margin-bottom: 6px;
	    }
    .quota-bucket-name { font-weight: 720; }
    .quota-feature {
      color: var(--muted);
      font-size: 12px;
	      border: 1px solid var(--line);
	      border-radius: 999px;
	      padding: 1px 7px;
	      background: var(--subtle);
	    }
    .quota-stack {
      display: grid;
      min-width: 0;
    }
    .quota-horizons {
      display: flex;
      margin-left: auto;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      font-size: 12px;
      font-weight: 750;
      line-height: 1.2;
      min-width: 0;
    }
    .quota-horizon {
      min-width: 0;
      overflow-wrap: anywhere;
      white-space: normal;
    }
    .quota-horizon.primary { color: var(--green); }
    .quota-horizon.weekly {
      color: var(--blue);
      text-align: right;
    }
    .quota-stack-row {
      display: grid;
      grid-template-columns: minmax(120px, 1fr) 44px;
      gap: 10px;
      align-items: center;
      min-width: 0;
    }
	    .quota-stack-bar {
	      position: relative;
	      height: 30px;
	      border-radius: 0;
	      background: var(--bar-bg);
	      overflow: hidden;
	      min-width: 0;
    }
    .quota-weekly-fill,
    .quota-primary-fill {
      position: absolute;
      left: 0;
      border-radius: 0;
    }
    .quota-weekly-fill {
      top: 0;
      bottom: 0;
      background: var(--blue);
      opacity: 0.86;
    }
	    .quota-primary-fill {
	      bottom: 0;
	      height: 20px;
	      display: flex;
	      align-items: center;
	      justify-content: flex-end;
      background: var(--green);
      color: #fff;
      overflow: visible;
    }
    .quota-primary-fill.empty {
      background: transparent;
      color: var(--muted);
    }
    .quota-primary-label {
      position: absolute;
      right: 5px;
      font-size: 11px;
      font-weight: 800;
      line-height: 1;
      white-space: nowrap;
      text-shadow: 0 1px 1px rgba(0, 0, 0, 0.28);
    }
    .quota-primary-fill.empty .quota-primary-label {
      left: 5px;
      right: auto;
      text-shadow: none;
    }
    .quota-weekly-label {
      color: var(--blue);
      font-size: 12px;
      font-weight: 800;
      text-align: right;
      white-space: nowrap;
    }
    .quota-counts,
    .quota-count-line {
      display: grid;
      gap: 4px;
    }
    .quota-count-line {
      grid-template-columns: auto auto 1fr;
      align-items: center;
      color: var(--muted);
      font-size: 12px;
    }
    .quota-count-line strong { color: var(--ink); }
    .quota-count-reset { color: var(--muted); }
	    .quota-empty, .quota-muted {
	      color: var(--muted);
	      background: var(--subtle);
	      border: 1px dashed var(--line);
	      border-radius: 6px;
	      padding: 10px;
	    }
	    .quota-loading {
	      min-height: 92px;
	      display: flex;
	      align-items: center;
	      justify-content: center;
	      gap: 10px;
	      color: var(--muted);
	      background: var(--subtle);
	      border: 1px dashed var(--line);
	      border-radius: 6px;
	      font-weight: 650;
	    }
	    .spinner {
	      width: 18px;
	      height: 18px;
	      border: 2px solid var(--bar-bg);
	      border-top-color: var(--red);
	      border-radius: 50%;
	      animation: spin 0.8s linear infinite;
	      flex: 0 0 auto;
	    }
	    @keyframes spin { to { transform: rotate(360deg); } }
    .quota-empty.error, .quota-refresh-error { color: var(--danger); }
    .quota-refresh-error {
      font-size: 12px;
      font-weight: 650;
    }
    .pin-menu {
      position: relative;
      margin: 0;
    }
    .pin-menu:last-child { margin-bottom: 0; }
    .pin-menu summary { list-style: none; }
    .pin-menu summary::-webkit-details-marker { display: none; }
    .pin-summary {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      width: auto;
      min-height: 22px;
      padding: 0;
      border: 0;
      background: transparent;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      white-space: nowrap;
    }
    .pin-summary:hover { color: var(--ink); }
    .pin-summary.session-active-action { color: var(--amber); }
    .pin-icon {
      width: 13px;
      height: 13px;
      flex: 0 0 auto;
    }
    .pin-menu-panel {
      position: absolute;
      left: 0;
      z-index: 20;
      width: min(430px, calc(100vw - 32px));
      max-height: 340px;
      overflow: auto;
      margin-top: 6px;
      padding: 8px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      box-shadow: var(--shadow);
    }
    .pin-menu-panel form { margin: 0 0 6px; }
    .pin-menu-panel form:last-child { margin-bottom: 0; }
    .pin-menu-item {
      min-height: 0;
      align-items: flex-start;
      justify-content: flex-start;
      flex-direction: column;
      gap: 2px;
      text-align: left;
      white-space: normal;
    }
    .pin-menu-name {
      font-weight: 750;
      color: var(--ink);
    }
	    .pin-menu-path,
	    .pin-menu-status,
	    .pin-menu-empty {
	      color: var(--muted);
	      font-size: 12px;
	      overflow-wrap: anywhere;
	    }
	    .pinned-sessions {
	      margin-top: 8px;
	      min-width: 0;
	      max-width: 100%;
	    }
	    .session-chips {
	      display: flex;
	      flex-wrap: wrap;
	      gap: 6px;
    }
    .session-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      max-width: 100%;
      padding: 4px 8px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--subtle);
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
      overflow: hidden;
      cursor: help;
    }
    .session-chip.active {
      color: var(--ink);
      border-color: var(--amber);
    }
    .session-chip-path {
      overflow: hidden;
      text-overflow: ellipsis;
    }
	    @media (max-width: 860px) {
	      .shell { width: min(100vw - 20px, 760px); margin-top: 10px; }
		      .topbar { align-items: flex-start; }
		      .logo { width: 180px; height: 36px; }
		      .top-actions { margin-left: 0; align-items: flex-start; }
      table, thead, tbody, tr, th, td { display: block; width: 100%; }
      thead { display: none; }
      td { border-bottom: 0; padding: 10px 12px; }
	      tr { border-bottom: 1px solid var(--line); }
	      tbody tr:last-child { border-bottom: 0; }
		      .actions { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
	      .actions form { margin: 0; }
	      .pin-menu { margin: 0; }
	      .pin-menu-panel { left: 0; right: auto; width: min(430px, calc(100vw - 44px)); }
	      .action-note { grid-column: 1 / -1; margin: 0; }
	    }
  </style>
</head>
<body>
	  <main class="shell">
	    <header class="topbar">
		      <img class="logo" src="/assets/provision-wordmark.png" alt="Provision">
	      <div class="top-meta">
	        <span class="pill">Active <strong id="activeProfile">__ACTIVE_PROFILE__</strong></span>
	        <span class="pill">Requests <strong id="activeRequests">__ACTIVE_REQUESTS__</strong></span>
	        <span class="pill">Tunnels <strong id="activeTunnels">__ACTIVE_WEBSOCKETS__</strong></span>
	        <span class="pill"><span id="proxyDot" class="dot"></span><span id="connectionState">Live (__BUSY__)</span></span>
	      </div>
	      <div class="top-actions">
	        <button id="themeToggle" class="theme-toggle" type="button" aria-label="Toggle color theme" title="Toggle color theme"></button>
	      </div>
	    </header>
    <div id="message" class="message" aria-live="polite"></div>
    <section class="profiles">
      <table>
        <colgroup>
          <col class="profile-col">
          <col class="plan-col">
          <col class="quota-col">
          <col class="actions-col">
        </colgroup>
        <thead>
          <tr><th>Profile</th><th>Plan</th><th>Remaining Quota</th><th></th></tr>
        </thead>
        <tbody id="profileRows">__ROWS__</tbody>
      </table>
    </section>
  </main>
  <script>
	    const TOKEN = __TOKEN__;
	    const INITIAL = __INITIAL_STATE__;
	    const THEME_KEY = "provision-theme";
	    const SUN_ICON = '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2"></path><path d="M12 20v2"></path><path d="m4.93 4.93 1.41 1.41"></path><path d="m17.66 17.66 1.41 1.41"></path><path d="M2 12h2"></path><path d="M20 12h2"></path><path d="m6.34 17.66-1.41 1.41"></path><path d="m19.07 4.93-1.41 1.41"></path></svg>';
	    const MOON_ICON = '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M20.5 14.4A7.5 7.5 0 0 1 9.6 3.5 8.5 8.5 0 1 0 20.5 14.4Z"></path></svg>';
	    let socket = null;
	    let reconnectTimer = null;
	    let latestLiveBusy = Boolean(INITIAL.status && INITIAL.status.live_busy);
		    let openPinMenuProfile = null;
		    let quotaRefreshTimer = null;
		    let quotaRefreshInFlight = "";
		    const pageDaemonPid = INITIAL.status ? INITIAL.status.pid || null : null;
		    let quotaRefreshDaemonPid = INITIAL.status ? INITIAL.status.pid || null : null;
		    const quotaRefreshQueue = [];
	    const quotaRefreshAttempted = new Set();

    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"']/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
      })[char]);
    }

	    function setConnection(label, state) {
	      const text = label === "Live" ? `Live (${latestLiveBusy ? "busy" : "idle"})` : label;
	      document.getElementById("connectionState").textContent = text;
	      const dot = document.getElementById("proxyDot");
	      dot.className = "dot" + (state ? " " + state : "");
	    }

	    function savedTheme() {
	      try {
	        const value = localStorage.getItem(THEME_KEY);
	        return value === "light" || value === "dark" ? value : null;
	      } catch {
	        return null;
	      }
	    }

	    function systemTheme() {
	      return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
	    }

	    function effectiveTheme() {
	      return savedTheme() || systemTheme();
	    }

	    function setTheme(theme) {
	      document.documentElement.dataset.theme = theme;
	      try {
	        localStorage.setItem(THEME_KEY, theme);
	      } catch {
	      }
	      updateThemeToggle();
	    }

	    function updateThemeToggle() {
	      const button = document.getElementById("themeToggle");
	      if (!button) return;
	      const current = effectiveTheme();
	      const target = current === "dark" ? "light" : "dark";
	      button.innerHTML = target === "dark" ? MOON_ICON : SUN_ICON;
	      button.title = `Switch to ${target} mode`;
	      button.setAttribute("aria-label", `Switch to ${target} mode`);
	    }

	    function rememberOpenPinMenu() {
	      const openMenu = document.querySelector("details.pin-menu[open]");
	      openPinMenuProfile = openMenu ? openMenu.dataset.profile || "" : null;
	    }

	    function restoreOpenPinMenu() {
	      if (!openPinMenuProfile) return;
	      document.querySelectorAll("details.pin-menu").forEach((menu) => {
	        menu.open = menu.dataset.profile === openPinMenuProfile;
	      });
	    }

	    function closePinMenus() {
	      openPinMenuProfile = null;
	      document.querySelectorAll("details.pin-menu[open]").forEach((menu) => {
	        menu.open = false;
	      });
	    }

		    function updateQuotaRefreshEpoch(status) {
		      const pid = status ? status.pid || null : null;
		      if (!pid || pid === quotaRefreshDaemonPid) return;
		      if (pageDaemonPid && pid !== pageDaemonPid) {
		        window.location.reload();
		        return;
		      }
		      quotaRefreshDaemonPid = pid;
	      quotaRefreshAttempted.clear();
	      quotaRefreshQueue.length = 0;
	      quotaRefreshInFlight = "";
	      if (quotaRefreshTimer) {
	        clearTimeout(quotaRefreshTimer);
	        quotaRefreshTimer = null;
	      }
	    }

	    function queueInitialQuotaRefreshes(profiles) {
	      for (const profile of profiles || []) {
	        const name = String(profile.name || "");
	        if (!name || profile.quota_has_payload || profile.quota_refresh_error) continue;
	        if (quotaRefreshAttempted.has(name)) continue;
	        quotaRefreshAttempted.add(name);
	        quotaRefreshQueue.push(name);
	      }
	    }

	    function scheduleNextQuotaRefresh(delay = 0) {
	      if (quotaRefreshTimer || quotaRefreshInFlight) return;
	      quotaRefreshTimer = setTimeout(() => {
	        quotaRefreshTimer = null;
	        if (!socket || socket.readyState !== WebSocket.OPEN || quotaRefreshInFlight) return;
	        while (quotaRefreshQueue.length) {
	          const profile = quotaRefreshQueue.shift();
	          if (!profile) continue;
	          quotaRefreshInFlight = profile;
	          socket.send(JSON.stringify({
	            action: "refresh_quota",
	            profile,
	            token: TOKEN
	          }));
	          return;
	        }
	      }, delay);
	    }

    function profileRow(profile, pendingAction, pendingProfile) {
      const name = String(profile.name || "");
      const reason = String(profile.switch_disabled_reason || "");
	      const pending = pendingProfile === name ? pendingAction : "";
	      const disabled = reason || pending ? "disabled" : "";
	      const useTitle = reason || (pending ? "Action in progress" : "");
	      const useLabel = pending === "switch" ? "Switching" : String(profile.switch_button_label || "Use");
	      let useClass = profile.active ? "primary-action current-action" : "primary-action";
	      if (profile.active && profile.has_active_sessions) useClass += " session-active-action";
	      const badge = profile.active ? '<span class="badge active-badge">Active</span>' : "";
	      const isRefreshing = pending === "refresh_quota";
		      const quota = isRefreshing
		        ? '<div class="quota-panel"><div class="quota-panel-head"><span class="quota-refresh-icon disabled" aria-hidden="true"><span class="spinner quota-spinner-small"></span></span><span class="quota-updated">Refreshing quota</span></div><div class="quota-loading"><span class="spinner"></span><span>Refreshing quota</span></div></div>'
		        : profile.quota_html || '<div class="quota-empty">No quota cached</div>';
		      const pinMenu = profile.pin_menu_html || "";
		      const pinnedSessions = profile.pinned_sessions_html || "";
      return `
        <tr class="profile-row${profile.active ? " active" : ""}" data-profile="${escapeHtml(name)}">
          <td class="profile-cell">
	            <div class="profile-name">${escapeHtml(name)}${badge}</div>
	            <div class="profile-email">${escapeHtml(profile.email || profile.account_id || "")}</div>
	            ${pinMenu}
	            ${pinnedSessions}
	          </td>
	          <td class="plan-cell">${escapeHtml(profile.plan_type || "unknown")}</td>
	          <td class="quota-cell">${quota}</td>
          <td class="actions">
            <form method="post" action="/api/switch" data-action="switch" data-profile="${escapeHtml(name)}">
              <input type="hidden" name="token" value="${escapeHtml(TOKEN)}">
              <input type="hidden" name="profile" value="${escapeHtml(name)}">
              <button class="${useClass}" ${disabled} title="${escapeHtml(useTitle)}">${escapeHtml(useLabel)}</button>
            </form>
		          </td>
	        </tr>
	      `;
	    }

    function render(packet) {
      const status = packet.status || {};
      updateQuotaRefreshEpoch(status);
      const pendingAction = packet.pending_action || "";
      const pendingProfile = String(packet.pending_profile || "");
      const activeRequests = Number(status.active_requests || 0);
      const activeTunnels = Number(status.active_websockets || 0);
      const liveBusy = Boolean(status.live_busy);
      latestLiveBusy = liveBusy;
	      if (pendingAction === "refresh_quota" && pendingProfile) {
	        quotaRefreshInFlight = pendingProfile;
	      } else if (quotaRefreshInFlight) {
	        quotaRefreshInFlight = "";
	        scheduleNextQuotaRefresh(250);
	      }
	      queueInitialQuotaRefreshes(status.profiles || []);
	      scheduleNextQuotaRefresh(250);
	      document.getElementById("activeProfile").textContent = status.active_profile || "none";
	      document.getElementById("activeRequests").textContent = String(activeRequests);
	      document.getElementById("activeTunnels").textContent = String(activeTunnels);
	      const connection = document.getElementById("connectionState");
	      const isDisconnected = connection.textContent === "Disconnected";
	      if (!isDisconnected) {
	        connection.textContent = `Live (${liveBusy ? "busy" : "idle"})`;
	        document.getElementById("proxyDot").className = "dot" + (liveBusy ? " busy" : "");
	      }
	      rememberOpenPinMenu();
      document.getElementById("profileRows").innerHTML = (status.profiles || [])
        .map((profile) => profileRow(profile, pendingAction, pendingProfile))
        .join("");
	      restoreOpenPinMenu();
      const message = document.getElementById("message");
      if (packet.message) {
        message.textContent = packet.message;
        message.classList.add("visible");
      } else {
        message.textContent = "";
        message.classList.remove("visible");
      }
    }

    function connect() {
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      const scheme = location.protocol === "https:" ? "wss" : "ws";
      socket = new WebSocket(`${scheme}://${location.host}/api/ui-ws?token=${encodeURIComponent(TOKEN)}`);
	      socket.addEventListener("open", () => {
	        setConnection("Live", "");
	        scheduleNextQuotaRefresh(250);
	      });
      socket.addEventListener("message", (event) => {
        try {
          const packet = JSON.parse(event.data);
          if (packet.type === "state") {
            render(packet);
          }
        } catch {
          setConnection("Live", "");
        }
      });
	      socket.addEventListener("close", () => {
	        quotaRefreshInFlight = "";
	        setConnection("Disconnected", "disconnected");
	        reconnectTimer = setTimeout(connect, 1500);
	      });
	      socket.addEventListener("error", () => {
	        quotaRefreshInFlight = "";
	        setConnection("Disconnected", "disconnected");
	      });
    }

	    document.addEventListener("submit", (event) => {
      const form = event.target.closest("form[data-action]");
      if (!form) return;
      if (!socket || socket.readyState !== WebSocket.OPEN) return;
      event.preventDefault();
	      const action = form.dataset.action;
	      const profile = form.dataset.profile || "";
	      if (action === "refresh_quota" && profile) {
	        quotaRefreshAttempted.add(profile);
	        let queuedIndex = quotaRefreshQueue.indexOf(profile);
	        while (queuedIndex !== -1) {
	          quotaRefreshQueue.splice(queuedIndex, 1);
	          queuedIndex = quotaRefreshQueue.indexOf(profile);
	        }
	        quotaRefreshInFlight = profile;
	      }
      socket.send(JSON.stringify({
        ...Object.fromEntries(new FormData(form).entries()),
        action,
        profile,
        token: TOKEN
	      }));
	    });

	    document.addEventListener("toggle", (event) => {
	      const menu = event.target;
	      if (!(menu instanceof HTMLDetailsElement) || !menu.classList.contains("pin-menu")) return;
	      if (menu.open) {
	        openPinMenuProfile = menu.dataset.profile || "";
	        document.querySelectorAll("details.pin-menu[open]").forEach((other) => {
	          if (other !== menu) other.open = false;
	        });
	      } else if (openPinMenuProfile === (menu.dataset.profile || "")) {
	        openPinMenuProfile = null;
	      }
	    }, true);

	    document.addEventListener("click", (event) => {
	      const target = event.target;
	      if (target instanceof Element && target.closest("details.pin-menu")) return;
	      closePinMenus();
	    });

	    document.getElementById("themeToggle").addEventListener("click", () => {
	      setTheme(effectiveTheme() === "dark" ? "light" : "dark");
	    });

	    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
	      if (!savedTheme()) {
	        document.documentElement.removeAttribute("data-theme");
	        updateThemeToggle();
	      }
	    });

	    updateThemeToggle();
	    render(INITIAL);
	    connect();
  </script>
</body>
</html>
""".replace("__TOKEN__", token_json).replace(
            "__INITIAL_STATE__", initial_json
        ).replace(
            "__ACTIVE_PROFILE__", active_profile
        ).replace(
            "__BUSY__", busy
        ).replace(
            "__ACTIVE_REQUESTS__", str(active_requests)
        ).replace(
            "__ACTIVE_WEBSOCKETS__", str(active_websockets)
        ).replace(
            "__ROWS__", rows
        )

    def send_json(self, data: dict[str, Any], *, status: int = 200) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_response_bytes(self, status: int, headers: Any, payload: bytes) -> None:
        self.send_response(status)
        for key, value in headers.items():
            lower = key.lower()
            if lower in RESPONSE_HOP_BY_HOP_HEADERS or lower in {"content-length", "content-encoding"}:
                continue
            self.send_header(key, value)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.write_downstream(payload)

    def send_logo_asset(self, name: str) -> None:
        payload = logo_asset_bytes(name)
        if payload is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("content-type", "image/png")
        self.send_header("cache-control", "public, max-age=3600")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_html(self, data: str, *, status: int = 200) -> None:
        payload = data.encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def write_state(paths: Paths, port: int) -> None:
    data = {
        "pid": os.getpid(),
        "port": port,
        "started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    paths.state.parent.mkdir(parents=True, exist_ok=True)
    temp = paths.state.with_suffix(".json.tmp")
    temp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    temp.chmod(0o600)
    temp.replace(paths.state)
    paths.state.chmod(0o600)


def serve(port: int | None = None) -> None:
    paths = Paths()
    paths.ensure_base()
    requested_port = DEFAULT_DAEMON_PORT if port is None else port
    try:
        server = ProvisionServer(("127.0.0.1", requested_port), paths)
    except OSError:
        if port is not None or requested_port == 0:
            raise
        sys.stderr.write(
            f"default port {DEFAULT_DAEMON_PORT} unavailable; using a dynamic port\n"
        )
        server = ProvisionServer(("127.0.0.1", 0), paths)
    write_state(paths, server.server_address[1])
    server.start_usage_auto_refresh()
    try:
        server.serve_forever()
    finally:
        server.stop_usage_auto_refresh()


def read_state(paths: Paths) -> dict[str, Any] | None:
    try:
        with paths.state.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def health(port: int, timeout: float = 1.0) -> dict[str, Any] | None:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception:
        return None


def can_connect(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def daemon_running(paths: Paths) -> dict[str, Any] | None:
    state = read_state(paths)
    if not state:
        return None
    port = state.get("port")
    if not isinstance(port, int):
        return None
    return health(port)


def wait_until_running(paths: Paths, deadline_seconds: float = 5.0) -> dict[str, Any]:
    deadline = time.time() + deadline_seconds
    while time.time() < deadline:
        status = daemon_running(paths)
        if status:
            return status
        time.sleep(0.1)
    raise RuntimeError(f"provision daemon did not start; see {paths.log}")
