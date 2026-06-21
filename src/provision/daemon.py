from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import html
import importlib.resources as package_resources
import json
import os
import queue
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import uuid
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
from .paths import Paths, default_codex_home
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

PROTOCOL_VERSION = 26
DEFAULT_DAEMON_HOST = "127.0.0.1"
DEFAULT_DAEMON_PORT = 4888
CHATGPT_USAGE_PATH = "/wham/usage"
CHATGPT_ANALYTICS_EVENTS_PATH = "/codex/analytics-events/events"
USAGE_CACHE_MIN_INTERVAL_SECONDS = 1.0
USAGE_CACHE_WAIT_SECONDS = 5.0
USAGE_AUTO_REFRESH_SECONDS = 3600.0
USAGE_AUTO_REFRESH_POLL_SECONDS = 30.0
USAGE_AUTO_REFRESH_ERROR_BACKOFF_SECONDS = 300.0
USAGE_AUTO_REFRESH_BILLING_BACKOFF_SECONDS = 86400.0
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
FAST_SERVICE_TIER = "priority"
STANDARD_SERVICE_TIER = "default"
FAST_SERVICE_TIER_VALUES = {"fast", FAST_SERVICE_TIER}
STATS_MAX_EVENTS = 2000
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\a]*(?:\a|\x1b\\)")
LOGIN_URL_RE = re.compile(r"https?://[^\s<>]+")
DEVICE_CODE_RE = re.compile(r"\b[A-Z0-9]{4,}(?:-[A-Z0-9]{4,})+\b")
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
PROFILE_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")
REASONING_LEVEL_PATTERN = re.compile(r"^[a-z0-9_-]{1,32}$")
REASONING_LEVELS = ("low", "medium", "high", "xhigh")
DEFAULT_MODEL_ID = "gpt-5.5"
DEFAULT_REASONING_EFFORT = "medium"
CODEX_MODEL_CATALOG_TIMEOUT_SECONDS = 2.0
CODEX_VERSION_TIMEOUT_SECONDS = 2.0
CODEX_APP_SERVER_SCHEMA_TIMEOUT_SECONDS = 10.0
CODEX_APP_SERVER_REQUEST_TIMEOUT_SECONDS = 10.0
APP_SERVER_RATE_LIMIT_CACHE_SECONDS = 300.0
APP_SERVER_RATE_LIMIT_FAILURE_BACKOFF_SECONDS = 900.0
DEFAULT_MODEL_CATALOG = [
    {
        "id": "gpt-5.5",
        "display": "gpt-5.5",
        "reasoning": list(REASONING_LEVELS),
        "default_reasoning": "medium",
        "note": "Newest bundled Codex CLI model metadata in this Provision build.",
    },
    {
        "id": "gpt-5.4",
        "display": "gpt-5.4",
        "reasoning": list(REASONING_LEVELS),
        "default_reasoning": "medium",
        "note": "",
    },
    {
        "id": "gpt-5.4-mini",
        "display": "gpt-5.4-mini",
        "reasoning": list(REASONING_LEVELS),
        "default_reasoning": "medium",
        "note": "",
    },
    {
        "id": "gpt-5.3-codex",
        "display": "gpt-5.3-codex",
        "reasoning": list(REASONING_LEVELS),
        "default_reasoning": "medium",
        "note": "",
    },
    {
        "id": "gpt-5.2",
        "display": "gpt-5.2",
        "reasoning": list(REASONING_LEVELS),
        "default_reasoning": "medium",
        "note": "",
    },
]
LOGIN_REQUIRED_MARKERS = (
    "refresh_token_reused",
    "refresh token has already been used",
    "please try signing in again",
)
LOGIN_ACTIVE_STATUSES = {"running", "canceling"}
LOGIN_BROWSER_REMOTE_NOTE = (
    "Browser login must complete in a browser running where the Provision daemon "
    "can receive localhost redirects. Use Device Auth for VM, SSH tunnel, or remote dashboards."
)
BILLING_REQUIRED_MARKERS = (
    "http error 402",
    "402: payment required",
    "payment required",
)
USAGE_PAYLOAD_STATE_MESSAGES = {
    "deactivated_workspace": {
        "title": "Workspace deactivated",
        "message": "This workspace is deactivated.",
        "level": "warning",
    },
}
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


class BillingRequiredError(AuthError):
    pass


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


def normalize_reasoning_level(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    effort = value.strip().lower()
    if not effort or not REASONING_LEVEL_PATTERN.match(effort):
        return None
    return effort


def codex_model_note(value: dict[str, Any]) -> str:
    availability = value.get("availability_nux")
    if not isinstance(availability, dict):
        availability = value.get("availabilityNux")
    message = availability.get("message") if isinstance(availability, dict) else None
    if isinstance(message, str) and message.strip():
        return message.strip().splitlines()[0]

    upgrade = value.get("upgrade")
    if isinstance(upgrade, str) and upgrade.strip():
        return f"Upgrade available: {upgrade.strip()}"
    if isinstance(upgrade, dict):
        model = upgrade.get("model")
        if isinstance(model, str) and model.strip():
            return f"Upgrade available: {model.strip()}"
    upgrade_info = value.get("upgradeInfo")
    if isinstance(upgrade_info, dict):
        model = upgrade_info.get("model")
        if isinstance(model, str) and model.strip():
            return f"Upgrade available: {model.strip()}"
    return ""


def normalize_codex_model_catalog_item(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    if value.get("hidden") is True or value.get("visibility") == "hide":
        return None

    model_id = value.get("slug") or value.get("id") or value.get("model")
    model_id = sanitize_model_id(model_id)
    if not model_id:
        return None

    display = value.get("display_name") or value.get("displayName") or model_id
    if not isinstance(display, str) or not display.strip():
        display = model_id

    raw_levels = value.get("supported_reasoning_levels")
    if raw_levels is None:
        raw_levels = value.get("supportedReasoningEfforts")
    reasoning: list[str] = []
    if isinstance(raw_levels, list):
        for raw_level in raw_levels:
            effort = raw_level
            if isinstance(raw_level, dict):
                effort = (
                    raw_level.get("effort")
                    or raw_level.get("reasoning_effort")
                    or raw_level.get("reasoningEffort")
                )
            level = normalize_reasoning_level(effort)
            if level and level not in reasoning:
                reasoning.append(level)
    if not reasoning:
        reasoning = list(REASONING_LEVELS)

    default_reasoning = (
        value.get("default_reasoning_level")
        or value.get("defaultReasoningEffort")
        or DEFAULT_REASONING_EFFORT
    )
    default_reasoning = normalize_reasoning_level(default_reasoning)
    if default_reasoning not in reasoning:
        default_reasoning = reasoning[0] if reasoning else DEFAULT_REASONING_EFFORT

    service_tiers = value.get("service_tiers")
    if service_tiers is None:
        service_tiers = value.get("serviceTiers")
    if not isinstance(service_tiers, list):
        service_tiers = []

    additional_speed_tiers = value.get("additional_speed_tiers")
    if additional_speed_tiers is None:
        additional_speed_tiers = value.get("additionalSpeedTiers")
    if not isinstance(additional_speed_tiers, list):
        additional_speed_tiers = []

    return {
        "id": model_id,
        "display": display.strip(),
        "reasoning": reasoning,
        "default_reasoning": default_reasoning,
        "note": codex_model_note(value),
        "service_tiers": [tier for tier in service_tiers if isinstance(tier, dict)],
        "additional_speed_tiers": [tier for tier in additional_speed_tiers if isinstance(tier, str)],
    }


def normalize_codex_model_catalog(value: Any) -> list[dict[str, Any]]:
    models = value.get("models") if isinstance(value, dict) else None
    if models is None and isinstance(value, dict):
        models = value.get("data")
    if not isinstance(models, list):
        return []

    catalog: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_model in models:
        item = normalize_codex_model_catalog_item(raw_model)
        if not item:
            continue
        model_id = str(item["id"])
        if model_id in seen:
            continue
        seen.add(model_id)
        catalog.append(item)
    return catalog


def subprocess_error_message(error: BaseException) -> str:
    if isinstance(error, subprocess.CalledProcessError):
        detail = (error.stderr or error.stdout or "").strip()
        if detail:
            return detail
        return f"command exited with status {error.returncode}"
    if isinstance(error, subprocess.TimeoutExpired):
        return "command timed out"
    return str(error)


@functools.lru_cache(maxsize=1)
def codex_cli_version() -> dict[str, Any]:
    try:
        result = subprocess.run(
            ["codex", "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=CODEX_VERSION_TIMEOUT_SECONDS,
        )
    except (
        FileNotFoundError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        UnicodeDecodeError,
    ) as exc:
        return {
            "available": False,
            "version": None,
            "error": subprocess_error_message(exc),
        }
    raw = result.stdout.strip()
    version = raw.split()[-1] if raw else ""
    return {
        "available": bool(version),
        "version": version or None,
        "raw": raw,
        "error": "" if version else "empty version output",
    }


@functools.lru_cache(maxsize=1)
def codex_model_catalog_probe() -> dict[str, Any]:
    error = ""
    try:
        result = subprocess.run(
            ["codex", "debug", "models", "--bundled"],
            check=True,
            capture_output=True,
            text=True,
            timeout=CODEX_MODEL_CATALOG_TIMEOUT_SECONDS,
        )
        catalog = normalize_codex_model_catalog(json.loads(result.stdout))
        if catalog:
            return {
                "source": "codex",
                "available": True,
                "count": len(catalog),
                "catalog": tuple(catalog),
                "error": "",
            }
        error = "Codex returned no visible bundled models"
    except (
        FileNotFoundError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        error = subprocess_error_message(exc)
    fallback = tuple(dict(item) for item in DEFAULT_MODEL_CATALOG)
    return {
        "source": "fallback",
        "available": False,
        "count": len(fallback),
        "catalog": fallback,
        "error": error,
    }


APP_SERVER_CAPABILITY_METHODS = {
    "account_read": "account/read",
    "account_updated": "account/updated",
    "account_login_start": "account/login/start",
    "account_login_completed": "account/login/completed",
    "account_logout": "account/logout",
    "account_rate_limits": "account/rateLimits/read",
    "account_rate_limits_updated": "account/rateLimits/updated",
    "account_usage": "account/usage/read",
    "rate_limit_reset_credit_consume": "account/rateLimitResetCredit/consume",
    "model_list": "model/list",
    "model_rerouted": "model/rerouted",
    "model_provider_capabilities_read": "modelProvider/capabilities/read",
    "model_verification": "model/verification",
    "thread_list": "thread/list",
    "thread_read": "thread/read",
    "thread_resume": "thread/resume",
    "thread_settings_update": "thread/settings/update",
    "thread_settings_updated": "thread/settings/updated",
    "thread_status_changed": "thread/status/changed",
    "thread_token_usage_updated": "thread/tokenUsage/updated",
    "turn_start": "turn/start",
    "turn_started": "turn/started",
    "turn_completed": "turn/completed",
    "turn_interrupt": "turn/interrupt",
    "turn_steer": "turn/steer",
    "remote_control_status_read": "remoteControl/status/read",
    "remote_control_enable": "remoteControl/enable",
    "remote_control_disable": "remoteControl/disable",
    "remote_control_pairing_start": "remoteControl/pairing/start",
}

APP_SERVER_CAPABILITY_GROUPS = {
    "account": (
        "account_read",
        "account_updated",
        "account_login_start",
        "account_login_completed",
        "account_logout",
    ),
    "usage": (
        "account_rate_limits",
        "account_rate_limits_updated",
        "account_usage",
        "rate_limit_reset_credit_consume",
    ),
    "model": (
        "model_list",
        "model_rerouted",
        "model_provider_capabilities_read",
        "model_verification",
    ),
    "thread": (
        "thread_list",
        "thread_read",
        "thread_resume",
        "thread_settings_update",
        "thread_settings_updated",
        "thread_status_changed",
    ),
    "token_usage": ("thread_token_usage_updated",),
    "turn": (
        "turn_start",
        "turn_started",
        "turn_completed",
        "turn_interrupt",
        "turn_steer",
    ),
    "remote_control": (
        "remote_control_status_read",
        "remote_control_enable",
        "remote_control_disable",
        "remote_control_pairing_start",
    ),
}


def app_server_capability_groups(methods: dict[str, bool]) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for group, method_names in APP_SERVER_CAPABILITY_GROUPS.items():
        missing = [name for name in method_names if not methods.get(name)]
        groups[group] = {
            "available": not missing,
            "count": len(method_names) - len(missing),
            "total": len(method_names),
            "missing": missing,
        }
    return groups


def app_server_control_plane_status(methods: dict[str, bool]) -> dict[str, Any]:
    read_only_methods = (
        "thread_list",
        "thread_read",
        "thread_status_changed",
        "thread_token_usage_updated",
    )
    interactive_methods = (
        "thread_resume",
        "turn_start",
        "turn_interrupt",
        "turn_steer",
    )
    remote_methods = (
        "remote_control_status_read",
        "remote_control_enable",
        "remote_control_disable",
        "remote_control_pairing_start",
    )
    read_only_missing = [name for name in read_only_methods if not methods.get(name)]
    interactive_missing = [name for name in interactive_methods if not methods.get(name)]
    remote_missing = [name for name in remote_methods if not methods.get(name)]
    return {
        "available": not read_only_missing,
        "read_only": not read_only_missing,
        "interactive": not interactive_missing,
        "remote_control": not remote_missing,
        "missing": {
            "read_only": read_only_missing,
            "interactive": interactive_missing,
            "remote_control": remote_missing,
        },
    }


@functools.lru_cache(maxsize=1)
def codex_app_server_schema_probe() -> dict[str, Any]:
    unavailable_methods = {name: False for name in APP_SERVER_CAPABILITY_METHODS}
    try:
        with tempfile.TemporaryDirectory(prefix="provision-codex-app-server-") as temp:
            out_dir = Path(temp)
            result = subprocess.run(
                [
                    "codex",
                    "app-server",
                    "generate-json-schema",
                    "--experimental",
                    "--out",
                    str(out_dir),
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=CODEX_APP_SERVER_SCHEMA_TIMEOUT_SECONDS,
            )
            schema_files = sorted(path.relative_to(out_dir).as_posix() for path in out_dir.rglob("*.json"))
            client_request = out_dir / "ClientRequest.json"
            schema_text = client_request.read_text(encoding="utf-8") if client_request.exists() else ""
            schema_text += "\n".join(
                path.read_text(encoding="utf-8", errors="ignore")
                for path in out_dir.rglob("*.json")
                if path != client_request
            )
    except (
        FileNotFoundError,
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        UnicodeDecodeError,
    ) as exc:
        return {
            "available": False,
            "source": "unavailable",
            "methods": unavailable_methods,
            "capability_groups": app_server_capability_groups(unavailable_methods),
            "control_plane": app_server_control_plane_status(unavailable_methods),
            "response_types": {},
            "schema_count": 0,
            "error": subprocess_error_message(exc),
        }

    methods = {name: method in schema_text for name, method in APP_SERVER_CAPABILITY_METHODS.items()}
    response_types = {
        "rate_limits_response": "v2/GetAccountRateLimitsResponse.json" in schema_files,
        "usage_response": "v2/GetAccountTokenUsageResponse.json" in schema_files,
        "reset_credit_response": "v2/ConsumeAccountRateLimitResetCreditResponse.json" in schema_files,
        "reset_credit_summary": "v2/RateLimitResetCreditsSummary.json" in schema_files,
    }
    available = (
        methods["account_rate_limits"]
        and methods["account_usage"]
        and response_types["rate_limits_response"]
        and response_types["usage_response"]
    )
    return {
        "available": available,
        "source": "codex",
        "methods": methods,
        "capability_groups": app_server_capability_groups(methods),
        "control_plane": app_server_control_plane_status(methods),
        "response_types": response_types,
        "schema_count": len(schema_files),
        "stdout": result.stdout.strip(),
        "error": "",
    }


class CodexAppServerError(RuntimeError):
    pass


class CodexAppServerClient:
    def __init__(
        self,
        *,
        env: dict[str, str] | None = None,
        timeout: float = CODEX_APP_SERVER_REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self.env = env
        self.timeout = timeout
        self.process: subprocess.Popen[str] | None = None
        self._reader: threading.Thread | None = None
        self._messages: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._pending: dict[int, dict[str, Any]] = {}
        self._request_id = 0

    def __enter__(self) -> CodexAppServerClient:
        self.start()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def start(self) -> None:
        if self.process is not None:
            return
        self.process = subprocess.Popen(
            ["codex", "app-server", "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            env=self.env,
        )
        if self.process.stdin is None or self.process.stdout is None:
            raise CodexAppServerError("codex app-server did not expose stdio")
        self._reader = threading.Thread(target=self._read_stdout, name="provision-codex-app-server", daemon=True)
        self._reader.start()
        self.initialize()

    def _read_stdout(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        for line in self.process.stdout:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict):
                self._messages.put(message)
        self._messages.put(None)

    def close(self) -> None:
        process = self.process
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
        self.process = None

    def initialize(self) -> None:
        self.request(
            "initialize",
            {
                "clientInfo": {
                    "name": "provision",
                    "title": "Provision",
                    "version": PROTOCOL_VERSION,
                },
                "capabilities": {"experimentalApi": True},
            },
        )
        self.notify("initialized", {})

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._send({"method": method, "params": params or {}})

    def request(self, method: str, params: Any = None) -> Any:
        self._request_id += 1
        request_id = self._request_id
        payload: dict[str, Any] = {"method": method, "id": request_id}
        if params is not None:
            payload["params"] = params
        self._send(payload)

        deadline = time.monotonic() + self.timeout
        while True:
            pending = self._pending.pop(request_id, None)
            if pending is not None:
                return self._response_result(pending)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CodexAppServerError(f"codex app-server request timed out: {method}")
            try:
                message = self._messages.get(timeout=remaining)
            except queue.Empty as exc:
                raise CodexAppServerError(f"codex app-server request timed out: {method}") from exc
            if message is None:
                raise CodexAppServerError("codex app-server exited before completing request")
            message_id = message.get("id")
            if message_id == request_id:
                return self._response_result(message)
            if isinstance(message_id, int):
                self._pending[message_id] = message

    def _send(self, payload: dict[str, Any]) -> None:
        if self.process is None or self.process.stdin is None:
            raise CodexAppServerError("codex app-server is not running")
        self.process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
        self.process.stdin.flush()

    def _response_result(self, message: dict[str, Any]) -> Any:
        if "error" in message:
            raise CodexAppServerError(str(message["error"]))
        return message.get("result")

    def read_account_rate_limits(self) -> dict[str, Any]:
        result = self.request("account/rateLimits/read")
        if not isinstance(result, dict):
            raise CodexAppServerError("account/rateLimits/read returned a non-object result")
        return result

    def read_account_usage(self) -> dict[str, Any]:
        result = self.request("account/usage/read")
        if not isinstance(result, dict):
            raise CodexAppServerError("account/usage/read returned a non-object result")
        return result

    def consume_account_rate_limit_reset_credit(self, idempotency_key: str) -> dict[str, Any]:
        result = self.request(
            "account/rateLimitResetCredit/consume",
            {"idempotencyKey": idempotency_key},
        )
        if not isinstance(result, dict):
            raise CodexAppServerError("account/rateLimitResetCredit/consume returned a non-object result")
        return result


def codex_compatibility_payload() -> dict[str, Any]:
    catalog = codex_model_catalog_probe()
    return {
        "cli": codex_cli_version(),
        "model_catalog": {
            "source": catalog.get("source"),
            "available": catalog.get("available"),
            "count": catalog.get("count"),
            "error": catalog.get("error") or "",
        },
        "app_server": codex_app_server_schema_probe(),
    }


def load_codex_model_catalog() -> tuple[dict[str, Any], ...]:
    catalog = codex_model_catalog_probe().get("catalog")
    return catalog if isinstance(catalog, tuple) else tuple(dict(item) for item in DEFAULT_MODEL_CATALOG)


def model_catalog() -> list[dict[str, Any]]:
    catalog = []
    for item in load_codex_model_catalog():
        copied = dict(item)
        if isinstance(copied.get("reasoning"), list):
            copied["reasoning"] = list(copied["reasoning"])
        if isinstance(copied.get("service_tiers"), list):
            copied["service_tiers"] = list(copied["service_tiers"])
        if isinstance(copied.get("additional_speed_tiers"), list):
            copied["additional_speed_tiers"] = list(copied["additional_speed_tiers"])
        catalog.append(copied)
    return catalog


def model_catalog_entry(model: str | None) -> dict[str, Any] | None:
    if not isinstance(model, str):
        return None
    for item in model_catalog():
        if item.get("id") == model:
            return item
    return None


def sanitize_model_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    model = value.strip()
    if not model or not PROFILE_MODEL_PATTERN.match(model):
        return None
    return model


def default_reasoning_for_model(model: str | None) -> str:
    entry = model_catalog_entry(model)
    default = entry.get("default_reasoning") if entry else None
    if isinstance(default, str) and default in reasoning_levels_for_model(model):
        return default
    return DEFAULT_REASONING_EFFORT


def reasoning_levels_for_model(model: str | None) -> list[str]:
    entry = model_catalog_entry(model)
    levels = entry.get("reasoning") if entry else None
    if isinstance(levels, list):
        cleaned = [level for level in levels if isinstance(level, str) and level in REASONING_LEVELS]
        if cleaned:
            return cleaned
    return list(REASONING_LEVELS)


def sanitize_reasoning_effort(value: Any, model: str | None = None) -> str | None:
    effort = normalize_reasoning_level(value)
    if not effort:
        return None
    if effort not in reasoning_levels_for_model(model):
        return None
    return effort


def model_display_name(model: str | None) -> str:
    entry = model_catalog_entry(model)
    display = entry.get("display") if entry else None
    if isinstance(display, str) and display:
        return display
    return model or DEFAULT_MODEL_ID


def reasoning_display_name(effort: str | None) -> str:
    return effort or ""


def model_setting_label(model: str | None, reasoning_effort: str | None) -> str:
    model_label = model_display_name(model)
    if reasoning_effort:
        return f"{model_label} / {reasoning_display_name(reasoning_effort)}"
    return model_label


def model_pill_label(model: str | None, reasoning_effort: str | None) -> str:
    model_label = (model or DEFAULT_MODEL_ID).lower()
    if reasoning_effort:
        return f"{model_label} {reasoning_display_name(reasoning_effort)}"
    return model_label


def read_stock_codex_model_setting() -> tuple[str, str]:
    path = default_codex_home() / "config.toml"
    try:
        with path.open("rb") as handle:
            config = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return DEFAULT_MODEL_ID, DEFAULT_REASONING_EFFORT
    model = sanitize_model_id(config.get("model")) or DEFAULT_MODEL_ID
    reasoning = sanitize_reasoning_effort(config.get("model_reasoning_effort"), model)
    return model, reasoning or default_reasoning_for_model(model)


def auth_error_requires_login(error: BaseException | str) -> bool:
    message = str(error).lower()
    return any(marker in message for marker in LOGIN_REQUIRED_MARKERS)


def login_required_message(error: BaseException | str | None = None) -> str:
    detail = str(error or "").strip()
    lowered = detail.lower()
    if "refresh_token_reused" in lowered or "refresh token has already been used" in lowered:
        return (
            "Login required: this profile's refresh token is stale or was already used. "
            "Start Login from the dashboard and prefer Device Auth when using a VM, SSH tunnel, "
            "or remote dashboard."
        )
    if auth_error_requires_login(detail):
        return (
            "Login required: this profile needs a fresh Codex CLI ChatGPT login. "
            "Start Login from the dashboard or run `provision login <profile> --device-auth`."
        )
    return detail or "Login required."


def error_requires_billing(error: BaseException | str | None) -> bool:
    if isinstance(error, BillingRequiredError):
        return True
    if isinstance(error, urllib.error.HTTPError) and error.code == 402:
        return True
    if error is None:
        return False
    message = str(error).lower()
    return any(marker in message for marker in BILLING_REQUIRED_MARKERS)


def http_error_detail_message(exc: urllib.error.HTTPError, detail: bytes | None) -> str:
    if detail:
        text = detail.decode("utf-8", errors="replace").strip()
        if text:
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                return text
            if isinstance(payload, dict):
                error = payload.get("error")
                if isinstance(error, dict):
                    message = error.get("message")
                    if isinstance(message, str) and message.strip():
                        return message.strip()
                message = payload.get("message")
                if isinstance(message, str) and message.strip():
                    return message.strip()
            return text
    return str(exc)


def billing_required_message(error: BaseException | str | None = None) -> str:
    if state := usage_payload_state(error):
        return state["message"]
    detail = str(error or "").strip()
    base = (
        "Billing required: this Codex CLI profile returned HTTP 402 Payment Required. "
        "Provision has paused automatic quota refreshes for this profile."
    )
    if not detail or detail.lower() in {"http error 402: payment required", "payment required"}:
        return base
    return f"{base} Upstream detail: {detail}"


def quota_refresh_error_message(error: BaseException | str | None) -> str:
    if state := usage_payload_state(error):
        return state["message"]
    if auth_error_requires_login(error or ""):
        return login_required_message(error)
    if error_requires_billing(error):
        return billing_required_message(error)
    return str(error or "")


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


def normalize_daemon_host(host: str | None) -> str:
    value = (host or DEFAULT_DAEMON_HOST).strip()
    return value or DEFAULT_DAEMON_HOST


def daemon_connect_host(host: str | None) -> str:
    value = normalize_daemon_host(host)
    if value in {"0.0.0.0", "::", "[::]"}:
        return DEFAULT_DAEMON_HOST
    return value


def daemon_url_host(host: str | None) -> str:
    value = daemon_connect_host(host)
    if ":" in value and not value.startswith("["):
        return f"[{value}]"
    return value


def daemon_bind_host(host: str | None) -> str:
    value = normalize_daemon_host(host)
    if ":" in value and not value.startswith("["):
        return f"[{value}]"
    return value


def daemon_bind_address(host: str | None, port: object) -> str:
    return f"{daemon_bind_host(host)}:{port}"


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


def encode_websocket_frame(opcode: int, payload: bytes, *, masked: bool = False) -> bytes:
    first = 0x80 | (opcode & 0x0F)
    length = len(payload)
    mask_bit = 0x80 if masked else 0
    if length < 126:
        header = struct.pack("!BB", first, mask_bit | length)
    elif length <= 0xFFFF:
        header = struct.pack("!BBH", first, mask_bit | 126, length)
    else:
        header = struct.pack("!BBQ", first, mask_bit | 127, length)
    if not masked:
        return header + payload
    mask = os.urandom(4)
    masked_payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return header + mask + masked_payload


class WebSocketMessageRewriter:
    def __init__(self, *, mask_output: bool) -> None:
        self.buffer = bytearray()
        self.mask_output = mask_output
        self.fragment_opcode: int | None = None
        self.fragment_parts: list[bytes] = []

    def feed(
        self,
        data: bytes,
        rewrite: Callable[[int, bytes], bytes],
    ) -> tuple[bytes, list[tuple[int, bytes]]]:
        self.buffer.extend(data)
        output = bytearray()
        messages: list[tuple[int, bytes]] = []
        offset = 0

        while True:
            parsed = self._parse_frame_at(offset)
            if parsed is None:
                break
            frame_length, fin, opcode, payload, raw_frame = parsed
            offset += frame_length
            if opcode in (0x1, 0x2):
                if fin:
                    rewritten = rewrite(opcode, payload)
                    messages.append((opcode, rewritten))
                    if rewritten == payload:
                        output.extend(raw_frame)
                    else:
                        output.extend(
                            encode_websocket_frame(
                                opcode,
                                rewritten,
                                masked=self.mask_output,
                            )
                        )
                    continue
                self.fragment_opcode = opcode
                self.fragment_parts = [payload]
                continue
            if opcode == 0x0 and self.fragment_opcode is not None:
                self.fragment_parts.append(payload)
                if fin:
                    message_opcode = self.fragment_opcode
                    rewritten = rewrite(message_opcode, b"".join(self.fragment_parts))
                    messages.append((message_opcode, rewritten))
                    output.extend(
                        encode_websocket_frame(
                            message_opcode,
                            rewritten,
                            masked=self.mask_output,
                        )
                    )
                    self.fragment_opcode = None
                    self.fragment_parts = []
                continue
            output.extend(raw_frame)

        if offset:
            del self.buffer[:offset]
        return bytes(output), messages

    def _parse_frame_at(
        self,
        offset: int,
    ) -> tuple[int, bool, int, bytes, bytes] | None:
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

        raw_end = cursor + length
        raw_frame = bytes(self.buffer[offset:raw_end])
        payload = bytes(self.buffer[cursor:raw_end])
        if mask:
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        return raw_end - offset, fin, opcode, payload, raw_frame


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


def rewrite_service_tier_value(value: Any, *, fast_enabled: bool) -> tuple[Any, str | None, bool]:
    if isinstance(value, list):
        changed = False
        service_tier = None
        rewritten = []
        for item in value:
            next_item, next_tier, next_changed = rewrite_service_tier_value(
                item,
                fast_enabled=fast_enabled,
            )
            rewritten.append(next_item)
            changed = changed or next_changed
            service_tier = next_tier or service_tier
        return rewritten, service_tier, changed
    if not isinstance(value, dict):
        return value, None, False

    rewritten = dict(value)
    current = rewritten.get("service_tier")
    changed = False
    if fast_enabled:
        if current != FAST_SERVICE_TIER:
            rewritten["service_tier"] = FAST_SERVICE_TIER
            changed = True
    elif current in FAST_SERVICE_TIER_VALUES:
        rewritten.pop("service_tier", None)
        changed = True
    service_tier = rewritten.get("service_tier")
    return rewritten, service_tier if isinstance(service_tier, str) else None, changed


def rewrite_service_tier_body(body: bytes | None, *, fast_enabled: bool) -> tuple[bytes | None, str | None, bool]:
    if not body:
        return body, None, False
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return body, None, False
    rewritten, service_tier, changed = rewrite_service_tier_value(value, fast_enabled=fast_enabled)
    if not changed:
        return body, service_tier, False
    encoded = json.dumps(rewritten, separators=(",", ":")).encode("utf-8")
    return encoded, service_tier, True


def rewrite_service_tier_websocket_message(
    opcode: int,
    payload: bytes,
    *,
    fast_enabled: bool,
) -> tuple[bytes, str | None, bool]:
    if opcode != 0x1:
        return payload, None, False
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return payload, None, False
    if not json_top_level_has_event_type(value, WEBSOCKET_RESPONSE_START_EVENT_TYPES):
        return payload, None, False
    rewritten_value, service_tier, changed = rewrite_service_tier_value(
        value,
        fast_enabled=fast_enabled,
    )
    if not changed:
        return payload, service_tier, False
    rewritten = json.dumps(rewritten_value, separators=(",", ":")).encode("utf-8")
    return rewritten, service_tier, changed


def apply_model_setting(
    value: dict[str, Any],
    *,
    model: str | None,
    reasoning_effort: str | None,
) -> tuple[dict[str, Any], bool]:
    rewritten = dict(value)
    changed = False
    if model and rewritten.get("model") != model:
        rewritten["model"] = model
        changed = True
    if reasoning_effort:
        reasoning = rewritten.get("reasoning")
        next_reasoning = dict(reasoning) if isinstance(reasoning, dict) else {}
        if next_reasoning.get("effort") != reasoning_effort:
            next_reasoning["effort"] = reasoning_effort
            rewritten["reasoning"] = next_reasoning
            changed = True
    return rewritten, changed


def rewrite_model_body(
    body: bytes | None,
    *,
    model: str | None,
    reasoning_effort: str | None,
) -> tuple[bytes | None, str | None, str | None, bool]:
    if not body or not model:
        return body, model, reasoning_effort, False
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return body, model, reasoning_effort, False
    if not isinstance(value, dict):
        return body, model, reasoning_effort, False
    rewritten, changed = apply_model_setting(
        value,
        model=model,
        reasoning_effort=reasoning_effort,
    )
    if not changed:
        return body, model, reasoning_effort, False
    encoded = json.dumps(rewritten, separators=(",", ":")).encode("utf-8")
    return encoded, model, reasoning_effort, True


def rewrite_model_websocket_message(
    opcode: int,
    payload: bytes,
    *,
    model: str | None,
    reasoning_effort: str | None,
) -> tuple[bytes, str | None, str | None, bool]:
    if opcode != 0x1 or not model:
        return payload, model, reasoning_effort, False
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return payload, model, reasoning_effort, False
    if not json_top_level_has_event_type(value, WEBSOCKET_RESPONSE_START_EVENT_TYPES):
        return payload, model, reasoning_effort, False
    if not isinstance(value, dict):
        return payload, model, reasoning_effort, False
    rewritten_value = dict(value)
    target = rewritten_value.get("response")
    if isinstance(target, dict):
        rewritten_target, changed = apply_model_setting(
            target,
            model=model,
            reasoning_effort=reasoning_effort,
        )
        rewritten_value["response"] = rewritten_target
    else:
        rewritten_value, changed = apply_model_setting(
            rewritten_value,
            model=model,
            reasoning_effort=reasoning_effort,
        )
    if not changed:
        return payload, model, reasoning_effort, False
    encoded = json.dumps(rewritten_value, separators=(",", ":")).encode("utf-8")
    return encoded, model, reasoning_effort, True


def int_value(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        return max(0, int(value))
    return 0


def token_usage_from_value(value: Any) -> dict[str, int] | None:
    if isinstance(value, list):
        for item in value:
            usage = token_usage_from_value(item)
            if usage:
                return usage
        return None
    if not isinstance(value, dict):
        return None

    usage = value.get("usage")
    if isinstance(usage, dict):
        normalized = normalize_token_usage(usage)
        if normalized:
            return normalized
    normalized = normalize_token_usage(value)
    if normalized:
        return normalized
    for item in value.values():
        usage = token_usage_from_value(item)
        if usage:
            return usage
    return None


def normalize_token_usage(value: dict[str, Any]) -> dict[str, int] | None:
    has_usage_key = any(
        key in value
        for key in (
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "prompt_tokens",
            "completion_tokens",
        )
    )
    if not has_usage_key:
        return None
    input_tokens = int_value(value.get("input_tokens", value.get("prompt_tokens")))
    output_tokens = int_value(value.get("output_tokens", value.get("completion_tokens")))
    cached_input_tokens = int_value(value.get("cached_input_tokens"))
    reasoning_output_tokens = int_value(value.get("reasoning_output_tokens"))
    input_details = value.get("input_tokens_details")
    if isinstance(input_details, dict):
        cached_input_tokens = max(cached_input_tokens, int_value(input_details.get("cached_tokens")))
    output_details = value.get("output_tokens_details")
    if isinstance(output_details, dict):
        reasoning_output_tokens = max(
            reasoning_output_tokens,
            int_value(output_details.get("reasoning_tokens")),
        )
    total_tokens = int_value(value.get("total_tokens"))
    if total_tokens <= 0:
        total_tokens = input_tokens + output_tokens
    return {
        "input_tokens": input_tokens,
        "cached_input_tokens": cached_input_tokens,
        "output_tokens": output_tokens,
        "reasoning_output_tokens": reasoning_output_tokens,
        "total_tokens": total_tokens,
    }


def websocket_message_token_usage(opcode: int, payload: bytes) -> dict[str, int] | None:
    value = websocket_message_json(opcode, payload)
    if value is None:
        return None
    return token_usage_from_value(value)


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
    used_percent = window.get("used_percent", window.get("usedPercent"))
    if not isinstance(used_percent, (int, float)):
        return None
    usage_window: dict[str, Any] = {"used_percent": float(used_percent)}
    window_minutes = window.get("window_minutes", window.get("windowDurationMins"))
    if isinstance(window_minutes, (int, float)):
        usage_window["limit_window_seconds"] = int(window_minutes * 60)
    reset_at = window.get("reset_at", window.get("resets_at", window.get("resetsAt")))
    if isinstance(reset_at, (int, float, str)):
        usage_window["reset_at"] = reset_at
    return usage_window


def normalize_credits_snapshot(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    credits: dict[str, Any] = {}
    if "has_credits" in value:
        credits["has_credits"] = value["has_credits"]
    elif "hasCredits" in value:
        credits["has_credits"] = value["hasCredits"]
    if "unlimited" in value:
        credits["unlimited"] = value["unlimited"]
    if "balance" in value:
        credits["balance"] = value["balance"]
    return credits if credits else None


def normalize_rate_limit_reset_credits_summary(value: Any) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    raw_count = value.get("available_count", value.get("availableCount"))
    if isinstance(raw_count, bool):
        return None
    if isinstance(raw_count, int):
        return {"available_count": max(0, raw_count)}
    if isinstance(raw_count, str):
        try:
            return {"available_count": max(0, int(raw_count))}
        except ValueError:
            return None
    return None


def usage_payload_from_rate_limit_snapshot(snapshot: Any) -> dict[str, Any] | None:
    if not isinstance(snapshot, dict):
        return None
    rate_limit: dict[str, Any] = {}
    primary = event_window_to_usage_window(snapshot.get("primary"))
    secondary = event_window_to_usage_window(snapshot.get("secondary"))
    if primary is not None:
        rate_limit["primary_window"] = primary
    if secondary is not None:
        rate_limit["secondary_window"] = secondary
    credits = normalize_credits_snapshot(snapshot.get("credits"))
    if isinstance(credits, dict):
        rate_limit["credits"] = credits
    reached_type = snapshot.get("rate_limit_reached_type", snapshot.get("rateLimitReachedType"))
    if isinstance(reached_type, str):
        rate_limit["rate_limit_reached_type"] = reached_type
    limit_id = normalize_rate_limit_id(
        snapshot.get("metered_limit_name")
        or snapshot.get("meteredLimitName")
        or snapshot.get("limit_id")
        or snapshot.get("limitId")
        or snapshot.get("limit_name")
        or snapshot.get("limitName")
    )
    payload: dict[str, Any] = {}
    if isinstance(credits, dict):
        payload["credits"] = credits
    if not rate_limit and not payload.get("credits"):
        return None
    plan_type = snapshot.get("plan_type", snapshot.get("planType"))
    if isinstance(plan_type, str):
        payload["plan_type"] = plan_type
    if limit_id == "codex":
        if not rate_limit:
            return payload
        payload["rate_limit"] = rate_limit
    else:
        if not rate_limit:
            return payload
        payload["additional_rate_limits"] = [
            {
                "limit_name": str(snapshot.get("limit_name") or snapshot.get("limitName") or limit_id),
                "metered_feature": limit_id,
                "rate_limit": rate_limit,
            }
        ]
    return payload


def usage_payload_from_app_server_rate_limits_response(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    payload = usage_payload_from_rate_limit_snapshot(value.get("rateLimits")) or {}
    by_limit_id = value.get("rateLimitsByLimitId")
    if isinstance(by_limit_id, dict):
        for limit_id, snapshot in by_limit_id.items():
            if not isinstance(snapshot, dict):
                continue
            enriched = dict(snapshot)
            enriched.setdefault("limitId", limit_id)
            update = usage_payload_from_rate_limit_snapshot(enriched)
            if update:
                payload = merge_usage_payload(payload, update)
    reset_credits = normalize_rate_limit_reset_credits_summary(value.get("rateLimitResetCredits"))
    if reset_credits is not None:
        payload["rate_limit_reset_credits"] = reset_credits
    return payload or None


def usage_payload_from_rate_limit_event(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    event = json_value_event_type(value)
    if event == "codex.rate_limits":
        details = value.get("rate_limits")
        snapshot = dict(details) if isinstance(details, dict) else {}
        for key in (
            "metered_limit_name",
            "meteredLimitName",
            "limit_id",
            "limitId",
            "limit_name",
            "limitName",
            "credits",
            "plan_type",
            "planType",
            "rate_limit_reached_type",
            "rateLimitReachedType",
        ):
            if key in value and key not in snapshot:
                snapshot[key] = value[key]
        return usage_payload_from_rate_limit_snapshot(snapshot)
    if value.get("type") == "token_count" and isinstance(value.get("rate_limits"), dict):
        return usage_payload_from_rate_limit_snapshot(value["rate_limits"])
    payload = value.get("payload")
    if isinstance(payload, dict):
        return usage_payload_from_rate_limit_event(payload)
    return None


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
    if isinstance(update.get("rate_limit_reset_credits"), dict):
        merged["rate_limit_reset_credits"] = dict(update["rate_limit_reset_credits"])

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


def provision_limit_name(
    active_profile: str,
    updated_at: datetime | None,
    model_label: str | None = None,
) -> str:
    profile_label = active_profile
    if model_label:
        profile_label = f"{profile_label} - {model_label}"
    if updated_at is None:
        return f"Provision ({profile_label})"
    return f"Provision ({profile_label} - updated {format_status_updated_at(updated_at)})"


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
    model_label: str | None = None,
    default_profile: str | None = None,
    default_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    labeled = dict(usage_payload_status_fallback(payload) or payload)
    additional = upsert_additional_rate_limit(
        labeled.get("additional_rate_limits"),
        additional_rate_limit(
            limit_name=provision_limit_name(active_profile, updated_at, model_label),
            metered_feature="codex",
            rate_limit=labeled.get("rate_limit"),
        ),
    )

    if default_profile and default_payload:
        default_labeled = usage_payload_status_fallback(default_payload) or default_payload
        additional = upsert_additional_rate_limit(
            additional,
            additional_rate_limit(
                limit_name=f"Provision profile ({default_profile})",
                metered_feature=DEFAULT_PROFILE_CODEX_LIMIT_ID,
                rate_limit=default_labeled.get("rate_limit"),
            ),
        )
        default_additional = default_labeled.get("additional_rate_limits")
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


def usage_payload_state_code(payload: Any) -> str | None:
    def visit(value: Any, depth: int = 0) -> str | None:
        if depth > 5:
            return None
        if isinstance(value, str):
            raw = value.strip()
            if raw in USAGE_PAYLOAD_STATE_MESSAGES:
                return raw
            if raw.startswith("{") and raw.endswith("}"):
                try:
                    decoded = json.loads(raw)
                except json.JSONDecodeError:
                    return None
                return visit(decoded, depth + 1)
            return None
        if not isinstance(value, dict):
            return None
        code = value.get("code")
        if isinstance(code, str) and code.strip():
            return code.strip()
        for key in ("detail", "error", "message", "reason", "status"):
            code = visit(value.get(key), depth + 1)
            if code:
                return code
        return None

    return visit(payload)


def humanize_code(value: str) -> str:
    words = [word for word in value.replace("-", "_").split("_") if word]
    return " ".join(words).capitalize() if words else "Unavailable"


def usage_payload_state(payload: Any) -> dict[str, str] | None:
    code = usage_payload_state_code(payload)
    if not code:
        return None
    message = USAGE_PAYLOAD_STATE_MESSAGES.get(code)
    if isinstance(message, dict):
        return {
            "code": code,
            "title": str(message.get("title") or humanize_code(code)),
            "message": str(message.get("message") or "Quota is unavailable for this profile."),
            "level": str(message.get("level") or "warning"),
        }
    return {
        "code": code,
        "title": "Quota unavailable",
        "message": f"Upstream returned {humanize_code(code).lower()}.",
        "level": "warning",
    }


def usage_payload_status_fallback(payload: dict[str, Any]) -> dict[str, Any] | None:
    state = usage_payload_state(payload)
    if not state or quota_bucket_rows(payload):
        return None
    return {
        "rate_limit": {
            "allowed": False,
            "reason": state["title"],
        },
    }


def usage_cache_summary(entry: dict[str, Any] | None) -> str:
    if not entry:
        return "No quota cached"
    payload = entry.get("payload")
    fetched_at = entry.get("fetched_at")
    error = entry.get("error")
    if not isinstance(payload, dict):
        if error:
            return quota_refresh_error_message(error)
        return "No quota cached"
    prefix = "Updated"
    if isinstance(fetched_at, datetime):
        prefix = f"Updated {format_status_updated_at(fetched_at)}"
    state = usage_payload_state(payload)
    if state and not quota_bucket_rows(payload):
        return f"{prefix}; {state['title']}"
    summary = (
        "unlimited or unmetered quota"
        if quota_payload_unlimited(payload)
        else usage_rate_limit_summary(payload.get("rate_limit"))
    )
    additional = payload.get("additional_rate_limits")
    extra = ""
    if isinstance(additional, list) and additional:
        bucket_count = len([row for row in additional if isinstance(row, dict)])
        if bucket_count:
            extra = f"; {bucket_count} extra bucket{'s' if bucket_count != 1 else ''}"
    if error_requires_billing(error):
        suffix = "; billing required on last refresh"
    else:
        suffix = f"; last refresh failed: {error}" if error else ""
    return f"{prefix}; {summary}{extra}{suffix}"


def quota_bucket_rows(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []

    buckets: list[dict[str, Any]] = []
    credits = payload.get("credits")
    credits = credits if isinstance(credits, dict) else None
    if isinstance(payload.get("rate_limit"), dict):
        rate_limit = dict(payload["rate_limit"])
        if credits:
            rate_limit["credits"] = credits
        buckets.append(
            {
                "name": "Codex",
                "metered_feature": "codex",
                "rate_limit": rate_limit,
            }
        )
    elif credits:
        buckets.append(
            {
                "name": "Codex",
                "metered_feature": "codex",
                "rate_limit": {
                    "allowed": bool(credits.get("has_credits", True)),
                    "credits": credits,
                },
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


def quota_rate_limit_unlimited(rate_limit: dict[str, Any]) -> bool:
    for key in ("unlimited", "quota_unlimited", "limits_disabled"):
        if rate_limit.get(key) is True:
            return True
    credits = rate_limit.get("credits")
    return isinstance(credits, dict) and credits.get("unlimited") is True


def quota_payload_unlimited(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    credits = payload.get("credits")
    if isinstance(credits, dict) and credits.get("unlimited") is True:
        return True
    rate_limit = payload.get("rate_limit")
    if isinstance(rate_limit, dict) and quota_rate_limit_unlimited(rate_limit):
        return True
    additional = payload.get("additional_rate_limits")
    if isinstance(additional, list):
        for row in additional:
            if isinstance(row, dict) and isinstance(row.get("rate_limit"), dict):
                if quota_rate_limit_unlimited(row["rate_limit"]):
                    return True
    return False


def quota_payload_credits(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    credits = payload.get("credits")
    if isinstance(credits, dict):
        return credits
    rate_limit = payload.get("rate_limit")
    if isinstance(rate_limit, dict) and isinstance(rate_limit.get("credits"), dict):
        return rate_limit["credits"]
    additional = payload.get("additional_rate_limits")
    if isinstance(additional, list):
        for row in additional:
            if not isinstance(row, dict) or not isinstance(row.get("rate_limit"), dict):
                continue
            credits = row["rate_limit"].get("credits")
            if isinstance(credits, dict):
                return credits
    return None


def credit_balance_is_zero(value: str) -> bool:
    cleaned = re.sub(r"[^0-9.+-]", "", value.replace(",", ""))
    if cleaned in {"", ".", "+", "-", "+.", "-."}:
        return False
    try:
        return float(cleaned) == 0.0
    except ValueError:
        return False


def credit_balance_label(credits: Any) -> str:
    if not isinstance(credits, dict) or credits.get("has_credits") is False:
        return ""
    if credits.get("unlimited") is True:
        return "\u221e"
    balance = credits.get("balance")
    if balance is not None:
        label = str(balance).strip()
        if label and not credit_balance_is_zero(label):
            return label
        return ""
    return "Available" if credits.get("has_credits") is True else ""


def render_quota_credits_pill(payload: Any) -> str:
    label = credit_balance_label(quota_payload_credits(payload))
    if not label:
        return ""
    return f'<span class="quota-credits-pill" title="Codex credits balance">Credits: {html.escape(label)}</span>'


def quota_payload_reset_credit_count(payload: Any) -> int:
    if not isinstance(payload, dict):
        return 0
    summary = payload.get("rate_limit_reset_credits")
    if not isinstance(summary, dict):
        return 0
    count = summary.get("available_count", summary.get("availableCount"))
    if isinstance(count, bool):
        return 0
    if isinstance(count, int):
        return max(0, count)
    if isinstance(count, str):
        try:
            return max(0, int(count))
        except ValueError:
            return 0
    return 0


def render_reset_credit_control(payload: Any, profile: str | None, token: str | None) -> str:
    count = quota_payload_reset_credit_count(payload)
    if count <= 0 or not profile or not token:
        return ""
    escaped_profile = html.escape(profile)
    label = f"Reset credit: {count}" if count == 1 else f"Reset credits: {count}"
    confirm = "Use one rate-limit reset credit for this Codex CLI profile?"
    return f"""
      <form method="post" action="/api/consume-reset-credit" class="reset-credit-form" data-action="consume_reset_credit" data-profile="{escaped_profile}" data-confirm="{html.escape(confirm)}">
        <input type="hidden" name="token" value="{html.escape(token)}">
        <input type="hidden" name="profile" value="{escaped_profile}">
        <button class="quota-reset-credit-pill" title="Use one rate-limit reset credit">{html.escape(label)}</button>
      </form>
    """


def quota_remaining_snapshot(payload: Any) -> dict[str, dict[str, float | None]]:
    snapshot: dict[str, dict[str, float | None]] = {}
    for bucket in quota_bucket_rows(payload):
        name = str(bucket.get("name") or bucket.get("metered_feature") or "quota")
        rate_limit = bucket.get("rate_limit")
        if not isinstance(rate_limit, dict):
            continue
        snapshot[name] = {
            "primary_remaining_percent": quota_window_remaining_percent(
                rate_limit.get("primary_window")
            ),
            "weekly_remaining_percent": quota_window_remaining_percent(
                rate_limit.get("secondary_window")
            ),
        }
    return snapshot


def quota_remaining_delta(
    old_payload: Any,
    new_payload: Any,
) -> dict[str, dict[str, float | None]]:
    old_snapshot = quota_remaining_snapshot(old_payload)
    new_snapshot = quota_remaining_snapshot(new_payload)
    delta: dict[str, dict[str, float | None]] = {}
    for name, current in new_snapshot.items():
        previous = old_snapshot.get(name, {})
        bucket_delta: dict[str, float | None] = dict(current)
        for key, value in current.items():
            old_value = previous.get(key)
            bucket_delta[key.replace("_remaining_percent", "_delta_percent")] = (
                round(float(value) - float(old_value), 2)
                if isinstance(value, (int, float)) and isinstance(old_value, (int, float))
                else None
            )
        delta[name] = bucket_delta
    return delta


def compact_stats_event(event: dict[str, Any]) -> dict[str, Any]:
    event_type = str(event.get("type") or "")
    compact = {
        "ts": str(event.get("ts") or ""),
        "type": event_type,
        "profile": str(event.get("profile") or "unknown"),
        "fast": bool(event.get("fast")),
    }
    if event_type == "token_usage" and isinstance(event.get("usage"), dict):
        compact["tokens"] = int_value(event["usage"].get("total_tokens"))
    if event_type == "websocket_tunnel":
        compact["bytes"] = int_value(event.get("bytes_up")) + int_value(event.get("bytes_down"))
    if event_type == "http_request":
        compact["status"] = event.get("status")
        compact["path"] = event.get("path")
    if event_type == "quota_update":
        compact["source"] = event.get("source")
        if isinstance(event.get("quota"), dict):
            compact["quota"] = event["quota"]
    if event_type == "reset_credit":
        compact["outcome"] = event.get("outcome")
    return compact


def usage_payload_reset_datetimes(
    payload: Any,
    relative_to: datetime | None = None,
) -> list[datetime]:
    if quota_payload_unlimited(payload):
        return []
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


def usage_entry_datetime(entry: dict[str, Any], key: str) -> datetime | None:
    value = entry.get(key)
    if isinstance(value, datetime):
        return value.astimezone()
    return parse_reset_datetime(value)


def usage_refresh_due_at(
    entry: dict[str, Any] | None,
    now: datetime | None = None,
) -> datetime:
    now = now.astimezone() if now else datetime.now().astimezone()
    if not isinstance(entry, dict):
        return now
    error = entry.get("error")
    if error_requires_billing(error) or entry.get("billing_required"):
        error_at = usage_entry_datetime(entry, "error_at") or usage_entry_datetime(entry, "fetched_at")
        if error_at is not None:
            return error_at + timedelta(seconds=USAGE_AUTO_REFRESH_BILLING_BACKOFF_SECONDS)
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


def quota_window_has_count(window: Any) -> bool:
    return isinstance(window, dict) and isinstance(window.get("remaining"), (int, float))


def quota_bucket_state(rate_limit: dict[str, Any]) -> tuple[str, str]:
    if quota_rate_limit_unlimited(rate_limit):
        return "Unlimited", "unlimited"
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


def quota_unknown_percent_text() -> str:
    return "\u221e?"


def quota_window_label(window: Any, fallback: str) -> str:
    if not isinstance(window, dict):
        return fallback
    label = format_window_seconds(window.get("limit_window_seconds"), fallback)
    return "Weekly" if label == "weekly" else label


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
    unbounded_kind = "unlimited" if quota_rate_limit_unlimited(rate_limit) else ""

    if primary_percent is None and weekly_percent is None and not unbounded_kind:
        count_rows = [
            render_quota_count_window(primary, "5h"),
            render_quota_count_window(secondary, "Weekly"),
        ]
        count_html = "".join(row for row in count_rows if row)
        if count_html:
            return {"count_html": count_html}
        if rate_limit.get("allowed") is True:
            unbounded_kind = "unknown"
        else:
            return {"count_html": '<div class="quota-muted">No window details</div>'}

    if unbounded_kind:
        status = "unlimited" if unbounded_kind == "unlimited" else "unknown"
        text = quota_unknown_percent_text()
        return {
            "special": unbounded_kind,
            "primary_reset_text": f"{primary_label} ({status})",
            "weekly_status": f"{weekly_label} ({status})",
            "primary_style": 100.0,
            "weekly_style": 100.0,
            "primary_text": text,
            "weekly_text": text,
            "primary_empty": "",
            "aria": f"{primary_label} and {weekly_label} quota {status}",
        }

    primary_visual = primary_percent
    if primary_visual is not None and weekly_percent is not None and weekly_percent <= 0:
        primary_visual = 0.0

    primary_reset_text = quota_status_text(primary_label, primary)
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


def render_quota_horizons(context: dict[str, Any], name: str, title: str = "") -> str:
    if context.get("count_html"):
        return f"""
          <div class="quota-title">
            <span class="quota-horizon weekly"></span>
            <span class="quota-bucket-name" title="{html.escape(title)}">{html.escape(name)}</span>
            <span class="quota-horizon primary"></span>
          </div>
        """
    weekly_status = str(context.get("weekly_status") or "")
    primary_status = str(context.get("primary_reset_text") or "")
    return f"""
      <div class="quota-title">
        <span class="quota-horizon weekly">{html.escape(weekly_status)}</span>
        <span class="quota-bucket-name" title="{html.escape(title)}">{html.escape(name)}</span>
        <span class="quota-horizon primary">{html.escape(primary_status)}</span>
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
    special = str(context.get("special") or "")
    stack_class = f" quota-stack-{html.escape(special)}" if special else ""
    weekly_label_html = f'<span class="quota-weekly-label">{html.escape(weekly_text)}</span>'
    primary_label_html = f'<span class="quota-primary-label-outside">{html.escape(primary_text)}</span>'
    bar_attrs = (
        f'role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="{primary_style:.0f}" aria-label="{html.escape(aria)}"'
        if not special
        else f'role="img" aria-label="{html.escape(aria)}"'
    )

    return f"""
      <div class="quota-stack{stack_class}">
        <div class="quota-stack-row">
          {weekly_label_html}
          <div class="quota-stack-bar" {bar_attrs}>
            <span class="quota-weekly-fill" style="width: {weekly_style:.2f}%"></span>
            <span class="quota-primary-fill{primary_empty}" style="width: {primary_style:.2f}%"></span>
          </div>
          {primary_label_html}
        </div>
      </div>
    """


def render_quota_bucket(bucket: dict[str, Any]) -> str:
    name = str(bucket.get("name") or "Quota bucket")
    feature = str(bucket.get("metered_feature") or "")
    rate_limit = bucket.get("rate_limit")
    if not isinstance(rate_limit, dict):
        return ""

    title = f"Metered feature: {feature}" if feature and feature != "codex" else ""
    context = quota_stack_context(rate_limit)
    stack_html = render_quota_stack(context)
    horizons_html = render_quota_horizons(context, name, title)
    return f"""
      <div class="quota-bucket">
        {horizons_html}
        {stack_html}
      </div>
    """


def render_quota_state(state: dict[str, str]) -> str:
    level = state.get("level") if state.get("level") in {"warning", "error", "info"} else "warning"
    title = state.get("title") or "Quota unavailable"
    message = state.get("message") or "Quota is unavailable for this profile."
    return f"""
      <div class="quota-empty quota-state {html.escape(level)}">
        <strong>{html.escape(title)}</strong>
        <span>{html.escape(message)}</span>
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
    credits_html: str = "",
    reset_credits_html: str = "",
    error_html: str = "",
) -> str:
    label = updated_label or "No quota cached"
    return f"""
      <div class="quota-panel">
        <div class="quota-panel-head">
          {render_quota_refresh_control(profile, token)}
          <span class="quota-updated">{html.escape(label)}</span>
          {reset_credits_html}
          {credits_html}
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
            if state := usage_payload_state(error):
                return render_quota_panel(
                    render_quota_state(state),
                    updated_label or "",
                    profile=profile,
                    token=token,
                )
            message = quota_refresh_error_message(error)
            error_class = " billing" if error_requires_billing(error) else ""
            return render_quota_panel(
                f'<div class="quota-empty error{error_class}">{html.escape(message)}</div>',
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
    elif state := usage_payload_state(payload):
        bucket_html = render_quota_state(state)
    else:
        bucket_html = '<div class="quota-muted">Quota payload has no bucket details</div>'
    if error:
        message = quota_refresh_error_message(error)
        error_class = " billing" if error_requires_billing(error) else ""
        error_html = (
            f'<div class="quota-refresh-error{error_class}">Last refresh failed: {html.escape(message)}</div>'
        )
    else:
        error_html = ""
    return render_quota_panel(
        bucket_html,
        updated_label or "",
        profile=profile,
        token=token,
        reset_credits_html=render_reset_credit_control(payload, profile, token),
        credits_html=render_quota_credits_pill(payload),
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


def parse_iso_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).astimezone()
    except (OSError, OverflowError, ValueError):
        return None


def auth_health_time_label(value: Any) -> str:
    parsed = parse_iso_datetime(value)
    return format_status_updated_at(parsed) if parsed is not None else ""


def render_auth_health_html(health: Any) -> str:
    if not isinstance(health, dict):
        return ""
    status = str(health.get("status") or "")
    if status not in {"login_required", "refresh_failed"}:
        return ""
    message = str(health.get("message") or "")
    timestamp = auth_health_time_label(health.get("error_at") or health.get("last_refresh_failed_at"))
    suffix = f" ({timestamp})" if timestamp else ""
    label = "Login required" if status == "login_required" else "Auth refresh failed"
    return f"""
      <div class="auth-health {html.escape(status)}" title="{html.escape(message)}">
        <strong>{html.escape(label)}</strong>{html.escape(suffix)}
      </div>
    """


def render_login_status_html(status: Any, profile: str | None = None, token: str | None = None) -> str:
    if not isinstance(status, dict):
        return ""
    state = str(status.get("status") or "").lower()
    if not state:
        return ""
    mode = str(status.get("mode") or "browser")
    state_class = state if state in {"complete", "error", "canceled"} else "running"
    title = {
        "running": "Login running",
        "canceling": "Canceling login",
        "canceled": "Login canceled",
        "complete": "Login captured",
        "error": "Login failed",
    }.get(state, "Login")
    mode_label = "device" if mode == "device" else "browser"
    auth_url = str(status.get("auth_url") or "")
    auth_link = ""
    if auth_url.startswith(("http://", "https://")):
        escaped_url = html.escape(auth_url, quote=True)
        auth_link = (
            f'<a class="login-link" href="{escaped_url}" target="_blank" '
            'rel="noopener noreferrer">Open login</a>'
        )
    user_code = str(status.get("user_code") or "")
    code_html = (
        f'<span class="login-code">Code <code>{html.escape(user_code)}</code></span>'
        if user_code
        else ""
    )
    cancel_html = ""
    if state in LOGIN_ACTIVE_STATUSES and profile and token:
        escaped_profile = html.escape(profile)
        cancel_html = f"""
          <form method="post" action="/api/login" class="login-cancel-form" data-action="cancel_login" data-profile="{escaped_profile}">
            <input type="hidden" name="token" value="{html.escape(token)}">
            <input type="hidden" name="profile" value="{escaped_profile}">
            <input type="hidden" name="login_action" value="cancel_login">
            <button class="login-cancel-action">Cancel Login</button>
          </form>
        """
    detail = str(status.get("message") or status.get("error") or "")
    if not detail and state == "running" and mode == "browser":
        detail = LOGIN_BROWSER_REMOTE_NOTE
    if not detail and state == "canceled":
        detail = "Login canceled."
    if not detail:
        lines = status.get("lines")
        if isinstance(lines, list) and lines:
            detail = str(lines[-1])
    detail_html = (
        f'<div class="login-detail">{html.escape(detail)}</div>'
        if detail
        else ""
    )
    return f"""
      <div class="login-status {state_class}">
        <div class="login-status-top"><strong>{html.escape(title)}</strong><span>{html.escape(mode_label)}</span></div>
        <div class="login-status-actions">{auth_link}{code_html}{cancel_html}</div>
        {detail_html}
      </div>
    """


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
        self.profile_settings: dict[str, dict[str, Any]] = self.load_profile_settings()
        self.profile_settings_lock = threading.Lock()
        self.pinned_sessions: dict[str, str] = self.load_pinned_sessions()
        self.usage_cache: dict[str, dict[str, Any]] = {}
        self.usage_cache_lock = threading.Lock()
        self.usage_refresh_lock = threading.Lock()
        self.last_usage_refresh_monotonic = 0.0
        self.usage_auto_refresh_stop = threading.Event()
        self.usage_auto_refresh_thread: threading.Thread | None = None
        self.login_jobs: dict[str, dict[str, Any]] = {}
        self.login_processes: dict[str, subprocess.Popen[str]] = {}
        self.login_jobs_lock = threading.Lock()
        self.app_server_rate_limit_cache: dict[str, dict[str, Any]] = {}
        self.app_server_rate_limit_lock = threading.Lock()
        self.stats_lock = threading.Lock()

    def log_message(self, format: str, *args: Any) -> None:
        message = format % args
        message = redact_proxy_token(message, self.proxy_token)
        sys.stderr.write(
            "%s %s\n"
            % (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                message,
            )
        )

    def load_profile_settings(self) -> dict[str, dict[str, Any]]:
        try:
            with self.paths.profile_settings.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(payload, dict):
            return {}
        settings: dict[str, dict[str, Any]] = {}
        for raw_profile, raw_settings in payload.items():
            if not isinstance(raw_profile, str) or not isinstance(raw_settings, dict):
                continue
            if self.store.profile_exists(raw_profile):
                profile_settings: dict[str, Any] = {
                    "fast_mode": bool(raw_settings.get("fast_mode")),
                }
                model = sanitize_model_id(raw_settings.get("model"))
                if model:
                    profile_settings["model"] = model
                    reasoning = sanitize_reasoning_effort(
                        raw_settings.get("reasoning_effort"),
                        model,
                    )
                    if reasoning:
                        profile_settings["reasoning_effort"] = reasoning
                if raw_settings.get("login_required"):
                    profile_settings["login_required"] = True
                    if isinstance(raw_settings.get("login_error"), str):
                        profile_settings["login_error"] = raw_settings["login_error"]
                    if isinstance(raw_settings.get("login_error_at"), str):
                        profile_settings["login_error_at"] = raw_settings["login_error_at"]
                if raw_settings.get("billing_required"):
                    profile_settings["billing_required"] = True
                    if isinstance(raw_settings.get("billing_error"), str):
                        profile_settings["billing_error"] = raw_settings["billing_error"]
                    if isinstance(raw_settings.get("billing_error_at"), str):
                        profile_settings["billing_error_at"] = raw_settings["billing_error_at"]
                settings[raw_profile] = profile_settings
        return settings

    def save_profile_settings_locked(self) -> None:
        try:
            self.paths.profile_settings.parent.mkdir(parents=True, exist_ok=True)
            temp = self.paths.profile_settings.with_suffix(
                self.paths.profile_settings.suffix + ".tmp"
            )
            encoded = json.dumps(self.profile_settings, indent=2, sort_keys=True) + "\n"
            with temp.open("w", encoding="utf-8") as handle:
                handle.write(encoded)
            temp.chmod(0o600)
            temp.replace(self.paths.profile_settings)
            self.paths.profile_settings.chmod(0o600)
        except OSError as exc:
            raise StoreError(f"failed to save profile settings: {exc}") from exc

    def profile_fast_mode(self, profile: str) -> bool:
        lock = getattr(self, "profile_settings_lock", None)
        if lock is None:
            return False
        with lock:
            return bool(self.profile_settings.get(profile, {}).get("fast_mode"))

    def profile_model_setting(self, profile: str) -> dict[str, Any]:
        stock_model, stock_reasoning = read_stock_codex_model_setting()
        with self.profile_settings_lock:
            settings = dict(self.profile_settings.get(profile, {}))
        model = sanitize_model_id(settings.get("model")) or stock_model
        reasoning = sanitize_reasoning_effort(settings.get("reasoning_effort"), model)
        reasoning = reasoning or stock_reasoning or default_reasoning_for_model(model)
        entry = model_catalog_entry(model) or {}
        return {
            "model": model,
            "reasoning_effort": reasoning,
            "label": model_setting_label(model, reasoning),
            "display": model_display_name(model),
            "source": "profile" if settings.get("model") else "codex-default",
            "note": entry.get("note") if isinstance(entry.get("note"), str) else "",
        }

    def profile_model_label(self, profile: str) -> str:
        setting = self.profile_model_setting(profile)
        return str(setting.get("label") or "")

    def set_profile_model(
        self,
        profile: str,
        *,
        model: str,
        reasoning_effort: str | None,
    ) -> None:
        if not self.store.profile_exists(profile):
            raise StoreError(f"unknown profile: {profile}")
        model = sanitize_model_id(model) or ""
        if not model:
            raise StoreError("invalid model")
        reasoning = sanitize_reasoning_effort(reasoning_effort, model)
        reasoning = reasoning or default_reasoning_for_model(model)
        with self.profile_settings_lock:
            settings = self.profile_settings.setdefault(profile, {})
            settings["model"] = model
            settings["reasoning_effort"] = reasoning
            self.save_profile_settings_locked()
        self.append_stats_event(
            {
                "type": "profile_setting",
                "profile": profile,
                "setting": "model",
                "model": model,
                "reasoning_effort": reasoning,
            }
        )

    def mark_profile_login_required(self, profile: str, error: BaseException | str) -> None:
        store = getattr(self, "store", None)
        lock = getattr(self, "profile_settings_lock", None)
        if store is None or lock is None or not store.profile_exists(profile):
            return
        message = login_required_message(error)
        with lock:
            settings = self.profile_settings.setdefault(profile, {})
            settings["login_required"] = True
            settings["login_error"] = message[:500]
            settings["login_error_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            self.save_profile_settings_locked()

    def clear_profile_login_required(self, profile: str) -> None:
        store = getattr(self, "store", None)
        lock = getattr(self, "profile_settings_lock", None)
        if store is None or lock is None or not store.profile_exists(profile):
            return
        with lock:
            settings = self.profile_settings.setdefault(profile, {})
            changed = bool(settings.pop("login_required", None))
            changed = bool(settings.pop("login_error", None)) or changed
            changed = bool(settings.pop("login_error_at", None)) or changed
            if changed:
                self.save_profile_settings_locked()

    def profile_login_required(self, profile: str) -> dict[str, Any]:
        lock = getattr(self, "profile_settings_lock", None)
        if lock is None:
            return {"required": False, "error": "", "error_at": ""}
        with lock:
            settings = dict(self.profile_settings.get(profile, {}))
        return {
            "required": bool(settings.get("login_required")),
            "error": str(settings.get("login_error") or ""),
            "error_at": str(settings.get("login_error_at") or ""),
        }

    def profile_auth_health(self, profile: str) -> dict[str, Any]:
        login_required = self.profile_login_required(profile)
        auth: dict[str, Any] = {}
        try:
            with self.store.auth_path(profile).open("r", encoding="utf-8") as handle:
                value = json.load(handle)
            if isinstance(value, dict):
                auth = value
        except (OSError, json.JSONDecodeError):
            auth = {}
        failed_at = str(auth.get("last_refresh_failed_at") or "")
        refresh_error = str(auth.get("last_refresh_error") or "")
        last_refresh = str(auth.get("last_refresh") or "")
        if login_required.get("required"):
            return {
                "status": "login_required",
                "message": login_required.get("error") or login_required_message(),
                "error_at": login_required.get("error_at") or failed_at,
                "last_refresh": last_refresh,
                "last_refresh_failed_at": failed_at,
            }
        if refresh_error or failed_at:
            return {
                "status": "refresh_failed",
                "message": quota_refresh_error_message(refresh_error or "token refresh failed"),
                "error_at": failed_at,
                "last_refresh": last_refresh,
                "last_refresh_failed_at": failed_at,
            }
        if last_refresh:
            return {
                "status": "ok",
                "message": "Auth refresh succeeded.",
                "last_refresh": last_refresh,
                "last_refresh_failed_at": "",
            }
        return {
            "status": "unknown",
            "message": "",
            "last_refresh": "",
            "last_refresh_failed_at": "",
        }

    def mark_profile_billing_required(self, profile: str, error: BaseException | str) -> None:
        store = getattr(self, "store", None)
        lock = getattr(self, "profile_settings_lock", None)
        if store is None or lock is None or not store.profile_exists(profile):
            return
        message = str(error)
        with lock:
            settings = self.profile_settings.setdefault(profile, {})
            settings["billing_required"] = True
            settings["billing_error"] = message[:500]
            settings["billing_error_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            self.save_profile_settings_locked()

    def clear_profile_billing_required(self, profile: str) -> None:
        store = getattr(self, "store", None)
        lock = getattr(self, "profile_settings_lock", None)
        if store is None or lock is None or not store.profile_exists(profile):
            return
        with lock:
            settings = self.profile_settings.setdefault(profile, {})
            changed = bool(settings.pop("billing_required", None))
            changed = bool(settings.pop("billing_error", None)) or changed
            changed = bool(settings.pop("billing_error_at", None)) or changed
            if changed:
                self.save_profile_settings_locked()

    def profile_billing_required(self, profile: str) -> dict[str, Any]:
        lock = getattr(self, "profile_settings_lock", None)
        if lock is None:
            return {"required": False, "error": "", "error_at": ""}
        with lock:
            settings = dict(self.profile_settings.get(profile, {}))
        return {
            "required": bool(settings.get("billing_required")),
            "error": str(settings.get("billing_error") or ""),
            "error_at": str(settings.get("billing_error_at") or ""),
        }

    def profile_switch_unavailable_reason(self, profile: str) -> str:
        billing = self.profile_billing_required(profile)
        if billing.get("required"):
            if state := usage_payload_state(billing.get("error")):
                return state["title"]
            return "Billing required"
        return ""

    def set_profile_fast_mode(self, profile: str, enabled: bool) -> None:
        if not self.store.profile_exists(profile):
            raise StoreError(f"unknown profile: {profile}")
        with self.profile_settings_lock:
            settings = self.profile_settings.setdefault(profile, {})
            settings["fast_mode"] = bool(enabled)
            self.save_profile_settings_locked()
        self.append_stats_event(
            {
                "type": "profile_setting",
                "profile": profile,
                "setting": "fast_mode",
                "enabled": bool(enabled),
            }
        )

    def toggle_profile_fast_mode(self, profile: str) -> bool:
        enabled = not self.profile_fast_mode(profile)
        self.set_profile_fast_mode(profile, enabled)
        return enabled

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
                "bytes_up": 0,
                "bytes_down": 0,
                "messages_up": 0,
                "messages_down": 0,
                "service_tier": None,
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

    def note_websocket_traffic(
        self,
        tunnel_id: int,
        *,
        bytes_count: int,
        message_count: int,
        from_downstream: bool,
        service_tier: str | None = None,
    ) -> None:
        with self.active_lock:
            tunnel = self.active_websockets.get(tunnel_id)
            if tunnel is None:
                return
            byte_key = "bytes_up" if from_downstream else "bytes_down"
            message_key = "messages_up" if from_downstream else "messages_down"
            tunnel[byte_key] = int(tunnel.get(byte_key) or 0) + max(0, bytes_count)
            tunnel[message_key] = int(tunnel.get(message_key) or 0) + max(0, message_count)
            if service_tier:
                tunnel["service_tier"] = service_tier

    def websocket_service_tier(self, tunnel_id: int) -> str | None:
        with self.active_lock:
            service_tier = self.active_websockets.get(tunnel_id, {}).get("service_tier")
        return service_tier if isinstance(service_tier, str) else None

    def websocket_session_key(self, tunnel_id: int) -> str | None:
        with self.active_lock:
            session_key = self.active_websockets.get(tunnel_id, {}).get("session_key")
        return session_key if isinstance(session_key, str) else None

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
            if auth_error_requires_login(exc):
                self.mark_profile_login_required(profile, exc)
            if error_requires_billing(exc):
                self.mark_profile_billing_required(profile, exc)
            error_at = datetime.now().astimezone()
            with self.usage_cache_lock:
                entry = self.usage_cache.setdefault(profile, {})
                entry["error"] = str(exc)
                entry["error_at"] = error_at
                entry["billing_required"] = error_requires_billing(exc)
                entry["event"] = None
                stale_payload = entry.get("payload")
                stale_fetched_at = entry.get("fetched_at")
                fetch_event.set()
            if isinstance(stale_payload, dict):
                return stale_payload, stale_fetched_at, "stale"
            raise

        with self.usage_cache_lock:
            entry = self.usage_cache.setdefault(profile, {})
            previous_payload = entry.get("payload")
            entry["payload"] = payload
            entry["fetched_at"] = fetched_at
            entry["fetched_monotonic"] = time.monotonic()
            entry["error"] = None
            entry.pop("error_at", None)
            entry.pop("billing_required", None)
            entry["event"] = None
            fetch_event.set()
        self.clear_profile_login_required(profile)
        self.clear_profile_billing_required(profile)
        self.append_stats_event(
            {
                "type": "quota_update",
                "profile": profile,
                "source": "usage_fetch",
                "fast": self.profile_fast_mode(profile),
                "quota": quota_remaining_delta(previous_payload, payload),
            }
        )
        self.schedule_app_server_rate_limit_refresh(profile)
        return payload, fetched_at, "fresh"

    def update_usage_cache_from_observation(
        self,
        profile: str,
        payload_update: dict[str, Any] | None,
        *,
        source: str,
        service_tier: str | None = None,
    ) -> bool:
        if not profile or not isinstance(payload_update, dict):
            return False
        fetched_at = datetime.now().astimezone()
        with self.usage_cache_lock:
            entry = self.usage_cache.setdefault(profile, {})
            previous_payload = entry.get("payload")
            entry["payload"] = merge_usage_payload(entry.get("payload"), payload_update)
            entry["fetched_at"] = fetched_at
            entry["fetched_monotonic"] = time.monotonic()
            entry["error"] = None
            entry.pop("error_at", None)
            entry.pop("billing_required", None)
            entry["source"] = source
            current_payload = entry.get("payload")
        self.clear_profile_login_required(profile)
        self.clear_profile_billing_required(profile)
        if isinstance(current_payload, dict):
            self.append_stats_event(
                {
                    "type": "quota_update",
                    "profile": profile,
                    "source": source,
                    "service_tier": service_tier,
                    "fast": service_tier in FAST_SERVICE_TIER_VALUES or self.profile_fast_mode(profile),
                    "quota": quota_remaining_delta(previous_payload, current_payload),
                }
            )
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
        *,
        service_tier: str | None = None,
    ) -> bool:
        return self.update_usage_cache_from_observation(
            profile,
            usage_payload_from_websocket_message(opcode, payload),
            source="websocket_event",
            service_tier=service_tier,
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

    def run_app_server_for_profile(self, profile: str, callback: Callable[[CodexAppServerClient], Any]) -> Any:
        if not self.store.profile_exists(profile):
            raise StoreError(f"unknown profile: {profile}")
        auth_source = self.store.auth_path(profile)
        with tempfile.TemporaryDirectory(prefix=f"provision-app-server-{profile}-") as temp:
            codex_home = Path(temp)
            auth_target = codex_home / "auth.json"
            shutil.copy2(auth_source, auth_target)
            auth_target.chmod(0o600)
            config = codex_home / "config.toml"
            config.write_text('cli_auth_credentials_store = "file"\n', encoding="utf-8")
            config.chmod(0o600)
            env = os.environ.copy()
            env["CODEX_HOME"] = str(codex_home)
            with CodexAppServerClient(env=env) as client:
                result = callback(client)
            if auth_target.exists():
                self.store.import_auth_file(profile, auth_target, overwrite=True, set_active=False)
            return result

    def consume_profile_rate_limit_reset_credit(
        self,
        profile: str,
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        key = idempotency_key or str(uuid.uuid4())

        def consume(client: CodexAppServerClient) -> dict[str, Any]:
            return {
                "consume": client.consume_account_rate_limit_reset_credit(key),
                "rate_limits": client.read_account_rate_limits(),
            }

        result = self.run_app_server_for_profile(profile, consume)
        consume_result = result.get("consume") if isinstance(result, dict) else {}
        rate_limits = result.get("rate_limits") if isinstance(result, dict) else {}
        outcome = str(consume_result.get("outcome") or "unknown") if isinstance(consume_result, dict) else "unknown"
        payload = usage_payload_from_app_server_rate_limits_response(rate_limits)
        if payload:
            self.update_usage_cache_from_observation(profile, payload, source="app_server_rate_limits")
        event = {
            "type": "reset_credit",
            "profile": profile,
            "outcome": outcome,
            "idempotency_key": key,
        }
        self.append_reset_credit_event(event)
        self.append_stats_event(event)
        return {
            "outcome": outcome,
            "idempotency_key": key,
            "payload": payload,
        }

    def cached_app_server_rate_limit_payload(self, profile: str) -> dict[str, Any] | None:
        with self.app_server_rate_limit_lock:
            entry = self.app_server_rate_limit_cache.get(profile)
            if not isinstance(entry, dict):
                return None
            payload = entry.get("payload")
            fetched = entry.get("fetched_monotonic")
            if (
                isinstance(payload, dict)
                and isinstance(fetched, (int, float))
                and time.monotonic() - float(fetched) <= APP_SERVER_RATE_LIMIT_CACHE_SECONDS
            ):
                return dict(payload)
        return None

    def app_server_rate_limit_refresh_due_locked(self, profile: str) -> bool:
        entry = self.app_server_rate_limit_cache.setdefault(profile, {})
        if entry.get("in_flight"):
            return False
        now = time.monotonic()
        fetched = entry.get("fetched_monotonic")
        if isinstance(fetched, (int, float)) and now - float(fetched) < APP_SERVER_RATE_LIMIT_CACHE_SECONDS:
            return False
        checked = entry.get("checked_monotonic")
        if isinstance(checked, (int, float)) and now - float(checked) < APP_SERVER_RATE_LIMIT_CACHE_SECONDS:
            return False
        failed = entry.get("failed_monotonic")
        if isinstance(failed, (int, float)) and now - float(failed) < APP_SERVER_RATE_LIMIT_FAILURE_BACKOFF_SECONDS:
            return False
        return True

    def schedule_app_server_rate_limit_refresh(self, profile: str) -> bool:
        store = getattr(self, "store", None)
        if not profile or store is None or not store.profile_exists(profile):
            return False
        with self.app_server_rate_limit_lock:
            if not self.app_server_rate_limit_refresh_due_locked(profile):
                return False
            self.app_server_rate_limit_cache.setdefault(profile, {})["in_flight"] = True
        threading.Thread(
            target=self.refresh_app_server_rate_limit_payload,
            args=(profile,),
            name=f"provision-app-server-rate-limits-{profile}",
            daemon=True,
        ).start()
        return True

    def refresh_app_server_rate_limit_payload(self, profile: str) -> dict[str, Any] | None:
        try:
            payload = self.read_app_server_rate_limit_payload_for_profile(profile)
        except Exception as exc:
            with self.app_server_rate_limit_lock:
                entry = self.app_server_rate_limit_cache.setdefault(profile, {})
                entry["in_flight"] = False
                entry["failed_monotonic"] = time.monotonic()
                entry["error"] = str(exc)
            self.log_message("app-server rate-limit read for profile %s failed: %s", profile, exc)
            return None
        with self.app_server_rate_limit_lock:
            entry = self.app_server_rate_limit_cache.setdefault(profile, {})
            entry["in_flight"] = False
            entry["checked_monotonic"] = time.monotonic()
            entry.pop("failed_monotonic", None)
            entry.pop("error", None)
            if isinstance(payload, dict):
                entry["payload"] = dict(payload)
                entry["fetched_monotonic"] = entry["checked_monotonic"]
                entry["fetched_at"] = datetime.now().astimezone()
        if isinstance(payload, dict):
            self.update_usage_cache_from_observation(profile, payload, source="app_server_rate_limits")
            return payload
        return None

    def read_app_server_rate_limit_payload_for_profile(self, profile: str) -> dict[str, Any] | None:
        probe = codex_app_server_schema_probe()
        methods = probe.get("methods") if isinstance(probe.get("methods"), dict) else {}
        if not methods.get("account_rate_limits"):
            return None

        def read_rate_limits(client: CodexAppServerClient) -> dict[str, Any] | None:
            return usage_payload_from_app_server_rate_limits_response(client.read_account_rate_limits())

        return self.run_app_server_for_profile(profile, read_rate_limits)

    def app_server_rate_limit_payload_for_profile(self, profile: str) -> dict[str, Any] | None:
        return self.cached_app_server_rate_limit_payload(profile)

    def append_reset_credit_event(self, event: dict[str, Any]) -> None:
        lock = getattr(self, "stats_lock", None)
        paths = getattr(self, "paths", None)
        if lock is None or paths is None:
            return
        payload = dict(event)
        payload["ts"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        try:
            encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n"
        except (TypeError, ValueError):
            return
        with lock:
            try:
                paths.reset_credit_events.parent.mkdir(parents=True, exist_ok=True)
                with paths.reset_credit_events.open("a", encoding="utf-8") as handle:
                    handle.write(encoded)
                paths.reset_credit_events.chmod(0o600)
            except OSError:
                return

    def append_stats_event(self, event: dict[str, Any]) -> None:
        lock = getattr(self, "stats_lock", None)
        paths = getattr(self, "paths", None)
        if lock is None or paths is None:
            return
        payload = dict(event)
        payload["ts"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        try:
            encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n"
        except (TypeError, ValueError):
            return
        with lock:
            try:
                paths.stats.parent.mkdir(parents=True, exist_ok=True)
                with paths.stats.open("a", encoding="utf-8") as handle:
                    handle.write(encoded)
                paths.stats.chmod(0o600)
            except OSError:
                return

    def record_http_stats(
        self,
        *,
        profile: str,
        route: str,
        path: str,
        method: str,
        status_code: int | None,
        duration_seconds: float,
        bytes_in: int,
        bytes_out: int,
        service_tier: str | None,
    ) -> None:
        self.append_stats_event(
            {
                "type": "http_request",
                "profile": profile,
                "route": route,
                "path": path,
                "method": method,
                "status": status_code,
                "duration_seconds": round(duration_seconds, 3),
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "service_tier": service_tier,
                "fast": service_tier in FAST_SERVICE_TIER_VALUES or self.profile_fast_mode(profile),
            }
        )

    def record_websocket_stats(self, tunnel_id: int) -> None:
        lock = getattr(self, "active_lock", None)
        if lock is None:
            return
        with lock:
            tunnel = dict(self.active_websockets.get(tunnel_id) or {})
        if not tunnel:
            return
        started = tunnel.get("started_monotonic")
        duration = (
            max(0.0, time.monotonic() - float(started))
            if isinstance(started, (int, float))
            else 0.0
        )
        service_tier = tunnel.get("service_tier")
        profile = str(tunnel.get("profile") or "unknown")
        self.append_stats_event(
            {
                "type": "websocket_tunnel",
                "profile": profile,
                "session_key": tunnel.get("session_key"),
                "duration_seconds": round(duration, 3),
                "bytes_up": int(tunnel.get("bytes_up") or 0),
                "bytes_down": int(tunnel.get("bytes_down") or 0),
                "messages_up": int(tunnel.get("messages_up") or 0),
                "messages_down": int(tunnel.get("messages_down") or 0),
                "service_tier": service_tier if isinstance(service_tier, str) else None,
                "fast": service_tier in FAST_SERVICE_TIER_VALUES or self.profile_fast_mode(profile),
            }
        )

    def record_token_usage(
        self,
        *,
        profile: str,
        tunnel_id: int,
        usage: dict[str, int],
    ) -> None:
        service_tier = self.websocket_service_tier(tunnel_id)
        self.append_stats_event(
            {
                "type": "token_usage",
                "profile": profile,
                "session_key": self.websocket_session_key(tunnel_id),
                "service_tier": service_tier,
                "fast": service_tier in FAST_SERVICE_TIER_VALUES or self.profile_fast_mode(profile),
                "usage": usage,
            }
        )

    def stats_events(self, max_events: int = STATS_MAX_EVENTS) -> list[dict[str, Any]]:
        paths = getattr(self, "paths", None)
        if paths is None:
            return []
        try:
            lines = paths.stats.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        events = []
        for line in lines[-max_events:]:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                events.append(event)
        return events

    def stats_summary(self) -> dict[str, Any]:
        events = self.stats_events()
        profiles = {
            name: {
                "profile": name,
                "requests": 0,
                "tunnels": 0,
                "active_tunnels": 0,
                "bytes_up": 0,
                "bytes_down": 0,
                "input_tokens": 0,
                "cached_input_tokens": 0,
                "output_tokens": 0,
                "reasoning_output_tokens": 0,
                "total_tokens": 0,
                "fast_turns": 0,
                "fast_tokens": 0,
                "quota_updates": 0,
                "last_event_at": "",
                "last_quota": {},
            }
            for name in self.store.profile_names()
        }
        recent: list[dict[str, Any]] = []
        series: list[dict[str, Any]] = []
        for event in events:
            profile = str(event.get("profile") or "unknown")
            row = profiles.setdefault(
                profile,
                {
                    "profile": profile,
                    "requests": 0,
                    "tunnels": 0,
                    "active_tunnels": 0,
                    "bytes_up": 0,
                    "bytes_down": 0,
                    "input_tokens": 0,
                    "cached_input_tokens": 0,
                    "output_tokens": 0,
                    "reasoning_output_tokens": 0,
                    "total_tokens": 0,
                    "fast_turns": 0,
                    "fast_tokens": 0,
                    "quota_updates": 0,
                    "last_event_at": "",
                    "last_quota": {},
                },
            )
            row["last_event_at"] = str(event.get("ts") or row["last_event_at"])
            event_type = event.get("type")
            if event_type == "http_request":
                row["requests"] += 1
                row["bytes_up"] += int_value(event.get("bytes_in"))
                row["bytes_down"] += int_value(event.get("bytes_out"))
            elif event_type == "websocket_tunnel":
                row["tunnels"] += 1
                row["bytes_up"] += int_value(event.get("bytes_up"))
                row["bytes_down"] += int_value(event.get("bytes_down"))
            elif event_type == "token_usage":
                usage = event.get("usage")
                if isinstance(usage, dict):
                    row["input_tokens"] += int_value(usage.get("input_tokens"))
                    row["cached_input_tokens"] += int_value(usage.get("cached_input_tokens"))
                    row["output_tokens"] += int_value(usage.get("output_tokens"))
                    row["reasoning_output_tokens"] += int_value(
                        usage.get("reasoning_output_tokens")
                    )
                    total = int_value(usage.get("total_tokens"))
                    row["total_tokens"] += total
                    if event.get("fast"):
                        row["fast_turns"] += 1
                        row["fast_tokens"] += total
            elif event_type == "quota_update":
                row["quota_updates"] += 1
                row["last_quota"] = event.get("quota") if isinstance(event.get("quota"), dict) else {}
            if event_type in {"http_request", "websocket_tunnel", "token_usage", "quota_update", "reset_credit"}:
                recent.append(compact_stats_event(event))
                traffic = int(row["bytes_up"]) + int(row["bytes_down"])
                value = int(row["total_tokens"]) or traffic or int(row["requests"]) + int(row["tunnels"]) + int(row["quota_updates"])
                series.append(
                    {
                        "ts": str(event.get("ts") or ""),
                        "profile": profile,
                        "tokens": int(row["total_tokens"]),
                        "traffic": traffic,
                        "requests": int(row["requests"]),
                        "quota_updates": int(row["quota_updates"]),
                        "value": value,
                    }
                )
        active_lock = getattr(self, "active_lock", None)
        if active_lock is not None:
            with active_lock:
                for tunnel in self.active_websockets.values():
                    profile = str(tunnel.get("profile") or "unknown")
                    row = profiles.setdefault(
                        profile,
                        {
                            "profile": profile,
                            "requests": 0,
                            "tunnels": 0,
                            "active_tunnels": 0,
                            "bytes_up": 0,
                            "bytes_down": 0,
                            "input_tokens": 0,
                            "cached_input_tokens": 0,
                            "output_tokens": 0,
                            "reasoning_output_tokens": 0,
                            "total_tokens": 0,
                            "fast_turns": 0,
                            "fast_tokens": 0,
                            "quota_updates": 0,
                            "last_event_at": "",
                            "last_quota": {},
                        },
                    )
                    row["active_tunnels"] += 1
                    row["bytes_up"] += int_value(tunnel.get("bytes_up"))
                    row["bytes_down"] += int_value(tunnel.get("bytes_down"))
        return {
            "profiles": sorted(profiles.values(), key=lambda item: str(item.get("profile") or "")),
            "recent": recent[-20:],
            "series": series[-300:],
        }

    def login_status(self, profile: str) -> dict[str, Any] | None:
        lock = getattr(self, "login_jobs_lock", None)
        if lock is None:
            return None
        with lock:
            job = self.login_jobs.get(profile)
            return dict(job) if isinstance(job, dict) else None

    def login_cancel_requested(self, profile: str) -> bool:
        lock = getattr(self, "login_jobs_lock", None)
        if lock is None:
            return False
        with lock:
            job = self.login_jobs.get(profile)
            return isinstance(job, dict) and bool(job.get("cancel_requested"))

    def start_profile_login(self, profile: str, *, device_auth: bool = False) -> None:
        if not self.store.profile_exists(profile):
            raise StoreError(f"unknown profile: {profile}")
        with self.login_jobs_lock:
            existing = self.login_jobs.get(profile)
            if isinstance(existing, dict) and existing.get("status") in LOGIN_ACTIVE_STATUSES:
                raise StoreError(f"login already running for {profile}")
            capture = self.paths.capture / f"{profile}-ui-{int(time.time())}"
            try:
                capture.mkdir(parents=True, exist_ok=False)
                capture.chmod(0o700)
                config = capture / "config.toml"
                config.write_text('cli_auth_credentials_store = "file"\n', encoding="utf-8")
                config.chmod(0o600)
            except OSError as exc:
                raise StoreError(f"failed to initialize login capture: {exc}") from exc
            self.login_jobs[profile] = {
                "profile": profile,
                "status": "running",
                "mode": "device" if device_auth else "browser",
                "started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "lines": [],
                "auth_url": "",
                "user_code": "",
                "error": "",
                "message": LOGIN_BROWSER_REMOTE_NOTE if not device_auth else "",
                "cancel_requested": False,
            }
        thread = threading.Thread(
            target=self.run_profile_login,
            args=(profile, capture, device_auth),
            name=f"provision-login-{profile}",
            daemon=True,
        )
        thread.start()

    def run_profile_login(self, profile: str, capture: Path, device_auth: bool) -> None:
        env = os.environ.copy()
        env["CODEX_HOME"] = str(capture)
        cmd = ["codex", "login"]
        if device_auth:
            cmd.append("--device-auth")
        try:
            process = subprocess.Popen(
                cmd,
                cwd=str(capture),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            with self.login_jobs_lock:
                self.login_processes[profile] = process
                job = self.login_jobs.get(profile)
                cancel_requested = isinstance(job, dict) and bool(job.get("cancel_requested"))
            if cancel_requested:
                process.terminate()
            assert process.stdout is not None
            for line in process.stdout:
                self.note_login_output(profile, line.rstrip("\n"))
            return_code = process.wait()
            if self.login_cancel_requested(profile):
                self.finish_profile_login(profile, "canceled", "Login canceled.")
                self.append_stats_event(
                    {
                        "type": "profile_login",
                        "profile": profile,
                        "mode": "device" if device_auth else "browser",
                        "status": "canceled",
                    }
                )
                return
            if return_code != 0:
                self.finish_profile_login(
                    profile,
                    "error",
                    f"codex login exited with status {return_code}",
                )
                return
            metadata = self.store.import_auth_file(
                profile,
                capture / "auth.json",
                overwrite=True,
                set_active=False,
            )
            label = metadata.get("email") or metadata.get("account_id") or metadata.get("kind") or profile
            self.finish_profile_login(profile, "complete", f"captured {label}")
            self.clear_profile_login_required(profile)
            self.clear_profile_billing_required(profile)
            self.append_stats_event(
                {
                    "type": "profile_login",
                    "profile": profile,
                    "mode": "device" if device_auth else "browser",
                    "status": "complete",
                }
            )
            with self.usage_cache_lock:
                entry = self.usage_cache.setdefault(profile, {})
                entry.pop("fetched_monotonic", None)
                entry.pop("error", None)
            try:
                self.usage_payload_for_profile(profile, force=True)
            except (
                AuthError,
                urllib.error.URLError,
                TimeoutError,
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ):
                pass
        except Exception as exc:
            if auth_error_requires_login(exc):
                self.mark_profile_login_required(profile, exc)
                self.finish_profile_login(profile, "error", login_required_message(exc))
            else:
                self.finish_profile_login(profile, "error", str(exc))
        finally:
            with self.login_jobs_lock:
                self.login_processes.pop(profile, None)
            self.store.delete_capture(capture)

    def note_login_output(self, profile: str, line: str) -> None:
        line = ANSI_ESCAPE_RE.sub("", line).strip()
        auth_url = ""
        match = LOGIN_URL_RE.search(line)
        if match:
            auth_url = match.group(0).rstrip(".,)")
        user_code = ""
        match = DEVICE_CODE_RE.search(line)
        if match:
            user_code = match.group(0)
        with self.login_jobs_lock:
            job = self.login_jobs.get(profile)
            if not isinstance(job, dict):
                return
            lines = list(job.get("lines") or [])
            if line:
                lines.append(line)
            job["lines"] = lines[-12:]
            if auth_url:
                job["auth_url"] = auth_url
            if user_code:
                job["user_code"] = user_code

    def finish_profile_login(self, profile: str, status: str, message: str) -> None:
        with self.login_jobs_lock:
            job = self.login_jobs.setdefault(profile, {"profile": profile})
            job["status"] = status
            job["finished_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            job.pop("cancel_requested", None)
            if status == "error":
                job["error"] = message
            else:
                job["message"] = message

    def cancel_profile_login(self, profile: str) -> None:
        if not self.store.profile_exists(profile):
            raise StoreError(f"unknown profile: {profile}")
        process: subprocess.Popen[str] | None = None
        with self.login_jobs_lock:
            job = self.login_jobs.get(profile)
            if not isinstance(job, dict) or job.get("status") not in LOGIN_ACTIVE_STATUSES:
                raise StoreError(f"no login is running for {profile}")
            job["status"] = "canceling"
            job["cancel_requested"] = True
            job["message"] = "Cancel requested."
            process = self.login_processes.get(profile)
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass

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
            if exc.code == 402:
                detail = exc.read()
                message = http_error_detail_message(exc, detail)
                error = BillingRequiredError(message)
                self.mark_profile_billing_required(profile, error)
                raise error from exc
            if retry_on_401 and exc.code == 401 and self.is_chatgpt_profile(auth_path):
                try:
                    force_refresh_chatgpt_auth(auth_path)
                except AuthError as refresh_exc:
                    if auth_error_requires_login(refresh_exc):
                        self.mark_profile_login_required(profile, refresh_exc)
                    raise
                return self.fetch_usage_payload_uncached(profile, retry_on_401=False)
            if exc.code == 401:
                detail = exc.read()
                message = detail.decode("utf-8", errors="replace") if detail else str(exc)
                self.mark_profile_login_required(profile, message)
            raise
        if isinstance(payload, dict):
            app_server_payload = self.cached_app_server_rate_limit_payload(profile)
            if app_server_payload:
                payload = merge_usage_payload(payload, app_server_payload)
        self.clear_profile_login_required(profile)
        self.clear_profile_billing_required(profile)
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
        available_profiles: list[str] = []
        for profile in due_profiles:
            billing = self.profile_billing_required(profile)
            if billing.get("required"):
                billing_error_at = parse_reset_datetime(billing.get("error_at"))
                if (
                    billing_error_at is not None
                    and billing_error_at + timedelta(seconds=USAGE_AUTO_REFRESH_BILLING_BACKOFF_SECONDS) > now
                ):
                    continue
            available_profiles.append(profile)
        return available_profiles

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
            except Exception as exc:
                self.log_message("usage auto-refresh for profile %s failed: %s", profile, exc)

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
        self.server.log_message(format, *args)

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
        if parsed.path == "/api/consume-reset-credit":
            self.handle_consume_reset_credit()
            return
        if parsed.path == "/api/toggle-fast":
            self.handle_toggle_fast()
            return
        if parsed.path == "/api/model":
            self.handle_set_model()
            return
        if parsed.path == "/api/login":
            self.handle_profile_login()
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
        profile_reason = self.server.profile_switch_unavailable_reason(str(profile or ""))
        if profile_reason:
            self.send_json({"error": f"profile unavailable: {profile_reason}"}, status=409)
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

    def handle_consume_reset_credit(self) -> None:
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
            self.server.consume_profile_rate_limit_reset_credit(profile)
        except (StoreError, CodexAppServerError, AuthError, OSError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        self.redirect_ui()

    def handle_toggle_fast(self) -> None:
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
        try:
            self.server.toggle_profile_fast_mode(profile)
        except StoreError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        self.redirect_ui()

    def handle_set_model(self) -> None:
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
        try:
            self.server.set_profile_model(
                profile,
                model=str(data.get("model") or ""),
                reasoning_effort=str(data.get("reasoning_effort") or ""),
            )
        except StoreError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        self.redirect_ui()

    def handle_profile_login(self) -> None:
        try:
            data = self.read_post_fields()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        profile = str(data.get("profile") or "")
        token = data.get("token")
        mode = str(data.get("mode") or "browser")
        login_action = str(data.get("login_action") or "start_login")
        if token != self.server.proxy_token:
            self.send_json({"error": "invalid UI token"}, status=401)
            return
        try:
            if login_action == "cancel_login":
                self.server.cancel_profile_login(profile)
            else:
                self.server.start_profile_login(profile, device_auth=mode == "device")
        except StoreError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
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
            profile_reason = self.server.profile_switch_unavailable_reason(profile)
            if profile_reason:
                self.send_ui_state(message=f"profile unavailable: {profile_reason}")
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
        if action == "consume_reset_credit":
            if not self.server.store.profile_exists(profile):
                self.send_ui_state(message=f"unknown profile: {profile}")
                return
            self.send_ui_state(
                pending_action="consume_reset_credit",
                pending_profile=profile,
            )
            try:
                result = self.server.consume_profile_rate_limit_reset_credit(profile)
            except (StoreError, CodexAppServerError, AuthError, OSError, json.JSONDecodeError) as exc:
                self.log_message("reset credit redemption for profile %s failed: %s", profile, exc)
                self.send_ui_state(message=f"Reset credit failed for {profile}: {exc}")
                return
            outcome = str(result.get("outcome") or "unknown")
            message = "" if outcome == "reset" else f"Reset credit result for {profile}: {outcome}"
            self.send_ui_state(message=message or None)
            return
        if action == "toggle_fast":
            try:
                self.server.toggle_profile_fast_mode(profile)
            except StoreError as exc:
                self.send_ui_state(message=str(exc))
                return
            self.send_ui_state()
            return
        if action == "set_model":
            try:
                self.server.set_profile_model(
                    profile,
                    model=str(message.get("model") or ""),
                    reasoning_effort=str(message.get("reasoning_effort") or ""),
                )
            except StoreError as exc:
                self.send_ui_state(message=str(exc))
                return
            self.send_ui_state()
            return
        if action == "start_login":
            mode = str(message.get("mode") or "browser")
            try:
                self.server.start_profile_login(profile, device_auth=mode == "device")
            except StoreError as exc:
                self.send_ui_state(message=str(exc))
                return
            self.send_ui_state()
            return
        if action == "cancel_login":
            try:
                self.server.cancel_profile_login(profile)
            except StoreError as exc:
                self.send_ui_state(message=str(exc))
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
        service_tier = None
        model_setting = self.server.profile_model_setting(profile)
        model = str(model_setting.get("model") or "")
        reasoning_effort = str(model_setting.get("reasoning_effort") or "")
        if route == UpstreamRoute.CODEX_API and parsed.path in ("/v1/responses", "/v1/responses/compact"):
            body, service_tier, changed = rewrite_service_tier_body(
                body,
                fast_enabled=self.server.profile_fast_mode(profile),
            )
            if changed:
                self.log_message(
                    "service tier override applied for profile %s: %s",
                    profile,
                    service_tier or "standard",
                )
            body, model, reasoning_effort, model_changed = rewrite_model_body(
                body,
                model=model,
                reasoning_effort=reasoning_effort,
            )
            if model_changed:
                self.log_message(
                    "model override applied for profile %s: %s",
                    profile,
                    model_setting_label(model, reasoning_effort),
                )
        request_id = self.server.begin_request(profile, session_key)
        started = time.monotonic()
        status_code: int | None = None
        bytes_out = 0
        try:
            status_code, bytes_out = self._proxy_to_upstream_once(
                method,
                parsed,
                body=body,
                retry_on_401=True,
                route=route,
                profile=profile,
            )
        finally:
            elapsed = time.monotonic() - started
            self.server.record_http_stats(
                profile=profile,
                route=route,
                path=parsed.path,
                method=method,
                status_code=status_code,
                duration_seconds=elapsed,
                bytes_in=len(body or b""),
                bytes_out=bytes_out,
                service_tier=service_tier,
            )
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
    ) -> tuple[int, int]:
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
                status = 402 if error_requires_billing(exc) else 502
                self.send_json({"error": quota_refresh_error_message(exc)}, status=status)
                return status, 0
            self.log_message(
                "usage response for profile %s served from %s cache",
                profile,
                cache_state,
            )
            self.send_json(labeled)
            return 200, len(json.dumps(labeled).encode("utf-8"))

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
                if route == UpstreamRoute.CODEX_API and parsed.path in ("/v1/responses", "/v1/responses/compact"):
                    self.server.clear_profile_billing_required(profile)
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
                        return response.status, len(json.dumps(labeled).encode("utf-8"))
                    self.send_response_bytes(response.status, response.headers, payload)
                    return response.status, len(payload)

                self.send_response(response.status)
                self.forward_response_headers(response.headers)
                self.prepare_close_delimited_response(response.headers)
                self.end_headers()
                bytes_out = 0
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    bytes_out += len(chunk)
                    if not self.write_downstream(chunk):
                        return response.status, bytes_out
                return response.status, bytes_out
        except urllib.error.HTTPError as exc:
            if retry_on_401 and exc.code == 401 and self.is_chatgpt_profile(auth_path):
                try:
                    force_refresh_chatgpt_auth(auth_path)
                except AuthError as refresh_exc:
                    if auth_error_requires_login(refresh_exc):
                        self.server.mark_profile_login_required(profile, refresh_exc)
                    self.send_json({"error": quota_refresh_error_message(refresh_exc)}, status=401)
                    return 401, 0
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
            if exc.code == 402:
                self.server.mark_profile_billing_required(
                    profile,
                    http_error_detail_message(exc, detail),
                )
            if exc.code == 401:
                message = detail.decode("utf-8", errors="replace") if detail else str(exc)
                self.server.mark_profile_login_required(profile, message)
            if detail:
                self.write_downstream(detail)
            return exc.code, len(detail or b"")
        except (urllib.error.URLError, TimeoutError, AuthError) as exc:
            if isinstance(exc, AuthError) and auth_error_requires_login(exc):
                self.server.mark_profile_login_required(profile, exc)
            if error_requires_billing(exc):
                self.server.mark_profile_billing_required(profile, exc)
            self.send_json({"error": str(exc)}, status=502)
            return 502, 0

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
                try:
                    auth = force_refresh_chatgpt_auth(auth_path)
                except AuthError as refresh_exc:
                    if auth_error_requires_login(refresh_exc):
                        self.server.mark_profile_login_required(profile, refresh_exc)
                    raise
                upstream = self.open_upstream_websocket(parsed, auth, profile=profile)
            self.server.attach_websocket_upstream(tunnel_id, upstream)
            self.server.clear_profile_billing_required(profile)
            self.log_message("websocket tunnel established for profile %s", profile)
            self.relay_websocket(upstream, tunnel_id, profile)
        except WebSocketHandshakeRejected as exc:
            self.log_message(
                "websocket handshake rejected for profile %s: %s",
                profile,
                exc,
            )
            if exc.status_code == 401:
                detail = exc.response.decode("utf-8", errors="replace")
                self.server.mark_profile_login_required(profile, detail or exc)
            if exc.status_code == 402:
                self.server.mark_profile_billing_required(
                    profile,
                    BillingRequiredError("HTTP Error 402: Payment Required"),
                )
            try:
                self.connection.sendall(exc.response)
            except OSError:
                pass
        except AuthError as exc:
            self.log_message("websocket auth error: %s", exc)
            if auth_error_requires_login(exc):
                self.server.mark_profile_login_required(profile, exc)
            if error_requires_billing(exc):
                self.server.mark_profile_billing_required(profile, exc)
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
                self.server.record_websocket_stats(tunnel_id)
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
            model_label=self.server.profile_model_label(active_profile),
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
        ssl_context = ssl.create_default_context()
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        upstream: ssl.SSLSocket | socket.socket = ssl_context.wrap_socket(
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
        downstream_rewriter = WebSocketMessageRewriter(mask_output=True)
        upstream_tracker = WebSocketMessageTracker()
        model_setting = self.server.profile_model_setting(profile)
        model = str(model_setting.get("model") or "")
        reasoning_effort = str(model_setting.get("reasoning_effort") or "")

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
                    service_tier = None
                    if from_downstream:
                        def rewrite_message(opcode: int, payload: bytes) -> bytes:
                            nonlocal service_tier
                            rewritten, next_tier, changed = rewrite_service_tier_websocket_message(
                                opcode,
                                payload,
                                fast_enabled=self.server.profile_fast_mode(profile),
                            )
                            if next_tier:
                                service_tier = next_tier
                            elif changed:
                                service_tier = STANDARD_SERVICE_TIER
                            current_model_setting = self.server.profile_model_setting(profile)
                            current_model = str(current_model_setting.get("model") or "")
                            current_reasoning = str(
                                current_model_setting.get("reasoning_effort") or ""
                            )
                            rewritten, _model, _reasoning, model_changed = rewrite_model_websocket_message(
                                opcode,
                                rewritten,
                                model=current_model,
                                reasoning_effort=current_reasoning,
                            )
                            if model_changed:
                                self.log_message(
                                    "websocket model override applied for profile %s: %s",
                                    profile,
                                    model_setting_label(current_model, current_reasoning),
                                )
                            return rewritten

                        outbound, messages = downstream_rewriter.feed(data, rewrite_message)
                    else:
                        outbound = data
                        messages = tracker.feed(data)
                    self.server.note_websocket_traffic(
                        tunnel_id,
                        bytes_count=len(outbound),
                        message_count=len(messages),
                        from_downstream=from_downstream,
                        service_tier=service_tier,
                    )
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
                                service_tier=self.server.websocket_service_tier(tunnel_id),
                            ):
                                self.log_message(
                                    "quota cache for profile %s updated from websocket event",
                                    profile,
                                )
                            usage = websocket_message_token_usage(opcode, payload)
                            if usage:
                                self.server.record_token_usage(
                                    profile=profile,
                                    tunnel_id=tunnel_id,
                                    usage=usage,
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
                    if outbound:
                        target.sendall(outbound)
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
            "host": self.server.server_address[0],
            "port": self.server.server_address[1],
            "provision_protocol": PROTOCOL_VERSION,
            "codex": codex_compatibility_payload(),
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
                item["billing_required"] = self.server.profile_billing_required(str(name)) if name else {}
                profiles.append(item)
            payload["profiles"] = profiles
        return payload

    def ui_status_payload(self) -> dict[str, Any]:
        status = self.status_payload(include_profiles=True)
        status["model_catalog"] = model_catalog()
        status["stats"] = self.server.stats_summary()
        for profile in status["profiles"]:
            name = str(profile.get("name") or "")
            snapshot = self.server.usage_cache_snapshot(name) if name else None
            billing_required = self.server.profile_billing_required(name)
            if isinstance(billing_required, dict) and billing_required.get("required") and not snapshot:
                snapshot = {
                    "error": billing_required.get("error") or "HTTP Error 402: Payment Required",
                    "error_at": billing_required.get("error_at") or "",
                    "billing_required": True,
                }
            payload = snapshot.get("payload") if isinstance(snapshot, dict) else None
            profile["fast_mode"] = self.server.profile_fast_mode(name)
            profile["model_setting"] = self.server.profile_model_setting(name)
            profile["login_required"] = self.server.profile_login_required(name)
            profile["auth_health"] = self.server.profile_auth_health(name)
            profile["auth_health_html"] = render_auth_health_html(profile["auth_health"])
            profile["billing_required"] = billing_required
            profile["login_status"] = self.server.login_status(name)
            profile["login_status_html"] = render_login_status_html(
                profile["login_status"],
                name,
                self.server.proxy_token,
            )
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
        billing = profile.get("billing_required")
        if isinstance(billing, dict) and billing.get("required"):
            if state := usage_payload_state(billing.get("error")):
                return state["title"]
            return "Billing required"
        block_reason = status.get("switch_block_reason")
        if isinstance(block_reason, str) and block_reason:
            return f"Disabled while {block_reason}"
        return ""

    def switch_button_label(self, profile: dict[str, Any], status: dict[str, Any]) -> str:
        if profile.get("active"):
            return "Current"
        billing = profile.get("billing_required")
        if isinstance(billing, dict) and billing.get("required"):
            return "Unavailable" if usage_payload_state(billing.get("error")) else "Billing"
        active_requests = status.get("blocking_active_requests")
        if isinstance(active_requests, int) and active_requests > 0:
            return "In Use"
        pending_work = status.get("blocking_pending_websocket_work")
        if isinstance(pending_work, int) and pending_work > 0:
            return "In Use"
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
            status_text = " / ".join(status_bits) if status_bits else "idle"
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

    def render_fast_pill(self, profile: dict[str, Any]) -> str:
        profile_name = str(profile.get("name") or "")
        enabled = bool(profile.get("fast_mode"))
        enabled_class = " enabled" if enabled else ""
        return f"""
          <form method="post" action="/api/toggle-fast" class="profile-pill-form" data-action="toggle_fast" data-profile="{html.escape(profile_name)}">
            <input type="hidden" name="token" value="{html.escape(self.server.proxy_token)}">
            <input type="hidden" name="profile" value="{html.escape(profile_name)}">
            <button class="profile-pill fast-pill{enabled_class}" title="Toggle fast mode">Fast</button>
          </form>
        """

    def render_login_pill(self, profile: dict[str, Any]) -> str:
        profile_name = str(profile.get("name") or "")
        login_required = profile.get("login_required")
        login_status = profile.get("login_status")
        status = str(login_status.get("status") or "") if isinstance(login_status, dict) else ""
        running = status in LOGIN_ACTIVE_STATUSES
        required = isinstance(login_required, dict) and bool(login_required.get("required"))
        if not required and not running:
            return ""
        error = ""
        if isinstance(login_required, dict):
            error = str(login_required.get("error") or "")
        if not error and isinstance(login_status, dict):
            error = str(login_status.get("error") or login_status.get("message") or "")
        disabled = "disabled" if running else ""
        cancel_disabled = "disabled" if status == "canceling" else ""
        title = "Login already running" if running else (error or "Refresh profile login")
        token = html.escape(self.server.proxy_token)
        name = html.escape(profile_name)
        cancel_form = (
            f"""
              <form method="post" action="/api/login" data-action="cancel_login" data-profile="{name}">
                <input type="hidden" name="token" value="{token}">
                <input type="hidden" name="profile" value="{name}">
                <input type="hidden" name="login_action" value="cancel_login">
                <button class="menu-action danger-action" {cancel_disabled}>Cancel Login</button>
              </form>
            """
            if running
            else ""
        )
        return f"""
          <details class="login-menu profile-login-menu" data-profile="{name}">
            <summary class="profile-pill login-pill" title="{html.escape(title)}">Login</summary>
            <div class="login-menu-panel">
              <div class="login-menu-note">{html.escape(LOGIN_BROWSER_REMOTE_NOTE)}</div>
              <form method="post" action="/api/login" data-action="start_login" data-profile="{name}">
                <input type="hidden" name="token" value="{token}">
                <input type="hidden" name="profile" value="{name}">
                <input type="hidden" name="mode" value="browser">
                <button class="menu-action" {disabled}>Browser Login</button>
              </form>
              <form method="post" action="/api/login" data-action="start_login" data-profile="{name}">
                <input type="hidden" name="token" value="{token}">
                <input type="hidden" name="profile" value="{name}">
                <input type="hidden" name="mode" value="device">
                <button class="menu-action" {disabled}>Device Auth</button>
              </form>
              {cancel_form}
            </div>
          </details>
        """

    def render_billing_pill(self, profile: dict[str, Any]) -> str:
        billing = profile.get("billing_required")
        if not isinstance(billing, dict) or not billing.get("required"):
            return ""
        state = usage_payload_state(billing.get("error"))
        title = state["message"] if state else billing_required_message(billing.get("error"))
        label = state["title"] if state else "Billing required"
        return (
            f'<span class="profile-pill billing-pill" title="{html.escape(title)}">'
            f"{html.escape(label)}</span>"
        )

    def render_profile_chips(self, profile: dict[str, Any]) -> str:
        chips = []
        if profile.get("active"):
            chips.append('<span class="badge active-badge">Active</span>')
        billing_pill = self.render_billing_pill(profile)
        if billing_pill:
            chips.append(billing_pill)
        chips.append(self.render_fast_pill(profile))
        login_pill = self.render_login_pill(profile)
        if login_pill:
            chips.append(login_pill)
        return f'<div class="profile-chips">{"".join(chips)}</div>'

    def render_model_menu(self, profile: dict[str, Any]) -> str:
        profile_name = str(profile.get("name") or "")
        setting = profile.get("model_setting") if isinstance(profile.get("model_setting"), dict) else {}
        current_model = str(setting.get("model") or DEFAULT_MODEL_ID)
        current_reasoning = str(setting.get("reasoning_effort") or default_reasoning_for_model(current_model))
        label = model_pill_label(current_model, current_reasoning)
        token = html.escape(self.server.proxy_token)
        name = html.escape(profile_name)
        items: list[str] = []
        for item in model_catalog():
            model = str(item.get("id") or "")
            if not model:
                continue
            display = str(item.get("display") or model)
            note = str(item.get("note") or "")
            selected_class = " selected" if model == current_model else ""
            reasoning_levels = reasoning_levels_for_model(model)
            reasoning_forms = []
            for reasoning in reasoning_levels:
                reasoning_selected = model == current_model and reasoning == current_reasoning
                reasoning_class = " selected" if reasoning_selected else ""
                reasoning_forms.append(
                    f"""
                    <form method="post" action="/api/model" data-action="set_model" data-profile="{name}">
                      <input type="hidden" name="token" value="{token}">
                      <input type="hidden" name="profile" value="{name}">
                      <input type="hidden" name="model" value="{html.escape(model)}">
                      <input type="hidden" name="reasoning_effort" value="{html.escape(reasoning)}">
                      <button class="model-reasoning-option{reasoning_class}">{html.escape(reasoning_display_name(reasoning))}</button>
                    </form>
                    """
                )
            items.append(
                f"""
                <div class="model-option{selected_class}" data-model="{html.escape(model)}" title="{html.escape(note)}">
                  <button class="model-option-label" type="button">
                    <span>{html.escape(display)}</span>
                    <span class="model-option-arrow">&rsaquo;</span>
                  </button>
                  <div class="model-reasoning-menu">{''.join(reasoning_forms)}</div>
                </div>
                """
            )
        return f"""
          <details class="model-menu" data-profile="{name}">
            <summary class="model-pill" title="Select model and reasoning effort">
              <span>{html.escape(label)}</span>
            </summary>
            <div class="model-menu-panel">{''.join(items)}</div>
          </details>
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
        switch_reason = str(profile.get("switch_disabled_reason") or "")
        switch_label = html.escape(str(profile.get("switch_button_label") or "Use"))
        switch_class = "primary-action current-action" if profile.get("active") else "primary-action"
        if profile.get("active") and profile.get("has_active_sessions"):
            switch_class += " session-active-action"
        disabled = "disabled" if switch_reason else ""
        pin_menu = str(profile.get("pin_menu_html") or "")
        pinned_sessions = str(profile.get("pinned_sessions_html") or "")
        login_status_html = str(profile.get("login_status_html") or "")
        auth_health_html = str(profile.get("auth_health_html") or "")
        profile_chips = self.render_profile_chips(profile)
        model_menu = self.render_model_menu(profile)
        token = html.escape(self.server.proxy_token)
        return f"""
          <tr class="profile-row{active}" data-profile="{name}">
            <td class="profile-cell">
              <div class="profile-name">{name} <span class="profile-plan">({plan})</span></div>
              <div class="profile-email">{email}</div>
              {auth_health_html}
              {profile_chips}
              {pin_menu}
              {pinned_sessions}
              {login_status_html}
            </td>
            <td class="model-cell">{model_menu}</td>
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
        codex = status.get("codex") if isinstance(status.get("codex"), dict) else {}
        codex_cli = codex.get("cli") if isinstance(codex.get("cli"), dict) else {}
        codex_version = html.escape(str(codex_cli.get("version") or "unknown"))
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
			      --red-hi: #eb5555;
			      --red-low: #ad2929;
			      --red-dark: #9f2424;
			      --green: #198754;
			      --green-hi: #22a66a;
			      --green-low: #116d42;
			      --blue: #2563eb;
			      --blue-hi: #4c7ff4;
			      --blue-low: #1e4fc2;
			      --amber: #b7791f;
			      --amber-hi: #d59b35;
			      --amber-low: #8d5d14;
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
		        --red-hi: #ff6f6f;
		        --red-low: #c83a3a;
		        --red-dark: #c83a3a;
		        --green: #35b779;
		        --green-hi: #48d996;
		        --green-low: #20915d;
		        --blue: #60a5fa;
		        --blue-hi: #7fb8ff;
		        --blue-low: #3b82d6;
		        --amber: #d79a2b;
		        --amber-hi: #efbd54;
		        --amber-low: #a86f16;
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
		      --red-hi: #eb5555;
		      --red-low: #ad2929;
		      --red-dark: #9f2424;
		      --green: #198754;
		      --green-hi: #22a66a;
		      --green-low: #116d42;
		      --blue: #2563eb;
		      --blue-hi: #4c7ff4;
		      --blue-low: #1e4fc2;
		      --amber: #b7791f;
		      --amber-hi: #d59b35;
		      --amber-low: #8d5d14;
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
			      --red-hi: #ff6f6f;
			      --red-low: #c83a3a;
			      --red-dark: #c83a3a;
			      --green: #35b779;
			      --green-hi: #48d996;
			      --green-low: #20915d;
			      --blue: #60a5fa;
			      --blue-hi: #7fb8ff;
			      --blue-low: #3b82d6;
			      --amber: #d79a2b;
			      --amber-hi: #efbd54;
			      --amber-low: #a86f16;
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
	      background: linear-gradient(180deg, var(--surface), var(--subtle));
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
		      gap: 8px;
		      justify-content: center;
		    }
		    .stats-toggle {
		      width: 30px;
		      min-height: 30px;
		      padding: 0;
		      display: inline-flex;
		      align-items: center;
		      justify-content: center;
		      border-radius: 999px;
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
		    .stats-toggle svg,
		    .theme-toggle svg {
		      width: 16px;
		      height: 16px;
		      stroke: currentColor;
		      stroke-width: 2;
		      stroke-linecap: round;
		      stroke-linejoin: round;
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
    .modal-backdrop {
      position: fixed;
      inset: 0;
      z-index: 80;
      display: grid;
      place-items: center;
      padding: 18px;
      background: rgba(0, 0, 0, 0.42);
    }
    .modal-backdrop[hidden] { display: none; }
    .stats-modal {
      width: min(980px, calc(100vw - 36px));
      max-height: calc(100vh - 36px);
      overflow: auto;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    .stats-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      background: var(--soft);
    }
    .stats-head h2 {
      margin: 0;
      font-size: 15px;
    }
    .stats-close {
      width: 30px;
      min-height: 30px;
      padding: 0;
      border-radius: 999px;
    }
    .stats-content {
      display: grid;
      gap: 16px;
      padding: 14px;
    }
    .stats-graph-card {
      display: grid;
      gap: 10px;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      background: var(--subtle);
    }
    .stats-graph-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
    }
    .stats-section h3 {
      margin: 0 0 8px;
      font-size: 12px;
      text-transform: uppercase;
      color: var(--muted);
      letter-spacing: 0;
    }
    .stats-graph-card h3 {
      margin: 0;
      font-size: 12px;
      text-transform: uppercase;
      color: var(--muted);
      letter-spacing: 0;
    }
    .stats-profile-toggles {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      justify-content: flex-end;
    }
    .stats-profile-toggle {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
      color: var(--muted);
      cursor: pointer;
    }
    .stats-profile-toggle input { margin: 0; }
    .stats-profile-toggle span {
      width: 9px;
      height: 9px;
      border-radius: 50%;
      background: var(--profile-color);
      display: inline-block;
    }
    .stats-graph {
      min-height: 190px;
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      color: var(--muted);
    }
    .stats-graph-svg {
      width: 100%;
      height: auto;
      min-height: 190px;
      display: block;
    }
    .stats-graph-empty {
      min-height: 190px;
      display: grid;
      place-items: center;
      color: var(--muted);
      font-weight: 650;
    }
    .stats-table-wrap {
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 6px;
    }
    .stats-table {
      table-layout: auto;
      min-width: 760px;
    }
    .stats-table th,
    .stats-table td {
      padding: 8px 10px;
      border-bottom: 1px solid var(--line);
      white-space: nowrap;
    }
    .stats-table tbody tr:last-child td { border-bottom: 0; }
    .stats-table td:first-child { font-weight: 700; color: var(--ink); }
    .stats-recent {
      display: grid;
      gap: 7px;
      max-height: 260px;
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px;
      background: var(--subtle);
    }
    .stats-event {
      display: grid;
      grid-template-columns: 116px 1fr;
      gap: 10px;
      color: var(--muted);
      font-size: 12px;
    }
    .stats-event strong { color: var(--ink); }
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
	    .profile-col { width: 270px; }
	    .model-col { width: 220px; }
	    .actions-col { width: 130px; }
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
	    .model-cell { color: var(--muted); min-width: 0; overflow: visible; }
	    .actions { width: 130px; }
	    .quota-cell { min-width: 0; overflow: hidden; }
	    .profile-name {
	      display: flex;
	      align-items: center;
      gap: 8px;
      font-weight: 700;
	      min-width: 0;
	      overflow-wrap: anywhere;
	      text-shadow: 0 1px 0 rgba(255, 255, 255, 0.58);
	    }
	    :root[data-theme="dark"] .profile-name {
	      text-shadow: 0 1px 0 rgba(0, 0, 0, 0.45);
	    }
    .profile-email {
      color: var(--muted);
      margin-top: 3px;
      overflow-wrap: anywhere;
    }
    .profile-plan {
      color: var(--muted);
      font-weight: 650;
    }
    .profile-chips {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
      margin-top: 8px;
    }
    .profile-pill-form { margin: 0; }
    .profile-pill {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: auto;
      min-height: 22px;
      padding: 1px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 750;
      color: var(--muted);
	      background: linear-gradient(180deg, var(--surface), var(--subtle));
	      border: 1px solid var(--line);
	      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.72), 0 1px 1px rgba(23, 23, 23, 0.04);
	      cursor: pointer;
	    }
	    :root[data-theme="dark"] .profile-pill {
	      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 1px 1px rgba(0, 0, 0, 0.26);
	    }
	    .fast-pill.enabled {
	      color: #fff;
	      background: linear-gradient(180deg, var(--blue-hi), var(--blue-low));
	      border-color: var(--blue);
	      text-shadow: 0 1px 0 rgba(0, 0, 0, 0.28);
	    }
		    .login-pill {
		      color: #fff;
		      background: linear-gradient(180deg, var(--red-hi), var(--red-low));
		      border-color: var(--danger);
		      text-shadow: 0 1px 0 rgba(0, 0, 0, 0.28);
		    }
		    .billing-pill {
		      color: #5f3b00;
		      background: linear-gradient(180deg, #ffd976, #e6af35);
		      border-color: #d79b1e;
		      cursor: default;
		    }
	    :root[data-theme="dark"] .billing-pill {
	      color: #211500;
		      background: linear-gradient(180deg, #ffd36b, #d79a2b);
		      border-color: #f2bd43;
		    }
    .login-status {
      margin-top: 8px;
      padding: 8px;
      border: 1px solid var(--line);
      border-left: 3px solid var(--amber);
      border-radius: 6px;
      background: var(--subtle);
      color: var(--muted);
      font-size: 12px;
    }
    .login-status.complete { border-left-color: var(--green); }
    .login-status.error { border-left-color: var(--danger); }
    .login-status.canceled { border-left-color: var(--muted); }
    .auth-health {
      margin-top: 5px;
      font-size: 11px;
      line-height: 1.35;
      color: var(--amber-dark);
      overflow-wrap: anywhere;
    }
    .auth-health.login_required {
      color: var(--danger);
    }
    :root[data-theme="dark"] .auth-health {
      color: #f2bd43;
    }
    :root[data-theme="dark"] .auth-health.login_required {
      color: #ff9a9a;
    }
    .login-status-top,
    .login-status-actions {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
    }
    .login-status-top strong { color: var(--ink); }
    .login-status-actions { margin-top: 5px; }
    .login-link {
      color: var(--red);
      font-weight: 750;
      text-decoration: none;
    }
    .login-cancel-form {
      margin: 0;
    }
    .login-cancel-action {
      min-height: 24px;
      padding: 2px 8px;
      border: 1px solid rgba(216, 52, 52, 0.45);
      border-radius: 6px;
      background: var(--surface);
      color: var(--danger);
      font-size: 12px;
      font-weight: 750;
    }
    .login-code code {
      padding: 1px 5px;
      border: 1px solid var(--line);
      border-radius: 4px;
      background: var(--surface);
      color: var(--ink);
      font: 12px/1.3 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    .login-detail {
      margin-top: 5px;
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
		      background: linear-gradient(180deg, var(--button-bg), var(--button-hover));
		      color: var(--ink);
	      font-weight: 650;
      cursor: pointer;
      white-space: nowrap;
      display: inline-flex;
	      align-items: center;
	      justify-content: center;
	      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.62), 0 1px 1px rgba(23, 23, 23, 0.04);
	    }
	    :root[data-theme="dark"] button {
	      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 1px 1px rgba(0, 0, 0, 0.28);
	    }
		    button:hover:not(:disabled) { border-color: var(--muted); background: var(--button-hover); }
		    button:disabled { color: var(--button-disabled-ink); background: var(--button-disabled-bg); cursor: not-allowed; }
	    .primary-action {
	      background: linear-gradient(180deg, var(--red-hi), var(--red-low));
	      border-color: var(--red);
	      color: #fff;
	      text-shadow: 0 1px 0 rgba(0, 0, 0, 0.32);
	    }
	    .primary-action:hover:not(:disabled) { background: var(--red-dark); border-color: var(--red-dark); }
	    .current-action,
	    .current-action:disabled {
	      background: linear-gradient(180deg, var(--green-hi), var(--green-low));
	      border-color: var(--green);
	      color: #fff;
	      opacity: 1;
	      text-shadow: 0 1px 0 rgba(0, 0, 0, 0.28);
	    }
	    .primary-action.session-active-action,
	    .primary-action.session-active-action:disabled {
	      background: linear-gradient(180deg, var(--amber-hi), var(--amber-low));
	      border-color: var(--amber);
	      color: #fff;
	      opacity: 1;
	      text-shadow: 0 1px 0 rgba(0, 0, 0, 0.28);
	    }
    .primary-action.session-active-action:hover:not(:disabled) {
      background: var(--amber-dark);
      border-color: var(--amber-dark);
    }
    form { margin: 0 0 7px; }
    form:last-child { margin-bottom: 0; }
    .login-menu,
    .model-menu {
      position: relative;
      margin: 0;
    }
    .login-menu summary,
    .model-menu summary {
      list-style: none;
    }
    .login-menu summary::-webkit-details-marker,
    .model-menu summary::-webkit-details-marker {
      display: none;
    }
    .login-menu-panel,
    .model-menu-panel,
    .model-reasoning-menu {
      position: absolute;
      z-index: 35;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      box-shadow: var(--shadow);
    }
    .login-menu-panel {
      left: 0;
      top: calc(100% + 6px);
      width: min(260px, calc(100vw - 32px));
      padding: 8px;
    }
    .login-menu-note {
      margin: 0 0 8px;
      color: var(--muted);
      font-size: 11px;
      line-height: 1.35;
    }
    .login-menu-panel form,
    .model-menu-panel form,
    .model-reasoning-menu form {
      margin: 0;
    }
    .danger-action {
      color: var(--danger);
    }
    .menu-action,
    .model-option-label,
    .model-reasoning-option {
      justify-content: flex-start;
      min-height: 30px;
      text-align: left;
    }
    .model-pill {
      width: 100%;
      min-height: 30px;
      padding: 3px 9px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--subtle);
      color: var(--ink);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      flex-wrap: wrap;
      gap: 5px;
      font-weight: 750;
      cursor: pointer;
	      text-align: center;
	      line-height: 1.2;
	      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.68), 0 1px 1px rgba(23, 23, 23, 0.04);
	      text-shadow: 0 1px 0 rgba(255, 255, 255, 0.58);
	    }
	    :root[data-theme="dark"] .model-pill {
	      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 1px 1px rgba(0, 0, 0, 0.28);
	      text-shadow: 0 1px 0 rgba(0, 0, 0, 0.45);
	    }
    .model-menu-panel {
      top: calc(100% + 6px);
      left: 0;
      width: 240px;
      padding: 7px;
    }
    .model-option {
      position: relative;
      margin-bottom: 4px;
    }
    .model-option:last-child { margin-bottom: 0; }
	    .model-option-label {
	      width: 100%;
	      justify-content: space-between;
	      gap: 8px;
	    }
	    .model-option-label span:first-child,
	    .model-reasoning-option {
	      text-shadow: 0 1px 0 rgba(255, 255, 255, 0.55);
	    }
	    :root[data-theme="dark"] .model-option-label span:first-child,
	    :root[data-theme="dark"] .model-reasoning-option {
	      text-shadow: 0 1px 0 rgba(0, 0, 0, 0.42);
	    }
	    .model-option.selected > .model-option-label,
	    .model-reasoning-option.selected {
	      border-color: var(--green);
	      color: var(--green);
	      background: linear-gradient(180deg, rgba(34, 166, 106, 0.12), rgba(17, 109, 66, 0.08));
	      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.55);
	    }
    .model-option-arrow {
      color: var(--muted);
      font-size: 16px;
      line-height: 1;
    }
    .model-reasoning-menu {
      display: none;
      top: 0;
      left: calc(100% + 6px);
      width: 132px;
      padding: 7px;
      gap: 4px;
    }
    .model-option:hover .model-reasoning-menu,
    .model-option:focus-within .model-reasoning-menu,
    .model-option.reasoning-open .model-reasoning-menu {
      display: grid;
    }
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
	      flex: 1 1 auto;
	      min-width: 0;
	      white-space: nowrap;
	      overflow: hidden;
	      text-overflow: ellipsis;
	    }
		    .quota-credits-pill {
		      flex: 0 0 auto;
		      margin-left: auto;
		      padding: 3px 8px;
	      border-radius: 999px;
	      border: 1px solid var(--amber-dark);
	      color: #2f2107;
	      background: #f5c84b;
	      font-size: 11px;
	      font-weight: 820;
	      line-height: 1.15;
	      white-space: nowrap;
	    }
		    :root[data-theme="dark"] .quota-credits-pill {
		      color: #281b04;
		      background: #e4b83d;
		      border-color: #f0cf66;
		    }
	    .reset-credit-form {
	      flex: 0 0 auto;
	      margin: 0 0 0 auto;
	    }
	    .quota-credits-pill + .reset-credit-form,
	    .reset-credit-form + .quota-credits-pill {
	      margin-left: 4px;
	    }
	    .quota-reset-credit-pill {
	      padding: 3px 8px;
	      border-radius: 999px;
	      border: 1px solid #b7791f;
	      color: #332205;
	      background: linear-gradient(180deg, #f8d76b, #e4ad28);
	      box-shadow: inset 0 1px 0 rgba(255,255,255,0.35);
	      font-size: 11px;
	      font-weight: 820;
	      line-height: 1.15;
	      white-space: nowrap;
	    }
	    .quota-reset-credit-pill:hover {
	      border-color: #8f5c10;
	      filter: brightness(0.98);
	    }
	    :root[data-theme="dark"] .quota-reset-credit-pill {
	      color: #261901;
	      background: linear-gradient(180deg, #f0ca58, #cf981f);
	      border-color: #f0cf66;
	    }
    .quota-bucket {
	      border: 1px solid var(--line);
	      border-radius: 0;
	      padding: 8px 10px;
	      background: var(--surface);
	      max-width: 100%;
	      overflow: hidden;
	    }
	    .quota-title {
	      display: grid;
	      grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr);
	      align-items: center;
	      gap: 8px;
	      min-width: 0;
      margin-bottom: 6px;
	    }
	    .quota-bucket-name {
	      font-weight: 720;
	      text-align: center;
	      min-width: 0;
	      overflow-wrap: anywhere;
	      text-shadow: 0 1px 0 rgba(255, 255, 255, 0.62);
	    }
	    :root[data-theme="dark"] .quota-bucket-name {
	      text-shadow: 0 1px 0 rgba(0, 0, 0, 0.45);
	    }
    .quota-stack {
      display: grid;
      min-width: 0;
    }
    .quota-horizon {
      min-width: 0;
      overflow-wrap: anywhere;
      white-space: normal;
      font-size: 12px;
      font-weight: 750;
      line-height: 1.2;
    }
	    .quota-horizon.primary {
	      color: var(--green);
	      text-align: right;
	      text-shadow: 0 1px 0 rgba(255, 255, 255, 0.58);
	    }
	    .quota-horizon.weekly {
	      color: var(--blue);
	      text-align: left;
	      text-shadow: 0 1px 0 rgba(255, 255, 255, 0.58);
	    }
	    :root[data-theme="dark"] .quota-horizon.primary,
	    :root[data-theme="dark"] .quota-horizon.weekly {
	      text-shadow: 0 1px 0 rgba(0, 0, 0, 0.45);
	    }
    .quota-stack-row {
      display: grid;
      grid-template-columns: 44px minmax(120px, 1fr) 44px;
      gap: 10px;
      align-items: center;
      min-width: 0;
    }
	    .quota-stack-bar {
	      position: relative;
	      height: 30px;
	      border-radius: 0;
		      background: linear-gradient(180deg, var(--surface), var(--bar-bg));
		      box-shadow: inset 0 1px 1px rgba(255, 255, 255, 0.62), inset 0 -1px 1px rgba(23, 23, 23, 0.08);
		      overflow: hidden;
	      min-width: 0;
    }
    .quota-weekly-fill,
    .quota-primary-fill {
      position: absolute;
      left: 0;
	      border-radius: 0;
	    }
	    .quota-stack-unlimited .quota-stack-bar,
	    .quota-stack-unknown .quota-stack-bar {
	      background: var(--soft);
	    }
	    .quota-weekly-fill {
	      top: 0;
	      bottom: 0;
		      background: linear-gradient(180deg, var(--blue-hi), var(--blue-low));
		      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.26), inset 0 -1px 0 rgba(0, 0, 0, 0.16);
		      opacity: 0.86;
    }
	    .quota-primary-fill {
	      bottom: 0;
	      height: 20px;
	      display: flex;
	      align-items: center;
	      justify-content: flex-end;
		      background: linear-gradient(180deg, var(--green-hi), var(--green-low));
		      color: #fff;
		      text-shadow: 0 1px 0 rgba(0, 0, 0, 0.28);
		      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.26), inset 0 -1px 0 rgba(0, 0, 0, 0.14);
		      overflow: visible;
	    }
	    .quota-stack-unlimited .quota-weekly-fill,
	    .quota-stack-unknown .quota-weekly-fill {
	      opacity: 0.35;
	    }
	    .quota-stack-unlimited .quota-primary-fill,
	    .quota-stack-unknown .quota-primary-fill {
	      opacity: 0.82;
	    }
    .quota-primary-fill.empty {
      background: transparent;
      color: var(--muted);
    }
	    .quota-primary-label-outside {
	      color: var(--green);
      font-size: 11px;
      font-weight: 800;
      line-height: 1;
	      white-space: nowrap;
	      text-align: left;
	      text-shadow: 0 1px 0 rgba(255, 255, 255, 0.58);
	    }
	    .quota-weekly-label {
	      color: var(--blue);
      font-size: 12px;
      font-weight: 800;
	      text-align: right;
	      white-space: nowrap;
	      text-shadow: 0 1px 0 rgba(255, 255, 255, 0.58);
	    }
	    :root[data-theme="dark"] .quota-primary-label-outside,
	    :root[data-theme="dark"] .quota-weekly-label {
	      text-shadow: 0 1px 0 rgba(0, 0, 0, 0.45);
	    }
	    @media (prefers-color-scheme: dark) {
	      :root:not([data-theme]) .profile-name,
	      :root:not([data-theme]) .model-pill,
	      :root:not([data-theme]) .model-option-label span:first-child,
	      :root:not([data-theme]) .model-reasoning-option,
	      :root:not([data-theme]) .quota-bucket-name,
	      :root:not([data-theme]) .quota-horizon.primary,
	      :root:not([data-theme]) .quota-horizon.weekly,
	      :root:not([data-theme]) .quota-primary-label-outside,
	      :root:not([data-theme]) .quota-weekly-label {
	        text-shadow: 0 1px 0 rgba(0, 0, 0, 0.45);
	      }
	      :root:not([data-theme]) button,
	      :root:not([data-theme]) .profile-pill,
	      :root:not([data-theme]) .model-pill {
	        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 1px 1px rgba(0, 0, 0, 0.28);
	      }
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
		      text-align: center;
		    }
	    .quota-state {
	      min-height: 86px;
	      display: flex;
	      flex-direction: column;
	      align-items: center;
	      justify-content: center;
	      gap: 5px;
	      line-height: 1.35;
	    }
	    .quota-state strong {
	      color: var(--ink);
	      font-size: 13px;
	    }
	    .quota-state span {
	      max-width: 46ch;
	      font-size: 12px;
	    }
	    .quota-state.warning {
	      border-color: rgba(183, 121, 31, 0.45);
	      color: #8a5a14;
	      background: rgba(245, 201, 92, 0.14);
	    }
	    :root[data-theme="dark"] .quota-state.warning {
	      color: #f0cf66;
	      background: rgba(242, 189, 67, 0.1);
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
    .quota-empty.error.billing, .quota-refresh-error.billing { color: #9a6100; }
    :root[data-theme="dark"] .quota-empty.error.billing,
    :root[data-theme="dark"] .quota-refresh-error.billing { color: #f2bd43; }
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
		      .actions { display: grid; grid-template-columns: 1fr; gap: 8px; }
	      .actions form { margin: 0; }
	      .pin-menu { margin: 0; }
	      .pin-menu-panel { left: 0; right: auto; width: min(430px, calc(100vw - 44px)); }
	      .model-menu-panel { width: min(260px, calc(100vw - 44px)); }
	      .model-reasoning-menu {
	        left: 0;
	        top: calc(100% + 4px);
	        width: 100%;
	      }
	      .action-note { grid-column: 1 / -1; margin: 0; }
	      .stats-modal table { display: table; width: 100%; }
	      .stats-modal thead { display: table-header-group; }
	      .stats-modal tbody { display: table-row-group; }
	      .stats-modal tr { display: table-row; border-bottom: 0; }
	      .stats-modal th,
	      .stats-modal td {
	        display: table-cell;
	        width: auto;
	        padding: 8px 10px;
	      }
	    }
  </style>
</head>
<body>
	  <main class="shell">
	    <header class="topbar">
		      <img class="logo" src="/assets/provision-wordmark.png" alt="Provision">
	      <div class="top-meta">
	        <span class="pill">Active <strong id="activeProfile">__ACTIVE_PROFILE__</strong></span>
	        <span class="pill">Codex CLI <strong id="codexVersion">__CODEX_VERSION__</strong></span>
	        <span class="pill">Requests <strong id="activeRequests">__ACTIVE_REQUESTS__</strong></span>
	        <span class="pill">Tunnels <strong id="activeTunnels">__ACTIVE_WEBSOCKETS__</strong></span>
	        <span class="pill"><span id="proxyDot" class="dot"></span><span id="connectionState">Live (__BUSY__)</span></span>
	      </div>
	      <div class="top-actions">
	        <button id="statsToggle" class="stats-toggle" type="button" aria-label="Open stats" title="Open stats"></button>
	        <button id="themeToggle" class="theme-toggle" type="button" aria-label="Toggle color theme" title="Toggle color theme"></button>
	      </div>
	    </header>
    <div id="message" class="message" aria-live="polite"></div>
    <div id="statsModal" class="modal-backdrop" hidden>
      <section class="stats-modal" role="dialog" aria-modal="true" aria-labelledby="statsTitle">
        <div class="stats-head">
          <h2 id="statsTitle">Stats</h2>
          <button id="statsClose" class="stats-close" type="button" aria-label="Close stats">x</button>
        </div>
        <div id="statsContent" class="stats-content"></div>
      </section>
    </div>
    <section class="profiles">
      <table>
        <colgroup>
          <col class="profile-col">
          <col class="model-col">
          <col class="quota-col">
          <col class="actions-col">
        </colgroup>
        <thead>
          <tr><th>Profile</th><th>Model</th><th>Remaining Quota</th><th></th></tr>
        </thead>
        <tbody id="profileRows">__ROWS__</tbody>
      </table>
    </section>
  </main>
  <script>
	    const TOKEN = __TOKEN__;
	    const INITIAL = __INITIAL_STATE__;
	    const LOGIN_BROWSER_REMOTE_NOTE = __LOGIN_BROWSER_REMOTE_NOTE__;
	    const THEME_KEY = "provision-theme";
	    const SUN_ICON = '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2"></path><path d="M12 20v2"></path><path d="m4.93 4.93 1.41 1.41"></path><path d="m17.66 17.66 1.41 1.41"></path><path d="M2 12h2"></path><path d="M20 12h2"></path><path d="m6.34 17.66-1.41 1.41"></path><path d="m19.07 4.93-1.41 1.41"></path></svg>';
	    const MOON_ICON = '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M20.5 14.4A7.5 7.5 0 0 1 9.6 3.5 8.5 8.5 0 1 0 20.5 14.4Z"></path></svg>';
	    const CHART_ICON = '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M3 3v18h18"></path><path d="m7 15 4-4 3 3 5-7"></path><path d="M19 7v5h-5"></path></svg>';
	    let socket = null;
	    let reconnectTimer = null;
	    let latestLiveBusy = Boolean(INITIAL.status && INITIAL.status.live_busy);
	    let latestStats = INITIAL.status && INITIAL.status.stats ? INITIAL.status.stats : { profiles: [], recent: [] };
	    let latestModelCatalog = INITIAL.status && Array.isArray(INITIAL.status.model_catalog) ? INITIAL.status.model_catalog : [];
	    const statsVisibleProfiles = {};
		    let openPinMenuProfile = null;
		    let openModelMenuProfile = null;
		    let openLoginMenuProfile = null;
		    let openReasoningProfile = null;
		    let openReasoningModel = null;
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

	    function formatNumber(value) {
	      return Number(value || 0).toLocaleString();
	    }

	    function formatBytes(value) {
	      const bytes = Number(value || 0);
	      if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
	      if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
	      return `${bytes} B`;
	    }

	    function formatEventTime(value) {
	      if (!value) return "";
	      const date = new Date(value);
	      if (Number.isNaN(date.getTime())) return String(value);
	      return date.toLocaleString([], {
	        month: "short",
	        day: "numeric",
	        hour: "2-digit",
	        minute: "2-digit"
	      });
	    }

	    function signedPercent(value) {
	      const number = Number(value);
	      if (!Number.isFinite(number)) return "";
	      const sign = number > 0 ? "+" : "";
	      return `${sign}${number.toFixed(Math.abs(number) < 1 && number !== 0 ? 1 : 0)}%`;
	    }

	    function quotaDeltaText(quota) {
	      if (!quota || typeof quota !== "object") return "";
	      const pieces = [];
	      for (const [name, row] of Object.entries(quota)) {
	        if (!row || typeof row !== "object") continue;
	        const primaryDelta = signedPercent(row.primary_delta_percent);
	        const weeklyDelta = signedPercent(row.weekly_delta_percent);
	        const primary = row.primary_remaining_percent;
	        const weekly = row.weekly_remaining_percent;
	        const bits = [];
	        if (primaryDelta) bits.push(`5h ${primaryDelta}`);
	        if (weeklyDelta) bits.push(`weekly ${weeklyDelta}`);
	        if (!bits.length && Number.isFinite(Number(primary))) bits.push(`5h ${Number(primary).toFixed(0)}%`);
	        if (!bits.length && Number.isFinite(Number(weekly))) bits.push(`weekly ${Number(weekly).toFixed(0)}%`);
	        if (bits.length) pieces.push(`${name}: ${bits.join(", ")}`);
	      }
	      return pieces.join("; ");
	    }

	    function statsEventText(event) {
	      const type = String(event.type || "");
	      const profile = String(event.profile || "unknown");
	      if (type === "token_usage") {
	        return `${profile} token usage: ${formatNumber(event.tokens)}${event.fast ? " fast" : ""}`;
	      }
	      if (type === "websocket_tunnel") {
	        return `${profile} tunnel closed: ${formatBytes(event.bytes)}`;
	      }
	      if (type === "http_request") {
	        const status = event.status ? `status ${event.status}` : "status unknown";
	        return `${profile} ${event.path || "request"} ${status}`;
	      }
	      if (type === "quota_update") {
	        const movement = quotaDeltaText(event.quota);
	        const suffix = movement ? `: ${movement}` : "";
	        return `${profile} quota update${event.source ? ` from ${event.source}` : ""}${event.fast ? " while fast" : ""}${suffix}`;
	      }
	      if (type === "reset_credit") {
	        return `${profile} reset credit: ${event.outcome || "unknown"}`;
	      }
	      return `${profile} ${type || "event"}`;
	    }

	    function statsProfileColor(index) {
	      const colors = ["#d83434", "#198754", "#2563eb", "#b7791f", "#7c3aed", "#0891b2", "#be185d"];
	      return colors[index % colors.length];
	    }

	    function statsProfiles(stats) {
	      const names = new Set();
	      for (const profile of Array.isArray(stats.profiles) ? stats.profiles : []) {
	        if (profile && profile.profile) names.add(String(profile.profile));
	      }
	      for (const point of Array.isArray(stats.series) ? stats.series : []) {
	        if (point && point.profile) names.add(String(point.profile));
	      }
	      return Array.from(names).sort();
	    }

	    function syncStatsVisibleProfiles(profiles) {
	      for (const profile of profiles) {
	        if (!(profile in statsVisibleProfiles)) statsVisibleProfiles[profile] = true;
	      }
	    }

	    function renderStatsGraph(stats, profiles) {
	      const series = Array.isArray(stats.series) ? stats.series : [];
	      const activeProfiles = profiles.filter((profile) => statsVisibleProfiles[profile]);
	      const points = series
	        .filter((point) => activeProfiles.includes(String(point.profile || "")))
	        .map((point) => ({
	          profile: String(point.profile || "unknown"),
	          ts: Date.parse(point.ts || ""),
	          value: Number(point.value || 0)
	        }))
	        .filter((point) => Number.isFinite(point.ts) && Number.isFinite(point.value));
	      if (!points.length) {
	        return '<div class="stats-graph-empty">No usage activity recorded yet</div>';
	      }
	      const minTs = Math.min(...points.map((point) => point.ts));
	      const maxTs = Math.max(...points.map((point) => point.ts));
	      const maxValue = Math.max(1, ...points.map((point) => point.value));
	      const width = 760;
	      const height = 190;
	      const padX = 24;
	      const padY = 18;
	      const usableWidth = width - padX * 2;
	      const usableHeight = height - padY * 2;
	      const grouped = new Map();
	      for (const point of points) {
	        if (!grouped.has(point.profile)) grouped.set(point.profile, []);
	        grouped.get(point.profile).push(point);
	      }
	      const lines = Array.from(grouped.entries()).map(([profile, rows]) => {
	        const profileIndex = profiles.indexOf(profile);
	        const color = statsProfileColor(profileIndex < 0 ? 0 : profileIndex);
	        const sorted = rows.slice().sort((a, b) => a.ts - b.ts);
	        const path = sorted.map((point, index) => {
	          const x = padX + (maxTs === minTs ? usableWidth : ((point.ts - minTs) / (maxTs - minTs)) * usableWidth);
	          const y = padY + usableHeight - (point.value / maxValue) * usableHeight;
	          return `${index ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`;
	        }).join(" ");
	        return `<path d="${path}" fill="none" stroke="${color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"></path>`;
	      }).join("");
	      return `
	        <svg class="stats-graph-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Profile usage trend">
	          <path d="M${padX} ${height - padY}H${width - padX}" stroke="currentColor" opacity="0.22"></path>
	          <path d="M${padX} ${padY}V${height - padY}" stroke="currentColor" opacity="0.22"></path>
	          ${lines}
	        </svg>
	      `;
	    }

	    function renderStats(stats) {
	      const content = document.getElementById("statsContent");
	      if (!content) return;
	      const profiles = Array.isArray(stats.profiles) ? stats.profiles : [];
	      const profileNames = statsProfiles(stats);
	      syncStatsVisibleProfiles(profileNames);
	      const toggles = profileNames.map((profile, index) => `
	        <label class="stats-profile-toggle">
	          <input type="checkbox" class="stats-profile-check" value="${escapeHtml(profile)}" ${statsVisibleProfiles[profile] ? "checked" : ""}>
	          <span style="--profile-color: ${statsProfileColor(index)}"></span>
	          ${escapeHtml(profile)}
	        </label>
	      `).join("");
	      const rows = profiles.length ? profiles.map((profile) => {
	        const traffic = `Up ${formatBytes(profile.bytes_up)} / Down ${formatBytes(profile.bytes_down)}`;
	        const activeTunnels = Number(profile.active_tunnels || 0);
	        const tunnelCount = activeTunnels
	          ? `${formatNumber(profile.tunnels)} closed / ${formatNumber(activeTunnels)} active`
	          : formatNumber(profile.tunnels);
	        const tokens = `${formatNumber(profile.total_tokens)} total (${formatNumber(profile.input_tokens)} in, ${formatNumber(profile.output_tokens)} out)`;
	        const fast = `${formatNumber(profile.fast_turns)} events / ${formatNumber(profile.fast_tokens)} tokens`;
	        const quota = quotaDeltaText(profile.last_quota) || "-";
	        return `
	          <tr>
	            <td>${escapeHtml(profile.profile || "unknown")}</td>
	            <td>${formatNumber(profile.requests)}</td>
	            <td>${escapeHtml(tunnelCount)}</td>
	            <td>${escapeHtml(traffic)}</td>
	            <td>${escapeHtml(tokens)}</td>
	            <td>${escapeHtml(fast)}</td>
	            <td>${formatNumber(profile.quota_updates)}</td>
	            <td>${escapeHtml(quota)}</td>
	          </tr>
	        `;
	      }).join("") : '<tr><td colspan="8">No stats recorded yet</td></tr>';
	      const recent = Array.isArray(stats.recent) ? stats.recent.slice().reverse() : [];
	      const recentHtml = recent.length ? recent.map((event) => `
	        <div class="stats-event">
	          <span>${escapeHtml(formatEventTime(event.ts))}</span>
	          <strong>${escapeHtml(statsEventText(event))}</strong>
	        </div>
	      `).join("") : '<div class="stats-event"><span></span><strong>No recent events</strong></div>';
	      content.innerHTML = `
	        <section class="stats-graph-card">
	          <div class="stats-graph-head">
	            <h3>Usage Trend</h3>
	            <div class="stats-profile-toggles">${toggles}</div>
	          </div>
	          <div class="stats-graph">${renderStatsGraph(stats, profileNames)}</div>
	        </section>
	        <section class="stats-section">
	          <h3>Profiles</h3>
	          <div class="stats-table-wrap">
	            <table class="stats-table">
	              <thead>
	                <tr>
	                  <th>Profile</th>
	                  <th>Requests</th>
	                  <th>Tunnels</th>
	                  <th>Traffic</th>
	                  <th>Tokens</th>
	                  <th>Fast</th>
	                  <th>Quota</th>
	                  <th>Last Movement</th>
	                </tr>
	              </thead>
	              <tbody>${rows}</tbody>
	            </table>
	          </div>
	        </section>
	        <section class="stats-section">
	          <h3>Recent Activity</h3>
	          <div class="stats-recent">${recentHtml}</div>
	        </section>
	      `;
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

	    function openMenuProfile(selector) {
	      const openMenu = document.querySelector(`${selector}[open]`);
	      return openMenu ? openMenu.dataset.profile || "" : null;
	    }

	    function rememberOpenMenus() {
	      openPinMenuProfile = openMenuProfile("details.pin-menu");
	      openModelMenuProfile = openMenuProfile("details.model-menu");
	      openLoginMenuProfile = openMenuProfile("details.login-menu");
	      const openReasoning = document.querySelector("details.model-menu[open] .model-option:hover, details.model-menu[open] .model-option.reasoning-open");
	      if (openReasoning) {
	        const modelMenu = openReasoning.closest("details.model-menu");
	        openReasoningProfile = modelMenu ? modelMenu.dataset.profile || null : null;
	        openReasoningModel = openReasoning.dataset.model || null;
	      }
	    }

	    function restoreMenu(selector, profile) {
	      if (!profile) return;
	      document.querySelectorAll(selector).forEach((menu) => {
	        menu.open = menu.dataset.profile === profile;
	      });
	    }

	    function restoreOpenMenus() {
	      restoreMenu("details.pin-menu", openPinMenuProfile);
	      restoreMenu("details.model-menu", openModelMenuProfile);
	      restoreMenu("details.login-menu", openLoginMenuProfile);
	      restoreReasoningMenu();
	    }

	    function restoreReasoningMenu() {
	      document.querySelectorAll(".model-option.reasoning-open").forEach((option) => {
	        option.classList.remove("reasoning-open");
	      });
	      if (!openReasoningProfile || !openReasoningModel) return;
	      const menu = Array.from(document.querySelectorAll("details.model-menu"))
	        .find((item) => item.dataset.profile === openReasoningProfile);
	      const option = menu
	        ? Array.from(menu.querySelectorAll(".model-option")).find((item) => item.dataset.model === openReasoningModel)
	        : null;
	      if (option) option.classList.add("reasoning-open");
	    }

	    function closeMenus(selector) {
	      document.querySelectorAll(`${selector}[open]`).forEach((menu) => {
	        menu.open = false;
	      });
	    }

	    function closeOpenMenus() {
	      openPinMenuProfile = null;
	      openModelMenuProfile = null;
	      openLoginMenuProfile = null;
	      openReasoningProfile = null;
	      openReasoningModel = null;
	      closeMenus("details.pin-menu");
	      closeMenus("details.model-menu");
	      closeMenus("details.login-menu");
	    }

	    function menuType(menu) {
	      if (menu.classList.contains("pin-menu")) return "pin";
	      if (menu.classList.contains("model-menu")) return "model";
	      if (menu.classList.contains("login-menu")) return "login";
	      return "";
	    }

	    function menuSelector(type) {
	      if (type === "pin") return "details.pin-menu";
	      if (type === "model") return "details.model-menu";
	      if (type === "login") return "details.login-menu";
	      return "";
	    }

	    function setOpenMenuProfile(type, profile) {
	      if (type === "pin") openPinMenuProfile = profile;
	      if (type === "model") openModelMenuProfile = profile;
	      if (type === "login") openLoginMenuProfile = profile;
	    }

	    function getOpenMenuProfile(type) {
	      if (type === "pin") return openPinMenuProfile;
	      if (type === "model") return openModelMenuProfile;
	      if (type === "login") return openLoginMenuProfile;
	      return null;
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
	        const billingRequired = profile.billing_required && typeof profile.billing_required === "object" && profile.billing_required.required;
	        if (!name || profile.quota_has_payload || profile.quota_refresh_error || billingRequired) continue;
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

		    function reasoningDisplay(value) {
		      return String(value || "");
		    }

		    function profileStateFromValue(value) {
		      if (!value) return null;
		      if (typeof value === "string") {
		        const raw = value.trim();
		        if (raw === "deactivated_workspace") {
		          return { code: raw, title: "Workspace deactivated", message: "This workspace is deactivated." };
		        }
		        if (raw.startsWith("{") && raw.endsWith("}")) {
		          try {
		            return profileStateFromValue(JSON.parse(raw));
		          } catch {
		            return null;
		          }
		        }
		        return null;
		      }
		      if (typeof value !== "object") return null;
		      const code = typeof value.code === "string" ? value.code : "";
		      if (code === "deactivated_workspace") {
		        return { code, title: "Workspace deactivated", message: "This workspace is deactivated." };
		      }
		      return profileStateFromValue(value.detail) || profileStateFromValue(value.error) || profileStateFromValue(value.message) || profileStateFromValue(value.reason);
		    }

		    function modelCatalog() {
	      return latestModelCatalog.length ? latestModelCatalog : [
	        { id: "gpt-5.5", display: "gpt-5.5", reasoning: ["low", "medium", "high", "xhigh"] },
	        { id: "gpt-5.4", display: "gpt-5.4", reasoning: ["low", "medium", "high", "xhigh"] },
	        { id: "gpt-5.4-mini", display: "gpt-5.4-mini", reasoning: ["low", "medium", "high", "xhigh"] },
	        { id: "gpt-5.3-codex", display: "gpt-5.3-codex", reasoning: ["low", "medium", "high", "xhigh"] },
	        { id: "gpt-5.2", display: "gpt-5.2", reasoning: ["low", "medium", "high", "xhigh"] }
	      ];
	    }

		    function renderProfileChips(profile, name) {
		      const chips = [];
		      if (profile.active) chips.push('<span class="badge active-badge">Active</span>');
			      const billingRequired = profile.billing_required && typeof profile.billing_required === "object" && profile.billing_required.required;
			      if (billingRequired) {
			        const detail = String(profile.billing_required.error || "This Codex CLI profile returned HTTP 402 Payment Required.");
			        const state = profileStateFromValue(profile.billing_required.error);
			        const title = state ? state.message : `Billing required: Provision has paused automatic quota refreshes for this profile. ${detail}`;
			        const label = state ? state.title : "Billing required";
			        chips.push(`<span class="profile-pill billing-pill" title="${escapeHtml(title)}">${escapeHtml(label)}</span>`);
			      }
		      const fastEnabled = Boolean(profile.fast_mode);
	      chips.push(`
	        <form method="post" action="/api/toggle-fast" class="profile-pill-form" data-action="toggle_fast" data-profile="${escapeHtml(name)}">
	          <input type="hidden" name="token" value="${escapeHtml(TOKEN)}">
	          <input type="hidden" name="profile" value="${escapeHtml(name)}">
	          <button class="profile-pill fast-pill${fastEnabled ? " enabled" : ""}" title="Toggle fast mode">Fast</button>
	        </form>
	      `);
	      const loginRequired = profile.login_required && typeof profile.login_required === "object" && profile.login_required.required;
	      const loginStatus = profile.login_status && typeof profile.login_status === "object" ? profile.login_status : null;
	      const loginState = loginStatus ? String(loginStatus.status || "") : "";
	      const loginRunning = loginState === "running" || loginState === "canceling";
	      if (loginRequired || loginRunning) {
	        const loginTitle = loginRunning ? "Login already running" : String((profile.login_required && profile.login_required.error) || "Refresh profile login");
	        const disabled = loginRunning ? "disabled" : "";
	        const cancelDisabled = loginState === "canceling" ? "disabled" : "";
	        const cancelForm = loginRunning ? `
	          <form method="post" action="/api/login" data-action="cancel_login" data-profile="${escapeHtml(name)}">
	            <input type="hidden" name="token" value="${escapeHtml(TOKEN)}">
	            <input type="hidden" name="profile" value="${escapeHtml(name)}">
	            <input type="hidden" name="login_action" value="cancel_login">
	            <button class="menu-action danger-action" ${cancelDisabled}>Cancel Login</button>
	          </form>
	        ` : "";
	        chips.push(`
	          <details class="login-menu profile-login-menu" data-profile="${escapeHtml(name)}">
	            <summary class="profile-pill login-pill" title="${escapeHtml(loginTitle)}">Login</summary>
	            <div class="login-menu-panel">
	              <div class="login-menu-note">${escapeHtml(LOGIN_BROWSER_REMOTE_NOTE)}</div>
	              <form method="post" action="/api/login" data-action="start_login" data-profile="${escapeHtml(name)}">
	                <input type="hidden" name="token" value="${escapeHtml(TOKEN)}">
	                <input type="hidden" name="profile" value="${escapeHtml(name)}">
	                <input type="hidden" name="mode" value="browser">
	                <button class="menu-action" ${disabled}>Browser Login</button>
	              </form>
	              <form method="post" action="/api/login" data-action="start_login" data-profile="${escapeHtml(name)}">
	                <input type="hidden" name="token" value="${escapeHtml(TOKEN)}">
	                <input type="hidden" name="profile" value="${escapeHtml(name)}">
	                <input type="hidden" name="mode" value="device">
	                <button class="menu-action" ${disabled}>Device Auth</button>
	              </form>
	              ${cancelForm}
	            </div>
	          </details>
	        `);
	      }
	      return `<div class="profile-chips">${chips.join("")}</div>`;
	    }

	    function renderModelMenu(profile, name) {
	      const setting = profile.model_setting && typeof profile.model_setting === "object" ? profile.model_setting : {};
	      const currentModel = String(setting.model || "gpt-5.5");
	      const currentReasoning = String(setting.reasoning_effort || "medium");
		      const label = `${currentModel.toLowerCase()} ${reasoningDisplay(currentReasoning)}`;
	      const items = modelCatalog().map((item) => {
	        const model = String(item.id || "");
	        if (!model) return "";
	        const display = String(item.display || model);
	        const note = String(item.note || "");
	        const selected = model === currentModel ? " selected" : "";
	        const levels = Array.isArray(item.reasoning) && item.reasoning.length ? item.reasoning : ["low", "medium", "high", "xhigh"];
	        const reasoning = levels.map((level) => {
	          const value = String(level || "");
	          if (!value) return "";
	          const reasoningSelected = model === currentModel && value === currentReasoning ? " selected" : "";
	          return `
	            <form method="post" action="/api/model" data-action="set_model" data-profile="${escapeHtml(name)}">
	              <input type="hidden" name="token" value="${escapeHtml(TOKEN)}">
	              <input type="hidden" name="profile" value="${escapeHtml(name)}">
	              <input type="hidden" name="model" value="${escapeHtml(model)}">
	              <input type="hidden" name="reasoning_effort" value="${escapeHtml(value)}">
	              <button class="model-reasoning-option${reasoningSelected}">${escapeHtml(reasoningDisplay(value))}</button>
	            </form>
	          `;
	        }).join("");
	        return `
	          <div class="model-option${selected}" data-model="${escapeHtml(model)}" title="${escapeHtml(note)}">
	            <button class="model-option-label" type="button">
	              <span>${escapeHtml(display)}</span>
	              <span class="model-option-arrow">&rsaquo;</span>
	            </button>
	            <div class="model-reasoning-menu">${reasoning}</div>
	          </div>
	        `;
	      }).join("");
	      return `
	        <details class="model-menu" data-profile="${escapeHtml(name)}">
	          <summary class="model-pill" title="Select model and reasoning effort">
	            <span>${escapeHtml(label)}</span>
	          </summary>
	          <div class="model-menu-panel">${items}</div>
	        </details>
	      `;
	    }

	    function profileRow(profile, pendingAction, pendingProfile) {
	      const name = String(profile.name || "");
	      const plan = String(profile.plan_type || "unknown");
	      const reason = String(profile.switch_disabled_reason || "");
	      const pending = pendingProfile === name ? pendingAction : "";
	      const disabled = reason || pending ? "disabled" : "";
	      const useTitle = reason || (pending ? "Action in progress" : "");
	      const useLabel = pending === "switch" ? "Switching" : String(profile.switch_button_label || "Use");
	      let useClass = profile.active ? "primary-action current-action" : "primary-action";
	      if (profile.active && profile.has_active_sessions) useClass += " session-active-action";
	      const quotaPendingLabel = pending === "consume_reset_credit" ? "Using reset credit" : "Refreshing quota";
	      const isQuotaPending = pending === "refresh_quota" || pending === "consume_reset_credit";
	      const quota = isQuotaPending
	        ? `<div class="quota-panel"><div class="quota-panel-head"><span class="quota-refresh-icon disabled" aria-hidden="true"><span class="spinner quota-spinner-small"></span></span><span class="quota-updated">${quotaPendingLabel}</span></div><div class="quota-loading"><span class="spinner"></span><span>${quotaPendingLabel}</span></div></div>`
	        : profile.quota_html || '<div class="quota-empty">No quota cached</div>';
	      const pinMenu = profile.pin_menu_html || "";
	      const pinnedSessions = profile.pinned_sessions_html || "";
	      const loginStatusHtml = profile.login_status_html || "";
	      const authHealthHtml = profile.auth_health_html || "";
	      return `
	        <tr class="profile-row${profile.active ? " active" : ""}" data-profile="${escapeHtml(name)}">
	          <td class="profile-cell">
	            <div class="profile-name">${escapeHtml(name)} <span class="profile-plan">(${escapeHtml(plan)})</span></div>
	            <div class="profile-email">${escapeHtml(profile.email || profile.account_id || "")}</div>
	            ${authHealthHtml}
	            ${renderProfileChips(profile, name)}
	            ${pinMenu}
	            ${pinnedSessions}
	            ${loginStatusHtml}
	          </td>
	          <td class="model-cell">${renderModelMenu(profile, name)}</td>
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
      latestStats = status.stats || latestStats || { profiles: [], recent: [] };
      if (Array.isArray(status.model_catalog)) latestModelCatalog = status.model_catalog;
	      if ((pendingAction === "refresh_quota" || pendingAction === "consume_reset_credit") && pendingProfile) {
	        quotaRefreshInFlight = pendingProfile;
	      } else if (quotaRefreshInFlight) {
	        quotaRefreshInFlight = "";
	        scheduleNextQuotaRefresh(250);
	      }
	      queueInitialQuotaRefreshes(status.profiles || []);
	      scheduleNextQuotaRefresh(250);
	      document.getElementById("activeProfile").textContent = status.active_profile || "none";
	      const codexCli = status.codex && status.codex.cli ? status.codex.cli : {};
	      document.getElementById("codexVersion").textContent = codexCli.version || "unknown";
	      document.getElementById("activeRequests").textContent = String(activeRequests);
	      document.getElementById("activeTunnels").textContent = String(activeTunnels);
	      const connection = document.getElementById("connectionState");
	      const isDisconnected = connection.textContent === "Disconnected";
	      if (!isDisconnected) {
	        connection.textContent = `Live (${liveBusy ? "busy" : "idle"})`;
	        document.getElementById("proxyDot").className = "dot" + (liveBusy ? " busy" : "");
	      }
	      rememberOpenMenus();
      document.getElementById("profileRows").innerHTML = (status.profiles || [])
        .map((profile) => profileRow(profile, pendingAction, pendingProfile))
        .join("");
	      restoreOpenMenus();
	      if (!document.getElementById("statsModal").hidden) {
	        renderStats(latestStats);
	      }
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
      const url = new URL("/api/ui-ws", window.location.href);
      url.protocol = location.protocol === "https:" ? "wss:" : "ws:";
      url.searchParams.set("token", TOKEN);
      socket = new WebSocket(url.toString());
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
	      const confirmMessage = form.dataset.confirm || "";
	      if (confirmMessage && !window.confirm(confirmMessage)) return;
	      if ((action === "refresh_quota" || action === "consume_reset_credit") && profile) {
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
	      if (!(menu instanceof HTMLDetailsElement)) return;
	      const type = menuType(menu);
	      if (!type) return;
	      const selector = menuSelector(type);
	      if (menu.open) {
	        setOpenMenuProfile(type, menu.dataset.profile || "");
	        document.querySelectorAll(`${selector}[open]`).forEach((other) => {
	          if (other !== menu) other.open = false;
	        });
	      } else if (getOpenMenuProfile(type) === (menu.dataset.profile || "")) {
	        setOpenMenuProfile(type, null);
	        if (type === "model") {
	          openReasoningProfile = null;
	          openReasoningModel = null;
	        }
	      }
	    }, true);

	    document.addEventListener("mouseover", (event) => {
	      const target = event.target;
	      if (!(target instanceof Element)) return;
	      const option = target.closest(".model-option");
	      if (!option) return;
	      const menu = option.closest("details.model-menu");
	      if (!menu || !menu.open) return;
	      openReasoningProfile = menu.dataset.profile || null;
	      openReasoningModel = option.dataset.model || null;
	      document.querySelectorAll(".model-option.reasoning-open").forEach((item) => {
	        if (item !== option) item.classList.remove("reasoning-open");
	      });
	      option.classList.add("reasoning-open");
	    });

	    document.addEventListener("focusin", (event) => {
	      const target = event.target;
	      if (!(target instanceof Element)) return;
	      const option = target.closest(".model-option");
	      if (!option) return;
	      const menu = option.closest("details.model-menu");
	      if (!menu || !menu.open) return;
	      openReasoningProfile = menu.dataset.profile || null;
	      openReasoningModel = option.dataset.model || null;
	      option.classList.add("reasoning-open");
	    });

	    document.addEventListener("click", (event) => {
	      const target = event.target;
	      if (
	        target instanceof Element
	        && target.closest("details.pin-menu, details.model-menu, details.login-menu")
	      ) return;
	      closeOpenMenus();
	    });

	    document.getElementById("statsToggle").addEventListener("click", () => {
	      const modal = document.getElementById("statsModal");
	      renderStats(latestStats);
	      modal.hidden = false;
	    });

	    document.getElementById("statsClose").addEventListener("click", () => {
	      document.getElementById("statsModal").hidden = true;
	    });

	    document.getElementById("statsModal").addEventListener("click", (event) => {
	      if (event.target === event.currentTarget) {
	        event.currentTarget.hidden = true;
	      }
	    });

	    document.getElementById("statsContent").addEventListener("change", (event) => {
	      const target = event.target;
	      if (!(target instanceof HTMLInputElement) || !target.classList.contains("stats-profile-check")) return;
	      statsVisibleProfiles[target.value] = target.checked;
	      renderStats(latestStats);
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

	    document.getElementById("statsToggle").innerHTML = CHART_ICON;
	    updateThemeToggle();
	    render(INITIAL);
	    connect();
  </script>
</body>
</html>
""".replace("__TOKEN__", token_json).replace(
            "__INITIAL_STATE__", initial_json
        ).replace(
            "__LOGIN_BROWSER_REMOTE_NOTE__", json.dumps(LOGIN_BROWSER_REMOTE_NOTE)
        ).replace(
            "__ACTIVE_PROFILE__", active_profile
        ).replace(
            "__CODEX_VERSION__", codex_version
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


def write_state(paths: Paths, host: str, port: int) -> None:
    data = {
        "pid": os.getpid(),
        "host": normalize_daemon_host(host),
        "port": port,
        "started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    paths.state.parent.mkdir(parents=True, exist_ok=True)
    temp = paths.state.with_suffix(".json.tmp")
    temp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    temp.chmod(0o600)
    temp.replace(paths.state)
    paths.state.chmod(0o600)


def serve(port: int | None = None, host: str | None = None) -> None:
    paths = Paths()
    paths.ensure_base()
    bind_host = normalize_daemon_host(host)
    requested_port = DEFAULT_DAEMON_PORT if port is None else port
    try:
        server = ProvisionServer((bind_host, requested_port), paths)
    except OSError:
        if port is not None or requested_port == 0:
            raise
        sys.stderr.write(
            f"default port {DEFAULT_DAEMON_PORT} unavailable; using a dynamic port\n"
        )
        server = ProvisionServer((bind_host, 0), paths)
    write_state(paths, bind_host, server.server_address[1])
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


def health(port: int, timeout: float = 1.0, host: str | None = None) -> dict[str, Any] | None:
    try:
        url = f"http://{daemon_url_host(host)}:{port}/health"
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception:
        return None


def can_connect(port: int, host: str | None = None) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex((daemon_connect_host(host), port)) == 0


def daemon_running(paths: Paths) -> dict[str, Any] | None:
    state = read_state(paths)
    if not state:
        return None
    port = state.get("port")
    if not isinstance(port, int):
        return None
    host = str(state.get("host") or DEFAULT_DAEMON_HOST)
    return health(port, host=host)


def wait_until_running(paths: Paths, deadline_seconds: float = 5.0) -> dict[str, Any]:
    deadline = time.time() + deadline_seconds
    while time.time() < deadline:
        status = daemon_running(paths)
        if status:
            return status
        time.sleep(0.1)
    raise RuntimeError(f"provision daemon did not start; see {paths.log}")
