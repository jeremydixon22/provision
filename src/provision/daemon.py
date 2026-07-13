from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import html
import importlib.resources as package_resources
import json
import os
import pty
import queue
import re
import signal
import shlex
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
from .paths import Paths, default_codex_home, launcher_path
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
DEFAULT_UPSTREAM_USER_AGENT = "OpenAI Codex CLI (Provision local proxy)"

PROTOCOL_VERSION = 28
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
RESET_CREDIT_CONFIRMATION_DELTA_PERCENT = 5.0
RESET_CREDIT_VERIFY_INITIAL_DELAY_SECONDS = 8.0
RESET_CREDIT_VERIFY_INTERVAL_SECONDS = 20.0
RESET_CREDIT_VERIFY_TIMEOUT_SECONDS = 600.0
RESET_CREDIT_ERROR_GUARD_SECONDS = 3600.0
RESET_CREDIT_COOLDOWN_SECONDS = 86400.0
WEBSOCKET_SWITCH_IDLE_SECONDS = 10.0
WEBSOCKET_COMPLETION_FALLBACK_SECONDS = 180.0
WEBSOCKET_TOOL_COMPLETION_FALLBACK_SECONDS = 600.0
UI_STATE_CHECK_SECONDS = 1.0
UI_HEARTBEAT_SECONDS = 15.0
UI_SAFETY_SNAPSHOT_SECONDS = 60.0
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
    "collab_agent_tool_call",
    "computer_call",
    "command_execution",
    "custom_tool_call",
    "dynamic_tool_call",
    "file_search_call",
    "function_call",
    "function_call_output",
    "hook_prompt",
    "image_generation_call",
    "local_shell_call",
    "mcp_call",
    "program",
    "program_output",
    "shell_call",
    "sub_agent_activity",
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
CONTROL_PLANE_EVENT_LIMIT = 240
CONTROL_PLANE_SESSION_EVENT_LIMIT = 32
CONTROL_TRANSCRIPT_MAX_ITEMS = 600
CONTROL_TRANSCRIPT_TEXT_LIMIT = 12000
CONTROL_TRANSCRIPT_EVENT_TEXT_LIMIT = 4000
CONTROL_CONTEXT_WINDOW_TOKENS = 256000
UI_DIRTY_LOG_LIMIT = 512
CONTROL_HISTORY_CACHE_SECONDS = 5.0
CONTROL_HISTORY_TURN_SEARCH_TEXT_LIMIT = 1600
CONTROL_HISTORY_SESSION_LIMIT = 24
CONTROL_HISTORY_TURN_LIMIT = 120
RESUME_CANDIDATE_LIMIT = 12
RESUME_CANDIDATE_SCAN_LIMIT = 800
RESUME_CANDIDATE_CACHE_SECONDS = 10.0
APP_SERVER_MODEL_CATALOG_CACHE_SECONDS = 300.0
APP_SERVER_MODEL_CATALOG_ERROR_BACKOFF_SECONDS = 60.0
CODEX_RUNTIME_VERSION_RECHECK_SECONDS = 60.0
UI_LAUNCHER_PERMISSION_PRESETS = {
    "read-only": ("--sandbox", "read-only", "--ask-for-approval", "on-request"),
    "workspace-write": ("--sandbox", "workspace-write", "--ask-for-approval", "on-request"),
    "full-access": ("--sandbox", "danger-full-access", "--ask-for-approval", "on-request"),
    "bypass": ("--dangerously-bypass-approvals-and-sandbox",),
}
CODEX_HISTORY_BRIDGE_NAMES = (
    "sessions",
    "archived_sessions",
    "shell_snapshots",
    "history.jsonl",
    "state_5.sqlite",
    "state_5.sqlite-shm",
    "state_5.sqlite-wal",
    "goals_1.sqlite",
    "goals_1.sqlite-shm",
    "goals_1.sqlite-wal",
    "logs_2.sqlite",
    "logs_2.sqlite-shm",
    "logs_2.sqlite-wal",
    "memories_1.sqlite",
    "memories_1.sqlite-shm",
    "memories_1.sqlite-wal",
    "memories",
    "rules",
    "skills",
    "plugins",
    "cache",
    "import-state",
    "generated_images",
    "models_cache.json",
    "installation_id",
    "version.json",
    ".personality_migration",
)
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\a]*(?:\a|\x1b\\)")
ENVIRONMENT_CONTEXT_RE = re.compile(r"\s*<environment_context>.*?</environment_context>\s*", re.DOTALL)
CODEX_GOAL_CONTEXT_RE = re.compile(
    r"<codex_internal_context\b(?=[^>]*\bsource\s*=\s*[\"']goal[\"'])[^>]*>.*?</codex_internal_context>",
    re.IGNORECASE | re.DOTALL,
)
CODEX_GOAL_OBJECTIVE_RE = re.compile(r"<objective>\s*(.*?)\s*</objective>", re.IGNORECASE | re.DOTALL)
CONTROL_TRANSCRIPT_EDGE_RE = re.compile(r"^[\s\ufeff\u200b\u200c\u200d]+|[\s\ufeff\u200b\u200c\u200d]+$")
USER_SHELL_COMMAND_RE = re.compile(
    r"<user_shell_command\b[^>]*>(?P<body>.*?)</user_shell_command\s*>",
    re.IGNORECASE | re.DOTALL,
)
USER_SHELL_COMMAND_COMMAND_RE = re.compile(
    r"<command\b[^>]*>\s*(?P<command>.*?)\s*</command\s*>",
    re.IGNORECASE | re.DOTALL,
)
USER_SHELL_COMMAND_RESULT_RE = re.compile(
    r"<result\b[^>]*>\s*(?P<result>.*?)\s*</result\s*>",
    re.IGNORECASE | re.DOTALL,
)
USER_SHELL_RESULT_EXIT_CODE_RE = re.compile(r"^\s*Exit code:\s*(?P<value>.+?)\s*$", re.IGNORECASE | re.MULTILINE)
USER_SHELL_RESULT_DURATION_RE = re.compile(r"^\s*Duration:\s*(?P<value>.+?)\s*$", re.IGNORECASE | re.MULTILINE)
USER_SHELL_RESULT_OUTPUT_RE = re.compile(
    r"^\s*Output:\s*(?P<value>.*)$",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)
LOGIN_URL_RE = re.compile(r"https?://[^\s<>]+")
DEVICE_CODE_RE = re.compile(r"\b[A-Z0-9]{4,}(?:-[A-Z0-9]{4,})+\b")
CONTROL_TOOL_CALL_RE = re.compile(r"^ctc_[a-f0-9]{16,}$", re.IGNORECASE)
WEB_SEARCH_TOOL_CALL_RE = re.compile(r"^ws_[A-Za-z0-9_-]+$", re.IGNORECASE)
PROGRAMMATIC_TOOL_INVOCATION_RE = re.compile(r"\btools\.([A-Za-z_][A-Za-z0-9_.]*)\s*\(")
PROGRAMMATIC_TOOL_COMMAND_RE = re.compile(r"[\"']cmd[\"']\s*:\s*(\"(?:\\.|[^\"\\])*\")", re.DOTALL)
PROGRAMMATIC_TOOL_PATCH_RE = re.compile(
    r"\b(?:const|let|var)\s+patch\s*=\s*(\"(?:\\.|[^\"\\])*\")",
    re.DOTALL,
)
PROGRAMMATIC_TOOL_PLAN_STEP_RE = re.compile(
    r"(?:[\"']step[\"']|\bstep)\s*:\s*(\"(?:\\.|[^\"\\])*\")\s*,\s*"
    r"(?:[\"']status[\"']|\bstatus)\s*:\s*(\"(?:\\.|[^\"\\])*\")",
    re.DOTALL,
)
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
PROFILE_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")
REASONING_LEVEL_PATTERN = re.compile(r"^[a-z0-9_-]{1,32}$")
REASONING_LEVELS = ("none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra")
GPT_56_REASONING_LEVELS = ("low", "medium", "high", "xhigh", "max", "ultra")
GPT_56_LUNA_REASONING_LEVELS = ("low", "medium", "high", "xhigh", "max")
LEGACY_REASONING_LEVELS = ("low", "medium", "high", "xhigh")
DEFAULT_MODEL_ID = "gpt-5.6-sol"
DEFAULT_REASONING_EFFORT = "medium"
CODEX_MODEL_CATALOG_TIMEOUT_SECONDS = 2.0
CODEX_VERSION_TIMEOUT_SECONDS = 2.0
CODEX_APP_SERVER_SCHEMA_TIMEOUT_SECONDS = 10.0
CODEX_APP_SERVER_REQUEST_TIMEOUT_SECONDS = 10.0
CODEX_APP_SERVER_TURN_TIMEOUT_SECONDS = 3600.0
APP_SERVER_RATE_LIMIT_CACHE_SECONDS = 300.0
APP_SERVER_RATE_LIMIT_FAILURE_BACKOFF_SECONDS = 900.0
DEFAULT_MODEL_CATALOG = [
    {
        "id": "gpt-5.6-sol",
        "display": "GPT-5.6-Sol",
        "reasoning": list(GPT_56_REASONING_LEVELS),
        "default_reasoning": "low",
        "note": "Latest frontier agentic coding model. Requires Codex CLI 0.144.0 or newer.",
        "minimal_client_version": "0.144.0",
        "service_tiers": [
            {"id": "priority", "name": "Fast", "description": "1.5x speed, increased usage"},
        ],
        "additional_speed_tiers": ["fast"],
    },
    {
        "id": "gpt-5.6-terra",
        "display": "GPT-5.6-Terra",
        "reasoning": list(GPT_56_REASONING_LEVELS),
        "default_reasoning": "medium",
        "note": "Balanced agentic coding model for everyday work. Requires Codex CLI 0.144.0 or newer.",
        "minimal_client_version": "0.144.0",
        "service_tiers": [
            {"id": "priority", "name": "Fast", "description": "1.5x speed, increased usage"},
        ],
        "additional_speed_tiers": ["fast"],
    },
    {
        "id": "gpt-5.6-luna",
        "display": "GPT-5.6-Luna",
        "reasoning": list(GPT_56_LUNA_REASONING_LEVELS),
        "default_reasoning": "medium",
        "note": "Fast and affordable agentic coding model. Requires Codex CLI 0.144.0 or newer.",
        "minimal_client_version": "0.144.0",
        "service_tiers": [
            {"id": "priority", "name": "Fast", "description": "1.5x speed, increased usage"},
        ],
        "additional_speed_tiers": ["fast"],
    },
    {
        "id": "gpt-5.5",
        "display": "GPT-5.5",
        "reasoning": list(LEGACY_REASONING_LEVELS),
        "default_reasoning": "medium",
        "note": "Frontier model for complex coding, research, and real-world work.",
        "minimal_client_version": "0.124.0",
        "service_tiers": [
            {"id": "priority", "name": "Fast", "description": "1.5x speed, increased usage"},
        ],
        "additional_speed_tiers": ["fast"],
    },
    {
        "id": "gpt-5.4",
        "display": "GPT-5.4",
        "reasoning": list(LEGACY_REASONING_LEVELS),
        "default_reasoning": "medium",
        "note": "Strong model for everyday coding.",
        "minimal_client_version": "0.98.0",
        "service_tiers": [
            {"id": "priority", "name": "Fast", "description": "1.5x speed, increased usage"},
        ],
        "additional_speed_tiers": ["fast"],
    },
    {
        "id": "gpt-5.4-mini",
        "display": "GPT-5.4-Mini",
        "reasoning": list(LEGACY_REASONING_LEVELS),
        "default_reasoning": "medium",
        "note": "Small, fast, and cost-efficient model for simpler coding tasks.",
        "minimal_client_version": "0.98.0",
    },
    {
        "id": "gpt-5.2",
        "display": "GPT-5.2",
        "reasoning": list(LEGACY_REASONING_LEVELS),
        "default_reasoning": "medium",
        "note": "Optimized for professional work and long-running agents.",
        "minimal_client_version": "0.0.1",
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


class ResetCreditGuardError(StoreError):
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


def ensure_default_upstream_user_agent(headers: dict[str, str]) -> dict[str, str]:
    if not any(key.lower() == "user-agent" for key in headers):
        headers["User-Agent"] = DEFAULT_UPSTREAM_USER_AGENT
    return headers


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
        raw_levels = value.get("supported_reasoning_efforts")
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
                    or raw_level.get("id")
                    or raw_level.get("name")
                )
            level = normalize_reasoning_level(effort)
            if level and level not in reasoning:
                reasoning.append(level)
    if not reasoning:
        reasoning = list(REASONING_LEVELS)

    default_reasoning = (
        value.get("default_reasoning_level")
        or value.get("default_reasoning_effort")
        or value.get("defaultReasoningEffort")
        or value.get("defaultReasoningLevel")
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
        "minimal_client_version": first_string_value(value, ("minimal_client_version", "minimalClientVersion")),
        "priority": value.get("priority") if isinstance(value.get("priority"), int) else None,
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


def codex_cli_version_probe() -> dict[str, Any]:
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
def codex_cli_version() -> dict[str, Any]:
    return codex_cli_version_probe()


_codex_runtime_version_lock = threading.Lock()
_codex_runtime_version_cache: tuple[float, dict[str, Any]] | None = None


def codex_runtime_version() -> dict[str, Any]:
    global _codex_runtime_version_cache
    now = time.monotonic()
    with _codex_runtime_version_lock:
        cached = _codex_runtime_version_cache
        if cached and now - cached[0] < CODEX_RUNTIME_VERSION_RECHECK_SECONDS:
            return dict(cached[1])
    value = codex_cli_version_probe()
    with _codex_runtime_version_lock:
        _codex_runtime_version_cache = (now, dict(value))
    return value


def codex_restart_requirement(
    startup: dict[str, Any],
    runtime: dict[str, Any],
) -> dict[str, Any]:
    startup_version = startup.get("version") if isinstance(startup.get("version"), str) else None
    runtime_version = runtime.get("version") if isinstance(runtime.get("version"), str) else None
    required = bool(startup_version and runtime_version and startup_version != runtime_version)
    return {
        "required": required,
        "startup_version": startup_version,
        "runtime_version": runtime_version,
        "reason": "Codex CLI changed after this Provision daemon started; restart Provision when active work is idle."
        if required
        else "",
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
        "interactive_api": not interactive_missing,
        "interactive": not interactive_missing,
        "provision_interaction": "pty",
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
                    "version": str(PROTOCOL_VERSION),
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

    def read_message(self, timeout: float) -> dict[str, Any] | None:
        try:
            message = self._messages.get(timeout=timeout)
        except queue.Empty:
            return None
        if message is None:
            raise CodexAppServerError("codex app-server exited")
        return message

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

    def list_threads(self, *, limit: int = 25) -> Any:
        params: dict[str, Any] = {
            "limit": limit,
            "sortKey": "updated_at",
        }
        return self.request("thread/list", params)

    def list_models(self) -> Any:
        return self.request("model/list", {})

    def start_turn(
        self,
        *,
        thread_id: str,
        text: str,
        cwd: str | None = None,
        model: str | None = None,
        effort: str | None = None,
        service_tier: str | None = None,
    ) -> Any:
        params: dict[str, Any] = {
            "threadId": thread_id,
            "input": [{"type": "text", "text": text}],
        }
        if cwd:
            params["cwd"] = cwd
        if model:
            params["model"] = model
        if effort:
            params["effort"] = effort
        if service_tier:
            params["serviceTier"] = service_tier
        return self.request("turn/start", params)

    def resume_thread(self, *, thread_id: str, cwd: str | None = None) -> Any:
        params: dict[str, Any] = {"threadId": thread_id}
        if cwd:
            params["cwd"] = cwd
        return self.request("thread/resume", params)

    def fork_thread(self, *, thread_id: str, cwd: str | None = None) -> Any:
        params: dict[str, Any] = {"threadId": thread_id}
        if cwd:
            params["cwd"] = cwd
        return self.request("thread/fork", params)


def thread_id_from_app_server_value(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    for key in ("id", "threadId", "thread_id"):
        thread_id = value.get(key)
        if isinstance(thread_id, str) and thread_id:
            return thread_id
    thread = value.get("thread")
    if isinstance(thread, dict):
        return thread_id_from_app_server_value(thread)
    return None


def turn_id_from_app_server_value(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    for key in ("id", "turnId", "turn_id"):
        turn_id = value.get(key)
        if isinstance(turn_id, str) and turn_id:
            return turn_id
    turn = value.get("turn")
    if isinstance(turn, dict):
        return turn_id_from_app_server_value(turn)
    return None


def app_server_thread_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if not isinstance(value, dict):
        return []
    for key in ("threads", "items", "data", "results"):
        rows = value.get(key)
        if isinstance(rows, list):
            return [item for item in rows if isinstance(item, dict)]
    thread = value.get("thread")
    if isinstance(thread, dict):
        return [thread]
    return []


def normalized_path_text(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return ""
    try:
        return str(Path(value).expanduser().resolve(strict=False))
    except OSError:
        return os.path.normpath(os.path.expanduser(value))


def app_server_thread_row_matches_cwd(row: dict[str, Any], cwd: str) -> bool:
    row_cwd = normalized_path_text(row.get("cwd"))
    target_cwd = normalized_path_text(cwd)
    return bool(row_cwd and target_cwd and row_cwd == target_cwd)


def app_server_thread_row_is_cli(row: dict[str, Any]) -> bool:
    source = row.get("source")
    if not source:
        return True
    if isinstance(source, str):
        return source.lower() == "cli"
    if isinstance(source, dict):
        for key in ("type", "kind", "source"):
            value = source.get(key)
            if isinstance(value, str):
                return value.lower() == "cli"
    return True


def first_app_server_thread_id(value: Any, *, cwd: str | None = None) -> str | None:
    rows = app_server_thread_rows(value)
    if cwd:
        for row in rows:
            if app_server_thread_row_is_cli(row) and app_server_thread_row_matches_cwd(row, cwd):
                thread_id = thread_id_from_app_server_value(row)
                if thread_id:
                    return thread_id
        return None
    for row in rows:
        if not app_server_thread_row_is_cli(row):
            continue
        thread_id = thread_id_from_app_server_value(row)
        if thread_id:
            return thread_id
    return thread_id_from_app_server_value(value)


def bridge_codex_history_into_app_home(codex_home: Path, source_home: Path | None = None) -> None:
    source = (source_home or default_codex_home()).expanduser()
    if not source.exists() or source.resolve() == codex_home.resolve():
        return
    for name in CODEX_HISTORY_BRIDGE_NAMES:
        source_path = source / name
        target_path = codex_home / name
        if not source_path.exists() or target_path.exists():
            continue
        try:
            target_path.symlink_to(source_path, target_is_directory=source_path.is_dir())
        except OSError:
            try:
                if source_path.is_dir():
                    shutil.copytree(source_path, target_path, symlinks=True)
                else:
                    shutil.copy2(source_path, target_path)
            except OSError:
                continue


RESUME_CANDIDATE_INSTRUCTION_PREFIXES = (
    "# agents.md instructions",
    "agents.md instructions",
    "# project instructions",
    "project instructions",
)


def resume_candidate_text_is_useful(text: str) -> bool:
    identity = transcript_identity_text(text).lower()
    if not identity:
        return False
    return not any(
        identity.startswith(prefix)
        for prefix in RESUME_CANDIDATE_INSTRUCTION_PREFIXES
    )


def resume_candidate_label_from_text(text: str) -> str:
    entries = user_transcript_entries(text)
    for role in ("user", "resume"):
        for entry in entries:
            candidate = str(entry.get("text") or "")
            if entry.get("role") == role and resume_candidate_text_is_useful(candidate):
                return candidate
    cleaned = clean_transcript_text(ENVIRONMENT_CONTEXT_RE.sub("\n", text))
    return cleaned if resume_candidate_text_is_useful(cleaned) else ""


def observed_turn_label_from_text(text: str) -> str:
    label = resume_candidate_label_from_text(text)
    if not label:
        label = clean_transcript_text(text)
    return label[:160]


def first_user_text_from_session_file(path: Path, *, max_lines: int = 240) -> str:
    try:
        with path.open("r", encoding="utf-8") as handle:
            for index, line in enumerate(handle):
                if index >= max_lines:
                    break
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict):
                    continue
                payload = row.get("payload")
                if not isinstance(payload, dict) or str(payload.get("role") or "") != "user":
                    continue
                content = payload.get("content")
                if isinstance(content, str):
                    text = content
                elif isinstance(content, list):
                    parts = []
                    for item in content:
                        if isinstance(item, dict):
                            value = item.get("text")
                            if isinstance(value, str):
                                parts.append(value)
                    text = "\n".join(parts)
                else:
                    text = ""
                text = resume_candidate_label_from_text(text)
                if text:
                    return text[:160]
    except OSError:
        return ""
    return ""


def codex_session_meta_from_file(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            first = handle.readline()
    except OSError:
        return None
    try:
        row = json.loads(first)
    except json.JSONDecodeError:
        return None
    if not isinstance(row, dict) or row.get("type") != "session_meta":
        return None
    payload = row.get("payload")
    return payload if isinstance(payload, dict) else None


def codex_session_files_for_cwd(
    cwd: str,
    *,
    codex_home: Path | None = None,
    scan_limit: int = RESUME_CANDIDATE_SCAN_LIMIT,
    include_archived: bool = False,
) -> list[tuple[Path, dict[str, Any]]]:
    target = normalized_path_text(cwd)
    if not target:
        return []
    home = (codex_home or default_codex_home()).expanduser()
    roots = [home / "sessions"]
    if include_archived:
        roots.append(home / "archived_sessions")
    try:
        files = sorted(
            (
                path
                for root in roots
                if root.exists()
                for path in root.rglob("rollout-*.jsonl")
                if path.is_file()
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return []
    matches: list[tuple[Path, dict[str, Any]]] = []
    for path in files[:scan_limit]:
        meta = codex_session_meta_from_file(path)
        if not meta:
            continue
        session_cwd = str(meta.get("cwd") or "")
        if normalized_path_text(session_cwd) != target:
            continue
        matches.append((path, meta))
    return matches


def codex_resume_candidates_for_cwd(
    cwd: str,
    *,
    codex_home: Path | None = None,
    limit: int = RESUME_CANDIDATE_LIMIT,
) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    for path, meta in codex_session_files_for_cwd(cwd, codex_home=codex_home):
        session_cwd = str(meta.get("cwd") or "")
        session_id = str(meta.get("id") or "")
        if not session_id:
            continue
        title = first_user_text_from_session_file(path)
        if not title:
            title = path.stem.replace("rollout-", "")
        candidates.append(
            {
                "id": session_id,
                "cwd": session_cwd,
                "timestamp": str(meta.get("timestamp") or ""),
                "label": title,
            }
        )
        if len(candidates) >= limit:
            break
    return candidates


def codex_history_user_text_is_prompt(text: str) -> bool:
    cleaned = transcript_identity_text(ENVIRONMENT_CONTEXT_RE.sub("\n", text)).lower()
    if not cleaned:
        return False
    if cleaned.startswith("<user_instructions>"):
        return False
    return resume_candidate_text_is_useful(text)


def codex_history_summary_text(value: Any) -> str:
    if isinstance(value, str):
        return clean_transcript_text(value)
    if isinstance(value, list):
        pieces = []
        for item in value:
            if isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    pieces.append(text)
                elif isinstance(item.get("summary_text"), str):
                    pieces.append(str(item["summary_text"]))
            elif isinstance(item, str):
                pieces.append(item)
        return clean_transcript_text("\n".join(pieces))
    return ""


def codex_history_source_turn_id(payload: dict[str, Any]) -> str:
    direct = payload.get("turn_id") or payload.get("turnId")
    if isinstance(direct, str) and direct:
        return direct
    metadata = payload.get("internal_chat_message_metadata_passthrough")
    if not isinstance(metadata, dict):
        metadata = payload.get("internalChatMessageMetadataPassthrough")
    if not isinstance(metadata, dict):
        return ""
    turn_id = metadata.get("turn_id") or metadata.get("turnId")
    return turn_id if isinstance(turn_id, str) else ""


def codex_history_entry(
    role: str,
    text: str,
    timestamp: str,
    *,
    turn_id: str = "",
    call_id: str = "",
) -> dict[str, Any]:
    entry: dict[str, Any] = {"role": role, "text": text, "ts": timestamp}
    if turn_id:
        entry["turn_id"] = turn_id
    if call_id:
        entry["call_id"] = call_id
    return entry


def codex_history_entries_from_response_item(payload: dict[str, Any], timestamp: str) -> list[dict[str, Any]]:
    item_type = str(payload.get("type") or "")
    source_turn_id = codex_history_source_turn_id(payload)
    if item_type == "message":
        role = str(payload.get("role") or "")
        text = transcript_text_from_content(payload.get("content"), preserve_edges=role != "user")
        if not text:
            return []
        if role == "user":
            return [
                codex_history_entry(
                    str(entry.get("role") or "user"),
                    str(entry.get("text") or ""),
                    timestamp,
                    turn_id=source_turn_id,
                )
                for entry in user_transcript_entries(text)
                if entry.get("text")
            ]
        if role == "assistant":
            return [codex_history_entry("assistant", text, timestamp, turn_id=source_turn_id)]
        return []
    if item_type == "reasoning":
        text = codex_history_summary_text(payload.get("summary") or payload.get("content"))
        return [
            codex_history_entry("assistant_progress", text, timestamp, turn_id=source_turn_id)
        ] if text else []
    tool_entry = tool_activity_entry_from_value(payload)
    if tool_entry:
        return [
            codex_history_entry(
                "tool",
                str(tool_entry.get("text") or ""),
                timestamp,
                turn_id=source_turn_id,
                call_id=str(tool_entry.get("call_id") or ""),
            )
        ]
    return []


def codex_history_entries_from_event_msg(payload: dict[str, Any], timestamp: str) -> list[dict[str, Any]]:
    event_type = str(payload.get("type") or "")
    source_turn_id = codex_history_source_turn_id(payload)
    if event_type == "agent_reasoning":
        text = clean_transcript_text(str(payload.get("text") or ""))
        return [
            codex_history_entry("assistant_progress", text, timestamp, turn_id=source_turn_id)
        ] if text else []
    if event_type in {"agent_message", "assistant_message"}:
        text = clean_transcript_text(str(payload.get("message") or payload.get("text") or ""))
        return [codex_history_entry("assistant", text, timestamp, turn_id=source_turn_id)] if text else []
    return []


def codex_history_entries_from_session_row(row: dict[str, Any]) -> list[dict[str, Any]]:
    timestamp = str(row.get("timestamp") or "")
    payload = row.get("payload")
    if not isinstance(payload, dict):
        return []
    row_type = str(row.get("type") or "")
    if row_type == "response_item":
        return codex_history_entries_from_response_item(payload, timestamp)
    if row_type == "event_msg":
        return codex_history_entries_from_event_msg(payload, timestamp)
    return []


def codex_history_display_text(text: str) -> tuple[str, bool]:
    cleaned = clean_transcript_text(text, preserve_edges=True)
    if len(cleaned) <= CONTROL_TRANSCRIPT_TEXT_LIMIT:
        return cleaned, False
    return cleaned[:CONTROL_TRANSCRIPT_TEXT_LIMIT].rstrip() + "\n...[truncated]", True


def codex_history_transcript_item(
    entry: dict[str, Any],
    *,
    turn_key: str,
    profile: str = "",
) -> dict[str, Any]:
    text = str(entry.get("text") or "")
    display, truncated = codex_history_display_text(text)
    item = {
        "role": str(entry.get("role") or "message"),
        "text": display,
        "full_text": text,
        "truncated": truncated,
        "ts": str(entry.get("ts") or ""),
        "updated_at": str(entry.get("ts") or ""),
        "turn_id": turn_key,
        "profile": profile,
        "source": "history",
    }
    call_id = entry.get("call_id")
    if isinstance(call_id, str) and call_id:
        item["call_id"] = call_id
    return item


def codex_history_turns_from_session_file(path: Path) -> list[dict[str, Any]]:
    meta = codex_session_meta_from_file(path)
    if not meta:
        return []
    session_id = str(meta.get("id") or path.stem.replace("rollout-", ""))
    session_timestamp = str(meta.get("timestamp") or "")
    turns: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    pending_context: list[dict[str, Any]] = []

    def finish_current() -> None:
        nonlocal current
        if current is None:
            return
        transcript = current.get("transcript")
        if isinstance(transcript, list):
            for index, item in enumerate(transcript):
                item["control_index"] = index
            current["search_text"] = transcript_identity_text(
                " ".join(str(item.get("full_text") or item.get("text") or "") for item in transcript)
            )[:CONTROL_HISTORY_TURN_SEARCH_TEXT_LIMIT]
            current["end_index"] = max(0, len(transcript) - 1)
        turns.append(current)
        current = None

    try:
        with path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                try:
                    row = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict):
                    continue
                for entry in codex_history_entries_from_session_row(row):
                    role = str(entry.get("role") or "")
                    text = str(entry.get("text") or "")
                    if role == "resume":
                        if current is None:
                            pending_context.append(entry)
                        else:
                            current["transcript"].append(
                                codex_history_transcript_item(entry, turn_key=str(current["key"]))
                            )
                        continue
                    if role == "user":
                        if not codex_history_user_text_is_prompt(text):
                            pending_context = []
                            continue
                        finish_current()
                        turn_index = len(turns)
                        turn_key = f"history:{session_id}:{turn_index}"
                        source_turn_id = str(entry.get("turn_id") or "")
                        label = observed_turn_label_from_text(text) or f"Turn {turn_index + 1}"
                        current = {
                            "key": turn_key,
                            "turn_id": source_turn_id or turn_key,
                            "source": "history",
                            "session_id": session_id,
                            "session_timestamp": session_timestamp,
                            "session_file": path.name,
                            "pending": False,
                            "start_index": 0,
                            "end_index": 0,
                            "timestamp": str(entry.get("ts") or session_timestamp),
                            "updated_at": str(entry.get("ts") or session_timestamp),
                            "label": label,
                            "transcript": [],
                        }
                        for context_entry in pending_context:
                            current["transcript"].append(
                                codex_history_transcript_item(
                                    context_entry,
                                    turn_key=turn_key,
                                )
                            )
                        pending_context = []
                        current["transcript"].append(codex_history_transcript_item(entry, turn_key=turn_key))
                        continue
                    if current is None:
                        continue
                    current["transcript"].append(
                        codex_history_transcript_item(entry, turn_key=str(current["key"]))
                    )
                    if entry.get("ts"):
                        current["updated_at"] = str(entry.get("ts") or "")
    except OSError:
        return []
    finish_current()
    return turns


def codex_history_turn_metadata(turn: dict[str, Any]) -> dict[str, Any]:
    return {
        "key": str(turn.get("key") or ""),
        "turn_id": str(turn.get("turn_id") or turn.get("key") or ""),
        "source": "history",
        "session_id": str(turn.get("session_id") or ""),
        "session_timestamp": str(turn.get("session_timestamp") or ""),
        "session_file": str(turn.get("session_file") or ""),
        "archived": bool(turn.get("archived")),
        "pending": False,
        "start_index": 0,
        "end_index": max(0, int(turn.get("end_index") or 0)),
        "timestamp": str(turn.get("timestamp") or ""),
        "updated_at": str(turn.get("updated_at") or ""),
        "label": str(turn.get("label") or "Historical turn"),
        "search_text": str(turn.get("search_text") or ""),
        "loaded": False,
    }


def control_turn_timestamp(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def history_turn_duplicates_observed(history_turn: dict[str, Any], observed_turn: dict[str, Any]) -> bool:
    history_id = str(history_turn.get("turn_id") or "")
    observed_id = str(observed_turn.get("turn_id") or "")
    if history_id and observed_id and not history_id.startswith("history:"):
        return history_id == observed_id
    history_label = transcript_identity_text(str(history_turn.get("label") or "")).lower()
    observed_label = transcript_identity_text(str(observed_turn.get("label") or "")).lower()
    if not history_label or history_label != observed_label:
        return False
    history_timestamp = control_turn_timestamp(history_turn.get("timestamp"))
    observed_timestamp = control_turn_timestamp(observed_turn.get("timestamp"))
    return (
        history_timestamp is not None
        and observed_timestamp is not None
        and abs(history_timestamp - observed_timestamp) <= 15
    )


def codex_history_turn_index_for_cwd(
    cwd: str,
    *,
    codex_home: Path | None = None,
) -> list[dict[str, Any]]:
    home = (codex_home or default_codex_home()).expanduser()
    files = codex_session_files_for_cwd(
        cwd,
        codex_home=home,
        include_archived=True,
    )
    turns: list[dict[str, Any]] = []
    archived_root = home / "archived_sessions"
    for path, _meta in files[:CONTROL_HISTORY_SESSION_LIMIT]:
        try:
            archived = path.is_relative_to(archived_root)
        except ValueError:
            archived = False
        for turn in codex_history_turns_from_session_file(path):
            turn["archived"] = archived
            turns.append(turn)
    turns.sort(
        key=lambda turn: (
            str(turn.get("timestamp") or turn.get("session_timestamp") or ""),
            str(turn.get("updated_at") or ""),
            str(turn.get("key") or ""),
        )
    )
    if len(turns) > CONTROL_HISTORY_TURN_LIMIT:
        turns = turns[-CONTROL_HISTORY_TURN_LIMIT:]
    return [codex_history_turn_metadata(turn) for turn in turns]


def codex_history_turn_payload_for_cwd(
    cwd: str,
    turn_key: str,
    *,
    codex_home: Path | None = None,
) -> dict[str, Any] | None:
    if not turn_key:
        return None
    home = (codex_home or default_codex_home()).expanduser()
    for path, _meta in codex_session_files_for_cwd(
        cwd,
        codex_home=home,
        include_archived=True,
    )[:CONTROL_HISTORY_SESSION_LIMIT]:
        try:
            archived = path.is_relative_to(home / "archived_sessions")
        except ValueError:
            archived = False
        for turn in codex_history_turns_from_session_file(path):
            if str(turn.get("key") or "") != turn_key:
                continue
            turn["archived"] = archived
            metadata = codex_history_turn_metadata(turn)
            metadata["loaded"] = True
            transcript = [dict(item) for item in turn.get("transcript") or [] if isinstance(item, dict)]
            for index, item in enumerate(transcript):
                item["control_index"] = index
            return {
                "turn": metadata,
                "transcript": transcript,
                "source": "history",
            }
    return None


def codex_compatibility_payload() -> dict[str, Any]:
    catalog = codex_model_catalog_probe()
    startup_cli = codex_cli_version()
    runtime_cli = codex_runtime_version()
    return {
        "cli": startup_cli,
        "runtime_cli": runtime_cli,
        "restart_required": codex_restart_requirement(startup_cli, runtime_cli),
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


def default_model_from_catalog() -> str:
    for item in load_codex_model_catalog():
        if not isinstance(item, dict):
            continue
        model = sanitize_model_id(item.get("id"))
        if model:
            return model
    return DEFAULT_MODEL_ID


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
        cleaned = []
        for level in levels:
            effort = normalize_reasoning_level(level)
            if effort and effort not in cleaned:
                cleaned.append(effort)
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
        model = default_model_from_catalog()
        return model, default_reasoning_for_model(model)
    model = sanitize_model_id(config.get("model")) or default_model_from_catalog()
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


def project_session_sentinel(
    proxy_token: str,
    cwd: str,
    *,
    session_key: str | None = None,
) -> str:
    payload_value = {"cwd": cwd}
    if session_key:
        payload_value["key"] = session_key
    payload = json.dumps(payload_value, separators=(",", ":")).encode("utf-8")
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
    raw_key = payload.get("key")
    key = normalize_session_key(raw_key) if isinstance(raw_key, str) and raw_key else normalize_session_key(cwd)
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


def websocket_message_thread_id(opcode: int, payload: bytes) -> str | None:
    value = websocket_message_json(opcode, payload)
    if value is None:
        return None
    return response_create_payload_thread_id(value)


def response_create_payload_turn_id(value: Any) -> str | None:
    metadata = response_create_payload_metadata(value)
    if not metadata:
        return None
    turn_id = metadata.get("turn_id")
    return turn_id if isinstance(turn_id, str) and turn_id else None


def response_create_payload_thread_id(value: Any) -> str | None:
    metadata = response_create_payload_metadata(value)
    if not metadata:
        return None
    for key in ("thread_id", "threadId"):
        thread_id = metadata.get(key)
        if isinstance(thread_id, str) and thread_id:
            return thread_id
    return None


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


def clean_transcript_text(value: str, *, preserve_edges: bool = False) -> str:
    text = value.replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        return ""
    if not preserve_edges:
        text = text.strip()
    return text


def clean_control_user_text(value: str) -> str:
    text = value.replace("\r\n", "\n").replace("\r", "\n")
    text = CONTROL_TRANSCRIPT_EDGE_RE.sub("", text)
    if not text:
        return ""
    return text


def transcript_identity_text(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def transcript_text_from_content(value: Any, *, preserve_edges: bool = False) -> str:
    if isinstance(value, str):
        return clean_transcript_text(value, preserve_edges=preserve_edges)
    if isinstance(value, list):
        pieces = [
            transcript_text_from_content(item, preserve_edges=preserve_edges)
            for item in value
        ]
        return "\n".join(piece for piece in pieces if piece)
    if not isinstance(value, dict):
        return ""

    item_type = str(value.get("type") or "").lower()
    if item_type in {"input_text", "output_text", "text"} and isinstance(value.get("text"), str):
        return clean_transcript_text(value["text"], preserve_edges=preserve_edges)
    if isinstance(value.get("text"), str) and item_type in {"message", "content"}:
        return clean_transcript_text(value["text"], preserve_edges=preserve_edges)
    for key in ("content", "parts"):
        text = transcript_text_from_content(value.get(key), preserve_edges=preserve_edges)
        if text:
            return text
    return ""


def transcript_text_from_input(value: Any) -> str:
    if isinstance(value, str):
        return clean_transcript_text(value)
    if isinstance(value, list):
        pieces = [transcript_text_from_input(item) for item in value]
        return "\n".join(piece for piece in pieces if piece)
    if not isinstance(value, dict):
        return ""

    role = str(value.get("role") or "").lower()
    if role and role not in {"user", "human"}:
        return ""
    text = transcript_text_from_content(value.get("content"))
    if text:
        return text
    if isinstance(value.get("text"), str):
        return clean_transcript_text(value["text"])
    return ""


def user_text_items_from_input(value: Any) -> list[str]:
    if isinstance(value, str):
        text = clean_transcript_text(value)
        return [text] if text else []
    if isinstance(value, list):
        items: list[str] = []
        for item in value:
            items.extend(user_text_items_from_input(item))
        return items
    if not isinstance(value, dict):
        return []

    role = str(value.get("role") or "").lower()
    if role and role not in {"user", "human"}:
        return []
    text = transcript_text_from_content(value.get("content"))
    if text:
        return [text]
    if isinstance(value.get("text"), str):
        text = clean_transcript_text(value["text"])
        return [text] if text else []
    return []


def user_entries_from_text_items(text_items: list[str]) -> list[dict[str, str]]:
    raw_entries: list[dict[str, str]] = []
    for text in text_items:
        raw_entries.extend(user_transcript_entries(text))
    last_user_index = -1
    for index, entry in enumerate(raw_entries):
        if entry.get("role") == "user":
            last_user_index = index
    if last_user_index < 0:
        return raw_entries
    entries: list[dict[str, str]] = []
    for index, entry in enumerate(raw_entries):
        text = str(entry.get("text") or "")
        if not text:
            continue
        role = str(entry.get("role") or "user")
        if role == "user":
            role = "user" if index == last_user_index else "resume"
        entries.append({"role": role, "text": text})
    return entries


def transcript_entries_from_input(value: Any) -> list[dict[str, str]]:
    return user_entries_from_text_items(user_text_items_from_input(value))


def response_create_payload_user_text(value: Any) -> str:
    entries = response_create_payload_user_entries(value)
    if entries:
        return "\n".join(
            entry["text"]
            for entry in entries
            if entry.get("role") in {"user", "resume"} and entry.get("text")
        )
    if isinstance(value, list):
        pieces = [response_create_payload_user_text(item) for item in value]
        return "\n".join(piece for piece in pieces if piece)
    if not response_create_payload_starts_turn(value) or not isinstance(value, dict):
        return ""
    payloads = [value]
    response = value.get("response")
    if isinstance(response, dict):
        payloads.append(response)
    for payload in payloads:
        text = transcript_text_from_input(payload.get("input"))
        if text:
            return text
    return ""


def response_create_payload_user_entries(value: Any) -> list[dict[str, str]]:
    if isinstance(value, list):
        entries: list[dict[str, str]] = []
        for item in value:
            entries.extend(response_create_payload_user_entries(item))
        return entries
    if not response_create_payload_starts_turn(value) or not isinstance(value, dict):
        return []
    payloads = [value]
    response = value.get("response")
    if isinstance(response, dict):
        payloads.append(response)
    for payload in payloads:
        entries = transcript_entries_from_input(payload.get("input"))
        if entries:
            return entries
    return []


def websocket_message_user_text(opcode: int, payload: bytes) -> str:
    value = websocket_message_json(opcode, payload)
    return response_create_payload_user_text(value) if value is not None else ""


def websocket_message_user_entries(opcode: int, payload: bytes) -> list[dict[str, str]]:
    value = websocket_message_json(opcode, payload)
    return response_create_payload_user_entries(value) if value is not None else []


def goal_context_display_text(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        objective = CODEX_GOAL_OBJECTIVE_RE.search(match.group(0))
        if not objective:
            return ""
        text = clean_control_user_text(objective.group(1))
        return f"Goal: {text}" if text else ""

    return CODEX_GOAL_CONTEXT_RE.sub(replace, value)


def user_shell_command_transcript_entries(block: str, *, role: str) -> list[dict[str, str]]:
    command_match = USER_SHELL_COMMAND_COMMAND_RE.search(block)
    if not command_match:
        return []
    command = clean_transcript_text(command_match.group("command"))
    if not command:
        return []

    result_match = USER_SHELL_COMMAND_RESULT_RE.search(block)
    result = clean_transcript_text(result_match.group("result")) if result_match else ""
    exit_code_match = USER_SHELL_RESULT_EXIT_CODE_RE.search(result)
    duration_match = USER_SHELL_RESULT_DURATION_RE.search(result)
    output_match = USER_SHELL_RESULT_OUTPUT_RE.search(result)
    exit_code = clean_transcript_text(exit_code_match.group("value")) if exit_code_match else ""
    duration = clean_transcript_text(duration_match.group("value")) if duration_match else ""
    output = clean_transcript_text(output_match.group("value")) if output_match else ""

    suffixes = []
    if exit_code:
        suffixes.append(f"exit {exit_code}")
    if duration:
        suffixes.append(f"duration {duration}")
    header = f"Command: {command}"
    if suffixes:
        header = f"{header} ({', '.join(suffixes)})"
    details = [header]
    if output:
        details.append(f"Output:\n{output}")
    elif result:
        details.append(f"Result:\n{result}")
    return [
        {"role": role, "text": f"! {command}"},
        {"role": "tool", "text": "\n".join(details)},
    ]


def user_transcript_segment_entries(text: str, *, role: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    offset = 0
    for match in USER_SHELL_COMMAND_RE.finditer(text):
        preceding = clean_control_user_text(text[offset : match.start()])
        if preceding:
            entries.append({"role": role, "text": preceding})
        shell_entries = user_shell_command_transcript_entries(match.group("body"), role=role)
        if shell_entries:
            entries.extend(shell_entries)
        else:
            unparsed = clean_control_user_text(match.group(0))
            if unparsed:
                entries.append({"role": role, "text": unparsed})
        offset = match.end()
    trailing = clean_control_user_text(text[offset:])
    if trailing:
        entries.append({"role": role, "text": trailing})
    return entries


def user_transcript_entries(text: str) -> list[dict[str, str]]:
    text = goal_context_display_text(text)
    matches = list(ENVIRONMENT_CONTEXT_RE.finditer(text))
    if not matches:
        return user_transcript_segment_entries(text, role="user")

    history = ENVIRONMENT_CONTEXT_RE.sub("\n\n", text[: matches[-1].start()])
    current = ENVIRONMENT_CONTEXT_RE.sub("\n\n", text[matches[-1].end() :])
    entries = user_transcript_segment_entries(history, role="resume")
    entries.extend(user_transcript_segment_entries(current, role="user"))
    if entries:
        return entries
    return user_transcript_segment_entries(
        ENVIRONMENT_CONTEXT_RE.sub("\n\n", text),
        role="user",
    )


def split_user_entries_by_prompt_suffix(
    entries: list[dict[str, str]],
    prompt: str,
) -> list[dict[str, str]]:
    prompt = clean_control_user_text(prompt)
    if not entries or not prompt:
        return entries
    result: list[dict[str, str]] = []
    for entry in entries:
        if entry.get("role") != "user":
            result.append(entry)
            continue
        text = clean_control_user_text(str(entry.get("text") or ""))
        if transcript_identity_text(text) == transcript_identity_text(prompt):
            result.append({"role": "user", "text": prompt})
            continue
        index = text.rfind(prompt)
        if index < 0 or text[index + len(prompt) :].strip():
            result.append(entry)
            continue
        replay = clean_control_user_text(text[:index])
        if replay:
            result.append({"role": "resume", "text": replay})
        result.append({"role": "user", "text": prompt})
    return result


def output_text_from_response(value: Any, *, preserve_edges: bool = False) -> str:
    if isinstance(value, list):
        pieces = [
            output_text_from_response(item, preserve_edges=preserve_edges)
            for item in value
        ]
        return "\n".join(piece for piece in pieces if piece)
    if not isinstance(value, dict):
        return ""
    item_type = str(value.get("type") or "").lower()
    role = str(value.get("role") or "").lower()
    if item_type in {"output_text", "text"} and isinstance(value.get("text"), str):
        return clean_transcript_text(value["text"], preserve_edges=preserve_edges)
    if role == "assistant":
        text = transcript_text_from_content(value.get("content"), preserve_edges=preserve_edges)
        if text:
            return text
    for key in ("output", "content", "message", "response"):
        text = output_text_from_response(value.get(key), preserve_edges=preserve_edges)
        if text:
            return text
    return ""


def websocket_message_assistant_entry(opcode: int, payload: bytes) -> dict[str, Any] | None:
    value = websocket_message_json(opcode, payload)
    if not isinstance(value, dict):
        return None
    event = json_value_event_type(value) or ""
    delta = value.get("delta")
    if isinstance(delta, str) and "output_text" in event:
        text = clean_transcript_text(delta, preserve_edges=True)
        return {"role": "assistant_progress", "text": text, "append": True} if text else None
    if isinstance(delta, dict):
        text = output_text_from_response(delta, preserve_edges=True)
        if text:
            return {"role": "assistant_progress", "text": text, "append": True}
    if "completed" in event or event.endswith(".done"):
        text = output_text_from_response(value.get("response") or value)
        if text:
            return {"role": "assistant", "text": text, "append": False}
    return None


def websocket_message_assistant_text(opcode: int, payload: bytes) -> tuple[str, bool]:
    entry = websocket_message_assistant_entry(opcode, payload)
    if not entry:
        return "", False
    return str(entry.get("text") or ""), bool(entry.get("append"))


def compact_tool_detail(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        parsed = parse_jsonish_string(value)
        if parsed is not None:
            return compact_tool_detail(parsed)
        return clean_transcript_text(value)
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        for key in ("patch", "input", "content", "arguments", "cmd", "command"):
            item = value.get(key)
            if isinstance(item, str) and "*** Begin Patch" in item:
                return clean_transcript_text(item)
        simple_lines = []
        for key, item in value.items():
            if item is None or isinstance(item, (str, int, float, bool)):
                simple_lines.append(f"{key}: {'' if item is None else item}")
            else:
                simple_lines = []
                break
        if simple_lines:
            return clean_transcript_text("\n".join(simple_lines))
        try:
            return clean_transcript_text(json.dumps(value, ensure_ascii=False, indent=2))
        except (TypeError, ValueError):
            return clean_transcript_text(str(value))
    if isinstance(value, list):
        content_text = [
            item.get("text")
            for item in value
            if isinstance(item, dict)
            and isinstance(item.get("text"), str)
            and str(item.get("type") or "").lower() in {"input_text", "output_text", "text"}
        ]
        if content_text and len(content_text) == len(value):
            return clean_transcript_text("\n".join(content_text))
        if all(item is None or isinstance(item, (str, int, float, bool)) for item in value):
            return clean_transcript_text("\n".join(str(item) for item in value if item is not None))
        try:
            return clean_transcript_text(json.dumps(value, ensure_ascii=False, indent=2))
        except (TypeError, ValueError):
            return clean_transcript_text(str(value))
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        encoded = str(value)
    return clean_transcript_text(encoded)


def parse_jsonish_string(value: str) -> Any | None:
    stripped = value.strip()
    if not stripped or stripped[0] not in "[{\"":
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def decoded_javascript_string_literal(value: str) -> str:
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return ""
    return decoded if isinstance(decoded, str) else ""


def programmatic_tool_string_property(source: str, name: str) -> str:
    match = re.search(
        rf"(?:[\"']{re.escape(name)}[\"']|\b{re.escape(name)})\s*:\s*(\"(?:\\.|[^\"\\])*\")",
        source,
        re.DOTALL,
    )
    return decoded_javascript_string_literal(match.group(1)) if match else ""


def programmatic_tool_input_details(name: str, source: str) -> str:
    payload: dict[str, Any] = {}
    if name == "update_plan":
        plan = [
            {
                "step": decoded_javascript_string_literal(match.group(1)),
                "status": decoded_javascript_string_literal(match.group(2)),
            }
            for match in PROGRAMMATIC_TOOL_PLAN_STEP_RE.finditer(source)
        ]
        if plan:
            payload["plan"] = plan
        explanation = programmatic_tool_string_property(source, "explanation")
        if explanation:
            payload["explanation"] = explanation
    elif name == "update_goal":
        status = programmatic_tool_string_property(source, "status")
        if status:
            payload["status"] = status
    elif name == "create_goal":
        objective = programmatic_tool_string_property(source, "objective")
        if objective:
            payload["objective"] = objective
    return json.dumps(payload, ensure_ascii=False, indent=2) if payload else ""


def programmatic_tool_call_details(value: dict[str, Any]) -> dict[str, str] | None:
    source = first_string_value(value, ("input", "arguments", "code"))
    if not source:
        return None
    match = PROGRAMMATIC_TOOL_INVOCATION_RE.search(source)
    if not match:
        return None
    name = match.group(1).rsplit(".", 1)[-1]
    details = {"name": name, "command": "", "input": ""}
    if name == "exec_command":
        command = PROGRAMMATIC_TOOL_COMMAND_RE.search(source)
        if command:
            details["command"] = decoded_javascript_string_literal(command.group(1))
    elif name == "apply_patch":
        patch = PROGRAMMATIC_TOOL_PATCH_RE.search(source)
        if patch:
            details["input"] = decoded_javascript_string_literal(patch.group(1))
    else:
        details["input"] = programmatic_tool_input_details(name, source)
    return details


def shell_join(value: list[Any]) -> str:
    parts = [str(item) for item in value if item is not None]
    return " ".join(shlex.quote(part) for part in parts)


def first_string_value(value: Any, keys: tuple[str, ...]) -> str:
    if not isinstance(value, dict):
        return ""
    for key in keys:
        item = value.get(key)
        if isinstance(item, str) and item.strip():
            return item.strip()
        if isinstance(item, (int, float, bool)):
            return str(item)
    return ""


def nested_command_value(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    command = first_string_value(value, ("command", "cmd", "shell_command", "program"))
    if "*** Begin Patch" in command:
        command = ""
    if command:
        return command
    for key in ("command", "cmd", "argv", "args"):
        item = value.get(key)
        if isinstance(item, list):
            command = shell_join(item)
            if command:
                return command
    for key in ("action", "input", "arguments"):
        nested = value.get(key)
        if isinstance(nested, str):
            parsed = parse_jsonish_string(nested)
            if isinstance(parsed, dict):
                command = nested_command_value(parsed)
                if command:
                    return command
        if isinstance(nested, dict):
            command = nested_command_value(nested)
            if command:
                return command
    return ""


def tool_call_identifier(value: dict[str, Any]) -> str:
    return first_string_value(
        value,
        ("call_id", "callId", "id", "item_id", "itemId", "tool_call_id", "toolCallId"),
    )


def tool_header_key(value: str) -> tuple[str, str] | None:
    first_line = value.splitlines()[0].strip() if value.strip() else ""
    for label in ("Command", "Tool"):
        prefix = f"{label}: "
        if first_line.startswith(prefix):
            name = first_line[len(prefix) :].strip()
            name = re.sub(r"\s+\([^)]*\)$", "", name).strip()
            return label.lower(), name
    return None


def tool_transcript_sections(value: str) -> tuple[str, list[tuple[str, str]]]:
    lines = value.splitlines()
    header = lines[0].strip() if lines else ""
    sections: list[tuple[str, str]] = []
    current_label = ""
    current_lines: list[str] = []

    def push_section() -> None:
        nonlocal current_label, current_lines
        if not current_label:
            return
        text = "\n".join(current_lines).rstrip()
        if text:
            sections.append((current_label, text))
        current_label = ""
        current_lines = []

    for raw_line in lines[1:]:
        match = re.match(r"^([A-Za-z][A-Za-z0-9 _/-]{1,40}):\s*$", raw_line)
        if match:
            push_section()
            current_label = match.group(1).strip()
            current_lines = []
            continue
        if not current_label:
            current_label = "Details"
            current_lines = []
        current_lines.append(raw_line)
    push_section()
    return header, sections


def merge_tool_sections(existing: str, update: str) -> str:
    update_header, update_sections = tool_transcript_sections(update)
    existing_header, existing_sections = tool_transcript_sections(existing)
    header = update_header or existing_header
    section_map: dict[str, str] = {}
    order: list[str] = []
    for label, text in existing_sections:
        if label not in section_map:
            order.append(label)
        section_map[label] = text
    for label, text in update_sections:
        if label not in section_map:
            order.append(label)
        section_map[label] = text
    pieces = [header] if header else []
    for label in order:
        text = section_map.get(label)
        if text:
            pieces.append(f"{label}:\n{text}")
    return "\n".join(pieces).strip()


def merge_tool_transcript_text(existing: str, update: str) -> str:
    existing = existing.rstrip()
    update = update.strip()
    if not existing:
        return update
    if not update or update == existing or update in existing:
        return existing
    if existing in update:
        return update

    existing_key = tool_header_key(existing)
    update_key = tool_header_key(update)
    if existing_key and existing_key == update_key:
        return merge_tool_sections(existing, update)

    lines = update.splitlines()
    if existing_key and lines:
        first = lines[0].strip()
        if first.startswith("Tool: call_") or first.startswith("Tool: "):
            remainder = "\n".join(lines[1:]).strip()
            if remainder:
                return merge_tool_sections(existing, f"{existing.splitlines()[0]}\n{remainder}")
    return f"{existing}\n{update}"


def is_control_tool_call_name(value: Any) -> bool:
    return isinstance(value, str) and bool(CONTROL_TOOL_CALL_RE.match(value.strip()))


def is_web_search_tool_call_name(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip().lower()
    return text in {"web_search", "web_search_call", "websearch"} or bool(
        WEB_SEARCH_TOOL_CALL_RE.match(text)
    )


def web_search_query_detail(value: Any) -> str:
    if isinstance(value, str):
        parsed = parse_jsonish_string(value)
        if parsed is not None:
            return web_search_query_detail(parsed)
        return ""
    if isinstance(value, list):
        queries = [web_search_query_detail(item) for item in value]
        return "\n".join(query for query in queries if query)
    if not isinstance(value, dict):
        return ""
    direct = first_string_value(value, ("query", "q", "search_query", "searchQuery"))
    if direct:
        return direct
    for key in ("queries", "input", "arguments", "params", "content", "action"):
        query = web_search_query_detail(value.get(key))
        if query:
            return query
    return ""


def image_generation_tool_status(value: dict[str, Any]) -> str:
    """Return a terminal image-generation status for tool result payloads."""
    normalized = str(value.get("type") or "").lower()
    if normalized == "image_generation_call":
        status = first_string_value(value, ("status", "state")).lower()
        if status in {"completed", "failed", "canceled", "cancelled"}:
            return status
        result = value.get("result")
        if isinstance(result, str) and result:
            return "completed"
        return ""
    if normalized != "function_call_output":
        return ""

    output = value.get("output")
    if not isinstance(output, list):
        return ""
    has_image = False
    has_generated_image_notice = False
    for item in output:
        if not isinstance(item, dict):
            continue
        item_type = str(item.get("type") or "").lower()
        if item_type == "input_image":
            has_image = True
        if item_type in {"input_text", "output_text", "text"}:
            text = item.get("text")
            if isinstance(text, str) and "generated images are saved to" in text.lower():
                has_generated_image_notice = True
    return "completed" if has_image and has_generated_image_notice else ""


def image_generation_tool_entry(value: dict[str, Any]) -> dict[str, Any] | None:
    status = image_generation_tool_status(value)
    if not status:
        return None
    if status == "completed":
        result = "Image generated successfully."
    elif status in {"canceled", "cancelled"}:
        result = "Image generation was canceled."
    else:
        result = "Image generation failed."
    return {
        "role": "tool",
        "text": f"Tool: Image generation (status {status})\nResult:\n{result}",
        "call_id": tool_call_identifier(value),
        "status": status,
    }


def tool_activity_entry_from_value(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    item_type = value.get("type")
    if not isinstance(item_type, str):
        return None
    normalized = item_type.lower()
    if not (
        normalized in WEBSOCKET_TOOL_OUTPUT_TYPES
        or normalized.endswith("_call")
        or "tool_call" in normalized
    ):
        return None

    call_id = tool_call_identifier(value)
    image_entry = image_generation_tool_entry(value)
    if image_entry:
        return image_entry
    programmatic_details = programmatic_tool_call_details(value) if normalized == "custom_tool_call" else None
    name = first_string_value(value, ("name", "tool_name", "server_label")) or call_id or normalized
    if programmatic_details:
        name = programmatic_details["name"] or name
    if is_control_tool_call_name(name) or is_control_tool_call_name(call_id):
        return None
    is_web_search = (
        normalized == "web_search_call"
        or is_web_search_tool_call_name(name)
        or is_web_search_tool_call_name(call_id)
    )
    is_programmatic = normalized in {"program", "program_output"}
    status = first_string_value(value, ("status", "state"))
    exit_code = first_string_value(value, ("exit_code", "exitCode", "returncode"))
    command = nested_command_value(value)
    if programmatic_details and programmatic_details["command"]:
        command = programmatic_details["command"]
    detail_sections: list[tuple[str, str]] = []
    seen_detail_text: set[tuple[str, str]] = set()
    if programmatic_details and programmatic_details["input"]:
        programmatic_input = programmatic_details["input"]
        seen_detail_text.add(("Input", programmatic_input))
        detail_sections.append(("Input", programmatic_input))
    if is_web_search:
        query = web_search_query_detail(value)
        if query:
            seen_detail_text.add(("Query", query))
            detail_sections.append(("Query", query))
    if "apply_patch" in name.lower() or normalized == "apply_patch_call":
        for key in ("cmd", "command"):
            text = compact_tool_detail(value.get(key))
            if text and "*** Begin Patch" in text:
                seen_detail_text.add(("Input", text))
                detail_sections.append(("Input", text))
    for key, label in (
        ("arguments", "Arguments"),
        ("input", "Input"),
        ("code", "Code"),
        ("patch", "Patch"),
        ("content", "Content"),
        ("caller", "Caller"),
        ("fingerprint", "Fingerprint"),
        ("params", "Parameters"),
        ("output", "Output"),
        ("stdout", "Stdout"),
        ("stderr", "Stderr"),
        ("result", "Result"),
        ("message", "Message"),
        ("summary", "Summary"),
    ):
        if programmatic_details and key in {"arguments", "input", "code"}:
            continue
        text = compact_tool_detail(value.get(key))
        if (
            is_web_search
            and query
            and label in {"Arguments", "Input", "Parameters"}
            and transcript_identity_text(text).lower()
            in {
                transcript_identity_text(query).lower(),
                f"query: {transcript_identity_text(query)}".lower(),
                f"q: {transcript_identity_text(query)}".lower(),
                f"search_query: {transcript_identity_text(query)}".lower(),
            }
        ):
            continue
        detail_key = (label, text)
        if text and detail_key not in seen_detail_text:
            seen_detail_text.add(detail_key)
            detail_sections.append((label, text))
    if normalized in {"local_shell_call", "shell_call", "command_execution"} or (
        command and not is_programmatic
    ):
        header = f"Command: {command or name}"
    elif is_web_search:
        header = "Tool: Web Search"
    elif normalized == "program":
        header = "Tool: Programmatic Tool Calling"
    elif normalized == "program_output":
        header = "Tool: Programmatic Tool Calling output"
    else:
        header = f"Tool: {name}"
    details = [header]
    suffixes = []
    if status:
        suffixes.append(f"status {status}")
    if exit_code:
        suffixes.append(f"exit {exit_code}")
    if suffixes:
        details[0] = f"{details[0]} ({', '.join(suffixes)})"

    for output_label, output_text in detail_sections:
        details.append(f"{output_label}:\n{output_text}")
    return {
        "role": "tool",
        "text": clean_transcript_text("\n".join(details)),
        "call_id": call_id,
        "status": status,
    }


def tool_activity_entries_from_value(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        entries: list[dict[str, Any]] = []
        for item in value:
            entries.extend(tool_activity_entries_from_value(item))
        return entries
    if not isinstance(value, dict):
        return []

    entries = []
    own = tool_activity_entry_from_value(value)
    if own:
        entries.append(own)
    for nested in value.values():
        entries.extend(tool_activity_entries_from_value(nested))

    deduped = []
    seen = set()
    for entry in entries:
        key = (entry.get("role"), entry.get("text"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    return deduped


def websocket_message_tool_entries(opcode: int, payload: bytes) -> list[dict[str, Any]]:
    value = websocket_message_json(opcode, payload)
    if value is None:
        return []
    return tool_activity_entries_from_value(value)


def app_server_message_method(message: dict[str, Any]) -> str:
    method = message.get("method")
    return method if isinstance(method, str) else ""


def app_server_message_params(message: dict[str, Any]) -> dict[str, Any]:
    params = message.get("params")
    return params if isinstance(params, dict) else {}


def app_server_message_turn_id(message: dict[str, Any]) -> str:
    params = app_server_message_params(message)
    for key in ("turnId", "turn_id"):
        value = params.get(key)
        if isinstance(value, str) and value:
            return value
    turn = params.get("turn")
    if isinstance(turn, dict):
        turn_id = turn_id_from_app_server_value(turn)
        return turn_id or ""
    return ""


def app_server_error_text(value: Any) -> str:
    if isinstance(value, str):
        return clean_transcript_text(value)
    if isinstance(value, dict):
        for key in ("message", "detail", "error", "reason"):
            text = app_server_error_text(value.get(key))
            if text:
                return text
        return compact_tool_detail(value)
    return ""


def app_server_tool_entry_from_item(item: dict[str, Any]) -> dict[str, Any] | None:
    item_type = str(item.get("type") or "")
    item_type_key = re.sub(r"[_-]", "", item_type).lower()
    call_id = first_string_value(item, ("id", "itemId", "item_id", "call_id", "callId"))
    name = first_string_value(item, ("name", "tool"))
    status = first_string_value(item, ("status", "state"))
    if is_control_tool_call_name(call_id) or is_control_tool_call_name(name):
        return None
    if item_type_key == "websearch" or is_web_search_tool_call_name(call_id) or is_web_search_tool_call_name(name):
        suffix = f" (status {status})" if status else ""
        details = [f"Tool: Web Search{suffix}"]
        query = web_search_query_detail(item)
        result = compact_tool_detail(item.get("result") or item.get("output"))
        error = compact_tool_detail(item.get("error"))
        if query:
            details.append(f"Query:\n{query}")
        if result:
            details.append(f"Result:\n{result}")
        if error:
            details.append(f"Error:\n{error}")
        return {"role": "tool", "text": "\n".join(details), "call_id": call_id, "status": status}
    if item_type_key == "commandexecution":
        command = nested_command_value(item) or first_string_value(item, ("command",))
        exit_code = first_string_value(item, ("exitCode", "exit_code"))
        suffixes = []
        if status:
            suffixes.append(f"status {status}")
        if exit_code:
            suffixes.append(f"exit {exit_code}")
        header = f"Command: {command or call_id or 'command'}"
        if suffixes:
            header = f"{header} ({', '.join(suffixes)})"
        output = compact_tool_detail(
            item.get("aggregatedOutput")
            or item.get("aggregated_output")
            or item.get("formattedOutput")
            or item.get("formatted_output")
            or item.get("output")
        )
        text = header if not output else f"{header}\nOutput:\n{output}"
        return {"role": "tool", "text": text, "call_id": call_id, "status": status}
    if item_type_key == "dynamictoolcall":
        namespace = first_string_value(item, ("namespace",))
        tool = first_string_value(item, ("tool", "name"))
        name = "/".join(part for part in (namespace, tool) if part) or call_id or "dynamic tool"
        suffix = f" (status {status})" if status else ""
        details = [f"Tool: {name}{suffix}"]
        for key, label in (
            ("arguments", "Arguments"),
            ("contentItems", "Content"),
            ("content_items", "Content"),
            ("result", "Result"),
            ("output", "Output"),
            ("error", "Error"),
        ):
            text = compact_tool_detail(item.get(key))
            if text:
                details.append(f"{label}:\n{text}")
        return {"role": "tool", "text": "\n".join(details), "call_id": call_id, "status": status}
    if item_type_key == "mcptoolcall":
        server = first_string_value(item, ("server",))
        tool = first_string_value(item, ("tool", "name"))
        name = "/".join(part for part in (server, tool) if part) or call_id or "mcp tool"
        suffix = f" (status {status})" if status else ""
        details = [f"Tool: {name}{suffix}"]
        arguments = compact_tool_detail(item.get("arguments"))
        result = compact_tool_detail(item.get("result"))
        error = compact_tool_detail(item.get("error"))
        if arguments:
            details.append(f"Arguments:\n{arguments}")
        if result:
            details.append(f"Result:\n{result}")
        if error:
            details.append(f"Error:\n{error}")
        return {"role": "tool", "text": "\n".join(details), "call_id": call_id, "status": status}
    if item_type_key == "filechange":
        changes = item.get("changes")
        paths = []
        if isinstance(changes, list):
            for change in changes:
                if isinstance(change, dict):
                    path = first_string_value(change, ("path",))
                    kind = first_string_value(change, ("kind",))
                    paths.append(f"{kind}: {path}" if kind and path else path or kind)
        if isinstance(changes, dict):
            for path, change in changes.items():
                kind = ""
                if isinstance(change, dict):
                    kind = first_string_value(change, ("kind", "type"))
                path_text = str(path)
                paths.append(f"{kind}: {path_text}" if kind else path_text)
        suffix = f" (status {status})" if status else ""
        detail = "\n".join(path for path in paths if path)
        text = f"Tool: file changes{suffix}" if not detail else f"Tool: file changes{suffix}\n{detail}"
        return {"role": "tool", "text": text, "call_id": call_id, "status": status}
    if item_type_key == "collabagenttoolcall":
        tool = first_string_value(item, ("tool", "name")) or "agent"
        suffix = f" (status {status})" if status else ""
        details = [f"Tool: agent {tool}{suffix}"]
        for key, label in (
            ("prompt", "Prompt"),
            ("model", "Model"),
            ("reasoningEffort", "Reasoning"),
            ("reasoning_effort", "Reasoning"),
            ("receiverAgents", "Receiver agents"),
            ("receiver_agents", "Receiver agents"),
            ("receiverThreadIds", "Receiver threads"),
            ("receiver_thread_ids", "Receiver threads"),
            ("agentsStates", "Agent states"),
            ("agents_states", "Agent states"),
        ):
            text = compact_tool_detail(item.get(key))
            if text:
                details.append(f"{label}:\n{text}")
        return {"role": "tool", "text": "\n".join(details), "call_id": call_id, "status": status}
    if item_type_key == "subagentactivity":
        kind = first_string_value(item, ("kind",)) or "activity"
        suffix = f" (status {status})" if status else ""
        details = [f"Tool: sub-agent {kind}{suffix}"]
        for key, label in (
            ("agentPath", "Agent path"),
            ("agent_path", "Agent path"),
            ("agentThreadId", "Agent thread"),
            ("agent_thread_id", "Agent thread"),
        ):
            text = compact_tool_detail(item.get(key))
            if text:
                details.append(f"{label}:\n{text}")
        return {"role": "tool", "text": "\n".join(details), "call_id": call_id, "status": status}
    if item_type_key == "hookprompt":
        suffix = f" (status {status})" if status else ""
        details = [f"Tool: hook prompt{suffix}"]
        fragments = compact_tool_detail(item.get("fragments"))
        if fragments:
            details.append(f"Fragments:\n{fragments}")
        return {"role": "tool", "text": "\n".join(details), "call_id": call_id, "status": status}
    if item_type_key in {
        "imageview",
        "imagegeneration",
        "collabtoolcall",
        "enteredreviewmode",
        "exitedreviewmode",
        "contextcompaction",
        "sleep",
    }:
        label = {
            "imageView": "image view",
            "imageGeneration": "image generation",
            "collabToolCall": "collab tool",
            "enteredReviewMode": "review mode started",
            "exitedReviewMode": "review mode completed",
            "contextCompaction": "context compaction",
            "sleep": "sleep",
        }.get(item_type, item_type)
        suffix = f" (status {status})" if status else ""
        detail = compact_tool_detail(item)
        text = f"Tool: {label}{suffix}" if not detail else f"Tool: {label}{suffix}\n{detail}"
        return {"role": "tool", "text": text, "call_id": call_id, "status": status}
    return None


def app_server_transcript_entries_from_message(message: dict[str, Any]) -> list[dict[str, Any]]:
    method = app_server_message_method(message)
    params = app_server_message_params(message)
    turn_id = app_server_message_turn_id(message)
    if method == "item/agentMessage/delta":
        delta = params.get("delta")
        text = clean_transcript_text(delta, preserve_edges=True) if isinstance(delta, str) else ""
        return [{"role": "assistant_progress", "text": text, "append": True, "turn_id": turn_id}] if text else []
    if method == "item/completed":
        item = params.get("item")
        if not isinstance(item, dict):
            return []
        item_type = str(item.get("type") or "")
        if item_type == "agentMessage":
            text = clean_transcript_text(str(item.get("text") or ""))
            return [{"role": "assistant", "text": text, "append": False, "turn_id": turn_id}] if text else []
        tool_entry = app_server_tool_entry_from_item(item)
        if tool_entry:
            tool_entry["turn_id"] = turn_id
            return [tool_entry]
    if method == "item/started":
        item = params.get("item")
        if isinstance(item, dict):
            tool_entry = app_server_tool_entry_from_item(item)
            if tool_entry:
                tool_entry["turn_id"] = turn_id
                return [tool_entry]
    if method in {"error", "turn/completed"}:
        error = params.get("error")
        if not error:
            turn = params.get("turn")
            error = turn.get("error") if isinstance(turn, dict) else None
        text = app_server_error_text(error)
        return [{"role": "error", "text": text, "append": False, "turn_id": turn_id}] if text else []
    return []


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


def context_summary_from_usage(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    input_tokens = int_value(value.get("input_tokens", value.get("prompt_tokens")))
    total_tokens = int_value(value.get("total_tokens"))
    if input_tokens <= 0 and total_tokens <= 0:
        return {}
    used_tokens = input_tokens if input_tokens > 0 else total_tokens
    remaining_tokens = max(0, CONTROL_CONTEXT_WINDOW_TOKENS - used_tokens)
    remaining_percent = round((remaining_tokens / CONTROL_CONTEXT_WINDOW_TOKENS) * 100)
    return {
        "window_tokens": CONTROL_CONTEXT_WINDOW_TOKENS,
        "input_tokens": input_tokens,
        "total_tokens": total_tokens,
        "remaining_tokens": remaining_tokens,
        "remaining_percent": remaining_percent,
        "label": f"~{remaining_percent}% left",
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


def render_reset_credit_control(
    payload: Any,
    profile: str | None,
    token: str | None,
    reset_credit: Any = None,
) -> str:
    if isinstance(reset_credit, dict) and reset_credit.get("blocks"):
        label = str(reset_credit.get("label") or "Reset pending")
        message = str(reset_credit.get("message") or "Reset-credit use is temporarily disabled.")
        return (
            '<span class="quota-reset-credit-pill disabled" '
            f'title="{html.escape(message)}">{html.escape(label)}</span>'
        )
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


def utc_timestamp(value: datetime | None = None) -> str:
    current = value or datetime.now(timezone.utc)
    return current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def reset_credit_confirmation_matches(before_payload: Any, current_payload: Any) -> bool:
    if not isinstance(current_payload, dict):
        return False
    if isinstance(before_payload, dict):
        before_count = quota_payload_reset_credit_count(before_payload)
        current_count = quota_payload_reset_credit_count(current_payload)
        if before_count > 0 and current_count < before_count:
            return True
    before_snapshot = quota_remaining_snapshot(before_payload)
    current_snapshot = quota_remaining_snapshot(current_payload)
    for name, current in current_snapshot.items():
        previous = before_snapshot.get(name)
        if not previous:
            continue
        for key in ("primary_remaining_percent", "weekly_remaining_percent"):
            current_value = current.get(key)
            previous_value = previous.get(key)
            if not isinstance(current_value, (int, float)) or not isinstance(previous_value, (int, float)):
                continue
            if float(current_value) - float(previous_value) >= RESET_CREDIT_CONFIRMATION_DELTA_PERCENT:
                return True
    return False


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


def compact_control_event(event: dict[str, Any]) -> dict[str, Any]:
    event_type = str(event.get("type") or "")
    compact = compact_stats_event(event)
    session_key = event.get("session_key")
    if isinstance(session_key, str) and session_key:
        compact["session_key"] = session_key
    service_tier = event.get("service_tier")
    if isinstance(service_tier, str) and service_tier:
        compact["service_tier"] = service_tier

    summary = control_event_summary(event)
    compact["summary"] = summary
    compact["search_text"] = " ".join(
        str(value)
        for value in (
            compact.get("profile"),
            event_type,
            summary,
            event.get("path"),
            event.get("status"),
            service_tier,
        )
        if value is not None
    )
    return compact


def control_event_summary(event: dict[str, Any]) -> str:
    event_type = str(event.get("type") or "")
    if event_type == "token_usage" and isinstance(event.get("usage"), dict):
        usage = event["usage"]
        total = int_value(usage.get("total_tokens"))
        input_tokens = int_value(usage.get("input_tokens"))
        output_tokens = int_value(usage.get("output_tokens"))
        suffix = " fast" if event.get("fast") else ""
        return f"Token usage: {total} total ({input_tokens} in, {output_tokens} out){suffix}"
    if event_type == "websocket_tunnel":
        bytes_total = int_value(event.get("bytes_up")) + int_value(event.get("bytes_down"))
        messages_total = int_value(event.get("messages_up")) + int_value(event.get("messages_down"))
        return f"Tunnel closed: {bytes_total} bytes, {messages_total} messages"
    if event_type == "http_request":
        method = str(event.get("method") or "HTTP")
        path = str(event.get("path") or "request")
        status = event.get("status")
        status_text = f" status {status}" if status else ""
        return f"{method} {path}{status_text}"
    return event_type.replace("_", " ") or "event"


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


def quota_stack_display_windows(
    rate_limit: dict[str, Any],
) -> tuple[Any, Any, bool]:
    """Map a temporarily absent five-hour quota to the stacked weekly display.

    When OpenAI suspends the five-hour limit, Codex can report its only weekly
    window as ``primary_window``. Treating that literal field name as a 5h
    value makes the UI draw an invented weekly layer and label the real weekly
    value as green. Preserve the weekly window and explicitly mark 5h as not
    enforced instead.
    """
    primary = rate_limit.get("primary_window")
    secondary = rate_limit.get("secondary_window")
    primary_is_weekly = quota_window_label(primary, "5h") == "Weekly"
    if primary_is_weekly:
        weekly = secondary if isinstance(secondary, dict) and secondary else primary
        return None, weekly, True
    if not isinstance(primary, dict) and isinstance(secondary, dict):
        return None, secondary, True
    return primary, secondary, False


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
    primary, secondary, primary_not_enforced = quota_stack_display_windows(rate_limit)
    primary_percent = quota_window_remaining_percent(primary)
    weekly_percent = quota_window_remaining_percent(secondary)
    primary_label = "5h" if primary_not_enforced else quota_window_label(primary, "5h")
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

    primary_reset_text = (
        f"{primary_label} (Not enforced)"
        if primary_not_enforced
        else quota_status_text(primary_label, primary)
    )
    weekly_status = quota_status_text(weekly_label, secondary)
    weekly_style = weekly_percent if weekly_percent is not None else 100.0
    primary_style = primary_visual if primary_visual is not None else 0.0
    primary_text = "N/A" if primary_not_enforced else quota_percent_text(primary_visual)
    weekly_text = quota_percent_text(weekly_percent)
    primary_empty = " empty" if primary_style <= 0 else ""
    aria = " / ".join(
        piece
        for piece in (
            f"{primary_label} not enforced" if primary_not_enforced else f"{primary_label} {primary_text}" if primary_text else "",
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
        "primary_not_enforced": primary_not_enforced,
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
    primary_class = "quota-horizon primary not-enforced" if context.get("primary_not_enforced") else "quota-horizon primary"
    return f"""
      <div class="quota-title">
        <span class="quota-horizon weekly">{html.escape(weekly_status)}</span>
        <span class="quota-bucket-name" title="{html.escape(title)}">{html.escape(name)}</span>
        <span class="{primary_class}">{html.escape(primary_status)}</span>
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
    primary_not_enforced = bool(context.get("primary_not_enforced"))
    aria = str(context.get("aria") or "")
    special = str(context.get("special") or "")
    stack_class = f" quota-stack-{html.escape(special)}" if special else ""
    if primary_not_enforced:
        stack_class += " quota-stack-primary-not-enforced"
    weekly_label_html = f'<span class="quota-weekly-label">{html.escape(weekly_text)}</span>'
    primary_label_class = "quota-primary-label-outside not-enforced" if primary_not_enforced else "quota-primary-label-outside"
    primary_label_html = f'<span class="{primary_label_class}">{html.escape(primary_text)}</span>'
    bar_attrs = (
        f'role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="{primary_style:.0f}" aria-label="{html.escape(aria)}"'
        if not special and not primary_not_enforced
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


def quota_bucket_matches_model(bucket: dict[str, Any], model: str) -> bool:
    model_text = model.strip().lower()
    if not model_text:
        return False
    feature = str(bucket.get("metered_feature") or "").lower()
    name = str(bucket.get("name") or "").lower()
    if feature == "codex":
        return model_text == "codex"
    if feature and (feature == model_text or feature in model_text or model_text in feature):
        return True
    if "spark" in model_text and ("spark" in feature or "spark" in name):
        return True
    return False


def quota_bucket_for_model_from_rows(rows: list[dict[str, Any]], model: str) -> dict[str, Any] | None:
    if not rows:
        return None
    for row in rows:
        if quota_bucket_matches_model(row, model):
            return row
    for row in rows:
        if str(row.get("metered_feature") or "") == "codex":
            return row
    return rows[0]


def quota_bucket_for_model(payload: Any, model: str) -> dict[str, Any] | None:
    return quota_bucket_for_model_from_rows(quota_bucket_rows(payload), model)


def render_compact_quota_bucket_html(bucket: dict[str, Any], *, secondary: bool = False) -> str:
    rate_limit = bucket.get("rate_limit")
    if not isinstance(rate_limit, dict):
        return ""
    context = quota_stack_context(rate_limit)
    name = str(bucket.get("name") or "Quota")
    title = f"{name} quota"
    if feature := str(bucket.get("metered_feature") or ""):
        title = f"{title}: {feature}"
    secondary_class = " secondary" if secondary else ""
    if context.get("count_html"):
        return f"""
          <span class="control-compact-quota count{secondary_class}" title="{html.escape(title)}">
            <span class="control-compact-quota-name">{html.escape(name)}</span>
            <span class="control-compact-quota-text">available</span>
          </span>
        """
    primary_style = float(context.get("primary_style") or 0.0)
    weekly_style = float(context.get("weekly_style") or 0.0)
    primary_text = str(context.get("primary_text") or "")
    weekly_text = str(context.get("weekly_text") or "")
    primary_not_enforced = bool(context.get("primary_not_enforced"))
    aria = str(context.get("aria") or title)
    special = str(context.get("special") or "")
    special_class = f" {html.escape(special)}" if special else ""
    if primary_not_enforced:
        special_class += " primary-not-enforced"
    primary_class = "control-compact-quota-primary not-enforced" if primary_not_enforced else "control-compact-quota-primary"
    return f"""
      <span class="control-compact-quota{special_class}{secondary_class}" title="{html.escape(title)}">
        <span class="control-compact-quota-name">{html.escape(name)}</span>
        <span class="control-compact-quota-weekly">{html.escape(weekly_text)}</span>
        <span class="control-compact-quota-bar" role="img" aria-label="{html.escape(aria)}">
          <span class="control-compact-quota-weekly-fill" style="width: {weekly_style:.2f}%"></span>
          <span class="control-compact-quota-primary-fill" style="width: {primary_style:.2f}%"></span>
        </span>
        <span class="{primary_class}">{html.escape(primary_text)}</span>
      </span>
    """


def compact_quota_bucket_key(bucket: dict[str, Any]) -> str:
    feature = str(bucket.get("metered_feature") or "").strip()
    if feature:
        return f"feature:{normalize_rate_limit_id(feature)}"
    name = transcript_identity_text(str(bucket.get("name") or "")).lower()
    if name == "codex":
        return "feature:codex"
    return f"name:{name}"


def compact_quota_buckets(payload: Any, model: str | None = None) -> list[dict[str, Any]]:
    rows = quota_bucket_rows(payload)
    if not rows:
        return []
    selected = quota_bucket_for_model_from_rows(rows, model or "")
    buckets: list[dict[str, Any]] = []
    seen: set[str] = set()

    def append_bucket(bucket: dict[str, Any] | None) -> None:
        if not isinstance(bucket, dict):
            return
        key = compact_quota_bucket_key(bucket)
        if key in seen:
            return
        seen.add(key)
        buckets.append(bucket)

    append_bucket(selected)
    for row in rows:
        append_bucket(row)
    return buckets


def render_compact_quota_html(entry: dict[str, Any] | None, model: str | None = None) -> str:
    if not isinstance(entry, dict):
        return ""
    payload = entry.get("payload")
    if not isinstance(payload, dict):
        error = entry.get("error")
        if error and (state := usage_payload_state(error)):
            return (
                '<span class="control-compact-quota state" title="'
                + html.escape(state.get("message") or state.get("title") or "Quota unavailable")
                + '">'
                + html.escape(state.get("title") or "Quota unavailable")
                + "</span>"
            )
        return ""
    buckets = compact_quota_buckets(payload, model)
    if not buckets:
        if state := usage_payload_state(payload):
            return (
                '<span class="control-compact-quota state" title="'
                + html.escape(state.get("message") or state.get("title") or "Quota unavailable")
                + '">'
                + html.escape(state.get("title") or "Quota unavailable")
                + "</span>"
            )
        return ""
    rendered = [
        render_compact_quota_bucket_html(bucket, secondary=index > 0)
        for index, bucket in enumerate(buckets)
    ]
    return "".join(item for item in rendered if item)


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
        reset_credits_html=render_reset_credit_control(
            payload,
            profile,
            token,
            entry.get("reset_credit") if isinstance(entry, dict) else None,
        ),
        credits_html=render_quota_credits_pill(payload),
        error_html=error_html,
    )


def quota_count_window_payload(window: Any, fallback: str) -> dict[str, Any] | None:
    if not isinstance(window, dict):
        return None
    reset = quota_reset_label(window)
    remaining = window.get("remaining")
    if isinstance(remaining, (int, float)):
        value = f"{remaining:g}"
    else:
        allowed = window.get("allowed")
        if isinstance(allowed, bool):
            value = "available" if allowed else "not available"
        else:
            return None
    return {
        "label": quota_window_label(window, fallback),
        "value": value,
        "reset": reset,
    }


def quota_stack_payload(rate_limit: dict[str, Any]) -> dict[str, Any]:
    context = quota_stack_context(rate_limit)
    if context.get("count_html"):
        rows = [
            quota_count_window_payload(rate_limit.get("primary_window"), "5h"),
            quota_count_window_payload(rate_limit.get("secondary_window"), "Weekly"),
        ]
        return {
            "count_rows": [row for row in rows if row],
            "title_placeholder": True,
        }
    payload: dict[str, Any] = {}
    for key in (
        "primary_reset_text",
        "weekly_status",
        "primary_style",
        "weekly_style",
        "primary_text",
        "weekly_text",
        "primary_empty",
        "primary_not_enforced",
        "aria",
        "special",
    ):
        if key in context:
            payload[key] = context.get(key)
    return payload


def quota_bucket_payload(bucket: dict[str, Any]) -> dict[str, Any] | None:
    rate_limit = bucket.get("rate_limit")
    if not isinstance(rate_limit, dict):
        return None
    name = str(bucket.get("name") or "Quota bucket")
    feature = str(bucket.get("metered_feature") or "")
    return {
        "name": name,
        "metered_feature": feature,
        "title": f"Metered feature: {feature}" if feature and feature != "codex" else "",
        "stack": quota_stack_payload(rate_limit),
    }


def reset_credit_control_payload(payload: Any, reset_credit: Any = None) -> dict[str, Any] | None:
    if isinstance(reset_credit, dict) and reset_credit.get("blocks"):
        return {
            "label": str(reset_credit.get("label") or "Reset pending"),
            "message": str(reset_credit.get("message") or "Reset-credit use is temporarily disabled."),
            "disabled": True,
        }
    count = quota_payload_reset_credit_count(payload)
    if count <= 0:
        return None
    return {
        "label": f"Reset credit: {count}" if count == 1 else f"Reset credits: {count}",
        "message": "Use one rate-limit reset credit for this Codex CLI profile?",
        "disabled": False,
        "count": count,
    }


def quota_panel_payload(
    entry: dict[str, Any] | None,
    updated_label: str | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "updated": updated_label or "",
        "buckets": [],
        "state": None,
        "empty": "No quota cached",
        "refresh_error": "",
        "refresh_error_billing": False,
        "credits_label": "",
        "reset_credit": None,
    }
    if not entry:
        return data
    payload = entry.get("payload")
    error = entry.get("error")
    if updated_label is None:
        data["updated"] = quota_updated_label(entry)
    if not isinstance(payload, dict):
        if error:
            if state := usage_payload_state(error):
                data["state"] = state
                data["empty"] = ""
            else:
                data["empty"] = quota_refresh_error_message(error)
                data["refresh_error_billing"] = error_requires_billing(error)
        return data

    buckets = [item for item in (quota_bucket_payload(bucket) for bucket in quota_bucket_rows(payload)) if item]
    if buckets:
        data["buckets"] = buckets
        data["empty"] = ""
    elif state := usage_payload_state(payload):
        data["state"] = state
        data["empty"] = ""
    else:
        data["empty"] = "Quota payload has no bucket details"
    if error:
        data["refresh_error"] = quota_refresh_error_message(error)
        data["refresh_error_billing"] = error_requires_billing(error)
    data["credits_label"] = credit_balance_label(quota_payload_credits(payload))
    data["reset_credit"] = reset_credit_control_payload(payload, entry.get("reset_credit"))
    return data


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
        self.control_transcripts: dict[str, list[dict[str, Any]]] = {}
        self.control_history_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
        self.control_history_cache_lock = threading.Lock()
        self.control_history_inflight: dict[str, threading.Event] = {}
        self.profile_settings: dict[str, dict[str, Any]] = self.load_profile_settings()
        self.profile_settings_lock = threading.Lock()
        self.pinned_sessions: dict[str, str] = self.load_pinned_sessions()
        self.session_tab_order: dict[str, int] = self.load_session_tab_order()
        self.next_session_tab_order = (max(self.session_tab_order.values()) + 1) if self.session_tab_order else 0
        self.reset_credit_state: dict[str, dict[str, Any]] = self.load_reset_credit_state()
        self.reset_credit_state_lock = threading.Lock()
        self.reset_credit_verify_threads: dict[str, threading.Thread] = {}
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
        self.app_server_model_catalog_cache: dict[str, dict[str, Any]] = {}
        self.app_server_model_catalog_lock = threading.Lock()
        self.stats_lock = threading.Lock()
        self.ui_launchers: dict[int, dict[str, Any]] = {}
        self.ui_launchers_lock = threading.Lock()
        self.ui_state_lock = threading.Lock()
        self.ui_state_version = 0
        self.ui_state_dirty_reasons: dict[str, int] = {}
        self.ui_state_dirty_log: list[tuple[int, str]] = []
        self.resume_candidates_cache: dict[str, tuple[float, list[dict[str, str]]]] = {}
        self.resume_candidates_lock = threading.Lock()
        self.resume_candidates_inflight: dict[str, threading.Event] = {}

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

    def mark_ui_dirty(self, reason: str = "state") -> int:
        lock = getattr(self, "ui_state_lock", None)
        if lock is None:
            return 0
        key = reason or "state"
        with lock:
            self.ui_state_version = int(getattr(self, "ui_state_version", 0)) + 1
            version = self.ui_state_version
            reasons = getattr(self, "ui_state_dirty_reasons", None)
            if isinstance(reasons, dict):
                reasons[key] = int(reasons.get(key) or 0) + 1
            dirty_log = getattr(self, "ui_state_dirty_log", None)
            if not isinstance(dirty_log, list):
                dirty_log = []
                setattr(self, "ui_state_dirty_log", dirty_log)
            dirty_log.append((version, key))
            if len(dirty_log) > UI_DIRTY_LOG_LIMIT:
                del dirty_log[: len(dirty_log) - UI_DIRTY_LOG_LIMIT]
            return version

    def ui_state_revision(self) -> int:
        lock = getattr(self, "ui_state_lock", None)
        if lock is None:
            return int(getattr(self, "ui_state_version", 0) or 0)
        with lock:
            return int(getattr(self, "ui_state_version", 0) or 0)

    def ui_state_dirty_reasons_since(self, revision: int) -> set[str]:
        lock = getattr(self, "ui_state_lock", None)
        current = int(getattr(self, "ui_state_version", 0) or 0)
        if revision >= current:
            return set()
        if lock is None:
            return {"state"}
        with lock:
            current = int(getattr(self, "ui_state_version", 0) or 0)
            if revision >= current:
                return set()
            dirty_log = getattr(self, "ui_state_dirty_log", None)
            if not isinstance(dirty_log, list) or not dirty_log:
                return {"state"}
            first_revision = int(dirty_log[0][0] or 0)
            if first_revision > revision + 1:
                return {"state"}
            reasons = {str(reason or "state") for version, reason in dirty_log if int(version or 0) > revision}
            return reasons or {"state"}

    def ui_state_liveness_signature(self) -> tuple[Any, ...]:
        with self.active_lock:
            self.expire_websocket_work_locked()
            now = time.monotonic()
            request_rows = tuple(
                sorted(
                    (
                        str(request.get("profile") or ""),
                        str(request.get("session_key") or ""),
                    )
                    for request in self.active_requests.values()
                )
            )
            tunnel_rows = tuple(
                sorted(
                    (
                        str(tunnel.get("profile") or ""),
                        str(tunnel.get("session_key") or ""),
                        int(tunnel.get("pending_work") or 0),
                        str(tunnel.get("turn_id") or ""),
                        str(tunnel.get("thread_id") or ""),
                        bool(
                            now - float(tunnel.get("last_data_activity_monotonic") or 0.0)
                            < WEBSOCKET_SWITCH_IDLE_SECONDS
                        ),
                    )
                    for tunnel in self.active_websockets.values()
                )
            )
        return request_rows, tunnel_rows

    def ui_launcher_permission_args(self, permission: str) -> list[str]:
        key = permission if permission in UI_LAUNCHER_PERMISSION_PRESETS else "workspace-write"
        return list(UI_LAUNCHER_PERMISSION_PRESETS[key])

    def build_ui_launcher_args(
        self,
        *,
        cwd: str,
        mode: str,
        permission: str,
        session_id: str = "",
        prompt: str = "",
    ) -> list[str]:
        args = [str(launcher_path())]
        permission_args = self.ui_launcher_permission_args(permission)
        if mode == "resume-last":
            args.append("resume")
            args.extend(["--cd", cwd])
            args.extend(permission_args)
            args.append("--last")
        elif mode == "resume-session":
            if not session_id:
                raise StoreError("resume-session requires a session id")
            args.append("resume")
            args.extend(["--cd", cwd])
            args.extend(permission_args)
            args.append(session_id)
        elif mode == "fork-session":
            if not session_id:
                raise StoreError("fork-session requires a session id")
            args.append("fork")
            args.extend(["--cd", cwd])
            args.extend(permission_args)
            args.append(session_id)
        else:
            args.extend(["--cd", cwd])
            args.extend(permission_args)
        if prompt.strip():
            args.append(prompt.strip())
        return args

    def drain_ui_launcher_pty(self, pid: int, master_fd: int, session_key: str) -> None:
        captured = bytearray()
        try:
            while True:
                try:
                    chunk = os.read(master_fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                if len(captured) < CONTROL_TRANSCRIPT_EVENT_TEXT_LIMIT:
                    captured.extend(chunk[: CONTROL_TRANSCRIPT_EVENT_TEXT_LIMIT - len(captured)])
        finally:
            try:
                os.close(master_fd)
            except OSError:
                pass
            try:
                _, status = os.waitpid(pid, 0)
                exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)
            except OSError:
                exit_code = 1
            with self.ui_launchers_lock:
                self.ui_launchers.pop(pid, None)
            with self.active_lock:
                record = self.observed_sessions.get(session_key)
                if isinstance(record, dict):
                    record["ui_launcher_exit_code"] = exit_code
                    record["ui_launcher_exited_at"] = datetime.now().astimezone()
                    record["last_seen_monotonic"] = time.monotonic()
                    record["last_seen_at"] = datetime.now().astimezone()
            self.log_message("UI-launched provision session %s exited with status %s", session_key, exit_code)
            self.mark_ui_dirty("ui_launcher_exit")

    def launch_ui_session(
        self,
        *,
        session_key: str,
        mode: str,
        permission: str,
        profile: str | None = None,
        session_id: str = "",
        prompt: str = "",
    ) -> dict[str, Any]:
        key = normalize_session_key(session_key)
        if not key:
            raise StoreError("unknown session")
        with self.active_lock:
            record = self.observed_sessions.get(key)
            if not isinstance(record, dict):
                raise StoreError("unknown session")
            cwd = str(record.get("cwd") or key)
        cwd_path = Path(cwd).expanduser()
        if not cwd_path.is_dir():
            raise StoreError(f"working directory is not available: {cwd}")
        resolved_cwd = str(cwd_path.resolve(strict=False))
        launch_profile = profile if profile and self.store.profile_exists(profile) else self.control_profile_for_session(key)
        launch_key = f"{normalize_session_key(resolved_cwd)}::ui::{uuid.uuid4().hex[:10]}"
        with self.active_lock:
            self.observe_session_locked(launch_key, resolved_cwd, launch_profile)
            record = self.observed_sessions.get(launch_key)
            if isinstance(record, dict):
                record["parent_session_key"] = key
                record["ui_launched"] = True
                record["title"] = f"{session_display_name(resolved_cwd)} (UI launcher)"
            if launch_profile:
                self.pinned_sessions[launch_key] = launch_profile
                if record is not None:
                    record["pinned_profile"] = launch_profile
                self.save_pinned_sessions_locked()
        if launch_profile:
            launch_profile = launch_profile
        args = self.build_ui_launcher_args(
            cwd=resolved_cwd,
            mode=mode,
            permission=permission,
            session_id=session_id,
            prompt=prompt,
        )
        child_pid, master_fd = pty.fork()
        if child_pid == 0:
            try:
                os.chdir(resolved_cwd)
                env = os.environ.copy()
                env.setdefault("TERM", "xterm-256color")
                env.pop("PROVISION_DISABLE_PTY", None)
                env["PROVISION_SESSION_KEY"] = launch_key
                os.execvpe(args[0], args, env)
            except BaseException:
                os._exit(127)
        with self.ui_launchers_lock:
            self.ui_launchers[child_pid] = {
                "pid": child_pid,
                "session_key": launch_key,
                "parent_session_key": key,
                "cwd": resolved_cwd,
                "profile": launch_profile,
                "mode": mode,
                "permission": permission,
                "started_at": datetime.now().astimezone(),
            }
        with self.active_lock:
            record = self.observed_sessions.get(launch_key)
            if isinstance(record, dict):
                record["ui_launcher_pid"] = child_pid
                record["ui_launcher_mode"] = mode
                record["ui_launcher_permission"] = permission
                record["last_profile"] = launch_profile
                record["last_seen_monotonic"] = time.monotonic()
                record["last_seen_at"] = datetime.now().astimezone()
        thread = threading.Thread(
            target=self.drain_ui_launcher_pty,
            args=(child_pid, master_fd, launch_key),
            name=f"provision-ui-launcher-{child_pid}",
            daemon=True,
        )
        thread.start()
        self.log_message(
            "UI launched provision session %s profile=%s mode=%s permission=%s",
            key,
            launch_profile,
            mode,
            permission,
        )
        self.mark_ui_dirty("ui_launcher_start")
        return {
            "ok": True,
            "pid": child_pid,
            "session_key": launch_key,
            "parent_session_key": key,
            "cwd": resolved_cwd,
            "profile": launch_profile,
            "mode": mode,
            "permission": permission,
        }

    def forget_session(self, session_key: str, *, force_live: bool = False) -> None:
        key = normalize_session_key(session_key)
        if not key:
            raise StoreError("unknown session")
        launcher_pids: list[int] = []
        sockets: list[socket.socket] = []
        control_paths_to_unlink: list[Path] = []
        with self.ui_launchers_lock:
            live_ui_launcher_pids = set(self.ui_launchers)
        with self.active_lock:
            self.expire_websocket_work_locked()
            record = self.observed_sessions.get(key)
            if not isinstance(record, dict):
                raise StoreError("unknown session")
            has_request = any(request.get("session_key") == key for request in self.active_requests.values())
            has_tunnel = any(tunnel.get("session_key") == key for tunnel in self.active_websockets.values())
            control_path = str(record.get("control_path") or "")
            control_live = bool(control_path and Path(control_path).exists())
            ui_pid = record.get("ui_launcher_pid")
            ui_live = isinstance(ui_pid, int) and ui_pid in live_ui_launcher_pids
            live = has_request or has_tunnel or control_live or ui_live
            if live and not force_live:
                raise StoreError("session still appears active; close it before forgetting")
            if live:
                if control_live:
                    control_candidate = Path(control_path)
                    try:
                        control_candidate.resolve(strict=False).relative_to(
                            self.paths.launchers.resolve(strict=False)
                        )
                        control_paths_to_unlink.append(control_candidate)
                    except (OSError, ValueError):
                        pass
                launcher_pid = record.get("launcher_pid")
                for pid in (ui_pid, launcher_pid):
                    if isinstance(pid, int) and pid > 0 and pid not in launcher_pids:
                        launcher_pids.append(pid)
                for tunnel in self.active_websockets.values():
                    if tunnel.get("session_key") != key:
                        continue
                    for socket_key in ("downstream", "upstream"):
                        value = tunnel.get(socket_key)
                        if isinstance(value, socket.socket):
                            sockets.append(value)
            self.observed_sessions.pop(key, None)
            self.control_transcripts.pop(key, None)
            changed_pin = self.pinned_sessions.pop(key, None) is not None
            changed_tab_order = self.session_tab_order.pop(key, None) is not None
            if changed_pin:
                self.save_pinned_sessions_locked()
            if changed_tab_order:
                self.save_session_tab_order_locked()
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for pid in launcher_pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        for path in control_paths_to_unlink:
            try:
                path.unlink()
            except OSError:
                pass
        self.mark_ui_dirty("session_forget")

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

    def resume_candidates_for_cwd(self, cwd: str) -> list[dict[str, str]]:
        key = normalized_path_text(cwd)
        if not key:
            return []
        lock = getattr(self, "resume_candidates_lock", None)
        cache = getattr(self, "resume_candidates_cache", None)
        inflight = getattr(self, "resume_candidates_inflight", None)
        if lock is None or not isinstance(cache, dict) or not isinstance(inflight, dict):
            return codex_resume_candidates_for_cwd(cwd, limit=RESUME_CANDIDATE_LIMIT)

        owner = False
        event: threading.Event
        while True:
            now = time.monotonic()
            with lock:
                cached = cache.get(key)
                if cached and now - cached[0] < RESUME_CANDIDATE_CACHE_SECONDS:
                    return [dict(item) for item in cached[1]]
                existing = inflight.get(key)
                if existing is None:
                    event = threading.Event()
                    inflight[key] = event
                    owner = True
                    break
                event = existing
            event.wait()

        assert owner
        try:
            candidates = codex_resume_candidates_for_cwd(cwd, limit=RESUME_CANDIDATE_LIMIT)
        except BaseException:
            with lock:
                inflight.pop(key, None)
                event.set()
            raise
        with lock:
            cache[key] = (time.monotonic(), [dict(item) for item in candidates])
            inflight.pop(key, None)
            event.set()
        return candidates

    def resume_candidates_for_session(self, session_key: str) -> list[dict[str, str]]:
        with self.active_lock:
            record = self.observed_sessions.get(session_key)
            if not isinstance(record, dict):
                raise StoreError("unknown session")
            cwd = str(record.get("cwd") or session_key)
        return self.resume_candidates_for_cwd(cwd)

    def history_turns_for_cwd(self, cwd: str) -> list[dict[str, Any]]:
        key = normalized_path_text(cwd)
        if not key:
            return []
        lock = getattr(self, "control_history_cache_lock", None)
        cache = getattr(self, "control_history_cache", None)
        inflight = getattr(self, "control_history_inflight", None)
        if lock is None or not isinstance(cache, dict) or not isinstance(inflight, dict):
            return codex_history_turn_index_for_cwd(cwd)

        owner = False
        event: threading.Event
        while True:
            now = time.monotonic()
            with lock:
                cached = cache.get(key)
                if cached and now - cached[0] < CONTROL_HISTORY_CACHE_SECONDS:
                    return [dict(item) for item in cached[1]]
                existing = inflight.get(key)
                if existing is None:
                    event = threading.Event()
                    inflight[key] = event
                    owner = True
                    break
                event = existing
            event.wait()

        assert owner
        try:
            turns = codex_history_turn_index_for_cwd(cwd)
        except BaseException:
            with lock:
                inflight.pop(key, None)
                event.set()
            raise
        with lock:
            # Cache from completion, not from before the potentially expensive scan.
            cache[key] = (time.monotonic(), [dict(item) for item in turns])
            inflight.pop(key, None)
            event.set()
        return turns

    def history_turn_index_for_session(self, session_key: str) -> list[dict[str, Any]]:
        with self.active_lock:
            record = self.observed_sessions.get(session_key)
            if not isinstance(record, dict):
                raise StoreError("unknown session")
            cwd = str(record.get("cwd") or session_key)
            observed_turns = self.control_turns_from_transcript(
                self.control_transcript_snapshot(session_key)
            )
        history_turns = self.history_turns_for_cwd(cwd)
        return [
            turn
            for turn in history_turns
            if not any(history_turn_duplicates_observed(turn, observed) for observed in observed_turns)
        ]

    def history_turn_payload_for_session(self, session_key: str, turn_key: str) -> dict[str, Any]:
        with self.active_lock:
            record = self.observed_sessions.get(session_key)
            if not isinstance(record, dict):
                raise StoreError("unknown session")
            cwd = str(record.get("cwd") or session_key)
        payload = codex_history_turn_payload_for_cwd(cwd, turn_key)
        if not payload:
            raise StoreError("historical turn was not found for this session")
        payload["session_key"] = session_key
        return payload

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
        self.mark_ui_dirty("profile_model")

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
        self.mark_ui_dirty("login_required")

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
        if changed:
            self.mark_ui_dirty("login_required_clear")

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
        self.mark_ui_dirty("billing_required")

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
        if changed:
            self.mark_ui_dirty("billing_required_clear")

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
        self.mark_ui_dirty("profile_fast_mode")

    def toggle_profile_fast_mode(self, profile: str) -> bool:
        enabled = not self.profile_fast_mode(profile)
        self.set_profile_fast_mode(profile, enabled)
        return enabled

    def load_reset_credit_state(self) -> dict[str, dict[str, Any]]:
        try:
            with self.paths.reset_credit_state.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(payload, dict):
            return {}
        states: dict[str, dict[str, Any]] = {}
        for raw_profile, raw_state in payload.items():
            if (
                isinstance(raw_profile, str)
                and isinstance(raw_state, dict)
                and self.store.profile_exists(raw_profile)
            ):
                states[raw_profile] = dict(raw_state)
        return states

    def save_reset_credit_state_locked(self) -> None:
        try:
            self.paths.reset_credit_state.parent.mkdir(parents=True, exist_ok=True)
            temp = self.paths.reset_credit_state.with_suffix(
                self.paths.reset_credit_state.suffix + ".tmp"
            )
            encoded = json.dumps(self.reset_credit_state, indent=2, sort_keys=True) + "\n"
            with temp.open("w", encoding="utf-8") as handle:
                handle.write(encoded)
            temp.chmod(0o600)
            temp.replace(self.paths.reset_credit_state)
            self.paths.reset_credit_state.chmod(0o600)
        except OSError as exc:
            raise StoreError(f"failed to save reset-credit state: {exc}") from exc

    def reset_credit_public_state_from_state(
        self,
        state: dict[str, Any],
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current = now.astimezone() if now else datetime.now().astimezone()
        status = str(state.get("status") or "")
        requested_at = parse_reset_datetime(state.get("requested_at"))
        verified_at = parse_reset_datetime(state.get("verified_at"))
        cooldown_until = parse_reset_datetime(state.get("cooldown_until"))
        guard_until = parse_reset_datetime(state.get("guard_until"))
        blocks = False
        label = ""
        title = ""

        if status in {"pending", "verifying"}:
            blocks = True
            label = "Reset verifying"
            title = (
                "Reset credit was accepted. Provision is waiting for the normal usage "
                "endpoint to confirm the refreshed quota before allowing another reset."
            )
        elif status == "unconfirmed":
            blocks = bool(cooldown_until and cooldown_until > current)
            label = "Reset unconfirmed"
            title = (
                "Reset credit was accepted, but the normal usage endpoint has not confirmed "
                "the quota recovery yet. Another reset is blocked to protect remaining credits."
            )
        elif status == "verified":
            blocks = bool(cooldown_until and cooldown_until > current)
            label = "Reset used"
            title = "Reset credit verified. Further reset-credit use is cooling down."
        elif status:
            blocks = bool(guard_until and guard_until > current)
            label = "Reset guarded" if blocks else "Reset available"
            title = str(state.get("error") or state.get("outcome") or "Previous reset-credit attempt did not complete.")

        if cooldown_until and cooldown_until > current:
            title = f"{title} Disabled until {format_status_updated_at(cooldown_until)}.".strip()
        elif guard_until and guard_until > current:
            title = f"{title} Retry after {format_status_updated_at(guard_until)}.".strip()
        if requested_at:
            title = f"{title} Requested {format_status_updated_at(requested_at)}.".strip()
        if verified_at:
            title = f"{title} Verified {format_status_updated_at(verified_at)}.".strip()

        return {
            "status": status,
            "label": label,
            "message": title,
            "blocks": blocks,
            "requested_at": utc_timestamp(requested_at) if requested_at else "",
            "verified_at": utc_timestamp(verified_at) if verified_at else "",
            "cooldown_until": utc_timestamp(cooldown_until) if cooldown_until else "",
            "guard_until": utc_timestamp(guard_until) if guard_until else "",
        }

    def normalize_reset_credit_state_locked(
        self,
        profile: str,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current = now.astimezone() if now else datetime.now().astimezone()
        state = self.reset_credit_state.get(profile)
        if not isinstance(state, dict):
            return {}
        changed = False
        status = str(state.get("status") or "")
        requested_at = parse_reset_datetime(state.get("requested_at"))
        cooldown_until = parse_reset_datetime(state.get("cooldown_until"))
        guard_until = parse_reset_datetime(state.get("guard_until"))
        if status in {"pending", "verifying"} and requested_at:
            if requested_at + timedelta(seconds=RESET_CREDIT_VERIFY_TIMEOUT_SECONDS) < current:
                state["status"] = "unconfirmed"
                state["last_error"] = "usage endpoint did not confirm the reset before the verification timeout"
                changed = True
        status = str(state.get("status") or "")
        if status in {"verified", "unconfirmed"} and cooldown_until and cooldown_until <= current:
            self.reset_credit_state.pop(profile, None)
            self.reset_credit_verify_threads.pop(profile, None)
            self.save_reset_credit_state_locked()
            return {}
        if status not in {"pending", "verifying", "verified", "unconfirmed"}:
            if guard_until and guard_until <= current:
                self.reset_credit_state.pop(profile, None)
                self.reset_credit_verify_threads.pop(profile, None)
                self.save_reset_credit_state_locked()
                return {}
        if changed:
            self.save_reset_credit_state_locked()
        return dict(state)

    def reset_credit_status(self, profile: str) -> dict[str, Any]:
        lock = getattr(self, "reset_credit_state_lock", None)
        if lock is None:
            return {}
        with lock:
            state = self.normalize_reset_credit_state_locked(profile)
            if not state:
                return {}
            return self.reset_credit_public_state_from_state(state)

    def reset_credit_awaiting_usage_confirmation(self, profile: str) -> bool:
        lock = getattr(self, "reset_credit_state_lock", None)
        if lock is None:
            return False
        with lock:
            state = self.normalize_reset_credit_state_locked(profile)
            return str(state.get("status") or "") in {"pending", "verifying", "unconfirmed"}

    def begin_reset_credit_attempt(self, profile: str, idempotency_key: str) -> None:
        if not self.store.profile_exists(profile):
            raise StoreError(f"unknown profile: {profile}")
        snapshot = self.usage_cache_snapshot(profile) or {}
        before_payload = snapshot.get("payload")
        now = datetime.now(timezone.utc)
        with self.reset_credit_state_lock:
            existing = self.normalize_reset_credit_state_locked(profile, now=now)
            public = self.reset_credit_public_state_from_state(existing, now=now) if existing else {}
            if public.get("blocks"):
                raise ResetCreditGuardError(
                    str(public.get("message") or "Reset credit is already pending for this profile.")
                )
            state: dict[str, Any] = {
                "status": "pending",
                "idempotency_key": idempotency_key,
                "requested_at": utc_timestamp(now),
                "cooldown_until": utc_timestamp(now + timedelta(seconds=RESET_CREDIT_COOLDOWN_SECONDS)),
            }
            if isinstance(before_payload, dict):
                state["before_payload"] = before_payload
            self.reset_credit_state[profile] = state
            self.save_reset_credit_state_locked()
        self.mark_ui_dirty("reset_credit_begin")

    def mark_reset_credit_attempt_error(
        self,
        profile: str,
        idempotency_key: str,
        error: BaseException | str,
    ) -> None:
        now = datetime.now(timezone.utc)
        with self.reset_credit_state_lock:
            state = self.reset_credit_state.setdefault(profile, {})
            state["status"] = "consume_error"
            state["idempotency_key"] = idempotency_key
            state.setdefault("requested_at", utc_timestamp(now))
            state["error"] = str(error)[:500]
            state["guard_until"] = utc_timestamp(now + timedelta(seconds=RESET_CREDIT_ERROR_GUARD_SECONDS))
            self.save_reset_credit_state_locked()
        self.mark_ui_dirty("reset_credit_error")

    def mark_reset_credit_outcome(
        self,
        profile: str,
        *,
        idempotency_key: str,
        outcome: str,
        payload: dict[str, Any] | None,
    ) -> None:
        now = datetime.now(timezone.utc)
        with self.reset_credit_state_lock:
            state = self.reset_credit_state.setdefault(profile, {})
            state["idempotency_key"] = idempotency_key
            state["outcome"] = outcome
            state["last_checked_at"] = utc_timestamp(now)
            if outcome == "reset":
                state["status"] = "verifying"
                state.setdefault("requested_at", utc_timestamp(now))
                state.setdefault(
                    "cooldown_until",
                    utc_timestamp(now + timedelta(seconds=RESET_CREDIT_COOLDOWN_SECONDS)),
                )
                if isinstance(payload, dict):
                    state["app_server_payload"] = payload
            else:
                state["status"] = outcome or "unknown"
                state["guard_until"] = utc_timestamp(now + timedelta(seconds=RESET_CREDIT_ERROR_GUARD_SECONDS))
            self.save_reset_credit_state_locked()
        self.mark_ui_dirty("reset_credit_outcome")
        if outcome == "reset":
            self.schedule_reset_credit_verification(
                profile,
                initial_delay=RESET_CREDIT_VERIFY_INITIAL_DELAY_SECONDS,
            )

    def reconcile_reset_credit_verification(
        self,
        profile: str,
        payload: dict[str, Any],
        *,
        source: str,
    ) -> bool:
        if source != "usage_fetch":
            return False
        lock = getattr(self, "reset_credit_state_lock", None)
        if lock is None:
            return False
        now = datetime.now(timezone.utc)
        verified = False
        with lock:
            state = self.normalize_reset_credit_state_locked(profile, now=now)
            if str(state.get("status") or "") not in {"pending", "verifying", "unconfirmed"}:
                return False
            state["last_checked_at"] = utc_timestamp(now)
            before_payload = state.get("before_payload")
            if reset_credit_confirmation_matches(before_payload, payload):
                state["status"] = "verified"
                state["verified_at"] = utc_timestamp(now)
                state["cooldown_until"] = utc_timestamp(
                    now + timedelta(seconds=RESET_CREDIT_COOLDOWN_SECONDS)
                )
                verified = True
            self.reset_credit_state[profile] = state
            self.save_reset_credit_state_locked()
        if verified:
            event = {
                "type": "reset_credit",
                "profile": profile,
                "outcome": "verified",
                "idempotency_key": str(state.get("idempotency_key") or ""),
            }
            self.append_reset_credit_event(event)
            self.append_stats_event(event)
            self.mark_ui_dirty("reset_credit_verified")
        return verified

    def reset_credit_profiles_needing_verification(self) -> list[str]:
        with self.reset_credit_state_lock:
            return [
                profile
                for profile in list(self.reset_credit_state)
                if str(self.normalize_reset_credit_state_locked(profile).get("status") or "")
                in {"pending", "verifying", "unconfirmed"}
            ]

    def schedule_reset_credit_verification(
        self,
        profile: str,
        *,
        initial_delay: float = 0.0,
    ) -> None:
        with self.reset_credit_state_lock:
            state = self.normalize_reset_credit_state_locked(profile)
            if str(state.get("status") or "") not in {"pending", "verifying", "unconfirmed"}:
                return
            current = self.reset_credit_verify_threads.get(profile)
            if current and current.is_alive():
                return
            thread = threading.Thread(
                target=self.reset_credit_verification_loop,
                args=(profile, max(0.0, float(initial_delay))),
                daemon=True,
            )
            self.reset_credit_verify_threads[profile] = thread
            thread.start()

    def reset_credit_verification_loop(self, profile: str, initial_delay: float) -> None:
        if initial_delay > 0:
            self.usage_auto_refresh_stop.wait(initial_delay)
        started = time.monotonic()
        while not self.usage_auto_refresh_stop.is_set():
            if not self.reset_credit_awaiting_usage_confirmation(profile):
                return
            try:
                self.usage_payload_for_profile(profile, force=True)
            except Exception as exc:
                self.log_message("reset-credit verification refresh for profile %s failed: %s", profile, exc)
            if not self.reset_credit_awaiting_usage_confirmation(profile):
                return
            if time.monotonic() - started >= RESET_CREDIT_VERIFY_TIMEOUT_SECONDS:
                with self.reset_credit_state_lock:
                    state = self.normalize_reset_credit_state_locked(profile)
                    if str(state.get("status") or "") in {"pending", "verifying"}:
                        state["status"] = "unconfirmed"
                        state["last_error"] = "usage endpoint did not confirm the reset before the verification timeout"
                        self.reset_credit_state[profile] = state
                        self.save_reset_credit_state_locked()
                return
            self.usage_auto_refresh_stop.wait(RESET_CREDIT_VERIFY_INTERVAL_SECONDS)

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

    def load_session_tab_order(self) -> dict[str, int]:
        try:
            with self.paths.session_tabs.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(payload, dict):
            return {}
        result: dict[str, int] = {}
        for key, value in payload.items():
            normalized = normalize_session_key(str(key))
            if not normalized or isinstance(value, bool):
                continue
            try:
                result[normalized] = max(0, int(value))
            except (TypeError, ValueError):
                continue
        return result

    def ensure_session_tab_order_state(self) -> None:
        if not hasattr(self, "session_tab_order"):
            self.session_tab_order = {}
        if not hasattr(self, "next_session_tab_order"):
            self.next_session_tab_order = (
                max(self.session_tab_order.values()) + 1 if self.session_tab_order else 0
            )

    def save_session_tab_order_locked(self) -> None:
        self.ensure_session_tab_order_state()
        if not hasattr(self, "paths"):
            return
        known = {
            key: int(order)
            for key, order in self.session_tab_order.items()
            if key in self.observed_sessions
        }
        self.session_tab_order = known
        if known:
            self.next_session_tab_order = max(known.values()) + 1
        try:
            self.paths.session_tabs.parent.mkdir(parents=True, exist_ok=True)
            temp = self.paths.session_tabs.with_suffix(self.paths.session_tabs.suffix + ".tmp")
            encoded = json.dumps(dict(sorted(known.items(), key=lambda item: item[1])), indent=2) + "\n"
            with temp.open("w", encoding="utf-8") as handle:
                handle.write(encoded)
            temp.chmod(0o600)
            temp.replace(self.paths.session_tabs)
            self.paths.session_tabs.chmod(0o600)
        except OSError as exc:
            raise StoreError(f"failed to save session tab order: {exc}") from exc

    def session_tab_order_for_key_locked(self, key: str) -> int:
        self.ensure_session_tab_order_state()
        existing = self.session_tab_order.get(key)
        if existing is not None:
            return int(existing)
        order = self.next_session_tab_order
        self.next_session_tab_order += 1
        self.session_tab_order[key] = order
        return order

    def reorder_sessions(self, session_keys: list[str]) -> None:
        self.ensure_session_tab_order_state()
        normalized_keys: list[str] = []
        seen: set[str] = set()
        for key in session_keys:
            normalized = normalize_session_key(str(key))
            if not normalized or normalized in seen:
                continue
            normalized_keys.append(normalized)
            seen.add(normalized)
        with self.active_lock:
            if not normalized_keys:
                raise StoreError("no session order supplied")
            observed_keys = set(self.observed_sessions)
            if not any(key in observed_keys for key in normalized_keys):
                raise StoreError("no known sessions supplied")
            ordered = 0
            for key in normalized_keys:
                if key not in observed_keys:
                    continue
                self.session_tab_order[key] = ordered
                record = self.observed_sessions.get(key)
                if isinstance(record, dict):
                    record["tab_order"] = ordered
                ordered += 1
            remaining = sorted(
                (key for key in observed_keys if key not in self.session_tab_order or key not in normalized_keys),
                key=lambda key: (
                    int(self.session_tab_order.get(key, self.observed_sessions[key].get("tab_order", 0))),
                    float(self.observed_sessions[key].get("first_seen_monotonic") or 0.0),
                    key,
                ),
            )
            for key in remaining:
                self.session_tab_order[key] = ordered
                self.observed_sessions[key]["tab_order"] = ordered
                ordered += 1
            self.next_session_tab_order = ordered
            self.save_session_tab_order_locked()
        self.mark_ui_dirty("session_reorder")

    def observe_session(
        self,
        cwd: str,
        profile: str | None = None,
        *,
        control_path: str | None = None,
        launcher_pid: int | None = None,
        pty_managed: bool = False,
        clear_control_path: bool = False,
    ) -> str:
        key = normalize_session_key(cwd)
        if not key:
            return ""
        with self.active_lock:
            self.observe_session_locked(
                key,
                cwd,
                profile,
                control_path=control_path,
                launcher_pid=launcher_pid,
                pty_managed=pty_managed,
                clear_control_path=clear_control_path,
            )
        return key

    def observe_session_locked(
        self,
        key: str,
        cwd: str,
        profile: str | None = None,
        *,
        control_path: str | None = None,
        launcher_pid: int | None = None,
        pty_managed: bool = False,
        clear_control_path: bool = False,
    ) -> None:
        now = time.monotonic()
        self.ensure_session_tab_order_state()
        new_tab_order = key not in self.session_tab_order
        new_session = key not in self.observed_sessions
        record = self.observed_sessions.setdefault(
            key,
            {
                "key": key,
                "cwd": cwd,
                "display": compact_session_path(cwd),
                "name": session_display_name(cwd),
                "first_seen_monotonic": now,
                "tab_order": self.session_tab_order_for_key_locked(key),
            },
        )
        previous_cwd = str(record.get("cwd") or "")
        previous_profile = str(record.get("last_profile") or "")
        previous_control_path = str(record.get("control_path") or "")
        previous_pty_managed = bool(record.get("pty_managed"))
        previous_launcher_pid = record.get("launcher_pid")
        record["tab_order"] = self.session_tab_order_for_key_locked(key)
        record["cwd"] = cwd
        record["display"] = compact_session_path(cwd)
        record["name"] = session_display_name(cwd)
        record["last_seen_monotonic"] = now
        record["last_seen_at"] = datetime.now().astimezone()
        if profile:
            record["last_profile"] = profile
        if control_path:
            record["control_path"] = control_path
            record["pty_managed"] = bool(pty_managed)
        elif clear_control_path:
            record.pop("control_path", None)
            record["pty_managed"] = False
        if launcher_pid is not None:
            record["launcher_pid"] = launcher_pid
        elif clear_control_path:
            record.pop("launcher_pid", None)
        if new_tab_order:
            self.save_session_tab_order_locked()
        state_changed = (
            new_session
            or new_tab_order
            or previous_cwd != str(record.get("cwd") or "")
            or previous_profile != str(record.get("last_profile") or "")
            or previous_control_path != str(record.get("control_path") or "")
            or previous_pty_managed != bool(record.get("pty_managed"))
            or previous_launcher_pid != record.get("launcher_pid")
        )
        if state_changed:
            self.mark_ui_dirty("session_observe")

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
        self.mark_ui_dirty("session_pin")

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
        self.mark_ui_dirty("session_unpin")

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
        self.mark_ui_dirty("request_begin")
        return request_id

    def end_request(self, request_id: int | None) -> None:
        changed = False
        with self.active_lock:
            if request_id is not None:
                changed = self.active_requests.pop(request_id, None) is not None
        if changed:
            self.mark_ui_dirty("request_end")

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
                "thread_id": None,
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
        self.mark_ui_dirty("websocket_begin")
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
        self.mark_ui_dirty("websocket_session")

    def attach_websocket_upstream(self, tunnel_id: int, upstream: socket.socket) -> None:
        with self.active_lock:
            tunnel = self.active_websockets.get(tunnel_id)
            if tunnel is not None:
                tunnel["upstream"] = upstream

    def remember_websocket_thread(self, tunnel_id: int, thread_id: str | None) -> None:
        if not thread_id:
            return
        with self.active_lock:
            tunnel = self.active_websockets.get(tunnel_id)
            if tunnel is None:
                return
            tunnel["thread_id"] = thread_id
            session_key = tunnel.get("session_key")
            if isinstance(session_key, str) and session_key:
                record = self.observed_sessions.get(session_key)
                if isinstance(record, dict):
                    record["thread_id"] = thread_id
                    record["last_seen_monotonic"] = time.monotonic()
                    record["last_seen_at"] = datetime.now().astimezone()
        self.mark_ui_dirty("websocket_thread")

    def touch_websocket_data(self, tunnel_id: int) -> None:
        with self.active_lock:
            tunnel = self.active_websockets.get(tunnel_id)
            if tunnel is not None:
                tunnel["last_data_activity_monotonic"] = time.monotonic()
        self.mark_ui_dirty("websocket_data")

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
        self.mark_ui_dirty("websocket_traffic")

    def websocket_service_tier(self, tunnel_id: int) -> str | None:
        with self.active_lock:
            service_tier = self.active_websockets.get(tunnel_id, {}).get("service_tier")
        return service_tier if isinstance(service_tier, str) else None

    def websocket_session_key(self, tunnel_id: int) -> str | None:
        with self.active_lock:
            session_key = self.active_websockets.get(tunnel_id, {}).get("session_key")
        return session_key if isinstance(session_key, str) else None

    @staticmethod
    def transcript_line_has_open_markdown_span(line: str) -> bool:
        stripped = line.strip()
        if not stripped:
            return False
        if re.match(r"^(?:[-*+]|\d+\.)\s*(?:\[[ xX]?\])?\s*(?:\*\*|__|`)?$", stripped):
            return True
        if stripped.endswith(("**", "__", "*", "_", "`")):
            return True
        if stripped.count("**") % 2:
            return True
        if stripped.count("__") % 2:
            return True
        if stripped.count("`") % 2:
            return True
        return False

    @classmethod
    def transcript_stream_separator(cls, existing: str, text: str) -> str:
        if not existing or not text:
            return ""
        existing_line = existing.rsplit("\n", 1)[-1]
        if existing.endswith(("\n", "\r")):
            return ""
        if (
            re.match(r"\s*(?:[-*+]\s+|-\d+\s+|\d+\.\s+|#{1,6}\s+|>\s?|```)", text)
            and not cls.transcript_line_has_open_markdown_span(existing_line)
        ):
            return "\n"
        if existing[-1].isspace() or text[0].isspace():
            return ""
        if cls.transcript_line_has_open_markdown_span(existing_line):
            return ""
        if re.match(r"\s*(?:[-*+]|\d+\.)\s+", existing_line) and (
            text[0].isupper() or text[0] in "\"'`("
        ):
            return "\n\n"
        if existing[-1] in ".!?" and (text[0].isupper() or text[0] in "\"'`("):
            return "\n"
        if existing[-1].islower() and text[0].isdigit():
            return " "
        return ""

    @staticmethod
    def transcript_display_text(text: str) -> str:
        if len(text) <= CONTROL_TRANSCRIPT_TEXT_LIMIT:
            return text
        return text[:CONTROL_TRANSCRIPT_TEXT_LIMIT].rstrip() + "\n...[truncated]"

    @classmethod
    def set_transcript_item_text(cls, item: dict[str, Any], role: str, full_text: str) -> None:
        if role in {"user", "user_pending", "resume", "context_compaction"}:
            full_text = clean_control_user_text(full_text)
        display = cls.transcript_display_text(full_text)
        item["text"] = display
        if display != full_text:
            item["full_text"] = full_text
            item["truncated"] = True
        else:
            item.pop("full_text", None)
            item.pop("truncated", None)
        item["search_text"] = f"{role} {full_text}"

    @staticmethod
    def transcript_item_full_text(item: dict[str, Any]) -> str:
        return str(item.get("full_text") or item.get("text") or "")

    @classmethod
    def transcript_item_matches(
        cls,
        item: dict[str, Any],
        *,
        role: str,
        text: str,
        turn_id: str,
    ) -> bool:
        if item.get("role") != role:
            return False
        existing_turn = str(item.get("turn_id") or "")
        if existing_turn and not turn_id:
            return False
        if turn_id and existing_turn and existing_turn != turn_id:
            return False
        existing_text = transcript_identity_text(cls.transcript_item_full_text(item))
        return existing_text == transcript_identity_text(text)

    @classmethod
    def transcript_text_matches(cls, item: dict[str, Any], text: str) -> bool:
        existing_text = transcript_identity_text(cls.transcript_item_full_text(item))
        return existing_text == transcript_identity_text(text)

    def promote_pending_user_transcript(
        self,
        transcript: list[dict[str, Any]],
        *,
        text: str,
        turn_id: str,
        profile: str,
        now: str,
    ) -> bool:
        for index in range(len(transcript) - 1, -1, -1):
            existing = transcript[index]
            if existing.get("role") != "user_pending":
                continue
            if not self.transcript_text_matches(existing, text):
                continue
            if turn_id:
                existing["role"] = "user"
                existing["turn_id"] = turn_id
            existing["profile"] = profile or existing.get("profile") or ""
            existing["updated_at"] = now
            self.set_transcript_item_text(existing, str(existing.get("role") or "user_pending"), text)
            replay_after_pending = any(
                item.get("role") in {"resume", "context_compaction"}
                for item in transcript[index + 1 :]
            )
            if replay_after_pending:
                transcript.append(transcript.pop(index))
            return True
        return False

    def recent_pending_user_prompt(self, session_key: str) -> str:
        transcript = self.control_transcripts.get(session_key, [])
        for existing in reversed(transcript[-12:]):
            if existing.get("role") != "user_pending":
                continue
            text = self.transcript_item_full_text(existing)
            if text.strip():
                return text
        return ""

    def assign_recent_user_turn_id(
        self,
        *,
        session_key: str,
        turn_id: str,
        profile: str,
    ) -> None:
        if not session_key or not turn_id:
            return
        transcript = getattr(self, "control_transcripts", {}).get(session_key)
        if not transcript:
            return
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        for existing in reversed(transcript[-12:]):
            if existing.get("role") not in {"user_pending", "user"}:
                continue
            if str(existing.get("turn_id") or ""):
                continue
            existing["role"] = "user"
            existing["turn_id"] = turn_id
            existing["profile"] = profile or existing.get("profile") or ""
            existing["updated_at"] = now
            text = self.transcript_item_full_text(existing)
            self.set_transcript_item_text(existing, "user", text)
            return

    def assign_recent_user_turn_id_in_transcript(
        self,
        transcript: list[dict[str, Any]],
        *,
        turn_id: str,
        profile: str,
        now: str,
    ) -> None:
        if not turn_id:
            return
        for existing in reversed(transcript[-12:]):
            if existing.get("role") not in {"user_pending", "user"}:
                continue
            if str(existing.get("turn_id") or ""):
                continue
            existing["role"] = "user"
            existing["turn_id"] = turn_id
            existing["profile"] = profile or existing.get("profile") or ""
            existing["updated_at"] = now
            text = self.transcript_item_full_text(existing)
            self.set_transcript_item_text(existing, "user", text)
            return

    def append_context_replay_marker(
        self,
        transcript: list[dict[str, Any]],
        *,
        turn_id: str,
        profile: str,
        now: str,
    ) -> None:
        text = (
            "Context replay observed at a resume or compaction boundary; "
            "duplicate resumed context was suppressed."
        )
        for existing in reversed(transcript[-12:]):
            if existing.get("role") != "context_compaction":
                continue
            if str(existing.get("turn_id") or "") != turn_id:
                continue
            existing["updated_at"] = now
            existing["profile"] = profile or existing.get("profile") or ""
            return
        item = {
            "ts": now,
            "updated_at": now,
            "role": "context_compaction",
            "turn_id": turn_id,
            "profile": profile,
        }
        self.set_transcript_item_text(item, "context_compaction", text)
        transcript.append(item)

    @staticmethod
    def transcript_has_activity_after(
        transcript: list[dict[str, Any]],
        index: int,
        *,
        turn_id: str,
    ) -> bool:
        for later in transcript[index + 1 :]:
            later_turn = str(later.get("turn_id") or "")
            if turn_id and later_turn and later_turn != turn_id:
                continue
            if later.get("role") in {"resume", "user", "context_compaction"}:
                continue
            return True
        return False

    def append_control_transcript(
        self,
        *,
        session_key: str,
        role: str,
        text: str,
        turn_id: str = "",
        profile: str = "",
        append: bool = False,
        call_id: str = "",
    ) -> None:
        if role in {"user", "user_pending", "resume", "context_compaction"}:
            text = clean_control_user_text(text)
        if not session_key or not text:
            return
        self.mark_ui_dirty("transcript")
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        transcript = self.control_transcripts.setdefault(session_key, [])
        if role == "user" and not turn_id and not append:
            for index in range(len(transcript) - 1, -1, -1):
                existing = transcript[index]
                if existing.get("role") != "user":
                    continue
                if not self.transcript_text_matches(existing, text):
                    continue
                replay_marker_seen = any(
                    item.get("role") in {"resume", "context_compaction"}
                    for item in transcript[index + 1 :]
                )
                if replay_marker_seen:
                    existing["updated_at"] = now
                    return
                break
        if role not in {"user", "user_pending", "resume", "context_compaction"} and turn_id:
            self.assign_recent_user_turn_id_in_transcript(
                transcript,
                turn_id=turn_id,
                profile=profile,
                now=now,
            )
        if role == "user" and not append and self.promote_pending_user_transcript(
            transcript,
            text=text,
            turn_id=turn_id,
            profile=profile,
            now=now,
        ):
            return
        if role == "resume" and not append and transcript and transcript[-1].get("role") == "resume":
            existing = transcript[-1]
            existing_turn = str(existing.get("turn_id") or "")
            if not turn_id or not existing_turn or existing_turn == turn_id:
                existing_full = self.transcript_item_full_text(existing)
                if transcript_identity_text(text) == transcript_identity_text(existing_full):
                    merged = existing_full
                elif transcript_identity_text(text) in transcript_identity_text(existing_full):
                    merged = existing_full
                elif transcript_identity_text(existing_full) in transcript_identity_text(text):
                    merged = text
                else:
                    merged = f"{existing_full.rstrip()}\n\n{text.lstrip()}"
                self.set_transcript_item_text(existing, "resume", merged)
                existing["updated_at"] = now
                existing["turn_id"] = turn_id or existing_turn or ""
                existing["profile"] = profile or existing.get("profile") or ""
                return
        if role in {"resume", "user"} and not append:
            for index in range(len(transcript) - 1, -1, -1):
                existing = transcript[index]
                if not self.transcript_item_matches(
                    existing,
                    role=role,
                    text=text,
                    turn_id=turn_id,
                ):
                    continue
                existing_turn = str(existing.get("turn_id") or "")
                if turn_id and not existing_turn:
                    existing["turn_id"] = turn_id
                existing["profile"] = profile or existing.get("profile") or ""
                existing["updated_at"] = now
                self.set_transcript_item_text(existing, role, text)
                if role == "resume" and self.transcript_has_activity_after(
                    transcript,
                    index,
                    turn_id=turn_id,
                ):
                    self.append_context_replay_marker(
                        transcript,
                        turn_id=turn_id,
                        profile=profile,
                        now=now,
                    )
                    if len(transcript) > CONTROL_TRANSCRIPT_MAX_ITEMS:
                        del transcript[0 : len(transcript) - CONTROL_TRANSCRIPT_MAX_ITEMS]
                return
        if role == "assistant":
            for existing in reversed(transcript):
                existing_turn = existing.get("turn_id")
                if existing.get("role") != "assistant_progress":
                    continue
                if turn_id and existing_turn and existing_turn != turn_id:
                    continue
                existing["role"] = "assistant"
                self.set_transcript_item_text(existing, "assistant", text)
                existing["updated_at"] = now
                existing["turn_id"] = turn_id or existing_turn or ""
                existing["profile"] = profile or existing.get("profile") or ""
                return
        if role == "tool" and call_id:
            for existing in reversed(transcript):
                if existing.get("role") != role or existing.get("call_id") != call_id:
                    continue
                existing_full = str(existing.get("full_text") or existing.get("text") or "")
                merged = merge_tool_transcript_text(existing_full, text)
                self.set_transcript_item_text(existing, role, merged)
                existing["updated_at"] = now
                existing["turn_id"] = turn_id or existing.get("turn_id") or ""
                existing["profile"] = profile or existing.get("profile") or ""
                return
        if (
            append
            and transcript
            and transcript[-1].get("role") == role
            and transcript[-1].get("turn_id") == turn_id
        ):
            existing = str(transcript[-1].get("full_text") or transcript[-1].get("text") or "")
            separator = self.transcript_stream_separator(existing, text)
            merged = existing + separator + text
            self.set_transcript_item_text(transcript[-1], role, merged)
            transcript[-1]["updated_at"] = now
            return
        clipped = self.transcript_display_text(text)
        for existing in transcript[-6:]:
            if (
                existing.get("role") == role
                and existing.get("turn_id") == turn_id
                and existing.get("text") == clipped
            ):
                return
        item = {
            "ts": now,
            "updated_at": now,
            "role": role,
            "text": clipped,
            "turn_id": turn_id,
            "profile": profile,
            "search_text": f"{role} {clipped}",
        }
        self.set_transcript_item_text(item, role, text)
        if call_id:
            item["call_id"] = call_id
        transcript.append(item)
        if len(transcript) > CONTROL_TRANSCRIPT_MAX_ITEMS:
            del transcript[0 : len(transcript) - CONTROL_TRANSCRIPT_MAX_ITEMS]

    def record_websocket_transcript_message(
        self,
        tunnel_id: int,
        *,
        role: str,
        text: str,
        append: bool = False,
        call_id: str = "",
    ) -> None:
        if not text:
            return
        with self.active_lock:
            tunnel = self.active_websockets.get(tunnel_id)
            if tunnel is None:
                return
            session_key = tunnel.get("session_key")
            if not isinstance(session_key, str) or not session_key:
                return
            turn_id = tunnel.get("turn_id") if isinstance(tunnel.get("turn_id"), str) else ""
            profile = str(tunnel.get("profile") or "")
            if role in {"user", "user_pending"} and int(tunnel.get("pending_work") or 0) <= 0:
                turn_id = ""
            self.append_control_transcript(
                session_key=session_key,
                role=role,
                text=text,
                turn_id=turn_id,
                profile=profile,
                append=append,
                call_id=call_id,
            )

    def record_websocket_transcript(
        self,
        tunnel_id: int,
        opcode: int,
        payload: bytes,
        *,
        from_downstream: bool,
    ) -> None:
        if from_downstream:
            session_key = ""
            with self.active_lock:
                tunnel = self.active_websockets.get(tunnel_id)
                if isinstance(tunnel, dict) and isinstance(tunnel.get("session_key"), str):
                    session_key = str(tunnel.get("session_key") or "")
            pending_prompt = self.recent_pending_user_prompt(session_key) if session_key else ""
            entries = split_user_entries_by_prompt_suffix(
                websocket_message_user_entries(opcode, payload),
                pending_prompt,
            )
            for entry in entries:
                self.record_websocket_transcript_message(
                    tunnel_id,
                    role=entry["role"],
                    text=entry["text"],
                    append=False,
                )
            return
        entry = websocket_message_assistant_entry(opcode, payload)
        if entry:
            self.record_websocket_transcript_message(
                tunnel_id,
                role=str(entry.get("role") or "assistant"),
                text=str(entry.get("text") or ""),
                append=bool(entry.get("append")),
            )
        for tool_entry in websocket_message_tool_entries(opcode, payload):
            self.record_websocket_transcript_message(
                tunnel_id,
                role=tool_entry["role"],
                text=tool_entry["text"],
                append=False,
                call_id=str(tool_entry.get("call_id") or ""),
            )

    def begin_websocket_work(
        self,
        tunnel_id: int,
        turn_id: str | None = None,
        thread_id: str | None = None,
    ) -> None:
        with self.active_lock:
            tunnel = self.active_websockets.get(tunnel_id)
            if tunnel is not None:
                tunnel["pending_work"] = 1
                tunnel["turn_id"] = turn_id
                if thread_id:
                    tunnel["thread_id"] = thread_id
                    session_key = tunnel.get("session_key")
                    if isinstance(session_key, str) and session_key:
                        record = self.observed_sessions.get(session_key)
                        if isinstance(record, dict):
                            record["thread_id"] = thread_id
                session_key = tunnel.get("session_key")
                profile = str(tunnel.get("profile") or "")
                if isinstance(session_key, str) and session_key and turn_id:
                    self.assign_recent_user_turn_id(
                        session_key=session_key,
                        turn_id=turn_id,
                        profile=profile,
                    )
                tunnel["saw_tool_output"] = False
                tunnel["completion_deadline_monotonic"] = None
                tunnel["last_data_activity_monotonic"] = time.monotonic()
        self.mark_ui_dirty("websocket_work_begin")

    def mark_websocket_tool_output(self, tunnel_id: int) -> None:
        with self.active_lock:
            tunnel = self.active_websockets.get(tunnel_id)
            if tunnel is not None and int(tunnel.get("pending_work") or 0) > 0:
                tunnel["saw_tool_output"] = True
                tunnel["last_data_activity_monotonic"] = time.monotonic()
        self.mark_ui_dirty("websocket_tool_output")

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
        self.mark_ui_dirty("websocket_work_complete")

    def finish_websocket_work(self, tunnel_id: int) -> None:
        with self.active_lock:
            tunnel = self.active_websockets.get(tunnel_id)
            if tunnel is not None:
                tunnel["pending_work"] = 0
                tunnel["turn_id"] = None
                tunnel["saw_tool_output"] = False
                tunnel["completion_deadline_monotonic"] = None
                tunnel["last_data_activity_monotonic"] = time.monotonic()
        self.mark_ui_dirty("websocket_work_finish")

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
        if finished:
            self.mark_ui_dirty("websocket_work_finish")
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
        changed = False
        with self.active_lock:
            changed = self.active_websockets.pop(tunnel_id, None) is not None
        if changed:
            self.mark_ui_dirty("websocket_end")

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
        if count:
            self.mark_ui_dirty("websocket_close")
        return count

    def control_transcript_snapshot(self, session_key: str) -> list[dict[str, Any]]:
        rows = []
        for index, item in enumerate(self.control_transcripts.get(session_key, [])[-CONTROL_TRANSCRIPT_MAX_ITEMS:]):
            copied = dict(item)
            copied["control_index"] = index
            rows.append(copied)
        return rows

    def control_turns_from_transcript(self, transcript: list[dict[str, Any]]) -> list[dict[str, Any]]:
        turns: list[dict[str, Any]] = []
        current: dict[str, Any] | None = None
        for index, item in enumerate(transcript):
            role = str(item.get("role") or "")
            turn_id = str(item.get("turn_id") or "")
            if role in {"user", "user_pending"}:
                if current is not None and turn_id and str(current.get("turn_id") or "") == turn_id:
                    current["end_index"] = index
                    current["updated_at"] = str(item.get("updated_at") or item.get("ts") or current.get("updated_at") or "")
                    if role == "user_pending":
                        current["pending"] = True
                    continue
                if current is not None:
                    current["end_index"] = max(int(current.get("start_index") or 0), index - 1)
                text = self.transcript_item_full_text(item)
                label = observed_turn_label_from_text(text) or "Untitled turn"
                key = turn_id or f"{role}-{index}"
                current = {
                    "key": key,
                    "turn_id": turn_id,
                    "pending": role == "user_pending",
                    "start_index": index,
                    "end_index": index,
                    "timestamp": str(item.get("ts") or ""),
                    "updated_at": str(item.get("updated_at") or item.get("ts") or ""),
                    "label": label,
                }
                turns.append(current)
                continue
            if current is not None:
                current["end_index"] = index
                current["updated_at"] = str(item.get("updated_at") or item.get("ts") or current.get("updated_at") or "")
                continue
            if turn_id:
                current = {
                    "key": turn_id,
                    "turn_id": turn_id,
                    "pending": False,
                    "start_index": index,
                    "end_index": index,
                    "timestamp": str(item.get("ts") or ""),
                    "updated_at": str(item.get("updated_at") or item.get("ts") or ""),
                    "label": f"Turn {turn_id}",
                }
                turns.append(current)
        if not turns and transcript:
            first = transcript[0]
            last = transcript[-1]
            turns.append(
                {
                    "key": "observed-activity",
                    "turn_id": "",
                    "pending": False,
                    "start_index": 0,
                    "end_index": len(transcript) - 1,
                    "timestamp": str(first.get("ts") or ""),
                    "updated_at": str(last.get("updated_at") or last.get("ts") or ""),
                    "label": "Observed activity",
                }
            )
        return turns

    def session_snapshots(self) -> list[dict[str, Any]]:
        with self.ui_launchers_lock:
            live_ui_launcher_pids = set(self.ui_launchers)
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
                active_thread_ids = [
                    str(tunnel.get("thread_id") or "")
                    for tunnel in self.active_websockets.values()
                    if tunnel.get("session_key") == key and tunnel.get("thread_id")
                ]
                thread_id = str(record.get("thread_id") or (active_thread_ids[0] if active_thread_ids else ""))
                control_path = str(record.get("control_path") or "")
                control_available = bool(control_path and Path(control_path).exists())
                pty_managed = bool(record.get("pty_managed"))
                ui_launcher_pid = record.get("ui_launcher_pid")
                ui_launcher_running = isinstance(ui_launcher_pid, int) and ui_launcher_pid in live_ui_launcher_pids
                associated_profile = str(pinned_profile or record.get("last_profile") or "")
                snapshots.append(
                    {
                        "key": key,
                        "cwd": str(record.get("cwd") or key),
                        "display": str(record.get("display") or compact_session_path(key)),
                        "name": str(record.get("name") or session_display_name(key)),
                        "title": str(record.get("title") or record.get("name") or session_display_name(key)),
                        "tab_order": int(record.get("tab_order") or self.session_tab_order_for_key_locked(key)),
                        "thread_id": thread_id,
                        "last_profile": record.get("last_profile"),
                        "pinned_profile": pinned_profile,
                        "associated_profile": associated_profile,
                        "parent_session_key": str(record.get("parent_session_key") or ""),
                        "ui_launched": bool(record.get("ui_launched")),
                        "active_requests": active_requests,
                        "active_tunnels": active_tunnels,
                        "pending_websocket_work": pending_work,
                        "recent_websocket_activity": recent_activity,
                        "pty_managed": pty_managed,
                        "pty_control_available": control_available,
                        "ui_launcher_pid": ui_launcher_pid if isinstance(ui_launcher_pid, int) else None,
                        "ui_launcher_running": ui_launcher_running,
                        "ui_launcher_mode": str(record.get("ui_launcher_mode") or ""),
                        "ui_launcher_permission": str(record.get("ui_launcher_permission") or ""),
                        "active": active_requests > 0 or pending_work > 0 or recent_activity > 0 or ui_launcher_running,
                        "first_seen_monotonic": record.get("first_seen_monotonic") or 0.0,
                        "last_seen_monotonic": record.get("last_seen_monotonic") or 0.0,
                        "interaction": {
                            "available": control_available,
                            "thread_id": thread_id,
                            "mode": "pty" if control_available else "",
                            "reason": "Ready to send input to the running Codex CLI terminal."
                            if control_available
                            else (
                                "This PTY-managed launcher is no longer reachable. Restart the Codex CLI session with `provision`."
                                if pty_managed
                                else "Restart this session with `provision` in an interactive terminal to enable UI input."
                            ),
                        },
                    }
                )
        snapshots.sort(
            key=lambda item: (
                int(item.get("tab_order") or 0),
                float(item.get("first_seen_monotonic") or 0.0),
                str(item.get("key") or ""),
            )
        )
        for snapshot in snapshots:
            profile = str(snapshot.get("associated_profile") or "")
            if not profile:
                profile = str(self.store.active_profile(required=False) or "")
            snapshot["associated_profile"] = profile
            quota_snapshot = self.usage_cache_snapshot(profile) if profile else None
            model_setting = self.profile_model_setting(profile) if profile else {}
            snapshot["model_setting"] = model_setting
            snapshot["quota_summary"] = usage_cache_summary(quota_snapshot)
            snapshot["quota_html"] = render_quota_html(
                quota_snapshot,
                quota_updated_label(quota_snapshot),
                profile or None,
                self.proxy_token,
            )
            snapshot["quota_compact_html"] = render_compact_quota_html(
                quota_snapshot,
                str(model_setting.get("model") or ""),
            )
        return snapshots

    def control_plane_sessions(self, sessions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        if sessions is None:
            sessions = self.session_snapshots()
        by_key = {
            str(session.get("key") or ""): dict(session, events=[], active_details={})
            for session in sessions
            if session.get("key")
        }
        now = time.monotonic()
        with self.active_lock:
            self.expire_websocket_work_locked()
            for key, session in by_key.items():
                request_rows = []
                for request in self.active_requests.values():
                    if request.get("session_key") != key:
                        continue
                    started = request.get("started_monotonic")
                    request_rows.append(
                        {
                            "profile": str(request.get("profile") or ""),
                            "age_seconds": round(now - float(started), 1)
                            if isinstance(started, (int, float))
                            else None,
                        }
                    )
                tunnel_rows = []
                for tunnel in self.active_websockets.values():
                    if tunnel.get("session_key") != key:
                        continue
                    started = tunnel.get("started_monotonic")
                    last_data = float(tunnel.get("last_data_activity_monotonic") or 0.0)
                    tunnel_rows.append(
                        {
                            "profile": str(tunnel.get("profile") or ""),
                            "pending_work": int(tunnel.get("pending_work") or 0),
                            "turn_id": tunnel.get("turn_id") if isinstance(tunnel.get("turn_id"), str) else "",
                            "thread_id": tunnel.get("thread_id")
                            if isinstance(tunnel.get("thread_id"), str)
                            else "",
                            "service_tier": tunnel.get("service_tier")
                            if isinstance(tunnel.get("service_tier"), str)
                            else "",
                            "age_seconds": round(now - float(started), 1)
                            if isinstance(started, (int, float))
                            else None,
                            "last_data_age_seconds": round(now - last_data, 1) if last_data > 0 else None,
                            "bytes_up": int(tunnel.get("bytes_up") or 0),
                            "bytes_down": int(tunnel.get("bytes_down") or 0),
                            "messages_up": int(tunnel.get("messages_up") or 0),
                            "messages_down": int(tunnel.get("messages_down") or 0),
                        }
                    )
                session["active_details"] = {
                    "requests": request_rows,
                    "tunnels": tunnel_rows,
                }
                transcript = self.control_transcript_snapshot(key)
                session["transcript"] = transcript
                session["turns"] = self.control_turns_from_transcript(transcript)

        for event in self.stats_events(CONTROL_PLANE_EVENT_LIMIT):
            session_key = event.get("session_key")
            if not isinstance(session_key, str) or session_key not in by_key:
                continue
            events = by_key[session_key]["events"]
            events.append(compact_control_event(event))
            if len(events) > CONTROL_PLANE_SESSION_EVENT_LIMIT:
                del events[0 : len(events) - CONTROL_PLANE_SESSION_EVENT_LIMIT]
            if event.get("type") == "token_usage":
                context = context_summary_from_usage(event.get("usage"))
                if context:
                    context["updated_at"] = str(event.get("ts") or "")
                    by_key[session_key]["context"] = context

        app_server = codex_app_server_schema_probe()
        control_status = app_server.get("control_plane") if isinstance(app_server, dict) else {}
        pty_available = any(
            bool(session.get("interaction", {}).get("available"))
            for session in sessions
            if isinstance(session.get("interaction"), dict)
        )
        return {
            "sessions": list(by_key.values()),
            "event_limit": CONTROL_PLANE_SESSION_EVENT_LIMIT,
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "interaction": {
                "available": pty_available,
                "mode": "pty",
                "app_server_interactive_api": bool(
                    isinstance(control_status, dict) and control_status.get("interactive_api")
                ),
                "app_server_turn_control": False,
                "reason": "PTY-managed Codex CLI input is available."
                if pty_available
                else "Launch or resume a Codex CLI session with `provision` in an interactive terminal to enable live UI input.",
            },
        }

    def pinned_sessions_for_profile(
        self,
        profile: str,
        sessions: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        if sessions is None:
            sessions = self.session_snapshots()
        return [
            session
            for session in sessions
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
            self.mark_ui_dirty("usage_error")
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
        self.mark_ui_dirty("usage_fetch")
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
        self.reconcile_reset_credit_verification(profile, payload, source="usage_fetch")
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
        self.mark_ui_dirty("usage_observation")
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
            self.reconcile_reset_credit_verification(profile, current_payload, source=source)
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

    def run_app_server_for_profile(
        self,
        profile: str,
        callback: Callable[[CodexAppServerClient], Any],
        *,
        include_history: bool = False,
    ) -> Any:
        if not self.store.profile_exists(profile):
            raise StoreError(f"unknown profile: {profile}")
        auth_source = self.store.auth_path(profile)
        with tempfile.TemporaryDirectory(prefix=f"provision-app-server-{profile}-") as temp:
            codex_home = Path(temp)
            if include_history:
                bridge_codex_history_into_app_home(codex_home)
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

    def profile_model_catalog_snapshot(self, profile: str) -> dict[str, Any]:
        """Return the latest read-only model/list result and refresh it when stale."""
        fallback = model_catalog()
        now = time.monotonic()
        should_refresh = False
        with self.app_server_model_catalog_lock:
            entry = self.app_server_model_catalog_cache.setdefault(profile, {})
            fetched = entry.get("fetched_monotonic")
            failed = entry.get("failed_monotonic")
            fresh = isinstance(fetched, (int, float)) and now - fetched < APP_SERVER_MODEL_CATALOG_CACHE_SECONDS
            recent_failure = isinstance(failed, (int, float)) and now - failed < APP_SERVER_MODEL_CATALOG_ERROR_BACKOFF_SECONDS
            if not fresh and not recent_failure and not entry.get("in_flight"):
                entry["in_flight"] = True
                should_refresh = True
            cached_catalog = entry.get("catalog")
            catalog = [dict(item) for item in cached_catalog] if isinstance(cached_catalog, tuple) else fallback
            snapshot = {
                "catalog": catalog,
                "source": str(entry.get("source") or "bundled-fallback"),
                "available": bool(entry.get("available")),
                "loading": bool(entry.get("in_flight")),
                "error": str(entry.get("error") or ""),
                "updated_at": str(entry.get("updated_at") or ""),
            }
        if should_refresh:
            threading.Thread(
                target=self.refresh_profile_model_catalog,
                args=(profile,),
                name=f"provision-app-server-model-list-{profile}",
                daemon=True,
            ).start()
        return snapshot

    def refresh_profile_model_catalog(self, profile: str) -> None:
        try:
            result = self.run_app_server_for_profile(profile, lambda client: client.list_models())
            catalog = normalize_codex_model_catalog(result)
            if not catalog:
                raise CodexAppServerError("model/list returned no visible models")
        except (StoreError, CodexAppServerError, OSError, json.JSONDecodeError) as exc:
            with self.app_server_model_catalog_lock:
                entry = self.app_server_model_catalog_cache.setdefault(profile, {})
                entry["in_flight"] = False
                entry["failed_monotonic"] = time.monotonic()
                entry["error"] = str(exc)
            self.log_message("app-server model/list for profile %s failed: %s", profile, exc)
            self.mark_ui_dirty("profile_model_catalog")
            return
        with self.app_server_model_catalog_lock:
            entry = self.app_server_model_catalog_cache.setdefault(profile, {})
            entry.update(
                {
                    "catalog": tuple(dict(item) for item in catalog),
                    "source": "app-server",
                    "available": True,
                    "error": "",
                    "fetched_monotonic": time.monotonic(),
                    "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "in_flight": False,
                }
            )
            entry.pop("failed_monotonic", None)
        self.mark_ui_dirty("profile_model_catalog")

    def control_profile_for_session(self, session_key: str) -> str:
        pinned = self.pinned_profile_for_session(session_key)
        if pinned:
            return pinned
        with self.active_lock:
            record = self.observed_sessions.get(session_key)
            last_profile = str(record.get("last_profile") or "") if isinstance(record, dict) else ""
        if last_profile and self.store.profile_exists(last_profile):
            return last_profile
        profile = self.store.active_profile()
        assert profile is not None
        return profile

    def active_turn_for_session(self, session_key: str) -> tuple[str, str]:
        with self.active_lock:
            self.expire_websocket_work_locked()
            for tunnel in self.active_websockets.values():
                if tunnel.get("session_key") != session_key:
                    continue
                thread_id = tunnel.get("thread_id") if isinstance(tunnel.get("thread_id"), str) else ""
                turn_id = tunnel.get("turn_id") if isinstance(tunnel.get("turn_id"), str) else ""
                if int(tunnel.get("pending_work") or 0) > 0 and thread_id and turn_id:
                    return thread_id, turn_id
        return "", ""

    def observed_thread_for_session(self, session_key: str) -> str:
        with self.active_lock:
            record = self.observed_sessions.get(session_key)
            if isinstance(record, dict):
                thread_id = record.get("thread_id")
                if isinstance(thread_id, str) and thread_id:
                    return thread_id
            for tunnel in self.active_websockets.values():
                if tunnel.get("session_key") != session_key:
                    continue
                thread_id = tunnel.get("thread_id")
                if isinstance(thread_id, str) and thread_id:
                    return thread_id
        return ""

    def resolve_app_server_thread_id(self, profile: str, cwd: str) -> str:
        def list_threads(client: CodexAppServerClient) -> Any:
            return client.list_threads(limit=50)

        result = self.run_app_server_for_profile(profile, list_threads, include_history=True)
        return first_app_server_thread_id(result, cwd=cwd) or ""

    def control_path_for_session(self, session_key: str) -> str:
        with self.active_lock:
            record = self.observed_sessions.get(session_key)
            if not isinstance(record, dict):
                return ""
            control_path = record.get("control_path")
        return control_path if isinstance(control_path, str) else ""

    def send_pty_control_payload(self, control_path: str, payload: dict[str, Any]) -> None:
        if not control_path:
            raise StoreError(
                "This session was not launched under Provision PTY control. "
                "Restart it with `provision` before using UI input."
            )
        path = Path(control_path)
        if not path.exists():
            raise StoreError(
                "Provision's PTY control socket for this session is no longer available. "
                "Restart the Codex CLI session with `provision`."
            )
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(2.0)
                client.connect(str(path))
                client.sendall(encoded)
                raw = client.recv(4096)
        except OSError as exc:
            raise StoreError(f"failed to send PTY control message: {exc}") from exc
        try:
            response = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StoreError(f"invalid PTY control response: {exc}") from exc
        if not isinstance(response, dict) or not response.get("ok"):
            error = response.get("error") if isinstance(response, dict) else None
            raise StoreError(str(error or "PTY control rejected the message"))

    def send_prompt_to_pty_control(self, control_path: str, text: str) -> None:
        self.send_pty_control_payload(control_path, {"action": "send_text", "text": text})

    def send_escape_to_pty_control(self, control_path: str) -> None:
        self.send_pty_control_payload(control_path, {"action": "send_escape"})

    def send_session_prompt(self, session_key: str, text: str) -> dict[str, Any]:
        prompt = clean_transcript_text(text)
        if not prompt:
            raise StoreError("prompt is empty")
        with self.active_lock:
            record = self.observed_sessions.get(session_key)
            if not isinstance(record, dict):
                raise StoreError("unknown session")
            cwd = str(record.get("cwd") or session_key)
            control_path = record.get("control_path") if isinstance(record.get("control_path"), str) else ""
        profile = self.control_profile_for_session(session_key)
        self.send_prompt_to_pty_control(str(control_path or ""), prompt)
        active_turn_id = ""
        with self.active_lock:
            record = self.observed_sessions.get(session_key)
            if isinstance(record, dict):
                record["last_profile"] = profile
                record["last_seen_monotonic"] = time.monotonic()
                record["last_seen_at"] = datetime.now().astimezone()
            for tunnel in self.active_websockets.values():
                if tunnel.get("session_key") != session_key:
                    continue
                if int(tunnel.get("pending_work") or 0) <= 0:
                    continue
                tunnel_turn_id = tunnel.get("turn_id")
                if isinstance(tunnel_turn_id, str) and tunnel_turn_id:
                    active_turn_id = tunnel_turn_id
                    break
        self.append_control_transcript(
            session_key=session_key,
            role="user_pending",
            text=prompt,
            turn_id=active_turn_id,
            profile=profile,
        )
        return {
            "ok": True,
            "profile": profile,
            "cwd": cwd,
            "mode": "pty",
        }

    def send_session_escape(self, session_key: str) -> dict[str, Any]:
        with self.active_lock:
            record = self.observed_sessions.get(session_key)
            if not isinstance(record, dict):
                raise StoreError("unknown session")
            control_path = record.get("control_path") if isinstance(record.get("control_path"), str) else ""
        self.send_escape_to_pty_control(str(control_path or ""))
        return {
            "ok": True,
            "mode": "pty",
        }

    def consume_profile_rate_limit_reset_credit(
        self,
        profile: str,
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        key = idempotency_key or str(uuid.uuid4())
        self.begin_reset_credit_attempt(profile, key)

        def consume(client: CodexAppServerClient) -> dict[str, Any]:
            return {
                "consume": client.consume_account_rate_limit_reset_credit(key),
                "rate_limits": client.read_account_rate_limits(),
            }

        try:
            result = self.run_app_server_for_profile(profile, consume)
        except Exception as exc:
            self.mark_reset_credit_attempt_error(profile, key, exc)
            raise
        consume_result = result.get("consume") if isinstance(result, dict) else {}
        rate_limits = result.get("rate_limits") if isinstance(result, dict) else {}
        outcome = str(consume_result.get("outcome") or "unknown") if isinstance(consume_result, dict) else "unknown"
        payload = usage_payload_from_app_server_rate_limits_response(rate_limits)
        self.mark_reset_credit_outcome(
            profile,
            idempotency_key=key,
            outcome=outcome,
            payload=payload,
        )
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
            "reset_credit": self.reset_credit_status(profile),
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
        if isinstance(payload, dict) and not self.reset_credit_awaiting_usage_confirmation(profile):
            self.update_usage_cache_from_observation(profile, payload, source="app_server_rate_limits")
            return payload
        if isinstance(payload, dict):
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
        self.mark_ui_dirty("stats")

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
        session_key: str | None = None,
    ) -> None:
        self.append_stats_event(
            {
                "type": "http_request",
                "profile": profile,
                "session_key": session_key,
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
            if event_type in {"http_request", "websocket_tunnel", "token_usage", "reset_credit"}:
                recent.append(compact_stats_event(event))
            if event_type in {"http_request", "websocket_tunnel", "token_usage", "quota_update", "reset_credit"}:
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
        self.mark_ui_dirty("login_start")
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
        self.mark_ui_dirty("login_output")

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
        self.mark_ui_dirty("login_finish")

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
        self.mark_ui_dirty("login_cancel")
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
            if app_server_payload and not self.reset_credit_awaiting_usage_confirmation(profile):
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
        for profile in self.reset_credit_profiles_needing_verification():
            self.schedule_reset_credit_verification(profile)
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
        if parsed.path in (
            "/v1/responses",
            "/v1/responses/compact",
            "/v1/images/generations",
        ):
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
        self.server.mark_ui_dirty("profile_switch")
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
        explicit_session_key = normalize_session_key(str(data.get("session_key") or ""))
        control_path = str(data.get("control_path") or "")
        launcher_pid_raw = str(data.get("launcher_pid") or "")
        try:
            launcher_pid = int(launcher_pid_raw) if launcher_pid_raw else None
        except ValueError:
            launcher_pid = None
        pty_managed = str(data.get("pty_managed") or "").lower() in {"1", "true", "yes"}
        if token != self.server.proxy_token:
            self.send_json({"error": "invalid UI token"}, status=401)
            return
        session_key = explicit_session_key or normalize_session_key(cwd)
        profile = self.server.profile_for_session(session_key)
        if explicit_session_key:
            with self.server.active_lock:
                self.server.observe_session_locked(
                    explicit_session_key,
                    cwd,
                    profile,
                    control_path=control_path or None,
                    launcher_pid=launcher_pid,
                    pty_managed=pty_managed,
                    clear_control_path=not bool(control_path),
                )
            session_key = explicit_session_key
        else:
            session_key = self.server.observe_session(
                cwd,
                profile,
                control_path=control_path or None,
                launcher_pid=launcher_pid,
                pty_managed=pty_managed,
                clear_control_path=not bool(control_path),
            )
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
        self.connection.settimeout(UI_STATE_CHECK_SECONDS)
        last_sent_version = self.send_ui_state()
        last_liveness_signature = self.server.ui_state_liveness_signature()
        last_safety_snapshot = time.monotonic()
        last_heartbeat = last_safety_snapshot
        try:
            while True:
                try:
                    message = self.read_websocket_json()
                except socket.timeout:
                    (
                        last_sent_version,
                        last_liveness_signature,
                        last_safety_snapshot,
                        last_heartbeat,
                    ) = self.send_ui_state_if_needed(
                        last_sent_version=last_sent_version,
                        last_liveness_signature=last_liveness_signature,
                        last_safety_snapshot=last_safety_snapshot,
                        last_heartbeat=last_heartbeat,
                    )
                    continue
                if message is None:
                    (
                        last_sent_version,
                        last_liveness_signature,
                        last_safety_snapshot,
                        last_heartbeat,
                    ) = self.send_ui_state_if_needed(
                        last_sent_version=last_sent_version,
                        last_liveness_signature=last_liveness_signature,
                        last_safety_snapshot=last_safety_snapshot,
                        last_heartbeat=last_heartbeat,
                    )
                    continue
                self.handle_ui_websocket_action(message)
                last_sent_version = self.server.ui_state_revision()
                last_liveness_signature = self.server.ui_state_liveness_signature()
                last_safety_snapshot = time.monotonic()
                last_heartbeat = last_safety_snapshot
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
            self.server.mark_ui_dirty("profile_switch")
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
        if action == "launch_session":
            session_key = str(message.get("session_key") or "")
            mode = str(message.get("mode") or "new")
            permission = str(message.get("permission") or "workspace-write")
            session_id = str(message.get("session_id") or "")
            prompt = str(message.get("prompt") or "")
            try:
                self.server.launch_ui_session(
                    session_key=session_key,
                    mode=mode,
                    permission=permission,
                    profile=profile or None,
                    session_id=session_id,
                    prompt=prompt,
                )
            except (StoreError, OSError) as exc:
                self.log_message("UI launcher failed for %s: %s", session_key, exc)
                self.send_ui_state(message=f"Launch failed: {exc}")
                return
            self.send_ui_state()
            return
        if action == "forget_session":
            session_key = str(message.get("session_key") or "")
            force_live = bool(message.get("force_live"))
            try:
                self.server.forget_session(session_key, force_live=force_live)
            except StoreError as exc:
                self.send_ui_state(message=f"Forget failed: {exc}")
                return
            self.send_ui_state()
            return
        if action == "reorder_sessions":
            raw_keys = message.get("session_keys")
            session_keys = [str(key) for key in raw_keys] if isinstance(raw_keys, list) else []
            try:
                self.server.reorder_sessions(session_keys)
            except StoreError as exc:
                self.send_ui_state(message=f"Reorder failed: {exc}")
                return
            self.send_ui_state()
            return
        if action == "session_prompt":
            session_key = str(message.get("session_key") or "")
            prompt = str(message.get("prompt") or "")
            try:
                result = self.server.send_session_prompt(session_key, prompt)
            except (StoreError, CodexAppServerError, AuthError, OSError, json.JSONDecodeError) as exc:
                self.log_message("session prompt failed for %s: %s", session_key, exc)
                self.send_ui_state(message=f"Session interaction failed: {exc}")
                return
            self.send_ui_state()
            return
        if action == "session_escape":
            session_key = str(message.get("session_key") or "")
            try:
                self.server.send_session_escape(session_key)
            except (StoreError, OSError, json.JSONDecodeError) as exc:
                self.log_message("session escape failed for %s: %s", session_key, exc)
                self.send_ui_state(message=f"Session escape failed: {exc}")
                return
            self.send_ui_state()
            return
        if action == "load_history_turn":
            session_key = str(message.get("session_key") or "")
            turn_key = str(message.get("turn_key") or "")
            try:
                payload = self.server.history_turn_payload_for_session(session_key, turn_key)
            except StoreError as exc:
                self.send_websocket_json(
                    {
                        "type": "history_turn",
                        "ok": False,
                        "session_key": session_key,
                        "turn_key": turn_key,
                        "error": str(exc),
                    }
                )
                return
            self.send_websocket_json(
                {
                    "type": "history_turn",
                    "ok": True,
                    "session_key": session_key,
                    "turn_key": turn_key,
                    "payload": payload,
                }
            )
            return
        if action == "load_history_index":
            session_key = str(message.get("session_key") or "")
            try:
                turns = self.server.history_turn_index_for_session(session_key)
            except StoreError as exc:
                self.send_websocket_json(
                    {
                        "type": "history_index",
                        "ok": False,
                        "session_key": session_key,
                        "error": str(exc),
                    }
                )
                return
            self.send_websocket_json(
                {
                    "type": "history_index",
                    "ok": True,
                    "session_key": session_key,
                    "turns": turns,
                }
            )
            return
        if action == "load_resume_candidates":
            session_key = str(message.get("session_key") or "")
            try:
                candidates = self.server.resume_candidates_for_session(session_key)
            except StoreError as exc:
                self.send_websocket_json(
                    {
                        "type": "resume_candidates",
                        "ok": False,
                        "session_key": session_key,
                        "error": str(exc),
                    }
                )
                return
            self.send_websocket_json(
                {
                    "type": "resume_candidates",
                    "ok": True,
                    "session_key": session_key,
                    "candidates": candidates,
                }
            )
            return
        self.send_ui_state(message=f"Unknown action: {action}")

    def send_ui_state(
        self,
        *,
        message: str | None = None,
        pending_action: str | None = None,
        pending_profile: str | None = None,
    ) -> int:
        version = self.server.ui_state_revision()
        self.send_websocket_json(
            {
                "type": "state",
                "message": message,
                "pending_action": pending_action,
                "pending_profile": pending_profile,
                "ui_state_version": version,
                "status": self.ui_status_payload(),
            }
        )
        return version

    def ui_delta_sections_for_reasons(
        self,
        reasons: set[str],
        *,
        liveness_changed: bool = False,
    ) -> set[str]:
        clean = {str(reason or "state") for reason in reasons}
        if "state" in clean:
            return {"full"}
        sections = {"base"}
        if liveness_changed:
            sections.update({"profiles", "control_plane"})

        for reason in clean:
            if reason in {
                "profile_switch",
                "profile_model",
                "profile_fast_mode",
                "login_required",
                "login_required_clear",
                "billing_required",
                "billing_required_clear",
                "usage_error",
                "usage_fetch",
                "usage_observation",
                "reset_credit_begin",
                "reset_credit_error",
                "reset_credit_outcome",
                "reset_credit_verified",
                "login_start",
                "login_output",
                "login_finish",
                "login_cancel",
            }:
                sections.add("profiles")
                continue
            if reason in {
                "request_begin",
                "request_end",
                "websocket_begin",
                "websocket_end",
                "websocket_close",
                "websocket_work_begin",
                "websocket_work_complete",
                "websocket_work_finish",
            }:
                sections.update({"profiles", "control_plane"})
                continue
            if reason in {
                "session_observe",
                "session_pin",
                "session_unpin",
                "session_reorder",
                "session_forget",
                "ui_launcher_start",
                "ui_launcher_exit",
                "websocket_session",
                "websocket_thread",
                "websocket_data",
                "websocket_traffic",
                "websocket_tool_output",
                "transcript",
            }:
                sections.add("control_plane")
                if reason in {"session_observe", "session_pin", "session_unpin", "session_reorder", "session_forget"}:
                    sections.add("profiles")
                continue
            if reason == "stats":
                sections.add("stats")
                continue
            return {"full"}
        return sections

    def ui_status_delta_payload(self, sections: set[str]) -> dict[str, Any]:
        if "full" in sections:
            return self.ui_status_payload()
        status = self.status_payload(include_profiles=False)
        full_status: dict[str, Any] | None = None
        if "profiles" in sections:
            full_status = self.ui_status_payload(
                include_control_plane="control_plane" in sections,
            )
            status["sessions"] = full_status.get("sessions", [])
            status["profiles"] = full_status.get("profiles", [])
        if "control_plane" in sections:
            status["control_plane"] = (
                full_status.get("control_plane", {})
                if full_status is not None
                else self.server.control_plane_sessions()
            )
        if "stats" in sections:
            status["stats"] = self.server.stats_summary()
        if "model_catalog" in sections:
            status["model_catalog"] = model_catalog()
        return status

    def send_ui_delta(
        self,
        *,
        reasons: set[str],
        liveness_changed: bool = False,
    ) -> int:
        sections = self.ui_delta_sections_for_reasons(reasons, liveness_changed=liveness_changed)
        if "full" in sections:
            return self.send_ui_state()
        version = self.server.ui_state_revision()
        self.send_websocket_json(
            {
                "type": "state_delta",
                "ui_state_version": version,
                "sections": sorted(sections),
                "reasons": sorted(reasons),
                "status": self.ui_status_delta_payload(sections),
            }
        )
        return version

    def send_ui_heartbeat(self) -> None:
        self.send_websocket_json(
            {
                "type": "heartbeat",
                "ui_state_version": self.server.ui_state_revision(),
                "live_busy": bool(self.status_payload().get("live_busy")),
                "sent_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
        )

    def send_ui_state_if_needed(
        self,
        *,
        last_sent_version: int,
        last_liveness_signature: tuple[Any, ...],
        last_safety_snapshot: float,
        last_heartbeat: float,
    ) -> tuple[int, tuple[Any, ...], float, float]:
        now = time.monotonic()
        current_version = self.server.ui_state_revision()
        current_liveness_signature = self.server.ui_state_liveness_signature()
        safety_due = now - last_safety_snapshot >= UI_SAFETY_SNAPSHOT_SECONDS
        liveness_changed = current_liveness_signature != last_liveness_signature
        state_due = (
            current_version != last_sent_version
            or liveness_changed
            or safety_due
        )
        if state_due:
            if safety_due:
                sent_version = self.send_ui_state()
            else:
                reasons = self.server.ui_state_dirty_reasons_since(last_sent_version)
                sent_version = self.send_ui_delta(
                    reasons=reasons,
                    liveness_changed=liveness_changed,
                )
            return sent_version, current_liveness_signature, now, now
        if now - last_heartbeat >= UI_HEARTBEAT_SECONDS:
            self.send_ui_heartbeat()
            return last_sent_version, last_liveness_signature, last_safety_snapshot, now
        return last_sent_version, last_liveness_signature, last_safety_snapshot, last_heartbeat

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
            with self.server.active_lock:
                self.server.observe_session_locked(str(session_key), str(session["cwd"]), profile)
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
                session_key=session_key,
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
                with self.server.active_lock:
                    self.server.observe_session_locked(str(session_key), str(session["cwd"]), profile)
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
                            thread_id = websocket_message_thread_id(opcode, payload)
                            if thread_id:
                                self.server.remember_websocket_thread(tunnel_id, thread_id)
                            if websocket_message_starts_response(opcode, payload):
                                self.server.begin_websocket_work(
                                    tunnel_id,
                                    websocket_message_turn_id(opcode, payload),
                                    thread_id,
                                )
                            self.server.record_websocket_transcript(
                                tunnel_id,
                                opcode,
                                payload,
                                from_downstream=True,
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
                            self.server.record_websocket_transcript(
                                tunnel_id,
                                opcode,
                                payload,
                                from_downstream=False,
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
        return ensure_default_upstream_user_agent(headers)

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

    def status_payload(
        self,
        *,
        include_profiles: bool = False,
        include_control_plane: bool = True,
    ) -> dict[str, Any]:
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
            sessions = self.server.session_snapshots()
            payload["sessions"] = sessions
            if include_control_plane:
                payload["control_plane"] = self.server.control_plane_sessions(sessions)
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

    def ui_status_payload(
        self,
        *,
        include_html: bool = False,
        include_control_plane: bool = True,
    ) -> dict[str, Any]:
        status = self.status_payload(
            include_profiles=True,
            include_control_plane=include_control_plane,
        )
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
            reset_credit = self.server.reset_credit_status(name)
            if isinstance(snapshot, dict) and reset_credit:
                snapshot = dict(snapshot)
                snapshot["reset_credit"] = reset_credit
            profile["fast_mode"] = self.server.profile_fast_mode(name)
            profile["model_setting"] = self.server.profile_model_setting(name)
            profile_catalog = self.server.profile_model_catalog_snapshot(name)
            profile["model_catalog"] = profile_catalog["catalog"]
            profile["model_catalog_status"] = {
                key: value for key, value in profile_catalog.items() if key != "catalog"
            }
            profile["login_required"] = self.server.profile_login_required(name)
            profile["auth_health"] = self.server.profile_auth_health(name)
            profile["billing_required"] = billing_required
            profile["login_status"] = self.server.login_status(name)
            profile["quota_summary"] = usage_cache_summary(snapshot)
            profile["quota_updated"] = quota_updated_label(snapshot)
            profile["quota_has_payload"] = isinstance(payload, dict)
            profile["quota_refresh_error"] = (
                str(snapshot.get("error") or "") if isinstance(snapshot, dict) else ""
            )
            profile["reset_credit"] = reset_credit
            profile["quota"] = quota_panel_payload(snapshot, profile["quota_updated"])
            profile["switch_disabled_reason"] = self.switch_disabled_reason(profile, status)
            profile["switch_button_label"] = self.switch_button_label(profile, status)
            sessions = status.get("sessions")
            profile["pinned_sessions"] = self.server.pinned_sessions_for_profile(
                name,
                sessions if isinstance(sessions, list) else None,
            )
            profile["has_active_sessions"] = self.server.profile_has_active_sessions(name)
            profile["has_active_pinned_sessions"] = self.server.profile_has_active_sessions(
                name,
                pinned_only=True,
            )
            profile["login_status_html"] = render_login_status_html(
                profile["login_status"],
                name,
                self.server.proxy_token,
            )
            profile["pin_menu_html"] = self.render_pin_menu(profile, status)
            profile["pinned_sessions_html"] = self.render_pinned_sessions(profile)
            if include_html:
                profile["auth_health_html"] = render_auth_health_html(profile["auth_health"])
                profile["quota_html"] = render_quota_html(
                    snapshot,
                    profile["quota_updated"],
                    name,
                    self.server.proxy_token,
                )
            if profile.get("active"):
                status["model_catalog"] = profile_catalog["catalog"]
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
        profile_catalog = profile.get("model_catalog")
        catalog = profile_catalog if isinstance(profile_catalog, list) and profile_catalog else model_catalog()
        for item in catalog:
            if not isinstance(item, dict):
                continue
            model = str(item.get("id") or "")
            if not model:
                continue
            display = str(item.get("display") or model)
            note = str(item.get("note") or "")
            selected_class = " selected" if model == current_model else ""
            reasoning_levels = item.get("reasoning")
            if not isinstance(reasoning_levels, list) or not reasoning_levels:
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
          <tr class="profile-row{active}" data-profile="{name}" data-profile-key="{name}">
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
        status = self.ui_status_payload(include_html=True)
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
        return r"""
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
			      --green: #35b779;
			      --green-hi: #48d996;
			      --green-low: #20915d;
			      --blue: #60a5fa;
			      --blue-hi: #7fb8ff;
			      --blue-low: #3b82d6;
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
		      --green: #35b779;
		      --green-hi: #48d996;
		      --green-low: #20915d;
		      --blue: #60a5fa;
		      --blue-hi: #7fb8ff;
		      --blue-low: #3b82d6;
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
      position: relative;
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
	    .stats-toggle.active {
	      color: #fff;
	      border-color: var(--red);
	      background: linear-gradient(180deg, var(--red-hi), var(--red-low));
	      text-shadow: 0 1px 0 rgba(0, 0, 0, 0.25);
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
	    .stats-backdrop {
	      place-items: start center;
	      padding-top: var(--stats-modal-top, 18px);
	      box-sizing: border-box;
	      background: transparent;
	    }
    .confirm-modal {
      width: min(440px, calc(100vw - 32px));
      display: grid;
      gap: 12px;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      color: var(--ink);
      box-shadow: var(--shadow);
    }
    .confirm-modal h2 {
      margin: 0;
      font-size: 15px;
    }
    .confirm-modal p {
      margin: 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.45;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .confirm-actions {
      display: flex;
      justify-content: flex-end;
      gap: 8px;
      margin-top: 2px;
    }
    .confirm-actions button {
      width: auto;
      min-height: 30px;
      padding: 4px 11px;
    }
    .confirm-actions .danger {
      color: #fff;
      border-color: var(--red);
      background: linear-gradient(180deg, var(--red-hi), var(--red-low));
      text-shadow: 0 1px 0 rgba(0, 0, 0, 0.25);
    }
    .ui-tooltip {
      position: fixed;
      z-index: 140;
      max-width: min(340px, calc(100vw - 24px));
      padding: 6px 8px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      color: var(--ink);
      box-shadow: var(--shadow);
      font-size: 12px;
      line-height: 1.35;
      overflow-wrap: anywhere;
      pointer-events: none;
    }
    .ui-tooltip[hidden] {
      display: none;
    }
	    .stats-modal {
	      width: min(1240px, calc(100vw - 32px));
	      height: calc(100vh - var(--stats-modal-top, 18px) - 18px);
	      max-height: calc(100vh - var(--stats-modal-top, 18px) - 18px);
	      min-height: 0;
	      overflow: hidden;
	      display: grid;
	      grid-template-rows: auto minmax(0, 1fr);
	      background: var(--surface);
	      border: 1px solid var(--line);
	      border-radius: 8px;
	      box-shadow: var(--shadow);
	      pointer-events: auto;
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
      align-content: start;
      gap: 16px;
      padding: 14px;
      box-sizing: border-box;
      min-width: 0;
      max-width: 100%;
      min-height: 0;
      height: 100%;
      overflow-y: auto;
      overflow-x: hidden;
    }
    .stats-graph-card {
      display: grid;
      gap: 10px;
      min-width: 0;
      max-width: 100%;
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
      min-width: 0;
    }
    .stats-profile-toggle {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      min-width: 0;
      max-width: 100%;
      font-size: 12px;
      color: var(--muted);
      cursor: pointer;
      overflow-wrap: anywhere;
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
	      position: relative;
	      min-width: 0;
	      max-width: 100%;
	      min-height: 230px;
	      overflow: hidden;
	      border: 1px solid var(--line);
	      border-radius: 6px;
	      background: linear-gradient(180deg, var(--surface), var(--subtle));
	      color: var(--muted);
	      touch-action: pan-y;
	    }
	    .stats-graph-svg {
	      width: 100%;
	      height: 230px;
	      display: block;
	    }
    .stats-graph-grid {
      stroke: currentColor;
      opacity: 0.12;
      stroke-width: 1;
    }
    .stats-graph-axis {
      stroke: currentColor;
      opacity: 0.32;
      stroke-width: 1.2;
    }
    .stats-graph-reference {
      stroke: var(--amber);
      stroke-width: 1;
      stroke-dasharray: 5 5;
      opacity: 0.75;
    }
    .stats-graph-label {
      fill: currentColor;
      opacity: 0.78;
      font: 11px ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .stats-graph-marker {
      stroke: var(--surface);
      stroke-width: 2;
    }
    .stats-graph-cursor {
      position: absolute;
      top: 0;
      bottom: 0;
      width: 1px;
      background: var(--red);
      opacity: 0.72;
      pointer-events: none;
      transform: translateX(-0.5px);
    }
    .stats-graph-hover-dot {
      position: absolute;
      width: 10px;
      height: 10px;
      border: 2px solid var(--surface);
      border-radius: 50%;
      background: var(--red);
      box-shadow: 0 0 0 2px rgba(216, 52, 52, 0.28);
      pointer-events: none;
      transform: translate(-50%, -50%);
    }
    .stats-graph-tooltip {
      position: absolute;
      z-index: 2;
      display: grid;
      gap: 4px;
      min-width: 210px;
      max-width: min(320px, calc(100% - 16px));
      padding: 8px 9px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      color: var(--ink);
      box-shadow: var(--shadow);
      font-size: 12px;
      pointer-events: none;
    }
    .stats-graph-tooltip[hidden],
    .stats-graph-cursor[hidden],
    .stats-graph-hover-dot[hidden] {
      display: none;
    }
    .stats-graph-tooltip strong {
      font-size: 12px;
    }
    .stats-graph-tooltip span {
      color: var(--muted);
      overflow-wrap: anywhere;
    }
	    .stats-graph-empty {
	      min-height: 230px;
	      display: grid;
	      place-items: center;
      color: var(--muted);
      font-weight: 650;
    }
	    .stats-table-wrap {
	      overflow: auto;
	      max-width: 100%;
	      max-height: min(320px, 34vh);
	      border: 1px solid var(--line);
	      border-radius: 6px;
	    }
    .stats-table {
      width: 100%;
      table-layout: fixed;
      min-width: 0;
      border-collapse: collapse;
    }
    .stats-table th,
    .stats-table td {
      padding: 8px 10px;
      border-bottom: 1px solid var(--line);
      white-space: normal;
      overflow-wrap: anywhere;
      word-break: break-word;
      vertical-align: top;
    }
    .stats-table tbody tr:last-child td { border-bottom: 0; }
    .stats-table td:first-child { font-weight: 700; color: var(--ink); }
    .stats-section {
      min-width: 0;
      max-width: 100%;
      overflow: hidden;
    }
	    .stats-recent {
	      display: grid;
	      gap: 7px;
	      min-width: 0;
	      max-width: 100%;
	      max-height: 320px;
	      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px;
      background: var(--subtle);
    }
    .stats-event {
      display: grid;
      grid-template-columns: minmax(84px, 116px) minmax(0, 1fr);
      gap: 10px;
      min-width: 0;
      color: var(--muted);
      font-size: 12px;
    }
    .stats-event strong {
      min-width: 0;
      color: var(--ink);
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    .session-tabs {
      margin-top: 14px;
      display: flex;
      align-items: stretch;
      gap: 8px;
      overflow-x: auto;
      padding: 2px 0 4px;
      scrollbar-width: thin;
    }
	    .session-tab {
	      position: relative;
	      width: auto;
	      min-width: 170px;
	      max-width: 280px;
	      min-height: 46px;
	      justify-content: flex-start;
      align-items: flex-start;
      flex-direction: column;
      gap: 2px;
      padding: 7px 10px;
      border-radius: 7px;
      text-align: left;
      color: var(--muted);
	      background: linear-gradient(180deg, var(--surface), var(--subtle));
	      flex: 0 0 auto;
	    }
	    .session-tab.dragging {
	      opacity: 0.52;
	    }
	    .session-tab.drop-before {
	      box-shadow: inset 3px 0 0 var(--red), inset 0 1px 0 rgba(255, 255, 255, 0.62);
	    }
	    .session-tab.drop-after {
	      box-shadow: inset -3px 0 0 var(--red), inset 0 1px 0 rgba(255, 255, 255, 0.62);
	    }
	    .session-tab.active {
	      border-color: var(--amber);
	      color: var(--ink);
	    }
    .session-tab.selected {
      border-color: var(--red);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.62), 0 0 0 2px rgba(216, 52, 52, 0.1);
    }
    :root[data-theme="dark"] .session-tab.selected {
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 0 0 2px rgba(240, 82, 82, 0.18);
    }
    .session-tab-title {
      max-width: 100%;
      overflow: hidden;
      text-overflow: ellipsis;
      font-weight: 780;
      color: var(--ink);
    }
	    .session-tab-meta {
	      max-width: 100%;
	      overflow: hidden;
	      text-overflow: ellipsis;
	      font-size: 11px;
	      color: var(--muted);
	      padding-right: 18px;
	    }
	    .session-tab-close {
	      position: absolute;
	      top: 4px;
	      right: 4px;
	      display: inline-flex;
	      align-items: center;
	      justify-content: center;
	      width: 20px;
	      min-height: 20px;
	      padding: 0;
	      border-radius: 999px;
	      color: var(--muted);
	      background: transparent;
	      border-color: transparent;
	      box-shadow: none;
	      font-size: 14px;
	      line-height: 1;
	      cursor: pointer;
	    }
	    .session-tab-close:hover:not(:disabled) {
	      color: #fff;
	      border-color: var(--red);
	      background: linear-gradient(180deg, var(--red-hi), var(--red-low));
	    }
	    .session-tab.launch-tab {
	      min-width: 64px;
	      max-width: 64px;
	      align-items: center;
      justify-content: center;
      text-align: center;
      color: var(--ink);
    }
    .session-tab.launch-tab .session-tab-title {
      font-size: 22px;
      line-height: 1;
    }
    .session-tab.launch-tab .session-tab-meta {
      font-size: 10px;
      padding-right: 0;
    }
    .session-tabs-empty {
      color: var(--muted);
      border: 1px dashed var(--line);
      border-radius: 7px;
      background: var(--subtle);
      padding: 9px 11px;
      font-size: 12px;
      font-weight: 650;
    }
    .launcher-dock {
      position: absolute;
      left: 0;
      right: 0;
      top: var(--control-dock-top, 0);
      bottom: 0;
      z-index: 66;
      pointer-events: none;
    }
    .launcher-dock[hidden] {
      display: none;
    }
    .launcher-modal {
      width: 100%;
      height: 100%;
      min-height: 0;
      display: grid;
      grid-template-rows: auto minmax(0, 1fr);
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      box-shadow: var(--shadow);
      overflow: hidden;
      pointer-events: auto;
    }
    .launcher-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 8px 12px;
      border-bottom: 1px solid var(--line);
      background: var(--soft);
    }
    .launcher-head h2 {
      margin: 0;
      font-size: 12px;
      color: var(--ink);
    }
    .launcher-grid {
      align-self: start;
      display: grid;
      grid-template-columns: minmax(220px, 1fr) minmax(150px, 210px) minmax(150px, 210px) auto;
      align-items: end;
      gap: 9px;
      padding: 10px 12px;
      background: var(--surface);
    }
    .launcher-field {
      display: grid;
      gap: 3px;
      min-width: 130px;
      flex: 0 1 auto;
    }
    .launcher-field.workdir {
      min-width: min(100%, 220px);
    }
    .launcher-field.resume-session {
      grid-column: 1 / 4;
    }
    .launcher-field[hidden] {
      display: none;
    }
    .launcher-field span {
      color: var(--muted);
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
    }
    .launcher-field select {
      min-height: 32px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--subtle);
      color: var(--ink);
      padding: 5px 8px;
      max-width: 100%;
    }
    .launcher-actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    .launcher-actions button {
      width: auto;
      min-height: 32px;
      padding: 4px 10px;
    }
    .control-dock {
      position: absolute;
      left: 0;
      right: 0;
      top: var(--control-dock-top, 0);
      bottom: 0;
      z-index: 65;
      pointer-events: none;
    }
    .control-dock[hidden] { display: none; }
    .control-modal {
      width: 100%;
      height: 100%;
      min-height: 0;
      position: relative;
      display: grid;
      grid-template-rows: auto auto auto minmax(0, 1fr) auto;
	      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      overflow: hidden;
      pointer-events: auto;
    }
    .control-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 14px;
      padding: 8px 12px;
      border-bottom: 1px solid var(--line);
      background: var(--soft);
    }
    .control-title-block {
      min-width: 0;
      display: grid;
      gap: 2px;
    }
    .control-head h2 {
      margin: 0;
      font-size: 12px;
      overflow-wrap: anywhere;
    }
    .control-close {
      width: 30px;
      min-height: 30px;
      padding: 0;
      border-radius: 999px;
      flex: 0 0 auto;
    }
    .control-head-actions {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 7px;
      flex-wrap: wrap;
      flex: 0 0 auto;
    }
	    .control-head-actions button {
	      width: auto;
	      min-height: 30px;
	      padding: 3px 9px;
	      border-radius: 999px;
	    }
	    #controlForget {
	      display: none;
	    }
    .control-turn-select {
      min-height: 30px;
      max-width: min(42vw, 360px);
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      color: var(--ink);
      padding: 4px 8px;
    }
    .control-toolbar {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
      padding: 8px 12px;
      border-bottom: 1px solid var(--line);
      background: var(--surface);
    }
    .control-view-tabs {
      display: inline-flex;
      gap: 6px;
      flex: 0 0 auto;
    }
    .control-view-button {
      width: auto;
      min-height: 30px;
      padding: 3px 10px;
      border-radius: 999px;
      color: var(--muted);
      background: linear-gradient(180deg, var(--surface), var(--subtle));
    }
    .control-view-button.active {
      color: #fff;
      border-color: var(--red);
      background: linear-gradient(180deg, var(--red-hi), var(--red-low));
      text-shadow: 0 1px 0 rgba(0, 0, 0, 0.28);
    }
    .control-search {
      flex: 1 1 260px;
      min-width: 160px;
      min-height: 30px;
      padding: 5px 9px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--subtle);
      color: var(--ink);
    }
	    .control-status-pills {
	      display: flex;
	      flex-wrap: wrap;
	      align-items: center;
	      gap: 6px;
	      padding: 8px 12px 6px;
	      background: var(--surface);
	    }
    .control-compact-quota {
      display: inline-grid;
      grid-template-columns: auto auto minmax(76px, 112px) auto;
      align-items: center;
      gap: 6px;
      min-height: 24px;
      max-width: 100%;
      padding: 2px 7px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: linear-gradient(180deg, var(--surface), var(--subtle));
      color: var(--muted);
      font-size: 11px;
      font-weight: 780;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.38);
    }
    :root[data-theme="dark"] .control-compact-quota {
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.07);
    }
    .control-compact-quota.state,
    .control-compact-quota.count {
      grid-template-columns: auto auto;
    }
    .control-compact-quota-name {
      color: var(--ink);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 92px;
    }
    .control-compact-quota-primary {
      color: var(--green);
      min-width: 30px;
      text-align: right;
    }
    .control-compact-quota-primary.not-enforced {
      color: var(--muted);
    }
    .control-compact-quota-weekly {
      color: var(--blue);
      min-width: 30px;
    }
    .control-compact-quota-text {
      color: var(--muted);
    }
    .control-compact-quota-bar {
      position: relative;
      display: block;
      width: 100%;
      min-width: 76px;
      height: 12px;
      border: 1px solid var(--line);
      background: var(--soft);
      overflow: hidden;
    }
    .control-compact-quota-weekly-fill,
    .control-compact-quota-primary-fill {
      position: absolute;
      left: 0;
      bottom: 0;
      display: block;
      max-width: 100%;
      transition: width 160ms ease;
    }
    .control-compact-quota-weekly-fill {
      height: 12px;
      background: linear-gradient(180deg, var(--blue-hi), var(--blue-low));
    }
    .control-compact-quota-primary-fill {
      height: 8px;
      background: linear-gradient(180deg, var(--green-hi), var(--green-low));
    }
	    .control-compact-quota.unlimited .control-compact-quota-bar,
	    .control-compact-quota.unknown .control-compact-quota-bar {
	      background: linear-gradient(90deg, rgba(59, 130, 214, 0.18), rgba(25, 135, 84, 0.16));
	    }
	    .control-compact-quota.secondary {
	      opacity: 0.9;
	    }
    .control-content {
      min-width: 0;
      min-height: 0;
      overflow: auto;
      padding: 10px 12px 14px;
      display: grid;
      gap: 12px;
    }
    .control-modal.discussion-view .control-content {
      align-content: start;
      grid-auto-rows: max-content;
    }
    .control-modal.details-view .control-search,
    .control-modal.resume-view .control-search,
    .control-modal.details-view .control-compose,
    .control-modal.resume-view .control-compose {
      display: none;
    }
    .control-resume-list {
      display: grid;
      gap: 8px;
    }
    .control-resume-item {
      width: 100%;
      min-height: 0;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      align-items: start;
      gap: 10px;
      padding: 9px 10px;
      text-align: left;
      white-space: normal;
      border-radius: 6px;
      background: linear-gradient(180deg, var(--surface), var(--subtle));
    }
    .control-resume-item.selected {
      border-color: var(--red);
      box-shadow: inset 3px 0 0 var(--red);
    }
    .control-resume-main {
      display: grid;
      gap: 4px;
      min-width: 0;
    }
    .control-resume-label {
      color: var(--ink);
      font-weight: 760;
      overflow-wrap: anywhere;
    }
    .control-resume-meta {
      color: var(--muted);
      font-size: 12px;
    }
    .control-resume-actions {
      display: flex;
      justify-content: flex-end;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 10px;
    }
    .control-resume-actions button {
      width: auto;
      min-width: 96px;
      border-radius: 999px;
    }
    .control-detail-section {
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      overflow: hidden;
    }
    .control-detail-section h3 {
      margin: 0;
      padding: 8px 10px;
      font-size: 12px;
      text-transform: uppercase;
      color: var(--muted);
      letter-spacing: 0;
      font-weight: 800;
      background: var(--subtle);
      border-bottom: 1px solid var(--line);
    }
    .control-section-body {
      padding: 8px;
      display: grid;
      gap: 8px;
    }
    .control-active-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(min(100%, 320px), 1fr));
      gap: 8px;
    }
    .control-active-card,
    .control-event {
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--subtle);
      padding: 8px;
      min-width: 0;
    }
    .control-active-card strong,
    .control-event strong {
      color: var(--ink);
    }
    .control-active-card {
      color: var(--muted);
      font-size: 12px;
      display: grid;
      gap: 4px;
    }
    .control-events {
      display: grid;
      gap: 7px;
    }
	    .control-transcript {
	      display: grid;
	      gap: 8px;
	      min-width: 0;
	      align-content: start;
	      grid-auto-rows: max-content;
	    }
	    .control-scroll-badge-row {
	      position: sticky;
	      z-index: 6;
	      display: flex;
	      pointer-events: none;
	      height: 0;
	    }
	    .control-scroll-badge-row.top {
	      top: 0;
	      justify-content: flex-start;
	    }
	    .control-scroll-badge-row.bottom {
	      bottom: 0;
	      justify-content: flex-end;
	    }
	    .control-scroll-badge {
	      width: auto;
	      min-height: 24px;
	      padding: 2px 8px;
	      border-radius: 999px;
	      border: 1px solid var(--line);
	      color: var(--muted);
	      background: linear-gradient(180deg, var(--surface), var(--subtle));
	      box-shadow: var(--shadow);
	      font-size: 11px;
	      font-weight: 780;
	      pointer-events: auto;
	    }
	    .control-scroll-badge[hidden] {
	      display: none;
	    }
	    .control-transcript-window-note {
	      color: var(--muted);
	      font-size: 11px;
	      font-weight: 650;
	      text-align: center;
	    }
	    .control-message {
	      display: grid;
	      gap: 4px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--subtle);
      padding: 8px;
      min-width: 0;
	      align-self: start;
    }
    .control-message.user {
      border-left: 3px solid var(--red);
    }
    .control-message.user_pending {
      border-left: 3px solid var(--amber);
      background: linear-gradient(180deg, rgba(242, 189, 67, 0.08), var(--subtle));
    }
    .control-message.assistant {
      border-left: 3px solid var(--green);
    }
    .control-message.assistant_progress {
      border-left: 3px solid var(--blue);
      background: linear-gradient(180deg, var(--surface), var(--subtle));
    }
    .control-message.assistant_activity {
      border-left-width: 4px;
    }
    .control-message.resume {
      border-left: 3px solid var(--amber);
    }
    .control-message.context_compaction {
      border-left: 3px solid var(--blue);
      background: linear-gradient(180deg, rgba(59, 130, 214, 0.08), var(--subtle));
    }
    .control-message.tool {
      border-left: 3px solid var(--amber);
    }
    .control-message-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 750;
    }
    .control-message-turn {
      display: inline-flex;
      align-items: center;
      gap: 5px;
    }
    .control-message-spinner {
      width: 11px;
      height: 11px;
      border: 2px solid var(--bar-bg);
      border-top-color: var(--amber);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      flex: 0 0 auto;
    }
    .control-message-text {
      min-width: 0;
      max-width: 100%;
      color: var(--ink);
      font-size: 13px;
      line-height: 1.45;
      overflow-wrap: break-word;
      word-break: normal;
    }
    .control-message-text.plain {
      white-space: pre-wrap;
    }
    .control-message-text.markdown {
      min-width: 0;
      max-width: 100%;
      white-space: normal;
    }
    .control-message-text.markdown > :first-child { margin-top: 0; }
    .control-message-text.markdown > :last-child { margin-bottom: 0; }
    .control-message-text.markdown p,
    .control-message-text.markdown ul,
    .control-message-text.markdown ol,
    .control-message-text.markdown blockquote,
    .control-message-text.markdown pre,
    .control-message-text.markdown table {
      min-width: 0;
      max-width: 100%;
      margin: 0 0 8px;
      overflow-wrap: break-word;
      word-break: normal;
    }
    .control-message-text.markdown h1,
    .control-message-text.markdown h2,
    .control-message-text.markdown h3,
    .control-message-text.markdown h4 {
      margin: 10px 0 6px;
      color: var(--ink);
      line-height: 1.25;
      letter-spacing: 0;
    }
    .control-message-text.markdown h1 { font-size: 17px; }
    .control-message-text.markdown h2 { font-size: 16px; }
    .control-message-text.markdown h3 { font-size: 15px; }
    .control-message-text.markdown h4 { font-size: 14px; }
    .control-message-text.markdown ul,
    .control-message-text.markdown ol {
      padding-left: 22px;
      box-sizing: border-box;
      width: 100%;
      overflow: hidden;
    }
    .control-message-text.markdown li {
      min-width: 0;
      max-width: 100%;
      margin: 3px 0;
      overflow-wrap: break-word;
      word-break: normal;
      white-space: normal;
    }
    .control-message-text.markdown blockquote {
      padding: 3px 0 3px 10px;
      border-left: 3px solid var(--line);
      color: var(--muted);
    }
    .control-message-text.markdown code,
    .control-message-text.markdown a {
      padding: 2px 5px;
      border: 1px solid rgba(59, 130, 214, 0.35);
      border-radius: 4px;
      background: linear-gradient(180deg, rgba(96, 165, 250, 0.14), rgba(96, 165, 250, 0.07));
      color: var(--blue-low);
      font: 12px/1.45 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.48);
      white-space: normal;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    .control-message-text.markdown a {
      text-decoration: none;
      font-weight: 760;
    }
    .control-message-text.markdown a:hover {
      border-color: rgba(59, 130, 214, 0.55);
      background: linear-gradient(180deg, rgba(96, 165, 250, 0.2), rgba(96, 165, 250, 0.11));
    }
    :root[data-theme="dark"] .control-message-text.markdown code,
    :root[data-theme="dark"] .control-message-text.markdown a {
      border-color: rgba(127, 184, 255, 0.32);
      background: linear-gradient(180deg, rgba(96, 165, 250, 0.16), rgba(96, 165, 250, 0.09));
      color: var(--blue-hi);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.07);
    }
    .control-message-text.markdown pre {
      max-width: 100%;
      overflow-x: hidden;
      padding: 8px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    .control-message-text.markdown pre code {
      display: block;
      padding: 0;
      border: 0;
      background: transparent;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    .control-message-text.markdown table {
      display: block;
      width: max-content;
      max-width: 100%;
      overflow-x: auto;
      border-collapse: collapse;
      table-layout: auto;
    }
    .control-message-text.markdown th,
    .control-message-text.markdown td {
      padding: 5px 7px;
      border: 1px solid var(--line);
      vertical-align: top;
      text-align: left;
    }
    .control-message-text.markdown th {
      background: var(--surface);
      color: var(--ink);
      font-size: 12px;
      text-transform: none;
    }
    .control-message.assistant_progress .control-message-text,
    .control-message.tool .control-message-text {
      padding-left: 8px;
      border-left: 1px solid var(--line);
    }
    .control-show-more {
      width: auto;
      min-height: 26px;
      justify-self: start;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 12px;
      color: var(--muted);
      background: var(--surface);
    }
    .control-show-more:hover {
      color: var(--ink);
      border-color: var(--red);
    }
    .control-activity-parts {
      display: grid;
      gap: 8px;
    }
	    .control-tool-block {
	      display: grid;
	      gap: 7px;
	      margin-left: 14px;
	      padding: 8px 9px;
	      border: 1px solid var(--line);
      border-left: 4px solid var(--amber);
      background: linear-gradient(180deg, var(--surface), var(--subtle));
      color: var(--ink);
	      white-space: pre-wrap;
	      overflow-wrap: anywhere;
	    }
	    .control-tool-summary {
	      display: flex;
	      align-items: center;
	      justify-content: space-between;
	      gap: 8px;
	      min-width: 0;
	    }
	    .control-tool-title {
	      display: inline-flex;
	      align-items: center;
	      gap: 6px;
	      min-width: 0;
	      font-weight: 800;
	      color: var(--ink);
	    }
	    .control-tool-title code {
	      max-width: min(100%, 48vw);
	      overflow: hidden;
	      text-overflow: ellipsis;
	      border: 1px solid rgba(183, 121, 31, 0.35);
	      border-radius: 4px;
	      padding: 1px 5px;
	      background: rgba(183, 121, 31, 0.1);
	      color: var(--ink);
	      font: 12px/1.4 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
	    }
	    .control-tool-status {
	      flex: 0 0 auto;
	      border: 1px solid var(--line);
	      border-radius: 999px;
	      padding: 1px 7px;
	      color: var(--muted);
	      background: var(--surface);
	      font-size: 11px;
	      font-weight: 780;
	    }
	    .control-tool-status.completed {
	      border-color: rgba(25, 135, 84, 0.34);
	      color: var(--green);
	      background: rgba(25, 135, 84, 0.08);
	    }
	    .control-tool-status.in_progress {
	      border-color: rgba(59, 130, 214, 0.34);
	      color: var(--blue);
	      background: rgba(59, 130, 214, 0.08);
	    }
		    .control-tool-command {
		      min-width: 0;
		      padding: 5px 7px;
		      border: 1px solid var(--line);
		      border-radius: 5px;
	      background: var(--subtle);
	      font: 12px/1.45 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
		      overflow-wrap: anywhere;
		      white-space: pre-wrap;
		    }
	    .control-tool-special {
	      display: grid;
	      gap: 6px;
	      padding: 7px;
	      border: 1px solid var(--line);
	      border-radius: 6px;
	      background: color-mix(in srgb, var(--surface) 86%, var(--blue) 14%);
	    }
	    .control-tool-special-title {
	      display: flex;
	      align-items: center;
	      justify-content: space-between;
	      gap: 8px;
	      font-size: 12px;
	      font-weight: 850;
	      color: var(--ink);
	    }
	    .control-tool-special-note {
	      color: var(--muted);
	      font-size: 12px;
	    }
	    .control-tool-plan-list {
	      display: grid;
	      gap: 4px;
	    }
	    .control-tool-plan-row {
	      display: grid;
	      grid-template-columns: 84px minmax(0, 1fr);
	      gap: 7px;
	      align-items: start;
	      font-size: 12px;
	    }
	    .control-tool-plan-status {
	      border: 1px solid var(--line);
	      border-radius: 999px;
	      padding: 1px 6px;
	      color: var(--muted);
	      background: var(--surface);
	      text-align: center;
	      font-size: 11px;
	      font-weight: 800;
	    }
	    .control-tool-plan-status.completed {
	      border-color: rgba(25, 135, 84, 0.34);
	      color: var(--green);
	      background: rgba(25, 135, 84, 0.08);
	    }
	    .control-tool-plan-status.in_progress {
	      border-color: rgba(59, 130, 214, 0.34);
	      color: var(--blue);
	      background: rgba(59, 130, 214, 0.08);
	    }
	    .control-tool-plan-status.pending {
	      color: var(--muted);
	    }
		    .control-tool-sections {
		      display: grid;
		      gap: 6px;
		    }
	    .control-tool-section {
	      display: grid;
	      gap: 3px;
	    }
	    .control-tool-section-label {
	      color: var(--muted);
	      font-size: 11px;
	      font-weight: 800;
	      text-transform: uppercase;
	    }
	    .control-tool-section pre {
	      margin: 0;
	      min-width: 0;
	      max-height: 220px;
	      overflow: auto;
	      padding: 6px 7px;
	      border: 1px solid var(--line);
	      border-radius: 5px;
	      background: var(--surface);
	      color: var(--ink);
	      font: 12px/1.45 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
	      white-space: pre-wrap;
	      overflow-wrap: anywhere;
	      word-break: break-word;
	    }
	    .control-tool-block .control-message-text {
	      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
	      font-size: 12px;
      line-height: 1.45;
    }
    .control-tool-block.control-signal {
      border-left-color: var(--line);
      color: var(--muted);
      opacity: 0.76;
    }
    .control-tool-block strong {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
    }
	    .control-tool-section.patch pre {
	      background: color-mix(in srgb, var(--surface) 88%, var(--blue) 12%);
	    }
	    .control-tool-section.collapsed pre {
	      max-height: none;
	      overflow: hidden;
	      color: var(--muted);
	    }
    .tool-patch-line {
      display: block;
      min-height: 1.35em;
    }
    .tool-patch-line.meta {
      color: var(--muted);
      font-weight: 800;
    }
    .tool-patch-line.add {
      color: var(--green);
      background: rgba(25, 135, 84, 0.08);
    }
    .tool-patch-line.delete {
      color: var(--red);
      background: rgba(204, 70, 70, 0.08);
    }
    .control-message.compact .control-message-text {
      overflow: hidden;
      max-height: 5.8em;
    }
    .control-message.compact .control-message-text.plain {
      white-space: nowrap;
      text-overflow: ellipsis;
      max-height: none;
    }
    .control-message.compact .control-message-text.expanded {
      overflow: visible;
      max-height: none;
    }
    .control-message.compact .control-message-text.expanded.plain {
      white-space: pre-wrap;
      text-overflow: clip;
    }
    @media (max-width: 640px) {
      .control-tool-block {
        margin-left: 8px;
      }
    }
    .control-event {
      display: grid;
      grid-template-columns: 126px minmax(0, 1fr);
      gap: 10px;
      color: var(--muted);
      font-size: 12px;
    }
    .control-event.compact {
      grid-template-columns: 112px minmax(0, 1fr);
      padding: 6px 8px;
    }
    .control-event-detail {
      display: grid;
      gap: 4px;
      min-width: 0;
    }
    .control-event-detail span {
      overflow-wrap: anywhere;
    }
    .control-empty {
      color: var(--muted);
      border: 1px dashed var(--line);
      border-radius: 6px;
      padding: 12px;
      text-align: center;
      font-weight: 650;
    }
	    .control-compose {
	      border-top: 1px solid var(--line);
	      padding: 8px 12px;
	      display: grid;
	      grid-template-columns: minmax(0, 1fr) auto;
	      gap: 10px;
	      background: var(--soft);
	      position: sticky;
	      bottom: 0;
	      z-index: 2;
	    }
    .control-compose textarea {
      min-height: 42px;
      height: 54px;
      max-height: min(180px, 28vh);
      resize: vertical;
      padding: 8px 9px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      color: var(--ink);
      font: inherit;
    }
    .control-compose button {
      width: auto;
      min-width: 92px;
      align-self: stretch;
    }
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
		    .quota-reset-credit-pill.disabled {
		      display: inline-flex;
		      align-items: center;
		      border-color: var(--line);
		      color: var(--muted);
		      background: var(--button-disabled-bg);
		      box-shadow: none;
		      cursor: not-allowed;
		    }
		    .quota-reset-credit-pill.disabled:hover {
		      border-color: var(--line);
		      filter: none;
		    }
		    :root[data-theme="dark"] .quota-reset-credit-pill {
		      color: #261901;
		      background: linear-gradient(180deg, #f0ca58, #cf981f);
		      border-color: #f0cf66;
		    }
		    :root[data-theme="dark"] .quota-reset-credit-pill.disabled {
		      color: var(--muted);
		      background: var(--button-disabled-bg);
		      border-color: var(--line);
		      box-shadow: none;
		    }
		    :root[data-theme="dark"] .quota-reset-credit-pill:hover {
		      background: linear-gradient(180deg, #ffd76f, #dda52c);
		      border-color: #ffe08a;
		      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.32), 0 0 0 2px rgba(240, 207, 102, 0.16);
		    }
		    :root[data-theme="dark"] .quota-reset-credit-pill.disabled:hover {
		      color: var(--muted);
		      background: var(--button-disabled-bg);
		      border-color: var(--line);
		      box-shadow: none;
		    }
		    @media (prefers-color-scheme: dark) {
		      :root:not([data-theme]) .quota-reset-credit-pill:hover {
		        background: linear-gradient(180deg, #ffd76f, #dda52c);
		        border-color: #ffe08a;
		        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.32), 0 0 0 2px rgba(240, 207, 102, 0.16);
		      }
		      :root:not([data-theme]) .quota-reset-credit-pill.disabled:hover {
		        color: var(--muted);
		        background: var(--button-disabled-bg);
		        border-color: var(--line);
		        box-shadow: none;
		      }
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
	    .quota-horizon.primary.not-enforced {
	      color: var(--muted);
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
	    .quota-primary-label-outside.not-enforced {
	      color: var(--muted);
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
	      .launcher-grid {
	        grid-template-columns: 1fr;
	      }
	      .launcher-field.resume-session {
	        grid-column: auto;
	      }
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
	      .control-active-grid { grid-template-columns: 1fr; }
	      .control-event,
	      .control-event.compact {
	        grid-template-columns: 1fr;
	      }
	      .control-compose {
	        grid-template-columns: 1fr;
	      }
	      .control-compose button {
	        width: 100%;
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
	        <span id="codexRestartRequired" class="pill" hidden>Restart Provision</span>
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
    <section id="sessionTabs" class="session-tabs" aria-label="Provision-managed Codex CLI sessions"></section>
    <section id="launcherBar" class="launcher-dock" aria-label="Launch Codex CLI session" hidden>
      <div class="launcher-modal" role="dialog" aria-modal="false" aria-labelledby="launcherTitle">
        <div class="launcher-head">
          <h2 id="launcherTitle">Launch Codex CLI</h2>
          <button id="launcherClose" class="control-close" type="button" aria-label="Close launcher">x</button>
        </div>
        <div class="launcher-grid">
          <label class="launcher-field workdir">
            <span>Workdir</span>
            <select id="launcherSession"></select>
          </label>
          <label class="launcher-field">
            <span>Mode</span>
            <select id="launcherMode">
              <option value="new">New session</option>
              <option value="resume-last">Resume latest</option>
              <option value="resume-session">Resume selected</option>
            </select>
          </label>
          <label class="launcher-field">
            <span>Permissions</span>
            <select id="launcherPermission">
              <option value="workspace-write">Workspace write</option>
              <option value="read-only">Read only</option>
              <option value="full-access">Full access</option>
              <option value="bypass">Bypass prompts</option>
            </select>
          </label>
          <div class="launcher-actions">
            <button id="launcherStart" type="button">Launch</button>
          </div>
          <label id="launcherResumeField" class="launcher-field resume-session" hidden>
            <span>Resume Session</span>
            <select id="launcherResumeSession"></select>
          </label>
        </div>
      </div>
    </section>
    <div id="controlModal" class="control-dock" hidden>
      <section class="control-modal" role="dialog" aria-modal="false" aria-labelledby="controlTitle">
        <div class="control-head">
          <div class="control-title-block">
            <h2 id="controlTitle">Session</h2>
          </div>
          <div class="control-head-actions">
            <select id="controlTurnSelect" class="control-turn-select" aria-label="Observed turn"></select>
            <button id="controlForget" type="button">Forget</button>
            <button id="controlClose" class="control-close" type="button" aria-label="Close session">x</button>
          </div>
	        </div>
	        <div id="controlStatusPills" class="control-status-pills"></div>
	        <div class="control-toolbar">
          <div class="control-view-tabs" role="tablist" aria-label="Session view">
            <button id="controlDiscussionView" class="control-view-button active" type="button" data-control-view="discussion">Discussion</button>
            <button id="controlDetailsView" class="control-view-button" type="button" data-control-view="details">Session Details</button>
            <button id="controlResumeView" class="control-view-button" type="button" data-control-view="resume">Resume</button>
          </div>
          <input id="controlSearch" class="control-search" type="search" placeholder="Search discussion">
        </div>
        <div id="controlContent" class="control-content"></div>
        <form id="controlCompose" class="control-compose">
          <textarea id="controlPrompt" placeholder="Live CLI input is not connected yet" disabled></textarea>
          <button id="controlSend" type="submit" disabled>Send</button>
        </form>
      </section>
    </div>
    <div id="statsModal" class="modal-backdrop stats-backdrop" hidden>
      <section class="stats-modal" role="dialog" aria-modal="true" aria-labelledby="statsTitle">
        <div class="stats-head">
          <h2 id="statsTitle">Stats</h2>
          <button id="statsClose" class="stats-close" type="button" aria-label="Close stats">x</button>
        </div>
        <div id="statsContent" class="stats-content"></div>
      </section>
    </div>
    <div id="confirmModal" class="modal-backdrop" hidden>
      <section class="confirm-modal" role="dialog" aria-modal="true" aria-labelledby="confirmTitle">
        <h2 id="confirmTitle">Confirm action</h2>
        <p id="confirmMessage"></p>
        <div class="confirm-actions">
          <button id="confirmCancel" type="button">Cancel</button>
          <button id="confirmAccept" class="danger" type="button">Confirm</button>
        </div>
      </section>
    </div>
    <div id="uiTooltip" class="ui-tooltip" hidden></div>
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
		    const CONTROL_TRANSCRIPT_WINDOW_SIZE = 80;
		    const CONTROL_TRANSCRIPT_WINDOW_STEP = 40;
		    let socket = null;
	    let reconnectTimer = null;
	    let latestStatus = INITIAL.status || {};
	    let latestLiveBusy = Boolean(INITIAL.status && INITIAL.status.live_busy);
	    let latestStats = INITIAL.status && INITIAL.status.stats ? INITIAL.status.stats : { profiles: [], recent: [] };
	    let latestModelCatalog = INITIAL.status && Array.isArray(INITIAL.status.model_catalog) ? INITIAL.status.model_catalog : [];
	    let latestControlPlane = INITIAL.status && INITIAL.status.control_plane ? INITIAL.status.control_plane : { sessions: [] };
	    let latestCodex = INITIAL.status && INITIAL.status.codex ? INITIAL.status.codex : {};
	    let pendingRenderPacket = null;
	    let pendingRenderFrame = null;
	    let selectedControlSessionKey = "";
		    let selectedLauncherSessionKey = "";
		    let draggedSessionTabKey = "";
		    let launcherPanelOpen = false;
		    let launcherMode = "new";
		    let launcherPermission = "workspace-write";
		    let launcherResumeSessionId = "";
		    let controlSearchText = "";
		    let controlView = "discussion";
			    let controlPromptHistoryIndex = null;
			    let controlPromptHistorySessionKey = "";
		    let controlPromptHistoryDraft = "";
		    let pendingControlRender = false;
		    let renderedControlScrollKey = "";
		    let controlRenderDeferredAt = 0;
		    let controlRenderDeferTimer = null;
		    let controlTurnSelectInteracting = false;
		    const controlScrollPositions = {};
	    const controlInnerScrollPositions = {};
	    const controlTranscriptWindows = {};
	    const expandedControlMessages = {};
	    const markdownRenderCache = new Map();
	    const historyTurnCache = {};
	    const historyTurnRequests = {};
	    const historyTurnIndexes = {};
	    const historyIndexRequests = {};
	    const resumeCandidateIndexes = {};
	    const resumeCandidateRequests = {};
	    const selectedControlTurnKeys = {};
		    const manuallySelectedControlTurnKeys = {};
		    const latestObservedUserKeys = {};
		    const followLatestTurnAfterUserInput = {};
		    const selectedResumeCandidateIds = {};
	    const statsVisibleProfiles = {};
	    let pendingConfirmation = null;
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

	    function normalizeControlMessageTextForDisplay(value, role) {
	      let text = String(value || "").replace(/\r\n?/g, "\n");
	      if (["user", "user_pending", "resume", "context_compaction"].includes(String(role || ""))) {
	        text = text.replace(/^[\s\uFEFF\u200B\u200C\u200D]+|[\s\uFEFF\u200B\u200C\u200D]+$/g, "");
	      }
	      return text;
	    }

	    function safeMarkdownHref(value) {
	      const raw = String(value || "").trim();
	      if (!raw) return "";
	      if (raw.startsWith("#")) return escapeHtml(raw);
	      try {
	        const parsed = new URL(raw, window.location.href);
	        if (!["http:", "https:", "mailto:"].includes(parsed.protocol)) return "";
	      } catch {
	        return "";
	      }
	      return escapeHtml(raw);
	    }

	    function restoreMarkdownTokens(html, inserts) {
	      return html.replace(/\u0000(\d+)\u0000/g, (_match, index) => inserts[Number(index)] || "");
	    }

	    function renderMarkdownInline(value) {
	      const inserts = [];
	      const token = (html) => {
	        inserts.push(html);
	        return `\u0000${inserts.length - 1}\u0000`;
	      };
	      let text = String(value || "");
	      text = text.replace(/`([^`\n]+)`/g, (_match, code) => (
	        token(`<code>${escapeHtml(code)}</code>`)
	      ));
	      text = text.replace(/\[([^\]\n]+)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g, (match, label, href) => {
	        const safeHref = safeMarkdownHref(href);
	        if (!safeHref) {
	          const rawHref = String(href || "").trim();
	          if (/^(?:\/|~\/|\.{1,2}\/)/.test(rawHref)) {
	            return token(`<code class="markdown-file-ref" title="${escapeHtml(rawHref)}">${escapeHtml(label)}</code>`);
	          }
	          return match;
	        }
	        return token(`<a href="${safeHref}" target="_blank" rel="noreferrer">${renderMarkdownInline(label)}</a>`);
	      });
	      text = text.replace(/(^|[\s([{,;])([A-Za-z_][A-Za-z0-9_.-]*=[A-Za-z0-9_./:-]+)/g, (_match, prefix, assignment) => (
	        `${prefix}${token(`<code>${escapeHtml(assignment)}</code>`)}`
	      ));
	      let html = escapeHtml(text);
	      html = html.replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>");
	      html = html.replace(/__([^_\n]+)__/g, "<strong>$1</strong>");
	      html = html.replace(/~~([^~\n]+)~~/g, "<del>$1</del>");
	      html = html.replace(/(^|[\s(])\*([^*\n]+)\*(?=$|[\s).,;:!?])/g, "$1<em>$2</em>");
	      html = html.replace(/(^|[\s(])_([^_\n]+)_(?=$|[\s).,;:!?])/g, "$1<em>$2</em>");
	      return restoreMarkdownTokens(html, inserts);
	    }

	    function parseJsonControlMessage(value) {
	      const text = String(value || "").trim();
	      if (!text || !/^[{[]/.test(text) || !/[}\]]$/.test(text)) return null;
	      try {
	        return JSON.parse(text);
	      } catch {
	        return null;
	      }
	    }

	    function renderMarkdownCodeBlock(value, language = "") {
	      const lang = language ? ` data-language="${escapeHtml(language)}"` : "";
	      return `<pre${lang}><code>${escapeHtml(value)}</code></pre>`;
	    }

	    function renderJsonControlMessage(value) {
	      const parsed = parseJsonControlMessage(value);
	      if (parsed === null) return "";
	      return renderMarkdownCodeBlock(JSON.stringify(parsed, null, 2), "json");
	    }

	    function cachedMarkdownRender(cacheKey, renderer) {
	      if (markdownRenderCache.has(cacheKey)) {
	        const value = markdownRenderCache.get(cacheKey);
	        markdownRenderCache.delete(cacheKey);
	        markdownRenderCache.set(cacheKey, value);
	        return value;
	      }
	      const value = renderer();
	      markdownRenderCache.set(cacheKey, value);
	      while (markdownRenderCache.size > 600) {
	        const first = markdownRenderCache.keys().next().value;
	        markdownRenderCache.delete(first);
	      }
	      return value;
	    }

			    function repairStreamedMarkdownSource(value) {
			      let source = String(value || "").replace(/\r\n?/g, "\n");
			      source = source.replace(/^(\s*)~~~([A-Za-z0-9_.+-]*)\s*$/gm, "$1```$2");
			      source = source.replace(/\[\s*\n{2,}\s*([^\]\n]{1,160}?)\s*\]/g, (_match, label) => `[${label.trim()}]`);
		      source = source.replace(/\[([^\]\n]{1,120}?)\s*\n{2,}\s*([^\]\n]{1,120}?)\]/g, (_match, left, right) => {
		        const label = `${left.trim()}${right.trim()}`;
		        return label.length <= 180 ? `[${label}]` : _match;
		      });
		      source = source.replace(/\]\s*\n{2,}\s*\(([^)\n]{1,500})\)/g, (_match, href) => `](${href.trim()})`);
		      source = source.replace(/\bx\n{2,}Unit\b/g, "xUnit");
		      return source;
		    }

	    function normalizeMarkdownSource(value) {
	      const lines = repairStreamedMarkdownSource(value).split("\n");
	      let inFence = false;
	      let fenceLanguage = "";
	      let repairFenceLines = false;
	      let passthroughMarkdownFence = false;
	      let yamlRepairStack = [];
	      let jsonRepairIndent = 0;
	      const normalizeFenceCodeLine = (line, lang) => {
	        const raw = String(line || "");
	        if (/^json$/i.test(lang)) {
	          const rendered = [];
	          for (const rawLine of raw.split("\n")) {
	            let text = rawLine.trim();
	            if (!text) {
	              rendered.push("");
	              continue;
	            }
	            const trailingClosers = [];
	            while (!/^[}\]],?$/.test(text)) {
	              const closeMatch = text.match(/^(.*\S)\s*([}\]])(,?)$/);
	              if (!closeMatch) break;
	              text = closeMatch[1].trimEnd();
	              trailingClosers.unshift(`${closeMatch[2]}${closeMatch[3] || ""}`);
	            }
	            while (/^[}\]]/.test(text)) {
	              jsonRepairIndent = Math.max(0, jsonRepairIndent - 1);
	              const close = text.slice(0, text[1] === "," ? 2 : 1);
	              rendered.push(`${" ".repeat(jsonRepairIndent * 2)}${close}`);
	              text = text.slice(close.length).trim();
	            }
	            if (text) {
	              rendered.push(`${" ".repeat(jsonRepairIndent * 2)}${text}`);
	              if (/[{[]\s*,?$/.test(text)) {
	                jsonRepairIndent += 1;
	              }
	            }
	            for (const close of trailingClosers) {
	              jsonRepairIndent = Math.max(0, jsonRepairIndent - 1);
	              rendered.push(`${" ".repeat(jsonRepairIndent * 2)}${close}`);
	            }
	          }
	          return rendered.join("\n");
	        }
	        if (/^(?:yaml|yml)$/i.test(lang)) {
	          const matches = Array.from(raw.matchAll(/[A-Za-z_][A-Za-z0-9_-]*:/g));
	          if (!matches.length) return raw;
	          const parentKeys = new Set(["launcher", "quota", "resume", "metadata"]);
	          const rendered = [];
	          for (let index = 0; index < matches.length; index += 1) {
	            const match = matches[index];
	            const next = matches[index + 1];
	            const segment = raw.slice(match.index, next ? next.index : undefined).trim();
	            const colon = segment.indexOf(":");
	            if (colon < 0) continue;
	            const key = segment.slice(0, colon).trim();
	            const value = segment.slice(colon + 1).trim();
	            let indent = Math.max(0, yamlRepairStack.length) * 2;
	            if (!value) {
	              if (!yamlRepairStack.length || key === "session") {
	                indent = 0;
	                yamlRepairStack = [key];
	              } else if (parentKeys.has(key) && yamlRepairStack[0] === "session") {
	                indent = 2;
	                yamlRepairStack = ["session", key];
	              } else {
	                yamlRepairStack.push(key);
	              }
	            }
	            rendered.push(`${" ".repeat(indent)}${key}:${value ? ` ${value}` : ""}`);
	          }
	          return rendered.join("\n");
	        }
	        if (/^(?:text|txt)$/i.test(lang)) {
	          return raw.replace(/(\S)(\d{2}:\d{2}:\d{2}\s+)/g, "$1\n$2");
	        }
	        return raw;
	      };
	      const normalizeLine = (line, options = {}) => {
	        let normalized = line;
	        if (options.markdownPassthrough) {
	          normalized = normalized.replace(/\s*```\s*$/, "");
	          normalized = normalized.replace(/^(#{1,4}\s+)([A-Z][A-Za-z0-9_./:+ -]*?)-\s+([A-Z0-9].*)$/, "$1$2\n\n- $3");
	          normalized = normalized.replace(/^(#{1,4}\s+)([A-Z][A-Za-z0-9_./:+-]*?)([A-Z][a-z].*)$/, "$1$2\n\n$3");
	          normalized = normalized.replace(/([A-Za-z0-9`)])-\s+([A-Z][A-Za-z0-9])/g, "$1\n- $2");
	        }
	        normalized = normalized.replace(/^(#{1,4}\s+.*?)(Working directory:\s*)/i, "$1\n\n$2");
	        normalized = normalized.replace(/(Working directory:\s+.*?)(Current status:)/i, "$1\n\n$2");
	        normalized = normalized.replace(/([^#\n])\s*(#{1,4}\s+\S)/g, "$1\n\n$2");
	        normalized = normalized.replace(/([^\n])\s*([-*+]\s+\[[ xX]\]\s+\S)/g, "$1\n$2");
	        normalized = normalized.replace(/([^\n])\s*([-*+]\s+\*\*\S)/g, "$1\n$2");
		        normalized = normalized.replace(/([.!?:])\s*([-*+]\s+\S)/g, "$1\n$2");
		        normalized = normalized.replace(/([.!?:])\s*-(\d+)(\s+\S.*)$/g, "$1\n- $2$3");
	        normalized = normalized.replace(/([A-Za-z0-9`)])-\s+([A-Z`])/g, "$1\n- $2");
	        normalized = normalized.replace(/^(\s*)-(\d+)(\s+\S.*)$/g, "$1- $2$3");
	        return normalized;
	      };
	      return lines.map((line) => {
	        const malformedFence = !inFence
	          ? line.match(/^\s*```(markdown|md|json|yaml|yml|toml|ini|bash|sh|shell|python|py|javascript|js|typescript|ts|html|css|xml|sql|text|txt)(?=\S)(.*)$/i)
	          : null;
	        if (malformedFence) {
	          const lang = malformedFence[1] || "";
	          const rest = malformedFence[2] || "";
	          if (/^(?:md|markdown)$/i.test(lang)) {
	            passthroughMarkdownFence = true;
	            return normalizeLine(rest, { markdownPassthrough: true });
	          }
	          inFence = true;
	          fenceLanguage = lang;
	          repairFenceLines = true;
	          yamlRepairStack = [];
	          jsonRepairIndent = 0;
	          const trailingFence = rest.match(/^(.*\S)\s*```\s*$/);
	          if (trailingFence) {
	            inFence = false;
	            fenceLanguage = "";
	            repairFenceLines = false;
	            const repaired = normalizeFenceCodeLine(trailingFence[1], lang);
	            yamlRepairStack = [];
	            jsonRepairIndent = 0;
	            return `\`\`\`${lang}\n${repaired}\n\`\`\``;
	          }
	          return `\`\`\`${lang}\n${normalizeFenceCodeLine(rest, lang)}`;
	        }
	        if (passthroughMarkdownFence) {
	          if (/^\s*```\s*$/.test(line)) {
	            passthroughMarkdownFence = false;
	            return "";
	          }
	          const trailingFence = line.match(/^(.*\S)\s*```\s*$/);
	          if (trailingFence) {
	            passthroughMarkdownFence = false;
	            return normalizeLine(trailingFence[1], { markdownPassthrough: true });
	          }
	          return normalizeLine(line, { markdownPassthrough: true });
	        }
	        if (/^\s*```/.test(line)) {
	          inFence = !inFence;
	          fenceLanguage = inFence ? (line.trim().match(/^```([A-Za-z0-9_.+-]*)/) || [])[1] || "" : "";
	          repairFenceLines = false;
	          yamlRepairStack = [];
	          jsonRepairIndent = 0;
	          return line;
	        }
	        if (inFence) {
	          const trailingFence = line.match(/^(.*\S)\s*```\s*$/);
	          if (trailingFence) {
	            inFence = false;
	            const repaired = repairFenceLines
	              ? normalizeFenceCodeLine(trailingFence[1], fenceLanguage)
	              : trailingFence[1];
	            fenceLanguage = "";
	            repairFenceLines = false;
	            yamlRepairStack = [];
	            jsonRepairIndent = 0;
	            return `${repaired}\n\`\`\``;
	          }
	          return repairFenceLines ? normalizeFenceCodeLine(line, fenceLanguage) : line;
	        }
	        return normalizeLine(line);
	      }).join("\n");
	    }

	    function markdownBlockStarts(lines, index) {
	      const line = lines[index] || "";
	      const next = lines[index + 1] || "";
	      return (
	        /^```/.test(line.trim())
	        || /^\s{0,3}#{1,4}\s+/.test(line)
	        || /^\s{0,3}>\s?/.test(line)
	        || /^\s*([-*+])\s+/.test(line)
	        || /^\s*\d+\.\s+/.test(line)
	        || /^\s{0,3}[-*_](?:\s*[-*_]){2,}\s*$/.test(line)
	        || markdownTableStarts(line, next)
	      );
	    }

	    function markdownTableStarts(line, next) {
	      return line.includes("|") && /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(next || "");
	    }

	    function markdownTableCells(line) {
	      let text = String(line || "").trim();
	      if (text.startsWith("|")) text = text.slice(1);
	      if (text.endsWith("|")) text = text.slice(0, -1);
	      return text.split("|").map((cell) => cell.trim());
	    }

	    function renderMarkdownTable(lines, index) {
	      const headers = markdownTableCells(lines[index]);
	      let cursor = index + 2;
	      const rows = [];
	      while (cursor < lines.length && lines[cursor].includes("|") && lines[cursor].trim()) {
	        rows.push(markdownTableCells(lines[cursor]));
	        cursor += 1;
	      }
	      const head = headers.map((cell) => `<th>${renderMarkdownInline(cell)}</th>`).join("");
	      const body = rows.map((row) => (
	        `<tr>${headers.map((_header, cellIndex) => `<td>${renderMarkdownInline(row[cellIndex] || "")}</td>`).join("")}</tr>`
	      )).join("");
	      return {
	        html: `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`,
	        index: cursor
	      };
	    }

	    function markdownIndentedCodeLines(lines, index) {
	      const codeLines = [];
	      let cursor = index;
	      while (cursor < lines.length && (/^(?: {4}|\t)/.test(lines[cursor]) || !lines[cursor].trim())) {
	        if (!lines[cursor].trim()) {
	          codeLines.push("");
	        } else {
	          codeLines.push(lines[cursor].replace(/^(?: {4}|\t)/, ""));
	        }
	        cursor += 1;
	      }
	      while (codeLines.length && !codeLines[codeLines.length - 1]) codeLines.pop();
	      return { codeLines, index: cursor };
	    }

	    function markdownIndentedCodeLooksIntentional(codeLines) {
	      const meaningful = codeLines.map((line) => line.trim()).filter(Boolean);
	      if (!meaningful.length) return false;
	      const strongCodeLine = meaningful.some((line) => (
	        /^[$>#]\s+/.test(line)
	        || /\s--?[A-Za-z0-9][\w-]*/.test(line)
	        || /(?:[{}[\];=]|=>|<\/?\w|&&|\|\|)/.test(line)
	      ));
	      const commandShaped = meaningful.every((line) => (
	        /^[A-Za-z0-9_./-]+(?:\s+[A-Za-z0-9_./:-]+){0,8}$/.test(line)
	      ));
	      const proseLike = meaningful.some((line) => (
	        line.split(/\s+/).length >= 10
	        && /[,.!?;:]/.test(line)
	        && !/\s--?[A-Za-z0-9][\w-]*/.test(line)
	      ));
	      return !proseLike && (strongCodeLine || (meaningful.length <= 4 && commandShaped));
	    }

	    function renderMarkdown(value) {
	      const lines = normalizeMarkdownSource(value).split("\n");
	      const blocks = [];
	      let index = 0;
	      while (index < lines.length) {
	        const line = lines[index];
	        const trimmed = line.trim();
	        if (!trimmed) {
	          index += 1;
	          continue;
	        }
	        if (/^(?: {4}|\t)/.test(line)) {
	          const rendered = markdownIndentedCodeLines(lines, index);
	          if (markdownIndentedCodeLooksIntentional(rendered.codeLines)) {
	            blocks.push(`<pre><code>${escapeHtml(rendered.codeLines.join("\n"))}</code></pre>`);
	            index = rendered.index;
	            continue;
	          }
	        }
	        const fence = trimmed.match(/^```([A-Za-z0-9_.+-]*)\s*$/);
	        if (fence) {
	          const codeLines = [];
	          index += 1;
	          while (index < lines.length && !/^```\s*$/.test(lines[index].trim())) {
	            codeLines.push(lines[index]);
	            index += 1;
	          }
	          if (index < lines.length) index += 1;
	          blocks.push(renderMarkdownCodeBlock(codeLines.join("\n"), fence[1] || ""));
	          continue;
	        }
	        const heading = line.match(/^\s{0,3}(#{1,4})\s+(.+)$/);
	        if (heading) {
	          const level = heading[1].length;
	          blocks.push(`<h${level}>${renderMarkdownInline(heading[2].trim())}</h${level}>`);
	          index += 1;
	          continue;
	        }
	        if (/^\s{0,3}[-*_](?:\s*[-*_]){2,}\s*$/.test(line)) {
	          blocks.push("<hr>");
	          index += 1;
	          continue;
	        }
	        if (markdownTableStarts(line, lines[index + 1] || "")) {
	          const rendered = renderMarkdownTable(lines, index);
	          blocks.push(rendered.html);
	          index = rendered.index;
	          continue;
	        }
	        if (/^\s{0,3}>\s?/.test(line)) {
	          const quoteLines = [];
	          while (index < lines.length && /^\s{0,3}>\s?/.test(lines[index])) {
	            quoteLines.push(lines[index].replace(/^\s{0,3}>\s?/, ""));
	            index += 1;
	          }
	          blocks.push(`<blockquote>${renderMarkdown(quoteLines.join("\n"))}</blockquote>`);
	          continue;
	        }
	        const unordered = line.match(/^\s*([-*+])\s+(.+)$/);
	        const ordered = line.match(/^\s*(\d+)\.\s+(.+)$/);
	        if (unordered || ordered) {
	          const listTag = ordered ? "ol" : "ul";
	          const start = ordered ? Math.max(1, Number(ordered[1] || 1)) : 1;
	          const items = [];
	          while (index < lines.length) {
	            const current = lines[index];
	            const itemMatch = listTag === "ol"
	              ? current.match(/^\s*\d+\.\s+(.+)$/)
	              : current.match(/^\s*[-*+]\s+(.+)$/);
	            if (!itemMatch) {
	              if (!current.trim() && index + 1 < lines.length) {
	                const next = lines[index + 1] || "";
	                const nextItem = listTag === "ol"
	                  ? next.match(/^\s*\d+\.\s+(.+)$/)
	                  : next.match(/^\s*[-*+]\s+(.+)$/);
	                if (nextItem) {
	                  index += 1;
	                  continue;
	                }
	              }
	              break;
	            }
	            const itemLines = [itemMatch[1]];
	            index += 1;
	            while (index < lines.length && /^\s{2,}\S/.test(lines[index]) && !markdownBlockStarts(lines, index)) {
	              itemLines.push(lines[index].trim());
	              index += 1;
	            }
	            items.push(`<li>${itemLines.map((itemLine) => renderMarkdownInline(itemLine)).join("<br>")}</li>`);
	          }
	          const startAttr = listTag === "ol" && start > 1 ? ` start="${start}"` : "";
	          blocks.push(`<${listTag}${startAttr}>${items.join("")}</${listTag}>`);
	          continue;
	        }
	        const paragraph = [];
	        while (index < lines.length && lines[index].trim() && !markdownBlockStarts(lines, index)) {
	          paragraph.push(lines[index].trim());
	          index += 1;
	        }
	        if (paragraph.length) {
	          blocks.push(`<p>${paragraph.map((part) => renderMarkdownInline(part)).join("<br>")}</p>`);
	        } else {
	          index += 1;
	        }
	      }
	      return blocks.join("");
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

	    function scrollSnapshot(element) {
	      if (!element) return null;
	      return {
	        top: element.scrollTop,
	        atBottom: element.scrollHeight - element.scrollTop - element.clientHeight < 24
	      };
	    }

	    function restoreScrollSnapshot(element, snapshot) {
	      if (!element || !snapshot) return;
	      element.scrollTop = snapshot.atBottom
	        ? Math.max(0, element.scrollHeight - element.clientHeight)
	        : snapshot.top;
	    }

	    function formatAge(seconds) {
	      const value = Number(seconds);
	      if (!Number.isFinite(value)) return "";
	      if (value < 60) return `${Math.max(0, Math.round(value))}s`;
	      if (value < 3600) return `${Math.round(value / 60)}m`;
	      return `${(value / 3600).toFixed(1)}h`;
	    }

	    function controlPlane(status) {
	      return status && status.control_plane && typeof status.control_plane === "object"
	        ? status.control_plane
	        : latestControlPlane || { sessions: [] };
	    }

	    function controlSessions(status) {
	      const plane = controlPlane(status);
	      return Array.isArray(plane.sessions) ? plane.sessions : [];
	    }

	    function sessionTitle(session) {
	      return String(session.title || session.name || session.display || session.cwd || "Session");
	    }

	    function sessionMeta(session) {
	      const pieces = [];
	      if (session.pinned_profile) pieces.push(`pinned ${session.pinned_profile}`);
	      else if (session.last_profile) pieces.push(`last ${session.last_profile}`);
	      const active = Number(session.active_requests || 0);
	      const pending = Number(session.pending_websocket_work || 0);
	      const tunnels = Number(session.active_tunnels || 0);
	      if (active) pieces.push(`${active} request${active === 1 ? "" : "s"}`);
	      if (pending) pieces.push(`${pending} turn${pending === 1 ? "" : "s"}`);
	      else if (tunnels) pieces.push(`${tunnels} tunnel${tunnels === 1 ? "" : "s"}`);
	      return pieces.join(" / ") || String(session.display || session.cwd || "idle");
	    }

	    function updateControlDockGeometry() {
	      const modal = document.getElementById("controlModal");
	      const tabs = document.getElementById("sessionTabs");
	      if (!modal || !tabs) return;
	      const top = tabs.offsetTop + tabs.offsetHeight + 8;
	      modal.style.setProperty("--control-dock-top", `${Math.max(0, top)}px`);
	      const launcher = document.getElementById("launcherBar");
	      if (launcher) launcher.style.setProperty("--control-dock-top", `${Math.max(0, top)}px`);
		      const stats = document.getElementById("statsModal");
		      if (stats) {
		        const tabsTop = tabs.getBoundingClientRect().top;
		        stats.style.setProperty("--stats-modal-top", `${Math.max(0, tabsTop)}px`);
		      }
	    }

	    function controlScrollKey() {
	      const turn = selectedControlTurnKeys[selectedControlSessionKey || ""] || "";
	      return `${selectedControlSessionKey || "none"}:${controlView || "discussion"}:${turn}:${controlSearchText || ""}`;
	    }

		    function controlTranscriptWindowKey() {
		      return `${selectedControlSessionKey || "none"}:${controlSearchText || ""}`;
		    }

		    function controlTranscriptWindow(total) {
		      if (total <= CONTROL_TRANSCRIPT_WINDOW_SIZE) {
		        return { start: 0, end: total };
		      }
		      const key = controlTranscriptWindowKey();
		      const existing = controlTranscriptWindows[key];
		      if (!existing) {
		        const start = Math.max(0, total - CONTROL_TRANSCRIPT_WINDOW_SIZE);
		        const value = { start, end: total, previousTotal: total };
		        controlTranscriptWindows[key] = value;
		        return value;
		      }
		      if (total > existing.previousTotal && existing.end >= existing.previousTotal) {
		        const delta = total - existing.previousTotal;
		        existing.end = total;
		        existing.start = Math.max(0, existing.start + delta);
		      }
		      existing.start = Math.max(0, Math.min(existing.start, total - 1));
		      existing.end = Math.max(existing.start + 1, Math.min(existing.end, total));
		      existing.previousTotal = total;
		      return existing;
		    }

		    function expandControlTranscriptWindow(direction) {
		      const key = controlTranscriptWindowKey();
		      const current = controlTranscriptWindows[key];
		      if (!current) return false;
		      const oldStart = current.start;
		      const oldEnd = current.end;
		      const total = Number(current.previousTotal || 0);
		      if (direction === "above") {
		        current.start = Math.max(0, current.start - CONTROL_TRANSCRIPT_WINDOW_STEP);
		      } else {
		        current.end = Math.min(total, current.end + CONTROL_TRANSCRIPT_WINDOW_STEP);
		      }
		      return oldStart !== current.start || oldEnd !== current.end;
		    }

	    function saveControlScroll() {
	      const content = document.getElementById("controlContent");
	      if (!content) return;
	      const key = renderedControlScrollKey || controlScrollKey();
	      controlScrollPositions[key] = content.scrollTop;
	    }

	    function saveControlInnerScroll() {
	      const content = document.getElementById("controlContent");
	      if (!content) return;
	      const prefix = renderedControlScrollKey || controlScrollKey();
	      content.querySelectorAll("[data-control-inner-scroll]").forEach((element) => {
	        const key = element.dataset.controlInnerScroll || "";
	        if (!key) return;
	        controlInnerScrollPositions[`${prefix}::${key}`] = element.scrollTop;
	      });
	    }

	    function restoreControlScroll() {
	      const content = document.getElementById("controlContent");
	      if (!content) return;
	      const top = controlScrollPositions[controlScrollKey()];
	      if (typeof top === "number") content.scrollTop = top;
	    }

	    function restoreControlInnerScroll() {
	      const content = document.getElementById("controlContent");
	      if (!content) return;
	      const prefix = controlScrollKey();
	      content.querySelectorAll("[data-control-inner-scroll]").forEach((element) => {
	        const key = element.dataset.controlInnerScroll || "";
	        const top = controlInnerScrollPositions[`${prefix}::${key}`];
	        if (typeof top === "number") element.scrollTop = top;
	      });
	    }

	    function controlContentAtBottom(content) {
	      if (!content) return true;
	      return content.scrollHeight - content.scrollTop - content.clientHeight < 24;
	    }

		    function updateControlScrollBadges() {
		      const content = document.getElementById("controlContent");
		      if (!content || controlView !== "discussion") return;
		      const transcript = content.querySelector(".control-transcript");
		      const topBadge = content.querySelector("[data-control-scroll='above']");
		      const bottomBadge = content.querySelector("[data-control-scroll='below']");
		      if (!transcript || !topBadge || !bottomBadge) return;
		      const bounds = content.getBoundingClientRect();
		      const hiddenAbove = Number(transcript.dataset.hiddenAbove || 0);
		      const hiddenBelow = Number(transcript.dataset.hiddenBelow || 0);
		      let visibleAbove = 0;
		      let visibleBelow = 0;
		      for (const item of transcript.querySelectorAll(".control-message[data-transcript-index]")) {
		        const itemBounds = item.getBoundingClientRect();
		        if (itemBounds.bottom < bounds.top + 8) visibleAbove += 1;
		        if (itemBounds.top > bounds.bottom - 8) visibleBelow += 1;
		      }
		      const above = hiddenAbove + visibleAbove;
		      const below = hiddenBelow + visibleBelow;
		      topBadge.hidden = above <= 0;
		      bottomBadge.hidden = below <= 0;
		      topBadge.textContent = `${above} above`;
		      bottomBadge.textContent = `${below} below`;
		      topBadge.title = hiddenAbove > 0 ? `Show older hidden transcript entries (${hiddenAbove} hidden)` : "Scroll upward";
		      bottomBadge.title = hiddenBelow > 0 ? `Show newer hidden transcript entries (${hiddenBelow} hidden)` : "Scroll downward";
		    }

	    function controlSelectionActive() {
	      const modal = document.getElementById("controlModal");
	      const selection = window.getSelection ? window.getSelection() : null;
	      if (!modal || !selection || selection.isCollapsed || !selection.rangeCount) return false;
	      const anchor = selection.anchorNode && selection.anchorNode.nodeType === Node.ELEMENT_NODE
	        ? selection.anchorNode
	        : selection.anchorNode ? selection.anchorNode.parentElement : null;
	      const focus = selection.focusNode && selection.focusNode.nodeType === Node.ELEMENT_NODE
	        ? selection.focusNode
	        : selection.focusNode ? selection.focusNode.parentElement : null;
	      return Boolean((anchor && modal.contains(anchor)) || (focus && modal.contains(focus)));
	    }

	    function controlRenderShouldDefer() {
	      return controlSelectionActive();
	    }

	    function flushPendingControlRender() {
	      if (!pendingControlRender || controlRenderShouldDefer()) return;
	      renderControlModal(true);
	    }

	    function scheduleControlRenderFlush() {
	      if (controlRenderDeferTimer) return;
	      controlRenderDeferTimer = setTimeout(() => {
	        controlRenderDeferTimer = null;
	        if (pendingControlRender) renderControlModal(true);
	      }, 2050);
	    }

	    function renderSessionTabs(status) {
	      const container = document.getElementById("sessionTabs");
	      if (!container) return;
	      const sessions = controlSessions(status);
	      const launchSelected = launcherPanelOpen ? " selected" : "";
	      const launchTab = `
	        <button class="session-tab launch-tab${launchSelected}" type="button" data-launch-tab="1" title="Launch a Codex CLI session">
	          <span class="session-tab-title">+</span>
	          <span class="session-tab-meta">Launch</span>
	        </button>
	      `;
	      if (!sessions.length) {
	        selectedControlSessionKey = "";
	        container.innerHTML = '<div class="session-tabs-empty">No Provision-managed Codex CLI sessions observed yet</div>' + launchTab;
	        updateControlDockGeometry();
	        return;
	      }
	      if (selectedControlSessionKey && !sessions.some((session) => session.key === selectedControlSessionKey)) {
	        selectedControlSessionKey = "";
	      }
	      container.innerHTML = sessions.map((session) => {
	        const key = String(session.key || "");
	        const active = session.active ? " active" : "";
	        const selected = key && key === selectedControlSessionKey ? " selected" : "";
	        return `
          <button class="session-tab${active}${selected}" type="button" draggable="true" data-session-key="${escapeHtml(key)}" title="${escapeHtml(session.cwd || session.display || key)}">
            <span class="session-tab-close" data-session-close="${escapeHtml(key)}" aria-label="Close tab" title="Close tab">x</span>
            <span class="session-tab-title">${escapeHtml(sessionTitle(session))}</span>
            <span class="session-tab-meta">${escapeHtml(sessionMeta(session))}</span>
          </button>
	        `;
	      }).join("") + launchTab;
	      updateControlDockGeometry();
	    }

		    function orderedSessionKeysFromTabs() {
		      return Array.from(document.querySelectorAll("#sessionTabs .session-tab[data-session-key]"))
		        .map((tab) => tab.dataset.sessionKey || "")
		        .filter(Boolean);
		    }

		    function clearSessionTabDropClasses() {
		      document.querySelectorAll("#sessionTabs .session-tab").forEach((tab) => {
		        tab.classList.remove("dragging", "drop-before", "drop-after");
		      });
		    }

		    function sendSessionTabOrder() {
		      if (!socket || socket.readyState !== WebSocket.OPEN) return;
		      const sessionKeys = orderedSessionKeysFromTabs();
		      if (!sessionKeys.length) return;
		      socket.send(JSON.stringify({
		        action: "reorder_sessions",
		        session_keys: sessionKeys,
		        token: TOKEN
		      }));
		    }

		    function sessionTabDropPosition(tab, event) {
		      const rect = tab.getBoundingClientRect();
		      return event.clientX > rect.left + rect.width / 2 ? "after" : "before";
		    }

		    async function forgetControlSession(sessionKey) {
		      if (!sessionKey || !socket || socket.readyState !== WebSocket.OPEN) return;
		      const sessions = controlSessions({ control_plane: latestControlPlane });
		      const session = sessions.find((item) => item.key === sessionKey);
		      if (!session) return;
		      const live = sessionIsLive(session);
		      const label = String(session.cwd || session.display || sessionKey);
		      if (live) {
		        const first = await confirmAction({
		          title: "Forget live session",
		          message: `This session appears live. Forgetting it will close the associated Codex CLI launcher and remove it from the dashboard:\n\n${label}`,
		          acceptLabel: "Continue",
		          danger: true
		        });
		        if (!first) return;
		        const second = await confirmAction({
		          title: "Close launcher",
		          message: `Confirm again: close this live launcher and forget the session?\n\n${label}`,
		          acceptLabel: "Close launcher",
		          danger: true
		        });
		        if (!second) return;
		      } else {
		        const confirmed = await confirmAction({
		          title: "Forget session",
		          message: `Forget this idle observed session from the dashboard?\n\n${label}`,
		          acceptLabel: "Forget",
		          danger: false
		        });
		        if (!confirmed) return;
		      }
		      socket.send(JSON.stringify({
		        action: "forget_session",
		        session_key: sessionKey,
		        force_live: live,
		        token: TOKEN
		      }));
		      if (selectedControlSessionKey === sessionKey) {
		        selectedControlSessionKey = "";
		        const modal = document.getElementById("controlModal");
		        if (modal) modal.hidden = true;
		      }
		    }

	    function launcherSessionScore(session) {
	      const key = String(session.key || "");
	      let score = 0;
	      if (key && key === selectedControlSessionKey) score += 16;
	      if (key && key === selectedLauncherSessionKey) score += 8;
	      if (!session.ui_launched) score += 4;
	      if (session.pty_control_available) score += 2;
	      if (session.active) score += 1;
	      return score;
	    }

		    function dedupedLauncherSessions(sessions) {
		      const byWorkdir = new Map();
	      for (const session of sessions) {
	        const key = String(session.key || "");
	        const cwd = String(session.cwd || session.display || key);
	        if (!key || !cwd) continue;
	        const workdirKey = cwd;
	        const existing = byWorkdir.get(workdirKey);
	        if (!existing || launcherSessionScore(session) > launcherSessionScore(existing)) {
	          byWorkdir.set(workdirKey, session);
	        }
	      }
		      return Array.from(byWorkdir.values());
		    }

		    function renderResumeCandidateOptions(candidates, selectedId) {
		      if (!candidates.length) return '<option value="">No resumable sessions found</option>';
		      return candidates.map((candidate) => {
		        const id = String(candidate.id || "");
		        const when = candidate.timestamp ? formatEventTime(candidate.timestamp) : "";
		        const label = `${when ? `${when} - ` : ""}${candidate.label || id}`;
		        return `<option value="${escapeHtml(id)}" ${id === selectedId ? "selected" : ""}>${escapeHtml(label)}</option>`;
		      }).join("");
		    }

		    function renderLauncherBar(status) {
		      const bar = document.getElementById("launcherBar");
		      const select = document.getElementById("launcherSession");
		      const modeSelect = document.getElementById("launcherMode");
		      const permissionSelect = document.getElementById("launcherPermission");
		      const resumeField = document.getElementById("launcherResumeField");
		      const resumeSelect = document.getElementById("launcherResumeSession");
		      const start = document.getElementById("launcherStart");
		      if (!bar || !select || !modeSelect || !permissionSelect || !resumeField || !resumeSelect || !start) return;
		      bar.hidden = !launcherPanelOpen;
		      if (!launcherPanelOpen) {
		        updateControlDockGeometry();
		        return;
	      }
	      const sessions = controlSessions(status);
	      const known = dedupedLauncherSessions(sessions);
	      if (!selectedLauncherSessionKey && selectedControlSessionKey && known.some((session) => session.key === selectedControlSessionKey)) {
	        selectedLauncherSessionKey = selectedControlSessionKey;
	      }
	      if (!selectedLauncherSessionKey || !known.some((session) => session.key === selectedLauncherSessionKey)) {
	        selectedLauncherSessionKey = known.length ? String(known[0].key || "") : "";
	      }
	      select.innerHTML = known.length
	        ? known.map((session) => {
	          const key = String(session.key || "");
	          const label = `${session.cwd || session.display || key}${session.associated_profile ? ` (${session.associated_profile})` : ""}`;
	          return `<option value="${escapeHtml(key)}" ${key === selectedLauncherSessionKey ? "selected" : ""}>${escapeHtml(label)}</option>`;
	        }).join("")
		        : '<option value="">No observed workdirs</option>';
	      select.disabled = !known.length;
	      const selectedSession = known.find((session) => String(session.key || "") === selectedLauncherSessionKey) || null;
	      if (selectedSession) requestResumeCandidates(selectedSession);
	      const candidates = selectedSession ? resumeCandidatesForSession(selectedSession) : [];
		      if (!launcherResumeSessionId || !candidates.some((candidate) => String(candidate.id || "") === launcherResumeSessionId)) {
		        launcherResumeSessionId = candidates.length ? String(candidates[0].id || "") : "";
		      }
		      modeSelect.value = launcherMode;
		      permissionSelect.value = launcherPermission;
		      resumeField.hidden = launcherMode !== "resume-session";
		      resumeSelect.innerHTML = renderResumeCandidateOptions(candidates, launcherResumeSessionId);
		      resumeSelect.disabled = launcherMode !== "resume-session" || !candidates.length;
		      const needsResumeSelection = launcherMode === "resume-session";
		      start.disabled = !known.length
		        || !socket
		        || socket.readyState !== WebSocket.OPEN
		        || (needsResumeSelection && !launcherResumeSessionId);
		      updateControlDockGeometry();
		    }

	    function selectedControlSession() {
	      const sessions = controlSessions({ control_plane: latestControlPlane });
	      return sessions.find((session) => session.key === selectedControlSessionKey) || null;
	    }

	    function controlCapabilityText(session) {
	      const interaction = latestControlPlane && typeof latestControlPlane.interaction === "object"
	        ? latestControlPlane.interaction
	        : {};
	      const sessionInteraction = session && typeof session.interaction === "object"
	        ? session.interaction
	        : {};
	      if (sessionInteraction.reason) return String(sessionInteraction.reason);
	      return String(interaction.reason || "Launch this Codex CLI session with `provision` to enable live UI input.");
	    }

	    function controlInteractionAvailable(session) {
	      return Boolean(session && session.interaction && session.interaction.available);
	    }

	    function updateControlComposeState(session) {
	      const prompt = document.getElementById("controlPrompt");
	      const button = document.getElementById("controlSend");
	      const available = controlInteractionAvailable(session);
	      prompt.disabled = !available;
	      button.disabled = !available || !prompt.value.trim();
	      prompt.placeholder = available
	        ? "Send to running Codex CLI"
	        : controlCapabilityText(session);
	    }

		    function resetControlPromptHistory() {
		      controlPromptHistoryIndex = null;
		      controlPromptHistorySessionKey = "";
		      controlPromptHistoryDraft = "";
		    }

		    function controlPromptHistory(session) {
		      const transcript = session && Array.isArray(session.transcript) ? session.transcript : [];
		      const history = [];
		      let previous = "";
		      for (const item of transcript) {
		        if (String(item.role || "") !== "user") continue;
		        const text = String(item.full_text || item.text || "").trim();
		        if (!text || text === previous) continue;
		        previous = text;
		        history.push(text);
		      }
		      return history;
		    }

		    function setControlPromptValue(value) {
		      const prompt = document.getElementById("controlPrompt");
		      if (!prompt) return;
		      prompt.value = value;
		      updateControlComposeState(selectedControlSession());
		      requestAnimationFrame(() => {
		        const end = prompt.value.length;
		        try {
		          prompt.setSelectionRange(end, end);
		        } catch {
		        }
		      });
		    }

		    function handleControlPromptHistory(event) {
		      if (!["ArrowUp", "ArrowDown"].includes(event.key) || event.shiftKey || event.altKey || event.metaKey || event.ctrlKey) {
		        return false;
		      }
		      const prompt = event.currentTarget;
		      if (!(prompt instanceof HTMLTextAreaElement) || prompt.disabled) return false;
		      const browsing = controlPromptHistoryIndex !== null
		        && controlPromptHistorySessionKey === selectedControlSessionKey;
		      if (prompt.value.trim() && !browsing) return false;
		      const history = controlPromptHistory(selectedControlSession());
		      if (!history.length) return false;
		      event.preventDefault();
		      if (!browsing) {
		        controlPromptHistorySessionKey = selectedControlSessionKey;
		        controlPromptHistoryDraft = prompt.value;
		        controlPromptHistoryIndex = history.length;
		      }
		      if (event.key === "ArrowUp") {
		        controlPromptHistoryIndex = Math.max(0, Number(controlPromptHistoryIndex) - 1);
		        setControlPromptValue(history[controlPromptHistoryIndex] || "");
		        return true;
		      }
		      controlPromptHistoryIndex = Math.min(history.length, Number(controlPromptHistoryIndex) + 1);
		      if (controlPromptHistoryIndex >= history.length) {
		        const draft = controlPromptHistoryDraft;
		        resetControlPromptHistory();
		        setControlPromptValue(draft);
		        return true;
		      }
		      setControlPromptValue(history[controlPromptHistoryIndex] || "");
		      return true;
		    }

	    function renderControlActiveDetails(session) {
	      const details = session.active_details && typeof session.active_details === "object" ? session.active_details : {};
	      const requests = Array.isArray(details.requests) ? details.requests : [];
	      const tunnels = Array.isArray(details.tunnels) ? details.tunnels : [];
	      const requestCards = requests.map((request) => `
	        <div class="control-active-card">
	          <strong>Request</strong>
	          <span>Profile: ${escapeHtml(request.profile || "unknown")}</span>
	          ${request.age_seconds != null ? `<span>Age: ${escapeHtml(formatAge(request.age_seconds))}</span>` : ""}
	        </div>
	      `);
	      const tunnelCards = tunnels.map((tunnel, index) => {
	        const traffic = `${formatBytes(tunnel.bytes_up)} up / ${formatBytes(tunnel.bytes_down)} down`;
	        const messages = `${formatNumber(tunnel.messages_up)} up / ${formatNumber(tunnel.messages_down)} down`;
	        const bits = [];
	        const hasTurn = Number(tunnel.pending_work || 0) > 0 || Boolean(tunnel.turn_id);
	        const label = `${hasTurn ? "Turn tunnel" : "Session tunnel"} ${index + 1}`;
	        if (Number(tunnel.pending_work || 0) > 0) bits.push("active");
	        else bits.push("idle");
	        if (tunnel.service_tier) bits.push(String(tunnel.service_tier));
	        return `
	          <div class="control-active-card">
	            <strong>${escapeHtml(label)}${bits.length ? ` (${escapeHtml(bits.join(", "))})` : ""}</strong>
	            <span>Profile: ${escapeHtml(tunnel.profile || "unknown")}</span>
	            ${tunnel.turn_id ? `<span>Turn: ${escapeHtml(tunnel.turn_id)}</span>` : ""}
	            ${tunnel.age_seconds != null ? `<span>Open: ${escapeHtml(formatAge(tunnel.age_seconds))}</span>` : ""}
	            ${tunnel.last_data_age_seconds != null ? `<span>Last data: ${escapeHtml(formatAge(tunnel.last_data_age_seconds))} ago</span>` : ""}
	            <span>Traffic: ${escapeHtml(traffic)}</span>
	            <span>Messages: ${escapeHtml(messages)}</span>
	          </div>
	        `;
	      });
	      const cards = requestCards.concat(tunnelCards);
	      if (!cards.length) return '<div class="control-empty">No active request or tunnel is currently attached to this session</div>';
	      return `<div class="control-active-grid">${cards.join("")}</div>`;
	    }

	    function controlTranscriptMatches(item, query) {
	      if (!query) return true;
	      const haystack = `${item.role || ""} ${item.text || ""} ${item.full_text || ""} ${item.search_text || ""}`.toLowerCase();
	      return haystack.includes(query.toLowerCase());
	    }

	    function controlTurnKey(turn) {
	      return String(turn && (turn.key || turn.turn_id || turn.start_index) || "");
	    }

	    function historyCacheKey(sessionKey, turnKey) {
	      return `${sessionKey || ""}\u0001${turnKey || ""}`;
	    }

	    function historyTurnPayload(session, turn) {
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      const turnKey = controlTurnKey(turn);
	      return historyTurnCache[historyCacheKey(sessionKey, turnKey)] || null;
	    }

	    function requestHistoryTurn(session, turn) {
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      const turnKey = controlTurnKey(turn);
	      if (!sessionKey || !turnKey || !socket || socket.readyState !== WebSocket.OPEN) return false;
	      const key = historyCacheKey(sessionKey, turnKey);
	      if (historyTurnCache[key] || historyTurnRequests[key]) return false;
	      historyTurnRequests[key] = true;
	      socket.send(JSON.stringify({
	        action: "load_history_turn",
	        session_key: sessionKey,
	        turn_key: turnKey,
	        token: TOKEN
	      }));
	      return true;
	    }

	    function historyTurnsForSession(session) {
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      if (Object.prototype.hasOwnProperty.call(historyTurnIndexes, sessionKey)) {
	        return historyTurnIndexes[sessionKey];
	      }
	      return session && Array.isArray(session.history_turns) ? session.history_turns : [];
	    }

	    function requestHistoryIndex(session) {
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      if (!sessionKey || !socket || socket.readyState !== WebSocket.OPEN) return false;
	      if (
	        Object.prototype.hasOwnProperty.call(historyTurnIndexes, sessionKey)
	        || historyIndexRequests[sessionKey]
	      ) return false;
	      historyIndexRequests[sessionKey] = true;
	      socket.send(JSON.stringify({
	        action: "load_history_index",
	        session_key: sessionKey,
	        token: TOKEN
	      }));
	      return true;
	    }

	    function resumeCandidatesForSession(session) {
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      if (Object.prototype.hasOwnProperty.call(resumeCandidateIndexes, sessionKey)) {
	        return resumeCandidateIndexes[sessionKey];
	      }
	      return session && Array.isArray(session.resume_candidates) ? session.resume_candidates : [];
	    }

	    function requestResumeCandidates(session) {
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      if (!sessionKey || !socket || socket.readyState !== WebSocket.OPEN) return false;
	      if (
	        Object.prototype.hasOwnProperty.call(resumeCandidateIndexes, sessionKey)
	        || resumeCandidateRequests[sessionKey]
	      ) return false;
	      resumeCandidateRequests[sessionKey] = true;
	      socket.send(JSON.stringify({
	        action: "load_resume_candidates",
	        session_key: sessionKey,
	        token: TOKEN
	      }));
	      return true;
	    }

	    function controlTurns(session, transcript = null) {
	      const liveTurns = session && Array.isArray(session.turns)
	        ? session.turns.map((turn) => ({ ...turn, source: turn.source || "live" }))
	        : [];
	      const historyTurns = historyTurnsForSession(session)
	        .map((turn) => ({ ...turn, source: "history" }))
	        .filter((historyTurn) => !liveTurns.some((liveTurn) => {
	          const historyId = String(historyTurn.turn_id || "");
	          const liveId = String(liveTurn.turn_id || "");
	          if (historyId && liveId && !historyId.startsWith("history:")) return historyId === liveId;
	          const historyLabel = String(historyTurn.label || "").trim().toLowerCase();
	          const liveLabel = String(liveTurn.label || "").trim().toLowerCase();
	          if (!historyLabel || historyLabel !== liveLabel) return false;
	          const historyTime = Date.parse(String(historyTurn.timestamp || ""));
	          const liveTime = Date.parse(String(liveTurn.timestamp || ""));
	          return Number.isFinite(historyTime) && Number.isFinite(liveTime)
	            && Math.abs(historyTime - liveTime) <= 15000;
	        }));
	      const turns = historyTurns.concat(liveTurns);
	      if (turns.length) return turns;
	      const rows = transcript || (session && Array.isArray(session.transcript) ? session.transcript : []);
	      if (!rows.length) return [];
	      return [{
	        key: "observed-activity",
	        source: "live",
	        label: "Observed activity",
	        start_index: 0,
	        end_index: rows.length - 1,
	        timestamp: rows[0].ts || "",
	        updated_at: rows[rows.length - 1].updated_at || rows[rows.length - 1].ts || ""
	      }];
	    }

	    function transcriptItemsForTurn(transcript, turn) {
	      if (turn && turn.source === "history") return [];
	      const start = Math.max(0, Number(turn && turn.start_index || 0));
	      const end = Math.max(start, Number(turn && turn.end_index != null ? turn.end_index : start));
	      return transcript.filter((item) => {
	        const index = Number(item.control_index);
	        return Number.isFinite(index) && index >= start && index <= end;
	      });
	    }

	    function turnTranscriptItems(session, transcript, turn) {
	      if (turn && turn.source === "history") {
	        const payload = historyTurnPayload(session, turn);
	        return payload && Array.isArray(payload.transcript) ? payload.transcript : [];
	      }
	      return transcriptItemsForTurn(transcript, turn);
	    }

	    function turnMatchesSearch(transcript, turn, query, session = null) {
	      if (!query) return true;
	      const label = String(turn && turn.label || "").toLowerCase();
	      const needle = query.toLowerCase();
	      if (label.includes(needle)) return true;
	      const searchText = String(turn && turn.search_text || "").toLowerCase();
	      if (searchText.includes(needle)) return true;
	      return turnTranscriptItems(session, transcript, turn).some((item) => controlTranscriptMatches(item, query));
	    }

	    function turnOptionLabel(turn, transcript, query, session = null) {
	      const when = turn && turn.timestamp ? formatEventTime(turn.timestamp) : "";
	      const label = String(turn && turn.label || turn && turn.turn_id || "Observed turn");
	      let prefix = when ? `${when} - ` : "";
	      let suffix = turn && turn.pending ? " (pending)" : "";
	      if (turn && turn.source === "history") suffix += turn.archived ? " (archived)" : " (history)";
	      if (query) {
	        const matches = turnTranscriptItems(session, transcript, turn)
	          .filter((item) => controlTranscriptMatches(item, query)).length;
	        if (matches > 0) suffix += ` (${matches} loaded match${matches === 1 ? "" : "es"})`;
	        else if (String(turn && turn.search_text || "").toLowerCase().includes(query.toLowerCase())) suffix += " (match)";
	      }
	      return `${prefix}${label}${suffix}`;
	    }

	    function latestUserInputKey(session) {
	      const transcript = session && Array.isArray(session.transcript) ? session.transcript : [];
	      for (let index = transcript.length - 1; index >= 0; index -= 1) {
	        const item = transcript[index] || {};
	        const role = String(item.role || "");
	        if (role !== "user" && role !== "user_pending") continue;
	        const text = String(item.full_text || item.text || "");
	        return [
	          role,
	          item.ts || "",
	          text.length,
	          text.slice(0, 96)
	        ].join(":");
	      }
	      return "";
	    }

	    function observeControlUserInputs(controlPlane) {
	      const sessions = controlSessions({ control_plane: controlPlane || latestControlPlane || { sessions: [] } });
	      for (const session of sessions) {
	        const sessionKey = String(session && session.key || "");
	        if (!sessionKey) continue;
	        const userKey = latestUserInputKey(session);
	        const previous = latestObservedUserKeys[sessionKey];
	        if (userKey && previous && userKey !== previous) {
	          delete manuallySelectedControlTurnKeys[sessionKey];
	          followLatestTurnAfterUserInput[sessionKey] = true;
	        }
	        latestObservedUserKeys[sessionKey] = userKey;
	      }
	    }

	    function selectedTurnForSessionShouldFollowLatest(sessionKey) {
	      if (!sessionKey || controlSearchText.trim()) return false;
	      if (manuallySelectedControlTurnKeys[sessionKey]) return false;
	      return Boolean(followLatestTurnAfterUserInput[sessionKey]);
	    }

	    function selectedTurnForSession(session, transcript) {
	      const turns = controlTurns(session, transcript);
	      if (!turns.length) return null;
	      const query = controlSearchText.trim();
	      const matchingTurns = query ? turns.filter((turn) => turnMatchesSearch(transcript, turn, query, session)) : turns;
	      const available = matchingTurns.length ? matchingTurns : turns;
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      const selectedKey = selectedControlTurnKeys[sessionKey] || "";
	      const selected = available.find((turn) => controlTurnKey(turn) === selectedKey);
	      const fallback = available[available.length - 1] || null;
	      if (fallback && selectedTurnForSessionShouldFollowLatest(sessionKey)) {
	        selectedControlTurnKeys[sessionKey] = controlTurnKey(fallback);
	        delete followLatestTurnAfterUserInput[sessionKey];
	        return fallback;
	      }
	      if (fallback) selectedControlTurnKeys[sessionKey] = controlTurnKey(selected || fallback);
	      return selected || fallback;
	    }

	    function renderControlTurnOptions(session) {
	      const transcript = session && Array.isArray(session.transcript) ? session.transcript : [];
	      const turns = controlTurns(session, transcript);
	      if (!turns.length) return '<option value="">No observed turns</option>';
	      const selected = selectedTurnForSession(session, transcript);
	      const selectedKey = controlTurnKey(selected);
	      return turns.map((turn) => {
	        const key = controlTurnKey(turn);
	        const disabled = controlSearchText && !turnMatchesSearch(transcript, turn, controlSearchText, session) ? "disabled" : "";
	        return `<option value="${escapeHtml(key)}" ${key === selectedKey ? "selected" : ""} ${disabled}>${escapeHtml(turnOptionLabel(turn, transcript, controlSearchText, session))}</option>`;
	      }).join("");
	    }

	    function controlMessageKey(item, fallback) {
	      const parts = [
	        selectedControlSessionKey || "session",
	        item.role || "message",
	        item.turn_id || "",
	        item.call_id || "",
	        item.ts || ""
	      ];
	      if (item.ts || item.call_id || item.turn_id) return parts.join("|");
	      parts.push(fallback || "");
	      return parts.join("|");
	    }

	    function compactControlMessageNeedsExpansion(value) {
	      const text = String(value || "");
	      if (!text) return false;
	      return text.split("\n").length > 4 || text.length > 360;
	    }

		    function splitToolStatusSuffix(value) {
		      const match = String(value || "").match(/^(.*?)(?:\s+\(([^)]*)\))?$/);
		      const label = match ? match[1].trim() : String(value || "").trim();
		      const attrs = {};
		      const suffix = match && match[2] ? match[2] : "";
		      for (const part of suffix.split(/\s*,\s*/)) {
		        const status = part.match(/^status\s+(.+)$/i);
		        const exit = part.match(/^exit\s+(.+)$/i);
		        const duration = part.match(/^duration\s+(.+)$/i);
		        if (status) attrs.status = status[1].trim();
		        else if (exit) attrs.exit = exit[1].trim();
		        else if (duration) attrs.duration = duration[1].trim();
		      }
		      return { label, attrs };
		    }

		    function parseToolActivityText(value) {
		      const lines = String(value || "").replace(/\r\n?/g, "\n").split("\n");
		      const first = lines[0] || "";
		      const firstMatch = first.match(/^(Tool|Command):\s*(.+)$/i);
		      if (!firstMatch) return null;
		      const parsedFirst = splitToolStatusSuffix(firstMatch[2]);
		      const result = {
		        kind: firstMatch[1].toLowerCase(),
		        name: firstMatch[1].toLowerCase() === "tool" ? parsedFirst.label : "command",
		        command: firstMatch[1].toLowerCase() === "command" ? parsedFirst.label : "",
		        status: parsedFirst.attrs.status || "",
		        exit: parsedFirst.attrs.exit || "",
		        duration: parsedFirst.attrs.duration || "",
		        sections: []
		      };
		      let currentSection = null;
		      const pushSection = () => {
		        if (!currentSection) return;
		        const text = currentSection.lines.join("\n").replace(/\s+$/g, "");
		        if (text.trim()) result.sections.push({ label: currentSection.label, text });
		        currentSection = null;
		      };
		      for (const rawLine of lines.slice(1)) {
		        const line = rawLine || "";
		        const commandMatch = line.match(/^Command:\s*(.+)$/i);
		        if (commandMatch) {
		          pushSection();
		          const parsedCommand = splitToolStatusSuffix(commandMatch[1]);
		          result.command = parsedCommand.label || result.command;
		          if (parsedCommand.attrs.status) result.status = parsedCommand.attrs.status;
		          if (parsedCommand.attrs.exit) result.exit = parsedCommand.attrs.exit;
		          if (parsedCommand.attrs.duration) result.duration = parsedCommand.attrs.duration;
		          continue;
		        }
		        const sectionMatch = line.match(/^([A-Za-z][A-Za-z0-9 _/-]{1,40}):\s*$/);
		        if (sectionMatch) {
		          pushSection();
		          currentSection = { label: sectionMatch[1].trim(), lines: [] };
		          continue;
		        }
		        if (!currentSection) currentSection = { label: "Details", lines: [] };
		        currentSection.lines.push(line);
		      }
		      pushSection();
		      return result;
		    }

		    function isControlToolName(name) {
		      return /^ctc_[a-f0-9]{16,}$/i.test(String(name || "").trim());
		    }

		    function toolSectionIsPatch(section) {
		      const label = String(section && section.label || "").toLowerCase();
		      const text = String(section && section.text || "");
		      return ["arguments", "input", "patch", "content"].includes(label) && /^\*\*\* Begin Patch/m.test(text);
		    }

			    function renderPatchText(text) {
			      return String(text || "").split("\n").map((line) => {
			        let cls = "context";
		        if (/^\*\*\* (Begin Patch|End Patch|Update File:|Add File:|Delete File:|Move to:)/.test(line) || /^@@/.test(line)) {
		          cls = "meta";
		        } else if (/^\+/.test(line)) {
		          cls = "add";
		        } else if (/^-/.test(line)) {
		          cls = "delete";
		        }
		        return `<span class="tool-patch-line ${cls}">${escapeHtml(line || " ")}</span>`;
			      }).join("");
			    }

			    function parseToolJsonText(value) {
			      const text = String(value || "").trim();
			      if (!text) return null;
			      if (/^[{[]/.test(text)) {
			        try {
			          return JSON.parse(text);
			        } catch {
			          return null;
			        }
			      }
			      const lines = text.split("\n");
			      const simple = {};
			      for (const line of lines) {
			        const match = line.match(/^([A-Za-z_][A-Za-z0-9_.-]*):\s*(.*)$/);
			        if (!match) return null;
			        simple[match[1]] = match[2];
			      }
			      return Object.keys(simple).length ? simple : null;
			    }

			    function toolSectionByLabel(parsed, labels) {
			      const wanted = new Set(labels.map((label) => label.toLowerCase()));
			      return (parsed.sections || []).find((section) => wanted.has(String(section.label || "").toLowerCase())) || null;
			    }

			    function toolPayloadFromLabels(parsed, labels) {
			      const section = toolSectionByLabel(parsed, labels);
			      return section ? parseToolJsonText(section.text) : null;
			    }

			    function toolSectionIsCollapsible(section) {
			      const label = String(section && section.label || "").toLowerCase();
			      const text = String(section && section.text || "");
			      return ["arguments", "input", "parameters", "params", "content", "patch"].includes(label)
			        && (text.includes("\n") || text.length > 180);
			    }

		    function summarizeToolSection(section, parsed) {
			      const text = String(section && section.text || "");
			      const payload = parseToolJsonText(text);
			      const name = String(parsed && parsed.name || "").toLowerCase();
			      if (payload && name === "update_plan" && Array.isArray(payload.plan)) {
			        return `${payload.plan.length} plan step${payload.plan.length === 1 ? "" : "s"}`;
			      }
			      if (payload && name === "create_goal" && payload.objective) {
			        return `objective: ${payload.objective}`;
			      }
			      if (payload && name === "update_goal" && payload.status) {
			        return `status: ${payload.status}`;
			      }
			      if (payload && typeof payload.cmd === "string" && payload.cmd.trim()) return payload.cmd.trim();
			      if (payload && typeof payload.command === "string" && payload.command.trim()) return payload.command.trim();
			      const first = text.split("\n").map((line) => line.trim()).find(Boolean) || "";
		      return first.length > 220 ? `${first.slice(0, 220).trim()}...` : first;
		    }

		    function toolSectionNeedsExpansion(section, parsed) {
		      if (!toolSectionIsCollapsible(section)) return false;
		      return summarizeToolSection(section, parsed) !== String(section && section.text || "");
		    }

			    function renderPlanToolSummary(parsed) {
			      const name = String(parsed.name || "").toLowerCase();
			      const args = toolPayloadFromLabels(parsed, ["Arguments", "Input", "Parameters"]);
			      const result = toolPayloadFromLabels(parsed, ["Result", "Output"]);
			      if (name === "update_plan" && args && Array.isArray(args.plan)) {
			        const explanation = args.explanation
			          ? `<div class="control-tool-special-note">${escapeHtml(args.explanation)}</div>`
			          : "";
			        const rows = args.plan.map((item) => {
			          const status = String(item && item.status || "pending");
			          const statusClass = status.toLowerCase().replace(/[^a-z0-9_-]+/g, "_");
			          const label = status.replace(/_/g, " ");
			          return `
			            <div class="control-tool-plan-row">
			              <span class="control-tool-plan-status ${escapeHtml(statusClass)}">${escapeHtml(label)}</span>
			              <span>${escapeHtml(item && item.step || "")}</span>
			            </div>
			          `;
			        }).join("");
			        return `
			          <div class="control-tool-special">
			            <div class="control-tool-special-title">
			              <span>Updated plan</span>
			              <span>${escapeHtml(args.plan.length)} step${args.plan.length === 1 ? "" : "s"}</span>
			            </div>
			            ${explanation}
			            <div class="control-tool-plan-list">${rows}</div>
			          </div>
			        `;
			      }
			      if (name === "create_goal" && args && args.objective) {
			        const budget = args.token_budget || args.tokenBudget
			          ? `<div class="control-tool-special-note">Budget: ${escapeHtml(args.token_budget || args.tokenBudget)} tokens</div>`
			          : "";
			        return `
			          <div class="control-tool-special">
			            <div class="control-tool-special-title"><span>Created goal</span></div>
			            <div>${escapeHtml(args.objective)}</div>
			            ${budget}
			          </div>
			        `;
			      }
			      if (name === "update_goal" && args && args.status) {
			        const goal = result && result.goal && typeof result.goal === "object" ? result.goal : null;
			        const usage = goal
			          ? [
			              goal.tokensUsed != null ? `Tokens: ${formatNumber(goal.tokensUsed)}` : "",
			              goal.timeUsedSeconds != null ? `Time: ${formatAge(goal.timeUsedSeconds)}` : ""
			            ].filter(Boolean).join(" / ")
			          : "";
			        return `
			          <div class="control-tool-special">
			            <div class="control-tool-special-title">
			              <span>Goal status</span>
			              <span>${escapeHtml(String(args.status))}</span>
			            </div>
			            ${goal && goal.objective ? `<div>${escapeHtml(goal.objective)}</div>` : ""}
			            ${usage ? `<div class="control-tool-special-note">${escapeHtml(usage)}</div>` : ""}
			          </div>
			        `;
			      }
			      if (name === "get_goal" && result && result.goal) {
			        const goal = result.goal;
			        return `
			          <div class="control-tool-special">
			            <div class="control-tool-special-title">
			              <span>Current goal</span>
			              <span>${escapeHtml(goal.status || "active")}</span>
			            </div>
			            ${goal.objective ? `<div>${escapeHtml(goal.objective)}</div>` : ""}
			          </div>
			        `;
			      }
			      return "";
			    }

		    function renderToolSection(section, ownerKey, sectionIndex, expanded, parsed) {
		      const isPatch = toolSectionIsPatch(section);
		      const collapsed = toolSectionNeedsExpansion(section, parsed) && !expanded;
			      const displayText = collapsed ? summarizeToolSection(section, parsed) : section.text;
			      const body = isPatch && !collapsed ? renderPatchText(displayText) : escapeHtml(displayText);
			      const scrollKey = `${ownerKey}:section:${sectionIndex}:${section.label}`;
			      return `
			        <div class="control-tool-section${isPatch ? " patch" : ""}${collapsed ? " collapsed" : ""}">
			          <span class="control-tool-section-label">${escapeHtml(section.label)}</span>
			          <pre data-control-inner-scroll="${escapeHtml(scrollKey)}">${body}</pre>
			        </div>
		      `;
		    }

		    function renderControlToolBlock(item, fallback, options = {}) {
		      const key = controlMessageKey(item, fallback);
		      const displayText = String(item.text || "");
		      const fullText = String(item.full_text || "");
		      const compact = Boolean(options.compact);
		      const hasMore = Boolean(item.truncated || (fullText && fullText !== displayText));
		      const expanded = Boolean(expandedControlMessages[key]);
		      const text = expanded && fullText ? fullText : displayText;
		      const parsed = parseToolActivityText(text);
		      if (!parsed) {
		        return `<div class="control-tool-block"><strong>Tool / command</strong>${renderControlMessageText(item, fallback, { markdown: false, compact })}</div>`;
		      }
		      if (parsed.kind === "tool" && isControlToolName(parsed.name) && !parsed.command && !parsed.sections.length) {
		        return `
		          <div class="control-tool-block control-signal">
		            <div class="control-tool-summary">
		              <span class="control-tool-title">Control signal <code>${escapeHtml(parsed.name)}</code></span>
		              <span class="control-tool-status observed">observed</span>
		            </div>
		          </div>
		        `;
		      }
		      const status = parsed.status || "observed";
		      const statusClass = status.toLowerCase().replace(/[^a-z0-9_-]+/g, "_");
		      const summaryBits = [parsed.exit ? `exit ${parsed.exit}` : "", parsed.duration || ""].filter(Boolean);
			      const summary = summaryBits.length ? `<span>${escapeHtml(summaryBits.join(" / "))}</span>` : "";
			      const special = renderPlanToolSummary(parsed);
			      const command = parsed.command
			        ? `<div class="control-tool-command">${escapeHtml(parsed.command)}</div>`
			        : "";
		      const hasCollapsedSections = parsed.sections.some((section) => toolSectionNeedsExpansion(section, parsed));
			      const sections = parsed.sections.length
			        ? `<div class="control-tool-sections">${parsed.sections.map((section, sectionIndex) => renderToolSection(section, key, sectionIndex, expanded, parsed)).join("")}</div>`
			        : "";
			      const button = hasMore || hasCollapsedSections
			        ? `<button class="control-show-more" type="button" data-message-key="${escapeHtml(key)}">${expanded ? "Show less" : "Show more"}</button>`
			        : "";
		      return `
		        <div class="control-tool-block">
		          <div class="control-tool-summary">
		            <span class="control-tool-title">${escapeHtml(parsed.kind === "command" ? "Command" : "Tool")} <code>${escapeHtml(parsed.name || parsed.command || "tool")}</code></span>
		            <span class="control-tool-status ${escapeHtml(statusClass)}">${escapeHtml(status)}</span>
			          </div>
			          ${summary}
			          ${special}
			          ${command}
			          ${sections}
			          ${button}
		        </div>
		      `;
		    }

	    function renderControlMessageText(item, fallback, options = {}) {
	      const key = controlMessageKey(item, fallback);
	      const role = String(item.role || "");
	      const displayText = normalizeControlMessageTextForDisplay(item.text, role);
	      const fullText = normalizeControlMessageTextForDisplay(item.full_text, role);
	      const compact = Boolean(options.compact);
	      const hasMore = Boolean(
	        item.truncated
	        || (fullText && fullText !== displayText)
	        || (compact && compactControlMessageNeedsExpansion(displayText))
	      );
	      const expanded = Boolean(expandedControlMessages[key]);
	      const text = expanded && fullText ? fullText : displayText;
	      const useMarkdown = options.markdown !== false && role !== "tool" && role !== "error";
	      const className = `control-message-text ${useMarkdown ? "markdown" : "plain"}${expanded ? " expanded" : ""}`;
	      const body = useMarkdown
	        ? cachedMarkdownRender(`${role}\u0001${text}`, () => {
	            const jsonBody = renderJsonControlMessage(text);
	            return jsonBody || renderMarkdown(text);
	          })
	        : escapeHtml(text);
	      const button = hasMore
	        ? `<button class="control-show-more" type="button" data-message-key="${escapeHtml(key)}">${expanded ? "Show less" : "Show more"}</button>`
	        : "";
	      return `<div class="${className}" data-control-inner-scroll="${escapeHtml(`${key}:message`)}">${body}</div>${button}`;
	    }

	    function controlTranscriptGroups(items) {
	      const groups = [];
	      for (const item of items) {
	        const role = String(item.role || "message");
	        if (role === "assistant_progress" || role === "tool") {
	          const turn = String(item.turn_id || "");
	          const last = groups[groups.length - 1];
	          if (turn && last && last.kind === "assistant_activity" && String(last.turn_id || "") === turn) {
	            last.items.push(item);
	            last.updated_at = item.updated_at || item.ts || last.updated_at;
	          } else {
	            groups.push({
	              kind: "assistant_activity",
	              role: "assistant_progress",
	              turn_id: turn,
	              ts: item.ts,
	              updated_at: item.updated_at || item.ts,
	              items: [item]
	            });
	          }
	        } else {
	          groups.push({ kind: "message", item });
	        }
	      }
	      return groups;
	    }

	    function controlMessageRoleLabel(role) {
	      if (role === "resume") return "resumed context";
	      if (role === "context_compaction") return "context replay";
	      if (role === "assistant_progress") return "assistant activity";
	      if (role === "tool") return "tool / command";
	      if (role === "user_pending") return "user";
	      return role;
	    }

	    function controlTurnMarkup(item) {
	      const turnId = String(item && item.turn_id || "");
	      if (turnId) return ` / ${escapeHtml(turnId)}`;
	      if (String(item && item.role || "") === "user_pending") {
	        return ` <span class="control-message-turn">/ <span class="control-message-spinner" aria-hidden="true"></span>pending</span>`;
	      }
	      return "";
	    }

	    function renderControlTranscriptGroup(group, index, total) {
	      const compact = index < Math.max(0, total - 5) ? " compact" : "";
	      if (group.kind === "assistant_activity") {
	        const turn = group.turn_id ? ` / ${group.turn_id}` : "";
	        const body = group.items.map((item, itemIndex) => {
	          const role = String(item.role || "");
	          if (role === "tool") {
	            return renderControlToolBlock(item, `activity-${index}-${itemIndex}`, { compact: Boolean(compact) });
	          }
	          return renderControlMessageText(item, `activity-${index}-${itemIndex}`, { compact: Boolean(compact) });
	        }).join("");
	        return `
	          <article class="control-message assistant_activity assistant_progress${compact}" data-transcript-index="${index}">
	            <div class="control-message-head">
	              <span>assistant activity${escapeHtml(turn)}</span>
	              <span>${escapeHtml(formatEventTime(group.updated_at || group.ts))}</span>
	            </div>
	            <div class="control-activity-parts">${body}</div>
	          </article>
	        `;
	      }
	      const item = group.item;
	      const role = String(item.role || "message");
	      const displayRole = controlMessageRoleLabel(role);
	      return `
	        <article class="control-message ${escapeHtml(role)}${compact}" data-transcript-index="${index}">
	          <div class="control-message-head">
	            <span>${escapeHtml(displayRole)}${controlTurnMarkup(item)}</span>
	            <span>${escapeHtml(formatEventTime(item.updated_at || item.ts))}</span>
	          </div>
	          ${renderControlMessageText(item, `message-${index}`, { compact: Boolean(compact) })}
	        </article>
	      `;
	    }

	    function renderControlTranscript(session) {
	      const transcript = Array.isArray(session.transcript) ? session.transcript.slice() : [];
	      const turns = controlTurns(session, transcript);
	      if (!transcript.length && !turns.length) {
	        return '<div class="control-empty">No discussion text captured for this session yet</div>';
	      }
	      const turn = selectedTurnForSession(session, transcript);
	      if (!turn) {
	        return '<div class="control-empty">No observed turns for this session yet</div>';
	      }
	      if (controlSearchText && !turnMatchesSearch(transcript, turn, controlSearchText, session)) {
	        return '<div class="control-empty">No observed turns match the current search</div>';
	      }
	      let visible = [];
	      let sourceNote = "";
	      if (turn.source === "history") {
	        const payload = historyTurnPayload(session, turn);
	        if (!payload) {
	          requestHistoryTurn(session, turn);
	          return '<div class="control-empty">Loading Codex session history for the selected turn...</div>';
	        }
	        visible = Array.isArray(payload.transcript) ? payload.transcript.slice() : [];
	        sourceNote = '<div class="control-transcript-window-note">Loaded from Codex session history.</div>';
	      } else {
	        visible = transcriptItemsForTurn(transcript, turn);
	        const pending = transcript.filter((item) => String(item.role || "") === "user_pending" && !visible.includes(item));
	        if (pending.length) visible = visible.concat(pending);
	      }
	      if (controlSearchText) {
	        const matched = visible.filter((item) => controlTranscriptMatches(item, controlSearchText));
	        if (!matched.length && !String(turn.label || "").toLowerCase().includes(controlSearchText.toLowerCase())) {
	          return '<div class="control-empty">No discussion entries in this turn match the current search</div>';
	        }
	      }
	      const groups = controlTranscriptGroups(visible);
	      const matchedTurns = controlSearchText
	        ? controlTurns(session, transcript).filter((candidate) => turnMatchesSearch(transcript, candidate, controlSearchText, session)).length
	        : 0;
	      const searchNote = matchedTurns > 1
	        ? `<div class="control-transcript-window-note">${matchedTurns} turns match. Use the turn selector to navigate.</div>`
	        : "";
	      return `
	        ${searchNote}
	        ${sourceNote}
	        <div class="control-transcript" data-total="${groups.length}">
	          ${groups.map((group, offset) => (
	            renderControlTranscriptGroup(group, offset, groups.length)
	          )).join("")}
	        </div>
	      `;
	    }

	    function renderControlEvents(session) {
	      const events = Array.isArray(session.events) ? session.events.slice().reverse() : [];
	      if (!events.length) {
	        return '<div class="control-empty">No recorded activity for this session yet</div>';
	      }
	      return `<div class="control-events">${events.map((event) => {
	        const summary = event.summary || statsEventText(event);
	        const profile = event.profile ? `<span>Profile: ${escapeHtml(event.profile)}</span>` : "";
	        const type = event.type ? `<span>Type: ${escapeHtml(event.type)}</span>` : "";
	        const tier = event.service_tier ? `<span>Tier: ${escapeHtml(event.service_tier)}</span>` : "";
	        return `
	          <div class="control-event compact">
	            <span>${escapeHtml(formatEventTime(event.ts))}</span>
	            <div class="control-event-detail">
	              <strong>${escapeHtml(summary)}</strong>
	              ${profile}
	              ${type}
	              ${tier}
	            </div>
	          </div>
	        `;
	      }).join("")}</div>`;
	    }

	    function sessionAssociatedProfile(session) {
	      return String((session && (session.associated_profile || session.pinned_profile || session.last_profile)) || "");
	    }

	    function sessionIsLive(session) {
	      if (!session) return false;
	      if (session.pty_control_available || session.ui_launcher_running || session.active) return true;
	      if (Number(session.active_requests || 0) > 0) return true;
	      if (Number(session.active_tunnels || 0) > 0) return true;
	      if (Number(session.pending_websocket_work || 0) > 0) return true;
	      return false;
	    }

	    function updateControlHeaderActions(session) {
	      const turnSelect = document.getElementById("controlTurnSelect");
	      const forget = document.getElementById("controlForget");
	      if (!turnSelect || !forget) return;
	      const connected = socket && socket.readyState === WebSocket.OPEN;
	      const turns = session ? controlTurns(session, Array.isArray(session.transcript) ? session.transcript : []) : [];
	      if (!controlTurnSelectInteracting && document.activeElement !== turnSelect) {
	        const nextOptions = session ? renderControlTurnOptions(session) : '<option value="">No observed turns</option>';
	        turnSelect.innerHTML = nextOptions;
	      }
	      turnSelect.disabled = !turns.length;
	      turnSelect.hidden = controlView !== "discussion";
	      forget.disabled = !connected || !session;
	      forget.title = sessionIsLive(session)
	        ? "Close the associated launcher and forget this live session"
	        : "Forget this idle observed session";
	    }

	    function sendLaunchSession(sessionKey, mode, sessionId = "") {
	      if (!sessionKey || !socket || socket.readyState !== WebSocket.OPEN) return;
	      const sessions = controlSessions({ control_plane: latestControlPlane });
	      const session = sessions.find((item) => item.key === sessionKey) || {};
	      socket.send(JSON.stringify({
	        action: "launch_session",
	        session_key: sessionKey,
	        profile: sessionAssociatedProfile(session),
	        mode,
	        session_id: sessionId,
	        permission: launcherPermission,
	        token: TOKEN
	      }));
	    }

	    function selectedResumeCandidateId(session) {
	      const key = String(session && session.key || selectedControlSessionKey || "");
	      const candidates = resumeCandidatesForSession(session);
	      const selected = selectedResumeCandidateIds[key] || "";
	      if (selected && candidates.some((candidate) => String(candidate.id || "") === selected)) return selected;
	      const fallback = candidates.length ? String(candidates[0].id || "") : "";
	      selectedResumeCandidateIds[key] = fallback;
	      return fallback;
	    }

	    function renderResumePane(session) {
	      const candidates = resumeCandidatesForSession(session);
	      if (!candidates.length) {
	        return '<div class="control-empty">No resumable Codex CLI sessions were found for this workdir.</div>';
	      }
	      const selectedId = selectedResumeCandidateId(session);
	      const rows = candidates.map((candidate) => {
	        const id = String(candidate.id || "");
	        const when = candidate.timestamp ? formatEventTime(candidate.timestamp) : "";
	        const selected = id === selectedId ? " selected" : "";
	        const label = candidate.label || id;
	        return `
	          <button class="control-resume-item${selected}" type="button" data-resume-candidate="${escapeHtml(id)}">
	            <span class="control-resume-main">
	              <span class="control-resume-label">${escapeHtml(label)}</span>
	              <span class="control-resume-meta">${escapeHtml([when, id].filter(Boolean).join(" / "))}</span>
	            </span>
	            <span class="badge">${id === selectedId ? "Selected" : "Choose"}</span>
	          </button>
	        `;
	      }).join("");
	      const disabled = !selectedId || !socket || socket.readyState !== WebSocket.OPEN ? "disabled" : "";
	      return `
	        <section class="control-detail-section">
	          <h3>Resume Session</h3>
	          <div class="control-section-body">
	            <div class="control-resume-list">${rows}</div>
	            <div class="control-resume-actions">
	              <button type="button" data-resume-action="resume-session" ${disabled}>Resume</button>
	              <button type="button" data-resume-action="fork-session" ${disabled}>Fork</button>
	            </div>
	          </div>
	        </section>
	      `;
	    }

	    function renderControlModal(force = false) {
	      const modal = document.getElementById("controlModal");
	      if (!modal || modal.hidden) return;
	      if (!force && controlRenderShouldDefer()) {
	        if (!controlRenderDeferredAt) controlRenderDeferredAt = Date.now();
	        if (Date.now() - controlRenderDeferredAt < 2000) {
	          pendingControlRender = true;
	          scheduleControlRenderFlush();
	          return;
	        }
	      }
	      controlRenderDeferredAt = 0;
	      const session = selectedControlSession();
	      if (!session) {
	        modal.hidden = true;
	        return;
	      }
	      requestHistoryIndex(session);
	      if (controlView === "resume") requestResumeCandidates(session);
	      updateControlDockGeometry();
	      document.getElementById("controlTitle").textContent = String(session.cwd || session.display || sessionTitle(session));
	      const active = Number(session.active_requests || 0);
	      const tunnels = Number(session.active_tunnels || 0);
	      const pending = Number(session.pending_websocket_work || 0);
	      const recent = Number(session.recent_websocket_activity || 0);
	      const associatedProfile = sessionAssociatedProfile(session) || "unknown";
	      const activeState = recent || pending || active || tunnels ? "Active" : "Idle";
	      const pills = [
	        `<span class="pill">${escapeHtml(session.pinned_profile ? `Pinned ${session.pinned_profile}` : `Profile ${associatedProfile}`)}</span>`,
	        `<span class="pill">Requests <strong>${active}</strong></span>`,
	        `<span class="pill">Tunnels <strong>${tunnels}</strong></span>`,
	        `<span class="pill">Turns <strong>${pending}</strong></span>`,
	        `<span class="pill">${activeState}</span>`
	      ];
	      if (session.context && session.context.label) {
	        const contextTitle = [
	          session.context.input_tokens ? `${formatNumber(session.context.input_tokens)} input tokens` : "",
	          session.context.remaining_tokens ? `${formatNumber(session.context.remaining_tokens)} tokens remaining` : "",
	          session.context.updated_at ? `Updated ${formatEventTime(session.context.updated_at)}` : ""
	        ].filter(Boolean).join(" / ");
	        pills.push(`<span class="pill" title="${escapeHtml(contextTitle)}">Context <strong>${escapeHtml(session.context.label)}</strong></span>`);
	      }
	      if (session.quota_compact_html) pills.push(String(session.quota_compact_html));
	      document.getElementById("controlStatusPills").innerHTML = pills.join("");
	      const panel = modal.querySelector(".control-modal");
	      if (panel) {
	        panel.classList.toggle("details-view", controlView === "details");
	        panel.classList.toggle("resume-view", controlView === "resume");
	        panel.classList.toggle("discussion-view", controlView === "discussion");
	      }
	      document.querySelectorAll("[data-control-view]").forEach((button) => {
	        button.classList.toggle("active", button.dataset.controlView === controlView);
	        button.setAttribute("aria-selected", button.dataset.controlView === controlView ? "true" : "false");
	      });
	      const content = document.getElementById("controlContent");
	      const nextScrollKey = controlScrollKey();
	      const sameScrollSurface = renderedControlScrollKey === nextScrollKey;
	      const shouldFollowDiscussion = controlView === "discussion"
	        && !controlSearchText
	        && (!sameScrollSurface || controlContentAtBottom(content));
	      if (sameScrollSurface) {
	        saveControlScroll();
	        saveControlInnerScroll();
	      }
	      if (controlView === "details") {
	        content.innerHTML = `
	          <section class="control-detail-section">
	            <h3>Active Turn State</h3>
	            <div class="control-section-body">${renderControlActiveDetails(session)}</div>
	          </section>
	          <section class="control-detail-section">
	            <h3>Session Activity</h3>
	            <div class="control-section-body">${renderControlEvents(session)}</div>
	          </section>
	        `;
	      } else if (controlView === "resume") {
	        content.innerHTML = renderResumePane(session);
	      } else {
	        content.innerHTML = renderControlTranscript(session);
	      }
	      normalizeNativeTooltips(modal);
	      renderedControlScrollKey = nextScrollKey;
	      if (shouldFollowDiscussion) {
	        content.scrollTop = content.scrollHeight;
	      } else {
	        restoreControlScroll();
	      }
	      requestAnimationFrame(restoreControlInnerScroll);
	      updateControlComposeState(session);
	      updateControlHeaderActions(session);
	      requestAnimationFrame(updateControlScrollBadges);
	      pendingControlRender = false;
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
	          value: Number(point.value || 0),
	          tokens: Number(point.tokens || 0),
	          traffic: Number(point.traffic || 0),
	          requests: Number(point.requests || 0),
	          quotaUpdates: Number(point.quota_updates || 0)
	        }))
	        .filter((point) => Number.isFinite(point.ts) && Number.isFinite(point.value));
	      if (!points.length) {
	        return '<div class="stats-graph-empty">No usage activity recorded yet</div>';
	      }
	      const minTs = Math.min(...points.map((point) => point.ts));
	      const maxTs = Math.max(...points.map((point) => point.ts));
	      const maxValue = Math.max(1, ...points.map((point) => point.value));
	      const width = 1000;
	      const height = 230;
	      const padLeft = 54;
	      const padRight = 24;
	      const padTop = 22;
	      const padBottom = 34;
	      const plotRight = width - padRight;
	      const plotBottom = height - padBottom;
	      const usableWidth = width - padLeft - padRight;
	      const usableHeight = height - padTop - padBottom;
	      const xFor = (ts) => padLeft + (maxTs === minTs ? usableWidth : ((ts - minTs) / (maxTs - minTs)) * usableWidth);
	      const yFor = (value) => padTop + usableHeight - (value / maxValue) * usableHeight;
	      const timeLabel = (ts) => new Date(ts).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
	      const yTicks = [0, maxValue / 2, maxValue];
	      const xTicks = maxTs === minTs ? [minTs] : [minTs, minTs + (maxTs - minTs) / 2, maxTs];
	      const yGrid = yTicks.map((value) => {
	        const y = yFor(value);
	        return `
	          <path class="stats-graph-grid" d="M${padLeft} ${y.toFixed(1)}H${width - padRight}"></path>
	          <text class="stats-graph-label" x="${padLeft - 8}" y="${(y + 4).toFixed(1)}" text-anchor="end">${escapeHtml(formatNumber(Math.round(value)))}</text>
	        `;
	      }).join("");
	      const xGrid = xTicks.map((ts) => {
	        const x = xFor(ts);
	        return `
	          <path class="stats-graph-grid" d="M${x.toFixed(1)} ${padTop}V${height - padBottom}"></path>
	          <text class="stats-graph-label" x="${x.toFixed(1)}" y="${height - 10}" text-anchor="${ts === minTs ? "start" : ts === maxTs ? "end" : "middle"}">${escapeHtml(timeLabel(ts))}</text>
	        `;
	      }).join("");
	      const referenceY = yFor(maxValue);
	      const reference = `
	        <path class="stats-graph-reference" d="M${padLeft} ${referenceY.toFixed(1)}H${width - padRight}"></path>
	        <text class="stats-graph-label" x="${width - padRight}" y="${(referenceY - 6).toFixed(1)}" text-anchor="end">peak ${escapeHtml(formatNumber(Math.round(maxValue)))}</text>
	      `;
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
	          const x = xFor(point.ts);
	          const y = yFor(point.value);
	          return `${index ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`;
	        }).join(" ");
	        const latest = sorted[sorted.length - 1];
	        const marker = latest
	          ? `<circle class="stats-graph-marker" cx="${xFor(latest.ts).toFixed(1)}" cy="${yFor(latest.value).toFixed(1)}" r="4.2" fill="${color}"></circle>`
	          : "";
	        return `
	          <path d="${path}" fill="none" stroke="${color}" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"></path>
	          ${marker}
	        `;
	      }).join("");
	      const interactivePoints = points.map((point) => {
	        const profileIndex = profiles.indexOf(point.profile);
	        return {
	          profile: point.profile,
	          ts: point.ts,
	          time: timeLabel(point.ts),
	          value: point.value,
	          tokens: point.tokens,
	          traffic: point.traffic,
	          requests: point.requests,
	          quotaUpdates: point.quotaUpdates,
	          x: xFor(point.ts),
	          y: yFor(point.value),
	          color: statsProfileColor(profileIndex < 0 ? 0 : profileIndex)
	        };
	      });
	      return `
	        <svg class="stats-graph-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Profile usage trend" data-points="${escapeHtml(JSON.stringify(interactivePoints))}" data-width="${width}" data-height="${height}" data-plot-left="${padLeft}" data-plot-right="${plotRight}" data-plot-top="${padTop}" data-plot-bottom="${plotBottom}">
	          ${yGrid}
	          ${xGrid}
	          <path class="stats-graph-axis" d="M${padLeft} ${height - padBottom}H${width - padRight}"></path>
	          <path class="stats-graph-axis" d="M${padLeft} ${padTop}V${height - padBottom}"></path>
	          ${reference}
	          ${lines}
	        </svg>
	        <div class="stats-graph-cursor" hidden></div>
	        <div class="stats-graph-hover-dot" hidden></div>
	        <div class="stats-graph-tooltip" hidden></div>
	      `;
	    }

	    function statsGraphData(graph) {
	      const svg = graph ? graph.querySelector(".stats-graph-svg") : null;
	      if (!svg) return null;
	      let points = [];
	      try {
	        points = JSON.parse(svg.dataset.points || "[]");
	      } catch {
	        points = [];
	      }
	      if (!Array.isArray(points) || !points.length) return null;
	      const bounds = svg.getBoundingClientRect();
	      const width = Number(svg.dataset.width || 1000);
	      const height = Number(svg.dataset.height || 230);
	      if (!bounds.width || !bounds.height || !width || !height) return null;
	      const plot = {
	        left: Number(svg.dataset.plotLeft || 0),
	        right: Number(svg.dataset.plotRight || width),
	        top: Number(svg.dataset.plotTop || 0),
	        bottom: Number(svg.dataset.plotBottom || height)
	      };
	      return { svg, points, bounds, width, height, plot };
	    }

	    function nearestStatsPoint(graph, clientX, clientY) {
	      const data = statsGraphData(graph);
	      if (!data) return null;
	      const x = ((clientX - data.bounds.left) / data.bounds.width) * data.width;
	      const y = ((clientY - data.bounds.top) / data.bounds.height) * data.height;
	      if (
	        x < data.plot.left ||
	        x > data.plot.right ||
	        y < data.plot.top ||
	        y > data.plot.bottom
	      ) {
	        return null;
	      }
	      let best = null;
	      let bestScore = Infinity;
	      for (const point of data.points) {
	        const dx = Number(point.x || 0) - x;
	        const dy = Number(point.y || 0) - y;
	        const score = Math.abs(dx) * 2 + Math.abs(dy);
	        if (score < bestScore) {
	          best = point;
	          bestScore = score;
	        }
	      }
	      if (!best) return null;
	      return { point: best, data };
	    }

	    function statsGraphTooltipHtml(point) {
	      const traffic = Number(point.traffic || 0);
	      const value = Number(point.value || 0);
	      const tokens = Number(point.tokens || 0);
	      const pieces = [
	        `<strong>${escapeHtml(point.profile || "unknown")}</strong>`,
	        `<span>${escapeHtml(point.time || "")}</span>`
	      ];
	      if (tokens) pieces.push(`<span>Tokens: ${escapeHtml(formatNumber(tokens))}</span>`);
	      if (value && value !== tokens) pieces.push(`<span>Trend value: ${escapeHtml(formatNumber(value))}</span>`);
	      if (traffic) pieces.push(`<span>Traffic: ${escapeHtml(formatBytes(traffic))}</span>`);
	      if (Number(point.requests || 0)) pieces.push(`<span>Requests: ${escapeHtml(formatNumber(point.requests))}</span>`);
	      if (Number(point.quotaUpdates || 0)) pieces.push(`<span>Quota updates: ${escapeHtml(formatNumber(point.quotaUpdates))}</span>`);
	      return pieces.join("");
	    }

	    function updateStatsGraphHover(graph, event) {
	      const nearest = nearestStatsPoint(graph, event.clientX, event.clientY);
	      if (!nearest) {
	        hideStatsGraphHover(graph);
	        return;
	      }
	      const { point, data } = nearest;
	      const cursor = graph.querySelector(".stats-graph-cursor");
	      const dot = graph.querySelector(".stats-graph-hover-dot");
	      const tooltip = graph.querySelector(".stats-graph-tooltip");
	      if (!cursor || !dot || !tooltip) return;
	      const left = (Number(point.x || 0) / data.width) * data.bounds.width;
	      const top = (Number(point.y || 0) / data.height) * data.bounds.height;
	      cursor.hidden = false;
	      dot.hidden = false;
	      tooltip.hidden = false;
	      cursor.style.left = `${left}px`;
	      dot.style.left = `${left}px`;
	      dot.style.top = `${top}px`;
	      dot.style.background = point.color || "";
	      tooltip.innerHTML = statsGraphTooltipHtml(point);
	      const tooltipWidth = tooltip.offsetWidth || 220;
	      const tooltipHeight = tooltip.offsetHeight || 96;
	      const preferredLeft = left > data.bounds.width * 0.58 ? left - tooltipWidth - 12 : left + 12;
	      const tooltipLeft = Math.max(8, Math.min(data.bounds.width - tooltipWidth - 8, preferredLeft));
	      const tooltipTop = Math.max(8, Math.min(data.bounds.height - tooltipHeight - 8, top - 42));
	      tooltip.style.left = `${tooltipLeft}px`;
	      tooltip.style.top = `${tooltipTop}px`;
	    }

	    function hideStatsGraphHover(graph) {
	      for (const selector of [".stats-graph-cursor", ".stats-graph-hover-dot", ".stats-graph-tooltip"]) {
	        const node = graph ? graph.querySelector(selector) : null;
	        if (node) node.hidden = true;
	      }
	    }

		    function setStatsOpen(open) {
		      const modal = document.getElementById("statsModal");
		      const toggle = document.getElementById("statsToggle");
		      if (!modal) return;
		      updateControlDockGeometry();
		      modal.hidden = !open;
		      if (toggle) toggle.classList.toggle("active", Boolean(open));
		      if (open) renderStats(latestStats);
		    }

	    function renderStats(stats) {
	      const content = document.getElementById("statsContent");
	      if (!content) return;
	      const contentScroll = scrollSnapshot(content);
	      const recentScroll = scrollSnapshot(content.querySelector(".stats-recent"));
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
	      const recent = Array.isArray(stats.recent) ? stats.recent.slice() : [];
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
	      normalizeNativeTooltips(content);
	      restoreScrollSnapshot(content, contentScroll);
	      restoreScrollSnapshot(content.querySelector(".stats-recent"), recentScroll);
		    }

		    function showUiMessage(text) {
		      const message = document.getElementById("message");
		      if (!message) return;
		      if (text) {
		        message.textContent = text;
		        message.classList.add("visible");
		      } else {
		        message.textContent = "";
		        message.classList.remove("visible");
		      }
		    }

	    function closeConfirmation(result) {
	      const modal = document.getElementById("confirmModal");
	      if (modal) modal.hidden = true;
	      if (pendingConfirmation) {
	        const resolve = pendingConfirmation.resolve;
	        pendingConfirmation = null;
	        resolve(Boolean(result));
	      }
	    }

	    function confirmAction({ title = "Confirm action", message = "", acceptLabel = "Confirm", danger = true } = {}) {
	      const modal = document.getElementById("confirmModal");
	      const titleNode = document.getElementById("confirmTitle");
	      const messageNode = document.getElementById("confirmMessage");
	      const accept = document.getElementById("confirmAccept");
	      const cancel = document.getElementById("confirmCancel");
	      if (!modal || !titleNode || !messageNode || !accept || !cancel) {
	        return Promise.resolve(false);
	      }
	      if (pendingConfirmation) closeConfirmation(false);
	      titleNode.textContent = title;
	      messageNode.textContent = message;
	      accept.textContent = acceptLabel;
	      accept.classList.toggle("danger", Boolean(danger));
	      modal.hidden = false;
	      accept.focus();
	      return new Promise((resolve) => {
	        pendingConfirmation = { resolve };
	      });
	    }

	    function normalizeNativeTooltips(root = document) {
	      if (!root || !root.querySelectorAll) return;
	      root.querySelectorAll("[title]").forEach((node) => {
		        const text = node.getAttribute("title") || "";
		        node.removeAttribute("title");
		        if (!text) return;
		        node.setAttribute("data-tooltip", text);
		        if (!node.getAttribute("aria-label") && !node.textContent.trim()) {
		          node.setAttribute("aria-label", text);
		        }
	      });
	    }

	    function uiTooltipTarget(target) {
	      if (!(target instanceof Element)) return null;
		      const node = target.closest("[data-tooltip], [title]");
		      if (!node) return null;
		      if (node.hasAttribute("title")) normalizeNativeTooltips(node.parentElement || document);
		      return node.getAttribute("data-tooltip") ? node : null;
	    }

	    function positionUiTooltip(event, target) {
	      const tooltip = document.getElementById("uiTooltip");
	      if (!tooltip || tooltip.hidden) return;
	      const rect = target.getBoundingClientRect();
	      const baseX = typeof event.clientX === "number" ? event.clientX : rect.left + rect.width / 2;
	      const baseY = typeof event.clientY === "number" ? event.clientY : rect.bottom;
	      const left = Math.max(8, Math.min(window.innerWidth - tooltip.offsetWidth - 8, baseX + 12));
	      const top = Math.max(8, Math.min(window.innerHeight - tooltip.offsetHeight - 8, baseY + 14));
	      tooltip.style.left = `${left}px`;
	      tooltip.style.top = `${top}px`;
	    }

	    function showUiTooltip(event) {
	      const target = uiTooltipTarget(event.target);
	      const tooltip = document.getElementById("uiTooltip");
	      if (!target || !tooltip) return;
	      tooltip.textContent = target.getAttribute("data-tooltip") || "";
	      if (!tooltip.textContent) return;
	      tooltip.hidden = false;
	      positionUiTooltip(event, target);
	    }

	    function hideUiTooltip() {
	      const tooltip = document.getElementById("uiTooltip");
	      if (tooltip) tooltip.hidden = true;
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

	    function renderAuthHealth(profile) {
	      if (profile.auth_health_html) return profile.auth_health_html;
	      const health = profile.auth_health && typeof profile.auth_health === "object" ? profile.auth_health : null;
	      if (!health) return "";
	      const status = String(health.status || "");
	      if (status !== "login_required" && status !== "refresh_failed") return "";
	      const label = status === "login_required" ? "Login required" : "Auth refresh failed";
	      const timestamp = formatEventTime(health.error_at || health.last_refresh_failed_at || "");
	      const suffix = timestamp ? ` (${timestamp})` : "";
	      return `
	        <div class="auth-health ${escapeHtml(status)}" title="${escapeHtml(health.message || "")}">
	          <strong>${escapeHtml(label)}</strong>${escapeHtml(suffix)}
	        </div>
	      `;
	    }

	    function renderQuotaRefreshControl(profileName) {
	      if (!profileName) return '<span class="quota-refresh-spacer"></span>';
	      return `
	        <form method="post" action="/api/refresh-quota" class="quota-refresh-form" data-action="refresh_quota" data-profile="${escapeHtml(profileName)}">
	          <input type="hidden" name="token" value="${escapeHtml(TOKEN)}">
	          <input type="hidden" name="profile" value="${escapeHtml(profileName)}">
	          <button class="quota-refresh-icon" aria-label="Refresh quota" title="Refresh quota">
	            <svg class="quota-refresh-glyph" viewBox="0 0 24 24" fill="none" aria-hidden="true">
	              <path d="M20 12a8 8 0 1 1-2.34-5.66"></path>
	              <path d="M20 4v5h-5"></path>
	            </svg>
	          </button>
	        </form>
	      `;
	    }

	    function renderQuotaCredits(label) {
	      return label
	        ? `<span class="quota-credits-pill" title="Codex credits balance">Credits: ${escapeHtml(label)}</span>`
	        : "";
	    }

	    function renderResetCreditControl(resetCredit, profileName) {
	      if (!resetCredit || typeof resetCredit !== "object") return "";
	      const label = String(resetCredit.label || "");
	      if (!label) return "";
	      const message = String(resetCredit.message || "");
	      if (resetCredit.disabled) {
	        return `<span class="quota-reset-credit-pill disabled" title="${escapeHtml(message)}">${escapeHtml(label)}</span>`;
	      }
	      return `
	        <form method="post" action="/api/consume-reset-credit" class="reset-credit-form" data-action="consume_reset_credit" data-profile="${escapeHtml(profileName)}" data-confirm="${escapeHtml(message)}">
	          <input type="hidden" name="token" value="${escapeHtml(TOKEN)}">
	          <input type="hidden" name="profile" value="${escapeHtml(profileName)}">
	          <button class="quota-reset-credit-pill" title="Use one rate-limit reset credit">${escapeHtml(label)}</button>
	        </form>
	      `;
	    }

	    function renderQuotaState(state) {
	      const data = state && typeof state === "object" ? state : {};
	      const level = ["warning", "error", "info"].includes(String(data.level || "")) ? String(data.level) : "warning";
	      const title = String(data.title || "Quota unavailable");
	      const message = String(data.message || "Quota is unavailable for this profile.");
	      return `
	        <div class="quota-empty quota-state ${escapeHtml(level)}">
	          <strong>${escapeHtml(title)}</strong>
	          <span>${escapeHtml(message)}</span>
	        </div>
	      `;
	    }

	    function renderQuotaCountRows(rows) {
	      return (rows || []).map((row) => {
	        const reset = row.reset ? ` <span class="quota-count-reset">(${escapeHtml(row.reset)})</span>` : "";
	        return `<div class="quota-count-line"><span>${escapeHtml(row.label || "")}</span><strong>${escapeHtml(row.value || "")}</strong>${reset}</div>`;
	      }).join("") || '<div class="quota-muted">No window details</div>';
	    }

	    function renderQuotaHorizons(stack, bucket) {
	      const name = String(bucket.name || "Quota bucket");
	      const title = String(bucket.title || "");
	      if (Array.isArray(stack.count_rows) && stack.count_rows.length) {
	        return `
	          <div class="quota-title">
	            <span class="quota-horizon weekly"></span>
	            <span class="quota-bucket-name" title="${escapeHtml(title)}">${escapeHtml(name)}</span>
	            <span class="quota-horizon primary"></span>
	          </div>
	        `;
	      }
	      const primaryNotEnforced = Boolean(stack.primary_not_enforced);
	      const primaryClass = primaryNotEnforced ? "primary not-enforced" : "primary";
	      return `
	        <div class="quota-title">
	          <span class="quota-horizon weekly">${escapeHtml(stack.weekly_status || "")}</span>
	          <span class="quota-bucket-name" title="${escapeHtml(title)}">${escapeHtml(name)}</span>
	          <span class="quota-horizon ${primaryClass}">${escapeHtml(stack.primary_reset_text || "")}</span>
	        </div>
	      `;
	    }

	    function renderQuotaStack(stack) {
	      if (Array.isArray(stack.count_rows) && stack.count_rows.length) {
	        return renderQuotaCountRows(stack.count_rows);
	      }
	      const primaryStyle = Number(stack.primary_style || 0);
	      const weeklyStyle = Number(stack.weekly_style || 0);
	      const primaryText = String(stack.primary_text || "");
	      const weeklyText = String(stack.weekly_text || "");
	      const primaryEmpty = String(stack.primary_empty || "");
	      const primaryNotEnforced = Boolean(stack.primary_not_enforced);
	      const special = String(stack.special || "");
	      const stackClass = `${special ? ` quota-stack-${special}` : ""}${primaryNotEnforced ? " quota-stack-primary-not-enforced" : ""}`;
	      const aria = String(stack.aria || "");
	      const barAttrs = special || primaryNotEnforced
	        ? `role="img" aria-label="${escapeHtml(aria)}"`
	        : `role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${primaryStyle.toFixed(0)}" aria-label="${escapeHtml(aria)}"`;
	      const primaryLabelClass = primaryNotEnforced ? "quota-primary-label-outside not-enforced" : "quota-primary-label-outside";
	      return `
	        <div class="quota-stack${escapeHtml(stackClass)}">
	          <div class="quota-stack-row">
	            <span class="quota-weekly-label">${escapeHtml(weeklyText)}</span>
	            <div class="quota-stack-bar" ${barAttrs}>
	              <span class="quota-weekly-fill" style="width: ${weeklyStyle.toFixed(2)}%"></span>
	              <span class="quota-primary-fill${escapeHtml(primaryEmpty)}" style="width: ${primaryStyle.toFixed(2)}%"></span>
	            </div>
	            <span class="${primaryLabelClass}">${escapeHtml(primaryText)}</span>
	          </div>
	        </div>
	      `;
	    }

	    function renderQuotaBucket(bucket) {
	      const stack = bucket && typeof bucket.stack === "object" ? bucket.stack : {};
	      return `
	        <div class="quota-bucket">
	          ${renderQuotaHorizons(stack, bucket || {})}
	          ${renderQuotaStack(stack)}
	        </div>
	      `;
	    }

	    function renderStructuredQuota(profile, profileName) {
	      const quota = profile.quota && typeof profile.quota === "object" ? profile.quota : null;
	      if (!quota) return profile.quota_html || '<div class="quota-empty">No quota cached</div>';
	      const updated = String(quota.updated || "No quota cached");
	      let body = "";
	      const buckets = Array.isArray(quota.buckets) ? quota.buckets : [];
	      if (buckets.length) {
	        body = buckets.map((bucket) => renderQuotaBucket(bucket)).join("");
	      } else if (quota.state) {
	        body = renderQuotaState(quota.state);
	      } else {
	        const empty = String(quota.empty || "No quota cached");
	        const emptyClass = quota.refresh_error_billing ? "quota-empty error billing" : empty === "Quota payload has no bucket details" ? "quota-muted" : "quota-empty";
	        body = `<div class="${emptyClass}">${escapeHtml(empty)}</div>`;
	      }
	      const refreshError = quota.refresh_error
	        ? `<div class="quota-refresh-error${quota.refresh_error_billing ? " billing" : ""}">Last refresh failed: ${escapeHtml(quota.refresh_error)}</div>`
	        : "";
	      return `
	        <div class="quota-panel">
	          <div class="quota-panel-head">
	            ${renderQuotaRefreshControl(profileName)}
	            <span class="quota-updated">${escapeHtml(updated)}</span>
	            ${renderResetCreditControl(quota.reset_credit, profileName)}
	            ${renderQuotaCredits(quota.credits_label)}
	          </div>
	          ${body}
	          ${refreshError}
	        </div>
	      `;
	    }

	    function modelCatalog(profile) {
	      const profileCatalog = profile && Array.isArray(profile.model_catalog) ? profile.model_catalog : [];
	      return profileCatalog.length ? profileCatalog : (latestModelCatalog.length ? latestModelCatalog : [
	        { id: "gpt-5.6-sol", display: "GPT-5.6-Sol", reasoning: ["low", "medium", "high", "xhigh", "max", "ultra"] },
		        { id: "gpt-5.6-terra", display: "GPT-5.6-Terra", reasoning: ["low", "medium", "high", "xhigh", "max", "ultra"] },
		        { id: "gpt-5.6-luna", display: "GPT-5.6-Luna", reasoning: ["low", "medium", "high", "xhigh", "max"] },
		        { id: "gpt-5.5", display: "GPT-5.5", reasoning: ["low", "medium", "high", "xhigh"] },
		        { id: "gpt-5.4", display: "GPT-5.4", reasoning: ["low", "medium", "high", "xhigh"] },
		        { id: "gpt-5.4-mini", display: "GPT-5.4-Mini", reasoning: ["low", "medium", "high", "xhigh"] },
	        { id: "gpt-5.2", display: "GPT-5.2", reasoning: ["low", "medium", "high", "xhigh"] }
	      ]);
	    }

	    function stableRenderHash(value) {
	      let hash = 2166136261;
	      const text = String(value || "");
	      for (let index = 0; index < text.length; index += 1) {
	        hash ^= text.charCodeAt(index);
	        hash = Math.imul(hash, 16777619);
	      }
	      return String(hash >>> 0);
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
		      const currentModel = String(setting.model || "gpt-5.6-sol");
		      const currentReasoning = String(setting.reasoning_effort || (currentModel === "gpt-5.6-sol" ? "low" : "medium"));
			      const label = `${currentModel.toLowerCase()} ${reasoningDisplay(currentReasoning)}`;
	      const items = modelCatalog(profile).map((item) => {
	        const model = String(item.id || "");
	        if (!model) return "";
	        const display = String(item.display || model);
	        const note = String(item.note || "");
	        const selected = model === currentModel ? " selected" : "";
		        const levels = Array.isArray(item.reasoning) && item.reasoning.length ? item.reasoning : ["none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"];
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
	        : renderStructuredQuota(profile, name);
	      const pinMenu = profile.pin_menu_html || "";
	      const pinnedSessions = profile.pinned_sessions_html || "";
	      const loginStatusHtml = profile.login_status_html || "";
	      const authHealthHtml = renderAuthHealth(profile);
	      return `
	        <tr class="profile-row${profile.active ? " active" : ""}" data-profile="${escapeHtml(name)}" data-profile-key="${escapeHtml(name)}">
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

	    function renderProfileRows(profiles, pendingAction, pendingProfile) {
	      const body = document.getElementById("profileRows");
	      if (!body) return;
	      const existing = new Map();
	      Array.from(body.children).forEach((row) => {
	        if (row instanceof HTMLElement) existing.set(row.dataset.profileKey || "", row);
	      });
	      const seen = new Set();
	      const template = document.createElement("template");
	      for (const [index, profile] of (profiles || []).entries()) {
	        const name = String(profile && profile.name || `profile-${index}`);
	        const html = profileRow(profile, pendingAction, pendingProfile).trim();
	        const hash = stableRenderHash(html);
	        let row = existing.get(name);
	        if (!row || row.dataset.renderHash !== hash) {
	          template.innerHTML = html;
	          const next = template.content.firstElementChild;
	          if (!(next instanceof HTMLElement)) continue;
	          next.dataset.profileKey = name;
	          next.dataset.renderHash = hash;
	          if (row) {
	            row.replaceWith(next);
	          } else {
	            body.appendChild(next);
	          }
	          row = next;
	          normalizeNativeTooltips(row);
	        }
	        seen.add(name);
	        body.appendChild(row);
	      }
	      for (const [key, row] of existing.entries()) {
	        if (!seen.has(key)) row.remove();
	      }
	    }

    function render(packet) {
      const status = packet.status || {};
      latestStatus = status;
      const sections = new Set(Array.isArray(packet.sections) ? packet.sections : ["full"]);
      const fullRender = sections.has("full") || !Array.isArray(packet.sections);
      const profilesChanged = fullRender || sections.has("profiles");
      const controlChanged = fullRender || sections.has("control_plane");
      const statsChanged = fullRender || sections.has("stats");
      updateQuotaRefreshEpoch(status);
      const pendingAction = packet.pending_action || "";
      const pendingProfile = String(packet.pending_profile || "");
      const activeRequests = Number(status.active_requests || 0);
      const activeTunnels = Number(status.active_websockets || 0);
      const liveBusy = Boolean(status.live_busy);
      latestLiveBusy = liveBusy;
      latestStats = status.stats || latestStats || { profiles: [], recent: [] };
      latestControlPlane = status.control_plane || latestControlPlane || { sessions: [] };
      observeControlUserInputs(latestControlPlane);
      latestCodex = status.codex || latestCodex || {};
      if (Array.isArray(status.model_catalog)) latestModelCatalog = status.model_catalog;
	      if ((pendingAction === "refresh_quota" || pendingAction === "consume_reset_credit") && pendingProfile) {
	        quotaRefreshInFlight = pendingProfile;
	      } else if (quotaRefreshInFlight) {
	        quotaRefreshInFlight = "";
	        scheduleNextQuotaRefresh(250);
	      }
	      if (profilesChanged) queueInitialQuotaRefreshes(status.profiles || []);
	      scheduleNextQuotaRefresh(250);
	      document.getElementById("activeProfile").textContent = status.active_profile || "none";
	      const codexCli = status.codex && status.codex.cli ? status.codex.cli : {};
	      document.getElementById("codexVersion").textContent = codexCli.version || "unknown";
	      const restartState = status.codex && status.codex.restart_required ? status.codex.restart_required : {};
	      const restartRequired = Boolean(restartState.required);
	      const restartNotice = document.getElementById("codexRestartRequired");
	      restartNotice.hidden = !restartRequired;
	      restartNotice.title = restartRequired ? String(restartState.reason || "Restart Provision when active work is idle.") : "";
	      document.getElementById("activeRequests").textContent = String(activeRequests);
	      document.getElementById("activeTunnels").textContent = String(activeTunnels);
	      if (controlChanged) {
	        renderSessionTabs(status);
	        renderLauncherBar(status);
	      }
	      const connection = document.getElementById("connectionState");
	      const isDisconnected = connection.textContent === "Disconnected";
	      if (!isDisconnected) {
	        connection.textContent = `Live (${liveBusy ? "busy" : "idle"})`;
	        document.getElementById("proxyDot").className = "dot" + (liveBusy ? " busy" : "");
	      }
	      if (profilesChanged) {
	        rememberOpenMenus();
	        renderProfileRows(status.profiles || [], pendingAction, pendingProfile);
	        restoreOpenMenus();
	      }
	      if (statsChanged && !document.getElementById("statsModal").hidden) {
	        renderStats(latestStats);
      }
	      if (controlChanged) renderControlModal();
	      if (fullRender || profilesChanged || controlChanged || statsChanged) normalizeNativeTooltips(document);
	      if (typeof packet.message === "string") {
	        showUiMessage(packet.message);
	      }
    }

	    function mergeStateDelta(packet) {
	      const delta = packet.status || {};
	      const previous = latestStatus || {};
	      const merged = {
	        ...previous,
	        ...delta,
	        profiles: Object.prototype.hasOwnProperty.call(delta, "profiles")
	          ? delta.profiles
	          : (previous.profiles || []),
	        sessions: Object.prototype.hasOwnProperty.call(delta, "sessions")
	          ? delta.sessions
	          : (previous.sessions || []),
	        control_plane: Object.prototype.hasOwnProperty.call(delta, "control_plane")
	          ? delta.control_plane
	          : (previous.control_plane || latestControlPlane || { sessions: [] }),
	        stats: Object.prototype.hasOwnProperty.call(delta, "stats")
	          ? delta.stats
	          : (previous.stats || latestStats || { profiles: [], recent: [] }),
	        codex: Object.prototype.hasOwnProperty.call(delta, "codex")
	          ? delta.codex
	          : (previous.codex || latestCodex || {}),
	        model_catalog: Object.prototype.hasOwnProperty.call(delta, "model_catalog")
	          ? delta.model_catalog
	          : (previous.model_catalog || latestModelCatalog || [])
	      };
	      latestStatus = merged;
	      return { ...packet, type: "state", status: merged };
	    }

	    function scheduleRender(packet) {
	      const statePacket = packet.type === "state_delta" ? mergeStateDelta(packet) : packet;
	      if (packet.type === "state") latestStatus = packet.status || {};
	      pendingRenderPacket = statePacket;
	      if (pendingRenderFrame) return;
	      pendingRenderFrame = requestAnimationFrame(() => {
	        const nextPacket = pendingRenderPacket;
	        pendingRenderPacket = null;
	        pendingRenderFrame = null;
	        if (nextPacket) render(nextPacket);
	      });
	    }

	    function handleHistoryTurnPacket(packet) {
	      const sessionKey = String(packet.session_key || "");
	      const turnKey = String(packet.turn_key || "");
	      const key = historyCacheKey(sessionKey, turnKey);
	      delete historyTurnRequests[key];
	      if (!packet.ok) {
	        showUiMessage(packet.error ? `History load failed: ${packet.error}` : "History load failed.");
	        return;
	      }
	      if (packet.payload && typeof packet.payload === "object") {
	        historyTurnCache[key] = packet.payload;
	      }
	      if (sessionKey === selectedControlSessionKey && selectedControlTurnKeys[sessionKey] === turnKey) {
	        renderControlModal(true);
	      }
	    }

	    function handleHistoryIndexPacket(packet) {
	      const sessionKey = String(packet.session_key || "");
	      delete historyIndexRequests[sessionKey];
	      if (!packet.ok) {
	        showUiMessage(packet.error ? `History index failed: ${packet.error}` : "History index failed.");
	        return;
	      }
	      historyTurnIndexes[sessionKey] = Array.isArray(packet.turns) ? packet.turns : [];
	      if (sessionKey === selectedControlSessionKey) renderControlModal(true);
	    }

	    function handleResumeCandidatesPacket(packet) {
	      const sessionKey = String(packet.session_key || "");
	      delete resumeCandidateRequests[sessionKey];
	      if (!packet.ok) {
	        showUiMessage(packet.error ? `Resume lookup failed: ${packet.error}` : "Resume lookup failed.");
	        return;
	      }
	      resumeCandidateIndexes[sessionKey] = Array.isArray(packet.candidates) ? packet.candidates : [];
	      if (sessionKey === selectedControlSessionKey) renderControlModal(true);
	      if (sessionKey === selectedLauncherSessionKey) {
	        renderLauncherBar({ control_plane: latestControlPlane });
	      }
	    }

	    function clearPendingSessionLookups() {
	      for (const key of Object.keys(historyTurnRequests)) delete historyTurnRequests[key];
	      for (const key of Object.keys(historyIndexRequests)) delete historyIndexRequests[key];
	      for (const key of Object.keys(resumeCandidateRequests)) delete resumeCandidateRequests[key];
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
	        renderLauncherBar({ control_plane: latestControlPlane });
	        updateControlHeaderActions(selectedControlSession());
	        scheduleNextQuotaRefresh(250);
	      });
      socket.addEventListener("message", (event) => {
        try {
          const packet = JSON.parse(event.data);
          if (packet.type === "state") {
            scheduleRender(packet);
          } else if (packet.type === "state_delta") {
            scheduleRender(packet);
	        } else if (packet.type === "history_turn") {
	          handleHistoryTurnPacket(packet);
	        } else if (packet.type === "history_index") {
	          handleHistoryIndexPacket(packet);
	        } else if (packet.type === "resume_candidates") {
	          handleResumeCandidatesPacket(packet);
	        } else if (packet.type === "heartbeat") {
            latestLiveBusy = Boolean(packet.live_busy);
            setConnection("Live", latestLiveBusy ? "busy" : "");
          }
        } catch {
          setConnection("Live", "");
        }
      });
	      socket.addEventListener("close", () => {
	        clearPendingSessionLookups();
	        quotaRefreshInFlight = "";
	        setConnection("Disconnected", "disconnected");
	        renderLauncherBar({ control_plane: latestControlPlane });
	        updateControlHeaderActions(selectedControlSession());
	        reconnectTimer = setTimeout(connect, 1500);
	      });
	      socket.addEventListener("error", () => {
	        clearPendingSessionLookups();
	        quotaRefreshInFlight = "";
	        setConnection("Disconnected", "disconnected");
	        renderLauncherBar({ control_plane: latestControlPlane });
	        updateControlHeaderActions(selectedControlSession());
	      });
    }

	    document.addEventListener("submit", async (event) => {
      const form = event.target.closest("form[data-action]");
      if (!form) return;
	      if (!socket || socket.readyState !== WebSocket.OPEN) return;
	      event.preventDefault();
	      const action = form.dataset.action;
	      const profile = form.dataset.profile || "";
	      const confirmMessage = form.dataset.confirm || "";
	      if (confirmMessage) {
	        const confirmed = await confirmAction({
	          title: action === "consume_reset_credit" ? "Use reset credit" : "Confirm action",
	          message: confirmMessage,
	          acceptLabel: action === "consume_reset_credit" ? "Use credit" : "Confirm",
	          danger: action === "consume_reset_credit"
	        });
	        if (!confirmed) return;
	      }
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

	    document.addEventListener("pointerover", showUiTooltip);
	    document.addEventListener("pointermove", (event) => {
	      const target = uiTooltipTarget(event.target);
	      if (target) positionUiTooltip(event, target);
	    });
	    document.addEventListener("pointerout", (event) => {
	      const next = event.relatedTarget;
	      if (next instanceof Element && uiTooltipTarget(next)) return;
	      hideUiTooltip();
	    });
	    document.addEventListener("focusin", showUiTooltip);
	    document.addEventListener("focusout", hideUiTooltip);

	    document.getElementById("launcherSession").addEventListener("change", (event) => {
	      selectedLauncherSessionKey = event.target.value || "";
	      launcherResumeSessionId = "";
	      renderLauncherBar({ control_plane: latestControlPlane });
	    });

	    document.getElementById("launcherMode").addEventListener("change", (event) => {
	      launcherMode = event.target.value || "new";
	      renderLauncherBar({ control_plane: latestControlPlane });
	    });

	    document.getElementById("launcherPermission").addEventListener("change", (event) => {
	      launcherPermission = event.target.value || "workspace-write";
	    });

		    document.getElementById("launcherResumeSession").addEventListener("change", (event) => {
		      launcherResumeSessionId = event.target.value || "";
		      renderLauncherBar({ control_plane: latestControlPlane });
		    });

	    document.getElementById("launcherStart").addEventListener("click", () => {
	      const sessionId = launcherMode === "resume-session" ? launcherResumeSessionId : "";
	      if (launcherMode === "resume-session" && !sessionId) return;
	      sendLaunchSession(
	        selectedLauncherSessionKey,
	        launcherMode,
	        sessionId
	      );
	      launcherPanelOpen = false;
	      renderSessionTabs({ control_plane: latestControlPlane });
	      renderLauncherBar({ control_plane: latestControlPlane });
	    });

	    document.getElementById("launcherClose").addEventListener("click", () => {
	      launcherPanelOpen = false;
	      renderSessionTabs({ control_plane: latestControlPlane });
	      renderLauncherBar({ control_plane: latestControlPlane });
	    });

	    document.getElementById("controlTurnSelect").addEventListener("change", (event) => {
	      if (!selectedControlSessionKey) return;
	      const selectedTurn = event.target.value || "";
	      selectedControlTurnKeys[selectedControlSessionKey] = selectedTurn;
	      if (selectedTurn) manuallySelectedControlTurnKeys[selectedControlSessionKey] = selectedTurn;
	      else delete manuallySelectedControlTurnKeys[selectedControlSessionKey];
	      delete followLatestTurnAfterUserInput[selectedControlSessionKey];
	      saveControlScroll();
	      renderControlModal(true);
	    });

	    document.getElementById("controlTurnSelect").addEventListener("pointerenter", () => {
	      controlTurnSelectInteracting = true;
	    });

	    document.getElementById("controlTurnSelect").addEventListener("pointerleave", () => {
	      controlTurnSelectInteracting = false;
	      updateControlHeaderActions(selectedControlSession());
	    });

	    document.getElementById("controlTurnSelect").addEventListener("focus", () => {
	      controlTurnSelectInteracting = true;
	    });

	    document.getElementById("controlTurnSelect").addEventListener("blur", () => {
	      controlTurnSelectInteracting = false;
	      updateControlHeaderActions(selectedControlSession());
	    });

	    document.getElementById("sessionTabs").addEventListener("click", (event) => {
	      const target = event.target;
	      if (!(target instanceof Element)) return;
		      const close = target.closest("[data-session-close]");
		      if (close) {
		        event.preventDefault();
		        event.stopPropagation();
		        forgetControlSession(close.dataset.sessionClose || "");
		        return;
		      }
	      const launchTab = target.closest("[data-launch-tab]");
	      if (launchTab) {
	        saveControlScroll();
			        resetControlPromptHistory();
		        launcherPanelOpen = true;
	        selectedControlSessionKey = "";
	        pendingControlRender = false;
	        document.getElementById("controlModal").hidden = true;
	        renderSessionTabs({ control_plane: latestControlPlane });
	        renderLauncherBar({ control_plane: latestControlPlane });
	        return;
	      }
	      const tab = target.closest(".session-tab");
	      if (!tab) return;
		      saveControlScroll();
		      resetControlPromptHistory();
		      launcherPanelOpen = false;
	      selectedControlSessionKey = tab.dataset.sessionKey || "";
	      selectedLauncherSessionKey = selectedControlSessionKey;
	      document.getElementById("controlModal").hidden = false;
	      renderSessionTabs({ control_plane: latestControlPlane });
	      renderLauncherBar({ control_plane: latestControlPlane });
	      updateControlDockGeometry();
	      renderControlModal(true);
	    });

		    document.getElementById("sessionTabs").addEventListener("dragstart", (event) => {
		      const target = event.target;
		      if (!(target instanceof Element)) return;
		      const tab = target.closest(".session-tab[data-session-key]");
		      if (!tab) return;
		      draggedSessionTabKey = tab.dataset.sessionKey || "";
		      tab.classList.add("dragging");
		      if (event.dataTransfer) {
		        event.dataTransfer.effectAllowed = "move";
		        event.dataTransfer.setData("text/plain", draggedSessionTabKey);
		      }
		    });

		    document.getElementById("sessionTabs").addEventListener("dragover", (event) => {
		      if (!draggedSessionTabKey) return;
		      const target = event.target;
		      if (!(target instanceof Element)) return;
		      const tab = target.closest(".session-tab[data-session-key]");
		      if (!tab || tab.dataset.sessionKey === draggedSessionTabKey) return;
		      event.preventDefault();
		      clearSessionTabDropClasses();
		      tab.classList.add(sessionTabDropPosition(tab, event) === "after" ? "drop-after" : "drop-before");
		    });

		    document.getElementById("sessionTabs").addEventListener("dragleave", (event) => {
		      const target = event.target;
		      if (!(target instanceof Element)) return;
		      const tab = target.closest(".session-tab[data-session-key]");
		      if (tab) tab.classList.remove("drop-before", "drop-after");
		    });

		    document.getElementById("sessionTabs").addEventListener("drop", (event) => {
	      if (!draggedSessionTabKey) return;
	      event.preventDefault();
	      const container = document.getElementById("sessionTabs");
		      const dragged = Array.from(container.querySelectorAll(".session-tab[data-session-key]"))
		        .find((tab) => tab.dataset.sessionKey === draggedSessionTabKey);
		      const target = event.target instanceof Element ? event.target.closest(".session-tab[data-session-key]") : null;
		      if (dragged && target && target !== dragged) {
		        const position = sessionTabDropPosition(target, event);
		        container.insertBefore(dragged, position === "after" ? target.nextSibling : target);
		        sendSessionTabOrder();
		      }
		      draggedSessionTabKey = "";
		      clearSessionTabDropClasses();
		    });

		    document.getElementById("sessionTabs").addEventListener("dragend", () => {
		      draggedSessionTabKey = "";
		      clearSessionTabDropClasses();
		    });

	    document.getElementById("controlForget").addEventListener("click", async () => {
		      await forgetControlSession(selectedControlSessionKey);
	    });

	    document.getElementById("controlClose").addEventListener("click", () => {
	      document.getElementById("controlModal").hidden = true;
	      selectedControlSessionKey = "";
	      pendingControlRender = false;
	      renderSessionTabs({ control_plane: latestControlPlane });
	      renderLauncherBar({ control_plane: latestControlPlane });
	    });

	    document.getElementById("controlModal").addEventListener("click", (event) => {
	      if (event.target === event.currentTarget) {
	        event.currentTarget.hidden = true;
	        selectedControlSessionKey = "";
	        pendingControlRender = false;
	        renderSessionTabs({ control_plane: latestControlPlane });
	        renderLauncherBar({ control_plane: latestControlPlane });
	      }
	    });

	    document.querySelectorAll("[data-control-view]").forEach((button) => {
	      button.addEventListener("click", () => {
	        saveControlScroll();
	        controlView = button.dataset.controlView || "discussion";
	        renderControlModal(true);
	      });
	    });

	    document.getElementById("controlSearch").addEventListener("input", (event) => {
	      controlSearchText = event.target.value || "";
	      renderControlModal(true);
	    });

	    document.getElementById("controlContent").addEventListener("click", (event) => {
	      const target = event.target;
	      if (!(target instanceof Element)) return;
	      const candidate = target.closest("[data-resume-candidate]");
	      if (candidate && selectedControlSessionKey) {
	        selectedResumeCandidateIds[selectedControlSessionKey] = candidate.dataset.resumeCandidate || "";
	        renderControlModal(true);
	        return;
	      }
	      const resumeAction = target.closest("[data-resume-action]");
	      if (resumeAction && selectedControlSessionKey) {
	        const selectedId = selectedResumeCandidateIds[selectedControlSessionKey] || "";
	        if (!selectedId) return;
	        sendLaunchSession(selectedControlSessionKey, resumeAction.dataset.resumeAction || "resume-session", selectedId);
	        return;
	      }
	      const button = target.closest(".control-show-more");
	      if (!button) return;
	      const key = button.dataset.messageKey || "";
	      if (!key) return;
	      expandedControlMessages[key] = !expandedControlMessages[key];
	      renderControlModal(true);
	    });

		    document.getElementById("controlContent").addEventListener("scroll", () => {
		      saveControlScroll();
		      updateControlScrollBadges();
		    }, { passive: true });

	    document.getElementById("controlPrompt").addEventListener("input", () => {
		      resetControlPromptHistory();
	      updateControlComposeState(selectedControlSession());
	    });

	    document.getElementById("controlPrompt").addEventListener("keydown", (event) => {
		      if (handleControlPromptHistory(event)) return;
	      if (event.key !== "Enter" || event.shiftKey || event.isComposing) return;
	      event.preventDefault();
	      document.getElementById("controlCompose").requestSubmit();
	    });

	    document.getElementById("controlCompose").addEventListener("submit", (event) => {
	      event.preventDefault();
	      const prompt = document.getElementById("controlPrompt");
	      const text = prompt.value.trim();
	      if (!text || !selectedControlSessionKey) return;
	      if (!socket || socket.readyState !== WebSocket.OPEN) {
	        showUiMessage("Dashboard websocket is not connected.");
	        return;
	      }
	      socket.send(JSON.stringify({
	        action: "session_prompt",
	        session_key: selectedControlSessionKey,
	        prompt: text,
	        token: TOKEN
	      }));
	      delete manuallySelectedControlTurnKeys[selectedControlSessionKey];
	      followLatestTurnAfterUserInput[selectedControlSessionKey] = true;
	      selectedControlTurnKeys[selectedControlSessionKey] = "";
	      prompt.value = "";
		      resetControlPromptHistory();
	      updateControlComposeState(selectedControlSession());
	    });

	    function sendSessionEscape() {
	      if (!selectedControlSessionKey) return false;
	      const session = selectedControlSession();
	      if (!controlInteractionAvailable(session)) return false;
	      if (!socket || socket.readyState !== WebSocket.OPEN) {
	        showUiMessage("Dashboard websocket is not connected.");
	        return true;
	      }
	      socket.send(JSON.stringify({
	        action: "session_escape",
	        session_key: selectedControlSessionKey,
	        token: TOKEN
	      }));
	      return true;
	    }

	    document.addEventListener("keydown", (event) => {
	      if (event.key !== "Escape" || event.defaultPrevented || pendingConfirmation) return;
	      const modal = document.getElementById("controlModal");
	      if (!modal || modal.hidden) return;
	      const active = document.activeElement;
	      if (active && active.id === "controlSearch") return;
	      if (sendSessionEscape()) event.preventDefault();
	    });

	    document.getElementById("statsToggle").addEventListener("click", () => {
	      const modal = document.getElementById("statsModal");
		      setStatsOpen(!modal || modal.hidden);
	    });

	    document.getElementById("statsClose").addEventListener("click", () => {
		      setStatsOpen(false);
	    });

	    document.getElementById("statsModal").addEventListener("click", (event) => {
	      if (event.target === event.currentTarget) {
		        setStatsOpen(false);
	      }
	    });

	    document.getElementById("statsContent").addEventListener("change", (event) => {
	      const target = event.target;
	      if (!(target instanceof HTMLInputElement) || !target.classList.contains("stats-profile-check")) return;
	      statsVisibleProfiles[target.value] = target.checked;
	      renderStats(latestStats);
	    });

	    document.getElementById("statsContent").addEventListener("pointermove", (event) => {
	      const target = event.target;
	      if (!(target instanceof Element)) return;
	      const graph = target.closest(".stats-graph");
	      if (!graph) return;
	      updateStatsGraphHover(graph, event);
	    });

	    document.getElementById("statsContent").addEventListener("pointerdown", (event) => {
	      const target = event.target;
	      if (!(target instanceof Element)) return;
	      const graph = target.closest(".stats-graph");
	      if (!graph) return;
	      updateStatsGraphHover(graph, event);
	    });

	    document.getElementById("statsContent").addEventListener("pointerleave", (event) => {
	      const target = event.target;
	      if (!(target instanceof Element)) return;
	      const graph = target.closest(".stats-graph");
	      if (graph) hideStatsGraphHover(graph);
	    }, true);

	    document.getElementById("confirmCancel").addEventListener("click", () => {
	      closeConfirmation(false);
	    });

	    document.getElementById("confirmAccept").addEventListener("click", () => {
	      closeConfirmation(true);
	    });

	    document.getElementById("confirmModal").addEventListener("click", (event) => {
	      if (event.target === event.currentTarget) closeConfirmation(false);
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

	    document.addEventListener("keydown", (event) => {
	      if (event.key === "Escape" && pendingConfirmation) {
	        event.preventDefault();
	        closeConfirmation(false);
	      }
	    });

	    window.addEventListener("resize", () => {
	      updateControlDockGeometry();
	      renderControlModal(true);
	    });

	    document.addEventListener("selectionchange", () => {
	      if (!controlSelectionActive()) setTimeout(flushPendingControlRender, 0);
	    });

	    document.getElementById("controlModal").addEventListener("focusout", () => {
	      setTimeout(flushPendingControlRender, 0);
	    });

	    document.getElementById("controlModal").addEventListener("mouseup", () => {
	      setTimeout(flushPendingControlRender, 0);
	    });

	    document.getElementById("statsToggle").innerHTML = CHART_ICON;
	    updateThemeToggle();
	    render(INITIAL);
	    normalizeNativeTooltips(document);
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
