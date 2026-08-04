from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import hmac
import html
import json
import os
import pty
import queue
import re
import secrets
import shlex
import shutil
import signal
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
from http.cookies import CookieError, SimpleCookie
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
from .connector import (
    CONNECTOR_ABI_VERSION,
    ConnectorError,
    LocalConnectorHub,
)
from .daemon_host import (
    DEFAULT_DAEMON_HOST,
    daemon_connect_host,
    daemon_host_is_loopback,
    daemon_url_host,
    normalize_daemon_host,
)
from .daemon_logging import configure_daemon_log_rotation
from .paths import Paths, default_codex_home, launcher_path
from .permissions import (
    PERMISSION_CONTROL_MAX_BYTES,
    PERMISSION_ID_MAX_CHARS,
    PERMISSION_PATH_MAX_CHARS,
    PERMISSION_PREVIEW_MAX_CHARS,
    PERMISSION_REASON_MAX_CHARS,
    bounded_permission_text,
)
from .provider_sessions import ClaudeSessionReader, GrokSessionReader, process_is_running
from .providers import ProviderError, canonical_provider
from .proxy_policy import (
    RESPONSE_HOP_BY_HOP_HEADERS,
    UPSTREAM_IDENTITY_HEADERS,
    backend_proxy_prefix,
    backend_upstream_path,
    ensure_default_upstream_user_agent,
    redact_proxy_token,
    should_forward_incoming_header,
)
from .remote import (
    REMOTE_ACTION_PROMPT_MAX_BYTES,
    REMOTE_DEFAULT_CAPABILITIES,
    REMOTE_DELTA_SYNC_MAX_BYTES,
    LocalRemoteAgentSocket,
    RemoteActionCache,
    RemoteControlLeases,
    RemoteCursorCodec,
    RemoteDeviceRegistry,
    RemoteError,
    RemoteStateSynchronizer,
    build_remote_discussion_page,
    build_remote_message_expand,
    build_remote_session_summaries,
    compact_json_bytes,
    opaque_identifier,
    remote_discussion_entry,
    remote_session_audit_ref,
    remote_session_id,
)
from .store import Store, StoreError
from .ui_assets import UI_ASSETS, dashboard_template, logo_asset_bytes, ui_asset

CODEX_API_POST_PROXY_PATHS = frozenset(
    {
        "/v1/responses",
        "/v1/responses/compact",
        "/v1/alpha/search",
        "/v1/images/generations",
        "/v1/images/edits",
    }
)

PROTOCOL_VERSION = 29
DEFAULT_DAEMON_PORT = 4888
UI_SESSION_COOKIE = "provision_ui_session"
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
# HTTP proxy reads use a 10 minute socket timeout. Keep a modest grace period
# so an interrupted request cannot hold session state hostage indefinitely.
STALE_HTTP_REQUEST_SECONDS = 15 * 60
UI_STATE_CHECK_SECONDS = 1.0
UI_HEARTBEAT_SECONDS = 15.0
UI_SAFETY_SNAPSHOT_SECONDS = 60.0
PROVIDER_SESSION_REFRESH_SECONDS = 0.5
PROVIDER_TRANSCRIPT_SOURCE_TEXT_LIMIT = 24 * 1024
PROVIDER_IDENTITY_CACHE_SECONDS = 60.0
PROVIDER_IDENTITY_ERROR_CACHE_SECONDS = 15.0
CLAUDE_AUTH_STATUS_TIMEOUT_SECONDS = 3.0
CLAUDE_AUTH_STATUS_MAX_BYTES = 64 * 1024
PROVIDER_IDENTITY_TEXT_MAX_CHARS = 320
PERMISSION_REQUEST_TIMEOUT_SECONDS = 60.0
PERMISSION_MAX_PENDING = 32
PERMISSION_RESOLVED_TTL_SECONDS = 5 * 60.0
PERMISSION_MAX_RESOLVED = 256
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
CONTROL_TRANSCRIPT_SNAPSHOT_MAX_BYTES = 64 * 1024
CONTROL_TURN_PAYLOAD_MAX_BYTES = 256 * 1024
CONTROL_CONTEXT_WINDOW_TOKENS = 272000
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
# A terminal which has exited should leave enough time for its final events to
# reach the Discussion view, but it should not remain a dashboard tab for the
# lifetime of a long-running daemon.  Session history remains available from
# Codex; this bounds only the daemon's live-observation state.
OBSERVED_SESSION_RETENTION_SECONDS = 90.0
UI_LAUNCHER_PERMISSION_PRESETS = {
    "read-only": ("--sandbox", "read-only", "--ask-for-approval", "on-request"),
    "workspace-write": (
        "--sandbox",
        "workspace-write",
        "--ask-for-approval",
        "on-request",
    ),
    "full-access": (
        "--sandbox",
        "danger-full-access",
        "--ask-for-approval",
        "on-request",
    ),
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
ENVIRONMENT_CONTEXT_RE = re.compile(
    r"\s*<environment_context>.*?</environment_context>\s*", re.DOTALL
)
CODEX_GOAL_CONTEXT_RE = re.compile(
    r"<codex_internal_context\b(?=[^>]*\bsource\s*=\s*[\"']goal[\"'])[^>]*>.*?</codex_internal_context>",
    re.IGNORECASE | re.DOTALL,
)
CODEX_GOAL_OBJECTIVE_RE = re.compile(
    r"<objective>\s*(.*?)\s*</objective>", re.IGNORECASE | re.DOTALL
)
CONTROL_TRANSCRIPT_EDGE_RE = re.compile(
    r"^[\s\ufeff\u200b\u200c\u200d]+|[\s\ufeff\u200b\u200c\u200d]+$"
)
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
USER_SHELL_RESULT_EXIT_CODE_RE = re.compile(
    r"^\s*Exit code:\s*(?P<value>.+?)\s*$", re.IGNORECASE | re.MULTILINE
)
USER_SHELL_RESULT_DURATION_RE = re.compile(
    r"^\s*Duration:\s*(?P<value>.+?)\s*$", re.IGNORECASE | re.MULTILINE
)
USER_SHELL_RESULT_OUTPUT_RE = re.compile(
    r"^\s*Output:\s*(?P<value>.*)$",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)
LOGIN_URL_RE = re.compile(r"https?://[^\s<>]+")
DEVICE_CODE_RE = re.compile(r"\b[A-Z0-9]{4,}(?:-[A-Z0-9]{4,})+\b")
CONTROL_TOOL_CALL_RE = re.compile(r"^ctc_[a-f0-9]{16,}$", re.IGNORECASE)
WEB_SEARCH_TOOL_CALL_RE = re.compile(r"^ws_[A-Za-z0-9_-]+$", re.IGNORECASE)
PROGRAMMATIC_TOOL_INVOCATION_RE = re.compile(r"\btools\.([A-Za-z_][A-Za-z0-9_.]*)\s*\(")
PROGRAMMATIC_TOOL_COMMAND_RE = re.compile(
    r"(?:[\"']cmd[\"']|\bcmd)\s*:\s*(\"(?:\\.|[^\"\\])*\")",
    re.DOTALL,
)
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

TOOL_TRANSCRIPT_SECTION_LABELS = frozenset(
    {
        "agent path",
        "agent states",
        "agent thread",
        "arguments",
        "caller",
        "code",
        "content",
        "details",
        "error",
        "fingerprint",
        "fragments",
        "input",
        "message",
        "model",
        "output",
        "parameters",
        "patch",
        "prompt",
        "query",
        "reasoning",
        "receiver agents",
        "receiver threads",
        "result",
        "results",
        "source",
        "status",
        "stderr",
        "stdout",
        "summary",
    }
)
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
            {
                "id": "priority",
                "name": "Fast",
                "description": "1.5x speed, increased usage",
            },
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
            {
                "id": "priority",
                "name": "Fast",
                "description": "1.5x speed, increased usage",
            },
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
            {
                "id": "priority",
                "name": "Fast",
                "description": "1.5x speed, increased usage",
            },
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
            {
                "id": "priority",
                "name": "Fast",
                "description": "1.5x speed, increased usage",
            },
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
            {
                "id": "priority",
                "name": "Fast",
                "description": "1.5x speed, increased usage",
            },
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

    input_modalities = value.get("input_modalities")
    if input_modalities is None:
        input_modalities = value.get("inputModalities")
    if not isinstance(input_modalities, list):
        input_modalities = []

    return {
        "id": model_id,
        "display": display.strip(),
        "reasoning": reasoning,
        "default_reasoning": default_reasoning,
        "note": codex_model_note(value),
        "service_tiers": [tier for tier in service_tiers if isinstance(tier, dict)],
        "additional_speed_tiers": [
            tier for tier in additional_speed_tiers if isinstance(tier, str)
        ],
        "input_modalities": [
            modality for modality in input_modalities if isinstance(modality, str)
        ],
        "minimal_client_version": first_string_value(
            value, ("minimal_client_version", "minimalClientVersion")
        ),
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


def provider_identity_text(value: Any, limit: int = PROVIDER_IDENTITY_TEXT_MAX_CHARS) -> str:
    """Return a short display-safe identity field without retaining raw output."""

    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ""
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value)).strip()
    return text[:limit]


def normalize_claude_auth_status(value: Any) -> dict[str, Any]:
    """Allowlist the documented, non-secret portion of ``claude auth status``."""

    if not isinstance(value, dict):
        return {
            "available": False,
            "logged_in": None,
            "status": "Authentication status unavailable",
        }
    logged_in_value = value.get("loggedIn")
    logged_in = logged_in_value if isinstance(logged_in_value, bool) else None
    status = (
        "Logged in"
        if logged_in is True
        else "Not logged in"
        if logged_in is False
        else "Authentication status unavailable"
    )
    return {
        "available": logged_in is not None,
        "logged_in": logged_in,
        "status": status,
        "auth_method": provider_identity_text(value.get("authMethod"), 80),
        "api_provider": provider_identity_text(value.get("apiProvider"), 80),
        "email": provider_identity_text(value.get("email")),
        "organization": provider_identity_text(value.get("orgName")),
        "subscription": provider_identity_text(value.get("subscriptionType"), 120),
    }


def claude_auth_status_probe(config_dir: Path | None = None) -> dict[str, Any]:
    """Read Claude's supported JSON auth summary for one effective profile root."""

    executable = shutil.which("claude")
    if not executable:
        return {
            "available": False,
            "logged_in": None,
            "status": "Claude CLI unavailable",
        }
    env = os.environ.copy()
    if config_dir is not None:
        env["CLAUDE_CONFIG_DIR"] = str(config_dir)
    try:
        result = subprocess.run(
            [executable, "auth", "status", "--json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=CLAUDE_AUTH_STATUS_TIMEOUT_SECONDS,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError):
        return {
            "available": False,
            "logged_in": None,
            "status": "Authentication status unavailable",
        }
    encoded = result.stdout.encode("utf-8", errors="replace")
    if not encoded or len(encoded) > CLAUDE_AUTH_STATUS_MAX_BYTES:
        return {
            "available": False,
            "logged_in": None,
            "status": "Authentication status unavailable",
        }
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "available": False,
            "logged_in": None,
            "status": "Authentication status unavailable",
        }
    return normalize_claude_auth_status(value)


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


def reported_codex_cli(compatibility: dict[str, Any] | None) -> dict[str, Any]:
    """Return the best available CLI identity for user-facing status.

    ``cli`` is intentionally frozen when the daemon starts so we can tell the
    user a restart is needed.  It is not, however, the version currently
    installed on disk.  Prefer the periodically refreshed probe in displays
    while preserving the startup value in the compatibility payload.
    """
    if not isinstance(compatibility, dict):
        return {}
    runtime = compatibility.get("runtime_cli")
    if isinstance(runtime, dict) and isinstance(runtime.get("version"), str):
        return runtime
    startup = compatibility.get("cli")
    return startup if isinstance(startup, dict) else {}


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
    "thread_search": "thread/search",
    "thread_search_occurrences": "thread/searchOccurrences",
    "thread_read": "thread/read",
    "thread_resume": "thread/resume",
    "thread_turns_list": "thread/turns/list",
    "thread_items_list": "thread/items/list",
    "thread_metadata_update": "thread/metadata/update",
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
    "history": (
        "thread_search",
        "thread_search_occurrences",
        "thread_turns_list",
        "thread_items_list",
        "thread_metadata_update",
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
            schema_files = sorted(
                path.relative_to(out_dir).as_posix() for path in out_dir.rglob("*.json")
            )
            client_request = out_dir / "ClientRequest.json"
            schema_text = (
                client_request.read_text(encoding="utf-8") if client_request.exists() else ""
            )
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

    methods = {
        name: method in schema_text for name, method in APP_SERVER_CAPABILITY_METHODS.items()
    }
    response_types = {
        "rate_limits_response": "v2/GetAccountRateLimitsResponse.json" in schema_files,
        "usage_response": "v2/GetAccountTokenUsageResponse.json" in schema_files,
        "reset_credit_response": "v2/ConsumeAccountRateLimitResetCreditResponse.json"
        in schema_files,
        "reset_credit_summary": "v2/RateLimitResetCreditsSummary.json" in schema_files,
        "raw_response_completed": "v2/RawResponseCompletedNotification.json" in schema_files,
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
        self._reader = threading.Thread(
            target=self._read_stdout, name="provision-codex-app-server", daemon=True
        )
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

    def consume_account_rate_limit_reset_credit(
        self,
        idempotency_key: str,
        *,
        credit_id: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, str] = {"idempotencyKey": idempotency_key}
        if isinstance(credit_id, str) and credit_id:
            params["creditId"] = credit_id
        result = self.request(
            "account/rateLimitResetCredit/consume",
            params,
        )
        if not isinstance(result, dict):
            raise CodexAppServerError(
                "account/rateLimitResetCredit/consume returned a non-object result"
            )
        return result

    def list_threads(
        self,
        *,
        limit: int = 25,
        cursor: str | None = None,
        is_pinned: bool | None = None,
    ) -> Any:
        params: dict[str, Any] = {
            "limit": limit,
            "sortKey": "updated_at",
        }
        if cursor:
            params["cursor"] = cursor
        if isinstance(is_pinned, bool):
            params["isPinned"] = is_pinned
        return self.request("thread/list", params)

    def list_thread_turns(
        self,
        thread_id: str,
        *,
        limit: int = 25,
        cursor: str | None = None,
        sort_direction: str = "desc",
        items_view: str = "summary",
    ) -> Any:
        params: dict[str, Any] = {
            "threadId": thread_id,
            "limit": limit,
            "sortDirection": sort_direction,
            "itemsView": items_view,
        }
        if cursor:
            params["cursor"] = cursor
        return self.request("thread/turns/list", params)

    def list_thread_items(
        self,
        thread_id: str,
        *,
        turn_id: str | None = None,
        limit: int = 100,
        cursor: str | None = None,
        sort_direction: str = "asc",
    ) -> Any:
        params: dict[str, Any] = {
            "threadId": thread_id,
            "limit": limit,
            "sortDirection": sort_direction,
        }
        if turn_id:
            params["turnId"] = turn_id
        if cursor:
            params["cursor"] = cursor
        return self.request("thread/items/list", params)

    def search_thread_occurrences(
        self,
        thread_id: str,
        search_term: str,
        *,
        limit: int = 25,
        cursor: str | None = None,
    ) -> Any:
        params: dict[str, Any] = {
            "threadId": thread_id,
            "searchTerm": search_term,
            "limit": limit,
        }
        if cursor:
            params["cursor"] = cursor
        return self.request("thread/searchOccurrences", params)

    def update_thread_pin(self, thread_id: str, *, is_pinned: bool) -> Any:
        return self.request(
            "thread/metadata/update",
            {"threadId": thread_id, "isPinned": is_pinned},
        )

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
    return not any(identity.startswith(prefix) for prefix in RESUME_CANDIDATE_INSTRUCTION_PREFIXES)


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


def codex_history_entries_from_response_item(
    payload: dict[str, Any], timestamp: str
) -> list[dict[str, Any]]:
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
        return (
            [codex_history_entry("assistant_progress", text, timestamp, turn_id=source_turn_id)]
            if text
            else []
        )
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


def codex_history_entries_from_event_msg(
    payload: dict[str, Any], timestamp: str
) -> list[dict[str, Any]]:
    event_type = str(payload.get("type") or "")
    source_turn_id = codex_history_source_turn_id(payload)
    if event_type == "agent_reasoning":
        text = clean_transcript_text(str(payload.get("text") or ""))
        return (
            [codex_history_entry("assistant_progress", text, timestamp, turn_id=source_turn_id)]
            if text
            else []
        )
    if event_type in {"agent_message", "assistant_message"}:
        text = clean_transcript_text(str(payload.get("message") or payload.get("text") or ""))
        return (
            [codex_history_entry("assistant", text, timestamp, turn_id=source_turn_id)]
            if text
            else []
        )
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
                " ".join(
                    str(item.get("full_text") or item.get("text") or "") for item in transcript
                )
            )[:CONTROL_HISTORY_TURN_SEARCH_TEXT_LIMIT]
            current["end_index"] = max(0, len(transcript) - 1)
        turns.append(current)
        current = None

    def append_current_entry(entry: dict[str, Any]) -> None:
        if current is None:
            return
        transcript = current["transcript"]
        call_id = str(entry.get("call_id") or "")
        if entry.get("role") == "tool" and call_id:
            for existing in reversed(transcript):
                if existing.get("role") != "tool" or existing.get("call_id") != call_id:
                    continue
                existing_text = str(existing.get("full_text") or existing.get("text") or "")
                merged = merge_tool_transcript_text(existing_text, str(entry.get("text") or ""))
                display, truncated = codex_history_display_text(merged)
                existing["text"] = display
                existing["full_text"] = merged
                existing["truncated"] = truncated
                if entry.get("ts"):
                    existing["updated_at"] = str(entry["ts"])
                    current["updated_at"] = str(entry["ts"])
                return
        transcript.append(codex_history_transcript_item(entry, turn_key=str(current["key"])))

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
                            append_current_entry(entry)
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
                        current["transcript"].append(
                            codex_history_transcript_item(entry, turn_key=turn_key)
                        )
                        continue
                    if current is None:
                        continue
                    append_current_entry(entry)
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


def history_turn_duplicates_observed(
    history_turn: dict[str, Any], observed_turn: dict[str, Any]
) -> bool:
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
            transcript = [
                dict(item) for item in turn.get("transcript") or [] if isinstance(item, dict)
            ]
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
    return (
        catalog
        if isinstance(catalog, tuple)
        else tuple(dict(item) for item in DEFAULT_MODEL_CATALOG)
    )


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
    if not detail or detail.lower() in {
        "http error 402: payment required",
        "payment required",
    }:
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
    raw = value[len(prefix) :]
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
    key = (
        normalize_session_key(raw_key)
        if isinstance(raw_key, str) and raw_key
        else normalize_session_key(cwd)
    )
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
        return "~" + normalized[len(home) :]
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
            length = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
            header_length = 4
        elif length == 127:
            if offset + 10 > len(data):
                return False
            length = struct.unpack("!Q", data[offset + 2 : offset + 10])[0]
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
            length = struct.unpack("!H", self.buffer[cursor : cursor + 2])[0]
            cursor += 2
        elif length == 127:
            if len(self.buffer) - cursor < 8:
                return None
            length = struct.unpack("!Q", self.buffer[cursor : cursor + 8])[0]
            cursor += 8

        mask = b""
        if masked:
            if len(self.buffer) - cursor < 4:
                return None
            mask = bytes(self.buffer[cursor : cursor + 4])
            cursor += 4

        if len(self.buffer) - cursor < length:
            return None

        payload = bytes(self.buffer[cursor : cursor + length])
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
            length = struct.unpack("!H", self.buffer[cursor : cursor + 2])[0]
            cursor += 2
        elif length == 127:
            if len(self.buffer) - cursor < 8:
                return None
            length = struct.unpack("!Q", self.buffer[cursor : cursor + 8])[0]
            cursor += 8

        mask = b""
        if masked:
            if len(self.buffer) - cursor < 4:
                return None
            mask = bytes(self.buffer[cursor : cursor + 4])
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


TERMINAL_ESCAPE_SEQUENCE_RE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[ -/]*[@-~])"
)


def terminal_display_text(value: bytes, *, limit: int = 16 * 1024) -> str:
    """Produce safe, bounded plain text for the local terminal-tail view."""
    text = value.decode("utf-8", errors="replace")
    text = TERMINAL_ESCAPE_SEQUENCE_RE.sub("", text)
    text = "".join(character for character in text if character in "\n\r\t" or ord(character) >= 32)
    return text[-limit:]


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
            transcript_text_from_content(item, preserve_edges=preserve_edges) for item in value
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
        pieces = [output_text_from_response(item, preserve_edges=preserve_edges) for item in value]
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


def provider_update_timestamp(value: Any) -> str:
    """Normalize a provider event timestamp for Discussion rendering."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return (
                datetime.fromtimestamp(float(value), timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )
        except (OverflowError, OSError, ValueError):
            return ""
    return ""


def grok_update_payload(value: Any) -> tuple[str, dict[str, Any], dict[str, Any]]:
    if not isinstance(value, dict):
        return "", {}, {}
    params = value.get("params")
    if not isinstance(params, dict):
        return "", {}, {}
    update = params.get("update")
    if not isinstance(update, dict):
        return "", params, {}
    return str(update.get("sessionUpdate") or ""), params, update


GROK_USAGE_FIELDS = (
    "inputTokens",
    "outputTokens",
    "totalTokens",
    "cachedReadTokens",
    "cacheCreationTokens",
    "reasoningTokens",
    "modelCalls",
    "apiDurationMs",
    "costUsdTicks",
    "numTurns",
)


def normalize_grok_turn_usage(value: Any) -> dict[str, int]:
    """Keep the documented numeric portion of a Grok turn usage packet.

    Grok's ``turn_completed`` session update reports work performed for that
    turn.  It is useful provider usage, but it is intentionally not treated as
    an account quota or accumulated across turns.
    """
    if not isinstance(value, dict):
        return {}
    usage: dict[str, int] = {}
    for field in GROK_USAGE_FIELDS:
        raw = value.get(field)
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            continue
        if raw < 0:
            continue
        usage[field] = int(raw)
    return usage


def grok_content_text(value: Any) -> str:
    if (
        isinstance(value, dict)
        and value.get("type") == "text"
        and isinstance(value.get("text"), str)
    ):
        text = clean_transcript_text(value["text"], preserve_edges=True)
        return text[:PROVIDER_TRANSCRIPT_SOURCE_TEXT_LIMIT]
    text = transcript_text_from_content(value, preserve_edges=True)
    return (text or compact_tool_detail(value))[:PROVIDER_TRANSCRIPT_SOURCE_TEXT_LIMIT]


PROVIDER_TOOL_INPUT_LIMIT = 8 * 1024
PROVIDER_TOOL_OUTPUT_LIMIT = 12 * 1024
PROVIDER_TOOL_PATCH_LIMIT = 16 * 1024


def bounded_provider_tool_text(value: Any, limit: int) -> str:
    text = clean_transcript_text(str(value or ""), preserve_edges=True)
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n…[truncated]"


def provider_tool_header(
    name: str,
    *,
    status: str = "",
    exit_code: Any = "",
    duration: Any = "",
) -> str:
    suffixes = []
    if status:
        suffixes.append(f"status {status}")
    if exit_code != "" and exit_code is not None:
        suffixes.append(f"exit {exit_code}")
    if duration != "" and duration is not None:
        try:
            duration_text = f"{float(duration):.1f}s"
        except (TypeError, ValueError):
            duration_text = str(duration)
        suffixes.append(f"duration {duration_text}")
    header = f"Tool: {name or 'tool'}"
    return f"{header} ({', '.join(suffixes)})" if suffixes else header


def grok_diff_patch(value: Any) -> tuple[str, str]:
    if not isinstance(value, list):
        return "", ""
    pieces = ["*** Begin Patch"]
    summaries: list[str] = []
    found = False
    for item in value:
        if not isinstance(item, dict) or str(item.get("type") or "") != "diff":
            continue
        path = str(item.get("path") or "")
        if not path:
            continue
        old = str(item.get("oldText") or "")
        new = str(item.get("newText") or "")
        operation = "Update"
        if not old:
            operation = "Add"
        elif not new:
            operation = "Delete"
        pieces.append(f"*** {operation} File: {path}")
        pieces.append("@@")
        pieces.extend(f"-{line}" for line in old.splitlines())
        pieces.extend(f"+{line}" for line in new.splitlines())
        added = len(new.splitlines())
        deleted = len(old.splitlines())
        summaries.append(f"{operation.lower()} {path} (+{added}/-{deleted})")
        found = True
    if not found:
        return "", ""
    pieces.append("*** End Patch")
    return (
        bounded_provider_tool_text("\n".join(pieces), PROVIDER_TOOL_PATCH_LIMIT),
        "; ".join(summaries),
    )


def grok_tool_input_text(value: Any, name: str) -> str:
    if not isinstance(value, dict):
        return bounded_provider_tool_text(compact_tool_detail(value), PROVIDER_TOOL_INPUT_LIMIT)
    normalized_name = name.lower()
    compact = dict(value)
    if normalized_name in {"edit", "write", "search_replace"}:
        for key in ("content", "old_string", "new_string", "oldText", "newText"):
            content = compact.pop(key, None)
            if isinstance(content, str):
                compact[f"{key}_chars"] = len(content)
    if normalized_name in {"bash", "run_terminal_command"}:
        compact.pop("command", None)
        compact.pop("description", None)
    return bounded_provider_tool_text(compact_tool_detail(compact), PROVIDER_TOOL_INPUT_LIMIT)


def grok_search_result_text(raw_output: dict[str, Any]) -> str:
    matches = raw_output.get("file_matches")
    if not isinstance(matches, list):
        return ""
    lines = [f"{int(raw_output.get('match_count') or 0)} matches"]
    for file_match in matches[:8]:
        if not isinstance(file_match, dict):
            continue
        path = str(file_match.get("path") or "")
        if path:
            lines.append(path)
        entries = file_match.get("matches")
        if isinstance(entries, list):
            for entry in entries[:4]:
                if not isinstance(entry, dict):
                    continue
                number = entry.get("line_number")
                content = str(entry.get("content") or "").strip()
                lines.append(f"  {number}: {content}" if number else f"  {content}")
            if len(entries) > 4:
                lines.append(f"  … {len(entries) - 4} more matches in this file")
    if len(matches) > 8:
        lines.append(f"… {len(matches) - 8} more files")
    return bounded_provider_tool_text("\n".join(lines), PROVIDER_TOOL_OUTPUT_LIMIT)


def update_grok_tool_state(
    state: dict[str, Any],
    update: dict[str, Any],
    *,
    name: str,
) -> None:
    state["name"] = state.get("name") or name or "tool"
    update_title = str(update.get("title") or "").strip()
    if update_title and update_title != state["name"]:
        state["summary"] = update_title
    update_kind = str(update.get("kind") or "").strip()
    if update_kind:
        state["kind"] = update_kind
    metadata = update.get("_meta")
    tool_metadata = metadata.get("x.ai/tool") if isinstance(metadata, dict) else None
    if isinstance(tool_metadata, dict):
        if tool_metadata.get("kind"):
            state["kind"] = str(tool_metadata["kind"])
        if tool_metadata.get("label") and not state.get("label"):
            state["label"] = str(tool_metadata["label"])

    raw_input = update.get("rawInput")
    if raw_input is not None:
        state["input_text"] = grok_tool_input_text(raw_input, str(state["name"]))
        if isinstance(raw_input, dict):
            command = raw_input.get("command") or raw_input.get("cmd")
            if isinstance(command, str) and command.strip():
                state["command"] = command.strip()
            description = raw_input.get("description")
            if isinstance(description, str) and description.strip():
                state["description"] = description.strip()
            if state["name"] in {"write", "search_replace"}:
                path = str(raw_input.get("file_path") or raw_input.get("path") or "")
                old = str(raw_input.get("old_string") or "")
                new = str(raw_input.get("new_string") or raw_input.get("content") or "")
                if path and (old or new):
                    patch, summary = grok_diff_patch(
                        [{"type": "diff", "path": path, "oldText": old, "newText": new}]
                    )
                    state["patch"] = patch
                    state["summary"] = state.get("summary") or summary

    content = update.get("content")
    patch, patch_summary = grok_diff_patch(content)
    if patch:
        state["patch"] = patch
        state["summary"] = state.get("summary") or patch_summary
    elif content is not None:
        content_text = grok_content_text(content)
        if content_text:
            state["output_text"] = bounded_provider_tool_text(
                content_text, PROVIDER_TOOL_OUTPUT_LIMIT
            )

    raw_output = update.get("rawOutput")
    raw_type = str(raw_output.get("type") or "") if isinstance(raw_output, dict) else ""
    if isinstance(raw_output, dict):
        if raw_type == "Bash":
            state["command"] = str(raw_output.get("command") or state.get("command") or "")
            state["description"] = str(
                raw_output.get("description") or state.get("description") or ""
            )
            state["cwd"] = str(raw_output.get("current_dir") or state.get("cwd") or "")
            state["exit_code"] = raw_output.get("exit_code")
            state["output_file"] = str(raw_output.get("output_file") or "")
            state["truncated"] = bool(raw_output.get("truncated"))
            if not state.get("output_text") and isinstance(
                raw_output.get("output_for_prompt"), str
            ):
                state["output_text"] = bounded_provider_tool_text(
                    raw_output["output_for_prompt"], PROVIDER_TOOL_OUTPUT_LIMIT
                )
        elif raw_type == "BackgroundTaskStarted":
            state["background"] = True
            state["status"] = "backgrounded"
            task = raw_output.get("BackgroundTaskStarted")
            if isinstance(task, dict):
                state["output_file"] = str(task.get("output_file") or "")
        elif raw_type == "TaskOutput":
            result = raw_output.get("Result")
            if isinstance(result, dict):
                state["command"] = str(result.get("command") or state.get("command") or "")
                state["exit_code"] = result.get("exit_code")
                state["duration"] = result.get("duration_secs")
                state["output_file"] = str(result.get("output_file") or "")
                state["truncated"] = bool(result.get("truncated"))
                if isinstance(result.get("output"), str):
                    state["output_text"] = bounded_provider_tool_text(
                        result["output"], PROVIDER_TOOL_OUTPUT_LIMIT
                    )
        elif raw_type == "GrepSearch":
            state["exit_code"] = raw_output.get("exit_code")
            search_text = grok_search_result_text(raw_output)
            if search_text:
                state["output_text"] = search_text
        elif raw_type == "ReadFile":
            value = raw_output.get("FileContent")
            if isinstance(value, dict):
                path = str(value.get("absolute_path") or "")
                total_lines = value.get("total_lines")
                if path:
                    state["summary"] = f"Read {path}"
                    if total_lines is not None:
                        state["summary"] += f" ({total_lines} lines)"
                read_text = value.get("content_concise") or value.get("content")
                if isinstance(read_text, str):
                    state["output_text"] = bounded_provider_tool_text(
                        read_text, PROVIDER_TOOL_OUTPUT_LIMIT
                    )
        elif raw_type == "ListDir":
            value = raw_output.get("Content")
            if isinstance(value, dict):
                root = str(value.get("absolute_root_path") or "")
                if root:
                    state["summary"] = f"Listed {root}"
                if isinstance(value.get("content"), str):
                    state["output_text"] = bounded_provider_tool_text(
                        value["content"], PROVIDER_TOOL_OUTPUT_LIMIT
                    )
        elif raw_type == "Todo":
            value = raw_output.get("TodosUpdated")
            if isinstance(value, dict) and isinstance(value.get("summary_for_prompt"), str):
                state["output_text"] = bounded_provider_tool_text(
                    value["summary_for_prompt"], PROVIDER_TOOL_OUTPUT_LIMIT
                )
                todos = value.get("todos")
                if isinstance(todos, list):
                    state["input_text"] = bounded_provider_tool_text(
                        json.dumps({"todos": todos}, ensure_ascii=False, indent=2),
                        PROVIDER_TOOL_INPUT_LIMIT,
                    )
        elif raw_type == "WebFetch":
            value = raw_output.get("Content")
            if isinstance(value, dict):
                url = str(value.get("url") or "")
                status_code = value.get("status_code")
                size = value.get("bytes")
                details = [
                    part
                    for part in (
                        url,
                        f"HTTP {status_code}" if status_code else "",
                        f"{size} bytes" if size else "",
                    )
                    if part
                ]
                if details:
                    state["summary"] = " / ".join(details)
        elif raw_type == "SearchReplace":
            value = raw_output.get("EditsApplied")
            if isinstance(value, dict):
                message = value.get("tool_output_for_prompt_concise")
                if isinstance(message, str):
                    state["summary"] = message

    incoming_status = str(update.get("status") or "").strip()
    if raw_type == "BackgroundTaskStarted":
        incoming_status = "backgrounded"
    terminal_status = str(state.get("terminal_status") or "")
    if (
        incoming_status in {"completed", "failed", "cancelled", "canceled"}
        and raw_type != "BackgroundTaskStarted"
    ):
        state["terminal_status"] = incoming_status
        state["status"] = incoming_status
    elif terminal_status:
        state["status"] = terminal_status
    elif incoming_status and not (state.get("background") and incoming_status == "in_progress"):
        state["status"] = incoming_status
    elif not state.get("status"):
        state["status"] = "in_progress"


def grok_tool_transcript_text(
    update: dict[str, Any],
    *,
    title: str,
    state: dict[str, Any] | None = None,
) -> str:
    tool_state = state if state is not None else {}
    update_grok_tool_state(tool_state, update, name=title)
    details = [
        provider_tool_header(
            str(tool_state.get("name") or title or "tool"),
            status=str(tool_state.get("status") or ""),
            exit_code=tool_state.get("exit_code", ""),
            duration=tool_state.get("duration", ""),
        )
    ]
    summary = str(tool_state.get("description") or tool_state.get("summary") or "")
    if summary:
        details.append(f"Summary:\n{summary}")
    command = str(tool_state.get("command") or "")
    if command:
        details.append(f"Command: {command}")
    input_text = str(tool_state.get("input_text") or "")
    if input_text and input_text not in {command, summary}:
        details.append(f"Input:\n{input_text}")
    patch = str(tool_state.get("patch") or "")
    if patch:
        details.append(f"Patch:\n{patch}")
    output = str(tool_state.get("output_text") or "")
    if output:
        label = "Error" if tool_state.get("status") == "failed" else "Output"
        details.append(f"{label}:\n{output}")
    metadata = []
    if tool_state.get("cwd"):
        metadata.append(f"cwd: {tool_state['cwd']}")
    if tool_state.get("output_file"):
        metadata.append(f"output file: {tool_state['output_file']}")
    if tool_state.get("truncated"):
        metadata.append("provider output truncated")
    if metadata:
        metadata_text = "\n".join(metadata)
        details.append(f"Details:\n{metadata_text}")
    return bounded_provider_tool_text("\n".join(details), PROVIDER_TRANSCRIPT_SOURCE_TEXT_LIMIT)


def claude_message_blocks(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, str):
        return [{"type": "text", "text": value}]
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def claude_tool_state(name: str, value: Any) -> dict[str, Any]:
    state: dict[str, Any] = {"name": name or "tool", "status": "in_progress"}
    if isinstance(value, dict):
        command = value.get("command") or value.get("cmd")
        description = value.get("description")
        if isinstance(command, str) and command.strip():
            state["command"] = command.strip()
        if isinstance(description, str) and description.strip():
            state["summary"] = description.strip()
        if name in {"Edit", "Write"}:
            path = str(value.get("file_path") or value.get("path") or "")
            old = str(value.get("old_string") or "")
            new = str(value.get("new_string") or value.get("content") or "")
            if path and (old or new):
                state["patch"], patch_summary = grok_diff_patch(
                    [{"type": "diff", "path": path, "oldText": old, "newText": new}]
                )
                state["summary"] = state.get("summary") or patch_summary
        state["input_text"] = grok_tool_input_text(value, name.lower())
    else:
        state["input_text"] = bounded_provider_tool_text(
            compact_tool_detail(value), PROVIDER_TOOL_INPUT_LIMIT
        )
    return state


def claude_tool_transcript_text(state: dict[str, Any]) -> str:
    details = [
        provider_tool_header(
            str(state.get("name") or "tool"),
            status=str(state.get("status") or ""),
            exit_code=state.get("exit_code", ""),
        )
    ]
    if state.get("summary"):
        details.append(f"Summary:\n{state['summary']}")
    if state.get("command"):
        details.append(f"Command: {state['command']}")
    if state.get("input_text") and state.get("input_text") != state.get("command"):
        details.append(f"Input:\n{state['input_text']}")
    if state.get("patch"):
        details.append(f"Patch:\n{state['patch']}")
    if state.get("output_text"):
        label = "Error" if state.get("status") == "failed" else "Output"
        details.append(f"{label}:\n{state['output_text']}")
    return bounded_provider_tool_text("\n".join(details), PROVIDER_TRANSCRIPT_SOURCE_TEXT_LIMIT)


def parse_jsonish_string(value: str) -> Any | None:
    stripped = value.strip()
    if not stripped or stripped[0] not in '[{"':
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


def programmatic_tool_first_argument(
    source: str,
    start: int,
    *,
    terminators: frozenset[str] = frozenset({",", ")"}),
) -> str:
    """Extract the first argument from a ``tools.*(...)`` call without evaluating JS."""
    delimiters: list[str] = []
    quote = ""
    escaped = False
    argument_start = start
    matching = {"(": ")", "[": "]", "{": "}"}
    for index in range(start, len(source)):
        char = source[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'", "`"}:
            quote = char
            continue
        if char in matching:
            delimiters.append(matching[char])
            continue
        if delimiters and char == delimiters[-1]:
            delimiters.pop()
            continue
        if not delimiters and char in terminators:
            return source[argument_start:index].strip()
    return ""


def programmatic_tool_argument_detail(source: str, invocation_end: int) -> str:
    argument = programmatic_tool_first_argument(source, invocation_end)
    if not argument:
        return ""
    decoded = decoded_javascript_string_literal(argument)
    if decoded:
        return decoded
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", argument):
        declaration = re.search(
            rf"\b(?:const|let|var)\s+{re.escape(argument)}\s*=\s*",
            source[:invocation_end],
        )
        if declaration:
            assigned = programmatic_tool_first_argument(
                source,
                declaration.end(),
                terminators=frozenset({";"}),
            )
            if assigned:
                argument = assigned
    return clean_transcript_text(argument)[:PROVIDER_TRANSCRIPT_SOURCE_TEXT_LIMIT]


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
        if not details["input"]:
            details["input"] = programmatic_tool_argument_detail(source, match.end())
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


def patch_tool_input(value: Any) -> str:
    """Return an apply_patch body embedded in a tool-call-shaped payload, if any."""
    if not isinstance(value, dict):
        return ""
    for key in ("patch", "input", "content", "arguments", "cmd", "command", "code"):
        text = compact_tool_detail(value.get(key))
        if "*** Begin Patch" in text:
            return text
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
    seen_labels: set[str] = set()

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
        label = match.group(1).strip() if match else ""
        label_key = label.lower()
        if label_key in TOOL_TRANSCRIPT_SECTION_LABELS and label_key not in seen_labels:
            push_section()
            current_label = label
            current_lines = []
            seen_labels.add(label_key)
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
    programmatic_details = (
        programmatic_tool_call_details(value) if normalized == "custom_tool_call" else None
    )
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
    original_name = name
    status = first_string_value(value, ("status", "state"))
    exit_code = first_string_value(value, ("exit_code", "exitCode", "returncode"))
    command = nested_command_value(value)
    if programmatic_details and programmatic_details["command"]:
        command = programmatic_details["command"]
    patch_input = patch_tool_input(value)
    if not patch_input and programmatic_details:
        for candidate in (
            programmatic_details["input"],
            programmatic_details["command"],
        ):
            if "*** Begin Patch" in candidate:
                patch_input = candidate
                break
    patch_source = ""
    if patch_input:
        patch_source = original_name or normalized
        name = "apply_patch"
        command = ""
    detail_sections: list[tuple[str, str]] = []
    seen_detail_text: set[tuple[str, str]] = set()
    if patch_input:
        source = (
            "native apply_patch"
            if "apply_patch" in patch_source.lower() or normalized == "apply_patch_call"
            else patch_source
        )
        seen_detail_text.add(("Source", source))
        detail_sections.append(("Source", source))
        seen_detail_text.add(("Input", patch_input))
        detail_sections.append(("Input", patch_input))
    if (
        programmatic_details
        and programmatic_details["input"]
        and ("Input", programmatic_details["input"]) not in seen_detail_text
    ):
        programmatic_input = programmatic_details["input"]
        seen_detail_text.add(("Input", programmatic_input))
        detail_sections.append(("Input", programmatic_input))
    if is_web_search:
        query = web_search_query_detail(value)
        if query:
            seen_detail_text.add(("Query", query))
            detail_sections.append(("Query", query))
    if not patch_input and ("apply_patch" in name.lower() or normalized == "apply_patch_call"):
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
        ("results", "Results"),
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
        if patch_input and text == patch_input:
            continue
        detail_key = (label, text)
        if text and detail_key not in seen_detail_text:
            seen_detail_text.add(detail_key)
            detail_sections.append((label, text))
    if patch_input:
        header = "Tool: apply_patch"
    elif normalized in {"local_shell_call", "shell_call", "command_execution"} or (
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


def app_server_agent_message_entry(
    item: Any,
    *,
    turn_id: str,
    authoritative: bool,
) -> dict[str, Any] | None:
    if not isinstance(item, dict) or str(item.get("type") or "") != "agentMessage":
        return None
    text = clean_transcript_text(str(item.get("text") or ""))
    if not text:
        return None
    entry: dict[str, Any] = {
        "role": "assistant",
        "text": text,
        "append": False,
        "turn_id": turn_id,
        "authoritative": authoritative,
    }
    source_item_id = first_string_value(item, ("id", "itemId", "item_id"))
    if source_item_id:
        entry["source_item_id"] = source_item_id
    return entry


def app_server_tool_entry_from_item(item: dict[str, Any]) -> dict[str, Any] | None:
    item_type = str(item.get("type") or "")
    item_type_key = re.sub(r"[_-]", "", item_type).lower()
    call_id = first_string_value(item, ("id", "itemId", "item_id", "call_id", "callId"))
    name = first_string_value(item, ("name", "tool"))
    status = first_string_value(item, ("status", "state"))
    if is_control_tool_call_name(call_id) or is_control_tool_call_name(name):
        return None
    if (
        item_type_key == "websearch"
        or is_web_search_tool_call_name(call_id)
        or is_web_search_tool_call_name(name)
    ):
        suffix = f" (status {status})" if status else ""
        details = [f"Tool: Web Search{suffix}"]
        query = web_search_query_detail(item)
        result_value = item.get("results")
        result_label = "Results"
        if result_value is None:
            result_value = item.get("result") or item.get("output")
            result_label = "Result"
        result = compact_tool_detail(result_value)
        error = compact_tool_detail(item.get("error"))
        if query:
            details.append(f"Query:\n{query}")
        if result:
            details.append(f"{result_label}:\n{result}")
        if error:
            details.append(f"Error:\n{error}")
        return {
            "role": "tool",
            "text": "\n".join(details),
            "call_id": call_id,
            "status": status,
        }
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
        return {
            "role": "tool",
            "text": "\n".join(details),
            "call_id": call_id,
            "status": status,
        }
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
        return {
            "role": "tool",
            "text": "\n".join(details),
            "call_id": call_id,
            "status": status,
        }
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
        text = (
            f"Tool: file changes{suffix}" if not detail else f"Tool: file changes{suffix}\n{detail}"
        )
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
        return {
            "role": "tool",
            "text": "\n".join(details),
            "call_id": call_id,
            "status": status,
        }
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
        return {
            "role": "tool",
            "text": "\n".join(details),
            "call_id": call_id,
            "status": status,
        }
    if item_type_key == "hookprompt":
        suffix = f" (status {status})" if status else ""
        details = [f"Tool: hook prompt{suffix}"]
        fragments = compact_tool_detail(item.get("fragments"))
        if fragments:
            details.append(f"Fragments:\n{fragments}")
        return {
            "role": "tool",
            "text": "\n".join(details),
            "call_id": call_id,
            "status": status,
        }
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


def app_server_transcript_entries_from_message(
    message: dict[str, Any],
) -> list[dict[str, Any]]:
    method = app_server_message_method(message)
    params = app_server_message_params(message)
    turn_id = app_server_message_turn_id(message)
    if method == "item/agentMessage/delta":
        delta = params.get("delta")
        text = clean_transcript_text(delta, preserve_edges=True) if isinstance(delta, str) else ""
        if not text:
            return []
        delta_entry: dict[str, Any] = {
            "role": "assistant_progress",
            "text": text,
            "append": True,
            "turn_id": turn_id,
        }
        source_item_id = first_string_value(params, ("itemId", "item_id", "id"))
        if source_item_id:
            delta_entry["source_item_id"] = source_item_id
        return [delta_entry]
    if method == "item/completed":
        item = params.get("item")
        if not isinstance(item, dict):
            return []
        item_type = str(item.get("type") or "")
        if item_type == "agentMessage":
            completed_entry = app_server_agent_message_entry(
                item,
                turn_id=turn_id,
                authoritative=True,
            )
            return [completed_entry] if completed_entry else []
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
        if text:
            return [{"role": "error", "text": text, "append": False, "turn_id": turn_id}]
        if method == "turn/completed":
            turn = params.get("turn")
            items = turn.get("items") if isinstance(turn, dict) else None
            if isinstance(items, list):
                for item in reversed(items):
                    if not isinstance(item, dict):
                        continue
                    phase = re.sub(r"[_-]", "", str(item.get("phase") or "")).lower()
                    if phase not in {"", "finalanswer"}:
                        continue
                    fallback_entry = app_server_agent_message_entry(
                        item,
                        turn_id=turn_id,
                        authoritative=True,
                    )
                    if fallback_entry:
                        fallback_entry["completion_fallback"] = True
                        return [fallback_entry]
        return []
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


def rewrite_service_tier_body(
    body: bytes | None, *, fast_enabled: bool
) -> tuple[bytes | None, str | None, bool]:
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
            "inputTokens",
            "output_tokens",
            "outputTokens",
            "total_tokens",
            "totalTokens",
            "prompt_tokens",
            "completion_tokens",
        )
    )
    if not has_usage_key:
        return None
    input_tokens = int_value(
        value.get("input_tokens", value.get("inputTokens", value.get("prompt_tokens")))
    )
    output_tokens = int_value(
        value.get("output_tokens", value.get("outputTokens", value.get("completion_tokens")))
    )
    cached_input_tokens = int_value(
        value.get("cached_input_tokens", value.get("cachedInputTokens"))
    )
    cache_write_input_tokens = int_value(
        value.get("cache_write_input_tokens", value.get("cacheWriteInputTokens"))
    )
    reasoning_output_tokens = int_value(
        value.get("reasoning_output_tokens", value.get("reasoningOutputTokens"))
    )
    input_details = value.get("input_tokens_details")
    if isinstance(input_details, dict):
        cached_input_tokens = max(
            cached_input_tokens, int_value(input_details.get("cached_tokens"))
        )
    output_details = value.get("output_tokens_details")
    if isinstance(output_details, dict):
        reasoning_output_tokens = max(
            reasoning_output_tokens,
            int_value(output_details.get("reasoning_tokens")),
        )
    total_tokens = int_value(value.get("total_tokens", value.get("totalTokens")))
    if total_tokens <= 0:
        total_tokens = input_tokens + output_tokens
    return {
        "input_tokens": input_tokens,
        "cached_input_tokens": cached_input_tokens,
        "cache_write_input_tokens": cache_write_input_tokens,
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
        if isinstance(status, str) and status.lower() in ANALYTICS_TURN_TERMINAL_STATUSES:
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
        ids.add(normalize_rate_limit_id(name[2 : -len(suffix)]))
    return sorted(ids, key=lambda item: (item != "codex", item))


def rate_limit_window_from_headers(
    headers: Any, prefix: str, window_name: str
) -> dict[str, Any] | None:
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


def normalize_rate_limit_reset_credits_summary(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    raw_count = value.get("available_count", value.get("availableCount"))
    if isinstance(raw_count, bool):
        return None
    if isinstance(raw_count, int):
        summary: dict[str, Any] = {"available_count": max(0, raw_count)}
        details = available_rate_limit_reset_credit_details(value)
        if details:
            summary["credits"] = details
        return summary
    if isinstance(raw_count, str):
        try:
            summary = {"available_count": max(0, int(raw_count))}
            details = available_rate_limit_reset_credit_details(value)
            if details:
                summary["credits"] = details
            return summary
        except ValueError:
            return None
    return None


def reset_credit_datetime_iso(value: Any) -> str:
    """Normalize a documented reset-credit timestamp for browser display."""
    moment = parse_reset_datetime(value)
    if moment is None:
        return ""
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def available_rate_limit_reset_credit_details(value: Any) -> list[dict[str, str]]:
    """Return selectable available credits without exposing unrelated fields."""
    if not isinstance(value, dict):
        return []
    raw_credits = value.get("credits")
    if not isinstance(raw_credits, list):
        return []
    credits: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw_credit in raw_credits:
        if not isinstance(raw_credit, dict):
            continue
        if str(raw_credit.get("status") or "").lower() != "available":
            continue
        credit_id = raw_credit.get("id")
        if not isinstance(credit_id, str):
            continue
        credit_id = credit_id.strip()
        if not credit_id or len(credit_id) > 512 or credit_id in seen:
            continue
        seen.add(credit_id)
        credits.append(
            {
                "id": credit_id,
                "issued_at": reset_credit_datetime_iso(raw_credit.get("grantedAt")),
                "expires_at": reset_credit_datetime_iso(raw_credit.get("expiresAt")),
            }
        )
    return credits


def selected_rate_limit_reset_credit_id(value: Any, requested_credit_id: str | None) -> str | None:
    """Validate an explicit UI choice, otherwise preserve automatic selection.

    A no-choice request intentionally uses the credit with the nearest known
    expiry only when the app server supplied a complete list.  If it did not,
    the app server remains responsible for selecting the credit.
    """
    requested = str(requested_credit_id or "").strip()
    if not requested:
        return preferred_rate_limit_reset_credit_id(value)
    available = {detail["id"] for detail in available_rate_limit_reset_credit_details(value)}
    if requested not in available:
        raise StoreError(
            "the selected reset credit is no longer available; refresh quota and choose again"
        )
    return requested


def preferred_rate_limit_reset_credit_id(value: Any) -> str | None:
    """Select the soonest-expiring credit only when Codex returned a complete list.

    Codex may return only the available count or cap the list of detail rows. In
    either case selecting an explicit id could skip an unseen, sooner-expiring
    credit, so the backend remains responsible for choosing the credit.
    """
    normalized = normalize_rate_limit_reset_credits_summary(value)
    if normalized is None:
        return None
    available_count = normalized["available_count"]
    details = value.get("credits") if isinstance(value, dict) else None
    if not isinstance(details, list) or len(details) != available_count:
        return None

    candidates: list[tuple[int, float, float, str]] = []
    for detail in details:
        if not isinstance(detail, dict) or str(detail.get("status") or "").lower() != "available":
            return None
        credit_id = detail.get("id")
        granted_at = detail.get("grantedAt")
        expires_at = detail.get("expiresAt")
        if not isinstance(credit_id, str) or not credit_id:
            return None
        granted_moment = parse_reset_datetime(granted_at)
        expires_moment = parse_reset_datetime(expires_at)
        if granted_moment is None:
            return None
        if expires_at is not None and expires_moment is None:
            return None
        # Expiring credits take precedence; then use grant time and id as stable tie-breakers.
        candidates.append(
            (
                1 if expires_moment is None else 0,
                expires_moment.timestamp() if expires_moment is not None else 0,
                granted_moment.timestamp(),
                credit_id,
            )
        )

    return min(candidates)[3] if candidates else None


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
    spend_control_reached = snapshot.get(
        "spend_control_reached",
        snapshot.get("spendControlReached"),
    )
    if isinstance(spend_control_reached, bool):
        rate_limit["spend_control_reached"] = spend_control_reached
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
                "limit_name": str(
                    snapshot.get("limit_name") or snapshot.get("limitName") or limit_id
                ),
                "metered_feature": limit_id,
                "rate_limit": rate_limit,
            }
        ]
    return payload


def usage_payload_from_app_server_rate_limits_response(
    value: Any,
) -> dict[str, Any] | None:
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
            "spend_control_reached",
            "spendControlReached",
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
        merged["credits"] = (
            {**credits, **update["credits"]}
            if isinstance(credits, dict)
            else dict(update["credits"])
        )
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
    if rate_limit.get("spend_control_reached") is True:
        return "spend control reached"
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


def quota_payload_reset_credit_details(payload: Any) -> list[dict[str, str]]:
    if not isinstance(payload, dict):
        return []
    summary = payload.get("rate_limit_reset_credits")
    if not isinstance(summary, dict):
        return []
    raw_details = summary.get("credits")
    if not isinstance(raw_details, list):
        return []
    details: list[dict[str, str]] = []
    for raw_detail in raw_details:
        if not isinstance(raw_detail, dict):
            continue
        credit_id = raw_detail.get("id")
        if not isinstance(credit_id, str) or not credit_id or len(credit_id) > 512:
            continue
        details.append(
            {
                "id": credit_id,
                "issued_at": str(raw_detail.get("issued_at") or ""),
                "expires_at": str(raw_detail.get("expires_at") or ""),
            }
        )
    return details


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
    if count <= 0 or not profile:
        return ""
    escaped_profile = html.escape(profile)
    label = f"Reset credit: {count}" if count == 1 else f"Reset credits: {count}"
    credits_json = html.escape(json.dumps(quota_payload_reset_credit_details(payload)), quote=True)
    return f"""
      <form method="post" action="/api/consume-reset-credit" class="reset-credit-form" data-action="consume_reset_credit" data-profile="{escaped_profile}" data-reset-credits="{credits_json}">
        <input type="hidden" name="profile" value="{escaped_profile}">
        <input type="hidden" name="credit_id" value="">
        <button class="quota-reset-credit-pill" title="Choose a reset credit to use">{html.escape(label)}</button>
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
            if not isinstance(current_value, (int, float)) or not isinstance(
                previous_value, (int, float)
            ):
                continue
            if (
                float(current_value) - float(previous_value)
                >= RESET_CREDIT_CONFIRMATION_DELTA_PERCENT
            ):
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
        error_at = usage_entry_datetime(entry, "error_at") or usage_entry_datetime(
            entry, "fetched_at"
        )
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
    if rate_limit.get("spend_control_reached") is True:
        return "Spend control", "exhausted"
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

    if rate_limit.get("spend_control_reached") is True:
        primary_style = primary_percent if primary_percent is not None else 0.0
        weekly_style = weekly_percent if weekly_percent is not None else primary_style
        weekly_text = quota_percent_text(weekly_percent)
        return {
            "special": "spend-control",
            "primary_reset_text": "Spend control reached",
            "weekly_status": quota_status_text(weekly_label, secondary),
            "primary_style": primary_style,
            "weekly_style": weekly_style,
            "primary_text": "Blocked",
            "weekly_text": weekly_text,
            "primary_empty": "" if primary_style > 0 else " empty",
            "aria": "Quota blocked because the account spend control was reached",
        }

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
            f"{primary_label} not enforced"
            if primary_not_enforced
            else f"{primary_label} {primary_text}"
            if primary_text
            else "",
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
    special = str(context.get("special") or "")
    special_class = f" {html.escape(special)}" if special else ""
    if context.get("count_html"):
        return f"""
          <div class="quota-title{special_class}">
            <span class="quota-horizon weekly"></span>
            <span class="quota-bucket-name" title="{html.escape(title)}">{html.escape(name)}</span>
            <span class="quota-horizon primary"></span>
          </div>
        """
    weekly_status = str(context.get("weekly_status") or "")
    primary_status = str(context.get("primary_reset_text") or "")
    primary_class = (
        "quota-horizon primary not-enforced"
        if context.get("primary_not_enforced")
        else "quota-horizon primary"
    )
    return f"""
      <div class="quota-title{special_class}">
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
    primary_label_class = (
        "quota-primary-label-outside not-enforced"
        if primary_not_enforced
        else "quota-primary-label-outside"
    )
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


def quota_bucket_for_model_from_rows(
    rows: list[dict[str, Any]], model: str
) -> dict[str, Any] | None:
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
    primary_class = (
        "control-compact-quota-primary not-enforced"
        if primary_not_enforced
        else "control-compact-quota-primary"
    )
    return f"""
      <span class="control-compact-quota{special_class}{secondary_class}" title="{html.escape(aria or title)}">
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


def compact_quota_payload(
    entry: dict[str, Any] | None,
    model: str | None = None,
) -> dict[str, Any]:
    """Return compact quota data for the browser without pre-rendered HTML."""
    data: dict[str, Any] = {"buckets": [], "state": None}
    if not isinstance(entry, dict):
        return data
    payload = entry.get("payload")
    if not isinstance(payload, dict):
        error = entry.get("error")
        if error and (state := usage_payload_state(error)):
            data["state"] = state
        return data
    buckets = [
        item
        for item in (
            quota_bucket_payload(bucket) for bucket in compact_quota_buckets(payload, model)
        )
        if item
    ]
    if buckets:
        data["buckets"] = buckets
    elif state := usage_payload_state(payload):
        data["state"] = state
    return data


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
    if not profile:
        return '<span class="quota-refresh-spacer"></span>'
    escaped_profile = html.escape(profile)
    return f"""
      <form method="post" action="/api/refresh-quota" class="quota-refresh-form" data-action="refresh_quota" data-profile="{escaped_profile}">
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
        error_html = f'<div class="quota-refresh-error{error_class}">Last refresh failed: {html.escape(message)}</div>'
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
            "message": str(
                reset_credit.get("message") or "Reset-credit use is temporarily disabled."
            ),
            "disabled": True,
        }
    count = quota_payload_reset_credit_count(payload)
    if count <= 0:
        return None
    return {
        "label": f"Reset credit: {count}" if count == 1 else f"Reset credits: {count}",
        "message": "Choose a reset credit to use for this Codex CLI profile.",
        "disabled": False,
        "count": count,
        "credits": quota_payload_reset_credit_details(payload),
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

    buckets = [
        item
        for item in (quota_bucket_payload(bucket) for bucket in quota_bucket_rows(payload))
        if item
    ]
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
    timestamp = auth_health_time_label(
        health.get("error_at") or health.get("last_refresh_failed_at")
    )
    suffix = f" ({timestamp})" if timestamp else ""
    label = "Login required" if status == "login_required" else "Auth refresh failed"
    return f"""
      <div class="auth-health {html.escape(status)}" title="{html.escape(message)}">
        <strong>{html.escape(label)}</strong>{html.escape(suffix)}
      </div>
    """


def render_login_status_html(
    status: Any, profile: str | None = None, token: str | None = None
) -> str:
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
    if state in LOGIN_ACTIVE_STATUSES and profile:
        escaped_profile = html.escape(profile)
        cancel_html = f"""
          <form method="post" action="/api/login" class="login-cancel-form" data-action="cancel_login" data-profile="{escaped_profile}">
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
    detail_html = f'<div class="login-detail">{html.escape(detail)}</div>' if detail else ""
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
        # Browser controls use an ephemeral, process-local session. The durable
        # proxy capability remains available to the launcher and CLI, but is
        # never rendered into dashboard HTML or JavaScript.
        self.ui_session_token = secrets.token_urlsafe(32)
        # Remote groundwork stays inert during normal local-only operation.
        # In particular, normal daemon startup creates neither a Remote Agent
        # capability nor remote credential material on disk.
        self.remote_runtime_lock = threading.Lock()
        self.remote_secret: bytes | None = None
        self.remote_cursor_codec: RemoteCursorCodec | None = None
        self.remote_devices: RemoteDeviceRegistry | None = None
        self.remote_state: RemoteStateSynchronizer | None = None
        self.remote_actions: RemoteActionCache | None = None
        self.remote_control_leases = RemoteControlLeases()
        self.remote_action_locks: dict[str, threading.Lock] = {}
        self.remote_action_locks_lock = threading.Lock()
        self.remote_agent_api: LocalRemoteAgentSocket | None = None
        self.connector_hub_lock = threading.Lock()
        self.connector_hub: LocalConnectorHub | None = None
        self.active_requests: dict[int, dict[str, Any]] = {}
        self.active_websockets: dict[int, dict[str, Any]] = {}
        self.active_lock = threading.Lock()
        self.permission_condition = threading.Condition()
        self.pending_permissions: dict[str, dict[str, Any]] = {}
        self.resolved_permissions: dict[str, float] = {}
        self.permission_routes: dict[str, str] = {}
        self.ui_client_count = 0
        self.next_request_id = 0
        self.next_websocket_id = 0
        self.observed_sessions: dict[str, dict[str, Any]] = {}
        self.control_transcripts: dict[str, list[dict[str, Any]]] = {}
        self.provider_session_readers: dict[str, ClaudeSessionReader | GrokSessionReader] = {}
        self.provider_session_readers_lock = threading.Lock()
        self.provider_session_last_refresh_monotonic = 0.0
        self.provider_identity_cache: dict[str, dict[str, Any]] = {}
        self.provider_identity_cache_lock = threading.Lock()
        self.control_history_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
        self.control_history_cache_lock = threading.Lock()
        self.control_history_inflight: dict[str, threading.Event] = {}
        self.profile_settings: dict[str, dict[str, Any]] = self.load_profile_settings()
        self.profile_settings_lock = threading.Lock()
        self.pinned_sessions: dict[str, str] = self.load_pinned_sessions()
        self.session_tab_order: dict[str, int] = self.load_session_tab_order()
        self.next_session_tab_order = (
            (max(self.session_tab_order.values()) + 1) if self.session_tab_order else 0
        )
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
        self.prune_orphaned_launcher_sockets()

    def log_message(self, format: str, *args: Any) -> None:
        message = format % args
        message = redact_proxy_token(message, self.proxy_token)
        try:
            sys.stderr.write(
                "%s %s\n"
                % (
                    datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    message,
                )
            )
        except OSError:
            # Logging must not interrupt cleanup when storage is unavailable.
            pass

    def prune_orphaned_launcher_sockets(self) -> None:
        """Remove dead PTY-control socket files left behind by interrupted CLIs.

        Each managed launcher owns a socket named with its own PID.  A Unix
        socket pathname can survive an interrupted process, causing needless
        filesystem growth and making an old session look controllable after a
        daemon restart.  Never touch a socket whose owning launcher is still
        running; a live launcher will re-register on its five-second
        heartbeat.
        """
        try:
            candidates = tuple(self.paths.launchers.glob("provision-*.sock"))
        except OSError:
            return
        for path in candidates:
            if not path.is_socket():
                continue
            match = re.fullmatch(r"provision-(\d+)-[0-9a-f]+\.sock", path.name)
            if match is None:
                continue
            try:
                launcher_pid = int(match.group(1))
            except ValueError:
                continue
            if process_is_running(launcher_pid):
                continue
            try:
                path.unlink()
            except OSError:
                continue

    def prune_stale_observed_sessions_locked(
        self,
        *,
        now: float,
        live_ui_launcher_pids: set[int],
    ) -> list[str]:
        """Evict departed live-session records while retaining durable pins.

        Pins are separate routing preferences and deliberately survive this
        cleanup.  The next request or PTY heartbeat recreates the lightweight
        observation record if that project becomes active again.
        """
        stale_keys: list[str] = []
        for key, record in self.observed_sessions.items():
            last_seen = float(record.get("last_seen_monotonic") or 0.0)
            if now - last_seen < OBSERVED_SESSION_RETENTION_SECONDS:
                continue
            control_path = str(record.get("control_path") or "")
            control_available = bool(control_path and Path(control_path).exists())
            ui_launcher_pid = record.get("ui_launcher_pid")
            ui_launcher_running = (
                isinstance(ui_launcher_pid, int) and ui_launcher_pid in live_ui_launcher_pids
            )
            provider_pid = record.get("provider_pid")
            provider_running = process_is_running(
                provider_pid if isinstance(provider_pid, int) else None
            )
            has_request = any(
                request.get("session_key") == key for request in self.active_requests.values()
            )
            has_tunnel = any(
                tunnel.get("session_key") == key for tunnel in self.active_websockets.values()
            )
            if (
                control_available
                or ui_launcher_running
                or provider_running
                or has_request
                or has_tunnel
            ):
                continue
            stale_keys.append(key)

        for key in stale_keys:
            self.observed_sessions.pop(key, None)
            self.control_transcripts.pop(key, None)
            self.session_tab_order.pop(key, None)
        if stale_keys:
            self.save_session_tab_order_locked()
        return stale_keys

    def ensure_remote_runtime(self) -> None:
        """Lazily allocate dormant local state for a future Remote Agent."""
        if self.remote_state is not None:
            return
        with self.remote_runtime_lock:
            if self.remote_state is not None:
                return
            secret = self.store.remote_secret()
            self.remote_secret = secret
            self.remote_cursor_codec = RemoteCursorCodec(secret)
            self.remote_devices = RemoteDeviceRegistry(
                self.paths.remote_devices, self.paths.remote_audit
            )
            self.remote_state = RemoteStateSynchronizer()
            self.remote_actions = RemoteActionCache(self.paths.remote_action_state)

    def remote_runtime(
        self,
    ) -> tuple[
        bytes,
        RemoteCursorCodec,
        RemoteDeviceRegistry,
        RemoteStateSynchronizer,
        RemoteActionCache,
    ]:
        self.ensure_remote_runtime()
        assert self.remote_secret is not None
        assert self.remote_cursor_codec is not None
        assert self.remote_devices is not None
        assert self.remote_state is not None
        assert self.remote_actions is not None
        return (
            self.remote_secret,
            self.remote_cursor_codec,
            self.remote_devices,
            self.remote_state,
            self.remote_actions,
        )

    def start_remote_agent_api(self) -> None:
        self.ensure_remote_runtime()
        with self.remote_runtime_lock:
            if self.remote_agent_api is None:
                self.remote_agent_api = LocalRemoteAgentSocket(
                    self.paths.remote_agent_socket,
                    self.store.remote_agent_token(),
                    self.handle_remote_agent_request,
                )
            agent_api = self.remote_agent_api
        agent_api.start()

    def stop_remote_agent_api(self) -> None:
        with self.remote_runtime_lock:
            agent_api = self.remote_agent_api
        if agent_api is not None:
            agent_api.stop()

    @staticmethod
    def connector_lanes() -> list[str]:
        return ["provision.echo/v1", "provision.remote/v1", "provision.remote-admin/v1"]

    def connector_status(self) -> dict[str, Any]:
        with self.connector_hub_lock:
            hub = self.connector_hub
        return {
            "enabled": bool(hub and hub.running()),
            "abi": CONNECTOR_ABI_VERSION,
            "lanes": self.connector_lanes(),
        }

    def connector_echo_frame(
        self,
        _connector_id: str,
        _link_id: str,
        _lane: str,
        payload: bytes,
    ) -> bytes:
        """Reference lane used to validate a connector without network access."""
        return payload

    def connector_remote_frame(
        self,
        _connector_id: str,
        _link_id: str,
        _lane: str,
        payload: bytes,
    ) -> bytes:
        """Adapt the bounded Remote service to the generic Connector ABI.

        The connector is a trusted *local* process.  Network peer identity,
        encryption, and pairing proof must be completed by that process before
        it submits an already-authenticated device request here.
        """
        try:
            request = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return compact_json_bytes({"ok": False, "error": "invalid remote connector frame"})
        if not isinstance(request, dict) or "token" in request:
            return compact_json_bytes({"ok": False, "error": "invalid remote connector frame"})
        try:
            result = self.handle_remote_agent_request(request)
        except RemoteError as exc:
            return compact_json_bytes({"ok": False, "error": str(exc)})
        return compact_json_bytes({"ok": True, "result": result})

    def connector_remote_admin_frame(
        self,
        _connector_id: str,
        _link_id: str,
        _lane: str,
        payload: bytes,
    ) -> bytes:
        """Handle host-local paired-device lifecycle requests.

        This lane is for an explicitly trusted connector's host-side pairing
        UI or a local Provision command.  It is intentionally distinct from
        the remote request lane so a connector does not accidentally forward
        device administration requests from an untrusted network peer.
        """
        try:
            request = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return compact_json_bytes({"ok": False, "error": "invalid remote connector frame"})
        if not isinstance(request, dict) or "token" in request:
            return compact_json_bytes({"ok": False, "error": "invalid remote connector frame"})
        try:
            result = self.handle_remote_admin_request(request)
        except RemoteError as exc:
            return compact_json_bytes({"ok": False, "error": str(exc)})
        return compact_json_bytes({"ok": True, "result": result})

    def start_connector_hub(self) -> dict[str, Any]:
        """Enable only the local Connector ABI socket; never a network listener."""
        with self.connector_hub_lock:
            if self.connector_hub is None:
                self.connector_hub = LocalConnectorHub(
                    self.paths.connector_socket,
                    self.store.connector_token(),
                    {
                        "provision.echo/v1": self.connector_echo_frame,
                        "provision.remote/v1": self.connector_remote_frame,
                        "provision.remote-admin/v1": self.connector_remote_admin_frame,
                    },
                )
            hub = self.connector_hub
        try:
            hub.start()
        except ConnectorError as exc:
            raise StoreError(str(exc)) from exc
        return self.connector_status()

    def stop_connector_hub(self) -> dict[str, Any]:
        with self.connector_hub_lock:
            hub = self.connector_hub
            self.connector_hub = None
        if hub is not None:
            hub.stop()
        return self.connector_status()

    def server_close(self) -> None:
        self.release_permission_requests()
        self.stop_connector_hub()
        self.stop_remote_agent_api()
        super().server_close()

    @staticmethod
    def permission_bridge_supported(record: dict[str, Any]) -> bool:
        provider = str(record.get("provider") or "codex")
        bridge = str(record.get("permission_bridge") or "").split(":", 1)[0]
        return (provider, bridge) in {
            ("claude", "claude-permission-hook-v1"),
            ("codex", "codex-permission-hook-v1"),
            ("grok", "grok-acp-permission-v1"),
        }

    @classmethod
    def permission_bridge_available(cls, record: dict[str, Any]) -> bool:
        control_path = str(record.get("control_path") or "")
        return bool(
            cls.permission_bridge_supported(record) and control_path and Path(control_path).exists()
        )

    def permission_bridge_state(self, session_key: str) -> tuple[bool, bool, str]:
        key = normalize_session_key(session_key)
        with self.active_lock:
            record = self.observed_sessions.get(key)
            if not isinstance(record, dict):
                return False, False, "Session is no longer available."
            supported = self.permission_bridge_available(record)
            provider = str(record.get("provider") or "codex")
        with self.permission_condition:
            enabled = self.permission_routes.get(key) == str(record.get("permission_bridge") or "")
        if supported:
            reason = "Browser approval is available for this managed session."
        elif provider == "grok":
            reason = (
                "Grok terminal sessions do not expose safe synchronous permission decisions yet."
            )
        elif provider == "codex":
            reason = "Codex terminal sessions require an app-server or explicit hook adapter."
        else:
            reason = "Restart this managed session to enable browser approvals."
        return supported, bool(supported and enabled), reason

    def set_permission_routing(self, session_key: str, enabled: bool) -> None:
        key = normalize_session_key(session_key)
        with self.active_lock:
            record = self.observed_sessions.get(key)
            if not isinstance(record, dict):
                raise StoreError("unknown session")
            supported = self.permission_bridge_available(record)
        if enabled and not supported:
            raise StoreError("browser approvals are unavailable for this session")
        with self.permission_condition:
            if enabled:
                self.permission_routes[key] = str(record.get("permission_bridge") or "")
            else:
                self.permission_routes.pop(key, None)
                self._release_permission_requests_locked(session_key=key)
            self.permission_condition.notify_all()
        self.mark_ui_dirty("permissions")

    def ui_client_connected(self) -> None:
        with self.permission_condition:
            self.ui_client_count += 1
        self.mark_ui_dirty("permissions")

    def ui_client_disconnected(self) -> None:
        with self.permission_condition:
            self.ui_client_count = max(0, self.ui_client_count - 1)
            if self.ui_client_count == 0:
                self._release_permission_requests_locked()
            self.permission_condition.notify_all()
        self.mark_ui_dirty("permissions")

    def _expire_permission_state_locked(self) -> bool:
        now = time.monotonic()
        changed = False
        for request in self.pending_permissions.values():
            if not request.get("decision") and now >= float(request.get("deadline") or 0.0):
                request["decision"] = "terminal"
                changed = True
        expired = [
            request_id
            for request_id, resolved_at in self.resolved_permissions.items()
            if now - resolved_at >= PERMISSION_RESOLVED_TTL_SECONDS
        ]
        for request_id in expired:
            self.resolved_permissions.pop(request_id, None)
        return changed

    def _release_permission_requests_locked(self, session_key: str = "") -> bool:
        changed = False
        for request in self.pending_permissions.values():
            if session_key and request.get("session_key") != session_key:
                continue
            if not request.get("decision"):
                request["decision"] = "terminal"
                changed = True
        return changed

    def release_permission_requests(self, session_key: str = "") -> None:
        with self.permission_condition:
            changed = self._release_permission_requests_locked(session_key=session_key)
            if session_key:
                self.permission_routes.pop(session_key, None)
            self.permission_condition.notify_all()
        if changed:
            self.mark_ui_dirty("permissions")

    def permission_state_snapshot(self) -> dict[str, Any]:
        with self.permission_condition:
            self._expire_permission_state_locked()
            pending = [
                {
                    key: value
                    for key, value in request.items()
                    if key
                    in {
                        "request_id",
                        "session_key",
                        "provider",
                        "workspace",
                        "native_session_id",
                        "turn_id",
                        "tool_name",
                        "category",
                        "reason",
                        "preview",
                        "requested_at",
                        "expires_at",
                    }
                }
                for request in self.pending_permissions.values()
                if not request.get("decision")
            ]
            clients = self.ui_client_count
            self.permission_condition.notify_all()
        pending.sort(key=lambda item: str(item.get("requested_at") or ""))
        return {"pending": pending, "browser_clients": clients}

    def request_permission(
        self,
        session_key: str,
        provider: str,
        request: dict[str, Any],
        *,
        timeout: float = PERMISSION_REQUEST_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        key = normalize_session_key(session_key)
        try:
            provider = canonical_provider(provider)
        except ProviderError:
            return {"ok": True, "decision": "terminal"}
        with self.active_lock:
            record = self.observed_sessions.get(key)
            if (
                not isinstance(record, dict)
                or str(record.get("provider") or "codex") != provider
                or not self.permission_bridge_supported(record)
            ):
                return {"ok": True, "decision": "terminal"}
            workspace = bounded_permission_text(
                record.get("name") or session_display_name(key), PERMISSION_PATH_MAX_CHARS
            )
            permission_bridge = str(record.get("permission_bridge") or "")
        now = datetime.now().astimezone()
        timeout = max(0.01, min(float(timeout), PERMISSION_REQUEST_TIMEOUT_SECONDS))
        deadline = time.monotonic() + timeout
        request_id = secrets.token_urlsafe(24)
        pending = {
            "request_id": request_id,
            "session_key": key,
            "provider": provider,
            "workspace": workspace,
            "native_session_id": bounded_permission_text(
                request.get("native_session_id"), PERMISSION_ID_MAX_CHARS
            ),
            "turn_id": bounded_permission_text(request.get("turn_id"), PERMISSION_ID_MAX_CHARS),
            "tool_name": bounded_permission_text(request.get("tool_name") or "Tool", 160),
            "category": bounded_permission_text(request.get("category") or "tool", 40),
            "reason": bounded_permission_text(request.get("reason"), PERMISSION_REASON_MAX_CHARS),
            "preview": bounded_permission_text(
                request.get("preview"), PERMISSION_PREVIEW_MAX_CHARS
            ),
            "requested_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=timeout)).isoformat(),
            "deadline": deadline,
            "decision": "",
            "permission_bridge": permission_bridge,
        }
        with self.permission_condition:
            self._expire_permission_state_locked()
            if (
                self.permission_routes.get(key) != permission_bridge
                or self.ui_client_count <= 0
                or len(self.pending_permissions) >= PERMISSION_MAX_PENDING
            ):
                return {"ok": True, "decision": "terminal"}
            self.pending_permissions[request_id] = pending
            self.permission_condition.notify_all()
        self.mark_ui_dirty("permissions")
        with self.permission_condition:
            while not pending["decision"]:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    pending["decision"] = "terminal"
                    break
                self.permission_condition.wait(timeout=remaining)
                if (
                    self.permission_routes.get(key) != permission_bridge
                    or self.ui_client_count <= 0
                ):
                    pending["decision"] = "terminal"
            decision = str(pending.get("decision") or "terminal")
            self.pending_permissions.pop(request_id, None)
            self.resolved_permissions[request_id] = time.monotonic()
            if len(self.resolved_permissions) > PERMISSION_MAX_RESOLVED:
                oldest = sorted(self.resolved_permissions, key=self.resolved_permissions.get)
                for old_id in oldest[: len(self.resolved_permissions) - PERMISSION_MAX_RESOLVED]:
                    self.resolved_permissions.pop(old_id, None)
        self.mark_ui_dirty("permissions")
        return {"ok": True, "decision": decision}

    def resolve_permission(self, request_id: str, session_key: str, decision: str) -> None:
        request_id = bounded_permission_text(request_id, PERMISSION_ID_MAX_CHARS)
        key = normalize_session_key(session_key)
        if decision not in {"allow", "deny", "terminal"}:
            raise StoreError("unsupported permission decision")
        with self.permission_condition:
            self._expire_permission_state_locked()
            request = self.pending_permissions.get(request_id)
            if request_id in self.resolved_permissions or not isinstance(request, dict):
                raise StoreError("permission request is no longer pending")
            if request.get("session_key") != key:
                raise StoreError("permission request does not belong to this session")
            if request.get("decision"):
                raise StoreError("permission request is no longer pending")
            request["decision"] = decision
            self.permission_condition.notify_all()
        self.mark_ui_dirty("permissions")

    def handle_remote_agent_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Dispatch the typed Unix-socket contract used by a future agent.

        The socket authenticates only the *local* process.  Device identity and
        capability checks below remain mandatory so this API cannot substitute
        for transport pairing when a remote transport is eventually added.
        """
        operation = request.get("operation")
        if not isinstance(operation, str):
            raise RemoteError("local remote-agent operation is required")
        device_id = request.get("device_id")
        if not isinstance(device_id, str):
            raise RemoteError("remote device ID is required")
        if operation == "device_enroll":
            if set(request) != {"operation", "device_id", "identity_fingerprint"}:
                raise RemoteError("invalid remote device enrollment request")
            identity_fingerprint = request.get("identity_fingerprint")
            if not isinstance(identity_fingerprint, str):
                raise RemoteError("remote device identity fingerprint is required")
            # The connector must have completed its own verified pairing before
            # it reaches this point. A newly enrolled device remains read-only
            # until a local host-side grant changes its capabilities.
            return self.enroll_remote_device(device_id, identity_fingerprint)
        if operation == "state":
            since = request.get("since_revision")
            cursor = request.get("cursor")
            if since is not None and (isinstance(since, bool) or not isinstance(since, int)):
                raise RemoteError("invalid remote revision")
            if cursor is not None and not isinstance(cursor, str):
                raise RemoteError("invalid remote session cursor")
            return self.remote_state_payload(
                device_id,
                since_revision=since,
                cursor=cursor or "",
            )
        session_id = request.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            raise RemoteError("remote session ID is required")
        if operation == "discussion":
            cursor = request.get("cursor")
            if cursor is not None and not isinstance(cursor, str):
                raise RemoteError("invalid remote discussion cursor")
            return self.remote_discussion_payload(device_id, session_id, cursor=cursor or "")
        if operation == "message_expand":
            message_id = request.get("message_id")
            cursor = request.get("cursor")
            if not isinstance(message_id, str) or not message_id:
                raise RemoteError("remote message ID is required")
            if cursor is not None and not isinstance(cursor, str):
                raise RemoteError("invalid remote expansion cursor")
            return self.remote_message_expand_payload(
                device_id,
                session_id,
                message_id,
                cursor=cursor or "",
            )
        if operation == "action":
            expected_revision = request.get("expected_revision")
            expected_turn_id = request.get("expected_turn_id")
            idempotency_key = request.get("idempotency_key")
            expires_at = request.get("expires_at")
            action = request.get("action")
            prompt = request.get("prompt", "")
            if isinstance(expected_revision, bool) or not isinstance(expected_revision, int):
                raise RemoteError("remote action revision is required")
            if not isinstance(expected_turn_id, str):
                raise RemoteError("invalid remote action turn")
            if not isinstance(idempotency_key, str) or not isinstance(expires_at, str):
                raise RemoteError("remote action idempotency key and expiry are required")
            if not isinstance(action, str) or not isinstance(prompt, str):
                raise RemoteError("invalid remote action")
            return self.perform_remote_action(
                device_id,
                action=action,
                session_id=session_id,
                expected_revision=expected_revision,
                expected_turn_id=expected_turn_id,
                idempotency_key=idempotency_key,
                expires_at=expires_at,
                prompt=prompt,
            )
        raise RemoteError("unsupported local remote-agent operation")

    def handle_remote_admin_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Manage paired devices from the host-local Connector Admin lane."""
        operation = request.get("operation")
        if operation == "device_list":
            if set(request) != {"operation"}:
                raise RemoteError("invalid remote device list request")
            _secret, _cursor_codec, devices, _state, _actions = self.remote_runtime()
            return {"devices": devices.list_devices()}
        if operation == "device_enroll":
            if set(request) != {"operation", "device_id", "identity_fingerprint"}:
                raise RemoteError("invalid remote device enrollment request")
            device_id = request.get("device_id")
            identity_fingerprint = request.get("identity_fingerprint")
            if not isinstance(device_id, str) or not isinstance(identity_fingerprint, str):
                raise RemoteError("remote device ID and identity fingerprint are required")
            return self.enroll_remote_device(device_id, identity_fingerprint)
        if operation == "device_set_capabilities":
            if set(request) != {"operation", "device_id", "capabilities"}:
                raise RemoteError("invalid remote device capability request")
            device_id = request.get("device_id")
            capabilities = request.get("capabilities")
            if not isinstance(device_id, str) or not isinstance(capabilities, list):
                raise RemoteError("remote device ID and capabilities are required")
            _secret, _cursor_codec, devices, _state, _actions = self.remote_runtime()
            result = devices.set_capabilities(device_id, capabilities)
            devices.append_audit(
                event="device_capabilities_updated",
                device_id=str(result.get("device_id") or ""),
                outcome="ok",
            )
            return result
        if operation == "device_revoke":
            if set(request) != {"operation", "device_id"}:
                raise RemoteError("invalid remote device revoke request")
            device_id = request.get("device_id")
            if not isinstance(device_id, str):
                raise RemoteError("remote device ID is required")
            self.revoke_remote_device(device_id)
            return {"device_id": device_id, "revoked": True}
        raise RemoteError("unsupported local remote-admin operation")

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
            reasons = {
                str(reason or "state")
                for version, reason in dirty_log
                if int(version or 0) > revision
            }
            return reasons or {"state"}

    def ui_state_liveness_signature(self) -> tuple[Any, ...]:
        self.refresh_provider_sessions()
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
            provider_rows = tuple(
                sorted(
                    (
                        key,
                        bool(record.get("provider_process_running")),
                        bool(record.get("provider_working")),
                        str(record.get("provider_session_id") or ""),
                    )
                    for key, record in getattr(self, "observed_sessions", {}).items()
                    if str(record.get("provider") or "codex") != "codex"
                )
            )
        return request_rows, tunnel_rows, provider_rows

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
                exit_code = (
                    os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)
                )
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
            self.log_message(
                "UI-launched provision session %s exited with status %s",
                session_key,
                exit_code,
            )
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
            if str(record.get("provider") or "codex") != "codex":
                raise StoreError("the dashboard launcher currently supports Codex sessions only")
            cwd = str(record.get("cwd") or key)
        cwd_path = Path(cwd).expanduser()
        if not cwd_path.is_dir():
            raise StoreError(f"working directory is not available: {cwd}")
        resolved_cwd = str(cwd_path.resolve(strict=False))
        launch_profile = (
            profile
            if profile and self.store.profile_exists(profile)
            else self.control_profile_for_session(key)
        )
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
            has_request = any(
                request.get("session_key") == key for request in self.active_requests.values()
            )
            has_tunnel = any(
                tunnel.get("session_key") == key for tunnel in self.active_websockets.values()
            )
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
        with self.provider_session_readers_lock:
            self.provider_session_readers.pop(key, None)
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
        self.release_permission_requests(key)
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
            if str(record.get("provider") or "codex") != "codex":
                return []
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
            if str(record.get("provider") or "codex") != "codex":
                return []
            cwd = str(record.get("cwd") or session_key)
            observed_turns = self.control_turns_from_transcript(
                self.control_transcript_snapshot(session_key)
            )
        history_turns = self.history_turns_for_cwd(cwd)
        return [
            turn
            for turn in history_turns
            if not any(
                history_turn_duplicates_observed(turn, observed) for observed in observed_turns
            )
        ]

    def history_turn_payload_for_session(self, session_key: str, turn_key: str) -> dict[str, Any]:
        with self.active_lock:
            record = self.observed_sessions.get(session_key)
            if not isinstance(record, dict):
                raise StoreError("unknown session")
            if str(record.get("provider") or "codex") != "codex":
                raise StoreError("native history is not available for this provider")
            cwd = str(record.get("cwd") or session_key)
        payload = codex_history_turn_payload_for_cwd(cwd, turn_key)
        if not payload:
            raise StoreError("historical turn was not found for this session")
        payload["session_key"] = session_key
        return payload

    def control_turn_payload_for_session(
        self,
        session_key: str,
        turn_key: str,
        *,
        before_index: int | None = None,
    ) -> dict[str, Any]:
        """Return one bounded, newest-first page of an observed turn.

        Full Discussion retention is useful locally, but it must not be part of
        every dashboard snapshot.  Older turn material is therefore fetched
        explicitly and bounded even when one turn contains many tool entries.
        """
        with self.active_lock:
            record = self.observed_sessions.get(session_key)
            if not isinstance(record, dict):
                raise StoreError("unknown session")
            transcript = self.control_transcript_snapshot(session_key)
            turn = next(
                (
                    candidate
                    for candidate in self.control_turns_from_transcript(transcript)
                    if str(candidate.get("key") or "") == turn_key
                ),
                None,
            )
        if not isinstance(turn, dict):
            raise StoreError("observed turn was not found for this session")
        start_index = max(0, int(turn.get("start_index") or 0))
        end_index = max(start_index, int(turn.get("end_index") or start_index))
        if before_index is None:
            page_end = end_index
        elif isinstance(before_index, bool) or not isinstance(before_index, int):
            raise StoreError("invalid observed turn cursor")
        else:
            page_end = min(end_index, before_index - 1)
        if page_end < start_index:
            raise StoreError("no older observed discussion is available")

        selected: list[dict[str, Any]] = []
        encoded_size = 2
        for item in reversed(transcript):
            control_index = int(item.get("control_index") or 0)
            if control_index < start_index or control_index > page_end:
                continue
            item_size = len(json.dumps(item, separators=(",", ":")).encode("utf-8"))
            if selected and encoded_size + item_size + 1 > CONTROL_TURN_PAYLOAD_MAX_BYTES:
                break
            selected.append(item)
            encoded_size += item_size + 1
        selected.reverse()
        if not selected:
            raise StoreError("observed turn could not be loaded")
        first_index = int(selected[0].get("control_index") or start_index)
        return {
            "source": "observed",
            "session_key": session_key,
            "turn_key": turn_key,
            "transcript": selected,
            "has_more_before": first_index > start_index,
            "next_before_index": first_index if first_index > start_index else None,
        }

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
            settings["login_error_at"] = (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            )
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
            settings["billing_error_at"] = (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            )
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
            title = str(
                state.get("error")
                or state.get("outcome")
                or "Previous reset-credit attempt did not complete."
            )

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
                state["last_error"] = (
                    "usage endpoint did not confirm the reset before the verification timeout"
                )
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
            return str(state.get("status") or "") in {
                "pending",
                "verifying",
                "unconfirmed",
            }

    def ensure_reset_credit_attempt_allowed(self, profile: str) -> None:
        """Fail before opening an app-server connection when a credit is guarded."""
        if not self.store.profile_exists(profile):
            raise StoreError(f"unknown profile: {profile}")
        with self.reset_credit_state_lock:
            existing = self.normalize_reset_credit_state_locked(profile)
            public = self.reset_credit_public_state_from_state(existing) if existing else {}
            if public.get("blocks"):
                raise ResetCreditGuardError(
                    str(
                        public.get("message") or "Reset credit is already pending for this profile."
                    )
                )

    def begin_reset_credit_attempt(self, profile: str, idempotency_key: str) -> None:
        if not self.store.profile_exists(profile):
            raise StoreError(f"unknown profile: {profile}")
        snapshot = self.usage_cache_snapshot(profile) or {}
        before_payload = snapshot.get("payload")
        now = datetime.now(timezone.utc)
        with self.reset_credit_state_lock:
            existing = self.normalize_reset_credit_state_locked(profile, now=now)
            public = (
                self.reset_credit_public_state_from_state(existing, now=now) if existing else {}
            )
            if public.get("blocks"):
                raise ResetCreditGuardError(
                    str(
                        public.get("message") or "Reset credit is already pending for this profile."
                    )
                )
            state: dict[str, Any] = {
                "status": "pending",
                "idempotency_key": idempotency_key,
                "requested_at": utc_timestamp(now),
                "cooldown_until": utc_timestamp(
                    now + timedelta(seconds=RESET_CREDIT_COOLDOWN_SECONDS)
                ),
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
            state["guard_until"] = utc_timestamp(
                now + timedelta(seconds=RESET_CREDIT_ERROR_GUARD_SECONDS)
            )
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
                state["guard_until"] = utc_timestamp(
                    now + timedelta(seconds=RESET_CREDIT_ERROR_GUARD_SECONDS)
                )
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
            if str(state.get("status") or "") not in {
                "pending",
                "verifying",
                "unconfirmed",
            }:
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
            if str(state.get("status") or "") not in {
                "pending",
                "verifying",
                "unconfirmed",
            }:
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
                self.log_message(
                    "reset-credit verification refresh for profile %s failed: %s",
                    profile,
                    exc,
                )
            if not self.reset_credit_awaiting_usage_confirmation(profile):
                return
            if time.monotonic() - started >= RESET_CREDIT_VERIFY_TIMEOUT_SECONDS:
                with self.reset_credit_state_lock:
                    state = self.normalize_reset_credit_state_locked(profile)
                    if str(state.get("status") or "") in {"pending", "verifying"}:
                        state["status"] = "unconfirmed"
                        state["last_error"] = (
                            "usage endpoint did not confirm the reset before the verification timeout"
                        )
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
            encoded = (
                json.dumps(dict(sorted(known.items(), key=lambda item: item[1])), indent=2) + "\n"
            )
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
                (
                    key
                    for key in observed_keys
                    if key not in self.session_tab_order or key not in normalized_keys
                ),
                key=lambda key: (
                    int(
                        self.session_tab_order.get(
                            key, self.observed_sessions[key].get("tab_order", 0)
                        )
                    ),
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
        provider: str = "codex",
        provider_profile: str | None = None,
        control_path: str | None = None,
        launcher_pid: int | None = None,
        provider_pid: int | None = None,
        provider_state_root: str | None = None,
        permission_bridge: str | None = None,
        pty_managed: bool = False,
        clear_control_path: bool = False,
    ) -> str:
        key = normalize_session_key(cwd)
        if not key:
            return ""
        provider = canonical_provider(provider)
        with self.active_lock:
            self.observe_session_locked(
                key,
                cwd,
                profile,
                provider=provider,
                provider_profile=provider_profile,
                control_path=control_path,
                launcher_pid=launcher_pid,
                provider_pid=provider_pid,
                provider_state_root=provider_state_root,
                permission_bridge=permission_bridge,
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
        provider: str = "codex",
        provider_profile: str | None = None,
        control_path: str | None = None,
        launcher_pid: int | None = None,
        provider_pid: int | None = None,
        provider_state_root: str | None = None,
        permission_bridge: str | None = None,
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
        previous_provider = str(record.get("provider") or "codex")
        previous_provider_profile = str(record.get("provider_profile") or "")
        previous_control_path = str(record.get("control_path") or "")
        previous_pty_managed = bool(record.get("pty_managed"))
        previous_launcher_pid = record.get("launcher_pid")
        previous_provider_pid = record.get("provider_pid")
        previous_provider_state_root = str(record.get("provider_state_root") or "")
        previous_permission_bridge = str(record.get("permission_bridge") or "")
        record["tab_order"] = self.session_tab_order_for_key_locked(key)
        record["cwd"] = cwd
        record["display"] = compact_session_path(cwd)
        record["name"] = session_display_name(cwd)
        record["last_seen_monotonic"] = now
        record["last_seen_at"] = datetime.now().astimezone()
        record["provider"] = provider
        if profile:
            record["last_profile"] = profile
        if provider != "codex":
            record["provider_profile"] = provider_profile or ""
        else:
            record.pop("provider_profile", None)
        if previous_provider != provider:
            for field in (
                "provider_model",
                "permission_bridge",
                "provider_pid",
                "provider_process_running",
                "provider_session_id",
                "provider_state_root",
                "provider_usage",
                "provider_usage_updated_at",
                "provider_working",
            ):
                record.pop(field, None)
            with self.permission_condition:
                self.permission_routes.pop(key, None)
                self._release_permission_requests_locked(session_key=key)
                self.permission_condition.notify_all()
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
        if provider_pid is not None:
            record["provider_pid"] = provider_pid
        elif clear_control_path:
            record.pop("provider_pid", None)
        if provider_state_root:
            record["provider_state_root"] = provider_state_root
        if permission_bridge:
            record["permission_bridge"] = bounded_permission_text(permission_bridge, 80)
        elif clear_control_path:
            record.pop("permission_bridge", None)
        current_permission_bridge = str(record.get("permission_bridge") or "")
        if previous_permission_bridge and previous_permission_bridge != current_permission_bridge:
            with self.permission_condition:
                self.permission_routes.pop(key, None)
                self._release_permission_requests_locked(session_key=key)
                self.permission_condition.notify_all()
        if new_tab_order:
            self.save_session_tab_order_locked()
        state_changed = (
            new_session
            or new_tab_order
            or previous_cwd != str(record.get("cwd") or "")
            or previous_profile != str(record.get("last_profile") or "")
            or previous_provider != str(record.get("provider") or "codex")
            or previous_provider_profile != str(record.get("provider_profile") or "")
            or previous_control_path != str(record.get("control_path") or "")
            or previous_pty_managed != bool(record.get("pty_managed"))
            or previous_launcher_pid != record.get("launcher_pid")
            or previous_provider_pid != record.get("provider_pid")
            or previous_provider_state_root != str(record.get("provider_state_root") or "")
            or previous_permission_bridge != str(record.get("permission_bridge") or "")
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
            if str(record.get("provider") or "codex") != "codex":
                raise StoreError("Codex profile pins apply only to Codex sessions")
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
        now = time.monotonic()
        for request in self.active_requests.values():
            started = request.get("started_monotonic")
            if (
                isinstance(started, (int, float))
                and now - float(started) > STALE_HTTP_REQUEST_SECONDS
            ):
                continue
            if request.get("session_key") == session_key:
                return str(request.get("profile") or "")
        for tunnel in self.active_websockets.values():
            if tunnel.get("session_key") != session_key:
                continue
            if int(tunnel.get("pending_work") or 0) > 0:
                return str(tunnel.get("profile") or "")
            last_data = float(tunnel.get("last_data_activity_monotonic") or 0.0)
            if now - last_data < WEBSOCKET_SWITCH_IDLE_SECONDS:
                return str(tunnel.get("profile") or "")
        return None

    def begin_request(
        self,
        profile: str,
        session_key: str | None = None,
        *,
        turn_work: bool = False,
    ) -> int:
        with self.active_lock:
            self.next_request_id += 1
            request_id = self.next_request_id
            self.active_requests[request_id] = {
                "profile": profile,
                "session_key": session_key,
                "turn_work": bool(turn_work),
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

    def expire_stale_requests_locked(self, now: float | None = None) -> int:
        current = time.monotonic() if now is None else now
        stale_ids = [
            request_id
            for request_id, request in self.active_requests.items()
            if isinstance(request.get("started_monotonic"), (int, float))
            and current - float(request["started_monotonic"]) > STALE_HTTP_REQUEST_SECONDS
        ]
        for request_id in stale_ids:
            self.active_requests.pop(request_id, None)
        return len(stale_ids)

    def expire_stale_requests(self) -> int:
        with self.active_lock:
            expired = self.expire_stale_requests_locked()
        if expired:
            self.log_message("expired %s stale upstream request record(s)", expired)
            self.mark_ui_dirty("request_expire")
        return expired

    def request_count(self, *, blocking_only: bool = False) -> int:
        self.expire_stale_requests()
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
        if re.match(
            r"\s*(?:[-*+]\s+|-\d+\s+|\d+\.\s+|#{1,6}\s+|>\s?|```)", text
        ) and not cls.transcript_line_has_open_markdown_span(existing_line):
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
            self.set_transcript_item_text(
                existing, str(existing.get("role") or "user_pending"), text
            )
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
        session_key: str,
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
            self.record_remote_transcript_change(
                session_key,
                transcript,
                existing,
                replace=True,
            )
            return
        item = {
            "item_id": f"cti_{uuid.uuid4().hex}",
            "ts": now,
            "updated_at": now,
            "role": "context_compaction",
            "turn_id": turn_id,
            "profile": profile,
        }
        self.set_transcript_item_text(item, "context_compaction", text)
        transcript.append(item)
        self.record_remote_transcript_change(
            session_key,
            transcript,
            item,
            replace=False,
        )

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
        tool_status: str = "",
        tool_kind: str = "",
        tool_title: str = "",
        source_item_id: str = "",
        authoritative: bool = False,
        timestamp: str = "",
    ) -> None:
        if role in {"user", "user_pending", "resume", "context_compaction"}:
            text = clean_control_user_text(text)
        if not session_key or not text:
            return
        self.mark_ui_dirty("transcript")
        now = timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        transcript = self.control_transcripts.setdefault(session_key, [])

        def notify_remote(item: dict[str, Any], *, replace: bool) -> None:
            self.record_remote_transcript_change(
                session_key,
                transcript,
                item,
                replace=replace,
            )

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
                    notify_remote(existing, replace=True)
                    return
                break
        if role not in {"user", "user_pending", "resume", "context_compaction"} and turn_id:
            self.assign_recent_user_turn_id_in_transcript(
                transcript,
                turn_id=turn_id,
                profile=profile,
                now=now,
            )
        if (
            role == "user"
            and not append
            and self.promote_pending_user_transcript(
                transcript,
                text=text,
                turn_id=turn_id,
                profile=profile,
                now=now,
            )
        ):
            for existing in reversed(transcript):
                if existing.get("role") == "user" and self.transcript_text_matches(existing, text):
                    notify_remote(existing, replace=True)
                    break
            return
        if (
            role == "resume"
            and not append
            and transcript
            and transcript[-1].get("role") == "resume"
        ):
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
                notify_remote(existing, replace=True)
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
                notify_remote(existing, replace=True)
                if role == "resume" and self.transcript_has_activity_after(
                    transcript,
                    index,
                    turn_id=turn_id,
                ):
                    self.append_context_replay_marker(
                        transcript,
                        session_key=session_key,
                        turn_id=turn_id,
                        profile=profile,
                        now=now,
                    )
                    if len(transcript) > CONTROL_TRANSCRIPT_MAX_ITEMS:
                        trim_count = len(transcript) - CONTROL_TRANSCRIPT_MAX_ITEMS
                        dropped = transcript[:trim_count]
                        del transcript[:trim_count]
                        for dropped_index, dropped_item in enumerate(dropped):
                            self.record_remote_transcript_remove(
                                session_key,
                                dropped_item,
                                index=dropped_index,
                            )
                return
        if role == "assistant":
            if source_item_id:
                for existing in reversed(transcript):
                    if existing.get("role") not in {"assistant", "assistant_progress"}:
                        continue
                    if existing.get("source_item_id") != source_item_id:
                        continue
                    existing["role"] = "assistant"
                    self.set_transcript_item_text(existing, "assistant", text)
                    existing["updated_at"] = now
                    existing["turn_id"] = turn_id or existing.get("turn_id") or ""
                    existing["profile"] = profile or existing.get("profile") or ""
                    existing["authoritative"] = authoritative or bool(existing.get("authoritative"))
                    notify_remote(existing, replace=True)
                    return
            for existing in reversed(transcript):
                progress_turn = str(existing.get("turn_id") or "")
                if existing.get("role") != "assistant_progress":
                    continue
                if turn_id and progress_turn and progress_turn != turn_id:
                    continue
                existing["role"] = "assistant"
                self.set_transcript_item_text(existing, "assistant", text)
                existing["updated_at"] = now
                existing["turn_id"] = turn_id or progress_turn
                existing["profile"] = profile or existing.get("profile") or ""
                if source_item_id:
                    existing["source_item_id"] = source_item_id
                if authoritative:
                    existing["authoritative"] = True
                notify_remote(existing, replace=True)
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
                if tool_status:
                    existing["status"] = tool_status
                if tool_kind:
                    existing["tool_kind"] = tool_kind
                if tool_title:
                    existing["tool_title"] = tool_title
                notify_remote(existing, replace=True)
                return
        if (
            append
            and transcript
            and transcript[-1].get("role") == role
            and transcript[-1].get("turn_id") == turn_id
        ):
            existing_text = str(transcript[-1].get("full_text") or transcript[-1].get("text") or "")
            separator = self.transcript_stream_separator(existing_text, text)
            merged = existing_text + separator + text
            self.set_transcript_item_text(transcript[-1], role, merged)
            transcript[-1]["updated_at"] = now
            notify_remote(transcript[-1], replace=True)
            return
        clipped = self.transcript_display_text(text)
        for existing in transcript[-6:]:
            if (
                existing.get("role") == role
                and existing.get("turn_id") == turn_id
                and existing.get("text") == clipped
            ):
                return
        new_item: dict[str, Any] = {
            "item_id": f"cti_{uuid.uuid4().hex}",
            "ts": now,
            "updated_at": now,
            "role": role,
            "text": clipped,
            "turn_id": turn_id,
            "profile": profile,
            "search_text": f"{role} {clipped}",
        }
        self.set_transcript_item_text(new_item, role, text)
        if call_id:
            new_item["call_id"] = call_id
        if tool_status:
            new_item["status"] = tool_status
        if tool_kind:
            new_item["tool_kind"] = tool_kind
        if tool_title:
            new_item["tool_title"] = tool_title
        if source_item_id:
            new_item["source_item_id"] = source_item_id
        if authoritative:
            new_item["authoritative"] = True
        transcript.append(new_item)
        notify_remote(new_item, replace=False)
        if len(transcript) > CONTROL_TRANSCRIPT_MAX_ITEMS:
            trim_count = len(transcript) - CONTROL_TRANSCRIPT_MAX_ITEMS
            dropped = transcript[:trim_count]
            del transcript[:trim_count]
            for dropped_index, dropped_item in enumerate(dropped):
                self.record_remote_transcript_remove(
                    session_key,
                    dropped_item,
                    index=dropped_index,
                )

    def record_websocket_transcript_message(
        self,
        tunnel_id: int,
        *,
        role: str,
        text: str,
        append: bool = False,
        call_id: str = "",
        source_item_id: str = "",
        authoritative: bool = False,
        turn_id_override: str = "",
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
            stored_turn_id = tunnel.get("turn_id")
            turn_id = turn_id_override or (
                stored_turn_id if isinstance(stored_turn_id, str) else ""
            )
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
                source_item_id=source_item_id,
                authoritative=authoritative,
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
        value = websocket_message_json(opcode, payload)
        if isinstance(value, dict) and isinstance(value.get("method"), str):
            for app_server_entry in app_server_transcript_entries_from_message(value):
                self.record_websocket_transcript_message(
                    tunnel_id,
                    role=str(app_server_entry.get("role") or "assistant"),
                    text=str(app_server_entry.get("text") or ""),
                    append=bool(app_server_entry.get("append")),
                    call_id=str(app_server_entry.get("call_id") or ""),
                    source_item_id=str(app_server_entry.get("source_item_id") or ""),
                    authoritative=bool(app_server_entry.get("authoritative")),
                    turn_id_override=str(app_server_entry.get("turn_id") or ""),
                )
            return
        assistant_entry = websocket_message_assistant_entry(opcode, payload)
        if assistant_entry:
            self.record_websocket_transcript_message(
                tunnel_id,
                role=str(assistant_entry.get("role") or "assistant"),
                text=str(assistant_entry.get("text") or ""),
                append=bool(assistant_entry.get("append")),
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
                cwd = (
                    str(record.get("cwd") or session_key)
                    if isinstance(record, dict)
                    else session_key
                )
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

    def control_transcript_snapshot_window(
        self,
        session_key: str,
        *,
        max_bytes: int | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, int | bool]]:
        """Return the newest transcript window and metadata for on-demand paging."""
        retained = self.control_transcripts.get(session_key, [])[-CONTROL_TRANSCRIPT_MAX_ITEMS:]
        rows: list[dict[str, Any]] = []
        for index, item in enumerate(retained):
            copied = dict(item)
            copied["control_index"] = index
            rows.append(copied)
        if max_bytes is None:
            start = 0
            return rows, {
                "start_index": start,
                "end_index": len(rows) - 1,
                "total_items": len(rows),
                "has_more_before": False,
            }

        selected: list[dict[str, Any]] = []
        encoded_size = 2
        for item in reversed(rows):
            item_size = len(json.dumps(item, separators=(",", ":")).encode("utf-8"))
            if selected and encoded_size + item_size + 1 > max_bytes:
                break
            selected.append(item)
            encoded_size += item_size + 1
        selected.reverse()
        start = int(selected[0].get("control_index") or 0) if selected else len(rows)
        return selected, {
            "start_index": start,
            "end_index": len(rows) - 1,
            "total_items": len(rows),
            "has_more_before": start > 0,
        }

    def control_transcript_snapshot(self, session_key: str) -> list[dict[str, Any]]:
        rows, _window = self.control_transcript_snapshot_window(session_key)
        return rows

    def control_turns_from_transcript(
        self, transcript: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        turns: list[dict[str, Any]] = []
        current: dict[str, Any] | None = None
        for index, item in enumerate(transcript):
            role = str(item.get("role") or "")
            turn_id = str(item.get("turn_id") or "")
            if role in {"user", "user_pending"}:
                if current is not None and turn_id and str(current.get("turn_id") or "") == turn_id:
                    current["end_index"] = index
                    current["updated_at"] = str(
                        item.get("updated_at") or item.get("ts") or current.get("updated_at") or ""
                    )
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
                current["updated_at"] = str(
                    item.get("updated_at") or item.get("ts") or current.get("updated_at") or ""
                )
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

    def apply_grok_session_record_locked(
        self,
        session_key: str,
        reader: GrokSessionReader,
        value: dict[str, Any],
        *,
        profile: str,
    ) -> None:
        kind, params, update = grok_update_payload(value)
        if not kind:
            return
        timestamp = provider_update_timestamp(value.get("timestamp"))
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        prompt_id = str(meta.get("promptId") or update.get("prompt_id") or "")
        if prompt_id:
            reader.current_turn_id = prompt_id
        turn_id = reader.current_turn_id

        if kind == "user_message_chunk":
            text = grok_content_text(update.get("content"))
            if not text:
                return
            reader.current_turn_id = ""
            reader.working = True
            self.append_control_transcript(
                session_key=session_key,
                role="user",
                text=text,
                profile=profile,
                timestamp=timestamp,
            )
            return
        if kind in {"agent_message_chunk", "agent_thought_chunk"}:
            text = grok_content_text(update.get("content"))
            if not text:
                return
            reader.working = True
            self.append_control_transcript(
                session_key=session_key,
                role="assistant_progress",
                text=text,
                turn_id=turn_id,
                profile=profile,
                append=True,
                timestamp=timestamp,
            )
            return
        if kind in {"tool_call", "tool_call_update"}:
            source_call_id = str(update.get("toolCallId") or "")
            if not source_call_id:
                return
            title = str(update.get("title") or "").strip()
            if kind == "tool_call" and title:
                reader.tool_names[source_call_id] = title
                if title == "get_command_or_subagent_output":
                    raw_input = update.get("rawInput")
                    task_ids = raw_input.get("task_ids") if isinstance(raw_input, dict) else None
                    if (
                        isinstance(task_ids, list)
                        and len(task_ids) == 1
                        and str(task_ids[0]) in reader.tool_states
                    ):
                        reader.tool_aliases[source_call_id] = str(task_ids[0])
                        return
            call_id = reader.tool_aliases.get(source_call_id, source_call_id)
            title = (
                reader.tool_names.get(call_id)
                or reader.tool_names.get(source_call_id)
                or title
                or str(update.get("kind") or "tool")
            )
            state = reader.tool_states.setdefault(call_id, {})
            shaped_update = update
            if call_id != source_call_id:
                shaped_update = dict(update)
                shaped_update.pop("kind", None)
                shaped_update.pop("title", None)
                shaped_update.pop("_meta", None)
            text = grok_tool_transcript_text(shaped_update, title=title, state=state)
            if not text:
                return
            reader.working = True
            self.append_control_transcript(
                session_key=session_key,
                role="tool",
                text=text,
                turn_id=turn_id,
                profile=profile,
                call_id=call_id,
                tool_status=str(state.get("status") or ""),
                tool_kind=str(state.get("kind") or ""),
                tool_title=str(state.get("summary") or ""),
                timestamp=timestamp,
            )
            return
        if kind in {"task_backgrounded", "task_completed"}:
            snapshot = update.get("task_snapshot")
            call_id = str(
                update.get("tool_call_id")
                or update.get("task_id")
                or (snapshot.get("task_id") if isinstance(snapshot, dict) else "")
                or ""
            )
            state = reader.tool_states.get(call_id)
            if not call_id or state is None:
                return
            if kind == "task_backgrounded":
                state["background"] = True
                state["status"] = "backgrounded"
                for source, target in (
                    ("command", "command"),
                    ("description", "description"),
                    ("cwd", "cwd"),
                    ("output_file", "output_file"),
                ):
                    if update.get(source):
                        state[target] = str(update[source])
            elif isinstance(snapshot, dict):
                completed_status = "completed"
                if snapshot.get("explicitly_killed"):
                    completed_status = "cancelled"
                elif not snapshot.get("completed", True):
                    completed_status = "failed"
                synthetic = {
                    "status": completed_status,
                    "rawOutput": {"type": "TaskOutput", "Result": snapshot},
                }
                update_grok_tool_state(
                    state,
                    synthetic,
                    name=str(state.get("name") or "run_terminal_command"),
                )
            text = grok_tool_transcript_text(
                {},
                title=str(state.get("name") or "run_terminal_command"),
                state=state,
            )
            self.append_control_transcript(
                session_key=session_key,
                role="tool",
                text=text,
                turn_id=turn_id,
                profile=profile,
                call_id=call_id,
                tool_status=str(state.get("status") or ""),
                tool_kind=str(state.get("kind") or "execute"),
                tool_title=str(state.get("summary") or ""),
                timestamp=timestamp,
            )
            return
        if kind == "session_recap":
            text = compact_tool_detail(update.get("summary"))
            if text:
                self.append_control_transcript(
                    session_key=session_key,
                    role="context_compaction",
                    text=text,
                    turn_id=turn_id,
                    profile=profile,
                    timestamp=timestamp,
                )
            return
        if kind != "turn_completed":
            return

        reader.working = False
        usage = normalize_grok_turn_usage(update.get("usage"))
        if usage:
            reader.latest_usage = usage
            reader.usage_updated_at = timestamp
        transcript = self.control_transcripts.get(session_key, [])
        for item in reversed(transcript):
            item_turn_id = str(item.get("turn_id") or "")
            if turn_id and item_turn_id and item_turn_id != turn_id:
                continue
            if item.get("role") != "assistant_progress":
                continue
            self.append_control_transcript(
                session_key=session_key,
                role="assistant",
                text=self.transcript_item_full_text(item),
                turn_id=turn_id or item_turn_id,
                profile=profile,
                timestamp=timestamp,
            )
            break

    def apply_claude_session_record_locked(
        self,
        session_key: str,
        reader: ClaudeSessionReader,
        value: dict[str, Any],
        *,
        profile: str,
    ) -> None:
        if value.get("isSidechain"):
            return
        kind = str(value.get("type") or "")
        subtype = str(value.get("subtype") or "")
        timestamp = provider_update_timestamp(value.get("timestamp"))
        prompt_id = str(value.get("promptId") or "")
        if prompt_id:
            reader.current_turn_id = prompt_id
        turn_id = reader.current_turn_id

        if kind == "user":
            message = value.get("message")
            content = message.get("content") if isinstance(message, dict) else None
            blocks = claude_message_blocks(content)
            tool_results = [block for block in blocks if block.get("type") == "tool_result"]
            if tool_results:
                for block in tool_results:
                    call_id = str(block.get("tool_use_id") or "")
                    if not call_id:
                        continue
                    state = reader.tool_states.setdefault(
                        call_id, {"name": "tool", "status": "in_progress"}
                    )
                    result_text = transcript_text_from_content(
                        block.get("content"), preserve_edges=True
                    ) or compact_tool_detail(block.get("content"))
                    state["output_text"] = bounded_provider_tool_text(
                        result_text, PROVIDER_TOOL_OUTPUT_LIMIT
                    )
                    state["status"] = "failed" if block.get("is_error") else "completed"
                    tool_result = value.get("toolUseResult")
                    if isinstance(tool_result, dict):
                        exit_code = tool_result.get("exitCode")
                        if exit_code is None:
                            exit_code = tool_result.get("exit_code")
                        if exit_code is not None:
                            state["exit_code"] = exit_code
                        if tool_result.get("interrupted"):
                            state["status"] = "cancelled"
                        stderr = tool_result.get("stderr")
                        if isinstance(stderr, str) and stderr.strip() and not result_text:
                            state["output_text"] = bounded_provider_tool_text(
                                stderr, PROVIDER_TOOL_OUTPUT_LIMIT
                            )
                    self.append_control_transcript(
                        session_key=session_key,
                        role="tool",
                        text=claude_tool_transcript_text(state),
                        turn_id=turn_id,
                        profile=profile,
                        call_id=call_id,
                        tool_status=str(state.get("status") or ""),
                        tool_kind=str(state.get("name") or "tool").lower(),
                        tool_title=str(state.get("summary") or ""),
                        timestamp=timestamp,
                    )
                return
            text = "\n".join(
                clean_transcript_text(str(block.get("text") or ""), preserve_edges=True)
                for block in blocks
                if block.get("type") == "text" and str(block.get("text") or "").strip()
            )
            if text:
                reader.working = True
                self.append_control_transcript(
                    session_key=session_key,
                    role="user",
                    text=text,
                    turn_id=turn_id,
                    profile=profile,
                    timestamp=timestamp,
                )
            return

        if kind == "assistant":
            message = value.get("message")
            if not isinstance(message, dict):
                return
            model = str(message.get("model") or "")
            if model:
                reader.model = model
            reader.working = str(message.get("stop_reason") or "") != "end_turn"
            for index, block in enumerate(claude_message_blocks(message.get("content"))):
                block_type = str(block.get("type") or "")
                if block_type == "text":
                    text = clean_transcript_text(str(block.get("text") or ""), preserve_edges=True)
                    if text:
                        self.append_control_transcript(
                            session_key=session_key,
                            role="assistant",
                            text=text,
                            turn_id=turn_id,
                            profile=profile,
                            source_item_id=f"{value.get('uuid') or ''}:{index}",
                            authoritative=True,
                            timestamp=timestamp,
                        )
                elif block_type == "tool_use":
                    call_id = str(block.get("id") or "")
                    if not call_id:
                        continue
                    state = claude_tool_state(str(block.get("name") or "tool"), block.get("input"))
                    reader.tool_states[call_id] = state
                    self.append_control_transcript(
                        session_key=session_key,
                        role="tool",
                        text=claude_tool_transcript_text(state),
                        turn_id=turn_id,
                        profile=profile,
                        call_id=call_id,
                        tool_status="in_progress",
                        tool_kind=str(state.get("name") or "tool").lower(),
                        tool_title=str(state.get("summary") or ""),
                        timestamp=timestamp,
                    )
            return

        if kind == "system" and subtype == "compact_boundary":
            metadata = value.get("compactMetadata")
            details = [str(value.get("content") or "Conversation compacted")]
            if isinstance(metadata, dict):
                before = metadata.get("preTokens")
                after = metadata.get("postTokens")
                trigger = metadata.get("trigger")
                if before is not None and after is not None:
                    details.append(f"Context: {before} → {after} tokens")
                if trigger:
                    details.append(f"Trigger: {trigger}")
            self.append_control_transcript(
                session_key=session_key,
                role="context_compaction",
                text="\n".join(details),
                turn_id=turn_id,
                profile=profile,
                timestamp=timestamp,
            )
            return
        if kind == "system" and subtype == "turn_duration":
            reader.working = False
        elif kind == "system" and subtype == "api_error":
            text = clean_transcript_text(str(value.get("content") or ""))
            if text:
                self.append_control_transcript(
                    session_key=session_key,
                    role="error",
                    text=text,
                    turn_id=turn_id,
                    profile=profile,
                    timestamp=timestamp,
                )

    def refresh_provider_sessions(self, *, force: bool = False) -> None:
        """Import new structured transcript records from supported local CLIs."""
        lock = getattr(self, "provider_session_readers_lock", None)
        readers = getattr(self, "provider_session_readers", None)
        if lock is None or not isinstance(readers, dict):
            return
        now = time.monotonic()
        with lock:
            last = float(getattr(self, "provider_session_last_refresh_monotonic", 0.0) or 0.0)
            if not force and now - last < PROVIDER_SESSION_REFRESH_SECONDS:
                return
            self.provider_session_last_refresh_monotonic = now
            with self.active_lock:
                candidates = [
                    (
                        key,
                        str(record.get("provider") or "codex"),
                        str(record.get("cwd") or key),
                        str(record.get("provider_profile") or ""),
                        str(record.get("provider_state_root") or ""),
                        record.get("provider_pid"),
                        str(record.get("control_path") or ""),
                    )
                    for key, record in self.observed_sessions.items()
                    if str(record.get("provider") or "codex") in {"grok", "claude"}
                ]
            for (
                session_key,
                provider,
                cwd,
                profile,
                state_root_text,
                provider_pid,
                control_path,
            ) in candidates:
                if not state_root_text:
                    if profile:
                        try:
                            state_root_text = str(
                                self.store.provider_profile_root(provider, profile)
                            )
                        except StoreError:
                            continue
                    else:
                        state_root_text = str(
                            Path.home() / (".grok" if provider == "grok" else ".claude")
                        )
                reader_type = GrokSessionReader if provider == "grok" else ClaudeSessionReader
                reader = readers.get(session_key)
                if not isinstance(reader, reader_type):
                    reader = reader_type()
                    readers[session_key] = reader
                batch = reader.refresh(
                    Path(state_root_text).expanduser(),
                    cwd,
                    provider_pid if isinstance(provider_pid, int) else None,
                )
                provider_running = process_is_running(
                    provider_pid if isinstance(provider_pid, int) else None
                ) or bool(control_path and Path(control_path).exists())
                state_changed = False
                with self.active_lock:
                    record = self.observed_sessions.get(session_key)
                    if (
                        not isinstance(record, dict)
                        or str(record.get("provider") or "") != provider
                    ):
                        continue
                    for value in batch.records:
                        if isinstance(reader, GrokSessionReader):
                            self.apply_grok_session_record_locked(
                                session_key,
                                reader,
                                value,
                                profile=profile,
                            )
                        else:
                            self.apply_claude_session_record_locked(
                                session_key,
                                reader,
                                value,
                                profile=profile,
                            )
                    updates = {
                        "provider_session_id": batch.session_id,
                        "provider_model": batch.model,
                        "provider_process_running": provider_running,
                        "provider_working": bool(reader.working and provider_running),
                    }
                    if isinstance(reader, GrokSessionReader):
                        updates["provider_usage"] = dict(reader.latest_usage)
                        updates["provider_usage_updated_at"] = reader.usage_updated_at
                    if batch.title:
                        updates["title"] = batch.title
                    if batch.session_id:
                        updates["thread_id"] = batch.session_id
                    for key, value in updates.items():
                        if record.get(key) != value:
                            record[key] = value
                            state_changed = True
                if state_changed:
                    self.mark_ui_dirty("provider_session")

    def session_snapshots(self) -> list[dict[str, Any]]:
        self.refresh_provider_sessions()
        self.expire_stale_requests()
        with self.ui_launchers_lock:
            live_ui_launcher_pids = set(self.ui_launchers)
        with self.active_lock:
            self.expire_websocket_work_locked()
            now = time.monotonic()
            stale_session_keys = self.prune_stale_observed_sessions_locked(
                now=now,
                live_ui_launcher_pids=live_ui_launcher_pids,
            )
            snapshots = []
            for key, record in self.observed_sessions.items():
                active_requests = sum(
                    1
                    for request in self.active_requests.values()
                    if request.get("session_key") == key
                )
                active_turn_requests = sum(
                    1
                    for request in self.active_requests.values()
                    if request.get("session_key") == key and bool(request.get("turn_work"))
                )
                active_tunnels = sum(
                    1
                    for tunnel in self.active_websockets.values()
                    if tunnel.get("session_key") == key
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
                thread_id = str(
                    record.get("thread_id") or (active_thread_ids[0] if active_thread_ids else "")
                )
                control_path = str(record.get("control_path") or "")
                control_available = bool(control_path and Path(control_path).exists())
                pty_managed = bool(record.get("pty_managed"))
                provider = str(record.get("provider") or "codex")
                permission_supported = self.permission_bridge_available(record)
                with self.permission_condition:
                    permission_enabled = permission_supported and (
                        self.permission_routes.get(key)
                        == str(record.get("permission_bridge") or "")
                    )
                if permission_supported:
                    permission_reason = "Browser approval is available for this managed session."
                elif provider == "grok":
                    permission_reason = (
                        "Grok terminal sessions do not expose safe synchronous "
                        "permission decisions yet."
                    )
                elif provider == "codex":
                    permission_reason = (
                        "Codex terminal sessions require an app-server or explicit hook adapter."
                    )
                else:
                    permission_reason = "Restart this managed session to enable browser approvals."
                provider_profile = str(record.get("provider_profile") or "")
                provider_process_running = bool(record.get("provider_process_running"))
                provider_working = bool(record.get("provider_working"))
                ui_launcher_pid = record.get("ui_launcher_pid")
                ui_launcher_running = (
                    isinstance(ui_launcher_pid, int) and ui_launcher_pid in live_ui_launcher_pids
                )
                associated_profile = str(pinned_profile or record.get("last_profile") or "")
                snapshots.append(
                    {
                        "key": key,
                        "cwd": str(record.get("cwd") or key),
                        "display": str(record.get("display") or compact_session_path(key)),
                        "name": str(record.get("name") or session_display_name(key)),
                        "title": str(
                            record.get("title") or record.get("name") or session_display_name(key)
                        ),
                        "tab_order": int(
                            record.get("tab_order") or self.session_tab_order_for_key_locked(key)
                        ),
                        "thread_id": thread_id,
                        "provider": provider,
                        "permission_routing_supported": permission_supported,
                        "permission_routing_enabled": permission_enabled,
                        "permission_routing_reason": permission_reason,
                        "provider_profile": provider_profile,
                        "last_profile": record.get("last_profile"),
                        "pinned_profile": pinned_profile,
                        "associated_profile": associated_profile,
                        "parent_session_key": str(record.get("parent_session_key") or ""),
                        "ui_launched": bool(record.get("ui_launched")),
                        "active_requests": active_requests,
                        "active_turn_requests": active_turn_requests,
                        "active_tunnels": active_tunnels,
                        "pending_websocket_work": pending_work,
                        "working": active_turn_requests > 0 or pending_work > 0 or provider_working,
                        "recent_websocket_activity": recent_activity,
                        "pty_managed": pty_managed,
                        "pty_control_available": control_available,
                        "ui_launcher_pid": ui_launcher_pid
                        if isinstance(ui_launcher_pid, int)
                        else None,
                        "ui_launcher_running": ui_launcher_running,
                        "ui_launcher_mode": str(record.get("ui_launcher_mode") or ""),
                        "ui_launcher_permission": str(record.get("ui_launcher_permission") or ""),
                        "active": (
                            active_requests > 0
                            or pending_work > 0
                            or recent_activity > 0
                            or control_available
                            or ui_launcher_running
                            or provider_process_running
                        ),
                        "provider_process_running": provider_process_running,
                        "provider_session_id": str(record.get("provider_session_id") or ""),
                        "provider_model": str(record.get("provider_model") or ""),
                        "provider_usage": dict(record.get("provider_usage") or {})
                        if isinstance(record.get("provider_usage"), dict)
                        else {},
                        "provider_usage_updated_at": str(
                            record.get("provider_usage_updated_at") or ""
                        ),
                        "first_seen_monotonic": record.get("first_seen_monotonic") or 0.0,
                        "last_seen_monotonic": record.get("last_seen_monotonic") or 0.0,
                        "interaction": {
                            "available": control_available,
                            "thread_id": thread_id,
                            "mode": "pty" if control_available else "",
                            "reason": f"Ready to send input to the running {provider.title()} terminal."
                            if control_available
                            else (
                                f"This PTY-managed {provider.title()} launcher is no longer reachable. Restart it with `provision {provider}`."
                                if pty_managed
                                else f"Restart this {provider.title()} session with Provision in an interactive terminal to enable UI input."
                            ),
                        },
                    }
                )
        if stale_session_keys:
            with self.provider_session_readers_lock:
                for key in stale_session_keys:
                    self.provider_session_readers.pop(key, None)
            for key in stale_session_keys:
                self.release_permission_requests(key)
            self.mark_ui_dirty("session_prune")
        snapshots.sort(
            key=lambda item: (
                int(item.get("tab_order") or 0),
                float(item.get("first_seen_monotonic") or 0.0),
                str(item.get("key") or ""),
            )
        )
        for snapshot in snapshots:
            provider = str(snapshot.get("provider") or "codex")
            if provider != "codex":
                provider_profile = str(snapshot.get("provider_profile") or "")
                snapshot["associated_profile"] = provider_profile
                snapshot["model_setting"] = {}
                snapshot["quota_summary"] = {
                    "available": False,
                    "source": "unavailable",
                }
                snapshot["quota_html"] = (
                    '<div class="quota-empty">Quota data is not exposed by this provider.</div>'
                )
                snapshot["quota_compact"] = {"buckets": [], "state": None}
                continue
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
                "",
            )
            snapshot["quota_compact"] = compact_quota_payload(
                quota_snapshot,
                str(model_setting.get("model") or ""),
            )
        return snapshots

    def provider_profile_snapshots(
        self,
        sessions: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Describe observed/configured native provider identities for the UI.

        These are deliberately separate from Codex account profiles. Claude
        identity labels come only from the CLI's documented, bounded
        ``auth status --json`` response; Provision does not read a provider
        credential store or manufacture an account-quota endpoint.
        """
        if sessions is None:
            sessions = self.session_snapshots()
        default_provider = self.store.default_provider()
        provider_configs = (
            {
                "provider": "claude",
                "label": "Claude",
                "managed_identity": "Provision-managed CLAUDE_CONFIG_DIR",
                "native_identity": "Vendor-managed Claude identity",
                "quota_source": "claude_native_usage_command",
                "quota_status": "Use /usage in Claude",
                "quota_detail": (
                    "Claude exposes subscription usage in its native /usage screen, "
                    "but the CLI does not document a machine-readable account-quota interface."
                ),
                "usage_empty": "Turn usage is not projected for Claude sessions yet.",
            },
            {
                "provider": "grok",
                "label": "Grok",
                "managed_identity": "Provision-managed GROK_HOME",
                "native_identity": "Vendor-managed Grok identity",
                "quota_source": "grok_native_usage_command",
                "quota_status": "Use /usage in Grok",
                "quota_detail": (
                    "Grok does not expose OAuth subscription quota in its structured "
                    "session feed. The native /usage command is available only for "
                    "eligible account tiers."
                ),
                "usage_empty": "No completed-turn usage observed yet.",
            },
        )
        profiles: list[dict[str, Any]] = []
        for config in provider_configs:
            provider = str(config["provider"])
            provider_label = str(config["label"])
            provider_sessions = [
                session
                for session in sessions
                if isinstance(session, dict) and str(session.get("provider") or "") == provider
            ]
            try:
                managed_names = set(self.store.provider_profile_names(provider))
                selected_name = self.store.active_provider_profile(provider) or ""
            except StoreError:
                managed_names = set()
                selected_name = ""
            observed_names = {
                str(session.get("provider_profile") or "") for session in provider_sessions
            }
            names = managed_names | {name for name in observed_names if name}
            include_native = "" in observed_names or (
                not selected_name and (default_provider == provider or bool(managed_names))
            )
            if not include_native and not names:
                continue

            ordered_names = ([""] if include_native else []) + sorted(names)
            for name in ordered_names:
                matching = [
                    session
                    for session in provider_sessions
                    if str(session.get("provider_profile") or "") == name
                ]
                latest = max(
                    matching,
                    key=lambda session: (
                        str(session.get("provider_usage_updated_at") or ""),
                        float(session.get("last_seen_monotonic") or 0.0),
                    ),
                    default={},
                )
                usage = latest.get("provider_usage")
                usage = dict(usage) if isinstance(usage, dict) else {}
                models = sorted(
                    {
                        str(session.get("provider_model") or "")
                        for session in matching
                        if str(session.get("provider_model") or "")
                    }
                )
                identity = (
                    self.provider_identity_snapshot(provider, name) if provider == "claude" else {}
                )
                account_parts = []
                for field in ("email", "organization"):
                    value = str(identity.get(field) or "")
                    if value and value not in account_parts:
                        account_parts.append(value)
                profiles.append(
                    {
                        "key": f"provider:{provider}:{name or 'native'}",
                        "provider": provider,
                        "provider_label": provider_label,
                        "name": name,
                        "display_name": name or "Native",
                        "managed": bool(name),
                        "profile_kind_label": "Managed provider profile"
                        if name
                        else "Provider native",
                        "identity_label": str(
                            config["managed_identity"] if name else config["native_identity"]
                        ),
                        "account_label": " · ".join(account_parts),
                        "auth_status": str(identity.get("status") or ""),
                        "auth_pending": bool(identity.get("pending")),
                        "logged_in": identity.get("logged_in"),
                        "auth_method": str(identity.get("auth_method") or ""),
                        "api_provider": str(identity.get("api_provider") or ""),
                        "subscription_label": str(identity.get("subscription") or ""),
                        "selected_for_provider": name == selected_name,
                        "selection_label": f"{provider_label} default",
                        "default_provider": default_provider == provider and name == selected_name,
                        "session_count": len(matching),
                        "active_session_count": sum(
                            1 for session in matching if session.get("active")
                        ),
                        "working_session_count": sum(
                            1 for session in matching if session.get("working")
                        ),
                        "models": models,
                        "usage": usage,
                        "usage_empty": str(config["usage_empty"]),
                        "usage_updated_at": str(latest.get("provider_usage_updated_at") or ""),
                        "usage_session": str(latest.get("name") or ""),
                        "quota": {
                            "available": False,
                            "source": str(config["quota_source"]),
                            "status": str(config["quota_status"]),
                            "detail": str(config["quota_detail"]),
                        },
                    }
                )
        return profiles

    def provider_identity_snapshot(self, provider: str, profile: str) -> dict[str, Any]:
        """Return cached identity metadata and refresh it without delaying UI state."""

        if provider != "claude":
            return {}
        key = f"{provider}:{profile or 'native'}"
        now = time.monotonic()
        pending = {
            "available": False,
            "logged_in": None,
            "pending": True,
            "status": "Checking login…",
        }
        with self.provider_identity_cache_lock:
            entry = self.provider_identity_cache.get(key)
            if isinstance(entry, dict):
                value = entry.get("value")
                updated_at = float(entry.get("updated_at") or 0.0)
                ttl = (
                    PROVIDER_IDENTITY_CACHE_SECONDS
                    if isinstance(value, dict) and value.get("available")
                    else PROVIDER_IDENTITY_ERROR_CACHE_SECONDS
                )
                if isinstance(value, dict) and now - updated_at < ttl:
                    return dict(value)
                if entry.get("in_flight"):
                    pending = dict(value) if isinstance(value, dict) else pending
                    pending["pending"] = True
                    pending.setdefault("status", "Checking login…")
                    return pending
            previous_value = entry.get("value") if isinstance(entry, dict) else None
            if isinstance(previous_value, dict) and previous_value:
                pending = dict(previous_value)
                pending["pending"] = True
            self.provider_identity_cache[key] = {
                "value": dict(previous_value) if isinstance(previous_value, dict) else {},
                "updated_at": float(entry.get("updated_at") or 0.0)
                if isinstance(entry, dict)
                else 0.0,
                "in_flight": True,
            }
        thread = threading.Thread(
            target=self.refresh_provider_identity,
            args=(provider, profile, key),
            daemon=True,
            name=f"provision-{provider}-identity-{profile or 'native'}",
        )
        thread.start()
        return pending

    def refresh_provider_identity(self, provider: str, profile: str, key: str) -> None:
        config_dir: Path | None = None
        if profile:
            try:
                config_dir = self.store.provider_profile_root(provider, profile)
            except StoreError:
                value = {
                    "available": False,
                    "logged_in": None,
                    "status": "Authentication status unavailable",
                }
            else:
                value = claude_auth_status_probe(config_dir)
        else:
            value = claude_auth_status_probe()
        value = dict(value)
        value["pending"] = False
        with self.provider_identity_cache_lock:
            self.provider_identity_cache[key] = {
                "value": value,
                "updated_at": time.monotonic(),
                "in_flight": False,
            }
        self.mark_ui_dirty("profiles")

    def control_plane_sessions(
        self, sessions: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        self.expire_stale_requests()
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
                            "turn_work": bool(request.get("turn_work")),
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
                            "turn_id": tunnel.get("turn_id")
                            if isinstance(tunnel.get("turn_id"), str)
                            else "",
                            "thread_id": tunnel.get("thread_id")
                            if isinstance(tunnel.get("thread_id"), str)
                            else "",
                            "service_tier": tunnel.get("service_tier")
                            if isinstance(tunnel.get("service_tier"), str)
                            else "",
                            "age_seconds": round(now - float(started), 1)
                            if isinstance(started, (int, float))
                            else None,
                            "last_data_age_seconds": round(now - last_data, 1)
                            if last_data > 0
                            else None,
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
                full_transcript = self.control_transcript_snapshot(key)
                transcript, transcript_window = self.control_transcript_snapshot_window(
                    key,
                    max_bytes=CONTROL_TRANSCRIPT_SNAPSHOT_MAX_BYTES,
                )
                session["transcript"] = transcript
                session["transcript_window"] = transcript_window
                session["turns"] = self.control_turns_from_transcript(full_transcript)

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
                "reason": "PTY-managed CLI input is available."
                if pty_available
                else "Launch a supported CLI with `provision` in an interactive terminal to enable live UI input.",
            },
        }

    # Remote control intentionally uses a narrow source rather than
    # control_plane_sessions().  The latter includes every retained
    # transcript item for the local dashboard; constructing it for remote
    # state would recreate the oversized snapshot problem this design solves.
    def remote_session_summaries(self) -> list[dict[str, Any]]:
        secret, _cursor_codec, _devices, _state, _actions = self.remote_runtime()
        sessions = self.session_snapshots()
        contexts: dict[str, dict[str, Any]] = {}
        for event in self.stats_events(CONTROL_PLANE_EVENT_LIMIT):
            session_key = event.get("session_key")
            if not isinstance(session_key, str) or not session_key:
                continue
            if event.get("type") != "token_usage":
                continue
            context = context_summary_from_usage(event.get("usage"))
            if context:
                contexts[session_key] = context
        with self.active_lock:
            self.expire_websocket_work_locked()
            turns_by_session: dict[str, list[dict[str, str]]] = {}
            for tunnel in self.active_websockets.values():
                session_key = tunnel.get("session_key")
                turn_id = tunnel.get("turn_id")
                if not isinstance(session_key, str) or not session_key:
                    continue
                if not isinstance(turn_id, str) or not turn_id:
                    continue
                turns_by_session.setdefault(session_key, []).append({"turn_id": turn_id})
        for session in sessions:
            key = str(session.get("key") or "")
            if key in contexts:
                session["context"] = contexts[key]
            session["active_details"] = {"tunnels": turns_by_session.get(key, [])}
        return build_remote_session_summaries({"sessions": sessions}, secret)

    def refresh_remote_state(self) -> int:
        _secret, _cursor_codec, _devices, state, _actions = self.remote_runtime()
        return state.refresh(self.remote_session_summaries())

    def record_remote_transcript_change(
        self,
        session_key: str,
        transcript: list[dict[str, Any]],
        item: dict[str, Any],
        *,
        replace: bool,
    ) -> None:
        """Queue one bounded Discussion delta without rebuilding a transcript."""
        remote_state = getattr(self, "remote_state", None)
        secret = getattr(self, "remote_secret", None)
        if not isinstance(remote_state, RemoteStateSynchronizer) or not isinstance(secret, bytes):
            return
        try:
            index = transcript.index(item)
        except ValueError:
            return
        session_id = remote_session_id(secret, session_key)
        entry = remote_discussion_entry(
            secret=secret,
            session_id=session_id,
            item=item,
            index=index,
        )
        remote_state.record_discussion_change(session_id, entry, replace=replace)

    def record_remote_transcript_remove(
        self,
        session_key: str,
        item: dict[str, Any],
        *,
        index: int,
    ) -> None:
        """Keep an attached remote Discussion cache correct after local trim."""
        remote_state = getattr(self, "remote_state", None)
        secret = getattr(self, "remote_secret", None)
        if not isinstance(remote_state, RemoteStateSynchronizer) or not isinstance(secret, bytes):
            return
        session_id = remote_session_id(secret, session_key)
        entry = remote_discussion_entry(
            secret=secret,
            session_id=session_id,
            item=item,
            index=index,
        )
        remote_state.record_discussion_remove(session_id, str(entry["message_id"]))

    def enroll_remote_device(
        self,
        device_id: str,
        identity_fingerprint: str,
        *,
        capabilities: set[str] | None = None,
    ) -> dict[str, Any]:
        """Record a verified pairing after a future transport handshake.

        This method is deliberately not wired to the dashboard, CLI, or HTTP
        proxy.  Pairing is a local-host action that the Remote Agent will call
        only after its cryptographic safety code is verified.
        """
        _secret, _cursor_codec, devices, _state, _actions = self.remote_runtime()
        result = devices.enroll(
            device_id,
            identity_fingerprint,
            capabilities=capabilities if capabilities is not None else REMOTE_DEFAULT_CAPABILITIES,
        )
        devices.append_audit(
            event="device_enrolled",
            device_id=str(result.get("device_id") or ""),
            outcome="ok",
        )
        return result

    def revoke_remote_device(self, device_id: str) -> None:
        _secret, _cursor_codec, devices, _state, _actions = self.remote_runtime()
        devices.revoke(device_id)
        self.remote_control_leases.release_all_for_device(device_id)
        devices.append_audit(
            event="device_revoked",
            device_id=device_id,
            outcome="ok",
        )

    def remote_state_payload(
        self,
        device_id: str,
        *,
        since_revision: int | None = None,
        cursor: str = "",
    ) -> dict[str, Any]:
        _secret, cursor_codec, devices, state, _actions = self.remote_runtime()
        devices.authorize(device_id, "read_state")
        if cursor and since_revision is not None:
            raise RemoteError("remote session cursor cannot be combined with a delta revision")
        revision = self.refresh_remote_state()
        if since_revision is None:
            payload = state.state_payload(
                cursor_codec=cursor_codec,
                cursor=cursor,
            )
            payload["type"] = "state"
            return payload
        deltas = state.deltas_since(since_revision)
        if deltas is None:
            payload = state.state_payload(cursor_codec=cursor_codec)
            payload["type"] = "state"
            payload["resync_required"] = True
            return payload
        payload = {
            "type": "state_delta",
            "protocol_version": 1,
            "revision": revision,
            "deltas": deltas,
        }
        if len(compact_json_bytes(payload)) > REMOTE_DELTA_SYNC_MAX_BYTES:
            snapshot = state.state_payload(cursor_codec=cursor_codec)
            snapshot["type"] = "state"
            snapshot["resync_required"] = True
            return snapshot
        return payload

    def remote_session_key(self, session_id: str) -> str:
        self.refresh_remote_state()
        _secret, _cursor_codec, _devices, state, _actions = self.remote_runtime()
        session_key = state.session_key_for_id(session_id)
        if not session_key:
            raise RemoteError("remote session was not found")
        return session_key

    def remote_discussion_payload(
        self,
        device_id: str,
        session_id: str,
        *,
        cursor: str = "",
    ) -> dict[str, Any]:
        secret, cursor_codec, devices, _state, _actions = self.remote_runtime()
        devices.authorize(device_id, "read_discussion")
        session_key = self.remote_session_key(session_id)
        with self.active_lock:
            transcript = self.control_transcript_snapshot(session_key)
        return build_remote_discussion_page(
            secret=secret,
            session_id=session_id,
            transcript=transcript,
            cursor_codec=cursor_codec,
            cursor=cursor,
        )

    def remote_message_expand_payload(
        self,
        device_id: str,
        session_id: str,
        message_id: str,
        *,
        cursor: str = "",
    ) -> dict[str, Any]:
        secret, cursor_codec, devices, _state, _actions = self.remote_runtime()
        devices.authorize(device_id, "read_discussion")
        session_key = self.remote_session_key(session_id)
        with self.active_lock:
            transcript = self.control_transcript_snapshot(session_key)
        return build_remote_message_expand(
            secret=secret,
            session_id=session_id,
            transcript=transcript,
            message_id=message_id,
            cursor_codec=cursor_codec,
            cursor=cursor,
        )

    def remote_action_lock(self, session_key: str) -> threading.Lock:
        with self.remote_action_locks_lock:
            return self.remote_action_locks.setdefault(session_key, threading.Lock())

    @staticmethod
    def validate_remote_action_expiry(expires_at: str) -> None:
        if not isinstance(expires_at, str) or not expires_at:
            raise RemoteError("remote action expiry is required")
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RemoteError("invalid remote action expiry") from exc
        if expiry.tzinfo is None:
            raise RemoteError("invalid remote action expiry")
        remaining = (expiry.astimezone(timezone.utc) - datetime.now(timezone.utc)).total_seconds()
        if remaining <= 0:
            raise RemoteError("remote action has expired")
        if remaining > 300:
            raise RemoteError("remote action expiry is too far in the future")

    def perform_remote_action(
        self,
        device_id: str,
        *,
        action: str,
        session_id: str,
        expected_revision: int,
        expected_turn_id: str = "",
        idempotency_key: str,
        expires_at: str,
        prompt: str = "",
    ) -> dict[str, Any]:
        secret, _cursor_codec, devices, state, actions = self.remote_runtime()
        capability_by_action = {
            "send_prompt": "send_prompt",
            "interrupt_turn": "interrupt_turn",
        }
        capability = capability_by_action.get(action)
        if not capability:
            raise RemoteError("remote action is not available")
        devices.authorize(device_id, capability)
        self.validate_remote_action_expiry(expires_at)
        if len(prompt.encode("utf-8")) > REMOTE_ACTION_PROMPT_MAX_BYTES:
            raise RemoteError("remote prompt exceeds its byte limit")
        if action == "send_prompt" and not prompt.strip():
            raise RemoteError("remote prompt is empty")
        if action == "interrupt_turn" and prompt:
            raise RemoteError("remote interrupt action does not accept a prompt")
        if action == "interrupt_turn" and not expected_turn_id:
            raise RemoteError("remote interrupt action requires the expected turn")

        semantic_ref = opaque_identifier(
            secret,
            "remote-action",
            f"{action}\0{session_id}\0{expected_revision}\0{expected_turn_id}\0{prompt}",
            prefix="request",
        )
        cached = actions.get(device_id, idempotency_key)
        if cached is not None:
            if cached.get("_semantic_ref") != semantic_ref:
                raise RemoteError("remote idempotency key was reused for a different action")
            if cached.get("_state") != "completed":
                raise RemoteError(
                    "remote action outcome is indeterminate; inspect the session before retrying"
                )
            return {key: value for key, value in cached.items() if not key.startswith("_")}

        self.refresh_remote_state()
        session = state.session_payload(session_id)
        session_key = state.session_key_for_id(session_id)
        if session is None or not session_key:
            raise RemoteError("remote session was not found")
        if expected_revision != int(session.get("unread_revision") or 0):
            raise RemoteError("remote action has a stale session revision")
        if expected_turn_id and expected_turn_id != str(session.get("current_turn_id") or ""):
            raise RemoteError("remote action has a stale turn")

        audit_session = remote_session_audit_ref(secret, session_key)
        action_lock = self.remote_action_lock(session_key)
        with action_lock:
            self.remote_control_leases.acquire(session_key, device_id)
            mutation_attempted = False
            try:
                # State can change while an adjacent device waited for the
                # session lock, so recheck before writing to the PTY.
                self.refresh_remote_state()
                session = state.session_payload(session_id)
                if session is None or expected_revision != int(session.get("unread_revision") or 0):
                    raise RemoteError("remote action has a stale session revision")
                if expected_turn_id and expected_turn_id != str(
                    session.get("current_turn_id") or ""
                ):
                    raise RemoteError("remote action has a stale turn")
                cached = actions.reserve(
                    device_id,
                    idempotency_key,
                    semantic_ref,
                    expires_at,
                )
                if cached is not None:
                    return {key: value for key, value in cached.items() if not key.startswith("_")}
                mutation_attempted = True
                if action == "send_prompt":
                    self.send_session_prompt(session_key, prompt)
                else:
                    self.send_session_escape(session_key)
                resulting_revision = self.refresh_remote_state()
                resulting_session = state.session_payload(session_id) or {}
                result = {
                    "ok": True,
                    "action": action,
                    "session_id": session_id,
                    "revision": resulting_revision,
                    "session_revision": int(
                        resulting_session.get("unread_revision") or resulting_revision
                    ),
                    "idempotency_key": idempotency_key,
                    "_semantic_ref": semantic_ref,
                }
                actions.remember(
                    device_id,
                    idempotency_key,
                    result,
                    expires_at=expires_at,
                )
                devices.append_audit(
                    event="remote_action",
                    device_id=device_id,
                    capability=capability,
                    session_ref=audit_session,
                    outcome="ok",
                    request_ref=semantic_ref,
                )
                return {key: value for key, value in result.items() if not key.startswith("_")}
            except (StoreError, RemoteError, OSError, json.JSONDecodeError) as exc:
                devices.append_audit(
                    event="remote_action",
                    device_id=device_id,
                    capability=capability,
                    session_ref=audit_session,
                    outcome="indeterminate" if mutation_attempted else "rejected",
                    request_ref=semantic_ref,
                )
                if isinstance(exc, RemoteError):
                    raise
                raise RemoteError("remote action was not completed") from exc
            finally:
                # A lease exists only for the serialized mutation.  Local
                # terminal input therefore remains immediately authoritative.
                self.remote_control_leases.release(session_key, device_id=device_id)

    def pinned_sessions_for_profile(
        self,
        profile: str,
        sessions: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        if sessions is None:
            sessions = self.session_snapshots()
        return [session for session in sessions if session.get("pinned_profile") == profile]

    def profile_has_active_sessions(self, profile: str, *, pinned_only: bool = False) -> bool:
        self.expire_stale_requests()
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
                    "fast": service_tier in FAST_SERVICE_TIER_VALUES
                    or self.profile_fast_mode(profile),
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
            fresh = (
                isinstance(fetched, (int, float))
                and now - fetched < APP_SERVER_MODEL_CATALOG_CACHE_SECONDS
            )
            recent_failure = (
                isinstance(failed, (int, float))
                and now - failed < APP_SERVER_MODEL_CATALOG_ERROR_BACKOFF_SECONDS
            )
            if not fresh and not recent_failure and not entry.get("in_flight"):
                entry["in_flight"] = True
                should_refresh = True
            cached_catalog = entry.get("catalog")
            catalog = (
                [dict(item) for item in cached_catalog]
                if isinstance(cached_catalog, tuple)
                else fallback
            )
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
                thread_id = (
                    tunnel.get("thread_id") if isinstance(tunnel.get("thread_id"), str) else ""
                )
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

    def pty_control_request(self, control_path: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not control_path:
            raise StoreError(
                "This session was not launched under Provision PTY control. "
                "Restart it with `provision` before using UI input."
            )
        path = Path(control_path)
        if not path.exists():
            raise StoreError(
                "Provision's PTY control socket for this session is no longer available. "
                "Restart the CLI session with Provision."
            )
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(encoded) > PERMISSION_CONTROL_MAX_BYTES:
            raise StoreError("PTY control message is too large")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(2.0)
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
        except OSError as exc:
            raise StoreError(f"failed to send PTY control message: {exc}") from exc
        if len(response) > PERMISSION_CONTROL_MAX_BYTES:
            raise StoreError("PTY control response is too large")
        try:
            value = bytes(response).split(b"\n", 1)[0]
            response_payload = json.loads(value.decode("utf-8")) if value else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StoreError(f"invalid PTY control response: {exc}") from exc
        if not isinstance(response_payload, dict) or not response_payload.get("ok"):
            error = response_payload.get("error") if isinstance(response_payload, dict) else None
            raise StoreError(str(error or "PTY control rejected the message"))
        return response_payload

    def send_pty_control_payload(self, control_path: str, payload: dict[str, Any]) -> None:
        self.pty_control_request(control_path, payload)

    def send_prompt_to_pty_control(self, control_path: str, text: str) -> None:
        self.send_pty_control_payload(control_path, {"action": "send_text", "text": text})

    def send_escape_to_pty_control(self, control_path: str) -> None:
        self.send_pty_control_payload(control_path, {"action": "send_escape"})

    def terminal_snapshot_for_session(self, session_key: str) -> dict[str, Any]:
        """Read one bounded visual terminal tail from a managed local PTY.

        This is intentionally on-demand and local-dashboard-only. It avoids
        adding raw terminal streams to routine status snapshots, history,
        search, logs, or the Connector/remote protocol.
        """
        with self.active_lock:
            record = self.observed_sessions.get(session_key)
            if not isinstance(record, dict):
                raise StoreError("unknown session")
            control_path = (
                record.get("control_path") if isinstance(record.get("control_path"), str) else ""
            )
            provider = str(record.get("provider") or "codex")
        response = self.pty_control_request(
            str(control_path or ""), {"action": "terminal_snapshot"}
        )
        if response.get("encoding") != "base64" or not isinstance(response.get("output"), str):
            raise StoreError("invalid PTY terminal snapshot")
        try:
            output = base64.b64decode(response["output"].encode("ascii"), validate=True)
        except (ValueError, binascii.Error, UnicodeEncodeError) as exc:
            raise StoreError(f"invalid PTY terminal snapshot: {exc}") from exc
        # Browser rendering must receive text only. Keep newlines/tabs but
        # strip control and ANSI escape sequences before escaped DOM rendering.
        text = terminal_display_text(output)
        return {
            "provider": provider,
            "text": text,
            "truncated": bool(response.get("truncated")),
        }

    def send_session_prompt(self, session_key: str, text: str) -> dict[str, Any]:
        prompt = clean_transcript_text(text)
        if not prompt:
            raise StoreError("prompt is empty")
        with self.active_lock:
            record = self.observed_sessions.get(session_key)
            if not isinstance(record, dict):
                raise StoreError("unknown session")
            cwd = str(record.get("cwd") or session_key)
            control_path = (
                record.get("control_path") if isinstance(record.get("control_path"), str) else ""
            )
            provider = str(record.get("provider") or "codex")
            provider_profile = str(record.get("provider_profile") or "")
        profile = (
            self.control_profile_for_session(session_key)
            if provider == "codex"
            else provider_profile
        )
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
            "provider": provider,
            "cwd": cwd,
            "mode": "pty",
        }

    def send_session_escape(self, session_key: str) -> dict[str, Any]:
        with self.active_lock:
            record = self.observed_sessions.get(session_key)
            if not isinstance(record, dict):
                raise StoreError("unknown session")
            control_path = (
                record.get("control_path") if isinstance(record.get("control_path"), str) else ""
            )
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
        credit_id: str | None = None,
    ) -> dict[str, Any]:
        if not self.store.profile_exists(profile):
            raise StoreError(f"unknown profile: {profile}")
        self.ensure_reset_credit_attempt_allowed(profile)
        key = idempotency_key or str(uuid.uuid4())
        attempt_started = False

        def consume(client: CodexAppServerClient) -> dict[str, Any]:
            nonlocal attempt_started
            rate_limits_before = client.read_account_rate_limits()
            reset_credits = rate_limits_before.get("rateLimitResetCredits")
            selected_credit_id = selected_rate_limit_reset_credit_id(reset_credits, credit_id)
            self.begin_reset_credit_attempt(profile, key)
            attempt_started = True
            return {
                "consume": client.consume_account_rate_limit_reset_credit(
                    key, credit_id=selected_credit_id
                ),
                "rate_limits": client.read_account_rate_limits(),
                "credit_id": selected_credit_id,
            }

        try:
            result = self.run_app_server_for_profile(profile, consume)
        except Exception as exc:
            if attempt_started:
                self.mark_reset_credit_attempt_error(profile, key, exc)
            raise
        consume_result = result.get("consume") if isinstance(result, dict) else {}
        rate_limits = result.get("rate_limits") if isinstance(result, dict) else {}
        outcome = (
            str(consume_result.get("outcome") or "unknown")
            if isinstance(consume_result, dict)
            else "unknown"
        )
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
            "credit_id": str(result.get("credit_id") or "") if isinstance(result, dict) else "",
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
        if (
            isinstance(fetched, (int, float))
            and now - float(fetched) < APP_SERVER_RATE_LIMIT_CACHE_SECONDS
        ):
            return False
        checked = entry.get("checked_monotonic")
        if (
            isinstance(checked, (int, float))
            and now - float(checked) < APP_SERVER_RATE_LIMIT_CACHE_SECONDS
        ):
            return False
        failed = entry.get("failed_monotonic")
        if (
            isinstance(failed, (int, float))
            and now - float(failed) < APP_SERVER_RATE_LIMIT_FAILURE_BACKOFF_SECONDS
        ):
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
            self.update_usage_cache_from_observation(
                profile, payload, source="app_server_rate_limits"
            )
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
            return usage_payload_from_app_server_rate_limits_response(
                client.read_account_rate_limits()
            )

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
                "cache_write_input_tokens": 0,
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
                    "cache_write_input_tokens": 0,
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
                    row["cache_write_input_tokens"] += int_value(
                        usage.get("cache_write_input_tokens")
                    )
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
                row["last_quota"] = (
                    event.get("quota") if isinstance(event.get("quota"), dict) else {}
                )
            if event_type in {
                "http_request",
                "websocket_tunnel",
                "token_usage",
                "reset_credit",
            }:
                recent.append(compact_stats_event(event))
            if event_type in {
                "http_request",
                "websocket_tunnel",
                "token_usage",
                "quota_update",
                "reset_credit",
            }:
                traffic = int(row["bytes_up"]) + int(row["bytes_down"])
                value = (
                    int(row["total_tokens"])
                    or traffic
                    or int(row["requests"]) + int(row["tunnels"]) + int(row["quota_updates"])
                )
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
                            "cache_write_input_tokens": 0,
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
            label = (
                metadata.get("email")
                or metadata.get("account_id")
                or metadata.get("kind")
                or profile
            )
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
                attempted = (
                    entry.get("auto_refresh_attempted_monotonic")
                    if isinstance(entry, dict)
                    else None
                )
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
                    and billing_error_at
                    + timedelta(seconds=USAGE_AUTO_REFRESH_BILLING_BACKOFF_SECONDS)
                    > now
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
            if not self.request_host_is_allowed():
                self.send_error(421, "dashboard Host header is not allowed")
                return
            self.send_dashboard_html(self.render_ui())
            return
        if parsed.path == "/api/ui-session":
            if not self.request_host_is_allowed():
                self.send_error(421, "dashboard Host header is not allowed")
                return
            self.send_ui_session()
            return
        if parsed.path in (
            "/assets/provision.png",
            "/assets/provision-wordmark.png",
        ):
            self.send_logo_asset(parsed.path.rsplit("/", 1)[-1])
            return
        if parsed.path in UI_ASSETS:
            self.send_ui_asset(parsed.path)
            return
        if parsed.path == "/api/status":
            if not self.request_host_is_allowed():
                self.send_error(421, "dashboard Host header is not allowed")
                return
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
        if parsed.path == "/api/profile-visibility":
            self.handle_profile_visibility()
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
        if parsed.path == "/api/permission-request":
            self.handle_permission_request()
            return
        if parsed.path == "/api/pin-session":
            self.handle_pin_session()
            return
        if parsed.path == "/api/connector":
            self.handle_connector()
            return
        if parsed.path in CODEX_API_POST_PROXY_PATHS:
            self.proxy_to_upstream("POST", parsed)
            return
        if self.is_chatgpt_backend_proxy_path(parsed.path):
            self.proxy_to_upstream("POST", parsed, route=UpstreamRoute.CHATGPT_BACKEND)
            return
        if parsed.path.startswith("/backend-api/"):
            self.send_json({"error": "invalid ChatGPT backend proxy path token"}, status=401)
            return
        self.send_error(404)

    def handle_connector(self) -> None:
        try:
            data = self.read_post_fields()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        if not self.control_request_is_authorized(data):
            self.send_json({"error": "invalid connector control token"}, status=401)
            return
        action = str(data.get("action") or "status")
        try:
            if action == "enable":
                connector = self.server.start_connector_hub()
            elif action == "disable":
                connector = self.server.stop_connector_hub()
            elif action == "status":
                connector = self.server.connector_status()
            else:
                raise StoreError("unsupported connector action")
        except StoreError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        self.send_json({"ok": True, "connector": connector})

    def handle_switch(self) -> None:
        try:
            data = self.read_post_fields()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        profile = data.get("profile")
        if not self.control_request_is_authorized(data):
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

    def handle_profile_visibility(self) -> None:
        try:
            data = self.read_post_fields()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        if not self.control_request_is_authorized(data):
            self.send_json({"error": "invalid UI token"}, status=401)
            return
        profile = str(data.get("profile") or "")
        hidden = str(data.get("hidden") or "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        try:
            self.server.store.set_profile_hidden(profile, hidden)
        except StoreError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        self.server.mark_ui_dirty("profiles")
        self.redirect_ui()

    def handle_refresh_quota(self) -> None:
        try:
            data = self.read_post_fields()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        profile = str(data.get("profile") or "")
        if not self.control_request_is_authorized(data):
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
        credit_id = str(data.get("credit_id") or "").strip() or None
        if not self.control_request_is_authorized(data):
            self.send_json({"error": "invalid UI token"}, status=401)
            return
        if not self.server.store.profile_exists(profile):
            self.send_json({"error": f"unknown profile: {profile}"}, status=400)
            return
        try:
            self.server.consume_profile_rate_limit_reset_credit(profile, credit_id=credit_id)
        except (
            StoreError,
            CodexAppServerError,
            AuthError,
            OSError,
            json.JSONDecodeError,
        ) as exc:
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
        if not self.control_request_is_authorized(data):
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
        if not self.control_request_is_authorized(data):
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
        mode = str(data.get("mode") or "browser")
        login_action = str(data.get("login_action") or "start_login")
        if not self.control_request_is_authorized(data):
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
        cwd = str(data.get("cwd") or "")
        explicit_session_key = normalize_session_key(str(data.get("session_key") or ""))
        control_path = str(data.get("control_path") or "")
        launcher_pid_raw = str(data.get("launcher_pid") or "")
        try:
            launcher_pid = int(launcher_pid_raw) if launcher_pid_raw else None
        except ValueError:
            launcher_pid = None
        provider_pid_raw = str(data.get("provider_pid") or "")
        try:
            provider_pid = int(provider_pid_raw) if provider_pid_raw else None
        except ValueError:
            provider_pid = None
        provider_state_root = str(data.get("provider_state_root") or "")
        permission_bridge = bounded_permission_text(data.get("permission_bridge"), 80)
        pty_managed = str(data.get("pty_managed") or "").lower() in {"1", "true", "yes"}
        if not self.control_request_is_authorized(data):
            self.send_json({"error": "invalid UI token"}, status=401)
            return
        try:
            provider = canonical_provider(str(data.get("provider") or "codex"))
        except ProviderError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        provider_profile = str(data.get("provider_profile") or "")
        session_key = explicit_session_key or normalize_session_key(cwd)
        profile = self.server.profile_for_session(session_key) if provider == "codex" else None
        if explicit_session_key:
            with self.server.active_lock:
                self.server.observe_session_locked(
                    explicit_session_key,
                    cwd,
                    profile,
                    provider=provider,
                    provider_profile=provider_profile or None,
                    control_path=control_path or None,
                    launcher_pid=launcher_pid,
                    provider_pid=provider_pid,
                    provider_state_root=provider_state_root or None,
                    permission_bridge=permission_bridge or None,
                    pty_managed=pty_managed,
                    clear_control_path=not bool(control_path),
                )
            session_key = explicit_session_key
        else:
            session_key = self.server.observe_session(
                cwd,
                profile,
                provider=provider,
                provider_profile=provider_profile or None,
                control_path=control_path or None,
                launcher_pid=launcher_pid,
                provider_pid=provider_pid,
                provider_state_root=provider_state_root or None,
                permission_bridge=permission_bridge or None,
                pty_managed=pty_managed,
                clear_control_path=not bool(control_path),
            )
        self.send_json({"ok": True, "session_key": session_key})

    def handle_permission_request(self) -> None:
        client_host = str(self.client_address[0] if self.client_address else "")
        if not daemon_host_is_loopback(client_host):
            self.send_json({"error": "permission bridge is loopback-only"}, status=403)
            return
        try:
            data = self.read_post_fields(max_bytes=PERMISSION_CONTROL_MAX_BYTES)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        supplied = str(data.get("token") or "")
        if not supplied or not hmac.compare_digest(supplied, self.server.proxy_token):
            self.send_json({"error": "invalid permission bridge token"}, status=401)
            return
        request = data.get("request")
        if not isinstance(request, dict):
            self.send_json({"error": "invalid permission request"}, status=400)
            return
        result = self.server.request_permission(
            str(data.get("session_key") or ""),
            str(data.get("provider") or ""),
            request,
        )
        self.send_json(result)

    def handle_pin_session(self) -> None:
        try:
            data = self.read_post_fields()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        if not self.control_request_is_authorized(data):
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

    def read_post_fields(self, *, max_bytes: int | None = None) -> dict[str, Any]:
        content_type = self.headers.get("content-type", "")
        try:
            length = int(self.headers.get("content-length", "0") or "0")
        except ValueError:
            raise ValueError("invalid content length") from None
        if length < 0:
            raise ValueError("invalid content length")
        if max_bytes is not None and length > max_bytes:
            raise ValueError("request body is too large")
        raw = self.rfile.read(length)
        if "application/json" in content_type:
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ValueError("invalid JSON") from None
            return data if isinstance(data, dict) else {}
        try:
            form = urllib.parse.parse_qs(raw.decode("utf-8"))
        except UnicodeDecodeError:
            raise ValueError("invalid form data") from None
        return {key: values[0] for key, values in form.items() if values}

    def request_origin_is_same_host(self) -> bool:
        if not self.request_host_is_allowed():
            return False
        origin = self.headers.get("origin", "")
        host = self.headers.get("host", "")
        if not origin or not host:
            return False
        parsed = urllib.parse.urlparse(origin)
        return parsed.scheme in {"http", "https"} and hmac.compare_digest(
            parsed.netloc.lower(), host.lower()
        )

    def request_host_is_allowed(self) -> bool:
        address = getattr(self.server, "server_address", (DEFAULT_DAEMON_HOST, 0))
        bind_host = str(address[0] or DEFAULT_DAEMON_HOST)
        if not daemon_host_is_loopback(bind_host):
            return True
        raw_host = self.headers.get("host", "")
        try:
            hostname = urllib.parse.urlsplit(f"//{raw_host}").hostname
        except ValueError:
            return False
        return bool(hostname and daemon_host_is_loopback(hostname))

    def dashboard_session_is_authorized(self) -> bool:
        if not self.request_origin_is_same_host():
            return False
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("cookie", ""))
        except CookieError:
            return False
        morsel = cookie.get(UI_SESSION_COOKIE)
        expected = getattr(self.server, "ui_session_token", "")
        return bool(morsel and expected and hmac.compare_digest(morsel.value, expected))

    def control_request_is_authorized(self, data: dict[str, Any]) -> bool:
        supplied = str(data.get("token") or "")
        proxy_token = self.server.proxy_token
        if supplied and hmac.compare_digest(supplied, proxy_token):
            return True
        return self.dashboard_session_is_authorized()

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
        if not self.control_request_is_authorized({"token": token}):
            self.send_json({"error": "invalid UI token"}, status=401)
            return
        key = self.headers.get("sec-websocket-key", "")
        if not key:
            self.send_json({"error": "missing websocket key"}, status=400)
            return

        self.accept_websocket(key)
        self.close_connection = True
        self.connection.settimeout(UI_STATE_CHECK_SECONDS)
        self.server.ui_client_connected()
        try:
            last_sent_version = self.send_ui_state()
            last_liveness_signature = self.server.ui_state_liveness_signature()
            last_safety_snapshot = time.monotonic()
            last_heartbeat = last_safety_snapshot
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
        finally:
            self.server.ui_client_disconnected()

    def accept_websocket(self, key: str) -> None:
        self.send_response(101)
        self.send_header("upgrade", "websocket")
        self.send_header("connection", "Upgrade")
        self.send_header("sec-websocket-accept", websocket_accept_key(key))
        self.end_headers()

    def handle_ui_websocket_action(self, message: dict[str, Any]) -> None:
        if not self.control_request_is_authorized(message):
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
        if action == "set_profile_visibility":
            hidden = str(message.get("hidden") or "").strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
            try:
                self.server.store.set_profile_hidden(profile, hidden)
            except StoreError as exc:
                self.send_ui_state(message=str(exc))
                return
            self.server.mark_ui_dirty("profiles")
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
                credit_id = str(message.get("credit_id") or "").strip() or None
                result = self.server.consume_profile_rate_limit_reset_credit(
                    profile, credit_id=credit_id
                )
            except (
                StoreError,
                CodexAppServerError,
                AuthError,
                OSError,
                json.JSONDecodeError,
            ) as exc:
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
        if action == "set_permission_routing":
            session_key = str(message.get("session_key") or "")
            enabled_value = message.get("enabled")
            if not isinstance(enabled_value, bool):
                self.send_ui_state(message="invalid browser approval setting")
                return
            try:
                self.server.set_permission_routing(session_key, enabled_value)
            except StoreError as exc:
                self.send_ui_state(message=str(exc))
                return
            self.send_ui_state()
            return
        if action == "resolve_permission":
            try:
                self.server.resolve_permission(
                    str(message.get("request_id") or ""),
                    str(message.get("session_key") or ""),
                    str(message.get("decision") or ""),
                )
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
            except (
                StoreError,
                CodexAppServerError,
                AuthError,
                OSError,
                json.JSONDecodeError,
            ) as exc:
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
        if action == "load_control_turn":
            session_key = str(message.get("session_key") or "")
            turn_key = str(message.get("turn_key") or "")
            before_index = message.get("before_index")
            try:
                payload = self.server.control_turn_payload_for_session(
                    session_key,
                    turn_key,
                    before_index=before_index,
                )
            except StoreError as exc:
                self.send_websocket_json(
                    {
                        "type": "control_turn",
                        "ok": False,
                        "session_key": session_key,
                        "turn_key": turn_key,
                        "error": str(exc),
                    }
                )
                return
            self.send_websocket_json(
                {
                    "type": "control_turn",
                    "ok": True,
                    "session_key": session_key,
                    "turn_key": turn_key,
                    "payload": payload,
                }
            )
            return
        if action == "terminal_snapshot":
            session_key = str(message.get("session_key") or "")
            try:
                snapshot = self.server.terminal_snapshot_for_session(session_key)
            except StoreError as exc:
                self.send_websocket_json(
                    {
                        "type": "terminal_snapshot",
                        "ok": False,
                        "session_key": session_key,
                        "error": str(exc),
                    }
                )
                return
            self.send_websocket_json(
                {
                    "type": "terminal_snapshot",
                    "ok": True,
                    "session_key": session_key,
                    "snapshot": snapshot,
                }
            )
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
                "provider_session",
            }:
                sections.add("control_plane")
                if reason in {
                    "session_observe",
                    "session_pin",
                    "session_unpin",
                    "session_reorder",
                    "session_forget",
                    "provider_session",
                }:
                    sections.add("profiles")
                continue
            if reason == "stats":
                sections.add("stats")
                continue
            if reason == "permissions":
                sections.update({"permissions", "control_plane"})
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
            status["provider_profiles"] = full_status.get("provider_profiles", [])
        if "control_plane" in sections:
            status["control_plane"] = (
                full_status.get("control_plane", {})
                if full_status is not None
                else self.server.control_plane_sessions()
            )
        if "stats" in sections:
            status["stats"] = self.server.stats_summary()
        if "permissions" in sections:
            permission_snapshot = getattr(self.server, "permission_state_snapshot", None)
            status["permissions"] = (
                permission_snapshot()
                if callable(permission_snapshot)
                else {"pending": [], "browser_clients": 0}
            )
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
        current_liveness_signature = self.server.ui_state_liveness_signature()
        current_version = self.server.ui_state_revision()
        safety_due = now - last_safety_snapshot >= UI_SAFETY_SNAPSHOT_SECONDS
        liveness_changed = current_liveness_signature != last_liveness_signature
        state_due = current_version != last_sent_version or liveness_changed or safety_due
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
        return (
            last_sent_version,
            last_liveness_signature,
            last_safety_snapshot,
            last_heartbeat,
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
            with self.server.active_lock:
                self.server.observe_session_locked(str(session_key), str(session["cwd"]), profile)
        service_tier = None
        model_setting = self.server.profile_model_setting(profile)
        model = str(model_setting.get("model") or "")
        reasoning_effort = str(model_setting.get("reasoning_effort") or "")
        if route == UpstreamRoute.CODEX_API and parsed.path in (
            "/v1/responses",
            "/v1/responses/compact",
        ):
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
        request_id = self.server.begin_request(
            profile,
            session_key,
            turn_work=(
                route == UpstreamRoute.CODEX_API
                and method == "POST"
                and parsed.path in {"/v1/responses", "/v1/responses/compact"}
            ),
        )
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
            try:
                try:
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
                except Exception as exc:
                    self.log_message("http proxy statistics recording failed: %s", exc)
                self.log_message(
                    "http proxy %s %s for profile %s completed status=%s duration=%.3fs",
                    method,
                    parsed.path,
                    profile,
                    status_code if status_code is not None else "unknown",
                    elapsed,
                )
            finally:
                # Finalization may fail during an outage or a disk-full event;
                # removal from active_requests must still be unconditional.
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
                if route == UpstreamRoute.CODEX_API and parsed.path in (
                    "/v1/responses",
                    "/v1/responses/compact",
                ):
                    self.server.clear_profile_billing_required(profile)
                if self.server.update_usage_cache_from_rate_limit_headers(
                    profile, response.headers
                ):
                    self.log_message(
                        "quota cache for profile %s updated from response headers",
                        profile,
                    )
                if self.should_label_usage_response(route, method, upstream_path, response.headers):
                    payload = response.read()
                    labeled = self.label_usage_response(
                        payload, profile, datetime.now().astimezone()
                    )
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
                    self.server.observe_session_locked(
                        str(session_key), str(session["cwd"]), profile
                    )
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
        prefixes = (
            backend_proxy_prefix(self.server.proxy_token),
            backend_proxy_prefix(),
        )
        return any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)

    def upstream_url(
        self,
        route: str,
        parsed: urllib.parse.ParseResult,
        auth: dict[str, Any],
        *,
        upstream_path: str | None = None,
    ) -> str:
        upstream_path = (
            upstream_path if upstream_path is not None else self.upstream_path(route, parsed)
        )
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

    def fetch_usage_payload_uncached(
        self, profile: str, *, retry_on_401: bool = True
    ) -> dict[str, Any] | None:
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
                            rewritten, _model, _reasoning, model_changed = (
                                rewrite_model_websocket_message(
                                    opcode,
                                    rewritten,
                                    model=current_model,
                                    reasoning_effort=current_reasoning,
                                )
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
        return (
            decode_project_session_sentinel(
                self.headers.get("openai-project", ""),
                self.server.proxy_token,
            )
            is not None
        )

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
        except OSError:
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
            "default_provider": self.server.store.default_provider(),
            "active_profile": self.server.store.active_profile(required=False),
            "active_requests": active_requests,
            "blocking_active_requests": blocking_requests,
            "active_websockets": active_websockets,
            "blocking_active_websockets": self.server.websocket_count(blocking_only=True),
            "active_websocket_work": self.server.active_websocket_work_count(),
            "blocking_active_websocket_work": self.server.active_websocket_work_count(
                blocking_only=True
            ),
            "pending_websocket_work": pending_work,
            "blocking_pending_websocket_work": blocking_pending_work,
            "recent_websocket_activity": recent_activity,
            "recent_websocket_data_activity": recent_activity,
            "live_busy": active_requests > 0 or pending_work > 0 or recent_activity > 0,
            "switch_block_reason": self.server.switch_block_reason(),
            "connector": self.server.connector_status(),
        }
        if include_profiles:
            sessions = self.server.session_snapshots()
            payload["sessions"] = sessions
            if include_control_plane:
                payload["control_plane"] = self.server.control_plane_sessions(sessions)
            payload["provider_profiles"] = self.server.provider_profile_snapshots(sessions)
            profiles = []
            for profile in self.server.store.list_profiles():
                item = dict(profile)
                name = item.get("name")
                item["quota_summary"] = usage_cache_summary(
                    self.server.usage_cache_snapshot(str(name)) if name else None
                )
                item["billing_required"] = (
                    self.server.profile_billing_required(str(name)) if name else {}
                )
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
        permission_snapshot = getattr(self.server, "permission_state_snapshot", None)
        status["permissions"] = (
            permission_snapshot()
            if callable(permission_snapshot)
            else {"pending": [], "browser_clients": 0}
        )
        for profile in status["profiles"]:
            name = str(profile.get("name") or "")
            snapshot = self.server.usage_cache_snapshot(name) if name else None
            billing_required = self.server.profile_billing_required(name)
            if (
                isinstance(billing_required, dict)
                and billing_required.get("required")
                and not snapshot
            ):
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
            if include_html:
                profile["login_status_html"] = render_login_status_html(
                    profile["login_status"],
                    name,
                    "",
                )
                profile["pin_menu_html"] = self.render_pin_menu(profile, status)
                profile["pinned_sessions_html"] = self.render_pinned_sessions(profile)
                profile["auth_health_html"] = render_auth_health_html(profile["auth_health"])
                profile["quota_html"] = render_quota_html(
                    snapshot,
                    profile["quota_updated"],
                    name,
                    "",
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
        sessions = status.get("sessions")
        codex_sessions = (
            [
                session
                for session in sessions
                if isinstance(session, dict) and str(session.get("provider") or "codex") == "codex"
            ]
            if isinstance(sessions, list)
            else []
        )
        if not codex_sessions:
            return f"""
              <details class="pin-menu profile-pin-menu" data-profile="{html.escape(profile_name)}">
                <summary class="pin-summary">{PIN_ICON_SVG}<span>Session Pins</span></summary>
                <div class="pin-menu-panel"><div class="pin-menu-empty">No Codex sessions observed</div></div>
              </details>
            """

        items: list[str] = []
        for session in codex_sessions:
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
            <div class="pin-menu-panel">{"".join(items)}</div>
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
            <div class="session-chips">{"".join(chips)}</div>
          </div>
        """

    def render_fast_pill(self, profile: dict[str, Any]) -> str:
        profile_name = str(profile.get("name") or "")
        enabled = bool(profile.get("fast_mode"))
        enabled_class = " enabled" if enabled else ""
        return f"""
          <form method="post" action="/api/toggle-fast" class="profile-pill-form" data-action="toggle_fast" data-profile="{html.escape(profile_name)}">
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
        name = html.escape(profile_name)
        cancel_form = (
            f"""
              <form method="post" action="/api/login" data-action="cancel_login" data-profile="{name}">
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
                <input type="hidden" name="profile" value="{name}">
                <input type="hidden" name="mode" value="browser">
                <button class="menu-action" {disabled}>Browser Login</button>
              </form>
              <form method="post" action="/api/login" data-action="start_login" data-profile="{name}">
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
        setting = (
            profile.get("model_setting") if isinstance(profile.get("model_setting"), dict) else {}
        )
        current_model = str(setting.get("model") or DEFAULT_MODEL_ID)
        current_reasoning = str(
            setting.get("reasoning_effort") or default_reasoning_for_model(current_model)
        )
        label = model_pill_label(current_model, current_reasoning)
        name = html.escape(profile_name)
        items: list[str] = []
        profile_catalog = profile.get("model_catalog")
        catalog = (
            profile_catalog
            if isinstance(profile_catalog, list) and profile_catalog
            else model_catalog()
        )
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
                  <div class="model-reasoning-menu">{"".join(reasoning_forms)}</div>
                </div>
                """
            )
        return f"""
          <details class="model-menu" data-profile="{name}">
            <summary class="model-pill" title="Select model and reasoning effort">
              <span>{html.escape(label)}</span>
            </summary>
            <div class="model-menu-panel">{"".join(items)}</div>
          </details>
        """

    def render_profile_rows(self, status: dict[str, Any]) -> str:
        rows = []
        for profile in status.get("profiles", []):
            if profile.get("hidden"):
                continue
            rows.append(self.render_profile_row(profile))
        for profile in status.get("provider_profiles", []):
            if isinstance(profile, dict):
                rows.append(self.render_provider_profile_row(profile))
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
        switch_class = (
            "primary-action current-action" if profile.get("active") else "primary-action"
        )
        if profile.get("active") and profile.get("has_active_sessions"):
            switch_class += " session-active-action"
        disabled = "disabled" if switch_reason else ""
        pin_menu = str(profile.get("pin_menu_html") or "")
        pinned_sessions = str(profile.get("pinned_sessions_html") or "")
        login_status_html = str(profile.get("login_status_html") or "")
        auth_health_html = str(profile.get("auth_health_html") or "")
        profile_chips = self.render_profile_chips(profile)
        model_menu = self.render_model_menu(profile)
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
                <input type="hidden" name="profile" value="{name}">
                <button class="{switch_class}" {disabled} title="{html.escape(switch_reason)}">{switch_label}</button>
              </form>
              <form method="post" action="/api/profile-visibility" data-action="set_profile_visibility" data-profile="{name}">
                <input type="hidden" name="profile" value="{name}">
                <input type="hidden" name="hidden" value="true">
                <button class="profile-visibility-action" title="Hide this profile from the dashboard">Hide</button>
              </form>
            </td>
          </tr>
        """

    def render_provider_profile_row(self, profile: dict[str, Any]) -> str:
        provider = str(profile.get("provider") or "provider")
        provider_label = str(profile.get("provider_label") or provider.title())
        display_name = str(profile.get("display_name") or profile.get("name") or "Native")
        key = html.escape(str(profile.get("key") or f"provider:{provider}:{display_name}"))
        session_count = int(profile.get("session_count") or 0)
        active_count = int(profile.get("active_session_count") or 0)
        usage = profile.get("usage") if isinstance(profile.get("usage"), dict) else {}
        models = profile.get("models") if isinstance(profile.get("models"), list) else []
        model_html = (
            "".join(
                f'<span class="model-pill provider-model-pill">{html.escape(str(model))}</span>'
                for model in models
                if str(model)
            )
            or '<span class="quota-muted">Observed model unavailable</span>'
        )
        usage_rows: list[str] = []
        for label, field in (
            ("Total tokens", "totalTokens"),
            ("Input", "inputTokens"),
            ("Output", "outputTokens"),
            ("Reasoning", "reasoningTokens"),
            ("Cached read", "cachedReadTokens"),
            ("Cache write", "cacheCreationTokens"),
            ("Model calls", "modelCalls"),
            ("Agent turns", "numTurns"),
        ):
            value = usage.get(field)
            if isinstance(value, int) and not isinstance(value, bool):
                usage_rows.append(
                    f"<span><span>{html.escape(label)}</span><strong>{value:,}</strong></span>"
                )
        cost_ticks = usage.get("costUsdTicks")
        if isinstance(cost_ticks, int) and not isinstance(cost_ticks, bool):
            cost = f"{cost_ticks / 10_000_000_000:.4f}".rstrip("0").rstrip(".") or "0"
            usage_rows.append(
                f"<span><span>Server-reported cost</span><strong>${html.escape(cost)}</strong></span>"
            )
        latest_usage = (
            '<div class="provider-usage-head">Latest observed turn</div>'
            f'<div class="provider-usage-grid">{"".join(usage_rows)}</div>'
            if usage_rows
            else (
                '<div class="quota-muted">'
                f"{html.escape(str(profile.get('usage_empty') or 'No completed-turn usage observed yet.'))}"
                "</div>"
            )
        )
        quota = profile.get("quota") if isinstance(profile.get("quota"), dict) else {}
        quota_status = html.escape(str(quota.get("status") or "Account quota unavailable"))
        quota_detail = html.escape(str(quota.get("detail") or ""))
        default_badge = (
            '<span class="badge active-badge">Default provider identity</span>'
            if profile.get("default_provider")
            else (
                '<span class="profile-pill provider-default-pill">'
                f"{html.escape(str(profile.get('selection_label') or f'{provider_label} default'))}"
                "</span>"
                if profile.get("selected_for_provider")
                else ""
            )
        )
        account_label = str(profile.get("account_label") or "")
        account_html = (
            f'<div class="profile-email">{html.escape(account_label)}</div>'
            if account_label
            else ""
        )
        profile_kind = str(
            profile.get("profile_kind_label")
            or ("Managed provider profile" if profile.get("managed") else "Provider native")
        )
        auth_status = str(profile.get("auth_status") or "")
        auth_status_class = " login-pill" if profile.get("logged_in") is False else ""
        auth_status_html = (
            f'<span class="profile-pill{auth_status_class}">{html.escape(auth_status)}</span>'
            if auth_status
            else ""
        )
        subscription = str(profile.get("subscription_label") or "")
        subscription_html = (
            f'<span class="profile-pill">{html.escape(subscription)}</span>' if subscription else ""
        )
        session_label = f"{session_count} session{'s' if session_count != 1 else ''}"
        if active_count:
            session_label += f" / {active_count} active"
        return f"""
          <tr class="profile-row provider-profile-row{" active" if profile.get("default_provider") else ""}" data-profile-key="{key}">
            <td class="profile-cell">
              <div class="profile-name">{html.escape(provider_label)} <span class="profile-plan">({html.escape(display_name)})</span></div>
              <div class="profile-email">{html.escape(str(profile.get("identity_label") or "Native provider identity"))}</div>
              {account_html}
              <div class="profile-chips"><span class="profile-pill provider-pill">{html.escape(profile_kind)}</span>{auth_status_html}{subscription_html}{default_badge}</div>
            </td>
            <td class="model-cell"><div class="provider-models">{model_html}</div></td>
            <td class="quota-cell">
              <div class="provider-quota-panel">
                <div class="provider-quota-head"><span>Account quota</span><strong>{quota_status}</strong></div>
                <div class="provider-quota-detail">{quota_detail}</div>
                {latest_usage}
              </div>
            </td>
            <td class="actions provider-actions"><span>{html.escape(session_label)}</span></td>
          </tr>
        """

    def render_ui(self) -> str:
        status = self.ui_status_payload(include_html=True)
        rows = self.render_profile_rows(status)
        active_profile = html.escape(str(status.get("active_profile") or "none"))
        default_provider = html.escape(str(status.get("default_provider") or "codex"))
        active_requests = int(status.get("active_requests") or 0)
        active_websockets = int(status.get("active_websockets") or 0)
        busy = "busy" if status.get("live_busy") else "idle"
        codex = status.get("codex") if isinstance(status.get("codex"), dict) else {}
        codex_cli = reported_codex_cli(codex)
        codex_version = html.escape(str(codex_cli.get("version") or "unknown"))
        initial_json = json.dumps(
            {"type": "state", "status": status, "message": None},
            separators=(",", ":"),
        ).replace("</", "<\\/")
        return (
            dashboard_template()
            .replace("__INITIAL_STATE__", initial_json)
            .replace("__LOGIN_BROWSER_REMOTE_NOTE__", json.dumps(LOGIN_BROWSER_REMOTE_NOTE))
            .replace("__ACTIVE_PROFILE__", active_profile)
            .replace("__DEFAULT_PROVIDER__", default_provider)
            .replace("__CODEX_VERSION__", codex_version)
            .replace("__BUSY__", busy)
            .replace("__ACTIVE_REQUESTS__", str(active_requests))
            .replace("__ACTIVE_WEBSOCKETS__", str(active_websockets))
            .replace("__ROWS__", rows)
        )

    def send_json(self, data: dict[str, Any], *, status: int = 200) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("content-type", "application/json; charset=utf-8")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.write_downstream(payload)
        except OSError:
            self.close_connection = True

    def send_response_bytes(self, status: int, headers: Any, payload: bytes) -> None:
        try:
            self.send_response(status)
            for key, value in headers.items():
                lower = key.lower()
                if lower in RESPONSE_HOP_BY_HOP_HEADERS or lower in {
                    "content-length",
                    "content-encoding",
                }:
                    continue
                self.send_header(key, value)
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.write_downstream(payload)
        except OSError:
            self.close_connection = True

    def send_logo_asset(self, name: str) -> None:
        payload = logo_asset_bytes(name)
        if payload is None:
            self.send_error(404)
            return
        try:
            self.send_response(200)
            self.send_header("content-type", "image/png")
            self.send_header("cache-control", "public, max-age=3600")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.write_downstream(payload)
        except OSError:
            self.close_connection = True

    def send_ui_asset(self, path: str) -> None:
        asset = ui_asset(path)
        if asset is None:
            self.send_error(404)
            return
        payload, content_type = asset
        try:
            self.send_response(200)
            self.send_header("content-type", content_type)
            self.send_header("cache-control", "no-cache")
            self.send_header("x-content-type-options", "nosniff")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.write_downstream(payload)
        except OSError:
            self.close_connection = True

    def send_html(self, data: str, *, status: int = 200) -> None:
        payload = data.encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.write_downstream(payload)
        except OSError:
            self.close_connection = True

    def send_dashboard_html(self, data: str, *, status: int = 200) -> None:
        payload = data.encode("utf-8")
        session = getattr(self.server, "ui_session_token", "")
        try:
            self.send_response(status)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("cache-control", "no-store")
            self.send_header("referrer-policy", "no-referrer")
            self.send_header("x-content-type-options", "nosniff")
            self.send_header("x-frame-options", "DENY")
            if cookie_header := self.dashboard_cookie_header(session):
                self.send_header("set-cookie", cookie_header)
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.write_downstream(payload)
        except OSError:
            self.close_connection = True

    def dashboard_cookie_header(self, session: str | None = None) -> str:
        value = session or getattr(self.server, "ui_session_token", "")
        if not value:
            return ""
        cookie = SimpleCookie()
        cookie[UI_SESSION_COOKIE] = value
        cookie[UI_SESSION_COOKIE]["httponly"] = True
        cookie[UI_SESSION_COOKIE]["samesite"] = "Strict"
        cookie[UI_SESSION_COOKIE]["path"] = "/"
        return cookie.output(header="").strip()

    def send_ui_session(self) -> None:
        try:
            self.send_response(204)
            self.send_header("cache-control", "no-store")
            if cookie_header := self.dashboard_cookie_header():
                self.send_header("set-cookie", cookie_header)
            self.send_header("content-length", "0")
            self.end_headers()
        except OSError:
            self.close_connection = True


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


def serve(
    port: int | None = None,
    host: str | None = None,
    *,
    allow_non_loopback: bool = False,
) -> None:
    paths = Paths()
    paths.ensure_base()
    configure_daemon_log_rotation(paths)
    bind_host = normalize_daemon_host(host)
    if not daemon_host_is_loopback(bind_host) and not allow_non_loopback:
        raise RuntimeError(
            f"refusing non-loopback daemon bind {bind_host!r}; "
            "pass --allow-non-loopback only behind an authenticated, encrypted boundary"
        )
    if not daemon_host_is_loopback(bind_host):
        sys.stderr.write(
            f"warning: Provision is listening beyond loopback on {bind_host}; "
            "protect this capability-bearing interface with authentication and encryption\n"
        )
    requested_port = DEFAULT_DAEMON_PORT if port is None else port
    try:
        server = ProvisionServer((bind_host, requested_port), paths)
    except OSError:
        if port is not None or requested_port == 0:
            raise
        sys.stderr.write(f"default port {DEFAULT_DAEMON_PORT} unavailable; using a dynamic port\n")
        server = ProvisionServer((bind_host, 0), paths)
    write_state(paths, bind_host, server.server_address[1])
    server.start_usage_auto_refresh()
    try:
        server.serve_forever()
    finally:
        server.stop_usage_auto_refresh()
        server.stop_connector_hub()
        server.stop_remote_agent_api()


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
