from __future__ import annotations

import base64
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
from datetime import datetime, timezone
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

PROTOCOL_VERSION = 18
DEFAULT_DAEMON_PORT = 4888
CHATGPT_USAGE_PATH = "/wham/usage"
USAGE_CACHE_MIN_INTERVAL_SECONDS = 1.0
USAGE_CACHE_WAIT_SECONDS = 5.0
DEFAULT_PROFILE_CODEX_LIMIT_ID = "provision_default_codex"
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class UpstreamRoute:
    CODEX_API = "codex-api"
    CHATGPT_BACKEND = "chatgpt-backend"


class WebSocketHandshakeRejected(RuntimeError):
    pass


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


def websocket_accept_key(key: str) -> str:
    digest = hashlib.sha1((key.strip() + WEBSOCKET_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


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
        return f"{label} {remaining:.0f}% left"
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


def percent_value(value: Any) -> float | None:
    if not isinstance(value, (int, float)):
        return None
    return max(0.0, min(100.0, float(value)))


def render_quota_window(window: Any, fallback: str) -> str:
    if not isinstance(window, dict):
        return ""
    label = html.escape(format_window_seconds(window.get("limit_window_seconds"), fallback))
    used_percent = percent_value(window.get("used_percent"))
    remaining = window.get("remaining")
    if used_percent is not None:
        remaining_percent = max(0.0, 100.0 - used_percent)
        level = "low" if remaining_percent <= 15 else "warn" if remaining_percent <= 35 else "good"
        value = f"{remaining_percent:.0f}% left"
        return f"""
          <div class="quota-window">
            <div class="quota-window-top">
              <span>{label}</span>
              <strong>{html.escape(value)}</strong>
            </div>
            <div class="quota-bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="{remaining_percent:.0f}" aria-label="{label} quota {html.escape(value)}">
              <span class="quota-fill {level}" style="width: {remaining_percent:.2f}%"></span>
            </div>
          </div>
        """
    if isinstance(remaining, (int, float)):
        return f"""
          <div class="quota-window count-only">
            <div class="quota-window-top">
              <span>{label}</span>
              <strong>{remaining:g} remaining</strong>
            </div>
          </div>
        """
    allowed = window.get("allowed")
    if isinstance(allowed, bool):
        value = "available" if allowed else "not available"
        return f"""
          <div class="quota-window count-only">
            <div class="quota-window-top">
              <span>{label}</span>
              <strong>{value}</strong>
            </div>
          </div>
        """
    return ""


def render_quota_bucket(bucket: dict[str, Any]) -> str:
    name = html.escape(str(bucket.get("name") or "Quota bucket"))
    feature = html.escape(str(bucket.get("metered_feature") or ""))
    rate_limit = bucket.get("rate_limit")
    if not isinstance(rate_limit, dict):
        return ""

    allowed = rate_limit.get("allowed")
    state = ""
    if isinstance(allowed, bool):
        state_class = "ok" if allowed else "blocked"
        state_text = "Available" if allowed else "Limited"
        state = f'<span class="quota-state {state_class}">{state_text}</span>'

    windows = [
        render_quota_window(rate_limit.get("primary_window"), "primary"),
        render_quota_window(rate_limit.get("secondary_window"), "secondary"),
    ]
    window_html = "".join(window for window in windows if window)
    if not window_html:
        window_html = '<div class="quota-muted">No window details</div>'

    feature_html = f'<span class="quota-feature">{feature}</span>' if feature and feature != "codex" else ""
    return f"""
      <div class="quota-bucket">
        <div class="quota-bucket-head">
          <span class="quota-bucket-name">{name}</span>
          {feature_html}
          {state}
        </div>
        <div class="quota-windows">{window_html}</div>
      </div>
    """


def render_quota_html(entry: dict[str, Any] | None) -> str:
    if not entry:
        return '<div class="quota-empty">No quota cached</div>'
    payload = entry.get("payload")
    error = entry.get("error")
    if not isinstance(payload, dict):
        if error:
            return f'<div class="quota-empty error">Refresh failed: {html.escape(str(error))}</div>'
        return '<div class="quota-empty">No quota cached</div>'

    buckets = quota_bucket_rows(payload)
    if buckets:
        bucket_html = "".join(render_quota_bucket(bucket) for bucket in buckets)
    else:
        bucket_html = '<div class="quota-muted">Quota payload has no bucket details</div>'
    error_html = (
        f'<div class="quota-refresh-error">Last refresh failed: {html.escape(str(error))}</div>'
        if error
        else ""
    )
    return f"""
      <div class="quota-panel">
        {bucket_html}
        {error_html}
      </div>
    """


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
        self.active_requests = 0
        self.active_lock = threading.Lock()
        self.usage_cache: dict[str, dict[str, Any]] = {}
        self.usage_cache_lock = threading.Lock()
        self.usage_refresh_lock = threading.Lock()
        self.last_usage_refresh_monotonic = 0.0

    def begin_request(self) -> None:
        with self.active_lock:
            self.active_requests += 1

    def end_request(self) -> None:
        with self.active_lock:
            self.active_requests -= 1

    def request_count(self) -> int:
        with self.active_lock:
            return self.active_requests

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

    def usage_cache_snapshot(self, profile: str) -> dict[str, Any] | None:
        with self.usage_cache_lock:
            entry = self.usage_cache.get(profile)
            return dict(entry) if entry else None

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
        if self.server.request_count() > 0:
            self.send_json({"error": "proxy is busy; switch after active requests finish"}, status=409)
            return
        try:
            self.server.store.set_active_profile(str(profile))
        except StoreError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
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
            if self.server.request_count() > 0:
                self.send_ui_state(
                    message=f"Switch disabled while {self.server.request_count()} request(s) are active"
                )
                return
            try:
                self.server.store.set_active_profile(profile)
            except StoreError as exc:
                self.send_ui_state(message=str(exc))
                return
            self.send_ui_state(message=f"Using {profile}")
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
        self.server.begin_request()
        started = time.monotonic()
        profile = self.server.store.active_profile(required=False)
        status_code: int | None = None
        try:
            status_code = self._proxy_to_upstream_once(
                method,
                parsed,
                body=body,
                retry_on_401=True,
                route=route,
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
            self.server.end_request()

    def _proxy_to_upstream_once(
        self,
        method: str,
        parsed: urllib.parse.ParseResult,
        *,
        body: bytes | None,
        retry_on_401: bool,
        route: str,
    ) -> int:
        profile = self.server.store.active_profile()
        assert profile is not None
        upstream_path = self.upstream_path(route, parsed)
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
                )
            self.send_response(exc.code)
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

        self.server.begin_request()
        self.close_connection = True
        upstream = None
        try:
            profile = self.server.store.active_profile()
            assert profile is not None
            auth_path = self.server.store.auth_path(profile)
            auth = ensure_fresh_chatgpt_auth(auth_path)
            upstream = self.open_upstream_websocket(parsed, auth)
            self.log_message("websocket tunnel established for profile %s", profile)
            self.relay_websocket(upstream)
        except WebSocketHandshakeRejected:
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
            self.server.end_request()

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
        return self.server.cached_usage_payload(
            profile,
            lambda: self.fetch_usage_payload_uncached(profile),
            force=force,
        )

    def fetch_usage_payload_uncached(self, profile: str, *, retry_on_401: bool = True) -> dict[str, Any] | None:
        auth_path = self.server.store.auth_path(profile)
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

    def open_upstream_websocket(
        self,
        parsed: urllib.parse.ParseResult,
        auth: dict[str, Any],
    ) -> ssl.SSLSocket | socket.socket:
        base = urllib.parse.urlparse(upstream_base_url(auth))
        scheme = "wss" if base.scheme == "https" else "ws"
        host = base.hostname
        if not host:
            raise OSError(f"invalid upstream base URL: {upstream_base_url(auth)}")
        port = base.port or (443 if scheme == "wss" else 80)
        upstream_path = base.path.rstrip("/") + parsed.path.removeprefix("/v1")
        if parsed.query:
            upstream_path += "?" + parsed.query

        raw = socket.create_connection((host, port), timeout=30)
        if scheme == "wss":
            upstream: ssl.SSLSocket | socket.socket = ssl.create_default_context().wrap_socket(
                raw,
                server_hostname=host,
            )
        else:
            upstream = raw
        upstream.settimeout(30)

        request = self.websocket_handshake_request(host, upstream_path, auth)
        upstream.sendall(request)
        response = self.read_websocket_handshake_response(upstream)
        self.connection.sendall(response)
        status_line = response.split(b"\r\n", 1)[0]
        if b" 101 " not in status_line:
            raise WebSocketHandshakeRejected(status_line.decode("iso-8859-1", errors="replace"))
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
            if lower in {"host", "connection", "upgrade"} or lower in UPSTREAM_IDENTITY_HEADERS:
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

    def relay_websocket(self, upstream: socket.socket) -> None:
        downstream = self.connection
        upstream.settimeout(None)
        downstream.settimeout(None)
        stop = threading.Event()

        def shutdown() -> None:
            stop.set()
            for sock in (upstream, downstream):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        def pipe(source: socket.socket, target: socket.socket) -> None:
            try:
                while not stop.is_set():
                    data = source.recv(65536)
                    if not data:
                        return
                    target.sendall(data)
            except OSError:
                return
            finally:
                shutdown()

        threads = [
            threading.Thread(target=pipe, args=(downstream, upstream), daemon=True),
            threading.Thread(target=pipe, args=(upstream, downstream), daemon=True),
        ]
        for thread in threads:
            thread.start()
        stop.wait()
        for thread in threads:
            thread.join(timeout=1)

    def is_chatgpt_profile(self, auth_path: Path) -> bool:
        try:
            with auth_path.open("r", encoding="utf-8") as handle:
                auth = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return False
        return isinstance(auth.get("tokens"), dict)

    def authorized_proxy_request(self) -> bool:
        auth = self.headers.get("authorization", "")
        if auth == f"Bearer {self.server.proxy_token}":
            return True
        return self.headers.get("openai-project", "") == self.local_project_sentinel()

    def local_project_sentinel(self) -> str:
        return f"provision-{self.server.proxy_token}"

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
        payload: dict[str, Any] = {
            "ok": True,
            "pid": os.getpid(),
            "port": self.server.server_address[1],
            "provision_protocol": PROTOCOL_VERSION,
            "active_profile": self.server.store.active_profile(required=False),
            "active_requests": self.server.request_count(),
        }
        if include_profiles:
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
            profile["quota_summary"] = usage_cache_summary(snapshot)
            profile["quota_html"] = render_quota_html(snapshot)
            profile["quota_updated"] = quota_updated_label(snapshot)
            profile["switch_disabled_reason"] = self.switch_disabled_reason(profile, status)
        return status

    def switch_disabled_reason(self, profile: dict[str, Any], status: dict[str, Any]) -> str:
        if profile.get("active"):
            return "Current profile"
        active_requests = status.get("active_requests")
        if isinstance(active_requests, int) and active_requests > 0:
            return f"Disabled until {active_requests} active request(s) finish"
        return ""

    def render_profile_rows(self, status: dict[str, Any]) -> str:
        return "".join(self.render_profile_row(profile) for profile in status.get("profiles", []))

    def render_profile_row(self, profile: dict[str, Any]) -> str:
        profile_name = str(profile.get("name") or "")
        name = html.escape(profile_name)
        email = html.escape(profile.get("email") or profile.get("account_id") or "")
        plan = html.escape(profile.get("plan_type") or "unknown")
        quota = profile.get("quota_html") or '<div class="quota-empty">No quota cached</div>'
        quota_updated = str(profile.get("quota_updated") or "")
        active = " active" if profile.get("active") else ""
        badge = '<span class="badge active-badge">Active</span>' if profile.get("active") else ""
        switch_reason = str(profile.get("switch_disabled_reason") or "")
        disabled = "disabled" if switch_reason else ""
        switch_hint = (
            f'<div class="action-note">{html.escape(switch_reason)}</div>' if switch_reason else ""
        )
        quota_hint = (
            f'<div class="action-note quota-note">{html.escape(quota_updated)}</div>'
            if quota_updated
            else ""
        )
        token = html.escape(self.server.proxy_token)
        return f"""
          <tr class="profile-row{active}" data-profile="{name}">
            <td class="profile-cell">
              <div class="profile-name">{name}{badge}</div>
              <div class="profile-email">{email}</div>
            </td>
            <td class="plan-cell">{plan}</td>
            <td class="quota-cell">{quota}</td>
            <td class="actions">
              <form method="post" action="/api/switch" data-action="switch" data-profile="{name}">
                <input type="hidden" name="token" value="{token}">
                <input type="hidden" name="profile" value="{name}">
                <button class="primary-action" {disabled} title="{html.escape(switch_reason)}">Use</button>
              </form>
              {switch_hint}
              <form method="post" action="/api/refresh-quota" data-action="refresh_quota" data-profile="{name}">
                <input type="hidden" name="token" value="{token}">
                <input type="hidden" name="profile" value="{name}">
                <button class="secondary-action">Refresh quota</button>
              </form>
              {quota_hint}
            </td>
          </tr>
        """

    def render_ui(self) -> str:
        status = self.ui_status_payload()
        rows = self.render_profile_rows(status)
        active_profile = html.escape(str(status.get("active_profile") or "none"))
        active_requests = int(status.get("active_requests") or 0)
        busy = "busy" if active_requests else "idle"
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
	      --amber: #b7791f;
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
	        --amber: #d79a2b;
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
		      --amber: #b7791f;
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
		      --amber: #d79a2b;
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
      overflow: hidden;
      box-shadow: var(--shadow);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }
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
	    .profile-cell { width: 250px; min-width: 0; }
	    .plan-cell { width: 110px; color: var(--muted); }
	    .actions { width: 155px; }
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
	      border-radius: 6px;
	      border: 1px solid var(--line);
	      background: var(--button-bg);
	      color: var(--ink);
      font-weight: 650;
      cursor: pointer;
      white-space: nowrap;
    }
	    button:hover:not(:disabled) { border-color: var(--muted); background: var(--button-hover); }
	    button:disabled { color: var(--button-disabled-ink); background: var(--button-disabled-bg); cursor: not-allowed; }
    .primary-action {
      background: var(--red);
      border-color: var(--red);
      color: #fff;
    }
    .primary-action:hover:not(:disabled) { background: var(--red-dark); border-color: var(--red-dark); }
    form { margin: 0 0 7px; }
    form:last-child { margin-bottom: 0; }
    .action-note {
      margin: -2px 0 7px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.3;
    }
    .quota-note {
      margin: -2px 0 0;
    }
		    .quota-panel { display: grid; gap: 10px; }
    .quota-bucket {
	      border: 1px solid var(--line);
	      border-radius: 6px;
	      padding: 10px;
	      background: var(--surface);
	      max-width: 100%;
	      overflow: hidden;
	    }
    .quota-bucket-head {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 8px;
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
    .quota-state {
      margin-left: auto;
      font-size: 12px;
      font-weight: 700;
    }
    .quota-state.ok { color: var(--green); }
    .quota-state.blocked { color: var(--danger); }
	    .quota-windows {
	      display: grid;
	      grid-template-columns: 1fr;
	      gap: 8px;
	      min-width: 0;
	    }
	    .quota-window {
	      min-width: 0;
	    }
	    .quota-window-top {
	      display: flex;
	      justify-content: space-between;
	      gap: 10px;
	      margin-bottom: 5px;
	      color: var(--muted);
	      font-size: 12px;
	      min-width: 0;
	    }
	    .quota-window-top span,
	    .quota-window-top strong { min-width: 0; overflow-wrap: anywhere; }
	    .quota-window-top strong { color: var(--ink); }
	    .quota-bar {
	      height: 8px;
	      background: var(--bar-bg);
	      border-radius: 999px;
	      overflow: hidden;
	    }
    .quota-fill {
      display: block;
      height: 100%;
      border-radius: inherit;
    }
    .quota-fill.good { background: var(--green); }
    .quota-fill.warn { background: var(--amber); }
    .quota-fill.low { background: var(--danger); }
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
	        <span class="pill"><span id="proxyDot" class="dot"></span><span id="connectionState">Live (__BUSY__)</span></span>
	      </div>
	      <div class="top-actions">
	        <button id="themeToggle" class="theme-toggle" type="button" aria-label="Toggle color theme" title="Toggle color theme"></button>
	      </div>
	    </header>
    <div id="message" class="message" aria-live="polite"></div>
    <div id="busyNotice" class="notice" aria-live="polite"></div>
    <section class="profiles">
      <table>
        <thead>
          <tr><th>Profile</th><th>Plan</th><th>Quota</th><th></th></tr>
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
	      const activeRequests = Number(document.getElementById("activeRequests").textContent || "0");
	      const text = label === "Live" ? `Live (${activeRequests ? "busy" : "idle"})` : label;
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

    function profileRow(profile, pendingAction, pendingProfile) {
      const name = String(profile.name || "");
      const reason = String(profile.switch_disabled_reason || "");
	      const pending = pendingProfile === name ? pendingAction : "";
	      const disabled = reason || pending ? "disabled" : "";
	      const useTitle = reason || (pending ? "Action in progress" : "");
	      const badge = profile.active ? '<span class="badge active-badge">Active</span>' : "";
	      const note = reason ? `<div class="action-note">${escapeHtml(reason)}</div>` : "";
	      const updated = profile.quota_updated
	        ? `<div class="action-note quota-note">${escapeHtml(profile.quota_updated)}</div>`
	        : "";
	      const isRefreshing = pending === "refresh_quota";
	      const quota = isRefreshing
	        ? '<div class="quota-loading"><span class="spinner"></span><span>Refreshing quota</span></div>'
	        : profile.quota_html || '<div class="quota-empty">No quota cached</div>';
      return `
        <tr class="profile-row${profile.active ? " active" : ""}" data-profile="${escapeHtml(name)}">
          <td class="profile-cell">
            <div class="profile-name">${escapeHtml(name)}${badge}</div>
            <div class="profile-email">${escapeHtml(profile.email || profile.account_id || "")}</div>
          </td>
          <td class="plan-cell">${escapeHtml(profile.plan_type || "unknown")}</td>
          <td class="quota-cell">${quota}</td>
          <td class="actions">
            <form method="post" action="/api/switch" data-action="switch" data-profile="${escapeHtml(name)}">
              <input type="hidden" name="token" value="${escapeHtml(TOKEN)}">
              <input type="hidden" name="profile" value="${escapeHtml(name)}">
              <button class="primary-action" ${disabled} title="${escapeHtml(useTitle)}">Use</button>
            </form>
            ${note}
	            <form method="post" action="/api/refresh-quota" data-action="refresh_quota" data-profile="${escapeHtml(name)}">
	              <input type="hidden" name="token" value="${escapeHtml(TOKEN)}">
	              <input type="hidden" name="profile" value="${escapeHtml(name)}">
	              <button class="secondary-action" ${pending === "refresh_quota" ? "disabled" : ""}>${pending === "refresh_quota" ? "Refreshing" : "Refresh quota"}</button>
	            </form>
	            ${updated}
	          </td>
        </tr>
      `;
    }

    function render(packet) {
      const status = packet.status || {};
      const activeRequests = Number(status.active_requests || 0);
	      document.getElementById("activeProfile").textContent = status.active_profile || "none";
	      document.getElementById("activeRequests").textContent = String(activeRequests);
	      const connection = document.getElementById("connectionState");
	      const isDisconnected = connection.textContent === "Disconnected";
	      if (!isDisconnected) {
	        connection.textContent = `Live (${activeRequests ? "busy" : "idle"})`;
	        document.getElementById("proxyDot").className = "dot" + (activeRequests ? " busy" : "");
	      }
      document.getElementById("busyNotice").textContent = activeRequests
        ? `Profile switching is disabled while ${activeRequests} upstream request(s) finish.`
        : "";
      document.getElementById("profileRows").innerHTML = (status.profiles || [])
        .map((profile) => profileRow(profile, packet.pending_action, packet.pending_profile))
        .join("");
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
	      socket.addEventListener("open", () => setConnection("Live", ""));
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
	        setConnection("Disconnected", "disconnected");
	        reconnectTimer = setTimeout(connect, 1500);
	      });
	      socket.addEventListener("error", () => setConnection("Disconnected", "disconnected"));
    }

	    document.addEventListener("submit", (event) => {
      const form = event.target.closest("form[data-action]");
      if (!form) return;
      if (!socket || socket.readyState !== WebSocket.OPEN) return;
      event.preventDefault();
      socket.send(JSON.stringify({
        action: form.dataset.action,
        profile: form.dataset.profile,
        token: TOKEN
	      }));
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
    server.serve_forever()


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
