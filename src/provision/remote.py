"""Bounded, local-only primitives for Provision's future remote control path.

This module deliberately contains no listener, relay, browser endpoint, or
cryptographic transport.  It is the daemon-side boundary a future approved
transport will use after its production-readiness gates are met.

The existing dashboard and proxy must never be repurposed as this interface:
their tokens and payload shapes have different security and performance
properties.  Values returned by this module are therefore small, explicit,
and free of credentials, raw quota payloads, HTML, search indexes, and full
transcript text unless a caller requests one bounded message page.
"""

from __future__ import annotations

import base64
from collections import deque
from collections.abc import Iterable, Mapping
import copy
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import struct
import threading
from typing import Any, Callable


REMOTE_PROTOCOL_VERSION = 1
REMOTE_DELTA_BUFFER_LIMIT = 500
REMOTE_INITIAL_STATE_MAX_BYTES = 100 * 1024
REMOTE_INITIAL_STATE_SESSION_LIMIT = 256
REMOTE_DELTA_SYNC_MAX_BYTES = 64 * 1024
REMOTE_DISCUSSION_PAGE_ENTRIES = 40
REMOTE_DISCUSSION_PAGE_MAX_BYTES = 64 * 1024
REMOTE_DISCUSSION_ENTRY_TEXT_MAX_BYTES = 16 * 1024
REMOTE_MESSAGE_EXPAND_MAX_BYTES = 256 * 1024
REMOTE_MESSAGE_EXPAND_CONTENT_MAX_BYTES = 240 * 1024
REMOTE_ACTION_PROMPT_MAX_BYTES = 32 * 1024
REMOTE_ACTION_IDEMPOTENCY_LIMIT = 500
REMOTE_ACTION_STATE_VERSION = 2
REMOTE_ACTION_STATE_MAX_BYTES = 512 * 1024
REMOTE_DEVICE_STATE_VERSION = 1
REMOTE_AGENT_REQUEST_MAX_BYTES = 64 * 1024
REMOTE_AGENT_RESPONSE_MAX_BYTES = REMOTE_MESSAGE_EXPAND_MAX_BYTES

REMOTE_CAPABILITIES = frozenset(
    {
        "read_state",
        "read_discussion",
        "send_prompt",
        "interrupt_turn",
        "resume_or_fork",
        "switch_profile",
        "manage_devices",
    }
)
REMOTE_DEFAULT_CAPABILITIES = frozenset({"read_state", "read_discussion"})
REMOTE_MUTATING_CAPABILITIES = frozenset(
    {"send_prompt", "interrupt_turn", "resume_or_fork", "switch_profile"}
)
REMOTE_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$")
REMOTE_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$")


class RemoteError(RuntimeError):
    """A remote-boundary request was malformed or cannot be completed."""


class RemoteAuthorizationError(RemoteError):
    """A paired device lacks a required capability."""


class RemoteCursorError(RemoteError):
    """An opaque discussion or expansion cursor was malformed or stale."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def compact_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def truncate_utf8(value: Any, limit: int, *, suffix: str = "…") -> tuple[str, bool]:
    """Limit a value by encoded bytes without emitting invalid UTF-8."""
    text = str(value or "")
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text, False
    if limit <= 0:
        return "", bool(text)
    marker = suffix.encode("utf-8")
    if len(marker) > limit:
        marker = marker[:limit]
        while marker:
            try:
                return marker.decode("utf-8"), True
            except UnicodeDecodeError:
                marker = marker[:-1]
        return "", True
    prefix = encoded[: limit - len(marker)]
    while prefix:
        try:
            return prefix.decode("utf-8").rstrip() + suffix, True
        except UnicodeDecodeError:
            prefix = prefix[:-1]
    return suffix, True


def bounded_string(value: Any, limit: int) -> str:
    return truncate_utf8(value, limit)[0]


def opaque_identifier(secret: bytes, namespace: str, value: str, *, prefix: str) -> str:
    if not secret:
        raise RemoteError("remote identifier secret is unavailable")
    material = namespace.encode("utf-8") + b"\0" + value.encode("utf-8")
    digest = hmac.new(secret, material, hashlib.sha256).hexdigest()[:32]
    return f"{prefix}_{digest}"


def remote_session_id(secret: bytes, session_key: str) -> str:
    return opaque_identifier(secret, "session", session_key, prefix="rs")


def remote_message_id(secret: bytes, session_id: str, item_id: str) -> str:
    return opaque_identifier(secret, f"message:{session_id}", item_id, prefix="rm")


def remote_session_audit_ref(secret: bytes, session_key: str) -> str:
    return opaque_identifier(secret, "audit-session", session_key, prefix="session")


class RemoteCursorCodec:
    """Authenticates opaque cursors without exposing local indexes or paths."""

    def __init__(self, secret: bytes) -> None:
        if len(secret) < 16:
            raise RemoteError("remote cursor secret is too short")
        self.secret = bytes(secret)

    def encode(self, payload: Mapping[str, Any]) -> str:
        body = compact_json_bytes(dict(payload))
        tag = hmac.new(self.secret, body, hashlib.sha256).digest()[:16]
        encoded_body = base64.urlsafe_b64encode(body).rstrip(b"=")
        encoded_tag = base64.urlsafe_b64encode(tag).rstrip(b"=")
        return (encoded_body + b"." + encoded_tag).decode("ascii")

    def decode(self, token: str) -> dict[str, Any]:
        if not isinstance(token, str) or "." not in token or len(token) > 2048:
            raise RemoteCursorError("invalid remote cursor")
        raw_body, raw_tag = token.split(".", 1)
        try:
            body = base64.urlsafe_b64decode(raw_body + "=" * (-len(raw_body) % 4))
            tag = base64.urlsafe_b64decode(raw_tag + "=" * (-len(raw_tag) % 4))
        except (ValueError, UnicodeEncodeError) as exc:
            raise RemoteCursorError("invalid remote cursor") from exc
        expected = hmac.new(self.secret, body, hashlib.sha256).digest()[:16]
        if len(tag) != len(expected) or not hmac.compare_digest(tag, expected):
            raise RemoteCursorError("invalid remote cursor")
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RemoteCursorError("invalid remote cursor") from exc
        if not isinstance(value, dict):
            raise RemoteCursorError("invalid remote cursor")
        return value


def validate_remote_device_id(value: Any) -> str:
    device_id = str(value or "")
    if not REMOTE_DEVICE_ID_RE.fullmatch(device_id):
        raise RemoteError("invalid remote device ID")
    return device_id


def validate_remote_capabilities(values: Iterable[Any]) -> list[str]:
    capabilities = sorted({str(value) for value in values})
    unknown = [value for value in capabilities if value not in REMOTE_CAPABILITIES]
    if unknown:
        raise RemoteError(f"unsupported remote capability: {unknown[0]}")
    return capabilities


class RemoteDeviceRegistry:
    """Daemon-owned authorization and metadata; the transport owns crypto keys."""

    def __init__(self, path: Path, audit_path: Path) -> None:
        self.path = path
        self.audit_path = audit_path
        self.lock = threading.RLock()
        self.devices = self._load()

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(payload, dict) or payload.get("version") != REMOTE_DEVICE_STATE_VERSION:
            return {}
        raw_devices = payload.get("devices")
        if not isinstance(raw_devices, dict):
            return {}
        devices: dict[str, dict[str, Any]] = {}
        for raw_id, raw_device in raw_devices.items():
            try:
                device_id = validate_remote_device_id(raw_id)
            except RemoteError:
                continue
            if not isinstance(raw_device, dict):
                continue
            try:
                capabilities = validate_remote_capabilities(raw_device.get("capabilities") or [])
            except RemoteError:
                continue
            fingerprint = bounded_string(raw_device.get("identity_fingerprint"), 256)
            if not fingerprint:
                continue
            devices[device_id] = {
                "identity_fingerprint": fingerprint,
                "capabilities": capabilities,
                "created_at": bounded_string(raw_device.get("created_at"), 64),
                "updated_at": bounded_string(raw_device.get("updated_at"), 64),
                "revoked_at": bounded_string(raw_device.get("revoked_at"), 64),
            }
        return devices

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": REMOTE_DEVICE_STATE_VERSION,
            "devices": self.devices,
        }
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary.chmod(0o600)
        temporary.replace(self.path)
        self.path.chmod(0o600)

    @staticmethod
    def _public_device(device_id: str, details: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "device_id": device_id,
            "identity_fingerprint": str(details.get("identity_fingerprint") or ""),
            "capabilities": list(details.get("capabilities") or []),
            "created_at": str(details.get("created_at") or ""),
            "updated_at": str(details.get("updated_at") or ""),
            "revoked_at": str(details.get("revoked_at") or ""),
        }

    def list_devices(self) -> list[dict[str, Any]]:
        with self.lock:
            return [
                self._public_device(device_id, details)
                for device_id, details in sorted(self.devices.items())
            ]

    def enroll(
        self,
        device_id: str,
        identity_fingerprint: str,
        *,
        capabilities: Iterable[Any] = REMOTE_DEFAULT_CAPABILITIES,
    ) -> dict[str, Any]:
        device_id = validate_remote_device_id(device_id)
        fingerprint = bounded_string(identity_fingerprint, 256)
        if not fingerprint:
            raise RemoteError("remote device identity fingerprint is required")
        validated_capabilities = validate_remote_capabilities(capabilities)
        now = utc_now()
        with self.lock:
            existing = self.devices.get(device_id)
            self.devices[device_id] = {
                "identity_fingerprint": fingerprint,
                "capabilities": validated_capabilities,
                "created_at": str(existing.get("created_at") or now) if existing else now,
                "updated_at": now,
                "revoked_at": "",
            }
            self._save_locked()
            return self._public_device(device_id, self.devices[device_id])

    def set_capabilities(self, device_id: str, capabilities: Iterable[Any]) -> dict[str, Any]:
        device_id = validate_remote_device_id(device_id)
        validated_capabilities = validate_remote_capabilities(capabilities)
        with self.lock:
            device = self.devices.get(device_id)
            if not device:
                raise RemoteError("unknown remote device")
            if device.get("revoked_at"):
                raise RemoteAuthorizationError("remote device is revoked")
            device["capabilities"] = validated_capabilities
            device["updated_at"] = utc_now()
            self._save_locked()
            return self._public_device(device_id, device)

    def revoke(self, device_id: str) -> None:
        device_id = validate_remote_device_id(device_id)
        with self.lock:
            device = self.devices.get(device_id)
            if not device:
                raise RemoteError("unknown remote device")
            if not device.get("revoked_at"):
                now = utc_now()
                device["revoked_at"] = now
                device["updated_at"] = now
                self._save_locked()

    def authorize(self, device_id: str, capability: str) -> dict[str, Any]:
        device_id = validate_remote_device_id(device_id)
        if capability not in REMOTE_CAPABILITIES:
            raise RemoteError("unsupported remote capability")
        with self.lock:
            device = self.devices.get(device_id)
            if not device:
                raise RemoteAuthorizationError("unknown remote device")
            if device.get("revoked_at"):
                raise RemoteAuthorizationError("remote device is revoked")
            if capability not in set(device.get("capabilities") or []):
                raise RemoteAuthorizationError(f"remote device lacks capability: {capability}")
            return self._public_device(device_id, device)

    def append_audit(
        self,
        *,
        event: str,
        device_id: str = "",
        capability: str = "",
        session_ref: str = "",
        outcome: str = "",
        request_ref: str = "",
    ) -> None:
        """Append metadata only; caller must never pass plaintext payloads."""
        row = {
            "ts": utc_now(),
            "event": bounded_string(event, 64),
            "device_id": bounded_string(device_id, 128),
            "capability": bounded_string(capability, 64),
            "session_ref": bounded_string(session_ref, 64),
            "outcome": bounded_string(outcome, 64),
            "request_ref": bounded_string(request_ref, 128),
        }
        with self.lock:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
            self.audit_path.chmod(0o600)


def safe_context_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, Any] = {}
    for key in (
        "window_tokens",
        "input_tokens",
        "total_tokens",
        "remaining_tokens",
        "remaining_percent",
    ):
        item = value.get(key)
        if isinstance(item, bool):
            continue
        if isinstance(item, int) and not isinstance(item, bool):
            if abs(item) <= 10**15:
                result[key] = item
        elif isinstance(item, float) and math.isfinite(item):
            number = int(item) if item.is_integer() else item
            if abs(number) <= 10**15:
                result[key] = number
    label = value.get("label")
    if isinstance(label, str) and label:
        result["label"] = bounded_string(label, 96)
    return result


def session_current_turn_id(session: Mapping[str, Any]) -> str:
    active_details = session.get("active_details")
    if isinstance(active_details, Mapping):
        tunnels = active_details.get("tunnels")
        if isinstance(tunnels, list):
            for tunnel in tunnels:
                if isinstance(tunnel, Mapping) and isinstance(tunnel.get("turn_id"), str) and tunnel.get("turn_id"):
                    return bounded_string(tunnel["turn_id"], 160)
    turns = session.get("turns")
    if isinstance(turns, list):
        for turn in reversed(turns):
            if isinstance(turn, Mapping) and isinstance(turn.get("turn_id"), str) and turn.get("turn_id"):
                return bounded_string(turn["turn_id"], 160)
    return ""


def build_remote_session_summaries(control_plane: Any, secret: bytes) -> list[dict[str, Any]]:
    """Convert a dashboard control plane into the small remote state contract."""
    if not isinstance(control_plane, Mapping):
        return []
    raw_sessions = control_plane.get("sessions")
    if not isinstance(raw_sessions, list):
        return []
    summaries: list[dict[str, Any]] = []
    for raw in raw_sessions:
        if not isinstance(raw, Mapping):
            continue
        key = raw.get("key")
        if not isinstance(key, str) or not key:
            continue
        label = raw.get("title") or raw.get("name") or raw.get("display") or "Session"
        interaction = raw.get("interaction")
        summaries.append(
            {
                "session_id": remote_session_id(secret, key),
                "label": bounded_string(label, 240),
                "profile": bounded_string(raw.get("associated_profile"), 96),
                "active": bool(raw.get("active")),
                "interactive": bool(isinstance(interaction, Mapping) and interaction.get("available")),
                "current_turn_id": session_current_turn_id(raw),
                "context": safe_context_summary(raw.get("context")),
                "quota": bounded_string(raw.get("quota_summary"), 240),
                "_source_session_key": key,
            }
        )
    return summaries


def public_remote_session(summary: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize the only fields allowed into an ordinary state snapshot."""
    session_id = summary.get("session_id")
    result: dict[str, Any] = {}
    if isinstance(session_id, str) and session_id:
        result["session_id"] = bounded_string(session_id, 80)
    for key, limit in (("label", 240), ("profile", 96), ("current_turn_id", 160), ("quota", 240)):
        value = summary.get(key)
        if isinstance(value, str):
            result[key] = bounded_string(value, limit)
    for key in ("active", "interactive"):
        if key in summary:
            result[key] = bool(summary.get(key))
    context = safe_context_summary(summary.get("context"))
    if context:
        result["context"] = context
    unread_revision = summary.get("unread_revision")
    if isinstance(unread_revision, int) and not isinstance(unread_revision, bool) and unread_revision >= 0:
        result["unread_revision"] = unread_revision
    return result


class RemoteStateSynchronizer:
    """Maintains a bounded session-index snapshot and replayable typed deltas."""

    _METRIC_FIELDS = frozenset(
        {"active", "interactive", "current_turn_id", "context", "quota", "unread_revision"}
    )

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.revision = 0
        # This changes only when the session index itself changes. Discussion
        # traffic advances ``revision`` too, but must not invalidate an
        # in-progress page walk through an otherwise unchanged session list.
        self.session_index_generation = 0
        self.sessions: dict[str, dict[str, Any]] = {}
        self.session_keys: dict[str, str] = {}
        self.deltas: deque[dict[str, Any]] = deque()
        self.history_floor_revision = 0

    def _append_delta_locked(self, delta: dict[str, Any]) -> None:
        self.deltas.append(delta)
        while len(self.deltas) > REMOTE_DELTA_BUFFER_LIMIT:
            removed = self.deltas.popleft()
            self.history_floor_revision = max(
                self.history_floor_revision,
                int(removed.get("revision") or 0),
            )

    def refresh(self, summaries: Iterable[Mapping[str, Any]]) -> int:
        candidate: dict[str, dict[str, Any]] = {}
        candidate_keys: dict[str, str] = {}
        for raw in summaries:
            session_id = raw.get("session_id")
            source_key = raw.get("_source_session_key")
            if not isinstance(session_id, str) or not session_id or not isinstance(source_key, str) or not source_key:
                continue
            candidate[session_id] = dict(raw)
            candidate_keys[session_id] = source_key
        with self.lock:
            changes: list[dict[str, Any]] = []
            for session_id in sorted(set(self.sessions) - set(candidate)):
                changes.append({"type": "session_remove", "session_id": session_id})
            for session_id in sorted(candidate):
                current = candidate[session_id]
                previous = self.sessions.get(session_id)
                if previous is None:
                    changes.append(
                        {
                            "type": "session_upsert",
                            "session": public_remote_session(current),
                        }
                    )
                    continue
                before = public_remote_session(previous)
                after = public_remote_session(current)
                changed_keys = {
                    key
                    for key in set(before) | set(after)
                    if key != "unread_revision" and before.get(key) != after.get(key)
                }
                if not changed_keys:
                    current["unread_revision"] = previous.get("unread_revision", self.revision)
                    continue
                previous_turn_id = str(before.get("current_turn_id") or "")
                current_turn_id = str(after.get("current_turn_id") or "")
                if previous_turn_id != current_turn_id:
                    if previous_turn_id:
                        changes.append(
                            {
                                "type": "turn_completed",
                                "session_id": session_id,
                                "turn_id": previous_turn_id,
                            }
                        )
                    if current_turn_id:
                        changes.append(
                            {
                                "type": "turn_started",
                                "session_id": session_id,
                                "turn_id": current_turn_id,
                            }
                        )
                    changed_keys.discard("current_turn_id")
                if not changed_keys:
                    continue
                if changed_keys <= self._METRIC_FIELDS:
                    changes.append(
                        {
                            "type": "session_metrics",
                            "session_id": session_id,
                            "metrics": {key: after.get(key) for key in sorted(changed_keys)},
                        }
                    )
                else:
                    changes.append(
                        {
                            "type": "session_upsert",
                            "session": after,
                        }
                    )
            if not changes:
                self.sessions = candidate
                self.session_keys = candidate_keys
                return self.revision

            self.revision += 1
            revision = self.revision
            # A Discussion/context/quota change advances the state revision,
            # but only an index-affecting change should force a client to
            # restart a paged session walk. ``active`` participates in the
            # ordering; the other metric fields do not.
            if any(
                change.get("type") in {"session_remove", "session_upsert"}
                or (
                    change.get("type") == "session_metrics"
                    and isinstance(change.get("metrics"), dict)
                    and "active" in change["metrics"]
                )
                for change in changes
            ):
                self.session_index_generation += 1
            changed_session_ids: set[str] = set()
            for change in changes:
                if change.get("type") == "session_remove":
                    continue
                session = change.get("session")
                session_id = (
                    str(session.get("session_id") or "")
                    if isinstance(session, dict)
                    else str(change.get("session_id") or "")
                )
                if session_id:
                    changed_session_ids.add(session_id)
            for change in changes:
                metrics = change.get("metrics")
                if change.get("type") != "session_remove":
                    session = change.get("session")
                    if isinstance(session, dict):
                        session["unread_revision"] = revision
                if isinstance(metrics, dict):
                    metrics["unread_revision"] = revision
                change["revision"] = revision
                self._append_delta_locked(change)
            for session_id, summary in candidate.items():
                previous = self.sessions.get(session_id)
                if previous is not None and summary.get("unread_revision") is None:
                    summary["unread_revision"] = (
                        revision
                        if session_id in changed_session_ids
                        else previous.get("unread_revision", revision)
                    )
                elif summary.get("unread_revision") is None:
                    summary["unread_revision"] = revision
            self.sessions = candidate
            self.session_keys = candidate_keys
            return revision

    def record_discussion_change(
        self,
        session_id: str,
        entry: Mapping[str, Any],
        *,
        replace: bool,
    ) -> int:
        """Append one bounded live Discussion delta without rebuilding history."""
        public_entry = public_remote_discussion_entry(entry)
        message_id = public_entry.get("message_id")
        if not isinstance(session_id, str) or not session_id or not isinstance(message_id, str) or not message_id:
            raise RemoteError("invalid remote discussion delta")
        with self.lock:
            self.revision += 1
            revision = self.revision
            session = self.sessions.get(session_id)
            if session is not None:
                session["unread_revision"] = revision
            self._append_delta_locked(
                {
                    "type": "message_replace" if replace else "message_append",
                    "session_id": session_id,
                    "message": public_entry,
                    "revision": revision,
                }
            )
            return revision

    def record_discussion_remove(self, session_id: str, message_id: str) -> int:
        """Remove one trimmed Discussion entry from a live client cache."""
        if not isinstance(session_id, str) or not session_id:
            raise RemoteError("invalid remote discussion delta")
        if not isinstance(message_id, str) or not message_id:
            raise RemoteError("invalid remote discussion delta")
        with self.lock:
            self.revision += 1
            revision = self.revision
            session = self.sessions.get(session_id)
            if session is not None:
                session["unread_revision"] = revision
            self._append_delta_locked(
                {
                    "type": "message_remove",
                    "session_id": session_id,
                    "message_id": message_id,
                    "revision": revision,
                }
            )
            return revision

    def session_key_for_id(self, session_id: str) -> str | None:
        with self.lock:
            value = self.session_keys.get(session_id)
            return str(value) if value else None

    def session_payload(self, session_id: str) -> dict[str, Any] | None:
        with self.lock:
            value = self.sessions.get(session_id)
            return public_remote_session(value) if value is not None else None

    def state_payload(
        self,
        *,
        cursor_codec: RemoteCursorCodec | None = None,
        cursor: str = "",
    ) -> dict[str, Any]:
        with self.lock:
            sessions = [public_remote_session(item) for item in self.sessions.values()]
            sessions.sort(key=lambda item: (not bool(item.get("active")), str(item.get("label") or ""), str(item.get("session_id") or "")))
            start = 0
            if cursor:
                if cursor_codec is None:
                    raise RemoteCursorError("remote session cursor is unavailable")
                decoded = cursor_codec.decode(cursor)
                if decoded.get("kind") != "session_index":
                    raise RemoteCursorError("remote session cursor is invalid")
                if decoded.get("generation") != self.session_index_generation:
                    raise RemoteCursorError("remote session cursor has expired")
                after_session_id = decoded.get("after_session_id")
                if not isinstance(after_session_id, str) or not after_session_id:
                    raise RemoteCursorError("remote session cursor is invalid")
                matching_indexes = [
                    index
                    for index, session in enumerate(sessions)
                    if session.get("session_id") == after_session_id
                ]
                if not matching_indexes:
                    raise RemoteCursorError("remote session cursor has expired")
                start = matching_indexes[0] + 1
            selected = sessions[start : start + REMOTE_INITIAL_STATE_SESSION_LIMIT]
            while True:
                end = start + len(selected)
                omitted = max(0, len(sessions) - end)
                payload: dict[str, Any] = {
                    "protocol_version": REMOTE_PROTOCOL_VERSION,
                    "revision": self.revision,
                    "session_count": len(sessions),
                    "sessions": selected,
                    "truncated_sessions": bool(omitted),
                    "has_more_sessions": bool(omitted and cursor_codec is not None),
                    "next_session_cursor": "",
                    "omitted_sessions": omitted,
                }
                if omitted:
                    if cursor_codec is None:
                        # Callers that do not supply a codec still receive a
                        # bounded state snapshot, but cannot continue with an
                        # unauthenticated cursor.
                        payload["has_more_sessions"] = False
                    elif selected:
                        payload["next_session_cursor"] = cursor_codec.encode(
                            {
                                "kind": "session_index",
                                "generation": self.session_index_generation,
                                "after_session_id": selected[-1]["session_id"],
                            }
                        )
                    else:
                        raise RemoteError("remote session summary exceeds its byte budget")
                if len(compact_json_bytes(payload)) <= REMOTE_INITIAL_STATE_MAX_BYTES:
                    return payload
                if not selected:
                    raise RemoteError("remote initial state exceeds its byte budget")
                # Include the continuation cursor in the size calculation so
                # a full page never becomes oversized only after pagination
                # metadata is attached.
                selected.pop()

    def deltas_since(self, revision: int) -> list[dict[str, Any]] | None:
        if not isinstance(revision, int) or revision < 0:
            raise RemoteError("invalid remote revision")
        with self.lock:
            if revision < self.history_floor_revision or revision > self.revision:
                return None
            return [copy.deepcopy(delta) for delta in self.deltas if int(delta.get("revision") or 0) > revision]


def transcript_item_local_id(item: Mapping[str, Any], index: int) -> str:
    value = item.get("item_id")
    if isinstance(value, str) and value:
        return value
    fallback = "\0".join(
        (
            str(item.get("ts") or ""),
            str(item.get("updated_at") or ""),
            str(item.get("role") or ""),
            str(item.get("turn_id") or ""),
            str(item.get("call_id") or ""),
            str(index),
        )
    )
    return "legacy_" + hashlib.sha256(fallback.encode("utf-8")).hexdigest()[:24]


def remote_discussion_entry(
    *,
    secret: bytes,
    session_id: str,
    item: Mapping[str, Any],
    index: int,
) -> dict[str, Any]:
    item_id = transcript_item_local_id(item, index)
    text, text_truncated = truncate_utf8(item.get("text"), REMOTE_DISCUSSION_ENTRY_TEXT_MAX_BYTES)
    return {
        "message_id": remote_message_id(secret, session_id, item_id),
        "role": bounded_string(item.get("role"), 48),
        "turn_id": bounded_string(item.get("turn_id"), 160),
        "updated_at": bounded_string(item.get("updated_at") or item.get("ts"), 64),
        "text": text,
        "truncated": bool(item.get("truncated")) or text_truncated,
        "_local_item_id": item_id,
    }


def public_remote_discussion_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    message_id = entry.get("message_id")
    if not isinstance(message_id, str) or not message_id:
        raise RemoteError("invalid remote discussion entry")
    text, text_truncated = truncate_utf8(entry.get("text"), REMOTE_DISCUSSION_ENTRY_TEXT_MAX_BYTES)
    return {
        "message_id": bounded_string(message_id, 80),
        "role": bounded_string(entry.get("role"), 48),
        "turn_id": bounded_string(entry.get("turn_id"), 160),
        "updated_at": bounded_string(entry.get("updated_at"), 64),
        "text": text,
        "truncated": bool(entry.get("truncated")) or text_truncated,
    }


def build_remote_discussion_page(
    *,
    secret: bytes,
    session_id: str,
    transcript: Iterable[Mapping[str, Any]],
    cursor_codec: RemoteCursorCodec,
    cursor: str = "",
) -> dict[str, Any]:
    entries = [
        remote_discussion_entry(secret=secret, session_id=session_id, item=item, index=index)
        for index, item in enumerate(transcript)
        if isinstance(item, Mapping)
    ]
    end = len(entries)
    if cursor:
        decoded = cursor_codec.decode(cursor)
        if decoded.get("kind") != "discussion" or decoded.get("session_id") != session_id:
            raise RemoteCursorError("remote discussion cursor does not match this session")
        before = decoded.get("before_message_id")
        if not isinstance(before, str):
            raise RemoteCursorError("invalid remote discussion cursor")
        matches = [index for index, entry in enumerate(entries) if entry.get("message_id") == before]
        if not matches:
            raise RemoteCursorError("remote discussion cursor has expired")
        end = matches[0]

    selected: list[dict[str, Any]] = []
    start = end
    for index in range(end - 1, -1, -1):
        candidate = public_remote_discussion_entry(entries[index])
        proposed = [candidate, *selected]
        response = {
            "session_id": session_id,
            "entries": proposed,
            "has_more": index > 0,
            "next_cursor": "cursor" if index > 0 else "",
        }
        if len(proposed) > REMOTE_DISCUSSION_PAGE_ENTRIES or len(compact_json_bytes(response)) > REMOTE_DISCUSSION_PAGE_MAX_BYTES:
            break
        selected = proposed
        start = index
    has_more = start > 0
    next_cursor = ""
    if has_more:
        next_cursor = cursor_codec.encode(
            {
                "kind": "discussion",
                "session_id": session_id,
                "before_message_id": entries[start]["message_id"],
            }
        )
    result = {
        "session_id": session_id,
        "entries": selected,
        "has_more": has_more,
        "next_cursor": next_cursor,
    }
    if len(compact_json_bytes(result)) > REMOTE_DISCUSSION_PAGE_MAX_BYTES:
        raise RemoteError("remote discussion page exceeds its byte budget")
    return result


def bounded_utf8_chunk(value: str, offset: int, limit: int) -> tuple[str, int]:
    encoded = value.encode("utf-8")
    if offset < 0 or offset > len(encoded):
        raise RemoteCursorError("invalid remote expansion cursor")
    end = min(len(encoded), offset + limit)
    while end > offset:
        try:
            return encoded[offset:end].decode("utf-8"), end
        except UnicodeDecodeError:
            end -= 1
    return "", offset


def build_remote_message_expand(
    *,
    secret: bytes,
    session_id: str,
    transcript: Iterable[Mapping[str, Any]],
    message_id: str,
    cursor_codec: RemoteCursorCodec,
    cursor: str = "",
) -> dict[str, Any]:
    matched_item: Mapping[str, Any] | None = None
    matched_item_id = ""
    for index, item in enumerate(transcript):
        if not isinstance(item, Mapping):
            continue
        item_id = transcript_item_local_id(item, index)
        candidate_id = remote_message_id(secret, session_id, item_id)
        if candidate_id == message_id:
            matched_item = item
            matched_item_id = item_id
            break
    if matched_item is None:
        raise RemoteError("remote discussion message was not found")

    offset = 0
    if cursor:
        decoded = cursor_codec.decode(cursor)
        if (
            decoded.get("kind") != "message_expand"
            or decoded.get("session_id") != session_id
            or decoded.get("message_id") != message_id
            or decoded.get("item_id") != matched_item_id
        ):
            raise RemoteCursorError("remote expansion cursor does not match this message")
        raw_offset = decoded.get("offset")
        if not isinstance(raw_offset, int):
            raise RemoteCursorError("invalid remote expansion cursor")
        offset = raw_offset
    full_text = str(matched_item.get("full_text") or matched_item.get("text") or "")
    text, next_offset = bounded_utf8_chunk(full_text, offset, REMOTE_MESSAGE_EXPAND_CONTENT_MAX_BYTES)
    has_more = next_offset < len(full_text.encode("utf-8"))
    next_cursor = ""
    if has_more:
        next_cursor = cursor_codec.encode(
            {
                "kind": "message_expand",
                "session_id": session_id,
                "message_id": message_id,
                "item_id": matched_item_id,
                "offset": next_offset,
            }
        )
    result = {
        "session_id": session_id,
        "message_id": message_id,
        "text": text,
        "has_more": has_more,
        "next_cursor": next_cursor,
    }
    if len(compact_json_bytes(result)) > REMOTE_MESSAGE_EXPAND_MAX_BYTES:
        raise RemoteError("remote message expansion exceeds its byte budget")
    return result


class RemoteActionCache:
    """Bounded idempotency cache for a future authenticated Remote Agent."""

    _RESULT_KEYS = frozenset(
        {
            "ok",
            "action",
            "session_id",
            "revision",
            "session_revision",
            "idempotency_key",
            "_semantic_ref",
            "_state",
            "_expires_at",
        }
    )

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.lock = threading.RLock()
        self.results: dict[tuple[str, str], dict[str, Any]] = {}
        self.order: deque[tuple[str, str]] = deque()
        self.load_error = ""
        self._load()

    def _load(self) -> None:
        if self.path is None:
            return
        try:
            details = self.path.stat()
        except FileNotFoundError:
            return
        except OSError:
            self.load_error = "remote action journal could not be read"
            return
        if not stat.S_ISREG(details.st_mode) or details.st_size > REMOTE_ACTION_STATE_MAX_BYTES:
            self.load_error = "remote action journal has an invalid format"
            return
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except FileNotFoundError:
            return
        except (OSError, json.JSONDecodeError):
            self.load_error = "remote action journal could not be read"
            return
        if not isinstance(payload, dict) or payload.get("version") != REMOTE_ACTION_STATE_VERSION:
            self.load_error = "remote action journal has an unsupported format"
            return
        entries = payload.get("entries")
        if not isinstance(entries, list):
            self.load_error = "remote action journal has an invalid format"
            return
        if len(entries) > REMOTE_ACTION_IDEMPOTENCY_LIMIT:
            self.load_error = "remote action journal has too many entries"
            return
        for entry in entries:
            if not isinstance(entry, dict):
                self.load_error = "remote action journal has an invalid entry"
                return
            device_id = entry.get("device_id")
            idempotency_key = entry.get("idempotency_key")
            result = entry.get("result")
            if (
                not isinstance(device_id, str)
                or not REMOTE_DEVICE_ID_RE.fullmatch(device_id)
                or not isinstance(idempotency_key, str)
                or not REMOTE_IDEMPOTENCY_KEY_RE.fullmatch(idempotency_key)
                or not isinstance(result, dict)
            ):
                self.load_error = "remote action journal has an invalid entry"
                return
            safe_result = {key: result[key] for key in self._RESULT_KEYS if key in result}
            if not isinstance(safe_result.get("_semantic_ref"), str):
                self.load_error = "remote action journal has an invalid entry"
                return
            state = safe_result.get("_state", "completed")
            if state not in {"pending", "completed"}:
                self.load_error = "remote action journal has an invalid entry"
                return
            expires_at = safe_result.get("_expires_at")
            if expires_at is not None and self._parse_expiry(expires_at) is None:
                self.load_error = "remote action journal has an invalid entry"
                return
            safe_result["_state"] = state
            key = (device_id, idempotency_key)
            if key in self.results:
                self.load_error = "remote action journal has a duplicate entry"
                return
            self.results[key] = safe_result
            self.order.append(key)

    def _ensure_usable_locked(self) -> None:
        if self.load_error:
            raise RemoteError(self.load_error)

    @staticmethod
    def _parse_expiry(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            expiry = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if expiry.tzinfo is None:
            return None
        return expiry.astimezone(timezone.utc)

    def _prune_expired_locked(self) -> bool:
        now = datetime.now(timezone.utc)
        changed = False
        retained: deque[tuple[str, str]] = deque()
        seen: set[tuple[str, str]] = set()
        for key in self.order:
            if key in seen:
                changed = True
                continue
            seen.add(key)
            result = self.results.get(key)
            if result is None:
                changed = True
                continue
            expiry = result.get("_expires_at")
            parsed_expiry = self._parse_expiry(expiry) if expiry is not None else None
            if parsed_expiry is not None and parsed_expiry <= now:
                self.results.pop(key, None)
                changed = True
                continue
            retained.append(key)
        if len(retained) != len(self.order):
            self.order = retained
        return changed

    def _save_locked(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entries = [
            {
                "device_id": device_id,
                "idempotency_key": idempotency_key,
                "result": self.results[(device_id, idempotency_key)],
            }
            for device_id, idempotency_key in self.order
            if (device_id, idempotency_key) in self.results
        ]
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {"version": REMOTE_ACTION_STATE_VERSION, "entries": entries},
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        temporary.replace(self.path)
        self.path.chmod(0o600)
        directory_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def get(self, device_id: str, idempotency_key: str) -> dict[str, Any] | None:
        if not REMOTE_IDEMPOTENCY_KEY_RE.fullmatch(idempotency_key):
            raise RemoteError("invalid remote idempotency key")
        with self.lock:
            self._ensure_usable_locked()
            if self._prune_expired_locked():
                try:
                    self._save_locked()
                except OSError as exc:
                    raise RemoteError("remote action journal could not be written") from exc
            result = self.results.get((device_id, idempotency_key))
            return dict(result) if result is not None else None

    def reserve(
        self,
        device_id: str,
        idempotency_key: str,
        semantic_ref: str,
        expires_at: str,
    ) -> dict[str, Any] | None:
        """Durably reserve an action before it reaches the local PTY.

        A crash after a PTY write must never turn a retry into a duplicate
        prompt. A surviving pending record therefore reports an indeterminate
        outcome instead of silently reissuing the action.
        """
        if not REMOTE_IDEMPOTENCY_KEY_RE.fullmatch(idempotency_key):
            raise RemoteError("invalid remote idempotency key")
        validate_remote_device_id(device_id)
        if not isinstance(semantic_ref, str) or not semantic_ref:
            raise RemoteError("remote action is missing its semantic reference")
        expiry = self._parse_expiry(expires_at)
        if expiry is None or expiry <= datetime.now(timezone.utc):
            raise RemoteError("remote action expiry is invalid")
        key = (device_id, idempotency_key)
        with self.lock:
            self._ensure_usable_locked()
            self._prune_expired_locked()
            existing = self.results.get(key)
            if existing is not None:
                if existing.get("_semantic_ref") != semantic_ref:
                    raise RemoteError("remote idempotency key was reused for a different action")
                if existing.get("_state") == "completed":
                    return dict(existing)
                raise RemoteError("remote action outcome is indeterminate; inspect the session before retrying")
            if len(self.results) >= REMOTE_ACTION_IDEMPOTENCY_LIMIT:
                raise RemoteError("remote action journal is at capacity; wait for pending actions to expire")
            self.results[key] = {
                "_semantic_ref": semantic_ref,
                "_state": "pending",
                "_expires_at": expires_at,
            }
            self.order.append(key)
            try:
                self._save_locked()
            except OSError as exc:
                self.results.pop(key, None)
                self.order.pop()
                raise RemoteError("remote action journal could not be written") from exc
        return None

    def remember(
        self,
        device_id: str,
        idempotency_key: str,
        result: Mapping[str, Any],
        *,
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        if not REMOTE_IDEMPOTENCY_KEY_RE.fullmatch(idempotency_key):
            raise RemoteError("invalid remote idempotency key")
        key = (device_id, idempotency_key)
        safe_result = {key: copy.deepcopy(result[key]) for key in self._RESULT_KEYS if key in result}
        if not isinstance(safe_result.get("_semantic_ref"), str):
            raise RemoteError("remote action result is missing its semantic reference")
        supplied_expiry = safe_result.get("_expires_at")
        if supplied_expiry is not None and self._parse_expiry(supplied_expiry) is None:
            raise RemoteError("remote action expiry is invalid")
        safe_result["_state"] = "completed"
        with self.lock:
            self._ensure_usable_locked()
            existing = self.results.get(key)
            if existing is not None:
                if existing.get("_semantic_ref") != safe_result.get("_semantic_ref"):
                    raise RemoteError("remote idempotency key was reused for a different action")
                stored_expiry = existing.get("_expires_at")
                if isinstance(stored_expiry, str):
                    safe_result["_expires_at"] = stored_expiry
            elif expires_at is not None:
                if self._parse_expiry(expires_at) is None:
                    raise RemoteError("remote action expiry is invalid")
                safe_result["_expires_at"] = expires_at
            if key not in self.results:
                if len(self.results) >= REMOTE_ACTION_IDEMPOTENCY_LIMIT:
                    raise RemoteError("remote action journal is at capacity; wait for pending actions to expire")
                self.order.append(key)
            self.results[key] = safe_result
            self._save_locked()
        return dict(safe_result)


class RemoteControlLeases:
    """Serializes remote mutations per session; local activity can revoke a lease."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.leases: dict[str, str] = {}

    def acquire(self, session_key: str, device_id: str) -> None:
        with self.lock:
            current = self.leases.get(session_key)
            if current and current != device_id:
                raise RemoteAuthorizationError("another paired device controls this session")
            self.leases[session_key] = device_id

    def release(self, session_key: str, *, device_id: str | None = None) -> None:
        with self.lock:
            current = self.leases.get(session_key)
            if current and (device_id is None or current == device_id):
                self.leases.pop(session_key, None)

    def release_all_for_device(self, device_id: str) -> None:
        with self.lock:
            for session_key, holder in list(self.leases.items()):
                if holder == device_id:
                    self.leases.pop(session_key, None)


class LocalRemoteAgentSocket:
    """A local Unix-socket capability boundary for a future Remote Agent.

    It is deliberately not an Internet listener and does not implement pairing,
    relay, or encryption.  The caller must already have a separate local
    capability token and run as the daemon user.  An approved transport
    authenticates the *remote* peer above this boundary.
    """

    def __init__(
        self,
        path: Path,
        token: str,
        request_handler: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> None:
        self.path = path
        self.token = token
        self.request_handler = request_handler
        self.stop_event = threading.Event()
        self.listener: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.lock = threading.RLock()

    def start(self) -> None:
        if not hasattr(socket, "AF_UNIX"):
            raise RemoteError("local remote-agent sockets are unsupported on this platform")
        with self.lock:
            if self.thread and self.thread.is_alive():
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                path_stat = self.path.stat()
            except FileNotFoundError:
                path_stat = None
            if path_stat is not None:
                if not stat.S_ISSOCK(path_stat.st_mode):
                    raise RemoteError("remote-agent socket path is not a socket")
                self.path.unlink()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(str(self.path))
                self.path.chmod(0o600)
                listener.listen(8)
                listener.settimeout(0.25)
            except BaseException:
                listener.close()
                try:
                    self.path.unlink()
                except FileNotFoundError:
                    pass
                raise
            self.listener = listener
            self.stop_event.clear()
            self.thread = threading.Thread(
                target=self._serve,
                name="provision-remote-agent-api",
                daemon=True,
            )
            self.thread.start()

    def stop(self) -> None:
        with self.lock:
            self.stop_event.set()
            listener = self.listener
            self.listener = None
            thread = self.thread
            self.thread = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        if thread is not None:
            thread.join(timeout=1)
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def _serve(self) -> None:
        while not self.stop_event.is_set():
            listener = self.listener
            if listener is None:
                return
            try:
                connection, _address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self._handle_connection(connection)
            finally:
                try:
                    connection.close()
                except OSError:
                    pass

    @staticmethod
    def _peer_is_current_user(connection: socket.socket) -> bool:
        if not hasattr(socket, "SO_PEERCRED"):
            return True
        try:
            credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _pid, uid, _gid = struct.unpack("3i", credentials)
        except (OSError, struct.error):
            return False
        return uid == os.geteuid()

    @staticmethod
    def _receive_request(connection: socket.socket) -> dict[str, Any]:
        connection.settimeout(5)
        data = bytearray()
        while len(data) <= REMOTE_AGENT_REQUEST_MAX_BYTES:
            chunk = connection.recv(min(4096, REMOTE_AGENT_REQUEST_MAX_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if b"\n" in chunk:
                break
        if len(data) > REMOTE_AGENT_REQUEST_MAX_BYTES or b"\n" not in data:
            raise RemoteError("invalid local remote-agent request")
        line = bytes(data.split(b"\n", 1)[0])
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RemoteError("invalid local remote-agent request") from exc
        if not isinstance(value, dict):
            raise RemoteError("invalid local remote-agent request")
        return value

    @staticmethod
    def _send_response(connection: socket.socket, value: Mapping[str, Any]) -> None:
        encoded = compact_json_bytes(dict(value)) + b"\n"
        if len(encoded) > REMOTE_AGENT_RESPONSE_MAX_BYTES:
            encoded = compact_json_bytes(
                {"ok": False, "error": "local remote-agent response exceeds its byte limit"}
            ) + b"\n"
        connection.sendall(encoded)

    def _handle_connection(self, connection: socket.socket) -> None:
        if not self._peer_is_current_user(connection):
            self._send_response(connection, {"ok": False, "error": "local peer is not authorized"})
            return
        try:
            request = self._receive_request(connection)
            token = request.pop("token", "")
            if not isinstance(token, str) or not hmac.compare_digest(token, self.token):
                self._send_response(connection, {"ok": False, "error": "invalid local remote-agent capability"})
                return
            result = self.request_handler(request)
            self._send_response(connection, {"ok": True, "result": result})
        except RemoteError as exc:
            self._send_response(connection, {"ok": False, "error": str(exc)})
        except (OSError, ValueError):
            self._send_response(connection, {"ok": False, "error": "invalid local remote-agent request"})
        except Exception:
            # Do not disclose daemon internals, credentials, or request body.
            self._send_response(connection, {"ok": False, "error": "local remote-agent request failed"})


def random_remote_secret() -> bytes:
    return os.urandom(32)
