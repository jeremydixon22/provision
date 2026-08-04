"""Structured local session readers for native provider CLIs.

The PTY bridge remains the source of terminal control.  Provider session
readers are a separate, read-only path for CLIs that publish an append-only
conversation log suitable for Provision's Discussion view.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

GROK_INITIAL_REPLAY_MAX_BYTES = 4 * 1024 * 1024
GROK_INCREMENTAL_READ_MAX_BYTES = 2 * 1024 * 1024
GROK_PENDING_RECORD_MAX_BYTES = 2 * 1024 * 1024
GROK_SEEN_EVENT_LIMIT = 8192
CLAUDE_INITIAL_REPLAY_MAX_BYTES = 4 * 1024 * 1024
CLAUDE_INCREMENTAL_READ_MAX_BYTES = 2 * 1024 * 1024
CLAUDE_PENDING_RECORD_MAX_BYTES = 2 * 1024 * 1024
CLAUDE_SEEN_EVENT_LIMIT = 8192


@dataclass(frozen=True)
class ProviderSessionBatch:
    """One incremental read from a provider-owned session log."""

    session_id: str = ""
    records: tuple[dict[str, Any], ...] = ()
    title: str = ""
    model: str = ""


def process_is_running(pid: int | None) -> bool:
    """Return whether a local process currently exists without signalling it."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _grok_active_session(
    state_root: Path,
    cwd: str,
    provider_pid: int | None,
) -> dict[str, Any] | None:
    try:
        value = json.loads((state_root / "active_sessions.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, list):
        return None
    candidates = [
        item
        for item in value
        if isinstance(item, dict)
        and str(item.get("cwd") or "") == cwd
        and isinstance(item.get("session_id"), str)
        and str(item.get("session_id") or "")
    ]
    if provider_pid:
        exact = [item for item in candidates if item.get("pid") == provider_pid]
        if exact:
            candidates = exact
    if not candidates:
        return None
    return max(candidates, key=lambda item: str(item.get("opened_at") or ""))


def _grok_cwd_group(state_root: Path, cwd: str) -> Path | None:
    sessions_root = state_root / "sessions"
    encoded = sessions_root / urllib.parse.quote(cwd, safe="")
    if encoded.is_dir():
        return encoded
    try:
        groups = list(sessions_root.iterdir())
    except OSError:
        return None
    # Grok uses a slug plus hash when an encoded cwd would exceed the
    # filesystem name limit, recording the original cwd in a small marker.
    for group in groups:
        try:
            if group.is_dir() and (group / ".cwd").read_text(encoding="utf-8").strip() == cwd:
                return group
        except (OSError, UnicodeError):
            continue
    return None


@dataclass
class GrokSessionReader:
    """Incrementally follow Grok's documented ``updates.jsonl`` source of truth."""

    session_id: str = ""
    source_path: Path | None = None
    source_identity: tuple[int, int] | None = None
    offset: int = 0
    pending: bytes = b""
    seen_event_ids: set[str] = field(default_factory=set)
    seen_event_order: list[str] = field(default_factory=list)
    metadata_mtime_ns: int = -1
    title: str = ""
    model: str = ""
    current_turn_id: str = ""
    working: bool = False
    tool_names: dict[str, str] = field(default_factory=dict)
    tool_states: dict[str, dict[str, Any]] = field(default_factory=dict)
    tool_aliases: dict[str, str] = field(default_factory=dict)
    latest_usage: dict[str, int] = field(default_factory=dict)
    usage_updated_at: str = ""

    def _reset_source(self, session_id: str, source_path: Path) -> None:
        self.session_id = session_id
        self.source_path = source_path
        self.source_identity = None
        self.offset = 0
        self.pending = b""
        self.seen_event_ids.clear()
        self.seen_event_order.clear()
        self.metadata_mtime_ns = -1
        self.title = ""
        self.model = ""
        self.current_turn_id = ""
        self.working = False
        self.tool_names.clear()
        self.tool_states.clear()
        self.tool_aliases.clear()
        self.latest_usage.clear()
        self.usage_updated_at = ""

    def _discover(
        self,
        state_root: Path,
        cwd: str,
        provider_pid: int | None,
    ) -> bool:
        active = _grok_active_session(state_root, cwd, provider_pid)
        if not active:
            return False
        session_id = str(active.get("session_id") or "")
        group = _grok_cwd_group(state_root, cwd)
        if not session_id or group is None:
            return False
        source_path = group / session_id / "updates.jsonl"
        if self.session_id != session_id or self.source_path != source_path:
            self._reset_source(session_id, source_path)
        return True

    def _refresh_metadata(self) -> None:
        if self.source_path is None:
            return
        summary_path = self.source_path.parent / "summary.json"
        try:
            stat = summary_path.stat()
        except OSError:
            return
        if stat.st_mtime_ns == self.metadata_mtime_ns:
            return
        self.metadata_mtime_ns = stat.st_mtime_ns
        try:
            value = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return
        if not isinstance(value, dict):
            return
        self.title = str(value.get("generated_title") or value.get("session_summary") or "")
        self.model = str(value.get("current_model_id") or "")

    def _remember_event(self, event_id: str) -> bool:
        if event_id in self.seen_event_ids:
            return False
        self.seen_event_ids.add(event_id)
        self.seen_event_order.append(event_id)
        if len(self.seen_event_order) > GROK_SEEN_EVENT_LIMIT:
            expired = self.seen_event_order[: len(self.seen_event_order) - GROK_SEEN_EVENT_LIMIT]
            del self.seen_event_order[: len(expired)]
            self.seen_event_ids.difference_update(expired)
        return True

    def refresh(
        self,
        state_root: Path,
        cwd: str,
        provider_pid: int | None = None,
    ) -> ProviderSessionBatch:
        if not self._discover(state_root, cwd, provider_pid) or self.source_path is None:
            return ProviderSessionBatch(
                session_id=self.session_id, title=self.title, model=self.model
            )
        self._refresh_metadata()
        try:
            stat = self.source_path.stat()
        except OSError:
            return ProviderSessionBatch(
                session_id=self.session_id, title=self.title, model=self.model
            )
        identity = (stat.st_dev, stat.st_ino)
        if self.source_identity != identity or stat.st_size < self.offset:
            self.source_identity = identity
            self.offset = 0
            self.pending = b""
        if self.offset == 0 and stat.st_size > GROK_INITIAL_REPLAY_MAX_BYTES:
            self.offset = stat.st_size - GROK_INITIAL_REPLAY_MAX_BYTES
            with self.source_path.open("rb") as handle:
                handle.seek(self.offset)
                handle.readline(GROK_INCREMENTAL_READ_MAX_BYTES)
                self.offset = handle.tell()
        try:
            with self.source_path.open("rb") as handle:
                handle.seek(self.offset)
                chunk = handle.read(GROK_INCREMENTAL_READ_MAX_BYTES)
                self.offset = handle.tell()
        except OSError:
            return ProviderSessionBatch(
                session_id=self.session_id, title=self.title, model=self.model
            )
        if not chunk:
            return ProviderSessionBatch(
                session_id=self.session_id, title=self.title, model=self.model
            )
        raw = self.pending + chunk
        lines = raw.split(b"\n")
        self.pending = lines.pop() if raw and not raw.endswith(b"\n") else b""
        if len(self.pending) > GROK_PENDING_RECORD_MAX_BYTES:
            # A provider tool result can theoretically be arbitrarily large.
            # Drop an oversized partial record rather than allowing a damaged
            # or hostile log line to grow daemon memory without bound.
            self.pending = b""
        records: list[dict[str, Any]] = []
        for line in lines:
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except (UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(value, dict):
                continue
            params = value.get("params")
            meta = params.get("_meta") if isinstance(params, dict) else None
            event_id = str(meta.get("eventId") or "") if isinstance(meta, dict) else ""
            if not event_id:
                # A stable identity prevents replay duplication after a file
                # replacement while retaining repeated, distinct events whose
                # timestamp or payload differs.
                event_id = hashlib.sha256(line).hexdigest()
            if self._remember_event(event_id):
                records.append(value)
        return ProviderSessionBatch(
            session_id=self.session_id,
            records=tuple(records),
            title=self.title,
            model=self.model,
        )


def _claude_session_records(state_root: Path, cwd: str) -> list[dict[str, Any]]:
    sessions_root = state_root / "sessions"
    try:
        paths = list(sessions_root.glob("*.json"))
    except OSError:
        return []
    records: list[dict[str, Any]] = []
    for path in paths:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if (
            isinstance(value, dict)
            and str(value.get("cwd") or "") == cwd
            and str(value.get("sessionId") or "")
        ):
            records.append(value)
    return records


def _claude_source_path(state_root: Path, cwd: str, session_id: str) -> Path | None:
    projects_root = state_root / "projects"
    if session_id and Path(session_id).name == session_id:
        try:
            groups = list(projects_root.iterdir())
        except OSError:
            groups = []
        matches = [
            group / f"{session_id}.jsonl"
            for group in groups
            if group.is_dir() and (group / f"{session_id}.jsonl").is_file()
        ]
        if matches:
            return max(matches, key=lambda path: path.stat().st_mtime_ns)

    # Claude's native project group is the absolute cwd with path separators
    # replaced by dashes.  The latest log is a useful fallback when the CLI has
    # already removed its live session record before Provision's first poll.
    group = projects_root / cwd.replace("/", "-")
    try:
        candidates = list(group.glob("*.jsonl"))
    except OSError:
        return None
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime_ns)


@dataclass
class ClaudeSessionReader:
    """Incrementally follow Claude Code's native project conversation log."""

    session_id: str = ""
    source_path: Path | None = None
    source_identity: tuple[int, int] | None = None
    offset: int = 0
    pending: bytes = b""
    seen_event_ids: set[str] = field(default_factory=set)
    seen_event_order: list[str] = field(default_factory=list)
    title: str = ""
    model: str = ""
    current_turn_id: str = ""
    working: bool = False
    tool_states: dict[str, dict[str, Any]] = field(default_factory=dict)

    def _reset_source(self, session_id: str, source_path: Path) -> None:
        self.session_id = session_id
        self.source_path = source_path
        self.source_identity = None
        self.offset = 0
        self.pending = b""
        self.seen_event_ids.clear()
        self.seen_event_order.clear()
        self.title = ""
        self.model = ""
        self.current_turn_id = ""
        self.working = False
        self.tool_states.clear()

    def _discover(
        self,
        state_root: Path,
        cwd: str,
        provider_pid: int | None,
    ) -> bool:
        candidates = _claude_session_records(state_root, cwd)
        if provider_pid:
            exact = [item for item in candidates if item.get("pid") == provider_pid]
            if exact:
                candidates = exact
        active = (
            max(candidates, key=lambda item: int(item.get("updatedAt") or 0))
            if candidates
            else None
        )
        session_id = str(active.get("sessionId") or "") if active else self.session_id
        source_path = _claude_source_path(state_root, cwd, session_id)
        if source_path is None:
            return self.source_path is not None
        if not session_id:
            session_id = source_path.stem
        if self.session_id != session_id or self.source_path != source_path:
            self._reset_source(session_id, source_path)
        if active:
            status = str(active.get("status") or "").lower()
            if status:
                self.working = status not in {"idle", "stopped", "exited", "closed"}
            if not self.title:
                self.title = str(active.get("name") or "")
        return True

    def _remember_event(self, event_id: str) -> bool:
        if event_id in self.seen_event_ids:
            return False
        self.seen_event_ids.add(event_id)
        self.seen_event_order.append(event_id)
        if len(self.seen_event_order) > CLAUDE_SEEN_EVENT_LIMIT:
            expired = self.seen_event_order[: len(self.seen_event_order) - CLAUDE_SEEN_EVENT_LIMIT]
            del self.seen_event_order[: len(expired)]
            self.seen_event_ids.difference_update(expired)
        return True

    def refresh(
        self,
        state_root: Path,
        cwd: str,
        provider_pid: int | None = None,
    ) -> ProviderSessionBatch:
        if not self._discover(state_root, cwd, provider_pid) or self.source_path is None:
            return ProviderSessionBatch(
                session_id=self.session_id, title=self.title, model=self.model
            )
        try:
            stat = self.source_path.stat()
        except OSError:
            return ProviderSessionBatch(
                session_id=self.session_id, title=self.title, model=self.model
            )
        identity = (stat.st_dev, stat.st_ino)
        if self.source_identity != identity or stat.st_size < self.offset:
            self.source_identity = identity
            self.offset = 0
            self.pending = b""
        if self.offset == 0 and stat.st_size > CLAUDE_INITIAL_REPLAY_MAX_BYTES:
            self.offset = stat.st_size - CLAUDE_INITIAL_REPLAY_MAX_BYTES
            try:
                with self.source_path.open("rb") as handle:
                    handle.seek(self.offset)
                    handle.readline(CLAUDE_INCREMENTAL_READ_MAX_BYTES)
                    self.offset = handle.tell()
            except OSError:
                return ProviderSessionBatch(
                    session_id=self.session_id, title=self.title, model=self.model
                )
        try:
            with self.source_path.open("rb") as handle:
                handle.seek(self.offset)
                chunk = handle.read(CLAUDE_INCREMENTAL_READ_MAX_BYTES)
                self.offset = handle.tell()
        except OSError:
            return ProviderSessionBatch(
                session_id=self.session_id, title=self.title, model=self.model
            )
        if not chunk:
            return ProviderSessionBatch(
                session_id=self.session_id, title=self.title, model=self.model
            )
        raw = self.pending + chunk
        lines = raw.split(b"\n")
        self.pending = lines.pop() if raw and not raw.endswith(b"\n") else b""
        if len(self.pending) > CLAUDE_PENDING_RECORD_MAX_BYTES:
            self.pending = b""
        records: list[dict[str, Any]] = []
        for line in lines:
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except (UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(value, dict):
                continue
            if value.get("type") == "ai-title":
                self.title = str(value.get("aiTitle") or self.title)
            message = value.get("message")
            if isinstance(message, dict) and message.get("model"):
                self.model = str(message.get("model") or self.model)
            event_id = str(value.get("uuid") or "") or hashlib.sha256(line).hexdigest()
            if self._remember_event(event_id):
                records.append(value)
        return ProviderSessionBatch(
            session_id=self.session_id,
            records=tuple(records),
            title=self.title,
            model=self.model,
        )
