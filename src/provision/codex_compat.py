"""Compatibility policies for Codex requests passing through Provision."""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable, Iterator, MutableMapping
from pathlib import Path
from typing import Any


def auth_revision(path: Path) -> str:
    """Opaque credential generation, including replacement of the same account."""
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError):
        return "unavailable"
    return auth_payload_revision(value)


def auth_payload_revision(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class AccountScopedCache(MutableMapping[str, dict[str, Any]]):
    """Invalidate profile entries when credentials change; callers own locking.

    Ownership stays outside entries so it cannot leak into dashboard snapshots.
    Workers must also compare their captured revision before publishing results.
    """

    def __init__(self, revision: Callable[[str], str]) -> None:
        self._revision = revision
        self._entries: dict[str, dict[str, Any]] = {}
        self._owners: dict[str, str] = {}

    def __getitem__(self, key: str) -> dict[str, Any]:
        if self._owners.get(key) != self._revision(key):
            self._entries.pop(key, None)
            self._owners.pop(key, None)
        return self._entries[key]

    def __setitem__(self, key: str, value: dict[str, Any]) -> None:
        self._owners[key] = self._revision(key)
        self._entries[key] = value

    def __delitem__(self, key: str) -> None:
        del self._entries[key]
        self._owners.pop(key, None)

    def __iter__(self) -> Iterator[str]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


class ModelRewriteContext:
    """Track configuration updates across an incremental response chain.

    Full-history requests establish their own mode. Incremental requests retain
    it so an update stored behind previous_response_id cannot silently override
    a later profile selection. Never introduce the feature into a legacy chain.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._configuration_updates = False

    def rewrite(
        self,
        value: dict[str, Any],
        *,
        model: str | None,
        reasoning_effort: str | None,
        compact: bool = False,
    ) -> tuple[dict[str, Any], bool]:
        with self._lock:
            result = dict(value)
            if model:
                result["model"] = model
            if not reasoning_effort:
                return result, result != value

            raw_input = value.get("input")
            items = list(raw_input) if isinstance(raw_input, list) else []
            updates = [
                i
                for i, item in enumerate(items)
                if isinstance(item, dict) and item.get("type") == "configuration_update"
            ]
            if not compact:
                if not value.get("previous_response_id"):
                    self._configuration_updates = bool(updates)
                elif updates:
                    self._configuration_updates = True
            use_updates = (
                not compact
                and model == "gpt-6-astra"
                and value.get("service_tier") not in {"priority", "flex"}
                and (bool(updates) or self._configuration_updates)
            )
            reasoning = value.get("reasoning")
            next_reasoning = dict(reasoning) if isinstance(reasoning, dict) else {}
            if use_updates:
                # Keep the initial effort in the cacheable prefix; the newest
                # control item owns the effort of the response being requested.
                next_reasoning.setdefault("effort", reasoning_effort)
                if isinstance(raw_input, str):
                    items = [{"role": "user", "content": raw_input}]
                # Insert before the current user message when available. Tool
                # continuations receive the control after their latest output.
                position = len(items)
                if items and isinstance(items[-1], dict) and items[-1].get("role") == "user":
                    position -= 1
                update = {
                    "type": "configuration_update",
                    "reasoning": {"effort": reasoning_effort},
                }
                # A pending control immediately before this turn may be replaced;
                # retain all earlier controls in their original history positions.
                if (
                    position
                    and isinstance(items[position - 1], dict)
                    and (items[position - 1].get("type") == "configuration_update")
                ):
                    items[position - 1] = update
                else:
                    items.insert(position, update)
                result["input"] = items
            else:
                next_reasoning["effort"] = reasoning_effort
                if updates:
                    # Other models and /responses/compact reject this Astra-only
                    # control. The request-level setting remains authoritative.
                    result["input"] = [
                        item
                        for item in items
                        if not (
                            isinstance(item, dict) and item.get("type") == "configuration_update"
                        )
                    ]
            result["reasoning"] = next_reasoning
            return result, result != value
