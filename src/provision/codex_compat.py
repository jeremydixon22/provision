"""Compatibility policies for Codex requests passing through Provision."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from collections.abc import Callable, Iterator, MutableMapping
from pathlib import Path
from typing import Any

_REFRESH_BOOKKEEPING = frozenset({"last_refresh", "last_refresh_failed_at", "last_refresh_error"})
_ROTATING_TOKEN_FIELDS = frozenset({"access_token", "refresh_token", "id_token"})
_AUTH_CLAIMS_KEY = "https://api.openai.com/auth"


def read_json_object(path: Path) -> Any:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def auth_revision(path: Path) -> str:
    """Account generation. A token refresh for that same account stays stable."""
    value = read_json_object(path)
    if value is None:
        return "unavailable"
    return auth_payload_revision(value)


def auth_payload_revision(value: Any) -> str:
    """Identity of the account, ignoring rotated tokens and refresh timestamps."""
    return _auth_digest(auth_account_identity(value))


def auth_material_fingerprint(value: Any) -> str:
    """Full credential fingerprint, including rotated tokens."""
    return _auth_digest(value)


def auth_account_identity(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    identity = {
        key: item
        for key, item in value.items()
        if key not in _REFRESH_BOOKKEEPING and key != "tokens"
    }
    tokens = value.get("tokens")
    if not isinstance(tokens, dict):
        return identity
    account_id = _token_account_id(tokens)
    if not account_id:
        identity["tokens"] = tokens
        return identity
    stable = {key: item for key, item in tokens.items() if key not in _ROTATING_TOKEN_FIELDS}
    stable["account_id"] = account_id
    # A workspace can contain multiple users. Keep their caches separate even
    # when tokens.account_id names the same workspace.
    for key in ("id_token", "access_token"):
        subject = _jwt_claims(tokens.get(key)).get("sub")
        if isinstance(subject, str) and subject:
            stable["subject"] = subject
            break
    identity["tokens"] = stable
    return identity


def same_account_credential_update(current: Any, refreshed: Any) -> bool:
    """True when refreshed tokens belong to the same account and differ."""
    if not isinstance(current, dict) or not isinstance(refreshed, dict):
        return False
    if auth_payload_revision(refreshed) != auth_payload_revision(current):
        return False
    return auth_material_fingerprint(refreshed) != auth_material_fingerprint(current)


def _auth_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _token_account_id(tokens: dict[str, Any]) -> str | None:
    account_id = tokens.get("account_id")
    if isinstance(account_id, str) and account_id:
        return account_id
    for key in ("id_token", "access_token"):
        found = _jwt_claim_account_id(tokens.get(key))
        if found:
            return found
    return None


def _jwt_claims(token: Any) -> dict[str, Any]:
    if not isinstance(token, str) or token.count(".") < 2:
        return {}
    try:
        segment = token.split(".", 2)[1]
        padded = segment + "=" * (-len(segment) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return {}
    return claims if isinstance(claims, dict) else {}


def _jwt_claim_account_id(token: Any) -> str | None:
    nested = _jwt_claims(token).get(_AUTH_CLAIMS_KEY)
    if not isinstance(nested, dict):
        return None
    for key in ("chatgpt_account_id", "account_id"):
        found = nested.get(key)
        if isinstance(found, str) and found:
            return found
    return None


class AccountScopedCache(MutableMapping[str, dict[str, Any]]):
    """Invalidate profile entries when the account changes; callers own locking.

    Token refresh for the same account keeps the entry. Ownership stays outside
    entries so it cannot leak into dashboard snapshots. Workers must also compare
    their captured revision before publishing results.
    """

    def __init__(self, revision: Callable[[str], str]) -> None:
        self._revision = revision
        self._entries: dict[str, dict[str, Any]] = {}
        self._owners: dict[str, str] = {}

    def discard_stale(self, key: str) -> None:
        """Remove a profile entry after its account changes."""
        if self._owners.get(key) != self._revision(key):
            self._entries.pop(key, None)
            self._owners.pop(key, None)

    def __getitem__(self, key: str) -> dict[str, Any]:
        self.discard_stale(key)
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
