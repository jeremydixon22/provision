from __future__ import annotations

import base64
import functools
import json
import os
import re
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any


CHATGPT_BACKEND_BASE_URL = "https://chatgpt.com/backend-api"
CHATGPT_CODEX_BASE_URL = f"{CHATGPT_BACKEND_BASE_URL}/codex"
OPENAI_API_BASE_URL = "https://api.openai.com/v1"
OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"
AUTH_CLAIMS_KEY = "https://api.openai.com/auth"
CODEX_CLIENT_ID_ENV = "PROVISION_CODEX_CLIENT_ID"
CODEX_CLIENT_ID_PATTERN = re.compile(rb"app_[A-Za-z0-9]{24}")
CODEX_CLIENT_ID_CONTEXT_TERMS = (
    b"client_id",
    b"refresh_token",
    b"access_token",
)


class AuthError(RuntimeError):
    pass


_refresh_locks: dict[Path, Lock] = {}
_refresh_locks_guard = Lock()


def _profile_lock(path: Path) -> Lock:
    resolved = path.resolve()
    with _refresh_locks_guard:
        lock = _refresh_locks.get(resolved)
        if lock is None:
            lock = Lock()
            _refresh_locks[resolved] = lock
        return lock


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise AuthError(f"{path} does not contain a JSON object")
    return value


def write_secret_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    encoded = json.dumps(data, indent=2, sort_keys=True) + "\n"
    with temp.open("w", encoding="utf-8") as handle:
        handle.write(encoded)
    temp.chmod(0o600)
    temp.replace(path)
    path.chmod(0o600)


def decode_jwt_claims(token: str | None) -> dict[str, Any]:
    if not token or token.count(".") < 2:
        return {}
    try:
        payload = token.split(".", 2)[1]
        padding = "=" * (-len(payload) % 4)
        raw = base64.urlsafe_b64decode((payload + padding).encode("ascii"))
        value = json.loads(raw.decode("utf-8"))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def auth_claims(auth: dict[str, Any]) -> dict[str, Any]:
    tokens = auth.get("tokens")
    if not isinstance(tokens, dict):
        return {}
    id_claims = decode_jwt_claims(tokens.get("id_token"))
    nested = id_claims.get(AUTH_CLAIMS_KEY)
    return nested if isinstance(nested, dict) else {}


def extract_metadata(auth: dict[str, Any]) -> dict[str, Any]:
    tokens = auth.get("tokens") if isinstance(auth.get("tokens"), dict) else {}
    id_claims = decode_jwt_claims(tokens.get("id_token")) if tokens else {}
    access_claims = decode_jwt_claims(tokens.get("access_token")) if tokens else {}
    nested = id_claims.get(AUTH_CLAIMS_KEY)
    if not isinstance(nested, dict):
        nested = access_claims.get(AUTH_CLAIMS_KEY)
    if not isinstance(nested, dict):
        nested = {}
    profile = access_claims.get("https://api.openai.com/profile")
    if not isinstance(profile, dict):
        profile = {}

    account_id = (
        tokens.get("account_id")
        or nested.get("chatgpt_account_id")
        or nested.get("account_id")
    )
    email = id_claims.get("email") or profile.get("email")
    name = id_claims.get("name")
    plan = nested.get("chatgpt_plan_type")
    auth_mode = auth.get("auth_mode")
    kind = "chatgpt" if tokens else "api_key" if auth.get("OPENAI_API_KEY") else "unknown"

    return {
        "kind": kind,
        "auth_mode": auth_mode,
        "email": email,
        "name": name,
        "account_id": account_id,
        "plan_type": plan,
        "imported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def access_token_expired(auth: dict[str, Any], skew_seconds: int = 300) -> bool:
    tokens = auth.get("tokens")
    if not isinstance(tokens, dict):
        return False
    claims = decode_jwt_claims(tokens.get("access_token"))
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        return False
    return exp <= time.time() + skew_seconds


def codex_client_id_from_bytes(data: bytes) -> str | None:
    candidates: dict[str, int] = {}
    for match in CODEX_CLIENT_ID_PATTERN.finditer(data):
        start = max(0, match.start() - 256)
        end = min(len(data), match.end() + 256)
        context = data[start:end]
        if not all(term in context for term in CODEX_CLIENT_ID_CONTEXT_TERMS):
            continue
        value = match.group(0).decode("ascii")
        candidates[value] = candidates.get(value, 0) + 1
    if not candidates:
        return None
    return max(candidates.items(), key=lambda item: item[1])[0]


def codex_client_id_candidate_paths() -> list[Path]:
    paths: list[Path] = []
    roots: list[Path] = []
    managed_root = os.environ.get("CODEX_MANAGED_PACKAGE_ROOT")
    if managed_root:
        roots.append(Path(managed_root).expanduser())

    executable = shutil.which("codex")
    if executable:
        path = Path(executable).resolve()
        paths.append(path)
        if path.parent.name == "bin":
            roots.append(path.parent.parent)
        roots.append(path.parent)

    seen_roots: set[Path] = set()
    for root in roots:
        root = root.resolve()
        if root in seen_roots or not root.exists():
            continue
        seen_roots.add(root)
        for name in ("codex", "codex.exe"):
            paths.extend(root.rglob(name))

    seen_paths: set[Path] = set()
    unique_paths = []
    for path in paths:
        try:
            path = path.resolve()
        except OSError:
            continue
        if path in seen_paths or not path.is_file():
            continue
        seen_paths.add(path)
        unique_paths.append(path)
    return unique_paths


@functools.lru_cache(maxsize=1)
def codex_client_id() -> str:
    configured = os.environ.get(CODEX_CLIENT_ID_ENV)
    if configured:
        try:
            encoded = configured.encode("ascii")
        except UnicodeEncodeError:
            encoded = b""
        if CODEX_CLIENT_ID_PATTERN.fullmatch(encoded):
            return configured
        raise AuthError(f"{CODEX_CLIENT_ID_ENV} is not a valid Codex OAuth client id")

    for path in codex_client_id_candidate_paths():
        try:
            client_id = codex_client_id_from_bytes(path.read_bytes())
        except OSError:
            continue
        if client_id:
            return client_id

    raise AuthError(
        "could not discover the Codex OAuth client id from the local Codex install; "
        f"set {CODEX_CLIENT_ID_ENV} or reinstall Codex"
    )


def refresh_chatgpt_tokens(auth_path: Path, auth: dict[str, Any]) -> dict[str, Any]:
    tokens = auth.get("tokens")
    if not isinstance(tokens, dict):
        raise AuthError("profile does not contain ChatGPT tokens")
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        raise AuthError("profile does not contain a refresh token")

    body = urllib.parse.urlencode(
        {
            "client_id": codex_client_id(),
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        OAUTH_TOKEN_URL,
        data=body,
        headers={"content-type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise AuthError(f"token refresh failed with HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise AuthError(f"token refresh failed: {exc}") from exc

    for key in ("id_token", "access_token", "refresh_token"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            tokens[key] = value
    if "account_id" not in tokens:
        new_claims = decode_jwt_claims(tokens.get("id_token"))
        nested = new_claims.get(AUTH_CLAIMS_KEY)
        if isinstance(nested, dict) and nested.get("chatgpt_account_id"):
            tokens["account_id"] = nested["chatgpt_account_id"]

    auth["tokens"] = tokens
    auth["last_refresh"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    write_secret_json(auth_path, auth)
    return auth


def ensure_fresh_chatgpt_auth(auth_path: Path) -> dict[str, Any]:
    lock = _profile_lock(auth_path)
    with lock:
        auth = load_json(auth_path)
        if access_token_expired(auth):
            return refresh_chatgpt_tokens(auth_path, auth)
        return auth


def force_refresh_chatgpt_auth(auth_path: Path) -> dict[str, Any]:
    lock = _profile_lock(auth_path)
    with lock:
        return refresh_chatgpt_tokens(auth_path, load_json(auth_path))


def upstream_auth_headers(auth: dict[str, Any]) -> dict[str, str]:
    tokens = auth.get("tokens")
    if isinstance(tokens, dict) and tokens.get("access_token"):
        headers = {"authorization": f"Bearer {tokens['access_token']}"}
        account_id = tokens.get("account_id")
        if account_id:
            headers["chatgpt-account-id"] = str(account_id)
        claims = auth_claims(auth)
        if claims.get("chatgpt_account_is_fedramp"):
            headers["x-openai-fedramp"] = "true"
        return headers

    api_key = auth.get("OPENAI_API_KEY")
    if isinstance(api_key, str) and api_key:
        return {"authorization": f"Bearer {api_key}"}

    raise AuthError("profile has neither ChatGPT tokens nor OPENAI_API_KEY")


def upstream_base_url(auth: dict[str, Any]) -> str:
    tokens = auth.get("tokens")
    if isinstance(tokens, dict) and tokens.get("access_token"):
        return CHATGPT_CODEX_BASE_URL
    return OPENAI_API_BASE_URL


def upstream_chatgpt_backend_base_url(auth: dict[str, Any]) -> str:
    tokens = auth.get("tokens")
    if isinstance(tokens, dict) and tokens.get("access_token"):
        return CHATGPT_BACKEND_BASE_URL
    raise AuthError("ChatGPT backend proxy requires a ChatGPT profile")
