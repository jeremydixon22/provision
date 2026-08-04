from __future__ import annotations

from .auth import AuthError

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
            return path[len(prefix) :]
    raise AuthError("invalid ChatGPT backend proxy path token")


def redact_proxy_token(text: str, proxy_token: str) -> str:
    if not proxy_token:
        return text
    return text.replace(f"provision-{proxy_token}", "provision-<redacted>").replace(
        proxy_token,
        "<redacted>",
    )
