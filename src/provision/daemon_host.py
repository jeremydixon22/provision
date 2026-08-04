from __future__ import annotations

import ipaddress

DEFAULT_DAEMON_HOST = "127.0.0.1"


def normalize_daemon_host(host: str | None) -> str:
    value = (host or DEFAULT_DAEMON_HOST).strip()
    return value or DEFAULT_DAEMON_HOST


def daemon_host_is_loopback(host: str | None) -> bool:
    value = normalize_daemon_host(host).strip("[]").lower()
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


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
