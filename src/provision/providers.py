"""Provider identities and supported local-launch contracts.

Provision deliberately keeps vendor clients responsible for their upstream
connections and credentials.  This module only describes the local executable
and the environment variable a vendor documents for an isolated *new* process.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

PROVIDER_PROFILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


@dataclass(frozen=True)
class ProviderSpec:
    """A locally launchable provider surface.

    ``profile_environment`` is empty where a vendor-supported profile-root
    override has not been established.  Callers must not invent one by copying
    a vendor's credential store.
    """

    name: str
    executable: str
    aliases: tuple[str, ...]
    profile_environment: str = ""
    login_args: tuple[str, ...] = ()
    pty_bypass_commands: tuple[str, ...] = ()
    pty_bypass_options: tuple[str, ...] = ()

    @property
    def supports_managed_profiles(self) -> bool:
        return bool(self.profile_environment and self.login_args)


PROVIDERS: tuple[ProviderSpec, ...] = (
    ProviderSpec(
        name="codex",
        executable="codex",
        aliases=("codex", "openai"),
    ),
    ProviderSpec(
        name="claude",
        executable="claude",
        aliases=("claude", "anthropic", "claude-code", "claudecode"),
        profile_environment="CLAUDE_CONFIG_DIR",
        login_args=("auth", "login"),
        pty_bypass_commands=(
            "auth",
            "agents",
            "doctor",
            "help",
            "mcp",
            "plugin",
            "plugins",
            "version",
        ),
        pty_bypass_options=(
            "-p",
            "--print",
            "--output-format",
            "--input-format",
            "--json-schema",
        ),
    ),
    ProviderSpec(
        name="grok",
        executable="grok",
        aliases=("grok", "xai", "grok-build", "grokbuild"),
        profile_environment="GROK_HOME",
        login_args=("login",),
        pty_bypass_commands=(
            "agent",
            "completions",
            "doctor",
            "export",
            "help",
            "inspect",
            "leader",
            "login",
            "logout",
            "mcp",
            "models",
            "plugin",
            "sessions",
            "trace",
            "update",
            "version",
            "worktree",
            "wrap",
        ),
        pty_bypass_options=(
            "-p",
            "--single",
            "--prompt-file",
            "--prompt-json",
            "--output-format",
            "--json-schema",
        ),
    ),
    ProviderSpec(
        name="antigravity",
        executable="agy",
        aliases=("antigravity", "agy", "google-antigravity"),
        # The official `agy` CLI needs a local compatibility probe before
        # Provision promises a profile-root/auth-store override.
        pty_bypass_commands=("help", "version"),
    ),
)

_BY_ALIAS = {alias.lower(): spec for spec in PROVIDERS for alias in spec.aliases}
_BY_NAME = {spec.name: spec for spec in PROVIDERS}


class ProviderError(RuntimeError):
    pass


def provider_names() -> tuple[str, ...]:
    return tuple(spec.name for spec in PROVIDERS)


def provider_spec(value: str) -> ProviderSpec:
    key = value.strip().lower()
    spec = _BY_ALIAS.get(key)
    if spec is None:
        choices = ", ".join(provider_names())
        raise ProviderError(f"unknown provider: {value} (choose one of: {choices})")
    return spec


def provider_alias(value: str) -> str | None:
    """Return a canonical provider name for a user-facing alias, if known."""
    spec = _BY_ALIAS.get(value.strip().lower())
    return spec.name if spec else None


def canonical_provider(value: str) -> str:
    return provider_spec(value).name


def provider_profile_root(home: Path, provider: str, profile: str) -> Path:
    """Return the Provision-owned root passed to a vendor's documented env var."""
    spec = provider_spec(provider)
    if not PROVIDER_PROFILE_NAME.match(profile):
        raise ProviderError(
            "profile names must start with an ASCII letter or digit and contain only letters, digits, dots, dashes, or underscores"
        )
    if not spec.profile_environment:
        raise ProviderError(
            f"{spec.name} does not yet have a verified Provision-managed profile root; "
            "use its native login until the compatibility probe is complete"
        )
    return home / "providers" / spec.name / "profiles" / profile


def provider_environment(home: Path, provider: str, profile: str | None) -> dict[str, str]:
    """Return only the vendor environment needed for a selected profile."""
    if not profile:
        return {}
    spec = provider_spec(provider)
    root = provider_profile_root(home, spec.name, profile)
    return {spec.profile_environment: str(root)}


def provider_rows() -> Iterable[ProviderSpec]:
    return PROVIDERS
