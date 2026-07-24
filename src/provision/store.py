from __future__ import annotations

import json
import re
import secrets
import shutil
from pathlib import Path
from typing import Any

from .auth import extract_metadata, load_json, write_secret_json
from .paths import Paths, default_codex_home


PROFILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class StoreError(RuntimeError):
    pass


def validate_profile_name(name: str) -> str:
    if not PROFILE_NAME.match(name):
        raise StoreError(
            "profile names must start with an ASCII letter or digit and contain only letters, digits, dots, dashes, or underscores"
        )
    return name


class Store:
    def __init__(self, paths: Paths | None = None) -> None:
        self.paths = paths or Paths()
        self.paths.ensure_base()

    def profile_dir(self, name: str) -> Path:
        return self.paths.profiles / validate_profile_name(name)

    def auth_path(self, name: str) -> Path:
        return self.profile_dir(name) / "auth.json"

    def metadata_path(self, name: str) -> Path:
        return self.profile_dir(name) / "metadata.json"

    def profile_exists(self, name: str) -> bool:
        return self.auth_path(name).exists()

    def profile_names(self) -> list[str]:
        names = []
        for path in sorted(self.paths.profiles.iterdir()):
            if path.is_dir() and (path / "auth.json").exists():
                names.append(path.name)
        return names

    def stored_active_profile(self) -> str | None:
        if not self.paths.active_profile.exists():
            return None
        name = self.paths.active_profile.read_text(encoding="utf-8").strip()
        return name or None

    def list_profiles(self) -> list[dict[str, Any]]:
        profiles = []
        active = self.stored_active_profile()
        for name in self.profile_names():
            metadata = self.read_metadata(name)
            metadata["name"] = name
            metadata["active"] = name == active
            metadata["hidden"] = bool(metadata.get("hidden"))
            profiles.append(metadata)
        return profiles

    def read_metadata(self, name: str) -> dict[str, Any]:
        path = self.metadata_path(name)
        if not path.exists():
            return {}
        try:
            with path.open("r", encoding="utf-8") as handle:
                value = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    def import_auth_file(
        self,
        name: str,
        source: Path,
        *,
        overwrite: bool = False,
        set_active: bool = False,
    ) -> dict[str, Any]:
        validate_profile_name(name)
        source = source.expanduser()
        if not source.exists():
            raise StoreError(f"auth file not found: {source}")
        target_dir = self.profile_dir(name)
        target_auth = target_dir / "auth.json"
        if target_auth.exists() and not overwrite:
            raise StoreError(f"profile already exists: {name}")

        auth = load_json(source)
        if not isinstance(auth.get("tokens"), dict) and not auth.get("OPENAI_API_KEY"):
            raise StoreError(f"{source} does not look like a Codex auth.json credential file")

        target_dir.mkdir(parents=True, exist_ok=True)
        target_dir.chmod(0o700)
        write_secret_json(target_auth, auth)

        prior_metadata = self.read_metadata(name)
        metadata = extract_metadata(auth)
        if prior_metadata.get("hidden"):
            metadata["hidden"] = True
        write_secret_json(target_dir / "metadata.json", metadata)
        if set_active or not self.paths.active_profile.exists():
            self.set_active_profile(name)
        return metadata

    def import_default_if_available(self) -> bool:
        if self.profile_exists("default"):
            return False
        source = default_codex_home() / "auth.json"
        if not source.exists():
            return False
        self.import_auth_file("default", source, set_active=True)
        return True

    def active_profile(self, *, required: bool = True) -> str | None:
        if self.paths.active_profile.exists():
            name = self.paths.active_profile.read_text(encoding="utf-8").strip()
            if name and self.profile_exists(name):
                return name
        if self.profile_exists("default"):
            self.set_active_profile("default")
            return "default"
        profiles = self.profile_names()
        if profiles:
            name = profiles[0]
            self.set_active_profile(name)
            return name
        if required:
            raise StoreError("no Codex profiles are enrolled; run `provision import-default` or `provision login <name>`")
        return None

    def set_active_profile(self, name: str) -> None:
        validate_profile_name(name)
        if not self.profile_exists(name):
            raise StoreError(f"profile does not exist: {name}")
        self.paths.active_profile.parent.mkdir(parents=True, exist_ok=True)
        self.paths.active_profile.write_text(name + "\n", encoding="utf-8")
        self.paths.active_profile.chmod(0o600)

    def set_profile_hidden(self, name: str, hidden: bool) -> None:
        """Persist dashboard visibility without changing profile availability.

        Hidden profiles continue to be eligible for routing and can remain
        active; this setting only declutters the dashboard profile list.
        """
        validate_profile_name(name)
        if not self.profile_exists(name):
            raise StoreError(f"profile does not exist: {name}")
        metadata = self.read_metadata(name)
        metadata["hidden"] = bool(hidden)
        write_secret_json(self.metadata_path(name), metadata)

    def remove_profile(self, name: str) -> None:
        """Remove credentials for a profile after a profile-scoped Codex logout."""
        directory = self.profile_dir(name)
        if not directory.exists():
            return
        shutil.rmtree(directory)
        if self.stored_active_profile() != name:
            return
        remaining = self.profile_names()
        if remaining:
            self.set_active_profile(remaining[0])
            return
        try:
            self.paths.active_profile.unlink()
        except FileNotFoundError:
            pass

    def proxy_token(self) -> str:
        if self.paths.proxy_token.exists():
            token = self.paths.proxy_token.read_text(encoding="utf-8").strip()
            if token:
                return token
        token = secrets.token_urlsafe(32)
        self.paths.proxy_token.parent.mkdir(parents=True, exist_ok=True)
        self.paths.proxy_token.write_text(token + "\n", encoding="utf-8")
        self.paths.proxy_token.chmod(0o600)
        return token

    def remote_secret(self) -> bytes:
        """Return the daemon-local secret used for opaque remote identifiers.

        This is intentionally distinct from the proxy token.  A future Remote
        Agent gets its authority from a paired transport identity, not from
        this value or any existing dashboard credential.
        """
        try:
            secret = self.paths.remote_secret.read_bytes()
        except OSError:
            secret = b""
        if len(secret) >= 32:
            return secret[:32]
        secret = secrets.token_bytes(32)
        self.paths.remote_secret.parent.mkdir(parents=True, exist_ok=True)
        self.paths.remote_secret.write_bytes(secret)
        self.paths.remote_secret.chmod(0o600)
        return secret

    def remote_agent_token(self) -> str:
        """Return the separate local capability for the future Remote Agent."""
        if self.paths.remote_agent_token.exists():
            token = self.paths.remote_agent_token.read_text(encoding="utf-8").strip()
            if token:
                return token
        token = secrets.token_urlsafe(32)
        self.paths.remote_agent_token.parent.mkdir(parents=True, exist_ok=True)
        self.paths.remote_agent_token.write_text(token + "\n", encoding="utf-8")
        self.paths.remote_agent_token.chmod(0o600)
        return token

    def connector_token(self) -> str:
        """Return the distinct local capability for an explicitly enabled Connector."""
        if self.paths.connector_token.exists():
            token = self.paths.connector_token.read_text(encoding="utf-8").strip()
            if token:
                return token
        token = secrets.token_urlsafe(32)
        self.paths.connector_token.parent.mkdir(parents=True, exist_ok=True)
        self.paths.connector_token.write_text(token + "\n", encoding="utf-8")
        self.paths.connector_token.chmod(0o600)
        return token

    def delete_capture(self, path: Path) -> None:
        try:
            shutil.rmtree(path)
        except FileNotFoundError:
            pass
