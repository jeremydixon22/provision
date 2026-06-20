from __future__ import annotations

import os
from pathlib import Path


def provision_home() -> Path:
    configured = os.environ.get("PROVISION_HOME")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".provision"


def default_codex_home() -> Path:
    configured = os.environ.get("CODEX_HOME")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".codex"


def source_root() -> Path:
    return Path(__file__).resolve().parents[1]


def launcher_path() -> Path:
    return source_root().parents[0] / "bin" / "provision"


class Paths:
    def __init__(self, home: Path | None = None) -> None:
        self.home = (home or provision_home()).expanduser()
        self.codex = self.home / "codex"
        self.profiles = self.codex / "profiles"
        self.capture = self.codex / "capture"
        self.active_profile = self.codex / "active-profile"
        self.profile_settings = self.codex / "profile-settings.json"
        self.session_pins = self.codex / "session-pins.json"
        self.stats = self.codex / "stats.jsonl"
        self.reset_credit_events = self.codex / "reset-credit-events.jsonl"
        self.state = self.home / "daemon.json"
        self.proxy_token = self.home / "proxy-token"
        self.log = self.home / "daemon.log"

    def ensure_base(self) -> None:
        for path in (self.home, self.codex, self.profiles, self.capture):
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)
