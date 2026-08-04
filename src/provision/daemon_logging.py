from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from typing import Any

from .paths import Paths

DAEMON_LOG_MAX_BYTES = 384 * 1024 * 1024
DAEMON_LOG_BACKUP_COUNT = 3


def daemon_log_archive_path(path: Path, index: int) -> Path:
    return path.with_name(f"{path.name}.{index}")


def rotate_daemon_log(
    path: Path,
    *,
    max_bytes: int = DAEMON_LOG_MAX_BYTES,
    backup_count: int = DAEMON_LOG_BACKUP_COUNT,
    force: bool = False,
) -> bool:
    """Rotate a daemon log before it grows beyond the configured limit."""
    try:
        if not force and path.stat().st_size < max_bytes:
            return False
    except OSError:
        return False
    try:
        daemon_log_archive_path(path, backup_count).unlink(missing_ok=True)
        for index in range(backup_count - 1, 0, -1):
            source = daemon_log_archive_path(path, index)
            if source.exists():
                source.replace(daemon_log_archive_path(path, index + 1))
        path.replace(daemon_log_archive_path(path, 1))
        return True
    except OSError:
        return False


class RotatingDaemonLog:
    """Thread-safe stderr/stdout sink for a daemon started by Provision."""

    encoding = "utf-8"
    errors = "backslashreplace"

    def __init__(
        self,
        path: Path,
        *,
        max_bytes: int = DAEMON_LOG_MAX_BYTES,
        backup_count: int = DAEMON_LOG_BACKUP_COUNT,
    ) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.lock = threading.RLock()
        self.handle: Any | None = None
        self._open_locked()

    def _open_locked(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.handle = self.path.open("ab")
            self.path.chmod(0o600)
        except OSError:
            self.handle = None

    def _rotate_locked(self, incoming_size: int) -> None:
        try:
            current_size = self.path.stat().st_size
        except OSError:
            current_size = 0
        if current_size <= 0 or current_size + incoming_size <= self.max_bytes:
            return
        if self.handle is not None:
            try:
                self.handle.close()
            except OSError:
                pass
            self.handle = None
        rotate_daemon_log(
            self.path,
            max_bytes=self.max_bytes,
            backup_count=self.backup_count,
            force=True,
        )
        self._open_locked()

    def write(self, data: str) -> int:
        if not isinstance(data, str):
            data = str(data)
        encoded = data.encode(self.encoding, errors=self.errors)
        with self.lock:
            self._rotate_locked(len(encoded))
            if self.handle is not None:
                try:
                    self.handle.write(encoded)
                    self.handle.flush()
                except OSError:
                    pass
        return len(data)

    def flush(self) -> None:
        with self.lock:
            if self.handle is not None:
                try:
                    self.handle.flush()
                except OSError:
                    pass

    def close(self) -> None:
        with self.lock:
            if self.handle is not None:
                try:
                    self.handle.close()
                except OSError:
                    pass
                self.handle = None

    def isatty(self) -> bool:
        return False

    def writable(self) -> bool:
        return True

    def fileno(self) -> int:
        with self.lock:
            if self.handle is None:
                raise OSError("daemon log is unavailable")
            return int(self.handle.fileno())


def configure_daemon_log_rotation(paths: Paths) -> None:
    """Install runtime rotation only for daemon processes Provision launched."""
    if os.environ.get("PROVISION_DAEMON_LOG") != str(paths.log):
        return
    sink = RotatingDaemonLog(paths.log)
    sys.stdout = sink
    sys.stderr = sink
