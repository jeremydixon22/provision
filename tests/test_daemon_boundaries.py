from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from provision.daemon import UI_DIRTY_LOG_LIMIT, ProvisionServer
from provision.daemon_host import (
    daemon_bind_address,
    daemon_connect_host,
    daemon_host_is_loopback,
    daemon_url_host,
)
from provision.daemon_logging import daemon_log_archive_path, rotate_daemon_log


class DaemonHostTests(unittest.TestCase):
    def test_loopback_policy_accepts_only_explicit_loopback_names_and_addresses(
        self,
    ) -> None:
        for host in (None, "localhost", "127.0.0.1", "127.8.9.10", "::1", "[::1]"):
            with self.subTest(host=host):
                self.assertTrue(daemon_host_is_loopback(host))
        for host in ("0.0.0.0", "::", "192.0.2.10", "provision.example"):
            with self.subTest(host=host):
                self.assertFalse(daemon_host_is_loopback(host))

    def test_wildcard_bind_is_rewritten_only_for_local_client_urls(self) -> None:
        self.assertEqual(daemon_connect_host("0.0.0.0"), "127.0.0.1")
        self.assertEqual(daemon_url_host("::"), "127.0.0.1")
        self.assertEqual(daemon_bind_address("0.0.0.0", 4888), "0.0.0.0:4888")


class DaemonLoggingTests(unittest.TestCase):
    def test_rotation_keeps_numbered_archives(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "daemon.log"
            log.write_bytes(b"old")

            self.assertTrue(rotate_daemon_log(log, max_bytes=1, backup_count=2))
            self.assertEqual(daemon_log_archive_path(log, 1).read_bytes(), b"old")
            self.assertFalse(log.exists())


class DaemonConcurrencyTests(unittest.TestCase):
    def test_concurrent_ui_mutations_remain_monotonic_and_bounded(self) -> None:
        server = ProvisionServer.__new__(ProvisionServer)
        server.ui_state_lock = threading.Lock()
        server.ui_state_version = 0
        server.ui_state_dirty_reasons = {}
        server.ui_state_dirty_log = []
        workers = [
            threading.Thread(
                target=lambda reason=f"worker-{index}": [
                    server.mark_ui_dirty(reason) for _ in range(500)
                ]
            )
            for index in range(8)
        ]

        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()

        self.assertEqual(server.ui_state_revision(), 4000)
        self.assertLessEqual(len(server.ui_state_dirty_log), UI_DIRTY_LOG_LIMIT)
        self.assertEqual(sum(server.ui_state_dirty_reasons.values()), 4000)


if __name__ == "__main__":
    unittest.main()
