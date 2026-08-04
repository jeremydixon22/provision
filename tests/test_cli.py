from __future__ import annotations

import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from provision import cli
from provision.auth import AuthError
from provision.paths import Paths
from provision.store import Store


class CliUsabilityTests(unittest.TestCase):
    def test_ui_open_prints_and_opens_the_same_url(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = Paths(Path(temp) / "home")
            output = StringIO()
            status = {"host": "127.0.0.1", "port": 4888, "pid": 123}
            with (
                patch.object(cli, "ensure_daemon", return_value=status),
                patch.object(cli.webbrowser, "open", return_value=True) as open_browser,
                redirect_stdout(output),
            ):
                result = cli.cmd_ui(paths, open_browser=True)

        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue().strip(), "http://127.0.0.1:4888/ui")
        open_browser.assert_called_once_with("http://127.0.0.1:4888/ui")

    def test_parser_exposes_collision_resistant_and_bind_safety_options(self) -> None:
        parser = cli.build_parser()

        ui = parser.parse_args(["ui", "--open"])
        daemon = parser.parse_args(["daemon", "--host", "0.0.0.0", "--allow-non-loopback"])

        self.assertTrue(ui.open)
        self.assertTrue(daemon.allow_non_loopback)

    def test_internal_permission_hook_dispatches_without_initializing_store(self) -> None:
        with (
            patch.object(cli, "run_permission_hook", return_value=0) as hook,
            patch.object(cli, "Store", side_effect=AssertionError("store must not initialize")),
        ):
            result = cli.main(["permission-hook", "--provider", "claude"])

        self.assertEqual(result, 0)
        hook.assert_called_once()

    def test_doctor_surfaces_actionable_oauth_client_id_discovery_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = Paths(Path(temp) / "home")
            store = Store(paths)
            output = StringIO()
            compatibility = {
                "cli": {"available": True, "version": "test"},
                "model_catalog": {"source": "codex", "count": 1},
            }
            error = AuthError(
                "could not discover the Codex OAuth client id; "
                "set PROVISION_CODEX_CLIENT_ID or reinstall Codex"
            )
            with (
                patch.object(cli, "codex_compatibility_payload", return_value=compatibility),
                patch.object(cli, "codex_client_id", side_effect=error),
                patch.object(cli, "daemon_running", return_value=None),
                redirect_stdout(output),
            ):
                cli.cmd_doctor(paths, store)

        self.assertIn("Codex OAuth client-id discovery", output.getvalue())
        self.assertIn("PROVISION_CODEX_CLIENT_ID", output.getvalue())


if __name__ == "__main__":
    unittest.main()
