from __future__ import annotations

import http.client
import json
import os
import socket
import tempfile
import threading
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from provision import launcher
from provision.daemon import ProvisionServer
from provision.paths import Paths
from provision.permissions import (
    normalize_permission_hook_request,
    permission_key_is_sensitive,
    provider_permission_hook_output,
    run_permission_hook,
)
from provision.store import StoreError


class PermissionPayloadTests(unittest.TestCase):
    def test_hook_request_is_bounded_and_redacts_sensitive_fields(self) -> None:
        request = normalize_permission_hook_request(
            {
                "hook_event_name": "PermissionRequest",
                "session_id": "session-1",
                "turn_id": "turn-1",
                "tool_name": "mcp__example__deploy",
                "tool_input": {
                    "host": "example.invalid",
                    "api_key": "must-not-escape",
                    "nested": {"authorization": "Bearer hidden"},
                },
            },
            "codex",
        )

        self.assertEqual(request["category"], "mcp")
        self.assertNotIn("must-not-escape", request["preview"])
        self.assertNotIn("Bearer hidden", request["preview"])
        self.assertIn("[redacted]", request["preview"])
        self.assertTrue(permission_key_is_sensitive("refresh-token"))

        shell = normalize_permission_hook_request(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_input": {"command": "API_KEY=must-not-escape deploy --token hidden-value"},
            },
            "claude",
        )
        self.assertNotIn("must-not-escape", shell["preview"])
        self.assertNotIn("hidden-value", shell["preview"])
        self.assertIn("[redacted]", shell["preview"])

    def test_provider_hook_output_matches_shared_native_contract(self) -> None:
        output = json.loads(provider_permission_hook_output("codex", "allow"))
        self.assertEqual(
            output["hookSpecificOutput"]["decision"],
            {"behavior": "allow"},
        )
        self.assertEqual(provider_permission_hook_output("claude", "terminal"), "")

    def test_hook_forwards_decision_without_exposing_daemon_token(self) -> None:
        native = {
            "hook_event_name": "PermissionRequest",
            "tool_name": "Bash",
            "tool_input": {"command": "pwd"},
        }
        output = StringIO()
        with patch(
            "provision.permissions.permission_socket_request",
            return_value={"ok": True, "decision": "deny"},
        ) as request:
            result = run_permission_hook(
                "claude",
                stdin=StringIO(json.dumps(native)),
                stdout=output,
                environ={"PROVISION_PERMISSION_SOCKET": "/tmp/test.sock"},
            )

        self.assertEqual(result, 0)
        self.assertEqual(
            json.loads(output.getvalue())["hookSpecificOutput"]["decision"]["behavior"],
            "deny",
        )
        self.assertNotIn("token", json.dumps(request.call_args.args[1]).lower())


class ProviderPermissionAdapterTests(unittest.TestCase):
    def test_claude_receives_session_only_permission_hook(self) -> None:
        argv, bridge = launcher.provider_permission_bridge_argv(
            "claude", ["claude", "--model", "sonnet"]
        )

        self.assertEqual(bridge, "claude-permission-hook-v1")
        self.assertEqual(argv[:2], ["claude", "--settings"])
        settings = json.loads(argv[2])
        hook = settings["hooks"]["PermissionRequest"][0]["hooks"][0]
        self.assertIn("permission-hook --provider claude", hook["command"])
        self.assertEqual(argv[3:], ["--model", "sonnet"])

    def test_explicit_claude_settings_are_preserved(self) -> None:
        original = ["claude", "--settings", "/tmp/user-settings.json"]
        argv, bridge = launcher.provider_permission_bridge_argv("claude", original)

        self.assertIs(argv, original)
        self.assertIsNone(bridge)

    def test_unsupported_native_tui_is_not_rewritten(self) -> None:
        original = ["grok", "--model", "grok-code-fast"]
        argv, bridge = launcher.provider_permission_bridge_argv("grok", original)

        self.assertIs(argv, original)
        self.assertIsNone(bridge)

    def test_control_socket_reassembles_fragmented_json(self) -> None:
        client, server = socket.socketpair()
        capture = launcher.TerminalCapture()
        capture.append(b"recent output")
        worker = threading.Thread(
            target=launcher.handle_control_connection,
            kwargs={
                "conn": server,
                "master_fd": -1,
                "capture": capture,
                "port": 4888,
                "host": "127.0.0.1",
                "proxy_token": "not-forwarded",
                "session_key": "/tmp/workspace",
                "provider": "claude",
            },
        )
        worker.start()
        client.sendall(b'{"action":"terminal_')
        client.sendall(b'snapshot"}\n')
        response = bytearray()
        while b"\n" not in response:
            response.extend(client.recv(1024))
        client.close()
        worker.join(timeout=1.0)

        self.assertFalse(worker.is_alive())
        payload = json.loads(bytes(response).split(b"\n", 1)[0])
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["encoding"], "base64")


class PermissionBrokerTests(unittest.TestCase):
    def make_server(self, workspace: Path) -> tuple[ProvisionServer, str]:
        server = ProvisionServer.__new__(ProvisionServer)
        key = str(workspace.resolve())
        control_path = workspace.parent / "control.sock"
        control_path.parent.mkdir(parents=True, exist_ok=True)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(control_path))
        self.addCleanup(listener.close)
        server.active_lock = threading.Lock()
        server.observed_sessions = {
            key: {
                "key": key,
                "cwd": key,
                "name": workspace.name,
                "provider": "claude",
                "permission_bridge": "claude-permission-hook-v1",
                "control_path": str(control_path),
                "launcher_pid": os.getpid(),
            }
        }
        server.permission_condition = threading.Condition()
        server.pending_permissions = {}
        server.resolved_permissions = {}
        server.permission_routes = {}
        server.ui_client_count = 0
        server.ui_state_lock = threading.Lock()
        server.ui_state_version = 0
        server.ui_state_dirty_reasons = {}
        server.ui_state_dirty_log = []
        return server, key

    def wait_for_request(self, server: ProvisionServer) -> dict[str, object]:
        with server.permission_condition:
            ready = server.permission_condition.wait_for(
                lambda: bool(server.pending_permissions), timeout=1.0
            )
            self.assertTrue(ready)
        requests = server.permission_state_snapshot()["pending"]
        self.assertEqual(len(requests), 1)
        return requests[0]

    def test_authenticated_browser_decision_completes_one_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            server, key = self.make_server(Path(temp) / "workspace")
            server.ui_client_connected()
            server.set_permission_routing(key, True)
            result: list[dict[str, object]] = []
            worker = threading.Thread(
                target=lambda: result.append(
                    server.request_permission(
                        key,
                        "claude",
                        {"tool_name": "Bash", "preview": "Command: pwd"},
                        timeout=1.0,
                    )
                )
            )
            worker.start()
            request = self.wait_for_request(server)

            server.resolve_permission(str(request["request_id"]), key, "allow")
            worker.join(timeout=1.0)

            self.assertFalse(worker.is_alive())
            self.assertEqual(result, [{"ok": True, "decision": "allow"}])
            with self.assertRaisesRegex(StoreError, "no longer pending"):
                server.resolve_permission(str(request["request_id"]), key, "deny")

    def test_missing_browser_falls_back_to_native_terminal_immediately(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            server, key = self.make_server(Path(temp) / "workspace")
            server.set_permission_routing(key, True)

            result = server.request_permission(
                key,
                "claude",
                {"tool_name": "Bash", "preview": "Command: pwd"},
                timeout=0.05,
            )

            self.assertEqual(result["decision"], "terminal")
            self.assertEqual(server.permission_state_snapshot()["pending"], [])

    def test_replacement_launcher_does_not_inherit_prior_browser_routing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            server, key = self.make_server(Path(temp) / "workspace")
            server.ui_client_connected()
            server.set_permission_routing(key, True)
            with server.active_lock:
                server.observed_sessions[key]["permission_bridge"] = (
                    "claude-permission-hook-v1:new-binding"
                )

            result = server.request_permission(
                key,
                "claude",
                {"tool_name": "Bash", "preview": "Command: pwd"},
                timeout=0.05,
            )

            self.assertEqual(result["decision"], "terminal")
            self.assertEqual(server.permission_state_snapshot()["pending"], [])

    def test_last_browser_disconnect_releases_pending_request_to_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            server, key = self.make_server(Path(temp) / "workspace")
            server.ui_client_connected()
            server.set_permission_routing(key, True)
            result: list[dict[str, object]] = []
            worker = threading.Thread(
                target=lambda: result.append(
                    server.request_permission(
                        key,
                        "claude",
                        {"tool_name": "Bash", "preview": "Command: pwd"},
                        timeout=1.0,
                    )
                )
            )
            worker.start()
            self.wait_for_request(server)

            server.ui_client_disconnected()
            worker.join(timeout=1.0)

            self.assertFalse(worker.is_alive())
            self.assertEqual(result, [{"ok": True, "decision": "terminal"}])


class PermissionBridgeHttpTests(unittest.TestCase):
    def test_loopback_endpoint_requires_proxy_token_and_falls_back_safely(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = Paths(Path(temp) / "home")
            workspace = str((Path(temp) / "workspace").resolve())
            server = ProvisionServer(("127.0.0.1", 0), paths)
            server.observe_session(
                workspace,
                provider="claude",
                permission_bridge="claude-permission-hook-v1",
                pty_managed=True,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            def post(token: str) -> tuple[int, dict[str, object]]:
                connection = http.client.HTTPConnection(
                    "127.0.0.1", server.server_address[1], timeout=2
                )
                body = json.dumps(
                    {
                        "token": token,
                        "session_key": workspace,
                        "provider": "claude",
                        "request": {"tool_name": "Bash", "preview": "Command: pwd"},
                    }
                )
                connection.request(
                    "POST",
                    "/api/permission-request",
                    body=body,
                    headers={"content-type": "application/json"},
                )
                response = connection.getresponse()
                payload = json.loads(response.read().decode("utf-8"))
                connection.close()
                return response.status, payload

            try:
                denied_status, denied = post("invalid")
                allowed_status, allowed = post(server.proxy_token)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            self.assertEqual(denied_status, 401)
            self.assertIn("error", denied)
            self.assertEqual(allowed_status, 200)
            self.assertEqual(allowed["decision"], "terminal")


if __name__ == "__main__":
    unittest.main()
