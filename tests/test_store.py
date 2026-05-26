from __future__ import annotations

import http.client
import json
import os
import socket
import tempfile
import threading
import time
import unittest
import urllib.parse
from argparse import Namespace
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path

import provision.daemon as daemon_module
from provision.auth import codex_client_id_from_bytes, decode_jwt_claims, extract_metadata
from provision.cli import cmd_import_default, daemon_switch_profile
from provision.daemon import analytics_completed_turn_ids
from provision.daemon import analytics_turn_ids
from provision.daemon import backend_proxy_prefix
from provision.daemon import backend_upstream_path
from provision.daemon import CHATGPT_ANALYTICS_EVENTS_PATH
from provision.daemon import label_usage_payload
from provision.daemon import logo_asset_bytes
from provision.daemon import Handler
from provision.daemon import ProvisionServer
from provision.daemon import decode_project_session_sentinel
from provision.daemon import project_session_sentinel
from provision.daemon import redact_proxy_token
from provision.daemon import render_quota_html
from provision.daemon import request_body_session
from provision.daemon import should_forward_incoming_header
from provision.daemon import usage_payload_from_rate_limit_headers
from provision.daemon import usage_payload_from_websocket_message
from provision.daemon import usage_cache_summary
from provision.daemon import usage_payload_reset_datetimes
from provision.daemon import usage_refresh_due_at
from provision.daemon import UpstreamRoute
from provision.daemon import WebSocketMessageTracker
from provision.daemon import WEBSOCKET_SWITCH_IDLE_SECONDS
from provision.daemon import websocket_accept_key
from provision.daemon import websocket_chunk_has_application_data
from provision.daemon import websocket_handshake_status
from provision.daemon import websocket_message_has_terminal_event
from provision.daemon import websocket_message_completion_action
from provision.daemon import websocket_message_has_tool_output
from provision.daemon import websocket_message_starts_response
from provision.daemon import websocket_message_turn_id
from provision.daemon import websocket_terminal_event_keeps_work_pending
from provision.launcher import chatgpt_base_url_override
from provision.launcher import configured_daemon_port
from provision.paths import Paths
from provision.store import Store


def fake_jwt(payload: dict) -> str:
    import base64

    raw = json.dumps(payload).encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"header.{encoded}.signature"


class StoreTests(unittest.TestCase):
    def test_decode_jwt_claims(self) -> None:
        token = fake_jwt({"email": "user@example.test", "exp": 123})
        self.assertEqual(decode_jwt_claims(token)["email"], "user@example.test")

    def test_import_auth_file_writes_profile_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            auth = {
                "auth_mode": "chatgpt",
                "tokens": {
                    "id_token": fake_jwt(
                        {
                            "email": "user@example.test",
                            "name": "Test User",
                            "https://api.openai.com/auth": {
                                "chatgpt_account_id": "acct_123",
                                "chatgpt_plan_type": "pro",
                            },
                        }
                    ),
                    "access_token": fake_jwt({"exp": 9999999999}),
                    "refresh_token": "rt_test",
                    "account_id": "acct_123",
                },
            }
            source = root / "auth.json"
            source.write_text(json.dumps(auth), encoding="utf-8")

            store = Store(Paths(root / "home"))
            metadata = store.import_auth_file("default", source)

            self.assertEqual(metadata["email"], "user@example.test")
            self.assertEqual(metadata["account_id"], "acct_123")
            self.assertTrue(store.auth_path("default").exists())
            self.assertEqual(store.active_profile(), "default")

    def test_import_default_command_is_idempotent_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            auth = {
                "auth_mode": "chatgpt",
                "tokens": {
                    "id_token": fake_jwt({"email": "user@example.test"}),
                    "access_token": fake_jwt({"exp": 9999999999}),
                    "refresh_token": "rt_test",
                },
            }
            source = root / "auth.json"
            source.write_text(json.dumps(auth), encoding="utf-8")
            store = Store(Paths(root / "home"))
            args = Namespace(name="default", source=source, overwrite=False)

            with redirect_stdout(StringIO()):
                self.assertEqual(cmd_import_default(store, args), 0)
                self.assertEqual(cmd_import_default(store, args), 0)
            self.assertEqual(store.read_metadata("default")["email"], "user@example.test")

    def test_empty_store_has_no_active_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Paths(Path(temp) / "home"))
            self.assertEqual(store.list_profiles(), [])
            self.assertIsNone(store.active_profile(required=False))

    def test_proxy_strips_incoming_identity_headers(self) -> None:
        self.assertFalse(should_forward_incoming_header("Authorization"))
        self.assertFalse(should_forward_incoming_header("ChatGPT-Account-ID"))
        self.assertFalse(should_forward_incoming_header("X-OpenAI-Fedramp"))
        self.assertFalse(should_forward_incoming_header("OpenAI-Organization"))
        self.assertFalse(should_forward_incoming_header("OpenAI-Project"))
        self.assertTrue(should_forward_incoming_header("X-Codex-Turn-State"))

    def test_backend_proxy_path_strips_local_token_prefix(self) -> None:
        self.assertEqual(backend_proxy_prefix("tok_123"), "/backend-api/provision-tok_123")
        self.assertEqual(
            backend_upstream_path("/backend-api/provision-tok_123/wham/usage", "tok_123"),
            "/wham/usage",
        )
        self.assertEqual(backend_proxy_prefix(), "/backend-api/provision")
        self.assertEqual(
            backend_upstream_path("/backend-api/provision/wham/usage", "tok_123"),
            "/wham/usage",
        )

    def test_backend_proxy_path_rejects_wrong_token(self) -> None:
        with self.assertRaises(RuntimeError):
            backend_upstream_path("/backend-api/provision-wrong/wham/usage", "tok_123")

    def test_chatgpt_base_url_override_uses_local_backend_path(self) -> None:
        self.assertEqual(
            chatgpt_base_url_override(12345, "tok_123"),
            'chatgpt_base_url="http://127.0.0.1:12345/backend-api/provision"',
        )

    def test_proxy_token_redaction(self) -> None:
        self.assertEqual(
            redact_proxy_token("GET /backend-api/provision-tok_123/wham/usage", "tok_123"),
            "GET /backend-api/provision-<redacted>/wham/usage",
        )
        self.assertEqual(
            redact_proxy_token("GET /api/ui-ws?token=tok_123", "tok_123"),
            "GET /api/ui-ws?token=<redacted>",
        )

    def test_websocket_accept_key_matches_rfc_example(self) -> None:
        self.assertEqual(
            websocket_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        )

    def test_upstream_websocket_handshake_disables_extensions(self) -> None:
        handler = Handler.__new__(Handler)
        handler.headers = {
            "Host": "127.0.0.1:4888",
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Key": "key",
            "Sec-WebSocket-Extensions": "permessage-deflate",
        }

        request = handler.websocket_handshake_request(
            "api.openai.com",
            "/v1/responses",
            {"tokens": {"access_token": "token"}},
        ).decode("iso-8859-1")

        self.assertIn("Sec-WebSocket-Key: key", request)
        self.assertIn("authorization: Bearer token", request)
        self.assertNotIn("Sec-WebSocket-Extensions", request)

    def test_websocket_handshake_status_parses_response_code(self) -> None:
        self.assertEqual(
            websocket_handshake_status(b"HTTP/1.1 101 Switching Protocols\r\n\r\n"),
            101,
        )
        self.assertEqual(
            websocket_handshake_status(b"HTTP/1.1 401 Unauthorized\r\n\r\n"),
            401,
        )
        self.assertIsNone(websocket_handshake_status(b"not http\r\n\r\n"))

    def test_logo_assets_are_packaged(self) -> None:
        full_logo = logo_asset_bytes("provision.png") or b""
        wordmark = logo_asset_bytes("provision-wordmark.png") or b""
        self.assertGreater(len(full_logo), 0)
        self.assertGreater(len(wordmark), 0)
        self.assertEqual(wordmark[25], 6)
        self.assertIsNone(logo_asset_bytes("../auth.json"))

    def test_quota_html_renders_bars_and_extra_buckets(self) -> None:
        markup = render_quota_html(
            {
                "payload": {
                    "rate_limit": {
                        "allowed": True,
                        "primary_window": {
                            "used_percent": 25,
                            "limit_window_seconds": 18000,
                            "reset_after_seconds": 3600,
                        },
                        "secondary_window": {
                            "used_percent": 16,
                            "limit_window_seconds": 604800,
                        },
                    },
                    "additional_rate_limits": [
                        {
                            "limit_name": "Spark",
                            "metered_feature": "gpt-5.3-codex-spark",
                            "rate_limit": {
                                "allowed": True,
                                "primary_window": {
                                    "used_percent": 90,
                                    "limit_window_seconds": 3600,
                                },
                            },
                        }
                    ],
                },
                "fetched_at": datetime(2026, 5, 22, 15, 36),
            }
        )

        self.assertIn('role="progressbar"', markup)
        self.assertIn("75%", markup)
        self.assertNotIn("75% left", markup)
        self.assertIn("5h (Resets", markup)
        self.assertIn("Updated 15:36 on 22 May", markup)
        self.assertIn("Weekly", markup)
        self.assertIn("Spark", markup)
        self.assertIn("gpt-5.3-codex-spark", markup)
        self.assertIn("quota-stack-bar", markup)

    def test_project_session_sentinel_carries_cwd(self) -> None:
        sentinel = project_session_sentinel("token", "/tmp/provision")

        decoded = decode_project_session_sentinel(sentinel, "token")

        self.assertEqual(decoded, {"key": "/tmp/provision", "cwd": "/tmp/provision"})
        self.assertEqual(decode_project_session_sentinel("provision-token", "token"), {})
        self.assertIsNone(decode_project_session_sentinel(sentinel, "other"))

    def test_request_body_session_reads_turn_metadata_workspace(self) -> None:
        body = json.dumps(
            {
                "type": "response.create",
                "client_metadata": {
                    "x-codex-turn-metadata": json.dumps(
                        {
                            "turn_id": "turn-1",
                            "workspaces": {"/tmp/provision": {"has_changes": True}},
                        }
                    )
                },
            }
        ).encode("utf-8")

        self.assertEqual(
            request_body_session(body),
            {"key": "/tmp/provision", "cwd": "/tmp/provision"},
        )

    def test_websocket_activity_distinguishes_control_frames(self) -> None:
        self.assertFalse(websocket_chunk_has_application_data(b"\x89\x00"))
        self.assertFalse(websocket_chunk_has_application_data(b"\x8a\x00"))
        self.assertFalse(
            websocket_chunk_has_application_data(b"\x89\x80\x00\x00\x00\x00")
        )
        self.assertTrue(websocket_chunk_has_application_data(b"\x81\x05hello"))
        self.assertTrue(
            websocket_chunk_has_application_data(b"\x81\x85\x00\x00\x00\x00hello")
        )

    def test_websocket_message_tracker_unmasks_client_frames(self) -> None:
        tracker = WebSocketMessageTracker()
        self.assertEqual(tracker.feed(b"\x81"), [])
        self.assertEqual(
            tracker.feed(b"\x85\x00\x00\x00\x00hello"),
            [(0x1, b"hello")],
        )

    def test_websocket_terminal_event_detection(self) -> None:
        self.assertTrue(
            websocket_message_has_terminal_event(
                0x1,
                b'{"type":"response.completed"}',
            )
        )
        self.assertTrue(
            websocket_message_has_terminal_event(
                0x1,
                b'{"response":{"id":"resp_123","status":"failed"}}',
            )
        )
        self.assertFalse(
            websocket_message_has_terminal_event(
                0x1,
                b'{"type":"response.output_item.done"}',
            )
        )

    def test_websocket_response_start_detection(self) -> None:
        metadata = json.dumps({"turn_id": "turn-123"})
        self.assertTrue(
            websocket_message_starts_response(
                0x1,
                json.dumps(
                    {
                        "type": "response.create",
                        "response": {"model": "gpt-test"},
                        "client_metadata": {
                            "x-codex-turn-metadata": metadata,
                        },
                    }
                ).encode("utf-8"),
            )
        )
        self.assertEqual(
            websocket_message_turn_id(
                0x1,
                json.dumps(
                    {
                        "type": "response.create",
                        "client_metadata": {
                            "x-codex-turn-metadata": metadata,
                        },
                    }
                ).encode("utf-8"),
            ),
            "turn-123",
        )
        self.assertFalse(
            websocket_message_starts_response(
                0x1,
                b'{"type":"session.update"}',
            )
        )
        self.assertFalse(
            websocket_message_starts_response(
                0x1,
                b'{"type":"session.update","response":{"type":"response.create"}}',
            )
        )
        self.assertFalse(
            websocket_message_starts_response(
                0x1,
                b'{"type":"response.create","generate":false}',
            )
        )
        self.assertFalse(
            websocket_message_starts_response(
                0x2,
                b'{"type":"response.create"}',
            )
        )

    def test_websocket_response_completion_action(self) -> None:
        self.assertEqual(
            websocket_message_completion_action(
                0x1,
                (
                    b'{"type":"response.completed","response":{"id":"resp_1",'
                    b'"status":"completed","output":[{"type":"message"}]}}'
                ),
            ),
            "complete",
        )
        self.assertEqual(
            websocket_message_completion_action(
                0x1,
                (
                    b'{"type":"response.completed","response":{"id":"resp_1",'
                    b'"status":"completed","output":[{"type":"function_call"}]}}'
                ),
            ),
            "keep",
        )
        self.assertEqual(
            websocket_message_completion_action(
                0x1,
                b'{"response":{"id":"resp_1","status":"failed"}}',
            ),
            "clear",
        )
        self.assertIsNone(
            websocket_message_completion_action(
                0x1,
                b'{"type":"response.function_call_arguments.done"}',
            )
        )
        self.assertTrue(
            websocket_message_has_tool_output(
                0x1,
                (
                    b'{"type":"response.output_item.done","item":'
                    b'{"type":"custom_tool_call"}}'
                ),
            )
        )

    def test_websocket_terminal_event_keeps_pending_for_tool_output(self) -> None:
        self.assertTrue(
            websocket_terminal_event_keeps_work_pending(
                0x1,
                (
                    b'{"type":"response.completed","response":{"id":"resp_1",'
                    b'"status":"completed","output":[{"type":"local_shell_call"}]}}'
                ),
            )
        )
        self.assertFalse(
            websocket_terminal_event_keeps_work_pending(
                0x1,
                (
                    b'{"type":"response.completed","response":{"id":"resp_1",'
                    b'"status":"completed","output":[{"type":"message"}]}}'
                ),
            )
        )

    def test_analytics_completed_turn_ids(self) -> None:
        payload = json.dumps(
            {
                "events": [
                    {
                        "event_type": "codex_turn_event",
                        "event_params": {
                            "turn_id": "turn-1",
                            "status": "completed",
                        },
                    },
                    {
                        "event_type": "codex_turn_event",
                        "event_params": {
                            "turn_id": "turn-2",
                            "status": "failed",
                        },
                    },
                    {
                        "event_type": "codex_turn_event",
                        "event_params": {
                            "turn_id": "turn-3",
                            "status": "in_progress",
                        },
                    },
                    {"event_type": "other"},
                ]
            }
        ).encode("utf-8")

        self.assertEqual(analytics_completed_turn_ids(payload), ["turn-1", "turn-2"])
        self.assertEqual(analytics_turn_ids(payload), ["turn-1", "turn-2", "turn-3"])

    def test_analytics_request_session_infers_pinned_turn_session(self) -> None:
        server = ProvisionServer.__new__(ProvisionServer)
        server.active_requests = {}
        server.active_websockets = {}
        server.active_lock = threading.Lock()
        server.next_request_id = 0
        server.next_websocket_id = 0
        server.observed_sessions = {}
        server.pinned_sessions = {"/tmp/pinned": "default"}
        server.proxy_token = "token"

        left, right = socket.socketpair()
        tunnel_id = server.begin_websocket("default", left, "/tmp/pinned")
        try:
            server.observe_session("/tmp/pinned", "default")
            server.begin_websocket_work(tunnel_id, "turn-pinned")
            handler = Handler.__new__(Handler)
            handler.server = server
            handler.headers = {}
            body = json.dumps(
                {
                    "events": [
                        {
                            "event_type": "codex_turn_event",
                            "event_params": {
                                "turn_id": "turn-pinned",
                                "status": "completed",
                            },
                        }
                    ]
                }
            ).encode("utf-8")

            session = handler.request_session(
                body,
                route=UpstreamRoute.CHATGPT_BACKEND,
                method="POST",
                upstream_path=CHATGPT_ANALYTICS_EVENTS_PATH,
            )

            self.assertEqual(session, {"key": "/tmp/pinned", "cwd": "/tmp/pinned"})
            request_id = server.begin_request("default", session["key"] if session else None)
            try:
                self.assertEqual(server.request_count(), 1)
                self.assertEqual(server.request_count(blocking_only=True), 0)
                self.assertIsNone(server.switch_block_reason())
            finally:
                server.end_request(request_id)
        finally:
            server.end_websocket(tunnel_id)
            left.close()
            right.close()

    def test_websocket_upstream_requires_https(self) -> None:
        handler = Handler.__new__(Handler)
        original = daemon_module.upstream_base_url
        try:
            daemon_module.upstream_base_url = lambda auth: "http://example.test/v1"
            with self.assertRaises(OSError) as exc:
                handler.open_upstream_websocket(
                    urllib.parse.urlparse("/v1/responses"),
                    {},
                )
        finally:
            daemon_module.upstream_base_url = original

        self.assertIn("requires HTTPS", str(exc.exception))

    def test_ui_post_redirect_has_zero_length_body(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            auth = {
                "auth_mode": "chatgpt",
                "tokens": {
                    "id_token": fake_jwt({"email": "user@example.test"}),
                    "access_token": fake_jwt({"exp": 9999999999}),
                    "refresh_token": "rt_test",
                },
            }
            source = root / "auth.json"
            source.write_text(json.dumps(auth), encoding="utf-8")
            paths = Paths(root / "home")
            store = Store(paths)
            store.import_auth_file("default", source)
            store.import_auth_file("work", source)
            server = ProvisionServer(("127.0.0.1", 0), paths)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                body = f"token={server.proxy_token}&profile=work"
                conn = http.client.HTTPConnection(
                    "127.0.0.1",
                    server.server_address[1],
                    timeout=2,
                )
                conn.request(
                    "POST",
                    "/api/switch",
                    body=body,
                    headers={"content-type": "application/x-www-form-urlencoded"},
                )
                response = conn.getresponse()
                payload = response.read()
                conn.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            self.assertEqual(response.status, 303)
            self.assertEqual(response.getheader("content-length"), "0")
            self.assertEqual(payload, b"")
            self.assertEqual(store.active_profile(), "work")

    def test_cli_daemon_switch_routes_through_running_daemon(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            auth = {
                "auth_mode": "chatgpt",
                "tokens": {
                    "id_token": fake_jwt({"email": "user@example.test"}),
                    "access_token": fake_jwt({"exp": 9999999999}),
                    "refresh_token": "rt_test",
                },
            }
            source = root / "auth.json"
            source.write_text(json.dumps(auth), encoding="utf-8")
            paths = Paths(root / "home")
            store = Store(paths)
            store.import_auth_file("default", source)
            store.import_auth_file("work", source)
            server = ProvisionServer(("127.0.0.1", 0), paths)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                daemon_switch_profile(store, "work", server.server_address[1])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            self.assertEqual(store.active_profile(), "work")

    def test_usage_payload_labels_active_and_default_profile_limits(self) -> None:
        active = {
            "rate_limit": {
                "allowed": True,
                "primary_window": {"remaining": 10},
                "secondary_window": {"remaining": 20},
            },
            "additional_rate_limits": [
                {
                    "limit_name": "Active extra bucket",
                    "metered_feature": "codex_active_extra",
                    "rate_limit": {
                        "allowed": True,
                        "primary_window": {"remaining": 5},
                        "secondary_window": {"remaining": 6},
                    },
                }
            ],
        }
        default_profile_payload = {
            "rate_limit": {
                "allowed": True,
                "primary_window": {"remaining": 1},
                "secondary_window": {"remaining": 2},
            },
            "additional_rate_limits": [
                {
                    "limit_name": "Default extra bucket",
                    "metered_feature": "codex_default_extra",
                    "rate_limit": {
                        "allowed": True,
                        "primary_window": {"remaining": 3},
                        "secondary_window": {"remaining": 4},
                    },
                }
            ],
        }

        labeled = label_usage_payload(
            active,
            active_profile="work",
            updated_at=datetime(2026, 5, 28, 15, 36),
            default_profile="default",
            default_payload=default_profile_payload,
        )

        rows = {
            row["metered_feature"]: row
            for row in labeled["additional_rate_limits"]
        }
        self.assertEqual(
            rows["codex"]["limit_name"],
            "Provision (work - updated 15:36 on 28 May)",
        )
        self.assertEqual(
            rows["provision_default_codex"]["limit_name"],
            "Provision profile (default)",
        )
        self.assertEqual(rows["codex_active_extra"]["limit_name"], "Active extra bucket")
        self.assertEqual(
            rows["provision_default_codex_default_extra"]["limit_name"],
            "Provision profile (default): Default extra bucket",
        )

    def test_usage_payload_replaces_existing_provision_labels(self) -> None:
        active = {
            "rate_limit": {"allowed": True},
            "additional_rate_limits": [
                {
                    "limit_name": "Old Provision label",
                    "metered_feature": "codex",
                    "rate_limit": {"allowed": False},
                },
                {
                    "limit_name": "Other",
                    "metered_feature": "other",
                    "rate_limit": {"allowed": True},
                },
            ],
        }

        labeled = label_usage_payload(
            active,
            active_profile="new",
            updated_at=datetime(2026, 5, 22, 9, 7),
        )

        rows = labeled["additional_rate_limits"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[-1]["metered_feature"], "codex")
        self.assertEqual(rows[-1]["limit_name"], "Provision (new - updated 09:07 on 22 May)")

    def test_usage_cache_reuses_recent_payload(self) -> None:
        server = ProvisionServer.__new__(ProvisionServer)
        server.usage_cache = {}
        server.usage_cache_lock = threading.Lock()
        server.usage_refresh_lock = threading.Lock()
        server.last_usage_refresh_monotonic = 0.0
        calls = 0

        def fetcher() -> dict:
            nonlocal calls
            calls += 1
            return {"rate_limit": {"allowed": True}}

        first, _, first_state = server.cached_usage_payload("default", fetcher)
        second, _, second_state = server.cached_usage_payload("default", fetcher, force=True)

        self.assertEqual(first, second)
        self.assertEqual(calls, 1)
        self.assertEqual(first_state, "fresh")
        self.assertEqual(second_state, "cached")

    def test_usage_payload_from_rate_limit_headers_reads_extra_buckets(self) -> None:
        payload = usage_payload_from_rate_limit_headers(
            {
                "x-codex-primary-used-percent": "25",
                "x-codex-primary-window-minutes": "300",
                "x-codex-primary-reset-at": "1790000000",
                "x-codex-spark-primary-used-percent": "60",
                "x-codex-spark-primary-window-minutes": "60",
                "x-codex-spark-limit-name": "Spark",
            }
        )

        self.assertIsInstance(payload, dict)
        assert payload is not None
        self.assertEqual(
            payload["rate_limit"]["primary_window"],
            {
                "used_percent": 25.0,
                "limit_window_seconds": 18000,
                "reset_at": 1790000000,
            },
        )
        self.assertEqual(payload["additional_rate_limits"][0]["limit_name"], "Spark")
        self.assertEqual(payload["additional_rate_limits"][0]["metered_feature"], "codex_spark")

    def test_usage_payload_from_websocket_rate_limit_event(self) -> None:
        payload = usage_payload_from_websocket_message(
            0x1,
            json.dumps(
                {
                    "type": "codex.rate_limits",
                    "metered_limit_name": "codex-spark",
                    "limit_name": "Spark",
                    "rate_limits": {
                        "primary": {
                            "used_percent": 20,
                            "window_minutes": 300,
                            "reset_at": 1790000000,
                        },
                        "secondary": {
                            "used_percent": 40,
                            "window_minutes": 10080,
                        },
                    },
                }
            ).encode("utf-8"),
        )

        self.assertIsInstance(payload, dict)
        assert payload is not None
        bucket = payload["additional_rate_limits"][0]
        self.assertEqual(bucket["metered_feature"], "codex_spark")
        self.assertEqual(bucket["limit_name"], "Spark")
        self.assertEqual(bucket["rate_limit"]["primary_window"]["limit_window_seconds"], 18000)
        self.assertEqual(bucket["rate_limit"]["secondary_window"]["used_percent"], 40.0)

    def test_usage_cache_observation_merges_with_existing_payload(self) -> None:
        server = ProvisionServer.__new__(ProvisionServer)
        server.usage_cache = {
            "default": {
                "payload": {
                    "rate_limit": {
                        "secondary_window": {
                            "used_percent": 10,
                            "limit_window_seconds": 604800,
                        }
                    },
                    "additional_rate_limits": [
                        {
                            "limit_name": "Spark",
                            "metered_feature": "codex_spark",
                            "rate_limit": {"primary_window": {"used_percent": 50}},
                        }
                    ],
                },
                "error": "old error",
            }
        }
        server.usage_cache_lock = threading.Lock()

        updated = server.update_usage_cache_from_observation(
            "default",
            {
                "rate_limit": {"primary_window": {"used_percent": 25}},
                "additional_rate_limits": [
                    {
                        "limit_name": "Spark",
                        "metered_feature": "codex_spark",
                        "rate_limit": {"secondary_window": {"used_percent": 70}},
                    }
                ],
            },
            source="test",
        )

        self.assertTrue(updated)
        snapshot = server.usage_cache_snapshot("default")
        assert snapshot is not None
        payload = snapshot["payload"]
        self.assertEqual(payload["rate_limit"]["primary_window"]["used_percent"], 25)
        self.assertEqual(payload["rate_limit"]["secondary_window"]["used_percent"], 10)
        spark = payload["additional_rate_limits"][0]["rate_limit"]
        self.assertEqual(spark["primary_window"]["used_percent"], 50)
        self.assertEqual(spark["secondary_window"]["used_percent"], 70)
        self.assertIsNone(snapshot["error"])
        self.assertEqual(snapshot["source"], "test")

    def test_usage_cache_observation_handles_null_additional_limits(self) -> None:
        server = ProvisionServer.__new__(ProvisionServer)
        server.usage_cache = {
            "default": {
                "payload": {
                    "rate_limit": {"primary_window": {"used_percent": 10}},
                    "additional_rate_limits": None,
                }
            }
        }
        server.usage_cache_lock = threading.Lock()

        updated = server.update_usage_cache_from_observation(
            "default",
            {
                "additional_rate_limits": [
                    {
                        "limit_name": "Spark",
                        "metered_feature": "codex_spark",
                        "rate_limit": {"primary_window": {"used_percent": 40}},
                    }
                ]
            },
            source="test",
        )

        self.assertTrue(updated)
        snapshot = server.usage_cache_snapshot("default")
        assert snapshot is not None
        payload = snapshot["payload"]
        self.assertEqual(
            payload["additional_rate_limits"][0]["metered_feature"],
            "codex_spark",
        )

    def test_usage_refresh_due_at_tracks_hourly_per_account(self) -> None:
        now = datetime(2026, 5, 25, 12, 0, tzinfo=timezone.utc)
        recent = {
            "fetched_at": now - timedelta(minutes=59),
            "payload": {"rate_limit": {}},
        }
        stale = {
            "fetched_at": now - timedelta(minutes=61),
            "payload": {"rate_limit": {}},
        }

        self.assertGreater(usage_refresh_due_at(recent, now), now)
        self.assertLessEqual(usage_refresh_due_at(stale, now), now)

    def test_usage_refresh_due_at_tracks_reset_plus_delay(self) -> None:
        fetched_at = datetime(2026, 5, 25, 5, 0, tzinfo=timezone.utc)
        reset_at = datetime(2026, 5, 25, 5, 55, tzinfo=timezone.utc)
        due_at = datetime(2026, 5, 25, 5, 56, tzinfo=timezone.utc)
        entry = {
            "fetched_at": fetched_at,
            "payload": {
                "rate_limit": {
                    "primary_window": {"used_percent": 90, "reset_at": reset_at.isoformat()},
                    "secondary_window": {"used_percent": 10},
                }
            },
        }

        self.assertEqual(usage_payload_reset_datetimes(entry["payload"], fetched_at), [reset_at])
        self.assertEqual(usage_refresh_due_at(entry, fetched_at), due_at)
        self.assertLessEqual(usage_refresh_due_at(entry, due_at), due_at)

        refreshed = dict(entry)
        refreshed["fetched_at"] = due_at + timedelta(seconds=5)
        self.assertGreater(usage_refresh_due_at(refreshed, due_at), due_at)

    def test_usage_auto_refresh_due_profiles_uses_per_profile_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            auth = {
                "auth_mode": "chatgpt",
                "tokens": {
                    "id_token": fake_jwt({"email": "user@example.test"}),
                    "access_token": fake_jwt({"exp": 9999999999}),
                    "refresh_token": "rt_test",
                },
            }
            source = root / "auth.json"
            source.write_text(json.dumps(auth), encoding="utf-8")
            paths = Paths(root / "home")
            store = Store(paths)
            store.import_auth_file("old", source)
            store.import_auth_file("recent", source)

            server = ProvisionServer(("127.0.0.1", 0), paths)
            now = datetime(2026, 5, 25, 12, 0, tzinfo=timezone.utc)
            try:
                server.usage_cache = {
                    "old": {
                        "fetched_at": now - timedelta(minutes=61),
                        "payload": {"rate_limit": {}},
                    },
                    "recent": {
                        "fetched_at": now - timedelta(minutes=15),
                        "payload": {"rate_limit": {}},
                    },
                }

                self.assertEqual(server.usage_auto_refresh_due_profiles(now), ["old"])
            finally:
                server.server_close()

    def test_usage_cache_summary_formats_last_known_quota(self) -> None:
        summary = usage_cache_summary(
            {
                "payload": {
                    "rate_limit": {
                        "primary_window": {
                            "used_percent": 25,
                            "limit_window_seconds": 18000,
                        },
                        "secondary_window": {
                            "remaining": 12,
                            "limit_window_seconds": 604800,
                        },
                    },
                    "additional_rate_limits": [{"limit_name": "Spark"}],
                },
                "fetched_at": datetime(2026, 5, 22, 15, 36),
            }
        )

        self.assertIn("Updated 15:36 on 22 May", summary)
        self.assertIn("5h 75%", summary)
        self.assertIn("weekly 12 remaining", summary)
        self.assertIn("1 extra bucket", summary)

    def test_websocket_work_state_blocks_until_terminal_event(self) -> None:
        server = ProvisionServer.__new__(ProvisionServer)
        server.active_requests = {}
        server.active_websockets = {}
        server.active_lock = threading.Lock()
        server.next_request_id = 0
        server.next_websocket_id = 0
        server.observed_sessions = {}
        server.pinned_sessions = {}

        left, right = socket.socketpair()
        tunnel_id = server.begin_websocket("default", left)
        try:
            self.assertEqual(server.request_count(), 0)
            self.assertEqual(server.websocket_count(), 1)
            self.assertIsNone(server.switch_block_reason())

            server.begin_websocket_work(tunnel_id, "turn-1")
            server.begin_websocket_work(tunnel_id, "turn-1")
            self.assertEqual(server.pending_websocket_work_count(), 1)
            self.assertIn("pending work", server.switch_block_reason() or "")

            with server.active_lock:
                server.active_websockets[tunnel_id][
                    "last_data_activity_monotonic"
                ] = time.monotonic() - WEBSOCKET_SWITCH_IDLE_SECONDS - 0.1

            self.assertIn("pending work", server.switch_block_reason() or "")
            server.complete_websocket_response(tunnel_id)
            self.assertIn("pending work", server.switch_block_reason() or "")
            with server.active_lock:
                server.active_websockets[tunnel_id][
                    "completion_deadline_monotonic"
                ] = time.monotonic() - 0.1
            self.assertEqual(server.pending_websocket_work_count(), 0)
            self.assertIsNone(server.switch_block_reason())

            server.begin_websocket_work(tunnel_id, "turn-2")
            server.complete_websocket_response(tunnel_id)
            self.assertEqual(server.finish_websocket_work_for_turn("turn-2"), 1)
            self.assertEqual(server.pending_websocket_work_count(), 0)
            self.assertIsNone(server.switch_block_reason())

            request_id = server.begin_request("default")
            self.assertIn("upstream request", server.switch_block_reason() or "")
            server.end_request(request_id)
        finally:
            server.end_websocket(tunnel_id)
            left.close()
            right.close()

    def test_pinned_session_activity_does_not_block_switching(self) -> None:
        server = ProvisionServer.__new__(ProvisionServer)
        server.active_requests = {}
        server.active_websockets = {}
        server.active_lock = threading.Lock()
        server.next_request_id = 0
        server.next_websocket_id = 0
        server.observed_sessions = {}
        server.pinned_sessions = {"/tmp/pinned": "default"}

        server.observe_session("/tmp/pinned", "default")
        request_id = server.begin_request("default", "/tmp/pinned")
        try:
            self.assertEqual(server.request_count(), 1)
            self.assertEqual(server.request_count(blocking_only=True), 0)
            self.assertIsNone(server.switch_block_reason())
            self.assertTrue(server.profile_has_active_sessions("default", pinned_only=True))
        finally:
            server.end_request(request_id)

        pinned_left, pinned_right = socket.socketpair()
        unpinned_left, unpinned_right = socket.socketpair()
        pinned_tunnel = server.begin_websocket("default", pinned_left, "/tmp/pinned")
        unpinned_tunnel = server.begin_websocket("other", unpinned_left, "/tmp/other")
        try:
            server.begin_websocket_work(pinned_tunnel, "turn-pinned")
            self.assertEqual(server.pending_websocket_work_count(), 1)
            self.assertEqual(server.pending_websocket_work_count(blocking_only=True), 0)
            self.assertIsNone(server.switch_block_reason())

            server.begin_websocket_work(unpinned_tunnel, "turn-other")
            self.assertEqual(server.pending_websocket_work_count(blocking_only=True), 1)
            self.assertIn("pending work", server.switch_block_reason() or "")
        finally:
            server.end_websocket(pinned_tunnel)
            server.end_websocket(unpinned_tunnel)
            pinned_left.close()
            pinned_right.close()
            unpinned_left.close()
            unpinned_right.close()

    def test_pinned_sessions_persist_without_persisting_observed_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            auth = {
                "auth_mode": "chatgpt",
                "tokens": {
                    "id_token": fake_jwt({"email": "user@example.test"}),
                    "access_token": fake_jwt({"exp": 9999999999}),
                    "refresh_token": "rt_test",
                },
            }
            source = root / "auth.json"
            source.write_text(json.dumps(auth), encoding="utf-8")
            paths = Paths(root / "home")
            store = Store(paths)
            store.import_auth_file("default", source)
            store.import_auth_file("work", source)

            first = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                first.observe_session("/tmp/provision-project", "default")
                first.pin_session("/tmp/provision-project", "work")
            finally:
                first.server_close()

            second = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                self.assertEqual(
                    second.pinned_profile_for_session("/tmp/provision-project"),
                    "work",
                )
                self.assertEqual(second.profile_for_session("/tmp/provision-project"), "work")
                self.assertEqual(second.session_snapshots(), [])

                second.observe_session("/tmp/provision-project", "work")
                snapshots = second.session_snapshots()
                self.assertEqual(snapshots[0]["pinned_profile"], "work")
            finally:
                second.server_close()

    def test_configured_daemon_port_reads_environment(self) -> None:
        old = os.environ.get("PROVISION_PORT")
        try:
            os.environ.pop("PROVISION_PORT", None)
            self.assertIsNone(configured_daemon_port())
            os.environ["PROVISION_PORT"] = "48123"
            self.assertEqual(configured_daemon_port(), 48123)
            os.environ["PROVISION_PORT"] = "bad"
            with self.assertRaises(RuntimeError):
                configured_daemon_port()
        finally:
            if old is None:
                os.environ.pop("PROVISION_PORT", None)
            else:
                os.environ["PROVISION_PORT"] = old

    def test_codex_client_id_is_discovered_from_auth_context(self) -> None:
        payload = (
            b"noise app_000000000000000000000000 " + (b"x" * 300) +
            b"client_id access_token refresh_token "
            b"app_ABCDEFGHIJKLMNOPQRSTUVWX Content-Type"
        )

        self.assertEqual(
            codex_client_id_from_bytes(payload),
            "app_ABCDEFGHIJKLMNOPQRSTUVWX",
        )


if __name__ == "__main__":
    unittest.main()
