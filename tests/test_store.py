from __future__ import annotations

import http.client
import json
import os
import tempfile
import threading
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from datetime import datetime
from io import StringIO
from pathlib import Path

from provision.auth import codex_client_id_from_bytes, decode_jwt_claims, extract_metadata
from provision.cli import cmd_import_default
from provision.daemon import backend_proxy_prefix
from provision.daemon import backend_upstream_path
from provision.daemon import label_usage_payload
from provision.daemon import logo_asset_bytes
from provision.daemon import ProvisionServer
from provision.daemon import redact_proxy_token
from provision.daemon import render_quota_html
from provision.daemon import should_forward_incoming_header
from provision.daemon import usage_cache_summary
from provision.daemon import websocket_accept_key
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
                        },
                        "secondary_window": {
                            "remaining": 12,
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
        self.assertIn("75% left", markup)
        self.assertIn("Spark", markup)
        self.assertIn("gpt-5.3-codex-spark", markup)
        self.assertIn("low", markup)

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
        self.assertIn("5h 75% left", summary)
        self.assertIn("weekly 12 remaining", summary)
        self.assertIn("1 extra bucket", summary)

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
