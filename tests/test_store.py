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
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any

import provision.auth as auth_module
import provision.cli as cli_module
import provision.daemon as daemon_module
import provision.launcher as launcher_module
from provision.auth import codex_client_id_from_bytes, decode_jwt_claims, extract_metadata
from provision.cli import cmd_import_default, daemon_switch_profile
from provision.daemon import analytics_completed_turn_ids
from provision.daemon import analytics_turn_ids
from provision.daemon import backend_proxy_prefix
from provision.daemon import backend_upstream_path
from provision.daemon import BillingRequiredError
from provision.daemon import CHATGPT_ANALYTICS_EVENTS_PATH
from provision.daemon import error_requires_billing
from provision.daemon import label_usage_payload
from provision.daemon import logo_asset_bytes
from provision.daemon import Handler
from provision.daemon import model_pill_label
from provision.daemon import normalize_codex_model_catalog
from provision.daemon import ProvisionServer
from provision.daemon import decode_project_session_sentinel
from provision.daemon import daemon_url_host
from provision.daemon import daemon_bind_address
from provision.daemon import project_session_sentinel
from provision.daemon import redact_proxy_token
from provision.daemon import render_quota_html
from provision.daemon import request_body_session
from provision.daemon import rewrite_model_body
from provision.daemon import rewrite_model_websocket_message
from provision.daemon import rewrite_service_tier_body
from provision.daemon import rewrite_service_tier_websocket_message
from provision.daemon import should_forward_incoming_header
from provision.daemon import usage_payload_from_rate_limit_headers
from provision.daemon import usage_payload_from_websocket_message
from provision.daemon import usage_cache_summary
from provision.daemon import usage_payload_reset_datetimes
from provision.daemon import usage_refresh_due_at
from provision.daemon import USAGE_AUTO_REFRESH_BILLING_BACKOFF_SECONDS
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
from provision.daemon import websocket_message_token_usage
from provision.daemon import websocket_message_turn_id
from provision.daemon import websocket_terminal_event_keeps_work_pending
from provision.launcher import chatgpt_base_url_override
from provision.launcher import configured_daemon_host
from provision.launcher import configured_daemon_port
from provision.launcher import openai_base_url_override
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

    def test_daemon_url_host_rewrites_wildcard_bind_for_local_clients(self) -> None:
        self.assertEqual(daemon_url_host("0.0.0.0"), "127.0.0.1")
        self.assertEqual(daemon_bind_address("0.0.0.0", 4888), "0.0.0.0:4888")
        self.assertEqual(
            openai_base_url_override(12345, "0.0.0.0"),
            'openai_base_url="http://127.0.0.1:12345/v1"',
        )
        self.assertEqual(
            openai_base_url_override(12345, "192.168.1.50"),
            'openai_base_url="http://192.168.1.50:12345/v1"',
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

    def test_quota_html_renders_nonzero_credits_pill(self) -> None:
        markup = render_quota_html(
            {
                "payload": {
                    "credits": {
                        "has_credits": True,
                        "unlimited": False,
                        "balance": "$12.34",
                    },
                    "rate_limit": {
                        "primary_window": {"used_percent": 49, "limit_window_seconds": 18000},
                        "secondary_window": {"used_percent": 100, "limit_window_seconds": 604800},
                    },
                },
                "fetched_at": datetime(2026, 5, 22, 15, 36),
            }
        )

        self.assertIn("quota-credits-pill", markup)
        self.assertIn("Credits: $12.34", markup)

    def test_quota_html_hides_zero_credits_pill(self) -> None:
        markup = render_quota_html(
            {
                "payload": {
                    "credits": {
                        "has_credits": True,
                        "unlimited": False,
                        "balance": "$0.00",
                    },
                    "rate_limit": {
                        "primary_window": {"used_percent": 49, "limit_window_seconds": 18000},
                        "secondary_window": {"used_percent": 100, "limit_window_seconds": 604800},
                    },
                }
            }
        )

        self.assertNotIn("quota-credits-pill", markup)
        self.assertNotIn("Credits:", markup)

    def test_quota_html_renders_available_credits_without_balance(self) -> None:
        markup = render_quota_html(
            {
                "payload": {
                    "credits": {
                        "has_credits": True,
                        "unlimited": False,
                        "balance": None,
                    },
                    "rate_limit": {
                        "primary_window": {"used_percent": 49, "limit_window_seconds": 18000},
                        "secondary_window": {"used_percent": 100, "limit_window_seconds": 604800},
                    },
                }
            }
        )

        self.assertIn("quota-credits-pill", markup)
        self.assertIn("Credits: Available", markup)

    def test_quota_html_renders_unlimited_credits_symbol(self) -> None:
        markup = render_quota_html(
            {
                "payload": {
                    "credits": {
                        "has_credits": True,
                        "unlimited": True,
                        "balance": None,
                    }
                }
            }
        )

        self.assertIn("quota-credits-pill", markup)
        self.assertIn("Credits: \u221e", markup)

    def test_quota_html_renders_reset_credit_control_when_available(self) -> None:
        markup = render_quota_html(
            {
                "payload": {
                    "rate_limit_reset_credits": {"available_count": 2},
                    "rate_limit": {
                        "primary_window": {"used_percent": 100, "limit_window_seconds": 18000},
                    },
                }
            },
            profile="default",
            token="ui-token",
        )

        self.assertIn("consume_reset_credit", markup)
        self.assertIn("Reset credits: 2", markup)
        self.assertIn("/api/consume-reset-credit", markup)

    def test_quota_html_hides_reset_credit_control_without_available_count(self) -> None:
        markup = render_quota_html(
            {
                "payload": {
                    "rate_limit_reset_credits": {"available_count": 0},
                    "rate_limit": {
                        "primary_window": {"used_percent": 100, "limit_window_seconds": 18000},
                    },
                }
            },
            profile="default",
            token="ui-token",
        )

        self.assertNotIn("consume_reset_credit", markup)
        self.assertNotIn("Reset credits:", markup)

    def test_quota_html_uses_primary_reset_even_when_weekly_exhausted(self) -> None:
        markup = render_quota_html(
            {
                "payload": {
                    "rate_limit": {
                        "primary_window": {
                            "used_percent": 49,
                            "limit_window_seconds": 18000,
                            "reset_at": "2026-05-29T20:00:00+00:00",
                        },
                        "secondary_window": {
                            "used_percent": 100,
                            "limit_window_seconds": 604800,
                            "reset_at": "2026-05-31T04:00:00+00:00",
                        },
                    },
                }
            }
        )

        self.assertIn("5h (Resets", markup)
        self.assertNotIn("5h (Weekly", markup)

    def test_quota_html_translates_deactivated_workspace_state(self) -> None:
        markup = render_quota_html(
            {
                "payload": {
                    "detail": {
                        "code": "deactivated_workspace",
                    }
                }
            }
        )

        self.assertIn("Workspace deactivated", markup)
        self.assertIn("quota-state", markup)
        self.assertIn("This workspace is deactivated.", markup)
        self.assertNotIn("{&quot;detail&quot;", markup)
        self.assertNotIn("deactivated_workspace", markup)

    def test_quota_html_translates_stringified_deactivated_workspace_error(self) -> None:
        markup = render_quota_html(
            {
                "error": '{"detail":{"code":"deactivated_workspace"}}',
            }
        )

        self.assertIn("Workspace deactivated", markup)
        self.assertIn("This workspace is deactivated.", markup)
        self.assertNotIn("{&quot;detail&quot;", markup)
        self.assertNotIn("deactivated_workspace", markup)

    def test_usage_cache_summary_translates_deactivated_workspace_state(self) -> None:
        summary = usage_cache_summary(
            {
                "payload": {
                    "detail": {
                        "code": "deactivated_workspace",
                    }
                },
                "fetched_at": datetime(2026, 5, 22, 15, 36),
            }
        )

        self.assertEqual(summary, "Updated 15:36 on 22 May; Workspace deactivated")

    def test_usage_cache_summary_translates_stringified_deactivated_workspace_error(self) -> None:
        self.assertEqual(
            usage_cache_summary({"error": '{"detail":{"code":"deactivated_workspace"}}'}),
            "This workspace is deactivated.",
        )

    def test_usage_payload_label_sanitizes_detail_only_state(self) -> None:
        labeled = label_usage_payload(
            {
                "detail": {
                    "code": "deactivated_workspace",
                }
            },
            active_profile="work",
        )

        self.assertNotIn("detail", labeled)
        self.assertEqual(labeled["rate_limit"]["allowed"], False)
        self.assertEqual(labeled["rate_limit"]["reason"], "Workspace deactivated")
        self.assertEqual(
            labeled["additional_rate_limits"][0]["rate_limit"]["reason"],
            "Workspace deactivated",
        )

    def test_model_pill_label_omits_separator_slash(self) -> None:
        self.assertEqual(model_pill_label("gpt-5.5", "medium"), "gpt-5.5 medium")
        self.assertNotIn("/", model_pill_label("gpt-5.5", "medium"))

    def test_codex_model_catalog_normalizes_bundled_shape(self) -> None:
        catalog = normalize_codex_model_catalog(
            {
                "models": [
                    {
                        "slug": "gpt-6-test",
                        "display_name": "GPT-6 Test",
                        "default_reasoning_level": "minimal",
                        "supported_reasoning_levels": [
                            {"effort": "minimal", "description": "fastest"},
                            {"effort": "low", "description": "light"},
                        ],
                        "service_tiers": [
                            {"id": "priority", "name": "Fast", "description": "faster"},
                        ],
                        "additional_speed_tiers": ["fast"],
                        "availability_nux": {"message": "New model\n\nDetails"},
                    },
                    {
                        "slug": "hidden-review-model",
                        "visibility": "hide",
                    },
                ]
            }
        )

        self.assertEqual(len(catalog), 1)
        self.assertEqual(catalog[0]["id"], "gpt-6-test")
        self.assertEqual(catalog[0]["display"], "GPT-6 Test")
        self.assertEqual(catalog[0]["default_reasoning"], "minimal")
        self.assertEqual(catalog[0]["reasoning"], ["minimal", "low"])
        self.assertEqual(catalog[0]["note"], "New model")
        self.assertEqual(catalog[0]["service_tiers"][0]["id"], "priority")
        self.assertEqual(catalog[0]["additional_speed_tiers"], ["fast"])

    def test_codex_compatibility_payload_reads_version_and_catalog(self) -> None:
        original_run = daemon_module.subprocess.run

        class Result:
            def __init__(self, stdout: str) -> None:
                self.stdout = stdout
                self.stderr = ""

        def fake_run(argv: list[str], **_kwargs: Any) -> Result:
            if argv == ["codex", "--version"]:
                return Result("codex-cli 0.141.0\n")
            if argv == ["codex", "debug", "models", "--bundled"]:
                return Result(
                    json.dumps(
                        {
                            "models": [
                                {
                                    "slug": "gpt-test",
                                    "display_name": "gpt-test",
                                    "default_reasoning_level": "medium",
                                    "supported_reasoning_levels": [{"effort": "medium"}],
                                }
                            ]
                        }
                    )
                )
            if argv[:5] == ["codex", "app-server", "generate-json-schema", "--experimental", "--out"]:
                out_dir = Path(argv[5])
                (out_dir / "v2").mkdir(parents=True, exist_ok=True)
                (out_dir / "ClientRequest.json").write_text(
                    "account/rateLimits/read account/rateLimits/updated account/usage/read "
                    "account/rateLimitResetCredit/consume",
                    encoding="utf-8",
                )
                (out_dir / "v2" / "GetAccountRateLimitsResponse.json").write_text("{}", encoding="utf-8")
                (out_dir / "v2" / "GetAccountTokenUsageResponse.json").write_text("{}", encoding="utf-8")
                (out_dir / "v2" / "ConsumeAccountRateLimitResetCreditResponse.json").write_text("{}", encoding="utf-8")
                (out_dir / "v2" / "RateLimitResetCreditsSummary.json").write_text("{}", encoding="utf-8")
                return Result("")
            raise AssertionError(argv)

        try:
            daemon_module.subprocess.run = fake_run
            daemon_module.codex_cli_version.cache_clear()
            daemon_module.codex_model_catalog_probe.cache_clear()
            daemon_module.codex_app_server_schema_probe.cache_clear()
            payload = daemon_module.codex_compatibility_payload()
        finally:
            daemon_module.subprocess.run = original_run
            daemon_module.codex_cli_version.cache_clear()
            daemon_module.codex_model_catalog_probe.cache_clear()
            daemon_module.codex_app_server_schema_probe.cache_clear()

        self.assertEqual(payload["cli"]["version"], "0.141.0")
        self.assertEqual(payload["model_catalog"]["source"], "codex")
        self.assertEqual(payload["model_catalog"]["count"], 1)
        self.assertTrue(payload["app_server"]["available"])
        self.assertTrue(payload["app_server"]["methods"]["rate_limit_reset_credit_consume"])

    def test_codex_app_server_schema_probe_reads_usage_and_reset_credit_methods(self) -> None:
        original_run = daemon_module.subprocess.run

        class Result:
            stdout = ""
            stderr = ""

        def fake_run(argv: list[str], **_kwargs: Any) -> Result:
            self.assertEqual(argv[:5], ["codex", "app-server", "generate-json-schema", "--experimental", "--out"])
            out_dir = Path(argv[5])
            (out_dir / "v2").mkdir(parents=True, exist_ok=True)
            (out_dir / "ClientRequest.json").write_text(
                "\n".join(
                    [
                        "account/rateLimits/read",
                        "account/rateLimits/updated",
                        "account/usage/read",
                        "account/rateLimitResetCredit/consume",
                    ]
                ),
                encoding="utf-8",
            )
            for name in (
                "GetAccountRateLimitsResponse",
                "GetAccountTokenUsageResponse",
                "ConsumeAccountRateLimitResetCreditResponse",
                "RateLimitResetCreditsSummary",
            ):
                (out_dir / "v2" / f"{name}.json").write_text("{}", encoding="utf-8")
            return Result()

        try:
            daemon_module.subprocess.run = fake_run
            daemon_module.codex_app_server_schema_probe.cache_clear()
            payload = daemon_module.codex_app_server_schema_probe()
        finally:
            daemon_module.subprocess.run = original_run
            daemon_module.codex_app_server_schema_probe.cache_clear()

        self.assertTrue(payload["available"])
        self.assertTrue(payload["methods"]["account_rate_limits"])
        self.assertTrue(payload["methods"]["account_usage"])
        self.assertTrue(payload["methods"]["rate_limit_reset_credit_consume"])
        self.assertTrue(payload["response_types"]["reset_credit_summary"])

    def test_usage_payload_from_app_server_rate_limits_response_reads_reset_credits(self) -> None:
        payload = daemon_module.usage_payload_from_app_server_rate_limits_response(
            {
                "rateLimits": {
                    "limitId": "codex",
                    "limitName": "Codex",
                    "primary": {"usedPercent": 75.0, "windowDurationMins": 300, "resetsAt": "2026-06-20T12:00:00Z"},
                    "secondary": {"usedPercent": 20.0},
                    "credits": {"hasCredits": True, "unlimited": False, "balance": "$12.34"},
                },
                "rateLimitsByLimitId": {
                    "gpt-5.3-codex-spark": {
                        "limitName": "GPT-5.3-Codex-Spark",
                        "primary": {"usedPercent": 40.0},
                    }
                },
                "rateLimitResetCredits": {"availableCount": "2"},
            }
        )

        self.assertIsNotNone(payload)
        assert payload is not None
        self.assertEqual(payload["rate_limit"]["primary_window"]["used_percent"], 75.0)
        self.assertEqual(payload["credits"]["balance"], "$12.34")
        self.assertEqual(payload["additional_rate_limits"][0]["metered_feature"], "gpt_5.3_codex_spark")
        self.assertEqual(payload["rate_limit_reset_credits"]["available_count"], 2)

    def test_codex_app_server_client_reads_account_rate_limits_and_usage(self) -> None:
        original_popen = daemon_module.subprocess.Popen

        class FakeProcess:
            def __init__(self) -> None:
                self.stdin = StringIO()
                self.stdout = StringIO(
                    "\n".join(
                        [
                            json.dumps({"id": 1, "result": {"serverInfo": {"name": "codex"}}}),
                            json.dumps({"id": 2, "result": {"rateLimits": {"limitId": "codex"}}}),
                            json.dumps({"id": 3, "result": {"summary": {"lifetimeTokens": 123}, "dailyUsageBuckets": []}}),
                            "",
                        ]
                    )
                )
                self.terminated = False

            def poll(self) -> None:
                return None

            def terminate(self) -> None:
                self.terminated = True

            def wait(self, timeout: float | None = None) -> int:
                return 0

            def kill(self) -> None:
                self.terminated = True

        fake = FakeProcess()

        def fake_popen(argv: list[str], **_kwargs: Any) -> FakeProcess:
            self.assertEqual(argv, ["codex", "app-server", "--stdio"])
            return fake

        try:
            daemon_module.subprocess.Popen = fake_popen
            with daemon_module.CodexAppServerClient(timeout=1) as client:
                rate_limits = client.read_account_rate_limits()
                usage = client.read_account_usage()
        finally:
            daemon_module.subprocess.Popen = original_popen

        sent = fake.stdin.getvalue()
        self.assertIn('"method":"initialize"', sent)
        self.assertIn('"method":"initialized"', sent)
        self.assertIn('"method":"account/rateLimits/read"', sent)
        self.assertIn('"method":"account/usage/read"', sent)
        self.assertEqual(rate_limits["rateLimits"]["limitId"], "codex")
        self.assertEqual(usage["summary"]["lifetimeTokens"], 123)

    def test_app_server_rate_limit_refresh_failure_logs_and_backs_off(self) -> None:
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
            Store(paths).import_auth_file("default", source)
            server = ProvisionServer(("127.0.0.1", 0), paths)
            original_read = server.read_app_server_rate_limit_payload_for_profile
            try:
                def fail_read(_profile: str) -> None:
                    raise RuntimeError("boom")

                server.read_app_server_rate_limit_payload_for_profile = fail_read  # type: ignore[method-assign]
                output = StringIO()
                with redirect_stderr(output):
                    result = server.refresh_app_server_rate_limit_payload("default")
            finally:
                server.read_app_server_rate_limit_payload_for_profile = original_read  # type: ignore[method-assign]
                server.server_close()

            self.assertIsNone(result)
            self.assertIn("app-server rate-limit read for profile default failed: boom", output.getvalue())
            entry = server.app_server_rate_limit_cache["default"]
            self.assertFalse(entry["in_flight"])
            self.assertIn("failed_monotonic", entry)
            self.assertFalse(server.schedule_app_server_rate_limit_refresh("default"))

    def test_app_server_rate_limit_refresh_updates_cached_usage(self) -> None:
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
            Store(paths).import_auth_file("default", source)
            server = ProvisionServer(("127.0.0.1", 0), paths)
            original_read = server.read_app_server_rate_limit_payload_for_profile
            payload = {
                "rate_limit": {"primary_window": {"used_percent": 25.0}},
                "rate_limit_reset_credits": {"available_count": 1},
            }
            try:
                server.read_app_server_rate_limit_payload_for_profile = lambda _profile: payload  # type: ignore[method-assign]

                result = server.refresh_app_server_rate_limit_payload("default")
            finally:
                server.read_app_server_rate_limit_payload_for_profile = original_read  # type: ignore[method-assign]
                server.server_close()

            self.assertEqual(result, payload)
            cached = server.cached_app_server_rate_limit_payload("default")
            self.assertEqual(cached, payload)
            snapshot = server.usage_cache_snapshot("default")
            assert snapshot is not None
            self.assertEqual(snapshot["payload"]["rate_limit_reset_credits"]["available_count"], 1)
            self.assertFalse(server.schedule_app_server_rate_limit_refresh("default"))

    def test_fetch_usage_merges_recent_app_server_rate_limit_cache(self) -> None:
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
            Store(paths).import_auth_file("default", source)
            server = ProvisionServer(("127.0.0.1", 0), paths)
            server.app_server_rate_limit_cache["default"] = {
                "payload": {
                    "credits": {"has_credits": True, "balance": "$1.00"},
                    "rate_limit_reset_credits": {"available_count": 2},
                },
                "fetched_monotonic": time.monotonic(),
            }

            class FakeResponse:
                def __enter__(self) -> FakeResponse:
                    return self

                def __exit__(self, *_args: Any) -> None:
                    return None

                def read(self) -> bytes:
                    return json.dumps(
                        {
                            "rate_limit": {
                                "primary_window": {"used_percent": 50.0},
                            }
                        }
                    ).encode("utf-8")

            original_ensure = daemon_module.ensure_fresh_chatgpt_auth
            original_urlopen = daemon_module.urllib.request.urlopen
            try:
                daemon_module.ensure_fresh_chatgpt_auth = lambda _auth_path: auth  # type: ignore[assignment]
                daemon_module.urllib.request.urlopen = lambda _request, timeout=10: FakeResponse()

                payload = server.fetch_usage_payload_uncached("default")
            finally:
                daemon_module.ensure_fresh_chatgpt_auth = original_ensure  # type: ignore[assignment]
                daemon_module.urllib.request.urlopen = original_urlopen
                server.server_close()

            assert payload is not None
            self.assertEqual(payload["rate_limit"]["primary_window"]["used_percent"], 50.0)
            self.assertEqual(payload["credits"]["balance"], "$1.00")
            self.assertEqual(payload["rate_limit_reset_credits"]["available_count"], 2)

    def test_usage_auto_refresh_logs_unexpected_failure_without_crashing(self) -> None:
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
            Store(paths).import_auth_file("default", source)
            server = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                server.usage_auto_refresh_due_profiles = lambda _now=None: ["default"]  # type: ignore[method-assign]

                def fail_refresh(_profile: str, *, force: bool = False) -> None:
                    raise RuntimeError("surprise")

                server.usage_payload_for_profile = fail_refresh  # type: ignore[method-assign]
                output = StringIO()
                with redirect_stderr(output):
                    server.refresh_due_usage_profiles()
            finally:
                server.server_close()

            self.assertIn("usage auto-refresh for profile default failed: surprise", output.getvalue())

    def test_server_log_message_redacts_proxy_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = Paths(Path(temp) / "home")
            server = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                output = StringIO()
                with redirect_stderr(output):
                    server.log_message(
                        "GET /backend-api/provision-%s/wham/usage",
                        server.proxy_token,
                    )
            finally:
                server.server_close()

            self.assertIn("provision-<redacted>", output.getvalue())
            self.assertNotIn(server.proxy_token, output.getvalue())

    def test_cancel_profile_login_terminates_running_process(self) -> None:
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
            Store(paths).import_auth_file("default", source)

            class FakeLoginProcess:
                def __init__(self) -> None:
                    self.terminated = False

                def poll(self) -> None:
                    return None

                def terminate(self) -> None:
                    self.terminated = True

                def wait(self, timeout: float | None = None) -> int:
                    return -15

                def kill(self) -> None:
                    self.terminated = True

            fake = FakeLoginProcess()
            server = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                server.login_jobs["default"] = {
                    "profile": "default",
                    "status": "running",
                    "mode": "browser",
                }
                server.login_processes["default"] = fake  # type: ignore[assignment]

                server.cancel_profile_login("default")

                job = server.login_jobs["default"]
                self.assertEqual(job["status"], "canceling")
                self.assertTrue(job["cancel_requested"])
                self.assertTrue(fake.terminated)
            finally:
                server.server_close()

    def test_login_status_html_warns_and_exposes_cancel_for_browser_login(self) -> None:
        markup = daemon_module.render_login_status_html(
            {
                "profile": "default",
                "status": "running",
                "mode": "browser",
                "auth_url": "https://example.test/login",
            },
            "default",
            "ui-token",
        )

        self.assertIn("Cancel Login", markup)
        self.assertIn("cancel_login", markup)
        self.assertIn("Device Auth for VM, SSH tunnel, or remote dashboards", markup)

    def test_login_menu_warns_and_exposes_cancel_while_running(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = Paths(Path(temp) / "home")
            server = ProvisionServer(("127.0.0.1", 0), paths)
            handler = Handler.__new__(Handler)
            handler.server = server
            try:
                markup = handler.render_login_pill(
                    {
                        "name": "default",
                        "login_required": {"required": True},
                        "login_status": {"status": "running", "mode": "browser"},
                    }
                )
            finally:
                server.server_close()

        self.assertIn("Browser Login", markup)
        self.assertIn("Device Auth", markup)
        self.assertIn("Cancel Login", markup)
        self.assertIn("Device Auth for VM, SSH tunnel, or remote dashboards", markup)

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

    def test_service_tier_rewrite_sets_priority_for_fast_mode(self) -> None:
        rewritten, service_tier, changed = rewrite_service_tier_body(
            b'{"model":"gpt-5.3-codex"}',
            fast_enabled=True,
        )

        self.assertTrue(changed)
        self.assertEqual(service_tier, "priority")
        assert rewritten is not None
        self.assertEqual(json.loads(rewritten.decode("utf-8"))["service_tier"], "priority")

    def test_service_tier_rewrite_removes_fast_when_disabled(self) -> None:
        rewritten, service_tier, changed = rewrite_service_tier_body(
            b'{"model":"gpt-5.3-codex","service_tier":"priority"}',
            fast_enabled=False,
        )

        self.assertTrue(changed)
        self.assertIsNone(service_tier)
        assert rewritten is not None
        self.assertNotIn("service_tier", json.loads(rewritten.decode("utf-8")))

    def test_websocket_service_tier_rewrite_only_touches_response_create(self) -> None:
        rewritten, service_tier, changed = rewrite_service_tier_websocket_message(
            0x1,
            b'{"type":"session.update","service_tier":"default"}',
            fast_enabled=True,
        )

        self.assertFalse(changed)
        self.assertIsNone(service_tier)
        self.assertEqual(rewritten, b'{"type":"session.update","service_tier":"default"}')

        rewritten, service_tier, changed = rewrite_service_tier_websocket_message(
            0x1,
            b'{"type":"response.create","response":{}}',
            fast_enabled=True,
        )

        self.assertTrue(changed)
        self.assertEqual(service_tier, "priority")
        self.assertEqual(json.loads(rewritten.decode("utf-8"))["service_tier"], "priority")

    def test_model_rewrite_sets_model_and_reasoning(self) -> None:
        rewritten, model, reasoning, changed = rewrite_model_body(
            b'{"input":"hello","model":"gpt-5.4"}',
            model="gpt-5.5",
            reasoning_effort="high",
        )

        self.assertTrue(changed)
        self.assertEqual(model, "gpt-5.5")
        self.assertEqual(reasoning, "high")
        assert rewritten is not None
        payload = json.loads(rewritten.decode("utf-8"))
        self.assertEqual(payload["model"], "gpt-5.5")
        self.assertEqual(payload["reasoning"]["effort"], "high")

    def test_websocket_model_rewrite_touches_response_payload(self) -> None:
        rewritten, model, reasoning, changed = rewrite_model_websocket_message(
            0x1,
            b'{"type":"response.create","response":{"model":"gpt-5.4"}}',
            model="gpt-5.5",
            reasoning_effort="xhigh",
        )

        self.assertTrue(changed)
        self.assertEqual(model, "gpt-5.5")
        self.assertEqual(reasoning, "xhigh")
        payload = json.loads(rewritten.decode("utf-8"))
        self.assertEqual(payload["response"]["model"], "gpt-5.5")
        self.assertEqual(payload["response"]["reasoning"]["effort"], "xhigh")

    def test_websocket_token_usage_normalization(self) -> None:
        usage = websocket_message_token_usage(
            0x1,
            json.dumps(
                {
                    "type": "response.completed",
                    "response": {
                        "usage": {
                            "input_tokens": 10,
                            "output_tokens": 7,
                            "input_tokens_details": {"cached_tokens": 4},
                            "output_tokens_details": {"reasoning_tokens": 3},
                        }
                    },
                }
            ).encode("utf-8"),
        )

        self.assertEqual(
            usage,
            {
                "input_tokens": 10,
                "cached_input_tokens": 4,
                "output_tokens": 7,
                "reasoning_output_tokens": 3,
                "total_tokens": 17,
            },
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

    def test_profile_fast_mode_persists(self) -> None:
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
            Store(paths).import_auth_file("default", source)

            server = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                server.set_profile_fast_mode("default", True)
                self.assertTrue(server.profile_fast_mode("default"))
            finally:
                server.server_close()

            reloaded = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                self.assertTrue(reloaded.profile_fast_mode("default"))
            finally:
                reloaded.server_close()

    def test_compact_proxy_applies_model_override_without_crashing(self) -> None:
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
            Store(paths).import_auth_file("default", source)
            server = ProvisionServer(("127.0.0.1", 0), paths)
            captured: dict[str, object] = {}
            original = Handler._proxy_to_upstream_once

            def fake_proxy(
                handler: Handler,
                method: str,
                parsed: urllib.parse.ParseResult,
                *,
                body: bytes | None,
                retry_on_401: bool,
                route: str,
                profile: str,
            ) -> tuple[int, int]:
                captured["body"] = body
                captured["profile"] = profile
                handler.send_json({"ok": True})
                return 200, len(b'{\n  "ok": true\n}')

            Handler._proxy_to_upstream_once = fake_proxy
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                server.set_profile_model(
                    "default",
                    model="gpt-5.4-mini",
                    reasoning_effort="high",
                )
                body = json.dumps({"input": "compact me"}).encode("utf-8")
                conn = http.client.HTTPConnection(
                    "127.0.0.1",
                    server.server_address[1],
                    timeout=2,
                )
                conn.request(
                    "POST",
                    "/v1/responses/compact",
                    body=body,
                    headers={
                        "authorization": f"Bearer {server.proxy_token}",
                        "content-type": "application/json",
                    },
                )
                response = conn.getresponse()
                response.read()
                conn.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                Handler._proxy_to_upstream_once = original

            self.assertEqual(response.status, 200)
            self.assertEqual(captured["profile"], "default")
            rewritten = json.loads(captured["body"].decode("utf-8"))
            self.assertEqual(rewritten["model"], "gpt-5.4-mini")
            self.assertEqual(rewritten["reasoning"]["effort"], "high")

    def test_stats_summary_aggregates_usage_events(self) -> None:
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
            Store(paths).import_auth_file("default", source)

            server = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                server.append_stats_event(
                    {
                        "type": "websocket_tunnel",
                        "profile": "default",
                        "bytes_up": 100,
                        "bytes_down": 250,
                    }
                )
                server.append_stats_event(
                    {
                        "type": "token_usage",
                        "profile": "default",
                        "fast": True,
                        "usage": {
                            "input_tokens": 10,
                            "cached_input_tokens": 3,
                            "output_tokens": 5,
                            "reasoning_output_tokens": 2,
                            "total_tokens": 15,
                        },
                    }
                )
                server.append_stats_event(
                    {
                        "type": "quota_update",
                        "profile": "default",
                        "quota": {
                            "Codex": {
                                "primary_remaining_percent": 90,
                                "primary_delta_percent": -5,
                            }
                        },
                    }
                )

                summary = server.stats_summary()
            finally:
                server.server_close()

            default = summary["profiles"][0]
            self.assertEqual(default["tunnels"], 1)
            self.assertEqual(default["bytes_up"], 100)
            self.assertEqual(default["bytes_down"], 250)
            self.assertEqual(default["total_tokens"], 15)
            self.assertEqual(default["fast_tokens"], 15)
            self.assertEqual(default["quota_updates"], 1)
            self.assertEqual(default["last_quota"]["Codex"]["primary_delta_percent"], -5)

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

    def test_usage_payload_can_include_model_in_provision_label(self) -> None:
        labeled = label_usage_payload(
            {"rate_limit": {"primary_window": {"used_percent": 15}}},
            active_profile="work",
            updated_at=datetime(2026, 5, 28, 15, 36),
            model_label="GPT-5.5 / High",
        )

        self.assertEqual(
            labeled["additional_rate_limits"][-1]["limit_name"],
            "Provision (work - GPT-5.5 / High - updated 15:36 on 28 May)",
        )

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

    def test_usage_payload_from_rate_limit_headers_renders_unlimited_credits(self) -> None:
        payload = usage_payload_from_rate_limit_headers(
            {
                "x-codex-credits-has-credits": "true",
                "x-codex-credits-unlimited": "true",
            }
        )

        self.assertIsInstance(payload, dict)
        assert payload is not None
        html = render_quota_html({"payload": payload})
        self.assertIn("Weekly (unlimited)", html)
        self.assertIn("5h (unlimited)", html)
        self.assertIn("\u221e?", html)
        self.assertIn("unlimited or unmetered quota", usage_cache_summary({"payload": payload}))

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

    def test_usage_payload_from_websocket_rate_limit_event_accepts_credits_only(self) -> None:
        payload = usage_payload_from_websocket_message(
            0x1,
            json.dumps(
                {
                    "type": "codex.rate_limits",
                    "rate_limits": {},
                    "credits": {
                        "has_credits": True,
                        "unlimited": True,
                    },
                }
            ).encode("utf-8"),
        )

        self.assertIsInstance(payload, dict)
        assert payload is not None
        self.assertEqual(payload["credits"]["unlimited"], True)
        self.assertEqual(usage_payload_reset_datetimes(payload), [])

    def test_usage_payload_from_websocket_token_count_reads_nested_credits(self) -> None:
        payload = usage_payload_from_websocket_message(
            0x1,
            json.dumps(
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "token_count",
                        "rate_limits": {
                            "limit_id": "codex",
                            "primary": {
                                "used_percent": 49,
                                "window_minutes": 300,
                                "resets_at": 1790000000,
                            },
                            "secondary": {
                                "used_percent": 100,
                                "window_minutes": 10080,
                                "resets_at": 1790100000,
                            },
                            "credits": {
                                "has_credits": True,
                                "unlimited": False,
                                "balance": "$12.34",
                            },
                            "plan_type": "team",
                            "rate_limit_reached_type": None,
                        },
                    },
                }
            ).encode("utf-8"),
        )

        self.assertIsInstance(payload, dict)
        assert payload is not None
        self.assertEqual(payload["credits"]["balance"], "$12.34")
        self.assertEqual(payload["rate_limit"]["credits"]["has_credits"], True)
        self.assertEqual(payload["rate_limit"]["primary_window"]["reset_at"], 1790000000)
        self.assertIn("Credits: $12.34", render_quota_html({"payload": payload}))

    def test_render_quota_html_marks_allowed_without_percentages_as_unknown(self) -> None:
        html = render_quota_html({"payload": {"rate_limit": {"allowed": True}}})

        self.assertIn("Weekly (unknown)", html)
        self.assertIn("5h (unknown)", html)
        self.assertIn("\u221e?", html)

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

    def test_billing_required_errors_are_classified(self) -> None:
        self.assertTrue(error_requires_billing("HTTP Error 402: Payment Required"))
        self.assertTrue(error_requires_billing(BillingRequiredError("subscription inactive")))
        self.assertFalse(error_requires_billing("HTTP Error 500: Internal Server Error"))

    def test_quota_html_renders_billing_required_error(self) -> None:
        markup = render_quota_html({"error": "HTTP Error 402: Payment Required"})

        self.assertIn("Billing required", markup)
        self.assertIn("paused automatic quota refreshes", markup)

    def test_usage_cache_summary_marks_stale_billing_required_refresh(self) -> None:
        summary = usage_cache_summary(
            {
                "payload": {
                    "rate_limit": {
                        "primary_window": {
                            "used_percent": 25,
                            "limit_window_seconds": 18000,
                        }
                    }
                },
                "fetched_at": datetime(2026, 5, 22, 15, 36),
                "error": "HTTP Error 402: Payment Required",
            }
        )

        self.assertIn("Updated 15:36 on 22 May", summary)
        self.assertIn("billing required on last refresh", summary)

    def test_usage_refresh_due_at_backs_off_billing_required_errors(self) -> None:
        now = datetime(2026, 5, 25, 12, 0, tzinfo=timezone.utc)
        failed_at = now - timedelta(hours=1)
        entry = {
            "error": "HTTP Error 402: Payment Required",
            "error_at": failed_at,
        }

        self.assertEqual(
            usage_refresh_due_at(entry, now),
            failed_at + timedelta(seconds=USAGE_AUTO_REFRESH_BILLING_BACKOFF_SECONDS),
        )
        self.assertGreater(usage_refresh_due_at(entry, now), now)

    def test_chatgpt_refresh_records_failure_and_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            auth_path = Path(temp) / "auth.json"
            auth = {
                "auth_mode": "chatgpt",
                "tokens": {
                    "id_token": fake_jwt({"email": "user@example.test"}),
                    "access_token": fake_jwt({"exp": 1}),
                    "refresh_token": "rt_test",
                },
            }
            auth_path.write_text(json.dumps(auth), encoding="utf-8")
            original_client_id = auth_module.codex_client_id
            original_urlopen = auth_module.urllib.request.urlopen

            def fail_urlopen(_request: Any, timeout: int = 30) -> Any:
                raise auth_module.urllib.error.HTTPError(
                    "https://auth.openai.com/oauth/token",
                    400,
                    "Bad Request",
                    {},
                    BytesIO(
                        b'{"error":{"code":"refresh_token_reused",'
                        b'"message":"Your refresh token has already been used"}}'
                    ),
                )

            class FakeResponse:
                def __enter__(self) -> FakeResponse:
                    return self

                def __exit__(self, *_args: Any) -> None:
                    return None

                def read(self) -> bytes:
                    return json.dumps(
                        {
                            "id_token": fake_jwt({"email": "user@example.test"}),
                            "access_token": fake_jwt({"exp": 9999999999}),
                            "refresh_token": "rt_new",
                        }
                    ).encode("utf-8")

            try:
                auth_module.codex_client_id = lambda: "app_ABCDEFGHIJKLMNOPQRSTUVWX"  # type: ignore[assignment]
                auth_module.urllib.request.urlopen = fail_urlopen
                with self.assertRaises(auth_module.AuthError):
                    auth_module.refresh_chatgpt_tokens(auth_path, dict(auth))
                failed = json.loads(auth_path.read_text(encoding="utf-8"))
                self.assertIn("last_refresh_failed_at", failed)
                self.assertIn("refresh_token_reused", failed["last_refresh_error"])

                auth_module.urllib.request.urlopen = lambda _request, timeout=30: FakeResponse()
                refreshed = auth_module.refresh_chatgpt_tokens(auth_path, failed)
            finally:
                auth_module.codex_client_id = original_client_id  # type: ignore[assignment]
                auth_module.urllib.request.urlopen = original_urlopen

            self.assertEqual(refreshed["tokens"]["refresh_token"], "rt_new")
            self.assertIn("last_refresh", refreshed)
            self.assertNotIn("last_refresh_error", refreshed)
            self.assertNotIn("last_refresh_failed_at", refreshed)

    def test_login_required_state_uses_actionable_stale_token_message(self) -> None:
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
            Store(paths).import_auth_file("default", source)

            server = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                server.mark_profile_login_required(
                    "default",
                    'HTTP 400 {"code":"refresh_token_reused","message":"Your refresh token has already been used"}',
                )
                state = server.profile_login_required("default")
                self.assertTrue(state["required"])
                self.assertIn("refresh token is stale", state["error"])
                self.assertTrue(state["error_at"])
                health = server.profile_auth_health("default")
                self.assertEqual(health["status"], "login_required")
                self.assertIn("refresh token is stale", health["message"])
                markup = daemon_module.render_auth_health_html(health)
                self.assertIn("Login required", markup)
            finally:
                server.server_close()

            reloaded = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                state = reloaded.profile_login_required("default")
                self.assertTrue(state["required"])
                self.assertTrue(state["error_at"])
            finally:
                reloaded.server_close()

    def test_profile_auth_health_reports_refresh_failure_from_auth_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            failed_at = "2026-06-20T12:00:00Z"
            auth = {
                "auth_mode": "chatgpt",
                "tokens": {
                    "id_token": fake_jwt({"email": "user@example.test"}),
                    "access_token": fake_jwt({"exp": 9999999999}),
                    "refresh_token": "rt_test",
                },
                "last_refresh_failed_at": failed_at,
                "last_refresh_error": "token refresh failed with HTTP 400: refresh_token_reused",
            }
            source = root / "auth.json"
            source.write_text(json.dumps(auth), encoding="utf-8")
            paths = Paths(root / "home")
            Store(paths).import_auth_file("default", source)

            server = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                health = server.profile_auth_health("default")
            finally:
                server.server_close()

            self.assertEqual(health["status"], "refresh_failed")
            self.assertEqual(health["last_refresh_failed_at"], failed_at)
            self.assertIn("refresh token is stale", health["message"])

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

    def test_billing_required_profile_state_persists_and_blocks_switching(self) -> None:
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
            store.import_auth_file("lapsed", source)

            server = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                server.mark_profile_billing_required("lapsed", "HTTP Error 402: Payment Required")
                self.assertEqual(server.profile_switch_unavailable_reason("lapsed"), "Billing required")
            finally:
                server.server_close()

            reloaded = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                billing = reloaded.profile_billing_required("lapsed")
                self.assertTrue(billing["required"])
                self.assertIn("Payment Required", billing["error"])
            finally:
                reloaded.server_close()

    def test_billing_required_profile_auto_refresh_is_paused(self) -> None:
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
            store.import_auth_file("lapsed", source)

            server = ProvisionServer(("127.0.0.1", 0), paths)
            now = datetime(2026, 5, 25, 12, 0, tzinfo=timezone.utc)
            try:
                with server.profile_settings_lock:
                    server.profile_settings["lapsed"] = {
                        "billing_required": True,
                        "billing_error": "HTTP Error 402: Payment Required",
                        "billing_error_at": (now - timedelta(hours=1)).isoformat(),
                    }
                self.assertEqual(server.usage_auto_refresh_due_profiles(now), [])

                with server.profile_settings_lock:
                    server.profile_settings["lapsed"]["billing_error_at"] = (
                        now - timedelta(seconds=USAGE_AUTO_REFRESH_BILLING_BACKOFF_SECONDS + 60)
                    ).isoformat()
                self.assertEqual(server.usage_auto_refresh_due_profiles(now), ["lapsed"])
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

    def test_configured_daemon_host_reads_environment(self) -> None:
        old = os.environ.get("PROVISION_HOST")
        try:
            os.environ.pop("PROVISION_HOST", None)
            self.assertIsNone(configured_daemon_host())
            os.environ["PROVISION_HOST"] = " 0.0.0.0 "
            self.assertEqual(configured_daemon_host(), "0.0.0.0")
        finally:
            if old is None:
                os.environ.pop("PROVISION_HOST", None)
            else:
                os.environ["PROVISION_HOST"] = old

    def test_launcher_passthrough_includes_new_codex_admin_commands(self) -> None:
        self.assertIn("archive", launcher_module.CODEX_PASSTHROUGH_COMMANDS)
        self.assertIn("delete", launcher_module.CODEX_PASSTHROUGH_COMMANDS)
        self.assertIn("unarchive", launcher_module.CODEX_PASSTHROUGH_COMMANDS)
        self.assertIn("exec-server", launcher_module.CODEX_PASSTHROUGH_COMMANDS)

    def test_ensure_daemon_passes_wildcard_host_without_port(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = Paths(Path(temp) / "home")
            captured: dict[str, Any] = {}
            original_running = launcher_module.daemon_running
            original_popen = launcher_module.subprocess.Popen
            original_wait = launcher_module.wait_until_running

            def fake_popen(argv: list[str], **kwargs: Any) -> object:
                captured["argv"] = argv
                captured["kwargs"] = kwargs
                return object()

            try:
                launcher_module.daemon_running = lambda _paths: None
                launcher_module.subprocess.Popen = fake_popen
                launcher_module.wait_until_running = lambda _paths: {
                    "pid": 123,
                    "host": "0.0.0.0",
                    "port": 4888,
                    "provision_protocol": daemon_module.PROTOCOL_VERSION,
                }

                status = launcher_module.ensure_daemon(paths, None, "0.0.0.0")
            finally:
                launcher_module.daemon_running = original_running
                launcher_module.subprocess.Popen = original_popen
                launcher_module.wait_until_running = original_wait

            self.assertEqual(status["host"], "0.0.0.0")
            argv = captured["argv"]
            self.assertIn("--host", argv)
            self.assertIn("0.0.0.0", argv)
            self.assertNotIn("--port", argv)

    def test_ensure_daemon_passes_wildcard_host_with_port(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = Paths(Path(temp) / "home")
            captured: dict[str, Any] = {}
            original_running = launcher_module.daemon_running
            original_popen = launcher_module.subprocess.Popen
            original_wait = launcher_module.wait_until_running

            def fake_popen(argv: list[str], **kwargs: Any) -> object:
                captured["argv"] = argv
                captured["kwargs"] = kwargs
                return object()

            try:
                launcher_module.daemon_running = lambda _paths: None
                launcher_module.subprocess.Popen = fake_popen
                launcher_module.wait_until_running = lambda _paths: {
                    "pid": 123,
                    "host": "0.0.0.0",
                    "port": 4999,
                    "provision_protocol": daemon_module.PROTOCOL_VERSION,
                }

                status = launcher_module.ensure_daemon(paths, 4999, "0.0.0.0")
            finally:
                launcher_module.daemon_running = original_running
                launcher_module.subprocess.Popen = original_popen
                launcher_module.wait_until_running = original_wait

            self.assertEqual(status["host"], "0.0.0.0")
            argv = captured["argv"]
            self.assertIn("--host", argv)
            self.assertIn("0.0.0.0", argv)
            self.assertIn("--port", argv)
            self.assertIn("4999", argv)

    def test_cmd_start_reports_wildcard_bind_separately_from_local_url(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = Paths(Path(temp) / "home")
            original = cli_module.ensure_daemon
            try:
                cli_module.ensure_daemon = lambda _paths, _port, _host: {
                    "pid": 123,
                    "host": "0.0.0.0",
                    "port": 4888,
                }
                output = StringIO()
                with redirect_stdout(output):
                    cli_module.cmd_start(paths, host="0.0.0.0")
            finally:
                cli_module.ensure_daemon = original

            self.assertIn("bound to 0.0.0.0:4888", output.getvalue())
            self.assertIn("local UI http://127.0.0.1:4888/ui", output.getvalue())

    def test_cmd_doctor_reports_codex_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = Paths(root / "home")
            store = Store(paths)
            source = root / "auth.json"
            source.write_text(json.dumps({"OPENAI_API_KEY": "sk-test"}), encoding="utf-8")
            store.import_auth_file("default", source)
            original_compat = cli_module.codex_compatibility_payload
            original_running = cli_module.daemon_running
            try:
                cli_module.codex_compatibility_payload = lambda: {
                    "cli": {"available": True, "version": "0.141.0"},
                    "model_catalog": {"source": "codex", "count": 5, "available": True},
                }
                cli_module.daemon_running = lambda _paths: {"pid": 123, "host": "127.0.0.1", "port": 4888}
                output = StringIO()
                with redirect_stdout(output):
                    result = cli_module.cmd_doctor(paths, store)
            finally:
                cli_module.codex_compatibility_payload = original_compat
                cli_module.daemon_running = original_running

            self.assertEqual(result, 0)
            self.assertIn("codex on PATH (0.141.0)", output.getvalue())
            self.assertIn("Codex model catalog readable (5 models from codex)", output.getvalue())

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

    def test_codex_client_id_is_discovered_from_login_flow_context(self) -> None:
        payload = (
            b"Logged in using ChatGPT\n"
            b"Logged in using access token\n"
            b"app_EMoamEEZ73f0CkXaXp7hrann"
            b"starting browser login flow"
            b"starting device code login flow"
        )

        self.assertEqual(
            codex_client_id_from_bytes(payload),
            "app_EMoamEEZ73f0CkXaXp7hrann",
        )

    def test_codex_client_id_ignores_plugin_and_connector_ids(self) -> None:
        payload = (
            b"RemotePluginDirectoryItem materialized_app_idsRemotePluginDirectory "
            b"app_idsreasonAppTemplateSummary "
            b"guardian_subagentasdk_app_6938a94a61d881918ef32cb999ff937c"
            b" connector_2b0a9009c9c64bf9933a3dae3f2b1254 marketplace plugin_id"
        )

        self.assertIsNone(codex_client_id_from_bytes(payload))


if __name__ == "__main__":
    unittest.main()
