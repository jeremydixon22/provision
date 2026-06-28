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
from provision.daemon import bridge_codex_history_into_app_home
from provision.daemon import CHATGPT_ANALYTICS_EVENTS_PATH
from provision.daemon import codex_resume_candidates_for_cwd
from provision.daemon import DEFAULT_UPSTREAM_USER_AGENT
from provision.daemon import error_requires_billing
from provision.daemon import ensure_default_upstream_user_agent
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
from provision.daemon import render_compact_quota_html
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
from provision.daemon import websocket_message_thread_id
from provision.daemon import websocket_message_token_usage
from provision.daemon import websocket_message_tool_entries
from provision.daemon import websocket_message_turn_id
from provision.daemon import websocket_terminal_event_keeps_work_pending
from provision.launcher import chatgpt_base_url_override
from provision.launcher import configured_daemon_host
from provision.launcher import configured_daemon_port
from provision.launcher import openai_base_url_override
from provision.paths import Paths
from provision.store import Store, StoreError


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

    def test_forwarded_headers_get_non_urllib_user_agent(self) -> None:
        headers = ensure_default_upstream_user_agent({"accept-encoding": "identity"})
        self.assertEqual(headers["User-Agent"], DEFAULT_UPSTREAM_USER_AGENT)

    def test_forwarded_headers_preserve_incoming_user_agent(self) -> None:
        headers = ensure_default_upstream_user_agent(
            {
                "accept-encoding": "identity",
                "User-Agent": "codex-cli-test",
            }
        )
        self.assertEqual(headers["User-Agent"], "codex-cli-test")

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

    def test_compact_quota_html_selects_model_bucket(self) -> None:
        markup = render_compact_quota_html(
            {
                "payload": {
                    "rate_limit": {
                        "primary_window": {"used_percent": 25, "limit_window_seconds": 18000},
                        "secondary_window": {"used_percent": 16, "limit_window_seconds": 604800},
                    },
                    "additional_rate_limits": [
                        {
                            "limit_name": "Provision (default - updated 15:36 on 22 May)",
                            "metered_feature": "codex",
                            "rate_limit": {
                                "primary_window": {
                                    "used_percent": 25,
                                    "limit_window_seconds": 18000,
                                },
                                "secondary_window": {
                                    "used_percent": 16,
                                    "limit_window_seconds": 604800,
                                },
                            },
                        },
                        {
                            "limit_name": "GPT-5.3-Codex-Spark",
                            "metered_feature": "gpt-5.3-codex-spark",
                            "rate_limit": {
                                "primary_window": {
                                    "used_percent": 90,
                                    "limit_window_seconds": 18000,
                                },
                                "secondary_window": {
                                    "used_percent": 50,
                                    "limit_window_seconds": 604800,
                                },
                            },
                        }
                    ],
                },
                "fetched_at": datetime(2026, 5, 22, 15, 36),
            },
            "gpt-5.3-codex-spark",
        )

        self.assertIn("control-compact-quota", markup)
        self.assertGreater(markup.count("control-compact-quota"), 1)
        self.assertIn("GPT-5.3-Codex-Spark", markup)
        self.assertIn('<span class="control-compact-quota-name">Codex</span>', markup)
        self.assertEqual(markup.count('<span class="control-compact-quota-name">Codex</span>'), 1)
        self.assertLess(
            markup.find("GPT-5.3-Codex-Spark"),
            markup.find('<span class="control-compact-quota-name">Codex</span>'),
        )
        self.assertIn("10%", markup)
        self.assertIn("50%", markup)

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

    def test_quota_html_disables_reset_credit_control_while_verifying(self) -> None:
        markup = render_quota_html(
            {
                "payload": {
                    "rate_limit_reset_credits": {"available_count": 2},
                    "rate_limit": {
                        "primary_window": {"used_percent": 100, "limit_window_seconds": 18000},
                    },
                },
                "reset_credit": {
                    "status": "verifying",
                    "label": "Reset verifying",
                    "message": "Waiting for usage confirmation.",
                    "blocks": True,
                },
            },
            profile="default",
            token="ui-token",
        )

        self.assertNotIn("consume_reset_credit", markup)
        self.assertNotIn("/api/consume-reset-credit", markup)
        self.assertIn("quota-reset-credit-pill disabled", markup)
        self.assertIn("Reset verifying", markup)

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
                    "account/rateLimitResetCredit/consume "
                    "thread/list thread/read thread/resume thread/status/changed thread/tokenUsage/updated "
                    "turn/start turn/interrupt turn/steer "
                    "remoteControl/status/read remoteControl/enable remoteControl/disable remoteControl/pairing/start",
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
        self.assertTrue(payload["app_server"]["control_plane"]["read_only"])
        self.assertTrue(payload["app_server"]["control_plane"]["interactive"])
        self.assertTrue(payload["app_server"]["control_plane"]["remote_control"])

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
                        "model/list",
                        "model/rerouted",
                        "modelProvider/capabilities/read",
                        "model/verification",
                        "thread/list",
                        "thread/read",
                        "thread/resume",
                        "thread/settings/update",
                        "thread/settings/updated",
                        "thread/status/changed",
                        "thread/tokenUsage/updated",
                        "turn/start",
                        "turn/started",
                        "turn/completed",
                        "turn/interrupt",
                        "turn/steer",
                        "remoteControl/status/read",
                        "remoteControl/enable",
                        "remoteControl/disable",
                        "remoteControl/pairing/start",
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
        self.assertTrue(payload["methods"]["thread_list"])
        self.assertTrue(payload["methods"]["turn_start"])
        self.assertTrue(payload["methods"]["remote_control_status_read"])
        self.assertTrue(payload["capability_groups"]["thread"]["available"])
        self.assertTrue(payload["capability_groups"]["token_usage"]["available"])
        self.assertTrue(payload["capability_groups"]["turn"]["available"])
        self.assertTrue(payload["capability_groups"]["remote_control"]["available"])
        self.assertTrue(payload["control_plane"]["read_only"])
        self.assertTrue(payload["control_plane"]["interactive"])
        self.assertTrue(payload["control_plane"]["remote_control"])
        self.assertTrue(payload["response_types"]["reset_credit_summary"])

    def test_app_server_control_plane_status_marks_missing_optional_layers(self) -> None:
        methods = {name: False for name in daemon_module.APP_SERVER_CAPABILITY_METHODS}
        methods["thread_list"] = True
        methods["thread_read"] = True
        methods["thread_status_changed"] = True
        methods["thread_token_usage_updated"] = True

        status = daemon_module.app_server_control_plane_status(methods)

        self.assertTrue(status["read_only"])
        self.assertFalse(status["interactive"])
        self.assertFalse(status["remote_control"])
        self.assertEqual(
            status["missing"]["interactive"],
            ["thread_resume", "turn_start", "turn_interrupt", "turn_steer"],
        )

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
        self.assertIn(f'"version":"{daemon_module.PROTOCOL_VERSION}"', sent)
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

    def test_reset_credit_guard_blocks_duplicate_consume_before_upstream_call(self) -> None:
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
            called = False
            try:
                now = datetime.now(timezone.utc)
                with server.reset_credit_state_lock:
                    server.reset_credit_state["default"] = {
                        "status": "verifying",
                        "requested_at": daemon_module.utc_timestamp(now),
                        "cooldown_until": daemon_module.utc_timestamp(now + timedelta(days=1)),
                    }
                    server.save_reset_credit_state_locked()

                def fail_if_called(*_args: Any, **_kwargs: Any) -> None:
                    nonlocal called
                    called = True
                    raise AssertionError("upstream consume should not be called")

                server.run_app_server_for_profile = fail_if_called  # type: ignore[method-assign]

                with self.assertRaises(daemon_module.ResetCreditGuardError):
                    server.consume_profile_rate_limit_reset_credit("default")
            finally:
                server.server_close()

            self.assertFalse(called)

    def test_reset_credit_consume_waits_for_usage_confirmation_before_cache_update(self) -> None:
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
            old_payload = {
                "rate_limit": {
                    "primary_window": {"used_percent": 0.0},
                    "secondary_window": {"used_percent": 99.0},
                },
                "rate_limit_reset_credits": {"available_count": 1},
            }
            optimistic_rate_limits = {
                "rateLimits": {
                    "limitId": "codex",
                    "primary": {"usedPercent": 0.0},
                    "secondary": {"usedPercent": 0.0},
                },
                "rateLimitResetCredits": {"availableCount": 0},
            }
            try:
                server.update_usage_cache_from_observation(
                    "default",
                    old_payload,
                    source="usage_fetch",
                )
                server.schedule_reset_credit_verification = lambda *_args, **_kwargs: None  # type: ignore[method-assign]
                server.run_app_server_for_profile = lambda _profile, callback: {  # type: ignore[method-assign]
                    "consume": {"outcome": "reset"},
                    "rate_limits": optimistic_rate_limits,
                }

                result = server.consume_profile_rate_limit_reset_credit("default", idempotency_key="test-key")
            finally:
                server.server_close()

            self.assertEqual(result["outcome"], "reset")
            snapshot = server.usage_cache_snapshot("default")
            assert snapshot is not None
            self.assertEqual(snapshot["payload"]["rate_limit"]["secondary_window"]["used_percent"], 99.0)
            status = server.reset_credit_status("default")
            self.assertTrue(status["blocks"])
            self.assertEqual(status["status"], "verifying")

    def test_usage_fetch_verifies_reset_credit_and_starts_cooldown(self) -> None:
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
            before_payload = {
                "rate_limit": {
                    "primary_window": {"used_percent": 0.0},
                    "secondary_window": {"used_percent": 99.0},
                },
                "rate_limit_reset_credits": {"available_count": 1},
            }
            after_payload = {
                "rate_limit": {
                    "primary_window": {"used_percent": 1.0},
                    "secondary_window": {"used_percent": 0.0},
                },
                "rate_limit_reset_credits": {"available_count": 0},
            }
            try:
                now = datetime.now(timezone.utc)
                with server.reset_credit_state_lock:
                    server.reset_credit_state["default"] = {
                        "status": "verifying",
                        "idempotency_key": "test-key",
                        "requested_at": daemon_module.utc_timestamp(now),
                        "cooldown_until": daemon_module.utc_timestamp(now + timedelta(days=1)),
                        "before_payload": before_payload,
                    }
                    server.save_reset_credit_state_locked()

                self.assertTrue(
                    server.reconcile_reset_credit_verification(
                        "default",
                        after_payload,
                        source="usage_fetch",
                    )
                )
                status = server.reset_credit_status("default")
            finally:
                server.server_close()

            self.assertEqual(status["status"], "verified")
            self.assertTrue(status["blocks"])
            self.assertIn("cooldown_until", status)

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

    def test_fetch_usage_ignores_app_server_rate_limits_while_reset_verifies(self) -> None:
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
            now = datetime.now(timezone.utc)
            server.app_server_rate_limit_cache["default"] = {
                "payload": {
                    "rate_limit": {"secondary_window": {"used_percent": 0.0}},
                    "rate_limit_reset_credits": {"available_count": 0},
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
                                "secondary_window": {"used_percent": 99.0},
                            },
                            "rate_limit_reset_credits": {"available_count": 1},
                        }
                    ).encode("utf-8")

            original_ensure = daemon_module.ensure_fresh_chatgpt_auth
            original_urlopen = daemon_module.urllib.request.urlopen
            try:
                with server.reset_credit_state_lock:
                    server.reset_credit_state["default"] = {
                        "status": "verifying",
                        "requested_at": daemon_module.utc_timestamp(now),
                        "cooldown_until": daemon_module.utc_timestamp(now + timedelta(days=1)),
                    }
                    server.save_reset_credit_state_locked()
                daemon_module.ensure_fresh_chatgpt_auth = lambda _auth_path: auth  # type: ignore[assignment]
                daemon_module.urllib.request.urlopen = lambda _request, timeout=10: FakeResponse()

                payload = server.fetch_usage_payload_uncached("default")
            finally:
                daemon_module.ensure_fresh_chatgpt_auth = original_ensure
                daemon_module.urllib.request.urlopen = original_urlopen
                server.server_close()

            assert payload is not None
            self.assertEqual(payload["rate_limit"]["secondary_window"]["used_percent"], 99.0)
            self.assertEqual(payload["rate_limit_reset_credits"]["available_count"], 1)

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
        keyed = project_session_sentinel(
            "token",
            "/tmp/provision",
            session_key="/tmp/provision::ui::abc123",
        )
        self.assertEqual(
            decode_project_session_sentinel(keyed, "token"),
            {"key": "/tmp/provision::ui::abc123", "cwd": "/tmp/provision"},
        )
        self.assertEqual(decode_project_session_sentinel("provision-token", "token"), {})
        self.assertIsNone(decode_project_session_sentinel(sentinel, "other"))

    def test_codex_resume_candidates_reads_recent_matching_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            session_dir = root / "sessions" / "2026" / "06" / "22"
            session_dir.mkdir(parents=True)
            session_file = session_dir / "rollout-2026-06-22T10-00-00-019abc.jsonl"
            session_file.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "timestamp": "2026-06-22T10:00:00Z",
                                "type": "session_meta",
                                "payload": {
                                    "id": "019abc",
                                    "timestamp": "2026-06-22T10:00:00Z",
                                    "cwd": "/workspace/provision",
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "message",
                                    "role": "user",
                                    "content": [
                                        {
                                            "type": "input_text",
                                            "text": "# AGENTS.md instructions for /workspace/provision\nFollow local project guidance.",
                                        }
                                    ],
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "message",
                                    "role": "user",
                                    "content": [{"type": "input_text", "text": "Resume me"}],
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            candidates = codex_resume_candidates_for_cwd(
                "/workspace/provision",
                codex_home=root,
            )

            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0]["id"], "019abc")
            self.assertEqual(candidates[0]["label"], "Resume me")

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

    def test_websocket_transcript_extracts_user_and_assistant_text(self) -> None:
        user_payload = {
            "type": "response.create",
            "client_metadata": {
                "x-codex-turn-metadata": json.dumps(
                    {"turn_id": "turn-123", "thread_id": "thread-456", "cwd": "/workspace/provision"}
                ),
            },
            "response": {
                "input": [
                    {
                        "role": "user",
                        "content": [{"type": "input_text", "text": "Fix the failing test."}],
                    }
                ]
            },
        }
        self.assertEqual(
            daemon_module.websocket_message_user_text(
                0x1,
                json.dumps(user_payload).encode("utf-8"),
            ),
            "Fix the failing test.",
        )
        encoded_user = json.dumps(user_payload).encode("utf-8")
        self.assertEqual(websocket_message_turn_id(0x1, encoded_user), "turn-123")
        self.assertEqual(websocket_message_thread_id(0x1, encoded_user), "thread-456")
        self.assertEqual(
            daemon_module.websocket_message_assistant_entry(
                0x1,
                b'{"type":"response.output_text.delta","delta":"Working"}',
            ),
            {"role": "assistant_progress", "text": "Working", "append": True},
        )
        self.assertEqual(
            daemon_module.websocket_message_assistant_text(
                0x1,
                b'{"type":"response.output_text.delta","delta":"Working"}',
            ),
            ("Working", True),
        )
        self.assertEqual(
            daemon_module.websocket_message_assistant_entry(
                0x1,
                (
                    b'{"type":"response.output_text.delta",'
                    b'"delta":{"type":"output_text","text":" 2024**"}}'
                ),
            ),
            {"role": "assistant_progress", "text": " 2024**", "append": True},
        )
        self.assertEqual(
            daemon_module.websocket_message_assistant_text(
                0x1,
                (
                    b'{"type":"response.completed","response":{"output":[{"role":"assistant",'
                    b'"content":[{"type":"output_text","text":"Done."}]}]}}'
                ),
            ),
            ("Done.", False),
        )
        self.assertEqual(
            websocket_message_tool_entries(
                0x1,
                json.dumps(
                    {
                        "type": "response.output_item.done",
                        "item": {
                            "type": "local_shell_call",
                            "command": "python -m pytest",
                            "status": "completed",
                            "exit_code": 0,
                            "stdout": "2 passed",
                        },
                    }
                ).encode("utf-8"),
            ),
            [
                {
                    "role": "tool",
                    "text": "Command: python -m pytest (status completed, exit 0)\nStdout:\n2 passed",
                    "call_id": "",
                    "status": "completed",
                }
            ],
        )
        self.assertEqual(
            websocket_message_tool_entries(
                0x1,
                json.dumps(
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "call_id": "call-1",
                            "output": "Exit code: 0\nOutput:\n2 passed",
                        },
                    }
                ).encode("utf-8"),
            ),
            [
                {
                    "role": "tool",
                    "text": "Tool: call-1\nOutput:\nExit code: 0\nOutput:\n2 passed",
                    "call_id": "call-1",
                    "status": "",
                }
            ],
        )
        self.assertEqual(
            websocket_message_tool_entries(
                0x1,
                json.dumps(
                    {
                        "type": "response.output_item.added",
                        "item": {
                            "type": "function_call",
                            "name": "ctc_0123456789abcdef",
                            "call_id": "ctc_0123456789abcdef",
                            "status": "in_progress",
                        },
                    }
                ).encode("utf-8"),
            ),
            [],
        )
        self.assertEqual(
            daemon_module.user_transcript_entries(
                "<environment_context><cwd>/tmp/old</cwd></environment_context>\n"
                "Earlier question\n"
                "<environment_context><cwd>/tmp/current</cwd></environment_context>\n"
                "Current question"
            ),
            [
                {"role": "resume", "text": "Earlier question"},
                {"role": "user", "text": "Current question"},
            ],
        )
        self.assertEqual(
            daemon_module.user_transcript_entries(
                "\ufeff\n\n"
                "<environment_context><cwd>/tmp/current</cwd></environment_context>\n\n"
                "\u200b\n\u200b\nInitial observed prompt\n\u200b\n\u200b"
            ),
            [{"role": "user", "text": "Initial observed prompt"}],
        )
        self.assertEqual(
            daemon_module.split_user_entries_by_prompt_suffix(
                [{"role": "user", "text": "Earlier follow-up\n\nCurrent question"}],
                "Current question",
            ),
            [
                {"role": "resume", "text": "Earlier follow-up"},
                {"role": "user", "text": "Current question"},
            ],
        )
        payload = {
            "type": "response.create",
            "response": {
                "input": [
                    {
                        "type": "message",
                        "role": "user",
                        "content": [
                            {
                                "type": "input_text",
                                "text": "<environment_context><cwd>/tmp/project</cwd></environment_context>",
                            }
                        ],
                    },
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "Earlier CLI prompt"}],
                    },
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "Current CLI prompt"}],
                    },
                ]
            },
        }
        self.assertEqual(
            daemon_module.response_create_payload_user_entries(payload),
            [
                {"role": "resume", "text": "Earlier CLI prompt"},
                {"role": "user", "text": "Current CLI prompt"},
            ],
        )
        padded_payload = {
            "type": "response.create",
            "response": {
                "input": [
                    {
                        "type": "message",
                        "role": "user",
                        "content": [
                            {
                                "type": "input_text",
                                "text": "<environment_context><cwd>/tmp/project</cwd></environment_context>\n\n",
                            },
                            {
                                "type": "input_text",
                                "text": "\u200b\n\u200b\nInitial observed prompt\n\u200b\n\u200b",
                            },
                        ],
                    }
                ]
            },
        }
        self.assertEqual(
            daemon_module.response_create_payload_user_entries(padded_payload),
            [{"role": "user", "text": "Initial observed prompt"}],
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
            self.assertEqual([event["type"] for event in summary["recent"]], ["websocket_tunnel", "token_usage"])
            self.assertEqual([point["quota_updates"] for point in summary["series"]][-1], 1)

    def test_control_plane_sessions_include_active_state_and_events(self) -> None:
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
            left, right = socket.socketpair()
            request_id: int | None = None
            tunnel_id: int | None = None
            try:
                cwd = "/workspace/provision"
                session_key = server.observe_session(cwd, "default")
                request_id = server.begin_request("default", session_key)
                tunnel_id = server.begin_websocket("default", left, session_key)
                server.begin_websocket_work(tunnel_id, "turn-123", "thread-456")
                server.note_websocket_traffic(
                    tunnel_id,
                    bytes_count=64,
                    message_count=2,
                    from_downstream=True,
                    service_tier="priority",
                )
                server.record_http_stats(
                    profile="default",
                    session_key=session_key,
                    route=UpstreamRoute.CODEX_API,
                    path="/v1/responses",
                    method="POST",
                    status_code=200,
                    duration_seconds=0.1,
                    bytes_in=12,
                    bytes_out=34,
                    service_tier="priority",
                )
                server.record_token_usage(
                    profile="default",
                    tunnel_id=tunnel_id,
                    usage={
                        "input_tokens": 10,
                        "cached_input_tokens": 0,
                        "output_tokens": 5,
                        "reasoning_output_tokens": 0,
                        "total_tokens": 15,
                    },
                )
                server.record_websocket_transcript_message(
                    tunnel_id,
                    role="user",
                    text="Fix the failing control-plane test.",
                )
                server.record_websocket_transcript_message(
                    tunnel_id,
                    role="assistant_progress",
                    text="Checking behavior.",
                    append=True,
                )
                server.record_websocket_transcript_message(
                    tunnel_id,
                    role="assistant_progress",
                    text="At this point I have enough context.",
                    append=True,
                )
                server.record_websocket_transcript_message(
                    tunnel_id,
                    role="tool",
                    text="Command: pytest\nOutput:\n1 passed",
                )

                payload = server.control_plane_sessions()
            finally:
                if request_id is not None:
                    server.end_request(request_id)
                if tunnel_id is not None:
                    server.end_websocket(tunnel_id)
                left.close()
                right.close()
                server.server_close()

            sessions = payload["sessions"]
            self.assertEqual(len(sessions), 1)
            session = sessions[0]
            self.assertEqual(session["key"], session_key)
            self.assertEqual(session["title"], "provision")
            self.assertEqual(session["thread_id"], "thread-456")
            self.assertEqual(session["active_requests"], 1)
            self.assertEqual(session["pending_websocket_work"], 1)
            self.assertIn("quota_html", session)
            self.assertIn("No quota cached", session["quota_html"])
            self.assertIn("quota_compact_html", session)
            self.assertEqual(session["quota_compact_html"], "")
            self.assertEqual(session["active_details"]["requests"][0]["profile"], "default")
            self.assertEqual(session["active_details"]["tunnels"][0]["turn_id"], "turn-123")
            self.assertEqual(session["active_details"]["tunnels"][0]["thread_id"], "thread-456")
            self.assertEqual(session["transcript"][0]["role"], "user")
            self.assertEqual(
                session["transcript"][1]["text"],
                "Checking behavior.\nAt this point I have enough context.",
            )
            self.assertEqual(session["transcript"][2]["role"], "tool")
            self.assertEqual(session["turns"][0]["turn_id"], "turn-123")
            self.assertIn("Fix the failing control-plane test.", session["turns"][0]["label"])
            self.assertEqual(session["context"]["input_tokens"], 10)
            self.assertIn("left", session["context"]["label"])
            event_types = {event["type"] for event in session["events"]}
            self.assertIn("http_request", event_types)
            self.assertIn("token_usage", event_types)
            self.assertTrue(
                any("Token usage" in event["summary"] for event in session["events"])
            )

    def test_session_tabs_keep_observed_order_and_persist_reorder(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = Paths(Path(temp) / "home")
            server = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                first = server.observe_session("/workspace/alpha", "default")
                second = server.observe_session("/workspace/beta", "default")
                server.observe_session("/workspace/alpha", "default")

                self.assertEqual(
                    [item["key"] for item in server.session_snapshots()],
                    [first, second],
                )

                server.reorder_sessions([second, first])
                self.assertEqual(
                    [item["key"] for item in server.session_snapshots()],
                    [second, first],
                )
            finally:
                server.server_close()

            restored = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                restored.observe_session("/workspace/alpha", "default")
                restored.observe_session("/workspace/beta", "default")

                self.assertEqual(
                    [item["key"] for item in restored.session_snapshots()],
                    [second, first],
                )
            finally:
                restored.server_close()

    @unittest.skipIf(not hasattr(socket, "AF_UNIX"), "PTY control sockets require AF_UNIX")
    def test_send_session_prompt_uses_pty_control_socket(self) -> None:
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
            control_path = root / "control.sock"
            ready = threading.Event()
            received: list[dict[str, Any]] = []

            def control_socket() -> None:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                    listener.bind(str(control_path))
                    listener.listen(1)
                    ready.set()
                    conn, _ = listener.accept()
                    with conn:
                        raw = conn.recv(4096)
                        received.append(json.loads(raw.decode("utf-8")))
                        conn.sendall(b'{"ok":true}')

            thread = threading.Thread(target=control_socket, daemon=True)
            thread.start()
            self.assertTrue(ready.wait(1.0))
            try:
                session_key = server.observe_session(
                    "/workspace/provision",
                    "default",
                    control_path=str(control_path),
                    launcher_pid=1234,
                    pty_managed=True,
                )
                snapshot = next(
                    item for item in server.session_snapshots() if item["key"] == session_key
                )
                self.assertTrue(snapshot["pty_managed"])
                self.assertTrue(snapshot["pty_control_available"])
                self.assertTrue(snapshot["interaction"]["available"])
                result = server.send_session_prompt(session_key, "Please continue.")
            finally:
                server.server_close()
            thread.join(1.0)

            self.assertEqual(result["mode"], "pty")
            self.assertEqual(result["profile"], "default")
            self.assertEqual(result["cwd"], "/workspace/provision")
            self.assertEqual(received, [{"action": "send_text", "text": "Please continue."}])
            transcript = server.control_transcripts[session_key]
            self.assertEqual(len(transcript), 1)
            self.assertEqual(transcript[0]["role"], "user_pending")
            self.assertEqual(transcript[0]["text"], "Please continue.")

            server.append_control_transcript(
                session_key=session_key,
                role="user",
                text="Please continue.",
                turn_id="turn-from-websocket",
                profile="default",
            )

            self.assertEqual(len(transcript), 1)
            self.assertEqual(transcript[0]["role"], "user")
            self.assertEqual(transcript[0]["turn_id"], "turn-from-websocket")

    def test_passive_session_observation_preserves_pty_control_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = Paths(root / "home")
            control_path = root / "control.sock"
            control_path.write_text("", encoding="utf-8")
            server = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                session_key = server.observe_session(
                    "/workspace/provision",
                    "default",
                    control_path=str(control_path),
                    launcher_pid=1234,
                    pty_managed=True,
                )
                server.observe_session("/workspace/provision", "default")
                snapshot = next(
                    item for item in server.session_snapshots() if item["key"] == session_key
                )
                self.assertTrue(snapshot["pty_managed"])
                self.assertTrue(snapshot["pty_control_available"])
                self.assertTrue(snapshot["interaction"]["available"])

                server.observe_session(
                    "/workspace/provision",
                    "default",
                    clear_control_path=True,
                )
                snapshot = next(
                    item for item in server.session_snapshots() if item["key"] == session_key
                )
                self.assertFalse(snapshot["pty_managed"])
                self.assertFalse(snapshot["pty_control_available"])
                self.assertFalse(snapshot["interaction"]["available"])
            finally:
                server.server_close()

    def test_ui_launcher_args_include_resume_cwd_and_permission(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            server = ProvisionServer(("127.0.0.1", 0), Paths(Path(temp) / "home"))
            try:
                args = server.build_ui_launcher_args(
                    cwd="/workspace/provision",
                    mode="resume-last",
                    permission="read-only",
                )
                self.assertEqual(args[0], str(Path("bin/provision").resolve()))
                self.assertEqual(args[1:6], ["resume", "--cd", "/workspace/provision", "--sandbox", "read-only"])
                self.assertIn("--last", args)
                selected = server.build_ui_launcher_args(
                    cwd="/workspace/provision",
                    mode="resume-session",
                    permission="workspace-write",
                    session_id="019abc",
                )
                self.assertEqual(selected[1], "resume")
                self.assertIn("019abc", selected)

                bypass = server.build_ui_launcher_args(
                    cwd="/workspace/provision",
                    mode="new",
                    permission="bypass",
                )
                self.assertIn("--dangerously-bypass-approvals-and-sandbox", bypass)
                self.assertNotIn("resume", bypass)
            finally:
                server.server_close()

    def test_forget_session_removes_idle_observed_session(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = Paths(Path(temp) / "home")
            auth = {
                "auth_mode": "chatgpt",
                "tokens": {
                    "id_token": fake_jwt({"email": "user@example.test"}),
                    "access_token": fake_jwt({"exp": 9999999999}),
                    "refresh_token": "rt_test",
                },
            }
            source = Path(temp) / "auth.json"
            source.write_text(json.dumps(auth), encoding="utf-8")
            Store(paths).import_auth_file("default", source)
            server = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                session_key = server.observe_session("/workspace/provision", "default")
                server.pin_session(session_key, "default")
                server.append_control_transcript(
                    session_key=session_key,
                    role="user",
                    text="old prompt",
                )
                server.forget_session(session_key)
                self.assertEqual(server.session_snapshots(), [])
                self.assertNotIn(session_key, server.control_transcripts)
                self.assertNotIn(session_key, server.pinned_sessions)
            finally:
                server.server_close()

    def test_forget_session_refuses_live_pty_control(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = Paths(root / "home")
            control_path = root / "control.sock"
            control_path.write_text("", encoding="utf-8")
            server = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                session_key = server.observe_session(
                    "/workspace/provision",
                    "default",
                    control_path=str(control_path),
                    pty_managed=True,
                )
                with self.assertRaises(StoreError):
                    server.forget_session(session_key)
                server.forget_session(session_key, force_live=True)
                self.assertEqual(server.session_snapshots(), [])
            finally:
                server.server_close()

    def test_codex_history_bridge_links_sessions_without_auth(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "stock"
            target = root / "app"
            (source / "sessions").mkdir(parents=True)
            (source / "sessions" / "rollout.jsonl").write_text("{}", encoding="utf-8")
            (source / "state_5.sqlite").write_text("state", encoding="utf-8")
            (source / "auth.json").write_text("stock-auth", encoding="utf-8")
            target.mkdir()

            bridge_codex_history_into_app_home(target, source)

            self.assertTrue((target / "sessions").exists())
            self.assertTrue((target / "state_5.sqlite").exists())
            self.assertFalse((target / "auth.json").exists())

    def test_app_server_thread_selection_requires_matching_cli_cwd(self) -> None:
        payload = {
            "data": [
                {"id": "app-thread", "cwd": "/workspace/provision", "source": "appServer"},
                {"id": "other-thread", "cwd": "/workspace/other", "source": "cli"},
                {"id": "target-thread", "cwd": "/workspace/provision", "source": "cli"},
            ]
        }

        self.assertEqual(
            daemon_module.first_app_server_thread_id(payload, cwd="/workspace/provision"),
            "target-thread",
        )
        self.assertIsNone(
            daemon_module.first_app_server_thread_id(payload, cwd="/workspace/missing"),
        )
        self.assertEqual(daemon_module.first_app_server_thread_id(payload), "other-thread")

    def test_tool_transcript_updates_matching_call_id(self) -> None:
        server = ProvisionServer.__new__(ProvisionServer)
        server.control_transcripts = {}
        session_key = "/workspace/provision"

        server.append_control_transcript(
            session_key=session_key,
            role="tool",
            text="Command: pytest (status in_progress)",
            call_id="call-1",
        )
        server.append_control_transcript(
            session_key=session_key,
            role="tool",
            text="Command: pytest (status completed, exit 0)\nOutput:\n1 passed",
            call_id="call-1",
        )

        transcript = server.control_transcripts[session_key]
        self.assertEqual(len(transcript), 1)
        self.assertIn("completed", transcript[0]["text"])
        self.assertIn("1 passed", transcript[0]["text"])

        server.append_control_transcript(
            session_key=session_key,
            role="tool",
            text="Command: python -m pytest\nArguments:\ncmd: python -m pytest",
            call_id="call-2",
        )
        server.append_control_transcript(
            session_key=session_key,
            role="tool",
            text="Tool: call-2\nOutput:\nExit code: 0\nOutput:\n2 passed",
            call_id="call-2",
        )

        self.assertEqual(len(transcript), 2)
        self.assertIn("Command: python -m pytest", transcript[1]["text"])
        self.assertIn("2 passed", transcript[1]["text"])
        self.assertNotIn("Tool: call-2", transcript[1]["text"])

        server.append_control_transcript(
            session_key=session_key,
            role="tool",
            text="Tool: apply_patch (status in_progress)\nArguments:\n*** Begin Patch\n*** Update File: app.py\n@@\n-old\n+new\n*** End Patch",
            call_id="call-3",
        )
        server.append_control_transcript(
            session_key=session_key,
            role="tool",
            text="Tool: apply_patch (status completed)",
            call_id="call-3",
        )

        self.assertEqual(len(transcript), 3)
        self.assertIn("Tool: apply_patch (status completed)", transcript[2]["text"])
        self.assertIn("Arguments:", transcript[2]["text"])
        self.assertIn("*** Begin Patch", transcript[2]["text"])
        self.assertIn("+new", transcript[2]["text"])

        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="Assistant answer",
            turn_id="turn-ui",
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant",
            text="Assistant answer",
            turn_id="turn-ui",
        )

        self.assertEqual(len(transcript), 4)
        self.assertEqual(transcript[3]["role"], "assistant")
        self.assertEqual(transcript[3]["text"], "Assistant answer")

        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="Checks pass and reports an",
            turn_id="turn-spacing",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="8-second measured window.",
            turn_id="turn-spacing",
            append=True,
        )
        spacing_text = transcript[-1]["text"]
        self.assertIn("an 8-second measured window", spacing_text)

        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="The result was meas",
            turn_id="turn-word-split",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="ured correctly.",
            turn_id="turn-word-split",
            append=True,
        )
        word_split_text = transcript[-1]["text"]
        self.assertIn("measured correctly", word_split_text)

        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="Why it may not be updated:\n\n- model training and deployment are separate from live browsing/tool access",
            turn_id="turn-list",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="- newer models can still carry older fixed training cutoffs",
            turn_id="turn-list",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="- product surfaces may prioritize tool-augmented current lookup",
            turn_id="turn-list",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="Practically: verify latest facts.",
            turn_id="turn-list",
            append=True,
        )

        list_text = transcript[-1]["text"]
        self.assertIn("access\n- newer models", list_text)
        self.assertIn("lookup\n\nPractically: verify latest facts.", list_text)

        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="Other plausible reasons:\n\n- **",
            turn_id="turn-bold-list",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="Safety/evaluation lag:** newer training data requires extra evaluation before deployment.",
            turn_id="turn-bold-list",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="- **",
            turn_id="turn-bold-list",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="Licensing/filtering constraints:** not all newer public data is usable for training.",
            turn_id="turn-bold-list",
            append=True,
        )

        bold_list_text = transcript[-1]["text"]
        self.assertIn(
            "- **Safety/evaluation lag:** newer training data requires extra evaluation",
            bold_list_text,
        )
        self.assertIn(
            "\n- **Licensing/filtering constraints:** not all newer public data",
            bold_list_text,
        )
        self.assertNotIn("- **\n\nSafety", bold_list_text)

        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="The acceptance checklist would be:\n\n- [x]",
            turn_id="turn-task-list",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text=" Passive session observation works",
            turn_id="turn-task-list",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="- [ ]",
            turn_id="turn-task-list",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text=" Launch from UI",
            turn_id="turn-task-list",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="- [ ]",
            turn_id="turn-task-list",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text=" Resume from UI",
            turn_id="turn-task-list",
            append=True,
        )

        task_list_text = transcript[-1]["text"]
        self.assertIn("- [x] Passive session observation works", task_list_text)
        self.assertIn("\n- [ ] Launch from UI", task_list_text)
        self.assertIn("\n- [ ] Resume from UI", task_list_text)
        self.assertNotIn("[x]\n\nPassive", task_list_text)

        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="Before:\n\n- active profile",
            turn_id="turn-spaced-list",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text=" - remaining quota buckets",
            turn_id="turn-spaced-list",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text=" - reset credit availability",
            turn_id="turn-spaced-list",
            append=True,
        )

        spaced_list_text = transcript[-1]["text"]
        self.assertIn("- active profile\n - remaining quota buckets", spaced_list_text)
        self.assertIn("\n - reset credit availability", spaced_list_text)
        self.assertNotIn("active profile - remaining", spaced_list_text)

        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="The important acceptance criteria are fairly concrete:\n\n- [x] Existing proxy/profile switching remains stable",
            turn_id="turn-complete-task-list",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="- [x] Control-plane sessions reflect observed Codex activity",
            turn_id="turn-complete-task-list",
            append=True,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text=" - [ ] Reset-credit behavior has been verified against live quota exhaustion",
            turn_id="turn-complete-task-list",
            append=True,
        )

        complete_task_list_text = transcript[-1]["text"]
        self.assertIn(
            "stable\n- [x] Control-plane sessions reflect observed",
            complete_task_list_text,
        )
        self.assertIn(
            "activity\n - [ ] Reset-credit behavior has been verified",
            complete_task_list_text,
        )
        self.assertNotIn("stable- [x]", complete_task_list_text)
        self.assertNotIn("activity - [ ]", complete_task_list_text)

        long_text = "x" * (daemon_module.CONTROL_TRANSCRIPT_TEXT_LIMIT + 25)
        server.append_control_transcript(
            session_key=session_key,
            role="assistant",
            text=long_text,
            turn_id="turn-long",
        )

        self.assertEqual(transcript[-1]["role"], "assistant")
        self.assertTrue(transcript[-1]["truncated"])
        self.assertEqual(transcript[-1]["full_text"], long_text)
        self.assertIn("...[truncated]", transcript[-1]["text"])

    def test_apply_patch_tool_entry_keeps_input_patch_body(self) -> None:
        entry = daemon_module.tool_activity_entry_from_value(
            {
                "type": "apply_patch_call",
                "call_id": "patch-1",
                "name": "apply_patch",
                "status": "completed",
                "input": "*** Begin Patch\n*** Update File: app.py\n@@\n-old\n+new\n*** End Patch",
            }
        )

        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry["role"], "tool")
        self.assertIn("Tool: apply_patch (status completed)", entry["text"])
        self.assertIn("Input:", entry["text"])
        self.assertIn("*** Begin Patch", entry["text"])
        self.assertIn("+new", entry["text"])

        command_shaped = daemon_module.tool_activity_entry_from_value(
            {
                "type": "apply_patch_call",
                "call_id": "patch-2",
                "name": "apply_patch",
                "cmd": "*** Begin Patch\n*** Update File: app.py\n@@\n-old\n+new\n*** End Patch",
            }
        )
        self.assertIsNotNone(command_shaped)
        assert command_shaped is not None
        self.assertIn("Tool: apply_patch", command_shaped["text"])
        self.assertIn("Input:", command_shaped["text"])
        self.assertNotIn("Command: *** Begin Patch", command_shaped["text"])

    def test_control_tool_call_entries_are_suppressed(self) -> None:
        control_entry = daemon_module.tool_activity_entry_from_value(
            {
                "type": "function_call",
                "call_id": "ctc_0123456789abcdef",
                "name": "ctc_0123456789abcdef",
                "status": "completed",
                "arguments": "*** Begin Patch\n*** Update File: app.py\n@@\n-old\n+new\n*** End Patch",
            }
        )

        self.assertIsNone(control_entry)
        entries = daemon_module.tool_activity_entries_from_value(
            [
                {
                    "type": "function_call",
                    "call_id": "ctc_0123456789abcdef",
                    "name": "ctc_0123456789abcdef",
                    "status": "completed",
                    "arguments": "*** Begin Patch\n*** Update File: app.py\n@@\n-old\n+new\n*** End Patch",
                },
                {
                    "type": "apply_patch_call",
                    "call_id": "patch-1",
                    "name": "apply_patch",
                    "status": "completed",
                    "input": "*** Begin Patch\n*** Update File: app.py\n@@\n-old\n+new\n*** End Patch",
                },
            ]
        )
        self.assertEqual(len(entries), 1)
        self.assertIn("Tool: apply_patch", entries[0]["text"])

    def test_observed_user_input_does_not_inherit_stale_turn_id(self) -> None:
        server = ProvisionServer.__new__(ProvisionServer)
        server.control_transcripts = {}
        server.active_lock = threading.RLock()
        session_key = "/workspace/provision"
        tunnel_id = 9
        server.active_websockets = {
            tunnel_id: {
                "session_key": session_key,
                "turn_id": "old-turn",
                "profile": "default",
            }
        }

        server.record_websocket_transcript_message(
            tunnel_id,
            role="user",
            text="Run the next validation pass.",
        )
        transcript = server.control_transcripts[session_key]
        self.assertEqual(transcript[0]["role"], "user")
        self.assertEqual(transcript[0]["turn_id"], "")

        server.active_websockets[tunnel_id]["turn_id"] = "new-turn"
        server.record_websocket_transcript_message(
            tunnel_id,
            role="assistant_progress",
            text="Starting validation.",
            append=True,
        )

        self.assertEqual(transcript[0]["turn_id"], "new-turn")
        self.assertEqual(transcript[1]["turn_id"], "new-turn")

        server.active_websockets[tunnel_id]["pending_work"] = 1
        server.active_websockets[tunnel_id]["turn_id"] = "active-turn"
        server.record_websocket_transcript_message(
            tunnel_id,
            role="user",
            text="A mid-turn clarification.",
        )
        self.assertEqual(transcript[-1]["turn_id"], "active-turn")

    def test_control_transcript_user_entries_trim_display_framing(self) -> None:
        server = ProvisionServer.__new__(ProvisionServer)
        server.control_transcripts = {}
        session_key = "/workspace/provision"

        server.append_control_transcript(
            session_key=session_key,
            role="user",
            text="\u200b\n\u200b\nInitial observed prompt\n\u200b\n\u200b",
        )

        transcript = server.control_transcripts[session_key]
        self.assertEqual(transcript[0]["text"], "Initial observed prompt")
        self.assertEqual(server.transcript_item_full_text(transcript[0]), "Initial observed prompt")
        self.assertEqual(transcript[0]["search_text"], "user Initial observed prompt")

    def test_same_turn_user_input_does_not_create_extra_control_turn(self) -> None:
        server = ProvisionServer.__new__(ProvisionServer)
        session_key = "/workspace/provision"
        transcript = [
            {
                "ts": "2026-06-26T00:00:00Z",
                "updated_at": "2026-06-26T00:00:00Z",
                "role": "user",
                "turn_id": "turn-1",
                "text": "Start the implementation.",
                "control_index": 0,
            },
            {
                "ts": "2026-06-26T00:00:01Z",
                "updated_at": "2026-06-26T00:00:01Z",
                "role": "assistant_progress",
                "turn_id": "turn-1",
                "text": "Working.",
                "control_index": 1,
            },
            {
                "ts": "2026-06-26T00:00:02Z",
                "updated_at": "2026-06-26T00:00:02Z",
                "role": "user",
                "turn_id": "turn-1",
                "text": "Also check the edge case.",
                "control_index": 2,
            },
            {
                "ts": "2026-06-26T00:00:03Z",
                "updated_at": "2026-06-26T00:00:03Z",
                "role": "assistant",
                "turn_id": "turn-1",
                "text": "Done.",
                "control_index": 3,
            },
        ]

        turns = server.control_turns_from_transcript(transcript)
        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0]["turn_id"], "turn-1")
        self.assertEqual(turns[0]["start_index"], 0)
        self.assertEqual(turns[0]["end_index"], 3)

    def test_resumed_context_replay_is_suppressed_with_marker(self) -> None:
        server = ProvisionServer.__new__(ProvisionServer)
        server.control_transcripts = {}
        session_key = "/workspace/project-alpha"
        turn_id = "turn-resume"
        resume_text = "Earlier turn one.\n\nEarlier turn two."
        user_text = "Go ahead and lock the hygiene/package-release arc, then address it"

        server.append_control_transcript(
            session_key=session_key,
            role="resume",
            text=resume_text,
            turn_id=turn_id,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="user",
            text=user_text,
            turn_id=turn_id,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="assistant_progress",
            text="Working on it.",
            turn_id=turn_id,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="tool",
            text="Command: pytest (status completed)",
            turn_id=turn_id,
            call_id="call-1",
        )

        server.append_control_transcript(
            session_key=session_key,
            role="resume",
            text=resume_text,
            turn_id=turn_id,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="user",
            text=user_text,
            turn_id=turn_id,
        )

        transcript = server.control_transcripts[session_key]
        roles = [item["role"] for item in transcript]
        self.assertEqual(roles.count("resume"), 1)
        self.assertEqual(roles.count("user"), 1)
        self.assertEqual(roles.count("context_compaction"), 1)
        marker = next(item for item in transcript if item["role"] == "context_compaction")
        self.assertIn("Context replay observed", marker["text"])
        self.assertNotIn(user_text, marker["text"])

    def test_pending_prompt_moves_after_resume_replay(self) -> None:
        server = ProvisionServer.__new__(ProvisionServer)
        server.control_transcripts = {}
        session_key = "/workspace/release-app"
        prompt = "Continue the release validation."

        server.append_control_transcript(
            session_key=session_key,
            role="user_pending",
            text=prompt,
        )
        server.append_control_transcript(
            session_key=session_key,
            role="resume",
            text="Earlier launcher prompt.\n\nAnother prior clarification.",
            turn_id="turn-release-app",
        )
        server.append_control_transcript(
            session_key=session_key,
            role="resume",
            text="Recent replayed prompt.",
            turn_id="turn-release-app",
        )
        server.append_control_transcript(
            session_key=session_key,
            role="user",
            text=prompt,
            turn_id="turn-release-app",
        )

        transcript = server.control_transcripts[session_key]
        self.assertEqual([item["role"] for item in transcript], ["resume", "user"])
        self.assertIn("Earlier launcher prompt.", transcript[0]["text"])
        self.assertIn("Recent replayed prompt.", transcript[0]["text"])
        self.assertEqual(transcript[1]["text"], prompt)
        self.assertEqual(transcript[1]["turn_id"], "turn-release-app")

    def test_structured_downstream_user_items_keep_only_last_as_user(self) -> None:
        server = ProvisionServer.__new__(ProvisionServer)
        server.control_transcripts = {}
        server.active_lock = threading.RLock()
        session_key = "/workspace/release-app"
        tunnel_id = 17
        server.active_websockets = {
            tunnel_id: {
                "session_key": session_key,
                "turn_id": "turn-release-app",
                "pending_work": 1,
                "profile": "default",
            }
        }
        payload = {
            "type": "response.create",
            "client_metadata": {
                "x-codex-turn-metadata": json.dumps(
                    {"turn_id": "turn-release-app", "thread_id": "thread-release-app"}
                )
            },
            "response": {
                "input": [
                    {
                        "type": "message",
                        "role": "user",
                        "content": [
                            {
                                "type": "input_text",
                                "text": "<environment_context><cwd>/workspace/release-app</cwd></environment_context>",
                            }
                        ],
                    },
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "Earlier launcher prompt"}],
                    },
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "Another prior clarification"}],
                    },
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "Current visible prompt"}],
                    },
                ]
            },
        }

        server.record_websocket_transcript(
            tunnel_id,
            0x1,
            json.dumps(payload).encode("utf-8"),
            from_downstream=True,
        )

        transcript = server.control_transcripts[session_key]
        self.assertEqual([item["role"] for item in transcript], ["resume", "user"])
        self.assertIn("Earlier launcher prompt", transcript[0]["text"])
        self.assertIn("Another prior clarification", transcript[0]["text"])
        self.assertEqual(transcript[1]["text"], "Current visible prompt")

    def test_anonymized_codex_stream_fixture_builds_control_transcript(self) -> None:
        fixture = (
            Path(__file__).parent
            / "fixtures"
            / "codex_streams"
            / "anonymized_control_plane_stream.jsonl"
        )
        server = ProvisionServer.__new__(ProvisionServer)
        server.control_transcripts = {}
        server.active_lock = threading.RLock()
        session_key = "/workspace/example"
        tunnel_id = 7
        server.active_websockets = {
            tunnel_id: {
                "session_key": session_key,
                "turn_id": "",
                "profile": "default",
            }
        }

        for line in fixture.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            payload = json.dumps(row["payload"]).encode("utf-8")
            from_downstream = row["direction"] == "downstream"
            if from_downstream:
                turn_id = daemon_module.websocket_message_turn_id(int(row["opcode"]), payload)
                with server.active_lock:
                    server.active_websockets[tunnel_id]["turn_id"] = turn_id or ""
            server.record_websocket_transcript(
                tunnel_id,
                int(row["opcode"]),
                payload,
                from_downstream=from_downstream,
            )

        transcript = server.control_transcripts[session_key]
        roles = [item["role"] for item in transcript]
        self.assertEqual(roles.count("resume"), 1)
        self.assertEqual(roles.count("user"), 1)
        self.assertEqual(roles.count("assistant"), 1)
        self.assertEqual(roles.count("tool"), 1)
        self.assertEqual(roles.count("context_compaction"), 1)
        self.assertIn("Summarized prior request", transcript[0]["text"])
        self.assertIn("Please complete the package hygiene work.", transcript[1]["text"])
        tool = next(item for item in transcript if item["role"] == "tool")
        self.assertIn("Command: pytest -q", tool["text"])
        self.assertIn("2 passed", tool["text"])
        assistant = next(item for item in transcript if item["role"] == "assistant")
        self.assertIn("Completed the hygiene pass.", assistant["text"])
        self.assertIn("[workflow.yml]\n\n(/workspace/example/.github/workflows/workflow.yml)", assistant["text"])

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
                    "app_server": {
                        "available": True,
                        "methods": {"rate_limit_reset_credit_consume": True},
                        "control_plane": {"read_only": True},
                    },
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
            self.assertIn("Codex app-server read-only control-plane schema readable", output.getvalue())

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
