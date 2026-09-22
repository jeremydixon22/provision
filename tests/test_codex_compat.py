from __future__ import annotations

import http.client
import json
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from provision import daemon
from provision.codex_compat import ModelRewriteContext
from provision.paths import Paths
from provision.store import Store, StoreError


def control(effort: str) -> dict:
    return {"type": "configuration_update", "reasoning": {"effort": effort}}


def request(cwd: str, **extra: object) -> dict:
    return {
        "model": "gpt-6-astra",
        "input": [],
        "client_metadata": {
            "x-codex-turn-metadata": json.dumps({"cwd": cwd, "thread_id": "thread-1"})
        },
        **extra,
    }


class ReasoningCompatibilityTests(unittest.TestCase):
    def test_http_keeps_history_and_prefix_but_overrides_current_turn(self) -> None:
        history = [
            control("high"),
            {"role": "user", "content": "earlier"},
            {"role": "assistant", "content": "answer"},
        ]
        original = {
            "model": "gpt-6-astra",
            "reasoning": {"effort": "medium", "summary": "auto"},
            "input": [*history, {"role": "user", "content": "next"}],
        }
        encoded = json.dumps(original).encode()
        body, _, _, changed = daemon.rewrite_model_body(
            encoded, model="gpt-6-astra", reasoning_effort="low"
        )
        rewritten = json.loads(body)
        self.assertTrue(changed)
        self.assertEqual(rewritten["reasoning"], original["reasoning"])
        self.assertEqual(rewritten["input"][:3], history)
        self.assertEqual(rewritten["input"][-2], control("low"))
        self.assertEqual(json.dumps(original).encode(), encoded)
        repeated, _, _, changed = daemon.rewrite_model_body(
            body, model="gpt-6-astra", reasoning_effort="low"
        )
        self.assertFalse(changed)
        self.assertEqual(repeated, body)

    def test_incremental_websocket_turn_inherits_mode_and_new_selection(self) -> None:
        context = ModelRewriteContext()
        daemon.rewrite_model_body(
            json.dumps({"input": [control("high"), {"role": "user", "content": "first"}]}).encode(),
            model="gpt-6-astra",
            reasoning_effort="low",
            context=context,
        )
        payload = {
            "type": "response.create",
            "response": {
                "previous_response_id": "response-1",
                "reasoning": {"effort": "medium"},
                "input": [{"type": "function_call_output", "call_id": "tool-1", "output": "done"}],
            },
        }
        result, _, _, _ = daemon.rewrite_model_websocket_message(
            1,
            json.dumps(payload).encode(),
            model="gpt-6-astra",
            reasoning_effort="max",
            context=context,
        )
        value = json.loads(result)["response"]
        self.assertEqual(value["input"][-1], control("max"))
        self.assertEqual(value["input"][0], payload["response"]["input"][0])
        self.assertEqual(value["reasoning"]["effort"], "medium")
        legacy, _ = context.rewrite(
            {"input": "new conversation"}, model="gpt-6-astra", reasoning_effort="low"
        )
        self.assertEqual(legacy["input"], "new conversation")
        self.assertEqual(legacy["reasoning"]["effort"], "low")

    def test_incompatible_models_tiers_and_compaction_use_request_effort(self) -> None:
        for model, compact, tier in [
            ("gpt-5.6-sol", False, "default"),
            ("gpt-6-astra", True, "default"),
            ("gpt-6-astra", False, "priority"),
        ]:
            with self.subTest(model=model, compact=compact, tier=tier):
                source = {
                    "input": [control("high"), {"role": "user", "content": "question"}],
                    "service_tier": tier,
                    "reasoning": {"effort": "high", "summary": "auto"},
                }
                result, _ = ModelRewriteContext().rewrite(
                    source, model=model, reasoning_effort="low", compact=compact
                )
                self.assertEqual(result["input"], source["input"][1:])
                self.assertEqual(result["reasoning"], {"effort": "low", "summary": "auto"})

    def test_malformed_and_non_response_messages_are_unchanged(self) -> None:
        for opcode, message in [(2, b"binary"), (1, b"bad-json"), (1, b'{"type":"ping"}')]:
            result, _, _, changed = daemon.rewrite_model_websocket_message(
                opcode, message, model="gpt-6-astra", reasoning_effort="low"
            )
            self.assertFalse(changed)
            self.assertEqual(result, message)


class QuotaCompatibilityTests(unittest.TestCase):
    def test_permission_overrides_percentages_and_reset_in_every_presentation(self) -> None:
        for allowed, label in [(False, "Included usage blocked"), (None, "Availability unknown")]:
            with self.subTest(allowed=allowed):
                payload = daemon.usage_payload_from_app_server_rate_limits_response(
                    {
                        "ordinaryUsageAllowed": allowed,
                        "rateLimits": {
                            "limitId": "codex",
                            "primary": {"usedPercent": 0, "windowDurationMins": 300, "resetsAt": 1},
                        },
                    }
                )
                self.assertIs(payload["ordinary_usage_allowed"], allowed)
                bucket = daemon.quota_bucket_rows(payload)[0]
                self.assertEqual(daemon.quota_bucket_state(bucket["rate_limit"])[0], label)
                self.assertIn(label, daemon.usage_cache_summary({"payload": payload}))
                self.assertIn(label, daemon.render_quota_html({"payload": payload}))
                self.assertIn(label, daemon.render_compact_quota_html({"payload": payload}))
                self.assertIn(label, daemon.quota_bucket_payload(bucket)["stack"]["aria"])

    def test_only_explicit_permission_recovers_or_clears_known_state(self) -> None:
        blocked = {"ordinary_usage_allowed": False}
        percentages = {"rate_limit": {"primary_window": {"used_percent": 0, "reset_at": 1}}}
        merged = daemon.merge_usage_payload(blocked, percentages)
        self.assertIs(merged["ordinary_usage_allowed"], False)
        unknown = daemon.merge_usage_payload(merged, {"ordinary_usage_allowed": None})
        self.assertIsNone(unknown["ordinary_usage_allowed"])
        recovered = daemon.merge_usage_payload(unknown, {"ordinary_usage_allowed": True})
        self.assertIs(recovered["ordinary_usage_allowed"], True)
        legacy = daemon.usage_payload_from_app_server_rate_limits_response(
            {"rateLimits": {"primary": {"usedPercent": 20}}}
        )
        self.assertNotIn("ordinary_usage_allowed", legacy)

    def test_alias_metadata_does_not_substitute_reserve_for_normal_luna(self) -> None:
        payload = daemon.usage_payload_from_app_server_rate_limits_response(
            {
                "ordinaryUsageAllowed": False,
                "rateLimitsByLimitId": {
                    "gpt-5.6-luna-reserve": {
                        "normalModelSlug": "gpt-5.6-luna",
                        "primary": {"usedPercent": 10},
                    }
                },
            }
        )
        buckets = daemon.quota_bucket_rows(payload)
        alias = buckets[1]
        self.assertEqual(alias["normal_model_slug"], "gpt-5.6-luna")
        self.assertIn("separate quota bucket", daemon.quota_bucket_payload(alias)["title"])
        self.assertFalse(daemon.quota_bucket_matches_model(alias, "gpt-5.6-luna"))
        self.assertEqual(
            daemon.quota_bucket_for_model_from_rows(buckets, "gpt-5.6-luna")["metered_feature"],
            "codex",
        )


class ServerCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.paths = Paths(self.root / "home")
        self.source = self.root / "auth.json"
        self.store = Store(self.paths)
        self.replace_auth("first")
        self.server = daemon.ProvisionServer(("127.0.0.1", 0), self.paths)
        self.addCleanup(self.server.server_close)

    def replace_auth(self, owner: str, profile: str = "default") -> None:
        self.source.write_text(json.dumps({"OPENAI_API_KEY": "fake-" + owner}))
        self.store.import_auth_file(profile, self.source, overwrite=True)

    def test_worktree_keeps_launcher_identity_pin_and_control_across_heartbeats(self) -> None:
        server = self.server
        key = "launcher-session"
        server.observe_session_locked(
            key, "/repo", "default", launcher_pid=111, control_path="/pty", pty_managed=True
        )
        server.pin_session(key, "default")
        handler = daemon.Handler.__new__(daemon.Handler)
        handler.server = server
        handler.headers = {
            "openai-project": daemon.project_session_sentinel(
                server.proxy_token, "/repo", session_key=key
            )
        }
        session = handler.request_session(json.dumps(request("/worktree")).encode())
        self.assertEqual(session, {"key": key, "cwd": "/worktree"})
        server.observe_session_locked(key, session["cwd"], "default", runtime_cwd=True)
        server.observe_session_locked(
            key, "/repo", "default", launcher_pid=111, control_path="/pty", pty_managed=True
        )
        self.assertEqual(handler.request_session()["cwd"], "/worktree")
        self.assertEqual(server.observed_sessions[key]["cwd"], "/worktree")
        self.assertEqual(server.observed_sessions[key]["control_path"], "/pty")
        self.assertEqual(server.pinned_profile_for_session(key), "default")
        server.active_websockets[1] = {"session_key": key, "profile": "default"}
        server.attach_websocket_session(1, "/second-worktree", "/second-worktree")
        self.assertEqual(server.active_websockets[1]["session_key"], key)
        self.assertEqual(list(server.observed_sessions), [key])
        self.assertEqual(server.observed_sessions[key]["cwd"], "/second-worktree")
        server.observe_session_locked(key, "/repo", "default", launcher_pid=222)
        self.assertEqual(server.observed_sessions[key]["cwd"], "/repo")

    def test_worktree_retains_native_history_from_original_and_current_directory(self) -> None:
        home = self.root / "codex"
        sessions = home / "sessions"
        sessions.mkdir(parents=True)
        for number, cwd in enumerate(("/repo", "/worktree")):
            rows = [
                {
                    "type": "session_meta",
                    "payload": {
                        "id": f"thread-{number}",
                        "cwd": cwd,
                        "timestamp": "2026-09-21T10:00:00Z",
                    },
                },
                {
                    "type": "response_item",
                    "timestamp": f"2026-09-21T10:0{number}:00Z",
                    "payload": {
                        "type": "message",
                        "role": "user",
                        "content": [
                            {"type": "input_text", "text": f"A useful historical prompt {number}"}
                        ],
                    },
                },
            ]
            (sessions / f"rollout-{number}.jsonl").write_text(
                "\n".join(json.dumps(row) for row in rows) + "\n"
            )
        server = self.server
        server.observe_session_locked("launcher", "/repo", "default")
        server.observe_session_locked("launcher", "/worktree", "default", runtime_cwd=True)
        with patch.object(daemon, "default_codex_home", return_value=home):
            turns = server.history_turn_index_for_session("launcher")
            self.assertEqual(len(turns), 2)
            self.assertEqual(
                {item["id"] for item in server.resume_candidates_for_session("launcher")},
                {"thread-0", "thread-1"},
            )
            for turn in turns:
                payload = server.history_turn_payload_for_session("launcher", turn["key"])
                self.assertEqual(payload["session_key"], "launcher")
                self.assertTrue(payload["transcript"])

    def test_http_turn_metadata_header_is_runtime_cwd_and_thread(self) -> None:
        handler = daemon.Handler.__new__(daemon.Handler)
        handler.server = self.server
        metadata = json.dumps({"cwd": "/worktree", "thread_id": "thread-2"})
        handler.headers = {
            "openai-project": daemon.project_session_sentinel(
                self.server.proxy_token, "/repo", session_key="launcher-session"
            ),
            "x-codex-turn-metadata": metadata,
        }
        self.assertEqual(handler.request_session(), {"key": "launcher-session", "cwd": "/worktree"})
        self.assertEqual(daemon.request_thread_id(None, metadata), "thread-2")

    def test_model_contexts_isolate_threads_profiles_and_unmanaged_requests(self) -> None:
        server = self.server
        first = server.model_rewrite_context("default", "session", "thread-1")
        self.assertIs(first, server.model_rewrite_context("default", "session", "thread-1"))
        self.assertIsNot(first, server.model_rewrite_context("default", "session", "thread-2"))
        self.assertIsNot(first, server.model_rewrite_context("other", "session", "thread-1"))
        self.replace_auth("new-model-owner")
        self.assertIsNot(first, server.model_rewrite_context("default", "session", "thread-1"))
        self.assertIsNot(
            server.model_rewrite_context("default", None),
            server.model_rewrite_context("default", None),
        )

    def test_reauthentication_invalidates_all_account_caches_without_leaking_owner(self) -> None:
        self.replace_auth("other", "other")
        caches = [
            self.server.usage_cache,
            self.server.app_server_rate_limit_cache,
            self.server.app_server_model_catalog_cache,
        ]
        for cache in caches:
            cache["default"] = {"payload": {"ordinary_usage_allowed": False}}
            cache["other"] = {"kept": True}
        self.assertEqual(set(self.server.usage_cache_snapshot("default")), {"payload"})
        self.replace_auth("second")
        for cache in caches:
            self.assertIsNone(cache.get("default"))
            self.assertEqual(cache.get("other"), {"kept": True})
        self.assertIsNone(self.server.usage_cache_snapshot("default"))

    def test_delayed_model_and_quota_reads_cannot_populate_replaced_profile(self) -> None:
        for kind in ("models", "quota"):
            with self.subTest(kind=kind):
                started, resume = threading.Event(), threading.Event()

                def delayed(*args, **kwargs):
                    started.set()
                    self.assertTrue(resume.wait(3))
                    return (
                        {"models": [{"id": "old-account-model"}]}
                        if kind == "models"
                        else {"ordinary_usage_allowed": False}
                    )

                method = (
                    "run_app_server_for_profile"
                    if kind == "models"
                    else "read_app_server_rate_limit_payload_for_profile"
                )
                target = (
                    self.server.refresh_profile_model_catalog
                    if kind == "models"
                    else self.server.refresh_app_server_rate_limit_payload
                )
                with patch.object(self.server, method, side_effect=delayed):
                    worker = threading.Thread(target=target, args=("default",))
                    worker.start()
                    self.assertTrue(started.wait(3))
                    self.replace_auth(kind)
                    resume.set()
                    worker.join(3)
                self.assertFalse(worker.is_alive())
                cache = (
                    self.server.app_server_model_catalog_cache
                    if kind == "models"
                    else self.server.app_server_rate_limit_cache
                )
                self.assertIsNone(cache.get("default"))
                self.assertIsNone(self.server.usage_cache_snapshot("default"))

    def test_usage_fetch_and_late_observation_cannot_cross_credential_generation(self) -> None:
        owner = self.server.profile_auth_revision("default")

        def fetch():
            self.replace_auth("replacement")
            return {"ordinary_usage_allowed": True}

        with self.assertRaisesRegex(StoreError, "credentials changed"):
            self.server.cached_usage_payload("default", fetch)
        self.assertFalse(
            self.server.update_usage_cache_from_observation(
                "default",
                {"ordinary_usage_allowed": False},
                source="late-websocket",
                auth_owner=owner,
            )
        )
        self.assertIsNone(self.server.usage_cache_snapshot("default"))

    def test_delayed_usage_error_does_not_mark_replacement_account_for_login(self) -> None:
        def fetch():
            self.replace_auth("new-login")
            raise daemon.AuthError("refresh_token_reused")

        with self.assertRaisesRegex(StoreError, "credentials changed"):
            self.server.cached_usage_payload("default", fetch)
        self.assertFalse(self.server.profile_login_required("default")["required"])

    def test_percentage_fetch_does_not_clear_backend_denial(self) -> None:
        self.server.usage_cache["default"] = {
            "payload": {"ordinary_usage_allowed": False},
            "fetched_monotonic": 0,
        }
        with patch.object(self.server, "schedule_app_server_rate_limit_refresh"):
            payload, _, _ = self.server.cached_usage_payload(
                "default", lambda: {"rate_limit": {"allowed": True}}
            )
        self.assertIs(payload["ordinary_usage_allowed"], False)

    def test_temporary_app_server_credentials_cannot_overwrite_new_login(self) -> None:
        class Client:
            def __init__(self, *, env):
                self.home = Path(env["CODEX_HOME"])

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        def callback(client):
            self.replace_auth("new-login")
            (client.home / "auth.json").write_text(json.dumps({"OPENAI_API_KEY": "stale-refresh"}))
            return {"models": []}

        with (
            patch.object(daemon, "CodexAppServerClient", Client),
            self.assertRaisesRegex(StoreError, "credentials changed"),
        ):
            self.server.run_app_server_for_profile("default", callback)
        self.assertEqual(
            json.loads(self.store.auth_path("default").read_text())["OPENAI_API_KEY"],
            "fake-new-login",
        )

    def test_websocket_relay_keeps_incremental_reasoning_without_repeated_metadata(self) -> None:
        client, downstream = socket.socketpair()
        upstream, backend = socket.socketpair()
        for sock in (client, downstream, upstream, backend):
            self.addCleanup(sock.close)
        backend.settimeout(2)
        handler = daemon.Handler.__new__(daemon.Handler)
        handler.server = self.server
        handler.connection = downstream
        handler.log_message = lambda *_args: None
        self.server.profile_settings["default"] = {
            "model": "gpt-6-astra",
            "reasoning_effort": "low",
            "fast": False,
        }
        tunnel = self.server.begin_websocket("default", downstream, None)
        worker = threading.Thread(
            target=handler.relay_websocket, args=(upstream, tunnel, "default")
        )
        worker.start()
        tracker = daemon.WebSocketMessageTracker()

        def send(value):
            client.sendall(
                daemon.encode_websocket_frame(1, json.dumps(value).encode(), masked=True)
            )
            while True:
                messages = tracker.feed(backend.recv(65536))
                if messages:
                    return json.loads(messages[0][1])

        try:
            first = send(
                request(
                    "/worktree",
                    type="response.create",
                    input=[control("high"), {"role": "user", "content": "first"}],
                )
            )
            self.assertEqual(first["input"][-2], control("low"))
            self.server.profile_settings["default"]["reasoning_effort"] = "max"
            second = send(
                {
                    "type": "response.create",
                    "previous_response_id": "response-1",
                    "input": [
                        {"type": "function_call_output", "call_id": "tool-1", "output": "done"}
                    ],
                }
            )
            self.assertEqual(second["input"][-1], control("max"))
            self.assertEqual(self.server.active_websockets[tunnel]["session_key"], "/worktree")
        finally:
            client.shutdown(socket.SHUT_RDWR)
            backend.shutdown(socket.SHUT_RDWR)
            worker.join(3)
            self.server.end_websocket(tunnel)
        self.assertFalse(worker.is_alive())

    def test_streaming_compaction_forwards_first_event_before_upstream_finishes(self) -> None:
        finish, upstream_finished = threading.Event(), threading.Event()
        first = b'data: {"type":"progress"}\n\n'

        class Upstream(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("content-length", "0")))
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("connection", "close")
                self.end_headers()
                self.wfile.write(first)
                self.wfile.flush()
                finish.wait(4)
                self.wfile.write(b"data: [DONE]\n\n")
                upstream_finished.set()

            def log_message(self, *_args):
                pass

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        proxy_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        upstream_thread.start()
        proxy_thread.start()
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        try:
            with patch.object(
                daemon, "upstream_base_url", return_value=f"http://127.0.0.1:{upstream.server_port}"
            ):
                connection.request(
                    "POST",
                    "/v1/responses/compact",
                    json.dumps({"model": "gpt-6-astra", "input": []}),
                    headers={
                        "authorization": "Bearer " + self.server.proxy_token,
                        "content-type": "application/json",
                    },
                )
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(len(first)), first)
                self.assertFalse(upstream_finished.is_set())
                finish.set()
                self.assertIn(b"[DONE]", response.read())
        finally:
            finish.set()
            connection.close()
            self.server.shutdown()
            upstream.shutdown()
            upstream.server_close()
            proxy_thread.join(3)
            upstream_thread.join(3)


if __name__ == "__main__":
    unittest.main()
