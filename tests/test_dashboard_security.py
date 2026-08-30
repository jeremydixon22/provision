from __future__ import annotations

import gzip
import unittest
from email.message import Message
from types import SimpleNamespace

from provision.daemon import UI_SESSION_COOKIE, Handler
from provision.ui_assets import dashboard_template, ui_asset


def bare_handler(*, origin: str = "http://127.0.0.1:4888") -> Handler:
    handler = object.__new__(Handler)
    handler.server = SimpleNamespace(
        proxy_token="durable-proxy-capability",
        ui_session_token="ephemeral-browser-session",
        server_address=("127.0.0.1", 4888),
    )
    handler.headers = Message()
    handler.headers["Host"] = "127.0.0.1:4888"
    handler.headers["Origin"] = origin
    handler.headers["Cookie"] = f"{UI_SESSION_COOKIE}=ephemeral-browser-session"
    return handler


class DashboardSecurityTests(unittest.TestCase):
    def test_dashboard_cookie_authorizes_same_origin_control_request(self) -> None:
        handler = bare_handler()

        self.assertTrue(handler.control_request_is_authorized({"token": ""}))

    def test_dashboard_cookie_rejects_cross_origin_control_request(self) -> None:
        handler = bare_handler(origin="https://attacker.invalid")

        self.assertFalse(handler.control_request_is_authorized({"token": ""}))

    def test_loopback_dashboard_rejects_dns_rebinding_host(self) -> None:
        handler = bare_handler(origin="http://attacker.invalid")
        handler.headers.replace_header("Host", "attacker.invalid")

        self.assertFalse(handler.request_host_is_allowed())
        self.assertFalse(handler.control_request_is_authorized({"token": ""}))

    def test_proxy_capability_remains_available_to_cli_clients(self) -> None:
        handler = bare_handler(origin="")

        self.assertTrue(
            handler.control_request_is_authorized({"token": "durable-proxy-capability"})
        )

    def test_rendered_dashboard_does_not_embed_proxy_capability(self) -> None:
        handler = bare_handler()
        handler.ui_status_payload = lambda **_kwargs: {
            "active_profile": "none",
            "default_provider": "codex",
            "active_requests": 0,
            "active_websockets": 0,
            "live_busy": False,
            "codex": {"cli": {"version": "test"}},
        }
        handler.render_profile_rows = lambda _status: ""

        rendered = handler.render_ui()

        self.assertNotIn("durable-proxy-capability", rendered)
        self.assertNotIn("__TOKEN__", rendered)
        self.assertNotIn('name="token"', rendered)

    def test_dashboard_response_issues_hardened_ephemeral_cookie(self) -> None:
        handler = bare_handler()
        response_headers: list[tuple[str, str]] = []
        body = bytearray()
        handler.send_response = lambda _status: None
        handler.send_header = lambda key, value: response_headers.append((key, value))
        handler.end_headers = lambda: None
        handler.write_downstream = body.extend

        handler.send_dashboard_html("<p>ready</p>")

        headers = {key.lower(): value for key, value in response_headers}
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertEqual(headers["x-frame-options"], "DENY")
        self.assertIn("HttpOnly", headers["set-cookie"])
        self.assertIn("SameSite=Strict", headers["set-cookie"])
        self.assertNotIn("durable-proxy-capability", headers["set-cookie"])
        self.assertEqual(bytes(body), b"<p>ready</p>")

    def test_dashboard_compresses_large_html_only_when_gzip_is_accepted(self) -> None:
        handler = bare_handler()
        handler.headers["Accept-Encoding"] = "br, gzip;q=0.8"
        response_headers: list[tuple[str, str]] = []
        body = bytearray()
        handler.send_response = lambda _status: None
        handler.send_header = lambda key, value: response_headers.append((key, value))
        handler.end_headers = lambda: None
        handler.write_downstream = body.extend

        html = "<main>" + ("discussion " * 500) + "</main>"
        handler.send_dashboard_html(html)

        headers = {key.lower(): value for key, value in response_headers}
        self.assertEqual(headers["content-encoding"], "gzip")
        self.assertEqual(headers["vary"], "accept-encoding")
        self.assertEqual(gzip.decompress(bytes(body)).decode("utf-8"), html)

    def test_large_ui_assets_use_gzip_when_the_browser_accepts_it(self) -> None:
        handler = bare_handler()
        handler.headers["Accept-Encoding"] = "gzip"
        response_headers: list[tuple[str, str]] = []
        body = bytearray()
        handler.send_response = lambda _status: None
        handler.send_header = lambda key, value: response_headers.append((key, value))
        handler.end_headers = lambda: None
        handler.write_downstream = body.extend

        handler.send_ui_asset("/assets/provision-ui.js")

        headers = {key.lower(): value for key, value in response_headers}
        self.assertEqual(headers["content-encoding"], "gzip")
        self.assertEqual(headers["vary"], "accept-encoding")
        self.assertIn("load_control_session", gzip.decompress(bytes(body)).decode("utf-8"))

    def test_dashboard_assets_are_packaged_separately(self) -> None:
        template = dashboard_template()
        stylesheet = ui_asset("/assets/provision-ui.css")
        script = ui_asset("/assets/provision-ui.js")

        self.assertIn('href="/assets/provision-ui.css"', template)
        self.assertIn('src="/assets/provision-ui.js"', template)
        self.assertIsNotNone(stylesheet)
        self.assertIsNotNone(script)
        assert stylesheet is not None
        assert script is not None
        self.assertEqual(stylesheet[1], "text/css; charset=utf-8")
        self.assertEqual(script[1], "text/javascript; charset=utf-8")
        self.assertIn('fetch("/api/ui-session"', script[0].decode("utf-8"))
        self.assertIn('id="permissionModal"', template)
        self.assertIn('id="controlPermissionsToggle"', template)
        self.assertIn('action: "resolve_permission"', script[0].decode("utf-8"))
        self.assertIn("function renderPermissionModal()", script[0].decode("utf-8"))
        self.assertIn(".permission-modal", stylesheet[0].decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
