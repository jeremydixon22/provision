#!/usr/bin/env python3
from __future__ import annotations

import argparse
import functools
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from provision.daemon import (  # noqa: E402
    DEFAULT_MODEL_CATALOG,
    Handler,
    compact_session_path,
    logo_asset_bytes,
    normalize_session_key,
    session_display_name,
)


class DemoStore:
    def __init__(self) -> None:
        self._active = "work"
        self._profiles = [
            {
                "name": "work",
                "email": "dev@example.test",
                "plan_type": "Plus",
                "active": True,
            },
            {
                "name": "research",
                "email": "research@example.test",
                "plan_type": "Pro",
                "active": False,
            },
            {
                "name": "sandbox",
                "email": "sandbox@example.test",
                "plan_type": "Team",
                "active": False,
            },
        ]

    def active_profile(self, *, required: bool = True) -> str | None:
        return self._active

    def list_profiles(self) -> list[dict[str, Any]]:
        return [dict(profile) for profile in self._profiles]

    def profile_names(self) -> list[str]:
        return [str(profile["name"]) for profile in self._profiles]

    def profile_exists(self, name: str) -> bool:
        return name in self.profile_names()


class DemoServer:
    def __init__(self) -> None:
        self.proxy_token = "demo-token"
        self.server_address = ("127.0.0.1", 4888)
        self.store = DemoStore()
        now = time.monotonic()
        self.sessions = self._session_rows(now)
        self.requests = [
            {
                "profile": "research",
                "session_key": normalize_session_key("/workspace/client-app"),
            }
        ]
        self.websockets = [
            {
                "profile": "work",
                "session_key": normalize_session_key("/workspace/provision"),
                "pending_work": 1,
                "last_data_activity_monotonic": now - 3,
            },
            {
                "profile": "research",
                "session_key": normalize_session_key("/workspace/client-app"),
                "pending_work": 0,
                "last_data_activity_monotonic": now - 7,
            },
        ]
        self.usage_cache = self._usage_cache()

    def _session_rows(self, now: float) -> list[dict[str, Any]]:
        rows = [
            ("/workspace/provision", "work", "work", True, 0, 1, 1, 1),
            ("/workspace/client-app", "research", "research", True, 1, 1, 0, 1),
            ("/workspace/notes-cli", "work", "", False, 0, 0, 0, 0),
        ]
        sessions: list[dict[str, Any]] = []
        for index, (
            cwd,
            last_profile,
            pinned_profile,
            active,
            requests,
            tunnels,
            pending,
            recent,
        ) in enumerate(rows):
            key = normalize_session_key(cwd)
            sessions.append(
                {
                    "key": key,
                    "cwd": cwd,
                    "display": compact_session_path(cwd),
                    "name": session_display_name(cwd),
                    "last_profile": last_profile,
                    "pinned_profile": pinned_profile,
                    "active_requests": requests,
                    "active_tunnels": tunnels,
                    "pending_websocket_work": pending,
                    "recent_websocket_activity": recent,
                    "active": active,
                    "last_seen_monotonic": now - index,
                }
            )
        return sessions

    def _usage_cache(self) -> dict[str, dict[str, Any]]:
        fetched_at = datetime.now().astimezone().replace(second=0, microsecond=0) - timedelta(minutes=4)
        return {
            "work": {
                "payload": usage_payload(
                    primary_remaining=63,
                    weekly_remaining=82,
                    primary_reset_seconds=7_200,
                    weekly_reset_seconds=390_000,
                    reset_credits=2,
                    additional=[
                        additional_limit(
                            "GPT-5.3-Codex-Spark",
                            "gpt-5.3-codex-spark",
                            primary_remaining=88,
                            weekly_remaining=46,
                            primary_reset_seconds=5_500,
                            weekly_reset_seconds=212_000,
                        )
                    ],
                ),
                "fetched_at": fetched_at,
                "fetched_monotonic": time.monotonic(),
                "error": None,
            },
            "research": {
                "payload": usage_payload(
                    primary_remaining=72,
                    weekly_remaining=55,
                    primary_reset_seconds=10_800,
                    weekly_reset_seconds=515_000,
                ),
                "fetched_at": fetched_at - timedelta(minutes=11),
                "fetched_monotonic": time.monotonic(),
                "error": None,
            },
            "sandbox": {
                "payload": usage_payload(
                    primary_remaining=18,
                    weekly_remaining=39,
                    primary_reset_seconds=3_600,
                    weekly_reset_seconds=88_000,
                ),
                "fetched_at": fetched_at - timedelta(minutes=17),
                "fetched_monotonic": time.monotonic(),
                "error": None,
            },
        }

    def session_pinned_locked(self, session_key: str | None) -> bool:
        return any(
            session.get("key") == session_key and session.get("pinned_profile")
            for session in self.sessions
        )

    def request_count(self, *, blocking_only: bool = False) -> int:
        return sum(
            1
            for request in self.requests
            if not blocking_only or not self.session_pinned_locked(request.get("session_key"))
        )

    def websocket_count(self, *, blocking_only: bool = False) -> int:
        return sum(
            1
            for websocket in self.websockets
            if not blocking_only or not self.session_pinned_locked(websocket.get("session_key"))
        )

    def pending_websocket_work_count(self, *, blocking_only: bool = False) -> int:
        return sum(
            1
            for websocket in self.websockets
            if int(websocket.get("pending_work") or 0) > 0
            and (not blocking_only or not self.session_pinned_locked(websocket.get("session_key")))
        )

    def active_websocket_work_count(self, *, blocking_only: bool = False) -> int:
        return self.pending_websocket_work_count(blocking_only=blocking_only)

    def recent_websocket_data_activity_count(
        self,
        seconds: float = 10.0,
        *,
        blocking_only: bool = False,
    ) -> int:
        now = time.monotonic()
        return sum(
            1
            for websocket in self.websockets
            if now - float(websocket.get("last_data_activity_monotonic") or 0.0) < seconds
            and (not blocking_only or not self.session_pinned_locked(websocket.get("session_key")))
        )

    def switch_block_reason(self) -> str | None:
        return None

    def session_snapshots(self) -> list[dict[str, Any]]:
        return [dict(session) for session in self.sessions]

    def control_plane_sessions(self, session_rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        session_rows = self.sessions if session_rows is None else session_rows
        sessions: list[dict[str, Any]] = []
        for session in session_rows:
            key = str(session.get("key") or "")
            transcript = [
                {
                    "ts": (datetime.now() - timedelta(minutes=12)).isoformat(),
                    "updated_at": (datetime.now() - timedelta(minutes=12)).isoformat(),
                    "role": "user",
                    "text": "Tighten the release notes and verify the quota dashboard behavior.",
                    "turn_id": "turn_demo",
                    "profile": session.get("last_profile") or "work",
                    "search_text": "user release notes quota dashboard",
                },
                {
                    "ts": (datetime.now() - timedelta(minutes=10)).isoformat(),
                    "updated_at": (datetime.now() - timedelta(minutes=10)).isoformat(),
                    "role": "tool",
                    "text": "Command: python3 tools/render_demo_assets.py (status completed, exit 0)\nStdout:\nRendered sanitized dashboard media.",
                    "turn_id": "turn_demo",
                    "profile": session.get("last_profile") or "work",
                    "search_text": "tool render demo assets",
                    "call_id": "call_demo",
                },
                {
                    "ts": (datetime.now() - timedelta(minutes=8)).isoformat(),
                    "updated_at": (datetime.now() - timedelta(minutes=8)).isoformat(),
                    "role": "assistant",
                    "text": "I updated the release copy, checked the dashboard layout, and confirmed the active session indicators remain visible.",
                    "turn_id": "turn_demo",
                    "profile": session.get("last_profile") or "work",
                    "search_text": "assistant updated release copy dashboard active session indicators",
                },
            ]
            for transcript_index, item in enumerate(transcript):
                item["control_index"] = transcript_index
            active_details = {
                "requests": [
                    {
                        "profile": request.get("profile"),
                        "age_seconds": 18.4,
                    }
                    for request in self.requests
                    if request.get("session_key") == key
                ],
                "tunnels": [
                    {
                        "profile": tunnel.get("profile"),
                        "pending_work": tunnel.get("pending_work"),
                        "turn_id": "turn_demo" if tunnel.get("pending_work") else "",
                        "service_tier": "priority" if tunnel.get("profile") == "work" else "default",
                        "age_seconds": 94.2,
                        "last_data_age_seconds": 3.0,
                        "bytes_up": 12432,
                        "bytes_down": 105884,
                        "messages_up": 17,
                        "messages_down": 42,
                    }
                    for tunnel in self.websockets
                    if tunnel.get("session_key") == key
                ],
            }
            turn = {
                "key": "turn_demo",
                "turn_id": "turn_demo",
                "pending": bool(session.get("pending_websocket_work")),
                "start_index": 0,
                "end_index": len(transcript) - 1,
                "timestamp": transcript[0]["ts"],
                "updated_at": transcript[-1]["updated_at"],
                "label": "Tighten the release notes and verify the quota dashboard behavior.",
            }
            sessions.append(
                dict(
                    session,
                    title=session.get("title") or session.get("name"),
                    active_details=active_details,
                    transcript=transcript,
                    turns=[turn],
                    events=[
                        {
                            "ts": (datetime.now() - timedelta(minutes=9)).isoformat(),
                            "type": "token_usage",
                            "profile": session.get("last_profile") or "work",
                            "fast": session.get("last_profile") == "work",
                            "tokens": 43120,
                            "summary": "Token usage: 43,120 total (39,400 in, 3,720 out)",
                            "search_text": "token usage codex cli session",
                        },
                        {
                            "ts": (datetime.now() - timedelta(minutes=2)).isoformat(),
                            "type": "websocket_tunnel",
                            "profile": session.get("last_profile") or "work",
                            "fast": False,
                            "bytes": 118316,
                            "summary": "Tunnel closed: 118316 bytes, 59 messages",
                            "search_text": "websocket tunnel closed",
                        },
                    ],
                )
            )
        return {
            "sessions": sessions,
            "event_limit": 32,
            "updated_at": datetime.now().isoformat(),
            "interaction": {
                "available": False,
                "reason": "Launch or resume a Codex CLI session with `provision` in an interactive terminal to enable live UI input.",
            },
        }

    def usage_cache_snapshot(self, profile: str) -> dict[str, Any] | None:
        entry = self.usage_cache.get(profile)
        return dict(entry) if entry else None

    def reset_credit_status(self, profile: str) -> dict[str, Any]:
        return {}

    def profile_billing_required(self, profile: str) -> dict[str, Any]:
        return {"required": False, "error": "", "error_at": ""}

    def profile_fast_mode(self, profile: str) -> bool:
        return profile == "work"

    def profile_model_setting(self, profile: str) -> dict[str, Any]:
        model = "gpt-5.5" if profile == "work" else "gpt-5.4"
        reasoning = "high" if profile == "work" else "medium"
        return {
            "model": model,
            "reasoning_effort": reasoning,
            "label": f"{model} {reasoning}",
            "display": model,
            "source": "profile",
            "note": "",
        }

    def profile_model_catalog_snapshot(self, profile: str) -> dict[str, Any]:
        return {
            "catalog": [dict(item) for item in DEFAULT_MODEL_CATALOG],
            "source": "demo",
            "available": True,
            "loading": False,
            "error": "",
            "updated_at": datetime.now().isoformat(),
        }

    def profile_login_required(self, profile: str) -> dict[str, Any]:
        return {"required": profile == "sandbox", "error": "Refresh login required.", "error_at": ""}

    def profile_auth_health(self, profile: str) -> dict[str, Any]:
        if profile == "sandbox":
            return {
                "status": "login_required",
                "message": "Refresh login required.",
                "error_at": "",
                "last_refresh": "",
                "last_refresh_failed_at": "",
            }
        return {
            "status": "ok",
            "message": "Auth refresh succeeded.",
            "last_refresh": datetime.now().isoformat(),
            "last_refresh_failed_at": "",
        }

    def login_status(self, profile: str) -> dict[str, Any] | None:
        return None

    def stats_summary(self) -> dict[str, Any]:
        now = datetime.now()
        return {
            "profiles": [
                {
                    "profile": "work",
                    "requests": 12,
                    "tunnels": 8,
                    "active_tunnels": 1,
                    "bytes_up": 420_000,
                    "bytes_down": 2_800_000,
                    "input_tokens": 280_000,
                    "cached_input_tokens": 31_000,
                    "output_tokens": 44_000,
                    "reasoning_output_tokens": 9_000,
                    "total_tokens": 324_000,
                    "fast_turns": 5,
                    "fast_tokens": 112_000,
                    "quota_updates": 4,
                    "last_event_at": now.isoformat(),
                    "last_quota": {},
                },
                {
                    "profile": "research",
                    "requests": 7,
                    "tunnels": 5,
                    "active_tunnels": 1,
                    "bytes_up": 180_000,
                    "bytes_down": 1_400_000,
                    "input_tokens": 140_000,
                    "cached_input_tokens": 18_000,
                    "output_tokens": 22_000,
                    "reasoning_output_tokens": 4_000,
                    "total_tokens": 162_000,
                    "fast_turns": 0,
                    "fast_tokens": 0,
                    "quota_updates": 3,
                    "last_event_at": (now - timedelta(minutes=11)).isoformat(),
                    "last_quota": {},
                },
            ],
            "recent": [],
            "series": [
                {
                    "ts": (now - timedelta(minutes=offset)).isoformat(),
                    "profile": profile,
                    "value": value,
                    "tokens": value,
                    "traffic": value * 4,
                    "requests": 1,
                    "quota_updates": 0,
                }
                for offset, profile, value in (
                    (40, "work", 40_000),
                    (30, "research", 22_000),
                    (20, "work", 95_000),
                    (10, "research", 62_000),
                    (2, "work", 160_000),
                )
            ],
        }

    def pinned_sessions_for_profile(
        self,
        profile: str,
        sessions: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        sessions = self.sessions if sessions is None else sessions
        return [
            dict(session)
            for session in sessions
            if session.get("pinned_profile") == profile
        ]

    def profile_has_active_sessions(self, profile: str, *, pinned_only: bool = False) -> bool:
        for request in self.requests:
            if request.get("profile") != profile:
                continue
            pinned = self.session_pinned_locked(request.get("session_key"))
            if not pinned_only or pinned:
                return True
        for websocket in self.websockets:
            if websocket.get("profile") != profile:
                continue
            pinned = self.session_pinned_locked(websocket.get("session_key"))
            if pinned_only and not pinned:
                continue
            if int(websocket.get("pending_work") or 0) > 0:
                return True
            if time.monotonic() - float(websocket.get("last_data_activity_monotonic") or 0.0) < 10:
                return True
        return False


def usage_payload(
    *,
    primary_remaining: float,
    weekly_remaining: float,
    primary_reset_seconds: int,
    weekly_reset_seconds: int,
    reset_credits: int = 0,
    additional: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload = {
        "rate_limit": {
            "primary_window": quota_window(primary_remaining, 18_000, primary_reset_seconds),
            "secondary_window": quota_window(weekly_remaining, 604_800, weekly_reset_seconds),
        }
    }
    if reset_credits:
        payload["rate_limit_reset_credits"] = {"available_count": reset_credits}
    if additional:
        payload["additional_rate_limits"] = additional
    return payload


def additional_limit(
    limit_name: str,
    metered_feature: str,
    *,
    primary_remaining: float,
    weekly_remaining: float,
    primary_reset_seconds: int,
    weekly_reset_seconds: int,
) -> dict[str, Any]:
    return {
        "limit_name": limit_name,
        "metered_feature": metered_feature,
        "rate_limit": {
            "primary_window": quota_window(primary_remaining, 18_000, primary_reset_seconds),
            "secondary_window": quota_window(weekly_remaining, 604_800, weekly_reset_seconds),
        },
    }


def quota_window(remaining_percent: float, window_seconds: int, reset_seconds: int) -> dict[str, Any]:
    return {
        "used_percent": max(0.0, min(100.0, 100.0 - remaining_percent)),
        "limit_window_seconds": window_seconds,
        "reset_after_seconds": reset_seconds,
    }


def render_demo_html() -> str:
    handler = Handler.__new__(Handler)
    handler.server = DemoServer()
    html = handler.render_ui()
    return html.replace("\n\t    connect();", "\n\t    // Demo page: the live daemon WebSocket is intentionally disabled.")


def write_demo_site(directory: Path) -> None:
    assets = directory / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    (directory / "index.html").write_text(render_demo_html(), encoding="utf-8")
    for name in ("provision.png", "provision-wordmark.png"):
        payload = logo_asset_bytes(name)
        if payload:
            (assets / name).write_bytes(payload)


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return


def serve(directory: Path) -> tuple[ThreadingHTTPServer, str]:
    handler = functools.partial(QuietHandler, directory=str(directory))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}/"


NODE_SCRIPT = r"""
const fs = require("fs");
const path = require("path");

let playwright;
try {
  playwright = require("playwright");
} catch {
  playwright = require("/usr/share/nodejs/playwright");
}

const outDir = process.env.DEMO_OUT_DIR;
const url = process.env.DEMO_URL;
const frameDir = process.env.DEMO_FRAME_DIR;
const browserPath = process.env.DEMO_CHROMIUM_EXECUTABLE || "";

async function newPage(browser, viewport, isMobile = false) {
  const context = await browser.newContext({
    viewport,
    deviceScaleFactor: 1,
    isMobile,
    colorScheme: "light"
  });
  await context.addInitScript(() => localStorage.setItem("provision-theme", "light"));
  const page = await context.newPage();
  await page.goto(url, { waitUntil: "load" });
  await page.waitForSelector("#profileRows .profile-row");
  await page.waitForTimeout(250);
  return { page, context };
}

(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  const launchOptions = browserPath ? { executablePath: browserPath } : {};
  const browser = await playwright.chromium.launch(launchOptions);

  let session = await newPage(browser, { width: 1440, height: 1000 });
  await session.page.screenshot({
    path: path.join(outDir, "provision-dashboard-desktop-light.png"),
    fullPage: true
  });
  await session.page.click("#sessionTabs .session-tab[data-session-key]");
  await session.page.waitForSelector("#controlModal:not([hidden])");
  await session.page.waitForTimeout(250);
  await session.page.mouse.move(960, 520);
  await session.page.waitForTimeout(150);
  await session.page.screenshot({
    path: path.join(outDir, "provision-control-plane-desktop-light.png"),
    fullPage: true
  });
  await session.context.close();

  session = await newPage(browser, { width: 390, height: 844 }, true);
  await session.page.screenshot({
    path: path.join(outDir, "provision-dashboard-mobile-light.png"),
    fullPage: true
  });
  await session.context.close();

  fs.mkdirSync(frameDir, { recursive: true });
  const videoContext = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    deviceScaleFactor: 1,
    colorScheme: "light"
  });
  await videoContext.addInitScript(() => localStorage.setItem("provision-theme", "light"));
  const videoPage = await videoContext.newPage();
  await videoPage.goto(url, { waitUntil: "load" });
  await videoPage.waitForSelector("#profileRows .profile-row");
  await videoPage.waitForTimeout(350);
  let frame = 0;
  for (; frame < 18; frame++) {
    await videoPage.screenshot({ path: path.join(frameDir, `frame-${String(frame).padStart(3, "0")}.png`) });
  }
  await videoPage.click("#themeToggle");
  await videoPage.waitForTimeout(350);
  for (; frame < 48; frame++) {
    await videoPage.screenshot({ path: path.join(frameDir, `frame-${String(frame).padStart(3, "0")}.png`) });
  }
  await videoPage.screenshot({
    path: path.join(outDir, "provision-dashboard-desktop-dark.png"),
    fullPage: true
  });
  await videoContext.close();

  await browser.close();
})();
"""


def render_assets(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="provision-demo-") as temp_root:
        site_dir = Path(temp_root) / "site"
        frame_dir = Path(temp_root) / "frames"
        site_dir.mkdir()
        frame_dir.mkdir()
        write_demo_site(site_dir)
        server, url = serve(site_dir)
        try:
            env = os.environ.copy()
            env["DEMO_URL"] = url
            env["DEMO_OUT_DIR"] = str(output_dir)
            env["DEMO_FRAME_DIR"] = str(frame_dir)
            env["DEMO_CHROMIUM_EXECUTABLE"] = chromium_executable()
            result = subprocess.run(
                ["node", "-e", NODE_SCRIPT],
                env=env,
                text=True,
                capture_output=True,
            )
            if result.returncode != 0 and not expected_capture_outputs_exist(output_dir, frame_dir):
                sys.stdout.write(result.stdout)
                sys.stderr.write(result.stderr)
                result.check_returncode()
            encode_video(frame_dir, output_dir / "provision-dashboard-theme-toggle.mp4")
        finally:
            server.shutdown()
            server.server_close()


def chromium_executable() -> str:
    for candidate in (
        os.environ.get("DEMO_CHROMIUM_EXECUTABLE"),
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
        "/usr/bin/chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
    ):
        if candidate and Path(candidate).exists():
            return candidate
    return ""


def expected_capture_outputs_exist(output_dir: Path, frame_dir: Path) -> bool:
    required = [
        output_dir / "provision-dashboard-desktop-light.png",
        output_dir / "provision-control-plane-desktop-light.png",
        output_dir / "provision-dashboard-mobile-light.png",
        output_dir / "provision-dashboard-desktop-dark.png",
    ]
    frames = sorted(frame_dir.glob("frame-*.png"))
    return all(path.exists() for path in required) and len(frames) >= 48


def encode_video(frame_dir: Path, output_path: Path) -> None:
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-framerate",
            "12",
            "-i",
            str(frame_dir / "frame-%03d.png"),
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            "-movflags",
            "+faststart",
            str(output_path),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Render sanitized Provision dashboard demo assets.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "docs" / "media",
        help="Directory for generated screenshots and video.",
    )
    args = parser.parse_args()
    render_assets(args.output_dir.resolve())
    for path in sorted(args.output_dir.glob("provision-*")):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
