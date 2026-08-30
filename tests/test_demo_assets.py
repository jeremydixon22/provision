from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path
from typing import Callable, cast


class DemoAssetTests(unittest.TestCase):
    def test_demo_site_includes_extracted_ui_assets_without_live_socket(self) -> None:
        root = Path(__file__).resolve().parents[1]
        module = runpy.run_path(str(root / "tools" / "render_demo_assets.py"))
        write_demo_site = cast(Callable[[Path], None], module["write_demo_site"])
        self.assertTrue(callable(write_demo_site))

        with tempfile.TemporaryDirectory() as temp:
            site = Path(temp)
            write_demo_site(site)
            markup = (site / "index.html").read_text(encoding="utf-8")
            script = (site / "assets" / "provision-ui.js").read_text(encoding="utf-8")

        self.assertIn('href="/assets/provision-ui.css"', markup)
        self.assertIn('src="/assets/provision-ui.js"', markup)
        self.assertIn("Claude", markup)
        self.assertIn("Grok", markup)
        self.assertIn("Discussion capture now shows the shell command", markup)
        self.assertIn("live daemon WebSocket is intentionally disabled", script)
        self.assertIn("Array.isArray(session && session.transcript)", script)
        self.assertNotIn("\n\t    connect();", script)


if __name__ == "__main__":
    unittest.main()
