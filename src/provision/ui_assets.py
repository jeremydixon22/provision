"""Packaged dashboard presentation assets.

The daemon owns data and control behavior; HTML, CSS, and JavaScript live in
normal frontend files so they can be reviewed and edited independently.
"""

from __future__ import annotations

import functools
import importlib.resources as package_resources

UI_ASSETS: dict[str, tuple[str, str]] = {
    "/assets/provision-ui.css": ("ui/styles.css", "text/css; charset=utf-8"),
    "/assets/provision-ui.js": ("ui/app.js", "text/javascript; charset=utf-8"),
}

LOGO_ASSETS = frozenset({"provision.png", "provision-wordmark.png"})


@functools.lru_cache(maxsize=1)
def dashboard_template() -> str:
    return (
        package_resources.files("provision").joinpath("ui/index.html").read_text(encoding="utf-8")
    )


@functools.lru_cache(maxsize=len(UI_ASSETS))
def ui_asset(path: str) -> tuple[bytes, str] | None:
    spec = UI_ASSETS.get(path)
    if spec is None:
        return None
    resource, content_type = spec
    try:
        payload = package_resources.files("provision").joinpath(resource).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return None
    return payload, content_type


@functools.lru_cache(maxsize=len(LOGO_ASSETS))
def logo_asset_bytes(name: str = "provision.png") -> bytes | None:
    if name not in LOGO_ASSETS:
        return None
    try:
        return package_resources.files("provision").joinpath(f"assets/{name}").read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return None
