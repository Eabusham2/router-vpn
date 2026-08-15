#!/usr/bin/env python3
"""Final authenticated Setup Center composition: admin + guide + device UX + AI + release status."""
from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
FORWARDING_EXTENSION_BASE = "http://127.0.0.1:8791"
FORWARDING_EXTENSION_PREFIX = "/api/admin/forwarding-extension"


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_ai = _load("routervpn_setup_center_ai_composition", "setup-center-ai-server.py")
_release = _load("routervpn_setup_center_release_status", "setup_center_release_status.py")
_verified = _load("routervpn_setup_center_verified_onboarding", "setup_center_verified_onboarding.py")


class Handler(_ai.Handler):
    def _inject_product_ui(self, text: str) -> str:
        # Repair only known stale generated-page copy before layering the mature
        # admin/guide/device/AI product surfaces on top of it.
        enriched = _verified.reconcile_setup_text(text)
        enriched = super()._inject_product_ui(enriched)
        if 'data-tab="release-status"' not in enriched:
            enriched = self._before_body(enriched, _release.RELEASE_PANEL)
        if 'id="rvpn-verified-onboarding"' not in enriched:
            enriched = self._before_body(enriched, _verified.VERIFIED_ONBOARDING_PANEL)
        return enriched

    def _proxy_forwarding_extension(self, method: str) -> bool:
        path = urlparse(self.path).path
        if not (path == FORWARDING_EXTENSION_PREFIX or path.startswith(FORWARDING_EXTENSION_PREFIX + "/")):
            return False
        if not self._require_auth():
            return True
        self._proxy_admin(FORWARDING_EXTENSION_BASE, path, method)
        return True

    def do_GET(self) -> None:
        if self._proxy_forwarding_extension("GET"):
            return
        if urlparse(self.path).path == "/api/release-status":
            if not self._require_auth():
                return
            self._send_ai_json(200, _release.release_status(Path(self.server.base_dir)))
            return
        super().do_GET()

    def do_POST(self) -> None:
        if self._proxy_forwarding_extension("POST"):
            return
        super().do_POST()

    def do_PUT(self) -> None:
        if self._proxy_forwarding_extension("PUT"):
            return
        super().do_PUT()

    def do_DELETE(self) -> None:
        if self._proxy_forwarding_extension("DELETE"):
            return
        super().do_DELETE()


class Server(_ai.Server):
    pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/opt/router-vpn")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8786)
    args = ap.parse_args()
    base = Path(args.base).resolve()
    static = base / "downloads"
    static.mkdir(parents=True, exist_ok=True)
    _ai._core._broker.cleanup_stale_temp()
    server = Server((args.bind, args.port), Handler, base, static)
    print(
        f"Router VPN Setup Center on {args.bind}:{args.port}; authenticated admin/downloads + Full Guide + verified onboarding + device UX + forwarding ownership/Protected DMZ + release/recovery status + server-side AI Help",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
