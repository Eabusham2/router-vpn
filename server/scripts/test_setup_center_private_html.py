#!/usr/bin/env python3
from __future__ import annotations

from io import BytesIO
from importlib.util import module_from_spec, spec_from_file_location
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile

HERE = Path(__file__).resolve().parent
spec = spec_from_file_location("router_vpn_setup_center_private_html", HERE / "setup-center-server.py")
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load setup-center-server.py")
setup = module_from_spec(spec)
spec.loader.exec_module(setup)


class DummyHandler:
    def __init__(self, static_dir: Path):
        self.server = SimpleNamespace(static_dir=str(static_dir))
        self.wfile = BytesIO()
        self.status = None
        self.headers = {}
        self.error = None
        self.json_error = None

    def send_error(self, status):
        self.status = status
        self.error = status

    def _json(self, status, payload):
        self.status = status
        self.json_error = payload

    def send_response(self, status):
        self.status = status

    def send_header(self, name, value):
        self.headers[name.lower()] = value

    def end_headers(self):
        pass


def serve(root: Path, name: str = "index.html") -> DummyHandler:
    handler = DummyHandler(root)
    setup.Handler._serve_setup_html(handler, name)
    return handler


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-setup-html-") as td:
        root = Path(td)
        page = root / "index.html"
        page.write_text(
            '<!doctype html><html><body><div id="wizard" class="overlay"></div></body></html>',
            encoding="utf-8",
        )
        os.chmod(page, 0o600)
        ok = serve(root)
        assert ok.status == 200, ok.json_error
        rendered = ok.wfile.getvalue().decode("utf-8")
        assert 'data-tab="server-admin"' in rendered
        assert "RouterVPNSetupCenter" not in rendered
        assert ok.headers.get("content-type") == "text/html; charset=utf-8"

        page.unlink()
        missing = serve(root)
        assert missing.status == 404

        real = root / "real.html"
        real.write_text("<html><body>secret</body></html>", encoding="utf-8")
        os.chmod(real, 0o600)
        try:
            page.symlink_to(real)
        except OSError:
            pass
        else:
            linked = serve(root)
            assert linked.status == 500
            assert linked.json_error and linked.json_error.get("error_code") == "setup_ui_error"
            assert linked.wfile.getvalue() == b""
            page.unlink()

        page.write_text(
            '<!doctype html><html><body><div id="wizard" class="overlay"></div></body></html>',
            encoding="utf-8",
        )
        os.chmod(page, 0o644)
        broad = serve(root)
        assert broad.status == 500
        assert broad.json_error and broad.json_error.get("error_code") == "setup_ui_error"
        assert broad.wfile.getvalue() == b""

    print("Setup Center verified private HTML tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
