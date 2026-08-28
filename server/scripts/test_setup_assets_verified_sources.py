#!/usr/bin/env python3
from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
import os
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent
spec = spec_from_file_location("router_vpn_setup_assets_verified_sources", HERE / "generate-setup-assets.py")
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load generate-setup-assets.py")
assets = module_from_spec(spec)
spec.loader.exec_module(assets)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-setup-assets-read-") as td:
        root = Path(td)
        private = root / "private.conf"
        private.write_text("secret-config\n", encoding="utf-8")
        os.chmod(private, 0o600)
        assert assets.read_text(private) == "secret-config\n"

        broad = root / "broad.conf"
        broad.write_text("must-not-leak\n", encoding="utf-8")
        os.chmod(broad, 0o644)
        assert assets.read_text(broad) == ""

        public = root / "modes.json"
        public.write_text('[{"id":"wg"}]\n', encoding="utf-8")
        os.chmod(public, 0o644)
        assert assets.read_json(public, private=False) == [{"id": "wg"}]
        assert assets.read_json(public) == {}

        real = root / "real.conf"
        real.write_text("symlink-secret\n", encoding="utf-8")
        os.chmod(real, 0o600)
        link = root / "link.conf"
        try:
            link.symlink_to(real)
        except OSError:
            pass
        else:
            assert assets.read_text(link) == ""

    source = (HERE / "generate-setup-assets.py").read_text(encoding="utf-8")
    assert 'read_verified_regular(path, private=private)' in source
    assert 'read_verified_regular(path, private=True)' in source
    assert '["openssl", "x509", "-inform", "PEM", "-outform", "DER"]' in source
    assert '"-in", str(path)' not in source
    print("Setup asset verified source read tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
