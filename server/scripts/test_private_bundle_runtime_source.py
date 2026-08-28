#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("router_vpn_build_download_runtime", HERE / "build-download-on-demand.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


def write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-private-runtime-source-") as td:
        root = Path(td)
        base = root / "state"
        bundle = base / "client-bundle"
        src = root / "exact-source"
        work = root / "work"
        work.mkdir()

        write(bundle / "routers.json", '{"selected_id":"home","profiles":[]}\n')
        write(bundle / "client.json", '{"listen":"127.0.0.1:8788"}\n')
        write(bundle / "generated/wg/wg.conf", "PRIVATE-NODE-PROFILE\n")
        write(bundle / "modes/stale.sh", "STALE-MODE\n")
        write(bundle / "client/stale.ps1", "STALE-CLIENT\n")
        write(bundle / "dist/stale.bin", "STALE-BINARY\n")
        write(bundle / "modes.json", "STALE-CATALOG\n")
        write(bundle / "logical-modes.json", "STALE-LOGICAL\n")
        write(bundle / "LICENSE", "STALE-LICENSE\n")

        write(src / "modes/current.sh", "CURRENT-MODE\n")
        write(src / "client/current.ps1", "CURRENT-CLIENT\n")
        write(src / "configs/client/modes.json", "CURRENT-CATALOG\n")
        write(src / "configs/client/logical-modes.json", "CURRENT-LOGICAL\n")
        write(src / "LICENSE", "CURRENT-LICENSE\n")

        out = MOD.build_private_bundle(work, base, src)
        assert (out / "routers.json").read_text(encoding="utf-8").startswith('{"selected_id"')
        assert (out / "generated/wg/wg.conf").read_text(encoding="utf-8") == "PRIVATE-NODE-PROFILE\n"
        assert not (out / "modes/stale.sh").exists()
        assert not (out / "client/stale.ps1").exists()
        assert not (out / "dist").exists()
        assert (out / "modes/current.sh").read_text(encoding="utf-8") == "CURRENT-MODE\n"
        assert (out / "client/current.ps1").read_text(encoding="utf-8") == "CURRENT-CLIENT\n"
        assert (out / "modes.json").read_text(encoding="utf-8") == "CURRENT-CATALOG\n"
        assert (out / "logical-modes.json").read_text(encoding="utf-8") == "CURRENT-LOGICAL\n"
        assert (out / "LICENSE").read_text(encoding="utf-8") == "CURRENT-LICENSE\n"

    print("Private bundle exact runtime source tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
