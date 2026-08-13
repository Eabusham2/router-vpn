#!/usr/bin/env python3
"""Recovered release scorer v2 with the composed Setup Center product wrapper."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
BASE = HERE / "recovered-release-audit.py"
spec = importlib.util.spec_from_file_location("routervpn_recovered_release_v1", BASE)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load recovered-release-audit.py")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

# The authenticated release/recovery surface is intentionally composed *above*
# setup-center-ai-server.py. The final product Handler subclasses the existing
# authenticated AI Handler, adds only a read-only exact-SHA/recovery route, and
# remains mounted read-only in production with no Docker socket/build path.
mod.RECOVERED[1]["pass"] = lambda: (
    mod.has(
        "server/scripts/setup-center-product-server.py",
        "setup-center-ai-server.py",
        "setup_center_release_status.py",
        "/api/release-status",
        "_require_auth()",
    )
    and mod.has(
        "server/scripts/setup_center_release_status.py",
        "exact-sha-image-only",
        "self_update_available",
        "safe_sequence",
    )
    and mod.has(
        "server/scripts/run-setup-center.sh",
        "/src/server/scripts/setup-center-product-server.py",
    )
    and mod.has(
        "server/portainer-current.yaml",
        '/src/server/scripts/setup-center-product-server.py',
        "/opt/router-vpn:/opt/router-vpn:ro",
    )
    and mod.no("server/portainer-current.yaml", "build:", "/var/run/docker.sock")
    and mod.has(
        ".github/workflows/setup-release-status-ci.yml",
        "test_setup_center_release.py",
        "/var/run/docker.sock",
    )
)
mod.RECOVERED[1]["note"] = (
    "authenticated read-only exact-SHA/recovery status is composed over the existing AI/auth boundary; "
    "production remains image-only and has no Docker socket"
)

raise SystemExit(mod.main())
