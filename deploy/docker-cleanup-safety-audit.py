#!/usr/bin/env python3
"""Protect unrelated Docker state from Router VPN cleanup/recovery operations."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
cleanup = (ROOT / "server/scripts/cleanup-router-vpn-docker.sh").read_text(encoding="utf-8")

for marker in (
    "--filter 'name=router-vpn-'",
    "ghcr.io/eabusham2/router-vpn-*|router-vpn-*",
    "docker ps -aq",
    "USED[\"$iid\"]=1",
    "docker image rm \"$iid\"",
    "Named volumes, unrelated images/containers, and Docker build cache were not touched.",
):
    assert marker in cleanup, f"Router VPN cleanup lost ownership/safety marker: {marker}"

# A Router VPN cleanup must never become a host-wide reclamation command.
forbidden_regexes = (
    r"docker\s+system\s+prune",
    r"docker\s+(?:image|container|volume|builder|buildx)\s+prune",
    r"docker\s+rm\s+-f\s+\$\(docker\s+ps\s+-aq",
    r"docker\s+rmi\s+-f\s+\$\(docker\s+images",
    r"rm\s+-rf\s+/(?:var/lib/docker|var/lib/containerd)",
    r"overlay2",
    r"containerd/.+rm\s+-rf",
)
# Ignore explanatory comments when checking command text.
commands = "\n".join(line for line in cleanup.splitlines() if not line.lstrip().startswith("#"))
for pattern in forbidden_regexes:
    assert not re.search(pattern, commands, re.I), f"Router VPN cleanup contains destructive host-wide operation: {pattern}"

# Search repository shell/Python deployment helpers as well; docs may mention
# forbidden commands historically, but executable deployment/recovery source may not.
for root_name in ("server", "deploy", "router"):
    for path in (ROOT / root_name).rglob("*"):
        if not path.is_file() or path.suffix not in {".sh", ".py", ".yml", ".yaml"}:
            continue
        body = path.read_text(encoding="utf-8", errors="replace")
        executable = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))
        for pattern in forbidden_regexes:
            assert not re.search(pattern, executable, re.I), f"{path.relative_to(ROOT)} contains forbidden Docker host-wide cleanup: {pattern}"

print("Router VPN Docker cleanup isolation audit: OK")
