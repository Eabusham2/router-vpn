#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []
def text(rel: str) -> str:
    p = ROOT / rel
    if not p.is_file(): errors.append(f"missing {rel}"); return ""
    return p.read_text(encoding="utf-8", errors="replace")
def need(rel: str, *values: str) -> None:
    body=text(rel)
    for value in values:
        if value not in body: errors.append(f"{rel}: missing {value!r}")
def forbid(rel: str, *values: str) -> None:
    body=text(rel)
    for value in values:
        if value in body: errors.append(f"{rel}: forbidden {value!r}")
cfg=json.loads(text("configs/current-requirements.json") or "{}")
assert cfg.get("repository_policy") == {"branch":"main","branches_or_prs":False,"direct_commits":True}
assert cfg.get("defaults",{}).get("mode") == "smart-auto"
assert cfg.get("defaults",{}).get("selected_node_count") == 1
assert cfg.get("defaults",{}).get("ipv6") is True
assert cfg.get("download_delivery",{}).get("retention_seconds_from_ready") == 1800
assert cfg.get("truth",{}).get("custom_xor_cipher") is False
need("deploy/materialize-production-compose.py","--sha","server/portainer-current.yaml","GENERATED exact-SHA Router VPN production compose","atomic_write")
need(".github/workflows/production-release-compose.yml","materialize-production-compose.py --sha","verify-production-compose.py")
need("deploy/package-macos-native.sh","server/scripts/source_provenance.py")
need("deploy/package-linux-native.sh","server/scripts/source_provenance.py")
need("server/scripts/build-download-on-demand.py",'Path(__file__).with_name("source_provenance.py")')
need("server/scripts/download_jobs.py","JOB_TTL_SECONDS = 30 * 60","retention_deadline_epoch=now + PACKAGE_RETENTION_SECONDS")
need("deploy/setup-center-download-retention-audit.py","30-minute Setup Center download contract")
need("deploy/unified-map-shipping-audit.py","Prove the unified map control center is in each real shipping entrypoint")
for rel in ("deploy/package-macos-native.sh","deploy/package-linux-native.sh"): forbid(rel,"$ROOT/deploy/source_provenance.py")
if errors:
    print("CURRENT REQUIREMENTS RECONCILIATION: FAIL")
    for error in errors: print(" - "+error)
    raise SystemExit(1)
print("CURRENT REQUIREMENTS RECONCILIATION: PASS")
