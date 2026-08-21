#!/usr/bin/env python3
"""Fail closed when generated/shipped profile stores drift from canonical schema defaults."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

types = read("internal/common/types.go")
profile_match = re.search(r"RouterProfileSchemaVersion\s*=\s*(\d+)", types)
store_match = re.search(r"RouterProfileStoreVersion\s*=\s*(\d+)", types)
assert profile_match and store_match, "canonical router profile schema constants are missing"
profile_version = int(profile_match.group(1))
store_version = int(store_match.group(1))

blank_store = f'{{"schema_version":{store_version},"selected_id":"","profiles":[]}}'
for path in (
    "deploy/package-builds.sh",
    "deploy/package-macos-native.sh",
    "deploy/package-linux-native.sh",
):
    source = read(path)
    assert blank_store in source, f"{path} does not seed canonical store schema v{store_version}"
    for stale in range(store_version):
        assert f'{{"schema_version":{stale},"selected_id":"","profiles":[]}}' not in source, f"{path} still seeds stale store schema v{stale}"

fallback = read("server/scripts/build-download-on-demand.py")
assert f"PROFILE_SCHEMA_VERSION = {store_version}" in fallback, "router-local package fallback seeds a stale router store schema"
for stale in range(store_version):
    assert f"PROFILE_SCHEMA_VERSION = {stale}" not in fallback, f"router-local package fallback still declares stale schema v{stale}"

bundle = read("server/scripts/create-bundle-json.py")
assert f"'schema_version':{profile_version}" in bundle, "generated home profile schema is stale"
assert f"json.dump({{'schema_version':{store_version},'selected_id':'home','profiles':[router_profile]}}" in bundle, "generated routers.json store schema is stale"
assert f"'profileSchemaVersion':{profile_version}" in bundle, "portable/mobile bundle profileSchemaVersion is stale"

# Current product defaults are intentionally explicit in generated home-node data.
# A v4 label with old defaults would be a silent behavior regression.
for marker in (
    "'ipv6_mode':'on'",
    "'startup_mode':'smart-auto'",
    "'mtu_policy':'auto'",
    "'auto_require_encrypted':False",
    "'auto_require_obfuscation':False",
):
    assert marker in bundle, f"generated home profile lost current default: {marker}"

print(f"profile schema shipping audit: OK (profile v{profile_version}, store v{store_version})")
