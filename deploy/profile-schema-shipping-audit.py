#!/usr/bin/env python3
"""Fail closed when generated/shipped profile stores drift from canonical schema defaults."""
from pathlib import Path
import ast
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
tree = ast.parse(bundle, filename="server/scripts/create-bundle-json.py")

def assigned_value(name: str) -> ast.AST:
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            return node.value
    raise AssertionError(f"missing generated assignment {name}")


def assigned_dict(name: str) -> dict[str, object]:
    value = assigned_value(name)
    if not isinstance(value, ast.Dict):
        raise AssertionError(f"{name} is no longer a literal mapping")
    values: dict[str, object] = {}
    for key, item in zip(value.keys, value.values):
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            try:
                values[key.value] = ast.literal_eval(item)
            except (ValueError, TypeError):
                values[key.value] = object()
    return values


def dict_value_node(mapping: ast.Dict, key_name: str) -> ast.AST:
    for key, value in zip(mapping.keys, mapping.values):
        if isinstance(key, ast.Constant) and key.value == key_name:
            return value
    raise AssertionError(f"generated mapping is missing {key_name}")


def expression_contains_string(node: ast.AST, expected: str) -> bool:
    return any(isinstance(part, ast.Constant) and part.value == expected for part in ast.walk(node))


router_defaults = assigned_dict("router_profile")
bundle_defaults = assigned_dict("bundle")
assert router_defaults.get("schema_version") == profile_version, "generated home profile schema is stale"

routers_store_node = assigned_value("routers_store")
assert isinstance(routers_store_node, ast.Dict), "routers_store is no longer a literal mapping"
assert ast.literal_eval(dict_value_node(routers_store_node, "schema_version")) == store_version, "generated routers.json store schema is stale"
assert ast.literal_eval(dict_value_node(routers_store_node, "selected_id")) == "home", "generated routers.json selected profile is stale"
profiles_node = dict_value_node(routers_store_node, "profiles")
assert (
    isinstance(profiles_node, ast.List)
    and len(profiles_node.elts) == 1
    and isinstance(profiles_node.elts[0], ast.Name)
    and profiles_node.elts[0].id == "router_profile"
), "generated routers.json no longer contains exactly the generated home profile"

routers_store_published = False
for node in ast.walk(tree):
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "write_private_json_batch"
        and node.args
        and isinstance(node.args[0], (ast.List, ast.Tuple))
    ):
        continue
    for item in node.args[0].elts:
        if not isinstance(item, (ast.Tuple, ast.List)) or len(item.elts) != 2:
            continue
        target, value = item.elts
        if (
            expression_contains_string(target, "routers.json")
            and isinstance(value, ast.Name)
            and value.id == "routers_store"
        ):
            routers_store_published = True
            break
assert routers_store_published, "routers_store is not published through the private atomic batch"
assert bundle_defaults.get("profileSchemaVersion") == profile_version, "portable/mobile bundle profileSchemaVersion is stale"

# Current product defaults are intentionally explicit in generated home-node data.
# A v4 label with old defaults would be a silent behavior regression.
for key, expected in {
    "ipv6_mode": "on",
    "startup_mode": "smart-auto",
    "mtu_policy": "auto",
    "auto_require_encrypted": False,
    "auto_require_obfuscation": False,
}.items():
    assert router_defaults.get(key) == expected, f"generated home profile lost current default: {key}={expected!r}"

android = read("android/app/src/main/java/com/eabusham/routervpn/AndroidNodeStore.java")
assert f"MAX_PROFILE_SCHEMA = {profile_version}" in android, "Android bundle importer schema ceiling is stale"
assert 'profileSchema > MAX_PROFILE_SCHEMA' in android, "Android must fail closed on future top-level profile schemas"
assert 'nestedSchema > MAX_PROFILE_SCHEMA' in android, "Android must fail closed on future nested profile schemas"

ios = read("ios/RouterVPN/App/Models.swift")
assert f"profileSchemaVersion: {profile_version}" in ios, "iOS empty/current bundle schema is stale"
assert f"guard profileSchemaVersion <= {profile_version} else" in ios, "iOS bundle importer schema ceiling is stale"

print(f"profile schema shipping audit: OK (profile v{profile_version}, store v{store_version})")
