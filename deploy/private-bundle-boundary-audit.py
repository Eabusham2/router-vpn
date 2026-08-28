#!/usr/bin/env python3
"""Keep private node credentials outside persistent Setup Center downloads."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

def read(rel: str) -> str:
    path = ROOT / rel
    assert path.is_file(), f"missing private-bundle contract source: {rel}"
    return path.read_text(encoding="utf-8")

publish = read("server/scripts/publish-downloads.sh")
init = read("server/init/noninteractive.sh")
install = read("server/install.sh")
upgrade = read("server/upgrade.sh")
doctor = read("server/scripts/doctor-current.sh")
broker = read("server/scripts/download-broker.py")
bundle_gen = read("server/scripts/create-bundle-json.py")
builder = read("server/scripts/build-download-on-demand.py")
sync_runtime = read("server/finalize/sync-client-runtime.sh")

# Public/static publishing must delete every historical credential-bearing form
# and never copy the canonical private bundle/CREDENTIALS into downloads.
for marker in (
    '"$OUT"/router-vpn-client-bundle.zip',
    '"$OUT"/router-vpn-bundle.json',
    '"$OUT"/CREDENTIALS.txt',
    'no static node credentials',
):
    assert marker in publish, f"publish-downloads lost private-material purge marker: {marker}"
assert 'copy_static "$BUNDLE/router-vpn-bundle.json"' not in publish
assert 'copy_static "$BUNDLE/CREDENTIALS.txt"' not in publish

# Init also removes cached legacy credential files before both new-install and
# already-initialized upgrade paths.
for marker in (
    '"$BASE/downloads/router-vpn-client-bundle.zip"',
    '"$BASE/router-vpn-client-bundle.zip"',
    '"$BASE/downloads/router-vpn-bundle.json"',
    '"$BASE/downloads/CREDENTIALS.txt"',
):
    assert marker in init, f"init no longer purges historical private material: {marker}"

# Install/upgrade/doctor must validate the canonical private source rather than
# demanding or recreating a persistent public credential file.
for rel, body in (("install", install), ("upgrade", upgrade), ("doctor", doctor)):
    assert 'client-bundle/router-vpn-bundle.json' in body, f"{rel} does not require canonical private bundle"
    assert 'downloads/router-vpn-bundle.json' in body, f"{rel} does not explicitly check legacy public bundle leakage"
    if rel in ("install", "upgrade"):
        assert 'test ! -e' in body and 'downloads/router-vpn-client-bundle.zip' in body, f"{rel} does not reject cached private bundle ZIP"

# The only user retrieval path is authenticated/on-demand broker generation or
# one-time LAN pairing. Broker reads the canonical client-bundle source directly.
for marker in (
    'name == "router-vpn-client-bundle.zip"',
    '"private-node-bundle"',
    'if path == "/api/pairing/redeem"',
    'Path(self.server.base_dir) / "client-bundle" / "router-vpn-bundle.json"',
    'if not self._require_auth()',
):
    assert marker in broker, f"broker private-node boundary lost marker: {marker}"


# A private node-link bundle must combine private node state with runtime code
# from the exact current source tree at request time. Persistent client-bundle
# copies of modes/client/dist are never authoritative package inputs.
for marker in (
    "def build_private_bundle(work: Path, base: Path, src_root: Path)",
    'for stale in ("modes", "client", "dist")',
    'copy_tree(src_root / "modes", root / "modes")',
    'copy_tree(src_root / "client", root / "client")',
    'copy_file(src_root / "configs" / "client" / "modes.json", root / "modes.json")',
    'copy_file(src_root / "configs" / "client" / "logical-modes.json", root / "logical-modes.json")',
    'copy_file(src_root / "LICENSE", root / "LICENSE")',
    "return build_private_bundle(work, base, src_root)",
):
    assert marker in builder, f"private bundle builder lost exact-runtime marker: {marker}"
for stale in (
    "return build_private_bundle(work, base)",
):
    assert stale not in builder, f"private bundle builder revived stale persistent-runtime input: {stale}"

for marker in (
    "PRIVATE_BATCH=/src/server/scripts/atomic-private-batch.py",
    "VERIFIED_READ=/src/server/scripts/verified-regular-read.py",
    'mktemp -d "$BUNDLE/.runtime-metadata.XXXXXX"',
    '"$BUNDLE/modes.json=$STAGE/modes.json"',
    '"$BUNDLE/logical-modes.json=$STAGE/logical-modes.json"',
    '"$BUNDLE/LICENSE=$STAGE/LICENSE"',
    "runtime code is injected from exact source",
):
    assert marker in sync_runtime, f"sync-client-runtime lost atomic metadata marker: {marker}"
for stale in (
    'cp -a /src/modes',
    'cp -a /src/client',
    'rm -rf "$BUNDLE/modes"',
    'rm -rf "$BUNDLE/client"',
):
    assert stale not in sync_runtime, f"sync-client-runtime revived mixed persistent runtime mutation: {stale}"

proc = subprocess.run(
    [sys.executable, str(ROOT / "server/scripts/test_private_bundle_runtime_source.py")],
    cwd=ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
assert proc.returncode == 0, "private bundle runtime source test failed: " + (proc.stdout + proc.stderr)[-4000:]

# Pairing/private bundles may contain the node API credential needed by the client,
# but never the Setup Center/admin bearer secret used for management mutations.
for forbidden in ("setup_token", "setup-center.token", "ROUTER_VPN_ADMIN_TOKEN_FILE", "admin_token"):
    assert forbidden not in bundle_gen, f"private client bundle generator leaked management credential concept: {forbidden}"
assert 'self.server.setup_token' not in broker[broker.index('def _redeem_pairing'):broker.index('def _dynamic')], "pairing redemption serialized Setup Center token"
assert 'router-vpn-bundle.json' in broker[broker.index('def _redeem_pairing'):broker.index('def _dynamic')], "pairing does not return the canonical minimal node bundle"

print("private node bundle publication/authentication/token-separation boundary audit: OK")
