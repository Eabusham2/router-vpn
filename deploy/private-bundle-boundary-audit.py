#!/usr/bin/env python3
"""Keep private node credentials outside persistent Setup Center downloads."""
from pathlib import Path

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

print("private node bundle publication/authentication boundary audit: OK")
