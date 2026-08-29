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
download_jobs = read("server/scripts/download_jobs.py")
owned_temp = read("server/scripts/owned-temp.py")
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
# already-initialized upgrade paths. It persists only catalog/license metadata;
# runtime code and platform binaries remain exact-source/on-demand inputs.
for marker in (
    '"$BASE/downloads/router-vpn-client-bundle.zip"',
    '"$BASE/router-vpn-client-bundle.zip"',
    '"$BASE/downloads/router-vpn-bundle.json"',
    '"$BASE/downloads/CREDENTIALS.txt"',
):
    assert marker in init, f"init no longer purges historical private material: {marker}"

for marker in (
    'python3 "$PRIVATE_WRITE" "$BASE/client-bundle/modes.json" < /src/configs/client/modes.json',
    'python3 "$PRIVATE_WRITE" "$BASE/client-bundle/logical-modes.json" < /src/configs/client/logical-modes.json',
    'python3 "$PRIVATE_WRITE" "$BASE/client-bundle/LICENSE" < /src/LICENSE',
    "Runtime code/binaries are injected",
):
    assert marker in init, f"init lost exact-source metadata/runtime separation marker: {marker}"
for stale in (
    "cp -a /src/modes /src/dist /src/client",
    'cp -a /src/modes "$BASE/client-bundle/"',
    'cp -a /src/client "$BASE/client-bundle/"',
    'cp -a /src/dist "$BASE/client-bundle/"',
):
    assert stale not in init, f"init revived persistent duplicate runtime tree: {stale}"

# Install/upgrade/doctor must validate the canonical private source rather than
# demanding or recreating a persistent public credential file.
for rel, body in (("install", install), ("upgrade", upgrade), ("doctor", doctor)):
    assert 'client-bundle/router-vpn-bundle.json' in body, f"{rel} does not require canonical private bundle"
    assert 'downloads/router-vpn-bundle.json' in body, f"{rel} does not explicitly check legacy public bundle leakage"
    if rel in ("install", "upgrade"):
        assert 'test ! -e' in body and 'downloads/router-vpn-client-bundle.zip' in body, f"{rel} does not reject cached private bundle ZIP"

# The only user retrieval path is authenticated/on-demand broker generation or
# one-time LAN pairing. Broker reads the canonical client-bundle source directly.
# GitHub bearer credentials are valid only for the initial api.github.com
# request. Artifact downloads redirect to blob storage; cross-origin redirects
# must remain HTTPS and must never carry Authorization/Cookie headers.
for marker in (
    "class _SafeGitHubRedirect",
    'new.scheme.lower() != "https"',
    'redirected.remove_header("Authorization")',
    'redirected.remove_header("Cookie")',
    'must start at https://api.github.com',
):
    assert marker in broker, f"broker lost GitHub redirect credential boundary: {marker}"


for marker in (
    'name == "router-vpn-client-bundle.zip"',
    '"private-node-bundle"',
    'if path == "/api/pairing/redeem"',
    'read_verified_regular = _verified.read_verified_regular',
    'def _setup_token',
    'def _pairing_bundle',
    'private=True',
    'lambda: _pairing_bundle(Path(self.server.base_dir))',
    'if not self._require_auth()',
):
    assert marker in broker, f"broker private-node boundary lost marker: {marker}"



# Shared-temp cleanup must prove Router VPN ownership, not merely trust a
# predictable filename prefix. Request, async-job, and nested package-build roots
# all carry the same private marker; foreign lookalikes/symlinks are skipped.
for marker in (
    "MARKER_NAME = \".router-vpn-owned-temp\"",
    "MARKER_VERSION = 2",
    "MARKER_PREFIX = b\"router-vpn-owned-temp-v2\\n\"",
    "def create_owned_temp",
    "def owned_temp_owner_pid",
    "def is_owned_temp",
    "def _pid_alive",
    "owner_pid != current_pid and _pid_alive(owner_pid)",
    "def cleanup_owned_temp",
    "stat.S_ISLNK",
    "os.path.samestat",
):
    assert marker in owned_temp, f"owned-temp helper lost cleanup-ownership marker: {marker}"
for marker in (
    'create_owned_temp("router-vpn-request-")',
    "cleanup_owned_temp(path)",
):
    assert marker in broker, f"download broker lost owned request/stale-temp marker: {marker}"
for marker in (
    'create_owned_temp("router-vpn-job-")',
    "cleanup_owned_temp(Path(path))",
):
    assert marker in download_jobs, f"download jobs lost owned temp marker: {marker}"
for marker in (
    'create_owned_temp("router-vpn-one-package-")',
    "cleanup_owned_temp(work)",
):
    assert marker in builder, f"package builder lost owned temp marker: {marker}"
for forbidden in (
    'if path.is_dir():\n                    shutil.rmtree(path)',
    'work = tempfile.mkdtemp(prefix="router-vpn-job-")',
    'TemporaryDirectory(prefix="router-vpn-one-package-")',
):
    assert forbidden not in broker + download_jobs + builder, f"prefix-only temp cleanup/creation revived: {forbidden}"

owned_temp_test = subprocess.run(
    [sys.executable, str(ROOT / "server/scripts/test_owned_temp.py")],
    cwd=ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
assert owned_temp_test.returncode == 0, "owned temporary-root safety tests failed: " + (owned_temp_test.stdout + owned_temp_test.stderr)[-4000:]


# Package/runtime source copies are one-pass descriptor reads, not
# validate-then-shutil races. Parent-chain and leaf identity are re-proved before
# the temporary package file is atomically adopted.
for marker in (
    'parent_chain_snapshot = _VERIFIED["parent_chain_snapshot"]',
    'verify_parent_chain = _VERIFIED["verify_parent_chain"]',
    'os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)',
    "package source changed during open",
    "package source changed during read",
    "refusing to package special filesystem entry",
    "package source directory changed during traversal",
    "os.replace(tmp, dst)",
):
    assert marker in builder, f"package builder lost race-safe copy marker: {marker}"
for forbidden in (
    "shutil.copy2(src, dst)",
    "shutil.copytree(src, dst, dirs_exist_ok=True)",
):
    assert forbidden not in builder, f"package builder revived validate-then-copy race: {forbidden}"

# Final package archives are private publications too: build into a same-directory
# temporary file, fsync it, re-prove parent + target identity, then replace once.
for marker in (
    "def _output_target_snapshot",
    "def _require_output_target_unchanged",
    'tempfile.mkstemp(prefix=f".{output.name}.archive-"',
    "os.fsync(stream.fileno())",
    "verify_parent_chain(parent_snapshot)",
    "_require_output_target_unchanged(output, before)",
    "os.replace(tmp, output)",
    "package output lost private 0600 mode",
):
    assert marker in builder, f"package builder lost atomic output marker: {marker}"
for forbidden in (
    'zipfile.ZipFile(output, "w"',
    "os.chmod(output, 0o600)",
):
    assert forbidden not in builder, f"package builder revived direct/post-commit package publication: {forbidden}"

download_safety = subprocess.run(
    [sys.executable, str(ROOT / "server/scripts/test_download_safety.py")],
    cwd=ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
assert download_safety.returncode == 0, "download/package safety tests failed: " + (download_safety.stdout + download_safety.stderr)[-4000:]

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


# Canonical private bundle metadata itself is one three-file transaction and all
# generated-profile inputs are verified no-follow private files. A symlinked
# mode directory/file or corrupt catalog must never be silently serialized.
for marker in (
    "read_verified_regular = VERIFIED[\"read_verified_regular\"]",
    "def read_generated_profiles",
    "refusing symlink generated profile entry",
    "generated mode contains non-regular/symlink entry",
    "generated mode directory changed during read",
    "generated profile root changed during read",
    "def write_private_json_batch",
    'str(SCRIPT_DIR / "atomic-private-batch.py")',
    '(base / "client-bundle" / "client.json", client_config)',
    '(base / "client-bundle" / "routers.json", routers_store)',
    '(base / "client-bundle" / "router-vpn-bundle.json", bundle)',
):
    assert marker in bundle_gen, f"private bundle generator lost verified transaction marker: {marker}"
for forbidden in (
    '(base / "config" / "router-agent.json").read_text',
    '(base / "client-bundle/modes.json").read_text',
    "mode_dir.is_dir()",
    "path.read_bytes()",
    "logical_modes = []",
):
    assert forbidden not in bundle_gen, f"private bundle generator revived unsafe read/fallback marker: {forbidden}"

bundle_test = subprocess.run(
    [sys.executable, str(ROOT / "server/scripts/test_create_bundle_transaction.py")],
    cwd=ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
assert bundle_test.returncode == 0, "private bundle generation transaction test failed: " + (bundle_test.stdout + bundle_test.stderr)[-4000:]

# Pairing/private bundles may contain the node API credential needed by the client,
# but never the Setup Center/admin bearer secret used for management mutations.
for forbidden in ("setup_token", "setup-center.token", "ROUTER_VPN_ADMIN_TOKEN_FILE", "admin_token"):
    assert forbidden not in bundle_gen, f"private client bundle generator leaked management credential concept: {forbidden}"
for forbidden in (
    'token_path.is_file()',
    'token_path.read_text(',
    'bundle.is_file()',
    'bundle.read_bytes()',
):
    assert forbidden not in broker, f"broker revived pathname-following private read: {forbidden}"

broker_security = subprocess.run(
    [sys.executable, str(ROOT / "server/scripts/test_broker_security.py")],
    cwd=ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
assert broker_security.returncode == 0, "broker private-read/pairing/redirect security tests failed: " + (broker_security.stdout + broker_security.stderr)[-4000:]

assert 'self.server.setup_token' not in broker[broker.index('def _redeem_pairing'):broker.index('def _dynamic')], "pairing redemption serialized Setup Center token"
assert 'router-vpn-bundle.json' in broker[broker.index('def _redeem_pairing'):broker.index('def _dynamic')], "pairing does not return the canonical minimal node bundle"

print("private node bundle publication/authentication/token-separation boundary audit: OK")
