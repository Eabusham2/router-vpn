#!/usr/bin/env python3
"""Exact generated Darwin SOCKS PF/utun acceptance; public admission stays separate."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import shutil

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("darwin_socks_original_child_gate", ROOT/"deploy/test_darwin_node_child_tun.py")
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
FLAG = "ROUTERVPN_DARWIN_SOCKS_CHILD_ACCEPTANCE"
HARNESS = "TestRouterVPNNodeChainSOCKSDarwinNativeHarness"
NATIVE = "TestRouterVPNNodeChainSOCKSDarwinNativeCommand"
CASES = ("run-wg", "run-awg-fast", "run-awg-strong", "middle-password",
         "final-token", "selected-dns", "middle-public", "held-proof-stop")
NEW_SOURCES = {
    "cmd/sing-box/routervpn_node_chain_socks_command_darwin_native_test.go",
    "cmd/sing-box/routervpn_node_chain_socks_command.go",
    "cmd/sing-box/routervpn_node_chain_socks_run_darwin.go",
    "cmd/sing-box/routervpn_node_chain_socks_control_darwin.go",
    "cmd/sing-box/routervpn_node_chain_socks_retirement_darwin.go",
    "routervpn/macosprocess/node_chain_socks_transfer.go",
    "protocol/routervpnamnezia/routervpn_node_chain_socks_peer_darwin_test.go",
    "protocol/routervpnamnezia/routervpn_node_chain_socks_process_darwin_test.go",
}
class JoinedWorkspace:
    """Retain the original workspace unless every awaited operation succeeded."""
    def __init__(self, prefix):
        self.path = Path(tempfile.mkdtemp(prefix=prefix)).absolute()
        self.identity = self.path.lstat()
        if self.path.is_symlink() or not self.path.is_dir():
            raise ValueError("Darwin SOCKS workspace lost its original directory")

    def __enter__(self):
        return self.path

    def __exit__(self, kind, error, traceback):
        # A reporting/compile exception can leave original children unjoined.
        # There is no generic retry or authority to delete their files here.
        if kind is not None:
            return False
        try:
            current = self.path.lstat()
        except OSError as failure:
            raise ValueError("Darwin SOCKS workspace identity disappeared") from failure
        if self.path.is_symlink() or not self.path.is_dir() or not os.path.samestat(self.identity, current):
            raise ValueError("Darwin SOCKS workspace was replaced; retained")
        shutil.rmtree(self.path)
        if self.path.exists() or self.path.is_symlink():
            raise ValueError("Darwin SOCKS original joined workspace did not retire")
        return False

def checked_sources(source):
    source, records = BASE.checked_sources(source)
    if not NEW_SOURCES.issubset(records):
        raise ValueError("Darwin SOCKS omitted its typed owner or actual encrypted peer")
    for name in ("test_darwin_socks_child_tun.py", "test_darwin_socks_child_tun_runner.py"):
        records["gate/"+name] = BASE.digest(ROOT/"deploy"/name)
    return source, records

def required_host(environment):
    if environment.get(FLAG) != "1":
        raise ValueError("Darwin SOCKS requires its explicit separate native purpose")
    return BASE.required_host(environment)

def check_verdict(output):
    BASE._check_selected_verdict(output, HARNESS, NATIVE, CASES)

def execute_images(source, before, captured, sudo, arch, uid, child, peer, identities):
    command = ["/usr/bin/env", BASE.FLAG+"=1", FLAG+"=1",
               "ROUTERVPN_DARWIN_NODE_CHILD_UID="+str(uid),
               "ROUTERVPN_DARWIN_NODE_CHILD_SHA256="+identities[child][-1],
               "ROUTERVPN_DARWIN_NODE_CHAIN_PEER="+str(peer),
               "ROUTERVPN_DARWIN_NODE_CHAIN_PEER_SHA256="+identities[peer][-1],
               "GORACE=atexit_sleep_ms=0", str(child), "-test.run=^"+HARNESS+"$",
               "-test.v", "-test.count=1", "-test.timeout=930s"]
    if sudo:
        command = [sudo, "-n", "--", *command]
    output = BASE.native_output(command, cwd=ROOT, env=captured, timeout=960, sudo=sudo)
    check_verdict(output)
    if checked_sources(source)[1] != before or any(BASE.image_identity(path) != value for path, value in identities.items()):
        raise ValueError("Darwin SOCKS changed its original source or native image")
    return {
        "schema": 1, "gate": "generated-darwin-ordered-socks-child",
        "scope": "actual-generated-command-pf-utun", "target": "darwin/"+arch,
        "toolchain": BASE.UID.RACE.TOOLCHAIN, "cases": list(CASES),
        "source_files": before,
        "source_sha256": hashlib.sha256(json.dumps(before, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "artifacts": {role: {"bytes": identities[path][2], "sha256": identities[path][-1]}
                      for role, path in (("generated-child-test", child), ("independent-encrypted-peer", peer))},
        "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "public_darwin_admission": "closed",
    }

def execute(source, go="go", *, environment=None):
    environment = dict(os.environ if environment is None else environment)
    arch, uid = required_host(environment)
    source, before = checked_sources(source)
    compiler, captured = BASE.selected_compiler(go, source, environment)
    sudo = BASE.UID.privilege_tool()
    with JoinedWorkspace(prefix="routervpn-darwin-socks-child-") as temporary:
        work = Path(temporary).resolve()
        work.chmod(0o755)
        child, peer = work/"child.test", work/"peer.test"
        for image, package in ((child, "./cmd/sing-box"), (peer, "./protocol/routervpnamnezia")):
            BASE.UID.run(BASE.native_fixture_compile(compiler, image, package), cwd=source, env=captured, timeout=600)
            image.chmod(0o755)
        if checked_sources(source)[1] != before:
            raise ValueError("Darwin SOCKS source changed during compilation")
        identities = {path: BASE.image_identity(path) for path in (child, peer)}
        # Original eight cases keep their own exact selector, verdict and 960s
        # bound. The typed eight are another owned invocation, not an expansion.
        original_environment = dict(captured)
        original_environment.pop(FLAG, None)
        original = BASE.execute_native_images(source, BASE.checked_sources(source)[1], original_environment, sudo,
                                               arch, uid, child, peer, identities)
        if original.get("cases") != list(BASE.CASES) or len(BASE.CASES) != 8:
            raise ValueError("Darwin SOCKS lost original eight-case preservation")
        result = execute_images(source, before, captured, sudo, arch, uid, child, peer, identities)
        result["original_eight"] = original
    if work.exists():
        raise ValueError("Darwin SOCKS compilation workspace did not retire")
    return result

def standalone(go="go", *, environment=None, required_commit=None, receipt=None):
    environment = dict(os.environ if environment is None else environment)
    required_host(environment)
    repository = BASE.repository_identity(required_commit)
    path = BASE.receipt_path(receipt)
    compiler, captured = BASE.preparation_compiler(go, ROOT, environment)
    previous = dict(os.environ)
    with JoinedWorkspace(prefix="routervpn-darwin-socks-core-") as temporary:
        workspace = Path(temporary).resolve()
        core, xray = workspace/"core", workspace/"xray"
        try:
            os.environ.clear(); os.environ.update(captured)
            BASE.BUILD.checkout(core, "https://github.com/SagerNet/sing-box.git", BASE.BUILD.PIN)
            BASE.BUILD.checkout(xray, "https://github.com/XTLS/Xray-core.git", BASE.BUILD.POLICY.XRAY.XRAY_PIN)
            BASE.BUILD.pristine(core, BASE.BUILD.PIN); BASE.BUILD.pristine(xray, BASE.BUILD.POLICY.XRAY.XRAY_PIN)
            BASE.BUILD.POLICY.prepare_native(core, xray)
            BASE.BUILD.PERFORMANCE.prepare(core); BASE.BUILD.OPENVPN.prepare(core)
            BASE.BUILD.EXTERNAL.prepare(core, go=str(compiler), env=captured); BASE.BUILD.BUFFERS.prepare(core)
            BASE.BUILD.run([compiler, "mod", "tidy"], cwd=core, env=captured)
            BASE.BUILD.run([compiler, "mod", "verify"], cwd=core, env=captured)
            BASE.BUILD.POLICY.AMNEZIA.verify(core)
            result = execute(core, str(compiler), environment=captured)
        finally:
            os.environ.clear(); os.environ.update(previous)
    if BASE.repository_identity(required_commit) != repository:
        raise ValueError("Darwin SOCKS candidate changed during native acceptance")
    result["repository"] = repository
    BASE.publish_receipt(path, result, workspace)
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--standalone", action="store_true")
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    parser.add_argument("--require-commit")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    if args.standalone == (args.source is not None) or not args.standalone and (args.require_commit or args.receipt):
        parser.error("provide prepared source or standalone exact original checkout")
    result = standalone(args.go, required_commit=args.require_commit, receipt=args.receipt) if args.standalone else execute(args.source, args.go)
    print(json.dumps(result, sort_keys=True))
