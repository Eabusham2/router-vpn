#!/usr/bin/env python3
"""Validate retained Windows source retirement with the original native MAX gate.

The trusted checkout runs this driver against a separately identity-checked
candidate. The candidate's unchanged MAX helper owns the original pinned core,
CGO/Rosenpass toolchain, process jobs, WFP peers and all QUIC verdicts.
"""
from pathlib import Path
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import platform
import re
import shlex
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = "TestRouterVPNNodeCapturedSourceRetirement"
BOX_ROOT = "TestRouterVPNNodeMTUSourceJoinsBeforeIrreversibleBoxClose"
SOURCE_CASES = (SOURCE_ROOT,) + tuple(SOURCE_ROOT + "/" + leaf for leaf in (
    "foreign-policy", "foreign-capture", "non-windows", "expired-caller",
    "held-owner", "pending-retry", "never-prepared"))
BOX_CASES = (BOX_ROOT,) + tuple(BOX_ROOT + "/" + leaf for leaf in (
    "pending-retry", "cancelled-wait", "expired-caller", "permanent-box-failure", "ordinary-external")) + (
    "TestRouterVPNNodeMTUNativeBoxCloseFailureRemainsUnacknowledged",)
ORIGINAL_ROOTS = (
    "TestRouterVPNNodePhysicalFactoryCancellationJoinsPartialOwner",
    "TestRouterVPNNodePhysicalRetirementKeepsExactJoinedSource",
    "TestRouterVPNNodePhysicalCallerContext")
ORIGINAL_CASES = ORIGINAL_ROOTS + tuple(ORIGINAL_ROOTS[0] + "/" + leaf for leaf in
    ("partial-source", "late-broker")) + tuple(ORIGINAL_ROOTS[1] + "/" + leaf for leaf in
    ("started", "partial-before-admission")) + tuple(ORIGINAL_ROOTS[2] + "/" + leaf for leaf in
    ("lower", "owner", "manager"))
BASELINES = (
    ("source-owner", "./routervpn/desktoppt", "^" + SOURCE_ROOT + "$", SOURCE_CASES),
    ("source-before-box", "./cmd/sing-box",
     "^TestRouterVPNNodeMTU(SourceJoinsBeforeIrreversibleBoxClose|NativeBoxCloseFailureRemainsUnacknowledged)$", BOX_CASES),
    ("original-physical", "./routervpn/desktoppt",
     "^TestRouterVPNNodePhysical(FactoryCancellationJoinsPartialOwner|RetirementKeepsExactJoinedSource|CallerContext)$", ORIGINAL_CASES))
CONTROLS = (
    ("node-source-before-box-close", "cmd/sing-box/routervpn_external.go", "./cmd/sing-box",
     BOX_ROOT, "pending-retry", "pending source poisoned irreversible native Box receipt"),
    ("node-source-original-policy", "routervpn/desktoppt/node_network.go", "./routervpn/desktoppt",
     SOURCE_ROOT, "foreign-policy", "foreign cleanup acquired original source"),
    ("node-source-original-caller", "routervpn/desktoppt/node_network.go", "./routervpn/desktoppt",
     SOURCE_ROOT, "pending-retry", "source cleanup widened original caller or three-second bound"))
PROJECTIONS = {
    "external.go.tmpl": "cmd/sing-box/routervpn_external.go",
    "mtu_node.go.tmpl": "cmd/sing-box/routervpn_mtu_node.go",
    "node_box_physical.go.tmpl": "routervpn_desktop_node_box_physical.go",
    "node_network.go.tmpl": "routervpn/desktoppt/node_network.go",
    "node_pq_peer_test.go.tmpl": "protocol/routervpnpq/node_pq_peer_test.go",
    "node_pq_peer_windows_test.go.tmpl": "protocol/routervpnpq/node_pq_peer_windows_test.go",
    "node_max_peer_windows_test.go.tmpl": "protocol/routervpnpq/node_max_peer_windows_test.go",
    "node_network_test.go.tmpl": "routervpn/desktoppt/node_network_test.go",
    "mtu_node_test.go.tmpl": "cmd/sing-box/routervpn_mtu_node_test.go",
}
TARGETS = {"windows/amd64": ("AMD64", "x86_64"), "windows/arm64": ("ARM64", "aarch64")}
FAILED_CASE = "max-quic-awg/off/packet-peer"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CLOCK = load("windows_retirement_trusted_verdict", ROOT / "deploy/test_focused_multihop_clocks.py")


def require_host(target, system, machine, captured, architecture):
    if (target not in TARGETS or system != "Windows" or machine not in TARGETS[target] or
            captured.get("GOOS") != "windows" or captured.get("GOARCH") != architecture or
            target != "windows/" + architecture or captured.get("CGO_ENABLED") != "1"):
        raise ValueError("source retirement requires its exact elevated matching-host Windows CGO target")
    return ["-race"] if architecture == "amd64" else []


def parse(output, package, names, status, joined, *, witness="", leaf=""):
    case = CLOCK.Case("native-retirement", "", frozenset(names), 45 if witness else 90,
                      55 if witness else 105, "source-retirement" if witness else "", witness,
                      frozenset((leaf,)) if witness else frozenset())
    original = CLOCK.PACKAGE
    try:
        CLOCK.PACKAGE = "github.com/sagernet/sing-box/" + package.removeprefix("./")
        result = CLOCK.verdict(output.encode(), case, status, process_group_joined=joined)
    finally:
        CLOCK.PACKAGE = original
    if not result["accepted"]:
        raise ValueError("native retirement verdict: " + result["reason"])
    return result



def require_source_contract(output, status):
    # Retain the raw captured transcript in its log. Windows text pipes can
    # forward CRCRLF; only the observation of line boundaries is normalized.
    lines = [line for line in output.replace("\r\n", "\n").replace("\r", "\n").split("\n") if line]
    results = [line for line in lines if re.fullmatch(r"test_\w+ \([^\r\n]+\) \.\.\. ok", line)]
    summaries = [line for line in lines if line.startswith("Ran ")]
    if (status != 0 or len(results) != 5 or len(set(results)) != 5 or
            len(summaries) != 1 or not re.fullmatch(r"Ran 5 tests in [0-9]+(?:\.[0-9]+)?s", summaries[0]) or
            not lines or lines[-1] != "OK" or lines.count("OK") != 1 or
            any(line.startswith(("FAILED", "ERROR", "FAIL:", "Traceback")) for line in lines)):
        raise ValueError("candidate source-retirement inventory/control self-tests did not pass")


def verify_max(result, target, sha, max_module):
    if (result.get("schema") != 2 or result.get("target") != target or
            result.get("repository", {}).get("commit") != sha or
            result.get("repository", {}).get("clean") is not True or
            result.get("execution_suite") != "quic" or result.get("prospective") is not False or
            result.get("native_firewall") != "actual-appid-scoped-wfp" or
            result.get("native_socket_source") != "actual-isolated-token" or
            result.get("private_key_workspace_removed") is not True or
            result.get("traffic_cases") != {"QUIC": max_module.MAX.TRAFFIC["QUIC"]} or
            result.get("credential_cases") != {"QUIC": max_module.MAX.CREDENTIALS["QUIC"]} or
            FAILED_CASE not in result.get("credential_cases", {}).get("QUIC", ())):
        raise ValueError("original complete MAX QUIC or its exact failed-key case was omitted")
    return result


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class Tee:
    def __init__(self, *outputs):
        self.outputs = outputs

    def write(self, value):
        for output in self.outputs:
            output.write(value)
        return len(value)

    def flush(self):
        for output in self.outputs:
            output.flush()


def selected_identity(source,sha,output):
    path=output.parent/"selection.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("Original trusted Windows selection is missing or redirected")
    raw=path.read_bytes()
    record=json.loads(raw)
    if (record.get("schema")!=1 or record.get("suite")!="windows-source-retirement" or
            record.get("source_sha")!=sha or record.get("repository")!="Eabusham2/router-vpn" or
            record.get("workflow_ref")!="refs/heads/main" or
            record.get("validation_scope")!="read-only-source-candidate" or
            record.get("base_sha")!=record.get("validator_sha") or
            record.get("base_tree")!=record.get("validator_tree")):
        raise ValueError("Original Windows source suite or authority changed")
    for key in ("validator_sha","validator_tree","base_sha","base_tree","source_sha","source_tree"):
        if not isinstance(record.get(key),str) or not re.fullmatch("[0-9a-f]{40}",record[key]):
            raise ValueError("Original Windows selection lost Git identity")
    for root,commit,tree in ((source,sha,record["source_tree"]),(ROOT,record["validator_sha"],record["validator_tree"])):
        if (CLOCK.git(root,"rev-parse","HEAD").decode().strip()!=commit or
                CLOCK.git(root,"rev-parse","HEAD^{tree}").decode().strip()!=tree or
                CLOCK.git(root,"status","--porcelain","--untracked-files=all")):
            raise ValueError("Original Windows source or validator checkout changed")
    return record,raw


def validate(args):
    source, output = Path(args.source).resolve(), Path(args.output).resolve()
    if not re.fullmatch("[0-9a-f]{40}", args.source_sha):
        raise ValueError("requested source SHA must be exact lowercase 40-hex")
    if output == source or source in output.parents or (output.exists() and any(output.iterdir())):
        raise ValueError("output must be new or empty and outside the candidate")
    if CLOCK.git(source, "rev-parse", "HEAD").decode().strip() != args.source_sha:
        raise ValueError("candidate HEAD differs from requested source")
    if CLOCK.git(source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("candidate is not an exact clean checkout")
    selected,selection_bytes=selected_identity(source,args.source_sha,output)
    output.mkdir(parents=True, exist_ok=True)
    before = CLOCK.snapshot(source)
    write_json(output / "source-before.json", before)
    manifest = {"schema": 1, "suite": "windows-source-retirement", "source_sha": args.source_sha,
                "selection": selected,
                "target": args.target, "accepted": False, "native": "pending", "commands": [],
                "required_baselines": {name: list(names) for name, _, _, names in BASELINES},
                "required_controls": [item[0] for item in CONTROLS], "required_max_suite": "quic",
                "required_failed_case": FAILED_CASE, "bounds": {"build": 600, "baseline": 90,
                "baseline_outer": 105, "control": 45, "control_outer": 55},
                "physical_limit": "MAX gate uses actual app-scoped WFP and isolated tokens; its original TUN fixture remains modeled."}
    owner = None
    original_stdout, original_stderr = sys.stdout, sys.stderr
    driver_log = (output / "driver.log").open("w", encoding="utf-8")
    sys.stdout, sys.stderr = Tee(original_stdout, driver_log), Tee(original_stderr, driver_log)
    previous_env = dict(os.environ)
    try:
        native_max = load("windows_retirement_candidate_max", source / "deploy/test_windows_node_max.py")
        node, reference, native = native_max.NODE, native_max.REFERENCE, native_max.REFERENCE.BUILD
        if not native_max.WFP.BOOT.IDENTITY.ctypes.windll.shell32.IsUserAnAdmin():
            raise ValueError("original MAX requires actual elevated Windows")
        compiler, captured, architecture = node.selected_compiler(args.go, source, dict(os.environ))
        race = require_host(args.target, platform.system(), platform.machine(), captured, architecture)
        captured.update(GOMAXPROCS="2", GOGC="100", GOMEMLIMIT="2GiB")
        manifest["compiler"] = str(compiler)
        manifest["race"] = bool(race)
        manifest["resources"] = {key: captured[key] for key in ("GOMAXPROCS", "GOGC", "GOMEMLIMIT")}
        owner = native_max.MAXCommandOwner()
        os.environ.clear()
        os.environ.update(captured)

        def run(name, command, cwd, bound):
            started = time.monotonic()
            log = output / (name + ".log")
            try:
                status, text = owner.run(command, cwd=cwd, env=captured, timeout=bound)
            except BaseException as error:
                details = []
                for field in ("stdout", "stderr"):
                    value = getattr(error, field, None)
                    if value:
                        details.append(value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value))
                log.write_text("".join(details) + "\n" + type(error).__name__ + ": " + str(error), encoding="utf-8")
                manifest["commands"].append({"name": name, "arguments": list(map(str, command)),
                    "exit": None, "seconds": time.monotonic() - started, "bound": bound,
                    "joined": owner.retired, "log": log.name, "failure": type(error).__name__,
                    "sha256": hashlib.sha256(log.read_bytes()).hexdigest()})
                write_json(output / "manifest.json", manifest)
                raise
            log.write_text(text, encoding="utf-8")
            manifest["commands"].append({"name": name, "arguments": list(map(str, command)),
                "exit": status, "seconds": time.monotonic() - started, "bound": bound,
                "joined": owner.retired, "log": log.name,
                "sha256": hashlib.sha256(log.read_bytes()).hexdigest()})
            write_json(output / "manifest.json", manifest)
            return status, text

        status, text = run("source-contract", [sys.executable, source / "deploy/test_desktop_node_routing_runner.py",
                           "NodeSourceRetirementVerdicts", "-v"], source, 60)
        require_source_contract(text, status)
        with owner.workspace("routervpn-windows-source-retirement-") as directory:
            workspace = Path(directory)
            core, xray, pq, cache = (workspace / name for name in ("core", "xray", "pq", "cargo-cache"))
            with owner.preparation():
                native.checkout(core, "https://github.com/SagerNet/sing-box.git", native.PIN)
                native.checkout(xray, "https://github.com/XTLS/Xray-core.git", native.POLICY.XRAY.XRAY_PIN)
                native.pristine(core, native.PIN)
                native.pristine(xray, native.POLICY.XRAY.XRAY_PIN)
                native.PQ.build(args.target, pq, cache)
                native.POLICY.prepare_native(core, xray)
                native.PERFORMANCE.prepare(core)
                native.OPENVPN.prepare(core)
                native.EXTERNAL.prepare(core, go=str(compiler), env=captured)
                native.BUFFERS.prepare(core)
                native.run([compiler, "mod", "tidy"], cwd=core, env=captured)
                native.run([compiler, "mod", "verify"], cwd=core, env=captured)
                native.POLICY.AMNEZIA.verify(core)
            manifest["projections"] = {}
            for template, generated in PROJECTIONS.items():
                actual, original = core / generated, source / "mobile/desktop" / template
                if actual.is_symlink() or actual.read_bytes() != original.read_bytes():
                    raise ValueError("native retirement projection differs: " + template)
                manifest["projections"][generated] = hashlib.sha256(actual.read_bytes()).hexdigest()
            _, original_core = native_max.checked_sources(core)
            write_json(output / "prepared-source-before.json", original_core)
            archive = native.PQ.verify(pq, args.target)
            captured["CGO_LDFLAGS"] = shlex.join(["-static", "-L" + str(pq), *archive["native_static_libs"]])
            build = [compiler, "test", "-c", "-p=1", "-mod=readonly", "-tags=" + native_max.TAGS,
                     *race, "-ldflags=-checklinkname=0"]
            images, verdicts = {}, []
            with reference.test_sources(core):
                for name, package, selection, required in BASELINES:
                    if package not in images:
                        binary = workspace / (name + ".test.exe")
                        status, _ = run("build-" + name, [*build, "-o", binary, package], core, 600)
                        if status:
                            raise ValueError("native baseline failed to compile: " + name)
                        images[package] = (binary, native_max.MAX.regular_digest(binary))
                    binary, digest = images[package]
                    status, text = run(name, [compiler, "tool", "test2json", "-p",
                        "github.com/sagernet/sing-box/" + package.removeprefix("./"), "-t", binary,
                        "-test.v=test2json", "-test.run=" + selection, "-test.count=1", "-test.timeout=90s"], core, 105)
                    verdicts.append(parse(text, package, required, status, owner.retired))
                    if native_max.MAX.regular_digest(binary) != digest:
                        raise ValueError("original native test image changed")
                controls = node.node_source_retirement_mutants(core)
                if tuple(tuple(item[:6]) for item in controls) != CONTROLS:
                    raise ValueError("candidate changed exact compiled source-retirement controls")
                for label, relative, package, parent, leaf, witness, replacement in controls:
                    changed = workspace / (label + ".go")
                    changed.write_text(replacement, encoding="utf-8")
                    overlay = workspace / (label + ".json")
                    write_json(overlay, {"Replace": {str(core / relative): str(changed)}})
                    control_identity = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in (changed, overlay)}
                    binary = workspace / (label + ".test.exe")
                    status, _ = run("build-" + label, [*build, "-overlay=" + str(overlay), "-o", binary, package], core, 600)
                    if status:
                        raise ValueError("negative control failed to compile: " + label)
                    digest = native_max.MAX.regular_digest(binary)
                    status, text = run(label, [compiler, "tool", "test2json", "-p",
                        "github.com/sagernet/sing-box/" + package.removeprefix("./"), "-t", binary,
                        "-test.v=test2json", "-test.run=^" + parent + "$/^" + leaf + "$",
                        "-test.count=1", "-test.timeout=45s"], core, 55)
                    verdicts.append(parse(text, package, (parent, parent + "/" + leaf), status, owner.retired,
                                          witness=witness, leaf=parent + "/" + leaf))
                    if (native_max.MAX.regular_digest(binary) != digest or
                            any(hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected for path, expected in control_identity.items())):
                        raise ValueError("original control image or overlay changed")
            if native_max.checked_sources(core)[1] != original_core:
                raise ValueError("focused native validation altered its pinned prepared source")
            manifest["focused_verdicts"] = verdicts
            with (output / "max-quic.log").open("w", encoding="utf-8") as log, contextlib.redirect_stdout(Tee(sys.stdout, log)):
                result = native_max.execute(core, pq, cache, str(compiler), prospective=False,
                    env=captured, expected_sha=args.source_sha, suite="quic", command_owner=owner)
            verify_max(result, args.target, args.source_sha, native_max)
            write_json(output / "max-quic.json", result)
            if native_max.checked_sources(core)[1] != original_core:
                raise ValueError("MAX changed original prepared source")
        if workspace.exists() or workspace.is_symlink() or not owner.retired:
            raise ValueError("original Windows job or prepared source workspace did not join")
        manifest["native"] = "passed"
        manifest["max_receipt_sha256"] = hashlib.sha256((output / "max-quic.json").read_bytes()).hexdigest()
        manifest["max_output_sha256"] = hashlib.sha256((output / "max-quic.log").read_bytes()).hexdigest()
        manifest["workspace_removed"] = True
        manifest["accepted"] = True
    except BaseException as error:
        manifest["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        os.environ.clear()
        os.environ.update(previous_env)
        manifest["original_jobs_joined"] = bool(owner is not None and owner.retired)
        after = CLOCK.snapshot(source)
        write_json(output / "source-after.json", after)
        manifest["source_unchanged"] = after == before and not bool(CLOCK.git(source, "status", "--porcelain", "--untracked-files=all"))
        try:
            manifest["selection_unchanged"] = selected_identity(source,args.source_sha,output) == (selected,selection_bytes)
        except (ValueError,OSError):
            manifest["selection_unchanged"] = False
        if not manifest["source_unchanged"] or not manifest["selection_unchanged"]:
            manifest["accepted"] = False
        write_json(output / "manifest.json", manifest)
        sys.stdout, sys.stderr = original_stdout, original_stderr
        driver_log.close()
    if not manifest["accepted"]:
        raise ValueError("source or original native ownership did not remain exact")


def self_tests():
    class Contracts(unittest.TestCase):
        def events(self, names, *, failure=False, witness=""):
            package = "github.com/sagernet/sing-box/routervpn/desktoppt"
            events = [{"Action": "start", "Package": package}]
            events += [{"Action": "run", "Package": package, "Test": name} for name in names]
            for name in reversed(names):
                if witness and "/" in name:
                    events.append({"Action": "output", "Package": package, "Test": name, "Output": witness + "\n"})
                events.append({"Action": "fail" if failure else "pass", "Package": package, "Test": name})
            events.append({"Action": "fail" if failure else "pass", "Package": package})
            return "\n".join(json.dumps(event) for event in events)


        def source_contract_output(self):
            # Exercise the real unittest reporter, then its observed Windows
            # forwarding forms. No native verdict is represented by this log.
            class Original(unittest.TestCase):
                def test_first(self): pass
                def test_second(self): pass
                def test_third(self): pass
                def test_fourth(self): pass
                def test_fifth(self): pass
            output = io.StringIO()
            result = unittest.TextTestRunner(stream=output, verbosity=2).run(
                unittest.defaultTestLoader.loadTestsFromTestCase(Original))
            self.assertTrue(result.wasSuccessful())
            self.assertEqual(result.testsRun, 5)
            return output.getvalue()

        def test_original_source_contract_accepts_windows_line_boundaries(self):
            original = self.source_contract_output()
            for ending in ("\n", "\r\n", "\r\r\n"):
                with self.subTest(ending=repr(ending)):
                    captured = original.replace("\n", ending)
                    require_source_contract(captured, 0)
                    self.assertEqual(captured, original.replace("\n", ending))

        def test_original_source_contract_rejects_incomplete_or_failed_receipts(self):
            original = self.source_contract_output()
            result = next(line for line in original.splitlines() if line.endswith(" ... ok"))
            for name, output, status in (
                    ("failed-exit", original, 1), ("signal", original, -15),
                    ("timeout", original, 124), ("missing-test", original.replace(result+"\n", "", 1), 0),
                    ("duplicate-test", original.replace(result+"\n", result+"\n"+result+"\n", 1), 0),
                    ("failed-test", original.replace(" ... ok", " ... FAIL", 1), 0),
                    ("skipped-test", original.replace(" ... ok", " ... skipped 'unavailable'", 1), 0),
                    ("missing-summary", re.sub(r"Ran 5 tests in [^\n]+\n", "", original), 0),
                    ("wrong-count", original.replace("Ran 5 tests", "Ran 4 tests"), 0),
                    ("duplicate-summary", original.replace("Ran 5 tests", "Ran 5 tests in 0.001s\nRan 5 tests"), 0),
                    ("missing-ok", original.replace("\nOK\n", "\n"), 0),
                    ("duplicate-ok", original+"OK\n", 0),
                    ("late-failure", original+"FAILED (errors=1)\n", 0),
                    ("forged-ok", original+"FAILED (errors=1)\nOK\n", 0)):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    require_source_contract(output.replace("\n", "\r\r\n"), status)


        def test_original_selection_binds_both_clean_checkouts_and_suite(self):
            with tempfile.TemporaryDirectory() as temporary:
                work=Path(temporary);source=work/"candidate";source.mkdir()
                output=work/"validation"/"tests";output.parent.mkdir()
                record=dict(schema=1,suite="windows-source-retirement",repository="Eabusham2/router-vpn",
                    workflow_ref="refs/heads/main",validation_scope="read-only-source-candidate",
                    validator_sha="a"*40,validator_tree="b"*40,base_sha="a"*40,base_tree="b"*40,
                    source_sha="e"*40,source_tree="f"*40)
                path=output.parent/"selection.json"
                def git(root,*args):
                    if args==("status","--porcelain","--untracked-files=all"):return b""
                    if args==("rev-parse","HEAD"):return (record["source_sha"] if root==source else record["validator_sha"]).encode()
                    if args==("rev-parse","HEAD^{tree}"):return (record["source_tree"] if root==source else record["validator_tree"]).encode()
                    raise AssertionError(args)
                path.write_text(json.dumps(record))
                with patch.object(CLOCK,"git",side_effect=git):
                    self.assertEqual(selected_identity(source,record["source_sha"],output)[0],record)
                    for key,value in (("suite","other"),("source_sha","c"*40),("validator_sha","c"*40),
                            ("source_tree","d"*40),("repository","other/repo"),("workflow_ref","refs/heads/other")):
                        with self.subTest(key=key):
                            path.write_text(json.dumps(dict(record,**{key:value})))
                            with self.assertRaises(ValueError):selected_identity(source,record["source_sha"],output)
                    path.write_text(json.dumps(record))
                    with patch.object(CLOCK,"git",return_value=b"dirty"):
                        with self.assertRaises(ValueError):selected_identity(source,record["source_sha"],output)
                    path.unlink()
                    with self.assertRaises(ValueError):selected_identity(source,record["source_sha"],output)

        def test_exact_inventory_and_original_case(self):
            self.assertEqual([len(item[3]) for item in BASELINES], [8, 7, 10])
            self.assertEqual(len(CONTROLS), 3)
            self.assertIn("TestRouterVPNNodeMTUNativeBoxCloseFailureRemainsUnacknowledged", BOX_CASES)
            self.assertEqual(FAILED_CASE, "max-quic-awg/off/packet-peer")

        def test_matching_host_and_original_race_boundary(self):
            for target, machine in (("windows/amd64", "AMD64"), ("windows/arm64", "ARM64")):
                arch = target.split("/")[1]
                env = {"GOOS": "windows", "GOARCH": arch, "CGO_ENABLED": "1"}
                self.assertEqual(require_host(target, "Windows", machine, env, arch), ["-race"] if arch == "amd64" else [])
                for wrong in ({**env, "CGO_ENABLED": "0"}, {**env, "GOARCH": "foreign"}, {**env, "GOOS": "linux"}):
                    with self.assertRaises(ValueError):
                        require_host(target, "Windows", machine, wrong, arch)
                with self.assertRaises(ValueError):
                    require_host(target, "Linux", machine, env, arch)
                with self.assertRaises(ValueError):
                    require_host(target, "Windows", "foreign", env, arch)

        def test_real_verdict_parser_accepts_complete_original_order(self):
            self.assertTrue(parse(self.events(SOURCE_CASES), "./routervpn/desktoppt", SOURCE_CASES, 0, True)["accepted"])

        def test_missing_duplicate_failed_skipped_reordered_unjoined_reject(self):
            good = self.events(SOURCE_CASES)
            bad = [self.events(SOURCE_CASES[:-1]), self.events(SOURCE_CASES + SOURCE_CASES[:1]),
                   self.events(SOURCE_CASES, failure=True), good.replace('"Action": "pass"', '"Action": "skip"', 1),
                   "\n".join(reversed(good.splitlines())), good + "\npanic: bounded failure\n", good + "\nWARNING: DATA RACE\n"]
            for output in bad:
                with self.assertRaises(ValueError):
                    parse(output, "./routervpn/desktoppt", SOURCE_CASES, 0, True)
            for status, joined in ((1, True), (124, True), (0, False)):
                with self.assertRaises(ValueError):
                    parse(good, "./routervpn/desktoppt", SOURCE_CASES, status, joined)

        def test_control_requires_real_expected_failure_and_exact_witness(self):
            names = (SOURCE_ROOT, SOURCE_ROOT + "/foreign-policy")
            witness = CONTROLS[1][5]
            raw = self.events(names, failure=True, witness=witness)
            self.assertTrue(parse(raw, "./routervpn/desktoppt", names, 1, True, witness=witness, leaf=names[1])["accepted"])
            for value, code in ((raw, 0), (raw, 2), (raw.replace(witness, "unrelated failure"), 1),
                                (raw + "\n[build failed]\n", 1), (raw + "\npanic: test timed out\n", 1)):
                with self.assertRaises(ValueError):
                    parse(value, "./routervpn/desktoppt", names, code, True, witness=witness, leaf=names[1])

        def test_max_receipt_cannot_drop_failed_case_or_native_scope(self):
            module = Mock()
            module.MAX.TRAFFIC = {"QUIC": ("original-positive",)}
            module.MAX.CREDENTIALS = {"QUIC": (FAILED_CASE,)}
            sha = "a" * 40
            good = {"schema": 2, "target": "windows/arm64", "repository": {"commit": sha, "clean": True},
                    "execution_suite": "quic", "prospective": False, "native_firewall": "actual-appid-scoped-wfp",
                    "native_socket_source": "actual-isolated-token", "private_key_workspace_removed": True,
                    "traffic_cases": module.MAX.TRAFFIC, "credential_cases": module.MAX.CREDENTIALS}
            verify_max(good, "windows/arm64", sha, module)
            for key, value in (("prospective", True), ("private_key_workspace_removed", False),
                               ("execution_suite", "tls"), ("native_firewall", "modeled"),
                               ("credential_cases", {"QUIC": ()}), ("traffic_cases", {"QUIC": ()})):
                with self.assertRaises(ValueError):
                    verify_max({**good, key: value}, "windows/arm64", sha, module)
    return unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Contracts)).wasSuccessful()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--source-sha")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--target", choices=tuple(TARGETS))
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    if args.self_test:
        return 0 if self_tests() else 1
    if not all((args.source, args.source_sha, args.output, args.target)):
        parser.error("--source --source-sha --output and --target are required")
    validate(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
