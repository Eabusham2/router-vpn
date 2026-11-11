#!/usr/bin/env python3
"""Run the desktop reference for captured Local SOCKS5 -> REALITY/Vision.

The focused mobile parser is mandatory in the existing non-peer libbox gate.
This separately bounded stage uses the prepared desktop source and executes only
the SOCKS/REALITY reference. Existing complete graph and peer gates remain.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PIN = "1ac1a339cb1223e9c70eae14c44411c75033c02d"
TOOLCHAIN = "go1.26.3"
TAGS = "with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego"
FIXTURE = "socks5--final-reality-vision.json"
CORE_PARENT = "TestImportedEntrySOCKSRealityVisionCapturedGraphs"
CORE = (CORE_PARENT, CORE_PARENT + "/default-home")
PEER_PARENT = "TestRouterVPNImportedSOCKSRealityVisionNativeTraffic"
PEER_CASES = (
    "success", "entry-auth", "auth-downgrade", "wrong-entry-ip",
    "final-reality-key", "final-user", "final-route", "dns-route",
    "final-identity", "final-token", "cancel", "close-owner",
)
PEERS = (PEER_PARENT,) + tuple(PEER_PARENT + "/" + name for name in PEER_CASES)
REFERENCE_DETECTOR_TESTS = (
    "TestReferenceDetectorRequiresEveryCapturedCompletion",
    "TestReferenceDetectorCancellationJoinsOriginalOwner",
    "TestReferenceDetectorRejectsUncapturedConfiguration",
)
REFERENCE_STARTUP_TESTS = (
    "TestRouterVPNDesktopNodeXrayStartupRecords",
    "TestRouterVPNDesktopNodeXrayDetectorRecords",
)


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


IMPORTED = module("routervpn_socks_xray_imported", "test_mobile_imported_entry.py")
XRAY = module("routervpn_socks_xray_preparation", "prepare-apple-xray.py")
DESKTOP = module("routervpn_socks_xray_desktop", "prepare-desktop-external.py")
RELAY = DESKTOP.RELAY


LAYER_CORE_PARENT = "TestImportedEntrySOCKSRealityVisionIndependentLayers"
LAYER_CORE = (LAYER_CORE_PARENT,) + tuple(LAYER_CORE_PARENT + "/" + IMPORTED.socks_label("reality-vision", a, b)
    for a in IMPORTED.LAYERS for b in IMPORTED.LAYERS)
LAYER_PEER_PARENT = "TestRouterVPNImportedSOCKSRealityVisionLayerTraffic"
LAYER_PEER_CASES = {}
for entry in IMPORTED.LAYERS:
    for final in IMPORTED.LAYERS:
        if not entry and not final:
            continue
        faults = ["success", "cancel", "close-owner"]
        if entry: faults.append("entry-layer-key")
        if entry == "aes-256-gcm+xor-whitening": faults.append("entry-layer-whitening")
        if final: faults.append("final-layer-key")
        if final == "aes-256-gcm+xor-whitening": faults.append("final-layer-whitening")
        LAYER_PEER_CASES[IMPORTED.socks_label("reality-vision", entry, final)] = faults
LAYER_PEERS = tuple(sorted(IMPORTED.names({LAYER_PEER_PARENT:
    [name for label, faults in LAYER_PEER_CASES.items() for name in [label, *(label + "/" + fault for fault in faults)]]})))


def failed_native_excerpt(raw):
    # Large test2json inventories end with thousands of verdict records. The
    # original assertion can be far outside a tail-only exception. Preserve
    # bounded output from the actual failed leaves, without changing verdicts.
    def events():
        for line in raw.splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                yield value

    failed = []
    for event in events():
        name = event.get("Test")
        if event.get("Action") == "fail" and isinstance(name, str) and name and name not in failed:
            failed.append(name)
    leaves = [name for name in failed if not any(other.startswith(name + "/") for other in failed)]
    captured = {name: "" for name in leaves[:4]}
    if not captured:
        return raw[-24000:]
    for event in events():
        name, output = event.get("Test"), event.get("Output")
        if isinstance(name, str) and name in captured and isinstance(output, str):
            captured[name] = (captured[name] + output)[-4000:]
    context = "Failed native test output (bounded):\n" + "\n".join(
        name + ":\n" + output for name, output in captured.items())
    context = context[:16000]
    separator = "\nNative process tail:\n"
    return context + separator + raw[-(24000 - len(context) - len(separator)):]


def require_verdicts(raw, status, expected):
    if status:
        raise ValueError("Scoped SOCKS REALITY execution failed:\n" + failed_native_excerpt(raw))
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("Action") in ("fail", "skip"):
            raise ValueError("Scoped SOCKS REALITY contains an unsuccessful verdict")
        output = event.get("Output", "")
        if "panic:" in output or "fatal error:" in output or "DATA RACE" in output:
            raise ValueError("Scoped SOCKS REALITY contains an aborted native process")
    IMPORTED.require_verdicts(raw, set(expected))


def run_command(command, cwd, env, timeout):
    result = subprocess.run([str(part) for part in command], cwd=cwd, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    return result.returncode, result.stdout


def check_file(path, expected, records, name):
    if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
        raise ValueError("Scoped SOCKS REALITY source differs: " + name)
    records[name] = hashlib.sha256(expected).hexdigest()


def reference_copies():
    return {
        "mobile/applexray/outbound.go.tmpl": "protocol/routervpnxray/outbound.go",
        "mobile/desktop/node_imported_socks_xray_test.go.tmpl": "protocol/routervpnamnezia/routervpn_imported_socks_xray_test.go",
        "mobile/desktop/node_imported_socks_entry_test.go.tmpl": "protocol/routervpnamnezia/routervpn_imported_socks_entry_test.go",
        "mobile/desktop/node_xray_peer_test.go.tmpl": "protocol/routervpnamnezia/routervpn_desktop_node_xray_peer_test.go",
        "mobile/desktop/node_layer_peer_test.go.tmpl": "protocol/routervpnamnezia/routervpn_desktop_node_layer_peer_test.go",
        "mobile/desktop/node_peer_test.go.tmpl": "protocol/routervpnamnezia/routervpn_desktop_node_peer_test.go",
    }


def check_reference_templates(vendor, records):
    for source, target in reference_copies().items():
        check_file(vendor / target, (ROOT / source).read_bytes(), records, target)


def checked_sources(vendor):
    if subprocess.check_output(["git", "-C", str(vendor), "rev-parse", "HEAD"], text=True).strip() != PIN:
        raise ValueError("Scoped SOCKS REALITY requires the exact shipping core")
    # Desktop peer preparation deliberately does not install the mobile bridge
    # or parser. Preserve the original peer closure, then bind this reference.
    IMPORTED.checked_sources(vendor, True)
    records = RELAY.OBSERVATION.verify(vendor)
    check_reference_templates(vendor, records)
    # Mirror the actual desktop relay producer and its separate DNS projection.
    # Loading a validation helper never installs mobile services into this tree.
    for package in RELAY.PACKAGES:
        for source in sorted((ROOT / "internal" / package).glob("*.go")):
            if package == "applexray" and source.name == "preparation_test.go":
                continue
            if source.name == "core_config_test.go":
                continue
            raw = RELAY.OBSERVATION.rewrite(source.read_bytes())
            for name in RELAY.PACKAGES:
                raw = raw.replace(('"router-vpn/internal/' + name + '"').encode(),
                                  ('"github.com/sagernet/sing-box/experimental/libbox/routervpn/' + name + '"').encode())
            target = "experimental/libbox/routervpn/" + package + "/" + source.name
            check_file(vendor / target, raw, records, target)
    for source in sorted((ROOT / "internal/dnsmeasure").glob("*.go")):
        target = "experimental/libbox/routervpn/dnsmeasure/" + source.name
        # Independently retain every source byte except the native clock's
        # declared import relocation; do not bless arbitrary prepared copies.
        raw = source.read_bytes().replace(
            b'"router-vpn/internal/hopmeasure"',
            b'"github.com/sagernet/sing-box/experimental/libbox/routervpn/hopmeasure"')
        check_file(vendor / target, raw, records, target)
    # SOCKS itself is the pinned real outbound. No copied test implementation
    # substitutes for its authentication, CONNECT or detour handling.
    paths = subprocess.check_output(
        ["git", "-C", str(vendor), "ls-tree", "-r", "--name-only", PIN, "--", "protocol/socks"], text=True).splitlines()
    expected_paths = {name for name in paths if name.endswith(".go")}
    actual_paths = {path.relative_to(vendor).as_posix() for path in (vendor / "protocol/socks").rglob("*.go")}
    if not expected_paths or actual_paths != expected_paths:
        raise ValueError("Scoped SOCKS REALITY lost the original SOCKS source set")
    for name in sorted(expected_paths):
        raw = subprocess.check_output(["git", "-C", str(vendor), "show", PIN + ":" + name])
        check_file(vendor / name, raw, records, name)
    for path in (
        ROOT / "deploy/test_mobile_imported_socks_xray.py",
        ROOT / "deploy/test_mobile_imported_socks_xray_runner.py",
        ROOT / "deploy/test_mobile_imported_entry.py",
        ROOT / "deploy/prepare-desktop-external.py",
        ROOT / "deploy/prepare-mobile-multihop.py",  # original peer verifier's relocation helper
        ROOT / "deploy/build-native-runtime.py",
        *RELAY.inputs(),
        *DESKTOP.inputs(),
        *XRAY.sources(),
    ):
        if path.is_symlink() or not path.is_file():
            raise ValueError("Scoped SOCKS REALITY lost an original preparation input")
        records["gate/" + path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return records


def captured_source_matrix(fixtures, original):
    if {path.name for path in fixtures.iterdir()} != IMPORTED.SOCKS_XRAY_FILES or any(path.is_symlink() or not path.is_file() for path in fixtures.iterdir()):
        raise ValueError("Scoped SOCKS REALITY source exporter changed its exact nine-file scope")
    captured = {name: (fixtures / name).read_bytes() for name in sorted(IMPORTED.SOCKS_XRAY_FILES)}
    if captured[FIXTURE] != original:
        raise ValueError("SOCKS REALITY layer export replaced the original Off/Off capture")
    return captured


def checked_xray(source):
    XRAY.checkout(source, XRAY.XRAY_PIN, "github.com/xtls/xray-core")
    original = subprocess.check_output(
        ["git", "-C", str(source), "ls-tree", "-r", "--name-only", XRAY.XRAY_PIN], text=True).splitlines()
    original = {name for name in original if name.endswith(".go") or name in ("go.mod", "go.sum")}
    generated = {
        "proxy/routervpn_vision_state_test.go":
            (ROOT / "mobile/applexray/vision_state_test.go.tmpl").read_bytes(),
        "core/routervpn_packet.go": (ROOT / "mobile/applexray/core_packet.go.tmpl").read_bytes(),
        "transport/internet/routervpn_scoped_dialer.go":
            (ROOT / "mobile/applexray/scoped_dialer.go.tmpl").read_text().replace("\n", os.linesep).encode(),
        "transport/internet/routervpn_scoped_dialer_test.go":
            (ROOT / "mobile/applexray/scoped_dialer_test.go.tmpl").read_text().replace("\n", os.linesep).encode(),
        "transport/internet/splithttp/routervpn_response_test.go":
            (ROOT / "mobile/applexray/wait_reader_test.go.tmpl").read_bytes(),
    }
    actual = {path.relative_to(source).as_posix() for path in source.rglob("*.go")} | {"go.mod", "go.sum"}
    if actual != original | set(generated):
        raise ValueError("Scoped SOCKS REALITY lost the exact prepared Xray source set")
    records = {}
    for relative in sorted(original):
        raw = subprocess.check_output(["git", "-C", str(source), "show", XRAY.XRAY_PIN + ":" + relative])
        text = raw.decode()
        patched = False
        for policy in (XRAY.SHARED.DATAGRAMS, XRAY.SHARED.CONNECTIONS, XRAY.SHARED.VISION):
            if relative in policy.PATCHES:
                text = policy.patch_text(relative, text)
                patched = True
        if relative in ("proxy/vless/outbound/outbound.go", "proxy/vless/inbound/inbound.go"):
            text = XRAY.patch_vision_buffers(text, inbound=relative.endswith("/inbound.go"))
            patched = True
        if relative == "transport/internet/dialer.go":
            text = XRAY.NATIVE_DIALER.patch(text)
            patched = True
        if relative == "transport/internet/reality/reality.go":
            anchor = "\tif !uConn.Verified {"
            guard = '\tif !uConn.Verified && core.RouterVPNIsNativeContext(ctx) {\n\t\t_ = uConn.Close()\n\t\treturn nil, errors.New("REALITY: native tunnel rejected an unverified server")\n\t}\n'
            if text.count(anchor) != 1:
                raise ValueError("Scoped SOCKS REALITY lost the pinned REALITY authentication boundary")
            text = text.replace(anchor, guard + anchor, 1)
            patched = True
        expected = text.replace("\n", os.linesep).encode() if patched else raw
        check_file(source / relative, expected, records, relative)
    for relative, raw in generated.items():
        check_file(source / relative, raw, records, relative)
    return records


def record_digest(records):
    return hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def compile_image(compiler, vendor, workspace, env, package, name):
    binary = workspace / (name + (".exe" if env["GOOS"] == "windows" else ""))
    status, output = run_command(
        [compiler, "test", "-mod=readonly", "-race", "-c", "-ldflags=-checklinkname=0",
         "-tags", TAGS, "-o", binary, package], vendor, env, 600)
    if status or binary.is_symlink() or not binary.is_file():
        raise ValueError("Scoped SOCKS REALITY native image did not compile:\n" + output[-24000:])
    return binary, hashlib.sha256(binary.read_bytes()).hexdigest()


def execute_image(compiler, vendor, env, image, digest, package, parent, expected, timeout=90):
    if image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
        raise ValueError("Scoped SOCKS REALITY image changed before execution")
    status, output = run_command(
        [compiler, "tool", "test2json", "-t", "-p", package, image,
         "-test.v", "-test.run=^" + parent + "$", "-test.count=1", "-test.timeout=" + str(timeout) + "s"],
        vendor, env, timeout + 15)
    require_verdicts(output, status, expected)
    if image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
        raise ValueError("Scoped SOCKS REALITY image changed during execution")
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    return {"sha256": digest, "verdicts": list(expected)}


def reference_instrumentation(source, workspace):
    # The pinned reference CLI stays byte-exact on disk. Declare the two extra
    # files explicitly in the build overlay and bind every byte in its receipt.
    replacements, records = {}, {}
    for template, name in (("reference_readiness.go.tmpl", "routervpn_reference_readiness.go"),
                           ("reference_readiness_test.go.tmpl", "routervpn_reference_readiness_test.go")):
        original = ROOT / "mobile/applexray" / template
        destination = workspace / name
        target = source / "main" / name
        if original.is_symlink() or not original.is_file() or target.exists() or target.is_symlink():
            raise ValueError("Reference detector instrumentation lost its exact source boundary")
        raw = original.read_bytes()
        destination.write_bytes(raw)
        replacements[str(target)] = str(destination)
        records["mobile/applexray/" + template] = hashlib.sha256(raw).hexdigest()
    overlay = workspace / "reference-detector-overlay.json"
    overlay.write_text(json.dumps({"Replace": replacements}, sort_keys=True, separators=(",", ":")))
    records["overlay_sha256"] = hashlib.sha256(overlay.read_bytes()).hexdigest()
    return overlay, records


def check_reference_instrumentation(source, workspace, overlay, records):
    if overlay.is_symlink() or not overlay.is_file() or hashlib.sha256(overlay.read_bytes()).hexdigest() != records["overlay_sha256"]:
        raise ValueError("Reference detector build overlay changed")
    expected = {}
    for template, name in (("reference_readiness.go.tmpl", "routervpn_reference_readiness.go"),
                           ("reference_readiness_test.go.tmpl", "routervpn_reference_readiness_test.go")):
        original = ROOT / "mobile/applexray" / template
        copied = workspace / name
        target = source / "main" / name
        if original.is_symlink() or copied.is_symlink() or not copied.is_file() or target.exists() or target.is_symlink():
            raise ValueError("Reference detector source identity changed")
        raw = original.read_bytes()
        if copied.read_bytes() != raw or hashlib.sha256(raw).hexdigest() != records["mobile/applexray/" + template]:
            raise ValueError("Reference detector copied source changed")
        expected[str(target)] = str(copied)
    if json.loads(overlay.read_text()) != {"Replace": expected}:
        raise ValueError("Reference detector overlay contains an undeclared source")


def build_reference(compiler, vendor, workspace, env):
    status, output = run_command(
        [compiler, "list", "-m", "-mod=readonly", "-json", "github.com/xtls/xray-core"], vendor, env, 30)
    if status:
        raise ValueError("Scoped SOCKS REALITY lost its Xray dependency:\n" + output[-8192:])
    source = Path(json.loads(output).get("Dir", ""))
    if not source.is_absolute() or source.is_symlink():
        raise ValueError("Scoped SOCKS REALITY has no original prepared Xray directory")
    before = checked_xray(source)
    overlay, instrumentation = reference_instrumentation(source, workspace)
    status, output = run_command(
        [compiler, "test", "-mod=readonly", "-race", "-json", "-overlay=" + str(overlay),
         "-ldflags=-checklinkname=0", "./main", "-run", "^TestReferenceDetector", "-count=1", "-timeout=30s"],
        source, env, 600)
    require_verdicts(output, status, REFERENCE_DETECTOR_TESTS)
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    binary = workspace / ("xray-reference.exe" if env["GOOS"] == "windows" else "xray-reference")
    status, output = run_command(
        [compiler, "build", "-mod=readonly", "-race", "-trimpath", "-overlay=" + str(overlay),
         "-ldflags=-checklinkname=0", "-o", binary, "./main"],
        source, env, 600)
    if status or binary.is_symlink() or not binary.is_file() or checked_xray(source) != before:
        raise ValueError("Scoped SOCKS REALITY actual Xray reference did not build:\n" + output[-24000:])
    check_reference_instrumentation(source, workspace, overlay, instrumentation)
    env["ROUTER_VPN_XRAY_TEST_BINARY"] = str(binary)
    env["ROUTER_VPN_XRAY_REFERENCE_DETECTOR_READY"] = "1"
    return source, before, binary, hashlib.sha256(binary.read_bytes()).hexdigest(), overlay, instrumentation


def run(vendor):
    vendor = vendor.resolve(strict=True)
    compiler_raw = shutil.which("go")
    if not compiler_raw:
        raise ValueError("Scoped SOCKS REALITY requires the shipping Go compiler")
    compiler = Path(compiler_raw).resolve(strict=True)
    env = dict(os.environ, GOTOOLCHAIN=TOOLCHAIN, GOWORK="off")
    for key, value in (("GOMAXPROCS", "1"), ("GOGC", "5"), ("GOMEMLIMIT", "256MiB")):
        env.setdefault(key, value)
    if subprocess.check_output([compiler, "env", "GOVERSION"], text=True, env=env).strip() != TOOLCHAIN:
        raise ValueError("Scoped SOCKS REALITY compiler is not the pinned shipping toolchain")
    for key in ("GOOS", "GOARCH"):
        env[key] = subprocess.check_output([compiler, "env", "GOHOST" + key[2:]], text=True, env=env).strip()
    before = checked_sources(vendor)
    subprocess.run([sys.executable, ROOT / "deploy/test_mobile_imported_socks_xray_runner.py"],
                   cwd=ROOT, env=env, check=True, timeout=30)
    subprocess.run([compiler, "mod", "verify"], cwd=vendor, env=env, check=True, timeout=120)
    receipt = {"scope": "desktop-reference-only", "core_pin": PIN, "toolchain": TOOLCHAIN,
               "native_parser": False, "native_reference": False,
               "source_count": len(before), "source_sha256": record_digest(before)}
    with tempfile.TemporaryDirectory(prefix="routervpn-imported-socks-reality-") as temporary:
        workspace = Path(temporary).resolve()
        fixtures = workspace / "sources"
        fixtures.mkdir()
        env["ROUTERVPN_IMPORTED_ENTRY_FIXTURES"] = str(fixtures)
        env["ROUTERVPN_REQUIRE_IMPORTED_ENTRY_FIXTURES"] = "1"
        status, output = run_command(
            [compiler, "test", "-mod=readonly", "-race", "-json", "./internal/mobilemultihop",
             "-run", "^" + CORE_PARENT + "$/^default-home$", "-count=1", "-timeout=30s"],
            ROOT, env, 240)
        require_verdicts(output, status, CORE)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if {path.name for path in fixtures.iterdir()} != {FIXTURE} or (fixtures / FIXTURE).is_symlink() or not (fixtures / FIXTURE).is_file():
            raise ValueError("SOCKS REALITY original exporter changed its exact one-file scope")
        original_fixture = (fixtures / FIXTURE).read_bytes()
        # Retain the original Off/Off exporter and require every independent
        # layer capture from the shared compiler before executing native peers.
        status, output = run_command(
            [compiler, "test", "-mod=readonly", "-race", "-json", "./internal/mobilemultihop",
             "-run", "^" + LAYER_CORE_PARENT + "$", "-count=1", "-timeout=30s"],
            ROOT, env, 240)
        require_verdicts(output, status, LAYER_CORE)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        original_fixtures = captured_source_matrix(fixtures, original_fixture)
        receipt["fixture_sha256"] = hashlib.sha256(original_fixtures[FIXTURE]).hexdigest()
        receipt["layer_fixtures_sha256"] = {name: hashlib.sha256(raw).hexdigest() for name, raw in original_fixtures.items()}
        xray, xray_before, reference, reference_digest, overlay, instrumentation = build_reference(compiler, vendor, workspace, env)
        native, native_digest = compile_image(compiler, vendor, workspace, env, "./protocol/routervpnamnezia", "socks-reality-peers")
        if checked_sources(vendor) != before or checked_xray(xray) != xray_before:
            raise ValueError("Scoped SOCKS REALITY source changed during peer build")
        receipt["reference_startup"] = execute_image(compiler, vendor, env, native, native_digest,
            "routervpnamnezia", "TestRouterVPNDesktopNodeXray(Startup|Detector)Records", REFERENCE_STARTUP_TESTS)
        receipt["peer"] = execute_image(compiler, vendor, env, native, native_digest,
                                        "routervpnamnezia", PEER_PARENT, PEERS)
        receipt["peer_layers"] = execute_image(compiler, vendor, env, native, native_digest,
            "routervpnamnezia", LAYER_PEER_PARENT, LAYER_PEERS, timeout=180)
        if reference.is_symlink() or hashlib.sha256(reference.read_bytes()).hexdigest() != reference_digest or checked_xray(xray) != xray_before:
            raise ValueError("Scoped SOCKS REALITY reference source or executable changed during execution")
        check_reference_instrumentation(xray, workspace, overlay, instrumentation)
        receipt["reference"] = {"pin": XRAY.XRAY_PIN, "sha256": reference_digest,
                                "source_sha256": record_digest(xray_before), "source_count": len(xray_before),
                                "detector_instrumentation": instrumentation,
                                "detector_verdicts": list(REFERENCE_DETECTOR_TESTS)}
        receipt["native_reference"] = True
        if captured_source_matrix(fixtures, original_fixture) != original_fixtures or checked_sources(vendor) != before:
            raise ValueError("Scoped SOCKS REALITY original capture or shipping source changed during execution")
    print(json.dumps(receipt, sort_keys=True), flush=True)
    print("Scoped SOCKS/REALITY receipts cover only these nine Local independent-layer desktop graphs. The mobile parser has its own required gate; OS/device and host Connected acceptance remain separate.", flush=True)
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vendor", type=Path)
    parser.add_argument("--reference-only", action="store_true", required=True)
    arguments = parser.parse_args()
    run(arguments.vendor)
