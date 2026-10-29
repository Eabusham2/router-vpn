#!/usr/bin/env python3
"""Run actual Windows compiler/factory/WFP/selected-DNS bootstrap composition.

This bounded gate uses the exact prepared native core. Only test compilation
adds executable-scoped firewall isolation and visibility into the real owned
resolver/kernel objects. No ordinary binary receives a scope/admission switch.
The existing harmless TUN fixture avoids changing the CI host's routes, so this
is bootstrap evidence, not a real TUN, Tor circuit, Connected or device test.

--prospective overlays the explicit static Windows admission diff while the
public compiler remains closed. Before opening delivery, remove that argument
and rerun the same gate against the unmodified admitted source.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "windows_bootstrap_identity_gate", ROOT / "deploy/test_desktop_windows_identity.py")
IDENTITY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(IDENTITY)
PREP = IDENTITY.PREP
RESOURCES = ROOT / "deploy/fixtures/windows-physical-bootstrap"
TEST = "TestRouterVPNDesktopTorWindowsPhysicalBootstrapComposition"
TAGS = ("with_wireguard", "with_gvisor", "with_quic", "with_utls", "with_openvpn",
        "with_naive_outbound", "routervpn_native_pq", "with_purego",
        "routervpn_windows_physical_composition")


def sources(source):
    source, _, _, socket_records = IDENTITY.checked_sources(source)
    if source == ROOT:
        raise ValueError("Windows bootstrap composition requires the actual prepared native core")
    records = {"socket/" + name: value for name, value in socket_records.items()}
    for package in ("common", "mobiletor"):
        for path in sorted((ROOT / "internal" / package).glob("*.go")):
            if path.name.endswith("_test.go"):
                continue
            target = source / "routervpn" / package / path.name
            if path.is_symlink() or target.is_symlink() or not target.is_file():
                raise ValueError("Windows bootstrap lost a regular shipping source: " + str(path))
            expected = PREP.relocated_shared_source(path.read_bytes())
            if target.read_bytes() != expected:
                raise ValueError("Windows bootstrap source differs from shipping bytes: " + path.name)
            records[target.relative_to(source).as_posix()] = hashlib.sha256(expected).hexdigest()
    copies = PREP.pt_copies()
    PREP.preflight_pt_files(source, copies)
    for relative, expected in copies.items():
        path = source / relative
        if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
            raise ValueError("Windows bootstrap native composition differs: " + relative)
        records[relative] = hashlib.sha256(expected).hexdigest()
    registry = source / "include/registry.go"
    if PREP.pt_registry_source(registry.read_text(encoding="utf-8")) != registry.read_bytes():
        raise ValueError("Windows bootstrap native registrations are incomplete")
    records["include/registry.go"] = hashlib.sha256(registry.read_bytes()).hexdigest()
    for name in ("kernel_observer.go", "resolver_access.go", "bootstrap_test.go"):
        path = RESOURCES / name
        raw = path.read_bytes()
        if path.is_symlink() or not raw.startswith(b"//go:build windows && routervpn_windows_physical_composition\n"):
            raise ValueError("Windows bootstrap fixture escaped its compile-time test tag")
        records["fixture/" + name] = hashlib.sha256(raw).hexdigest()
    records["runner"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return source, records


def prospective_admission(bridge, policy, box):
    """Exact, reviewable static predicate change; unknown source is rejected."""
    helper = "func DesktopPhysicalBrokerSupported(targetOS string) bool {\n"
    if helper in policy:
        # The shared helper may already admit independently proved Darwin.
        # Preserve that exact current set; no arbitrary predicate is accepted.
        before = next((value for value in (
            helper + '\treturn targetOS == "linux"\n}',
            helper + '\treturn targetOS == "linux" || targetOS == "darwin"\n}',
        ) if policy.count(value) == 1), None)
        if before is None:
            raise ValueError("Prospective Windows bootstrap admission predicate changed")
        policy = IDENTITY.replace_once(policy, before, before[:-2] + ' || targetOS == "windows"\n}')
        if bridge.count("!DesktopPhysicalBrokerSupported(targetOS)") != 1 or bridge.count("DesktopPhysicalBrokerSupported(targetOS) && kill") != 1 or \
                policy.count("!DesktopPhysicalBrokerSupported(p.metadata.TargetOS)") != 1 or \
                box.count("!mobiletor.DesktopPhysicalBrokerSupported(runtime.GOOS)") != 1:
            raise ValueError("Prospective Windows bootstrap lost the shared OS admission call sites")
        return bridge, policy, box
    bridge = IDENTITY.replace_once(bridge, '(targetOS != "linux" || profile["multihop_enabled"] == true)',
                                   '(!DesktopPhysicalBrokerSupported(targetOS) || profile["multihop_enabled"] == true)')
    bridge = IDENTITY.replace_once(bridge, 'predecessor == nil && targetOS == "linux" && kill != "off"',
                                   'predecessor == nil && DesktopPhysicalBrokerSupported(targetOS) && kill != "off"')
    policy = IDENTITY.replace_once(policy, 'p.metadata.TargetOS != "linux"',
                                   '!DesktopPhysicalBrokerSupported(p.metadata.TargetOS)')
    anchor = 'const DesktopPhysicalOutboundTag = "routervpn-tor-physical-egress"\n'
    policy = IDENTITY.replace_once(policy, anchor, anchor + '\n' + helper +
                                   '\treturn targetOS == "linux" || targetOS == "windows"\n}\n')
    box = IDENTITY.replace_once(box, 'runtime.GOOS != "linux"',
                                '!mobiletor.DesktopPhysicalBrokerSupported(runtime.GOOS)')
    return bridge, policy, box


def overlay(source, workspace, prospective):
    replacements = {}

    def replace(relative, raw):
        path = workspace / (str(len(replacements)) + ".go")
        path.write_bytes(raw)
        replacements[str(source / relative)] = str(path)

    if prospective:
        paths = ("routervpn/mobiletor/desktop_bridge.go", "routervpn/mobiletor/desktop_physical_policy.go",
                 "routervpn_desktop_tor_box_physical.go")
        changed = prospective_admission(*(source.joinpath(path).read_text(encoding="utf-8") for path in paths))
        for path, body in zip(paths, changed):
            replace(path, body.encode())
    policy = source / "routervpn/mobiletor/desktop_socket_windows_policy.go"
    raw = IDENTITY.replace_once(policy.read_text(encoding="utf-8"),
                                "return newDesktopWindowsSocketPolicy(ctx, capture, options, nil)",
                                "return desktopWindowsCompositionConstruct(ctx, capture, options)")
    replace(policy.relative_to(source), raw.encode())
    # The production callback deliberately redacts the transport cause. This
    # explicit fixture has only its public selected resolver; preserve the
    # identical failure branch and retain its cause in this test compilation.
    network = source / "routervpn/desktoppt/network.go"
    raw = IDENTITY.replace_once(network.read_text(encoding="utf-8"),
                                'return nil, errors.New("Snowflake captured native DNS lookup failed")',
                                'return nil, errors.Join(errors.New("Snowflake captured native DNS lookup failed"), err)')
    replace(network.relative_to(source), raw.encode())
    for name, relative in (
        ("kernel_observer.go", "routervpn/mobiletor/desktop_socket_windows_composition_overlay.go"),
        ("resolver_access.go", "routervpn/desktoppt/tor_windows_composition_overlay.go"),
        ("bootstrap_test.go", "routervpn_windows_physical_composition_test.go"),
    ):
        if (source / relative).exists() or (source / relative).is_symlink():
            raise ValueError("Unowned bootstrap test file exists in the prepared core")
        replace(relative, (RESOURCES / name).read_bytes())
    path = workspace / "overlay.json"
    path.write_text(json.dumps({"Replace": replacements}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return path


def execute(source, go="go", *, prospective=False, env=None, bootstrap_only=False):
    if platform.system() != "Windows" or not IDENTITY.ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("Windows bootstrap composition requires an actual elevated Windows host")
    source, before = sources(source)
    compiler, captured, architecture = IDENTITY.selected_compiler(go, source, dict(os.environ if env is None else env))
    race = ["-race"] if architecture == "amd64" and not bootstrap_only else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    with tempfile.TemporaryDirectory(prefix="routervpn-windows-bootstrap-") as directory:
        workspace = Path(directory)
        selected = overlay(source, workspace, prospective)
        binary = workspace / "bootstrap.test.exe"
        command = [compiler, "test", "-c", "-mod=readonly", "-tags=" + ",".join(TAGS), *race,
                   "-ldflags=-checklinkname=0", "-overlay=" + str(selected), "-o", binary, "."]
        status, output = IDENTITY.run(command, cwd=source, env=captured, timeout=600)
        if status:
            raise ValueError("Windows bootstrap full native compilation failed:\n" + output[-32768:])
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        status, output = IDENTITY.run([binary, "-test.run=^" + TEST + "$", "-test.count=1", "-test.timeout=90s", "-test.v"],
                                      cwd=source, env=captured, timeout=105)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if status or "--- PASS: " + TEST + " (" not in output or "--- SKIP:" in output or "DATA RACE" in output:
            raise ValueError("Windows bootstrap did not prove its actual native DNS/kernel composition")
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest or sources(source)[1] != before:
            raise ValueError("Windows bootstrap source or binary changed during execution")
    label = "Prospective static admission overlay" if prospective else "Unmodified admitted compiler"
    print(label + ": exact Windows Box/factory/isolated-token/WFP/selected external DNS bootstrap passed. "
          "Actual TUN, Tor circuit, Connected, wrapper launch and device acceptance remain separate.", flush=True)


def standalone(go="go", *, prospective=False, native_test=None):
    """Prepare the same pinned sources for a focused CGO-disabled diagnostic.

    This does not build/publish packages, link PQ, or claim race verification.
    Matching native package builds separately invoke execute with their actual
    compiler, shipping tags, verified PQ archive and supported race setting.
    """
    if platform.system() != "Windows" or not IDENTITY.ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("Standalone native diagnostic requires actual elevated Windows")
    compiler, captured, _ = IDENTITY.selected_compiler(go, ROOT, dict(os.environ))
    spec = importlib.util.spec_from_file_location("windows_bootstrap_native_builder", ROOT / "deploy/build-native-runtime.py")
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    if native.run([compiler, "env", "GOVERSION"], env=captured) != native.TOOLCHAIN:
        raise ValueError("Standalone Windows bootstrap requires the pinned shipping compiler")
    captured["PATH"] = str(compiler.parent) + os.pathsep + captured.get("PATH", "")
    captured["CGO_ENABLED"] = "0"
    previous = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix="routervpn-windows-bootstrap-core-") as directory:
        workspace = Path(directory)
        source, xray = workspace / "core", workspace / "xray"
        try:
            # Existing preparation functions invoke bare go; bind all of them
            # to the already verified effective compiler in this private runner.
            os.environ.clear()
            os.environ.update(captured)
            native.checkout(source, "https://github.com/SagerNet/sing-box.git", native.PIN)
            native.checkout(xray, "https://github.com/XTLS/Xray-core.git", native.POLICY.XRAY.XRAY_PIN)
            native.pristine(source, native.PIN)
            native.pristine(xray, native.POLICY.XRAY.XRAY_PIN)
            native.POLICY.prepare_native(source, xray)
            native.PERFORMANCE.prepare(source)
            native.OPENVPN.prepare(source)
            native.EXTERNAL.prepare(source, go=str(compiler), env=captured)
            native.BUFFERS.prepare(source)
            native.run([compiler, "mod", "tidy"], cwd=source, env=captured)
            native.run([compiler, "mod", "verify"], cwd=source, env=captured)
            native.POLICY.AMNEZIA.verify(source)
            print("Standalone diagnostic: exact pinned native source, CGO disabled; no package/PQ/race claim.", flush=True)
            selected_test = execute if native_test is None else native_test
            selected_test(source, str(compiler), prospective=prospective, env=captured, bootstrap_only=True)
        finally:
            os.environ.clear()
            os.environ.update(previous)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--go", default="go")
    parser.add_argument("--prospective", action="store_true")
    parser.add_argument("--standalone", action="store_true")
    arguments = parser.parse_args()
    if arguments.standalone:
        if arguments.source is not None:
            parser.error("--standalone owns its fresh pinned source; do not supply another source")
        standalone(arguments.go, prospective=arguments.prospective)
    else:
        if arguments.source is None:
            parser.error("a prepared native source or --standalone is required")
        execute(arguments.source, arguments.go, prospective=arguments.prospective)
