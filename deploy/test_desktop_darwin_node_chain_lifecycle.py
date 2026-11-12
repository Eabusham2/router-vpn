#!/usr/bin/env python3
"""Required ordered Darwin child/source/component progress; no native utun claim."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TEST_TIMEOUT = "120s"
PROCESS_TIMEOUT = 600
PHASES = {
    "protocol/tun": {
        "TestRouterVPNDarwinNodeChainInboundRetirement": (
            "native-retry", "ambiguous-stack", "replacement-native", "cancel-after-stack",
            "bounded-waiter", "legacy-close", "never-started", "successor"),
        "TestRouterVPNDarwinNodeChainInboundAdmission": (
            "nil", "unbounded", "cancelled", "borrowed", "started", "namespace", "external", "unenabled"),
    },
    "adapter/inbound": {
        "TestRouterVPNTunDarwinOrderedManagerRetirement": (
            "retained-retry", "cancel-after-close", "foreign-tag", "unstarted-partial", "unrelated-reader"),
        "TestRouterVPNTunDarwinOrderedManagerAdmission": (
            "nil", "unbounded", "cancelled", "lifecycle", "access"),
    },
    "cmd/sing-box": {
        "TestRouterVPNNodeChainDarwinCommandFlags": (
            "physical-transfer-sha256", "physical-mtu", "journal-parent-handle", "journal-parent-image",
            "journal-pipe", "journal-capture-sha256", "linux-parent-channel", "linux-parent-directory",
            "linux-parent-capture", "exact-captured-arguments", "empty-family", "unknown-family"),
        "TestRouterVPNNodeChainDarwinManifestReplay": (
            "configured", "restored", "missing", "unprojected", "middle", "source", "config",
            "session", "platform", "graph", "ordinary"),
        "TestRouterVPNNodeChainDarwinNativeRetirementOrder": (
            "exact-order", "proof-retry", "tun-retry", "source-retry", "ambiguous-box",
            "cancel-after-source", "missing-manager", "partial-components"),
        "TestRouterVPNNodeChainDarwinNativeRetirementAdmission": ("nil", "unbounded", "cancelled", "locked"),
        "TestRouterVPNNodeChainDarwinStoppedReceipt": ("joined", "source-retry", "box-failure", "foreign-file", "foreign-workspace", "authenticated-ack"),
        "TestRouterVPNNodeChainDarwinOriginalControl": (
            "exact", "policy-pointer", "replacement-root", "late-source", "missing-authority", "capture", "handshake", "retiring"),
        "TestRouterVPNNodeChainDarwinEarlyStop": ("receipt-before-acquisition", "authenticated-before-run"),
        "TestRouterVPNNodeChainDarwinMeasurementStartup": (
            "absent", "request-regular", "request-directory", "request-symlink",
            "cancel-regular", "cancel-directory", "cancel-symlink",
            "result-regular", "result-directory", "result-symlink"),
        "TestRouterVPNNodeChainDarwinSelectionBinding": (
            "session", "source", "config", "uid", "device", "inode", "engine", "controller", "catalog", "inputs", "family"),
    },
    "experimental/libbox/routervpn/mobilemultihop": {
        "TestDesktopNodeReadyDarwinRequiresExactOrderedPolicy": ("configured", "restored", "ordinary-policy", "windows-utun", "linux-utun"),
        "TestDesktopNodeReadyDarwinPreservesOriginalDNSAndTUN": (
            "schema", "kind", "session", "source", "config", "transfer", "dns", "index",
            "mtu", "time", "query", "bound", "nan", "infinite", "cover-count", "cover-digest"),
        "TestDesktopNodeReadyDarwinRejectsForeignInterface": (
            "empty", "fixed", "missing-unit", "negative", "plus", "suffix", "unicode", "case", "newline"),
    },
}
COPIES = {
    "mobile/mtu/manager.go.tmpl": "adapter/inbound/routervpn_mtu.go",
    "mobile/mtu/tun.go.tmpl": "protocol/tun/routervpn_mtu.go",
    "mobile/desktop/tun_node_chain_retirement_darwin.go.tmpl": "protocol/tun/routervpn_node_chain_retirement_darwin.go",
    "mobile/desktop/tun_node_chain_retirement_darwin_test.go.tmpl": "protocol/tun/routervpn_node_chain_retirement_darwin_test.go",
    "mobile/desktop/inbound_node_chain_retirement_darwin_test.go.tmpl": "adapter/inbound/routervpn_node_chain_retirement_darwin_test.go",
    "mobile/desktop/node_chain_command.go.tmpl": "cmd/sing-box/routervpn_node_chain_command.go",
    "mobile/desktop/node_chain_control_other.go.tmpl": "cmd/sing-box/routervpn_node_chain_control_other.go",
    "mobile/desktop/node_chain_control_darwin.go.tmpl": "cmd/sing-box/routervpn_node_chain_control_darwin.go",
    "mobile/desktop/node_chain_run_darwin.go.tmpl": "cmd/sing-box/routervpn_node_chain_run_darwin.go",
    "mobile/desktop/node_chain_retirement_darwin.go.tmpl": "cmd/sing-box/routervpn_node_chain_retirement_darwin.go",
    "mobile/desktop/node_chain_control_command_test.go.tmpl": "cmd/sing-box/routervpn_node_chain_control_command_test.go",
    "mobile/desktop/node_chain_control_darwin_test.go.tmpl": "cmd/sing-box/routervpn_node_chain_control_darwin_test.go",
    "mobile/desktop/node_chain_retirement_darwin_test.go.tmpl": "cmd/sing-box/routervpn_node_chain_retirement_darwin_test.go",
    "internal/mobilemultihop/desktop_node_ready.go": "experimental/libbox/routervpn/mobilemultihop/desktop_node_ready.go",
    "internal/mobilemultihop/desktop_node_ready_darwin_chain_test.go": "experimental/libbox/routervpn/mobilemultihop/desktop_node_ready_darwin_chain_test.go",
}
MUTATIONS = (
    ("repeat-stack", "protocol/tun", "protocol/tun/routervpn_node_chain_retirement_darwin.go",
     "if *joined {", "if false {",
     "TestRouterVPNDarwinNodeChainInboundRetirement/native-retry",
     "original cleanup repeated or replaced an already joined component"),
    ("lost-native-failure", "protocol/tun", "protocol/tun/routervpn_node_chain_retirement_darwin.go",
     "if err := native.RouterVPNDesktopDarwinNodeChainCloseContext(ctx); err != nil {\n\t\t\t\treturn err\n\t\t\t}",
     "if err := native.RouterVPNDesktopDarwinNodeChainCloseContext(ctx); err != nil {\n\t\t\t\t_ = err\n\t\t\t}",
     "TestRouterVPNDarwinNodeChainInboundRetirement/native-retry",
     "failed native component was acknowledged or lost its original stack progress"),
    ("successor-capability", "protocol/tun", "protocol/tun/routervpn_node_chain_retirement_darwin.go",
     "next.routervpnDarwinNodeChain.Store(true)", "next.routervpnDarwinNodeChain.Store(false)",
     "TestRouterVPNDarwinNodeChainInboundRetirement/successor",
     "MTU successor lost original capability or inherited old cleanup state"),
    ("lost-manager-failure", "adapter/inbound", "adapter/inbound/routervpn_mtu.go",
     "if err := owned.RouterVPNDesktopDarwinNodeChainCloseContext(ctx); err != nil {\n\t\t\treturn err\n\t\t}",
     "if err := owned.RouterVPNDesktopDarwinNodeChainCloseContext(ctx); err != nil {\n\t\t\t_ = err\n\t\t}",
     "TestRouterVPNTunDarwinOrderedManagerRetirement/retained-retry",
     "failed native owner was dropped or later owner retired before its original join"),
    ("foreign-tag", "adapter/inbound", "adapter/inbound/routervpn_mtu.go",
     "if m.inboundByTag[original.Tag()] == original {", "if true {",
     "TestRouterVPNTunDarwinOrderedManagerRetirement/foreign-tag",
     "original cleanup consumed or erased a replacement tag owner"),
    ("foreign-command-flag", "cmd/sing-box", "cmd/sing-box/routervpn_node_chain_command.go",
     "if command.Flags().Changed(name) {", "if command.Flags().Changed(name) && false {",
     "TestRouterVPNNodeChainDarwinCommandFlags/physical-mtu",
     "explicit foreign platform flag reached inherited Darwin dispatch"),
    ("changed-inherited-selection", "cmd/sing-box", "cmd/sing-box/routervpn_node_chain_control_darwin.go",
     "owner.capture.Selection() != owner.selection", "false",
     "TestRouterVPNNodeChainDarwinSelectionBinding/inputs",
     "changed original inherited selection reached policy replay"),
    ("source-before-tun-join", "cmd/sing-box", "cmd/sing-box/routervpn_node_chain_retirement_darwin.go",
     "if err := owner.manager.RouterVPNCloseDarwinNodeChainTunContext(ctx); err != nil {\n\t\t\t\treturn err\n\t\t\t}",
     "if err := owner.manager.RouterVPNCloseDarwinNodeChainTunContext(ctx); err != nil {\n\t\t\t\t_ = err\n\t\t\t}",
     "TestRouterVPNNodeChainDarwinNativeRetirementOrder/tun-retry",
     "failed original native stage acknowledged later cleanup"),
    ("box-before-source-join", "cmd/sing-box", "cmd/sing-box/routervpn_node_chain_retirement_darwin.go",
     "if err := owner.source.CloseSource(ctx); err != nil {\n\t\t\t\treturn err\n\t\t\t}",
     "if err := owner.source.CloseSource(ctx); err != nil {\n\t\t\t\t_ = err\n\t\t\t}",
     "TestRouterVPNNodeChainDarwinNativeRetirementOrder/source-retry",
     "failed original native stage acknowledged later cleanup"),
    ("unpublished-stopped-ack", "cmd/sing-box", "cmd/sing-box/routervpn_node_chain_retirement_darwin.go",
     "if err := files.publish(\"stopped.json\", closed); err != nil {\n\t\treturn err\n\t}",
     "if err := files.publish(\"stopped.json\", closed); err != nil {\n\t\t_ = err\n\t}",
     "TestRouterVPNNodeChainDarwinStoppedReceipt/foreign-file",
     "unjoined source/Box or foreign file produced stopped ACK"),
    ("unpublished-early-stop", "cmd/sing-box", "cmd/sing-box/routervpn_node_chain_control_darwin.go",
     "if owner == nil || !owner.retired.Load() {",
     "if owner == nil || (owner.native != nil && !owner.retired.Load()) {",
     "TestRouterVPNNodeChainDarwinEarlyStop/receipt-before-acquisition",
     "unpublished no-resource retirement acknowledged authenticated Stop"),
    ("cancelled-admission-before-cleanup", "cmd/sing-box", "cmd/sing-box/routervpn_node_chain_run_darwin.go",
     "defer stopAdmission()\n\tfiles, err := routerVPNOpenExternalFiles(control.scope.Workspace)",
     "defer stopAdmission()\n\tif err := control.original(admission); err != nil { return err }\n\tfiles, err := routerVPNOpenExternalFiles(control.scope.Workspace)",
     "TestRouterVPNNodeChainDarwinEarlyStop/authenticated-before-run",
     "early authenticated Stop omitted its original no-resource retirement"),
    ("foreign-cleanup-writer", "cmd/sing-box", "cmd/sing-box/routervpn_node_chain_retirement_darwin.go",
     "workspaceErr := control.workspace(files)", "workspaceErr := error(nil)",
     "TestRouterVPNNodeChainDarwinStoppedReceipt/foreign-workspace",
     "foreign workspace granted receipt authority or suppressed original native join"),
    ("preexisting-measurement-request", "cmd/sing-box", "cmd/sing-box/routervpn_node_chain_run_darwin.go",
     '"node-chain-measure-request.json", ', '',
     "TestRouterVPNNodeChainDarwinMeasurementStartup/request-regular",
     "preexisting ordered measurement mailbox reached native preparation"),
    ("preexisting-measurement-cancel", "cmd/sing-box", "cmd/sing-box/routervpn_node_chain_run_darwin.go",
     '"node-chain-measure-cancel.json", ', '',
     "TestRouterVPNNodeChainDarwinMeasurementStartup/cancel-regular",
     "preexisting ordered measurement mailbox reached native preparation"),
    ("preexisting-measurement-result", "cmd/sing-box", "cmd/sing-box/routervpn_node_chain_run_darwin.go",
     '"node-chain-measure-result.json",', '',
     "TestRouterVPNNodeChainDarwinMeasurementStartup/result-regular",
     "preexisting ordered measurement mailbox reached native preparation"),
    ("ordinary-darwin-policy", "experimental/libbox/routervpn/mobilemultihop", "experimental/libbox/routervpn/mobilemultihop/desktop_node_ready.go",
     'exact && chain != nil && meta.TargetOS == "darwin"',
     '(exact || true) && (chain != nil || true) && meta.TargetOS == "darwin"',
     "TestDesktopNodeReadyDarwinRequiresExactOrderedPolicy/ordinary-policy",
     "ordinary Darwin policy acquired ordered selected-DNS readiness"),
    ("foreign-ready-target", "experimental/libbox/routervpn/mobilemultihop", "experimental/libbox/routervpn/mobilemultihop/desktop_node_ready.go",
     'exact && chain != nil && meta.TargetOS == "darwin"', 'exact && chain != nil && meta.TargetOS != ""',
     "TestDesktopNodeReadyDarwinRequiresExactOrderedPolicy/windows-utun",
     "foreign target adopted Darwin interface shape"),
    ("foreign-ready-interface", "experimental/libbox/routervpn/mobilemultihop", "experimental/libbox/routervpn/mobilemultihop/desktop_node_ready.go",
     'interfaceValid = desktopNodeChainReadyInterface("darwin", r.InterfaceName)', 'interfaceValid = true',
     "TestDesktopNodeReadyDarwinRejectsForeignInterface/fixed",
     "Darwin selected-DNS readiness accepted a foreign interface"),
)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy" / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def receipt(package):
    # Reuse the independently tested strict run->terminal/package parser.
    # Each instance accepts exactly this compiled package, never a union.
    result = load("darwin_lifecycle_receipt", "test_desktop_darwin_retirement.py")
    result.PACKAGE = "github.com/sagernet/sing-box/" + package
    return result


def discover(output, cases):
    roots = output.strip().splitlines()
    if len(roots) != len(set(roots)) or set(roots) != set(cases):
        raise ValueError("Darwin lifecycle changed its exact compiled roots")


def checked_source(source, env):
    source = source.resolve()
    runner = receipt("protocol/tun")
    if platform.system() != "Darwin":
        raise ValueError("Darwin lifecycle requires its actual compiler host")
    _, version = runner.run(["go", "env", "GOVERSION", "GOOS", "GOARCH"], cwd=source, env=env)
    cpu = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "AMD64": "amd64"}.get(platform.machine())
    if version.strip().splitlines() != ["go1.26.3", "darwin", cpu]:
        raise ValueError("Darwin lifecycle changed its compiler or host architecture")
    retained = load("darwin_lifecycle_retained", "prepare-retained-tun.py")
    records = retained.verify(source)
    prep = load("darwin_lifecycle_prepare", "prepare-desktop-mtu.py")
    original = source / "protocol/tun/inbound.go"
    if original.is_symlink() or prep.inbound_retirement_patch(original.read_bytes()) != original.read_bytes():
        raise ValueError("Darwin lifecycle lost its complete pinned inbound projection")
    records["protocol/tun/inbound.go"] = hashlib.sha256(original.read_bytes()).hexdigest()
    for relative, target in COPIES.items():
        template, generated = ROOT / relative, source / target
        if template.is_symlink() or generated.is_symlink() or template.read_bytes() != generated.read_bytes():
            raise ValueError("Darwin lifecycle changed original template: " + relative)
        records[target] = hashlib.sha256(generated.read_bytes()).hexdigest()
    for relative in ("deploy/prepare-desktop-mtu.py", "deploy/prepare-desktop-external.py",
                     "deploy/test_desktop_darwin_node_chain_lifecycle.py",
                     "deploy/test_desktop_darwin_node_chain_lifecycle_runner.py"):
        path = ROOT / relative
        if path.is_symlink():
            raise ValueError("Darwin lifecycle linked a required source input")
        records["gate/" + relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    raw = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def compile_image(source, package, image, tags, env):
    receipt(package).run(["go", "test", "-c", "-race", "-mod=readonly", "-ldflags=-checklinkname=0",
                          "-tags=" + tags, "-o", image, "./" + package], cwd=source, env=env)


def execute(source, package, image, selection, env, failure=False):
    validator = receipt(package)
    return validator.run(["go", "tool", "test2json", "-p", validator.PACKAGE, "-t", image,
                          "-test.v", "-test.run=" + selection, "-test.count=1",
                          "-test.timeout=" + TEST_TIMEOUT], cwd=source, env=env, failure=failure)


def check(source, tags=""):
    source, env = source.resolve(), os.environ.copy()
    source_hash = checked_source(source, env)
    verdicts, images = {}, {}
    with tempfile.TemporaryDirectory(prefix="routervpn-darwin-lifecycle-") as directory:
        directory = Path(directory)
        for package, cases in PHASES.items():
            image = directory / (package.replace("/", "-") + ".test")
            compile_image(source, package, image, tags, env)
            selector = "^(" + "|".join(cases) + ")$"
            validator = receipt(package)
            _, listing = validator.run([image, "-test.list=" + selector], cwd=source, env=env)
            discover(listing, cases)
            code, output = execute(source, package, image, selector, env)
            if code != 0:
                raise ValueError("Darwin lifecycle baseline did not exit successfully")
            verdicts[package] = validator.require_pass(output, cases)
            images[package] = hashlib.sha256(image.read_bytes()).hexdigest()
        for label, package, relative, before, after, witness, message in MUTATIONS:
            target = source / relative
            original = target.read_bytes()
            raw = original.decode("utf-8")
            if raw.count(before) != 1:
                raise ValueError("Darwin lifecycle causal boundary changed: " + label)
            try:
                target.write_bytes(raw.replace(before, after, 1).encode("utf-8"))
                image = directory / (label + ".test")
                compile_image(source, package, image, tags, env)
                root, leaf = witness.split("/", 1)
                selector = "^" + re.escape(root) + "$/^" + re.escape(leaf) + "$"
                code, output = execute(source, package, image, selector, env, failure=True)
                receipt(package).require_rejection(code, output, witness, message)
                print("Rejected Darwin lifecycle control: " + label, flush=True)
            finally:
                target.write_bytes(original)
        if checked_source(source, env) != source_hash:
            raise ValueError("Darwin lifecycle failed to restore its original source")
    print("Darwin ordered component lifecycle: " + json.dumps({
        "schema": 1, "kind": "darwin-ordered-component-lifecycle-v1",
        "source_sha256": source_hash, "race_image_sha256": images,
        "component_verdicts": verdicts, "causal_controls": len(MUTATIONS),
    }, sort_keys=True), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--tags", default="")
    arguments = parser.parse_args()
    check(arguments.source, arguments.tags)
