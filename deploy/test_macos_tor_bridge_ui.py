#!/usr/bin/env python3
"""Execute the shipping Tor UI stages and, on macOS, its actual AppKit callbacks."""
from pathlib import Path
import argparse
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_macos_source_closure import compiler_invocation

ROOT = Path(__file__).resolve().parents[1]
MAC = ROOT / "client/macos"
BUILDER = MAC / "build-native-app.sh"
MUTATION = 'python3 "$SESSION_MUTATION_TRANSFORM" "$UNIFIED_SRC" "$HARDENED_UNIFIED_SRC" unified'
TOR = 'python3 "$TOR_BRIDGE_TRANSFORM" "$HARDENED_UNIFIED_SRC" "$HARDENED_UNIFIED_SRC"'


def pipeline_commands(builder, work):
    variables = dict(re.findall(r'^([A-Z_]+)="([^"\n]+)"$', builder, re.MULTILINE))
    required = {
        "UNIFIED_SRC": "$ROOT/client/macos/RouterVPNMacUnifiedShell.swift",
        "SESSION_MUTATION_TRANSFORM": "$ROOT/client/macos/macos-session-mutation-transform.py",
        "TOR_BRIDGE_TRANSFORM": "$ROOT/client/macos/macos-tor-bridge-ui-transform.py",
        "HARDENED_UNIFIED_SRC": "$BUILD_WORK/RouterVPNMacUnifiedShell.swift",
    }
    if any(variables.get(name) != value for name, value in required.items()):
        raise ValueError("The Tor source pipeline no longer names the captured native sources")
    lines = builder.splitlines()
    if lines.count(MUTATION) != 1 or lines.count(TOR) != 1:
        raise ValueError("The actual build must execute both Unified transformations exactly once")
    invocation = compiler_invocation(builder)
    operands = shlex.split(invocation.replace("\\\n", " "))
    if operands.count("$HARDENED_UNIFIED_SRC") != 1 or "$UNIFIED_SRC" in operands:
        raise ValueError("The compiler must consume the transformed Unified source")
    if not builder.index(MUTATION) < builder.index(TOR) < builder.index(invocation):
        raise ValueError("Tor transformation must follow session hardening and precede compilation")
    resolved = {
        name: value.replace("$ROOT", str(ROOT)).replace("$BUILD_WORK", str(work))
        for name, value in required.items()
    }
    commands = []
    for line in (MUTATION, TOR):
        commands.append([
            sys.executable if value == "python3" else resolved.get(value.removeprefix("$"), value)
            for value in shlex.split(line)
        ])
    return commands, Path(resolved["HARDENED_UNIFIED_SRC"])


def generate(builder, work):
    commands, output = pipeline_commands(builder, work)
    for command in commands:
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
    text = output.read_text()
    required = (
        'button("Tor bridges…", #selector(openTorBridgeBuilder))',
        'button("Add external node…", #selector(addExternalNode))',
        'button("Pair Router node", #selector(pairNode))',
        'button("Import / add custom", #selector(importNode))',
        'button("Select", #selector(selectNode))',
        'button("External direct", #selector(connectExternalDirect))',
        'button("External via entry…", #selector(connectExternalViaEntry))',
        'button("Remove", #selector(removeNode))',
        'button("50-sample latency", #selector(latencySelected))',
        'self.mutationBusy(from: statusObject)',
        'private final class RouterVPNTorBridgeBuilder: NSWindowController',
        '@objc func openTorBridgeBuilder()',
        'retainUnifiedController(builder)',
        '/api/tor-bridge/capabilities', '/api/tor-bridge/import',
    )
    for marker in required:
        if marker not in text:
            raise ValueError("The compiled Nodes source lost a real control, form, or session guard: " + marker)
    # Re-applying an owned build stage must not duplicate native selectors/classes.
    subprocess.run(commands[1], check=True, capture_output=True, text=True, timeout=30)
    if output.read_text() != text:
        raise ValueError("The Tor transformation duplicates or rewrites its own generated UI")
    swift = shutil.which("swiftc")
    if not swift:
        raise RuntimeError("swiftc is required to parse the actual transformed source")
    subprocess.run([swift, "-parse", str(output)], check=True, capture_output=True, text=True, timeout=60)
    return text


APPKIT = r'''
import AppKit
import Foundation

final class ProductAPI {
    private let lock = NSLock()
    private var imports: [[String: Any]] = []
    func snapshot() -> [[String: Any]] { lock.lock(); defer { lock.unlock() }; return imports }
    func json(_ path: String, timeout: TimeInterval = 15) throws -> Any {
        guard path == "/api/tor-bridge/capabilities" else { throw NSError(domain: "Unexpected capability endpoint", code: 1) }
        return ["transports": ["obfs4", "meek_lite", "snowflake", "webtunnel", "custom"].map {
            ["id": $0, "supported": $0 != "webtunnel", "strict_kill_switch": $0 == "obfs4", "description": "fixture support", "reason": "fixture unavailable"] as [String: Any]
        }]
    }
    func request(_ path: String, method: String = "GET", body: [String: Any]? = nil, timeout: TimeInterval = 15) throws -> Data {
        guard path == "/api/tor-bridge/import", method == "POST", let body else { throw NSError(domain: "Unexpected import request", code: 2) }
        lock.lock(); imports.append(body); lock.unlock()
        return Data("{\"ok\":true}".utf8)
    }
}
final class ProductWindowController: NSWindowController { var refreshCount = 0; func refreshAll() { refreshCount += 1 } }
var checks = 0
func check(_ condition: @autoclosure () -> Bool, _ message: String) {
    checks += 1
    if !condition() { fputs(message + "\n", stderr); exit(1) }
}
func wait(_ condition: () -> Bool, _ message: String) {
    let deadline = Date().addingTimeInterval(5)
    while !condition() && Date() < deadline { _ = RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.005)) }
    check(condition(), message)
}
func descendants(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(descendants) }
'''

APPKIT_MAIN = r'''
extension RouterVPNTorBridgeBuilder {
    func exercise(api: ProductAPI, owner: ProductWindowController) {
        wait({ self.capabilities.count == 5 }, "The real capability callback never reached the form")
        let buttons = descendants(window!.contentView!).compactMap { $0 as? NSButton }
        let saveButton = buttons.first { $0.title == "Save Tor node" }!
        check(saveButton.target === self && saveButton.action == #selector(save), "Native Save selector does not reach the form")
        window!.contentView!.layoutSubtreeIfNeeded()
        check(window!.minSize.width >= 600 && window!.minSize.height >= 520, "Native Tor editor lost its usable minimum size")

        nameField.stringValue = "  Private bridge fixture  "
        bridgeText.string = " \n  Bridge obfs4 203.0.113.44:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abcdefghijklmnopqrstuvwxyz012345 iat-mode=0  \n\n"
        transportPopup.selectItem(at: 0); killSwitchPopup.selectItem(at: 1)
        saveButton.performClick(nil)
        wait({ api.snapshot().count == 1 && owner.refreshCount == 1 }, "Native Save did not finish the owned import request")
        let first = api.snapshot()[0]
        check(Set(first.keys) == ["name", "transport", "bridges", "kill_switch_policy"], "Tor form changed the import schema or silently selected another DNS policy")
        check(first["name"] as? String == "Private bridge fixture" && first["transport"] as? String == "obfs4" && first["kill_switch_policy"] as? String == "on-connect", "Tor form lost its explicit transport or protection choice")
        check((first["bridges"] as? [String])?.count == 1 && (first["bridges"] as? [String])?.first?.hasPrefix("Bridge obfs4 ") == true, "Tor bridge line input was not preserved")

        bridgeText.string = "Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.example.net/ front=cdn.example.net ice=stun:stun.example.net:3478 utls-imitate=hellorandomizedalpn"
        transportPopup.selectItem(at: 2); killSwitchPopup.selectItem(at: 1)
        saveButton.performClick(nil)
        check(api.snapshot().count == 1 && status.stringValue.contains("Kill switch Off"), "Dynamic Tor transport bypassed the captured protection gate")
        killSwitchPopup.selectItem(at: 0)
        saveButton.performClick(nil)
        wait({ api.snapshot().count == 2 && owner.refreshCount == 2 }, "Explicit dynamic transport choice did not reach native Save")
        check(api.snapshot()[1]["transport"] as? String == "snowflake" && api.snapshot()[1]["kill_switch_policy"] as? String == "off", "Tor form silently changed dynamic transport or protection")

        transportPopup.selectItem(at: 3); saveButton.performClick(nil)
        check(api.snapshot().count == 2 && status.stringValue.contains("cannot run"), "Unavailable transport was submitted as available")
        bridgeText.string = " \n \n"; saveButton.performClick(nil)
        check(api.snapshot().count == 2 && status.stringValue.contains("at least one"), "Empty bridge input reached the private importer")
        let closeButton = buttons.first { $0.title == "Close" }!
        check(closeButton.target === self && closeButton.action == #selector(closePanel), "Native Close does not reach the owned window")
        closeButton.performClick(nil)
    }
}
@main struct Fixture {
    static func main() {
        _ = NSApplication.shared
        let api = ProductAPI(), owner = ProductWindowController(window: nil)
        let form = RouterVPNTorBridgeBuilder(owner: owner, api: api)
        form.exercise(api: api, owner: owner)
        print("macOS Tor AppKit callbacks: \(checks) checks PASS")
    }
}
'''


def appkit(text, work):
    if sys.platform != "darwin":
        return "AppKit execution requires macOS"
    start = text.index("private final class RouterVPNTorBridgeBuilder: NSWindowController")
    end = text.index("\nextension ProductWindowController {", start)
    source = work / "TorBridgeForm.swift"
    source.write_text(APPKIT + text[start:end] + APPKIT_MAIN)
    binary = work / "tor-bridge-form"
    subprocess.run(["swiftc", "-swift-version", "5", "-parse-as-library", str(source), "-framework", "AppKit", "-o", str(binary)], check=True, capture_output=True, text=True, timeout=120)
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=30)
    return result.stdout.strip()


def shipping():
    with tempfile.TemporaryDirectory(prefix="routervpn-macos-tor-ui-") as directory:
        work = Path(directory)
        text = generate(BUILDER.read_text(), work)
        evidence = appkit(text, work)
        print("macOS Tor shipping source pipeline: PASS; " + evidence)


class TorBuildPipeline(unittest.TestCase):
    def test_shipping_pipeline_and_native_form(self):
        shipping()

    def test_declared_but_unused_transformer_is_rejected(self):
        builder = BUILDER.read_text().replace(TOR + "\n", "", 1)
        with self.assertRaisesRegex(ValueError, "execute both"):
            pipeline_commands(builder, Path("/unused"))

    def test_compiling_the_raw_source_is_rejected(self):
        builder = BUILDER.read_text()
        invocation = compiler_invocation(builder)
        changed = builder.replace(invocation, invocation.replace('"$HARDENED_UNIFIED_SRC"', '"$UNIFIED_SRC"'), 1)
        with self.assertRaisesRegex(ValueError, "consume the transformed"):
            pipeline_commands(changed, Path("/unused"))

    def test_late_transformer_is_rejected(self):
        builder = BUILDER.read_text().replace(TOR + "\n", "", 1) + "\n" + TOR + "\n"
        with self.assertRaisesRegex(ValueError, "precede compilation"):
            pipeline_commands(builder, Path("/unused"))

    def test_missing_nodes_anchor_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-macos-tor-ui-negative-") as directory:
            source = Path(directory) / "MissingNodes.swift"
            source.write_text((MAC / "RouterVPNMacUnifiedShell.swift").read_text().replace('row.addArrangedSubview(button("Add external node…", #selector(addExternalNode)));', ""))
            result = subprocess.run([sys.executable, str(MAC / "macos-tor-bridge-ui-transform.py"), str(source), str(source)], capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing blind Tor UI injection", result.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shipping-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.shipping_only:
            shipping()
        else:
            unittest.main(argv=[__file__])
    except subprocess.CalledProcessError as error:
        raise SystemExit((error.stdout or "") + (error.stderr or ""))
