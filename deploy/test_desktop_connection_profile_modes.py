#!/usr/bin/env python3
"""Execute desktop profile callbacks with all seven exit modes and three owners.

Uses the shipping WPF composition and both AppKit profile entry points. Widgets
are value-only doubles; HTTP is a recording local boundary and UserDefaults uses
a fresh suite. These are snapshot/restore tests, not device networking or visual
acceptance. Broken historical capture/load implementations must fail by assertion.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8-sig")


def block(source, marker):
    start = source.index(marker)
    brace = source.index("{", start)
    depth, end = 1, brace + 1
    while depth and end < len(source):
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    if depth:
        raise AssertionError("Shipping source block is unclosed: " + marker)
    return source[start:end]


def run(command, *, negative=False):
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=90)
    output = result.stdout + result.stderr
    if negative:
        if result.returncode == 0 or "PROFILE-CHECK:" not in output:
            raise RuntimeError("Negative did not fail on a behavioral assertion:\n" + output)
    elif result.returncode:
        raise RuntimeError("Shipping fixture failed:\n" + output)
    elif output.strip():
        print(output.strip())


def windows(shell):
    command = [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
               str(ROOT / "client/test-windows-connection-profile-modes.ps1")]
    for mutation in ("shipping", "capture-two-modes", "load-fallback", "connect-fallback"):
        run(command + ["-Mutation", mutation], negative=mutation != "shipping")
    print("WPF historical capture, load-default and Connect-default negatives: 3 rejected")


SWIFT_BOUNDARIES = r'''
import Foundation
@MainActor final class Item { var representedObject: Any? }
@MainActor final class Popup {
    var indexOfSelectedItem = -1
    var selectedItem: Item? = Item()
    func selectItem(at index: Int) { indexOfSelectedItem = index }
}
@MainActor class NSView {
    struct Identifier { let rawValue: String }
    var identifier: Identifier?
    var subviews: [NSView] = []
}
@MainActor final class NSButton: NSView { enum State { case on, off }; var state = State.off }
@MainActor final class Window { var contentView: NSView? = NSView() }
@MainActor final class Field { var stringValue = "" }
@MainActor final class ProductAPI {
    var calls: [(path: String, body: [String: Any])] = []
    var loaded: [String: Any] = [:]
    func request(_ path: String, method: String, body: [String: Any], timeout: TimeInterval) throws -> Data {
        check(method == "POST" && ["/api/connection-profile/setup/save", "/api/connection-profile/setup/update", "/api/connection-profile/setup/load"].contains(path), "unexpected endpoint or automatic connection")
        // JSON round trip models the actual controller boundary, including
        // quoted identities, Boolean types, and array preservation.
        let decoded = try JSONSerialization.jsonObject(with: JSONSerialization.data(withJSONObject: body)) as! [String: Any]
        calls.append((path, decoded))
        let result: [String: Any] = path.hasSuffix("/load") ? loaded : ["profile": ["name": body["name"] ?? "saved"]]
        return try JSONSerialization.data(withJSONObject: result)
    }
}
let fixtureSuite = "routervpn-profile-modes-" + UUID().uuidString
let fixtureDefaults = UserDefaults(suiteName: fixtureSuite)!
defer { fixtureDefaults.removePersistentDomain(forName: fixtureSuite) }
var checks = 0
@MainActor func check(_ result: Bool, _ message: String) {
    checks += 1
    if !result { print("PROFILE-CHECK: " + message); exit(1) }
}
@MainActor func rejects(_ operation: () throws -> Void, _ message: String) {
    var rejected = false
    do { try operation() } catch { rejected = true }
    check(rejected, message)
}
'''

SWIFT_PRODUCT = r'''
@MainActor final class ProductWindowController {
    let routerPopup = Popup(), multihopEntryPopup = Popup(), multihopExitPopup = Popup()
    let multihopExitModePopup = Popup(), multihopExecutionPopup = Popup()
    let api = ProductAPI()
    let window: Window? = Window()
    var profiles: [[String: Any]] = [["id": "node", "node_kind": "router-vpn", "private_key": "never-copy"]]
    var multihopNodeIDs = ["entry \"private\"", "exit \"private\""]
    func refreshAll() {}
    func refreshUnifiedModeMenu(preferred: String?) {}
    func refreshUnifiedHopOverlay() {}
    func refreshUnifiedChrome() {}
    func refreshUnifiedTelemetry() {}
    func refreshAdvanced() {}
    PRODUCT_METHODS
}
@MainActor final class Settings {
    let api = ProductAPI(), name = Field(), status = Field(), popup = Popup()
    var owner: ProductWindowController?
    var busy = false
    func syncMutationState() -> Bool { busy }
    func refresh() {}
    SETTINGS_METHODS
}
'''

SWIFT_TEST = r'''
let expectedModes = ["shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "naive-h2", "naive-h3"]
let executions = ["local", "server", "auto"]
check(RouterVPNNodeExitModes.choices.map { $0.id } == expectedModes, "shipping exit catalog changed or disappeared")
let owner = ProductWindowController(), settings = Settings()
settings.owner = owner
settings.popup.selectedItem?.representedObject = ["id": "saved-profile", "name": "Saved profile"]
settings.name.stringValue = "Saved \"whole\" path"
let toggle = NSButton(); toggle.identifier = NSView.Identifier(rawValue: "unified-multihop-toggle")
owner.window?.contentView?.subviews = [toggle]
@MainActor func choose(_ mode: Int, _ execution: Int) {
    fixtureDefaults.set("custom:Saved layers", forKey: macConnectionModeKey)
    fixtureDefaults.set(try! JSONEncoder().encode([MacConnectionCustomPreset(name: "Saved layers", layers: ["pq", "wg"])]), forKey: macConnectionCustomPresetsKey)
    fixtureDefaults.set(true, forKey: macConnectionMultihopEnabledKey)
    owner.routerPopup.selectItem(at: 0); owner.multihopEntryPopup.selectItem(at: 0); owner.multihopExitPopup.selectItem(at: 1)
    owner.multihopExitModePopup.selectItem(at: mode); owner.multihopExecutionPopup.selectItem(at: execution)
}
@MainActor func verify(_ body: [String: Any], _ mode: String, _ execution: String, updating: Bool) {
    var keys = Set(["name", "mode", "custom_layers", "multihop_enabled", "multihop_entry_id", "multihop_exit_id", "multihop_exit_mode", "multihop_execution"])
    if updating { keys.insert("id") }
    check(Set(body.keys) == keys, "private fields copied or snapshot fields missing")
    check(body["multihop_enabled"] as? Bool == true && body["multihop_entry_id"] as? String == "entry \"private\"" && body["multihop_exit_id"] as? String == "exit \"private\"", "exact graph identities changed")
    check(body["multihop_exit_mode"] as? String == mode, "snapshot replaced the selected exit mode")
    check(body["multihop_execution"] as? String == execution, "snapshot replaced the selected execution")
    check(body["mode"] as? String == "custom:Saved layers" && body["custom_layers"] as? [String] == ["pq", "wg"], "mode or CUSTOM layers changed")
    if updating { check(body["id"] as? String == "saved-profile", "saved profile identity changed") }
}
@MainActor func loaded(_ body: [String: Any]) -> [String: Any] {
    var payload = body
    payload["profile"] = ["name": "Loaded profile"]
    payload["selected_node_id"] = "private-node"
    payload["private_key"] = "never-copy"
    return payload
}
for (m, mode) in expectedModes.enumerated() {
    for (e, execution) in executions.enumerated() {
        // Main profile manager: execute the exact snapshot, POST and Load
        // functions called by its native modal Add/Load/Update actions.
        choose(m, e)
        let add = try owner.connectionProfileSnapshot(name: settings.name.stringValue, id: nil)
        _ = try owner.connectionProfilePOST("/api/connection-profile/setup/save", body: add)
        verify(owner.api.calls.last!.body, mode, execution, updating: false)
        let payload = loaded(add)
        choose((m + 1) % 7, (e + 1) % 3)
        owner.multihopEntryPopup.selectItem(at: 1); owner.multihopExitPopup.selectItem(at: 0)
        let before = owner.api.calls.count
        owner.applyLoadedConnectionProfile(payload)
        check(owner.api.calls.count == before, "profile manager Load auto-connected")
        check(try RouterVPNNodeExitModes.require(index: owner.multihopExitModePopup.indexOfSelectedItem) == mode, "profile manager Load changed the selected mode")
        let update = try owner.connectionProfileSnapshot(name: settings.name.stringValue, id: "saved-profile")
        _ = try owner.connectionProfilePOST("/api/connection-profile/setup/update", body: update)
        verify(owner.api.calls.last!.body, mode, execution, updating: true)

        // Settings entry point: invoke the actual native button callbacks,
        // including mutation checks, request encoding, and complete restoration.
        choose(m, e)
        var count = settings.api.calls.count
        settings.addProfile()
        check(settings.api.calls.count == count + 1 && settings.status.stringValue.hasPrefix("Added "), "actual Settings Add callback failed")
        verify(settings.api.calls.last!.body, mode, execution, updating: false)
        settings.api.loaded = loaded(settings.api.calls.last!.body)
        choose((m + 1) % 7, (e + 1) % 3)
        owner.multihopEntryPopup.selectItem(at: 1); owner.multihopExitPopup.selectItem(at: 0)
        count = settings.api.calls.count
        settings.loadProfile()
        check(settings.api.calls.count == count + 1 && settings.status.stringValue.hasPrefix("Loaded "), "actual Settings Load callback failed or connected")
        check(toggle.state == .on, "Settings Load lost the multihop toggle")
        count = settings.api.calls.count
        settings.updateProfile()
        check(settings.api.calls.count == count + 1 && settings.status.stringValue.hasPrefix("Updated "), "actual Settings Update callback failed")
        verify(settings.api.calls.last!.body, mode, execution, updating: true)
    }
}
for invalid: String? in ["stale-mode", "", nil, "SHADOWSOCKS"] {
    choose(0, 0)
    var payload = loaded(try owner.connectionProfileSnapshot(name: "bad", id: nil))
    payload["multihop_exit_mode"] = invalid
    owner.applyLoadedConnectionProfile(payload)
    check(owner.multihopExitModePopup.indexOfSelectedItem == -1, "profile manager Load replaced an unsupported exit")
    rejects({ _ = try owner.connectionProfileSnapshot(name: "bad", id: nil) }, "profile manager captured an invalid loaded exit")
    rejects({ _ = try RouterVPNNodeExitModes.require(index: owner.multihopExitModePopup.indexOfSelectedItem) }, "Connect selector accepted an invalid exit")
    choose(0, 0); settings.api.loaded = payload
    settings.loadProfile()
    check(owner.multihopExitModePopup.indexOfSelectedItem == -1, "Settings Load replaced an unsupported exit")
    let before = settings.api.calls.count
    settings.addProfile(); settings.updateProfile()
    check(settings.api.calls.count == before, "invalid Settings snapshot reached the controller")
}
for invalidIndex in [-1, 7, 100] {
    choose(0, 0); owner.multihopExitModePopup.selectItem(at: invalidIndex)
    rejects({ _ = try owner.connectionProfileSnapshot(name: "bad", id: nil) }, "out-of-range main exit index was accepted")
    rejects({ _ = try settings.currentMultihopSnapshot() }, "out-of-range Settings exit index was accepted")
}
choose(6, 2); settings.busy = true
let before = settings.api.calls.count
settings.addProfile(); settings.loadProfile(); settings.updateProfile()
check(settings.api.calls.count == before, "busy profile mutation reached the controller")
settings.busy = false
fixtureDefaults.set(false, forKey: macConnectionMultihopEnabledKey)
let disabled = try owner.connectionProfileSnapshot(name: "direct", id: nil)
check(disabled["multihop_enabled"] as? Bool == false && disabled["multihop_exit_mode"] as? String == "" && disabled["multihop_execution"] as? String == "", "disabled graph retained an exit choice")
let disabledSettings = try settings.currentMultihopSnapshot()
check(!disabledSettings.enabled && disabledSettings.entry.isEmpty && disabledSettings.exit.isEmpty && disabledSettings.exitMode.isEmpty && disabledSettings.execution.isEmpty, "disabled Settings graph retained another graph")
print("Actual AppKit profile capture/Load and Settings Add/Load/Update callbacks: \(checks) checks PASS")
'''


def swift_source():
    product = read("client/macos/RouterVPNMacProduct.swift")
    profiles = read("client/macos/RouterVPNConnectionProfiles.swift")
    settings = read("client/macos/RouterVPNProfileSettings.swift")
    # The build compiles these two files directly; only Product/Unified source
    # receives the session-mutation transform. Verify the real modal callers.
    build = read("client/macos/build-native-app.sh")
    assert '"$PROFILE_SRC"' in build and '"$SETTINGS_SRC"' in build
    for endpoint in ("save", "update"):
        assert f'connectionProfilePOST("/api/connection-profile/setup/{endpoint}", body: connectionProfileSnapshot(' in profiles
    assert 'applyLoadedConnectionProfile(payload)' in profiles
    catalog = block(product, "enum RouterVPNNodeExitModes {")
    declarations = profiles[profiles.index("private let macConnectionModeKey"):profiles.index("private struct MacConnectionProfileList")]
    declarations += block(profiles, "private struct MacConnectionCustomPreset:")
    declarations += "\n" + block(settings, "private struct MacConnectionPresetMirror:")
    for marker in ("private func macCurrentConnectionModeSnapshot(", "private func macApplyLoadedConnectionMode("):
        declarations += "\n@MainActor " + block(settings, marker)
    product_methods = block(product, "    func multihopExecutionChoice(")
    for marker in ("    private func connectionProfileSnapshot(", "    private func connectionProfilePOST(", "    private func applyLoadedConnectionProfile("):
        product_methods += "\n" + block(profiles, marker)
    settings_methods = "\n".join(block(settings, marker) for marker in (
        "    private func requireIdle(", "    private func selectedID(",
        "    private func currentMultihopSnapshot(", "    private func applyLoadedMultihop(",
        "    private func write(", "    @objc private func addProfile(",
        "    @objc private func updateProfile(", "    @objc private func loadProfile(",
    ))
    # Allow the fixture to invoke the real private callbacks. AppKit ordinarily
    # provides main-actor isolation; the value-only owner classes do so here.
    methods = SWIFT_PRODUCT.replace("PRODUCT_METHODS", product_methods).replace("SETTINGS_METHODS", settings_methods)
    methods = methods.replace("@objc ", "").replace("private func ", "func ")
    return (SWIFT_BOUNDARIES + catalog + "\n" + declarations + methods + SWIFT_TEST).replace("UserDefaults.standard", "fixtureDefaults")


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise RuntimeError("Negative source seam changed: " + old)
    return source.replace(old, new, 1)


def macos(directory):
    source = swift_source()
    variants = {
        "shipping": source,
        "manager-two-mode-capture": replace_once(source,
            'let exitMode = try (multihop ? RouterVPNNodeExitModes.require(index: multihopExitModePopup.indexOfSelectedItem) : "")',
            'let exitMode = multihop ? (multihopExitModePopup.indexOfSelectedItem == 1 ? "hysteria2" : "shadowsocks") : ""'),
        "settings-two-mode-capture": replace_once(source,
            'let exitMode = try RouterVPNNodeExitModes.require(index: owner.multihopExitModePopup.indexOfSelectedItem)',
            'let exitMode = owner.multihopExitModePopup.indexOfSelectedItem == 1 ? "hysteria2" : "shadowsocks"'),
        "manager-load-default": replace_once(source,
            'RouterVPNNodeExitModes.index(for: payload["multihop_exit_mode"] as? String ?? "") ?? -1',
            'RouterVPNNodeExitModes.index(for: payload["multihop_exit_mode"] as? String ?? "") ?? 0'),
        "settings-load-default": replace_once(source,
            'RouterVPNNodeExitModes.index(for: exitMode) ?? -1',
            'RouterVPNNodeExitModes.index(for: exitMode) ?? 0'),
    }
    for name, program in variants.items():
        path, binary = directory / (name + ".swift"), directory / name
        path.write_text(program, encoding="utf-8")
        run(["swiftc", "-swift-version", "6", "-module-cache-path", str(directory / "swift-module-cache"), str(path), "-o", str(binary)])
        run([str(binary)], negative=name != "shipping")
    print("AppKit historical capture and invalid-load negatives: 4 rejected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=("windows", "macos"))
    parser.add_argument("--shell", default="pwsh")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="routervpn-connection-profile-modes-") as temporary:
        if args.platform == "windows":
            windows(args.shell)
        else:
            macos(Path(temporary))
