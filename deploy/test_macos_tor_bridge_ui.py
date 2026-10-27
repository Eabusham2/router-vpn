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
from test_desktop_amnezia_forms import block

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
        '"Plain Tor — no bridges"', 'Tor bridge lines — leave empty for Plain Tor',
    )
    for marker in required:
        if marker not in text:
            raise ValueError("The compiled Nodes source lost a real control, form, or session guard: " + marker)
    menu_dispatch(builder, (MAC / "RouterVPNMenuBar.m").read_text(), text)
    # Re-applying an owned build stage must not duplicate native selectors/classes.
    subprocess.run(commands[1], check=True, capture_output=True, text=True, timeout=30)
    if output.read_text() != text:
        raise ValueError("The Tor transformation duplicates or rewrites its own generated UI")
    swift = shutil.which("swiftc")
    if not swift:
        raise RuntimeError("swiftc is required to parse the actual transformed source")
    subprocess.run([swift, "-parse", str(output)], check=True, capture_output=True, text=True, timeout=60)
    return text


def code_tokens(source):
    pattern = r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|[A-Za-z_]\w*|[^\s]'
    return tuple(token for token in re.findall(pattern, source) if not token.startswith(("//", "/*")))


def code_at(source, marker):
    tokens, wanted = code_tokens(source), code_tokens(marker)
    matches = [i for i in range(len(tokens)-len(wanted)+1) if tokens[i:i+len(wanted)] == wanted]
    if len(matches) != 1:
        raise ValueError("Expected one actual menu dispatch operation: " + marker)
    return matches[0]


def menu_dispatch(builder, menu, generated):
    """The Objective-C menu must open the same captured Swift editor."""
    compile_menu = 'xcrun clang -fobjc-arc -fblocks -fmodules -isysroot "$SDK" -mmacosx-version-min=13.0 -arch "$CLANG_ARCH" -c "$MENU_SRC" -o "$MENU_OBJ"'
    invocation = compiler_invocation(builder)
    if builder.splitlines().count('MENU_SRC="$ROOT/client/macos/RouterVPNMenuBar.m"') != 1 or builder.splitlines().count(compile_menu) != 1 or shlex.split(invocation.replace("\\\n", " ")).count("$MENU_OBJ") != 1 or builder.index(compile_menu) >= builder.index(invocation):
        raise ValueError("The compiled product lost the actual native menu dispatch object")
    try:
        installed = block(menu, "- (void)installMenuBarItem")
        code_at(installed, '[menu addItemWithTitle:@"Tor Bridges…" action:@selector(showTorBridges:) keyEquivalent:@""]; menu.itemArray.lastObject.target = self;')
        dispatch = block(menu, "- (void)showTorBridges:(id)sender")
        positions = [code_at(dispatch, marker) for marker in (
            'NSWindow *window = [self routerVPNWindow];',
            'id controller = window.windowController;',
            'SEL action = NSSelectorFromString(@"openTorBridgeBuilder");',
            '[self showRouterVPN:sender];',
            'if ([controller respondsToSelector:action])',
            '[NSApp sendAction:action to:controller from:sender];',
        )]
        if positions != sorted(positions) or '"/api/tor-bridge/import"' in code_tokens(menu):
            raise ValueError("The native menu bypasses the captured Swift editor")
        opened = block(generated, "@objc func openTorBridgeBuilder()")
        for marker in ('guard ensureMutationIdle("opening Tor bridge controls") else { return }',
                       'let builder = RouterVPNTorBridgeBuilder(owner: self, api: api)',
                       'retainUnifiedController(builder)', 'builder.showWindow(nil)'):
            code_at(opened, marker)
    except (AssertionError, ValueError) as error:
        raise ValueError("The Tor menu must reach the captured Swift editor: " + str(error)) from error


APPKIT = r'''
import AppKit
import Foundation
import CoreFoundation

// Controller/idle replies are explicit UI doubles. Every view, selector,
// checkbox, source helper and Save callback below is the actual AppKit source.
func publicFixture() -> [String: Any] {
    ["selected_id": "tor-edit", "profiles": [
        ["id": "tor-edit", "name": "Captured Tor exit", "node_kind": "external",
         "profile_token": String(repeating: "a", count: 64),
         "external": ["protocol": "tor-bridge"], "kill_switch_policy": "always",
         "multihop_enabled": true, "multihop_entry_id": "entry", "multihop_exit_id": "tor-edit",
         "multihop_entry_mode": "awg2-strong", "multihop_execution": "local"],
        ["id": "entry", "name": "Captured Router entry", "node_kind": "router-vpn",
         "profile_token": String(repeating: "b", count: 64)]
    ] as [[String: Any]]]
}
final class ProductAPI {
    private let lock = NSLock()
    private var imports: [[String: Any]] = []
    private var catalog = publicFixture()
    private var reads = 0
    func snapshot() -> [[String: Any]] { lock.lock(); defer { lock.unlock() }; return imports }
    func readCount() -> Int { lock.lock(); defer { lock.unlock() }; return reads }
    func replaceCatalog(_ next: [String: Any]) { lock.lock(); defer { lock.unlock() }; catalog = next }
    func json(_ path: String, timeout: TimeInterval = 15) throws -> Any {
        guard timeout > 0 && timeout <= 15 else { throw NSError(domain: "Unbounded test request", code: 1) }
        if path == "/api/nodes" { lock.lock(); defer { lock.unlock() }; reads += 1; return catalog }
        guard path == "/api/tor-bridge/capabilities" else { throw NSError(domain: "Unexpected capability endpoint", code: 1) }
        return ["profile_update_source_preconditions": true, "transports": ["obfs4", "meek_lite", "snowflake", "webtunnel", "custom", "tor"].map {
            ["id": $0, "supported": $0 != "webtunnel", "strict_kill_switch": $0 == "obfs4",
             "strict_router_entry_kill_switch": true, "description": "fixture support", "reason": "fixture unavailable"] as [String: Any]
        }]
    }
    func request(_ path: String, method: String = "GET", body: [String: Any]? = nil, timeout: TimeInterval = 15) throws -> Data {
        guard path == "/api/tor-bridge/import", method == "POST", let body, timeout > 0, timeout <= 20 else { throw NSError(domain: "Unexpected import request", code: 2) }
        lock.lock(); imports.append(body); lock.unlock()
        return Data("{\"ok\":true}".utf8)
    }
}
final class ProductWindowController: NSWindowController {
    var profiles = publicFixture()["profiles"] as! [[String: Any]]
    var selected = "tor-edit"
    var refreshCount = 0
    private let idleLock = NSLock()
    private var foregroundIdle = true, backgroundIdle = true, required = 0
    func selectedNodeID() -> String? { selected }
    func refreshAll() { refreshCount += 1 }
    func setIdle(foreground: Bool, background: Bool) { idleLock.lock(); defer { idleLock.unlock() }; foregroundIdle = foreground; backgroundIdle = background }
    func ensureMutationIdle(_ reason: String) -> Bool { idleLock.lock(); defer { idleLock.unlock() }; return foregroundIdle }
    func requireMutationIdle(_ reason: String) throws {
        idleLock.lock(); let allowed = backgroundIdle; required += 1; idleLock.unlock()
        if !allowed { throw NSError(domain: "RouterVPN.TestBusy", code: 1, userInfo: [NSLocalizedDescriptionKey: "test owner entered another connection before Save"]) }
    }
    func requiredCount() -> Int { idleLock.lock(); defer { idleLock.unlock() }; return required }
}
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
    func exerciseAdd(api: ProductAPI, owner: ProductWindowController) {
        wait({ self.capabilities.count == 6 }, "The real capability callback never reached the form")
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
        transportPopup.selectItem(at: 0); bridgeText.string = " \n \n"; saveButton.performClick(nil)
        check(api.snapshot().count == 2 && status.stringValue.contains("between one and eight"), "Empty bridge input reached the private importer")
        transportPopup.selectItem(at: 5); bridgeText.string = "retained pasted bridge text"; saveButton.performClick(nil)
        check(api.snapshot().count == 2 && status.stringValue.contains("Clear the bridge lines"), "Plain Tor silently discarded pasted bridge configuration")
        bridgeText.string = ""; killSwitchPopup.selectItem(at: 2); saveButton.performClick(nil)
        check(api.snapshot().count == 2 && status.stringValue.contains("Kill switch Off"), "Plain Tor Direct borrowed Router strict authority")
        killSwitchPopup.selectItem(at: 0); saveButton.performClick(nil)
        wait({ api.snapshot().count == 3 && owner.refreshCount == 3 }, "Plain Tor native Save did not finish")
        check(api.snapshot()[2]["transport"] as? String == "tor" && (api.snapshot()[2]["bridges"] as? [String])?.isEmpty == true, "Plain Tor native Save invented bridge lines")
        let closeButton = buttons.first { $0.title == "Close" }!
        check(closeButton.target === self && closeButton.action == #selector(closePanel), "Native Close does not reach the owned window")
        closeButton.performClick(nil)
    }
}

extension RouterVPNTorBridgeBuilder {
    func updateControls() -> NSButton {
        wait({ self.capabilities.count == 6 }, "Captured editor capability reply did not reach AppKit")
        check(updateSelected.isEnabled && updateSelected.target === self && updateSelected.action == #selector(updateSelectionChanged), "Native Update selector does not reach the captured checkbox")
        updateSelected.performClick(nil)
        check(updateSelected.state == .on, "Actual Update click did not select Update")
        check(bridgeText.string.isEmpty, "Update read back private bridge lines")
        if (torBridgeUpdateProfile(opened)?["external"] as? [String: Any])?["protocol"] as? String == "tor" {
            check(selectedTransport() == "tor", "Saved Plain Tor did not reopen its native transport choice")
        }
        bridgeText.string = "snowflake 192.0.2.3:80 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.example.net/ front=cdn.example.net ice=stun:stun.example.net:3478"
        transportPopup.selectItem(at: 2)
        return descendants(window!.contentView!).compactMap { $0 as? NSButton }.first { $0.title == "Save Tor node" }!
    }
    func exerciseCapturedUpdate(api: ProductAPI, owner: ProductWindowController, fault: String = "", transport: String = "snowflake") {
        let save = updateControls()
        if transport == "tor" { transportPopup.selectItem(at: 5); bridgeText.string = "" }
        if fault == "invalid-policy" || fault == "missing-policy" {
            check(selectedKillSwitch().isEmpty, "Unavailable saved AppKit protection became Off")
            save.performClick(nil)
            check(api.snapshot().isEmpty && status.stringValue.contains("valid kill-switch"), "Unavailable saved protection reached import")
            closePanel(); return
        }
        check(selectedKillSwitch() == "always" && nameField.stringValue == "Captured Tor exit", "Actual Update replaced saved Always or the captured name")
        if fault == "foreground-busy" { owner.setIdle(foreground: false, background: false) }
        if fault == "background-busy" { owner.setIdle(foreground: true, background: false) }
        if fault == "no-source-capability" { capabilityRoot["profile_update_source_preconditions"] = false }
        if ["exit-relink", "entry-relink", "missing-entry", "duplicate-entry", "selected", "owner-replaced"].contains(fault) {
            var current = publicFixture()
            var profiles = current["profiles"] as! [[String: Any]]
            if fault == "exit-relink" { profiles[0]["profile_token"] = String(repeating: "c", count: 64) }
            if fault == "entry-relink" || fault == "owner-replaced" { profiles[1]["profile_token"] = String(repeating: "c", count: 64) }
            if fault == "missing-entry" { profiles.remove(at: 1) }
            if fault == "duplicate-entry" { profiles.append(profiles[1]) }
            if fault == "selected" { current["selected_id"] = "entry" }
            current["profiles"] = profiles
            api.replaceCatalog(current)
            if fault == "owner-replaced" { owner.profiles = profiles }
        }
        save.performClick(nil)
        if fault == "foreground-busy" {
            check(api.snapshot().isEmpty && owner.requiredCount() == 0 && status.stringValue.contains("Disconnect"), "Busy AppKit owner admitted Save")
        } else if fault == "no-source-capability" {
            check(api.snapshot().isEmpty && api.readCount() == 0 && status.stringValue.contains("Update the local controller"), "Missing source capability downgraded Update")
        } else if !fault.isEmpty {
            wait({ !api.snapshot().isEmpty || self.status.stringValue.contains("Tor node rejected") }, "Changed source did not complete its owned AppKit refusal")
            check(api.snapshot().isEmpty && owner.refreshCount == 0, "Changed captured source reached AppKit import")
            check(owner.requiredCount() == 1, "Background Save lost its second owner-idle check")
        } else {
            wait({ api.snapshot().count == 1 && owner.refreshCount == 1 }, "Captured AppKit Update did not finish")
            let body = api.snapshot()[0]
            check(Set(body.keys) == ["id", "name", "transport", "bridges", "kill_switch_policy", "expected_selected_node_id", "expected_profile_tokens"], "Captured Update copied unrelated path or private settings")
            check(body["id"] as? String == "tor-edit" && body["name"] as? String == "Captured Tor exit" && body["transport"] as? String == transport && body["kill_switch_policy"] as? String == "always", "Captured Update changed saved identity/name/protection")
            check(body["expected_selected_node_id"] as? String == "tor-edit" && body["expected_profile_tokens"] as? [String: String] == ["tor-edit": String(repeating: "a", count: 64), "entry": String(repeating: "b", count: 64)], "Captured Update adopted another public source revision")
            check(api.readCount() == 1 && owner.requiredCount() == 1, "Update skipped current-source or idle admission")
        }
        closePanel()
    }
}
@main struct Fixture {
    static func main() {
        _ = NSApplication.shared
        do {
            let api = ProductAPI(), owner = ProductWindowController(window: nil)
            let form = RouterVPNTorBridgeBuilder(owner: owner, api: api)
            form.exerciseAdd(api: api, owner: owner)
        }
        for fault in ["", "exit-relink", "entry-relink", "missing-entry", "duplicate-entry", "selected", "owner-replaced", "foreground-busy", "background-busy", "no-source-capability", "invalid-policy", "missing-policy"] {
            let api = ProductAPI(), owner = ProductWindowController(window: nil)
            if fault == "invalid-policy" { owner.profiles[0]["kill_switch_policy"] = "unavailable" }
            if fault == "missing-policy" { owner.profiles[0].removeValue(forKey: "kill_switch_policy") }
            let form = RouterVPNTorBridgeBuilder(owner: owner, api: api)
            form.exerciseCapturedUpdate(api: api, owner: owner, fault: fault)
        }
        for plain in [false, true] { for transport in ["tor", "snowflake"] {
            let api = ProductAPI(), owner = ProductWindowController(window: nil)
            if plain { owner.profiles[0]["external"] = ["protocol": "tor"] }
            api.replaceCatalog(["selected_id": "tor-edit", "profiles": owner.profiles])
            let form = RouterVPNTorBridgeBuilder(owner: owner, api: api)
            form.exerciseCapturedUpdate(api: api, owner: owner, transport: transport)
        } }
        print("macOS Tor actual AppKit callbacks: \(checks) checks PASS")
    }
}
'''


def appkit(text, work):
    start = text.index("func torBridgeUpdateProfile(")
    end = text.index("\nextension ProductWindowController {", start)
    external = (MAC / "RouterVPNMacExternalNode.swift").read_text()
    helpers = "\n".join(block(external, marker) for marker in (
        "func externalValidateCapturedBody(", "func externalCapturedBody("))
    source = work / "TorBridgeForm.swift"
    actual = APPKIT + helpers + "\n" + text[start:end] + APPKIT_MAIN
    source.write_text(actual)
    # Linux can parse the complete actual AppKit fixture, but cannot execute or
    # type-check Apple's framework. Darwin keeps the real compile/run gate.
    subprocess.run(["swiftc", "-swift-version", "5", "-parse-as-library", "-parse", str(source)], check=True, capture_output=True, text=True, timeout=60)
    if sys.platform != "darwin":
        return "AppKit execution requires macOS; full fixture syntax checked only"
    binary = work / "tor-bridge-form"
    subprocess.run(["swiftc", "-swift-version", "5", "-parse-as-library", str(source), "-framework", "AppKit", "-o", str(binary)], check=True, capture_output=True, text=True, timeout=120)
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=30)
    controls = (
        ("update-selector", "updateSelected.action = #selector(updateSelectionChanged)",
         "updateSelected.action = nil", "Native Update selector does not reach the captured checkbox"),
        ("saved-protection", '["off", "on-connect", "always"].firstIndex(of: policy) ?? -1',
         "0", "Actual Update replaced saved Always or the captured name"),
        ("current-source", "try externalValidateCapturedBody(body, current: current)",
         "_ = current", "Changed captured source reached AppKit import"),
    )
    for name, original, replacement, witness in controls:
        if actual.count(original) != 1:
            raise AssertionError(name + " mutation must target one actual AppKit callback")
        changed = work / (name + ".swift")
        changed.write_text(actual.replace(original, replacement))
        changed_binary = work / name
        subprocess.run(["swiftc", "-swift-version", "5", "-parse-as-library", str(changed), "-framework", "AppKit", "-o", str(changed_binary)], check=True, capture_output=True, text=True, timeout=120)
        rejected = subprocess.run([str(changed_binary)], capture_output=True, text=True, timeout=30)
        if rejected.returncode == 0 or witness not in rejected.stdout + rejected.stderr:
            raise AssertionError(name + " AppKit mutation missed its actual assertion: " + rejected.stdout + rejected.stderr)
    return result.stdout.strip() + "; 3 actual AppKit callback mutation controls rejected"


def shipping():
    with tempfile.TemporaryDirectory(prefix="routervpn-macos-tor-ui-") as directory:
        work = Path(directory)
        text = generate(BUILDER.read_text(), work)
        evidence = appkit(text, work)
        print("macOS Tor shipping source pipeline: PASS; " + evidence)


class TorBuildPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="routervpn-macos-tor-ui-suite-")
        cls.work = Path(cls.temporary.name)
        cls.generated = generate(BUILDER.read_text(), cls.work)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_shipping_pipeline_and_native_form(self):
        evidence = appkit(self.generated, self.work)
        print("macOS Tor shipping source pipeline: PASS; " + evidence)

    def test_menu_dispatch_requires_actual_selector_target_and_call(self):
        menu = (MAC / "RouterVPNMenuBar.m").read_text()
        for marker in (
            'SEL action = NSSelectorFromString(@"openTorBridgeBuilder");',
            'if ([controller respondsToSelector:action])',
            '[NSApp sendAction:action to:controller from:sender];',
        ):
            with self.subTest(marker=marker):
                self.assertEqual(menu.count(marker), 1)
                changed = menu.replace(marker, '/* ' + marker + ' */')
                with self.assertRaisesRegex(ValueError, "captured Swift editor"):
                    menu_dispatch(BUILDER.read_text(), changed, self.generated)

    def test_menu_dispatch_cannot_link_a_different_object_or_duplicate_importer(self):
        builder, menu = BUILDER.read_text(), (MAC / "RouterVPNMenuBar.m").read_text()
        invocation = compiler_invocation(builder)
        changed = builder.replace(invocation, invocation.replace('"$MENU_OBJ"', '"$OTHER_MENU_OBJ"'))
        with self.assertRaisesRegex(ValueError, "native menu"):
            menu_dispatch(changed, menu, self.generated)
        duplicated = menu.replace('[NSApp sendAction:action to:controller from:sender];',
                                  '[NSApp sendAction:action to:controller from:sender];\nNSURL *bypass = [NSURL URLWithString:@"/api/tor-bridge/import"];')
        with self.assertRaisesRegex(ValueError, "captured Swift editor"):
            menu_dispatch(builder, duplicated, self.generated)

    def test_menu_reaches_the_same_owned_idle_guarded_swift_editor(self):
        opened = block(self.generated, "@objc func openTorBridgeBuilder()")
        for marker in ('guard ensureMutationIdle("opening Tor bridge controls") else { return }',
                       'retainUnifiedController(builder)'):
            with self.subTest(marker=marker):
                self.assertEqual(opened.count(marker), 1)
                changed = self.generated.replace(opened, opened.replace(marker, '/* ' + marker + ' */'))
                with self.assertRaisesRegex(ValueError, "captured Swift editor"):
                    menu_dispatch(BUILDER.read_text(), (MAC / "RouterVPNMenuBar.m").read_text(), changed)

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
