#!/usr/bin/env python3
"""Execute desktop profile callbacks with captured entry/exit modes and three owners.

Uses the shipping WPF composition and both AppKit profile entry points. Widgets
are value-only doubles; HTTP is a recording local boundary and UserDefaults uses
a fresh suite. These are snapshot/restore tests, not device networking or visual
acceptance. Broken historical capture/load implementations must fail by assertion.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import re
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


def behavioral_diagnostic(output):
    # PowerShell 7 decorates each wrapped error line independently. Remove only
    # SGR styling and its leading continuation gutter; preserve message words,
    # punctuation and inline pipes before comparing the exact asserted cause.
    plain = re.sub(r"\x1b\[[0-9;:]*m", "", output)
    plain = re.sub(r"(?m)^[ \t]*\|[ \t]?", "", plain)
    return " ".join(plain.split())


def run(command, *, negative=False, witness=None):
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=90)
    output = result.stdout + result.stderr
    if negative:
        diagnostic = behavioral_diagnostic(output)
        if result.returncode == 0 or "PROFILE-CHECK:" not in diagnostic or (witness and witness not in diagnostic):
            raise RuntimeError("Negative did not fail on a behavioral assertion:\n" + output)
    elif result.returncode:
        raise RuntimeError("Shipping fixture failed:\n" + output)
    elif output.strip():
        print(output.strip())


def windows(shell):
    command = [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
               str(ROOT / "client/test-windows-connection-profile-modes.ps1")]
    setup_witnesses = {
        "setup-expectation": "Setup action discarded its original source inventory",
        "setup-current-receipt": "A changed setup owner was adopted: visible-off",
        "setup-response-source": "Malformed setup reply was adopted: changed-token",
        "setup-response-order": "Malformed setup reply was adopted: reordered-members",
        "setup-load-inventory": "Load discarded an original saved selection source",
        "setup-refresh-retirement": "Setup kept its pending catalog refresh",
        "setup-uncertain-owner": "Uncertain Load retained the old selected-node authority",
    }
    for mutation in ("shipping", "capture-two-modes", "load-fallback", "connect-fallback", "entry-capture-fallback", "entry-load-fallback", "entry-connect-fallback", "startup-deadline", "ordered-drop-middle", "ordered-final-owner", "ordered-capability", "ordered-source", "ordered-locked-source", "setup-expectation", "setup-current-receipt", "setup-response-source", "setup-response-order", "setup-load-inventory", "setup-refresh-retirement", "setup-uncertain-owner"):
        run(command + ["-Mutation", mutation], negative=mutation != "shipping", witness=setup_witnesses.get(mutation))
    print("WPF pair and ordered capture, setup ownership/response, load/Connect, capability and startup deadline negatives: 19 rejected")
    editor = [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
              str(ROOT / "client/test-windows-ordered-editor.ps1")]
    if os.name == "nt":
        editor.append("-WPF")
    run(editor)


SWIFT_BOUNDARIES = r'''
import Foundation
import CoreFoundation
@MainActor final class Item { var representedObject: Any? }
@MainActor final class Popup {
    var indexOfSelectedItem = -1
    var selectedItem: Item? = Item()
    func selectItem(at index: Int) { indexOfSelectedItem = index }
    func removeAllItems() { indexOfSelectedItem = -1 }
}
@MainActor final class DispatchQueue {
    enum QoS { case utility, userInitiated }
    static let main = DispatchQueue(), background = DispatchQueue()
    static func global(qos: QoS) -> DispatchQueue { background }
    var pending: [() -> Void] = []
    func async(execute: @escaping () -> Void) { pending.append(execute) }
    func sync<T>(execute: () -> T) -> T { execute() }
    func run(_ index: Int = 0) { check(pending.indices.contains(index), "missing deferred shipping callback"); pending.remove(at: index)() }
    static func clear() { main.pending = []; background.pending = [] }
}
@MainActor final class MacViaEntryCandidateReservation { static let shared = MacViaEntryCandidateReservation(); var active = false }
@MainActor class NSView {
    struct Identifier { let rawValue: String }
    var identifier: Identifier?
    var subviews: [NSView] = []
}
@MainActor final class NSButton: NSView { enum State { case on, off }; var state = State.off }
@MainActor final class Window { var contentView: NSView? = NSView() }
@MainActor final class Field { var stringValue = ""; var string = "" }
@MainActor final class ProductAPI {
    var calls: [(path: String, body: [String: Any], timeout: TimeInterval)] = []
    var loaded: [String: Any] = [:]
    var busy = false
    var failLoad = false, malformedLoad = false
    var afterStatus: (() -> Void)?
    var afterLoad: (() -> Void)?
    var afterSetup: ((String) -> Void)?
    var setupResponse: (([String: Any]) -> [String: Any])?
    var nodeReplies: [[String: Any]] = [], hopReplies: [[String: Any]] = []
    var orderedCapabilities: [String: Any] = ["ordered_nodes_supported": true]
    var orderedCurrent: [String: Any] = [:]
    var afterOrderedSnapshot: (() -> Void)?
    func json(_ path: String, timeout: TimeInterval = 5) throws -> Any {
        if path == "/api/status" { afterStatus?(); return ["connected": busy, "phase": busy ? "connected" : "off"] }
        if path == "/api/multihop/status" { return orderedCapabilities }
        if path == "/api/profiles" { let captured = orderedCurrent; afterOrderedSnapshot?(); return captured }
        check(path.hasPrefix("/api/nodes?sort=") && !nodeReplies.isEmpty, "unexpected node catalog request")
        return nodeReplies.removeFirst()
    }
    func request(_ path: String, method: String = "GET", body: [String: Any]? = nil, timeout: TimeInterval) throws -> Data {
        if method == "GET" {
            check(path == "/api/multihop/status" && !hopReplies.isEmpty, "unexpected hop catalog request")
            return try JSONSerialization.data(withJSONObject: hopReplies.removeFirst())
        }
        check(method == "POST" && ["/api/connection-profile/setup/save", "/api/connection-profile/setup/update", "/api/connection-profile/setup/load", "/api/profile/select", "/api/multihop/connect"].contains(path), "unexpected endpoint or automatic connection")
        let body = body ?? [:]
        // JSON round trip models the actual controller boundary, including
        // quoted identities, Boolean types, and array preservation.
        let decoded = try JSONSerialization.jsonObject(with: JSONSerialization.data(withJSONObject: body)) as! [String: Any]
        calls.append((path, decoded, timeout))
        if path.hasSuffix("/load") {
            if failLoad { throw NSError(domain: "fixture", code: 1, userInfo: [NSLocalizedDescriptionKey: "Load response timed out"]) }
            if malformedLoad { return Data("[]".utf8) }
            afterLoad?()
        }
        var result: [String: Any] = path.hasSuffix("/load") ? loaded : ["profile": ["name": body["name"] ?? "saved"]]
        if ["/api/connection-profile/setup/save", "/api/connection-profile/setup/update"].contains(path) {
            result = decoded
            result["profile"] = ["name": body["name"] ?? "saved", "mode": body["mode"] ?? "smart-auto"]
            result["selected_node_id"] = body["expected_selected_node_id"]
            result["profile_tokens"] = body["expected_profile_tokens"]
            if result["multihop_nodes"] == nil { result["multihop_nodes"] = NSNull() }
        }
        if path.hasPrefix("/api/connection-profile/setup/") {
            check(decoded["expected_selected_node_id"] is String && decoded["expected_profile_tokens"] is [String: String], "setup request lost its original source capture")
            if let setupResponse { result = setupResponse(result) }
            afterSetup?(path)
        }
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
@MainActor final class FixtureLiveOwner {var mutations:Set<UUID>=[];var generation=UUID()}
@MainActor final class ProductWindowController {
    let liveTelemetryDelivery=FixtureLiveOwner();func clearLiveHTTPS(){}
    let routerPopup = Popup(), multihopEntryPopup = Popup(), multihopExitPopup = Popup()
    let nodePopup = Popup(), externalEntryPopup = Popup(), nodeSortPopup = Popup(), basePopup = Popup()
    let multihopExitModePopup = Popup(), multihopExecutionPopup = Popup(), multihopEntryModePopup = Popup()
    let api = ProductAPI()
    let window: Window? = Window()
    let errorLabel = Field(), advancedText = Field(), multihopComparisonLabel = Field()
    var profiles: [[String: Any]] = []
    var routerIDs: [String] = []
    PRODUCT_PROPERTIES
    var multihopProgressGeneration = UUID()
    var progressTimeout: TimeInterval = 0
    func startMultihopProgress(timeout: TimeInterval = 180) { progressTimeout = timeout }
    var stoppedProgress: [UUID] = []
    func stopCapturedComparisonProgress(_ owner: UUID?) { if let owner { stoppedProgress.append(owner) } }
    func stopMultihopProgress() {}
    func refreshModes() {}
    func refreshLive() {}
    func refreshUnifiedModeMenu(preferred: String?) {}
    func refreshUnifiedHopOverlay() {}
    func refreshUnifiedChrome() {}
    func refreshUnifiedTelemetry() {}
    func populateIdentityPopup(_ popup: Popup, names: [String], ids: [String]) { popup.selectItem(at: ids.isEmpty ? -1 : 0) }
    func renderProfiles(selected: String) {}
    func multihopComparisonSummary(_ payload: [String: Any]) -> String { "comparison" }
    func appendHelp(_ message: String) {}
    var candidatesOpened = 0
    func unifiedEntryCandidatesChanged() { candidatesOpened += 1 }
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
let expectedModes = ["shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "naive-h2", "naive-h3", "wg", "awg2-fast", "awg2-strong", "ss-v2ray", "split", "max", "wg-pq", "awg2-pq", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"]
let executions = ["local", "server", "auto"]
check(RouterVPNNodeExitModes.choices.map { $0.id } == expectedModes, "shipping exit catalog changed or disappeared")
let owner = ProductWindowController(), settings = Settings()
settings.owner = owner
settings.popup.selectedItem?.representedObject = ["id": "saved-profile", "name": "Saved profile"]
settings.name.stringValue = "Saved \"whole\" path"
let toggle = NSButton(); toggle.identifier = NSView.Identifier(rawValue: "unified-multihop-toggle")
owner.window?.contentView?.subviews = [toggle]
let selectedID = "private-node", entryID = "entry_private", exitID = "exit_private"
let expectedEntries = ["", "wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "naive-h2", "naive-h3", "ss-v2ray", "split", "max", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg", "wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "openvpn"]
check(RouterVPNNodeEntryModes.choices.map { $0.id } == expectedEntries, "entry mode catalog changed or reduced")
let sourceTokens = [selectedID: String(repeating: "a", count: 64), entryID: String(repeating: "b", count: 64), exitID: String(repeating: "c", count: 64)]
@MainActor func catalogRows(_ ids: [String], tokens: [String: String] = sourceTokens) -> [[String: Any]] {
    ids.map { ["id": $0, "name": "Same display name", "node_kind": "router-vpn", "profile_token": tokens[$0] ?? String(repeating: "d", count: 64)] }
}
@MainActor func choose(_ mode: Int, _ execution: Int) {
    DispatchQueue.clear()
    owner.api.busy = false; owner.connectionProfileSelection = nil; owner.connectionProfileSelectionGeneration = UUID()
    owner.routerIDs = [selectedID, entryID, exitID]; owner.profiles = catalogRows(owner.routerIDs)
    owner.connectionProfileCatalogSelectedID = selectedID
    owner.multihopNodeIDs = [entryID, exitID]; owner.multihopNodeTokens = sourceTokens
    fixtureDefaults.set("custom:Saved layers", forKey: macConnectionModeKey)
    fixtureDefaults.set(try! JSONEncoder().encode([MacConnectionCustomPreset(name: "Saved layers", layers: ["pq", "wg"])]), forKey: macConnectionCustomPresetsKey)
    fixtureDefaults.set(true, forKey: macConnectionMultihopEnabledKey)
    owner.routerPopup.selectItem(at: 0); owner.multihopEntryPopup.selectItem(at: 0); owner.multihopExitPopup.selectItem(at: 1)
    owner.multihopExitModePopup.selectItem(at: mode); owner.multihopExecutionPopup.selectItem(at: execution)
    owner.multihopEntryModePopup.selectItem(at: (mode * 3 + execution) % expectedEntries.count)
    owner.basePopup.selectItem(at: 0)
}
@MainActor func verify(_ body: [String: Any], _ mode: String, _ execution: String, updating: Bool) {
    var keys = Set(["expected_selected_node_id", "expected_profile_tokens", "name", "mode", "custom_layers", "multihop_enabled", "multihop_entry_id", "multihop_exit_id", "multihop_exit_mode", "multihop_execution", "multihop_entry_mode"])
    if updating { keys.insert("id") }
    check(Set(body.keys) == keys, "private fields copied or snapshot fields missing")
    check(body["multihop_enabled"] as? Bool == true && body["multihop_entry_id"] as? String == "entry_private" && body["multihop_exit_id"] as? String == "exit_private", "exact graph identities changed")
    check(body["multihop_exit_mode"] as? String == mode, "snapshot replaced the selected exit mode")
    check(body["multihop_execution"] as? String == execution, "snapshot replaced the selected execution")
    let entryIndex = (expectedModes.firstIndex(of: mode)! * 3 + executions.firstIndex(of: execution)!) % expectedEntries.count
    check(body["multihop_entry_mode"] as? String == expectedEntries[entryIndex], "snapshot replaced the selected entry mode")
    check(body["mode"] as? String == "custom:Saved layers" && body["custom_layers"] as? [String] == ["pq", "wg"], "mode or CUSTOM layers changed")
    if updating { check(body["id"] as? String == "saved-profile", "saved profile identity changed") }
}
@MainActor func loaded(_ body: [String: Any]) -> [String: Any] {
    var payload = body
    payload["profile"] = ["name": "Loaded profile", "mode": body["mode"] ?? "smart-auto"]
    payload["selected_node_id"] = "private-node"
    payload["profile_tokens"] = sourceTokens
    payload["private_key"] = "never-copy"
    return payload
}
for (m, mode) in expectedModes.enumerated() {
    for (e, execution) in executions.enumerated() {
        // Main profile manager: execute the exact snapshot, POST and Load
        // functions called by its native modal Add/Load/Update actions.
        choose(m, e)
        let add = try owner.connectionProfileSnapshot(name: settings.name.stringValue, id: nil)
        verify(add, mode, execution, updating: false)
        _ = try owner.connectionProfilePOST("/api/connection-profile/setup/save", body: add)
        verify(owner.api.calls.last!.body, mode, execution, updating: false)
        let payload = loaded(add)
        choose((m + 1) % expectedModes.count, (e + 1) % 3)
        owner.multihopEntryPopup.selectItem(at: 1); owner.multihopExitPopup.selectItem(at: 0)
        let before = owner.api.calls.count
        try owner.applyLoadedConnectionProfile(payload)
        check(owner.api.calls.count == before, "profile manager Load auto-connected")
        check(try RouterVPNNodeExitModes.require(index: owner.multihopExitModePopup.indexOfSelectedItem) == mode, "profile manager Load changed the selected mode")
        let update = try owner.connectionProfileSnapshot(name: settings.name.stringValue, id: "saved-profile")
        verify(update, mode, execution, updating: true)
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
        choose((m + 1) % expectedModes.count, (e + 1) % 3)
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
// Execute the composed main Connect callback with its real deferred work.
for (i, entryMode) in expectedEntries.enumerated() {
    for (e, execution) in executions.enumerated() {
        choose(i % expectedModes.count, e); owner.multihopEntryModePopup.selectItem(at: i)
        let before = owner.api.calls.count
        owner.connectMultihop()
        let progressOwner = owner.multihopProgressGeneration
        check(owner.api.calls.count == before, "Connect posted before its deferred owner ran")
        // Replacing the displayed value cannot rewrite the already captured body.
        owner.multihopEntryModePopup.selectItem(at: (i + 1) % expectedEntries.count)
        DispatchQueue.background.run()
        check(owner.api.calls.count == before + 1, "main Connect lost its captured request")
        let call = owner.api.calls.last!
        let keyModes = ["wg-pq", "awg2-pq", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"]
        let phases = (entryMode.isEmpty || keyModes.contains(entryMode) ? 120 : 0) + (keyModes.contains(expectedModes[i % expectedModes.count]) ? 120 : 0)
        let expectedTimeout: TimeInterval = execution == "auto" && phases > 0 ? TimeInterval(210 + phases) : 180
        check(call.timeout == expectedTimeout && owner.progressTimeout == expectedTimeout, "Connect or progress lost the captured native startup deadline")
        check(call.path == "/api/multihop/connect" && Set(call.body.keys) == Set(["entry_id", "exit_id", "base", "entry_mode", "exit_mode", "execution"]), "main Connect copied private fields or omitted graph choices")
        check(call.body["entry_mode"] as? String == entryMode && call.body["exit_mode"] as? String == expectedModes[i % expectedModes.count] && call.body["execution"] as? String == execution, "main Connect replaced captured entry, exit or execution")
        check(call.body["entry_id"] as? String == entryID && call.body["exit_id"] as? String == exitID && call.body["base"] as? String == "auto", "main Connect replaced exact identities or saved base fallback")
        owner.multihopProgressGeneration = UUID()
        DispatchQueue.main.run()
        check(owner.stoppedProgress.last == progressOwner, "Delayed Connect finalizer captured the replacement comparison owner")
        while !DispatchQueue.main.pending.isEmpty { DispatchQueue.main.run() }
        check(owner.liveTelemetryDelivery.mutations.isEmpty, "completed Connect retained its live-response mutation lease")
        DispatchQueue.clear()
    }
}
for i in [-1, expectedEntries.count, 100] {
    choose(0, 0); owner.multihopEntryModePopup.selectItem(at: i)
    let before = owner.api.calls.count; owner.connectMultihop()
    check(owner.api.calls.count == before && DispatchQueue.background.pending.isEmpty, "unavailable main entry reached Connect")
}
for invalid: String? in ["stale-mode", "", nil, "SHADOWSOCKS"] {
    choose(0, 0)
    var payload = loaded(try owner.connectionProfileSnapshot(name: "bad", id: nil))
    payload["multihop_exit_mode"] = invalid
    let previous = owner.captureConnectionProfileSelection(), generation = owner.connectionProfileSelectionGeneration
    rejects({ try owner.applyLoadedConnectionProfile(payload) }, "profile manager Load accepted an unsupported exit")
    check(owner.captureConnectionProfileSelection() == previous && owner.connectionProfileSelectionGeneration == generation, "failed Load mutated the existing selection")
    choose(0, 0); settings.api.loaded = payload
    let settingsPrevious = owner.captureConnectionProfileSelection()
    settings.loadProfile()
    check(settings.status.stringValue.hasPrefix("Load failed:") && owner.captureConnectionProfileSelection() == settingsPrevious, "Settings Load accepted an unsupported exit")
}
for invalidEntry: Any in ["stale-mode", "WG", "wg ", "auto", "OpenVPN", "WireGuard", "amneziawg ", NSNull(), 7] {
    choose(0, 0)
    var payload = loaded(try owner.connectionProfileSnapshot(name: "bad entry", id: nil))
    payload["multihop_entry_mode"] = invalidEntry
    let before = owner.captureConnectionProfileSelection(), generation = owner.connectionProfileSelectionGeneration
    rejects({ try owner.applyLoadedConnectionProfile(payload) }, "loaded entry silently became a base or another mode")
    check(owner.captureConnectionProfileSelection() == before && owner.connectionProfileSelectionGeneration == generation, "invalid entry load changed the captured owner")
}
choose(4, 2)
var legacyEntry = loaded(try owner.connectionProfileSnapshot(name: "legacy", id: nil))
legacyEntry.removeValue(forKey: "multihop_entry_mode")
try owner.applyLoadedConnectionProfile(legacyEntry)
check(try RouterVPNNodeEntryModes.require(index: owner.multihopEntryModePopup.indexOfSelectedItem) == "", "legacy load retained a different explicit entry mode")
for invalidIndex in [-1, expectedEntries.count, 100] {
    choose(0, 0); owner.multihopEntryModePopup.selectItem(at: invalidIndex)
    rejects({ _ = try owner.connectionProfileSnapshot(name: "bad entry", id: nil) }, "unavailable entry selector reached main profile save")
    rejects({ _ = try settings.currentMultihopSnapshot() }, "unavailable entry selector reached Settings save")
}
for invalidIndex in [-1, expectedModes.count, 100] {
    choose(0, 0); owner.multihopExitModePopup.selectItem(at: invalidIndex)
    rejects({ _ = try owner.connectionProfileSnapshot(name: "bad", id: nil) }, "out-of-range main exit index was accepted")
    rejects({ _ = try settings.currentMultihopSnapshot() }, "out-of-range Settings exit index was accepted")
    let before = settings.api.calls.count
    settings.addProfile(); settings.updateProfile()
    check(settings.api.calls.count == before, "invalid Settings snapshot reached the controller")
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
RACE_TESTS
ORDERED_TESTS
SETUP_TESTS
print("Actual AppKit profiles, deferred catalogs and Settings Add/Load/Update callbacks: \(checks) checks PASS")
'''

SWIFT_ORDERED = r'''
@MainActor func chooseOrdered(_ count: Int = 4) -> [[String: String]] {
    choose(0, 0)
    let ids = (0..<count).map { "ordered-\($0)" }
    let tokens = Dictionary(uniqueKeysWithValues: ids.enumerated().map { ($0.element, String(format: "%064x", $0.offset + 1)) })
    let rows = ids.enumerated().map { ["id": $0.element, "mode": $0.offset == count - 1 ? "shadowsocks" : "wg"] }
    owner.routerIDs = ids; owner.profiles = catalogRows(ids, tokens: tokens); owner.routerPopup.selectItem(at: count - 1)
    owner.connectionProfileCatalogSelectedID = ids.last!
    owner.multihopEntryPopup.selectItem(at: -1); owner.multihopExitPopup.selectItem(at: -1)
    owner.connectionProfileSelection = RouterVPNConnectionProfileSelection(selectedNodeID: ids.last!, multihopEnabled: true,
        entryMode: "", execution: "local", profileTokens: tokens, orderedNodes: rows)
    owner.api.orderedCurrent = ["selected_id": ids.last!, "profiles": owner.profiles]
    owner.api.orderedCapabilities = ["ordered_nodes_supported": true]; owner.api.afterOrderedSnapshot = nil
    return rows
}
@MainActor func verifyOrderedSnapshot(_ body: [String: Any], rows: [[String: String]], updating: Bool) {
    var keys = Set(["expected_selected_node_id", "expected_profile_tokens", "name", "mode", "custom_layers", "multihop_enabled", "multihop_nodes", "multihop_execution"])
    if updating { keys.insert("id") }
    check(Set(body.keys) == keys, "ordered save mixed pair fields or private credentials")
    check(body["multihop_nodes"] as? [[String: String]] == rows, "ordered save dropped, substituted or reordered a member")
    check(body["mode"] as? String == "shadowsocks" && body["custom_layers"] as? [String] == [], "ordered save retained unrelated mode or layers")
    check(body["multihop_enabled"] as? Bool == true && body["multihop_execution"] as? String == "local", "ordered save lost exact execution")
}
for length in [2, 3, 4, 8] {
    let rows = chooseOrdered(length)
    let selection = owner.captureConnectionProfileSelection()
    for updating in [false, true] {
        let snapshot = try owner.connectionProfileSnapshot(name: "Complete ordered path", id: updating ? "saved-profile" : nil)
        verifyOrderedSnapshot(snapshot, rows: rows, updating: updating)
        _ = try settings.write(path: updating ? "/api/connection-profile/setup/update" : "/api/connection-profile/setup/save", updating: updating)
        verifyOrderedSnapshot(settings.api.calls.last!.body, rows: rows, updating: updating)
        var payload = snapshot
        payload["profile"] = ["name": "Loaded ordered path", "mode": "shadowsocks"]; payload["selected_node_id"] = selection.selectedNodeID; payload["profile_tokens"] = selection.profileTokens
        owner.connectionProfileSelection?.orderedNodes = []
        try owner.applyLoadedConnectionProfile(payload)
        check(owner.captureConnectionProfileSelection().orderedNodes == rows, "manager Load lost a middle node")
        owner.connectionProfileSelection?.orderedNodes = []
        try settings.applyLoadedMultihop(payload)
        check(owner.captureConnectionProfileSelection().orderedNodes == rows, "Settings Load lost a middle node")
    }
    DispatchQueue.clear()
    let before = owner.api.calls.count, capturedProgress = owner.multihopProgressGeneration
    owner.connectMultihop(); check(owner.api.calls.count == before, "ordered Connect did not defer its captured request")
    DispatchQueue.background.run()
    check(owner.api.calls.count == before + 1, "ordered Connect never reached the real controller endpoint")
    let request = owner.api.calls.last!
    check(request.path == "/api/multihop/connect" && request.timeout == 180, "ordered Connect used the wrong endpoint or deadline")
    check(Set(request.body.keys) == Set(["nodes", "execution", "expected_selected_node_id", "expected_profile_tokens"]), "ordered Connect copied secrets or omitted freshness owners")
    check(request.body["nodes"] as? [[String: String]] == rows && request.body["execution"] as? String == "local", "ordered Connect lost the actual full order")
    check(request.body["expected_profile_tokens"] as? [String: String] == selection.profileTokens && request.body["expected_selected_node_id"] as? String == selection.selectedNodeID, "ordered Connect lost all-source locked-capture preconditions")
    owner.multihopProgressGeneration = UUID(); DispatchQueue.main.run()
    check(owner.stoppedProgress.last == capturedProgress, "ordered completion retired a replacement progress owner")
    DispatchQueue.clear()
}
for invalid in [[String: Any](), ["ordered_nodes_supported": false], ["ordered_nodes_supported": "true"], ["ordered_nodes_supported": 1]] {
    _ = chooseOrdered(); owner.api.orderedCapabilities = invalid; let before = owner.api.calls.count
    owner.connectMultihop(); DispatchQueue.background.run()
    check(owner.api.calls.count == before, "an older or malformed controller silently accepted the ordered request")
}
for changedIndex in 0..<4 {
    _ = chooseOrdered(); let before = owner.api.calls.count
    var changed = owner.profiles; changed[changedIndex]["profile_token"] = String(repeating: "f", count: 64)
    owner.api.orderedCurrent["profiles"] = changed
    owner.connectMultihop(); DispatchQueue.background.run()
    check(owner.api.calls.count == before, "a relinked ordered member reached Connect")
}
_ = chooseOrdered(); owner.api.orderedCurrent["selected_id"] = "replacement"
var orderedBefore = owner.api.calls.count; owner.connectMultihop(); DispatchQueue.background.run()
check(owner.api.calls.count == orderedBefore, "ordered Connect substituted the original selected control")
_ = chooseOrdered(); owner.api.afterOrderedSnapshot = { owner.connectionProfileSelectionGeneration = UUID() }
orderedBefore = owner.api.calls.count; owner.connectMultihop(); DispatchQueue.background.run()
check(owner.api.calls.count == orderedBefore, "stale ordered callback overwrote a newer selection")
_ = chooseOrdered(); owner.api.busy = true; orderedBefore = owner.api.calls.count; owner.connectMultihop()
check(DispatchQueue.background.pending.isEmpty && owner.api.calls.count == orderedBefore, "busy ordered Connect reached its worker")
_ = chooseOrdered()
let complete = owner.captureConnectionProfileSelection()
var missingToken = complete; missingToken.profileTokens.removeValue(forKey: "ordered-1")
rejects({ _ = try RouterVPNOrderedNodes.connectBody(missingToken, current: owner.api.orderedCurrent) }, "missing middle-source token passed")
var extraField = complete.orderedNodes; extraField[1]["credential"] = "must-not-copy"
rejects({ _ = try RouterVPNOrderedNodes.decode(extraField, control: complete.selectedNodeID) }, "private node field entered an ordered reference")
var wrongFinal = complete.orderedNodes; wrongFinal[3]["id"] = "replacement"
rejects({ _ = try RouterVPNOrderedNodes.decode(wrongFinal, control: complete.selectedNodeID) }, "arbitrary final member replaced the independently selected control")
for key in ["multihop_entry_id", "multihop_exit_id", "multihop_exit_mode", "multihop_entry_mode"] {
    var payload: [String: Any] = ["multihop_nodes": complete.orderedNodes, "multihop_enabled": true, "multihop_execution": "local", "selected_node_id": complete.selectedNodeID, "profile_tokens": complete.profileTokens]
    payload[key] = "mixed"
    rejects({ _ = try owner.validatedLoadedConnectionProfileSelection(payload) }, "mixed ordered/pair restore was accepted")
}
// Exercise the exact model and apply transaction used by the native editor.
_ = chooseOrdered(8)
var draft = try owner.makeOrderedNodeDraft()
let originalControl = draft.control
try draft.chooseMode("awg2-fast", at: 0); try draft.chooseMode("awg2-strong", at: 1)
check(draft.nodes[0]["mode"] == "awg2-fast" && draft.nodes[1]["mode"] == "awg2-strong", "editor substituted the chosen AWG variant")
for mode in ["awg", "wg-pq", "shadowsocks", "", "AWG2 Fast"] {
    rejects({ try draft.chooseMode(mode, at: 0) }, "editor accepted an unsupported or normalized prefix transport")
}
rejects({ try draft.chooseMode("awg2-fast", at: draft.prefixes.count) }, "editor changed its final exit transport")
try draft.move(1, by: -1); check(draft.prefixes[0] == "ordered-1" && draft.nodes.last?["id"] == originalControl, "editor move changed the final owner")
check(draft.nodes[0]["mode"] == "awg2-strong" && draft.nodes[1]["mode"] == "awg2-fast", "editor move lost its member transport")
try draft.remove(1); try draft.add("ordered-0")
check(draft.prefixes.last == "ordered-0", "editor remove/add did not preserve explicit order")
check(draft.nodes[0]["mode"] == "awg2-strong" && draft.nodes[draft.prefixes.count - 1]["mode"] == "wg", "editor remove/add reassigned another member transport")
rejects({ try draft.add("ordered-0") }, "duplicate editor hop accepted")
rejects({ try draft.add(originalControl) }, "editor accepted the final exit as a prefix")
rejects({ try draft.move(draft.prefixes.count, by: -1) }, "editor moved its pinned exit")
rejects({ try draft.remove(draft.prefixes.count) }, "editor removed its pinned exit")
let staged = try draft.selection(); orderedBefore = owner.api.calls.count
try owner.applyOrderedNodeDraft(draft)
check(owner.captureConnectionProfileSelection().orderedNodes == staged.orderedNodes && owner.api.calls.count == orderedBefore, "editor Apply connected or lost its selected order")
let reopenedDraft = try owner.makeOrderedNodeDraft()
check(reopenedDraft.nodes == staged.orderedNodes, "reopened editor reset selected AWG transport")
rejects({ try owner.applyOrderedNodeDraft(draft) }, "stale editor generation was accepted twice")
// Imported custom middle is retained as its original external source.
_ = chooseOrdered(3)
let customBase = owner.captureConnectionProfileSelection()
var customCatalog = owner.profiles
customCatalog[1]["node_kind"] = "external"
customCatalog[1]["external"] = ["protocol": "shadowsocks", "ordered_middle_supported": true]
var customSelection = customBase
customSelection.orderedNodes[1]["mode"] = "shadowsocks"
var customDraft = try RouterVPNOrderedNodeDraft(selection: customSelection, generation: UUID(), catalog: customCatalog)
check(customDraft.nodes[1]["mode"] == "shadowsocks", "custom middle lost its imported transport")
rejects({ try customDraft.chooseMode("wg", at: 1) }, "custom middle acquired paired WireGuard transport")
let customCaptured = try customDraft.selection()
let customCurrent: [String: Any] = ["selected_id": customBase.selectedNodeID, "profiles": customCatalog]
let customBody = try RouterVPNOrderedNodes.connectBody(customCaptured, current: customCurrent)
check(customBody["nodes"] as? [[String: String]] == customCaptured.orderedNodes, "custom Connect lost original source order")
try customDraft.move(1, by: -1)
rejects({ _ = try customDraft.selection() }, "custom source became physical entry")
customCatalog[1]["profile_token"] = String(repeating: "f", count: 64)
rejects({ _ = try RouterVPNOrderedNodes.connectBody(customCaptured, current: ["selected_id": customBase.selectedNodeID, "profiles": customCatalog]) }, "relinked custom middle retained permission")
_ = chooseOrdered(); let staleDraft = try owner.makeOrderedNodeDraft()
var staleCatalog = owner.profiles; staleCatalog[1]["profile_token"] = String(repeating: "e", count: 64); owner.api.orderedCurrent["profiles"] = staleCatalog
rejects({ try owner.applyOrderedNodeDraft(staleDraft) }, "editor Apply accepted a relinked middle node")
_ = chooseOrdered(); let busyDraft = try owner.makeOrderedNodeDraft(); owner.api.busy = true
rejects({ try owner.applyOrderedNodeDraft(busyDraft) }, "editor Apply changed a running connection")
_ = chooseOrdered(); var emptyDraft = try owner.makeOrderedNodeDraft()
while !emptyDraft.prefixes.isEmpty { try emptyDraft.remove(0) }
rejects({ _ = try emptyDraft.selection() }, "editor accepted a final exit with no entry")
_ = chooseOrdered()
owner.routerPopup.selectItem(at: 0); owner.recordConnectionProfileNodeChoice("ordered-0")
check(owner.connectionProfileSelection?.orderedNodes.isEmpty == true && owner.connectionProfileSelection?.nodeDefaultsPending == true,
      "explicit new selected node inherited the prior node's ordered path")
let newOrder = [["id": "ordered-1", "mode": "wg"], ["id": "ordered-2", "mode": "wg"], ["id": "ordered-0", "mode": "shadowsocks"]]
var newCatalog = owner.profiles
newCatalog[0]["multihop_nodes"] = newOrder; newCatalog[0]["multihop_enabled"] = true; newCatalog[0]["multihop_execution"] = "local"
let catalogCapture = owner.beginConnectionProfileRefresh(hops: false)
check(try owner.applyConnectionProfileNodeCatalog(["profiles": newCatalog, "selected_id": "ordered-0"], capture: catalogCapture), "new selected node's matching catalog was discarded")
check(owner.captureConnectionProfileSelection().orderedNodes == newOrder && !owner.captureConnectionProfileSelection().nodeDefaultsPending,
      "new selected node lost its own saved ordered path")
try owner.requireResolvedConnectionProfileSelection()
_ = chooseOrdered(); owner.routerPopup.selectItem(at: 0); owner.recordConnectionProfileNodeChoice("ordered-0")
newCatalog[0]["multihop_nodes"] = [["id": "ordered-1", "mode": "wg"], ["id": "ordered-2", "mode": "shadowsocks"]]
let invalidCapture = owner.beginConnectionProfileRefresh(hops: false)
rejects({ _ = try owner.applyConnectionProfileNodeCatalog(["profiles": newCatalog, "selected_id": "ordered-0"], capture: invalidCapture) }, "malformed saved node path fell back to a different pair")
check(owner.routerPopup.indexOfSelectedItem == -1, "malformed saved ordered path acquired a resolved selected control")
_ = chooseOrdered(); fixtureDefaults.set(false, forKey: macConnectionMultihopEnabledKey)
let ordinary = try owner.connectionProfileSnapshot(name: "direct", id: nil)
check(ordinary["multihop_nodes"] == nil && ordinary["multihop_enabled"] as? Bool == false, "disabled ordered draft contaminated a direct profile")
DispatchQueue.clear()
'''

SWIFT_SETUP = r'''
@MainActor func setupRows(_ count: Int = 4) -> [[String: String]] {
    owner.api.afterSetup = nil; settings.api.afterSetup = nil
    owner.api.setupResponse = nil; settings.api.setupResponse = nil
    owner.api.afterLoad = nil; settings.api.afterLoad = nil
    owner.api.afterStatus = nil; settings.api.afterStatus = nil
    var rows = chooseOrdered(count)
    for i in 0..<(count - 1) { rows[i]["mode"] = ["awg2-fast", "wg", "awg2-strong"][i % 3] }
    owner.connectionProfileSelection?.orderedNodes = rows
    owner.profiles[count - 1]["multihop_enabled"] = true
    owner.profiles[count - 1]["multihop_nodes"] = rows
    owner.profiles[count - 1]["multihop_execution"] = "local"
    return rows
}
@MainActor func setupLoaded(_ rows: [[String: String]], tokens: [String: String]) -> [String: Any] {
    ["profile": ["name": "Captured ordered setup", "mode": "shadowsocks"], "mode": "shadowsocks", "custom_layers": [String](),
     "multihop_nodes": rows, "multihop_enabled": true, "multihop_execution": "local",
     "selected_node_id": rows.last!["id"]!, "profile_tokens": tokens]
}
@MainActor func setupAction(_ manager: Bool, _ operation: String) throws {
    if manager {
        let body: [String: Any] = operation == "load" ? ["id": "saved-profile"] : try owner.connectionProfileSnapshot(name: "Original setup", id: operation == "update" ? "saved-profile" : nil)
        let reply = try owner.connectionProfilePOST("/api/connection-profile/setup/" + operation, body: body)
        if operation == "load" { try owner.applyLoadedConnectionProfile(reply) }
    } else {
        if operation == "load" { settings.loadProfile(); if settings.status.stringValue.hasPrefix("Load failed:") { throw RouterVPNOrderedNodes.issue(settings.status.stringValue) } }
        else { _ = try settings.write(path: "/api/connection-profile/setup/" + operation, updating: operation == "update") }
    }
}
for manager in [true, false] {
    for count in [2, 3, 4, 8] { for operation in ["save", "update", "load"] {
        let rows = setupRows(count), original = owner.captureConnectionProfileSelection()
        let api = manager ? owner.api : settings.api
        api.loaded = setupLoaded(rows, tokens: original.profileTokens)
        let before = api.calls.count
        try setupAction(manager, operation)
        check(api.calls.count == before + 1, "setup action connected or duplicated its request")
        let request = api.calls.last!.body
        check(request["expected_selected_node_id"] as? String == original.selectedNodeID && request["expected_profile_tokens"] as? [String: String] == original.profileTokens,
              "setup request lost complete original inventory")
        check(owner.captureConnectionProfileSelection().orderedNodes == rows && owner.captureConnectionProfileSelection().profileTokens == original.profileTokens,
              "finalized setup response lost a member mode or source receipt")
        check(!String(data: try JSONSerialization.data(withJSONObject: request), encoding: .utf8)!.contains("private_key"), "setup request copied private sources")
    } }
    for operation in ["save", "update", "load"] { for fault in ["new-generation", "visible-off", "mode-change", "source-relinked"] {
        let rows = setupRows(), original = owner.captureConnectionProfileSelection()
        let api = manager ? owner.api : settings.api
        api.loaded = setupLoaded(rows, tokens: original.profileTokens)
        api.afterSetup = { _ in
            if fault == "new-generation" { owner.recordVisibleConnectionProfileSelection() }
            if fault == "visible-off" { fixtureDefaults.set(false, forKey: macConnectionMultihopEnabledKey) }
            if fault == "mode-change" { fixtureDefaults.set("auto", forKey: macConnectionModeKey) }
            if fault == "source-relinked" { owner.profiles[0]["profile_token"] = String(repeating: "f", count: 64) }
        }
        rejects({ try setupAction(manager, operation) }, "late setup response accepted " + fault)
        if fault == "visible-off" { check(!fixtureDefaults.bool(forKey: macConnectionMultihopEnabledKey), "late setup response reversed a newer Off choice") }
        if fault == "mode-change" { check(fixtureDefaults.string(forKey: macConnectionModeKey) == "auto", "late setup response replaced a newer mode") }
    } }
    for operation in ["save", "update"] { for fault in ["changed-token", "extra-token", "missing-token", "reordered-members", "changed-mode", "wrong-final-mode", "server-execution"] {
        let rows = setupRows(), original = owner.captureConnectionProfileSelection(), generation = owner.connectionProfileSelectionGeneration
        let api = manager ? owner.api : settings.api
        api.setupResponse = { value in
            var value = value
            if ["changed-token", "extra-token", "missing-token"].contains(fault) {
                var tokens = value["profile_tokens"] as! [String: String]
                if fault == "changed-token" { tokens[rows[0]["id"]!] = String(repeating: "e", count: 64) }
                if fault == "extra-token" { tokens["unrelated"] = String(repeating: "d", count: 64) }
                if fault == "missing-token" { tokens.removeValue(forKey: rows[0]["id"]!) }
                value["profile_tokens"] = tokens
            }
            if fault == "reordered-members" { var changed = rows; changed.swapAt(0, 1); value["multihop_nodes"] = changed }
            if fault == "changed-mode" { var changed = rows; changed[0]["mode"] = "awg2-strong"; value["multihop_nodes"] = changed }
            if fault == "wrong-final-mode" { value["profile"] = ["name": "Wrong mode", "mode": "smart-auto"] }
            if fault == "server-execution" { value["multihop_execution"] = "server" }
            return value
        }
        rejects({ try setupAction(manager, operation) }, "setup response accepted " + fault)
        check(owner.captureConnectionProfileSelection() == original && owner.connectionProfileSelectionGeneration == generation,
              "rejected setup response replaced original UI ownership")
    } }
    // The stored catalog has four members; the unsaved editor has three, and
    // the loaded target has two with a different independently selected final.
    let storedRows = setupRows(), oldControl = owner.captureConnectionProfileSelection().selectedNodeID
    var draft = storedRows; draft.remove(at: 1); owner.connectionProfileSelection?.orderedNodes = draft
    let originalTokens = try owner.connectionProfileCatalogTokens(owner.profiles)
    let targetRows = [["id": "ordered-0", "mode": "awg2-fast"], ["id": "ordered-1", "mode": "shadowsocks"]]
    let targetTokens = ["ordered-0": String(repeating: "a", count: 64), "ordered-1": String(repeating: "b", count: 64)]
    let api = manager ? owner.api : settings.api
    api.loaded = setupLoaded(targetRows, tokens: targetTokens)
    try setupAction(manager, "load")
    let request = api.calls.last!.body
    check(request["expected_selected_node_id"] as? String == oldControl && request["expected_profile_tokens"] as? [String: String] == originalTokens,
          "Load substituted draft or target sources for the original saved inventory")
    check(owner.captureConnectionProfileSelection().selectedNodeID == "ordered-1" && owner.captureConnectionProfileSelection().orderedNodes == targetRows && owner.captureConnectionProfileSelection().profileTokens == targetTokens,
          "Load did not retain its finalized target receipt")
    check(owner.routerPopup.indexOfSelectedItem == -1, "changed Load target source was treated as an old resolved catalog node")
    rejects({ _ = try owner.connectionProfileSnapshot(name: "Too early", id: nil) }, "changed Load receipt authorized a write before matching catalog confirmation")
    var confirmed = owner.profiles
    for index in confirmed.indices { if let id = confirmed[index]["id"] as? String, let token = targetTokens[id] { confirmed[index]["profile_token"] = token } }
    confirmed[1]["multihop_enabled"] = true; confirmed[1]["multihop_nodes"] = targetRows; confirmed[1]["multihop_execution"] = "local"
    let refresh = owner.beginConnectionProfileRefresh(hops: false)
    check(try owner.applyConnectionProfileNodeCatalog(["profiles": confirmed, "selected_id": "ordered-1"], capture: refresh), "matching Load target catalog was discarded")
    try setupAction(manager, "save")
    check(api.calls.last!.body["expected_profile_tokens"] as? [String: String] == targetTokens, "later setup write reused the pre-Load source receipt")
    let rows = setupRows(), original = owner.captureConnectionProfileSelection()
    api.loaded = setupLoaded(rows, tokens: original.profileTokens)
    api.setupResponse = { value in var value = value; var tokens = value["profile_tokens"] as! [String: String]; tokens["unrelated"] = String(repeating: "c", count: 64); value["profile_tokens"] = tokens; return value }
    rejects({ try setupAction(manager, "load") }, "Load accepted unrelated response source receipts")
    check(owner.routerPopup.indexOfSelectedItem == -1 && owner.connectionProfileCatalogSelectedID.isEmpty, "invalid Load retained resolved prior authority")
}
_ = setupRows()
let staleBody = try owner.connectionProfileSnapshot(name: "Original On choice", id: nil)
fixtureDefaults.set(false, forKey: macConnectionMultihopEnabledKey); owner.recordVisibleConnectionProfileSelection()
let beforeStale = owner.api.calls.count
rejects({ _ = try owner.connectionProfilePOST("/api/connection-profile/setup/save", body: staleBody) }, "old setup body overrode a newer Off choice before dispatch")
check(owner.api.calls.count == beforeStale, "stale setup body reached transport")
_ = setupRows()
let modeBody = try owner.connectionProfileSnapshot(name: "Original mode", id: nil)
let beforeModeChange = owner.api.calls.count
owner.api.afterStatus = { fixtureDefaults.set("auto", forKey: macConnectionModeKey); owner.api.afterStatus = nil }
rejects({ _ = try owner.connectionProfilePOST("/api/connection-profile/setup/save", body: modeBody) }, "status handoff sent a setup after its original mode changed")
check(owner.api.calls.count == beforeModeChange, "mode-stale setup reached transport")
_ = setupRows(); let oldCatalog = owner.beginConnectionProfileRefresh(hops: false), oldProfiles = owner.profiles
try setupAction(true, "save")
check(!(try owner.applyConnectionProfileNodeCatalog(["profiles": oldProfiles, "selected_id": "ordered-3"], capture: oldCatalog)), "pre-save catalog reply replaced finalized source ownership")
DispatchQueue.clear()
'''

SWIFT_RACES = r'''
@MainActor func nodeReply(_ ids: [String], selected: String = selectedID, tokens: [String: String] = sourceTokens) -> [String: Any] {
    ["profiles": catalogRows(ids, tokens: tokens), "selected_id": selected]
}
@MainActor func hopReply(_ ids: [String], tokens: [String: String] = sourceTokens) -> [String: Any] {
    ["nodes": catalogRows(ids, tokens: tokens), "configured_entry_id": ids.first ?? "", "configured_exit_id": ids.first ?? ""]
}
@MainActor func loadThrough(_ manager: Bool, _ payload: [String: Any]) throws {
    if manager { owner.api.loaded = payload; let response = try owner.connectionProfilePOST("/api/connection-profile/setup/load", body: ["id": "saved-profile"]); try owner.applyLoadedConnectionProfile(response) }
    else { settings.api.loaded = payload; settings.loadProfile(); check(settings.status.stringValue.hasPrefix("Loaded "), "Settings deferred Load failed") }
}
@MainActor func runNodeReply(_ payload: [String: Any]) {
    owner.api.nodeReplies = [payload]; DispatchQueue.background.run(); DispatchQueue.main.run()
}
@MainActor func runHopReply(_ payload: [String: Any]) {
    owner.api.hopReplies = [payload]; DispatchQueue.background.run(); DispatchQueue.main.run()
}
for manager in [true, false] {
    choose(4, 2)
    var first = loaded(try owner.connectionProfileSnapshot(name: "first", id: nil))
    first["multihop_entry_id"] = "new-entry"; first["multihop_exit_id"] = "new-exit"
    let firstTokens = [selectedID: sourceTokens[selectedID]!, "new-entry": String(repeating: "d", count: 64), "new-exit": String(repeating: "e", count: 64)]
    first["profile_tokens"] = firstTokens
    let postCount = owner.api.calls.count
    try loadThrough(manager, first)
    check(owner.multihopEntryPopup.indexOfSelectedItem == -1 && owner.multihopExitPopup.indexOfSelectedItem == -1, "Load used an old or first catalog node")
    let waiting = owner.captureConnectionProfileSelection()
    check(waiting.entryID == "new-entry" && waiting.exitID == "new-exit" && waiting.exitMode == "reality-xhttp" && waiting.execution == "auto", "unresolved Load lost its exact references")
    rejects({ _ = try owner.connectionProfileSnapshot(name: "waiting", id: nil) }, "unresolved Load allowed another profile save")
    runNodeReply(nodeReply(["new-exit", selectedID, "new-entry"], tokens: firstTokens))
    runHopReply(hopReply(["new-exit", "new-entry"], tokens: firstTokens))
    let resolved = owner.captureConnectionProfileSelection()
    check(resolved == waiting && owner.multihopEntryPopup.indexOfSelectedItem == 1 && owner.multihopExitPopup.indexOfSelectedItem == 0, "deferred catalogs restored indices instead of exact IDs")
    check(owner.api.calls.count == postCount + (manager ? 1 : 0), "deferred profile restoration connected automatically")
    _ = try owner.connectionProfileSnapshot(name: "resolved", id: nil)

    // Release the second Load's node response first, then the first Load's
    // already-fetched response. The later graph owns both catalog families.
    choose(0, 0)
    let original = loaded(try owner.connectionProfileSnapshot(name: "original", id: nil))
    try loadThrough(manager, original)
    owner.api.nodeReplies = [nodeReply([selectedID, entryID, exitID])]; DispatchQueue.background.run()
    var newer = first; newer["multihop_exit_mode"] = "naive-h3"; newer["multihop_execution"] = "server"
    try loadThrough(manager, newer)
    owner.api.nodeReplies = [nodeReply([selectedID, "new-entry", "new-exit"], tokens: firstTokens)]; DispatchQueue.background.run()
    check(DispatchQueue.main.pending.count == 2, "real node refreshes did not defer independently")
    DispatchQueue.main.run(1)
    let newerIDs = owner.routerIDs
    DispatchQueue.main.run()
    check(owner.routerIDs == newerIDs && owner.captureConnectionProfileSelection().entryID == "new-entry", "old node reply overwrote a newer loaded profile")
    runHopReply(hopReply(["new-exit", "new-entry"], tokens: firstTokens))
    check(owner.captureConnectionProfileSelection().exitMode == "naive-h3" && owner.captureConnectionProfileSelection().execution == "server", "old reply changed loaded mode/execution")
}

// Two requests from the same selection: completion order must not replace the
// newest catalog. Snapshot equality alone cannot detect this ordering.
choose(5, 1); owner.recordVisibleConnectionProfileSelection()
owner.refreshAdvanced(); owner.refreshAdvanced()
owner.api.hopReplies = [hopReply([entryID, exitID]), hopReply([exitID, "extra", entryID])]
DispatchQueue.background.run(); DispatchQueue.background.run()
DispatchQueue.main.run(1); let latest = owner.multihopNodeIDs; DispatchQueue.main.run()
check(latest == [exitID, "extra", entryID] && owner.multihopNodeIDs == latest, "older refresh replaced the newest catalog")

// Actual user callbacks advance ownership even for A -> B -> A changes.
choose(0, 0); owner.recordVisibleConnectionProfileSelection()
owner.refreshProfiles(); owner.api.nodeReplies = [nodeReply([selectedID, entryID, exitID])]; DispatchQueue.background.run()
let nodeGeneration = owner.connectionProfileSelectionGeneration
owner.routerPopup.selectItem(at: 1); owner.selectRouter()
check(owner.connectionProfileSelectionGeneration != nodeGeneration && owner.routerPopup.indexOfSelectedItem == -1 && owner.captureConnectionProfileSelection().selectedNodeID == entryID, "actual node callback did not capture provisional ownership")
DispatchQueue.main.run()
check(owner.routerPopup.indexOfSelectedItem == -1 && owner.captureConnectionProfileSelection().selectedNodeID == entryID, "late node reply replaced a newer user-selected node")
DispatchQueue.background.run(); DispatchQueue.main.run()
DispatchQueue.main.run() // captured asyncAction mutation completion precedes its new catalog reply
check(owner.liveTelemetryDelivery.mutations.isEmpty, "completed node selection retained its live-response mutation lease")
runNodeReply(nodeReply([exitID, selectedID, entryID], selected: entryID))
check(owner.routerPopup.indexOfSelectedItem == 2 && owner.captureConnectionProfileSelection().selectedNodeID == entryID, "confirmed user node choice did not resolve by identity")
DispatchQueue.clear()
for aba in [false, true] {
    choose(0, 0); owner.recordVisibleConnectionProfileSelection()
    owner.refreshAdvanced(); owner.api.hopReplies = [hopReply([exitID, entryID, "stale-only"])]
    DispatchQueue.background.run()
    owner.multihopExitModePopup.selectItem(at: 6); owner.connectionProfileHopChanged()
    owner.multihopExecutionPopup.selectItem(at: 2); owner.multihopExecutionChanged()
    if aba { owner.multihopExitModePopup.selectItem(at: 0); owner.connectionProfileHopChanged(); owner.multihopExecutionPopup.selectItem(at: 0); owner.multihopExecutionChanged() }
    let current = owner.captureConnectionProfileSelection(), ids = owner.multihopNodeIDs
    DispatchQueue.main.run()
    check(owner.multihopNodeIDs == ids && owner.captureConnectionProfileSelection() == current, "late refresh overwrote a newer user selection or ABA generation")
}

// Same-ID credentials changed: opaque source identity differs despite equal
// IDs and names. Keep the captured reference unresolved until explicit choice.
choose(3, 2); owner.recordVisibleConnectionProfileSelection()
var relinked = sourceTokens; relinked[exitID] = String(repeating: "f", count: 64)
owner.refreshAdvanced(); runHopReply(hopReply([entryID, exitID], tokens: relinked))
check(owner.multihopExitPopup.indexOfSelectedItem == -1 && owner.captureConnectionProfileSelection().profileTokens[exitID] == sourceTokens[exitID], "same-ID relink replaced captured node credentials")
rejects({ _ = try owner.connectionProfileSnapshot(name: "relinked", id: nil) }, "same-ID relink allowed stale profile capture")
let rejectedPosts = settings.api.calls.count; settings.addProfile(); settings.updateProfile()
check(settings.api.calls.count == rejectedPosts, "same-ID relink reached profile mutation")
owner.multihopExitPopup.selectItem(at: 1); owner.connectionProfileHopChanged()
check(owner.captureConnectionProfileSelection().profileTokens[exitID] == relinked[exitID], "explicit new node choice did not adopt its current source")
owner.refreshAdvanced(); runHopReply(hopReply([exitID, entryID], tokens: relinked))
check(owner.multihopExitPopup.indexOfSelectedItem == 0, "explicit replacement was not retained")

choose(2, 0); owner.recordVisibleConnectionProfileSelection()
owner.refreshAdvanced(); runHopReply(hopReply([entryID]))
check(owner.multihopExitPopup.indexOfSelectedItem == -1 && owner.captureConnectionProfileSelection().exitID == exitID, "removed exit silently became the first node")
owner.refreshAdvanced(); runHopReply(hopReply([entryID, "different-relink"]))
check(owner.multihopExitPopup.indexOfSelectedItem == -1 && owner.captureConnectionProfileSelection().exitID == exitID, "newly linked node inherited a removed identity")
owner.refreshAdvanced(); runHopReply(hopReply([exitID, entryID]))
check(owner.multihopExitPopup.indexOfSelectedItem == 0, "same captured source could not resolve after catalog removal")

// A relink of the selected control node also invalidates the displayed owner.
choose(2, 1); owner.recordVisibleConnectionProfileSelection()
var changedControl = sourceTokens; changedControl[selectedID] = String(repeating: "f", count: 64)
owner.refreshProfiles(); runNodeReply(nodeReply([selectedID, entryID, exitID], tokens: changedControl))
check(owner.routerPopup.indexOfSelectedItem == -1 && owner.captureConnectionProfileSelection().profileTokens[selectedID] == sourceTokens[selectedID], "selected control node relink was adopted silently")
rejects({ _ = try owner.connectionProfileSnapshot(name: "control relink", id: nil) }, "relinked control allowed a profile write")
DispatchQueue.clear()

for malformed in ["missing token", "duplicate ID"] {
    choose(1, 2); owner.recordVisibleConnectionProfileSelection()
    let previous = owner.captureConnectionProfileSelection(), ids = owner.multihopNodeIDs
    var reply = hopReply([entryID, exitID])
    var rows = reply["nodes"] as! [[String: Any]]
    if malformed == "missing token" { rows[0].removeValue(forKey: "profile_token") } else { rows.append(rows[0]) }
    reply["nodes"] = rows; owner.refreshAdvanced(); runHopReply(reply)
    check(owner.multihopNodeIDs == ids && owner.captureConnectionProfileSelection() == previous, "malformed catalog partially changed ownership")
}

// Busy session or a candidate-owned temporary path cannot load a profile,
// including a session that begins after the Settings HTTP Load returns.
choose(6, 2); owner.recordVisibleConnectionProfileSelection()
let busyPayload = loaded(try owner.connectionProfileSnapshot(name: "busy", id: nil))
let previousBusy = owner.captureConnectionProfileSelection()
owner.api.busy = true
rejects({ try owner.applyLoadedConnectionProfile(busyPayload) }, "active session accepted manager Load")
rejects({ _ = try owner.connectionProfileSnapshot(name: "busy", id: nil) }, "active session accepted manager Add/Update")
let busyPosts = settings.api.calls.count; settings.addProfile(); settings.updateProfile()
check(settings.api.calls.count == busyPosts, "active session accepted Settings Add/Update")
settings.api.loaded = busyPayload; settings.loadProfile()
check(settings.status.stringValue.hasPrefix("Load failed:") && owner.captureConnectionProfileSelection() == previousBusy, "post-response active session allowed Settings Load")
owner.multihopEntryPopup.selectItem(at: 1); let candidates = owner.candidatesOpened; owner.connectionProfileEntryChanged()
check(owner.captureConnectionProfileSelection() == previousBusy && owner.candidatesOpened == candidates, "busy entry action changed selection or opened candidates")
owner.api.busy = false; MacViaEntryCandidateReservation.shared.active = true
rejects({ try owner.applyLoadedConnectionProfile(busyPayload) }, "candidate-owned path accepted manager Load")
rejects({ try settings.applyLoadedMultihop(busyPayload) }, "active path accepted direct Settings Load delivery")
let candidatePosts = settings.api.calls.count; settings.addProfile(); settings.updateProfile()
check(settings.api.calls.count == candidatePosts, "candidate-owned path accepted Settings Add/Update")
MacViaEntryCandidateReservation.shared.active = false
settings.api.afterLoad = { owner.api.busy = true }
settings.loadProfile()
check(settings.status.stringValue.hasPrefix("Load failed:") && owner.routerPopup.indexOfSelectedItem == -1 && owner.connectionProfileCatalogSelectedID.isEmpty, "session beginning after HTTP Load retained stale UI authority")
settings.api.afterLoad = nil; owner.api.busy = false
choose(6, 2); owner.recordVisibleConnectionProfileSelection()
for malformed in ["missing map", "wrong token"] {
    var invalid = busyPayload
    if malformed == "missing map" { invalid.removeValue(forKey: "profile_tokens") }
    else { var tokens = sourceTokens; tokens[entryID] = "not-an-opaque-source-token"; invalid["profile_tokens"] = tokens }
    let generation = owner.connectionProfileSelectionGeneration
    rejects({ try owner.applyLoadedConnectionProfile(invalid) }, "unowned Load was accepted")
    check(owner.captureConnectionProfileSelection() == previousBusy && owner.connectionProfileSelectionGeneration == generation, "invalid source tokens partially changed a loaded profile")
}
for manager in [true, false] {
    for malformed in [false, true] {
        choose(4, 1); owner.recordVisibleConnectionProfileSelection()
        let previous = owner.captureConnectionProfileSelection(), generation = owner.connectionProfileSelectionGeneration
        let api = manager ? owner.api : settings.api
        api.failLoad = !malformed; api.malformedLoad = malformed
        if manager {
            rejects({ let payload = try owner.connectionProfilePOST("/api/connection-profile/setup/load", body: ["id": "saved-profile"]); try owner.applyLoadedConnectionProfile(payload) }, "uncertain manager Load succeeded")
        } else { settings.loadProfile(); check(settings.status.stringValue.hasPrefix("Load failed:"), "uncertain Settings Load succeeded") }
        check(owner.captureConnectionProfileSelection() == previous && owner.connectionProfileSelectionGeneration != generation && owner.routerPopup.indexOfSelectedItem == -1 && owner.connectionProfileCatalogSelectedID.isEmpty, "uncertain Load retained old resolved node authority")
        rejects({ _ = try owner.connectionProfileSnapshot(name: "uncertain Load", id: nil) }, "uncertain Load authorized a profile write")
        owner.api.busy = true; owner.multihopEntryPopup.selectItem(at: 0); owner.connectionProfileEntryChanged()
        check(owner.routerPopup.indexOfSelectedItem == -1 && owner.connectionProfileCatalogSelectedID.isEmpty, "blocked UI edit reauthorized an uncertain Load")
        owner.api.busy = false; api.failLoad = false; api.malformedLoad = false
    }
}
DispatchQueue.clear()
'''


def swift_source():
    product = read("client/macos/RouterVPNMacProduct.swift")
    profiles = read("client/macos/RouterVPNConnectionProfiles.swift")
    settings = read("client/macos/RouterVPNProfileSettings.swift")
    transform_path = ROOT / "client/macos/macos-session-mutation-transform.py"
    spec = importlib.util.spec_from_file_location("profile_mutation_transform", transform_path)
    transform = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transform)
    generated_product = transform.transform(product, "product")
    # The build compiles these two files directly; only Product/Unified source
    # receives the session-mutation transform. Verify the real modal callers.
    build = read("client/macos/build-native-app.sh")
    assert '"$PROFILE_SRC"' in build and '"$SETTINGS_SRC"' in build
    for endpoint in ("save", "update"):
        assert f'connectionProfilePOST("/api/connection-profile/setup/{endpoint}", body: connectionProfileSnapshot(' in profiles
    assert 'try applyLoadedConnectionProfile(payload)' in profiles
    catalog = block(product, "enum RouterVPNNodeExitModes {") + "\n" + block(product, "enum RouterVPNNodeEntryModes {") + "\n" + block(product, "enum RouterVPNMultihopStartup {")
    declarations = profiles[profiles.index("private let macConnectionModeKey"):profiles.index("private struct MacConnectionProfileList")]
    declarations += block(profiles, "private struct MacConnectionCustomPreset:")
    declarations += "\n" + block(settings, "private struct MacConnectionPresetMirror:")
    for marker in ("private func macCurrentConnectionModeSnapshot(", "private func macApplyLoadedConnectionMode("):
        declarations += "\n@MainActor " + block(settings, marker)
    product_methods = block(product, "    func multihopExecutionChoice(")
    product_methods += "\n" + profiles[profiles.index("extension ProductWindowController {\n") + len("extension ProductWindowController {\n"):profiles.index("    @objc func manageConnectionProfiles()")]
    for marker in ("    func mutationBusy(from status:", "    func mutationBusy()", "    func requireMutationIdle(", "    @discardableResult func ensureMutationIdle("):
        product_methods += "\n" + block(generated_product, marker)
    for marker in ("    func asyncAction(", "    @objc func selectRouter()", "    @objc func connectMultihop()", "    func multihopBaseChoice()"):
        product_methods += "\n" + block(generated_product, marker)
    telemetry=read("client/macos/RouterVPNMacTelemetry.swift")
    for marker in ("    func beginLiveHTTPSMutation(","    func endLiveHTTPSMutation("):
        product_methods += "\n" + block(telemetry,marker)
    for marker in ("    func refreshAll()", "    func refreshProfiles()", "    func refreshProfiles(order:", "    func refreshAdvanced()", "    @objc func multihopExecutionChanged()"):
        product_methods += "\n" + block(product, marker)
    for marker in ("    func connectionProfileSnapshot(", "    func connectionProfilePOST(", "    private func applyLoadedConnectionProfile("):
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
    properties = product[product.index("    var multihopNodeIDs:"):product.index("    let dnsModeIDs")]
    methods = methods.replace("PRODUCT_PROPERTIES", properties)
    methods = methods.replace("@objc ", "").replace("private func ", "func ")
    # Rename only the queue boundary so Swift does not apply its special
    # DispatchQueue.global inference to the deterministic value-only scheduler.
    return (SWIFT_BOUNDARIES + catalog + "\n" + declarations + methods + SWIFT_TEST.replace("RACE_TESTS", SWIFT_RACES).replace("ORDERED_TESTS", SWIFT_ORDERED).replace("SETUP_TESTS", SWIFT_SETUP)).replace("UserDefaults.standard", "fixtureDefaults").replace("DispatchQueue", "DeferredQueue")


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
        "manager-entry-capture": replace_once(source,
            'let entryMode = try (multihop ? RouterVPNNodeEntryModes.require(index: multihopEntryModePopup.indexOfSelectedItem) : "")',
            'let entryMode = "wg"'),
        "main-entry-connect": replace_once(source, '"entry_mode": entryMode', '"entry_mode": "wg"'),
        "main-progress-owner": replace_once(source, 'self.stopCapturedComparisonProgress(progressOwner)', 'self.stopCapturedComparisonProgress(self.multihopProgressGeneration)'),
        "main-startup-deadline": replace_once(source, '"execution": execution], timeout: timeout)', '"execution": execution], timeout: 180)'),
        "unsupported-entry-load": replace_once(source,
            'selection.entryMode.flatMap({ RouterVPNNodeEntryModes.index(for: $0) }) != nil,', 'true,'),
        "unsupported-load": replace_once(source,
            'RouterVPNNodeExitModes.index(for: selection.exitMode) != nil,', 'true,'),
        "selection-generation": replace_once(source,
            'capture.generation == connectionProfileSelectionGeneration &&', 'true &&'),
        "request-order": replace_once(source,
            'capture.request == (hops ? connectionProfileHopsRequest : connectionProfileNodesRequest) &&', 'true &&'),
        "same-id-relink": replace_once(source,
            'if let expected = selection.profileTokens[id], expected != actual { return -1 }',
            'if let expected = selection.profileTokens[id], expected != actual { return index }'),
        "first-node-fallback": replace_once(source,
            'let actual = tokens[id], validConnectionProfileToken(actual) else { return -1 }',
            'let actual = tokens[id], validConnectionProfileToken(actual) else { return 0 }'),
        "post-response-manager-idle": replace_once(source,
            '        try requireMutationIdle("loading a connection profile")\n', ''),
        "post-response-settings-idle": replace_once(source,
            '        try owner.requireMutationIdle("loading a connection profile")\n        let selection =',
            '        let selection ='),
        "ordered-drop-middle": replace_once(source, '"multihop_nodes": selectedPath.orderedNodes',
            '"multihop_nodes": [selectedPath.orderedNodes.first!, selectedPath.orderedNodes.last!]'),
        "ordered-final-owner": replace_once(source, 'rows.last?["id"] == control', 'true'),
        "ordered-middle-source": replace_once(source, 'matches[0]["profile_token"] as? String == token', 'true'),
        "ordered-capability": replace_once(source, 'CFGetTypeID(enabled) == CFBooleanGetTypeID(), enabled.boolValue', 'true, true'),
        "ordered-request-owner": replace_once(source, 'self.connectionProfileSelectionGeneration == generation &&', 'true &&'),
        "ordered-locked-source-preconditions": replace_once(source, 'return ["nodes": rows, "execution": "local", "expected_selected_node_id": selection.selectedNodeID,\n                "expected_profile_tokens": tokens]', 'return ["nodes": rows, "execution": "local", "expected_selected_node_id": selection.selectedNodeID,\n                "expected_profile_tokens": [String: String]()]'),
    }
    setup_variants = {
        "setup-source-preconditions": ('request.merge(expected) { _, original in original }', 'request.removeValue(forKey: "expected_profile_tokens")', "setup request lost its original source capture"),
        "setup-generation": ('connectionProfileSelectionGeneration == admittedGeneration,', 'true,', "late setup response accepted new-generation"),
        "setup-mode": ('guard connectionProfileSelectionGeneration == admittedGeneration, captureConnectionProfileSelection() == original,\n              UserDefaults.standard.string(forKey: macConnectionModeKey) == mode,', 'guard connectionProfileSelectionGeneration == admittedGeneration, captureConnectionProfileSelection() == original,\n              true,', "late setup response accepted mode-change"),
        "setup-live-source": ('originals.allSatisfy({ current[$0.key] == $0.value })', 'true', "late setup response accepted source-relinked"),
        "setup-response-source": ('response["profile_tokens"] as? [String: String] == body["expected_profile_tokens"] as? [String: String]', 'true', "setup response accepted changed-token"),
        "setup-response-order": ('finalized.orderedNodes == wanted', 'true', "setup response accepted reordered-members"),
        "setup-load-inventory": ('let graph = loading || external ? matches[0] : body', 'let graph = external ? matches[0] : body', "setup request lost complete original inventory"),
        "setup-response-inventory": ('Set(tokens.keys) == referenced,', 'true,', "Load accepted unrelated response source receipts"),
        "setup-stale-body": ('if writing && !(profiles.first(where:', 'if false && !(profiles.first(where:', "old setup body overrode a newer Off choice before dispatch"),
    }
    for name, (old, new, _) in setup_variants.items():
        variants[name] = replace_once(source, old.replace("UserDefaults.standard", "fixtureDefaults"), new)
    for name, program in variants.items():
        path, binary = directory / (name + ".swift"), directory / name
        path.write_text(program, encoding="utf-8")
        run(["swiftc", "-swift-version", "6", "-module-cache-path", str(directory / "swift-module-cache"), str(path), "-o", str(binary)])
        run([str(binary)], negative=name != "shipping", witness=setup_variants[name][2] if name in setup_variants else None)
        if name != "shipping": print("PASS causal AppKit " + name, flush=True)
    print(f"AppKit capture, refresh ownership, relink and post-response idle negatives: {len(variants) - 1} rejected")


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
