#!/usr/bin/env python3
"""Execute desktop profile callbacks with all eight exit modes and three owners.

Uses the shipping WPF composition and both AppKit profile entry points. Widgets
are value-only doubles; HTTP is a recording local boundary and UserDefaults uses
a fresh suite. These are snapshot/restore tests, not device networking or visual
acceptance. Broken historical capture/load implementations must fail by assertion.
"""
from __future__ import annotations

import argparse
import importlib.util
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
    func removeAllItems() { indexOfSelectedItem = -1 }
}
@MainActor final class DispatchQueue {
    enum QoS { case utility, userInitiated }
    static let main = DispatchQueue(), background = DispatchQueue()
    static func global(qos: QoS) -> DispatchQueue { background }
    var pending: [() -> Void] = []
    func async(execute: @escaping () -> Void) { pending.append(execute) }
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
    var calls: [(path: String, body: [String: Any])] = []
    var loaded: [String: Any] = [:]
    var busy = false
    var failLoad = false, malformedLoad = false
    var afterLoad: (() -> Void)?
    var nodeReplies: [[String: Any]] = [], hopReplies: [[String: Any]] = []
    func json(_ path: String, timeout: TimeInterval = 5) throws -> Any {
        if path == "/api/status" { return ["connected": busy, "phase": busy ? "connected" : "off"] }
        check(path.hasPrefix("/api/nodes?sort=") && !nodeReplies.isEmpty, "unexpected node catalog request")
        return nodeReplies.removeFirst()
    }
    func request(_ path: String, method: String = "GET", body: [String: Any]? = nil, timeout: TimeInterval) throws -> Data {
        if method == "GET" {
            check(path == "/api/multihop/status" && !hopReplies.isEmpty, "unexpected hop catalog request")
            return try JSONSerialization.data(withJSONObject: hopReplies.removeFirst())
        }
        check(method == "POST" && ["/api/connection-profile/setup/save", "/api/connection-profile/setup/update", "/api/connection-profile/setup/load", "/api/profile/select"].contains(path), "unexpected endpoint or automatic connection")
        let body = body ?? [:]
        // JSON round trip models the actual controller boundary, including
        // quoted identities, Boolean types, and array preservation.
        let decoded = try JSONSerialization.jsonObject(with: JSONSerialization.data(withJSONObject: body)) as! [String: Any]
        calls.append((path, decoded))
        if path.hasSuffix("/load") {
            if failLoad { throw NSError(domain: "fixture", code: 1, userInfo: [NSLocalizedDescriptionKey: "Load response timed out"]) }
            if malformedLoad { return Data("[]".utf8) }
            afterLoad?()
        }
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
    let nodePopup = Popup(), externalEntryPopup = Popup(), nodeSortPopup = Popup()
    let multihopExitModePopup = Popup(), multihopExecutionPopup = Popup()
    let api = ProductAPI()
    let window: Window? = Window()
    let errorLabel = Field(), advancedText = Field(), multihopComparisonLabel = Field()
    var profiles: [[String: Any]] = []
    var routerIDs: [String] = []
    PRODUCT_PROPERTIES
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
let expectedModes = ["shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "naive-h2", "naive-h3", "wg"]
let executions = ["local", "server", "auto"]
check(RouterVPNNodeExitModes.choices.map { $0.id } == expectedModes, "shipping exit catalog changed or disappeared")
let owner = ProductWindowController(), settings = Settings()
settings.owner = owner
settings.popup.selectedItem?.representedObject = ["id": "saved-profile", "name": "Saved profile"]
settings.name.stringValue = "Saved \"whole\" path"
let toggle = NSButton(); toggle.identifier = NSView.Identifier(rawValue: "unified-multihop-toggle")
owner.window?.contentView?.subviews = [toggle]
let selectedID = "private-node", entryID = "entry \"private\"", exitID = "exit \"private\""
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
print("Actual AppKit profiles, deferred catalogs and Settings Add/Load/Update callbacks: \(checks) checks PASS")
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
    catalog = block(product, "enum RouterVPNNodeExitModes {")
    declarations = profiles[profiles.index("private let macConnectionModeKey"):profiles.index("private struct MacConnectionProfileList")]
    declarations += block(profiles, "private struct MacConnectionCustomPreset:")
    declarations += "\n" + block(settings, "private struct MacConnectionPresetMirror:")
    for marker in ("private func macCurrentConnectionModeSnapshot(", "private func macApplyLoadedConnectionMode("):
        declarations += "\n@MainActor " + block(settings, marker)
    product_methods = block(product, "    func multihopExecutionChoice(")
    product_methods += "\n" + profiles[profiles.index("extension ProductWindowController {\n") + len("extension ProductWindowController {\n"):profiles.index("    @objc func manageConnectionProfiles()")]
    for marker in ("    func mutationBusy(from status:", "    func mutationBusy()", "    func requireMutationIdle(", "    @discardableResult func ensureMutationIdle("):
        product_methods += "\n" + block(generated_product, marker)
    for marker in ("    func asyncAction(", "    @objc func selectRouter()"):
        product_methods += "\n" + block(generated_product, marker)
    for marker in ("    func refreshAll()", "    func refreshProfiles()", "    func refreshProfiles(order:", "    func refreshAdvanced()", "    @objc func multihopExecutionChanged()"):
        product_methods += "\n" + block(product, marker)
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
    properties = product[product.index("    var multihopNodeIDs:"):product.index("    let dnsModeIDs")]
    methods = methods.replace("PRODUCT_PROPERTIES", properties)
    methods = methods.replace("@objc ", "").replace("private func ", "func ")
    # Rename only the queue boundary so Swift does not apply its special
    # DispatchQueue.global inference to the deterministic value-only scheduler.
    return (SWIFT_BOUNDARIES + catalog + "\n" + declarations + methods + SWIFT_TEST.replace("RACE_TESTS", SWIFT_RACES)).replace("UserDefaults.standard", "fixtureDefaults").replace("DispatchQueue", "DeferredQueue")


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
    }
    for name, program in variants.items():
        path, binary = directory / (name + ".swift"), directory / name
        path.write_text(program, encoding="utf-8")
        run(["swiftc", "-swift-version", "6", "-module-cache-path", str(directory / "swift-module-cache"), str(path), "-o", str(binary)])
        run([str(binary)], negative=name != "shipping")
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
