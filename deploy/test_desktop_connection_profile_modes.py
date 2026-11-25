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
import time
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


def run(command, *, negative=False, witness=None, observation=None, marker="PROFILE-CHECK:", receipt=None):
    started = time.monotonic()
    if observation is not None:
        print("Native profile fixture started: " + observation, flush=True)
    try:
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=90)
    except subprocess.TimeoutExpired as expired:
        # subprocess.run has already killed and joined this child. Preserve its
        # native milestones and diagnostics, then fail on the original timeout;
        # a preceding behavioral assertion cannot turn this into a verdict.
        print("Native profile fixture timed out: " + (observation or str(command[0])) +
              "; elapsed=" + format(time.monotonic() - started, ".3f"), flush=True)
        for captured in (expired.stdout, expired.stderr):
            if captured:
                if isinstance(captured, bytes):
                    captured = captured.decode("utf-8", errors="replace")
                print(captured, end="" if captured.endswith("\n") else "\n", flush=True)
        raise
    if observation is not None:
        print("Native profile fixture finished: " + observation +
              "; exit=" + str(result.returncode) +
              "; elapsed=" + format(time.monotonic() - started, ".3f"), flush=True)
    output = result.stdout + result.stderr
    if negative:
        diagnostic = behavioral_diagnostic(output)
        crashed = re.search(r"(?i)(?:\b(?:panic|fatal(?: error)?):|\bsegmentation fault\b|\b(?:SIGABRT|SIGSEGV|SIGILL|SIGBUS)\b|\*\*\*\s*Signal\s+\d+)", diagnostic)
        expected = marker + " " + witness if witness else marker
        if result.returncode != 1 or crashed or expected not in diagnostic:
            raise RuntimeError("Negative did not fail on a behavioral assertion:\n" + output)
    elif result.returncode:
        raise RuntimeError("Shipping fixture failed:\n" + output)
    elif receipt and re.findall(r"^PROFILE-GROUP [^\r\n]*", output, re.MULTILINE) != [receipt]:
        raise RuntimeError("Incomplete or duplicated profile group receipt:\n" + output)
    elif output.strip():
        print(output.strip(), flush=True)


WINDOWS_EDITOR_CONTROLS = {'followup-position': 'A fresh trial did not follow the inserted hop before its retained suffix', 'local-imported-position': 'Local imported nodes lost complete original path', 'local-imported-capability': 'Local imported nodes accepted invalid source capability', 'hysteria-final-layer-required': 'Hysteria final layer was not offered', 'hysteria-final-layer-type': 'Hysteria accepted malformed final layer', 'hysteria-execution-global': 'Hysteria execution borrowed unrelated global capability', 'openvpn-execution-global': 'OpenVPN execution borrowed unrelated global capability', 'openvpn-execution-capability': 'OpenVPN execution accepted absent or nonboolean native hint', 'openvpn-execution-final-layer': 'OpenVPN execution refused captured final layer', 'socks-execution-final-layer': 'SOCKS execution refused captured final layer', 'socks-execution-old-trio': 'SOCKS execution refused a complete later prefix', 'connect-execution-prefix-layer': 'CONNECT execution admitted a malformed paired prefix layer', 'hostname-minimum': 'hostname trio acquired suffix packet authority', 'hostname-conflict': 'hostname execution accepted conflicting source capabilities', 'hostname-capability': 'hostname execution lost complete saved prefix', 'socks-execution-global': 'SOCKS execution borrowed unrelated global capability',
 'socks-execution-capability': 'SOCKS execution accepted absent or nonboolean native hint',
 'socks-execution-entry-layer': 'SOCKS execution accepted malformed entry layer',
 'socks-execution-layer': 'SOCKS execution admitted layered middle or final',
 'imported-execution-prefix': 'complete imported execution prefix refused',
 'connect-execution-global': 'CONNECT execution borrowed unrelated global '
                             'capability',
 'connect-execution-final': 'CONNECT execution admitted malformed final layer',
 'connect-execution-final-layer-required': 'CONNECT execution refused captured final layer',
 'imported-execution-capability': 'imported execution accepted absent or '
                                  'nonboolean native capability',
 'connect-protocol': 'CONNECT request borrowed a different saved protocol',
 'connect-mode': 'CONNECT Add substituted its exact saved transport',
 'socks-mode': 'SOCKS Add substituted its saved transport',
 'final-mode': 'Apply substituted the explicitly selected Hysteria2 final',
 'raw-mode': 'raw ordered mode whitelist admitted an alias or unsupported '
             'transport',
 'add-mode': 'Add changed the selected node or transport',
 'change-mode': 'Change mode replaced its original node or ignored selected '
                'transport',
 'row-label': 'editor row mislabeled its captured transport',
 'source-token': 'relinked middle node replaced the original editor draft',
 'summary-reset': 'new incomplete ordered selection displayed a previous path '
                  'transport summary'}

def windows_editor_inventory(source):
    matches = re.findall(r"\$controls=@\{([^}]+)\}", source)
    if len(matches) != 1:
        raise RuntimeError("ordered editor control inventory missing or duplicated")
    pairs = re.findall(r"'([^']+)'='([^']+)'", matches[0])
    if len(pairs) != len(WINDOWS_EDITOR_CONTROLS) or len(dict(pairs)) != len(pairs) or dict(pairs) != WINDOWS_EDITOR_CONTROLS:
        raise RuntimeError("ordered editor control inventory changed")
    return WINDOWS_EDITOR_CONTROLS.copy()

WINDOWS_EDITOR_GROUPS = ("editor", "wg", "awg2-fast", "awg2-strong", "socks", "openvpn")


def windows_editor(shell):
    path = ROOT / "client/test-windows-ordered-editor.ps1"
    controls = windows_editor_inventory(path.read_text())
    command = [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(path)]
    if os.name == "nt":
        command.append("-WPF")
    for group in WINDOWS_EDITOR_GROUPS:
        run(command + ["-PositiveOnly", "-Group", group], observation="ordered-editor:shipping:" + group)
    for name, witness in controls.items():
        group = "editor"
        if name.startswith(("socks-execution-", "openvpn-execution-")):
            group = name.split("-", 1)[0]
        elif name in ("connect-protocol", "connect-mode"):
            group = "wg"
        run(command + ["-Group", group, "-NegativeControl", name], negative=True, marker="ORDERED-EDITOR:",
            witness=witness, observation="ordered-editor:" + name)
        print("Actual ordered editor causal control " + name + ": rejected", flush=True)


# Unchanged case inventory. The last selected ordered case also supplies the
# original saved graph for the setup ownership and rollback controls.
WINDOWS_PROFILE_GROUPS = {
    "pair-local": (range(0, 57, 3), (), ()),
    "pair-server": (range(1, 57, 3), (), ()),
    "pair-auto": (range(2, 57, 3), range(78), ()),
    "ordered-local": ((), (), range(25)),
    "ordered-selected": ((), (), range(25, 40)),
    "setup": ((), (), (40,)),
}
WINDOWS_PROFILE_CONTROLS = {
    "capture-two-modes": ("pair-local", "Snapshot replaced the selected exit mode"),
    "load-fallback": ("pair-auto", "Unsupported loaded mode silently became a valid exit"),
    "connect-fallback": ("pair-auto", "Out-of-range exit index accepted by the shipping Connect selector"),
    "entry-capture-fallback": ("pair-local", "Snapshot replaced the selected entry mode"),
    "entry-load-fallback": ("pair-auto", "Unsupported loaded entry silently became a valid mode"),
    "entry-connect-fallback": ("pair-auto", "Main Connect replaced the captured entry, exit or execution"),
    "startup-deadline": ("pair-auto", "Main Connect lost the captured native startup deadline"),
    "ordered-drop-middle": ("ordered-local", "Ordered profile truncated or reordered a middle node"),
    "ordered-execution-capture": ("ordered-selected", "Ordered profile borrowed an unrelated logical mode or execution"),
    "ordered-execution-connect": ("ordered-selected", "Ordered Connect changed its complete path"),
    "ordered-final-owner": ("setup", "Invalid or foreign-final ordered selection was accepted"),
    "ordered-capability": ("ordered-local", "An older controller received ordered nodes as a legacy pair"),
    "ordered-source": ("ordered-local", "Changed ordered selection reached Connect: relinked-middle"),
    "ordered-locked-source": ("ordered-local", "Ordered Connect lost original selected control or all-source hash preconditions"),
    "setup-expectation": ("pair-local", "Setup action discarded its original source inventory"),
    "setup-current-receipt": ("setup", "A changed setup owner was adopted: visible-off"),
    "setup-response-source": ("setup", "Malformed setup reply was adopted: changed-token"),
    "setup-response-order": ("setup", "Malformed setup reply was adopted: reordered-members"),
    "setup-load-inventory": ("setup", "Load discarded an original saved selection source"),
    "setup-refresh-retirement": ("setup", "Setup kept its pending catalog refresh"),
    "setup-uncertain-owner": ("setup", "Failed prepared Load changed the previous selected-node authority"),
}


def windows(shell):
    command = [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
               str(ROOT / "client/test-windows-connection-profile-modes.ps1")]
    run(command + ["-TransactionOnly"], observation="profile:coordinated-recovery")
    for group, cases in WINDOWS_PROFILE_GROUPS.items():
        pair, connect, ordered = (",".join(map(str, rows)) for rows in cases)
        run(command + ["-Group", group, "-Mutation", "shipping"],
            observation="profile:shipping:" + group,
            receipt=f"PROFILE-GROUP {group} pair={pair} connect={connect} ordered={ordered}")
    for mutation, (group, witness) in WINDOWS_PROFILE_CONTROLS.items():
        run(command + ["-Group", group, "-Mutation", mutation], negative=True,
            witness=witness, observation="profile:" + mutation)
    print("WPF pair and ordered capture, setup ownership/response, load/Connect, capability and startup deadline negatives: 21 rejected", flush=True)
    windows_editor(shell)


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
@MainActor final class Window { var isVisible=true; var contentView: NSView? = NSView() }
@MainActor final class Field { var stringValue = ""; var string = "" }
@MainActor final class ProductAPI {
    var calls: [(path: String, body: [String: Any], timeout: TimeInterval)] = []
    var displaySavedMode: ((String) -> Void)?
    var loaded: [String: Any] = [:] { didSet { displaySavedMode?(loaded["mode"] as? String ?? "smart-auto") } }
    var busy = false
    var failLoad = false, malformedLoad = false
    var afterStatus: (() -> Void)?
    var afterLoad: (() -> Void)?
    var afterSetup: ((String) -> Void)?
    var setupResponse: (([String: Any]) -> [String: Any])?
    var nodeReplies: [[String: Any]] = [], hopReplies: [[String: Any]] = []
    var orderedCapabilities: [String: Any] = ["ordered_nodes_supported": true, "ordered_executions": ["local", "server", "auto"]]
    var orderedCurrent: [String: Any] = [:]
    var afterOrderedSnapshot: (() -> Void)?
    func json(_ path: String, timeout: TimeInterval = 5) throws -> Any {
        if path == "/api/status" { afterStatus?(); return ["connected": busy, "phase": busy ? "connected" : "off"] }
        if path == "/api/multihop/status" { return orderedCapabilities }
        if path == "/api/profiles" { let captured = orderedCurrent; afterOrderedSnapshot?(); return captured }
        check(path.hasPrefix("/api/nodes?sort=") && !nodeReplies.isEmpty, "unexpected node catalog request")
        return nodeReplies.removeFirst()
    }
    var loadOwner = "", loadState = "absent", loadFinished = false, loadRevision = UInt64(0)
    var loadStages = [String]()
    func loadReply(_ operation: String, snapshot: [String:Any]? = nil) throws -> Data {
        let absent = operation != loadOwner || loadState == "absent"
        var tx: [String:Any] = ["operation_id":operation,"state":absent ? "absent" : loadState,"finished":absent ? false : loadFinished]
        if !absent { tx["generation"] = String(repeating:"c",count:32); tx["receipt_sha256"] = String(repeating:"b",count:64) }
        var result: Any = NSNull()
        if var fields = snapshot ?? (absent ? nil : loaded) {
            // The controller's canonical snapshot uses JSON null for no ordered
            // path, including legacy entry/exit pairs. An empty array is invalid.
            let defaults: [String: Any] = ["multihop_nodes": NSNull(), "multihop_enabled": false,
                "multihop_execution": "local", "multihop_entry_id": "", "multihop_exit_id": "",
                "multihop_entry_mode": "", "multihop_exit_mode": ""]
            for (key, value) in defaults where fields[key] == nil || fields[key] is NSNull { fields[key] = value }
            result = fields
        }
        return try JSONSerialization.data(withJSONObject:["ok":true,"revision":String(loadRevision),"transaction":tx,"snapshot":result])
    }
    func request(_ wirePath: String, method: String = "GET", body: [String: Any]? = nil, timeout: TimeInterval) throws -> Data {
        var path = wirePath
        if path.hasPrefix(MacProfileLoadTransaction.base) {
            let stage = String(path.dropFirst(MacProfileLoadTransaction.base.count)), op = body?["operation_id"] as? String ?? ""
            check(MacProfileLoadTransaction.token(op,count:32), "missing operation owner")
            loadStages.append(stage)
            if stage == "status" {
                if op == loadOwner && !loadFinished && (failLoad || malformedLoad) { throw RouterVPNOrderedNodes.issue("unavailable status") }
                return try loadReply(op)
            }
            if stage != "prepare" {
                check(op == loadOwner && body?["generation"] as? String == String(repeating:"c",count:32) && body?["receipt_sha256"] as? String == String(repeating:"b",count:64), "stale ownership at controller")
                if stage == "commit" { loadState="committed" }
                else if stage == "abort" { loadState="aborted" }
                else if stage == "finish" { check(["committed","aborted"].contains(loadState), "premature finish"); loadFinished=true }
                else { throw RouterVPNOrderedNodes.issue("unexpected Load stage") }
                return try loadReply(op)
            }
            check(loadState == "absent" || loadFinished, "second Load bypassed unresolved controller owner")
            check(body?["expected_revision"] as? String == String(loadRevision), "Load ignored its original controller revision")
            loadRevision += 1; loadOwner=op; loadState="prepared"; loadFinished=false
            path = "/api/connection-profile/setup/load"
        } else { check(path != "/api/connection-profile/setup/load", "UI issued a legacy single-step load") }
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
        if wirePath == MacProfileLoadTransaction.base + "prepare" { return try loadReply(loadOwner,snapshot:result) }
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
@MainActor final class FixtureLiveOwner {var mutations:Set<UUID>=[];var generation=UUID(),mapGeneration=UUID()}
@MainActor final class ProductWindowController {
    let liveTelemetryDelivery=FixtureLiveOwner();func clearLiveHTTPS(){};func refreshStatus(){}
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
    var shownMode: String?
    func refreshUnifiedModeMenu(preferred: String?) { shownMode = preferred }
    func refreshUnifiedHopOverlay() {}
    func refreshUnifiedChrome() {}
    func refreshUnifiedTelemetry() {}
    func populateIdentityPopup(_ popup: Popup, names: [String], ids: [String]) { popup.selectItem(at: ids.isEmpty ? -1 : 0) }
    func renderProfiles(selected: String) {}
    func multihopComparisonSummary(_ payload: [String: Any]) -> String { "comparison" }
    func appendHelp(_ message: String) {}
    var draftMeasurement: ([String:Any], Int, ([String:Any]) throws -> Void)?
    func showOrderedPrefixCandidates(savedPrefix: Bool, draft: [String:Any], position: Int, choose: @escaping ([String:Any]) throws -> Void) {
        if savedPrefix { draftMeasurement = (draft,position,choose) }
    }
    var candidatesOpened = 0
    func unifiedEntryCandidatesChanged() { candidatesOpened += 1 }
    // Independently exercise the two checked local projection stages on fixture
    // receipts. The actual profile Load callbacks above/below also cross every
    // prepare, commit and finish stage on the recording controller.
    func applyLoadedConnectionProfile(_ value: [String:Any]) throws {
        try requireMutationIdle("previewing the prepared connection profile")
        let target = try validatedLoadedConnectionProfileSelection(value)
        let previous = try MacProfileLoadTransaction.Local(defaults:fixtureDefaults,selection:captureConnectionProfileSelection())
        let next = try previous.projected(snapshot:value,selection:target)
        try next.install(in:fixtureDefaults,from:previous,allowingPartial:false)
        try adoptCoordinatedProfileSelection(target)
        refreshAll(); refreshUnifiedModeMenu(preferred:next.mode);refreshUnifiedChrome()
    }
    PRODUCT_METHODS
}
@MainActor final class Settings {
    let api = ProductAPI(), name = Field(), status = Field(), popup = Popup()
    var owner: ProductWindowController?
    var busy = false
    func syncMutationState() -> Bool { busy }
    func refresh() {}
    func applyLoadedMultihop(_ value: [String:Any]) throws { try owner!.applyLoadedConnectionProfile(value) }
    SETTINGS_METHODS
}
'''

SWIFT_TEST = r'''
let expectedModes = ["shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "naive-h2", "naive-h3", "wg", "awg2-fast", "awg2-strong", "ss-v2ray", "split", "max", "wg-pq", "awg2-pq", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"]
let executions = ["local", "server", "auto"]
check(RouterVPNNodeExitModes.choices.map { $0.id } == expectedModes, "shipping exit catalog changed or disappeared")
let owner = ProductWindowController(), settings = Settings()
settings.owner = owner
settings.api.displaySavedMode = { mode in
    settings.popup.selectedItem?.representedObject = ["id": "saved-profile", "name": "Saved profile", "mode": mode]
}
settings.api.displaySavedMode?("smart-auto")
settings.name.stringValue = "Saved \"whole\" path"
let toggle = NSButton(); toggle.identifier = NSView.Identifier(rawValue: "unified-multihop-toggle")
owner.window?.contentView?.subviews = [toggle]
let selectedID = "private-node", entryID = "entry_private", exitID = "exit_private"
let expectedEntries = ["", "wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "naive-h2", "naive-h3", "ss-v2ray", "split", "max", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg", "wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "openvpn"]
check(RouterVPNNodeEntryModes.choices.map { $0.id } == expectedEntries, "entry mode catalog changed or reduced")
let sourceTokens = [selectedID: String(repeating: "a", count: 64), entryID: String(repeating: "b", count: 64), exitID: String(repeating: "c", count: 64)]
// Exercise the actual receipt and AppKit validator for both non-ordered
// wire shapes alongside an explicit malformed ordered-path control.
do {
    let api = ProductAPI(), operation = String(repeating: "e", count: 32)
    api.loadOwner = operation; api.loadState = "prepared"; api.loadRevision = 1
    for pair in [false, true] {
        var fields: [String: Any] = ["selected_node_id": selectedID, "mode": "wg",
            "profile": ["mode": "wg"], "profile_tokens": pair ? sourceTokens : [selectedID: sourceTokens[selectedID]!]]
        if pair {
            fields["multihop_enabled"] = true; fields["multihop_entry_id"] = entryID; fields["multihop_exit_id"] = exitID
            fields["multihop_entry_mode"] = "wg"; fields["multihop_exit_mode"] = "shadowsocks"
        }
        let receipt = try MacProfileLoadTransaction.Reply(api.loadReply(operation, snapshot: fields), operation: operation)
        var snapshot = receipt.snapshot!
        let path = try owner.validatedLoadedConnectionProfileSelection(snapshot)
        check(snapshot["multihop_nodes"] is NSNull && path.orderedNodes.isEmpty && path.multihopEnabled == pair &&
              path.exitID == (pair ? exitID : "") && path.execution == "local", "canonical direct or pair Load lost its saved path")
        snapshot["multihop_nodes"] = [[String: String]]()
        rejects({ _ = try owner.validatedLoadedConnectionProfileSelection(snapshot) }, "empty ordered path was accepted as an absent path")
    }
}
@MainActor func catalogRows(_ ids: [String], tokens: [String: String] = sourceTokens) -> [[String: Any]] {
    ids.map { ["id": $0, "name": "Same display name", "node_kind": "router-vpn", "profile_token": tokens[$0] ?? String(repeating: "d", count: 64)] }
}
@MainActor func choose(_ mode: Int, _ execution: Int) {
    DispatchQueue.clear()
    owner.api.busy = false; owner.connectionProfileSelection = nil; owner.connectionProfileSelectionGeneration = UUID()
    owner.routerIDs = [selectedID, entryID, exitID]; owner.profiles = catalogRows(owner.routerIDs)
    owner.connectionProfileCatalogSelectedID = selectedID
    owner.multihopNodeIDs = [entryID, exitID]; owner.multihopNodeTokens = sourceTokens
    fixtureDefaults.set("custom:\u{0301}Saved layers", forKey: macConnectionModeKey)
    fixtureDefaults.set(try! JSONEncoder().encode([MacConnectionCustomPreset(name: "\u{0301}Saved layers", layers: ["pq", "wg"])]), forKey: macConnectionCustomPresetsKey)
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
    check(body["mode"] as? String == "custom:\u{0301}Saved layers" && body["custom_layers"] as? [String] == ["pq", "wg"], "mode or CUSTOM layers changed")
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
        fixtureDefaults.removeObject(forKey: macConnectionCustomPresetsKey)
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
        fixtureDefaults.removeObject(forKey: macConnectionCustomPresetsKey)
        settings.loadProfile()
        check(settings.api.calls.count == count + 1 && settings.status.stringValue.hasPrefix("Loaded ") && settings.api.loadStages.suffix(3) == ["prepare","commit","finish"], "actual Settings Load callback failed or connected")
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
CONNECT_EXECUTION_TESTS
// Both native Load actions must resolve the literal saved spelling before
// allowing the controller to change the current node or its policy.
for manager in [true, false] {
    for (savedName, sibling) in [("Gaming", "gaming"), ("Café", "Cafe\u{0301}")] {
        choose(0, 0)
        let api = manager ? owner.api : settings.api
        var payload = loaded(try owner.connectionProfileSnapshot(name: "Saved setup", id: nil))
        payload["mode"] = "custom:" + savedName
        payload["profile"] = ["name": "Saved setup", "mode": "custom:" + savedName]
        payload["custom_layers"] = ["pq", "wg"]
        api.loaded = payload
        let other = MacConnectionCustomPreset(name: sibling, layers: ["reality"])
        let original = try JSONEncoder().encode([other])
        fixtureDefaults.set(original, forKey: macConnectionCustomPresetsKey)
        let before = api.calls.count, generation = owner.connectionProfileSelectionGeneration
        if manager {
            rejects({ _ = try owner.connectionProfilePOST("/api/connection-profile/setup/load", body: ["id": "saved-profile", "expected_mode": (owner.api.loaded["mode"] as? String ?? "smart-auto")]) },
                    "manager allowed a different literal CUSTOM target")
        } else {
            settings.loadProfile()
            check(settings.status.stringValue.hasPrefix("Load failed:"), "Settings allowed a different literal CUSTOM target")
        }
        check(api.calls.count == before && owner.connectionProfileSelectionGeneration == generation &&
              fixtureDefaults.data(forKey: macConnectionCustomPresetsKey) == original,
              "CUSTOM collision reached a mutation or changed the current preset")
        // Older stores may contain both spellings. Only the exact match is
        // restored, including when Swift considers their Strings equivalent.
        fixtureDefaults.set(try JSONEncoder().encode([other, MacConnectionCustomPreset(name: savedName, layers: ["old"])]), forKey: macConnectionCustomPresetsKey)
        fixtureDefaults.set("custom:" + savedName, forKey: macConnectionModeKey)
        let snapshot = try owner.connectionProfileSnapshot(name: "Captured setup", id: nil)
        check(snapshot["custom_layers"] as? [String] == ["old"], "profile save borrowed layers from an equivalent name")
        if manager {
            let reply = try owner.connectionProfilePOST("/api/connection-profile/setup/load", body: ["id": "saved-profile", "expected_mode": (owner.api.loaded["mode"] as? String ?? "smart-auto")])
            try owner.applyLoadedConnectionProfile(reply)
        } else {
            settings.loadProfile()
            check(settings.status.stringValue.hasPrefix("Loaded "), "Settings failed to restore the exact CUSTOM target")
        }
        let applied = try JSONDecoder().decode([MacConnectionCustomPreset].self, from: fixtureDefaults.data(forKey: macConnectionCustomPresetsKey)!)
        check(applied.count == 2 && applied.first(where: { $0.name.utf8.elementsEqual(sibling.utf8) })?.layers == ["reality"] &&
              applied.first(where: { $0.name.utf8.elementsEqual(savedName.utf8) })?.layers == ["pq", "wg"],
              "restoring the exact CUSTOM target replaced its sibling or lost captured layers")
        check((api.calls.last?.body["expected_mode"] as? String)?.utf8.elementsEqual(("custom:" + savedName).utf8) == true,
              "Load POST did not bind the preflighted literal mode")
    }
}
// Reopen a completed profile Load with a fresh window and empty catalogs.
// The two initialized transport controls still have their first menu items.
for pair in [true, false] {
    choose(4, 1)
    var snapshot = loaded(try owner.connectionProfileSnapshot(name: "Reopen saved path", id: nil))
    if !pair {
        snapshot["multihop_enabled"] = false
        snapshot["multihop_execution"] = "local"
        snapshot["profile_tokens"] = [selectedID: sourceTokens[selectedID]!]
        for field in ["multihop_entry_id", "multihop_exit_id", "multihop_entry_mode", "multihop_exit_mode"] { snapshot[field] = "" }
    }
    owner.api.loaded = snapshot
    let reply = try owner.connectionProfilePOST("/api/connection-profile/setup/load",
        body: ["id": "saved-profile", "expected_mode": snapshot["mode"]!])
    let saved = try owner.validatedLoadedConnectionProfileSelection(reply)
    let bytes = fixtureDefaults.data(forKey: MacProfileLoadTransaction.pathKey)
    check(bytes.flatMap { try? JSONDecoder().decode(RouterVPNConnectionProfileSelection.self, from: $0) } == saved &&
          owner.api.loadFinished, "cold launch fixture did not finish its original Load")
    let fresh = ProductWindowController()
    fresh.multihopEntryModePopup.selectItem(at: 0)
    fresh.multihopExitModePopup.selectItem(at: 0)
    fresh.multihopExecutionPopup.selectItem(at: pair ? 1 : 0)
    DispatchQueue.clear()
    fresh.refreshAll()
    check(fresh.captureConnectionProfileSelection() == saved && fixtureDefaults.data(forKey: MacProfileLoadTransaction.pathKey) == bytes,
          "cold launch replaced a saved transport with a window default")
    rejects({ try fresh.requireResolvedConnectionProfileSelection() }, "cold launch trusted a saved path before confirming its catalog")
    fresh.api.nodeReplies = [nodeReply([exitID, selectedID, entryID])]
    DispatchQueue.background.run(); DispatchQueue.main.run()
    fresh.api.hopReplies = [hopReply([exitID, entryID])]
    DispatchQueue.background.run(); DispatchQueue.main.run()
    try fresh.requireResolvedConnectionProfileSelection()
    check(fresh.captureConnectionProfileSelection() == saved && fixtureDefaults.data(forKey: MacProfileLoadTransaction.pathKey) == bytes,
          "cold launch adopted a configured hop from outside the saved path")
    check(fresh.api.calls.isEmpty, "cold launch started or changed a connection")
    if pair {
        fresh.multihopExitModePopup.selectItem(at: 0)
        fresh.connectionProfileHopChanged()
        check(fresh.captureConnectionProfileSelection().exitMode == "shadowsocks" &&
              fixtureDefaults.data(forKey: MacProfileLoadTransaction.pathKey) == nil,
              "explicit transport change did not supersede the reopened profile")
    }
}
print("Actual AppKit profiles, deferred catalogs and Settings Add/Load/Update callbacks: \(checks) checks PASS")
'''

SWIFT_ORDERED_EDITOR = r'''
// Only AppKit widget values are doubled. Selection/render/transport callbacks
// below are extracted unchanged from the shipping ordered editor.
@MainActor final class NSMenu { var cancelled=false; func cancelTracking(){cancelled=true} }
@MainActor final class EditorPopup {
    let menu=NSMenu()
    var indexOfSelectedItem = -1
    var isEnabled = true
    var items: [Item] = []
    var lastItem: Item? { items.last }
    var selectedItem: Item? { items.indices.contains(indexOfSelectedItem) ? items[indexOfSelectedItem] : nil }
    func selectItem(at index: Int) { indexOfSelectedItem = index }
    func removeAllItems() { items.removeAll(); indexOfSelectedItem = -1 }
    func addItem(withTitle: String) { items.append(Item()) }
}
@MainActor final class OrderedEditor {
    var draft: RouterVPNOrderedNodeDraft
    let path = EditorPopup(), transport = EditorPopup(), status = Field()
    weak var owner: ProductWindowController?
    var window: Window? = Window()
    let candidates=EditorPopup()
    var openedRevision: UUID?
    var revision=UUID()
    init(_ draft: RouterVPNOrderedNodeDraft) { self.draft = draft; render() }
    EDITOR_METHODS
}
'''

SWIFT_ORDERED = r'''
for count in [3, 9] {
    let ids = (0..<count).map { "schema8-\($0)" }
    let tokens = Dictionary(uniqueKeysWithValues: ids.enumerated().map { ($0.element, String(format:"%064x",$0.offset+1)) })
    var profiles = catalogRows(ids, tokens: tokens)
    for i in 1..<count {
        profiles[i]["node_kind"] = "external"
        profiles[i]["external"] = ["protocol":"shadowsocks","ordered_middle_supported":true,"ordered_local_imported_nodes_supported":true,"ordered_external_final":true] as [String:Any]
    }
    let initial = RouterVPNConnectionProfileSelection(selectedNodeID: ids[0], profileTokens:tokens)
    var editor = try RouterVPNOrderedNodeDraft(selection:initial,generation:UUID(),catalog:profiles)
    try editor.chooseExternalExit(ids.last!)
    for id in ids.dropFirst().dropLast() { try editor.add(id) }
    let saved8 = try editor.selection()
    let current: [String:Any] = ["selected_id":ids[0],"profiles":profiles]
    let body8 = try RouterVPNOrderedNodes.connectBody(saved8,current:current)
    check((body8["external_final"] as? Bool) == true && saved8.orderedNodes.first?["id"] == ids[0] && saved8.orderedNodes.last?["id"] == ids.last! && saved8.profileTokens == tokens, "external final lost its selected WireGuard entry or source tokens")
    let loaded = try RouterVPNOrderedNodeDraft(selection:saved8,generation:UUID(),catalog:profiles)
    check(try loaded.selection() == saved8, "saved external final lost its exit in the editor")
    var other = saved8; other.execution = "server"
    rejects({ _ = try RouterVPNOrderedNodes.connectBody(other,current:current) }, "external final accepted Server")
    profiles[count-1]["profile_token"] = String(repeating:"f", count:64)
    rejects({ _ = try RouterVPNOrderedNodes.connectBody(saved8,current:["selected_id":ids[0],"profiles":profiles]) }, "external final accepted a relinked exit")
}
@MainActor func chooseOrdered(_ count: Int = 4, finalMode: String = "shadowsocks", prefixMode: String = "wg") -> [[String: String]] {
    choose(0, 0)
    let ids = (0..<count).map { "ordered-\($0)" }
    let tokens = Dictionary(uniqueKeysWithValues: ids.enumerated().map { ($0.element, String(format: "%064x", $0.offset + 1)) })
    let rows = ids.enumerated().map { ["id": $0.element, "mode": $0.offset == count - 1 ? finalMode : prefixMode] }
    owner.routerIDs = ids; owner.profiles = catalogRows(ids, tokens: tokens); owner.routerPopup.selectItem(at: count - 1)
    owner.connectionProfileCatalogSelectedID = ids.last!
    owner.multihopEntryPopup.selectItem(at: -1); owner.multihopExitPopup.selectItem(at: -1)
    owner.connectionProfileSelection = RouterVPNConnectionProfileSelection(selectedNodeID: ids.last!, multihopEnabled: true,
        entryMode: "", execution: "local", profileTokens: tokens, orderedNodes: rows)
    owner.api.orderedCurrent = ["selected_id": ids.last!, "profiles": owner.profiles]
    owner.api.orderedCapabilities = ["ordered_nodes_supported": true, "ordered_executions": ["local", "server", "auto"]]; owner.api.afterOrderedSnapshot = nil
    if finalMode == "hysteria2" { owner.api.orderedCapabilities["ordered_hysteria_executions"] = ["local", "server", "auto"] }
    if finalMode == "shadowsocks" { owner.api.orderedCapabilities["ordered_paired_ss_executions"] = ["local", "server", "auto"] }
    fixtureDefaults.set(finalMode, forKey: macConnectionModeKey)
    return rows
}
@MainActor func chooseImportedExecution(_ requested: String, prefix: String = "wg", entryLayer: String? = nil, finalLayer: String? = nil, count: Int = 3, mixed: Bool = false) -> RouterVPNConnectionProfileSelection {
    _ = chooseOrdered(count, prefixMode: prefix)
    let middle = count - 2
    if mixed {
        for position in 0..<middle { owner.connectionProfileSelection?.orderedNodes[position]["mode"] = RouterVPNOrderedNodes.prefixModes[position % 3]; owner.profiles[position]["start_layer"] = ["off", "aes-256-gcm", "aes-256-gcm+xor-whitening"][position % 3] }
    }
    owner.profiles[middle]["node_kind"] = "external"
    owner.profiles[middle]["external"] = ["protocol": "shadowsocks", "ordered_middle_supported": true, "ordered_execution_middle_supported": true]
    if let entryLayer { owner.profiles[0]["start_layer"] = entryLayer }
    if let finalLayer { owner.profiles[count - 1]["start_layer"] = finalLayer }
    owner.connectionProfileSelection?.orderedNodes[middle]["mode"] = "shadowsocks"
    owner.multihopExecutionPopup.selectItem(at: requested == "server" ? 1 : 2)
    owner.api.orderedCapabilities = ["ordered_nodes_supported": true, "ordered_executions": ["local"], "ordered_imported_trio_executions": ["local", "server", "auto"]]
    owner.api.orderedCurrent = ["selected_id": "ordered-\(count - 1)", "profiles": owner.profiles]
    return owner.captureConnectionProfileSelection()
}
@MainActor func verifyOrderedSnapshot(_ body: [String: Any], rows: [[String: String]], updating: Bool, execution: String = "local") {
    var keys = Set(["expected_selected_node_id", "expected_profile_tokens", "name", "mode", "custom_layers", "multihop_enabled", "multihop_nodes", "multihop_execution"])
    if updating { keys.insert("id") }
    check(Set(body.keys) == keys, "ordered save mixed pair fields or private credentials")
    check(body["multihop_nodes"] as? [[String: String]] == rows, "ordered save dropped, substituted or reordered a member")
    check(body["mode"] as? String == rows.last?["mode"] && body["custom_layers"] as? [String] == [], "ordered save retained unrelated mode or layers")
    check(body["multihop_enabled"] as? Bool == true && body["multihop_execution"] as? String == execution, "ordered save lost exact execution")
}
for finalMode in ["shadowsocks", "hysteria2"] { for prefixMode in ["wg", "awg2-fast", "awg2-strong"] { for length in [2, 3, 4, 8] {
    let rows = chooseOrdered(length, finalMode: finalMode, prefixMode: prefixMode)
    let selection = owner.captureConnectionProfileSelection()
    for updating in [false, true] {
        let snapshot = try owner.connectionProfileSnapshot(name: "Complete ordered path", id: updating ? "saved-profile" : nil)
        verifyOrderedSnapshot(snapshot, rows: rows, updating: updating)
        _ = try settings.write(path: updating ? "/api/connection-profile/setup/update" : "/api/connection-profile/setup/save", updating: updating)
        verifyOrderedSnapshot(settings.api.calls.last!.body, rows: rows, updating: updating)
        var payload = snapshot
        payload["profile"] = ["name": "Loaded ordered path", "mode": finalMode]; payload["selected_node_id"] = selection.selectedNodeID; payload["profile_tokens"] = selection.profileTokens
        owner.connectionProfileSelection?.orderedNodes = []
        try owner.applyLoadedConnectionProfile(payload)
        check(owner.captureConnectionProfileSelection().orderedNodes == rows, "manager Load lost a middle node")
        check(fixtureDefaults.string(forKey: macConnectionModeKey) == finalMode && owner.shownMode == finalMode, "manager Load substituted the ordered final mode")
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
} } }
for requested in ["server", "auto"] { for count in [2, 3, 8] {
    let rows = chooseOrdered(count)
    owner.multihopExecutionPopup.selectItem(at: requested == "server" ? 1 : 2)
    let selection = owner.captureConnectionProfileSelection()
    check(selection.execution == requested, "ordered snapshot relabelled explicit execution")
    let draft = try owner.makeOrderedNodeDraft()
    check(try draft.selection().execution == requested, "ordered editor relabelled explicit execution")
    for updating in [false, true] {
        let snapshot = try owner.connectionProfileSnapshot(name: "Selected ordered execution", id: updating ? "saved-profile" : nil)
        verifyOrderedSnapshot(snapshot, rows: rows, updating: updating, execution: requested)
        _ = try settings.write(path: updating ? "/api/connection-profile/setup/update" : "/api/connection-profile/setup/save", updating: updating)
        verifyOrderedSnapshot(settings.api.calls.last!.body, rows: rows, updating: updating, execution: requested)
        var payload = snapshot
        payload["profile"] = ["name": "Loaded execution", "mode": "shadowsocks"]; payload["selected_node_id"] = selection.selectedNodeID; payload["profile_tokens"] = selection.profileTokens
        try owner.applyLoadedConnectionProfile(payload)
        check(owner.captureConnectionProfileSelection().execution == requested, "ordered Load relabelled execution")
    }
    DispatchQueue.clear()
    let before = owner.api.calls.count
    owner.connectMultihop(); DispatchQueue.background.run()
    check(owner.api.calls.count == before + 1 && owner.api.calls.last!.body["execution"] as? String == requested && owner.api.calls.last!.body["nodes"] as? [[String:String]] == rows, "ordered callback relabelled execution or dropped members")
    DispatchQueue.main.run(); DispatchQueue.clear()
} }
for invalid in [[String: Any](), ["ordered_nodes_supported": false], ["ordered_nodes_supported": "true"], ["ordered_nodes_supported": 1]] {
    _ = chooseOrdered(); owner.api.orderedCapabilities = invalid
    owner.api.orderedCapabilities["ordered_executions"] = ["local", "server", "auto"]
    let before = owner.api.calls.count
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
for count in [9,16] {
    let rows=chooseOrdered(count), selected=owner.captureConnectionProfileSelection()
    let body=try RouterVPNOrderedNodes.connectBody(selected,current:owner.api.orderedCurrent)
    check(body["nodes"] as? [[String:String]] == rows && (body["expected_profile_tokens"] as? [String:String])?.count == count,"extended paired original sources lost")
    var draft=try owner.makeOrderedNodeDraft();try draft.remove(count-2);try draft.add(rows[count-2]["id"]!)
    check(try draft.selection().orderedNodes == rows,"extended paired editor lost a restored member")
    for fault in ["server","auto","layer","token","kind"] {
        var changed=selected, current=owner.api.orderedCurrent, profiles=owner.profiles
        if ["server","auto"].contains(fault){changed.execution=fault}
        else if fault=="layer"{profiles[count-2]["start_layer"]="aes-256-gcm"}
        else if fault=="token"{profiles[count-2]["profile_token"]=String(repeating:"f",count:64)}
        else{profiles[count-2]["node_kind"]="external"}
        current["profiles"]=profiles
        rejects({_ = try RouterVPNOrderedNodes.connectBody(changed,current:current)},"extended paired editor admitted "+fault)
    }
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
rejects({ try draft.chooseMode("awg2-fast", at: draft.prefixes.count) }, "editor accepted a prefix transport as its final exit")
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
// The final transport is selected by the actual AppKit callbacks, then retained
// by the shipping Apply transaction and a reopened editor.
for prefixMode in ["wg", "awg2-fast", "awg2-strong"] {
    _ = chooseOrdered(3, prefixMode: prefixMode)
    let editor = OrderedEditor(try owner.makeOrderedNodeDraft())
    editor.path.selectItem(at: editor.draft.prefixes.count); editor.selectedHopChanged()
    check(editor.transport.isEnabled && editor.transport.items.compactMap { $0.representedObject as? String } == ["shadowsocks", "hysteria2"],
          "ordered editor did not expose the supported final transport")
    editor.transport.selectItem(at: 1); editor.transportChanged()
    check(editor.draft.nodes.last?["mode"] == "hysteria2" && editor.draft.nodes.dropLast().allSatisfy { $0["mode"] == prefixMode },
          "ordered final callback substituted a member transport")
    let captured = try editor.draft.selection(), before = owner.api.calls.count
    try owner.applyOrderedNodeDraft(editor.draft)
    check(owner.captureConnectionProfileSelection() == captured && owner.api.calls.count == before,
          "Hysteria2 editor Apply connected or replaced the captured sources")
    check(fixtureDefaults.string(forKey: macConnectionModeKey) == "hysteria2" && owner.shownMode == "hysteria2",
          "ordered Apply displayed a different final transport")
    let reopened = OrderedEditor(try owner.makeOrderedNodeDraft())
    reopened.path.selectItem(at: reopened.draft.prefixes.count); reopened.selectedHopChanged()
    check(reopened.transport.selectedItem?.representedObject as? String == "hysteria2" && reopened.draft.nodes == captured.orderedNodes,
          "reopened editor substituted its Hysteria2 final")
    reopened.transport.selectItem(at: 0); reopened.transportChanged()
    check(reopened.draft.nodes.last?["mode"] == "shadowsocks", "final callback could not explicitly return to Shadowsocks")
}
for layer in ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"] {
    _ = chooseOrdered(2, finalMode: "hysteria2")
    owner.profiles[1]["start_layer"] = layer; owner.api.orderedCurrent["profiles"] = owner.profiles
    let original = owner.captureConnectionProfileSelection()
    let captured = try? owner.makeOrderedNodeDraft()
    check(captured?.finalMode == "hysteria2", "Hysteria final layer was not offered")
    _ = try RouterVPNOrderedNodes.connectBody(original, current: owner.api.orderedCurrent)
}
for layer in ["aes", "xor", "garbage", "OFF", "off ", NSNull(), 0, true] as [Any] {
    _ = chooseOrdered(2, finalMode: "hysteria2")
    let original = owner.captureConnectionProfileSelection()
    owner.profiles[1]["start_layer"] = layer; owner.api.orderedCurrent["profiles"] = owner.profiles
    rejects({ _ = try RouterVPNOrderedNodes.connectBody(original, current: owner.api.orderedCurrent) }, "Hysteria2 accepted an invalid final source")
    rejects({ _ = try owner.makeOrderedNodeDraft() }, "Hysteria2 editor reopened an incompatible final source")
    rejects({ _ = try owner.connectionProfileSnapshot(name: "Invalid final", id: nil) }, "Hysteria2 snapshot saved an incompatible final source")
    let before = owner.api.calls.count
    owner.connectMultihop()
    check(DispatchQueue.background.pending.isEmpty && owner.api.calls.count == before, "Hysteria2 Connect bypassed the final source policy")
}
_ = chooseOrdered(2)
owner.profiles[1]["start_layer"] = "aes"; owner.api.orderedCurrent["profiles"] = owner.profiles
var layeredDraft = try owner.makeOrderedNodeDraft()
check(layeredDraft.allowedModes(at: 1) == ["shadowsocks"], "layered final editor offered Hysteria2")
rejects({ try layeredDraft.chooseMode("hysteria2", at: 1) }, "layered final changed to Hysteria2")
for invalidMode in ["HYSTERIA2", "hysteria2 ", "wg", "reality-vision", ""] {
    _ = chooseOrdered(2)
    var badFinal = owner.captureConnectionProfileSelection().orderedNodes; badFinal[1]["mode"] = invalidMode
    rejects({ _ = try RouterVPNOrderedNodes.decode(badFinal, control: "ordered-1") }, "ordered decoder normalized an unsupported final mode")
}
_ = chooseOrdered(3, finalMode: "hysteria2")
let hysteriaOriginal = owner.captureConnectionProfileSelection()
for execution in ["LOCAL", "", "compare"] {
    var changed = hysteriaOriginal; changed.execution = execution
    rejects({ _ = try RouterVPNOrderedNodes.connectBody(changed, current: owner.api.orderedCurrent) }, "Hysteria2 ordered path acquired another execution")
}
for requested in ["server", "auto"] {
    var chosen = hysteriaOriginal; chosen.execution = requested
    let body = try RouterVPNOrderedNodes.connectBody(chosen, current: owner.api.orderedCurrent)
    check(body["execution"] as? String == requested && body["nodes"] as? [[String:String]] == chosen.orderedNodes, "ordered Connect lost requested execution or full inventory")
}
for changedIndex in owner.profiles.indices {
    var changed = owner.profiles; changed[changedIndex]["profile_token"] = String(repeating: "e", count: 64)
    rejects({ _ = try RouterVPNOrderedNodes.connectBody(hysteriaOriginal, current: ["selected_id": hysteriaOriginal.selectedNodeID, "profiles": changed]) }, "Hysteria2 reused a relinked original source")
}
let hysteriaDraft = try owner.makeOrderedNodeDraft()
var changedFinal = owner.profiles; changedFinal[2]["start_layer"] = "xor"
owner.api.orderedCurrent["profiles"] = changedFinal
rejects({ try owner.applyOrderedNodeDraft(hysteriaDraft) }, "Hysteria2 Apply missed a changed final policy")
for fault in ["stored-mode", "public-mode", "missing-public-mode", "noncanonical-execution"] {
    var payload: [String: Any] = ["profile": ["mode": "hysteria2"], "mode": "hysteria2", "multihop_nodes": hysteriaOriginal.orderedNodes,
        "multihop_enabled": true, "multihop_execution": "local", "selected_node_id": hysteriaOriginal.selectedNodeID, "profile_tokens": hysteriaOriginal.profileTokens]
    if fault == "stored-mode" { payload["profile"] = ["mode": "shadowsocks"] }
    if fault == "public-mode" { payload["mode"] = "shadowsocks" }
    if fault == "missing-public-mode" { payload.removeValue(forKey: "mode") }
    if fault == "noncanonical-execution" { payload["multihop_execution"] = "SERVER" }
    rejects({ _ = try owner.validatedLoadedConnectionProfileSelection(payload) }, "Hysteria2 Load accepted inconsistent final metadata: " + fault)
}
// The selected node's own saved defaults retain the same mode only after the
// original catalog source and final policy have been validated.
_ = chooseOrdered(3, finalMode: "hysteria2")
let catalogHysteria = owner.captureConnectionProfileSelection()
owner.connectionProfileSelection?.nodeDefaultsPending = true
owner.profiles[2]["multihop_nodes"] = catalogHysteria.orderedNodes
owner.profiles[2]["multihop_enabled"] = true; owner.profiles[2]["multihop_execution"] = "local"
fixtureDefaults.set("shadowsocks", forKey: macConnectionModeKey)
let hysteriaRefresh = owner.beginConnectionProfileRefresh(hops: false)
check(try owner.applyConnectionProfileNodeCatalog(["profiles": owner.profiles, "selected_id": catalogHysteria.selectedNodeID], capture: hysteriaRefresh),
      "Hysteria2 saved defaults were discarded")
check(owner.captureConnectionProfileSelection().orderedNodes == catalogHysteria.orderedNodes && fixtureDefaults.string(forKey: macConnectionModeKey) == "hysteria2" && owner.shownMode == "hysteria2",
      "Hysteria2 catalog defaults displayed another final mode")

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
check(!customDraft.canMeasure(after:1), "hostname-only source offered a private response measurement")
var responseCatalog=customCatalog
responseCatalog[1]["external"]=["protocol":"shadowsocks","ordered_middle_supported":true,"ordered_local_imported_nodes_supported":true]
var dnsCatalog=customCatalog
dnsCatalog[1]["external"]=["protocol":"shadowsocks","ordered_middle_supported":true,"ordered_execution_middle_supported":false,"ordered_hostname_execution_middle_supported":true]
for prefix in RouterVPNOrderedNodes.prefixModes {
 var ordinary=customSelection;ordinary.orderedNodes[0]["mode"]=prefix
 let hostname=try RouterVPNOrderedNodeDraft(selection:ordinary,generation:UUID(),catalog:dnsCatalog)
 check(hostname.canMeasure(after:1),"original hostname lost its single paired Local packet owner")
 for flag:Any in [false,true,0,NSNull(),"false"] {
  var conflict=dnsCatalog;var hints=conflict[1]["external"] as! [String:Any];hints["ordered_local_imported_nodes_supported"]=flag;conflict[1]["external"]=hints
  let draft=try RouterVPNOrderedNodeDraft(selection:ordinary,generation:UUID(),catalog:conflict)
  let bool=flag as? NSNumber,valid=bool.map{CFGetTypeID($0)==CFBooleanGetTypeID() && !$0.boolValue}==true
  check(draft.canMeasure(after:1)==valid,"hostname accepted conflicting or untyped original literal admission")
 }
}
let responseDraft=try RouterVPNOrderedNodeDraft(selection:customSelection,generation:UUID(),catalog:responseCatalog)
check(responseDraft.canMeasure(after:1), "original literal prefix did not offer a private response measurement")
for position in [0,1,2] { for layer:Any in ["aes-256-gcm","aes-256-gcm+xor-whitening",false,NSNull()] {
    var changed=responseCatalog; changed[position]["start_layer"]=layer
    let draft=try RouterVPNOrderedNodeDraft(selection:customSelection,generation:UUID(),catalog:changed)
    check(!draft.canMeasure(after:1), "layered or malformed source offered a private response measurement")
} }
check(customDraft.allowedModes(at: 2) == ["shadowsocks"], "imported middle editor offered a Hysteria2 final")
rejects({ try customDraft.chooseMode("hysteria2", at: 2) }, "imported middle acquired a Hysteria2 final")
var mixedFinal = customSelection.orderedNodes; mixedFinal[2]["mode"] = "hysteria2"
rejects({ _ = try RouterVPNOrderedNodes.decode(mixedFinal, control: customBase.selectedNodeID) }, "imported middle references acquired a Hysteria2 final")
var plainHysteria = customBase; plainHysteria.orderedNodes = [customBase.orderedNodes[0], ["id": customBase.selectedNodeID, "mode": "hysteria2"]]
plainHysteria.profileTokens.removeValue(forKey: "ordered-1")
var addImported = try RouterVPNOrderedNodeDraft(selection: plainHysteria, generation: UUID(), catalog: customCatalog)
rejects({ try addImported.add("ordered-1") }, "Hysteria2 editor added an imported middle")
rejects({ try customDraft.chooseMode("wg", at: 1) }, "custom middle acquired paired WireGuard transport")
let customCaptured = try customDraft.selection()
let customCurrent: [String: Any] = ["selected_id": customBase.selectedNodeID, "profiles": customCatalog]
let customBody = try RouterVPNOrderedNodes.connectBody(customCaptured, current: customCurrent)
check(customBody["nodes"] as? [[String: String]] == customCaptured.orderedNodes, "custom Connect lost original source order")
try customDraft.move(1, by: -1)
rejects({ _ = try customDraft.selection() }, "custom source became physical entry")
customCatalog[1]["profile_token"] = String(repeating: "f", count: 64)
rejects({ _ = try RouterVPNOrderedNodes.connectBody(customCaptured, current: ["selected_id": customBase.selectedNodeID, "profiles": customCatalog]) }, "relinked custom middle retained permission")

// Load the original later hostname and its literal predecessor through the
// same profile manager, editor and Connect path used by the product.
for (count, host, entry) in [(4,2,"wg"), (9,2,"awg2-fast"), (96,94,"awg2-strong")] {
    _ = chooseOrdered(count)
    owner.connectionProfileSelection?.orderedNodes[0]["mode"] = entry
    for i in 1..<(count-1) {
        owner.connectionProfileSelection?.orderedNodes[i]["mode"] = "shadowsocks"
        owner.profiles[i]["node_kind"] = "external"
        owner.profiles[i]["external"] = ["protocol":"shadowsocks", "ordered_middle_supported":true,
            "ordered_execution_middle_supported":i != host, "ordered_local_imported_nodes_supported":i != host,
            "ordered_hostname_execution_middle_supported":i == host]
    }
    let original = owner.captureConnectionProfileSelection()
    let profiles = owner.profiles
    owner.api.orderedCurrent["profiles"] = profiles
    let draft = try owner.makeOrderedNodeDraft()
    check(try draft.selection() == original && draft.canMeasure(after: host), "later hostname or its measurement lost the original path")
    if count > 4 {
        var partial = original
        let removed = partial.orderedNodes.remove(at:host)
        partial.profileTokens.removeValue(forKey:removed["id"]!)
        var editor = try RouterVPNOrderedNodeDraft(selection:partial, generation:UUID(), catalog:profiles)
        try editor.add(removed["id"]!)
        check(try editor.selection().orderedNodes[count-2] == removed, "the editor substituted an added later hostname")
    }
    let snapshot = try owner.connectionProfileSnapshot(name:"Saved resolver", id:nil)
    verifyOrderedSnapshot(snapshot, rows:original.orderedNodes, updating:false)
    var load = snapshot
    load["profile"] = ["name":"Saved resolver","mode":"shadowsocks"]
    load["selected_node_id"] = original.selectedNodeID; load["profile_tokens"] = original.profileTokens
    owner.connectionProfileSelection?.orderedNodes = []
    try owner.applyLoadedConnectionProfile(load)
    check(owner.captureConnectionProfileSelection() == original, "later hostname Load lost a saved source or transport")
    let before = owner.api.calls.count
    DispatchQueue.clear(); owner.connectMultihop(); DispatchQueue.background.run(); DispatchQueue.main.run(); DispatchQueue.clear()
    check(owner.api.calls.count == before+1 && owner.api.calls.last!.body["nodes"] as? [[String:String]] == original.orderedNodes &&
          owner.api.calls.last!.body["execution"] as? String == "local" && owner.api.calls.last!.body["expected_profile_tokens"] as? [String:String] == original.profileTokens,
          "later hostname Connect replaced the saved source or execution")
    for fault in ["second-name", "private", "extra-packet", "enabled-layer", "server", "conflicting-hints", "relink"] {
        var selected = original, changed = profiles
        if fault == "second-name" { changed[1]["external"] = changed[host]["external"] }
        if fault == "private" || fault == "extra-packet" {
            changed[1]["node_kind"] = "router-vpn"; changed[1].removeValue(forKey:"external")
            if fault == "extra-packet" {
                guard count > 4 else { continue }
                selected.orderedNodes[1]["mode"] = "wg"
                if host == 2 { changed[2]["external"] = profiles[1]["external"]; changed[3]["external"] = profiles[host]["external"] }
            }
        }
        if fault == "enabled-layer" { changed[1]["start_layer"] = "aes-256-gcm" }
        if fault == "server" { selected.execution = "server" }
        if fault == "relink" { changed[host]["profile_token"] = String(repeating:"f",count:64) }
        if fault == "conflicting-hints" {
            var hints = changed[host]["external"] as! [String:Any]
            hints["ordered_local_imported_nodes_supported"] = true; changed[host]["external"] = hints
        }
        rejects({ _ = try RouterVPNOrderedNodes.connectBody(selected,current:["selected_id":selected.selectedNodeID,"profiles":changed]) },
                "later hostname accepted " + fault)
    }
}
// Build the saved WG/literal/paired-stream family through the native editor
// and serialize exactly the same references for each selected execution.
for count in [4, 9, 16, 96] {
    _ = chooseOrdered(count)
    let position = count / 2
    var original = owner.captureConnectionProfileSelection()
    for i in 1..<count {
        original.orderedNodes[i]["mode"] = "shadowsocks"
        if i != position && i < count - 1 {
            owner.profiles[i]["node_kind"] = "external"
            owner.profiles[i]["external"] = ["protocol": "shadowsocks", "ordered_middle_supported": true,
                "ordered_local_imported_nodes_supported": true, "ordered_multiple_imported_execution_supported": true]
        }
    }
    let profiles = owner.profiles
    for execution in ["server", "auto"] {
        original.execution = execution
        let editor = try RouterVPNOrderedNodeDraft(selection: original, generation: UUID(), catalog: profiles)
        let payload = try RouterVPNOrderedNodes.connectBody(try editor.selection(), current: ["selected_id": original.selectedNodeID, "profiles": profiles])
        check(editor.allowedModes(at: position) == ["shadowsocks"] && payload["nodes"] as? [[String:String]] == original.orderedNodes &&
              payload["execution"] as? String == execution && payload["expected_profile_tokens"] as? [String:String] == original.profileTokens,
              "selected private stream lost its exact saved route")
        var penultimate = original
        penultimate.orderedNodes.swapAt(position,count-2)
        let measured = try RouterVPNOrderedNodeDraft(selection: penultimate,generation:UUID(),catalog:profiles)
        let insert = count < 96
        check(measured.canMeasure(after:count-2) && measured.canMeasure(after:1) == insert,
              "the editor did not bind its private response to the Compare penultimate source")
        if position != count-2 { check(editor.canMeasure(after:position) == insert && editor.canMeasure(after:count-2),
                                       "the editor offered private response for a different saved position") }
        var publicProfiles = profiles
        publicProfiles[position]["node_kind"]="external";publicProfiles[position]["external"]=profiles[1]["external"]
        let allImported = try RouterVPNOrderedNodeDraft(selection: original, generation: UUID(), catalog: publicProfiles)
        check(allImported.canMeasure(after:count-2),
              "the all-imported selected route lost its penultimate Compare prefix")
        check(allImported.canMeasure(after:1) == insert && allImported.canMeasure(after:count-3) == insert,
              "Compare insertion lost an eligible imported prefix or exceeded capacity")
        publicProfiles[0]["start_layer"]="aes-256-gcm"
        let layered = try? RouterVPNOrderedNodeDraft(selection: original, generation: UUID(), catalog: publicProfiles)
        check(layered?.canMeasure(after:count-2) != true,"a layered selected route acquired a private response")
        var base = original
        let removed = base.orderedNodes.remove(at: position)
        base.profileTokens.removeValue(forKey: removed["id"]!)
        if execution == "auto" && count <= 16 {
            var catalog = profiles
            var literal = catalog[1]["external"] as! [String:Any]
            literal["ordered_execution_middle_supported"] = true; catalog[1]["external"] = literal
            var applying = try RouterVPNOrderedNodeDraft(selection:base,generation:UUID(),catalog:catalog)
            check(applying.canMeasure(after:position-1),"unsaved response draft lost original imported prefix")
            let used:[String:Any]=["draft_action":"insert-measured-hop","candidate_id":removed["id"]!,
                "expected_selected_node_id":original.selectedNodeID,"expected_profile_tokens":original.profileTokens,
                "requested_execution":"auto","proposed_path":original.orderedNodes]
            var stale=used;var tokens=original.profileTokens;tokens[original.selectedNodeID]=String(repeating:"0",count:64);stale["expected_profile_tokens"]=tokens
            rejects({try applying.insertMeasured(stale,after:position-1)},"unsaved response accepted stale source tokens")
            check(try applying.selection()==base,"rejected response changed the editor")
            try applying.insertMeasured(used,after:position-1)
            let next=try applying.selection()
            check(next==original && applying.canMeasure(after:count-2),"unsaved response lost original final or next measurable prefix")
            let request=try RouterVPNOrderedNodes.connectBody(next,current:["selected_id":original.selectedNodeID,"profiles":catalog])
            check(request["nodes"] as? [[String:String]]==original.orderedNodes && request["expected_profile_tokens"] as? [String:String]==original.profileTokens,
                  "remeasuring the unsaved response lost its complete token-bound editor request")
        }
        if count > 4 {
            var edited = try RouterVPNOrderedNodeDraft(selection: base, generation: UUID(), catalog: profiles)
            try edited.add(removed["id"]!)
            check(try edited.selection().orderedNodes[count-2] == removed, "adding a paired stream substituted a packet transport")
        }
        for fault in ["entry", "first-remote", "second-private", "layer", "hostname", "relink"] {
            var bad = original, sources = profiles
            if fault == "entry" { bad.orderedNodes[0]["mode"] = "awg2-pq" }
            if fault == "first-remote" { bad.orderedNodes.swapAt(1, position) }
            if fault == "second-private" {
                let i = count == 4 ? 1 : position + 1
                sources[i].removeValue(forKey: "external"); sources[i]["node_kind"] = "router-vpn"
                if i >= 2 {
                    let recursive = try RouterVPNOrderedNodeDraft(selection:bad,generation:UUID(),catalog:sources)
                    check(recursive.canMeasure(after:i) == insert && recursive.canMeasure(after:position) == insert,
                          "two distinct private stream positions lost independent measurement")
                    let request = try RouterVPNOrderedNodes.connectBody(try recursive.selection(),current:["selected_id":bad.selectedNodeID,"profiles":sources])
                    check(request["nodes"] as? [[String:String]] == bad.orderedNodes,"recursive draft changed its original route")
                    continue
                }
            }
            if fault == "layer" { sources[count-1]["start_layer"] = "aes-256-gcm" }
            if fault == "hostname" {
                var hints = sources[1]["external"] as! [String:Any]; hints["ordered_hostname_execution_middle_supported"] = true
                sources[1]["external"] = hints
            }
            if fault == "relink" { sources[position]["profile_token"] = String(repeating:"f",count:64) }
            rejects({ _ = try RouterVPNOrderedNodes.connectBody(bad,current:["selected_id": bad.selectedNodeID, "profiles":sources]) },
                    "selected private stream accepted " + fault)
        }
    }
}
// Local graphs keep independent imported SS owners at every requested
// interior position. The same shipping editor, capture and request callbacks
// are exercised; the controller boundary records public references only.
do {
    _ = chooseOrdered(9)
    for i in 0..<9 {
        owner.profiles[i]["start_layer"] = "off"
        if i > 0 { owner.connectionProfileSelection?.orderedNodes[i]["mode"] = "shadowsocks" }
        if [1,4,6,7].contains(i) {
            owner.profiles[i]["node_kind"] = "external"
            owner.profiles[i]["external"] = ["protocol":"shadowsocks","ordered_middle_supported":true,"ordered_local_imported_nodes_supported":true]
        }
    }
    let saved = owner.captureConnectionProfileSelection()
    let editor = try RouterVPNOrderedNodeDraft(selection:saved,generation:UUID(),catalog:owner.profiles)
    check(editor.allowedModes(at:3) == ["shadowsocks"] && editor.canMeasure(after:3) && editor.canMeasure(after:6), "extended consecutive private streams lost their source positions")
    let request = try RouterVPNOrderedNodes.connectBody(saved,current:["selected_id":saved.selectedNodeID,"profiles":owner.profiles])
    check(request["nodes"] as? [[String:String]] == saved.orderedNodes, "extended private stream Connect lost its suffix")
    owner.profiles[1]["external"] = ["protocol":"shadowsocks","ordered_middle_supported":true,"ordered_local_imported_nodes_supported":false,"ordered_execution_middle_supported":false,"ordered_hostname_execution_middle_supported":true]
    let hostDraft = try RouterVPNOrderedNodeDraft(selection:saved,generation:UUID(),catalog:owner.profiles)
    let hostRequest = try RouterVPNOrderedNodes.connectBody(saved,current:["selected_id":saved.selectedNodeID,"profiles":owner.profiles])
    check(hostDraft.canMeasure(after:1) && hostDraft.canMeasure(after:6) && hostRequest["nodes"] as? [[String:String]] == saved.orderedNodes,"original hostname or following stream lost the saved route")
    owner.profiles[4]["external"] = owner.profiles[1]["external"]
    rejects({ _ = try RouterVPNOrderedNodes.connectBody(saved,current:["selected_id":saved.selectedNodeID,"profiles":owner.profiles]) }, "two hostnames replaced original stream owners")

} catch { check(false, "Local imported nodes lost complete original path") }
let localImportedLayouts: [(Int, [Int])] = [(3,[0,1]),(4,[1]),(4,[1,2]),(5,[1,3]),(6,[1,3]),(8,[1,4,6]),(8,[1,2,3,4,5,6])]
for (count, importedPositions) in localImportedLayouts { for prefix in RouterVPNOrderedNodes.prefixModes {
    _ = chooseOrdered(count, prefixMode: prefix)
    for position in importedPositions {
        owner.profiles[position]["node_kind"] = "external"
        owner.profiles[position]["external"] = ["protocol":"shadowsocks", "ordered_middle_supported":true,
            "ordered_execution_middle_supported":true, "ordered_local_imported_nodes_supported":true, "password":"private-import-\(position)"]
        owner.connectionProfileSelection?.orderedNodes[position]["mode"] = "shadowsocks"
    }
    owner.profiles[count - 1]["start_layer"] = ["off","aes-256-gcm","aes-256-gcm+xor-whitening"][count % 3]
    owner.api.orderedCurrent = ["selected_id":"ordered-\(count - 1)", "profiles":owner.profiles]
    let original = owner.captureConnectionProfileSelection()
    do {
        let draft = try owner.makeOrderedNodeDraft()
        check(try draft.selection() == original, "Local imported nodes lost complete original path")
        let body = try RouterVPNOrderedNodes.connectBody(original, current: owner.api.orderedCurrent)
        check(body["nodes"] as? [[String:String]] == original.orderedNodes && body["execution"] as? String == "local" && body["expected_profile_tokens"] as? [String:String] == original.profileTokens, "Local imported nodes changed order, modes or source references")
    } catch { check(false, "Local imported nodes lost complete original path") }
    if count == 5 && importedPositions == [1,3] {
        var saved = original
        saved.orderedNodes[2]["mode"] = "shadowsocks"
        var sources = owner.profiles
        for index in sources.indices { sources[index]["start_layer"] = "off" }
        let reopened = try RouterVPNOrderedNodeDraft(selection: saved, generation: UUID(), catalog: sources)
        check(reopened.canMeasure(after: 2) && reopened.canMeasure(after: 3), "recursive private response lost its paired or later imported position")
        let reapplied = try reopened.selection()
        check(reopened.allowedModes(at: 2) == ["shadowsocks"] && reapplied == saved, "named paired stream lost its preserved Local suffix")
        let active: [String:Any] = ["selected_id":saved.selectedNodeID,"profiles":sources]
        let request = try RouterVPNOrderedNodes.connectBody(saved,current:active)
        check(request["nodes"] as? [[String:String]] == saved.orderedNodes && request["expected_profile_tokens"] as? [String:String] == saved.profileTokens,"named paired stream Connect lost an original source")
        sources[3]["start_layer"] = "aes-256-gcm"
        rejects({ _ = try RouterVPNOrderedNodeDraft(selection:saved,generation:UUID(),catalog:sources) },"named paired stream borrowed a layered suffix")
        saved.execution = "server"
        rejects({ _ = try RouterVPNOrderedNodes.connectBody(saved,current:active) },"named paired stream borrowed selected execution")
    }
    let before = owner.api.calls.count
    owner.connectMultihop()
    check(!DispatchQueue.background.pending.isEmpty, "Local imported nodes omitted actual Connect")
    DispatchQueue.background.run(); DispatchQueue.main.run(); DispatchQueue.clear()
    check(owner.api.calls.count == before + 1 && owner.api.calls.last!.body["nodes"] as? [[String:String]] == original.orderedNodes, "Local imported nodes shortened actual Connect")
    for updating in [false,true] {
        let snapshot = try owner.connectionProfileSnapshot(name:"Independent imported nodes",id:updating ? "independent-saved" : nil)
        verifyOrderedSnapshot(snapshot,rows:original.orderedNodes,updating:updating)
        var payload = snapshot
        payload["profile"] = ["name":"Independent imported nodes","mode":"shadowsocks"]
        payload["selected_node_id"] = original.selectedNodeID; payload["profile_tokens"] = original.profileTokens
        owner.connectionProfileSelection?.orderedNodes = []
        try owner.applyLoadedConnectionProfile(payload)
        check(owner.captureConnectionProfileSelection() == original,"Local imported nodes lost complete profile roundtrip")
    }
    for position in importedPositions {
        for flag: Any? in [false,NSNumber(value:1),"true",NSNull(),nil] {
            var changed = owner.profiles
            var external = changed[position]["external"] as! [String:Any]
            external["ordered_local_imported_nodes_supported"] = flag
            changed[position]["external"] = external
            rejects({ _ = try RouterVPNOrderedNodes.connectBody(original,current:["selected_id":original.selectedNodeID,"profiles":changed]) },"Local imported nodes accepted invalid source capability")
        }
        var changed = owner.profiles
        var external = changed[position]["external"] as! [String:Any]; external["protocol"] = "socks5"; changed[position]["external"] = external
        rejects({ _ = try RouterVPNOrderedNodes.connectBody(original,current:["selected_id":original.selectedNodeID,"profiles":changed]) },"Local imported nodes substituted a saved transport")
    }
    for position in 0..<count {
        var changed = owner.profiles; changed[position]["profile_token"] = String(repeating:"f",count:64)
        rejects({ _ = try RouterVPNOrderedNodes.connectBody(original,current:["selected_id":original.selectedNodeID,"profiles":changed]) },"Local imported nodes accepted a replaced source")
    }
    for execution in ["server","auto"] {
        var changed = original; changed.execution = execution
        rejects({ _ = try RouterVPNOrderedNodes.connectBody(changed,current:owner.api.orderedCurrent) },"Local imported nodes borrowed Server or Compare authority")
        var enabled=owner.profiles
        for position in importedPositions {
            var ext=enabled[position]["external"] as! [String:Any]; ext["ordered_multiple_imported_execution_supported"]=true; enabled[position]["external"]=ext
        }
        let selectedCurrent:[String:Any]=["selected_id":original.selectedNodeID,"profiles":enabled]
        if importedPositions.contains(0) {
            rejects({ _ = try RouterVPNOrderedNodes.connectBody(changed,current:selectedCurrent) },"Custom entry borrowed multiple-import execution")
        } else {
            let payload=try RouterVPNOrderedNodes.connectBody(changed,current:selectedCurrent)
            check(payload["nodes"] as? [[String:String]] == original.orderedNodes && payload["execution"] as? String == execution,"Multiple imported execution lost its complete selected order")
            DispatchQueue.clear()
            let originalProfiles=owner.profiles, originalCurrent=owner.api.orderedCurrent, originalCapabilities=owner.api.orderedCapabilities
            owner.profiles=enabled;owner.api.orderedCurrent=selectedCurrent;owner.connectionProfileSelection=changed
            owner.multihopExecutionPopup.selectItem(at:execution=="server" ? 1:2)
            owner.api.orderedCapabilities=["ordered_nodes_supported":true,"ordered_executions":["local","server","auto"]]
            let before=owner.api.calls.count
            owner.connectMultihop();DispatchQueue.background.run();DispatchQueue.main.run();DispatchQueue.clear()
            check(owner.api.calls.count==before,"Multiple imported execution used the generic native capability")
            owner.api.orderedCapabilities["ordered_multiple_imported_executions"]=["local","server","auto"]
            owner.connectMultihop();DispatchQueue.background.run();DispatchQueue.main.run();DispatchQueue.clear()
            check(owner.api.calls.count==before+1 && owner.api.calls.last!.body["nodes"] as? [[String:String]]==original.orderedNodes,"Multiple imported execution lost the actual native Connect")
            owner.profiles=originalProfiles;owner.api.orderedCurrent=originalCurrent;owner.api.orderedCapabilities=originalCapabilities
            owner.connectionProfileSelection=original;owner.multihopExecutionPopup.selectItem(at:0)
            for position in importedPositions {
                var invalid=enabled,ext=enabled[position]["external"] as! [String:Any]; ext["ordered_multiple_imported_execution_supported"]=1; invalid[position]["external"]=ext
                rejects({ _ = try RouterVPNOrderedNodes.connectBody(changed,current:["selected_id":original.selectedNodeID,"profiles":invalid]) },"Multiple imported execution accepted an untyped member capability")
            }
        }
    }
    var duplicate = original.orderedNodes; duplicate[1]["id"] = duplicate[0]["id"]
    rejects({ _ = try RouterVPNOrderedNodes.decode(duplicate,control:original.selectedNodeID) },"Local imported nodes accepted duplicate sources")
    var entryDraft = try owner.makeOrderedNodeDraft(); try entryDraft.move(1,by:-1)
    if count == 3 && importedPositions == [0,1] {
        check(try entryDraft.selection().orderedNodes.map { $0["id"]! } == [original.orderedNodes[1]["id"]!, original.orderedNodes[0]["id"]!, original.orderedNodes[2]["id"]!], "Custom entry reorder lost original distinct providers")
    } else {
        rejects({ _ = try entryDraft.selection() },"Local imported nodes acquired physical entry")
    }
} }

// The editor must also cross the legacy boundary from a selected saved original.
for count in [9,16] { for requested in ["server","auto"] {
    _ = chooseOrdered(count)
    var selected = owner.captureConnectionProfileSelection()
    selected.execution = requested
    var catalog = owner.profiles
    for position in 1..<count-1 {
        selected.orderedNodes[position]["mode"] = "shadowsocks"
        catalog[position]["node_kind"] = "external"
        catalog[position]["external"] = ["protocol":"shadowsocks","ordered_middle_supported":true,
            "ordered_multiple_imported_execution_supported":true,"ordered_local_imported_nodes_supported":true]
    }
    let complete = try RouterVPNOrderedNodeDraft(selection:selected,generation:UUID(),catalog:catalog)
    for packetMode in ["awg2-fast","awg2-strong"] {
        var packet=selected;packet.orderedNodes[0]["mode"]=packetMode
        let draft: RouterVPNOrderedNodeDraft
        do { draft=try RouterVPNOrderedNodeDraft(selection:packet,generation:UUID(),catalog:catalog) }
        catch { check(false,"longer selected AWG2 draft lost its complete original"); continue }
        check(try draft.selection()==packet && draft.allowedModes(at:0)==["wg","awg2-fast","awg2-strong"] && draft.canMeasure(after:0) && draft.canMeasure(after:1) && draft.canMeasure(after:count-2),"longer selected AWG2 permits only its original packet and supported selected response positions")
        check(try RouterVPNOrderedNodes.connectBody(packet,current:["selected_id":packet.selectedNodeID,"profiles":catalog])["nodes"] as? [[String:String]]==packet.orderedNodes,"longer selected AWG2 connect preserves original source order")
        var unknown=catalog;var ext=unknown[1]["external"] as! [String:Any];ext["ordered_multiple_imported_execution_supported"]=false;unknown[1]["external"]=ext
        rejects({ _=try RouterVPNOrderedNodeDraft(selection:packet,generation:UUID(),catalog:unknown) },"longer selected AWG2 borrowed an unqualified imported original")
    }
    var localStream=selected;localStream.execution="local"
    var mixed=localStream, mixedCatalog=catalog
    for pos in 0..<3 { mixed.orderedNodes[pos]["mode"]=["awg2-fast","wg","awg2-strong"][pos];mixedCatalog[pos].removeValue(forKey:"external");mixedCatalog[pos]["node_kind"]="router-vpn" }
    let mixedDraft=try RouterVPNOrderedNodeDraft(selection:mixed,generation:UUID(),catalog:mixedCatalog)
    for position in 0..<count-1 { check(mixedDraft.canMeasure(after:position),"mixed Local stops only at its exact final") }
    check(try mixedDraft.selection()==mixed && mixedDraft.allowedModes(at:1)==RouterVPNOrderedNodes.prefixModes,"mixed Local native roles failed editor roundtrip")
    check(try RouterVPNOrderedNodes.connectBody(mixed,current:["selected_id":mixed.selectedNodeID,"profiles":mixedCatalog])["nodes"] as? [[String:String]]==mixed.orderedNodes,"mixed Local lost a source at Connect")
    var shorterMixed=mixed
    let packetID=shorterMixed.orderedNodes.remove(at:2)["id"]!
    shorterMixed.profileTokens.removeValue(forKey:packetID)
    let preceding=try RouterVPNOrderedNodeDraft(selection:shorterMixed,generation:UUID(),catalog:mixedCatalog)
    check(preceding.canMeasure(after:1),"measured packet before the first import lost its Local chooser")
    var insert=preceding
    let adoption:[String:Any]=["candidate_id":packetID,"expected_selected_node_id":mixed.selectedNodeID,"expected_profile_tokens":mixed.profileTokens,"proposed_path":mixed.orderedNodes]
    do {try insert.insertMeasured(adoption,after:1)}
    catch {check(false,"original measured packet could not be inserted before its captured streams")}
    check(try insert.selection()==mixed,"measured packet insertion lost its original imported suffix")
    var misplaced=preceding
    rejects({try misplaced.insertMeasured(adoption,after:preceding.prefixes.count-1)},"measured packet moved across an original stream")
    check(misplaced.nodes==shorterMixed.orderedNodes,"failed measured insertion changed source")
    var stale=adoption;var revoked=mixed.profileTokens;revoked[packetID]=String(repeating:"f",count:64);stale["expected_profile_tokens"]=revoked
    rejects({try misplaced.insertMeasured(stale,after:1)},"measured packet acquired a replacement source token")
    var crossed=mixed;crossed.execution=requested
    rejects({_ = try RouterVPNOrderedNodeDraft(selection:crossed,generation:UUID(),catalog:mixedCatalog)},"mixed Local source crossed execution scope")
    let measurable=try RouterVPNOrderedNodeDraft(selection:localStream,generation:UUID(),catalog:catalog)
    for last in Set([7,count-2]) {
        check(measurable.canMeasure(after:last),"Longer original Local stream prefix lost response eligibility")
        check(complete.canMeasure(after:last),"Longer selected source lost its Compare penultimate position")
    }
    var layeredSuffix=catalog;layeredSuffix[count-2]["start_layer"]=NSNull()
    rejects({ _ = try RouterVPNOrderedNodeDraft(selection:localStream,generation:UUID(),catalog:layeredSuffix) },"Malformed later import entered a complete Local source")
    check(try complete.selection()==selected,"Longer Server or Compare editor lost the complete retained original")
    let connected = try RouterVPNOrderedNodes.connectBody(selected,current:["selected_id":selected.selectedNodeID,"profiles":catalog])
    check(connected["nodes"] as? [[String:String]]==selected.orderedNodes,"Longer selected request changed original order")
    var shorter=selected
    let addition=shorter.orderedNodes.remove(at:count-2)["id"]!
    shorter.profileTokens.removeValue(forKey:addition)
    var editor=try RouterVPNOrderedNodeDraft(selection:shorter,generation:UUID(),catalog:catalog)
    try editor.add(addition)
    check(try editor.selection()==selected,"Selected editor could not append its independently captured Shadowsocks member")
    for position in [0,1,count-1] {
        var bad=catalog;bad[position]["start_layer"]="aes-256-gcm"
        rejects({ _=try RouterVPNOrderedNodes.connectBody(selected,current:["selected_id":selected.selectedNodeID,"profiles":bad]) },
                "Longer selected path accepted a layered member")
    }
} }

// Darwin has a separate exact-trio capability. Its generic paired capability
// stays Local, and a changed catalog cannot borrow the earlier public hint.
let importedExecutionLayers = ["off", "aes-256-gcm", "aes-256-gcm+xor-whitening"]
for requested in ["server", "auto"] { for prefix in ["wg", "awg2-fast", "awg2-strong"] {
  for entryLayer in importedExecutionLayers { for finalLayer in importedExecutionLayers {
    let original = chooseImportedExecution(requested, prefix: prefix, entryLayer: entryLayer, finalLayer: finalLayer)
    do {
        let draft = try owner.makeOrderedNodeDraft()
        check(try draft.selection() == original, "imported execution draft changed original trio or choice")
    } catch { check(false, "imported execution draft lost independent paired layers or exact native capability") }
    let before = owner.api.calls.count
    owner.connectMultihop()
    check(!DispatchQueue.background.pending.isEmpty, "imported execution did not use separate exact-trio capability")
    DispatchQueue.background.run()
    check(owner.api.calls.count == before + 1 && owner.api.calls.last!.body["execution"] as? String == requested && owner.api.calls.last!.body["nodes"] as? [[String:String]] == original.orderedNodes,
          "imported execution did not use separate exact-trio capability")
    DispatchQueue.main.run(); DispatchQueue.clear()
    check(owner.profiles[0]["start_layer"] as? String == entryLayer && owner.profiles[2]["start_layer"] as? String == finalLayer, "imported execution changed independent paired layers")
  } }
} }
// Longer imported execution keeps every original prefix, token and layer.
for count in 4...8 { for requested in ["server", "auto"] { for prefix in RouterVPNOrderedNodes.prefixModes {
    _ = chooseImportedExecution(requested, prefix: prefix, entryLayer: "aes-256-gcm", finalLayer: "aes-256-gcm+xor-whitening", count: count)
    let middle = count - 2
    for position in 1..<middle { owner.profiles[position]["start_layer"] = importedExecutionLayers[position % 3] }
    owner.api.orderedCurrent["profiles"] = owner.profiles
    let original = owner.captureConnectionProfileSelection()
    do { let draft = try owner.makeOrderedNodeDraft(); check(try draft.selection() == original, "complete imported execution draft lost original prefixes") }
    catch { check(false, "complete imported execution draft refused original prefixes") }
    let expectedLayers = owner.profiles.map { $0["start_layer"] as? String ?? "" }
    let before = owner.api.calls.count
    owner.connectMultihop(); check(!DispatchQueue.background.pending.isEmpty, "complete imported execution refused its captured native capability")
    DispatchQueue.background.run(); DispatchQueue.main.run(); DispatchQueue.clear()
    check(owner.api.calls.count == before + 1, "complete imported execution duplicated or omitted Connect")
    let body = owner.api.calls.last!.body
    check(body["nodes"] as? [[String:String]] == original.orderedNodes && body["execution"] as? String == requested && body["expected_profile_tokens"] as? [String:String] == original.profileTokens, "complete imported execution shortened or replaced original members")
    check(owner.profiles.map { $0["start_layer"] as? String ?? "" } == expectedLayers, "complete imported execution changed a paired prefix layer")
    for position in 0..<count {
        var relinked = owner.profiles; relinked[position]["profile_token"] = String(repeating:"f",count:64)
        rejects({ _ = try RouterVPNOrderedNodes.connectBody(original,current:["selected_id":original.selectedNodeID,"profiles":relinked]) }, "complete imported execution accepted a relinked original member")
    }
} } }
for requested in ["server","auto"] {
    let originalRows=chooseOrdered(4)
    var captured=owner.captureConnectionProfileSelection()
    captured.execution=requested
    var catalog=owner.profiles
    var candidate=catalog[0];candidate["id"]="added-packet";candidate["name"]="Added packet";candidate["profile_token"]=String(repeating:"c",count:64)
    catalog.append(candidate)
    let initial=try RouterVPNOrderedNodeDraft(selection:captured,generation:UUID(),catalog:catalog)
    var proposal=originalRows;proposal.insert(["id":"added-packet","mode":"awg2-strong"],at:2)
    var tokens=captured.profileTokens;tokens["added-packet"]=String(repeating:"c",count:64)
    let original:[String:Any]=["candidate_id":"added-packet","requested_execution":requested,"expected_selected_node_id":captured.selectedNodeID,"proposed_path":proposal,"expected_profile_tokens":tokens]
    for field in ["requested_execution","expected_selected_node_id","proposed_path","expected_profile_tokens"] {
        var altered=original
        switch field {
        case "proposed_path": var rows=proposal;rows[3]["mode"]="awg2-fast";altered[field]=rows
        case "expected_profile_tokens": var replace=tokens;replace[captured.selectedNodeID]=String(repeating:"0",count:64);altered[field]=replace
        default: altered[field]="local"
        }
        var draft=initial
        rejects({try draft.insertMeasured(altered,after:1)},"selected editor accepted changed original "+field)
        check(draft.nodes==originalRows,"rejected selection mutated draft")
    }
    var updated=initial
    try updated.insertMeasured(original,after:1)
    let checked=try updated.selection()
    check(checked.execution==requested && checked.orderedNodes==proposal && checked.profileTokens==tokens,"selected measured insertion changed execution, suffix or source tokens")
    owner.connectionProfileSelection = captured
    owner.profiles = catalog
    owner.api.orderedCurrent = ["selected_id":captured.selectedNodeID,"profiles":catalog]
    let editorOriginal=try RouterVPNOrderedNodeDraft(selection:captured,generation:owner.connectionProfileSelectionGeneration,catalog:catalog)
    let picker=OrderedEditor(editorOriginal);picker.owner=owner;picker.path.selectItem(at:1);owner.draftMeasurement=nil;picker.measureNext()
    let submitted=owner.draftMeasurement!
    check(submitted.0["execution"] as? String==requested && submitted.0["nodes"] as? [[String:String]]==originalRows && submitted.1==1,"actual editor button failed original complete selected capture")
    let previous=picker.revision;picker.revision=UUID()
    rejects({try submitted.2(["requested_execution":requested])},"stale editor delivered a measured hop");picker.revision=previous
    try submitted.2(["candidate_id":"added-packet","requested_execution":requested,"expected_selected_node_id":captured.selectedNodeID,"proposed_path":proposal,"expected_profile_tokens":tokens])
    check(picker.draft.nodes==proposal && picker.draft.execution==requested,"actual editor callback lost selected proposed path")
    owner.draftMeasurement=nil;DispatchQueue.main.run()
    check(owner.draftMeasurement?.1==2 && owner.draftMeasurement?.0["nodes"] as? [[String:String]]==proposal && proposal.count-2 != 2,"accepted insertion did not reopen the exact measured node ahead of its retained suffix")
    let stalePicker=OrderedEditor(editorOriginal);stalePicker.owner=owner;stalePicker.path.selectItem(at:1);stalePicker.measureNext()
    try owner.draftMeasurement!.2(original)
    owner.draftMeasurement=nil;stalePicker.revision=UUID();DispatchQueue.main.run()
    check(owner.draftMeasurement == nil,"retired editor revision started a queued candidate trial")
    owner.draftMeasurement=nil;picker.menuWillOpen(picker.candidates.menu);DispatchQueue.main.run()
    check(picker.candidates.menu.cancelled && owner.draftMeasurement?.1==proposal.count-2,"selected draft picker did not offer next-hop measurement")
    owner.draftMeasurement=nil
}
for requested in ["server", "auto"] {
    let original = chooseImportedExecution(requested, entryLayer:"aes-256-gcm", finalLayer:"aes-256-gcm+xor-whitening", count:8, mixed:true)
    let draft = try owner.makeOrderedNodeDraft()
    check(try draft.selection() == original, "mixed imported execution changed complete original prefix modes")
    let before = owner.api.calls.count; owner.connectMultihop(); DispatchQueue.background.run(); DispatchQueue.main.run(); DispatchQueue.clear()
    check(owner.api.calls.count == before+1 && owner.api.calls.last!.body["nodes"] as? [[String:String]] == original.orderedNodes, "mixed imported execution shortened original prefixes")
    for position in 1..<6 {
        var changed = owner.profiles; changed[position]["start_layer"] = "xor"
        check(!RouterVPNOrderedNodes.importedExecutionPrefixes(original.orderedNodes,profiles:changed), "complete imported execution accepted malformed later prefix layer")
        rejects({ _ = try RouterVPNOrderedNodes.connectBody(original,current:["selected_id":original.selectedNodeID,"profiles":changed]) }, "complete imported execution body accepted malformed later prefix layer")
        changed = owner.profiles; changed[position]["node_kind"] = "external"; changed[position]["external"] = changed[6]["external"]
        check(!RouterVPNOrderedNodes.importedExecutionPrefixes(original.orderedNodes,profiles:changed), "complete imported execution admitted a second imported prefix")
    }
}
for capability in [NSNull(), false, 1, "true"] as [Any] {
    let original = chooseImportedExecution("server")
    var catalog = owner.profiles
    var middle = catalog[1]["external"] as! [String: Any]
    middle["ordered_execution_middle_supported"] = capability; catalog[1]["external"] = middle
    rejects({ _ = try RouterVPNOrderedNodes.connectBody(original, current: ["selected_id": original.selectedNodeID, "profiles": catalog]) }, "imported execution accepted absent or nonboolean member capability")
    rejects({ _ = try RouterVPNOrderedNodeDraft(selection: original, generation: UUID(), catalog: catalog) }, "imported execution draft accepted absent or nonboolean member capability")
}
for position in [0, 2] {
    for layer in ["aes", "xor", "aes-256-gcm+xor", " aes-256-gcm", "salamander", "OFF", true, 0, NSNull()] as [Any] {
        let original = chooseImportedExecution("auto")
        var catalog = owner.profiles; catalog[position]["start_layer"] = layer
        rejects({ _ = try RouterVPNOrderedNodes.connectBody(original, current: ["selected_id": original.selectedNodeID, "profiles": catalog]) }, "Darwin imported execution accepted a malformed paired layer")
        rejects({ _ = try RouterVPNOrderedNodeDraft(selection: original, generation: UUID(), catalog: catalog) }, "Darwin imported execution draft accepted a malformed paired layer")
    }
    for layer in [""] + importedExecutionLayers {
        let original = chooseImportedExecution("auto")
        var catalog = owner.profiles; catalog[position]["start_layer"] = layer
        check(try RouterVPNOrderedNodes.connectBody(original, current: ["selected_id": original.selectedNodeID, "profiles": catalog])["execution"] as? String == "auto", "Darwin imported execution lost an original paired layer")
    }
}
for fault in ["missing", "wrong-type", "local-only", "paired-only", "stale-middle", "stale-token", "stale-entry-layer", "stale-final-layer", "changed-owner"] {
    _ = chooseImportedExecution("server")
    if fault == "missing" { owner.api.orderedCapabilities.removeValue(forKey: "ordered_imported_trio_executions") }
    if fault == "wrong-type" { owner.api.orderedCapabilities["ordered_imported_trio_executions"] = "server" }
    if fault == "local-only" { owner.api.orderedCapabilities["ordered_imported_trio_executions"] = ["local"] }
    if fault == "paired-only" { owner.api.orderedCapabilities.removeValue(forKey: "ordered_imported_trio_executions"); owner.api.orderedCapabilities["ordered_executions"] = ["local", "server", "auto"] }
    if ["stale-middle", "stale-token", "stale-entry-layer", "stale-final-layer"].contains(fault) {
        var changed = owner.profiles
        if fault == "stale-middle" { var external = changed[1]["external"] as! [String: Any]; external["ordered_execution_middle_supported"] = false; changed[1]["external"] = external }
        if fault == "stale-token" { changed[1]["profile_token"] = String(repeating: "f", count: 64) }
        if fault == "stale-entry-layer" || fault == "stale-final-layer" {
            let position = fault == "stale-entry-layer" ? 0 : 2
            changed[position]["start_layer"] = "aes-256-gcm+xor-whitening"
            changed[position]["profile_token"] = String(repeating: "e", count: 64)
        }
        owner.api.orderedCurrent["profiles"] = changed
    }
    if fault == "changed-owner" { owner.api.afterOrderedSnapshot = { owner.connectionProfileSelectionGeneration = UUID() } }
    let before = owner.api.calls.count
    owner.connectMultihop(); DispatchQueue.background.run()
    check(owner.api.calls.count == before, "imported execution dispatched after capability or owner change: " + fault)
    DispatchQueue.clear()
}
for fault in ["paired", "too-long", "other-import", "entry-import", "final-import"] {
    _ = chooseImportedExecution("auto")
    if fault == "too-long" { _ = chooseImportedExecution("auto", count: 9) }
    if fault == "paired" { owner.profiles[1].removeValue(forKey: "external"); owner.profiles[1]["node_kind"] = "router-vpn"; owner.connectionProfileSelection?.orderedNodes[1]["mode"] = "wg" }
    if fault == "other-import" { owner.connectionProfileSelection?.orderedNodes[1]["mode"] = "socks5"; owner.profiles[1]["external"] = ["protocol": "socks5", "ordered_middle_supported": true, "ordered_execution_middle_supported": true] }
    if fault == "entry-import" || fault == "final-import" { let index = fault == "entry-import" ? 0 : 2; owner.profiles[index]["external"] = owner.profiles[1]["external"]; owner.profiles[index]["node_kind"] = "external" }
    owner.api.orderedCapabilities = ["ordered_nodes_supported": true, "ordered_executions": ["local"], "ordered_imported_trio_executions": ["local", "server", "auto"]]
    owner.api.orderedCurrent = ["selected_id": owner.captureConnectionProfileSelection().selectedNodeID, "profiles": owner.profiles]
    let before = owner.api.calls.count
    owner.connectMultihop()
    if !DispatchQueue.background.pending.isEmpty { DispatchQueue.background.run() }
    check(owner.api.calls.count == before, "imported execution capability escaped complete captured prefixes: " + fault)
    DispatchQueue.clear()
}

// Typed imported-middle protocols remain distinct across editor and public
// save/load receipts; the native schema and all credentials stay in the controller.
for middleMode in ["shadowsocks", "socks5", "http-connect", "https-connect", "openvpn"] { for prefixMode in ["wg", "awg2-fast", "awg2-strong"] {
    let connectMiddle = ["http-connect", "https-connect"].contains(middleMode)
    let otherMiddle = middleMode == "http-connect" ? "https-connect" : middleMode == "https-connect" ? "http-connect" : middleMode == "socks5" ? "shadowsocks" : "socks5"
    for count in 3...8 {
    let middle = count - 2
    _ = chooseOrdered(count, prefixMode: prefixMode)
    let paired = owner.captureConnectionProfileSelection()
    var catalog = owner.profiles
    catalog[middle]["node_kind"] = "external"
    catalog[middle]["external"] = ["protocol": middleMode, "ordered_middle_supported": true]
    var captured = paired
    captured.orderedNodes[middle]["mode"] = middleMode
    owner.profiles = catalog
    owner.api.orderedCurrent = ["selected_id": captured.selectedNodeID, "profiles": catalog]
    owner.connectionProfileSelection = captured
    let draft = try owner.makeOrderedNodeDraft()
    check(draft.allowedModes(at: middle) == [middleMode] && draft.nodes == captured.orderedNodes,
          "typed imported editor substituted the saved middle protocol")
    if middleMode == "openvpn" { check(RouterVPNOrderedNodes.modeName(middleMode) == "OpenVPN", "OpenVPN editor concealed its transport") }
    if connectMiddle {
        check(RouterVPNOrderedNodes.modeName(middleMode) == (middleMode == "http-connect" ? "HTTP CONNECT" : "HTTPS CONNECT"), "CONNECT editor mislabeled the exact imported protocol")
    }
    check(draft.allowedModes(at: count - 1) == ["shadowsocks"],
          "SOCKS imported middle editor offered a Hysteria2 final")
    let staged = try draft.selection()
    let body = try RouterVPNOrderedNodes.connectBody(staged, current: owner.api.orderedCurrent)
    check(body["nodes"] as? [[String: String]] == captured.orderedNodes &&
          body["expected_profile_tokens"] as? [String: String] == captured.profileTokens &&
          Set(body.keys) == Set(["nodes", "execution", "expected_selected_node_id", "expected_profile_tokens"]),
          "typed imported request lost references or copied private source fields")
    let snapshot = try owner.connectionProfileSnapshot(name: "Typed middle", id: nil)
    verifyOrderedSnapshot(snapshot, rows: captured.orderedNodes, updating: false)
    var payload = snapshot
    payload["profile"] = ["name": "Typed middle", "mode": "shadowsocks"]
    payload["selected_node_id"] = captured.selectedNodeID
    payload["profile_tokens"] = captured.profileTokens
    let restored = try owner.validatedLoadedConnectionProfileSelection(payload)
    check(restored.orderedNodes == captured.orderedNodes && restored.profileTokens == captured.profileTokens,
          "typed middle Load changed a public source or transport")
    var prepared = snapshot
    prepared["expected_profile_tokens"] = captured.profileTokens
    let confirmed = try owner.confirmedConnectionProfileSave(payload, body: prepared, original: captured)
    check(confirmed == captured, "typed middle Save adopted another captured selection")
    var changedReply = payload
    var changedRows = captured.orderedNodes
    changedRows[middle]["mode"] = otherMiddle
    changedReply["multihop_nodes"] = changedRows
    rejects({ _ = try owner.confirmedConnectionProfileSave(changedReply, body: prepared, original: captured) },
            "typed middle response borrowed another compiler family")
    var changedCatalog = catalog
    changedCatalog[middle]["external"] = ["protocol": otherMiddle, "ordered_middle_supported": true]
    rejects({ _ = try RouterVPNOrderedNodes.connectBody(captured, current: ["selected_id": captured.selectedNodeID, "profiles": changedCatalog]) },
            connectMiddle ? "CONNECT Connect borrowed HTTP or HTTPS transport" : "SOCKS Connect borrowed another imported protocol")
    rejects({ _ = try RouterVPNOrderedNodeDraft(selection: captured, generation: UUID(), catalog: changedCatalog) },
            "SOCKS draft reopened against another imported protocol")
    changedCatalog = catalog
    changedCatalog[middle]["profile_token"] = String(repeating: "f", count: 64)
    rejects({ _ = try RouterVPNOrderedNodes.connectBody(captured, current: ["selected_id": captured.selectedNodeID, "profiles": changedCatalog]) },
            "typed imported middle reused changed credential identity")
    var noMiddle = paired
    noMiddle.orderedNodes.remove(at: middle)
    noMiddle.profileTokens.removeValue(forKey: "ordered-\(middle)")
    var added = try RouterVPNOrderedNodeDraft(selection: noMiddle, generation: UUID(), catalog: catalog)
    try added.add("ordered-\(middle)")
    check(added.modes == Array(repeating: prefixMode, count: count - 2) + [middleMode], connectMiddle ? "CONNECT editor Add replaced the captured middle mode" : "SOCKS editor Add replaced the captured middle mode")
    check(try added.selection().orderedNodes == captured.orderedNodes, "typed editor Add lost the complete order")
    try added.move(middle, by: -1)
    rejects({ _ = try added.selection() }, "typed imported member acquired the physical prefix")
    var otherExecution = captured
    otherExecution.execution = "server"
    rejects({ _ = try RouterVPNOrderedNodes.connectBody(otherExecution, current: owner.api.orderedCurrent) },
            "typed imported middle acquired Server execution")
    otherExecution.execution = "auto"
    rejects({ _ = try RouterVPNOrderedNodes.connectBody(otherExecution, current: owner.api.orderedCurrent) },
            "typed imported middle acquired Compare execution")
    let calls = owner.api.calls.count
    owner.api.orderedCapabilities = ["ordered_nodes_supported": false]
    owner.connectMultihop()
    DispatchQueue.background.run()
    check(owner.api.calls.count == calls, "closed Darwin capability dispatched a typed imported path")
} } }
_ = chooseOrdered(3)
var socksCatalog = owner.profiles
socksCatalog[1]["node_kind"] = "external"
socksCatalog[1]["external"] = ["protocol": "socks5", "ordered_middle_supported": true]
let socksOriginal = owner.captureConnectionProfileSelection()
for unsupported in ["SOCKS5", "socks", "HTTP-CONNECT", "HTTPS-CONNECT", "http-connect ", "", "shadowsocks2022"] {
    var profile = socksCatalog[1]
    profile["external"] = ["protocol": unsupported, "ordered_middle_supported": true]
    check(RouterVPNOrderedNodes.importedMiddleMode(profile) == nil, "SOCKS catalog normalized an unsupported protocol")
}
let invalidSOCKSCapabilities: [Any] = [1, "true", false, NSNull()]
for protocolName in ["shadowsocks", "socks5", "http-connect", "https-connect", "openvpn"] { for capability in invalidSOCKSCapabilities {
    var profile = socksCatalog[1]
    profile["external"] = ["protocol": protocolName, "ordered_middle_supported": capability]
    check(RouterVPNOrderedNodes.importedMiddleMode(profile) == nil, "SOCKS imported capability accepted non-boolean authority")
} }
for protocolName in ["socks5", "http-connect", "https-connect", "openvpn"] { for invalidRows in [
    [["id":"ordered-0","mode":"socks5"],["id":"ordered-2","mode":"shadowsocks"]],
    [["id":"ordered-0","mode":"wg"],["id":"ordered-2","mode":"socks5"]],
    [["id":"ordered-0","mode":"wg"],["id":"ordered-1","mode":"socks5"],["id":"ordered-2","mode":"hysteria2"]],
    [["id":"ordered-0","mode":"wg"],["id":"ordered-1","mode":"socks5"],["id":"extra","mode":"awg2-fast"],["id":"ordered-2","mode":"shadowsocks"]]
] {
    let typedRows = invalidRows.map { row in var typed = row; if typed["mode"] == "socks5" { typed["mode"] = protocolName }; return typed }
    rejects({ _ = try RouterVPNOrderedNodes.decode(typedRows, control: "ordered-2") }, "imported reference escaped its three-node Local middle position")
} }
var pairedSocks = socksOriginal
pairedSocks.orderedNodes[1]["mode"] = "socks5"
rejects({ _ = try RouterVPNOrderedNodes.connectBody(pairedSocks, current: owner.api.orderedCurrent) },
        "paired node acquired imported SOCKS authority")

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
@MainActor func setupRows(_ count: Int = 4, finalMode: String = "shadowsocks") -> [[String: String]] {
    owner.api.afterSetup = nil; settings.api.afterSetup = nil
    owner.api.setupResponse = nil; settings.api.setupResponse = nil
    owner.api.afterLoad = nil; settings.api.afterLoad = nil
    owner.api.afterStatus = nil; settings.api.afterStatus = nil
    var rows = chooseOrdered(count, finalMode: finalMode)
    for i in 0..<(count - 1) { rows[i]["mode"] = ["awg2-fast", "wg", "awg2-strong"][i % 3] }
    owner.connectionProfileSelection?.orderedNodes = rows
    owner.profiles[count - 1]["multihop_enabled"] = true
    owner.profiles[count - 1]["multihop_nodes"] = rows
    owner.profiles[count - 1]["multihop_execution"] = "local"
    return rows
}
@MainActor func setupLoaded(_ rows: [[String: String]], tokens: [String: String]) -> [String: Any] {
    ["profile": ["name": "Captured ordered setup", "mode": rows.last!["mode"]!], "mode": rows.last!["mode"]!, "custom_layers": [String](),
     "multihop_nodes": rows, "multihop_enabled": true, "multihop_execution": "local",
     "selected_node_id": rows.last!["id"]!, "profile_tokens": tokens]
}
@MainActor func setupAction(_ manager: Bool, _ operation: String) throws {
    if manager {
        let body: [String: Any] = operation == "load" ? ["id": "saved-profile", "expected_mode": (owner.api.loaded["mode"] as? String ?? "smart-auto")] : try owner.connectionProfileSnapshot(name: "Original setup", id: operation == "update" ? "saved-profile" : nil)
        let reply = try owner.connectionProfilePOST("/api/connection-profile/setup/" + operation, body: body)
        if operation == "load" { try owner.applyLoadedConnectionProfile(reply) }
    } else {
        if operation == "load" { settings.loadProfile(); if settings.status.stringValue.hasPrefix("Load failed:") { throw RouterVPNOrderedNodes.issue(settings.status.stringValue) } }
        else { _ = try settings.write(path: "/api/connection-profile/setup/" + operation, updating: operation == "update") }
    }
}
for manager in [true, false] { for requested in ["server", "auto"] { for prefix in ["wg", "awg2-fast", "awg2-strong"] { for operation in ["save", "update", "load"] { for count in [3,4,8] {
  for entryLayer in importedExecutionLayers { for finalLayer in importedExecutionLayers {
    _ = setupRows(count)
    let original = chooseImportedExecution(requested, prefix: prefix, entryLayer: entryLayer, finalLayer: finalLayer, count:count), rows = original.orderedNodes
    let api = manager ? owner.api : settings.api
    api.loaded = setupLoaded(rows, tokens: original.profileTokens)
    api.loaded["multihop_execution"] = requested
    let before = api.calls.count
    try setupAction(manager, operation)
    check(api.calls.count == before + 1 && !api.calls.last!.path.contains("multihop/connect"), "imported complete-profile action auto-connected or duplicated request")
    let restored = owner.captureConnectionProfileSelection()
    check(restored.orderedNodes == rows && restored.execution == requested && restored.profileTokens == original.profileTokens, "imported complete-profile action changed captured source or execution")
    if operation != "load" { verifyOrderedSnapshot(api.calls.last!.body, rows: rows, updating: operation == "update", execution: requested) }
    check(owner.profiles[0]["start_layer"] as? String == entryLayer && owner.profiles[count-1]["start_layer"] as? String == finalLayer, "imported complete profile changed independent paired layers")
  } }
} } } } }
for manager in [true, false] {
    for finalMode in ["shadowsocks", "hysteria2"] { for count in [2, 3, 4, 8] { for operation in ["save", "update", "load"] {
        let rows = setupRows(count, finalMode: finalMode), original = owner.captureConnectionProfileSelection()
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
        check(fixtureDefaults.string(forKey: macConnectionModeKey) == finalMode, "setup action replaced the selected ordered final mode")
        if operation != "load" { verifyOrderedSnapshot(request, rows: rows, updating: operation == "update") }
    } } }
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
    check(owner.captureConnectionProfileSelection() == original && api.loadState == "aborted" && api.loadFinished, "invalid prepared Load failed to restore the original selected authority")
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
    if manager { owner.api.loaded = payload; let response = try owner.connectionProfilePOST("/api/connection-profile/setup/load", body: ["id": "saved-profile", "expected_mode": (owner.api.loaded["mode"] as? String ?? "smart-auto")]); try owner.applyLoadedConnectionProfile(response) }
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
for manager in [true, false] {
    let previousBusyLoad = owner.captureConnectionProfileSelection()
    let api = manager ? owner.api : settings.api
    api.loaded = busyPayload
    api.afterLoad = { owner.api.busy = true }
    if manager {
        rejects({ _ = try owner.connectionProfilePOST("/api/connection-profile/setup/load", body:["id":"saved-profile","expected_mode":busyPayload["mode"] as! String]) },
            "session beginning after manager prepare permitted Load")
    } else {
        settings.loadProfile()
        check(settings.status.stringValue.hasPrefix("Load failed:"), "session beginning after Settings prepare permitted Load")
    }
    check(api.loadState == "aborted" && api.loadFinished && previousBusyLoad == owner.captureConnectionProfileSelection(), "session beginning after HTTP Load retained stale UI authority")
    api.afterLoad = nil; owner.api.busy = false
}
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
            rejects({ let payload = try owner.connectionProfilePOST("/api/connection-profile/setup/load", body: ["id": "saved-profile", "expected_mode": (owner.api.loaded["mode"] as? String ?? "smart-auto")]); try owner.applyLoadedConnectionProfile(payload) }, "uncertain manager Load succeeded")
        } else { settings.loadProfile(); check(settings.status.stringValue.hasPrefix("Load failed:"), "uncertain Settings Load succeeded") }
        check(owner.captureConnectionProfileSelection() == previous && owner.connectionProfileSelectionGeneration != generation && MacProfileLoadTransaction.Store.standard.pending, "uncertain Load retained old resolved node authority")
        rejects({ _ = try owner.connectionProfileSnapshot(name: "uncertain Load", id: nil) }, "uncertain Load authorized a profile write")
        owner.api.busy = true; owner.multihopEntryPopup.selectItem(at: 0); owner.connectionProfileEntryChanged()
        check(MacProfileLoadTransaction.Store.standard.pending, "blocked UI edit reauthorized an uncertain Load")
        owner.api.busy = false; api.failLoad = false; api.malformedLoad = false
        let store = MacProfileLoadTransaction.Store.standard
        try store.locked {
            if let pending = try store.read() {
                _ = try MacProfileLoadTransaction.recover(pending, store:store, defaults:fixtureDefaults,
                    send:{ stage,fields in try api.request(MacProfileLoadTransaction.base+stage,method:"POST",body:fields,timeout:15) },
                    checkPath:owner.requireCoordinatedProfilePath, adopt:owner.adoptCoordinatedProfileSelection)
            }
        }
        check(!store.pending, "uncertain Load failed to release the original owner after recovery")
    }
}

DispatchQueue.clear()
'''


SWIFT_CONNECT_EXECUTION = r'''
// CONNECT keeps its distinct typed capability across all complete prefixes.
for count in 3...8 { for protocolName in ["http-connect", "https-connect"] { for requested in ["server", "auto"] {
  for entryLayer in ["off", "aes-256-gcm", "aes-256-gcm+xor-whitening"] {
    let middle = count - 2, final = count - 1
    _ = chooseImportedExecution(requested, entryLayer: entryLayer, finalLayer: "off", count: count, mixed: true)
    owner.profiles[middle]["external"] = ["protocol": protocolName, "ordered_middle_supported": true, "ordered_connect_execution_middle_supported": true]
    owner.connectionProfileSelection?.orderedNodes[middle]["mode"] = protocolName
    owner.api.orderedCurrent = ["selected_id": "ordered-\(final)", "profiles": owner.profiles]
    owner.api.orderedCapabilities = ["ordered_nodes_supported": true, "ordered_executions": ["local"], "ordered_connect_trio_executions": ["local", "server", "auto"]]
    let original = owner.captureConnectionProfileSelection()
    do { let draft = try owner.makeOrderedNodeDraft(); check(try draft.selection() == original, "CONNECT execution draft lost original complete path") }
    catch { check(false, "CONNECT execution draft lost original complete path") }
    let before = owner.api.calls.count
    owner.connectMultihop(); check(!DispatchQueue.background.pending.isEmpty, "CONNECT execution did not use its distinct native capability"); DispatchQueue.background.run()
    check(owner.api.calls.count == before + 1 && owner.api.calls.last!.body["execution"] as? String == requested && owner.api.calls.last!.body["nodes"] as? [[String:String]] == original.orderedNodes, "CONNECT execution did not use its distinct native capability")
    DispatchQueue.main.run(); DispatchQueue.clear()
    for finalLayer in ["aes-256-gcm", "aes-256-gcm+xor-whitening"] {
        owner.profiles[final]["start_layer"] = finalLayer
        owner.api.orderedCurrent = ["selected_id": "ordered-\(final)", "profiles": owner.profiles]
        do { let draft = try owner.makeOrderedNodeDraft(); check(try draft.selection() == original, "CONNECT execution refused captured final layer") }
        catch { check(false, "CONNECT execution refused captured final layer") }
        let calls = owner.api.calls.count
        owner.connectMultihop(); DispatchQueue.background.run()
        check(owner.api.calls.count == calls + 1 && owner.api.calls.last!.body["nodes"] as? [[String:String]] == original.orderedNodes && owner.api.calls.last!.body["execution"] as? String == requested && owner.profiles[final]["start_layer"] as? String == finalLayer, "CONNECT execution replaced original final layer")
        DispatchQueue.main.run(); DispatchQueue.clear()
    }
    owner.profiles[final]["start_layer"] = "off"
    owner.api.orderedCurrent = ["selected_id": "ordered-\(final)", "profiles": owner.profiles]
    for fault in ["hint", "numeric-hint", "final-layer", "long", "wrong-protocol", "later-prefix-layer", "prefix-layer-type", "prefix-kind", "middle-layer"] {
        var catalog = owner.profiles, rows = original.orderedNodes
        if fault == "hint" || fault == "numeric-hint" { var ext = catalog[middle]["external"] as! [String:Any]; ext["ordered_connect_execution_middle_supported"] = fault == "hint" ? false : 1; catalog[middle]["external"] = ext }
        if fault == "final-layer" { catalog[final]["start_layer"] = "xor-only" }
        if fault == "long" { rows.insert(["id":"extra", "mode":"wg"], at:0) }
        if fault == "wrong-protocol" { rows[middle]["mode"] = protocolName == "http-connect" ? "https-connect" : "http-connect" }
        if fault == "later-prefix-layer" { catalog[middle - 1]["start_layer"] = "aes-256-gcm " }
        if fault == "prefix-layer-type" { catalog[middle - 1]["start_layer"] = true }
        if fault == "prefix-kind" { catalog[middle - 1]["node_kind"] = "external" }
        if fault == "middle-layer" { catalog[middle]["start_layer"] = "aes-256-gcm" }
        check(!RouterVPNOrderedNodes.connectExecutionTrio(rows, profiles:catalog), "CONNECT execution accepted changed typed trio: " + fault)
    }
    owner.api.orderedCapabilities.removeValue(forKey:"ordered_connect_trio_executions")
    owner.api.orderedCapabilities["ordered_imported_trio_executions"] = ["local", "server", "auto"]
    owner.api.orderedCapabilities["ordered_executions"] = ["local", "server", "auto"]
    let blocked = owner.api.calls.count
    owner.connectMultihop(); DispatchQueue.background.run(); DispatchQueue.main.run(); DispatchQueue.clear()
    check(owner.api.calls.count == blocked, "CONNECT execution borrowed unrelated native capability")
  }
} } }

DispatchQueue.clear()
'''


SWIFT_SOCKS_EXECUTION = r'''
@MainActor func chooseSOCKSExecution(_ requested: String, prefix: String = "wg", entryLayer: String = "off", finalLayer: String = "off", count: Int = 3) -> RouterVPNConnectionProfileSelection {
    _ = setupRows(count)
    _ = chooseImportedExecution(requested, prefix: prefix, entryLayer: entryLayer, finalLayer: finalLayer, count: count)
    owner.profiles[count - 2]["external"] = ["protocol": "socks5", "ordered_middle_supported": true, "ordered_socks_execution_middle_supported": true]
    owner.connectionProfileSelection?.orderedNodes[count - 2]["mode"] = "socks5"
    owner.api.orderedCurrent = ["selected_id": "ordered-\(count - 1)", "profiles": owner.profiles]
    owner.api.orderedCapabilities = ["ordered_nodes_supported": true, "ordered_executions": ["local"], "ordered_socks_trio_executions": ["local", "server", "auto"]]
    return owner.captureConnectionProfileSelection()
}
for count in 3...8 { for requested in ["server", "auto"] { for prefix in ["wg", "awg2-fast", "awg2-strong"] {
  for entryLayer in ["off", "aes-256-gcm", "aes-256-gcm+xor-whitening"] {
    let original = chooseSOCKSExecution(requested, prefix: prefix, entryLayer: entryLayer, count: count)
    check(RouterVPNOrderedNodes.socksExecutionTrio(original.orderedNodes, profiles: owner.profiles), "SOCKS execution lost its distinct complete source hint")
    do { let draft = try owner.makeOrderedNodeDraft(); check(try draft.selection() == original, "SOCKS execution draft lost the original typed trio") }
    catch { check(false, "SOCKS execution draft lost the original typed trio") }
    let before = owner.api.calls.count
    owner.connectMultihop(); check(!DispatchQueue.background.pending.isEmpty, "SOCKS execution did not use its distinct native capability"); DispatchQueue.background.run()
    check(owner.api.calls.count == before + 1, "SOCKS execution did not use its distinct native capability")
    let posted = owner.api.calls.last!.body
    check(posted["execution"] as? String == requested, "SOCKS execution did not use its distinct native capability")
    check(posted["nodes"] as? [[String:String]] == original.orderedNodes, "SOCKS execution did not use its distinct native capability")
    check(posted["expected_profile_tokens"] as? [String:String] == original.profileTokens, "SOCKS execution did not use its distinct native capability")
    DispatchQueue.main.run(); DispatchQueue.clear()
    for unrelated in ["ordered_executions", "ordered_imported_trio_executions", "ordered_connect_trio_executions"] {
        _ = chooseSOCKSExecution(requested, prefix: prefix, entryLayer: entryLayer, count: count)
        owner.api.orderedCapabilities.removeValue(forKey: "ordered_socks_trio_executions")
        owner.api.orderedCapabilities[unrelated] = ["local", "server", "auto"]
        let blocked = owner.api.calls.count
        owner.connectMultihop(); DispatchQueue.background.run(); DispatchQueue.main.run(); DispatchQueue.clear()
        check(owner.api.calls.count == blocked, "SOCKS execution borrowed unrelated native capability")
    }
    for manager in [true, false] { for operation in ["save", "update", "load"] {
        let saved = chooseSOCKSExecution(requested, prefix: prefix, entryLayer: entryLayer, count: count)
        let api = manager ? owner.api : settings.api
        api.loaded = setupLoaded(saved.orderedNodes, tokens: saved.profileTokens)
        api.loaded["multihop_execution"] = requested
        let callsBefore = api.calls.count
        try setupAction(manager, operation)
        check(api.calls.count == callsBefore + 1 && !api.calls.last!.path.contains("multihop/connect"), "SOCKS complete-profile action auto-connected or duplicated a request")
        let restored = owner.captureConnectionProfileSelection()
        check(restored.orderedNodes == saved.orderedNodes && restored.execution == requested && restored.profileTokens == saved.profileTokens, "SOCKS complete-profile action replaced an original source or execution")
        if operation != "load" { verifyOrderedSnapshot(api.calls.last!.body, rows: saved.orderedNodes, updating: operation == "update", execution: requested) }
        check(owner.profiles[0]["start_layer"] as? String == entryLayer && owner.profiles[count - 1]["start_layer"] as? String == "off", "SOCKS complete-profile action replaced a captured Start Layer")
    } }
  }
} } }
for count in [3, 4, 8] { for requested in ["server", "auto"] { for entryLayer in ["off", "aes-256-gcm", "aes-256-gcm+xor-whitening"] { for finalLayer in ["aes-256-gcm", "aes-256-gcm+xor-whitening"] {
    let original = chooseSOCKSExecution(requested, entryLayer: entryLayer, finalLayer: finalLayer, count: count)
    check(RouterVPNOrderedNodes.socksExecutionTrio(original.orderedNodes, profiles: owner.profiles), "SOCKS execution refused captured final layer")
    let before = owner.api.calls.count
    owner.connectMultihop(); DispatchQueue.background.run(); DispatchQueue.main.run(); DispatchQueue.clear()
    check(owner.api.calls.count == before + 1 && owner.api.calls.last!.body["nodes"] as? [[String:String]] == original.orderedNodes, "SOCKS layered execution lost complete original request")
    for manager in [true, false] { for operation in ["save", "update", "load"] {
        let saved = chooseSOCKSExecution(requested, entryLayer: entryLayer, finalLayer: finalLayer, count: count)
        let api = manager ? owner.api : settings.api
        api.loaded = setupLoaded(saved.orderedNodes, tokens: saved.profileTokens); api.loaded["multihop_execution"] = requested
        try setupAction(manager, operation)
        let restored = owner.captureConnectionProfileSelection()
        check(restored == saved && owner.profiles[count - 1]["start_layer"] as? String == finalLayer && owner.profiles[0]["start_layer"] as? String == entryLayer, "SOCKS layered profile replaced original source or policy")
    } }
} } } }
for count in [3, 8] { for fault in ["missing-hint", "false-hint", "numeric-hint", "too-long", "wrong-protocol", "wrong-row", "entry-kind", "final-kind", "duplicate-catalog", "entry-layer", "entry-layer-type", "later-prefix-layer", "middle-layer", "final-layer", "final-layer-type", "final-mode"] {
    let activeCount = fault == "too-long" ? 8 : count
    let middle = activeCount - 2, final = activeCount - 1
    let original = chooseSOCKSExecution("server", count: activeCount)
    var catalog = owner.profiles, rows = original.orderedNodes
    if fault.hasSuffix("hint") {
        var external = catalog[middle]["external"] as! [String:Any]
        if fault == "missing-hint" { external.removeValue(forKey: "ordered_socks_execution_middle_supported") }
        if fault == "false-hint" { external["ordered_socks_execution_middle_supported"] = false }
        if fault == "numeric-hint" { external["ordered_socks_execution_middle_supported"] = 1 }
        catalog[middle]["external"] = external
    }
    if fault == "too-long" { var extra = catalog[0]; extra["id"] = "extra"; catalog.append(extra); rows.insert(["id":"extra", "mode":"wg"], at:0) }
    if fault == "wrong-protocol" { var external = catalog[middle]["external"] as! [String:Any]; external["protocol"] = "http-connect"; catalog[middle]["external"] = external }
    if fault == "wrong-row" { rows[middle]["mode"] = "shadowsocks" }
    if fault == "entry-kind" { catalog[0]["node_kind"] = "external" }
    if fault == "final-kind" { catalog[final]["node_kind"] = "external" }
    if fault == "duplicate-catalog" { catalog.append(catalog[middle]) }
    if fault == "later-prefix-layer" { catalog[middle - 1]["start_layer"] = "unsupported" }
    if fault == "entry-layer" { catalog[0]["start_layer"] = "aes-256-gcm " }
    if fault == "entry-layer-type" { catalog[0]["start_layer"] = true }
    if fault == "middle-layer" { catalog[middle]["start_layer"] = "aes-256-gcm" }
    if fault == "final-layer" { catalog[final]["start_layer"] = "AES-256-GCM" }
    if fault == "final-layer-type" { catalog[final]["start_layer"] = true }
    if fault == "final-mode" { rows[final]["mode"] = "hysteria2" }
    check(!RouterVPNOrderedNodes.socksExecutionTrio(rows, profiles: catalog), "SOCKS execution accepted changed typed source: " + fault)
} }
for count in [3, 8] { for position in 0..<count {
    let original = chooseSOCKSExecution("auto", count: count)
    var current = owner.profiles
    current[position]["profile_token"] = String(repeating: "f", count:64)
    rejects({ _ = try RouterVPNOrderedNodes.connectBody(original, current:["selected_id":original.selectedNodeID, "profiles":current]) }, "SOCKS execution accepted a relinked original member")
} }
DispatchQueue.clear()
'''

SWIFT_HYSTERIA_EXECUTION = r'''
for count in [2,4,8] { for requested in ["server","auto"] { for finalLayer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
    _ = chooseOrdered(count, finalMode: "hysteria2", prefixMode: "awg2-strong")
    owner.profiles[count-1]["start_layer"] = finalLayer; owner.api.orderedCurrent["profiles"] = owner.profiles
    owner.multihopExecutionPopup.selectItem(at: requested == "server" ? 1 : 2)
    owner.api.orderedCapabilities = ["ordered_nodes_supported":true,"ordered_executions":["local"],"ordered_hysteria_executions":["local","server","auto"]]
    let original = owner.captureConnectionProfileSelection()
    check(RouterVPNOrderedNodes.pairedHysteriaExecutionPath(original.orderedNodes, profiles:owner.profiles), "paired Hysteria source refused")
    let before = owner.api.calls.count
    owner.connectMultihop(); DispatchQueue.background.run(); DispatchQueue.main.run(); DispatchQueue.clear()
    check(owner.api.calls.count == before + 1, "Hysteria execution did not use its distinct native capability")
    check(owner.api.calls.last!.body["nodes"] as? [[String:String]] == original.orderedNodes && owner.api.calls.last!.body["execution"] as? String == requested, "Hysteria execution changed original ordered request")
    for unrelated in ["ordered_executions","ordered_imported_trio_executions","ordered_connect_trio_executions","ordered_socks_trio_executions","ordered_openvpn_executions"] {
        owner.api.orderedCapabilities = ["ordered_nodes_supported":true,unrelated:["local","server","auto"]]
        let blocked = owner.api.calls.count
        owner.connectMultihop(); DispatchQueue.background.run(); DispatchQueue.main.run(); DispatchQueue.clear()
        check(owner.api.calls.count == blocked,"Hysteria execution borrowed unrelated native capability")
    }
    for fault in ["final-layer","external-final","foreign-prefix","duplicate-source"] {
        var catalog = owner.profiles, rows = original.orderedNodes
        if fault == "final-layer" { catalog[count-1]["start_layer"] = "xor-only" }
        if fault == "external-final" { catalog[count-1]["external"] = ["protocol":"hysteria2"] }
        if fault == "foreign-prefix" { rows[0]["mode"] = "shadowsocks" }
        if fault == "duplicate-source" { catalog.append(catalog[0]) }
        check(!RouterVPNOrderedNodes.pairedHysteriaExecutionPath(rows,profiles:catalog),"Hysteria execution accepted foreign source or final layer")
    }
    var current = owner.profiles
    current[0]["profile_token"] = String(repeating:"f",count:64)
    rejects({_ = try RouterVPNOrderedNodes.connectBody(original,current:["selected_id":original.selectedNodeID,"profiles":current])},"Hysteria execution accepted relinked source")
} } }
DispatchQueue.clear()
'''

SWIFT_PAIRED_SS_EXECUTION = r'''
for count in [2,4,8] { for requested in ["server","auto"] {
    _ = chooseOrdered(count, finalMode: "shadowsocks", prefixMode: "awg2-strong")
    owner.multihopExecutionPopup.selectItem(at: requested == "server" ? 1 : 2)
    owner.api.orderedCapabilities = ["ordered_nodes_supported":true,"ordered_executions":["local"],"ordered_paired_ss_executions":["local","server","auto"]]
    for position in owner.profiles.indices { owner.profiles[position]["start_layer"] = ["off","aes-256-gcm","aes-256-gcm+xor-whitening"][position % 3] }
    owner.api.orderedCurrent = ["selected_id":owner.connectionProfileCatalogSelectedID,"profiles":owner.profiles]
    let original = owner.captureConnectionProfileSelection()
    check(RouterVPNOrderedNodes.pairedSSExecutionPath(original.orderedNodes, profiles:owner.profiles), "paired paired SS source refused")
    let before = owner.api.calls.count
    owner.connectMultihop(); DispatchQueue.background.run(); DispatchQueue.main.run(); DispatchQueue.clear()
    check(owner.api.calls.count == before + 1, "paired SS execution did not use its distinct native capability")
    check(owner.api.calls.last!.body["nodes"] as? [[String:String]] == original.orderedNodes && owner.api.calls.last!.body["execution"] as? String == requested, "paired SS execution changed original ordered request")
    for unrelated in ["ordered_executions","ordered_imported_trio_executions","ordered_connect_trio_executions","ordered_socks_trio_executions","ordered_openvpn_executions","ordered_hysteria_executions"] {
        owner.api.orderedCapabilities = ["ordered_nodes_supported":true,unrelated:["local","server","auto"]]
        let blocked = owner.api.calls.count
        owner.connectMultihop(); DispatchQueue.background.run(); DispatchQueue.main.run(); DispatchQueue.clear()
        check(owner.api.calls.count == blocked,"paired SS execution borrowed unrelated native capability")
    }
    for fault in ["final-layer","external-final","foreign-prefix","duplicate-source"] {
        var catalog = owner.profiles, rows = original.orderedNodes
        if fault == "final-layer" { catalog[count-1]["start_layer"] = "unrecognized" }
        if fault == "external-final" { catalog[count-1]["external"] = ["protocol":"shadowsocks"] }
        if fault == "foreign-prefix" { rows[0]["mode"] = "shadowsocks" }
        if fault == "duplicate-source" { catalog.append(catalog[0]) }
        check(!RouterVPNOrderedNodes.pairedSSExecutionPath(rows,profiles:catalog),"paired SS execution accepted foreign source or final layer")
    }
    var current = owner.profiles
    current[0]["profile_token"] = String(repeating:"f",count:64)
    rejects({_ = try RouterVPNOrderedNodes.connectBody(original,current:["selected_id":original.selectedNodeID,"profiles":current])},"paired SS execution accepted relinked source")
} }
DispatchQueue.clear()
'''

SWIFT_OPENVPN_EXECUTION = r'''
@MainActor func chooseOpenVPNExecution(_ requested: String, prefix: String = "wg", entryLayer: String = "off", finalLayer: String = "off", count: Int = 3) -> RouterVPNConnectionProfileSelection {
    _ = setupRows(count)
    _ = chooseImportedExecution(requested, prefix: prefix, entryLayer: entryLayer, finalLayer: finalLayer, count: count)
    owner.profiles[count - 2]["external"] = ["protocol": "openvpn", "ordered_middle_supported": true, "ordered_openvpn_execution_middle_supported": true]
    owner.connectionProfileSelection?.orderedNodes[count - 2]["mode"] = "openvpn"
    owner.api.orderedCurrent = ["selected_id": "ordered-\(count - 1)", "profiles": owner.profiles]
    owner.api.orderedCapabilities = ["ordered_nodes_supported": true, "ordered_executions": ["local"], "ordered_openvpn_executions": ["local", "server", "auto"]]
    return owner.captureConnectionProfileSelection()
}
for count in 3...8 { for requested in ["server", "auto"] { for prefix in ["wg", "awg2-fast", "awg2-strong"] {
  for entryLayer in ["off", "aes-256-gcm", "aes-256-gcm+xor-whitening"] {
    let original = chooseOpenVPNExecution(requested, prefix: prefix, entryLayer: entryLayer, count: count)
    check(RouterVPNOrderedNodes.openVPNExecutionPath(original.orderedNodes, profiles: owner.profiles), "OpenVPN execution lost its distinct complete source hint")
    do { let draft = try owner.makeOrderedNodeDraft(); check(try draft.selection() == original, "OpenVPN execution draft lost the original typed trio") }
    catch { check(false, "OpenVPN execution draft lost the original typed trio") }
    let before = owner.api.calls.count
    owner.connectMultihop(); check(!DispatchQueue.background.pending.isEmpty, "OpenVPN execution did not use its distinct native capability"); DispatchQueue.background.run()
    check(owner.api.calls.count == before + 1, "OpenVPN execution did not use its distinct native capability")
    let posted = owner.api.calls.last!.body
    check(posted["execution"] as? String == requested, "OpenVPN execution did not use its distinct native capability")
    check(posted["nodes"] as? [[String:String]] == original.orderedNodes, "OpenVPN execution did not use its distinct native capability")
    check(posted["expected_profile_tokens"] as? [String:String] == original.profileTokens, "OpenVPN execution did not use its distinct native capability")
    DispatchQueue.main.run(); DispatchQueue.clear()
    for unrelated in ["ordered_executions", "ordered_imported_trio_executions", "ordered_connect_trio_executions", "ordered_socks_trio_executions"] {
        _ = chooseOpenVPNExecution(requested, prefix: prefix, entryLayer: entryLayer, count: count)
        owner.api.orderedCapabilities.removeValue(forKey: "ordered_openvpn_executions")
        owner.api.orderedCapabilities[unrelated] = ["local", "server", "auto"]
        let blocked = owner.api.calls.count
        owner.connectMultihop(); DispatchQueue.background.run(); DispatchQueue.main.run(); DispatchQueue.clear()
        check(owner.api.calls.count == blocked, "OpenVPN execution borrowed unrelated native capability")
    }
    for manager in [true, false] { for operation in ["save", "update", "load"] {
        let saved = chooseOpenVPNExecution(requested, prefix: prefix, entryLayer: entryLayer, count: count)
        let api = manager ? owner.api : settings.api
        api.loaded = setupLoaded(saved.orderedNodes, tokens: saved.profileTokens)
        api.loaded["multihop_execution"] = requested
        let callsBefore = api.calls.count
        try setupAction(manager, operation)
        check(api.calls.count == callsBefore + 1 && !api.calls.last!.path.contains("multihop/connect"), "OpenVPN complete-profile action auto-connected or duplicated a request")
        let restored = owner.captureConnectionProfileSelection()
        check(restored.orderedNodes == saved.orderedNodes && restored.execution == requested && restored.profileTokens == saved.profileTokens, "OpenVPN complete-profile action replaced an original source or execution")
        if operation != "load" { verifyOrderedSnapshot(api.calls.last!.body, rows: saved.orderedNodes, updating: operation == "update", execution: requested) }
        check(owner.profiles[0]["start_layer"] as? String == entryLayer && owner.profiles[count - 1]["start_layer"] as? String == "off", "OpenVPN complete-profile action replaced a captured Start Layer")
    } }
  }
} } }
for count in [3, 4, 8] { for requested in ["server", "auto"] { for entryLayer in ["off", "aes-256-gcm", "aes-256-gcm+xor-whitening"] { for finalLayer in ["aes-256-gcm", "aes-256-gcm+xor-whitening"] {
    let original = chooseOpenVPNExecution(requested, entryLayer: entryLayer, finalLayer: finalLayer, count: count)
    check(RouterVPNOrderedNodes.openVPNExecutionPath(original.orderedNodes, profiles: owner.profiles), "OpenVPN execution refused captured final layer")
    let before = owner.api.calls.count
    owner.connectMultihop(); DispatchQueue.background.run(); DispatchQueue.main.run(); DispatchQueue.clear()
    check(owner.api.calls.count == before + 1 && owner.api.calls.last!.body["nodes"] as? [[String:String]] == original.orderedNodes, "OpenVPN layered execution lost complete original request")
    for manager in [true, false] { for operation in ["save", "update", "load"] {
        let saved = chooseOpenVPNExecution(requested, entryLayer: entryLayer, finalLayer: finalLayer, count: count)
        let api = manager ? owner.api : settings.api
        api.loaded = setupLoaded(saved.orderedNodes, tokens: saved.profileTokens); api.loaded["multihop_execution"] = requested
        try setupAction(manager, operation)
        let restored = owner.captureConnectionProfileSelection()
        check(restored == saved && owner.profiles[count - 1]["start_layer"] as? String == finalLayer && owner.profiles[0]["start_layer"] as? String == entryLayer, "OpenVPN layered profile replaced original source or policy")
    } }
} } } }
for count in [3, 8] { for fault in ["missing-hint", "false-hint", "numeric-hint", "too-long", "wrong-protocol", "wrong-row", "entry-kind", "final-kind", "duplicate-catalog", "entry-layer", "entry-layer-type", "later-prefix-layer", "middle-layer", "final-layer", "final-layer-type", "final-mode"] {
    let activeCount = fault == "too-long" ? 8 : count
    let middle = activeCount - 2, final = activeCount - 1
    let original = chooseOpenVPNExecution("server", count: activeCount)
    var catalog = owner.profiles, rows = original.orderedNodes
    if fault.hasSuffix("hint") {
        var external = catalog[middle]["external"] as! [String:Any]
        if fault == "missing-hint" { external.removeValue(forKey: "ordered_openvpn_execution_middle_supported") }
        if fault == "false-hint" { external["ordered_openvpn_execution_middle_supported"] = false }
        if fault == "numeric-hint" { external["ordered_openvpn_execution_middle_supported"] = 1 }
        catalog[middle]["external"] = external
    }
    if fault == "too-long" { var extra = catalog[0]; extra["id"] = "extra"; catalog.append(extra); rows.insert(["id":"extra", "mode":"wg"], at:0) }
    if fault == "wrong-protocol" { var external = catalog[middle]["external"] as! [String:Any]; external["protocol"] = "http-connect"; catalog[middle]["external"] = external }
    if fault == "wrong-row" { rows[middle]["mode"] = "shadowsocks" }
    if fault == "entry-kind" { catalog[0]["node_kind"] = "external" }
    if fault == "final-kind" { catalog[final]["node_kind"] = "external" }
    if fault == "duplicate-catalog" { catalog.append(catalog[middle]) }
    if fault == "later-prefix-layer" { catalog[middle - 1]["start_layer"] = "unsupported" }
    if fault == "entry-layer" { catalog[0]["start_layer"] = "aes-256-gcm " }
    if fault == "entry-layer-type" { catalog[0]["start_layer"] = true }
    if fault == "middle-layer" { catalog[middle]["start_layer"] = "aes-256-gcm" }
    if fault == "final-layer" { catalog[final]["start_layer"] = "AES-256-GCM" }
    if fault == "final-layer-type" { catalog[final]["start_layer"] = true }
    if fault == "final-mode" { rows[final]["mode"] = "hysteria2" }
    check(!RouterVPNOrderedNodes.openVPNExecutionPath(rows, profiles: catalog), "OpenVPN execution accepted changed typed source: " + fault)
} }
for count in [3, 8] { for position in 0..<count {
    let original = chooseOpenVPNExecution("auto", count: count)
    var current = owner.profiles
    current[position]["profile_token"] = String(repeating: "f", count:64)
    rejects({ _ = try RouterVPNOrderedNodes.connectBody(original, current:["selected_id":original.selectedNodeID, "profiles":current]) }, "OpenVPN execution accepted a relinked original member")
} }
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
    assert 'refreshUnifiedModeMenu(preferred: payload["mode"] as? String)' in profiles
    assert 'MacProfileLoadTransaction.load(body: request' in profiles
    assert 'body: ["id": id, "expected_mode": profile.mode]' in profiles
    assert 'popup.lastItem?.representedObject = ["id": id, "name": profileName, "mode": mode]' in settings
    catalog = block(product, "enum RouterVPNNodeExitModes {") + "\n" + block(product, "enum RouterVPNNodeEntryModes {") + "\n" + block(product, "enum RouterVPNMultihopStartup {")
    declarations = profiles[profiles.index("private let macConnectionModeKey"):profiles.index("private struct MacConnectionProfileList")]
    declarations += block(profiles, "struct MacConnectionCustomPreset:")
    transaction = read("client/macos/RouterVPNProfileLoadTransaction.swift")
    transaction = transaction.replace('FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]', 'FileManager.default.temporaryDirectory.appendingPathComponent("routervpn-profile-load-fixture-" + String(ProcessInfo.processInfo.processIdentifier))')
    declarations += "\n" + transaction + "\n"
    for marker in ("func macCurrentConnectionModeSnapshot(",):
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
    for marker in ("    func connectionProfileSnapshot(", "    func connectionProfilePOST("):
        product_methods += "\n" + block(profiles, marker)
    settings_methods = "\n".join(block(settings, marker) for marker in (
        "    private func requireIdle(", "    private func selectedID(",
        "    private func currentMultihopSnapshot(",
        "    private func write(", "    @objc private func addProfile(",
        "    @objc private func updateProfile(", "    @objc private func loadProfile(",
    ))
    editor_source = profiles[profiles.index("final class RouterVPNOrderedNodeEditor:"):]
    editor_methods = "\n".join(block(editor_source, marker) for marker in (
        "    private func render(", "    @objc private func selectedHopChanged()",
        "    @objc private func transportChanged()", "    @objc private func measureNext()", "    func menuWillOpen(",
    ))
    editor = SWIFT_ORDERED_EDITOR.replace("EDITOR_METHODS", editor_methods).replace("@objc ", "").replace("private func ", "func ")
    # Allow the fixture to invoke the real private callbacks. AppKit ordinarily
    # provides main-actor isolation; the value-only owner classes do so here.
    methods = SWIFT_PRODUCT.replace("PRODUCT_METHODS", product_methods).replace("SETTINGS_METHODS", settings_methods)
    properties = product[product.index("    var multihopNodeIDs:"):product.index("    let dnsModeIDs")]
    methods = methods.replace("PRODUCT_PROPERTIES", properties)
    methods = methods.replace("@objc ", "").replace("private func ", "func ")
    # Rename only the queue boundary so Swift does not apply its special
    # DispatchQueue.global inference to the deterministic value-only scheduler.
    return (SWIFT_BOUNDARIES + catalog + "\n" + declarations + methods + editor + SWIFT_TEST.replace("RACE_TESTS", SWIFT_RACES).replace("ORDERED_TESTS", SWIFT_ORDERED).replace("SETUP_TESTS", SWIFT_SETUP).replace("CONNECT_EXECUTION_TESTS", SWIFT_CONNECT_EXECUTION + SWIFT_SOCKS_EXECUTION + SWIFT_OPENVPN_EXECUTION + SWIFT_HOSTNAME_EXECUTION + SWIFT_HYSTERIA_EXECUTION + SWIFT_PAIRED_SS_EXECUTION)).replace("UserDefaults.standard", "fixtureDefaults").replace("defaults: .standard", "defaults: fixtureDefaults").replace("verify(in: .standard)", "verify(in: fixtureDefaults)").replace("DispatchQueue", "DeferredQueue")


SWIFT_HOSTNAME_EXECUTION = r'''
// Hostname admission has a separate saved-resolver hint and requires an
// original packet prefix in the Server suffix. The UI never resolves a name.
for count in [3, 4, 8] { for requested in ["server", "auto"] {
    _ = chooseImportedExecution(requested, count: count)
    let middle = count - 2
    var hints = owner.profiles[middle]["external"] as! [String: Any]
    hints["ordered_execution_middle_supported"] = false
    hints["ordered_hostname_execution_middle_supported"] = true
    owner.profiles[middle]["external"] = hints
    owner.api.orderedCurrent["profiles"] = owner.profiles
    let original = owner.captureConnectionProfileSelection()
    if count == 3 {
        rejects({ _ = try RouterVPNOrderedNodes.connectBody(original,current:owner.api.orderedCurrent) }, "hostname trio acquired suffix packet authority")
        rejects({ _ = try owner.makeOrderedNodeDraft() }, "hostname trio draft acquired suffix packet authority")
        continue
    }
    do { let draft = try owner.makeOrderedNodeDraft(); check(try draft.selection() == original, "hostname draft changed complete saved prefix") }
    catch { check(false, "hostname draft refused complete saved prefix") }
    for updating in [false, true] {
        let snapshot = try owner.connectionProfileSnapshot(name:"Saved hostname execution",id:updating ? "saved-profile" : nil)
        verifyOrderedSnapshot(snapshot,rows:original.orderedNodes,updating:updating,execution:requested)
        _ = try settings.write(path:updating ? "/api/connection-profile/setup/update" : "/api/connection-profile/setup/save",updating:updating)
        verifyOrderedSnapshot(settings.api.calls.last!.body,rows:original.orderedNodes,updating:updating,execution:requested)
        var payload = snapshot
        payload["profile"] = ["name":"Saved hostname execution","mode":"shadowsocks"]
        payload["selected_node_id"] = original.selectedNodeID; payload["profile_tokens"] = original.profileTokens
        try owner.applyLoadedConnectionProfile(payload)
        check(owner.captureConnectionProfileSelection() == original,"hostname Load changed original source or choice")
    }
    DispatchQueue.clear()
    let before = owner.api.calls.count
    owner.connectMultihop(); DispatchQueue.background.run(); DispatchQueue.main.run(); DispatchQueue.clear()
    check(owner.api.calls.count == before+1 && owner.api.calls.last!.body["nodes"] as? [[String:String]] == original.orderedNodes && owner.api.calls.last!.body["execution"] as? String == requested && owner.api.calls.last!.body["expected_profile_tokens"] as? [String:String] == original.profileTokens,"hostname callback lost original source or choice")
    for capability in [NSNull(), false, 1, "true"] as [Any] {
        var changed = owner.profiles; var external = changed[middle]["external"] as! [String:Any]
        external["ordered_hostname_execution_middle_supported"] = capability; changed[middle]["external"] = external
        rejects({ _ = try RouterVPNOrderedNodes.connectBody(original,current:["selected_id":original.selectedNodeID,"profiles":changed]) },"hostname execution accepted absent or nonboolean capability")
    }
    var changed = owner.profiles; var external = changed[middle]["external"] as! [String:Any]
    external["ordered_execution_middle_supported"] = true; changed[middle]["external"] = external
    rejects({ _ = try RouterVPNOrderedNodes.connectBody(original,current:["selected_id":original.selectedNodeID,"profiles":changed]) },"hostname execution accepted conflicting capabilities")
    for position in 0..<count {
        var changed = owner.profiles; changed[position]["profile_token"] = String(repeating:"f",count:64)
        rejects({ _ = try RouterVPNOrderedNodes.connectBody(original,current:["selected_id":original.selectedNodeID,"profiles":changed]) },"hostname execution accepted relinked original member")
    }
    var stale = owner.profiles; var revoked = stale[middle]["external"] as! [String:Any]
    revoked["ordered_hostname_execution_middle_supported"] = false; stale[middle]["external"] = revoked
    owner.api.orderedCurrent["profiles"] = stale
    let stopped = owner.api.calls.count; owner.connectMultihop(); DispatchQueue.background.run(); DispatchQueue.clear()
    check(owner.api.calls.count == stopped,"hostname callback ignored fresh capability revocation")
} }

'''


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
        "post-response-manager-idle": replace_once(source, 'try self.requireMutationIdle("adopting the prepared connection profile")',
            'if transport != nil { try self.requireMutationIdle("adopting the prepared connection profile") }'),
        "post-response-settings-idle": replace_once(source, 'try self.requireMutationIdle("adopting the prepared connection profile")',
            'if transport == nil { try self.requireMutationIdle("adopting the prepared connection profile") }'),
        "ordered-drop-middle": replace_once(source, '"multihop_nodes": selectedPath.orderedNodes',
            '"multihop_nodes": [selectedPath.orderedNodes.first!, selectedPath.orderedNodes.last!]'),
        "ordered-final-owner": replace_once(source, 'rows.last?["id"] == control', 'true'),
        "ordered-middle-source": replace_once(source, 'matches[0]["profile_token"] as? String == token', 'true'),
        "ordered-capability": replace_once(source, 'CFGetTypeID(enabled) == CFBooleanGetTypeID(), enabled.boolValue', 'true, true'),
        "ordered-request-owner": replace_once(source, 'self.connectionProfileSelectionGeneration == generation &&', 'true &&'),
        "ordered-locked-source-preconditions": replace_once(source, 'return ["nodes": rows, "execution": selection.execution, "expected_selected_node_id": selection.selectedNodeID,\n                "expected_profile_tokens": tokens]', 'return ["nodes": rows, "execution": selection.execution, "expected_selected_node_id": selection.selectedNodeID,\n                "expected_profile_tokens": [String: String]()]'),
    }
    execution_variants = {
        "ordered-execution-capture": (
            'value.entryID = ""; value.exitID = ""; value.entryMode = ""; value.exitMode = ""\n            let executionIndex = multihopExecutionPopup.indexOfSelectedItem\n            value.execution = (0..<3).contains(executionIndex) ? ["local", "server", "auto"][executionIndex] : ""',
            'value.entryID = ""; value.exitID = ""; value.entryMode = ""; value.exitMode = ""\n            value.execution = "local"',
            "ordered snapshot relabelled explicit execution"),
        "ordered-execution-connect": ('"nodes": rows, "execution": selection.execution', '"nodes": rows, "execution": "local"',
            "ordered callback relabelled execution or dropped members"),
    }
    for name, (old, new, _) in execution_variants.items():
        variants[name] = replace_once(source, old, new)
    setup_variants = {
        "setup-source-preconditions": ('request.merge(expected) { _, original in original }', 'request.removeValue(forKey: "expected_profile_tokens")', "setup request lost its original source capture"),
        "setup-generation": ('connectionProfileSelectionGeneration == admittedGeneration,', 'true,', "late setup response accepted new-generation"),
        "setup-mode": ('guard connectionProfileSelectionGeneration == admittedGeneration, captureConnectionProfileSelection() == original,\n              UserDefaults.standard.string(forKey: macConnectionModeKey) == mode,', 'guard connectionProfileSelectionGeneration == admittedGeneration, captureConnectionProfileSelection() == original,\n              true,', "late setup response accepted mode-change"),
        "setup-live-source": ('originals.allSatisfy({ current[$0.key] == $0.value })', 'true', "late setup response accepted source-relinked"),
        "setup-response-source": ('response["profile_tokens"] as? [String: String] == body["expected_profile_tokens"] as? [String: String]', 'true', "setup response accepted changed-token"),
        # Omit only order; keep each exact id/mode row so the newer typed-middle
        # protocol refusal cannot preempt the original reordered-member witness.
        "setup-response-order": ('finalized.orderedNodes == wanted', 'finalized.orderedNodes.sorted(by: { ($0["id"] ?? "") < ($1["id"] ?? "") }) == wanted.sorted(by: { ($0["id"] ?? "") < ($1["id"] ?? "") })', "setup response accepted reordered-members"),
        "setup-load-inventory": ('let graph = loading || external ? matches[0] : body', 'let graph = external ? matches[0] : body', "setup request lost complete original inventory"),
        "setup-response-inventory": ('Set(tokens.keys) == referenced,', 'true,', "Load accepted unrelated response source receipts"),
        "setup-stale-body": ('if writing && !(profiles.first(where:', 'if false && !(profiles.first(where:', "old setup body overrode a newer Off choice before dispatch"),
    }
    final_variants = {
        "local-imported-position": ('mode == "shadowsocks" && (3...physicalTraversalDepth).contains(count) && position > 0 && position < count - 1', 'mode == "shadowsocks" && (3...physicalTraversalDepth).contains(count) && position > 0 && position == count - 2', "Local imported nodes lost complete original path"),
        "local-imported-capability": ('CFGetTypeID(allowed) == CFBooleanGetTypeID()', 'true', "Local imported nodes accepted invalid source capability"),
        "ordered-final-draft": ('[["id": control, "mode": finalMode]]', '[["id": control, "mode": "shadowsocks"]]', "ordered final callback substituted a member transport"),
        "ordered-final-snapshot": ('"mode": selectedPath.orderedNodes.last!["mode"]!', '"mode": "shadowsocks"', "ordered save retained unrelated mode or layers"),
        "ordered-final-apply": ('let mode = selection.orderedNodes.last!["mode"]!\\n        fixtureDefaults.set(mode, forKey: macConnectionModeKey)', 'let mode = "shadowsocks"\\n        fixtureDefaults.set(mode, forKey: macConnectionModeKey)', "ordered Apply displayed a different final transport"),
        "ordered-final-widget": ('transport.isEnabled = !modes.isEmpty', 'transport.isEnabled = draft.prefixes.indices.contains(index)', "ordered editor did not expose the supported final transport"),
        "ordered-final-layer": ('return ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(hysteriaFinalLayer)', 'return true', "Hysteria2 accepted an invalid final source"),
        "ordered-imported-final": ('["shadowsocks", "socks5", "http-connect", "https-connect", "openvpn"].contains(mode) && rows.last?["mode"] == "shadowsocks")', '["shadowsocks", "socks5", "http-connect", "https-connect", "openvpn"].contains(mode))', "imported middle references acquired a Hysteria2 final"),
        "ordered-imported-choice": ('return finalModes.filter { $0 == "shadowsocks" || importedIDs.isDisjoint(with: prefixes) }', 'return finalModes', "imported middle editor offered a Hysteria2 final"),
        "ordered-loaded-final": ('fromCatalog || (stored?["mode"] as? String == selection.orderedNodes.last?["mode"] && payload["mode"] as? String == selection.orderedNodes.last?["mode"])', 'true', "Hysteria2 Load accepted inconsistent final metadata: stored-mode"),
    }
    for name, (old, new, _) in final_variants.items():
        variants[name] = replace_once(source, old.replace("\\n", "\n"), new.replace("\\n", "\n"))
    for name, (old, new, _) in setup_variants.items():
        variants[name] = replace_once(source, old.replace("UserDefaults.standard", "fixtureDefaults"), new)
    socks_variants = {
        "ordered-socks-protocol": ('row["mode"] == importedMode', '["shadowsocks", "socks5"].contains(row["mode"]!)', "SOCKS Connect borrowed another imported protocol"),
        "ordered-socks-draft-mode": ('modes.insert(mode, at: position)', 'modes.insert(mode == "socks5" ? "shadowsocks" : mode, at: position)', "SOCKS editor Add replaced the captured middle mode"),
        "ordered-socks-capability": ('CFGetTypeID(value) == CFBooleanGetTypeID(), value.boolValue,', 'value.boolValue,', "SOCKS imported capability accepted non-boolean authority"),
        "ordered-socks-final": ('return finalModes.filter { $0 == "shadowsocks" || importedIDs.isDisjoint(with: prefixes) }', 'return finalModes.filter { $0 == "shadowsocks" || !modes.contains("shadowsocks") }', "SOCKS imported middle editor offered a Hysteria2 final"),
    }
    for name, (old, new, _) in socks_variants.items():
        variants[name] = replace_once(source, old, new)
    connect_variants = {
        "ordered-connect-protocol": ('row["mode"] == importedMode', '(row["mode"] == importedMode || (["http-connect", "https-connect"].contains(row["mode"]!) && ["http-connect", "https-connect"].contains(importedMode!)))', "CONNECT Connect borrowed HTTP or HTTPS transport"),
        "ordered-connect-draft-mode": ('modes.insert(mode, at: position)', 'modes.insert(mode == "https-connect" ? "http-connect" : mode, at: position)', "CONNECT editor Add replaced the captured middle mode"),
    }
    for name, (old, new, _) in connect_variants.items():
        variants[name] = replace_once(source, old, new)
    imported_execution_variants = {
        "imported-execution-old-trio": ('guard (3...8).contains(rows.count), rows.dropLast(2).allSatisfy', 'guard rows.count == 3, rows.dropLast(2).allSatisfy', "complete imported execution draft refused original prefixes"),
        "imported-execution-later-prefix-layer": ('where position != middle {', 'where position != middle && (position == 0 || position == members.count - 1) {', "complete imported execution accepted malformed later prefix layer"),
        "imported-execution-later-prefix-kind": ('guard finalProfile(paired, mode: "shadowsocks") else { return false }', 'guard true else { return false }', "complete imported execution admitted a second imported prefix"),
        "imported-execution-layer": ('guard let layer = raw as? String, ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(layer) else { return false }', 'guard let layer = raw as? String, !layer.isEmpty || layer.isEmpty else { return false }', "complete imported execution accepted malformed later prefix layer"),
        "imported-execution-layers-disabled": ('["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(layer)', '["", "off"].contains(layer)', "imported execution draft lost independent paired layers or exact native capability"),
        "imported-execution-entry-layer": ('for (position, paired) in members.enumerated() where position != middle {', 'for (position, paired) in members.enumerated() where position != middle && position != 0 {', "Darwin imported execution accepted a malformed paired layer"),
        "imported-execution-final-layer": ('for (position, paired) in members.enumerated() where position != middle {', 'for (position, paired) in members.enumerated() where position != middle && position != members.count - 1 {', "Darwin imported execution accepted a malformed paired layer"),
        "measured-mixed-packet-position": ('try updated.insert(id, mode: proposedMode, at: index + 1)', 'try updated.insert(id, mode: proposedMode, at: updated.prefixes.count)', "original measured packet could not be inserted before its captured streams"),
        "imported-execution-boolean": ('CFGetTypeID(literal) == CFBooleanGetTypeID() else { return false }', 'true else { return false }', "imported execution accepted absent or nonboolean member capability"),
        "imported-execution-live-capability": ('capabilities[executionCapability] as? [String]', 'capabilities[executionCapability == "ordered_imported_trio_executions" ? "ordered_executions" : executionCapability] as? [String]', "imported execution did not use separate exact-trio capability"),
        "multiple-imported-execution-live-capability": ('capabilities[executionCapability] as? [String]', 'capabilities[executionCapability == "ordered_multiple_imported_executions" ? "ordered_executions" : executionCapability] as? [String]', "Multiple imported execution used the generic native capability"),
        "imported-execution-draft": (' || RouterVPNOrderedNodes.importedExecutionPrefixes(ordered, profiles: capturedCatalog)', '', "imported execution draft lost independent paired layers or exact native capability"),
        "imported-execution-body": (' || importedExecutionPrefixes(rows, profiles: profiles)', '', "imported execution did not use separate exact-trio capability"),
    }
    imported_execution_variants.update({
        "connect-execution-prefix-layer": ('["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(allowedLayer)', '(position < middle || ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(allowedLayer))', "CONNECT execution accepted changed typed trio: later-prefix-layer"),
        "connect-execution-old-trio": ('guard (3...8).contains(count), rows.dropLast(2).allSatisfy', 'guard count == 3, rows.dropLast(2).allSatisfy', "CONNECT execution draft lost original complete path"),
        "connect-execution-final-layer": ('["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(allowedLayer)', '(position == count - 1 || ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(allowedLayer))', "CONNECT execution accepted changed typed trio: final-layer"),
        "connect-execution-boolean": ('CFGetTypeID(hint) == CFBooleanGetTypeID(), hint.boolValue', 'hint.boolValue', "CONNECT execution accepted changed typed trio: numeric-hint"),
        "connect-execution-capability": ('"ordered_connect_trio_executions" : (importedPrefixes', '"ordered_imported_trio_executions" : (importedPrefixes', "CONNECT execution did not use its distinct native capability"),
        "socks-execution-old-trio": ('guard (3...8).contains(socksCount), rows.dropLast(2).allSatisfy', 'guard socksCount == 3, rows.dropLast(2).allSatisfy', "SOCKS execution lost its distinct complete source hint"),
        "socks-execution-final-layer": ('["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(socksPrefixLayer)', '(position == socksCount - 1 || ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(socksPrefixLayer))', "SOCKS execution accepted changed typed source: final-layer"),
        "socks-execution-capability": ('"ordered_socks_trio_executions" : (connectTrio', '"ordered_connect_trio_executions" : (connectTrio', "SOCKS execution did not use its distinct native capability"),
        "socks-execution-boolean": ('CFGetTypeID(socksHint) == CFBooleanGetTypeID(), socksHint.boolValue', 'socksHint.boolValue', "SOCKS execution accepted changed typed source: numeric-hint"),
        "socks-execution-layer": ('position != socksMiddle || socksPrefixLayer == "" || socksPrefixLayer == "off"', 'true', "SOCKS execution accepted changed typed source: middle-layer"),
        "socks-execution-entry-layer": ('["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(socksPrefixLayer)', 'true', "SOCKS execution accepted changed typed source: entry-layer"),
        "socks-execution-protocol": ('importedMiddleMode(members[socksMiddle]) == rows[socksMiddle]["mode"],', 'importedMiddleMode(members[socksMiddle]) != nil,', "SOCKS execution accepted changed typed source: wrong-protocol"),
        "socks-execution-draft": (' || RouterVPNOrderedNodes.socksExecutionTrio(ordered, profiles: capturedCatalog)', '', "SOCKS execution draft lost the original typed trio"),
        "socks-execution-body": (' || socksExecutionTrio(rows, profiles: profiles)', '', "SOCKS execution did not use its distinct native capability"),
    })
    imported_execution_variants.update({
        "hostname-execution-minimum": ('guard rows.count >= 4, let hostname', 'guard rows.count >= 3, let hostname', "hostname trio acquired suffix packet authority"),
        "hostname-execution-boolean": ('CFGetTypeID(hostname) == CFBooleanGetTypeID(),', 'true,', "hostname execution accepted absent or nonboolean capability"),
        "hostname-execution-conflict": ('!(literal.boolValue && hostname.boolValue)', 'true', "hostname execution accepted conflicting capabilities"),
    })
    imported_execution_variants.update({
        "socks-execution-final-layer-required": ('position != socksMiddle || socksPrefixLayer == "" || socksPrefixLayer == "off"', '(position != socksMiddle && position != socksCount - 1) || socksPrefixLayer == "" || socksPrefixLayer == "off"', "SOCKS execution refused captured final layer"),
        "connect-execution-final-layer-required": ('position != middle || allowedLayer == "" || allowedLayer == "off"', '(position != middle && position != count - 1) || allowedLayer == "" || allowedLayer == "off"', "CONNECT execution refused captured final layer"),
    })
    imported_execution_variants.update({
        "openvpn-execution-capability": ('"ordered_openvpn_executions" : (socksTrio', '"ordered_executions" : (socksTrio', "OpenVPN execution did not use its distinct native capability"),
        "openvpn-execution-boolean": ('CFGetTypeID(openVPNHint) == CFBooleanGetTypeID(), openVPNHint.boolValue', 'openVPNHint.boolValue', "OpenVPN execution accepted changed typed source: numeric-hint"),
        "openvpn-execution-final-layer-required": ('position != openVPNMiddle || openVPNLayer == "" || openVPNLayer == "off"', '(position != openVPNMiddle && position != openVPNCount - 1) || openVPNLayer == "" || openVPNLayer == "off"', "OpenVPN execution refused captured final layer"),
    })
    imported_execution_variants.update({
        "hysteria-execution-capability": ('"ordered_hysteria_executions" : openVPNPath', '"ordered_executions" : openVPNPath', "Hysteria execution did not use its distinct native capability"),
        "hysteria-final-layer-required": ('return ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(hysteriaFinalLayer)', 'return hysteriaFinalLayer.isEmpty || hysteriaFinalLayer == "off"', "Hysteria final layer was not offered"),
        "paired-ss-execution-capability": ('"ordered_paired_ss_executions" : pairedHysteria', '"ordered_executions" : pairedHysteria', "paired SS execution did not use its distinct native capability"),
    })
    imported_execution_variants["retired-draft-followup"] = (
        'self.window?.isVisible == true, self.revision == revision,',
        'self.window?.isVisible == true,', "retired editor revision started a queued candidate trial")
    for name, (old, new, _) in imported_execution_variants.items():
        variants[name] = replace_once(source, old, new)
    for name, program in variants.items():
        path, binary = directory / (name + ".swift"), directory / name
        path.write_text(program, encoding="utf-8")
        run(["swiftc", "-swift-version", "6", "-module-cache-path", str(directory / "swift-module-cache"), str(path), "-o", str(binary)])
        run([str(binary)], negative=name != "shipping", witness=(execution_variants.get(name) or setup_variants.get(name) or final_variants.get(name) or socks_variants.get(name) or connect_variants.get(name) or imported_execution_variants.get(name) or (None, None, None))[2])
        if name != "shipping": print("PASS causal AppKit " + name, flush=True)
    from test_appkit_profile_load_transaction import main as test_durable_load
    test_durable_load()
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
