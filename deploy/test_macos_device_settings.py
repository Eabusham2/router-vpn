#!/usr/bin/env python3
"""Exercise the shipping AppKit Settings callback and captured device transaction.

Foundation runs the exact serializer/transaction. A small AppKit boundary double
drives the actual Settings callback, controls and targets on other build hosts.
The full AppKit compiler still runs through build-native-app.sh on macOS.
"""
from pathlib import Path
import argparse
import importlib.util
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "client/macos/RouterVPNMacDeviceSettings.swift"
SETTINGS = ROOT / "client/macos/RouterVPNProfileSettings.swift"
BUILDER = ROOT / "client/macos/build-native-app.sh"


def shipping(model=None, settings=None, build=None):
    model = MODEL.read_text() if model is None else model
    settings = SETTINGS.read_text() if settings is None else settings
    build = BUILDER.read_text() if build is None else build
    spec = importlib.util.spec_from_file_location("mac_device_source_closure", ROOT / "deploy/test_macos_source_closure.py")
    closure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(closure)
    assert MODEL in closure.compiled_inputs(build), "Device serializer is absent from shipping swiftc"
    assert 'test_macos_device_settings.py" --shipping-only' in build, "Native builder lost device callback gate"
    for marker in (
        'let displayedProfileID = routerPopup.selectedItem?.representedObject as? String ?? ""',
        'let displayedNodeKind = (profiles.first(where:',
        'let data: Data? = displayedNodeKind == "router-vpn" ?',
        'let deviceData: Data? = displayedNodeKind == "external" ?',
        'MacProfileDeviceSettings.capture($0, displayedProfileID: displayedProfileID)',
        'let supportsDeviceSettings = capturedDevice?.devicePolicySupported == true',
        'commonPreferenceViews.forEach { $0.isEnabled = supportsCommonSettings && !settingsMutationBusy }',
        'let policyControls = MacDevicePolicyControls(',
        'withExtendedLifetime((connectionProfiles, policyControls))',
        'try capturedDevice.save(edits: deviceEdits, displayedProfileID:',
        'try self.api.requestRaw("/api/profile/device", body: $0, timeout: 8)',
        'externalStartup.saveData(startupMode: settings.startupMode, autoConnect: settings.autoConnect)',
        'requestRaw("/api/profile/startup", body: payload',
    ):
        assert marker in settings, "Shipping Settings callback lost " + marker
    assert 'try Self.requireIdle(readStatus())' in model
    assert 'guard displayedProfileID() == profileID else' in model
    assert 'if edits.startupMode != displayedStartup || edits.autoConnect != autoConnect {' in model
    product = (ROOT / "client/macos/RouterVPNMacUnifiedShell.swift").read_text()
    assert 'editProfileSettings' in product, "Unified native Settings has no real callback"
    assert 'Last recorded interface MTU:' in settings
    assert 'capturedDevice?.note ??' in settings, "Device capability note is not shown by the shipping form"
    assert '("Auto — default","auto")' in settings, "Auto label invents a path measurement"
    workflow = (ROOT / ".github/workflows/macos-native-app.yml").read_text()
    assert workflow.count("- 'deploy/test_macos_device_settings.py'") == 2, "Fixture-only edits do not trigger both native workflow events"
    assert 'run: python3 deploy/test_macos_device_settings.py\n' in workflow, "macOS workflow omitted executable device defects"
    for key in ('"dns_mode":', '"effective_mtu":', '"jumbo_tun":', '"start_layer":', '"external":'):
        assert key not in model, "Narrow common policy copied unrelated field " + key


def extracts(source):
    sections = []
    for expression in (
        r"^private struct RouterVPNProfileSettingsPayloadV2: Codable \{.*?^\}",
        r"^private struct MacProfileStartupSettings: Decodable, Sendable \{.*?^\}",
        r"^private func macMutationBusy\(_ api: ProductAPI\) -> Bool \{.*?^\}",
        r"^private final class MacDevicePolicyControls: NSObject \{.*?^\}",
        r"^extension ProductWindowController \{.*?^\}",
    ):
        found = re.findall(expression, source, re.M | re.S)
        assert len(found) == 1, "Shipping Settings callback boundary changed: " + expression
        sections.append(found[0])
    # Linux has no Objective-C selector runtime. Targets and real update methods
    # remain intact; only AppKit's selector representation is a boundary double.
    return re.sub(r"#selector\([^)]*\)", "nil", "\n".join(sections)).replace("@objc ", "")


BOUNDARY = r'''
import Foundation

var checks = 0
func check(_ result: Bool, _ message: String) {
    if !result { fatalError("device fixture: " + message) }
    checks += 1
}
func data(_ object: [String: Any]) -> Data { try! JSONSerialization.data(withJSONObject: object) }
func object(_ value: Data) -> [String: Any] { try! JSONSerialization.jsonObject(with: value) as! [String: Any] }
func rejects(_ message: String, _ body: () throws -> Void) {
    var failed = false
    do { try body() } catch { failed = true }
    check(failed, message)
}
let fixtureID = "exit-quoted"
let fixtureToken = String(repeating: "b", count: 64)
let startupToken = String(repeating: "c", count: 64)
func saved(_ override: [String: Any] = [:]) -> [String: Any] {
    var result: [String: Any] = [
        "profile_id": fixtureID, "profile_token": fixtureToken, "node_kind": "external",
        "protocol": "shadowsocks", "device_policy_supported": true, "device_policy_reason": "",
        "home_lan_access": true, "kill_switch_policy": "always", "ipv6_mode": "off",
        "mtu_policy": "auto", "manual_mtu": 0, "effective_mtu": 1392, "mtu_source": "historical path",
        "startup_mode": "smart-auto", "auto_connect": false,
        "external": ["password": "must-never-copy"], "jumbo_tun": true,
        "dns_mode": "home", "entry_id": "independent-entry", "start_layer": "private-policy"
    ]
    result.merge(override) { _, current in current }
    return result
}
func edited(_ capture: MacProfileDeviceSettings) -> MacProfileDeviceSettings.Edits {
    MacProfileDeviceSettings.Edits(homeLANAccess: capture.homeLANAccess,
        killSwitchPolicy: capture.killSwitchPolicy, ipv6Mode: capture.ipv6Mode,
        mtuPolicy: capture.mtuPolicy, manualMTUText: String(capture.manualMTU),
        startupMode: capture.displayedStartup, autoConnect: capture.autoConnect)
}
func echo(_ body: Data, original: [String: Any] = saved()) -> Data {
    var response = original
    response.merge(object(body)) { _, current in current }
    response["profile_token"] = String(repeating: "d", count: 64)
    return data(response)
}
let idleState: [String: Any] = ["connected": false, "phase": "off"]

enum Orientation { case vertical, horizontal }
enum Bezel { case rounded }
enum State { case on, off }
enum ModalResult { case alertFirstButtonReturn, alertSecondButtonReturn }
struct Color { static let secondaryLabelColor = Color() }
struct Font { static func systemFont(ofSize: Double) -> Font { Font() } }
class NSView: NSObject { var frame = NSRect.zero }
class NSControl: NSView { var isEnabled = true; var target: AnyObject?; var action: String? }
class NSStackView: NSView {
    var orientation = Orientation.vertical
    var spacing = 0.0
    var arrangedSubviews: [NSView] = []
    func addArrangedSubview(_ view: NSView) { arrangedSubviews.append(view) }
}
class NSTextField: NSControl {
    var stringValue: String
    var textColor: Color?
    var font: Font?
    init(string: String) { stringValue = string; super.init() }
    convenience init(labelWithString: String) { self.init(string: labelWithString) }
    convenience init(wrappingLabelWithString: String) { self.init(string: wrappingLabelWithString) }
}
class NSMenuItem {
    var title: String
    var representedObject: Any?
    init(_ title: String) { self.title = title }
}
class NSPopUpButton: NSControl {
    var items: [NSMenuItem] = []
    var selected = 0
    var selectedItem: NSMenuItem? { selected >= 0 && selected < items.count ? items[selected] : nil }
    var lastItem: NSMenuItem? { items.last }
    func addItem(withTitle title: String) { items.append(NSMenuItem(title)) }
    func selectItem(at index: Int) { selected = index }
}
class NSButton: NSControl {
    var title: String
    var state = State.off
    var bezelStyle = Bezel.rounded
    init(title: String, target: AnyObject?, action: String?) {
        self.title = title; super.init(); self.target = target; self.action = action
    }
    convenience init(checkboxWithTitle title: String, target: AnyObject?, action: String?) {
        self.init(title: title, target: target, action: action)
    }
}
class NSAlert {
    var messageText = ""
    var informativeText = ""
    var accessoryView: NSView?
    var buttons: [NSButton] = []
    static var interact: ((NSAlert) -> ModalResult)?
    static var presentations = 0
    func addButton(withTitle title: String) { buttons.append(NSButton(title: title, target: nil, action: nil)) }
    func runModal() -> ModalResult {
        Self.presentations += 1
        return Self.interact?(self) ?? .alertSecondButtonReturn
    }
}
final class ProductAPI {
    var device = saved()
    var startup: [String: Any] = ["profile_id":fixtureID, "profile_token":startupToken,
        "node_kind":"external", "startup_mode":"manual", "auto_connect":false]
    var router: Data?
    var rejectDeviceRead = false
    var reads: [String] = []
    var writes: [(String, Data)] = []
    var statusCount = 0
    var onDeviceRead: (() -> Void)?
    var onStatus: ((Int) throws -> Data)?
    var changeReceipt: (([String: Any]) -> [String: Any])?
    func request(_ path: String, timeout: TimeInterval = 15) throws -> Data {
        check(timeout > 0 && timeout <= 8, "Settings read has a bounded timeout")
        reads.append(path)
        switch path {
        case "/api/profile/settings":
            guard let router else { throw MacProfileDeviceSettings.issue("external node") }
            return router
        case "/api/profile/device":
            onDeviceRead?()
            if rejectDeviceRead { throw MacProfileDeviceSettings.issue("controller selected a Router node") }
            return data(device)
        case "/api/profile/startup": return data(startup)
        case "/api/status":
            statusCount += 1
            return try onStatus?(statusCount) ?? data(idleState)
        default: throw MacProfileDeviceSettings.issue("Unexpected Settings read: " + path)
        }
    }
    func requestRaw(_ path: String, body: Data, timeout: TimeInterval = 15) throws -> Data {
        check(timeout > 0 && timeout <= 8, "Settings save has a bounded timeout")
        writes.append((path, body))
        var receipt = path == "/api/profile/device" ? object(echo(body, original: device)) : object(body)
        receipt = changeReceipt?(receipt) ?? receipt
        return data(receipt)
    }
}
final class ProductWindowController: NSObject {
    let api: ProductAPI
    let routerPopup = NSPopUpButton()
    var profiles: [[String: Any]] = [["id":fixtureID,"node_kind":"external"]]
    var done = false
    var message = ""
    var error = ""
    init(api: ProductAPI) {
        self.api = api; super.init()
        routerPopup.addItem(withTitle: "Captured"); routerPopup.lastItem?.representedObject = fixtureID
        routerPopup.addItem(withTitle: "Replacement"); routerPopup.lastItem?.representedObject = "replacement"
    }
    func asyncAction(_ work: @escaping () throws -> String) {
        DispatchQueue.global().async {
            do { let result = try work(); DispatchQueue.main.async { self.message = result; self.done = true } }
            catch { let detail = error.localizedDescription; DispatchQueue.main.async { self.error = detail; self.done = true } }
        }
    }
}
private final class MacConnectionProfileControls {
    let root = NSStackView()
    init(api: ProductAPI, owner: ProductWindowController) {
        root.addArrangedSubview(NSTextField(labelWithString: "Existing connection profiles"))
    }
}
'''

TESTS = r'''
// Decode exact typed policy, preserving escaped IDs and discarding private data.
let capture = try MacProfileDeviceSettings.capture(data(saved()), displayedProfileID: fixtureID)
let keys: Set<String> = ["profile_id","profile_token","home_lan_access","kill_switch_policy","ipv6_mode","mtu_policy","manual_mtu"]
for kill in ["off","on-connect","always"] {
    for ipv6 in ["on","auto","off"] {
        for mtu in ["auto","manual","default"] {
            var values = edited(capture)
            values.homeLANAccess = false; values.killSwitchPolicy = kill; values.ipv6Mode = ipv6
            values.mtuPolicy = mtu; values.manualMTUText = mtu == "manual" ? "1400" : "stale text"
            let body = object(try capture.saveData(displayedProfileID: fixtureID, edits: values))
            check(Set(body.keys) == keys, "Unchanged startup alias or unrelated private fields were posted")
            check(body["profile_id"] as? String == fixtureID && body["profile_token"] as? String == fixtureToken, "Device save lost captured source")
            check(body["manual_mtu"] as? Int == (mtu == "manual" ? 1400 : 0), "Saved MTU came from history/default instead of requested policy")
            check(body["home_lan_access"] as? Bool == false && body["kill_switch_policy"] as? String == kill && body["ipv6_mode"] as? String == ipv6, "Requested common fields were replaced")
        }
    }
}
for mode in ["manual","last"] {
    var values = edited(capture); values.startupMode = mode; values.autoConnect = mode != "manual"
    let body = object(try capture.saveData(displayedProfileID: fixtureID, edits: values))
    check(Set(body.keys) == keys.union(["startup_mode","auto_connect"]), "Edited startup was not one atomic common transaction")
    check(body["startup_mode"] as? String == mode && body["auto_connect"] as? Bool == values.autoConnect, "Startup pair was lost")
}
for originalAutomatic in [false,true] {
    let original = try MacProfileDeviceSettings.capture(data(saved(["auto_connect":originalAutomatic])), displayedProfileID:fixtureID)
    var values = edited(original); values.autoConnect = !originalAutomatic
    let body = object(try original.saveData(displayedProfileID:fixtureID, edits:values))
    check(Set(body.keys) == keys.union(["startup_mode","auto_connect"]), "Auto-connect-only edit lost its atomic pair")
    check(body["startup_mode"] as? String == "smart-auto" && body["auto_connect"] as? Bool == !originalAutomatic, "Auto-connect-only device edit rewrote the stored startup alias")
}
do {
    let raw: [String:Any] = ["profile_id":fixtureID,"profile_token":startupToken,"node_kind":"external","startup_mode":"smart-auto","auto_connect":false]
    let captured = try JSONDecoder().decode(MacProfileStartupSettings.self, from:data(raw))
    for automatic in [false,true] {
        let body = object(try captured.saveData(startupMode:"auto",autoConnect:automatic))
        check(body["startup_mode"] as? String == "smart-auto" && body["auto_connect"] as? Bool == automatic, "Startup-only no-op or auto-connect-only save rewrote the stored alias")
        check(body["profile_token"] as? String == startupToken, "Startup alias preservation replaced its own captured token")
    }
}
do {
    let id = "node \"quoted\""
    let quoted = try MacProfileDeviceSettings.capture(data(saved(["profile_id":id])), displayedProfileID:id)
    check(object(try quoted.saveData(displayedProfileID:id, edits:edited(quoted)))["profile_id"] as? String == id, "JSON escaping changed the captured identity")
}
do {
    let note = "Tor Auto uses a 1280-byte virtual interface. Retest is not yet implemented."
    let tor = try MacProfileDeviceSettings.capture(data(saved(["protocol":"tor-bridge", "note":note])), displayedProfileID:fixtureID)
    let body = object(try tor.saveData(displayedProfileID:fixtureID, edits:edited(tor)))
    check(tor.note == note && body["note"] == nil,
          "Captured Tor capability note was lost or copied into policy")
}
let invalidCaptures: [[String:Any]] = [
    ["profile_id":"foreign"], ["profile_token":"short"], ["profile_token":String(repeating:"G",count:64)],
    ["node_kind":"router-vpn"], ["device_policy_supported":"true"], ["home_lan_access":"false"],
    ["auto_connect":1], ["manual_mtu":"1280"], ["mtu_policy":"fixed"], ["startup_mode":"unknown"],
    ["ipv6_mode":"maybe"], ["kill_switch_policy":"maybe"], ["manual_mtu":1392],
    ["mtu_policy":"manual","manual_mtu":1279], ["mtu_policy":"manual","manual_mtu":9001]
]
for override in invalidCaptures {
    rejects("Malformed or foreign captured policy was accepted") {
        _ = try MacProfileDeviceSettings.capture(data(saved(override)), displayedProfileID:fixtureID)
    }
}
for fixed in ["", "1279", "9001", "-1400", "+1400", "1400.0", "1e3", "14 00", "１２８０"] {
    var values = edited(capture); values.mtuPolicy = "manual"; values.manualMTUText = fixed
    rejects("Invalid fixed MTU silently became a default") { _ = try capture.saveData(displayedProfileID:fixtureID, edits:values) }
}
for fixed in ["1280", "9000"] {
    var values = edited(capture); values.mtuPolicy = "manual"; values.manualMTUText = fixed
    check(object(try capture.saveData(displayedProfileID:fixtureID, edits:values))["manual_mtu"] as? Int == Int(fixed), "Fixed MTU boundary was lost")
}
do {
    var values = edited(capture); values.startupMode = "manual"; values.autoConnect = true
    rejects("Manual startup accepted auto-connect") { _ = try capture.saveData(displayedProfileID:fixtureID, edits:values) }
    let unsupported = try MacProfileDeviceSettings.capture(data(saved(["device_policy_supported":false,"protocol":"tor"])), displayedProfileID:fixtureID)
    rejects("An unsupported runtime enabled common device mutation") { _ = try unsupported.saveData(displayedProfileID:fixtureID, edits:edited(unsupported)) }
}
for bad in [["connected":true,"phase":"connected"], ["connected":false,"phase":"reasserting"],
            ["connected":false,"phase":"future-phase"], ["connected":"false"], ["phase":"off"]] as [[String:Any]] {
    var writes = 0
    rejects("Active, unknown or malformed status bypassed fresh idle admission") {
        try capture.save(edits:edited(capture), displayedProfileID:{fixtureID}, readStatus:{data(bad)}, persist:{ writes += 1; return echo($0) })
    }
    check(writes == 0, "Rejected status still posted policy")
}
do {
    var current = fixtureID; var writes = 0
    rejects("Selection changed during fresh idle read but was adopted") {
        try capture.save(edits:edited(capture), displayedProfileID:{current}, readStatus:{current = "replacement"; return data(idleState)},
                         persist:{ writes += 1; return echo($0) })
    }
    check(writes == 0, "Stale displayed owner reached persistence")
}
do {
    var writes = 0
    try capture.save(edits:edited(capture), displayedProfileID:{fixtureID}, readStatus:{data(idleState)}, persist:{ writes += 1; return echo($0) })
    check(writes == 1, "One Save emitted more than one device transaction")
}
for (field,value) in [("profile_id","other"),("ipv6_mode","on"),("startup_mode","auto")] {
    rejects("A mismatched saved policy was announced as success") {
        try capture.save(edits:edited(capture), displayedProfileID:{fixtureID}, readStatus:{data(idleState)}, persist:{
            var result = object(echo($0)); result[field] = value; return data(result)
        })
    }
}
func descendants(_ view: NSView) -> [NSView] {
    [view] + ((view as? NSStackView)?.arrangedSubviews.flatMap(descendants) ?? [])
}
func button(_ alert: NSAlert, _ title: String) -> NSButton {
    let found = descendants(alert.accessoryView!).compactMap{$0 as? NSButton}.first{$0.title == title}
    check(found != nil, "Shipping control missing: " + title); return found!
}
func popup(_ alert: NSAlert, _ title: String) -> NSPopUpButton {
    for row in descendants(alert.accessoryView!).compactMap({$0 as? NSStackView}) {
        if (row.arrangedSubviews.first as? NSTextField)?.stringValue == title,
           let result = row.arrangedSubviews.last as? NSPopUpButton { return result }
    }
    fatalError("device fixture: Missing popup " + title)
}
func manual(_ alert: NSAlert) -> NSTextField {
    for row in descendants(alert.accessoryView!).compactMap({$0 as? NSStackView}) {
        if (row.arrangedSubviews.first as? NSTextField)?.stringValue.hasPrefix("Fixed MTU ") == true,
           let result = row.arrangedSubviews.last as? NSTextField { return result }
    }
    fatalError("device fixture: Missing fixed MTU field")
}
func choose(_ popup: NSPopUpButton, _ id: String) {
    guard let index = popup.items.firstIndex(where:{$0.representedObject as? String == id}) else {
        fatalError("device fixture: Missing policy choice " + id)
    }
    popup.selectItem(at:index)
    (popup.target as? MacDevicePolicyControls)?.update()
}
func runEditor(_ api: ProductAPI = ProductAPI(), interaction: @escaping (NSAlert,ProductWindowController)->ModalResult,
               configure: ((ProductWindowController)->Void)? = nil) -> ProductWindowController {
    let owner = ProductWindowController(api:api)
    configure?(owner)
    NSAlert.interact = { interaction($0,owner) }
    owner.editProfileSettings()
    let deadline = Date().addingTimeInterval(8)
    while !owner.done && Date() < deadline { RunLoop.main.run(until:Date().addingTimeInterval(0.005)) }
    check(owner.done, "Real Settings callback failed to finish")
    NSAlert.interact = nil
    return owner
}
func inspectCommon(_ alert: NSAlert, editable: Bool) {
    check(button(alert,"Allow home LAN access").isEnabled == editable, "Common LAN control is disconnected from native device support")
    for title in ["Kill switch","IPv6","MTU"] {
        check(popup(alert,title).isEnabled == editable, "Common " + title + " control is disconnected from native device support")
    }
    for title in ["WG / AWG base","Start layer"] {
        check(!popup(alert,title).isEnabled, "Imported node enabled a Router-only control")
    }
    for title in ["DAITA-like traffic padding (bounded; supported modes only)","Jumbo TUN / jumbo packet mode (compatible paths only)","Private in-tunnel SOCKS5 utility"] {
        check(!button(alert,title).isEnabled, "Imported node enabled unsupported Router-only mutation")
    }
}
do {
    let api = ProductAPI()
    let owner = runEditor(api) { alert,_ in
        inspectCommon(alert,editable:true)
        check(!manual(alert).isEnabled, "Auto MTU permits an unrelated fixed override")
        choose(popup(alert,"MTU"),"manual"); check(manual(alert).isEnabled, "Fixed MTU field did not activate")
        manual(alert).stringValue = "1400"
        button(alert,"Allow home LAN access").state = .off
        choose(popup(alert,"Kill switch"),"on-connect"); choose(popup(alert,"IPv6"),"on")
        return .alertFirstButtonReturn
    }
    check(owner.error.isEmpty && api.writes.count == 1 && api.writes[0].0 == "/api/profile/device", "Real ordinary-node Save did not use the native common endpoint")
    let body = object(api.writes[0].1)
    check(Set(body.keys) == keys && body["manual_mtu"] as? Int == 1400, "Real callback lost exact narrow payload")
    check(body["profile_token"] as? String == fixtureToken && body["ipv6_mode"] as? String == "on", "Real callback replaced policy ownership")
    check(!api.reads.contains("/api/profile/startup"), "Supported device Settings unnecessarily adopted a separate startup token")
}
do {
    let api = ProductAPI()
    let owner = runEditor(api) { alert,_ in
        choose(popup(alert,"Default mode on startup"),"last")
        button(alert,"Auto-connect when Router VPN starts").state = .on
        return .alertFirstButtonReturn
    }
    check(owner.error.isEmpty && api.writes.count == 1, "Edited startup caused a partial/multiple transaction")
    check(Set(object(api.writes[0].1).keys) == keys.union(["startup_mode","auto_connect"]), "Real startup edit did not join common Save")
}
do {
    let api = ProductAPI()
    let note = "Tor Auto uses a 1280-byte virtual interface. Retest is not yet implemented."
    api.device = saved(["protocol":"tor-bridge", "note":note])
    let owner = runEditor(api) { alert,_ in
        inspectCommon(alert,editable:true)
        check(alert.informativeText == note, "Real Tor form replaced its captured capability note")
        check(popup(alert,"MTU").selectedItem?.title == "Auto — default", "Real Tor Auto claimed a measured path")
        return .alertFirstButtonReturn
    }
    check(owner.error.isEmpty && api.writes.count == 1 && api.writes[0].0 == "/api/profile/device", "Real Tor device Save lost its captured route")
}
do {
    let api = ProductAPI()
    let owner = runEditor(api) {alert,_ in
        button(alert,"Auto-connect when Router VPN starts").state = .on
        return .alertFirstButtonReturn
    }
    check(owner.error.isEmpty && api.writes.count == 1 && api.writes[0].0 == "/api/profile/device", "Real auto-connect-only edit changed common transaction routes")
    let body = object(api.writes[0].1)
    check(body["startup_mode"] as? String == "smart-auto" && body["auto_connect"] as? Bool == true, "Real device callback rewrote a startup alias while toggling auto-connect")
}
do {
    let api = ProductAPI()
    api.device = saved(["protocol":"tor","device_policy_supported":false,"device_policy_reason":"Native owner pending"])
    let owner = runEditor(api) { alert,_ in
        inspectCommon(alert,editable:false)
        check(button(alert,"Allow home LAN access").state == .on && popup(alert,"IPv6").selectedItem?.representedObject as? String == "off", "Unsupported runtime replaced its saved read-only device values with defaults")
        choose(popup(alert,"Default mode on startup"),"last")
        button(alert,"Auto-connect when Router VPN starts").state = .on
        return .alertFirstButtonReturn
    }
    check(owner.error.isEmpty && api.writes.count == 1 && api.writes[0].0 == "/api/profile/startup", "Unsupported Tor lost its startup-only route")
    let body = object(api.writes[0].1)
    check(Set(body.keys) == ["profile_id","profile_token","startup_mode","auto_connect"], "Unsupported Tor posted disabled common defaults")
    check(body["profile_token"] as? String == startupToken, "Startup-only Save substituted the device/entry token")
}
for automatic in [false,true] {
    let api = ProductAPI()
    api.device = saved(["protocol":"tor","device_policy_supported":false,"device_policy_reason":"Native owner pending"])
    api.startup["startup_mode"] = "smart-auto"
    let owner = runEditor(api) {alert,_ in
        button(alert,"Auto-connect when Router VPN starts").state = automatic ? .on : .off
        return .alertFirstButtonReturn
    }
    check(owner.error.isEmpty && api.writes.count == 1 && api.writes[0].0 == "/api/profile/startup", "Unsupported startup alias lost its separate save route")
    let body = object(api.writes[0].1)
    check(body["profile_token"] as? String == startupToken && body["startup_mode"] as? String == "smart-auto" && body["auto_connect"] as? Bool == automatic, "Unsupported startup callback rewrote its alias or adopted the device token")
}
do {
    let api = ProductAPI()
    let owner = runEditor(api) { alert,_ in
        let automatic = button(alert,"Auto-connect when Router VPN starts")
        automatic.state = .on
        choose(popup(alert,"Default mode on startup"),"manual")
        check(automatic.state == .off && !automatic.isEnabled, "Manual startup retained enabled auto-connect")
        return .alertFirstButtonReturn
    }
    check(owner.error.isEmpty && object(api.writes[0].1)["auto_connect"] as? Bool == false, "Manual startup produced invalid payload")
}
for changedAt in ["read","modal","idle"] {
    let api = ProductAPI()
    let owner = runEditor(api, interaction:{alert,owner in
        if changedAt == "modal" { owner.routerPopup.selectItem(at:1) }
        return .alertFirstButtonReturn
    }, configure:{owner in
        if changedAt == "read" { api.onDeviceRead = { DispatchQueue.main.sync {owner.routerPopup.selectItem(at:1)} } }
        if changedAt == "idle" { api.onStatus = {count in
            if count == 2 { DispatchQueue.main.sync {owner.routerPopup.selectItem(at:1)} }
            return data(idleState)
        } }
    })
    check(api.writes.isEmpty && !owner.error.isEmpty, "Real callback adopted a replacement owner during " + changedAt)
}
for phase in ["connected","reasserting","future-phase"] {
    let api = ProductAPI()
    api.onStatus = {count in data(count == 1 ? idleState : ["connected":phase == "connected","phase":phase])}
    let owner = runEditor(api) {_,_ in .alertFirstButtonReturn}
    check(!owner.error.isEmpty && api.writes.isEmpty, "Real callback skipped fresh idle check: " + phase)
}
do {
    let api = ProductAPI(); api.onStatus = {_ in data(["connected":false,"phase":"future-phase"])}
    let owner = runEditor(api) {alert,_ in
        inspectCommon(alert,editable:false)
        check(alert.buttons.first?.isEnabled == false, "Unknown initial connection phase enabled Save")
        return .alertFirstButtonReturn
    }
    check(api.writes.isEmpty && owner.message.contains("locked"), "Locked native Settings posted a policy")
}
for value in ["", "1279", "9001", "1400.0"] {
    let api = ProductAPI()
    let owner = runEditor(api) {alert,_ in choose(popup(alert,"MTU"),"manual"); manual(alert).stringValue = value; return .alertFirstButtonReturn}
    check(!owner.error.isEmpty && api.writes.isEmpty, "Real invalid fixed input was silently defaulted: " + value)
}
do {
    let api = ProductAPI()
    let owner = runEditor(api) {_,_ in .alertSecondButtonReturn}
    check(owner.error.isEmpty && api.writes.isEmpty, "Cancel still saved device settings")
}
do {
    let api = ProductAPI(); api.changeReceipt = { original in var result = original; result["profile_id"] = "replacement"; return result }
    let owner = runEditor(api) {_,_ in .alertFirstButtonReturn}
    check(api.writes.count == 1 && !owner.error.isEmpty, "Foreign saved echo was announced as success")
}
// The displayed imported node remains selected while the controller has moved
// to a Router. Its valid Router-only response must never choose this edit route.
do {
    let api = ProductAPI()
    api.router = try JSONEncoder().encode(RouterVPNProfileSettingsPayloadV2.unavailableDefaults)
    api.rejectDeviceRead = true
    api.startup["profile_id"] = "controller-router"; api.startup["node_kind"] = "router-vpn"
    _ = runEditor(api) {_,_ in .alertFirstButtonReturn}
    check(api.writes.isEmpty && !api.reads.contains("/api/profile/settings"), "External editor adopted the controller's unrelated Router-only settings")
}
do {
    let api = ProductAPI()
    api.router = try JSONEncoder().encode(RouterVPNProfileSettingsPayloadV2.unavailableDefaults)
    _ = runEditor(api, interaction:{_,_ in .alertFirstButtonReturn}, configure:{$0.profiles = []})
    check(api.writes.isEmpty && !api.reads.contains("/api/profile/settings") && !api.reads.contains("/api/profile/device"), "Missing displayed kind chose an unbound settings route")
}
// The complete Router-node Settings route still serializes its original policy.
do {
    let api = ProductAPI()
    api.router = try JSONEncoder().encode(RouterVPNProfileSettingsPayloadV2.unavailableDefaults)
    let owner = runEditor(api, interaction:{alert,_ in
        check(popup(alert,"WG / AWG base").isEnabled && button(alert,"Jumbo TUN / jumbo packet mode (compatible paths only)").isEnabled, "Router-only settings were removed")
        return .alertFirstButtonReturn
    }, configure:{$0.profiles = [["id":fixtureID,"node_kind":"router-vpn"]]})
    check(owner.error.isEmpty && api.writes.count == 1 && api.writes[0].0 == "/api/profile/settings", "Router Settings changed routes")
    check(!api.reads.contains("/api/profile/device") && !api.reads.contains("/api/profile/startup"), "Router Settings adopted an external capture")
}
print("PASS: \(checks) captured device serializer, transaction and actual Settings callback/control checks")
'''


def run(args, *, broken=False, timeout=90):
    result = subprocess.run([str(value) for value in args], text=True, capture_output=True, timeout=timeout)
    combined = result.stdout + result.stderr
    if broken:
        if result.returncode == 0 or "device fixture:" not in combined:
            raise AssertionError("Broken device guard did not reach its intended executable assertion:\n" + combined[-7000:])
    elif result.returncode:
        raise RuntimeError(combined[-10000:])
    elif result.stdout.strip():
        print(result.stdout.strip(), flush=True)
    return result


def executable(negative=True):
    model, settings = MODEL.read_text(), SETTINGS.read_text()
    with tempfile.TemporaryDirectory(prefix="routervpn-macos-device-") as name:
        directory = Path(name)

        def exercise(label, altered_model=model, altered_settings=settings, broken=False):
            path = directory / "RouterVPNMacDeviceSettings.swift"
            main = directory / "main.swift"
            binary = directory / label
            path.write_text(altered_model)
            main.write_text(BOUNDARY + extracts(altered_settings) + TESTS)
            run(["swiftc", "-module-cache-path", directory / "module-cache", path, main, "-o", binary])
            run([binary], broken=broken)

        exercise("shipping")
        if negative:
            variants = (
                ("fresh-idle", "model", "try Self.requireIdle(readStatus())", "_ = try readStatus()"),
                ("post-read-owner", "model", "guard displayedProfileID() == profileID else", "guard true else"),
                ("unchanged-startup", "model", "if edits.startupMode != displayedStartup || edits.autoConnect != autoConnect {", "if true {"),
                ("device-startup-alias", "model", 'body["startup_mode"] = edits.startupMode == displayedStartup ? startupMode : edits.startupMode', 'body["startup_mode"] = edits.startupMode'),
                ("fallback-startup-alias", "settings", "let savedStartup = startupMode == displayedStartup ? self.startupMode : startupMode", "let savedStartup = startupMode"),
                ("captured-node-kind", "settings", 'let data: Data? = displayedNodeKind == "router-vpn" ?', 'let data: Data? = true ?'),
                ("historical-mtu", "model", '"manual_mtu": fixed', '"manual_mtu": effectiveMTU ?? fixed'),
                ("foreign-capture", "model", "value.profileID == displayedProfileID,", "true,"),
                ("common-disabled", "settings", "commonPreferenceViews.forEach { $0.isEnabled = supportsCommonSettings && !settingsMutationBusy }", "commonPreferenceViews.forEach { $0.isEnabled = supportsNodeSettings && !settingsMutationBusy }"),
                ("wrong-route", "settings", 'requestRaw("/api/profile/device", body: $0', 'requestRaw("/api/profile/settings", body: $0'),
            )
            for label, target, old, new in variants:
                value = model if target == "model" else settings
                assert value.count(old) == 1, "Device negative no longer applies: " + label
                exercise(label, altered_model=value.replace(old, new) if target == "model" else model,
                         altered_settings=value.replace(old, new) if target == "settings" else settings, broken=True)
                print("Rejected executable AppKit device defect: " + label, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shipping-only", action="store_true")
    args = parser.parse_args()
    shipping()
    executable(negative=not args.shipping_only)
    print("AppKit common device Settings source/composition: PASS")
