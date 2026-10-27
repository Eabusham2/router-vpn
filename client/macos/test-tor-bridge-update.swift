// Execute shipping callback/capture code with value-only UI and queue boundaries.
// Actual AppKit widgets are exercised by test_macos_tor_bridge_ui on macOS.
import Foundation
import CoreFoundation
/* HELPERS */
enum QoS { case userInitiated }
final class DispatchQueue {
    static let main = DispatchQueue()
    static func global(qos: QoS) -> DispatchQueue { DispatchQueue() }
    func async(_ action: () -> Void) { action() }
}
final class Field { var stringValue = "" }
final class Area { var string = "" }
final class Popup { var indexOfSelectedItem = 0; func selectItem(at index: Int) { indexOfSelectedItem = index } }
enum CheckState { case on, off }
final class Toggle { var state = CheckState.on }
final class Owner {
    var profiles: [[String: Any]]; var selected: String; var busy = false
    init(_ catalog: [String: Any]) { profiles = catalog["profiles"] as! [[String: Any]]; selected = catalog["selected_id"] as! String }
    func selectedNodeID() -> String? { selected }
    func ensureMutationIdle(_ action: String) -> Bool { !busy }
    func requireMutationIdle(_ action: String) throws { if busy { throw NSError(domain: "busy", code: 1) } }
    func refreshAll() {}
}
final class ProductAPI {
    var current: [String: Any]; var saved: [String: Any]?; var reads = 0
    init(_ current: [String: Any]) { self.current = current }
    func json(_ path: String, timeout: Double) throws -> Any { precondition(path == "/api/nodes"); reads += 1; return current }
    func request(_ path: String, method: String, body: [String: Any], timeout: Double) throws -> Data {
        precondition(path == "/api/tor-bridge/import" && method == "POST"); saved = body; return Data("saved".utf8)
    }
}
final class Form {
    var productOwner: Owner?; let api: ProductAPI; let opened: [String: Any]
    let updateSelected = Toggle(), nameField = Field(), transportPopup = Popup(), killSwitchPopup = Popup(), bridgeText = Area(), status = Field()
    var capabilityRoot: [String: Any]; var capabilities: [String: [String: Any]] = [:]
    let transportIDs = ["obfs4", "meek_lite", "snowflake", "webtunnel", "custom"]
    init(owner: Owner, api: ProductAPI, capabilities: [String: Any]) {
        productOwner = owner; self.api = api; capabilityRoot = capabilities
        for row in capabilities["transports"] as! [[String: Any]] { self.capabilities[row["id"] as! String] = row }
        /* CAPTURE */
    }
    /* METHODS */
    func renderCapability() {}
    /* SAVE */
}
var checks = 0
func check(_ value: @autoclosure () -> Bool, _ message: String) { checks += 1; if !value() { fatalError(message) } }
let directory = URL(fileURLWithPath: CommandLine.arguments[1])
func object(_ name: String) throws -> [String: Any] { try JSONSerialization.jsonObject(with: Data(contentsOf: directory.appendingPathComponent(name))) as! [String: Any] }
let catalog = try object("tor-update-source-catalog.json"), caps = try object("tor-update-capabilities.json"), lines = try object("tor-update-input-lines.json")
for (index, id) in ["obfs4", "meek_lite", "snowflake", "webtunnel"].enumerated() {
    for (killIndex, kill) in ["off", "on-connect", "always"].enumerated() {
        let owner = Owner(catalog), api = ProductAPI(catalog)
        let active = Form(owner: owner, api: api, capabilities: caps)
        active.transportPopup.indexOfSelectedItem = index; active.killSwitchPopup.indexOfSelectedItem = killIndex
        active.bridgeText.string = (lines[id] as! [String]).joined(separator: "\n")
        active.save()
        check(api.saved != nil, "Actual Save rejected valid captured update: "+active.status.stringValue)
        let body = api.saved!
        check(body["id"] as? String == "tor-edit" && body["expected_selected_node_id"] as? String == "tor-edit", "Update target changed")
        check((body["expected_profile_tokens"] as? [String: String])?.count == 2, "Entry/source identity dropped")
        check(body["transport"] as? String == id && body["kill_switch_policy"] as? String == kill, "Transport/protection changed")
        for key in ["profile_id", "entry_id", "entry_mode", "direct", "execution", "api_token", "dns_mode"] { check(body[key] == nil, "Copied unrelated field "+key) }
        try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]).write(to: directory.appendingPathComponent("tor-update-\(id)-\(kill).json"))
    }
}
let always = try object("tor-update-always-source-catalog.json")
let alwaysOwner = Owner(always), alwaysAPI = ProductAPI(always)
let saved = Form(owner: alwaysOwner, api: alwaysAPI, capabilities: caps)
saved.updateSelectionChanged()
check(saved.killSwitchPopup.indexOfSelectedItem == 2 && saved.nameField.stringValue == "Captured Tor exit", "Update checkbox did not load saved Always and name")
saved.transportPopup.indexOfSelectedItem = 2; saved.bridgeText.string = (lines["snowflake"] as! [String]).joined(separator: "\n")
saved.save(); check(alwaysAPI.saved?["kill_switch_policy"] as? String == "always", "Actual Save lost untouched saved Always protection")
try JSONSerialization.data(withJSONObject: alwaysAPI.saved!, options: [.sortedKeys]).write(to: directory.appendingPathComponent("tor-update-preserved-protection.json"))
for fault in ["selected", "exit-token", "entry-token", "missing-entry", "duplicate-exit", "entry-is-external", "server-path", "old-controller", "missing-token", "busy", "retired-owner", "display-mutated", "invalid-saved-policy", "missing-saved-policy"] {
    var opened = catalog, current = catalog, capability = caps
    var profiles = opened["profiles"] as! [[String: Any]]
    switch fault {
    case "selected": current["selected_id"] = "entry"
    case "exit-token", "entry-token": var now = profiles; now[fault == "exit-token" ? 0 : 1]["profile_token"] = String(repeating: "a", count: 64); current["profiles"] = now
    case "missing-entry": current["profiles"] = [profiles[0]]
    case "duplicate-exit": current["profiles"] = profiles + [profiles[0]]
    case "entry-is-external": profiles[1]["node_kind"] = "external"; opened["profiles"] = profiles; current = opened
    case "server-path": profiles[0]["multihop_execution"] = "server"; opened["profiles"] = profiles; current = opened
    case "old-controller": capability["profile_update_source_preconditions"] = false
    case "missing-token": profiles[0]["profile_token"] = ""; opened["profiles"] = profiles; current = opened
    case "invalid-saved-policy": profiles[0]["kill_switch_policy"] = "unexpected"; opened["profiles"] = profiles; current = opened
    case "missing-saved-policy": profiles[0].removeValue(forKey: "kill_switch_policy"); opened["profiles"] = profiles; current = opened
    default: break
    }
    let owner = Owner(opened), api = ProductAPI(current)
    let active = Form(owner: owner, api: api, capabilities: capability)
    if fault == "busy" { owner.busy = true }
    if fault == "retired-owner" { active.productOwner = nil }
    if fault == "display-mutated" { owner.profiles[1]["profile_token"] = String(repeating: "b", count: 64); api.current["profiles"] = owner.profiles }
    active.transportPopup.indexOfSelectedItem = 2; active.killSwitchPopup.indexOfSelectedItem = 2; active.bridgeText.string = (lines["snowflake"] as! [String]).joined(separator: "\n")
    if fault == "invalid-saved-policy" || fault == "missing-saved-policy" { active.updateSelectionChanged(); check(active.killSwitchPopup.indexOfSelectedItem == -1, "Missing/invalid policy became Off") }
    active.save(); check(api.saved == nil, "Tor update adopted "+fault)
}
let owner = Owner(catalog), api = ProductAPI(catalog)
let newForm = Form(owner: owner, api: api, capabilities: caps); newForm.updateSelected.state = .off; newForm.transportPopup.indexOfSelectedItem = 2
newForm.bridgeText.string = (lines["snowflake"] as! [String]).joined(separator: "\n"); newForm.killSwitchPopup.indexOfSelectedItem = 2
newForm.save(); check(api.saved == nil, "Direct dynamic transport borrowed Router authority")
newForm.killSwitchPopup.indexOfSelectedItem = 0; newForm.save()
check(api.saved != nil && api.saved!["id"] == nil && api.saved!["expected_profile_tokens"] == nil && api.reads == 0, "Add borrowed captured update identity")
print("Swift actual Tor editor capture/callback: \(checks) checks PASS")
