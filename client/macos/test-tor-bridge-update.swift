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
let localCatalog = try object("tor-update-source-catalog.json"), caps = try object("tor-update-capabilities.json"), lines = try object("tor-update-input-lines.json")
let selections = ["local", "server"] + ["wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"].map { "ordinary-" + $0 }
for execution in selections {
let ordinary = execution.hasPrefix("ordinary-"), tcpOnly = ["ordinary-socks5", "ordinary-http-connect", "ordinary-https-connect"].contains(execution)
let filePrefix = execution == "local" ? "" : execution + "-"
let catalog = try object("tor-update-\(filePrefix)source-catalog.json")
for (index, id) in ["obfs4", "meek_lite", "snowflake", "webtunnel"].enumerated() {
    for (killIndex, kill) in ["off", "on-connect", "always"].enumerated() {
        let owner = Owner(catalog), api = ProductAPI(catalog)
        let active = Form(owner: owner, api: api, capabilities: caps)
        active.transportPopup.indexOfSelectedItem = index; active.killSwitchPopup.indexOfSelectedItem = killIndex
        active.bridgeText.string = (lines[id] as! [String]).joined(separator: "\n")
        active.save()
        if tcpOnly && id == "snowflake" && kill != "off" {
            check(api.saved == nil, "Strict Snowflake escaped the captured TCP-only predecessor check")
            continue
        }
        check(api.saved != nil, "Actual Save rejected valid captured update: "+active.status.stringValue)
        let body = api.saved!
        check(body["id"] as? String == "tor-edit" && body["expected_selected_node_id"] as? String == "tor-edit", "Update target changed")
        check((body["expected_profile_tokens"] as? [String: String])?.count == 2, "Entry/source identity dropped")
        check(body["transport"] as? String == id && body["kill_switch_policy"] as? String == kill, "Transport/protection changed")
        for key in ["profile_id", "entry_id", "entry_mode", "direct", "execution", "api_token", "dns_mode"] { check(body[key] == nil, "Copied unrelated field "+key) }
        try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]).write(to: directory.appendingPathComponent("tor-update-\(filePrefix)\(id)-\(kill).json"))
    }
}
let always = try object("tor-update-\(filePrefix)always-source-catalog.json")
let alwaysOwner = Owner(always), alwaysAPI = ProductAPI(always)
let saved = Form(owner: alwaysOwner, api: alwaysAPI, capabilities: caps)
saved.updateSelectionChanged()
check(saved.killSwitchPopup.indexOfSelectedItem == 2 && saved.nameField.stringValue == "Captured Tor exit", "Update checkbox did not load saved Always and name")
saved.transportPopup.indexOfSelectedItem = ordinary ? 1 : 2; saved.bridgeText.string = (lines[ordinary ? "meek_lite" : "snowflake"] as! [String]).joined(separator: "\n")
saved.save(); check(alwaysAPI.saved?["kill_switch_policy"] as? String == "always", "Actual Save lost untouched saved Always protection")
try JSONSerialization.data(withJSONObject: alwaysAPI.saved!, options: [.sortedKeys]).write(to: directory.appendingPathComponent("tor-update-\(filePrefix)preserved-protection.json"))
var faults = ["selected", "exit-token", "entry-token", "missing-entry", "duplicate-exit", "entry-is-external", "compare-path", "server-direct", "server-external-entry", "compare-off", "server-direct-off", "server-external-off", "old-controller", "missing-token", "busy", "retired-owner", "display-mutated", "invalid-saved-policy", "missing-saved-policy"]
if ordinary { faults += ["ordinary-mode", "ordinary-public-proof", "ordinary-capability", "ordinary-fixed-bypass"]; if tcpOnly { faults += ["ordinary-mixed-udp", "ordinary-mixed-udp-bare", "ordinary-mixed-udp-unicode"] } }
for fault in faults {
    var opened = catalog, current = catalog, capability = caps
    var profiles = opened["profiles"] as! [[String: Any]]
    switch fault {
    case "selected": current["selected_id"] = "entry"
    case "exit-token", "entry-token": var now = profiles; now[fault == "exit-token" ? 0 : 1]["profile_token"] = String(repeating: "a", count: 64); current["profiles"] = now
    case "missing-entry": current["profiles"] = [profiles[0]]
    case "duplicate-exit": current["profiles"] = profiles + [profiles[0]]
    case "entry-is-external":
        profiles[1]["node_kind"] = "external"
        if ordinary { var external = profiles[1]["external"] as! [String: Any]; external["protocol"] = "unknown"; profiles[1]["external"] = external }
        opened["profiles"] = profiles; current = opened
    case "compare-path", "compare-off": profiles[0]["multihop_execution"] = "auto"; opened["profiles"] = profiles; current = opened
    case "server-direct", "server-direct-off": profiles[0]["multihop_execution"] = "server"; profiles[0]["multihop_enabled"] = false; opened["profiles"] = profiles; current = opened
    case "server-external-entry", "server-external-off": profiles[0]["multihop_execution"] = "server"; profiles[1]["node_kind"] = "external"; opened["profiles"] = profiles; current = opened
    case "old-controller": capability["profile_update_source_preconditions"] = false
    case "missing-token": profiles[0]["profile_token"] = ""; opened["profiles"] = profiles; current = opened
    case "invalid-saved-policy": profiles[0]["kill_switch_policy"] = "unexpected"; opened["profiles"] = profiles; current = opened
    case "missing-saved-policy": profiles[0].removeValue(forKey: "kill_switch_policy"); opened["profiles"] = profiles; current = opened
    case "ordinary-mode", "ordinary-fixed-bypass": profiles[0]["multihop_entry_mode"] = "unrelated-mode"; opened["profiles"] = profiles; current = opened
    case "ordinary-public-proof":
        var external = profiles[1]["external"] as! [String: Any]; external["expected_public_ip"] = ""; profiles[1]["external"] = external
        opened["profiles"] = profiles; current = opened
    case "ordinary-capability": capability["transports"] = (capability["transports"] as! [[String: Any]]).map { row -> [String: Any] in var changed = row; changed["strict_external_entry_kill_switch"] = false; return changed }
    default: break
    }
    let owner = Owner(opened), api = ProductAPI(current)
    let active = Form(owner: owner, api: api, capabilities: capability)
    if fault == "busy" { owner.busy = true }
    if fault == "retired-owner" { active.productOwner = nil }
    if fault == "display-mutated" { owner.profiles[1]["profile_token"] = String(repeating: "b", count: 64); api.current["profiles"] = owner.profiles }
    let fixed = fault.hasSuffix("-off") || fault == "ordinary-fixed-bypass"
    active.transportPopup.indexOfSelectedItem = fixed ? 0 : ordinary ? 1 : 2
    active.killSwitchPopup.indexOfSelectedItem = fault.hasSuffix("-off") ? 0 : 2
    active.bridgeText.string = (lines[fixed ? "obfs4" : ordinary ? "meek_lite" : "snowflake"] as! [String]).joined(separator: "\n")
    if fault.hasPrefix("ordinary-mixed-udp") {
        var mixed = (lines["snowflake"] as! [String])[0]
        if fault.hasSuffix("-bare") { mixed = mixed.replacingOccurrences(of: "Bridge ", with: "") }
        if fault.hasSuffix("-unicode") { mixed = mixed.replacingOccurrences(of: "Bridge snowflake ", with: "bRiDgE\u{00a0}SnOwFlAkE\u{00a0}") }
        active.transportPopup.indexOfSelectedItem = 4; active.bridgeText.string = ((lines["obfs4"] as! [String]) + [mixed]).joined(separator: "\n")
    }
    if fault == "invalid-saved-policy" || fault == "missing-saved-policy" { active.updateSelectionChanged(); check(active.killSwitchPopup.indexOfSelectedItem == -1, "Missing/invalid policy became Off") }
    active.save(); check(api.saved == nil, "Tor update adopted "+fault)
}
}
let owner = Owner(localCatalog), api = ProductAPI(localCatalog)
let newForm = Form(owner: owner, api: api, capabilities: caps); newForm.updateSelected.state = .off; newForm.transportPopup.indexOfSelectedItem = 2
newForm.bridgeText.string = (lines["snowflake"] as! [String]).joined(separator: "\n"); newForm.killSwitchPopup.indexOfSelectedItem = 2
newForm.save(); check(api.saved == nil, "Direct dynamic transport borrowed Router authority")
newForm.killSwitchPopup.indexOfSelectedItem = 0; newForm.save()
check(api.saved != nil && api.saved!["id"] == nil && api.saved!["expected_profile_tokens"] == nil && api.reads == 0, "Add borrowed captured update identity")
print("Swift actual Tor editor capture/callback: \(checks) checks PASS")
