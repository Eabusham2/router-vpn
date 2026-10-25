#!/usr/bin/env python3
"""Run each native external-node form and consume its real payload in Go.

GTK uses actual widgets/JsonBuilder under Xvfb. Windows executes the shipping
Save callback with non-network controller doubles. Swift executes the shipping
peer-field block and parameter parser with value-only field doubles; the normal
macOS build separately compiles the complete AppKit window.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def block(source, marker):
    start = source.index(marker)
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth and end < len(source):
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    if depth:
        raise AssertionError('Unclosed shipping form block: '+marker)
    return source[start:end]


def swift_form(directory):
    source = (ROOT/'client/macos/RouterVPNMacExternalNode.swift').read_text()
    helper = source[source.index('// Keep the provider'):source.index('extension ProductWindowController')]
    csv = block(source, 'private func externalCSV(')
    fields = block(source, 'if selected == "wireguard" || selected == "amneziawg"')
    proxy = source[source.index('        let user = username.stringValue'):source.index('        if selected == "wireguard" || selected == "amneziawg"')]
    extra = block(source, '        do {\n            let layer = ["off"')
    extra += ' catch { appendHelp(error.localizedDescription); return }'

    identity = block(source, '    func populateIdentityPopup(')
    unified = (ROOT/'client/macos/RouterVPNMacUnifiedShell.swift').read_text()
    start = unified.index('    private func startUnifiedSelectedMode() {')
    end = unified.index('        guard let popup = findUnifiedView("unified-mode-popup")', start)
    dispatch = unified[start:end] + '    }\n'
    dispatch = dispatch.replace('UserDefaults.standard', 'DispatchDefaults.standard')
    product = (ROOT/'client/macos/RouterVPNMacProduct.swift').read_text()
    for name in ('routerPopup', 'nodePopup', 'externalEntryPopup', 'multihopEntryPopup', 'multihopExitPopup'):
        assert 'self.populateIdentityPopup(self.'+name+', names: names, ids:' in product
        assert 'self.'+name+'.addItems(withTitles: names)' not in product
    test = r'''
import Foundation
HELPER
final class Field { var stringValue: String; init(_ value: String) { stringValue = value } }
final class Popup { var indexOfSelectedItem = 0 }
final class TextArea { var string = "" }
final class Form {
    var selected = "amneziawg"
    var result: [String: Any]?
    var message = ""
    let server = Field("203.0.113.60"); let expected = Field("203.0.113.60")
    let username = Field(""); let password = Field(""); let method = Field(""); let secret = Field(""); let tlsName = Field("")
    let responseURL = Field(""); let responseName = Field(""); let startLayer = Popup()
    let layerAPI = Field(""); let layerPort = Field(""); let layerKey = Field("")
    let openVPNConfig = TextArea(); let openVPNPairing = TextArea()
    let serverPeerPublic = Field(""); let serverPeerAddresses = Field(""); let serverPeerMTU = Field(""); let serverPeerKeepalive = Field("")
    let wgPrivate = Field(Data(repeating: 112, count: 32).base64EncodedString())
    let wgPeer = Field(Data(repeating: 113, count: 32).base64EncodedString())
    let wgPSK = Field("")
    let wgAddresses = Field("10.66.0.2/32, fd66::2/128")
    let wgAllowed = Field("0.0.0.0/0, ::/0")
    let wgDNS = Field("9.9.9.9")
    let wgMTU = Field("1280")
    let wgKeepalive = Field("17")
    let awgParameters = Field("Jc=3; Jmin=40; Jmax=900; S1=56; S2=48; S3=24; S4=32; H1=10000000-19999999; H2=20000000-29999999; H3=30000000-39999999; H4=40000000-49999999")
    CSV
    func appendHelp(_ text: String) { message = text }
    func save() {
        result = nil
        var body: [String: Any] = ["protocol": selected, "name": "Imported AWG fixture", "server": server.stringValue, "port": 51820, "expected_public_ip": expected.stringValue]
        PROXY
        FIELDS
        EXTRA
        result = body
    }
}
func check(_ value: Bool, _ message: String) { precondition(value, message) }
let form = Form()
let parameters = form.awgParameters.stringValue
form.save()
check(form.result != nil, form.message)
let first = form.result!
let awg = first["awg_parameters"] as! [String: String]
check(awg.count == 11 && awg["h4"] == "40000000-49999999" && awg["s4"] == "32", "Provider values changed")
check(first["wg_keepalive"] as? Int == 17 && first["wg_mtu"] as? Int == 1280, "Peer settings changed")
let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try JSONSerialization.data(withJSONObject: first, options: [.sortedKeys]).write(to: output.appendingPathComponent("amneziawg.json"))
var count = 1
for bad in ["", parameters+";JC=3", parameters.replacingOccurrences(of: "S4=32; ", with: ""), parameters+";unknown=4", parameters.replacingOccurrences(of: "H1=10000000-19999999", with: "H1=1--9"), parameters.replacingOccurrences(of: "S4=32", with: "S4=bad"), String(repeating: "Jc=3;", count: 1000)] {
    form.awgParameters.stringValue = bad; form.save()
    check(form.result == nil, "Malformed AWG fields reached the controller"); count += 1
}
form.awgParameters.stringValue = parameters
for bad in ["-1", "65536", "bad"] {
    form.wgKeepalive.stringValue = bad; form.save()
    check(form.result == nil, "Invalid keepalive reached the controller"); count += 1
}
form.wgKeepalive.stringValue = "17"
for bad in ["1279", "9001", "bad"] {
    form.wgMTU.stringValue = bad; form.save()
    check(form.result == nil, "Invalid MTU reached the controller"); count += 1
}
form.wgMTU.stringValue = "1280"; form.selected = "wireguard"; form.save()
check(form.result != nil && form.result!["awg_parameters"] == nil && form.result!["wg_keepalive"] as? Int == 17, "Ordinary WG became AWG")
try JSONSerialization.data(withJSONObject: form.result!, options: [.sortedKeys]).write(to: output.appendingPathComponent("wireguard.json"))
count += 1
let protocols = ["shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect"]
let layers = ["off", "aes-256-gcm", "aes-256-gcm+xor-whitening"]
let key = Data(repeating: 7, count: 32).base64EncodedString()
form.responseURL.stringValue = "https://203.0.113.60:8443/node-response"; form.responseName.stringValue = "external.example"
for protocolID in protocols {
    for (index, layer) in layers.enumerated() {
        form.selected = protocolID; form.startLayer.indexOfSelectedItem = index
        let proxy = ["socks5", "http-connect", "https-connect"].contains(protocolID)
        form.username.stringValue = proxy ? " user literal " : ""; form.password.stringValue = proxy ? " password literal " : ""
        form.method.stringValue = protocolID == "shadowsocks" ? "aes-256-gcm" : ""
        form.secret.stringValue = ["shadowsocks", "hysteria2"].contains(protocolID) ? " private proxy secret " : ""
        form.tlsName.stringValue = ["hysteria2", "https-connect"].contains(protocolID) ? "external.example" : ""
        form.layerAPI.stringValue = index == 0 ? "" : "http://10.77.0.1:8787"; form.layerPort.stringValue = index == 0 ? "" : "8389"; form.layerKey.stringValue = index == 0 ? "" : key
        form.save(); check(form.result != nil, form.message)
        let body = form.result!
        check(body["start_layer"] as? String == layer, "Selected external layer changed")
        let response = body["response_probe"] as! [String: String]
        check(response["url"] == form.responseURL.stringValue && response["server_name"] == "external.example", "Response endpoint changed")
        if proxy { check(body["username"] as? String == " user literal " && body["password"] as? String == " password literal ", "Proxy credential whitespace changed") }
        if index == 0 { check(body["start_layer_provision"] == nil, "Off retained private provision") }
        else {
            let provision = body["start_layer_provision"] as! [String: Any], transport = provision["transport"] as! [String: Any]
            check(provision["mode"] as? String == layer && transport["password"] as? String == key && transport["server"] as? String == "203.0.113.60", "Private provision ownership changed")
        }
        try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]).write(to: output.appendingPathComponent(protocolID+"-"+layer+".json")); count += 1
    }
}
for bad in ["", "0", "65536", "invalid"] {
    form.layerPort.stringValue = bad; form.save(); check(form.result == nil, "Invalid provisioned port accepted"); count += 1
}
form.layerPort.stringValue = "8389"; form.layerKey.stringValue = ""; form.save(); check(form.result == nil, "Missing key accepted"); count += 1
form.layerKey.stringValue = key; form.layerAPI.stringValue = ""; form.save(); check(form.result == nil, "Missing private API accepted"); count += 1
form.layerAPI.stringValue = "http://10.77.0.1:8787"; form.startLayer.indexOfSelectedItem = 0; form.save(); check(form.result == nil, "Off silently discarded private provision"); count += 1
form.layerAPI.stringValue = ""; form.layerPort.stringValue = ""; form.layerKey.stringValue = ""; form.selected = "wireguard"; form.save(); check(form.result != nil && form.result!["server_peer"] == nil, "Local WireGuard response probe incorrectly required a server peer"); count += 1
let serverPublic = "bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg="
form.serverPeerPublic.stringValue = serverPublic; form.serverPeerAddresses.stringValue = "10.66.0.3/32, fd66::3/128"; form.serverPeerMTU.stringValue = "1360"; form.serverPeerKeepalive.stringValue = "25"
for packet in ["wireguard", "amneziawg"] { for (index, layer) in layers.enumerated() {
    form.selected = packet; form.startLayer.indexOfSelectedItem = index
    form.layerAPI.stringValue = index == 0 ? "" : "http://10.77.0.1:8787"; form.layerPort.stringValue = index == 0 ? "" : "8389"; form.layerKey.stringValue = index == 0 ? "" : key
    form.save(); check(form.result != nil, form.message)
    let body = form.result!, peer = body["server_peer"] as! [String: Any]
    check(peer.count == 4 && peer["public_key"] as? String == serverPublic && peer["mtu"] as? Int == 1360 && peer["persistent_keepalive_interval"] as? Int == 25 && peer["addresses"] as? [String] == ["10.66.0.3/32", "fd66::3/128"], "Separate server peer descriptor changed")
    check(body["wg_private_key"] as? String == form.wgPrivate.stringValue && body["wg_peer_public_key"] as? String == form.wgPeer.stringValue && (body["wg_addresses"] as? [String])?.first == "10.66.0.2/32", "Server descriptor replaced the local private peer")
    try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]).write(to: output.appendingPathComponent(packet+"-"+layer+".json")); count += 1
} }
for (field, invalid) in [(form.serverPeerPublic, ""), (form.serverPeerPublic, "invalid"), (form.serverPeerAddresses, ""), (form.serverPeerMTU, ""), (form.serverPeerMTU, "1279"), (form.serverPeerMTU, "9001"), (form.serverPeerMTU, "bad"), (form.serverPeerKeepalive, "-1"), (form.serverPeerKeepalive, "65536")] {
    let previous = field.stringValue; field.stringValue = invalid; form.save(); check(form.result == nil, "Incomplete or invalid server descriptor reached controller"); field.stringValue = previous; count += 1
}
form.selected = "shadowsocks"; form.save(); check(form.result == nil, "Proxy accepted packet-only server descriptor"); count += 1
for field in [form.serverPeerPublic, form.serverPeerAddresses, form.serverPeerMTU, form.serverPeerKeepalive] { field.stringValue = "" }
form.startLayer.indexOfSelectedItem = 0; form.layerAPI.stringValue = ""; form.layerPort.stringValue = ""; form.layerKey.stringValue = ""
form.selected = "shadowsocks"; form.responseURL.stringValue = ""; form.save(); check(form.result == nil, "Partial response endpoint accepted"); count += 1

let openVPNFixtures = try JSONSerialization.jsonObject(with: Data(contentsOf: output.appendingPathComponent("external-openvpn-client.json"))) as! [String: Any]
let openVPNLayers = openVPNFixtures["layers"] as! [String: [String: Any]]
for (index, layer) in layers.enumerated() {
    let fixture = openVPNLayers[layer]!, external = fixture["external"] as! [String: Any], original = external["openvpn"] as! [String: Any]
    let probe = external["response_probe"] as! [String: String]
    form.selected = "openvpn"; form.server.stringValue = "203.0.113.20"; form.expected.stringValue = external["expected_public_ip"] as! String; form.openVPNConfig.string = original["config"] as! String
    form.openVPNPairing.string = String(decoding: try JSONSerialization.data(withJSONObject: external["openvpn_pairing"]!, options: [.sortedKeys, .prettyPrinted]), as: UTF8.self)
    form.username.stringValue = original["username"] as! String; form.password.stringValue = original["password"] as! String
    form.responseURL.stringValue = probe["url"]!; form.responseName.stringValue = probe["server_name"] ?? ""; form.startLayer.indexOfSelectedItem = index
    form.layerAPI.stringValue = ""; form.layerPort.stringValue = ""; form.layerKey.stringValue = ""
    if let provision = external["start_layer"] as? [String: Any], let transport = provision["transport"] as? [String: Any] {
        form.layerAPI.stringValue = provision["api"] as! String; form.layerPort.stringValue = String(transport["server_port"] as! Int); form.layerKey.stringValue = transport["password"] as! String
    }
    form.save(); check(form.result != nil, form.message)
    let body = form.result!, inline = body["openvpn"] as! [String: String]
    check(inline["config"] == form.openVPNConfig.string && inline["username"] == form.username.stringValue && inline["password"] == form.password.stringValue && body["openvpn_pairing_json"] as? String == form.openVPNPairing.string, "OpenVPN source or private pairing bytes changed")
    var capturedBody = body; capturedBody["server"] = "203.0.113.20"; capturedBody["expected_public_ip"] = external["expected_public_ip"]
    try JSONSerialization.data(withJSONObject: capturedBody, options: [.sortedKeys]).write(to: output.appendingPathComponent("openvpn-"+layer+".json")); count += 1
}
form.openVPNPairing.string = ""; form.openVPNConfig.string += "remote 203.0.113.21 443 tcp\n"; form.responseURL.stringValue = ""; form.responseName.stringValue = ""; form.startLayer.indexOfSelectedItem = 0; form.layerAPI.stringValue = ""; form.layerPort.stringValue = ""; form.layerKey.stringValue = ""
form.save(); check(form.result != nil && form.result!["openvpn_pairing_json"] == nil, "Plain Local multiremote incorrectly requires pairing")
try JSONSerialization.data(withJSONObject: form.result!, options: [.sortedKeys]).write(to: output.appendingPathComponent("openvpn-local-multiremote.json")); count += 1
form.selected = "shadowsocks"; form.save(); check(form.result == nil, "Changing protocol discarded private OpenVPN source"); count += 1
form.openVPNConfig.string = ""; form.selected = "openvpn"; form.save(); check(form.result == nil, "Empty OpenVPN source reached controller"); count += 1
form.openVPNPairing.string = ""; form.selected = "shadowsocks"
var profile: [String: Any] = ["id": "captured-exit", "node_kind": "external"]
check(try externalSavedExecution(profile) == "local", "Legacy external default is not Local"); count += 1
for choice in ["local", "server", "auto"] {
    profile["multihop_execution"] = choice
    check(try externalSavedExecution(profile) == choice, "Saved external execution changed")
    let body = try externalConnectBody(profile: profile, entryID: "captured-entry", execution: choice)
    check(body.count == 3 && body["profile_id"] as? String == "captured-exit" && body["entry_id"] as? String == "captured-entry" && body["execution"] as? String == choice, "Captured execution mixed unrelated state")
    let direct = try externalConnectBody(profile: profile, execution: choice, direct: true)
    check(direct["direct"] as? Bool == true && direct["execution"] as? String == "local" && direct["entry_id"] == nil, "Direct retained Server / Compare"); count += 1
}
func rejects(_ work: () throws -> Void) -> Bool { do { try work(); return false } catch { return true } }
check(rejects { _ = try externalConnectBody(profile: profile, entryID: "captured-exit", execution: "local") }, "Self-hop accepted"); count += 1
check(rejects { _ = try externalConnectBody(profile: profile, execution: "invalid") }, "Invalid execution accepted"); count += 1
profile["multihop_execution"] = "invalid"; check(rejects { _ = try externalSavedExecution(profile) }, "Invalid saved execution silently replaced"); count += 1
profile["node_kind"] = "router-vpn"; check(rejects { _ = try externalConnectBody(profile: profile, execution: "local") }, "Router selection became external"); count += 1
let upstream: [String: Any] = ["id": "entry", "node_kind": "router-vpn"]
var captured: [String: Any] = ["id": "exit", "node_kind": "external", "external": ["protocol": "wireguard", "has_response_probe": true, "has_server_peer": true]]
for transport in ["wireguard", "amneziawg", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect", "openvpn"] {
    captured["external"] = ["protocol": transport, "has_response_probe": true, "has_server_peer": ["wireguard", "amneziawg"].contains(transport), "has_openvpn_pairing": transport == "openvpn"]
    for choice in ["local", "server", "auto"] {
        let body = try externalPathConnectBody(captured: captured, entryID: "entry", execution: choice, direct: false, current: [captured, upstream])
        check(body["profile_id"] as? String == "exit" && body["entry_id"] as? String == "entry" && body["execution"] as? String == choice, "External path changed its captured identity"); count += 1
    }
}
var replacedPairing = captured
replacedPairing["external"] = ["protocol": "openvpn", "has_response_probe": true, "has_openvpn_pairing": false]
check(rejects { _ = try externalPathConnectBody(captured: captured, entryID: "entry", execution: "auto", direct: false, current: [replacedPairing, upstream]) }, "Stale OpenVPN pairing eligibility reached controller"); count += 1
captured["external"] = ["protocol": "wireguard", "has_response_probe": true, "has_server_peer": true]
for changed in ["removed", "duplicate", "protocol", "peer", "probe", "entry"] {
    var fresh = captured, catalog = [captured, upstream]
    if changed == "removed" { catalog = [upstream] }
    if changed == "duplicate" { catalog.append(captured) }
    if changed == "entry" { catalog = [captured] }
    if ["protocol", "peer", "probe"].contains(changed) {
        var ext = fresh["external"] as! [String: Any]
        if changed == "protocol" { ext["protocol"] = "amneziawg" }
        if changed == "peer" { ext["has_server_peer"] = false }
        if changed == "probe" { ext["has_response_probe"] = false }
        fresh["external"] = ext; catalog = [fresh, upstream]
    }
    check(rejects { _ = try externalPathConnectBody(captured: captured, entryID: "entry", execution: "server", direct: false, current: catalog) }, "Changed path identity accepted: "+changed); count += 1
}
for ext: [String: Any] in [["protocol": "wireguard", "has_response_probe": true, "has_server_peer": false], ["protocol": "amneziawg", "has_response_probe": false, "has_server_peer": true], ["protocol": "openvpn", "has_response_probe": true, "has_server_peer": true]] {
    captured["external"] = ext
    check(rejects { _ = try externalPathConnectBody(captured: captured, entryID: "entry", execution: "auto", direct: false, current: [captured, upstream]) }, "Unprovisioned or unsupported comparison became eligible"); count += 1
}

let capabilityData = try Data(contentsOf: output.appendingPathComponent("entry-mode-catalog.json"))
let capability = try JSONSerialization.jsonObject(with: capabilityData) as! [String: Any]
let entryModes = capability["router_vpn_entry_modes"] as! [[String: Any]]
var entryModeNode: [String: Any] = ["id": "entry", "node_kind": "router-vpn", "base_tunnel": "awg"]
captured = ["id": "exit", "node_kind": "external", "base_tunnel": "wg", "multihop_entry_mode": "wg", "external": ["protocol": "shadowsocks", "has_response_probe": true]]
for mode in entryModes { for choice in ["local", "server", "auto"] {
    let id = mode["id"] as! String
    let body = try externalPathConnectBody(captured: captured, entryID: "entry", execution: choice, direct: false, current: [captured, entryModeNode], entryMode: id, entryModes: entryModes)
    check(body["entry_mode"] as? String == id && body["profile_id"] as? String == "exit" && body["entry_id"] as? String == "entry" && body["execution"] as? String == choice, "Exact Router entry mode changed")
    try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]).write(to: output.appendingPathComponent("entry-mode-"+id+"-"+choice+".json")); count += 1
} }
check(try externalEntryMode(captured: captured, entry: entryModeNode, selected: "", modes: entryModes) == "awg2-fast", "Entry saved AWG base changed"); count += 1
entryModeNode["base_tunnel"] = "wg"; captured["base_tunnel"] = "awg"
check(try externalEntryMode(captured: captured, entry: entryModeNode, selected: "", modes: entryModes) == "wg", "Exit base overrode selected entry WG"); count += 1
for bad in ["all", "smart-auto", "custom", "auto", "unknown", " wg"] {
    check(rejects { _ = try externalPathConnectBody(captured: captured, entryID: "entry", execution: "local", direct: false, current: [captured, entryModeNode], entryMode: bad, entryModes: entryModes) }, "Unknown or uncompiled mode reached controller"); count += 1
}
let ordinary: [String: Any] = ["id": "ordinary", "node_kind": "external"]
check(rejects { _ = try externalPathConnectBody(captured: captured, entryID: "ordinary", execution: "local", direct: false, current: [captured, ordinary], entryMode: "wg", entryModes: entryModes) }, "External entry accepted a Router mode"); count += 1
check(rejects { _ = try externalPathConnectBody(captured: captured, entryID: "", execution: "local", direct: true, current: [captured], entryMode: "wg", entryModes: entryModes) }, "Direct accepted a Router mode"); count += 1
let directMode = try externalPathConnectBody(captured: captured, entryID: "", execution: "local", direct: true, current: [captured], entryMode: "", entryModes: entryModes)
check(directMode["entry_mode"] == nil, "Direct retained disabled Router mode"); count += 1
let ordinaryMode = try externalPathConnectBody(captured: captured, entryID: "ordinary", execution: "local", direct: false, current: [captured, ordinary], entryMode: "", entryModes: entryModes)
check(ordinaryMode["entry_mode"] == nil, "External entry retained disabled Router mode"); count += 1
var changedModeOwner = captured; changedModeOwner["multihop_entry_mode"] = "hysteria2"
check(rejects { _ = try externalPathConnectBody(captured: captured, entryID: "entry", execution: "local", direct: false, current: [changedModeOwner, entryModeNode], entryMode: "wg", entryModes: entryModes) }, "Changed saved entry mode owner accepted"); count += 1
final class NSMenuItem { let title: String; var representedObject: Any?; init(title: String, action: Any?, keyEquivalent: String) { self.title = title } }
final class NSMenu { var autoenablesItems = true; var items: [NSMenuItem] = []; func addItem(_ item: NSMenuItem) { items.append(item) } }
final class NSPopUpButton { var menu: NSMenu? }
IDENTITY
let menu = NSPopUpButton()
let names = ["Home", "Home", "Direct — no entry", "Direct — no entry"]
let ids = ["entry-one", "entry-two", "", "entry-three"]
populateIdentityPopup(menu, names: names, ids: ids)
check(menu.menu!.items.map(\.title) == names && menu.menu!.items.map({ $0.representedObject as! String }) == ids, "Duplicate titles changed node identity or Direct")
check(menu.menu!.autoenablesItems == false, "Identity entries were left to automatic menu validation"); count += 1
populateIdentityPopup(menu, names: names, ids: ["wrong-count"])
check(menu.menu!.items.isEmpty, "Partial catalog exposed misaligned private identities"); count += 1
@MainActor final class DispatchDefaults {
    static let standard = DispatchDefaults()
    var reads = 0
    func bool(forKey: String) -> Bool { reads += 1; return true }
}
final class DispatchAPI {
    var body: [String: Any]?; var path = ""
    func request(_ path: String, method: String, body: [String: Any], timeout: Double) throws -> Data {
        self.path = path; self.body = body; return Data("{}".utf8)
    }
}
@MainActor final class DispatchForm {
    let routerPopup = Popup(); var profiles: [[String: Any]] = []
    let api = DispatchAPI(); var pending: (() throws -> String)?
    let unifiedMultihopEnabledKey = "unrelated-router-choice"
    var routerConnections = 0; var idle = true; var error = ""
    func appendHelp(_ text: String) { error = text }
    func connectMultihop() { routerConnections += 1 }
    func requireMutationIdle(_ action: String) throws { if !idle { throw NSError(domain: "fixture", code: 409) } }
    func asyncAction(_ action: @escaping () throws -> String) { pending = action }
    DISPATCH
    func connect() { startUnifiedSelectedMode() }
}
for choice in ["local", "server", "auto"] {
    let dispatch = DispatchForm(); DispatchDefaults.standard.reads = 0
    dispatch.profiles = [["id": "captured-exit", "node_kind": "external", "multihop_execution": choice]]
    dispatch.connect()
    check(dispatch.pending != nil && dispatch.routerConnections == 0 && DispatchDefaults.standard.reads == 0, "Unrelated Router toggle bypassed external primary Connect")
    dispatch.profiles = [["id": "replacement", "node_kind": "router-vpn"]]
    _ = try dispatch.pending!()
    check(dispatch.api.path == "/api/external-profile/connect" && dispatch.api.body?["profile_id"] as? String == "captured-exit" && dispatch.api.body?["execution"] as? String == choice, "Asynchronous external dispatch changed its captured node/choice"); count += 1
}
let invalidDispatch = DispatchForm(); invalidDispatch.profiles = [["id": "captured-exit", "node_kind": "external", "multihop_execution": "invalid"]]; invalidDispatch.connect()
check(invalidDispatch.pending == nil && invalidDispatch.routerConnections == 0, "Invalid external execution fell through to Router Connect"); count += 1
let staleDispatch = DispatchForm(); staleDispatch.profiles = [["id": "captured-exit", "node_kind": "external", "multihop_execution": "server"]]; staleDispatch.connect(); staleDispatch.idle = false
check(rejects { _ = try staleDispatch.pending!() } && staleDispatch.api.body == nil, "Changed VPN owner accepted a queued external Connect"); count += 1
let routerDispatch = DispatchForm(); routerDispatch.profiles = [["id": "router", "node_kind": "router-vpn"]]; routerDispatch.connect()
check(routerDispatch.routerConnections == 1 && routerDispatch.pending == nil, "Router multihop control was removed by external priority"); count += 1
for (index, profiles) in [(-1, [["id": "captured-exit", "node_kind": "external"]]), (1, [["id": "captured-exit", "node_kind": "external"]]), (0, []), (0, [["id": "", "node_kind": "external"]]), (0, [["id": "bad", "node_kind": "unknown"]])] {
    let missing = DispatchForm(); missing.routerPopup.indexOfSelectedItem = index; missing.profiles = profiles; DispatchDefaults.standard.reads = 0; missing.connect()
    check(missing.pending == nil && missing.routerConnections == 0 && DispatchDefaults.standard.reads == 0 && !missing.error.isEmpty, "Unknown selected identity fell through to unrelated Router controls"); count += 1
}
print("PASS shipping Swift external serialization, node identity and captured dispatch: \(count) cases")
'''.replace('HELPER', helper).replace('CSV', csv).replace('FIELDS', fields).replace('PROXY', proxy).replace('EXTRA', extra).replace('IDENTITY', identity).replace('DISPATCH', dispatch)
    path = directory/'main.swift'
    path.write_text(test)
    binary = directory/'swift-form'
    subprocess.run(['swiftc', '-swift-version', '6', str(path), '-o', str(binary)], check=True, timeout=120)
    subprocess.run([str(binary), str(directory)], check=True, timeout=30)


def linux_form(directory):
    flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'gtk+-3.0', 'json-glib-1.0'], text=True).split()
    binary = directory/'gtk-form'
    product = (ROOT/'client/linux/routervpn-gtk-product-v4.c').read_text()
    helpers = block(product, 'static const char *external_saved_execution_v4(') + '\n' + block(product, 'static char *json_external_hop_body(')
    for marker in ('static const char *external_path_string_v4(', 'static gboolean external_path_flag_v4(', 'static JsonObject *external_path_object_v4(', 'static char *external_path_current_body_v4(', 'static char *external_entry_mode_v4(', 'static char *external_path_mode_body_v4('):
        helpers += '\n' + block(product, marker)
    unified = (ROOT/'client/linux/routervpn-unified-shell-v8.inc').read_text()
    helpers += '\n' + block(unified, 'static int linux_unified_selected_external_v8(') + '\n' + block(unified, 'static void linux_unified_connect_v8(')
    fixture = (ROOT/'client/linux/test-external-amnezia.c').read_text()
    assert fixture.count('// EXTERNAL_PATH_TEST_HELPERS') == 1
    compiled = directory/'gtk-form.c'
    compiled.write_text(fixture.replace('// EXTERNAL_PATH_TEST_HELPERS', helpers))
    subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-I'+str(ROOT/'client/linux'), str(compiled), '-o', str(binary), *flags], check=True, timeout=120)
    subprocess.run(['xvfb-run', '-a', str(binary), str(directory)], check=True, timeout=60)


def windows_form(directory, shell):
    subprocess.run([shell, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                    str(ROOT/'client/test-windows-external-amnezia.ps1'), '-Root', str(ROOT),
                    '-Output', str(directory)], check=True, timeout=60)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=['linux', 'darwin', 'windows'], default='windows' if sys.platform == 'win32' else sys.platform)
    args = parser.parse_args()
    shells = [None]
    if args.platform == 'windows':
        shells = [shell for shell in ('pwsh', 'powershell.exe') if shutil.which(shell)]
        if not shells:
            raise SystemExit('PowerShell is required to execute the actual Save callback')
    for shell in shells:
        with tempfile.TemporaryDirectory(prefix='router-vpn-amnezia-form-') as temporary:
            directory = Path(temporary)
            shutil.copyfile(ROOT/'deploy/fixtures/external-openvpn-client.json', directory/'external-openvpn-client.json')
            env = dict(os.environ, ROUTERVPN_AWG_FORM_PAYLOADS=str(directory), ROUTERVPN_EXTERNAL_FORM_PAYLOADS=str(directory))
            subprocess.run(['go', 'test', '-count=1', './cmd/client', '-run', '^TestDesktopExternalEntryModeFormCatalog$'], cwd=ROOT, env=env, check=True, timeout=180)
            if args.platform == 'linux':
                linux_form(directory)
            elif args.platform == 'darwin':
                swift_form(directory)
            else:
                windows_form(directory, shell)
            env = dict(os.environ, ROUTERVPN_AWG_FORM_PAYLOADS=str(directory), ROUTERVPN_EXTERNAL_FORM_PAYLOADS=str(directory))
            subprocess.run(['go', 'test', '-race', '-count=1', './cmd/client', '-run', '^TestDesktop(Amnezia|ExternalProxy|ExternalPacket|ExternalEntryMode|ExternalOpenVPN)FormPayload$'], cwd=ROOT, env=env, check=True, timeout=180)
    print('Verified native '+args.platform+' forms to exact Go AWG/WG profiles and authenticated proxy/layer runtime graphs', flush=True)


if __name__ == '__main__':
    main()
