#!/usr/bin/env python3
"""Run shipping app strategy/IPC against the shipping provider coordinator.

NetworkExtension, native transport starts and DNS/node traffic are boundary
doubles. Policy, app async ownership, IPC parsing, selection and provider state
transitions are production Swift; no physical-device behavior is claimed.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
PROVIDER = ROOT / 'ios/RouterVPN/PacketTunnel'
spec = importlib.util.spec_from_file_location('max_app_readiness', ROOT / 'deploy/test_ios_max_hostname.py')
MAX = importlib.util.module_from_spec(spec); spec.loader.exec_module(MAX)
SHIM = r'''
import Foundation

// Only the CryptoKit boundary is replaced on this offline fixture. Its digest
// remains deterministic and input-sensitive; production always uses SHA-256.
enum SHA256 {
    static func hash(data: Data) -> [UInt8] {
        var h: UInt64 = 14695981039346656037
        for byte in data { h = (h ^ UInt64(byte)) &* 1099511628211 }
        return (0..<32).map { UInt8(truncatingIfNeeded: h >> (($0 % 8) * 8)) }
    }
}
final class RuntimeTrace: @unchecked Sendable {
    static let shared = RuntimeTrace()
    private let lock = NSLock()
    private var values: [String] = [], failures: [String: Int] = [:]
    private var paused = false, noDNS = false, live = false
    func reset() { lock.withLock { values = []; failures = [:]; paused = false; noDNS = false; live = false } }
    func fail(_ raw: String, count: Int = 1) { lock.withLock { failures[raw] = count } }
    func pause(_ value: Bool) { lock.withLock { paused = value } }
    func dns(_ value: Bool) { lock.withLock { noDNS = !value } }
    func vpn(_ value: Bool) { lock.withLock { live = value } }
    var attempts: [String] { lock.withLock { values } }
    var isLive: Bool { lock.withLock { live } }
    func attempt(_ raw: String) -> (Bool, Bool, Bool) { lock.withLock {
        values.append(raw); let fail = (failures[raw] ?? 0) != 0
        if let count = failures[raw], count > 0 { failures[raw] = count - 1 }
        return (paused, fail, !noDNS)
    } }
}
final class TestDriver: RouterVPNStrategyDriver, @unchecked Sendable {
    let node: String
    init(node: String) { self.node = node }
    func replace(_ attempt: RouterVPNStrategyAttempt, proving: @escaping @Sendable () -> Void,
                 completion: @escaping @Sendable (Result<RouterVPNStrategyProof, Error>) -> Void) {
        let behavior = RuntimeTrace.shared.attempt(attempt.candidate.raw)
        if behavior.0 { return }
        proving()
        if behavior.1 { completion(.failure(IOSStrategyWire.failure("fixture transport failure"))) }
        else { completion(.success(RouterVPNStrategyProof(nodeID: node, dns: behavior.2))) }
    }
    func activate(_ attempt: RouterVPNStrategyAttempt, completion: @escaping @Sendable (Error?) -> Void) { completion(nil) }
    func protect(epoch: String) {}
}
enum NEVPNStatus { case invalid, disconnected, connecting, connected, reasserting, disconnecting }
@MainActor class NEVPNConnection {
    var status: NEVPNStatus = .disconnected
    var connectedDate: Date?
    func startVPNTunnel(options: [String: NSObject]? = nil) throws {}
    func stopVPNTunnel() {}
}
@MainActor final class NETunnelProviderProtocol {
    var providerBundleIdentifier: String?, serverAddress: String?
    var providerConfiguration: [String: Any]?
    var includeAllNetworks = false, enforceRoutes = false, excludeLocalNetworks = false
    var excludeAPNs = true, excludeCellularServices = true
}
@MainActor final class NEOnDemandRuleConnect {}
@MainActor final class NETunnelProviderSession: NEVPNConnection {
    weak var manager: NETunnelProviderManager?
    var owner: RouterVPNProviderStrategy?
    var starts = 0, stops = 0, messages = 0
    var corruptStatus = false
    override func startVPNTunnel(options: [String: NSObject]?) throws {
        if let c = (manager?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
           ["external-libbox", "multihop-libbox"].contains(c["engine"] as? String ?? "") {
            starts += 1; status = .connected; connectedDate = Date(); RuntimeTrace.shared.vpn(true)
            return
        }
        guard let c = (manager?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
              let data = c["bundle"] as? Data, let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let profiles = root["routerProfiles"] as? [[String: Any]], let profile = profiles.first,
              let catalog = c["strategy_catalog"] as? [String: Any], let plan = c["strategy"] as? [String: Any] else {
            throw IOSStrategyWire.failure("missing captured strategy")
        }
        let policy = try RouterVPNStrategyPolicy(catalog: catalog, root: root, profile: profile)
        owner = try RouterVPNProviderStrategy(policy: policy, plan: policy.plan(plan, initial: true),
            bundleDigest: RouterVPNModel.iosStrategyDigest(data), nodeID: root["nodeProofId"] as! String,
            driver: TestDriver(node: root["nodeProofId"] as! String))
        starts += 1; status = .connected; connectedDate = Date(); RuntimeTrace.shared.vpn(true)
        owner!.start()
    }
    override func stopVPNTunnel() { stops += 1; owner?.stop(); status = .disconnected; RuntimeTrace.shared.vpn(false) }
    func sendProviderMessage(_ data: Data, responseHandler: @escaping @Sendable (Data?) -> Void) throws {
        messages += 1
        guard !corruptStatus else { responseHandler(Data("{}".utf8)); return }
        responseHandler(owner?.handle(data))
    }
}
@MainActor final class NETunnelProviderManager {
    static var stored: [NETunnelProviderManager] = []
    static var saveHook: (@MainActor () async -> Void)?
    static var failLoad = false
    var protocolConfiguration: Any?
    var localizedDescription: String?
    var isEnabled = false, isOnDemandEnabled = false
    var onDemandRules: [NEOnDemandRuleConnect]?
    var saves = 0, reads = 0
    let connection: NEVPNConnection
    init() { let session = NETunnelProviderSession(); connection = session; session.manager = self }
    static func loadAllFromPreferences() async throws -> [NETunnelProviderManager] {
        await Task.yield(); if failLoad { throw IOSStrategyWire.failure("fixture preferences unavailable") }; return stored
    }
    func saveToPreferences() async throws {
        saves += 1; if !Self.stored.contains(where: { $0 === self }) { Self.stored.append(self) }
        let hook = Self.saveHook; Self.saveHook = nil; await hook?(); await Task.yield()
    }
    func loadFromPreferences() async throws { reads += 1; await Task.yield() }
}
enum IOSDNSRuntimePolicy {
    static func selectedProfile(in bundle: ClientBundle) -> RouterProfile? {
        let values = bundle.routerProfiles.filter { $0.id == bundle.selectedRouterID }; return values.count == 1 ? values[0] : nil
    }
    static func patch(_ value: ClientBundle) throws -> ClientBundle { value }
}
enum IOSRuntimeSelector {
    static func normalizedStartLayer(in b: ClientBundle) throws -> String { IOSDNSRuntimePolicy.selectedProfile(in: b)?.startLayer ?? "off" }
    static func selectRaw(bundle: ClientBundle, rawProfileID: String) throws -> IOSRuntimeSelection {
        guard let files = bundle.profiles[rawProfileID], !files.isEmpty,
              let logical = bundle.logicalModes.first(where: { $0.variants.values.contains(rawProfileID) }) else { throw IOSStrategyWire.failure("missing raw fixture") }
        return IOSRuntimeSelection(engine: .libbox, logicalModeID: logical.id, rawProfileID: rawProfileID,
            files: try files.mapValues { guard let data = Data(base64Encoded: $0) else { throw IOSStrategyWire.failure("invalid fixture") }; return data })
    }
    static func candidates(bundle: ClientBundle, logicalModeID: String) throws -> [IOSRuntimeSelection] {
        guard let mode = bundle.logicalModes.first(where: { $0.id == logicalModeID }) else { throw IOSStrategyWire.failure("missing logical fixture") }
        var seen = Set<String>()
        return ["native", "wg", "awg"].compactMap { mode.variants[$0] }.filter { seen.insert($0).inserted }.compactMap { try? selectRaw(bundle: bundle, rawProfileID: $0) }
    }
    static func runnableModes(in bundle: ClientBundle) -> [LogicalMode] { bundle.logicalModes }
    static func selectMultihop(bundle: ClientBundle, rawProfileID: String?) throws -> IOSRuntimeSelection {
        guard let raw = rawProfileID, IOSNativeMAXProfile.modeIDs.contains(raw) else { throw IOSStrategyWire.failure("separate multihop fixture") }
        let selected = try selectRaw(bundle: bundle, rawProfileID: raw)
        return IOSRuntimeSelection(engine: .multihop, logicalModeID: selected.logicalModeID, rawProfileID: raw, files: selected.files)
    }
}
enum IOSRuntimeSelectionError: LocalizedError {
    case unsupportedMode(String), invalidSingBoxConfig
    var errorDescription: String? { switch self { case .unsupportedMode(let m): return m; case .invalidSingBoxConfig: return "invalid graph" } }
}
@MainActor enum IOSMTUMeasurementGate { static var current = "" }
@MainActor enum IOSMTUControl {
    static func withHold<T>(model: RouterVPNModel, operation: @MainActor () async throws -> T) async throws -> T { try await operation() }
}
@MainActor final class FixturePreferences {
    static let standard = FixturePreferences()
    var values: [String: Data] = [:]
    func data(forKey key: String) -> Data? { values[key] }
    func set(_ data: Data, forKey key: String) { values[key] = data }
}
func LibboxRouterResolveXrayProfile(_ mode: String, _ wrapper: String, _ original: String, _ error: inout NSError?) -> String? {
    precondition(!RuntimeTrace.shared.isLive, "ambient host resolver used after VPN startup")
    return try! String(decoding: JSONEncoder().encode(["sing-box.json": Data(wrapper.utf8), "xray.json": Data(original.utf8)]), as: UTF8.self)
}
func LibboxRouterResolveXrayStartLayerProfile(_ mode: String, _ wrapper: String, _ original: String, _ aes: String, _ policy: String, _ error: inout NSError?) -> String? {
    precondition(!RuntimeTrace.shared.isLive, "ambient Start Layer resolver used after VPN startup")
    return try! String(decoding: JSONEncoder().encode(["sing-box.json": Data(wrapper.utf8), "xray.json": Data(original.utf8), "start-layer-source.json": Data(aes.utf8)]), as: UTF8.self)
}
func LibboxRouterCheckMAXProfile(_ mode: String, _ files: String, _ metadata: String, _ error: inout NSError?) -> String? {
    do { return try bridge(["Op": "max-check", "Mode": mode, "Files": files, "Policy": metadata]) }
    catch let failure as NSError { error = failure; return nil }
}
@MainActor final class RouterVPNModel {
    var bundle: ClientBundle?
    var entryBundle: ClientBundle?
    var connected = false, tunnelTransitioning = false, auto = true, baseFallback = false, homeLANAccess = false
    var activeEngine = "none", activeRawProfile = "", selectedLogicalMode = "base-raw", selectedMode = "wg", message = "", routerName = "Home"
    var activeSessionIdentity: IOSSessionIdentity?
    var iosStrategyStatus: IOSStrategyStatus?
    var iosConnectGeneration = UUID(), multihopProgressGeneration = UUID()
    var multihopProgressText = ""
    var iosStrategyTaskActive = false, userDisconnectInProgress = false
    var iosUserDisconnectInProgress: Bool { userDisconnectInProgress }
    var profileMutationBlocked: Bool { connected || tunnelTransitioning || userDisconnectInProgress }
    var selectedRouterProfile: RouterProfile? { bundle.flatMap { IOSDNSRuntimePolicy.selectedProfile(in: $0) } }
    var selectedNodeProfile: RouterProfile? { selectedRouterProfile }
    var modes: [VPNMode] { bundle?.modes ?? [] }
    var logicalModes: [LogicalMode] { bundle?.logicalModes ?? [] }
    var strictKillSwitchEnabled: Bool { selectedRouterProfile?.killSwitch == true }
    func saveRouter() -> Bool { bundle != nil }
    func importBundle(_ data: Data) throws { bundle = try JSONDecoder().decode(ClientBundle.self, from: data) }
    func iosMultihopEntryBundle(for bundle: ClientBundle) throws -> ClientBundle {
        guard let entryBundle else { throw IOSStrategyWire.failure("separate multihop fixture") }; return entryBundle
    }
    func drainDisconnect() async { while userDisconnectInProgress { await Task.yield() } }
    // SHIPPING_MODEL_METHODS
}
'''
TEST = r'''
func fixture() throws -> ClientBundle {
    let fields: [String: Any] = ["id": "home", "name": "Home", "node_kind": "router-vpn", "node_proof_id": String(repeating: "a", count: 64),
        "endpoint": "192.0.2.1", "router_api": "http://10.77.0.1:8787", "api_token": "fixture-only",
        "adguard_ipv4": "10.77.0.1", "adguard_ipv6": "fd77:77::1", "socks_host": "10.77.0.1", "socks_port": 1080,
        "socks_username": "", "socks_password": "", "base_tunnel": "auto", "base_fallback": true,
        "kill_switch": true, "home_lan_access": false, "custom_layers": ["wireguard"]]
    var value = ClientBundle.empty
    value.selectedRouterID = "home"; value.nodeProofID = String(repeating: "a", count: 64); value.endpoint = "192.0.2.1"
    value.routerProfiles = [try JSONDecoder().decode(RouterProfile.self, from: JSONSerialization.data(withJSONObject: fields))]
    value.logicalModes = [LogicalMode(id: "base-raw", name: "Raw", description: "", baseSelector: true, fallback: true, variants: ["wg": "wg", "awg": "awg2-fast"])]
    let raw = "[Interface]\nPrivateKey=fixture\n[Peer]\nPublicKey=fixture\n"
    value.profiles = ["wg": ["wg.conf": Data(raw.utf8).base64EncodedString()], "awg2-fast": ["awg.conf": Data(raw.utf8).base64EncodedString()]]
    for id in ["wg", "awg2-fast"] {
        let mode: [String: Any] = ["id": id, "name": id, "protection": "fixture", "ping_min_ms": 1, "ping_max_ms": 2,
            "traffic_min_pct": 1, "traffic_max_pct": 2, "speed_loss_min_pct": 1, "speed_loss_max_pct": 2]
        value.modes.append(try JSONDecoder().decode(VPNMode.self, from: JSONSerialization.data(withJSONObject: mode)))
    }
    return value
}
func externalFixture() throws -> ClientBundle {
    var value = try fixture()
    value.routerProfiles[0].nodeKind = "external"
    let fields: [String: Any] = ["protocol": "socks5", "expected_public_ip": "8.8.8.8",
        "socks5": ["host": "192.0.2.9", "port": 1080, "username": "fixture", "password": "fixture-secret"]]
    value.routerProfiles[0].external = try JSONDecoder().decode(ExternalNodeConfig.self, from: JSONSerialization.data(withJSONObject: fields))
    return value
}
func maxAppFixture(_ mode: String, role: String? = nil) throws -> ClientBundle {
    var value = try fixture()
    let values = try object(Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[role == nil ? 2 : 3])))
    let fixtures = role.map { values[$0] as! [String: Any] } ?? values
    let fixture = fixtures[mode] as! [String: Any], policy = fixture["policy"] as! [String: String]
    var files = fixture["files"] as! [String: String]
    let name = mode.hasPrefix("max-tls-") ? "outer-xray.json" : "middle-sing-box.json"
    var root = try object(Data(base64Encoded: files[name]!)!), out = root["outbounds"] as! [[String: Any]]
    if mode.hasPrefix("max-tls-") {
        var settings = out[0]["settings"] as! [String: Any], remote = settings["vnext"] as! [[String: Any]]
        remote[0]["address"] = "Captured-MAX.example"; settings["vnext"] = remote; out[0]["settings"] = settings
    } else { let index = out.firstIndex { $0["tag"] as? String == "outer" }!; out[index]["server"] = "Captured-MAX.example" }
    root["outbounds"] = out; files[name] = try json(root).base64EncodedString()
    value.profiles = [mode: files]; value.nodeProofID = policy["node_id"]!; value.endpoint = "Captured-MAX.example"
    value.routerProfiles[0].nodeProofID = value.nodeProofID; value.routerProfiles[0].endpoint = value.endpoint
    value.routerProfiles[0].routerAPI = policy["router_api"]!; value.routerProfiles[0].startLayer = "aes-256-gcm"
    let family = mode.hasPrefix("max-tls-") ? "max-tls" : "max-quic"
    value.logicalModes = [LogicalMode(id: family, name: family, description: "", baseSelector: true, fallback: true,
                                      variants: [mode.hasSuffix("-awg") ? "awg" : "wg": mode])]
    let descriptor: [String: Any] = ["id": mode, "name": mode, "protection": "fixture", "ping_min_ms": 1, "ping_max_ms": 2,
        "traffic_min_pct": 1, "traffic_max_pct": 2, "speed_loss_min_pct": 1, "speed_loss_max_pct": 2]
    value.modes = [try JSONDecoder().decode(VPNMode.self, from: json(descriptor))]
    return value
}
@main struct Tests {
    @MainActor static func main() async throws {
        defer { TestCompiler.shared.close() }
        var checks = 0
        func check(_ label: String, _ value: @autoclosure () -> Bool) {
            guard value() else {
                // A negative control must fail with its exact assertion even
                // where the Swift crash reporter cannot inspect peer threads.
                FileHandle.standardError.write(Data(("FAIL: " + label + "\n").utf8))
                exit(1)
            }
            checks += 1
        }
        func fresh() throws -> RouterVPNModel {
            RuntimeTrace.shared.reset(); NETunnelProviderManager.stored = []; NETunnelProviderManager.saveHook = nil
            NETunnelProviderManager.failLoad = false
            let value = RouterVPNModel(); value.bundle = try fixture(); return value
        }
        var model = try fresh(); RuntimeTrace.shared.fail("wg")
        await model.connect()
        check("AUTO tries both inside one provider", RuntimeTrace.shared.attempts == ["wg", "awg2-fast"])
        check("AUTO adopts proven candidate only", model.connected && model.activeRawProfile == "awg2-fast" && model.activeSessionIdentity?.runtimeEpoch != nil)
        let manager = NETunnelProviderManager.stored[0], session = manager.connection as! NETunnelProviderSession
        let proto = manager.protocolConfiguration as! NETunnelProviderProtocol
        check("strict routes and on-demand retained", proto.includeAllNetworks && proto.enforceRoutes && manager.isOnDemandEnabled && !proto.excludeLocalNetworks)
        check("single VPN start with no trial stop", session.starts == 1 && session.stops == 0)
        let old = model.activeSessionIdentity, saves = manager.saves
        RuntimeTrace.shared.fail("wg")
        await model.runIOSSmartAuto()
        check("SMART failed reduction restores last good", model.connected && model.activeRawProfile == "awg2-fast")
        check("same mode fresh runtime invalidates measurement", model.activeSessionIdentity != old)
        check("SMART did not stop or rewrite VPN", session.starts == 1 && session.stops == 0 && manager.saves == saves && manager.isOnDemandEnabled)
        await model.runIOSSmartAuto()
        check("SMART simplification can retain WG", model.connected && model.activeRawProfile == "wg")
        await model.runIOSCustom(layers: ["wireguard"])
        check("CUSTOM uses captured policy in same session", model.connected && model.activeRawProfile == "wg" && session.starts == 1 && session.stops == 0)
        let before = RuntimeTrace.shared.attempts.count
        await model.runIOSCustom(layers: ["amneziawg2"])
        check("new policy cannot mutate active frozen session", RuntimeTrace.shared.attempts.count == before && model.message.contains("captured policy"))
        session.corruptStatus = true; await model.refreshTunnelStatus()
        check("invalid reply is not Connected", !model.connected && model.activeSessionIdentity == nil && model.tunnelTransitioning)
        session.corruptStatus = false; await model.refreshTunnelStatus()
        check("fresh exact status recovers identity", model.connected && model.activeSessionIdentity != nil)
        model.disconnect(); await model.drainDisconnect()
        check("explicit Disconnect stops and disables on-demand", session.stops == 1 && !manager.isOnDemandEnabled && !model.profileMutationBlocked)

        model = try fresh(); RuntimeTrace.shared.dns(false)
        await model.connect()
        check("node proof alone cannot connect", !model.connected && model.activeSessionIdentity == nil && model.iosStrategyStatus?.phase == .blocked)
        check("failed strategy retains protected hold", model.tunnelTransitioning && NETunnelProviderManager.stored[0].isOnDemandEnabled)
        model.disconnect(); await model.drainDisconnect()
        check("blocked strategy remains disconnectable", !model.profileMutationBlocked)

        model = try fresh(); RuntimeTrace.shared.pause(true)
        let pending = model
        let operation = Task { await pending.connect() }
        for _ in 0..<200 where RuntimeTrace.shared.attempts.isEmpty { await Task.yield() }
        check("system Connected is not app Connected before proof", !model.connected && model.activeSessionIdentity == nil)
        let preparing = model.iosConnectGeneration
        model.disconnect(); await model.drainDisconnect(); await operation.value
        check("cancel revokes pending generation", model.iosConnectGeneration != preparing && !model.connected && !model.profileMutationBlocked)

        model = try fresh(); let duringSave = model
        NETunnelProviderManager.saveHook = { duringSave.disconnect(); await duringSave.drainDisconnect() }
        await model.connect(); await model.drainDisconnect()
        check("cancel during preference save cannot start later", (NETunnelProviderManager.stored[0].connection as! NETunnelProviderSession).starts == 0 && !model.connected)
        model = try fresh(); let changed = model
        NETunnelProviderManager.saveHook = { changed.bundle?.routerProfiles[0].apiToken = "changed fixture" }
        await model.connect()
        check("changed source before preference readback prevents start", (NETunnelProviderManager.stored[0].connection as! NETunnelProviderSession).starts == 0)
        model = try fresh(); model.bundle?.routerProfiles[0].multihopEnabled = true
        NETunnelProviderManager.failLoad = true
        await model.connect()
        check("unknown multihop status keeps settings locked", !model.connected && model.activeSessionIdentity == nil && model.profileMutationBlocked)

        model = try fresh(); model.bundle = try externalFixture()
        await model.connectSelectedExternal()
        check("external startup obtains exact session identity", model.connected && model.activeSessionIdentity?.engine == "external-libbox")
        let externalManager = NETunnelProviderManager.stored[0], externalSession = externalManager.connection as! NETunnelProviderSession
        model.disconnect(); await model.drainDisconnect()
        check("external explicit Disconnect keeps verified ownership", externalSession.stops == 1 && !externalManager.isOnDemandEnabled && !model.profileMutationBlocked)
        model = try fresh(); model.bundle = try externalFixture(); let externalCancelled = model
        NETunnelProviderManager.saveHook = { externalCancelled.disconnect(); await externalCancelled.drainDisconnect() }
        await model.connectSelectedExternal()
        check("cancel during external save cannot start later", (NETunnelProviderManager.stored[0].connection as! NETunnelProviderSession).starts == 0 && !model.connected)
        model = try fresh(); model.bundle = try externalFixture(); let externalChanged = model
        NETunnelProviderManager.saveHook = { externalChanged.bundle?.routerProfiles[0].external?.expectedPublicIP = "9.9.9.9" }
        await model.connectSelectedExternal()
        check("external captured source cannot change during save", (NETunnelProviderManager.stored[0].connection as! NETunnelProviderSession).starts == 0)
        model = try fresh(); model.bundle = try externalFixture(); NETunnelProviderManager.failLoad = true
        await model.connectSelectedExternal()
        check("unknown external status keeps settings locked", !model.connected && model.profileMutationBlocked)
        model = try fresh(); model.bundle = try externalFixture(); model.bundle?.selectedRouterID = "missing"
        await model.connectSelectedExternal()
        check("missing external selection cannot use first profile", NETunnelProviderManager.stored.isEmpty)
        model = try fresh(); var duplicate = try externalFixture()
        duplicate.routerProfiles.append(duplicate.routerProfiles[0]); model.bundle = duplicate
        await model.connectSelectedExternal()
        check("duplicate external selection cannot choose another owner", NETunnelProviderManager.stored.isEmpty)
        for change in ["stable", "entry-policy", "entry-assets", "entry-id", "slot"] {
            model = try fresh(); model.bundle = try externalFixture()
            var entry = try fixture(); entry.selectedRouterID="entry"; entry.routerProfiles[0].id="entry"
            model.entryBundle=entry
            model.bundle?.routerProfiles[0].multihopEnabled=true
            model.bundle?.routerProfiles[0].multihopEntryID="entry"
            model.bundle?.routerProfiles[0].multihopEntryMode="wg"
            model.bundle?.routerProfiles[0].multihopExitID="home"
            model.bundle?.routerProfiles[0].multihopExitMode="socks5"
            model.bundle?.routerProfiles[0].multihopExecution="local"
            let changing=model
            NETunnelProviderManager.saveHook = {
                if change=="entry-policy" { changing.entryBundle?.routerProfiles[0].homeLANAccess=true }
                if change=="entry-assets" { changing.entryBundle?.profiles["wg"]?["wg.conf"]=Data("different private transport".utf8).base64EncodedString() }
                if change=="entry-id" { changing.entryBundle?.selectedRouterID="missing" }
                if change=="slot" { (NETunnelProviderManager.stored[0].protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["tor_entry_bundle"]=Data("foreign owner".utf8) }
            }
            await model.connectSelectedExternal()
            let manager=NETunnelProviderManager.stored[0],session=manager.connection as! NETunnelProviderSession
            if change=="stable" {
                let config=(manager.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
                let captured=try JSONDecoder().decode(ClientBundle.self,from:config["external_entry_bundle"] as! Data)
                check("ordinary external app captures exact complete entry",model.connected && captured.routerProfiles==entry.routerProfiles && captured.profiles==entry.profiles && config["external_entry_mode"] as? String=="wg")
                check("ordinary external app cannot retain a Tor owner",config["tor_entry_bundle"]==nil && config["tor_entry_mode"]==nil)
                let identity=model.activeSessionIdentity
                check("external status binds complete captured predecessor",identity?.entryBundleData==config["external_entry_bundle"] as? Data && identity?.entryMode=="wg")
                let proto=manager.protocolConfiguration as! NETunnelProviderProtocol
                proto.providerConfiguration?["external_entry_bundle"]=Data("replacement-entry-owner".utf8)
                await model.refreshTunnelStatus()
                check("same-label external predecessor change invalidates measurement identity",model.activeSessionIdentity != identity)
                proto.providerConfiguration?["tor_entry_bundle"]=Data("ambiguous-owner".utf8)
                await model.refreshTunnelStatus()
                check("mixed external predecessor status is unverified",model.activeSessionIdentity==nil && model.profileMutationBlocked)
            } else {check("changed external entry cannot start after preference save",session.starts==0 && !model.connected)}
        }
        for raw in IOSNativeMAXProfile.modeIDs.sorted() {
            model = try fresh(); let captured = try maxAppFixture(raw); model.bundle = captured
            await model.connect(rawProfileID: raw)
            check("MAX candidate reaches same owned provider", model.connected && model.activeRawProfile == raw)
            let manager = NETunnelProviderManager.stored[0], session = manager.connection as! NETunnelProviderSession
            let configuration = (manager.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
            let hashes = try IOSMAXSourceSelection.sourceHashes(provider: configuration) { try bridge(["Op": "max-check", "Mode": $0, "Files": $1, "Policy": $2]) }
            check("MAX app carries real no-DNS source hash", configuration["max_source_sha256"] as? [String: String] == hashes && hashes["bundle/" + raw]?.count == 64)
            let saved = try JSONDecoder().decode(ClientBundle.self, from: configuration["bundle"] as! Data)
            check("MAX saved source keeps hostname and credentials", saved.routerProfiles == captured.routerProfiles && saved.profiles == captured.profiles && model.bundle?.profiles == captured.profiles)
            check("MAX preparation creates no second VPN", session.starts == 1 && session.stops == 0)
            model.disconnect(); await model.drainDisconnect()
            model = try fresh(); model.bundle = captured
            NETunnelProviderManager.saveHook = {
                let proto = NETunnelProviderManager.stored[0].protocolConfiguration as! NETunnelProviderProtocol
                proto.providerConfiguration?["max_source_sha256"] = ["bundle/" + raw: String(repeating: "f", count: 64)]
            }
            await model.connect(rawProfileID: raw)
            check("MAX changed source hash at readback prevents start", (NETunnelProviderManager.stored[0].connection as! NETunnelProviderSession).starts == 0 && !model.connected)
        }
        for change in ["", "entry-token", "entry-asset", "saved-LAN"] {
            model = try fresh()
            var entry = try maxAppFixture("max-tls-wg", role: "entry"), exit = try maxAppFixture("max-quic-awg", role: "exit")
            entry.selectedRouterID = "entry"; entry.routerProfiles[0].id = "entry"
            exit.selectedRouterID = "exit"; exit.routerProfiles[0].id = "exit"
            exit.routerProfiles[0].multihopEnabled = true; exit.routerProfiles[0].multihopEntryID = "entry"
            exit.routerProfiles[0].multihopExitID = "exit"; exit.routerProfiles[0].multihopEntryMode = "max-tls-wg"
            exit.routerProfiles[0].multihopExitMode = "max-quic-awg"
            model.bundle = exit; model.entryBundle = entry; let changing = model
            NETunnelProviderManager.saveHook = {
                if change == "entry-token" { changing.entryBundle?.routerProfiles[0].apiToken = "changed private entry" }
                if change == "entry-asset" { changing.entryBundle?.profiles["max-tls-wg"]?["wg.conf"] = Data("changed entry asset".utf8).base64EncodedString() }
                if change == "saved-LAN" { (NETunnelProviderManager.stored[0].protocolConfiguration as! NETunnelProviderProtocol).excludeLocalNetworks = true }
            }
            await model.connect(rawProfileID: "max-quic-awg")
            let manager = NETunnelProviderManager.stored[0], session = manager.connection as! NETunnelProviderSession
            if change.isEmpty {
                let config = (manager.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
                let hashes = config["max_source_sha256"] as! [String: String]
                check("MAX multihop carries both complete source identities", Set(hashes.keys) == ["entryBundle/max-tls-wg", "bundle/max-quic-awg"] && session.starts == 1)
                let saved = try JSONDecoder().decode(ClientBundle.self, from: config["entryBundle"] as! Data)
                check("MAX multihop saved entry stays exact", saved.profiles == entry.profiles && saved.routerProfiles == entry.routerProfiles)
                model.disconnect(); await model.drainDisconnect()
            } else {
                check("MAX multihop changed captured entry or LAN prevents start " + change, session.starts == 0 && !model.connected)
            }
        }
        print("iOS app + provider owned strategies: PASS (\(checks) executable checks)")
    }
}
'''

def strip_imports(text):
    return '\n'.join(line for line in text.splitlines() if not line.startswith(('import ', '@preconcurrency import ')))

def main():
    swift = shutil.which('swiftc')
    if not swift:
        raise SystemExit('swiftc required for shipping app/provider strategy tests')
    model = (APP / 'RouterVPNModel.swift').read_text()
    methods = model[model.index('    func connect() async'):model.index('    func applyForward(dmz:')]
    selection = (APP / 'IOSRuntimeSelection.swift').read_text().split('enum IOSRuntimeSelectionError:', 1)[0]
    wire = (APP / 'IOSStrategySession.swift').read_text().replace('#if canImport(NetworkExtension)', '#if true')
    source = SHIM.replace('    // SHIPPING_MODEL_METHODS', methods)
    external = (APP / 'RouterVPNModelExternal.swift').read_text()
    external_selection = external[external.index('    var selectedNodeProfile:'):external.index('    var selectedNodeIsExternal:')]
    source = source.replace('    var selectedNodeProfile: RouterProfile? { selectedRouterProfile }', external_selection)
    external_properties = external[external.index('    var selectedNodeIsExternal:'):external.index('    func nodeRuntimeSummary(')]
    external_methods = external[external.index('    func connectSelectedExternal() async'):]
    source += '\n@MainActor extension RouterVPNModel {\n' + external_properties + external_methods
    for text in [selection, (APP / 'Models.swift').read_text(), (APP / 'IOSSessionIdentity.swift').read_text(), wire,
                 (APP / 'IOSOwnedStrategy.swift').read_text(), (APP / 'IOSStrategySupport.swift').read_text().replace('UserDefaults.standard', 'FixturePreferences.standard'),
                 (APP / 'IOSNativePQProfile.swift').read_text(), (APP / 'IOSMultihopStartLayer.swift').read_text(),
                 (PROVIDER / 'RouterVPNStrategyPolicy.swift').read_text(), (PROVIDER / 'RouterVPNProviderStrategy.swift').read_text()]:
        source += '\n' + strip_imports(text)
    source = 'import CoreFoundation\n' + source + MAX.P.SWIFT[:MAX.P.SWIFT.index('func profile(')] + TEST
    with tempfile.TemporaryDirectory(prefix='routervpn-owned-app-') as tmp, tempfile.TemporaryDirectory(prefix='.ios-owned-max-go-', dir=ROOT) as go_tmp:
        go_tmp = Path(go_tmp)
        (go_tmp / 'main.go').write_text(MAX.GO)
        compiler = Path(tmp) / 'compiler'; fixture = Path(tmp) / 'max-fixtures.json'; multihop = Path(tmp) / 'max-multihop.json'
        subprocess.run(['go', 'build', '-o', str(compiler), str(go_tmp / 'main.go')], cwd=ROOT, check=True, timeout=120)
        subprocess.run(['go', 'test', '-count=1', '-run', '^TestExportMAX(Multihop)?MobileProfiles$', './internal/mobilemultihop'],
                       cwd=ROOT, env=dict(os.environ, ROUTERVPN_MAX_PROFILE_FIXTURES=str(fixture), ROUTERVPN_MAX_MULTIHOP_FIXTURES=str(multihop)), check=True, timeout=90)
        file = Path(tmp) / 'AppTests.swift'; binary = Path(tmp) / 'app-tests'
        file.write_text(source)
        subprocess.run([swift, '-swift-version', '6', '-parse-as-library', str(file), '-o', str(binary)], check=True, timeout=150)
        subprocess.run([str(binary), str(compiler), str(fixture), str(multihop)], check=True, timeout=40)
        for label, before, after, expected in [
            ('premature connection', 'connected = status.isProven', 'connected = true', 'node proof alone cannot connect'),
            ('runtime epoch collapse', 'runtimeEpoch: status.runtimeEpoch)', 'runtimeEpoch: status.providerSession)', 'same mode fresh runtime invalidates measurement'),
            ('cancel generation lost', 'iosConnectGeneration = UUID(); iosStrategyTaskActive = false;', 'iosStrategyTaskActive = false;', 'cancel revokes pending generation'),
            ('mutable source accepted', 'try iosStrategySource(current) == iosStrategySource(source)', '!current.selectedRouterID.isEmpty', 'changed source before preference readback prevents start'),
            ('mutable MAX entry accepted', 'guard try encoder.encode(iosMultihopEntryBundle(for: bundle)) == capturedEntry else', 'guard !capturedEntry.isEmpty else', 'MAX multihop changed captured entry or LAN prevents start entry-token'),
        ]:
            assert source.count(before) == 1, label
            file.write_text(source.replace(before, after))
            subprocess.run([swift, '-swift-version', '6', '-parse-as-library', str(file), '-o', str(binary)], check=True, timeout=150)
            result = subprocess.run([str(binary), str(compiler), str(fixture), str(multihop)], capture_output=True, text=True, timeout=40)
            assert result.returncode != 0 and expected in result.stderr, label + ': ' + result.stderr[-3000:]
        print('Negative controls: premature connection, reused epoch, lost cancel owner, mutable source and replaced MAX entry are rejected')

if __name__ == '__main__':
    main()
