#!/usr/bin/env python3
"""Execute shipping Apple node-store/model persistence with a durable-write double.

The cryptography/file boundary is replaced by an atomic, failure-injectable map;
normalization, inventory reads, selection, link, save and ownership are shipping
Swift. This specifically catches temporary Speed Lab state leaking into records.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "ios/RouterVPN/App"

SWIFT = r'''
import Foundation

@MainActor enum UserDefaults {
 static let suite = "RouterVPN.NodeStore.Test." + UUID().uuidString
 static let standard = Foundation.UserDefaults(suiteName: suite)!
}
@MainActor final class IOSNodeBundleStore {
 static let shared = IOSNodeBundleStore()
 var records: [String: Data] = [:]
 var storageError: Error?
 var writes = 0, failWrite = false, failAtWrite: Int?
 func reset() { records = [:]; storageError = nil; writes = 0; failWrite = false; failAtWrite = nil }
 private func commitRecords(_ next: [String: Data]) throws {
  if failWrite || failAtWrite == writes + 1 { throw NSError(domain: "DurableWriteBoundary", code: 1) }
  records = next; writes += 1
 }
 // SHIPPING_STORE
}
enum IOSDNSRuntimePolicy {
 static func patch(_ value: ClientBundle) throws -> ClientBundle {
  if value.routerProfiles.contains(where: { $0.dnsMode == "invalid" }) { throw NSError(domain: "DNSPolicyBoundary", code: 1) }
  var prepared = value
  if value.routerProfiles.contains(where: { $0.dnsMode == "rescue" }) {
   prepared.profiles["wg"] = ["wg.conf": Data("exact DNS-patched runtime asset".utf8).base64EncodedString()]
  }
  return prepared
 }
}
enum IOSExternalExecution {
 static func validateImported(_ value: ClientBundle) throws {}
 static func issue() -> NSError { NSError(domain: "ExternalValidationBoundary", code: 1) }
}
@MainActor final class RouterVPNModel {
 var bundle: ClientBundle?, modes: [VPNMode] = [], logicalModes: [LogicalMode] = []
 var endpoint = "", apiToken = "", routerAPI = "", socksHost = "", socksPort = "0"
 var lanImportHost = "", message = "", multihopProgressText = ""
 var selectedMode = "wg", selectedLogicalMode = "fast"
 var multihopProgressGeneration = UUID(), profileMutationBlocked = false
 let iosSpeedLabOwnership = IOSSpeedLabOwnership()
 private let bundleKey = "router-vpn.bundle", lanImportKey = "router-vpn.lan-import-host"
 var iosRunnableLogicalModes: [LogicalMode] { logicalModes }
 var allNodeProfiles: [RouterProfile] { IOSNodeBundleStore.shared.profiles(current: bundle) }
 func nodeRuntimeSummary(_ profile: RouterProfile) -> String { profile.name }
 func apply(_ value: ClientBundle) {
  selectedMode = selectedLogicalMode
  bundle = value; modes = value.modes; logicalModes = value.logicalModes
  endpoint = value.endpoint; apiToken = value.apiToken; routerAPI = value.routerAPI
  socksHost = value.socks5Host; socksPort = String(value.socks5Port)
 }
 // SHIPPING_PERSISTED_BUNDLE
 // SHIPPING_IMPORT
 // SHIPPING_LATENCY_COMMIT
 // SHIPPING_SAVE
 // SHIPPING_LEGACY_MODES
 // SHIPPING_SELECT_AND_LINK
}

func encoded(_ value: ClientBundle) throws -> Data {
 let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
 return try encoder.encode(value)
}
func node(_ id: String, proof: String? = nil) throws -> RouterProfile {
 var value: [String: Any] = [
  "id": id, "name": id, "node_kind": proof == nil ? "external" : "router-vpn",
  "endpoint": "198.51.100.8", "router_api": "http://10.8.0.1:8787", "api_token": " exact node secret ",
  "adguard_ipv4": "10.8.0.1", "adguard_ipv6": "fd08::1", "socks_host": "10.8.0.1", "socks_port": 1080,
  "socks_username": "", "socks_password": "", "dns_mode": "custom", "dns_protocol": "tcp",
  "dns_host": "9.9.9.9", "dns_port": 5353, "ipv6_mode": "off", "home_lan_access": false,
  "mtu_policy": "fixed", "manual_mtu": 1380,
  "external": ["protocol": "socks5", "expected_public_ip": "203.0.113.8",
   "socks5": ["host": "198.51.100.8", "port": 1080, "username": " exact user ", "password": " exact proxy secret "]]
 ]
 if let proof { value["node_proof_id"] = proof; value.removeValue(forKey: "external") }
 return try JSONDecoder().decode(RouterProfile.self, from: JSONSerialization.data(withJSONObject: value))
}
func bundle(_ profile: RouterProfile) -> ClientBundle {
 var value = ClientBundle.empty
 value.routerProfiles = [profile]; value.selectedRouterID = profile.id; value.endpoint = profile.endpoint
 value.nodeProofID = profile.nodeProofID ?? ""
 value.profiles = ["wg": ["wg.conf": Data("exact private imported asset".utf8).base64EncodedString()]]
 return value
}
func temporary(_ source: ClientBundle) -> ClientBundle {
 var value = source
 value.routerProfiles[0].dnsMode = "home"; value.routerProfiles[0].dnsProtocol = "https"
 value.routerProfiles[0].dnsHost = "10.8.0.1"; value.routerProfiles[0].dnsPort = 443
 value.routerProfiles[0].ipv6Mode = "on"; value.routerProfiles[0].mtuPolicy = "auto"
 value.routerProfiles[0].manualMTU = nil; value.routerProfiles[0].homeLANAccess = true
 value.routerProfiles[0].multihopEnabled = false
 return value
}

@MainActor @main struct Tests {
 static var checks = 0
 static func check(_ name: String, _ condition: @autoclosure () throws -> Bool) throws {
  guard try condition() else { throw NSError(domain: "NodeStoreTransaction", code: 1, userInfo: [NSLocalizedDescriptionKey: name]) }
  checks += 1
 }
 static func reject(_ name: String, _ operation: () throws -> Void) throws {
  do { try operation() } catch { checks += 1; return }
  throw NSError(domain: "NodeStoreRejection", code: 1, userInfo: [NSLocalizedDescriptionKey: name])
 }
 static func main() throws {
  defer { UserDefaults.standard.removePersistentDomain(forName: UserDefaults.suite) }
  let store = IOSNodeBundleStore.shared
  let first = bundle(try node("first")), second = bundle(try node("second")), third = bundle(try node("third"))
  let model = RouterVPNModel()
  try model.importBundle(encoded(first))
  try store.save(second)
  let initial = store.records, savedDefaults = UserDefaults.standard.data(forKey: "router-vpn.bundle")!, initialWrites = store.writes
  let changed = temporary(first)
  for _ in 0..<10 {
   let profiles = store.profiles(current: changed)
   try check("inventory returns durable policy", profiles.first(where: { $0.id == "first" }) == first.routerProfiles[0].withoutPrivateRouterFields())
   let stored = try JSONDecoder().decode(ClientBundle.self, from: store.bundleData(containing: "first", current: changed)!)
   try check("lookup keeps original policy and credentials", stored.routerProfiles[0].dnsMode == "custom" && stored.routerProfiles[0].external == first.routerProfiles[0].external)
  }
  try check("reads never invoke durable writer", store.records == initial && store.writes == initialWrites)

  let owner = try model.iosSpeedLabOwnership.begin {}
  try IOSSpeedLabContext.$owner.withValue(owner) {
   try model.importBundle(encoded(changed))
   try reject("temporary worker cannot durably link a node") { try model.linkNodeBundle(encoded(third)) }
   try check("owned save updates temporary model", model.bundle!.routerProfiles[0].dnsMode == "home")
   _ = model.allNodeProfiles
   model.selectNode("second")
   try check("owned selection reads exact saved target", model.bundle!.selectedRouterID == "second" && model.bundle!.routerProfiles[0].dnsMode == "custom")
   try model.importBundle(encoded(temporary(second)))
   model.selectNode("first")
   try check("reselecting previous node does not pick its temporary overrides", model.bundle!.routerProfiles[0].dnsMode == "custom")
   try model.importBundle(encoded(changed))
  }
  try check("temporary save and selection preserve every private record byte", store.records == initial && store.writes == initialWrites)
  try check("temporary save leaves durable defaults byte-identical", UserDefaults.standard.data(forKey: "router-vpn.bundle") == savedDefaults)
  _ = model.iosSpeedLabOwnership.admit(.disconnect)
  try IOSSpeedLabContext.$owner.withValue(owner) {
   IOSSpeedLabContext.$restoringSelection.withValue(true) {
    model.selectNode("first")
   }
   try check("late unowned mutation refused", !model.saveRouter())
  }
  try check("allowed idle restoration preserves private bytes", store.records == initial && UserDefaults.standard.data(forKey: "router-vpn.bundle") == savedDefaults)
  model.iosSpeedLabOwnership.finish(owner)

  let secondOwner = try model.iosSpeedLabOwnership.begin {}
  try IOSSpeedLabContext.$owner.withValue(secondOwner) { try model.importBundle(encoded(changed)) }
  let writesBeforeLink = store.writes
  store.failAtWrite = writesBeforeLink + 2
  try model.linkNodeBundle(encoded(third))
  try check("link succeeds with exactly one durable write even when a second would fail", store.writes == writesBeforeLink + 1)
  store.failAtWrite = nil
  try check("newer user link persists its own input", model.bundle!.selectedRouterID == "third" && store.records.count == 3)
  try check("linked defaults equal the exact committed private bytes", UserDefaults.standard.data(forKey: "router-vpn.bundle") == store.records["bundle-third"])
  try check("newer user link never preserves a temporary old bundle", initial.allSatisfy { store.records[$0.key] == $0.value })
  try check("newer explicit action supersedes cleanup", !model.iosSpeedLabOwnership.mayRestoreSelection(secondOwner))
  let afterLink = store.records, afterLinkDefaults = UserDefaults.standard.data(forKey: "router-vpn.bundle")
  try IOSSpeedLabContext.$owner.withValue(secondOwner) {
   try reject("late import cannot replace newer saved node") { try model.importBundle(encoded(changed)) }
  }
  try check("late work leaves newer user state intact", store.records == afterLink && UserDefaults.standard.data(forKey: "router-vpn.bundle") == afterLinkDefaults)
  model.iosSpeedLabOwnership.finish(secondOwner)

  let previousSecond = store.records["bundle-second"]
  _ = try store.updateMetadata(profileID: "first", current: changed, name: "Renamed", location: "Here", latitude: 1, longitude: 2)
  let renamed = try JSONDecoder().decode(ClientBundle.self, from: store.bundleData(containing: "first", current: changed)!)
  try check("targeted metadata edit keeps saved policy and private assets", renamed.routerProfiles[0].name == "Renamed" && renamed.routerProfiles[0].dnsMode == "custom" && renamed.profiles == first.profiles)
  try check("metadata does not rewrite unrelated record", store.records["bundle-second"] == previousSecond)
  let beforeRemove = store.records["bundle-first"]
  _ = try store.remove(profileID: "second", current: changed)
  try check("remove never rewrites a temporary current node", store.records["bundle-first"] == beforeRemove && store.records["bundle-second"] == nil)

  let beforeFailure = store.records, defaultsBeforeFailure = UserDefaults.standard.data(forKey: "router-vpn.bundle")
  let modelBeforeFailure = try encoded(model.bundle!)
  store.failWrite = true
  try reject("failed explicit save is surfaced") { try model.importBundle(encoded(second)) }
  try check("failed save keeps records defaults and active model", store.records == beforeFailure && UserDefaults.standard.data(forKey: "router-vpn.bundle") == defaultsBeforeFailure && encoded(model.bundle!) == modelBeforeFailure)
  try reject("failed link is atomic") { _ = try store.link(encoded(second), preserving: bundle(try node("legacy")), prepare: { $0 }) }
  try check("failed preservation does not partly add legacy state", store.records == beforeFailure)
  try reject("failed model link is surfaced") { try model.linkNodeBundle(encoded(second)) }
  try check("failed model link leaves records defaults and active model intact", store.records == beforeFailure && UserDefaults.standard.data(forKey: "router-vpn.bundle") == defaultsBeforeFailure && encoded(model.bundle!) == modelBeforeFailure)
  store.failWrite = false
  var invalidDNS = bundle(try node("invalid-router", proof: String(repeating: "b", count: 64)))
  invalidDNS.routerProfiles[0].dnsMode = "invalid"
  let writesBeforeInvalid = store.writes
  try reject("invalid linked DNS is rejected before any durable change") { try model.linkNodeBundle(encoded(invalidDNS)) }
  try check("invalid DNS leaves original records defaults and model unchanged", store.writes == writesBeforeInvalid && store.records == beforeFailure && UserDefaults.standard.data(forKey: "router-vpn.bundle") == defaultsBeforeFailure && encoded(model.bundle!) == modelBeforeFailure)

  store.reset()
  UserDefaults.standard.set(try encoded(first), forKey: "router-vpn.bundle")
  model.apply(changed)
  _ = store.profiles(current: first)
  _ = store.bundleData(containing: "first", current: first)
  try check("legacy saved-only reads stay read-only", store.records.isEmpty && store.writes == 0)
  try model.linkNodeBundle(encoded(second))
  let legacySaved = try JSONDecoder().decode(ClientBundle.self, from: store.bundleData(containing: "first", current: nil)!)
  try check("link preserves saved legacy source rather than temporary current", legacySaved.routerProfiles[0].dnsMode == "custom" && legacySaved.profiles == first.profiles)
  try check("legacy preservation and incoming node commit together once", store.writes == 1)

  store.reset(); UserDefaults.standard.removeObject(forKey: "router-vpn.bundle")
  var needsPatch = third; needsPatch.routerProfiles[0].dnsMode = "rescue"
  store.failAtWrite = 2
  try model.linkNodeBundle(encoded(needsPatch))
  let patchedData = store.records["bundle-third"]!, patched = try JSONDecoder().decode(ClientBundle.self, from: patchedData)
  try check("DNS runtime preparation happens before private commit", patched.profiles["wg"]?["wg.conf"] == Data("exact DNS-patched runtime asset".utf8).base64EncodedString())
  try check("model and defaults adopt exact prepared committed source", model.bundle!.profiles == patched.profiles && encoded(model.bundle!) == encoded(patched) && UserDefaults.standard.data(forKey: "router-vpn.bundle") == patchedData && store.writes == 1)

  store.reset()
  var multiple = first; multiple.routerProfiles.append(second.routerProfiles[0])
  try model.importBundle(encoded(multiple))
  let recordID = store.records.keys.first!
  model.selectNode("second")
  try check("multi-node selection keeps one owning private record", store.records.count == 1 && store.records[recordID] != nil && model.bundle!.selectedRouterID == "second")
  model.selectNode("first")
  try check("both nodes keep exact shared assets after selection", model.bundle!.routerProfiles.count == 2 && model.bundle!.profiles == multiple.profiles)
  try store.save(third)
  var collision = multiple; collision.routerProfiles.append(third.routerProfiles[0])
  let beforeCollision = store.records
  try reject("one incoming bundle cannot merge different owners") { try store.save(collision) }
  try check("owner collision leaves both records intact", store.records == beforeCollision)

  store.reset(); UserDefaults.standard.removeObject(forKey: "router-vpn.bundle")
  try model.linkNodeBundle(encoded(third))
  try store.save(second)
  let directSource = store.bundleData(containing: "third", current: model.bundle)!
  let directSelection = try encoded(model.bundle!)
  model.selectedMode = "exact user raw mode"
  let otherRecord = store.records["bundle-second"]
  let measurements = try IOSLatencyResult.summarize(id: "third", name: "third", values: Array(1...50).map(Double.init), failed: 0)
  try check("50 sample median min max and average are real statistics", measurements.samples == 50 && measurements.medianMs == 25.5 && measurements.minMs == 1 && measurements.maxMs == 50 && measurements.averageMs == 25.5)
  try check("50 sample interpolated p90 and 10 percent trimmed mean are computed", measurements.p90Ms == 45.1 && measurements.trimmedMeanMs == 25.5)
  let statisticsOwner = try model.iosSpeedLabOwnership.begin {}
  let writesBeforeStatistics = store.writes
  store.failAtWrite = writesBeforeStatistics + 2
  try model.commitNodeLatency(measurements, expectedRecord: directSource, expectedSelection: directSelection, owner: statisticsOwner)
  store.failAtWrite = nil
  try check("50 sample statistics use one atomic durable write", store.writes == writesBeforeStatistics + 1 && store.records["bundle-second"] == otherRecord)
  try check("statistics commit preserves the user's existing mode choice", model.selectedMode == "exact user raw mode")
  let statisticsData = store.bundleData(containing: "third", current: model.bundle)!
  let savedStatistics = try JSONDecoder().decode(ClientBundle.self, from: statisticsData).routerProfiles[0]
  try check("all requested metrics persist in actual profile fields", savedStatistics.latencySamples == 50 && savedStatistics.latencyMinMs == 1 && savedStatistics.latencyMedianMs == 25.5 && savedStatistics.latencyAverageMs == 25.5 && savedStatistics.latencyTrimmedMeanMs == 25.5 && savedStatistics.latencyP90Ms == 45.1 && savedStatistics.latencyMaxMs == 50 && savedStatistics.latencyLastTest != nil)
  try check("model and defaults adopt identical committed statistics", encoded(model.bundle!) == encoded(JSONDecoder().decode(ClientBundle.self, from: statisticsData)) && UserDefaults.standard.data(forKey: "router-vpn.bundle") == statisticsData)
  let statisticsRecords = store.records, statisticsDefaults = UserDefaults.standard.data(forKey: "router-vpn.bundle")
  try reject("stale source cannot overwrite newer statistics") { try model.commitNodeLatency(measurements, expectedRecord: directSource, expectedSelection: directSelection, owner: statisticsOwner) }
  let currentSelection = try encoded(model.bundle!)
  let partial = try IOSLatencyResult.summarize(id: "third", name: "third", values: Array(1...49).map(Double.init), failed: 1)
  try reject("failed sample does not overwrite durable 50 sample ranking") { try model.commitNodeLatency(partial, expectedRecord: statisticsData, expectedSelection: currentSelection, owner: statisticsOwner) }
  let stale = try IOSLatencyResult.summarize(id: "third", name: "third", values: Array(1...50).map(Double.init), failed: 0, measuredAt: Date().addingTimeInterval(-301))
  try reject("stale result timestamp cannot become fresh ranking") { try model.commitNodeLatency(stale, expectedRecord: statisticsData, expectedSelection: currentSelection, owner: statisticsOwner) }
  try reject("invalid direct values rejected") { _ = try IOSLatencyResult.summarize(id: "third", name: "third", values: [.nan], failed: 0) }
  store.failWrite = true
  try reject("statistics durable failure is surfaced") { try model.commitNodeLatency(measurements, expectedRecord: statisticsData, expectedSelection: currentSelection, owner: statisticsOwner) }
  store.failWrite = false
  try check("failed writes and stale results leave records RAM and defaults untouched", store.records == statisticsRecords && encoded(model.bundle!) == currentSelection && UserDefaults.standard.data(forKey: "router-vpn.bundle") == statisticsDefaults)
  _ = model.iosSpeedLabOwnership.admit(.profile)
  try reject("newer user mutation revokes statistics commit") { try model.commitNodeLatency(measurements, expectedRecord: statisticsData, expectedSelection: currentSelection, owner: statisticsOwner) }
  model.iosSpeedLabOwnership.finish(statisticsOwner)

  store.reset()
  let proof = String(repeating: "a", count: 64), router = bundle(try node("legacy-router", proof: String(repeating: "a", count: 64)))
  try store.save(router)
  try check("router id remains deterministic", store.profiles(current: nil).first?.id == "rvpn-" + String(proof.prefix(16)))
  let canonical = try JSONDecoder().decode(ClientBundle.self, from: store.bundleData(containing: "legacy-router", current: temporary(router))!)
  try check("router lookup keeps proof and full private bundle", canonical.nodeProofID == proof && canonical.profiles == router.profiles && canonical.routerProfiles[0].dnsMode == "custom")
  store.storageError = NSError(domain: "CorruptPrivateStore", code: 1)
  let corruptBefore = store.records
  try check("corrupt store does not expose fallback", store.profiles(current: first).isEmpty && store.bundleData(containing: "first", current: first) == nil)
  try reject("corrupt store refuses save") { try store.save(first) }
  try check("corrupt store bytes stay intact", store.records == corruptBefore)
  print("Apple node-store transaction persistence: PASS (\(checks) shipping Swift checks; durable-write boundary doubled)")
 }
}
extension RouterProfile {
 func withoutPrivateRouterFields() -> RouterProfile {
  var copy = self
  copy.nodeProofID = nil; copy.routerAPI = ""; copy.apiToken = ""; copy.adGuardIPv4 = ""; copy.adGuardIPv6 = ""
  copy.socksHost = ""; copy.socksPort = 0; copy.socksUsername = ""; copy.socksPassword = ""
  copy.daitaHost = nil; copy.daitaPort = nil; copy.daitaRateKbps = nil; copy.baseTunnel = nil; copy.baseFallback = nil; copy.pathProbeURL = nil
  return copy
 }
}
'''


def main():
    swift = shutil.which("swiftc")
    if not swift:
        raise SystemExit("swiftc required")
    store = (APP / "IOSNodeBundleStore.swift").read_text()
    model = (APP / "RouterVPNModel.swift").read_text()
    external = (APP / "RouterVPNModelExternal.swift").read_text()
    body = SWIFT.replace(" // SHIPPING_STORE", store[store.index("    func link("):store.index("    private func storeDirectory(")])
    body = body.replace(" // SHIPPING_PERSISTED_BUNDLE", model[model.index("    var persistedNodeBundle:"):model.index("    init()")])
    body = body.replace(" // SHIPPING_IMPORT", model[model.index("    func importBundle("):model.index("    func restoreIOSSpeedLabBundle(")])
    body = body.replace(" // SHIPPING_LATENCY_COMMIT", model[model.index("    func commitNodeLatency("):model.index("    func importFromLAN(")])
    body = body.replace(" // SHIPPING_SAVE", model[model.index("    @discardableResult\n    func saveRouter("):model.index("    private func apply(")])
    body = body.replace(" // SHIPPING_LEGACY_MODES", model[model.index("    private func legacyLogicalModes("):model.index("    func modeCandidates(")])
    body = body.replace(" // SHIPPING_SELECT_AND_LINK", external[external.index("    func selectNode("):external.index("    func connectSelectedExternal(")])
    with tempfile.TemporaryDirectory(prefix="routervpn-node-store-") as folder:
        work = Path(folder)
        source = work / "Test.swift"
        source.write_text(body)
        subprocess.run([swift, "-swift-version", "6", "-module-cache-path", str(work / "module-cache"), str(APP / "Models.swift"), str(APP / "IOSNodeLatencyStatistics.swift"), str(APP / "IOSSpeedLabOwnership.swift"), str(source), "-o", str(work / "test")], check=True, timeout=90)
        subprocess.run([str(work / "test")], check=True, timeout=30)


if __name__ == "__main__":
    main()
