#!/usr/bin/env python3
"""Execute the shipping PacketTunnel strategy driver with native boundary doubles.

The extracted driver and deadline callback are unchanged. The fixture exposes
only their serial queue for deterministic draining; platform/core operations are
doubled so failed DNS, close, path and late callback cases run on Linux Swift 6.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'ios/RouterVPN/PacketTunnel'

FIXTURE = r'''
import Foundation

enum IOSNativeMAXProfile {
    static let modeIDs: Set<String> = ["max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"]
}
enum IOSMAXSourceSelection {
    static func profile(_ root: [String: Any]) throws -> [String: Any] {
        guard let profiles = root["routerProfiles"] as? [[String: Any]], profiles.count == 1,
              profiles[0]["id"] as? String == root["selectedRouterID"] as? String else { throw Main.failure }
        return profiles[0]
    }
}
final class MAXGate: @unchecked Sendable {
    let entered = DispatchSemaphore(value: 0)
    let cancelled = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
}
final class MAXBoundary: @unchecked Sendable {
    static let shared = MAXBoundary()
    private let lock = NSLock()
    private var owners: [RouterVPNMAXPreparation] = []
    private var next: MAXGate?
    func holdNext() -> MAXGate {
        lock.lock(); defer { lock.unlock() }
        let gate = MAXGate(); next = gate; return gate
    }
    func takeGate() -> MAXGate? { lock.lock(); defer { lock.unlock() }; let gate = next; next = nil; return gate }
    func add(_ owner: RouterVPNMAXPreparation) { lock.lock(); owners.append(owner); lock.unlock() }
    var all: [RouterVPNMAXPreparation] { lock.lock(); defer { lock.unlock() }; return owners }
}
final class RouterVPNMAXPreparation: @unchecked Sendable {
    let id = UUID().uuidString
    private let captured: Data
    private let gate: MAXGate?
    private let lock = NSLock()
    private var cancelled = false
    private var closed = false
    init(provider: [String: Any]) throws {
        guard Set(provider.keys) == ["engine", "bundle", "rawProfileID", "max_source_sha256"],
              provider["engine"] as? String == "libbox", let raw = provider["rawProfileID"] as? String,
              IOSNativeMAXProfile.modeIDs.contains(raw), let data = provider["bundle"] as? Data,
              provider["max_source_sha256"] as? [String: String] == ["bundle/" + raw: Main.digest],
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any], root["max_launch_owner"] == nil else { throw Main.failure }
        captured = data; gate = MAXBoundary.shared.takeGate(); MAXBoundary.shared.add(self)
    }
    func run() throws -> [String: Any] {
        gate?.entered.signal()
        if let gate { precondition(gate.release.wait(timeout: .now() + 8) == .success, "fixture MAX worker was never released") }
        guard healthy() else { throw Main.failure }
        var root = try JSONSerialization.jsonObject(with: captured) as! [String: Any]
        var profile = try IOSMAXSourceSelection.profile(root)
        profile["endpoint"] = "203.0.113.40"
        root["routerProfiles"] = [profile]; root["max_launch_owner"] = id
        return ["bundle": try JSONSerialization.data(withJSONObject: root)]
    }
    func healthy() -> Bool { lock.lock(); defer { lock.unlock() }; return !cancelled && !closed }
    func cancel() { lock.lock(); cancelled = true; lock.unlock(); gate?.cancelled.signal() }
    func close() { cancel(); lock.lock(); closed = true; lock.unlock() }
    var isClosed: Bool { lock.lock(); defer { lock.unlock() }; return closed }
    static func issue() -> NSError { Main.failure }
}

final class Forwarding {
    var active = false
    func invalidate() { active = false }
}

final class PacketTunnelProvider: @unchecked Sendable {
    final class NetworkProofGuard {}
    struct LibboxCompilation {
        let files: [String: Data]
        let nodeID: String
        let proofURL: URL
        let profile: Data
    }
    var libboxEngine: RouterVPNLibboxEngine?
    var forwardingChannel: Forwarding? = Forwarding()
    var owner: RouterVPNProviderStrategy!
    private var driver: StrategyRuntimeDriver!
    private var pathGuard: NetworkProofGuard?
    var reasserting = true
    var events: [String] = []
    var engines: [RouterVPNLibboxEngine] = []
    var proofs: [(Error?) -> Void] = []
    var activeEngines = 0
    var maximumEngines = 0
    var initialLease = String(repeating: "1", count: 32)
    var dnsHook: ((RouterVPNLibboxEngine) throws -> Void)?
    var performanceHook: ((RouterVPNLibboxEngine) throws -> Void)?
    var mtuHook: ((RouterVPNLibboxEngine) -> Void)?
    var forwardingHook: (() -> Void)?
    var failCompile = Set<String>()
    var failStart = Set<String>()
    var failClose = Set<String>()

    func currentProviderStrategy() -> RouterVPNProviderStrategy? { owner }
    func beginLibboxSettings(epoch: String) { events.append("settings:" + epoch) }
    func clearPathProofGuard() { pathGuard = nil; forwardingChannel?.invalidate(); events.append("unprove") }
    func currentPathProofGuard() -> NetworkProofGuard? { pathGuard }
    func cancelActiveProof() { events.append("cancel-proof") }
    func armNetworkProofGuard() -> NetworkProofGuard {
        let value = NetworkProofGuard(); pathGuard = value; events.append("arm"); return value
    }
    func compileLibbox(provider: [String: Any], root: [String: Any], selectedProfile: [String: Any]) throws -> LibboxCompilation {
        guard let raw = provider["rawProfileID"] as? String,
              Set(provider.keys) == ["rawProfileID"],
              root["immutable"] as? String == "captured",
              selectedProfile["node_proof_id"] as? String == Main.node else { throw Main.failure }
        events.append("compile:" + raw)
        if failCompile.contains(raw) { throw Main.failure }
        if IOSNativeMAXProfile.modeIDs.contains(raw) {
            guard root["max_launch_owner"] as? String == MAXBoundary.shared.all.last?.id,
                  selectedProfile["endpoint"] as? String == "203.0.113.40",
                  selectedProfile["tls_name"] as? String == "vpn.example.invalid" else { throw Main.failure }
        }
        return LibboxCompilation(files: ["sing-box.json": Data(raw.utf8)], nodeID: Main.node,
            proofURL: URL(string: "http://10.66.0.1:18118/node-proof")!,
            profile: try JSONSerialization.data(withJSONObject: selectedProfile))
    }
    func proveSelectedNode(url: URL, expectedNodeID: String, proxyPort: Int,
                           completion: @escaping (Error?) -> Void) {
        precondition(expectedNodeID == Main.node && proxyPort == RouterVPNLibboxEngine.proofProxyPort)
        if IOSNativeMAXProfile.modeIDs.contains(libboxEngine?.raw ?? "") {
            precondition(MAXBoundary.shared.all.last?.isClosed == true, "MAX preparation was not drained before node proof")
        }
        events.append("node:" + (libboxEngine?.raw ?? "missing")); proofs.append(completion)
    }
    func enableForwarding(profileData: Data, proofID: String, captured: NetworkProofGuard) {
        precondition(proofID == Main.node && pathGuard === captured)
        events.append("forward:" + (libboxEngine?.raw ?? "missing"))
        forwardingChannel?.active = true; forwardingHook?()
    }
    func configure(_ kind: String, _ raws: [String], catalog: [String]? = nil, preferred: String? = nil) throws {
        let captured = catalog ?? raws
        let profile: [String: Any] = ["id": "home", "node_kind": "router-vpn", "node_proof_id": Main.node,
                                      "endpoint": "vpn.example.invalid", "tls_name": "vpn.example.invalid"]
        var files: [String: [String: String]] = [:]
        for raw in captured { files[raw] = ["sing-box.json": Data("{}".utf8).base64EncodedString()] }
        let root: [String: Any] = ["selectedRouterID": "home", "immutable": "captured", "profiles": files, "routerProfiles": [profile]]
        let policy = try RouterVPNStrategyPolicy(catalog: ["version": 1, "candidates": captured.map(Main.reference)],
                                                 root: root, profile: profile)
        let plan = try policy.plan(Main.request(kind, raws, preferred: preferred), initial: true)
        driver = StrategyRuntimeDriver(provider: self, bundle: try JSONSerialization.data(withJSONObject: root),
            profile: try JSONSerialization.data(withJSONObject: profile), strict: true, initialHold: initialLease,
            maxSources: Dictionary(uniqueKeysWithValues: captured.filter(IOSNativeMAXProfile.modeIDs.contains).map { ("bundle/" + $0, Main.digest) }))
        owner = try RouterVPNProviderStrategy(policy: policy, plan: plan, bundleDigest: Main.digest, nodeID: Main.node, driver: driver)
    }
    func start() { owner.start(); flush() }
    func flush() { for _ in 0..<16 { driver.queue.sync {} } }
    func finish(_ index: Int, error: Error? = nil) { proofs[index](error); flush() }
    func expire(_ epoch: String) { StrategyExpiry(provider: self, epoch: epoch).expire(); flush() }
    func changedPath() {
        pathGuard = nil
        owner.invalidate(epoch: owner.currentEpoch)
    }
    func stop() {
        let done = DispatchSemaphore(value: 0)
        stopWithoutWaiting { done.signal() }
        precondition(done.wait(timeout: .now() + 8) == .success); flush()
    }
    func stopWithoutWaiting(_ completion: @escaping () -> Void) {
        owner.stop()
        driver.drain { [self] in
            clearPathProofGuard(); cancelActiveProof()
            let old = libboxEngine; libboxEngine = nil; old?.stop(); completion()
        }
    }
    func drain(_ completion: @escaping () -> Void) {
        driver.drain(completion)
    }

    // SHIPPING_DRIVER
}

final class RouterVPNLibboxEngine {
    static let proofProxyPort = 1099
    let settingsEpoch: String
    unowned let tunnel: PacketTunnelProvider
    var strategyMTUHold = ""
    var raw = ""
    var started = false
    var stopped = false
    init(tunnel: PacketTunnelProvider, strategyEpoch: String) {
        self.tunnel = tunnel; settingsEpoch = strategyEpoch; tunnel.engines.append(self)
    }
    func prepareMTUHold(_ value: String) throws { strategyMTUHold = value }
    func start(files: [String: Data], strict: Bool) throws {
        guard strict, !stopped, let data = files["sing-box.json"], let value = String(data: data, encoding: .utf8) else { throw Main.failure }
        raw = value; tunnel.events.append("start:" + raw)
        if tunnel.failStart.contains(raw) { throw Main.failure }
        started = true; tunnel.activeEngines += 1; tunnel.maximumEngines = max(tunnel.maximumEngines, tunnel.activeEngines)
    }
    func stopCheckedForStrategy() throws {
        tunnel.events.append("close:" + raw)
        if tunnel.failClose.contains(raw) { throw Main.failure }
        if started { started = false; tunnel.activeEngines -= 1 }
        stopped = true
    }
    func stop() { try? stopCheckedForStrategy() }
    func proveStrategyDNS() throws { tunnel.events.append("dns:" + raw); try tunnel.dnsHook?(self) }
    func activatePerformance() throws { tunnel.events.append("performance:" + raw); try tunnel.performanceHook?(self) }
    func activateMTU(profile: [String: Any]) { tunnel.events.append("mtu:" + raw); tunnel.mtuHook?(self) }
}

@main struct Main {
    static let node = String(repeating: "a", count: 64)
    static let digest = String(repeating: "b", count: 64)
    static var failure: NSError { NSError(domain: "NativeBoundary", code: 1) }
    static func reference(_ raw: String) -> [String: String] { ["raw": raw, "logical": raw] }
    static func request(_ kind: String, _ raws: [String], preferred: String? = nil) -> [String: Any] {
        var value: [String: Any] = ["version": 1, "request_id": UUID().uuidString,
                                  "kind": kind, "candidates": raws.map(reference)]
        if let preferred { value["preferred_raw"] = preferred }
        return value
    }
    static func data(_ object: [String: Any]) -> Data { try! JSONSerialization.data(withJSONObject: object) }
    static func status(_ provider: PacketTunnelProvider) -> [String: Any] {
        try! JSONSerialization.jsonObject(with: provider.owner.handle(data(["operation": "strategy-status", "bundle_digest": digest]))!) as! [String: Any]
    }
    static func run(_ provider: PacketTunnelProvider, _ kind: String, _ raws: [String], preferred: String? = nil) -> Data? {
        let result = provider.owner.handle(data(["operation": "strategy-run", "request_id": status(provider)["request_id"]!,
            "provider_session": provider.owner.providerSession, "strategy": request(kind, raws, preferred: preferred)]))
        provider.flush(); return result
    }
    static func cancel(_ provider: PacketTunnelProvider) {
        precondition(provider.owner.handle(data(["operation": "strategy-cancel", "request_id": status(provider)["request_id"]!,
            "provider_session": provider.owner.providerSession])) != nil)
        provider.flush()
    }
    static func main() throws {
        var checks = 0
        func check(_ label: String, _ condition: @autoclosure () -> Bool) {
            guard condition() else { fatalError(label) }; checks += 1
        }
        let auto = PacketTunnelProvider()
        try auto.configure("auto", ["wg", "shadowsocks"]); auto.start()
        check("provider stays reasserting until both proofs", auto.reasserting && status(auto)["phase"] as? String == "proving")
        check("initial measurement hold reaches native owner", auto.engines[0].strategyMTUHold == auto.initialLease)
        let firstEpoch = auto.owner.currentEpoch
        auto.finish(0, error: failure)
        check("node failure closes native engine before replacement", auto.events.firstIndex(of: "close:wg")! < auto.events.firstIndex(of: "start:shadowsocks")!)
        check("one native packet reader at any time", auto.maximumEngines == 1 && auto.activeEngines == 1)
        check("replacement preserves acknowledged measurement hold", auto.engines[1].strategyMTUHold == auto.initialLease)
        auto.finish(0)
        check("late old proof does not invoke current DNS", !auto.events.contains("dns:wg") && !auto.events.contains("dns:shadowsocks"))
        auto.finish(1)
        check("DNS precedes performance and final MTU", auto.events.firstIndex(of: "dns:shadowsocks")! < auto.events.firstIndex(of: "performance:shadowsocks")! && auto.events.firstIndex(of: "performance:shadowsocks")! < auto.events.firstIndex(of: "mtu:shadowsocks")!)
        check("only final proven owner gets forwarding", auto.events.filter { $0.hasPrefix("forward:") } == ["forward:shadowsocks"] && auto.forwardingChannel?.active == true)
        check("native activation publishes Connected last", status(auto)["phase"] as? String == "connected" && !auto.reasserting && status(auto)["proven_raw"] as? String == "shadowsocks")
        auto.expire(firstEpoch)
        check("stale native deadline cannot replace the winner", auto.engines.count == 2 && status(auto)["phase"] as? String == "connected")

        auto.libboxEngine?.strategyMTUHold = String(repeating: "2", count: 32)
        check("later AUTO starts within the same provider", run(auto, "auto", ["wg"]) != nil && auto.engines.count == 3)
        check("later request inherits live hold, not launch default", auto.engines[2].strategyMTUHold == String(repeating: "2", count: 32))
        check("new request revokes old forwarding before proof", auto.forwardingChannel?.active == false && auto.reasserting && status(auto)["proven_raw"] as? String == "")
        auto.finish(2, error: failure)
        check("failed later request starts immutable previous graph afresh", auto.engines.map(\.raw) == ["wg", "shadowsocks", "wg", "shadowsocks"])
        auto.finish(3)
        check("restored runtime does not claim requested success", status(auto)["outcome"] as? String == "restored" && auto.maximumEngines == 1)

        let dns = PacketTunnelProvider()
        dns.dnsHook = { _ in throw failure }
        try dns.configure("manual", ["wg"]); dns.start(); dns.finish(0)
        check("native DNS failure prevents every final activation", !dns.events.contains("performance:wg") && !dns.events.contains("mtu:wg") && dns.forwardingChannel?.active == false)
        check("native DNS failure leaves protected settings owner", status(dns)["phase"] as? String == "blocked" && dns.reasserting && dns.activeEngines == 0)

        for boundary in ["dns", "performance", "mtu", "forward"] {
            let path = PacketTunnelProvider()
            let invalidate: (RouterVPNLibboxEngine) -> Void = { $0.tunnel.changedPath() }
            if boundary == "dns" { path.dnsHook = invalidate }
            if boundary == "performance" { path.performanceHook = invalidate }
            if boundary == "mtu" { path.mtuHook = invalidate }
            if boundary == "forward" { path.forwardingHook = { [unowned path] in path.changedPath() } }
            try path.configure("manual", ["wg"]); path.start(); path.finish(0)
            check("path change during \(boundary) cannot publish proof", status(path)["phase"] as? String == "blocked" && status(path)["proven_raw"] as? String == "" && path.reasserting)
            check("path change during \(boundary) retires forwarding", path.forwardingChannel?.active == false && path.activeEngines == 0)
            path.stop()
        }

        let smart = PacketTunnelProvider()
        try smart.configure("smart", ["naive-h3", "hysteria2", "naive-h2"], preferred: "naive-h3")
        smart.start(); smart.finish(0); smart.finish(1, error: failure)
        check("SMART failure restores the original native graph", smart.engines.map(\.raw) == ["naive-h3", "hysteria2", "naive-h3"])
        check("intermediate SMART successes never activate MTU", !smart.events.contains { $0.hasPrefix("mtu:") })
        smart.finish(2); smart.finish(3)
        check("SMART settles only after restored proof and compatible reduction", status(smart)["proven_raw"] as? String == "naive-h2" && smart.maximumEngines == 1)
        check("fresh SMART generations have distinct epochs", Set(smart.engines.map(\.settingsEpoch)).count == 4)

        let cancelled = PacketTunnelProvider()
        try cancelled.configure("smart", ["naive-h3", "hysteria2"], preferred: "naive-h3")
        cancelled.start(); cancelled.finish(0); cancel(cancelled)
        cancelled.finish(1)
        check("cancelled native proof cannot steal the restore epoch", status(cancelled)["proven_raw"] as? String == "" && cancelled.engines.map(\.raw) == ["naive-h3", "hysteria2", "naive-h3"])
        cancelled.finish(2)
        check("cancel waits for fresh node and DNS on last good", status(cancelled)["phase"] as? String == "cancelled" && status(cancelled)["proven_raw"] as? String == "naive-h3" && !cancelled.reasserting)

        let quarantine = PacketTunnelProvider()
        quarantine.failClose = ["wg"]
        try quarantine.configure("auto", ["wg", "shadowsocks"])
        quarantine.start(); quarantine.finish(0, error: failure)
        check("unverified native close forbids replacement", quarantine.engines.count == 1 && !quarantine.events.contains("compile:shadowsocks") && status(quarantine)["phase"] as? String == "blocked")
        check("close failure retains protection and publishes no proof", quarantine.reasserting && status(quarantine)["node_proven"] as? Bool == false)
        _ = run(quarantine, "auto", ["shadowsocks"])
        check("a later IPC cannot bypass teardown quarantine", quarantine.engines.count == 1 && status(quarantine)["phase"] as? String == "blocked")

        let cancelledEarly = PacketTunnelProvider()
        try cancelledEarly.configure("auto", ["wg", "shadowsocks"]); cancelledEarly.start(); cancel(cancelledEarly)
        cancelledEarly.finish(0)
        check("early cancellation retires the reader without starting another", cancelledEarly.activeEngines == 0 && cancelledEarly.engines.count == 1 && cancelledEarly.reasserting)

        let stopped = PacketTunnelProvider()
        try stopped.configure("auto", ["wg", "shadowsocks"]); stopped.start(); let stoppedEpoch = stopped.owner.currentEpoch
        stopped.stop(); stopped.finish(0); stopped.expire(stoppedEpoch)
        check("explicit stop invalidates queued proof and expiry", status(stopped)["phase"] as? String == "stopped" && stopped.engines.count == 1 && stopped.activeEngines == 0)

        let invalid = PacketTunnelProvider()
        invalid.failCompile = ["wg"]
        try invalid.configure("auto", ["wg", "shadowsocks"]); invalid.start()
        check("invalid immutable candidate never creates a runtime", invalid.engines.count == 1 && invalid.engines[0].raw == "shadowsocks")
        invalid.finish(0)
        check("remaining captured candidate still requires native DNS", invalid.events.contains("dns:shadowsocks") && status(invalid)["phase"] as? String == "connected")

        let maximum = PacketTunnelProvider()
        let beforeMAX = MAXBoundary.shared.all.count
        try maximum.configure("auto", ["max-tls-wg", "max-quic-wg"]); maximum.start()
        maximum.finish(0, error: failure)
        check("MAX fallback captures a fresh preparation owner", MAXBoundary.shared.all.count == beforeMAX + 2)
        check("each MAX launch drains preparation before native proof", MAXBoundary.shared.all.suffix(2).allSatisfy(\.isClosed))
        maximum.finish(1)
        check("MAX keeps the single native reader and exact final mode", maximum.maximumEngines == 1 && status(maximum)["proven_raw"] as? String == "max-quic-wg")
        maximum.stop()

        let held = PacketTunnelProvider()
        try held.configure("auto", ["max-tls-wg"])
        let gate = MAXBoundary.shared.holdNext(); held.owner.start()
        check("MAX preparation can be held inside the real driver queue", gate.entered.wait(timeout: .now() + 4) == .success)
        let heldRequest = status(held)["request_id"]!
        check("Cancel acknowledges before the MAX worker returns", held.owner.handle(data(["operation": "strategy-cancel", "request_id": heldRequest,
              "provider_session": held.owner.providerSession])) != nil && gate.cancelled.wait(timeout: .now() + 2) == .success)
        let drained = DispatchSemaphore(value: 0); held.drain { drained.signal() }
        check("Cancel does not pretend that a held MAX worker has drained", drained.wait(timeout: .now()) == .timedOut)
        gate.release.signal()
        check("MAX cancellation drains the exact old worker", drained.wait(timeout: .now() + 4) == .success)
        held.flush()
        check("cancelled MAX output cannot create a native engine", held.engines.isEmpty && status(held)["phase"] as? String == "cancelled")
        check("a later request uses fresh captured MAX preparation", run(held, "auto", ["max-tls-wg"]) != nil && held.engines.count == 1)
        held.finish(0)
        check("the replacement still needs both native proofs", status(held)["phase"] as? String == "connected" && held.events.contains("dns:max-tls-wg"))
        held.stop()

        let heldStop = PacketTunnelProvider()
        try heldStop.configure("manual", ["max-tls-wg"])
        let stopGate = MAXBoundary.shared.holdNext(); heldStop.owner.start()
        check("Stop scenario captures a pending MAX worker", stopGate.entered.wait(timeout: .now() + 4) == .success)
        let stoppedMAX = DispatchSemaphore(value: 0); heldStop.stopWithoutWaiting { stoppedMAX.signal() }
        check("Stop cancels before waiting for its serial driver", stopGate.cancelled.wait(timeout: .now() + 2) == .success)
        check("OS stop completion waits for MAX cleanup", stoppedMAX.wait(timeout: .now()) == .timedOut)
        stopGate.release.signal()
        check("OS stop completes only after the pending worker drains", stoppedMAX.wait(timeout: .now() + 4) == .success)
        heldStop.flush()
        check("stopped MAX output never reaches native startup", heldStop.engines.isEmpty && status(heldStop)["phase"] as? String == "stopped")

        for provider in [auto, dns, smart, cancelled, cancelledEarly, invalid] { provider.stop() }
        print("Shipping iOS native strategy driver: PASS (\(checks) executable generation, DNS, MTU, restoration and quarantine checks)")
    }
}
'''


def main():
    provider = (SOURCE / 'PacketTunnelProvider.swift').read_text()
    first = provider.index('    private final class StrategyRuntimeDriver:')
    last = provider.index('    private func enableForwarding(', first)
    driver = provider[first:last]
    original = '        private let queue = DispatchQueue('
    assert driver.count(original) == 1
    driver = driver.replace(original, '        let queue = DispatchQueue(', 1)
    protect = driver.index('        func protect(epoch: String)')
    signal = driver.index('            cancelMAXPreparation()', protect)
    no_immediate_cancel = driver[:signal] + driver[signal:].replace('            cancelMAXPreparation()', '            // mutation: cancellation deferred until queue admission', 1)
    close_before_proof = '                retireMAXPreparation(preparation); preparation = nil'
    assert driver.count(close_before_proof) == 1
    no_adoption_drain = driver.replace(close_before_proof, '                // mutation: retain preparation until after proof callback')
    with tempfile.TemporaryDirectory(prefix='router-ios-native-strategy-') as temporary:
        directory = Path(temporary)
        for name, source, accepted in [('shipping',driver,True), ('deferred-cancel',no_immediate_cancel,False), ('undrained-adoption',no_adoption_drain,False)]:
            harness = directory / (name + '.swift')
            harness.write_text(FIXTURE.replace('    // SHIPPING_DRIVER', source))
            binary = directory / name
            subprocess.run(['swiftc', '-swift-version', '6', '-parse-as-library',
                str(SOURCE / 'RouterVPNStrategyPolicy.swift'), str(SOURCE / 'RouterVPNProviderStrategy.swift'),
                str(harness), '-o', str(binary)], check=True, timeout=90)
            result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=20)
            if accepted:
                assert result.returncode == 0, result.stderr[-6000:]
                print(result.stdout.strip())
            else:
                assert result.returncode != 0, name + ' driver regression was accepted'
        print('Two compiled MAX cancellation/adoption regressions rejected')


if __name__ == '__main__':
    main()
