#!/usr/bin/env python3
"""Execute the shipping provider strategy owner with controlled native callbacks.

The real policy parser, candidate loop, restoration/cancellation state and IPC
are compiled by Swift 6. Only NetworkExtension/Libbox operations are doubled.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'ios/RouterVPN/PacketTunnel'
TEST = r'''
import Foundation

final class Settings { let name: String; init(_ name: String) { self.name = name } }

final class Driver: RouterVPNStrategyDriver, @unchecked Sendable {
    struct Pending {
        let attempt: RouterVPNStrategyAttempt
        let proving: @Sendable () -> Void
        let done: @Sendable (Result<RouterVPNStrategyProof, Error>) -> Void
    }
    var pending: [Pending] = []
    var activated: [RouterVPNStrategyAttempt] = []
    var holds: [String] = []
    var deferActivation = false
    var activation: (@Sendable (Error?) -> Void)?
    func replace(_ attempt: RouterVPNStrategyAttempt, proving: @escaping @Sendable () -> Void,
                 completion: @escaping @Sendable (Result<RouterVPNStrategyProof, Error>) -> Void) {
        pending.append(Pending(attempt: attempt, proving: proving, done: completion))
    }
    func activate(_ attempt: RouterVPNStrategyAttempt, completion: @escaping @Sendable (Error?) -> Void) {
        activated.append(attempt)
        if deferActivation { activation = completion } else { completion(nil) }
    }
    func protect(epoch: String) { holds.append(epoch) }
    func pass(_ index: Int, node: String = String(repeating: "a", count: 64), dns: Bool = true) {
        pending[index].proving()
        pending[index].done(.success(RouterVPNStrategyProof(nodeID: node, dns: dns)))
    }
    func fail(_ index: Int) {
        pending[index].done(.failure(NSError(domain: "Fixture", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "SECRET-PROFILE-MATERIAL"])))
    }
}

@main struct Main {
    static let digest = String(repeating: "b", count: 64)
    static let node = String(repeating: "a", count: 64)
    static func reference(_ raw: String, _ logical: String? = nil) -> [String: String] {
        ["raw": raw, "logical": logical ?? raw]
    }
    static func capture(_ raws: [String], profile overrides: [String: Any] = [:], logical: [[String: Any]] = [],
                        refs: [[String: String]]? = nil) throws -> RouterVPNStrategyPolicy {
        var profile: [String: Any] = ["id": "home", "node_kind": "router-vpn"]
        for (key, value) in overrides { profile[key] = value }
        var files: [String: [String: String]] = [:]
        for raw in raws { files[raw] = ["sing-box.json": Data("{}".utf8).base64EncodedString()] }
        let root: [String: Any] = ["selectedRouterID": "home", "profiles": files, "logicalModes": logical]
        return try RouterVPNStrategyPolicy(catalog: ["version": 1, "candidates": refs ?? raws.map { reference($0) }], root: root, profile: profile)
    }
    static func request(_ kind: String, _ raws: [String], preferred: String? = nil,
                        id: String = UUID().uuidString, refs: [[String: String]]? = nil) -> [String: Any] {
        var value: [String: Any] = ["version": 1, "request_id": id, "kind": kind,
                                  "candidates": refs ?? raws.map { reference($0) }]
        if let preferred { value["preferred_raw"] = preferred }
        return value
    }
    static func message(_ value: [String: Any]) -> Data { try! JSONSerialization.data(withJSONObject: value) }
    static func status(_ owner: RouterVPNProviderStrategy) -> [String: Any] {
        let response = owner.handle(message(["operation": "strategy-status", "bundle_digest": digest]))!
        return try! JSONSerialization.jsonObject(with: response) as! [String: Any]
    }
    static func start(_ kind: String, _ raws: [String], preferred: String? = nil,
                      profile: [String: Any] = [:]) throws -> (RouterVPNProviderStrategy, Driver) {
        let policy = try capture(raws, profile: profile)
        let plan = try policy.plan(request(kind, raws, preferred: preferred), initial: true)
        let driver = Driver()
        let owner = try RouterVPNProviderStrategy(policy: policy, plan: plan, bundleDigest: digest, nodeID: node, driver: driver)
        owner.start(); return (owner, driver)
    }
    static func cancel(_ owner: RouterVPNProviderStrategy) -> Data? {
        owner.handle(message(["operation": "strategy-cancel", "request_id": status(owner)["request_id"]!, "provider_session": owner.providerSession]))
    }
    static func run(_ owner: RouterVPNProviderStrategy, _ strategy: [String: Any], previous: String? = nil) -> Data? {
        owner.handle(message(["operation": "strategy-run", "request_id": previous ?? status(owner)["request_id"] as! String,
                              "provider_session": owner.providerSession, "strategy": strategy]))
    }
    static func main() throws {
        var checks = 0
        func check(_ label: String, _ value: @autoclosure () -> Bool) {
            guard value() else { fatalError(label) }; checks += 1
        }
        func rejects(_ label: String, _ body: () throws -> Void) {
            do { try body(); fatalError(label) } catch { checks += 1 }
        }

        // Initial AUTO owns one provider and a different native epoch for every
        // candidate. A delayed proof from the first core cannot adopt the second.
        let (auto, ad) = try start("auto", ["wg", "shadowsocks"])
        check("starts unproved", status(auto)["phase"] as? String == "trying" && status(auto)["proven_raw"] as? String == "")
        let first = ad.pending[0].attempt.epoch
        ad.fail(0)
        check("next owned candidate", ad.pending.count == 2 && ad.pending[1].attempt.candidate.raw == "shadowsocks" && ad.pending[1].attempt.epoch != first)
        ad.pass(0)
        check("stale first proof cannot activate", ad.activated.isEmpty && status(auto)["proven_raw"] as? String == "")
        ad.pass(1)
        check("exact second candidate proved", status(auto)["phase"] as? String == "connected" && status(auto)["proven_raw"] as? String == "shadowsocks")
        check("both proof predicates exposed", status(auto)["dns_proven"] as? Bool == true && status(auto)["node_proven"] as? Bool == true)
        check("same immutable digest", status(auto)["bundle_digest"] as? String == digest)
        check("no candidate error material in IPC", !String(data: auto.handle(message(["operation": "strategy-status", "bundle_digest": digest]))!, encoding: .utf8)!.contains("SECRET"))
        check("one final activation", ad.activated.count == 1 && ad.holds.isEmpty)

        for failure in ["node", "dns"] {
            let (owner, driver) = try start("auto", ["wg", "shadowsocks"])
            driver.pass(0, node: failure == "node" ? String(repeating: "c", count: 64) : node, dns: failure != "dns")
            check("wrong \(failure) proof never connects", driver.pending.count == 2 && driver.activated.isEmpty && status(owner)["proven_raw"] as? String == "")
            driver.fail(1)
            check("exhaustion retains protection", status(owner)["phase"] as? String == "blocked" && driver.holds.count == 1 && status(owner)["node_proven"] as? Bool == false)
        }

        // SMART re-proves the remembered configuration, visits only compatible
        // reduction edges, restores it after a failed edge, and proves restoration.
        let (smart, sd) = try start("smart", ["naive-h3", "hysteria2", "naive-h2", "max"], preferred: "naive-h3")
        sd.pass(0)
        check("remembered mode precedes reduction", sd.pending.map { $0.attempt.candidate.raw } == ["naive-h3", "hysteria2"])
        sd.fail(1)
        check("failed edge restores exact immutable good", sd.pending[2].attempt.candidate.raw == "naive-h3" && sd.pending[2].attempt.restoring && status(smart)["proven_raw"] as? String == "")
        sd.pass(1)
        check("late failed-edge completion ignored", sd.pending.count == 3 && sd.activated.isEmpty)
        sd.pass(2)
        check("restoration itself must pass before next edge", sd.pending[3].attempt.candidate.raw == "naive-h2")
        sd.pass(3)
        check("SMART settles on compatible proved reduction", status(smart)["proven_raw"] as? String == "naive-h2" && sd.activated.count == 1)
        check("unrelated candidate not a simplification", !sd.pending.contains { $0.attempt.candidate.raw == "max" })

        let (cancelled, cd) = try start("smart", ["naive-h3", "hysteria2"], preferred: "naive-h3")
        cd.pass(0)
        let oldEpoch = cd.pending[1].attempt.epoch
        check("cancel request accepted", cancel(cancelled) != nil)
        check("cancel restores fresh native owner", cd.pending[2].attempt.candidate.raw == "naive-h3" && cd.pending[2].attempt.epoch != oldEpoch)
        cd.pass(1)
        check("cancelled candidate cannot win", status(cancelled)["proven_raw"] as? String == "")
        cd.pass(2)
        check("cancelled restoration remains proven and protected", status(cancelled)["phase"] as? String == "cancelled" && status(cancelled)["proven_raw"] as? String == "naive-h3" && cd.holds.isEmpty)
        check("repeat cancel retains good owner", cancel(cancelled) != nil && cd.pending.count == 3 && cd.holds.isEmpty)

        let (early, ed) = try start("auto", ["wg", "shadowsocks"])
        _ = cancel(early); ed.pass(0)
        check("cancel before proof stays a protected sink", status(early)["phase"] as? String == "cancelled" && status(early)["proven_raw"] as? String == "" && ed.holds.count == 1 && ed.pending.count == 1)

        let (restoreFailure, fd) = try start("smart", ["naive-h3", "hysteria2"], preferred: "naive-h3")
        fd.pass(0); fd.fail(1); fd.fail(2)
        check("failed restoration is never reported connected", status(restoreFailure)["phase"] as? String == "blocked" && status(restoreFailure)["proven_raw"] as? String == "" && fd.holds.count == 1)

        // Later requests can only select captured references and must name the
        // current provider + request owner. Restarted apps may discover status
        // by the exact original configuration digest without changing anything.
        let previousRequest = status(auto)["request_id"] as! String
        let next = request("auto", ["wg"])
        check("owned run IPC accepted", run(auto, next) != nil)
        check("busy replacement denied", run(auto, request("auto", ["shadowsocks"])) == nil)
        check("old request poll denied", auto.handle(message(["operation": "strategy-status", "request_id": previousRequest])) == nil)
        check("wrong provider poll denied", auto.handle(message(["operation": "strategy-status", "request_id": next["request_id"]!, "provider_session": UUID().uuidString])) == nil)
        check("wrong digest discovery denied", auto.handle(message(["operation": "strategy-status", "bundle_digest": String(repeating: "0", count: 64)])) == nil)
        check("stale cancel denied", auto.handle(message(["operation": "strategy-cancel", "request_id": previousRequest, "provider_session": auto.providerSession])) == nil)
        ad.fail(2)
        check("failed request restores previous proved configuration", ad.pending[3].attempt.candidate.raw == "shadowsocks" && ad.pending[3].attempt.restoring)
        ad.pass(3)
        check("restoration does not claim requested AUTO succeeded", status(auto)["outcome"] as? String == "restored" && status(auto)["proven_raw"] as? String == "shadowsocks")
        check("late earlier run cannot replace newer request", run(auto, request("auto", ["wg"]), previous: previousRequest) == nil)
        check("request UUID replay denied", run(auto, next) == nil)
        var injection = request("auto", ["wg"]); injection["files"] = ["sing-box.json": "attacker"]
        check("IPC never accepts replacement assets", run(auto, injection) == nil)
        check("IPC cannot select missing catalog candidate", run(auto, request("auto", ["max"])) == nil)

        let provedEpoch = status(auto)["runtime_epoch"] as! String
        auto.invalidate(epoch: provedEpoch)
        check("path change discards proof before asynchronous recovery", status(auto)["proven_raw"] as? String == "" && ad.pending[4].attempt.restoring)
        auto.invalidate(epoch: provedEpoch)
        check("old path event cannot invalidate replacement", ad.pending.count == 5)
        ad.pass(4)
        check("fresh path re-proved", status(auto)["phase"] as? String == "connected" && status(auto)["runtime_epoch"] as? String != provedEpoch)
        auto.stop(); ad.pass(4)
        check("late callback cannot restart stopped provider", status(auto)["phase"] as? String == "stopped" && status(auto)["proven_raw"] as? String == "")

        let (duringActivation, da) = try start("manual", ["wg"])
        da.deferActivation = true; da.pass(0)
        check("no proven status before owner activation", status(duringActivation)["phase"] as? String == "proving" && status(duringActivation)["proven_raw"] as? String == "")
        _ = cancel(duringActivation)
        da.activation?(nil)
        check("stale final activation cannot claim connection", status(duringActivation)["proven_raw"] as? String == "" && da.pending.count == 2)

        // Policy validation is run in the provider, even when the app already
        // checked the same choices. Explicit selections do not inherit AUTO filters.
        let strict = try capture(["wg", "awg2-fast"], profile: ["auto_require_encrypted": true, "auto_require_obfuscation": true])
        _ = try strict.plan(request("manual", ["wg"]), initial: true); checks += 1
        rejects("AUTO obfuscation must be enforced") { _ = try strict.plan(request("auto", ["wg"]), initial: true) }
        _ = try strict.plan(request("auto", ["awg2-fast"]), initial: true); checks += 1
        rejects("manual cannot cycle raws") { _ = try strict.plan(request("manual", ["wg", "awg2-fast"]), initial: true) }
        let custom = try capture(["wg", "awg2-fast"], profile: ["custom_layers": ["amneziawg2", "light-obfuscation"]])
        _ = try custom.plan(request("custom", ["awg2-fast"]), initial: true); checks += 1
        rejects("CUSTOM cannot omit requested layer") { _ = try custom.plan(request("custom", ["wg"]), initial: true) }
        rejects("unknown kind rejected") { _ = try custom.plan(request("silent-fallback", ["wg"]), initial: true) }
        var malformed = request("manual", ["wg"]); malformed["version"] = true
        rejects("boolean is not schema version") { _ = try custom.plan(malformed, initial: true) }
        malformed = request("manual", ["wg"]); malformed["request_id"] = "not-a-uuid"
        rejects("request owner must be a UUID") { _ = try custom.plan(malformed, initial: true) }
        rejects("duplicate candidates rejected") { _ = try custom.plan(request("auto", ["wg", "wg"]), initial: true) }
        rejects("oversized catalog rejected") { _ = try capture(Array(repeating: "wg", count: 33), refs: Array(repeating: reference("wg"), count: 33)) }
        rejects("external node cannot acquire Router VPN strategy") { _ = try capture(["wg"], profile: ["node_kind": "external"]) }
        rejects("multihop cannot acquire single-node strategy") { _ = try capture(["wg"], profile: ["multihop_enabled": true]) }

        let logical: [[String: Any]] = [["id": "base", "variants": ["wg": "wg", "awg": "awg2-fast"], "base_selector": true, "fallback": true]]
        let refs = [reference("wg", "base"), reference("awg2-fast", "base")]
        let fixed = try capture(["wg", "awg2-fast"], profile: ["base_tunnel": "wg", "base_fallback": false], logical: logical, refs: refs)
        _ = try fixed.plan(request("logical", ["wg"], refs: [refs[0]]), initial: true); checks += 1
        rejects("logical cannot invent base fallback") { _ = try fixed.plan(request("logical", ["wg", "awg2-fast"], refs: refs), initial: true) }
        let fallback = try capture(["wg", "awg2-fast"], profile: ["base_tunnel": "awg", "base_fallback": true], logical: logical, refs: refs)
        _ = try fallback.plan(request("logical", ["awg2-fast", "wg"], refs: Array(refs.reversed())), initial: true); checks += 1
        rejects("logical fallback preserves exact order") { _ = try fallback.plan(request("logical", ["wg", "awg2-fast"], refs: refs), initial: true) }
        rejects("logical cannot omit a captured preferred base") { _ = try fallback.plan(request("logical", ["wg"], refs: [refs[0]]), initial: true) }

        let maxRaws = ["max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"]
        let maxRefs = maxRaws.map { reference($0, $0.hasPrefix("max-tls-") ? "max-tls" : "max-quic") }
        let maxLogical: [[String: Any]] = [
            ["id": "all", "variants": ["wg": "all", "awg": "all"], "base_selector": true, "fallback": true],
            ["id": "max-tls", "variants": ["wg": "max-tls-wg", "awg": "max-tls-awg"], "base_selector": true, "fallback": true],
            ["id": "max-quic", "variants": ["wg": "max-quic-wg", "awg": "max-quic-awg"], "base_selector": true, "fallback": true]
        ]
        let all = try capture(maxRaws, logical: maxLogical, refs: maxRefs)
        _ = try all.plan(request("all", maxRaws, refs: maxRefs), initial: true); checks += 1
        _ = try all.plan(request("all", maxRaws, refs: maxRefs), initial: false); checks += 1
        rejects("ALL cannot prefer QUIC before a captured TLS branch") { _ = try all.plan(request("all", maxRaws, refs: Array(maxRefs.reversed())), initial: true) }
        rejects("ALL cannot silently omit a preparable branch") { _ = try all.plan(request("all", [maxRaws[0]], refs: [maxRefs[0]]), initial: true) }
        let allAWG = try capture(maxRaws, profile: ["base_tunnel": "awg", "base_fallback": false], logical: maxLogical, refs: maxRefs)
        _ = try allAWG.plan(request("all", [maxRaws[1], maxRaws[3]], refs: [maxRefs[1], maxRefs[3]]), initial: true); checks += 1
        rejects("ALL cannot invent a disallowed WG fallback") { _ = try allAWG.plan(request("all", maxRaws, refs: maxRefs), initial: true) }
        let partialMAX = try capture([maxRaws[2]], logical: maxLogical, refs: [maxRefs[2]])
        _ = try partialMAX.plan(request("all", [maxRaws[2]], refs: [maxRefs[2]]), initial: true); checks += 1
        rejects("ALL cannot downgrade to a weaker family") { _ = try fallback.plan(request("all", ["wg"], refs: [refs[0]]), initial: true) }

        let (quarantined, qd) = try start("auto", ["wg", "shadowsocks"])
        let failedEpoch = qd.pending[0].attempt.epoch
        quarantined.teardownFailed(epoch: failedEpoch)
        qd.pass(0)
        check("teardown failure blocks without a replacement", status(quarantined)["phase"] as? String == "blocked" && qd.pending.count == 1 && qd.holds.count == 1)
        quarantined.teardownFailed(epoch: failedEpoch)
        check("stale teardown callback cannot replace protection", qd.holds.count == 1)

        // Real settings queue: a late OS callback cannot overwrite the newest
        // configuration. Only non-nil full settings can enter this interface.
        var osCalls: [(Settings, (Error?) -> Void)] = []
        let settings = RouterVPNSettingsQueue<Settings> { value, callback in osCalls.append((value, callback)) }
        var settingsResults: [String: Bool] = [:]
        settings.begin(epoch: "old")
        settings.submit(Settings("old"), epoch: "old") { settingsResults["old"] = $0 == nil }
        settings.begin(epoch: "current")
        settings.submit(Settings("current"), epoch: "current") { settingsResults["current"] = $0 == nil }
        check("OS settings calls remain serial across generations", osCalls.count == 1)
        osCalls[0].1(nil)
        check("old OS completion is not adopted", settingsResults["old"] == false && osCalls.count == 2 && osCalls[1].0.name == "current")
        osCalls[0].1(nil)
        check("duplicate OS callback cannot resubmit settings", osCalls.count == 2)
        settings.retire(epoch: "old")
        osCalls[1].1(nil)
        check("old cleanup cannot retire current settings", settingsResults["current"] == true && settings.current("current"))
        settings.submit(Settings("old-again"), epoch: "old") { settingsResults["stale-submit"] = $0 == nil }
        check("retired platform cannot reapply DNS settings", settingsResults["stale-submit"] == false && osCalls.count == 2)
        settings.retire(epoch: "current")
        check("explicit retirement leaves no mutable platform owner", !settings.current("current"))
        print("Shipping iOS provider strategy: PASS (\(checks) executable policy, proof, ownership and cancellation checks)")
    }
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='router-ios-strategy-') as temporary:
        directory = Path(temporary)
        harness = directory / 'main.swift'
        harness.write_text(TEST)
        binary = directory / 'strategy-tests'
        subprocess.run([
            'swiftc', '-swift-version', '6', '-parse-as-library',
            str(SOURCE / 'RouterVPNStrategyPolicy.swift'),
            str(SOURCE / 'RouterVPNProviderStrategy.swift'), str(SOURCE / 'RouterVPNSettingsQueue.swift'),
            str(harness), '-o', str(binary),
        ], check=True, timeout=45)
        subprocess.run([str(binary)], check=True, timeout=15)

if __name__ == '__main__':
    main()
