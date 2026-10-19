#!/usr/bin/env python3
"""Execute the shipping strategy IPC validation and once-only reply owner."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
TEST = r'''
import Foundation

@main struct Tests {
    @MainActor static func main() async throws {
        var checks = 0
        func check(_ label: String, _ value: @autoclosure () throws -> Bool) throws {
            guard try value() else { fatalError(label) }; checks += 1
        }
        func reject(_ label: String, _ operation: () throws -> Void) {
            do { try operation(); fatalError("Accepted " + label) } catch { checks += 1 }
        }
        let candidate = IOSStrategyCandidate(raw: "wg", logical: "base-raw")
        let other = IOSStrategyCandidate(raw: "awg2-fast", logical: "base-raw")
        let catalog = [candidate, other]
        let digest = String(repeating: "a", count: 64)
        let provider = UUID().uuidString, request = UUID().uuidString, epoch = UUID().uuidString
        let good: [String: Any] = ["version": 1, "provider_session": provider, "runtime_epoch": epoch,
            "request_id": request, "bundle_digest": digest, "kind": "smart", "phase": "connected",
            "outcome": "success", "node_proven": true, "dns_proven": true,
            "current_raw": "wg", "current_logical": "base-raw", "proven_raw": "wg", "proven_logical": "base-raw",
            "engine": "libbox", "attempt": 2, "candidate_count": 2, "message": "Both proofs passed."]
        func data(_ object: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: object) }
        func decode(_ object: [String: Any]) throws -> IOSStrategyStatus {
            try IOSStrategyWire.status(data(object), bundleDigest: digest, catalog: catalog,
                                       requestID: request, providerSession: provider)
        }
        try check("proven current owner", decode(good).isProven)
        for phase in ["starting", "trying", "proving", "restoring", "blocked", "stopped"] {
            var value = good; value["phase"] = phase; value["outcome"] = ["blocked", "stopped"].contains(phase) ? "blocked" : "pending"
            value["node_proven"] = false; value["dns_proven"] = false
            value["proven_raw"] = ""; value["proven_logical"] = ""
            try check("unproven phase " + phase, !decode(value).isProven)
            value["node_proven"] = true; value["dns_proven"] = true
            reject("premature proof in " + phase) { _ = try decode(value) }
        }
        var cancelled = good; cancelled["phase"] = "cancelled"; cancelled["outcome"] = "cancelled"
        try check("cancel can retain proven protected owner", decode(cancelled).isProven)
        var restored = good; restored["outcome"] = "restored"
        try check("restoration differs from requested success", decode(restored).outcome == .restored)
        let invalid: [(String, Any)] = [
            ("version", true), ("version", 2), ("provider_session", UUID().uuidString),
            ("request_id", UUID().uuidString), ("bundle_digest", String(repeating: "b", count: 64)),
            ("runtime_epoch", ""), ("runtime_epoch", "other"), ("engine", "wireguard"),
            ("attempt", -1), ("attempt", 0), ("attempt", 129), ("attempt", 1.5),
            ("candidate_count", 0), ("candidate_count", 3), ("candidate_count", true),
            ("phase", "unknown"), ("phase", "trying"), ("kind", "unknown"),
            ("node_proven", false), ("dns_proven", false), ("dns_proven", 1),
            ("proven_raw", "awg2-fast"), ("proven_logical", "other"), ("current_raw", "other"),
            ("current_logical", "other"), ("message", String(repeating: "x", count: 513)),
            ("message", "nul\u{0}"), ("extra", "secret")]
        for (key, value) in invalid { var mutated = good; mutated[key] = value
            reject("invalid status " + key + String(describing: value).prefix(20)) { _ = try decode(mutated) }
        }
        for key in good.keys { var mutated = good; mutated.removeValue(forKey: key)
            reject("missing " + key) { _ = try decode(mutated) }
        }
        reject("oversized reply") { _ = try IOSStrategyWire.status(Data(repeating: 32, count: 8193), bundleDigest: digest, catalog: catalog) }
        let plan = try IOSStrategyPlan(kind: .smart, candidates: catalog, preferredRaw: other.raw)
        try check("preferred SMART remains captured", try plan.object()["preferred_raw"] as? String == other.raw)
        reject("duplicate runtime") { _ = try IOSStrategyPlan(kind: .automatic, candidates: [candidate, candidate]) }
        reject("empty plan") { _ = try IOSStrategyPlan(kind: .automatic, candidates: []) }
        reject("multiple manual candidates") { _ = try IOSStrategyPlan(kind: .manual, candidates: catalog) }
        reject("mixed logical selection") { _ = try IOSStrategyPlan(kind: .logical, candidates: [candidate, .init(raw: "shadowsocks", logical: "ss")]) }
        reject("foreign preferred") { _ = try IOSStrategyPlan(kind: .smart, candidates: catalog, preferredRaw: "foreign") }
        reject("preferred manual") { _ = try IOSStrategyPlan(kind: .manual, candidates: [candidate], preferredRaw: candidate.raw) }
        for value in ["", "../wg", "wg/peer", "wg..peer", "wg key", String(repeating: "w", count: 97), "🗝"] {
            reject("unsafe candidate") { _ = try IOSStrategyPlan(kind: .manual, candidates: [.init(raw: value, logical: "base")]) }
        }
        let object: [String: Any] = ["version": 1, "candidates": [["raw": "wg", "logical": "base-raw"], ["raw": "awg2-fast", "logical": "base-raw"]]]
        try check("catalog round trip", IOSStrategyWire.catalog(["strategy_catalog": object]) == catalog)
        for (key, value) in [("version", true as Any), ("version", 2), ("secret", "credential"), ("candidates", [])] {
            var invalid = object; invalid[key] = value
            reject("bad catalog " + key) { _ = try IOSStrategyWire.catalog(["strategy_catalog": invalid]) }
        }
        func identity(_ owner: String = provider, _ generation: String = epoch) throws -> IOSSessionIdentity {
            try IOSSessionIdentity(connectedAt: Date(timeIntervalSince1970: 1), engine: "libbox", rawProfile: "wg",
                bundleData: Data("frozen bundle".utf8), entryBundleData: nil, providerSession: owner, runtimeEpoch: generation)
        }
        let original = try identity()
        try check("same epoch matches", original == identity())
        try check("same labels new generation differs", original != identity(provider, UUID().uuidString))
        try check("new provider differs", original != identity(UUID().uuidString, epoch))
        reject("partial epoch identity") { _ = try IOSSessionIdentity(connectedAt: Date(), engine: "libbox", rawProfile: "wg", bundleData: Data([1]), entryBundleData: nil, providerSession: provider) }
        reject("foreign engine epoch") { _ = try IOSSessionIdentity(connectedAt: Date(), engine: "wireguard", rawProfile: "wg", bundleData: Data([1]), entryBundleData: nil, providerSession: provider, runtimeEpoch: epoch) }
        // Cancellation before registration and simultaneous late replies may
        // resume exactly once; neither can resurrect a cancelled IPC request.
        let early = IOSStrategyReply(); early.finish(nil, cancelled: true)
        do { let _: Data = try await withCheckedThrowingContinuation { _ = early.install($0) }; fatalError("early cancel accepted") }
        catch is CancellationError { checks += 1 }
        for _ in 0..<30 {
            let reply = IOSStrategyReply()
            let value: Data = try await withCheckedThrowingContinuation { continuation in
                guard reply.install(continuation) else { fatalError("fresh reply already finished") }
                DispatchQueue.concurrentPerform(iterations: 8) { _ in reply.finish(Data([42])) }
            }
            try check("concurrent reply delivered once", value == Data([42]))
            reply.finish(nil, cancelled: true)
        }
        print("iOS owned strategy session: PASS (\(checks) executable checks)")
    }
}
'''

def main():
    swift = shutil.which('swiftc')
    if not swift:
        raise SystemExit('swiftc required for the shipping strategy session checks')
    with tempfile.TemporaryDirectory(prefix='routervpn-strategy-session-') as tmp:
        source = Path(tmp) / 'Tests.swift'
        binary = Path(tmp) / 'strategy-session'
        source.write_text(TEST)
        subprocess.run([swift, '-swift-version', '6', str(APP / 'IOSStrategySession.swift'),
                        str(APP / 'IOSSessionIdentity.swift'), str(source), '-o', str(binary)], check=True, timeout=120)
        subprocess.run([str(binary)], check=True, timeout=30)

if __name__ == '__main__':
    main()
