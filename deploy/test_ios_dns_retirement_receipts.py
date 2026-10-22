#!/usr/bin/env python3
"""Execute the shipping Apple cleanup-receipt store against a real filesystem.

This tests lost-IPC recovery evidence, identity, atomicity and bounded private
storage. It does not establish physical NetworkExtension or signing behavior.
"""
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "ios/RouterVPN/App/IOSDNSRetirementReceipts.swift"

FIXTURE = r'''
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

struct Failed: Error { let description: String }
final class Check: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func that(_ label: String, _ condition: Bool) throws {
        guard condition else { throw Failed(description: label) }
        lock.lock(); count += 1; lock.unlock()
    }
    func rejects(_ label: String, _ operation: () throws -> Void) throws {
        do { try operation() } catch { try that(label, true); return }
        throw Failed(description: label)
    }
    func summary() -> Int { lock.lock(); defer { lock.unlock() }; return count }
}
final class Clock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: TimeInterval = 1_790_000_000
    func now() -> Date { lock.lock(); defer { lock.unlock() }; return Date(timeIntervalSince1970: value) }
    func advance(_ seconds: TimeInterval) { lock.lock(); value += seconds; lock.unlock() }
}
final class Outcomes: @unchecked Sendable {
    private let lock = NSLock()
    private var failures = 0
    func record(_ good: Bool) { lock.lock(); if !good { failures += 1 }; lock.unlock() }
    func count() -> Int { lock.lock(); defer { lock.unlock() }; return failures }
}

@main struct Main {
    static let epoch = "2B08908E-0FF4-498F-AE54-9FE1A27147C9"
    static let proof = "BB200B6A-5EF7-40AD-9C84-E1BD22512400"
    static let request = String(repeating: "a", count: 32)

    static func payload(_ changes: [String: Any] = [:]) throws -> Data {
        var value: [String: Any] = ["schema": 1, "request_id": request, "ack_id": request,
            "node_id": "external-node", "session_id": epoch, "native_session_id": proof,
            "complete": true, "drained": true, "stage": "complete", "public_transport": "tls",
            "results": [["median_ms": 12.5, "address": "1.1.1.1"]],
            "api_token": "must-never-be-stored", "private_source": "another-secret"]
        for (key, replacement) in changes { value[key] = replacement }
        return try JSONSerialization.data(withJSONObject: value)
    }
    static func main() throws {
        let checks = Check(), clock = Clock(), fm = FileManager.default
        let container = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try fm.createDirectory(at: container, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let owner = IOSDNSRetirementReceipts(container: container, now: { clock.now() })
        try owner.requireAvailable()
        try checks.that("preflight never publishes a cleanup acknowledgement",
            try fm.contentsOfDirectory(atPath: container.appendingPathComponent("DNSRetirement").path).isEmpty)
        func recovered(_ session: String = epoch, _ native: String = proof, _ nonce: String = request, _ node: String = "external-node") -> Data? {
            owner.drained(providerSession: session, nativeSession: native, request: nonce, nodeID: node)
        }
        try checks.that("absence is not an acknowledgement", recovered() == nil)
        let original = try payload()
        try owner.storeDrained(original)
        guard let response = recovered(), let value = try JSONSerialization.jsonObject(with: response) as? [String: Any] else {
            throw Failed(description: "lost IPC must recover a committed exact cleanup acknowledgement")
        }
        try checks.that("recovery is complete and drained", value["complete"] as? Bool == true && value["drained"] as? Bool == true)
        try checks.that("recovery cannot publish timing", (value["results"] as? [Any])?.isEmpty == true && value["stage"] as? String == "cancelled" && value["failure"] is String)
        let directory = container.appendingPathComponent("DNSRetirement", isDirectory: true)
        let file = directory.appendingPathComponent("dns-\(epoch.lowercased())-\(request).json")
        let encoded = try Data(contentsOf: file), text = String(decoding: encoded, as: UTF8.self)
        for forbidden in ["must-never-be-stored", "another-secret", "results", "median_ms", "1.1.1.1", "public_transport"] {
            try checks.that("private or measurement fields are discarded: \(forbidden)", !text.contains(forbidden))
        }
        let directoryMode = try fm.attributesOfItem(atPath: directory.path)[.posixPermissions] as? NSNumber
        let fileMode = try fm.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber
        try checks.that("directory and file are private", directoryMode?.intValue == 0o700 && fileMode?.intValue == 0o600)
        try checks.that("different provider epoch is not drained", recovered(UUID().uuidString) == nil)
        try checks.that("different native proof is not drained", recovered(epoch, UUID().uuidString) == nil)
        try checks.that("different nonce is not drained", recovered(epoch, proof, String(repeating: "b", count: 32)) == nil)
        try checks.that("different selected node is not drained", recovered(epoch, proof, request, "other-node") == nil)

        for changes: [String: Any] in [
            ["complete": false], ["drained": false], ["complete": 1], ["drained": 1],
            ["schema": 2], ["ack_id": String(repeating: "b", count: 32)],
            ["request_id": "../escape", "ack_id": "../escape"],
            ["request_id": String(repeating: "A", count: 32), "ack_id": String(repeating: "A", count: 32)],
            ["session_id": "bad-epoch"], ["native_session_id": "bad-proof"],
            ["node_id": "../other-owner"], ["node_id": ""], ["node_id": String(repeating: "n", count: 129)]
        ] {
            try checks.rejects("unacknowledged or malformed native receipt \(changes)") { try owner.storeDrained(payload(changes)) }
            try checks.that("rejected receipt leaves original bytes intact", try Data(contentsOf: file) == encoded)
        }
        try checks.rejects("oversized native receipt") { try owner.storeDrained(Data(repeating: 32, count: 65537)) }
        clock.advance(60)
        try owner.storeDrained(original)
        try checks.that("idempotent acknowledgement does not extend retention", try Data(contentsOf: file) == encoded)
        clock.advance(IOSDNSRetirementReceipts.maximumAge)
        try checks.that("expired receipt cannot release an owner", recovered() == nil)
        try owner.storeDrained(original)
        try checks.that("fresh native drain can replace expired evidence", recovered() != nil)
        clock.advance(-301)
        try checks.that("receipt from a future clock is rejected", recovered() == nil)
        clock.advance(301)

        let good = try Data(contentsOf: file)
        try Data("{\"incomplete\":".utf8).write(to: file)
        try checks.that("torn or malformed receipt cannot release", recovered() == nil)
        try good.write(to: file)
        try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        try checks.that("publicly readable receipt is rejected", recovered() == nil)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        try Data(repeating: 0, count: 4097).write(to: file)
        try checks.that("oversized stored receipt is rejected", recovered() == nil)
        try good.write(to: file)
        let other = container.appendingPathComponent("unrelated-file")
        try Data("unrelated owner".utf8).write(to: other)
        try fm.removeItem(at: file)
        try fm.createSymbolicLink(at: file, withDestinationURL: other)
        try checks.that("receipt symlink cannot release", recovered() == nil)
        try owner.storeDrained(original)
        try checks.that("atomic replacement does not modify symlink target", try String(contentsOf: other, encoding: .utf8) == "unrelated owner")
        try checks.that("legitimate replacement can recover", recovered() != nil)
        let hard = container.appendingPathComponent("hard-link")
        try checks.that("hard-link fixture", link(file.path, hard.path) == 0)
        try checks.that("receipt hard link is rejected", recovered() == nil)
        try fm.removeItem(at: hard)
        try fm.removeItem(at: file)
        try checks.that("FIFO fixture", mkfifo(file.path, mode_t(0o600)) == 0)
        try checks.that("receipt FIFO cannot block or release", recovered() == nil)
        try fm.removeItem(at: file)
        try owner.storeDrained(original)

        let second = container.appendingPathComponent("second", isDirectory: true)
        try fm.createDirectory(at: second, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try fm.createSymbolicLink(at: second.appendingPathComponent("DNSRetirement"), withDestinationURL: directory)
        let wrongDirectory = IOSDNSRetirementReceipts(container: second, now: { clock.now() })
        try checks.rejects("symlink directory cannot receive evidence") { try wrongDirectory.storeDrained(original) }
        try checks.that("symlink directory cannot return evidence", wrongDirectory.drained(providerSession: epoch, nativeSession: proof, request: request, nodeID: "external-node") == nil)
        let unavailable = IOSDNSRetirementReceipts(container: nil)
        try checks.rejects("missing capability rejects before native work starts") { try unavailable.requireAvailable() }
        try checks.rejects("missing entitlement is not a working store") { try unavailable.storeDrained(original) }
        try checks.that("missing container never acknowledges", unavailable.drained(providerSession: epoch, nativeSession: proof, request: request, nodeID: "external-node") == nil)

        let outcomes = Outcomes()
        DispatchQueue.concurrentPerform(iterations: 32) { index in
            let nonce = String(format: "%032x", index + 1)
            do {
                let peer = IOSDNSRetirementReceipts(container: container, now: { clock.now() })
                try peer.storeDrained(payload(["request_id": nonce, "ack_id": nonce]))
                outcomes.record(peer.drained(providerSession: epoch, nativeSession: proof, request: nonce, nodeID: "external-node") != nil)
            } catch { outcomes.record(false) }
        }
        try checks.that("independent concurrent owners publish atomic complete records", outcomes.count() == 0)
        let foreign = directory.appendingPathComponent("foreign.json")
        try Data("do not prune".utf8).write(to: foreign)
        let foreignLink = directory.appendingPathComponent("dns-foreign.json")
        try fm.createSymbolicLink(at: foreignLink, withDestinationURL: other)
        for index in 1...(IOSDNSRetirementReceipts.maximumRecords + 4) {
            clock.advance(1)
            let nonce = String(format: "%032x", index + 1000)
            try owner.storeDrained(payload(["request_id": nonce, "ack_id": nonce]))
        }
        let names = try fm.contentsOfDirectory(atPath: directory.path)
        let receipts = names.filter { $0.hasPrefix("dns-" + epoch.lowercased()) && $0.hasSuffix(".json") }
        try checks.that("valid receipt storage remains bounded", receipts.count == IOSDNSRetirementReceipts.maximumRecords)
        try checks.that("pruning preserves foreign files", try String(contentsOf: foreign, encoding: .utf8) == "do not prune")
        try checks.that("pruning preserves foreign links", try fm.destinationOfSymbolicLink(atPath: foreignLink.path) == other.path)
        let latest = String(format: "%032x", IOSDNSRetirementReceipts.maximumRecords + 1004)
        try checks.that("pruning retains the newly acknowledged owner", recovered(epoch, proof, latest) != nil)
        clock.advance(IOSDNSRetirementReceipts.maximumAge + 1)
        let final = String(repeating: "f", count: 32)
        try owner.storeDrained(payload(["request_id": final, "ack_id": final]))
        let remaining = try fm.contentsOfDirectory(atPath: directory.path).filter { $0.hasPrefix("dns-" + epoch.lowercased()) }
        try checks.that("stale owned evidence is pruned", remaining.count == 1 && recovered(epoch, proof, final) != nil)
        print("Apple DNS retirement receipts: PASS (\(checks.summary()) shipping Swift filesystem checks)")
    }
}
'''


def main():
    swift = shutil.which("swiftc")
    if not swift:
        raise SystemExit("swiftc required")
    for name in ("RouterVPN", "PacketTunnel"):
        entitlement = ROOT / f"ios/RouterVPN/Resources/{name}.entitlements"
        with entitlement.open("rb") as handle:
            value = plistlib.load(handle)
        assert value["com.apple.security.application-groups"] == ["group.com.eabusham.routervpn"]
        assert "packet-tunnel-provider" in value["com.apple.developer.networking.networkextension"]
    assert "App/IOSDNSRetirementReceipts.swift" in (ROOT / "ios/RouterVPN/project.yml").read_text()
    with tempfile.TemporaryDirectory(prefix="routervpn-dns-retirement-") as folder:
        work = Path(folder)
        fixture = work / "Main.swift"
        fixture.write_text(FIXTURE)

        def compile_run(source, label, expected, failure_marker=""):
            binary = work / label
            subprocess.run([swift, "-swift-version", "6", "-module-cache-path", str(work / "modules"),
                            str(source), str(fixture), "-o", str(binary)], check=True, timeout=90)
            result = subprocess.run([str(binary), str(work / (label + "-container"))], text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=35)
            if expected:
                if result.returncode:
                    raise SystemExit(result.stdout)
                print(result.stdout, end="")
            else:
                assert result.returncode != 0, f"negative control unexpectedly passed: {label}"
                assert failure_marker in result.stdout, f"negative control failed for the wrong reason: {label}\n{result.stdout}"
                print(f"Apple DNS receipt negative control rejected: {label}")

        compile_run(SOURCE, "shipping", True)
        source = SOURCE.read_text()
        for label, original, replacement, failure_marker in (
            ("unacknowledged-drain", "native.complete, native.drained,", "native.complete,", "unacknowledged or malformed native receipt"),
            ("wrong-native-proof", "receipt.native_session_id == nativeSession, receipt.request_id", "receipt.request_id", "different native proof is not drained"),
        ):
            assert source.count(original) == 1
            mutation = work / f"{label}.swift"
            mutation.write_text(source.replace(original, replacement, 1))
            compile_run(mutation, label, False, failure_marker)
        if platform.system() == "Darwin":
            sdk = subprocess.check_output(["xcrun", "--sdk", "iphonesimulator", "--show-sdk-path"], text=True).strip()
            architecture = "arm64" if platform.machine() == "arm64" else "x86_64"
            subprocess.run([swift, "-swift-version", "6", "-typecheck", "-sdk", sdk,
                            "-target", architecture + "-apple-ios17.0-simulator", str(SOURCE)], check=True, timeout=60)
            print("Apple DNS receipt actual iOS SDK typecheck: PASS")


if __name__ == "__main__":
    main()
