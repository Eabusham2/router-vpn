#!/usr/bin/env python3
"""Execute Apple candidate publication and store commit ordering on real files.

Linux uses the existing OpenSSL SHA256 shim; this is source/publication evidence,
not a NetworkExtension lifecycle or signed app-group acceptance claim.
"""
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
SWIFT = r'''
import Foundation
struct Failed: Error { let message: String }
func require(_ good: Bool, _ label: String) throws { if !good { throw Failed(message: label) } }
func rejects(_ label: String, _ action: () throws -> Void) throws {
    do { try action() } catch { return }; throw Failed(message: label)
}
@MainActor final class Store {
    let publisher: IOSCandidateCatalogPublication
    var records: [String: Data] = [:], durable: [String: Data] = [:]
    var failWrite = false, observeWrite: (() throws -> Void)?
    init(_ publisher: IOSCandidateCatalogPublication) { self.publisher = publisher }
    func writeEncryptedRecords(_ next: [String: Data]) throws {
        try observeWrite?(); if failWrite { throw Failed(message: "durable write failure") }; durable = next
    }
    func cleanupLegacyStoresBestEffort() {}
    // SHIPPING_COMMIT
    func save(_ value: [String: Data]) throws { try commitRecords(value) }
}
@main struct Main {
    @MainActor static func main() throws {
        let fm = FileManager.default, root = URL(fileURLWithPath: CommandLine.arguments[1])
        try fm.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let publisher = IOSCandidateCatalogPublication(container: root), store = Store(publisher)
        let original = ["supported": Data("exact private input".utf8), "unsupported": Data("original unsupported bytes".utf8)]
        try store.save(original)
        let stamp = try publisher.current(records: original)
        let request = String(repeating: "a", count: 32)
        func inventory(_ stamp: IOSCandidateCatalogPublication.Stamp) throws -> Data {
            try JSONSerialization.data(withJSONObject: ["schema": 1, "revision": stamp.revision, "inputs": ["original-source"]])
        }
        let capture = try publisher.capture(request: request, inventory: inventory(stamp), expected: stamp)
        try require(publisher.current(capture), "exact original publication")
        try rejects("same request cannot replace admitted file") { _ = try publisher.capture(request: request, inventory: inventory(stamp), expected: stamp) }
        try rejects("unsupported source changes count") { _ = try publisher.current(records: ["supported": original["supported"]!]) }
        let directory = root.appendingPathComponent("candidate-sources-v1")
        let source = directory.appendingPathComponent(request + ".json")
        let bytes = try Data(contentsOf: source)
        try fm.removeItem(at: source); try bytes.write(to: source); try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: source.path)
        try require(!publisher.current(capture), "same-byte replacement revokes original file identity")
        try rejects("stale cleanup must retain replacement") { try publisher.remove(capture) }
        try require(fm.fileExists(atPath: source.path), "replacement retained")
        let replacement = try publisher.reopen(request: request)
        try publisher.remove(replacement)
        try require(!fm.fileExists(atPath: source.path), "only current source cleanup")
        let live = try publisher.capture(request: request, inventory: inventory(stamp), expected: stamp)
        store.observeWrite = { try require(!publisher.current(live), "invalidation precedes durable write") }
        var changed = original; changed["unsupported"] = Data("changed unsupported".utf8)
        try store.save(changed); try store.save(original)
        let returned = try publisher.current(records: original)
        try require(returned.generation > stamp.generation && returned.revision != stamp.revision && !publisher.current(live), "away/back never revives")
        try publisher.remove(live)
        let failed = try publisher.capture(request: request, inventory: inventory(returned), expected: returned)
        store.failWrite = true
        try rejects("failed private commit") { try store.save(changed) }
        try require(store.records == original && store.durable == original && !publisher.current(failed), "failed write preserves store and invalidates old candidate")
        try rejects("incomplete publication is unavailable") { _ = try publisher.current(records: original) }
        store.failWrite = false; store.observeWrite = nil; try store.save(original)
        try publisher.remove(failed)
        let recovered = try publisher.current(records: original)
        let final = try publisher.capture(request: request, inventory: inventory(recovered), expected: recovered)
        // A symlink can neither replace a private input nor turn cleanup into
        // deletion of an unrelated source.
        try fm.removeItem(at: source); let unrelated = root.appendingPathComponent("unrelated")
        try Data("untouched".utf8).write(to: unrelated)
        try fm.createSymbolicLink(at: source, withDestinationURL: unrelated)
        try require(!publisher.current(final), "symlink source refused")
        try rejects("symlink cleanup refused") { try publisher.remove(final) }
        try require(try Data(contentsOf: unrelated) == Data("untouched".utf8), "unrelated data retained")
        try rejects("request traversal") { _ = try publisher.reopen(request: "../catalog") }
        let catalog = directory.appendingPathComponent("catalog.json")
        try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: catalog.path)
        try rejects("readable catalog refused") { _ = try publisher.current(records: original) }
        print("Apple candidate catalog source/publication/commit controls PASS")
    }
}
'''

def main():
    swift = shutil.which('swiftc')
    if not swift:
        raise SystemExit('swiftc required')
    store = (APP/'IOSNodeBundleStore.swift').read_text()
    commit = store[store.index('    private func commitRecords('):store.index('    func candidateSnapshot(')]
    # App-group location is the only substituted dependency. Commit ordering,
    # failure/adoption behavior and real publication IO remain shipping code.
    commit = commit.replace('IOSCandidateCatalogPublication.shared', 'publisher')
    body = SWIFT.replace('    // SHIPPING_COMMIT', commit)
    with tempfile.TemporaryDirectory(prefix='routervpn-candidate-catalog-') as temporary:
        work = Path(temporary); source = work/'Test.swift'; source.write_text(body)
        options = [swift, '-j', '1', '-swift-version', '6', '-module-cache-path', str(work/'modules')]
        if platform.system() != 'Darwin':
            from test_ios_physical_path import LINUX_CRYPTO
            crypto = work/'CryptoKit.swift'; crypto.write_text(LINUX_CRYPTO)
            subprocess.run(options + ['-emit-module', '-emit-library', '-module-name', 'CryptoKit', str(crypto), '-lcrypto', '-emit-module-path', str(work/'CryptoKit.swiftmodule'), '-o', str(work/'libCryptoKit.so')], check=True, timeout=90)
            options += ['-I', str(work), '-L', str(work), '-lCryptoKit', '-Xlinker', '-rpath', '-Xlinker', str(work)]
        subprocess.run(options + [str(APP/'IOSCandidateCatalogPublication.swift'), str(source), '-o', str(work/'test')], check=True, timeout=90)
        subprocess.run([str(work/'test'), str(work/'container')], check=True, timeout=30)
        shipping = (APP/'IOSCandidateCatalogPublication.swift').read_text()
        mutants = [
            ('same-byte-replacement', shipping.replace('now.inventory.identity == capture.inventory.identity &&', 'true &&'), body),
            ('late-invalidation', shipping, body.replace('let publication = try publisher.beginChange()\n        try writeEncryptedRecords(next)', 'try writeEncryptedRecords(next)\n        let publication = try publisher.beginChange()')),
        ]
        for name, code, fixture in mutants:
            mutant = work/(name + '.swift'); mutant.write_text(code)
            source.write_text(fixture)
            binary = work/name
            subprocess.run(options + [str(mutant), str(source), '-o', str(binary)], check=True, timeout=90)
            result = subprocess.run([str(binary), str(work/(name + '-container'))], capture_output=True, text=True, timeout=30)
            if result.returncode == 0 or 'Failed' not in result.stderr:
                raise AssertionError('causal publication control did not reject ' + name)
        print('Apple candidate catalog: two causal controls rejected')

if __name__ == '__main__':
    main()
