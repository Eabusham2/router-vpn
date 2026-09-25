#!/usr/bin/env python3
"""Compile the shipping Libbox engine under Swift 6 and exercise owned delivery.

The entire engine source is compiled unchanged. Libbox handles are deliberately
non-Sendable API doubles, so the old asynchronous captures fail this compilation.
Apple CI still compiles the real generated framework in the mandatory IPA job.
"""
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / 'ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift'
LIBBOX = r'''
import Foundation
public final class LibboxTestState: @unchecked Sendable {
    public static let shared = LibboxTestState()
    private let lock = NSLock()
    private var block = false
    private var fail = false
    private var plan: LibboxRouterMultihop?
    private var starts = 0
    private var stops = 0
    public func configure(block: Bool = false, fail: Bool = false) {
        lock.lock(); defer { lock.unlock() }
        self.block = block; self.fail = fail; plan = nil
    }
    public func make(_ text: String) -> LibboxRouterMultihop {
        lock.lock(); defer { lock.unlock() }
        let value = LibboxRouterMultihop(text, block: block, fail: fail)
        plan = value; return value
    }
    public func current() -> LibboxRouterMultihop? { lock.lock(); defer { lock.unlock() }; return plan }
    public func started() { lock.lock(); starts += 1; lock.unlock() }
    public func stopped() { lock.lock(); stops += 1; lock.unlock() }
    public func counts() -> (Int, Int) { lock.lock(); defer { lock.unlock() }; return (starts, stops) }
}
// Intentionally no Sendable conformance: these model generated Objective-C refs.
public final class LibboxRouterMultihop {
    private let text: String
    private let block: Bool
    private let fail: Bool
    private let lock = NSLock()
    private var closed = false
    private var valid = true
    public let entered = DispatchSemaphore(value: 0)
    private let release = DispatchSemaphore(value: 0)
    init(_ text: String, block: Bool, fail: Bool) { self.text = text; self.block = block; self.fail = fail }
    public func config() -> String { text }
    public func run(_ server: LibboxCommandServer) throws {
        entered.signal()
        if block { _ = release.wait(timeout: .now() + 5) }
        lock.lock(); let failed = closed || fail; lock.unlock()
        if failed { throw NSError(domain: "Fixture", code: 1) }
    }
    public func healthy() -> Bool { lock.lock(); defer { lock.unlock() }; return !closed && valid }
    public func networkChanged() { lock.lock(); valid = false; lock.unlock() }
    public func close() throws { lock.lock(); closed = true; lock.unlock(); release.signal() }
    public func progressJSON() -> String { "{\"stage\":\"fixture\"}" }
    public func allowCompletion() { release.signal() }
}
public final class LibboxCommandServer {
    public init() {}
    public func start() throws { LibboxTestState.shared.started() }
    public func startOrReloadService(_ text: String, options: LibboxOverrideOptions) throws {}
    public func closeService() throws {}
    public func close() { LibboxTestState.shared.stopped() }
    public func pause() {}
    public func wake() {}
}
public final class LibboxSetupOptions {
    public init() {}
    public var basePath = "", workingPath = "", tempPath = "", commandServerSecret = ""
    public var logMaxLines = 0
    public var oomKillerEnabled = false
}
public final class LibboxOverrideOptions { public init() {} }
public func LibboxNewRouterMultihop(_ text: String, _ metadata: String, _ failure: UnsafeMutablePointer<NSError?>?) -> LibboxRouterMultihop? { LibboxTestState.shared.make(text) }
public func LibboxSetup(_ setup: LibboxSetupOptions, _ failure: UnsafeMutablePointer<NSError?>?) {}
public func LibboxNewCommandServer(_ platform: AnyObject, _ handler: AnyObject, _ failure: UnsafeMutablePointer<NSError?>?) -> LibboxCommandServer? { LibboxCommandServer() }
'''
HARNESS = r'''
import Foundation
import Libbox
final class PacketTunnelProvider {
    private let lock = NSLock()
    private var cancels = 0
    func writeLibboxLog(_ text: String) {}
    func cancelTunnelWithError(_ error: Error) { lock.lock(); cancels += 1; lock.unlock() }
    func count() -> Int { lock.lock(); defer { lock.unlock() }; return cancels }
}
final class RouterVPNLibboxPlatform {
    init(tunnel: PacketTunnelProvider) {}
    var onLog: ((String) -> Void)?
    var onStopService: (() throws -> Void)?
    var onReloadService: (() throws -> Void)?
    var includeAllNetworksRequested = false
    func reset() {}
}
enum RouterVPNLibboxCompileProbe { static func verifyPinnedRuntime() throws {} }
final class CompletionState: @unchecked Sendable {
    private let lock = NSLock()
    private var calls = 0
    private var failures = 0
    let done = DispatchSemaphore(value: 0)
    func finish(_ error: Error?) { lock.lock(); calls += 1; if error != nil { failures += 1 }; lock.unlock(); done.signal() }
    func values() -> (Int, Int) { lock.lock(); defer { lock.unlock() }; return (calls, failures) }
    func wait() -> Bool { done.wait(timeout: .now() + 5) == .success }
}
@main struct Tests {
    static func main() throws {
        let files = ["sing-box.json": Data("{\"inbounds\":[],\"outbounds\":[]}".utf8)]
        let state = LibboxTestState.shared
        var checks = 0
        func check(_ label: String, _ value: @autoclosure () -> Bool) {
            guard value() else { fatalError("FAIL: " + label) }; checks += 1
        }
        do {
            let provider = PacketTunnelProvider()
            let engine = RouterVPNLibboxEngine(tunnel: provider)
            try engine.start(files: files, strict: false)
            let completed = CompletionState(); engine.completeMultihopExecution(completed.finish)
            check("non-multihop completes immediately once", completed.values() == (1, 0))
            engine.stop()
        }
        do {
            state.configure()
            let provider = PacketTunnelProvider(), completed = CompletionState()
            let engine = RouterVPNLibboxEngine(tunnel: provider)
            try engine.start(files: files, strict: false, multihopMetadata: "fixture")
            engine.completeMultihopExecution(completed.finish)
            check("comparison completion delivered", completed.wait())
            check("one successful result", completed.values() == (1, 0))
            engine.invalidateMultihop()
            let deadline = Date().addingTimeInterval(3)
            while provider.count() == 0 && Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
            check("expired proof reaches health cancellation", provider.count() > 0)
            engine.stop()
            check("health timer does not repeat completion", completed.values() == (1, 0))
        }
        do {
            state.configure(block: true)
            let provider = PacketTunnelProvider(), completed = CompletionState()
            let engine = RouterVPNLibboxEngine(tunnel: provider)
            try engine.start(files: files, strict: false, multihopMetadata: "fixture")
            let old = state.current()!
            engine.completeMultihopExecution(completed.finish)
            check("comparison entered before stop", old.entered.wait(timeout: .now() + 3) == .success)
            engine.stop()
            check("cancelled comparison returns", completed.wait())
            check("cancelled comparison cannot claim success", completed.values() == (1, 1))
            state.configure()
            try engine.start(files: files, strict: false, multihopMetadata: "new-fixture")
            let replacement = CompletionState(); engine.completeMultihopExecution(replacement.finish)
            check("replacement completed", replacement.wait())
            check("replacement succeeded", replacement.values() == (1, 0))
            old.allowCompletion(); Thread.sleep(forTimeInterval: 1.15)
            check("old health task cannot cancel replacement", provider.count() == 0)
            check("old completion remains one-shot", completed.values() == (1, 1))
            engine.stop()
        }
        do {
            state.configure(fail: true)
            let provider = PacketTunnelProvider(), completed = CompletionState()
            let engine = RouterVPNLibboxEngine(tunnel: provider)
            try engine.start(files: files, strict: false, multihopMetadata: "fixture")
            engine.completeMultihopExecution { error in engine.stop(); completed.finish(error) }
            check("failure allows reentrant owned cleanup", completed.wait())
            check("failure is delivered once", completed.values() == (1, 1))
            check("failed comparison never reports health cancellation", provider.count() == 0)
        }
        check("no mock native server survives tests", state.counts().0 == state.counts().1)
        print("Swift 6 shipping Libbox delivery: PASS (\(checks) checks; native handles doubled, no network opened)")
    }
}
'''

def main():
    swift = shutil.which('swiftc')
    if swift is None:
        raise SystemExit('swiftc required to compile the shipping concurrency boundary')
    with tempfile.TemporaryDirectory(prefix='routervpn-libbox-delivery-') as tmp:
        tmp = Path(tmp)
        stub, harness = tmp/'Libbox.swift', tmp/'Harness.swift'
        stub.write_text(LIBBOX); harness.write_text(HARNESS)
        lib = tmp/('libLibbox.dylib' if platform.system() == 'Darwin' else 'libLibbox.so')
        subprocess.run([swift,'-swift-version','6','-emit-module','-emit-library','-module-name','Libbox',str(stub),
                        '-emit-module-path',str(tmp/'Libbox.swiftmodule'),'-o',str(lib)],check=True,timeout=60)
        args=[swift,'-swift-version','6','-I',str(tmp),'-L',str(tmp),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(tmp)]
        subprocess.run(args+[str(ENGINE),str(harness),'-o',str(tmp/'test')],check=True,timeout=90)
        subprocess.run([str(tmp/'test')],check=True,timeout=25)
        broken=tmp/'Broken.swift'
        text=ENGINE.read_text()
        seam='DispatchQueue.global(qos: .userInitiated).async { delivery.run() }'
        assert text.count(seam)==1
        # Require an explicit Sendable closure: Apple's preconcurrency Dispatch
        # overload and compiler versions can diagnose inferred closures differently.
        broken.write_text(text.replace(seam, 'let unsafe: @Sendable () -> Void = { try? plan.run(owned); completion(nil) }; DispatchQueue.global(qos: .userInitiated).async(execute: unsafe)'))
        bad=subprocess.run(args+[str(broken),str(harness),'-o',str(tmp/'bad')],capture_output=True,text=True,timeout=90)
        diagnostics = (bad.stdout + bad.stderr).lower()
        assert bad.returncode != 0 and ('sendable' in diagnostics or 'data race' in diagnostics), ('Regression control accepted unowned foreign captures or failed for another reason: ' + diagnostics[-2000:])
        print('Negative control: old non-Sendable asynchronous captures correctly rejected')

if __name__ == '__main__':
    main()
