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
    private var capturedLayers: [String] = []
    private var capturedPairs: [[String]] = []
    private var starts = 0
    private var stops = 0
    private var paddingCount: Int64 = 0
    private var server: LibboxCommandServer?
    public func configure(block: Bool = false, fail: Bool = false) {
        lock.lock(); defer { lock.unlock() }
        self.block = block; self.fail = fail; plan = nil
    }
    public func make(_ text: String, layer: String? = nil, exit: String? = nil) -> LibboxRouterMultihop {
        lock.lock(); defer { lock.unlock() }
        if let layer { capturedLayers.append(layer) }
        if let exit { capturedPairs.append([layer ?? "", exit]) }
        let value = LibboxRouterMultihop(text, block: block, fail: fail)
        plan = value; return value
    }
    public func layers() -> [String] { lock.lock(); defer { lock.unlock() }; return capturedLayers }
    public func pairs() -> [[String]] { lock.lock(); defer { lock.unlock() }; return capturedPairs }
    public func current() -> LibboxRouterMultihop? { lock.lock(); defer { lock.unlock() }; return plan }
    public func configurePadding(_ count: Int64) { lock.lock(); paddingCount=count; lock.unlock() }
    public func makeServer() -> LibboxCommandServer {
        lock.lock(); defer { lock.unlock() }
        let value=LibboxCommandServer(paddingCount);server=value;return value
    }
    public func currentServer() -> LibboxCommandServer? { lock.lock(); defer { lock.unlock() }; return server }
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
    private let lock=NSLock()
    private let paddingCount: Int64
    private var invalidated=false
    private var active=false
    private var strategyEvents: [String] = []
    private var failDNS = false, failClose = false
    public init(_ count: Int64 = 0) { paddingCount=count }
    public func activate(_ count: UnsafeMutablePointer<Int64>, _ failure: UnsafeMutablePointer<NSError?>?) -> Bool {
        lock.lock();defer { lock.unlock() }
        if invalidated { failure?.pointee=NSError(domain:"Fixture",code:7);return false }
        count.pointee=paddingCount;active=paddingCount>0;return true
    }
    public func invalidatePadding() { lock.lock(); invalidated=true; active=false; lock.unlock() }
    public func performanceFailure() -> String { lock.lock(); defer { lock.unlock() }; return paddingCount==0 || (active && !invalidated) ? "" : "fixture path invalidated" }
    public func configureStrategy(dns: Bool = false, close: Bool = false) { lock.lock(); failDNS=dns; failClose=close; lock.unlock() }
    public func strategyCalls() -> [String] { lock.lock(); defer { lock.unlock() }; return strategyEvents }
    public func strategy(_ operation: String, _ failure: UnsafeMutablePointer<NSError?>?) -> Bool {
        lock.lock(); defer { lock.unlock() }; strategyEvents.append(operation)
        if (operation == "dns" && failDNS) || (operation == "close" && failClose) {
            failure?.pointee=NSError(domain:"NativeStrategyFixture",code:8);return false
        }
        return true
    }

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
public final class LibboxRouterHopMeasurement {
    public init() {}
    public func start(_ request: String, bytes: Int64) throws {}
    public func cancel(_ request: String) {}
    public func statusJSON() -> String { "{}" }
    public func networkChanged() {}
    public func close() throws {}
}
// Exact generated scalar/error ABI, including output and NSError pointers.
public func LibboxRouterStartPerformance(_ server: LibboxCommandServer, _ count: UnsafeMutablePointer<Int64>, _ failure: UnsafeMutablePointer<NSError?>?) -> Bool { server.activate(count,failure) }
public func LibboxRouterInvalidatePerformance(_ server: LibboxCommandServer) { server.invalidatePadding() }
public func LibboxRouterPerformanceFailure(_ server: LibboxCommandServer) -> String? { server.performanceFailure() }
public func LibboxRouterStrategyStartService(_ server: LibboxCommandServer, _ content: String, _ failure: UnsafeMutablePointer<NSError?>?) -> Bool { server.strategy("start",failure) }
public func LibboxRouterStrategyDNSProof(_ server: LibboxCommandServer, _ failure: UnsafeMutablePointer<NSError?>?) -> Bool { server.strategy("dns",failure) }
public func LibboxRouterStrategyCloseService(_ server: LibboxCommandServer, _ failure: UnsafeMutablePointer<NSError?>?) -> Bool { server.strategy("close",failure) }

public func LibboxNewRouterHopMeasurement(_ server: LibboxCommandServer, _ metadata: String, _ failure: UnsafeMutablePointer<NSError?>?) -> LibboxRouterHopMeasurement? { LibboxRouterHopMeasurement() }

public func LibboxNewRouterMultihop(_ text: String, _ metadata: String, _ failure: UnsafeMutablePointer<NSError?>?) -> LibboxRouterMultihop? { LibboxTestState.shared.make(text) }
public func LibboxNewRouterMultihopWithEntryStartLayer(_ text: String, _ metadata: String, _ layer: String, _ failure: UnsafeMutablePointer<NSError?>?) -> LibboxRouterMultihop? { LibboxTestState.shared.make(text,layer:layer) }
public func LibboxNewRouterMultihopWithStartLayers(_ text: String, _ metadata: String, _ entry: String, _ exit: String, _ failure: UnsafeMutablePointer<NSError?>?) -> LibboxRouterMultihop? { LibboxTestState.shared.make(text,layer:entry,exit:exit) }
public func LibboxSetup(_ setup: LibboxSetupOptions, _ failure: UnsafeMutablePointer<NSError?>?) {}
public func LibboxNewCommandServer(_ platform: AnyObject, _ handler: AnyObject, _ failure: UnsafeMutablePointer<NSError?>?) -> LibboxCommandServer? { LibboxTestState.shared.makeServer() }

public final class LibboxTorTestState: @unchecked Sendable {
    public static let shared = LibboxTorTestState()
    private let lock = NSLock()
    private var block = false
    private var payload: String?
    private var request: LibboxRouterTorProofRequest?
    private var roots: [String] = []
    public func configure(block: Bool = false, payload: String? = nil) { lock.lock(); self.block=block; self.payload=payload; request=nil; lock.unlock() }
    public func make(_ session: String) -> LibboxRouterTorProofRequest { lock.lock(); defer { lock.unlock() }; let value=LibboxRouterTorProofRequest(session,block,payload); request=value; return value }
    public func current() -> LibboxRouterTorProofRequest? { lock.lock(); defer { lock.unlock() }; return request }
    public func saveRoot(_ path: String) { lock.lock(); roots.append(path); lock.unlock() }
    public func stateRoots() -> [String] { lock.lock(); defer { lock.unlock() }; return roots }
}
// Deliberately non-Sendable, like the actual generated gomobile reference.
public final class LibboxRouterTorProofRequest {
    private let session: String, block: Bool, payload: String?
    private let lock = NSLock()
    private var cancels = 0
    private let release = DispatchSemaphore(value:0)
    public let entered = DispatchSemaphore(value:0)
    init(_ session: String, _ block: Bool, _ payload: String?) { self.session=session;self.block=block;self.payload=payload }
    public func run() throws -> String {
        entered.signal()
        if block { _ = release.wait(timeout:.now()+4) }
        if let payload { return payload }
        let clock=ISO8601DateFormatter();clock.formatOptions=[.withInternetDateTime,.withFractionalSeconds]
        let value:[String:Any] = ["session_id":session,"ip":"203.0.113.77","is_tor":true,"checked_at":clock.string(from:Date())]
        return String(decoding:try JSONSerialization.data(withJSONObject:value),as:UTF8.self)
    }
    // Intentionally permits late Run success after cancel. The shipping host
    // must reject it even when a native callback arrives after its owner left.
    public func cancel() { lock.lock(); cancels+=1;lock.unlock();release.signal() }
    public func cancelCount() -> Int { lock.lock();defer {lock.unlock()};return cancels }
    public func healthy() -> Bool { cancelCount()==0 }
}
public func LibboxRouterTorSetStateDirectory(_ path:String,_ failure:UnsafeMutablePointer<NSError?>?) {
    do { try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700]);LibboxTorTestState.shared.saveRoot(path) }
    catch { failure?.pointee=error as NSError }
}
public func LibboxRouterTorCreateProof(_ server:LibboxCommandServer,_ tag:String,_ session:String,_ failure:UnsafeMutablePointer<NSError?>?) -> LibboxRouterTorProofRequest? { LibboxTorTestState.shared.make(session) }
public func LibboxRouterTorCreateProofWithPredecessor(_ server:LibboxCommandServer,_ tag:String,_ session:String,_ profile:String,_ failure:UnsafeMutablePointer<NSError?>?) -> LibboxRouterTorProofRequest? { LibboxTorTestState.shared.make(session) }
public final class LibboxExternalTestState: @unchecked Sendable {
    public static let shared = LibboxExternalTestState()
    private let lock = NSLock()
    private var block = false, invalid = false
    private var request: LibboxRouterExternalProofRequest?
    private var capture: [String] = []
    public func configure(block: Bool = false, invalid: Bool = false) { lock.lock(); self.block=block; self.invalid=invalid; request=nil; lock.unlock() }
    public func make(_ source: String, _ capture: String, _ session: String) -> LibboxRouterExternalProofRequest {
        lock.lock(); defer { lock.unlock() }
        self.capture=[source,capture,session]; let value=LibboxRouterExternalProofRequest(session,block,invalid);request=value;return value
    }
    public func current() -> LibboxRouterExternalProofRequest? { lock.lock(); defer { lock.unlock() }; return request }
    public func captured() -> [String] { lock.lock(); defer { lock.unlock() }; return capture }
}
// Foreign native references deliberately remain non-Sendable. Result-policy
// validation is exercised separately against shipping Swift and the Go compiler.
public final class LibboxRouterExternalProofRequest {
    private let session: String, block: Bool, invalid: Bool
    private let lock=NSLock(), release=DispatchSemaphore(value:0)
    private var cancels=0
    public let entered=DispatchSemaphore(value:0)
    init(_ session:String,_ block:Bool,_ invalid:Bool){self.session=session;self.block=block;self.invalid=invalid}
    public func run() throws -> String {
        entered.signal();if block {_ = release.wait(timeout:.now()+4)}
        return String(decoding:try JSONSerialization.data(withJSONObject:["session_id":session,"valid": !invalid]),as:UTF8.self)
    }
    public func cancel(){lock.lock();cancels+=1;lock.unlock();release.signal()}
    public func cancelCount()->Int{lock.lock();defer{lock.unlock()};return cancels}
    public func healthy()->Bool{cancelCount()==0}
}
public func LibboxRouterExternalCreateProof(_ server:LibboxCommandServer,_ source:String,_ capture:String,_ session:String,_ failure:UnsafeMutablePointer<NSError?>?) -> LibboxRouterExternalProofRequest? { LibboxExternalTestState.shared.make(source,capture,session) }
'''
HARNESS = r'''
import Foundation
import Libbox
// Policy compilation and schema validation have a real Swift/Go gate. This
// boundary isolates foreign-handle delivery, cancellation and exact config use.
struct RouterVPNExternalPolicy: Sendable {
    let sourceConfig: String, capture: String, config: String
    func validateProof(_ result:String,sessionID:String,began:Date)throws {
        guard let value=try JSONSerialization.jsonObject(with:Data(result.utf8)) as? [String:Any],
              value["session_id"] as? String==sessionID,value["valid"] as? Bool==true else {throw NSError(domain:"ExternalPolicyFixture",code:1)}
    }
}
final class PacketTunnelProvider {
    private let lock = NSLock()
    private var cancels = 0
    func writeLibboxLog(_ text: String) {}
    func cancelTunnelWithError(_ error: Error) { lock.lock(); cancels += 1; lock.unlock() }
    func beginLibboxSettings(epoch: String) {}
    func nativeLibboxFailure(_ engine: RouterVPNLibboxEngine, error: Error) { cancelTunnelWithError(error) }
    func count() -> Int { lock.lock(); defer { lock.unlock() }; return cancels }
}
final class MTUPlatformDouble {
    var hasOwner = false
    var measurementReady = true
    func initialMeasurementHold(_ lease: String) throws {}
    func stop() {}
    func invalidate() {}
    func activate(server: LibboxCommandServer, config: String, profile: String, onAbort: @escaping @Sendable (String) -> Void) { hasOwner = true }
    func request(operation: String, request: String, session: String) -> Data? { nil }
}
final class RouterVPNLibboxPlatform {
    let mtu = MTUPlatformDouble()
    init(tunnel: PacketTunnelProvider, settingsEpoch: String) {}
    var onLog: ((String) -> Void)?
    var onStopService: (() throws -> Void)?
    var onReloadService: (() throws -> Void)?
    var includeAllNetworksRequested = false
    func reset() {}
}
enum RouterVPNLibboxCompileProbe { static func verifyPinnedRuntime() throws {} }
final class RouterVPNPQFactory: @unchecked Sendable {
    static let shared = RouterVPNPQFactory()
    private let lock = NSLock()
    private var failure = false
    static func failNext() { shared.lock.lock(); shared.failure = true; shared.lock.unlock() }
    static func install() throws {
        shared.lock.lock(); let fail = shared.failure; shared.failure = false; shared.lock.unlock()
        if fail { throw NSError(domain: "TestPQFactory", code: 1) }
    }
}
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
            let engine = RouterVPNLibboxEngine(tunnel: PacketTunnelProvider())
            let before = state.counts()
            RouterVPNPQFactory.failNext()
            var rejected = false
            do { try engine.start(files: files, strict: true) } catch { rejected = true }
            check("failed protocol registration cannot create a native service", rejected && state.counts() == before)
            do { try engine.start(files: files, strict: true); fatalError("retired startup owner was reused") } catch { checks += 1 }
            let replacement = RouterVPNLibboxEngine(tunnel: PacketTunnelProvider())
            try replacement.start(files: files, strict: true)
            check("registration failure allows a fresh startup owner", state.currentServer() != nil)
            replacement.stop()
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
            try engine.start(files: files, strict: false, multihopMetadata: "{}")
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
            try engine.start(files: files, strict: false, multihopMetadata: "{}")
            let old = state.current()!
            engine.completeMultihopExecution(completed.finish)
            check("comparison entered before stop", old.entered.wait(timeout: .now() + 3) == .success)
            engine.stop()
            check("cancelled comparison returns", completed.wait())
            check("cancelled comparison cannot claim success", completed.values() == (1, 1))
            state.configure()
            let replacementEngine = RouterVPNLibboxEngine(tunnel: provider)
            try replacementEngine.start(files: files, strict: false, multihopMetadata: "{}")
            let replacement = CompletionState(); replacementEngine.completeMultihopExecution(replacement.finish)
            check("replacement completed", replacement.wait())
            check("replacement succeeded", replacement.values() == (1, 0))
            old.allowCompletion(); Thread.sleep(forTimeInterval: 1.15)
            check("old health task cannot cancel replacement", provider.count() == 0)
            check("old completion remains one-shot", completed.values() == (1, 1))
            replacementEngine.stop()
        }
        do {
            state.configure(fail: true)
            let provider = PacketTunnelProvider(), completed = CompletionState()
            let engine = RouterVPNLibboxEngine(tunnel: provider)
            try engine.start(files: files, strict: false, multihopMetadata: "{}")
            engine.completeMultihopExecution { error in engine.stop(); completed.finish(error) }
            check("failure allows reentrant owned cleanup", completed.wait())
            check("failure is delivered once", completed.values() == (1, 1))
            check("failed comparison never reports health cancellation", provider.count() == 0)
        }
        do {
            state.configurePadding(1)
            let provider=PacketTunnelProvider()
            let owned=RouterVPNLibboxEngine(tunnel:provider)
            try owned.start(files:files,strict:false)
            try owned.activatePerformance()
            let old=state.currentServer()!
            old.invalidatePadding()
            let deadline=Date().addingTimeInterval(3)
            while provider.count()==0 && Date()<deadline { Thread.sleep(forTimeInterval:0.01) }
            check("padding failure cancels its owned tunnel",provider.count()>0)
            owned.stop()
            state.configurePadding(0)
            let replacementProvider=PacketTunnelProvider()
            let replacement=RouterVPNLibboxEngine(tunnel:replacementProvider)
            try replacement.start(files:files,strict:false)
            try replacement.activatePerformance()
            old.invalidatePadding()
            Thread.sleep(forTimeInterval:0.65)
            check("old padding failure cannot cancel replacement",replacementProvider.count()==0)
            replacement.stop()
        }
        do {
            state.configurePadding(2)
            let provider=PacketTunnelProvider()
            let engine=RouterVPNLibboxEngine(tunnel:provider)
            try engine.start(files:files,strict:false)
            let server=state.currentServer()!
            try engine.activatePerformance()
            engine.stop()
            let before=provider.count()
            server.invalidatePadding();Thread.sleep(forTimeInterval:0.65)
            check("stopped padding timer cannot cancel again",provider.count()==before)
            state.configurePadding(0)
        }
        do {
            let provider=PacketTunnelProvider()
            let owner=RouterVPNLibboxEngine(tunnel:provider,strategyEpoch:UUID().uuidString)
            let lease=String(repeating:"1",count:32)
            try owner.prepareMTUHold(lease)
            try owner.start(files:files,strict:true)
            let server=state.currentServer()!
            try owner.proveStrategyDNS()
            check("strategy engine uses fresh-start and owned DNS APIs",server.strategyCalls()==["start","dns"])
            check("actual strategy engine retains acknowledged measurement lease",owner.strategyMTUHold==lease)
            try owner.stopCheckedForStrategy()
            check("strategy engine uses checked teardown",server.strategyCalls()==["start","dns","close"])
            let before=state.counts()
            var refused=false
            do { try owner.start(files:files,strict:true) } catch { refused=true }
            check("retired strategy native handle cannot restart",refused && state.counts()==before)
        }
        do {
            let provider=PacketTunnelProvider()
            let owner=RouterVPNLibboxEngine(tunnel:provider,strategyEpoch:UUID().uuidString)
            try owner.start(files:files,strict:true)
            let server=state.currentServer()!
            server.configureStrategy(dns:true,close:true)
            var refused=false
            do { try owner.proveStrategyDNS() } catch { refused=true }
            check("native DNS error reaches engine caller",refused)
            for _ in 0..<2 {
                refused=false
                do { try owner.stopCheckedForStrategy() } catch { refused=true }
                check("unverified teardown remains sticky after owner retirement",refused)
            }
            check("repeated checked teardown never reenters retired native handle",server.strategyCalls()==["start","dns","close"])
        }
        for execution in ["local","server","auto"] {
            state.configure()
            let profile:[String:Any] = ["node_kind":"router-vpn","start_layer":"aes"]
            let assets=["shadowsocks":["sing-box.json":Data("{}".utf8).base64EncodedString()]]
            let captured=try IOSMultihopStartLayer.capture(profile:profile,profiles:assets)
            let metadata=String(decoding:try JSONSerialization.data(withJSONObject:["entry_start_layer":captured.mode,"execution":execution]),as:UTF8.self)
            let engine=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            let before=state.layers().count
            try engine.start(files:files,strict:true,multihopMetadata:metadata,entryStartLayerSource:captured.source)
            check("exact layer reaches native factory even in Local",state.layers().count==before+1 && state.layers().last==captured.source)
            let completed=CompletionState();engine.completeMultihopExecution(completed.finish)
            check("layered execution completes under the same owner",completed.wait() && completed.values()==(1,0))
            engine.stop()
            for source in [nil,"", "{}"] as [String?] {
                let stoppedBefore=state.counts()
                var rejected=false
                let invalidOwner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
                do {try invalidOwner.start(files:files,strict:true,multihopMetadata:metadata,entryStartLayerSource:source)}catch{rejected=true}
                check("missing or changed layer cannot start a native service",rejected && state.counts()==stoppedBefore)
            }
        }
        for execution in ["local","server","auto"] { for entryMode in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] { for exitMode in ["aes-256-gcm","aes-256-gcm+xor-whitening"] {
            state.configure()
            let entry = try IOSMultihopStartLayer.capture(profile:["node_kind":"router-vpn","start_layer":entryMode], profiles:["shadowsocks":["sing-box.json":Data("entry-source".utf8).base64EncodedString()]])
            let exit = try IOSMultihopStartLayer.capture(profile:["node_kind":"router-vpn","start_layer":exitMode], profiles:["shadowsocks":["sing-box.json":Data("exit-source".utf8).base64EncodedString()]])
            var value:[String:String] = ["execution":execution,"exit_start_layer":exit.mode]
            if entry.source != nil {value["entry_start_layer"]=entry.mode}
            let metadata=String(decoding:try JSONSerialization.data(withJSONObject:value),as:UTF8.self)
            let engine=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),before=state.pairs().count
            try engine.start(files:files,strict:true,multihopMetadata:metadata,entryStartLayerSource:entry.source,exitStartLayerSource:exit.source)
            check("both exact sources reach one native factory",state.pairs().count==before+1 && state.pairs().last==[entry.source ?? "",exit.source!])
            let completed=CompletionState();engine.completeMultihopExecution(completed.finish)
            check("layered Local/Server/Auto completes once",completed.wait() && completed.values()==(1,0))
            engine.stop()
            for source in [nil,"","{}",entry.source] as [String?] {
                // Equal canonical modes do not prove node ownership: the native
                // compiler checks keys. Here reject only missing/malformed data.
                if source==entry.source && source != nil {continue}
                let previous=state.counts(),pairCount=state.pairs().count
                var refused=false
                let invalidOwner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
                do{try invalidOwner.start(files:files,strict:true,multihopMetadata:metadata,entryStartLayerSource:entry.source,exitStartLayerSource:source)}catch{refused=true}
                check("missing exit cannot start a bare engine",refused && state.counts()==previous && state.pairs().count==pairCount)
            }
            var missingOwner=value;missingOwner.removeValue(forKey:"exit_start_layer")
            let wrong=String(decoding:try JSONSerialization.data(withJSONObject:missingOwner),as:UTF8.self)
            var refused=false
            let invalidOwner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            do{try invalidOwner.start(files:files,strict:true,multihopMetadata:wrong,entryStartLayerSource:entry.source,exitStartLayerSource:exit.source)}catch{refused=true}
            check("unrequested exit source not activated",refused)
        }}}
        let torFiles=["sing-box.json":Data("{\"inbounds\":[],\"outbounds\":[{\"type\":\"routervpn-tor\",\"tag\":\"routervpn-tor-exit\",\"session_id\":\"tor-session\"}]}".utf8)]
        let externalState=LibboxExternalTestState.shared
        let externalConfig="{\"inbounds\":[{\"type\":\"tun\",\"tag\":\"captured-tun\"}],\"outbounds\":[] }"
        let externalFiles=["sing-box.json":Data(externalConfig.utf8)]
        let externalPolicy=RouterVPNExternalPolicy(sourceConfig:"exact source bytes",capture:"frozen profile/policy",config:externalConfig)
        for action in ["stable","stop","network","pause","invalid"] {
            state.configure();externalState.configure(block:["stop","network","pause"].contains(action),invalid:action=="invalid")
            let provider=PacketTunnelProvider(),owner=RouterVPNLibboxEngine(tunnel:provider)
            try owner.start(files:externalFiles,strict:true,externalPolicy:externalPolicy)
            let server=state.currentServer()!,done=CompletionState()
            owner.proveExternal(completion:done.finish)
            guard let request=externalState.current()else{fatalError("missing external proof")}
            if ["stop","network","pause"].contains(action) {
                check("external native proof entered",request.entered.wait(timeout:.now()+2) == .success)
                if action=="stop"{owner.stop()}else if action=="network"{owner.invalidateMultihop()}else{owner.pause()}
                check("external interruption cancels its native handle",request.cancelCount()>0)
            }
            check("external result delivered exactly once",done.wait() && done.values()==(1,action=="stable" ? 0:1))
            check("external proof receives exact compiler source and capture",Array(externalState.captured().prefix(2))==[externalPolicy.sourceConfig,externalPolicy.capture])
            check("external startup uses bounded owned service",server.strategyCalls().first=="start")
            owner.stop();request.cancel()
            check("late external result cannot touch a retired owner",done.values()==(1,action=="stable" ? 0:1) && provider.count()==0)
        }
        do {
            state.configure();externalState.configure()
            let provider=PacketTunnelProvider(),owner=RouterVPNLibboxEngine(tunnel:provider)
            try owner.start(files:externalFiles,strict:true,externalPolicy:externalPolicy)
            let done=CompletionState();owner.proveExternal(completion:done.finish)
            check("external native proof retained before health loss",done.wait() && done.values()==(1,0))
            externalState.current()!.cancel()
            let deadline=Date().addingTimeInterval(3)
            while provider.count()==0 && Date()<deadline{Thread.sleep(forTimeInterval:0.02)}
            check("external health loss invalidates retained owner",provider.count()>0)
            owner.stop()
        }
        do {
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider());var rejected=false
            do{try owner.start(files:["sing-box.json":Data((externalConfig+" ").utf8)],strict:true,externalPolicy:externalPolicy)}catch{rejected=true}
            check("external compiler bytes cannot be silently rewritten",rejected)
        }
        let torState=LibboxTorTestState.shared
        for cancelled in [false,true] {
            torState.configure(block:cancelled)
            let provider=PacketTunnelProvider(), owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            try owner.start(files:torFiles,strict:true)
            let done=CompletionState()
            owner.proveTor(sessionID:"tor-session",completion:done.finish)
            let request=torState.current()!
            if cancelled {
                check("Tor native wait began",request.entered.wait(timeout:.now()+2) == .success)
                owner.stop()
                check("Tor stop cancels captured request immediately",request.cancelCount()>0)
            }
            check("Tor proof callback consumed once",done.wait() && done.values()==(1,cancelled ? 1 : 0))
            owner.stop();Thread.sleep(forTimeInterval:0.04)
            check("late Tor success cannot reactivate retired session",done.values()==(1,cancelled ? 1 : 0) && provider.count()==0)
        }
        check("Tor uses a stable private directory across new engine roots",Set(torState.stateRoots()).count==1 && torState.stateRoots().count>=2 && !torState.stateRoots()[0].contains("routervpn-libbox-"))
        for fails in [false,true] {
            torState.configure()
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            try owner.start(files:torFiles,strict:true)
            let server=state.currentServer()!;server.configureStrategy(dns:fails)
            let done=CompletionState();owner.proveTor(sessionID:"tor-session",completion:done.finish)
            check("Tor requires its selected native DNS before Connected",done.wait() && done.values()==(1,fails ? 1:0))
            check("Tor DNS proof belongs to the same captured runtime",server.strategyCalls()==["start","dns"])
            owner.stop()
        }
        do {
            torState.configure()
            let provider=PacketTunnelProvider(),owner=RouterVPNLibboxEngine(tunnel:provider)
            try owner.start(files:torFiles,strict:true)
            let done=CompletionState();owner.proveTor(sessionID:"tor-session",completion:done.finish)
            check("Tor circuit retained before runtime health test",done.wait() && done.values()==(1,0))
            torState.current()!.cancel()
            let until=Date().addingTimeInterval(2.5)
            while provider.count()==0 && Date()<until {Thread.sleep(forTimeInterval:0.02)}
            check("lost native Tor health retires only its retained session",provider.count()>0 && done.values()==(1,0))
            owner.stop();let before=provider.count();Thread.sleep(forTimeInterval:1.15)
            check("retired Tor health timer cannot touch a replacement",provider.count()==before)
        }
        for method in ["invalidate","pause"] {
            torState.configure(block:true)
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            try owner.start(files:torFiles,strict:false)
            let done=CompletionState();owner.proveTor(sessionID:"tor-session",completion:done.finish)
            let request=torState.current()!
            check("Tor wait entered before network invalidation",request.entered.wait(timeout:.now()+2) == .success)
            if method=="pause" {owner.pause()}else{owner.invalidateMultihop()}
            check("network/pause revoke the captured Tor proof",done.wait() && done.values()==(1,1) && request.cancelCount()>0)
            owner.stop()
        }
        for payload in ["{}","{\"session_id\":\"other\",\"ip\":\"203.0.113.77\",\"is_tor\":true,\"checked_at\":\"2020-01-01T00:00:00Z\"}","{\"session_id\":\"tor-session\",\"ip\":\"203.0.113.77\",\"is_tor\":false,\"checked_at\":\"2026-10-19T00:00:00Z\"}"] {
            torState.configure(payload:payload)
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            try owner.start(files:torFiles,strict:false)
            let done=CompletionState();owner.proveTor(sessionID:"tor-session",completion:done.finish)
            check("malformed/replayed/non-Tor results cannot report Connected",done.wait() && done.values()==(1,1));owner.stop()
        }
        check("no mock native server survives successful shutdown", state.counts().0 == state.counts().1)
        do {
            torState.configure()
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            try owner.start(files:torFiles,strict:true)
            let retained=state.currentServer()!,before=state.counts()
            retained.configureStrategy(close:true)
            var failed=false
            do {try owner.stopCheckedForStrategy()}catch{failed=true}
            check("unconfirmed Tor close retains native owner",failed && state.counts()==before && retained.strategyCalls()==["start","close"])
            var blocked=false
            let replacement=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            do{try replacement.start(files:files,strict:false)}catch{blocked=true}
            check("quarantined Tor cannot overlap a replacement core",blocked && state.counts()==before)
        }
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
        subprocess.run(args+[str(ROOT/"ios/RouterVPN/App/IOSMultihopStartLayer.swift"),str(ENGINE),str(harness),'-o',str(tmp/'test')],check=True,timeout=90)
        subprocess.run([str(tmp/'test')],check=True,timeout=25)
        broken=tmp/'Broken.swift'
        text=ENGINE.read_text()
        seam='DispatchQueue.global(qos: .userInitiated).async { delivery.run() }'
        start=text.index('    func completeMultihopExecution(')
        end=text.index('    /// Only this delivery object',start)
        delivery=text[start:end]
        assert delivery.count(seam)==1
        # Require an explicit Sendable closure: Apple's preconcurrency Dispatch
        # overload and compiler versions can diagnose inferred closures differently.
        broken.write_text(text[:start]+delivery.replace(seam, 'let unsafe: @Sendable () -> Void = { try? plan.run(owned); completion(nil) }; DispatchQueue.global(qos: .userInitiated).async(execute: unsafe)')+text[end:])
        bad=subprocess.run(args+[str(ROOT/"ios/RouterVPN/App/IOSMultihopStartLayer.swift"),str(broken),str(harness),'-o',str(tmp/'bad')],capture_output=True,text=True,timeout=90)
        diagnostics = (bad.stdout + bad.stderr).lower()
        assert bad.returncode != 0 and ('sendable' in diagnostics or 'data race' in diagnostics), ('Regression control accepted unowned foreign captures or failed for another reason: ' + diagnostics[-2000:])
        print('Negative control: old non-Sendable asynchronous captures correctly rejected')

if __name__ == '__main__':
    main()
