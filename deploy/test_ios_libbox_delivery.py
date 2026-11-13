#!/usr/bin/env python3
"""Compile the shipping Libbox engine under Swift 6 and exercise owned delivery.

The entire engine source is compiled unchanged. Libbox handles are deliberately
non-Sendable API doubles, so the old asynchronous captures fail this compilation.
Apple CI still compiles the real generated framework in the mandatory IPA job.
"""
from pathlib import Path
import argparse
import importlib.util
import os
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / 'ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift'
spec = importlib.util.spec_from_file_location('apple_dns_boundary', ROOT / 'deploy/test_ios_dns_measurement.py')
DNS = importlib.util.module_from_spec(spec); spec.loader.exec_module(DNS)
spec = importlib.util.spec_from_file_location('apple_crypto_boundary', ROOT / 'deploy/test_ios_physical_path.py')
CRYPTO = importlib.util.module_from_spec(spec); spec.loader.exec_module(CRYPTO)
spec = importlib.util.spec_from_file_location('apple_execution_host_boundary', ROOT / 'deploy/ios_node_chain_execution_host_boundary.py')
EXECUTION = importlib.util.module_from_spec(spec); spec.loader.exec_module(EXECUTION)
spec = importlib.util.spec_from_file_location('apple_prefix_host_boundary', ROOT / 'deploy/ios_node_candidate_prefix_host_boundary.py')
PREFIX = importlib.util.module_from_spec(spec); spec.loader.exec_module(PREFIX)
LIBBOX = r'''
import Foundation
#if !canImport(ObjectiveC)
public typealias NSErrorPointer = UnsafeMutablePointer<NSError?>?
#endif
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
    private var setupPath = ""
    private var setupPaths: [String] = []
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
    public func setup(_ path:String){lock.lock();setupPath=path;setupPaths.append(path);lock.unlock()}
    public func directory()->String{lock.lock();defer{lock.unlock()};return setupPath}
    public func directories()->[String]{lock.lock();defer{lock.unlock()};return setupPaths}
}
// Intentionally no Sendable conformance: these model generated Objective-C refs.
public final class LibboxRouterMultihop {
    private let text: String
    private let block: Bool
    private let fail: Bool
    private let lock = NSLock()
    private var closed = false
    private var valid = true
    private var completed = false
    private var execution = "local"
    private var pins = "{}"
    private var pinFailure = false
    public let entered = DispatchSemaphore(value: 0)
    private let release = DispatchSemaphore(value: 0)
    init(_ text: String, block: Bool, fail: Bool) { self.text = text; self.block = block; self.fail = fail }
    public func config() -> String { text }
    public func sourceSHA256() -> String { String(repeating:"a",count:64) }
    public func metadata() -> String { "{}" }
    public func mtuProfile() -> String { "{}" }
    public func run(_ server: LibboxCommandServer) throws {
        entered.signal()
        if block { _ = release.wait(timeout: .now() + 5) }
        lock.lock(); let failed = closed || fail; if !failed { completed = true }; lock.unlock()
        if failed { throw NSError(domain: "Fixture", code: 1) }
    }
    public func healthy() -> Bool { lock.lock(); defer { lock.unlock() }; return !closed && valid }
    public func networkChanged() { lock.lock(); valid = false; lock.unlock() }
    public func close() throws { lock.lock(); closed = true; lock.unlock(); release.signal() }
    public func progressJSON() -> String { lock.lock();defer{lock.unlock()};return String(decoding:try! JSONSerialization.data(withJSONObject:["stage":completed ? "selected":"pending","complete":completed,"execution":execution]),as:UTF8.self) }
    public func setExecution(_ value:String,complete:Bool=true) { lock.lock();execution=value;completed=complete;lock.unlock() }
    public func serverIdentityPinsJSON(_ failure: UnsafeMutablePointer<NSError?>?) -> String? {
        lock.lock();defer{lock.unlock()}
        guard !closed && valid && completed && !pinFailure else { failure?.pointee=NSError(domain:"Fixture.Pins",code:1);return nil }
        return pins
    }
    public func setPins(_ value:String,fail:Bool=false) {lock.lock();pins=value;pinFailure=fail;lock.unlock()}
    public func allowCompletion() { release.signal() }
}
public final class LibboxRouterNodeChain {
    private let text:String,block:Bool,fail:Bool
    private let lock=NSLock()
    private var valid=true,closed=false,completed=false,running=false
    private var closeFailures=0,closeCount=0
    private var healthHook:(()->Void)?
    private var measurementServer:LibboxCommandServer?
    public let entered=DispatchSemaphore(value:0)
    private let release=DispatchSemaphore(value:0),exited=DispatchSemaphore(value:0)
    public init(_ text:String,block:Bool=false,fail:Bool=false){self.text=text;self.block=block;self.fail=fail}
    public func config()->String{text}
    public func sourceSHA256()->String{String(repeating:"c",count:64)}
    public func configSHA256()->String{String(repeating:"d",count:64)}
    public func run(_ server:LibboxCommandServer)throws{
        lock.lock();running=true;measurementServer=server;lock.unlock();entered.signal()
        if block{_ = release.wait(timeout:.now()+5)}
        lock.lock();let bad=closed || !valid || fail;running=false;completed = !bad;lock.unlock();exited.signal()
        if bad{throw NSError(domain:"NodeChainFixture",code:1)}
    }
    public func healthy()->Bool{
        lock.lock();let value=valid && !closed && completed,hook=healthHook;healthHook=nil;lock.unlock();hook?();return value
    }
    public func networkChanged(){lock.lock();valid=false;lock.unlock()}
    public func configureClose(_ failures:Int){lock.lock();closeFailures=failures;lock.unlock()}
    public func closeCalls()->Int{lock.lock();defer{lock.unlock()};return closeCount}
    public func configureHealth(_ valid:Bool,hook:(()->Void)?=nil){lock.lock();self.valid=valid;healthHook=hook;lock.unlock()}
    public func allowCompletion(){release.signal()}
    public func close()throws{
        lock.lock();closeCount+=1;closed=true;valid=false
        let pending=closeFailures>0,join=running;if pending{closeFailures-=1};lock.unlock()
        if pending{throw NSError(domain:"NodeChainJoinFixture",code:1)}
        release.signal()
        if join && exited.wait(timeout:.now()+3) != .success{throw NSError(domain:"NodeChainJoinFixture",code:2)}
    }
    public func progressJSON()->String{lock.lock();defer{lock.unlock()};return String(decoding:try! JSONSerialization.data(withJSONObject:["stage":completed ? "ready":"pending","complete":completed,"ready":completed && valid && !closed,"execution":"local"]),as:UTF8.self)}
    public func measurement(_ server:LibboxCommandServer)->LibboxRouterHopMeasurement?{lock.lock();defer{lock.unlock()};return measurementServer === server && completed && valid && !closed ? LibboxRouterHopMeasurement():nil}
}
public final class LibboxCommandServer {
    private let lock=NSLock()
    private let paddingCount: Int64
    private var invalidated=false
    private var active=false
    private var strategyEvents: [String] = []
    private var failDNS = false, failClose = false
    private var configuration = "", instanceClosed=false
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
    public func torCleanup(_ success:Bool) { lock.lock(); strategyEvents.append(success ? "tor-delete" : "tor-delete-failed"); lock.unlock() }
    public func captureConfiguration(_ text:String){lock.lock();configuration=text;lock.unlock()}
    public func capturedConfiguration()->String{lock.lock();defer{lock.unlock()};return configuration}
    public func instanceJoined()->Bool{lock.lock();defer{lock.unlock()};return instanceClosed}
    public func strategy(_ operation: String, _ failure: UnsafeMutablePointer<NSError?>?) -> Bool {
        lock.lock(); defer { lock.unlock() }; strategyEvents.append(operation)
        if (operation == "dns" && failDNS) || (operation == "close" && failClose) {
            failure?.pointee=NSError(domain:"NativeStrategyFixture",code:8);return false
        }
        if operation == "close" { instanceClosed=true }
        return true
    }

    public func start() throws { LibboxTestState.shared.started() }
    public func startOrReloadService(_ text: String, options: LibboxOverrideOptions) throws { captureConfiguration(text) }
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
    private let lock=NSLock()
    private var request="",closed=0,complete=false,drained=false,failClose=false
    private var cancelledRequests:[String]=[]
    private var latencyExits:[String]=[]
    private var responseExits:[String]=[]
    public init() {}
    public func start(_ request: String, bytes: Int64) throws {lock.lock();self.request=request;complete=false;drained=false;lock.unlock()}
    public func startLatency(_ request: String, exitID: String) throws {lock.lock();self.request=request;latencyExits.append(exitID);complete=false;drained=false;lock.unlock()}
    public func startResponse(_ request: String, exitID: String) throws {lock.lock();self.request=request;responseExits.append(exitID);complete=false;drained=false;lock.unlock()}
    public func latencyExitCalls()->[String]{lock.lock();defer{lock.unlock()};return latencyExits}
    public func responseExitCalls()->[String]{lock.lock();defer{lock.unlock()};return responseExits}
    public func cancel(_ request: String) {lock.lock();cancelledRequests.append(request);if self.request==request{complete=true};lock.unlock()}
    public func cancellationCalls()->[String]{lock.lock();defer{lock.unlock()};return cancelledRequests}
    public func configure(closeFails:Bool){lock.lock();failClose=closeFails;lock.unlock()}
    public func finishDrain(){lock.lock();complete=true;drained=true;lock.unlock()}
    public func closeCount()->Int{lock.lock();defer{lock.unlock()};return closed}
    public func statusJSON() -> String {
        lock.lock();defer{lock.unlock()}
        return String(decoding:try! JSONSerialization.data(withJSONObject:["request_id":request,"stage":complete ? "complete":"running","complete":complete,"drained":drained,"results":[]]),as:UTF8.self)
    }
    public func networkChanged() {lock.lock();complete=true;lock.unlock()}
    public func close() throws {lock.lock();closed+=1;complete=true;let failed=failClose;if !failed{drained=true};lock.unlock();if failed{throw NSError(domain:"HopCloseFixture",code:1)}}
}
public final class LibboxHopTestState: @unchecked Sendable {
    public static let shared=LibboxHopTestState()
    private let lock=NSLock()
    private var probe:LibboxRouterHopMeasurement?,arguments:[String]=[]
    private var callback:(()->Void)?
    public func configure(_ callback:(()->Void)?=nil){lock.lock();probe=nil;arguments=[];self.callback=callback;lock.unlock()}
    public func make(_ arguments:[String])->LibboxRouterHopMeasurement{lock.lock();let p=LibboxRouterHopMeasurement();probe=p;self.arguments=arguments;let callback=self.callback;lock.unlock();callback?();return p}
    public func current()->LibboxRouterHopMeasurement?{lock.lock();defer{lock.unlock()};return probe}
    public func captured()->[String]{lock.lock();defer{lock.unlock()};return arguments}
}
public final class LibboxDNSTestState: @unchecked Sendable {
    public static let shared=LibboxDNSTestState()
    private let lock=NSLock()
    private var probe:LibboxRouterDNSMeasurement?,arguments:[String]=[]
    private var callback:(()->Void)?
    public func configure(_ callback:(()->Void)?=nil){lock.lock();probe=nil;arguments=[];self.callback=callback;lock.unlock()}
    public func make(_ arguments:[String],node:String,session:String)->LibboxRouterDNSMeasurement{lock.lock();let p=LibboxRouterDNSMeasurement(node:node,session:session);probe=p;self.arguments=arguments;let callback=self.callback;lock.unlock();callback?();return p}
    public func current()->LibboxRouterDNSMeasurement?{lock.lock();defer{lock.unlock()};return probe}
    public func captured()->[String]{lock.lock();defer{lock.unlock()};return arguments}
}
// Exact generated scalar/error ABI, including output and NSError pointers.
public func LibboxRouterStartPerformance(_ server: LibboxCommandServer, _ count: UnsafeMutablePointer<Int64>, _ failure: UnsafeMutablePointer<NSError?>?) -> Bool { server.activate(count,failure) }
public func LibboxRouterInvalidatePerformance(_ server: LibboxCommandServer) { server.invalidatePadding() }
public func LibboxRouterPerformanceFailure(_ server: LibboxCommandServer) -> String? { server.performanceFailure() }
public func LibboxRouterStrategyStartService(_ server: LibboxCommandServer, _ content: String, _ failure: UnsafeMutablePointer<NSError?>?) -> Bool { server.captureConfiguration(content);return server.strategy("start",failure) }
public func LibboxRouterStrategyDNSProof(_ server: LibboxCommandServer, _ failure: UnsafeMutablePointer<NSError?>?) -> Bool { server.strategy("dns",failure) }
public func LibboxRouterStrategyCloseService(_ server: LibboxCommandServer, _ failure: UnsafeMutablePointer<NSError?>?) -> Bool { server.strategy("close",failure) }

public func LibboxRouterImportedEntryNewHopMeasurement(_ plan:LibboxRouterMultihop,_ server:LibboxCommandServer,_ failure:UnsafeMutablePointer<NSError?>?)->LibboxRouterHopMeasurement? { plan.healthy() ? LibboxRouterHopMeasurement():nil }
public func LibboxRouterNodeChainNewHopMeasurement(_ plan:LibboxRouterNodeChain,_ server:LibboxCommandServer,_ failure:UnsafeMutablePointer<NSError?>?)->LibboxRouterHopMeasurement? {plan.measurement(server)}
public func LibboxNewRouterHopMeasurement(_ server: LibboxCommandServer, _ metadata: String, _ failure: UnsafeMutablePointer<NSError?>?) -> LibboxRouterHopMeasurement? { LibboxRouterHopMeasurement() }

public func LibboxNewRouterMultihop(_ text: String, _ metadata: String, _ failure: UnsafeMutablePointer<NSError?>?) -> LibboxRouterMultihop? { LibboxTestState.shared.make(text) }
public func LibboxNewRouterMultihopWithEntryStartLayer(_ text: String, _ metadata: String, _ layer: String, _ failure: UnsafeMutablePointer<NSError?>?) -> LibboxRouterMultihop? { LibboxTestState.shared.make(text,layer:layer) }
public func LibboxNewRouterMultihopWithStartLayers(_ text: String, _ metadata: String, _ entry: String, _ exit: String, _ failure: UnsafeMutablePointer<NSError?>?) -> LibboxRouterMultihop? { LibboxTestState.shared.make(text,layer:entry,exit:exit) }
public func LibboxSetup(_ setup: LibboxSetupOptions, _ failure: UnsafeMutablePointer<NSError?>?) {LibboxTestState.shared.setup(setup.basePath)}
public func LibboxNewCommandServer(_ platform: AnyObject, _ handler: AnyObject, _ failure: UnsafeMutablePointer<NSError?>?) -> LibboxCommandServer? { let server=LibboxTestState.shared.makeServer();LibboxExecutionHostFixture.shared.returned(server,failure);return server }

public final class LibboxTorTestState: @unchecked Sendable {
    public static let shared = LibboxTorTestState()
    private let lock = NSLock()
    private var block = false, nativeError = false
    private var payload: String?
    private var request: LibboxRouterTorProofRequest?
    private var roots: [String] = []
    private var closeFailures = 0
    private var padding = ""
    public func configure(block: Bool = false, payload: String? = nil, nativeError: Bool = false, closeFailures:Int = 0, padding:String = "") { lock.lock(); self.block=block; self.payload=payload; self.nativeError=nativeError; self.closeFailures=closeFailures; self.padding=padding; request=nil; lock.unlock() }
    public func make(_ session: String, server:LibboxCommandServer) -> LibboxRouterTorProofRequest { lock.lock(); defer { lock.unlock() }; let value=LibboxRouterTorProofRequest(session,block,payload,nativeError,server,closeFailures,padding); request=value; return value }
    public func current() -> LibboxRouterTorProofRequest? { lock.lock(); defer { lock.unlock() }; return request }
    public func saveRoot(_ path: String) { lock.lock(); roots.append(path); lock.unlock() }
    public func stateRoots() -> [String] { lock.lock(); defer { lock.unlock() }; return roots }
}
// Deliberately non-Sendable, like the actual generated gomobile reference.
public final class LibboxRouterTorProofRequest {
    private let session: String, block: Bool, payload: String?, nativeError: Bool
    private let lock = NSLock()
    private var cancels = 0, proved = false
    private let server:LibboxCommandServer
    private var closeFailures:Int, closes=0, acknowledged=false, entryRetired=false
    private var padding:String, paddingError=false
    private let release = DispatchSemaphore(value:0)
    public let entered = DispatchSemaphore(value:0)
    init(_ session: String, _ block: Bool, _ payload: String?, _ nativeError: Bool, _ server:LibboxCommandServer, _ closeFailures:Int, _ padding:String) { self.session=session;self.block=block;self.payload=payload;self.nativeError=nativeError;self.server=server;self.closeFailures=closeFailures;self.padding=padding }
    // gobind v0.1.12: nonnull NSString plus NSErrorPointer, not Swift throws.
    public func run(_ failure: NSErrorPointer) -> String {
        entered.signal()
        if block { _ = release.wait(timeout:.now()+4) }
        lock.lock(); proved=true; lock.unlock()
        if nativeError { failure?.pointee=NSError(domain:"NativeTorRun",code:37) }
        if let payload { return payload }
        let clock=ISO8601DateFormatter();clock.formatOptions=[.withInternetDateTime,.withFractionalSeconds]
        let value:[String:Any] = ["session_id":session,"ip":"203.0.113.77","is_tor":true,"checked_at":clock.string(from:Date()),"dns_proven":true]
        do { return String(decoding:try JSONSerialization.data(withJSONObject:value),as:UTF8.self) }
        catch { failure?.pointee=error as NSError;return "" }
    }
    // Intentionally permits late Run success after cancel. The shipping host
    // must reject it even when a native callback arrives after its owner left.
    public func cancel() { lock.lock(); cancels+=1;lock.unlock();release.signal() }
    public func cancelCount() -> Int { lock.lock();defer {lock.unlock()};return cancels }
    public func healthy() -> Bool { lock.lock();defer{lock.unlock()};return cancels==0 && proved }
    public func configurePadding(_ text:String, fail:Bool=false){lock.lock();padding=text;paddingError=fail;lock.unlock()}
    public func paddingStatusJSON(_ failure:NSErrorPointer)->String{lock.lock();defer{lock.unlock()};if paddingError{failure?.pointee=NSError(domain:"NativePaddingStatus",code:1)};return padding}
    public func dnsSession() -> String { session }
    public func configureClose(failures:Int) { lock.lock();closeFailures=failures;lock.unlock() }
    public func retireEntry() { lock.lock();entryRetired=true;lock.unlock() }
    public func closeCount()->Int { lock.lock();defer{lock.unlock()};return closes }
    public func close()throws {
        cancel()
        lock.lock();defer{lock.unlock()}
        if acknowledged{return}
        closes+=1
        guard !entryRetired, !server.strategyCalls().contains("close") else {throw NSError(domain:"RetiredTorCleanupEntry",code:1)}
        if closeFailures>0 {closeFailures-=1;server.torCleanup(false);throw NSError(domain:"PendingTorDelete",code:1)}
        acknowledged=true;server.torCleanup(true)
    }
}
public func LibboxRouterTorSetStateDirectory(_ path:String,_ failure:UnsafeMutablePointer<NSError?>?) {
    do { try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700]);LibboxTorTestState.shared.saveRoot(path) }
    catch { failure?.pointee=error as NSError }
}
public func LibboxRouterTorCreateProof(_ server:LibboxCommandServer,_ tag:String,_ session:String,_ failure:UnsafeMutablePointer<NSError?>?) -> LibboxRouterTorProofRequest? { LibboxTorTestState.shared.make(session,server:server) }
public func LibboxRouterTorCreateProofWithPredecessor(_ server:LibboxCommandServer,_ tag:String,_ session:String,_ profile:String,_ failure:UnsafeMutablePointer<NSError?>?) -> LibboxRouterTorProofRequest? { LibboxTorTestState.shared.make(session,server:server) }
// The native compiler/source boundary is doubled here. The native graph gates
// separately reconstruct and validate the full exit and predecessor sources.
public func LibboxRouterTorPaddingSource(_ config:String,_ profile:String,_ session:String,_ failure:NSErrorPointer)->String {
    guard let value=try? JSONSerialization.jsonObject(with:Data(profile.utf8)) as? [String:Any] else{failure?.pointee=NSError(domain:"PaddingSourceFixture",code:1);return ""}
    return value["daita_enabled"] as? Bool==true ? String(repeating:"b",count:64):""
}
public final class LibboxExternalTestState: @unchecked Sendable {
    public static let shared = LibboxExternalTestState()
    private let lock = NSLock()
    private var block = false, invalid = false, nativeError = false
    private var execution = ""
    private var request: LibboxRouterExternalProofRequest?
    private var capture: [String] = []
    public func configure(block: Bool = false, invalid: Bool = false, nativeError: Bool = false, execution: String = "") { lock.lock(); self.block=block; self.invalid=invalid; self.nativeError=nativeError; self.execution=execution; request=nil; lock.unlock() }
    public func make(_ source: String, _ capture: String, _ session: String) -> LibboxRouterExternalProofRequest {
        lock.lock(); defer { lock.unlock() }
        self.capture=[source,capture,session]; let value=LibboxRouterExternalProofRequest(session,block,invalid,nativeError,execution);request=value;return value
    }
    public func current() -> LibboxRouterExternalProofRequest? { lock.lock(); defer { lock.unlock() }; return request }
    public func captured() -> [String] { lock.lock(); defer { lock.unlock() }; return capture }
}
// Foreign native references deliberately remain non-Sendable. Result-policy
// validation is exercised separately against shipping Swift and the Go compiler.
public final class LibboxRouterExternalProofRequest {
    private let session: String, block: Bool, invalid: Bool, nativeError: Bool
    private let lock=NSLock(), release=DispatchSemaphore(value:0)
    private var cancels=0,proved=false
    private var selectedExecution: String
    public let entered=DispatchSemaphore(value:0)
    init(_ session:String,_ block:Bool,_ invalid:Bool,_ nativeError:Bool,_ execution:String){self.session=session;self.block=block;self.invalid=invalid;self.nativeError=nativeError;self.selectedExecution=execution}
    public func run(_ failure: NSErrorPointer) -> String {
        entered.signal();if block {_ = release.wait(timeout:.now()+4)}
        lock.lock();proved = !invalid;lock.unlock()
        if nativeError { failure?.pointee=NSError(domain:"NativeExternalRun",code:41) }
        do { return String(decoding:try JSONSerialization.data(withJSONObject:["session_id":session,"valid": !invalid]),as:UTF8.self) }
        catch { failure?.pointee=error as NSError;return "" }
    }
    public func cancel(){lock.lock();cancels+=1;lock.unlock();release.signal()}
    public func close()throws{cancel()}
    public func cancelCount()->Int{lock.lock();defer{lock.unlock()};return cancels}
    public func healthy()->Bool{lock.lock();defer{lock.unlock()};return cancels==0 && proved}
    // These explicit native replies exercise the shipping host's validation.
    // The separate execution-owner gate proves real comparison/lease traffic.
    public func progressJSON()->String{"{}"}
    public func execution()->String{lock.lock();defer{lock.unlock()};return selectedExecution}
}
public func LibboxRouterExternalCreateProof(_ server:LibboxCommandServer,_ source:String,_ capture:String,_ session:String,_ failure:UnsafeMutablePointer<NSError?>?) -> LibboxRouterExternalProofRequest? { LibboxExternalTestState.shared.make(source,capture,session) }
public func LibboxRouterExternalCreateHopMeasurement(_ server:LibboxCommandServer,_ proof:LibboxRouterExternalProofRequest,_ source:String,_ capture:String,_ session:String,_ failure:UnsafeMutablePointer<NSError?>?) -> LibboxRouterHopMeasurement? {
    guard proof === LibboxExternalTestState.shared.current(),proof.healthy(),[source,capture,session]==LibboxExternalTestState.shared.captured()else{failure?.pointee=NSError(domain:"WrongNativeProof",code:1);return nil}
    return LibboxHopTestState.shared.make(["external",source,capture,session])
}
public func LibboxRouterTorCreateHopMeasurement(_ server:LibboxCommandServer,_ proof:LibboxRouterTorProofRequest,_ exitID:String,_ failure:UnsafeMutablePointer<NSError?>?) -> LibboxRouterHopMeasurement? {
    guard proof === LibboxTorTestState.shared.current(),proof.healthy()else{failure?.pointee=NSError(domain:"WrongNativeTorProof",code:1);return nil}
    return LibboxHopTestState.shared.make(["tor",exitID])
}
public func LibboxRouterExternalCreateDNSMeasurement(_ server:LibboxCommandServer,_ proof:LibboxRouterExternalProofRequest,_ source:String,_ capture:String,_ session:String,_ failure:UnsafeMutablePointer<NSError?>?) -> LibboxRouterDNSMeasurement? {
    guard proof === LibboxExternalTestState.shared.current(),proof.healthy(),[source,capture,session]==LibboxExternalTestState.shared.captured()else{failure?.pointee=NSError(domain:"WrongDNSNativeProof",code:1);return nil}
    return LibboxDNSTestState.shared.make(["external",source,capture,session],node:"saved-exit",session:session)
}
public func LibboxRouterTorCreateDNSMeasurement(_ server:LibboxCommandServer,_ proof:LibboxRouterTorProofRequest,_ exitID:String,_ failure:UnsafeMutablePointer<NSError?>?) -> LibboxRouterDNSMeasurement? {
    guard proof === LibboxTorTestState.shared.current(),proof.healthy()else{failure?.pointee=NSError(domain:"WrongDNSTorProof",code:1);return nil}
    return LibboxDNSTestState.shared.make(["tor",exitID],node:exitID,session:proof.dnsSession())
}

'''
HARNESS = r'''
import Foundation
import Libbox
import CryptoKit
// Policy compilation and schema validation have a real Swift/Go gate. This
// boundary isolates foreign-handle delivery, cancellation and exact config use.
struct RouterVPNExternalPolicy: Sendable {
    let sourceConfig: String, capture: String, config: String, metadata: String
    init(sourceConfig:String,capture:String,config:String,metadata:String="{}") {
        self.sourceConfig=sourceConfig;self.capture=capture;self.config=config;self.metadata=metadata
    }
    var executionRequested:String? {
        (try? JSONSerialization.jsonObject(with:Data(metadata.utf8)) as? [String:Any])?["execution"] as? String
    }
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
    let independentSession = UUID().uuidString
    var hasOwner = false
    var measurementReady = true
    private let proofLock=NSLock()
    private var changing = false
    var isChanging:Bool{get{proofLock.lock();defer{proofLock.unlock()};return changing}set{proofLock.lock();changing=newValue;proofLock.unlock()}}
    private var proofEpoch = UUID()
    var proofObservationToken:UUID?{proofLock.lock();defer{proofLock.unlock()};return changing ? nil:proofEpoch}
    func mutateProofEpoch(){proofLock.lock();proofEpoch=UUID();proofLock.unlock()}
    var statusCallback: (() -> Void)?
    private var server:LibboxCommandServer?
    private var failures=0,drained=false
    private(set) var closeSnapshots:[[String]]=[]
    private(set) var cleanupSnapshots:[[String]]=[]
    func initialMeasurementHold(_ lease: String) throws {}
    func stop(){try? stopChecked()}
    func stopChecked()throws {
        guard hasOwner,!drained else{return}
        closeSnapshots.append(server?.strategyCalls() ?? [])
        if failures>0{failures-=1;throw NSError(domain:"MTURetirementFixture",code:1)}
        drained=true
    }
    func invalidate() {}
    func drainForTorCleanup()throws {
        guard hasOwner,!drained else{return}
        cleanupSnapshots.append(server?.strategyCalls() ?? [])
        if failures>0{failures-=1;throw NSError(domain:"MTURetirementFixture",code:1)}
        drained=true
    }
    func activate(server: LibboxCommandServer, config: String, profile: String, onAbort: @escaping @Sendable (String) -> Void) { hasOwner = true;self.server=server;failures=MTUActivationFixture.shared.failures() }
    func activateImported(server:LibboxCommandServer,plan:LibboxRouterMultihop,onAbort:@escaping @Sendable(String)->Void)throws {
        guard plan.healthy() else{throw NSError(domain:"ImportedMTUFixture",code:1)}
        hasOwner=true;self.server=server;failures=MTUActivationFixture.shared.failures()
    }
    func activateNodeChain(server:LibboxCommandServer,plan:LibboxRouterNodeChain,onAbort:@escaping @Sendable(String)->Void)throws {
        guard plan.healthy() else{throw NSError(domain:"NodeChainMTUFixture",code:1)}
        hasOwner=true;self.server=server;failures=MTUActivationFixture.shared.failures()
        MTUActivationFixture.shared.recordChain(plan)
    }
    func activateExternal(server:LibboxCommandServer,proof:LibboxRouterExternalProofRequest,source:String,capture:String,onAbort:@escaping @Sendable(String)->Void)throws {
        guard proof.healthy() else{throw NSError(domain:"ExternalMTUFixture",code:1)}
        hasOwner=true;self.server=server;failures=MTUActivationFixture.shared.failures();MTUActivationFixture.shared.record([source,capture],proof:proof)
    }
    func activateTor(server:LibboxCommandServer,proof:LibboxRouterTorProofRequest,config:String,profile:String,onAbort:@escaping @Sendable(String)->Void)throws {
        guard proof.healthy() else{throw NSError(domain:"TorMTUFixture",code:1)}
        hasOwner=true;self.server=server;failures=MTUActivationFixture.shared.failures();MTUActivationFixture.shared.recordTor([config,profile],proof:proof)
    }
    func request(operation: String, request: String, session: String) -> Data? {
        guard operation == "mtu-status", session.isEmpty || session == independentSession else { return nil }
        let data=try? JSONSerialization.data(withJSONObject:["ack_id":request,"session_id":independentSession])
        let callback=statusCallback;statusCallback=nil;callback?()
        return data
    }
}
final class MTUActivationFixture:@unchecked Sendable {
    static let shared=MTUActivationFixture()
    private let lock=NSLock()
    private var values:[String]=[],proof:LibboxRouterExternalProofRequest?,callback:(()->Void)?
    private var torProof:LibboxRouterTorProofRequest?
    private var chain:LibboxRouterNodeChain?
    private var closeFailures=0
    private weak var platform:RouterVPNLibboxPlatform?
    func configure(failures:Int=0,_ callback:(()->Void)?=nil){lock.lock();values=[];proof=nil;torProof=nil;self.callback=callback;closeFailures=failures;lock.unlock()}
    func failures()->Int{lock.lock();defer{lock.unlock()};return closeFailures}
    func retainWeak(_ platform:RouterVPNLibboxPlatform){lock.lock();self.platform=platform;lock.unlock()}
    func currentPlatform()->RouterVPNLibboxPlatform?{lock.lock();defer{lock.unlock()};return platform}
    func record(_ values:[String],proof:LibboxRouterExternalProofRequest){lock.lock();self.values=values;self.proof=proof;let callback=self.callback;lock.unlock();callback?()}
    func recordTor(_ values:[String],proof:LibboxRouterTorProofRequest){lock.lock();self.values=values;torProof=proof;let callback=self.callback;lock.unlock();callback?()}
    func captured()->[String]{lock.lock();defer{lock.unlock()};return values}
    func owns(_ proof:LibboxRouterExternalProofRequest?)->Bool{lock.lock();defer{lock.unlock()};return self.proof === proof}
    func ownsTor(_ proof:LibboxRouterTorProofRequest?)->Bool{lock.lock();defer{lock.unlock()};return torProof === proof}
    func recordChain(_ plan:LibboxRouterNodeChain){lock.lock();chain=plan;let callback=self.callback;lock.unlock();callback?()}
    func ownsChain(_ plan:LibboxRouterNodeChain)->Bool{lock.lock();defer{lock.unlock()};return chain === plan}
}
final class RouterVPNLibboxPlatform {
    let mtu = MTUPlatformDouble()
    private(set) var resets=0
    init(tunnel: PacketTunnelProvider, settingsEpoch: String) {MTUActivationFixture.shared.retainWeak(self)}
    var onLog: ((String) -> Void)?
    var onStopService: (() throws -> Void)?
    var onReloadService: (() throws -> Void)?
    var includeAllNetworksRequested = false
    func reset() {resets+=1}
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
    private var nativeError: NSError?
    let done = DispatchSemaphore(value: 0)
    func finish(_ error: Error?) { lock.lock(); calls += 1; if let error { failures += 1;nativeError=error as NSError }; lock.unlock(); done.signal() }
    func values() -> (Int, Int) { lock.lock(); defer { lock.unlock() }; return (calls, failures) }
    func matches(_ domain: String, _ code: Int) -> Bool { lock.lock(); defer { lock.unlock() }; return nativeError?.domain==domain && nativeError?.code==code }
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
        let chainText="{\"inbounds\":[{\"type\":\"tun\",\"tag\":\"captured-chain-tun\"}],\"outbounds\":[]}"
        for scenario in ["success","cancel","proof-failure"] {
            MTUActivationFixture.shared.configure()
            let plan=LibboxRouterNodeChain(chainText,block:scenario=="cancel",fail:scenario=="proof-failure")
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState()
            try owner.start(nodeChain:plan,strict:true)
            let server=state.currentServer()!,directory=state.directory()
            check("ordered plan preserves one exact graph without proof injection",owner.ownsNodeChain && server.capturedConfiguration()==chainText && server.strategyCalls()==["start"])
            owner.completeNodeChainExecution(done.finish)
            if scenario=="cancel" {
                check("ordered Run entered original server",plan.entered.wait(timeout:.now()+2) == .success)
                try owner.stopCheckedForStrategy();plan.allowCompletion()
                check("ordered cancellation cannot deliver late success",done.wait() && done.values()==(1,1))
            } else if scenario=="proof-failure" {
                check("failed prefix or DNS cannot finish startup",done.wait() && done.values()==(1,1))
                var refused=false;do{try owner.activateNodeChainMTU()}catch{refused=true}
                check("unproved chain cannot adopt MTU",refused)
                try owner.stopCheckedForStrategy()
            } else {
                check("ordered proof completes once",done.wait() && done.values()==(1,0))
                try owner.activateNodeChainMTU()
                check("ordered MTU keeps original complete plan",MTUActivationFixture.shared.ownsChain(plan))
                check("ordered progress belongs to current plan",owner.multihopProgress() != nil)
                try owner.stopCheckedForStrategy()
            }
            check("ordered shutdown joins native proof and original service",plan.closeCalls()>=2 && server.strategyCalls()==["start","close"] && !FileManager.default.fileExists(atPath:directory))
            check("retired ordered progress cannot be delivered",!owner.ownsNodeChain && owner.multihopProgress()==nil)
        }
        do {
            let plan=LibboxRouterNodeChain(chainText),owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),before=state.counts()
            var refused=false
            do{try owner.start(files:files,strict:false,multihopMetadata:nil,nodeChainPlan:plan)}catch{refused=true}
            check("ordered substituted config is rejected before native start",refused && state.counts()==before)
            try plan.close()
        }
        for pause in [false,true] {
            let plan=LibboxRouterNodeChain(chainText),owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState()
            try owner.start(nodeChain:plan,strict:false)
            if pause{owner.pause()}else{owner.invalidateMultihop()}
            owner.completeNodeChainExecution(done.finish)
            check("ordered network change before delivery cannot publish readiness",done.wait() && done.values()==(1,1))
            try owner.stopCheckedForStrategy()
        }
        do {
            let plan=LibboxRouterNodeChain(chainText)
            var owner:RouterVPNLibboxEngine?=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            try owner!.start(nodeChain:plan,strict:true)
            let done=CompletionState();owner!.completeNodeChainExecution(done.finish)
            check("retirement fixture proves original chain",done.wait() && done.values()==(1,0))
            let server=state.currentServer()!,directory=state.directory(),before=state.counts()
            weak var platform=MTUActivationFixture.shared.currentPlatform()
            plan.configureClose(4)
            var refused=false;do{try owner!.stopCheckedForStrategy()}catch{refused=true}
            owner=nil
            check("unjoined ordered proof retains original TUN and private source",refused && platform != nil && platform?.resets==0 && FileManager.default.fileExists(atPath:directory) && state.counts()==before)
            let blocked=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            refused=false;do{try blocked.start(files:files,strict:false)}catch{refused=true}
            check("unjoined ordered proof blocks replacement service",refused && state.counts()==before)
            let replacement=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            try replacement.start(files:files,strict:false)
            check("joined ordered retry closes only original native owner",server.strategyCalls()==["start","close"] && !FileManager.default.fileExists(atPath:directory))
            replacement.stop()
        }
        do {
            let provider=PacketTunnelProvider(),owner=RouterVPNLibboxEngine(tunnel:provider),plan=LibboxRouterNodeChain(chainText),done=CompletionState()
            try owner.start(nodeChain:plan,strict:false);owner.completeNodeChainExecution(done.finish)
            check("health fixture proves original chain",done.wait() && done.values()==(1,0))
            let platform=MTUActivationFixture.shared.currentPlatform()!
            platform.mtu.isChanging=true;plan.configureHealth(false)
            Thread.sleep(forTimeInterval:1.15)
            check("only owned MTU transaction defers chain health failure",provider.count()==0)
            platform.mtu.isChanging=false
            plan.configureHealth(false){platform.mtu.mutateProofEpoch();plan.configureHealth(true)}
            Thread.sleep(forTimeInterval:1.15)
            check("completed MTU transaction cannot publish old health failure",provider.count()==0)
            plan.configureHealth(false)
            Thread.sleep(forTimeInterval:1.15)
            check("unowned ordinary health failure stops ordered service",provider.count()>0)
            try owner.stopCheckedForStrategy()
        }
        do {
            let plan=LibboxRouterNodeChain(chainText),owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState()
            try owner.start(nodeChain:plan,strict:false);owner.completeNodeChainExecution(done.finish)
            check("native retirement fixture proves original chain",done.wait() && done.values()==(1,0))
            let server=state.currentServer()!,directory=state.directory(),before=state.counts()
            server.configureStrategy(close:true)
            var refused=false;do{try owner.stopCheckedForStrategy()}catch{refused=true}
            check("failed original Box close retains private chain files",refused && state.counts()==before && FileManager.default.fileExists(atPath:directory))
            server.configureStrategy(close:false)
            try owner.stopCheckedForStrategy()
            check("native close retry uses only captured original Box",server.strategyCalls()==["start","close","close"] && !FileManager.default.fileExists(atPath:directory))
        }
        if CommandLine.arguments.contains("--chain-only") {
            print("Swift 6 ordered chain delivery: PASS (\(checks) shipping lifecycle checks; native handles doubled)");return
        }
        for cancel in [false, true] {
            state.configure(block: cancel)
            let exact = "{\"inbounds\":[{\"type\":\"mixed\",\"tag\":\"routervpn-proof\",\"listen\":\"127.0.0.1\",\"listen_port\":1099}],\"outbounds\":[]}"
            let plan = state.make(exact)
            let owner = RouterVPNLibboxEngine(tunnel: PacketTunnelProvider())
            try owner.start(files: ["sing-box.json": Data(exact.utf8)], strict: true, multihopMetadata: nil, importedPlan: plan)
            check("imported plan starts exact bytes without duplicate proof injection", state.currentServer()?.capturedConfiguration() == exact)
            let done = CompletionState(); owner.completeMultihopExecution(done.finish)
            if cancel {
                check("imported original Run entered", plan.entered.wait(timeout: .now()+2) == .success)
                owner.stop()
                check("imported Stop joins original proof cancellation", done.wait() && done.values() == (1, 1) && !plan.healthy())
            } else {
                check("imported proof delivery completes once", done.wait() && done.values() == (1, 0))
                try owner.enableHopMeasurement(metadata: plan.metadata())
                try owner.activateImportedMTU()
                owner.stop()
                check("imported Stop retires original plan", !plan.healthy())
            }
            let replaced = RouterVPNLibboxEngine(tunnel: PacketTunnelProvider())
            var rejected = false
            do { try replaced.start(files: files, strict: false, multihopMetadata: nil, importedPlan: state.make(exact)) } catch { rejected = true }
            check("imported graph byte substitution rejected", rejected)
        }
        state.configure()
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
        for exitMode in ["hysteria2","wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"] { for execution in ["local", "server"] {
            state.configure()
            let sourceBundle=try JSONSerialization.data(withJSONObject:["selectedRouterID":"exit","routerProfiles":[["id":"exit","multihop_enabled":true,"multihop_entry_id":"entry","multihop_exit_id":"exit","multihop_entry_mode":"max-quic-awg","multihop_exit_mode":exitMode,"multihop_execution":"auto"]]])
            let entryBundle=try JSONSerialization.data(withJSONObject:["selectedRouterID":"entry","routerProfiles":[["id":"entry"]]])
            let source=try IOSMultihopExecution.Source(configuration:["engine":"multihop-libbox","mode":exitMode,"bundle":sourceBundle,"entryBundle":entryBundle]) { $0==sourceBundle ? String(repeating:"a",count:64):String(repeating:"b",count:64) }
            let metadata=String(decoding:try JSONSerialization.data(withJSONObject:["entry_id":"entry","exit_id":"exit","entry_mode":"max-quic-awg","exit_mode":exitMode,"execution":execution]),as:UTF8.self)
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState(),request=String(repeating:"c",count:32)
            try owner.start(files:files,strict:true,multihopMetadata:metadata)
            owner.completeMultihopExecution(done.finish)
            check("restorable execution waits for controller completion",done.wait() && done.values()==(1,0))
            state.current()!.setExecution(execution)
            var fields:[String:String]=[:]
            if execution=="server" && exitMode != "hysteria2" {
                fields["expected_packet_public_key"]=Data(repeating:7,count:32).base64EncodedString()
                if exitMode.contains("pq") || exitMode.hasPrefix("max-") {fields["expected_pq_client_identity"]=String(repeating:"a",count:64)}
            }
            let pinsJSON=String(decoding:try JSONSerialization.data(withJSONObject:fields),as:UTF8.self)
            state.current()!.setPins(pinsJSON)
            check("comparison alone cannot expose unproved original source",owner.multihopExecutionSnapshot(request:request)==nil)
            try owner.enableHopMeasurement(metadata:metadata)
            var rejected=false
            do{try owner.bindMultihopExecutionSource(source,metadata:metadata.replacingOccurrences(of:"max-quic-awg",with:"wg"))}catch{rejected=true}
            check("runtime source binding rejects changed entry mode",rejected)
            try owner.bindMultihopExecutionSource(source,metadata:metadata)
            let captured=try IOSMultihopExecution.Capture.decode(owner.multihopExecutionSnapshot(request:request)!,source:source,request:request)
            check("receipt binds actual winner and native epoch without changing requested auto",captured.execution==execution && captured.sessionID==owner.settingsEpoch && captured.source.requested=="auto")
            let expectedPins=try IOSMultihopExecution.ServerIdentityPins(json:pinsJSON,source:source,execution:execution)
            check("actual native owner pins reach the same receipt",captured.pins==expectedPins)
            state.current()!.setPins(pinsJSON,fail:true)
            check("failed native pin capture cannot mint a partial receipt",owner.multihopExecutionSnapshot(request:request)==nil)
            state.current()!.setPins("{\"private_key\":\"unowned\"}")
            check("extra native fields cannot leak into a receipt",owner.multihopExecutionSnapshot(request:request)==nil)
            state.current()!.setPins(pinsJSON)
            check("malformed request cannot mint a restoration receipt",owner.multihopExecutionSnapshot(request:"foreign")==nil)
            state.current()!.setExecution(execution,complete:false)
            check("unfinished comparison cannot be restored",owner.multihopExecutionSnapshot(request:request)==nil)
            state.current()!.setExecution(execution)
            owner.invalidateMultihop()
            check("expired network or lease invalidates the winner receipt",owner.multihopExecutionSnapshot(request:request)==nil)
            owner.stop()
            check("retired native owner cannot expose a winner",owner.multihopExecutionSnapshot(request:request)==nil)
        }}
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
        let torProfile="{\"id\":\"captured-tor\",\"node_kind\":\"external\",\"mtu_policy\":\"auto\",\"external\":{\"protocol\":\"tor\"}}"
        let torConfig="{\"inbounds\":[{\"type\":\"tun\",\"tag\":\"captured-tun\",\"mtu\":1380}],\"outbounds\":[{\"type\":\"routervpn-tor\",\"tag\":\"routervpn-tor-exit\",\"session_id\":\"tor-session\"}],\"route\":{\"final\":\"routervpn-tor-exit\"}}"
        let torFiles=["sing-box.json":Data(torConfig.utf8)]
        let torServerConfig=torConfig.replacingOccurrences(of:"\"routervpn-tor\"",with:"\"routervpn-server-tor\"")
        let torServerFiles=["sing-box.json":Data(torServerConfig.utf8)]
        let torEntryProfile="{\"id\":\"entry\",\"node_kind\":\"router-vpn\"}"
        let torServerProfile="{\"id\":\"captured-tor\",\"node_kind\":\"external\",\"mtu_policy\":\"auto\",\"multihop_enabled\":true,\"multihop_execution\":\"server\",\"multihop_entry_id\":\"entry\",\"multihop_entry_mode\":\"wg\",\"multihop_exit_id\":\"captured-tor\",\"multihop_exit_mode\":\"tor\",\"external\":{\"protocol\":\"tor\",\"expected_public_ip\":\"\"}}"
        let externalState=LibboxExternalTestState.shared
        let externalConfig="{\"inbounds\":[{\"type\":\"tun\",\"tag\":\"captured-tun\"}],\"outbounds\":[] }"
        let externalFiles=["sing-box.json":Data(externalConfig.utf8)]
        let externalCapture=String(decoding:try JSONSerialization.data(withJSONObject:[
            "schema":1,"exit_id":"saved-exit","protocol":"shadowsocks","expected_public_ip":"198.51.100.9",
            "profile":["id":"saved-exit","node_kind":"external","mtu_policy":"auto",
                       "external":["protocol":"shadowsocks","expected_public_ip":"198.51.100.9"]]
        ],options:[.sortedKeys]),as:UTF8.self)
        let externalPolicy=RouterVPNExternalPolicy(sourceConfig:"exact source bytes",capture:externalCapture,config:externalConfig)
        for action in ["stable","stop","network","pause","invalid","native-error"] {
            state.configure();externalState.configure(block:["stop","network","pause"].contains(action),invalid:action=="invalid",nativeError:action=="native-error")
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
            if action=="native-error" { check("external nonempty result cannot hide the native NSError",done.matches("NativeExternalRun",41)) }
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
        let paddingProfile=torProfile.dropLast()+",\"daita_enabled\":true,\"daita_rate_kbps\":64}"
        let paddingSession="f23e19720ad035b32b52db1cd4c22f294256ed705f38d54fd58d073dc3baba64"
        func paddingValue(_ now:Date = Date())->[String:Any] {
            let t=Int64((now.timeIntervalSince1970*1000).rounded(.down))
            return ["path_checked_at":t-100,"dns_checked_at":t-200,"receipt":[
                "direction":"outgoing","accounting":"tor-link-cell","session_sha256":paddingSession,"source_sha256":String(repeating:"b",count:64),
                "generation":7,"rate_kbps":64,"channel_cells":2,"channel_cell_bytes":1028,"observed_at":t-50,"expires_at":t+9000]]
        }
        func paddingText(_ value:[String:Any])throws->String{String(decoding:try JSONSerialization.data(withJSONObject:value),as:UTF8.self)}
        do {
            let now=Date(),value=paddingValue(now),text=try paddingText(value)
            let policy=try RouterVPNTorPaddingReceipt.Policy.capture(config:torConfig,profile:String(paddingProfile),sessionID:"tor-session",execution:"local")
            let initial=try policy.validate(text,previous:nil,now:now)
            check("padding capture hashes the exact session independently",policy.sessionSHA256==paddingSession && policy.rate==64 && policy.enabled)
            check("padding accepts its actual observed counters",initial?.cells==2 && initial?.bytes==1028)
            let same=try policy.validate(text,previous:initial,now:now)
            check("reading a receipt never renews its timestamps",same==initial)
            let t=Int64((now.timeIntervalSince1970*1000).rounded(.down))
            let faults:[(String,Any)] = [
                ("direction","incoming"),("accounting","delivered-bytes"),("session_sha256",String(repeating:"a",count:64)),("source_sha256",String(repeating:"a",count:64)),
                ("generation",0),("generation",true),("generation",1.5),("generation",UInt64(Int64.max)+1),("rate_kbps",192),("rate_kbps","64"),
                ("channel_cells",0),("channel_cells",UInt64.max),("channel_cell_bytes",1023),("channel_cell_bytes",1027),("channel_cell_bytes",1030),
                ("observed_at",t+1),("observed_at",t-5001),("expires_at",t),("expires_at",t+10001),("observed_at",false),("expires_at",Int64.max)]
            for (key,bad) in faults {
                var changed=value,receipt=value["receipt"] as! [String:Any];receipt[key]=bad;changed["receipt"]=receipt
                var rejected=false;do{_ = try policy.validate(paddingText(changed),previous:nil,now:now)}catch{rejected=true}
                check("padding receipt rejects invalid "+key+":"+String(describing:bad),rejected)
            }
            for (key,bad) in [("dns_checked_at",t),("path_checked_at",t+1),("dns_checked_at",t-30001),("path_checked_at",Int64(0))] {
                var changed=value;changed[key]=bad
                var rejected=false;do{_ = try policy.validate(paddingText(changed),previous:nil,now:now)}catch{rejected=true}
                check("padding receipt rejects invalid proof completion "+key,rejected)
            }
            for fault in ["generation","cells","bytes","observed","dns","path","missing","extra","cached"] {
                var changed=value,receipt=value["receipt"] as! [String:Any]
                switch fault {
                case "generation":receipt["generation"]=8
                case "cells":receipt["channel_cells"]=1;receipt["channel_cell_bytes"]=514
                case "bytes":receipt["channel_cell_bytes"]=1024
                case "observed":receipt["observed_at"]=t-51
                case "dns":changed["dns_checked_at"]=t-201
                case "path":changed["path_checked_at"]=t-101
                case "missing":receipt.removeValue(forKey:"generation")
                case "extra":receipt["delivered"]=true
                default:break
                }
                changed["receipt"]=receipt
                var rejected=false;do{_ = try policy.validate(paddingText(changed),previous:initial,now:fault=="cached" ? now.addingTimeInterval(6):now)}catch{rejected=true}
                check("padding progress rejects "+fault,rejected)
            }
            for execution in ["local","server"] {
                let off=try RouterVPNTorPaddingReceipt.Policy.capture(config:torConfig,profile:torProfile,sessionID:"tor-session",execution:execution)
                let absent=try off.validate("",previous:nil,now:now)
                check("Off and Server own no Local receipt",absent==nil)
                var rejected=false;do{_ = try off.validate(text,previous:nil,now:now)}catch{rejected=true}
                check("Off and Server reject a hidden Local padding owner",rejected)
            }
            for rate in ["31","193","-1","true","null","\"64\"","64.5"] {
                let invalid=String(paddingProfile).replacingOccurrences(of:"\"daita_rate_kbps\":64",with:"\"daita_rate_kbps\":"+rate)
                var rejected=false;do{_ = try RouterVPNTorPaddingReceipt.Policy.capture(config:torConfig,profile:invalid,sessionID:"tor-session",execution:"local")}catch{rejected=true}
                check("padding capture rejects invalid selected rate "+rate,rejected)
            }
        }
        for invalid in [false,true] {
            torState.configure(padding:invalid ? "":try paddingText(paddingValue()))
            let provider=PacketTunnelProvider(),owner=RouterVPNLibboxEngine(tunnel:provider),done=CompletionState()
            try owner.start(files:torFiles,strict:true)
            owner.proveTor(sessionID:"tor-session",profile:String(paddingProfile),completion:done.finish)
            check("enabled padding requires its retained native receipt",done.wait() && done.values()==(1,invalid ? 1:0))
            if !invalid {
                try owner.activateTorMTU()
                let request=torState.current()!
                request.configurePadding(try paddingText(paddingValue()),fail:true)
                var rejected=false;do{try owner.activateTorMTU()}catch{rejected=true}
                check("padding native error cannot be hidden by nonempty receipt",rejected)
                request.configurePadding(try paddingText(paddingValue()))
                rejected=false;do{try owner.activateTorMTU()}catch{rejected=true}
                check("a rejected receipt cannot revive its old native owner",rejected && request.cancelCount()>0)
                let deadline=Date().addingTimeInterval(3)
                while provider.count()==0 && Date()<deadline{Thread.sleep(forTimeInterval:0.01)}
                check("padding receipt loss retires the exact Apple owner",provider.count()>0)
            }
            owner.stop()
        }
        do {
            torState.configure(padding:try paddingText(paddingValue()))
            let provider=PacketTunnelProvider(),owner=RouterVPNLibboxEngine(tunnel:provider),done=CompletionState()
            try owner.start(files:torFiles,strict:true)
            owner.proveTor(sessionID:"tor-session",profile:String(paddingProfile),completion:done.finish)
            check("padding health fixture starts with a valid receipt",done.wait() && done.values()==(1,0))
            let request=torState.current()!;request.configurePadding("{}")
            check("native healthy alone cannot represent a valid receipt",request.healthy())
            let deadline=Date().addingTimeInterval(3)
            while provider.count()==0 && Date()<deadline{Thread.sleep(forTimeInterval:0.01)}
            check("padding timer validates receipts independently of native healthy flag",provider.count()>0 && request.cancelCount()>0)
            owner.stop()
        }
        do {
            torState.configure(nativeError:true)
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState()
            try owner.start(files:torFiles,strict:true)
            let server=state.currentServer()!
            owner.proveTor(sessionID:"tor-session",profile:torProfile,completion:done.finish)
            check("Tor nonempty result cannot hide the native NSError",done.wait() && done.values()==(1,1) && done.matches("NativeTorRun",37))
            check("failed Tor native result cannot start subsequent DNS proof",server.strategyCalls()==["start"])
            owner.stop()
        }
        for profile in ["", "[]", "null",String(repeating:" ",count:4*1024*1024+1)] {
            torState.configure()
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState()
            try owner.start(files:torFiles,strict:true)
            owner.proveTor(sessionID:"tor-session",profile:profile,completion:done.finish)
            check("Tor proof rejects a missing or malformed frozen profile",done.values()==(1,1) && torState.current()==nil)
            owner.stop()
        }
        for invalid in ["listener","second-tun","wrong-final","other-controller"] {
            var graph=try JSONSerialization.jsonObject(with:Data(torConfig.utf8)) as! [String:Any]
            var inbounds=graph["inbounds"] as! [[String:Any]]
            if invalid=="listener"{inbounds.append(["type":"mixed","tag":"unused-proof","listen":"127.0.0.1","listen_port":1099])}
            if invalid=="second-tun"{inbounds.append(["type":"tun","tag":"other-tun"])}
            graph["inbounds"]=inbounds
            if invalid=="wrong-final"{graph["route"]=["final":"direct"]}
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),before=state.counts()
            var rejected=false
            do{try owner.start(files:["sing-box.json":try JSONSerialization.data(withJSONObject:graph)],strict:true,multihopMetadata:invalid=="other-controller" ? "{}":nil)}catch{rejected=true}
            check("Tor cannot gain an unproved listener or competing graph owner",rejected && state.counts()==before)
        }
        for cancelled in [false,true] {
            torState.configure(block:cancelled)
            let provider=PacketTunnelProvider(), owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            try owner.start(files:torFiles,strict:true)
            check("Tor keeps the exact compiled graph without a local proof listener",state.currentServer()!.capturedConfiguration()==torConfig)
            let done=CompletionState()
            owner.proveTor(sessionID:"tor-session",profile:torProfile,completion:done.finish)
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
        let privateRoot=URL(fileURLWithPath:torState.stateRoots()[0]).resolvingSymlinksInPath().path
        check("Tor uses a stable private directory across new engine roots",Set(torState.stateRoots()).count==1 && torState.stateRoots().count>=2 && state.directories().allSatisfy{directory in
            let runtime=URL(fileURLWithPath:directory).resolvingSymlinksInPath().path
            return privateRoot != runtime && !privateRoot.hasPrefix(runtime+"/")
        })
        for selection in ["local","auto"] {
            torState.configure()
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState()
            try owner.start(files:torServerFiles,strict:true)
            owner.proveTor(sessionID:UUID().uuidString,profile:torServerProfile.replacingOccurrences(of:"\"server\"",with:"\""+selection+"\""),predecessorProfile:torEntryProfile,completion:done.finish)
            check("Server source cannot change its selected execution before proof",done.wait() && done.values()==(1,1) && torState.current()==nil)
            owner.stop()
        }
        for execution in ["local","server"] {
            let original=torServerProfile.replacingOccurrences(of:"\"server\"",with:"\"auto\"")
            let leaf=torServerProfile.replacingOccurrences(of:"\"server\"",with:"\""+execution+"\"")
            state.configure();torState.configure();LibboxHopTestState.shared.configure();LibboxDNSTestState.shared.configure();MTUActivationFixture.shared.configure()
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState()
            try owner.start(files:execution=="server" ? torServerFiles:torFiles,strict:true)
            check("unproved Tor cannot export comparison handles",owner.torComparisonNative()==nil)
            owner.proveTor(sessionID:UUID().uuidString,profile:leaf,predecessorProfile:torEntryProfile,sourceProfile:original,completion:done.finish)
            check("Compare proof retains original auto and exact leaf",done.wait() && done.values()==(1,0))
            let captured=owner.torComparisonNative()
            check("Compare exports only the exact retained server and proof",captured?.0 === state.currentServer() && captured?.1 === torState.current())
            let exit=try JSONSerialization.jsonObject(with:Data(original.utf8)) as! [String:Any],entry=try JSONSerialization.jsonObject(with:Data(torEntryProfile.utf8)) as! [String:Any]
            let configuration:[String:Any]=["engine":"external-libbox","mode":"external-tor","bundle":try JSONSerialization.data(withJSONObject:["selectedRouterID":"captured-tor","routerProfiles":[exit]]),"tor_entry_bundle":try JSONSerialization.data(withJSONObject:["selectedRouterID":"entry","routerProfiles":[entry]]),"tor_entry_mode":"wg"]
            let source=try IOSMultihopExecution.Source(configuration:configuration){_ in String(repeating:"a",count:64)}
            try owner.enableExternalHopMeasurement(exitID:"captured-tor");try owner.enableExternalDNSMeasurement(exitID:"captured-tor");try owner.activateTorMTU();try owner.bindTorExecutionSource(source)
            let request=String(repeating:"c",count:32),snapshot=try IOSMultihopExecution.Capture.decode(owner.multihopExecutionSnapshot(request:request)!,source:source,request:request)
            check("Compare restoration receipt preserves original auto and proved leaf",snapshot.source.requested=="auto" && snapshot.execution==execution && snapshot.pins == .empty)
            let info=owner.hopMeasurementRequest(operation:"hop-measure-info",request:request,session:"")!
            let binding=try IOSHopMeasurementBinding.decode(info,request:request,mtuSession:MTUActivationFixture.shared.currentPlatform()!.mtu.independentSession)
            let fingerprint=SHA256.hash(data:Data(state.currentServer()!.capturedConfiguration().utf8)).map{String(format:"%02x",$0)}.joined()
            check("Tor measurement Info retains original auto and proved leaf",binding.node_id=="captured-tor" && binding.execution?.valid==true && binding.execution?.requested=="auto" && binding.execution?.selected==execution && binding.execution?.config_sha256==fingerprint)
            owner.stop();check("retired Tor cannot export comparison handles",owner.torComparisonNative()==nil)
            for field in ["dns_host","ipv6_mode","home_lan_access","manual_mtu","multihop_entry_id","external"] {
                state.configure();torState.configure()
                let changedOwner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),rejected=CompletionState()
                try changedOwner.start(files:execution=="server" ? torServerFiles:torFiles,strict:true)
                var wrong=try JSONSerialization.jsonObject(with:Data(leaf.utf8)) as! [String:Any]
                if field=="external"{wrong[field]=["protocol":"tor-bridge","expected_public_ip":""]}
                else if field=="home_lan_access"{wrong[field]=false}
                else if field=="manual_mtu"{wrong[field]=1380}
                else{wrong[field]="changed"}
                changedOwner.proveTor(sessionID:UUID().uuidString,profile:String(decoding:try JSONSerialization.data(withJSONObject:wrong),as:UTF8.self),predecessorProfile:torEntryProfile,sourceProfile:original,completion:rejected.finish)
                check("Compare source mutation is rejected before native proof",rejected.wait() && rejected.values()==(1,1) && torState.current()==nil && changedOwner.torComparisonNative()==nil)
                changedOwner.stop()
            }
        }
        for kind in ["tor","tor-bridge"] {for mode in ["wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn"] {
            let entry:[String:Any]=["id":"entry","node_kind":"external","router_api":"","api_token":"","node_proof_id":"",
                "external":["protocol":mode,"expected_public_ip":"203.0.113.88",mode.replacingOccurrences(of:"-",with:"_"):["password":"exact ordinary credential"]],
                "dns_mode":"custom","dns_protocol":"tcp","dns_host":"9.9.9.9","dns_port":5353,"mtu_policy":"fixed","manual_mtu":1380]
            let selected:[String:Any]=["id":"captured-tor","node_kind":"external","external":["protocol":kind,"expected_public_ip":""],
                "multihop_enabled":true,"multihop_execution":"local","multihop_entry_id":"entry","multihop_entry_mode":mode,"multihop_exit_id":"captured-tor","multihop_exit_mode":kind]
            let configuration:[String:Any]=["engine":"external-libbox","mode":"external-"+kind,
                "bundle":try JSONSerialization.data(withJSONObject:["selectedRouterID":"captured-tor","routerProfiles":[selected]]),
                "tor_entry_bundle":try JSONSerialization.data(withJSONObject:["selectedRouterID":"entry","routerProfiles":[entry]]),"tor_entry_mode":mode]
            let source=try IOSMultihopExecution.Source(configuration:configuration){_ in String(repeating:"a",count:64)}
            for fault in ["stable","private-token","wrong-protocol","missing-public-ip","lost-proof"] {
                state.configure();torState.configure();LibboxHopTestState.shared.configure();LibboxDNSTestState.shared.configure();MTUActivationFixture.shared.configure()
                let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState()
                try owner.start(files:torFiles,strict:true)
                var capturedEntry=entry
                if fault=="private-token" {capturedEntry["api_token"]="unowned private authority"}
                if fault=="wrong-protocol" {var ext=capturedEntry["external"] as! [String:Any];ext["protocol"]="foreign";capturedEntry["external"]=ext}
                if fault=="missing-public-ip" {var ext=capturedEntry["external"] as! [String:Any];ext["expected_public_ip"]="";capturedEntry["external"]=ext}
                let profile=String(decoding:try JSONSerialization.data(withJSONObject:selected),as:UTF8.self)
                let predecessor=String(decoding:try JSONSerialization.data(withJSONObject:capturedEntry),as:UTF8.self)
                owner.proveTor(sessionID:UUID().uuidString,profile:profile,predecessorProfile:predecessor,completion:done.finish)
                check("ordinary Tor proof delivery completes before binding",done.wait() && done.values()==(1,0))
                try owner.enableExternalHopMeasurement(exitID:"captured-tor")
                try owner.enableExternalDNSMeasurement(exitID:"captured-tor")
                try owner.activateTorMTU()
                if fault=="lost-proof" {torState.current()!.cancel()}
                var refused=false;do{try owner.bindTorExecutionSource(source)}catch{refused=true}
                check("ordinary Tor binds only the current typed Local proof",refused == (fault != "stable"))
                let request=String(repeating:"d",count:32),snapshot=owner.multihopExecutionSnapshot(request:request)
                if fault=="stable" {
                    let receipt=try snapshot.map{try IOSMultihopExecution.Capture.decode($0,source:source,request:request)}
                    check("ordinary Tor retained receipt uses actual Local native owner",receipt?.execution=="local" && receipt?.source==source && receipt?.pins == .empty)
                    torState.current()!.cancel()
                    check("lost ordinary Tor proof immediately revokes restoration",owner.multihopExecutionSnapshot(request:request)==nil)
                } else {check("invalid ordinary Tor cannot expose a restore receipt",snapshot==nil)}
                owner.stop()
                check("ordinary Tor stop retires exact proof and receipt",torState.current()!.cancelCount()>0 && owner.multihopExecutionSnapshot(request:request)==nil)
            }
        }}
        for action in ["stable","cancel-proof","delete-retry","reconnect-retry","mtu-retry","hop-retry","dns-retry","native-retry"] {
            torState.configure(block:action=="cancel-proof",closeFailures:action=="delete-retry" ? 2:(action=="reconnect-retry" ? 1:0))
            MTUActivationFixture.shared.configure(failures:action=="mtu-retry" ? 1:0)
            let roots=torState.stateRoots().count,provider=PacketTunnelProvider()
            var owner:RouterVPNLibboxEngine?=RouterVPNLibboxEngine(tunnel:provider)
            try owner!.start(files:torServerFiles,strict:true)
            let server=state.currentServer()!,directory=state.directory(),platform=MTUActivationFixture.shared.currentPlatform()!
            check("Server never initializes a local Tor directory",torState.stateRoots().count==roots && server.capturedConfiguration()==torServerConfig)
            let done=CompletionState();owner!.proveTor(sessionID:UUID().uuidString,profile:torServerProfile,predecessorProfile:torEntryProfile,completion:done.finish)
            let request=torState.current()!
            if action=="cancel-proof" {
                check("Server native proof entered before cancel",request.entered.wait(timeout:.now()+2) == .success)
            } else {
                check("Server proves captured exit and selected DNS",done.wait() && done.values()==(1,0))
                let profile=try JSONSerialization.jsonObject(with:Data(torServerProfile.utf8)) as! [String:Any]
                let entry=try JSONSerialization.jsonObject(with:Data(torEntryProfile.utf8)) as! [String:Any]
                let configuration:[String:Any]=["engine":"external-libbox","mode":"external-tor","bundle":try JSONSerialization.data(withJSONObject:["selectedRouterID":"captured-tor","routerProfiles":[profile]]),"tor_entry_bundle":try JSONSerialization.data(withJSONObject:["selectedRouterID":"entry","routerProfiles":[entry]]),"tor_entry_mode":"wg"]
                let source=try IOSMultihopExecution.Source(configuration:configuration){_ in String(repeating:"a",count:64)}
                var refused=false;do{try owner!.bindTorExecutionSource(source)}catch{refused=true}
                check("Tor execution cannot bind before measurement and MTU adoption",refused)
                try owner!.enableExternalHopMeasurement(exitID:"captured-tor")
                try owner!.enableExternalDNSMeasurement(exitID:"captured-tor")
                try owner!.activateTorMTU();try owner!.bindTorExecutionSource(source)
                let id=String(repeating:"d",count:32),receipt=owner!.multihopExecutionSnapshot(request:id)
                let captured=try receipt.map{try IOSMultihopExecution.Capture.decode($0,source:source,request:id)}
                check("actual proved Tor execution is retained for restoration",captured?.execution=="server")
                let info=owner!.hopMeasurementRequest(operation:"hop-measure-info",request:id,session:"")!
                let binding=try IOSHopMeasurementBinding.decode(info,request:id,mtuSession:platform.mtu.independentSession)
                check("Tor Server measurement Info requires its actual proved execution",binding.node_id=="captured-tor" && binding.execution?.valid==true && binding.execution?.requested=="server" && binding.execution?.selected=="server")
            }
            if action=="hop-retry" {LibboxHopTestState.shared.current()!.configure(closeFails:true)}
            if action=="dns-retry" {LibboxDNSTestState.shared.current()!.configure(hold:true)}
            if action=="native-retry" {server.configureStrategy(close:true)}
            let before=state.counts()
            var failed=false;do{try owner!.stopCheckedForStrategy()}catch{failed=true}
            check("Server cancellation cannot retain a data receipt",request.cancelCount()>0 && owner!.multihopExecutionSnapshot(request:String(repeating:"d",count:32))==nil)
            if action=="delete-retry" || action=="reconnect-retry" {
                check("pending DELETE keeps exact native Box and files",failed && state.counts()==before && !server.strategyCalls().contains("close") && FileManager.default.fileExists(atPath:directory))
                check("pending DELETE preserves physical monitor until acknowledgment",platform.resets==0 && platform.mtu.closeSnapshots.isEmpty)
                if action=="delete-retry" {
                    let blocked=RouterVPNLibboxEngine(tunnel:provider)
                    var rejected=false;do{try blocked.start(files:files,strict:false)}catch{rejected=true}
                    check("unacknowledged old lease blocks a replacement owner",rejected && state.counts()==before)
                    try owner!.stopCheckedForStrategy()
                    check("same retained request retries DELETE",request.closeCount()==3)
                } else {
                    owner=nil
                    torState.configure()
                    let replacement=RouterVPNLibboxEngine(tunnel:provider)
                    try replacement.start(files:files,strict:false)
                    check("new start joins the retired exact lease before construction",request.closeCount()==2 && server.strategyCalls().last=="close")
                    replacement.stop()
                }
            } else if ["mtu-retry","hop-retry","dns-retry"].contains(action) {
                check("measurement drain precedes DELETE and keeps the exact entry",failed && state.counts()==before && request.closeCount()==0 && !server.strategyCalls().contains("close") && FileManager.default.fileExists(atPath:directory))
                check("measurement drain cannot terminally retire the physical monitor",platform.resets==0 && platform.mtu.closeSnapshots.isEmpty)
                if action=="hop-retry" {LibboxHopTestState.shared.current()!.configure(closeFails:false)}
                if action=="dns-retry" {LibboxDNSTestState.shared.current()!.configure(hold:false)}
                try owner!.stopCheckedForStrategy()
                check("same measurement owner drains before the sole DELETE",request.closeCount()==1 && server.strategyCalls().filter{$0=="close"}.count==1)
            } else if action=="native-retry" {
                check("acknowledged lease retains a failed native Box drain",failed && request.closeCount()==1 && FileManager.default.fileExists(atPath:directory) && platform.resets==0)
                server.configureStrategy()
                try owner!.stopCheckedForStrategy()
                check("native retry cannot DELETE an acknowledged lease again",request.closeCount()==1)
            } else { check("Server teardown completed",!failed) }
            let deletion=server.strategyCalls().firstIndex(of:"tor-delete"),closure=server.strategyCalls().firstIndex(of:"close")
            check("Server DELETE precedes native Box closure",deletion != nil && closure != nil && deletion! < closure!)
            check("successful Server close removes only owned runtime",!FileManager.default.fileExists(atPath:directory) && platform.resets==1)
            if action=="cancel-proof" {check("late Server proof never reconnects",done.wait() && done.values()==(1,1))}
        }
        for fails in [false,true] {
            torState.configure()
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            try owner.start(files:torFiles,strict:true)
            let server=state.currentServer()!;server.configureStrategy(dns:fails)
            let done=CompletionState();owner.proveTor(sessionID:"tor-session",profile:torProfile,completion:done.finish)
            check("Tor requires its selected native DNS before Connected",done.wait() && done.values()==(1,fails ? 1:0))
            check("Tor DNS proof belongs to the same captured runtime",server.strategyCalls()==["start","dns"])
            owner.stop()
        }
        do {
            torState.configure()
            let provider=PacketTunnelProvider(),owner=RouterVPNLibboxEngine(tunnel:provider)
            try owner.start(files:torFiles,strict:true)
            let done=CompletionState();owner.proveTor(sessionID:"tor-session",profile:torProfile,completion:done.finish)
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
            let done=CompletionState();owner.proveTor(sessionID:"tor-session",profile:torProfile,completion:done.finish)
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
            let done=CompletionState();owner.proveTor(sessionID:"tor-session",profile:torProfile,completion:done.finish)
            check("malformed/replayed/non-Tor results cannot report Connected",done.wait() && done.values()==(1,1));owner.stop()
        }
        for fault in ["missing","false","number","string","null","tor-number"] {
            let clock=ISO8601DateFormatter();clock.formatOptions=[.withInternetDateTime,.withFractionalSeconds]
            var proof:[String:Any] = ["session_id":"tor-session","ip":"203.0.113.77","is_tor":true,"checked_at":clock.string(from:Date()),"dns_proven":true]
            switch fault {
            case "missing":proof.removeValue(forKey:"dns_proven")
            case "false":proof["dns_proven"]=false
            case "number":proof["dns_proven"]=1
            case "string":proof["dns_proven"]="true"
            case "null":proof["dns_proven"]=NSNull()
            default:proof["is_tor"]=1
            }
            let payload=String(decoding:try JSONSerialization.data(withJSONObject:proof),as:UTF8.self)
            torState.configure(payload:payload)
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            try owner.start(files:torFiles,strict:false)
            let done=CompletionState();owner.proveTor(sessionID:"tor-session",profile:torProfile,completion:done.finish)
            check("Tor cannot connect without exact Boolean DNS/exit proof: "+fault,done.wait() && done.values()==(1,1));owner.stop()
        }
        let hopState=LibboxHopTestState.shared
        // Explicit compiler-receipt fixtures exercise the actual engine. The
        // separate Swift/Go policy and native execution gates validate graph,
        // credential, comparison and lease contents; no such traffic is doubled
        // into a successful live native acceptance claim here.
        let executionCases:[(name:String,requested:String?,entry:String?,receipt:String?,selected:String,valid:Bool)] = [
            ("direct",nil,nil,nil,"",true),
            ("ordinary-paired-local","local","external",nil,"",true),
            ("router-paired-local","local","router-vpn",nil,"",true),
            ("paired-server","server","router-vpn","server","server",true),
            ("paired-auto-local","auto","router-vpn","auto","local",true),
            ("paired-auto-server","auto","router-vpn","auto","server",true),
            ("restored-auto-server","auto","router-vpn","server","server",true),
            ("missing-paired-auto","auto","router-vpn",nil,"",false),
            ("missing-paired-server","server","router-vpn",nil,"",false),
            ("wrong-selected","server","router-vpn","server","local",false),
            ("unfinished-selection","auto","router-vpn","auto","auto",false),
            ("wrong-captured-profile",nil,nil,nil,"",false),
            ("wrong-captured-exit",nil,nil,nil,"",false),
            ("unrequested-receipt",nil,nil,nil,"",false),
            ("wrong-type-requested",nil,nil,nil,"",false),
        ]
        var nativeFingerprints=Set<String>()
        for (index,fixture) in executionCases.enumerated() {
            state.configure();externalState.configure(execution:fixture.selected);hopState.configure();MTUActivationFixture.shared.configure()
            var capture=try JSONSerialization.jsonObject(with:Data(externalCapture.utf8)) as! [String:Any]
            var profile=capture["profile"] as! [String:Any]
            if let requested=fixture.requested {profile["multihop_execution"]=requested}
            if let kind=fixture.entry {
                profile["multihop_enabled"]=true;profile["multihop_entry_id"]="captured-entry";profile["multihop_exit_id"]="saved-exit"
                profile["multihop_entry_mode"]=kind=="external" ? "socks5":"wg";profile["multihop_exit_mode"]="shadowsocks"
                capture["entry"]=["id":"captured-entry","node_kind":kind];capture["entry_tag"]="external-entry"
            }
            if fixture.name=="wrong-captured-profile" {profile["id"]="other-exit"}
            if fixture.name=="wrong-captured-exit" {capture["exit_id"]="other-exit"}
            if fixture.name=="wrong-type-requested" {profile["multihop_execution"]=42}
            capture["profile"]=profile
            var metadata:[String:Any]=[:]
            if let selected=fixture.receipt {capture["execution"]=["selection":selected];metadata["execution"]=selected}
            if fixture.name=="unrequested-receipt" {capture["execution"]=["selection":"server"]}
            let captured=String(decoding:try JSONSerialization.data(withJSONObject:capture,options:[.sortedKeys]),as:UTF8.self)
            let receipt=String(decoding:try JSONSerialization.data(withJSONObject:metadata,options:[.sortedKeys]),as:UTF8.self)
            // Whitespace remains part of exact native configuration identity.
            let config=externalConfig+String(repeating:" ",count:index+1)
            let policy=RouterVPNExternalPolicy(sourceConfig:"captured source "+fixture.name,capture:captured,config:config,metadata:receipt)
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState()
            try owner.start(files:["sing-box.json":Data(config.utf8)],strict:true,externalPolicy:policy)
            owner.proveExternal(completion:done.finish)
            check("execution fixture retains completed proof",done.wait() && done.values()==(1,0))
            try owner.enableExternalHopMeasurement(exitID:"saved-exit")
            let request=String(repeating:"f",count:32)
            let information=owner.hopMeasurementRequest(operation:"hop-measure-info",request:request,session:"")
            check("external execution Info matches captured policy: "+fixture.name,(information != nil)==fixture.valid)
            if let information {
                let mtu=MTUActivationFixture.shared.currentPlatform()!.mtu
                let binding=try IOSHopMeasurementBinding.decode(information,request:request,mtuSession:mtu.independentSession)
                let expected=fixture.receipt==nil ? "local":fixture.selected
                let configFingerprint=SHA256.hash(data:Data(state.currentServer()!.capturedConfiguration().utf8)).map{String(format:"%02x",$0)}.joined()
                check("execution Info preserves original request and actual winner",binding.node_id=="saved-exit" && binding.execution?.valid==true && binding.execution?.requested==(fixture.requested ?? "local") && binding.execution?.selected==expected)
                check("execution Info fingerprints exact running native config",binding.execution?.config_sha256==configFingerprint && nativeFingerprints.insert(configFingerprint).inserted)
                check("execution Info cannot use a foreign provider epoch",owner.hopMeasurementRequest(operation:"hop-measure-info",request:request,session:UUID().uuidString)==nil)
            }
            owner.stop()
            check("retired execution cannot export an Info receipt",owner.hopMeasurementRequest(operation:"hop-measure-info",request:request,session:"")==nil)
        }
        for tor in [false,true] {for event in ["cancel-proof","network","pause","stop","during-mtu-stop","during-mtu-network","foreign-exit"] {
            state.configure();externalState.configure();torState.configure();hopState.configure();MTUActivationFixture.shared.configure()
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState()
            if tor {try owner.start(files:torFiles,strict:true);owner.proveTor(sessionID:"tor-session",profile:torProfile,completion:done.finish)}
            else {try owner.start(files:externalFiles,strict:true,externalPolicy:externalPolicy);owner.proveExternal(completion:done.finish)}
            check("Info staleness fixture owns a proved path",done.wait() && done.values()==(1,0))
            let exitID=tor ? "captured-tor":"saved-exit"
            try owner.enableExternalHopMeasurement(exitID:event=="foreign-exit" ? "foreign-exit":exitID)
            let request=String(repeating:"9",count:32)
            if event != "foreign-exit" {check("current Info exists before invalidation",owner.hopMeasurementRequest(operation:"hop-measure-info",request:request,session:"") != nil)}
            switch event {
            case "cancel-proof": if tor {torState.current()!.cancel()}else{externalState.current()!.cancel()}
            case "network": owner.invalidateMultihop()
            case "pause": owner.pause()
            case "stop": owner.stop()
            case "during-mtu-stop": MTUActivationFixture.shared.currentPlatform()!.mtu.statusCallback={owner.stop()}
            case "during-mtu-network": MTUActivationFixture.shared.currentPlatform()!.mtu.statusCallback={owner.invalidateMultihop()}
            default: break
            }
            check("Info rejects stale proof, session or foreign exit: "+event,owner.hopMeasurementRequest(operation:"hop-measure-info",request:request,session:"")==nil)
            owner.stop()
        }}
        for tor in [false,true] {for action in ["stable","cancel-proof","late-factory","retired-reply","latency","latency-retired","response","response-retired"] {
            state.configure();externalState.configure();torState.configure();hopState.configure()
            let exitID=tor ? "captured-tor":"saved-exit"
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            if tor {try owner.start(files:torFiles,strict:true)}else{try owner.start(files:externalFiles,strict:true,externalPolicy:externalPolicy)}
            let done=CompletionState()
            if tor{owner.proveTor(sessionID:"tor-session",profile:torProfile,completion:done.finish)}else{owner.proveExternal(completion:done.finish)}
            check("measurement retains completed native proof",done.wait() && done.values()==(1,0))
            if action=="cancel-proof" {if tor{torState.current()!.cancel()}else{externalState.current()!.cancel()}}
            if action=="late-factory" {hopState.configure {owner.stop()}}
            var failed=false
            do{try owner.enableExternalHopMeasurement(exitID:exitID)}catch{failed=true}
            check("only the proved current factory is adopted",failed == ["cancel-proof","late-factory"].contains(action))
            let probe=hopState.current()
            if action=="cancel-proof" {check("failed native proof cannot call factory",probe==nil)}
            else {
                let expected=tor ? ["tor",exitID]:["external"]+externalState.captured()
                check("factory receives exact retained proof selection",hopState.captured()==expected)
            }
            if action=="late-factory" {check("late native measurement is closed",probe?.closeCount()==1)}
            if !failed {
                let id=String(repeating:tor ? "b":"a",count:32),other=String(repeating:"c",count:32)
                let mtuSession=MTUActivationFixture.shared.currentPlatform()!.mtu.independentSession
                check("MTU and provider ownership epochs are independent",mtuSession != owner.settingsEpoch)
                check("MTU UUID cannot be substituted for provider epoch",owner.hopMeasurementRequest(operation:"hop-measure-start",request:id,session:mtuSession)==nil)
                let hopInfo=owner.hopMeasurementRequest(operation:"hop-measure-info",request:id,session:"")!
                let binding=try IOSHopMeasurementBinding.decode(hopInfo,request:id,mtuSession:mtuSession)
                check("Info binds provider epoch and exact MTU owner separately",binding.session_id==owner.settingsEpoch && binding.mtu_session_id==mtuSession)
                check("Info exposes only the captured external exit",binding.node_id==exitID)
                let nativeConfig=state.currentServer()!.capturedConfiguration()
                let fingerprint=SHA256.hash(data:Data(nativeConfig.utf8)).map{String(format:"%02x",$0)}.joined()
                check("Info binds exact running config and proved Local execution",binding.execution?.valid==true && binding.execution?.requested=="local" && binding.execution?.selected=="local" && binding.execution?.config_sha256==fingerprint)
                var badMTU=false;do{_ = try IOSHopMeasurementBinding.decode(hopInfo,request:id,mtuSession:UUID().uuidString)}catch{badMTU=true}
                check("foreign MTU echo cannot enable a hop measurement",badMTU)
                let startOperation=action.hasPrefix("response") ? "hop-measure-response-start":action.hasPrefix("latency") ? "hop-measure-latency-start":"hop-measure-start"
                check("foreign MTU UUID cannot start routed50",owner.hopMeasurementRequest(operation:"hop-measure-latency-start",request:id,session:mtuSession)==nil)
                check("foreign MTU UUID cannot start live response",owner.hopMeasurementRequest(operation:"hop-measure-response-start",request:id,session:mtuSession)==nil)
                check("bounded request starts on adopted owner",owner.hopMeasurementRequest(operation:startOperation,request:id,session:binding.session_id) != nil)
                check("routed50 gets the native captured exit only",probe!.latencyExitCalls()==(action.hasPrefix("latency") ? [exitID]:[]))
                check("live response gets the native captured exit only",probe!.responseExitCalls()==(action.hasPrefix("response") ? [exitID]:[]))
                let beforeCancel=try JSONSerialization.jsonObject(with:Data(probe!.statusJSON().utf8)) as! NSDictionary
                let beforeCancelCalls=probe!.cancellationCalls()
                check("early cancel receives bounded discard receipt",owner.hopMeasurementRequest(operation:"hop-measure-cancel",request:other,session:owner.settingsEpoch) != nil)
                let afterCancel=try JSONSerialization.jsonObject(with:Data(probe!.statusJSON().utf8)) as! NSDictionary
                check("foreign request cannot cancel current work",afterCancel.isEqual(beforeCancel) && probe!.cancellationCalls()==beforeCancelCalls)
                check("late start after early cancel is rejected",owner.hopMeasurementRequest(operation:"hop-measure-start",request:other,session:owner.settingsEpoch)==nil)
                check("late routed50 start after early cancel is rejected",owner.hopMeasurementRequest(operation:"hop-measure-latency-start",request:other,session:owner.settingsEpoch)==nil)
                check("late live response after early cancel is rejected",owner.hopMeasurementRequest(operation:"hop-measure-response-start",request:other,session:owner.settingsEpoch)==nil)
                check("retired session cannot start on current native owner",owner.hopMeasurementRequest(operation:"hop-measure-start",request:other,session:UUID().uuidString)==nil)
                if action=="retired-reply" || action=="latency-retired" || action=="response-retired" {
                    owner.stop()
                    let response=RouterVPNLibboxEngine.retiredHopMeasurementRequest(operation:"hop-measure-status",request:id,session:owner.settingsEpoch)!
                    let value=try JSONSerialization.jsonObject(with:response) as! [String:Any]
                    check("retired request can prove its actual drain",value["request_id"] as? String==id && value["drained"] as? Bool==true)
                    check("retired receipt cannot start a new measurement",RouterVPNLibboxEngine.retiredHopMeasurementRequest(operation:"hop-measure-start",request:id,session:owner.settingsEpoch)==nil)
                    check("retired receipt cannot start routed50",RouterVPNLibboxEngine.retiredHopMeasurementRequest(operation:"hop-measure-latency-start",request:id,session:owner.settingsEpoch)==nil)
                    check("retired receipt cannot start live response",RouterVPNLibboxEngine.retiredHopMeasurementRequest(operation:"hop-measure-response-start",request:id,session:owner.settingsEpoch)==nil)
                    check("retired receipt survives a late cancelled retry",RouterVPNLibboxEngine.retiredHopMeasurementRequest(operation:"hop-measure-cancel",request:id,session:owner.settingsEpoch) != nil)
                }
            }
            owner.stop()
        }}
        let dnsState=LibboxDNSTestState.shared
        for tor in [false,true] {for action in ["stable","cancel-proof","late-factory","before-proof"] {
            state.configure();externalState.configure();torState.configure();dnsState.configure();IOSDNSRetirementReceipts.shared.reset()
            let exitID=tor ? "captured-tor":"saved-exit"
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState()
            if tor {try owner.start(files:torFiles,strict:true)}else{try owner.start(files:externalFiles,strict:true,externalPolicy:externalPolicy)}
            if action != "before-proof" {
                if tor{owner.proveTor(sessionID:UUID().uuidString,profile:torProfile,completion:done.finish)}else{owner.proveExternal(completion:done.finish)}
                check("DNS requires completed native route/DNS proof",done.wait() && done.values()==(1,0))
            }
            if action=="cancel-proof"{if tor{torState.current()!.cancel()}else{externalState.current()!.cancel()}}
            if action=="late-factory"{dnsState.configure{owner.stop()}}
            var failed=false;do{try owner.enableExternalDNSMeasurement(exitID:exitID)}catch{failed=true}
            check("only a current successful native proof creates DNS ownership",failed == (action != "stable"))
            if ["before-proof","cancel-proof"].contains(action){check("unproved DNS never calls its factory",dnsState.current()==nil)}
            else {
                check("DNS factory receives the retained exact source/proof",dnsState.captured()==(tor ? ["tor",exitID]:["external"]+externalState.captured()))
                if action=="late-factory"{check("late DNS factory handle drains before it is discarded",dnsState.current()!.counts().2==1)}
                else {
                    let id=String(repeating:tor ? "e":"d",count:32)
                    let info=try JSONSerialization.jsonObject(with:owner.dnsMeasurementRequest(operation:"dns-measure-info",request:id,session:"",nativeSession:"",transport:"")!) as! [String:Any]
                    let nativeSession=info["native_session_id"] as! String
                    check("DNS Info distinguishes proof and provider ownership",info["session_id"] as? String==owner.settingsEpoch && nativeSession != owner.settingsEpoch)
                    let mtu=MTUActivationFixture.shared.currentPlatform()!.mtu;mtu.hasOwner=true;mtu.measurementReady=false
                    check("adaptive MTU must actually drain before DNS Start",owner.dnsMeasurementRequest(operation:"dns-measure-start",request:id,session:owner.settingsEpoch,nativeSession:nativeSession,transport:"tls")==nil && dnsState.current()!.counts().0==0)
                    mtu.measurementReady=true
                    check("ready captured owner can start native DNS",owner.dnsMeasurementRequest(operation:"dns-measure-start",request:id,session:owner.settingsEpoch,nativeSession:nativeSession,transport:"tls") != nil && dnsState.current()!.counts().0==1)
                    owner.stop()
                    let cleaned=RouterVPNDNSMeasurementRegistry.shared.reply(operation:"dns-measure-drain",request:id,session:owner.settingsEpoch,nativeSession:nativeSession,transport:"")!
                    let value=try JSONSerialization.jsonObject(with:cleaned) as! [String:Any]
                    check("retired engine remains addressable only for exact DNS cleanup",value["drained"] as? Bool==true && (value["results"] as? [Any])?.isEmpty==true && dnsState.current()!.counts().1==0)
                }
            }
            owner.stop()
        }}
        for event in ["stable","cancel-proof","late-factory","before-proof","tor"] {
            state.configure();externalState.configure();torState.configure();MTUActivationFixture.shared.configure()
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState()
            if event=="tor" {try owner.start(files:torFiles,strict:true);owner.proveTor(sessionID:"tor-session",profile:torProfile,completion:done.finish)}
            else {try owner.start(files:externalFiles,strict:true,externalPolicy:externalPolicy);if event != "before-proof" {owner.proveExternal(completion:done.finish)}}
            if event != "before-proof" {check("MTU factory follows final native proof",done.wait() && done.values()==(1,0))}
            if event=="cancel-proof" {externalState.current()!.cancel()}
            if event=="late-factory" {MTUActivationFixture.shared.configure {owner.stop()}}
            var failed=false;do{try owner.activateExternalMTU()}catch{failed=true}
            check("external MTU cannot adopt an unproved or retired runtime",failed == (event != "stable"))
            if ["stable","late-factory"].contains(event) {
                check("MTU receives exact source capture and retained proof",MTUActivationFixture.shared.captured()==[externalPolicy.sourceConfig,externalPolicy.capture] && MTUActivationFixture.shared.owns(externalState.current()))
            } else {check("unproved or Tor path never calls ordinary external MTU",MTUActivationFixture.shared.captured().isEmpty)}
            owner.stop()
        }
        for event in ["stable","cancel-proof","late-factory","before-proof","external"] {
            state.configure();externalState.configure();torState.configure();MTUActivationFixture.shared.configure()
            let owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState()
            if event=="external" {try owner.start(files:externalFiles,strict:true,externalPolicy:externalPolicy);owner.proveExternal(completion:done.finish)}
            else {try owner.start(files:torFiles,strict:true);if event != "before-proof"{owner.proveTor(sessionID:"tor-session",profile:torProfile,completion:done.finish)}}
            if event != "before-proof"{check("Tor MTU activation waits for final DNS and circuit proof",done.wait() && done.values()==(1,0))}
            if event=="cancel-proof"{torState.current()!.cancel()}
            if event=="late-factory"{MTUActivationFixture.shared.configure{owner.stop()}}
            var failed=false;do{try owner.activateTorMTU()}catch{failed=true}
            check("Tor MTU cannot adopt an ordinary, unproved or retired runtime",failed == (event != "stable"))
            if ["stable","late-factory"].contains(event) {
                check("Tor MTU receives exact graph profile and retained proof",MTUActivationFixture.shared.captured()==[torConfig,torProfile] && MTUActivationFixture.shared.ownsTor(torState.current()))
            }else{check("unproved or ordinary path never calls Tor MTU",MTUActivationFixture.shared.captured().isEmpty)}
            owner.stop()
        }
        for external in [false,true] {
            state.configure();externalState.configure();MTUActivationFixture.shared.configure(failures:1)
            let provider=PacketTunnelProvider(),done=CompletionState()
            let owner=RouterVPNLibboxEngine(tunnel:provider)
            if external {
                try owner.start(files:externalFiles,strict:true,externalPolicy:externalPolicy)
                owner.proveExternal(completion:done.finish)
                check("retirement fixture owns a proved external path",done.wait() && done.values()==(1,0))
                try owner.activateExternalMTU()
            } else {
                try owner.start(files:files,strict:true)
                owner.activateMTU(profile:["mtu_policy":"fixed","mtu":1420])
            }
            let platform=MTUActivationFixture.shared.currentPlatform()!,server=state.currentServer()!,directory=state.directory()
            check("MTU retirement owns its private runtime files",FileManager.default.fileExists(atPath:directory))
            if !external {
                try platform.onStopService?()
                check("native service stop cannot discard an owned MTU drain",provider.count()==1 && platform.mtu.closeSnapshots.isEmpty && platform.resets==0)
            }
            let before=state.counts();try owner.stopCheckedForStrategy()
            check("MTU retries the exact owner only after its Box closes",platform.mtu.closeSnapshots == (external ? [["start"],["start","close"]] : [[],["close"]]))
            check("successful MTU retry releases native resources",state.counts().0==before.0 && state.counts().1==before.1+1 && platform.resets==1 && !FileManager.default.fileExists(atPath:directory))
            try owner.stopCheckedForStrategy()
            check("retired MTU cannot close a replacement native owner",platform.mtu.closeSnapshots.count==2 && server.strategyCalls()==(external ? ["start","close"]:["close"]))
            MTUActivationFixture.shared.configure()
            let replacement=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            try replacement.start(files:files,strict:false);replacement.stop()
        }
        check("no mock native server survives successful shutdown", state.counts().0 == state.counts().1)
        if CommandLine.arguments.contains("--tor-server-physical-close") {
            torState.configure()
            var owner:RouterVPNLibboxEngine?=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            try owner!.start(files:torServerFiles,strict:true)
            let done=CompletionState();owner!.proveTor(sessionID:UUID().uuidString,profile:torServerProfile,predecessorProfile:torEntryProfile,completion:done.finish)
            check("physical reset fixture owns a proved Server lease",done.wait() && done.values()==(1,0))
            let request=torState.current()!,server=state.currentServer()!,before=state.counts(),directory=state.directory()
            weak var platform=MTUActivationFixture.shared.currentPlatform()
            request.retireEntry()
            var failed=false;do{try owner!.stopCheckedForStrategy()}catch{failed=true}
            check("physical entry loss cannot borrow another route for DELETE",failed && request.closeCount()==1 && !server.strategyCalls().contains("close") && state.counts()==before)
            owner=nil
            let replacement=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            var refused=false;do{try replacement.start(files:files,strict:false)}catch{refused=true}
            check("lost physical entry retains exact cleanup and blocks replacement",refused && request.closeCount()==2 && platform != nil && platform?.resets==0 && state.counts()==before && FileManager.default.fileExists(atPath:directory))
        } else {
            torState.configure()
            var owner:RouterVPNLibboxEngine?=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            let external=CommandLine.arguments.contains("--external-close")
            let mtu=CommandLine.arguments.contains("--mtu-close")
            if mtu {
                MTUActivationFixture.shared.configure(failures:2)
                try owner!.start(files:files,strict:true);owner!.activateMTU(profile:["mtu_policy":"fixed","mtu":1420])
            } else if external {try owner!.start(files:externalFiles,strict:true,externalPolicy:externalPolicy)}
            else {try owner!.start(files:torFiles,strict:true)}
            let label=mtu ? "MTU":(external ? "external":"Tor"),directory=state.directory()
            weak var platform=MTUActivationFixture.shared.currentPlatform()
            let retained=state.currentServer()!,before=state.counts()
            retained.configureStrategy(close:!mtu)
            var failed=false
            do {try owner!.stopCheckedForStrategy()}catch{failed=true}
            check("unconfirmed \(label) close retains native owner",failed && state.counts()==before && retained.strategyCalls()==(mtu ? ["close"]:["start","close"]))
            if mtu {check("failed MTU retry belongs to the closed Box",platform?.mtu.closeSnapshots == [[],["close"]])}
            owner=nil
            check("failed \(label) drain retains platform and runtime files",platform != nil && platform?.resets==0 && FileManager.default.fileExists(atPath:directory))
            var blocked=false
            let replacement=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
            do{try replacement.start(files:files,strict:false)}catch{blocked=true}
            check("quarantined \(label) cannot overlap a replacement core",blocked && state.counts()==before)
        }
        print("Swift 6 shipping Libbox delivery: PASS (\(checks) checks; native handles doubled, no network opened)")
    }
}
'''

# Candidate object lifecycle is exercised in test_ios_node_candidate_session.py.
# These unavailable SDK handles preserve compilation of the entire existing
# engine without making legacy delivery scenarios claim candidate readiness.
CANDIDATE_NATIVE = r'''
public protocol LibboxRouterNodeChainCandidateCatalogProtocol: AnyObject {func currentInventorySHA256()->String}
public final class LibboxRouterNodeChainCandidateMeasurement {
 public func metadata()->String{""}
 public func start(_ request:String,candidateID:String)throws{throw NSError(domain:"UnavailableCandidateBoundary",code:1)}
 public func statusJSON()->String{""}
 public func cancel(_ request:String){}
 public func networkChanged(){}
 public func close()throws{}
}
public func LibboxRouterNodeChainNewCandidateMeasurement(_ plan:LibboxRouterNodeChain,_ server:LibboxCommandServer,_ prefix:Int32,_ inventory:String,_ catalog:LibboxRouterNodeChainCandidateCatalogProtocol,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainCandidateMeasurement?{error?.pointee=NSError(domain:"UnavailableCandidateBoundary",code:1);return nil}
public func LibboxRouterNodeChainCloseCandidateMeasurement(_ plan:LibboxRouterNodeChain,_ prefix:Int32,_ inventory:String,_ error:UnsafeMutablePointer<NSError?>?)->Bool{false}
'''
CANDIDATE_SOURCE = r'''
struct IOSNodeChainCapture {
 struct Member {let id:String;let mode:String;let profile:[String:Any]}
 let members:[Member]
 init(plan:LibboxRouterNodeChain)throws{throw NSError(domain:"UnavailableOriginalSourceBoundary",code:1)}
}
'''

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--chain-only',action='store_true')
    parser.add_argument('--execution-only',action='store_true')
    parser.add_argument('--prefix-only',action='store_true')
    parser.add_argument('--shipping-only',action='store_true')
    requested=parser.parse_args()
    swift = shutil.which('swiftc')
    if swift is None:
        raise SystemExit('swiftc required to compile the shipping concurrency boundary')
    subprocess.run([sys.executable,str(ROOT/'deploy/test_ios_proof_cancel_delivery.py')],check=True,timeout=180)
    subprocess.run([sys.executable,str(ROOT/'deploy/test_ios_node_chain_measurement_delivery.py')],check=True,timeout=90)
    with tempfile.TemporaryDirectory(prefix='routervpn-libbox-delivery-') as tmp:
        tmp = Path(tmp)
        stub, harness = tmp/'Libbox.swift', tmp/'Harness.swift'
        stub.write_text(LIBBOX + DNS.NATIVE + CANDIDATE_NATIVE + EXECUTION.NATIVE + PREFIX.NATIVE); harness.write_text(DNS.STORAGE + HARNESS.replace("    func activateImported(server:", EXECUTION.MTU_METHODS + "    func activateImported(server:", 1) .replace('        let chainText=', PREFIX.TESTS + EXECUTION.TESTS + '        let chainText=', 1) + CANDIDATE_SOURCE + EXECUTION.SOURCE + EXECUTION.IPC_TYPES + PREFIX.SOURCE)
        hop_types = (ROOT/'ios/RouterVPN/App/IOSHopMeasurements.swift').read_text().split('// HOP_RESULT_TYPES_BEGIN',1)[1].split('// HOP_RESULT_TYPES_END',1)[0]
        binding = tmp/'HopBinding.swift'; binding.write_text('import Foundation\n' + hop_types)
        lib = tmp/('libLibbox.dylib' if platform.system() == 'Darwin' else 'libLibbox.so')
        environment = dict(os.environ)
        if platform.system() != 'Darwin':
            environment['XDG_DATA_HOME'] = str(tmp/'application-support')
        subprocess.run([swift,'-swift-version','6','-emit-module','-emit-library','-module-name','Libbox',str(stub),
                        '-emit-module-path',str(tmp/'Libbox.swiftmodule'),'-o',str(lib)],check=True,timeout=60)
        args=[swift,'-swift-version','6','-I',str(tmp),'-L',str(tmp),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(tmp),str(ROOT/'ios/RouterVPN/App/IOSMultihopExecution.swift'),str(binding),str(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNDNSMeasurementSession.swift')]
        if platform.system() != 'Darwin':
            crypto = tmp/'CryptoKit.swift'; crypto.write_text(CRYPTO.LINUX_CRYPTO)
            subprocess.run([swift,'-swift-version','6','-emit-module','-emit-library','-module-name','CryptoKit',str(crypto),'-lcrypto','-o',str(tmp/'libCryptoKit.so')],cwd=tmp,check=True,timeout=60)
            args += ['-lCryptoKit']
        args += [str(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNNodeChainExecutionHost.swift'), str(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNNodeChainExecutionRegistry.swift'), str(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNTorPaddingReceipt.swift'), str(ROOT/'ios/RouterVPN/App/IOSCandidateCatalogPublication.swift'), str(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNNodeCandidateSession.swift'), str(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNNodeCandidatePrefixHost.swift')]
        subprocess.run(args+[str(ROOT/"ios/RouterVPN/App/IOSMultihopStartLayer.swift"),str(ENGINE),str(harness),'-o',str(tmp/'test')],check=True,timeout=90)
        subprocess.run([str(tmp/'test'),'--prefix-only'],env=environment,check=True,timeout=25)
        text=ENGINE.read_text()
        for name,before,after,witness in (
            ('prefix-pending-owner','            pendingNodeCandidatePrefixCleanup = prefixCleanup','            // omitted original prefix pending owner','prefix failed close retains original pending owner'),
            ('prefix-retirement','        try RouterVPNNodeCandidatePrefixHost.requireAvailable()','        // omitted original prefix retirement gate','prefix pending native close blocks replacement'),
        ):
            if name=='prefix-retirement':
                begin=text.index('    func start(files: [String: Data], strict: Bool, multihopMetadata:')
                prefix,scope=text[:begin],text[begin:];assert scope.count(before)==1,name
                changed=prefix+scope.replace(before,after,1)
            else:
                assert text.count(before)==1,name;changed=text.replace(before,after,1)
            broken=tmp/(name+'.swift');broken.write_text(changed);binary=tmp/name
            subprocess.run(args+[str(ROOT/'ios/RouterVPN/App/IOSMultihopStartLayer.swift'),str(broken),str(harness),'-o',str(binary)],check=True,timeout=90)
            failed=subprocess.run([str(binary),'--prefix-only'],env=environment,capture_output=True,text=True,timeout=25)
            assert failed.returncode!=0 and 'FAIL: '+witness in failed.stdout+failed.stderr,(name,(failed.stdout+failed.stderr)[-1500:])
            print('Rejected prefix whole-engine defect mutation:',name)
        if requested.prefix_only:return
        if requested.execution_only or not requested.chain_only:
            subprocess.run([str(tmp/'test'),'--execution-only'],env=environment,check=True,timeout=25)
            text=ENGINE.read_text()
            for name,before,after,witness in (
                ('execution-retirement','            executionCleanup.retainForRetirement()','            // missing original retirement gate','retained execution blocks replacement native admission'),
                ('execution-pending-owner','            pendingNodeChainExecutionCleanup = executionCleanup','            // missing original pending owner','execution failed cleanup retains original engine slot'),
                ('execution-native-bind','        if let created { try host.bindNative(created) }','        if let created { _ = created }','execution startup retains bound original server'),
                ('execution-hop-adoption','            self.hopMeasurement = probe\n            // Generic ordered hop metadata','            // omitted original probe\n            // Generic ordered hop metadata','execution retains ordinary owned hop metadata'),
            ):
                assert text.count(before)==1,name
                broken=tmp/(name+'.swift');broken.write_text(text.replace(before,after,1));binary=tmp/name
                subprocess.run(args+[str(ROOT/'ios/RouterVPN/App/IOSMultihopStartLayer.swift'),str(broken),str(harness),'-o',str(binary)],check=True,timeout=90)
                failed=subprocess.run([str(binary),'--execution-only'],env=environment,capture_output=True,text=True,timeout=25)
                assert failed.returncode != 0 and 'FAIL: '+witness in failed.stdout+failed.stderr,(name,(failed.stdout+failed.stderr)[-1500:])
                print('Rejected ordered execution defect mutation:',name)
            if requested.execution_only:return
        if requested.chain_only or not requested.shipping_only:
            subprocess.run([str(tmp/'test'),'--chain-only'],env=environment,check=True,timeout=25)
            text=ENGINE.read_text()
            chain_start=text.index('        if let nodeChainPlan {')
            chain_end=text.index('        } else if let importedPlan {',chain_start)
            chain=text[chain_start:chain_end]
            injection=chain.replace('            safeFiles = files','            safeFiles = try validateAndInjectProof(files)',1)
            assert injection != chain
            mutations=[('chain-proof-injection',text[:chain_start]+injection+text[chain_end:],'ordered plan preserves one exact graph without proof injection')]
            for name,before,after,failure in (
                ('chain-join-required','            if let failure = nativeFailure ?? drainFailure { throw failure }','            _ = nativeFailure; _ = drainFailure','unjoined ordered proof retains original TUN and private source'),
                ('chain-mtu-observation','            guard !healthy, current(owner), owner.platform.mtu.proofObservationToken == mtuObservation else { return }','            guard !healthy, current(owner) else { return }','completed MTU transaction cannot publish old health failure'),
            ):
                assert text.count(before)==1,name
                mutations.append((name,text.replace(before,after,1),failure))
            for name,source,failure in mutations:
                broken=tmp/(name+'.swift');broken.write_text(source)
                binary=tmp/name
                subprocess.run(args+[str(ROOT/'ios/RouterVPN/App/IOSMultihopStartLayer.swift'),str(broken),str(harness),'-o',str(binary)],check=True,timeout=90)
                failed=subprocess.run([str(binary),'--chain-only'],env=environment,capture_output=True,text=True,timeout=25)
                assert failed.returncode != 0 and 'FAIL: '+failure in failed.stdout+failed.stderr,name+': missing causal assertion '+(failed.stdout+failed.stderr)[-1500:]
                print('Rejected ordered-owner defect mutation: '+name)
            if requested.chain_only:return
        subprocess.run([str(tmp/'test')],env=environment,check=True,timeout=25)
        subprocess.run([str(tmp/'test'),'--external-close'],env=environment,check=True,timeout=25)
        subprocess.run([str(tmp/'test'),'--mtu-close'],env=environment,check=True,timeout=25)
        subprocess.run([str(tmp/'test'),'--tor-server-physical-close'],env=environment,check=True,timeout=25)
        if requested.shipping_only:return
        broken=tmp/'Broken.swift'
        text=ENGINE.read_text()
        foreign_cancel='            guard let probe = owners[id] else {'
        assert text.count(foreign_cancel)==1
        broken.write_text(text.replace(foreign_cancel,
            '            if operation == "hop-measure-cancel", owners[id] == nil { owners.values.first?.cancel(request) }\n'+foreign_cancel))
        subprocess.run(args+[str(ROOT/"ios/RouterVPN/App/IOSMultihopStartLayer.swift"),str(broken),str(harness),'-o',str(tmp/'foreign-cancel')],check=True,timeout=90)
        bad=subprocess.run([str(tmp/'foreign-cancel')],env=environment,capture_output=True,text=True,timeout=25)
        assert bad.returncode != 0 and 'FAIL: foreign request cannot cancel current work' in bad.stdout+bad.stderr, 'Foreign cancellation negative control did not fail at the ownership assertion'
        print('Negative control: a foreign cancellation reaching the native owner is rejected')
        for label, before, after, expected in (
            ('padding-receipt-required', '                    paddingReceipt = try padding.validate(text, previous: paddingReceipt, now: Date())', '                    _ = text', 'enabled padding requires its retained native receipt'),
            ('padding-health-required', '            guard let owner, current(owner), !healthy(), current(owner) else { return }', '            guard let owner, current(owner), !request.healthy(), current(owner) else { return }', 'padding timer validates receipts independently of native healthy flag'),
            ('ordinary-tor-proof-binding', '            if entry["node_kind"] as? String == "router-vpn" { return true }', '            if entry["node_kind"] as? String == "router-vpn" { return true }; return false', 'ordinary Tor binds only the current typed Local proof'),
            ('server-delete-required', '            try proof.close()', '            // missing exact lease DELETE', 'Server DELETE precedes native Box closure'),
            ('server-delete-acknowledged', '            try proof.close()', '            try? proof.close()', 'pending DELETE keeps exact native Box and files'),
            ('server-measurement-drain', '            if let drainFailure { throw drainFailure }', '            _ = drainFailure', 'measurement drain precedes DELETE and keeps the exact entry'),
            ('server-retirement-blocks-replacement', '        try Self.torServerRetirement.requireAvailable()', '        // missing retired Server owner', 'unacknowledged old lease blocks a replacement owner'),
            ('server-captured-execution', '              Self.torExecutionSelection(capturedProfile) == execution,\n              IOSMultihopExecution.torLeafMatches(source: sourceProfile ?? profile, leaf: profile, execution: execution),', '              true,', 'Server source cannot change its selected execution before proof'),
            ('tor-compare-source', '              IOSMultihopExecution.torLeafMatches(source: sourceProfile ?? profile, leaf: profile, execution: execution),', '              true,', 'Compare source mutation is rejected before native proof'),
            ('measurement-execution-authority', '                guard requested == "local", capture["execution"] == nil else { return nil }', '                guard capture["execution"] == nil else { return nil }', 'external execution Info matches captured policy: missing-paired-auto'),
            ('measurement-config-identity', 'SHA256.hash(data: Data(config.utf8))', 'SHA256.hash(data: Data("uncaptured configuration".utf8))', 'Tor measurement Info retains original auto and proved leaf'),
        ):
            if label == 'server-retirement-blocks-replacement':
                # Both ordinary and ordered execution startup enforce this
                # gate. This existing witness exercises the ordinary entry.
                begin=text.index('    func start(files: [String: Data], strict: Bool, multihopMetadata:')
                prefix,scope=text[:begin],text[begin:]
                assert scope.count(before)==1,label
                replacement=prefix+scope.replace(before,after,1)
            else:
                assert text.count(before)==1,label
                replacement=text.replace(before,after,1)
            broken.write_text(replacement)
            executable=tmp/label
            subprocess.run(args+[str(ROOT/"ios/RouterVPN/App/IOSMultihopStartLayer.swift"),str(broken),str(harness),'-o',str(executable)],check=True,timeout=90)
            bad=subprocess.run([str(executable)],env=environment,capture_output=True,text=True,timeout=25)
            assert bad.returncode != 0 and 'FAIL: '+expected in bad.stdout+bad.stderr, label+': wrong negative boundary: '+(bad.stdout+bad.stderr)[-2000:]
            print('Negative control rejected: '+label)
        seam='DispatchQueue.global(qos: .userInitiated).async { delivery.run() }'
        start=text.index('    func completeMultihopExecution(')
        end=text.index('    func completeNodeChainExecution(',start)
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
