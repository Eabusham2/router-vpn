#!/usr/bin/env python3
"""Exercise the shipping checked-exit owner, URLSession and real AppKit callbacks."""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
MAC = ROOT / 'client/macos'

MAIN = r'''
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(AppKit)
import AppKit
#endif
let routerVPNProductBaseURL = URL(string: CommandLine.arguments[1])!
let fixture = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
var checks = 0
@MainActor func check(_ ok: @autoclosure () -> Bool, _ message: String) {
    checks += 1
    if !ok() { try! FileHandle.standardError.write(contentsOf: Data((message + "\n").utf8)); exit(1) }
}
@MainActor func spin(_ seconds: TimeInterval = 0.01) {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline { _ = RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.002)) }
}
@MainActor func wait(_ predicate: () -> Bool, _ message: String) {
    let deadline = Date().addingTimeInterval(6)
    while !predicate() && Date() < deadline { spin() }
    check(predicate(), message)
}
func token(_ character: Character) -> String { String(repeating: String(character), count: 32) }
func identity(_ character: Character = "a", _ pid: Int32 = 321) -> RouterVPNMacShutdownIdentity {
    RouterVPNMacShutdownIdentity(processID: pid, token: token(character))
}
func receipt(_ owner: RouterVPNMacShutdownIdentity, code: Int = 200) -> RouterVPNMacShutdownReply {
    var data = owner.body; data["closed"] = true
    return RouterVPNMacShutdownReply(code: code, data: try! JSONSerialization.data(withJSONObject: data, options: .sortedKeys))
}
final class FakeProcess: RouterVPNMacShutdownProcess {
    var processIdentifier: Int32 = 321; var isRunning = true
    var successful = true, retiredBeforeReady = false
    var joinFailure: String?
    var joinedSuccessfully: Bool { !isRunning && successful }
}
final class ControlledRequest: RouterVPNMacShutdownRequest {
    let completion: (Result<RouterVPNMacShutdownReply, Error>) -> Void
    let owner: RouterVPNMacShutdownIdentity
    var started = false, cancelled = false
    init(_ owner: RouterVPNMacShutdownIdentity, _ completion: @escaping (Result<RouterVPNMacShutdownReply, Error>) -> Void) { self.owner = owner; self.completion = completion }
    func start() { started = true }
    func cancel() { cancelled = true }
    @MainActor func reply(_ value: RouterVPNMacShutdownReply) { completion(.success(value)); spin() }
    @MainActor func fail() { completion(.failure(NSError(domain: NSURLErrorDomain, code: NSURLErrorTimedOut))); spin() }
}
@MainActor final class Factory {
    var requests: [ControlledRequest] = []
    func make(_ url: URL, _ owner: RouterVPNMacShutdownIdentity, _ timeout: TimeInterval,
              _ completion: @escaping (Result<RouterVPNMacShutdownReply, Error>) -> Void) -> RouterVPNMacShutdownRequest {
        check(url.path == "/api/controller/shutdown" && timeout >= 35, "Shutdown request endpoint/deadline drifted")
        let request = ControlledRequest(owner, completion); requests.append(request); return request
    }
}
@MainActor func controlledTests() {
    let owned = identity()
    check(owned.valid && owned.accepts(receipt(owned).data), "Valid exact receipt rejected")
    for invalid in [RouterVPNMacShutdownIdentity(processID: 0, token: owned.token), RouterVPNMacShutdownIdentity(processID: -1, token: owned.token), RouterVPNMacShutdownIdentity(processID: 1, token: ""), RouterVPNMacShutdownIdentity(processID: 1, token: token("A")), RouterVPNMacShutdownIdentity(processID: 1, token: token("g"))] {
        check(!invalid.valid && !invalid.accepts(receipt(owned).data), "Invalid launch identity accepted")
    }
    let text = String(data: receipt(owned).data, encoding: .utf8)!
    let invalid = [text.replacingOccurrences(of: "321", with: "322"), text.replacingOccurrences(of: owned.token, with: token("b")), text.replacingOccurrences(of: "true", with: "1"), text.replacingOccurrences(of: "\"schema\":1", with: "\"schema\":true"), text.replacingOccurrences(of: "\"process_id\":321", with: "\"process_id\":true"), text.replacingOccurrences(of: "\"closed\":true", with: "\"closed\":false"), text.replacingOccurrences(of: "\"schema\":1", with: "\"schema\":1,\"schema\":1"), text.replacingOccurrences(of: "\"schema\":1", with: "\"schema\":1,\"sch\\u0065ma\":1"), text.replacingOccurrences(of: "\"schema\":1", with: "\"schema\":1,\"extra\":1"), text + "{}", "[]", "null", String(repeating: " ", count: 4097) + text]
    for raw in invalid { check(!owned.accepts(Data(raw.utf8)), "Malformed/foreign shutdown receipt accepted") }
    func make(_ factory: Factory, _ process: FakeProcess, exitTimeout: TimeInterval = 1, current: @escaping () -> Bool = { true }) -> RouterVPNMacShutdownController {
        RouterVPNMacShutdownController(baseURL: routerVPNProductBaseURL, identity: owned, process: process, pollInterval: 0.002, exitTimeout: exitTimeout, isCurrent: current, factory: factory.make)
    }
    do {
        let f = Factory(), p = FakeProcess(); let flow = make(f, p)
        var replies: [Bool] = []; flow.onFinish = { replies.append($0) }
        flow.start(); check(replies.isEmpty && f.requests.isEmpty, "Termination replied before terminateLater returned")
        spin(); flow.start(); check(f.requests.count == 1 && flow.pending, "Duplicate Quit started another request")
        f.requests[0].reply(receipt(owned)); check(flow.acknowledged && flow.phase == .waitingForProcess && replies.isEmpty, "Receipt allowed quit before owned Process exit")
        p.isRunning = false; wait({ replies == [true] }, "Owned Process exit did not complete checked shutdown")
        f.requests[0].reply(receipt(owned)); check(replies == [true], "Duplicate HTTP callback repeated termination reply")
    }
    do {
        let f = Factory(), p = FakeProcess(); let flow = make(f, p)
        var replies: [Bool] = []; flow.onFinish = { replies.append($0) }
        flow.start(); spin(); let first = f.requests[0]; first.reply(receipt(owned, code: 503))
        check(replies == [false] && p.isRunning && !flow.acknowledged, "503 did not preserve owned Process")
        flow.start(); spin(); check(f.requests.count == 2 && f.requests[1].owner == first.owner, "Retry borrowed another launch identity")
        first.reply(receipt(owned)); check(!flow.acknowledged && flow.phase == .requesting, "Stale prior-attempt reply adopted")
        f.requests[1].reply(receipt(identity("b"))); check(replies == [false, false] && !flow.acknowledged && p.isRunning, "Foreign receipt closed app")
        flow.start(); spin(); f.requests[2].fail(); check(replies == [false, false, false] && p.isRunning, "Timeout terminated owner")
    }
    do {
        let f = Factory(), p = FakeProcess(); p.isRunning = false; let flow = make(f, p)
        var reply: Bool?; flow.onFinish = { reply = $0 }; flow.start(); spin()
        check(reply == false && f.requests.isEmpty, "Unacknowledged Process exit was treated as cleanup")
    }
    do {
        let f = Factory(), p = FakeProcess(); var current = true; let flow = make(f, p, current: { current })
        var replies: [Bool] = []; flow.onFinish = { replies.append($0) }; flow.start(); spin(); current = false
        f.requests[0].reply(receipt(owned)); check(replies == [false] && !flow.acknowledged && p.isRunning, "Replaced owner accepted old receipt")
    }
    do {
        let f = Factory(), p = FakeProcess(); var current = true; let flow = make(f, p, current: { current })
        var replies: [Bool] = []; flow.onFinish = { replies.append($0) }; flow.start(); spin(); f.requests[0].reply(receipt(owned)); current = false
        wait({ replies == [false] }, "Replaced waiting Process did not retire the old attempt")
        check(p.isRunning, "Replacement Process was signaled")
    }
    do {
        let f = Factory(), p = FakeProcess(); let flow = make(f, p, exitTimeout: 0.025)
        var replies: [Bool] = []; flow.onFinish = { replies.append($0) }; flow.start(); spin(); f.requests[0].reply(receipt(owned))
        wait({ replies == [false] }, "Unfinished Process exit had no visible retry boundary")
        check(flow.acknowledged && p.isRunning, "Exit wait lost checked receipt or killed owner")
        flow.start(); spin(); check(f.requests.count == 1, "Exit retry repeated acknowledged controller request")
        p.isRunning = false; wait({ replies == [false, true] }, "Exit retry did not complete exact owner")
    }
    do {
        let f = Factory(), p = FakeProcess(); let flow = make(f, p)
        var replies: [Bool] = []; flow.onFinish = { replies.append($0) }; flow.start(); spin(); flow.retire()
        check(f.requests[0].cancelled && replies == [false], "Retired request did not cancel its own HTTP task")
        p.isRunning = false; f.requests[0].reply(receipt(owned)); check(replies == [false], "Retired callback quit the replacement view")
    }
    do {
        let f = Factory(), p = FakeProcess(); p.retiredBeforeReady = true; let flow = make(f, p)
        var replies: [Bool] = []; flow.onFinish = { replies.append($0) }; flow.start(); spin()
        check(f.requests.isEmpty && replies.isEmpty && !flow.acknowledged && flow.phase == .waitingForProcess,
              "Canceled startup invented HTTP readiness or a cleanup receipt")
        p.isRunning = false; wait({ replies == [true] }, "Canceled startup did not require its actual successful join")
        check(!flow.acknowledged, "A supervisor join was relabeled as an HTTP cleanup receipt")
    }
    for canceledStartup in [false, true] {
        let f = Factory(), p = FakeProcess(); p.retiredBeforeReady = canceledStartup; let flow = make(f, p)
        var replies: [Bool] = []; flow.onFinish = { replies.append($0) }; flow.start(); spin()
        if !canceledStartup { f.requests[0].reply(receipt(owned)) }
        p.successful = false; p.isRunning = false
        wait({ replies == [false] }, "Failed process join was accepted as successful cleanup")
    }
    do {
        let f = Factory(), p = FakeProcess(); let flow = make(f, p)
        var replies: [Bool] = []; flow.onFinish = { replies.append($0) }; flow.start(); spin()
        f.requests[0].reply(receipt(owned)); p.joinFailure = "Supervisor lost actual process-join authority"
        wait({ replies == [false] }, "Lost supervisor authority was replaced by a fabricated join")
        check(p.isRunning, "An unknown process join became an exited process")
    }
    do {
        let f = Factory(), p = FakeProcess(); p.retiredBeforeReady = true; p.successful = false; p.isRunning = false
        let flow = make(f,p); var replies:[Bool]=[]; flow.onFinish={replies.append($0)}; flow.start(); spin()
        check(replies == [false] && f.requests.isEmpty, "An already failed startup join invented successful cleanup")
    }
}
@MainActor func authorizationProtocolTests() {
    func packet(_ kind: UInt32, _ rights: UInt32) -> Data {
        var bytes = [UInt8](repeating: 0, count: 80)
        func word(_ offset: Int, _ value: UInt32) {
            for index in 0..<4 { bytes[offset + index] = UInt8(truncatingIfNeeded: value >> (index * 8)) }
        }
        word(0, 80); word(4, 8); word(8, 68); word(12, 0x012cc16d)
        word(48, 1); word(72, kind); word(76, rights)
        return Data(bytes)
    }
    for right: UInt32 in [1<<1, 1<<3, 1<<7, 1<<9, 1<<11, 1<<20, 1<<22, 1<<24] {
        check(RouterVPNMacPathACL.accepts(packet(1, right)), "Read-only system ACL was rejected")
        check(!RouterVPNMacPathACL.accepts(packet(1, right), privateAuthority: true), "Private socket ACL granted another principal access")
    }
    check(RouterVPNMacPathACL.accepts(packet(2, ~UInt32(0)), privateAuthority: true), "Benign deny-only system ACL was rejected")
    for bit in 0..<32 where ![1,3,7,9,11,20,22,24].contains(bit) {
        check(!RouterVPNMacPathACL.accepts(packet(1, UInt32(1) << bit)), "ACL mutation or unknown authority escaped mode validation")
    }
    for kind: UInt32 in [0,3,4,15] { check(!RouterVPNMacPathACL.accepts(packet(kind, 0)), "Unknown native ACL kind was accepted") }
    for length in 0..<80 { check(!RouterVPNMacPathACL.accepts(packet(1, 2).prefix(length)), "Truncated native ACL readback was accepted") }
    let credentials = RouterVPNMacControllerCredentials(accessToken:String(repeating:"a", count:64), ownerToken:String(repeating:"b", count:32))
    check(credentials.valid, "Exact private credentials were rejected")
    for token in ["", String(repeating:"A",count:64), String(repeating:"g",count:64), String(repeating:"a",count:63)] {
        check(!RouterVPNMacControllerCredentials(accessToken:token, ownerToken:credentials.ownerToken).valid, "Invalid bearer capability was accepted")
    }
    let required = RouterVPNMacLocalAuthorization(required:true)
    var request = URLRequest(url:URL(string:"http://127.0.0.1:8788/api/status")!)
    do { try required.authorize(&request); check(false, "An unowned installed client adopted a localhost listener") } catch { check(true, "") }
    try! required.capture(credentials, processID:7341, live:{true})
    do { try required.authorize(&request); check(false, "A controller without the HMAC readiness proof received bearer authority") } catch { check(true, "") }
    do { try required.capture(credentials, processID:7342, live:{true}); check(false, "A replacement PID overwrote captured controller authority") } catch { check(true, "") }
    #if canImport(CryptoKit)
    let challenge=String(repeating:"c", count:32)
    let known="0c9ebde843b7781f9d838880a3d9bcf4873bba693b790e3a18d642f20f7fba96"
    check((try! credentials.mac("routervpn-controller-identity-response\n7341\n"+challenge)) == known, "Swift and Go controller HMAC encoding disagree")
    let identityText="{\"schema\":1,\"process_id\":7341,\"challenge\":\""+challenge+"\",\"proof\":\""+known+"\"}"
    check(credentials.acceptsIdentity(Data(identityText.utf8),pid:7341,challenge:challenge), "Exact controller HMAC identity failed")
    check(!credentials.acceptsIdentity(Data(identityText.utf8),pid:7342,challenge:challenge), "Different child PID inherited identity proof")
    check(!credentials.acceptsIdentity(Data(identityText.utf8),pid:7341,challenge:String(repeating:"d",count:32)), "Old challenge replay was accepted")
    for raw in [identityText.replacingOccurrences(of:"\"schema\":1",with:"\"schema\":true"), identityText.replacingOccurrences(of:"\"schema\":1",with:"\"schema\":1,\"schema\":1"), identityText.replacingOccurrences(of:"\"schema\":1",with:"\"schema\":1,\"extra\":1"), identityText.replacingOccurrences(of:known,with:String(repeating:"0",count:64))] {
        check(!credentials.acceptsIdentity(Data(raw.utf8),pid:7341,challenge:challenge), "Malformed or forged HMAC identity was accepted")
    }
    for (phase, proof) in [("started","e78362463553b0a65584f437659b528e9f19d133644d330589a8636af51be5b3"),("joined","e605ecac49a66efe3be84652b57007e0a771a6c42edde25d5c076915de4eb7c6")] {
        let raw="{\"schema\":1,\"phase\":\""+phase+"\",\"process_id\":7341,\"exit_code\":0,\"proof\":\""+proof+"\"}"
        check(credentials.acceptsSupervisor(Data(raw.utf8),phase:phase,pid:7341)?.exitCode == 0, "Actual joined receipt format failed")
        for bad in [raw.replacingOccurrences(of:"7341",with:"7342"), raw.replacingOccurrences(of:"\"exit_code\":0",with:"\"exit_code\":7"), raw.replacingOccurrences(of:"\"phase\":\""+phase+"\"",with:"\"phase\":\"unknown\""), raw.replacingOccurrences(of:"\"schema\":1",with:"\"schema\":1,\"schema\":1"), raw.replacingOccurrences(of:proof,with:String(repeating:"0",count:64))] {
            check(credentials.acceptsSupervisor(Data(bad.utf8),phase:phase,pid:7341) == nil, "Forged or replayed supervisor process-join proof was accepted")
        }
    }
    #endif
}
@MainActor func realTransport(_ character: Character) -> Result<RouterVPNMacShutdownReply, Error> {
    var result: Result<RouterVPNMacShutdownReply, Error>?
    let request = try! RouterVPNMacShutdownTransport(url: routerVPNProductBaseURL.appendingPathComponent("api/controller/shutdown"), identity: identity(character), timeout: 35) { value in DispatchQueue.main.async { result = value } }
    request.start(); wait({ result != nil }, "Actual shutdown URLSession did not finish"); return result!
}
@MainActor func transportTests() {
    if case .success(let reply) = realTransport("a") { check(reply.code == 200 && identity().accepts(reply.data), "Actual receipt changed") } else { check(false, "Actual shutdown request failed") }
    if case .success(let reply) = realTransport("b") { check(reply.code == 503, "Pending cleanup HTTP status was hidden") } else { check(false, "503 transport failed") }
    if case .success(let reply) = realTransport("c") { check(!identity("c").accepts(reply.data), "Actual foreign identity accepted") } else { check(false, "Foreign fixture request failed") }
    if case .success(let reply) = realTransport("d") { check(reply.code == 307, "Shutdown redirect was followed") } else { check(false, "Redirect refusal did not return its HTTP status") }
    for c: Character in ["e", "f"] {
        if case .failure = realTransport(c) { check(true, "") } else { check(false, "Oversized terminal response was buffered/accepted") }
    }
    var result: Result<RouterVPNMacShutdownReply, Error>?
    let request = try! RouterVPNMacShutdownTransport(url: routerVPNProductBaseURL.appendingPathComponent("api/controller/shutdown"), identity: identity("1"), timeout: 35) { value in DispatchQueue.main.async { result = value } }
    request.start(); wait({ FileManager.default.fileExists(atPath: fixture.appendingPathComponent("blocked").path) }, "Blocked owned task did not reach server")
    request.cancel(); wait({ result != nil }, "Canceled owned transport did not drain")
    if case .failure = result! { check(true, "") } else { check(false, "Canceled transport reported success") }
    if case .success(let reply) = realTransport("2") { check(identity("2").accepts(reply.data), "Owned cancellation affected another request") } else { check(false, "Replacement task was canceled") }
    for raw in ["https://127.0.0.1:8788/api/controller/shutdown", "http://localhost:8788/api/controller/shutdown", "http://127.0.0.1:8788/api/emergency-stop", "http://127.0.0.1:8788/api/controller/shutdown?pid=1", "http://owner@127.0.0.1:8788/api/controller/shutdown"] {
        do { _ = try RouterVPNMacShutdownTransport(url: URL(string: raw)!, identity: identity(), timeout: 35) { _ in }; check(false, "Invalid controller transport accepted") } catch { check(true, "") }
    }
}
@MainActor func realProcess() -> (Process, Pipe) {
    let process = Process(), input = Pipe()
    process.executableURL = URL(fileURLWithPath: "/bin/sh"); process.arguments = ["-c", "read marker"]
    process.standardInput = input; process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
    try! process.run(); return (process, input)
}
@MainActor func release(_ process: Process, _ input: Pipe) {
    if process.isRunning { try! input.fileHandleForWriting.write(contentsOf: Data("done\n".utf8)) }
    try! input.fileHandleForWriting.close(); wait({ !process.isRunning }, "Owned fixture Process did not exit")
}
@MainActor func processTests() {
    let (process, input) = realProcess(); let owned = identity("a", process.processIdentifier)
    let flow = RouterVPNMacShutdownController(baseURL: routerVPNProductBaseURL, identity: owned, process: process, pollInterval: 0.002, isCurrent: { true })
    var replies: [Bool] = []; flow.onFinish = { replies.append($0) }; flow.start()
    wait({ flow.acknowledged }, "Actual URLSession did not confirm the captured Process")
    check(process.isRunning && replies.isEmpty, "Actual Process was killed/quit before its exit")
    release(process, input); wait({ replies == [true] }, "Actual process cleanup/exit was not joined")
    check(process.joinedSuccessfully, "Actual successful Process join was rejected")
    let failed = Process(); failed.executableURL = URL(fileURLWithPath:"/bin/sh"); failed.arguments=["-c","exit 7"]
    try! failed.run(); wait({!failed.isRunning},"Failed fixture Process never joined")
    check(!failed.joinedSuccessfully,"Actual nonzero Process exit became successful cleanup")
}
authorizationProtocolTests(); controlledTests(); transportTests(); processTests()
#if canImport(AppKit)
appKitTests()
#endif
print("macOS checked shutdown: \(checks) executable checks passed")
'''

APPKIT = r'''
#if canImport(AppKit)
@MainActor final class ProductAPI { var calls = 0; func ready() -> Bool { calls += 1; return calls > 1 } }
@MainActor final class ProductWindowController: NSWindowController {
    init(api: ProductAPI) { super.init(window: NSWindow(contentRect: NSRect(x: 0, y: 0, width: 320, height: 200), styleMask: [.titled], backing: .buffered, defer: false)) }
    required init?(coder: NSCoder) { nil }
}
@MainActor final class ReplyApplication: NSApplication {
    var replies: [Bool] = []; var requests = 0
    override func reply(toApplicationShouldTerminate value: Bool) { replies.append(value) }
    override func terminate(_ sender: Any?) { requests += 1 }
}
@MainActor func appKitTests() {
    let app = ReplyApplication()
    let delegate = ProductDelegate()
    check(delegate.applicationShouldTerminateAfterLastWindowClosed(app), "Last window no longer uses application termination")
    check(delegate.applicationShouldTerminate(app) == .terminateNow && delegate.shutdown == nil, "Unowned controller was stopped")
    let (process, input) = realProcess(); delegate.controller = process; delegate.controllerOwnerToken = token("a"); delegate.ownsController = true
    check(delegate.applicationShouldTerminate(app) == .terminateLater, "Owned Quit did not defer AppKit termination")
    check(app.replies.isEmpty, "AppKit received reply before terminateLater")
    wait({ delegate.shutdown?.acknowledged == true }, "Actual delegate did not request checked cleanup")
    check(delegate.shutdownPanel?.window?.isVisible == true && app.replies.isEmpty && process.isRunning, "AppKit hid pending cleanup or killed controller")
    check(delegate.applicationShouldTerminate(app) == .terminateLater, "Repeated Quit bypassed pending owner")
    try! input.fileHandleForWriting.write(contentsOf: Data("done\n".utf8)); try! input.fileHandleForWriting.close()
    let modalDeadline = Date().addingTimeInterval(6)
    while app.replies.isEmpty && Date() < modalDeadline { _ = RunLoop.main.run(mode: .modalPanel, before: Date().addingTimeInterval(0.01)) }
    check(app.replies == [true] && !process.isRunning, "Actual AppKit modal termination loop did not join Process exit")
    delegate.applicationWillTerminate(Notification(name: NSApplication.willTerminateNotification))
    delegate.shutdownPanel?.close()
    let failed = ProductDelegate(); let (other, otherInput) = realProcess()
    failed.controller = other; failed.controllerOwnerToken = token("c"); failed.ownsController = true
    check(failed.applicationShouldTerminate(app) == .terminateLater, "Foreign fixture quit did not defer")
    wait({ app.replies == [true, false] }, "Foreign receipt did not cancel AppKit termination")
    check(other.isRunning && failed.shutdownPanel?.retry.isEnabled == true, "Failed cleanup killed controller or hid retry")
    let requests = app.requests; failed.shutdownPanel?.retry.performClick(nil)
    check(app.requests == requests + 1, "Actual Retry button did not enter normal AppKit termination callback")
    release(other, otherInput); failed.shutdownPanel?.close()
    let launcher = ProductDelegate(); try! launcher.ensureController()
    let launched = launcher.controller!
    let saved = URL(fileURLWithPath: CommandLine.arguments[3]).appendingPathComponent("owner.json")
    wait({ FileManager.default.fileExists(atPath: saved.path) }, "Actual controller launcher did not pass environment")
    let record = try! JSONSerialization.jsonObject(with: Data(contentsOf: saved)) as! [String: Any]
    check(record["owner_token"] as? String == launcher.controllerOwnerToken && (record["process_id"] as? Int) == Int(launched.processIdentifier), "Launcher nonce/PID not captured from exact Process")
    check(RouterVPNMacShutdownIdentity(processID: launched.processIdentifier, token: launcher.controllerOwnerToken).valid && launcher.ownsController, "Launcher nonce is invalid or unowned")
    try! Data("done".utf8).write(to: saved.deletingLastPathComponent().appendingPathComponent("release"))
    wait({ !launched.isRunning }, "Launch fixture did not exit")
}
#endif
'''

class Server(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, directory):
        self.directory = directory
        self.requests = []
        self.errors = []
        super().__init__(('127.0.0.1', 0), Handler)

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *args): pass
    def do_GET(self):
        self.server.errors.append('Shutdown redirect escaped the owned endpoint')
        self.send_error(404)
    def do_POST(self):
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if size <= 0 or size > 1024 or self.path != '/api/controller/shutdown': raise AssertionError('Invalid endpoint/envelope')
            value = json.loads(self.rfile.read(size))
            if set(value) != {'schema', 'process_id', 'owner_token'} or type(value['schema']) is not int or value['schema'] != 1 or type(value['process_id']) is not int or value['process_id'] <= 0 or not re.fullmatch('[0-9a-f]{32}', value['owner_token']): raise AssertionError('Invalid captured shutdown body')
            self.server.requests.append(value)
            key = value['owner_token'][0]
            if key == '1':
                (self.server.directory/'blocked').write_text('ready')
                time.sleep(0.5)
            if key == 'd':
                self.send_response(307); self.send_header('Location', '/foreign-shutdown'); self.send_header('Content-Length', '0'); self.end_headers(); return
            reply = {**value, 'closed': True}
            if key == 'c': reply['owner_token'] = '0'*32
            data = json.dumps(reply,separators=(',',':')).encode()
            self.send_response(503 if key == 'b' else 200); self.send_header('Content-Type', 'application/json')
            if key == 'e':
                self.send_header('Content-Length', '4097'); self.send_header('Connection','close'); self.end_headers(); self.wfile.write(b' '*4097); self.close_connection = True; return
            if key == 'f':
                self.send_header('Transfer-Encoding','chunked'); self.end_headers()
                for _ in range(12): self.wfile.write(b'200\r\n'+b' '*512+b'\r\n'); self.wfile.flush()
                self.wfile.write(b'0\r\n\r\n'); return
            self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError): pass
        except Exception as error:
            self.server.errors.append(type(error).__name__+': '+str(error)); self.close_connection = True

def shipping_contract():
    product=(MAC/'RouterVPNMacProduct.swift').read_text()
    start=product.index('@MainActor final class ProductDelegate:')
    block=product[start:product.index('\nfunc runProductSelfTest()',start)]
    for unwanted in ('/api/emergency-stop','.terminate()','timeout: 2'):
        if unwanted in block: raise AssertionError('Unchecked controller stop remains in actual AppKit delegate: '+unwanted)
    for required in ('func applicationShouldTerminate(','.terminateLater','reply(toApplicationShouldTerminate: allowed)','HOMEVPN_CONTROLLER_OWNER','controllerOwnerToken = token','self.controller === process'):
        if required not in block: raise AssertionError('Actual delegate lost checked shutdown binding: '+required)
    build=(MAC/'build-native-app.sh').read_text()
    if 'SHUTDOWN_SRC="$ROOT/client/macos/RouterVPNMacShutdown.swift"' not in build or '"$EXTERNAL_NODE_SRC" "$SHUTDOWN_SRC" "$MAP_GEOMETRY_SRC"' not in build or 'test_macos_shutdown.py" --shipping-only' not in build: raise AssertionError('Checked shutdown source/tests absent from real native compile')
    if '[NSApp terminate:nil];' not in (MAC/'RouterVPNMenuBar.m').read_text(): raise AssertionError('Menu Quit bypasses actual AppKit callback')
    return block

def execute(directory, swift, source, block, name):
    directory.mkdir()
    (directory/'Shutdown.swift').write_text(source)
    body=MAIN
    sources=[MAC/'RouterVPNMacControllerAuth.swift', directory/'Shutdown.swift']
    package=directory/'package'; package.mkdir()
    if sys.platform=='darwin':
        anchor='let root = Bundle.main.bundleURL.deletingLastPathComponent()'
        if block.count(anchor)!=1: raise AssertionError('Actual launch package seam drifted')
        block=block.replace(anchor,'let root = URL(fileURLWithPath: CommandLine.arguments[3], isDirectory: true)')
        (directory/'Delegate.swift').write_text('import AppKit\nimport Foundation\n'+block+'\n'+APPKIT)
        sources.extend([MAC/'RouterVPNMacControllerLaunch.swift', directory/'Delegate.swift'])
        binary=package/'router-vpn-client'
        binary.write_text('#!/usr/bin/env python3\nimport os,json,pathlib,time\np=pathlib.Path(os.environ["HOMEVPN_ROOT"])\n(p/"owner.json").write_text(json.dumps({"process_id":os.getpid(),"owner_token":os.environ["HOMEVPN_CONTROLLER_OWNER"]}))\nwhile not (p/"release").exists(): time.sleep(0.01)\n')
        binary.chmod(0o700); (package/'client.json').write_text('{}')
    (directory/'main.swift').write_text(body); sources.append(directory/'main.swift')
    executable=directory/'check'
    compilation=subprocess.run([swift,'-swift-version','6','-module-cache-path',str(directory/'module-cache'),*[str(x) for x in sources],'-o',str(executable)],capture_output=True,text=True,timeout=90)
    if compilation.returncode: raise AssertionError('Actual Swift shutdown source failed to compile:\n'+compilation.stdout+compilation.stderr)
    server=Server(directory); thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    try:
        run=subprocess.run([str(executable),f'http://127.0.0.1:{server.server_port}',str(directory),str(package)],capture_output=True,text=True,timeout=45)
        if run.returncode==0 and server.errors: raise AssertionError('; '.join(server.errors))
        return run
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)

def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--shipping-only',action='store_true'); args=parser.parse_args()
    block=shipping_contract()
    swift=os.environ.get('SWIFTC','swiftc')
    source=(MAC/'RouterVPNMacShutdown.swift').read_text()
    with tempfile.TemporaryDirectory(prefix='routervpn-macos-shutdown-') as temp:
        directory=Path(temp)
        result=execute(directory/'shipping',swift,source,block,'shipping')
        if result.returncode: raise AssertionError(result.stdout+result.stderr)
        print(result.stdout.strip())
        if not args.shipping_only:
            mutations={
                'foreign-receipt':('reply.code == 200 && identity.accepts(reply.data)','reply.code == 200'),
                'stale-attempt':('guard generation == captured, replyPending, phase == .requesting else { return }','guard replyPending, phase == .requesting else { return }'),
                'replacement-owner':('&& isCurrent()','&& true'),
                'oversized-response':('private static let limit = 4096','private static let limit = 1048576'),
                'redirect':('completionHandler(nil)','completionHandler(request)'),
                'failed-join':('terminationReason == .exit && terminationStatus == 0','true'),
            }
            for name,(old,new) in mutations.items():
                if source.count(old)!=1: raise AssertionError('Mutation anchor drifted: '+name)
                result=execute(directory/name,swift,source.replace(old,new),block,name)
                if result.returncode==0: raise AssertionError('Broken shutdown invariant passed: '+name)
            print('macOS checked shutdown: 6 executable negative controls rejected')
    print('Actual AppKit callbacks: '+('passed' if sys.platform=='darwin' else 'require macOS CI; Foundation/URLSession/Process checks passed locally'))

if __name__=='__main__': main()
