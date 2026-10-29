#!/usr/bin/env python3
"""Run the shipping MTU owner and real URLSession; exercise AppKit on macOS."""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
import argparse
import json
import os
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
MAC = ROOT / "client/macos"

MAIN = r'''
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(AppKit)
import AppKit
final class ProductWindowController: NSWindowController { var mtuPanel: RouterVPNMacMTUPanel? }
#endif
let routerVPNProductBaseURL = URL(string: CommandLine.arguments[1])!
let fixture = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
var checks = 0
func check(_ value: @autoclosure () -> Bool, _ message: String) {
    checks += 1
    if !value() { fputs(message + "\n", stderr); exit(1) }
}
func spin(_ seconds: TimeInterval = 0.03) {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline { _ = RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.005)) }
}
func wait(_ predicate: () -> Bool, _ message: String) {
    let deadline = Date().addingTimeInterval(5)
    while !predicate() && Date() < deadline { spin(0.005) }
    check(predicate(), message)
}
func exists(_ name: String) -> Bool { FileManager.default.fileExists(atPath: fixture.appendingPathComponent(name).path) }
func flag(_ name: String, _ value: String = "ready") { try! Data(value.utf8).write(to: fixture.appendingPathComponent(name), options: .atomic) }
func status(_ request: String = "", session: String = "session-a", profile: String = "profile-a",
            running: Bool = false, complete: Bool = false, waiting: Bool = false, restored: Bool = false,
            requested: Bool = false, measured: Bool = false, candidates: Bool = false, optimization: Bool? = nil) -> RouterVPNMacMTUReply {
    var rows: [[String: Any]] = []
    if candidates { rows = [["mtu": 1360, "working": true, "packets_sent": 10, "packets_received": 9,
                            "median_rtt_ms": 12.5, "latency_kind": "authenticated UDP response", "download": ["bytes": 1048576, "seconds": 0.5, "mbps": 16.777216]]] }
    var body: [String: Any] = ["session_id": session, "profile_id": profile, "requested": requested, "waiting_commit": waiting,
        "status": ["request_id": request, "phase": complete ? "complete" : (running ? "measuring" : "idle"),
                   "running": running, "complete": complete, "measured": measured, "restored": restored,
                   "original_mtu": 1420, "effective_mtu": 1360, "source": measured ? "authenticated-path" : "saved-history", "candidates": rows]]
    if let optimization { body["optimization_allowed"] = optimization }
    return RouterVPNMacMTUReply(code: 200, data: try! JSONSerialization.data(withJSONObject: body))
}
final class ControlledRequest: RouterVPNMacMTURequest {
    let url: URL; let body: [String: Any]?; let completion: (Result<RouterVPNMacMTUReply, Error>) -> Void
    var started = false, cancelled = false, delivered = false
    init(_ url: URL, _ body: [String: Any]?, _ completion: @escaping (Result<RouterVPNMacMTUReply, Error>) -> Void) { self.url = url; self.body = body; self.completion = completion }
    func start() { started = true }
    func cancel() { cancelled = true }
    func reply(_ value: RouterVPNMacMTUReply) { delivered = true; completion(.success(value)); spin() }
    func fail() { delivered = true; completion(.failure(NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled))); spin() }
}
final class ControlledFactory {
    var requests: [ControlledRequest] = []
    func make(_ url: URL, _ body: [String: Any]?, _ timeout: TimeInterval, _ callback: @escaping (Result<RouterVPNMacMTUReply, Error>) -> Void) -> RouterVPNMacMTURequest {
        let request = ControlledRequest(url, body, callback); requests.append(request); return request
    }
    func next(_ path: String) -> ControlledRequest {
        wait({ self.requests.contains { $0.url.path == path && $0.started && !$0.delivered && !$0.cancelled } }, "Missing owned request " + path)
        return requests.first { $0.url.path == path && $0.started && !$0.delivered && !$0.cancelled }!
    }
    func controller() -> RouterVPNMacMTUController { RouterVPNMacMTUController(baseURL: routerVPNProductBaseURL, pollInterval: 0.005, factory: make) }
}
func begin(_ factory: ControlledFactory) -> (RouterVPNMacMTUController, ControlledRequest) {
    let owner = factory.controller(); owner.open(retest: true)
    factory.next("/api/mtu/status").reply(status())
    let post = factory.next("/api/mtu/retest")
    check(Set(post.body!.keys) == ["request_id", "session_id", "profile_id"], "Manual request did not capture its complete identity")
    check(post.body?["session_id"] as? String == "session-a" && post.body?["profile_id"] as? String == "profile-a", "Manual request captured the wrong connection")
    check(RouterVPNMacMTUTransport.validRequestID(owner.requestID), "Manual request ID is not32 lowercase hex")
    return (owner, post)
}
// A complete mailbox is still pending until both commit and the owned POST drain.
do {
    let f = ControlledFactory(); let (owner, post) = begin(f)
    let poll = f.next("/api/mtu/status")
    let query = Dictionary(uniqueKeysWithValues: URLComponents(url: poll.url, resolvingAgainstBaseURL: false)!.queryItems!.map { ($0.name, $0.value!) })
    check(query == ["session_id": "session-a", "request_id": owner.requestID], "Status poll lost the captured identity")
    poll.reply(status(owner.requestID, complete: true, measured: true, candidates: true))
    check(owner.view.busy && !owner.view.canRetest, "Complete mailbox bypassed the pending POST drain")
    post.reply(RouterVPNMacMTUReply(code: 200, data: Data("{}".utf8)))
    check(owner.view.busy && !owner.view.canRetest, "Ended POST released controls before fresh final status")
    f.next("/api/mtu/status").reply(status(owner.requestID, complete: true, waiting: true, measured: true))
    check(owner.view.busy && !owner.view.canRetest, "Complete mailbox bypassed waiting_commit")
    f.next("/api/mtu/status").reply(status(owner.requestID, complete: true, measured: true, candidates: true))
    check(!owner.view.busy && owner.view.canRetest, "Drained completed request did not release controls")
    check(owner.view.measurements.contains("9/10") && owner.view.measurements.contains("1048576 bytes") && owner.view.measurements.contains("16.78 Mbps"), "Candidate evidence was replaced with a fabricated result")
    let priorID = owner.requestID; owner.retest(); f.next("/api/mtu/status").reply(status(priorID, complete: true))
    let nextPost = f.next("/api/mtu/retest")
    check(owner.requestID != priorID && nextPost.body?["session_id"] as? String == "session-a", "Retest reused a completed request ID")
    owner.stop()
}
// Cancel ACK, canceled HTTP response and native rollback are distinct events.
do {
    let f = ControlledFactory(); let (owner, post) = begin(f)
    f.next("/api/mtu/status").reply(status(owner.requestID, running: true))
    owner.cancel(); check(post.cancelled, "Cancellation did not abort the owned pending POST")
    let cancel = f.next("/api/mtu/cancel")
    check(cancel.body?["request_id"] as? String == owner.requestID && cancel.body?["session_id"] as? String == "session-a", "Cancel lost the exact owner")
    cancel.reply(RouterVPNMacMTUReply(code: 200, data: try! JSONSerialization.data(withJSONObject: ["request_id": owner.requestID, "session_id": "session-a", "phase": "canceling"])))
    check(owner.view.busy && !owner.view.canRetest, "Cancellation ACK was treated as completed rollback")
    post.reply(RouterVPNMacMTUReply(code: 409, data: Data("cancelled after rollback".utf8)))
    f.next("/api/mtu/status").reply(status(owner.requestID, complete: true, restored: true))
    check(owner.view.busy, "Pre-completion poll attested to final cancellation status")
    f.next("/api/mtu/status").reply(status(owner.requestID, complete: true, restored: true))
    check(!owner.view.busy && owner.view.detail.contains("original MTU was restored"), "POST409 erased a matching restored receipt")
    owner.stop()
}
// Before registration404 is allowed only while this exact POST is pending.
do {
    let f = ControlledFactory(); let (owner, post) = begin(f)
    f.next("/api/mtu/status").reply(RouterVPNMacMTUReply(code: 404, data: Data()))
    check(owner.view.busy, "Unregistered pending POST was retired too soon")
    owner.cancel(); check(post.cancelled, "Early Cancel left a POST able to register late")
    f.next("/api/mtu/cancel").reply(RouterVPNMacMTUReply(code: 404, data: Data()))
    post.fail()
    f.next("/api/mtu/status").reply(RouterVPNMacMTUReply(code: 404, data: Data()))
    check(owner.view.busy, "Old404 retired an operation before its final status read")
    f.next("/api/mtu/status").reply(RouterVPNMacMTUReply(code: 404, data: Data()))
    check(!owner.view.busy && !owner.view.canRetest && owner.view.detail.contains("No rollback result is claimed"), "Missing retired request remained pending or claimed restoration")
    owner.stop()
}
// Wrong connection, selected profile, request, and disappeared observed owners.
for changed in ["session", "profile", "request", "missing", "conflict"] {
    let f = ControlledFactory(); let (owner, post) = begin(f)
    f.next("/api/mtu/status").reply(status(owner.requestID, running: true))
    let bad: RouterVPNMacMTUReply
    if changed == "missing" || changed == "conflict" { bad = RouterVPNMacMTUReply(code: changed == "missing" ? 404 : 409, data: Data()) }
    else { bad = status(changed == "request" ? String(repeating: "e", count: 32) : owner.requestID,
                       session: changed == "session" ? "session-new" : "session-a", profile: changed == "profile" ? "profile-new" : "profile-a", complete: true, measured: true) }
    f.next("/api/mtu/status").reply(bad)
    check(!owner.view.busy && !owner.view.canRetest && post.cancelled, "Foreign or missing observed owner was adopted: " + changed)
    check(!f.requests.contains { $0.url.path == "/api/mtu/cancel" }, "Retirement attempted to cancel a replacement")
    owner.stop()
}
// A queued completion from a closed window cannot publish into any view.
do {
    let f = ControlledFactory(); let owner = f.controller(); owner.open()
    let old = f.next("/api/mtu/status"); owner.stop(); let before = owner.view.title
    old.reply(status(String(repeating: "d", count: 32), running: true))
    check(owner.sessionID.isEmpty && owner.requestID.isEmpty && owner.view.title == before, "Closed queued callback mutated captured view")
}
// Auto observation binds the first owner, including a pre-commit empty mailbox.
do {
    let f = ControlledFactory(); let owner = f.controller(); owner.open()
    f.next("/api/mtu/status").reply(status(waiting: true, requested: true))
    let next = f.next("/api/mtu/status")
    check(next.url.query?.contains("session_id=session-a") == true && next.url.query?.contains("request_id") == false, "Pending Auto lost session-only capture")
    next.reply(status(String(repeating: "a", count: 32), running: true, requested: true))
    check(owner.requestID == String(repeating: "a", count: 32) && owner.seenRequest, "Auto request was not captured")
    check(owner.requestClose(), "Closing an Auto observer demanded test cancellation")
    check(!f.requests.contains { $0.url.path == "/api/mtu/cancel" }, "Auto Close cancelled someone else's operation")
}
// Manual Close requests cancellation and waits for the authoritative drain.
do {
    let f = ControlledFactory(); let (owner, post) = begin(f)
    f.next("/api/mtu/status").reply(status(owner.requestID, running: true))
    check(!owner.requestClose() && post.cancelled, "Manual Close abandoned an active POST")
    f.next("/api/mtu/cancel").reply(RouterVPNMacMTUReply(code: 409, data: Data("operation finished".utf8)))
    post.fail()
    f.next("/api/mtu/status").reply(status(owner.requestID, complete: true, restored: true))
    check(!owner.view.closeReady, "Manual Close accepted a status read begun before drain")
    f.next("/api/mtu/status").reply(status(owner.requestID, complete: true, restored: true))
    check(owner.view.closeReady && !owner.view.busy, "Cancel409 discarded the completed close/rollback receipt")
    owner.stop()
}
// Once the user explicitly cancels Auto, closing must not abort that Cancel.
do {
    let f = ControlledFactory(); let owner = f.controller(); owner.open()
    let request = String(repeating: "a", count: 32)
    f.next("/api/mtu/status").reply(status(request, running: true, requested: true))
    owner.cancel(); let cancel = f.next("/api/mtu/cancel")
    check(!owner.requestClose() && !cancel.cancelled, "Auto Close abandoned an explicit pending cancellation")
    cancel.reply(RouterVPNMacMTUReply(code: 200, data: try! JSONSerialization.data(withJSONObject: ["request_id": request, "phase": "canceling"])))
    f.next("/api/mtu/status").reply(status(request, complete: true, restored: true))
    check(owner.view.busy && !owner.view.closeReady, "Auto Close accepted stale rollback status")
    f.next("/api/mtu/status").reply(status(request, complete: true, restored: true))
    check(owner.view.closeReady && !owner.view.busy, "Explicit Auto cancellation failed to drain before closing")
    check(f.requests.filter { $0.url.path == "/api/mtu/cancel" }.count == 1, "Close sent a duplicate Auto cancellation")
    owner.stop()
}
// A finished historical saved value is never relabelled as a fresh measurement.
do {
    let f = ControlledFactory(); let owner = f.controller(); owner.open()
    f.next("/api/mtu/status").reply(status())
    check(owner.view.detail.contains("Saved MTU (historical)") && !owner.view.detail.contains("Effective interface MTU") && owner.view.detail.contains("No fresh measurement") && owner.view.canRetest, "Saved legacy value became effective/measured or disabled valid Retest")
    f.next("/api/mtu/status").reply(status(String(repeating: "b", count: 32), running: true, requested: true))
    check(owner.seenRequest && owner.requestID == String(repeating: "b", count: 32), "Idle Auto observer froze before its request appeared")
    f.next("/api/mtu/status").reply(status(String(repeating: "c", count: 32), running: true, requested: true))
    check(!owner.view.busy && !owner.view.canRetest && owner.requestID == String(repeating: "b", count: 32), "Auto observer silently followed a replacement request")
    owner.stop()
}

// Configured interface policy is separate from the legacy requested flag.
for start in [false, true] {
    let f = ControlledFactory(); let owner = f.controller(); owner.open(retest: start)
    f.next("/api/mtu/status").reply(status(optimization: false))
    check(!owner.view.canRetest && !owner.view.busy && owner.view.detail.contains("Retest is disabled"), "Configured policy incorrectly enabled Retest")
    owner.retest()
    check(!f.requests.contains { $0.url.path == "/api/mtu/retest" }, "Configured policy emitted an MTU mutation")
    owner.stop()
}
do {
    let f = ControlledFactory(); let owner = f.controller(); owner.open()
    f.next("/api/mtu/status").reply(status(optimization: true))
    check(owner.view.canRetest, "Explicit eligible policy disabled Retest")
    owner.retest()
    f.next("/api/mtu/status").reply(status(optimization: false))
    check(!owner.view.canRetest && !f.requests.contains { $0.url.path == "/api/mtu/retest" }, "Retest ignored freshly captured configured policy")
    owner.stop()
}
for bad: Any in [NSNull(), "false", 0, 1] {
    let f = ControlledFactory(); let owner = f.controller(); owner.open()
    var body = try! JSONSerialization.jsonObject(with: status().data) as! [String: Any]
    body["optimization_allowed"] = bad
    f.next("/api/mtu/status").reply(RouterVPNMacMTUReply(code: 200, data: try! JSONSerialization.data(withJSONObject: body)))
    check(owner.sessionID.isEmpty && !owner.view.canRetest && owner.view.detail.contains("MTU status rejected"), "Malformed optimization capability adopted a connection")
    owner.stop()
}

// Exercise the actual Foundation transport and controller together on loopback.
flag("mode", "manual")
let live = RouterVPNMacMTUController(baseURL: routerVPNProductBaseURL, pollInterval: 0.02)
live.open(retest: true)
wait({ live.seenRequest && exists("post-started") }, "Native Retest did not reach the loopback controller")
live.cancel()
wait({ exists("cancel-ack") && !live.manualPostPending && exists("post-closed") }, "Native Cancel did not close its actual pending POST")
check(live.view.busy && !live.view.canRetest, "Native cancellation ACK completed the view before rollback")
flag("complete")
wait({ !live.view.busy }, "Native rollback never completed its captured view")
check(live.view.detail.contains("original MTU was restored"), "Actual native final receipt was lost")
live.stop()

flag("mode", "auto")
let automatic = RouterVPNMacMTUController(baseURL: routerVPNProductBaseURL, pollInterval: 0.02)
automatic.open(); wait({ automatic.seenRequest }, "Actual Auto observer did not capture its owner")
check(automatic.requestClose(), "Actual Auto Close unexpectedly waited")
flag("mode", "stale")
let stale = RouterVPNMacMTUController(baseURL: routerVPNProductBaseURL, pollInterval: 0.02)
stale.open(); wait({ exists("stale-started") }, "Stale native request did not start")
stale.stop(); let before = stale.view.title
flag("mode", "replacement")
let replacement = RouterVPNMacMTUController(baseURL: routerVPNProductBaseURL, pollInterval: 0.02)
replacement.open(); wait({ replacement.seenRequest }, "Old close prevented replacement observation")
flag("release-stale"); spin(0.1)
check(stale.sessionID.isEmpty && stale.view.title == before && replacement.sessionID == "session-replacement", "Actual stale callback changed old or replacement state")
replacement.stop()

for mode in ["redirect", "oversized", "stream"] {
    flag("mode", mode); var reply: Result<RouterVPNMacMTUReply, Error>?
    let transport = try RouterVPNMacMTUTransport(url: routerVPNProductBaseURL.appendingPathComponent("api/mtu/status"), body: nil, timeout: 5) { reply = $0 }
    transport.start(); wait({ reply != nil }, "Native MTU transport stalled: " + mode)
    if mode == "redirect" { if case .success(let response)? = reply { check(response.code == 302, "MTU transport followed a redirect") } else { check(false, "Redirect response was not retained") } }
    else { if case .failure(let error)? = reply { check((error as NSError).domain == "RouterVPNMTU" && (error as NSError).code == 2, "Response bound waited for timeout") } else { check(false, "Oversized MTU response was accepted") } }
}
for url in ["https://127.0.0.1/api/mtu/status", "http://example.invalid/api/mtu/status", "http://127.0.0.1/api/disconnect", "http://u:p@127.0.0.1/api/mtu/status", "http://127.0.0.1/api/mtu/status?request_id=bad", "http://127.0.0.1/api/mtu/status?session_id=a&session_id=b", "http://127.0.0.1/api/mtu/status?extra=1"] {
    do { _ = try RouterVPNMacMTUTransport(url: URL(string: url)!, body: nil, timeout: 1) { _ in }; check(false, "Foreign/ambiguous endpoint was accepted") } catch { checks += 1 }
}
for body: [String: Any] in [[:], ["request_id": String(repeating: "a", count: 32), "session_id": "s"], ["request_id": String(repeating: "a", count: 32), "session_id": "s", "profile_id": "p", "extra": true]] {
    do { _ = try RouterVPNMacMTUTransport(url: routerVPNProductBaseURL.appendingPathComponent("api/mtu/retest"), body: body, timeout: 1) { _ in }; check(false, "Ambiguous manual identity was accepted") } catch { checks += 1 }
}
#if canImport(AppKit)
let app = NSApplication.shared; app.setActivationPolicy(.accessory)
flag("mode", "auto")
var panelClosed = false
let panel = RouterVPNMacMTUPanel(baseURL: routerVPNProductBaseURL, retest: false) { _ in panelClosed = true }
panel.showWindow(nil)
wait({ panel.controller.seenRequest }, "Actual AppKit panel failed to observe Auto")
@MainActor func view(_ root: NSView, _ id: String) -> NSView? {
    if root.identifier?.rawValue == id { return root }
    for child in root.subviews { if let found = view(child, id) { return found } }
    return nil
}
let content = panel.window!.contentView!
let cancelButton = view(content, "mtu-cancel") as! NSButton
let retestButton = view(content, "mtu-retest") as! NSButton
let phase = view(content, "mtu-phase") as! NSTextField
check(cancelButton.isEnabled && !retestButton.isEnabled && phase.stringValue.contains("MTU test"), "AppKit controls did not reflect the actual owner")
content.layoutSubtreeIfNeeded()
check(content.bounds.width >= 680 && content.bounds.height >= 500, "MTU panel lost usable native bounds")
let bitmap = content.bitmapImageRepForCachingDisplay(in: content.bounds)!
content.cacheDisplay(in: content.bounds, to: bitmap)
check(bitmap.pixelsWide >= 680 && bitmap.pixelsHigh >= 500, "Actual MTU panel failed to render")
panel.window!.performClose(nil); wait({ panelClosed }, "Actual Auto panel did not detach")
// Invoke the shipping AppKit controls, then verify the actual network and UI
// remain pending after Cancel until the captured rollback receipt arrives.
for name in ["post-started", "post-closed", "cancel-ack", "complete"] { try? FileManager.default.removeItem(at: fixture.appendingPathComponent(name)) }
flag("mode", "manual")
var manualClosed = false
let manualPanel = RouterVPNMacMTUPanel(baseURL: routerVPNProductBaseURL, retest: false) { _ in manualClosed = true }
manualPanel.showWindow(nil)
wait({ manualPanel.controller.view.canRetest }, "AppKit idle panel did not enable Retest")
let manualContent = manualPanel.window!.contentView!
let runButton = view(manualContent, "mtu-retest") as! NSButton
let abortButton = view(manualContent, "mtu-cancel") as! NSButton
runButton.performClick(nil)
wait({ manualPanel.controller.seenRequest && exists("post-started") }, "Actual AppKit Retest callback did not start its captured request")
abortButton.performClick(nil)
wait({ exists("cancel-ack") && exists("post-closed") && !manualPanel.controller.manualPostPending }, "Actual AppKit Cancel callback did not abort its owned request")
check(!runButton.isEnabled && manualPanel.controller.view.busy, "AppKit Cancel enabled Retest before rollback")
flag("complete")
wait({ !manualPanel.controller.view.busy }, "Actual AppKit rollback never completed")
let result = view(manualContent, "mtu-measurement-status") as! NSTextField
check(result.stringValue.contains("original MTU was restored") && !abortButton.isEnabled && runButton.isEnabled, "AppKit controls lost the confirmed rollback result")
manualPanel.window!.performClose(nil); wait({ manualClosed }, "Completed manual panel did not close")
print("Actual macOS SDK/AppKit MTU controls and rendering: PASS")
#endif
print("Shipping MTU capture, rollback, cancellation, replacement and native HTTP checks: \(checks) PASS")
'''


def run_case(directory, mutation):
    work = directory / mutation
    work.mkdir()
    hits, errors = [], []
    lock = threading.Lock()
    request = {"id": ""}
    before_admission = {}

    def mode():
        try:
            return (work / "mode").read_text()
        except FileNotFoundError:
            return "manual"

    def payload(identifier="", *, session="session-a", running=False, complete=False, restored=False):
        return {"session_id": session, "profile_id": "profile-a", "requested": False, "waiting_commit": False,
                "status": {"request_id": identifier, "phase": "complete" if complete else "measuring" if running else "idle",
                           "running": running, "complete": complete, "measured": False, "restored": restored,
                           "original_mtu": 1420, "effective_mtu": 1420, "source": "restored-captured-interface" if restored else "saved-history", "candidates": []}}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def handle(self):
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                pass

        def send_json(self, body, code=200):
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            self.wfile.flush()

        def do_GET(self):
            current = mode()
            with lock:
                hits.append((current, "GET", self.path))
            parsed = urlsplit(self.path)
            if parsed.path != "/api/mtu/status":
                errors.append("redirect/foreign path was followed")
                self.send_json({}, 500)
                return
            if current == "redirect":
                self.send_response(302)
                self.send_header("Location", "/must-not-follow")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if current in ("oversized", "stream"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                if current == "oversized":
                    self.send_header("Content-Length", str(3 * 1024 * 1024))
                else:
                    self.send_header("Connection", "close")
                self.end_headers()
                try:
                    if current == "oversized":
                        self.wfile.write(b"{")
                        self.wfile.flush()
                        time.sleep(0.1)
                    else:
                        for _ in range(48):
                            self.wfile.write(b"x" * 65536)
                            self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                self.close_connection = True
                return
            if current == "stale":
                (work / "stale-started").write_text("ready")
                until = time.monotonic() + 5
                while not (work / "release-stale").exists() and time.monotonic() < until:
                    time.sleep(0.01)
                self.send_json(payload("c" * 32, session="session-stale", running=True))
                return
            if current in ("auto", "replacement"):
                self.send_json(payload("a" * 32, session="session-replacement" if current == "replacement" else "session-a", running=True))
                return
            query = parse_qs(parsed.query)
            if query:
                identifiers = query.get("request_id", [])
                if set(query) != {"session_id", "request_id"} or query.get("session_id") != ["session-a"] or len(identifiers) != 1 or len(identifiers[0]) != 32 or any(c not in "0123456789abcdef" for c in identifiers[0]):
                    errors.append("real poll changed captured identity")
                    self.send_json({}, 409)
                    return
                identifier = identifiers[0]
                with lock:
                    registered = request["id"]
                    not_started = before_admission.setdefault(identifier, threading.Event())
                if registered != identifier:
                    # This is the shipping controller's 404 boundary: the
                    # captured POST may still be queued on another connection.
                    # A valid-but-unregistered ID is not a replaced session.
                    self.send_json({}, 404)
                    not_started.set()
                    return
                complete = (work / "complete").exists()
                self.send_json(payload(identifier, running=not complete, complete=complete, restored=complete))
            else:
                self.send_json(payload())

        def do_POST(self):
            current = mode()
            try:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with lock:
                    hits.append((current, "POST", self.path))
                if current != "manual":
                    errors.append("closed Auto/replacement observer mutated server state")
                if self.path == "/api/mtu/retest":
                    assert set(body) == {"session_id", "request_id", "profile_id"}
                    assert body["session_id"] == "session-a" and body["profile_id"] == "profile-a"
                    assert len(body["request_id"]) == 32 and all(c in "0123456789abcdef" for c in body["request_id"])
                    with lock:
                        not_started = before_admission.setdefault(body["request_id"], threading.Event())
                    # Force the real status-before-POST-registration ordering;
                    # no scheduler timing assumption or sleep proves this case.
                    assert not_started.wait(3), "native MTU owner did not retain its queued POST across the actual unregistered status"
                    with lock:
                        request["id"] = body["request_id"]
                    (work / "post-started").write_text("ready")
                    until = time.monotonic() + 5
                    while time.monotonic() < until:
                        ready, _, _ = select.select([self.connection], [], [], 0.02)
                        if ready and self.connection.recv(1, socket.MSG_PEEK) == b"":
                            (work / "post-closed").write_text("closed")
                            return
                    errors.append("native manual POST was not aborted")
                    self.send_json({}, 500)
                elif self.path == "/api/mtu/cancel":
                    assert body == {"request_id": request["id"], "session_id": "session-a"}
                    self.send_json({**body, "phase": "canceling"})
                    (work / "cancel-ack").write_text("ready")
                else:
                    raise AssertionError("foreign mutation path")
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as error:
                errors.append(str(error))

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    controller = (MAC / "RouterVPNMacMTUController.swift").read_text()
    mutations = {
        "missing-session-owner": ("value.session_id != sessionID || value.profile_id != profileID", "false"),
        "missing-request-owner": ("guard value.status.request_id == requestID else", "guard true else"),
        "missing-early-cancel": ("if manualPostPending { postTask?.cancel() }", "if manualPostPending { /* missing owned abort */ }"),
        "early-completion": ("return manualPostPending || cancelTask != nil || awaitingFinalStatus", "return cancelTask != nil || awaitingFinalStatus"),
        "stale-final-status": ("self.postTask = nil; self.manualPostPending = false\n                    self.completionEpoch &+= 1; self.awaitingFinalStatus = true", "self.postTask = nil; self.manualPostPending = false"),
        "frozen-idle-observer": ("return operationPending || (!manual && snapshot != nil && requestID.isEmpty)", "return operationPending"),
        "follow-missing-owner": ("if !seenRequest && manualPostPending {", "if true {"),
        "closed-callback": ("guard let self, !self.closed, self.generation == owner, self.pollID == taskOwner else", "guard let self else"),
        "configured-policy": ("var optimizationAllowed: Bool { optimization_allowed ?? true }", "var optimizationAllowed: Bool { true }"),
        "null-capability": ('object?["optimization_allowed"] == nil || value.optimization_allowed != nil,', ''),
    }
    if mutation != "shipping":
        before, after = mutations[mutation]
        assert controller.count(before) == 1, (mutation, controller.count(before))
        controller = controller.replace(before, after, 1)
    (work / "Controller.swift").write_text(controller)
    (work / "main.swift").write_text(MAIN)
    sources = [str(MAC / "RouterVPNMacControllerAuth.swift"), str(MAC / "RouterVPNMacMTUTransport.swift"), str(work / "Controller.swift")]
    if sys.platform == "darwin":
        sources.append(str(MAC / "RouterVPNMacMTUPanel.swift"))
    sources.append(str(work / "main.swift"))
    try:
        subprocess.run(["swiftc", "-swift-version", "5", "-module-cache-path", str(directory / "module-cache"), *sources, "-o", str(work / "test")], check=True, timeout=120)
        result = subprocess.run([str(work / "test"), "http://127.0.0.1:" + str(server.server_address[1]), str(work)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=50)
        if mutation == "shipping":
            print(result.stdout, end="", flush=True)
            assert result.returncode == 0, result.stdout + "\nHits: " + repr(hits) + "\nErrors: " + repr(errors)
            assert not errors, errors
            assert not any(path == "/must-not-follow" for _, _, path in hits)
            expected = 2 if sys.platform == "darwin" else 1
            assert sum(method == "POST" and path == "/api/mtu/retest" for _, method, path in hits) == expected, hits
            assert sum(method == "POST" and path == "/api/mtu/cancel" for _, method, path in hits) == expected, hits
            assert len(before_admission) == expected and all(event.is_set() for event in before_admission.values()), "actual status-before-registration case was not exercised"
        else:
            expected = {
                "missing-session-owner": "Foreign or missing observed owner was adopted: session",
                "missing-request-owner": "Foreign or missing observed owner was adopted: request",
                "missing-early-cancel": "Cancellation did not abort the owned pending POST",
                "early-completion": "Complete mailbox bypassed the pending POST drain",
                "stale-final-status": "Ended POST released controls before fresh final status",
                "frozen-idle-observer": "Missing owned request /api/mtu/status",
                "follow-missing-owner": "Missing retired request remained pending",
                "closed-callback": "Closed queued callback mutated captured view",
                "configured-policy": "Configured policy incorrectly enabled Retest",
                "null-capability": "Malformed optimization capability adopted a connection",
            }[mutation]
            assert result.returncode != 0 and expected in result.stdout, (mutation, result.returncode, result.stdout)
            print("MTU negative control " + mutation + ": rejected", flush=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shipping-only", action="store_true")
    args = parser.parse_args()
    cases = ["shipping"] if args.shipping_only else ["shipping", "missing-session-owner", "missing-request-owner", "missing-early-cancel", "early-completion", "stale-final-status", "frozen-idle-observer", "follow-missing-owner", "closed-callback", "configured-policy", "null-capability"]
    with tempfile.TemporaryDirectory(prefix="router-vpn-macos-mtu-") as directory:
        for case in cases:
            run_case(Path(directory), case)
    print("macOS captured MTU progress/Cancel lifecycle: PASS", flush=True)


if __name__ == "__main__":
    main()
