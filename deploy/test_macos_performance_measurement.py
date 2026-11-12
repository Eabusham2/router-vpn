#!/usr/bin/env python3
"""Execute the shipping Performance owner/delegates with its native URLSession transport."""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import json
import select
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def block(source, marker):
    start = source.index(marker)
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def run_case(directory, mutation):
    fixture = directory / mutation
    fixture.mkdir()
    hits, errors = [], []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args):
            pass

        def handle(self):
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            self.reply(None)

        def do_POST(self):
            self.reply(json.loads(self.rfile.read(int(self.headers['Content-Length']))))

        def reply(self, body):
            mode = (fixture / 'mode').read_text()
            hits.append((mode, self.path, body))
            try:
                if mode in ('blocked', 'preflight', 'replacement'):
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.wfile.write(b'{')
                    self.wfile.flush()
                    (fixture / (mode + '-started')).write_text('ready')
                    deadline = time.monotonic() + 6
                    while time.monotonic() < deadline:
                        ready, _, _ = select.select([self.connection], [], [], .02)
                        if ready and self.connection.recv(1, socket.MSG_PEEK) == b'':
                            (fixture / (mode + '-cancelled')).write_text('closed')
                            return
                    errors.append(mode + ' network request remained open')
                    return
                if self.path == '/api/multihop/status':
                    value = {'connected': True, 'entry_id': 'active-entry', 'exit_id': 'active-exit'}
                    if mode.startswith('ordered'):
                        value.update(ordered_capture='a' * 64, ordered_nodes=3)
                        if mode == 'ordered-missing': value.pop('ordered_capture')
                        if mode == 'ordered-count': value['ordered_nodes'] = True
                        if mode == 'ordered-token': value['ordered_capture'] = 'bad'
                    if mode == 'disconnected':
                        value['connected'] = False
                    if mode == 'numeric-connected':
                        value['connected'] = 1
                    if mode == 'same-hop':
                        value['exit_id'] = value['entry_id']
                    if mode == 'missing-hop':
                        value.pop('entry_id')
                elif self.path == '/api/profiles':
                    value = {'selected_id': 'selected-node'}
                else:
                    value = {'mode': mode, 'path': self.path, 'download_bytes': 12345, 'download_ms': 67, 'error': 'kept per-hop error'}
                if mode == 'ordered' and self.path == '/api/multihop/speed-test':
                    value['hops'] = [{'role': 'entry', 'router_id': 'a'}, {'role': 'intermediate', 'router_id': 'middle-kept', 'speed_label': 'Cumulative path through node 2 of 3'}, {'role': 'exit', 'router_id': 'c'}]
                raw = json.dumps(value).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as error:
                errors.append(str(error))

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    source = (ROOT / 'client/macos/RouterVPNMacTelemetry.swift').read_text()
    owner = block(source, 'private final class RouterVPNMacPerformanceMeasurement').replace('private ', '').replace('private(set) ', '')
    delegates = '\n'.join(block(block(source, 'private final class RouterVPNMacPerformanceController'), marker) for marker in ('    private func render(', '    func windowShouldClose(', '    func windowWillClose(')).replace('private func ', 'func ')
    if mutation == 'missing-cancel':
        owner = owner.replace('request?.cancel()', '_ = request')
    if mutation == 'missing-generation':
        owner = owner.replace('generation == owner', 'true').replace('self.true', 'true')
    if mutation == 'missing-closed':
        owner = owner.replace('if self.closed { self.running = false; return }', '').replace('guard !closed else { return }', '')
    (fixture / 'Owner.swift').write_text('import Foundation\nimport CoreFoundation\n' + owner)
    main = r'''
import Foundation
import CoreFoundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
let base = URL(string: CommandLine.arguments[1])!
let fixture = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
func fail(_ text: String) -> Never { fputs(text + "\n", stderr); exit(1) }
func require(_ value: Bool, _ text: String) { if !value { fail(text) } }
func wait(_ condition: () -> Bool, _ text: String) {
    let until = Date().addingTimeInterval(3)
    while !condition() && Date() < until { _ = RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.01)) }
    require(condition(), text)
}
func exists(_ name: String) -> Bool { FileManager.default.fileExists(atPath: fixture.appendingPathComponent(name).path) }
func mode(_ value: String) { try! Data(value.utf8).write(to: fixture.appendingPathComponent("mode"), options: .atomic) }
final class Field { var stringValue = ""; var isEnabled = true }
final class NSWindow { var closes = 0; func performClose(_ sender: Any?) { closes += 1 } }
final class Panel {
    let measurement = RouterVPNMacPerformanceMeasurement(baseURL: base)
    var closed = false, closeWanted = false
    let result = Field(), cancelButton = Field(), actions = [Field(), Field(), Field(), Field(), Field(), Field()]
    let window: NSWindow? = NSWindow()
    init() { measurement.changed = { [weak self] text in self?.render(text) } }
    DELEGATES
}
let panel = Panel(), owner = panel.measurement
mode("blocked")
require(owner.start(.speed), "first measurement was rejected")
require(!owner.start(.hops), "overlapping request was admitted")
require(panel.actions.allSatisfy { !$0.isEnabled } && panel.cancelButton.isEnabled, "panel left competing controls enabled")
wait({ exists("blocked-started") }, "real throughput request did not start")
require(!panel.windowShouldClose(panel.window!), "close detached an active measurement")
require(owner.request != nil && owner.running, "cancel dropped its native request before completion")
wait({ !owner.running }, "cancelled transport did not retire")
wait({ exists("blocked-cancelled") }, "cancel did not close the real network request")
require(panel.window!.closes == 1 && panel.closeWanted, "pending close did not resume after completion")
require(panel.result.stringValue.contains("Controller cleanup may still be pending"), "cancellation overstated controller drain")
panel.windowWillClose(Notification(name: Notification.Name("closed")))
require(!owner.start(.speed), "closed panel was restarted")

let active = RouterVPNMacPerformanceMeasurement(baseURL: base)
var messages: [String] = []
active.changed = { messages.append($0) }
for kind: RouterVPNMacPerformanceMeasurement.Kind in [.hops, .node, .live, .speed] {
    mode("valid")
    require(active.start(kind), "valid measurement did not start")
    wait({ !active.running }, "valid measurement did not complete")
    require(messages.last!.contains("12345") && messages.last!.contains("67") && messages.last!.contains("kept per-hop error"), "actual bytes/time or hop errors were replaced")
}
mode("ordered")
require(active.start(.hops), "ordered measurement did not start")
wait({ !active.running }, "ordered measurement did not complete")
require(messages.last!.contains("middle-kept") && messages.last!.contains("Cumulative path through node 2 of 3"), "ordered intermediate row or cumulative label lost")
for invalid in ["ordered-missing", "ordered-count", "ordered-token"] {
    mode(invalid); require(active.start(.hops), "invalid ordered preflight did not start")
    wait({ !active.running }, "invalid ordered preflight did not complete")
    require(messages.last!.contains("no complete measurement capture"), "invalid ordered capture reached pair endpoint")
}
for invalid in ["disconnected", "numeric-connected", "same-hop", "missing-hop"] {
    mode(invalid)
    require(active.start(.hops), "invalid graph preflight did not start")
    wait({ !active.running }, "invalid graph preflight did not complete")
    require(messages.last!.contains("Connect an actual multihop graph"), "invalid graph became a throughput request")
}
mode("preflight")
require(active.start(.hops), "cancellable preflight did not start")
wait({ exists("preflight-started") }, "preflight never reached network")
active.cancel()
wait({ !active.running }, "preflight cancellation did not retire")
wait({ exists("preflight-cancelled") }, "preflight cancellation retained its network request")
let obsoleteGeneration = active.generation
mode("replacement")
require(active.start(.speed), "replacement measurement was rejected")
wait({ exists("replacement-started") }, "replacement request did not start")
let count = messages.count
// Replay an obsolete terminal delivery while newer real network work is live.
active.finish(.success(Data("stale".utf8)), owner: obsoleteGeneration)
require(active.running && active.request != nil && messages.count == count, "stale completion retired or mutated replacement")
active.close()
let closedCount = messages.count
wait({ !active.running }, "forced close did not retire owned request")
wait({ exists("replacement-cancelled") }, "forced close did not cancel real network request")
require(messages.count == closedCount, "closed owner published a late result")

let invalid: [(String, [String: Any]?, Double)] = [
    ("/api/disconnect", nil, 5), ("/api/profiles", [:], 5), ("/api/multihop/status", nil, 6),
    ("/api/connection/live-latency", ["samples": 50], 12),
    ("/api/connection/speed-test", ["bytes": 1], 45),
    ("/api/profile/latency", ["id": "node", "samples": true], 180),
    ("/api/profile/latency", ["id": "", "samples": 50], 180),
    ("/api/multihop/speed-test", ["entry_id": "same", "exit_id": "same", "bytes": 4194304], 70),
    ("/api/multihop/speed-test", ["entry_id": "in", "exit_id": "out", "bytes": 4194304, "mutate": true], 70),
    ("/api/multihop/speed-test", ["entry_id": "in", "exit_id": "out", "bytes": 8388608, "ordered_capture": "bad"], 100),
    ("/api/multihop/speed-test", ["entry_id": "in", "exit_id": "out", "bytes": 4194304, "ordered_capture": String(repeating: "a", count: 64)], 100),
    ("/api/multihop/speed-test", ["entry_id": "in", "exit_id": "out", "bytes": 8388608, "ordered_capture": String(repeating: "a", count: 64)], 101),
    ("/api/connection/speed-test", ["bytes": 8388608], Double.infinity)
]
for (path, body, timeout) in invalid {
    do {
        _ = try RouterVPNMacSpeedLabTransport(url: base.appendingPathComponent(path), body: body, timeout: timeout) { _ in }
        fail("invalid Performance transport request was accepted: " + path)
    } catch { }
}
print("Shipping macOS Performance: real cancellation, panel close, preflight, 50 samples, active hops, stale completion and bounded requests PASS")
'''.replace('DELEGATES', delegates)
    (fixture / 'main.swift').write_text(main)
    try:
        subprocess.run(['swiftc', '-swift-version', '5', '-module-cache-path', str(directory / 'module-cache'), str(ROOT / 'client/macos/RouterVPNMacControllerAuth.swift'), str(ROOT / 'client/macos/RouterVPNMacSpeedLabTransport.swift'), str(fixture / 'Owner.swift'), str(fixture / 'main.swift'), '-o', str(fixture / 'performance-test')], check=True, timeout=120)
        result = subprocess.run([str(fixture / 'performance-test'), 'http://127.0.0.1:' + str(server.server_address[1]), str(fixture)], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=25)
        if mutation == 'shipping':
            print(result.stdout, end='')
            assert result.returncode == 0, result.stdout + repr(hits) + repr(errors)
            assert not errors, errors
            hops = [body for _, path, body in hits if path == '/api/multihop/speed-test']
            assert hops == [{'entry_id': 'active-entry', 'exit_id': 'active-exit', 'bytes': 4194304}, {'entry_id': 'active-entry', 'exit_id': 'active-exit', 'bytes': 8388608, 'ordered_capture': 'a' * 64}], hops
            nodes = [body for _, path, body in hits if path == '/api/profile/latency']
            assert nodes == [{'id': 'selected-node', 'samples': 50}], nodes
            assert len([1 for mode, path, _ in hits if mode == 'preflight' and path != '/api/multihop/status']) == 0, hits
            assert len([1 for mode, _, _ in hits if mode == 'blocked']) == 1, hits
        else:
            expected = {'missing-cancel': 'cancelled transport did not retire', 'missing-generation': 'stale completion retired or mutated replacement', 'missing-closed': 'closed owner published a late result'}[mutation]
            assert result.returncode != 0 and expected in result.stdout, mutation + ': ' + result.stdout
            print('Negative Performance control ' + mutation + ': rejected', flush=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shipping-only', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='router-vpn-macos-performance-') as temporary:
        for mutation in (['shipping'] if args.shipping_only else ['shipping', 'missing-cancel', 'missing-generation', 'missing-closed']):
            run_case(Path(temporary), mutation)


if __name__ == '__main__':
    main()
