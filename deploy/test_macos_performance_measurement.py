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


EXTENDED_THROUGHPUT_SCENARIOS = (
    'extended-external-3', 'extended-external-9', 'extended-external-lost',
    'extended-external-label', 'extended-private-local', 'extended-private-server',
    'extended-private-second-private', 'extended-private-lost', 'extended-private-swapped',
    'extended-private-label', 'extended-roles-9', 'extended-roles-16',
    'extended-roles-96', 'extended-roles-swapped', 'extended-roles-lost',
    'extended-roles-label', 'extended-mixed-9', 'extended-mixed-16',
    'extended-mixed-foreign', 'extended-mixed-label', 'extended-mixed-lost',
    'extended-paired', 'extended-paired-marker', 'extended-paired-label',
    'extended-9', 'extended-16', 'extended-reordered',
    'extended-foreign', 'extended-short', 'extended-borrowed',
    'extended-selected-local', 'extended-selected-server', 'extended-selected-generation',
    'extended-selected-winner',
)


def extended_throughput_fixture(count, winner=None, paired=False, packets=0, *, roles=None):
    ids = ['active-entry', *[f'public-{i}' for i in range(1, count-1)], 'active-exit']
    source = {'source_sha256': 'b'*64, 'config_sha256': 'c'*64, 'node_ids': ids}
    if roles is not None:
        assert not (paired or packets) and len(roles) == count
        source['selected_roles_json' if winner else 'local_roles_json'] = json.dumps(roles, separators=(',', ':'))
    if paired: source['paired_wireguard'] = True
    if packets: source['paired_prefix_nodes'] = packets
    common = dict(connected=True, entry_id=ids[0], exit_id=ids[-1], ordered_capture='a'*64,
                  ordered_nodes=count, ordered_local_source=source)
    if winner:
        common.pop('ordered_local_source')
        common['ordered_original_source'] = dict(source, generation_sha256='f'*64, selected_execution=winner)
        common['execution'] = winner
    rows = []
    for i, member in enumerate(ids):
        interior = 0 < i < count-1
        public = roles[i] == 'public-path' if roles is not None else interior and not paired and i >= packets
        prefix = 'Cumulative ' + (winner+' ' if winner else '') + f'path through node {i+1} of {count}' + (' to the public benchmark' if public else '')
        rows.append(dict(router_id=member, role='intermediate' if interior else 'entry' if i == 0 else 'exit',
                         speed_label=prefix+' transfer', latency_label=prefix+' HTTP response',
                         speed=dict(router_id=member, bytes=8388608), latency=dict(router_id=member)))
    return dict(common, execution=winner or 'local'), dict(common, mode='multihop', bytes=8388608, hops=rows)


def external_final_throughput(count, fault=''):
    original, result = extended_throughput_fixture(count)
    exit_id = original['exit_id']
    original['ordered_local_source']['external_final_node_id'] = exit_id
    result['ordered_local_source'] = dict(original['ordered_local_source'])
    result['execution'] = 'local'
    last = result['hops'][-1]
    for key in ('latency_label', 'speed_label'):
        last[key] = last[key].replace(f'of {count}', f'of {count} to the public benchmark')
    if fault == 'foreign':
        original['ordered_local_source']['external_final_node_id'] = original['entry_id']
    if fault == 'mixed':
        original['ordered_local_source']['paired_wireguard'] = True
    if fault == 'server':
        original['execution'] = 'server'
    if fault == 'lost':
        result['ordered_local_source'].pop('external_final_node_id')
    if fault == 'label':
        last['latency_label'] = last['latency_label'].replace(' to the public benchmark', '')
    return original, result


def selected_private_throughput(count, winner, fault=''):
    roles = ['private-node' if i in (0, count-2, count-1) else 'public-path' for i in range(count)]
    if fault == 'second-private':
        roles[2] = 'private-node'
    original, result = extended_throughput_fixture(count, winner, roles=roles)
    key = 'ordered_original_source'
    result[key] = dict(result[key])
    if fault == 'first-private':
        roles[1], roles[-2] = roles[-2], roles[1]
    if fault == 'first-private':
        original[key]['selected_roles_json'] = json.dumps(roles, separators=(',', ':'))
    if fault == 'local-marker':
        original[key]['local_roles_json'] = original[key].pop('selected_roles_json')
    if fault == 'lost':
        del result[key]['selected_roles_json']
    if fault == 'swapped':
        roles[2],roles[-2] = roles[-2],roles[2]
        result[key]['selected_roles_json'] = json.dumps(roles, separators=(',', ':'))
    if fault == 'label':
        result['hops'][-2]['speed_label'] = result['hops'][-2]['speed_label'].replace(' transfer', ' to the public benchmark transfer')
    return original, result


def native_throughput_pairs(directory):
    if directory is None:
        return {}
    return {count: tuple((directory/f'{count}-{kind}.json').read_bytes() for kind in ('get','post'))
            for count in (9,16)}


def run_case(directory, mutation, native_originals=None):
    fixture = directory / mutation
    fixture.mkdir()
    hits, errors = [], []
    native = native_throughput_pairs(native_originals)
    for count, (_, response) in native.items():
        (fixture/f'{count}-native.json').write_bytes(response)

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
                if mode.startswith('extended-'):
                    count = 96 if mode == 'extended-roles-96' else 16 if mode in ('extended-16','extended-mixed-16','extended-selected-server','extended-roles-16') else 9
                    winner = ('local' if mode == 'extended-selected-local' else 'server') if mode.startswith('extended-selected-') else None
                    roles = None
                    if mode.startswith('extended-roles-'):
                        roles = ['public-path' if 0 < i < count-1 and i % 4 >= 2 else 'private-node' for i in range(count)]
                    original, measured = extended_throughput_fixture(count, winner, paired=mode.startswith('extended-paired'), packets=3 if mode.startswith('extended-mixed') else 0, roles=roles)
                    if mode.startswith('extended-external-'):
                        fault = mode.removeprefix('extended-external-')
                        original, measured = external_final_throughput(int(fault) if fault.isdecimal() else 9, fault)
                    if mode.startswith('extended-private-'):
                        case = mode.removeprefix('extended-private-')
                        original, measured = selected_private_throughput(16, 'local' if case == 'local' else 'server',
                                                                        '' if case in ('local','server') else case)
                    if mode == 'extended-roles-swapped':
                        roles[3],roles[4] = roles[4],roles[3]
                        measured['ordered_local_source'] = dict(measured['ordered_local_source'],local_roles_json=json.dumps(roles,separators=(',', ':')))
                    if mode == 'extended-roles-lost':
                        measured['ordered_local_source'] = {k:v for k,v in measured['ordered_local_source'].items() if k != 'local_roles_json'}
                    if mode == 'extended-roles-label':
                        measured['hops'][4]['latency_label'] = 'Cumulative path through node 5 of 9 to the public benchmark HTTP response'
                    if mode == 'extended-roles-both': original['ordered_local_source']['paired_prefix_nodes'] = 2
                    if mode == 'extended-roles-only-public':
                        unqualified = ['private-node', *['public-path']*(count-2), 'private-node']
                        original['ordered_local_source']['local_roles_json'] = json.dumps(unqualified, separators=(',', ':'))
                    if mode == 'extended-roles-space': original['ordered_local_source']['local_roles_json'] = json.dumps(roles)
                    if mode == 'extended-roles-array': original['ordered_local_source']['local_roles_json'] = roles
                    if mode == 'extended-mixed-foreign': measured['ordered_local_source'] = dict(measured['ordered_local_source'],paired_prefix_nodes=2)
                    if mode == 'extended-mixed-lost': measured['ordered_local_source'] = {k:v for k,v in measured['ordered_local_source'].items() if k != 'paired_prefix_nodes'}
                    if mode == 'extended-mixed-label': measured['hops'][3]['speed_label'] = 'Cumulative path through node 4 of 9 transfer'
                    if mode == 'extended-mixed-bool': original['ordered_local_source']['paired_prefix_nodes'] = True
                    if mode == 'extended-mixed-over': original['ordered_local_source']['paired_prefix_nodes'] = count-1
                    if mode == 'extended-mixed-both': original['ordered_local_source']['paired_wireguard'] = True
                    if mode == 'extended-selected-mixed': original['ordered_original_source']['paired_prefix_nodes'] = 3
                    if mode == 'extended-paired-marker': measured['ordered_local_source'] = {k:v for k,v in measured['ordered_local_source'].items() if k != 'paired_wireguard'}
                    if mode == 'extended-paired-label': measured['hops'][2]['speed_label'] = 'Cumulative path through node 3 of 9 to the public benchmark transfer'
                    if mode == 'extended-paired-numeric': original['ordered_local_source']['paired_wireguard'] = 1
                    if mode == 'extended-paired-false': original['ordered_local_source']['paired_wireguard'] = False
                    if mode == 'extended-selected-paired': original['ordered_original_source']['paired_wireguard'] = True
                    if mode == 'extended-selected-generation':
                        measured['ordered_original_source'] = dict(measured['ordered_original_source'], generation_sha256='e'*64)
                    if mode == 'extended-selected-winner':
                        measured['execution'] = 'local'
                    if mode == 'extended-selected-both':
                        original['ordered_local_source'] = dict(original['ordered_original_source'])
                    if mode == 'extended-borrowed':
                        original = dict(original, ordered_nodes=3); del original['ordered_local_source']
                    if mode == 'extended-server': original['execution'] = 'server'
                    if mode == 'extended-duplicate': original['ordered_local_source']['node_ids'][2] = 'public-1'
                    if mode == 'extended-missing': del original['ordered_local_source']
                    if mode == 'extended-reordered': measured['hops'][2], measured['hops'][3] = measured['hops'][3], measured['hops'][2]
                    if mode == 'extended-foreign': measured['ordered_local_source'] = dict(measured['ordered_local_source'], config_sha256='d'*64)
                    if mode == 'extended-short': measured['hops'].pop()
                    value = original if self.path == '/api/multihop/status' else measured
                raw = json.dumps(value).encode()
                if mode.startswith('native-'):
                    original, response = native[int(mode.split('-')[1])]
                    raw = original if self.path == '/api/multihop/status' else response
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
    if mutation in ('wrong-private-label', 'wrong-local-private-label'):
        original = 'localRoles.map { $0[i] == "public-path" } ?? (interior && !pairedWireGuard && i >= (pairedPrefixNodes ?? 1))'
        assert owner.count(original) == 1
        fallback = 'interior && !pairedWireGuard && i >= (pairedPrefixNodes ?? 1)'
        replacement = fallback if mutation == 'wrong-private-label' else f'selected == nil ? ({fallback}) : ({original})'
        owner = owner.replace(original, replacement)
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
for scenario in EXTENDED_THROUGHPUT_SCENARIOS {
    mode(scenario); require(active.start(.hops), "extended Local preflight did not start")
    wait({ !active.running }, "extended Local response did not complete")
    if ["extended-external-3","extended-external-9"].contains(scenario) {
        let n = scenario.split(separator:"-").last!
        require(messages.last!.contains("Cumulative path through node "+n+" of "+n+" to the public benchmark transfer"), "public exit throughput substituted the private final label")
    } else if ["extended-roles-9","extended-roles-16","extended-roles-96"].contains(scenario) {
        let count = scenario.split(separator:"-").last!
        require(messages.last!.contains("Cumulative path through node 4 of "+count+" to the public benchmark transfer") && messages.last!.contains("Cumulative path through node 5 of "+count+" transfer") && messages.last!.contains("Cumulative path through node "+count+" of "+count+" HTTP response"), "private stream positions lost their original measurements")
    } else if scenario == "extended-paired" {
        require(messages.last!.contains("Cumulative path through node 3 of 9 transfer") && !messages.last!.contains("to the public benchmark"), "private paired throughput acquired public labels")
    } else if ["extended-mixed-9","extended-mixed-16"].contains(scenario) {
        let count = scenario.hasSuffix("16") ? "16" : "9"
        require(messages.last!.contains("Cumulative path through node 3 of "+count+" transfer") && messages.last!.contains("Cumulative path through node 4 of "+count+" to the public benchmark transfer"), "mixed throughput lost original public/private boundary")
    } else if ["extended-private-local","extended-private-server","extended-private-second-private"].contains(scenario) {
        let winner = scenario.hasSuffix("local") ? "local" : "server"
        require(messages.last!.contains("Cumulative " + winner + " path through node 15 of 16 transfer") &&
                messages.last!.contains("to the public benchmark transfer"), "the selected original private transfer was mislabeled")
    } else if ["extended-9", "extended-16", "extended-selected-local", "extended-selected-server"].contains(scenario) {
        require(messages.last!.contains("public-" + (["extended-9", "extended-selected-local"].contains(scenario) ? "7" : "14")) && messages.last!.contains("to the public benchmark transfer"), "extended throughput lost original rows")
    } else { require(messages.last!.contains("another ordered route"), "foreign extended throughput result displayed") }
}
for count in [9,16] where exists("\(count)-native.json") {
    mode("native-\(count)"); require(active.start(.hops), "native POST not started")
    wait({ !active.running }, "native POST did not finish")
    let original = try! Data(contentsOf: fixture.appendingPathComponent("\(count)-native.json"))
    require(messages.last == String(data:original, encoding:.utf8), "native source or actual throughput rows were lost")
    print("Swift displayed all \(count) exact native throughput rows")
}
for invalid in ["extended-external-foreign","extended-external-mixed","extended-external-server","extended-private-first-private","extended-private-local-marker","extended-roles-only-public","extended-roles-both","extended-roles-space","extended-roles-array","extended-mixed-bool","extended-mixed-over","extended-mixed-both","extended-selected-mixed","extended-paired-numeric", "extended-paired-false", "extended-selected-paired", "ordered-missing", "ordered-count", "ordered-token", "extended-server", "extended-duplicate", "extended-missing", "extended-selected-both"] {
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
'''.replace('DELEGATES', delegates).replace('EXTENDED_THROUGHPUT_SCENARIOS', json.dumps(EXTENDED_THROUGHPUT_SCENARIOS))
    (fixture / 'main.swift').write_text(main)
    try:
        subprocess.run(['swiftc', '-swift-version', '5', '-module-cache-path', str(directory / 'module-cache'), str(ROOT / 'client/macos/RouterVPNMacControllerAuth.swift'), str(ROOT / 'client/macos/RouterVPNMacSpeedLabTransport.swift'), str(fixture / 'Owner.swift'), str(fixture / 'main.swift'), '-o', str(fixture / 'performance-test')], check=True, timeout=120)
        result = subprocess.run([str(fixture / 'performance-test'), 'http://127.0.0.1:' + str(server.server_address[1]), str(fixture)], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=25)
        if mutation == 'shipping':
            print(result.stdout, end='')
            assert result.returncode == 0, result.stdout + repr(hits) + repr(errors)
            assert not errors, errors
            records = [(mode, body) for mode, path, body in hits if path == '/api/multihop/speed-test']
            assert [mode for mode, _ in records] == ['valid', 'ordered', *EXTENDED_THROUGHPUT_SCENARIOS, *[f'native-{n}' for n in native]], records
            hops = [body for _, body in records]
            expected = [{'entry_id': 'active-entry', 'exit_id': 'active-exit', 'bytes': 4194304}] + [
                {'entry_id': 'active-entry', 'exit_id': 'active-exit', 'bytes': 8388608, 'ordered_capture': 'a'*64}]*(1+len(EXTENDED_THROUGHPUT_SCENARIOS))
            for original, _ in native.values():
                preflight = json.loads(original)
                expected.append({key: preflight[key] for key in ('entry_id','exit_id','ordered_capture')} | {'bytes':8388608})
            assert hops == expected, hops
            nodes = [body for _, path, body in hits if path == '/api/profile/latency']
            assert nodes == [{'id': 'selected-node', 'samples': 50}], nodes
            assert len([1 for mode, path, _ in hits if mode == 'preflight' and path != '/api/multihop/status']) == 0, hits
            assert len([1 for mode, _, _ in hits if mode == 'blocked']) == 1, hits
        else:
            expected = {
                'missing-cancel': 'cancelled transport did not retire',
                'missing-generation': 'stale completion retired or mutated replacement',
                'missing-closed': 'closed owner published a late result',
                'wrong-private-label': 'the selected original private transfer was mislabeled',
                'wrong-local-private-label': 'private stream positions lost their original measurements',
            }[mutation]
            assert result.returncode != 0 and expected in result.stdout, mutation + ': ' + result.stdout
            if mutation in ('wrong-private-label', 'wrong-local-private-label'):
                scenario = 'extended-private-local' if mutation == 'wrong-private-label' else 'extended-roles-9'
                assert hits[-1][:2] == (scenario, '/api/multihop/speed-test'), hits
            print('Negative Performance control ' + mutation + ': rejected', flush=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shipping-only', action='store_true')
    parser.add_argument('--native-originals',type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='router-vpn-macos-performance-') as temporary:
        for mutation in (['shipping'] if args.shipping_only else ['shipping', 'missing-cancel', 'missing-generation', 'missing-closed', 'wrong-private-label', 'wrong-local-private-label']):
            run_case(Path(temporary), mutation, args.native_originals)


if __name__ == '__main__':
    main()
