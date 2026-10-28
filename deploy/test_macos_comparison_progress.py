#!/usr/bin/env python3
"""Run the shipping AppKit comparison observer with real bounded loopback HTTP.

The window/label surfaces are small headless substitutes. The URLSession,
redirect delegate, source-correlated observer and owner cleanup are extracted
from the shipping source, including executable negative controls. The existing
32KiB check is a completed-body bound; this test does not claim streaming caps.
"""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import json
import os
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
    hits = []
    errors = []

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
            try:
                hits.append(self.path)
                if self.path != '/api/multihop/status':
                    self.send_response(500)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                case = json.loads((fixture / 'phase').read_text())
                mode = case['mode']
                value = {'execution': 'local', 'comparison': {
                    'id': 'opaque-server-progress', 'request_id': case['request_id'],
                    'stage': mode, 'complete': case.get('complete', False),
                    'last_node_measurement': 'tor-last-relay-http',
                    'external_measurement': 'same-captured-endpoint-http',
                    'measurements': [{'candidate': {'execution': 'local', 'transport': 'tor'},
                                      'eligible': True, 'last_node_ms': 20, 'external_ms': 40, 'score_ms': 30}]}}
                if mode == 'wrong-request':
                    value['comparison']['request_id'] = 'f' * 32
                elif mode == 'missing-request':
                    value['comparison'].pop('request_id')
                elif mode == 'wrong-last':
                    value['comparison']['last_node_measurement'] = 'icmp'
                elif mode == 'wrong-external':
                    value['comparison']['external_measurement'] = 'other-target-http'
                if mode == 'redirect':
                    self.send_response(302)
                    self.send_header('Location', '/must-not-follow')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    (fixture / ('served-' + mode)).write_text('ready')
                    return
                raw = json.dumps(value).encode()
                if mode == 'oversized':
                    raw = b' ' * 32769 + raw
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                if mode in ('old-held', 'replacement-held', 'closed-held'):
                    self.wfile.write(raw[:1]); self.wfile.flush()
                    (fixture / ('started-' + mode)).write_text('ready')
                    until = time.monotonic() + 5
                    while time.monotonic() < until:
                        if (fixture / ('release-' + mode)).exists():
                            self.wfile.write(raw[1:]); self.wfile.flush()
                            (fixture / ('served-' + mode)).write_text('ready')
                            return
                        readable, _, _ = select.select([self.connection], [], [], .01)
                        if readable and self.connection.recv(1, socket.MSG_PEEK) == b'':
                            (fixture / ('cancelled-' + mode)).write_text('closed')
                            return
                    errors.append(mode + ' did not drain before its deadline')
                    self.close_connection = True
                    return
                self.wfile.write(raw); self.wfile.flush()
                (fixture / ('served-' + mode)).write_text('ready')
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as error:
                errors.append(str(error))

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    source = (ROOT / 'client/macos/RouterVPNMacProduct.swift').read_text()
    assert 'let routerVPNProductBaseURL = URL(string: "http://127.0.0.1:8788")!' in source
    delegate = block(source, 'private final class MultihopProgressTransportDelegate:')
    markers = ['    func stopMultihopProgress(', '    func startMultihopProgress(',
               '    func startCapturedComparisonProgress(', '    func stopCapturedComparisonProgress(',
               '    private func beginMultihopProgress(', '    func pollMultihopProgress(',
               '    func multihopComparisonSummary(']
    methods = '\n'.join(block(source, marker) for marker in markers).replace('private func ', 'func ')
    mutations = {
        'missing-request': ('guard comparison["request_id"] as? String == requestID,', 'guard !requestID.isEmpty,'),
        'missing-generation': ('guard let self, self.multihopProgressGeneration == generation else { return }', 'guard let self else { return }'),
        'unowned-stop': ('guard let owner, multihopProgressGeneration == owner else { return }', 'guard owner != nil else { return }'),
    }
    if mutation in mutations:
        old, new = mutations[mutation]
        assert methods.count(old) == 1, mutation
        methods = methods.replace(old, new)
    # Arrival evidence observes the real queued completion immediately before
    # its unchanged owner guard. It replaces a timing assumption in the stale
    # completion regression; none of the production branches are copied.
    arrival = '            DispatchQueue.main.async {\n'
    assert methods.count(arrival) == 1
    methods = methods.replace(arrival, arrival + '                _ = self?.deliveredCallbacks.insert(generation)\n')
    program = r'''
import Foundation
import CoreFoundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
let routerVPNProductBaseURL=URL(string:CommandLine.arguments[1])!
let fixture=URL(fileURLWithPath:CommandLine.arguments[2],isDirectory:true)
DELEGATE
final class Window { var isVisible=true }
final class Label { var stringValue="" }
final class Product {
 var window:Window?=Window();let multihopComparisonLabel=Label()
 var multihopProgressTimer:Timer?;var multihopProgressTask:URLSessionDataTask?;var multihopProgressSession:URLSession?
 var multihopProgressGeneration=UUID();var multihopProgressDeadline=Date.distantPast
 var multihopProgressLastID="",multihopProgressOldID=""
 var multihopProgressExpectedID:String?;var multihopProgressUpdate:(([String:Any],String)->Void)?
 var deliveredCallbacks:Set<UUID>=[]
 METHODS
}
func fail(_ text:String)->Never{fputs(text+"\n",stderr);exit(1)}
func check(_ value:Bool,_ text:String){if !value{fail(text)}}
func wait(_ predicate:()->Bool,_ text:String){let until=Date().addingTimeInterval(4);while !predicate()&&Date()<until{_ = RunLoop.current.run(mode:.default,before:Date().addingTimeInterval(0.005))};check(predicate(),text)}
func pump(_ seconds:TimeInterval){let until=Date().addingTimeInterval(seconds);while Date()<until{_ = RunLoop.current.run(mode:.default,before:Date().addingTimeInterval(0.005))}}
func exists(_ name:String)->Bool{FileManager.default.fileExists(atPath:fixture.appendingPathComponent(name).path)}
func flag(_ name:String){try! Data("ready".utf8).write(to:fixture.appendingPathComponent(name),options:.atomic)}
func phase(_ mode:String,_ requestID:String,_ complete:Bool=false){try! JSONSerialization.data(withJSONObject:["mode":mode,"request_id":requestID,"complete":complete]).write(to:fixture.appendingPathComponent("phase"),options:.atomic)}
let first=String(repeating:"a",count:32),second=String(repeating:"b",count:32)
let owner=Product();var callbacks=0;var latest=""
for id in ["",String(repeating:"A",count:32),"short"]{
 check(owner.startCapturedComparisonProgress(requestID:id,timeout:540)==nil&&owner.multihopProgressSession==nil,"Malformed request gained comparison progress authority")
}
for mode in ["wrong-request","missing-request","wrong-last","wrong-external","oversized","redirect"]{
 phase(mode,first)
 let capture=owner.startCapturedComparisonProgress(requestID:first,timeout:540){_,text in callbacks+=1;latest=text}
 check(capture != nil,"Valid request owner did not start")
 wait({exists("served-"+mode)&&owner.multihopProgressTask==nil},"Native status response did not complete: "+mode)
 check(callbacks==0&&owner.multihopComparisonLabel.stringValue.isEmpty,"Foreign or malformed progress reached the captured UI: "+mode)
 owner.stopCapturedComparisonProgress(capture)
}
phase("valid",first,true)
let firstOwner=owner.startCapturedComparisonProgress(requestID:first,timeout:540){_,text in callbacks+=1;latest=text}
wait({callbacks==1},"Exact native HTTP status did not reach observer")
check(latest.contains("last-relay HTTP")&&latest.contains("same external-server HTTP")&&latest.contains("30.0 ms") && !latest.lowercased().contains("icmp"),"Tor HTTP response measurements were mislabeled")
check(owner.multihopProgressTask==nil&&owner.multihopProgressSession==nil&&owner.multihopProgressUpdate==nil&&owner.multihopProgressExpectedID==nil,"Terminal observer retained callback or HTTP ownership")
owner.stopCapturedComparisonProgress(firstOwner)
phase("old-held",first)
let old=owner.startCapturedComparisonProgress(requestID:first,timeout:540){_,_ in callbacks+=100}
wait({exists("started-old-held")},"Old observer did not open its native HTTP request")
phase("replacement-held",second)
let replacement=owner.startCapturedComparisonProgress(requestID:second,timeout:960){_,text in callbacks+=1;latest=text}
guard let replacementTask=owner.multihopProgressTask else{fail("Replacement observer did not capture its native task")}
wait({exists("cancelled-old-held")&&exists("started-replacement-held")&&old.map{owner.deliveredCallbacks.contains($0)}==true},"Observer replacement did not cancel old native HTTP and drain its queued completion")
check(owner.multihopProgressTask === replacementTask&&owner.multihopProgressGeneration==replacement&&callbacks==1,"Late old completion changed the replacement task owner")
owner.stopCapturedComparisonProgress(old)
check(owner.multihopProgressTask === replacementTask&&owner.multihopProgressSession != nil,"Old captured stop cancelled replacement HTTP")
flag("release-replacement-held")
wait({callbacks==2},"Replacement observer could not complete after old IO drained")
owner.stopCapturedComparisonProgress(replacement)
phase("terminal",first,true)
var nestedOwner:UUID?
let terminal=owner.startCapturedComparisonProgress(requestID:first,timeout:540){_,_ in
 callbacks+=1;phase("nested",second);nestedOwner=owner.startCapturedComparisonProgress(requestID:second,timeout:960){_,_ in callbacks+=1}
}
wait({nestedOwner != nil&&callbacks>=4},"Old terminal cleanup cancelled a replacement callback owner")
check(owner.multihopProgressGeneration==nestedOwner&&owner.multihopProgressSession != nil,"Terminal callback cleanup lost the replacement observer")
owner.stopCapturedComparisonProgress(terminal)
check(owner.multihopProgressGeneration==nestedOwner&&owner.multihopProgressSession != nil,"Delayed old action finalizer stopped a newer observer")
owner.multihopProgressDeadline=Date().addingTimeInterval(-1);owner.pollMultihopProgress()
check(owner.multihopProgressSession==nil&&owner.multihopProgressUpdate==nil,"Expired observer retained callback authority")
phase("closed-held",second)
let closed=owner.startCapturedComparisonProgress(requestID:second,timeout:540){_,_ in callbacks+=1000}
wait({exists("started-closed-held")},"Close fixture did not enter native IO")
let before=callbacks;owner.window?.isVisible=false;owner.pollMultihopProgress()
wait({exists("cancelled-closed-held")},"Hidden/closed window left native progress IO active")
pump(0.1);check(callbacks==before&&owner.multihopProgressSession==nil&&owner.multihopProgressUpdate==nil,"Closed window revived its comparison callback")
owner.stopCapturedComparisonProgress(closed)
print("Actual Swift comparison HTTP nonce, generation, redirect, bounds, replacement and close: PASS")
'''.replace('DELEGATE', delegate).replace('METHODS', methods)
    main = fixture / 'main.swift'
    main.write_text(program)
    try:
        subprocess.run(['swiftc', '-swift-version', '5', '-module-cache-path', str(directory / 'module-cache'),
                        str(main), '-o', str(fixture / 'progress-test')], check=True, timeout=120)
        result = subprocess.run([str(fixture / 'progress-test'), 'http://127.0.0.1:' + str(server.server_address[1]), str(fixture)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=35)
        if mutation == 'shipping':
            print(result.stdout, end='')
            assert result.returncode == 0, result.stdout + '\nHTTP errors: ' + repr(errors)
            assert not errors, errors
            assert '/must-not-follow' not in hits, 'Native comparison observer followed a redirect'
        else:
            expected = {'missing-request': 'Foreign or malformed progress reached',
                        'missing-generation': 'Late old completion changed',
                        'unowned-stop': 'Old captured stop cancelled replacement HTTP'}[mutation]
            assert result.returncode != 0 and expected in result.stdout, mutation + ': ' + result.stdout
            print('Actual comparison control ' + mutation + ': rejected at its ownership assertion', flush=True)
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shipping-only', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='routervpn-macos-comparison-progress-') as temporary:
        directory = Path(temporary)
        for mutation in (['shipping'] if args.shipping_only else ['shipping', 'missing-request', 'missing-generation', 'unowned-stop']):
            run_case(directory, mutation)
    print('macOS exact captured comparison progress: PASS', flush=True)


if __name__ == '__main__':
    main()
