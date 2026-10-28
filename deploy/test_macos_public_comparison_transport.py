#!/usr/bin/env python3
"""Exercise the shipping public Connect transport with actual Foundation HTTP.

The test observes the configuration of the native session that actually creates
each task. It does not wait nine minutes or simulate Foundation's timers. Real
loopback requests check dispatch, redirect rejection and per-request cleanup.
"""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import json
import re
import subprocess
import tempfile
import threading

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

        def do_GET(self):
            hits.append(('GET', self.path, None))
            raw = b'{"ok":true}'
            self.send_response(200)
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            try:
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                hits.append(('POST', self.path, body))
                if body.get('test_case') == 'redirect':
                    self.send_response(302)
                    self.send_header('Location', '/must-not-follow')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                raw = json.dumps({'ok': True, 'captured': body}).encode()
                self.send_response(200)
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
    source = (ROOT / 'client/macos/RouterVPNMacProduct.swift').read_text()
    api = block(source, 'final class ProductAPI {')
    delegate = (block(source, 'private final class ProductComparisonTransportDelegate:')
                if 'private final class ProductComparisonTransportDelegate:' in source else '')
    if mutation == 'shared-session':
        old = 'let activeSession = comparisonSession ?? session'
        assert api.count(old) == 1
        api = api.replace(old, 'let activeSession = session')
    elif mutation == 'missing-close':
        old = 'defer { comparisonSession?.invalidateAndCancel() }'
        assert api.count(old) == 1
        api = api.replace(old, '/* mutation: dedicated native session never invalidated */')
    elif mutation == 'redirect':
        old = 'completionHandler(nil)'
        assert delegate.count(old) == 1
        delegate = delegate.replace(old, 'completionHandler(request)')
    if delegate:
        # Observe the real framework invalidation event. The test retains its
        # observed session so Linux deallocation cannot stand in for explicit
        # cleanup of Darwin's delegate-retaining session.
        delegate = delegate[:-1] + '''
    func urlSession(_ session: URLSession, didBecomeInvalidWithError error: Error?) { observeInvalidated(session) }
}'''
    # This single observation runs after the shipping dataTask factory. No
    # session-selection, request-building or completion branches are copied.
    creation = re.search(r'^        let task = ([A-Za-z]+)\.dataTask\(with: req\).*$', api, re.MULTILINE)
    assert creation is not None
    api = api.replace(creation.group(0), creation.group(0) + '\n        observeTask(' + creation.group(1) + ', task)')
    program = r'''
import Foundation
import CoreFoundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
let routerVPNProductBaseURL=URL(string:CommandLine.arguments[1])!
DELEGATE_SOURCE
API_SOURCE
final class Observation {
 let session:URLSession;weak var task:URLSessionDataTask?
 let resource:TimeInterval,request:TimeInterval;let method:String?,url:URL?,body:Data?
 init(_ session:URLSession,_ task:URLSessionDataTask){self.session=session;self.task=task;resource=session.configuration.timeoutIntervalForResource;request=task.originalRequest?.timeoutInterval ?? -1;method=task.originalRequest?.httpMethod;url=task.originalRequest?.url;body=task.originalRequest?.httpBody}
}
var observations:[Observation]=[]
let invalidatedLock=NSLock();var invalidated:Set<ObjectIdentifier>=[]
func observeInvalidated(_ session:URLSession){invalidatedLock.lock();invalidated.insert(ObjectIdentifier(session));invalidatedLock.unlock()}
func wasInvalidated(_ observation:Observation)->Bool{invalidatedLock.lock();defer{invalidatedLock.unlock()};return invalidated.contains(ObjectIdentifier(observation.session))}
func observeTask(_ session:URLSession,_ task:URLSessionDataTask){observations.append(Observation(session,task))}
func fail(_ message:String)->Never{fputs(message+"\n",stderr);exit(1)}
func check(_ condition:Bool,_ message:String){if !condition{fail(message)}}
func wait(_ predicate:()->Bool,_ text:String){let until=Date().addingTimeInterval(4);while !predicate()&&Date()<until{_ = RunLoop.current.run(mode:.default,before:Date().addingTimeInterval(0.005))};check(predicate(),text)}
let api=ProductAPI(),endpoint="/api/external-profile/connect"
let id=String(repeating:"a",count:32),token=String(repeating:"b",count:64)
let captured:[String:Any]=["profile_id":id,"entry_id":"entry","execution":"auto","direct":false,"comparison_request_id":String(repeating:"c",count:32),"expected_selected_node_id":"entry","expected_profile_tokens":[id:token,"entry":token]]
let data=try api.request(endpoint,method:"POST",body:captured,timeout:540)
check(data.count>0&&observations.count==1,"Captured public connection did not use the native transport")
let connected=observations[0]
check(connected.resource==540&&connected.request==540,"Captured Tor comparison still uses the five-minute session ceiling")
check(connected.method=="POST"&&connected.url==routerVPNProductBaseURL.appendingPathComponent("api/external-profile/connect"),"Captured connection changed its endpoint")
let encoded=try JSONSerialization.jsonObject(with:connected.body!) as! NSDictionary
check(encoded.isEqual(to:captured),"Captured connection changed its source body")
wait({wasInvalidated(connected)},"Completed comparison retained its dedicated session")
_ = try api.request("/api/status",timeout:1)
check(observations.last!.resource==300&&observations.last!.request==1,"Ordinary request inherited the extended comparison budget")
var redirected=captured;redirected["test_case"]="redirect"
do{_ = try api.request(endpoint,method:"POST",body:redirected,timeout:540);fail("Captured comparison followed a redirect")}catch{}
let redirect=observations.last!
wait({wasInvalidated(redirect)},"Rejected comparison retained its dedicated session")
_ = try api.request(endpoint,method:"POST",body:captured,timeout:540)
let next=observations.last!
check(next.resource==540,"An old comparison invalidated its replacement")
wait({wasInvalidated(next)},"Replacement comparison retained its session")
let before=observations.count
var malformed:[[String:Any]]=[]
for key in ["profile_id","execution","comparison_request_id","expected_selected_node_id","expected_profile_tokens"]{var body=captured;body.removeValue(forKey:key);malformed.append(body)}
for nonce in ["",String(repeating:"C",count:32),"short"]{var body=captured;body["comparison_request_id"]=nonce;malformed.append(body)}
for value in [true,1,"false"] as [Any]{var body=captured;body["direct"]=value;malformed.append(body)}
for execution in ["local","server"]{var body=captured;body["execution"]=execution;malformed.append(body)}
for body in malformed{do{_ = try api.request(endpoint,method:"POST",body:body,timeout:540);fail("Malformed comparison gained an extended native session")}catch{}}
for timeout in [301.0,541.0,Double.infinity,Double.nan]{do{_ = try api.request(endpoint,method:"POST",body:captured,timeout:timeout);fail("Unbounded comparison deadline was accepted")}catch{}}
for path in ["/api/disconnect",endpoint+"?other=1",endpoint+"#other", "http://example.invalid"+endpoint]{do{_ = try api.request(path,method:"POST",body:captured,timeout:540);fail("Foreign extended comparison endpoint was accepted")}catch{}}
do{_ = try api.request(endpoint,method:"GET",body:captured,timeout:540);fail("Wrong comparison method was accepted")}catch{}
check(observations.count==before,"Invalid extended request launched native HTTP")
_ = try api.request("/api/status",timeout:1)
check(observations.last!.resource==300,"Dedicated session cleanup broke the shared ordinary transport")
print("Public macOS Tor comparison: actual540s session, ordinary300s ceiling, captured body, redirects and ownership PASS")
'''.replace('DELEGATE_SOURCE', delegate).replace('API_SOURCE', api)
    main = fixture / 'main.swift'
    main.write_text(program)
    try:
        subprocess.run(['swiftc', '-swift-version', '5', '-module-cache-path', str(directory / 'module-cache'),
                        str(main), '-o', str(fixture / 'transport-test')], check=True, timeout=120)
        result = subprocess.run([str(fixture / 'transport-test'), 'http://127.0.0.1:' + str(server.server_address[1])],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
        if mutation == 'shipping':
            print(result.stdout, end='')
            assert result.returncode == 0, result.stdout
            assert not errors, errors
            assert not any(path == '/must-not-follow' for _, path, _ in hits), hits
        else:
            expected = {'shared-session': 'five-minute session ceiling',
                        'missing-close': 'Completed comparison retained',
                        'redirect': 'Captured comparison followed a redirect'}[mutation]
            assert result.returncode != 0 and expected in result.stdout, mutation + ': ' + result.stdout
            print('Public comparison transport control ' + mutation + ': rejected', flush=True)
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shipping-only', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='routervpn-macos-public-comparison-') as temporary:
        for mutation in (['shipping'] if args.shipping_only else ['shipping', 'shared-session', 'missing-close', 'redirect']):
            run_case(Path(temporary), mutation)


if __name__ == '__main__':
    main()
