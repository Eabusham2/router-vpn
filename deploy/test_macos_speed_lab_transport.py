#!/usr/bin/env python3
"""Exercise the shipping Swift loopback transport and dialog ownership methods."""
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

ROOT=Path(__file__).resolve().parents[1]


def block(source, marker):
    start=source.index(marker);end=source.index('{',start)+1;depth=1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]


def run_case(directory, mutation):
    fixture=directory/mutation;fixture.mkdir()
    hits=[];errors=[];events=[]
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*args):pass
        def handle(self):
            try:super().handle()
            except(BrokenPipeError,ConnectionResetError):pass
        def do_GET(self):
            hits.append(self.path)
            self.send_response(500);self.send_header('Content-Length','0');self.end_headers()
        def do_POST(self):
            try:
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                if self.path=='/api/profile/fastest':
                    assert body=={'samples':50,'select':True},'wrong Fastest request'
                    hits.append('fastest')
                    if hits.count('fastest')==1:
                        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Connection','close');self.end_headers()
                        self.wfile.write(b'{');self.wfile.flush();(fixture/'fastest-started').write_text('ready')
                        deadline=time.monotonic()+5
                        while time.monotonic()<deadline:
                            ready,_,_=select.select([self.connection],[],[],.05)
                            if ready and self.connection.recv(1,socket.MSG_PEEK)==b'':
                                (fixture/'fastest-cancelled').write_text('closed');return
                        errors.append('Fastest request was not cancelled');return
                    raw=json.dumps({'selected':True,'selected_id':'winner','winner':{'id':'winner','name':'Measured node','samples':50,'failed':0,'trimmed_mean_ms':12.5}}).encode()
                    self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw);return
                assert self.path=='/api/speed-lab/run'
                case=body['test_case'];hits.append(case)
                if case=='close':
                    self.send_response(200);self.send_header('Connection','close');self.end_headers()
                    self.wfile.write(b'{');self.wfile.flush();(fixture/'started').write_text('ready')
                    deadline=time.monotonic()+5
                    while time.monotonic()<deadline:
                        ready,_,_=select.select([self.connection],[],[],.05)
                        if ready and self.connection.recv(1,socket.MSG_PEEK)==b'':
                            (fixture/'cancelled').write_text('closed');return
                    errors.append('old request was not cancelled');return
                if case=='replacement':
                    (fixture/'replacement-started').write_text('ready')
                    deadline=time.monotonic()+5
                    while not(fixture/'release').exists() and time.monotonic()<deadline:time.sleep(.01)
                if case=='redirect':
                    self.send_response(302);self.send_header('Location','/must-not-follow');self.send_header('Content-Length','0');self.end_headers();return
                if case in ('oversized','oversized-untyped'):
                    self.send_response(200);self.send_header('Content-Length',str(3*1024*1024))
                    # Match the shipping Go JSON endpoint. Foundation may
                    # buffer an untyped prefix to infer the response MIME type
                    # before delivering either response or data delegates:
                    # https://developer.apple.com/documentation/foundation/urlresponse/mimetype
                    # https://developer.apple.com/forums/thread/64875
                    if case=='oversized':self.send_header('Content-Type','application/json')
                    self.end_headers();events.append(case+':headers')
                    # Keep both declared bodies incomplete. The untyped case
                    # supplies a bounded sniffable prefix, still far below the
                    # 2MiB data limit, so only the header bound can reject it.
                    try:self.wfile.write(b'{' if case=='oversized' else b'x'*4096);self.wfile.flush();events.append(case+':prefix')
                    except(BrokenPipeError,ConnectionResetError):
                        (fixture/(case+'-cancelled')).write_text('closed');events.append(case+':cancelled');return
                    deadline=time.monotonic()+5
                    while time.monotonic()<deadline:
                        ready,_,_=select.select([self.connection],[],[],.05)
                        if ready and self.connection.recv(1,socket.MSG_PEEK)==b'':
                            (fixture/(case+'-cancelled')).write_text('closed');events.append(case+':cancelled');return
                    errors.append(case+' native request was not cancelled');self.close_connection=True;return
                if case=='stream':
                    self.send_response(200);self.send_header('Connection','close');self.end_headers()
                    try:
                        for _ in range(48):self.wfile.write(b'x'*65536);self.wfile.flush()
                    except(BrokenPipeError,ConnectionResetError):pass
                    self.close_connection=True;return
                raw=json.dumps({'ok':case!='failure','owner':case}).encode()
                self.send_response(500 if case=='failure' else 200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            except(BrokenPipeError,ConnectionResetError):pass
            except Exception as error:errors.append(str(error))
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    source=(ROOT/'client/macos/RouterVPNMacSpeedLab.swift').read_text()
    methods='\n'.join(block(source, marker) for marker in ('    private func stopSpeedLabComparisonProgress(', '    private func startSpeedLabComparisonProgress(', '    private func performLocalRequest(', '    func windowWillClose('))
    methods=methods.replace('private func ','func ')
    fastest_source=block((ROOT/'client/macos/RouterVPNMacTelemetry.swift').read_text(),'private final class RouterVPNMacFastestController')
    fastest_methods='\n'.join(block(fastest_source,marker) for marker in ('    func start(', '    @objc private func cancelOrClose(', '    func windowShouldClose(', '    func windowWillClose(', '    private func finish('))
    fastest_methods=fastest_methods.replace('@objc private func ','func ').replace('private func ','func ')
    if mutation=='missing-cancel':methods=methods.replace('request?.cancel(); request = nil','request = nil')
    if mutation=='missing-owner':methods=methods.replace('guard let self, !self.closed, self.generation == owner else { return }','guard let self else { return }; _ = owner')
    transport=(ROOT/'client/macos/RouterVPNMacSpeedLabTransport.swift').read_text()
    if mutation=='missing-size-completion':
        marker='if oversized { finish(nil, cancelOwnedTask: true) }'
        assert transport.count(marker)==2
        transport=transport.replace(marker,'if oversized { dataTask.cancel() }',1)
    (fixture/'Transport.swift').write_text(transport)
    main=r'''
import Foundation
import CoreFoundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
let routerVPNProductBaseURL=URL(string:CommandLine.arguments[1])!
let fixture=URL(fileURLWithPath:CommandLine.arguments[2],isDirectory:true)
final class Field{var title="";var stringValue="";var string="";var isEnabled=true;func startAnimation(_ sender:Any?){};func stopAnimation(_ sender:Any?){}}
final class NSWindow{var closes=0;func performClose(_ sender:Any?){closes+=1}}
final class FastestOwner {
 let status=Field(),progress=Field(),cancelButton=Field();let window:NSWindow?=NSWindow()
 var request:RouterVPNMacSpeedLabTransport?;var completed:((String)->Void)?
 var started=false,closeWanted=false,isRunning=false
 FASTEST_METHODS
}
final class Product {
 var owner:UUID?;var requestID:String?;var callback:(([String:Any],String)->Void)?;var starts=0;var stops=0
 func startCapturedComparisonProgress(requestID:String?,timeout:TimeInterval,update:(([String:Any],String)->Void)?=nil)->UUID?{
  guard let requestID else{return nil};owner=UUID();self.requestID=requestID;callback=update;starts+=1;return owner
 }
 func stopCapturedComparisonProgress(_ captured:UUID?){if let captured,owner==captured{owner=nil;requestID=nil;callback=nil;stops+=1}}
}
final class Owner {
 let product:Product?=Product();var comparisonProgressOwner:UUID?
 var closed=false,cancelled=false,loadingOptions=false;var generation:UInt64=0;var request:RouterVPNMacSpeedLabTransport?
 let runButton=Field(),status=Field(),detail=Field();var updates=0
 func refreshControls(){}
 METHODS
}
func fail(_ message:String)->Never{fputs(message+"\n",stderr);exit(1)}
func wait(_ predicate:()->Bool,_ message:String){let until=Date().addingTimeInterval(5);while !predicate()&&Date()<until{_ = RunLoop.current.run(mode:.default,before:Date().addingTimeInterval(0.01))};if !predicate(){fail(message)}}
func exists(_ name:String)->Bool{FileManager.default.fileExists(atPath:fixture.appendingPathComponent(name).path)}
// Drive the shipping delegate with a suspended native task to prove that an
// already-known bound violation cannot depend on a later completion event.
// Network cancellation and replacement ownership are exercised below.
for scenario in ["headers","stream"] {
 var callbacks=0;var terminal:Result<Data,Error>?
 let endpoint=routerVPNProductBaseURL.appendingPathComponent("api/speed-lab/run")
 let owned=try RouterVPNMacSpeedLabTransport(url:endpoint,body:nil,timeout:8){value in callbacks+=1;terminal=value}
 let boundary=URLSession(configuration:.ephemeral),task=URLSession.shared.dataTask(with:endpoint)
 if scenario=="headers" {
  let response=HTTPURLResponse(url:endpoint,statusCode:200,httpVersion:"HTTP/1.1",headerFields:["Content-Length":String(3*1024*1024)])!
  var disposition:URLSession.ResponseDisposition?
  owned.urlSession(boundary,dataTask:task,didReceive:response){disposition=$0}
  if disposition != .cancel{fail("Declared-size rejection allowed its response")}
 } else {owned.urlSession(boundary,dataTask:task,didReceive:Data(repeating:1,count:3*1024*1024))}
 guard callbacks==1,case .failure(let error)?=terminal,(error as NSError).domain=="RouterVPNSpeedLab",(error as NSError).code==2 else{fail("Known-size rejection waited for framework completion: "+scenario)}
 owned.urlSession(boundary,dataTask:task,didReceive:Data([1]));owned.urlSession(boundary,task:task,didCompleteWithError:nil)
 if callbacks != 1{fail("Late native callbacks completed a rejected owner again")};task.cancel();boundary.invalidateAndCancel()
}
let notice=Notification(name:Notification.Name("fixture-close"))
let old=Owner();let requestID=String(repeating:"a",count:32)
try old.performLocalRequest("/api/speed-lab/run",body:["test_case":"close","scope":"temporary","topology":"external","execution":"auto","comparison_request_id":requestID],timeout:8){_ in old.updates+=1}
wait({exists("started")},"Old native request did not reach loopback")
guard let capturedProgress=old.product?.callback,old.product?.requestID==requestID else{fail("Native Speed Lab transport did not retain its exact comparison observer")}
capturedProgress(["comparison":["request_id":String(repeating:"b",count:32)]],"foreign")
if !old.detail.string.isEmpty{fail("Foreign comparison updated Speed Lab")}
capturedProgress(["comparison":["request_id":requestID,"complete":false]],"owned Tor HTTP progress")
if old.detail.string != "owned Tor HTTP progress"{fail("Captured comparison did not update active Speed Lab")}
old.cancelled=true;capturedProgress(["comparison":["request_id":requestID]],"cancelled")
if old.detail.string != "owned Tor HTTP progress"{fail("Cancelled Speed Lab accepted comparison progress")};old.cancelled=false
old.windowWillClose(notice)
capturedProgress(["comparison":["request_id":requestID]],"closed")
if old.product?.callback != nil || old.comparisonProgressOwner != nil || old.detail.string != "owned Tor HTTP progress"{fail("Closed Speed Lab retained or revived its comparison callback")}
old.status.stringValue=""
let replacement=Owner();var replacementResult:Result<Data,Error>?
try replacement.performLocalRequest("/api/speed-lab/run",body:["test_case":"replacement"],timeout:8){result in replacement.updates+=1;replacementResult=result}
wait({exists("replacement-started")},"Replacement request did not start")
old.windowWillClose(notice)
wait({exists("cancelled")},"Closing the dialog did not cancel its actual native request")
try Data("go".utf8).write(to:fixture.appendingPathComponent("release"))
wait({replacementResult != nil},"Old close cancelled replacement")
guard case .success(let owned)?=replacementResult,String(decoding:owned,as:UTF8.self).contains("replacement")else{fail("Replacement owner failed")}
for _ in 0..<10{_ = RunLoop.current.run(mode:.default,before:Date().addingTimeInterval(0.01))}
if old.updates != 0 || !old.status.stringValue.isEmpty || replacement.updates != 1{fail("Closed/stale callback mutated dialog state")}
var count=4
for scenario in ["success","failure","redirect","oversized","oversized-untyped","stream"] {
 let owner=Owner();var result:Result<Data,Error>?
 try owner.performLocalRequest("/api/speed-lab/run",body:["test_case":scenario],timeout:8){reply in owner.updates+=1;result=reply}
 wait({result != nil},"Native response never completed: "+scenario)
 if scenario=="success" {guard case .success?=result else{fail("Valid native response failed")}}
 else {guard case .failure?=result else{fail("Invalid native response reported success: "+scenario)}}
 if scenario.hasPrefix("oversized") || scenario=="stream" {guard case .failure(let error)?=result,(error as NSError).domain=="RouterVPNSpeedLab",(error as NSError).code==2 else{fail("Oversized native response was accepted or only timed out: "+scenario)}}
 if scenario.hasPrefix("oversized") {wait({exists(scenario+"-cancelled")},"Rejected native response did not cancel its actual task")}
 if owner.updates != 1{fail("Native completion was delivered more than once")};count+=1
}
for raw in ["https://127.0.0.1/api/speed-lab/run","http://example.invalid/api/speed-lab/run","http://127.0.0.1/api/disconnect","http://u:p@127.0.0.1/api/speed-lab/run","http://127.0.0.1/api/speed-lab/run?other=1"] {
 do{_ = try RouterVPNMacSpeedLabTransport(url:URL(string:raw)!,body:nil,timeout:1){_ in};fail("Foreign native endpoint was accepted")}catch{count+=1}
}
let fastest=FastestOwner();var fastestCallbacks=0
fastest.completed={_ in fastestCallbacks+=1};fastest.start()
wait({exists("fastest-started")},"Actual fifty-sample request did not start")
if fastest.windowShouldClose(fastest.window!) || !fastest.isRunning || fastest.request==nil || fastest.cancelButton.isEnabled {fail("Fastest Close dropped its live request before completion")}
wait({exists("fastest-cancelled") && !fastest.isRunning},"Fastest Close did not cancel its actual native request")
if fastestCallbacks != 1 || fastest.window!.closes != 1 || fastest.request != nil {fail("Fastest Close did not complete its captured owner exactly once")}
let nextFastest=FastestOwner();var nextMessage=""
nextFastest.completed={nextMessage=$0};nextFastest.start();fastest.windowWillClose(notice);fastest.start()
wait({!nextFastest.isRunning},"Old Fastest owner cancelled its replacement")
if !nextMessage.contains("12.5 ms trimmed mean from 50 TCP samples") || !nextMessage.contains("Press Connect") {fail("Fastest omitted the confirmed complete winner: "+nextMessage)}
// Feed decoded JSON through the actual shipping terminal method. Numeric JSON
// and boolean JSON are deliberately separate, including fractional counts that
// NSNumber.intValue would silently truncate into an apparently complete result.
let validWinner:[String:Any] = ["id":"owned", "samples":50, "failed":0, "trimmed_mean_ms":12.5]
let validReply:[String:Any] = ["selected":true, "selected_id":"owned", "winner":validWinner]
var invalidReplies:[(String,[String:Any])] = []
for (field,value) in [("id","" as Any),("samples",50.9 as Any),("samples",49 as Any),("samples",true as Any),("failed",0.9 as Any),("failed",1 as Any),("failed",false as Any),("trimmed_mean_ms",true as Any),("trimmed_mean_ms",0 as Any),("trimmed_mean_ms",-1 as Any),("trimmed_mean_ms","12.5" as Any)] {
 var winner=validWinner;winner[field]=value;var reply=validReply;reply["winner"]=winner
 invalidReplies.append(("winner \(field)=\(value)",reply))
}
for (field,value) in [("selected",1 as Any),("selected",false as Any),("selected_id","foreign" as Any),("winner",NSNull() as Any)] {
 var reply=validReply;reply[field]=value;invalidReplies.append((field,reply))
}
var missingCount=validWinner;missingCount.removeValue(forKey:"samples")
var missingReply=validReply;missingReply["winner"]=missingCount;invalidReplies.append(("missing count",missingReply))
let goodData=try JSONSerialization.data(withJSONObject:validReply)
for (name,reply) in invalidReplies {
 let owner=FastestOwner();owner.started=true;owner.isRunning=true;owner.closeWanted=true
 var messages:[String]=[];owner.completed={messages.append($0)}
 owner.finish(.success(try JSONSerialization.data(withJSONObject:reply)))
 if messages.count != 1 || messages[0].hasPrefix("Selected ") || !messages[0].contains("did not confirm") || owner.isRunning || owner.completed != nil || owner.window!.closes != 1 {fail("Malformed Fastest reply accepted or failed to retire: "+name)}
 let terminal=owner.status.stringValue
 owner.finish(.success(goodData));owner.finish(.failure(NSError(domain:"late",code:1)))
 if messages.count != 1 || owner.status.stringValue != terminal || owner.window!.closes != 1 {fail("Late Fastest reply revived a rejected owner: "+name)}
 count+=1
}
let confirmed=FastestOwner();confirmed.isRunning=true;var confirmedCallbacks=0
confirmed.completed={_ in confirmedCallbacks+=1};confirmed.finish(.success(goodData))
let confirmedMessage=confirmed.status.stringValue
confirmed.finish(.failure(NSError(domain:"duplicate",code:2)));confirmed.finish(.success(goodData))
if confirmedCallbacks != 1 || !confirmedMessage.hasPrefix("Selected ") || confirmed.status.stringValue != confirmedMessage {fail("Duplicate Fastest completion replaced a confirmed result")}
count+=1
let invalidFastestBodies:[[String:Any]] = [["samples":5,"select":true],["samples":50.1,"select":true],["samples":50,"select":false],["samples":50,"select":1],["samples":50,"select":true,"include_external":true]]
for body in invalidFastestBodies {
 do {_ = try RouterVPNMacSpeedLabTransport(url:routerVPNProductBaseURL.appendingPathComponent("api/profile/fastest"),body:body,timeout:185){_ in};fail("Malformed Fastest selection request accepted")}catch{count+=1}
}
for timeout in [186.0,Double.infinity,Double.nan] {
 do {_ = try RouterVPNMacSpeedLabTransport(url:routerVPNProductBaseURL.appendingPathComponent("api/profile/fastest"),body:["samples":50,"select":true],timeout:timeout){_ in};fail("Unbounded Fastest request accepted")}catch{count+=1}
}
count+=4
print("Actual Swift URLSession cancellation, ownership, bounds and failure controls: \(count) cases PASS")
'''.replace('FASTEST_METHODS',fastest_methods).replace('METHODS',methods)
    (fixture/'main.swift').write_text(main)
    try:
        subprocess.run(['swiftc','-swift-version','5','-module-cache-path',str(directory/'module-cache'),str(ROOT/'client/macos/RouterVPNMacControllerAuth.swift'),str(fixture/'Transport.swift'),str(fixture/'main.swift'),'-o',str(fixture/'transport-test')],check=True,timeout=120)
        result=subprocess.run([str(fixture/'transport-test'),'http://127.0.0.1:'+str(server.server_address[1]),str(fixture)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=35)
        if mutation=='shipping':
            print(result.stdout,end='');assert result.returncode==0,result.stdout+'\nLoopback events: '+repr(events)+'\nHits: '+repr(hits)+'\nErrors: '+repr(errors)
            assert not errors,errors
            assert '/must-not-follow' not in hits,'Native transport followed a redirect'
        else:
            assert result.returncode!=0,'Mutation escaped the real lifecycle test: '+mutation
            expected={'missing-cancel':'did not cancel','missing-owner':'mutated dialog','missing-size-completion':'Known-size rejection waited for framework completion'}[mutation]
            assert expected in result.stdout,result.stdout
            print('Negative lifecycle control '+mutation+': rejected',flush=True)
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--shipping-only',action='store_true');args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='router-vpn-macos-speed-lab-transport-') as temporary:
        directory=Path(temporary)
        for mutation in (['shipping'] if args.shipping_only else ['shipping','missing-cancel','missing-owner','missing-size-completion']):run_case(directory,mutation)
    subprocess.run([os.environ.get('PYTHON','python3'),str(ROOT/'deploy/test_macos_comparison_progress.py')]+(['--shipping-only'] if args.shipping_only else []),check=True)
    subprocess.run([os.environ.get('PYTHON','python3'),str(ROOT/'deploy/test_macos_public_comparison_transport.py')]+(['--shipping-only'] if args.shipping_only else []),check=True)
    print('macOS shipping Speed Lab transport and captured dialog lifecycle: PASS',flush=True)


if __name__=='__main__':main()
