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
    hits=[];errors=[]
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
                assert self.path=='/api/speed-lab/run'
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
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
                if case=='oversized':
                    self.send_response(200);self.send_header('Content-Length',str(3*1024*1024));self.end_headers()
                    # Begin the declared response, then keep it open. The
                    # client must reject the header bound and close its task;
                    # an eventual empty-body timeout cannot pass this case.
                    try:self.wfile.write(b'x');self.wfile.flush()
                    except(BrokenPipeError,ConnectionResetError):
                        (fixture/'oversized-cancelled').write_text('closed');return
                    deadline=time.monotonic()+5
                    while time.monotonic()<deadline:
                        ready,_,_=select.select([self.connection],[],[],.05)
                        if ready and self.connection.recv(1,socket.MSG_PEEK)==b'':
                            (fixture/'oversized-cancelled').write_text('closed');return
                    errors.append('oversized native request was not cancelled');self.close_connection=True;return
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
    methods=block(source,'    private func performLocalRequest(')+'\n'+block(source,'    func windowWillClose(')
    methods=methods.replace('private func ','func ')
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
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
let routerVPNProductBaseURL=URL(string:CommandLine.arguments[1])!
let fixture=URL(fileURLWithPath:CommandLine.arguments[2],isDirectory:true)
final class Field{var title="";var stringValue="";var string=""}
final class Owner {
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
let old=Owner();try old.performLocalRequest("/api/speed-lab/run",body:["test_case":"close"],timeout:8){_ in old.updates+=1}
wait({exists("started")},"Old native request did not reach loopback")
old.windowWillClose(notice)
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
for scenario in ["success","failure","redirect","oversized","stream"] {
 let owner=Owner();var result:Result<Data,Error>?
 try owner.performLocalRequest("/api/speed-lab/run",body:["test_case":scenario],timeout:8){reply in owner.updates+=1;result=reply}
 wait({result != nil},"Native response never completed: "+scenario)
 if scenario=="success" {guard case .success?=result else{fail("Valid native response failed")}}
 else {guard case .failure?=result else{fail("Invalid native response reported success: "+scenario)}}
 if scenario=="oversized" || scenario=="stream" {guard case .failure(let error)?=result,(error as NSError).domain=="RouterVPNSpeedLab",(error as NSError).code==2 else{fail("Oversized native response was accepted or only timed out: "+scenario)}}
 if scenario=="oversized" {wait({exists("oversized-cancelled")},"Rejected native response did not cancel its actual task")}
 if owner.updates != 1{fail("Native completion was delivered more than once")};count+=1
}
for raw in ["https://127.0.0.1/api/speed-lab/run","http://example.invalid/api/speed-lab/run","http://127.0.0.1/api/disconnect","http://u:p@127.0.0.1/api/speed-lab/run","http://127.0.0.1/api/speed-lab/run?other=1"] {
 do{_ = try RouterVPNMacSpeedLabTransport(url:URL(string:raw)!,body:nil,timeout:1){_ in};fail("Foreign native endpoint was accepted")}catch{count+=1}
}
print("Actual Swift URLSession cancellation, ownership, bounds and failure controls: \(count) cases PASS")
'''.replace('METHODS',methods)
    (fixture/'main.swift').write_text(main)
    try:
        subprocess.run(['swiftc','-swift-version','5','-module-cache-path',str(directory/'module-cache'),str(fixture/'Transport.swift'),str(fixture/'main.swift'),'-o',str(fixture/'transport-test')],check=True,timeout=120)
        result=subprocess.run([str(fixture/'transport-test'),'http://127.0.0.1:'+str(server.server_address[1]),str(fixture)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=35)
        if mutation=='shipping':
            print(result.stdout,end='');assert result.returncode==0,result.stdout
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
    print('macOS shipping Speed Lab transport and captured dialog lifecycle: PASS',flush=True)


if __name__=='__main__':main()
