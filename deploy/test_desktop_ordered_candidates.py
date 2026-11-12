#!/usr/bin/env python3
"""Execute shipping ordered-candidate controls; native toolkit boundaries explicit."""
import argparse
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]

def block(source, marker):
    start=source.index(marker); brace=source.index('{',start); depth=1; i=brace+1
    while depth:
        if source[i]=='{': depth+=1
        elif source[i]=='}': depth-=1
        i+=1
    return source[start:i]

def swift_form(directory):
    source=(ROOT/'client/macos/RouterVPNMacTelemetry.swift').read_text()
    policy=block(source,'private enum RouterVPNOrderedCandidateDisplay {')
    owner=block(source,'private final class RouterVPNMacOrderedCandidates:')
    fields=owner[owner.index('{')+1:owner.index('    init()')].replace('fileprivate private(set) ','').replace('private ','')
    methods='\n'.join(block(owner,'func '+n+'(').replace('@objc ','') for n in ['controls','capture','measure','saveProfile','cancelTest','windowShouldClose','windowWillClose','tick','issue','send','receive'])
    # Extracted methods keep actual HTTP construction/start/cancel and delivery.
    # The transport and AppKit views are small explicit doubles here; the real
    # transport is separately compiled and constructor-tested below.
    program=r'''
import Foundation
import CoreFoundation
final class NSMenuItem {var representedObject:Any?;let title:String;init(_ value:String){title=value}}
final class NSPopUpButton {var isEnabled=true;var items:[NSMenuItem]=[];var selectedItem:NSMenuItem?;var lastItem:NSMenuItem?{items.last};init(frame:Int,pullsDown:Bool){};func removeAllItems(){items=[];selectedItem=nil};func addItem(withTitle:String){items.append(NSMenuItem(withTitle))};func select(_ item:NSMenuItem?){selectedItem=item}}
extension Int {static var zero:Int{0}}
final class NSTableView {var selectedRow=0;var selectedRowIndexes=IndexSet(integer:0);func reloadData(){}}
final class NSTextField {var stringValue="";init(){};init(wrappingLabelWithString:String){stringValue=wrappingLabelWithString}}
final class NSButton {var isEnabled=false;init(title:String,target:Any?,action:Any?) {}}
final class NSWindow {var closed=false;func close(){closed=true}}
let routerVPNProductBaseURL=URL(string:"http://127.0.0.1:8080")!
final class RouterVPNMacSpeedLabTransport {
 static var calls:[RouterVPNMacSpeedLabTransport]=[]
 let url:URL;let body:[String:Any]?;let timeout:TimeInterval;let completion:(Result<Data,Error>)->Void;var started=false;var cancelled=false
 init(url:URL,body:[String:Any]?,timeout:TimeInterval,completion:@escaping(Result<Data,Error>)->Void)throws{self.url=url;self.body=body;self.timeout=timeout;self.completion=completion;Self.calls.append(self)}
 func start(){started=true};func cancel(){cancelled=true}
 func finish(_ value:[String:Any]){completion(.success(try! JSONSerialization.data(withJSONObject:value)))}
}
POLICY
final class Form {
FIELDS
var window:NSWindow?=NSWindow()
METHODS
}
var checks=0
func check(_ ok:Bool,_ message:String){checks+=1;if !ok{fatalError(message)}}
func settle(){RunLoop.current.run(until:Date().addingTimeInterval(0.03))}
let now=Date().timeIntervalSince1970*1000
func row()->[String:Any]{["candidate_id":"custom","measurement":"routed-tcp-connect","stage":"complete","complete":true,"drained":true,"measured_at":now,"expires_at":now+120000,"results":[["node_id":"custom","role":"candidate","kind":"tcp-connect","ready":true,"benchmark":["measurement":"routed-tcp-connect","attempts":50,"failed":0,"trimmed_mean_ms":2.0,"distribution":["samples":50,"min_ms":1.0,"max_ms":3.0]]]]]}
check(RouterVPNOrderedCandidateDisplay.score(row(),now:now)==2,"complete TCP row rejected")
check(RouterVPNOrderedCandidateDisplay.score(row(),now:now+120000)==nil,"poll renewed expiry")
var invalid=row();invalid["measurement"]="icmp";check(RouterVPNOrderedCandidateDisplay.score(invalid)==nil,"ICMP became candidate score")
let path:[[String:Any]]=[["id":"entry","mode":"wg"],["id":"custom","mode":"shadowsocks"],["id":"final","mode":"shadowsocks"]]
let catalog:[String:Any]=["view_token":String(repeating:"a",count:64),"prefix_position":0,"expires_at":now+120000,"prefixes":[["position":0,"name":"Entry","mode":"wg"]],"candidates":[["id":"custom","name":"Original custom","proposed_path":path]]]
let f=Form();f.capture();let first=RouterVPNMacSpeedLabTransport.calls.last!;check(first.started&&first.url.query=="prefix_position=0","catalog request did not start exact prefix")
first.finish(catalog);settle();check(f.view != nil,"original catalog was not adopted")
f.measure();let run=RouterVPNMacSpeedLabTransport.calls.last!;check(run.started&&run.body?["samples"] as? Int==50&&run.body?["candidate_ids"] as? [String]==["custom"]&&run.timeout==180,"actual test lost original inputs")
let result:[String:Any]=["request_id":f.requestID,"view_token":catalog["view_token"]!,"prefix_position":0,"drained":true,"accepted":true,"results":[row()]]
run.finish(result);settle();check(!f.pendingDrain&&f.save.isEnabled,"joined TCP result did not enable explicit save")
f.prefix.selectedItem?.representedObject=1;f.controls();check(!f.test.isEnabled && !f.save.isEnabled,"new uncaptured prefix reused original result");f.prefix.selectedItem?.representedObject=0;f.controls()
let observed=Form();try! observed.receive(catalog,action:"catalog");observed.requestID=f.requestID;try! observed.receive(result,action:"run");observed.nextRetry = .distantPast;observed.tick();let statusRequest=RouterVPNMacSpeedLabTransport.calls.last!
check(statusRequest.started&&statusRequest.url.query=="request_id="+observed.requestID,"completed job timer did not observe exact original owner")
var lost=result;lost["accepted"]=false;lost["results"]=[[String:Any]]();statusRequest.finish(lost);settle();check(observed.rows.isEmpty && !observed.save.isEnabled,"stale source/proof status retained scored rows")
try! observed.receive(result,action:"run");observed.nextRetry = .distantPast;observed.tick();RouterVPNMacSpeedLabTransport.calls.last!.completion(.failure(NSError(domain:"source unavailable",code:1)));settle();check(observed.rows.isEmpty&&observed.receipt==nil,"failed status request left scored rows visible")


f.profileName.stringValue="Named next connection";f.saveProfile();let saved=RouterVPNMacSpeedLabTransport.calls.last!;check(saved.url.path.hasSuffix("/save-profile")&&saved.body?["name"] as? String=="Named next connection"&&(saved.body?["proposed_path"] as? [[String:Any]])?.count==3,"actual save did not retain full explicit proposed path")
saved.finish(["ok":true,"active_path_changed":false,"profile_name":"Named next connection"]);settle();check(f.receipt==nil&&f.status.stringValue.contains("active path is unchanged"),"save implied live path adoption")
f.measure();let running=RouterVPNMacSpeedLabTransport.calls.last!;check(!f.windowShouldClose(f.window!)&&running.cancelled&&f.pendingDrain && !f.window!.closed,"close escaped original running job")
var late=result;late["request_id"]=f.requestID;running.finish(late);settle();check(f.receipt==nil&&f.rows.isEmpty&&f.pendingDrain,"late successful completion revived cancelled result");f.nextRetry = .distantPast;f.tick();let cancellation=RouterVPNMacSpeedLabTransport.calls.last!;check(cancellation.url.path.hasSuffix("/cancel")&&cancellation.body?["request_id"] as? String==f.requestID,"cancel changed original request")
cancellation.finish(["request_id":f.requestID,"drained":true]);settle();check(f.window!.closed && !f.pendingDrain,"original drain did not release pending close")
print("Swift shipping ordered-candidate controls: \(checks) checks PASS")
'''.replace('POLICY',policy).replace('FIELDS',fields).replace('METHODS',methods.replace('func issue(', 'static func issue('))
    # Static marker extraction starts at func, so restore only that qualifier.
    path=directory/'main.swift';path.write_text(program)
    subprocess.run(['swiftc','-swift-version','5','-module-cache-path',str(directory/'cache'),str(path),'-o',str(directory/'controls')],check=True,timeout=120)
    subprocess.run([str(directory/'controls')],check=True,timeout=30)
    transport=(ROOT/'client/macos/RouterVPNMacSpeedLabTransport.swift').read_text()
    harness=r'''
final class RouterVPNMacLocalAuthorization {static let shared=RouterVPNMacLocalAuthorization();func authorize(_ request:inout URLRequest)throws{}}
var checks=0
func admit(_ path:String,_ body:[String:Any]?,_ timeout:Double,_ valid:Bool){checks+=1;do{let t=try RouterVPNMacSpeedLabTransport(url:URL(string:"http://127.0.0.1:8080"+path)!,body:body,timeout:timeout){_ in};t.cancel();if !valid{fatalError("invalid transport admitted: "+path)}}catch{if valid{fatalError("valid transport rejected: \(error)")}}}
let id=String(repeating:"a",count:32),view=String(repeating:"b",count:64)
let run:[String:Any]=["request_id":id,"view_token":view,"prefix_position":0,"candidate_ids":["original"],"samples":50]
admit("/api/multihop/prefix-candidates",run,180,true)
admit("/api/multihop/prefix-candidates?request_id="+id,run,180,false)
admit("/api/multihop/prefix-candidates?request_id="+id,nil,25,true)
admit("/api/multihop/prefix-candidates?request_id="+id+"&request_id="+id,nil,25,false)
var bad=run;bad["samples"]=49;admit("/api/multihop/prefix-candidates",bad,180,false)
bad=run;bad["prefix_position"]=true;admit("/api/multihop/prefix-candidates",bad,180,false)
bad=run;bad["candidate_ids"]=["original","original"];admit("/api/multihop/prefix-candidates",bad,180,false)
admit("/api/multihop/prefix-candidates/catalog?prefix_position=0",nil,25,true)
admit("/api/multihop/prefix-candidates/catalog?prefix_position=0&prefix_position=1",nil,25,false)
admit("/api/multihop/prefix-candidates/catalog?prefix_position=8",nil,25,false)
admit("/api/multihop/prefix-candidates/cancel",["request_id":id],25,true)
admit("/api/multihop/prefix-candidates/cancel",["request_id":id,"endpoint":"foreign"],25,false)
admit("/api/multihop/prefix-candidates/save-profile",["request_id":id,"view_token":view,"candidate_id":"original","name":"Explicit next","proposed_path":[["id":"entry","mode":"wg"],["id":"original","mode":"shadowsocks"]]],25,true)
admit("/api/connect",[:],25,false)
print("Actual Swift ordered-candidate bounded transport: \(checks) checks PASS")
'''
    path.write_text(transport+harness)
    subprocess.run(['swiftc','-swift-version','5','-module-cache-path',str(directory/'cache'),str(path),'-o',str(directory/'transport')],check=True,timeout=120)
    subprocess.run([str(directory/'transport')],check=True,timeout=30)

def main():
    p=argparse.ArgumentParser();p.add_argument('--platform',choices=['windows','darwin'],required=True);p.add_argument('--shell',default='pwsh');args=p.parse_args()
    with tempfile.TemporaryDirectory(prefix='ordered-candidate-forms-') as d:
        if args.platform=='darwin':swift_form(Path(d))
        else:subprocess.run([args.shell,'-NoProfile','-File',str(ROOT/'client/test-windows-ordered-candidates.ps1'),'-Root',str(ROOT)],check=True,timeout=90)
if __name__=='__main__':main()
