#!/usr/bin/env python3
"""Exercise the shipping AppKit DNS owner and real loopback URLSession.

Swift/Foundation runs the exact controller and transport on every host. macOS
also compiles and renders the actual AppKit panel and clicks its controls. The
HTTP fixture is local, has no VPN, and never contacts a resolver or router.
"""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
import argparse
import importlib.util
import json
import platform
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
MAC = ROOT / 'client/macos'
PROFILE, TOKEN, SESSION = 'exit-a', 'a' * 64, 'b' * 32


MAIN = r'''
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(AppKit)
import AppKit
final class ProductWindowController:NSWindowController {
 var dnsPanel:RouterVPNMacDNSPanel?
 func appendHelp(_ text:String){}
 func refreshProfiles(){}
}
#endif
let routerVPNProductBaseURL=URL(string:CommandLine.arguments[1])!
let fixture=URL(fileURLWithPath:CommandLine.arguments[2],isDirectory:true)
let profileID="exit-a",profileToken=String(repeating:"a",count:64),sessionID=String(repeating:"b",count:32)
var checks=0
func check(_ value:@autoclosure ()->Bool,_ message:String){checks+=1;if !value(){fputs(message+"\n",stderr);exit(1)}}
func spin(_ seconds:TimeInterval=0.02){let until=Date().addingTimeInterval(seconds);while Date()<until{_ = RunLoop.main.run(mode:.default,before:Date().addingTimeInterval(0.002))}}
func wait(_ predicate:()->Bool,_ message:String){let until=Date().addingTimeInterval(6);while !predicate() && Date()<until{spin(0.003)};check(predicate(),message)}
func flag(_ name:String,_ value:String="ready"){try! Data(value.utf8).write(to:fixture.appendingPathComponent(name),options:.atomic)}
func exists(_ name:String)->Bool{FileManager.default.fileExists(atPath:fixture.appendingPathComponent(name).path)}
func json(_ value:Any)->Data{try! JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
func reply(_ value:Any,code:Int=200)->RouterVPNMacDNSReply{RouterVPNMacDNSReply(code:code,data:json(value))}
func rows()->[[String:Any]]{
 [
  ["id":"selected","name":"Home AdGuard","kind":"selected","address":"192.168.50.133","port":53,"transport":"udp","route":"entry","route_label":"Selected Home entry","samples":3,"failed":0,"ready":true,"median_ms":1.2],
  ["id":"cf4a","name":"Cloudflare Primary","kind":"public","address":"1.1.1.1","port":53,"transport":"tcp","route":"exit","route_label":"Captured exit","samples":3,"failed":0,"ready":true,"median_ms":12.5],
  ["id":"q4a","name":"Quad9 Primary","kind":"public","address":"9.9.9.9","port":53,"transport":"tcp","route":"exit","route_label":"Captured exit","samples":3,"failed":0,"ready":true,"median_ms":8.4],
  ["id":"cf6a","name":"Cloudflare IPv6 Primary","kind":"public","address":"2606:4700:4700::1111","port":53,"transport":"tcp","route":"exit","route_label":"Captured exit","samples":0,"failed":3,"ready":false,"failure":"IPv6 is disabled on this captured path"]
 ]
}
func status(_ request:String="",stage:String="idle",complete:Bool=true,drained:Bool=true,withRows:Bool=false,token:String=profileToken,session:String=sessionID,expires:Int=120000,comparison:String="tcp")->[String:Any]{
 let transport=request.isEmpty || stage=="cancelled" && complete && drained ? "":comparison
 var compared=rows()
 if comparison != "tcp"{for index in compared.indices where compared[index]["kind"] as? String=="public"{
  compared[index]["transport"]=comparison;compared[index]["port"]=comparison=="tls" ? 853:443
  compared[index]["server_name"]=compared[index]["id"] as? String=="q4a" ? "dns.quad9.net":"cloudflare-dns.com"
  if comparison=="https"{compared[index]["path"]="/dns-query"}
 }}
 return ["profile_id":profileID,"profile_token":token,"session_id":session,"request_id":request,"expires_in_ms":withRows ? expires:0,
  "status":["schema":1,"node_id":profileID,"session_id":session,"request_id":request,"public_transport":transport,"stage":stage,"complete":complete,"drained":drained,"results":withRows ? compared:[]]]
}
func draft(_ request:String,result:String="q4a",host:String="9.9.9.9",expires:Int=115000,comparison:String="tcp")->[String:Any]{
 var value:[String:Any]=["profile_id":profileID,"profile_token":profileToken,"mode":comparison=="tcp" ? "custom":comparison=="tls" ? "dot":"doh","protocol":comparison,"host":host,"port":comparison=="tcp" ? 53:comparison=="tls" ? 853:443,"measurement_id":request,"result_id":result]
 if comparison != "tcp"{value["server_name"]="dns.quad9.net"}
 if comparison=="https"{value["path"]="/dns-query"}
 return ["session_id":sessionID,"request_id":request,"expires_in_ms":expires,"draft":value]
}
final class Clock{var now=Date()}
final class ControlledRequest:RouterVPNMacDNSRequest{
 let url:URL,body:[String:Any]?,completion:(Result<RouterVPNMacDNSReply,Error>)->Void
 var started=false,cancelled=false,delivered=false
 init(_ url:URL,_ body:[String:Any]?,_ completion:@escaping(Result<RouterVPNMacDNSReply,Error>)->Void){self.url=url;self.body=body;self.completion=completion}
 func start(){started=true}
 func cancel(){cancelled=true}
 func answer(_ value:RouterVPNMacDNSReply){delivered=true;completion(.success(value));spin()}
 func fail(){delivered=true;completion(.failure(NSError(domain:NSURLErrorDomain,code:NSURLErrorCancelled)));spin()}
}
final class ControlledFactory{
 var requests:[ControlledRequest]=[]
 let clock=Clock()
 func make(_ url:URL,_ body:[String:Any]?,_ timeout:TimeInterval,_ callback:@escaping(Result<RouterVPNMacDNSReply,Error>)->Void)->RouterVPNMacDNSRequest{let request=ControlledRequest(url,body,callback);requests.append(request);return request}
 func next(_ path:String,post:Bool=false,query:Bool=false)->ControlledRequest{
  func matches(_ r:ControlledRequest)->Bool{r.url.path==path && (r.body != nil)==post && (r.url.query != nil)==query && r.started && !r.delivered && !r.cancelled}
  wait({self.requests.contains(where:matches)},"Missing owned DNS request "+path)
  return requests.first(where:matches)!
 }
 func poll()->ControlledRequest{next("/api/dns/measurement",query:true)}
 func controller()->RouterVPNMacDNSController{RouterVPNMacDNSController(baseURL:routerVPNProductBaseURL,profileID:profileID,pollInterval:0.01,clock:{self.clock.now},factory:make)}
}
func begin(_ f:ControlledFactory)->(RouterVPNMacDNSController,ControlledRequest){
 let owner=f.controller();owner.open(retest:true);f.next("/api/dns/measurement").answer(reply(status()))
 let start=f.next("/api/dns/measurement",post:true)
 check(Set(start.body!.keys)==["profile_id","profile_token","session_id","request_id","public_transport"],"Start lost exact captured fields")
 check(start.body?["profile_token"] as? String==profileToken && start.body?["session_id"] as? String==sessionID,"Start adopted a different source")
 check(RouterVPNMacDNSTransport.validRequestID(owner.requestID),"Fresh DNS nonce is not 32 lowercase hex")
 return(owner,start)
}
func complete(_ f:ControlledFactory)->RouterVPNMacDNSController{
 let(owner,start)=begin(f);start.answer(reply(status(owner.requestID,stage:"measuring",complete:false,drained:false)))
 f.poll().answer(reply(status(owner.requestID,stage:"complete",withRows:true)))
 check(owner.view.canSelect && !owner.view.busy,"Completed DNS samples were not usable")
 check(owner.view.detail.contains("complete") && !owner.view.detail.contains("Starting"),"Completed DNS status retained an old progress label")
 check(owner.view.rows.count==4 && owner.view.rows.first?.kind=="selected","Selected-policy route was lost among public results")
 check(owner.view.rows.last?.samples==0 && owner.view.rows.last?.failed==3 && owner.view.rows.last?.median_ms==nil,"Unreachable resolver became a scored sample")
 return owner
}
// A complete poll before Start's HTTP task ends cannot release this owner.
do{
 let f=ControlledFactory();let(owner,start)=begin(f)
 f.poll().answer(reply(status(owner.requestID,stage:"complete",withRows:true)))
 check(owner.view.busy && !owner.view.canSelect,"Complete status bypassed pending Start")
 start.answer(reply(status(owner.requestID,stage:"complete",withRows:true)))
 check(owner.view.busy && !owner.view.canSelect,"Start completion retained stale terminal receipt")
 f.poll().answer(reply(status(owner.requestID,stage:"complete",withRows:true)))
 check(owner.view.canSelect,"Fresh post-Start drain was not accepted")
 _ = f.poll();let count=f.requests.count;start.answer(reply(status(owner.requestID,stage:"complete",withRows:true)))
 check(f.requests.count==count,"Duplicate Start completion scheduled another operation")
 check(owner.requestClose(),"Completed owner did not close")
}
// Cancel before admission tombstones the nonce and still joins the Start task.
do{
 let f=ControlledFactory();let(owner,start)=begin(f)
 check(!owner.requestClose(),"Close abandoned a pending Start")
 check(start.cancelled,"Cancellation did not abort its pending Start")
 let cancel=f.next("/api/dns/measurement/cancel",post:true)
 check(cancel.body?["request_id"] as? String==owner.requestID && cancel.body?["profile_id"] as? String==profileID,"Cancel lost the original owner")
 cancel.answer(reply(status(owner.requestID,stage:"cancelled")))
 f.poll().answer(reply(status(owner.requestID,stage:"cancelled")))
 check(!owner.view.closeReady && owner.view.busy,"Tombstone released an unfinished Start task")
 start.fail()
 f.next("/api/dns/measurement/cancel",post:true).answer(reply(status(owner.requestID,stage:"cancelled")))
 f.poll().answer(reply(status(owner.requestID,stage:"cancelled")))
 check(owner.view.closeReady && owner.requestClose(),"Captured tombstone did not finish after Start drained")
 let title=owner.view.title,count=f.requests.count
 start.answer(reply(status(owner.requestID,stage:"complete",withRows:true)))
 check(owner.view.title==title && f.requests.count==count,"Closed Start callback mutated a retired owner")
}
// Cancel HTTP success and complete=true do not establish native socket drain.
do{
 let f=ControlledFactory();let(owner,start)=begin(f);start.answer(reply(status(owner.requestID,stage:"measuring",complete:false,drained:false)))
 check(!owner.requestClose(),"Active DNS owner closed early")
 f.next("/api/dns/measurement/cancel",post:true).answer(reply(status(owner.requestID,stage:"draining",drained:false)))
 f.poll().answer(reply(status(owner.requestID,stage:"draining",drained:false)))
 check(!owner.view.closeReady && owner.view.canCancel,"Complete without drain released the DNS owner")
 f.poll().answer(reply(["error":"owner unavailable"],code:409))
 check(!owner.view.closeReady,"Missing controller response was treated as drain")
 f.poll().answer(reply(status(owner.requestID,stage:"cancelled")))
 check(owner.view.closeReady && owner.requestClose(),"Final native drain did not release close")
}
// Every positive result belongs to the exact captured token, session and nonce.
for field in ["token","session","request"]{
 let f=ControlledFactory();let(owner,start)=begin(f);start.answer(reply(status(owner.requestID,stage:"measuring",complete:false,drained:false)))
 var wrong=status(owner.requestID,stage:"complete",withRows:true)
 if field=="token"{wrong["profile_token"]=String(repeating:"c",count:64)}
 if field=="session"{wrong["session_id"]=String(repeating:"d",count:32);var s=wrong["status"] as! [String:Any];s["session_id"]=wrong["session_id"];wrong["status"]=s}
 if field=="request"{wrong["request_id"]=String(repeating:"e",count:32);var s=wrong["status"] as! [String:Any];s["request_id"]=wrong["request_id"];wrong["status"]=s}
 f.poll().answer(reply(wrong))
 check(!owner.view.canSelect && owner.stagedDraft==nil,"Foreign DNS receipt adopted: "+field)
 f.poll().answer(reply(status(owner.requestID,stage:"cancelled")));_ = owner.requestClose()
}
// Stage the exact fastest PUBLIC row, then recheck idle immediately before Save.
do{
 let f=ControlledFactory()
 let current=complete(f);current.choose("selected")
 check(!f.requests.contains{$0.url.path=="/api/dns/measurement/select"},"Selected-policy row was offered as public Fastest")
 current.choose("fastest")
 let select=f.next("/api/dns/measurement/select",post:true)
 check(select.body?["result_id"] as? String=="fastest","Fastest invented its own saved resolver")
 select.answer(reply(draft(current.requestID)))
 f.next("/api/status").answer(reply(["connected":true,"phase":"connected"]))
 check(current.stagedDraft?.result_id=="q4a" && !current.view.canSave,"Connected draft became an active DNS change")
 f.poll().answer(reply(status(current.requestID,stage:"complete",withRows:true)))
 f.next("/api/status").answer(reply(["connected":false,"phase":"off"]))
 check(current.view.canSave,"Explicit disconnect did not enable measured Save")
 current.save();f.next("/api/status").answer(reply(["connected":true,"phase":"connected"]))
 check(!f.requests.contains{$0.url.path=="/api/dns/policy"},"Save skipped its fresh idle check")
 f.poll().answer(reply(status(current.requestID,stage:"complete",withRows:true)))
 f.next("/api/status").answer(reply(["connected":false,"phase":"off"]))
 current.save();f.next("/api/status").answer(reply(["connected":false,"phase":"off"]))
 let save=f.next("/api/dns/policy",post:true)
 let expected=current.stagedDraft!.body
 check(json(save.body!)==json(expected),"Measured Save changed the exact server draft")
 check(expected["measurement_id"] as? String==current.requestID && expected["result_id"] as? String=="q4a","Save lost its measured receipt")
 let stalePoll=f.poll()
 save.answer(reply(expected));check(current.stagedDraft==nil && current.view.detail.contains("saved"),"Save did not validate its policy echo")
 check(stalePoll.cancelled,"Saved policy retained an obsolete measurement poll")
 stalePoll.answer(reply(["error":"previous source changed"],code:409))
 check(current.view.detail.contains("saved"),"Old poll overwrote a successful measured Save")
 _ = current.requestClose()
}
for fault in ["different-resolver","expired-reply","expired-local","active-phase","expired-save","expired-idle"]{
 let f=ControlledFactory()
 let current=complete(f);current.choose("q4a");let select=f.next("/api/dns/measurement/select",post:true)
 if fault=="expired-local"{f.clock.now=f.clock.now.addingTimeInterval(121)}
 select.answer(reply(draft(current.requestID,host:fault=="different-resolver" ? "1.1.1.1":"9.9.9.9",expires:fault=="expired-reply" ? 0:115000)))
 if fault=="expired-save" || fault=="expired-idle"{
  f.next("/api/status").answer(reply(["connected":false,"phase":"off"]))
  check(current.view.canSave,"Valid disconnected draft was not staged")
  if fault=="expired-idle"{current.save()}
  f.clock.now=f.clock.now.addingTimeInterval(121)
  if fault=="expired-idle"{f.next("/api/status").answer(reply(["connected":false,"phase":"off"]))}else{current.save()}
  check(!f.requests.contains{$0.url.path=="/api/dns/policy"},"Expired draft crossed save admission: "+fault)
 }else if fault=="active-phase"{
  f.next("/api/status").answer(reply(["connected":false,"phase":"reasserting"]))
  check(!current.view.canSave,"Unknown/active phase enabled DNS Save")
  f.clock.now=f.clock.now.addingTimeInterval(121);current.save();spin()
  check(!f.requests.contains{$0.url.path=="/api/dns/policy"},"Expired local draft was posted")
 }else{check(current.stagedDraft==nil,"Invalid measured draft adopted: "+fault)}
 _ = current.requestClose()
}
// Encrypted comparison choices retain their exact port, server name and path.
for comparison in ["tls","https"]{
 let f=ControlledFactory(),current=f.controller();current.open(retest:true,publicTransport:comparison)
 f.next("/api/dns/measurement").answer(reply(status()))
 let start=f.next("/api/dns/measurement",post:true)
 check(start.body?["public_transport"] as? String==comparison,"Encrypted comparison transport was replaced")
 start.answer(reply(status(current.requestID,stage:"measuring",complete:false,drained:false,comparison:comparison)))
 f.poll().answer(reply(status(current.requestID,stage:"complete",withRows:true,comparison:comparison)))
 current.choose("fastest");f.next("/api/dns/measurement/select",post:true).answer(reply(draft(current.requestID,comparison:comparison)))
 f.next("/api/status").answer(reply(["connected":false,"phase":"off"]))
 current.save();f.next("/api/status").answer(reply(["connected":false,"phase":"off"]))
 let save=f.next("/api/dns/policy",post:true),body=save.body!
 check(body["protocol"] as? String==comparison && body["server_name"] as? String=="dns.quad9.net" && body["port"] as? Int==(comparison=="tls" ? 853:443),"Encrypted measured draft lost its protocol parameters")
 check(body["path"] as? String==(comparison=="https" ? "/dns-query":""),"Encrypted measured draft lost its exact path")
 save.answer(reply(body));_ = current.requestClose()
}
// Malformed score/count/lifecycle fields fail closed, but ordinary failures stay visible.
do{
 let nonce=String(repeating:"f",count:32)
 check((try? RouterVPNMacDNSSnapshot.decode(json(status(nonce,stage:"complete",withRows:true)))) != nil,"Ordinary failed resolver row was rejected")
 for field in ["zero","failed-score","samples","drain"]{
  var bad=status(nonce,stage:"complete",withRows:true),s:[String:Any]
  s=bad["status"] as! [String:Any];var r=s["results"] as! [[String:Any]]
  if field=="zero"{r[1]["median_ms"]=0}
  if field=="failed-score"{r[3]["median_ms"]=0}
  if field=="samples"{r[1]["samples"]=4}
  if field=="drain"{s["complete"]=false}
  s["results"]=r;bad["status"]=s
  check((try? RouterVPNMacDNSSnapshot.decode(json(bad)))==nil,"Invalid DNS measurement accepted: "+field)
 }
}
// Execute the actual Product Retest dispatch without an AppKit/network boundary.
final class PopupItem{var representedObject:Any?=profileID}
final class Popup{var selectedItem:PopupItem?=PopupItem()}
final class API{
 var paths:[String]=[]
 func request(_ path:String,method:String,body:[String:Any],timeout:TimeInterval)throws->Data{paths.append(path);return Data("legacy home node".utf8)}
}
final class RetestHarness{
 let routerPopup=Popup(),api=API();var profiles:[[String:Any]]=[],opened:[String]=[],messages:[String]=[]
 func appendHelp(_ value:String){messages.append(value)}
 func showDNSMeasurement(profileID:String){opened.append(profileID)}
 func asyncAction(_ action:()throws->String){messages.append((try? action()) ?? "failed")}
 // SHIPPING_RETEST
}
do{
 let product=RetestHarness();product.profiles=[["id":profileID,"node_kind":"external"]];product.retestDNS()
 check(product.opened==[profileID] && product.api.paths.isEmpty,"External Retest went through legacy Router endpoint")
 product.profiles=[["id":profileID,"node_kind":"router-vpn"]];product.retestDNS()
 check(product.api.paths==["/api/dns/retest"],"Router Retest lost its existing implementation")
 product.routerPopup.selectedItem=nil;product.retestDNS();check(product.api.paths.count==1,"Missing selection invoked a DNS action")
}
// Real local URLSession: cancel-before-admission must keep the nonce tombstoned.
do{
 flag("mode","late")
 let owner=RouterVPNMacDNSController(baseURL:routerVPNProductBaseURL,profileID:profileID,pollInterval:0.02)
 owner.open(retest:true);wait({exists("start-seen")},"Real Start did not reach loopback")
 check(!owner.requestClose(),"Real queued Start closed without cancellation")
 wait({owner.view.closeReady},"Real cancellation tombstone did not drain")
 check(owner.requestClose(),"Real tombstone owner did not close")
 flag("release-start");wait({exists("late-start-rejected")},"Cancelled queued Start was later admitted")
 check(!exists("native-admitted"),"Cancelled queued Start created native work")
}
do{
 flag("mode","draining")
 let owner=RouterVPNMacDNSController(baseURL:routerVPNProductBaseURL,profileID:profileID,pollInterval:0.02)
 owner.open(retest:true);wait({exists("native-admitted")},"Real native fixture did not start")
 _ = owner.requestClose();wait({exists("cancel-seen")},"Real Cancel did not arrive")
 spin(0.08);check(!owner.view.closeReady,"Real un-drained workers released Close")
 flag("native-drained");wait({owner.view.closeReady},"Real drain was not observed");_ = owner.requestClose()
}
// This HTTP boundary must never redirect or accept an oversized response.
for mode in ["redirect","oversize"]{
 flag("mode",mode);var done=false,failed=false,code=0
 let task=try! RouterVPNMacDNSTransport(url:routerVPNProductBaseURL.appendingPathComponent("api/status"),body:nil,timeout:2){result in
  DispatchQueue.main.async{switch result{case .success(let reply):code=reply.code;case .failure:failed=true};done=true}
 }
 task.start();wait({done},"Transport boundary did not finish")
 check(mode=="redirect" ? code==302:failed,"Unsafe DNS HTTP response was accepted")
}
for path in ["https://127.0.0.1:8788/api/status","http://example.test/api/status","http://127.0.0.1:8788/api/other","http://127.0.0.1:8788/api/dns/measurement?request_id=bad"]{
 check((try? RouterVPNMacDNSTransport(url:URL(string:path)!,body:nil,timeout:2){_ in})==nil,"DNS transport accepted unowned endpoint")
}
#if canImport(AppKit)
_ = NSApplication.shared
flag("mode","complete")
var panelClosed=false
let panel=RouterVPNMacDNSPanel(baseURL:routerVPNProductBaseURL,profileID:profileID,retest:false,onSaved:{}){_ in panelClosed=true}
panel.showWindow(nil);panel.window?.makeKeyAndOrderFront(nil)
check(panel.window?.sheetParent==nil,"DNS results blocked the main Disconnect control with a sheet")
wait({panel.controller.view.canRetest},"AppKit panel did not capture its connected node")
func find(_ view:NSView,_ id:String)->NSView?{if view.identifier?.rawValue==id{return view};for child in view.subviews{if let value=find(child,id){return value}};return nil}
let content=panel.window!.contentView!
let retest=find(content,"dns-retest") as! NSButton;retest.performClick(nil)
wait({panel.controller.view.canSelect},"Actual AppKit Retest did not report rows")
let table=find(content,"dns-results") as! NSTableView
check(table.numberOfRows==4 && table.tableColumns.count==7,"Actual AppKit table omitted DNS routes or failures")
let fastest=find(content,"dns-fastest") as! NSButton;fastest.performClick(nil)
wait({panel.controller.stagedDraft != nil},"Actual Fastest button did not request a measured draft")
check(!(find(content,"dns-save") as! NSButton).isEnabled,"Actual panel saved while connected")
flag("disconnected")
wait({panel.controller.view.canSave},"Actual panel did not observe explicit Disconnect")
(find(content,"dns-save") as! NSButton).performClick(nil)
wait({exists("saved-draft")},"Actual Save button did not send the measured draft")
wait({panel.controller.stagedDraft==nil},"Actual Save did not finish")
content.layoutSubtreeIfNeeded()
let bitmap=content.bitmapImageRepForCachingDisplay(in:content.bounds)!
content.cacheDisplay(in:content.bounds,to:bitmap)
check(bitmap.pixelsWide>=850 && bitmap.pixelsHigh>=530,"Actual DNS panel failed to render")
try! bitmap.representation(using:.png,properties:[:])!.write(to:fixture.appendingPathComponent("dns-panel.png"))
panel.window?.performClose(nil);check(panelClosed,"Actual native window did not close")
for name in ["native-admitted","native-drained","cancel-seen"]{try? FileManager.default.removeItem(at:fixture.appendingPathComponent(name))}
flag("mode","draining")
var drainingClosed=false
let drainingPanel=RouterVPNMacDNSPanel(baseURL:routerVPNProductBaseURL,profileID:profileID,retest:true,onSaved:{}){_ in drainingClosed=true}
drainingPanel.showWindow(nil)
wait({exists("native-admitted")},"Actual panel did not start its captured DNS owner")
drainingPanel.window?.performClose(nil)
wait({exists("cancel-seen")},"Actual close did not cancel the captured DNS test")
check(!drainingClosed && drainingPanel.window?.isVisible==true,"Actual panel closed before native drain")
flag("native-drained");wait({drainingClosed},"Actual panel did not close after native drain")
print("Actual macOS SDK/AppKit DNS table, controls and rendering: PASS")
#endif
print("macOS captured DNS owner/transport: PASS (\(checks) checks, real loopback lifecycle and HTTP boundaries)")
'''


def source_member(text, signature):
    start = text.index(signature); brace = text.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        if text[end] == '{': depth += 1
        if text[end] == '}': depth -= 1
        end += 1
    return text[start:end]


def response(request='', stage='idle', complete=True, drained=True, with_rows=False, transport='tcp'):
    rows = [
        dict(id='selected', name='Home AdGuard', kind='selected', address='192.168.50.133', port=53, transport='udp', route='entry', route_label='Selected Home entry', samples=3, failed=0, ready=True, median_ms=1.2),
        dict(id='cf4a', name='Cloudflare Primary', kind='public', address='1.1.1.1', port=53, transport='tcp', route='exit', route_label='Captured exit', samples=3, failed=0, ready=True, median_ms=12.5),
        dict(id='q4a', name='Quad9 Primary', kind='public', address='9.9.9.9', port=53, transport='tcp', route='exit', route_label='Captured exit', samples=3, failed=0, ready=True, median_ms=8.4),
        dict(id='cf6a', name='Cloudflare IPv6 Primary', kind='public', address='2606:4700:4700::1111', port=53, transport='tcp', route='exit', route_label='Captured exit', samples=0, failed=3, ready=False, failure='IPv6 is disabled on this captured path'),
    ]
    return dict(profile_id=PROFILE, profile_token=TOKEN, session_id=SESSION, request_id=request, expires_in_ms=120000 if with_rows else 0,
                status=dict(schema=1, node_id=PROFILE, session_id=SESSION, request_id=request, public_transport=transport if request else '', stage=stage, complete=complete, drained=drained, results=rows if with_rows else []))


def fixture(work, controller, main, module_cache, expected=None):
    state, lock, errors, paths = {}, threading.Lock(), [], []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass

        def answer(self, value, code=200):
            body = json.dumps(value).encode()
            self.send_response(code); self.send_header('content-type', 'application/json'); self.send_header('content-length', str(len(body))); self.end_headers()
            try: self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError): pass

        def do_GET(self):
            parsed = urlsplit(self.path); paths.append(parsed.path)
            mode = (work / 'mode').read_text() if (work / 'mode').exists() else ''
            if parsed.path == '/api/status':
                if mode == 'redirect':
                    self.send_response(302); self.send_header('location', '/must-not-follow'); self.send_header('content-length', '0'); self.end_headers(); return
                if mode == 'oversize':
                    self.send_response(200); self.send_header('content-length', str(3 * 1024 * 1024)); self.end_headers(); return
                self.answer(dict(connected=not (work / 'disconnected').exists(), phase='off' if (work / 'disconnected').exists() else 'connected')); return
            if parsed.path != '/api/dns/measurement': self.answer({}, 404); return
            nonce = parse_qs(parsed.query).get('request_id', [''])[0]
            if not nonce: self.answer(response()); return
            with lock: cancelled = state.get(nonce) == 'cancelled'
            if cancelled:
                drained = mode != 'draining' or (work / 'native-drained').exists()
                self.answer(response(nonce, 'cancelled' if drained else 'draining', True, drained, transport='' if drained else 'tcp'))
            elif mode == 'complete': self.answer(response(nonce, 'complete', with_rows=True))
            else: self.answer(response(nonce, 'measuring', False, False))

        def do_POST(self):
            try:
                data = json.loads(self.rfile.read(int(self.headers.get('content-length', '0'))))
                nonce = data.get('request_id', '')
                mode = (work / 'mode').read_text() if (work / 'mode').exists() else ''
                paths.append(self.path)
                if self.path == '/api/dns/measurement':
                    (work / 'start-seen').write_text(nonce)
                    if mode == 'late':
                        deadline = time.monotonic() + 5
                        while not (work / 'release-start').exists() and time.monotonic() < deadline: time.sleep(0.01)
                    with lock:
                        if state.get(nonce) == 'cancelled':
                            (work / 'late-start-rejected').write_text(nonce)
                            self.answer({'error': 'nonce cancelled before admission'}, 409); return
                        state[nonce] = 'started'
                    (work / 'native-admitted').write_text(nonce)
                    self.answer(response(nonce, 'measuring', False, False), 202)
                elif self.path == '/api/dns/measurement/cancel':
                    with lock: state[nonce] = 'cancelled'
                    if mode == 'draining': (work / 'cancel-seen').write_text(nonce)
                    drained = mode != 'draining' or (work / 'native-drained').exists()
                    self.answer(response(nonce, 'cancelled' if drained else 'draining', True, drained, transport='' if drained else 'tcp'), 202)
                elif self.path == '/api/dns/measurement/select':
                    self.answer(dict(session_id=SESSION, request_id=nonce, expires_in_ms=115000,
                                     draft=dict(profile_id=PROFILE, profile_token=TOKEN, mode='custom', protocol='tcp', host='9.9.9.9', port=53, measurement_id=nonce, result_id='q4a')))
                elif self.path == '/api/dns/policy':
                    if not (work / 'disconnected').exists(): errors.append('active Save was posted')
                    (work / 'saved-draft').write_text(json.dumps(data)); self.answer(data)
                else: self.answer({}, 404)
            except (BrokenPipeError, ConnectionResetError): pass
            except Exception as error: errors.append(str(error))

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler); server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    (work / 'Controller.swift').write_text(controller); (work / 'main.swift').write_text(main)
    sources = [str(MAC / 'RouterVPNMacDNSTransport.swift'), str(work / 'Controller.swift')]
    if platform.system() == 'Darwin': sources.append(str(MAC / 'RouterVPNMacDNSPanel.swift'))
    sources.append(str(work / 'main.swift'))
    try:
        subprocess.run(['swiftc', '-swift-version', '5', '-module-cache-path', str(module_cache), *sources, '-o', str(work / 'test')], check=True, timeout=120)
        result = subprocess.run([str(work / 'test'), 'http://127.0.0.1:' + str(server.server_address[1]), str(work)], capture_output=True, text=True, timeout=90)
        if expected:
            assert result.returncode != 0 and expected in result.stderr + result.stdout, (result.returncode, result.stdout, result.stderr)
        else:
            print(result.stdout, end='', flush=True)
            assert result.returncode == 0, result.stdout + result.stderr
            assert not errors and '/must-not-follow' not in paths, (errors, paths)
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--shipping-only', action='store_true'); parser.add_argument('--mutation', action='append')
    args = parser.parse_args()
    product = (MAC / 'RouterVPNMacProduct.swift').read_text()
    retest = source_member(product, '@objc func retestDNS()').replace('@objc ', '', 1)
    main = MAIN.replace(' // SHIPPING_RETEST', retest)
    controller = (MAC / 'RouterVPNMacDNSController.swift').read_text()
    spec = importlib.util.spec_from_file_location('dns_source_closure', ROOT / 'deploy/test_macos_source_closure.py')
    closure = importlib.util.module_from_spec(spec); spec.loader.exec_module(closure)
    builder = (MAC / 'build-native-app.sh').read_text()
    required = {MAC / ('RouterVPNMacDNS' + name + '.swift') for name in ['Transport', 'Controller', 'Panel']}
    assert required <= closure.compiled_inputs(builder), 'native DNS source is absent from the actual shipping compiler'
    assert 'test_macos_dns_measurement.py' in builder and 'RouterVPNMacDNSPanel?' in product
    assert 'run: python3 deploy/test_macos_dns_measurement.py\n' in (ROOT / '.github/workflows/macos-native-app.yml').read_text(), 'full DNS defect gate must run in native CI'
    mutations = {
        'foreign-source': ('value.profile_token == capture.profile_token,', 'true,', 'Foreign DNS receipt adopted: token'),
        'pending-start': ('fromPoll && tasks["start"] == nil && tasks["cancel"] == nil && value.completed', 'fromPoll && tasks["cancel"] == nil && value.completed', 'Start completion retained stale terminal receipt'),
        'missing-drain': ('fromPoll && tasks["start"] == nil && tasks["cancel"] == nil && value.completed', 'fromPoll && tasks["start"] == nil && tasks["cancel"] == nil && value.status.complete', 'Complete without drain released the DNS owner'),
        'queued-start': ('tasks["start"]?.cancel()', '/* queued Start was not cancelled */', 'Cancellation did not abort its pending Start'),
        'active-save': ('guard try Self.disconnected(self.success(result)),', 'guard true,', 'Save skipped its fresh idle check'),
        'changed-draft': ('value.draft.matches(expected),', 'true,', 'Invalid measured draft adopted: different-resolver'),
    }
    with tempfile.TemporaryDirectory(prefix='macos-dns-measurement-') as temporary:
        work = Path(temporary); shipping = work / 'shipping'; shipping.mkdir()
        fixture(shipping, controller, main, work / 'modules')
        if args.shipping_only: return
        for name, (before, after, expected) in mutations.items():
            if args.mutation and name not in args.mutation: continue
            assert controller.count(before) == 1, (name, controller.count(before))
            negative = work / name; negative.mkdir()
            fixture(negative, controller.replace(before, after, 1), main, work / 'modules', expected)
            print('Rejected native DNS defect mutation: ' + name, flush=True)


if __name__ == '__main__': main()
