#!/usr/bin/env python3
"""Execute shipping ordered-candidate controls; native toolkit boundaries explicit."""
import argparse
from pathlib import Path
import re
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

def swift_launcher(directory):
    """Execute the shipping button bindings, delegates and dialog factory.

    AppKit selector delivery, windows and the dialog constructor are explicit
    boundaries here. The actual dialog's purpose/retirement methods are also
    exercised by swift_form, and native AppKit compilation remains required.
    """
    original=(ROOT/'client/macos/RouterVPNMacTelemetry.swift').read_text()
    controls=(
        ('baseline',None,None,None),
        ('factory-purpose','let controller=RouterVPNMacOrderedCandidates(savedPath: savedPath, savedPrefix: savedPrefix,',
         'let controller=RouterVPNMacOrderedCandidates(savedPath: savedPath, savedPrefix: false,',
         'prefix button did not open its captured prefix purpose'),
        ('button-selector','action: #selector(savedPrefixCandidates)',
         'action: #selector(savedPathCandidates)',
         'prefix button did not open its captured prefix purpose'),
        ('busy-owner','|| !existing.closeForPurposeChange()', '|| false',
         'purpose change replaced an active candidate owner'),
    )
    for name,old,new,witness in controls:
        source=original
        if old is not None:
            assert source.count(old)==1,(name,source.count(old))
            source=source.replace(old,new,1)
        launch=block(source,'func showOrderedPrefixCandidates(')
        panel=block(source,'private final class RouterVPNMacPerformanceController:')
        begin=panel.index('        let savedCandidates = NSButton(')
        end=panel.index('        let orderedLatency = NSButton(',begin)
        buttons=re.sub(r'#selector\((\w+)\)',r'"\1"',panel[begin:end])
        delegates='\n'.join(block(panel,'func '+method+'(') for method in ('prefixCandidates','savedPathCandidates','savedPrefixCandidates'))
        program=r'''
import Foundation
var retained:[ObjectIdentifier:Any]=[:]
var telemetryOrderedCandidatesKey:UInt8=0
enum Association {case OBJC_ASSOCIATION_RETAIN_NONATOMIC}
func objc_getAssociatedObject(_ owner:AnyObject,_ key:UnsafeRawPointer)->Any? {retained[ObjectIdentifier(owner)]}
func objc_setAssociatedObject(_ owner:AnyObject,_ key:UnsafeRawPointer,_ value:Any?,_ policy:Association){retained[ObjectIdentifier(owner)]=value}
final class Window {var shown=0;func makeKeyAndOrderFront(_ sender:Any?){shown+=1}}
final class RouterVPNMacOrderedCandidates {
 static var made:[RouterVPNMacOrderedCandidates]=[]
 let savedPath:Bool,savedPrefix:Bool;var closed=false,replaceAllowed=true;var closeRequests=0
 let window:Window?=Window()
 init(savedPath:Bool=false,savedPrefix:Bool=false,draft:[String:Any]?=nil,position:Int=0,choose:(([String:Any]) throws -> Void)?=nil){self.savedPath=savedPath||savedPrefix;self.savedPrefix=savedPrefix;Self.made.append(self)}
 func matchesPurpose(savedPath:Bool,savedPrefix:Bool)->Bool{self.savedPath==(savedPath||savedPrefix)&&self.savedPrefix==savedPrefix}
 func closeForPurposeChange()->Bool{closeRequests+=1;if replaceAllowed{closed=true};return replaceAllowed}
 func showWindow(_ sender:Any?){window?.shown+=1}
}
final class ProductWindowController { LAUNCH }
enum Bezel {case rounded}
enum Orientation {case horizontal}
final class NSButton {
 let title:String;let target:Any?;let action:String;var bezelStyle:Bezel = .rounded
 init(title:String,target:Any?,action:String){self.title=title;self.target=target;self.action=action}
 func click(){guard let panel=target as? LaunchPanel else{fatalError("button lost its shipping target")};panel.fire(action)}
}
final class NSStackView {
 var views:[Any];var orientation:Orientation = .horizontal;var spacing=0
 init(views:[Any]=[]){self.views=views};func addArrangedSubview(_ view:Any){views.append(view)}
}
final class MeasurementBoundary {var running=false}
final class LaunchPanel {
 let product:ProductWindowController?;var closed=false;let measurement=MeasurementBoundary()
 var actions:[NSButton]=[];let stack=NSStackView()
 init(product:ProductWindowController){self.product=product;BUTTONS}
 DELEGATES
 func fire(_ action:String){switch action{case "savedPathCandidates":savedPathCandidates();case "savedPrefixCandidates":savedPrefixCandidates();default:fatalError("unknown shipping selector")}}
}
var checks=0
func check(_ ok:Bool,_ message:String){checks+=1;if !ok{fatalError(message)}}
let panel=LaunchPanel(product:ProductWindowController())
let rows=panel.stack.views.compactMap{$0 as? NSStackView}
check(rows.count==1&&rows[0].views.count==2,"saved candidate controls are not visible in their shared row")
let prefix=panel.actions.first{$0.title=="Test selected prefix only"}!
let saved=panel.actions.first{$0.title=="Test saved Local path"}!
check(rows[0].views.contains{($0 as? NSButton)===prefix},"prefix control was never placed in the panel")
prefix.click();let first=RouterVPNMacOrderedCandidates.made.last!
check(first.savedPath&&first.savedPrefix,"prefix button did not open its captured prefix purpose")
prefix.click();check(RouterVPNMacOrderedCandidates.made.count==1&&first.closeRequests==0,"same-purpose click replaced its original dialog")
first.replaceAllowed=false;saved.click()
check(RouterVPNMacOrderedCandidates.made.count==1&& !first.closed,"purpose change replaced an active candidate owner")
first.replaceAllowed=true;saved.click();let second=RouterVPNMacOrderedCandidates.made.last!
check(RouterVPNMacOrderedCandidates.made.count==2&&first.closed&&second.savedPath&& !second.savedPrefix,"idle dialog did not switch to the complete saved purpose")
panel.prefixCandidates();let connected=RouterVPNMacOrderedCandidates.made.last!
check(RouterVPNMacOrderedCandidates.made.count==3&& !connected.savedPath&& !connected.savedPrefix,"connected candidate purpose changed")
panel.measurement.running=true;prefix.click();check(RouterVPNMacOrderedCandidates.made.count==3,"running Performance measurement launched a competing dialog")
panel.measurement.running=false;panel.closed=true;prefix.click();check(RouterVPNMacOrderedCandidates.made.count==3,"closed Performance panel launched another dialog")
print("Swift shipping candidate launcher: \(checks) checks PASS; AppKit/constructor boundaries explicit")
'''
        program=re.sub(r'\s*(&&|\|\|)\s*',r' \1 ',program).replace('LAUNCH',launch).replace('BUTTONS',buttons).replace('DELEGATES',delegates)
        path=directory/'launcher.swift';path.write_text(program)
        binary=directory/'launcher'
        subprocess.run(['swiftc','-swift-version','5','-module-cache-path',str(directory/'launcher-cache'),str(path),'-o',str(binary)],check=True,timeout=120)
        result=subprocess.run([str(binary)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
        if witness is None:
            assert result.returncode==0,result.stdout
            print(result.stdout.strip(),flush=True)
        else:
            assert result.returncode!=0 and witness in result.stdout,(name,result.stdout[-4000:])
            print('Swift candidate launcher causal control rejected: '+name,flush=True)

def swift_form(directory):
    source=(ROOT/'client/macos/RouterVPNMacTelemetry.swift').read_text()
    policy=block(source,'private enum RouterVPNOrderedCandidateDisplay {')
    policy+='\n'+block((ROOT/'client/macos/RouterVPNMacViaEntryPolicy.swift').read_text(),'final class MacViaEntryCandidateReservation:')
    product=(ROOT/'client/macos/RouterVPNMacProduct.swift').read_text()
    assert 'self.statusLabel.stringValue = productConnectionStatusLabel(connected: connected, phase: phase)' in product
    policy+='\n'+block(product,'func productConnectionStatusLabel(')
    summary=(ROOT/'client/macos/RouterVPNHomeSummary.swift').read_text()
    policy+='\n'+block(summary,'private struct RouterVPNDesktopHomeSummary:')
    policy+='\nprivate final class HomeForm {\n'+block(summary,'func formatHomeSummary(')+'\n}'
    owner=block(source,'private final class RouterVPNMacOrderedCandidates:')
    fields=owner[owner.index('{')+1:owner.index('    init(savedPath:')].replace('fileprivate private(set) ','').replace('private ','')
    methods='\n'.join(block(owner,'func '+n+'(').replace('@objc ','') for n in ['matchesPurpose','closeForPurposeChange','controls','capture','measure','saveProfile','cancelTest','windowShouldClose','windowWillClose','tick','savedStatus','issue','send','receive','receiveSaved'])
    # Extracted methods keep actual HTTP construction/start/cancel and delivery.
    # The transport and AppKit views are small explicit doubles here; the real
    # transport is separately compiled and constructor-tested below.
    program=r'''
import Foundation
import CoreFoundation
final class NSMenuItem {var representedObject:Any?;let title:String;init(_ value:String){title=value}}
final class NSPopUpButton {var isEnabled=true;var items:[NSMenuItem]=[];var selectedItem:NSMenuItem?;var lastItem:NSMenuItem?{items.last};init(frame:Int,pullsDown:Bool){};func removeAllItems(){items=[];selectedItem=nil};func addItem(withTitle:String){items.append(NSMenuItem(withTitle))};func select(_ item:NSMenuItem?){selectedItem=item}}
extension Int {static var zero:Int{0}}
final class NSTableView {var selectedRow=0;var selectedRowIndexes=IndexSet(integer:0);func selectRowIndexes(_ indexes:IndexSet,byExtendingSelection:Bool){selectedRowIndexes=indexes;selectedRow=indexes.first ?? -1};func reloadData(){}}
final class NSTextField {var isHidden=false;var stringValue="";init(){};init(wrappingLabelWithString:String){stringValue=wrappingLabelWithString}}
final class NSButton {var title="";var isEnabled=false;init(title:String,target:Any?,action:Any?) {}}
final class NSWindow {var closed=false;var onClose:(()->Void)?;func close(){closed=true;onClose?()};func performClose(_ sender:Any?){close()}}
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
init(savedPath:Bool=false,savedPrefix:Bool=false,draft:[String:Any]?=nil,position:Int=0,choose:(([String:Any]) throws -> Void)?=nil){self.draft=draft;self.position=position;self.choose=choose;self.savedPath=savedPath || savedPrefix;self.savedPrefix=savedPrefix;window?.onClose={[weak self] in self?.windowWillClose(Notification(name:Notification.Name("closed")))}}
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
let catalog:[String:Any]=["measurement":"routed-tcp-connect","view_token":String(repeating:"a",count:64),"prefix_position":0,"expires_at":now+120000,"prefixes":[["position":0,"name":"Entry","mode":"wg"]],"candidates":[["id":"custom","name":"Original custom","proposed_path":path]]]
let responseMetric="routed-candidate-response"
var streamCatalog=catalog;streamCatalog["measurement"]=responseMetric;streamCatalog["prefix_position"]=1
streamCatalog["prefixes"]=[["position":1,"id":"custom","mode":"shadowsocks","measurement":responseMetric]]
streamCatalog["candidates"]=[["id":"custom","name":"Paired target","kind":"router-vpn","proposed_path":path]]
for position in [7,8,14,94] {
 var late=streamCatalog;late["prefix_position"]=position;late["prefixes"]=[["position":position,"id":"custom","mode":"shadowsocks","measurement":responseMetric]]
 check(RouterVPNOrderedCandidateDisplay.metric(late,position:position)==responseMetric,"late native response prefix lost its distinct metric")
 late["requested_execution"]="server";check(RouterVPNOrderedCandidateDisplay.metric(late,position:position)==nil,"late private response escaped Local ownership")
}
for position in [0,95,96] {
 var late=streamCatalog;late["prefixes"]=[["position":position,"mode":"shadowsocks","measurement":responseMetric]]
 check(RouterVPNOrderedCandidateDisplay.metric(late,position:position)==nil,"response crossed physical or final prefix boundary")
}
var unownedStream=streamCatalog;unownedStream["prefixes"]=[["position":1,"mode":"shadowsocks","measurement":responseMetric]]
check(RouterVPNOrderedCandidateDisplay.metric(unownedStream,position:1)==nil,"missing stream prefix identity acquired a private response score")
let otherPrefix:[String:Any]=["execution":"local","nodes":[["id":"entry","mode":"wg"],["id":"another","mode":"shadowsocks"],["id":"final","mode":"shadowsocks"]]]
check(RouterVPNOrderedCandidateDisplay.metric(streamCatalog,position:1,draft:otherPrefix)==nil,"foreign draft prefix acquired a private response score")
var streamRow=row();streamRow["measurement"]=responseMetric
var inner=(streamRow["results"] as! [[String:Any]])[0];inner["kind"]="private-agent-response"
var benchmark=inner["benchmark"] as! [String:Any];benchmark["measurement"]=responseMetric;inner["benchmark"]=benchmark
streamRow["results"]=[inner]
var foreignCatalog=streamCatalog;foreignCatalog["prefixes"]=[["position":1,"id":"custom","mode":"shadowsocks"]]
check(RouterVPNOrderedCandidateDisplay.metric(foreignCatalog,position:1)==nil,"missing per-prefix response capability accepted")
foreignCatalog=streamCatalog;foreignCatalog["candidates"]=[["id":"custom","kind":"external"]]
check(RouterVPNOrderedCandidateDisplay.metric(foreignCatalog,position:1)==nil,"unpaired source substituted for private-agent candidate")
let streamForm=Form(position:1);try! streamForm.receive(streamCatalog,action:"catalog");streamForm.requestID="private"
var streamResult:[String:Any]=["measurement":responseMetric,"request_id":"private","view_token":streamCatalog["view_token"]!,"prefix_position":1,"drained":true,"accepted":true,"results":[streamRow]]
try! streamForm.receive(streamResult,action:"run");streamForm.controls()
check(streamForm.rows.count==1 && streamForm.save.isEnabled,"authenticated 50-sample response did not reach chooser")
check(RouterVPNOrderedCandidateDisplay.score(streamRow,measurement:responseMetric,now:now+120000)==nil,"expired private response admitted")
check(RouterVPNOrderedCandidateDisplay.score(streamRow,now:now)==nil,"private response ranked alongside TCP")
for (field,bad) in [("kind","tcp-connect"),("role","final")] {
 var item=inner;item[field]=bad;var wrong=streamRow;wrong["results"]=[item]
 check(RouterVPNOrderedCandidateDisplay.score(wrong,measurement:responseMetric,now:now)==nil,"crossed response kind or role")
}
for (field,bad) in [("measurement","routed-tcp-connect" as Any),("attempts",49 as Any),("failed",1 as Any)] {
 var b=benchmark;b[field]=bad;var item=inner;item["benchmark"]=b;var wrong=streamRow;wrong["results"]=[item]
 check(RouterVPNOrderedCandidateDisplay.score(wrong,measurement:responseMetric,now:now)==nil,"crossed benchmark or incomplete responses")
}
streamResult["measurement"]="routed-tcp-connect"
do{try streamForm.receive(streamResult,action:"run");fatalError("cross-metric result replaced captured metric")}catch{checks+=1}
var bogus=streamCatalog;bogus["prefixes"]=[["position":1,"id":"custom","mode":"wg"]]
check(RouterVPNOrderedCandidateDisplay.metric(bogus,position:1)==nil,"packet prefix presented a private-agent receipt")
let purpose=Form(savedPrefix:true)
check(purpose.matchesPurpose(savedPath:false,savedPrefix:true) && purpose.matchesPurpose(savedPath:true,savedPrefix:true),"prefix purpose lost normalized saved ownership")
check(!purpose.matchesPurpose(savedPath:true,savedPrefix:false) && !purpose.matchesPurpose(savedPath:false,savedPrefix:false),"another purpose reused a prefix dialog")
purpose.pendingDrain=true;check(!purpose.closeForPurposeChange() && !purpose.closed && purpose.pendingDrain,"purpose change closed a retained native job")
purpose.pendingDrain=false;check(purpose.closeForPurposeChange() && purpose.closed && purpose.window!.closed,"idle purpose change did not close its exact original window")
let fetching=Form();fetching.capture();let pending=RouterVPNMacSpeedLabTransport.calls.last!
check(!fetching.closeForPurposeChange() && !fetching.closed && fetching.request===pending && !pending.cancelled,"purpose change replaced an in-flight source request")
pending.finish(catalog);settle();check(fetching.closeForPurposeChange() && fetching.closed,"completed source capture could not retire its dialog")
let sparse=Form();var sparseCatalog=catalog
sparseCatalog["prefixes"]=[0,2,4,6].map{["position":$0,"name":"Packet \($0)","mode":"awg2-fast"] as [String:Any]}
sparse.capture();RouterVPNMacSpeedLabTransport.calls.last!.finish(sparseCatalog);settle()
check(sparse.prefix.items.compactMap{$0.representedObject as? Int}==[0,2,4,6],"connected packet picker changed the original sparse positions")
sparse.prefix.selectedItem=sparse.prefix.items[2];sparse.capture()
let sparseRequest=RouterVPNMacSpeedLabTransport.calls.last!
check(sparseRequest.url.path=="/api/multihop/prefix-candidates/catalog" && sparseRequest.url.query=="prefix_position=4" && sparseRequest.body==nil && sparse.view==nil,"connected packet recapture used a different purpose or an index in the displayed list")
sparseCatalog["prefix_position"]=4;sparseCatalog["view_token"]=String(repeating:"b",count:64);sparseRequest.finish(sparseCatalog);settle()
check(sparse.position==4 && sparse.view?["view_token"] as? String==String(repeating:"b",count:64),"connected sparse recapture lost its new token or selected position")
let f=Form();f.capture();let first=RouterVPNMacSpeedLabTransport.calls.last!;check(first.started&&first.url.query=="prefix_position=0","catalog request did not start exact prefix")
first.finish(catalog);settle();check(f.view != nil,"original catalog was not adopted")
f.measure();let run=RouterVPNMacSpeedLabTransport.calls.last!;check(run.started&&run.body?["samples"] as? Int==50&&run.body?["candidate_ids"] as? [String]==["custom"]&&run.timeout==180,"actual test lost original inputs")
let result:[String:Any]=["measurement":"routed-tcp-connect","request_id":f.requestID,"view_token":catalog["view_token"]!,"prefix_position":0,"drained":true,"accepted":true,"results":[row()]]
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

var savedCatalog=catalog;savedCatalog["scope"]="saved-complete-local";savedCatalog["schema"]=1;savedCatalog["samples"]=50;savedCatalog["measurement"]="routed-tcp-connect"
func savedResult(_ form:Form)->[String:Any]{["schema":1,"scope":"saved-complete-local","request_id":form.requestID,"view_token":savedCatalog["view_token"]!,"prefix_position":0,"measurement":"routed-tcp-connect","running":false,"drained":false,"cancelled":false,"native_down":true,"accepted":true,"reviewing":true,"cleanup_pending":false,"active_path_changed":false,"saved_profile_id":"","results":[row()]]}
func savedForm()->Form{let value=Form(savedPath:true);try! value.receive(savedCatalog,action:"catalog");value.requestID=String(repeating:"c",count:32);return value}
for purpose in [false,true] {let expired=Form(savedPath:purpose);try! expired.receive(purpose ? savedCatalog:catalog,action:"catalog");expired.view?["expires_at"]=now-1;let before=RouterVPNMacSpeedLabTransport.calls.count;expired.measure();check(RouterVPNMacSpeedLabTransport.calls.count==before && expired.requestID.isEmpty && !expired.pendingDrain && !MacViaEntryCandidateReservation.shared.active && expired.status.stringValue.contains("expired"),"expired catalog created a request or editing owner")}
let sf=Form(savedPath:true);sf.capture();let savedCapture=RouterVPNMacSpeedLabTransport.calls.last!
check(savedCapture.url.path=="/api/multihop/saved-candidates/catalog" && f.endpoint=="/api/multihop/prefix-candidates","saved scope did not capture its immutable endpoint")
savedCapture.finish(savedCatalog);settle();sf.measure();let savedRun=RouterVPNMacSpeedLabTransport.calls.last!
check(MacViaEntryCandidateReservation.shared.active,"saved Test did not reserve editing before its HTTP start")
check(savedRun.url.path=="/api/multihop/saved-candidates" && savedRun.body?["samples"] as? Int==50,"saved Test used another purpose or sample count")
var testing=savedResult(sf);testing["running"]=true;testing["native_down"]=false;testing["accepted"]=false;testing["reviewing"]=false
savedRun.finish(testing);settle();check(sf.pendingDrain && sf.rows.isEmpty && !sf.save.isEnabled,"Testing exposed choices before native DOWN")
sf.nextRetry = .distantPast;sf.tick();let savedPoll=RouterVPNMacSpeedLabTransport.calls.last!
check(savedPoll.url.path=="/api/multihop/saved-candidates" && savedPoll.url.query=="request_id="+sf.requestID,"saved Testing did not poll its original request")
savedPoll.finish(savedResult(sf));settle();check(sf.pendingDrain && sf.save.isEnabled && !sf.test.isEnabled && sf.rows.count==1,"DOWN review lost its live observer or explicit Save")
check(MacViaEntryCandidateReservation.shared.active,"native DOWN prematurely released the review edit lease")
let overlapping=Form(savedPath:true);try! overlapping.receive(savedCatalog,action:"catalog");overlapping.controls();let overlapCalls=RouterVPNMacSpeedLabTransport.calls.count;overlapping.measure();check(RouterVPNMacSpeedLabTransport.calls.count==overlapCalls && overlapping.requestID.isEmpty,"retained review admitted another saved Test")
for key in ["native_down","reviewing","cleanup_pending","running","cancelled","drained"]{
 let value=savedForm();var wrong=savedResult(value);wrong[key] = ["cleanup_pending","running","cancelled","drained"].contains(key)
 try! value.receive(wrong,action:"poll");value.controls()
 check(!value.save.isEnabled && value.rows.isEmpty,"saved choice escaped original DOWN: "+key)
}
let missing=savedForm();var unknown=savedResult(missing);unknown.removeValue(forKey:"cleanup_pending");try! missing.receive(unknown,action:"poll");missing.controls();check(!missing.save.isEnabled && missing.rows.isEmpty,"missing cleanup truth became review authority")
let expired=savedForm();var oldRow=row();oldRow["measured_at"]=now-120000;oldRow["expires_at"]=now;var old=savedResult(expired);old["results"]=[oldRow];try! expired.receive(old,action:"poll");expired.controls();check(!expired.save.isEnabled && expired.rows.isEmpty,"saved result polling renewed completion expiry")
let wrongScope=savedForm();var foreign=savedResult(wrongScope);foreign["scope"]="connected-prefix";do{try wrongScope.receive(foreign,action:"run");fatalError("foreign purpose became saved result")}catch{checks+=1}
var wrongCatalog=savedCatalog;wrongCatalog["scope"]="connected-prefix";do{try Form(savedPath:true).receive(wrongCatalog,action:"catalog");fatalError("foreign purpose became saved catalog")}catch{checks+=1}
sf.profileName.stringValue="Saved separate graph";sf.view?["expires_at"]=now-1;sf.saveProfile();let commit=RouterVPNMacSpeedLabTransport.calls.last!
check(commit.url.path=="/api/multihop/saved-candidates/save-profile" && commit.body?["name"] as? String=="Saved separate graph" && (commit.body?["proposed_path"] as? [[String:Any]])?.count==3,"saved profile append lost its explicit complete graph")
func written(_ form:Form)->[String:Any]{var value=savedResult(form);value["accepted"]=false;value["reviewing"]=false;value["saved_profile_id"]="profile-original";value["profile_id"]="profile-original";value["profile_name"]="Saved separate graph";value["saved"]=true;value["ok"]=true;value["cleanup_pending"]=true;value["cleanup_error"]="Original observer remains pending.";value["failure"]="Result invalidated after its committed write.";return value}
commit.finish(written(sf));settle();check(sf.savedProfileID=="profile-original" && sf.pendingDrain && !sf.save.isEnabled && sf.status.stringValue.contains("Saved separate graph") && sf.status.stringValue.contains("Result invalidated"),"committed saved identity was lost after cleanup invalidation")
let calls=RouterVPNMacSpeedLabTransport.calls.count;sf.saveProfile();check(RouterVPNMacSpeedLabTransport.calls.count==calls,"committed profile was offered for duplicate Save")
sf.nextRetry = .distantPast;sf.tick();let savedCancel=RouterVPNMacSpeedLabTransport.calls.last!;check(savedCancel.url.path=="/api/multihop/saved-candidates/cancel" && savedCancel.body?["request_id"] as? String==sf.requestID && savedCancel.body?["view_token"] as? String==savedCatalog["view_token"] as? String,"saved cleanup changed purpose or owner")
var joined=written(sf);joined["drained"]=true;joined["cleanup_pending"]=false;joined["cleanup_error"]="";savedCancel.finish(joined);settle();check(!sf.pendingDrain && sf.savedProfileID=="profile-original" && sf.status.stringValue.contains("Saved separate graph"),"joined Cancel erased a committed profile")
check(!MacViaEntryCandidateReservation.shared.active,"original observer join did not release its edit lease")
let uncertain=savedForm();try! uncertain.receive(savedResult(uncertain),action:"run");uncertain.controls();uncertain.profileName.stringValue="Uncertain reply";uncertain.saveProfile();RouterVPNMacSpeedLabTransport.calls.last!.completion(.failure(NSError(domain:"lost Save response",code:1)));settle();check(uncertain.pendingDrain && !uncertain.save.isEnabled,"uncertain Save abandoned its original owner")
uncertain.nextRetry = .distantPast;uncertain.tick();let recover=RouterVPNMacSpeedLabTransport.calls.last!;check(recover.body==nil && recover.url.query=="request_id="+uncertain.requestID,"uncertain Save retried append instead of original status")
recover.finish(written(uncertain));settle();check(uncertain.savedProfileID=="profile-original" && !uncertain.save.isEnabled,"original status failed to recover committed Save identity")
let closing=Form(savedPath:true);try! closing.receive(savedCatalog,action:"catalog");closing.controls();closing.measure();RouterVPNMacSpeedLabTransport.calls.last!.finish(savedResult(closing));settle();check(!closing.windowShouldClose(closing.window!) && closing.pendingDrain && !closing.window!.closed,"saved review close escaped its retained observer")
closing.nextRetry = .distantPast;closing.tick();let closingCancel=RouterVPNMacSpeedLabTransport.calls.last!;var closed=savedResult(closing);closed["drained"]=true;closed["cancelled"]=true;closed["accepted"]=false;closed["reviewing"]=false;closingCancel.finish(closed);settle();check(closing.window!.closed && !closing.pendingDrain,"saved review did not wait for original observer join")
check(!MacViaEntryCandidateReservation.shared.active,"joined window close retained its original edit lease")
func neverStarted(_ form:Form)->[String:Any]{var value=savedResult(form);value["admission_cancelled"]=true;value["started"]=false;value["drained"]=true;value["native_down"]=false;value["accepted"]=false;value["cancelled"]=true;value["reviewing"]=false;value["results"]=[[String:Any]]();return value}
let early=Form(savedPath:true);try! early.receive(savedCatalog,action:"catalog");early.controls();early.measure();RouterVPNMacSpeedLabTransport.calls.last!.completion(.failure(NSError(domain:"initial admission refused",code:409)));settle()
check(early.pendingDrain && MacViaEntryCandidateReservation.shared.active && !early.save.isEnabled,"HTTP admission failure was treated as native DOWN")
early.nextRetry = .distantPast;early.tick();let earlyCancel=RouterVPNMacSpeedLabTransport.calls.last!
check(earlyCancel.body?["view_token"] as? String==savedCatalog["view_token"] as? String,"never-started Cancel lost its original view")
for fault in ["view","request","started","missing-started","native-down","accepted","cancelled","results"] {
 var invalid=neverStarted(early)
 switch fault {case "view":invalid["view_token"]=String(repeating:"b",count:64);case "request":invalid["request_id"]=String(repeating:"b",count:32);case "started":invalid["started"]=true;case "missing-started":invalid.removeValue(forKey:"started");case "native-down":invalid["native_down"]=true;case "accepted":invalid["accepted"]=true;case "cancelled":invalid["cancelled"]=false;default:invalid["results"]=[row()]}
 var rejected=false;do{try early.receive(invalid,action:"cancel")}catch{rejected=true}
 check(rejected && early.pendingDrain && MacViaEntryCandidateReservation.shared.active,"invalid never-started receipt retired original authority: "+fault)
}
earlyCancel.finish(neverStarted(early));settle();check(!early.pendingDrain && !early.savedNativeDown && early.rows.isEmpty && !early.save.isEnabled && !MacViaEntryCandidateReservation.shared.active && early.status.stringValue=="Cancelled before the temporary path started.","exact never-started receipt did not retire only its nonce")
let admitted=savedForm();try! admitted.receive(savedResult(admitted),action:"run")
var refusedLate=false;do{try admitted.receive(neverStarted(admitted),action:"cancel")}catch{refusedLate=true};check(refusedLate && admitted.pendingDrain,"never-started receipt retired an admitted job")
var unproved=savedResult(admitted);unproved["drained"]=true;unproved["native_down"]=false
var refusedDown=false;do{try admitted.receive(unproved,action:"cancel")}catch{refusedDown=true};check(refusedDown && admitted.pendingDrain,"admitted cleanup retired without native DOWN")
var prefixCatalog=savedCatalog;prefixCatalog["scope"]="saved-prefix-local";prefixCatalog["application_open"]=false;prefixCatalog["dns_open"]=false;prefixCatalog["proof_scope"]="selected-prefix"
func prefixResult(_ form:Form)->[String:Any]{var value=savedResult(form);value["scope"]="saved-prefix-local";value["application_open"]=false;value["dns_open"]=false;value["proof_scope"]="selected-prefix";return value}
do{try Form(savedPrefix:true).receive(savedCatalog,action:"catalog");fatalError("complete catalog became prefix preparation")}catch{checks+=1}
for key in ["application_open","dns_open","proof_scope"] {var missing=prefixCatalog;missing.removeValue(forKey:key);do{try Form(savedPrefix:true).receive(missing,action:"catalog");fatalError("prefix catalog omitted closed proof: "+key)}catch{checks+=1}}
let pf=Form(savedPrefix:true);pf.capture();let prefixCapture=RouterVPNMacSpeedLabTransport.calls.last!
check(prefixCapture.url.path=="/api/multihop/saved-candidates/catalog" && prefixCapture.url.query=="prefix_position=0&scope=saved-prefix-local","prefix catalog lost explicit captured purpose")
prefixCapture.finish(prefixCatalog);settle();pf.measure();let prefixRun=RouterVPNMacSpeedLabTransport.calls.last!
check(prefixRun.body?["scope"] as? String=="saved-prefix-local" && prefixRun.body?["samples"] as? Int==50 && MacViaEntryCandidateReservation.shared.active,"prefix Run lost captured purpose or reservation")
var prefixTesting=prefixResult(pf);prefixTesting["running"]=true;prefixTesting["native_down"]=false;prefixTesting["accepted"]=false;prefixTesting["reviewing"]=false
prefixRun.finish(prefixTesting);settle();check(pf.pendingDrain && pf.rows.isEmpty && !pf.save.isEnabled,"prefix Testing exposed choices before native DOWN")
pf.nextRetry = .distantPast;pf.tick();RouterVPNMacSpeedLabTransport.calls.last!.finish(prefixResult(pf));settle()
check(pf.pendingDrain && pf.rows.count==1 && pf.save.isEnabled && MacViaEntryCandidateReservation.shared.active,"prefix DOWN review lost its original observer")
for action in ["run","poll","save","cancel"] {for key in ["scope","proof_scope","application_open","dns_open"] {
 var foreign=prefixResult(pf);foreign["drained"]=true;foreign["saved_profile_id"]="foreign-write"
 if key=="scope" {foreign[key]="saved-complete-local"} else if key=="proof_scope" {foreign[key]="ordinary-path"} else {foreign[key]=true}
 var refused=false;do{try pf.receive(foreign,action:action)}catch{refused=true}
 check(refused && pf.pendingDrain && pf.savedProfileID.isEmpty && MacViaEntryCandidateReservation.shared.active,"prefix response changed purpose or closed proof: "+action+":"+key)
}}
pf.profileName.stringValue="Prefix future profile";pf.saveProfile();let prefixSave=RouterVPNMacSpeedLabTransport.calls.last!
check(prefixSave.body?["scope"] as? String=="saved-prefix-local" && (prefixSave.body?["proposed_path"] as? [[String:Any]])?.count==3,"prefix Save lost purpose or complete original graph")
var prefixWritten=written(pf);prefixWritten["scope"]="saved-prefix-local";prefixWritten["application_open"]=false;prefixWritten["dns_open"]=false;prefixWritten["proof_scope"]="selected-prefix"
prefixSave.finish(prefixWritten);settle();check(pf.pendingDrain && pf.savedProfileID=="profile-original" && !pf.save.isEnabled,"prefix Save lost committed identity before cleanup")
pf.nextRetry = .distantPast;pf.tick();let prefixCancel=RouterVPNMacSpeedLabTransport.calls.last!
check(prefixCancel.body?["scope"] as? String=="saved-prefix-local" && prefixCancel.body?["request_id"] as? String==pf.requestID,"prefix Cancel lost captured purpose")
prefixWritten["drained"]=true;prefixWritten["cleanup_pending"]=false;prefixWritten["cleanup_error"]="";prefixCancel.finish(prefixWritten);settle()
check(!pf.pendingDrain && !MacViaEntryCandidateReservation.shared.active && pf.savedProfileID=="profile-original","prefix cleanup did not retain the write and join its owner")
let editorBody:[String:Any]=["execution":"local","nodes":[["id":"entry","mode":"wg"],["id":"final","mode":"shadowsocks"]]]
var editorDeliveries=0
let editorForm=Form(savedPrefix:true,draft:editorBody) { response in
    check(response["candidate_id"] as? String=="custom","draft choice changed original measured candidate")
    editorDeliveries+=1
}
editorForm.capture();let editorCatalogRequest=RouterVPNMacSpeedLabTransport.calls.last!
check(editorCatalogRequest.url.path=="/api/multihop/draft-candidates/catalog" && editorCatalogRequest.body?["scope"]==nil && editorCatalogRequest.body?["execution"] as? String=="local","draft catalog rewrote the ordered editor request")
var editorCatalog=prefixCatalog;editorCatalog["origin"]="editor-draft";editorCatalogRequest.finish(editorCatalog);settle()
let automatic=RouterVPNMacSpeedLabTransport.calls.last!
check(automatic !== editorCatalogRequest && automatic.url.path=="/api/multihop/draft-candidates" && automatic.body?["candidate_ids"] as? [String]==["custom"] && automatic.body?["samples"] as? Int==50,"opening a valid draft picker did not measure its eligible candidates")
var editorReceipt=prefixResult(editorForm);editorReceipt["origin"]="editor-draft";automatic.finish(editorReceipt);settle()
editorForm.saveProfile();let choosing=RouterVPNMacSpeedLabTransport.calls.last!
check(choosing.url.path=="/api/multihop/draft-candidates/choose" && choosing.body?["name"]==nil && choosing.body?["scope"] as? String=="saved-prefix-local","draft adoption went through persistent Save")
var choice=editorReceipt;choice["drained"]=true;choice["native_down"]=true;choice["accepted"]=false;choice["chosen"]=true;choice["candidate_id"]="custom";choice["saved_profile_id"]=""
choosing.finish(choice);settle();check(editorDeliveries==1 && !editorForm.pendingDrain,"drained selection failed to return to its original editor")
for (requested, winner) in [("server","server"),("auto","local"),("auto","server")] {
    let original = [["id":"entry","mode":"wg"],["id":"source","mode":"shadowsocks"],["id":"packet","mode":"awg2-fast"],["id":"final","mode":"shadowsocks"]]
    let proposed = Array(original.prefix(3)) + [["id":"custom","mode":"shadowsocks"]] + Array(original.suffix(1))
    let draft:[String:Any] = ["execution":requested,"nodes":original,"expected_selected_node_id":"final","expected_profile_tokens":["entry":"e","source":"s","packet":"p","final":"f"]]
    var delivered = 0
    let form = Form(savedPrefix:true,draft:draft,position:2) { result in
        check(result["requested_execution"] as? String == requested && result["selected_execution"] as? String == winner &&
              result["selection_epoch"] as? Int == 17 && result["proposed_path"] as? [[String:String]] == proposed, "selected draft changed winner, epoch or suffix")
        delivered += 1
    }
    form.capture();let admission=RouterVPNMacSpeedLabTransport.calls.last!
    check(admission.url.query=="prefix_position=2&scope=draft-complete-selected" && admission.body?["nodes"] as? [[String:String]] == original && admission.body?["execution"] as? String == requested && admission.body?["scope"] == nil, "selected catalog lost original input")
    var offer=savedCatalog;offer["scope"]="draft-complete-selected";offer["origin"]="editor-draft";offer["prefix_position"]=2;offer["requested_execution"]=requested
    offer["prefixes"]=[["id":"packet","position":2,"mode":"awg2-fast","name":"Packet"]];offer["candidates"]=[["id":"custom","name":"Added","proposed_path":proposed]]
    for (key,bad) in [("scope","saved-prefix-local" as Any),("requested_execution","local"),("selected_execution",winner),("prefixes",[["position":2,"mode":"wg","id":"packet"]])] {
        var changed=offer;changed[key]=bad
        do{try form.receive(changed,action:"catalog");fatalError("foreign selected catalog: "+key)}catch{checks+=1}
    }
    admission.finish(offer);settle();let run=RouterVPNMacSpeedLabTransport.calls.last!
    check(run.url.path=="/api/multihop/draft-candidates" && run.body?["scope"] as? String == "draft-complete-selected" && run.body?["samples"] as? Int == 50, "selected draft run changed purpose")
    var observed=savedResult(form);observed["origin"]="editor-draft";observed["scope"]="draft-complete-selected";observed["prefix_position"]=2;observed["requested_execution"]=requested
    do{try form.receive(observed,action:"poll");fatalError("unselected candidate became a reviewable result")}catch{checks+=1}
    observed["selected_execution"]=winner;observed["selection_epoch"]=17
    run.finish(observed);settle()
    check(form.save.isEnabled && form.selectedWinner == winner && form.status.stringValue.contains(winner),"genuine measured winner was not reviewable")
    for (key,bad) in [("scope","saved-prefix-local" as Any),("selected_execution",winner=="local" ? "server":"local"),("selection_epoch",18),("selection_epoch",true),("admission_cancelled",true),("requested_execution","local")] {
        var changed=observed;changed[key]=bad
        do{try form.receive(changed,action:"poll");fatalError("changed selected measurement: "+key)}catch{checks+=1}
    }
    form.saveProfile();let apply=RouterVPNMacSpeedLabTransport.calls.last!
    check(apply.url.path=="/api/multihop/draft-candidates/choose" && apply.body?["scope"] as? String=="draft-complete-selected" && apply.body?["proposed_path"] as? [[String:String]] == proposed, "selected choose lost complete proposed path")
    var chosen=observed;chosen["drained"]=true;chosen["accepted"]=false;chosen["reviewing"]=false;chosen["chosen"]=true;chosen["candidate_id"]="custom";chosen["proposed_path"]=proposed
    apply.finish(chosen);settle();check(delivered==1 && !form.pendingDrain,"selected choose failed joined editor handoff")
}
let unavailable=Form(savedPrefix:true,draft:editorBody);unavailable.capture();let only=RouterVPNMacSpeedLabTransport.calls.last!
var unavailableCatalog=editorCatalog;unavailableCatalog["candidates"]=[["id":"custom","name":"Incompatible","save_reason":"Cannot insert at this position"]]
only.finish(unavailableCatalog);settle();check(RouterVPNMacSpeedLabTransport.calls.last === only && !unavailable.pendingDrain,"unsupported draft candidate started a worker")
check(productConnectionStatusLabel(connected:false,phase:"candidate:testing")=="○ Testing","temporary Home exposed its internal phase")
check(productConnectionStatusLabel(connected:true,phase:"connected")=="● Connected","ordinary Connected label changed")
let home:[String:Any]=["actual_exit_status":"proved","actual_exit_ip":"203.0.113.9","connection_phase":"candidate:testing","connected":false,"path_proof":"proved","dns_status":"unknown","lan_access":false,"kill_switch":"off","warnings":[]]
let homeText=HomeForm().formatHomeSummary(try! JSONDecoder().decode(RouterVPNDesktopHomeSummary.self,from:JSONSerialization.data(withJSONObject:home)))
check(homeText.contains("Connection: Testing • temporary path") && !homeText.contains("203.0.113.9") && !homeText.contains("path proof proved"),"temporary Home reused ordinary public-exit proof")
let originalNodes=[["id":"entry","mode":"wg"],["id":"imported","mode":"shadowsocks"],["id":"originalFinal","mode":"shadowsocks"]]
let finalNodes=Array(originalNodes.dropLast())+[["id":"custom","mode":"shadowsocks"]]
let finalChoice:[String:Any]=["id":"custom","name":"Measured paired candidate","kind":"router-vpn","proposal_action":"save-final-profile","proposed_path":finalNodes]
let draftFinal:[String:Any]=["nodes":originalNodes,"execution":"local","expected_selected_node_id":"originalFinal"]
check(RouterVPNOrderedCandidateDisplay.savesMeasuredFinal(finalChoice,draft:draftFinal,position:1,metric:responseMetric),"same-length final projection refused")
for field in ["proposal_action","kind","proposed_path"] {
 var bad=finalChoice;bad[field]=field=="proposed_path" ? Array(originalNodes.dropLast())+[["id":"foreign","mode":"shadowsocks"]] as Any : "foreign"
 check(!RouterVPNOrderedCandidateDisplay.savesMeasuredFinal(bad,draft:draftFinal,position:1,metric:responseMetric),"foreign final action or path admitted")
}
var namedCatalog=streamCatalog;namedCatalog["schema"]=1;namedCatalog["samples"]=50;namedCatalog["scope"]="saved-prefix-local";namedCatalog["origin"]="editor-draft"
namedCatalog["proof_scope"]="selected-prefix";namedCatalog["application_open"]=false;namedCatalog["dns_open"]=false
namedCatalog["prefixes"]=[["position":1,"id":"imported","mode":"shadowsocks","measurement":responseMetric]];namedCatalog["candidates"]=[finalChoice]
let named=Form(savedPrefix:true,draft:draftFinal,position:1){_ in fatalError("named save changed the active editor")}
try! named.receive(namedCatalog,action:"catalog")
var namedResults:[String:Any]=["schema":1,"scope":"saved-prefix-local","request_id":named.requestID,"view_token":namedCatalog["view_token"]!,"prefix_position":1,"measurement":responseMetric,"running":false,"drained":false,"cancelled":false,"native_down":true,"accepted":true,"reviewing":true,"cleanup_pending":false,"active_path_changed":false,"saved_profile_id":"","results":[streamRow],"origin":"editor-draft","proof_scope":"selected-prefix","application_open":false,"dns_open":false]
RouterVPNMacSpeedLabTransport.calls.last!.finish(namedResults);settle()
check(named.save.isEnabled && named.save.title=="Save profile with this final" && !named.profileName.isHidden,"named final action did not reach the original form: \(named.status.stringValue), row \(named.rows.count), title \(named.save.title), id \(named.requestID), phase \(named.phase)")
named.profileName.stringValue="Measured final";named.saveProfile()
let namedPost=RouterVPNMacSpeedLabTransport.calls.last!
check(namedPost.url.path=="/api/multihop/draft-candidates/save-profile" && namedPost.body?["scope"] as? String=="saved-prefix-local" && namedPost.body?["name"] as? String=="Measured final" && namedPost.body?["proposed_path"] as? [[String:String]]==finalNodes,"named final did not submit the exact original candidate scope and path")
namedResults["saved_profile_id"]="named-result";namedResults["profile_id"]="named-result";namedResults["saved"]=true;namedResults["profile_name"]="Measured final";namedResults["candidate_id"]="custom";namedResults["proposal_action"]="save-final-profile";namedResults["accepted"]=false;namedResults["reviewing"]=false;namedResults["drained"]=true;namedResults["results"]=[]
var rejected=namedResults;rejected["chosen"]=true;do{try named.receive(rejected,action:"save");fatalError("named save adopted a draft change")}catch{checks+=1}
namedPost.finish(namedResults);settle()
check(named.savedProfileID=="named-result" && !named.pendingDrain && !named.save.isEnabled,"named final did not retain its separate saved-profile identity")
print("Swift shipping ordered-candidate controls: \(checks) checks PASS")
'''.replace('POLICY',policy).replace('FIELDS',fields).replace('METHODS',methods.replace('func issue(', 'static func issue('))
    # Static marker extraction starts at func, so restore only that qualifier.
    path=directory/'main.swift';path.write_text(program)
    subprocess.run(['swiftc','-swift-version','5','-module-cache-path',str(directory/'cache'),str(path),'-o',str(directory/'controls')],check=True,timeout=120)
    subprocess.run([str(directory/'controls')],check=True,timeout=30)
    controls=[
        ('native-down','flag(value, "native_down") && ','','saved choice escaped original DOWN: native_down'),
        ('cleanup',' && falseFlag(value, "cleanup_pending")','','saved choice escaped original DOWN: cleanup_pending'),
        ('review-idle','(savedPath || !pendingDrain)','!pendingDrain','DOWN review lost its live observer or explicit Save'),
        ('committed-id','savedProfileID=id;','savedProfileID="";','committed saved identity was lost after cleanup invalidation'),
        ('endpoint','savedPath ? "/api/multihop/saved-candidates" : "/api/multihop/prefix-candidates"','"/api/multihop/prefix-candidates"','saved scope did not capture its immutable endpoint'),
        ('early-review-release','if !pendingDrain,request == nil,let lease=editLease','if (!pendingDrain || savedNativeDown),request == nil,let lease=editLease','native DOWN prematurely released the review edit lease'),
        ('joined-close-release','if closeWanted,request==nil,!pendingDrain {controls();window?.close();return}','if closeWanted,request==nil,!pendingDrain {window?.close();return}','joined window close retained its original edit lease'),
        ('never-started-view','value["view_token"] as? String == view?["view_token"] as? String,','true,','invalid never-started receipt retired original authority: view'),
        ('late-admission','guard action=="cancel",!savedAdmitted,savedProfileID.isEmpty,','guard action=="cancel",savedProfileID.isEmpty,','never-started receipt retired an admitted job'),
        ('native-join','guard !RouterVPNOrderedCandidateDisplay.flag(value,"drained") || RouterVPNOrderedCandidateDisplay.flag(value,"native_down") else','guard true else','admitted cleanup retired without native DOWN'),
        ('prefix-application','falseFlag(value,"application_open") && ','','prefix catalog omitted closed proof: application_open'),
        ('prefix-dns','falseFlag(value,"dns_open") && ','','prefix catalog omitted closed proof: dns_open'),
        ('prefix-proof',' && value["proof_scope"] as? String == "selected-prefix"','','prefix catalog omitted closed proof: proof_scope'),
        ('selected-epoch','selected == winner && generation == epoch','selected == winner','changed selected measurement: selection_epoch'),
        ('prefix-request','capturedBody?["scope"]=savedScope','capturedBody?["scope"]="saved-complete-local"','prefix Run lost captured purpose or reservation'),
    ]
    for name,old,new,witness in controls:
        assert program.count(old)==1,(name,program.count(old))
        mutant=program.replace(old,new,1);assert mutant!=program
        path.write_text(mutant)
        subprocess.run(['swiftc','-swift-version','5','-module-cache-path',str(directory/'cache'),str(path),'-o',str(directory/'controls')],check=True,timeout=120)
        result=subprocess.run([str(directory/'controls')],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
        assert result.returncode!=0 and witness in result.stdout,(name,result.stdout[-4000:])
        print('Swift saved-path causal control rejected: '+name,flush=True)
    transport=(ROOT/'client/macos/RouterVPNMacSpeedLabTransport.swift').read_text()
    harness=r'''
final class RouterVPNMacLocalAuthorization {static let shared=RouterVPNMacLocalAuthorization();func authorize(_ request:inout URLRequest)throws{}}
var checks=0
func admit(_ path:String,_ body:[String:Any]?,_ timeout:Double,_ valid:Bool){checks+=1;do{let t=try RouterVPNMacSpeedLabTransport(url:URL(string:"http://127.0.0.1:8080"+path)!,body:body,timeout:timeout){_ in};t.cancel();if !valid{fatalError("invalid transport admitted: "+path)}}catch{if valid{fatalError("valid transport rejected: \(error)")}}}
let id=String(repeating:"a",count:32),view=String(repeating:"b",count:64)
let run:[String:Any]=["request_id":id,"view_token":view,"prefix_position":0,"candidate_ids":["original"],"samples":50]
admit("/api/multihop/prefix-candidates",run,180,true)
var fullInventory=run;fullInventory["candidate_ids"]=(0..<129).map{String(format:"linked-candidate-%04d",$0)};admit("/api/multihop/prefix-candidates",fullInventory,180,true)
var oversizedInventory=run;oversizedInventory["candidate_ids"]=(0..<1000).map{String(format:"linked-candidate-%04d",$0)};admit("/api/multihop/prefix-candidates",oversizedInventory,180,false)
admit("/api/multihop/prefix-candidates?request_id="+id,run,180,false)
admit("/api/multihop/prefix-candidates?request_id="+id,nil,25,true)
admit("/api/multihop/prefix-candidates?request_id="+id+"&request_id="+id,nil,25,false)
var bad=run;bad["samples"]=49;admit("/api/multihop/prefix-candidates",bad,180,false)
bad=run;bad["prefix_position"]=true;admit("/api/multihop/prefix-candidates",bad,180,false)
bad=run;bad["candidate_ids"]=["original","original"];admit("/api/multihop/prefix-candidates",bad,180,false)
admit("/api/multihop/prefix-candidates/catalog?prefix_position=0",nil,25,true)
admit("/api/multihop/prefix-candidates/catalog?prefix_position=0&prefix_position=1",nil,25,false)
admit("/api/multihop/prefix-candidates/catalog?prefix_position=8",nil,25,true)
admit("/api/multihop/prefix-candidates/catalog?prefix_position=96",nil,25,false)
admit("/api/multihop/prefix-candidates/catalog?prefix_position=08",nil,25,false)
admit("/api/multihop/prefix-candidates/cancel",["request_id":id],25,true)
admit("/api/multihop/prefix-candidates/cancel",["request_id":id,"endpoint":"foreign"],25,false)
admit("/api/multihop/prefix-candidates/save-profile",["request_id":id,"view_token":view,"candidate_id":"original","name":"Explicit next","proposed_path":[["id":"entry","mode":"wg"],["id":"original","mode":"shadowsocks"]]],25,true)
admit("/api/connect",[:],25,false)
print("Actual Swift ordered-candidate bounded transport: \(checks) checks PASS")
'''
    marker='print("Actual Swift ordered-candidate bounded transport:'
    saved=harness[harness.index('let id='):harness.index(marker)].replace('/api/multihop/prefix-candidates','/api/multihop/saved-candidates')
    saved=saved.replace('admit("/api/multihop/saved-candidates/cancel",["request_id":id],25,true)','admit("/api/multihop/saved-candidates/cancel",["request_id":id,"view_token":view],25,true)')
    extra='''
admit("/api/multihop/saved-candidates-extra",run,180,false)
admit("/api/multihop/saved-candidates/unknown",nil,25,false)
admit("/api/multihop/saved-candidates?prefix_position=0",nil,25,false)
admit("/api/multihop/saved-candidates",run,181,false)
admit("/api/multihop/saved-candidates/cancel",["request_id":id],26,false)
admit("/api/multihop/saved-candidates/cancel",["request_id":id],25,false)
admit("/api/multihop/saved-candidates/cancel",["request_id":id,"view_token":"foreign"],25,false)
admit("/api/multihop/saved-candidates/cancel",["request_id":id,"view_token":view,"native_down":true],25,false)
admit("/api/multihop/prefix-candidates/cancel",["request_id":id,"view_token":view],25,false)
admit("/api/multihop/saved-candidates/catalog?prefix_position=0&scope=saved-prefix-local",nil,25,true)
admit("/api/multihop/prefix-candidates/catalog?prefix_position=0&scope=saved-prefix-local",nil,25,false)
admit("/api/multihop/saved-candidates/catalog?scope=saved-prefix-local&prefix_position=0",nil,25,false)
admit("/api/multihop/saved-candidates/catalog?prefix_position=0&scope=saved-prefix-local&scope=saved-prefix-local",nil,25,false)
admit("/api/multihop/saved-candidates/catalog?prefix_position=0&scope=foreign",nil,25,false)
var prefixRun=run;prefixRun["scope"]="saved-prefix-local";admit("/api/multihop/saved-candidates",prefixRun,180,true)
admit("/api/multihop/prefix-candidates",prefixRun,180,false)
prefixRun["scope"]=true;admit("/api/multihop/saved-candidates",prefixRun,180,false)
prefixRun["scope"]="foreign";admit("/api/multihop/saved-candidates",prefixRun,180,false)
admit("/api/multihop/saved-candidates/cancel",["request_id":id,"view_token":view,"scope":"saved-prefix-local"],25,true)
let streamPath=[["id":"entry","mode":"wg"],["id":"imported","mode":"shadowsocks"],["id":"original","mode":"shadowsocks"]]
let streamDraft:[String:Any]=["execution":"local","nodes":streamPath,"expected_selected_node_id":"original","expected_profile_tokens":["entry":view,"imported":view,"original":view]]
admit("/api/multihop/draft-candidates/catalog?prefix_position=1&scope=saved-prefix-local",streamDraft,25,true)
var selectedStream=streamDraft;selectedStream["execution"]="server"
admit("/api/multihop/draft-candidates/catalog?prefix_position=1&scope=draft-complete-selected",selectedStream,25,false)
for packet in ["wg","awg2-fast","awg2-strong"] {
 var qualified=streamDraft
 var path=streamPath;path[0]["mode"]=packet;qualified["nodes"]=path
 admit("/api/multihop/draft-candidates/catalog?prefix_position=1&scope=saved-prefix-local",qualified,25,true)
 path.insert(["id":"second","mode":packet],at:1);qualified["nodes"]=path;qualified["expected_profile_tokens"]=["entry":view,"second":view,"imported":view,"original":view]
 admit("/api/multihop/draft-candidates/catalog?prefix_position=2&scope=saved-prefix-local",qualified,25,true)
 path.swapAt(1,2);path.insert(["id":"later","mode":"shadowsocks"],at:3);qualified["nodes"]=path;qualified["expected_profile_tokens"]=["entry":view,"second":view,"imported":view,"later":view,"original":view]
 admit("/api/multihop/draft-candidates/catalog?prefix_position=3&scope=saved-prefix-local",qualified,25,false)
}
let deepPath=(0..<16).map { ["id":"deep-"+String($0),"mode":$0 == 15 ? "shadowsocks":"wg"] }
let deep:[String:Any]=["execution":"local","nodes":deepPath,"expected_selected_node_id":"deep-15","expected_profile_tokens":Dictionary(uniqueKeysWithValues:deepPath.map {($0["id"]!,view)})]
admit("/api/multihop/draft-candidates/catalog?prefix_position=8&scope=saved-prefix-local",deep,25,true)
var deepServer=deep;deepServer["execution"]="server";admit("/api/multihop/draft-candidates/catalog?prefix_position=8&scope=draft-complete-selected",deepServer,25,false)
var deepMixed=deep;var deepNodes=deepPath;deepNodes[8]["mode"]="awg2-fast";deepMixed["nodes"]=deepNodes;admit("/api/multihop/draft-candidates/catalog?prefix_position=8&scope=saved-prefix-local",deepMixed,25,false)
var deepSS=deep
var deepImports=deepPath
for i in 1..<deepImports.count { deepImports[i]["mode"]="shadowsocks" }
deepSS["nodes"]=deepImports
for at in [7,8,14] { admit("/api/multihop/draft-candidates/catalog?prefix_position=" + String(at) + "&scope=saved-prefix-local",deepSS,25,true) }
admit("/api/multihop/draft-candidates/catalog?prefix_position=15&scope=saved-prefix-local",deepSS,25,false)
var mixedAfter=deepSS;var foreignSuffix=deepImports;foreignSuffix[13]["mode"]="wg";mixedAfter["nodes"]=foreignSuffix
admit("/api/multihop/draft-candidates/catalog?prefix_position=8&scope=saved-prefix-local",mixedAfter,25,false)
for packets in [2,9] {
 var qualified=deepSS;var path=deepImports
 for i in 0..<packets { path[i]["mode"]=i%2==0 ? "awg2-strong":"wg" };qualified["nodes"]=path
 for pos in [0,packets-1,packets,14] {admit("/api/multihop/draft-candidates/catalog?prefix_position="+String(pos)+"&scope=saved-prefix-local",qualified,25,true)}
 qualified["execution"]="auto";admit("/api/multihop/draft-candidates/catalog?prefix_position=8&scope=draft-complete-selected",qualified,25,false)
}
var selectedDeepSS=deepSS;selectedDeepSS["execution"]="auto"
admit("/api/multihop/draft-candidates/catalog?prefix_position=8&scope=draft-complete-selected",selectedDeepSS,25,false)
var deepRun=run;deepRun["prefix_position"]=8;deepRun["scope"]="saved-prefix-local";admit("/api/multihop/draft-candidates",deepRun,180,true)
deepRun["scope"]="draft-complete-selected";admit("/api/multihop/draft-candidates",deepRun,180,false)
let namedFinalBody:[String:Any]=["request_id":id,"view_token":view,"scope":"saved-prefix-local","candidate_id":"original","name":"Explicit future final","proposed_path":[["id":"entry","mode":"wg"],["id":"imported","mode":"shadowsocks"],["id":"original","mode":"shadowsocks"]]]
admit("/api/multihop/draft-candidates/save-profile",namedFinalBody,25,true)
var crossScope=namedFinalBody;crossScope["scope"]="draft-complete-selected";admit("/api/multihop/draft-candidates/save-profile",crossScope,25,false)
var emptyName=namedFinalBody;emptyName["name"]="";admit("/api/multihop/draft-candidates/save-profile",emptyName,25,false)
admit("/api/multihop/draft-candidates/choose",namedFinalBody,25,false)
admit("/api/multihop/saved-candidates/save-profile",["request_id":id,"view_token":view,"scope":"saved-prefix-local","candidate_id":"original","name":"Explicit prefix next","proposed_path":[["id":"entry","mode":"wg"],["id":"original","mode":"shadowsocks"]]],25,true)
'''
    harness=harness.replace(marker,'do {\n'+saved+'}\n'+extra+marker,1)
    path.write_text(transport+harness)
    subprocess.run(['swiftc','-swift-version','5','-module-cache-path',str(directory/'cache'),str(path),'-o',str(directory/'transport')],check=True,timeout=120)
    subprocess.run([str(directory/'transport')],check=True,timeout=30)

def linux_policy(directory):
    """Compile actual shipping guards without an X display; HTTP is a boundary."""
    import importlib.util
    spec=importlib.util.spec_from_file_location('ordered_linux_mutation',ROOT/'client/linux/apply-session-mutation.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    composed=directory/'routervpn-gtk-product.c';module.apply(ROOT/'client/linux/routervpn-gtk-product.c',composed)
    source=composed.read_text()
    guards='\n'.join(block(source,'static gboolean '+name+'(') for name in ['routervpn_phase_busy','routervpn_mutation_busy_from_status','routervpn_mutation_busy'])
    candidates=(ROOT/'client/linux/routervpn-ordered-candidates-v1.inc').read_text()
    helpers=(ROOT/'client/linux/routervpn-telemetry-v9.inc').read_text()
    declarations=candidates[candidates.index('typedef struct {'):candidates.index('} LinuxOrderedCandidates;')+len('} LinuxOrderedCandidates;')]
    guards+='\n'+declarations+'\n'+'\n'.join(block(helpers,marker) for marker in ['static JsonNode *linux_ec_member(', 'static const char *linux_ec_string(', 'static gboolean linux_ec_bool(', 'static double linux_ec_number(', 'static JsonArray *linux_ec_array(', 'static JsonObject *linux_ec_object('])+'\n'+'\n'.join(block(candidates,marker) for marker in ['static const char*linux_oc_measurement_kind(', 'static const char*linux_oc_prefix_measurement(', 'static gboolean linux_oc_catalog_measurement(', 'static double linux_oc_score(', 'static JsonObject*linux_oc_root(', 'static gboolean linux_oc_same_measurement(', 'static double linux_oc_current_score(', 'static const char*linux_oc_scope(', 'static gboolean linux_oc_draft_execution(', 'static gboolean linux_oc_saved_envelope(', 'static gboolean linux_oc_before_start(', 'static gboolean linux_oc_ready(', 'static gboolean linux_oc_final_choice(', 'static gboolean linux_oc_final_saved(', 'static gboolean linux_oc_view_fresh('])
    program=r"""
#include <gtk/gtk.h>
#include <glib-object.h>
#include <math.h>
#include <json-glib/json-glib.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
typedef struct{GObject*window;}App;
typedef struct{char*data;}Buffer;
typedef struct RVHttpJobV16 RVHttpJobV16;
static unsigned checks,calls;
static gboolean linux_async_busy_v16(App*a){(void)a;return FALSE;}
static gboolean api_request(const char*p,const char*m,const char*b,long ms,Buffer*out,char**e){(void)p;(void)m;(void)b;(void)ms;(void)e;calls++;out->data=g_strdup("{\"connected\":false,\"phase\":\"off\"}");return TRUE;}
static JsonNode*parse_json(const char*raw){JsonParser*p=json_parser_new();g_assert(json_parser_load_from_data(p,raw,-1,NULL));JsonNode*n=json_node_copy(json_parser_get_root(p));g_object_unref(p);return n;}
static const char*obj_string(JsonObject*o,const char*k){return json_object_has_member(o,k)?json_object_get_string_member(o,k):"";}
SHIPPING_GUARDS
static void check(gboolean ok,const char*message){checks++;if(!ok){fprintf(stderr,"SAVED-GTK-GUARD: %s\n",message);exit(1);}}
int main(void){
 check(routervpn_phase_busy("candidate:testing"),"temporary candidate phase was treated as idle");
 check(!routervpn_phase_busy("off")&&!routervpn_phase_busy("failed")&&routervpn_phase_busy("proving")&&routervpn_phase_busy("disconnecting"),"ordinary phase behavior changed");
 JsonNode*n=parse_json("{\"connected\":false,\"phase\":\"candidate:testing\"}");check(routervpn_mutation_busy_from_status(json_node_get_object(n)),"candidate status lost its transition guard");json_node_free(n);
 n=parse_json("{\"expires_at\":1001}");check(linux_oc_view_fresh(json_node_get_object(n),1000),"fresh catalog rejected");check(!linux_oc_view_fresh(json_node_get_object(n),1001),"expired catalog retained test admission");json_object_remove_member(json_node_get_object(n),"expires_at");check(!linux_oc_view_fresh(json_node_get_object(n),1000),"missing catalog expiry retained test admission");json_object_set_double_member(json_node_get_object(n),"expires_at",NAN);check(!linux_oc_view_fresh(json_node_get_object(n),1000),"nonfinite catalog expiry retained test admission");json_node_free(n);
 App app={.window=g_object_new(G_TYPE_OBJECT,NULL)};check(!routervpn_mutation_busy(&app),"ordinary DOWN status did not permit mutation");unsigned original=calls;
 g_object_set_data(app.window,"linux-ordered-candidates-pending",&app);
 check(routervpn_mutation_busy(&app)&&calls==original,"retained DOWN review did not block mutation before HTTP");
 g_object_set_data(app.window,"linux-ordered-candidates-pending",NULL);check(!routervpn_mutation_busy(&app),"joined review did not release mutation guard");g_object_unref(app.window);
 JsonNode*view=parse_json("{\"scope\":\"saved-complete-local\",\"measurement\":\"routed-tcp-connect\"}");
 n=parse_json("{\"schema\":1,\"scope\":\"saved-complete-local\",\"measurement\":\"routed-tcp-connect\",\"samples\":50,\"prefix_position\":0,\"active_path_changed\":false,\"accepted\":true,\"native_down\":false,\"reviewing\":true,\"cleanup_pending\":false}");LinuxOrderedCandidates candidate={.saved_path=TRUE,.pending=TRUE,.receipt=n,.view=view};JsonObject*r=json_node_get_object(n);
 check(!linux_oc_ready(&candidate),"saved results were available before native DOWN");json_object_set_boolean_member(r,"native_down",TRUE);check(linux_oc_ready(&candidate),"DOWN observer review incorrectly required full owner drain");
 const char*foreign_scopes[]={"connected-prefix","saved-prefix-local",""};
 for(unsigned i=0;i<3;i++){json_object_set_string_member(r,"scope",foreign_scopes[i]);check(!linux_oc_saved_envelope(&candidate,r,TRUE),"foreign saved catalog scope accepted");check(!linux_oc_ready(&candidate),"foreign saved response scope offered adoption");}json_object_set_string_member(r,"scope","saved-complete-local");
 json_object_set_int_member(r,"prefix_position",1);check(!linux_oc_saved_envelope(&candidate,r,TRUE)&&!linux_oc_ready(&candidate),"foreign saved prefix accepted");json_object_remove_member(r,"prefix_position");check(!linux_oc_saved_envelope(&candidate,r,TRUE)&&!linux_oc_ready(&candidate),"missing saved prefix accepted");json_object_set_string_member(r,"prefix_position","0");check(!linux_oc_saved_envelope(&candidate,r,TRUE)&&!linux_oc_ready(&candidate),"string saved prefix accepted");json_object_set_int_member(r,"prefix_position",0);
 json_object_set_string_member(r,"schema","1");check(!linux_oc_saved_envelope(&candidate,r,TRUE)&&!linux_oc_ready(&candidate),"string saved schema accepted");json_object_set_int_member(r,"schema",1);
 json_object_set_string_member(r,"measurement","icmp");check(!linux_oc_saved_envelope(&candidate,r,TRUE)&&!linux_oc_ready(&candidate),"foreign saved measurement accepted");json_object_set_string_member(r,"measurement","routed-tcp-connect");
 json_object_remove_member(r,"active_path_changed");check(!linux_oc_ready(&candidate),"missing path-change proof accepted");json_object_set_string_member(r,"active_path_changed","false");check(!linux_oc_ready(&candidate),"string path-change proof accepted");json_object_set_boolean_member(r,"active_path_changed",TRUE);check(!linux_oc_ready(&candidate),"changed saved path offered adoption");json_object_set_boolean_member(r,"active_path_changed",FALSE);
 json_object_set_string_member(json_node_get_object(view),"scope","connected-prefix");check(!linux_oc_ready(&candidate),"changed captured purpose offered adoption");json_object_set_string_member(json_node_get_object(view),"scope","saved-complete-local");
 json_object_set_boolean_member(r,"reviewing",FALSE);check(!linux_oc_ready(&candidate),"closed review retained adoption");json_object_set_boolean_member(r,"reviewing",TRUE);
 json_object_set_boolean_member(r,"cleanup_pending",TRUE);check(!linux_oc_ready(&candidate),"cleanup failure permitted adoption");json_object_set_boolean_member(r,"cleanup_pending",FALSE);
 candidate.close_wanted=TRUE;check(!linux_oc_ready(&candidate),"closing review retained adoption");candidate.close_wanted=FALSE;candidate.cancel_wanted=TRUE;check(!linux_oc_ready(&candidate),"cancelled review retained adoption");candidate.cancel_wanted=FALSE;
 strcpy(candidate.saved_profile,"original-write");check(!linux_oc_ready(&candidate),"committed profile offered repeat adoption");candidate.saved_profile[0]=0;json_object_set_boolean_member(r,"accepted",FALSE);check(!linux_oc_ready(&candidate),"invalidated review retained adoption");
 json_object_set_boolean_member(r,"admission_cancelled",TRUE);check(!linux_oc_before_start(r),"missing started field proved no admission");json_object_set_boolean_member(r,"started",TRUE);check(!linux_oc_before_start(r),"started owner bypassed native retirement");json_object_set_string_member(r,"started","false");check(!linux_oc_before_start(r),"string started value became an absence receipt");json_object_set_boolean_member(r,"started",FALSE);check(linux_oc_before_start(r),"explicit original tombstone was not recognized");json_object_set_boolean_member(r,"accepted",TRUE);check(!linux_oc_ready(&candidate),"never-started cancellation exposed results");json_node_free(n);

 n=parse_json("{\"schema\":1,\"scope\":\"saved-prefix-local\",\"measurement\":\"routed-tcp-connect\",\"samples\":50,\"prefix_position\":0,\"active_path_changed\":false,\"accepted\":true,\"native_down\":true,\"reviewing\":true,\"cleanup_pending\":false,\"application_open\":false,\"dns_open\":false,\"proof_scope\":\"selected-prefix\"}");candidate.receipt=n;candidate.saved_prefix=TRUE;r=json_node_get_object(n);json_object_set_string_member(json_node_get_object(view),"scope","saved-prefix-local");
 check(linux_oc_saved_envelope(&candidate,r,TRUE)&&linux_oc_ready(&candidate),"closed prefix catalog and DOWN review rejected");
 const char*closed_fields[]={"application_open","dns_open"};char witness[128];
 for(unsigned i=0;i<2;i++){json_object_remove_member(r,closed_fields[i]);snprintf(witness,sizeof(witness),"prefix guard accepted missing %s",closed_fields[i]);check(!linux_oc_saved_envelope(&candidate,r,TRUE)&&!linux_oc_ready(&candidate),witness);json_object_set_string_member(r,closed_fields[i],"false");check(!linux_oc_saved_envelope(&candidate,r,TRUE)&&!linux_oc_ready(&candidate),"string closed flag became prefix proof");json_object_set_boolean_member(r,closed_fields[i],TRUE);check(!linux_oc_saved_envelope(&candidate,r,TRUE)&&!linux_oc_ready(&candidate),"open ingress became prefix proof");json_object_set_boolean_member(r,closed_fields[i],FALSE);}
 json_object_set_string_member(r,"proof_scope","ordinary-path");check(!linux_oc_saved_envelope(&candidate,r,TRUE)&&!linux_oc_ready(&candidate),"foreign prefix proof scope accepted");json_object_remove_member(r,"proof_scope");check(!linux_oc_saved_envelope(&candidate,r,TRUE)&&!linux_oc_ready(&candidate),"missing prefix proof scope accepted");json_object_set_string_member(r,"proof_scope","selected-prefix");
 json_object_set_string_member(r,"scope","saved-complete-local");check(!linux_oc_saved_envelope(&candidate,r,TRUE)&&!linux_oc_ready(&candidate),"complete saved path substituted for prefix preparation");json_object_set_string_member(r,"scope","saved-prefix-local");json_object_set_boolean_member(r,"native_down",FALSE);check(!linux_oc_ready(&candidate),"prefix review bypassed original native DOWN");json_object_set_boolean_member(r,"native_down",TRUE);check(linux_oc_ready(&candidate),"restored exact prefix review rejected");json_node_free(n);
 json_node_free(view);
 JsonNode*response_view=parse_json("{\"measurement\":\"routed-candidate-response\",\"samples\":50,\"prefixes\":[{\"position\":1,\"id\":\"middle\",\"mode\":\"shadowsocks\",\"measurement\":\"routed-candidate-response\"}],\"candidates\":[{\"id\":\"paired\",\"kind\":\"router-vpn\"}]}");
 JsonObject*cv=linux_oc_root(response_view),*prefix=json_array_get_object_element(linux_ec_array(cv,"prefixes"),0);candidate.view=response_view;
 check(linux_oc_catalog_measurement(cv,1),"qualified stream prefix rejected its response metric");
 check(!linux_oc_catalog_measurement(cv,0)&&!linux_oc_catalog_measurement(cv,7)&&!linux_oc_catalog_measurement(cv,96),"catalog supplied an uncaptured or out-of-bound prefix");
 json_object_remove_member(prefix,"measurement");check(!linux_oc_catalog_measurement(cv,1),"stream prefix without native response capability was offered");json_object_set_string_member(prefix,"measurement","routed-candidate-response");
 json_object_set_string_member(prefix,"mode","wg");check(!linux_oc_catalog_measurement(cv,1),"packet prefix borrowed the stream response metric");json_object_set_string_member(prefix,"mode","shadowsocks");
 json_object_set_string_member(cv,"measurement","routed-tcp-connect");check(!linux_oc_catalog_measurement(cv,1),"stream prefix borrowed packet TCP timing");json_object_set_string_member(cv,"measurement","routed-candidate-response");
 JsonArray*prefixes=linux_ec_array(cv,"prefixes");json_array_add_object_element(prefixes,json_object_ref(prefix));check(!linux_oc_catalog_measurement(cv,1),"duplicate selected prefix admitted mixed authority");json_array_remove_element(prefixes,1);
 JsonNode*response=parse_json("{\"schema\":1,\"measurement\":\"routed-candidate-response\",\"complete\":true,\"drained\":true,\"stage\":\"complete\",\"candidate_id\":\"paired\",\"measured_at\":1000,\"expires_at\":121000,\"results\":[{\"node_id\":\"paired\",\"role\":\"candidate\",\"kind\":\"private-agent-response\",\"ready\":true,\"benchmark\":{\"schema\":1,\"measurement\":\"routed-candidate-response\",\"attempts\":50,\"failed\":0,\"trimmed_mean_ms\":2,\"distribution\":{\"samples\":50,\"min_ms\":1,\"max_ms\":3}}}]}");
 JsonObject*cr=linux_oc_root(response),*rr=json_array_get_object_element(linux_ec_array(cr,"results"),0),*benchmark=linux_ec_object(rr,"benchmark"),*distribution=linux_ec_object(benchmark,"distribution");
 check(linux_oc_current_score(&candidate,cr,1000)==2,"complete matching response score rejected");
 JsonObject*paired=json_array_get_object_element(linux_ec_array(cv,"candidates"),0);
 json_object_set_string_member(paired,"kind","external");check(isnan(linux_oc_current_score(&candidate,cr,1000)),"imported candidate borrowed a private-agent response");json_object_set_string_member(paired,"kind","router-vpn");
 json_object_remove_member(paired,"kind");check(isnan(linux_oc_current_score(&candidate,cr,1000)),"unqualified candidate borrowed a private-agent response");json_object_set_string_member(paired,"kind","router-vpn");
 JsonArray*paired_rows=linux_ec_array(cv,"candidates");json_array_add_object_element(paired_rows,json_object_ref(paired));check(isnan(linux_oc_current_score(&candidate,cr,1000)),"duplicate candidate source earned a response score");json_array_remove_element(paired_rows,1);
 check(isnan(linux_oc_current_score(&candidate,cr,999))&&isnan(linux_oc_current_score(&candidate,cr,121000)),"response accepted a future or expired sample");
 json_object_set_string_member(cv,"measurement","routed-tcp-connect");check(isnan(linux_oc_current_score(&candidate,cr,1000)),"authenticated response was pooled with TCP scores");json_object_set_string_member(cv,"measurement","routed-candidate-response");
 json_object_set_string_member(benchmark,"measurement","routed-tcp-connect");check(isnan(linux_oc_current_score(&candidate,cr,1000)),"response borrowed a TCP benchmark");json_object_set_string_member(benchmark,"measurement","routed-candidate-response");
 json_object_set_string_member(rr,"kind","tcp-connect");check(isnan(linux_oc_current_score(&candidate,cr,1000)),"TCP connection masqueraded as authenticated response");json_object_set_string_member(rr,"kind","private-agent-response");
 json_object_set_string_member(cr,"measurement","routed-tcp-connect");check(isnan(linux_oc_current_score(&candidate,cr,1000)),"response borrowed a foreign outer metric");json_object_set_string_member(cr,"measurement","routed-candidate-response");
 json_object_set_string_member(rr,"node_id","foreign");check(isnan(linux_oc_current_score(&candidate,cr,1000)),"response borrowed another candidate");json_object_set_string_member(rr,"node_id","paired");
 json_object_set_int_member(benchmark,"attempts",49);check(isnan(linux_oc_current_score(&candidate,cr,1000)),"partial response attempts earned a score");json_object_set_int_member(benchmark,"attempts",50);
 json_object_set_int_member(distribution,"samples",49);check(isnan(linux_oc_current_score(&candidate,cr,1000)),"partial response distribution earned a score");json_object_set_int_member(distribution,"samples",50);
 json_object_set_int_member(benchmark,"failed",1);check(isnan(linux_oc_current_score(&candidate,cr,1000)),"failed response earned a score");json_object_set_int_member(benchmark,"failed",0);
 json_object_set_boolean_member(cr,"drained",FALSE);check(isnan(linux_oc_current_score(&candidate,cr,1000)),"undrained response earned a score");json_object_set_boolean_member(cr,"drained",TRUE);
 json_object_set_string_member(cr,"measurement","unknown");check(isnan(linux_oc_score(cr,1000)),"unqualified measurement earned a score");

 json_object_set_string_member(cr,"measurement","routed-candidate-response");
 const char*selected_modes[]={"server","auto"};
 for(unsigned i=0;i<2;i++){json_object_set_string_member(cv,"requested_execution",selected_modes[i]);check(!linux_oc_catalog_measurement(cv,1),"response catalog borrowed selected execution");}json_object_remove_member(cv,"requested_execution");
 json_object_set_string_member(cv,"scope","draft-complete-selected");check(!linux_oc_catalog_measurement(cv,1),"response catalog borrowed complete selected scope");json_object_remove_member(cv,"scope");
 candidate.draft="captured";candidate.draft_source=parse_json("{\"execution\":\"local\",\"nodes\":[{\"id\":\"entry\",\"mode\":\"wg\"},{\"id\":\"middle\",\"mode\":\"shadowsocks\"},{\"id\":\"final\",\"mode\":\"shadowsocks\"}]}");candidate.position=1;
 json_object_set_string_member(paired,"proposal_action","save-final-profile");
 JsonNode*proposal=parse_json("[{\"id\":\"entry\",\"mode\":\"wg\"},{\"id\":\"middle\",\"mode\":\"shadowsocks\"},{\"id\":\"paired\",\"mode\":\"shadowsocks\"}]");json_object_set_member(paired,"proposed_path",proposal);
 check(linux_oc_final_choice(&candidate,paired),"original named final proposal was rejected");
 json_object_remove_member(paired,"proposal_action");check(!linux_oc_final_choice(&candidate,paired),"response draft invented final replacement authority");json_object_set_string_member(paired,"proposal_action","save-final-profile");
 JsonObject*first=json_array_get_object_element(json_node_get_array(proposal),0);json_object_set_string_member(first,"id","substitute");check(!linux_oc_final_choice(&candidate,paired),"named final save changed an original upstream member");json_object_set_string_member(first,"id","entry");
 JsonObject*last=json_array_get_object_element(json_node_get_array(proposal),2);json_object_set_string_member(last,"mode","wg");check(!linux_oc_final_choice(&candidate,paired),"named final save relabelled candidate transport");json_object_set_string_member(last,"mode","shadowsocks");
 json_object_set_string_member(paired,"kind","external");check(!linux_oc_final_choice(&candidate,paired),"named final save borrowed an imported candidate");json_object_set_string_member(paired,"kind","router-vpn");
 json_object_set_string_member(linux_oc_root(candidate.draft_source),"execution","server");check(!linux_oc_final_choice(&candidate,paired),"named final save borrowed Server scope");json_object_set_string_member(linux_oc_root(candidate.draft_source),"execution","local");
 candidate.position=0;check(!linux_oc_final_choice(&candidate,paired),"named final save truncated an interior suffix");candidate.position=1;
 candidate.final_save=TRUE;candidate.chosen_id="paired";json_object_set_string_member(cr,"proposal_action","save-final-profile");json_object_set_member(cr,"proposed_path",json_node_copy(proposal));
 check(linux_oc_final_saved(&candidate,cr),"named saved receipt lost original proposal");
 json_object_set_boolean_member(cr,"chosen",TRUE);check(!linux_oc_final_saved(&candidate,cr),"named save accepted a live editor adoption");json_object_set_boolean_member(cr,"chosen",FALSE);
 json_object_set_string_member(cr,"candidate_id","foreign");check(!linux_oc_final_saved(&candidate,cr),"named save borrowed a different candidate");json_object_set_string_member(cr,"candidate_id","paired");
 JsonObject*saved_first=json_array_get_object_element(linux_ec_array(cr,"proposed_path"),0);json_object_set_string_member(saved_first,"id","foreign");check(!linux_oc_final_saved(&candidate,cr),"named saved receipt changed original prefix");json_object_set_string_member(saved_first,"id","entry");
 json_object_remove_member(cr,"proposal_action");check(!linux_oc_final_saved(&candidate,cr),"named saved receipt lost explicit proposal action");

 JsonArray*deep_nodes=json_array_new(),*deep_proposal=json_array_new();
 for(guint i=0;i<16;i++){
  char*id=i==0?g_strdup("entry"):i==15?g_strdup("final"):g_strdup_printf("middle-%u",i);const char*mode=i?"shadowsocks":"wg";
  JsonObject*before=json_object_new(),*after=json_object_new();json_object_set_string_member(before,"id",id);json_object_set_string_member(before,"mode",mode);json_object_set_string_member(after,"id",i==15?"paired":id);json_object_set_string_member(after,"mode",mode);json_array_add_object_element(deep_nodes,before);json_array_add_object_element(deep_proposal,after);g_free(id);
 }
 json_object_set_array_member(linux_oc_root(candidate.draft_source),"nodes",deep_nodes);json_object_set_array_member(paired,"proposed_path",deep_proposal);candidate.position=14;
 json_object_set_int_member(prefix,"position",14);json_object_set_string_member(prefix,"id","middle-14");
 check(linux_oc_catalog_measurement(cv,14)&&linux_oc_final_choice(&candidate,paired),"qualified late stream lost its complete named final proposal");
 json_object_set_int_member(prefix,"position",95);check(!linux_oc_catalog_measurement(cv,95),"physical final acquired next-candidate authority");json_object_set_int_member(prefix,"position",14);
 json_object_set_string_member(cr,"proposal_action","save-final-profile");json_object_set_member(cr,"proposed_path",json_node_copy(linux_ec_member(paired,"proposed_path")));
 check(linux_oc_final_saved(&candidate,cr),"late saved response lost complete original proposal");
 JsonObject*deep_before=json_array_get_object_element(deep_nodes,8),*deep_after=json_array_get_object_element(deep_proposal,8);
 json_object_set_string_member(deep_before,"mode","wg");json_object_set_string_member(deep_after,"mode","wg");check(!linux_oc_final_choice(&candidate,paired),"late stream proposal borrowed a mixed packet family");
 json_object_set_string_member(deep_before,"mode","shadowsocks");json_object_set_string_member(deep_after,"mode","shadowsocks");
 json_object_set_string_member(deep_after,"id","substitute-late");check(!linux_oc_final_choice(&candidate,paired),"late named final replaced an earlier imported identity");
 JsonNode*packet_original=parse_json("[{\"id\":\"entry\",\"mode\":\"awg2-strong\"},{\"id\":\"packet\",\"mode\":\"wg\"},{\"id\":\"middle\",\"mode\":\"shadowsocks\"},{\"id\":\"final\",\"mode\":\"shadowsocks\"}]");
 char*packet_json=json_to_string(packet_original,FALSE);JsonNode*packet_proposal=parse_json(packet_json);g_free(packet_json);json_object_set_string_member(json_array_get_object_element(json_node_get_array(packet_proposal),3),"id","paired");
 json_object_set_member(linux_oc_root(candidate.draft_source),"nodes",packet_original);json_object_set_member(paired,"proposed_path",packet_proposal);candidate.position=2;
 check(linux_oc_final_choice(&candidate,paired),"original AWG and packet prefix lost its named measured final");
 JsonObject*packet_before=json_array_get_object_element(json_node_get_array(packet_original),0),*packet_after=json_array_get_object_element(json_node_get_array(packet_proposal),0);
 json_object_set_string_member(packet_before,"mode","wg-pq");json_object_set_string_member(packet_after,"mode","wg-pq");check(!linux_oc_final_choice(&candidate,paired),"response proposal borrowed an unqualified packet transport");
 json_node_free(candidate.draft_source);json_node_free(response);json_node_free(response_view);
 printf("Shipping GTK candidate status guards: %u checks PASS; actual GObject, controlled HTTP.\n",checks);return 0;
}
"""
    flags=subprocess.check_output(['pkg-config','--cflags','--libs','gtk+-3.0','gobject-2.0','json-glib-1.0'],text=True).split()
    controls=[('phase',' || g_str_has_prefix(lower, "candidate:")','', 'temporary candidate phase was treated as idle'),('review','if(app&&app->window&&g_object_get_data(G_OBJECT(app->window),"linux-ordered-candidates-pending")!=NULL)return TRUE;','', 'retained DOWN review did not block mutation before HTTP')]
    controls.append(('native-down','linux_ec_bool(receipt,"native_down")&&','', 'saved results were available before native DOWN'))
    controls.append(('purpose','strcmp(linux_ec_string(o,"scope"),linux_oc_scope(s))||','strcmp(linux_oc_scope(s),linux_oc_scope(s))||', 'foreign saved catalog scope accepted'))
    controls.append(('prefix','linux_ec_number(o,"prefix_position")!=s->position||','', 'foreign saved prefix accepted'))
    controls.append(('prefix-application','for(unsigned i=0;i<2;i++)','for(unsigned i=1;i<2;i++)','prefix guard accepted missing application_open'))
    controls.append(('prefix-dns','for(unsigned i=0;i<2;i++)','for(unsigned i=0;i<1;i++)','prefix guard accepted missing dns_open'))
    controls.append(('prefix-proof','if(strcmp(linux_ec_string(o,"proof_scope"),"selected-prefix"))return FALSE;','','foreign prefix proof scope accepted'))
    controls.append(('final-action','strcmp(linux_ec_string(choice,"proposal_action"),"save-final-profile")||','','response draft invented final replacement authority'))
    controls.append(('final-prefix','!json_node_equal(node,json_array_get_element(proposed,i))||','','named final save changed an original upstream member'))
    for label,before,after,witness in [('baseline','','',''),*controls]:
        text=guards
        if before:
            assert text.count(before)==1,label
            text=text.replace(before,after,1)
        path=directory/'candidate-guards.c';path.write_text(program.replace('SHIPPING_GUARDS',text));binary=directory/'candidate-guards'
        subprocess.run(['gcc','-O1','-Wall','-Wextra','-Werror',str(path),'-o',str(binary),*flags],check=True,timeout=60)
        result=subprocess.run([str(binary)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15)
        if witness:
            assert result.returncode!=0 and witness in result.stdout,(label,result.stdout)
        else:
            assert result.returncode==0,result.stdout
            print(result.stdout.strip(),flush=True)
    print('GTK candidate phase, retained-review, native-DOWN, purpose, prefix, closed-proof and named-final causal controls: 10 PASS',flush=True)

def linux_actions(directory):
    source=(ROOT/'client/linux/routervpn-performance-v17.inc').read_text()
    fields=source[source.index('typedef struct {'):source.index('} LinuxPerformanceV17;')+len('} LinuxPerformanceV17;')]
    action=block(source,'static void linux_performance_response_v17(')
    program=r'''
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <stdio.h>
typedef struct {void *window;} App;
FIELDS
static gboolean busy,saved_path,saved_prefix;
static unsigned launches,latency_launches,checks;
static App*latency_app;
static void check(gboolean ok,const char*message){checks++;if(!ok)g_error("%s",message);}
static gboolean linux_async_busy_v16(App*a){(void)a;return busy;}
static void linux_async_cancel_request_v17(App*a,guint64 generation){(void)a;(void)generation;}
static const char*active_router_id(App*a){(void)a;return "original";}
static void linux_mtu_dialog_v20(App*a){(void)a;}
static void linux_external_comparison_open(App*a){(void)a;}
static void linux_performance_begin_v17(LinuxPerformanceV17*p,const char*path,const char*body,long timeout,gboolean get){(void)p;(void)path;(void)body;(void)timeout;(void)get;g_error("candidate button issued ordinary measurement");}
/* Only destination dialog construction is doubled. Actual signal dispatch,
 * captured purpose arguments and asynchronous busy guards are unchanged. */
static void linux_ordered_candidates_open_captured(App*a,gboolean path,gboolean prefix){(void)a;launches++;saved_path=path;saved_prefix=prefix;}
static void linux_ordered_candidates_open_purpose(App*a,gboolean path){linux_ordered_candidates_open_captured(a,path,FALSE);}
static void linux_ordered_candidates_open(App*a){linux_ordered_candidates_open_captured(a,FALSE,FALSE);}
static void linux_ordered_latency_open_v1(App*a){latency_launches++;latency_app=a;}
ACTION
int main(void){
 App app={0};LinuxPerformanceV17 panel={.app=&app};
 linux_performance_response_v17(NULL,8,&panel);check(launches==1&&!saved_path&&!saved_prefix,"connected button changed purpose");
 linux_performance_response_v17(NULL,9,&panel);check(launches==2&&saved_path&&!saved_prefix,"complete saved button changed purpose");
 linux_performance_response_v17(NULL,10,&panel);check(launches==3&&saved_path&&saved_prefix,"prefix button launched complete saved connection");
 panel.generation=1;linux_performance_response_v17(NULL,10,&panel);check(launches==3,"pending Performance launched prefix test");
 panel.generation=0;busy=TRUE;linux_performance_response_v17(NULL,10,&panel);check(launches==3,"busy Performance launched prefix test");
 busy=FALSE;linux_performance_response_v17(NULL,10,&panel);check(launches==4&&saved_path&&saved_prefix,"settled Performance lost prefix purpose");
 linux_performance_response_v17(NULL,11,&panel);check(latency_launches==1&&latency_app==&app&&launches==4,"ordered latency button lost its captured application");
 panel.generation=1;linux_performance_response_v17(NULL,11,&panel);check(latency_launches==1,"pending Performance launched ordered latency");
 panel.generation=0;busy=TRUE;linux_performance_response_v17(NULL,11,&panel);check(latency_launches==1,"busy Performance launched ordered latency");
 busy=FALSE;linux_performance_response_v17(NULL,11,&panel);check(latency_launches==2&&latency_app==&app&&launches==4,"settled Performance lost ordered latency");
 printf("GTK actual Performance candidate actions: %u checks PASS; dialog construction doubled.\n",checks);return 0;
}
'''.replace('FIELDS',fields).replace('ACTION',action)
    flags=subprocess.check_output(['pkg-config','--cflags','--libs','gtk+-3.0','json-glib-1.0'],text=True).split()
    anchor='linux_ordered_candidates_open_captured(p->app,TRUE,TRUE)'
    assert program.count(anchor)==1
    latency_anchor='linux_ordered_latency_open_v1(p->app)'
    assert program.count(latency_anchor)==1
    for label,before,after,witness in [
        ('positive','','',''),
        ('selected-prefix',anchor,'linux_ordered_candidates_open_captured(p->app,TRUE,FALSE)','prefix button launched complete saved connection'),
        ('ordered-latency',latency_anchor,'linux_ordered_latency_open_v1(NULL)','ordered latency button lost its captured application'),
    ]:
        path=directory/'performance-candidate-actions.c';binary=directory/'performance-candidate-actions'
        path.write_text(program.replace(before,after,1) if witness else program)
        subprocess.run(['gcc','-O1','-Wall','-Wextra','-Werror',str(path),'-o',str(binary),*flags],check=True,timeout=60)
        result=subprocess.run([str(binary)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15)
        if witness:
            assert result.returncode!=0 and witness in result.stdout,result.stdout
            print('GTK '+label+' button ownership control rejected',flush=True)
        else:
            assert result.returncode==0,result.stdout
            print(result.stdout.strip(),flush=True)


def linux_form(directory):
    import json, os, time
    source=(ROOT/'client/linux/routervpn-telemetry-v9.inc').read_text()
    helpers=source[source.index('static JsonNode *linux_ec_member'):source.index('static void linux_ec_lease')]
    methods=(ROOT/'client/linux/routervpn-ordered-candidates-v1.inc').read_text()
    now=int(time.time()*1000)
    path=[{'id':'entry','mode':'wg'},{'id':'custom','mode':'shadowsocks'},{'id':'final','mode':'shadowsocks'}]
    catalog={'schema':1,'scope':'saved-complete-local','measurement':'routed-tcp-connect','samples':50,'view_token':'a'*64,'prefix_position':0,'expires_at':now+120000,'prefixes':[{'position':0,'name':'Original entry','mode':'wg'}],'candidates':[{'id':'custom','name':'Original custom','proposed_path':path}]}
    row={'schema':1,'candidate_id':'custom','measurement':'routed-tcp-connect','stage':'complete','complete':True,'drained':True,'measured_at':now,'expires_at':now+120000,'results':[{'node_id':'custom','role':'candidate','kind':'tcp-connect','ready':True,'benchmark':{'schema':1,'measurement':'routed-tcp-connect','attempts':50,'failed':0,'trimmed_mean_ms':2.0,'distribution':{'samples':50,'min_ms':1.0,'median_ms':2.0,'average_ms':2.0,'p90_ms':3.0,'max_ms':3.0,'jitter_ms':0.0}}}]}
    response_catalog=json.loads(json.dumps(catalog))
    response_catalog.update(scope='saved-prefix-local',origin='editor-draft',measurement='routed-candidate-response',prefix_position=1,application_open=False,dns_open=False,proof_scope='selected-prefix')
    response_catalog['prefixes']=[{'position':1,'id':'middle','name':'Imported middle','mode':'shadowsocks','measurement':'routed-candidate-response'}]
    response_catalog['candidates']=[{'id':'paired','name':'Paired candidate','kind':'router-vpn','proposal_action':'save-final-profile','proposed_path':[{'id':'entry','mode':'wg'},{'id':'middle','mode':'shadowsocks'},{'id':'paired','mode':'shadowsocks'}]}]
    response_row=json.loads(json.dumps(row))
    response_row.update(candidate_id='paired',measurement='routed-candidate-response')
    response_row['results'][0].update(node_id='paired',kind='private-agent-response')
    response_row['results'][0]['benchmark']['measurement']='routed-candidate-response'
    deep_draft={'execution':'local','expected_selected_node_id':'final','nodes':[{'id':'entry' if i==0 else 'final' if i==15 else f'middle-{i}','mode':'wg' if i==0 else 'shadowsocks'} for i in range(16)]}
    deep_catalog=json.loads(json.dumps(response_catalog))
    deep_catalog['prefix_position']=14
    deep_catalog['prefixes'][0].update(position=14,id='middle-14')
    deep_catalog['candidates'][0]['proposed_path']=json.loads(json.dumps(deep_draft['nodes']))
    deep_catalog['candidates'][0]['proposed_path'][-1]['id']='paired'
    packet_draft={'execution':'local','expected_selected_node_id':'final','nodes':[{'id':'entry','mode':'awg2-strong'},{'id':'packet','mode':'wg'},{'id':'middle','mode':'shadowsocks'},{'id':'final','mode':'shadowsocks'}]}
    packet_catalog=json.loads(json.dumps(response_catalog));packet_catalog['prefix_position']=2;packet_catalog['prefixes'][0].update(position=2,id='middle')
    packet_catalog['candidates'][0]['proposed_path']=json.loads(json.dumps(packet_draft['nodes']));packet_catalog['candidates'][0]['proposed_path'][-1]['id']='paired'
    for name,value in [('catalog',catalog),('row',row),('response-catalog',response_catalog),('response-row',response_row),('deep-response-catalog',deep_catalog),('deep-response-draft',deep_draft),('packet-response-catalog',packet_catalog),('packet-response-draft',packet_draft)]: (directory/(name+'.json')).write_text(json.dumps(value))
    program=r'''
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <curl/curl.h>
#include <stdatomic.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
typedef struct {GtkWidget*window;} App;
typedef struct {gboolean closed;guint auxiliary_jobs;} LinuxAsyncActionsV16;
static LinuxAsyncActionsV16 async_state;
static guint checks,freed;
static gboolean busy;
static GPtrArray*paths,*bodies;
static const char*output;
static LinuxAsyncActionsV16*linux_async_state_v16(App*a){(void)a;return &async_state;}
static gboolean routervpn_require_mutation_idle(App*a,const char*label){(void)a;(void)label;return !busy;}
static JsonNode*parse_json(const char*raw){if(!raw)return NULL;JsonParser*p=json_parser_new();JsonNode*n=NULL;if(json_parser_load_from_data(p,raw,-1,NULL))n=json_node_copy(json_parser_get_root(p));g_object_unref(p);return n;}
/* Real widgets and shipping actions; only HTTP worker delivery is doubled. */
typedef struct {atomic_int cancelled;gboolean ready;CURLcode result;long status;char*response;} RVHttpJobV16;
static RVHttpJobV16*rv_http_start_method_v17(const char*path,const char*body,long timeout,const char*label,int get){(void)label;(void)get;g_assert(timeout==25000||timeout==180000||timeout==3000);RVHttpJobV16*j=g_new0(RVHttpJobV16,1);atomic_init(&j->cancelled,0);g_ptr_array_add(paths,g_strdup(path));g_ptr_array_add(bodies,g_strdup(body));return j;}
static gboolean rv_http_ready_v16(RVHttpJobV16*j){return j&&j->ready;}
static void rv_http_cancel_v16(RVHttpJobV16*j){if(j){atomic_store(&j->cancelled,1);j->ready=TRUE;j->result=CURLE_ABORTED_BY_CALLBACK;}}
static void rv_http_free_v16(RVHttpJobV16*j){if(!j)return;freed++;g_free(j->response);g_free(j);}
HELPERS
static guint selected_deliveries;
static gboolean linux_ordered_adopt_measured_v1(GtkWindow*parent,const char*draft,int position,JsonObject*response) {
    if(GTK_IS_WINDOW(parent)&&draft&&position==2&&linux_ec_bool(response,"chosen")&&linux_ec_number(response,"selection_epoch")==17&&json_array_get_length(linux_ec_array(response,"proposed_path"))==5){selected_deliveries++;return TRUE;}
    return GTK_IS_WINDOW(parent) && draft != NULL && position == 0 && linux_ec_bool(response,"chosen");
}
METHODS
static void check(gboolean ok,const char*message){checks++;if(!ok)g_error("ORDERED-CANDIDATE-GTK: %s",message);}
static void fixture_saved_envelope(JsonObject*o){json_object_set_int_member(o,"schema",1);json_object_set_string_member(o,"scope","saved-complete-local");json_object_set_int_member(o,"prefix_position",0);json_object_set_string_member(o,"measurement","routed-tcp-connect");json_object_set_boolean_member(o,"active_path_changed",FALSE);}
static JsonNode*fixture(const char*name){char*path=g_strdup_printf("%s/%s.json",output,name),*raw=NULL;g_assert(g_file_get_contents(path,&raw,NULL,NULL));g_free(path);JsonNode*n=parse_json(raw);g_free(raw);return n;}
static char*encode(JsonNode*n){JsonGenerator*g=json_generator_new();json_generator_set_root(g,n);char*body=json_generator_to_data(g,NULL);g_object_unref(g);return body;}
static void reply_code(LinuxOrderedCandidates*s,JsonNode*n,int status){g_assert(s->job);s->job->response=encode(n);s->job->status=status;s->job->result=CURLE_OK;s->job->ready=TRUE;linux_oc_tick(s);}
static void reply(LinuxOrderedCandidates*s,JsonNode*n){reply_code(s,n,200);}
static void choose(LinuxOrderedCandidates*s){GtkTreePath*p=gtk_tree_path_new_from_indices(0,-1);gtk_tree_selection_select_path(gtk_tree_view_get_selection(GTK_TREE_VIEW(s->table)),p);gtk_tree_path_free(p);}
int main(int argc,char**argv){
 output=argv[1];check(gtk_init_check(&argc,&argv),"real GTK display required");paths=g_ptr_array_new_with_free_func(g_free);bodies=g_ptr_array_new_with_free_func(g_free);App app={.window=gtk_window_new(GTK_WINDOW_TOPLEVEL)};
 JsonNode*catalog=fixture("catalog"),*row=fixture("row");JsonObject*ro=linux_oc_root(row);gint64 at=(gint64)linux_ec_number(ro,"measured_at");
 check(linux_oc_score(ro,at)==2,"valid50 TCP score rejected");check(isnan(linux_oc_score(ro,at+120000)),"poll renewed expired receipt");
 JsonObject*benchmark=linux_ec_object(json_array_get_object_element(linux_ec_array(ro,"results"),0),"benchmark");json_object_set_int_member(benchmark,"attempts",49);check(isnan(linux_oc_score(ro,at)),"partial sample result sorted");json_object_set_int_member(benchmark,"attempts",50);
 linux_ordered_candidates_open(&app);LinuxOrderedCandidates*s=g_object_get_data(G_OBJECT(app.window),"linux-ordered-candidates");check(s&&s->job&&strcmp(g_ptr_array_index(paths,0),"/api/multihop/prefix-candidates/catalog?prefix_position=0")==0,"real dialog did not capture prefix0");reply(s,catalog);choose(s);
 guint before=paths->len;busy=TRUE;gtk_button_clicked(GTK_BUTTON(s->test));check(paths->len==before,"busy main state started candidate job");busy=FALSE;gtk_button_clicked(GTK_BUTTON(s->test));check(s->pending&&async_state.auxiliary_jobs==1,"original native job lease missing");
 JsonNode*body=parse_json(g_ptr_array_index(bodies,paths->len-1));JsonObject*bo=linux_oc_root(body);check(linux_ec_number(bo,"samples")==50&&strcmp(linux_ec_string(bo,"view_token"),linux_ec_string(linux_oc_root(catalog),"view_token"))==0&&strcmp(json_array_get_string_element(linux_ec_array(bo,"candidate_ids"),0),"custom")==0,"actual test callback lost exact source selection");json_node_free(body);
 JsonNode*result=json_node_new(JSON_NODE_OBJECT);JsonObject*result_object=json_object_new();json_node_take_object(result,result_object);json_object_set_string_member(result_object,"request_id",s->request);json_object_set_string_member(result_object,"view_token",linux_ec_string(linux_oc_root(catalog),"view_token"));json_object_set_int_member(result_object,"prefix_position",0);json_object_set_boolean_member(result_object,"accepted",TRUE);json_object_set_boolean_member(result_object,"drained",TRUE);JsonArray*results=json_array_new();json_array_add_element(results,json_node_copy(row));json_object_set_array_member(result_object,"results",results);fixture_saved_envelope(result_object);reply(s,result);choose(s);linux_oc_controls(s);
 check(!s->pending&&async_state.auxiliary_jobs==0&&gtk_widget_get_sensitive(s->save),"joined current row did not enable explicit save");
 s->retry=0;linux_oc_tick(s);check(s->phase==5&&strstr(g_ptr_array_index(paths,paths->len-1),"/api/multihop/prefix-candidates?request_id=")!=NULL,"timer did not observe exact completed owner");
 /* JsonNode copies retain the same object: this mutable negative response must
  * own an independent parsed tree before changing its accepted result. */
 char*lost_raw=encode(result);JsonNode*lost=parse_json(lost_raw);g_free(lost_raw);JsonObject*lost_object=linux_oc_root(lost);json_object_set_boolean_member(lost_object,"accepted",FALSE);json_object_set_array_member(lost_object,"results",json_array_new());
 check(lost_object!=result_object&&linux_ec_bool(result_object,"accepted")&&json_array_get_length(linux_ec_array(result_object,"results"))==1,"negative response changed the original complete result");
 reply(s,lost);check(gtk_tree_model_iter_n_children(GTK_TREE_MODEL(s->store),NULL)==0&&!gtk_widget_get_sensitive(s->save),"stale original proof retained scored rows");json_node_free(lost);
 gtk_button_clicked(GTK_BUTTON(s->refresh));reply(s,catalog);choose(s);gtk_button_clicked(GTK_BUTTON(s->test));json_object_set_string_member(result_object,"request_id",s->request);reply(s,result);choose(s);linux_oc_controls(s);

 gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(s->prefix),"1","Uncaptured prefix");gtk_combo_box_set_active_id(GTK_COMBO_BOX(s->prefix),"1");linux_oc_controls(s);check(!gtk_widget_get_sensitive(s->test)&&!gtk_widget_get_sensitive(s->save),"uncaptured prefix borrowed old receipt");gtk_combo_box_set_active_id(GTK_COMBO_BOX(s->prefix),"0");linux_oc_controls(s);
 gtk_entry_set_text(GTK_ENTRY(s->name),"Named next connection");gtk_button_clicked(GTK_BUTTON(s->save));body=parse_json(g_ptr_array_index(bodies,paths->len-1));bo=linux_oc_root(body);check(strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/prefix-candidates/save-profile")==0&&strcmp(linux_ec_string(bo,"name"),"Named next connection")==0&&json_array_get_length(linux_ec_array(bo,"proposed_path"))==3,"actual Save did not send complete named next-path");json_node_free(body);
 JsonNode*saved=parse_json("{\"ok\":true,\"active_path_changed\":false,\"profile_name\":\"Named next connection\"}");reply(s,saved);check(s->receipt==NULL&&strstr(gtk_label_get_text(GTK_LABEL(s->status)),"active path is unchanged"),"save claimed live path replacement");
 choose(s);gtk_button_clicked(GTK_BUTTON(s->test));check(linux_oc_delete(s->dialog,NULL,s)&&s->pending&&!s->closed,"close escaped original native job");linux_oc_tick(s);s->retry=0;linux_oc_tick(s);check(s->phase==3&&strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/prefix-candidates/cancel")==0,"cancel did not retain original request");
 JsonNode*cancel=json_node_new(JSON_NODE_OBJECT);JsonObject*co=json_object_new();json_node_take_object(cancel,co);json_object_set_string_member(co,"request_id",s->request);json_object_set_boolean_member(co,"drained",FALSE);reply(s,cancel);check(s->pending&&async_state.auxiliary_jobs==1,"unjoined cancellation released hold");s->retry=0;linux_oc_tick(s);json_object_set_boolean_member(co,"drained",TRUE);reply(s,cancel);check(g_object_get_data(G_OBJECT(app.window),"linux-ordered-candidates")==NULL&&async_state.auxiliary_jobs==0,"joined cancellation did not release close");

 /* Saved-path purpose keeps its original observer during DOWN review. */
 linux_ordered_candidates_open_purpose(&app,TRUE);s=g_object_get_data(G_OBJECT(app.window),"linux-ordered-candidates");
 check(s->saved_path&&strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/saved-candidates/catalog?prefix_position=0")==0,"saved dialog captured another purpose");char*foreign_catalog_raw=encode(catalog);JsonNode*foreign_catalog=parse_json(foreign_catalog_raw);g_free(foreign_catalog_raw);json_object_set_string_member(linux_oc_root(foreign_catalog),"scope","connected-prefix");check(!linux_oc_receive(s,linux_oc_root(foreign_catalog),1)&&s->view==NULL,"foreign catalog purpose changed the saved dialog");json_object_set_string_member(linux_oc_root(foreign_catalog),"scope","saved-complete-local");json_object_remove_member(linux_oc_root(foreign_catalog),"prefix_position");check(!linux_oc_receive(s,linux_oc_root(foreign_catalog),1)&&s->view==NULL,"missing catalog prefix became position zero");json_node_free(foreign_catalog);reply(s,catalog);choose(s);guint before_expired=paths->len;json_object_set_int_member(linux_oc_root(s->view),"expires_at",g_get_real_time()/1000-1);gtk_button_clicked(GTK_BUTTON(s->test));check(paths->len==before_expired&&!s->pending&&async_state.auxiliary_jobs==0&&s->request[0]==0&&strstr(gtk_label_get_text(GTK_LABEL(s->status)),"expired"),"expired GTK catalog created a request or retained owner");json_object_set_int_member(linux_oc_root(s->view),"expires_at",g_get_real_time()/1000+120000);gtk_button_clicked(GTK_BUTTON(s->test));
 check(s->pending&&async_state.auxiliary_jobs==1&&g_object_get_data(G_OBJECT(app.window),"linux-ordered-candidates-pending")==s,"saved request lost mutation guard lease");
 check(strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/saved-candidates")==0,"saved test used connected endpoint");
 json_object_set_string_member(result_object,"request_id",s->request);json_object_set_boolean_member(result_object,"drained",FALSE);json_object_set_boolean_member(result_object,"running",TRUE);json_object_set_boolean_member(result_object,"accepted",FALSE);json_object_set_boolean_member(result_object,"native_down",FALSE);json_object_set_boolean_member(result_object,"reviewing",FALSE);json_object_set_boolean_member(result_object,"cleanup_pending",FALSE);reply_code(s,result,202);
 check(s->pending&&!gtk_widget_get_sensitive(s->save)&&!gtk_widget_get_sensitive(s->test)&&gtk_tree_model_iter_n_children(GTK_TREE_MODEL(s->store),NULL)==0,"202 admission exposed results or released ownership");
 s->retry=0;linux_oc_tick(s);char*expected_poll=g_strdup_printf("/api/multihop/saved-candidates?request_id=%s",s->request);check(strcmp(g_ptr_array_index(paths,paths->len-1),expected_poll)==0,"saved poll changed purpose or original request");g_free(expected_poll);
 json_object_set_boolean_member(result_object,"running",FALSE);json_object_set_boolean_member(result_object,"accepted",TRUE);json_object_set_boolean_member(result_object,"reviewing",TRUE);reply(s,result);
 check(gtk_tree_model_iter_n_children(GTK_TREE_MODEL(s->store),NULL)==0&&!gtk_widget_get_sensitive(s->save),"accepted result before native DOWN exposed choices");
 s->retry=0;linux_oc_tick(s);json_object_set_boolean_member(result_object,"native_down",TRUE);reply(s,result);choose(s);linux_oc_controls(s);
 check(s->pending&&async_state.auxiliary_jobs==1&&gtk_widget_get_sensitive(s->save)&&!gtk_widget_get_sensitive(s->test)&&!gtk_widget_get_sensitive(s->refresh)&&gtk_widget_get_sensitive(s->cancel),"DOWN review lost Save or original observer reservation");
 check(g_str_has_prefix(gtk_label_get_text(GTK_LABEL(s->status)),"Disconnected."),"DOWN review reported a live daily connection");
 char*foreign_raw=encode(result);JsonNode*foreign=parse_json(foreign_raw);g_free(foreign_raw);JsonObject*fo=linux_oc_root(foreign);json_object_set_string_member(fo,"saved_profile_id","foreign-write");json_object_set_boolean_member(fo,"drained",TRUE);
 for(int phase=2;phase<=5;phase++){json_object_set_string_member(fo,"scope","connected-prefix");check(!linux_oc_receive(s,fo,phase)&&s->pending&&async_state.auxiliary_jobs==1&&!s->saved_profile[0],"foreign purpose retired or saved original GTK owner");json_object_set_string_member(fo,"scope","saved-complete-local");json_object_set_int_member(fo,"prefix_position",1);check(!linux_oc_receive(s,fo,phase)&&s->pending&&async_state.auxiliary_jobs==1&&!s->saved_profile[0],"foreign prefix retired or saved original GTK owner");json_object_set_int_member(fo,"prefix_position",0);}json_node_free(foreign);
 JsonNode*late_early=parse_json("{\"drained\":true,\"native_down\":false,\"started\":false,\"admission_cancelled\":true,\"active_path_changed\":false}");JsonObject*late_eo=linux_oc_root(late_early);fixture_saved_envelope(late_eo);json_object_set_string_member(late_eo,"request_id",s->request);json_object_set_string_member(late_eo,"view_token",linux_ec_string(linux_oc_root(catalog),"view_token"));check(!linux_oc_receive(s,late_eo,3)&&s->pending&&s->saved_admitted&&async_state.auxiliary_jobs==1,"never-started receipt retired an admitted GTK owner");json_node_free(late_early);
 s->retry=0;linux_oc_tick(s);reply(s,result);check(strcmp(linux_ec_string(linux_oc_selected(s),"id"),"custom")==0,"review poll silently changed selected candidate");
 JsonObject*receipt_row=linux_oc_result(s,"custom");json_object_set_int_member(receipt_row,"measured_at",g_get_real_time()/1000-120001);json_object_set_int_member(receipt_row,"expires_at",g_get_real_time()/1000-1);linux_oc_controls(s);check(!gtk_widget_get_sensitive(s->save),"review observer renewed measurement expiry");json_object_set_int_member(receipt_row,"measured_at",at);json_object_set_int_member(receipt_row,"expires_at",at+120000);
 gtk_entry_set_text(GTK_ENTRY(s->name),"Saved Local future");linux_oc_controls(s);gtk_button_clicked(GTK_BUTTON(s->save));body=parse_json(g_ptr_array_index(bodies,paths->len-1));bo=linux_oc_root(body);
 check(strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/saved-candidates/save-profile")==0&&strcmp(linux_ec_string(bo,"request_id"),s->request)==0&&strcmp(linux_ec_string(bo,"view_token"),linux_ec_string(linux_oc_root(catalog),"view_token"))==0&&json_array_get_length(linux_ec_array(bo,"proposed_path"))==3,"saved callback lost exact next-profile proposal");json_node_free(body);
 JsonNode*committed=parse_json("{\"saved_profile_id\":\"original-write\",\"profile_name\":\"Saved Local future\",\"native_down\":true,\"drained\":false,\"failure\":\"Original observer changed after append\"}");JsonObject*commit=linux_oc_root(committed);fixture_saved_envelope(commit);json_object_set_string_member(commit,"request_id",s->request);json_object_set_string_member(commit,"view_token",linux_ec_string(linux_oc_root(catalog),"view_token"));reply(s,committed);
 check(strcmp(s->saved_profile,"original-write")==0&&s->pending&&s->cancel_wanted&&!gtk_widget_get_sensitive(s->save)&&strstr(gtk_label_get_text(GTK_LABEL(s->status)),"invalidated"),"committed profile was hidden or repeat Save offered after cleanup failure");
 s->retry=0;linux_oc_tick(s);check(strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/saved-candidates/cancel")==0,"post-Save cleanup changed endpoint");json_object_set_boolean_member(commit,"drained",TRUE);json_object_set_boolean_member(commit,"native_down",FALSE);reply(s,committed);
 check(s->pending&&async_state.auxiliary_jobs==1&&!strstr(gtk_label_get_text(GTK_LABEL(s->status)),"path is disconnected"),"saved write falsely supplied a native DOWN receipt");
 s->retry=0;linux_oc_tick(s);json_object_set_boolean_member(commit,"native_down",TRUE);reply(s,committed);
 check(!s->pending&&async_state.auxiliary_jobs==0&&g_object_get_data(G_OBJECT(app.window),"linux-ordered-candidates-pending")==NULL&&!gtk_widget_get_sensitive(s->save)&&strstr(gtk_label_get_text(GTK_LABEL(s->status)),"Use Profiles"),"final cleanup lost the write or selected a daily connection");
 json_object_set_string_member(commit,"saved_profile_id","foreign-write");check(!linux_oc_receive(s,commit,5),"retry changed original committed identity");gtk_widget_destroy(s->dialog);json_node_free(committed);

 /* A refused POST still owns its nonce until a typed no-admission tombstone. */
 linux_ordered_candidates_open_purpose(&app,TRUE);s=g_object_get_data(G_OBJECT(app.window),"linux-ordered-candidates");reply(s,catalog);choose(s);gtk_button_clicked(GTK_BUTTON(s->test));
 s->job->ready=TRUE;s->job->status=409;s->job->result=CURLE_OK;linux_oc_tick(s);check(s->pending&&s->cancel_wanted,"early refusal dropped original cancellation responsibility");
 s->retry=0;linux_oc_tick(s);body=parse_json(g_ptr_array_index(bodies,paths->len-1));bo=linux_oc_root(body);check(strcmp(linux_ec_string(bo,"view_token"),linux_ec_string(linux_oc_root(catalog),"view_token"))==0&&strcmp(linux_ec_string(bo,"request_id"),s->request)==0,"pre-admission Cancel lost exact original view and nonce");json_node_free(body);
 JsonNode*early=parse_json("{\"drained\":true,\"native_down\":false,\"started\":false,\"admission_cancelled\":true,\"active_path_changed\":false}");JsonObject*eo=linux_oc_root(early);fixture_saved_envelope(eo);json_object_set_string_member(eo,"request_id",s->request);json_object_set_string_member(eo,"view_token","foreign");reply(s,early);
 check(s->pending&&async_state.auxiliary_jobs==1,"foreign no-admission receipt retired original owner");s->retry=0;linux_oc_tick(s);json_object_set_string_member(eo,"view_token",linux_ec_string(linux_oc_root(catalog),"view_token"));reply(s,early);
 check(!s->pending&&async_state.auxiliary_jobs==0&&s->receipt==NULL&&strcmp(gtk_label_get_text(GTK_LABEL(s->status)),"Cancelled before the temporary path started.")==0,"typed original no-admission receipt claimed native shutdown or retained reservation");check(!gtk_widget_get_sensitive(s->save)&&gtk_tree_model_iter_n_children(GTK_TREE_MODEL(s->store),NULL)==0,"never-started cancellation exposed choices");gtk_widget_destroy(s->dialog);json_node_free(early);
 /* Prefix-only uses the same owned workflow with its captured private purpose. */
 char*prefix_raw=encode(catalog);JsonNode*prefix_catalog=parse_json(prefix_raw);g_free(prefix_raw);JsonObject*pco=linux_oc_root(prefix_catalog);json_object_set_string_member(pco,"scope","saved-prefix-local");json_object_set_boolean_member(pco,"application_open",FALSE);json_object_set_boolean_member(pco,"dns_open",FALSE);json_object_set_string_member(pco,"proof_scope","selected-prefix");
 linux_ordered_candidates_open_captured(&app,TRUE,TRUE);s=g_object_get_data(G_OBJECT(app.window),"linux-ordered-candidates");
 check(s->saved_path&&s->saved_prefix&&strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/saved-candidates/catalog?prefix_position=0&scope=saved-prefix-local")==0,"prefix dialog lost explicit catalog purpose");
 check(!linux_oc_receive(s,linux_oc_root(catalog),1)&&s->view==NULL,"complete catalog substituted for prefix preparation");json_object_remove_member(pco,"proof_scope");check(!linux_oc_receive(s,pco,1)&&s->view==NULL,"prefix catalog omitted selected proof");json_object_set_string_member(pco,"proof_scope","selected-prefix");reply(s,prefix_catalog);choose(s);gtk_button_clicked(GTK_BUTTON(s->test));
 body=parse_json(g_ptr_array_index(bodies,paths->len-1));bo=linux_oc_root(body);check(strcmp(linux_ec_string(bo,"scope"),"saved-prefix-local")==0&&linux_ec_number(bo,"samples")==50&&s->pending&&async_state.auxiliary_jobs==1,"prefix Run lost purpose or exact samples");json_node_free(body);
 prefix_raw=encode(result);JsonNode*prefix_result=parse_json(prefix_raw);g_free(prefix_raw);JsonObject*pro=linux_oc_root(prefix_result);json_object_set_string_member(pro,"request_id",s->request);json_object_set_string_member(pro,"scope","saved-prefix-local");json_object_set_boolean_member(pro,"application_open",FALSE);json_object_set_boolean_member(pro,"dns_open",FALSE);json_object_set_string_member(pro,"proof_scope","selected-prefix");json_object_set_boolean_member(pro,"drained",FALSE);json_object_set_boolean_member(pro,"native_down",FALSE);json_object_set_boolean_member(pro,"accepted",FALSE);json_object_set_boolean_member(pro,"reviewing",FALSE);json_object_set_boolean_member(pro,"running",TRUE);reply_code(s,prefix_result,202);
 check(s->pending&&!gtk_widget_get_sensitive(s->save)&&gtk_tree_model_iter_n_children(GTK_TREE_MODEL(s->store),NULL)==0,"prefix Testing exposed choices before native DOWN");s->retry=0;linux_oc_tick(s);json_object_set_boolean_member(pro,"native_down",TRUE);json_object_set_boolean_member(pro,"accepted",TRUE);json_object_set_boolean_member(pro,"reviewing",TRUE);json_object_set_boolean_member(pro,"running",FALSE);reply(s,prefix_result);choose(s);linux_oc_controls(s);
 check(s->pending&&gtk_widget_get_sensitive(s->save)&&!gtk_widget_get_sensitive(s->test)&&async_state.auxiliary_jobs==1,"prefix DOWN review lost original observer or explicit Save");
 prefix_raw=encode(prefix_result);JsonNode*prefix_foreign=parse_json(prefix_raw);g_free(prefix_raw);JsonObject*pfo=linux_oc_root(prefix_foreign);json_object_set_string_member(pfo,"saved_profile_id","foreign-write");json_object_set_boolean_member(pfo,"drained",TRUE);
 for(int phase=2;phase<=5;phase++){json_object_set_string_member(pfo,"scope","saved-complete-local");check(!linux_oc_receive(s,pfo,phase)&&s->pending&&!s->saved_profile[0],"foreign complete response retired prefix owner");json_object_set_string_member(pfo,"scope","saved-prefix-local");json_object_set_string_member(pfo,"proof_scope","ordinary-path");check(!linux_oc_receive(s,pfo,phase)&&s->pending&&!s->saved_profile[0],"foreign proof retired prefix owner");json_object_set_string_member(pfo,"proof_scope","selected-prefix");const char*closed_flags[]={"application_open","dns_open"};for(unsigned i=0;i<2;i++){json_object_set_boolean_member(pfo,closed_flags[i],TRUE);check(!linux_oc_receive(s,pfo,phase)&&s->pending&&!s->saved_profile[0],"open prefix ingress retired original owner");json_object_set_boolean_member(pfo,closed_flags[i],FALSE);}}json_node_free(prefix_foreign);
 gtk_entry_set_text(GTK_ENTRY(s->name),"Prefix future profile");gtk_button_clicked(GTK_BUTTON(s->save));body=parse_json(g_ptr_array_index(bodies,paths->len-1));bo=linux_oc_root(body);check(strcmp(linux_ec_string(bo,"scope"),"saved-prefix-local")==0&&json_array_get_length(linux_ec_array(bo,"proposed_path"))==3,"prefix Save lost purpose or complete source path");json_node_free(body);
 json_object_set_string_member(pro,"saved_profile_id","prefix-write");json_object_set_string_member(pro,"profile_name","Prefix future profile");json_object_set_boolean_member(pro,"accepted",FALSE);json_object_set_boolean_member(pro,"reviewing",FALSE);json_object_set_boolean_member(pro,"cleanup_pending",TRUE);reply(s,prefix_result);check(s->pending&&strcmp(s->saved_profile,"prefix-write")==0&&!gtk_widget_get_sensitive(s->save),"prefix Save lost committed write before observer join");
 s->retry=0;linux_oc_tick(s);body=parse_json(g_ptr_array_index(bodies,paths->len-1));bo=linux_oc_root(body);check(strcmp(linux_ec_string(bo,"scope"),"saved-prefix-local")==0&&strcmp(linux_ec_string(bo,"request_id"),s->request)==0,"prefix Cancel lost captured purpose");json_node_free(body);json_object_set_boolean_member(pro,"drained",TRUE);json_object_set_boolean_member(pro,"cleanup_pending",FALSE);reply(s,prefix_result);
 check(!s->pending&&async_state.auxiliary_jobs==0&&strcmp(s->saved_profile,"prefix-write")==0,"prefix cleanup did not retain write and release original observer");gtk_widget_destroy(s->dialog);json_node_free(prefix_catalog);json_node_free(prefix_result);
 /* Exercise the editor handoff's catalog request through actual GTK delivery. */
 GtkWidget*editor=gtk_window_new(GTK_WINDOW_TOPLEVEL);
 const char*draft_body="{\"execution\":\"local\",\"nodes\":[]}";
 linux_ordered_candidates_open_draft(&app,GTK_WINDOW(editor),draft_body,0);
 s=g_object_get_data(G_OBJECT(app.window),"linux-ordered-candidates");
 check(!strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/draft-candidates/catalog?prefix_position=0&scope=saved-prefix-local") &&
       !strcmp(g_ptr_array_index(bodies,bodies->len-1),draft_body),"draft catalog lost exact posted editor body");
 char *dto=encode(catalog);JsonNode*editor_catalog=parse_json(dto);g_free(dto);JsonObject*eco=linux_oc_root(editor_catalog);
 json_object_set_string_member(eco,"scope","saved-prefix-local");json_object_set_boolean_member(eco,"application_open",FALSE);
 json_object_set_boolean_member(eco,"dns_open",FALSE);json_object_set_string_member(eco,"proof_scope","selected-prefix");
 json_object_set_string_member(eco,"origin","editor-draft");reply(s,editor_catalog);
 check(s->view&&!gtk_widget_get_sensitive(s->prefix)&&!gtk_widget_get_visible(s->name),"editor capture enabled a different prefix or profile write");
 check(s->pending && s->phase==2 && !strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/draft-candidates"),"opening the next hop picker failed to measure insertable candidates");
 char*cancel_request=g_strdup(s->request);linux_oc_cancel(s);s->retry=0;linux_oc_tick(s);s->retry=0;linux_oc_tick(s);
 JsonObject*finished=linux_oc_root(cancel);fixture_saved_envelope(finished);
 json_object_set_string_member(finished,"origin","editor-draft");json_object_set_string_member(finished,"scope","saved-prefix-local");json_object_set_boolean_member(finished,"application_open",FALSE);json_object_set_boolean_member(finished,"dns_open",FALSE);
 json_object_set_string_member(finished,"proof_scope","selected-prefix");json_object_set_string_member(finished,"request_id",cancel_request);json_object_set_string_member(finished,"view_token",linux_ec_string(eco,"view_token"));json_object_set_boolean_member(finished,"native_down",TRUE);
 reply(s,cancel);g_free(cancel_request);check(!s->pending,"auto-launched draft measurement did not drain");
 gtk_widget_destroy(editor);json_node_free(editor_catalog);
 for(int i=0;i<3;i++){
  const char*requested=i?"auto":"server",*winner=i==1?"local":"server";
  GtkWidget*owner=gtk_window_new(GTK_WINDOW_TOPLEVEL);
  char*raw=g_strdup_printf("{\"execution\":\"%s\",\"nodes\":[{\"id\":\"entry\",\"mode\":\"wg\"},{\"id\":\"source\",\"mode\":\"shadowsocks\"},{\"id\":\"packet\",\"mode\":\"awg2-fast\"},{\"id\":\"final\",\"mode\":\"shadowsocks\"}],\"expected_selected_node_id\":\"final\",\"expected_profile_tokens\":{\"entry\":\"e\",\"source\":\"s\",\"packet\":\"p\",\"final\":\"f\"}}",requested);
  linux_ordered_candidates_open_draft(&app,GTK_WINDOW(owner),raw,2);
  LinuxOrderedCandidates*form=g_object_get_data(G_OBJECT(app.window),"linux-ordered-candidates");
  check(!strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/draft-candidates/catalog?prefix_position=2&scope=draft-complete-selected")&&!strcmp(g_ptr_array_index(bodies,bodies->len-1),raw),"selected draft catalog changed original input or scope");
  JsonNode*offer=fixture("catalog");JsonObject*o=linux_oc_root(offer);
  fixture_saved_envelope(o);json_object_set_string_member(o,"origin","editor-draft");json_object_set_string_member(o,"scope","draft-complete-selected");
  json_object_set_string_member(o,"requested_execution",requested);json_object_set_int_member(o,"prefix_position",2);json_object_set_int_member(o,"samples",50);
  JsonNode*stops=parse_json("[{\"id\":\"packet\",\"mode\":\"awg2-fast\",\"position\":2,\"name\":\"Original packet\"}]");json_object_set_member(o,"prefixes",stops);
  JsonObject*route=json_array_get_object_element(linux_ec_array(o,"candidates"),0);
  json_object_set_member(route,"proposed_path",parse_json("[{\"id\":\"entry\",\"mode\":\"wg\"},{\"id\":\"source\",\"mode\":\"shadowsocks\"},{\"id\":\"packet\",\"mode\":\"awg2-fast\"},{\"id\":\"custom\",\"mode\":\"shadowsocks\"},{\"id\":\"final\",\"mode\":\"shadowsocks\"}]"));
  json_object_set_string_member(o,"selected_execution",winner);check(!linux_oc_saved_envelope(form,o,TRUE),"catalog invented an early winner");json_object_remove_member(o,"selected_execution");
  JsonObject*stop=json_array_get_object_element(linux_ec_array(o,"prefixes"),0);
  json_object_set_string_member(stop,"id","replacement");check(!linux_oc_saved_envelope(form,o,TRUE),"catalog borrowed foreign packet ID");json_object_set_string_member(stop,"id","packet");
  json_object_set_string_member(o,"requested_execution","local");check(!linux_oc_saved_envelope(form,o,TRUE),"catalog borrowed Local execution");json_object_set_string_member(o,"requested_execution",requested);
  reply(form,offer);check(form->pending&&form->phase==2,"selected catalog did not start original candidate");
  JsonNode*run=parse_json(g_ptr_array_index(bodies,paths->len-1));check(!strcmp(linux_ec_string(linux_oc_root(run),"scope"),"draft-complete-selected")&&linux_ec_number(linux_oc_root(run),"samples")==50,"selected run changed purpose or samples");json_node_free(run);
  JsonNode*receipt=parse_json("{}");JsonObject*value=linux_oc_root(receipt);fixture_saved_envelope(value);
  json_object_set_string_member(value,"origin","editor-draft");json_object_set_string_member(value,"scope","draft-complete-selected");json_object_set_int_member(value,"prefix_position",2);
  json_object_set_string_member(value,"request_id",form->request);json_object_set_string_member(value,"view_token",linux_ec_string(o,"view_token"));json_object_set_string_member(value,"requested_execution",requested);
  json_object_set_boolean_member(value,"native_down",TRUE);json_object_set_boolean_member(value,"accepted",TRUE);json_object_set_boolean_member(value,"reviewing",TRUE);json_object_set_boolean_member(value,"cleanup_pending",FALSE);json_object_set_boolean_member(value,"drained",FALSE);json_object_set_boolean_member(value,"cancelled",FALSE);json_object_set_boolean_member(value,"running",FALSE);
  json_object_set_string_member(value,"saved_profile_id","");JsonArray*scores=json_array_new();json_array_add_element(scores,json_node_copy(row));json_object_set_array_member(value,"results",scores);
  check(!linux_oc_saved_envelope(form,value,FALSE),"unselected measurement became a reviewable result");
  json_object_set_string_member(value,"selected_execution",winner);json_object_set_int_member(value,"selection_epoch",17);reply(form,receipt);choose(form);linux_oc_controls(form);
  check(gtk_widget_get_sensitive(form->save)&&strstr(gtk_label_get_text(GTK_LABEL(form->status)),winner),"selected winner missing from genuine review");
  json_object_set_boolean_member(value,"admission_cancelled",TRUE);check(!linux_oc_saved_envelope(form,value,FALSE),"never-started cancel borrowed a selected winner");json_object_remove_member(value,"admission_cancelled");
  json_object_set_int_member(value,"selection_epoch",18);check(!linux_oc_saved_envelope(form,value,FALSE),"review borrowed another epoch");json_object_set_int_member(value,"selection_epoch",17);
  json_object_set_string_member(value,"selected_execution",!strcmp(winner,"local")?"server":"local");check(!linux_oc_saved_envelope(form,value,FALSE),"review borrowed another winner");json_object_set_string_member(value,"selected_execution",winner);
  gtk_button_clicked(GTK_BUTTON(form->save));JsonNode*choose_body=parse_json(g_ptr_array_index(bodies,paths->len-1));
  check(!strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/draft-candidates/choose")&&!strcmp(linux_ec_string(linux_oc_root(choose_body),"scope"),"draft-complete-selected")&&json_array_get_length(linux_ec_array(linux_oc_root(choose_body),"proposed_path"))==5,"selected choose lost scope or suffix");json_node_free(choose_body);
  json_object_set_boolean_member(value,"drained",TRUE);json_object_set_boolean_member(value,"chosen",TRUE);json_object_set_boolean_member(value,"accepted",FALSE);json_object_set_boolean_member(value,"reviewing",FALSE);
  json_object_set_string_member(value,"candidate_id",linux_ec_string(route,"id"));json_object_set_member(value,"proposed_path",json_node_copy(linux_ec_member(route,"proposed_path")));reply(form,receipt);
  check(selected_deliveries==(guint)i+1&&!async_state.auxiliary_jobs,"selected choose failed joined editor handoff");
  gtk_widget_destroy(owner);json_node_free(receipt);json_node_free(offer);g_free(raw);
 }
 {
  linux_ordered_candidates_open_captured(&app,TRUE,TRUE);
  LinuxOrderedCandidates*saved=g_object_get_data(G_OBJECT(app.window),"linux-ordered-candidates");
  GtkWidget*saved_window=g_object_ref(saved->dialog);
  linux_ordered_candidates_open_captured(&app,FALSE,FALSE);
  check(g_object_get_data(G_OBJECT(app.window),"linux-ordered-candidates")==saved&&saved->job&&!saved->closed,"purpose change displaced an in-flight capture");
  reply_code(saved,catalog,503);
  check(!saved->job&&!saved->pending,"initial catalog failure retained a native candidate");
  linux_ordered_candidates_open_captured(&app,FALSE,FALSE);
  LinuxOrderedCandidates*selected=g_object_get_data(G_OBJECT(app.window),"linux-ordered-candidates");
  check(saved->closed&&selected!=saved&&!selected->saved_path&&!selected->saved_prefix,"idle saved prefix window blocked connected candidates");g_object_unref(saved_window);
  JsonNode*sparse=fixture("catalog");JsonObject*value=linux_oc_root(sparse);JsonArray*prefixes=json_array_new();
  for(int pos=0;pos<=6;pos+=2){JsonObject*p=json_object_new();json_object_set_int_member(p,"position",pos);json_object_set_string_member(p,"id","packet");json_object_set_string_member(p,"name","Original packet");json_object_set_string_member(p,"mode","awg2-fast");json_array_add_object_element(prefixes,p);}
  json_object_set_array_member(value,"prefixes",prefixes);reply(selected,sparse);
  check(gtk_combo_box_set_active_id(GTK_COMBO_BOX(selected->prefix),"4")&&!gtk_combo_box_set_active_id(GTK_COMBO_BOX(selected->prefix),"3"),"connected picker lost sparse packet stop or offered an imported position");
  gtk_combo_box_set_active_id(GTK_COMBO_BOX(selected->prefix),"4");gtk_button_clicked(GTK_BUTTON(selected->refresh));
  check(selected->position==4&&strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/prefix-candidates/catalog?prefix_position=4")==0,"connected packet recapture used an ordinal or a saved purpose");
  json_object_set_int_member(value,"prefix_position",4);char*token=g_strnfill(64,'b');json_object_set_string_member(value,"view_token",token);reply(selected,sparse);
  check(selected->view&&!strcmp(linux_ec_string(linux_oc_root(selected->view),"view_token"),token),"sparse packet recapture lost its new token");g_free(token);json_node_free(sparse);gtk_widget_destroy(selected->dialog);
 }

 for(int close_case=0;close_case<4;close_case++){
  GtkWidget*owner=gtk_window_new(GTK_WINDOW_TOPLEVEL);
  const char*original="{\"execution\":\"local\",\"expected_selected_node_id\":\"final\",\"nodes\":[{\"id\":\"entry\",\"mode\":\"wg\"},{\"id\":\"middle\",\"mode\":\"shadowsocks\"},{\"id\":\"final\",\"mode\":\"shadowsocks\"}]}";
  char*deep_original=NULL;int response_position=close_case==2?14:close_case==3?2:1,response_count=close_case==2?16:close_case==3?4:3;
  if(close_case>=2){JsonNode*input=fixture(close_case==2?"deep-response-draft":"packet-response-draft");deep_original=encode(input);json_node_free(input);original=deep_original;}
  linux_ordered_candidates_open_draft(&app,GTK_WINDOW(owner),original,response_position);
  LinuxOrderedCandidates*form=g_object_get_data(G_OBJECT(app.window),"linux-ordered-candidates");
  JsonNode*offer=fixture(close_case==2?"deep-response-catalog":close_case==3?"packet-response-catalog":"response-catalog"),*sample=fixture("response-row");reply(form,offer);
  check(form->phase==2&&form->pending&&gtk_widget_get_visible(form->name)&&!strcmp(gtk_button_get_label(GTK_BUTTON(form->save)),"Save profile with this final"),"response draft lost named future-profile action");
  JsonNode*receipt=parse_json("{}");JsonObject*value=linux_oc_root(receipt);
  json_object_set_int_member(value,"schema",1);json_object_set_string_member(value,"origin","editor-draft");json_object_set_string_member(value,"scope","saved-prefix-local");json_object_set_string_member(value,"proof_scope","selected-prefix");
  json_object_set_boolean_member(value,"application_open",FALSE);json_object_set_boolean_member(value,"dns_open",FALSE);json_object_set_boolean_member(value,"active_path_changed",FALSE);
  json_object_set_string_member(value,"measurement","routed-candidate-response");json_object_set_int_member(value,"prefix_position",response_position);
  json_object_set_string_member(value,"request_id",form->request);json_object_set_string_member(value,"view_token",linux_ec_string(linux_oc_root(offer),"view_token"));
  json_object_set_boolean_member(value,"native_down",TRUE);json_object_set_boolean_member(value,"accepted",TRUE);json_object_set_boolean_member(value,"reviewing",TRUE);json_object_set_boolean_member(value,"drained",FALSE);
  JsonArray*scores=json_array_new();json_array_add_element(scores,json_node_copy(sample));json_object_set_array_member(value,"results",scores);reply(form,receipt);choose(form);linux_oc_controls(form);
  check(gtk_widget_get_sensitive(form->save)&&form->pending&&strstr(gtk_label_get_text(GTK_LABEL(form->note)),"authenticated"),"response review did not show fresh private-agent timing after native DOWN");
  guint old_requests=paths->len,old_adoptions=selected_deliveries;gtk_button_clicked(GTK_BUTTON(form->save));check(paths->len==old_requests,"named final save invented a profile name");
  gtk_entry_set_text(GTK_ENTRY(form->name),"Measured future final");gtk_button_clicked(GTK_BUTTON(form->save));
  JsonNode*write=parse_json(g_ptr_array_index(bodies,bodies->len-1));JsonObject*posted=linux_oc_root(write);
  check(!strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/draft-candidates/save-profile")&&!strcmp(linux_ec_string(posted,"name"),"Measured future final")&&!strcmp(linux_ec_string(posted,"scope"),"saved-prefix-local")&&!strcmp(linux_ec_string(posted,"candidate_id"),"paired")&&json_array_get_length(linux_ec_array(posted,"proposed_path"))==(guint)response_count,"named final Save lost its exact name, path or original scope");json_node_free(write);
  json_object_set_boolean_member(value,"ok",TRUE);json_object_set_boolean_member(value,"saved",TRUE);json_object_set_boolean_member(value,"accepted",FALSE);json_object_set_boolean_member(value,"reviewing",FALSE);json_object_set_boolean_member(value,"cleanup_pending",TRUE);
  json_object_set_string_member(value,"saved_profile_id","future-final");json_object_set_string_member(value,"profile_name","Measured future final");json_object_set_string_member(value,"candidate_id","paired");json_object_set_string_member(value,"proposal_action","save-final-profile");
  JsonObject*choice=json_array_get_object_element(linux_ec_array(linux_oc_root(offer),"candidates"),0);json_object_set_member(value,"proposed_path",json_node_copy(linux_ec_member(choice,"proposed_path")));
  JsonObject*first=json_array_get_object_element(linux_ec_array(value,"proposed_path"),0);json_object_set_string_member(first,"id","foreign");check(!linux_oc_receive(form,value,4)&&form->pending&&!form->saved_profile[0],"named saved response changed its upstream path");json_object_set_string_member(first,"id","entry");
  if(close_case)check(linux_oc_delete(form->dialog,NULL,form)&&form->close_wanted,"Close did not retain pending named save");
  reply(form,receipt);check(form->pending&&!strcmp(form->saved_profile,"future-final")&&!strcmp(form->draft,original)&&selected_deliveries==old_adoptions&&!gtk_widget_get_sensitive(form->save),"named save changed Home, inserted a hop or forgot the committed write before cleanup");
  form->retry=0;linux_oc_tick(form);json_object_set_boolean_member(value,"drained",TRUE);json_object_set_boolean_member(value,"cleanup_pending",FALSE);reply(form,receipt);
  if(close_case)check(!g_object_get_data(G_OBJECT(app.window),"linux-ordered-candidates")&&!async_state.auxiliary_jobs,"late committed save did not close after original cleanup");
  else{check(!form->pending&&!async_state.auxiliary_jobs&&!strcmp(form->saved_profile,"future-final")&&strstr(gtk_label_get_text(GTK_LABEL(form->status)),"Use Profiles"),"named saved profile lost explicit future Load or native retirement");gtk_widget_destroy(form->dialog);}
  gtk_widget_destroy(owner);json_node_free(receipt);json_node_free(sample);json_node_free(offer);g_free(deep_original);
 }
 check(freed==paths->len,"owned HTTP worker leaked");json_node_free(catalog);json_node_free(row);json_node_free(result);json_node_free(saved);json_node_free(cancel);gtk_widget_destroy(app.window);g_ptr_array_free(paths,TRUE);g_ptr_array_free(bodies,TRUE);printf("Shipping GTK ordered-candidate controls: %u checks PASS; real widgets, controlled HTTP delivery.\n",checks);return 0;
}
'''.replace('HELPERS',helpers).replace('METHODS',methods)
    path=directory/'ordered.c';path.write_text(program)
    flags=subprocess.check_output(['pkg-config','--cflags','--libs','gtk+-3.0','json-glib-1.0','libcurl'],text=True).split()
    binary=directory/'ordered-gtk'
    subprocess.run(['gcc','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function',str(path),'-o',str(binary),*flags,'-lm','-pthread'],check=True,timeout=90)
    command=[str(binary),str(directory)]
    if not os.environ.get('DISPLAY'):command=['xvfb-run','-a',*command]
    subprocess.run(command,check=True,timeout=60)


def main():
    p=argparse.ArgumentParser();p.add_argument('--platform',choices=['windows','darwin','linux'],required=True);p.add_argument('--shell',default='pwsh');args=p.parse_args()
    with tempfile.TemporaryDirectory(prefix='ordered-candidate-forms-') as d:
        if args.platform=='darwin':swift_launcher(Path(d));swift_form(Path(d))
        elif args.platform=='linux':linux_actions(Path(d));linux_policy(Path(d));linux_form(Path(d))
        else:subprocess.run([args.shell,'-NoProfile','-File',str(ROOT/'client/test-windows-ordered-candidates.ps1'),'-Root',str(ROOT)],check=True,timeout=90)
if __name__=='__main__':main()
