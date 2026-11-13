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
    policy+='\n'+block((ROOT/'client/macos/RouterVPNMacViaEntryPolicy.swift').read_text(),'final class MacViaEntryCandidateReservation:')
    product=(ROOT/'client/macos/RouterVPNMacProduct.swift').read_text()
    assert 'self.statusLabel.stringValue = productConnectionStatusLabel(connected: connected, phase: phase)' in product
    policy+='\n'+block(product,'func productConnectionStatusLabel(')
    summary=(ROOT/'client/macos/RouterVPNHomeSummary.swift').read_text()
    policy+='\n'+block(summary,'private struct RouterVPNDesktopHomeSummary:')
    policy+='\nprivate final class HomeForm {\n'+block(summary,'func formatHomeSummary(')+'\n}'
    owner=block(source,'private final class RouterVPNMacOrderedCandidates:')
    fields=owner[owner.index('{')+1:owner.index('    init(savedPath:')].replace('fileprivate private(set) ','').replace('private ','')
    methods='\n'.join(block(owner,'func '+n+'(').replace('@objc ','') for n in ['controls','capture','measure','saveProfile','cancelTest','windowShouldClose','windowWillClose','tick','savedStatus','issue','send','receive','receiveSaved'])
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
init(savedPath:Bool=false){self.savedPath=savedPath}
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
check(productConnectionStatusLabel(connected:false,phase:"candidate:testing")=="○ Testing","temporary Home exposed its internal phase")
check(productConnectionStatusLabel(connected:true,phase:"connected")=="● Connected","ordinary Connected label changed")
let home:[String:Any]=["actual_exit_status":"proved","actual_exit_ip":"203.0.113.9","connection_phase":"candidate:testing","connected":false,"path_proof":"proved","dns_status":"unknown","lan_access":false,"kill_switch":"off","warnings":[]]
let homeText=HomeForm().formatHomeSummary(try! JSONDecoder().decode(RouterVPNDesktopHomeSummary.self,from:JSONSerialization.data(withJSONObject:home)))
check(homeText.contains("Connection: Testing • temporary path") && !homeText.contains("203.0.113.9") && !homeText.contains("path proof proved"),"temporary Home reused ordinary public-exit proof")
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
    guards+='\n'+declarations+'\n'+'\n'.join(block(helpers,marker) for marker in ['static JsonNode *linux_ec_member(', 'static gboolean linux_ec_bool(', 'static double linux_ec_number('])+'\n'+block(candidates,'static JsonObject*linux_oc_root(')+'\n'+block(candidates,'static gboolean linux_oc_before_start(')+'\n'+block(candidates,'static gboolean linux_oc_ready(')+'\n'+block(candidates,'static gboolean linux_oc_view_fresh(')
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
 n=parse_json("{\"accepted\":true,\"native_down\":false,\"reviewing\":true,\"cleanup_pending\":false}");LinuxOrderedCandidates candidate={.saved_path=TRUE,.pending=TRUE,.receipt=n};JsonObject*r=json_node_get_object(n);
 check(!linux_oc_ready(&candidate),"saved results were available before native DOWN");json_object_set_boolean_member(r,"native_down",TRUE);check(linux_oc_ready(&candidate),"DOWN observer review incorrectly required full owner drain");
 json_object_set_boolean_member(r,"reviewing",FALSE);check(!linux_oc_ready(&candidate),"closed review retained adoption");json_object_set_boolean_member(r,"reviewing",TRUE);
 json_object_set_boolean_member(r,"cleanup_pending",TRUE);check(!linux_oc_ready(&candidate),"cleanup failure permitted adoption");json_object_set_boolean_member(r,"cleanup_pending",FALSE);
 candidate.close_wanted=TRUE;check(!linux_oc_ready(&candidate),"closing review retained adoption");candidate.close_wanted=FALSE;candidate.cancel_wanted=TRUE;check(!linux_oc_ready(&candidate),"cancelled review retained adoption");candidate.cancel_wanted=FALSE;
 strcpy(candidate.saved_profile,"original-write");check(!linux_oc_ready(&candidate),"committed profile offered repeat adoption");candidate.saved_profile[0]=0;json_object_set_boolean_member(r,"accepted",FALSE);check(!linux_oc_ready(&candidate),"invalidated review retained adoption");
 json_object_set_boolean_member(r,"admission_cancelled",TRUE);check(!linux_oc_before_start(r),"missing started field proved no admission");json_object_set_boolean_member(r,"started",TRUE);check(!linux_oc_before_start(r),"started owner bypassed native retirement");json_object_set_string_member(r,"started","false");check(!linux_oc_before_start(r),"string started value became an absence receipt");json_object_set_boolean_member(r,"started",FALSE);check(linux_oc_before_start(r),"explicit original tombstone was not recognized");json_object_set_boolean_member(r,"accepted",TRUE);check(!linux_oc_ready(&candidate),"never-started cancellation exposed results");json_node_free(n);

 printf("Shipping GTK candidate status guards: %u checks PASS; actual GObject, controlled HTTP.\n",checks);return 0;
}
"""
    flags=subprocess.check_output(['pkg-config','--cflags','--libs','gtk+-3.0','gobject-2.0','json-glib-1.0'],text=True).split()
    controls=[('phase',' || g_str_has_prefix(lower, "candidate:")','', 'temporary candidate phase was treated as idle'),('review','if(app&&app->window&&g_object_get_data(G_OBJECT(app->window),"linux-ordered-candidates-pending")!=NULL)return TRUE;','', 'retained DOWN review did not block mutation before HTTP')]
    controls.append(('native-down','linux_ec_bool(receipt,"native_down")&&','', 'saved results were available before native DOWN'))
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
    print('GTK candidate phase, retained-review and native-DOWN causal controls: 3 PASS',flush=True)

def linux_form(directory):
    import json, os, time
    source=(ROOT/'client/linux/routervpn-telemetry-v9.inc').read_text()
    helpers=source[source.index('static JsonNode *linux_ec_member'):source.index('static void linux_ec_lease')]
    methods=(ROOT/'client/linux/routervpn-ordered-candidates-v1.inc').read_text()
    now=int(time.time()*1000)
    path=[{'id':'entry','mode':'wg'},{'id':'custom','mode':'shadowsocks'},{'id':'final','mode':'shadowsocks'}]
    catalog={'schema':1,'view_token':'a'*64,'prefix_position':0,'expires_at':now+120000,'prefixes':[{'position':0,'name':'Original entry','mode':'wg'}],'candidates':[{'id':'custom','name':'Original custom','proposed_path':path}]}
    row={'schema':1,'candidate_id':'custom','measurement':'routed-tcp-connect','stage':'complete','complete':True,'drained':True,'measured_at':now,'expires_at':now+120000,'results':[{'node_id':'custom','role':'candidate','kind':'tcp-connect','ready':True,'benchmark':{'schema':1,'measurement':'routed-tcp-connect','attempts':50,'failed':0,'trimmed_mean_ms':2.0,'distribution':{'samples':50,'min_ms':1.0,'median_ms':2.0,'average_ms':2.0,'p90_ms':3.0,'max_ms':3.0,'jitter_ms':0.0}}}]}
    for name,value in [('catalog',catalog),('row',row)]: (directory/(name+'.json')).write_text(json.dumps(value))
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
METHODS
static void check(gboolean ok,const char*message){checks++;if(!ok)g_error("ORDERED-CANDIDATE-GTK: %s",message);}
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
 JsonNode*result=json_node_new(JSON_NODE_OBJECT);JsonObject*result_object=json_object_new();json_node_take_object(result,result_object);json_object_set_string_member(result_object,"request_id",s->request);json_object_set_string_member(result_object,"view_token",linux_ec_string(linux_oc_root(catalog),"view_token"));json_object_set_int_member(result_object,"prefix_position",0);json_object_set_boolean_member(result_object,"accepted",TRUE);json_object_set_boolean_member(result_object,"drained",TRUE);JsonArray*results=json_array_new();json_array_add_element(results,json_node_copy(row));json_object_set_array_member(result_object,"results",results);reply(s,result);choose(s);linux_oc_controls(s);
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
 check(s->saved_path&&strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/saved-candidates/catalog?prefix_position=0")==0,"saved dialog captured another purpose");reply(s,catalog);choose(s);guint before_expired=paths->len;json_object_set_int_member(linux_oc_root(s->view),"expires_at",g_get_real_time()/1000-1);gtk_button_clicked(GTK_BUTTON(s->test));check(paths->len==before_expired&&!s->pending&&async_state.auxiliary_jobs==0&&s->request[0]==0&&strstr(gtk_label_get_text(GTK_LABEL(s->status)),"expired"),"expired GTK catalog created a request or retained owner");json_object_set_int_member(linux_oc_root(s->view),"expires_at",g_get_real_time()/1000+120000);gtk_button_clicked(GTK_BUTTON(s->test));
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
 JsonNode*late_early=parse_json("{\"drained\":true,\"native_down\":false,\"started\":false,\"admission_cancelled\":true,\"active_path_changed\":false}");JsonObject*late_eo=linux_oc_root(late_early);json_object_set_string_member(late_eo,"request_id",s->request);json_object_set_string_member(late_eo,"view_token",linux_ec_string(linux_oc_root(catalog),"view_token"));check(!linux_oc_receive(s,late_eo,3)&&s->pending&&s->saved_admitted&&async_state.auxiliary_jobs==1,"never-started receipt retired an admitted GTK owner");json_node_free(late_early);
 s->retry=0;linux_oc_tick(s);reply(s,result);check(strcmp(linux_ec_string(linux_oc_selected(s),"id"),"custom")==0,"review poll silently changed selected candidate");
 JsonObject*receipt_row=linux_oc_result(s,"custom");json_object_set_int_member(receipt_row,"measured_at",g_get_real_time()/1000-120001);json_object_set_int_member(receipt_row,"expires_at",g_get_real_time()/1000-1);linux_oc_controls(s);check(!gtk_widget_get_sensitive(s->save),"review observer renewed measurement expiry");json_object_set_int_member(receipt_row,"measured_at",at);json_object_set_int_member(receipt_row,"expires_at",at+120000);
 gtk_entry_set_text(GTK_ENTRY(s->name),"Saved Local future");linux_oc_controls(s);gtk_button_clicked(GTK_BUTTON(s->save));body=parse_json(g_ptr_array_index(bodies,paths->len-1));bo=linux_oc_root(body);
 check(strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/saved-candidates/save-profile")==0&&strcmp(linux_ec_string(bo,"request_id"),s->request)==0&&strcmp(linux_ec_string(bo,"view_token"),linux_ec_string(linux_oc_root(catalog),"view_token"))==0&&json_array_get_length(linux_ec_array(bo,"proposed_path"))==3,"saved callback lost exact next-profile proposal");json_node_free(body);
 JsonNode*committed=parse_json("{\"saved_profile_id\":\"original-write\",\"profile_name\":\"Saved Local future\",\"native_down\":true,\"drained\":false,\"failure\":\"Original observer changed after append\"}");JsonObject*commit=linux_oc_root(committed);json_object_set_string_member(commit,"request_id",s->request);json_object_set_string_member(commit,"view_token",linux_ec_string(linux_oc_root(catalog),"view_token"));reply(s,committed);
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
 JsonNode*early=parse_json("{\"drained\":true,\"native_down\":false,\"started\":false,\"admission_cancelled\":true,\"active_path_changed\":false}");JsonObject*eo=linux_oc_root(early);json_object_set_string_member(eo,"request_id",s->request);json_object_set_string_member(eo,"view_token","foreign");reply(s,early);
 check(s->pending&&async_state.auxiliary_jobs==1,"foreign no-admission receipt retired original owner");s->retry=0;linux_oc_tick(s);json_object_set_string_member(eo,"view_token",linux_ec_string(linux_oc_root(catalog),"view_token"));reply(s,early);
 check(!s->pending&&async_state.auxiliary_jobs==0&&s->receipt==NULL&&strcmp(gtk_label_get_text(GTK_LABEL(s->status)),"Cancelled before the temporary path started.")==0,"typed original no-admission receipt claimed native shutdown or retained reservation");check(!gtk_widget_get_sensitive(s->save)&&gtk_tree_model_iter_n_children(GTK_TREE_MODEL(s->store),NULL)==0,"never-started cancellation exposed choices");gtk_widget_destroy(s->dialog);json_node_free(early);
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
        if args.platform=='darwin':swift_form(Path(d))
        elif args.platform=='linux':linux_policy(Path(d));linux_form(Path(d))
        else:subprocess.run([args.shell,'-NoProfile','-File',str(ROOT/'client/test-windows-ordered-candidates.ps1'),'-Root',str(ROOT)],check=True,timeout=90)
if __name__=='__main__':main()
