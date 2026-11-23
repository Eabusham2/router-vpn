#!/usr/bin/env python3
"""Execute shipping live-HTTPS decoders and asynchronous delivery ownership.

GTK uses real widgets; Swift and PowerShell use value-only native-control doubles.
HTTP completion is an explicit fixture boundary, never network measurement proof.
The prepared Box latency3 suite supplies the independent encrypted network gate.
"""
from pathlib import Path
import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MUTATION = None
MUTATIONS = {
    'darwin': [
        ('binding == other.binding && response.isEqual(other.response)', 'response.isEqual(other.response)'),
        ('number(d,"samples") == 3', 'number(d,"samples") != nil'),
        ('uptime < deadline }', 'true }'),
        ('!liveHTTPSPaused(), ', ''),
        ('@transform-product', ''),
        ('@transform-unified', ''),
        (' || orderedLatencyPresented()', ''),
    ],
    'linux': [
        ('if(strcmp(linux_ec_string(a,keys[i]),linux_ec_string(b,keys[i])))return FALSE;', 'if(FALSE)return FALSE;'),
        ('linux_ec_number(d,"samples")!=3', 'FALSE'),
        ('g_get_monotonic_time()>=t->live_deadline', 'FALSE'),
        ('(actions ? actions->generation : 0) == generation', '((void)actions, (void)generation, TRUE)'),
        ('linux_telemetry_same_route_v9(t->route_status, t->map_status) &&', 'TRUE &&'),
        ('if (!rv_http_ready_v16(t->route_job)) return;', 'if (FALSE) return;'),
        ('g_strcmp0(active_router_id(t->app),t->live_selected)==0', 'TRUE'),
    ],
    'windows': [
        ('if($A.Binding[$Key]-cne$B.Binding[$Key])', 'if($false)'),
        ("(UnifiedLiveNumber $D 'samples')-ne3", '$false'),
        ('[System.Diagnostics.Stopwatch]::GetTimestamp()-ge$script:UnifiedLiveHTTPS.Deadline', '$false'),
    ],
}


class ExecutedNegativeControl(Exception):
    """Every selected shell reached the intended shipping assertion."""


WINDOWS_NEGATIVE_ASSERTIONS = (
    'late/foreign live value published: source',
    'malformed receipt accepted: partial',
    'expired live value survived',
)


def windows_negative_receipt(result, shell, expected):
    lines = result.stdout.splitlines()
    if (result.returncode == 0 or 'RV_LIVE_START' not in lines or
            'RV_LIVE_ASSERT:' + expected not in lines):
        raise AssertionError(
            f'{shell}: negative control did not execute its exact assertion '
            f'{expected!r}; exit={result.returncode}\n{result.stdout}')



def shipping(source):
    if MUTATION is not None:
        before, after = MUTATION
        if before.startswith('@transform-'):
            return source
        assert source.count(before) == 1, 'negative control source seam drifted'
        source = source.replace(before, after, 1)
    return source


def block(source, marker):
    start = source.index(marker)
    brace = source.index('{', start)
    depth, end = 1, brace + 1
    while depth and end < len(source):
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    assert depth == 0, marker
    return source[start:end]


def fixture(directory):
    value = dict(connected=True, profile_id='selected', profile_token='a'*64,
                 session_id='b'*32, request_id='c'*32, source_sha256='d'*64,
                 config_sha256='e'*64, network_sha256='f'*64, measured_at=0,
                 expires_in_ms=10000, measurement='routed-https-response-after-tls')
    value['response'] = dict(schema=1, measurement=value['measurement'],
        endpoint='https://speed.cloudflare.com/__down?bytes=1', attempts=3,
        distribution=dict(samples=3, min_ms=2, median_ms=4, average_ms=4,
                          p90_ms=6, max_ms=6, jitter_ms=4))
    (directory/'receipt.json').write_text(json.dumps(value))


def swift(directory):
    source = shipping((ROOT/'client/macos/RouterVPNMacTelemetry.swift').read_text())
    policy = block(source, 'private struct RouterVPNLiveHTTPSReceipt {').replace('private struct','struct',1)
    policy += '\n' + block(source, 'struct RouterVPNMacLiveRouteReceipt {')
    owner = block(source, 'private final class RouterVPNLiveTelemetryDelivery {').replace('private final','final',1)
    owner += '\n'+block((ROOT/'client/macos/RouterVPNMacViaEntryPolicy.swift').read_text(), 'final class MacViaEntryCandidateReservation:')
    methods = '\n'.join(block(source, 'func '+name+'(') for name in
        ['clearLiveHTTPS', 'liveHTTPSPaused', 'beginLiveHTTPSMutation', 'endLiveHTTPSMutation', 'showLiveHTTPS', 'displayUnifiedLiveRoute', 'refreshUnifiedTelemetry'])
    globe = (ROOT/'client/macos/RouterVPNMacGlobeChrome.swift').read_text()
    methods += '\n' + block(globe, 'func refreshUnifiedMapChrome(')
    spec=importlib.util.spec_from_file_location('live_mutation_transform',ROOT/'client/macos/macos-session-mutation-transform.py')
    transform=importlib.util.module_from_spec(spec);spec.loader.exec_module(transform)
    product=transform.transform((ROOT/'client/macos/RouterVPNMacProduct.swift').read_text(),'product')
    unified=transform.transform((ROOT/'client/macos/RouterVPNMacUnifiedShell.swift').read_text(),'unified')
    if MUTATION is not None and MUTATION[0].startswith('@transform-'):
        before='let liveMutation = beginLiveHTTPSMutation()'
        if MUTATION[0]=='@transform-product':
            assert product.count(before)==1;product=product.replace(before,'let liveMutation = UUID()',1)
        else:
            assert unified.count(before)==1;unified=unified.replace(before,'let liveMutation = UUID()',1)
    methods += '\n'+block(product,'func asyncAction(')+'\n'+block(unified,'func connectUnified(')
    program = r'''
import Foundation
import CoreFoundation
final class DispatchQueue {
 static let main = DispatchQueue(); static let background = DispatchQueue(); var jobs:[()->Void]=[];var timers:[()->Void]=[]
 static func global(qos:DispatchQoS.QoSClass)->DispatchQueue{background}
 func async(execute:@escaping()->Void){if self === Self.main{jobs.append(execute)}else{execute()}}
 func asyncAfter(deadline:DispatchTime,execute:@escaping()->Void){timers.append(execute)}
 func flush(){let pending=jobs;jobs=[];pending.forEach{$0()}}
 func flushOne(){jobs.removeFirst()()}
}
enum Color {case labelColor,secondaryLabelColor}
class NSView {}
class NSButton:NSView {enum State {case on,off};var state=State.off;var title="Disconnect"}
final class MacUnifiedConnectButton:NSButton {var stopRetryToken:String?}
final class Field{var stringValue="-- ms";var toolTip="";var textColor=Color.labelColor}
final class Popup{var indexOfSelectedItem=0}
final class Window{var isVisible=true;var attachedSheet:Window?}
final class RouterAnnotation{let routerID="selected";let storedSubtitle:String?="catalog";var subtitle:String?="catalog"}
final class Map{var annotations:[Any]=[RouterAnnotation()]}
final class RouterVPNMacPerformanceController{var window:Window?=Window()}
final class RouterVPNMacExternalComparisonController{var window:Window?=Window()}
final class RouterVPNMacOrderedCandidates{var window:Window?=Window()}
var candidatePresented=false
var telemetryPerformanceControllerKey:UInt8=0,telemetryExternalComparisonControllerKey:UInt8=0,telemetryOrderedCandidatesKey:UInt8=0
func objc_getAssociatedObject(_ value:AnyObject,_ key:UnsafeRawPointer)->Any?{candidatePresented ? RouterVPNMacOrderedCandidates():nil}
final class ProductAPI {
 var calls:[String]=[];var replies:[[String:Any]]=[];var statuses:[[String:Any]]=[];var receipt:[String:Any]=[:]
 func json(_ path:String,timeout:TimeInterval=15)throws->Any{calls.append(path);if path=="/api/multihop/status"{if statuses.isEmpty{return ["connected":false] as [String:Any]};return statuses.removeFirst()};if replies.isEmpty{throw NSError(domain:"no fixture",code:1)};return replies.removeFirst()}
 func request(_ path:String,method:String,body:[String:Any],timeout:TimeInterval)throws->Data{calls.append(path);return try JSONSerialization.data(withJSONObject:receipt)}
}
typealias CLLocationCoordinate2D=Double
final class Chrome {
 var refreshID:UUID?,selectionGeneration:UUID?,mutationGeneration:UUID?
 var path:Double=0
 func update(ids:[String]?,coordinates:[Double?],routeID:String,pathMs:Double,deadline:Double){path=pathMs}
}
func productStopRetryToken(_ value:[String:Any])throws->String?{nil}
POLICY
OWNER
final class Form {
 var unifiedLiveProbe:NSLock{liveTelemetryDelivery.probe}
 let unifiedMapChromeView:Chrome?=Chrome();var mapMutationGeneration:UUID?=UUID()
 static func unifiedMapCoordinate(_ node:[String:Any])->Double?{nil}
 func refreshUnifiedHopOverlay(){}
 let liveTelemetryDelivery=RouterVPNLiveTelemetryDelivery();var window:Window?=Window();var map=Map();var routerPopup=Popup();var routerIDs=["selected"]
 var telemetryLiveLabel:Field?=Field(),telemetryHopLabel:Field?=Field();var connectionProfileSelectionGeneration=UUID();var api=ProductAPI()
 var multihopEntryPopup=Popup(),multihopExitPopup=Popup(),multihopNodeIDs:[String]=[];var connect=MacUnifiedConnectButton();var paused=false,orderedLatencyVisible=false;let errorLabel=Field()
 func telemetryFind(_ id:String)->NSView?{id=="unified-connect" ? connect : NSButton()}
 func refreshUnifiedFastNodeMenu(){};func refreshUnifiedForwardingMaster(){};func unifiedSpeedLabPresented()->Bool{paused}
 func orderedLatencyPresented()->Bool{orderedLatencyVisible}
 func findUnifiedView(_ id:String)->NSView?{telemetryFind(id)};func appendHelp(_ message:String){};func refreshAll(){};func refreshLive(){};func refreshUnifiedChrome(){};func startUnifiedSelectedMode(){}
 METHODS
}
var checks=0
func check(_ ok:Bool,_ message:String){checks+=1;if !ok{fatalError(message)}}
let raw=try! Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[1]).appendingPathComponent("receipt.json"))
func value()->[String:Any]{var v=try! JSONSerialization.jsonObject(with:raw) as! [String:Any];v["measured_at"]=Date().timeIntervalSince1970*1000;return v}
func decode(_ v:[String:Any])->RouterVPNLiveHTTPSReceipt?{RouterVPNLiveHTTPSReceipt.decode(v,started:ProcessInfo.processInfo.systemUptime)}
check(decode(value())?.median==4,"typed three-response fixture rejected")
for fault in ["partial","fifty","expired","boolean","endpoint","mixed","source","future","bad-digest"] {
 var v=value();var r=v["response"] as! [String:Any];var d=r["distribution"] as! [String:Any]
 switch fault{case "partial":d["samples"]=2;case "fifty":r["attempts"]=50;case "expired":v["expires_in_ms"]=0;case "boolean":d["median_ms"]=true;case "endpoint":r["endpoint"]="https://elsewhere.invalid";case "mixed":v["benchmark"] = [:] as [String:String];case "source":v.removeValue(forKey:"source_sha256");case "future":v["measured_at"]=Date().timeIntervalSince1970*1000+1000;default:v["network_sha256"]="invalid"}
 r["distribution"]=d;v["response"]=r;check(decode(v)==nil,"invalid live receipt accepted: "+fault)
}
for fault in ["valid","source","selection","generation","closed","disconnect","paused","ordered-latency","modal","mutation","connect-mutation"] {
 let f=Form();let v=value();var checked=v;if fault=="source"{checked["source_sha256"]=String(repeating:"0",count:64)}
 f.api.replies=[v,checked];f.refreshUnifiedTelemetry()
 check(f.telemetryLiveLabel!.stringValue=="-- ms","background reply published before main delivery")
 check(f.api.calls==["/api/multihop/status","/api/connection/live-latency","/api/connection/live-latency?request_id="+String(repeating:"c",count:32),"/api/multihop/status"],"delivery skipped exact-request validation")
 switch fault{case "selection":f.connectionProfileSelectionGeneration=UUID();case "generation":f.liveTelemetryDelivery.generation=UUID();case "closed":f.window!.isVisible=false;case "disconnect":f.connect.title="Connect";case "paused":f.paused=true;case "ordered-latency":f.orderedLatencyVisible=true;case "modal":f.window!.attachedSheet=Window();case "mutation":f.asyncAction{"completed mutation"};case "connect-mutation":f.api.replies=[["connected":true]];f.connectUnified();default:break}
 if fault=="mutation"||fault=="connect-mutation" {
  check(!f.liveTelemetryDelivery.mutations.isEmpty,"shipping mutation did not retain its exact UI lease")
  let before=f.api.calls.count;f.refreshUnifiedTelemetry();check(f.api.calls.count==before,"polling crossed unfinished same-profile mutation")
  DispatchQueue.main.flushOne();check(f.liveTelemetryDelivery.receipt==nil&&f.telemetryLiveLabel!.stringValue=="-- ms","queued pre-mutation receipt appeared before mutation completion")
 }
 DispatchQueue.main.flush();let good=fault=="valid"
 check((f.liveTelemetryDelivery.receipt != nil)==good,"late/foreign delivery acquired receipt: "+fault)
 check((f.telemetryLiveLabel!.stringValue=="4.0 ms HTTPS")==good,"wrong metric label or stale visible score: "+fault)
 check(f.liveTelemetryDelivery.mutations.isEmpty,"captured mutation UI lease did not release")
 if good {check((f.map.annotations[0] as! RouterAnnotation).subtitle=="4.0 ms HTTPS","map missed truthful selected HTTPS");DispatchQueue.main.timers.forEach{$0()};check(f.liveTelemetryDelivery.receipt==nil&&(f.map.annotations[0] as! RouterAnnotation).subtitle=="catalog","expiry did not clear map and receipt")}
 DispatchQueue.main.timers=[]
}
let f=Form();f.paused=true;f.refreshUnifiedTelemetry();check(f.api.calls.isEmpty,"background polling starved explicit measurement")
f.paused=false;candidatePresented=true;f.refreshUnifiedTelemetry();check(f.api.calls.isEmpty,"connected prefix dialog did not pause background live measurement");candidatePresented=false
f.orderedLatencyVisible=true;f.refreshUnifiedTelemetry();check(f.api.calls.isEmpty,"ordered latency dialog did not pause background live measurement")
let token=String(repeating:"b",count:64)
let fullIDs=(0..<16).map{"node-"+String($0)}
let formatter=ISO8601DateFormatter();formatter.formatOptions=[.withInternetDateTime,.withFractionalSeconds]
for fault in ["valid","missing-entry","short-imported","donor-token","late-interior","exit","samples","expiry","map-mutation","selection","paused","bad-entry","busy"] {
 let ids=fault=="short-imported" ? ["external-entry","paired-exit"] : fullIDs
 let graph:[String:Any]=["connected":true,"active_node_ids":ids,"active_route_id":token,"actual_entry_id":ids.first!,"actual_exit_id":ids.last!]
 let f=Form()
 let now=formatter.string(from:Date().addingTimeInterval(fault=="expiry" ? -12 : -0.1))
 var path:[String:Any]=["connected":true,"mode":"multihop","router_id":ids.last!,"samples":2,"failed":0,"median_ms":7.0,"proof":"private proof","measured_at":now]
 var entry:[String:Any]=["id":ids.first!,"samples":2,"failed":0,"median_ms":3.0]
 let exit:[String:Any]=["id":ids.last!,"samples":2,"failed":0,"median_ms":7.0,"description":"private proof","measured_at":now]
 var current=graph
 if fault=="exit"{path["router_id"]=ids[13]};if fault=="samples"{path["samples"]=true}
 if fault=="bad-entry"{entry["id"]=ids[3]}
 if fault=="late-interior"{var changed=ids;changed.swapAt(9,10);current["active_node_ids"]=changed}
 f.api.receipt=["entry_id":ids.first!,"exit_id":ids.last!,"entry":entry,"exit":exit,"current_path":path,"active_route_id":fault=="donor-token" ? String(repeating:"a",count:64) : token]
 if fault=="missing-entry" || fault=="short-imported"{f.api.receipt.removeValue(forKey:"entry")}
 f.api.statuses=[graph,graph,current]
 if fault=="busy"{f.unifiedLiveProbe.lock()}
 f.refreshUnifiedTelemetry();f.refreshUnifiedMapChrome()
 if fault=="busy"{f.unifiedLiveProbe.unlock()}
 if fault=="map-mutation"{f.mapMutationGeneration=UUID()};if fault=="selection"{f.connectionProfileSelectionGeneration=UUID()};if fault=="paused"{f.paused=true}
 DispatchQueue.main.flush()
 check(f.api.calls.filter{$0=="/api/multihop/live-latency"}.count==(fault=="busy" ? 0 : 1) && !f.api.calls.contains("/api/connection/live-latency"),"Connect and globe competed for native live response")
 let accepted=fault=="valid" || fault=="short-imported"
 check((f.unifiedMapChromeView!.path==7)==accepted && (f.telemetryLiveLabel!.stringValue=="7.0 ms")==accepted,"unbound route displayed or lost: "+fault)
 if accepted {check(f.telemetryHopLabel!.stringValue.contains("PATH 7.0 ms") && f.telemetryHopLabel!.stringValue.contains("IN 3.0")==(fault=="valid"),"wrong original private endpoints visible")}
 DispatchQueue.main.timers=[]
}
let r=decode(value())!;check(!r.current(r.deadline),"deadline remained current")
print("Shipping Swift live HTTPS decoder/delivery: \(checks) checks PASS; native controls/HTTP are fixture boundaries.")
'''.replace('POLICY',policy).replace('OWNER',owner).replace('METHODS',methods)
    path=directory/'live.swift';path.write_text(program)
    binary=directory/'live-swift'
    subprocess.run(['swiftc','-swift-version','5','-module-cache-path',str(directory/'cache'),str(path),'-o',str(binary)],check=True,timeout=120)
    subprocess.run([str(binary),str(directory)],check=True,timeout=30)


def linux(directory):
    source=shipping((ROOT/'client/linux/routervpn-telemetry-v9.inc').read_text())
    fields=source[:source.index('#include "routervpn-connection-profiles')]
    helpers='\n'.join(block(source,'static '+signature) for signature in [
        'JsonNode *linux_ec_member(', 'JsonObject *linux_ec_object(',
        'const char *linux_ec_string(', 'gboolean linux_ec_bool(',
        'double linux_ec_number(', 'gboolean linux_ec_token('])
    methods=source[source.index('static gboolean linux_live_paused('):source.index('static void linux_telemetry_free(')]
    methods += source[source.index('static gboolean linux_telemetry_original_path_v9('):source.index('static void linux_install_telemetry_v9(')]
    globe=(ROOT/'client/linux/routervpn-globe-v10.inc').read_text()
    methods=block(globe,'static JsonArray *linux_globe_active_ids_v10(')+'\n'+methods
    program=r'''
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <curl/curl.h>
#include <stdatomic.h>
#include <math.h>
#include <string.h>
typedef struct {GtkWidget*window,*map;const char*selected;} App;
typedef struct {guint64 generation;} LinuxAsyncActionsV16;
typedef struct {int unused;} LinuxUnifiedV8;
static LinuxAsyncActionsV16 state;static gboolean busy;static guint checks,starts,frees;static char*last_path;
static atomic_int controller_exit_pending;
static LinuxAsyncActionsV16*linux_async_state_v16(App*a){(void)a;return &state;}
static gboolean linux_async_busy_v16(App*a){(void)a;return busy;}
static gboolean routervpn_mutation_busy(App*a){(void)a;g_error("synchronous status request on GTK polling thread");return TRUE;}
static gboolean routervpn_phase_busy(const char*phase){return !strcmp(phase,"starting")||!strcmp(phase,"stopping");}
static gboolean routervpn_mutation_busy_from_status(JsonObject*o){return o==NULL||(json_object_has_member(o,"connected")&&json_object_get_boolean_member(o,"connected"));}
static const char*active_router_id(App*a){return a->selected;}
static guint map_requests,profile_applies,forward_applies;
typedef struct {atomic_int cancelled;gboolean ready;CURLcode result;long status;char*response;} RVHttpJobV16;
static RVHttpJobV16*rv_http_start_method_v17(const char*path,const char*body,long timeout,const char*label,int get){(void)label;g_assert(timeout>0&&timeout<=8000);g_assert(get==1||(!strcmp(path,"/api/multihop/live-latency")&&strstr(body,"original-entry")&&strstr(body,"original-final")&&strstr(body,"\"samples\":2")));if(!get)map_requests++;starts++;g_free(last_path);last_path=g_strdup(path);RVHttpJobV16*j=g_new0(RVHttpJobV16,1);atomic_init(&j->cancelled,0);return j;}
static gboolean rv_http_ready_v16(RVHttpJobV16*j){return j&&j->ready;}
static void rv_http_cancel_v16(RVHttpJobV16*j){if(j){atomic_store(&j->cancelled,1);j->ready=TRUE;}}
static void rv_http_free_v16(RVHttpJobV16*j){if(j){g_assert(j->ready);frees++;g_free(j->response);g_free(j);}}
static JsonNode*parse_json(const char*raw){if(!raw)return NULL;JsonParser*p=json_parser_new();JsonNode*n=NULL;if(json_parser_load_from_data(p,raw,-1,NULL))n=json_node_copy(json_parser_get_root(p));g_object_unref(p);return n;}
FIELDS
HELPERS
#define ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH 96
#define obj_string linux_ec_string
static JsonArray *linux_ordered_array_v1(JsonObject*o,const char*k){JsonNode*n=linux_ec_member(o,k);return n&&JSON_NODE_HOLDS_ARRAY(n)?json_node_get_array(n):NULL;}
static void linux_telemetry_apply_fastest_v9(LinuxTelemetryV9*t,JsonObject*o){(void)t;(void)o;profile_applies++;}
static void linux_telemetry_set_forward_label_v9(LinuxTelemetryV9*t,gboolean known,gboolean enabled){(void)t;(void)known;(void)enabled;forward_applies++;}
METHODS
static void check(gboolean value,const char*message){checks++;if(!value)g_error("live HTTPS GTK: %s",message);}
static JsonNode*value(const char*raw){JsonNode*n=parse_json(raw);json_object_set_int_member(json_node_get_object(n),"measured_at",g_get_real_time()/1000);return n;}
static void reply(LinuxTelemetryV9*t,JsonNode*n){JsonGenerator*g=json_generator_new();json_generator_set_root(g,n);t->live_job->response=json_generator_to_data(g,NULL);g_object_unref(g);t->live_job->status=200;t->live_job->result=CURLE_OK;t->live_job->ready=TRUE;linux_live_tick(t);}
int main(int argc,char**argv){
 check(gtk_init_check(&argc,&argv),"real GTK display");char*path=g_build_filename(argv[1],"receipt.json",NULL),*raw=NULL;g_assert(g_file_get_contents(path,&raw,NULL,NULL));g_free(path);
 App app={.window=gtk_window_new(GTK_WINDOW_TOPLEVEL),.map=gtk_drawing_area_new(),.selected="selected"};LinuxTelemetryV9 t={.app=&app,.live=gtk_label_new("-- ms")};g_object_set_data(G_OBJECT(app.window),"linux-telemetry-v9",&t);
 for(int fault=0;fault<9;fault++){
  JsonNode*n=value(raw);JsonObject*o=json_node_get_object(n),*r=linux_ec_object(o,"response"),*d=linux_ec_object(r,"distribution");
  switch(fault){case 1:json_object_set_int_member(d,"samples",2);break;case 2:json_object_set_int_member(r,"attempts",50);break;case 3:json_object_set_int_member(o,"expires_in_ms",0);break;case 4:json_object_set_boolean_member(d,"median_ms",TRUE);break;case 5:json_object_set_string_member(r,"endpoint","https://elsewhere.invalid");break;case 6:json_object_set_null_member(o,"benchmark");break;case 7:json_object_remove_member(o,"source_sha256");break;case 8:json_object_set_int_member(o,"measured_at",g_get_real_time()/1000+1000);break;}
  double ms;gint64 deadline;check(linux_live_receipt(o,g_get_real_time()/1000,g_get_monotonic_time(),g_get_monotonic_time()-100,&ms,&deadline)==(fault==0),"decoder admitted malformed/mixed response");json_node_free(n);
 }
 for(int fault=0;fault<7;fault++){
  linux_live_clear(&t);busy=FALSE;app.selected="selected";JsonNode*n=value(raw);linux_live_start(&t);check(t.live_job!=NULL,"background response did not start");reply(&t,n);
  check(t.live_ms==0&&t.live_job!=NULL&&strstr(last_path,"?request_id=cccccccccccccccccccccccccccccccc")!=NULL,"first reply acquired score without exact validation");
  switch(fault){case 1:json_object_set_string_member(json_node_get_object(n),"source_sha256","0000000000000000000000000000000000000000000000000000000000000000");break;case 2:state.generation++;break;case 3:busy=TRUE;break;case 4:app.selected="foreign";break;case 5:json_object_set_int_member(json_node_get_object(n),"expires_in_ms",0);break;case 6:rv_http_cancel_v16(t.live_job);break;}
  reply(&t,n);check((t.live_ms==4)==(fault==0),"late/foreign delivery published HTTPS");check(t.live_job==NULL&&t.live_capture==NULL,"owned HTTP delivery not joined");
  if(fault==0){check(strcmp(gtk_label_get_text(GTK_LABEL(t.live)),"4.0 ms HTTPS")==0&&linux_live_map_ms(&app,"selected")==4&&linux_live_map_ms(&app,"foreign")==0,"truthful map/source display missing");t.live_deadline=g_get_monotonic_time()-1;linux_live_tick(&t);check(t.live_ms==0&&strcmp(gtk_label_get_text(GTK_LABEL(t.live)),"-- ms")==0,"expired response remained visible");}
  json_node_free(n);
 }
 busy=TRUE;guint before=starts;linux_live_start(&t);check(starts==before,"background probe started during manual action");busy=FALSE;
 GtkWidget*panel=gtk_window_new(GTK_WINDOW_TOPLEVEL);gtk_window_set_transient_for(GTK_WINDOW(panel),GTK_WINDOW(app.window));g_object_set_data(G_OBJECT(panel),"linux-performance-v17",&t);gtk_widget_show(panel);linux_live_start(&t);check(starts==before,"visible Performance did not pause polling");gtk_widget_destroy(panel);
 t.hop=gtk_label_new("");state.generation=0;
 JsonNode*route=parse_json("{\"connected\":true,\"actual_entry_id\":\"original-entry\",\"actual_exit_id\":\"original-final\",\"active_node_ids\":[\"original-entry\",\"original-final\"]}");
 JsonNode*receipt=parse_json("{\"entry_id\":\"original-entry\",\"exit_id\":\"original-final\",\"current_path\":{\"connected\":true,\"mode\":\"multihop\",\"router_id\":\"original-final\",\"samples\":2,\"median_ms\":7}}");
 char*route_id=g_strnfill(64,'a'),*other=g_strnfill(64,'b');
 json_object_set_string_member(json_node_get_object(route),"active_route_id",route_id);
 JsonNode*controller=parse_json("{\"connected\":true,\"phase\":\"connected\"}");t.controller_status=json_object_ref(json_node_get_object(controller));json_node_free(controller);
 for(guint fault=0;fault<9;fault++){
  app.selected="selected";busy=FALSE;atomic_store(&controller_exit_pending,0);
  JsonObject*r=json_node_get_object(receipt),*path=linux_ec_object(r,"current_path");
  json_object_set_string_member(r,"active_route_id",fault==1?other:route_id);
  json_object_set_string_member(path,"router_id",fault==2?"foreign":"original-final");
  guint initial=starts;
  g_clear_pointer(&t.map_latency,json_object_unref);linux_telemetry_refresh_path_v9(&t,json_node_get_object(route));
  check(starts==initial+1&&map_requests==fault+1&&t.route_job!=NULL&&t.live_job==NULL,"connected route issued a competing or synchronous live request");
  linux_telemetry_receive_route_v9(&t);
  check(t.map_latency==NULL&&t.route_job!=NULL,"unfinished route response published or was joined early");
  if(fault==3)state.generation++;
  if(fault==4)app.selected="foreign";
  if(fault==5)busy=TRUE;
  if(fault==6)t.route_started-=11*G_TIME_SPAN_SECOND;
  if(fault==7){char*serialized=json_to_string(route,FALSE);JsonNode*changed=parse_json(serialized);g_free(serialized);JsonArray*ids=linux_ordered_array_v1(json_node_get_object(changed),"active_node_ids");json_array_add_string_element(ids,"changed-interior");g_clear_pointer(&t.map_status,json_object_unref);t.map_status=json_object_ref(json_node_get_object(changed));json_node_free(changed);}
  if(fault==8)atomic_store(&controller_exit_pending,1);
  t.route_job->response=json_to_string(receipt,FALSE);t.route_job->ready=TRUE;t.route_job->status=200;t.route_job->result=CURLE_OK;
  linux_telemetry_receive_route_v9(&t);
  check(t.route_job==NULL&&t.route_status==NULL,"route worker was not joined");
  char*reason=g_strdup_printf("Connect and Map borrowed a foreign, stale or missing private final: %u",fault);check((t.map_latency!=NULL)==(fault==0)&&(strcmp(gtk_label_get_text(GTK_LABEL(t.live)),"7.0 ms")==0)==(fault==0),reason);g_free(reason);
 }
 busy=FALSE;app.selected="selected";atomic_store(&controller_exit_pending,0);
 JsonNode*draft=parse_json("{\"connected\":false,\"enabled\":true,\"entry_id\":\"original-entry\",\"exit_id\":\"original-final\"}");
 for(guint fault=0;fault<8;fault++){
  app.selected="selected";
  json_object_set_boolean_member(t.controller_status,"connected",TRUE);json_object_set_string_member(t.controller_status,"phase","connected");
  json_object_set_string_member(t.controller_status,"router_id","selected");json_object_set_string_member(t.controller_status,"mode","wireguard");
  guint before_map=map_requests;linux_telemetry_refresh_path_v9(&t,json_node_get_object(draft));
  check(t.live_job!=NULL&&t.route_job==NULL&&map_requests==before_map,"saved draft starved current ordinary connection response");
  JsonNode*private_reply=parse_json("{\"connected\":true,\"router_id\":\"selected\",\"mode\":\"wireguard\",\"samples\":2,\"failed\":0,\"median_ms\":5}");JsonObject*private_value=json_node_get_object(private_reply);
  if(fault==1)json_object_set_string_member(private_value,"mode","multihop");
  if(fault==2)app.selected="changed";
  if(fault==3)json_object_set_string_member(private_value,"router_id","changed");
  if(fault==4)json_object_set_string_member(private_value,"mode","shadowsocks");
  if(fault==5)state.generation++;
  if(fault==6)json_object_remove_member(private_value,"router_id");
  if(fault==7)t.live_started-=11*G_TIME_SPAN_SECOND;
  reply(&t,private_reply);json_node_free(private_reply);
  check((strcmp(gtk_label_get_text(GTK_LABEL(t.live)),"5.0 ms")==0)==(fault==0),"unbound, stale or ordered GET populated ordinary Connect value");
  if(fault==0){t.live_deadline=g_get_monotonic_time()-1;linux_live_tick(&t);check(!strcmp(gtk_label_get_text(GTK_LABEL(t.live)),"-- ms"),"expired private response remained visible");}
 }
 app.selected="selected";
 json_object_set_boolean_member(t.controller_status,"connected",FALSE);json_object_set_string_member(t.controller_status,"phase","off");
 for(guint fault=0;fault<4;fault++){
  linux_telemetry_refresh_path_v9(&t,json_node_get_object(draft));
  check(t.route_job!=NULL&&t.live_job==NULL,"explicit disconnected draft lost its sole observer");
  JsonNode*answer=parse_json("{\"entry_id\":\"original-entry\",\"exit_id\":\"original-final\",\"entry\":{\"median_ms\":3},\"exit\":{\"median_ms\":7}}");JsonObject*a=json_node_get_object(answer);
  if(fault==1)json_object_set_string_member(a,"active_route_id",route_id);
  if(fault==2)json_object_set_object_member(a,"current_path",json_object_new());
  if(fault==3)json_object_set_string_member(a,"entry_id","changed");
  t.route_job->response=json_to_string(answer,FALSE);t.route_job->ready=TRUE;t.route_job->status=200;t.route_job->result=CURLE_OK;json_node_free(answer);linux_telemetry_receive_route_v9(&t);
  check((strstr(gtk_label_get_text(GTK_LABEL(t.hop)),"IN 3.0")!=NULL)==(fault==0)&&t.map_latency==NULL,"draft displayed an active, changed or fabricated full path");
 }
 json_node_free(draft);
 atomic_store(&controller_exit_pending,1);guint shutdown_starts=starts;
 linux_live_start(&t);linux_telemetry_refresh_v9(&t);
 check(starts==shutdown_starts&&t.live_job==NULL&&t.route_job==NULL,"shutdown/layout preview attached to a controller");
 atomic_store(&controller_exit_pending,0);
 // The real polling callback must return with all reads still outstanding.
 // Delayed and failed status cannot launch a speculative native probe.
 for(guint fault=0;fault<5;fault++){
  t.refresh_after=0;guint initial=starts,published_profiles=profile_applies,published_forward=forward_applies;
  gint64 began=g_get_monotonic_time();linux_telemetry_refresh_v9(&t);
  check(g_get_monotonic_time()-began<100000&&starts==initial+4,"periodic refresh blocked or missed a background read");
  for(int i=0;i<4;i++)check(t.refresh_jobs[i]!=NULL&&!t.refresh_jobs[i]->ready,"pending read was not retained");
  for(int tick=0;tick<10;tick++)linux_telemetry_refresh_v9(&t);
  check(starts==initial+4&&profile_applies==published_profiles&&forward_applies==published_forward,"pending refresh overlapped or applied unfinished data");
  if(fault==1)state.generation++;
  if(fault==2)app.selected="foreign";
  if(fault==3)busy=TRUE;
  t.refresh_after=g_get_monotonic_time()+3*G_TIME_SPAN_SECOND;
  for(int i=0;i<4;i++){t.refresh_jobs[i]->response=g_strdup(i==0?"{\"profiles\":[]}":i==1?"{\"enabled\":false}":"{}");t.refresh_jobs[i]->ready=TRUE;t.refresh_jobs[i]->status=200;t.refresh_jobs[i]->result=CURLE_OK;}
  if(fault==4)t.refresh_jobs[2]->status=503;
  // Block a new round while checking delivery of this exact one.
  busy=fault==3;linux_telemetry_refresh_v9(&t);
  gboolean accepted=fault==0||fault==4;
  check((profile_applies==published_profiles+1)==accepted&&(forward_applies==published_forward+1)==accepted,"changed selection/generation applied stale control reads");
  check(t.route_job==NULL&&t.live_job==NULL,"unknown status started a native measurement");
  for(int i=0;i<4;i++){if(t.refresh_jobs[i]){rv_http_cancel_v16(t.refresh_jobs[i]);rv_http_free_v16(t.refresh_jobs[i]);t.refresh_jobs[i]=NULL;}}
  busy=FALSE;app.selected="selected";
 }
 g_clear_pointer(&t.map_status,json_object_unref);g_clear_pointer(&t.map_latency,json_object_unref);g_clear_pointer(&t.controller_status,json_object_unref);g_free(t.refresh_id);g_free(t.route_profile_id);g_free(t.live_selected);g_free(t.live_router_id);g_free(t.live_mode);
 json_node_free(route);json_node_free(receipt);g_free(route_id);g_free(other);gtk_widget_destroy(t.hop);
 check(starts==frees,"HTTP owner leaked");linux_live_clear(&t);gtk_widget_destroy(t.live);gtk_widget_destroy(app.map);gtk_widget_destroy(app.window);g_free(raw);g_free(last_path);
 printf("Shipping GTK live HTTPS decoder/delivery: %u checks PASS; real widgets, controlled HTTP boundary.\n",checks);return 0;
}
'''.replace('FIELDS',fields).replace('HELPERS',helpers).replace('METHODS',methods)
    path=directory/'live.c';path.write_text(program)
    binary=directory/'live-gtk'
    flags=subprocess.check_output(['pkg-config','--cflags','--libs','gtk+-3.0','json-glib-1.0','libcurl'],text=True).split()
    subprocess.run(['gcc','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-misleading-indentation',str(path),'-o',str(binary),*flags,'-lm'],check=True,timeout=90)
    command=[str(binary),str(directory)]
    if not os.environ.get('DISPLAY'):command=['xvfb-run','-a',*command]
    subprocess.run(command,check=True,timeout=30)


def windows(directory):
    source=shipping((ROOT/'client/RouterVPN-Windows-Telemetry.ps1').read_text(encoding='utf-8-sig'))
    names=['ExternalComparisonValue','ExternalComparisonToken','UnifiedLiveNumber','ReadUnifiedLiveHTTPS','TestUnifiedLiveHTTPSMatch','ClearUnifiedLiveHTTPS','ExpireUnifiedLiveHTTPS','UnifiedLiveHTTPSForID','UnifiedTelemetryBusy','CancelUnifiedTelemetryRefreshAsync','StartUnifiedTelemetryRefresh','CompleteUnifiedTelemetryRefresh']
    methods='\n'.join(block(source,'function '+name) for name in names)
    program=r'''
param([string]$Output)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Net.Http
$script:Checks=0
function Check($Value,[string]$Message){$script:Checks++;if(-not$Value){[Console]::Error.WriteLine('RV_LIVE_ASSERT:'+$Message);throw $Message}}
$script:Controls=@{}
function Control([string]$Name){if(-not$script:Controls.ContainsKey($Name)){$script:Controls[$Name]=[pscustomobject]@{Text='-- ms';ToolTip='';Foreground='';IsEnabled=$false;IsChecked=$false;Content='';Tag=$null}};return $script:Controls[$Name]}
function UnifiedAsyncBusy{return $script:Busy}
function Test-RouterVPNMutationBusyFromStatus($S){return $false}
function ApplyUnifiedFastestStore($S){}
function Get-RouterVPNOrderedValue($S,$K){return $S.$K}
$script:Busy=$false;$Window=[pscustomobject]@{OwnedWindows=@();IsVisible=$true};$MapCanvas=[pscustomobject]@{Children=@()};$RouterCombo=[pscustomobject]@{SelectedValue='selected'};$BaseUrl='http://127.0.0.1:1';$script:UnifiedProtectionPending=$false
$script:UnifiedTelemetryTasks=@{};$script:UnifiedTelemetryRequests=@{};$script:UnifiedTelemetryPending=$null;$script:UnifiedTelemetryOriginal=$null;$script:UnifiedTelemetryDiscard=$false;$script:UnifiedLiveHTTPS=$null
$script:UnifiedTelemetryPoller=[pscustomobject]@{};$script:UnifiedTelemetryPoller|Add-Member ScriptMethod Start {};$script:UnifiedTelemetryPoller|Add-Member ScriptMethod Stop {}
$script:Replies=[System.Collections.Generic.Queue[string]]::new();$script:Paths=[System.Collections.Generic.List[string]]::new()
$script:UnifiedTelemetryClient=[pscustomobject]@{}
$script:UnifiedTelemetryClient|Add-Member ScriptMethod SendAsync {param($Req,$Token)
 $script:Paths.Add($Req.RequestUri.PathAndQuery);$Resp=[System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::NotFound)
 if($Req.RequestUri.AbsolutePath-in@('/api/connection/live-latency','/api/multihop/live-latency')){$Resp.StatusCode=[System.Net.HttpStatusCode]::OK;$Resp.Content=[System.Net.Http.StringContent]::new($script:Replies.Dequeue())}
 elseif($Req.RequestUri.AbsolutePath-eq'/api/status' -and $script:ControllerStatus){$Resp.StatusCode=[System.Net.HttpStatusCode]::OK;$Resp.Content=[System.Net.Http.StringContent]::new(($script:ControllerStatus|ConvertTo-Json))}
 else{$Resp.Content=[System.Net.Http.StringContent]::new('{}')}
 $Completed=New-Object 'System.Threading.Tasks.TaskCompletionSource[System.Net.Http.HttpResponseMessage]'
 $Completed.SetResult($Resp)
 return $Completed.Task
}
METHODS
function Value{$V=Get-Content (Join-Path $Output 'receipt.json') -Raw|ConvertFrom-Json;$V.measured_at=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();return $V}
function Decode($V){ReadUnifiedLiveHTTPS $V ([System.Diagnostics.Stopwatch]::GetTimestamp())}
[Console]::WriteLine('RV_LIVE_START')
Check ((Decode (Value)).Median-eq4) 'valid live3 rejected'
foreach($Fault in @('partial','fifty','expired','boolean','endpoint','mixed','source','future')){
 $V=Value;switch($Fault){partial{$V.response.distribution.samples=2}fifty{$V.response.attempts=50}expired{$V.expires_in_ms=0}boolean{$V.response.distribution.median_ms=$true}endpoint{$V.response.endpoint='https://elsewhere.invalid'}mixed{$V|Add-Member NoteProperty benchmark ([pscustomobject]@{})}source{$V.source_sha256='invalid'}future{$V.measured_at+=1000}}
 Check ($null-eq(Decode $V)) ('malformed receipt accepted: '+$Fault)
}
foreach($Fault in @('valid','source','cancel','busy','expired')){
 ClearUnifiedLiveHTTPS;$script:Busy=$false;$V=Value;$Other=($V|ConvertTo-Json -Depth 9)|ConvertFrom-Json
 switch($Fault){source{$Other.source_sha256='0'*64}expired{$Other.expires_in_ms=0}}
 $script:Replies.Enqueue(($V|ConvertTo-Json -Depth 9));$script:Replies.Enqueue(($Other|ConvertTo-Json -Depth 9));StartUnifiedTelemetryRefresh;CompleteUnifiedTelemetryRefresh
 Check ($null-eq$script:UnifiedLiveHTTPS-and(UnifiedTelemetryBusy)-and$script:Paths[$script:Paths.Count-1].EndsWith('?request_id='+('c'*32))) 'first reply skipped captured validation'
 if($Fault-eq'cancel'){[void](CancelUnifiedTelemetryRefreshAsync)};if($Fault-eq'busy'){$script:Busy=$true}
 CompleteUnifiedTelemetryRefresh;Check (($null-ne$script:UnifiedLiveHTTPS)-eq($Fault-eq'valid')) ('late/foreign live value published: '+$Fault)
 Check (-not(UnifiedTelemetryBusy)-and$null-eq$script:UnifiedTelemetryPending) 'owned tasks did not drain'
 if($Fault-eq'valid'){Check ((Control 'UnifiedLiveLatency').Text-eq'4.0 ms HTTPS'-and(UnifiedLiveHTTPSForID 'selected')-eq4-and(UnifiedLiveHTTPSForID 'foreign')-eq0) 'metric/source label wrong';$script:UnifiedLiveHTTPS.Deadline=[long]0;ExpireUnifiedLiveHTTPS;Check ((Control 'UnifiedLiveLatency').Text-eq'-- ms'-and$null-eq$script:UnifiedLiveHTTPS) 'expired live value survived'}
}
$script:Busy=$false
$route='a'*64;$script:UnifiedMapRouteID=$route
$script:UnifiedDisplayedRoute=[pscustomobject]@{RouteID=$route;IDs=@('original-entry','middle','original-final')}
foreach($Fault in @('valid','route','exit')){
 $script:Paths.Clear()
 $p=@{connected=$true;mode='multihop';router_id='original-final';samples=2;median_ms=7}
 $receipt=@{entry_id='original-entry';exit_id='original-final';active_route_id=$route;current_path=$p}
 if($Fault-eq'route'){$receipt.active_route_id='b'*64}
 if($Fault-eq'exit'){$p.router_id='foreign'}
 $script:Replies.Enqueue(($receipt|ConvertTo-Json -Depth 9))
 StartUnifiedTelemetryRefresh;CompleteUnifiedTelemetryRefresh
 Check ($script:Paths.Contains('/api/multihop/live-latency') -and -not $script:Paths.Contains('/api/connection/live-latency')) 'connected route issued competing live requests'
 Check (($null-ne$script:UnifiedMapLatency)-eq($Fault-eq'valid') -and ((Control 'UnifiedLiveLatency').Text-eq'7.0 ms')-eq($Fault-eq'valid')) 'Connect and Map adopted a foreign private final'
}
$script:UnifiedDisplayedRoute=$null;$script:UnifiedMapRouteID='';(Control 'UnifiedMultihop').IsChecked=$true
$MultihopEntryCombo=[pscustomobject]@{SelectedValue='draft-entry'};$MultihopExitCombo=[pscustomobject]@{SelectedValue='draft-final'}
$script:ControllerStatus=@{connected=$false;phase='off'}
$script:Paths.Clear();$script:Replies.Enqueue((@{connected=$true;mode='multihop';router_id='draft-final';median_ms=9}|ConvertTo-Json))
StartUnifiedTelemetryRefresh;CompleteUnifiedTelemetryRefresh
Check ($script:Paths.Contains('/api/connection/live-latency') -and -not $script:Paths.Contains('/api/multihop/live-latency') -and (Control 'UnifiedLiveLatency').Text-eq'-- ms') 'unknown route competed with draft or displayed unbound ordered response'
$draft=@{entry_id='draft-entry';exit_id='draft-final';entry=@{median_ms=6};exit=@{median_ms=8}}
foreach($Fault in @('disconnected','route-started','state-changed')){
 $script:Paths.Clear()
 $reply=$draft.Clone()
 if($Fault-eq'route-started'){$reply.active_route_id=$route;$reply.current_path=@{connected=$true;mode='multihop';router_id='draft-final';median_ms=9}}
 if($Fault-eq'state-changed'){$script:ControllerStatus=@{connected=$true;phase='connected';mode='wg'}}
 $script:Replies.Enqueue(($reply|ConvertTo-Json -Depth 9))
 StartUnifiedTelemetryRefresh;CompleteUnifiedTelemetryRefresh
 Check ($script:Paths.Contains('/api/multihop/live-latency') -and -not $script:Paths.Contains('/api/connection/live-latency')) 'explicit disconnected draft started another observer'
 Check (((Control 'UnifiedMultihopLatency').Text -match 'IN 6') -eq ($Fault-eq'disconnected') -and $null-eq$script:UnifiedMapLatency -and (Control 'UnifiedLiveLatency').Text-eq'-- ms') 'draft displayed an active or changed route'
}
$script:Paths.Clear();$script:Replies.Enqueue((@{connected=$true;mode='wg';router_id='selected';median_ms=5}|ConvertTo-Json))
StartUnifiedTelemetryRefresh;CompleteUnifiedTelemetryRefresh
Check ($script:Paths.Contains('/api/connection/live-latency') -and -not $script:Paths.Contains('/api/multihop/live-latency') -and (Control 'UnifiedLiveLatency').Text-eq'5.0 ms') 'draft checkbox hid connected single-node response'
$script:Busy=$false;$Before=$script:Paths.Count;$Window.OwnedWindows=@([pscustomobject]@{IsVisible=$true});StartUnifiedTelemetryRefresh;Check ($script:Paths.Count-eq$Before) 'manual panel did not pause background polling'
Write-Output "Shipping PowerShell live HTTPS decoder/delivery: $script:Checks checks PASS; WPF controls and HTTP delivery are fixture boundaries."
'''.replace('METHODS',methods)
    path=directory/'live.ps1';path.write_text(program, encoding='utf-8-sig')
    shells=[x for x in ('pwsh','powershell.exe') if shutil.which(x)]
    if not shells:raise RuntimeError('PowerShell is required')
    for shell in shells:
        command=[shell,'-NoLogo','-NoProfile','-File',str(path),'-Output',str(directory)]
        if MUTATION is None:
            subprocess.run(command,check=True,timeout=60)
        else:
            expected=WINDOWS_NEGATIVE_ASSERTIONS[MUTATIONS['windows'].index(MUTATION)]
            result=subprocess.run(command,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=60)
            windows_negative_receipt(result,shell,expected)
            print(f'{shell} live HTTPS assertion {expected!r}: rejected',flush=True)
    if MUTATION is not None:
        raise ExecutedNegativeControl()


def run(platform, negative_controls=False):
    global MUTATION
    with tempfile.TemporaryDirectory(prefix='router-vpn-live-response-forms-') as temporary:
        directory=Path(temporary);fixture(directory)
        {'linux':linux,'darwin':swift,'windows':windows}[platform](directory)
        if negative_controls:
            for index, mutation in enumerate(MUTATIONS[platform], 1):
                MUTATION = mutation
                try:
                    with open(directory/'negative-control.log','w') as log:
                        saved = subprocess.run
                        def quiet(*args, **kwargs):
                            if kwargs.get('stdout') == subprocess.PIPE:
                                return saved(*args, **kwargs)
                            kwargs.update(stdout=log, stderr=subprocess.STDOUT)
                            return saved(*args, **kwargs)
                        subprocess.run = quiet
                        try: {'linux':linux,'darwin':swift,'windows':windows}[platform](directory)
                        finally: subprocess.run = saved
                except ExecutedNegativeControl:
                    print(f'{platform} live HTTPS negative control {index}: rejected in every selected shell', flush=True)
                except subprocess.CalledProcessError as failure:
                    # A compiler failure is not an executed negative witness.
                    if platform == 'windows' or Path(failure.cmd[0]).name in ('swiftc','gcc'):
                        raise AssertionError((directory/'negative-control.log').read_text()) from failure
                    print(f'{platform} live HTTPS negative control {index}: rejected', flush=True)
                else:
                    raise AssertionError(f'{platform} live HTTPS negative control {index} escaped')
                finally:
                    MUTATION = None


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform',choices=['linux','darwin','windows'],default='windows' if sys.platform=='win32' else sys.platform)
    parser.add_argument('--negative-controls',action='store_true')
    args=parser.parse_args();run(args.platform,args.negative_controls)
