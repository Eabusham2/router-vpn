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
    ],
    'linux': [
        ('if(strcmp(linux_ec_string(a,keys[i]),linux_ec_string(b,keys[i])))return FALSE;', 'if(FALSE)return FALSE;'),
        ('linux_ec_number(d,"samples")!=3', 'FALSE'),
        ('g_get_monotonic_time()>=t->live_deadline', 'FALSE'),
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
    owner = block(source, 'private final class RouterVPNLiveTelemetryDelivery {').replace('private final','final',1)
    methods = '\n'.join(block(source, 'func '+name+'(') for name in
        ['clearLiveHTTPS', 'liveHTTPSPaused', 'beginLiveHTTPSMutation', 'endLiveHTTPSMutation', 'showLiveHTTPS', 'refreshUnifiedTelemetry'])
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
var telemetryPerformanceControllerKey:UInt8=0,telemetryExternalComparisonControllerKey:UInt8=0
func objc_getAssociatedObject(_ value:AnyObject,_ key:UnsafeRawPointer)->Any?{nil}
final class ProductAPI {
 var calls:[String]=[];var replies:[[String:Any]]=[]
 func json(_ path:String,timeout:TimeInterval=15)throws->Any{calls.append(path);if replies.isEmpty{throw NSError(domain:"no fixture",code:1)};return replies.removeFirst()}
 func request(_ path:String,method:String,body:[String:Any],timeout:TimeInterval)throws->Data{calls.append(path);return Data("{}".utf8)}
}
func productStopRetryToken(_ value:[String:Any])throws->String?{nil}
POLICY
OWNER
final class Form {
 let liveTelemetryDelivery=RouterVPNLiveTelemetryDelivery();var window:Window?=Window();var map=Map();var routerPopup=Popup();var routerIDs=["selected"]
 var telemetryLiveLabel:Field?=Field(),telemetryHopLabel:Field?=Field();var connectionProfileSelectionGeneration=UUID();var api=ProductAPI()
 var multihopEntryPopup=Popup(),multihopExitPopup=Popup(),multihopNodeIDs:[String]=[];var connect=MacUnifiedConnectButton();var paused=false;let errorLabel=Field()
 func telemetryFind(_ id:String)->NSView?{id=="unified-connect" ? connect : NSButton()}
 func refreshUnifiedFastNodeMenu(){};func refreshUnifiedForwardingMaster(){};func unifiedSpeedLabPresented()->Bool{paused}
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
for fault in ["valid","source","selection","generation","closed","disconnect","paused","modal","mutation","connect-mutation"] {
 let f=Form();let v=value();var checked=v;if fault=="source"{checked["source_sha256"]=String(repeating:"0",count:64)}
 f.api.replies=[v,checked];f.refreshUnifiedTelemetry()
 check(f.telemetryLiveLabel!.stringValue=="-- ms","background reply published before main delivery")
 check(f.api.calls.count==2 && f.api.calls[1].hasSuffix("?request_id="+String(repeating:"c",count:32)),"delivery skipped exact-request validation")
 switch fault{case "selection":f.connectionProfileSelectionGeneration=UUID();case "generation":f.liveTelemetryDelivery.generation=UUID();case "closed":f.window!.isVisible=false;case "disconnect":f.connect.title="Connect";case "paused":f.paused=true;case "modal":f.window!.attachedSheet=Window();case "mutation":f.asyncAction{"completed mutation"};case "connect-mutation":f.api.replies=[["connected":true]];f.connectUnified();default:break}
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
static LinuxAsyncActionsV16*linux_async_state_v16(App*a){(void)a;return &state;}
static gboolean linux_async_busy_v16(App*a){(void)a;return busy;}
static const char*active_router_id(App*a){return a->selected;}
typedef struct {atomic_int cancelled;gboolean ready;CURLcode result;long status;char*response;} RVHttpJobV16;
static RVHttpJobV16*rv_http_start_method_v17(const char*path,const char*body,long timeout,const char*label,int get){(void)body;(void)label;g_assert(get==1&&(timeout==3500||timeout==3000));starts++;g_free(last_path);last_path=g_strdup(path);RVHttpJobV16*j=g_new0(RVHttpJobV16,1);atomic_init(&j->cancelled,0);return j;}
static gboolean rv_http_ready_v16(RVHttpJobV16*j){return j&&j->ready;}
static void rv_http_cancel_v16(RVHttpJobV16*j){atomic_store(&j->cancelled,1);j->ready=TRUE;}
static void rv_http_free_v16(RVHttpJobV16*j){frees++;g_free(j->response);g_free(j);}
static JsonNode*parse_json(const char*raw){if(!raw)return NULL;JsonParser*p=json_parser_new();JsonNode*n=NULL;if(json_parser_load_from_data(p,raw,-1,NULL))n=json_node_copy(json_parser_get_root(p));g_object_unref(p);return n;}
FIELDS
HELPERS
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
    source=shipping((ROOT/'client/RouterVPN-Windows-Telemetry.ps1').read_text())
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
$script:Busy=$false;$Window=[pscustomobject]@{OwnedWindows=@();IsVisible=$true};$MapCanvas=[pscustomobject]@{Children=@()};$RouterCombo=[pscustomobject]@{SelectedValue='selected'};$BaseUrl='http://127.0.0.1:1';$script:UnifiedProtectionPending=$false
$script:UnifiedTelemetryTasks=@{};$script:UnifiedTelemetryRequests=@{};$script:UnifiedTelemetryPending=$null;$script:UnifiedTelemetryOriginal=$null;$script:UnifiedTelemetryDiscard=$false;$script:UnifiedLiveHTTPS=$null
$script:UnifiedTelemetryPoller=[pscustomobject]@{};$script:UnifiedTelemetryPoller|Add-Member ScriptMethod Start {};$script:UnifiedTelemetryPoller|Add-Member ScriptMethod Stop {}
$script:Replies=[System.Collections.Generic.Queue[string]]::new();$script:Paths=[System.Collections.Generic.List[string]]::new()
$script:UnifiedTelemetryClient=[pscustomobject]@{}
$script:UnifiedTelemetryClient|Add-Member ScriptMethod SendAsync {param($Req,$Token)
 $script:Paths.Add($Req.RequestUri.PathAndQuery);$Resp=[System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::NotFound)
 if($Req.RequestUri.AbsolutePath-ceq'/api/connection/live-latency'){$Resp.StatusCode=[System.Net.HttpStatusCode]::OK;$Resp.Content=[System.Net.Http.StringContent]::new($script:Replies.Dequeue())}else{$Resp.Content=[System.Net.Http.StringContent]::new('{}')}
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
$script:Busy=$false;$Before=$script:Paths.Count;$Window.OwnedWindows=@([pscustomobject]@{IsVisible=$true});StartUnifiedTelemetryRefresh;Check ($script:Paths.Count-eq$Before) 'manual panel did not pause background polling'
Write-Output "Shipping PowerShell live HTTPS decoder/delivery: $script:Checks checks PASS; WPF controls and HTTP delivery are fixture boundaries."
'''.replace('METHODS',methods)
    path=directory/'live.ps1';path.write_text(program)
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
