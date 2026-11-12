#!/usr/bin/env python3
"""Execute desktop external-comparison actions against the shipping Go JSON.

GTK uses real widgets under Xvfb and a controlled short-HTTP delivery boundary.
Swift executes the actual asynchronous controller methods with value-only AppKit
objects and a synchronized API fixture. PowerShell executes generated WPF
callbacks with control/task-delivery doubles. Native packaged rendering and real
VPN/network receipts remain separate gates.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def block(source, marker):
    start = source.index(marker)
    brace = source.index('{', start)
    depth, pos = 1, brace + 1
    while depth and pos < len(source):
        depth += (source[pos] == '{') - (source[pos] == '}')
        pos += 1
    if depth:
        raise AssertionError('unclosed shipping block: ' + marker)
    return source[start:pos]


def swift_form(directory):
    source = (ROOT/'client/macos/RouterVPNMacTelemetry.swift').read_text()
    policy = block(source, 'private enum RouterVPNExternalComparisonDisplay {')
    owner = block(source, 'private final class RouterVPNMacExternalComparisonController:')
    fields = owner[owner.index('{')+1:owner.index('    init(api:')].replace('private(set) ', '').replace('private ', '')
    names = ['controls', 'comparePaths', 'connectFastest', 'begin', 'cancelComparison', 'windowShouldClose', 'windowWillClose', 'tick', 'send', 'receive']
    methods = '\n'.join(block(owner, 'func '+name+'(').replace('@objc ', '') for name in names)
    program = r'''
import Foundation
final class NSTextField { var stringValue: String; init(wrappingLabelWithString: String) {stringValue=wrappingLabelWithString} }
final class NSTextView {var string=""}
final class NSButton {var isEnabled=true;init(title:String,target:Any?,action:Any?){} }
final class NSWindow {var closes=0;func performClose(_ sender:Any?){closes+=1}}
final class ProductWindowController {
 let lock=NSLock();var busy=false;var refreshes=0
 func requireMutationIdle(_ text:String)throws{lock.lock();let reject=busy;lock.unlock();if reject{throw NSError(domain:"busy fixture",code:1)}}
 func refreshAll(){refreshes+=1};func refreshUnifiedChrome(){};func refreshUnifiedFastNodeMenu(){}
}
final class ProductAPI {
 struct Call {let path:String;let method:String;let body:[String:Any]?}
 let condition=NSCondition();var calls:[Call]=[];var replies:[Data]=[];var blocked=false;var completed=0
 func request(_ path:String,method:String="GET",body:[String:Any]?=nil,timeout:TimeInterval=15)throws->Data {
  condition.lock();defer{condition.unlock()};calls.append(Call(path:path,method:method,body:body));condition.broadcast()
  while blocked{condition.wait()};guard !replies.isEmpty,timeout==10 else{throw NSError(domain:"missing fixture response",code:1)}
  completed+=1;return replies.removeFirst()
 }
 func push(_ data:Data){condition.lock();replies.append(data);condition.unlock()}
 func snapshot()->[Call]{condition.lock();defer{condition.unlock()};return calls}
 func gate(_ value:Bool){condition.lock();blocked=value;condition.broadcast();condition.unlock()}
 func completions()->Int{condition.lock();defer{condition.unlock()};return completed}
}
POLICY
final class Form {
 FIELDS
 var window:NSWindow?=NSWindow()
 init(_ value:ProductWindowController){api=ProductAPI();product=value}
 METHODS
}
let output=URL(fileURLWithPath:CommandLine.arguments[1]);var checks=0
func data(_ name:String)->Data{try! Data(contentsOf:output.appendingPathComponent(name+".json"))}
func object(_ name:String)->[String:Any]{try! JSONSerialization.jsonObject(with:data(name)) as! [String:Any]}
func check(_ value:Bool,_ text:String){checks+=1;if !value{fatalError(text)}}
func spin(_ predicate:()->Bool){let deadline=Date().addingTimeInterval(8);while !predicate()&&Date()<deadline{RunLoop.current.run(until:Date().addingTimeInterval(0.01))};check(predicate(),"actual asynchronous callback did not settle")}
func save(_ call:ProductAPI.Call,_ name:String){try! JSONSerialization.data(withJSONObject:call.body!).write(to:output.appendingPathComponent(name+".json"))}
let offer=object("offer"),request=offer["request_id"] as! String,cohort=offer["cohort_id"] as! String
check(RouterVPNExternalComparisonDisplay.matches(object("compared"),request:request,cohort:cohort),"matching public result rejected")
check(!RouterVPNExternalComparisonDisplay.matches(object("foreign"),request:request,cohort:cohort),"foreign public result accepted")
let rows=object("compared")["rows"] as! [[String:Any]],bad=object("incomplete")["rows"] as! [[String:Any]]
check(RouterVPNExternalComparisonDisplay.score(rows[0])==4.5,"actual fifty metric lost")
check(RouterVPNExternalComparisonDisplay.score(bad[0])==nil,"49 samples became a score")
check(RouterVPNExternalComparisonDisplay.rows(rows,historical:true).contains("not a current winner"),"history became a live winner")
check(!RouterVPNExternalComparisonDisplay.state(object("draining")).contains("original connection state was restored"),"undrained cancellation claimed restoration")
let warning=RouterVPNExternalComparisonDisplay.state(object("connected-warning"));check(warning.contains("winner selection was saved") && !warning.contains("winner is connected"),"committed warning claimed a currently connected path")
do {
 // Keep the actual weak Product owner alive through asynchronous delivery.
 let owner=ProductWindowController();let f=Form(owner)
 f.api.push(data("offer"));f.api.push(data("active"));f.comparePaths();spin{f.api.snapshot().count==2 && !f.inflight}
 let calls=f.api.snapshot();check(calls[0].method=="GET"&&calls[1].method=="POST","Compare skipped a fresh offer");save(calls[1],"compare-body")
 f.api.push(data("compared"));f.nextPoll = .distantPast;f.tick();spin{f.finished && !f.inflight}
 check(f.status.stringValue.contains("original connection state was restored") && !f.status.stringValue.contains("winner is connected") && owner.refreshes==1,"Compare-only adopted a winner")
 check(f.api.snapshot()[2].path=="/api/speed-lab/external-comparison?request_id="+request,"poll lost its captured request")
}
do {
 let owner=ProductWindowController();let f=Form(owner)
 f.api.push(data("offer"));f.api.push(data("connected"));f.connectFastest();spin{f.api.snapshot().count==2 && f.finished && !f.inflight}
 save(f.api.snapshot()[1],"connect-body");check(f.status.stringValue.contains("winner is connected")&&owner.refreshes==1,"explicit final adoption missing")
}
do {
 let owner=ProductWindowController();let f=Form(owner)
 f.api.push(data("offer"));f.api.push(data("foreign"));f.connectFastest();spin{f.api.snapshot().count==2 && !f.inflight}
 check(f.cancelWanted && !f.finished && !f.detail.string.contains("4.50"),"foreign reply adopted a score")
 f.api.push(data("draining"));f.nextPoll = .distantPast;f.tick();spin{f.api.snapshot().count==3 && !f.inflight};save(f.api.snapshot()[2],"cancel-body")
 check(!f.windowShouldClose(f.window!) && !f.finished && f.window!.closes==0,"close escaped before native drain")
 f.api.push(data("cancelled"));f.nextPoll = .distantPast;f.tick();spin{f.finished && !f.inflight}
 check(f.window!.closes==1 && f.status.stringValue.contains("original connection state was restored"),"owned cancellation did not release close")
}
do {
 let owner=ProductWindowController();let f=Form(owner)
 f.api.gate(true);f.api.push(data("offer"));f.send("offer",path:"/api/speed-lab/external-comparison");spin{f.api.snapshot().count==1}
 f.windowWillClose(Notification(name:Notification.Name("fixture close")));f.api.gate(false);spin{f.api.completions()==1};RunLoop.current.run(until:Date().addingTimeInterval(0.05))
 check(f.closed && f.requestID.isEmpty && !f.started && f.api.snapshot().count==1,"late preview response started a closed window")
}
do {
 let owner=ProductWindowController();let f=Form(owner);owner.busy=true
 f.comparePaths();spin{!f.inflight};check(f.api.snapshot().isEmpty && !f.started,"changed main intent sent a batch")
}
print("Actual Swift asynchronous external comparison actions: \(checks) checks PASS; AppKit objects/API delivery are explicit fixture boundaries.")
'''.replace('POLICY', policy).replace('FIELDS', fields).replace('METHODS', methods)
    path = directory/'main.swift'; path.write_text(program)
    subprocess.run(['swiftc','-swift-version','5','-module-cache-path',str(directory/'swift-cache'),str(path),'-o',str(directory/'comparison-swift')],check=True,timeout=120)
    subprocess.run([str(directory/'comparison-swift'),str(directory)],check=True,timeout=60)


def linux_form(directory):
    source = (ROOT/'client/linux/routervpn-telemetry-v9.inc').read_text()
    methods = source[source.index('/* One panel retains one server-issued intent.'):source.index('#include "routervpn-performance-v17.inc"')]
    program = r'''
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <curl/curl.h>
#include <stdatomic.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
typedef struct {GtkWidget*window;} App;
typedef struct {gboolean closed;guint auxiliary_jobs;} LinuxAsyncActionsV16;
static LinuxAsyncActionsV16 async_state;
static gboolean busy;
static guint refreshes,checks,freed;
static GPtrArray*paths,*bodies;
static const char*output;
static LinuxAsyncActionsV16*linux_async_state_v16(App*a){(void)a;return &async_state;}
static gboolean routervpn_require_mutation_idle(App*a,const char*label){(void)a;(void)label;return !busy;}
static void refresh_all(App*a){(void)a;refreshes++;}
static JsonNode*parse_json(const char*raw){if(raw==NULL)return NULL;JsonParser*p=json_parser_new();JsonNode*n=NULL;if(json_parser_load_from_data(p,raw,-1,NULL))n=json_node_copy(json_parser_get_root(p));g_object_unref(p);return n;}
/* Actual GTK callbacks and lifecycle, controlled HTTP worker completion only. */
typedef struct {atomic_int cancelled;gboolean ready;CURLcode result;long status;char*response;} RVHttpJobV16;
static RVHttpJobV16*rv_http_start_method_v17(const char*path,const char*body,long timeout,const char*label,int get){(void)label;(void)get;g_assert(timeout==10000||timeout==3000);RVHttpJobV16*j=g_new0(RVHttpJobV16,1);atomic_init(&j->cancelled,0);g_ptr_array_add(paths,g_strdup(path));g_ptr_array_add(bodies,g_strdup(body));return j;}
static gboolean rv_http_ready_v16(RVHttpJobV16*j){return j!=NULL&&j->ready;}
static void rv_http_cancel_v16(RVHttpJobV16*j){if(j!=NULL){atomic_store(&j->cancelled,1);j->ready=TRUE;j->result=CURLE_ABORTED_BY_CALLBACK;}}
static void rv_http_free_v16(RVHttpJobV16*j){if(j==NULL)return;freed++;g_free(j->response);g_free(j);}
METHODS
static void check(gboolean ok,const char*message){checks++;if(!ok)g_error("external comparison GTK fixture: %s",message);}
static char*fixture(const char*name){char*path=g_strdup_printf("%s/%s.json",output,name),*raw=NULL;g_assert(g_file_get_contents(path,&raw,NULL,NULL));g_free(path);return raw;}
static JsonObject*object(const char*name,JsonNode**root){char*raw=fixture(name);*root=parse_json(raw);g_free(raw);g_assert(*root&&JSON_NODE_HOLDS_OBJECT(*root));return json_node_get_object(*root);}
static void reply(LinuxExternalComparison*s,const char*name){g_assert(s->job);s->job->response=fixture(name);s->job->status=200;s->job->result=CURLE_OK;s->job->ready=TRUE;linux_ec_tick(s);}
static void save_body(guint index,const char*name){char*path=g_strdup_printf("%s/%s.json",output,name);g_assert(g_file_set_contents(path,g_ptr_array_index(bodies,index),-1,NULL));g_free(path);}
static LinuxExternalComparison*open_panel(App*a){linux_external_comparison_open(a);LinuxExternalComparison*s=g_object_get_data(G_OBJECT(a->window),"linux-external-comparison");check(s!=NULL,"actual GTK panel did not open");reply(s,"offer");return s;}
int main(int argc,char**argv){
 output=argv[1];check(gtk_init_check(&argc,&argv),"real GTK display initialized");paths=g_ptr_array_new_with_free_func(g_free);bodies=g_ptr_array_new_with_free_func(g_free);
 App a={.window=gtk_window_new(GTK_WINDOW_TOPLEVEL)};JsonNode*offer_root,*complete_root,*bad_root,*foreign_root;JsonObject*offer=object("offer",&offer_root),*complete=object("compared",&complete_root),*bad=object("incomplete",&bad_root),*foreign=object("foreign",&foreign_root);
 const char*request=linux_ec_string(offer,"request_id"),*cohort=linux_ec_string(offer,"cohort_id");
 check(linux_ec_matches(complete,request,cohort),"matching receipt rejected");check(!linux_ec_matches(foreign,request,cohort),"foreign receipt accepted");
 check(linux_ec_score(json_array_get_object_element(linux_ec_array(complete,"rows"),0))==4.5,"actual common50 score missing");check(isnan(linux_ec_score(json_array_get_object_element(linux_ec_array(bad,"rows"),0))),"49 samples became a score");
 GString*text=g_string_new("");linux_ec_append_rows(text,linux_ec_array(complete,"rows"),TRUE);check(strstr(text->str,"not a current winner")!=NULL,"history shown as current winner");g_string_free(text,TRUE);
 LinuxExternalComparison*s=open_panel(&a);guint first=paths->len;g_signal_emit_by_name(s->compare,"clicked");check(paths->len==first+1&&s->phase==1,"actual Compare did not capture fresh offer");reply(s,"offer");save_body(paths->len-1,"compare-body");check(s->started&&!s->finished&&async_state.auxiliary_jobs==1,"batch lease was not held");reply(s,"active");s->next_poll=0;linux_ec_tick(s);char*poll=g_strdup_printf("/api/speed-lab/external-comparison?request_id=%s",request);check(strcmp(g_ptr_array_index(paths,paths->len-1),poll)==0,"poll lost captured request");g_free(poll);reply(s,"compared");check(s->finished&&async_state.auxiliary_jobs==0&&strstr(gtk_label_get_text(GTK_LABEL(s->status)),"original connection state was restored")!=NULL,"Compare-only lost original restoration");gtk_widget_destroy(s->dialog);
 s=open_panel(&a);g_signal_emit_by_name(s->fastest,"clicked");reply(s,"offer");save_body(paths->len-1,"connect-body");reply(s,"connected");check(s->finished&&strstr(gtk_label_get_text(GTK_LABEL(s->status)),"winner is connected")!=NULL&&refreshes==2,"explicit fastest adoption missing");gtk_widget_destroy(s->dialog);
 s=open_panel(&a);g_signal_emit_by_name(s->fastest,"clicked");reply(s,"offer");reply(s,"connected-warning");check(strstr(gtk_label_get_text(GTK_LABEL(s->status)),"winner selection was saved")!=NULL&&strstr(gtk_label_get_text(GTK_LABEL(s->status)),"winner is connected")==NULL&&!s->finished,"committed warning claimed current connection or drained owner");s->next_poll=0;linux_ec_tick(s);reply(s,"cancelled");gtk_widget_destroy(s->dialog);
 s=open_panel(&a);g_signal_emit_by_name(s->fastest,"clicked");reply(s,"offer");reply(s,"foreign");check(s->cancel_wanted&&!s->finished,"foreign result acquired winner");s->next_poll=0;linux_ec_tick(s);save_body(paths->len-1,"cancel-body");check(strcmp(g_ptr_array_index(paths,paths->len-1),"/api/speed-lab/external-comparison/cancel")==0,"did not cancel captured request");check(linux_ec_delete(s->dialog,NULL,s),"close escaped before cancellation drain");reply(s,"draining");check(!s->finished&&!s->closed&&async_state.auxiliary_jobs==1,"undrained cleanup released panel");s->next_poll=0;linux_ec_tick(s);reply(s,"cancelled");check(g_object_get_data(G_OBJECT(a.window),"linux-external-comparison")==NULL&&async_state.auxiliary_jobs==0,"owned completed drain did not close panel");
 s=open_panel(&a);busy=TRUE;first=paths->len;g_signal_emit_by_name(s->fastest,"clicked");check(paths->len==first&&!s->started,"busy main state sent batch");busy=FALSE;gtk_widget_destroy(s->dialog);
 linux_external_comparison_open(&a);s=g_object_get_data(G_OBJECT(a.window),"linux-external-comparison");check(linux_ec_delete(s->dialog,NULL,s),"pending preview close was not joined");linux_ec_tick(s);check(g_object_get_data(G_OBJECT(a.window),"linux-external-comparison")==NULL,"late preview kept a panel alive");
 check(freed==paths->len,"HTTP worker ownership leaked");gtk_widget_destroy(a.window);json_node_free(offer_root);json_node_free(complete_root);json_node_free(bad_root);json_node_free(foreign_root);g_ptr_array_free(paths,TRUE);g_ptr_array_free(bodies,TRUE);
 printf("Actual GTK external comparison actions: %u checks PASS; real widgets, controlled HTTP delivery boundary.\n",checks);return 0;
}
'''.replace('METHODS', methods)
    path = directory/'comparison.c'; path.write_text(program)
    flags = subprocess.check_output(['pkg-config','--cflags','--libs','gtk+-3.0','json-glib-1.0','libcurl'],text=True).split()
    binary = directory/'comparison-gtk'
    subprocess.run(['gcc','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function',str(path),'-o',str(binary),*flags,'-lm','-pthread'],check=True,timeout=90)
    command=[str(binary),str(directory)]
    if not os.environ.get('DISPLAY'):command=['xvfb-run','-a',*command]
    subprocess.run(command,check=True,timeout=60)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform',choices=['linux','darwin','windows'],default='windows' if sys.platform=='win32' else sys.platform)
    args=parser.parse_args()
    if args.platform == 'darwin':
        subprocess.run([sys.executable,str(ROOT/'deploy/test_desktop_ordered_candidates.py'),'--platform',args.platform],check=True,timeout=300)
    # The live3 receipt is a distinct ephemeral value; execute its shipping UI
    # ownership checks in every existing native comparison-forms lane.
    subprocess.run([sys.executable,str(ROOT/'deploy/test_desktop_live_response_forms.py'),'--platform',args.platform,'--negative-controls'],check=True,timeout=240)
    shells=[None]
    if args.platform=='windows':
        shells=[name for name in ('pwsh','powershell.exe') if shutil.which(name)]
        if not shells:raise SystemExit('PowerShell is required')
    for shell in shells:
        with tempfile.TemporaryDirectory(prefix='router-vpn-external-comparison-forms-') as temporary:
            directory=Path(temporary)
            env=dict(os.environ,ROUTERVPN_EXTERNAL_COMPARISON_FORM_FIXTURES=str(directory))
            subprocess.run(['go','test','-count=1','./cmd/client','-run','^TestDesktopExternalComparisonFormFixtures$'],cwd=ROOT,env=env,check=True,timeout=180)
            if args.platform=='linux':linux_form(directory)
            elif args.platform=='darwin':swift_form(directory)
            else:subprocess.run([shell,'-NoLogo','-NoProfile','-File',str(ROOT/'client/test-windows-external-comparison.ps1'),'-Root',str(ROOT),'-Output',str(directory)],check=True,timeout=90)
            subprocess.run(['go','test','-count=1','./cmd/client','-run','^TestDesktopExternalComparisonFormPayloads$'],cwd=ROOT,env=env,check=True,timeout=180)
    print('Native '+args.platform+' external comparison forms -> exact public Go request: PASS',flush=True)


if __name__=='__main__':main()
