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
static void reply(LinuxOrderedCandidates*s,JsonNode*n){g_assert(s->job);s->job->response=encode(n);s->job->status=200;s->job->result=CURLE_OK;s->job->ready=TRUE;linux_oc_tick(s);}
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
 JsonNode*lost=json_node_copy(result);JsonObject*lost_object=linux_oc_root(lost);json_object_set_boolean_member(lost_object,"accepted",FALSE);json_object_set_array_member(lost_object,"results",json_array_new());reply(s,lost);check(gtk_tree_model_iter_n_children(GTK_TREE_MODEL(s->store),NULL)==0&&!gtk_widget_get_sensitive(s->save),"stale original proof retained scored rows");json_node_free(lost);
 gtk_button_clicked(GTK_BUTTON(s->refresh));reply(s,catalog);choose(s);gtk_button_clicked(GTK_BUTTON(s->test));json_object_set_string_member(result_object,"request_id",s->request);reply(s,result);choose(s);linux_oc_controls(s);

 gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(s->prefix),"1","Uncaptured prefix");gtk_combo_box_set_active_id(GTK_COMBO_BOX(s->prefix),"1");linux_oc_controls(s);check(!gtk_widget_get_sensitive(s->test)&&!gtk_widget_get_sensitive(s->save),"uncaptured prefix borrowed old receipt");gtk_combo_box_set_active_id(GTK_COMBO_BOX(s->prefix),"0");linux_oc_controls(s);
 gtk_entry_set_text(GTK_ENTRY(s->name),"Named next connection");gtk_button_clicked(GTK_BUTTON(s->save));body=parse_json(g_ptr_array_index(bodies,paths->len-1));bo=linux_oc_root(body);check(strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/prefix-candidates/save-profile")==0&&strcmp(linux_ec_string(bo,"name"),"Named next connection")==0&&json_array_get_length(linux_ec_array(bo,"proposed_path"))==3,"actual Save did not send complete named next-path");json_node_free(body);
 JsonNode*saved=parse_json("{\"ok\":true,\"active_path_changed\":false,\"profile_name\":\"Named next connection\"}");reply(s,saved);check(s->receipt==NULL&&strstr(gtk_label_get_text(GTK_LABEL(s->status)),"active path is unchanged"),"save claimed live path replacement");
 choose(s);gtk_button_clicked(GTK_BUTTON(s->test));check(linux_oc_delete(s->dialog,NULL,s)&&s->pending&&!s->closed,"close escaped original native job");linux_oc_tick(s);s->retry=0;linux_oc_tick(s);check(s->phase==3&&strcmp(g_ptr_array_index(paths,paths->len-1),"/api/multihop/prefix-candidates/cancel")==0,"cancel did not retain original request");
 JsonNode*cancel=json_node_new(JSON_NODE_OBJECT);JsonObject*co=json_object_new();json_node_take_object(cancel,co);json_object_set_string_member(co,"request_id",s->request);json_object_set_boolean_member(co,"drained",FALSE);reply(s,cancel);check(s->pending&&async_state.auxiliary_jobs==1,"unjoined cancellation released hold");s->retry=0;linux_oc_tick(s);json_object_set_boolean_member(co,"drained",TRUE);reply(s,cancel);check(g_object_get_data(G_OBJECT(app.window),"linux-ordered-candidates")==NULL&&async_state.auxiliary_jobs==0,"joined cancellation did not release close");
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
        elif args.platform=='linux':linux_form(Path(d))
        else:subprocess.run([args.shell,'-NoProfile','-File',str(ROOT/'client/test-windows-ordered-candidates.ps1'),'-Root',str(ROOT)],check=True,timeout=90)
if __name__=='__main__':main()
