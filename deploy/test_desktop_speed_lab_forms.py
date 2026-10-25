#!/usr/bin/env python3
"""Execute the native Speed Lab options/defaults/Run callbacks, then Go consumers.

GTK uses real widgets under Xvfb. PowerShell executes the generated WPF callback
with selection-only widget doubles. Swift compiles the shipping callback and
options/default helpers with value-only AppKit doubles; actual AppKit remains
part of the macOS build. No VPN, Internet benchmark or private target is used.
"""
from pathlib import Path
import argparse
import os
import re
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
        raise AssertionError('Unclosed shipping source: ' + marker)
    return source[start:pos]


def linux_form(directory):
    source = (ROOT/'client/linux/routervpn-speed-lab-v12.inc').read_text()
    struct = source[:source.index('} LinuxSpeedLabV12;')+len('} LinuxSpeedLabV12;')]
    methods = '\n'.join(block(source, marker) for marker in (
        'static const char *linux_speed_lab_active_id_v12(',
        'static GtkWidget *linux_speed_lab_combo_v12(',
        'static void linux_speed_lab_append_nodes_v12(',
    ))
    methods += '\n' + (ROOT/'client/linux/routervpn-speed-lab-path-v19.inc').read_text()
    methods += '\n' + '\n'.join(block(source, marker) for marker in (
        'static gboolean linux_speed_lab_apply_options_v12(',
        'static void linux_speed_lab_refresh_controls_v12(',
        'static char *linux_speed_lab_request_body_v12(',
    ))
    callback = block(source, 'static void linux_speed_lab_run_v12(')
    program = r'''
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <stdlib.h>
#include <string.h>
typedef struct { int unused; } App;
typedef struct { char *data; size_t len; } Buffer;
STRUCT
static JsonNode *parse_json(const char *raw){JsonParser*p=json_parser_new();JsonNode*n=NULL;if(json_parser_load_from_data(p,raw,-1,NULL))n=json_node_copy(json_parser_get_root(p));g_object_unref(p);return n;}
static const char *obj_string(JsonObject*o,const char*k){return o&&json_object_has_member(o,k)?json_object_get_string_member(o,k):"";}
METHODS
static char *captured;
static void linux_speed_lab_start_v12(LinuxSpeedLabV12*s,gboolean options){g_assert(!options);g_free(captured);captured=linux_speed_lab_request_body_v12(s);}
CALLBACK
static unsigned checks;
static void check(gboolean value,const char*message){checks++;if(!value){g_printerr("%s\n",message);exit(1);}}
static GtkWidget *combo(const char*const*ids,size_t count){return linux_speed_lab_combo_v12(ids,ids,count);}
static void choose(GtkWidget*w,const char*id){check(gtk_combo_box_set_active_id(GTK_COMBO_BOX(w),id),"Missing fixture choice");}
static void emit(LinuxSpeedLabV12*s,const char*directory,const char*name){g_clear_pointer(&captured,g_free);gtk_button_clicked(GTK_BUTTON(s->run));check(captured!=NULL,gtk_label_get_text(GTK_LABEL(s->status)));char*path=g_strdup_printf("%s/%s.json",directory,name);check(g_file_set_contents(path,captured,-1,NULL),"Cannot write captured Run payload");g_free(path);}
static void reject(LinuxSpeedLabV12*s){g_clear_pointer(&captured,g_free);gtk_button_clicked(GTK_BUTTON(s->run));check(captured==NULL,"Invalid selection reached the controller");}
int main(int argc,char**argv){gtk_init(&argc,&argv);check(argc==2,"Expected fixture directory");LinuxSpeedLabV12 s={0};
 const char*scopes[]={"current","temporary"},*tops[]={"system-direct","router","multihop","external"},*bases[]={"auto","wg","awg"},*exits[]={"shadowsocks","hysteria2"},*times[]={"auto","custom"};
 s.scope=combo(scopes,2);s.topology=combo(tops,4);s.base=combo(bases,3);s.exit_mode=combo(exits,2);s.duration_mode=combo(times,2);
 s.node=gtk_combo_box_text_new();s.entry=gtk_combo_box_text_new();s.exit=gtk_combo_box_text_new();s.mode=gtk_combo_box_text_new();s.entry_mode=gtk_combo_box_text_new();s.execution=gtk_combo_box_text_new();s.layers=gtk_entry_new();
 s.min_time=gtk_scale_new_with_range(GTK_ORIENTATION_HORIZONTAL,1,60,1);s.max_time=gtk_scale_new_with_range(GTK_ORIENTATION_HORIZONTAL,1,60,1);gtk_range_set_value(GTK_RANGE(s.min_time),4);gtk_range_set_value(GTK_RANGE(s.max_time),12);
 s.daita=gtk_check_button_new();s.jumbo=gtk_check_button_new();s.encrypted=gtk_check_button_new();s.obfuscated=gtk_check_button_new();s.status=gtk_label_new("");s.run=gtk_button_new();
 char*input=g_build_filename(argv[1],"speed-lab-options.json",NULL);check(g_file_get_contents(input,&s.response.data,NULL,NULL),"Missing real controller options");g_free(input);
 g_signal_connect(s.node,"changed",G_CALLBACK(linux_speed_lab_path_changed_v19),&s);g_signal_connect(s.entry,"changed",G_CALLBACK(linux_speed_lab_path_changed_v19),&s);g_signal_connect(s.topology,"changed",G_CALLBACK(linux_speed_lab_path_changed_v19),&s);g_signal_connect(s.run,"clicked",G_CALLBACK(linux_speed_lab_run_v12),&s);
 check(linux_speed_lab_apply_options_v12(&s),"Actual options parser failed");s.options_ready=TRUE;
 check(strcmp(linux_speed_lab_active_id_v12(s.node),"exit")==0&&strcmp(linux_speed_lab_active_id_v12(s.entry),"entry")==0&&strcmp(linux_speed_lab_active_id_v12(s.entry_mode),"awg2-strong")==0&&strcmp(linux_speed_lab_active_id_v12(s.execution),"auto")==0,"Saved path defaults changed");
 JsonArray*modes=linux_speed_lab_catalog_v19(&s,"router_vpn_entry_modes");check(json_array_get_length(modes)==19,"Mode catalog reduced");
 emit(&s,argv[1],"speed-lab-current");choose(s.scope,"temporary");
 const char*executions[]={"local","server","auto"};
 for(guint i=0;i<json_array_get_length(modes);i++){const char*mode=obj_string(json_array_get_object_element(modes,i),"id");for(guint j=0;j<3;j++){choose(s.entry_mode,mode);choose(s.execution,executions[j]);char*name=g_strdup_printf("speed-lab-external-%s-%s",mode,executions[j]);emit(&s,argv[1],name);g_free(name);}}
 choose(s.entry,"");check(strcmp(linux_speed_lab_active_id_v12(s.execution),"local")==0,"Direct retained Server");emit(&s,argv[1],"speed-lab-external-direct");choose(s.execution,"server");reject(&s);
 choose(s.entry,"external-entry");emit(&s,argv[1],"speed-lab-external-entry");choose(s.execution,"auto");reject(&s);
 choose(s.entry,"entry");choose(s.execution,"auto");linux_speed_lab_select_v19(s.entry_mode,"missing-mode");reject(&s);choose(s.entry_mode,"wg");
 linux_speed_lab_select_v19(s.entry,"missing-entry");reject(&s);choose(s.entry,"entry");linux_speed_lab_select_v19(s.execution,"invalid");reject(&s);choose(s.execution,"auto");
 JsonObject*node=linux_speed_lab_find_v19(&s,"nodes","exit");json_object_set_boolean_member(node,"has_response_probe",FALSE);reject(&s);json_object_set_boolean_member(node,"has_response_probe",TRUE);
 json_object_set_boolean_member(node,"has_openvpn_pairing",FALSE);reject(&s);json_object_set_boolean_member(node,"has_openvpn_pairing",TRUE);
 JsonArray*nodes=linux_speed_lab_catalog_v19(&s,"nodes");json_array_add_object_element(nodes,json_object_ref(node));reject(&s);json_array_remove_element(nodes,json_array_get_length(nodes)-1);
 json_object_set_string_member(node,"multihop_entry_id","removed-entry");linux_speed_lab_defaults_v19(&s);check(strcmp(linux_speed_lab_active_id_v12(s.entry),"removed-entry")==0,"Unavailable entry became Direct");reject(&s);json_object_set_string_member(node,"multihop_entry_id","entry");linux_speed_lab_defaults_v19(&s);
 choose(s.topology,"multihop");choose(s.entry,"entry");choose(s.exit,"exit-router");for(guint j=0;j<3;j++){choose(s.execution,executions[j]);char*name=g_strdup_printf("speed-lab-multihop-%s",executions[j]);emit(&s,argv[1],name);g_free(name);}
 choose(s.exit,"entry");reject(&s);choose(s.exit,"exit-router");choose(s.topology,"system-direct");emit(&s,argv[1],"speed-lab-system-direct");
 json_node_free(s.options);g_free(s.response.data);g_free(captured);printf("Actual GTK Speed Lab options/defaults/Run callback: %u checks PASS\n",checks);return 0;}
'''.replace('STRUCT', struct).replace('METHODS', methods).replace('\nCALLBACK\n', '\n'+callback+'\n')
    path = directory/'speed-lab.c'; path.write_text(program)
    flags = subprocess.check_output(['pkg-config','--cflags','--libs','gtk+-3.0','json-glib-1.0'], text=True).split()
    subprocess.run(['gcc','-Wall','-Wextra','-Werror',str(path),'-o',str(directory/'speed-lab')]+flags, check=True)
    subprocess.run(['xvfb-run','-a',str(directory/'speed-lab'),str(directory)],check=True,timeout=60)


def swift_form(directory):
    source = (ROOT/'client/macos/RouterVPNMacSpeedLab.swift').read_text()
    policy = block(source, 'private enum RouterVPNMacSpeedLabPathPolicy')
    methods = '\n'.join(block(source, marker) for marker in (
        '    private func selected(', '    private func populate(', '    private func selectPreserving(',
        '    private func applyPathDefaults(', '    private func setEntryModeDefault(',
        '    @objc private func pathChanged(', '    private func loadOptions(',
        '    @objc private func refreshControls(', '    private func requestBody(',
        '    private func hopSummary(', '    @objc private func runSpeedLab(',
    )).replace('@objc ', '').replace('private func ', 'func ')
    program = r'''
import Foundation
import CoreFoundation
POLICY
class NSControl { var isEnabled = true }
final class Item { var title: String; var representedObject: Any?; init(_ title:String){self.title=title} }
final class NSPopUpButton: NSControl {
 var items:[Item]=[];var index = -1
 var numberOfItems:Int{items.count};var selectedItem:Item?{index>=0&&index<items.count ? items[index]:nil};var lastItem:Item?{items.last}
 func item(at:Int)->Item?{at>=0&&at<items.count ? items[at]:nil};func selectItem(at:Int){index=at}
 func addItem(withTitle:String){items.append(Item(withTitle))};func insertItem(withTitle:String,at:Int){items.insert(Item(withTitle),at:at)};func removeAllItems(){items=[];index = -1}
}
final class Field: NSControl { var stringValue="";var doubleValue:Double=4 }
final class TextArea {var string=""}
final class Button: NSControl { enum State {case on,off};var state=State.off;var title="" }
final class Request {func cancel(){}}
final class Form {
 let scope=NSPopUpButton(),topology=NSPopUpButton(),node=NSPopUpButton(),entry=NSPopUpButton(),exit=NSPopUpButton(),mode=NSPopUpButton(),base=NSPopUpButton(),exitMode=NSPopUpButton(),entryMode=NSPopUpButton(),execution=NSPopUpButton(),durationMode=NSPopUpButton()
 let minTime=Field(),maxTime=Field(),layers=Field(),idle=Field(),download=Field(),upload=Field(),idleDetail=Field(),downloadDetail=Field(),uploadDetail=Field(),status=Field()
 let daita=Button(),jumbo=Button(),encrypted=Button(),obfuscated=Button(),runButton=Button();let detail=TextArea()
 var nodes:[[String:Any]]=[],entryModes:[[String:Any]]=[],executions:[[String:Any]]=[]
 var updatingChoices=false,closed=false,optionsReady=false,cancelled=false,loadingOptions=false
 var request:Request?;var captured:[String:Any]?;var options=Data()
 func performLocalRequest(_ path:String,body:[String:Any]?,timeout:TimeInterval,completion:@escaping(Result<Data,Error>)->Void)throws{
  if path=="/api/speed-lab/options"{loadingOptions=false;completion(.success(options))}
  else {precondition(path=="/api/speed-lab/run"&&body != nil);captured=body}
 }
 METHODS
}
var checks=0
func check(_ result:Bool,_ message:String){checks+=1;precondition(result,message)}
func fill(_ popup:NSPopUpButton,_ values:[String]){for v in values{popup.addItem(withTitle:v);popup.lastItem?.representedObject=v};popup.selectItem(at:0)}
func choose(_ popup:NSPopUpButton,_ value:String){guard let index=popup.items.firstIndex(where:{$0.representedObject as? String==value})else{fatalError("Missing choice "+value)};popup.selectItem(at:index)}
let output=URL(fileURLWithPath:CommandLine.arguments[1],isDirectory:true),f=Form()
fill(f.scope,["current","temporary"]);fill(f.topology,["system-direct","router","multihop","external"]);fill(f.base,["auto","wg","awg"]);fill(f.exitMode,["shadowsocks","hysteria2"]);fill(f.durationMode,["auto","custom"]);f.maxTime.doubleValue=12
f.options=try Data(contentsOf:output.appendingPathComponent("speed-lab-options.json"));f.loadOptions()
check(f.selected(f.node)=="exit"&&f.selected(f.entry)=="entry"&&f.selected(f.entryMode)=="awg2-strong"&&f.selected(f.execution)=="auto","Saved path defaults changed")
check(f.entryModes.count==19,"Reduced raw entry catalog")
func emit(_ name:String)throws{f.captured=nil;f.runSpeedLab();check(f.captured != nil,f.detail.string);try JSONSerialization.data(withJSONObject:f.captured!,options:[.sortedKeys]).write(to:output.appendingPathComponent(name+".json"))}
func reject(){f.captured=nil;f.runSpeedLab();check(f.captured==nil,"Invalid selection reached controller")}
try emit("speed-lab-current");choose(f.scope,"temporary")
for m in f.entryModes{let id=m["id"] as! String;for execution in ["local","server","auto"]{choose(f.entryMode,id);choose(f.execution,execution);try emit("speed-lab-external-"+id+"-"+execution)}}
choose(f.entry,"");f.pathChanged(f.entry);check(f.selected(f.execution)=="local","Direct retained Server");try emit("speed-lab-external-direct");choose(f.execution,"server");reject()
choose(f.entry,"external-entry");f.pathChanged(f.entry);try emit("speed-lab-external-entry");choose(f.execution,"auto");reject()
choose(f.entry,"entry");f.pathChanged(f.entry);choose(f.execution,"auto");f.selectPreserving(f.entryMode,"missing-mode");reject();choose(f.entryMode,"wg")
f.selectPreserving(f.entry,"missing-entry");reject();choose(f.entry,"entry");f.selectPreserving(f.execution,"invalid");reject();choose(f.execution,"auto")
let exitIndex=f.nodes.firstIndex(where:{$0["id"] as? String=="exit"})!
f.nodes[exitIndex]["has_response_probe"]=false;reject();f.nodes[exitIndex]["has_response_probe"]=true
f.nodes[exitIndex]["has_openvpn_pairing"]=false;reject();f.nodes[exitIndex]["has_openvpn_pairing"]=true
f.nodes.append(f.nodes[exitIndex]);reject();f.nodes.removeLast()
f.nodes[exitIndex]["multihop_entry_id"]="removed-entry";f.applyPathDefaults();check(f.selected(f.entry)=="removed-entry","Unavailable saved entry became Direct");reject();f.nodes[exitIndex]["multihop_entry_id"]="entry";f.applyPathDefaults()
choose(f.topology,"multihop");f.pathChanged(f.topology);choose(f.entry,"entry");choose(f.exit,"exit-router")
for execution in ["local","server","auto"]{choose(f.execution,execution);try emit("speed-lab-multihop-"+execution)}
choose(f.exit,"entry");reject();choose(f.exit,"exit-router");choose(f.topology,"system-direct");try emit("speed-lab-system-direct")
print("Actual Swift Speed Lab options/defaults/Run callback: \(checks) checks PASS")
'''.replace('POLICY', policy).replace('METHODS', methods)
    path = directory/'main.swift'; path.write_text(program)
    subprocess.run(['swiftc','-swift-version','5','-module-cache-path',str(directory/'module-cache'),str(path),'-o',str(directory/'speed-lab-swift')],check=True,timeout=120)
    subprocess.run([str(directory/'speed-lab-swift'),str(directory)],check=True,timeout=60)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform',choices=['linux','darwin','windows'],default='windows' if sys.platform=='win32' else sys.platform)
    args=parser.parse_args()
    shells=[None]
    if args.platform=='windows':
        shells=[value for value in ('pwsh','powershell.exe') if shutil.which(value)]
        if not shells: raise SystemExit('PowerShell is required')
    for shell in shells:
        with tempfile.TemporaryDirectory(prefix='router-vpn-speed-lab-forms-') as temporary:
            directory=Path(temporary);env=dict(os.environ,ROUTERVPN_EXTERNAL_FORM_PAYLOADS=str(directory))
            subprocess.run(['go','test','-count=1','./cmd/client','-run','^TestDesktopSpeedLabPathFormCatalog$'],cwd=ROOT,env=env,check=True,timeout=180)
            if args.platform=='linux': linux_form(directory)
            elif args.platform=='darwin': swift_form(directory)
            else: subprocess.run([shell,'-NoLogo','-NoProfile','-File',str(ROOT/'client/test-windows-speed-lab-paths.ps1'),'-Root',str(ROOT),'-Output',str(directory)],check=True,timeout=120)
            subprocess.run(['go','test','-race','-count=1','./cmd/client','-run','^TestDesktopSpeedLabPathFormPayload$'],cwd=ROOT,env=env,check=True,timeout=180)
    print('Native '+args.platform+' Speed Lab forms -> exact captured Go paths: PASS',flush=True)


if __name__=='__main__': main()
