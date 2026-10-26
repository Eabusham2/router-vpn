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
    choices = (ROOT/'client/linux/routervpn-multihop-choices-v22.inc').read_text()
    methods = choices[:choices.index('static gboolean linux_multihop_exit_supported_v22(')]
    methods += '\n'.join(block(choices, marker) for marker in (
        'static gboolean linux_multihop_exit_supported_v22(',
        'static gboolean linux_multihop_exit_advertised_v22(',
        'static void linux_multihop_select_preserving_v22(',
        'static void linux_multihop_exit_choices_v22(',
    ))
    methods += '\n' + '\n'.join(block(source, marker) for marker in (
        'static const char *linux_speed_lab_active_id_v12(',
        'static GtkWidget *linux_speed_lab_combo_v12(',
        'static void linux_speed_lab_append_nodes_v12(',
    ))
    methods += '\n' + block((ROOT/'client/linux/routervpn-gtk-product-v3.c').read_text(), 'static const char *active_router_id(')
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
typedef struct { GtkWidget *router_combo; GPtrArray *router_ids; } App;
typedef struct { char *data; size_t len; } Buffer;
STRUCT
static JsonNode *parse_json(const char *raw){JsonParser*p=json_parser_new();JsonNode*n=NULL;if(json_parser_load_from_data(p,raw,-1,NULL))n=json_node_copy(json_parser_get_root(p));g_object_unref(p);return n;}
static const char *obj_string(JsonObject*o,const char*k){return o&&json_object_has_member(o,k)?json_object_get_string_member(o,k):"";}
/* Public preference reads are controlled at this boundary. The actual dialog
 * capture, main-node reader, options parser, validation and Run callback run. */
static gboolean staged_enabled;
static const char *staged_entry="", *staged_exit="", *staged_mode="shadowsocks", *staged_execution="local";
static gboolean linux_profile_selection_v11(gboolean*enabled,char**entry,char**exit,char**mode){*enabled=staged_enabled;*entry=g_strdup(staged_entry);*exit=g_strdup(staged_exit);*mode=g_strdup(staged_mode);return staged_enabled;}
static char *linux_multihop_execution_choice_v1(void){return g_strdup(staged_execution);}
METHODS
static char *captured;
static void linux_speed_lab_start_v12(LinuxSpeedLabV12*s,gboolean options){g_assert(!options);g_free(captured);captured=linux_speed_lab_request_body_v12(s);}
CALLBACK
static unsigned checks;
static void check(gboolean value,const char*message){checks++;if(!value){g_printerr("%s\n",message);exit(1);}}
static GtkWidget *combo(const char*const*ids,size_t count){return linux_speed_lab_combo_v12(ids,ids,count);}
static void choose(GtkWidget*w,const char*id){check(gtk_combo_box_set_active_id(GTK_COMBO_BOX(w),id),"Missing fixture choice");}
static void emit(LinuxSpeedLabV12*s,const char*directory,const char*name){linux_speed_lab_refresh_controls_v12(NULL,s);check(gtk_widget_get_sensitive(s->run),gtk_label_get_text(GTK_LABEL(s->status)));g_clear_pointer(&captured,g_free);gtk_button_clicked(GTK_BUTTON(s->run));check(captured!=NULL,gtk_label_get_text(GTK_LABEL(s->status)));char*path=g_strdup_printf("%s/%s.json",directory,name);check(g_file_set_contents(path,captured,-1,NULL),"Cannot write captured Run payload");g_free(path);}
static void reject(LinuxSpeedLabV12*s){linux_speed_lab_refresh_controls_v12(NULL,s);check(!gtk_widget_get_sensitive(s->run),"Invalid path left Run enabled");g_clear_pointer(&captured,g_free);gtk_button_clicked(GTK_BUTTON(s->run));check(captured==NULL,"Invalid selection reached the controller");}
int main(int argc,char**argv){gtk_init(&argc,&argv);check(argc==2,"Expected fixture directory");LinuxSpeedLabV12 s={0};App app={0};s.app=&app;
 app.router_combo=gtk_combo_box_text_new();app.router_ids=g_ptr_array_new_with_free_func(g_free);const char*main_ids[]={"exit","entry","external-entry","exit-router"};for(guint i=0;i<G_N_ELEMENTS(main_ids);i++){gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app.router_combo),main_ids[i],main_ids[i]);g_ptr_array_add(app.router_ids,g_strdup(main_ids[i]));}choose(app.router_combo,"exit");linux_speed_lab_capture_selection_v19(&s);
 const char*scopes[]={"current","temporary"},*tops[]={"system-direct","router","multihop","external"},*bases[]={"auto","wg","awg"},*times[]={"auto","custom"};
 s.scope=combo(scopes,2);s.topology=combo(tops,4);s.base=combo(bases,3);s.exit_mode=gtk_combo_box_text_new();linux_multihop_exit_choices_v22(s.exit_mode,"shadowsocks");s.duration_mode=combo(times,2);
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
 char*original_token=g_strdup(obj_string(node,"profile_token"));json_object_set_string_member(node,"profile_token","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");reject(&s);check(g_strcmp0(obj_string(s.captured_profile_tokens,"exit"),original_token)==0,"Relink replaced the detached capture");json_object_set_string_member(node,"profile_token",original_token);g_free(original_token);
 JsonObject*entry_node=linux_speed_lab_find_v19(&s,"nodes","entry");char*entry_token=g_strdup(obj_string(entry_node,"profile_token"));json_object_remove_member(entry_node,"profile_token");reject(&s);json_object_set_string_member(entry_node,"profile_token",entry_token);g_free(entry_token);
 choose(app.router_combo,"entry");reject(&s);choose(app.router_combo,"exit");staged_enabled=TRUE;reject(&s);staged_enabled=FALSE;
 json_object_set_boolean_member(node,"has_openvpn_pairing",FALSE);reject(&s);json_object_set_boolean_member(node,"has_openvpn_pairing",TRUE);
 JsonArray*nodes=linux_speed_lab_catalog_v19(&s,"nodes");json_array_add_object_element(nodes,json_object_ref(node));reject(&s);json_array_remove_element(nodes,json_array_get_length(nodes)-1);
 json_object_set_string_member(node,"multihop_entry_id","removed-entry");linux_speed_lab_defaults_v19(&s);check(strcmp(linux_speed_lab_active_id_v12(s.entry),"removed-entry")==0,"Unavailable entry became Direct");reject(&s);json_object_set_string_member(node,"multihop_entry_id","entry");linux_speed_lab_defaults_v19(&s);
 choose(s.topology,"multihop");choose(s.entry,"entry");choose(s.exit,"exit-router");for(guint j=0;j<3;j++){choose(s.execution,executions[j]);char*name=g_strdup_printf("speed-lab-multihop-%s",executions[j]);emit(&s,argv[1],name);g_free(name);}
 JsonArray*exit_modes=linux_speed_lab_catalog_v19(&s,"supported_exit_modes");check(exit_modes!=NULL&&json_array_get_length(exit_modes)==7,"Reduced Router exit catalog");
 for(guint i=0;i<json_array_get_length(exit_modes);i++){const char*mode=json_array_get_string_element(exit_modes,i);choose(s.exit_mode,mode);for(guint j=0;j<3;j++){choose(s.execution,executions[j]);char*name=g_strdup_printf("speed-lab-multihop-%s-%s",mode,executions[j]);emit(&s,argv[1],name);g_free(name);}}
 linux_speed_lab_select_v19(s.exit_mode,"unknown-exit");reject(&s);choose(s.exit_mode,"naive-h3");
 json_array_add_string_element(exit_modes,"naive-h3");reject(&s);json_array_remove_element(exit_modes,json_array_get_length(exit_modes)-1);
 JsonObject*current=json_object_get_object_member(json_node_get_object(s.options),"current");json_object_set_boolean_member(current,"connected",TRUE);json_object_set_string_member(current,"mode","multihop");json_object_set_string_member(current,"entry_id","different-entry");json_object_set_string_member(current,"exit_id","exit-router");json_object_set_string_member(current,"exit_mode","reality-xhttp");linux_speed_lab_defaults_v19(&s);check(strcmp(linux_speed_lab_active_id_v12(s.exit_mode),"naive-h3")==0,"Another live graph changed the selected exit transport");
 json_object_set_string_member(current,"entry_id","entry");linux_speed_lab_defaults_v19(&s);check(strcmp(linux_speed_lab_active_id_v12(s.exit_mode),"reality-xhttp")==0,"Exact live graph exit transport was not preserved");
 json_object_set_string_member(current,"router_id","exit-router");choose(s.scope,"current");char*current_body=linux_speed_lab_request_body_v12(&s);check(current_body!=NULL,"Current hopped owner could not bind revisions");JsonNode*current_request=parse_json(current_body);JsonObject*current_tokens=json_object_get_object_member(json_node_get_object(current_request),"expected_profile_tokens");check(json_object_get_size(current_tokens)==3&&json_object_has_member(current_tokens,"exit")&&json_object_has_member(current_tokens,"entry")&&json_object_has_member(current_tokens,"exit-router"),"Current path omitted its active hop or selected node");json_node_free(current_request);g_free(current_body);json_object_set_string_member(current,"entry_id","removed-entry");reject(&s);json_object_set_string_member(current,"entry_id","entry");json_object_set_string_member(current,"router_id","");reject(&s);json_object_set_string_member(current,"router_id","exit-router");choose(s.scope,"temporary");
 choose(s.exit,"entry");reject(&s);choose(s.exit,"exit-router");choose(s.topology,"system-direct");emit(&s,argv[1],"speed-lab-system-direct");
 JsonNode*reload=parse_json(s.response.data);JsonArray*reload_nodes=json_object_get_array_member(json_node_get_object(reload),"nodes");for(guint i=0;i<json_array_get_length(reload_nodes);i++){JsonObject*n=json_array_get_object_element(reload_nodes,i);json_object_set_boolean_member(n,"selected",strcmp(obj_string(n,"id"),"entry")==0);}JsonGenerator*generator=json_generator_new();json_generator_set_root(generator,reload);g_free(s.response.data);s.response.data=json_generator_to_data(generator,NULL);g_object_unref(generator);json_node_free(reload);
 staged_enabled=TRUE;staged_entry="entry";staged_exit="exit-router";staged_mode="reality-pq-vision";staged_execution="auto";choose(app.router_combo,"entry");check(!linux_speed_lab_apply_options_v12(&s),"A delayed catalog replaced the original main selection");linux_speed_lab_capture_selection_v19(&s);check(linux_speed_lab_apply_options_v12(&s),"Reloaded options failed");check(strcmp(linux_speed_lab_active_id_v12(s.topology),"multihop")==0&&strcmp(linux_speed_lab_active_id_v12(s.entry),"entry")==0&&strcmp(linux_speed_lab_active_id_v12(s.exit),"exit-router")==0&&strcmp(linux_speed_lab_active_id_v12(s.exit_mode),"reality-pq-vision")==0&&strcmp(linux_speed_lab_active_id_v12(s.execution),"auto")==0,"Loaded whole-connection profile choices changed");
 exit_modes=linux_speed_lab_catalog_v19(&s,"supported_exit_modes");for(guint i=0;i<json_array_get_length(exit_modes);i++){const char*mode=json_array_get_string_element(exit_modes,i);choose(s.exit_mode,mode);for(guint j=0;j<3;j++){choose(s.execution,executions[j]);char*name=g_strdup_printf("speed-lab-multihop-%s-%s",mode,executions[j]);emit(&s,argv[1],name);g_free(name);}}
 staged_mode="naive-h2";reject(&s);staged_mode="reality-pq-vision";staged_execution="server";reject(&s);staged_execution="auto";staged_entry="exit-router";reject(&s);staged_entry="entry";
 staged_mode="missing-saved-exit";linux_speed_lab_capture_selection_v19(&s);check(linux_speed_lab_apply_options_v12(&s),"Unknown saved mode options failed");check(strcmp(linux_speed_lab_active_id_v12(s.exit_mode),"missing-saved-exit")==0,"Unknown saved exit was replaced");reject(&s);
 staged_enabled=FALSE;gtk_combo_box_set_active(GTK_COMBO_BOX(app.router_combo),-1);linux_speed_lab_capture_selection_v19(&s);g_free(s.response.data);s.response.data=g_strdup("{\"nodes\":[],\"logical_modes\":[{\"id\":\"smart-auto\"}]}");check(linux_speed_lab_apply_options_v12(&s),"First-use empty node options failed");choose(s.scope,"temporary");choose(s.topology,"system-direct");char*empty_body=linux_speed_lab_request_body_v12(&s);check(empty_body!=NULL,"First-use System direct was blocked");JsonNode*empty_request=parse_json(empty_body);JsonObject*empty_object=json_node_get_object(empty_request);check(!obj_string(empty_object,"expected_selected_node_id")[0]&&json_object_get_size(json_object_get_object_member(empty_object,"expected_profile_tokens"))==0,"First-use System direct invented a node identity");json_node_free(empty_request);g_free(empty_body);s.closed=TRUE;g_clear_pointer(&captured,g_free);gtk_button_clicked(GTK_BUTTON(s.run));check(captured==NULL,"Closed Speed Lab issued a request");
 json_node_free(s.options);json_object_unref(s.captured_profile_tokens);g_free(s.staged_selected);g_free(s.staged_entry);g_free(s.staged_exit);g_free(s.staged_exit_mode);g_free(s.staged_execution);g_free(s.response.data);g_free(captured);g_ptr_array_unref(app.router_ids);printf("Actual GTK Speed Lab options/defaults/Run callback: %u checks PASS\n",checks);return 0;}
'''.replace('STRUCT', struct).replace('METHODS', methods).replace('\nCALLBACK\n', '\n'+callback+'\n')
    path = directory/'speed-lab.c'; path.write_text(program)
    flags = subprocess.check_output(['pkg-config','--cflags','--libs','gtk+-3.0','json-glib-1.0'], text=True).split()
    subprocess.run(['gcc','-Wall','-Wextra','-Werror',str(path),'-o',str(directory/'speed-lab')]+flags, check=True)
    subprocess.run(['xvfb-run','-a',str(directory/'speed-lab'),str(directory)],check=True,timeout=60)
    subprocess.run([sys.executable,str(ROOT/'client/linux/test-multihop-profiles-v22.py')],check=True,timeout=90)


def swift_form(directory):
    source = (ROOT/'client/macos/RouterVPNMacSpeedLab.swift').read_text()
    policy = block(source, 'private enum RouterVPNMacSpeedLabPathPolicy')
    exit_modes = block((ROOT/'client/macos/RouterVPNMacProduct.swift').read_text(), 'enum RouterVPNNodeExitModes')
    exit_initializer = block(source, 'for choice in RouterVPNNodeExitModes.choices')
    profile_source = (ROOT/'client/macos/RouterVPNConnectionProfiles.swift').read_text()
    profile_selection = block(profile_source, 'struct RouterVPNConnectionProfileSelection:')
    profile_capture = block(profile_source, '    func captureConnectionProfileSelection(')
    methods = '\n'.join(block(source, marker) for marker in (
        '    private func selected(', '    private func populate(', '    private func selectPreserving(',
        '    private func validateCapturedSelection(', '    private func applyCapturedSelection(',
        '    private func applyPathDefaults(', '    private func setEntryModeDefault(',
        '    @objc private func pathChanged(', '    private func loadOptions(',
        '    @objc private func refreshControls(', '    private func bindCapturedProfiles(', '    private func requestBody(',
        '    private func hopSummary(', '    @objc private func runSpeedLab(',
    )).replace('@objc ', '').replace('private func ', 'func ')
    program = r'''
import Foundation
import CoreFoundation
EXIT_MODES
PROFILE_SELECTION
POLICY
class NSControl { var isEnabled = true }
final class Item { var title: String; var representedObject: Any?; init(_ title:String){self.title=title} }
final class NSPopUpButton: NSControl {
 var items:[Item]=[];var index = -1
 var numberOfItems:Int{items.count};var indexOfSelectedItem:Int{index};var selectedItem:Item?{index>=0&&index<items.count ? items[index]:nil};var lastItem:Item?{items.last}
 func item(at:Int)->Item?{at>=0&&at<items.count ? items[at]:nil};func selectItem(at:Int){index=at}
 func addItem(withTitle:String){items.append(Item(withTitle))};func insertItem(withTitle:String,at:Int){items.insert(Item(withTitle),at:at)};func removeAllItems(){items=[];index = -1}
}
final class Field: NSControl { var stringValue="";var doubleValue:Double=4 }
final class TextArea {var string=""}
final class Button: NSControl { enum State {case on,off};var state=State.off;var title="" }
final class Request {func cancel(){}}
private let macConnectionMultihopEnabledKey="routervpn.unified.multihop-enabled.v1"
final class ProductWindowController {
 let routerPopup=NSPopUpButton(),multihopEntryPopup=NSPopUpButton(),multihopExitPopup=NSPopUpButton(),multihopExitModePopup=NSPopUpButton(),multihopExecutionPopup=NSPopUpButton()
 var connectionProfileSelection:RouterVPNConnectionProfileSelection?
 var connectionProfileSelectionGeneration=UUID()
 var routerIDs:[String]=[],multihopNodeIDs:[String]=[],profiles:[[String:Any]]=[],multihopNodeTokens:[String:String]=[:]
 PROFILE_CAPTURE
}
final class Form {
 weak var product:ProductWindowController?
 let capturedSelection:RouterVPNConnectionProfileSelection
 let selectionGeneration:UUID
 let scope=NSPopUpButton(),topology=NSPopUpButton(),node=NSPopUpButton(),entry=NSPopUpButton(),exit=NSPopUpButton(),mode=NSPopUpButton(),base=NSPopUpButton(),exitMode=NSPopUpButton(),entryMode=NSPopUpButton(),execution=NSPopUpButton(),durationMode=NSPopUpButton()
 let minTime=Field(),maxTime=Field(),layers=Field(),idle=Field(),download=Field(),upload=Field(),idleDetail=Field(),downloadDetail=Field(),uploadDetail=Field(),status=Field()
 let daita=Button(),jumbo=Button(),encrypted=Button(),obfuscated=Button(),runButton=Button();let detail=TextArea()
 var nodes:[[String:Any]]=[],entryModes:[[String:Any]]=[],executions:[[String:Any]]=[]
 var exitModes:[String]=[],currentPath:[String:Any]=[:]
 var updatingChoices=false,closed=false,optionsReady=false,cancelled=false,loadingOptions=false
 var request:Request?;var captured:[String:Any]?;var options=Data();var deferOptions=false;var pendingOptions:((Result<Data,Error>)->Void)?
 init(_ product:ProductWindowController){self.product=product;self.capturedSelection=RouterVPNMacSpeedLabPathPolicy.activeSelection(product.captureConnectionProfileSelection());self.selectionGeneration=product.connectionProfileSelectionGeneration}
 func performLocalRequest(_ path:String,body:[String:Any]?,timeout:TimeInterval,completion:@escaping(Result<Data,Error>)->Void)throws{
  if path=="/api/speed-lab/options"{if deferOptions{pendingOptions=completion}else{loadingOptions=false;completion(.success(options))}}
  else {precondition(path=="/api/speed-lab/run"&&body != nil);captured=body}
 }
 func initializeExitModes(){EXIT_INITIALIZER}
 func finishOptions(){let completion=pendingOptions;pendingOptions=nil;loadingOptions=false;completion?(.success(options))}
 METHODS
}
var checks=0
func check(_ result:Bool,_ message:String){checks+=1;precondition(result,message)}
func fill(_ popup:NSPopUpButton,_ values:[String]){for v in values{popup.addItem(withTitle:v);popup.lastItem?.representedObject=v};popup.selectItem(at:0)}
func choose(_ popup:NSPopUpButton,_ value:String){guard let index=popup.items.firstIndex(where:{$0.representedObject as? String==value})else{fatalError("Missing choice "+value)};popup.selectItem(at:index)}
let output=URL(fileURLWithPath:CommandLine.arguments[1],isDirectory:true)
let originalOptions=try Data(contentsOf:output.appendingPathComponent("speed-lab-options.json"))
let originalRoot=try JSONSerialization.jsonObject(with:originalOptions) as! [String:Any]
func product(_ id:String,_ mode:String="shadowsocks",_ execution:String="local")->ProductWindowController{
 let p=ProductWindowController();p.profiles=originalRoot["nodes"] as! [[String:Any]];p.routerIDs=p.profiles.map{$0["id"] as! String};p.multihopNodeIDs=p.profiles.filter{RouterVPNMacSpeedLabPathPolicy.kind($0)=="router-vpn"}.map{$0["id"] as! String}
 for node in p.profiles{if let id=node["id"] as? String,let token=node["profile_token"] as? String{p.multihopNodeTokens[id]=token}}
 fill(p.routerPopup,p.routerIDs);choose(p.routerPopup,id);fill(p.multihopEntryPopup,p.multihopNodeIDs);choose(p.multihopEntryPopup,"entry");fill(p.multihopExitPopup,p.multihopNodeIDs);choose(p.multihopExitPopup,"exit-router");fill(p.multihopExitModePopup,RouterVPNNodeExitModes.choices.map{$0.id});choose(p.multihopExitModePopup,mode);fill(p.multihopExecutionPopup,["local","server","auto"]);choose(p.multihopExecutionPopup,execution);return p
}
func configure(_ f:Form,_ options:Data){fill(f.scope,["current","temporary"]);fill(f.topology,["system-direct","router","multihop","external"]);fill(f.base,["auto","wg","awg"]);f.initializeExitModes();f.exitMode.selectItem(at:0);fill(f.durationMode,["auto","custom"]);f.maxTime.doubleValue=12;f.options=options}
UserDefaults.standard.setVolatileDomain([macConnectionMultihopEnabledKey:true],forName:UserDefaults.argumentDomain)
let mainProduct=product("exit"),f=Form(mainProduct);configure(f,originalOptions);f.loadOptions()
check(f.selected(f.node)=="exit"&&f.selected(f.entry)=="entry"&&f.selected(f.entryMode)=="awg2-strong"&&f.selected(f.execution)=="auto","Saved path defaults changed")
check(f.entryModes.count==19,"Reduced raw entry catalog")
check(f.exitModes==RouterVPNNodeExitModes.choices.map{$0.id},"UI and native exit catalogs differ")
func emit(_ name:String)throws{f.captured=nil;f.runSpeedLab();check(f.captured != nil,f.detail.string);check(f.captured!["expected_selected_node_id"] as? String==f.capturedSelection.selectedNodeID,"Run lost its captured main selection");let tokens=f.captured!["expected_profile_tokens"] as? [String:String] ?? [:];for id in [f.capturedSelection.selectedNodeID]+["node_id","entry_id","exit_id"].compactMap({f.captured![$0] as? String}) where !id.isEmpty{check(tokens[id]?.count==64,"Run omitted exact identity for "+id)};try JSONSerialization.data(withJSONObject:f.captured!,options:[.sortedKeys]).write(to:output.appendingPathComponent(name+".json"))}
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
for exitMode in f.exitModes{choose(f.exitMode,exitMode);for execution in ["local","server","auto"]{choose(f.execution,execution);try emit("speed-lab-multihop-"+exitMode+"-"+execution)}}
f.selectPreserving(f.exitMode,"removed-exit-mode");reject();choose(f.exitMode,"naive-h3")
let supportedExitModes=f.exitModes;f.exitModes.removeAll{$0=="naive-h3"};reject();f.exitModes=supportedExitModes
f.currentPath=["entry_id":"entry","exit_id":"exit-router","exit_mode":"reality-pq-vision"];f.applyPathDefaults();check(f.selected(f.exitMode)=="reality-pq-vision","Matching current graph lost its exact exit mode")
f.currentPath["entry_id"]="different-entry";choose(f.exitMode,"naive-h2");f.applyPathDefaults();check(f.selected(f.exitMode)=="naive-h2","Unrelated graph replaced the selected exit mode")
choose(f.exit,"entry");reject();choose(f.exit,"exit-router");choose(f.topology,"system-direct");try emit("speed-lab-system-direct")
var routerRoot=originalRoot;var routerNodes=originalRoot["nodes"] as! [[String:Any]]
for i in routerNodes.indices{routerNodes[i]["selected"]=routerNodes[i]["id"] as? String=="entry"};routerRoot["nodes"]=routerNodes
let routerOptions=try JSONSerialization.data(withJSONObject:routerRoot)
for mode in RouterVPNNodeExitModes.choices.map({$0.id}){for execution in ["local","server","auto"]{
 let owner=product("entry",mode,execution),snapshot=Form(owner);configure(snapshot,routerOptions);snapshot.deferOptions=true;snapshot.loadOptions();snapshot.finishOptions()
 check(snapshot.optionsReady&&snapshot.selected(snapshot.topology)=="multihop"&&snapshot.selected(snapshot.entry)=="entry"&&snapshot.selected(snapshot.exit)=="exit-router"&&snapshot.selected(snapshot.exitMode)==mode&&snapshot.selected(snapshot.execution)==execution,"Disconnected whole-profile snapshot changed")
 choose(snapshot.scope,"temporary");snapshot.runSpeedLab();check(snapshot.captured != nil,snapshot.detail.string);try JSONSerialization.data(withJSONObject:snapshot.captured!,options:[.sortedKeys]).write(to:output.appendingPathComponent("speed-lab-multihop-"+mode+"-"+execution+".json"))
}}
do{let owner=product("entry","naive-h2","auto"),snapshot=Form(owner);configure(snapshot,routerOptions);snapshot.deferOptions=true;snapshot.loadOptions();choose(owner.multihopExitModePopup,"reality-xhttp");snapshot.finishOptions();check(!snapshot.optionsReady && !snapshot.runButton.isEnabled && snapshot.nodes.isEmpty,"Replaced visible profile was adopted by stale options");snapshot.runSpeedLab();check(snapshot.captured==nil,"Stale options still allowed Run")}
do{let owner=product("entry","naive-h2","auto"),snapshot=Form(owner);configure(snapshot,routerOptions);snapshot.deferOptions=true;snapshot.loadOptions();choose(owner.routerPopup,"exit-router");snapshot.finishOptions();check(!snapshot.optionsReady&&snapshot.nodes.isEmpty,"Changed main node accepted old options")}
do{let owner=product("entry","naive-h2","auto"),snapshot=Form(owner);configure(snapshot,originalOptions);snapshot.loadOptions();check(!snapshot.optionsReady&&snapshot.nodes.isEmpty,"Unrelated selected API node adopted saved multihop")}
do{let owner=product("entry","naive-h2","auto");owner.connectionProfileSelection=RouterVPNConnectionProfileSelection(selectedNodeID:"entry",multihopEnabled:true,entryID:"removed-entry",exitID:"exit-router",exitMode:"naive-h2",execution:"auto");owner.multihopEntryPopup.selectItem(at:-1);let snapshot=Form(owner);configure(snapshot,routerOptions);snapshot.loadOptions();check(snapshot.optionsReady&&snapshot.selected(snapshot.entry)=="removed-entry","Missing saved entry became a different path");choose(snapshot.scope,"temporary");snapshot.runSpeedLab();check(snapshot.captured==nil,"Missing saved entry reached controller")}
do{let owner=product("entry","naive-h2","auto"),snapshot=Form(owner);configure(snapshot,routerOptions);snapshot.deferOptions=true;snapshot.loadOptions();snapshot.closed=true;snapshot.finishOptions();check(!snapshot.optionsReady&&snapshot.nodes.isEmpty,"Closed window adopted options")}
do{let owner=product("entry","naive-h2","auto");let index=owner.routerIDs.firstIndex(of:"entry")!;owner.profiles[index]["profile_token"]=String(repeating:"a",count:64);owner.multihopNodeTokens["entry"]=String(repeating:"a",count:64);let snapshot=Form(owner);var relinked=routerRoot;var nodes=routerNodes;nodes[index]["profile_token"]=String(repeating:"b",count:64);relinked["nodes"]=nodes;configure(snapshot,try JSONSerialization.data(withJSONObject:relinked));snapshot.loadOptions();check(!snapshot.optionsReady&&snapshot.nodes.isEmpty,"Same-ID relink ignored captured source token")}
do{let owner=product("exit","naive-h2","auto"),snapshot=Form(owner);configure(snapshot,originalOptions);snapshot.deferOptions=true;snapshot.loadOptions();choose(owner.multihopExitModePopup,"reality-xhttp");owner.multihopNodeTokens["entry"]=String(repeating:"b",count:64);snapshot.finishOptions();check(snapshot.optionsReady&&snapshot.selected(snapshot.topology)=="external","Inactive main hop choices blocked an external-node path")}
do{let owner=product("entry","naive-h2","auto"),snapshot=Form(owner);configure(snapshot,routerOptions);snapshot.deferOptions=true;snapshot.loadOptions();choose(owner.multihopExitModePopup,"reality-xhttp");choose(owner.multihopExitModePopup,"naive-h2");owner.connectionProfileSelectionGeneration=UUID();snapshot.finishOptions();check(!snapshot.optionsReady&&snapshot.nodes.isEmpty,"Main selection ABA accepted an old options owner")}
for change in ["mode","node","relink","generation","missing-hop-token"]{
 let owner=product("entry","naive-h2","auto"),snapshot=Form(owner);configure(snapshot,routerOptions);snapshot.loadOptions();check(snapshot.optionsReady,"Test did not reach Ready");choose(snapshot.scope,"temporary")
 if change=="mode"{choose(owner.multihopExitModePopup,"reality-xhttp")}
 if change=="node"{choose(owner.routerPopup,"exit-router")}
 if change=="relink"{let i=owner.routerIDs.firstIndex(of:"entry")!;owner.profiles[i]["profile_token"]=String(repeating:"b",count:64);owner.multihopNodeTokens["entry"]=String(repeating:"b",count:64)}
 if change=="generation"{owner.connectionProfileSelectionGeneration=UUID()}
 if change=="missing-hop-token"{let i=snapshot.nodes.firstIndex(where:{$0["id"] as? String=="exit-router"})!;snapshot.nodes[i].removeValue(forKey:"profile_token")}
 snapshot.runSpeedLab();check(snapshot.captured==nil,"Post-Ready replacement reached controller: "+change)
}
UserDefaults.standard.setVolatileDomain([macConnectionMultihopEnabledKey:false],forName:UserDefaults.argumentDomain)
do{let owner=ProductWindowController(),snapshot=Form(owner);var empty=originalRoot;empty["nodes"]=[[String:Any]]();configure(snapshot,try JSONSerialization.data(withJSONObject:empty));snapshot.loadOptions();choose(snapshot.scope,"temporary");choose(snapshot.topology,"system-direct");snapshot.runSpeedLab();check(snapshot.captured != nil,snapshot.detail.string);check(snapshot.captured?["expected_selected_node_id"] as? String=="" && (snapshot.captured?["expected_profile_tokens"] as? [String:String])==[:],"No-node System Direct omitted its empty-selection precondition")}
UserDefaults.standard.removeVolatileDomain(forName:UserDefaults.argumentDomain)
print("Actual Swift Speed Lab options/defaults/Run callback: \(checks) checks PASS")
'''.replace('EXIT_MODES', exit_modes).replace('PROFILE_SELECTION', profile_selection).replace('PROFILE_CAPTURE', profile_capture).replace('EXIT_INITIALIZER', exit_initializer).replace('POLICY', policy).replace('METHODS', methods)
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
            directory=Path(temporary);env=dict(os.environ,ROUTERVPN_EXTERNAL_FORM_PAYLOADS=str(directory),
                ROUTERVPN_SPEED_LAB_FORM_CAPTURE_REQUIRED='1')
            subprocess.run(['go','test','-count=1','./cmd/client','-run','^TestDesktopSpeedLabPathFormCatalog$'],cwd=ROOT,env=env,check=True,timeout=180)
            if args.platform=='linux': linux_form(directory)
            elif args.platform=='darwin': swift_form(directory)
            else: subprocess.run([shell,'-NoLogo','-NoProfile','-File',str(ROOT/'client/test-windows-speed-lab-paths.ps1'),'-Root',str(ROOT),'-Output',str(directory)],check=True,timeout=120)
            subprocess.run(['go','test','-race','-count=1','./cmd/client','-run','^TestDesktopSpeedLabPathFormPayload$'],cwd=ROOT,env=env,check=True,timeout=180)
    print('Native '+args.platform+' Speed Lab forms -> exact captured Go paths: PASS',flush=True)


if __name__=='__main__': main()
