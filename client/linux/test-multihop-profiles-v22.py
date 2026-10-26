#!/usr/bin/env python3
"""Exercise shipping GTK profile controls, persistence and Connect serialization.

The real modal Add/Load/Update handlers run against an isolated in-process HTTP
fixture. GTK widgets and GKeyFile reads/writes are real; no VPN is started.
"""
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent


def block(source, marker):
    start = source.index(marker)
    brace = source.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main():
    profiles = (HERE/'routervpn-connection-profiles-v11.inc').read_text()
    settings = (HERE/'routervpn-profile-settings-v1.inc').read_text()
    asynchronous = (HERE/'routervpn-async-actions-v16.inc').read_text()
    choices = (HERE/'routervpn-multihop-choices-v22.inc').read_text()
    methods = '\n'.join(block(asynchronous, marker) for marker in (
        'static char *linux_multihop_execution_choice_v1(',
        'static void linux_multihop_store_execution_v1(',
    ))
    methods += '\n' + block(settings, 'static void profile_settings_grid_row_v7(')
    for marker in (
        'static gboolean linux_profile_selection_v11(',
        'static void linux_profile_store_selection_v11(',
        'static void linux_profile_apply_custom_v11(',
        'static char *linux_profile_setup_body_v11(',
        'static void linux_profile_populate_nodes_v11(',
        'static void linux_profile_populate_saved_v11(',
        'static gboolean linux_profile_mutation_busy_v11(',
    ):
        methods += '\n' + block(profiles, marker)
    begin = profiles.index('typedef struct {\n    GtkWidget *dialog, *name, *saved, *multi')
    end = profiles.index('} LinuxProfileEditorV22;', begin)+len('} LinuxProfileEditorV22;')
    methods += '\n' + profiles[begin:end]
    for marker in (
        'static void linux_profile_editor_changed_v22(',
        'static void linux_profile_manager_v11(',
        'static gboolean linux_profile_runtime_active_v11(',
        'static void linux_profile_connect_v11(',
    ):
        methods += '\n' + block(profiles, marker)
    program = r'''
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
typedef struct {GtkWidget*window;} App;
typedef struct {App*app;GtkWidget*mode,*multihop;} LinuxUnifiedV8;
typedef struct {char*data;size_t len;} Buffer;
static unsigned checks, saved_count, updated_count, connected_count, delegated_count;
static gboolean status_busy, mutation_busy;
static char *keypath,*saved_body,*updated_body,*connected_body;
static const char *wanted_mode,*wanted_execution;
static void check(gboolean yes,const char*message){checks++;if(!yes){g_printerr("GTK profile check failed: %s\n",message);exit(1);}}
static JsonNode*parse_json(const char*raw){JsonParser*p=json_parser_new();JsonNode*n=NULL;if(json_parser_load_from_data(p,raw,-1,NULL))n=json_node_copy(json_parser_get_root(p));g_object_unref(p);return n;}
static const char*obj_string(JsonObject*obj,const char*key){return obj&&json_object_has_member(obj,key)?json_object_get_string_member(obj,key):"";}
static GKeyFile*linux_unified_load_keyfile_v8(void){GKeyFile*k=g_key_file_new();g_key_file_load_from_file(k,keypath,G_KEY_FILE_NONE,NULL);return k;}
static void linux_unified_save_keyfile_v8(GKeyFile*k){gsize n=0;char*raw=g_key_file_to_data(k,&n,NULL);check(g_file_set_contents(keypath,raw,n,NULL),"GKeyFile persistence failed");g_free(raw);}
static char*linux_unified_custom_layers_for_mode_v8(const char*mode){check(strcmp(mode,"smart-auto")==0,"fixture mode changed");return NULL;}
static void linux_unified_store_mode_v8(const char*mode){check(strcmp(mode,"smart-auto")==0,"Load changed logical mode");}
static void linux_unified_refresh_mode_combo_v8(LinuxUnifiedV8*s){(void)s;}
static void linux_unified_refresh_v8(LinuxUnifiedV8*s){(void)s;}
static void linux_unified_connect_v8(GtkButton*b,gpointer s){(void)b;(void)s;delegated_count++;}
static void append_diag(App*a,const char*text){(void)a;check(text&&text[0],"Empty rejection reason");}
static gboolean routervpn_require_mutation_idle(App*a,const char*reason){(void)a;(void)reason;return !mutation_busy;}
static char*json_string_body(const char*key,const char*value){JsonObject*o=json_object_new();json_object_set_string_member(o,key,value);JsonNode*n=json_node_new(JSON_NODE_OBJECT);json_node_take_object(n,o);JsonGenerator*g=json_generator_new();json_generator_set_root(g,n);char*raw=json_generator_to_data(g,NULL);g_object_unref(g);json_node_free(n);return raw;}
static gboolean api_request(const char*path,const char*method,const char*body,long timeout,Buffer*out,char**err){(void)method;(void)timeout;(void)err;const char*response=NULL;char*allocated=NULL;
 if(strcmp(path,"/api/status")==0)response=status_busy?"{\"connected\":true,\"phase\":\"connected\"}":"{\"connected\":false,\"phase\":\"off\"}";
 else if(strcmp(path,"/api/multihop/status")==0)response="{\"nodes\":[{\"id\":\"entry\",\"name\":\"Entry\"},{\"id\":\"exit\",\"name\":\"Exit\"}]}";
 else if(strcmp(path,"/api/connection-profiles")==0)response="{\"profiles\":[{\"id\":\"fixture\",\"name\":\"Fixture\",\"mode\":\"smart-auto\",\"node_id\":\"entry\"}]}";
 else if(strcmp(path,"/api/connection-profile/setup/save")==0){saved_count++;g_free(saved_body);saved_body=g_strdup(body);response="{\"ok\":true}";}
 else if(strcmp(path,"/api/connection-profile/setup/update")==0){updated_count++;g_free(updated_body);updated_body=g_strdup(body);response="{\"ok\":true}";}
 else if(strcmp(path,"/api/connection-profile/setup/load")==0){allocated=g_strdup_printf("{\"mode\":\"smart-auto\",\"multihop_enabled\":true,\"multihop_entry_id\":\"entry\",\"multihop_exit_id\":\"exit\",\"multihop_exit_mode\":\"%s\",\"multihop_execution\":\"%s\",\"custom_layers\":[]}",wanted_mode,wanted_execution);response=allocated;}
 else{check(FALSE,"Unexpected API route");}
 out->data=g_strdup(response);out->len=strlen(response);g_free(allocated);return TRUE;
}
static void post_and_log(App*a,const char*path,const char*body,long timeout,const char*label){(void)a;(void)timeout;(void)label;check(strcmp(path,"/api/multihop/connect")==0,"Profile Connect changed endpoint");connected_count++;g_free(connected_body);connected_body=g_strdup(body);}
CHOICES
METHODS
static void choose(GtkWidget*combo,const char*id){check(gtk_combo_box_set_active_id(GTK_COMBO_BOX(combo),id),"Requested choice missing from real control");}
static GtkWidget*find_entry(GtkWidget*root){if(GTK_IS_ENTRY(root))return root;if(!GTK_IS_CONTAINER(root))return NULL;GList*children=gtk_container_get_children(GTK_CONTAINER(root));GtkWidget*found=NULL;for(GList*p=children;p&&!found;p=p->next)found=find_entry(GTK_WIDGET(p->data));g_list_free(children);return found;}
static GtkWidget*find_grid(GtkWidget*root){if(GTK_IS_GRID(root)&&gtk_grid_get_child_at(GTK_GRID(root),1,3)!=NULL)return root;if(!GTK_IS_CONTAINER(root))return NULL;GList*children=gtk_container_get_children(GTK_CONTAINER(root));GtkWidget*found=NULL;for(GList*p=children;p&&!found;p=p->next)found=find_grid(GTK_WIDGET(p->data));g_list_free(children);return found;}
static GtkWidget*find_dialog(void){GList*all=gtk_window_list_toplevels();GtkWidget*found=NULL;for(GList*p=all;p&&!found;p=p->next)if(GTK_IS_DIALOG(p->data)&&g_strcmp0(gtk_window_get_title(GTK_WINDOW(p->data)),"Connection profiles")==0)found=p->data;g_list_free(all);return found;}
static void check_body(const char*raw,gboolean connect){JsonNode*n=parse_json(raw);check(n&&JSON_NODE_HOLDS_OBJECT(n),"Invalid captured payload");JsonObject*o=json_node_get_object(n);check(strcmp(obj_string(o,connect?"entry_id":"multihop_entry_id"),"entry")==0&&strcmp(obj_string(o,connect?"exit_id":"multihop_exit_id"),"exit")==0,"Captured identities changed");check(strcmp(obj_string(o,connect?"exit_mode":"multihop_exit_mode"),wanted_mode)==0,"Captured exit transport changed");check(strcmp(obj_string(o,connect?"execution":"multihop_execution"),wanted_execution)==0,"Captured execution changed");json_node_free(n);}
static void check_stored(void){gboolean on=FALSE;char*a=NULL,*b=NULL,*m=NULL;linux_profile_selection_v11(&on,&a,&b,&m);char*execution=linux_multihop_execution_choice_v1();check(on&&strcmp(a,"entry")==0&&strcmp(b,"exit")==0&&strcmp(m,wanted_mode)==0&&strcmp(execution,wanted_execution)==0,"Load/readback changed the complete staged graph");g_free(a);g_free(b);g_free(m);g_free(execution);}
static unsigned stage,ticks,old_saved,old_updated;
static LinuxUnifiedV8*active;
static gboolean drive(gpointer unused){(void)unused;check(++ticks<100,"Modal callback timed out");GtkWidget*dialog=find_dialog();if(!dialog)return G_SOURCE_CONTINUE;GtkWidget*grid=find_grid(dialog),*name=find_entry(dialog);check(grid&&name,"Actual profile controls missing");GtkWidget*entry=gtk_grid_get_child_at(GTK_GRID(grid),1,0),*exit=gtk_grid_get_child_at(GTK_GRID(grid),1,1),*mode=gtk_grid_get_child_at(GTK_GRID(grid),1,2),*execution=gtk_grid_get_child_at(GTK_GRID(grid),1,3);
 if(stage==0){gtk_entry_set_text(GTK_ENTRY(name),"Fixture");choose(entry,"entry");choose(exit,"exit");choose(mode,wanted_mode);choose(execution,wanted_execution);check(gtk_widget_get_sensitive(gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog),2)),"Valid Add disabled");stage++;gtk_dialog_response(GTK_DIALOG(dialog),2);}
 else if(stage==1){check(saved_count==old_saved+1,"Add handler was not invoked");check_body(saved_body,FALSE);choose(mode,"shadowsocks");choose(execution,"local");stage++;gtk_dialog_response(GTK_DIALOG(dialog),1);}
 else if(stage==2){check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(mode)),wanted_mode)==0&&strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(execution)),wanted_execution)==0,"Load left visible controls on different values");check_stored();check(gtk_widget_get_sensitive(gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog),3)),"Valid Update disabled");stage++;gtk_dialog_response(GTK_DIALOG(dialog),3);}
 else{check(updated_count==old_updated+1,"Update handler was not invoked");check_body(updated_body,FALSE);check_stored();unsigned before=connected_count;linux_profile_connect_v11(NULL,active);check(connected_count==before+1,"Loaded primary Connect did not use staged graph");check_body(connected_body,TRUE);
 linux_multihop_select_preserving_v22(mode,"future-mode");check(!gtk_widget_get_sensitive(gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog),2))&&!gtk_widget_get_sensitive(gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog),3)),"Unavailable saved exit left Add/Update enabled");choose(mode,wanted_mode);linux_multihop_select_preserving_v22(execution,"future-execution");check(!gtk_widget_get_sensitive(gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog),2)),"Invalid execution left Add enabled");gtk_dialog_response(GTK_DIALOG(dialog),GTK_RESPONSE_CLOSE);return G_SOURCE_REMOVE;}
 return G_SOURCE_CONTINUE;
}
int main(int argc,char**argv){gtk_init(&argc,&argv);check(argc==2,"Missing fixture directory");keypath=g_build_filename(argv[1],"settings.ini",NULL);App app={gtk_window_new(GTK_WINDOW_TOPLEVEL)};LinuxUnifiedV8 state={&app,gtk_combo_box_text_new(),gtk_check_button_new()};gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.mode),"smart-auto","SMART AUTO");choose(state.mode,"smart-auto");gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(state.multihop),TRUE);active=&state;
 const char*modes[]={"shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp","naive-h2","naive-h3","wg","awg2-fast","awg2-strong","ss-v2ray","split","max"},*executions[]={"local","server","auto"};
 JsonArray*catalog=json_array_new();for(guint i=0;i<G_N_ELEMENTS(modes);i++)json_array_add_string_element(catalog,modes[i]);for(guint i=0;i<G_N_ELEMENTS(modes);i++)check(linux_multihop_exit_advertised_v22(catalog,modes[i]),"Eight-mode capability mismatch");json_array_unref(catalog);
 for(guint i=0;i<G_N_ELEMENTS(modes);i++)for(guint j=0;j<G_N_ELEMENTS(executions);j++){wanted_mode=modes[i];wanted_execution=executions[j];linux_profile_store_selection_v11(TRUE,"entry","exit","shadowsocks");linux_multihop_store_execution_v1("local");stage=ticks=0;old_saved=saved_count;old_updated=updated_count;g_timeout_add(10,drive,NULL);linux_profile_manager_v11(NULL,&state);check(stage==3,"Modal sequence incomplete");}
 unsigned before=connected_count;linux_profile_store_selection_v11(TRUE,"entry","exit","future-mode");gboolean on;char*a=NULL,*b=NULL,*m=NULL;linux_profile_selection_v11(&on,&a,&b,&m);check(on&&strcmp(m,"future-mode")==0,"Unknown persisted exit became Shadowsocks");g_free(a);g_free(b);g_free(m);linux_profile_connect_v11(NULL,&state);check(connected_count==before,"Unknown exit was connected");
 linux_profile_store_selection_v11(TRUE,"entry","exit","naive-h3");linux_multihop_store_execution_v1("future-execution");char*unknown=linux_multihop_execution_choice_v1();check(strcmp(unknown,"future-execution")==0,"Unknown execution became Local");g_free(unknown);linux_profile_connect_v11(NULL,&state);check(connected_count==before,"Unknown execution was connected");
 linux_multihop_store_execution_v1("auto");mutation_busy=TRUE;linux_profile_connect_v11(NULL,&state);check(connected_count==before,"Changed session ownership reached Connect");mutation_busy=FALSE;status_busy=TRUE;linux_profile_connect_v11(NULL,&state);check(connected_count==before&&delegated_count==1,"Active connection did not delegate to Disconnect");status_busy=FALSE;
 check(linux_profile_setup_body_v11(&state,"Fixture",NULL,TRUE,"entry","entry","naive-h3","auto")==NULL,"Same-node profile accepted");check(linux_profile_setup_body_v11(&state,"Fixture",NULL,TRUE,"entry","exit","unknown","auto")==NULL,"Unknown saved exit accepted");check(linux_profile_setup_body_v11(&state,"Fixture",NULL,TRUE,"entry","exit","naive-h3","unknown")==NULL,"Unknown saved execution accepted");
 gtk_widget_destroy(app.window);gtk_widget_destroy(state.mode);gtk_widget_destroy(state.multihop);g_free(keypath);g_free(saved_body);g_free(updated_body);g_free(connected_body);printf("Actual GTK Add/Load/Update/Connect + disk restore: %u checks, 39 exact exit/execution graphs PASS\n",checks);return 0;}
'''.replace('\nCHOICES\n', '\n'+choices+'\n').replace('\nMETHODS\n', '\n'+methods+'\n')
    with tempfile.TemporaryDirectory(prefix='routervpn-gtk-multihop-profiles-') as temporary:
        directory = Path(temporary)
        source = directory/'profiles.c'
        source.write_text(program)
        flags = subprocess.check_output(['pkg-config','--cflags','--libs','gtk+-3.0','json-glib-1.0'],text=True).split()
        subprocess.run(['gcc','-Wall','-Wextra','-Werror',str(source),'-o',str(directory/'profiles')]+flags,check=True)
        subprocess.run(['xvfb-run','-a',str(directory/'profiles'),str(directory)],check=True,timeout=60)


if __name__ == '__main__':
    main()
