/* Executable source fixture: GTK and JSON are real, controller I/O is doubled. */
#include <gtk/gtk.h>
#include <glib/gstdio.h>
#include <json-glib/json-glib.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
typedef struct { GtkWidget *window; } App;
typedef struct { App *app; GtkWidget *node, *mode, *multihop, *connect, *stack; gboolean syncing; } LinuxUnifiedV8;
typedef struct { char *data; size_t len; } Buffer;
static guint checks, posts, delegates, writes, stage, ticks;
static gboolean busy, active, capability = TRUE, socks_capability = TRUE, openvpn_capability = TRUE, hysteria_capability = TRUE, late_read, late_post, bad_reply, fail_write;
static char *keypath, *last_body, *last_path;
static JsonNode *catalog, *saved;
static LinuxUnifiedV8 *unified;
static void check(gboolean ok, const char *message) { checks++; if (!ok) { g_printerr("GTK ordered: %s\n", message); exit(1); } }
static JsonNode *parse_json(const char *raw) { if (!raw) return NULL; JsonParser *p=json_parser_new(); JsonNode *n=NULL; if(json_parser_load_from_data(p,raw,-1,NULL))n=json_node_copy(json_parser_get_root(p));g_object_unref(p);return n; }
static const char *obj_string(JsonObject *o,const char *k) { JsonNode *n=o&&json_object_has_member(o,k)?json_object_get_member(o,k):NULL;return n&&JSON_NODE_HOLDS_VALUE(n)&&json_node_get_value_type(n)==G_TYPE_STRING?json_node_get_string(n):""; }
#define external_path_string_v4 obj_string
#include "ordered-source-helpers.h"
static GKeyFile *linux_unified_load_keyfile_v8(void) { GKeyFile *k=g_key_file_new();g_key_file_load_from_file(k,keypath,G_KEY_FILE_NONE,NULL);return k; }
static void linux_unified_save_keyfile_v8(GKeyFile *k) { if(fail_write)return;gsize size;char *raw=g_key_file_to_data(k,&size,NULL);check(g_file_set_contents(keypath,raw,size,NULL),"settings write");g_free(raw); }
static char *linux_unified_custom_layers_for_mode_v8(const char *mode) { (void)mode;return NULL; }
static void linux_unified_store_mode_v8(const char *mode) { (void)mode; }
static void linux_unified_refresh_mode_combo_v8(LinuxUnifiedV8 *s) { (void)s; }
static void refresh_all(App *app) { g_object_set_data_full(G_OBJECT(app->window),"router-vpn-source-catalog-v24",copy_public_source_value_v24(catalog),(GDestroyNotify)json_node_free); }
static void linux_unified_refresh_v8(LinuxUnifiedV8 *s) { s->syncing=TRUE;gtk_combo_box_set_active_id(GTK_COMBO_BOX(s->node),obj_string(json_node_get_object(catalog),"selected_id"));s->syncing=FALSE; }
static gboolean linux_async_busy_v16(App *app) { (void)app;return busy; }
static gboolean routervpn_require_mutation_idle(App *app,const char *reason) { (void)app;(void)reason;return !busy&&!active; }
static void append_diag(App *app,const char *text) { (void)app;check(text&&text[0],"empty refusal"); }
static void linux_unified_connect_v8(GtkButton *b,gpointer p) { (void)b;(void)p;delegates++; }
static void linux_unified_multihop_v8(GtkButton *b,gpointer p) { (void)b;(void)p;delegates++; }
static GtkWidget *make_button(const char *label,GCallback callback,gpointer data) { GtkWidget *b=gtk_button_new_with_label(label);g_signal_connect(b,"clicked",callback,data);return b; }
static void profile_settings_grid_row_v7(GtkWidget *grid,int row,const char *label,GtkWidget *value) { gtk_grid_attach(GTK_GRID(grid),gtk_label_new(label),0,row,1,1);gtk_grid_attach(GTK_GRID(grid),value,1,row,1,1); }
static char *json_string_body(const char *key,const char *value) { JsonObject *o=json_object_new();json_object_set_string_member(o,key,value);JsonNode *n=json_node_new(JSON_NODE_OBJECT);json_node_take_object(n,o);char *raw=json_to_string(n,FALSE);json_node_free(n);return raw; }
static char *linux_multihop_execution_choice_v1(void) { GKeyFile*k=linux_unified_load_keyfile_v8();char*s=g_key_file_get_string(k,"state","multihop_execution",NULL);g_key_file_unref(k);return s?s:g_strdup("local"); }
static void linux_multihop_store_execution_v1(const char *value) { GKeyFile*k=linux_unified_load_keyfile_v8();g_key_file_set_string(k,"state","multihop_execution",value);linux_unified_save_keyfile_v8(k);g_key_file_unref(k); }
static gboolean api_request(const char *,const char *,const char *,long,Buffer *,char **);
static void post_and_log(App *app,const char *path,const char *body,long timeout,const char *label) { (void)app;(void)label;check(timeout==180000,"ordered deadline");posts++;g_free(last_body);g_free(last_path);last_body=g_strdup(body);last_path=g_strdup(path); }
#include "routervpn-multihop-choices-v22.inc"
#include "routervpn-connection-profiles-v11.inc"

static void change_choice(void) { gtk_combo_box_set_active_id(GTK_COMBO_BOX(unified->node),"n8");gtk_combo_box_set_active_id(GTK_COMBO_BOX(unified->node),"exit"); }
static JsonObject *response_from(JsonObject *request) {
    JsonObject *o=json_object_new();json_object_set_string_member(o,"selected_node_id",obj_string(request,"expected_selected_node_id"));json_object_set_string_member(o,"mode",obj_string(request,"mode"));json_object_set_boolean_member(o,"multihop_enabled",TRUE);json_object_set_string_member(o,"multihop_execution",obj_string(request,"multihop_execution"));
    JsonArray *rows=linux_ordered_array_v1(request,"multihop_nodes");JsonObject*tokens=linux_ordered_object_v1(request,"expected_profile_tokens");
    if(rows)json_object_set_array_member(o,"multihop_nodes",json_array_ref(rows));if(tokens)json_object_set_object_member(o,"profile_tokens",json_object_ref(tokens));
    return o;
}
static gboolean api_request(const char *path,const char *method,const char *body,long timeout,Buffer *out,char **error) {
    (void)method;(void)timeout;(void)error;char *raw=NULL;
    if(strcmp(path,"/api/status")==0)raw=g_strdup(active?"{\"connected\":true,\"phase\":\"connected\"}":"{\"connected\":false,\"phase\":\"off\"}");
    else if(strcmp(path,"/api/profiles")==0) { raw=json_to_string(catalog,FALSE);if(late_read){late_read=FALSE;change_choice();} }
    else if(strcmp(path,"/api/multihop/status")==0)raw=g_strdup_printf("{\"ordered_nodes_supported\":%s,\"ordered_executions\":[\"local\",\"server\",\"auto\"],\"ordered_hysteria_executions\":[%s],\"ordered_openvpn_executions\":[%s],\"ordered_socks_trio_executions\":[%s],\"ordered_connect_trio_executions\":[\"local\",\"server\",\"auto\"],\"nodes\":[],\"supported_entry_modes\":[\"wg\",\"awg2-fast\",\"awg2-strong\"]}",capability?"true":"false",hysteria_capability?"\"local\",\"server\",\"auto\"":"",openvpn_capability?"\"local\",\"server\",\"auto\"":"",socks_capability?"\"local\",\"server\",\"auto\"":"");
    else if(strcmp(path,"/api/connection-profiles")==0)raw=g_strdup("{\"profiles\":[{\"id\":\"saved\",\"name\":\"Original\",\"mode\":\"shadowsocks\",\"node_id\":\"exit\"}]}");
    else if(strcmp(path,"/api/connection-profile/setup/save")==0||strcmp(path,"/api/connection-profile/setup/update")==0) {
        writes++;g_free(last_body);g_free(last_path);last_body=g_strdup(body);last_path=g_strdup(path);JsonNode *n=parse_json(body);JsonObject *q=json_node_get_object(n);
        if(linux_ordered_flag_v1(q,"multihop_enabled")) {
            JsonObject *o=response_from(q);raw=linux_ordered_json_v1(o);json_object_unref(o);
            if(saved)json_node_free(saved);saved=parse_json(raw);
        } else raw=g_strdup("{\"ok\":true}");
        json_node_free(n);if(late_post){late_post=FALSE;change_choice();}
    } else if(strcmp(path,"/api/connection-profile/setup/load")==0) {
        check(strstr(body,"expected_selected_node_id")&&strstr(body,"expected_profile_tokens"),"Load lost displayed source receipt");
        if(bad_reply)raw=g_strdup("{\"mode\":\"shadowsocks\",\"multihop_enabled\":true,\"multihop_nodes\":[{\"id\":\"n1\",\"mode\":\"wg\"},{\"id\":\"exit\",\"mode\":\"shadowsocks\"}],\"selected_node_id\":\"exit\",\"multihop_execution\":\"local\"}");
        else raw=json_to_string(saved,FALSE);
    } else check(FALSE,"unexpected controller route");
    out->data=raw;out->len=strlen(raw);return TRUE;
}

static GtkWidget *find_type(GtkWidget *root,GType type) {
    if(G_TYPE_CHECK_INSTANCE_TYPE(root,type))return root;if(!GTK_IS_CONTAINER(root))return NULL;
    GList*list=gtk_container_get_children(GTK_CONTAINER(root));GtkWidget*found=NULL;for(GList*p=list;p&&!found;p=p->next)found=find_type(p->data,type);g_list_free(list);return found;
}
static GtkWidget *find_name(GtkWidget *root,const char *name) {
    if(g_strcmp0(gtk_widget_get_name(root),name)==0)return root;if(!GTK_IS_CONTAINER(root))return NULL;
    GList*list=gtk_container_get_children(GTK_CONTAINER(root));GtkWidget*found=NULL;for(GList*p=list;p&&!found;p=p->next)found=find_name(p->data,name);g_list_free(list);return found;
}
static GtkWidget *dialog_named(const char *title) { GList*all=gtk_window_list_toplevels();GtkWidget*d=NULL;for(GList*p=all;p&&!d;p=p->next)if(GTK_IS_DIALOG(p->data)&&g_strcmp0(gtk_window_get_title(p->data),title)==0)d=p->data;g_list_free(all);return d; }
static void click(GtkWidget *root,const char *label) { GtkWidget*b=linux_profile_find_button_v11(root,label);check(b!=NULL,"real button missing");gtk_button_clicked(GTK_BUTTON(b)); }
static void choose(GtkWidget *combo,const char *id) { check(gtk_combo_box_set_active_id(GTK_COMBO_BOX(combo),id),"real choice missing"); }
static void select_row(GtkWidget *list,int index) { gtk_list_box_select_row(GTK_LIST_BOX(list),gtk_list_box_get_row_at_index(GTK_LIST_BOX(list),index)); }
static char *snapshot(void) { LinuxOrderedStateV1*o=linux_ordered_state_v1(unified);JsonObject*v=linux_ordered_value_v1(o->selection);char*raw=linux_ordered_json_v1(v);json_object_unref(v);return raw; }
static int editor_case;
static const char *connect_editor_protocol, *connect_editor_prefix;
static guint connect_editor_count = 3;
static gboolean drive_editor(gpointer data) {
    (void)data;check(++ticks<100,"editor callback timeout");GtkWidget*d=dialog_named("Ordered native path");if(!d)return G_SOURCE_CONTINUE;
    GtkWidget*list=find_type(d,GTK_TYPE_LIST_BOX),*candidate=find_name(d,"ordered-node-candidate"),*transport=find_name(d,"ordered-prefix-transport");check(list&&candidate&&transport,"ordered controls missing");
    if(editor_case==0) {
        check(gtk_combo_box_get_active_id(GTK_COMBO_BOX(candidate))==NULL,"new source was chosen implicitly");
        choose(candidate,"n1");click(d,"Add entry / hop");choose(transport,"awg2-fast");
        choose(transport,"shadowsocks");check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),"awg2-fast")==0,"unsupported prefix choice remained visible");
        choose(candidate,"n2");click(d,"Add entry / hop");choose(transport,"awg2-strong");
        click(d,"Move up");check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),"awg2-strong")==0,"mode did not travel with member");
        select_row(list,1);check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),"awg2-fast")==0,"reordered fast mode lost");
        choose(candidate,"n3");click(d,"Add entry / hop");click(d,"Remove");
        select_row(list,2);check(gtk_widget_get_sensitive(transport),"final transport chooser unavailable");choose(transport,"wg");check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),"shadowsocks")==0,"packet mode accepted as final");click(d,"Remove");
        check(gtk_list_box_get_row_at_index(GTK_LIST_BOX(list),2)!=NULL&&gtk_list_box_get_row_at_index(GTK_LIST_BOX(list),3)==NULL,"final removed or middle truncated");
        gtk_dialog_response(GTK_DIALOG(d),GTK_RESPONSE_APPLY);
    } else if(editor_case==1) {
        select_row(list,0);check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),"awg2-strong")==0,"reopen lost first mode");
        select_row(list,1);check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),"awg2-fast")==0,"reopen lost middle mode");
        choose(transport,"wg");gtk_dialog_response(GTK_DIALOG(d),GTK_RESPONSE_CANCEL);
    } else if(editor_case==2||editor_case==3) {
        if(stage++==0){choose(candidate,"n4");click(d,"Add entry / hop");if(editor_case==2)late_read=TRUE;else json_object_set_string_member(external_source_profile_v24(json_node_get_object(catalog),"n4"),"profile_token","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");gtk_dialog_response(GTK_DIALOG(d),GTK_RESPONSE_APPLY);return G_SOURCE_CONTINUE;}
        gtk_dialog_response(GTK_DIALOG(d),GTK_RESPONSE_CANCEL);
    } else if(editor_case==4) {
        for(int i=1;i<=8;i++){char*id=g_strdup_printf("n%d",i);choose(candidate,id);click(d,"Add entry / hop");g_free(id);}
        check(gtk_list_box_get_row_at_index(GTK_LIST_BOX(list),7)!=NULL&&gtk_list_box_get_row_at_index(GTK_LIST_BOX(list),8)==NULL,"cap silently truncated a member");gtk_dialog_response(GTK_DIALOG(d),GTK_RESPONSE_CANCEL);
    } else if(editor_case==6) {
        choose(candidate,"n1");click(d,"Add entry / hop");
        choose(candidate,"n2");click(d,"Add entry / hop");
        check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),"shadowsocks")==0,"custom middle acquired paired transport");
        choose(transport,"wg");check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),"shadowsocks")==0,"custom middle accepted paired mode");
        gtk_dialog_response(GTK_DIALOG(d),GTK_RESPONSE_APPLY);
    } else if(editor_case==9) {
        choose(candidate,"n1");click(d,"Add entry / hop");choose(transport,"awg2-fast");
        choose(candidate,"n2");click(d,"Add entry / hop");
        check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),"socks5")==0,"SOCKS Add substituted its saved transport");
        choose(transport,"shadowsocks");check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),"socks5")==0,"SOCKS Change mode substituted Shadowsocks");
        select_row(list,2);choose(transport,"hysteria2");check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),"shadowsocks")==0,"SOCKS middle admitted an unsupported final");
        gtk_dialog_response(GTK_DIALOG(d),GTK_RESPONSE_APPLY);
    } else if(editor_case==10) {
        for(guint i=0;i<connect_editor_count-2;i++){
            char *id=g_strdup_printf("n%u",i==0?1:i+2);choose(candidate,id);g_free(id);
            click(d,"Add entry / hop");choose(transport,connect_editor_prefix);
        }
        choose(transport,connect_editor_protocol);
        check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),connect_editor_prefix)==0,"CONNECT acquired physical entry transport");
        choose(candidate,"n2");click(d,"Add entry / hop");
        check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),connect_editor_protocol)==0,"CONNECT Add substituted its exact saved transport");
        GtkListBoxRow *middle_row=gtk_list_box_get_row_at_index(GTK_LIST_BOX(list),connect_editor_count-2);
        GtkWidget *middle_label=find_type(GTK_WIDGET(middle_row),GTK_TYPE_LABEL);
        const char *title=strcmp(connect_editor_protocol,"shadowsocks")==0?"Shadowsocks 2022":strcmp(connect_editor_protocol,"socks5")==0?"SOCKS5":strcmp(connect_editor_protocol,"openvpn")==0?"OpenVPN":strcmp(connect_editor_protocol,"https-connect")==0?"HTTPS CONNECT":"HTTP CONNECT";
        check(middle_label&&strstr(gtk_label_get_text(GTK_LABEL(middle_label)),title),"CONNECT row concealed its saved transport");
        const char *other=strcmp(connect_editor_protocol,"https-connect")==0?"http-connect":"https-connect";
        choose(transport,other);check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),connect_editor_protocol)==0,"CONNECT Change mode substituted its saved protocol");
        choose(transport,"shadowsocks");check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),connect_editor_protocol)==0,"CONNECT Change mode substituted Shadowsocks");
        select_row(list,connect_editor_count-1);choose(transport,"hysteria2");check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),"shadowsocks")==0,"CONNECT middle admitted an unsupported final");
        gtk_dialog_response(GTK_DIALOG(d),GTK_RESPONSE_APPLY);
    } else if(editor_case==7) {
        choose(candidate,"n1");click(d,"Add entry / hop");choose(transport,"awg2-fast");
        select_row(list,1);choose(transport,"hysteria2");
        check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),"hysteria2")==0,"selected Hysteria2 final ignored");
        choose(candidate,"n2");click(d,"Add entry / hop");
        check(gtk_list_box_get_row_at_index(GTK_LIST_BOX(list),2)==NULL,"imported middle added to Hysteria2 final");
        gtk_dialog_response(GTK_DIALOG(d),GTK_RESPONSE_APPLY);
    } else if(editor_case==8) {
        select_row(list,1);check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(transport)),"hysteria2")==0,"reopen lost Hysteria2 final");
        choose(transport,"shadowsocks");gtk_dialog_response(GTK_DIALOG(d),GTK_RESPONSE_CANCEL);
    } else if(editor_case==5) {
        gtk_widget_destroy(unified->app->window);
    }
    return G_SOURCE_REMOVE;
}
static void edit(int kind,gboolean fresh) { editor_case=kind;stage=ticks=0;g_timeout_add(1,drive_editor,NULL);linux_ordered_editor_v1(unified,fresh); }
static int profile_case;
static gboolean drive_profiles(gpointer data) {
    (void)data;check(++ticks<100,"profile callback timeout");GtkWidget*d=dialog_named("Connection profiles");if(!d)return G_SOURCE_CONTINUE;
    GtkWidget*name=find_type(d,GTK_TYPE_ENTRY);check(name!=NULL,"profile name control missing");gtk_entry_set_text(GTK_ENTRY(name),"Mixed original path");
    if(profile_case==5){gtk_widget_destroy(d);return G_SOURCE_REMOVE;}
    if(stage++==0) { if(profile_case==2)late_post=TRUE;gtk_dialog_response(GTK_DIALOG(d),profile_case==1||profile_case==3?1:2);return G_SOURCE_CONTINUE; }
    if(profile_case==0&&stage==2){check(writes>0,"save handler not invoked");gtk_dialog_response(GTK_DIALOG(d),3);return G_SOURCE_CONTINUE;}
    gtk_dialog_response(GTK_DIALOG(d),GTK_RESPONSE_CLOSE);return G_SOURCE_REMOVE;
}
static void profiles(int kind) { profile_case=kind;stage=ticks=0;g_timeout_add(1,drive_profiles,NULL);linux_profile_manager_v11(NULL,unified); }

static int model_only(void) {
    for (guint count=2;count<=8;count++) for (guint final_choice=0;final_choice<2;final_choice++) for (guint execution_choice=0;execution_choice<3;execution_choice++) {
        const char *final_mode=final_choice==0?"shadowsocks":"hysteria2";
        JsonArray *nodes=json_array_new(),*profiles=json_array_new();JsonObject*tokens=json_object_new(),*store=json_object_new();
        json_object_set_string_member(store,"selected_id","exit");
        for(guint i=0;i<count;i++) {
            char*id=i+1==count?g_strdup("exit"):g_strdup_printf("n%u",i);char*token=g_strdup_printf("%064x",i+1);
            const char*modes[]={"wg","awg2-fast","awg2-strong"};JsonObject*row=json_object_new(),*profile=json_object_new();
            json_object_set_string_member(row,"id",id);json_object_set_string_member(row,"mode",i+1==count?final_mode:modes[i%3]);json_array_add_object_element(nodes,row);
            json_object_set_string_member(profile,"id",id);json_object_set_string_member(profile,"profile_token",token);json_object_set_string_member(profile,"node_kind","router-vpn");json_array_add_object_element(profiles,profile);
            json_object_set_string_member(tokens,id,token);g_free(id);g_free(token);
        }
        json_object_set_array_member(store,"profiles",profiles);
        LinuxOrderedSelectionV1*selection=linux_ordered_selection_v1("exit",nodes,tokens);check(selection!=NULL,"exact bounded graph rejected");const char *executions[]={"local","server","auto"};check(linux_ordered_execution_v1(selection,executions[execution_choice]),"explicit paired execution rejected");check(!linux_ordered_execution_v1(selection,"compare")&&!linux_ordered_execution_v1(selection,"")&&!linux_ordered_execution_v1(selection,"SERVER"),"invalid execution normalized");check(linux_ordered_current_v1(selection,store),"original source inventory rejected");
        char*body=linux_ordered_connect_body_v1(selection);JsonNode*request=parse_json(body);JsonObject*q=json_node_get_object(request);
        check(json_object_get_size(q)==4&&json_array_get_length(linux_ordered_array_v1(q,"nodes"))==count,"complete serialized graph changed");check(strcmp(obj_string(q,"execution"),executions[execution_choice])==0,"Connect relabelled requested execution");
        check(json_object_get_size(linux_ordered_object_v1(q,"expected_profile_tokens"))==count,"original source inventory missing");
        JsonObject*value=linux_ordered_value_v1(selection);char*raw=linux_ordered_json_v1(value);JsonNode*disk=parse_json(raw);LinuxOrderedSelectionV1*reopened=linux_ordered_decode_v1(json_node_get_object(disk));check(reopened&&linux_ordered_current_v1(reopened,store),"disk reopen lost source inventory");check(strcmp(reopened->execution,executions[execution_choice])==0,"disk reopen relabelled requested execution");
        JsonObject*selected=json_array_get_object_element(profiles,count-1);
        if (final_choice==1) {
            check(strcmp(linux_ordered_execution_capability_v1(selection),execution_choice==0?"ordered_executions":"ordered_hysteria_executions")==0,"Hysteria execution borrowed unrelated global capability");
            for (guint layer=0;layer<2;layer++) {
                json_object_set_string_member(selected,"start_layer",layer==0?"aes-256-gcm":"aes-256-gcm+xor-whitening");
                check(!linux_ordered_current_v1(selection,store),"layered Hysteria2 final admitted");
            }
            json_object_set_boolean_member(selected,"start_layer",FALSE);check(!linux_ordered_current_v1(selection,store),"malformed Hysteria2 layer admitted");
            json_object_set_string_member(selected,"start_layer","off");check(linux_ordered_current_v1(selection,store),"original unlayered Hysteria2 final refused");
            if (count==3) {
                JsonObject *middle=json_array_get_object_element(nodes,1);char *original=g_strdup(obj_string(middle,"mode"));
                json_object_set_string_member(middle,"mode","shadowsocks");check(!linux_ordered_rows_v1(nodes,"exit"),"imported middle acquired Hysteria2 final");
                json_object_set_string_member(middle,"mode",original);g_free(original);
            }
        }
        json_object_set_boolean_member(selected,"multihop_enabled",TRUE);json_object_set_array_member(selected,"multihop_nodes",json_array_ref(nodes));
        char*load=linux_ordered_load_capture_v1(store,"exit","different-saved-profile");check(load!=NULL,"current ordered Load capture failed");JsonNode*load_node=parse_json(load);JsonObject*load_body=json_node_get_object(load_node);
        check(strcmp(obj_string(load_body,"id"),"different-saved-profile")==0&&strcmp(obj_string(load_body,"expected_selected_node_id"),"exit")==0&&json_object_get_size(linux_ordered_object_v1(load_body,"expected_profile_tokens"))==count,"Load lost complete current graph");g_free(load);json_node_free(load_node);
        json_object_remove_member(selected,"multihop_nodes");json_object_set_string_member(selected,"multihop_entry_id","n0");json_object_set_string_member(selected,"multihop_exit_id",count>2?"n1":"exit");
        load=linux_ordered_load_capture_v1(store,"exit","another-pair-target");check(load!=NULL,"current pair Load capture failed");load_node=parse_json(load);check(json_object_get_size(linux_ordered_object_v1(json_node_get_object(load_node),"expected_profile_tokens"))==(count>2?3:2),"Load lost current pair/control inventory");g_free(load);json_node_free(load_node);
        json_object_set_boolean_member(selected,"multihop_enabled",FALSE);json_object_set_array_member(selected,"multihop_nodes",json_array_ref(nodes));
        load=linux_ordered_load_capture_v1(store,"exit","direct-target");check(load!=NULL,"direct Load capture failed");load_node=parse_json(load);check(json_object_get_size(linux_ordered_object_v1(json_node_get_object(load_node),"expected_profile_tokens"))==1,"Off included remembered draft in Load expectation");g_free(load);json_node_free(load_node);
        json_object_set_boolean_member(selected,"multihop_enabled",TRUE);JsonObject*first_source=json_array_get_object_element(profiles,0);char*first_token=g_strdup(obj_string(first_source,"profile_token"));json_object_remove_member(first_source,"profile_token");check(linux_ordered_load_capture_v1(store,"exit","different-target")==NULL,"Load substituted missing current member source");json_object_set_string_member(first_source,"profile_token",first_token);g_free(first_token);json_object_set_boolean_member(selected,"multihop_enabled",FALSE);
        JsonObject*reply=json_object_new();json_object_set_string_member(reply,"selected_node_id","exit");json_object_set_string_member(reply,"mode",final_mode);json_object_set_boolean_member(reply,"multihop_enabled",TRUE);json_object_set_string_member(reply,"multihop_execution",executions[execution_choice]);json_object_set_array_member(reply,"multihop_nodes",json_array_ref(nodes));json_object_set_object_member(reply,"profile_tokens",json_object_ref(tokens));
        LinuxOrderedSelectionV1*accepted=linux_ordered_response_v1(reply);check(accepted!=NULL,"complete committed source receipt rejected");check(linux_ordered_same_path_v1(accepted,selection),"original committed execution rejected");linux_ordered_selection_free_v1(accepted);
        json_object_set_string_member(reply,"multihop_execution",executions[(execution_choice+1)%3]);accepted=linux_ordered_response_v1(reply);check(accepted!=NULL&&!linux_ordered_same_path_v1(accepted,selection),"committed receipt relabelled requested execution");linux_ordered_selection_free_v1(accepted);json_object_set_string_member(reply,"multihop_execution",executions[execution_choice]);
        json_object_set_string_member(reply,"mode",final_choice==0?"hysteria2":"shadowsocks");check(linux_ordered_response_v1(reply)==NULL,"different final mode borrowed committed receipt");json_object_set_string_member(reply,"mode",final_mode);
        json_object_set_string_member(tokens,"unlinked","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");check(linux_ordered_response_v1(reply)==NULL,"extra committed source receipt accepted");json_object_remove_member(tokens,"unlinked");
        char*response_token=g_strdup(obj_string(tokens,"n0"));json_object_remove_member(tokens,"n0");check(linux_ordered_response_v1(reply)==NULL,"missing committed source receipt accepted");json_object_set_string_member(tokens,"n0",response_token);g_free(response_token);json_object_unref(reply);
        LinuxOrderedStateV1 owner={0};check(linux_ordered_store_v1(&owner,linux_ordered_selection_v1("exit",nodes,tokens),TRUE),"disk receipt did not persist");
        LinuxOrderedSelectionV1*replacement=linux_ordered_selection_v1("exit",nodes,tokens);json_object_set_string_member(json_array_get_object_element(replacement->nodes,0),"mode","awg2-strong");fail_write=TRUE;
        check(!linux_ordered_store_v1(&owner,replacement,TRUE)&&owner.invalid&&strcmp(obj_string(json_array_get_object_element(owner.selection->nodes,0),"mode"),"wg")==0,"failed write acquired replacement receipt");
        check(!linux_ordered_store_v1(&owner,NULL,FALSE)&&owner.selection!=NULL,"failed clear lost original receipt");fail_write=FALSE;check(linux_ordered_store_v1(&owner,NULL,FALSE)&&owner.selection==NULL,"explicit clear failed");
        for(guint i=0;i<count;i++) {
            JsonObject*p=json_array_get_object_element(profiles,i);char*old=g_strdup(obj_string(p,"profile_token"));json_object_set_string_member(p,"profile_token","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");check(!linux_ordered_current_v1(selection,store),"replaced middle source connected");json_object_set_string_member(p,"profile_token",old);g_free(old);
            json_object_set_string_member(p,"node_kind","external");check(!linux_ordered_current_v1(selection,store),"external source accepted");json_object_set_string_member(p,"node_kind","router-vpn");
        }
        JsonObject*final=json_array_get_object_element(nodes,count-1);json_object_set_string_member(final,"id","foreign");check(!linux_ordered_rows_v1(nodes,"exit"),"foreign final accepted");json_object_set_string_member(final,"id","exit");
        json_object_set_string_member(final,"mode","wg");check(!linux_ordered_rows_v1(nodes,"exit"),"unsupported final accepted");json_object_set_string_member(final,"mode",final_mode);
        JsonObject*first=json_array_get_object_element(nodes,0);char*mode=g_strdup(obj_string(first,"mode"));json_object_set_string_member(first,"mode","wg-pq");check(!linux_ordered_rows_v1(nodes,"exit"),"unsupported prefix accepted");json_object_set_string_member(first,"mode",mode);g_free(mode);
        json_object_set_string_member(tokens,"unlinked","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");check(linux_ordered_selection_v1("exit",nodes,tokens)==NULL,"unlinked inventory accepted");json_object_remove_member(tokens,"unlinked");
        json_object_remove_member(tokens,"n0");check(linux_ordered_selection_v1("exit",nodes,tokens)==NULL,"missing original source accepted");check(linux_ordered_current_v1(selection,store),"mutable source map corrupted capture");
        json_object_set_string_member(store,"selected_id","n0");check(!linux_ordered_current_v1(selection,store),"changed selected exit accepted");
        linux_ordered_selection_free_v1(reopened);linux_ordered_selection_free_v1(selection);json_node_free(disk);json_object_unref(value);json_node_free(request);json_array_unref(nodes);json_object_unref(tokens);json_object_unref(store);g_free(raw);g_free(body);
    }
    printf("Shipping ordered source model/serialization/persistence: %u checks PASS.\n",checks);return 0;
}

static void connect_model_only(void) {
    const char *protocols[]={"http-connect","https-connect","openvpn","socks5","shadowsocks"}, *prefixes[]={"wg","awg2-fast","awg2-strong"};
    for(guint p=0;p<G_N_ELEMENTS(protocols);p++)for(guint prefix=0;prefix<G_N_ELEMENTS(prefixes);prefix++){
        for(guint count=3;count<=8;count++){
        guint middle_index=count-2;
        JsonArray *nodes=json_array_new(), *profiles=json_array_new();JsonObject *store=json_object_new(), *tokens=json_object_new();
        for(guint i=0;i<count;i++){
            char id_buffer[24];g_snprintf(id_buffer,sizeof(id_buffer),"prefix-%u",i);
            const char *id=i==middle_index?"middle":i==count-1?"exit":id_buffer;
            const char *mode=i==middle_index?protocols[p]:i==count-1?"shadowsocks":prefixes[(prefix+i)%G_N_ELEMENTS(prefixes)];
            JsonObject *row=json_object_new(), *profile=json_object_new();char *token=g_strdup_printf("%064x",i+1);
            json_object_set_string_member(row,"id",id);json_object_set_string_member(row,"mode",mode);json_array_add_object_element(nodes,row);
            json_object_set_string_member(profile,"id",id);json_object_set_string_member(profile,"node_kind",i==middle_index?"external":"router-vpn");json_object_set_string_member(profile,"profile_token",token);json_array_add_object_element(profiles,profile);
            json_object_set_string_member(tokens,id,token);g_free(token);
        }
        JsonObject *middle=json_array_get_object_element(profiles,middle_index), *external=json_object_new();
        json_object_set_string_member(external,"protocol",protocols[p]);json_object_set_boolean_member(external,"ordered_middle_supported",TRUE);json_object_set_string_member(external,"password","connect-model-secret");json_object_set_object_member(middle,"external",external);
        json_object_set_array_member(store,"profiles",profiles);json_object_set_string_member(store,"selected_id","exit");
        JsonNode *catalog_root=json_node_new(JSON_NODE_OBJECT);json_node_take_object(catalog_root,store);
        LinuxOrderedSelectionV1 *selection=linux_ordered_selection_v1("exit",nodes,tokens);
        check(selection&&linux_ordered_current_v1(selection,store),"CONNECT source model refused original typed graph");
        if(p<2) {
            json_object_set_boolean_member(external,"ordered_connect_execution_middle_supported",TRUE);
            const char *choices[]={"server","auto"};
            for(guint choice=0;choice<2;choice++) {
                gboolean allowed=linux_ordered_execution_v1(selection,choices[choice]);
                check(allowed,"CONNECT execution lost complete original prefixes");
                {
                    check(linux_ordered_current_v1(selection,store),"CONNECT execution lost original native hint");
                    check(strcmp(linux_ordered_execution_capability_v1(selection),"ordered_connect_trio_executions")==0,"CONNECT execution borrowed unrelated global capability");
                    json_object_set_boolean_member(external,"ordered_connect_execution_middle_supported",FALSE);
                    check(!linux_ordered_current_v1(selection,store),"CONNECT execution accepted false native hint");
                    json_object_set_boolean_member(external,"ordered_connect_execution_middle_supported",TRUE);
                    for(guint position=0;position<middle_index;position++) {
                        JsonObject *paired=json_array_get_object_element(profiles,position);
                        json_object_set_string_member(paired,"start_layer",position%2?"aes-256-gcm+xor-whitening":"aes-256-gcm");
                        check(linux_ordered_current_v1(selection,store),"CONNECT execution lost independent prefix layer");
                        json_object_set_string_member(paired,"start_layer","aes-256-gcm ");
                        check(!linux_ordered_current_v1(selection,store),"CONNECT execution accepted malformed prefix layer");
                        json_object_set_boolean_member(paired,"start_layer",TRUE);
                        check(!linux_ordered_current_v1(selection,store),"CONNECT execution accepted nonstring prefix layer");
                        json_object_set_string_member(paired,"start_layer","off");
                    }
                    JsonObject *final=json_array_get_object_element(profiles,count-1);
                    const char *final_layers[]={"aes-256-gcm","aes-256-gcm+xor-whitening"};
                    for(guint layer=0;layer<2;layer++) {
                        json_object_set_string_member(final,"start_layer",final_layers[layer]);
                        check(linux_ordered_current_v1(selection,store),"CONNECT execution refused captured final layer");
                        check(strcmp(linux_ordered_string_v1(final,"start_layer"),final_layers[layer])==0,"CONNECT execution replaced original final layer");
                    }
                    json_object_set_string_member(final,"start_layer","xor-only");
                    check(!linux_ordered_current_v1(selection,store),"CONNECT execution accepted malformed final layer");
                    json_object_set_boolean_member(final,"start_layer",TRUE);
                    check(!linux_ordered_current_v1(selection,store),"CONNECT execution accepted nonstring final layer");
                    json_object_set_string_member(final,"start_layer","off");
                }
                check(linux_ordered_execution_v1(selection,"local"),"CONNECT original Local choice lost");
            }
        }
        const char *titles[]={"HTTP CONNECT","HTTPS CONNECT","OpenVPN","SOCKS5","Shadowsocks 2022"};const char *title=titles[p];check(strcmp(linux_ordered_mode_name_v1(protocols[p]),title)==0,"CONNECT model concealed exact transport title");
        LinuxOrderedEditorV1 editor={.catalog=catalog_root,.control="exit",.modes=g_ptr_array_new_with_free_func(g_free)};
        for(guint i=0;i<middle_index;i++)g_ptr_array_add(editor.modes,g_strdup(prefixes[(prefix+i)%G_N_ELEMENTS(prefixes)]));g_ptr_array_add(editor.modes,g_strdup(protocols[p]));
        check(linux_ordered_editor_final_allowed_v1(&editor,"shadowsocks"),"CONNECT final chooser refused original paired final");
        check(!linux_ordered_editor_final_allowed_v1(&editor,"hysteria2"),"CONNECT final chooser admitted Hysteria2");
        char *body=linux_ordered_connect_body_v1(selection);JsonNode *request=parse_json(body);JsonObject *q=json_node_get_object(request);JsonArray *sent=linux_ordered_array_v1(q,"nodes");
        check(sent&&json_array_get_length(sent)==count&&strcmp(obj_string(q,"execution"),"local")==0,"CONNECT source model changed complete Local graph");
        for(guint i=0;i<count;i++)check(strcmp(obj_string(json_array_get_object_element(sent,i),"id"),obj_string(json_array_get_object_element(nodes,i),"id"))==0&&strcmp(obj_string(json_array_get_object_element(sent,i),"mode"),obj_string(json_array_get_object_element(nodes,i),"mode"))==0,"CONNECT source model changed original member reference");
        check(json_object_get_size(linux_ordered_object_v1(q,"expected_profile_tokens"))==count&&strstr(body,"connect-model-secret")==NULL,"CONNECT source model lost references or copied credentials");
        JsonObject *value=linux_ordered_value_v1(selection);char *raw=linux_ordered_json_v1(value);JsonNode *disk=parse_json(raw);LinuxOrderedSelectionV1 *reopened=linux_ordered_decode_v1(json_node_get_object(disk));
        check(reopened&&linux_ordered_current_v1(reopened,store),"CONNECT source model lost exact roundtrip");
        json_object_set_string_member(external,"protocol",protocols[(p+1)%G_N_ELEMENTS(protocols)]);check(!linux_ordered_current_v1(selection,store),"CONNECT selection borrowed a different saved protocol");json_object_set_string_member(external,"protocol",protocols[p]);
        json_object_set_boolean_member(external,"ordered_middle_supported",FALSE);check(!linux_ordered_current_v1(selection,store),"CONNECT source model accepted false capability");
        json_object_set_int_member(external,"ordered_middle_supported",1);check(!linux_ordered_current_v1(selection,store),"CONNECT source model accepted numeric capability");
        json_object_set_string_member(external,"ordered_middle_supported","true");check(!linux_ordered_current_v1(selection,store),"CONNECT source model accepted string capability");
        json_object_remove_member(external,"ordered_middle_supported");check(!linux_ordered_current_v1(selection,store),"CONNECT source model accepted absent capability");json_object_set_boolean_member(external,"ordered_middle_supported",TRUE);
        char *token=g_strdup(obj_string(middle,"profile_token"));json_object_set_string_member(middle,"profile_token","eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");check(!linux_ordered_current_v1(selection,store),"CONNECT source model borrowed relinked source");json_object_set_string_member(middle,"profile_token",token);g_free(token);
        JsonObject *first=json_array_get_object_element(nodes,0), *last=json_array_get_object_element(nodes,count-1);
        json_object_set_string_member(first,"mode",protocols[p]);check(!linux_ordered_rows_v1(nodes,"exit"),"CONNECT source model granted physical entry");json_object_set_string_member(first,"mode",prefixes[prefix]);
        json_object_set_string_member(last,"mode","hysteria2");check(!linux_ordered_rows_v1(nodes,"exit"),"CONNECT source model granted unsupported final");json_object_set_string_member(last,"mode","shadowsocks");
        if(count>3){
            JsonObject *typed=json_array_get_object_element(nodes,middle_index);
            const char *unsupported[]={"naive-h2","shadowsocks ","SS2022"};
            for(guint j=0;j<G_N_ELEMENTS(unsupported);j++){
                json_object_set_string_member(typed,"mode",unsupported[j]);
                check(!linux_ordered_rows_v1(nodes,"exit"),"imported path accepted unsupported or normalized transport");
            }
            json_object_set_string_member(typed,"mode",protocols[p]);
        }
        g_ptr_array_unref(editor.modes);linux_ordered_selection_free_v1(reopened);linux_ordered_selection_free_v1(selection);json_node_free(disk);json_object_unref(value);json_node_free(request);json_array_unref(nodes);json_object_unref(tokens);json_node_free(catalog_root);g_free(raw);g_free(body);
    }
    }
    printf("Shipping ordered source model including CONNECT: %u checks PASS.\n",checks);
}

static void socks_execution_model(LinuxUnifiedV8 *state) {
    const char *prefixes[]={"wg","awg2-fast","awg2-strong"}, *choices[]={"server","auto"}, *layers[]={"off","aes-256-gcm","aes-256-gcm+xor-whitening"};
    for(guint count=3;count<=8;count++)for(guint p=0;p<G_N_ELEMENTS(prefixes);p++)for(guint e=0;e<G_N_ELEMENTS(choices);e++)for(guint l=0;l<G_N_ELEMENTS(layers);l++) {
        JsonNode *root=parse_json("{\"selected_id\":\"exit\",\"profiles\":[{\"id\":\"entry\",\"node_kind\":\"router-vpn\"},{\"id\":\"middle\",\"node_kind\":\"external\",\"external\":{\"protocol\":\"socks5\",\"ordered_middle_supported\":true,\"ordered_socks_execution_middle_supported\":true,\"password\":\"socks-private-secret\"}},{\"id\":\"exit\",\"node_kind\":\"router-vpn\"}]}");
        JsonObject *store=json_node_get_object(root), *tokens=json_object_new();JsonArray *catalog_profiles=json_object_get_array_member(store,"profiles"), *nodes=json_array_new(), *source_profiles=json_array_new();
        guint middle=count-2;
        json_array_add_object_element(source_profiles,json_object_ref(json_array_get_object_element(catalog_profiles,0)));
        for(guint i=1;i<middle;i++){
            JsonObject *profile=json_object_new();char *id=g_strdup_printf("paired-%u",i);
            json_object_set_string_member(profile,"id",id);g_free(id);json_object_set_string_member(profile,"node_kind","router-vpn");
            json_array_add_object_element(catalog_profiles,profile);json_array_add_object_element(source_profiles,json_object_ref(profile));
        }
        json_array_add_object_element(source_profiles,json_object_ref(json_array_get_object_element(catalog_profiles,1)));
        json_array_add_object_element(source_profiles,json_object_ref(json_array_get_object_element(catalog_profiles,2)));
        for(guint i=0;i<count;i++){
            JsonObject *profile=json_array_get_object_element(source_profiles,i), *row=json_object_new();const char *id=obj_string(profile,"id");char *token=g_strdup_printf("%064x",i+1);
            json_object_set_string_member(profile,"profile_token",token);json_object_set_string_member(tokens,id,token);g_free(token);
            json_object_set_string_member(profile,"start_layer",i<middle?layers[l]:"off");
            json_object_set_string_member(row,"id",id);json_object_set_string_member(row,"mode",i<middle?prefixes[p]:i==middle?"socks5":"shadowsocks");json_array_add_object_element(nodes,row);
        }
        LinuxOrderedSelectionV1 *selection=linux_ordered_selection_v1("exit",nodes,tokens);
        check(selection&&linux_ordered_execution_v1(selection,choices[e])&&linux_ordered_current_v1(selection,store),"SOCKS execution lost original typed trio");
        check(strcmp(linux_ordered_execution_capability_v1(selection),"ordered_socks_trio_executions")==0,"SOCKS execution borrowed unrelated global capability");
        for(guint f=1;f<G_N_ELEMENTS(layers);f++){
            JsonObject *paired_final=json_array_get_object_element(source_profiles,count-1);
            json_object_set_string_member(paired_final,"start_layer",layers[f]);
            check(linux_ordered_current_v1(selection,store),"SOCKS execution refused captured final layer");
            char *layered=linux_ordered_connect_body_v1(selection);check(layered!=NULL,"SOCKS layered execution lost request");g_free(layered);
            json_object_set_string_member(paired_final,"start_layer","off");
        }

        char *body=linux_ordered_connect_body_v1(selection);JsonNode *request=parse_json(body);JsonObject *posted=json_node_get_object(request);
        check(strcmp(obj_string(posted,"execution"),choices[e])==0&&json_object_get_size(linux_ordered_object_v1(posted,"expected_profile_tokens"))==count&&strstr(body,"socks-private-secret")==NULL,"SOCKS execution copied credentials or lost original sources");json_node_free(request);g_free(body);
        JsonObject *external=linux_ordered_object_v1(json_array_get_object_element(source_profiles,middle),"external");
        json_object_set_boolean_member(external,"ordered_socks_execution_middle_supported",FALSE);check(!linux_ordered_current_v1(selection,store),"SOCKS execution accepted false native hint");
        json_object_set_int_member(external,"ordered_socks_execution_middle_supported",1);check(!linux_ordered_current_v1(selection,store),"SOCKS execution accepted numeric native hint");
        json_object_set_string_member(external,"ordered_socks_execution_middle_supported","true");check(!linux_ordered_current_v1(selection,store),"SOCKS execution accepted string native hint");
        json_object_set_null_member(external,"ordered_socks_execution_middle_supported");check(!linux_ordered_current_v1(selection,store),"SOCKS execution accepted null native hint");
        json_object_remove_member(external,"ordered_socks_execution_middle_supported");
        json_object_set_boolean_member(external,"ordered_execution_middle_supported",TRUE);json_object_set_boolean_member(external,"ordered_connect_execution_middle_supported",TRUE);
        check(!linux_ordered_current_v1(selection,store),"SOCKS execution borrowed unrelated source hint");
        json_object_set_boolean_member(external,"ordered_socks_execution_middle_supported",TRUE);
        JsonObject *entry=json_array_get_object_element(source_profiles,0);
        json_object_set_string_member(entry,"start_layer","aes-256-gcm ");check(!linux_ordered_current_v1(selection,store),"SOCKS execution accepted malformed entry layer");
        json_object_set_boolean_member(entry,"start_layer",TRUE);check(!linux_ordered_current_v1(selection,store),"SOCKS execution accepted nonstring entry layer");
        json_object_set_string_member(entry,"start_layer",layers[l]);
        for(guint i=1;i<middle;i++){
            JsonObject *profile=json_array_get_object_element(source_profiles,i);
            json_object_set_string_member(profile,"start_layer","unsupported");check(!linux_ordered_current_v1(selection,store),"SOCKS execution admitted malformed later prefix layer");
            json_object_set_string_member(profile,"start_layer",layers[l]);
        }
        for(guint i=middle;i<count;i++){
            JsonObject *profile=json_array_get_object_element(source_profiles,i);
            json_object_set_string_member(profile,"start_layer",i==middle?"aes-256-gcm":"AES-256-GCM");check(!linux_ordered_current_v1(selection,store),"SOCKS execution admitted layered middle or final");
            json_object_set_boolean_member(profile,"start_layer",TRUE);check(!linux_ordered_current_v1(selection,store),"SOCKS execution admitted nonstring middle or final layer");
            json_object_set_string_member(profile,"start_layer","off");
        }
        for(guint i=0;i<count;i++){
            JsonObject *profile=json_array_get_object_element(source_profiles,i);char *token=g_strdup(obj_string(profile,"profile_token"));
            json_object_set_string_member(profile,"profile_token","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");check(!linux_ordered_current_v1(selection,store),"SOCKS execution borrowed relinked source");json_object_set_string_member(profile,"profile_token",token);g_free(token);
        }
        if(count==8){
        JsonArray *long_nodes=json_array_new();JsonObject *extra=json_object_new(), *long_tokens=json_object_new();
        json_object_set_string_member(extra,"id","extra");json_object_set_string_member(extra,"mode","wg");json_array_add_object_element(long_nodes,extra);
        json_object_set_string_member(long_tokens,"extra","dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
        for(guint i=0;i<count;i++){JsonObject *row=json_array_get_object_element(nodes,i);const char *id=obj_string(row,"id");json_array_add_object_element(long_nodes,json_object_ref(row));json_object_set_string_member(long_tokens,id,obj_string(tokens,id));}
        LinuxOrderedSelectionV1 *long_selection=linux_ordered_selection_v1("exit",long_nodes,long_tokens);
        check(long_selection==NULL,"SOCKS execution escaped maximum path length");linux_ordered_selection_free_v1(long_selection);json_array_unref(long_nodes);json_object_unref(long_tokens);
        }
        if(state!=NULL){
            JsonNode *original_catalog=catalog;catalog=json_node_copy(root);
            refresh_all(state->app);
            LinuxOrderedStateV1 *owned=linux_ordered_state_v1(state);LinuxOrderedSelectionV1 *captured=linux_ordered_selection_v1("exit",selection->nodes,selection->tokens);
            check(captured&&linux_ordered_execution_v1(captured,choices[e])&&linux_ordered_store_v1(owned,captured,TRUE),"SOCKS execution callback capture failed");
            guint before=posts;linux_profile_connect_v11(NULL,state);check(posts==before+1,"SOCKS execution callback lost distinct native capability");
            JsonNode *sent=parse_json(last_body);JsonObject *value=json_node_get_object(sent);
            check(strcmp(obj_string(value,"execution"),choices[e])==0&&json_array_get_length(linux_ordered_array_v1(value,"nodes"))==count&&json_object_get_size(linux_ordered_object_v1(value,"expected_profile_tokens"))==count,"SOCKS callback replaced execution or original source inventory");json_node_free(sent);
            socks_capability=FALSE;before=posts;linux_profile_connect_v11(NULL,state);check(posts==before,"SOCKS execution callback borrowed unrelated global capability");socks_capability=TRUE;
            char *before_profiles=snapshot();profiles(0);check(posts==before,"SOCKS profile save or update connected implicitly");linux_ordered_store_v1(owned,NULL,FALSE);profiles(1);char *after_profiles=snapshot();
            check(strcmp(before_profiles,after_profiles)==0,"SOCKS Add Load Update replaced original selection");g_free(before_profiles);g_free(after_profiles);
            check(strcmp(obj_string(external_source_profile_v24(json_node_get_object(catalog),"entry"),"start_layer"),layers[l])==0,"SOCKS complete profiles replaced original entry layer");
            json_node_free(catalog);catalog=original_catalog;refresh_all(state->app);check(linux_ordered_store_v1(owned,NULL,FALSE),"SOCKS callback failed to retire its selection");
        }
        linux_ordered_selection_free_v1(selection);json_array_unref(source_profiles);json_array_unref(nodes);json_object_unref(tokens);json_node_free(root);
    }
}

static void openvpn_execution_model(LinuxUnifiedV8 *state) {
    const char *prefixes[]={"wg","awg2-fast","awg2-strong"}, *choices[]={"server","auto"}, *layers[]={"off","aes-256-gcm","aes-256-gcm+xor-whitening"};
    for(guint count=3;count<=8;count++)for(guint p=0;p<G_N_ELEMENTS(prefixes);p++)for(guint e=0;e<G_N_ELEMENTS(choices);e++)for(guint l=0;l<G_N_ELEMENTS(layers);l++) {
        JsonNode *root=parse_json("{\"selected_id\":\"exit\",\"profiles\":[{\"id\":\"entry\",\"node_kind\":\"router-vpn\"},{\"id\":\"middle\",\"node_kind\":\"external\",\"external\":{\"protocol\":\"openvpn\",\"ordered_middle_supported\":true,\"ordered_openvpn_execution_middle_supported\":true,\"password\":\"openvpn-private-secret\"}},{\"id\":\"exit\",\"node_kind\":\"router-vpn\"}]}");
        JsonObject *store=json_node_get_object(root), *tokens=json_object_new();JsonArray *catalog_profiles=json_object_get_array_member(store,"profiles"), *nodes=json_array_new(), *source_profiles=json_array_new();
        guint middle=count-2;
        json_array_add_object_element(source_profiles,json_object_ref(json_array_get_object_element(catalog_profiles,0)));
        for(guint i=1;i<middle;i++){
            JsonObject *profile=json_object_new();char *id=g_strdup_printf("paired-%u",i);
            json_object_set_string_member(profile,"id",id);g_free(id);json_object_set_string_member(profile,"node_kind","router-vpn");
            json_array_add_object_element(catalog_profiles,profile);json_array_add_object_element(source_profiles,json_object_ref(profile));
        }
        json_array_add_object_element(source_profiles,json_object_ref(json_array_get_object_element(catalog_profiles,1)));
        json_array_add_object_element(source_profiles,json_object_ref(json_array_get_object_element(catalog_profiles,2)));
        for(guint i=0;i<count;i++){
            JsonObject *profile=json_array_get_object_element(source_profiles,i), *row=json_object_new();const char *id=obj_string(profile,"id");char *token=g_strdup_printf("%064x",i+1);
            json_object_set_string_member(profile,"profile_token",token);json_object_set_string_member(tokens,id,token);g_free(token);
            json_object_set_string_member(profile,"start_layer",i<middle?layers[l]:"off");
            json_object_set_string_member(row,"id",id);json_object_set_string_member(row,"mode",i<middle?prefixes[p]:i==middle?"openvpn":"shadowsocks");json_array_add_object_element(nodes,row);
        }
        LinuxOrderedSelectionV1 *selection=linux_ordered_selection_v1("exit",nodes,tokens);
        check(selection&&linux_ordered_execution_v1(selection,choices[e])&&linux_ordered_current_v1(selection,store),"OpenVPN execution lost original typed trio");
        check(strcmp(linux_ordered_execution_capability_v1(selection),"ordered_openvpn_executions")==0,"OpenVPN execution borrowed unrelated global capability");
        for(guint f=1;f<G_N_ELEMENTS(layers);f++){
            JsonObject *paired_final=json_array_get_object_element(source_profiles,count-1);
            json_object_set_string_member(paired_final,"start_layer",layers[f]);
            check(linux_ordered_current_v1(selection,store),"OpenVPN execution refused captured final layer");
            char *layered=linux_ordered_connect_body_v1(selection);check(layered!=NULL,"OpenVPN layered execution lost request");g_free(layered);
            json_object_set_string_member(paired_final,"start_layer","off");
        }

        char *body=linux_ordered_connect_body_v1(selection);JsonNode *request=parse_json(body);JsonObject *posted=json_node_get_object(request);
        check(strcmp(obj_string(posted,"execution"),choices[e])==0&&json_object_get_size(linux_ordered_object_v1(posted,"expected_profile_tokens"))==count&&strstr(body,"openvpn-private-secret")==NULL,"OpenVPN execution copied credentials or lost original sources");json_node_free(request);g_free(body);
        JsonObject *external=linux_ordered_object_v1(json_array_get_object_element(source_profiles,middle),"external");
        json_object_set_boolean_member(external,"ordered_openvpn_execution_middle_supported",FALSE);check(!linux_ordered_current_v1(selection,store),"OpenVPN execution accepted false native hint");
        json_object_set_int_member(external,"ordered_openvpn_execution_middle_supported",1);check(!linux_ordered_current_v1(selection,store),"OpenVPN execution accepted numeric native hint");
        json_object_set_string_member(external,"ordered_openvpn_execution_middle_supported","true");check(!linux_ordered_current_v1(selection,store),"OpenVPN execution accepted string native hint");
        json_object_set_null_member(external,"ordered_openvpn_execution_middle_supported");check(!linux_ordered_current_v1(selection,store),"OpenVPN execution accepted null native hint");
        json_object_remove_member(external,"ordered_openvpn_execution_middle_supported");
        json_object_set_boolean_member(external,"ordered_execution_middle_supported",TRUE);json_object_set_boolean_member(external,"ordered_connect_execution_middle_supported",TRUE);
        check(!linux_ordered_current_v1(selection,store),"OpenVPN execution borrowed unrelated source hint");
        json_object_set_boolean_member(external,"ordered_openvpn_execution_middle_supported",TRUE);
        JsonObject *entry=json_array_get_object_element(source_profiles,0);
        json_object_set_string_member(entry,"start_layer","aes-256-gcm ");check(!linux_ordered_current_v1(selection,store),"OpenVPN execution accepted malformed entry layer");
        json_object_set_boolean_member(entry,"start_layer",TRUE);check(!linux_ordered_current_v1(selection,store),"OpenVPN execution accepted nonstring entry layer");
        json_object_set_string_member(entry,"start_layer",layers[l]);
        for(guint i=1;i<middle;i++){
            JsonObject *profile=json_array_get_object_element(source_profiles,i);
            json_object_set_string_member(profile,"start_layer","unsupported");check(!linux_ordered_current_v1(selection,store),"OpenVPN execution admitted malformed later prefix layer");
            json_object_set_string_member(profile,"start_layer",layers[l]);
        }
        for(guint i=middle;i<count;i++){
            JsonObject *profile=json_array_get_object_element(source_profiles,i);
            json_object_set_string_member(profile,"start_layer",i==middle?"aes-256-gcm":"AES-256-GCM");check(!linux_ordered_current_v1(selection,store),"OpenVPN execution admitted layered middle or final");
            json_object_set_boolean_member(profile,"start_layer",TRUE);check(!linux_ordered_current_v1(selection,store),"OpenVPN execution admitted nonstring middle or final layer");
            json_object_set_string_member(profile,"start_layer","off");
        }
        for(guint i=0;i<count;i++){
            JsonObject *profile=json_array_get_object_element(source_profiles,i);char *token=g_strdup(obj_string(profile,"profile_token"));
            json_object_set_string_member(profile,"profile_token","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");check(!linux_ordered_current_v1(selection,store),"OpenVPN execution borrowed relinked source");json_object_set_string_member(profile,"profile_token",token);g_free(token);
        }
        if(count==8){
        JsonArray *long_nodes=json_array_new();JsonObject *extra=json_object_new(), *long_tokens=json_object_new();
        json_object_set_string_member(extra,"id","extra");json_object_set_string_member(extra,"mode","wg");json_array_add_object_element(long_nodes,extra);
        json_object_set_string_member(long_tokens,"extra","dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
        for(guint i=0;i<count;i++){JsonObject *row=json_array_get_object_element(nodes,i);const char *id=obj_string(row,"id");json_array_add_object_element(long_nodes,json_object_ref(row));json_object_set_string_member(long_tokens,id,obj_string(tokens,id));}
        LinuxOrderedSelectionV1 *long_selection=linux_ordered_selection_v1("exit",long_nodes,long_tokens);
        check(long_selection==NULL,"OpenVPN execution escaped maximum path length");linux_ordered_selection_free_v1(long_selection);json_array_unref(long_nodes);json_object_unref(long_tokens);
        }
        if(state!=NULL){
            JsonNode *original_catalog=catalog;catalog=json_node_copy(root);
            refresh_all(state->app);
            LinuxOrderedStateV1 *owned=linux_ordered_state_v1(state);LinuxOrderedSelectionV1 *captured=linux_ordered_selection_v1("exit",selection->nodes,selection->tokens);
            check(captured&&linux_ordered_execution_v1(captured,choices[e])&&linux_ordered_store_v1(owned,captured,TRUE),"OpenVPN execution callback capture failed");
            guint before=posts;linux_profile_connect_v11(NULL,state);check(posts==before+1,"OpenVPN execution callback lost distinct native capability");
            JsonNode *sent=parse_json(last_body);JsonObject *value=json_node_get_object(sent);
            check(strcmp(obj_string(value,"execution"),choices[e])==0&&json_array_get_length(linux_ordered_array_v1(value,"nodes"))==count&&json_object_get_size(linux_ordered_object_v1(value,"expected_profile_tokens"))==count,"OpenVPN callback replaced execution or original source inventory");json_node_free(sent);
            openvpn_capability=FALSE;before=posts;linux_profile_connect_v11(NULL,state);check(posts==before,"OpenVPN execution callback borrowed unrelated global capability");openvpn_capability=TRUE;
            char *before_profiles=snapshot();profiles(0);check(posts==before,"OpenVPN profile save or update connected implicitly");linux_ordered_store_v1(owned,NULL,FALSE);profiles(1);char *after_profiles=snapshot();
            check(strcmp(before_profiles,after_profiles)==0,"OpenVPN Add Load Update replaced original selection");g_free(before_profiles);g_free(after_profiles);
            check(strcmp(obj_string(external_source_profile_v24(json_node_get_object(catalog),"entry"),"start_layer"),layers[l])==0,"OpenVPN complete profiles replaced original entry layer");
            json_node_free(catalog);catalog=original_catalog;refresh_all(state->app);check(linux_ordered_store_v1(owned,NULL,FALSE),"OpenVPN callback failed to retire its selection");
        }
        linux_ordered_selection_free_v1(selection);json_array_unref(source_profiles);json_array_unref(nodes);json_object_unref(tokens);json_node_free(root);
    }
}

static void imported_execution_model(LinuxUnifiedV8 *state) {
    const char *executions[]={"server","auto"};
    const guint counts[]={3,4,8};
    for(guint c=0;c<G_N_ELEMENTS(counts);c++){guint count=counts[c];for(guint e=0;e<G_N_ELEMENTS(executions);e++){
        JsonNode *root=parse_json("{\"selected_id\":\"exit\",\"profiles\":[{\"id\":\"entry\",\"node_kind\":\"router-vpn\"},{\"id\":\"middle\",\"node_kind\":\"external\",\"external\":{\"protocol\":\"shadowsocks\",\"ordered_middle_supported\":true,\"ordered_execution_middle_supported\":true}},{\"id\":\"exit\",\"node_kind\":\"router-vpn\"}]}");
        JsonObject *store=json_node_get_object(root),*tokens=json_object_new();JsonArray *profiles=json_object_get_array_member(store,"profiles"),*nodes=json_array_new();
        for(guint i=0;i<count-3;i++) {
            JsonObject *p=json_object_new();char *id=g_strdup_printf("prefix-%u",i);
            json_object_set_string_member(p,"id",id);g_free(id);json_object_set_string_member(p,"node_kind","router-vpn");
            json_array_add_object_element(profiles,p);
        }
        // Keep catalog order independent: rows retain every prefix then middle/final.
        JsonArray *ordered=json_array_new();json_array_add_object_element(ordered,json_object_ref(json_array_get_object_element(profiles,0)));
        for(guint i=3;i<count;i++)json_array_add_object_element(ordered,json_object_ref(json_array_get_object_element(profiles,i)));
        json_array_add_object_element(ordered,json_object_ref(json_array_get_object_element(profiles,1)));
        json_array_add_object_element(ordered,json_object_ref(json_array_get_object_element(profiles,2)));
        for(guint i=0;i<count;i++){
            JsonObject *profile=json_array_get_object_element(ordered,i),*row=json_object_new();const char *id=obj_string(profile,"id");char *token=g_strdup_printf("%064x",i+1);
            json_object_set_string_member(profile,"profile_token",token);json_object_set_string_member(tokens,id,token);g_free(token);
            json_object_set_string_member(row,"id",id);json_object_set_string_member(row,"mode",i<count-2?(i%2?"awg2-strong":"wg"):"shadowsocks");json_array_add_object_element(nodes,row);
        }
        LinuxOrderedSelectionV1 *selection=linux_ordered_selection_v1("exit",nodes,tokens);
        check(selection&&linux_ordered_execution_v1(selection,executions[e])&&linux_ordered_current_v1(selection,store),"literal imported execution lost original trio or purpose");
        if(state != NULL) {
            JsonNode *original_catalog=catalog;catalog=json_node_copy(root);
            LinuxOrderedStateV1 *owned=linux_ordered_state_v1(state);
            LinuxOrderedSelectionV1 *captured=linux_ordered_selection_v1("exit",selection->nodes,selection->tokens);
            check(captured&&linux_ordered_execution_v1(captured,executions[e])&&linux_ordered_store_v1(owned,captured,TRUE),"complete imported callback capture failed");
            guint before=posts;linux_profile_connect_v11(NULL,state);
            check(posts==before+1,"complete imported callback did not connect");
            JsonNode *request=parse_json(last_body);JsonObject *body=json_node_get_object(request);
            check(strcmp(obj_string(body,"execution"),executions[e])==0&&json_array_get_length(linux_ordered_array_v1(body,"nodes"))==count&&json_object_get_size(linux_ordered_object_v1(body,"expected_profile_tokens"))==count,"complete imported callback lost choice or original inventory");
            check(strcmp(obj_string(json_array_get_object_element(linux_ordered_array_v1(body,"nodes"),count-2),"id"),"middle")==0,"complete imported callback changed penultimate");json_node_free(request);
            JsonObject *live_middle=external_source_profile_v24(json_node_get_object(catalog),"middle");
            json_object_set_boolean_member(linux_ordered_object_v1(live_middle,"external"),"ordered_execution_middle_supported",FALSE);
            before=posts;linux_profile_connect_v11(NULL,state);check(posts==before,"complete imported callback ignored original capability");
            json_node_free(catalog);catalog=original_catalog;
            check(linux_ordered_store_v1(owned,NULL,FALSE),"complete imported callback fixture did not retire its selection");
        }
        JsonObject *external=json_object_get_object_member(json_array_get_object_element(profiles,1),"external");
        json_object_set_boolean_member(external,"ordered_execution_middle_supported",FALSE);check(!linux_ordered_current_v1(selection,store),"imported execution accepted false native capability");
        json_object_set_int_member(external,"ordered_execution_middle_supported",1);check(!linux_ordered_current_v1(selection,store),"imported execution accepted numeric native capability");
        json_object_remove_member(external,"ordered_execution_middle_supported");check(!linux_ordered_current_v1(selection,store),"imported execution accepted absent native capability");
        json_object_set_boolean_member(external,"ordered_execution_middle_supported",TRUE);
        json_object_set_boolean_member(external,"ordered_execution_middle_supported",FALSE);
        json_object_set_boolean_member(external,"ordered_hostname_execution_middle_supported",TRUE);
        check(linux_ordered_current_v1(selection,store)==(count>=4),"hostname execution lost bounded saved prefix");
        if(count>=4) {
            json_object_set_int_member(external,"ordered_hostname_execution_middle_supported",1);check(!linux_ordered_current_v1(selection,store),"hostname execution accepted numeric capability");
            json_object_remove_member(external,"ordered_hostname_execution_middle_supported");check(!linux_ordered_current_v1(selection,store),"hostname execution accepted absent capability");
            json_object_set_boolean_member(external,"ordered_hostname_execution_middle_supported",TRUE);
            json_object_set_boolean_member(external,"ordered_execution_middle_supported",TRUE);check(!linux_ordered_current_v1(selection,store),"hostname execution accepted conflicting capabilities");
            json_object_set_boolean_member(external,"ordered_execution_middle_supported",FALSE);
            if(state!=NULL) {
                JsonNode *previous=catalog;catalog=json_node_copy(root);LinuxOrderedStateV1 *owned=linux_ordered_state_v1(state);
                LinuxOrderedSelectionV1 *captured=linux_ordered_selection_v1("exit",selection->nodes,selection->tokens);
                check(captured&&linux_ordered_execution_v1(captured,executions[e])&&linux_ordered_store_v1(owned,captured,TRUE),"hostname callback capture failed");
                guint before=posts;linux_profile_connect_v11(NULL,state);check(posts==before+1,"hostname callback omitted original Connect");
                JsonNode *request=parse_json(last_body);JsonObject *body=json_node_get_object(request);
                check(json_array_get_length(linux_ordered_array_v1(body,"nodes"))==count&&strcmp(obj_string(body,"execution"),executions[e])==0&&json_object_get_size(linux_ordered_object_v1(body,"expected_profile_tokens"))==count,"hostname callback lost original source inventory");json_node_free(request);
                JsonObject *live=external_source_profile_v24(json_node_get_object(catalog),"middle");json_object_set_boolean_member(linux_ordered_object_v1(live,"external"),"ordered_hostname_execution_middle_supported",FALSE);
                before=posts;linux_profile_connect_v11(NULL,state);check(posts==before,"hostname callback ignored changed capability");
                json_node_free(catalog);catalog=previous;check(linux_ordered_store_v1(owned,NULL,FALSE),"hostname callback fixture failed retirement");
            }
        }
        json_object_remove_member(external,"ordered_hostname_execution_middle_supported");
        json_object_set_boolean_member(external,"ordered_execution_middle_supported",TRUE);
        JsonObject *middle=json_array_get_object_element(profiles,1);json_object_set_string_member(middle,"profile_token","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");check(!linux_ordered_current_v1(selection,store),"imported execution borrowed changed original source token");
        linux_ordered_selection_free_v1(selection);json_array_unref(ordered);json_array_unref(nodes);json_object_unref(tokens);json_node_free(root);
    }}
}

int main(int argc,char **argv) {
    keypath=g_build_filename(argv[1],"ordered-settings.ini",NULL);g_remove(keypath);
    model_only();
    connect_model_only();
    imported_execution_model(NULL);
    socks_execution_model(NULL);
    openvpn_execution_model(NULL);
    if(argc==3&&strcmp(argv[2],"--model-only")==0){puts("GTK callbacks require a display and were not executed.");return 0;}
    check(gtk_init_check(&argc,&argv),"real GTK display");
    App app={gtk_window_new(GTK_WINDOW_TOPLEVEL)};LinuxUnifiedV8 state={.app=&app,.node=gtk_combo_box_text_new(),.mode=gtk_combo_box_text_new(),.multihop=gtk_check_button_new()};unified=&state;
    JsonObject*o=json_object_new();JsonArray*rows=json_array_new();json_object_set_string_member(o,"selected_id","exit");
    for(int i=0;i<=8;i++){char*id=i?g_strdup_printf("n%d",i):g_strdup("exit");char*token=g_strdup_printf("%064x",i+1);JsonObject*p=json_object_new();json_object_set_string_member(p,"id",id);json_object_set_string_member(p,"name",id);json_object_set_string_member(p,"profile_token",token);json_object_set_string_member(p,"node_kind","router-vpn");json_array_add_object_element(rows,p);gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.node),id,id);g_free(id);g_free(token);}
    json_object_set_array_member(o,"profiles",rows);catalog=json_node_new(JSON_NODE_OBJECT);json_node_take_object(catalog,o);refresh_all(&app);choose(state.node,"exit");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.mode),"smart-auto","SMART AUTO");choose(state.mode,"smart-auto");
    imported_execution_model(&state);
    socks_execution_model(&state);
    openvpn_execution_model(&state);
    edit(0,TRUE);LinuxOrderedStateV1*owned=linux_ordered_state_v1(&state);check(owned->selection!=NULL,"Apply lost original path");char*original=snapshot();
    check(strstr(original,"awg2-fast")&&strstr(original,"awg2-strong"),"mixed modes not retained");
    edit(1,FALSE);char*after=snapshot();check(strcmp(original,after)==0,"cancel modified retained path");g_free(after);
    edit(2,FALSE);after=snapshot();check(strcmp(original,after)==0,"late choice applied");g_free(after);
    edit(3,FALSE);after=snapshot();check(strcmp(original,after)==0,"replaced added source applied");g_free(after);
    edit(4,TRUE);after=snapshot();check(strcmp(original,after)==0,"cancel of long graph changed retained path");g_free(after);
    guint before=posts;linux_profile_connect_v11(NULL,&state);check(posts==before+1,"original graph did not connect");
    JsonNode*request=parse_json(last_body);JsonObject*q=json_node_get_object(request);check(json_object_get_size(q)==4&&strcmp(obj_string(q,"execution"),"local")==0,"Connect used legacy or unsupported fields");check(json_object_get_size(linux_ordered_object_v1(q,"expected_profile_tokens"))==3,"original source inventory missing");json_node_free(request);
    capability=FALSE;before=posts;linux_profile_connect_v11(NULL,&state);check(posts==before,"unavailable native capability connected");capability=TRUE;
    JsonObject*middle=external_source_profile_v24(json_node_get_object(catalog),"n1");char*token=g_strdup(obj_string(middle,"profile_token"));json_object_set_string_member(middle,"profile_token","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");linux_profile_connect_v11(NULL,&state);check(posts==before,"replaced middle source connected");json_object_set_string_member(middle,"profile_token",token);g_free(token);
    busy=TRUE;guint delegated=delegates;linux_profile_connect_v11(NULL,&state);check(posts==before&&delegates==delegated+1,"pending Connect did not delegate owned Disconnect");busy=FALSE;
    late_read=TRUE;linux_profile_connect_v11(NULL,&state);check(posts==before,"late Connect selection posted");
    JsonNode*invalid=parse_json(original);JsonObject*value=json_node_get_object(invalid);JsonArray*nodes=linux_ordered_array_v1(value,"nodes");json_object_set_string_member(json_array_get_object_element(nodes,2),"id","n8");check(!linux_ordered_rows_v1(nodes,"exit"),"foreign final accepted");json_node_free(invalid);
    refresh_all(&app);profiles(0);check(writes==2,"ordered Add/Update not executed");after=snapshot();check(strcmp(original,after)==0,"saved response changed complete path");g_free(after);
    request=parse_json(last_body);q=json_node_get_object(request);check(json_array_get_length(linux_ordered_array_v1(q,"multihop_nodes"))==3&&strcmp(obj_string(q,"mode"),"shadowsocks")==0&&!json_object_has_member(q,"multihop_entry_id"),"save truncated ordered graph");json_node_free(request);
    linux_ordered_store_v1(owned,NULL,FALSE);profiles(1);after=snapshot();check(strcmp(original,after)==0,"Load replaced original order/modes/tokens");g_free(after);
    guint64 generation=owned->generation;profiles(2);check(owned->generation>generation,"fixture late choice not delivered");after=snapshot();check(strcmp(original,after)==0,"late response overwrote original choice");g_free(after);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(state.multihop),FALSE);profiles(4);request=parse_json(last_body);check(!linux_ordered_flag_v1(json_node_get_object(request),"multihop_enabled")&&!json_object_has_member(json_node_get_object(request),"multihop_nodes"),"Off saved an ordered graph");json_node_free(request);after=snapshot();check(strcmp(original,after)==0,"Off destroyed remembered ordered draft");g_free(after);gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(state.multihop),TRUE);
    guint before_close=writes;profiles(5);check(writes==before_close,"destroyed profile dialog issued a write");
    bad_reply=TRUE;profiles(3);before=posts;linux_profile_connect_v11(NULL,&state);check(owned->invalid&&posts==before,"incomplete loaded receipt fell back to a pair");bad_reply=FALSE;
    GKeyFile*key=linux_unified_load_keyfile_v8();char*raw=g_key_file_get_string(key,"connection-profile-selection","ordered_selection",NULL);check(raw&&strcmp(raw,original)==0,"disk save lost original public inventory");g_free(raw);g_key_file_unref(key);
    JsonObject *custom=external_source_profile_v24(json_node_get_object(catalog),"n2"), *external=json_object_new();
    json_object_set_string_member(custom,"node_kind","external");json_object_set_string_member(external,"protocol","shadowsocks");json_object_set_boolean_member(external,"ordered_middle_supported",TRUE);json_object_set_object_member(custom,"external",external);
    refresh_all(&app);edit(6,TRUE);check(owned->selection!=NULL&&linux_ordered_current_v1(owned->selection,json_node_get_object(catalog)),"custom editor Apply lost original source");
    before=posts;linux_profile_connect_v11(NULL,&state);check(posts==before+1,"custom editor did not reach shipping Connect");
    request=parse_json(last_body);q=json_node_get_object(request);check(strcmp(obj_string(json_array_get_object_element(linux_ordered_array_v1(q,"nodes"),1),"mode"),"shadowsocks")==0,"custom Connect invented paired transport");json_node_free(request);
    json_object_set_boolean_member(external,"ordered_middle_supported",FALSE);before=posts;linux_profile_connect_v11(NULL,&state);check(posts==before,"unsupported custom source retained Connect authority");json_object_set_boolean_member(external,"ordered_middle_supported",TRUE);
    json_object_set_string_member(external,"protocol","socks5");
    refresh_all(&app);edit(9,TRUE);check(owned->selection!=NULL&&linux_ordered_current_v1(owned->selection,json_node_get_object(catalog)),"SOCKS editor Apply lost original source");
    before=posts;linux_profile_connect_v11(NULL,&state);check(posts==before+1,"SOCKS editor did not reach shipping Connect");
    request=parse_json(last_body);q=json_node_get_object(request);
    check(strcmp(obj_string(json_array_get_object_element(linux_ordered_array_v1(q,"nodes"),1),"mode"),"socks5")==0&&strcmp(obj_string(q,"execution"),"local")==0,"SOCKS Connect lost complete Local ordering");
    check(strcmp(linux_ordered_string_v1(linux_ordered_object_v1(q,"expected_profile_tokens"),"n2"),obj_string(custom,"profile_token"))==0,"SOCKS Connect lost original source token");json_node_free(request);
    char *socks_saved=snapshot();profiles(0);linux_ordered_store_v1(owned,NULL,FALSE);profiles(1);
    after=snapshot();check(strcmp(socks_saved,after)==0,"SOCKS Save Load Update replaced original typed selection");g_free(after);
    const char *foreign_protocols[]={"shadowsocks","SOCKS5","socks5 ","http-connect"};
    for(guint i=0;i<G_N_ELEMENTS(foreign_protocols);i++){
        json_object_set_string_member(external,"protocol",foreign_protocols[i]);
        check(!linux_ordered_current_v1(owned->selection,json_node_get_object(catalog)),"SOCKS selection accepted a changed source transport");
    }
    json_object_set_string_member(external,"protocol","socks5");
    json_object_set_boolean_member(external,"ordered_middle_supported",FALSE);before=posts;linux_profile_connect_v11(NULL,&state);check(posts==before,"SOCKS Connect ignored native capability");json_object_set_boolean_member(external,"ordered_middle_supported",TRUE);
    char *socks_token=g_strdup(obj_string(custom,"profile_token"));json_object_set_string_member(custom,"profile_token","eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    check(!linux_ordered_current_v1(owned->selection,json_node_get_object(catalog)),"SOCKS relinking retained old draft authority");json_object_set_string_member(custom,"profile_token",socks_token);g_free(socks_token);
    JsonObject *socks_entry=json_array_get_object_element(owned->selection->nodes,0);char *socks_entry_mode=g_strdup(obj_string(socks_entry,"mode"));
    json_object_set_string_member(socks_entry,"mode","socks5");check(!linux_ordered_rows_v1(owned->selection->nodes,"exit"),"SOCKS middle became physical entry");
    json_object_set_string_member(socks_entry,"mode",socks_entry_mode);g_free(socks_entry_mode);
    g_free(socks_saved);
    const char *connect_protocols[]={"http-connect","https-connect","openvpn","socks5","shadowsocks"}, *connect_prefixes[]={"wg","awg2-fast","awg2-strong"};
    for(guint protocol_index=0;protocol_index<G_N_ELEMENTS(connect_protocols);protocol_index++)for(guint prefix_index=0;prefix_index<G_N_ELEMENTS(connect_prefixes);prefix_index++){
        for(connect_editor_count=3;connect_editor_count<=8;connect_editor_count++){
        connect_editor_protocol=connect_protocols[protocol_index];connect_editor_prefix=connect_prefixes[prefix_index];
        json_object_set_string_member(external,"protocol",connect_editor_protocol);json_object_set_boolean_member(external,"ordered_middle_supported",TRUE);
        refresh_all(&app);edit(10,TRUE);
        check(owned->selection!=NULL&&linux_ordered_current_v1(owned->selection,json_node_get_object(catalog)),"CONNECT editor Apply lost original source");
        before=posts;linux_profile_connect_v11(NULL,&state);check(posts==before+1,"CONNECT editor did not reach shipping Connect");
        request=parse_json(last_body);q=json_node_get_object(request);JsonArray *connect_nodes=linux_ordered_array_v1(q,"nodes");
        check(connect_nodes&&json_array_get_length(connect_nodes)==connect_editor_count&&strcmp(obj_string(q,"execution"),"local")==0,"CONNECT request lost complete Local ordering");
        check(strcmp(obj_string(json_array_get_object_element(connect_nodes,0),"mode"),connect_editor_prefix)==0&&strcmp(obj_string(json_array_get_object_element(connect_nodes,connect_editor_count-2),"mode"),connect_editor_protocol)==0&&strcmp(obj_string(json_array_get_object_element(connect_nodes,connect_editor_count-1),"mode"),"shadowsocks")==0,"CONNECT request changed an original transport");
        check(strcmp(linux_ordered_string_v1(linux_ordered_object_v1(q,"expected_profile_tokens"),"n2"),obj_string(custom,"profile_token"))==0,"CONNECT request lost original source token");
        check(strstr(last_body,"password")==NULL&&strstr(last_body,"api_token")==NULL,"CONNECT request copied credentials");json_node_free(request);
        char *connect_saved=snapshot();profiles(0);linux_ordered_store_v1(owned,NULL,FALSE);profiles(1);after=snapshot();
        check(strcmp(connect_saved,after)==0,"CONNECT Add Load Update replaced original typed selection");g_free(after);g_free(connect_saved);
        const char *changed_protocols[]={connect_protocols[(protocol_index+1)%G_N_ELEMENTS(connect_protocols)],strcmp(connect_editor_protocol,"shadowsocks")==0?"socks5":"shadowsocks","HTTP-CONNECT","HTTPS-CONNECT","http-connect ","https-connect "};
        for(guint i=0;i<G_N_ELEMENTS(changed_protocols);i++){
            json_object_set_string_member(external,"protocol",changed_protocols[i]);
            check(!linux_ordered_current_v1(owned->selection,json_node_get_object(catalog)),"CONNECT selection borrowed a different saved protocol");
        }
        json_object_set_string_member(external,"protocol",connect_editor_protocol);
        json_object_set_boolean_member(external,"ordered_middle_supported",FALSE);before=posts;linux_profile_connect_v11(NULL,&state);check(posts==before,"CONNECT ignored native capability");
        json_object_set_int_member(external,"ordered_middle_supported",1);check(!linux_ordered_current_v1(owned->selection,json_node_get_object(catalog)),"CONNECT accepted numeric capability");
        json_object_set_string_member(external,"ordered_middle_supported","true");check(!linux_ordered_current_v1(owned->selection,json_node_get_object(catalog)),"CONNECT accepted string capability");
        json_object_set_null_member(external,"ordered_middle_supported");check(!linux_ordered_current_v1(owned->selection,json_node_get_object(catalog)),"CONNECT accepted null capability");
        json_object_remove_member(external,"ordered_middle_supported");check(!linux_ordered_current_v1(owned->selection,json_node_get_object(catalog)),"CONNECT accepted absent capability");
        json_object_set_boolean_member(external,"ordered_middle_supported",TRUE);
        char *connect_token=g_strdup(obj_string(custom,"profile_token"));json_object_set_string_member(custom,"profile_token","dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
        check(!linux_ordered_current_v1(owned->selection,json_node_get_object(catalog)),"CONNECT relinking retained old source authority");json_object_set_string_member(custom,"profile_token",connect_token);g_free(connect_token);
        JsonObject *connect_entry=json_array_get_object_element(owned->selection->nodes,0), *connect_final=json_array_get_object_element(owned->selection->nodes,connect_editor_count-1);
        json_object_set_string_member(connect_entry,"mode",connect_editor_protocol);check(!linux_ordered_rows_v1(owned->selection->nodes,"exit"),"CONNECT middle became physical entry");json_object_set_string_member(connect_entry,"mode",connect_editor_prefix);
        json_object_set_string_member(connect_final,"mode","hysteria2");check(!linux_ordered_rows_v1(owned->selection->nodes,"exit"),"CONNECT middle acquired unsupported final authority");json_object_set_string_member(connect_final,"mode","shadowsocks");
        JsonArray *extended=json_array_new();
        for(guint i=0;i<connect_editor_count;i++){
            guint original=i==connect_editor_count-3?connect_editor_count-2:i==connect_editor_count-2?connect_editor_count-3:i;
            json_array_add_element(extended,json_node_copy(json_array_get_element(owned->selection->nodes,original)));
        }
        check(!linux_ordered_rows_v1(extended,"exit"),"CONNECT borrowed an unsupported graph shape");json_array_unref(extended);
    }
    }
    json_object_set_string_member(external,"protocol","shadowsocks");
    refresh_all(&app);edit(7,TRUE);check(owned->selection!=NULL&&strcmp(obj_string(json_array_get_object_element(owned->selection->nodes,1),"mode"),"hysteria2")==0,"editor did not retain Hysteria2 final");
    g_free(original);original=snapshot();edit(8,FALSE);after=snapshot();check(strcmp(original,after)==0,"cancel replaced selected Hysteria2 final");g_free(after);
    before=posts;linux_profile_connect_v11(NULL,&state);check(posts==before+1,"Hysteria2 path did not reach Connect");request=parse_json(last_body);q=json_node_get_object(request);check(strcmp(obj_string(json_array_get_object_element(linux_ordered_array_v1(q,"nodes"),1),"mode"),"hysteria2")==0,"Connect replaced Hysteria2 final");json_node_free(request);
    for (guint choice=0;choice<2;choice++) {
        const char *execution=choice==0?"server":"auto";
        check(linux_ordered_execution_v1(owned->selection,execution),"Hysteria editor refused captured execution");
        before=posts;linux_profile_connect_v11(NULL,&state);check(posts==before+1,"Hysteria execution did not reach its captured Connect callback");
        request=parse_json(last_body);q=json_node_get_object(request);
        check(strcmp(obj_string(q,"execution"),execution)==0&&strcmp(obj_string(json_array_get_object_element(linux_ordered_array_v1(q,"nodes"),1),"mode"),"hysteria2")==0,"Hysteria execution callback replaced final or choice");json_node_free(request);
        hysteria_capability=FALSE;before=posts;linux_profile_connect_v11(NULL,&state);check(posts==before,"Hysteria execution borrowed unrelated global capability");hysteria_capability=TRUE;
    }
    check(linux_ordered_execution_v1(owned->selection,"local"),"Hysteria Local selection lost");
    profiles(0);request=parse_json(last_body);q=json_node_get_object(request);check(strcmp(obj_string(q,"mode"),"hysteria2")==0,"profile write replaced Hysteria2 final");json_node_free(request);
    linux_ordered_store_v1(owned,NULL,FALSE);profiles(1);after=snapshot();check(strcmp(original,after)==0,"profile Load replaced Hysteria2 final");g_free(after);
    g_object_ref(app.window);edit(5,TRUE);after=snapshot();check(strcmp(original,after)==0,"parent close replaced original path");g_free(after);
    g_free(original);g_object_unref(app.window);gtk_widget_destroy(state.node);gtk_widget_destroy(state.mode);gtk_widget_destroy(state.multihop);json_node_free(catalog);if(saved)json_node_free(saved);g_free(last_body);g_free(last_path);g_free(keypath);
    printf("Shipping GTK ordered editor + Add/Load/Update/Connect: %u checks PASS; real callbacks/persistence, doubled controller boundary.\n",checks);return 0;
}
