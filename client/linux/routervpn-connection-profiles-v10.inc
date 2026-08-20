typedef struct {
    App *app;
    LinuxUnifiedV8 *base;
    GtkWidget *dialog;
    GtkWidget *name;
    GtkWidget *profiles;
    GtkWidget *status;
} LinuxConnectionProfilesV10;

static char *linux_connection_profile_body_v10(const char *id,const char *name,const char *mode,const char *layers){
    JsonBuilder *builder=json_builder_new();
    json_builder_begin_object(builder);
    if(id!=NULL&&id[0]){json_builder_set_member_name(builder,"id");json_builder_add_string_value(builder,id);}
    if(name!=NULL){json_builder_set_member_name(builder,"name");json_builder_add_string_value(builder,name);}
    if(mode!=NULL){json_builder_set_member_name(builder,"mode");json_builder_add_string_value(builder,mode);}
    json_builder_set_member_name(builder,"custom_layers");json_builder_begin_array(builder);
    if(layers!=NULL&&layers[0]){gchar **parts=g_strsplit(layers,",",-1);for(guint i=0;parts!=NULL&&parts[i]!=NULL;i++){g_strstrip(parts[i]);if(parts[i][0])json_builder_add_string_value(builder,parts[i]);}g_strfreev(parts);}
    json_builder_end_array(builder);json_builder_end_object(builder);
    JsonNode *root=json_builder_get_root(builder);JsonGenerator *gen=json_generator_new();json_generator_set_root(gen,root);char *body=json_generator_to_data(gen,NULL);json_node_free(root);g_object_unref(gen);g_object_unref(builder);return body;
}

static void linux_connection_profiles_set_status_v10(LinuxConnectionProfilesV10 *state,const char *text){if(state!=NULL&&state->status!=NULL)gtk_label_set_text(GTK_LABEL(state->status),text!=NULL?text:"");}

static void linux_connection_profiles_refresh_v10(LinuxConnectionProfilesV10 *state){
    if(state==NULL||state->profiles==NULL)return;Buffer out={0};char *err=NULL;
    if(!api_request("/api/connection-profiles","GET",NULL,5000,&out,&err)){linux_connection_profiles_set_status_v10(state,err!=NULL?err:"Connection profiles unavailable.");g_free(err);free(out.data);return;}
    JsonNode *root=parse_json(out.data);gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(state->profiles));guint count=0;
    if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject *obj=json_node_get_object(root);JsonArray *profiles=json_object_has_member(obj,"profiles")?json_object_get_array_member(obj,"profiles"):NULL;for(guint i=0;profiles!=NULL&&i<json_array_get_length(profiles);i++){JsonObject *p=json_array_get_object_element(profiles,i);if(p==NULL)continue;const char *id=obj_string(p,"id");const char *name=obj_string(p,"name");const char *mode=obj_string(p,"mode");const char *node=obj_string(p,"node_id");if(id[0]=='\0')continue;char *label=g_strdup_printf("%s • %s • %s",name[0]?name:id,mode[0]?mode:"smart-auto",node);gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state->profiles),id,label);g_free(label);count++;}}
    if(count>0)gtk_combo_box_set_active(GTK_COMBO_BOX(state->profiles),0);char *msg=g_strdup_printf("%u saved connection profile(s). Node keys/API tokens/external credentials are never duplicated.",count);linux_connection_profiles_set_status_v10(state,msg);g_free(msg);if(root!=NULL)json_node_free(root);g_free(err);free(out.data);
}

static void linux_connection_profiles_refresh_clicked_v10(GtkButton *button,gpointer data){(void)button;linux_connection_profiles_refresh_v10((LinuxConnectionProfilesV10*)data);}

static gboolean linux_connection_profiles_write_v10(LinuxConnectionProfilesV10 *state,gboolean updating){
    if(state==NULL)return FALSE;const char *raw_name=gtk_entry_get_text(GTK_ENTRY(state->name));char *name=g_strdup(raw_name!=NULL?raw_name:"");g_strstrip(name);if(name[0]=='\0'){linux_connection_profiles_set_status_v10(state,"Enter a profile name.");g_free(name);return FALSE;}
    char *mode=linux_unified_selected_mode_v8();if(mode==NULL||mode[0]=='\0'){g_free(mode);mode=g_strdup("smart-auto");}char *layers=linux_unified_custom_layers_for_mode_v8(mode);const char *id=updating?gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->profiles)):NULL;if(updating&&(id==NULL||id[0]=='\0')){linux_connection_profiles_set_status_v10(state,"Select a saved profile to update.");g_free(name);g_free(mode);g_free(layers);return FALSE;}
    char *body=linux_connection_profile_body_v10(id,name,mode,layers);Buffer out={0};char *err=NULL;const char *path=updating?"/api/connection-profile/update":"/api/connection-profile/save";gboolean ok=api_request(path,"POST",body,12000,&out,&err);if(ok){linux_connection_profiles_set_status_v10(state,updating?"Connection profile updated from the current node/mode/settings.":"Connection profile added from the current node/mode/settings.");linux_connection_profiles_refresh_v10(state);}else linux_connection_profiles_set_status_v10(state,err!=NULL?err:"Connection profile write failed.");g_free(body);g_free(name);g_free(mode);g_free(layers);g_free(err);free(out.data);return ok;
}

static void linux_connection_profiles_add_v10(GtkButton *button,gpointer data){(void)button;(void)linux_connection_profiles_write_v10((LinuxConnectionProfilesV10*)data,FALSE);}
static void linux_connection_profiles_update_v10(GtkButton *button,gpointer data){(void)button;(void)linux_connection_profiles_write_v10((LinuxConnectionProfilesV10*)data,TRUE);}

static void linux_connection_profiles_apply_loaded_mode_v10(LinuxConnectionProfilesV10 *state,JsonObject *root){
    if(state==NULL||root==NULL)return;const char *mode=obj_string(root,"mode");if(mode[0]=='\0')mode="smart-auto";
    if(g_str_has_prefix(mode,"custom:")&&json_object_has_member(root,"custom_layers")){
        JsonArray *layers=json_object_get_array_member(root,"custom_layers");const char *name=mode+strlen("custom:");if(name[0]&&layers!=NULL&&json_array_get_length(layers)>0){GString *joined=g_string_new("");for(guint i=0;i<json_array_get_length(layers);i++){const char *layer=json_array_get_string_element(layers,i);if(layer==NULL||layer[0]=='\0')continue;if(joined->len)g_string_append_c(joined,',');g_string_append(joined,layer);}if(joined->len){GKeyFile *key=linux_unified_load_keyfile_v8();char *group=g_strdup_printf("preset:%s",name);g_key_file_set_string(key,group,"layers",joined->str);linux_unified_save_keyfile_v8(key);g_free(group);g_key_file_unref(key);}g_string_free(joined,TRUE);}
    }
    linux_unified_store_mode_v8(mode);linux_unified_refresh_mode_combo_v8(state->base);refresh_all(state->app);linux_unified_refresh_v8(state->base);
}

static void linux_connection_profiles_load_v10(GtkButton *button,gpointer data){
    (void)button;LinuxConnectionProfilesV10 *state=data;if(state==NULL)return;const char *id=gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->profiles));if(id==NULL||id[0]=='\0'){linux_connection_profiles_set_status_v10(state,"Select a saved profile to load.");return;}char *body=json_string_body("id",id);Buffer out={0};char *err=NULL;if(!api_request("/api/connection-profile/load","POST",body,12000,&out,&err)){linux_connection_profiles_set_status_v10(state,err!=NULL?err:"Connection profile load failed.");g_free(body);g_free(err);free(out.data);return;}JsonNode *root=parse_json(out.data);if(root==NULL||!JSON_NODE_HOLDS_OBJECT(root)){linux_connection_profiles_set_status_v10(state,"Connection profile load returned invalid JSON.");}else{JsonObject *obj=json_node_get_object(root);linux_connection_profiles_apply_loaded_mode_v10(state,obj);const char *mode=obj_string(obj,"mode");const char *node=obj_string(obj,"selected_node_id");char *msg=g_strdup_printf("Loaded node %s • mode %s. Connect separately so the real dataplane can establish and prove the path.",node,mode[0]?mode:"smart-auto");linux_connection_profiles_set_status_v10(state,msg);g_free(msg);}if(root!=NULL)json_node_free(root);g_free(body);g_free(err);free(out.data);
}

static void linux_connection_profiles_delete_v10(GtkButton *button,gpointer data){
    (void)button;LinuxConnectionProfilesV10 *state=data;if(state==NULL)return;const char *id=gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->profiles));if(id==NULL||id[0]=='\0'){linux_connection_profiles_set_status_v10(state,"Select a saved profile to delete.");return;}char *body=json_string_body("id",id);Buffer out={0};char *err=NULL;if(api_request("/api/connection-profile/delete","POST",body,10000,&out,&err)){linux_connection_profiles_set_status_v10(state,"Deleted saved connection profile.");linux_connection_profiles_refresh_v10(state);}else linux_connection_profiles_set_status_v10(state,err!=NULL?err:"Connection profile delete failed.");g_free(body);g_free(err);free(out.data);
}

static void linux_connection_profiles_selection_v10(GtkComboBox *combo,gpointer data){LinuxConnectionProfilesV10 *state=data;if(state==NULL)return;gchar *text=gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(combo));if(text!=NULL){char **parts=g_strsplit(text," • ",2);if(parts!=NULL&&parts[0]!=NULL)gtk_entry_set_text(GTK_ENTRY(state->name),parts[0]);g_strfreev(parts);g_free(text);}}

static void linux_connection_profiles_v10(GtkButton *button,gpointer data){
    (void)button;LinuxTelemetryV9 *telemetry=data;if(telemetry==NULL)return;LinuxConnectionProfilesV10 state={0};state.app=telemetry->app;state.base=telemetry->base;
    state.dialog=gtk_dialog_new_with_buttons("Connection profiles",GTK_WINDOW(state.app->window),GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT,"Close",GTK_RESPONSE_CLOSE,NULL);gtk_window_set_default_size(GTK_WINDOW(state.dialog),650,420);GtkWidget *area=gtk_dialog_get_content_area(GTK_DIALOG(state.dialog));GtkWidget *box=gtk_box_new(GTK_ORIENTATION_VERTICAL,8);gtk_container_set_border_width(GTK_CONTAINER(box),16);GtkWidget *note=gtk_label_new("Save/load the selected node plus current Mode/CUSTOM layers, DNS, kill switch, IPv6, MTU and multihop choices. Node keys, API tokens and external credentials remain only in the linked node store.");gtk_label_set_line_wrap(GTK_LABEL(note),TRUE);gtk_label_set_xalign(GTK_LABEL(note),0.0f);gtk_box_pack_start(GTK_BOX(box),note,FALSE,FALSE,0);state.name=gtk_entry_new();gtk_entry_set_placeholder_text(GTK_ENTRY(state.name),"Profile name");gtk_box_pack_start(GTK_BOX(box),state.name,FALSE,FALSE,0);state.profiles=gtk_combo_box_text_new();gtk_box_pack_start(GTK_BOX(box),state.profiles,FALSE,FALSE,0);GtkWidget *row=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,6);gtk_box_pack_start(GTK_BOX(row),make_button("Add profile",G_CALLBACK(linux_connection_profiles_add_v10),&state),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(row),make_button("Load",G_CALLBACK(linux_connection_profiles_load_v10),&state),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(row),make_button("Update",G_CALLBACK(linux_connection_profiles_update_v10),&state),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(row),make_button("Delete",G_CALLBACK(linux_connection_profiles_delete_v10),&state),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(row),make_button("Refresh",G_CALLBACK(linux_connection_profiles_refresh_clicked_v10),&state),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),row,FALSE,FALSE,0);state.status=gtk_label_new("");gtk_label_set_line_wrap(GTK_LABEL(state.status),TRUE);gtk_label_set_xalign(GTK_LABEL(state.status),0.0f);gtk_box_pack_start(GTK_BOX(box),state.status,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(area),box,TRUE,TRUE,0);g_signal_connect(state.profiles,"changed",G_CALLBACK(linux_connection_profiles_selection_v10),&state);linux_connection_profiles_refresh_v10(&state);gtk_widget_show_all(state.dialog);gtk_dialog_run(GTK_DIALOG(state.dialog));gtk_widget_destroy(state.dialog);
}

/* Linux connection profiles v10: Add / Load / Update / Delete complete connection choices.
 * Stored records reference linked node IDs and never duplicate node secrets or credentials. */
