/* Linux native typed external-node creator.
 *
 * This form only sends the bounded typed fields accepted by
 * /api/external-profile/create. OpenVPN and Tor keep their dedicated hardened
 * import/builders; arbitrary runtime JSON, executable paths and directives are
 * never accepted here.
 */

typedef struct {
    App *app;
    GtkWidget *dialog;
    GtkWidget *protocol;
    GtkWidget *name;
    GtkWidget *server;
    GtkWidget *port;
    GtkWidget *expected;
    GtkWidget *username;
    GtkWidget *password;
    GtkWidget *method;
    GtkWidget *secret;
    GtkWidget *tls_name;
    GtkWidget *wg_private;
    GtkWidget *wg_peer;
    GtkWidget *wg_psk;
    GtkWidget *wg_addresses;
    GtkWidget *wg_allowed;
    GtkWidget *wg_dns;
    GtkWidget *wg_mtu;
    GtkWidget *status;
} LinuxExternalNodeV14;

static gboolean linux_external_mutation_idle_v14(App *app) {
    (void)app;
    Buffer out={0}; char *err=NULL; gboolean idle=FALSE;
    if (api_request("/api/status","GET",NULL,4000,&out,&err)) {
        JsonNode *root=parse_json(out.data);
        if (root!=NULL && JSON_NODE_HOLDS_OBJECT(root)) {
            JsonObject *obj=json_node_get_object(root);
            gboolean connected=json_object_has_member(obj,"connected") && json_object_get_boolean_member(obj,"connected");
            const char *phase=obj_string(obj,"phase");
            idle=!connected && (phase[0]=='\0' || g_ascii_strcasecmp(phase,"off")==0 || g_ascii_strcasecmp(phase,"failed")==0);
            json_node_free(root);
        }
    }
    g_free(err); free(out.data); return idle;
}

static GtkWidget *linux_external_field_v14(const char *placeholder, gboolean secret) {
    GtkWidget *field=gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(field),placeholder);
    if (secret) gtk_entry_set_visibility(GTK_ENTRY(field),FALSE);
    return field;
}

static void linux_external_csv_v14(JsonBuilder *builder, const char *name, const char *raw) {
    json_builder_set_member_name(builder,name); json_builder_begin_array(builder);
    gchar **parts=g_strsplit(raw!=NULL?raw:"",",",-1);
    for (guint i=0;parts!=NULL && parts[i]!=NULL;i++) { char *value=g_strdup(parts[i]); g_strstrip(value); if(value[0])json_builder_add_string_value(builder,value); g_free(value); }
    g_strfreev(parts); json_builder_end_array(builder);
}

static char *linux_external_payload_v14(LinuxExternalNodeV14 *state, char **validation_error) {
    if(validation_error!=NULL)*validation_error=NULL;
    const char *protocol=gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->protocol));
    if(protocol==NULL){if(validation_error!=NULL)*validation_error=g_strdup("Choose an external node protocol.");return NULL;}
    const char *port_text=gtk_entry_get_text(GTK_ENTRY(state->port));
    char *port_end=NULL; long port=g_ascii_strtoll(port_text,&port_end,10);
    if(port_end==port_text || (port_end!=NULL && *port_end!='\0') || port<1 || port>65535){if(validation_error!=NULL)*validation_error=g_strdup("Port must be 1..65535.");return NULL;}

    JsonBuilder *builder=json_builder_new(); json_builder_begin_object(builder);
    json_builder_set_member_name(builder,"name");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->name)));
    json_builder_set_member_name(builder,"protocol");json_builder_add_string_value(builder,protocol);
    json_builder_set_member_name(builder,"server");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->server)));
    json_builder_set_member_name(builder,"port");json_builder_add_int_value(builder,port);
    json_builder_set_member_name(builder,"expected_public_ip");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->expected)));
    if(g_strcmp0(protocol,"socks5")==0 || g_strcmp0(protocol,"http-connect")==0 || g_strcmp0(protocol,"https-connect")==0){
        json_builder_set_member_name(builder,"username");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->username)));
        json_builder_set_member_name(builder,"password");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->password)));
    }
    if(g_strcmp0(protocol,"https-connect")==0 || g_strcmp0(protocol,"hysteria2")==0){json_builder_set_member_name(builder,"tls_server_name");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->tls_name)));}
    if(g_strcmp0(protocol,"shadowsocks")==0){json_builder_set_member_name(builder,"method");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->method)));json_builder_set_member_name(builder,"secret");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->secret)));}
    if(g_strcmp0(protocol,"hysteria2")==0){json_builder_set_member_name(builder,"secret");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->secret)));}
    if(g_strcmp0(protocol,"wireguard")==0){
        json_builder_set_member_name(builder,"wg_private_key");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->wg_private)));
        json_builder_set_member_name(builder,"wg_peer_public_key");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->wg_peer)));
        const char *psk=gtk_entry_get_text(GTK_ENTRY(state->wg_psk));if(psk!=NULL&&psk[0]){json_builder_set_member_name(builder,"wg_preshared_key");json_builder_add_string_value(builder,psk);}
        linux_external_csv_v14(builder,"wg_addresses",gtk_entry_get_text(GTK_ENTRY(state->wg_addresses)));
        linux_external_csv_v14(builder,"wg_allowed_ips",gtk_entry_get_text(GTK_ENTRY(state->wg_allowed)));
        linux_external_csv_v14(builder,"wg_dns",gtk_entry_get_text(GTK_ENTRY(state->wg_dns)));
        const char *mtu_text=gtk_entry_get_text(GTK_ENTRY(state->wg_mtu));if(mtu_text!=NULL&&mtu_text[0]){char *mtu_end=NULL;long mtu=g_ascii_strtoll(mtu_text,&mtu_end,10);if(mtu_end==mtu_text||(mtu_end!=NULL&&*mtu_end!='\0')||mtu<1280||mtu>9000){if(validation_error!=NULL)*validation_error=g_strdup("WireGuard MTU must be 1280..9000 when set.");g_object_unref(builder);return NULL;}json_builder_set_member_name(builder,"wg_mtu");json_builder_add_int_value(builder,mtu);}
    }
    json_builder_end_object(builder);JsonNode *root=json_builder_get_root(builder);JsonGenerator *generator=json_generator_new();json_generator_set_root(generator,root);char *payload=json_generator_to_data(generator,NULL);g_object_unref(generator);json_node_free(root);g_object_unref(builder);return payload;
}

static gboolean linux_external_save_v14(LinuxExternalNodeV14 *state) {
    if(!linux_external_mutation_idle_v14(state->app)){gtk_label_set_text(GTK_LABEL(state->status),"VPN state changed while the external-node dialog was open. Nothing was saved.");return FALSE;}
    char *validation=NULL;char *payload=linux_external_payload_v14(state,&validation);
    if(payload==NULL){gtk_label_set_text(GTK_LABEL(state->status),validation!=NULL?validation:"Invalid external-node form.");g_free(validation);return FALSE;}
    Buffer out={0};char *err=NULL;gboolean ok=api_request("/api/external-profile/create","POST",payload,25000,&out,&err);g_free(payload);
    if(!ok){char *message=g_strdup_printf("External node rejected: %s",err!=NULL?err:"unknown error");gtk_label_set_text(GTK_LABEL(state->status),message);g_free(message);g_free(err);free(out.data);return FALSE;}
    gtk_label_set_text(GTK_LABEL(state->status),"External node saved and selected.");append_diag(state->app,"Saved validated typed external node (WG/SOCKS5/HTTP/HTTPS/Shadowsocks/Hysteria2).");refresh_all(state->app);g_free(err);free(out.data);return TRUE;
}

static void on_linux_external_node_v14(GtkButton *button, gpointer data) {
    (void)button;App *app=data;if(app==NULL)return;
    if(!linux_external_mutation_idle_v14(app)){append_diag(app,"Disconnect or let the active VPN transition finish before adding an external node. Unknown controller state fails closed.");return;}
    LinuxExternalNodeV14 state={0};state.app=app;
    state.dialog=gtk_dialog_new_with_buttons("Add external node",GTK_WINDOW(app->window),GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT,"Cancel",GTK_RESPONSE_CANCEL,"Save node",GTK_RESPONSE_ACCEPT,NULL);gtk_window_set_default_size(GTK_WINDOW(state.dialog),760,760);
    GtkWidget *content=gtk_dialog_get_content_area(GTK_DIALOG(state.dialog));GtkWidget *box=gtk_box_new(GTK_ORIENTATION_VERTICAL,6);gtk_container_set_border_width(GTK_CONTAINER(box),14);
    GtkWidget *intro=gtk_label_new("Create a validated full-device external node. OpenVPN uses Import; Tor uses Tor bridges. Relevant fields depend on protocol; the controller re-validates the complete profile before persistence.");gtk_label_set_line_wrap(GTK_LABEL(intro),TRUE);gtk_label_set_xalign(GTK_LABEL(intro),0.0f);gtk_box_pack_start(GTK_BOX(box),intro,FALSE,FALSE,0);
    state.protocol=gtk_combo_box_text_new();gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.protocol),"wireguard","WireGuard");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.protocol),"socks5","SOCKS5");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.protocol),"http-connect","HTTP CONNECT");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.protocol),"https-connect","HTTPS CONNECT");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.protocol),"shadowsocks","Shadowsocks");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.protocol),"hysteria2","Hysteria2");gtk_combo_box_set_active_id(GTK_COMBO_BOX(state.protocol),"wireguard");gtk_box_pack_start(GTK_BOX(box),state.protocol,FALSE,FALSE,0);
    state.name=linux_external_field_v14("Display name",FALSE);state.server=linux_external_field_v14("Server IP / hostname",FALSE);state.port=linux_external_field_v14("Port",FALSE);state.expected=linux_external_field_v14("Expected public exit IP",FALSE);state.username=linux_external_field_v14("Username (proxy only)",FALSE);state.password=linux_external_field_v14("Password / proxy credential",TRUE);state.method=linux_external_field_v14("Shadowsocks method",FALSE);state.secret=linux_external_field_v14("Shadowsocks / Hysteria2 secret",TRUE);state.tls_name=linux_external_field_v14("TLS server name / SNI",FALSE);state.wg_private=linux_external_field_v14("WG private key",TRUE);state.wg_peer=linux_external_field_v14("WG peer public key",FALSE);state.wg_psk=linux_external_field_v14("WG preshared key (optional)",TRUE);state.wg_addresses=linux_external_field_v14("WG addresses, comma-separated CIDRs",FALSE);state.wg_allowed=linux_external_field_v14("WG AllowedIPs, comma-separated CIDRs",FALSE);state.wg_dns=linux_external_field_v14("WG DNS IPs, comma-separated",FALSE);state.wg_mtu=linux_external_field_v14("WG MTU (optional)",FALSE);
    GtkWidget *fields[]={state.name,state.server,state.port,state.expected,state.username,state.password,state.method,state.secret,state.tls_name,state.wg_private,state.wg_peer,state.wg_psk,state.wg_addresses,state.wg_allowed,state.wg_dns,state.wg_mtu};for(guint i=0;i<G_N_ELEMENTS(fields);i++)gtk_box_pack_start(GTK_BOX(box),fields[i],FALSE,FALSE,0);
    GtkWidget *note=gtk_label_new("Plain HTTP CONNECT never accepts TLS metadata. HTTPS CONNECT and Hysteria2 require TLS/SNI. The typed maker cannot inject executable paths, arbitrary sing-box JSON, Tor directives, or raw OpenVPN configuration.");gtk_label_set_line_wrap(GTK_LABEL(note),TRUE);gtk_label_set_xalign(GTK_LABEL(note),0.0f);gtk_box_pack_start(GTK_BOX(box),note,FALSE,FALSE,0);
    state.status=gtk_label_new("");gtk_label_set_line_wrap(GTK_LABEL(state.status),TRUE);gtk_label_set_xalign(GTK_LABEL(state.status),0.0f);gtk_box_pack_start(GTK_BOX(box),state.status,FALSE,FALSE,0);
    GtkWidget *scroll=gtk_scrolled_window_new(NULL,NULL);gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),GTK_POLICY_NEVER,GTK_POLICY_AUTOMATIC);gtk_container_add(GTK_CONTAINER(scroll),box);gtk_box_pack_start(GTK_BOX(content),scroll,TRUE,TRUE,0);gtk_widget_show_all(state.dialog);
    while(TRUE){int response=gtk_dialog_run(GTK_DIALOG(state.dialog));if(response==GTK_RESPONSE_ACCEPT){if(linux_external_save_v14(&state))break;continue;}break;}gtk_widget_destroy(state.dialog);
}
