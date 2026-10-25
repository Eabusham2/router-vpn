/* Linux native typed external-node creator.
 *
 * This form only sends the bounded typed fields accepted by
 * /api/external-profile/create. Inline OpenVPN and raw private pairing text are
 * validated by the controller's native bounded parser. Tor keeps its dedicated
 * builder; arbitrary runtime JSON, scripts and executable paths are not accepted.
 */
#include <math.h>

typedef struct {
    App *app;
    GtkWidget *dialog;
    GtkWidget *protocol;
    GtkWidget *name;
    GtkWidget *server;
    GtkWidget *port;
    GtkWidget *expected;
    GtkWidget *location;
    GtkWidget *latitude;
    GtkWidget *longitude;
    GtkWidget *username;
    GtkWidget *password;
    GtkWidget *method;
    GtkWidget *secret;
    GtkWidget *tls_name;
    GtkWidget *response_url;
    GtkWidget *response_name;
    GtkWidget *start_layer;
    GtkWidget *layer_api;
    GtkWidget *layer_port;
    GtkWidget *layer_key;
    GtkWidget *wg_private;
    GtkWidget *wg_peer;
    GtkWidget *wg_psk;
    GtkWidget *wg_addresses;
    GtkWidget *wg_allowed;
    GtkWidget *wg_dns;
    GtkWidget *wg_mtu;
    GtkWidget *wg_keepalive;
    GtkWidget *awg_parameters;
    GtkWidget *server_peer_public;
    GtkWidget *server_peer_addresses;
    GtkWidget *server_peer_mtu;
    GtkWidget *server_peer_keepalive;
    GtkWidget *openvpn_config;
    GtkWidget *openvpn_pairing;
    GtkWidget *openvpn_response_probes;
    GtkWidget *openvpn_start_layers;
    GtkWidget *status;
} LinuxExternalNodeV14;

static char *linux_external_text_v14(GtkWidget *view) {
    if(view==NULL)return g_strdup("");
    GtkTextBuffer *buffer=gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));GtkTextIter start,end;
    gtk_text_buffer_get_bounds(buffer,&start,&end);return gtk_text_buffer_get_text(buffer,&start,&end,FALSE);
}

static gboolean linux_external_openvpn_v14(LinuxExternalNodeV14 *state,JsonBuilder *builder,const char *protocol,char **error) {
    g_autofree char *config=linux_external_text_v14(state->openvpn_config),*pairing=linux_external_text_v14(state->openvpn_pairing),*probes=linux_external_text_v14(state->openvpn_response_probes),*layers=linux_external_text_v14(state->openvpn_start_layers);
    g_autofree char *trimmed=g_strdup(pairing),*trimmed_probes=g_strdup(probes),*trimmed_layers=g_strdup(layers);g_strstrip(trimmed);g_strstrip(trimmed_probes);g_strstrip(trimmed_layers);
    if(g_strcmp0(protocol,"openvpn")!=0){
        if(config[0]||trimmed[0]||trimmed_probes[0]||trimmed_layers[0]){if(error!=NULL)*error=g_strdup("OpenVPN profile, pairing, response-map, and layer-map fields belong only to OpenVPN.");return FALSE;}
        return TRUE;
    }
    if(!config[0]||strlen(config)>256*1024||strlen(pairing)>512*1024||strlen(probes)>40*1024||strlen(layers)>128*1024){if(error!=NULL)*error=g_strdup("Paste a bounded inline OpenVPN profile and private pairing, response-map, or layer-map fields.");return FALSE;}
    if(trimmed_layers[0]&&!trimmed_probes[0]){if(error!=NULL)*error=g_strdup("A per-host Start Layer map requires the complete response map for those same OpenVPN hosts.");return FALSE;}
    json_builder_set_member_name(builder,"openvpn");json_builder_begin_object(builder);
    json_builder_set_member_name(builder,"config");json_builder_add_string_value(builder,config);
    json_builder_set_member_name(builder,"username");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->username)));
    json_builder_set_member_name(builder,"password");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->password)));json_builder_end_object(builder);
    if(trimmed[0]){json_builder_set_member_name(builder,"openvpn_pairing_json");json_builder_add_string_value(builder,pairing);}
    if(trimmed_probes[0]){json_builder_set_member_name(builder,"openvpn_response_probes_json");json_builder_add_string_value(builder,probes);}
    if(trimmed_layers[0]){json_builder_set_member_name(builder,"openvpn_start_layers_json");json_builder_add_string_value(builder,layers);}
    return TRUE;
}

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

static gboolean linux_external_amnezia_v14(JsonBuilder *builder, const char *raw, char **validation_error) {
    const char *keys[]={"jc","jmin","jmax","s1","s2","s3","s4","h1","h2","h3","h4"};
    if(raw==NULL||strlen(raw)>4096){if(validation_error!=NULL)*validation_error=g_strdup("AmneziaWG parameters are missing or too long.");return FALSE;}
    GHashTable *values=g_hash_table_new_full(g_str_hash,g_str_equal,g_free,g_free);
    gchar **lines=g_strsplit_set(raw,";\r\n",-1);gboolean valid=TRUE;
    for(guint i=0;lines[i]!=NULL&&valid;i++){
        char *line=g_strstrip(lines[i]);if(!line[0])continue;
        gchar **pair=g_strsplit(line,"=",-1);
        if(g_strv_length(pair)!=2){valid=FALSE;g_strfreev(pair);break;}
        char *key=g_ascii_strdown(g_strstrip(pair[0]),-1);char *value=g_strstrip(pair[1]);
        gboolean known=FALSE;for(guint j=0;j<G_N_ELEMENTS(keys);j++)if(g_strcmp0(key,keys[j])==0)known=TRUE;
        guint separators=0;gboolean digits=value[0]!='\0';
        for(guint j=0;value[j];j++)if(!g_ascii_isdigit(value[j])){
            if(key[0]=='h'&&value[j]=='-'&&j>0&&value[j+1]!='\0'&&separators==0)separators++;
            else digits=FALSE;
        }
        valid=known&&digits&&!g_hash_table_contains(values,key);
        if(valid)g_hash_table_insert(values,key,g_strdup(value));else g_free(key);
        g_strfreev(pair);
    }
    valid=valid&&g_hash_table_size(values)==G_N_ELEMENTS(keys);
    if(valid){
        json_builder_set_member_name(builder,"awg_parameters");json_builder_begin_object(builder);
        for(guint i=0;i<G_N_ELEMENTS(keys);i++){
            json_builder_set_member_name(builder,keys[i]);
            json_builder_add_string_value(builder,g_hash_table_lookup(values,keys[i]));
        }
        json_builder_end_object(builder);
    }else if(validation_error!=NULL)*validation_error=g_strdup("Supply each of Jc, Jmin, Jmax, S1-S4 and H1-H4 exactly once as key=value. Use provider numbers or header ranges, separated by lines or semicolons.");
    g_strfreev(lines);g_hash_table_unref(values);return valid;
}

static gboolean linux_external_coordinates_v14(LinuxExternalNodeV14 *state, JsonBuilder *builder, char **validation_error) {
    char *lat_text=g_strdup(gtk_entry_get_text(GTK_ENTRY(state->latitude)));
    char *lon_text=g_strdup(gtk_entry_get_text(GTK_ENTRY(state->longitude)));
    g_strstrip(lat_text); g_strstrip(lon_text);
    gboolean has_lat=lat_text[0]!='\0',has_lon=lon_text[0]!='\0';
    if(has_lat!=has_lon){if(validation_error!=NULL)*validation_error=g_strdup("Latitude and longitude must both be supplied or both left blank.");g_free(lat_text);g_free(lon_text);return FALSE;}
    const char *location=gtk_entry_get_text(GTK_ENTRY(state->location));
    if(location!=NULL&&location[0]){json_builder_set_member_name(builder,"location");json_builder_add_string_value(builder,location);}
    if(has_lat){
        char *lat_end=NULL,*lon_end=NULL;double lat=g_ascii_strtod(lat_text,&lat_end),lon=g_ascii_strtod(lon_text,&lon_end);
        if(lat_end==lat_text||lon_end==lon_text||(lat_end!=NULL&&*lat_end!='\0')||(lon_end!=NULL&&*lon_end!='\0')||!isfinite(lat)||!isfinite(lon)||lat < -90.0||lat > 90.0||lon < -180.0||lon > 180.0){if(validation_error!=NULL)*validation_error=g_strdup("Coordinates must be finite latitude -90..90 and longitude -180..180.");g_free(lat_text);g_free(lon_text);return FALSE;}
        json_builder_set_member_name(builder,"latitude");json_builder_add_double_value(builder,lat);
        json_builder_set_member_name(builder,"longitude");json_builder_add_double_value(builder,lon);
    }
    g_free(lat_text);g_free(lon_text);return TRUE;
}

static gboolean linux_external_server_peer_v14(LinuxExternalNodeV14 *state, JsonBuilder *builder, const char *protocol, char **validation_error) {
    g_autofree char *key=g_strdup(gtk_entry_get_text(GTK_ENTRY(state->server_peer_public)));
    g_autofree char *addresses=g_strdup(gtk_entry_get_text(GTK_ENTRY(state->server_peer_addresses)));
    g_autofree char *mtu=g_strdup(gtk_entry_get_text(GTK_ENTRY(state->server_peer_mtu)));
    g_autofree char *keepalive=g_strdup(gtk_entry_get_text(GTK_ENTRY(state->server_peer_keepalive)));
    g_strstrip(key);g_strstrip(addresses);g_strstrip(mtu);g_strstrip(keepalive);
    if(!key[0]&&!addresses[0]&&!mtu[0]&&!keepalive[0])return TRUE;
    const char *message=NULL;
    if(g_strcmp0(protocol,"wireguard")!=0&&g_strcmp0(protocol,"amneziawg")!=0)message="Server peer fields apply only to WireGuard or AmneziaWG.";
    char *end=NULL;gint64 value=g_ascii_strtoll(mtu,&end,10);
    if(message==NULL&&(end==mtu||*end!='\0'||value<1280||value>9000))message="Server peer MTU is required with a descriptor and must be 1280..9000.";
    gint64 seconds=0;
    if(keepalive[0]){seconds=g_ascii_strtoll(keepalive,&end,10);if(message==NULL&&(end==keepalive||*end!='\0'||seconds<0||seconds>65535))message="Server peer keepalive must be 0..65535 seconds.";}
    gsize size=0;guchar *decoded=g_base64_decode(key,&size);char *canonical=g_base64_encode(decoded,size);
    if(message==NULL&&(size!=32||g_strcmp0(canonical,key)!=0))message="Server peer public key must be canonical 32-byte Base64.";
    g_free(decoded);g_free(canonical);
    gchar **parts=g_strsplit(addresses,",",-1);guint count=0;
    for(guint i=0;parts[i]!=NULL;i++)if(g_strstrip(parts[i])[0])count++;
    g_strfreev(parts);
    if(message==NULL&&(count<1||count>2))message="Supply one server peer CIDR per IP family, up to two addresses.";
    if(message!=NULL){if(validation_error!=NULL)*validation_error=g_strdup(message);return FALSE;}
    json_builder_set_member_name(builder,"server_peer");json_builder_begin_object(builder);
    json_builder_set_member_name(builder,"public_key");json_builder_add_string_value(builder,key);
    linux_external_csv_v14(builder,"addresses",addresses);
    json_builder_set_member_name(builder,"mtu");json_builder_add_int_value(builder,value);
    if(keepalive[0]){json_builder_set_member_name(builder,"persistent_keepalive_interval");json_builder_add_int_value(builder,seconds);}
    json_builder_end_object(builder);return TRUE;
}

static gboolean linux_external_transport_fields_v14(LinuxExternalNodeV14 *state, JsonBuilder *builder, const char *protocol, char **validation_error) {
    const char *probe=gtk_entry_get_text(GTK_ENTRY(state->response_url));
    const char *name=gtk_entry_get_text(GTK_ENTRY(state->response_name));
    const char *layer=gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->start_layer));
    const char *api=gtk_entry_get_text(GTK_ENTRY(state->layer_api));
    const char *port=gtk_entry_get_text(GTK_ENTRY(state->layer_port));
    const char *key=gtk_entry_get_text(GTK_ENTRY(state->layer_key));
    g_autofree char *layers=linux_external_text_v14(state->openvpn_start_layers);g_strstrip(layers);
    const char *message=NULL;
    gboolean supported=g_strcmp0(protocol,"wireguard")==0||g_strcmp0(protocol,"amneziawg")==0||g_strcmp0(protocol,"shadowsocks")==0||g_strcmp0(protocol,"hysteria2")==0||g_strcmp0(protocol,"socks5")==0||g_strcmp0(protocol,"http-connect")==0||g_strcmp0(protocol,"https-connect")==0||g_strcmp0(protocol,"openvpn")==0;
    gboolean off=g_strcmp0(layer,"off")==0;
    if(layers[0]){
        if(g_strcmp0(protocol,"openvpn")!=0||off||(g_strcmp0(layer,"aes-256-gcm")!=0&&g_strcmp0(layer,"aes-256-gcm+xor-whitening")!=0)||probe[0]||name[0]||api[0]||port[0]||key[0]){
            if(validation_error!=NULL){*validation_error=g_strdup("Choose the matching active Start Layer for the OpenVPN host map and leave single-server response and layer fields blank.");}
            return FALSE;
        }
        json_builder_set_member_name(builder,"start_layer");json_builder_add_string_value(builder,layer);return TRUE;
    }
    if(!off&&g_strcmp0(layer,"aes-256-gcm")!=0&&g_strcmp0(layer,"aes-256-gcm+xor-whitening")!=0)message="Choose a supported external Start Layer.";
    else if(!supported&&(probe[0]||name[0]||!off||api[0]||port[0]||key[0]))message="Response probes and external Start Layers require a supported external transport.";
    else if(name[0]&&!probe[0])message="Supply the HTTPS response URL with its certificate server name.";
    else if(off&&(api[0]||port[0]||key[0]))message="Select a Start Layer before supplying its provisioned credentials.";
    char *end=NULL;long value=off?0:g_ascii_strtoll(port,&end,10);
    if(message==NULL&&!off&&(!api[0]||!key[0]||end==port||(end!=NULL&&*end!='\0')||value<1||value>65535))message="An active Start Layer requires its private API, AES port (1..65535), and key.";
    if(message!=NULL){if(validation_error!=NULL)*validation_error=g_strdup(message);return FALSE;}
    if(probe[0]){json_builder_set_member_name(builder,"response_probe");json_builder_begin_object(builder);json_builder_set_member_name(builder,"url");json_builder_add_string_value(builder,probe);json_builder_set_member_name(builder,"server_name");json_builder_add_string_value(builder,name);json_builder_end_object(builder);}
    json_builder_set_member_name(builder,"start_layer");json_builder_add_string_value(builder,layer);
    if(!off){
        json_builder_set_member_name(builder,"start_layer_provision");json_builder_begin_object(builder);
        json_builder_set_member_name(builder,"mode");json_builder_add_string_value(builder,layer);
        json_builder_set_member_name(builder,"api");json_builder_add_string_value(builder,api);
        json_builder_set_member_name(builder,"transport");json_builder_begin_object(builder);
        json_builder_set_member_name(builder,"type");json_builder_add_string_value(builder,"shadowsocks");
        json_builder_set_member_name(builder,"tag");json_builder_add_string_value(builder,"provisioned-exit-layer");
        json_builder_set_member_name(builder,"server");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->server)));
        json_builder_set_member_name(builder,"server_port");json_builder_add_int_value(builder,value);
        json_builder_set_member_name(builder,"method");json_builder_add_string_value(builder,"2022-blake3-aes-256-gcm");
        json_builder_set_member_name(builder,"password");json_builder_add_string_value(builder,key);
        json_builder_end_object(builder);json_builder_end_object(builder);
    }
    return TRUE;
}

static char *linux_external_payload_v14(LinuxExternalNodeV14 *state, char **validation_error) {
    if(validation_error!=NULL)*validation_error=NULL;
    const char *protocol=gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->protocol));
    if(protocol==NULL){if(validation_error!=NULL)*validation_error=g_strdup("Choose an external node protocol.");return NULL;}
    const char *port_text=gtk_entry_get_text(GTK_ENTRY(state->port));
    char *port_end=NULL; long port=g_ascii_strtoll(port_text,&port_end,10);
    if(g_strcmp0(protocol,"openvpn")!=0&&(port_end==port_text || (port_end!=NULL && *port_end!='\0') || port<1 || port>65535)){if(validation_error!=NULL)*validation_error=g_strdup("Port must be 1..65535.");return NULL;}
    if(g_strcmp0(protocol,"openvpn")==0)port=0; // Exact remotes come only from the native inline parser.

    JsonBuilder *builder=json_builder_new(); json_builder_begin_object(builder);
    json_builder_set_member_name(builder,"name");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->name)));
    json_builder_set_member_name(builder,"protocol");json_builder_add_string_value(builder,protocol);
    json_builder_set_member_name(builder,"server");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->server)));
    json_builder_set_member_name(builder,"port");json_builder_add_int_value(builder,port);
    json_builder_set_member_name(builder,"expected_public_ip");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->expected)));
    if(!linux_external_coordinates_v14(state,builder,validation_error)){g_object_unref(builder);return NULL;}
    if(g_strcmp0(protocol,"socks5")==0 || g_strcmp0(protocol,"http-connect")==0 || g_strcmp0(protocol,"https-connect")==0){
        json_builder_set_member_name(builder,"username");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->username)));
        json_builder_set_member_name(builder,"password");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->password)));
    }
    if(g_strcmp0(protocol,"https-connect")==0 || g_strcmp0(protocol,"hysteria2")==0){json_builder_set_member_name(builder,"tls_server_name");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->tls_name)));}
    if(g_strcmp0(protocol,"shadowsocks")==0){json_builder_set_member_name(builder,"method");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->method)));json_builder_set_member_name(builder,"secret");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->secret)));}
    if(g_strcmp0(protocol,"hysteria2")==0){json_builder_set_member_name(builder,"secret");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->secret)));}
    if(g_strcmp0(protocol,"wireguard")==0||g_strcmp0(protocol,"amneziawg")==0){
        json_builder_set_member_name(builder,"wg_private_key");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->wg_private)));
        json_builder_set_member_name(builder,"wg_peer_public_key");json_builder_add_string_value(builder,gtk_entry_get_text(GTK_ENTRY(state->wg_peer)));
        const char *psk=gtk_entry_get_text(GTK_ENTRY(state->wg_psk));if(psk!=NULL&&psk[0]){json_builder_set_member_name(builder,"wg_preshared_key");json_builder_add_string_value(builder,psk);}
        linux_external_csv_v14(builder,"wg_addresses",gtk_entry_get_text(GTK_ENTRY(state->wg_addresses)));
        linux_external_csv_v14(builder,"wg_allowed_ips",gtk_entry_get_text(GTK_ENTRY(state->wg_allowed)));
        linux_external_csv_v14(builder,"wg_dns",gtk_entry_get_text(GTK_ENTRY(state->wg_dns)));
        const char *mtu_text=gtk_entry_get_text(GTK_ENTRY(state->wg_mtu));if(mtu_text!=NULL&&mtu_text[0]){char *mtu_end=NULL;long mtu=g_ascii_strtoll(mtu_text,&mtu_end,10);if(mtu_end==mtu_text||(mtu_end!=NULL&&*mtu_end!='\0')||mtu<1280||mtu>9000){if(validation_error!=NULL)*validation_error=g_strdup("WireGuard MTU must be 1280..9000 when set.");g_object_unref(builder);return NULL;}json_builder_set_member_name(builder,"wg_mtu");json_builder_add_int_value(builder,mtu);}
        const char *keepalive_text=gtk_entry_get_text(GTK_ENTRY(state->wg_keepalive));
        if(keepalive_text!=NULL&&keepalive_text[0]){
            char *end=NULL;long keepalive=g_ascii_strtoll(keepalive_text,&end,10);
            if(end==keepalive_text||(end!=NULL&&*end!='\0')||keepalive<0||keepalive>65535){if(validation_error!=NULL)*validation_error=g_strdup("Keepalive must be 0..65535 seconds.");g_object_unref(builder);return NULL;}
            json_builder_set_member_name(builder,"wg_keepalive");json_builder_add_int_value(builder,keepalive);
        }
        if(g_strcmp0(protocol,"amneziawg")==0){
            GtkTextBuffer *buffer=gtk_text_view_get_buffer(GTK_TEXT_VIEW(state->awg_parameters));GtkTextIter start,end;
            gtk_text_buffer_get_bounds(buffer,&start,&end);char *raw=gtk_text_buffer_get_text(buffer,&start,&end,FALSE);
            gboolean valid=linux_external_amnezia_v14(builder,raw,validation_error);g_free(raw);
            if(!valid){g_object_unref(builder);return NULL;}
        }
    }
    if(!linux_external_openvpn_v14(state,builder,protocol,validation_error)||!linux_external_server_peer_v14(state,builder,protocol,validation_error)||!linux_external_transport_fields_v14(state,builder,protocol,validation_error)){g_object_unref(builder);return NULL;}
    json_builder_end_object(builder);JsonNode *root=json_builder_get_root(builder);JsonGenerator *generator=json_generator_new();json_generator_set_root(generator,root);char *payload=json_generator_to_data(generator,NULL);g_object_unref(generator);json_node_free(root);g_object_unref(builder);return payload;
}

static gboolean linux_external_save_v14(LinuxExternalNodeV14 *state) {
    if(!linux_external_mutation_idle_v14(state->app)){gtk_label_set_text(GTK_LABEL(state->status),"VPN state changed while the external-node dialog was open. Nothing was saved.");return FALSE;}
    char *validation=NULL;char *payload=linux_external_payload_v14(state,&validation);
    if(payload==NULL){gtk_label_set_text(GTK_LABEL(state->status),validation!=NULL?validation:"Invalid external-node form.");g_free(validation);return FALSE;}
    Buffer out={0};char *err=NULL;gboolean ok=api_request("/api/external-profile/create","POST",payload,25000,&out,&err);g_free(payload);
    if(!ok){char *message=g_strdup_printf("External node rejected: %s",err!=NULL?err:"unknown error");gtk_label_set_text(GTK_LABEL(state->status),message);g_free(message);g_free(err);free(out.data);return FALSE;}
    gtk_label_set_text(GTK_LABEL(state->status),"External node saved and selected. Use a Router entry for Home AdGuard, or choose a resolver in DNS for Direct.");append_diag(state->app,"Saved validated typed external node (WG/AWG/SOCKS5/HTTP/HTTPS/Shadowsocks/Hysteria2) with real coordinates only when explicitly supplied.");refresh_all(state->app);g_free(err);free(out.data);return TRUE;
}

static void on_linux_external_node_v14(GtkButton *button, gpointer data) {
    (void)button;App *app=data;if(app==NULL)return;
    if(!linux_external_mutation_idle_v14(app)){append_diag(app,"Disconnect or let the active VPN transition finish before adding an external node. Unknown controller state fails closed.");return;}
    LinuxExternalNodeV14 state={0};state.app=app;
    state.dialog=gtk_dialog_new_with_buttons("Add external node",GTK_WINDOW(app->window),GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT,"Cancel",GTK_RESPONSE_CANCEL,"Save node",GTK_RESPONSE_ACCEPT,NULL);gtk_window_set_default_size(GTK_WINDOW(state.dialog),780,820);
    GtkWidget *content=gtk_dialog_get_content_area(GTK_DIALOG(state.dialog));GtkWidget *box=gtk_box_new(GTK_ORIENTATION_VERTICAL,6);gtk_container_set_border_width(GTK_CONTAINER(box),14);
    GtkWidget *intro=gtk_label_new("Create a full-device external node. For OpenVPN, paste your private inline profile below. Tor has its own Tor bridges form. Home AdGuard is the default through a Router entry. For Direct, choose a resolver in DNS.");gtk_label_set_line_wrap(GTK_LABEL(intro),TRUE);gtk_label_set_xalign(GTK_LABEL(intro),0.0f);gtk_box_pack_start(GTK_BOX(box),intro,FALSE,FALSE,0);
    state.protocol=gtk_combo_box_text_new();gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.protocol),"wireguard","WireGuard");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.protocol),"amneziawg","AmneziaWG");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.protocol),"socks5","SOCKS5");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.protocol),"http-connect","HTTP CONNECT");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.protocol),"https-connect","HTTPS CONNECT");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.protocol),"shadowsocks","Shadowsocks");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.protocol),"hysteria2","Hysteria2");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.protocol),"openvpn","OpenVPN");gtk_combo_box_set_active_id(GTK_COMBO_BOX(state.protocol),"wireguard");gtk_box_pack_start(GTK_BOX(box),state.protocol,FALSE,FALSE,0);
    state.name=linux_external_field_v14("Display name",FALSE);state.server=linux_external_field_v14("Server IP / hostname",FALSE);state.port=linux_external_field_v14("Port",FALSE);state.expected=linux_external_field_v14("Expected public exit IP",FALSE);state.location=linux_external_field_v14("Location label (optional, e.g. Austin, TX)",FALSE);state.latitude=linux_external_field_v14("Latitude -90..90 (optional)",FALSE);state.longitude=linux_external_field_v14("Longitude -180..180 (optional)",FALSE);state.username=linux_external_field_v14("Username (proxy only)",FALSE);state.password=linux_external_field_v14("Password / proxy credential",TRUE);state.method=linux_external_field_v14("Shadowsocks method",FALSE);state.secret=linux_external_field_v14("Shadowsocks / Hysteria2 secret",TRUE);state.tls_name=linux_external_field_v14("TLS server name / SNI",FALSE);state.wg_private=linux_external_field_v14("WG private key",TRUE);state.wg_peer=linux_external_field_v14("WG peer public key",FALSE);state.wg_psk=linux_external_field_v14("WG preshared key (optional)",TRUE);state.wg_addresses=linux_external_field_v14("WG addresses, comma-separated CIDRs",FALSE);state.wg_allowed=linux_external_field_v14("WG AllowedIPs, comma-separated CIDRs",FALSE);state.wg_dns=linux_external_field_v14("WG DNS IPs, comma-separated",FALSE);state.wg_mtu=linux_external_field_v14("WG MTU (optional)",FALSE);
    state.wg_keepalive=linux_external_field_v14("WG / AWG keepalive seconds 0..65535 (blank means disabled)",FALSE);
    GtkWidget *fields[]={state.name,state.server,state.port,state.expected,state.location,state.latitude,state.longitude,state.username,state.password,state.method,state.secret,state.tls_name,state.wg_private,state.wg_peer,state.wg_psk,state.wg_addresses,state.wg_allowed,state.wg_dns,state.wg_mtu,state.wg_keepalive};for(guint i=0;i<G_N_ELEMENTS(fields);i++)gtk_box_pack_start(GTK_BOX(box),fields[i],FALSE,FALSE,0);
    GtkWidget *external_note=gtk_label_new("Optional Server / Compare: use a Router entry and an HTTPS response probe on this external server's public IP. WireGuard, AmneziaWG, Shadowsocks, Hysteria2 and authenticated SOCKS5 / HTTP(S) are supported. Start Layers require matching server provisioning; AES + XOR keeps authenticated encryption.");gtk_label_set_line_wrap(GTK_LABEL(external_note),TRUE);gtk_label_set_xalign(GTK_LABEL(external_note),0.0f);gtk_box_pack_start(GTK_BOX(box),external_note,FALSE,FALSE,0);
    state.response_url=linux_external_field_v14("HTTPS response URL on this external server",FALSE);state.response_name=linux_external_field_v14("Response certificate server name (when needed)",FALSE);
    state.start_layer=gtk_combo_box_text_new();gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.start_layer),"off","External Start Layer: Off");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.start_layer),"aes-256-gcm","AES-256-GCM");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.start_layer),"aes-256-gcm+xor-whitening","AES-256-GCM + XOR whitening");gtk_combo_box_set_active_id(GTK_COMBO_BOX(state.start_layer),"off");
    state.layer_api=linux_external_field_v14("Provisioned layer private API URL",FALSE);state.layer_port=linux_external_field_v14("Provisioned AES transport port",FALSE);state.layer_key=linux_external_field_v14("Provisioned AES key (32-byte Base64)",TRUE);
    GtkWidget *transport_fields[]={state.response_url,state.response_name,state.start_layer,state.layer_api,state.layer_port,state.layer_key};for(guint i=0;i<G_N_ELEMENTS(transport_fields);i++)gtk_box_pack_start(GTK_BOX(box),transport_fields[i],FALSE,FALSE,0);
    GtkWidget *awg_note=gtk_label_new("AmneziaWG: copy all 11 provider values as key=value, one per line or separated by semicolons. Required: Jc, Jmin, Jmax, S1-S4 and H1-H4. Header ranges are preserved.");gtk_label_set_line_wrap(GTK_LABEL(awg_note),TRUE);gtk_label_set_xalign(GTK_LABEL(awg_note),0.0f);gtk_box_pack_start(GTK_BOX(box),awg_note,FALSE,FALSE,0);
    state.awg_parameters=gtk_text_view_new();gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(state.awg_parameters),GTK_WRAP_WORD_CHAR);
    GtkWidget *awg_scroll=gtk_scrolled_window_new(NULL,NULL);gtk_widget_set_size_request(awg_scroll,-1,100);gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(awg_scroll),GTK_POLICY_NEVER,GTK_POLICY_AUTOMATIC);gtk_container_add(GTK_CONTAINER(awg_scroll),state.awg_parameters);gtk_box_pack_start(GTK_BOX(box),awg_scroll,FALSE,FALSE,0);
    GtkWidget *peer_note=gtk_label_new("WireGuard / AmneziaWG Server and Compare: copy the public descriptor of the separate client peer provisioned on the Router entry. Its public identity and addresses must differ from this device. Keep its private key and preshared key on the server. The WG peer public key above still identifies the remote provider. Leave all descriptor fields blank for Local-only use.");gtk_label_set_line_wrap(GTK_LABEL(peer_note),TRUE);gtk_label_set_xalign(GTK_LABEL(peer_note),0.0f);gtk_box_pack_start(GTK_BOX(box),peer_note,FALSE,FALSE,0);
    state.server_peer_public=linux_external_field_v14("Separate server-side client public key",FALSE);state.server_peer_addresses=linux_external_field_v14("Server peer CIDRs, one per family, comma separated",FALSE);state.server_peer_mtu=linux_external_field_v14("Server peer MTU — required with descriptor, 1280..9000",FALSE);state.server_peer_keepalive=linux_external_field_v14("Server peer keepalive seconds — optional, 0..65535",FALSE);
    GtkWidget *peer_fields[]={state.server_peer_public,state.server_peer_addresses,state.server_peer_mtu,state.server_peer_keepalive};for(guint i=0;i<G_N_ELEMENTS(peer_fields);i++)gtk_box_pack_start(GTK_BOX(box),peer_fields[i],FALSE,FALSE,0);
    GtkWidget *openvpn_note=gtk_label_new("OpenVPN: paste the original inline profile and use the username/password fields above. Server / Compare additionally needs this device's private pairing JSON and a separate provider identity on the Router entry. The controller validates the original profile and JSON before saving; scripts and file paths are rejected. Leave pairing blank for Local only.");gtk_label_set_line_wrap(GTK_LABEL(openvpn_note),TRUE);gtk_label_set_xalign(GTK_LABEL(openvpn_note),0.0f);gtk_box_pack_start(GTK_BOX(box),openvpn_note,FALSE,FALSE,0);
    GtkWidget *probes_note=gtk_label_new("For multiple OpenVPN remote hosts, supply a response endpoint for every original remote IP. To add encryption or whitening, paste the matching per-host Start Layer map, choose its AES mode above, and leave single-server response and layer fields blank. Every host needs its own provisioned layer; the original OpenVPN fallback order and credentials are preserved.");gtk_label_set_line_wrap(GTK_LABEL(probes_note),TRUE);gtk_label_set_xalign(GTK_LABEL(probes_note),0.0f);gtk_box_pack_start(GTK_BOX(box),probes_note,FALSE,FALSE,0);
    state.openvpn_config=gtk_text_view_new();state.openvpn_pairing=gtk_text_view_new();state.openvpn_response_probes=gtk_text_view_new();state.openvpn_start_layers=gtk_text_view_new();
    GtkWidget *openvpn_fields[]={state.openvpn_config,state.openvpn_pairing,state.openvpn_response_probes,state.openvpn_start_layers};const char *openvpn_labels[]={"Private inline OpenVPN profile","Private OpenVPN pairing JSON","Private OpenVPN per-remote response map JSON","Private OpenVPN per-host Start Layer map JSON"};
    for(guint i=0;i<G_N_ELEMENTS(openvpn_fields);i++){
        gtk_box_pack_start(GTK_BOX(box),gtk_label_new(openvpn_labels[i]),FALSE,FALSE,0);
        gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(openvpn_fields[i]),GTK_WRAP_WORD_CHAR);
        GtkWidget *field_scroll=gtk_scrolled_window_new(NULL,NULL);gtk_widget_set_size_request(field_scroll,-1,130);gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(field_scroll),GTK_POLICY_NEVER,GTK_POLICY_AUTOMATIC);gtk_container_add(GTK_CONTAINER(field_scroll),openvpn_fields[i]);gtk_box_pack_start(GTK_BOX(box),field_scroll,FALSE,FALSE,0);
    }
    GtkWidget *note=gtk_label_new("Optional coordinates must be real values you provide; Router VPN never fabricates a custom-node pin from IP geolocation. Plain HTTP CONNECT never accepts TLS metadata. HTTPS CONNECT and Hysteria2 require TLS/SNI. The typed maker cannot inject executable paths, arbitrary sing-box JSON, Tor directives, or OpenVPN scripts and file paths.");gtk_label_set_line_wrap(GTK_LABEL(note),TRUE);gtk_label_set_xalign(GTK_LABEL(note),0.0f);gtk_box_pack_start(GTK_BOX(box),note,FALSE,FALSE,0);
    state.status=gtk_label_new("");gtk_label_set_line_wrap(GTK_LABEL(state.status),TRUE);gtk_label_set_xalign(GTK_LABEL(state.status),0.0f);gtk_box_pack_start(GTK_BOX(box),state.status,FALSE,FALSE,0);
    GtkWidget *scroll=gtk_scrolled_window_new(NULL,NULL);gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),GTK_POLICY_NEVER,GTK_POLICY_AUTOMATIC);gtk_container_add(GTK_CONTAINER(scroll),box);gtk_box_pack_start(GTK_BOX(content),scroll,TRUE,TRUE,0);gtk_widget_show_all(state.dialog);
    while(TRUE){int response=gtk_dialog_run(GTK_DIALOG(state.dialog));if(response==GTK_RESPONSE_ACCEPT){if(linux_external_save_v14(&state))break;continue;}break;}gtk_widget_destroy(state.dialog);
}
