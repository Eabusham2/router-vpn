/* Execute the shipping GTK form and its real JsonBuilder serialization.
 * Only the controller request is replaced; this test never starts a VPN. */
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <stdlib.h>
#include <string.h>
typedef struct { GtkWidget *window; } App;
typedef struct { char *data; } Buffer;
static const char *dispatch_execution="local";
static gboolean dispatch_connected=FALSE,dispatch_external=TRUE;
static char *dispatch_path=NULL,*dispatch_body=NULL;
static guint router_dispatches=0;
static const char *dispatch_catalog=NULL;static gboolean dispatch_catalog_failed=FALSE;
static gboolean api_request(const char *path,const char *method,const char *body,int timeout,Buffer *out,char **err){
    (void)method;(void)body;(void)timeout;(void)err;
    if(g_strcmp0(path,"/api/status")==0){out->data=g_strdup_printf("{\"connected\":%s,\"phase\":\"off\"}",dispatch_connected?"true":"false");return TRUE;}
    if(g_strcmp0(path,"/api/profiles")==0&&dispatch_catalog_failed)return FALSE;
    if(g_strcmp0(path,"/api/profiles")==0&&dispatch_catalog!=NULL){out->data=g_strdup(dispatch_catalog);return TRUE;}
    if(g_strcmp0(path,"/api/profiles")==0){out->data=g_strdup_printf("{\"selected_id\":\"captured-exit\",\"profiles\":[{\"id\":\"captured-exit\",\"node_kind\":\"%s\",\"multihop_execution\":\"%s\"}]}",dispatch_external?"external":"router-vpn",dispatch_execution);return TRUE;}
    return FALSE;
}
static JsonNode *parse_json(const char *raw){JsonParser *p=json_parser_new();JsonNode *n=NULL;if(json_parser_load_from_data(p,raw,-1,NULL))n=json_node_copy(json_parser_get_root(p));g_object_unref(p);return n;}
static const char *obj_string(JsonObject *obj,const char *key){return json_object_has_member(obj,key)?json_object_get_string_member(obj,key):"";}
static void append_diag(App *app,const char *text){(void)app;(void)text;}
static void refresh_all(App *app){(void)app;}
#include "routervpn-external-node-v14.inc"
typedef struct { App *app; GtkWidget *multihop; GtkWidget *mode; } LinuxUnifiedV8;
static void post_and_log(App *app,const char *path,const char *body,int timeout,const char *label){(void)app;(void)timeout;(void)label;g_free(dispatch_path);g_free(dispatch_body);dispatch_path=g_strdup(path);dispatch_body=g_strdup(body);}
static void on_linux_multihop_v7(GtkButton *button,App *app){(void)button;(void)app;router_dispatches++;}
static char *linux_unified_custom_layers_for_mode_v8(const char *mode){(void)mode;return NULL;}
static char *strategy_custom_body_v7(const char *layers){(void)layers;return NULL;}
// EXTERNAL_PATH_TEST_HELPERS

static void check(gboolean ok,const char *message){if(!ok){g_printerr("%s\n",message);exit(1);}}
static GtkWidget *field(const char *value){GtkWidget *w=gtk_entry_new();gtk_entry_set_text(GTK_ENTRY(w),value);return w;}
static char *fixture_json_text(JsonNode *node){JsonGenerator *generator=json_generator_new();json_generator_set_root(generator,node);char *text=json_generator_to_data(generator,NULL);g_object_unref(generator);return text;}
static void awg_text(LinuxExternalNodeV14 *s,const char *value){gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->awg_parameters)),value,-1);}
static const char *parameters="Jc=3; Jmin=40; Jmax=900; S1=56; S2=48; S3=24; S4=32; H1=10000000-19999999; H2=20000000-29999999; H3=30000000-39999999; H4=40000000-49999999";

int main(int argc,char **argv){
    gtk_init(&argc,&argv);check(argc==2,"Expected a private fixture output directory");
    LinuxExternalNodeV14 s={0};
    s.protocol=gtk_combo_box_text_new();gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(s.protocol),"wireguard","WireGuard");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(s.protocol),"amneziawg","AmneziaWG");gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.protocol),"amneziawg");
    const char *proxy_protocols[]={"shadowsocks","hysteria2","socks5","http-connect","https-connect"};
    for(guint i=0;i<G_N_ELEMENTS(proxy_protocols);i++)gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(s.protocol),proxy_protocols[i],proxy_protocols[i]);
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(s.protocol),"openvpn","OpenVPN");s.openvpn_config=gtk_text_view_new();s.openvpn_pairing=gtk_text_view_new();s.openvpn_response_probes=gtk_text_view_new();
    s.response_url=field("");s.response_name=field("");s.layer_api=field("");s.layer_port=field("");s.layer_key=field("");s.start_layer=gtk_combo_box_text_new();
    s.server_peer_public=field("");s.server_peer_addresses=field("");s.server_peer_mtu=field("");s.server_peer_keepalive=field("");
    const char *layers[]={"off","aes-256-gcm","aes-256-gcm+xor-whitening"};
    for(guint i=0;i<G_N_ELEMENTS(layers);i++)gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(s.start_layer),layers[i],layers[i]);
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.start_layer),"off");
    s.name=field("Imported AWG fixture");s.server=field("203.0.113.60");s.port=field("51820");s.expected=field("203.0.113.60");s.location=field("");s.latitude=field("");s.longitude=field("");
    s.username=field("");s.password=field("");s.method=field("");s.secret=field("");s.tls_name=field("");
    char private_bytes[32],peer_bytes[32];memset(private_bytes,'p',32);memset(peer_bytes,'q',32);
    char *private_key=g_base64_encode((guchar*)private_bytes,32),*peer_key=g_base64_encode((guchar*)peer_bytes,32);
    s.wg_private=field(private_key);s.wg_peer=field(peer_key);s.wg_psk=field("");s.wg_addresses=field("10.66.0.2/32, fd66::2/128");s.wg_allowed=field("0.0.0.0/0, ::/0");s.wg_dns=field("9.9.9.9");s.wg_mtu=field("1280");s.wg_keepalive=field("17");s.awg_parameters=gtk_text_view_new();awg_text(&s,parameters);
    char *error=NULL,*body=linux_external_payload_v14(&s,&error);check(body!=NULL,error?error:"Valid form rejected");
    JsonNode *root=parse_json(body);check(root!=NULL,"Form emitted invalid JSON");JsonObject *obj=json_node_get_object(root);
    check(g_strcmp0(obj_string(obj,"protocol"),"amneziawg")==0,"AWG protocol was changed");
    check(json_object_get_int_member(obj,"wg_keepalive")==17&&json_object_get_int_member(obj,"wg_mtu")==1280,"Peer settings were changed");
    check(g_strcmp0(obj_string(obj,"wg_private_key"),private_key)==0&&g_strcmp0(obj_string(obj,"wg_peer_public_key"),peer_key)==0,"Peer keys were changed");
    JsonObject *awg=json_object_get_object_member(obj,"awg_parameters");check(json_object_get_size(awg)==11,"AWG fields were lost");
    const char *keys[]={"jc","jmin","jmax","s1","s2","s3","s4","h1","h2","h3","h4"};
    const char *values[]={"3","40","900","56","48","24","32","10000000-19999999","20000000-29999999","30000000-39999999","40000000-49999999"};
    for(guint i=0;i<G_N_ELEMENTS(keys);i++)check(g_strcmp0(obj_string(awg,keys[i]),values[i])==0,"Provider value changed");
    char *output=g_build_filename(argv[1],"amneziawg.json",NULL);check(g_file_set_contents(output,body,-1,NULL),"Fixture write failed");g_free(output);json_node_free(root);g_free(body);
    unsigned count=1;
    const char *bad[]={"","Jc=3","Jc=3;Jc=3","Jc=3;unexpected=4","Jc=3;H1=1--9","Jc=bad"};
    for(guint i=0;i<G_N_ELEMENTS(bad);i++){awg_text(&s,bad[i]);body=linux_external_payload_v14(&s,&error);check(body==NULL,"Malformed parameters accepted");g_free(error);error=NULL;count++;}
    char *duplicate=g_strconcat(parameters,";JC=3",NULL);awg_text(&s,duplicate);body=linux_external_payload_v14(&s,&error);check(body==NULL,"Duplicate complete parameters accepted");g_free(error);error=NULL;g_free(duplicate);count++;
    awg_text(&s,parameters);
    const char *invalid_keepalive[]={"-1","65536","bad"};
    for(guint i=0;i<G_N_ELEMENTS(invalid_keepalive);i++){gtk_entry_set_text(GTK_ENTRY(s.wg_keepalive),invalid_keepalive[i]);body=linux_external_payload_v14(&s,&error);check(body==NULL,"Invalid keepalive accepted");g_free(error);error=NULL;count++;}
    gtk_entry_set_text(GTK_ENTRY(s.wg_keepalive),"17");
    const char *invalid_mtu[]={"1279","9001","bad"};
    for(guint i=0;i<G_N_ELEMENTS(invalid_mtu);i++){gtk_entry_set_text(GTK_ENTRY(s.wg_mtu),invalid_mtu[i]);body=linux_external_payload_v14(&s,&error);check(body==NULL,"Invalid MTU accepted");g_free(error);error=NULL;count++;}
    gtk_entry_set_text(GTK_ENTRY(s.wg_mtu),"1280");gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.protocol),"wireguard");body=linux_external_payload_v14(&s,&error);check(body!=NULL,"WireGuard form regressed");root=parse_json(body);obj=json_node_get_object(root);check(!json_object_has_member(obj,"awg_parameters")&&json_object_get_int_member(obj,"wg_keepalive")==17,"WireGuard was changed into AWG");count++;
    output=g_build_filename(argv[1],"wireguard.json",NULL);check(g_file_set_contents(output,body,-1,NULL),"WireGuard fixture write failed");g_free(output);json_node_free(root);g_free(body);g_free(private_key);g_free(peer_key);
    gtk_entry_set_text(GTK_ENTRY(s.port),"8388");gtk_entry_set_text(GTK_ENTRY(s.response_url),"https://203.0.113.60:8443/node-response");gtk_entry_set_text(GTK_ENTRY(s.response_name),"external.example");
    char key_bytes[32];memset(key_bytes,7,32);char *key=g_base64_encode((guchar*)key_bytes,32);
    for(guint pi=0;pi<G_N_ELEMENTS(proxy_protocols);pi++)for(guint li=0;li<G_N_ELEMENTS(layers);li++){
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.protocol),proxy_protocols[pi]);gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.start_layer),layers[li]);
        gtk_entry_set_text(GTK_ENTRY(s.username)," user literal ");gtk_entry_set_text(GTK_ENTRY(s.password)," password literal ");gtk_entry_set_text(GTK_ENTRY(s.method),"aes-256-gcm");gtk_entry_set_text(GTK_ENTRY(s.secret)," private proxy secret ");gtk_entry_set_text(GTK_ENTRY(s.tls_name),"external.example");
        gtk_entry_set_text(GTK_ENTRY(s.layer_api),li?"http://10.77.0.1:8787":"");gtk_entry_set_text(GTK_ENTRY(s.layer_port),li?"8389":"");gtk_entry_set_text(GTK_ENTRY(s.layer_key),li?key:"");
        body=linux_external_payload_v14(&s,&error);check(body!=NULL,error?error:"Valid proxy/layer form rejected");root=parse_json(body);obj=json_node_get_object(root);
        check(g_strcmp0(obj_string(obj,"start_layer"),layers[li])==0,"Selected layer changed");JsonObject *probe=json_object_get_object_member(obj,"response_probe");check(g_strcmp0(obj_string(probe,"url"),"https://203.0.113.60:8443/node-response")==0&&g_strcmp0(obj_string(probe,"server_name"),"external.example")==0,"Response endpoint changed");
        if(pi>=2)check(g_strcmp0(obj_string(obj,"username")," user literal ")==0&&g_strcmp0(obj_string(obj,"password")," password literal ")==0,"Proxy credential whitespace changed");
        if(li==0)check(!json_object_has_member(obj,"start_layer_provision"),"Off retained private provision");
        else{JsonObject *provision=json_object_get_object_member(obj,"start_layer_provision"),*transport=json_object_get_object_member(provision,"transport");check(g_strcmp0(obj_string(provision,"mode"),layers[li])==0&&g_strcmp0(obj_string(transport,"password"),key)==0&&g_strcmp0(obj_string(transport,"server"),"203.0.113.60")==0,"Provision ownership changed");}
        char *name=g_strdup_printf("%s-%s.json",proxy_protocols[pi],layers[li]);output=g_build_filename(argv[1],name,NULL);check(g_file_set_contents(output,body,-1,NULL),"Proxy fixture write failed");g_free(output);g_free(name);json_node_free(root);g_free(body);count++;
    }
    const char *bad_ports[]={"","0","65536","invalid"};
    for(guint i=0;i<G_N_ELEMENTS(bad_ports);i++){gtk_entry_set_text(GTK_ENTRY(s.layer_port),bad_ports[i]);body=linux_external_payload_v14(&s,&error);check(body==NULL,"Invalid provisioned port accepted");g_free(error);error=NULL;count++;}
    gtk_entry_set_text(GTK_ENTRY(s.layer_port),"8389");gtk_entry_set_text(GTK_ENTRY(s.layer_key),"");body=linux_external_payload_v14(&s,&error);check(body==NULL,"Missing provisioned key accepted");g_free(error);error=NULL;count++;
    gtk_entry_set_text(GTK_ENTRY(s.layer_key),key);gtk_entry_set_text(GTK_ENTRY(s.layer_api),"");body=linux_external_payload_v14(&s,&error);check(body==NULL,"Missing provisioned API accepted");g_free(error);error=NULL;count++;
    gtk_entry_set_text(GTK_ENTRY(s.layer_api),"http://10.77.0.1:8787");gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.start_layer),"off");body=linux_external_payload_v14(&s,&error);check(body==NULL,"Off silently discarded provision");g_free(error);error=NULL;count++;
    gtk_entry_set_text(GTK_ENTRY(s.layer_api),"");gtk_entry_set_text(GTK_ENTRY(s.layer_port),"");gtk_entry_set_text(GTK_ENTRY(s.layer_key),"");gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.protocol),"wireguard");body=linux_external_payload_v14(&s,&error);check(body!=NULL,"Local WireGuard response probe incorrectly required a server peer");root=parse_json(body);check(!json_object_has_member(json_node_get_object(root),"server_peer"),"Local-only packet form invented a server peer");json_node_free(root);g_free(body);count++;
    const char *server_public="bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg=";
    gtk_entry_set_text(GTK_ENTRY(s.server_peer_public),server_public);gtk_entry_set_text(GTK_ENTRY(s.server_peer_addresses),"10.66.0.3/32, fd66::3/128");gtk_entry_set_text(GTK_ENTRY(s.server_peer_mtu),"1360");gtk_entry_set_text(GTK_ENTRY(s.server_peer_keepalive),"25");
    const char *packets[]={"wireguard","amneziawg"};
    for(guint pi=0;pi<G_N_ELEMENTS(packets);pi++)for(guint li=0;li<G_N_ELEMENTS(layers);li++){
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.protocol),packets[pi]);gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.start_layer),layers[li]);gtk_entry_set_text(GTK_ENTRY(s.port),"51820");
        gtk_entry_set_text(GTK_ENTRY(s.layer_api),li?"http://10.77.0.1:8787":"");gtk_entry_set_text(GTK_ENTRY(s.layer_port),li?"8389":"");gtk_entry_set_text(GTK_ENTRY(s.layer_key),li?key:"");
        body=linux_external_payload_v14(&s,&error);check(body!=NULL,error?error:"Packet form failed");root=parse_json(body);obj=json_node_get_object(root);
        JsonObject *peer=json_object_get_object_member(obj,"server_peer");JsonArray *addresses=json_object_get_array_member(peer,"addresses");
        check(json_object_get_size(peer)==4&&g_strcmp0(obj_string(peer,"public_key"),server_public)==0&&json_object_get_int_member(peer,"mtu")==1360&&json_object_get_int_member(peer,"persistent_keepalive_interval")==25&&json_array_get_length(addresses)==2&&g_strcmp0(json_array_get_string_element(addresses,0),"10.66.0.3/32")==0&&g_strcmp0(json_array_get_string_element(addresses,1),"fd66::3/128")==0,"Separate server descriptor changed");
        check(g_strcmp0(obj_string(obj,"wg_private_key"),gtk_entry_get_text(GTK_ENTRY(s.wg_private)))==0&&g_strcmp0(json_array_get_string_element(json_object_get_array_member(obj,"wg_addresses"),0),"10.66.0.2/32")==0,"Server descriptor replaced local private peer");
        char *name=g_strdup_printf("%s-%s.json",packets[pi],layers[li]);output=g_build_filename(argv[1],name,NULL);check(g_file_set_contents(output,body,-1,NULL),"Packet fixture write failed");g_free(output);g_free(name);json_node_free(root);g_free(body);count++;
    }
    GtkWidget *bad_fields[]={s.server_peer_public,s.server_peer_public,s.server_peer_addresses,s.server_peer_mtu,s.server_peer_mtu,s.server_peer_mtu,s.server_peer_mtu,s.server_peer_keepalive,s.server_peer_keepalive};const char *bad_values[]={"","invalid","","","1279","9001","bad","-1","65536"};
    for(guint i=0;i<G_N_ELEMENTS(bad_fields);i++){char *previous=g_strdup(gtk_entry_get_text(GTK_ENTRY(bad_fields[i])));gtk_entry_set_text(GTK_ENTRY(bad_fields[i]),bad_values[i]);body=linux_external_payload_v14(&s,&error);check(body==NULL,"Incomplete or invalid server descriptor reached controller");g_free(error);error=NULL;gtk_entry_set_text(GTK_ENTRY(bad_fields[i]),previous);g_free(previous);count++;}
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.protocol),"shadowsocks");body=linux_external_payload_v14(&s,&error);check(body==NULL,"Proxy accepted packet-only descriptor");g_free(error);error=NULL;count++;
    GtkWidget *peer_fields[]={s.server_peer_public,s.server_peer_addresses,s.server_peer_mtu,s.server_peer_keepalive};for(guint i=0;i<G_N_ELEMENTS(peer_fields);i++)gtk_entry_set_text(GTK_ENTRY(peer_fields[i]),"");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.start_layer),"off");gtk_entry_set_text(GTK_ENTRY(s.layer_api),"");gtk_entry_set_text(GTK_ENTRY(s.layer_port),"");gtk_entry_set_text(GTK_ENTRY(s.layer_key),"");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.protocol),"shadowsocks");gtk_entry_set_text(GTK_ENTRY(s.response_url),"");body=linux_external_payload_v14(&s,&error);check(body==NULL,"Partial response endpoint accepted");g_free(error);error=NULL;count++;
    char *openvpn_path=g_build_filename(argv[1],"external-openvpn-client.json",NULL),*openvpn_raw=NULL;
    check(g_file_get_contents(openvpn_path,&openvpn_raw,NULL,NULL),"Synthetic OpenVPN fixture missing");g_free(openvpn_path);
    JsonNode *openvpn_fixture=parse_json(openvpn_raw);g_free(openvpn_raw);JsonObject *openvpn_layers=json_object_get_object_member(json_node_get_object(openvpn_fixture),"layers");
    for(guint li=0;li<G_N_ELEMENTS(layers);li++){
        JsonObject *fixture=json_object_get_object_member(openvpn_layers,layers[li]),*external=json_object_get_object_member(fixture,"external"),*original=json_object_get_object_member(external,"openvpn"),*probe=json_object_get_object_member(external,"response_probe");
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.protocol),"openvpn");gtk_entry_set_text(GTK_ENTRY(s.server),"203.0.113.20");gtk_entry_set_text(GTK_ENTRY(s.expected),obj_string(external,"expected_public_ip"));
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s.openvpn_config)),obj_string(original,"config"),-1);
        JsonGenerator *pairing_generator=json_generator_new();json_generator_set_root(pairing_generator,json_object_get_member(external,"openvpn_pairing"));char *pairing_text=json_generator_to_data(pairing_generator,NULL);g_object_unref(pairing_generator);
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s.openvpn_pairing)),pairing_text,-1);
        gtk_entry_set_text(GTK_ENTRY(s.username),obj_string(original,"username"));gtk_entry_set_text(GTK_ENTRY(s.password),obj_string(original,"password"));gtk_entry_set_text(GTK_ENTRY(s.response_url),obj_string(probe,"url"));gtk_entry_set_text(GTK_ENTRY(s.response_name),obj_string(probe,"server_name"));gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.start_layer),layers[li]);
        gtk_entry_set_text(GTK_ENTRY(s.layer_api),"");gtk_entry_set_text(GTK_ENTRY(s.layer_port),"");gtk_entry_set_text(GTK_ENTRY(s.layer_key),"");
        if(li>0){JsonObject *layer=json_object_get_object_member(external,"start_layer"),*transport=json_object_get_object_member(layer,"transport");char *number=g_strdup_printf("%d",(int)json_object_get_int_member(transport,"server_port"));gtk_entry_set_text(GTK_ENTRY(s.layer_api),obj_string(layer,"api"));gtk_entry_set_text(GTK_ENTRY(s.layer_port),number);gtk_entry_set_text(GTK_ENTRY(s.layer_key),obj_string(transport,"password"));g_free(number);}
        body=linux_external_payload_v14(&s,&error);check(body!=NULL,error?error:"OpenVPN form failed");root=parse_json(body);obj=json_node_get_object(root);JsonObject *saved_openvpn=json_object_get_object_member(obj,"openvpn");
        check(g_strcmp0(obj_string(saved_openvpn,"config"),obj_string(original,"config"))==0&&g_strcmp0(obj_string(saved_openvpn,"username"),obj_string(original,"username"))==0&&g_strcmp0(obj_string(saved_openvpn,"password"),obj_string(original,"password"))==0&&g_strcmp0(obj_string(obj,"openvpn_pairing_json"),pairing_text)==0,"OpenVPN source or private pairing bytes changed");g_free(pairing_text);
        char *name=g_strdup_printf("openvpn-%s.json",layers[li]);output=g_build_filename(argv[1],name,NULL);check(g_file_set_contents(output,body,-1,NULL),"OpenVPN payload write failed");g_free(name);g_free(output);g_free(body);json_node_free(root);count++;
    }
    char *original_config=linux_external_text_v14(s.openvpn_config),*multiremote=g_strconcat(original_config,"remote 203.0.113.21 443 tcp\n",NULL);g_free(original_config);gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s.openvpn_config)),multiremote,-1);g_free(multiremote);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s.openvpn_pairing)),"",-1);gtk_entry_set_text(GTK_ENTRY(s.response_url),"");gtk_entry_set_text(GTK_ENTRY(s.response_name),"");gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.start_layer),"off");gtk_entry_set_text(GTK_ENTRY(s.layer_api),"");gtk_entry_set_text(GTK_ENTRY(s.layer_port),"");gtk_entry_set_text(GTK_ENTRY(s.layer_key),"");
    body=linux_external_payload_v14(&s,&error);check(body!=NULL,"Unpaired Local multiremote rejected");root=parse_json(body);check(!json_object_has_member(json_node_get_object(root),"openvpn_pairing_json"),"Plain Local profile acquired pairing");output=g_build_filename(argv[1],"openvpn-local-multiremote.json",NULL);check(g_file_set_contents(output,body,-1,NULL),"Local multiremote write failed");g_free(output);g_free(body);json_node_free(root);count++;
    char *multi_path=g_build_filename(argv[1],"external-openvpn-multihost-client.json",NULL),*multi_raw=NULL;check(g_file_get_contents(multi_path,&multi_raw,NULL,NULL),"Synthetic multi-host OpenVPN fixture missing");g_free(multi_path);JsonNode *multi_fixture=parse_json(multi_raw);g_free(multi_raw);JsonObject *multi=json_object_get_object_member(json_node_get_object(multi_fixture),"external"),*multi_inline=json_object_get_object_member(multi,"openvpn"),*probes=json_object_get_object_member(multi,"openvpn_response_probes");
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s.openvpn_config)),obj_string(multi_inline,"config"),-1);gtk_entry_set_text(GTK_ENTRY(s.username),obj_string(multi_inline,"username"));gtk_entry_set_text(GTK_ENTRY(s.password),obj_string(multi_inline,"password"));gtk_entry_set_text(GTK_ENTRY(s.expected),obj_string(multi,"expected_public_ip"));
    char *pairing_raw=fixture_json_text(json_object_get_member(multi,"openvpn_pairing")),*map_raw=fixture_json_text(json_object_get_member(multi,"openvpn_response_probes")),*pairing_text=g_strconcat("\n",pairing_raw,"\n",NULL),*map_text=g_strconcat("\n",map_raw,"\n",NULL);g_free(pairing_raw);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s.openvpn_pairing)),pairing_text,-1);gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s.openvpn_response_probes)),map_text,-1);
    body=linux_external_payload_v14(&s,&error);check(body!=NULL,error?error:"OpenVPN multi-host form rejected");root=parse_json(body);obj=json_node_get_object(root);JsonObject *saved_multi=json_object_get_object_member(obj,"openvpn");check(g_strcmp0(obj_string(obj,"openvpn_response_probes_json"),map_text)==0&&g_strcmp0(obj_string(obj,"openvpn_pairing_json"),pairing_text)==0&&g_strcmp0(obj_string(saved_multi,"config"),obj_string(multi_inline,"config"))==0&&g_strcmp0(obj_string(saved_multi,"username"),obj_string(multi_inline,"username"))==0&&g_strcmp0(obj_string(saved_multi,"password"),obj_string(multi_inline,"password"))==0&&!json_object_has_member(obj,"response_probe"),"Actual OpenVPN callback changed private map, source, or credentials");
    output=g_build_filename(argv[1],"openvpn-multihost.json",NULL);check(g_file_set_contents(output,body,-1,NULL),"OpenVPN map payload write failed");g_free(output);g_free(body);json_node_free(root);count++;
    GList *hosts=json_object_get_members(probes);const char *first_host=hosts->data;char *first_probe=fixture_json_text(json_object_get_member(probes,first_host)),*duplicate_map=g_strdup_printf("{\"%s\":%s,%s",first_host,first_probe,map_raw+1);g_list_free(hosts);g_free(first_probe);gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s.openvpn_response_probes)),duplicate_map,-1);
    body=linux_external_payload_v14(&s,&error);check(body!=NULL,"Raw private map unexpectedly parsed by native form");root=parse_json(body);check(g_strcmp0(obj_string(json_node_get_object(root),"openvpn_response_probes_json"),duplicate_map)==0,"Native OpenVPN callback parsed or changed raw duplicate map before strict controller validation");output=g_build_filename(argv[1],"openvpn-multihost-duplicate.json",NULL);check(g_file_set_contents(output,body,-1,NULL),"Duplicate map payload write failed");g_free(output);g_free(body);json_node_free(root);count++;
    char *oversized=g_strnfill(40961,'x');gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s.openvpn_response_probes)),oversized,-1);g_free(oversized);body=linux_external_payload_v14(&s,&error);check(body==NULL,"Oversized OpenVPN map reached controller");g_free(error);error=NULL;count++;gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s.openvpn_response_probes)),"",-1);g_free(pairing_text);g_free(map_text);g_free(map_raw);g_free(duplicate_map);json_node_free(multi_fixture);
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.protocol),"shadowsocks");body=linux_external_payload_v14(&s,&error);check(body==NULL,"Changing protocol discarded OpenVPN source");g_free(error);error=NULL;count++;
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s.openvpn_config)),"",-1);gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.protocol),"openvpn");body=linux_external_payload_v14(&s,&error);check(body==NULL,"Empty OpenVPN source reached controller");g_free(error);error=NULL;count++;json_node_free(openvpn_fixture);
    JsonObject *profile=json_object_new();check(g_strcmp0(external_saved_execution_v4(profile),"local")==0,"Legacy external default is not Local");count++;
    const char *executions[]={"local","server","auto"};
    for(guint i=0;i<G_N_ELEMENTS(executions);i++){
        json_object_set_string_member(profile,"multihop_execution",executions[i]);check(g_strcmp0(external_saved_execution_v4(profile),executions[i])==0,"Saved execution changed");
        body=json_external_hop_body("captured-exit","captured-entry",executions[i],FALSE);check(body!=NULL,"Valid captured external request rejected");root=parse_json(body);obj=json_node_get_object(root);check(json_object_get_size(obj)==3&&g_strcmp0(obj_string(obj,"profile_id"),"captured-exit")==0&&g_strcmp0(obj_string(obj,"entry_id"),"captured-entry")==0&&g_strcmp0(obj_string(obj,"execution"),executions[i])==0,"Captured execution mixed unrelated state");json_node_free(root);g_free(body);
        body=json_external_hop_body("captured-exit","",executions[i],TRUE);root=parse_json(body);obj=json_node_get_object(root);check(json_object_get_boolean_member(obj,"direct")&&g_strcmp0(obj_string(obj,"execution"),"local")==0&&!json_object_has_member(obj,"entry_id"),"Direct retained Server / Compare");json_node_free(root);g_free(body);count++;
    }
    check(json_external_hop_body("captured-exit","captured-exit","local",FALSE)==NULL,"Self-hop accepted");count++;
    check(json_external_hop_body("captured-exit","entry","invalid",FALSE)==NULL,"Invalid execution accepted");count++;
    json_object_set_string_member(profile,"multihop_execution","invalid");check(external_saved_execution_v4(profile)==NULL,"Invalid saved execution silently replaced");json_object_unref(profile);g_free(key);count++;
    const char *eligible[]={"wireguard","amneziawg","shadowsocks","hysteria2","socks5","http-connect","https-connect","openvpn"};
    JsonNode *captured_node=parse_json("{\"id\":\"exit\",\"node_kind\":\"external\",\"external\":{\"protocol\":\"wireguard\",\"has_response_probe\":true,\"has_server_peer\":true}}");JsonObject *captured=json_node_get_object(captured_node);
    for(guint pi=0;pi<G_N_ELEMENTS(eligible);pi++)for(guint ei=0;ei<G_N_ELEMENTS(executions);ei++){
        json_object_set_string_member(json_object_get_object_member(captured,"external"),"protocol",eligible[pi]);
        gboolean openvpn=g_strcmp0(eligible[pi],"openvpn")==0;json_object_set_boolean_member(json_object_get_object_member(captured,"external"),"has_openvpn_pairing",openvpn);
        char *catalog=g_strdup_printf("{\"profiles\":[{\"id\":\"exit\",\"node_kind\":\"external\",\"external\":{\"protocol\":\"%s\",\"has_response_probe\":true,\"has_server_peer\":true,\"has_openvpn_pairing\":%s}},{\"id\":\"entry\",\"node_kind\":\"router-vpn\"}]}",eligible[pi],openvpn?"true":"false");JsonNode *current=parse_json(catalog);g_free(catalog);
        body=external_path_current_body_v4(captured,current,"entry",executions[ei],FALSE,&error);check(body!=NULL,error?error:"Eligible captured external path rejected");root=parse_json(body);obj=json_node_get_object(root);check(g_strcmp0(obj_string(obj,"profile_id"),"exit")==0&&g_strcmp0(obj_string(obj,"entry_id"),"entry")==0&&g_strcmp0(obj_string(obj,"execution"),executions[ei])==0,"External path changed captured identity");json_node_free(root);json_node_free(current);g_free(body);count++;
    }
    JsonNode *replaced_pairing=parse_json("{\"profiles\":[{\"id\":\"exit\",\"node_kind\":\"external\",\"external\":{\"protocol\":\"openvpn\",\"has_response_probe\":true,\"has_server_peer\":true,\"has_openvpn_pairing\":false}},{\"id\":\"entry\",\"node_kind\":\"router-vpn\"}]}");
    body=external_path_current_body_v4(captured,replaced_pairing,"entry","auto",FALSE,&error);check(body==NULL,"Stale OpenVPN pairing eligibility reached controller");g_free(error);error=NULL;count++;
    json_object_set_boolean_member(json_object_get_object_member(captured,"external"),"has_openvpn_pairing",FALSE);
    body=external_path_current_body_v4(captured,replaced_pairing,"entry","auto",FALSE,&error);check(body==NULL,"OpenVPN comparison accepted missing independent pairing");g_free(error);error=NULL;json_node_free(replaced_pairing);count++;
    json_object_set_string_member(json_object_get_object_member(captured,"external"),"protocol","wireguard");
    for(guint ci=0;ci<6;ci++){
        JsonNode *current=parse_json("{\"profiles\":[{\"id\":\"exit\",\"node_kind\":\"external\",\"external\":{\"protocol\":\"wireguard\",\"has_response_probe\":true,\"has_server_peer\":true}},{\"id\":\"entry\",\"node_kind\":\"router-vpn\"}]}");JsonArray *catalog=json_object_get_array_member(json_node_get_object(current),"profiles");JsonObject *fresh=json_array_get_object_element(catalog,0),*ext=json_object_get_object_member(fresh,"external");
        if(ci==0)json_array_remove_element(catalog,0);
        if(ci==1)json_array_add_element(catalog,json_node_copy(captured_node));
        if(ci==2)json_object_set_string_member(ext,"protocol","amneziawg");
        if(ci==3)json_object_set_boolean_member(ext,"has_server_peer",FALSE);
        if(ci==4)json_object_set_boolean_member(ext,"has_response_probe",FALSE);
        if(ci==5)json_array_remove_element(catalog,1);
        body=external_path_current_body_v4(captured,current,"entry","server",FALSE,&error);check(body==NULL,"Stale external path identity accepted");g_free(error);error=NULL;json_node_free(current);count++;
    }
    char *catalog_path=g_build_filename(argv[1],"entry-mode-catalog.json",NULL),*catalog_text=NULL;
    check(g_file_get_contents(catalog_path,&catalog_text,NULL,NULL),"Shipping entry-mode capability response missing");g_free(catalog_path);
    JsonNode *mode_catalog=parse_json(catalog_text);g_free(catalog_text);JsonArray *entry_modes=json_object_get_array_member(json_node_get_object(mode_catalog),"router_vpn_entry_modes");
    check(entry_modes!=NULL&&json_array_get_length(entry_modes)==19,"Native Router mode catalog changed");
    json_object_set_string_member(captured,"base_tunnel","wg");json_object_set_string_member(captured,"multihop_entry_mode","wg");json_object_set_string_member(json_object_get_object_member(captured,"external"),"protocol","shadowsocks");
    JsonNode *mode_current=parse_json("{\"profiles\":[{\"id\":\"entry\",\"node_kind\":\"router-vpn\",\"base_tunnel\":\"awg\"},{\"id\":\"ordinary\",\"node_kind\":\"external\"}]}");
    JsonArray *mode_nodes=json_object_get_array_member(json_node_get_object(mode_current),"profiles");
    JsonNode *mode_exit=parse_json("{\"id\":\"exit\",\"node_kind\":\"external\",\"base_tunnel\":\"wg\",\"multihop_entry_mode\":\"wg\",\"external\":{\"protocol\":\"shadowsocks\",\"has_response_probe\":true,\"has_server_peer\":true}}");json_array_add_element(mode_nodes,mode_exit);
    JsonObject *mode_entry=json_array_get_object_element(mode_nodes,0);
    for(guint mi=0;mi<json_array_get_length(entry_modes);mi++)for(guint ei=0;ei<G_N_ELEMENTS(executions);ei++){
        const char *mode=obj_string(json_array_get_object_element(entry_modes,mi),"id");
        body=external_path_mode_body_v4(captured,mode_current,"entry",executions[ei],FALSE,mode,entry_modes,&error);check(body!=NULL,error?error:"Exact native entry rejected");root=parse_json(body);obj=json_node_get_object(root);
        check(g_strcmp0(obj_string(obj,"profile_id"),"exit")==0&&g_strcmp0(obj_string(obj,"entry_id"),"entry")==0&&g_strcmp0(obj_string(obj,"entry_mode"),mode)==0&&g_strcmp0(obj_string(obj,"execution"),executions[ei])==0,"Exact Router mode changed");
        char *name=g_strdup_printf("entry-mode-%s-%s.json",mode,executions[ei]);output=g_build_filename(argv[1],name,NULL);check(g_file_set_contents(output,body,-1,NULL),"Entry mode fixture write failed");g_free(name);g_free(output);g_free(body);json_node_free(root);count++;
    }
    char *mode=external_entry_mode_v4(captured,mode_entry,"",entry_modes,&error);check(mode!=NULL&&g_strcmp0(mode,"awg2-fast")==0,"Entry saved AWG base changed");g_free(mode);count++;
    json_object_set_string_member(mode_entry,"base_tunnel","wg");json_object_set_string_member(captured,"base_tunnel","awg");
    mode=external_entry_mode_v4(captured,mode_entry,"",entry_modes,&error);check(mode!=NULL&&g_strcmp0(mode,"wg")==0,"Exit base overrode selected entry WG");g_free(mode);count++;
    const char *bad_modes[]={"all","smart-auto","custom","auto","unknown"," wg"};
    for(guint mi=0;mi<G_N_ELEMENTS(bad_modes);mi++){
        body=external_path_mode_body_v4(captured,mode_current,"entry","local",FALSE,bad_modes[mi],entry_modes,&error);check(body==NULL,"Uncompiled entry mode reached controller");g_free(error);error=NULL;count++;
    }
    body=external_path_mode_body_v4(captured,mode_current,"ordinary","local",FALSE,"wg",entry_modes,&error);check(body==NULL,"External entry accepted Router mode");g_free(error);error=NULL;count++;
    body=external_path_mode_body_v4(captured,mode_current,"","local",TRUE,"wg",entry_modes,&error);check(body==NULL,"Direct accepted Router mode");g_free(error);error=NULL;count++;
    body=external_path_mode_body_v4(captured,mode_current,"","local",TRUE,"",entry_modes,&error);check(body!=NULL,"Direct failed with disabled Router mode");root=parse_json(body);check(!json_object_has_member(json_node_get_object(root),"entry_mode"),"Direct retained Router mode");json_node_free(root);g_free(body);count++;
    body=external_path_mode_body_v4(captured,mode_current,"ordinary","local",FALSE,"",entry_modes,&error);check(body!=NULL,"External entry failed with disabled Router mode");root=parse_json(body);check(!json_object_has_member(json_node_get_object(root),"entry_mode"),"External entry retained Router mode");json_node_free(root);g_free(body);count++;
    json_object_set_string_member(json_array_get_object_element(mode_nodes,2),"multihop_entry_mode","hysteria2");
    body=external_path_mode_body_v4(captured,mode_current,"entry","local",FALSE,"wg",entry_modes,&error);check(body==NULL,"Changed saved entry mode owner accepted");g_free(error);error=NULL;count++;
    json_node_free(mode_current);json_node_free(mode_catalog);
    json_node_free(captured_node);
    App app={0};LinuxUnifiedV8 dispatch={.app=&app,.multihop=gtk_check_button_new(),.mode=gtk_combo_box_text_new()};
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(dispatch.multihop),TRUE);
    for(guint i=0;i<G_N_ELEMENTS(executions);i++){
        dispatch_execution=executions[i];g_clear_pointer(&dispatch_path,g_free);g_clear_pointer(&dispatch_body,g_free);router_dispatches=0;
        linux_unified_connect_v8(NULL,&dispatch);
        check(router_dispatches==0&&g_strcmp0(dispatch_path,"/api/external-profile/connect")==0&&dispatch_body!=NULL,"Unrelated Router toggle bypassed primary external Connect");
        root=parse_json(dispatch_body);obj=json_node_get_object(root);check(g_strcmp0(obj_string(obj,"profile_id"),"captured-exit")==0&&g_strcmp0(obj_string(obj,"execution"),executions[i])==0&&json_object_get_size(obj)==2,"Primary external Connect changed captured choice");json_node_free(root);count++;
    }
    dispatch_execution="invalid";g_clear_pointer(&dispatch_path,g_free);g_clear_pointer(&dispatch_body,g_free);linux_unified_connect_v8(NULL,&dispatch);check(dispatch_path==NULL&&router_dispatches==0,"Invalid external execution fell through to Router Connect");count++;
    dispatch_catalog_failed=TRUE;linux_unified_connect_v8(NULL,&dispatch);check(dispatch_path==NULL&&router_dispatches==0,"Unavailable catalog fell through to Router Connect");count++;dispatch_catalog_failed=FALSE;
    const char *bad_catalogs[]={"{", "[]", "{}", "{\"selected_id\":\"captured-exit\",\"profiles\":[]}", "{\"selected_id\":\"captured-exit\",\"profiles\":null}", "{\"selected_id\":\"captured-exit\",\"profiles\":[{\"id\":\"other\",\"node_kind\":\"external\"}]}", "{\"selected_id\":\"captured-exit\",\"profiles\":[{\"id\":\"captured-exit\",\"node_kind\":\"external\"},{\"id\":\"captured-exit\",\"node_kind\":\"router-vpn\"}]}", "{\"selected_id\":\"captured-exit\",\"profiles\":[{\"id\":\"captured-exit\",\"node_kind\":\"unknown\"}]}"};
    for(guint i=0;i<G_N_ELEMENTS(bad_catalogs);i++){dispatch_catalog=bad_catalogs[i];linux_unified_connect_v8(NULL,&dispatch);check(dispatch_path==NULL&&router_dispatches==0,"Malformed or missing selected node fell through to Router Connect");count++;}dispatch_catalog=NULL;
    dispatch_external=FALSE;linux_unified_connect_v8(NULL,&dispatch);check(router_dispatches==1&&dispatch_path==NULL,"Router multihop was removed by external priority");count++;
    dispatch_external=TRUE;dispatch_connected=TRUE;linux_unified_connect_v8(NULL,&dispatch);check(g_strcmp0(dispatch_path,"/api/disconnect")==0&&router_dispatches==1,"External priority bypassed Disconnect");g_free(dispatch_path);g_free(dispatch_body);count++;
    g_print("PASS shipping GTK external form and captured primary requests: %u cases\n",count);return 0;
}
