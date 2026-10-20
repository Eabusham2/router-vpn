/* Execute the shipping GTK form and its real JsonBuilder serialization.
 * Only the controller request is replaced; this test never starts a VPN. */
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <stdlib.h>
#include <string.h>
typedef struct { GtkWidget *window; } App;
typedef struct { char *data; } Buffer;
static gboolean api_request(const char *path,const char *method,const char *body,int timeout,Buffer *out,char **err){(void)path;(void)method;(void)body;(void)timeout;(void)out;(void)err;return FALSE;}
static JsonNode *parse_json(const char *raw){JsonParser *p=json_parser_new();JsonNode *n=NULL;if(json_parser_load_from_data(p,raw,-1,NULL))n=json_node_copy(json_parser_get_root(p));g_object_unref(p);return n;}
static const char *obj_string(JsonObject *obj,const char *key){return json_object_has_member(obj,key)?json_object_get_string_member(obj,key):"";}
static void append_diag(App *app,const char *text){(void)app;(void)text;}
static void refresh_all(App *app){(void)app;}
#include "routervpn-external-node-v14.inc"

static void check(gboolean ok,const char *message){if(!ok){g_printerr("%s\n",message);exit(1);}}
static GtkWidget *field(const char *value){GtkWidget *w=gtk_entry_new();gtk_entry_set_text(GTK_ENTRY(w),value);return w;}
static void awg_text(LinuxExternalNodeV14 *s,const char *value){gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->awg_parameters)),value,-1);}
static const char *parameters="Jc=3; Jmin=40; Jmax=900; S1=56; S2=48; S3=24; S4=32; H1=10000000-19999999; H2=20000000-29999999; H3=30000000-39999999; H4=40000000-49999999";

int main(int argc,char **argv){
    gtk_init(&argc,&argv);check(argc==2,"Expected a private fixture output directory");
    LinuxExternalNodeV14 s={0};
    s.protocol=gtk_combo_box_text_new();gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(s.protocol),"wireguard","WireGuard");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(s.protocol),"amneziawg","AmneziaWG");gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.protocol),"amneziawg");
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
    g_print("PASS shipping GTK external form: %u cases\n",count);return 0;
}
