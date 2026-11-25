/* Both purposes retain their exact HTTP/native owner. Saved-path testing must
 * prove native DOWN before review; Save creates a future connection profile. */
typedef struct {
    App *app;
    GWeakRef editor;
    char *draft, *chosen_id;
    gboolean auto_run;
    GtkWidget *dialog,*prefix,*table,*status,*preview,*name,*refresh,*test,*save,*use_draft,*cancel,*note;
    GtkListStore *store;
    RVHttpJobV16 *job;
    JsonNode *view,*receipt,*draft_source;
    char selected_winner[7];
    gint64 selected_epoch;
    guint poll;
    int phase,position;
    char request[33],saved_profile[161];
    gboolean pending,cancel_wanted,close_wanted,closed,held,saved_path,saved_prefix,saved_admitted,final_save;
    gint64 retry;
} LinuxOrderedCandidates;
static gboolean linux_oc_view_fresh(JsonObject*o,gint64 now){double expires=linux_ec_number(o,"expires_at");return isfinite(expires)&&expires>now;}
static const char*linux_oc_measurement_kind(const char*measurement){
    if(!strcmp(measurement,"routed-tcp-connect"))return "tcp-connect";
    if(!strcmp(measurement,"routed-candidate-response"))return "private-agent-response";
    return "";
}
static const char*linux_oc_prefix_measurement(JsonObject*prefix){
    const char*mode=linux_ec_string(prefix,"mode"),*measurement=linux_ec_string(prefix,"measurement");
    if(!strcmp(mode,"wg")||!strcmp(mode,"awg2-fast")||!strcmp(mode,"awg2-strong"))
        return !measurement[0]||!strcmp(measurement,"routed-tcp-connect")?"routed-tcp-connect":"";
    if(!strcmp(mode,"shadowsocks")&&!strcmp(measurement,"routed-candidate-response"))return measurement;
    return "";
}
static JsonObject*linux_oc_root(JsonNode*n){return n&&JSON_NODE_HOLDS_OBJECT(n)?json_node_get_object(n):NULL;}
static gboolean linux_oc_response_id(const char *id) {
    return id && *id && strlen(id) <= 64 && strspn(id,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == strlen(id);
}
static gboolean linux_oc_response_source(JsonObject *view, JsonObject *draft, int position) {
    JsonArray *rows = linux_ec_array(view,"response_source_nodes");
    guint count = rows ? json_array_get_length(rows) : 0;
    if (linux_ec_number(view,"prefix_position") != position || count < 4 || count > 96 || position < 1 || position > (int)count-2 || (position < (int)count-2 && count == 96)) return FALSE;
    JsonArray *nodes = linux_ec_array(draft,"nodes");
    if (draft && (strcmp(linux_ec_string(draft,"execution"),"auto") || !nodes || json_array_get_length(nodes) != count)) return FALSE;
    g_autoptr(GHashTable) ids = g_hash_table_new(g_str_hash,g_str_equal);
    gboolean private_interior = FALSE;
    for (guint i=0; i<count; i++) {
        JsonObject *row = linux_oc_root(json_array_get_element(rows,i));
        const char *id = linux_ec_string(row,"id"), *mode = i == 0 ? "wg" : "shadowsocks";
        const char *kind = linux_ec_string(row,"kind");
        if (i == 0 || i == count-1) {
            if (strcmp(kind,"router-vpn")) return FALSE;
        } else if (!strcmp(kind,"router-vpn")) {
            if (i < 2 || private_interior || position != (int)count-2) return FALSE;
            private_interior = TRUE;
        } else if (strcmp(kind,"external")) return FALSE;
        if (!row || json_object_get_size(row) != 3 || !linux_oc_response_id(id) || !g_hash_table_add(ids,(gpointer)id) ||
            strcmp(linux_ec_string(row,"mode"),mode)) return FALSE;
        if (draft) {
            JsonObject *node = linux_oc_root(json_array_get_element(nodes,i));
            if (!node || json_object_get_size(node)!=2 || strcmp(linux_ec_string(node,"id"),id) || strcmp(linux_ec_string(node,"mode"),mode)) return FALSE;
        }
    }
    return TRUE;
}
static gboolean linux_oc_response_proposal(JsonArray *rows, JsonObject *choice, int position) {
    const char *id = linux_ec_string(choice,"id");
    JsonArray *proposal = linux_ec_array(choice,"proposed_path");
    guint count = json_array_get_length(rows), at = (guint)position + 1;
    gboolean insert = at < count-1;
    if (!linux_oc_response_id(id) || strcmp(linux_ec_string(choice,"kind"),"router-vpn") ||
        strcmp(linux_ec_string(choice,"proposal_action"),insert ? "save-intermediate-profile" : "save-final-profile") ||
        !proposal || json_array_get_length(proposal) != count + (guint)insert) return FALSE;
    JsonObject *candidate = linux_oc_root(json_array_get_element(proposal,at));
    if (!candidate || json_object_get_size(candidate)!=2 || strcmp(linux_ec_string(candidate,"id"),id) ||
        strcmp(linux_ec_string(candidate,"mode"),"shadowsocks")) return FALSE;
    for (guint i=0; i<count; i++) {
        JsonObject *source = linux_oc_root(json_array_get_element(rows,i));
        if (!strcmp(linux_ec_string(source,"id"),id)) return FALSE;
        if (!insert && i == at) continue;
        JsonObject *node = linux_oc_root(json_array_get_element(proposal, insert && i>=at ? i+1 : i));
        if (!node || json_object_get_size(node)!=2 || strcmp(linux_ec_string(node,"id"),linux_ec_string(source,"id")) ||
            strcmp(linux_ec_string(node,"mode"),linux_ec_string(source,"mode"))) return FALSE;
    }
    return TRUE;
}
static gboolean linux_oc_response_winner(JsonObject*o,int position){
    if((linux_ec_member(o,"response_source_nodes") ? !linux_oc_response_source(o,NULL,position) : position!=1)||strcmp(linux_ec_string(o,"requested_execution"),"auto")||
       strcmp(linux_ec_string(o,"required_selected_execution"),"local"))return FALSE;
    JsonNode*winner=linux_ec_member(o,"selected_execution"),*epoch=linux_ec_member(o,"selection_epoch");
    if(!winner&&!epoch)return !strcmp(linux_ec_string(o,"scope"),"draft-complete-selected");
    return !strcmp(linux_ec_string(o,"selected_execution"),"local")&&epoch&&JSON_NODE_HOLDS_VALUE(epoch)&&
        json_node_get_value_type(epoch)==G_TYPE_INT64&&json_node_get_int(epoch)>0;
}
/* Only the original three-node connected Compare catalog has no source map. */
static gboolean linux_oc_legacy_connected_response(JsonObject *view) {
    JsonArray *prefixes = linux_ec_array(view,"prefixes"), *choices = linux_ec_array(view,"candidates");
    if (!linux_oc_response_winner(view,1) || !linux_ec_member(view,"selection_epoch") ||
        !prefixes || json_array_get_length(prefixes) != 2 || !choices) return FALSE;
    const char *ids[2], *modes[] = {"wg", "shadowsocks"};
    for (guint i = 0; i < 2; i++) {
        JsonObject *prefix = linux_oc_root(json_array_get_element(prefixes,i));
        ids[i] = linux_ec_string(prefix,"id");
        if (!ids[i][0] || linux_ec_number(prefix,"position") != i || strcmp(linux_ec_string(prefix,"mode"),modes[i])) return FALSE;
    }
    if (!strcmp(ids[0],ids[1])) return FALSE;
    for (guint i = 0; i < json_array_get_length(choices); i++) {
        JsonObject *choice = linux_oc_root(json_array_get_element(choices,i));
        const char *id = linux_ec_string(choice,"id");
        if (!id[0] || !strcmp(id,ids[0]) || !strcmp(id,ids[1]) || strcmp(linux_ec_string(choice,"kind"),"router-vpn") ||
            linux_ec_member(choice,"proposal_action")) return FALSE;
        if (!linux_ec_member(choice,"proposed_path") && linux_ec_string(choice,"save_reason")[0]) continue;
        JsonArray *path = linux_ec_array(choice,"proposed_path");
        if (!path || json_array_get_length(path) != 3) return FALSE;
        for (guint j = 0; j < 3; j++) {
            JsonObject *node = linux_oc_root(json_array_get_element(path,j));
            if (!node || json_object_get_size(node) != 2 || strcmp(linux_ec_string(node,"id"),j < 2 ? ids[j] : id) ||
                strcmp(linux_ec_string(node,"mode"),j ? "shadowsocks" : "wg")) return FALSE;
        }
    }
    return TRUE;
}
static gboolean linux_oc_response_draft(JsonObject*draft,int position,JsonObject*view){
    if(linux_ec_member(view,"response_source_nodes"))return draft && linux_oc_response_source(view,draft,position);
    JsonArray*nodes=linux_ec_array(draft,"nodes");
    return position==1&&!strcmp(linux_ec_string(draft,"execution"),"auto")&&nodes&&json_array_get_length(nodes)==3&&
        !strcmp(linux_ec_string(linux_oc_root(json_array_get_element(nodes,0)),"mode"),"wg")&&
        !strcmp(linux_ec_string(linux_oc_root(json_array_get_element(nodes,1)),"mode"),"shadowsocks")&&
        !strcmp(linux_ec_string(linux_oc_root(json_array_get_element(nodes,2)),"mode"),"shadowsocks");
}
static gboolean linux_oc_catalog_measurement(JsonObject*catalog,int position){
    const char*measurement=linux_ec_string(catalog,"measurement");
    if(position<0||position>=96||!linux_oc_measurement_kind(measurement)[0]||linux_ec_number(catalog,"samples")!=50)return FALSE;
    if(!strcmp(measurement,"routed-candidate-response")){
        const char*requested=linux_ec_string(catalog,"requested_execution"),*selected=linux_ec_string(catalog,"selected_execution");
        if(position<1||position>=95)return FALSE;
        if((!strcmp(linux_ec_string(catalog,"scope"),"draft-complete-selected")||
           (requested[0]&&strcmp(requested,"local"))||(selected[0]&&strcmp(selected,"local")))&&
           !linux_oc_response_winner(catalog,position))return FALSE;
    }
    JsonArray*prefixes=linux_ec_array(catalog,"prefixes");guint matches=0;
    for(guint i=0;prefixes&&i<json_array_get_length(prefixes);i++){
        JsonNode*node=json_array_get_element(prefixes,i);
        JsonObject*prefix=node&&JSON_NODE_HOLDS_OBJECT(node)?json_node_get_object(node):NULL;
        if(linux_ec_number(prefix,"position")!=position)continue;
        if(strcmp(linux_oc_prefix_measurement(prefix),measurement))return FALSE;
        matches++;
    }
    return matches==1;
}
static double linux_oc_score(JsonObject *o,gint64 now){
    const char*measurement=linux_ec_string(o,"measurement"),*kind=linux_oc_measurement_kind(measurement);
    JsonArray *rows=linux_ec_array(o,"results");
    double at=linux_ec_number(o,"measured_at"),expires=linux_ec_number(o,"expires_at");
    if(!kind[0]||strcmp(linux_ec_string(o,"stage"),"complete")||!linux_ec_bool(o,"complete")||!linux_ec_bool(o,"drained")||!isfinite(at)||at<=0||at>now||expires!=at+120000||expires<=now||rows==NULL||json_array_get_length(rows)!=1)return NAN;
    JsonNode*n=json_array_get_element(rows,0);JsonObject*r=n&&JSON_NODE_HOLDS_OBJECT(n)?json_node_get_object(n):NULL;
    JsonObject*b=linux_ec_object(r,"benchmark"),*d=linux_ec_object(b,"distribution");
    if(strcmp(linux_ec_string(r,"node_id"),linux_ec_string(o,"candidate_id"))||strcmp(linux_ec_string(r,"kind"),kind)||strcmp(linux_ec_string(r,"role"),"candidate")||!linux_ec_bool(r,"ready")||strcmp(linux_ec_string(b,"measurement"),measurement)||linux_ec_number(b,"attempts")!=50||linux_ec_number(b,"failed")!=0||linux_ec_number(d,"samples")!=50)return NAN;
    double score=linux_ec_number(b,"trimmed_mean_ms"),min=linux_ec_number(d,"min_ms"),max=linux_ec_number(d,"max_ms");
    return isfinite(score)&&isfinite(min)&&isfinite(max)&&min>0&&score>=min&&score<=max?score:NAN;
}
static gboolean linux_oc_same_measurement(LinuxOrderedCandidates*s,JsonObject*o){
    const char*measurement=linux_ec_string(linux_oc_root(s->view),"measurement");
    return linux_oc_measurement_kind(measurement)[0]&&!strcmp(linux_ec_string(o,"measurement"),measurement);
}
static double linux_oc_current_score(LinuxOrderedCandidates*s,JsonObject*o,gint64 now){
    if(!linux_oc_same_measurement(s,o))return NAN;
    if(!strcmp(linux_ec_string(o,"measurement"),"routed-candidate-response")){
        JsonArray*choices=linux_ec_array(linux_oc_root(s->view),"candidates");guint matches=0;
        for(guint i=0;choices&&i<json_array_get_length(choices);i++){
            JsonObject*choice=linux_oc_root(json_array_get_element(choices,i));
            if(strcmp(linux_ec_string(choice,"id"),linux_ec_string(o,"candidate_id")))continue;
            if(strcmp(linux_ec_string(choice,"kind"),"router-vpn"))return NAN;
            matches++;
        }
        if(matches!=1)return NAN;
    }
    return linux_oc_score(o,now);
}
static const char*linux_oc_base(LinuxOrderedCandidates*s){return s->draft?"/api/multihop/draft-candidates":s->saved_path?"/api/multihop/saved-candidates":"/api/multihop/prefix-candidates";}
static const char*linux_oc_scope(LinuxOrderedCandidates*s){
    const char*requested=linux_ec_string(linux_oc_root(s->draft_source),"execution");
    if(!strcmp(requested,"server")||!strcmp(requested,"auto"))return "draft-complete-selected";
    return s->saved_prefix?"saved-prefix-local":"saved-complete-local";}
static char*linux_oc_catalog_path(LinuxOrderedCandidates*s){return g_strdup_printf("%s/catalog?prefix_position=%d%s%s",linux_oc_base(s),s->position,s->saved_prefix?"&scope=":"",s->saved_prefix?linux_oc_scope(s):"");}
static gboolean linux_oc_draft_execution(LinuxOrderedCandidates*s,JsonObject*o,gboolean catalog){
    JsonObject*draft=linux_oc_root(s->draft_source);
    const char*requested=linux_ec_string(draft,"execution");
    if(strcmp(linux_ec_string(o,"requested_execution"),requested))return FALSE;
    JsonNode*selected=linux_ec_member(o,"selected_execution"),*epoch=linux_ec_member(o,"selection_epoch");
    if(catalog){
        JsonArray*nodes=linux_ec_array(draft,"nodes"),*rows=linux_ec_array(o,"prefixes");
        if(selected||epoch||!nodes||!rows||s->position<0||(guint)s->position>=json_array_get_length(nodes))return FALSE;
        JsonObject*original=linux_oc_root(json_array_get_element(nodes,s->position));
        const char*mode=linux_ec_string(original,"mode");
        gboolean packet=!strcmp(mode,"wg")||!strcmp(mode,"awg2-fast")||!strcmp(mode,"awg2-strong");
        if(!packet&&(!linux_oc_response_draft(draft,s->position,o)||!linux_oc_response_winner(o,s->position)||strcmp(linux_ec_string(o,"measurement"),"routed-candidate-response")))return FALSE;
        guint found=0;
        for(guint i=0;i<json_array_get_length(rows);i++){
            JsonObject*row=linux_oc_root(json_array_get_element(rows,i));
            if(linux_ec_number(row,"position")!=s->position)continue;
            if(strcmp(linux_ec_string(row,"id"),linux_ec_string(original,"id"))||strcmp(linux_ec_string(row,"mode"),mode))return FALSE;
            found++;
        }
        return found==1;
    }
    if(!selected&&!epoch){
        JsonArray*results=linux_ec_array(o,"results");
        return !s->selected_winner[0]&&!linux_ec_bool(o,"accepted")&&!linux_ec_bool(o,"reviewing")&&!linux_ec_bool(o,"chosen")&&(!results||!json_array_get_length(results));
    }
    const char*winner=linux_ec_string(o,"selected_execution");
    if (!strcmp(linux_ec_string(o,"measurement"),"routed-candidate-response") && !linux_oc_response_winner(o,s->position)) {
        JsonArray *results=linux_ec_array(o,"results");
        if (strcmp(winner,"server") || strcmp(requested,"auto") || strcmp(linux_ec_string(o,"required_selected_execution"),"local") ||
            !linux_oc_response_source(o,draft,s->position) || !linux_ec_bool(o,"native_down") || linux_ec_bool(o,"chosen") ||
            linux_ec_bool(o,"saved") || !linux_ec_member(o,"saved_profile_id") || linux_ec_string(o,"saved_profile_id")[0] ||
            !results || json_array_get_length(results) || (!linux_ec_bool(o,"cancelled") && !linux_ec_string(o,"failure")[0])) return FALSE;
        const char *fields[]={"running","accepted","reviewing"};
        for (guint i=0; i<G_N_ELEMENTS(fields); i++) {
            JsonNode *flag=linux_ec_member(o,fields[i]);
            if (!flag || !JSON_NODE_HOLDS_VALUE(flag) || json_node_get_value_type(flag)!=G_TYPE_BOOLEAN || json_node_get_boolean(flag)) return FALSE;
        }
    }
    if(linux_ec_bool(o,"admission_cancelled")||(strcmp(winner,"local")&&strcmp(winner,"server"))||(!strcmp(requested,"server")&&strcmp(winner,"server"))||
       !epoch||!JSON_NODE_HOLDS_VALUE(epoch)||json_node_get_value_type(epoch)!=G_TYPE_INT64||json_node_get_int(epoch)<=0)return FALSE;
    return !s->selected_winner[0]||(!strcmp(winner,s->selected_winner)&&json_node_get_int(epoch)==s->selected_epoch);
}
static gboolean linux_oc_saved_envelope(LinuxOrderedCandidates*s,JsonObject*o,gboolean catalog){
    if(s->draft && strcmp(linux_ec_string(o,"origin"),"editor-draft"))return FALSE;
    if(strcmp(linux_ec_string(o,"scope"),linux_oc_scope(s))||linux_ec_number(o,"schema")!=1||linux_ec_number(o,"prefix_position")!=s->position||!linux_oc_measurement_kind(linux_ec_string(o,"measurement"))[0])return FALSE;
    if(!strcmp(linux_oc_scope(s),"draft-complete-selected")){if(!linux_oc_draft_execution(s,o,catalog))return FALSE;}
    else if(s->saved_prefix){
        const char*fields[]={"application_open","dns_open"};
        for(unsigned i=0;i<2;i++){JsonNode*flag=linux_ec_member(o,fields[i]);if(!flag||!JSON_NODE_HOLDS_VALUE(flag)||json_node_get_value_type(flag)!=G_TYPE_BOOLEAN||json_node_get_boolean(flag))return FALSE;}
        if(strcmp(linux_ec_string(o,"proof_scope"),"selected-prefix"))return FALSE;
    }
    if(catalog)return linux_ec_number(o,"samples")==50;
    JsonNode*changed=linux_ec_member(o,"active_path_changed");
    return changed&&JSON_NODE_HOLDS_VALUE(changed)&&json_node_get_value_type(changed)==G_TYPE_BOOLEAN&&!json_node_get_boolean(changed)&&strcmp(linux_ec_string(linux_oc_root(s->view),"scope"),linux_ec_string(o,"scope"))==0&&linux_oc_same_measurement(s,o);
}
static gboolean linux_oc_before_start(JsonObject*o){
    JsonNode*started=linux_ec_member(o,"started");
    return linux_ec_bool(o,"admission_cancelled")&&started&&JSON_NODE_HOLDS_VALUE(started)&&json_node_get_value_type(started)==G_TYPE_BOOLEAN&&!json_node_get_boolean(started);
}
static gboolean linux_oc_ready(LinuxOrderedCandidates*s){
    JsonObject*receipt=linux_oc_root(s->receipt);
    if(s->cancel_wanted||s->close_wanted||!linux_ec_bool(receipt,"accepted")||!linux_oc_same_measurement(s,receipt))return FALSE;
    if(s->saved_path)return linux_oc_saved_envelope(s,receipt,FALSE)&&!linux_oc_before_start(receipt)&&linux_ec_bool(receipt,"native_down")&&linux_ec_bool(receipt,"reviewing")&&!linux_ec_bool(receipt,"cleanup_pending")&&!s->saved_profile[0];
    return !s->pending;
}
static gboolean linux_oc_final_choice(LinuxOrderedCandidates*s,JsonObject*choice){
    JsonObject*draft=linux_oc_root(s->draft_source);
    JsonArray*original=linux_ec_array(draft,"nodes"),*proposed=linux_ec_array(choice,"proposed_path");
    guint count=original?json_array_get_length(original):0;
    const char*id=linux_ec_string(choice,"id");
    JsonObject *view = linux_oc_root(s->view);
    if (linux_ec_member(view,"response_source_nodes")) {
        return s->draft && s->saved_path && s->saved_prefix && !strcmp(linux_oc_scope(s),"draft-complete-selected") &&
            !strcmp(linux_ec_string(view,"measurement"),"routed-candidate-response") && linux_oc_response_source(view,draft,s->position) &&
            linux_oc_response_proposal(linux_ec_array(view,"response_source_nodes"),choice,s->position);
    }
    if(!strcmp(linux_ec_string(choice,"proposal_action"),"save-intermediate-profile")){
        guint at=(guint)s->position+1;
        if(!s->draft||!s->saved_path||!s->saved_prefix||strcmp(linux_oc_scope(s),"saved-prefix-local")||
           strcmp(linux_ec_string(draft,"execution"),"local")||strcmp(linux_ec_string(linux_oc_root(s->view),"measurement"),"routed-candidate-response")||
           strcmp(linux_ec_string(choice,"kind"),"router-vpn")||!id[0]||count<4||count>=96||s->position<1||at>=count-1||
           !proposed||json_array_get_length(proposed)!=count+1)return FALSE;
        if(strcmp(linux_ec_string(linux_oc_root(json_array_get_element(original,at-1)),"mode"),"shadowsocks")||
           strcmp(linux_ec_string(linux_oc_root(json_array_get_element(original,at)),"mode"),"shadowsocks")||
           strcmp(linux_ec_string(linux_oc_root(json_array_get_element(original,count-1)),"mode"),"shadowsocks"))return FALSE;
        for(guint i=0;i<count;i++){
            JsonNode*node=json_array_get_element(original,i);
            if(!strcmp(linux_ec_string(linux_oc_root(node),"id"),id)||!json_node_equal(node,json_array_get_element(proposed,i<at?i:i+1)))return FALSE;
        }
        JsonObject*added=linux_oc_root(json_array_get_element(proposed,at));
        return !strcmp(linux_ec_string(added,"id"),id)&&!strcmp(linux_ec_string(added,"mode"),"shadowsocks");
    }
    gboolean selected=linux_oc_response_draft(draft,s->position,linux_oc_root(s->view))&&linux_oc_response_winner(linux_oc_root(s->view),s->position);
    if(!s->draft||!s->saved_path||!s->saved_prefix||(!selected&&(strcmp(linux_oc_scope(s),"saved-prefix-local")||
       strcmp(linux_ec_string(draft,"execution"),"local")))||strcmp(linux_ec_string(linux_oc_root(s->view),"measurement"),"routed-candidate-response")||
       strcmp(linux_ec_string(choice,"proposal_action"),"save-final-profile")||strcmp(linux_ec_string(choice,"kind"),"router-vpn")||!id[0]||
       count<3||count>96||s->position<1||(guint)s->position+2!=count||!proposed||json_array_get_length(proposed)!=count)return FALSE;
    if(strcmp(linux_ec_string(linux_oc_root(json_array_get_element(original,s->position)),"mode"),"shadowsocks")||
       strcmp(linux_ec_string(linux_oc_root(json_array_get_element(original,count-1)),"mode"),"shadowsocks"))return FALSE;
    gboolean stream=FALSE;
    for(guint i=0;i+1<count;i++){
        JsonNode*node=json_array_get_element(original,i);
        if(!json_node_equal(node,json_array_get_element(proposed,i))||!strcmp(linux_ec_string(linux_oc_root(node),"id"),id))return FALSE;
        const char*mode=linux_ec_string(linux_oc_root(node),"mode");
        if(!strcmp(mode,"shadowsocks")&&i>0)stream=TRUE;
        else if(stream||(strcmp(mode,"wg")&&strcmp(mode,"awg2-fast")&&strcmp(mode,"awg2-strong")))return FALSE;
    }
    JsonObject*last=linux_oc_root(json_array_get_element(proposed,count-1));
    return !strcmp(linux_ec_string(last,"id"),id)&&!strcmp(linux_ec_string(last,"mode"),"shadowsocks")&&
        strcmp(linux_ec_string(linux_oc_root(json_array_get_element(original,count-1)),"id"),id);
}
static JsonNode *linux_oc_response_draft_path(LinuxOrderedCandidates *s, JsonObject *view, JsonObject *choice) {
    JsonObject *draft=linux_oc_root(s->draft_source);
    JsonArray *nodes=linux_ec_array(draft,"nodes"), *path=linux_ec_array(choice,"draft_path");
    guint count=nodes ? json_array_get_length(nodes) : 0;
    const char *id=linux_ec_string(choice,"id");
    if (!draft || strcmp(linux_ec_string(view,"measurement"),"routed-candidate-response") ||
        strcmp(linux_ec_string(choice,"draft_action"),"insert-measured-hop") || strcmp(linux_ec_string(choice,"kind"),"router-vpn") ||
        !linux_oc_response_id(id) || !path || count>=96 || s->position<1 || (guint)s->position+1>=count ||
        json_array_get_length(path)!=count+1) return NULL;
    if (!strcmp(linux_ec_string(draft,"execution"),"auto")) {
        if (!linux_oc_response_draft(draft,s->position,view)) return NULL;
        if (count>3) {
            JsonArray *source=linux_ec_array(view,"response_source_nodes");
            for (guint i=1; i<count-1; i++)
                if (strcmp(linux_ec_string(linux_oc_root(json_array_get_element(source,i)),"kind"),"external")) return NULL;
        }
    } else if (strcmp(linux_ec_string(draft,"execution"),"local")) return NULL;
    guint at=(guint)s->position+1;
    JsonObject *added=linux_oc_root(json_array_get_element(path,at));
    if (!added || json_object_get_size(added)!=2 || strcmp(linux_ec_string(added,"id"),id) || strcmp(linux_ec_string(added,"mode"),"shadowsocks")) return NULL;
    for (guint i=0; i<count; i++) {
        JsonNode *row=json_array_get_element(nodes,i);
        if (!strcmp(linux_ec_string(linux_oc_root(row),"id"),id) || !json_node_equal(row,json_array_get_element(path,i<at?i:i+1))) return NULL;
    }
    return linux_ec_member(choice,"draft_path");
}
static gboolean linux_oc_final_saved(LinuxOrderedCandidates*s,JsonObject*response){
    if(!s->final_save||!s->chosen_id||strcmp(linux_ec_string(response,"candidate_id"),s->chosen_id)||
       linux_ec_bool(response,"chosen"))return FALSE;
    JsonArray*choices=linux_ec_array(linux_oc_root(s->view),"candidates");guint matches=0;
    for(guint i=0;choices&&i<json_array_get_length(choices);i++){
        JsonObject*choice=linux_oc_root(json_array_get_element(choices,i));
        if(strcmp(linux_ec_string(choice,"id"),s->chosen_id))continue;
        JsonNode*path=linux_ec_member(response,"proposed_path");
        if(strcmp(linux_ec_string(response,"proposal_action"),linux_ec_string(choice,"proposal_action"))||!linux_oc_final_choice(s,choice)||!path||!json_node_equal(path,linux_ec_member(choice,"proposed_path")))return FALSE;
        matches++;
    }
    return matches==1;
}
static JsonObject*linux_oc_result(LinuxOrderedCandidates*s,const char*id){
    JsonArray*rows=linux_ec_array(linux_oc_root(s->receipt),"results");
    for(guint i=0;rows&&i<json_array_get_length(rows);i++){JsonObject*r=linux_oc_root(json_array_get_element(rows,i));if(strcmp(linux_ec_string(r,"candidate_id"),id)==0)return r;}return NULL;
}
static JsonObject*linux_oc_selected(LinuxOrderedCandidates*s){
    GtkTreeSelection*selection=gtk_tree_view_get_selection(GTK_TREE_VIEW(s->table));GtkTreeModel*model=NULL;GList*paths=gtk_tree_selection_get_selected_rows(selection,&model);JsonObject*choice=NULL;
    if(g_list_length(paths)==1){GtkTreeIter iter;if(gtk_tree_model_get_iter(model,&iter,paths->data))gtk_tree_model_get(model,&iter,3,&choice,-1);}g_list_free_full(paths,(GDestroyNotify)gtk_tree_path_free);return choice;
}
static void linux_oc_hold(LinuxOrderedCandidates*s,gboolean hold){LinuxAsyncActionsV16*a=linux_async_state_v16(s->app);if(hold&&!s->held){if(a)a->auxiliary_jobs++;s->held=TRUE;g_object_set_data(G_OBJECT(s->app->window),"linux-ordered-candidates-pending",s);}else if(!hold&&s->held){if(a&&a->auxiliary_jobs>0)a->auxiliary_jobs--;s->held=FALSE;if(g_object_get_data(G_OBJECT(s->app->window),"linux-ordered-candidates-pending")==s)g_object_set_data(G_OBJECT(s->app->window),"linux-ordered-candidates-pending",NULL);}}
static void linux_oc_controls(LinuxOrderedCandidates*s){
    if(s->closed)return;
    const char*prefix=gtk_combo_box_get_active_id(GTK_COMBO_BOX(s->prefix));gboolean captured=prefix&&atoi(prefix)==s->position;gboolean idle=s->job==NULL&&!s->pending;gtk_widget_set_sensitive(s->refresh,idle);gtk_widget_set_sensitive(s->prefix,idle&&!s->draft);gtk_widget_set_sensitive(s->test,idle&&captured&&s->view!=NULL);gtk_widget_set_sensitive(s->cancel,s->pending);
    JsonObject*choice=linux_oc_selected(s);JsonArray*path=linux_ec_array(choice,"proposed_path");JsonObject*row=linux_oc_result(s,linux_ec_string(choice,"id"));
    gboolean response_draft=s->draft&&!strcmp(linux_ec_string(linux_oc_root(s->view),"measurement"),"routed-candidate-response");
    gboolean allowed=!s->draft||(response_draft?linux_oc_final_choice(s,choice):!linux_ec_string(choice,"proposal_action")[0]);
    gtk_widget_set_visible(s->name,!s->draft||response_draft);
    gtk_button_set_label(GTK_BUTTON(s->save),response_draft?(!strcmp(linux_ec_string(choice,"proposal_action"),"save-intermediate-profile")?"Save profile with this hop":"Save profile with this final"):s->draft?"Add measured hop to draft":"Save next-connection profile");
    gboolean ready=s->job==NULL && captured && linux_oc_ready(s) && isfinite(linux_oc_current_score(s,row,g_get_real_time()/1000));
    gboolean insert=linux_oc_response_draft_path(s,linux_oc_root(s->view),choice)!=NULL;
    gtk_widget_set_visible(s->use_draft,insert);
    gtk_widget_set_sensitive(s->use_draft,ready && insert);
    gtk_widget_set_sensitive(s->save,ready && allowed && path && json_array_get_length(path)>=2);
}
static void linux_oc_send(LinuxOrderedCandidates*s,int phase,const char*path,const char*body){
    if(s->closed||s->job){
        return;
    }
    s->phase=phase;s->job=rv_http_start_method_v17(path,body?body:"",phase==2?180000:25000,"Ordered prefix candidates",body==NULL);
    if(!s->job){gtk_label_set_text(GTK_LABEL(s->status),"Could not start request; original cancellation will be retried if needed.");if(s->pending)s->cancel_wanted=TRUE;s->retry=g_get_monotonic_time()+G_USEC_PER_SEC;}linux_oc_controls(s);
}
static char*linux_oc_body(LinuxOrderedCandidates*s,int phase){
    JsonBuilder*b=json_builder_new();json_builder_begin_object(b);json_builder_set_member_name(b,"request_id");json_builder_add_string_value(b,s->request);
    if(s->saved_prefix){json_builder_set_member_name(b,"scope");json_builder_add_string_value(b,linux_oc_scope(s));}
    if(phase!=3||s->saved_path||linux_ec_member(linux_oc_root(s->view),"response_source_nodes")){
        json_builder_set_member_name(b,"view_token");json_builder_add_string_value(b,linux_ec_string(linux_oc_root(s->view),"view_token"));
        if(phase==2){
            json_builder_set_member_name(b,"prefix_position");json_builder_add_int_value(b,s->position);json_builder_set_member_name(b,"samples");json_builder_add_int_value(b,50);
            json_builder_set_member_name(b,"candidate_ids");json_builder_begin_array(b);
            GtkTreeModel*model=NULL;GList*paths=gtk_tree_selection_get_selected_rows(gtk_tree_view_get_selection(GTK_TREE_VIEW(s->table)),&model);
            for(GList*i=paths;i;i=i->next){GtkTreeIter iter;gchar*id=NULL;if(gtk_tree_model_get_iter(model,&iter,i->data)){gtk_tree_model_get(model,&iter,1,&id,-1);if(id)json_builder_add_string_value(b,id);g_free(id);}}g_list_free_full(paths,(GDestroyNotify)gtk_tree_path_free);json_builder_end_array(b);
        }else if(phase==4||phase==6){
            JsonObject*choice=linux_oc_selected(s);json_builder_set_member_name(b,"candidate_id");json_builder_add_string_value(b,linux_ec_string(choice,"id"));s->final_save=phase==4&&linux_oc_final_choice(s,choice);g_free(s->chosen_id);s->chosen_id=g_strdup(linux_ec_string(choice,"id"));
            if(!s->draft||s->final_save){json_builder_set_member_name(b,"name");json_builder_add_string_value(b,gtk_entry_get_text(GTK_ENTRY(s->name)));}
            json_builder_set_member_name(b,"proposed_path");JsonNode*n=phase==6?linux_oc_response_draft_path(s,linux_oc_root(s->view),choice):linux_ec_member(choice,"proposed_path");if(n)json_builder_add_value(b,json_node_copy(n));else json_builder_add_null_value(b);
        }
    }
    json_builder_end_object(b);JsonNode*n=json_builder_get_root(b);JsonGenerator*g=json_generator_new();json_generator_set_root(g,n);char*body=json_generator_to_data(g,NULL);g_object_unref(g);json_node_free(n);g_object_unref(b);return body;
}
static gint linux_oc_compare(GtkTreeModel*model,GtkTreeIter*a,GtkTreeIter*b,gpointer data){
    (void)data;double x,y;gchar*left=NULL,*right=NULL;gtk_tree_model_get(model,a,4,&x,1,&left,-1);gtk_tree_model_get(model,b,4,&y,1,&right,-1);int result=x<y?-1:x>y?1:g_strcmp0(left,right);g_free(left);g_free(right);return result;
}
static void linux_oc_rows(LinuxOrderedCandidates*s,gboolean measured){
    char*selected=g_strdup(linux_ec_string(linux_oc_selected(s),"id"));
    gtk_list_store_clear(s->store);JsonArray*choices=linux_ec_array(linux_oc_root(s->view),"candidates");
    if(measured&&s->saved_path&&!linux_oc_ready(s)){g_free(selected);return;}
    for(guint i=0;choices&&i<json_array_get_length(choices);i++){
        JsonObject*c=linux_oc_root(json_array_get_element(choices,i));const char*id=linux_ec_string(c,"id");double score=linux_oc_current_score(s,linux_oc_result(s,id),g_get_real_time()/1000);
        if(measured&&!isfinite(score)){
            continue;
        }
        const char*metric=!strcmp(linux_ec_string(linux_oc_root(s->view),"measurement"),"routed-candidate-response")?"node replies":"TCP";
        char*text=isfinite(score)?g_strdup_printf("%.2f ms · 50/50 %s",score,metric):g_strdup("Not tested");GtkTreeIter iter;gtk_list_store_append(s->store,&iter);gtk_list_store_set(s->store,&iter,0,linux_ec_string(c,"name"),1,id,2,text,3,c,4,isfinite(score)?score:G_MAXDOUBLE,-1);g_free(text);
    }
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(s->store),measured?4:GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID,GTK_SORT_ASCENDING);
    if(selected[0]){GtkTreeIter iter;gboolean valid=gtk_tree_model_get_iter_first(GTK_TREE_MODEL(s->store),&iter);while(valid){gchar*id=NULL;gtk_tree_model_get(GTK_TREE_MODEL(s->store),&iter,1,&id,-1);if(g_strcmp0(id,selected)==0)gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(s->table)),&iter);g_free(id);valid=gtk_tree_model_iter_next(GTK_TREE_MODEL(s->store),&iter);}}g_free(selected);
}
static gboolean linux_oc_receive(LinuxOrderedCandidates*s,JsonObject*o,int phase){
    JsonObject *prior = linux_oc_root(s->view), *draft_source = linux_oc_root(s->draft_source);
    JsonNode *source = linux_ec_member(o,"response_source_nodes"), *expected = linux_ec_member(prior,"response_source_nodes");
    if (phase == 1 && source) {
        if (!linux_oc_response_source(o,draft_source,s->position) || !linux_oc_response_winner(o,s->position) ||
            (!s->draft && !linux_ec_member(o,"selection_epoch")) ||
            strcmp(linux_ec_string(o,"measurement"),"routed-candidate-response")) return FALSE;
        JsonArray *rows = json_node_get_array(source), *choices = linux_ec_array(o,"candidates");
        JsonArray *prefixes = linux_ec_array(o,"prefixes");
        const char *id = linux_ec_string(linux_oc_root(json_array_get_element(rows,s->position)),"id");
        for (guint i=0; prefixes && i<json_array_get_length(prefixes); i++) {
            JsonObject *prefix = linux_oc_root(json_array_get_element(prefixes,i));
            if (linux_ec_number(prefix,"position") == s->position && strcmp(linux_ec_string(prefix,"id"),id)) return FALSE;
        }
        for (guint i=0; choices && i<json_array_get_length(choices); i++) {
            JsonObject *choice = linux_oc_root(json_array_get_element(choices,i));
            if (linux_ec_member(choice,"proposed_path") || linux_ec_member(choice,"proposal_action")) {
                if (!linux_oc_response_proposal(rows,choice,s->position)) return FALSE;
            } else if (!linux_oc_response_draft_path(s,o,choice)) return FALSE;
        }
    } else if (phase == 1 && !s->saved_path && !s->draft && !strcmp(linux_ec_string(o,"measurement"),"routed-candidate-response") &&
               (!strcmp(linux_ec_string(o,"requested_execution"),"auto") || !strcmp(linux_ec_string(o,"required_selected_execution"),"local"))) {
        if (s->position != 1 || !linux_oc_legacy_connected_response(o)) return FALSE;
    } else if (phase != 1 && (source || expected)) {
        if (linux_ec_number(o,"prefix_position")!=s->position || !source || !expected || !json_node_equal(source,expected) || strcmp(linux_ec_string(o,"view_token"),linux_ec_string(prior,"view_token"))) return FALSE;
        if (!s->draft && (!linux_oc_response_winner(o,s->position) || !linux_ec_member(o,"selection_epoch") ||
            json_node_get_int(linux_ec_member(o,"selection_epoch")) != json_node_get_int(linux_ec_member(prior,"selection_epoch")))) return FALSE;
        if (!s->draft && strcmp(s->request,linux_ec_string(o,"request_id"))) return FALSE;
        if (!s->draft && phase == 3) {
            JsonArray *results=linux_ec_array(o,"results");
            JsonNode *saved=linux_ec_member(o,"saved_profile_id");
            if (strcmp(linux_ec_string(o,"measurement"),"routed-candidate-response") || linux_ec_number(o,"prefix_position")!=s->position ||
                !results || json_array_get_length(results) || (saved && (!JSON_NODE_HOLDS_VALUE(saved) ||
                json_node_get_value_type(saved)!=G_TYPE_STRING || *json_node_get_string(saved)))) return FALSE;
            gboolean started=linux_ec_bool(o,"started");
            const char *fields[]={"started","admission_cancelled","running","accepted","reviewing","cleanup_pending","active_path_changed","ok","cancelled","drained"};
            const gboolean values[]={started,!started,FALSE,FALSE,FALSE,FALSE,FALSE,TRUE,TRUE,TRUE};
            for (guint i=0; i<G_N_ELEMENTS(fields); i++) {
                JsonNode *flag=linux_ec_member(o,fields[i]);
                if (!flag || !JSON_NODE_HOLDS_VALUE(flag) || json_node_get_value_type(flag)!=G_TYPE_BOOLEAN || json_node_get_boolean(flag)!=values[i]) return FALSE;
            }
            if (!started && s->saved_admitted) return FALSE;
        }
        if (!s->draft && (phase==2 || phase==5) && linux_ec_number(o,"prefix_position")==s->position &&
            !strcmp(linux_ec_string(o,"measurement"),"routed-candidate-response")) s->saved_admitted=TRUE;
        if (!s->draft && phase == 4) {
            JsonNode *path = linux_ec_member(o,"proposed_path");
            JsonArray *choices = linux_ec_array(prior,"candidates");
            gboolean matched = FALSE;
            for (guint i=0; choices && i<json_array_get_length(choices); i++) {
                JsonObject *choice = linux_oc_root(json_array_get_element(choices,i));
                if (!g_strcmp0(linux_ec_string(choice,"id"),s->chosen_id) && !strcmp(linux_ec_string(o,"proposal_action"),linux_ec_string(choice,"proposal_action")) &&
                    path && json_node_equal(path,linux_ec_member(choice,"proposed_path"))) matched = TRUE;
            }
            JsonNode *changed = linux_ec_member(o,"active_path_changed");
            if (!matched || g_strcmp0(s->chosen_id,linux_ec_string(o,"candidate_id")) || strcmp(s->request,linux_ec_string(o,"request_id")) ||
                !changed || !JSON_NODE_HOLDS_VALUE(changed) || json_node_get_value_type(changed)!=G_TYPE_BOOLEAN || json_node_get_boolean(changed)) return FALSE;
        }
    }
    if(phase==1){
        if(s->saved_path&&!linux_oc_saved_envelope(s,o,TRUE))return FALSE;
        if(!linux_oc_catalog_measurement(o,s->position))return FALSE;
        if(s->draft&&!strcmp(linux_ec_string(o,"measurement"),"routed-candidate-response")){
            JsonObject*draft=linux_oc_root(s->draft_source);JsonArray*nodes=linux_ec_array(draft,"nodes");
            if((strcmp(linux_ec_string(draft,"execution"),"local") && !(linux_oc_response_draft(draft,s->position,o) && linux_oc_response_winner(o,s->position)))||!nodes||s->position<1||(guint)s->position+1>=json_array_get_length(nodes))return FALSE;
            JsonObject*original=linux_oc_root(json_array_get_element(nodes,s->position));JsonArray*prefixes=linux_ec_array(o,"prefixes");
            for(guint i=0;prefixes&&i<json_array_get_length(prefixes);i++){
                JsonObject*prefix=linux_oc_root(json_array_get_element(prefixes,i));
                if(linux_ec_number(prefix,"position")==s->position&&(strcmp(linux_ec_string(prefix,"id"),linux_ec_string(original,"id"))||strcmp(linux_ec_string(prefix,"mode"),linux_ec_string(original,"mode"))))return FALSE;
            }
        }
        const char*token=linux_ec_string(o,"view_token");JsonArray*choices=linux_ec_array(o,"candidates");double expires=linux_ec_number(o,"expires_at");
        if(!linux_ec_token(token,64)||linux_ec_number(o,"prefix_position")!=s->position||!isfinite(expires)||expires<=g_get_real_time()/1000||!choices||json_array_get_length(choices)<1)return FALSE;
        gtk_list_store_clear(s->store);if(s->view)json_node_free(s->view);s->view=json_node_new(JSON_NODE_OBJECT);json_node_set_object(s->view,o);
        if(s->receipt){json_node_free(s->receipt);s->receipt=NULL;}gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(s->prefix));JsonArray*prefixes=linux_ec_array(o,"prefixes");
        for(guint i=0;prefixes&&i<json_array_get_length(prefixes);i++){JsonObject*p=linux_oc_root(json_array_get_element(prefixes,i));double value=linux_ec_number(p,"position");if(!isfinite(value)||value<0||value>=96||floor(value)!=value||!linux_oc_prefix_measurement(p)[0])continue;char*id=g_strdup_printf("%d",(int)value),*name=g_strdup_printf("After node %d · %s · %s",(int)value+1,linux_ec_string(p,"name"),linux_ec_string(p,"mode"));gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(s->prefix),id,name);if((int)value==s->position)gtk_combo_box_set_active_id(GTK_COMBO_BOX(s->prefix),id);g_free(id);g_free(name);}
        const char*note=!strcmp(linux_ec_string(o,"measurement"),"routed-candidate-response")?
            "Measure 50 authenticated replies from each paired candidate through the selected Shadowsocks prefix, including connection time. Results use the same response measurement. Save a named profile to use the measured path on a future connection.":
            "Measure 50 TCP connection handshakes per candidate through the selected WireGuard/AWG prefix. These timings measure connection establishment and do not authenticate candidate credentials. A temporary route must close before a measured hop can be adopted.";
        gtk_label_set_text(GTK_LABEL(s->note),note);
        s->saved_profile[0]=0;s->final_save=FALSE;linux_oc_rows(s,FALSE);
        if(s->draft && !s->close_wanted && !s->cancel_wanted){
            GtkTreeModel *model=GTK_TREE_MODEL(s->store);GtkTreeIter iter;
            for(gboolean found=gtk_tree_model_get_iter_first(model,&iter);found;found=gtk_tree_model_iter_next(model,&iter)){
                JsonObject *candidate=NULL;gtk_tree_model_get(model,&iter,3,&candidate,-1);
                JsonArray *path=linux_ec_array(candidate,"proposed_path");
                if(linux_oc_response_draft_path(s,o,candidate) || (path && json_array_get_length(path)>=3&&
                   (strcmp(linux_ec_string(o,"measurement"),"routed-candidate-response")||linux_oc_final_choice(s,candidate)))){
                    gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(s->table)),&iter);s->auto_run=TRUE;
                }
            }
        }
        gtk_label_set_text(GTK_LABEL(s->status),!strcmp(linux_oc_scope(s),"draft-complete-selected")?"Test the complete draft temporarily. Choose a measured hop after the route closes.":s->saved_prefix?"Test only the selected saved prefix. It must return to Disconnected before future-profile choices appear.":s->saved_path?"Test the complete saved Local path temporarily. It must return to Disconnected before future-profile choices appear.":"Select saved candidates and test through this captured prefix.");return TRUE;
    }
    if(s->saved_path){
        if(!linux_oc_saved_envelope(s,o,FALSE))return FALSE;
        if(strcmp(linux_ec_string(o,"request_id"),s->request)||strcmp(linux_ec_string(o,"view_token"),linux_ec_string(linux_oc_root(s->view),"view_token")))return FALSE;
        if(!strcmp(linux_oc_scope(s),"draft-complete-selected")&&linux_ec_string(o,"selected_execution")[0]){
            g_strlcpy(s->selected_winner,linux_ec_string(o,"selected_execution"),sizeof s->selected_winner);
            s->selected_epoch=json_node_get_int(linux_ec_member(o,"selection_epoch"));
        }
        if(linux_oc_before_start(o)&&s->saved_admitted)return FALSE;
        if(linux_ec_bool(o,"running")||linux_ec_bool(o,"started")||linux_ec_bool(o,"native_down")||linux_ec_bool(o,"reviewing"))s->saved_admitted=TRUE;
        if(s->draft && (phase==6 || (phase==4&&!s->final_save))){
            if (phase==6) {
                JsonArray *choices=linux_ec_array(linux_oc_root(s->view),"candidates");
                JsonNode *confirmed=linux_ec_member(o,"proposed_path");
                if (strcmp(linux_ec_string(o,"draft_action"),"insert-measured-hop") || !confirmed ||
                    linux_ec_member(o,"profile_id") ||
                    (!strcmp(linux_oc_scope(s),"draft-complete-selected") && (strcmp(s->selected_winner,"local") || s->selected_epoch<=0))) return FALSE;
                const char *fields[]={"accepted","running","reviewing","cleanup_pending","cancelled","saved"};
                for(guint i=0;i<G_N_ELEMENTS(fields);i++){
                    JsonNode *flag=linux_ec_member(o,fields[i]);
                    if(!flag && !strcmp(fields[i],"saved"))continue;
                    if(!flag || !JSON_NODE_HOLDS_VALUE(flag) || json_node_get_value_type(flag)!=G_TYPE_BOOLEAN || json_node_get_boolean(flag))return FALSE;
                }
                JsonNode *saved_id=linux_ec_member(o,"saved_profile_id");
                if(!saved_id || !JSON_NODE_HOLDS_VALUE(saved_id) || json_node_get_value_type(saved_id)!=G_TYPE_STRING)return FALSE;
                guint matches=0;
                for(guint i=0; choices && i<json_array_get_length(choices); i++) {
                    JsonObject *choice=linux_oc_root(json_array_get_element(choices,i));
                    if (g_strcmp0(linux_ec_string(choice,"id"),s->chosen_id)) continue;
                    JsonNode *offered=linux_oc_response_draft_path(s,linux_oc_root(s->view),choice);
                    if (!offered || !json_node_equal(confirmed,offered)) return FALSE;
                    matches++;
                }
                if (matches!=1) return FALSE;
            }
            if(s->cancel_wanted || s->close_wanted || !linux_ec_bool(o,"chosen") || !linux_ec_bool(o,"drained") ||
               !linux_ec_bool(o,"native_down") || linux_ec_bool(o,"accepted") || linux_ec_string(o,"saved_profile_id")[0] ||
               g_strcmp0(s->chosen_id,linux_ec_string(o,"candidate_id")))return FALSE;
            s->pending=FALSE;linux_oc_hold(s,FALSE);
            GtkWindow *editor=g_weak_ref_get(&s->editor);
            gboolean adopted=editor && linux_ordered_adopt_measured_v1(editor,s->draft,s->position,o);
            if(editor)g_object_unref(editor);
            if(s->receipt){json_node_free(s->receipt);s->receipt=NULL;}
            gtk_list_store_clear(s->store);
            if(adopted)s->close_wanted=TRUE;
            else gtk_label_set_text(GTK_LABEL(s->status),"The editor or its linked sources changed. Recapture the current prefix.");
            return TRUE;
        }
        const char*saved=linux_ec_string(o,"saved_profile_id");
        if(saved[0]){
            if(s->draft&&!linux_oc_final_saved(s,o))return FALSE;
            if(strlen(saved)>=sizeof(s->saved_profile)||(s->saved_profile[0]&&strcmp(s->saved_profile,saved)))return FALSE;
            g_strlcpy(s->saved_profile,saved,sizeof(s->saved_profile));s->pending=!(linux_ec_bool(o,"drained")&&linux_ec_bool(o,"native_down")&&!linux_ec_bool(o,"active_path_changed"));s->cancel_wanted=s->pending;
            if(s->receipt){json_node_free(s->receipt);s->receipt=NULL;}gtk_list_store_clear(s->store);if(!s->pending)linux_oc_hold(s,FALSE);
            const char*name=linux_ec_string(o,"profile_name");GString*message=g_string_new(NULL);g_string_append_printf(message,"Saved %s for a future connection. %s",name[0]?name:saved,s->pending?"Original cleanup is not confirmed; Cancel will retry.":"The temporary path is disconnected. Use Profiles to load it.");
            if(linux_ec_bool(o,"active_path_changed"))g_string_append(message," The controller reported an unexpected active-path change.");
            const char*failure=linux_ec_string(o,"failure");if(failure[0])g_string_append_printf(message," The comparison was invalidated: %s",failure);gtk_label_set_text(GTK_LABEL(s->status),message->str);g_string_free(message,TRUE);return TRUE;
        }
    }
    if(phase==4){if(s->saved_path||!linux_ec_bool(o,"ok")||linux_ec_bool(o,"active_path_changed"))return FALSE;if(s->receipt){json_node_free(s->receipt);s->receipt=NULL;}char*message=g_strdup_printf("Saved %s. Disconnect before loading this complete profile; the active path is unchanged.",linux_ec_string(o,"profile_name"));gtk_label_set_text(GTK_LABEL(s->status),message);g_free(message);return TRUE;}
    if(strcmp(linux_ec_string(o,"request_id"),s->request))return FALSE;
    if(phase==3){if(!linux_ec_bool(o,"drained")||(s->saved_path&&((!linux_ec_bool(o,"native_down")&&!linux_oc_before_start(o))||linux_ec_bool(o,"active_path_changed"))))return FALSE;s->pending=FALSE;if(s->receipt){json_node_free(s->receipt);s->receipt=NULL;}linux_oc_hold(s,FALSE);gtk_label_set_text(GTK_LABEL(s->status),s->saved_path&&linux_oc_before_start(o)?"Cancelled before the temporary path started.":"Cancelled; original native work drained.");return TRUE;}
    if(s->cancel_wanted||s->close_wanted){s->pending=TRUE;if(s->receipt){json_node_free(s->receipt);s->receipt=NULL;}gtk_list_store_clear(s->store);gtk_label_set_text(GTK_LABEL(s->status),"Waiting for cancellation of this exact completed request.");return TRUE;}
    if(strcmp(linux_ec_string(o,"view_token"),linux_ec_string(linux_oc_root(s->view),"view_token"))||linux_ec_number(o,"prefix_position")!=s->position||!linux_oc_same_measurement(s,o))return FALSE;
    if(s->receipt){
        json_node_free(s->receipt);
    }
    s->receipt=json_node_new(JSON_NODE_OBJECT);json_node_set_object(s->receipt,o);s->pending=!linux_ec_bool(o,"drained");if(!s->pending)linux_oc_hold(s,FALSE);linux_oc_rows(s,TRUE);
    if(s->saved_path){
        gboolean cleanup=linux_ec_bool(o,"cleanup_pending");if(cleanup)s->cancel_wanted=TRUE;
        if(linux_oc_ready(s)&&!strcmp(linux_oc_scope(s),"draft-complete-selected")){
            char*text=g_strdup_printf("Selected execution: %s. Choose a measured hop for this draft.",s->selected_winner);
            gtk_label_set_text(GTK_LABEL(s->status),text);g_free(text);return TRUE;
        }
        gtk_label_set_text(GTK_LABEL(s->status),linux_oc_ready(s)?"Disconnected. Results for this measurement are sorted by 10% trimmed mean and expire 120 seconds after measurement. Select one to save an explicit future profile.":cleanup?"Original cleanup is pending; Cancel will retry before another operation.":s->pending&&s->draft_source?"Testing the original draft. Waiting for its temporary route to close.":s->pending?"Testing the original saved Local path. Waiting for native shutdown before showing choices.":"No adoptable original receipt; retest.");
    }else gtk_label_set_text(GTK_LABEL(s->status),s->pending?"Original cleanup is pending; retry Cancel.":linux_ec_bool(o,"accepted")?"Complete results for this measurement are sorted by trimmed mean. Each expires after 120 seconds. Select one to preview its next-connection path.":"No adoptable original receipt; retest.");return TRUE;
}
static gboolean linux_oc_tick(gpointer data){
    LinuxOrderedCandidates*s=data;if(s->closed)return G_SOURCE_REMOVE;
    if(s->job&&rv_http_ready_v16(s->job)){
        RVHttpJobV16*job=s->job;int phase=s->phase;s->job=NULL;gboolean ok=!atomic_load(&job->cancelled)&&job->result==CURLE_OK&&job->status>=200&&job->status<300;JsonNode*root=ok?parse_json(job->response):NULL;
        if(!root||!JSON_NODE_HOLDS_OBJECT(root)||!linux_oc_receive(s,json_node_get_object(root),phase)){gtk_label_set_text(GTK_LABEL(s->status),"Request failed or changed its original capture. Pending native cleanup will be retried.");if(s->receipt){json_node_free(s->receipt);s->receipt=NULL;}if(phase==2||phase==5)gtk_list_store_clear(s->store);if(phase==2||phase==3||(s->saved_path&&(phase==4||phase==5||phase==6))){s->pending=TRUE;s->cancel_wanted=TRUE;}}
        if(root){
            json_node_free(root);
        }
        rv_http_free_v16(job);s->retry=g_get_monotonic_time()+G_USEC_PER_SEC;
    }
    if(s->auto_run && !s->job){s->auto_run=FALSE;if(!s->close_wanted&&!s->cancel_wanted)gtk_button_clicked(GTK_BUTTON(s->test));}
    if(s->close_wanted&&!s->job&&!s->pending){s->poll=0;gtk_widget_destroy(s->dialog);return G_SOURCE_REMOVE;}
    if(s->pending&&s->cancel_wanted&&!s->job&&g_get_monotonic_time()>=s->retry){char*body=linux_oc_body(s,3),*path=g_strdup_printf("%s/cancel",linux_oc_base(s));linux_oc_send(s,3,path,body);g_free(path);g_free(body);}
    gboolean observe=(s->saved_path&&s->pending&&!s->cancel_wanted)||(!s->pending&&linux_ec_bool(linux_oc_root(s->receipt),"accepted"));
    if(observe&&!s->job&&g_get_monotonic_time()>=s->retry){char*path=g_strdup_printf("%s?request_id=%s",linux_oc_base(s),s->request);linux_oc_send(s,5,path,NULL);g_free(path);}
    GtkTreeIter iter;gboolean valid=gtk_tree_model_get_iter_first(GTK_TREE_MODEL(s->store),&iter);while(valid){gchar*id=NULL;gtk_tree_model_get(GTK_TREE_MODEL(s->store),&iter,1,&id,-1);JsonObject*row=linux_oc_result(s,id?id:"");if(row&&!isfinite(linux_oc_current_score(s,row,g_get_real_time()/1000)))gtk_list_store_set(s->store,&iter,2,"Expired — retest",-1);g_free(id);valid=gtk_tree_model_iter_next(GTK_TREE_MODEL(s->store),&iter);}
    linux_oc_controls(s);return G_SOURCE_CONTINUE;
}
static void linux_oc_cancel(LinuxOrderedCandidates*s){s->cancel_wanted=TRUE;if(s->receipt){json_node_free(s->receipt);s->receipt=NULL;}if(s->phase==2)rv_http_cancel_v16(s->job);gtk_label_set_text(GTK_LABEL(s->status),"Cancelling the original request; waiting for native cleanup.");}
static gboolean linux_oc_delete(GtkWidget*w,GdkEvent*event,gpointer data){(void)w;(void)event;LinuxOrderedCandidates*s=data;if(s->job||s->pending){s->close_wanted=TRUE;linux_oc_cancel(s);return TRUE;}return FALSE;}
static void linux_oc_destroy(GtkWidget*w,gpointer data){
    (void)w;LinuxOrderedCandidates*s=data;s->closed=TRUE;if(s->poll)g_source_remove(s->poll);rv_http_cancel_v16(s->job);rv_http_free_v16(s->job);s->job=NULL;
    if(s->pending&&linux_ec_token(s->request,32)){char*body=linux_oc_body(s,3),*path=g_strdup_printf("%s/cancel",linux_oc_base(s));RVHttpJobV16*cancel=rv_http_start_method_v17(path,body,3000,"Cancel original candidate",0);g_free(path);g_free(body);if(cancel){gint64 deadline=g_get_monotonic_time()+3500000;while(!rv_http_ready_v16(cancel)&&g_get_monotonic_time()<deadline)g_usleep(10000);rv_http_free_v16(cancel);}}
    g_weak_ref_clear(&s->editor);if(s->draft_source)json_node_free(s->draft_source);g_free(s->draft);g_free(s->chosen_id);
    linux_oc_hold(s,FALSE);gtk_list_store_clear(s->store);if(s->view)json_node_free(s->view);if(s->receipt)json_node_free(s->receipt);g_object_unref(s->store);
    if(s->app->window&&g_object_get_data(G_OBJECT(s->app->window),"linux-ordered-candidates")==s)g_object_set_data(G_OBJECT(s->app->window),"linux-ordered-candidates",NULL);
}
static void linux_oc_selection(GtkTreeSelection*selection,gpointer data){
    (void)selection;LinuxOrderedCandidates*s=data;if(s->closed)return;
    JsonObject *choice=linux_oc_selected(s);
    JsonNode *named=linux_ec_member(choice,"proposed_path"), *draft=linux_oc_response_draft_path(s,linux_oc_root(s->view),choice);
    GString *text=g_string_new(NULL);
    JsonNode *paths[]={draft,named};
    for(guint p=0;p<2;p++){
        if(!paths[p] || !JSON_NODE_HOLDS_ARRAY(paths[p]) || (p && draft && json_node_equal(draft,named)))continue;
        g_string_append(text,p?(draft?"\nNamed profile · ":"Proposed complete path: "):"Use in draft · ");
        JsonArray *nodes=json_node_get_array(paths[p]);
        for(guint i=0;i<json_array_get_length(nodes);i++){
            JsonObject *node=linux_oc_root(json_array_get_element(nodes,i));
            if(i)g_string_append(text," → ");
            g_string_append_printf(text,"%s (%s)",linux_ec_string(node,"id"),linux_ec_string(node,"mode"));
        }
    }
    if(!text->len)g_string_append(text,linux_ec_string(choice,"save_reason"));
    gtk_label_set_text(GTK_LABEL(s->preview),text->str);g_string_free(text,TRUE);linux_oc_controls(s);
}
static void linux_oc_action(GtkButton*button,gpointer data){
    LinuxOrderedCandidates*s=data;int action=GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button),"ordered-candidate-action"));if(action==3){linux_oc_cancel(s);return;}if(action==5){gtk_window_close(GTK_WINDOW(s->dialog));return;}if(s->job||(s->pending&&action!=4&&action!=6))return;
    if(action==1){const char*chosen=gtk_combo_box_get_active_id(GTK_COMBO_BOX(s->prefix));if(chosen)s->position=atoi(chosen);char*path=linux_oc_catalog_path(s);linux_oc_send(s,1,path,s->draft);g_free(path);return;}
    if(action==2){linux_oc_controls(s);if(!gtk_widget_get_sensitive(s->test))return;if(!linux_oc_view_fresh(linux_oc_root(s->view),g_get_real_time()/1000)){gtk_label_set_text(GTK_LABEL(s->status),"The catalog expired. Capture this prefix again before testing.");return;}if(!s->view||gtk_tree_selection_count_selected_rows(gtk_tree_view_get_selection(GTK_TREE_VIEW(s->table)))<1){gtk_label_set_text(GTK_LABEL(s->status),"Select at least one candidate row.");return;}if(!routervpn_require_mutation_idle(s->app,s->saved_path?"testing a saved Local path":"testing connected prefix candidates"))return;char*uuid=g_uuid_string_random();guint n=0;for(char*p=uuid;*p;p++)if(*p!='-')s->request[n++]=*p;s->request[n]=0;s->selected_epoch=0;s->selected_winner[0]=0;g_free(uuid);char*body=linux_oc_body(s,2);if(s->receipt){json_node_free(s->receipt);s->receipt=NULL;}s->pending=TRUE;s->cancel_wanted=FALSE;s->saved_admitted=FALSE;linux_oc_hold(s,TRUE);linux_oc_send(s,2,linux_oc_base(s),body);g_free(body);return;}
    if(action==6){
        linux_oc_controls(s);
        if(!gtk_widget_get_sensitive(s->use_draft))return;
        g_autofree char *body=linux_oc_body(s,6), *path=g_strdup_printf("%s/choose",linux_oc_base(s));
        linux_oc_send(s,6,path,body);return;
    }
    if(action==4){linux_oc_controls(s);if(!gtk_widget_get_sensitive(s->save))return;const char*name=gtk_entry_get_text(GTK_ENTRY(s->name));char*trim=g_strdup(name);g_strstrip(trim);gboolean named=trim[0]!='\0';g_free(trim);gboolean final=linux_oc_final_choice(s,linux_oc_selected(s));if((!s->draft||final)&&!named){gtk_label_set_text(GTK_LABEL(s->status),"Enter an explicit next-connection profile name.");return;}char*body=linux_oc_body(s,4),*path=g_strdup_printf("%s/%s",linux_oc_base(s),s->draft&&!final?"choose":"save-profile");linux_oc_send(s,4,path,body);g_free(path);g_free(body);}
}
static void linux_ordered_candidates_open_source(App*app,gboolean saved_path,gboolean saved_prefix,GtkWindow*editor,const char*draft,int position){
    if(!app||!app->window){
        return;
    }
    if(saved_prefix)saved_path=TRUE;
    LinuxOrderedCandidates*old=g_object_get_data(G_OBJECT(app->window),"linux-ordered-candidates");
    if(old&&!old->closed){
        gboolean same=!draft&&!old->draft&&old->saved_path==saved_path&&old->saved_prefix==saved_prefix;
        if(same||old->job||old->pending){
            if(!same)gtk_label_set_text(GTK_LABEL(old->status),"Finish or cancel the current candidate test before opening a different test.");
            gtk_window_present(GTK_WINDOW(old->dialog));return;
        }
        gtk_widget_destroy(old->dialog);
    }
    LinuxOrderedCandidates*s=g_new0(LinuxOrderedCandidates,1);s->app=app;s->draft=g_strdup(draft);s->draft_source=draft?json_from_string(draft,NULL):NULL;s->position=position;g_weak_ref_init(&s->editor,editor);s->saved_path=saved_path;s->saved_prefix=saved_prefix;s->dialog=gtk_window_new(GTK_WINDOW_TOPLEVEL);gtk_window_set_title(GTK_WINDOW(s->dialog),draft?"Measure the next hop":saved_prefix?"Test saved prefix":saved_path?"Test saved Local path":"Candidates through connected prefix");gtk_window_set_transient_for(GTK_WINDOW(s->dialog),editor?editor:GTK_WINDOW(app->window));if(editor)gtk_window_set_modal(GTK_WINDOW(s->dialog),TRUE);gtk_window_set_destroy_with_parent(GTK_WINDOW(s->dialog),TRUE);gtk_window_set_default_size(GTK_WINDOW(s->dialog),820,560);
    GtkWidget*box=gtk_box_new(GTK_ORIENTATION_VERTICAL,10);gtk_container_set_border_width(GTK_CONTAINER(box),16);gtk_container_add(GTK_CONTAINER(s->dialog),box);
    s->note=gtk_label_new("Capture a prefix to see the available measurement. Each scored candidate requires 50 fresh samples through the selected route.");gtk_label_set_line_wrap(GTK_LABEL(s->note),TRUE);gtk_label_set_max_width_chars(GTK_LABEL(s->note),90);gtk_box_pack_start(GTK_BOX(box),s->note,FALSE,FALSE,0);
    s->prefix=gtk_combo_box_text_new();gtk_box_pack_start(GTK_BOX(box),s->prefix,FALSE,FALSE,0);s->store=gtk_list_store_new(5,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_POINTER,G_TYPE_DOUBLE);gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(s->store),4,linux_oc_compare,NULL,NULL);s->table=gtk_tree_view_new_with_model(GTK_TREE_MODEL(s->store));gtk_tree_selection_set_mode(gtk_tree_view_get_selection(GTK_TREE_VIEW(s->table)),GTK_SELECTION_MULTIPLE);
    GtkCellRenderer*r=gtk_cell_renderer_text_new();gtk_tree_view_append_column(GTK_TREE_VIEW(s->table),gtk_tree_view_column_new_with_attributes("Saved candidate",r,"text",0,NULL));r=gtk_cell_renderer_text_new();gtk_tree_view_append_column(GTK_TREE_VIEW(s->table),gtk_tree_view_column_new_with_attributes("Latency",r,"text",2,NULL));GtkWidget*scroll=gtk_scrolled_window_new(NULL,NULL);gtk_container_add(GTK_CONTAINER(scroll),s->table);gtk_box_pack_start(GTK_BOX(box),scroll,TRUE,TRUE,0);
    s->preview=gtk_label_new("Select a result to preview its complete next-connection path.");gtk_label_set_line_wrap(GTK_LABEL(s->preview),TRUE);gtk_box_pack_start(GTK_BOX(box),s->preview,FALSE,FALSE,0);s->name=gtk_entry_new();gtk_entry_set_placeholder_text(GTK_ENTRY(s->name),"Explicit next-connection profile name");gtk_entry_set_max_length(GTK_ENTRY(s->name),64);if(draft)gtk_widget_set_no_show_all(s->name,TRUE);gtk_box_pack_start(GTK_BOX(box),s->name,FALSE,FALSE,0);
    s->status=gtk_label_new("Capturing saved sources…");gtk_label_set_line_wrap(GTK_LABEL(s->status),TRUE);gtk_box_pack_start(GTK_BOX(box),s->status,FALSE,FALSE,0);GtkWidget*buttons=gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);const char*labels[]={"Capture this prefix","Test selected candidates","Cancel test","Save next-connection profile","Close","Use in draft"};GtkWidget*items[6];for(int i=0;i<6;i++){items[i]=gtk_button_new_with_label(labels[i]);g_object_set_data(G_OBJECT(items[i]),"ordered-candidate-action",GINT_TO_POINTER(i+1));g_signal_connect(items[i],"clicked",G_CALLBACK(linux_oc_action),s);gtk_container_add(GTK_CONTAINER(buttons),items[i]);}s->refresh=items[0];s->test=items[1];s->cancel=items[2];s->save=items[3];s->use_draft=items[5];gtk_widget_set_no_show_all(s->use_draft,TRUE);gtk_box_reorder_child(GTK_BOX(buttons),s->use_draft,3);if(draft)gtk_button_set_label(GTK_BUTTON(s->save),"Add measured hop to draft");gtk_box_pack_start(GTK_BOX(box),buttons,FALSE,FALSE,0);
    g_object_set_data(G_OBJECT(app->window),"linux-ordered-candidates",s);g_object_set_data_full(G_OBJECT(s->dialog),"ordered-candidate-state",s,g_free);g_signal_connect(s->dialog,"delete-event",G_CALLBACK(linux_oc_delete),s);g_signal_connect(s->dialog,"destroy",G_CALLBACK(linux_oc_destroy),s);g_signal_connect(gtk_tree_view_get_selection(GTK_TREE_VIEW(s->table)),"changed",G_CALLBACK(linux_oc_selection),s);s->poll=g_timeout_add(200,linux_oc_tick,s);char*path=linux_oc_catalog_path(s);linux_oc_send(s,1,path,s->draft);g_free(path);gtk_widget_show_all(s->dialog);
}
static void linux_ordered_candidates_open_draft(App *app, GtkWindow *parent, const char *draft, int position) {
    linux_ordered_candidates_open_source(app,TRUE,TRUE,parent,draft,position);
}
static void linux_ordered_candidates_open_captured(App*app,gboolean saved_path,gboolean saved_prefix){
    linux_ordered_candidates_open_source(app,saved_path,saved_prefix,NULL,NULL,0);
}
static void linux_ordered_candidates_open_purpose(App*app,gboolean saved_path){linux_ordered_candidates_open_captured(app,saved_path,FALSE);}
static void linux_ordered_candidates_open(App*app){linux_ordered_candidates_open_purpose(app,FALSE);}
