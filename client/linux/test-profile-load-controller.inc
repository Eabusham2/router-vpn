/* HTTP boundary for the shipping GTK Load protocol. The harness supplies its
 * own legacy-shaped snapshot, while this controller tracks real phase order. */
static char *fixture_load_op, *fixture_load_state, *fixture_load_snapshot;
static gboolean fixture_load_finished;
static guint fixture_load_commits, fixture_load_revision;
static const char *fixture_drop_action;
static const char *fixture_reject_action;
static gboolean fixture_bad_absent;
#define FIXTURE_LOAD_GEN "abcdef0123456789abcdef0123456789"
#define FIXTURE_LOAD_SHA "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

static gboolean fixture_load_http(const char *path,const char *body,Buffer *out,char **error) {
    const char *action=strrchr(path,'/')+1;
    g_autoptr(JsonNode) req=parse_json(body);
    JsonObject *q=json_node_get_object(req);
    const char *op=obj_string(q,"operation_id");
    if(fixture_reject_action && !strcmp(fixture_reject_action,action)){
        fixture_reject_action=NULL;if(error)*error=g_strdup("fixture refused request");return FALSE;
    }
    gboolean absent=FALSE, superseded=FALSE;
    g_autofree char *revision=g_strdup_printf("%u",fixture_load_revision);
    if(!strcmp(action,"cancel") && g_strcmp0(op,fixture_load_op)){
        if(strcmp(obj_string(q,"expected_revision"),revision))superseded=TRUE;
        else{
            check(!fixture_load_op||fixture_load_finished,"cancel replaced a live owner");
            g_free(fixture_load_state);fixture_load_state=g_strdup("aborted");g_free(fixture_load_op);fixture_load_op=g_strdup(op);
            g_clear_pointer(&fixture_load_snapshot,g_free);fixture_load_finished=FALSE;fixture_load_revision++;
        }
    }else
    if(!strcmp(action,"prepare")){
        check(strlen(op)==32,"prepare omitted unique operation");
        if(strcmp(obj_string(q,"expected_revision"),revision)){if(error)*error=g_strdup("stale revision");return FALSE;}
        fixture_load_revision++;
        check(fixture_load_finished || !fixture_load_op,"prepare replaced unfinished owner");
        Buffer snapshot={0};check(api_request("/fixture/profile-snapshot","POST",body,15000,&snapshot,error),"snapshot fixture absent");
        g_autoptr(JsonNode) n=parse_json(snapshot.data);g_free(snapshot.data);
        JsonObject *s=json_node_get_object(n);
        const char *selected=obj_string(s,"selected_node_id");
        if(!selected[0]){json_object_set_string_member(s,"selected_node_id","exit");selected="exit";}
        json_object_set_boolean_member(s,"ok",TRUE);
        JsonObject *p=json_object_new();json_object_set_string_member(p,"id",obj_string(q,"id"));json_object_set_string_member(p,"node_id",selected);
        json_object_set_string_member(p,"mode",obj_string(s,"mode"));json_object_set_object_member(s,"profile",p);
        if(!json_object_has_member(s,"multihop_execution"))json_object_set_string_member(s,"multihop_execution","local");
        if(!json_object_has_member(s,"profile_tokens")&&!json_object_has_member(s,"multihop_nodes")){
            JsonObject *tokens=json_object_new();json_object_set_string_member(tokens,selected,FIXTURE_LOAD_SHA);
            if(json_object_get_boolean_member(s,"multihop_enabled")){
                json_object_set_string_member(tokens,obj_string(s,"multihop_entry_id"),FIXTURE_LOAD_SHA);
                json_object_set_string_member(tokens,obj_string(s,"multihop_exit_id"),FIXTURE_LOAD_SHA);
            }
            json_object_set_object_member(s,"profile_tokens",tokens);
        }
        if(!json_object_has_member(s,"multihop_nodes"))json_object_set_null_member(s,"multihop_nodes");
        g_free(fixture_load_snapshot);fixture_load_snapshot=json_to_string(n,FALSE);g_free(fixture_load_op);fixture_load_op=g_strdup(op);
        g_free(fixture_load_state);fixture_load_state=g_strdup("prepared");fixture_load_finished=FALSE;
    }else if(!strcmp(action,"status") && g_strcmp0(op,fixture_load_op)) absent=TRUE;
    else{
        check(fixture_load_op&&!strcmp(op,fixture_load_op),"wrong Load operation");
        if((strcmp(action,"status") && strcmp(action,"cancel")) || json_object_has_member(q,"generation")){
            check(!strcmp(obj_string(q,"generation"),FIXTURE_LOAD_GEN)&&!strcmp(obj_string(q,"receipt_sha256"),FIXTURE_LOAD_SHA),"original generation and digest lost");
        }
        if(!strcmp(action,"commit")||!strcmp(action,"abort")){
            check(!strcmp(fixture_load_state,"prepared"),"wrong terminal transition");
            g_free(fixture_load_state);fixture_load_state=g_strdup(!strcmp(action,"commit")?"committed":"aborted");
            if(!strcmp(action,"commit"))fixture_load_commits++;
        }else if(!strcmp(action,"finish")){
            check(strcmp(fixture_load_state,"prepared")!=0,"prepared operation finished");fixture_load_finished=TRUE;
        }else check(!strcmp(action,"status")||!strcmp(action,"cancel"),"unknown Load phase");
    }
    if(fixture_drop_action && !strcmp(fixture_drop_action,action)){
        fixture_drop_action=NULL;if(error)*error=g_strdup("fixture lost reply");return FALSE;
    }
    JsonObject *tx=json_object_new(),*env=json_object_new();
    json_object_set_string_member(tx,"operation_id",op);
    json_object_set_string_member(tx,"state",absent?"absent":superseded?"superseded":fixture_load_state);json_object_set_boolean_member(tx,"finished",superseded||(!absent&&fixture_load_finished));
    if(!absent&&!superseded){json_object_set_string_member(tx,"generation",FIXTURE_LOAD_GEN);json_object_set_string_member(tx,"receipt_sha256",FIXTURE_LOAD_SHA);}
    g_autofree char *latest=g_strdup_printf("%u",fixture_load_revision);json_object_set_string_member(env,"revision",latest);
    json_object_set_boolean_member(env,"ok",TRUE);json_object_set_object_member(env,"transaction",tx);
    if(absent||superseded||!fixture_load_snapshot)json_object_set_null_member(env,"snapshot");else json_object_set_member(env,"snapshot",parse_json(fixture_load_snapshot));
    if(absent&&fixture_bad_absent){fixture_bad_absent=FALSE;json_object_set_string_member(tx,"generation",FIXTURE_LOAD_GEN);}
    g_autoptr(JsonNode) root=json_node_new(JSON_NODE_OBJECT);json_node_take_object(root,env);
    out->data=json_to_string(root,FALSE);out->len=strlen(out->data);return TRUE;
}
