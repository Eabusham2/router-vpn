/* Connected candidate jobs keep the exact HTTP/native owner. A successful save
 * creates a complete next-connection profile; it never edits the active path. */
typedef struct {
    App *app;
    GtkWidget *dialog,*prefix,*table,*status,*preview,*name,*refresh,*test,*save,*cancel;
    GtkListStore *store;
    RVHttpJobV16 *job;
    JsonNode *view,*receipt;
    guint poll;
    int phase,position;
    char request[33];
    gboolean pending,cancel_wanted,close_wanted,closed,held;
    gint64 retry;
} LinuxOrderedCandidates;
static double linux_oc_score(JsonObject *o,gint64 now){
    JsonArray *rows=linux_ec_array(o,"results");
    double at=linux_ec_number(o,"measured_at"),expires=linux_ec_number(o,"expires_at");
    if(strcmp(linux_ec_string(o,"measurement"),"routed-tcp-connect")||strcmp(linux_ec_string(o,"stage"),"complete")||!linux_ec_bool(o,"complete")||!linux_ec_bool(o,"drained")||!isfinite(at)||at<=0||at>now||expires!=at+120000||expires<=now||rows==NULL||json_array_get_length(rows)!=1)return NAN;
    JsonNode*n=json_array_get_element(rows,0);JsonObject*r=n&&JSON_NODE_HOLDS_OBJECT(n)?json_node_get_object(n):NULL;
    JsonObject*b=linux_ec_object(r,"benchmark"),*d=linux_ec_object(b,"distribution");
    if(strcmp(linux_ec_string(r,"node_id"),linux_ec_string(o,"candidate_id"))||strcmp(linux_ec_string(r,"kind"),"tcp-connect")||strcmp(linux_ec_string(r,"role"),"candidate")||!linux_ec_bool(r,"ready")||strcmp(linux_ec_string(b,"measurement"),"routed-tcp-connect")||linux_ec_number(b,"attempts")!=50||linux_ec_number(b,"failed")!=0||linux_ec_number(d,"samples")!=50)return NAN;
    double score=linux_ec_number(b,"trimmed_mean_ms"),min=linux_ec_number(d,"min_ms"),max=linux_ec_number(d,"max_ms");
    return isfinite(score)&&isfinite(min)&&isfinite(max)&&min>0&&score>=min&&score<=max?score:NAN;
}
static JsonObject*linux_oc_root(JsonNode*n){return n&&JSON_NODE_HOLDS_OBJECT(n)?json_node_get_object(n):NULL;}
static JsonObject*linux_oc_result(LinuxOrderedCandidates*s,const char*id){
    JsonArray*rows=linux_ec_array(linux_oc_root(s->receipt),"results");
    for(guint i=0;rows&&i<json_array_get_length(rows);i++){JsonObject*r=linux_oc_root(json_array_get_element(rows,i));if(strcmp(linux_ec_string(r,"candidate_id"),id)==0)return r;}return NULL;
}
static JsonObject*linux_oc_selected(LinuxOrderedCandidates*s){
    GtkTreeSelection*selection=gtk_tree_view_get_selection(GTK_TREE_VIEW(s->table));GtkTreeModel*model=NULL;GList*paths=gtk_tree_selection_get_selected_rows(selection,&model);JsonObject*choice=NULL;
    if(g_list_length(paths)==1){GtkTreeIter iter;if(gtk_tree_model_get_iter(model,&iter,paths->data))gtk_tree_model_get(model,&iter,3,&choice,-1);}g_list_free_full(paths,(GDestroyNotify)gtk_tree_path_free);return choice;
}
static void linux_oc_hold(LinuxOrderedCandidates*s,gboolean hold){LinuxAsyncActionsV16*a=linux_async_state_v16(s->app);if(hold&&!s->held){if(a)a->auxiliary_jobs++;s->held=TRUE;}else if(!hold&&s->held){if(a&&a->auxiliary_jobs>0)a->auxiliary_jobs--;s->held=FALSE;}}
static void linux_oc_controls(LinuxOrderedCandidates*s){
    if(s->closed)return;
    const char*prefix=gtk_combo_box_get_active_id(GTK_COMBO_BOX(s->prefix));gboolean captured=prefix&&atoi(prefix)==s->position;gboolean idle=s->job==NULL&&!s->pending;gtk_widget_set_sensitive(s->refresh,idle);gtk_widget_set_sensitive(s->prefix,idle);gtk_widget_set_sensitive(s->test,idle&&captured&&s->view!=NULL);gtk_widget_set_sensitive(s->cancel,s->pending);
    JsonObject*choice=linux_oc_selected(s);JsonArray*path=linux_ec_array(choice,"proposed_path");JsonObject*row=linux_oc_result(s,linux_ec_string(choice,"id"));
    gtk_widget_set_sensitive(s->save,idle&&captured&&linux_ec_bool(linux_oc_root(s->receipt),"accepted")&&path&&json_array_get_length(path)>=2&&isfinite(linux_oc_score(row,g_get_real_time()/1000)));
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
    if(phase!=3){
        json_builder_set_member_name(b,"view_token");json_builder_add_string_value(b,linux_ec_string(linux_oc_root(s->view),"view_token"));
        if(phase==2){
            json_builder_set_member_name(b,"prefix_position");json_builder_add_int_value(b,s->position);json_builder_set_member_name(b,"samples");json_builder_add_int_value(b,50);
            json_builder_set_member_name(b,"candidate_ids");json_builder_begin_array(b);
            GtkTreeModel*model=NULL;GList*paths=gtk_tree_selection_get_selected_rows(gtk_tree_view_get_selection(GTK_TREE_VIEW(s->table)),&model);
            for(GList*i=paths;i;i=i->next){GtkTreeIter iter;gchar*id=NULL;if(gtk_tree_model_get_iter(model,&iter,i->data)){gtk_tree_model_get(model,&iter,1,&id,-1);if(id)json_builder_add_string_value(b,id);g_free(id);}}g_list_free_full(paths,(GDestroyNotify)gtk_tree_path_free);json_builder_end_array(b);
        }else{
            JsonObject*choice=linux_oc_selected(s);json_builder_set_member_name(b,"candidate_id");json_builder_add_string_value(b,linux_ec_string(choice,"id"));json_builder_set_member_name(b,"name");json_builder_add_string_value(b,gtk_entry_get_text(GTK_ENTRY(s->name)));
            json_builder_set_member_name(b,"proposed_path");JsonNode*n=linux_ec_member(choice,"proposed_path");if(n)json_builder_add_value(b,json_node_copy(n));else json_builder_add_null_value(b);
        }
    }
    json_builder_end_object(b);JsonNode*n=json_builder_get_root(b);JsonGenerator*g=json_generator_new();json_generator_set_root(g,n);char*body=json_generator_to_data(g,NULL);g_object_unref(g);json_node_free(n);g_object_unref(b);return body;
}
static gint linux_oc_compare(GtkTreeModel*model,GtkTreeIter*a,GtkTreeIter*b,gpointer data){
    (void)data;double x,y;gchar*left=NULL,*right=NULL;gtk_tree_model_get(model,a,4,&x,1,&left,-1);gtk_tree_model_get(model,b,4,&y,1,&right,-1);int result=x<y?-1:x>y?1:g_strcmp0(left,right);g_free(left);g_free(right);return result;
}
static void linux_oc_rows(LinuxOrderedCandidates*s,gboolean measured){
    gtk_list_store_clear(s->store);JsonArray*choices=linux_ec_array(linux_oc_root(s->view),"candidates");
    for(guint i=0;choices&&i<json_array_get_length(choices);i++){
        JsonObject*c=linux_oc_root(json_array_get_element(choices,i));const char*id=linux_ec_string(c,"id");double score=linux_oc_score(linux_oc_result(s,id),g_get_real_time()/1000);
        if(measured&&!isfinite(score)){
            continue;
        }
        char*text=isfinite(score)?g_strdup_printf("%.2f ms · 50/50 TCP",score):g_strdup("Not tested");GtkTreeIter iter;gtk_list_store_append(s->store,&iter);gtk_list_store_set(s->store,&iter,0,linux_ec_string(c,"name"),1,id,2,text,3,c,4,isfinite(score)?score:G_MAXDOUBLE,-1);g_free(text);
    }
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(s->store),measured?4:GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID,GTK_SORT_ASCENDING);
}
static gboolean linux_oc_receive(LinuxOrderedCandidates*s,JsonObject*o,int phase){
    if(phase==1){
        const char*token=linux_ec_string(o,"view_token");JsonArray*choices=linux_ec_array(o,"candidates");double expires=linux_ec_number(o,"expires_at");
        if(!linux_ec_token(token,64)||linux_ec_number(o,"prefix_position")!=s->position||!isfinite(expires)||expires<=g_get_real_time()/1000||!choices||json_array_get_length(choices)<1)return FALSE;
        gtk_list_store_clear(s->store);if(s->view)json_node_free(s->view);s->view=json_node_new(JSON_NODE_OBJECT);json_node_set_object(s->view,o);
        if(s->receipt){json_node_free(s->receipt);s->receipt=NULL;}gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(s->prefix));JsonArray*prefixes=linux_ec_array(o,"prefixes");
        for(guint i=0;prefixes&&i<json_array_get_length(prefixes);i++){JsonObject*p=linux_oc_root(json_array_get_element(prefixes,i));double value=linux_ec_number(p,"position");if(!isfinite(value)||value<0||value>7||floor(value)!=value)continue;char*id=g_strdup_printf("%d",(int)value),*name=g_strdup_printf("After node %d · %s · %s",(int)value+1,linux_ec_string(p,"name"),linux_ec_string(p,"mode"));gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(s->prefix),id,name);if((int)value==s->position)gtk_combo_box_set_active_id(GTK_COMBO_BOX(s->prefix),id);g_free(id);g_free(name);}
        linux_oc_rows(s,FALSE);gtk_label_set_text(GTK_LABEL(s->status),"Select saved candidates and test through this captured packet prefix.");return TRUE;
    }
    if(phase==4){if(!linux_ec_bool(o,"ok")||linux_ec_bool(o,"active_path_changed"))return FALSE;if(s->receipt){json_node_free(s->receipt);s->receipt=NULL;}char*message=g_strdup_printf("Saved %s. Disconnect before loading this complete profile; the active path is unchanged.",linux_ec_string(o,"profile_name"));gtk_label_set_text(GTK_LABEL(s->status),message);g_free(message);return TRUE;}
    if(strcmp(linux_ec_string(o,"request_id"),s->request))return FALSE;
    if(phase==3){if(!linux_ec_bool(o,"drained"))return FALSE;s->pending=FALSE;if(s->receipt){json_node_free(s->receipt);s->receipt=NULL;}linux_oc_hold(s,FALSE);gtk_label_set_text(GTK_LABEL(s->status),"Cancelled; original native work drained.");return TRUE;}
    if(s->cancel_wanted||s->close_wanted){s->pending=TRUE;if(s->receipt){json_node_free(s->receipt);s->receipt=NULL;}gtk_list_store_clear(s->store);gtk_label_set_text(GTK_LABEL(s->status),"Waiting for cancellation of this exact completed request.");return TRUE;}
    if(strcmp(linux_ec_string(o,"view_token"),linux_ec_string(linux_oc_root(s->view),"view_token"))||linux_ec_number(o,"prefix_position")!=s->position)return FALSE;
    if(s->receipt){
        json_node_free(s->receipt);
    }
    s->receipt=json_node_new(JSON_NODE_OBJECT);json_node_set_object(s->receipt,o);s->pending=!linux_ec_bool(o,"drained");if(!s->pending)linux_oc_hold(s,FALSE);linux_oc_rows(s,TRUE);
    gtk_label_set_text(GTK_LABEL(s->status),s->pending?"Original cleanup is pending; retry Cancel.":linux_ec_bool(o,"accepted")?"Complete TCP results sorted by trimmed mean. Each expires after 120 seconds. Select one to preview its next-connection path.":"No adoptable original receipt; retest.");return TRUE;
}
static gboolean linux_oc_tick(gpointer data){
    LinuxOrderedCandidates*s=data;if(s->closed)return G_SOURCE_REMOVE;
    if(s->job&&rv_http_ready_v16(s->job)){
        RVHttpJobV16*job=s->job;int phase=s->phase;s->job=NULL;gboolean ok=!atomic_load(&job->cancelled)&&job->result==CURLE_OK&&job->status>=200&&job->status<300;JsonNode*root=ok?parse_json(job->response):NULL;
        if(!root||!JSON_NODE_HOLDS_OBJECT(root)||!linux_oc_receive(s,json_node_get_object(root),phase)){gtk_label_set_text(GTK_LABEL(s->status),"Request failed or changed its original capture. Pending native cleanup will be retried.");if(s->receipt){json_node_free(s->receipt);s->receipt=NULL;}if(phase==2||phase==5)gtk_list_store_clear(s->store);if(phase==2||phase==3){s->pending=TRUE;s->cancel_wanted=TRUE;}}
        if(root){
            json_node_free(root);
        }
        rv_http_free_v16(job);s->retry=g_get_monotonic_time()+G_USEC_PER_SEC;
    }
    if(s->close_wanted&&!s->job&&!s->pending){s->poll=0;gtk_widget_destroy(s->dialog);return G_SOURCE_REMOVE;}
    if(s->pending&&s->cancel_wanted&&!s->job&&g_get_monotonic_time()>=s->retry){char*body=linux_oc_body(s,3);linux_oc_send(s,3,"/api/multihop/prefix-candidates/cancel",body);g_free(body);}
    if(!s->pending&&!s->job&&linux_ec_bool(linux_oc_root(s->receipt),"accepted")&&g_get_monotonic_time()>=s->retry){char*path=g_strdup_printf("/api/multihop/prefix-candidates?request_id=%s",s->request);linux_oc_send(s,5,path,NULL);g_free(path);}
    GtkTreeIter iter;gboolean valid=gtk_tree_model_get_iter_first(GTK_TREE_MODEL(s->store),&iter);while(valid){gchar*id=NULL;gtk_tree_model_get(GTK_TREE_MODEL(s->store),&iter,1,&id,-1);JsonObject*row=linux_oc_result(s,id?id:"");if(row&&!isfinite(linux_oc_score(row,g_get_real_time()/1000)))gtk_list_store_set(s->store,&iter,2,"Expired — retest",-1);g_free(id);valid=gtk_tree_model_iter_next(GTK_TREE_MODEL(s->store),&iter);}
    linux_oc_controls(s);return G_SOURCE_CONTINUE;
}
static void linux_oc_cancel(LinuxOrderedCandidates*s){s->cancel_wanted=TRUE;if(s->receipt){json_node_free(s->receipt);s->receipt=NULL;}if(s->phase==2)rv_http_cancel_v16(s->job);gtk_label_set_text(GTK_LABEL(s->status),"Cancelling the original request; waiting for native cleanup.");}
static gboolean linux_oc_delete(GtkWidget*w,GdkEvent*event,gpointer data){(void)w;(void)event;LinuxOrderedCandidates*s=data;if(s->job||s->pending){s->close_wanted=TRUE;linux_oc_cancel(s);return TRUE;}return FALSE;}
static void linux_oc_destroy(GtkWidget*w,gpointer data){
    (void)w;LinuxOrderedCandidates*s=data;s->closed=TRUE;if(s->poll)g_source_remove(s->poll);rv_http_cancel_v16(s->job);rv_http_free_v16(s->job);s->job=NULL;
    if(s->pending&&linux_ec_token(s->request,32)){char*body=linux_oc_body(s,3);RVHttpJobV16*cancel=rv_http_start_method_v17("/api/multihop/prefix-candidates/cancel",body,3000,"Cancel original candidate",0);g_free(body);if(cancel){gint64 deadline=g_get_monotonic_time()+3500000;while(!rv_http_ready_v16(cancel)&&g_get_monotonic_time()<deadline)g_usleep(10000);rv_http_free_v16(cancel);}}
    linux_oc_hold(s,FALSE);gtk_list_store_clear(s->store);if(s->view)json_node_free(s->view);if(s->receipt)json_node_free(s->receipt);g_object_unref(s->store);
    if(s->app->window&&g_object_get_data(G_OBJECT(s->app->window),"linux-ordered-candidates")==s)g_object_set_data(G_OBJECT(s->app->window),"linux-ordered-candidates",NULL);
}
static void linux_oc_selection(GtkTreeSelection*selection,gpointer data){
    (void)selection;LinuxOrderedCandidates*s=data;if(s->closed)return;JsonObject*choice=linux_oc_selected(s);JsonArray*nodes=linux_ec_array(choice,"proposed_path");GString*text=g_string_new(nodes?"Proposed complete path: ":linux_ec_string(choice,"save_reason"));
    for(guint i=0;nodes&&i<json_array_get_length(nodes);i++){JsonObject*n=linux_oc_root(json_array_get_element(nodes,i));if(i)g_string_append(text," → ");g_string_append_printf(text,"%s (%s)",linux_ec_string(n,"id"),linux_ec_string(n,"mode"));}gtk_label_set_text(GTK_LABEL(s->preview),text->str);g_string_free(text,TRUE);linux_oc_controls(s);
}
static void linux_oc_action(GtkButton*button,gpointer data){
    LinuxOrderedCandidates*s=data;int action=GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button),"ordered-candidate-action"));if(action==3){linux_oc_cancel(s);return;}if(action==5){gtk_window_close(GTK_WINDOW(s->dialog));return;}if(s->job||s->pending)return;
    if(action==1){const char*chosen=gtk_combo_box_get_active_id(GTK_COMBO_BOX(s->prefix));if(chosen)s->position=atoi(chosen);char*path=g_strdup_printf("/api/multihop/prefix-candidates/catalog?prefix_position=%d",s->position);linux_oc_send(s,1,path,NULL);g_free(path);return;}
    if(action==2){linux_oc_controls(s);if(!gtk_widget_get_sensitive(s->test))return;if(!s->view||gtk_tree_selection_count_selected_rows(gtk_tree_view_get_selection(GTK_TREE_VIEW(s->table)))<1){gtk_label_set_text(GTK_LABEL(s->status),"Select at least one candidate row.");return;}if(!routervpn_require_mutation_idle(s->app,"testing connected prefix candidates"))return;char*uuid=g_uuid_string_random();guint n=0;for(char*p=uuid;*p;p++)if(*p!='-')s->request[n++]=*p;s->request[n]=0;g_free(uuid);char*body=linux_oc_body(s,2);if(s->receipt){json_node_free(s->receipt);s->receipt=NULL;}s->pending=TRUE;s->cancel_wanted=FALSE;linux_oc_hold(s,TRUE);linux_oc_send(s,2,"/api/multihop/prefix-candidates",body);g_free(body);return;}
    if(action==4){linux_oc_controls(s);if(!gtk_widget_get_sensitive(s->save))return;const char*name=gtk_entry_get_text(GTK_ENTRY(s->name));char*trim=g_strdup(name);g_strstrip(trim);gboolean named=trim[0]!='\0';g_free(trim);if(!named){gtk_label_set_text(GTK_LABEL(s->status),"Enter an explicit next-connection profile name.");return;}char*body=linux_oc_body(s,4);linux_oc_send(s,4,"/api/multihop/prefix-candidates/save-profile",body);g_free(body);}
}
static void linux_ordered_candidates_open(App*app){
    if(!app||!app->window){
        return;
    }
    LinuxOrderedCandidates*old=g_object_get_data(G_OBJECT(app->window),"linux-ordered-candidates");if(old&&!old->closed){gtk_window_present(GTK_WINDOW(old->dialog));return;}
    LinuxOrderedCandidates*s=g_new0(LinuxOrderedCandidates,1);s->app=app;s->dialog=gtk_window_new(GTK_WINDOW_TOPLEVEL);gtk_window_set_title(GTK_WINDOW(s->dialog),"Candidates through connected prefix");gtk_window_set_transient_for(GTK_WINDOW(s->dialog),GTK_WINDOW(app->window));gtk_window_set_destroy_with_parent(GTK_WINDOW(s->dialog),TRUE);gtk_window_set_default_size(GTK_WINDOW(s->dialog),820,560);
    GtkWidget*box=gtk_box_new(GTK_ORIENTATION_VERTICAL,10);gtk_container_set_border_width(GTK_CONTAINER(box),16);gtk_container_add(GTK_CONTAINER(s->dialog),box);
    GtkWidget*note=gtk_label_new("50 TCP connections to saved SS2022 candidates through an existing WireGuard/AWG prefix. This is not ICMP or candidate authentication. Save explicitly for the next connection; the active path stays unchanged.");gtk_label_set_line_wrap(GTK_LABEL(note),TRUE);gtk_label_set_max_width_chars(GTK_LABEL(note),90);gtk_box_pack_start(GTK_BOX(box),note,FALSE,FALSE,0);
    s->prefix=gtk_combo_box_text_new();gtk_box_pack_start(GTK_BOX(box),s->prefix,FALSE,FALSE,0);s->store=gtk_list_store_new(5,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_POINTER,G_TYPE_DOUBLE);gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(s->store),4,linux_oc_compare,NULL,NULL);s->table=gtk_tree_view_new_with_model(GTK_TREE_MODEL(s->store));gtk_tree_selection_set_mode(gtk_tree_view_get_selection(GTK_TREE_VIEW(s->table)),GTK_SELECTION_MULTIPLE);
    GtkCellRenderer*r=gtk_cell_renderer_text_new();gtk_tree_view_append_column(GTK_TREE_VIEW(s->table),gtk_tree_view_column_new_with_attributes("Saved candidate",r,"text",0,NULL));r=gtk_cell_renderer_text_new();gtk_tree_view_append_column(GTK_TREE_VIEW(s->table),gtk_tree_view_column_new_with_attributes("TCP timing",r,"text",2,NULL));GtkWidget*scroll=gtk_scrolled_window_new(NULL,NULL);gtk_container_add(GTK_CONTAINER(scroll),s->table);gtk_box_pack_start(GTK_BOX(box),scroll,TRUE,TRUE,0);
    s->preview=gtk_label_new("Select a result to preview its complete next-connection path.");gtk_label_set_line_wrap(GTK_LABEL(s->preview),TRUE);gtk_box_pack_start(GTK_BOX(box),s->preview,FALSE,FALSE,0);s->name=gtk_entry_new();gtk_entry_set_placeholder_text(GTK_ENTRY(s->name),"Explicit next-connection profile name");gtk_entry_set_max_length(GTK_ENTRY(s->name),64);gtk_box_pack_start(GTK_BOX(box),s->name,FALSE,FALSE,0);
    s->status=gtk_label_new("Capturing saved sources…");gtk_label_set_line_wrap(GTK_LABEL(s->status),TRUE);gtk_box_pack_start(GTK_BOX(box),s->status,FALSE,FALSE,0);GtkWidget*buttons=gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);const char*labels[]={"Capture this prefix","Test selected candidates","Cancel test","Save next-connection profile","Close"};GtkWidget*items[5];for(int i=0;i<5;i++){items[i]=gtk_button_new_with_label(labels[i]);g_object_set_data(G_OBJECT(items[i]),"ordered-candidate-action",GINT_TO_POINTER(i+1));g_signal_connect(items[i],"clicked",G_CALLBACK(linux_oc_action),s);gtk_container_add(GTK_CONTAINER(buttons),items[i]);}s->refresh=items[0];s->test=items[1];s->cancel=items[2];s->save=items[3];gtk_box_pack_start(GTK_BOX(box),buttons,FALSE,FALSE,0);
    g_object_set_data(G_OBJECT(app->window),"linux-ordered-candidates",s);g_object_set_data_full(G_OBJECT(s->dialog),"ordered-candidate-state",s,g_free);g_signal_connect(s->dialog,"delete-event",G_CALLBACK(linux_oc_delete),s);g_signal_connect(s->dialog,"destroy",G_CALLBACK(linux_oc_destroy),s);g_signal_connect(gtk_tree_view_get_selection(GTK_TREE_VIEW(s->table)),"changed",G_CALLBACK(linux_oc_selection),s);s->poll=g_timeout_add(200,linux_oc_tick,s);linux_oc_send(s,1,"/api/multihop/prefix-candidates/catalog?prefix_position=0",NULL);gtk_widget_show_all(s->dialog);
}
