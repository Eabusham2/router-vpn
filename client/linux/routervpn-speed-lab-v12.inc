typedef struct {
    App *app;
    GtkWidget *dialog;
    GtkWidget *scope;
    GtkWidget *topology;
    GtkWidget *node;
    GtkWidget *entry;
    GtkWidget *exit;
    GtkWidget *mode;
    GtkWidget *base;
    GtkWidget *exit_mode;
    GtkWidget *layers;
    GtkWidget *duration_mode;
    GtkWidget *min_time;
    GtkWidget *max_time;
    GtkWidget *min_label;
    GtkWidget *max_label;
    GtkWidget *daita;
    GtkWidget *jumbo;
    GtkWidget *encrypted;
    GtkWidget *obfuscated;
    GtkWidget *idle;
    GtkWidget *download;
    GtkWidget *upload;
    GtkWidget *idle_detail;
    GtkWidget *download_detail;
    GtkWidget *upload_detail;
    GtkWidget *status;
    GtkWidget *detail;
    GtkWidget *run;
    GThread *worker;
    guint poll_source;
    gint cancelled;
    gint complete;
    gboolean closed;
    gboolean owns_slot;
    gboolean loading_options;
    gboolean options_ready;
    gboolean request_ok;
    long request_timeout;
    char *request_body;
    char *request_error;
    Buffer response;
} LinuxSpeedLabV12;

/* Only the worker touches response storage until complete is published. All
 * GTK access stays on the main thread; close cancels and joins before freeing
 * the dialog state or allowing the app to clean up libcurl. */
#define LINUX_SPEED_LAB_RESPONSE_LIMIT (2u * 1024u * 1024u)

static size_t linux_speed_lab_receive_v12(void *data, size_t size, size_t count, void *opaque) {
    LinuxSpeedLabV12 *s = opaque;
    if (g_atomic_int_get(&s->cancelled) || s->response.len > LINUX_SPEED_LAB_RESPONSE_LIMIT ||
        (size != 0 && count > (LINUX_SPEED_LAB_RESPONSE_LIMIT - s->response.len) / size)) return 0;
    return write_cb(data, size, count, &s->response);
}

static int linux_speed_lab_progress_v12(void *opaque, curl_off_t total_down, curl_off_t down,
                                        curl_off_t total_up, curl_off_t up) {
    (void)total_down; (void)down; (void)total_up; (void)up;
    LinuxSpeedLabV12 *s = opaque;
    return g_atomic_int_get(&s->cancelled) ? 1 : 0;
}

static gpointer linux_speed_lab_worker_v12(gpointer opaque) {
    LinuxSpeedLabV12 *s = opaque;
    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        s->request_error = g_strdup("libcurl initialization failed");
        g_atomic_int_set(&s->complete, 1);
        return NULL;
    }
    const char *path = s->loading_options ? "/api/speed-lab/options" : "/api/speed-lab/run";
    char *url = g_strdup_printf("%s%s", ROUTER_VPN_BASE_URL, path);
    struct curl_slist *headers = curl_slist_append(NULL, "Accept: application/json");
    if (!s->loading_options) headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 3000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, s->request_timeout);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, linux_speed_lab_receive_v12);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, s);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, linux_speed_lab_progress_v12);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, s);
    if (!s->loading_options) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, s->request_body);
    CURLcode code = g_atomic_int_get(&s->cancelled) ? CURLE_ABORTED_BY_CALLBACK : curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    s->request_ok = code == CURLE_OK && status >= 200 && status < 300;
    if (!s->request_ok) {
        if (code != CURLE_OK) s->request_error = g_strdup(curl_easy_strerror(code));
        else if (s->response.data != NULL && g_utf8_validate(s->response.data, -1, NULL))
            s->request_error = g_utf8_make_valid(s->response.data, MIN(s->response.len, (size_t)4096));
        else s->request_error = g_strdup("Local controller request failed");
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    g_free(url);
    g_atomic_int_set(&s->complete, 1);
    return NULL;
}

static void linux_speed_lab_release_request_v12(LinuxSpeedLabV12 *s) {
    if (s->owns_slot) {
        LinuxAsyncActionsV16 *owner = linux_async_state_v16(s->app);
        s->owns_slot = FALSE;
        if (owner != NULL && owner->auxiliary_jobs != 0) {
            owner->auxiliary_jobs--;
            if (!owner->closed && owner->changed != NULL) owner->changed(s->app);
        }
    }
    g_clear_pointer(&s->request_body, g_free);
    g_clear_pointer(&s->request_error, g_free);
    free(s->response.data);
    s->response = (Buffer){0};
}

static void linux_speed_lab_destroy_v12(GtkWidget *widget, gpointer data) {
    (void)widget;
    LinuxSpeedLabV12 *s = data;
    s->closed = TRUE;
    g_atomic_int_set(&s->cancelled, 1);
    if (s->poll_source != 0) { g_source_remove(s->poll_source); s->poll_source = 0; }
    if (s->worker != NULL) { g_thread_join(s->worker); s->worker = NULL; }
    linux_speed_lab_release_request_v12(s);
}

static const char *linux_speed_lab_active_id_v12(GtkWidget *combo) {
    const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(combo));
    return id != NULL ? id : "";
}

static GtkWidget *linux_speed_lab_combo_v12(const char *const ids[], const char *const labels[], size_t count) {
    GtkWidget *combo = gtk_combo_box_text_new();
    for (size_t i = 0; i < count; i++) gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), ids[i], labels[i]);
    if (count > 0) gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);
    return combo;
}

static GtkWidget *linux_speed_lab_metric_v12(const char *heading, GtkWidget **big_out, GtkWidget **detail_out) {
    GtkWidget *frame = gtk_frame_new(NULL);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_container_set_border_width(GTK_CONTAINER(box), 12);
    GtkWidget *title = gtk_label_new(heading); gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    GtkWidget *big = gtk_label_new("--"); gtk_label_set_xalign(GTK_LABEL(big), 0.0f);
    PangoAttrList *attrs = pango_attr_list_new(); pango_attr_list_insert(attrs, pango_attr_weight_new(PANGO_WEIGHT_BOLD)); pango_attr_list_insert(attrs, pango_attr_scale_new(1.75)); gtk_label_set_attributes(GTK_LABEL(big), attrs); pango_attr_list_unref(attrs);
    GtkWidget *detail = gtk_label_new("waiting for test"); gtk_label_set_xalign(GTK_LABEL(detail), 0.0f); gtk_label_set_line_wrap(GTK_LABEL(detail), TRUE);
    gtk_box_pack_start(GTK_BOX(box), title, FALSE, FALSE, 0); gtk_box_pack_start(GTK_BOX(box), big, FALSE, FALSE, 0); gtk_box_pack_start(GTK_BOX(box), detail, FALSE, FALSE, 0); gtk_container_add(GTK_CONTAINER(frame), box);
    *big_out = big; *detail_out = detail; return frame;
}

static void linux_speed_lab_append_nodes_v12(GtkWidget *combo, JsonArray *nodes, const char *kind_filter) {
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(combo));
    for (guint i = 0; nodes != NULL && i < json_array_get_length(nodes); i++) {
        JsonObject *n = json_array_get_object_element(nodes, i); if (n == NULL) continue;
        const char *id = obj_string(n, "id"); if (id[0] == '\0') continue;
        const char *kind = obj_string(n, "node_kind"); if (kind[0] == '\0') kind = "router-vpn";
        if (kind_filter != NULL && kind_filter[0] != '\0' && g_ascii_strcasecmp(kind, kind_filter) != 0) continue;
        const char *name = obj_string(n, "name"); if (name[0] == '\0') name = id;
        double ms = json_object_has_member(n, "latency_trimmed_mean_ms") ? json_object_get_double_member(n, "latency_trimmed_mean_ms") : 0.0;
        char *label = ms > 0.0 ? g_strdup_printf("%s • %.1f ms", name, ms) : g_strdup(name);
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), id, label); g_free(label);
    }
    if (gtk_tree_model_iter_n_children(gtk_combo_box_get_model(GTK_COMBO_BOX(combo)), NULL) > 0) gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);
}

static gboolean linux_speed_lab_apply_options_v12(LinuxSpeedLabV12 *s) {
    JsonNode *root = parse_json(s->response.data);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) {
        if (root != NULL) json_node_free(root);
        gtk_label_set_text(GTK_LABEL(s->status), "Speed Lab options returned invalid JSON");
        return FALSE;
    }
    JsonObject *obj = json_node_get_object(root); JsonArray *nodes = json_object_has_member(obj, "nodes") ? json_object_get_array_member(obj, "nodes") : NULL;
    linux_speed_lab_append_nodes_v12(s->node, nodes, NULL); linux_speed_lab_append_nodes_v12(s->entry, nodes, NULL); linux_speed_lab_append_nodes_v12(s->exit, nodes, "router-vpn");
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(s->mode)); JsonArray *modes = json_object_has_member(obj, "logical_modes") ? json_object_get_array_member(obj, "logical_modes") : NULL;
    for (guint i=0; modes != NULL && i<json_array_get_length(modes); i++) { JsonObject*m=json_array_get_object_element(modes,i); if(m==NULL)continue; const char*id=obj_string(m,"id"); if(id[0]=='\0')continue; const char*name=obj_string(m,"name"); gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(s->mode),id,name[0]?name:id); }
    if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(s->mode), "smart-auto")) gtk_combo_box_set_active(GTK_COMBO_BOX(s->mode), 0);
    json_node_free(root); return TRUE;
}

static void linux_speed_lab_refresh_controls_v12(GtkComboBox *ignored, gpointer data) {
    (void)ignored; LinuxSpeedLabV12 *s=data; if(s==NULL||s->closed)return;
    if (s->worker != NULL || !s->options_ready) {
        GtkWidget *all[] = {s->scope,s->topology,s->node,s->entry,s->exit,s->mode,s->base,s->exit_mode,s->layers,s->daita,s->jumbo,s->encrypted,s->obfuscated,s->duration_mode,s->min_time,s->max_time};
        for (guint i=0; i<G_N_ELEMENTS(all); i++) gtk_widget_set_sensitive(all[i], FALSE);
        gtk_widget_set_sensitive(s->run, s->worker != NULL && !s->loading_options && !g_atomic_int_get(&s->cancelled));
        return;
    }
    gtk_widget_set_sensitive(s->scope, TRUE);
    gtk_widget_set_sensitive(s->duration_mode, TRUE);
    gtk_widget_set_sensitive(s->run, TRUE);
    gboolean temporary = strcmp(linux_speed_lab_active_id_v12(s->scope), "temporary") == 0;
    GtkWidget *controls[] = {s->topology,s->node,s->entry,s->exit,s->mode,s->base,s->exit_mode,s->layers,s->daita,s->jumbo,s->encrypted,s->obfuscated};
    for(size_t i=0;i<G_N_ELEMENTS(controls);i++) gtk_widget_set_sensitive(controls[i], temporary);
    const char *top=linux_speed_lab_active_id_v12(s->topology); const char *mode=linux_speed_lab_active_id_v12(s->mode);
    gtk_widget_set_sensitive(s->entry, temporary && (strcmp(top,"multihop")==0 || strcmp(top,"external")==0)); gtk_widget_set_sensitive(s->exit, temporary && strcmp(top,"multihop")==0); gtk_widget_set_sensitive(s->exit_mode, temporary && strcmp(top,"multihop")==0); gtk_widget_set_sensitive(s->layers, temporary && strcmp(mode,"custom")==0);
    gboolean custom_time=strcmp(linux_speed_lab_active_id_v12(s->duration_mode),"custom")==0; gtk_widget_set_sensitive(s->min_time,custom_time); gtk_widget_set_sensitive(s->max_time,custom_time);
}

static void linux_speed_lab_time_v12(GtkRange *ignored, gpointer data) {
    (void)ignored; LinuxSpeedLabV12 *s=data; if(s==NULL)return; double min=gtk_range_get_value(GTK_RANGE(s->min_time)),max=gtk_range_get_value(GTK_RANGE(s->max_time));
    if(min>max){max=min;gtk_range_set_value(GTK_RANGE(s->max_time),max);} if(max<min){min=max;gtk_range_set_value(GTK_RANGE(s->min_time),min);}
    char *a=g_strdup_printf("Min %.0f s",min),*b=g_strdup_printf("Max %.0f s",max);gtk_label_set_text(GTK_LABEL(s->min_label),a);gtk_label_set_text(GTK_LABEL(s->max_label),b);g_free(a);g_free(b);
}

static char *linux_speed_lab_request_body_v12(LinuxSpeedLabV12 *s) {
    JsonBuilder *b=json_builder_new(); json_builder_begin_object(b);
#define SL_STR(name,value) do{json_builder_set_member_name(b,(name));json_builder_add_string_value(b,(value));}while(0)
#define SL_BOOL(name,value) do{json_builder_set_member_name(b,(name));json_builder_add_boolean_value(b,(value));}while(0)
    const char *scope=linux_speed_lab_active_id_v12(s->scope),*duration=linux_speed_lab_active_id_v12(s->duration_mode); SL_STR("scope",scope);SL_STR("duration_mode",duration);
    if(strcmp(duration,"custom")==0){json_builder_set_member_name(b,"min_seconds");json_builder_add_double_value(b,gtk_range_get_value(GTK_RANGE(s->min_time)));json_builder_set_member_name(b,"max_seconds");json_builder_add_double_value(b,gtk_range_get_value(GTK_RANGE(s->max_time)));}
    if(strcmp(scope,"temporary")==0){
        SL_STR("topology",linux_speed_lab_active_id_v12(s->topology));SL_STR("node_id",linux_speed_lab_active_id_v12(s->node));SL_STR("entry_id",linux_speed_lab_active_id_v12(s->entry));SL_STR("exit_id",linux_speed_lab_active_id_v12(s->exit));SL_STR("mode",linux_speed_lab_active_id_v12(s->mode));SL_STR("base",linux_speed_lab_active_id_v12(s->base));SL_STR("exit_mode",linux_speed_lab_active_id_v12(s->exit_mode));
        if(strcmp(linux_speed_lab_active_id_v12(s->mode),"custom")==0){const char*raw=gtk_entry_get_text(GTK_ENTRY(s->layers));json_builder_set_member_name(b,"custom_layers");json_builder_begin_array(b);char**parts=g_strsplit(raw,",",-1);for(int i=0;parts[i]!=NULL;i++){char*x=g_strstrip(parts[i]);if(x[0])json_builder_add_string_value(b,x);}g_strfreev(parts);json_builder_end_array(b);}
        SL_BOOL("daita",gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(s->daita)));SL_BOOL("jumbo",gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(s->jumbo)));SL_BOOL("require_encrypted",gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(s->encrypted)));SL_BOOL("require_obfuscation",gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(s->obfuscated)));
    }
    json_builder_end_object(b);JsonGenerator*g=json_generator_new();JsonNode*root=json_builder_get_root(b);json_generator_set_root(g,root);char*body=json_generator_to_data(g,NULL);json_node_free(root);g_object_unref(g);g_object_unref(b);
#undef SL_STR
#undef SL_BOOL
    return body;
}

static double linux_speed_lab_number_v12(JsonObject *obj,const char *key){return obj!=NULL&&json_object_has_member(obj,key)?json_object_get_double_member(obj,key):0.0;}

static char *linux_speed_lab_hops_v12(JsonObject *obj, guint *count_out) {
    if (count_out != NULL) *count_out = 0;
    if (obj == NULL || !json_object_has_member(obj, "hops")) return NULL;
    JsonArray *hops = json_object_get_array_member(obj, "hops");
    if (hops == NULL || json_array_get_length(hops) == 0) return NULL;
    GString *text = g_string_new("PER-HOP — SAME PROVED GRAPH\n");
    guint count = 0;
    for (guint i = 0; i < json_array_get_length(hops); i++) {
        JsonObject *hop = json_array_get_object_element(hops, i); if (hop == NULL) continue;
        const char *role = obj_string(hop, "role"), *name = obj_string(hop, "name"), *id = obj_string(hop, "router_id");
        if (name[0] == '\0') name = id;
        char *latency = NULL, *speed = NULL;
        if (json_object_has_member(hop, "latency")) {
            JsonObject *stats = json_object_get_object_member(hop, "latency"); latency = g_strdup_printf("%.1f ms", linux_speed_lab_number_v12(stats, "median_ms"));
        } else if (json_object_has_member(hop, "latency_error")) latency = g_strdup_printf("RTT unavailable: %s", obj_string(hop, "latency_error"));
        else latency = g_strdup("RTT unavailable");
        if (json_object_has_member(hop, "speed")) {
            JsonObject *stats = json_object_get_object_member(hop, "speed"); speed = g_strdup_printf("↓ %.1f / ↑ %.1f Mbps", linux_speed_lab_number_v12(stats, "download_mbps"), linux_speed_lab_number_v12(stats, "upload_mbps"));
        } else if (json_object_has_member(hop, "speed_error")) speed = g_strdup_printf("speed unavailable: %s", obj_string(hop, "speed_error"));
        else speed = g_strdup("speed unavailable");
        g_string_append_printf(text, "%s • %s • %s • %s\n", role[0] ? role : "hop", name[0] ? name : "node", latency, speed); g_free(latency); g_free(speed); count++;
    }
    if (count == 0) { g_string_free(text, TRUE); return NULL; }
    if (count_out != NULL) *count_out = count;
    return g_string_free(text, FALSE);
}

static gboolean linux_speed_lab_valid_summary_v12(JsonObject *object) {
    JsonNode *ok = json_object_get_member(object, "ok");
    if (ok == NULL || !JSON_NODE_HOLDS_VALUE(ok) || json_node_get_value_type(ok) != G_TYPE_BOOLEAN || !json_node_get_boolean(ok)) return FALSE;
    JsonNode *node = json_object_get_member(object, "summary");
    if (node == NULL || !JSON_NODE_HOLDS_OBJECT(node)) return FALSE;
    JsonObject *summary = json_node_get_object(node);
    static const char *const keys[] = {"idle_ms", "download_mbps", "upload_mbps", "download_loaded_ms", "upload_loaded_ms", "download_bufferbloat_ms", "upload_bufferbloat_ms"};
    for (guint i = 0; i < G_N_ELEMENTS(keys); i++) {
        JsonNode *value = json_object_get_member(summary, keys[i]);
        if (value == NULL || !JSON_NODE_HOLDS_VALUE(value)) return FALSE;
        GType type = json_node_get_value_type(value);
        if (type != G_TYPE_INT64 && type != G_TYPE_DOUBLE) return FALSE;
        double number = json_node_get_double(value);
        if (!isfinite(number) || number < 0.0) return FALSE;
    }
    return TRUE;
}

static void linux_speed_lab_render_v12(LinuxSpeedLabV12 *s, const char *text) {
    JsonNode*root=parse_json(text);if(root==NULL||!JSON_NODE_HOLDS_OBJECT(root)||!linux_speed_lab_valid_summary_v12(json_node_get_object(root))){gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->detail)),"Speed Lab returned invalid JSON",-1);gtk_label_set_text(GTK_LABEL(s->status),"Speed Lab response invalid");if(root!=NULL)json_node_free(root);return;}
    JsonObject*obj=json_node_get_object(root),*summary=json_object_has_member(obj,"summary")?json_object_get_object_member(obj,"summary"):NULL,*measurement=json_object_has_member(obj,"measurement")?json_object_get_object_member(obj,"measurement"):NULL;
    JsonObject*idle_stats=measurement&&json_object_has_member(measurement,"idle_latency")?json_object_get_object_member(measurement,"idle_latency"):NULL,*down=measurement&&json_object_has_member(measurement,"download")?json_object_get_object_member(measurement,"download"):NULL,*up=measurement&&json_object_has_member(measurement,"upload")?json_object_get_object_member(measurement,"upload"):NULL;
    JsonObject*down_loaded=down&&json_object_has_member(down,"loaded_latency")?json_object_get_object_member(down,"loaded_latency"):NULL,*up_loaded=up&&json_object_has_member(up,"loaded_latency")?json_object_get_object_member(up,"loaded_latency"):NULL;
    char*x=g_strdup_printf("%.1f ms",linux_speed_lab_number_v12(summary,"idle_ms"));gtk_label_set_text(GTK_LABEL(s->idle),x);g_free(x);x=g_strdup_printf("%.1f Mbps",linux_speed_lab_number_v12(summary,"download_mbps"));gtk_label_set_text(GTK_LABEL(s->download),x);g_free(x);x=g_strdup_printf("%.1f Mbps",linux_speed_lab_number_v12(summary,"upload_mbps"));gtk_label_set_text(GTK_LABEL(s->upload),x);g_free(x);
    x=g_strdup_printf("p90 %.1f • max %.1f • jitter %.1f ms",linux_speed_lab_number_v12(idle_stats,"p90_ms"),linux_speed_lab_number_v12(idle_stats,"max_ms"),linux_speed_lab_number_v12(idle_stats,"jitter_ms"));gtk_label_set_text(GTK_LABEL(s->idle_detail),x);g_free(x);
    x=g_strdup_printf("loaded %.1f ms • +%.1f bloat • p90 %.1f",linux_speed_lab_number_v12(summary,"download_loaded_ms"),linux_speed_lab_number_v12(summary,"download_bufferbloat_ms"),linux_speed_lab_number_v12(down_loaded,"p90_ms"));gtk_label_set_text(GTK_LABEL(s->download_detail),x);g_free(x);
    x=g_strdup_printf("loaded %.1f ms • +%.1f bloat • p90 %.1f",linux_speed_lab_number_v12(summary,"upload_loaded_ms"),linux_speed_lab_number_v12(summary,"upload_bufferbloat_ms"),linux_speed_lab_number_v12(up_loaded,"p90_ms"));gtk_label_set_text(GTK_LABEL(s->upload_detail),x);g_free(x);
    guint hop_count=0;char*hop_text=linux_speed_lab_hops_v12(obj,&hop_count);if(hop_text!=NULL){char*combined=g_strdup_printf("%s\nFULL RESULT\n%s",hop_text,text?text:"{}");gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->detail)),combined,-1);g_free(combined);g_free(hop_text);}else gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->detail)),text?text:"{}",-1);
    if(hop_count>0){x=g_strdup_printf("Finished • real HTTPS throughput + loaded latency • %u hop measurements",hop_count);gtk_label_set_text(GTK_LABEL(s->status),x);g_free(x);}else gtk_label_set_text(GTK_LABEL(s->status),"Finished • real HTTPS throughput + loaded latency");json_node_free(root);
}

static gboolean linux_speed_lab_complete_v12(gpointer data) {
    LinuxSpeedLabV12 *s = data;
    if (!g_atomic_int_get(&s->complete)) return G_SOURCE_CONTINUE;
    g_thread_join(s->worker);
    s->worker = NULL;
    s->poll_source = 0;
    if (s->closed) return G_SOURCE_REMOVE;
    if (g_atomic_int_get(&s->cancelled)) {
        gtk_label_set_text(GTK_LABEL(s->status), "Cancelled. Controller cleanup must finish before another test can start.");
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->detail)),
            "The test request was cancelled. Temporary-path restoration is owned by the controller; cancellation does not claim restoration has already succeeded.", -1);
    } else if (!s->request_ok) {
        gtk_label_set_text(GTK_LABEL(s->status), "Speed Lab failed closed; see details.");
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->detail)), s->request_error ? s->request_error : "Local request failed", -1);
    } else if (s->loading_options) {
        s->options_ready = linux_speed_lab_apply_options_v12(s);
        if (s->options_ready) gtk_label_set_text(GTK_LABEL(s->status), "Ready • current configuration selected; no saved preferences changed");
    } else linux_speed_lab_render_v12(s, s->response.data);
    linux_speed_lab_release_request_v12(s);
    gtk_button_set_label(GTK_BUTTON(s->run), "Run Speed Lab");
    linux_speed_lab_refresh_controls_v12(NULL, s);
    return G_SOURCE_REMOVE;
}

static void linux_speed_lab_start_v12(LinuxSpeedLabV12 *s, gboolean options) {
    if (s->closed || s->worker != NULL) return;
    if (linux_async_busy_v16(s->app)) {
        gtk_label_set_text(GTK_LABEL(s->status), "Another operation is pending; no Speed Lab request was started.");
        return;
    }
    LinuxAsyncActionsV16 *owner = linux_async_ensure_v16(s->app);
    owner->auxiliary_jobs++;
    s->owns_slot = TRUE;
    if (owner->changed != NULL) owner->changed(s->app);
    s->loading_options = options;
    s->request_ok = FALSE;
    s->request_timeout = options ? 10000L : 110000L;
    if (!options) {
        s->request_body = linux_speed_lab_request_body_v12(s);
        if (strcmp(linux_speed_lab_active_id_v12(s->duration_mode), "custom") == 0)
            s->request_timeout = MAX(90000L, (long)(gtk_range_get_value(GTK_RANGE(s->max_time))*2000.0 + 80000.0));
        gtk_label_set_text(GTK_LABEL(s->status), "Proving path and testing throughput/loaded latency… Cancel or Close stops this request.");
        GtkWidget *metrics[] = {s->idle,s->download,s->upload,s->idle_detail,s->download_detail,s->upload_detail};
        for (guint i=0; i<G_N_ELEMENTS(metrics); i++) gtk_label_set_text(GTK_LABEL(metrics[i]), "--");
    } else gtk_label_set_text(GTK_LABEL(s->status), "Loading test options…");
    g_atomic_int_set(&s->cancelled, 0);
    g_atomic_int_set(&s->complete, 0);
    GError *error = NULL;
    s->worker = g_thread_try_new("router-vpn-speed-lab", linux_speed_lab_worker_v12, s, &error);
    if (s->worker == NULL) {
        gtk_label_set_text(GTK_LABEL(s->status), error ? error->message : "Cannot start Speed Lab worker");
        g_clear_error(&error);
        linux_speed_lab_release_request_v12(s);
    } else {
        gtk_button_set_label(GTK_BUTTON(s->run), options ? "Loading…" : "Cancel test");
        s->poll_source = g_timeout_add(100, linux_speed_lab_complete_v12, s);
    }
    linux_speed_lab_refresh_controls_v12(NULL, s);
}

static void linux_speed_lab_run_v12(GtkButton *button, gpointer data) {
    (void)button;
    LinuxSpeedLabV12 *s = data;
    if (s == NULL || s->closed) return;
    if (s->worker != NULL) {
        g_atomic_int_set(&s->cancelled, 1);
        gtk_widget_set_sensitive(s->run, FALSE);
        gtk_label_set_text(GTK_LABEL(s->status), "Cancelling test request…");
        return;
    }
    if (s->options_ready) linux_speed_lab_start_v12(s, FALSE);
}

static GtkWidget *linux_speed_lab_grid_label_v12(const char*text){GtkWidget*w=gtk_label_new(text);gtk_label_set_xalign(GTK_LABEL(w),0.0f);return w;}

static void linux_speed_lab_open_v12(GtkButton *button,gpointer data){
    (void)button;App*app=data;if(app==NULL)return;LinuxSpeedLabV12*s=g_new0(LinuxSpeedLabV12,1);s->app=app;s->dialog=gtk_dialog_new_with_buttons("Router VPN Speed Lab",GTK_WINDOW(app->window),GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT,"Close",GTK_RESPONSE_CLOSE,NULL);gtk_window_set_default_size(GTK_WINDOW(s->dialog),900,690);
    GtkWidget*area=gtk_dialog_get_content_area(GTK_DIALOG(s->dialog)),*root=gtk_box_new(GTK_ORIENTATION_VERTICAL,10);gtk_container_set_border_width(GTK_CONTAINER(root),16);GtkWidget*title=gtk_label_new(NULL);gtk_label_set_markup(GTK_LABEL(title),"<span size='xx-large' weight='bold'>Router VPN Speed Lab</span>\nReal HTTPS Mbps with idle, download-loaded and upload-loaded latency. Current path is default; Temporary builds and restores a test-only graph.");gtk_label_set_line_wrap(GTK_LABEL(title),TRUE);gtk_label_set_xalign(GTK_LABEL(title),0.0f);gtk_box_pack_start(GTK_BOX(root),title,FALSE,FALSE,0);
    GtkWidget*cards=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8);gtk_box_pack_start(GTK_BOX(cards),linux_speed_lab_metric_v12("IDLE LATENCY",&s->idle,&s->idle_detail),TRUE,TRUE,0);gtk_box_pack_start(GTK_BOX(cards),linux_speed_lab_metric_v12("DOWNLOAD",&s->download,&s->download_detail),TRUE,TRUE,0);gtk_box_pack_start(GTK_BOX(cards),linux_speed_lab_metric_v12("UPLOAD",&s->upload,&s->upload_detail),TRUE,TRUE,0);gtk_box_pack_start(GTK_BOX(root),cards,FALSE,FALSE,0);
    const char*scope_ids[]={"current","temporary"},*scope_labels[]={"Current path","Temporary config"};s->scope=linux_speed_lab_combo_v12(scope_ids,scope_labels,2);const char*top_ids[]={"system-direct","router","multihop","external"},*top_labels[]={"System direct","Router VPN node","Multihop","External exit / hop"};s->topology=linux_speed_lab_combo_v12(top_ids,top_labels,4);gtk_combo_box_set_active(GTK_COMBO_BOX(s->topology),1);s->node=gtk_combo_box_text_new();s->entry=gtk_combo_box_text_new();s->exit=gtk_combo_box_text_new();s->mode=gtk_combo_box_text_new();const char*base_ids[]={"auto","wg","awg"},*base_labels[]={"Auto","WireGuard","AmneziaWG"};s->base=linux_speed_lab_combo_v12(base_ids,base_labels,3);const char*exit_ids[]={"shadowsocks","hysteria2"},*exit_labels[]={"Shadowsocks","Hysteria2"};s->exit_mode=linux_speed_lab_combo_v12(exit_ids,exit_labels,2);s->layers=gtk_entry_new();gtk_entry_set_placeholder_text(GTK_ENTRY(s->layers),"CUSTOM layers, comma-separated");
    GtkWidget*grid=gtk_grid_new();gtk_grid_set_row_spacing(GTK_GRID(grid),6);gtk_grid_set_column_spacing(GTK_GRID(grid),8);GtkWidget*labels[]={linux_speed_lab_grid_label_v12("Test"),linux_speed_lab_grid_label_v12("Topology"),linux_speed_lab_grid_label_v12("Mode"),linux_speed_lab_grid_label_v12("Node / exit"),linux_speed_lab_grid_label_v12("Entry"),linux_speed_lab_grid_label_v12("Exit"),linux_speed_lab_grid_label_v12("Base"),linux_speed_lab_grid_label_v12("Exit transport"),linux_speed_lab_grid_label_v12("CUSTOM layers")};GtkWidget*widgets[]={s->scope,s->topology,s->mode,s->node,s->entry,s->exit,s->base,s->exit_mode,s->layers};for(int i=0;i<9;i++){int row=i/3,col=(i%3)*2;gtk_grid_attach(GTK_GRID(grid),labels[i],col,row,1,1);gtk_grid_attach(GTK_GRID(grid),widgets[i],col+1,row,1,1);gtk_widget_set_hexpand(widgets[i],TRUE);}gtk_box_pack_start(GTK_BOX(root),grid,FALSE,FALSE,0);
    const char*duration_ids[]={"auto","custom"},*duration_labels[]={"Auto timing","Custom timing"};s->duration_mode=linux_speed_lab_combo_v12(duration_ids,duration_labels,2);s->min_label=gtk_label_new("Min 4 s");s->max_label=gtk_label_new("Max 12 s");s->min_time=gtk_scale_new_with_range(GTK_ORIENTATION_HORIZONTAL,1,60,1);s->max_time=gtk_scale_new_with_range(GTK_ORIENTATION_HORIZONTAL,1,60,1);gtk_range_set_value(GTK_RANGE(s->min_time),4);gtk_range_set_value(GTK_RANGE(s->max_time),12);GtkWidget*time_row=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8);gtk_box_pack_start(GTK_BOX(time_row),s->duration_mode,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(time_row),s->min_label,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(time_row),s->min_time,TRUE,TRUE,0);gtk_box_pack_start(GTK_BOX(time_row),s->max_label,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(time_row),s->max_time,TRUE,TRUE,0);gtk_box_pack_start(GTK_BOX(root),time_row,FALSE,FALSE,0);
    GtkWidget*flags=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,10);s->daita=gtk_check_button_new_with_label("DAITA-like");s->jumbo=gtk_check_button_new_with_label("Jumbo");s->encrypted=gtk_check_button_new_with_label("Require encrypted AUTO");s->obfuscated=gtk_check_button_new_with_label("Require obfuscation AUTO");gtk_box_pack_start(GTK_BOX(flags),s->daita,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(flags),s->jumbo,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(flags),s->encrypted,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(flags),s->obfuscated,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(root),flags,FALSE,FALSE,0);
    GtkWidget*scroll=gtk_scrolled_window_new(NULL,NULL);gtk_widget_set_vexpand(scroll,TRUE);s->detail=gtk_text_view_new();gtk_text_view_set_editable(GTK_TEXT_VIEW(s->detail),FALSE);gtk_text_view_set_monospace(GTK_TEXT_VIEW(s->detail),TRUE);gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->detail)),"Ready. Temporary configurations require Router VPN to be disconnected.",-1);gtk_container_add(GTK_CONTAINER(scroll),s->detail);gtk_box_pack_start(GTK_BOX(root),scroll,TRUE,TRUE,0);
    GtkWidget*actions=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8);s->status=gtk_label_new("Cloudflare Speed Test edge • no Mbps derived from RTT");gtk_label_set_xalign(GTK_LABEL(s->status),0.0f);s->run=gtk_button_new_with_label("Run Speed Lab");gtk_box_pack_start(GTK_BOX(actions),s->status,TRUE,TRUE,0);gtk_box_pack_end(GTK_BOX(actions),s->run,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(root),actions,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(area),root,TRUE,TRUE,0);
    g_signal_connect(s->scope,"changed",G_CALLBACK(linux_speed_lab_refresh_controls_v12),s);g_signal_connect(s->topology,"changed",G_CALLBACK(linux_speed_lab_refresh_controls_v12),s);g_signal_connect(s->mode,"changed",G_CALLBACK(linux_speed_lab_refresh_controls_v12),s);g_signal_connect(s->duration_mode,"changed",G_CALLBACK(linux_speed_lab_refresh_controls_v12),s);g_signal_connect(s->min_time,"value-changed",G_CALLBACK(linux_speed_lab_time_v12),s);g_signal_connect(s->max_time,"value-changed",G_CALLBACK(linux_speed_lab_time_v12),s);g_signal_connect(s->run,"clicked",G_CALLBACK(linux_speed_lab_run_v12),s);
    g_object_set_data(G_OBJECT(s->dialog), "linux-speed-lab-v12", s);
    g_signal_connect(s->dialog, "destroy", G_CALLBACK(linux_speed_lab_destroy_v12), s);
    gtk_widget_show_all(s->dialog);
    linux_speed_lab_start_v12(s, TRUE);
    linux_speed_lab_time_v12(NULL,s);
    gtk_dialog_run(GTK_DIALOG(s->dialog));
    if (!s->closed) gtk_widget_destroy(s->dialog);
    g_free(s);
}

static void linux_install_speed_lab_v12(App *app){
    if (app == NULL || app->window == NULL) return;
    LinuxUnifiedV8 *base = g_object_get_data(G_OBJECT(app->window), "linux-unified-v8");
    if (base == NULL) return;
    GtkWidget *settings = linux_telemetry_find_button_v9(base->stack, "Open settings");
    if (settings == NULL || !GTK_IS_BOX(gtk_widget_get_parent(settings))) return;
    GtkWidget *button = linux_telemetry_button_v9("Speed Lab", G_CALLBACK(linux_speed_lab_open_v12), app);
    gtk_widget_set_tooltip_text(button, "Ookla-style Router VPN test: real HTTPS throughput plus idle/download-loaded/upload-loaded latency, current or temporary direct/multihop/external paths, Auto or custom min/max time.");
    gtk_box_pack_start(GTK_BOX(gtk_widget_get_parent(settings)), button, FALSE, FALSE, 0);
    gtk_widget_show_all(app->window);
}

/* Linux Speed Lab v12: /api/speed-lab/options + /api/speed-lab/run; current path or temporary System direct, Router VPN, Multihop, External exit/hop; SMART/AUTO/CUSTOM/logical modes; WireGuard/AmneziaWG; real download/upload Mbps; idle/download-loaded/upload-loaded ms, exact per-hop RTT/Mbps on the same proved multihop graph, p90/max/jitter/bufferbloat; Auto timing or 1–60 second custom min/max sliders. */

#include "routervpn-speed-lab-self-test-v13.inc"
