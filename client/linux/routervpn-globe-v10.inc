typedef struct {
    App *app;
    GPtrArray *route_ids;
    GtkWidget *location_button;
    GCancellable *location_request;
    gint64 location_expires;
    double device_lat, device_lon;
    GHashTable *external_ids;
    double path_ms;
    gint64 path_expires;
    double phase;
    gboolean connected;
    guint animation_source;
    guint refresh_source;
} LinuxGlobeV10;

static void linux_globe_xy_v10(double lat,double lon,double width,double height,double*x,double*y){
    double cx=width/2.0,cy=height/2.0,rx=fmax(40.0,width/2.0-18.0),ry=fmax(40.0,height/2.0-16.0),lat_rad=lat*G_PI/180.0;
    *x=cx+(lon/180.0)*rx*0.92*cos(lat_rad*0.55);*y=cy-(lat/90.0)*ry*0.86;
}

static void linux_globe_free_v10(gpointer data){
    LinuxGlobeV10*g=data;if(g==NULL)return;if(g->animation_source)g_source_remove(g->animation_source);if(g->refresh_source)g_source_remove(g->refresh_source);if(g->location_button)g_object_set_data(G_OBJECT(g->location_button),"routervpn-location-globe",NULL);g_ptr_array_unref(g->route_ids);if(g->location_request){g_cancellable_cancel(g->location_request);g_object_unref(g->location_request);}if(g->external_ids!=NULL)g_hash_table_unref(g->external_ids);g_free(g);
}

static LinuxGlobeV10*linux_globe_state_v10(App*app){return app!=NULL&&app->window!=NULL?g_object_get_data(G_OBJECT(app->window),"linux-globe-v10"):NULL;}

static JsonArray *linux_globe_active_ids_v10(JsonObject *status) {
    const char *token = obj_string(status, "active_route_id");
    JsonArray *active = linux_ordered_array_v1(status, "active_node_ids");
    guint count = active ? json_array_get_length(active) : 0;
    if (strlen(token) != 64 || strspn(token, "0123456789abcdef") != 64 || count < 2 || count > ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH) return NULL;
    for (guint i = 0; i < count; i++) {
        JsonNode *member = json_array_get_element(active, i);
        if (!JSON_NODE_HOLDS_VALUE(member) || json_node_get_value_type(member) != G_TYPE_STRING) return NULL;
        const char *id = json_node_get_string(member);
        if (!id || !id[0] || (!i && strcmp(id, obj_string(status, "actual_entry_id"))) ||
            (i + 1 == count && strcmp(id, obj_string(status, "actual_exit_id")))) return NULL;
        for (guint j = 0; j < i; j++) if (!strcmp(id, json_array_get_string_element(active, j))) return NULL;
    }
    return active;
}

static void linux_globe_load_route(LinuxGlobeV10 *g, JsonObject *status, JsonObject *receipt) {
    JsonArray *nodes = linux_ordered_array_v1(status, "nodes");
    for (guint i = 0; nodes && i < json_array_get_length(nodes); i++) {
        JsonObject *node = json_array_get_object_element(nodes, i);
        if (g_strcmp0(obj_string(node, "node_kind"), "external") == 0)
            g_hash_table_add(g->external_ids, g_strdup(obj_string(node, "id")));
    }
    if (!linux_ordered_flag_v1(status, "connected")) {
        LinuxUnifiedV8 *base = g_object_get_data(G_OBJECT(g->app->window), "linux-unified-v8");
        if (!base || !gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(base->multihop))) return;
        LinuxOrderedStateV1 *state = linux_ordered_state_v1(base);
        if (!state || state->invalid) return;
        if (state->selection) {
            LinuxOrderedSelectionV1 *selection = state->selection;
            if (!linux_ordered_owns_v1(state, state->generation, selection->control)) return;
            for (guint i = 0; i < json_array_get_length(selection->nodes); i++)
                g_ptr_array_add(g->route_ids, g_strdup(obj_string(json_array_get_object_element(selection->nodes, i), "id")));
        } else {
            g_autofree char *entry = NULL, *exit = NULL;
            gboolean enabled = FALSE;
            linux_profile_selection_v11(&enabled, &entry, &exit, NULL, NULL);
            if (enabled && entry && exit && entry[0] && exit[0] && strcmp(entry, exit)) {
                g_ptr_array_add(g->route_ids, g_strdup(entry));
                g_ptr_array_add(g->route_ids, g_strdup(exit));
            }
        }
        return;
    }

    JsonArray *active = linux_globe_active_ids_v10(status);
    if (!active) return;
    const char *token = obj_string(status, "active_route_id");
    guint count = json_array_get_length(active);
    for (guint i = 0; i < count; i++) g_ptr_array_add(g->route_ids, g_strdup(json_array_get_string_element(active, i)));
    g->connected = TRUE;
    // Telemetry owns /api/multihop/live-latency. The globe adopts its
    // measured response only when it names this exact running route.
    JsonObject *path = linux_ordered_object_v1(receipt, "current_path");
    if (path && !strcmp(obj_string(receipt, "active_route_id"), token) && json_object_has_member(path, "median_ms")) {
        double ms = json_object_get_double_member(path, "median_ms");
        if (isfinite(ms) && ms > 0) g->path_ms = ms;
    }
}

static gboolean linux_globe_refresh_v10(gpointer data) {
    LinuxGlobeV10 *g = data;
    if (!g || !g->app || !g->app->window) return G_SOURCE_REMOVE;
    g->connected = FALSE; g->path_ms = 0;
    g_ptr_array_set_size(g->route_ids, 0); g_hash_table_remove_all(g->external_ids);
    LinuxTelemetryV9 *telemetry = g_object_get_data(G_OBJECT(g->app->window), "linux-telemetry-v9");
    if (!linux_async_busy_v16(g->app) && telemetry && telemetry->map_status) {
        g->path_expires = telemetry->map_latency_expires;
        linux_globe_load_route(g, telemetry->map_status,
                               g->path_expires > g_get_monotonic_time() ? telemetry->map_latency : NULL);
    }
    if (g->app->map) gtk_widget_queue_draw(g->app->map);
    return G_SOURCE_CONTINUE;
}

static gboolean linux_globe_tick_v10(gpointer data){LinuxGlobeV10*g=data;if(g==NULL||g->app==NULL||g->app->window==NULL)return G_SOURCE_REMOVE;if (g->location_expires && g_get_monotonic_time() >= g->location_expires) {
        g->location_expires=0;
        if(g->location_button)gtk_button_set_label(GTK_BUTTON(g->location_button),"Show my location");
        if(g->app->map)gtk_widget_queue_draw(g->app->map);
    }
    if(g->connected){g->phase+=0.018;if(g->phase>=1.0)g->phase-=1.0;if(g->app->map!=NULL)gtk_widget_queue_draw(g->app->map);}return G_SOURCE_CONTINUE;}

static int linux_globe_position(LinuxGlobeV10 *g, const char *id) {
    for (guint i = 0; g && i < g->route_ids->len; i++)
        if (g_strcmp0(id, g_ptr_array_index(g->route_ids, i)) == 0) return (int)i;
    return -1;
}

static void linux_globe_hop_color(int index, int count, double *r, double *green, double *b) {
    static const double colors[][3] = {{.22,.57,1},{.27,.78,.47},{.76,.61,1},{.95,.82,.36},
                                        {.34,.81,.84},{.95,.35,.68},{.54,.61,1},{1,.60,.20}};
    guint slot = index == 0 ? 0 : index == count - 1 ? G_N_ELEMENTS(colors) - 1 :
                 1 + (index - 1) % (G_N_ELEMENTS(colors) - 2);
    const double *color = colors[slot];
    *r = color[0]; *green = color[1]; *b = color[2];
}

static void linux_globe_role_color_v10(LinuxGlobeV10*g,MapNode*n,double*r,double*green,double*b){
    int index = linux_globe_position(g, n->id);
    if (index >= 0) { linux_globe_hop_color(index, (int)g->route_ids->len, r, green, b); return; }
    if(n->selected){*r=0.57;*green=0.42;*b=1.0;return;}
    if(g!=NULL&&g->external_ids!=NULL&&g_hash_table_contains(g->external_ids,n->id)){*r=0.95;*green=0.35;*b=0.68;return;}
    *r=0.28;*green=0.78;*b=0.84;
}

static gboolean linux_globe_draw_v10(GtkWidget*widget,cairo_t*cr,gpointer data){
    App*app=data;LinuxGlobeV10*g=linux_globe_state_v10(app);GtkAllocation allocation;gtk_widget_get_allocation(widget,&allocation);double width=allocation.width,height=allocation.height,cx=width/2.0,cy=height/2.0,rx=fmax(40.0,width/2.0-16.0),ry=fmax(40.0,height/2.0-14.0);
    cairo_set_source_rgb(cr,0.025,0.055,0.105);cairo_paint(cr);cairo_save(cr);cairo_translate(cr,cx,cy);cairo_scale(cr,rx,ry);cairo_arc(cr,0,0,1,0,2*G_PI);cairo_set_source_rgb(cr,0.055,0.145,0.255);cairo_fill_preserve(cr);cairo_set_source_rgb(cr,0.18,0.34,0.53);cairo_set_line_width(cr,2.0/fmax(rx,ry));cairo_stroke(cr);cairo_restore(cr);
    cairo_save(cr);cairo_rectangle(cr,cx-rx,cy-ry,rx*2,ry*2);cairo_clip(cr);cairo_set_source_rgba(cr,0.20,0.36,0.55,0.58);cairo_set_line_width(cr,0.8);
    for(int lat=-60;lat<=60;lat+=30){double x0,y0,x1,y1;linux_globe_xy_v10(lat,-175,width,height,&x0,&y0);linux_globe_xy_v10(lat,175,width,height,&x1,&y1);cairo_move_to(cr,x0,y0);cairo_curve_to(cr,cx-rx*.35,y0,cx+rx*.35,y1,x1,y1);}for(int lon=-120;lon<=120;lon+=60){double x0,y0,x1,y1;linux_globe_xy_v10(-88,lon,width,height,&x0,&y0);linux_globe_xy_v10(88,lon,width,height,&x1,&y1);cairo_move_to(cr,x0,y0);cairo_curve_to(cr,x0+(cx-x0)*.65,cy,x1+(cx-x1)*.65,cy,x1,y1);}cairo_stroke(cr);cairo_restore(cr);
    cairo_select_font_face(cr,"Sans",CAIRO_FONT_SLANT_NORMAL,CAIRO_FONT_WEIGHT_BOLD);cairo_set_font_size(cr,11);cairo_set_source_rgba(cr,.73,.82,.94,.92);cairo_move_to(cr,20,24);cairo_show_text(cr,"ROUTER VPN GLOBE • REAL COORDINATES");

    MapNode *hops[ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH] = {0};
    guint count = g ? MIN(g->route_ids->len, G_N_ELEMENTS(hops)) : 0;
    for (guint i = 0; i < app->nodes->len; i++) {
        MapNode *node = g_ptr_array_index(app->nodes, i);
        int position = linux_globe_position(g, node->id);
        if (node->has_coordinates && position >= 0 && (guint)position < count) hops[position] = node;
    }
    for (guint i = 1; i < count; i++) {
        if (!hops[i-1] || !hops[i]) continue;
        double ax, ay, bx, by, r, green, b;
        linux_globe_xy_v10(hops[i-1]->latitude, hops[i-1]->longitude, width, height, &ax, &ay);
        linux_globe_xy_v10(hops[i]->latitude, hops[i]->longitude, width, height, &bx, &by);
        linux_globe_hop_color((int)i, (int)count, &r, &green, &b);
        cairo_set_source_rgba(cr,r,green,b,.92); cairo_set_line_width(cr,3);
        cairo_move_to(cr,ax,ay); cairo_line_to(cr,bx,by); cairo_stroke(cr);
        double step = g->phase * (count - 1);
        if (g->connected && (guint)step == i-1) {
            double t = step - (i-1);
            cairo_set_source_rgb(cr,1,1,1);
            cairo_arc(cr,ax+(bx-ax)*t,ay+(by-ay)*t,4,0,2*G_PI); cairo_fill(cr);
        }
    }
    if (g && g->connected) {
        g_autofree char *path = g->path_ms > 0 && g_get_monotonic_time() < g->path_expires ? g_strdup_printf("PATH %.1f ms", g->path_ms) : g_strdup("LIVE MULTIHOP");
        cairo_set_source_rgb(cr,.86,.94,1); cairo_move_to(cr,20,42); cairo_show_text(cr,path);
    }
    guint plotted = 0;
    for (guint i=0; i<app->nodes->len; i++) {
        MapNode *node = g_ptr_array_index(app->nodes,i);
        if (!node->has_coordinates) continue;
        int position = linux_globe_position(g, node->id);
        double x,y,r,green,b,size = position >= 0 || node->selected ? 7.0 : 5.2;
        linux_globe_xy_v10(node->latitude,node->longitude,width,height,&x,&y);
        linux_globe_role_color_v10(g,node,&r,&green,&b);
        cairo_set_source_rgba(cr,r,green,b,.25); cairo_arc(cr,x,y,size+5,0,2*G_PI); cairo_fill(cr);
        cairo_set_source_rgb(cr,r,green,b); cairo_arc(cr,x,y,size,0,2*G_PI); cairo_fill(cr);
        const char *name = node->name[0] ? node->name : node->id;
        g_autofree char *title = position >= 0 ? g_strdup_printf("%d. %s",position+1,name) : g_strdup(name);
        double https_ms = linux_live_map_ms(app,node->id);
        g_autofree char *label = https_ms>0 ? g_strdup_printf("%s  %.1f ms HTTPS",title,https_ms) :
                                 node->latency>0 ? g_strdup_printf("%s  %.1f ms",title,node->latency) : g_strdup(title);
        cairo_set_source_rgb(cr,.92,.96,1); cairo_set_font_size(cr,10.5);
        cairo_move_to(cr,x+size+5,y-5); cairo_show_text(cr,label); plotted++;
    }
    if (g && g->location_expires > g_get_monotonic_time()) {
        double x, y; linux_globe_xy_v10(g->device_lat,g->device_lon,width,height,&x,&y);
        cairo_set_source_rgb(cr,.43,.92,.62); cairo_arc(cr,x,y,6,0,2*G_PI); cairo_fill(cr);
        cairo_move_to(cr,x+9,y+12); cairo_show_text(cr,"YOU");
    }
    if(plotted==0){cairo_set_source_rgba(cr,.75,.80,.88,.92);cairo_move_to(cr,24,height/2.0);cairo_show_text(cr,"No real node coordinates — Router VPN never invents map locations.");}
    cairo_set_font_size(cr,9);cairo_set_source_rgba(cr,.55,.65,.78,.82);cairo_move_to(cr,20,height-14);cairo_show_text(cr,"Only linked real coordinates • device location is not fabricated");return FALSE;
}

static gboolean linux_globe_click_v10(GtkWidget*widget,GdkEventButton*event,gpointer data){
    App*app=data;if(app==NULL||event==NULL||event->button!=1)return FALSE;GtkAllocation allocation;gtk_widget_get_allocation(widget,&allocation);double best=18.0;MapNode*hit=NULL;for(guint i=0;i<app->nodes->len;i++){MapNode*n=g_ptr_array_index(app->nodes,i);if(!n->has_coordinates)continue;double x,y;linux_globe_xy_v10(n->latitude,n->longitude,allocation.width,allocation.height,&x,&y);double d=hypot(event->x-x,event->y-y);if(d<best){best=d;hit=n;}}if(hit==NULL)return FALSE;if(!routervpn_require_mutation_idle(app,"selecting a node from the VPN globe"))return TRUE;char*body=json_string_body("id",hit->id);Buffer out={0};char*err=NULL;if(api_request("/api/profile/select","POST",body,10000,&out,&err)){append_diag(app,"Selected node from the VPN globe.");refresh_profiles(app);}else append_diag(app,err!=NULL?err:"Map node selection failed.");g_free(body);g_free(err);free(out.data);return TRUE;
}

/* One explicit location request owns one GeoClue client and its private bus
 * connection. Ending the request releases the client, including on window close. */
typedef struct {
    double latitude, longitude;
    gint64 expires;
} LinuxGlobeFix;

static GVariant *linux_geoclue_call(GDBusConnection *bus, const char *path, const char *interface,
                                    const char *method, GVariant *args, const GVariantType *reply,
                                    GCancellable *cancel, GError **error) {
    return g_dbus_connection_call_sync(bus, "org.freedesktop.GeoClue2", path, interface, method, args,
                                       reply, G_DBUS_CALL_FLAGS_NONE, 15000, cancel, error);
}

static void linux_globe_locate(GTask *task, gpointer source, gpointer data, GCancellable *cancel) {
    (void)source; (void)data;
    const char *props = "org.freedesktop.DBus.Properties", *client = "org.freedesktop.GeoClue2.Client";
    g_autoptr(GError) error = NULL;
    g_autofree char *address = g_dbus_address_get_for_bus_sync(G_BUS_TYPE_SYSTEM, cancel, &error);
    g_autoptr(GDBusConnection) bus = NULL;
    g_autoptr(GVariant) owner = NULL, configured = NULL, accuracy = NULL, started = NULL;
    const char *path = NULL;
    LinuxGlobeFix *fix = NULL;
    if (address) bus = g_dbus_connection_new_for_address_sync(address, G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
                           G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION, NULL, cancel, &error);
    if (!bus) goto done;
    g_dbus_connection_set_exit_on_close(bus, FALSE);
    owner = linux_geoclue_call(bus, "/org/freedesktop/GeoClue2/Manager", "org.freedesktop.GeoClue2.Manager",
                               "GetClient", NULL, G_VARIANT_TYPE("(o)"), cancel, &error);
    if (!owner) goto done;
    g_variant_get(owner, "(&o)", &path);
    configured = linux_geoclue_call(bus, path, props, "Set", g_variant_new("(ssv)",client,"DesktopId",g_variant_new_string("router-vpn")),
                                    G_VARIANT_TYPE_UNIT, cancel, &error);
    if (!configured) goto done;
    accuracy = linux_geoclue_call(bus, path, props, "Set", g_variant_new("(ssv)",client,"RequestedAccuracyLevel",g_variant_new_uint32(4)),
                                  G_VARIANT_TYPE_UNIT, cancel, &error);
    if (!accuracy) goto done;
    started = linux_geoclue_call(bus, path, client, "Start", NULL, G_VARIANT_TYPE_UNIT, cancel, &error);
    if (!started) goto done;
    gint64 deadline = g_get_monotonic_time() + 30 * G_TIME_SPAN_SECOND;
    while (!g_cancellable_is_cancelled(cancel) && g_get_monotonic_time() < deadline) {
        g_autoptr(GVariant) reply = linux_geoclue_call(bus,path,props,"Get",g_variant_new("(ss)",client,"Location"),
                                                       G_VARIANT_TYPE("(v)"), cancel, &error);
        if (!reply) break;
        g_autoptr(GVariant) location = NULL;
        g_variant_get(reply, "(v)", &location);
        if (!g_variant_is_of_type(location,G_VARIANT_TYPE_OBJECT_PATH)) break;
        const char *object = g_variant_get_string(location,NULL);
        if (strcmp(object,"/") != 0) {
            g_autoptr(GVariant) values = linux_geoclue_call(bus,object,props,"GetAll",
                g_variant_new("(s)","org.freedesktop.GeoClue2.Location"),G_VARIANT_TYPE("(a{sv})"),cancel,&error);
            if (!values) break;
            g_autoptr(GVariant) dict = g_variant_get_child_value(values,0);
            double lat, lon, meters;
            guint64 seconds, micros;
            if (g_variant_lookup(dict,"Latitude","d",&lat) && g_variant_lookup(dict,"Longitude","d",&lon) &&
                g_variant_lookup(dict,"Accuracy","d",&meters) && g_variant_lookup(dict,"Timestamp","(tt)",&seconds,&micros) &&
                isfinite(lat) && fabs(lat)<=90 && isfinite(lon) && fabs(lon)<=180 && meters>=0 && meters<=10000 &&
                seconds < (guint64)G_MAXINT64/G_TIME_SPAN_SECOND && micros < G_TIME_SPAN_SECOND) {
                gint64 age = g_get_real_time() - ((gint64)seconds * G_TIME_SPAN_SECOND + (gint64)micros);
                if (age>=0 && age<30*G_TIME_SPAN_SECOND) {
                    fix=g_new(LinuxGlobeFix,1);
                    *fix=(LinuxGlobeFix){lat,lon,g_get_monotonic_time()+30*G_TIME_SPAN_SECOND-age};
                    break;
                }
            }
        }
        g_usleep(250000);
    }
done:
    if (bus) g_dbus_connection_close_sync(bus,NULL,NULL);
    if (fix) g_task_return_pointer(task,fix,g_free);
    else if (error) g_task_return_error(task,g_steal_pointer(&error));
    else g_task_return_new_error(task,G_IO_ERROR,G_IO_ERROR_TIMED_OUT,"Location services did not return a fresh position.");
}

static void linux_globe_located(GObject *source, GAsyncResult *result, gpointer data) {
    (void)data;
    GtkButton *button=GTK_BUTTON(source);
    LinuxGlobeV10 *g=g_object_get_data(source,"routervpn-location-globe");
    g_autoptr(GError) error=NULL;
    g_autofree LinuxGlobeFix *fix=g_task_propagate_pointer(G_TASK(result),&error);
    if (!g || g_task_get_cancellable(G_TASK(result))!=g->location_request) return;
    g_clear_object(&g->location_request);
    if (fix && fix->expires>g_get_monotonic_time()) {
        g->device_lat=fix->latitude; g->device_lon=fix->longitude; g->location_expires=fix->expires;
        gtk_button_set_label(button,"Hide my location");
    } else {
        gtk_button_set_label(button,"Retry my location");
        gtk_widget_set_tooltip_text(GTK_WIDGET(button),error?error->message:"No fresh location fix.");
    }
    gtk_widget_queue_draw(g->app->map);
}

static void linux_globe_location_destroy(GtkWidget *button, gpointer unused) {
    (void)unused;
    LinuxGlobeV10 *g=g_object_get_data(G_OBJECT(button),"routervpn-location-globe");
    if (!g) return;
    g_object_set_data(G_OBJECT(button),"routervpn-location-globe",NULL);
    g->location_button=NULL;
    if (g->location_request) {g_cancellable_cancel(g->location_request);g_clear_object(&g->location_request);}
}

static void linux_globe_toggle_location(GtkButton *button, gpointer data) {
    LinuxGlobeV10 *g=data;
    if (g->location_request || g->location_expires>g_get_monotonic_time()) {
        if (g->location_request) {g_cancellable_cancel(g->location_request);g_clear_object(&g->location_request);}
        g->location_expires=0;
        gtk_button_set_label(button,"Show my location");
        gtk_widget_queue_draw(g->app->map);
        return;
    }
    g->location_request=g_cancellable_new();
    g_autoptr(GTask) task=g_task_new(button,g->location_request,linux_globe_located,NULL);
    gtk_button_set_label(button,"Locating… (cancel)");
    g_task_run_in_thread(task,linux_globe_locate);
}

static void linux_install_globe_v10(App*app){
    if(app==NULL||app->window==NULL||app->map==NULL){
        return;
    }
    LinuxGlobeV10*g=g_new0(LinuxGlobeV10,1);g->app=app;g->route_ids=g_ptr_array_new_with_free_func(g_free);g->external_ids=g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);g_object_set_data_full(G_OBJECT(app->window),"linux-globe-v10",g,linux_globe_free_v10);g_signal_handlers_disconnect_by_func(app->map,G_CALLBACK(routervpn_flat_map_v9),app);gtk_widget_add_events(app->map,GDK_BUTTON_PRESS_MASK);g_signal_connect(app->map,"draw",G_CALLBACK(linux_globe_draw_v10),app);g_signal_connect(app->map,"button-press-event",G_CALLBACK(linux_globe_click_v10),app);GtkWidget *frame = gtk_widget_get_parent(app->map);
    if (GTK_IS_FRAME(frame)) {
        g->location_button = gtk_button_new_with_label("Show my location");
        gtk_widget_set_tooltip_text(g->location_button,"Show a fresh location from the desktop location service.");
        g_object_set_data(G_OBJECT(g->location_button),"routervpn-location-globe",g);
        g_signal_connect(g->location_button,"clicked",G_CALLBACK(linux_globe_toggle_location),g);
        g_signal_connect(g->location_button,"destroy",G_CALLBACK(linux_globe_location_destroy),NULL);
        gtk_frame_set_label_widget(GTK_FRAME(frame),g->location_button);
        gtk_frame_set_label_align(GTK_FRAME(frame),.98f,.5f);
        gtk_widget_show(g->location_button);
    }
    g->animation_source=g_timeout_add(60,linux_globe_tick_v10,g);g->refresh_source=g_timeout_add(2000,linux_globe_refresh_v10,g);linux_globe_refresh_v10(g);gtk_widget_queue_draw(app->map);
}

/* Linux globe v10 shipping contract: custom offline VPN globe; only real stored
 * coordinates; entry blue, exit orange, selected purple, external pink, normal teal;
 * measured node ms labels; clickable map nodes; active entry→exit curve; animated packet;
 * measured PATH ms badge; no IP geolocation and no fabricated device location. */
