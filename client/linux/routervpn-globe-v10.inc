typedef struct {
    App *app;
    char *entry_id;
    char *exit_id;
    GHashTable *external_ids;
    double path_ms;
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
    LinuxGlobeV10*g=data;if(g==NULL)return;if(g->animation_source)g_source_remove(g->animation_source);if(g->refresh_source)g_source_remove(g->refresh_source);g_free(g->entry_id);g_free(g->exit_id);if(g->external_ids!=NULL)g_hash_table_unref(g->external_ids);g_free(g);
}

static LinuxGlobeV10*linux_globe_state_v10(App*app){return app!=NULL&&app->window!=NULL?g_object_get_data(G_OBJECT(app->window),"linux-globe-v10"):NULL;}

static gboolean linux_globe_refresh_v10(gpointer data){
    LinuxGlobeV10*g=data;if(g==NULL||g->app==NULL||g->app->window==NULL)return G_SOURCE_REMOVE;g->connected=FALSE;g->path_ms=0.0;g_clear_pointer(&g->entry_id,g_free);g_clear_pointer(&g->exit_id,g_free);
    if(g->external_ids==NULL)g->external_ids=g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);else g_hash_table_remove_all(g->external_ids);

    Buffer profiles_out={0};char*profiles_err=NULL;if(api_request("/api/profiles","GET",NULL,2500,&profiles_out,&profiles_err)){JsonNode*root=parse_json(profiles_out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject*obj=json_node_get_object(root);JsonArray*profiles=json_object_has_member(obj,"profiles")?json_object_get_array_member(obj,"profiles"):NULL;for(guint i=0;profiles!=NULL&&i<json_array_get_length(profiles);i++){JsonObject*p=json_array_get_object_element(profiles,i);if(p==NULL)continue;const char*id=obj_string(p,"id"),*kind=obj_string(p,"node_kind");if(id[0]&&g_ascii_strcasecmp(kind,"external")==0)g_hash_table_add(g->external_ids,g_strdup(id));}json_node_free(root);}}g_free(profiles_err);free(profiles_out.data);

    Buffer out={0};char*err=NULL;if(api_request("/api/multihop/status","GET",NULL,2500,&out,&err)){JsonNode*root=parse_json(out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject*obj=json_node_get_object(root);gboolean connected=json_object_has_member(obj,"connected")&&json_object_get_boolean_member(obj,"connected");const char*entry=obj_string(obj,"entry_id"),*exit=obj_string(obj,"exit_id");if(connected&&entry[0]&&exit[0]&&strcmp(entry,exit)!=0){g->connected=TRUE;g->entry_id=g_strdup(entry);g->exit_id=g_strdup(exit);char*body=g_strdup_printf("{\"entry_id\":\"%s\",\"exit_id\":\"%s\",\"samples\":2}",entry,exit);Buffer latency={0};char*latency_err=NULL;if(api_request("/api/multihop/live-latency","POST",body,5500,&latency,&latency_err)){JsonNode*l=parse_json(latency.data);if(l!=NULL&&JSON_NODE_HOLDS_OBJECT(l)){JsonObject*lo=json_node_get_object(l);if(json_object_has_member(lo,"current_path")){JsonObject*p=json_object_get_object_member(lo,"current_path");if(p!=NULL&&json_object_has_member(p,"median_ms"))g->path_ms=json_object_get_double_member(p,"median_ms");}json_node_free(l);}}g_free(latency_err);free(latency.data);g_free(body);}json_node_free(root);}}g_free(err);free(out.data);if(g->app->map!=NULL)gtk_widget_queue_draw(g->app->map);return G_SOURCE_CONTINUE;
}

static gboolean linux_globe_tick_v10(gpointer data){LinuxGlobeV10*g=data;if(g==NULL||g->app==NULL||g->app->window==NULL)return G_SOURCE_REMOVE;if(g->connected){g->phase+=0.018;if(g->phase>=1.0)g->phase-=1.0;if(g->app->map!=NULL)gtk_widget_queue_draw(g->app->map);}return G_SOURCE_CONTINUE;}

static void linux_globe_role_color_v10(LinuxGlobeV10*g,MapNode*n,double*r,double*green,double*b){
    if(g!=NULL&&g->entry_id!=NULL&&g_strcmp0(n->id,g->entry_id)==0){*r=0.22;*green=0.57;*b=1.0;return;}
    if(g!=NULL&&g->exit_id!=NULL&&g_strcmp0(n->id,g->exit_id)==0){*r=1.0;*green=0.60;*b=0.20;return;}
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

    MapNode*entry_node=NULL,*exit_node=NULL;guint plotted=0;for(guint i=0;i<app->nodes->len;i++){MapNode*n=g_ptr_array_index(app->nodes,i);if(!n->has_coordinates)continue;double x,y,r,green,b;linux_globe_xy_v10(n->latitude,n->longitude,width,height,&x,&y);linux_globe_role_color_v10(g,n,&r,&green,&b);double size=(g!=NULL&&((g->entry_id&&g_strcmp0(n->id,g->entry_id)==0)||(g->exit_id&&g_strcmp0(n->id,g->exit_id)==0))||n->selected)?7.0:5.2;cairo_set_source_rgba(cr,r,green,b,.25);cairo_arc(cr,x,y,size+5,0,2*G_PI);cairo_fill(cr);cairo_set_source_rgb(cr,r,green,b);cairo_arc(cr,x,y,size,0,2*G_PI);cairo_fill(cr);cairo_set_source_rgb(cr,.92,.96,1.0);cairo_set_font_size(cr,10.5);char*label=n->latency>0?g_strdup_printf("%s  %.1f ms",n->name[0]?n->name:n->id,n->latency):g_strdup(n->name[0]?n->name:n->id);cairo_move_to(cr,x+size+5,y-5);cairo_show_text(cr,label);g_free(label);if(g!=NULL&&g->entry_id&&g_strcmp0(n->id,g->entry_id)==0)entry_node=n;if(g!=NULL&&g->exit_id&&g_strcmp0(n->id,g->exit_id)==0)exit_node=n;plotted++;}
    if(g!=NULL&&g->connected&&entry_node!=NULL&&exit_node!=NULL){double ax,ay,bx,by;linux_globe_xy_v10(entry_node->latitude,entry_node->longitude,width,height,&ax,&ay);linux_globe_xy_v10(exit_node->latitude,exit_node->longitude,width,height,&bx,&by);double c1x=ax+(bx-ax)*.34,c2x=ax+(bx-ax)*.66,curve_y=fmin(height-26,fmax(ay,by)+44);cairo_set_line_cap(cr,CAIRO_LINE_CAP_ROUND);cairo_move_to(cr,ax,ay);cairo_curve_to(cr,c1x,curve_y,c2x,curve_y,bx,by);cairo_set_source_rgba(cr,.22,.57,1.0,.28);cairo_set_line_width(cr,9);cairo_stroke_preserve(cr);cairo_set_source_rgba(cr,.35,.78,1.0,.96);cairo_set_line_width(cr,3.2);cairo_stroke(cr);double t=g->phase,u=1.0-t,px=u*u*u*ax+3*u*u*t*c1x+3*u*t*t*c2x+t*t*t*bx,py=u*u*u*ay+3*u*u*t*curve_y+3*u*t*t*curve_y+t*t*t*by;cairo_set_source_rgba(cr,.35,.85,1,.24);cairo_arc(cr,px,py,8,0,2*G_PI);cairo_fill(cr);cairo_set_source_rgb(cr,1,1,1);cairo_arc(cr,px,py,3.5,0,2*G_PI);cairo_fill(cr);char*path=g->path_ms>0?g_strdup_printf("PATH %.1f ms",g->path_ms):g_strdup("LIVE MULTIHOP");cairo_set_source_rgba(cr,.03,.08,.16,.88);cairo_rectangle(cr,(ax+bx)/2-46,(ay+by)/2+18,92,20);cairo_fill(cr);cairo_set_source_rgb(cr,.86,.94,1);cairo_move_to(cr,(ax+bx)/2-40,(ay+by)/2+32);cairo_show_text(cr,path);g_free(path);}
    if(plotted==0){cairo_set_source_rgba(cr,.75,.80,.88,.92);cairo_move_to(cr,24,height/2.0);cairo_show_text(cr,"No real node coordinates — Router VPN never invents map locations.");}
    cairo_set_font_size(cr,9);cairo_set_source_rgba(cr,.55,.65,.78,.82);cairo_move_to(cr,20,height-14);cairo_show_text(cr,"Only linked real coordinates • device location is not fabricated");return FALSE;
}

static gboolean linux_globe_click_v10(GtkWidget*widget,GdkEventButton*event,gpointer data){
    App*app=data;if(app==NULL||event==NULL||event->button!=1)return FALSE;GtkAllocation allocation;gtk_widget_get_allocation(widget,&allocation);double best=18.0;MapNode*hit=NULL;for(guint i=0;i<app->nodes->len;i++){MapNode*n=g_ptr_array_index(app->nodes,i);if(!n->has_coordinates)continue;double x,y;linux_globe_xy_v10(n->latitude,n->longitude,allocation.width,allocation.height,&x,&y);double d=hypot(event->x-x,event->y-y);if(d<best){best=d;hit=n;}}if(hit==NULL)return FALSE;char*body=json_string_body("id",hit->id);Buffer out={0};char*err=NULL;if(api_request("/api/profile/select","POST",body,10000,&out,&err)){append_diag(app,"Selected node from the VPN globe.");refresh_profiles(app);}else append_diag(app,err!=NULL?err:"Map node selection failed.");g_free(body);g_free(err);free(out.data);return TRUE;
}

static void linux_install_globe_v10(App*app){
    if(app==NULL||app->window==NULL||app->map==NULL)return;LinuxGlobeV10*g=g_new0(LinuxGlobeV10,1);g->app=app;g->external_ids=g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);g_object_set_data_full(G_OBJECT(app->window),"linux-globe-v10",g,linux_globe_free_v10);g_signal_handlers_disconnect_by_func(app->map,G_CALLBACK(routervpn_flat_map_v9),app);gtk_widget_add_events(app->map,GDK_BUTTON_PRESS_MASK);g_signal_connect(app->map,"draw",G_CALLBACK(linux_globe_draw_v10),app);g_signal_connect(app->map,"button-press-event",G_CALLBACK(linux_globe_click_v10),app);g->animation_source=g_timeout_add(60,linux_globe_tick_v10,g);g->refresh_source=g_timeout_add(2000,linux_globe_refresh_v10,g);linux_globe_refresh_v10(g);gtk_widget_queue_draw(app->map);
}

/* Linux globe v10 shipping contract: custom offline VPN globe; only real stored
 * coordinates; entry blue, exit orange, selected purple, external pink, normal teal;
 * measured node ms labels; clickable map nodes; active entry→exit curve; animated packet;
 * measured PATH ms badge; no IP geolocation and no fabricated device location. */
