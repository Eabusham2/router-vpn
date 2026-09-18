/* Exercise the shipped Fastest selector, nonmodal Performance buttons and the
 * multihop dialog callback with isolated, explicitly fictional test nodes. */
typedef struct {
    App *app;
    LinuxUnifiedV8 *base;
    LinuxTelemetryV9 *telemetry;
    LinuxPerformanceV17 *panel;
    guint source, dialog_source;
    guint64 old_generation;
    int stage, ticks, beats, failure, dialog_ticks;
} LinuxExtendedProbeV17;

static LinuxPerformanceV17 *linux_test_performance_v17(void) {
    GList *windows=gtk_window_list_toplevels();LinuxPerformanceV17 *found=NULL;
    for(GList *p=windows;p!=NULL;p=p->next){found=g_object_get_data(G_OBJECT(p->data),"linux-performance-v17");if(found!=NULL)break;}
    g_list_free(windows);return found;
}
static gboolean linux_test_multihop_dialog_v17(gpointer data) {
    LinuxExtendedProbeV17 *p=data;p->dialog_ticks++;
    GList *windows=gtk_window_list_toplevels();GtkWidget *dialog=NULL,*button=NULL;
    for(GList *item=windows;item!=NULL;item=item->next){
        if(GTK_IS_DIALOG(item->data)&&g_strcmp0(gtk_window_get_title(GTK_WINDOW(item->data)),"Router VPN multihop / map")==0){dialog=item->data;button=linux_telemetry_find_button_v9(dialog,"Connect real multihop");break;}
    }
    g_list_free(windows);
    if(dialog==NULL&&p->dialog_ticks<80)return G_SOURCE_CONTINUE;
    p->dialog_source=0;
    if(button==NULL){p->failure=20;if(dialog!=NULL)gtk_dialog_response(GTK_DIALOG(dialog),GTK_RESPONSE_CLOSE);return G_SOURCE_REMOVE;}
    gtk_button_clicked(GTK_BUTTON(button));
    LinuxAsyncActionsV16 *s=linux_async_state_v16(p->app);
    if(s->primary==NULL||!s->primary->connecting){p->failure=21;gtk_dialog_response(GTK_DIALOG(dialog),GTK_RESPONSE_CLOSE);}
    return G_SOURCE_REMOVE;
}
static gboolean linux_extended_probe_v17(gpointer data) {
    LinuxExtendedProbeV17 *p=data;LinuxAsyncActionsV16 *s=linux_async_state_v16(p->app);
    p->ticks++;p->beats++;
    if(p->ticks>320){p->failure=1;goto finish;}
    if(p->stage==0){
        gint64 start=g_get_monotonic_time();
        g_signal_emit_by_name(p->telemetry->fastest,"changed");
        if(g_get_monotonic_time()-start>500000||s->primary==NULL||s->primary->connecting||gtk_widget_get_sensitive(p->base->connect)){p->failure=2;goto finish;}
        start=g_get_monotonic_time();
        (void)refresh_timer(p->app);(void)linux_unified_refresh_v8(p->base);(void)linux_telemetry_refresh_v9(p->telemetry);
        if(g_get_monotonic_time()-start>200000){p->failure=3;goto finish;}
        p->stage=1;p->beats=0;
    }else if(p->stage==1&&!linux_async_busy_v16(p->app)){
        linux_telemetry_refresh_fastest_v9(p->telemetry);
        if(p->beats<4||g_strcmp0(gtk_combo_box_get_active_id(GTK_COMBO_BOX(p->telemetry->fastest)),"fixture-fast")!=0){p->failure=4;goto finish;}
        puts("Linux extended actions: Fastest stayed responsive, updated only selected node and did not connect: PASS");
        GtkWidget *button=linux_telemetry_find_button_v9(p->base->stack,"Performance");
        if(button==NULL){p->failure=5;goto finish;}
        gtk_button_clicked(GTK_BUTTON(button));p->panel=linux_test_performance_v17();
        if(p->panel==NULL||gtk_window_get_modal(GTK_WINDOW(p->panel->dialog))){p->failure=6;goto finish;}
        gtk_button_clicked(GTK_BUTTON(p->panel->actions[2]));gtk_window_resize(GTK_WINDOW(p->panel->dialog),640,480);p->stage=2;p->beats=0;
    }else if(p->stage==2&&p->panel->generation==0){
        int minimum=0;gtk_widget_get_preferred_width(p->panel->dialog,&minimum,NULL);
        if(minimum>640){p->failure=14;goto finish;}
        if(p->beats<4||strstr(gtk_label_get_text(GTK_LABEL(p->panel->result)),"finished")==NULL){p->failure=7;goto finish;}
        gtk_button_clicked(GTK_BUTTON(p->panel->actions[3]));p->stage=3;p->beats=0;
    }else if(p->stage==3&&p->panel->generation==0){
        if(strstr(gtk_label_get_text(GTK_LABEL(p->panel->result)),"finished")==NULL){p->failure=8;goto finish;}
        puts("Linux extended actions: Performance current-path and exact routed-hop requests completed asynchronously: PASS");
        gtk_button_clicked(GTK_BUTTON(p->panel->actions[2]));p->stage=4;p->beats=0;
    }else if(p->stage==4&&p->beats>=6){
        gtk_dialog_response(GTK_DIALOG(p->panel->dialog),6);p->stage=5;p->beats=0;
    }else if(p->stage==5&&p->panel->generation==0){
        if(strstr(gtk_label_get_text(GTK_LABEL(p->panel->result)),"cancelled")==NULL){p->failure=9;goto finish;}
        gtk_button_clicked(GTK_BUTTON(p->panel->actions[2]));p->stage=6;p->beats=0;
    }else if(p->stage==6&&p->beats>=6){
        p->old_generation=p->panel->generation;
        gtk_dialog_response(GTK_DIALOG(p->panel->dialog),GTK_RESPONSE_CLOSE);p->panel=NULL;
        p->stage=7;p->beats=0;
    }else if(p->stage==7&&!linux_async_busy_v16(p->app)){
        puts("Linux extended actions: Performance Cancel and Close terminated their owned requests: PASS");
        p->dialog_source=g_timeout_add(25,linux_test_multihop_dialog_v17,p);
        on_linux_multihop_v7(NULL,p->app);
        if(p->dialog_source!=0){g_source_remove(p->dialog_source);p->dialog_source=0;p->failure=10;}
        if(p->failure||s->primary==NULL||!s->primary->connecting){p->failure=11;goto finish;}
        linux_async_cancel_request_v17(p->app,p->old_generation);
        if(atomic_load(&s->primary->cancelled)){p->failure=12;goto finish;}
        p->stage=8;p->beats=0;
    }else if(p->stage==8&&p->beats>=6){
        gtk_button_clicked(GTK_BUTTON(p->base->connect));p->stage=9;p->beats=0;
    }else if(p->stage==9&&!linux_async_busy_v16(p->app)){
        puts("Linux extended actions: multihop handed ownership to map; stale observer could not cancel it; Disconnect worked: PASS");
        goto finish;
    }
    return G_SOURCE_CONTINUE;
finish:
    p->source=0;
    while(g_source_remove_by_user_data(p->telemetry)){}
    while(g_source_remove_by_user_data(p->base)){}
    if(p->panel!=NULL){gtk_widget_destroy(p->panel->dialog);p->panel=NULL;}
    gtk_widget_destroy(p->app->window);gtk_main_quit();return G_SOURCE_REMOVE;
}
static int linux_extended_actions_self_test_v17(void) {
    App app={0};app.nodes=g_ptr_array_new_with_free_func(free_map_node);app.router_ids=g_ptr_array_new_with_free_func(g_free);app.mode_ids=g_ptr_array_new_with_free_func(g_free);
    build_ui_v5(&app);linux_install_telemetry_v9(&app);gtk_widget_show_all(app.window);g_object_ref(app.window);
    LinuxExtendedProbeV17 p={.app=&app,.base=g_object_get_data(G_OBJECT(app.window),"linux-unified-v8"),.telemetry=g_object_get_data(G_OBJECT(app.window),"linux-telemetry-v9")};
    p.source=g_timeout_add(25,linux_extended_probe_v17,&p);gtk_main();
    for(int i=0;i<10;i++){while(gtk_events_pending())gtk_main_iteration_do(FALSE);g_usleep(20000);}
    LinuxAsyncActionsV16 *s=linux_async_state_v16(&app);
    if(s==NULL||!s->closed||s->primary!=NULL||s->stop!=NULL||s->poll!=0)p.failure=13;
    g_object_unref(app.window);g_ptr_array_unref(app.nodes);g_ptr_array_unref(app.router_ids);g_ptr_array_unref(app.mode_ids);
    if(p.failure)fprintf(stderr,"Linux extended UI acceptance failed: %d (stage %d)\n",p.failure,p.stage);
    return p.failure?70+p.failure:0;
}
