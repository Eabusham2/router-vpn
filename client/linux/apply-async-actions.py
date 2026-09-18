#!/usr/bin/env python3
"""Add owned asynchronous actions after the frozen session-mutation transform.

The existing transformer verifies source hashes and exact anchors first. These
additional exact seams keep short transactional profile operations synchronous;
long actions get an owned request and Stop gets a separate preemption lane.
"""
from pathlib import Path


def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise RuntimeError(f"Linux async action composition drifted: {old[:100]}")
    return text.replace(old, new, 1)


def apply(path: Path) -> None:
    text = path.read_text()
    if path.name == "routervpn-gtk-product.c":
        anchor = "static size_t write_cb("
        text = replace_once(text, anchor, '#include "routervpn-async-actions-v16.inc"\n\n' + anchor)
        anchor = "static gboolean routervpn_mutation_busy(App *app) {\n"
        text = replace_once(text, anchor, anchor + "    if (linux_async_busy_v16(app)) return TRUE;\n")
        anchor = "static void post_and_log(App *app, const char *path, const char *body, long timeout_ms, const char *label) {\n"
        text = replace_once(text, anchor, anchor + "    if (linux_async_dispatch_v16(app, path, body, timeout_ms, label)) return;\n")
    elif path.name == "routervpn-unified-shell-v8.inc":
        anchor = "    (void)button; LinuxUnifiedV8 *state=data; Buffer out={0}; char *err=NULL; gboolean status_ok=FALSE, active=FALSE, disconnecting=FALSE;"
        text = replace_once(text, anchor, anchor + '''
    if (linux_async_stopping_v16(state->app)) return;
    if (linux_async_connecting_v16(state->app)) {
        post_and_log(state->app, "/api/disconnect", "{}", 30000, "Disconnect");
        return;
    }''')
        anchor = "gtk_widget_set_sensitive(state->connect,status_ok&&!disconnecting);"
        text = replace_once(text, anchor, '''gboolean pending=linux_async_busy_v16(state->app), local_connect=linux_async_connecting_v16(state->app), local_stop=linux_async_stopping_v16(state->app);
    if(local_stop)gtk_button_set_label(GTK_BUTTON(state->connect),"Disconnecting…");
    else if(local_connect)gtk_button_set_label(GTK_BUTTON(state->connect),"Disconnect");
    gtk_widget_set_sensitive(state->connect,!local_stop&&!disconnecting&&(local_connect||(status_ok&&(!pending||busy))));
    busy=busy||pending;''')
        anchor = "static void build_ui_v5(App *app) {"
        text = replace_once(text, anchor, '''static void linux_async_controls_v16(App *app) {
    LinuxUnifiedV8 *state=g_object_get_data(G_OBJECT(app->window),"linux-unified-v8");
    if(state==NULL)return;
    if(linux_async_busy_v16(app)) {
        GtkWidget *controls[]={state->node,state->mode,state->dns,state->kill_switch,state->multihop};
        for(guint i=0;i<G_N_ELEMENTS(controls);i++)gtk_widget_set_sensitive(controls[i],FALSE);
        if(linux_async_stopping_v16(app)) {gtk_button_set_label(GTK_BUTTON(state->connect),"Disconnecting…");gtk_widget_set_sensitive(state->connect,FALSE);}
        else if(linux_async_connecting_v16(app)) {gtk_button_set_label(GTK_BUTTON(state->connect),"Disconnect");gtk_widget_set_sensitive(state->connect,TRUE);}
    } else linux_unified_refresh_v8(state);
}

''' + anchor)
        anchor = 'g_object_set_data_full(G_OBJECT(app->window),"linux-unified-v8",state,g_free);'
        text = replace_once(text, anchor, anchor + 'linux_async_ensure_v16(app)->changed=linux_async_controls_v16;')
    path.write_text(text)
