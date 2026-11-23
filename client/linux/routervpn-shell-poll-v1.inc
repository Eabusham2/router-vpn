/* One GTK owner supplies the shell, Home, diagnostics and incremental events.
 * Only completed loopback GETs reach the existing renderers. */
static guint64 linux_shell_generation_v1(App *app) {
    LinuxAsyncActionsV16 *actions = linux_async_state_v16(app);
    return actions ? actions->generation : 0;
}

static void linux_shell_cancel_v1(LinuxShellReadings *round) {
    round->discarded = TRUE;
    for (guint i = 0; i < G_N_ELEMENTS(round->jobs); i++) rv_http_cancel_v16(round->jobs[i]);
}

static void linux_shell_release_v1(LinuxShellReadings *round) {
    for (guint i = 0; i < G_N_ELEMENTS(round->jobs); i++) {
        rv_http_free_v16(round->jobs[i]);
        round->jobs[i] = NULL;
        round->paths[i] = NULL;
    }
    g_clear_pointer(&round->cursor_path, g_free);
    g_clear_pointer(&round->selected, g_free);
    round->active = FALSE;
}

static void linux_shell_destroy_v1(GtkWidget *widget, gpointer data) {
    (void)widget;
    LinuxUnifiedV8 *state = data;
    LinuxShellReadings *round = &state->readings;
    round->closed = TRUE;
    if (round->timer && g_main_context_find_source_by_id(NULL, round->timer)) g_source_remove(round->timer);
    round->timer = 0;
    linux_shell_cancel_v1(round);
    linux_shell_release_v1(round);
}

static JsonNode *linux_shell_object_v1(LinuxShellReadings *round, guint slot) {
    RVHttpJobV16 *job = round->jobs[slot];
    if (!job || atomic_load(&job->cancelled) || job->result != CURLE_OK || job->status / 100 != 2 || !job->response) return NULL;
    JsonNode *node = parse_json(job->response);
    if (node && !JSON_NODE_HOLDS_OBJECT(node)) { json_node_free(node); return NULL; }
    return node;
}

static void linux_shell_deliver_v1(LinuxUnifiedV8 *state) {
    LinuxShellReadings *round = &state->readings;
    JsonNode *status_node = linux_shell_object_v1(round, 0);
    JsonNode *settings_node = linux_shell_object_v1(round, 1);
    JsonNode *protection_node = linux_shell_object_v1(round, 2);
    JsonNode *home_node = linux_shell_object_v1(round, 3);
    JsonObject *status = status_node ? json_node_get_object(status_node) : NULL;
    JsonObject *settings = settings_node ? json_node_get_object(settings_node) : NULL;
    JsonObject *protection = protection_node ? json_node_get_object(protection_node) : NULL;
    JsonObject *home = home_node ? json_node_get_object(home_node) : NULL;
    if (!round->selected || !settings || g_strcmp0(obj_string(settings, "profile_id"), round->selected)) {
        round->paths[1] = NULL;
        gtk_label_set_text(GTK_LABEL(state->settings_summary), "AUTO requirements unavailable");
    }
    if (!round->selected || !protection || g_strcmp0(obj_string(protection, "profile_id"), round->selected))
        round->paths[2] = NULL;
    const char *target = round->selected;
    g_autofree char *phase = g_ascii_strdown(obj_string(status, "phase"), -1);
    g_strstrip(phase);
    gboolean active = status && ((json_object_has_member(status, "connected") && json_object_get_boolean_member(status, "connected")) ||
                                 (phase[0] && strcmp(phase, "off") && strcmp(phase, "failed")));
    if (active && obj_string(status, "router_id")[0])
        target = obj_string(status, "router_id");
    if (!status || !home || g_strcmp0(obj_string(home, "node_id"), target)) round->paths[3] = NULL;
    refresh_status_readings(state->app, round);
    if (state->app->event_seq == round->cursor) refresh_session_events_readings(state->app, round);
    refresh_diagnostics_readings_v1(state->app, round);
    linux_unified_render_v1(state, round);
    if (status_node) json_node_free(status_node);
    if (settings_node) json_node_free(settings_node);
    if (protection_node) json_node_free(protection_node);
    if (home_node) json_node_free(home_node);
}

static gboolean linux_shell_tick_v1(gpointer data) {
    LinuxUnifiedV8 *state = data;
    LinuxShellReadings *round = &state->readings;
    if (round->closed) return G_SOURCE_REMOVE;
    const char *selected = active_router_id(state->app);
    gboolean busy = linux_async_busy_v16(state->app) || atomic_load_explicit(&controller_exit_pending, memory_order_acquire);
    if (round->active) {
        if (busy || round->generation != linux_shell_generation_v1(state->app) || g_strcmp0(round->selected, selected))
            linux_shell_cancel_v1(round);
        for (guint i = 0; i < G_N_ELEMENTS(round->jobs); i++)
            if (round->jobs[i] && !rv_http_ready_v16(round->jobs[i])) return G_SOURCE_CONTINUE;
        if (!round->discarded) linux_shell_deliver_v1(state);
        linux_shell_release_v1(round);
    }
    if (busy || g_get_monotonic_time() < round->refresh_after) return G_SOURCE_CONTINUE;
    round->active = TRUE;
    round->discarded = FALSE;
    round->selected = g_strdup(active_router_id(state->app));
    round->generation = linux_shell_generation_v1(state->app);
    round->cursor = state->app->event_seq;
    round->cursor_path = g_strdup_printf("/api/session/events?after=%" G_GUINT64_FORMAT, round->cursor);
    const char *paths[] = {"/api/status", "/api/profile/settings", "/api/profile/protection", "/api/home-summary",
                           "/api/session", "/api/session/events?after=0", round->cursor ? round->cursor_path : NULL};
    const long timeouts[] = {1800, 3500, 3500, 5000, 1800, 1800, 2200};
    G_STATIC_ASSERT(G_N_ELEMENTS(paths) == G_N_ELEMENTS(round->jobs));
    for (guint i = 0; i < G_N_ELEMENTS(paths); i++) {
        round->paths[i] = paths[i];
        if (paths[i]) round->jobs[i] = rv_http_start_method_v17(paths[i], "", timeouts[i], "Refresh Router VPN", 1);
    }
    round->refresh_after = g_get_monotonic_time() + 1500 * G_TIME_SPAN_MILLISECOND;
    return G_SOURCE_CONTINUE;
}

static gboolean linux_unified_refresh_v8(gpointer data) {
    LinuxUnifiedV8 *state = data;
    if (!state || state->readings.closed) return G_SOURCE_REMOVE;
    if (state->readings.active) linux_shell_cancel_v1(&state->readings);
    state->readings.refresh_after = 0;
    return linux_shell_tick_v1(state);
}

static void linux_shell_request_v1(App *app) {
    LinuxUnifiedV8 *state = app && app->window ? g_object_get_data(G_OBJECT(app->window), "linux-unified-v8") : NULL;
    if (state) (void)linux_unified_refresh_v8(state);
}
