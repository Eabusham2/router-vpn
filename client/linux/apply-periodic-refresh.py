"""Give the final composed GTK renderers an explicit source of periodic replies."""

def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("GTK periodic refresh source changed: " + old[:90])
    return text.replace(old, new, 1)


def replace_function(text, original, rewrite):
    start = text.index(original)
    end = text.index("\n}\n", start) + 2
    return text[:start] + rewrite(text[start:end]) + text[end:]


def reader(text, signature, replacement, wrapper, calls):
    def change(body):
        if body.count("api_request(") != calls:
            raise ValueError("GTK periodic renderer changed its controller reads: " + signature)
        return once(body, signature, replacement).replace("api_request(", "linux_shell_read_v1(round, ") + wrapper
    return replace_function(text, signature, change)


def core(text):
    for name in ("refresh_status", "refresh_session_events"):
        signature = f"static void {name}(App *app) {{"
        snapshot = f"{name}_readings"
        text = reader(text, signature, f"static void {snapshot}(App *app, const LinuxShellReadings *round) {{",
                      f"\n\n{signature}\n    {snapshot}(app, NULL);\n}}", 1)
    text = once(text, "static void refresh_status_readings(", '#include "routervpn-shell-readings-v1.inc"\n\nstatic void refresh_status_readings(')
    return replace_function(text, "static gboolean refresh_timer(gpointer data) {",
                            lambda _: "static gboolean refresh_timer(gpointer data) {\n    linux_shell_request_v1(data);\n    return G_SOURCE_CONTINUE;\n}")


def unified(text):
    text = once(text, "} LinuxUnifiedV8;", "    LinuxShellReadings readings;\n} LinuxUnifiedV8;")
    text = reader(text, "static void linux_unified_refresh_protection_v21(LinuxUnifiedV8 *state) {",
                  "static void linux_unified_refresh_protection_v21(LinuxUnifiedV8 *state, const LinuxShellReadings *round) {", "", 1)
    text = once(text, "!linux_protection_mutation_busy_v26(state->app, !enabled)",
                "!linux_protection_readings_busy_v1(state->app, !enabled, round)")
    text = once(text, "static void linux_unified_refresh_protection_v21(", "static gboolean linux_protection_readings_busy_v1(App *, gboolean, const LinuxShellReadings *);\n\nstatic void linux_unified_refresh_protection_v21(")
    signature = "static gboolean linux_protection_mutation_busy_v26(App *app, gboolean enabled) {"
    text = reader(text, signature, "static gboolean linux_protection_readings_busy_v1(App *app, gboolean enabled, const LinuxShellReadings *round) {",
                  "\n\n" + signature + "\n    return linux_protection_readings_busy_v1(app, enabled, NULL);\n}", 1)
    text = once(text, "if(enabled)return routervpn_mutation_busy(app);",
                "if(enabled && round==NULL)return routervpn_mutation_busy(app);")
    text = once(text, "(void)linux_stop_retry_token_v26(obj,&valid);",
                "(void)linux_stop_retry_token_v26(obj,&valid);\n            if(enabled){gboolean blocked=!valid || routervpn_mutation_busy_from_status(obj) || g_object_get_data(G_OBJECT(app->window),\"linux-ordered-candidates-pending\")!=NULL;json_node_free(root);g_free(err);free(out.data);return blocked;}")
    signature = "static gboolean linux_unified_refresh_v8(gpointer data) {"
    text = reader(text, signature, "static gboolean linux_unified_render_v1(gpointer data, const LinuxShellReadings *round) {", "", 2)
    text = once(text, "linux_unified_refresh_protection_v21(state);", "linux_unified_refresh_protection_v21(state,round);")
    text = once(text, "state->syncing=FALSE;refresh_home_summary_v6(state->app);", "state->syncing=FALSE;refresh_home_summary_readings_v1(state->app,round);")
    text = once(text, "static GtkWidget *linux_unified_row_v8(", '#include "routervpn-shell-poll-v1.inc"\n\nstatic GtkWidget *linux_unified_row_v8(')
    text = once(text, 'g_timeout_add(1500,linux_unified_refresh_v8,state);',
                'g_signal_connect(app->window,"destroy",G_CALLBACK(linux_shell_destroy_v1),state);state->readings.timer=g_timeout_add(100,linux_shell_tick_v1,state);')
    return text


def diagnostics(text):
    signature = "static gboolean refresh_diagnostics_page_v5(gpointer data) {"
    text = reader(text, signature, "static gboolean refresh_diagnostics_readings_v1(gpointer data, const LinuxShellReadings *round) {",
                  "\n\n" + signature + "\n    linux_shell_request_v1(data);\n    return G_SOURCE_CONTINUE;\n}", 3)
    text = once(text, "    (void)g_timeout_add_seconds(2, refresh_timer, &app);\n", "")
    return once(text, "    (void)g_timeout_add_seconds(2, refresh_diagnostics_page_v5, &app);\n", "")
