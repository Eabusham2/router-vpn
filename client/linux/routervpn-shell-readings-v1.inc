/* Periodic rendering consumes only completed, retained GETs. Explicit actions
 * still obtain fresh authorization from the controller through api_request. */
typedef struct {
    const char *paths[7];
    RVHttpJobV16 *jobs[7];
    char *cursor_path, *selected;
    guint64 generation, cursor;
    gboolean active, discarded, closed;
    gint64 refresh_after;
    guint timer;
} LinuxShellReadings;

static gboolean linux_shell_read_v1(const LinuxShellReadings *round, const char *path, const char *method,
                                     const char *body, long timeout, Buffer *out, char **error) {
    if (round == NULL) return api_request(path, method, body, timeout, out, error);
    memset(out, 0, sizeof(*out));
    if (error) *error = NULL;
    for (guint i = 0; i < G_N_ELEMENTS(round->paths); i++) {
        if (g_strcmp0(path, round->paths[i]) != 0) continue;
        RVHttpJobV16 *job = round->jobs[i];
        if (job && rv_http_ready_v16(job) && !atomic_load(&job->cancelled) && job->result == CURLE_OK &&
            job->status >= 200 && job->status < 300 && job->response && !strcmp(method, "GET") && !body) {
            out->data = strdup(job->response);
            if (out->data) { out->len = job->length; return TRUE; }
        }
        break;
    }
    if (error) *error = g_strdup("Controller read unavailable");
    return FALSE;
}

static void linux_shell_request_v1(App *app);
