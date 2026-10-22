#!/usr/bin/env python3
"""Drive the production GTK candidates include with real widgets and HTTP workers.

The fixture owns only numeric loopback and must acquire the controller port. No
VPN or saved node store is opened. Native callback/receipt code is unchanged;
adapters provide only the surrounding app widgets and logging/mutation owner.
"""
from __future__ import annotations

import datetime
import http.server
import json
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "client/linux/routervpn-via-entry-candidates-v1.inc"
HARNESS = r'''
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>

typedef struct { GtkWidget *window; } App;
typedef struct { char *id, *name; double latitude, longitude, latency_ms; gboolean has_coordinates; } LinuxMultihopNodeV7;
typedef struct { App *app; GtkWidget *dialog, *map, *entry, *exit, *mode, *summary; GPtrArray *nodes; int pick_role; } LinuxMultihopDialogV7;
typedef struct { guint auxiliary_jobs; void (*changed)(App *app); } LinuxAsyncActionsV16;
static LinuxAsyncActionsV16 owner = {0};
static LinuxAsyncActionsV16 *linux_async_ensure_v16(App *app) { (void)app; return &owner; }
static gboolean routervpn_require_mutation_idle(App *app, const char *action) { (void)app; (void)action; return owner.auxiliary_jobs == 0; }
static void append_diag(App *app, const char *text) { (void)app; (void)text; }
static JsonNode *parse_json(const char *text) {
    if (text == NULL) return NULL;
    JsonParser *parser = json_parser_new(); GError *error = NULL; JsonNode *root = NULL;
    if (json_parser_load_from_data(parser, text, -1, &error)) root = json_node_copy(json_parser_get_root(parser));
    g_clear_error(&error); g_object_unref(parser); return root;
}
static GtkWidget *make_button(const char *label, GCallback callback, gpointer data) {
    GtkWidget *button = gtk_button_new_with_label(label); g_signal_connect(button, "clicked", callback, data); return button;
}
static LinuxMultihopNodeV7 *linux_multihop_find_v7(LinuxMultihopDialogV7 *parent, const char *id) {
    for (guint i = 0; i < parent->nodes->len; i++) { LinuxMultihopNodeV7 *n = g_ptr_array_index(parent->nodes, i); if (g_strcmp0(id, n->id) == 0) return n; }
    return NULL;
}
static void linux_multihop_update_summary_v7(LinuxMultihopDialogV7 *parent, const char *text) { gtk_label_set_text(GTK_LABEL(parent->summary), text != NULL ? text : ""); }
#include "routervpn-via-entry-candidates-v1.inc"

static const char *scenario;
static LinuxMultihopDialogV7 parent;
static gint64 started;
static int phase, beats;
static char *old_nonce;
static gboolean main_destroyed, parent_responded;
static void check(gboolean value, const char *message) { if (!value) g_error("candidate UI assertion: %s", message); }
static gboolean rejected_case(void) { return strcmp(scenario, "expired") == 0 || strcmp(scenario, "wrong_id") == 0 || strcmp(scenario, "undrained") == 0 || strcmp(scenario, "wrong_mode") == 0 || strcmp(scenario, "missing") == 0 || strcmp(scenario, "malformed") == 0; }
static gboolean invalid_selection_case(void) { return strcmp(scenario, "stale_validate") == 0 || strcmp(scenario, "stale_base") == 0 || strcmp(scenario, "stale_mode") == 0 || strcmp(scenario, "conflict") == 0; }
static void check_rows(LinuxCandidatesV1 *s) {
    check(gtk_tree_model_iter_n_children(GTK_TREE_MODEL(s->rows), NULL) == 3, "candidate rows were lost");
    check(g_hash_table_size(s->eligible) == 2, "failed row became eligible");
    GtkTreeIter iter; gboolean row = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(s->rows), &iter), found = FALSE;
    while (row) {
        char *id = NULL, *text = NULL; gboolean eligible; double median;
        gtk_tree_model_get(GTK_TREE_MODEL(s->rows), &iter, LINUX_CANDIDATE_ID_V1, &id, LINUX_CANDIDATE_TEXT_V1, &text, LINUX_CANDIDATE_ELIGIBLE_V1, &eligible, LINUX_CANDIDATE_MEDIAN_V1, &median, -1);
        if (strcmp(id, "failed") == 0) { found = TRUE; check(!eligible && median == 0 && strstr(text, "unavailable") != NULL && strstr(text, "TCP response") == NULL, "failure was fabricated into a latency"); }
        if (strcmp(id, "best") == 0) check(eligible && fabs(median - 7.25) < .0001 && strstr(text, "via Entry · TCP response") != NULL, "missing routed response label or median");
        g_free(id); g_free(text); row = gtk_tree_model_iter_next(GTK_TREE_MODEL(s->rows), &iter);
    }
    check(found, "failed candidate disappeared");
    check(strstr(gtk_label_get_text(GTK_LABEL(s->heading)), strcmp(scenario, "awg_strong") == 0 ? "AmneziaWG Strong entry" : strcmp(scenario, "awg") == 0 ? "AmneziaWG Fast entry" : "WireGuard entry") != NULL, "wrong captured entry base label");
}
static gboolean drive(gpointer data) {
    (void)data; beats++;
    check(g_get_monotonic_time() - started < 12000000, "UI/cancellation deadline exceeded");
    LinuxCandidatesV1 *s = g_object_get_data(G_OBJECT(parent.dialog), "linux-via-entry-candidates-v1");
    if (s == NULL) return G_SOURCE_CONTINUE;
    check(owner.auxiliary_jobs == 1, "candidate dialog did not own mutation reservation");
    if (strcmp(scenario, "all_failed") == 0 && s->receipt) {
        check(gtk_tree_model_iter_n_children(GTK_TREE_MODEL(s->rows), NULL) == 3 && g_hash_table_size(s->eligible) == 0, "all-failed response lost rows or fabricated success");
        check(!gtk_widget_get_sensitive(s->fastest) && !gtk_widget_get_sensitive(s->select), "all-failed response allowed measured selection");
        phase = 2; linux_candidates_close_v1(NULL, s); return G_SOURCE_CONTINUE;
    }
    if (rejected_case()) {
        check(!s->receipt, "invalid or undrained receipt published");
        if (s->request_id == NULL && !s->cancelled && s->last_error != NULL) {
            check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(parent.exit)), "slow") == 0, "invalid receipt changed selection");
            check(gtk_widget_get_sensitive(s->retest), "confirmed cleanup did not enable Retest");
            phase = 2; linux_candidates_close_v1(NULL, s);
        }
        return G_SOURCE_CONTINUE;
    }
    if (strcmp(scenario, "cancel_retest") == 0 && phase == 0 && s->job != NULL && beats > 3) {
        old_nonce = g_strdup(s->request_id); gtk_button_clicked(GTK_BUTTON(s->cancel)); phase = 1;
        check(!gtk_widget_get_sensitive(s->retest) && !s->receipt, "pending cancel allowed Retest/adoption");
        return G_SOURCE_CONTINUE;
    }
    if (strcmp(scenario, "cancel_retest") == 0 && phase == 1 && s->request_id == NULL && !s->cancelled) {
        check(gtk_widget_get_sensitive(s->retest), "Cancel did not enable Retest after acknowledgement");
        gtk_button_clicked(GTK_BUTTON(s->retest));
        check(s->request_id != NULL && strcmp(s->request_id, old_nonce) != 0, "Retest reused old request identity");
        phase = 2; return G_SOURCE_CONTINUE;
    }
    if (strcmp(scenario, "entry_change") == 0 && phase == 0 && s->job != NULL && beats > 3) {
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(parent.entry), "best"); phase = 2; return G_SOURCE_CONTINUE;
    }
    if (strncmp(scenario, "close_", 6) == 0 && phase == 0 && s->job != NULL && beats > 3) {
        GtkWidget *target = strcmp(scenario, "close_main") == 0 ? parent.app->window : strcmp(scenario, "close_parent") == 0 ? parent.dialog : s->dialog;
        if (target == s->dialog) gtk_window_close(GTK_WINDOW(target));
        else {
            /* A modal grab suppresses window-manager close delivery to an
             * insensitive owner. Emit the owner's actual delete-event signal
             * to exercise application shutdown after an external close intent. */
            GdkEvent *event = gdk_event_new(GDK_DELETE); gboolean handled = FALSE;
            g_signal_emit_by_name(target, "delete-event", event, &handled); gdk_event_free(event);
            check(handled, "owner close did not wait for native cleanup");
        }
        phase = 2; return G_SOURCE_CONTINUE;
    }
    if (strcmp(scenario, "entry_change") == 0 || strncmp(scenario, "close_", 6) == 0) {
        check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(parent.exit)), "slow") == 0, "closed/reselected operation adopted a late result");
        return G_SOURCE_CONTINUE;
    }
    if (invalid_selection_case() && phase == 1) {
        check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(parent.exit)), "slow") == 0, "stale validation adopted exit");
        if (s->request_id == NULL && !s->cancelled && s->last_error != NULL) { phase = 2; linux_candidates_close_v1(NULL, s); }
        return G_SOURCE_CONTINUE;
    }
    if (strcmp(scenario, "cancel_retry") == 0 && phase == 1 && s->cancelled && s->cancel_job == NULL && !s->cancel_ack) {
        check(!gtk_widget_get_sensitive(s->retest) && gtk_widget_get_sensitive(s->cancel), "unacknowledged cleanup released reservation");
        gtk_button_clicked(GTK_BUTTON(s->cancel)); phase = 2; return G_SOURCE_CONTINUE;
    }
    if (s->receipt && ((strcmp(scenario, "cancel_retest") == 0 && phase == 2) || phase == 0)) {
        check_rows(s);
        check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(parent.exit)), "slow") == 0, "measurement selected or connected automatically");
        check(gtk_widget_get_sensitive(s->fastest), "eligible fastest action is disabled");
        gtk_button_clicked(GTK_BUTTON(s->fastest));
        check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(parent.exit)), "slow") == 0, "selection changed before validation returned");
        phase = strcmp(scenario, "cancel_retest") == 0 ? 3 : 1;
    }
    return G_SOURCE_CONTINUE;
}
static void main_destroy(GtkWidget *widget, gpointer data) { (void)widget; (void)data; main_destroyed = TRUE; }
static void parent_response(GtkDialog *dialog, gint response, gpointer data) { (void)dialog; (void)response; (void)data; parent_responded = TRUE; }
int main(int argc, char **argv) {
    gtk_init(&argc, &argv); curl_global_init(CURL_GLOBAL_DEFAULT);
    check(argc == 2, "missing scenario"); scenario = argv[1];
    App app = {gtk_window_new(GTK_WINDOW_TOPLEVEL)}; g_object_ref_sink(app.window);
    parent.app = &app; parent.dialog = gtk_dialog_new(); g_object_ref_sink(parent.dialog);
    parent.entry = gtk_combo_box_text_new(); parent.exit = gtk_combo_box_text_new(); parent.summary = gtk_label_new(""); parent.nodes = g_ptr_array_new_with_free_func(g_free);
    const char *ids[] = {"entry", "slow", "best", "failed"}; const char *names[] = {"Entry", "Slow", "Best", "Failed"};
    for (guint i = 0; i < G_N_ELEMENTS(ids); i++) {
        LinuxMultihopNodeV7 *node = g_new0(LinuxMultihopNodeV7, 1); node->id = (char *)ids[i]; node->name = (char *)names[i]; node->latency_ms = 1000 + i;
        g_ptr_array_add(parent.nodes, node); gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(parent.entry), ids[i], names[i]); gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(parent.exit), ids[i], names[i]);
    }
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(parent.entry), "entry"); gtk_combo_box_set_active_id(GTK_COMBO_BOX(parent.exit), "slow");
    linux_candidates_bind_entry_v1(&parent);
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(parent.entry), "slow");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(parent.entry), "entry");
    check(owner.auxiliary_jobs == 0 && g_object_get_data(G_OBJECT(parent.dialog), "linux-via-entry-candidates-v1") == NULL, "programmatic refresh opened a measurement lane");
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(parent.dialog)); gtk_container_add(GTK_CONTAINER(box), parent.entry); gtk_container_add(GTK_CONTAINER(box), parent.exit); gtk_container_add(GTK_CONTAINER(box), parent.summary);
    g_signal_connect(app.window, "destroy", G_CALLBACK(main_destroy), NULL); g_signal_connect(parent.dialog, "response", G_CALLBACK(parent_response), NULL);
    gtk_widget_show_all(app.window); gtk_widget_show_all(parent.dialog); started = g_get_monotonic_time(); guint driver = g_timeout_add(20, drive, NULL);
    if (strcmp(scenario, "picker") == 0) {
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(parent.entry), "slow");
        GdkEvent *event = gdk_event_new(GDK_KEY_PRESS); event->key.keyval = GDK_KEY_Down;
        event->key.window = g_object_ref(gtk_widget_get_window(parent.entry)); event->key.send_event = TRUE;
        gboolean handled = FALSE;
        g_signal_emit_by_name(parent.entry, "key-press-event", event, &handled);
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(parent.entry), "entry");
        event->type = GDK_KEY_RELEASE; g_signal_emit_by_name(parent.entry, "key-release-event", event, &handled); gdk_event_free(event);
    } else on_linux_candidates_v1(NULL, &parent);
    while (g_main_context_iteration(NULL, FALSE)) {}
    g_source_remove(driver); check(owner.auxiliary_jobs == 0, "mutation reservation leaked after drain");
    check(beats >= 5, "UI heartbeat did not run during HTTP request");
    gboolean chosen = strcmp(scenario, "success") == 0 || strcmp(scenario, "awg") == 0 || strcmp(scenario, "awg_strong") == 0 || strcmp(scenario, "picker") == 0 || strcmp(scenario, "cancel_retest") == 0 || strcmp(scenario, "cancel_retry") == 0;
    check(strcmp(gtk_combo_box_get_active_id(GTK_COMBO_BOX(parent.exit)), chosen ? "best" : "slow") == 0, "final selected exit mismatch");
    for (guint i = 0; i < parent.nodes->len; i++) { LinuxMultihopNodeV7 *node = g_ptr_array_index(parent.nodes, i); check(node->latency_ms == 1000 + i, "routed measurement overwrote direct latency cache"); }
    check(main_destroyed == (strcmp(scenario, "close_main") == 0), "main close ownership was not preserved");
    check(parent_responded == (strcmp(scenario, "close_parent") == 0 || strcmp(scenario, "close_main") == 0), "parent close ownership was not preserved");
    gtk_widget_destroy(parent.dialog); g_object_unref(parent.dialog); if (!main_destroyed) gtk_widget_destroy(app.window); g_object_unref(app.window);
    g_ptr_array_unref(parent.nodes); g_free(old_nonce); curl_global_cleanup();
    printf("GTK routed candidate UI %s: PASS (%d responsive ticks)\n", scenario, beats); return 0;
}
'''


def main() -> int:
    for tool in ("gcc", "pkg-config", "xvfb-run"):
        if not shutil.which(tool):
            raise SystemExit(f"candidate UI tests require {tool}")
    state = {"case": "", "requests": [], "errors": [], "measure": 0, "cancel": 0, "nonces": set(), "cancelled": set()}
    lock = threading.Lock()

    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def reply(self, value, status=200):
            data = json.dumps(value).encode()
            self.close_connection = True
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def wait(self, seconds):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                try:
                    if select.select([self.connection], [], [], .02)[0] and not self.connection.recv(1, socket.MSG_PEEK):
                        return False
                except (ConnectionResetError, OSError):
                    return False
            return True

        def do_POST(self):
            self.connection.settimeout(3)
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length < 32768:
                    raise ValueError("bad request size")
                body = json.loads(self.rfile.read(length))
                nonce = body["request_id"]
                if not re.fullmatch("[0-9a-f]{32}", nonce):
                    raise ValueError("invalid nonce")
            except Exception as error:
                with lock:
                    state["errors"].append(str(error))
                self.reply({"error": "invalid request"}, 400)
                return
            with lock:
                scenario = state["case"]
                state["requests"].append((self.path, body))
            if self.path == "/api/multihop/candidates":
                if body != {"request_id": nonce, "entry_id": "entry", "base": "auto", "candidate_ids": ["slow", "best", "failed"], "samples": 5}:
                    with lock:
                        state["errors"].append(("uncaptured request", body))
                with lock:
                    state["measure"] += 1
                    index = state["measure"]
                    if nonce in state["nonces"] or nonce in state["cancelled"]:
                        state["errors"].append("measurement nonce reused")
                    state["nonces"].add(nonce)
                delayed = scenario in {"entry_change", "close_dialog", "close_main", "close_parent"} or (scenario == "cancel_retest" and index == 1)
                if not self.wait(.8 if delayed else .18):
                    return
                now = datetime.datetime.now(datetime.timezone.utc)
                response = {"schema": 1, "request_id": nonce, "entry_id": "entry", "entry_base": "awg" if scenario in {"awg", "awg_strong"} else "wg", "entry_mode": "awg2-strong" if scenario == "awg_strong" else "awg2-fast" if scenario == "awg" else "wg", "drained": True,
                            "measured_at": now.isoformat(), "expires_at": (now + datetime.timedelta(seconds=120)).isoformat(),
                            "results": [{"id": "slow", "samples": 5, "failed": 0, "median_ms": 20.5},
                                        {"id": "best", "samples": 5, "failed": 0, "median_ms": 7.25},
                                        {"id": "failed", "samples": 4, "failed": 1, "median_ms": 1}],
                            "errors": [{"id": "failed", "error": "candidate TCP timeout"}], "fastest_id": "best"}
                if scenario == "all_failed":
                    response["results"] = None
                    response["errors"] = [{"id": item, "error": "candidate TCP timeout"} for item in ("slow", "best", "failed")]
                    response["fastest_id"] = ""
                elif scenario == "expired":
                    response["expires_at"] = (now - datetime.timedelta(seconds=1)).isoformat()
                elif scenario == "wrong_id":
                    response["request_id"] = "0" * 32
                elif scenario == "undrained":
                    response["drained"] = False
                elif scenario == "wrong_mode":
                    response["entry_mode"] = "awg2-fast"
                elif scenario == "missing":
                    response["results"] = response["results"][1:]
                elif scenario == "malformed":
                    response["results"] = [{"id": "not-captured", "samples": 5, "failed": 0, "median_ms": 1}]
                self.reply(response)
            elif self.path == "/api/multihop/candidates/validate":
                if body != {"request_id": nonce, "entry_id": "entry", "exit_id": "best"}:
                    with lock:
                        state["errors"].append(("invalid validation", body))
                self.wait(.12)
                self.reply({"ok": True, "measured": True, "request_id": "0" * 32 if scenario == "stale_validate" else nonce,
                            "entry_id": "entry", "exit_id": "best", "entry_base": "awg" if scenario in {"awg", "awg_strong", "stale_base"} else "wg",
                            "entry_mode": "awg2-strong" if scenario == "awg_strong" else "awg2-fast" if scenario in {"awg", "stale_mode"} else "wg"}, 409 if scenario == "conflict" else 200)
            elif self.path == "/api/multihop/candidates/cancel":
                if body != {"request_id": nonce}:
                    with lock:
                        state["errors"].append(("invalid cancellation", body))
                with lock:
                    state["cancel"] += 1
                    index = state["cancel"]
                    state["cancelled"].add(nonce)
                self.wait(.13)
                self.reply({"ok": True, "drained": not (scenario == "cancel_retry" and index == 1), "request_id": nonce})
            else:
                with lock:
                    state["errors"].append(("unexpected endpoint", self.path))
                self.reply({"error": "unexpected endpoint"}, 404)

    try:
        server = Server(("127.0.0.1", 8788), Handler)
    except OSError as error:
        raise SystemExit(f"Refusing to use an occupied controller port: {error}") from error
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="routervpn-candidate-ui-") as directory:
            temp = Path(directory)
            harness = temp / "candidate-ui.c"
            harness.write_text(HARNESS)
            flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "gtk+-3.0", "json-glib-1.0", "libcurl"], text=True))
            binary = temp / "candidate-ui"
            command = ["gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-O1", f"-I{temp}", f"-I{SOURCE.parent}", str(harness), "-o", str(binary), *flags, "-lm"]
            subprocess.run(command, check=True)
            cases = ["success", "awg", "awg_strong", "all_failed", "picker", "cancel_retest", "cancel_retry", "stale_validate", "stale_base", "stale_mode", "conflict", "entry_change", "expired", "wrong_id", "undrained", "wrong_mode", "missing", "malformed", "close_dialog", "close_parent", "close_main"]
            env = os.environ.copy()
            env["G_DEBUG"] = "fatal-criticals"
            def run(case, *, mutation=False):
                with lock:
                    state.update(case=case, requests=[], errors=[], measure=0, cancel=0, nonces=set(), cancelled=set())
                result = subprocess.run(["xvfb-run", "-a", str(binary), case], text=True, capture_output=True, env=env, timeout=18)
                if mutation:
                    if result.returncode == 0:
                        raise AssertionError("candidate UI negative control passed")
                    print(f"GTK routed candidate mutation rejected: {case}")
                    return
                if result.returncode:
                    raise AssertionError(result.stdout + result.stderr)
                with lock:
                    if state["errors"]:
                        raise AssertionError(state["errors"])
                    if state["measure"] != (2 if case == "cancel_retest" else 1):
                        raise AssertionError(f"wrong measurement count: {state}")
                    if not state["cancel"]:
                        raise AssertionError("dialog released without explicit native cancellation acknowledgement")
                    if not state["nonces"].issubset(state["cancelled"]):
                        raise AssertionError("an owned nonce was left live")
                print(result.stdout.strip())
            for case in cases:
                run(case)
            original = SOURCE.read_text()
            mutations = [("stale_validate", 'else if (!linux_candidates_validated_v1(s, job->response))', 'else if (FALSE)'),
                         ("undrained", '&& linux_candidates_true_v1(top, "drained")', '&& TRUE')]
            for case, old, new in mutations:
                if original.count(old) != 1:
                    raise AssertionError("negative-control seam changed")
                (temp / SOURCE.name).write_text(original.replace(old, new, 1))
                # Keep the now-unused validator referenced in the intentionally
                # broken build so this control fails on behavior, not a warning.
                mutation_command = command.copy()
                mutation_command.insert(1, "-Wno-unused-function")
                subprocess.run(mutation_command, check=True)
                run(case, mutation=True)
            print("GTK routed candidate UI: PASS (21 real-widget/HTTP lifecycles; 2 behavioral mutations rejected)")
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
