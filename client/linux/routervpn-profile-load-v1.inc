/* Coordinated idle-only profile Load. The journal and its local settings are
 * changed in one private rename while a directory lock excludes other writers. */
static gboolean linux_load_hex(const char *value, gsize length) {
    return value && strlen(value) == length && strspn(value, "0123456789abcdef") == length;
}

static gboolean linux_load_revision(const char *value) {
    guint64 generation;
    return value && value[0] && (!value[1] || value[0] != '0') &&
           strspn(value, "0123456789") == strlen(value) &&
           g_ascii_string_to_unsigned(value, 10, 0, G_MAXUINT64, &generation, NULL);
}

static gboolean linux_load_boolean(JsonObject *obj, const char *field, gboolean *out) {
    JsonNode *n = obj ? json_object_get_member(obj, field) : NULL;
    if (!n || !JSON_NODE_HOLDS_VALUE(n) || json_node_get_value_type(n) != G_TYPE_BOOLEAN) return FALSE;
    *out = json_node_get_boolean(n); return TRUE;
}

static JsonNode *linux_load_call(const char *action, JsonObject *request, GError **error) {
    g_autofree char *body = linux_ordered_json_v1(request);
    g_autofree char *path = g_strconcat("/api/connection-profile/setup/load/", action, NULL);
    Buffer buf = {0}; char *reason = NULL;
    gboolean ok = api_request(path, "POST", body, 15000, &buf, &reason);
    JsonNode *reply = ok && buf.data ? parse_json(buf.data) : NULL;
    free(buf.data);
    if (!reply || !JSON_NODE_HOLDS_OBJECT(reply)) {
        if (reply) json_node_free(reply);
        linux_load_error(error, reason ? reason : "Could not verify the profile Load response. Reopen Profiles to recover.");
        reply = NULL;
    }
    g_free(reason); return reply;
}

static JsonObject *linux_load_receipt(JsonNode *reply, JsonObject *request, gboolean allow_absent, GError **error) {
    JsonObject *root = json_node_get_object(reply);
    JsonObject *tx = linux_ordered_object_v1(root, "transaction");
    const char *op = linux_ordered_string_v1(tx, "operation_id");
    const char *state = linux_ordered_string_v1(tx, "state");
    gboolean ok = FALSE, finished = FALSE;
    if (!linux_load_revision(linux_ordered_string_v1(root, "revision")) || !linux_load_boolean(root, "ok", &ok) || !ok || !linux_load_boolean(tx, "finished", &finished) ||
        !linux_load_hex(op, 32) || strcmp(op, linux_ordered_string_v1(request, "operation_id")) != 0) goto invalid;
    JsonNode *snapshot = json_object_get_member(root, "snapshot");
    if (!snapshot) goto invalid;
    if (!strcmp(state, "absent") && allow_absent && !finished && JSON_NODE_HOLDS_NULL(snapshot) &&
        !json_object_has_member(tx, "generation") && !json_object_has_member(tx, "receipt_sha256")) return tx;
    if (strcmp(state, "prepared") && strcmp(state, "committed") && strcmp(state, "aborted")) goto invalid;
    if (!strcmp(state, "prepared") && finished) goto invalid;
    if (!JSON_NODE_HOLDS_OBJECT(snapshot) && (strcmp(state, "aborted") || !JSON_NODE_HOLDS_NULL(snapshot))) goto invalid;
    const char *names[] = {"generation", "receipt_sha256"};
    for (guint i = 0; i < G_N_ELEMENTS(names); i++) {
        const char *value = linux_ordered_string_v1(tx, names[i]);
        if (!linux_load_hex(value, i ? 64 : 32) ||
            (json_object_has_member(request, names[i]) && strcmp(value, linux_ordered_string_v1(request, names[i])))) goto invalid;
    }
    return tx;
invalid:
    linux_load_error(error, "The controller did not confirm the captured profile Load owner.");
    return NULL;
}

static void linux_load_owner(JsonObject *request, JsonObject *tx) {
    json_object_set_string_member(request, "generation", linux_ordered_string_v1(tx, "generation"));
    json_object_set_string_member(request, "receipt_sha256", linux_ordered_string_v1(tx, "receipt_sha256"));
}

static gboolean linux_load_step(const char *action, JsonObject *owner, const char *state, gboolean finished, GError **error) {
    g_autoptr(JsonNode) response = linux_load_call(action, owner, error);
    if (!response) return FALSE;
    JsonObject *tx = linux_load_receipt(response, owner, FALSE, error);
    if (!tx) return FALSE;
    return (strcmp(linux_ordered_string_v1(tx, "state"), state) == 0 && linux_ordered_flag_v1(tx, "finished") == finished) ||
        linux_load_error(error, "The profile transaction did not reach its requested phase. Reopen Profiles to recover.");
}

static const char *const linux_load_keys[] = {
    "selected_mode", "multihop_execution", "enabled", "entry", "exit", "entry_mode", "exit_mode", "ordered_selection", "layers"
};

static const char *linux_load_group(guint i, const char *preset) {
    return i < 2 ? "state" : i < 8 ? "connection-profile-selection" : preset;
}

/* Raw GKeyFile values preserve escaped names, unknown legacy layers and the
 * distinction between an absent field and an empty field. */
static char *linux_load_projection(GKeyFile *key, const char *preset) {
    g_autoptr(JsonObject) p = json_object_new();
    for (guint i = 0; i < G_N_ELEMENTS(linux_load_keys); i++) {
        const char *group = linux_load_group(i, preset), *name = linux_load_keys[i];
        if (!group || !group[0]) continue;
        g_autofree char *value = g_key_file_get_value(key, group, name, NULL);
        if (value) json_object_set_string_member(p, name, value);
        if (g_key_file_has_group(key, group)) json_object_set_boolean_member(p, group, TRUE);
    }
    return linux_ordered_json_v1(p);
}

static gboolean linux_load_restore(LinuxLoadFile *file, GError **error) {
    g_autofree char *before = g_key_file_get_string(file->key, LINUX_LOAD_GROUP, "before", NULL);
    g_autofree char *after = g_key_file_get_string(file->key, LINUX_LOAD_GROUP, "after", NULL);
    g_autofree char *preset = g_key_file_get_string(file->key, LINUX_LOAD_GROUP, "preset_group", NULL);
    g_autofree char *current = linux_load_projection(file->key, preset);
    g_autoptr(JsonNode) old = before ? parse_json(before) : NULL;
    if (!old || !JSON_NODE_HOLDS_OBJECT(old) || g_strcmp0(after, current))
        return linux_load_error(error, "The staged choices changed. Recovery preserved the newer settings and kept Connect blocked.");
    JsonObject *p = json_node_get_object(old);
    for (guint i = 0; i < G_N_ELEMENTS(linux_load_keys); i++) {
        const char *group = linux_load_group(i, preset), *name = linux_load_keys[i];
        if (!group || !group[0]) continue;
        if (json_object_has_member(p, name)) g_key_file_set_value(file->key, group, name, linux_ordered_string_v1(p, name));
        else g_key_file_remove_key(file->key, group, name, NULL);
        if (!json_object_has_member(p, group)) {
            gsize count = 0; g_auto(GStrv) keys = g_key_file_get_keys(file->key, group, &count, NULL);
            if (!count) g_key_file_remove_group(file->key, group, NULL);
        }
    }
    return TRUE;
}

static gboolean linux_load_clear(LinuxLoadFile *file, const char *op, GError **error) {
    g_key_file_remove_group(file->key, LINUX_LOAD_GROUP, NULL);
    if (op) g_key_file_set_string(file->key, "state", LINUX_LOAD_REVISION, op);
    return linux_load_write(file, error);
}

static gboolean linux_load_recover(const char *expected_op, gboolean *was_committed, GError **error) {
    g_auto(LinuxLoadFile) file = {.directory = -1};
    if (!linux_load_open(&file, TRUE, error)) return FALSE;
    if (!g_key_file_has_group(file.key, LINUX_LOAD_GROUP)) return TRUE;
    g_autofree char *op = g_key_file_get_string(file.key, LINUX_LOAD_GROUP, "operation_id", NULL);
    g_autofree char *phase = g_key_file_get_string(file.key, LINUX_LOAD_GROUP, "phase", NULL);
    if (!linux_load_hex(op, 32) || !phase) return linux_load_error(error, "The local recovery record has no valid owner.");
    if (expected_op && strcmp(expected_op, op)) return linux_load_error(error, "A newer profile Load owns the current recovery record.");
    gboolean sending = !strcmp(phase, "preparing_sent");
    gboolean preparing = !strcmp(phase, "preparing") || sending, staged = !strcmp(phase, "staged");
    gboolean complete = !strcmp(phase, "complete"), rolled = !strcmp(phase, "rolled_back");
    if (!preparing && !staged && !complete && !rolled) return linux_load_error(error, "The local recovery phase is invalid.");
    g_autoptr(JsonObject) owner = json_object_new();
    json_object_set_string_member(owner, "operation_id", op);
    if (!preparing) {
        g_autofree char *gen = g_key_file_get_string(file.key, LINUX_LOAD_GROUP, "generation", NULL);
        g_autofree char *sha = g_key_file_get_string(file.key, LINUX_LOAD_GROUP, "receipt_sha256", NULL);
        if (!linux_load_hex(gen, 32) || !linux_load_hex(sha, 64)) return linux_load_error(error, "The local recovery receipt is invalid.");
        json_object_set_string_member(owner, "generation", gen); json_object_set_string_member(owner, "receipt_sha256", sha);
    }
    g_autoptr(JsonNode) reply = linux_load_call("status", owner, error);
    if (!reply) return FALSE;
    JsonObject *tx = linux_load_receipt(reply, owner, TRUE, error);
    if (!tx) return FALSE;
    const char *state = linux_ordered_string_v1(tx, "state");
    if (!strcmp(state, "absent") && sending) {
        g_autofree char *raw = g_key_file_get_string(file.key, LINUX_LOAD_GROUP, "request", NULL);
        g_autoptr(JsonNode) original = raw ? parse_json(raw) : NULL;
        if (!original || !JSON_NODE_HOLDS_OBJECT(original) || strcmp(linux_ordered_string_v1(json_node_get_object(original), "operation_id"), op))
            return linux_load_error(error, "The pending profile request lost its original recovery capture.");
        const char *revision = linux_ordered_string_v1(json_node_get_object(original), "expected_revision");
        if (!linux_load_revision(revision)) return linux_load_error(error, "The pending profile Load has no original controller revision.");
        g_autoptr(JsonObject) cancellation = json_object_new();
        json_object_set_string_member(cancellation, "operation_id", op);
        json_object_set_string_member(cancellation, "expected_revision", revision);
        g_clear_pointer(&reply, json_node_free);
        reply = linux_load_call("cancel", cancellation, error);
        if (!reply) return FALSE;
        JsonObject *env = json_node_get_object(reply);
        tx = linux_ordered_object_v1(env, "transaction");
        if (!strcmp(linux_ordered_string_v1(tx, "state"), "superseded")) {
            gboolean ok = FALSE, finished = FALSE;
            if (!linux_load_boolean(env, "ok", &ok) || !ok || !linux_load_boolean(tx, "finished", &finished) || !finished ||
                !linux_load_revision(linux_ordered_string_v1(env, "revision")) || !strcmp(revision, linux_ordered_string_v1(env, "revision")) ||
                strcmp(op, linux_ordered_string_v1(tx, "operation_id")) || !json_object_has_member(env, "snapshot") ||
                !JSON_NODE_HOLDS_NULL(json_object_get_member(env, "snapshot")) || json_object_has_member(tx, "generation") ||
                json_object_has_member(tx, "receipt_sha256"))
                return linux_load_error(error, "The cancelled profile Load has no verified superseding revision.");
            return linux_load_clear(&file, NULL, error);
        }
        tx = linux_load_receipt(reply, owner, FALSE, error);
        if (!tx) return FALSE;
        state = linux_ordered_string_v1(tx, "state");
    }
    if (!strcmp(state, "absent")) {
        if (staged) return linux_load_error(error, "The controller no longer owns this staged Load. The local settings were preserved.");
        /* The terminal receipt may have been superseded. Remove only this
         * journal; do not project its choices or replace the newer revision. */
        if (was_committed) *was_committed = FALSE;
        return linux_load_clear(&file, NULL, error);
    }
    linux_load_owner(owner, tx);
    if (!strcmp(state, "committed")) {
        if (!staged && !complete) return linux_load_error(error, "The committed profile does not match the local recovery phase.");
        if (staged) {
            g_autofree char *preset = g_key_file_get_string(file.key, LINUX_LOAD_GROUP, "preset_group", NULL);
            g_autofree char *after = g_key_file_get_string(file.key, LINUX_LOAD_GROUP, "after", NULL);
            g_autofree char *current = linux_load_projection(file.key, preset);
            if (g_strcmp0(after, current)) return linux_load_error(error, "The committed profile differs from local settings. Recovery preserved the current choices.");
            g_key_file_set_string(file.key, LINUX_LOAD_GROUP, "phase", "complete");
            if (!linux_load_write(&file, error)) return FALSE;
        }
    } else {
        if (complete || (!strcmp(state, "aborted") && !rolled && !preparing))
            return linux_load_error(error, "The controller and local recovery phases disagree.");
        if (!rolled) {
            if (staged && !linux_load_restore(&file, error)) return FALSE;
            g_key_file_set_string(file.key, LINUX_LOAD_GROUP, "generation", linux_ordered_string_v1(tx, "generation"));
            g_key_file_set_string(file.key, LINUX_LOAD_GROUP, "receipt_sha256", linux_ordered_string_v1(tx, "receipt_sha256"));
            g_key_file_set_string(file.key, LINUX_LOAD_GROUP, "phase", "rolled_back");
            if (!linux_load_write(&file, error)) return FALSE;
        }
        if (!strcmp(state, "prepared") && !linux_load_step("abort", owner, "aborted", FALSE, error)) return FALSE;
        state = "aborted";
    }
    if (was_committed) *was_committed = !strcmp(state, "committed");
    if (!linux_ordered_flag_v1(tx, "finished") && !linux_load_step("finish", owner, state, TRUE, error)) return FALSE;
    return linux_load_clear(&file, op, error);
}

static gboolean linux_load_stage(LinuxLoadFile *file, JsonObject *owner, JsonObject *request, JsonObject *snapshot, GError **error) {
    const char *mode = linux_ordered_string_v1(snapshot, "mode");
    const char *control = linux_ordered_string_v1(snapshot, "selected_node_id");
    JsonObject *profile = linux_ordered_object_v1(snapshot, "profile");
    JsonObject *tokens = linux_ordered_object_v1(snapshot, "profile_tokens");
    gboolean enabled = FALSE, ok = FALSE;
    if (!snapshot || !linux_load_boolean(snapshot, "ok", &ok) || !ok || !mode[0] || !control[0] || !tokens ||
        strcmp(linux_ordered_string_v1(profile, "id"), linux_ordered_string_v1(request, "id")) ||
        strcmp(mode, linux_ordered_string_v1(request, "expected_mode")) ||
        strcmp(mode, linux_ordered_string_v1(profile, "mode")) || strcmp(control, linux_ordered_string_v1(profile, "node_id")) ||
        !linux_load_hex(linux_ordered_string_v1(tokens, control), 64) ||
        !linux_load_boolean(snapshot, "multihop_enabled", &enabled))
        return linux_load_error(error, "The prepared profile did not confirm the saved node, mode and source.");
    g_autofree char *preset = g_str_has_prefix(mode, "custom:") ? g_strconcat("preset:", mode + 7, NULL) : NULL;
    g_autofree char *before = linux_load_projection(file->key, preset);
    if (!linux_profile_stage_custom_v11(file->key, mode, linux_ordered_array_v1(snapshot, "custom_layers"), error)) return FALSE;
    g_key_file_set_string(file->key, "state", "selected_mode", mode);
    const char *execution = linux_ordered_string_v1(snapshot, "multihop_execution");
    if (!linux_multihop_execution_supported_v22(execution)) return linux_load_error(error, "The prepared profile has an invalid execution choice.");
    g_key_file_set_string(file->key, "state", "multihop_execution", execution);
    const char *group = "connection-profile-selection";
    g_key_file_set_boolean(file->key, group, "enabled", enabled);
    JsonNode *nodes = json_object_get_member(snapshot, "multihop_nodes");
    if (nodes && JSON_NODE_HOLDS_ARRAY(nodes) && !json_array_get_length(json_node_get_array(nodes)))
        return linux_load_error(error, "The prepared profile declares an empty ordered path.");
    gboolean ordered = linux_ordered_response_present_v1(snapshot);
    if (ordered) {
        LinuxOrderedSelectionV1 *selection = linux_ordered_response_v1(snapshot);
        if (!selection) return linux_load_error(error, "The prepared ordered profile has incomplete source receipts.");
        g_autoptr(JsonObject) value = linux_ordered_value_v1(selection);
        g_autofree char *graph = linux_ordered_json_v1(value);
        linux_ordered_selection_free_v1(selection);
        g_key_file_set_string(file->key, group, "ordered_selection", graph);
    } else {
        const char *entry = linux_ordered_string_v1(snapshot, "multihop_entry_id");
        const char *exit = linux_ordered_string_v1(snapshot, "multihop_exit_id");
        if (enabled && (!entry[0] || !exit[0] || !strcmp(entry, exit) ||
            !linux_load_hex(linux_ordered_string_v1(tokens, entry), 64) || !linux_load_hex(linux_ordered_string_v1(tokens, exit), 64)))
            return linux_load_error(error, "The prepared pair has incomplete source receipts.");
        guint expected = 1 + (enabled && strcmp(control, entry) != 0) + (enabled && strcmp(control, exit) != 0);
        if (json_object_get_size(tokens) != expected) return linux_load_error(error, "The prepared source inventory contains a different node.");
        g_key_file_remove_key(file->key, group, "ordered_selection", NULL);
    }
    const char *fields[] = {"entry", "exit", "entry_mode", "exit_mode"};
    for (guint i = 0; i < G_N_ELEMENTS(fields); i++) {
        g_autofree char *name = g_strconcat("multihop_", i == 0 ? "entry_id" : i == 1 ? "exit_id" : fields[i], NULL);
        const char *value = !ordered && enabled ? linux_ordered_string_v1(snapshot, name) : (!enabled && i == 3 ? "shadowsocks" : "");
        g_key_file_set_string(file->key, group, fields[i], value);
    }
    g_autofree char *after = linux_load_projection(file->key, preset);
    g_key_file_set_string(file->key, LINUX_LOAD_GROUP, "phase", "staged");
    g_key_file_set_string(file->key, LINUX_LOAD_GROUP, "generation", linux_ordered_string_v1(owner, "generation"));
    g_key_file_set_string(file->key, LINUX_LOAD_GROUP, "receipt_sha256", linux_ordered_string_v1(owner, "receipt_sha256"));
    g_key_file_set_string(file->key, LINUX_LOAD_GROUP, "preset_group", preset ? preset : "");
    g_key_file_set_string(file->key, LINUX_LOAD_GROUP, "before", before);
    g_key_file_set_string(file->key, LINUX_LOAD_GROUP, "after", after);
    return linux_load_write(file, error);
}

static gboolean linux_load_attempt(LinuxUnifiedV8 *ui, const char *body, guint64 generation, char **snapshot_text, char **captured_op, gboolean *committed, GError **error) {
    g_autoptr(JsonNode) capture = parse_json(body);
    if (!capture || !JSON_NODE_HOLDS_OBJECT(capture)) return linux_load_error(error, "The captured profile request is invalid.");
    JsonObject *request = json_node_get_object(capture);
    g_auto(LinuxLoadFile) file = {.directory = -1};
    if (!linux_load_open(&file, FALSE, error)) return FALSE;
    guint8 random[16]; gsize offset = 0;
    while (offset < sizeof(random)) {
        ssize_t count = getrandom(random + offset, sizeof(random) - offset, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return linux_load_error(error, "Cannot create a profile Load owner.");
        offset += (gsize)count;
    }
    char op[33];
    for (guint i = 0; i < sizeof(random); i++) g_snprintf(op + 2 * i, 3, "%02x", random[i]);
    *captured_op = g_strdup(op);
    g_autoptr(JsonObject) owner = json_object_new();
    json_object_set_string_member(owner, "operation_id", op);
    g_autoptr(JsonNode) initial = linux_load_call("status", owner, error);
    if (!initial) return FALSE;
    JsonObject *unowned = linux_load_receipt(initial, owner, TRUE, error);
    if (!unowned) return FALSE;
    if (strcmp(linux_ordered_string_v1(unowned, "state"), "absent")) return linux_load_error(error, "The new profile Load owner has already been used.");
    const char *revision = linux_ordered_string_v1(json_node_get_object(initial), "revision");
    json_object_set_string_member(request, "operation_id", op);
    json_object_set_string_member(request, "expected_revision", revision);
    g_key_file_set_string(file.key, LINUX_LOAD_GROUP, "operation_id", op);
    g_autofree char *original_request = linux_ordered_json_v1(request);
    g_key_file_set_string(file.key, LINUX_LOAD_GROUP, "request", original_request);
    /* Sending is durable before the first byte of the POST. Recovery must
     * cancel or settle this exact owner/revision even if status says absent. */
    g_key_file_set_string(file.key, LINUX_LOAD_GROUP, "phase", "preparing_sent");
    if (!linux_load_write(&file, error)) return FALSE;
    g_autoptr(JsonNode) prepared = linux_load_call("prepare", request, error);
    if (!prepared) return FALSE;
    JsonObject *tx = linux_load_receipt(prepared, request, FALSE, error);
    if (!tx) return FALSE;
    if (strcmp(linux_ordered_string_v1(tx, "state"), "prepared")) return linux_load_error(error, "The original profile Load could not be prepared.");
    linux_load_owner(owner, tx);
    JsonObject *snapshot = linux_ordered_object_v1(json_node_get_object(prepared), "snapshot");
    const char *original = linux_ordered_string_v1(request, "expected_selected_node_id");
    if (!linux_ordered_owns_v1(linux_ordered_state_v1(ui), generation, original) || linux_async_busy_v16(ui->app))
        return linux_load_error(error, "A newer selection superseded this profile Load.");
    if (!linux_load_stage(&file, owner, request, snapshot, error)) return FALSE;
    *snapshot_text = linux_ordered_json_v1(snapshot);
    if (!linux_load_step("commit", owner, "committed", FALSE, error)) {
        /* A dropped reply can follow a durable commit. Only this owner's
         * authoritative receipt can turn that ambiguous result into success. */
        if (!linux_load_step("status", owner, "committed", FALSE, NULL)) return FALSE;
        g_clear_error(error);
    }
    *committed = TRUE;
    g_key_file_set_string(file.key, LINUX_LOAD_GROUP, "phase", "complete");
    if (!linux_load_write(&file, error) || !linux_load_step("finish", owner, "committed", TRUE, error) ||
        !linux_load_clear(&file, op, error)) return FALSE;
    return TRUE;
}

static gboolean linux_load_profile(LinuxUnifiedV8 *ui, const char *body, guint64 generation, Buffer *out, char **reason) {
    g_autoptr(GError) error = NULL;
    g_autofree char *snapshot = NULL, *op = NULL;
    gboolean committed = FALSE;
    if (!linux_load_attempt(ui, body, generation, &snapshot, &op, &committed, &error)) {
        g_autoptr(GError) recovery = NULL;
        gboolean settled = !op || linux_load_recover(op, &committed, &recovery);
        if (!settled || !committed || !snapshot) {
            *reason = settled ? g_strdup(error->message) : g_strdup_printf("%s Recovery pending: %s", error->message, recovery->message);
            return FALSE;
        }
        g_auto(LinuxLoadFile) file = {.directory = -1};
        if (!linux_load_open(&file, FALSE, NULL)) {
            *reason = g_strdup("A newer profile Load owns the local selection."); return FALSE;
        }
        g_autofree char *current = g_key_file_get_string(file.key, "state", LINUX_LOAD_REVISION, NULL);
        if (g_strcmp0(current, op)) {
            *reason = g_strdup("The original Load completed after a newer selection."); return FALSE;
        }
    }
    out->len = strlen(snapshot); out->data = g_steal_pointer(&snapshot); return TRUE;
}
