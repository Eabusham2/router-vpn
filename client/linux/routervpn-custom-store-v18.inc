#ifndef ROUTERVPN_CUSTOM_STORE_V18
#define ROUTERVPN_CUSTOM_STORE_V18
#include <errno.h>
#include <glib/gstdio.h>
#include <unistd.h>
#include "routervpn-profile-load-store-v1.inc"

typedef enum {
    LINUX_CUSTOM_SAVE, LINUX_CUSTOM_DELETE, LINUX_CUSTOM_CHECK_RESTORE
} LinuxCustomWriteV18;

static gboolean linux_custom_name_valid_v18(const char *name, gboolean allow_colon) {
    if (name == NULL || !g_utf8_validate(name, -1, NULL) || !name[0] ||
        g_utf8_strlen(name, -1) > 64) return FALSE;
    for (const char *p = name; *p; p = g_utf8_next_char(p))
        if (g_unichar_iscntrl(g_utf8_get_char(p)) || strchr("[]", *p) != NULL || (!allow_colon && *p == ':')) return FALSE;
    return TRUE;
}

static gboolean linux_custom_target_v18(GKeyFile *key, const char *editing, const char *name, gboolean restore, GError **error) {
    gboolean same_name = g_strcmp0(name, editing) == 0;
    /* A Settings profile can already own a literal colon. GTK group names
     * support it, while the builder has always reserved it for new names. */
    if (!linux_custom_name_valid_v18(name, restore || same_name)) {
        const char *reason = restore ? "The saved CUSTOM name cannot be represented in the Linux preset file. Rename the source preset." :
                                      "Use a CUSTOM name of 1–64 characters without control characters, colons or brackets.";
        g_set_error_literal(error, G_FILE_ERROR, G_FILE_ERROR_INVAL, reason);
        return FALSE;
    }
    g_autofree char *group = g_strconcat("preset:", name, NULL);
    if (g_key_file_has_group(key, group) && (restore || same_name)) return TRUE;
    g_autofree char *folded = g_utf8_casefold(name, -1);
    g_auto(GStrv) groups = g_key_file_get_groups(key, NULL);
    for (gsize i = 0; groups[i]; i++) {
        if (!g_str_has_prefix(groups[i], "preset:")) continue;
        const char *existing = groups[i] + strlen("preset:");
        if (g_strcmp0(editing, existing) == 0) continue;
        g_autofree char *existing_folded = g_utf8_casefold(existing, -1);
        if (g_strcmp0(folded, existing_folded) == 0) {
            g_set_error_literal(error, G_FILE_ERROR, G_FILE_ERROR_EXIST, "A CUSTOM preset already uses this name. Choose another name or edit the existing preset.");
            return FALSE;
        }
    }
    return TRUE;
}

static gboolean linux_custom_publish_v18(const char *editing, const char *name,
                                         const char *layers, LinuxCustomWriteV18 action, GError **error) {
    g_auto(LinuxLoadFile) file = {.directory = -1};
    if (!linux_load_open(&file, FALSE, error)) return FALSE;
    GKeyFile *key = file.key;
    gboolean ok = FALSE;
    gboolean deleting = action == LINUX_CUSTOM_DELETE;
    if (editing) {
        g_autofree char *source = g_strconcat("preset:", editing, NULL);
        if (!g_key_file_has_group(key, source)) {
            g_set_error_literal(error, G_FILE_ERROR, G_FILE_ERROR_NOENT, "The original CUSTOM preset is missing. Reopen the builder.");
            goto done;
        }
    }
    if (!deleting && !linux_custom_target_v18(key, editing, name,
            action == LINUX_CUSTOM_CHECK_RESTORE, error)) goto done;
    if (action == LINUX_CUSTOM_CHECK_RESTORE) { ok = TRUE; goto done; }
    if (editing != NULL && (deleting || g_strcmp0(editing, name) != 0)) {
        char *group = g_strconcat("preset:", editing, NULL);
        g_key_file_remove_group(key, group, NULL);
        g_free(group);
    }
    if (deleting) {
        g_autofree char *selected = g_key_file_get_string(key, "state", "selected_mode", NULL);
        g_autofree char *removed = g_strconcat("custom:", editing, NULL);
        if (g_strcmp0(selected, removed) == 0)
            g_key_file_set_string(key, "state", "selected_mode", "smart-auto");
    } else {
        char *group = g_strconcat("preset:", name, NULL);
        char *mode = g_strconcat("custom:", name, NULL);
        g_key_file_set_string(key, group, "layers", layers);
        g_key_file_set_string(key, "state", "selected_mode", mode);
        g_free(group); g_free(mode);
    }
    ok = linux_load_write(&file, error);
done:
    return ok;
}

#endif
