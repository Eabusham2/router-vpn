#ifndef ROUTERVPN_PROFILE_LOAD_STORE_V1
#define ROUTERVPN_PROFILE_LOAD_STORE_V1
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/random.h>
#include <unistd.h>
#include <glib/gstdio.h>

/* The same private file contains the user's settings and the Load record.
 * Stage and rollback therefore publish the settings and their phase together. */
#define LINUX_LOAD_GROUP "connection-profile-load-v1"
#define LINUX_LOAD_REVISION "last_profile_load"
typedef struct {
    int directory;
    char *path;
    GKeyFile *key;
    GBytes *preimage;
    struct stat identity;
} LinuxLoadFile;

static gboolean linux_load_error(GError **error, const char *message) {
    g_set_error_literal(error, G_FILE_ERROR, G_FILE_ERROR_FAILED, message);
    return FALSE;
}

static void linux_load_close(LinuxLoadFile *file) {
    if (file->directory >= 0) close(file->directory);
    g_free(file->path);
    if (file->preimage) g_bytes_unref(file->preimage);
    if (file->key) g_key_file_unref(file->key);
}
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(LinuxLoadFile, linux_load_close)

static gboolean linux_load_same_file(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode &&
        a->st_size == b->st_size && a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static gboolean linux_load_read(const char *path, GBytes **bytes, struct stat *identity, GError **error) {
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT || linux_load_error(error, "Cannot read the private profile settings.");
    struct stat after;
    if (fstat(fd, identity) || !S_ISREG(identity->st_mode) || identity->st_uid != getuid() || identity->st_nlink != 1 ||
        identity->st_size < 0 || identity->st_size > 1024 * 1024) {
        close(fd); return linux_load_error(error, "The local profile settings must be an owned, bounded regular file.");
    }
    gsize size = (gsize)identity->st_size, offset = 0;
    g_autofree char *data = g_malloc(size + 1);
    while (offset < size) {
        ssize_t count = read(fd, data + offset, size - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        offset += (gsize)count;
    }
    gboolean same = offset == size && !g_lstat(path, &after) && linux_load_same_file(identity, &after);
    close(fd);
    if (!same) return linux_load_error(error, "Local settings changed while they were being read.");
    data[size] = 0; *bytes = g_bytes_new_take(g_steal_pointer(&data), size);
    return TRUE;
}

static gboolean linux_load_open(LinuxLoadFile *file, gboolean allow_pending, GError **error) {
    file->path = linux_unified_preset_path_v8();
    g_autofree char *parent = g_path_get_dirname(file->path);
    struct stat st;
    file->directory = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (file->directory < 0 || fstat(file->directory, &st) || st.st_uid != getuid() ||
        (st.st_mode & 0022) || flock(file->directory, LOCK_EX | LOCK_NB))
        return linux_load_error(error, "The settings directory is busy or unsafe. Retry after the current profile operation.");
    file->key = g_key_file_new();
    if (!linux_load_read(file->path, &file->preimage, &file->identity, error)) return FALSE;
    if (file->preimage) {
        gsize size = 0;
        const char *data = g_bytes_get_data(file->preimage, &size);
        if (!g_key_file_load_from_data(file->key, data, size, G_KEY_FILE_KEEP_COMMENTS, error)) return FALSE;
    }
    if (!allow_pending && g_key_file_has_group(file->key, LINUX_LOAD_GROUP))
        return linux_load_error(error, "A previous profile Load needs recovery. Open Connection profiles to retry.");
    return TRUE;
}

static gboolean linux_load_parent_current(LinuxLoadFile *file) {
    struct stat held, current;
    g_autofree char *parent = g_path_get_dirname(file->path);
    return fstat(file->directory, &held) == 0 && g_lstat(parent, &current) == 0 && S_ISDIR(current.st_mode) &&
        current.st_uid == getuid() && !(current.st_mode & 0022) && current.st_dev == held.st_dev && current.st_ino == held.st_ino;
}

static gboolean linux_load_write(LinuxLoadFile *file, GError **error) {
    gsize size = 0;
    g_autofree char *data = g_key_file_to_data(file->key, &size, error);
    if (!data) return FALSE;
    if (size > 1024 * 1024) return linux_load_error(error, "The local profile settings exceed their storage limit.");
    g_autoptr(GBytes) previous = NULL;
    struct stat identity;
    if (!linux_load_read(file->path, &previous, &identity, error)) return FALSE;
    if ((previous == NULL) != (file->preimage == NULL) || (previous &&
        (!g_bytes_equal(previous, file->preimage) || !linux_load_same_file(&file->identity, &identity))))
        return linux_load_error(error, "A newer local settings write superseded this profile Load.");
    if (!linux_load_parent_current(file)) return linux_load_error(error, "The profile settings directory was replaced.");
    if (previous && (identity.st_mode & 077)) {
        /* GLib preserves an existing destination's mode on replacement. Tighten
         * the captured inode first so the journal is never published publicly. */
        int fd = open(file->path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        struct stat before, secured, current;
        gboolean protected = fd >= 0 && fstat(fd, &before) == 0 && linux_load_same_file(&identity, &before) &&
            fchmod(fd, 0600) == 0 && fsync(fd) == 0 && fstat(fd, &secured) == 0 &&
            g_lstat(file->path, &current) == 0 && linux_load_same_file(&secured, &current);
        if (fd >= 0) close(fd);
        if (!protected) return linux_load_error(error, "Cannot protect the original local settings before staging a profile Load.");
        file->identity = secured;
    }
    if (!g_file_set_contents_full(file->path, data, size, G_FILE_SET_CONTENTS_CONSISTENT | G_FILE_SET_CONTENTS_DURABLE, 0600, error)) return FALSE;
    /* Confirm both the rename and the directory entry before advancing to
     * another store. An ambiguous write leaves recovery to the disk phase. */
    if (fsync(file->directory) || !linux_load_parent_current(file))
        return linux_load_error(error, "Cannot confirm the local settings directory write.");
    g_autoptr(GBytes) published = NULL;
    if (!linux_load_read(file->path, &published, &identity, error)) return FALSE;
    if (!published || (identity.st_mode & 077) || g_bytes_get_size(published) != size ||
        memcmp(data, g_bytes_get_data(published, NULL), size))
        return linux_load_error(error, "The private settings changed before their write could be confirmed.");
    g_clear_pointer(&file->preimage, g_bytes_unref);
    file->preimage = g_steal_pointer(&published); file->identity = identity;
    return TRUE;
}

static gboolean linux_load_pending(void) {
    g_auto(LinuxLoadFile) file = {.directory = -1};
    return !linux_load_open(&file, FALSE, NULL);
}

static gboolean linux_load_fences_launch(const char *path) {
    return (g_str_has_prefix(path, "/api/strategy/") || !strcmp(path, "/api/connect-logical") ||
            g_str_has_suffix(path, "/connect") || !strcmp(path, "/api/speed-lab/run")) && linux_load_pending();
}

static gboolean linux_load_save_ordinary(GKeyFile *draft, GError **error) {
    g_auto(LinuxLoadFile) file = {.directory = -1};
    if (!linux_load_open(&file, FALSE, error)) return FALSE;
    g_autofree char *current = g_key_file_get_string(file.key, "state", LINUX_LOAD_REVISION, NULL);
    g_autofree char *original = g_key_file_get_string(draft, "state", LINUX_LOAD_REVISION, NULL);
    if (g_key_file_has_group(draft, LINUX_LOAD_GROUP) || g_strcmp0(current, original) != 0)
        return linux_load_error(error, "A newer profile Load owns these settings.");
    g_key_file_unref(file.key); file.key = g_key_file_ref(draft);
    return linux_load_write(&file, error);
}
#endif
