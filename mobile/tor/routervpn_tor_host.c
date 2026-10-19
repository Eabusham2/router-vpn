#define _POSIX_C_SOURCE 200809L
#include "routervpn_tor_host.h"
#include "tor_api.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    uint64_t handle;
    tor_main_configuration_t *configuration;
    char **arguments;
    size_t count;
    pthread_t thread;
    int control;
    int daemon_control;
    struct stat daemon_identity;
    int exited;
    int result;
    int stopping;
    int control_claimed;
} routervpn_tor;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static routervpn_tor *owned;
static uint64_t generation;
static int started_once;

int32_t routervpn_tor_abi(void) { return ROUTERVPN_TOR_ABI; }
const char *routervpn_tor_version(void) { return tor_api_get_provider_version(); }

static void release(routervpn_tor *instance) {
    if (instance->control >= 0) close(instance->control);
    if (instance->daemon_control >= 0) {
        struct stat current;
        /* The main loop normally closes this endpoint. A failed initialization
         * may not adopt it. Never close a descriptor reused by another app
         * thread after Tor exited (the upstream embedding double-close bug). */
        if (fstat(instance->daemon_control, &current) == 0 &&
            current.st_dev == instance->daemon_identity.st_dev &&
            current.st_ino == instance->daemon_identity.st_ino)
            close(instance->daemon_control);
    }
    if (instance->configuration)
        tor_main_configuration_free(instance->configuration);
    if (instance->arguments) {
        for (size_t i = 0; i < instance->count; i++) {
            if (instance->arguments[i]) {
                size_t length = strlen(instance->arguments[i]);
                volatile char *bytes = instance->arguments[i];
                for (size_t j = 0; j < length; j++) bytes[j] = 0;
                free(instance->arguments[i]);
            }
        }
        free(instance->arguments);
    }
    free(instance);
}

static void *run(void *value) {
    routervpn_tor *instance = value;
    int result = tor_run_main(instance->configuration);
    pthread_mutex_lock(&lock);
    instance->result = result;
    instance->exited = 1;
    pthread_cond_broadcast(&changed);
    pthread_mutex_unlock(&lock);
    return NULL;
}

int32_t routervpn_tor_start(const char *const *arguments, size_t count,
                           uint64_t *handle) {
    if (!handle) return -1;
    *handle = 0;
    if (!arguments || count == 0 || count > 128) return -1;
    size_t total = 0;
    for (size_t i = 0; i < count; i++) {
        if (!arguments[i]) return -1;
        size_t length = strnlen(arguments[i], 8193);
        if (!length || length > 8192 || total > 65536 - length) return -1;
        total += length;
    }
    if (strcmp(arguments[0], "tor") != 0) return -1;

    pthread_mutex_lock(&lock);
    if (owned || generation == INT64_MAX) {
        pthread_mutex_unlock(&lock);
        return -2;
    }
    /* Tor's public API does not support repeated tor_run_main calls safely.
     * Session changes quiesce and reconfigure the resident instance; final
     * shutdown (including initialization failure) requires a new process. */
    if (started_once) {
        pthread_mutex_unlock(&lock);
        return -3;
    }
    routervpn_tor *instance = calloc(1, sizeof(*instance));
    if (!instance) { pthread_mutex_unlock(&lock); return -1; }
    instance->control = -1;
    instance->daemon_control = -1;
    instance->count = count + 2;
    instance->arguments = calloc(instance->count + 1, sizeof(char *));
    if (!instance->arguments) goto failed;
    for (size_t i = 0; i < count; i++) {
        instance->arguments[i] = strdup(arguments[i]);
        if (!instance->arguments[i]) goto failed;
    }
    /* Same preauthenticated socketpair contract as Tor's public setup API,
     * with explicit endpoint ownership so initialization failure and normal
     * main-loop shutdown cannot double-close a reused numeric descriptor. */
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) goto failed;
    instance->control = sockets[0];
    instance->daemon_control = sockets[1];
    if (fstat(sockets[1], &instance->daemon_identity) != 0 ||
        instance->daemon_identity.st_ino == 0) {
        close(instance->daemon_control);
        instance->daemon_control = -1;
        goto failed;
    }
    if (fcntl(sockets[0], F_SETFD, FD_CLOEXEC) < 0 ||
        fcntl(sockets[1], F_SETFD, FD_CLOEXEC) < 0) goto failed;
    char descriptor[32];
    if (snprintf(descriptor, sizeof(descriptor), "%d", sockets[1]) <= 0) goto failed;
    instance->arguments[count] = strdup("__OwningControllerFD");
    instance->arguments[count + 1] = strdup(descriptor);
    if (!instance->arguments[count] || !instance->arguments[count + 1]) goto failed;
    instance->configuration = tor_main_configuration_new();
    if (!instance->configuration ||
        tor_main_configuration_set_command_line(instance->configuration,
            (int)instance->count, instance->arguments) != 0) goto failed;
    instance->handle = ++generation;
    owned = instance;
    if (pthread_create(&instance->thread, NULL, run, instance) != 0) {
        owned = NULL;
        goto failed;
    }
    started_once = 1;
    *handle = instance->handle;
    pthread_mutex_unlock(&lock);
    return 0;
failed:
    release(instance);
    pthread_mutex_unlock(&lock);
    return -1;
}

int32_t routervpn_tor_control(uint64_t handle) {
    pthread_mutex_lock(&lock);
    int fd = -1;
    if (owned && owned->handle == handle && !owned->stopping &&
        !owned->exited && !owned->control_claimed) {
        fd = dup(owned->control);
        if (fd >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
            close(fd);
            fd = -1;
        }
        if (fd >= 0) owned->control_claimed = 1;
    }
    pthread_mutex_unlock(&lock);
    return fd;
}

int32_t routervpn_tor_status(uint64_t handle, int32_t *exit_code) {
    if (!exit_code) return -1;
    *exit_code = 0;
    pthread_mutex_lock(&lock);
    int result = -1;
    if (owned && owned->handle == handle) {
        result = owned->exited;
        if (result) *exit_code = owned->result;
    }
    pthread_mutex_unlock(&lock);
    return result;
}

int32_t routervpn_tor_close(uint64_t handle, uint32_t wait_ms) {
    if (!handle || wait_ms > 5000) return -1;
    pthread_mutex_lock(&lock);
    /* A stale stop never touches a newer process instance. */
    if (!owned || owned->handle != handle) {
        int result = handle <= generation ? 0 : -1;
        pthread_mutex_unlock(&lock);
        return result;
    }
    routervpn_tor *instance = owned;
    instance->stopping = 1;
    (void)shutdown(instance->control, SHUT_RDWR);
    struct timespec deadline;
    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
        pthread_mutex_unlock(&lock);
        return 1;
    }
    deadline.tv_sec += (time_t)(wait_ms / 1000);
    deadline.tv_nsec += (long)(wait_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    while (!instance->exited && wait_ms) {
        int status = pthread_cond_timedwait(&changed, &lock, &deadline);
        /* Another closer may have joined this exact instance while the mutex
         * was released by pthread_cond_timedwait. Do not dereference it. */
        if (owned != instance || owned->handle != handle) {
            pthread_mutex_unlock(&lock);
            return 0;
        }
        if (status != 0) break;
    }
    if (!instance->exited) {
        pthread_mutex_unlock(&lock);
        return 1;
    }
    /* The thread set exited under this mutex and performs no more owner
     * access. Join before freeing its arguments or releasing the singleton. */
    if (pthread_join(instance->thread, NULL) != 0) {
        pthread_mutex_unlock(&lock);
        return -1;
    }
    owned = NULL;
    release(instance);
    pthread_mutex_unlock(&lock);
    return 0;
}
