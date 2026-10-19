/* Executable C-ABI boundary double. Never compiled into a mobile package. */
#define _POSIX_C_SOURCE 200809L
#include "routervpn_tor_host.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int sockets[2] = {-1, -1};
static int starts, claims, closes, joined, released, owned, ever, claimed;

static int mode(const char *name) {
    const char *current = getenv("ROUTERVPN_TOR_LOADER_SCENARIO");
    return current && strcmp(current, name) == 0;
}
int32_t routervpn_tor_abi(void) { return mode("bad-abi") ? 9 : 1; }
const char *routervpn_tor_version(void) { return mode("bad-version") ? "tor 0.4.9.13" : "tor 0.4.9.14"; }
int32_t routervpn_tor_start(const char *const *arguments, size_t count, uint64_t *handle) {
    pthread_mutex_lock(&lock);
    starts++;
    *handle = 0;
    if (owned || ever || !arguments || !count) { pthread_mutex_unlock(&lock); return -2; }
    if (mode("empty-handle")) { pthread_mutex_unlock(&lock); return 0; }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) { pthread_mutex_unlock(&lock); return -1; }
    owned = ever = 1;
    *handle = 41;
    pthread_mutex_unlock(&lock);
    return mode("start-error-handle") ? -1 : 0;
}
int32_t routervpn_tor_control(uint64_t handle) {
    pthread_mutex_lock(&lock);
    claims++;
    int result = -1;
    if (owned && handle == 41 && !claimed && !mode("claim-failed")) {
        claimed = 1;
        result = mode("conversion-failed") ? open("/dev/null", O_RDONLY) : dup(sockets[0]);
    }
    pthread_mutex_unlock(&lock);
    return result;
}
int32_t routervpn_tor_status(uint64_t handle, int32_t *code) {
    pthread_mutex_lock(&lock);
    int result = owned && handle == 41 ? 0 : -1;
    *code = 0;
    if (result == 0 && mode("exit-code")) { result = 1; *code = 17; }
    if (mode("unknown-status")) result = -1;
    pthread_mutex_unlock(&lock);
    return result;
}
int32_t routervpn_tor_close(uint64_t handle, uint32_t wait_ms) {
    if (wait_ms > 100 || handle != 41) abort();
    pthread_mutex_lock(&lock);
    closes++;
    if (mode("close-error")) { pthread_mutex_unlock(&lock); return -1; }
    if (mode("timeout") && !released) {
        pthread_mutex_unlock(&lock);
        struct timespec delay = {0, 10000000L};
        nanosleep(&delay, NULL);
        return 1;
    }
    if (owned) {
        close(sockets[0]); close(sockets[1]);
        sockets[0] = sockets[1] = -1;
        owned = 0;
        joined++;
    }
    pthread_mutex_unlock(&lock);
    return 0;
}
int routervpn_test_count(int which) {
    pthread_mutex_lock(&lock);
    int value = which == 0 ? starts : which == 1 ? claims : which == 2 ? closes : which == 3 ? joined : owned;
    pthread_mutex_unlock(&lock);
    return value;
}
void routervpn_test_release(void) {
    pthread_mutex_lock(&lock);
    released = 1;
    pthread_mutex_unlock(&lock);
}
