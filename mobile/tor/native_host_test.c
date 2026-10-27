#define _POSIX_C_SOURCE 200809L
#include "routervpn_tor_host.h"
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#ifdef __linux__
#include <dirent.h>
#endif
#include <unistd.h>

static void command(int fd, const char *text, const char *expected) {
    assert(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
    char bytes[8192];
    size_t used = 0;
    int complete = 0;
    while (!complete) {
        struct pollfd p = {fd, POLLIN, 0};
        assert(poll(&p, 1, 10000) == 1);
        ssize_t n = read(fd, bytes + used, sizeof(bytes) - used - 1);
        assert(n > 0);
        used += (size_t)n;
        bytes[used] = 0;
        assert(used < sizeof(bytes) - 1);
        for (char *line = bytes; line && *line;) {
            char *end = strstr(line, "\r\n");
            if (!end) break;
            if (end - line >= 4 && line[3] == ' ') {
                assert(memcmp(line, expected, 3) == 0);
                complete = 1;
            }
            line = end + 2;
        }
    }
    if (strcmp(bytes, expected) != 0) {
        fprintf(stderr, "Unexpected native control reply: %s", bytes);
        assert(0);
    }
}

static int descriptor_count(void) {
#ifdef __linux__
    DIR *directory = opendir("/proc/self/fd");
    assert(directory);
    int count = 0;
    while (readdir(directory)) count++;
    closedir(directory);
    return count;
#else
    return 0;
#endif
}

static int32_t await_exit(uint64_t handle) {
    struct timespec delay = {0, 10000000L};
    int32_t code;
    for (int i = 0; i < 500; i++) {
        if (routervpn_tor_status(handle, &code) == 1) return code;
        nanosleep(&delay, NULL);
    }
    assert(0 && "Tor failed-start thread did not exit");
    return -1;
}

static void close_final(uint64_t handle) {
    for (int i = 0; i < 12; i++) {
        int result = routervpn_tor_close(handle, 5000);
        assert(result >= 0);
        if (result == 0) return;
    }
    assert(0 && "Tor final thread failed to join");
}

static void verify_idle(int fd) {
    command(fd, "SETCONF DisableNetwork=1 SocksPort=0 UseBridges=0 Bridge ClientTransportPlugin\r\n", "250 OK\r\n");
    command(fd, "SIGNAL CLEARDNSCACHE\r\n", "250 OK\r\n");
    command(fd, "ROUTERVPN_PADDING INFO\r\n",
        "250 version=1 direction=outgoing min_rate_kbps=32 max_rate_kbps=192 default_rate_kbps=192 max_ttl_ms=10000 max_pending_cells=1 accounting=tor-link-cell username_hex_lengths=32,64 password_hex_length=64 generation_highwater=0\r\n");
    command(fd, "ROUTERVPN_PADDING START aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 1 192 10000 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\r\n",
        "551 Padding start is stale or unavailable\r\n");
    command(fd, "GETCONF DisableNetwork SocksPort UseBridges Bridge ClientTransportPlugin\r\n",
        "250-DisableNetwork=1\r\n250-SocksPort=0\r\n250-UseBridges=0\r\n250-Bridge\r\n250 ClientTransportPlugin\r\n");
    command(fd, "GETINFO orconn-status circuit-status stream-status address-mappings/cache net/listeners/or net/listeners/extor net/listeners/dir net/listeners/socks net/listeners/trans net/listeners/natd net/listeners/httptunnel net/listeners/dns net/listeners/control net/listeners/metrics\r\n",
        "250-orconn-status=\r\n250-circuit-status=\r\n250-stream-status=\r\n250-address-mappings/cache=\r\n250-net/listeners/or=\r\n250-net/listeners/extor=\r\n250-net/listeners/dir=\r\n250-net/listeners/socks=\r\n250-net/listeners/trans=\r\n250-net/listeners/natd=\r\n250-net/listeners/httptunnel=\r\n250-net/listeners/dns=\r\n250-net/listeners/control=\r\n250-net/listeners/metrics=\r\n250 OK\r\n");
}

int main(int argc, char **argv) {
    assert(argc == 3);
    assert(routervpn_tor_abi() == 1);
    assert(strstr(routervpn_tor_version(), "0.4.9.14") != NULL);
    char torrc[4096];
    assert(snprintf(torrc, sizeof(torrc), "%s/routervpn-empty-torrc", argv[1]) > 0);
    FILE *empty = fopen(torrc, "w");
    assert(empty && fclose(empty) == 0);
    const char *arguments[] = {"tor", "--quiet", "-f", torrc, "--defaults-torrc", torrc,
        "--DataDirectory", argv[1], "--ClientOnly", "1", "--DisableNetwork", "1",
        "--__DisableSignalHandlers", "1", "--UseBridges", "0", "--SocksPort", "0",
        "--ControlPort", "0", "--Log", "err stderr"};
    size_t count = sizeof(arguments) / sizeof(arguments[0]);
    uint64_t handle = 0, other = 1;
    /* Preflight validation does not consume the one permitted Tor invocation. */
    assert(routervpn_tor_start(NULL, 0, &other) == -1 && other == 0);
    if (strcmp(argv[2], "failed-start") == 0) {
        const char *bad[] = {"tor", "--quiet", "-f", torrc, "--RouterVPNInvalidOption", "1"};
        assert(routervpn_tor_start(bad, sizeof(bad) / sizeof(bad[0]), &handle) == 0);
        assert(await_exit(handle) != 0);
    } else {
        assert(routervpn_tor_start(arguments, count, &handle) == 0 && handle > 0);
        assert(routervpn_tor_start(arguments, count, &other) == -2 && other == 0);
        if (strcmp(argv[2], "resident") == 0) {
            int fd = routervpn_tor_control(handle);
            assert(fd >= 0);
            assert(routervpn_tor_control(handle) == -1);
            verify_idle(fd);
            int settled = descriptor_count();
            /* Reconfigure actual C Tor with networking disabled throughout.
             * Every session clears bridge/plugin data and reads all active
             * socket/circuit inventories. This is not a public circuit proof. */
            for (int iteration = 0; iteration < 64; iteration++) {
                command(fd, "SETCONF UseBridges=1 SocksPort=\"auto IsolateSOCKSAuth\" ClientTransportPlugin=\"obfs4 socks5 127.0.0.1:18443\" Bridge=\"obfs4 198.51.100.9:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=Y2VydA iat-mode=0\"\r\n", "250 OK\r\n");
                command(fd, "GETCONF UseBridges ClientTransportPlugin Bridge\r\n",
                    "250-UseBridges=1\r\n250-ClientTransportPlugin=obfs4 socks5 127.0.0.1:18443\r\n250 Bridge=obfs4 198.51.100.9:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=Y2VydA iat-mode=0\r\n");
                verify_idle(fd);
                assert(descriptor_count() == settled);
            }
            close_final(handle);
            close(fd);
        } else if (strcmp(argv[2], "fd-reuse") == 0) {
            int fd = routervpn_tor_control(handle);
            assert(fd >= 0);
            verify_idle(fd);
            command(fd, "SIGNAL HALT\r\n", "250 OK\r\n");
            assert(await_exit(handle) == 0);
            /* Reuse closed Tor descriptor numbers before releasing wrapper
             * ownership. Its cleanup must not close another app thread's FD. */
            int replacements[64];
            for (size_t i = 0; i < 64; i++) {
                replacements[i] = open("/dev/null", O_RDONLY);
                assert(replacements[i] >= 0);
            }
            close_final(handle);
            for (size_t i = 0; i < 64; i++) {
                assert(fcntl(replacements[i], F_GETFD) >= 0);
                close(replacements[i]);
            }
            close(fd);
        } else {
            assert(strcmp(argv[2], "premature-stop") == 0);
            /* Owning EOF may arrive before Tor adopts the native socket. */
            int result = routervpn_tor_close(handle, 0);
            assert(result == 0 || result == 1);
        }
    }
    close_final(handle);
    int32_t code = -1;
    assert(routervpn_tor_control(handle) == -1);
    assert(routervpn_tor_status(handle, &code) == -1);
    assert(routervpn_tor_close(handle, 0) == 0);
    assert(routervpn_tor_start(arguments, count, &other) == -3 && other == 0);
    assert(routervpn_tor_status(handle + 1, &code) == -1);
    printf("Pinned native Tor %s lifecycle passed\n", argv[2]);
    return 0;
}
