/* Diagnostic negative control ONLY. This intentionally exercises the repeated
 * tor_run_main contract that the shipping host forbids. With the exact pinned
 * unpatched source it reproduces the worker-pool mutex destruction failure.
 * It is never linked into Android, Apple or the shipping native host. */
#define _POSIX_C_SOURCE 200809L
#include "tor_api.h"
#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void *run(void *configuration) {
    assert(tor_run_main(configuration) == 0);
    return NULL;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    char torrc[4096];
    assert(snprintf(torrc,sizeof(torrc),"%s/empty-torrc",argv[1]) > 0);
    FILE *empty = fopen(torrc,"w");
    assert(empty && fclose(empty) == 0);
    for (int i = 0; i < 2; i++) {
        int pair[2];
        assert(socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
        char descriptor[32];
        assert(snprintf(descriptor,sizeof(descriptor),"%d",pair[1]) > 0);
        char *arguments[] = {"tor", "--quiet", "-f", torrc, "--defaults-torrc", torrc,
            "--DataDirectory", argv[1], "--ClientOnly", "1", "--DisableNetwork", "1",
            "--SocksPort", "0", "--ControlPort", "0", "--__DisableSignalHandlers", "1",
            "--Log", "err stderr", "__OwningControllerFD", descriptor};
        tor_main_configuration_t *configuration = tor_main_configuration_new();
        assert(configuration);
        assert(tor_main_configuration_set_command_line(configuration,
            (int)(sizeof(arguments)/sizeof(arguments[0])),arguments) == 0);
        pthread_t thread;
        assert(pthread_create(&thread,NULL,run,configuration) == 0);
        const char *query = "GETINFO version\r\n";
        assert(write(pair[0],query,strlen(query)) == (ssize_t)strlen(query));
        char response[1024] = {0};
        size_t used = 0;
        while (!strstr(response,"250 OK\r\n")) {
            struct pollfd p = {pair[0],POLLIN,0};
            assert(poll(&p,1,10000) == 1);
            ssize_t n = read(pair[0],response+used,sizeof(response)-used-1);
            assert(n > 0);
            used += (size_t)n;
            assert(used < sizeof(response)-1);
            response[used] = 0;
        }
        assert(strstr(response,"0.4.9.14"));
        shutdown(pair[0],SHUT_RDWR);
        assert(pthread_join(thread,NULL) == 0);
        close(pair[0]);
        /* Tor owns and closes pair[1]; no embedding configuration field owns
         * that FD, so this avoids the separate upstream double-close bug. */
        tor_main_configuration_free(configuration);
    }
    puts("UNSAFE restart diagnostic survived two invocations; no restart support is implied");
    return 0;
}
