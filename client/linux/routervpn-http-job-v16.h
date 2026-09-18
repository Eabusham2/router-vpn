/* Owned loopback request. Only its worker accesses CURL handles and result
 * storage; the UI reads results after ready (acquire) and joins before free.
 * No GTK calls, shared CURL handles, proxies, redirects or unbounded responses.
 * https://curl.se/libcurl/c/threadsafe.html
 * https://curl.se/libcurl/c/curl_multi_poll.html */
#ifndef ROUTERVPN_HTTP_JOB_V16_H
#define ROUTERVPN_HTTP_JOB_V16_H
#include <curl/curl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RV_HTTP_LIMIT_V16 (2u * 1024u * 1024u)
typedef struct {
    pthread_t thread;
    atomic_int cancelled, ready;
    char *url, *body, *label, *response;
    size_t length;
    long timeout_ms, status;
    CURLcode result;
    int connecting;
} RVHttpJobV16;

static size_t rv_http_receive_v16(void *data, size_t size, size_t count, void *opaque) {
    RVHttpJobV16 *job = opaque;
    if (atomic_load(&job->cancelled) || job->length > RV_HTTP_LIMIT_V16 ||
        (size != 0 && count > (RV_HTTP_LIMIT_V16 - job->length) / size)) return 0;
    size_t length = size * count;
    char *next = realloc(job->response, job->length + length + 1);
    if (next == NULL) return 0;
    job->response = next;
    memcpy(next + job->length, data, length);
    job->length += length;
    next[job->length] = '\0';
    return length;
}

static void *rv_http_work_v16(void *opaque) {
    RVHttpJobV16 *job = opaque;
    CURL *easy = curl_easy_init();
    CURLM *multi = curl_multi_init();
    struct curl_slist *headers = NULL;
    int added = 0;
    job->result = CURLE_FAILED_INIT;
    if (easy == NULL || multi == NULL) goto done;
    headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (headers == NULL) goto done;
#define RV_SET(option, value) do { if (curl_easy_setopt(easy, option, value) != CURLE_OK) goto done; } while (0)
    RV_SET(CURLOPT_URL, job->url);
    RV_SET(CURLOPT_PROXY, "");
    RV_SET(CURLOPT_NOPROXY, "*");
    RV_SET(CURLOPT_FOLLOWLOCATION, 0L);
    RV_SET(CURLOPT_NOSIGNAL, 1L);
    RV_SET(CURLOPT_CONNECTTIMEOUT_MS, 3000L);
    RV_SET(CURLOPT_TIMEOUT_MS, job->timeout_ms);
    RV_SET(CURLOPT_HTTPHEADER, headers);
    RV_SET(CURLOPT_POSTFIELDS, job->body);
    RV_SET(CURLOPT_WRITEFUNCTION, rv_http_receive_v16);
    RV_SET(CURLOPT_WRITEDATA, job);
#undef RV_SET
    if (curl_multi_add_handle(multi, easy) != CURLM_OK) goto done;
    added = 1;
    int running = 1;
    while (running && !atomic_load(&job->cancelled)) {
        if (curl_multi_perform(multi, &running) != CURLM_OK) goto done;
        if (running && curl_multi_poll(multi, NULL, 0, 50, NULL) != CURLM_OK) goto done;
    }
    if (atomic_load(&job->cancelled)) job->result = CURLE_ABORTED_BY_CALLBACK;
    else {
        int remaining = 0;
        CURLMsg *message;
        while ((message = curl_multi_info_read(multi, &remaining)) != NULL)
            if (message->msg == CURLMSG_DONE && message->easy_handle == easy)
                job->result = message->data.result;
        (void)curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &job->status);
    }
done:
    if (added) (void)curl_multi_remove_handle(multi, easy);
    if (multi != NULL) curl_multi_cleanup(multi);
    if (easy != NULL) curl_easy_cleanup(easy);
    curl_slist_free_all(headers);
    atomic_store_explicit(&job->ready, 1, memory_order_release);
    return NULL;
}

static RVHttpJobV16 *rv_http_start_v16(const char *path, const char *body, long timeout_ms, const char *label) {
    static const char base[] = "http://127.0.0.1:8788";
    if (path == NULL || strncmp(path, "/api/", 5) != 0 || strlen(path) > 256 ||
        strchr(path, '\r') != NULL || strchr(path, '\n') != NULL ||
        body == NULL || strlen(body) > RV_HTTP_LIMIT_V16 || timeout_ms < 1 || timeout_ms > 300000) return NULL;
    RVHttpJobV16 *job = calloc(1, sizeof(*job));
    if (job == NULL) return NULL;
    atomic_init(&job->cancelled, 0);
    atomic_init(&job->ready, 0);
    job->url = malloc(sizeof(base) + strlen(path));
    job->body = strdup(body);
    job->label = strdup(label != NULL ? label : "Request");
    job->timeout_ms = timeout_ms;
    job->connecting = strstr(path, "/connect") != NULL || strncmp(path, "/api/strategy/", 14) == 0 || strcmp(path, "/api/auto") == 0;
    if (job->url != NULL) (void)snprintf(job->url, sizeof(base) + strlen(path), "%s%s", base, path);
    if (job->url != NULL && job->body != NULL && job->label != NULL && pthread_create(&job->thread, NULL, rv_http_work_v16, job) == 0)
        return job;
    free(job->url); free(job->body); free(job->label); free(job);
    return NULL;
}

static int rv_http_ready_v16(RVHttpJobV16 *job) {
    return job != NULL && atomic_load_explicit(&job->ready, memory_order_acquire);
}

static void rv_http_cancel_v16(RVHttpJobV16 *job) {
    if (job != NULL) atomic_store(&job->cancelled, 1);
}

static void rv_http_free_v16(RVHttpJobV16 *job) {
    if (job == NULL) return;
    rv_http_cancel_v16(job);
    (void)pthread_join(job->thread, NULL);
    free(job->url); free(job->body); free(job->label); free(job->response); free(job);
}
#endif
