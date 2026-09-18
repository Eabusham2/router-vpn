#!/usr/bin/env python3
"""Compile the shipping loopback worker and test request ownership/lifetime."""
from pathlib import Path
import http.server
import json
import os
import select
import shlex
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
C_TEST = r'''
#define _GNU_SOURCE
#include "routervpn-http-job-v16.h"
#include <time.h>
#include <unistd.h>
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9; }
int main(int argc,char **argv) {
    if(argc!=2 || curl_global_init(CURL_GLOBAL_DEFAULT)!=CURLE_OK)return 2;
    int mode=atoi(argv[1]);
    const char *paths[]={"/api/ok","/api/slow","/api/large","/api/redirect","/api/slow","/api/error"};
    if(mode<0||mode>5)return 3;
    char *body=strdup("{\"owned\":true}");
    RVHttpJobV16 *job=rv_http_start_v16(paths[mode],body,mode==4?120:4000,"test");
    memset(body,'x',strlen(body));free(body); /* Caller storage does not survive. */
    if(job==NULL)return 4;
    double start=now();
    if(mode==1) {
        usleep(150000);rv_http_cancel_v16(job);
        while(!rv_http_ready_v16(job)&&now()-start<2)usleep(1000);
        if(!rv_http_ready_v16(job)||now()-start>0.8||job->result!=CURLE_ABORTED_BY_CALLBACK)return 5;
    } else {
        while(!rv_http_ready_v16(job)&&now()-start<5)usleep(1000);
        if(!rv_http_ready_v16(job))return 6;
        if(mode==0 && (job->result!=CURLE_OK||job->status!=200||strcmp(job->response,"{\"ok\":true}")!=0))return 7;
        if(mode==2 && (job->result!=CURLE_WRITE_ERROR||job->length>RV_HTTP_LIMIT_V16))return 8;
        if(mode==3 && (job->result!=CURLE_OK||job->status!=302))return 9;
        if(mode==4 && job->result!=CURLE_OPERATION_TIMEDOUT)return 10;
        if(mode==5 && (job->result!=CURLE_OK||job->status!=409))return 11;
    }
    rv_http_free_v16(job);
    if(rv_http_start_v16("https://example.invalid", "{}", 1000,"bad")!=NULL)return 12;
    if(rv_http_start_v16("/api/ok", "{}", 0,"bad")!=NULL)return 13;
    curl_global_cleanup();printf("shipping HTTP worker scenario %d: PASS\n",mode);return 0;
}
'''


def main():
    received, cancelled, failures = [], [], []
    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_POST(self):
            self.connection.settimeout(2)
            n = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(n) if 0 <= n < 65536 else b''
            received.append(self.path)
            if body != b'{"owned":true}':
                failures.append('caller body was not captured')
            if self.path == '/api/slow':
                end = time.monotonic() + 3
                while time.monotonic() < end:
                    try:
                        closed = select.select([self.connection], [], [], .02)[0] and not self.connection.recv(1, socket.MSG_PEEK)
                    except ConnectionResetError:
                        closed = True
                    if closed:
                        cancelled.append(self.path)
                        return
            status, content = 200, b'{"ok":true}'
            if self.path == '/api/large': content = b'x' * (3 << 20)
            if self.path == '/api/redirect': status = 302
            if self.path == '/api/error': status = 409
            try:
                self.send_response(status)
                self.send_header('Location', 'http://127.0.0.1:8788/redirect-target')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except (BrokenPipeError, ConnectionResetError):
                pass
    # An existing local controller is never reused or stopped by this test.
    server = Server(('127.0.0.1', 8788), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='router-vpn-http-job-') as work:
            src, binary = Path(work)/'test.c', Path(work)/'test'
            src.write_text(C_TEST)
            flags = shlex.split(subprocess.check_output(['pkg-config', '--cflags', '--libs', 'libcurl'], text=True))
            subprocess.run(['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pthread', '-I'+str(ROOT/'client/linux'), str(src), '-o', str(binary), *flags], check=True, timeout=30)
            for case in range(6):
                subprocess.run([str(binary), str(case)], check=True, timeout=8, env=dict(os.environ, http_proxy='http://127.0.0.1:1', ALL_PROXY='http://127.0.0.1:1'))
        end = time.monotonic()+1
        while len(cancelled)<2 and time.monotonic()<end:time.sleep(.02)
        assert len(received)==6 and len(cancelled)==2 and not failures, (received,cancelled,failures)
        assert '/redirect-target' not in received
        print('Bounded worker, immutable request, no proxies/redirects, cancellation and timeout: PASS')
    finally:
        server.shutdown();server.server_close();thread.join(timeout=2)


if __name__ == '__main__':
    main()
