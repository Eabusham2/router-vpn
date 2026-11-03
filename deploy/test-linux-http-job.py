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
#include <json-glib/json-glib.h>
/* SHIPPING_MULTIHOP_CHOICES */
#include "routervpn-multihop-http-v26.h"
#include <time.h>
#include <unistd.h>
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9; }
int main(int argc,char **argv) {
    if(argc!=2 || curl_global_init(CURL_GLOBAL_DEFAULT)!=CURLE_OK)return 2;
    static const char secret[]="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    if(!rv_controller_auth_publish(42,secret))return 26;
    int mode=atoi(argv[1]);
    const char *paths[]={"/api/ok","/api/slow","/api/large","/api/redirect","/api/slow","/api/error","/api/read","/api/connection/speed-test","/api/multihop/connect"};
    if(mode<0||mode>17)return 3;
    static const char compare[]="{\"entry_id\":\"captured-entry\",\"entry_mode\":\"\",\"exit_id\":\"captured-exit\",\"exit_mode\":\"shadowsocks\",\"execution\":\"auto\"}";
    static const char complete[]="{\"entry_id\":\"captured-entry\",\"entry_mode\":\"wg-pq\",\"exit_id\":\"captured-exit\",\"exit_mode\":\"max-quic-awg\",\"execution\":\"auto\"}";
    char *body=strdup(mode>=15?(mode==16?complete:compare):"{\"owned\":true}");
    RVHttpJobV16 *job=mode>=15?rv_http_start_multihop_comparison_v26("/api/multihop/connect",body,mode==16?450000:330000,"Captured graph",0):mode>=11?rv_http_start_comparison_progress_v25():mode>=9?rv_http_start_tor_comparison_v25(body,"Tor compare"):
        mode==6?rv_http_start_method_v17(paths[mode],"",4000,"read",1):rv_http_start_v16(paths[mode],body,mode==4?120:4000,"test");
    memset(body,'x',strlen(body));free(body); /* Caller storage does not survive. */
    if(job==NULL)return 4;
    rv_controller_auth_clear(42,secret);
    if(!rv_controller_auth_publish(43,"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))return 27;
    double start=now();
    if(mode>=9 && mode<=10 && (job->timeout_ms!=540000L||job->get||!job->connecting||strcmp(job->url,"http://127.0.0.1:8788/api/external-profile/connect")!=0))return 17;
    if(mode>=11 && mode<=14 && (job->timeout_ms!=2000L||!job->get||job->connecting||job->response_limit!=32768||strcmp(job->url,"http://127.0.0.1:8788/api/multihop/status")!=0))return 18;
    if(mode>=15 && (job->timeout_ms!=(mode==16?450000:330000)||job->get||!job->connecting||strcmp(job->url,"http://127.0.0.1:8788/api/multihop/connect")!=0))return 28;
    if(mode==1 || mode==10 || mode==17) {
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
        if((mode==9 || mode==15 || mode==16) && (job->result!=CURLE_OK||job->status!=200||strcmp(job->response,"{\"ok\":true}")!=0))return 19;
        if(mode==11 && (job->result!=CURLE_OK||job->status!=200||strcmp(job->response,"{\"get\":true}")!=0))return 20;
        if(mode==12 && (job->result!=CURLE_WRITE_ERROR||job->length>32768))return 21;
        if(mode==13 && (job->result!=CURLE_OK||job->status!=302))return 22;
        if(mode==14 && (job->result!=CURLE_OPERATION_TIMEDOUT||now()-start<1.5||now()-start>3))return 23;
    }
    if(mode==6 && (job->result!=CURLE_OK||job->status!=200||!job->get||job->connecting||strcmp(job->response,"{\"get\":true}")!=0))return 14;
    if(mode==7 && (job->result!=CURLE_OK||job->connecting))return 15;
    if(mode==8 && (job->result!=CURLE_OK||!job->connecting))return 16;
    rv_http_free_v16(job);
    if(rv_http_start_v16("https://example.invalid", "{}", 1000,"bad")!=NULL)return 12;
    if(rv_http_start_v16("/api/ok", "{}", 0,"bad")!=NULL)return 13;
    if(rv_http_start_v16("/api/ok", "{}", 300001,"bad")!=NULL)return 24;
    if(rv_http_start_v16("/api/external-profile/connect", "{}", 540000,"uncaptured")!=NULL)return 25;
    /* Rejected requests must not create even a transient HTTP worker. */
    const char *bad[]={
        "{}", "[]", "null", "{", "{\"entry_id\":\"a\",\"entry_mode\":\"\",\"exit_id\":\"b\",\"exit_mode\":\"shadowsocks\",\"execution\":\"server\"}",
        "{\"entry_id\":\"a\",\"entry_mode\":\"\",\"exit_id\":\"a\",\"exit_mode\":\"shadowsocks\",\"execution\":\"auto\"}",
        "{\"entry_id\":\"\",\"entry_mode\":\"\",\"exit_id\":\"b\",\"exit_mode\":\"shadowsocks\",\"execution\":\"auto\"}",
        "{\"entry_id\":\"a\",\"entry_mode\":\"foreign\",\"exit_id\":\"b\",\"exit_mode\":\"shadowsocks\",\"execution\":\"auto\"}",
        "{\"entry_id\":\"a\",\"entry_mode\":\"\",\"exit_id\":\"b\",\"exit_mode\":\"foreign\",\"execution\":\"auto\"}",
        "{\"entry_id\":\"a\",\"entry_mode\":false,\"exit_id\":\"b\",\"exit_mode\":\"shadowsocks\",\"execution\":\"auto\"}",
        "{\"entry_id\":\"a\",\"entry_mode\":\"\",\"exit_id\":\"b\",\"exit_mode\":\"shadowsocks\",\"execution\":\"auto\",\"execution\":\"auto\"}",
        "{\"entry_id\":\"a\",\"entry_mode\":\"\",\"exit_id\":\"b\",\"exit_mode\":\"shadowsocks\",\"execution\":\"auto\",\"extra\":true}",
        "{\"entry_id\":\"a\",\"entry_mode\":\"\",\"exit_id\":\"b\",\"exit_mode\":\"shadowsocks\",\"execution\":\"auto\"} {}"
    };
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++)if(rv_http_start_multihop_comparison_v26("/api/multihop/connect",bad[i],330000,"invalid",0)!=NULL){fprintf(stderr,"invalid Compare request accepted: %zu\n",i);return 29;}
    char *trailing=NULL;
    if(asprintf(&trailing,"%s 1",compare)<0)return 34;
    if(rv_http_start_multihop_comparison_v26("/api/multihop/connect",trailing,330000,"trailing scalar",0)!=NULL)return 35;
    free(trailing);
    const char *foreign[]={"/api/connect","/api/multihop/connect?changed=1","/api/external-profile/connect","http://127.0.0.1:8788/api/multihop/connect"};
    for(size_t i=0;i<sizeof(foreign)/sizeof(foreign[0]);i++)if(rv_http_start_multihop_comparison_v26(foreign[i],compare,330000,"foreign",0)!=NULL)return 30;
    const long wrong[]={0,180000,300000,300001,329999,330001,450000,450001};
    for(size_t i=0;i<sizeof(wrong)/sizeof(wrong[0]);i++)if(rv_http_start_multihop_comparison_v26("/api/multihop/connect",compare,wrong[i],"wrong budget",0)!=NULL)return 31;
    if(rv_http_start_multihop_comparison_v26("/api/multihop/connect",compare,330000,"GET",1)!=NULL)return 32;
    if(rv_http_start_v16("/api/multihop/connect",compare,330000,"uncaptured generic")!=NULL)return 33;
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
        def do_GET(self):
            received.append(self.path)
            if self.headers.get('Authorization') != 'Bearer ' + 'a' * 64:
                failures.append('read credential was omitted or taken from replacement owner')
            if self.path not in ('/api/read','/api/multihop/status') or int(self.headers.get('Content-Length','0')) != 0:
                failures.append('read method/body contract changed')
            if self.server.case == 14:
                self.wait_for_close()
                return
            content = b'x' * 65536 if self.server.case == 12 else b'{"get":true}'
            try:
                self.send_response(302 if self.server.case == 13 else 200)
                self.send_header('Location','http://127.0.0.1:8788/redirect-target')
                self.send_header('Content-Length',str(len(content)));self.end_headers();self.wfile.write(content)
            except (BrokenPipeError,ConnectionResetError):
                pass
        def wait_for_close(self):
            end = time.monotonic() + 3
            while time.monotonic() < end:
                try:
                    closed = select.select([self.connection], [], [], .02)[0] and not self.connection.recv(1, socket.MSG_PEEK)
                except ConnectionResetError:
                    closed = True
                if closed:
                    cancelled.append(self.path)
                    return
        def do_POST(self):
            self.connection.settimeout(2)
            n = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(n) if 0 <= n < 65536 else b''
            received.append(self.path)
            if self.headers.get('Authorization') != 'Bearer ' + 'a' * 64:
                failures.append('action credential was omitted or taken from replacement owner')
            expected = {'entry_id':'captured-entry','entry_mode':'wg-pq' if self.server.case == 16 else '',
                        'exit_id':'captured-exit','exit_mode':'max-quic-awg' if self.server.case == 16 else 'shadowsocks','execution':'auto'}
            if (self.server.case < 15 and body != b'{"owned":true}') or (self.server.case >= 15 and json.loads(body) != expected):
                failures.append('caller body was not captured')
            if self.path == '/api/slow' or self.server.case in (10,17):
                self.wait_for_close()
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
            choices = (ROOT/'client/linux/routervpn-multihop-choices-v22.inc').read_text()
            def block(marker):
                start=choices.index(marker); opening=choices.index('{',start); depth=1; end=opening+1
                while depth:
                    depth += (choices[end]=='{')-(choices[end]=='}'); end+=1
                return choices[start:end]
            methods=[]
            for name in ('linux_multihop_exits_v22','linux_multihop_entries_v23'):
                marker='static const struct { const char *id; const char *label; } '+name+'[] = {'
                start=choices.index(marker); end=choices.index('\n};',start)+3; methods.append(choices[start:end])
            for marker in ('static gboolean linux_multihop_exit_supported_v22(', 'static gboolean linux_multihop_entry_supported_v23(',
                           'static long linux_multihop_initial_key_ms_v23(', 'static long linux_multihop_startup_timeout_v23('):
                methods.append(block(marker))
            src.write_text(C_TEST.replace('/* SHIPPING_MULTIHOP_CHOICES */','\n'.join(methods)))
            flags = shlex.split(subprocess.check_output(['pkg-config', '--cflags', '--libs', 'libcurl','json-glib-1.0'], text=True))
            subprocess.run(['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pthread', '-I'+str(ROOT/'client/linux'), str(src), '-o', str(binary), *flags], check=True, timeout=30)
            for case in range(18):
                server.case = case
                subprocess.run([str(binary), str(case)], check=True, timeout=8, env=dict(os.environ, http_proxy='http://127.0.0.1:1', ALL_PROXY='http://127.0.0.1:1'))
        end = time.monotonic()+1
        while len(cancelled)<5 and time.monotonic()<end:time.sleep(.02)
        assert len(received)==18 and len(cancelled)==5 and not failures, (received,cancelled,failures)
        assert '/redirect-target' not in received
        print('Owned HTTP worker: 18 actual loopback cases; generic 300s cap, exact captured multihop330/450s, captured Tor540s, streaming 32KiB progress, cancellation and timeout: PASS')
    finally:
        server.shutdown();server.server_close();thread.join(timeout=2)


if __name__ == '__main__':
    main()
