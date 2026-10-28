#!/usr/bin/env python3
"""Execute GTK's shipping comparison owners with actual loopback HTTP workers.

The fixture supplies only the public captured request and final result surfaces;
separate form tests execute their actual builders and Go consumers. The real
GTK widgets, async submit/poll/cancel, Speed Lab worker/start/finish/destroy and
progress parser/formatter execute here. No VPN or private endpoint is used.
"""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import ast
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


def block(source, marker):
    start = source.index(marker)
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def program():
    core = (ROOT/'client/linux/routervpn-gtk-product.c').read_text()
    common = '\n'.join(block(core, x) for x in ('static size_t write_cb(', 'static JsonNode *parse_json(',
                                                'static const char *obj_string(', 'static double obj_double('))
    tree = ast.parse((ROOT/'client/linux/apply-multihop-execution.py').read_text())
    values = ast.literal_eval(next(n.value for n in tree.body if isinstance(n, ast.Assign)
                                  and any(isinstance(t, ast.Name) and t.id == 'REPLACEMENTS' for t in n.targets)))
    formatter = block(next(b for _, b in values if 'static char *linux_multihop_progress_text_v1(' in b),
                      'static char *linux_multihop_progress_text_v1(')
    speed = (ROOT/'client/linux/routervpn-speed-lab-v12.inc').read_text()
    struct = speed[:speed.index('} LinuxSpeedLabV12;')+len('} LinuxSpeedLabV12;')]
    early = '\n'.join(block(speed, x) for x in (
        'static size_t linux_speed_lab_receive_v12(', 'static int linux_speed_lab_progress_v12(',
        'static gpointer linux_speed_lab_worker_v12(', 'static void linux_speed_lab_stop_comparison_v25(',
        'static void linux_speed_lab_comparison_v25(', 'static void linux_speed_lab_release_request_v12(',
        'static void linux_speed_lab_destroy_v12('))
    late = '\n'.join(block(speed, x) for x in ('static gboolean linux_speed_lab_complete_v12(',
                                             'static void linux_speed_lab_start_v12(',
                                             'static void linux_speed_lab_run_v12('))
    path = (ROOT/'client/linux/routervpn-speed-lab-path-v19.inc').read_text()
    timeout = '\n'.join(block(path, x) for x in ('static gboolean linux_speed_lab_tor_compare_request_v19(',
                                               'static long linux_speed_lab_request_timeout_v19('))
    text = C_PROGRAM
    for key, value in [('COMMON', common), ('FORMATTER', formatter), ('SPEED_STRUCT', struct),
                       ('SPEED_EARLY', early), ('SPEED_TIMEOUT', timeout), ('SPEED_LATE', late)]:
        text = text.replace('\n'+key+'\n', '\n'+value+'\n')
    return text


C_PROGRAM = r'''
#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <curl/curl.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define ROUTER_VPN_BASE_URL "http://127.0.0.1:8788"
typedef struct {GtkWidget *window,*error;} App;
typedef struct {char *data;size_t len;} Buffer;
static GKeyFile *linux_unified_load_keyfile_v8(void){return g_key_file_new();}
static void linux_unified_save_keyfile_v8(GKeyFile *key){(void)key;}
static unsigned checks;
static const char *directory;
static void check(gboolean ok,const char *message){checks++;if(!ok){g_printerr("comparison owner assertion: %s\n",message);exit(1);}}
static void append_diag(App *app,const char *line){(void)app;(void)line;}
static void refresh_all(App *app){(void)app;}
COMMON
#include "routervpn-async-actions-v16.inc"
FORMATTER
SPEED_STRUCT
#define LINUX_SPEED_LAB_RESPONSE_LIMIT (2u * 1024u * 1024u)
SPEED_EARLY
/* Only form inputs and final-result rendering are controlled here. Actual
 * source-captured form builders and Go consumers run in their separate gates. */
static char *speed_body;
static JsonObject *speed_node;
static JsonObject *linux_speed_lab_find_v19(LinuxSpeedLabV12*s,const char*key,const char*id){(void)s;return strcmp(key,"nodes")==0&&strcmp(id,"tor-node")==0?speed_node:NULL;}
SPEED_TIMEOUT
static char *linux_speed_lab_request_body_v12(LinuxSpeedLabV12*s){(void)s;return g_strdup(speed_body);}
static gboolean linux_speed_lab_apply_options_v12(LinuxSpeedLabV12*s){(void)s;check(FALSE,"Unexpected options boundary");return FALSE;}
static void linux_speed_lab_render_v12(LinuxSpeedLabV12*s,const char*json){(void)s;(void)json;check(FALSE,"Unexpected successful benchmark boundary");}
static void linux_speed_lab_refresh_controls_v12(GtkComboBox*combo,gpointer data){(void)combo;(void)data;}
SPEED_LATE
static char *fixture_path(const char *name){return g_build_filename(directory,name,NULL);}
static gboolean exists(const char *name){char*p=fixture_path(name);gboolean yes=g_file_test(p,G_FILE_TEST_EXISTS);g_free(p);return yes;}
static void wait_file(const char *name){gint64 end=g_get_monotonic_time()+4000000;while(!exists(name)&&g_get_monotonic_time()<end)g_usleep(1000);check(exists(name),name);}
static void mark(const char *name){char*p=fixture_path(name);check(g_file_set_contents(p,"ready",-1,NULL),"Cannot write fixture marker");g_free(p);}
static void phase(const char *mode,const char *request,gboolean complete){char*p=fixture_path("phase");char*json=g_strdup_printf("{\"mode\":\"%s\",\"request_id\":\"%s\",\"complete\":%s}",mode,request,complete?"true":"false");check(g_file_set_contents(p,json,-1,NULL),"Cannot set fixture phase");g_free(json);g_free(p);}
static void wait_job(RVHttpJobV16 *job){gint64 end=g_get_monotonic_time()+3500000;while(!rv_http_ready_v16(job)&&g_get_monotonic_time()<end)g_usleep(1000);check(rv_http_ready_v16(job),"Owned status worker did not finish");}
static void init_app(App *app){app->window=gtk_window_new(GTK_WINDOW_TOPLEVEL);g_object_ref_sink(app->window);app->error=gtk_label_new("");}
static unsigned next_id=1;
static char *new_id(void){return g_strdup_printf("%032x",next_id++);}
static char *public_body(const char *id){return g_strdup_printf("{\"profile_id\":\"tor-node\",\"entry_id\":\"entry\",\"execution\":\"auto\",\"comparison_request_id\":\"%s\",\"expected_selected_node_id\":\"tor-node\",\"expected_profile_tokens\":{\"tor-node\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"entry\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}}",id);}
static guint64 start_public(App *app,const char *id){char*body=public_body(id);guint64 generation=linux_async_request_v17(app,"/api/external-profile/connect",body,180000,"Captured Tor",FALSE);g_free(body);LinuxAsyncActionsV16*s=linux_async_state_v16(app);check(generation!=0&&s->primary!=NULL&&s->primary->timeout_ms==540000,"Captured public Tor did not receive its scoped budget");check(strcmp(s->comparison_request_id,id)==0,"Public observer lost captured nonce");return generation;}
static const char *summary(App*app){return g_object_get_data(G_OBJECT(app->window),"linux-multihop-progress");}
static void clear_summary(App*app){g_object_set_data_full(G_OBJECT(app->window),"linux-multihop-progress",NULL,g_free);}
static void end_public(App*app){LinuxAsyncActionsV16*s=linux_async_state_v16(app);linux_async_cancel_request_v17(app,s->generation);if(s->poll){g_source_remove(s->poll);s->poll=0;}rv_http_free_v16(s->primary);s->primary=NULL;linux_async_progress_v1(s);check(s->progress==NULL,"Public progress survived action cleanup");}
static void public_read(App*app,const char*mode,const char*id,gboolean terminal,gboolean stale){LinuxAsyncActionsV16*s=linux_async_state_v16(app);phase(mode,id,terminal);s->next_progress=0;linux_async_progress_v1(s);check(s->progress!=NULL,"Expected public status worker");wait_job(s->progress);if(stale)s->progress_generation--;linux_async_progress_v1(s);}
static char *replacement_id;
static gboolean replacement_callback;
static void replace_public(App*app){if(!replacement_callback)return;replacement_callback=FALSE;end_public(app);start_public(app,replacement_id);phase("held-public-replacement",replacement_id,FALSE);linux_async_progress_v1(linux_async_state_v16(app));}
static void speed_request(const char*id){g_free(speed_body);speed_body=g_strdup_printf("{\"scope\":\"temporary\",\"topology\":\"external\",\"node_id\":\"tor-node\",\"entry_id\":\"entry\",\"execution\":\"auto\",\"comparison_request_id\":\"%s\"}",id);}
static void init_speed(LinuxSpeedLabV12*s,App*app){memset(s,0,sizeof(*s));s->app=app;s->request_generation=7;s->options_ready=TRUE;s->status=gtk_label_new("");s->detail=gtk_text_view_new();s->run=gtk_button_new();s->idle=gtk_label_new("");s->download=gtk_label_new("");s->upload=gtk_label_new("");s->idle_detail=gtk_label_new("");s->download_detail=gtk_label_new("");s->upload_detail=gtk_label_new("");}
static void start_speed(LinuxSpeedLabV12*s,const char*id){speed_request(id);linux_speed_lab_start_v12(s,FALSE);check(s->worker!=NULL&&s->owns_slot&&s->request_timeout==960000L,"Actual temporary Tor start lost owned 960s budget");check(strcmp(s->comparison_request_id,id)==0,"Temporary observer borrowed another nonce");}
static void speed_read(LinuxSpeedLabV12*s,const char*mode,const char*id,gboolean terminal,gboolean stale){phase(mode,id,terminal);s->next_comparison=0;linux_speed_lab_comparison_v25(s);check(s->comparison_progress!=NULL,"Expected temporary status worker");wait_job(s->comparison_progress);if(stale)s->comparison_generation--;linux_speed_lab_comparison_v25(s);}
static void finish_speed(LinuxSpeedLabV12*s){gint64 end=g_get_monotonic_time()+4000000;while(!g_atomic_int_get(&s->complete)&&g_get_monotonic_time()<end)g_usleep(1000);check(g_atomic_int_get(&s->complete),"Temporary primary did not join");if(s->poll_source){g_source_remove(s->poll_source);s->poll_source=0;}check(linux_speed_lab_complete_v12(s)==G_SOURCE_REMOVE,"Temporary finish retained old source");}
static LinuxSpeedLabV12 *replacement_speed;
static gboolean speed_replace_callback;
static void replace_speed(App*app){(void)app;if(!speed_replace_callback)return;speed_replace_callback=FALSE;check(replacement_speed->request_body==NULL&&replacement_speed->comparison_progress==NULL,"Old temporary resources were not retired before slot release");start_speed(replacement_speed,replacement_id);}
int main(int argc,char**argv){gtk_init(&argc,&argv);check(argc==2,"Expected fixture directory");directory=argv[1];check(curl_global_init(CURL_GLOBAL_DEFAULT)==CURLE_OK,"libcurl initialization failed");
    (void)linux_multihop_execution_choice_v1;(void)linux_multihop_store_execution_v1;(void)linux_multihop_entry_choice_v23;(void)linux_multihop_store_entry_v23;
    (void)linux_async_connecting_v16;(void)linux_async_stopping_v16;(void)linux_async_dispatch_v16;
    App app={0};init_app(&app);
    const char*invalid_requests[]={"{}","{\"comparison_request_id\":\"bad\"}","{\"comparison_request_id\":1}","{\"comparison_request_id\":\"11111111111111111111111111111111\",\"execution\":\"local\"}"};
    /* An empty ordinary request still uses its original budget; only malformed
     * explicit comparison markers must fail before reaching the wire. */
    for(guint i=1;i<G_N_ELEMENTS(invalid_requests);i++)check(linux_async_request_v17(&app,"/api/external-profile/connect",invalid_requests[i],180000,"Invalid captured request",FALSE)==0,"Malformed captured request started HTTP");
    char*id=new_id();guint64 first=start_public(&app,id);LinuxAsyncActionsV16*s=linux_async_state_v16(&app);
    const char*mismatches[]={"wrong-request","missing-request","typed-request","wrong-last","wrong-external","typed-complete","redirect","oversized"};
    for(guint i=0;i<G_N_ELEMENTS(mismatches);i++){public_read(&app,mismatches[i],id,TRUE,FALSE);check(summary(&app)==NULL&&!s->progress_complete,"Unowned or malformed progress changed the public UI");}
    public_read(&app,"stale-generation",id,FALSE,TRUE);check(summary(&app)==NULL,"A stale action generation changed the public UI");
    public_read(&app,"public-valid",id,FALSE,FALSE);check(summary(&app)!=NULL&&strstr(summary(&app),"Tor last-relay HTTP")&&strstr(summary(&app),"same external-server HTTP")&&strstr(summary(&app),"(20.00 + 40.00) / 2 = 30.00 ms"),"Public comparison lost truthful HTTP measurements");
    clear_summary(&app);replacement_id=new_id();replacement_callback=TRUE;s->changed=replace_public;
    public_read(&app,"public-terminal",id,TRUE,FALSE);check(s->generation!=first&&s->primary!=NULL&&s->progress!=NULL&&!s->progress_complete&&strcmp(s->comparison_request_id,replacement_id)==0,"Old terminal callback retired the replacement owner");
    wait_file("started-held-public-replacement");RVHttpJobV16*replacement_job=s->progress;check(replacement_job!=NULL&&!atomic_load(&replacement_job->cancelled),"Old terminal cleanup cancelled replacement status");
    linux_async_cancel_request_v17(&app,first);check(!atomic_load(&s->primary->cancelled)&&!atomic_load(&replacement_job->cancelled),"Old cancel retired replacement action");
    linux_async_cancel_request_v17(&app,s->generation);check(atomic_load(&s->primary->cancelled)&&atomic_load(&replacement_job->cancelled),"Captured cancel did not cancel its status reader");end_public(&app);wait_file("cancelled-held-public-replacement");s->changed=NULL;g_free(id);g_free(replacement_id);replacement_id=NULL;
    id=new_id();start_public(&app,id);phase("held-public-expiry",id,FALSE);linux_async_progress_v1(s);wait_file("started-held-public-expiry");s->progress_deadline=g_get_monotonic_time()-1;linux_async_progress_v1(s);check(s->progress==NULL,"Expired observer retained status reader");wait_file("cancelled-held-public-expiry");end_public(&app);g_free(id);
    id=new_id();start_public(&app,id);phase("held-public-close",id,FALSE);linux_async_progress_v1(s);wait_file("started-held-public-close");gtk_widget_destroy(app.window);check(s->closed&&s->primary==NULL&&s->progress==NULL&&s->poll==0,"Actual window close retained public owner");wait_file("cancelled-held-public-close");g_object_unref(app.window);g_free(id);
    App speed_app={0};init_app(&speed_app);speed_node=json_object_new();json_object_set_string_member(speed_node,"external_protocol","tor");LinuxSpeedLabV12 speed;init_speed(&speed,&speed_app);id=new_id();start_speed(&speed,id);
    const char*initial=gtk_label_get_text(GTK_LABEL(speed.status));char*initial_copy=g_strdup(initial);
    speed_read(&speed,"wrong-request",id,TRUE,FALSE);check(strcmp(gtk_label_get_text(GTK_LABEL(speed.status)),initial_copy)==0&&!speed.comparison_complete,"Unowned temporary progress changed the dialog");
    speed_read(&speed,"stale-speed-generation",id,FALSE,TRUE);check(strcmp(gtk_label_get_text(GTK_LABEL(speed.status)),initial_copy)==0,"Stale temporary generation changed the dialog");g_free(initial_copy);
    speed_read(&speed,"speed-valid",id,FALSE,FALSE);check(strstr(gtk_label_get_text(GTK_LABEL(speed.status)),"Tor HTTP responses")!=NULL,"Temporary progress omitted real measurement labels");
    phase("held-speed-cancel",id,FALSE);speed.next_comparison=0;linux_speed_lab_comparison_v25(&speed);wait_file("started-held-speed-cancel");RVHttpJobV16*speed_job=speed.comparison_progress;
    linux_speed_lab_stop_comparison_v25(&speed,speed.request_generation-1);check(speed.comparison_progress==speed_job&&!atomic_load(&speed_job->cancelled),"Old temporary finalizer cancelled a replacement observer");
    linux_speed_lab_run_v12(NULL,&speed);check(g_atomic_int_get(&speed.cancelled)&&speed.comparison_progress==NULL,"Actual Cancel did not retire the temporary status worker");wait_file("cancelled-held-speed-cancel");finish_speed(&speed);check(!speed.owns_slot&&speed.worker==NULL&&strstr(gtk_label_get_text(GTK_LABEL(speed.status)),"Cancelled")!=NULL,"Cancelled temporary request claimed success or retained ownership");g_free(id);
    id=new_id();start_speed(&speed,id);speed_read(&speed,"speed-failed",id,TRUE,FALSE);check(speed.comparison_complete&&strstr(gtk_label_get_text(GTK_LABEL(speed.status)),"restoration")!=NULL&&strstr(gtk_label_get_text(GTK_LABEL(speed.status)),"Finished")==NULL,"Failed comparison claimed completed throughput or restoration");
    guint64 previous_generation=speed.request_generation;replacement_id=new_id();replacement_speed=&speed;speed_replace_callback=TRUE;LinuxAsyncActionsV16*speed_owner=linux_async_state_v16(&speed_app);speed_owner->changed=replace_speed;
    char*release=g_strdup_printf("release-primary-%s",id);mark(release);g_free(release);finish_speed(&speed);check(speed.request_generation!=previous_generation&&speed.worker!=NULL&&speed.request_body!=NULL&&strstr(speed.request_body,replacement_id)&&strcmp(gtk_button_get_label(GTK_BUTTON(speed.run)),"Cancel test")==0,"Old finish callback revived or damaged the replacement test");speed_owner->changed=NULL;g_free(id);
    phase("held-speed-close",replacement_id,FALSE);linux_speed_lab_comparison_v25(&speed);wait_file("started-held-speed-close");linux_speed_lab_destroy_v12(NULL,&speed);check(speed.closed&&speed.worker==NULL&&speed.comparison_progress==NULL&&!speed.owns_slot&&speed.poll_source==0,"Actual dialog Close retained a request or status worker");wait_file("cancelled-held-speed-close");g_free(replacement_id);replacement_id=NULL;
    gtk_widget_destroy(speed_app.window);g_object_unref(speed_app.window);json_object_unref(speed_node);g_free(speed_body);curl_global_cleanup();printf("GTK actual comparison submit/worker/progress/Cancel/Close/finalizer: %u checks PASS\n",checks);return 0;}
'''


MUTATIONS = {
    'missing-request': ('client/linux/routervpn-comparison-progress-v25.h',
                        'g_strcmp0(linux_comparison_string_v25(progress, "request_id"), expected) != 0 ||', 'FALSE ||'),
    'missing-generation': ('client/linux/routervpn-async-actions-v16.inc',
                           's->progress_generation == generation &&', 's->generation == generation &&'),
    'unowned-speed-stop': ('client/linux/routervpn-speed-lab-v12.inc',
                           'if (generation == 0 || generation != s->request_generation) return;', 'if (generation == 0) return;'),
    'late-speed-finish': ('client/linux/routervpn-speed-lab-v12.inc',
                          'if (s->closed || s->request_generation != generation || s->worker != NULL) return G_SOURCE_REMOVE;',
                          'if (s->closed) return G_SOURCE_REMOVE;'),
    'late-public-stop': ('client/linux/routervpn-async-actions-v16.inc',
                         'if (s->changed != NULL) s->changed(s->app);\n        }\n        return;',
                         'if (s->changed != NULL) s->changed(s->app);\n            if (complete) { rv_http_cancel_v16(s->progress); rv_http_free_v16(s->progress); s->progress = NULL; }\n        }\n        return;'),
    'missing-cancel': ('client/linux/routervpn-async-actions-v16.inc',
                       'rv_http_cancel_v16(s->primary); rv_http_cancel_v16(s->progress);\n    }',
                       'rv_http_cancel_v16(s->primary);\n    }'),
}


def run_case(work, name):
    fixture = work/name
    fixture.mkdir()
    errors, hits, cancellations = [], [], []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_):
            pass

        def handle(self):
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                pass

        def respond(self, status, data):
            self.send_response(status)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            self.close_connection = True

        def wait_owned(self, mode, rest=None):
            (fixture/('started-'+mode)).write_text('ready')
            until = time.monotonic()+6
            while time.monotonic()<until:
                if (fixture/('release-'+mode)).exists():
                    if rest is not None:
                        self.wfile.write(rest); self.wfile.flush()
                    return True
                try:
                    readable = select.select([self.connection], [], [], .01)[0]
                    closed = readable and not self.connection.recv(1, socket.MSG_PEEK)
                except ConnectionResetError:
                    closed = True
                if closed:
                    cancellations.append(mode)
                    (fixture/('cancelled-'+mode)).write_text('closed')
                    return False
            errors.append(mode+' did not close or finish')
            return False

        def do_POST(self):
            try:
                hits.append(self.path)
                size = int(self.headers.get('Content-Length', '0'))
                value = json.loads(self.rfile.read(size))
                if self.path not in ('/api/external-profile/connect','/api/speed-lab/run'):
                    raise AssertionError('Unexpected POST '+self.path)
                mode = 'primary-'+value['comparison_request_id']
                if self.wait_owned(mode):
                    self.respond(409, b'{"error":"fixture terminal failure"}')
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as error:
                errors.append(str(error))

        def do_GET(self):
            try:
                hits.append(self.path)
                if self.path != '/api/multihop/status':
                    raise AssertionError('Redirect or foreign URL followed: '+self.path)
                phase = json.loads((fixture/'phase').read_text())
                mode = phase['mode']
                progress = {'id':'opaque-server-id','request_id':phase['request_id'],'stage':mode,
                            'complete':phase['complete'],'last_node_measurement':'tor-last-relay-http',
                            'external_measurement':'same-captured-endpoint-http',
                            'measurements':[{'candidate':{'execution':'local','transport':'tor'},
                                             'eligible':True,'last_node_ms':20,'external_ms':40,'score_ms':30}]}
                if mode == 'wrong-request': progress['request_id'] = 'f'*32
                if mode == 'missing-request': progress.pop('request_id')
                if mode == 'typed-request': progress['request_id'] = 1
                if mode == 'wrong-last': progress['last_node_measurement'] = 'icmp'
                if mode == 'wrong-external': progress['external_measurement'] = 'other-endpoint-http'
                if mode == 'typed-complete': progress['complete'] = 'true'
                if mode == 'speed-failed': progress['failure'] = 'No valid candidate'
                if mode == 'redirect':
                    self.send_response(302);self.send_header('Location','/must-not-follow');self.send_header('Content-Length','0');self.end_headers();return
                data = json.dumps({'comparison':progress}).encode()
                if mode == 'oversized': data = b' '*32769+data
                if mode.startswith('held-'):
                    self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data[:1]);self.wfile.flush()
                    self.wait_owned(mode,data[1:])
                else:
                    self.respond(200,data)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as error:
                errors.append(str(error))

    # Never reuse or stop an existing controller on this port.
    server = ThreadingHTTPServer(('127.0.0.1',8788),Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True)
    thread.start()
    try:
        include = fixture/'include'; include.mkdir()
        for path in ('routervpn-async-actions-v16.inc','routervpn-http-job-v16.h','routervpn-comparison-progress-v25.h'):
            (include/path).write_bytes((ROOT/'client/linux'/path).read_bytes())
        source = program()
        if name != 'baseline':
            path, old, new = MUTATIONS[name]
            if path.endswith('routervpn-speed-lab-v12.inc'):
                assert source.count(old) == 1, (name,'source anchor drift')
                source = source.replace(old,new)
            else:
                target = include/Path(path).name
                text = target.read_text()
                assert text.count(old) == 1, (name,'include anchor drift')
                target.write_text(text.replace(old,new))
        cfile,binary = fixture/'test.c',fixture/'test'
        cfile.write_text(source)
        flags = shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','gtk+-3.0','json-glib-1.0','libcurl'],text=True))
        subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-pthread','-I'+str(include),str(cfile),'-o',str(binary),*flags,'-lm'],check=True,timeout=45)
        result = subprocess.run(['xvfb-run','-a',str(binary),str(fixture)],capture_output=True,text=True,timeout=40,
                                env=dict(os.environ,http_proxy='http://127.0.0.1:1',ALL_PROXY='http://127.0.0.1:1'))
        if name == 'baseline':
            if result.returncode: raise AssertionError(result.stdout+result.stderr)
            assert not errors, errors
            assert all(hit in ('/api/external-profile/connect','/api/speed-lab/run','/api/multihop/status') for hit in hits), hits
            assert len(cancellations)>=10, cancellations
            print(result.stdout.strip(),flush=True)
        else:
            expected = {
                'missing-request':'Unowned or malformed progress changed the public UI',
                'missing-generation':'A stale action generation changed the public UI',
                'unowned-speed-stop':'Old temporary finalizer cancelled a replacement observer',
                'late-speed-finish':'Old finish callback revived or damaged the replacement test',
                'missing-cancel':'Captured cancel did not cancel its status reader',
                'late-public-stop':'Old terminal callback retired the replacement owner',
            }[name]
            output = result.stdout+result.stderr
            assert result.returncode and 'comparison owner assertion: '+expected in output, (name,result.returncode,output)
            print('Rejected executable GTK progress mutation '+name+': '+expected,flush=True)
    finally:
        server.shutdown();server.server_close();thread.join(timeout=2)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-only',action='store_true')
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='routervpn-gtk-comparison-') as directory:
        work=Path(directory)
        run_case(work,'baseline')
        if not args.baseline_only:
            for name in MUTATIONS:
                run_case(work,name)
    print('GTK captured public/temporary comparison: actual HTTP, bounded reader and exact owner cleanup PASS',flush=True)


if __name__=='__main__':
    main()
