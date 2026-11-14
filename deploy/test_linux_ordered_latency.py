#!/usr/bin/env python3
"""Exercise shipping GTK ordered-latency callbacks and original loopback jobs.

--source-only checks source linkage, never claims GTK/native acceptance. The
mandatory Linux workflow uses --self-test and requires real GTK/json-glib/Xvfb.
"""
from __future__ import annotations
import argparse
import contextlib
import copy
import hashlib
import http.server
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "client/linux/routervpn-ordered-latency-v1.inc"
FIXTURE = ROOT / "client/linux/test-ordered-latency-v1.c"
CAPTURE = dict(session_id="session-123-456", profile_id="exit-a", profile_token="a"*64,
               source_sha256="b"*64, config_sha256="c"*64, generation_sha256="d"*64)
NODES = [dict(node_id=f"node-{i}", position=i, label=f"Hop {i+1}", role=("entry","intermediate","exit")[i],
              kind="public-path" if i == 1 else "private-node",
              measurement="routed-https-response-after-tls" if i == 1 else "routed-private-response-including-connection") for i in range(3)]


def receipt(position, request="e"*32, *, old=False):
    node = NODES[position]
    return dict(schema=1, source_sha256=CAPTURE["source_sha256"], config_sha256=CAPTURE["config_sha256"],
                generation_sha256="f"*64 if old else CAPTURE["generation_sha256"], node_id=node["node_id"], position=position,
                request_id=request, measured_at=int(time.time()*1000)-10000,
                result=dict(node_id=node["node_id"], kind=node["kind"], role=node["role"], ready=True,
                            label="Cumulative path through custom node 2 of 3 → Cloudflare edge" if position == 1 else f"Cumulative path through node {position+1} of 3",
                            benchmark=dict(schema=1, attempts=50, failed=0, measurement=node["measurement"],
                                           endpoint="https://speed.cloudflare.com/__down?bytes=1" if position == 1 else "",
                                           trimmed_mean_ms=3.0, distribution=dict(samples=50, min_ms=1.0, median_ms=3.0,
                                                                                average_ms=3.0, p90_ms=4.0, max_ms=5.0, jitter_ms=0.5))))


def info():
    return dict(schema=1, capture=copy.deepcopy(CAPTURE), nodes=copy.deepcopy(NODES), history=[receipt(0, old=True)],
                status=dict(request_id="", stage="idle", complete=True, drained=True, results=[]))


def ordinary_fixture(count):
    nodes = [dict(node_id=f"node-{i}", position=i, label=f"Private hop {i+1}",
                  role="entry" if i == 0 else "exit" if i == count-1 else "intermediate",
                  kind="private-node", measurement="routed-private-response-including-connection") for i in range(count)]
    receipts = []
    for position, node in enumerate(nodes):
        saved = receipt(0)
        saved.update(node_id=node["node_id"], position=position)
        saved["result"].update(node_id=node["node_id"], role=node["role"], kind=node["kind"],
                               label=f"Cumulative path through node {position+1} of {count}")
        receipts.append(saved)
    return dict(info=dict(schema=1, capture=copy.deepcopy(CAPTURE), nodes=nodes, history=[copy.deepcopy(receipts[0])],
                          status=dict(request_id="", stage="idle", complete=True, drained=True, results=[])), receipts=receipts)


def fixture_data():
    return {'info': info(), **{f'receipt{i}': receipt(i) for i in range(3)},
            'ordinary': [ordinary_fixture(count) for count in range(2, 9)]}


def receipt_model(directory, data):
    # The slice is byte-for-byte production helpers, with no GTK/process mocks
    # inside receipt validation. Native widgets and owned HTTP remain below.
    source = SOURCE.read_text()
    first = 'static const char *linux_ol_string_v1('
    last = 'static void linux_ol_message_v1('
    assert source.count(first) == source.count(last) == 1
    block = source[source.index(first):source.index(last)]
    flags = shlex.split(subprocess.check_output(['pkg-config', '--cflags', '--libs', 'json-glib-1.0'], text=True))
    fixture = ROOT/'client/linux/test-ordered-latency-receipts-v1.c'
    controls = {
        'private-budget': ('double maximum = public_path ? 5000 : 2000;', 'double maximum = position == 1 ? 5000 : 2000;'),
        'path-length': ('g_snprintf(label, sizeof(label), "Cumulative path through node %d of %d", position+1, count);', 'g_snprintf(label, sizeof(label), "Cumulative path through node %d of %d", position+1, 3);'),
    }
    for name, change in [('shipping', None), *controls.items()]:
        text = block
        if change:
            before, after = change
            assert text.count(before) == 1, name
            text = text.replace(before, after, 1)
        include = directory/(name+'-validators.inc'); include.write_text(text)
        binary = directory/(name+'-receipt-model')
        run(['cc', '-O1', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
             '-DROUTERVPN_ORDERED_VALIDATORS="'+str(include)+'"', fixture, '-o', binary, *flags, '-lm'])
        run([binary, data], broken=change is not None)
        if change: print('Rejected changed shipping C receipt validator: '+name, flush=True)


def sources():
    paths = [SOURCE, FIXTURE, ROOT/"client/linux/test-ordered-latency-receipts-v1.c", Path(__file__), ROOT/"client/linux/routervpn-http-job-v16.h",
             ROOT/"client/linux/routervpn-controller-auth-v1.h", ROOT/"client/linux/routervpn-performance-v17.inc",
             ROOT/"client/linux/routervpn-telemetry-v9.inc", ROOT/"client/linux/build-native-app.sh",
             ROOT/".github/workflows/linux-native-app.yml"]
    for path in paths:
        if path.is_symlink() or not path.is_file(): raise AssertionError("Lost original GTK source: "+str(path))
    return {str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def check_sources():
    before = sources(); source = SOURCE.read_text(); build = (ROOT/"client/linux/build-native-app.sh").read_text()
    performance = (ROOT/"client/linux/routervpn-performance-v17.inc").read_text()
    telemetry = (ROOT/"client/linux/routervpn-telemetry-v9.inc").read_text()
    workflow = (ROOT/".github/workflows/linux-native-app.yml").read_text()
    assert '#include "routervpn-ordered-latency-v1.inc"' in performance
    assert '"50 responses per hop"' in performance and 'linux_ordered_latency_open_v1(p->app)' in performance
    assert '*actions[10]' in performance and 'id<10' in performance and 'i<10' in performance
    assert 'ORDERED_LATENCY_INC="$ROOT/client/linux/routervpn-ordered-latency-v1.inc"' in build
    assert build.count('"$ORDERED_LATENCY_INC"') == 2
    assert build.index('G_CALLBACK(linux_ordered_latency_parent_delete_v1)') < build.index('G_CALLBACK(on_delete)', build.index('install_new ='))
    assert 'g_object_get_data(G_OBJECT(w),"ordered-latency-state")!=NULL' in telemetry
    assert 'python3 deploy/test_linux_ordered_latency.py --self-test' in workflow
    assert workflow.count("'deploy/test_linux_ordered_latency.py'") == 2
    for required in ('s->job_generation[kind] == s->generation', '!(s->complete && s->drained)',
                     'linux_ol_same_capture_v1(capture,', 'linux_ol_receipt_v1(json_node_get_object(record), capture, node, (int)json_array_get_length(json_node_get_array(s->nodes)), TRUE)',
                     's->jobs[i] != NULL', 'gtk_window_close(GTK_WINDOW(parent))',
                     'if (s->complete && s->drained) return TRUE;', 'rv_http_free_v16(s->jobs[i])',
                     'g_date_time_format(date, "%Y-%m-%d %H:%M:%S %Z")'):
        assert required in source, required
    assert 'gtk_dialog_run(' not in source and 'gtk_tree_sortable_set_sort_column_id' not in source
    assert '/api/profile/latency' not in source and '/api/profile/fastest' not in source
    assert '#include "routervpn-http-job-v16.h"' in FIXTURE.read_text()
    print("Linux ordered latency source linkage: PASS (GTK execution not claimed)", flush=True)
    return before


def run(args, *, broken=False, timeout=60):
    result = subprocess.run([str(a) for a in args], text=True, capture_output=True, timeout=timeout)
    if broken:
        if result.returncode == 0 or "Ordered latency check failed:" not in result.stdout+result.stderr:
            raise AssertionError("Mutated original guard lacked its causal fixture failure:\n"+result.stdout+result.stderr)
    elif result.returncode:
        raise RuntimeError(result.stdout+result.stderr)
    else:
        print(result.stdout.strip(), flush=True)
    return result


@contextlib.contextmanager
def controller(scenario):
    lock = threading.Lock()
    state = dict(request="", position=1, admitted=False, cancelled=False, polls=0, failures=[], bodies=[], cancels=[])
    def view(stage="measuring", complete=False, drained=False, saved=False):
        value=info(); request=state["request"];position=state["position"]
        value.update(request_id=request,node_id=NODES[position]["node_id"],position=position)
        value["status"]=dict(request_id=request,stage=stage,complete=complete,drained=drained,results=[])
        if saved:value["receipt"]=receipt(position,request)
        return value
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version="HTTP/1.1"
        def log_message(self,*_):pass
        def reply(self,code,value):
            raw=json.dumps(value).encode()
            try:
                self.send_response(code);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(raw)));self.send_header("Connection","close");self.end_headers();self.wfile.write(raw)
            except (BrokenPipeError,ConnectionResetError):pass
        def do_GET(self):
            parsed=urllib.parse.urlsplit(self.path)
            if parsed.path!="/api/speed-lab/ordered-latency":state["failures"].append("foreign GET");return self.reply(400,{})
            request=urllib.parse.parse_qs(parsed.query).get("request_id",[""])[0]
            if not request:return self.reply(200,info())
            with lock:
                if request!=state["request"]:return self.reply(404,{"error":"not yet admitted"})
                state["polls"]+=1
                if scenario=="poll-error" and state["polls"]==1:return self.reply(503,{})
                if scenario=="stale" and state["polls"]==1:
                    value=view();value["capture"]["generation_sha256"]="9"*64;return self.reply(200,value)
                if not state["cancelled"] and scenario in ("saved","partial","missing-receipt"):
                    value=view("complete",True,True,scenario!="missing-receipt")
                    if scenario=="partial":value["receipt"]["result"]["benchmark"]["distribution"]["samples"]=49
                    return self.reply(200,value)
                if state["cancelled"]:
                    if scenario in ("commit-race","replacement-commit"):return self.reply(200,view("complete",True,True,True))
                    return self.reply(200,view("cancelled",True,state["polls"]>=3))
                return self.reply(200,view("finishing",False,False))
        def do_POST(self):
            try:
                length=int(self.headers.get("Content-Length","0"));assert 0<length<4096
                body=json.loads(self.rfile.read(length));assert set(body)=={"capture","node_id","position","request_id"}
                assert body["capture"]==CAPTURE;position=body["position"];assert type(position)is int and 0<=position<=2
                assert body["node_id"]==NODES[position]["node_id"]
                request=body["request_id"];assert isinstance(request,str) and len(request)==32 and set(request)<=set("0123456789abcdef")
                assert self.path in ("/api/speed-lab/ordered-latency","/api/speed-lab/ordered-latency/cancel")
            except (AssertionError,KeyError,ValueError) as e:
                state["failures"].append(str(e) or "request identity");return self.reply(400,{})
            if self.path.endswith("/cancel"):
                with lock:
                    if state["request"] and state["request"]!=request:state["failures"].append("cancel crossed owners");return self.reply(409,{})
                    state.update(request=request,position=position,cancelled=True);state["bodies"].append(body);state["cancels"].append(request)
                    if scenario in ("commit-race","replacement-commit"):return self.reply(200,view("complete",True,True,True))
                    return self.reply(202 if state["admitted"] else 200,view("cancelled",True,not state["admitted"]))
            if scenario=="early":time.sleep(.4)
            with lock:
                if state["request"] and state["request"]!=request:state["failures"].append("Start crossed owners");return self.reply(409,{})
                state.update(request=request,position=position);state["bodies"].append(body)
                if state["cancelled"]:return self.reply(409,{"error":"queued Start tombstoned"})
                state["admitted"]=True
                return self.reply(503,{}) if scenario=="http-error" else self.reply(202,view("starting",False,False))
    class Server(http.server.ThreadingHTTPServer):
        allow_reuse_address=True
        daemon_threads=False
    server=Server(("127.0.0.1",8788),Handler);thread=threading.Thread(target=server.serve_forever);thread.start()
    try:yield state
    finally:
        server.shutdown();server.server_close();thread.join()
        if state["failures"]:raise AssertionError(state["failures"])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source-only',action='store_true');parser.add_argument('--self-test',action='store_true');parser.add_argument('--receipt-model',action='store_true');args=parser.parse_args()
    if args.source_only and (args.self_test or args.receipt_model):parser.error("source-only cannot claim native self-test")
    if args.self_test and args.receipt_model:parser.error("receipt-model cannot replace the full GTK self-test")
    before=check_sources()
    if args.source_only:return
    with tempfile.TemporaryDirectory(prefix='routervpn-c-ordered-receipts-') as temporary:
        directory=Path(temporary);data=directory/'fixture.json';data.write_text(json.dumps(fixture_data()))
        receipt_model(directory,data)
    if args.receipt_model:
        assert sources()==before,'original C receipt source changed during validation'
        return
    missing=[name for name in ('pkg-config','cc','xvfb-run') if not shutil.which(name)]
    if missing:raise RuntimeError("Actual GTK validation unavailable; missing "+', '.join(missing))
    flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','gtk+-3.0','libcurl','json-glib-1.0'],text=True))
    with tempfile.TemporaryDirectory(prefix='routervpn-gtk-ordered-') as temporary:
        directory=Path(temporary);data=directory/'fixture.json';data.write_text(json.dumps(fixture_data()))
        def compile_to(name,text=None,live=False):
            command=['cc','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function','-I'+str(SOURCE.parent)]
            if text is not None:
                include=directory/(name+'.inc');include.write_text(text);command.append('-DROUTERVPN_ORDERED_SOURCE="'+str(include)+'"')
            if live:command.append('-DROUTERVPN_ORDERED_LIVE')
            binary=directory/name;run([*command,FIXTURE,'-o',binary,*flags,'-lm','-pthread']);return binary
        binary=compile_to('shipping');run(['xvfb-run','-a',binary,data])
        source=SOURCE.read_text();mutations={
            'native-drain':('!JSON_NODE_HOLDS_OBJECT(record) || !complete || !drained ||','!JSON_NODE_HOLDS_OBJECT(record) || !complete ||'),
            'http-join':('for (int i = 0; i < OL_JOBS_V1; i++) if (s->jobs[i] != NULL) return FALSE;','/* mutation: unfinished workers ignored */'),
            'capture-owner':('if (g_strcmp0(linux_ol_string_v1(a, keys[i]), linux_ol_string_v1(b, keys[i])) != 0) return FALSE;','if (FALSE) return FALSE;'),
            'partial-fifty':('linux_ol_number_v1(d, "samples", 50, 50, TRUE)','linux_ol_number_v1(d, "samples", 49, 50, TRUE)'),
        }
        for name,(original,replacement) in mutations.items():
            assert source.count(original)==1,name
            mutant=compile_to(name,source.replace(original,replacement,1));run(['xvfb-run','-a',mutant,data],broken=True)
            print('Rejected broken GTK ordered-latency guard: '+name,flush=True)
        live=compile_to('live',live=True)
        for scenario in ('early','accepted','saved','commit-race','http-error','poll-error','stale','partial','missing-receipt','replacement-commit'):
            with controller(scenario) as state:
                run(['xvfb-run','-a',live,scenario],timeout=25)
                assert state['bodies'] and len({b['request_id'] for b in state['bodies']})==1
                if scenario!='saved':assert state['cancels'] and len(set(state['cancels']))==1
                if scenario=='early':assert not state['admitted']
            print('Real GTK/libcurl ordered-latency scenario: '+scenario,flush=True)
    assert sources()==before,'original GTK source changed during validation'
    print('GTK ordered latency: shipping callbacks,4 compiled controls,10 real HTTP scenarios PASS',flush=True)

if __name__=='__main__':main()
