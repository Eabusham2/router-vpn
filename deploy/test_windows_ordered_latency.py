#!/usr/bin/env python3
"""Shipping PowerShell ownership/receipt checks, actual HTTP and Windows WPF.

The HTTP fixture models the authenticated controller's native drain receipts;
it does not execute a tunnel. WPF executes only on Windows, in both CI shells.
"""
from pathlib import Path
import argparse
import contextlib
import http.server
import json
import os
import subprocess
import tempfile
import threading
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "client/RouterVPN-Windows-SpeedLab.ps1"
TEST = ROOT / "client/test-windows-ordered-latency.ps1"
CAPTURE = dict(session_id="session-1794630000000-7", profile_id="home-a", profile_token="a"*64,
               source_sha256="b"*64, config_sha256="c"*64, generation_sha256="d"*64)
NODES = [dict(node_id=f"node-{p}", position=p, role=("entry", "intermediate", "exit")[p], label=f"Hop {p+1}",
              kind="public-path" if p == 1 else "private-node",
              measurement="routed-https-response-after-tls" if p == 1 else "routed-private-response-including-connection") for p in range(3)]

def receipt(request="e"*32, position=0):
    node = NODES[position]
    return dict(schema=1, position=position, source_sha256=CAPTURE["source_sha256"], config_sha256=CAPTURE["config_sha256"],
                generation_sha256=CAPTURE["generation_sha256"], node_id=node["node_id"], request_id=request, measured_at=int(time.time()*1000)-100,
                result=dict(node_id=node["node_id"], role=node["role"], kind=node["kind"], label="Cumulative path through custom node 2 of 3 → Cloudflare edge" if position == 1 else f"Cumulative path through node {position+1} of 3", ready=True,
                  benchmark=dict(schema=1, measurement=node["measurement"], endpoint="https://speed.cloudflare.com/__down?bytes=1" if position == 1 else "",
                                 attempts=50, failed=0, trimmed_mean_ms=12.0,
                                 distribution=dict(samples=50,min_ms=10.0,median_ms=11.0,average_ms=12.0,p90_ms=15.0,max_ms=20.0,jitter_ms=.5))))

@contextlib.contextmanager
def controller(scenario):
    state = dict(request="", position=0, admitted=False, cancelled=False, polls=0, cancel_polls=0, failures=[], bodies=[])
    lock = threading.Lock()
    def view(stage="idle", complete=True, drained=True):
        return dict(schema=1,capture=CAPTURE.copy(),nodes=NODES,history=[receipt()],request_id=state["request"],
                    node_id=f"node-{state['position']}" if state["request"] else "",position=state["position"],
                    status=dict(request_id=state["request"],stage=stage,complete=complete,drained=drained,
                                failure="cancelled" if stage == "cancelled" else "",results=[]))
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *_): pass
        def reply(self, code, value):
            raw = json.dumps(value).encode()
            try:
                self.send_response(code);self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)));self.send_header("Connection", "close");self.end_headers();self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError): pass
        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            if url.path != "/api/speed-lab/ordered-latency":
                state["failures"].append("foreign GET");return self.reply(400,{})
            request = urllib.parse.parse_qs(url.query).get("request_id", [""])[0]
            with lock:
                if not request: return self.reply(200,view())
                if request != state["request"]: return self.reply(404,{})
                if state["cancelled"]:
                    state["cancel_polls"] += 1
                    return self.reply(200,view("cancelled", True, not state["admitted"] or state["cancel_polls"] >= 3))
                state["polls"] += 1
                if scenario == "transport" and state["polls"] == 1: return self.reply(503,{"error":"fixture request failed"})
                if state["polls"] == 1: return self.reply(200,view("draining", True, False))
                value = view("complete");value["receipt"] = receipt(request,state["position"])
                if scenario == "partial": value["receipt"]["result"]["benchmark"]["distribution"]["samples"] = 49
                if scenario == "foreign": value["capture"]["generation_sha256"] = "f"*64
                return self.reply(200,value)
        def do_POST(self):
            try:
                length=int(self.headers.get("Content-Length","0"));assert 0 < length < 4096
                body=json.loads(self.rfile.read(length));assert set(body)=={"capture","node_id","position","request_id"}
                assert body["capture"] == CAPTURE;position=body["position"];assert type(position) is int and 0 <= position <= 2
                assert body["node_id"] == f"node-{position}"
                request=body["request_id"];assert len(request)==32 and set(request)<=(set("0123456789abcdef"))
                if self.path not in ("/api/speed-lab/ordered-latency", "/api/speed-lab/ordered-latency/cancel"): raise AssertionError("foreign POST")
            except (AssertionError, ValueError, KeyError) as error:
                state["failures"].append(str(error) or "request identity");return self.reply(400,{})
            if self.path.endswith("/cancel"):
                with lock:
                    assert not state["request"] or state["request"] == request
                    state.update(request=request,position=position,cancelled=True);state["bodies"].append(body)
                    return self.reply(202 if state["admitted"] else 200,view("cancelled",True,not state["admitted"]))
            if scenario == "early": time.sleep(.4)
            with lock:
                assert not state["request"] or state["request"] == request
                state.update(request=request,position=position);state["bodies"].append(body)
                if state["cancelled"]: return self.reply(409,{"error":"queued Start tombstoned"})
                state["admitted"] = True
                return self.reply(202,view("starting",False,False))
    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = False
        block_on_close = True
    server=Server(("127.0.0.1",0),Handler);thread=threading.Thread(target=server.serve_forever);thread.start()
    try: yield f"http://127.0.0.1:{server.server_address[1]}",state
    finally: server.shutdown();server.server_close();thread.join()

CONTROLS = {
    "foreign_capture": ("if([string](Get-RouterVPNOrderedValue $Capture $Key)-cne[string](Get-RouterVPNOrderedValue $State.Capture $Key))", "if($false)"),
    "premature_drain": ("$Finished=$Complete-and$Drained", "$Finished=$Complete"),
    "partial_fifty": ("(Get-RouterVPNOrderedValue $Distribution 'samples') 50 50 -Integer", "(Get-RouterVPNOrderedValue $Distribution 'samples') 0 50 -Integer"),
    "unjoined_http": ("return $State.Drained-and$State.Jobs.Count-eq0", "return $State.Drained"),
    "invalidated_history": ("if($State.Invalid){$State.Status='The original test finished", "if($false){$State.Status='The original test finished"),
    "invalidated_drain": ("if(-not$Finished-or$Stage-cne'complete'", "if(-not$Finished-or$State.Invalid-or$Stage-cne'complete'"),
}

def run(shell, arguments, *, broken=False):
    command=[shell,"-NoLogo","-NoProfile","-NonInteractive"]
    if os.name == "nt": command.append("-STA")
    command += ["-File",str(TEST),*arguments]
    result=subprocess.run(command,capture_output=True,text=True,timeout=50)
    if (result.returncode == 0) == broken or (broken and "ORDERED CONTROL" not in result.stdout+result.stderr):
        raise AssertionError(f"Wrong executable verdict {command}:\n{result.stdout}{result.stderr}")
    print(result.stdout.strip() if not broken else "Rejected "+arguments[-1],flush=True)
    return dict(exit=result.returncode,stdout=result.stdout.strip(),stderr=result.stderr.strip())

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--shell",default="pwsh");parser.add_argument("--self-test",action="store_true");args=parser.parse_args()
    results=[dict(case="shipping-model",**run(args.shell,[]))]
    for scenario in ("success","public","exit","early","cancel","owner-close","partial","foreign","transport"):
        with controller(scenario) as (base,state):
            result=run(args.shell,["-Live","-Scenario",scenario,"-BaseUrl",base])
            if state["failures"] or not state["bodies"]: raise AssertionError(state)
            if scenario in ("early","cancel","owner-close","partial","foreign","transport") and not state["cancelled"]: raise AssertionError("missing exact cancellation")
            if scenario == "early" and state["admitted"]: raise AssertionError("queued Start escaped cancellation tombstone")
            results.append(dict(case=scenario,**result))
    if args.self_test:
        with tempfile.TemporaryDirectory(prefix="routervpn-ordered-windows-") as value:
            for name,(before,after) in CONTROLS.items():
                source=SOURCE.read_text()
                if source.count(before)!=1: raise AssertionError(f"control {name} no longer has one causal target")
                path=Path(value)/(name+".ps1");path.write_text(source.replace(before,after,1))
                results.append(dict(case=name,**run(args.shell,["-Source",str(path)],broken=True)))
    print(json.dumps(dict(scope="shipping PowerShell model and actual loopback HTTP; WPF only on Windows",results=results),indent=2))

if __name__ == "__main__": main()
