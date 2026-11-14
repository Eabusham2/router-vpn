#!/usr/bin/env python3
"""Execute the shipping ordered-fifty Swift model/controller and bounded transport.

The controller's loopback task is an explicit test double; receipts, validation,
late callbacks and cancellation are production code. This is not AppKit, native
tunnel, installed-package or physical-device acceptance.
"""
from pathlib import Path
import argparse
import json
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "client/macos/RouterVPNMacOrderedLatency.swift"
FIXTURE = r'''
import Foundation
import CoreFoundation
var checks = 0
func check(_ value: @autoclosure () -> Bool, _ label: String) {
    checks += 1
    if !value() { fputs("FAIL: \(label)\n", stderr); exit(1) }
}
func rejected(_ label: String, _ run: () throws -> Void) {
    do { try run(); check(false, label) } catch { checks += 1 }
}
func raw(_ value: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: value) }
func decoded(_ value: [String: Any]) throws -> RouterVPNOrderedLatencyReply { try .decode(raw(value)) }
let fixedNow = Date(timeIntervalSince1970: 1794630000)
let capture: [String: Any] = ["session_id":"session-1794630000000-7", "profile_id":"home-a", "profile_token":String(repeating:"a", count:64),
    "source_sha256":String(repeating:"b", count:64), "config_sha256":String(repeating:"c", count:64), "generation_sha256":String(repeating:"d", count:64)]
let nodes: [[String: Any]] = (0..<3).map { position in
    ["node_id":"node-\(position)", "position":position, "role":["entry", "intermediate", "exit"][position], "label":"Hop \(position+1)",
     "kind":position == 1 ? "public-path" : "private-node", "measurement":position == 1 ? "routed-https-response-after-tls" : "routed-private-response-including-connection"]
}
func receipt(_ request: String, _ position: Int = 0) -> [String: Any] {
    ["schema":1, "position":position, "source_sha256":capture["source_sha256"]!, "config_sha256":capture["config_sha256"]!, "generation_sha256":capture["generation_sha256"]!,
     "node_id":"node-\(position)", "request_id":request, "measured_at":Int64(fixedNow.timeIntervalSince1970*1000)-100,
     "result":["node_id":"node-\(position)", "role":nodes[position]["role"]!, "kind":nodes[position]["kind"]!, "label":position == 1 ? "Cumulative path through custom node 2 of 3 → Cloudflare edge" : "Cumulative path through node \(position+1) of 3", "ready":true,
       "benchmark":["schema":1, "measurement":nodes[position]["measurement"]!, "endpoint":position == 1 ? "https://speed.cloudflare.com/__down?bytes=1" : "", "attempts":50, "failed":0, "trimmed_mean_ms":12.0,
         "distribution":["samples":50,"min_ms":10.0,"median_ms":11.0,"average_ms":12.0,"p90_ms":15.0,"max_ms":20.0,"jitter_ms":0.5]]]]
}
func response(_ request: String = "", position: Int = 0, stage: String = "idle", complete: Bool = true, drained: Bool = true,
              saved: [String: Any]? = nil, failure: String = "") -> [String: Any] {
    var value: [String: Any] = ["schema":1,"capture":capture,"nodes":nodes,"history":[receipt(String(repeating:"e",count:32))],
       "node_id":request.isEmpty ? "" : "node-\(position)","position":position,"request_id":request,
       "status":["request_id":request,"stage":stage,"complete":complete,"drained":drained,"failure":failure,"results":[]]]
    if let saved { value["receipt"] = saved }
    return value
}
final class Task: RouterVPNOrderedLatencyTask {
    let url: URL; let body: [String: Any]?; let completion: (Result<Data, Error>) -> Void
    var starts=0, cancels=0
    init(_ url: URL, _ body: [String: Any]?, _ completion: @escaping (Result<Data, Error>) -> Void) { self.url=url;self.body=body;self.completion=completion }
    func start() { starts += 1 }; func cancel() { cancels += 1 }
    func reply(_ value: [String: Any]) throws { completion(.success(try raw(value))) }
}
final class Driver {
    var jobs: [Task] = []; var now = fixedNow; var throwStart = false; var selectionCurrent = true
    lazy var controller = RouterVPNMacOrderedLatencyController(base:URL(string:"http://127.0.0.1:8788")!,profileID:"home-a",clock:{[unowned self] in self.now},selectionCurrent:{[unowned self] in self.selectionCurrent},factory:{[unowned self] url,body,timeout,reply in
        check(timeout == 6,"original bounded HTTP request")
        if self.throwStart && body != nil { throw NSError(domain:"test",code:1) }
        let task=Task(url,body,reply);self.jobs.append(task);return task
    })
    func open() throws { controller.open();try jobs[0].reply(response());pump();check(controller.canRetest,"capture enables explicit retest") }
    func pump() { for _ in 0..<3 { _ = RunLoop.current.run(mode:.default,before:Date().addingTimeInterval(0.005)) } }
    func stop() { for task in jobs { task.completion(.failure(NSError(domain:"closed test",code:1))) };pump();if controller.closeReady { controller.stop() } }
}


// Paired paths retain every real position; the middle of a private three-node
// path is not the special imported HTTPS endpoint.
func pairedNodes(_ count: Int) -> [[String: Any]] {
    (0..<count).map { position in
        ["node_id":"node-\(position)", "position":position, "role":position == 0 ? "entry" : position == count-1 ? "exit" : "intermediate",
         "label":"Private hop \(position+1)", "kind":"private-node", "measurement":"routed-private-response-including-connection"]
    }
}
func pairedReceipt(_ count: Int, _ position: Int, _ request: String) -> [String: Any] {
    var saved=receipt(request), result=saved["result"] as! [String:Any]
    let node=pairedNodes(count)[position]
    saved["position"]=position;saved["node_id"]=node["node_id"]!
    result["node_id"]=node["node_id"]!;result["role"]=node["role"]!;result["kind"]="private-node"
    result["label"]="Cumulative path through node \(position+1) of \(count)";saved["result"]=result
    return saved
}
for count in 2...8 {
    let rows=pairedNodes(count), owner=Driver();owner.controller.open()
    var info=response();info["nodes"]=rows;info["history"]=[pairedReceipt(count,0,String(repeating:"e",count:32))]
    try owner.jobs[0].reply(info);owner.pump()
    check(owner.controller.canRetest && owner.controller.nodes.count == count,"whole private inventory \(count)")
    let captured=try decoded(info).capture
    for position in 0..<count {
        let node=try JSONDecoder().decode(RouterVPNOrderedLatencyNode.self,from:raw(rows[position]))
        let valid=try JSONDecoder().decode(RouterVPNOrderedLatencyReceipt.self,from:raw(pairedReceipt(count,position,String(repeating:"f",count:32))))
        try node.validate(count:count);try valid.validate(capture:captured,node:node,count:count,current:true,now:fixedNow);checks += 2
        var wrong=pairedReceipt(count,position,String(repeating:"f",count:32)), result=wrong["result"] as! [String:Any]
        var benchmark=result["benchmark"] as! [String:Any], distribution=benchmark["distribution"] as! [String:Any]
        distribution["max_ms"]=2001.0;benchmark["distribution"]=distribution;result["benchmark"]=benchmark;wrong["result"]=result
        rejected("private budget including middle \(count)/\(position)") {try JSONDecoder().decode(RouterVPNOrderedLatencyReceipt.self,from:raw(wrong)).validate(capture:captured,node:node,count:count,current:true,now:fixedNow)}
        result["benchmark"]=(pairedReceipt(count,position,String(repeating:"f",count:32))["result"] as! [String:Any])["benchmark"]!
        result["label"]="Cumulative path through node \(position+1) of \(count == 8 ? 7 : 8)";wrong["result"]=result
        rejected("foreign path length \(count)/\(position)") {try JSONDecoder().decode(RouterVPNOrderedLatencyReceipt.self,from:raw(wrong)).validate(capture:captured,node:node,count:count,current:true,now:fixedNow)}
    }
    owner.controller.retest(position:count-1);let request=owner.controller.requestID
    let terminal=response(request,position:count-1,stage:"complete",saved:pairedReceipt(count,count-1,request))
    try owner.jobs.last!.reply(terminal);owner.pump()
    check(owner.controller.drained && owner.controller.history.contains(where:{$0.position == count-1 && $0.request_id == request}),"last private hop saved through shipping callback \(count)")
    check(owner.controller.requestClose(),"whole private path joined \(count)");owner.controller.stop()
}
for count in [1,9] {
    let owner=Driver();owner.controller.open();var info=response();info["nodes"]=pairedNodes(count);info["history"]=[]
    try owner.jobs[0].reply(info);owner.pump();check(owner.controller.invalid && !owner.controller.canRetest,"unbounded inventory refused")
    check(owner.controller.requestClose(),"refused inventory joined");owner.controller.stop()
}

// Receipt meanings remain separate, exact-fifty and tied to their original path.
let cap = try decoded(response()).capture
check(RouterVPNOrderedCapture.session(cap.session_id),"tracker session remains its real opaque format")
for position in 0..<3 {
    let row=try JSONDecoder().decode(RouterVPNOrderedLatencyNode.self,from:raw(nodes[position]));try row.validate()
    let valid=try JSONDecoder().decode(RouterVPNOrderedLatencyReceipt.self,from:raw(receipt(String(repeating:"f",count:32),position)))
    try valid.validate(capture:cap,node:row,current:true,now:fixedNow);checks += 1
    check(valid.display.contains("50 responses") && !valid.display.contains("ICMP"),"historical response label")
    for change in ["samples","attempts","failed","meaning","endpoint","generation","node","position","future","negative","unordered","budget","jitter","label","idle","download","upload","response"] {
        var bad=receipt(String(repeating:"f",count:32),position), result=bad["result"] as! [String:Any]
        var b=result["benchmark"] as! [String:Any], d=b["distribution"] as! [String:Any]
        switch change {
        case "samples":d["samples"]=49
        case "attempts":b["attempts"]=49
        case "failed":b["failed"]=1
        case "meaning":b["measurement"]="icmp-rtt"
        case "endpoint":b["endpoint"]="https://unselected.invalid/"
        case "generation":bad["generation_sha256"]=String(repeating:"e",count:64)
        case "node":bad["node_id"]="other"
        case "position":bad["position"]=(position+1)%3
        case "future":bad["measured_at"]=Int64(fixedNow.timeIntervalSince1970*1000)+5000
        case "negative":d["min_ms"] = -1
        case "unordered":d["median_ms"]=30
        case "budget":d["max_ms"]=position == 1 ? 5001.0 : 2001.0
        case "jitter":d["jitter_ms"]=11.0
        case "label":result["label"]="wrong metric"
        default:result[change]=[String:Any]()
        }
        b["distribution"]=d;result["benchmark"]=b;bad["result"]=result
        rejected("receipt \(position) \(change)") { try JSONDecoder().decode(RouterVPNOrderedLatencyReceipt.self,from:raw(bad)).validate(capture:cap,node:row,current:true,now:fixedNow) }
    }
}
var wrong=response();var wrongCapture=capture;wrongCapture["session_id"]=String(repeating:"e",count:32);wrong["capture"]=wrongCapture
rejected("ordinary hex session substituted for tracker capture") { _=try decoded(wrong) }
wrong=response();wrong["schema"]=2;rejected("response schema") { _=try decoded(wrong) }
wrong=response(complete:false,drained:true);rejected("drain before completion") { _=try decoded(wrong) }

let empty=Driver();empty.controller.open();var emptyInfo=response();emptyInfo.removeValue(forKey:"history")
try empty.jobs[0].reply(emptyInfo);empty.pump()
check(empty.controller.canRetest && empty.controller.history.isEmpty,"first measurement accepts omitted empty backend history")
check(empty.controller.requestClose(),"empty history view closes");empty.controller.stop()

// Real shipping callback path: an HTTP completion cannot release the owner.
let d=Driver();try d.open();d.controller.retest(position:0);let request=d.controller.requestID;let start=d.jobs.last!
check(start.starts == 1 && (start.body?["request_id"] as? String) == request,"explicit captured start")
try start.reply(response(request,stage:"draining",complete:true,drained:false,failure:"joining"));d.pump()
check(!d.controller.drained && !d.controller.canRetest,"complete without native drain remains owned")
let poll=d.jobs.last!;check(poll.url.query == "request_id="+request,"poll retains original request")
var foreign=response(request,stage:"cancelled",failure:"cancelled");var foreignCapture=capture;foreignCapture["generation_sha256"]=String(repeating:"f",count:64);foreign["capture"]=foreignCapture
try poll.reply(foreign);d.pump();check(!d.controller.drained && d.controller.cancelling,"foreign terminal reply cannot release original")
let cancel=d.jobs.last(where:{$0.url.path.hasSuffix("/cancel")})!;try cancel.reply(response(request,stage:"cancelled",failure:"cancelled"));d.pump()
check(d.controller.drained && d.controller.history.count == 1,"cancel preserves prior history")
check(d.controller.requestClose(),"close after original drain and HTTP join");d.controller.stop()

// Cancel-before-start acknowledgement keeps the original HTTP operation owned.
let queued=Driver();try queued.open();queued.controller.retest(position:1);let oldStart=queued.jobs.last!, qid=queued.controller.requestID
check(!queued.controller.requestClose(),"queued start blocks close")
let qcancel=queued.jobs.last(where:{$0.url.path.hasSuffix("/cancel")})!
try qcancel.reply(response(qid,position:1,stage:"cancelled",failure:"cancelled"));queued.pump()
check(queued.controller.drained && !queued.controller.closeReady,"terminal cancel still joins queued HTTP start")
try oldStart.reply(response(qid,position:1,stage:"starting",complete:false,drained:false));queued.pump()
check(queued.controller.drained && queued.controller.closeReady,"late start cannot revive cancelled test")
check(queued.controller.requestClose(),"queued owner now safely closes");queued.controller.stop()

// Durable success may race a user's Cancel. Show the committed receipt honestly.
let saved=Driver();try saved.open();saved.controller.retest(position:2);let sid=saved.controller.requestID, savedStart=saved.jobs.last!
saved.controller.cancel();let savedCancel=saved.jobs.last!
try savedStart.reply(response(sid,position:2,stage:"complete",saved:receipt(sid,2)));saved.pump()
check(saved.controller.history.contains(where:{$0.request_id==sid}),"durably committed exact receipt retained")
check(saved.controller.message.contains("before cancellation"),"cancel race reports existing durable commit")
try savedCancel.reply(response(sid,position:2,stage:"cancelled",failure:"cancelled"));saved.pump()
check(saved.controller.history.contains(where:{$0.request_id==sid}),"late cancel does not delete committed history")
check(saved.controller.requestClose(),"saved owner closes");saved.controller.stop()

// Selection may change before a completed callback is consumed. Keep cleanup
// authority for the original request while refusing history adoption/retest.
let replaced=Driver();try replaced.open();replaced.controller.retest(position:0)
let rid=replaced.controller.requestID, replacedStart=replaced.jobs.last!
replaced.selectionCurrent=false
try replacedStart.reply(response(rid,stage:"starting",complete:false,drained:false));replaced.pump()
check(replaced.controller.invalid && !replaced.controller.canRetest && !replaced.controller.drained,"replacement is latched before processing completed callbacks")
let replacedCancel=replaced.jobs.last(where:{$0.url.path.hasSuffix("/cancel")})!
let replacedPoll=replaced.jobs.last(where:{$0.url.query == "request_id="+rid})!
var invalidReceipt=receipt(rid);invalidReceipt["generation_sha256"]=String(repeating:"f",count:64)
try replacedPoll.reply(response(rid,stage:"complete",saved:invalidReceipt));replaced.pump()
check(!replaced.controller.drained,"invalidated view still rejects foreign cleanup receipt")
try replacedCancel.reply(response(rid,stage:"complete",saved:receipt(rid)));replaced.pump()
check(replaced.controller.drained && replaced.controller.closeReady,"exact committed original drains invalidated view")
check(replaced.controller.history.count == 1 && replaced.controller.history[0].request_id != rid,"replacement cannot adopt original committed history")
check(!replaced.controller.canRetest && replaced.controller.requestClose(),"invalidated view can close and cannot retest old capture");replaced.controller.stop()

// Failed start construction admitted no HTTP task; the saved record survives.
let construction=Driver();try construction.open();construction.throwStart=true;construction.controller.retest(position:0)
check(construction.controller.drained && construction.controller.canRetest && construction.controller.history.count==1,"factory failure has no phantom owner")
check(construction.controller.requestClose(),"factory failure closes");construction.controller.stop()

// Actual shipping transport validates operation-specific paths, bodies and bounds.
let body:[String:Any]=["capture":capture,"node_id":"node-0","position":0,"request_id":String(repeating:"e",count:32)]
for suffix in ["", "/cancel"] {
    let value=try RouterVPNMacSpeedLabTransport(url:URL(string:"http://127.0.0.1:8788/api/speed-lab/ordered-latency"+suffix)!,body:body,timeout:6){_ in};value.cancel();checks += 1
}
for item in ["extra","position-bool","position-high","request","session","token","timeout","query","cancel-get","foreign"] {
    var b=body, url="http://127.0.0.1:8788/api/speed-lab/ordered-latency", timeout=6.0, get=false
    switch item {
    case "extra":b["other"]=true
    case "position-bool":b["position"]=true
    case "position-high":b["position"]=3
    case "request":b["request_id"]="other"
    case "session":var c=capture;c["session_id"]="other";b["capture"]=c
    case "token":var c=capture;c["profile_token"]="other";b["capture"]=c
    case "timeout":timeout=7
    case "query":url += "?request_id="+String(repeating:"e",count:32)
    case "cancel-get":url += "/cancel";get=true
    default:url="http://example.invalid/api/speed-lab/ordered-latency"
    }
    rejected("transport \(item)") { let value=try RouterVPNMacSpeedLabTransport(url:URL(string:url)!,body:get ? nil:b,timeout:timeout){_ in};value.cancel() }
}
print("PASS \(checks) shipping ordered-fifty checks")
'''

CONTROLS = {
    "three_only": ("(2...8).contains(rows.count)", "rows.count == 3"),
    "private_middle_budget": ("maximum = node.kind == \"public-path\" ? 5000.0 : 2000.0", "maximum = node.position == 1 ? 5000.0 : 2000.0"),
    "foreign_capture": ("reply.capture == capture", "true"),
    "premature_drain": ("let finished = reply.status.complete && reply.status.drained", "let finished = reply.status.complete"),
    "partial_fifty": ("b.attempts == 50, b.failed == 0, d.samples == 50", "b.attempts >= 0, b.failed >= 0, d.samples >= 0"),
    "unjoined_http": ("var closeReady: Bool { drained && tasks.isEmpty }", "var closeReady: Bool { drained }"),
    "invalidated_history": ("if invalid {\n                message =", "if false {\n                message ="),
    "invalidated_drain": ("guard finished, reply.status.stage == \"complete\",", "guard finished, !invalid, reply.status.stage == \"complete\","),
}

def run_case(directory, name, change):
    case = directory / name
    case.mkdir()
    source = SOURCE.read_text()
    marker = "#if canImport(AppKit)"
    if source.count(marker) != 1:
        raise AssertionError("shipping model/AppKit boundary changed")
    # Exercise the exact Foundation model/controller on every host. The full
    # panel remains in build-native-app.sh and requires the real AppKit build.
    source = source.split(marker, 1)[0]
    if change:
        before, after = change
        if source.count(before) != 1:
            raise AssertionError(f"control {name} no longer targets exactly one shipping statement")
        source = source.replace(before, after, 1)
    (case / "Ordered.swift").write_text(source)
    (case / "main.swift").write_text(FIXTURE)
    command = ["swiftc", "-swift-version", "5", "-module-cache-path", str(directory / "module-cache"),
               str(ROOT / "client/macos/RouterVPNMacControllerAuth.swift"),
               str(ROOT / "client/macos/RouterVPNMacSpeedLabTransport.swift"),
               str(case / "Ordered.swift"), str(case / "main.swift"), "-o", str(case / "fixture")]
    build = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if build.returncode:
        raise AssertionError(f"{name} fixture failed to compile:\n{build.stdout}{build.stderr}")
    result = subprocess.run([str(case / "fixture")], capture_output=True, text=True, timeout=30)
    if (result.returncode == 0) != (change is None):
        raise AssertionError(f"{name} wrong verdict {result.returncode}:\n{result.stdout}{result.stderr}")
    if change is not None and "FAIL:" not in result.stderr:
        raise AssertionError(f"{name} failed without its semantic assertion")
    return {"case":name,"exit":result.returncode,"stdout":result.stdout.strip(),"stderr":result.stderr.strip()}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="routervpn-ordered-macos-") as value:
        directory = Path(value)
        rows = [run_case(directory, "shipping", None)]
        if args.self_test:
            rows.extend(run_case(directory, name, change) for name, change in CONTROLS.items())
        print(json.dumps({"scope":"Swift production model/controller with loopback task double; transport constructor validation", "results":rows}, indent=2))

if __name__ == "__main__":
    main()
