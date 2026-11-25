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
let nodes: [[String: Any]] = (0..<3).map { position -> [String: Any] in
    let role: String = ["entry", "intermediate", "exit"][position]
    let label: String = position == 1 ? "Cumulative path through custom node 2 of 3 → Cloudflare edge" : "Cumulative path through node \(position+1) of 3"
    let kind: String = position == 1 ? "public-path" : "private-node"
    let measurement: String = position == 1 ? "routed-https-response-after-tls" : "routed-private-response-including-connection"
    return ["node_id":"node-\(position)", "position":position, "role":role, "label":label, "kind":kind, "measurement":measurement]
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
         "label":"Cumulative path through node \(position+1) of \(count)", "kind":"private-node", "measurement":"routed-private-response-including-connection"]
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

// Every CONNECT prefix count retains its original public penultimate receipt.
for count in 3...8 {
    let middle=count-2, owner=Driver()
    var rows=pairedNodes(count), publicNode=nodes[1]
    publicNode["position"]=middle;publicNode["node_id"]="node-\(middle)"
    publicNode["label"]="Cumulative path through custom node \(middle+1) of \(count) → Cloudflare edge"
    rows[middle]=publicNode
    func saved(_ request:String)->[String:Any] {
        var value=receipt(request,1), result=value["result"] as! [String:Any]
        value["position"]=middle;value["node_id"]=publicNode["node_id"]!
        result["node_id"]=publicNode["node_id"]!;result["label"]=publicNode["label"]!;value["result"]=result
        return value
    }
    owner.controller.open();var info=response();info["nodes"]=rows;info["history"]=[saved(String(repeating:"e",count:32))]
    try owner.jobs[0].reply(info);owner.pump()
    check(owner.controller.canRetest && owner.controller.nodes.count == count,"CONNECT bounded inventory \(count)")
    let capture=try decoded(info).capture,node=try JSONDecoder().decode(RouterVPNOrderedLatencyNode.self,from:raw(publicNode))
    for current in [false,true] {try JSONDecoder().decode(RouterVPNOrderedLatencyReceipt.self,from:raw(saved(String(repeating:"e",count:32)))).validate(capture:capture,node:node,count:count,current:current,now:fixedNow);checks += 1}
    for position in 0..<count where position != middle {
        var misplaced=publicNode;misplaced["position"]=position;misplaced["role"]=position == 0 ? "entry" : position == count-1 ? "exit" : "intermediate"
        misplaced["label"]="Cumulative path through custom node \(position+1) of \(count) → Cloudflare edge"
        if position == 0 || position == count-1 {
            rejected("public row cannot become an endpoint") {try JSONDecoder().decode(RouterVPNOrderedLatencyNode.self,from:raw(misplaced)).validate(count:count)}
        } else {
            let moved = try JSONDecoder().decode(RouterVPNOrderedLatencyNode.self,from:raw(misplaced))
            rejected("original CONNECT receipt cannot move to another interior") {try JSONDecoder().decode(RouterVPNOrderedLatencyReceipt.self,from:raw(saved(String(repeating:"e",count:32)))).validate(capture:capture,node:moved,count:count,current:true,now:fixedNow)}
        }
    }
    var stale=saved(String(repeating:"e",count:32));stale["generation_sha256"]=String(repeating:"f",count:64)
    rejected("CONNECT current result cannot borrow replacement generation") {try JSONDecoder().decode(RouterVPNOrderedLatencyReceipt.self,from:raw(stale)).validate(capture:capture,node:node,count:count,current:true,now:fixedNow)}
    owner.controller.retest(position:middle);let request=owner.controller.requestID
    try owner.jobs.last!.reply(response(request,position:middle,stage:"complete",saved:saved(request)));owner.pump()
    check(owner.controller.drained && owner.controller.history.contains(where:{$0.position == middle && $0.request_id == request}),"CONNECT original callback committed fifty receipt \(count)")
    check(owner.controller.requestClose(),"CONNECT complete owner joins");owner.controller.stop()
}

// Receipt meanings remain separate, exact-fifty and tied to their original path.
let cap = try decoded(response()).capture
check(RouterVPNOrderedCapture.session(cap.session_id),"tracker session remains its real opaque format")
for count in [9,16,96] {
 let roles = (0..<count).map { $0 == 0 || $0 == count-1 || $0 % 4 < 2 ? "private-node" : "public-path" }
 let roleJSON=String(decoding:try JSONEncoder().encode(roles),as:UTF8.self)
 var marker=capture;marker["extended_local_nodes"]=count;marker["local_roles_json"]=roleJSON
 var members=pairedNodes(count),history=[[String:Any]]()
 for i in members.indices {
  let external=roles[i]=="public-path"
  if external {var row=nodes[1];row["position"]=i;row["node_id"]="node-"+String(i);row["label"]="Cumulative path through custom node \(i+1) of \(count) → Cloudflare edge";members[i]=row}
  var measured=receipt(String(format:"%032x",i+1777),external ? 1:0)
  measured["position"]=i;measured["node_id"]=members[i]["node_id"]
  var result=measured["result"] as! [String:Any];for key in ["node_id","kind","role","label"] {result[key]=members[i][key]}
  measured["result"]=result;history.append(measured)
 }
 var info=response();info["nodes"]=members;info["capture"]=marker;info["history"]=history
 let owner=Driver();owner.controller.open();try owner.jobs[0].reply(info);owner.pump()
 check(owner.controller.canRetest && owner.controller.history.count==count && owner.controller.nodes.map(\.kind)==roles,"long private stream roles or original history were lost")
 owner.controller.retest(position:count-2)
 let body=owner.jobs.last!.body!,outgoing=body["capture"] as! [String:Any]
 let actualBody=try JSONSerialization.data(withJSONObject:outgoing,options:[.sortedKeys]),wantedBody=try JSONSerialization.data(withJSONObject:marker,options:[.sortedKeys])
 check(actualBody==wantedBody,"role-bound original capture must survive retest in full")
 for suffix in ["","/cancel"] {
  let url=URL(string:"http://127.0.0.1:8788/api/speed-lab/ordered-latency"+suffix)!
  do {let accepted=try RouterVPNMacSpeedLabTransport(url:url,body:body,timeout:6){_ in};accepted.cancel();checks+=1}
  catch {check(false,"original private role inventory refused by retest or cancel transport")}
  for fault in ["whitespace","array","null","foreign","missing","end","only-public-interiors","no-public","both","selected"] {
   var invalid=marker,q=body
   switch fault {
   case "whitespace":invalid["local_roles_json"]=" "+roleJSON
   case "array":invalid["local_roles_json"]=roles
   case "null":invalid["local_roles_json"]=NSNull()
   case "foreign":invalid["local_roles_json"]=roleJSON.replacingOccurrences(of:"public-path",with:"public-node")
   case "missing":invalid["local_roles_json"]=String(decoding:try JSONEncoder().encode(Array(roles.dropLast())),as:UTF8.self)
   case "only-public-interiors","no-public":
    let unqualified=roles.indices.map{fault=="no-public" || $0==0 || $0==count-1 ? "private-node":"public-path"}
    invalid["local_roles_json"]=String(decoding:try JSONEncoder().encode(unqualified),as:UTF8.self)
   case "end":var changed=roles;changed[0]="public-path";invalid["local_roles_json"]=String(decoding:try JSONEncoder().encode(changed),as:UTF8.self)
   case "both":invalid["paired_prefix_nodes"]=2
   default:invalid["extended_original_nodes"]=count
   }
   q["capture"]=invalid
   rejected("transport admitted a conflicting or malformed private-role inventory"){let task=try RouterVPNMacSpeedLabTransport(url:url,body:q,timeout:6){_ in};task.cancel()}
   var bad=info;bad["capture"]=invalid
   rejected("decoder admitted a conflicting or malformed private-role inventory"){_ = try decoded(bad)}
  }
 }
 for fault in ["stripped","swapped","history","budget"] {
  var bad=info,changed=marker
  if fault=="stripped" {changed.removeValue(forKey:"local_roles_json")}
  if fault=="swapped" {var swapped=roles;swapped.swapAt(3,4);changed["local_roles_json"]=String(decoding:try JSONEncoder().encode(swapped),as:UTF8.self)}
  if fault=="history" {var wrong=history;wrong[3]["position"]=4;bad["history"]=wrong}
  if fault=="budget" {bad["history"]=Array(repeating:history[0],count:129)}
  bad["capture"]=changed
  let refused=Driver();refused.controller.open();try refused.jobs[0].reply(bad);refused.pump()
  check(refused.controller.invalid && !refused.controller.canRetest,"original roles and bounded history must all agree: "+fault)
 }
 var saved=history[count-2];saved["request_id"]=owner.controller.requestID
 var stale=response(owner.controller.requestID,position:count-2,stage:"complete",saved:saved)
 var stripped=marker;stripped.removeValue(forKey:"local_roles_json");stale["capture"]=stripped
 try owner.jobs.last!.reply(stale);owner.pump()
 check(!owner.controller.drained && owner.controller.cancelling && owner.controller.history.count==count && owner.jobs.contains(where:{$0.url.path.hasSuffix("/cancel")}),"changed role inventory must cancel without saving a receipt")
}
for count in [9,16] {
 let owner=Driver(), rows=pairedNodes(count);var info=response(), extended=capture;extended["extended_local_nodes"]=count
 var observed=receipt(String(repeating:"d",count:32));let p=count-2
 observed["position"]=p;observed["node_id"]=rows[p]["node_id"]
 var result=observed["result"] as! [String:Any];for key in ["node_id","kind","role","label"] {result[key]=rows[p][key]};observed["result"]=result
 info["nodes"]=rows;info["capture"]=extended;info["history"]=[observed];owner.controller.open();try owner.jobs[0].reply(info);owner.pump()
 check(owner.controller.history.count==1 && owner.controller.nodes.count==count && owner.controller.canRetest,"all-paired original Local latency was refused")
 var mixed=rows;var foreign=nodes[1];foreign["position"]=1;foreign["label"]="Cumulative path through custom node 2 of "+String(count)+" → Cloudflare edge";mixed[1]=foreign
 let denied=Driver();info["nodes"]=mixed;info["history"]=[];denied.controller.open();try denied.jobs[0].reply(info);denied.pump()
 check(denied.controller.nodes.isEmpty && !denied.controller.canRetest,"mixed public/private long Local history admitted")
 for packets in [1,3,count-2] {
  let driver=Driver();var members=pairedNodes(count),history=[[String:Any]]()
  for i in members.indices {
   let imported=i >= packets && i < count-1
   if imported {var publicRow=nodes[1];publicRow["position"]=i;publicRow["node_id"]="node-"+String(i);publicRow["label"]="Cumulative path through custom node \(i+1) of \(count) → Cloudflare edge";members[i]=publicRow}
   var row=receipt(String(format:"%032x",i+555),imported ? 1:0)
   row["position"]=i;row["node_id"]=members[i]["node_id"]
   var result=row["result"] as! [String:Any];for key in ["node_id","kind","role","label"] {result[key]=members[i][key]};row["result"]=result;history.append(row)
  }
  var marker=extended;marker["paired_prefix_nodes"]=packets;info["capture"]=marker;info["nodes"]=members;info["history"]=history
  driver.controller.open();try driver.jobs[0].reply(info);driver.pump()
  check(driver.controller.history.count==count && driver.controller.nodes.count==count && driver.controller.canRetest,"mixed original source lost its measured roles")
  driver.controller.retest(position:packets)
  let outgoing=(driver.jobs.last!.body!["capture"] as! [String:Any])
  check(outgoing["paired_prefix_nodes"] as? Int==packets,"mixed retest discarded original packet count")
  let body=driver.jobs.last!.body!
  for suffix in ["","/cancel"] {
   do {
    let task=try RouterVPNMacSpeedLabTransport(url:URL(string:"http://127.0.0.1:8788/api/speed-lab/ordered-latency"+suffix)!,body:body,timeout:6){_ in};task.cancel();checks+=1
   } catch {check(false,"transport rejected a measured mixed original position at retest or cancel")}
   for invalid:Any in [true,NSNull(),"3",0,count-1] {
    var foreign=outgoing,bad=body;foreign["paired_prefix_nodes"]=invalid;bad["capture"]=foreign
    rejected("untyped mixed count entered retest or cancel"){let task=try RouterVPNMacSpeedLabTransport(url:URL(string:"http://127.0.0.1:8788/api/speed-lab/ordered-latency"+suffix)!,body:bad,timeout:6){_ in};task.cancel()}
   }
  }
  for malformed:Any in [0,true,NSNull(),count-1,packets+1] {
   let invalid=Driver();marker["paired_prefix_nodes"]=malformed;info["capture"]=marker;invalid.controller.open();try invalid.jobs[0].reply(info);invalid.pump()
   check(!invalid.controller.canRetest,"changed mixed count gained measured roles")
  }
 }
}
// Ordinary Local history includes every independent imported interior. The
// selected Local/Server receipt grammar remains limited to its original path.
for count in Array(3...8) + [9,16] {
    let owner=Driver();var rows=pairedNodes(count), records=[[String:Any]]()
    for position in 1..<(count-1) {
        var node=nodes[1];node["position"]=position;node["node_id"]="node-\(position)"
        node["label"]="Cumulative path through custom node \(position+1) of \(count) → Cloudflare edge";rows[position]=node
        var value=receipt(String(format:"%032x",position+901),1),result=value["result"] as! [String:Any]
        value["position"]=position;value["node_id"]=node["node_id"]!;result["node_id"]=node["node_id"]!;result["label"]=node["label"]!;value["result"]=result;records.append(value)
    }
    owner.controller.open();var info=response();info["nodes"]=rows;info["history"]=records; if count > 8 { var extended = info["capture"] as! [String:Any]; extended["extended_local_nodes"] = count; info["capture"] = extended }
    try owner.jobs[0].reply(info);owner.pump()
    check(owner.controller.canRetest && owner.controller.nodes.count==count && owner.controller.history.count==count-2,"independent imported interior receipt was refused")
    let capture=try decoded(info).capture
    for position in 1..<(count-1) {
        let node=try JSONDecoder().decode(RouterVPNOrderedLatencyNode.self,from:raw(rows[position]))
        let saved=records[position-1]
        for current in [false,true] {try JSONDecoder().decode(RouterVPNOrderedLatencyReceipt.self,from:raw(saved)).validate(capture:capture,node:node,count:count,current:current,now:fixedNow);checks += 1}
        var bad=saved, result=bad["result"] as! [String:Any], benchmark=result["benchmark"] as! [String:Any], distribution=benchmark["distribution"] as! [String:Any]
        distribution["samples"]=49;benchmark["distribution"]=distribution;result["benchmark"]=benchmark;bad["result"]=result
        rejected("independent history requires fifty samples") {try JSONDecoder().decode(RouterVPNOrderedLatencyReceipt.self,from:raw(bad)).validate(capture:capture,node:node,count:count,current:true,now:fixedNow)}
        bad=saved;bad["source_sha256"]=String(repeating:"f",count:64)
        rejected("independent history retains original source") {try JSONDecoder().decode(RouterVPNOrderedLatencyReceipt.self,from:raw(bad)).validate(capture:capture,node:node,count:count,current:true,now:fixedNow)}
        if position != count-2 {for execution in ["local","server"] {
            var selected=rows[position];selected["label"]="Cumulative \(execution) path through custom node \(position+1) of \(count) → Cloudflare edge"
            rejected("independent history cannot borrow selected execution") {try JSONDecoder().decode(RouterVPNOrderedLatencyNode.self,from:raw(selected)).validate(count:count)}
        }}
        if count > 8 && position != count-2 { continue }
        owner.controller.retest(position:position);let request=owner.controller.requestID;var current=saved;current["request_id"]=request
        var terminal=response(request,position:position,stage:"complete",saved:current);terminal["capture"]=info["capture"];try owner.jobs.last!.reply(terminal);owner.pump()
        check(owner.controller.drained && owner.controller.history.contains(where:{$0.position==position && $0.request_id==request}),"independent callback commits exact original receipt")
        // The run-loop timer can issue a simultaneous status request while the
        // start completion is queued. Join that exact request before another hop.
        if let poll=owner.jobs.last(where:{$0.url.query=="request_id="+request}) { try poll.reply(terminal);owner.pump() }

    }
    check(owner.controller.requestClose(),"independent public owner joins");owner.controller.stop()
}

do {
    var rows = nodes, saved = receipt(String(repeating: "e", count: 32), 1)
    rows[0]["kind"] = "public-path"; rows[0]["measurement"] = nodes[1]["measurement"]
    rows[0]["label"] = "Cumulative path through custom node 1 of 3 → Cloudflare edge"
    saved["node_id"] = rows[0]["node_id"]; saved["position"] = 0
    var result = saved["result"] as! [String: Any]
    for key in ["node_id", "role", "label"] { result[key] = rows[0][key] }
    saved["result"] = result
    var info = response(); info["nodes"] = rows; info["history"] = [saved]
    let owner = Driver(), entry = try decoded(info).nodes![0]
    rejected("unbound public entry") { try entry.validate() }
    var misplaced = info, wrong = rows
    wrong[1]["kind"] = "private-node"; wrong[1]["label"] = "Cumulative path through node 2 of 3"
    wrong[1]["measurement"] = "routed-private-response-including-connection"; misplaced["nodes"] = wrong
    rejected("public entry requires public middle") { try owner.controller.receive(decoded(misplaced), kind: "capture") }
    try owner.controller.receive(decoded(info), kind: "capture")
    check(owner.controller.history.count == 1 && owner.controller.nodes[0] == entry, "public entry history displayed")
    owner.controller.retest(position: 0); let request = owner.controller.requestID; saved["request_id"] = request
    try owner.jobs.last!.reply(response(request, position: 0, stage: "complete", saved: saved)); owner.pump()
    check(owner.controller.drained && owner.controller.history.first?.request_id == request, "original public entry retest saved")
    check(owner.controller.requestClose(), "public entry owner drained"); owner.controller.stop()
}

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

// Direct decoded validators reject out-of-range positions before label arithmetic.
var overflowNode=nodes[0];overflowNode["position"]=Int.max
rejected("maximum integer position is a refusal, not an arithmetic trap") { try JSONDecoder().decode(RouterVPNOrderedLatencyNode.self,from:raw(overflowNode)).validate(count:3) }

// Each selected label remains bound to its captured node in current and history replies.
func selectedCapture(_ execution:String, _ rows:[[String:Any]]) throws -> [String:Any] {
    var value=capture
    let selected:[String:Any] = ["schema":1,"source_sha256":capture["source_sha256"]!,"config_sha256":capture["config_sha256"]!,
        "generation_sha256":capture["generation_sha256"]!,"selected_execution":execution,
        "nodes":rows.map { ["node_id":$0["node_id"]!,"position":$0["position"]!,"role":$0["role"]!,"kind":$0["kind"]!] }]
    value["selected_capture"]=String(data:try raw(selected),encoding:.utf8)!
    return value
}
for execution in ["local","server"] {
    for (count,publicSlots) in [(4,[1]),(5,[1,3]),(8,[1,4,6]),(9,Array(1..<8)),(16,Array(1..<15)),(9,[1,2,3,5,6,7]),(16,Array(1..<14))] {
        var rows=pairedNodes(count),history=[[String:Any]]()
        for position in publicSlots {
            var node=nodes[1]; let id="node-\(position)"
            node["position"]=position;node["node_id"]=id;node["label"]="Cumulative path through custom node \(position+1) of \(count) → Cloudflare edge"
            rows[position]=node
            var saved=receipt(String(format:"%032x",position+801),1),result=saved["result"] as! [String:Any]
            saved["position"]=position;saved["node_id"]=id;result["node_id"]=id
            result["label"]=(node["label"] as! String).replacingOccurrences(of:"Cumulative path",with:"Cumulative \(execution) path")
            saved["result"]=result;history.append(saved)
        }
        for i in rows.indices{rows[i]["label"]=(rows[i]["label"] as! String).replacingOccurrences(of:"Cumulative path",with:"Cumulative \(execution) path")}
        var original=try selectedCapture(execution,rows)
        if count > 8 { original["extended_original_nodes"] = count }
        let old=original
        let wire=try JSONSerialization.jsonObject(with:Data((original["selected_capture"] as! String).utf8)) as! [String:Any]
        var seals=publicSlots.map{["position":$0,"tag":"test-public-\($0)","source_sha256":String(format:"%064x",$0)] as [String:Any]}
        func bound(_ seals:[[String:Any]])throws->[String:Any] {
            var capture=old,selected=wire
            selected["multiple_imported"]=["schema":6,"original_source_sha256":String(repeating:"7",count:64),"public":seals] as [String:Any]
            capture["selected_capture"]=String(data:try raw(selected),encoding:.utf8)!;return capture
        }
        original=try bound(seals)
        if count == 9 && publicSlots.count == count - 2 {
            for invalidPrivate in [[1],[2,4]] {
                var wrong = wire
                var inventory = wrong["nodes"] as! [[String:Any]]
                for i in invalidPrivate { inventory[i]["kind"] = "private-node" }
                wrong["nodes"] = inventory
                wrong["multiple_imported"] = ["schema":6,"original_source_sha256":String(repeating:"7",count:64),
                    "public":seals.filter { !invalidPrivate.contains($0["position"] as! Int) }] as [String:Any]
                var bad = original; bad["selected_capture"] = String(data:try raw(wrong),encoding:.utf8)!
                rejected("selected private role borrowed a different complete public inventory") {
                    try JSONDecoder().decode(RouterVPNOrderedCapture.self,from:raw(bad)).validate()
                }
            }
        }
        var info=response();info["capture"]=original;info["nodes"]=rows;info["history"]=history
        let owner=Driver();owner.controller.open()
        do {try owner.controller.receive(decoded(info),kind:"capture")} catch {check(false,"multiple-import selected response lost its public inventory or durable label")}
        check(owner.controller.history.count==publicSlots.count,"multiple-import selected history lost an original public position")
        for position in publicSlots {
            let body:[String:Any]=["capture":original,"node_id":"node-\(position)","position":position,"request_id":String(repeating:"e",count:32)]
            for suffix in ["","/cancel"] {
                do {let task=try RouterVPNMacSpeedLabTransport(url:URL(string:"http://127.0.0.1:8788/api/speed-lab/ordered-latency"+suffix)!,body:body,timeout:6){_ in};task.cancel();checks+=1}
                catch {check(false,"multiple-import selected transport lost its original public hop")}
            }
        }
        seals[0]["position"]=0
        for bad in [old,try bound(seals)] {
            rejected("selected view accepted unbound multiple-import inventory"){try JSONDecoder().decode(RouterVPNOrderedCapture.self,from:raw(bad)).validate()}
            let body:[String:Any]=["capture":bad,"node_id":"node-1","position":1,"request_id":String(repeating:"e",count:32)]
            rejected("selected transport accepted unbound multiple-import inventory"){let task=try RouterVPNMacSpeedLabTransport(url:URL(string:"http://127.0.0.1:8788/api/speed-lab/ordered-latency")!,body:body,timeout:6){_ in};task.cancel()}
        }
        owner.controller.stop()
    }
}
for execution in ["local", "server"] {
    for layout in [0,2,3,4,5,6,7,8] {
        let count = layout == 0 ? 3 : layout
        var rows = layout == 0 ? nodes : pairedNodes(count)
        let originalCapture=try selectedCapture(execution,rows)
        let cap=try JSONDecoder().decode(RouterVPNOrderedCapture.self,from:raw(originalCapture))
        var records = (0..<count).map { layout == 0 ? receipt(String(repeating:"e",count:32),$0) : pairedReceipt(count,$0,String(repeating:"e",count:32)) }
        for position in 0..<count {
            rows[position]["label"] = (rows[position]["label"] as! String).replacingOccurrences(of:"Cumulative path",with:"Cumulative \(execution) path")
            var result=records[position]["result"] as! [String:Any];result["label"]=rows[position]["label"]!;records[position]["result"]=result
            let node=try JSONDecoder().decode(RouterVPNOrderedLatencyNode.self,from:raw(rows[position]))
            let saved=try JSONDecoder().decode(RouterVPNOrderedLatencyReceipt.self,from:raw(records[position]))
            do { try node.validate(count:count);try saved.validate(capture:cap,node:node,count:count,current:true,now:fixedNow);try saved.validate(capture:cap,node:node,count:count,current:false,now:fixedNow);checks += 3 }
            catch { check(false,"canonical selected receipt \(execution)/\(layout)/\(position)") }
            for other in ["ordinary","local","server"] where other != execution {
                var bad=records[position], changed=bad["result"] as! [String:Any]
                let prefix=other == "ordinary" ? "Cumulative path" : "Cumulative \(other) path"
                changed["label"]=(changed["label"] as! String).replacingOccurrences(of:"Cumulative \(execution) path",with:prefix);bad["result"]=changed
                for current in [false,true] { rejected("receipt cannot borrow another selected path") { try JSONDecoder().decode(RouterVPNOrderedLatencyReceipt.self,from:raw(bad)).validate(capture:cap,node:node,count:count,current:current,now:fixedNow) } }
            }
            var badNode=rows[position];badNode["label"]=(node.label).replacingOccurrences(of:"Cumulative \(execution) path",with:"Cumulative auto path")
            rejected("only canonical selected labels are admitted") { try JSONDecoder().decode(RouterVPNOrderedLatencyNode.self,from:raw(badNode)).validate(count:count) }
        }
        let owner=Driver();owner.controller.open();var info=response();info["capture"]=originalCapture;info["nodes"]=rows;info["history"]=[records[0]]
        var uncaptured=info;uncaptured["capture"]=capture
        rejected("selected inventory requires actual facade capture") {try owner.controller.receive(decoded(uncaptured),kind:"capture")}
        for key in ["source_sha256","config_sha256","generation_sha256"] {
            var changed=originalCapture;changed[key]=String(repeating:"f",count:64)
            rejected("selected facade binds \(key)") {try JSONDecoder().decode(RouterVPNOrderedCapture.self,from:raw(changed)).validate()}
        }
        var mixed=info, mixedRows=rows;mixedRows[1]["label"]=(mixedRows[1]["label"] as! String).replacingOccurrences(of:"Cumulative \(execution) path",with:"Cumulative path");mixed["nodes"]=mixedRows
        rejected("mixed selected inventory cannot be captured") { try owner.controller.receive(decoded(mixed),kind:"capture") }
        var foreign=info, wrong=records[0], result=wrong["result"] as! [String:Any];result["label"]=(result["label"] as! String).replacingOccurrences(of:"Cumulative \(execution) path",with:"Cumulative path");wrong["result"]=result;foreign["history"]=[wrong]
        rejected("foreign selected history cannot be captured") { try owner.controller.receive(decoded(foreign),kind:"capture") }
        try owner.jobs[0].reply(info);owner.pump();check(owner.controller.canRetest,"selected callback capture")
        owner.controller.retest(position:count-1);let request=owner.controller.requestID;var saved=records[count-1];saved["request_id"]=request
        check((owner.jobs.last!.body?["capture"] as? [String:Any])?["selected_capture"] as? String == originalCapture["selected_capture"] as? String,"selected request retains opaque native capture")
        var terminal=response(request,position:count-1,stage:"complete",saved:saved);terminal["capture"]=originalCapture
        var wrongTerminal=terminal;wrongTerminal["capture"]=capture
        rejected("selected callback cannot omit original facade") {try owner.controller.receive(decoded(wrongTerminal),kind:"start")}
        try owner.jobs.last!.reply(terminal);owner.pump()
        check(owner.controller.drained && owner.controller.history.contains(where:{$0.request_id == request && $0.result.label == rows[count-1]["label"] as! String}),"selected callback retains exact durable label")
        check(owner.controller.requestClose(),"selected path joins original workers");owner.controller.stop()
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
for position in 0...7 { for suffix in ["", "/cancel"] {
    var capturedBody=body;capturedBody["position"]=position;capturedBody["node_id"]="node-\(position)"
    do { let value=try RouterVPNMacSpeedLabTransport(url:URL(string:"http://127.0.0.1:8788/api/speed-lab/ordered-latency"+suffix)!,body:capturedBody,timeout:6){_ in};value.cancel();checks += 1 }
    catch { check(false,"original bounded hop transport rejected position \(position)") }
} }
// The actual transport must preserve the opaque retained facade, including a
// complete eight-node inventory, before any loopback request can be scheduled.
for execution in ["local", "server"] {
    let rows:[[String:Any]] = (0..<8).map { position in
        ["node_id":"node-\(position)","position":position,"role":position == 0 ? "entry" : position == 7 ? "exit" : "intermediate","kind":position == 6 ? "public-path" : "private-node"]
    }
    let originalCapture=try selectedCapture(execution,rows)
    var selectedBody=body;selectedBody["capture"]=originalCapture;selectedBody["position"]=6;selectedBody["node_id"]="node-6"
    for suffix in ["", "/cancel"] {
        do {let task=try RouterVPNMacSpeedLabTransport(url:URL(string:"http://127.0.0.1:8788/api/speed-lab/ordered-latency"+suffix)!,body:selectedBody,timeout:6){_ in};task.cancel();checks += 1}
        catch {check(false,"actual transport refused complete selected \(execution) capture")}
    }
    for fault in ["source", "config", "generation", "choice", "node", "position", "empty", "unknown", "oversized"] {
        var changedBody=selectedBody, changedCapture=originalCapture
        var selected=try JSONSerialization.jsonObject(with:(originalCapture["selected_capture"] as! String).data(using:.utf8)!) as! [String:Any]
        switch fault {
        case "source":selected["source_sha256"]=String(repeating:"f",count:64)
        case "config":selected["config_sha256"]=String(repeating:"f",count:64)
        case "generation":selected["generation_sha256"]=String(repeating:"f",count:64)
        case "choice":selected["selected_execution"]="auto"
        case "node":changedBody["node_id"]="another-node"
        case "position":changedBody["position"]=5
        case "empty":selected["nodes"]=[]
        case "unknown":selected["secret"]="unexpected"
        default:break
        }
        changedCapture["selected_capture"]=fault == "oversized" ? String(repeating:" ",count:8193) : String(data:try raw(selected),encoding:.utf8)!
        changedBody["capture"]=changedCapture
        rejected("selected transport \(fault)"){let task=try RouterVPNMacSpeedLabTransport(url:URL(string:"http://127.0.0.1:8788/api/speed-lab/ordered-latency")!,body:changedBody,timeout:6){_ in};task.cancel()}
    }
}
for item in ["extra","position-bool","position-high","position-negative","position-fractional","request","session","token","timeout","query","cancel-get","foreign"] {
    var b=body, url="http://127.0.0.1:8788/api/speed-lab/ordered-latency", timeout=6.0, get=false
    switch item {
    case "extra":b["other"]=true
    case "position-bool":b["position"]=true
    case "position-high":b["position"]=8
    case "position-negative":b["position"] = -1
    case "position-fractional":b["position"]=1.5
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
// Exercise the actual transport used by the AppKit candidate editor.
func draftRequest(_ path: String, _ q: [String:Any]?, _ timeout: TimeInterval = 25) throws {
    let task = try RouterVPNMacSpeedLabTransport(url: URL(string:"http://127.0.0.1:8788/api/multihop/draft-candidates"+path)!, body:q, timeout:timeout) { _ in }
    task.cancel()
}
for execution in ["local","server","auto"] {
    for count in [3,9,16,96] {
        let proposed=(0..<count).map { ["id":"candidate-\($0)","mode":$0 == 0 ? "wg":"shadowsocks"] }
        let scope=execution=="local" ? "saved-prefix-local":"draft-complete-selected"
        let tokens=Dictionary(uniqueKeysWithValues: proposed.enumerated().map { ($0.element["id"]!,String(format:"%064x",$0.offset+1)) })
        let catalog:[String:Any]=["nodes":proposed,"execution":execution,"expected_profile_tokens":tokens,"expected_selected_node_id":proposed.last!["id"]!]
        let path="/catalog?prefix_position=0&scope="+scope, request=String(repeating:"a",count:32), view=String(repeating:"b",count:64)
        try draftRequest(path,catalog)
        let run:[String:Any]=["scope":scope,"request_id":request,"view_token":view,"prefix_position":0,"candidate_ids":["different"],"samples":50]
        try draftRequest("",run,180);try draftRequest("?request_id="+request,nil)
        try draftRequest("/cancel",["scope":scope,"request_id":request,"view_token":view])
        let choice:[String:Any]=["scope":scope,"request_id":request,"view_token":view,"candidate_id":"different","proposed_path":proposed]
        try draftRequest("/choose",choice)
        var altered=catalog;altered["expected_selected_node_id"]="other"
        rejected("candidate source capture changed its final node"){try draftRequest(path,altered)}
        altered=catalog;altered["expected_profile_tokens"]=["other":view]
        rejected("candidate source tokens changed"){try draftRequest(path,altered)}
        rejected("selected draft scope ignored"){try draftRequest(path.replacingOccurrences(of:scope,with:"saved-complete-local"),catalog)}
        let streamPath=path.replacingOccurrences(of:"position=0",with:"position=1")
        if execution=="local" {try draftRequest(streamPath,catalog);checks+=1}
        else {rejected("selected execution borrowed a Local response prefix"){try draftRequest(streamPath,catalog)}}
        rejected("draft choose became a profile save"){try draftRequest("/save-profile",choice)}
        var wrong=run;wrong.removeValue(forKey:"scope")
        rejected("draft start omitted original scope"){try draftRequest("",wrong,180)}
        if count>8 {
            var rows=proposed;rows[1]["mode"]="socks5";altered=catalog;altered["nodes"]=rows
            rejected("unsupported long candidate family accepted"){try draftRequest(path,altered)}
        }
    }
}
print("PASS \(checks) shipping ordered-fifty checks")
'''

CONTROLS = {
    "drop_local_roles_retest": ('if let local_roles_json { result["local_roles_json"] = local_roles_json }', 'if let local_roles_json { _ = local_roles_json }'),
    "unbound_public_entry": ('rows.map(\\.kind) == ["public-path", "public-path", "private-node"]',
                             'rows[0].kind == "public-path" && rows[2].kind == "private-node"'),
    "imported_position": ("isPublic && count >= 3 && position > 0 && position < count - 1 && (position == count - 2 || receiptKind(count: count) == \"ordinary\" || multipleImported)", "isPublic && count >= 3 && position == count - 2"),
    "connect_three_only": ("isPublic && count >= 3 && position > 0 && position < count - 1 && (position == count - 2 || receiptKind(count: count) == \"ordinary\" || multipleImported)", "isPublic && count == 3 && position == 1"),
    "selected_labels": ('["ordinary", "local", "server"].first', '["ordinary"].first'),
    "selected_receipt": ('result.label == node.label', 'true'),
    # Capture identity and uniform labels jointly reject a mixed initial inventory.
    # This control omits both initial checks; receipt validation remains original.
    "mixed_inventory": ('            for row in rows { try row.validate(count: rows.count, multipleImported: multipleImported, extendedLocalCount: reply.capture.extended_local_nodes, extendedOriginalCount: reply.capture.extended_original_nodes, pairedLocal: pairedLocal, pairedPrefixNodes: reply.capture.paired_prefix_nodes, localRoles: reply.capture.localRoles(), customEntry: customEntry); try reply.capture.validateNode(row, count: rows.count) }\n            guard Set(rows.compactMap { $0.receiptKind(count: rows.count) }).count == 1 else {', '            for row in rows { try row.validate(count: rows.count, multipleImported: multipleImported, extendedLocalCount: reply.capture.extended_local_nodes, extendedOriginalCount: reply.capture.extended_original_nodes, pairedLocal: pairedLocal, pairedPrefixNodes: reply.capture.paired_prefix_nodes, localRoles: reply.capture.localRoles(), customEntry: customEntry) }\n            guard true else {'),
    "three_only": ("reply.capture.admits(count: rows.count)", "rows.count == 3"),
    "private_middle_budget": ("maximum = node.kind == \"public-path\" ? 5000.0 : 2000.0", "maximum = node.position == 1 ? 5000.0 : 2000.0"),
    "foreign_capture": ("reply.capture == capture", "true"),
    "premature_drain": ("let finished = reply.status.complete && reply.status.drained", "let finished = reply.status.complete"),
    "partial_fifty": ("b.attempts == 50, b.failed == 0, d.samples == 50", "b.attempts >= 0, b.failed >= 0, d.samples >= 0"),
    "unjoined_http": ("var closeReady: Bool { drained && tasks.isEmpty }", "var closeReady: Bool { drained }"),
    "invalidated_history": ("if invalid {\n                message =", "if false {\n                message ="),
    "invalidated_drain": ("guard finished, reply.status.stage == \"complete\",", "guard finished, !invalid, reply.status.stage == \"complete\","),
}

def run_case(directory, name, change, transport_change=None):
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
    transport = (ROOT / "client/macos/RouterVPNMacSpeedLabTransport.swift").read_text()
    if transport_change:
        before, after = transport_change
        if transport.count(before) != 1:
            raise AssertionError(f"transport control {name} lost its exact source seam")
        transport = transport.replace(before, after, 1)
    (case / "Transport.swift").write_text(transport)
    (case / "Ordered.swift").write_text(source)
    (case / "main.swift").write_text(FIXTURE)
    command = ["swiftc", "-swift-version", "5", "-module-cache-path", str(directory / "module-cache"),
               str(ROOT / "client/macos/RouterVPNMacControllerAuth.swift"),
               str(case / "Transport.swift"),
               str(case / "Ordered.swift"), str(case / "main.swift"), "-o", str(case / "fixture")]
    build = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if build.returncode:
        raise AssertionError(f"{name} fixture failed to compile:\n{build.stdout}{build.stderr}")
    result = subprocess.run([str(case / "fixture")], capture_output=True, text=True, timeout=30)
    if (result.returncode == 0) != (change is None and transport_change is None):
        raise AssertionError(f"{name} wrong verdict {result.returncode}:\n{result.stdout}{result.stderr}")
    if (change is not None or transport_change is not None) and "FAIL:" not in result.stderr:
        raise AssertionError(f"{name} failed without its semantic assertion")
    return {"case":name,"exit":result.returncode,"stdout":result.stdout.strip(),"stderr":result.stderr.strip()}

TRANSPORT_CONTROLS = {
    "transport_local_roles": ('RouterVPNSelectedPublicInventory.localRoles(capture["local_roles_json"], count: count.intValue) != nil','true'),
    "transport-selected-capture": ("                    selectedCaptureValid() &&\n", "                    true &&\n"),
    "transport-three-only": ("                    position!.doubleValue.rounded() == position!.doubleValue && (0..<(extendedCount?.intValue ?? 8)).contains(position!.intValue)\n", "                    position!.doubleValue.rounded() == position!.doubleValue && (0...2).contains(position!.intValue)\n"),
    "transport-boolean": ("position != nil && CFGetTypeID(position!) != CFBooleanGetTypeID() &&\n", "position != nil && true &&\n"),
    "transport-fractional": ("                    position!.doubleValue.rounded() == position!.doubleValue && (0..<(extendedCount?.intValue ?? 8)).contains(position!.intValue)\n", "                    (0..<(extendedCount?.intValue ?? 8)).contains(position!.intValue)\n"),
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="routervpn-ordered-macos-") as value:
        directory = Path(value)
        rows = [run_case(directory, "shipping", None)]
        if args.self_test:
            rows.extend(run_case(directory, name, change) for name, change in CONTROLS.items())
            rows.extend(run_case(directory, name, None, change) for name, change in TRANSPORT_CONTROLS.items())
        print(json.dumps({"scope":"Swift production model/controller with loopback task double; transport constructor validation", "results":rows}, indent=2))

if __name__ == "__main__":
    main()
