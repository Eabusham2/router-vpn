#!/usr/bin/env python3
"""Execute shipping ordered-fifty history/transaction/retained IPC owner; native/OS boundaries doubled."""
from pathlib import Path
import subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
BOUNDARY=r'''
import Foundation
import CoreFoundation
func fault()->NSError{NSError(domain:"OrderedBoundary",code:1)}
enum IOSExternalExecution { static func validatePrivateNodeJSON(_ data:Data)throws{_ = try JSONSerialization.jsonObject(with:data)} }
func LibboxRouterValidatePrivateNodeJSON(_ raw:String,_ error:inout NSError?)->Bool{do{_ = try JSONSerialization.jsonObject(with:Data(raw.utf8));return true}catch{return false}}
@MainActor enum IOSPrivateJSONStore {
 static var value:Data?,writeHook:(()->Void)?,writes=0
 static func read(_ filename:String,maximumBytes:Int)throws->Data?{value}
 static func write(_ data:Data,filename:String,maximumBytes:Int)throws{guard data.count<=maximumBytes else{throw fault()};value=data;writes+=1;writeHook?()}
 static func remove(_ filename:String)throws{value=nil}
}
final class LibboxRouterOrderedLatency:@unchecked Sendable {
 var cancels=0,closes=0,starts=0,drains=0,closeFailures=0,startFails=false,raw="",saved=""
 func start(_ request:String,nodeID:String)throws{starts+=1;if startFails{throw fault()}}
 func cancel(_ request:String){cancels+=1}
 func drain(_ request:String)throws{drains+=1}
 func statusJSON()->String{raw}
 func savedJSON(_ node:String)->String{saved}
 func close()throws{closes+=1;if closeFailures>0{closeFailures-=1;throw fault()}}
}
func json(_ value:Any)->String{String(data:try! JSONSerialization.data(withJSONObject:value,options:[.sortedKeys]),encoding:.utf8)!}
func receipt(_ position:Int=1,_ request:String=String(repeating:"a",count:32),_ at:Int64=1000)->[String:Any]{
 let id=["entry","middle","final"][position]
 let distribution:[String:Any]=["samples":50,"min_ms":1,"median_ms":2,"average_ms":2.5,"p90_ms":4,"max_ms":5,"jitter_ms":1]
 let benchmark:[String:Any]=["schema":1,"measurement":position==1 ? "routed-https-response-after-tls":"routed-private-response-including-connection","endpoint":position==1 ? "https://speed.cloudflare.com/__down?bytes=1":"","attempts":50,"failed":0,"distribution":distribution,"trimmed_mean_ms":2.25]
 let result:[String:Any]=["node_id":id,"role":position==0 ? "entry":position==2 ? "exit":"intermediate","kind":position==1 ? "public-path":"private-node","label":position==1 ? "Cumulative path through custom node 2 of 3 → Cloudflare edge":"Cumulative path through node \(position+1) of 3","ready":true,"benchmark":benchmark]
 return ["schema":1,"source_sha256":String(repeating:"1",count:64),"config_sha256":String(repeating:"2",count:64),"generation_sha256":String(repeating:"3",count:64),"position":position,"node_id":id,"request_id":request,"measured_at":at,"result":result]
}
func status(_ value:[String:Any])->String{json(["request_id":value["request_id"]!,"stage":"complete","complete":true,"drained":true,"results":[value["result"]!]])}
func request(_ suffix:String="a",operation:String="ordered-latency-open")->RouterVPNOrderedLatencyRequest{
 RouterVPNOrderedLatencyRequest.parse(Data(json(["operation":operation,"request_id":String(repeating:suffix,count:32),"session_id":"00000000-0000-0000-0000-000000000001","owner":String(repeating:"b",count:32),"lease":String(repeating:"c",count:32),"source_sha256":String(repeating:"1",count:64),"config_sha256":String(repeating:"2",count:64),"node_id":"middle"]).utf8))!
}
'''
TESTS=r'''
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ name:String,_ value:Bool){if !value{fatalError(name)};checks+=1}
 @MainActor static func rejects(_ name:String,_ operation:()throws->Void){do{try operation();fatalError(name)}catch{checks+=1}}
 @MainActor static func records()throws {
  for p in 0..<3 {let r=try IOSOrderedLatencyRecord(json(receipt(p)));check("exact50 captured node",r.position==p && r.median==2 && r.trimmed==2.25)}
  for count in 2...8 { for position in 0..<count {
   var value=receipt(0);value["position"]=position;value["node_id"]="ordinary-\(position)"
   var row=value["result"] as! [String:Any];row["node_id"]=value["node_id"]!;row["role"]=position==0 ? "entry":position==count-1 ? "exit":"intermediate";row["kind"]="private-node";row["label"]="Cumulative path through node \(position+1) of \(count)";value["result"]=row
   let record=try IOSOrderedLatencyRecord(json(value));check("ordinary count/kind semantics",record.count==count && record.position==position && record.kind=="private-node" && record.detail.contains("including connection establishment"))
   row["role"]=position==0 ? "exit":"entry";value["result"]=row
   rejects("ordinary role bound to captured count"){_ = try IOSOrderedLatencyRecord(json(value))}
  }}
  var mutations:[(String,([String:Any])->[String:Any])]=[]
  for (key,value) in [("schema",2 as Any),("position",8),("source_sha256","bad"),("generation_sha256","bad"),("request_id","bad"),("measured_at",-1),("extra","secret")] {mutations.append((key,{v in var v=v;v[key]=value;return v}))}
  for (key,value) in [("attempts",49 as Any),("failed",1),("endpoint","https://secret.invalid"),("measurement","icmp")] {mutations.append((key,{v in var v=v;var r=v["result"] as! [String:Any];var b=r["benchmark"] as! [String:Any];b[key]=value;r["benchmark"]=b;v["result"]=r;return v}))}
  for (key,value) in [("samples",49 as Any),("min_ms",0),("average_ms",6),("jitter_ms",7),("max_ms",true)] {mutations.append((key,{v in var v=v;var r=v["result"] as! [String:Any];var b=r["benchmark"] as! [String:Any];var d=b["distribution"] as! [String:Any];d[key]=value;b["distribution"]=d;r["benchmark"]=b;v["result"]=r;return v}))}
  for (key,value) in [("label","secret credential" as Any),("ready",false),("role","exit"),("node_id","other"),("download",["bytes":1])] {mutations.append((key,{v in var v=v;var r=v["result"] as! [String:Any];r[key]=value;v["result"]=r;return v}))}
  for (name,mutate) in mutations {rejects("reject invalid receipt "+name){_ = try IOSOrderedLatencyRecord(json(mutate(receipt())))}}
  let r=try IOSOrderedLatencyRecord(json(receipt())),profile=String(repeating:"4",count:64)
  try IOSOrderedLatencyHistory.save(r,profile:profile,current:{})
  let previous=IOSPrivateJSONStore.value
  check("durable complete-source history",try IOSOrderedLatencyHistory.load(profile:profile,source:r.source,config:r.config,position:1,node:r.node)?.raw==r.raw)
  check("foreign profile sees no history",try IOSOrderedLatencyHistory.load(profile:String(repeating:"5",count:64),source:r.source,config:r.config,position:1,node:r.node)==nil)
  rejects("same receipt cannot replace history"){try IOSOrderedLatencyHistory.save(r,profile:profile,current:{})}
  let fresh=try IOSOrderedLatencyRecord(json(receipt(1,String(repeating:"d",count:32),2000)))
  var calls=0
  rejects("post-write source change rolls back"){try IOSOrderedLatencyHistory.save(fresh,profile:profile,current:{calls+=1;if calls==3{throw fault()}})}
  check("previous history survives stale commit",IOSPrivateJSONStore.value==previous)
  let foreign=Data("foreign newer writer".utf8);calls=0
  rejects("rollback cannot replace foreign write"){try IOSOrderedLatencyHistory.save(fresh,profile:profile,current:{calls+=1;if calls==3{IOSPrivateJSONStore.value=foreign;throw fault()}})}
  check("foreign writer retained",IOSPrivateJSONStore.value==foreign)
  IOSPrivateJSONStore.value=previous
  var old=receipt();old["result"]=(receipt(0)["result"]!);rejects("status result must equal saved"){
   _ = try IOSOrderedLatencyRecord.completed(status:status(old),saved:r.raw,source:r.source,config:r.config,node:r.node,position:1,request:r.request)
  }
 }
 @MainActor static func owners()throws {
  let r=request(),owner=RouterVPNOrderedLatencyOwner(r,current:{}),native=LibboxRouterOrderedLatency()
  native.saved=json(receipt());native.raw=status(receipt());native.closeFailures=1
  do{try owner.open{retain in retain(native)}}catch{fatalError("original returned facade was not retained")}
  _ = try owner.response(start:true)
  check("native exact request started",native.starts==1 && native.drains==1)
  rejects("failed facade close stays retained"){try owner.close()}
  check("failed close not acknowledged",!owner.isClosed())
  try owner.close();check("same facade retried",owner.isClosed() && native.closes==2)
  let late=RouterVPNOrderedLatencyOwner(request("d"),current:{}),lateNative=LibboxRouterOrderedLatency()
  rejects("late factory result rejected"){try late.open{retain in retain(lateNative);late.cancel()}}
  try late.close();check("late returned facade joined",lateNative.closes==1)
  let cancelled=RouterVPNOrderedLatencyOwner(request("e"),current:{});cancelled.cancel();try cancelled.close();var entered=false
  rejects("prefactory cancelled cannot acquire"){try cancelled.open{_ in entered=true}}
  check("cancelled factory never entered",!entered)
  let registry=RouterVPNOrderedLatencyRegistry(),before=request("f",operation:"ordered-latency-close")
  check("cancel before open returns closed",registry.cleanup(before) != nil)
  check("late open cannot reuse cancelled request",!registry.retain(RouterVPNOrderedLatencyOwner(request("f"),current:{})))
  let stale=RouterVPNOrderedLatencyOwner(request("0"),current:{throw fault()});entered=false
  rejects("stale owner no factory"){try stale.open{_ in entered=true}}
  check("stale factory not entered",!entered)
 }
 @MainActor static func transactions()async throws {
  let raw=json(receipt()),r=try IOSOrderedLatencyRecord(raw)
  var events:[String]=[],closes=0
  let t=IOSOrderedLatencyTransaction(request:r.request,source:r.source,config:r.config,node:r.node,position:1,send:{op in
   events.append(op)
   if op=="ordered-latency-open"{return ["opened":true,"closed":false]}
   if op=="ordered-latency-close"{closes+=1;return ["closed":true]}
   return ["status":status(receipt()),"saved":raw]
  },pause:{})
  let result=try await t.run(current:{},update:{_ in})
  check("50 receipt returned only after joined close",result.raw==raw && closes==1 && events.last=="ordered-latency-close")
  var retryCloses=0
  let retry=IOSOrderedLatencyTransaction(request:r.request,source:r.source,config:r.config,node:r.node,position:1,send:{op in
   if op=="ordered-latency-open"{return ["opened":true,"closed":false]}
   if op=="ordered-latency-close"{retryCloses+=1;return ["closed":retryCloses>1]}
   return ["status":status(receipt()),"saved":raw]
  },pause:{})
  do{_ = try await retry.run(current:{},update:{_ in});fatalError("failed close cannot produce new history")}catch{checks+=1}
  check("failed close retries original before returning failure",retryCloses==2)
  var cancelled:IOSOrderedLatencyTransaction!,cleanup=0
  cancelled=IOSOrderedLatencyTransaction(request:r.request,source:r.source,config:r.config,node:r.node,position:1,send:{op in
   if op=="ordered-latency-open"{cancelled.cancel();return ["opened":true,"closed":false]}
   cleanup+=1;return ["closed":true]
  },pause:{})
  do{_ = try await cancelled.run(current:{},update:{_ in});fatalError("cancelled open committed")}catch{checks+=1}
  check("cancelled open still joins original",cleanup==1)
  var current=true
  let stale=IOSOrderedLatencyTransaction(request:r.request,source:r.source,config:r.config,node:r.node,position:1,send:{op in
   if op=="ordered-latency-open"{return ["opened":true,"closed":false]}
   if op=="ordered-latency-close"{current=false;return ["closed":true]}
   return ["status":status(receipt()),"saved":raw]
  },pause:{})
  do{_ = try await stale.run(current:{if !current{throw fault()}},update:{_ in});fatalError("stale close committed")}catch{checks+=1}
 }
 @MainActor static func main()async throws {try records();try owners();try await transactions();print("iOS ordered fifty history + transaction + retained IPC: PASS (\(checks) executable checks; native/file boundaries doubled)")}
}
'''
def sources():
    history=(ROOT/'ios/RouterVPN/App/IOSOrderedLatencyHistory.swift').read_text()
    owner=(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNOrderedLatency.swift').read_text().replace('import Libbox\n','')
    app=(ROOT/'ios/RouterVPN/App/IOSOrderedLatency.swift').read_text()
    transaction=app[app.index('@MainActor final class IOSOrderedLatencyTransaction'):app.index('@MainActor final class IOSOrderedLatency:')]
    return history+owner+transaction

def main():
    source=sources()
    with tempfile.TemporaryDirectory(prefix='ios-ordered-fifty-') as tmp:
        p=Path(tmp);swift=p/'Fixture.swift';binary=p/'fixture'
        def run(text):
            swift.write_text(BOUNDARY+text+TESTS)
            subprocess.run(['swiftc','-j','1','-swift-version','6','-parse-as-library','-module-cache-path',str(p/'modules'),str(swift),'-o',str(binary)],check=True,timeout=90)
            return subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
        result=run(source);assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip(),flush=True)
        for name,before,after,witness in [
            ('exact-fifty','Self.integer(benchmark, "attempts") == 50','Self.integer(benchmark, "attempts") >= 49','reject invalid receipt attempts'),
            ('closed-label','Self.text(result, "label") == label','!label.isEmpty','reject invalid receipt label'),
            ('source-rollback','            try current()\n        } catch {','            // omitted post-write source check\n        } catch {','post-write source change rolls back'),
            ('factory-retain','lock.lock(); native = returned; lock.unlock()','lock.lock(); _ = returned; lock.unlock()','original returned facade was not retained'),
            ('failed-close','        try captured?.close()','        try? captured?.close()','failed facade close stays retained'),
            ('request-tombstone','tombstones[owner.request.key] == nil','true','late open cannot reuse cancelled request'),
            ('failed-close-history','guard cleanClose else { throw CancellationError() }','_ = cleanClose','failed close cannot produce new history'),
            ('post-close-current','        try require(current)\n        guard let receipt','        // omitted original owner check\n        guard let receipt','stale close committed'),
        ]:
            assert source.count(before)==1,name
            result=run(source.replace(before,after,1));assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,result.stdout+result.stderr)
            print('Rejected ordered fifty causal control: '+name,flush=True)
if __name__=='__main__':main()
