#!/usr/bin/env python3
"""Run Apple candidate capture via the real shared Go input compiler, plus receipts."""
from pathlib import Path
import os
import platform
import subprocess
import tempfile
import test_ios_node_chain_capture as C
from test_ios_physical_path import LINUX_CRYPTO
ROOT=C.ROOT
APP=C.APP
GO=C.GO.replace(' case "chain-imported":', ' case "candidate-supported":value=strconv.FormatBool(mobilemultihop.NodeChainCandidateInputSupported(r.Source))\n case "chain-imported":',1)
LIBBOX=C.LIBBOX+r'''
public func LibboxRouterNodeChainCandidateInputSupported(_ source:String)->Bool{(try? bridge(["Op":"candidate-supported","Source":source])) == "true"}
'''
SWIFT=C.SWIFT[:C.SWIFT.index('@MainActor @main struct Tests')]+r'''
@MainActor final class IOSNodeBundleStore {
 static let shared=IOSNodeBundleStore()
 func candidateSnapshot()throws->(records:[String:Data],stamp:IOSCandidateCatalogPublication.Stamp){throw NSError(domain:"NoPrivateStoreInCaptureFixture",code:1)}
}
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ name:String,_ value:@autoclosure ()throws->Bool)throws{guard try value()else{throw NSError(domain:"CandidateCheck",code:1,userInfo:[NSLocalizedDescriptionKey:name])};checks+=1}
 static func reject(_ name:String,_ action:()throws->Void)throws{do{try action()}catch{checks+=1;return};throw NSError(domain:"CandidateCheck",code:1,userInfo:[NSLocalizedDescriptionKey:"ACCEPTED "+name])}
 static func main(){defer{LibboxTestClose()};do{try run();print("Apple candidates: \(checks) shipping Swift/shared Go capture and receipt checks PASS")}
 catch{FileHandle.standardError.write(Data(("FAIL after \(checks): \(error.localizedDescription)\n").utf8));exit(1)}}
 static func run()throws {
  let prefix=IOSNodeCandidatePrefix(position:0,profile_id:"chain-node-0",node_id:String(repeating:"a",count:64),mode:"wg")
  let tail=IOSNodeCandidatePrefix(position:1,profile_id:"other-final",node_id:String(repeating:"b",count:64),mode:"shadowsocks")
  func compile(_ records:[String:Data],_ proofs:[IOSNodeCandidatePrefix]?=nil)throws->(inventory:Data,rows:[IOSNodeCandidateCapture.Row]){
   let stamp=IOSCandidateCatalogPublication.Stamp(schema:1,epoch:UUID().uuidString,generation:1,ready:true,sources_sha256:try IOSCandidateCatalogPublication.sourcesDigest(records))
   return try IOSNodeCandidateCapture.compile(records:records,stamp:stamp,prefixPosition:0,proofs:proofs ?? [prefix,tail])
  }
  for(method,size)in[("2022-blake3-aes-128-gcm",16),("2022-blake3-aes-256-gcm",32),("2022-blake3-chacha20-poly1305",32)] {
   let fixture=try sources(3).map{try editProfile($0){p in
    p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""
   }}
   var paired=try object(fixture[1]), files=paired["profiles"] as! [String:[String:String]]
   var graph=try object(Data(base64Encoded:files["shadowsocks"]!["sing-box.json"]!)!),out=graph["outbounds"] as! [[String:Any]]
   out[0]["method"]=method;out[0]["password"]=Data(repeating:1,count:size).base64EncodedString();graph["outbounds"]=out
   files["shadowsocks"]!["sing-box.json"]=try data(graph).base64EncodedString();paired["profiles"]=files
   let actual=try compile(["candidate":data(paired)])
   try check("paired exact cipher source admitted",actual.rows.count==1 && actual.rows[0].reason.isEmpty && LibboxRouterNodeChainCandidateInputSupported(actual.rows[0].input))
   var custom=try profile(fixture[1]);custom["id"]="custom";custom["name"]="Custom";custom["node_kind"]="external";custom.removeValue(forKey:"node_proof_id")
   for key in ["router_api","api_token","adguard_ipv6","socks_host","socks_username","socks_password"]{custom[key]=""};custom["socks_port"]=0
   custom["external"]=["protocol":"shadowsocks","expected_public_ip":"203.0.113.76","shadowsocks":["server":"198.51.100.76","port":443,"method":method,"password":Data(repeating:0,count:size).base64EncodedString()]]
   var imported=paired;imported["selectedRouterID"]="custom";imported["routerProfiles"]=[custom];imported["profiles"]=[String:[String:String]]()
   let combined=try compile(["paired":data(paired),"custom":data(imported)])
   try check("original imported cipher admitted",combined.rows.count==2 && combined.rows.allSatisfy{$0.reason.isEmpty})
   for fault in ["hostname","layer","bad-key","legacy"] {
    var bad=imported,changed=custom
    if fault=="layer"{changed["start_layer"]="aes-256-gcm"}
    else{var ext=changed["external"] as! [String:Any],ss=ext["shadowsocks"] as! [String:Any];ss[fault=="hostname" ? "server":fault=="legacy" ? "method":"password"]=fault=="hostname" ? "hostname.example":fault=="legacy" ? "aes-256-gcm":"bad";ext["shadowsocks"]=ss;changed["external"]=ext}
    bad["routerProfiles"]=[changed]
    let result=try compile(["paired":data(paired),"unsupported":data(bad)])
    try check("unsupported \(fault) stays unscored without suppressing valid source",result.rows.count==2 && result.rows.filter{!$0.input.isEmpty}.count==1)
   }
   var legacy=paired,legacyFiles=files,legacyGraph=graph,legacyOut=out
   legacyOut[0]["method"]="aes-256-gcm";legacyOut[0]["password"]="legacy password";legacyGraph["outbounds"]=legacyOut
   legacyFiles["shadowsocks"]!["sing-box.json"]=try data(legacyGraph).base64EncodedString();legacy["profiles"]=legacyFiles
   let legacyResult=try compile(["legacy":data(legacy),"custom":data(imported)])
   try check("paired legacy stays unscored",legacyResult.rows.first{$0.id == "chain-node-1"}?.input.isEmpty == true)
   let original=try IOSNodeChainCapture.compile(bundles:fixture)
   defer{try? original.plan.close()}
   let records=["entry":fixture[0],"paired":try data(paired),"final":fixture[2],"custom":try data(imported)]
   if method == "2022-blake3-aes-256-gcm" {
    let pairedProposal=try IOSNodeCandidateProposal.compile(original:original,records:records,position:0,candidateID:"chain-node-1",measuredInput:actual.rows[0].input)
    try check("future paired proposal keeps selected final own policy",pairedProposal.profiles.count==2 && pairedProposal.profiles.last?.id=="chain-node-1" && pairedProposal.profiles.last?.adGuardIPv4 == "10.81.0.53" && pairedProposal.profiles.last?.multihopNodes?.map(\.id)==["chain-node-0","chain-node-1"])
   } else {
    do {
     _ = try IOSNodeCandidateProposal.compile(original:original,records:records,position:0,candidateID:"chain-node-1",measuredInput:actual.rows[0].input)
     throw NSError(domain:"UnexpectedCandidateProposal",code:1)
    } catch {
     try check("unsupported paired final explains independent timing eligibility",error.localizedDescription.contains("AES-256 Shadowsocks 2022 paired final") && error.localizedDescription.contains("score remains usable"))
    }
   }
   let customInput=combined.rows.first{$0.id=="custom"}!.input
   let customProposal=try IOSNodeCandidateProposal.compile(original:original,records:records,position:0,candidateID:"custom",measuredInput:customInput)
   try check("future imported proposal preserves original paired final",customProposal.profiles.map(\.id)==["chain-node-0","custom","chain-node-2"] && customProposal.profiles[1].normalizedNodeKind=="external" && customProposal.profiles[1].nodeProofID==nil && customProposal.profiles.last?.adGuardIPv4 == "10.82.0.53")
   try reject("future custom candidate after second prefix"){_ = try IOSNodeCandidateProposal.compile(original:original,records:records,position:1,candidateID:"custom",measuredInput:customInput)}
   var stale=records;stale["entry"]=try editProfile(fixture[0]){$0["home_lan_access"]=false}
   try reject("future proposal changed original prefix"){_ = try IOSNodeCandidateProposal.compile(original:original,records:stale,position:0,candidateID:"custom",measuredInput:customInput)}
   var changedFinal=records;changedFinal["final"]=try editProfile(fixture[2]){$0["adguard_ipv4"]="10.82.0.54"}
   try reject("future custom proposal substituted final DNS"){_ = try IOSNodeCandidateProposal.compile(original:original,records:changedFinal,position:0,candidateID:"custom",measuredInput:customInput)}
   try reject("future proposal changed measured source"){_ = try IOSNodeCandidateProposal.compile(original:original,records:records,position:0,candidateID:"custom",measuredInput:actual.rows[0].input)}
   try check("proposal compilation leaves original chain unchanged",original.members.count==3 && original.members[1].id=="chain-node-1" && original.members.last?.id=="chain-node-2")
   try reject("no eligible inventory"){_ = try compile(["only-prefix":fixture[0]])}
   let lazy=IOSNodeCandidatePrefix(position:0,profile_id:prefix.profile_id,node_id:prefix.node_id,mode:"shadowsocks")
   try reject("lazy SS prefix"){_ = try compile(["candidate":data(paired)],[lazy,tail])}
  }
  let hash=String(repeating:"c",count:64)
  let metadata=IOSNodeCandidateMetadata(schema:1,capture_sha256:hash,prefix_position:0,prefix_id:prefix.profile_id,source_sha256:hash,config_sha256:hash,targets:[.init(id:"target",source_sha256:hash)])
  try metadata.validate(prefix:prefix,source:hash,config:hash,ids:["target"])
  let distribution:[String:Any]=["samples":50,"min_ms":1.0,"median_ms":2.0,"average_ms":2.5,"p90_ms":3.0,"max_ms":4.0,"jitter_ms":0.5]
  let benchmark:[String:Any]=["schema":1,"measurement":"routed-tcp-connect","attempts":50,"failed":0,"distribution":distribution,"trimmed_mean_ms":2.4]
  let row:[String:Any]=["node_id":"target","role":"candidate","kind":"tcp-connect","ready":true,"benchmark":benchmark]
  let receipt:[String:Any]=["schema":1,"measurement":"routed-tcp-connect","request_id":"request","complete":true,"drained":true,"stage":"complete","capture_sha256":hash,"prefix_position":0,"prefix_id":prefix.profile_id,"candidate_id":"target","candidate_source_sha256":hash,"measured_at":1000000,"expires_at":1120000,"results":[row]]
  func score(_ value:[String:Any],_ now:Int64=1000001)throws->Double{try JSONDecoder().decode(IOSNodeCandidateResult.self,from:data(value)).score(request:"request",target:metadata.targets[0],metadata:metadata,now:now).trimmed_mean_ms}
  try check("complete50 TCP score",score(receipt)==2.4)
  for key in ["schema","measurement","request_id","complete","drained","stage","capture_sha256","prefix_position","prefix_id","candidate_id","candidate_source_sha256","expires_at","measured_at"] {
   var bad=receipt
   switch key {case "complete","drained":bad[key]=false;case "schema","prefix_position":bad[key]=99;case "expires_at":bad[key]=1120001;case "measured_at":bad[key]=1000002;default:bad[key]="foreign"}
   try reject("receipt foreign \(key)"){_ = try score(bad)}
  }
  try reject("expired without renewal"){_ = try score(receipt,1120000)}
  for key in ["attempts","failed","distribution","trimmed_mean_ms"] {
   var bad=receipt,changed=row,b=benchmark
   if key=="distribution"{var d=distribution;d["samples"]=49;b[key]=d}else{b[key]=key=="failed" ? 1:99}
   changed["benchmark"]=b;bad["results"]=[changed]
   try reject("incomplete benchmark \(key)"){_ = try score(bad)}
  }
 }
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='.ios-candidate-compiler-',dir=ROOT) as gofolder,tempfile.TemporaryDirectory(prefix='ios-candidates-') as folder:
        work=Path(folder);go=Path(gofolder)/'main.go';go.write_text(GO);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(go)],cwd=ROOT,check=True,timeout=180)
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        stub=work/'Libbox.swift';stub.write_text(LIBBOX);test=work/'Tests.swift';test.write_text(SWIFT)
        library=work/('libLibbox.dylib' if platform.system()=='Darwin' else 'libLibbox.so')
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(stub),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(library)],check=True,timeout=90)
        if platform.system()!='Darwin':
            crypto=work/'CryptoKit.swift';crypto.write_text(LINUX_CRYPTO)
            subprocess.run(options+['-emit-module','-emit-library','-module-name','CryptoKit',str(crypto),'-lcrypto','-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/'libCryptoKit.so')],check=True,timeout=90)
            options+=['-lCryptoKit']
        command=options+['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
        files=['Models.swift','IOSMultihopStartLayer.swift','IOSCandidateCatalogPublication.swift','IOSNodeChainCapture.swift','IOSNodeCandidateCapture.swift','IOSNodeCandidateResult.swift','IOSNodeCandidateProposal.swift']
        binary=work/'test'
        subprocess.run(command+[str(APP/name) for name in files]+[str(test),'-o',str(binary)],check=True,timeout=90)
        subprocess.run([str(binary),str(compiler)],check=True,timeout=180)
        for filename, before, after, marker in [
            ('IOSNodeCandidateCapture.swift', 'guard LibboxRouterNodeChainCandidateInputSupported(input) else', 'guard true else', 'paired legacy stays unscored'),
            ('IOSNodeCandidateResult.swift', 'expires_at - measured_at == 120000,', 'true,', 'ACCEPTED receipt foreign expires_at'),
            ('IOSNodeCandidateProposal.swift', 'Array(priorNodes.prefix(position + 1)) == Array(afterNodes.prefix(position + 1)),', 'true,', 'ACCEPTED future proposal changed original prefix'),
        ]:
            code=(APP/filename).read_text();assert code.count(before)==1
            mutant=work/filename;mutant.write_text(code.replace(before,after))
            subprocess.run(command+[str(mutant if name==filename else APP/name) for name in files]+[str(test),'-o',str(binary)],check=True,timeout=90)
            result=subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
            if result.returncode==0 or marker not in result.stdout+result.stderr:raise AssertionError('candidate causal control failed: '+filename+' '+result.stderr[-1500:])
        print('Apple candidate capture/receipt/proposal: three causal controls rejected')
if __name__=='__main__':main()
