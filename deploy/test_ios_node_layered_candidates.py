#!/usr/bin/env python3
"""Execute paired SS layer catalogs/proposals using shipping Swift and Go sources.

This gate proves source capture and future profile semantics. Actual encrypted
prefix/listener timing remains the separate mandatory native component gate.
"""
from pathlib import Path
import platform
import subprocess
import tempfile
import test_ios_node_candidates as C

ROOT,APP=C.ROOT,C.APP
assert C.SAVE_GO.count(' case "candidate-supported":') == 1
GO=C.SAVE_GO.replace(' case "candidate-supported":', ' case "candidate-node-config":var node *mobilemultihop.NodeProfile;node,err=mobilemultihop.ParseNodeLaunchInput(r.Source);if err==nil{value=node.Config()}\n case "candidate-supported":',1)
LIBBOX=C.SAVE_LIBBOX+r'''
public func LibboxLayeredCandidateConfig(_ source:String)throws->String{try bridge(["Op":"candidate-node-config","Source":source])}
'''
SWIFT=C.SWIFT[:C.SWIFT.index('@MainActor @main struct Tests')]+r'''
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ name:String,_ value:@autoclosure ()throws->Bool)throws{guard try value()else{throw NSError(domain:"LayeredCandidate",code:1,userInfo:[NSLocalizedDescriptionKey:name])};checks+=1}
 static func reject(_ name:String,_ action:()throws->Void)throws{do{try action()}catch{checks+=1;return};throw NSError(domain:"LayeredCandidate",code:1,userInfo:[NSLocalizedDescriptionKey:"ACCEPTED "+name])}
 static func main(){defer{LibboxTestClose()};do{try run(CommandLine.arguments[2]);print("Apple layered paired candidates: \(checks) actual source and proposal checks PASS")}
 catch{FileHandle.standardError.write(Data(("FAIL after \(checks): \(error.localizedDescription)\n").utf8));exit(1)}}
 static func run(_ layer:String)throws {
  var fixture=try sources(4,"off",true).map{try editProfile($0){p in p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""}}
  fixture[3]=try editProfile(fixture[3]){$0["start_layer"]=layer}
  let original=try IOSNodeChainCapture.compile(bundles:fixture);defer{try? original.plan.close()}
  let source=original.launchInput, final=try profile(fixture[3]), root=try object(fixture[3]), files=root["profiles"] as! [String:[String:String]]
  let input:String
  do{input=try IOSNodeCandidateCapture.member(profile:final,files:files)}catch{throw NSError(domain:"LayeredCandidate",code:1,userInfo:[NSLocalizedDescriptionKey:"paired layered member omitted from catalog"])}
  try check("actual layered member compiler admits original source",LibboxRouterNodeChainCandidateInputSupported(input))
  let graph=try object(Data(try LibboxLayeredCandidateConfig(input).utf8)),tag=graph["route"] as! [String:Any]
  let out=(graph["outbounds"] as! [[String:Any]]).first{$0["tag"] as? String == tag["final"] as? String}!
  let captured=try object(Data(base64Encoded:files["shadowsocks"]!["sing-box.json"]!)!), ss=(captured["outbounds"] as! [[String:Any]])[0]
  try check("layered candidate keeps exact concrete owner",out["type"] as? String == (layer.hasSuffix("xor-whitening") ? "routervpn-aes-xor":"shadowsocks"))
  try check("layered candidate keeps original secret and address",out["password"] as? String == ss["password"] as? String && out["server"] as? String == ss["server"] as? String)
  try check("layered candidate uses only captured TCP port",out["server_port"] as? Int == (layer.hasSuffix("xor-whitening") ? 8389:ss["server_port"] as! Int) && out["detour"] == nil && out["udp_over_tcp"] == nil)
  let records=Dictionary(uniqueKeysWithValues:fixture.enumerated().map{("original-\($0.offset)",$0.element)})
  let proofs=original.members.enumerated().map{IOSNodeCandidatePrefix(position:$0.offset,profile_id:$0.element.id,node_id:$0.element.profile["node_proof_id"] as! String,mode:$0.element.mode)}
  let stamp=IOSCandidateCatalogPublication.Stamp(schema:1,epoch:UUID().uuidString,generation:1,ready:true,sources_sha256:try IOSCandidateCatalogPublication.sourcesDigest(records))
  let inventory=try IOSNodeCandidateCapture.compile(records:records,stamp:stamp,prefixPosition:2,proofs:proofs)
  let row=inventory.rows.first{$0.id==final["id"] as! String}!
  try check("original layered row remains eligible",row.input==input && row.reason.isEmpty)
  let proposal=try IOSNodeCandidateProposal.compile(original:original,records:records,position:2,candidateID:row.id,measuredInput:input)
  try check("future proposal retains complete original positions",proposal.profiles.map(\.id)==original.members.map(\.id))
  try check("future proposal keeps final selected layer",proposal.profiles.last?.startLayer==layer)
  try check("future proposal retains requested execution",proposal.profiles.last?.multihopExecution==original.selectionExecution)
  let before=try object(Data(source.utf8)),after=try object(Data(proposal.launchInput.utf8))
  let priorNodes=before["nodes"] as! [String],nextNodes=after["nodes"] as! [String],priorIDs=before["identity_sources"] as! [String],nextIDs=after["identity_sources"] as! [String]
  for position in 0..<3{try check("future proposal retains original prefix source and identity",priorNodes[position]==nextNodes[position] && priorIDs[position]==nextIDs[position])}
  try check("candidate capture leaves original source unchanged",original.launchInput==source)
  var changed=records, replacement=root, assets=files, changedGraph=captured, changedOut=ss
  changedOut["password"]=Data(repeating:9,count:32).base64EncodedString();changedGraph["outbounds"]=[changedOut];assets["shadowsocks"]!["sing-box.json"]=try data(changedGraph).base64EncodedString();replacement["profiles"]=assets;changed["original-3"]=try data(replacement)
  try reject("changed captured secret cannot adopt measured input"){_ = try IOSNodeCandidateProposal.compile(original:original,records:changed,position:2,candidateID:row.id,measuredInput:input)}
  try reject("layered final target cannot duplicate retained suffix"){_ = try IOSNodeCandidateProposal.compile(original:original,records:records,position:1,candidateID:row.id,measuredInput:input)}
  for raw in [true,7,"foreign","xor-whitening"] as [Any]{var bad=final;bad["start_layer"]=raw;try reject("noncanonical paired layer"){_ = try IOSNodeCandidateCapture.member(profile:bad,files:files)}}
 }
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='.ios-layered-candidate-go-',dir=ROOT) as gofolder,tempfile.TemporaryDirectory(prefix='ios-layered-candidates-') as folder:
        work=Path(folder);source=Path(gofolder)/'main.go';source.write_text(GO);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(source)],cwd=ROOT,check=True,timeout=180)
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        stub=work/'Libbox.swift';stub.write_text(LIBBOX);test=work/'Tests.swift';test.write_text(SWIFT)
        library=work/('libLibbox.dylib' if platform.system()=='Darwin' else 'libLibbox.so')
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(stub),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(library)],check=True,timeout=90)
        if platform.system()!='Darwin':
            crypto=work/'CryptoKit.swift';crypto.write_text(C.LINUX_CRYPTO)
            subprocess.run(options+['-emit-module','-emit-library','-module-name','CryptoKit',str(crypto),'-lcrypto','-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/'libCryptoKit.so')],check=True,timeout=90)
            options+=['-lCryptoKit']
        command=options+['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
        files=['Models.swift','IOSMultihopStartLayer.swift','IOSCandidateCatalogPublication.swift','IOSNodeChainCapture.swift','IOSImportedOpenVPNSource.swift','IOSNodeCandidateOriginalCapture.swift','IOSNodeChainProviderCapture.swift','IOSNodeChainSOCKSCapture.swift','IOSNodeChainCONNECTCapture.swift','IOSNodeChainExecutionCapture.swift','IOSNodeCandidateCapture.swift','IOSNodeCandidateResult.swift','IOSNodeCandidateProposal.swift']
        binary=work/'test'
        subprocess.run(command+[str(APP/name) for name in files]+[str(test),'-o',str(binary)],check=True,timeout=90)
        for layer in ('off','aes-256-gcm','aes-256-gcm+xor-whitening'):
            subprocess.run([str(binary),str(compiler),layer],check=True,timeout=180)
        name='IOSNodeCandidateCapture.swift';text=(APP/name).read_text();anchor='["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(layer)'
        assert text.count(anchor)==1
        mutant=work/name;mutant.write_text(text.replace(anchor,'["", "off"].contains(layer)',1))
        subprocess.run(command+[str(mutant if path==name else APP/path) for path in files]+[str(test),'-o',str(binary)],check=True,timeout=90)
        for layer in ('aes-256-gcm','aes-256-gcm+xor-whitening'):
            result=subprocess.run([str(binary),str(compiler),layer],capture_output=True,text=True,timeout=180)
            if result.returncode!=1 or 'paired layered member omitted from catalog' not in result.stderr:
                raise AssertionError('old Off-only Apple guard did not reach intended refusal: '+result.stdout+result.stderr)
        print('Apple layered paired candidate capture: two old-Off controls rejected')
if __name__=='__main__':main()
