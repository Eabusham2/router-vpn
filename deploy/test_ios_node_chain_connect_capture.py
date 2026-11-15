#!/usr/bin/env python3
"""Execute the typed source/provider composition with the real shared Go parser."""
from pathlib import Path
import importlib.util
import platform
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
spec=importlib.util.spec_from_file_location('original_ordered_capture',ROOT/'deploy/test_ios_node_chain_capture.py')
C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)

CONNECT_CASES=r'''
 static func connectMiddle()throws {
  for count in 3...8 {for mode in ["wg","awg2-fast","awg2-strong"] {for kind in ["http-connect","https-connect"] {
   let middlePosition=count-2,finalPosition=count-1
   let layer="off",key=kind.replacingOccurrences(of:"-",with:"_")
   var bundles=try sources(count,layer,true)
   for position in bundles.indices {
    bundles[position]=try editProfile(bundles[position]){p in
     p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""
    }
   }
   let originalMiddle=try profile(bundles[middlePosition]),id="saved-socks-middle"
   var middle=originalMiddle
   middle["id"]=id;middle["node_kind"]="external";middle.removeValue(forKey:"node_proof_id")
   middle["router_api"]="";middle["api_token"]="";middle["endpoint"]="203.0.113.20";middle["start_layer"]="off"
   middle["home_lan_access"]=false;middle["kill_switch_policy"]="always"
   var credentials:[String:Any]=["host":"203.0.113.20","port":1080,"username":"saved user","password":"saved:password"]
   if kind=="https-connect" {credentials["tls_server_name"]="Original.Proxy.Example"}
   middle["external"]=["protocol":kind,"expected_public_ip":"203.0.113.88",key:credentials] as [String:Any]
   bundles[middlePosition]=try data(["selectedRouterID":id,"routerProfiles":[middle],"profiles":[String:[String:String]]()])
   bundles[finalPosition]=try editProfile(bundles[finalPosition]){p in var nodes=p["multihop_nodes"] as! [[String:Any]];for prefix in 0..<middlePosition {nodes[prefix]["mode"]=mode};nodes[middlePosition]=["id":id,"mode":kind];p["multihop_nodes"]=nodes}
   bundles[finalPosition]=try editProfile(bundles[finalPosition]){p in p["dns_mode"]="custom";p["dns_protocol"]="tcp";p["dns_host"]="10.82.0.53";p["dns_port"]=5353}
   var finalRoot=try object(bundles[finalPosition]),assets=finalRoot["profiles"] as! [String:[String:String]]
   var finalGraph=try object(Data(base64Encoded:assets["shadowsocks"]!["sing-box.json"]!)!)
   finalGraph["dns"]=["servers":[["type":"tcp","tag":"home-dns","server":"10.82.0.53","server_port":5353,"detour":"proxy"]],"final":"home-dns"]
   assets["shadowsocks"]!["sing-box.json"]=try data(finalGraph).base64EncodedString();finalRoot["profiles"]=assets;bundles[finalPosition]=try data(finalRoot)
   bundles[finalPosition]=Data(try LibboxTestCONNECTService(String(decoding:bundles[finalPosition],as:UTF8.self)).utf8)
   let capture=try IOSNodeChainCONNECTCapture.compile(bundles:bundles);defer{try? capture.plan.close()}
   let source=try object(Data(capture.source.utf8)),graph=try object(Data(capture.config.utf8))
   try check("typed CONNECT source schema",source["schema"] as? Int==4 && source["kind"]==nil && (source["identity_sources"] as? [String] )?[middlePosition]=="")
   try check("typed CONNECT device policy",capture.strict && !capture.homeLANAccess && capture.members[0].mode==mode && capture.members[middlePosition].mode==kind)
   try check("all CONNECT prefixes retained",capture.members.count==count && capture.members.prefix(middlePosition).allSatisfy{$0.mode==mode} && capture.members.last?.mode=="shadowsocks")
   let identities=source["identity_sources"] as! [String]
   try check("every original paired identity retained",identities.count==count && identities.enumerated().allSatisfy{$0.offset==middlePosition ? $0.element.isEmpty : !$0.element.isEmpty})
   let out=(graph["outbounds"] as! [[String:Any]]).first{$0["type"] as? String=="http"}!
   try check("typed CONNECT original credentials and detour",out["username"] as? String=="saved user" && out["password"] as? String=="saved:password" && out["server"] as? String=="203.0.113.20" && out["detour"] is String)
   try check("typed CONNECT single original TUN",(graph["inbounds"] as! [Any]).count==1)
   let tls=out["tls"] as? [String:Any]
   try check("CONNECT original TLS and SNI",kind=="http-connect" ? tls==nil : tls?["enabled"] as? Bool==true && tls?["server_name"] as? String=="Original.Proxy.Example" && tls?["insecure"]==nil)
   let dns=graph["dns"] as! [String:Any],resolvers=dns["servers"] as! [[String:Any]]
   try check("CONNECT preserves final selected TCP resolver",resolvers.contains{$0["server"] as? String=="10.82.0.53" && $0["server_port"] as? Int==5353 && $0["type"] as? String=="tcp"})
   var unsupported=bundles
   unsupported[finalPosition]=try edit(unsupported[finalPosition]){root in var assets=root["profiles"] as! [String:[String:String]];assets["shadowsocks"]!.removeValue(forKey:"routervpn-ss-service.json");root["profiles"]=assets}
   try reject("CONNECT cannot invent final SS service authority"){_ = try IOSNodeChainCONNECTCapture.compile(bundles:unsupported)}
   var mixed:[String:Any]=["engine":"multihop-libbox","mode":"shadowsocks","rawProfileID":"shadowsocks","modeCandidates":["shadowsocks"],"bundle":bundles[finalPosition],IOSNodeChainCONNECTCapture.providerKey:capture.source]
   mixed[IOSNodeChainSOCKSCapture.providerKey]=capture.source
   try reject("CONNECT cannot borrow SOCKS provider identity"){_ = try IOSNodeChainCONNECTCapture.reopenProvider(mixed)}

   let replay=try IOSNodeChainCONNECTCapture.reopen(capture.source,selectedProfile:profile(bundles[finalPosition]));defer{try? replay.plan.close()}
   try check("typed CONNECT exact replay",replay.source==capture.source && replay.config==capture.config)
   try reject("CONNECT cannot borrow generic launch"){_ = try IOSNodeChainCapture.reopen(capture.source,selectedProfile:profile(bundles[finalPosition]))}
   var provider:[String:Any]=["engine":"multihop-libbox","mode":"shadowsocks","rawProfileID":"shadowsocks","modeCandidates":["shadowsocks"],"bundle":bundles[finalPosition],IOSNodeChainCONNECTCapture.providerKey:capture.source]
   let reopened=try IOSNodeChainCONNECTCapture.reopenProvider(provider);try reopened.plan.close()
   var replacedFinal=try profile(bundles[finalPosition]);replacedFinal["api_token"]="relinked-final"
   try reject("CONNECT replaced final control"){_ = try IOSNodeChainCONNECTCapture.reopen(capture.source,selectedProfile:replacedFinal)}
   var staleProvider=provider
   staleProvider["bundle"]=try edit(bundles[finalPosition]){root in var files=root["profiles"] as! [String:[String:String]];files["shadowsocks"]!["sing-box.json"]=Data("replacement".utf8).base64EncodedString();root["profiles"]=files}
   try reject("CONNECT replaced provider assets"){_ = try IOSNodeChainCONNECTCapture.reopenProvider(staleProvider)}
   provider[IOSNodeChainProviderCapture.key]=capture.source
   try reject("CONNECT mixed provider owner"){_ = try IOSNodeChainCONNECTCapture.reopenProvider(provider)}
   for fault in ["credential","token","endpoint","layer","order","dns","final-assets"] {
    var changed=bundles
    if fault=="order"{changed.swapAt(0,middlePosition)}
    else if fault=="dns"{changed[finalPosition]=try editProfile(changed[finalPosition]){$0["dns_mode"]="custom";$0["dns_protocol"]="tcp";$0["dns_host"]="resolver.example.test";$0["dns_port"]=53}}
    else if fault=="final-assets"{changed[finalPosition]=try edit(changed[finalPosition]){$0["profiles"]=[String:[String:String]]()}}
    else {changed[middlePosition]=try editProfile(changed[middlePosition]){p in
     if fault=="token"{p["api_token"]="borrowed"}
     if fault=="endpoint"{p["endpoint"]="203.0.113.21"}
     if fault=="layer"{p["start_layer"]="aes-256-gcm"}
     if fault=="credential"{var ext=p["external"] as! [String:Any],socks=ext[key] as! [String:Any];socks["password"]="";ext[key]=socks;p["external"]=ext}
    }}
    try reject("CONNECT captured refusal "+fault){_ = try IOSNodeChainCONNECTCapture.compile(bundles:changed)}
   }
  }}}
 }
'''
CONNECT_SWIFT=C.SWIFT.replace(' static func hostnameMiddle()',CONNECT_CASES+' static func hostnameMiddle()',1)

def main():
    tests=CONNECT_SWIFT.replace('try run();print("Apple ordered native capture: PASS (\\(checks) shipping Swift / shared Go checks; no native connection)")','try connectMiddle();print("iOS typed CONNECT source: PASS \\(checks) actual shared-parser and provider checks")',1)
    assert tests!=C.SWIFT
    with tempfile.TemporaryDirectory(prefix='.ios-typed-connect-source-',dir=ROOT) as go_dir,tempfile.TemporaryDirectory(prefix='ios-typed-connect-source-') as folder:
        go_dir,work=Path(go_dir),Path(folder)
        (go_dir/'main.go').write_text(C.GO);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(go_dir/'main.go')],cwd=ROOT,check=True,timeout=180)
        lib=work/'Libbox.swift';lib.write_text(C.LIBBOX)
        code=work/'Tests.swift';code.write_text(tests)
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        library=work/('libLibbox.dylib' if platform.system()=='Darwin' else 'libLibbox.so')
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(lib),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(library)],check=True,timeout=90)
        command=options+['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
        command += [str(APP/name) for name in ('Models.swift','IOSMultihopStartLayer.swift','IOSNodeChainCapture.swift','IOSImportedOpenVPNSource.swift','IOSNodeChainProviderCapture.swift','IOSNodeChainSOCKSCapture.swift')]
        original=(APP/'IOSNodeChainCONNECTCapture.swift').read_text();source=work/'TypedCapture.swift';binary=work/'tests'
        def run(value):
            source.write_text(value)
            subprocess.run(command+[str(source),str(code),'-o',str(binary)],check=True,timeout=90)
            return subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
        result=run(original);assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip())
        for name,before,after,witness in (
            ('final-source','try json(selectedProfile) == json(result.finalProfile)','true','ACCEPTED CONNECT replaced final control'),
            ('provider-assets','selected == original else','true else','ACCEPTED CONNECT replaced provider assets'),
            ('provider-purpose','.allSatisfy({ configuration[$0] == nil })','.allSatisfy({ _ in true })','ACCEPTED CONNECT cannot borrow SOCKS provider identity'),
        ):
            assert original.count(before)==1,name
            rejected=run(original.replace(before,after,1))
            assert rejected.returncode!=0 and witness in rejected.stdout+rejected.stderr,(name,rejected.stdout+rejected.stderr)
            print('Rejected typed CONNECT capture mutation: '+name)
if __name__=='__main__':main()
