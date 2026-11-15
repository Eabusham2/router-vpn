#!/usr/bin/env python3
"""Run shipping Swift OpenVPN middle capture/provider against the real Go compiler.

The bridge is socket-free. These checks do not certify an Apple native image,
VPN device, connected OpenVPN generation, or encrypted traffic.
"""
from pathlib import Path
import importlib.util
import platform
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
spec=importlib.util.spec_from_file_location('ordered_capture',ROOT/'deploy/test_ios_node_chain_capture.py')
C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
CASES=r'''
 static func openVPNMiddle()throws {
  for mode in ["wg","awg2-fast","awg2-strong"] {for network in ["tcp","udp"] {
   var bundles=try sources(3,"off",true)
   for position in bundles.indices {bundles[position]=try editProfile(bundles[position]){p in
    p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""
   }}
   let id="saved-openvpn-middle"
   var middle=try profile(bundles[1]);middle["id"]=id;middle["node_kind"]="external";middle.removeValue(forKey:"node_proof_id")
   middle["router_api"]="";middle["api_token"]="";middle["endpoint"]="203.0.113.20";middle["start_layer"]="off"
   middle["home_lan_access"]=false;middle["kill_switch_policy"]="always"
   let original="client\ndev tun\nproto "+network+"\nremote 203.0.113.20 1194\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint "+String(repeating:"ab",count:32)+"\ntun-mtu 1400\ndata-ciphers AES-256-GCM:AES-128-GCM\n"
   middle["external"]=["protocol":"openvpn","expected_public_ip":"203.0.113.88","openvpn":["config":original,"username":" exact user ","password":" exact secret "]]
   bundles[1]=try data(["selectedRouterID":id,"routerProfiles":[middle],"profiles":[String:[String:String]]()])
   bundles[2]=try editProfile(bundles[2]){p in var nodes=p["multihop_nodes"] as! [[String:Any]];nodes[0]["mode"]=mode;nodes[1]=["id":id,"mode":"openvpn"];p["multihop_nodes"]=nodes}
   let capture=try IOSNodeChainCapture.compile(bundles:bundles);defer{try? capture.plan.close()}
   let launch=try object(Data(capture.launchInput.utf8)),graph=try object(Data(capture.config.utf8))
   try check("OpenVPN exact source schema",launch["schema"] as? Int==5 && (launch["identity_sources"] as? [String])?[1]=="")
   try check("OpenVPN original order and policy",capture.strict && !capture.homeLANAccess && capture.members.map(\.mode)==[mode,"openvpn","shadowsocks"])
   let endpoint=(graph["endpoints"] as! [[String:Any]]).first{$0["type"] as? String=="openvpn-client"}!
   try check("OpenVPN original credentials",endpoint["username"] as? String==" exact user " && endpoint["password"] as? String==" exact secret ")
   try check("OpenVPN original prefix detour",endpoint["detour"] is String && endpoint["system"] as? Bool==false)
   let selected=try IOSRuntimeSelector.selectNodeChain(capture)
   try check("OpenVPN actual app native selection",selected.nodeChainInput==capture.launchInput && selected.rawProfileID=="shadowsocks" && selected.files.isEmpty)
   let dns=graph["dns"] as! [String:Any],resolvers=dns["servers"] as! [[String:Any]]
   let resolver=resolvers.first{$0["tag"] as? String==dns["final"] as? String}!
   try check("OpenVPN keeps final selected DNS",resolver["server"] as? String=="10.82.0.53" && resolver["detour"] is String && resolver["detour"] as? String != endpoint["tag"] as? String)
   let member=try object(Data((launch["nodes"] as! [String])[1].utf8)),saved=try object(Data((member["capture"] as! String).utf8))
   let ext=(saved["profile"] as! [String:Any])["external"] as! [String:Any]
   try check("OpenVPN raw source retained",(ext["openvpn"] as! [String:Any])["config"] as? String==original)
   let replay=try IOSNodeChainCapture.reopen(capture.launchInput,selectedProfile:profile(bundles[2]));defer{try? replay.plan.close()}
   try check("OpenVPN exact replay",replay.launchInput==capture.launchInput && replay.config==capture.config)
   var provider:[String:Any]=["engine":"multihop-libbox","mode":"shadowsocks","rawProfileID":"shadowsocks","modeCandidates":["shadowsocks"],"bundle":bundles[2],IOSNodeChainProviderCapture.key:capture.launchInput]
   let reopened=try IOSNodeChainProviderCapture.reopen(provider);try reopened.plan.close()
   provider["external_entry_mode"]="openvpn"
   try reject("OpenVPN mixed provider owner"){_ = try IOSNodeChainProviderCapture.reopen(provider)}
   var replaced=try profile(bundles[2]);replaced["api_token"]="replaced-final"
   try reject("OpenVPN final identity substitution"){_ = try IOSNodeChainCapture.reopen(capture.launchInput,selectedProfile:replaced)}
   for fault in ["endpoint","token","layer","remote-count","hostname","private-remote","order","server","auto"] {
    var changed=bundles
    if fault=="order"{changed.swapAt(0,1)}
    else if fault=="server" || fault=="auto" {
     try reject("OpenVPN refuses execution "+fault){_ = try IOSNodeChainCapture.compileOriginalForExecution(bundles:changed,requested:fault)};continue
    } else { changed[1]=try editProfile(changed[1]){p in
     if fault=="endpoint"{p["endpoint"]="203.0.113.21"}
     if fault=="token"{p["api_token"]="borrowed-paired-secret"}
     if fault=="layer"{p["start_layer"]="aes-256-gcm"}
     if ["remote-count","hostname","private-remote"].contains(fault){var e=p["external"] as! [String:Any],o=e["openvpn"] as! [String:Any];var raw=o["config"] as! String
      if fault=="remote-count"{raw += "remote 203.0.113.21 443\n"}
      if fault=="hostname"{raw=raw.replacingOccurrences(of:"203.0.113.20",with:"provider.example.test")}
      if fault=="private-remote"{raw=raw.replacingOccurrences(of:"203.0.113.20",with:"10.42.0.1");p["endpoint"]="10.42.0.1"}
      o["config"]=raw;e["openvpn"]=o;p["external"]=e
     }
    }}
    try reject("OpenVPN source refusal "+fault){_ = try IOSNodeChainCapture.compile(bundles:changed)}
   }
  }}
 }
'''

def main():
    tests=C.SWIFT.replace(' static func hostnameMiddle()',CASES+' static func hostnameMiddle()',1)
    tests=tests.replace('try run();print("Apple ordered native capture: PASS (\\(checks) shipping Swift / shared Go checks; no native connection)")','try openVPNMiddle();print("iOS OpenVPN middle capture: PASS \\(checks) actual Swift/shared-Go checks; native/device acceptance separate")',1)
    assert tests!=C.SWIFT
    with tempfile.TemporaryDirectory(prefix='.ios-openvpn-middle-',dir=ROOT) as go_dir,tempfile.TemporaryDirectory(prefix='ios-openvpn-middle-') as folder:
        go_dir,work=Path(go_dir),Path(folder)
        (go_dir/'main.go').write_text(C.GO);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(go_dir/'main.go')],cwd=ROOT,check=True,timeout=180)
        selector=(APP/'IOSNodeChainLaunch.swift').read_text()
        selector=selector[selector.index('    static func selectNodeChain(_ capture: IOSNodeChainCapture)'):]
        boundary='import Foundation\nstruct IOSRuntimeSelection {enum Engine {case multihop};let engine:Engine;let logicalModeID:String;let rawProfileID:String;let files:[String:String];let nodeChainInput:String}\nenum IOSRuntimeSelector {\n'+selector
        (work/'Selector.swift').write_text(boundary)
        (work/'Libbox.swift').write_text(C.LIBBOX);(work/'Tests.swift').write_text(tests)
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        library=work/('libLibbox.dylib' if platform.system()=='Darwin' else 'libLibbox.so')
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(work/'Libbox.swift'),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(library)],check=True,timeout=90)
        command=options+['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
        command += [str(APP/name) for name in ('Models.swift','IOSImportedOpenVPNSource.swift','IOSMultihopStartLayer.swift','IOSNodeChainProviderCapture.swift','IOSNodeChainSOCKSCapture.swift')]
        original=(APP/'IOSNodeChainCapture.swift').read_text();source=work/'Capture.swift';binary=work/'tests'
        def run(value):
            source.write_text(value)
            subprocess.run(command+[str(source),str(work/'Selector.swift'),str(work/'Tests.swift'),'-o',str(binary)],check=True,timeout=90)
            return subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
        result=run(original);assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip())
        before='try json(selectedProfile, maximum: 256 * 1024) == json(capture.finalProfile, maximum: 256 * 1024)'
        assert original.count(before)==1
        failed=run(original.replace(before,'true',1))
        assert failed.returncode!=0 and 'ACCEPTED OpenVPN final identity substitution' in failed.stdout+failed.stderr,failed.stdout+failed.stderr
        print('Rejected OpenVPN final-control substitution mutation')
if __name__=='__main__':main()
