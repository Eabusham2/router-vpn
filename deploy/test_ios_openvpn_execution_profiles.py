#!/usr/bin/env python3
"""Exercise complete Apple OpenVPN execution profile CRUD with original private nodes.

Uses the shipping profile callbacks and atomic store preparation. Source parsing
is real; private persistence and NetworkExtension remain explicit boundaries.
"""
from pathlib import Path
import os
import tempfile

import test_ios_node_chain_connect_profiles as C
import test_ios_openvpn_execution_capture as O

PROFILE_NODE_COUNTS = (3, 4, 5, 6, 7, 8)

SETUP = r'''
 struct ProfileCapture {let source:String,config:String;let close:()throws->Void}
 static func profileSource(_ bundles:[Data],_ requested:String)throws->ProfileCapture{
  let value=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested)
  try check("complete profile uses the distinct OpenVPN execution",value.isOpenVPN && !value.isCONNECT && !value.isSOCKS)
  return ProfileCapture(source:value.source,config:value.config,close:{try value.close()})
 }
 static func setupOpenVPN(_ count:Int,_ network:String,_ requested:String,_ layer:String)throws->(RouterVPNModel,[String]) {
  _ = try setup(count)
  let store=IOSNodeBundleStore.shared;store.records=[:]
  guard let path=ProcessInfo.processInfo.environment["ROUTER_VPN_APPLE_OPENVPN_FIXTURES"] else{throw failure("original private provider fixture missing")}
  let fixtures=try object(Data(contentsOf:URL(fileURLWithPath:path)))
  let row=fixtures["\(count)/mixed/\(network)/\(layer)"] as! [String:Any]
  let roots=row["bundles"] as! [[String:Any]]
  var bundles=try roots.map{original -> ClientBundle in
   var root=original,profiles=root["routerProfiles"] as! [[String:Any]],profile=profiles[0]
   profile["name"]=profile["id"]
   for key in ["router_api","api_token","adguard_ipv4","adguard_ipv6","socks_host","socks_username","socks_password"]{if profile[key]==nil{profile[key]=""}}
   if profile["socks_port"]==nil{profile["socks_port"]=0}
   profiles[0]=profile;root["routerProfiles"]=profiles
   return try JSONDecoder().decode(ClientBundle.self,from:JSONSerialization.data(withJSONObject:root))
  }
  let ids=bundles.map{value in value.routerProfiles[0].normalizedNodeKind=="router-vpn" ? "rvpn-"+String(value.routerProfiles[0].nodeProofID!.prefix(16)):value.routerProfiles[0].id}
  let modes=(0..<count-2).map{["wg","awg2-fast","awg2-strong"][$0%3]}+["openvpn","shadowsocks"]
  for position in bundles.indices{
   bundles[position].selectedRouterID=ids[position];bundles[position].routerProfiles[0].id=ids[position]
   if position==count-1{
    bundles[position].routerProfiles[0].multihopExecution=requested
    bundles[position].routerProfiles[0].multihopNodes=ids.enumerated().map{.init(id:$0.element,mode:modes[$0.offset])}
   }
   bundles[position].routerProfiles[0]=try IOSConnectionProfileStore.fixtureCanonicalProfile(bundles[position].routerProfiles[0])
   try store.save(bundles[position])
  }
  let model=RouterVPNModel();model.bundle=try stored(ids[count-1]);return(model,ids)
 }
 static func openVPNRoundtrip()throws {
  guard CommandLine.arguments.count==3,let count=Int(CommandLine.arguments[2]),(3...8).contains(count) else {throw failure("missing complete OpenVPN profile phase")}
  var completedCases=0
  for network in ["tcp","udp"] {for requested in ["server","auto"] {for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
   let kind="openvpn",middlePosition=count-2,finalPosition=count-1
   let(model,ids)=try setupOpenVPN(count,network,requested,layer),store=IOSNodeBundleStore.shared
   let middle=try stored(ids[middlePosition]),final=model.bundle!,host=middle.routerProfiles[0].endpoint
   let expectedPublicIP=middle.routerProfiles[0].external!.expectedPublicIP
   let originalMiddlePolicy=middle.routerProfiles[0]
   let prefixModes=(0..<count-2).map{["wg","awg2-fast","awg2-strong"][$0%3]}
'''


def original_callbacks():
    start=C.TYPED.index('   let beforeSource=')
    stop=C.TYPED.rindex('  }}}}}}')
    body=C.TYPED[start:stop]
    def replace(before, after):
        nonlocal body
        assert body.count(before)==1, before
        body=body.replace(before,after,1)
    replace('Array(repeating:mode,count:count-2)+[kind,"shadowsocks"]','prefixModes+[kind,"shadowsocks"]')
    replace('saved.chainPolicies?[middlePosition].externalPublicIP=="203.0.113.76"','saved.chainPolicies?[middlePosition].externalPublicIP==expectedPublicIP')
    body=body.replace('PRIVATE-CONNECT-USER',' captured user ').replace('PRIVATE-CONNECT-PASSWORD',' captured secret ')
    replace('captured[middlePosition].routerProfiles[0].homeLANAccess==false && captured[middlePosition].routerProfiles[0].killSwitchPolicy=="always" && captured[middlePosition].routerProfiles[0].dnsProtocol=="tcp" && captured[middlePosition].routerProfiles[0].dnsHost=="10.81.0.53" && captured[middlePosition].routerProfiles[0].dnsPort==5353','captured[middlePosition].routerProfiles[0].homeLANAccess==originalMiddlePolicy.homeLANAccess && captured[middlePosition].routerProfiles[0].killSwitchPolicy==originalMiddlePolicy.killSwitchPolicy && captured[middlePosition].routerProfiles[0].dnsProtocol==originalMiddlePolicy.dnsProtocol && captured[middlePosition].routerProfiles[0].dnsHost==originalMiddlePolicy.dnsHost && captured[middlePosition].routerProfiles[0].dnsPort==originalMiddlePolicy.dnsPort')
    first=body.index('     if kind=="https-connect" {source.routerProfiles[0].external?.httpsConnect?.username=')
    last=body.index('\n    }',first)
    body=body[:first]+'     source.routerProfiles[0].external?.openVPN?.username="relinked-user";source.routerProfiles[0].external?.openVPN?.password="relinked-valid-password"'+body[last:]
    replace('(kind=="https-connect" ? stored(ids[middlePosition]).routerProfiles[0].external?.httpsConnect?.password : stored(ids[middlePosition]).routerProfiles[0].external?.httpConnect?.password)','stored(ids[middlePosition]).routerProfiles[0].external?.openVPN?.password')
    replace('"Typed CONNECT original route"','"Original OpenVPN execution route"')
    replace('failure("actual typed Add callback did not persist")','failure("actual OpenVPN Add callback did not persist: "+actions.status)')
    replace('   let visible=String(decoding:IOSPrivateJSONStore.bytes!,as:UTF8.self)', '   try check("OpenVPN profile keeps original final layer",saved.preferences?.startLayer==layer && saved.chainPolicies?.last?.preferences.startLayer==layer)\n   let visible=String(decoding:IOSPrivateJSONStore.bytes!,as:UTF8.self)')
    replace('   let originalBytes=try encoded(middle.routerProfiles[0].external!),originalAssets=final.profiles', '   try check("OpenVPN saved preference keeps private pairing in its original node",!visible.contains("private_key") && !visible.contains("server-private-password"))\n   let originalBytes=try encoded(middle.routerProfiles[0].external!),originalAssets=final.profiles')
    return SETUP+body+r'''
   completedCases+=1
  }}}
  try check("complete OpenVPN profile phase keeps every transport, selection and final layer",completedCases==12)
  print("PASS Apple OpenVPN complete profiles nodes=\(count): \(completedCases) original Add/Load/Update/Delete cases")
 }
'''


TYPED=original_callbacks()


def main():
    with tempfile.TemporaryDirectory(prefix='ios-openvpn-profiles-') as folder:
        destination=Path(folder)/'original-provider-fixtures.json'
        O.emit_fixtures(destination)
        previous=os.environ.get('ROUTER_VPN_APPLE_OPENVPN_FIXTURES')
        os.environ['ROUTER_VPN_APPLE_OPENVPN_FIXTURES']=str(destination)
        try:
            C.TYPED=TYPED
            C.main(label='OpenVPN execution',roundtrip='openVPNRoundtrip',binary_cases=[(count,) for count in PROFILE_NODE_COUNTS])
        finally:
            if previous is None:os.environ.pop('ROUTER_VPN_APPLE_OPENVPN_FIXTURES',None)
            else:os.environ['ROUTER_VPN_APPLE_OPENVPN_FIXTURES']=previous


if __name__=='__main__':main()
