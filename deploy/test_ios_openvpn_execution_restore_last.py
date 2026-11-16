#!/usr/bin/env python3
"""Retain complete Apple OpenVPN execution and concrete Last/restore choices.

The actual Go source/Last constructors validate independently provisioned
Server descriptors. Native reader and Instance.Close are explicit boundaries.
"""
from pathlib import Path
import os
import tempfile

import test_ios_node_chain_execution_restore_last as LAST
import test_ios_openvpn_execution_capture as SOURCE

PREFIX_NODE_COUNTS=(3,4,5,6,7,8)


def original_swift():
    swift=LAST.SWIFT
    begin=swift.index('@main struct Tests')
    fixture=SOURCE.FIXTURE+r'''
func openVPNServerFixture(_ mode:String,_ network:String,_ count:Int,_ layer:String="off")throws->String {
 guard let path=ProcessInfo.processInfo.environment["ROUTER_VPN_APPLE_OPENVPN_FIXTURES"] else{throw NSError(domain:"MissingServerSource",code:1)}
 let cases=try object(Data(contentsOf:URL(fileURLWithPath:path)))
 let row=cases["\(count)/\(mode)/\(network)/\(layer)"] as! [String:Any]
 return row["server_source"] as! String
}
'''
    swift=swift[:begin]+fixture+swift[begin:]
    begin=swift.index('  var paths=[[Data]]()')
    end=swift.index('  for bundles in paths{',begin)
    swift=swift[:begin]+r'''
  guard CommandLine.arguments.count==3,let count=Int(CommandLine.arguments[2]),(3...8).contains(count)else{fatalError("missing complete OpenVPN Last phase")}
  var paths=[([Data],String)]()
  for network in ["tcp","udp"]{for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"]{
   paths.append((try openVPNFixture("mixed",network,"auto",count,layer),try openVPNServerFixture("mixed",network,count,layer)))
  }}
'''+swift[end:]
    def replace(before,after):
        nonlocal swift
        assert swift.count(before)==1,before
        swift=swift.replace(before,after,1)
    replace('  for bundles in paths{for selected in ["local","server"]{','  for (bundles,serverSource) in paths{for selected in ["local","server"]{')
    replace('   let saved=try LibboxTestSavedLast(original.launchInput,selected)','   let saved=try LibboxTestOpenVPNExecutionLast(original.launchInput,selected,serverSource)')
    replace('   if original.isSOCKS{','   if original.isOpenVPN{')
    replace('last.isSOCKS && fields["kind"] as? String=="routervpn-node-chain-socks-execution-preparation-input"','last.isOpenVPN && fields["kind"] as? String=="routervpn-node-chain-openvpn-execution-preparation-input"')
    replace('next.isSOCKS==original.isSOCKS && next.isCONNECT==original.isCONNECT','next.isOpenVPN==original.isOpenVPN && next.isSOCKS==original.isSOCKS && next.isCONNECT==original.isCONNECT')
    replace('   let bundles=try socksFixture(mode,"server",true),final=try profile(bundles.last!)','   let bundles=try openVPNFixture(mode,"tcp","server",count),final=try profile(bundles.last!)\n   let serverSource=try openVPNServerFixture(mode,"tcp",count)')
    replace('   let saved=try LibboxTestSavedLast(original.launchInput,"server")','   let saved=try LibboxTestOpenVPNExecutionLast(original.launchInput,"server",serverSource)')
    replace('reject("Server-only SOCKS Last cannot select Local"){_ = try LibboxTestSavedLast(original.launchInput,"local")}','reject("Server-only OpenVPN Last cannot select Local"){_ = try LibboxTestOpenVPNExecutionLast(original.launchInput,"local",serverSource)}')
    replace('last.isSOCKS && last.requested=="server"','last.isOpenVPN && last.requested=="server"')
    replace('  print("PASS Apple typed restore/Last: \\(checks) checks")','  print("PASS Apple OpenVPN prefix restore/Last nodes=\\(count): \\(checks) checks")')
    swift=swift.replace('SOCKS Last','OpenVPN Last')
    return swift


def main():
    with tempfile.TemporaryDirectory(prefix='ios-openvpn-last-') as folder:
        destination=Path(folder)/'original-provider-fixtures.json'
        SOURCE.emit_fixtures(destination)
        previous=os.environ.get('ROUTER_VPN_APPLE_OPENVPN_FIXTURES')
        os.environ['ROUTER_VPN_APPLE_OPENVPN_FIXTURES']=str(destination)
        try:
            LAST.SWIFT=original_swift()
            LAST.main(binary_cases=[(count,) for count in PREFIX_NODE_COUNTS])
        finally:
            if previous is None:os.environ.pop('ROUTER_VPN_APPLE_OPENVPN_FIXTURES',None)
            else:os.environ['ROUTER_VPN_APPLE_OPENVPN_FIXTURES']=previous


if __name__=='__main__':main()
