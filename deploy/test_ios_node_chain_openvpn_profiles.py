#!/usr/bin/env python3
"""Actual Apple OpenVPN middle Add/Update/Load/Delete with native source replay.

Uses the existing transaction fixture's storage/NetworkExtension boundaries;
all profile callbacks, source compilation and original credential checks are
shipping methods. No native tunnel or device acceptance is inferred.
"""
import test_ios_node_chain_connect_profiles as C

def replace_once(source, before, after):
    assert source.count(before)==1, before
    return source.replace(before,after,1)

def main():
    source=C.TYPED
    source=replace_once(source,'static func connectRoundtrip()throws','static func openVPNRoundtrip()throws')
    source=replace_once(source,'for count in 3...8 {for mode in (count==3 ? ["wg","awg2-fast","awg2-strong"]:["wg"]) {for host in (count==3 ? ["198.51.100.76","2001:db8::76"]:["198.51.100.76"]) {for authenticated in (count==3 ? [false,true]:[true]) {for kind in ["http-connect","https-connect"] {','for count in [3,4,8] {for mode in (count==3 ? ["wg","awg2-fast","awg2-strong"] : ["wg"]) {for network in ["tcp","udp"] { let host="203.0.113.20",kind="openvpn"')
    # This Local profile fixture removes CONNECT's authentication loop. Its
    # source family and execution scope remain independent of CONNECT choices.
    source=replace_once(source,'for requested in ([3,4,8].contains(count) && mode=="wg" && host=="198.51.100.76" && authenticated ? ["local","server","auto"]:["local"]) {','for requested in ["local"] {')
    first=source.index('   var socks:[String:Any]')
    last=source.index('   profile.external=',first)
    source=source[:first]+r'''
   let raw="client\ndev tun\nproto "+network+"\nremote "+host+" 1194\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint "+String(repeating:"ab",count:32)+"\ntun-mtu 1400\ndata-ciphers AES-256-GCM:AES-128-GCM\n"
   let original:[String:Any]=["protocol":kind,"expected_public_ip":"203.0.113.76","openvpn":["config":raw,"username":"PRIVATE-OPENVPN-USER","password":"PRIVATE-OPENVPN-PASSWORD"]]
'''+source[last:]
    source=source.replace('IOSNodeChainCONNECTCapture.compile','IOSNodeChainCapture.compile')
    source=source.replace('afterSource.source==beforeSource.source','afterSource.launchInput==beforeSource.launchInput')
    source=source.replace('PRIVATE-CONNECT-USER','PRIVATE-OPENVPN-USER').replace('PRIVATE-CONNECT-PASSWORD','PRIVATE-OPENVPN-PASSWORD')
    first=source.index('     if kind=="https-connect" {source.routerProfiles[0].external?.httpsConnect?.username=')
    last=source.index('\n    }',first)
    source=source[:first]+'     source.routerProfiles[0].external?.openVPN?.username="relinked-user";source.routerProfiles[0].external?.openVPN?.password="relinked-valid-password"'+source[last:]
    source=replace_once(source,'(kind=="https-connect" ? stored(ids[middlePosition]).routerProfiles[0].external?.httpsConnect?.password : stored(ids[middlePosition]).routerProfiles[0].external?.httpConnect?.password)','stored(ids[middlePosition]).routerProfiles[0].external?.openVPN?.password')
    source=replace_once(source,'  }}}}}','  }}}')
    source=source.replace('Typed CONNECT original route','OpenVPN original route')
    source=source.replace('failure("actual typed Add callback did not persist")','failure("actual OpenVPN Add callback did not persist: "+actions.status)')
    C.TYPED=source
    C.main(label='OpenVPN middle',roundtrip='openVPNRoundtrip')
if __name__=='__main__':main()
