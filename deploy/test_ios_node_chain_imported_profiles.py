#!/usr/bin/env python3
"""Actual Apple Imported SS middle Add/Update/Load/Delete with native source replay.

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
    source=replace_once(source,'static func connectRoundtrip()throws','static func importedSSRoundtrip()throws')
    source=replace_once(source,'for count in 3...8 {for mode in (count==3 ? ["wg","awg2-fast","awg2-strong"]:["wg"]) {for host in (count==3 ? ["198.51.100.76","2001:db8::76"]:["198.51.100.76"]) {for authenticated in (count==3 ? [false,true]:[true]) {for kind in ["http-connect","https-connect"] {','for count in [3,4,8] {for mode in (count==3 ? ["wg","awg2-fast","awg2-strong"] : ["wg"]) {for hostname in [false,true] { let host=hostname ? "Middle.Example.Test":"203.0.113.20",kind="shadowsocks"')
    first=source.index('   var socks:[String:Any]')
    last=source.index('   profile.external=',first)
    source=source[:first]+r'''
   let original:[String:Any]=["protocol":kind,"expected_public_ip":"203.0.113.76","shadowsocks":["server":host,"port":8388,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:79,count:32).base64EncodedString()]]
'''+source[last:]
    source=source.replace('IOSNodeChainCONNECTCapture.compile','IOSNodeChainCapture.compile')
    source=source.replace('afterSource.source==beforeSource.source','afterSource.launchInput==beforeSource.launchInput')
    source=source.replace('PRIVATE-CONNECT-USER','PRIVATE-SS-USER').replace('PRIVATE-CONNECT-PASSWORD','T09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT08=')
    first=source.index('     if kind=="https-connect" {source.routerProfiles[0].external?.httpsConnect?.username=')
    last=source.index('\n    }',first)
    source=source[:first]+'     source.routerProfiles[0].external?.shadowsocks?.password=Data(repeating:80,count:32).base64EncodedString()'+source[last:]
    source=replace_once(source,'(kind=="https-connect" ? stored(ids[middlePosition]).routerProfiles[0].external?.httpsConnect?.password : stored(ids[middlePosition]).routerProfiles[0].external?.httpConnect?.password)','stored(ids[middlePosition]).routerProfiles[0].external?.shadowsocks?.password')
    source=replace_once(source,'  }}}}}','  }}}')
    source=source.replace('=="relinked-valid-password"','==Data(repeating:80,count:32).base64EncodedString()')
    source=source.replace('Typed CONNECT original route','Imported SS original route')
    source=source.replace('failure("actual typed Add callback did not persist")','failure("actual Imported SS Add callback did not persist: "+actions.status)')
    C.TYPED=source
    C.main(label='Imported SS middle',roundtrip='importedSSRoundtrip')
if __name__=='__main__':main()
