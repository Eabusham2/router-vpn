#!/usr/bin/env python3
"""Exercise selected SOCKS final layers through the actual opaque restore control.

The published complete-count/Off tests remain separate. These focused sources
use the real shared source/Last parsers and original Swift control; native
provider replies and private-store I/O remain explicit test boundaries.
"""
import test_ios_connect_execution_control as C
import test_ios_socks_execution_capture as S

PRELUDE=C.SWIFT[:C.SWIFT.index('@MainActor final class Provider')]+S.SWIFT[S.SWIFT.index('func socksFixture('):S.SWIFT.index('@main struct Tests')]+r'''
func layeredSOCKSEntryLayer(_ count:Int,_ finalLayer:String)->String {
 // Keep the original eight-node packet budget. The independent wrapped entry
 // is exercised at four nodes; no synthetic MTU or wider assets are supplied.
 count==8 ? "off":finalLayer=="aes-256-gcm" ? "aes-256-gcm+xor-whitening":"aes-256-gcm"
}
func layeredSOCKSFixture(_ count:Int,_ requested:String,_ finalLayer:String)throws->[Data] {
 guard [4,8].contains(count),["server","auto"].contains(requested),["aes-256-gcm","aes-256-gcm+xor-whitening"].contains(finalLayer) else{throw IOSNodeChainExecutionSession.issue()}
 var bundles=try socksFixture("awg2-strong",requested,true,count,layeredSOCKSEntryLayer(count,finalLayer))
 bundles[count-1]=try editProfile(bundles[count-1]){$0["start_layer"]=finalLayer}
 return bundles
}
'''
SWIFT=PRELUDE+C.SWIFT[C.SWIFT.index('@MainActor final class Provider'):]
before='''   for count in [3,4,8] {for kind in ["http-connect","https-connect"] {for requested in ["server","auto"] {
    let bundles=try connectFixture(kind,"wg",requested,count),source=try IOSNodeChainExecutionSession.Source.compile(bundles,requested:requested)'''
after='''   for count in [4,8] {for finalLayer in ["aes-256-gcm","aes-256-gcm+xor-whitening"] {for requested in ["server","auto"] {
    let bundles=try layeredSOCKSFixture(count,requested,finalLayer),source=try IOSNodeChainExecutionSession.Source.compile(bundles,requested:requested)
    let replay=try IOSNodeChainExecutionCapture.reopen(source.input,selectedProfile:profile(bundles[count-1]))
    check(replay.isSOCKS && !replay.isCONNECT && replay.members.count==count && replay.finalProfile["start_layer"] as? String==finalLayer && replay.members.prefix(count-2).allSatisfy{$0.profile["start_layer"] as? String==layeredSOCKSEntryLayer(count,finalLayer)},"layered SOCKS restoration keeps complete independent original source")
    guard case .socks(let original)=replay.local else{fatalError("original typed SOCKS source missing")}
    let metadata=try object(Data(original.plan.metadata().utf8)),proofs=metadata["proofs"] as! [[String:Any]],graph=try object(Data(replay.config.utf8))
    let final=(graph["outbounds"] as! [[String:Any]]).first{$0["tag"] as? String==proofs[count-1]["tag"] as? String}!
    let assets=try object(bundles[count-1])["profiles"] as! [String:[String:String]],saved=try object(Data(base64Encoded:assets["shadowsocks"]!["sing-box.json"]!)!)
    let privateFinal=(saved["outbounds"] as! [[String:Any]]).first{$0["tag"] as? String=="proxy"}!
    check(proofs[count-1]["start_layer"] as? String==finalLayer && final["type"] as? String==(finalLayer=="aes-256-gcm+xor-whitening" ? "routervpn-aes-xor":"shadowsocks") && final["method"] as? String=="2022-blake3-aes-256-gcm" && final["password"] as? String==privateFinal["password"] as? String && final["udp_over_tcp"]==nil,"selected SOCKS final layer retains original native transport and private key")
    check(!replay.healthy(),"layered source cannot claim native proof")
    try replay.close()
    var changed=try object(Data(source.finalProfileJSON.utf8));changed["start_layer"]="off"
    await reject("changed final layer source"){_ = try IOSNodeChainExecutionSession.Source.reopen(source.input,finalProfileJSON:String(decoding:try data(changed),as:UTF8.self))}'''
assert SWIFT.count(before)==1
SWIFT=SWIFT.replace(before,after,1).replace('PASS Apple CONNECT control:','PASS Apple layered SOCKS control:',1)


def main():
    C.SWIFT=SWIFT
    # Keep the four original compiled intent, winner, process and release controls.
    C.main(label="layered SOCKS")


if __name__=='__main__':main()
