#!/usr/bin/env python3
"""Exercise final CONNECT layers through shipping source and restore consumers.

The original complete-count/Off matrices remain required. These additive
four/eight-node paths retain the actual shared source/Last compiler and Swift
control; provider replies, TUN and private-store I/O are explicit boundaries.
"""
import test_ios_connect_execution_control as C

PRELUDE = C.SWIFT[:C.SWIFT.index('@MainActor final class Provider')] + r'''
func layeredCONNECTKind(_ count:Int)->String {count==4 ? "http-connect":"https-connect"}
func layeredCONNECTEntryLayer(_ count:Int,_ finalLayer:String)->String {
 // Preserve the original configured packet budget. Four nodes exercise
 // independently wrapped prefixes; eight retain their original Off prefixes.
 count==8 ? "off":finalLayer=="aes-256-gcm" ? "aes-256-gcm+xor-whitening":"aes-256-gcm"
}
func layeredCONNECTFixture(_ count:Int,_ requested:String,_ finalLayer:String)throws->[Data] {
 guard [4,8].contains(count),["server","auto"].contains(requested),["aes-256-gcm","aes-256-gcm+xor-whitening"].contains(finalLayer) else{throw IOSNodeChainExecutionSession.issue()}
 var bundles=try connectFixture(layeredCONNECTKind(count),"awg2-strong",requested,count,layeredCONNECTEntryLayer(count,finalLayer))
 bundles[count-1]=try editProfile(bundles[count-1]){$0["start_layer"]=finalLayer}
 return bundles
}
'''
SWIFT = PRELUDE + C.SWIFT[C.SWIFT.index('@MainActor final class Provider'):]
before = '''   for count in [3,4,8] {for kind in ["http-connect","https-connect"] {for requested in ["server","auto"] {
    let bundles=try connectFixture(kind,"wg",requested,count),source=try IOSNodeChainExecutionSession.Source.compile(bundles,requested:requested)'''
after = '''   for count in [4,8] {for finalLayer in ["aes-256-gcm","aes-256-gcm+xor-whitening"] {for requested in ["server","auto"] {
    let bundles=try layeredCONNECTFixture(count,requested,finalLayer),source=try IOSNodeChainExecutionSession.Source.compile(bundles,requested:requested)
    let replay=try IOSNodeChainExecutionCapture.reopen(source.input,selectedProfile:profile(bundles[count-1]))
    check(replay.isCONNECT && !replay.isSOCKS && replay.members.count==count && replay.finalProfile["start_layer"] as? String==finalLayer && replay.members.prefix(count-2).allSatisfy{$0.profile["start_layer"] as? String==layeredCONNECTEntryLayer(count,finalLayer)},"layered CONNECT restoration keeps complete independent original source")
    guard case .connect(let original)=replay.local else{fatalError("original typed CONNECT source missing")}
    let metadata=try object(Data(original.plan.metadata().utf8)),proofs=metadata["proofs"] as! [[String:Any]],graph=try object(Data(replay.config.utf8))
    let final=(graph["outbounds"] as! [[String:Any]]).first{$0["tag"] as? String==proofs[count-1]["tag"] as? String}!
    let assets=try object(bundles[count-1])["profiles"] as! [String:[String:String]],saved=try object(Data(base64Encoded:assets["shadowsocks"]!["sing-box.json"]!)!)
    let privateFinal=(saved["outbounds"] as! [[String:Any]]).first{$0["tag"] as? String=="proxy"}!,uot=final["udp_over_tcp"] as? [String:Any]
    check(proofs[count-1]["start_layer"] as? String==finalLayer && final["type"] as? String==(finalLayer=="aes-256-gcm+xor-whitening" ? "routervpn-aes-xor":"shadowsocks") && final["method"] as? String=="2022-blake3-aes-256-gcm" && final["password"] as? String==privateFinal["password"] as? String && uot?["enabled"] as? Bool==true && uot?["version"] as? Int==2 && final["detour"] as? String==proofs[count-2]["tag"] as? String,"selected CONNECT final layer retains original UoT transport and private key")
    check(!replay.healthy(),"layered source cannot claim native proof")
    try replay.close()
    var changed=try object(Data(source.finalProfileJSON.utf8));changed["start_layer"]="off"
    await reject("changed final layer source"){_ = try IOSNodeChainExecutionSession.Source.reopen(source.input,finalProfileJSON:String(decoding:try data(changed),as:UTF8.self))}'''
assert SWIFT.count(before) == 1
SWIFT = SWIFT.replace(before, after, 1).replace('PASS Apple CONNECT control:', 'PASS Apple layered CONNECT control:', 1)


def main():
    C.SWIFT = SWIFT
    # Execute the existing intent, winner, process and cleanup controls.
    C.main(label="layered CONNECT")


if __name__ == '__main__':
    main()
