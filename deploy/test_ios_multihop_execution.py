#!/usr/bin/env python3
"""Run shared app/extension multihop restoration parsing and source ownership.

Hash inputs are explicitly substituted here; shipping callers use SHA-256.
The native controller/Box health has separate runtime and delivery gates.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
SWIFT = r'''
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ text:String,_ value:@autoclosure()->Bool){guard value()else{fatalError("FAIL: "+text)};checks+=1}
 static func reject(_ text:String,_ action:()throws->Void){do{try action();fatalError("FAIL: "+text)}catch{checks+=1}}
 static func digest(_ data:Data)->String{let hash=data.reduce(UInt64(14695981039346656037)){($0 ^ UInt64($1)) &* 1099511628211};return String(repeating:String(format:"%016llx",hash),count:4)}
 static func source(_ requested:String="auto",_ entry:String="max-quic-awg",_ exit:String="reality-xhttp")throws->[String:Any]{
  let bundle=try JSONSerialization.data(withJSONObject:["selectedRouterID":"exit","routerProfiles":[["id":"exit","multihop_enabled":true,"multihop_entry_id":"entry","multihop_exit_id":"exit","multihop_entry_mode":entry,"multihop_exit_mode":exit,"multihop_execution":requested]],"profiles":["private":"exact exit credential bytes"]])
  let predecessor=try JSONSerialization.data(withJSONObject:["selectedRouterID":"entry","routerProfiles":[["id":"entry"]],"profiles":["private":"exact entry credential bytes"]])
  return ["engine":"multihop-libbox","rawProfileID":exit,"bundle":bundle,"entryBundle":predecessor]
 }
 static func external(_ requested:String="auto",_ kind:String="shadowsocks",_ layer:String="off")throws->[String:Any]{
  var profile:[String:Any]=["id":"external-exit","node_kind":"external","external":["protocol":kind,"shadowsocks":["server":"198.51.100.8","password":"exact captured external credential"],"response_probe":["url":"https://198.51.100.8/response","server_name":"node.example.test"]],"multihop_enabled":true,"multihop_entry_id":"entry","multihop_exit_id":"external-exit","multihop_entry_mode":"max-tls-awg","multihop_exit_mode":kind,"multihop_execution":requested]
  if layer != "off" {var ext=profile["external"] as! [String:Any];ext["start_layer"]=["mode":layer,"api":"http://10.99.0.1:8787","transport":["type":"shadowsocks","tag":"provisioned-exit-layer","server":"198.51.100.8","server_port":8388,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:7,count:32).base64EncodedString()]];profile["external"]=ext;profile["start_layer"]=layer}
  let root:[String:Any]=["selectedRouterID":"external-exit","routerProfiles":[profile]]
  let predecessor=try source()["entryBundle"] as! Data
  return ["engine":"external-libbox","mode":"external-"+kind,"bundle":try JSONSerialization.data(withJSONObject:root),"external_entry_bundle":predecessor,"external_entry_mode":"max-tls-awg"]
 }
 static func mapped(_ requested:String="auto",_ layer:String="off")throws->[String:Any]{
  var value=try external(requested,"openvpn"),root=try JSONSerialization.jsonObject(with:value["bundle"] as! Data) as! [String:Any]
  let index=layer=="off" ? 1:layer=="aes-256-gcm" ? 2:3
  let fixture=try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[index]))) as! [String:Any]
  var profiles=root["routerProfiles"] as! [[String:Any]]
  profiles[0]["external"]=fixture["external"];profiles[0]["start_layer"]=layer;root["routerProfiles"]=profiles
  value["bundle"]=try JSONSerialization.data(withJSONObject:root,options:.sortedKeys)
  return value
 }
 static func main()throws{
  let session=UUID().uuidString,request=String(repeating:"d",count:32),hold=String(repeating:"e",count:32)
  for entry in ["wg","awg2-strong","reality-xhttp","max-quic-awg"] {for requested in ["local","server","auto"]{
   let config=try source(requested,entry),before=try IOSMultihopExecution.Source(configuration:config,digest:digest)
   for winner in ["local","server"]{
    if requested != "auto" && requested != winner {
     reject("fixed execution cannot grant a different winner"){_ = try IOSMultihopExecution.Capture(source:before,execution:winner,session:session,request:request)}
     continue
    }
    let capture=try IOSMultihopExecution.Capture(source:before,execution:winner,session:session,request:request)
    let bytes=try capture.encoded(),text=String(decoding:bytes,as:UTF8.self)
    let parsed=try IOSMultihopExecution.Capture.decode(bytes,source:before,request:request)
    check("capture retains exact requested policy and actual winner",parsed==capture && parsed.source.requested==requested)
    let selected=try IOSMultihopExecution.restoredExecution(option:text as NSString,source:before,mtuHold:hold)
    let unchanged=try IOSMultihopExecution.Source(configuration:config,digest:digest)
    check("runtime launch option forces only proved winner",selected==winner && before==unchanged)
    check("launch receipt contains no private configuration",!text.contains("credential") && !text.contains("private"))
   }
  }}
  let config=try source(),capturedSource=try IOSMultihopExecution.Source(configuration:config,digest:digest)
  let capture=try IOSMultihopExecution.Capture(source:capturedSource,execution:"server",session:session,request:request)
  let bytes=try capture.encoded(),text=String(decoding:bytes,as:UTF8.self)
  let ordinary=try IOSMultihopExecution.restoredExecution(option:nil,source:capturedSource,mtuHold:"")
  check("ordinary startup does not invent restoration override",ordinary==nil)
  for field in ["bundle","entryBundle"]{
   var changed=config
   var object=try JSONSerialization.jsonObject(with:changed[field] as! Data) as! [String:Any]
   object["profiles"]=["private":"replacement credentials with identical displayed IDs"]
   changed[field]=try JSONSerialization.data(withJSONObject:object)
   let replacement=try IOSMultihopExecution.Source(configuration:changed,digest:digest)
   reject("same labels cannot restore changed credentials "+field){_ = try IOSMultihopExecution.Capture.decode(bytes,source:replacement,request:request)}
  }
  for field in ["schema","request_id","session_id","healthy","execution","extra"]{
   var object=try JSONSerialization.jsonObject(with:bytes) as! [String:Any]
   switch field {
   case "schema":object[field]=true
   case "request_id":object[field]=String(repeating:"a",count:32)
   case "session_id":object[field]="not-an-epoch"
   case "healthy":object[field]=false
   default:object[field]="auto"
   }
   let bad=try JSONSerialization.data(withJSONObject:object)
   reject("invalid native receipt cannot restore "+field){_ = try IOSMultihopExecution.Capture.decode(bad,source:capturedSource,request:request)}
  }
  for field in ["bundle_sha256","entry_sha256","entry_id","exit_id","entry_mode","exit_mode","requested","extra"]{
   var object=try JSONSerialization.jsonObject(with:bytes) as! [String:Any],changed=object["source"] as! [String:Any]
   changed[field]=field.hasSuffix("sha256") ? String(repeating:"f",count:64):"replacement"
   object["source"]=changed
   let bad=try JSONSerialization.data(withJSONObject:object)
   reject("source mismatch rejects restoration "+field){_ = try IOSMultihopExecution.Capture.decode(bad,source:capturedSource,request:request)}
  }
  for hold in ["","foreign"," "+hold]{reject("restoration requires its active MTU lease"){_ = try IOSMultihopExecution.restoredExecution(option:text as NSString,source:capturedSource,mtuHold:hold)}}
  for malformed:NSObject in [NSNumber(value:true),NSData(data:bytes),String(repeating:"a",count:4097) as NSString]{reject("non-text or unbounded option is rejected"){_ = try IOSMultihopExecution.restoredExecution(option:malformed,source:capturedSource,mtuHold:hold)}}
  for changed in ["raw","missing-entry","mixed-engine","duplicate-selection","wrong-entry","wrong-exit","disabled"]{
   var value=config
   if changed=="raw"{value["rawProfileID"]="wg"}
   else if changed=="missing-entry"{value.removeValue(forKey:"entryBundle")}
   else if changed=="mixed-engine"{value["engine"]="external-libbox"}
   else {
    var object=try JSONSerialization.jsonObject(with:value["bundle"] as! Data) as! [String:Any]
    var profiles=object["routerProfiles"] as! [[String:Any]]
    if changed=="duplicate-selection"{profiles.append(profiles[0])}
    if changed=="wrong-entry"{profiles[0]["multihop_entry_id"]="another-entry"}
    if changed=="wrong-exit"{profiles[0]["multihop_exit_id"]="another-exit"}
    if changed=="disabled"{profiles[0]["multihop_enabled"]=false}
    object["routerProfiles"]=profiles;value["bundle"]=try JSONSerialization.data(withJSONObject:object)
   }
   reject("invalid frozen predecessor roles "+changed){_ = try IOSMultihopExecution.Source(configuration:value,digest:digest)}
  }
  for kind in ["shadowsocks","hysteria2","socks5","http-connect","https-connect"] { for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] { for requested in ["server","auto"] {
   let original=try external(requested,kind,layer),source=try IOSMultihopExecution.Source(configuration:original,digest:digest)
   let needsReceipt=try IOSMultihopExecution.requiresCapture(configuration:original)
   check("external execution requires captured runtime receipt",needsReceipt)
   for winner in ["local","server"] where requested=="auto" || requested==winner {
    let receipt=try IOSMultihopExecution.Capture(source:source,execution:winner,session:session,request:request)
    let bytes=try receipt.encoded(),parsed=try IOSMultihopExecution.Capture.decode(bytes,source:source,request:request)
    let override=try IOSMultihopExecution.restoredExecution(option:String(decoding:bytes,as:UTF8.self) as NSString,source:source,mtuHold:hold)
    check("external restore retains requested Compare and proved choice",parsed==receipt && override==winner && source.requested==requested)
    check("receipt never copies external credentials or relay endpoints",!String(decoding:bytes,as:UTF8.self).contains("credential") && !String(decoding:bytes,as:UTF8.self).contains("response_probe"))
    for field in ["bundle","external_entry_bundle"] {
     var changed=original,root=try JSONSerialization.jsonObject(with:original[field] as! Data) as! [String:Any]
     root["profiles"]=["private":"changed private transport"]
     changed[field]=try JSONSerialization.data(withJSONObject:root)
     let replacement=try IOSMultihopExecution.Source(configuration:changed,digest:digest)
     reject("external labels cannot restore replaced credential source "+field){_ = try IOSMultihopExecution.Capture.decode(bytes,source:replacement)}
    }
   }
   for mutation in ["entryBundle","tor_entry_bundle","tor_entry_mode","external_entry_mode","mode","rawProfileID"] {
    var changed=original
    changed[mutation]=mutation.hasSuffix("bundle") || mutation=="entryBundle" ? original["external_entry_bundle"] : "foreign"
    reject("external receipt rejects mixed engine/source "+mutation){_ = try IOSMultihopExecution.Source(configuration:changed,digest:digest)}
   }
  }}}
  for kind in ["wireguard","amneziawg","openvpn","unknown"] {reject("unsupported external protocol cannot acquire restoration owner"){_ = try IOSMultihopExecution.Source(configuration:external("server",kind),digest:digest)}}
  for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] { for requested in ["server","auto"] {
   let original=try mapped(requested,layer),source=try IOSMultihopExecution.Source(configuration:original,digest:digest)
   let needsReceipt=try IOSMultihopExecution.requiresCapture(configuration:original)
   check("paired mapped OpenVPN captures the proved runtime owner",needsReceipt && source.requested==requested)
   for winner in ["local","server"] where requested=="auto" || requested==winner {
    let receipt=try IOSMultihopExecution.Capture(source:source,execution:winner,session:session,request:request),bytes=try receipt.encoded()
    let restored=try IOSMultihopExecution.restoredExecution(option:String(decoding:bytes,as:UTF8.self) as NSString,source:source,mtuHold:hold)
    check("mapped OpenVPN restores the proved winner without rerunning Compare",restored==winner && source.requested==requested)
    check("mapped receipt omits private map, provider identities and pairing",!String(decoding:bytes,as:UTF8.self).contains("provider.example") && !String(decoding:bytes,as:UTF8.self).contains("openvpn_response_probes") && !String(decoding:bytes,as:UTF8.self).contains("private_key") && !String(decoding:bytes,as:UTF8.self).contains("openvpn_start_layers") && !String(decoding:bytes,as:UTF8.self).contains("10.93.0.1"))
    for field in ["probe","provider","pairing","remote","entry"]+(layer=="off" ? []:["layer-key","layer-api","layer-port","layer-host","entry-layer"]) {
     var changed=original,root=try JSONSerialization.jsonObject(with:original["bundle"] as! Data) as! [String:Any],profiles=root["routerProfiles"] as! [[String:Any]],ext=profiles[0]["external"] as! [String:Any]
     if field=="probe" {var map=ext["openvpn_response_probes"] as! [String:Any],probe=map["203.0.113.21"] as! [String:Any];probe["server_name"]="replacement.example";map["203.0.113.21"]=probe;ext["openvpn_response_probes"]=map}
     if field=="provider" {var value=ext["openvpn"] as! [String:Any];value["password"]="replacement credential";ext["openvpn"]=value}
     if field=="pairing" {var pair=ext["openvpn_pairing"] as! [String:Any];pair["private_key"]=Data(repeating:4,count:32).base64EncodedString();ext["openvpn_pairing"]=pair}
     if field=="remote" {var value=ext["openvpn"] as! [String:Any];value["config"]=(value["config"] as! String).replacingOccurrences(of:"443 tcp",with:"8443 tcp");ext["openvpn"]=value}
     if field.hasPrefix("layer-") {
      var layers=ext["openvpn_start_layers"] as! [String:Any],provision=layers["203.0.113.21"] as! [String:Any],transport=provision["transport"] as! [String:Any]
      if field=="layer-key" {transport["password"]=Data(repeating:9,count:32).base64EncodedString()}
      if field=="layer-api" {provision["api"]="http://10.94.0.1:8787"}
      if field=="layer-port" {transport["server_port"]=8443}
      if field=="layer-host" {transport["server"]="203.0.113.99"}
      provision["transport"]=transport;layers["203.0.113.21"]=provision;ext["openvpn_start_layers"]=layers
     }
     profiles[0]["external"]=ext;root["routerProfiles"]=profiles;changed["bundle"]=try JSONSerialization.data(withJSONObject:root,options:.sortedKeys)
     if field=="entry" {var entry=try JSONSerialization.jsonObject(with:original["external_entry_bundle"] as! Data) as! [String:Any];entry["profiles"]=["private":"replacement entry credential"];changed["external_entry_bundle"]=try JSONSerialization.data(withJSONObject:entry,options:.sortedKeys)}
     if field=="entry-layer" {var entry=try JSONSerialization.jsonObject(with:original["external_entry_bundle"] as! Data) as! [String:Any],nodes=entry["routerProfiles"] as! [[String:Any]];nodes[0]["start_layer"]="aes-256-gcm";entry["routerProfiles"]=nodes;changed["external_entry_bundle"]=try JSONSerialization.data(withJSONObject:entry,options:.sortedKeys)}
     let replacement=try IOSMultihopExecution.Source(configuration:changed,digest:digest)
     reject("mapped OpenVPN receipt cannot adopt changed captured "+field){_ = try IOSMultihopExecution.Capture.decode(bytes,source:replacement)}
    }
   }
   for fault in ["missing-pair","null-pair","legacy-probe","null-map","one-host","bad-value","exit-layer","selected-layer","foreign-protocol"]+(layer=="off" ? []:["missing-layer-map","null-layer-map","partial-layer-map","mixed-layer-mode","unknown-layer-field","foreign-layer-host","layered-no-probes"]) {
    var changed=original,root=try JSONSerialization.jsonObject(with:original["bundle"] as! Data) as! [String:Any],profiles=root["routerProfiles"] as! [[String:Any]],ext=profiles[0]["external"] as! [String:Any]
    switch fault {
    case "missing-pair":ext.removeValue(forKey:"openvpn_pairing")
    case "null-pair":ext["openvpn_pairing"]=NSNull()
    case "legacy-probe":ext["response_probe"]=["url":"https://203.0.113.20/response"]
    case "null-map":ext["openvpn_response_probes"]=NSNull()
    case "one-host":ext["openvpn_response_probes"]=["203.0.113.20":["url":"https://203.0.113.20/response"]]
    case "bad-value":ext["openvpn_response_probes"]=["203.0.113.20":NSNull(),"203.0.113.21":NSNull()]
    case "exit-layer":ext["start_layer"]=["mode":"aes-256-gcm"]
    case "selected-layer":profiles[0]["start_layer"]=layer=="off" ? "aes-256-gcm":"off"
    case "missing-layer-map":ext.removeValue(forKey:"openvpn_start_layers")
    case "null-layer-map":ext["openvpn_start_layers"]=NSNull()
    case "partial-layer-map":var layers=ext["openvpn_start_layers"] as! [String:Any];layers.removeValue(forKey:"203.0.113.21");ext["openvpn_start_layers"]=layers
    case "mixed-layer-mode":var layers=ext["openvpn_start_layers"] as! [String:Any],provision=layers["203.0.113.21"] as! [String:Any];provision["mode"]=layer=="aes-256-gcm" ? "aes-256-gcm+xor-whitening":"aes-256-gcm";layers["203.0.113.21"]=provision;ext["openvpn_start_layers"]=layers
    case "unknown-layer-field":var layers=ext["openvpn_start_layers"] as! [String:Any],provision=layers["203.0.113.21"] as! [String:Any];provision["unknown"]=true;layers["203.0.113.21"]=provision;ext["openvpn_start_layers"]=layers
    case "foreign-layer-host":var layers=ext["openvpn_start_layers"] as! [String:Any];layers["203.0.113.99"]=layers.removeValue(forKey:"203.0.113.21");ext["openvpn_start_layers"]=layers
    case "layered-no-probes":ext.removeValue(forKey:"openvpn_response_probes")
    default:ext["protocol"]="shadowsocks"
    }
    profiles[0]["external"]=ext;root["routerProfiles"]=profiles;changed["bundle"]=try JSONSerialization.data(withJSONObject:root,options:.sortedKeys)
    reject("mapped restore rejects incompatible captured contract "+fault){_ = try IOSMultihopExecution.Source(configuration:changed,digest:digest)}
   }
  }}
  let local=try external("local"),needsLocal=try IOSMultihopExecution.requiresCapture(configuration:local)
  check("plain external Local does not invent lease ownership",!needsLocal)
  reject("plain external Local cannot adopt an unrelated execution receipt"){_ = try IOSMultihopExecution.Source(configuration:local,digest:digest)}
  print("Apple exact multihop winner receipt: PASS (\(checks) shipping Swift checks)")
 }
}
'''

def main():
    swift = shutil.which('swiftc')
    if not swift:
        raise SystemExit('swiftc required')
    with tempfile.TemporaryDirectory(prefix='routervpn-ios-execution-') as folder:
        path, binary = Path(folder)/'test.swift', Path(folder)/'test'
        path.write_text((APP/'IOSMultihopExecution.swift').read_text()+'\n'+SWIFT)
        subprocess.run([swift, '-swift-version', '6', '-parse-as-library', str(path), '-o', str(binary)], check=True, timeout=90)
        fixtures=[ROOT/'deploy/fixtures'/name for name in ['external-openvpn-multihost-client.json','external-openvpn-multihost-layered-aes-client.json','external-openvpn-multihost-layered-xor-client.json']]
        subprocess.run([str(binary), *map(str,fixtures)], check=True, timeout=20)
    provider = (ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
    assert 'currentPathProofGuard() === guardState' in provider
    assert 'engine.bindMultihopExecutionSource(source, metadata: hopMetadata)' in provider
    assert '"execution": restoredMultihopExecution ?? selectedProfile["multihop_execution"]' in provider
    assert '} else if execution == "local" { try engine.start(files: finalFiles, strict: strict) }' not in provider
    assert 'App/IOSMultihopExecution.swift' in (ROOT/'ios/RouterVPN/project.yml').read_text()

if __name__ == '__main__':
    main()
