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
        subprocess.run([str(binary)], check=True, timeout=20)
    provider = (ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
    assert 'currentPathProofGuard() === guardState' in provider
    assert 'engine.bindMultihopExecutionSource(source, metadata: hopMetadata)' in provider
    assert '"execution": restoredMultihopExecution ?? selectedProfile["multihop_execution"]' in provider
    assert '} else if execution == "local" { try engine.start(files: finalFiles, strict: strict) }' not in provider
    assert 'App/IOSMultihopExecution.swift' in (ROOT/'ios/RouterVPN/project.yml').read_text()

if __name__ == '__main__':
    main()
