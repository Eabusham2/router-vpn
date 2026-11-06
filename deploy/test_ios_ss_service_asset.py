#!/usr/bin/env python3
"""Exercise the unchanged shipping Swift capture with actual SHA256 providers."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import ios_test_crypto_bridge as crypto
ROOT=Path(__file__).resolve().parents[1]
SWIFT=r'''import Foundation
@main struct Tests {
 static func main() throws {
  let root=URL(fileURLWithPath:CommandLine.arguments[1]);let files=try JSONSerialization.jsonObject(with:Data(contentsOf:root)) as! [String:String]
  let node=String(repeating:"a",count:64),profile:[String:Any]=["node_kind":"router-vpn","node_proof_id":String(repeating:"a",count:64),"start_layer":"aes-256-gcm"]
  var ordinary=files;ordinary.removeValue(forKey:"routervpn-ss-service.json")
  let old=try IOSMultihopStartLayer.capture(profile:profile,profiles:["shadowsocks":ordinary])
  let current=try IOSMultihopStartLayer.capture(profile:profile,profiles:["shadowsocks":files])
  precondition(old.mode==current.mode && old.source != current.source && NSDictionary(dictionary:old.graphProfile).isEqual(to:current.graphProfile))
  let retained=try JSONSerialization.jsonObject(with:Data(current.source!.utf8)) as! [String:Any]
  precondition((retained["profile"] as! [String:String])==files)
  try IOSMultihopStartLayer.validateCapturedSSService(files,node:node)
  var count=3
  for fault in ["missing", "wrong-type", "foreign"] {
   var changed=profile
   if fault=="missing" {changed.removeValue(forKey:"node_proof_id")}
   if fault=="wrong-type" {changed["node_proof_id"]=true}
   if fault=="foreign" {changed["node_proof_id"]=String(repeating:"b",count:64)}
   do {_ = try IOSMultihopStartLayer.capture(profile:changed,profiles:["shadowsocks":files]);fatalError("accepted missing/foreign captured node: "+fault)}catch{}
   count+=1
  }
  for fault in ["node","image","schema","version","endpoint","port","method","key","source","raw-whitespace","extra","unknown","malformed"] {
   var changed=files,claim=try JSONSerialization.jsonObject(with:Data(base64Encoded:files["routervpn-ss-service.json"]!)!) as! [String:Any]
   switch fault {
   case "node":claim["node_id"]=String(repeating:"b",count:64)
   case "image":claim["configured_image"]="foreign:latest"
   case "schema":claim["schema"]=2
   case "version":claim["uot_version"]=true
   case "endpoint":claim["endpoint"]="192.0.2.99"
   case "port":claim["port"]=9999
   case "method":claim["method"]="foreign"
   case "key":claim["key_sha256"]=String(repeating:"b",count:64)
   case "source":claim["source_sha256"]=String(repeating:"b",count:64)
   case "raw-whitespace":var raw=Data(base64Encoded:files["sing-box.json"]!)!;raw.append(10);changed["sing-box.json"]=raw.base64EncodedString()
   case "extra":claim["foreign"]=true
   default:break
   }
   changed["routervpn-ss-service.json"]=try JSONSerialization.data(withJSONObject:claim,options:[.sortedKeys]).base64EncodedString()
   if fault=="unknown" {changed["foreign.json"]=changed.removeValue(forKey:"routervpn-ss-service.json")}
   if fault=="malformed" {changed["routervpn-ss-service.json"]=Data("{".utf8).base64EncodedString()}
   do {_ = try IOSMultihopStartLayer.capture(profile:profile,profiles:["shadowsocks":changed]);fatalError("accepted foreign service: "+fault)}catch{}
   count+=1
  }
  print("Apple SS service companion: PASS \(count) actual capture/hash controls; no UoT activation")
 }
}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='ios-ss-service-') as temporary:
        root=Path(temporary);flags,env=crypto.prepare(root/'crypto')
        key=base64.b64encode(b's'*32).decode()
        raw=json.dumps({'outbounds':[{'type':'shadowsocks','tag':'proxy','server':'192.0.2.44','server_port':8388,'method':'2022-blake3-aes-256-gcm','password':key}]},sort_keys=True).encode()+b'\n'
        claim={'schema':1,'node_id':'a'*64,'configured_image':'ghcr.io/sagernet/sing-box:v1.13.12','uot_version':2,'endpoint':'192.0.2.44','port':8388,'method':'2022-blake3-aes-256-gcm','key_sha256':hashlib.sha256(key.encode()).hexdigest(),'source_sha256':hashlib.sha256(raw).hexdigest()}
        files={'sing-box.json':base64.b64encode(raw).decode(),'routervpn-ss-service.json':base64.b64encode(json.dumps(claim).encode()).decode()}
        fixture=root/'files.json';fixture.write_text(json.dumps(files));test=root/'Tests.swift';test.write_text(SWIFT)
        subprocess.run(['swiftc','-swift-version','6',*flags,str(ROOT/'ios/RouterVPN/App/IOSMultihopStartLayer.swift'),str(test),'-o',str(root/'tests')],check=True,timeout=90)
        subprocess.run([str(root/'tests'),str(fixture)],env=dict(os.environ,**env),check=True,timeout=30)
if __name__=='__main__': main()
