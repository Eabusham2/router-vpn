#!/usr/bin/env python3
"""Exercise the exact shared Swift capture and source requirement policy."""
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
TEST=r"""
import Foundation
@main struct Test {
 static func main() throws {
  var checks=0
  func check(_ name:String,_ value:Bool){precondition(value,name);checks += 1}
  func reject(_ name:String,_ block:()throws->Void){do{try block();fatalError("accepted "+name)}catch{checks += 1}}
  let profile:[String:Any] = ["id":"entry","node_kind":"router-vpn","start_layer":"off","home_lan_access":false,"dns_mode":"doh3","ipv6_mode":"off","manual_mtu":1500]
  let asset=Data("{\"outbounds\":[]}".utf8).base64EncodedString()
  let assets=["shadowsocks":["sing-box.json":asset]]
  let original=try JSONSerialization.data(withJSONObject:profile,options:[.sortedKeys])
  for alias in ["", "off", "none", "disabled"]{
   var p=profile;p["start_layer"]=alias
   let value=try IOSMultihopStartLayer.capture(profile:p,profiles:[:])
   check("off requires no assets",value.source==nil&&value.mode=="off")
   try IOSMultihopStartLayer.validateExit(p)
  }
  for (alias,mode) in [("aes","aes-256-gcm"),(" AES-256-GCM ","aes-256-gcm"),("aes+xor","aes-256-gcm+xor-whitening"),("aes-xor","aes-256-gcm+xor-whitening"),("aes-256-gcm+xor-whitening","aes-256-gcm+xor-whitening")]{
   var p=profile;p["start_layer"]=alias
   let captured=try IOSMultihopStartLayer.capture(profile:p,profiles:assets)
   check("canonical selection captured",captured.mode==mode&&captured.source != nil)
   var expected=p;expected["start_layer"]="off"
   check("only base composition sees Off",try JSONSerialization.data(withJSONObject:captured.graphProfile,options:[.sortedKeys])==JSONSerialization.data(withJSONObject:expected,options:[.sortedKeys]))
   let source=try JSONSerialization.jsonObject(with:Data(captured.source!.utf8)) as! [String:Any]
   check("exact node source retained",source["profile"] as? [String:String]==assets["shadowsocks"])
   let metadata=String(decoding:try JSONSerialization.data(withJSONObject:["entry_start_layer":mode]),as:UTF8.self)
   check("required source retained",try IOSMultihopStartLayer.requiredSource(metadata:metadata,source:captured.source)==captured.source)
   reject("requested source missing"){_=try IOSMultihopStartLayer.requiredSource(metadata:metadata,source:nil)}
   reject("requested source empty"){_=try IOSMultihopStartLayer.requiredSource(metadata:metadata,source:"")}
   reject("unrequested source"){_=try IOSMultihopStartLayer.requiredSource(metadata:"{}",source:captured.source)}
   reject("owner missing"){_=try IOSMultihopStartLayer.requiredSource(metadata:nil,source:captured.source)}
   reject("exit cannot silently omit layer"){try IOSMultihopStartLayer.validateExit(p)}
   reject("missing source assets"){_=try IOSMultihopStartLayer.capture(profile:p,profiles:[:])}
   var external=p;external["node_kind"]="external"
   reject("source is not the home node"){_=try IOSMultihopStartLayer.capture(profile:external,profiles:assets)}
   for bad in ["{}","{\"mode\":\"off\",\"profile\":{}}",String(repeating:" ",count:16385)]{
    reject("corrupt or changed source"){_=try IOSMultihopStartLayer.requiredSource(metadata:metadata,source:bad)}
   }
  }
  for bad:Any in [true,3,NSNull(),"xor","other"]{var p=profile;p["start_layer"]=bad;reject("invalid mode type"){_=try IOSMultihopStartLayer.capture(profile:p,profiles:assets)}}
  var requested=profile;requested["start_layer"]="aes"
  for bad in ["",asset+"\n","!base64",Data([0xff]).base64EncodedString(),String(repeating:"A",count:16385)]{
   reject("noncanonical or oversized asset"){_=try IOSMultihopStartLayer.capture(profile:requested,profiles:["shadowsocks":["sing-box.json":bad]])}
  }
  reject("extra source helper"){_=try IOSMultihopStartLayer.capture(profile:requested,profiles:["shadowsocks":["sing-box.json":asset,"helper":"e30="]])}
  check("ordinary factory unchanged",try IOSMultihopStartLayer.requiredSource(metadata:nil,source:nil)==nil)
  check("ordinary metadata unchanged",try IOSMultihopStartLayer.requiredSource(metadata:"{}",source:nil)==nil)
  reject("invalid required mode type"){_=try IOSMultihopStartLayer.requiredSource(metadata:"{\"entry_start_layer\":true}",source:nil)}
  check("caller source unchanged",try JSONSerialization.data(withJSONObject:profile,options:[.sortedKeys])==original)
  print("Apple captured entry-layer policy: PASS (\(checks) checks; no engine or network started)")
 }
}
"""
def main():
 with tempfile.TemporaryDirectory(prefix='entry-layer-capture-') as tmp:
  root=Path(tmp);source=root/'test.swift';source.write_text(TEST);binary=root/'tests'
  subprocess.run(['swiftc','-swift-version','6',str(ROOT/'ios/RouterVPN/App/IOSMultihopStartLayer.swift'),str(source),'-o',str(binary)],check=True,timeout=60)
  subprocess.run([str(binary)],check=True,timeout=10)
if __name__=='__main__':main()
