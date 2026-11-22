"""Build original imported-node bundles for Swift Local and selected-execution tests."""

INDEPENDENT_BUNDLES = r'''  // Change the original packet assets before any identity/member is captured.
  // The independent imported TUN stays1280; historical effective_mtu stays9000.
  for position in bundles.indices {
   var root=try object(bundles[position]),assets=root["profiles"] as! [String:[String:String]]
   for kind in ["wg","awg2-fast","awg2-strong"] {
    var files=assets[kind]!
    for (name,encoded) in files {if name.hasSuffix(".conf") {let raw=String(decoding:Data(base64Encoded:encoded)!,as:UTF8.self);files[name]=Data(raw.replacingOccurrences(of:"MTU=2000",with:"MTU=\(ceiling)").utf8).base64EncodedString()}}
    assets[kind]=files
   }
   root["profiles"]=assets;bundles[position]=try data(root)
   bundles[position]=try editProfile(bundles[position]){p in p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""}
   if positions.contains(position) {
    var p=try profile(bundles[position]);p["node_kind"]="external";p.removeValue(forKey:"node_proof_id");p["router_api"]="";p["api_token"]="";p["endpoint"]="203.0.113.\(30+position)";p["start_layer"]="off";p["home_lan_access"]=false;p["kill_switch_policy"]="always"
    p["dns_mode"]="custom";p["dns_protocol"]="tcp";p["dns_host"]="10.81.0.53";p["dns_port"]=5353
    p["external"]=["protocol":"shadowsocks","expected_public_ip":"203.0.113.\(80+position)","shadowsocks":["server":"203.0.113.\(30+position)","port":8388+position,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:UInt8(91+position),count:32).base64EncodedString()]]
    bundles[position]=try data(["selectedRouterID":p["id"]!,"routerProfiles":[p],"profiles":[String:[String:String]]()])
   }
  }
  bundles[count-1]=try editProfile(bundles[count-1]){p in var nodes=p["multihop_nodes"] as! [[String:Any]];for position in 0..<count-1 {if positions.contains(position){nodes[position]["mode"]="shadowsocks"}else if mode != "mixed"{nodes[position]["mode"]=mode}};p["multihop_nodes"]=nodes}
  return bundles
 }
'''
