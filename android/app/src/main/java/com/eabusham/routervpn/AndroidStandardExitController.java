package com.eabusham.routervpn;

import android.content.Context;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Builds one real Android graph: full-device TUN -> custom exit -> Router VPN WireGuard entry. */
final class AndroidStandardExitController {
    private static final int MAX_BUNDLE=32*1024*1024,MAX_CONFIG=4*1024*1024,MAX_SESSION_DIRS=32;
    private static final SecureRandom RANDOM=new SecureRandom();
    private final Context context;

    AndroidStandardExitController(Context context){this.context=context.getApplicationContext();}

    NativeSingBoxController.SessionInfo prepare(File entryBundle,AndroidStandardExitStore.Entry exit)throws Exception{
        if(entryBundle==null)throw new IllegalArgumentException("Choose a Router VPN WireGuard entry node.");
        AndroidStandardExitStore.validate(exit);
        JSONObject entry=loadBundle(entryBundle);AndroidNodeStore.validateBundle(entry);WgConfig wg=parseWireGuard(entry);
        JSONObject config=buildConfig(entry,wg,exit);byte[]raw=(config.toString(2)+"\n").getBytes(StandardCharsets.UTF_8);if(raw.length>MAX_CONFIG)throw new IllegalStateException("Android custom-exit config exceeds safety limit.");
        File root=new File(context.getFilesDir(),"layered-sessions");if(!root.isDirectory()&&!root.mkdirs())throw new IllegalStateException("Cannot create layered session directory.");File[]dirs=root.listFiles(File::isDirectory);if(dirs!=null&&dirs.length>=MAX_SESSION_DIRS)throw new IllegalStateException("Too many private layered sessions exist; disconnect before retrying.");
        String id=randomHex(16);File session=new File(root,id);if(!session.mkdir())throw new IllegalStateException("Cannot create custom-exit session.");
        try{if(AndroidKillSwitchPolicy.strictRequested(entry))writeFile(new File(session,AndroidKillSwitchPolicy.SESSION_MARKER),new byte[]{'1','\n'});writeFile(new File(session,"sing-box.json"),raw);return new NativeSingBoxController.SessionInfo(id,"standard-"+exit.protocol);}catch(Throwable t){deleteTree(session);throw t;}
    }

    private static JSONObject buildConfig(JSONObject entry,WgConfig wg,AndroidStandardExitStore.Entry exit)throws Exception{
        JSONArray endpoints=new JSONArray().put(wg.toEndpointJson());JSONArray outbounds=new JSONArray();
        JSONObject custom=customExitJson(exit);if("wireguard".equals(exit.protocol))endpoints.put(custom);else outbounds.put(custom);
        JSONObject dns=selectedDns(entry);int mtu=effectiveMtu(entry);JSONObject tun=new JSONObject().put("type","tun").put("tag","tun-in").put("address",new JSONArray().put("172.29.92.1/30").put("fd29:92::1/126")).put("mtu",mtu).put("auto_route",true).put("strict_route",true).put("stack","system");
        JSONObject proof=new JSONObject().put("type","mixed").put("tag","standard-exit-proof").put("listen","127.0.0.1").put("listen_port",1099);
        JSONObject route=new JSONObject().put("rules",new JSONArray().put(new JSONObject().put("protocol","dns").put("action","hijack-dns"))).put("final","custom-exit").put("auto_detect_interface",true);
        return new JSONObject().put("log",new JSONObject().put("level","warn").put("timestamp",true)).put("dns",new JSONObject().put("servers",new JSONArray().put(dns)).put("final","selected-dns")).put("inbounds",new JSONArray().put(tun).put(proof)).put("endpoints",endpoints).put("outbounds",outbounds).put("route",route);
    }

    private static JSONObject customExitJson(AndroidStandardExitStore.Entry e)throws Exception{
        if("wireguard".equals(e.protocol)){JSONObject peer=new JSONObject().put("address",e.server).put("port",e.serverPort).put("public_key",e.wgPeerPublicKey).put("allowed_ips",new JSONArray(e.wgAllowedIps));if(!e.wgPreSharedKey.isEmpty())peer.put("pre_shared_key",e.wgPreSharedKey);JSONObject endpoint=new JSONObject().put("type","wireguard").put("tag","custom-exit").put("address",new JSONArray(e.wgAddresses)).put("private_key",e.wgPrivateKey).put("peers",new JSONArray().put(peer)).put("detour","entry-wg");if(e.wgMtu!=0)endpoint.put("mtu",e.wgMtu);return endpoint;}
        JSONObject out=new JSONObject().put("tag","custom-exit").put("server",e.server).put("server_port",e.serverPort).put("detour","entry-wg");
        if("socks5".equals(e.protocol)){out.put("type","socks").put("version","5");if(!e.username.isEmpty())out.put("username",e.username).put("password",e.password);}
        else if("http".equals(e.protocol)||"https".equals(e.protocol)){out.put("type","http");if(!e.username.isEmpty())out.put("username",e.username).put("password",e.password);if("https".equals(e.protocol))out.put("tls",new JSONObject().put("enabled",true).put("server_name",e.tlsServerName));}
        else if("shadowsocks".equals(e.protocol))out.put("type","shadowsocks").put("method",e.method).put("password",e.secret);
        else if("hysteria2".equals(e.protocol))out.put("type","hysteria2").put("password",e.secret).put("tls",new JSONObject().put("enabled",true).put("server_name",e.tlsServerName));
        else throw new IllegalArgumentException("Unsupported Android custom exit protocol: "+e.protocol);return out;
    }

    private static JSONObject selectedDns(JSONObject bundle)throws Exception{
        JSONObject p=selectedProfile(bundle);String mode=p.optString("dns_mode","fastest").toLowerCase(Locale.ROOT),protocol=p.optString("dns_protocol","udp").toLowerCase(Locale.ROOT),host=p.optString("dns_host",p.optString("fastest_dns_host","1.1.1.1")).trim(),sni=p.optString("dns_server_name","").trim(),path=p.optString("dns_path","/dns-query").trim(),detour="custom-exit";int port=p.optInt("dns_port",0);
        if("home".equals(mode)){host=p.optString("adguard_ipv4",p.optString("adguard_ipv6","10.77.0.1")).trim();protocol="udp";port=53;sni="";detour="entry-wg";}else if("fastest".equals(mode)){host=p.optString("fastest_dns_host","1.1.1.1").trim();protocol="udp";port=53;sni="";}else if("doh".equals(mode)){protocol="https";if(port<=0)port=443;}else if("dot".equals(mode)){protocol="tls";if(port<=0)port=853;}else if("doh3".equals(mode)){protocol="h3";if(port<=0)port=443;}else if("rescue".equals(mode)){protocol="https";if(host.isEmpty())host="1.1.1.1";if(sni.isEmpty())sni="cloudflare-dns.com";if(port<=0)port=443;}else{if("doh".equals(protocol))protocol="https";else if("dot".equals(protocol))protocol="tls";else if("doh3".equals(protocol))protocol="h3";if(port<=0)port=("https".equals(protocol)||"h3".equals(protocol))?443:"tls".equals(protocol)?853:53;}
        if(host.isEmpty())throw new IllegalStateException("Selected DNS host is empty.");boolean literal=host.matches("[0-9.]+")||(host.contains(":")&&host.matches("[0-9A-Fa-f:.%]+$"));if(!literal)throw new IllegalStateException("Android custom exit requires literal DNS server IP to avoid pre-tunnel DNS.");
        if(("tls".equals(protocol)||"https".equals(protocol)||"h3".equals(protocol))&&sni.isEmpty())throw new IllegalStateException("Encrypted selected DNS requires TLS server name.");JSONObject server=new JSONObject().put("type",protocol).put("tag","selected-dns").put("server",host).put("server_port",port).put("detour",detour);if("tls".equals(protocol)||"https".equals(protocol)||"h3".equals(protocol))server.put("tls",new JSONObject().put("enabled",true).put("server_name",sni));if("https".equals(protocol)||"h3".equals(protocol))server.put("path",path.isEmpty()?"/dns-query":path);return server;
    }

    private static int effectiveMtu(JSONObject bundle){try{JSONObject p=selectedProfile(bundle);int v=p.optInt("effective_mtu",1280);return v>=1280&&v<=9000?v:1280;}catch(Exception e){return 1280;}}
    private static JSONObject selectedProfile(JSONObject bundle){JSONArray ps=bundle.optJSONArray("routerProfiles");String wanted=bundle.optString("selectedRouterID","").trim();if(ps==null)throw new IllegalStateException("Entry bundle has no router profile.");for(int i=0;i<ps.length();i++){JSONObject p=ps.optJSONObject(i);if(p!=null&&wanted.equals(p.optString("id")))return p;}JSONObject p=ps.length()>0?ps.optJSONObject(0):null;if(p==null)throw new IllegalStateException("Entry bundle has no selected router profile.");return p;}

    private static WgConfig parseWireGuard(JSONObject bundle)throws Exception{JSONObject profiles=bundle.optJSONObject("profiles"),wgProfile=profiles==null?null:profiles.optJSONObject("wg");String encoded=wgProfile==null?"":wgProfile.optString("wg.conf","").trim();if(encoded.isEmpty())throw new IllegalStateException("Entry node has no standard WireGuard profile.");byte[]raw=Base64.decode(encoded,Base64.DEFAULT);if(raw.length==0||raw.length>1024*1024)throw new IllegalStateException("Entry WireGuard profile size is invalid.");String config=new String(raw,StandardCharsets.UTF_8);Map<String,String>iface=new LinkedHashMap<>(),peer=new LinkedHashMap<>(),current=null;int peers=0;for(String line0:config.split("\\r?\\n")){String line=line0.trim();int comment=line.indexOf('#');if(comment>=0)line=line.substring(0,comment).trim();if(line.isEmpty())continue;if("[Interface]".equalsIgnoreCase(line)){current=iface;continue;}if("[Peer]".equalsIgnoreCase(line)){peers++;if(peers>1)throw new IllegalStateException("Android custom exit requires exactly one entry WireGuard peer.");current=peer;continue;}int eq=line.indexOf('=');if(current!=null&&eq>0)current.put(line.substring(0,eq).trim().toLowerCase(Locale.ROOT),line.substring(eq+1).trim());}if(peers!=1)throw new IllegalStateException("Android custom exit requires exactly one entry WireGuard peer.");WgConfig r=new WgConfig();r.privateKey=req(iface,"privatekey","Entry WireGuard private key missing.");r.addresses=csv(req(iface,"address","Entry WireGuard address missing."));r.publicKey=req(peer,"publickey","Entry WireGuard peer key missing.");r.preSharedKey=peer.getOrDefault("presharedkey","").trim();r.allowedIps=csv(req(peer,"allowedips","Entry WireGuard AllowedIPs missing."));HostPort hp=parseEndpoint(req(peer,"endpoint","Entry WireGuard endpoint missing."));r.host=hp.host;r.port=hp.port;String mtu=iface.getOrDefault("mtu","").trim();if(!mtu.isEmpty())r.mtu=Integer.parseInt(mtu);if(r.mtu!=0&&(r.mtu<1280||r.mtu>9000))throw new IllegalStateException("Entry WireGuard MTU is outside safe range.");return r;}
    private static final class WgConfig{String privateKey,publicKey,preSharedKey,host;List<String>addresses,allowedIps;int port,mtu;JSONObject toEndpointJson()throws Exception{JSONObject e=new JSONObject().put("type","wireguard").put("tag","entry-wg").put("address",new JSONArray(addresses)).put("private_key",privateKey);if(mtu!=0)e.put("mtu",mtu);JSONObject p=new JSONObject().put("address",host).put("port",port).put("public_key",publicKey).put("allowed_ips",new JSONArray(allowedIps));if(!preSharedKey.isEmpty())p.put("pre_shared_key",preSharedKey);return e.put("peers",new JSONArray().put(p));}}
    private static final class HostPort{final String host;final int port;HostPort(String h,int p){host=h;port=p;}}
    private static HostPort parseEndpoint(String v){String h,p;if(v.startsWith("[")){int c=v.indexOf(']');if(c<1||c+2>v.length()||v.charAt(c+1)!=':')throw new IllegalStateException("Entry WireGuard endpoint invalid.");h=v.substring(1,c).trim();p=v.substring(c+2).trim();}else{int c=v.lastIndexOf(':');if(c<1||c==v.length()-1)throw new IllegalStateException("Entry WireGuard endpoint invalid.");h=v.substring(0,c).trim();p=v.substring(c+1).trim();}int port=Integer.parseInt(p);if(h.isEmpty()||port<1||port>65535)throw new IllegalStateException("Entry WireGuard endpoint invalid.");return new HostPort(h,port);}
    private static String req(Map<String,String>m,String k,String msg){String v=m.getOrDefault(k,"").trim();if(v.isEmpty())throw new IllegalStateException(msg);return v;}
    private static List<String> csv(String v){List<String>r=new ArrayList<>();for(String p:v.split(",")){p=p.trim();if(!p.isEmpty())r.add(p);}if(r.isEmpty())throw new IllegalStateException("WireGuard list is empty.");return r;}
    private static JSONObject loadBundle(File f)throws Exception{if(f==null||!f.isFile()||f.length()<=0||f.length()>MAX_BUNDLE)throw new IllegalStateException("Entry node bundle missing/invalid.");try(FileInputStream in=new FileInputStream(f);ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]b=new byte[8192];int total=0,n;while((n=in.read(b))!=-1){total+=n;if(total>MAX_BUNDLE)throw new IllegalStateException("Entry bundle exceeds safety limit.");out.write(b,0,n);}return new JSONObject(new String(out.toByteArray(),StandardCharsets.UTF_8));}}
    private static void writeFile(File f,byte[]d)throws Exception{try(FileOutputStream out=new FileOutputStream(f,false)){out.write(d);out.flush();out.getFD().sync();}}
    private static String randomHex(int bytes){byte[]v=new byte[bytes];RANDOM.nextBytes(v);StringBuilder s=new StringBuilder();for(byte b:v)s.append(String.format(Locale.ROOT,"%02x",b&255));return s.toString();}
    private static void deleteTree(File f){if(f==null||!f.exists())return;File[]c=f.listFiles();if(c!=null)for(File x:c)deleteTree(x);f.delete();}
}
