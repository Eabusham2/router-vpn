package com.eabusham.routervpn;

import android.content.Context;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** App-private typed custom-exit store. Secret fields never leave the private Entry object. */
final class AndroidStandardExitStore {
    static final int SCHEMA_VERSION = 1;
    static final int MAX_EXITS = 64;
    private static final int MAX_STORE = 512 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Set<String> SS_METHODS = new HashSet<>(Arrays.asList(
            "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
            "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"));

    static final class Capability {
        final String protocol; final boolean supported; final String reason;
        Capability(String protocol, boolean supported, String reason) { this.protocol=protocol; this.supported=supported; this.reason=reason; }
    }

    static final class Entry {
        String id="", name="", protocol="", server="", expectedPublicIp="";
        int serverPort, wgMtu;
        String username="", password="", method="", secret="", tlsServerName="";
        String wgPrivateKey="", wgPeerPublicKey="", wgPreSharedKey="";
        final List<String> wgAddresses = new ArrayList<>(), wgAllowedIps = new ArrayList<>();

        JSONObject summary() throws Exception {
            return new JSONObject().put("id",id).put("name",name).put("protocol",protocol)
                    .put("server",server).put("server_port",serverPort).put("expected_public_ip",expectedPublicIp)
                    .put("has_credentials",!username.isEmpty()||!password.isEmpty())
                    .put("has_secret",!secret.isEmpty()||!wgPreSharedKey.isEmpty())
                    .put("has_wireguard_key",!wgPrivateKey.isEmpty()||!wgPeerPublicKey.isEmpty());
        }
    }

    private final Context context;
    private final File storeFile;
    AndroidStandardExitStore(Context context) { this.context=context.getApplicationContext(); storeFile = new File(this.context.getFilesDir(), "standard-exits.json"); }

    static List<Capability> capabilities() {
        List<Capability> r=new ArrayList<>();
        r.add(new Capability("wireguard",true,"")); r.add(new Capability("socks5",true,""));
        r.add(new Capability("http",true,"")); r.add(new Capability("https",true,""));
        r.add(new Capability("shadowsocks",true,"")); r.add(new Capability("hysteria2",true,""));
        r.add(new Capability("openvpn",false,"Pinned sing-box 1.13.x has no OpenVPN endpoint; keep unavailable until a stable pinned dataplane is validated."));
        return r;
    }

    synchronized List<Entry> list() throws Exception { return readStore(); }
    synchronized Entry get(String id) throws Exception {
        for (Entry e:list()) if(e.id.equals(id)) return e;
        throw new IllegalArgumentException("Custom standard exit was not found.");
    }
    synchronized Entry save(Entry entry) throws Exception {
        requireMutable("saving or replacing a custom exit");
        validate(entry);
        List<Entry> all=readStore(); boolean found=false;
        for(int i=0;i<all.size();i++) if(all.get(i).id.equals(entry.id)){all.set(i,entry);found=true;break;}
        if(!found){if(all.size()>=MAX_EXITS)throw new IllegalStateException("Too many custom standard exits are stored.");all.add(entry);}
        writeStore(all); return entry;
    }
    synchronized void remove(String id) throws Exception {
        requireMutable("deleting a custom exit");
        if(!safeId(id)) throw new IllegalArgumentException("Invalid custom exit id.");
        List<Entry> all=readStore(), next=new ArrayList<>(); boolean found=false;
        for(Entry e:all){if(e.id.equals(id))found=true;else next.add(e);} if(!found)throw new IllegalArgumentException("Custom standard exit was not found.");
        writeStore(next);
    }

    private void requireMutable(String action){
        AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
        AndroidRuntimeRegistry engines=AndroidRuntimeRegistry.get(context);
        boolean activeOrTransitioning=home.connected||"connecting".equals(home.phase)
                ||engines.orchestrator.isRunning()||engines.multihop.isActiveOrTransitioning()
                ||"UP".equals(engines.singBox.getState())||"STARTING".equals(engines.singBox.getState())||"STOPPING".equals(engines.singBox.getState())
                ||"UP".equals(engines.xray.getState())||"STARTING".equals(engines.xray.getState())||"STOPPING".equals(engines.xray.getState());
        if(activeOrTransitioning)throw new IllegalStateException("Disconnect Router VPN before "+action+"; live external-exit identity and proof must remain immutable for the session.");
    }

    private List<Entry> readStore() throws Exception {
        if(!storeFile.exists()) return new ArrayList<>();
        if(!storeFile.isFile()||storeFile.length()<=0||storeFile.length()>MAX_STORE) throw new IllegalStateException("Custom exit store is invalid or too large.");
        byte[] raw=readLimited(storeFile,MAX_STORE); JSONObject root=new JSONObject(new String(raw,StandardCharsets.UTF_8));
        if(root.optInt("schema_version",0)!=SCHEMA_VERSION) throw new IllegalStateException("Unsupported custom exit store schema.");
        JSONArray rows=root.optJSONArray("exits"); List<Entry> result=new ArrayList<>(); Set<String> seen=new HashSet<>();
        if(rows!=null)for(int i=0;i<rows.length();i++){Entry e=fromJson(rows.getJSONObject(i));validate(e);if(!seen.add(e.id))throw new IllegalStateException("Duplicate custom exit id.");result.add(e);}
        if(result.size()>MAX_EXITS)throw new IllegalStateException("Too many custom exits are stored."); return result;
    }

    private void writeStore(List<Entry> rows) throws Exception {
        JSONArray array=new JSONArray(); for(Entry e:rows){validate(e);array.put(toJson(e));}
        byte[] raw=(new JSONObject().put("schema_version",SCHEMA_VERSION).put("exits",array).toString(2)+"\n").getBytes(StandardCharsets.UTF_8);
        if(raw.length>MAX_STORE)throw new IllegalStateException("Custom exit store exceeds safety limit.");
        AndroidPrivateFileStore.write(storeFile, raw, MAX_STORE);
    }

    static void validate(Entry e) throws Exception {
        if(e==null)throw new IllegalArgumentException("Custom exit is required.");
        e.id=e.id==null?"":e.id.trim(); if(e.id.isEmpty())e.id="exit-"+randomHex(6); if(!safeId(e.id))throw new IllegalArgumentException("Invalid custom exit id.");
        e.name=e.name==null?"":e.name.trim();if(e.name.isEmpty())e.name="Custom Exit";if(e.name.length()>120)throw new IllegalArgumentException("Custom exit name is too long.");
        e.protocol=normalizeProtocol(e.protocol); if("openvpn".equals(e.protocol))throw new IllegalArgumentException("OpenVPN custom exit is unavailable on pinned sing-box 1.13.x; no fake OpenVPN mode is exposed.");
        if(!Arrays.asList("wireguard","socks5","http","https","shadowsocks","hysteria2").contains(e.protocol))throw new IllegalArgumentException("Unsupported custom exit protocol: "+e.protocol);
        e.server=literalIp(e.server,"Custom exit server").getHostAddress(); if(e.serverPort<1||e.serverPort>65535)throw new IllegalArgumentException("Custom exit port must be 1..65535.");
        InetAddress expected=literalIp(e.expectedPublicIp,"Expected public exit IP"); if(isPrivate(expected))throw new IllegalArgumentException("Expected public exit IP must be public.");e.expectedPublicIp=expected.getHostAddress();
        e.username=trimBound(e.username,"username");e.password=trimBound(e.password,"password");e.secret=trimBound(e.secret,"secret");e.method=trimBound(e.method,"method").toLowerCase(Locale.ROOT);e.tlsServerName=trimBound(e.tlsServerName,"TLS server name");
        e.wgPrivateKey=trimBound(e.wgPrivateKey,"WireGuard private key");e.wgPeerPublicKey=trimBound(e.wgPeerPublicKey,"WireGuard public key");e.wgPreSharedKey=trimBound(e.wgPreSharedKey,"WireGuard preshared key");
        if(("socks5".equals(e.protocol)||"http".equals(e.protocol)||"https".equals(e.protocol))&&e.username.isEmpty()!=e.password.isEmpty())throw new IllegalArgumentException("Proxy username/password must both be set or both be empty.");
        if("https".equals(e.protocol)&&(e.tlsServerName.isEmpty()||e.tlsServerName.matches(".*[ /\\\\?#@].*")))throw new IllegalArgumentException("HTTPS proxy requires a valid TLS server name for certificate verification.");
        if("shadowsocks".equals(e.protocol)){if(!SS_METHODS.contains(e.method))throw new IllegalArgumentException("Unsupported or insecure Shadowsocks method.");if(e.secret.isEmpty())throw new IllegalArgumentException("Shadowsocks password/PSK is required.");}
        if("hysteria2".equals(e.protocol)){if(e.secret.isEmpty())throw new IllegalArgumentException("Hysteria2 password is required.");if(e.tlsServerName.isEmpty()||e.tlsServerName.matches(".*[ /\\\\?#@].*"))throw new IllegalArgumentException("Hysteria2 requires a valid TLS server name.");}
        if("wireguard".equals(e.protocol)){validateKey(e.wgPrivateKey,"WireGuard private key",false);validateKey(e.wgPeerPublicKey,"WireGuard peer public key",false);validateKey(e.wgPreSharedKey,"WireGuard preshared key",true);validateCidrs(e.wgAddresses,"WireGuard interface addresses");validateCidrs(e.wgAllowedIps,"WireGuard AllowedIPs");if(e.wgMtu!=0&&(e.wgMtu<1280||e.wgMtu>9000))throw new IllegalArgumentException("WireGuard MTU must be 1280..9000.");}
    }

    private static String normalizeProtocol(String p){p=p==null?"":p.trim().toLowerCase(Locale.ROOT);if("wg".equals(p))return"wireguard";if("socks".equals(p))return"socks5";if("http-connect".equals(p))return"http";if("https-connect".equals(p))return"https";if("ss".equals(p))return"shadowsocks";if("hy2".equals(p))return"hysteria2";if("ovpn".equals(p))return"openvpn";return p;}
    private static boolean safeId(String v){return v!=null&&v.matches("[A-Za-z0-9._-]{1,96}")&&!v.equals(".")&&!v.equals("..")&&!v.contains("..");}
    private static String trimBound(String v,String label){v=v==null?"":v.trim();if(v.length()>4096)throw new IllegalArgumentException(label+" is too long.");return v;}
    private static InetAddress literalIp(String value,String label)throws Exception{value=value==null?"":value.trim();boolean v4=value.matches("[0-9.]+"),v6=value.contains(":")&&value.matches("[0-9A-Fa-f:.%]+$");if(!v4&&!v6)throw new IllegalArgumentException(label+" must be a literal IP to avoid pre-tunnel DNS.");return InetAddress.getByName(value);}
    private static boolean isPrivate(InetAddress a){if(a.isAnyLocalAddress()||a.isLoopbackAddress()||a.isLinkLocalAddress()||a.isSiteLocalAddress())return true;byte[]b=a.getAddress();return b.length==16&&(b[0]&0xfe)==0xfc;}
    private static void validateKey(String value,String label,boolean optional){if(value.isEmpty()&&optional)return;byte[]raw;try{raw=Base64.decode(value,Base64.DEFAULT);}catch(Exception e){throw new IllegalArgumentException(label+" is not base64.");}if(raw.length!=32)throw new IllegalArgumentException(label+" must decode to 32 bytes.");}
    private static void validateCidrs(List<String> values,String label)throws Exception{if(values==null||values.isEmpty())throw new IllegalArgumentException(label+" are required.");if(values.size()>32)throw new IllegalArgumentException(label+" has too many entries.");for(String v:values){String[]p=v.trim().split("/",-1);if(p.length!=2)throw new IllegalArgumentException("Invalid "+label+": "+v);InetAddress ip=literalIp(p[0],label);int prefix=Integer.parseInt(p[1]);int max=ip.getAddress().length==4?32:128;if(prefix<0||prefix>max)throw new IllegalArgumentException("Invalid "+label+" prefix: "+v);}}
    private static String randomHex(int n){byte[]b=new byte[n];RANDOM.nextBytes(b);StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format(Locale.ROOT,"%02x",x&255));return s.toString();}
    private static byte[] readLimited(File f,int max)throws Exception{return AndroidPrivateFileStore.read(f,max);}
    private static JSONObject toJson(Entry e)throws Exception{JSONObject o=new JSONObject().put("id",e.id).put("name",e.name).put("protocol",e.protocol).put("server",e.server).put("server_port",e.serverPort).put("expected_public_ip",e.expectedPublicIp).put("username",e.username).put("password",e.password).put("method",e.method).put("secret",e.secret).put("tls_server_name",e.tlsServerName).put("wg_addresses",new JSONArray(e.wgAddresses)).put("wg_private_key",e.wgPrivateKey).put("wg_peer_public_key",e.wgPeerPublicKey).put("wg_pre_shared_key",e.wgPreSharedKey).put("wg_allowed_ips",new JSONArray(e.wgAllowedIps)).put("wg_mtu",e.wgMtu);return o;}
    private static Entry fromJson(JSONObject o)throws Exception{Entry e=new Entry();e.id=o.optString("id","");e.name=o.optString("name","");e.protocol=o.optString("protocol","");e.server=o.optString("server","");e.serverPort=o.optInt("server_port",0);e.expectedPublicIp=o.optString("expected_public_ip","");e.username=o.optString("username","");e.password=o.optString("password","");e.method=o.optString("method","");e.secret=o.optString("secret","");e.tlsServerName=o.optString("tls_server_name","");e.wgPrivateKey=o.optString("wg_private_key","");e.wgPeerPublicKey=o.optString("wg_peer_public_key","");e.wgPreSharedKey=o.optString("wg_pre_shared_key","");e.wgMtu=o.optInt("wg_mtu",0);JSONArray a=o.optJSONArray("wg_addresses"),b=o.optJSONArray("wg_allowed_ips");if(a!=null)for(int i=0;i<a.length();i++)e.wgAddresses.add(a.getString(i));if(b!=null)for(int i=0;i<b.length();i++)e.wgAllowedIps.add(b.getString(i));return e;}
}
