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
        Integer wgKeepalive;
        String username="", password="", method="", secret="", tlsServerName="";
        String wgPrivateKey="", wgPeerPublicKey="", wgPreSharedKey="";
        String openVPNConfig="";
        String torTransport="";
        String startupMode="smart-auto";
        boolean autoConnect;
        JSONObject torPolicy = new JSONObject();
        JSONObject policy = new JSONObject();
        JSONObject responseProbe = new JSONObject();
        JSONObject startLayer;
        JSONObject awgParameters = new JSONObject();
        final List<String> torBridges = new ArrayList<>();
        final List<String> wgAddresses = new ArrayList<>(), wgAllowedIps = new ArrayList<>(), wgDns = new ArrayList<>();

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
        r.add(new Capability("wireguard",true,"")); r.add(new Capability("amneziawg",true,"Native imported AmneziaWG retains every supplied obfuscation parameter.")); r.add(new Capability("socks5",true,""));
        r.add(new Capability("http",true,"")); r.add(new Capability("https",true,""));
        r.add(new Capability("shadowsocks",true,"")); r.add(new Capability("hysteria2",true,""));
        r.add(new Capability("openvpn",true,"Native pinned OpenVPN with saved DNS/network policy, complete Router VPN entries and current entry/DNS/public-exit proof."));
        r.add(new Capability("tor",true,"Native Tor circuit with dynamic Tor-exit proof."));
        r.add(new Capability("tor-bridge",true,"Native obfs4 / meek / Snowflake / WebTunnel / Custom bridge circuits with captured protected networking."));
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
        if(AndroidVpnMutationGuard.isBusy(context))throw new IllegalStateException("Disconnect Router VPN before "+action+"; live external-exit identity and proof must remain immutable for the session.");
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
        validateStartup(e);
        e.id=e.id==null?"":e.id.trim(); if(e.id.isEmpty())e.id="exit-"+randomHex(6); if(!safeId(e.id))throw new IllegalArgumentException("Invalid custom exit id.");
        e.name=e.name==null?"":e.name.trim();if(e.name.isEmpty())e.name="Custom Exit";if(e.name.length()>120)throw new IllegalArgumentException("Custom exit name is too long.");
        e.protocol=normalizeProtocol(e.protocol);
        if(AndroidTorProfile.isTor(e.protocol)){if(e.responseProbe!=null&&e.responseProbe.length()!=0)throw new IllegalArgumentException("Tor cannot borrow an external response endpoint.");validateStartLayer(e);AndroidTorProfile.validate(e);return;}
        if("openvpn".equals(e.protocol)){
            JSONObject compiled=AndroidOpenVPN.endpoint(e, "");
            // This primary address labels the saved node. Its native endpoint
            // retains the complete remote list and must not gain a conflicting
            // singular server merely to populate display fields.
            JSONObject primary=compiled.has("servers")?compiled.getJSONArray("servers").getJSONObject(0):compiled;
            e.server=primary.getString("server");e.serverPort=primary.getInt("server_port");
        }
        if(!Arrays.asList("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn").contains(e.protocol))throw new IllegalArgumentException("Unsupported custom exit protocol: "+e.protocol);
        e.server=AndroidNumericAddress.canonical(e.server); validateResponseProbe(e); validateStartLayer(e); if(e.serverPort<1||e.serverPort>65535)throw new IllegalArgumentException("Custom exit port must be 1..65535.");
        InetAddress expected=AndroidNumericAddress.parse(e.expectedPublicIp); if(isPrivate(expected))throw new IllegalArgumentException("Expected public exit IP must be public.");e.expectedPublicIp=AndroidNumericAddress.canonical(e.expectedPublicIp);
        if(!"openvpn".equals(e.protocol)){e.username=credential(e.username,"username");e.password=credential(e.password,"password");}e.secret=credential(e.secret,"secret");e.method=trimBound(e.method,"method").toLowerCase(Locale.ROOT);e.tlsServerName=trimBound(e.tlsServerName,"TLS server name");
        e.wgPrivateKey=trimBound(e.wgPrivateKey,"WireGuard private key");e.wgPeerPublicKey=trimBound(e.wgPeerPublicKey,"WireGuard public key");e.wgPreSharedKey=trimBound(e.wgPreSharedKey,"WireGuard preshared key");
        if(("socks5".equals(e.protocol)||"http".equals(e.protocol)||"https".equals(e.protocol))&&e.username.isEmpty()!=e.password.isEmpty())throw new IllegalArgumentException("Proxy username/password must both be set or both be empty.");
        if("https".equals(e.protocol)&&(e.tlsServerName.isEmpty()||e.tlsServerName.matches(".*[ /\\\\?#@].*")))throw new IllegalArgumentException("HTTPS proxy requires a valid TLS server name for certificate verification.");
        if("shadowsocks".equals(e.protocol)){if(!SS_METHODS.contains(e.method))throw new IllegalArgumentException("Unsupported or insecure Shadowsocks method.");if(e.secret.isEmpty())throw new IllegalArgumentException("Shadowsocks password/PSK is required.");}
        if("hysteria2".equals(e.protocol)){if(e.secret.isEmpty())throw new IllegalArgumentException("Hysteria2 password is required.");if(e.tlsServerName.isEmpty()||e.tlsServerName.matches(".*[ /\\\\?#@].*"))throw new IllegalArgumentException("Hysteria2 requires a valid TLS server name.");}
        if("wireguard".equals(e.protocol)||"amneziawg".equals(e.protocol)){
            validateKey(e.wgPrivateKey,"WireGuard private key",false);validateKey(e.wgPeerPublicKey,"WireGuard peer public key",false);validateKey(e.wgPreSharedKey,"WireGuard preshared key",true);validateCidrs(e.wgAddresses,"WireGuard interface addresses");validateCidrs(e.wgAllowedIps,"WireGuard AllowedIPs");
            if(e.wgMtu!=0&&(e.wgMtu<1280||e.wgMtu>9000))throw new IllegalArgumentException("WireGuard MTU must be 1280..9000.");
            if(e.wgKeepalive!=null&&(e.wgKeepalive<0||e.wgKeepalive>65535))throw new IllegalArgumentException("Keepalive must be an integer from 0 to 65535.");
            if(e.wgDns.size()>4)throw new IllegalArgumentException("Too many imported DNS addresses.");for(String dns:e.wgDns)AndroidNumericAddress.parse(dns);
            if("amneziawg".equals(e.protocol))AndroidExternalAmnezia.endpoint(e);
            else if(e.awgParameters!=null&&e.awgParameters.length()!=0)throw new IllegalArgumentException("AmneziaWG parameters cannot be discarded by selecting WireGuard.");
        }
    }

    /** Same-server HTTPS response identity; the native compiler repeats this validation. */
    static void validateResponseProbe(Entry e)throws Exception{
        if(e.responseProbe==null)throw new IllegalArgumentException("External response settings must be an object.");
        if(e.responseProbe.length()==0)return;
        if(!serverExecutionProtocol(e.protocol)||!e.responseProbe.has("url")||e.responseProbe.length()>2)throw new IllegalArgumentException("A response endpoint belongs to its saved authenticated external transport.");
        JSONArray keys=e.responseProbe.names();for(int i=0;i<keys.length();i++)if(!Arrays.asList("url","server_name").contains(keys.getString(i)))throw new IllegalArgumentException("Unowned response endpoint field.");
        if(!(e.responseProbe.get("url") instanceof String)||e.responseProbe.has("server_name")&&!(e.responseProbe.get("server_name") instanceof String))throw new IllegalArgumentException("Response endpoint settings must be text.");
        String text=e.responseProbe.getString("url"),name=e.responseProbe.optString("server_name","");java.net.URI url=new java.net.URI(text);
        String host=url.getHost();if(host!=null&&host.startsWith("[")&&host.endsWith("]"))host=host.substring(1,host.length()-1);
        if(text.length()>2048||!text.equals(text.trim())||!"https".equals(url.getScheme())||host==null||!e.server.equals(host)
                ||url.getUserInfo()!=null||url.getRawQuery()!=null||url.getRawFragment()!=null||url.isOpaque()||url.getRawAuthority().endsWith(":")
                ||url.getPort()==0||url.getPort()>65535||url.getRawPath().contains("%")||isPrivate(AndroidNumericAddress.parse(host)))throw new IllegalArgumentException("Use verified HTTPS on this external server's literal public address.");
        if(!name.isEmpty()&&(name.length()>253||name.endsWith(".")||!name.matches("(?i)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")||name.contains("..")))throw new IllegalArgumentException("Response TLS server name is invalid.");
    }

    static boolean serverExecutionProtocol(String protocol){
        return Arrays.asList("shadowsocks","hysteria2","socks5","http","https").contains(protocol);
    }

    /** The choice never supplies credentials: its exact provisioned layer stays in this private node. */
    static void validateStartLayer(Entry exit)throws Exception{
        JSONObject policy=exit.policy==null?new JSONObject():exit.policy;
        if(policy.has("start_layer")&&!(policy.get("start_layer") instanceof String))throw new IllegalArgumentException("External Start Layer choice must be text.");
        String mode=policy.optString("start_layer","off");
        if(mode.isEmpty()||"off".equals(mode)){
            if(exit.startLayer!=null)throw new IllegalArgumentException("A provisioned external Start Layer needs its exact selected mode.");
            return;
        }
        if(!serverExecutionProtocol(exit.protocol)||!Arrays.asList("aes-256-gcm","aes-256-gcm+xor-whitening").contains(mode)||exit.startLayer==null)throw new IllegalArgumentException("External Start Layer requires a supported transport and its private provisioned settings.");
        JSONObject layer=exit.startLayer;
        if(layer.length()!=3||!mode.equals(layer.getString("mode"))||!(layer.get("api") instanceof String))throw new IllegalArgumentException("External Start Layer lost its selected mode or private service address.");
        JSONObject transport=layer.getJSONObject("transport");
        Set<String> allowed=new HashSet<>(Arrays.asList("type","tag","server","server_port","method","password"));
        JSONArray fields=transport.names();
        if(transport.length()!=allowed.size())throw new IllegalArgumentException("External Start Layer transport must retain its exact provisioned fields.");
        for(int i=0;i<fields.length();i++){String key=fields.getString(i);if(!allowed.contains(key))throw new IllegalArgumentException("Unowned external Start Layer transport field.");if(!"server_port".equals(key)&&!(transport.get(key) instanceof String))throw new IllegalArgumentException("External Start Layer text field has an invalid type.");}
        if(!"shadowsocks".equals(transport.getString("type"))||!"2022-blake3-aes-256-gcm".equals(transport.getString("method"))||!exit.server.equals(transport.getString("server"))||transport.getString("tag").isEmpty())throw new IllegalArgumentException("External Start Layer must be authenticated AES on this exact server.");
        Object port=transport.get("server_port");if(!(port instanceof Number)||((Number)port).doubleValue()!=((Number)port).intValue()||((Number)port).intValue()<1||((Number)port).intValue()>65535)throw new IllegalArgumentException("External Start Layer port must be 1..65535.");
        String key=credential(transport.getString("password"),"Start Layer key");if(key.isEmpty())throw new IllegalArgumentException("External Start Layer key is required.");
        // The shared native compiler additionally verifies the private API,
        // canonical AES key and exact wrapped graph before save or connection.
    }

    static boolean authenticatedExecutionTransport(Entry exit){
        if(exit==null||!serverExecutionProtocol(exit.protocol))return false;
        if(Arrays.asList("socks5","http","https").contains(exit.protocol))return exit.username!=null&&!exit.username.isEmpty()&&exit.password!=null&&!exit.password.isEmpty();
        return exit.secret!=null&&!exit.secret.isEmpty();
    }

    static void validateExecution(Entry exit,boolean hasEntry,String execution)throws Exception{
        if(!Arrays.asList("local","server","auto").contains(execution))throw new IllegalArgumentException("Choose Local, Server, or Compare both.");
        if(!"local".equals(execution)){
            if(!hasEntry||!authenticatedExecutionTransport(exit)||exit.responseProbe==null||exit.responseProbe.length()==0)throw new IllegalArgumentException("Server and Compare both need a Router VPN entry, an authenticated Shadowsocks, Hysteria2 or SOCKS5/HTTP(S) exit, and its verified HTTPS response endpoint.");
            validateResponseProbe(exit);
        }
    }

    private static String normalizeProtocol(String p){p=p==null?"":p.trim().toLowerCase(Locale.ROOT);if("wg".equals(p))return"wireguard";if("awg".equals(p)||"awg2".equals(p)||"amnezia".equals(p))return"amneziawg";if("socks".equals(p))return"socks5";if("http-connect".equals(p))return"http";if("https-connect".equals(p))return"https";if("ss".equals(p))return"shadowsocks";if("hy2".equals(p))return"hysteria2";if("ovpn".equals(p))return"openvpn";if("tor_bridge".equals(p))return"tor-bridge";return p;}
    private static boolean safeId(String v){return v!=null&&v.matches("[A-Za-z0-9._-]{1,96}")&&!v.equals(".")&&!v.equals("..")&&!v.contains("..");}
    private static String credential(String v,String label){v=v==null?"":v;if(v.length()>4096||v.indexOf('\0')>=0)throw new IllegalArgumentException(label+" is invalid or too long.");return v;}
    private static String trimBound(String v,String label){v=v==null?"":v.trim();if(v.length()>4096)throw new IllegalArgumentException(label+" is too long.");return v;}
    private static InetAddress literalIp(String value,String label)throws Exception{value=value==null?"":value.trim();boolean v4=value.matches("[0-9.]+"),v6=value.contains(":")&&value.matches("[0-9A-Fa-f:.%]+$");if(!v4&&!v6)throw new IllegalArgumentException(label+" must be a literal IP to avoid pre-tunnel DNS.");return InetAddress.getByName(value);}
    private static boolean isPrivate(InetAddress a){if(a.isAnyLocalAddress()||a.isLoopbackAddress()||a.isLinkLocalAddress()||a.isSiteLocalAddress())return true;byte[]b=a.getAddress();return b.length==16&&(b[0]&0xfe)==0xfc;}
    private static void validateKey(String value,String label,boolean optional){if(value.isEmpty()&&optional)return;byte[]raw;try{raw=Base64.decode(value,Base64.DEFAULT);}catch(Exception e){throw new IllegalArgumentException(label+" is not base64.");}if(raw.length!=32)throw new IllegalArgumentException(label+" must decode to 32 bytes.");}
    private static void validateCidrs(List<String> values,String label)throws Exception{if(values==null||values.isEmpty())throw new IllegalArgumentException(label+" are required.");if(values.size()>32)throw new IllegalArgumentException(label+" has too many entries.");for(String v:values){String[]p=v.trim().split("/",-1);if(p.length!=2)throw new IllegalArgumentException("Invalid "+label+": "+v);InetAddress ip=literalIp(p[0],label);int prefix=Integer.parseInt(p[1]);int max=ip.getAddress().length==4?32:128;if(prefix<0||prefix>max)throw new IllegalArgumentException("Invalid "+label+" prefix: "+v);}}
    private static String randomHex(int n){byte[]b=new byte[n];RANDOM.nextBytes(b);StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format(Locale.ROOT,"%02x",x&255));return s.toString();}
    private static byte[] readLimited(File f,int max)throws Exception{return AndroidPrivateFileStore.read(f,max);}
    static Entry copy(Entry entry)throws Exception{return fromJson(toJson(entry));}
    static String snapshot(Entry entry)throws Exception{return toJson(entry).toString();}
    static JSONObject startupMetadata(Entry entry)throws Exception{validateStartup(entry);return new JSONObject().put("startup_mode",entry.startupMode).put("auto_connect",entry.autoConnect);}
    static void applyStartupMetadata(Entry entry,JSONObject value)throws Exception{
        if(value==null||value.length()!=2||!(value.get("startup_mode") instanceof String)||!(value.get("auto_connect") instanceof Boolean))throw new IllegalArgumentException("External startup requires an exact mode and On/Off choice.");
        entry.startupMode=value.getString("startup_mode");entry.autoConnect=value.getBoolean("auto_connect");validateStartup(entry);
    }
    private static void validateStartup(Entry entry){
        if(entry.startupMode==null||!Arrays.asList("smart-auto","auto","last","manual").contains(entry.startupMode))throw new IllegalArgumentException("Invalid external startup behavior.");
        if(entry.autoConnect&&"manual".equals(entry.startupMode))throw new IllegalArgumentException("Manual startup must stay disconnected.");
    }
    private static JSONObject toJson(Entry e)throws Exception{validateStartup(e);JSONObject o=new JSONObject().put("startup_mode",e.startupMode).put("auto_connect",e.autoConnect).put("id",e.id).put("name",e.name).put("protocol",e.protocol).put("server",e.server).put("server_port",e.serverPort).put("expected_public_ip",e.expectedPublicIp).put("username",e.username).put("password",e.password).put("method",e.method).put("secret",e.secret).put("tls_server_name",e.tlsServerName).put("wg_addresses",new JSONArray(e.wgAddresses)).put("wg_private_key",e.wgPrivateKey).put("wg_peer_public_key",e.wgPeerPublicKey).put("wg_pre_shared_key",e.wgPreSharedKey).put("wg_allowed_ips",new JSONArray(e.wgAllowedIps)).put("wg_mtu",e.wgMtu).put("wg_dns",new JSONArray(e.wgDns)).put("wg_keepalive",e.wgKeepalive).put("awg_parameters",e.awgParameters==null?new JSONObject():e.awgParameters).put("openvpn_config",e.openVPNConfig).put("response_probe",e.responseProbe).put("policy",e.policy==null?new JSONObject():e.policy);if(e.startLayer!=null)o.put("start_layer",new JSONObject(e.startLayer.toString()));if(AndroidTorProfile.isTor(e.protocol)||e.torPolicy!=null&&e.torPolicy.length()!=0)o.put("tor_policy",e.torPolicy);if("tor-bridge".equals(e.protocol)||e.torTransport!=null&&!e.torTransport.isEmpty()||!e.torBridges.isEmpty())o.put("tor_bridge",new JSONObject().put("transport",e.torTransport).put("bridges",new JSONArray(e.torBridges)));return o;}
    private static Entry fromJson(JSONObject o)throws Exception{Entry e=new Entry();if(o.has("startup_mode")&&!(o.get("startup_mode") instanceof String)||o.has("auto_connect")&&!(o.get("auto_connect") instanceof Boolean))throw new IllegalArgumentException("Invalid stored external startup settings.");e.startupMode=o.optString("startup_mode","smart-auto");e.autoConnect=o.optBoolean("auto_connect",false);validateStartup(e);e.id=o.optString("id","");e.name=o.optString("name","");e.protocol=o.optString("protocol","");e.server=o.optString("server","");e.serverPort=o.optInt("server_port",0);e.expectedPublicIp=o.optString("expected_public_ip","");e.username=o.optString("username","");e.password=o.optString("password","");e.method=o.optString("method","");e.secret=o.optString("secret","");e.tlsServerName=o.optString("tls_server_name","");e.wgPrivateKey=o.optString("wg_private_key","");e.wgPeerPublicKey=o.optString("wg_peer_public_key","");e.wgPreSharedKey=o.optString("wg_pre_shared_key","");e.wgMtu=o.optInt("wg_mtu",0);if(o.has("wg_keepalive")){Object raw=o.get("wg_keepalive");if(!(raw instanceof Number)||((Number)raw).doubleValue()!=((Number)raw).intValue()||((Number)raw).intValue()<0||((Number)raw).intValue()>65535)throw new IllegalArgumentException("Invalid stored WireGuard keepalive.");e.wgKeepalive=((Number)raw).intValue();}if(o.has("awg_parameters"))e.awgParameters=new JSONObject(o.getJSONObject("awg_parameters").toString());JSONArray dns=o.optJSONArray("wg_dns");if(o.has("wg_dns")&&dns==null)throw new IllegalArgumentException("Invalid stored WireGuard DNS.");if(dns!=null)for(int i=0;i<dns.length();i++){if(!(dns.get(i) instanceof String))throw new IllegalArgumentException("Invalid stored WireGuard DNS.");e.wgDns.add(dns.getString(i));}e.openVPNConfig=o.optString("openvpn_config","");if(o.has("start_layer"))e.startLayer=new JSONObject(o.getJSONObject("start_layer").toString());if(o.has("response_probe"))e.responseProbe=new JSONObject(o.getJSONObject("response_probe").toString());if(o.has("policy"))e.policy=new JSONObject(o.getJSONObject("policy").toString());if(o.has("tor_policy"))e.torPolicy=new JSONObject(o.getJSONObject("tor_policy").toString());if(o.has("tor_bridge")){JSONObject bridge=o.getJSONObject("tor_bridge");e.torTransport=bridge.getString("transport");JSONArray lines=bridge.getJSONArray("bridges");for(int i=0;i<lines.length();i++)e.torBridges.add(lines.getString(i));}JSONArray a=o.optJSONArray("wg_addresses"),b=o.optJSONArray("wg_allowed_ips");if(a!=null)for(int i=0;i<a.length();i++)e.wgAddresses.add(a.getString(i));if(b!=null)for(int i=0;i<b.length();i++)e.wgAllowedIps.add(b.getString(i));return e;}
}
