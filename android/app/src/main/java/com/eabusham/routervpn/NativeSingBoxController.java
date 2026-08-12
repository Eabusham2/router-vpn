package com.eabusham.routervpn;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
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
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Prepares bounded app-private libbox sessions; no large configs cross Binder. */
final class NativeSingBoxController {
    static final String PREFS = "router-vpn";
    static final String STATE_KEY = "layered_state_v1";
    static final String MODE_KEY = "layered_mode_v1";
    static final String ERROR_KEY = "layered_error_v1";

    private static final long MAX_BUNDLE = 64L * 1024L * 1024L;
    private static final int MAX_CONFIG = 4 * 1024 * 1024;
    private static final int MAX_PROFILE_FILE = 8 * 1024 * 1024;
    private static final int MAX_PROFILE_TOTAL = 32 * 1024 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Map<String,String> KNOWN_TLS_NAMES = new HashMap<>();
    static {
        KNOWN_TLS_NAMES.put("1.1.1.1", "cloudflare-dns.com"); KNOWN_TLS_NAMES.put("1.0.0.1", "cloudflare-dns.com");
        KNOWN_TLS_NAMES.put("2606:4700:4700::1111", "cloudflare-dns.com"); KNOWN_TLS_NAMES.put("2606:4700:4700::1001", "cloudflare-dns.com");
        KNOWN_TLS_NAMES.put("8.8.8.8", "dns.google"); KNOWN_TLS_NAMES.put("8.8.4.4", "dns.google");
        KNOWN_TLS_NAMES.put("2001:4860:4860::8888", "dns.google"); KNOWN_TLS_NAMES.put("2001:4860:4860::8844", "dns.google");
        KNOWN_TLS_NAMES.put("9.9.9.9", "dns.quad9.net"); KNOWN_TLS_NAMES.put("149.112.112.112", "dns.quad9.net"); KNOWN_TLS_NAMES.put("2620:fe::fe", "dns.quad9.net");
    }

    static final class ModeInfo {
        final String id;
        final String name;
        ModeInfo(String id, String name) { this.id = id; this.name = name; }
        @Override public String toString() { return name; }
    }

    static final class SessionInfo {
        final String sessionId;
        final String modeId;
        SessionInfo(String sessionId, String modeId) { this.sessionId = sessionId; this.modeId = modeId; }
    }

    private static final class DnsSelection {
        String mode, protocol, host, serverName, path; int port;
    }

    private final Context context;

    NativeSingBoxController(Context context) { this.context = context.getApplicationContext(); }

    List<ModeInfo> listDirectLibboxModes(File privateBundle) throws Exception {
        JSONObject root = loadBundle(privateBundle);
        JSONObject profiles = root.optJSONObject("profiles");
        JSONArray modes = root.optJSONArray("modes");
        List<ModeInfo> result = new ArrayList<>();
        if (profiles == null || modes == null) return result;
        for (int i = 0; i < modes.length(); i++) {
            JSONObject mode = modes.optJSONObject(i);
            if (mode == null) continue;
            String id = mode.optString("id", "").trim();
            if (!safeToken(id)) continue;
            JSONObject profile = profiles.optJSONObject(id);
            if (profile == null) continue;
            String encoded = profile.optString("sing-box.json", "").trim();
            if (encoded.isEmpty()) continue;
            byte[] config;
            try { config = Base64.decode(encoded, Base64.DEFAULT); } catch (IllegalArgumentException invalid) { continue; }
            if (config.length == 0 || config.length > MAX_CONFIG) continue;
            if (!isDirectFullDeviceConfig(new String(config, StandardCharsets.UTF_8))) continue;
            String name = mode.optString("name", id).trim();
            result.add(new ModeInfo(id, name.isEmpty() ? id : name));
        }
        return result;
    }

    SessionInfo prepareSession(File privateBundle, String modeId) throws Exception {
        if (!safeToken(modeId)) throw new IllegalArgumentException("Invalid mode id.");
        JSONObject root = loadBundle(privateBundle);
        JSONObject profiles = root.optJSONObject("profiles");
        JSONObject profile = profiles == null ? null : profiles.optJSONObject(modeId);
        if (profile == null) throw new IllegalStateException("The selected mode has no generated profile.");
        String configEncoded = profile.optString("sing-box.json", "").trim();
        if (configEncoded.isEmpty()) throw new IllegalStateException("The selected mode has no sing-box config.");
        byte[] rawConfig = Base64.decode(configEncoded, Base64.DEFAULT);
        if (rawConfig.length == 0 || rawConfig.length > MAX_CONFIG) throw new IllegalStateException("sing-box config size is invalid.");
        String rawConfigText = new String(rawConfig, StandardCharsets.UTF_8);
        if (!isDirectFullDeviceConfig(rawConfigText)) throw new IllegalStateException("This mode still depends on another local engine and is not a direct embedded libbox mode.");
        JSONObject patchedConfig = new JSONObject(rawConfigText);
        applySelectedDns(root, patchedConfig);
        byte[] config = (patchedConfig.toString(2) + "\n").getBytes(StandardCharsets.UTF_8);
        if (config.length > MAX_CONFIG) throw new IllegalStateException("Patched sing-box config exceeds safety limit.");

        File rootDir = new File(context.getFilesDir(), "layered-sessions");
        if (!rootDir.isDirectory() && !rootDir.mkdirs()) throw new IllegalStateException("Cannot create layered session directory.");
        cleanupOldSessions(rootDir);
        String sessionId = randomHex(16);
        File session = new File(rootDir, sessionId);
        if (!session.mkdir()) throw new IllegalStateException("Cannot create layered session.");
        int total = 0;
        try {
            JSONArray names = profile.names();
            if (names == null) throw new IllegalStateException("Selected mode profile is empty.");
            for (int i = 0; i < names.length(); i++) {
                String name = names.getString(i);
                if (!safeFileName(name)) throw new IllegalStateException("Unsafe profile filename: " + name);
                byte[] decoded;
                if ("sing-box.json".equals(name)) decoded = config;
                else {
                    String encoded = profile.optString(name, "").trim();
                    if (encoded.isEmpty()) continue;
                    decoded = Base64.decode(encoded, Base64.DEFAULT);
                }
                if (decoded.length > MAX_PROFILE_FILE) throw new IllegalStateException("Profile file is too large: " + name);
                total += decoded.length;
                if (total > MAX_PROFILE_TOTAL) throw new IllegalStateException("Selected mode profile exceeds safety limit.");
                writeFile(new File(session, name), decoded);
            }
            File configFile = new File(session, "sing-box.json");
            if (!configFile.isFile() || configFile.length() == 0) throw new IllegalStateException("Session is missing sing-box.json.");
            return new SessionInfo(sessionId, modeId);
        } catch (Throwable error) { deleteTree(session); throw error; }
    }

    private static void applySelectedDns(JSONObject bundle, JSONObject config) throws Exception {
        DnsSelection selected = dnsSelection(bundle);
        String detour = chooseDnsDetour(config);
        String protocol = selected.protocol;
        if ("rescue".equals(protocol)) {
            protocol = "https";
            if (selected.serverName.isEmpty()) {
                selected.host = "1.1.1.1"; selected.serverName = "cloudflare-dns.com"; selected.port = 443; selected.path = "/dns-query";
            }
        }
        if (!("udp".equals(protocol)||"tcp".equals(protocol)||"tls".equals(protocol)||"https".equals(protocol)||"h3".equals(protocol))) throw new IllegalStateException("Unsupported selected DNS protocol: " + protocol);
        JSONObject server = new JSONObject().put("type", protocol).put("tag", "selected-dns").put("server", selected.host).put("server_port", selected.port).put("detour", detour);
        if ("tls".equals(protocol)||"https".equals(protocol)||"h3".equals(protocol)) {
            if (selected.serverName.isEmpty()) throw new IllegalStateException("Encrypted selected DNS requires a TLS server name.");
            server.put("tls", new JSONObject().put("enabled", true).put("server_name", selected.serverName));
        }
        if ("https".equals(protocol)||"h3".equals(protocol)) server.put("path", selected.path);
        config.put("dns", new JSONObject().put("servers", new JSONArray().put(server)).put("final", "selected-dns"));
        JSONObject route = config.optJSONObject("route"); if (route == null) { route = new JSONObject(); config.put("route", route); }
        JSONArray rules = route.optJSONArray("rules"); if (rules == null) rules = new JSONArray();
        boolean hasDnsRule = false;
        for (int i=0;i<rules.length();i++) { JSONObject rule=rules.optJSONObject(i); if(rule!=null && "dns".equals(rule.optString("protocol"))) { hasDnsRule=true; break; } }
        if (!hasDnsRule) {
            JSONArray next = new JSONArray().put(new JSONObject().put("protocol", "dns").put("action", "hijack-dns"));
            for(int i=0;i<rules.length();i++) next.put(rules.get(i));
            rules = next;
        }
        route.put("rules", rules);
    }

    private static DnsSelection dnsSelection(JSONObject bundle) throws Exception {
        JSONArray profiles = bundle.optJSONArray("routerProfiles");
        String selectedId = bundle.optString("selectedRouterID", "").trim();
        JSONObject profile = null;
        if (profiles != null) {
            for(int i=0;i<profiles.length();i++){JSONObject p=profiles.optJSONObject(i);if(p!=null && selectedId.equals(p.optString("id"))){profile=p;break;}}
            if(profile==null && profiles.length()>0) profile=profiles.optJSONObject(0);
        }
        if(profile==null) throw new IllegalStateException("Node bundle has no selected router DNS profile.");
        DnsSelection s = new DnsSelection();
        s.mode = profile.optString("dns_mode", "fastest").toLowerCase(Locale.ROOT);
        String fastest = profile.optString("fastest_dns_host", "1.1.1.1").trim();
        s.protocol = profile.optString("dns_protocol", "udp").toLowerCase(Locale.ROOT);
        s.host = profile.optString("dns_host", fastest).trim();
        s.port = profile.optInt("dns_port", 0);
        s.serverName = profile.optString("dns_server_name", "").trim();
        s.path = profile.optString("dns_path", "/dns-query").trim();
        if ("home".equals(s.mode)) { s.host=profile.optString("adguard_ipv4", profile.optString("adguard_ipv6", "10.77.0.1")).trim(); s.protocol="udp";s.port=53;s.serverName="";s.path=""; }
        else if ("fastest".equals(s.mode)) { s.host=fastest;s.protocol="udp";s.port=53;s.serverName="";s.path=""; }
        else if ("doh".equals(s.mode)) { s.protocol="https";if(s.port<=0)s.port=443; }
        else if ("dot".equals(s.mode)) { s.protocol="tls";if(s.port<=0)s.port=853; }
        else if ("doh3".equals(s.mode)) { s.protocol="h3";if(s.port<=0)s.port=443; }
        else if ("rescue".equals(s.mode)) { s.protocol="rescue";if(s.host.isEmpty())s.host=fastest;if(s.port<=0)s.port=443; }
        else { if("doh".equals(s.protocol))s.protocol="https";else if("dot".equals(s.protocol))s.protocol="tls";else if("doh3".equals(s.protocol))s.protocol="h3"; if(s.port<=0)s.port=("https".equals(s.protocol)||"h3".equals(s.protocol))?443:"tls".equals(s.protocol)?853:53; }
        if(s.host.isEmpty()) throw new IllegalStateException("Selected DNS host is empty.");
        if(s.serverName.isEmpty()) { String known=KNOWN_TLS_NAMES.get(s.host); if(known!=null)s.serverName=known; else if(s.host.indexOf(':')<0 && hasLetter(s.host))s.serverName=s.host; }
        if(s.path.isEmpty())s.path="/dns-query";
        return s;
    }

    private static boolean hasLetter(String value){for(int i=0;i<value.length();i++)if(Character.isLetter(value.charAt(i)))return true;return false;}
    private static String chooseDnsDetour(JSONObject config) {
        JSONArray outbounds=config.optJSONArray("outbounds");
        if(outbounds!=null) for(String candidate:new String[]{"proxy","tcp-stack","ss-hop","outer"}) for(int i=0;i<outbounds.length();i++){JSONObject o=outbounds.optJSONObject(i);if(o!=null&&candidate.equals(o.optString("tag")))return candidate;}
        return "direct";
    }

    void start(SessionInfo session) {
        Intent intent = new Intent(context, LayeredVpnService.class).setAction(LayeredVpnService.ACTION_START).putExtra(LayeredVpnService.EXTRA_SESSION_ID, session.sessionId).putExtra(LayeredVpnService.EXTRA_MODE_ID, session.modeId);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(intent); else context.startService(intent);
    }
    void stop() { context.startService(new Intent(context, LayeredVpnService.class).setAction(LayeredVpnService.ACTION_STOP)); }
    String getState() { return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(STATE_KEY, "DOWN"); }
    String getMode() { return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(MODE_KEY, ""); }
    String getError() { return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(ERROR_KEY, ""); }

    private static JSONObject loadBundle(File file) throws Exception {
        if (file == null || !file.isFile()) throw new IllegalStateException("Import/link a Router VPN node first.");
        if (file.length() <= 0 || file.length() > MAX_BUNDLE) throw new IllegalStateException("Private node bundle size is invalid.");
        return new JSONObject(new String(readLimited(file, (int) MAX_BUNDLE), StandardCharsets.UTF_8));
    }
    private static boolean isDirectFullDeviceConfig(String content) {
        try {
            JSONObject root = new JSONObject(content); JSONArray inbounds = root.optJSONArray("inbounds"); boolean tun = false;
            if (inbounds != null) for (int i=0;i<inbounds.length();i++){JSONObject inbound=inbounds.optJSONObject(i);if(inbound!=null&&"tun".equals(inbound.optString("type"))&&inbound.optBoolean("auto_route",false))tun=true;}
            if(!tun)return false; JSONArray outbounds=root.optJSONArray("outbounds");
            if(outbounds!=null)for(int i=0;i<outbounds.length();i++){JSONObject outbound=outbounds.optJSONObject(i);if(outbound==null)continue;String server=outbound.optString("server","").trim().toLowerCase(Locale.ROOT);if("127.0.0.1".equals(server)||"::1".equals(server)||"localhost".equals(server))return false;}
            return true;
        } catch(Exception invalid){return false;}
    }
    private static boolean safeToken(String value){return value!=null&&value.matches("[A-Za-z0-9._-]{1,96}")&&!value.equals(".")&&!value.equals("..")&&!value.contains("..");}
    private static boolean safeFileName(String value){return value!=null&&value.matches("[A-Za-z0-9._-]{1,128}")&&!value.equals(".")&&!value.equals("..")&&!value.contains("..");}
    private static byte[] readLimited(File file,int max)throws Exception{try(FileInputStream input=new FileInputStream(file);ByteArrayOutputStream output=new ByteArrayOutputStream()){byte[] buffer=new byte[8192];int total=0,read;while((read=input.read(buffer))!=-1){total+=read;if(total>max)throw new IllegalStateException("File exceeds safety limit.");output.write(buffer,0,read);}return output.toByteArray();}}
    private static void writeFile(File file,byte[] data)throws Exception{try(FileOutputStream output=new FileOutputStream(file,false)){output.write(data);output.getFD().sync();}}
    private static String randomHex(int bytes){byte[] raw=new byte[bytes];RANDOM.nextBytes(raw);StringBuilder out=new StringBuilder(bytes*2);for(byte b:raw)out.append(String.format(Locale.ROOT,"%02x",b&0xff));return out.toString();}
    private static void cleanupOldSessions(File root){File[] children=root.listFiles();if(children==null)return;long cutoff=System.currentTimeMillis()-24L*60L*60L*1000L;for(File child:children)if(child.isDirectory()&&child.lastModified()<cutoff)deleteTree(child);}
    static void deleteTree(File file){if(file==null)return;File[] children=file.listFiles();if(children!=null)for(File child:children)deleteTree(child);file.delete();}
}
