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
import java.nio.charset.CodingErrorAction;
import java.nio.ByteBuffer;

import io.nekohasekai.libbox.Libbox;
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
            String candidate;
            try {
                candidate = compileStandaloneProfile(root, profile, id);
                if (!isDirectFullDeviceConfig(candidate)) continue;
                if (AndroidStartLayer.nativeXray(id)) {
                    JSONObject config = new JSONObject(candidate);
                    applySelectedDns(root, config);
                    AndroidXrayLibboxPolicy.normalizeDnsRoutes(config);
                    if (!AndroidStartLayer.nativeCapabilityReason(root, id).isEmpty()) continue;
                    AndroidStartLayer.RelayPlan plan = AndroidStartLayer.apply(root, config, id);
                    if (plan != null) { plan.clear(); throw new IllegalStateException("Native Xray cannot require another relay."); }
                    config = AndroidXrayLibboxPolicy.applyDevice(root, config);
                    applyPerformance(root, config);
                    // No DNS/socket creation while populating readiness. The
                    // selected launch resolves and checks the actual native core.
                } else if (nativeWireGuardFamily(id)) {
                    JSONObject config = new JSONObject(candidate);
                    applySelectedDns(root, config);
                    config = AndroidWireGuardLibboxPolicy.apply(root, config);
                    if (!AndroidStartLayer.nativeCapabilityReason(root, id).isEmpty()) continue;
                    AndroidStartLayer.RelayPlan plan = AndroidStartLayer.apply(root, config, id);
                    if (plan != null) { plan.clear(); throw new IllegalStateException("Native WG/AWG must own its Start Layer without a local relay."); }
                    config = applyPerformance(root, config);
                    Libbox.checkConfig(config.toString());
                }
            } catch (Exception invalid) { continue; }
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
        String capturedBundle = root.toString();
        String rawConfigText = AndroidStartLayer.nativeXray(modeId)
                ? AndroidXrayLibboxPolicy.resolve(root, profile, modeId)
                : compileStandaloneProfile(root, profile, modeId);
        if (nativeWireGuardFamily(modeId)) {
            // Only the compiled graph is staged. A second WireGuard VPN or
            // unused raw-backend file must never be started implicitly.
            profile = new JSONObject().put("sing-box.json", "native-wireguard-graph");
        }
        if (!isDirectFullDeviceConfig(rawConfigText)) throw new IllegalStateException("This mode still depends on another local engine and is not a direct embedded libbox mode.");
        JSONObject patchedConfig = new JSONObject(rawConfigText);
        applySelectedDns(root, patchedConfig);
        if (AndroidStartLayer.nativeXray(modeId)) AndroidXrayLibboxPolicy.normalizeDnsRoutes(patchedConfig);
        if (nativeWireGuardFamily(modeId)) patchedConfig = AndroidWireGuardLibboxPolicy.apply(root, patchedConfig);
        // Recompile after DNS selection: UDP/DoH3 must use the real Hysteria2
        // leg, not the SS2022 WebSocket/TLS transport restricted to TCP.
        if ("ss-v2ray".equals(modeId)) patchedConfig = new JSONObject(compileNativeSIP003(profile, modeId, patchedConfig.toString()));
        AndroidStartLayer.RelayPlan relayPlan = AndroidStartLayer.apply(root, patchedConfig, modeId);
        try {
            if (AndroidStartLayer.nativeXray(modeId)) patchedConfig = AndroidXrayLibboxPolicy.applyDevice(root, patchedConfig);
            patchedConfig = applyPerformance(root, patchedConfig);
            Libbox.checkConfig(patchedConfig.toString());
            byte[] config = (patchedConfig.toString(2) + "\n").getBytes(StandardCharsets.UTF_8);
            if (config.length > MAX_CONFIG) throw new IllegalStateException("Patched sing-box config exceeds safety limit.");

            if (AndroidStartLayer.nativeXray(modeId) && (Thread.currentThread().isInterrupted()
                    || !capturedBundle.equals(loadBundle(privateBundle).toString()))) {
                throw new IllegalStateException("Selected node changed or preparation was cancelled; no Xray session was staged.");
            }
            File rootDir = new File(context.getFilesDir(), "layered-sessions");
            if (!rootDir.isDirectory() && !rootDir.mkdirs()) throw new IllegalStateException("Cannot create layered session directory.");
            cleanupOldSessions(rootDir);
            String sessionId = randomHex(16);
            File session = new File(rootDir, sessionId);
            if (!session.mkdir()) throw new IllegalStateException("Cannot create layered session.");
            int total = 0;
            try {
                if (AndroidKillSwitchPolicy.strictRequested(root)) {
                    writeFile(new File(session, AndroidKillSwitchPolicy.SESSION_MARKER), new byte[]{'1','\n'});
                }
                if (relayPlan != null) {
                    byte[] metadata = (relayPlan.metadata().toString(2) + "\n").getBytes(StandardCharsets.UTF_8);
                    if (metadata.length <= 0 || metadata.length > 16 * 1024) throw new IllegalStateException("Start Layer relay metadata exceeds safety limit.");
                    total += metadata.length;
                    if (total > MAX_PROFILE_TOTAL) throw new IllegalStateException("Selected mode profile exceeds safety limit.");
                    writeFile(new File(session, AndroidStartLayerRelay.SESSION_FILE), metadata);
                }
                JSONArray names = profile.names();
                if (names == null) throw new IllegalStateException("Selected mode profile is empty.");
                for (int i = 0; i < names.length(); i++) {
                    String name = names.getString(i);
                    if (AndroidStartLayer.nativeXray(modeId) && "xray.json".equals(name)) continue;
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
                JSONObject mtuProfile=new JSONObject(AndroidProfileSelection.selectedRouterProfile(root).toString());
                mtuProfile.put("node_proof_id",AndroidNodeStore.stableNodeIdentity(root));
                byte[] mtuBytes=mtuProfile.toString().getBytes(StandardCharsets.UTF_8);
                if(mtuBytes.length>256*1024)throw new IllegalStateException("Captured MTU metadata exceeds its bound.");
                total += mtuBytes.length;
                if(total>MAX_PROFILE_TOTAL)throw new IllegalStateException("MTU metadata exceeds the staged profile budget.");
                writeFile(new File(session,"routervpn-mtu.json"),mtuBytes);
                File configFile = new File(session, "sing-box.json");
                if (!configFile.isFile() || configFile.length() == 0) throw new IllegalStateException("Session is missing sing-box.json.");
                return new SessionInfo(sessionId, modeId);
            } catch (Throwable error) { deleteTree(session); throw error; }
        } finally {
            if (relayPlan != null) relayPlan.clear();
        }
    }

    static JSONObject applyPerformance(JSONObject bundle, JSONObject config) throws Exception {
        JSONObject profile = new JSONObject(AndroidProfileSelection.selectedRouterProfile(bundle).toString());
        profile.put("node_proof_id", AndroidNodeStore.stableNodeIdentity(bundle));
        String policy = new JSONObject().put("entry",profile).put("exit",profile).toString();
        String result = Libbox.routerApplyPerformancePolicy(config.toString(),policy);
        if (result == null || result.isEmpty() || result.length() > MAX_CONFIG) throw new IllegalStateException("Native performance policy returned no bounded graph.");
        return new JSONObject(result);
    }

    static boolean nativeMultihopEntry(String mode) {
        return nativeWireGuardFamily(mode) || "shadowsocks".equals(mode) || "hysteria2".equals(mode);
    }

    static boolean nativeWireGuardFamily(String mode) {
        return "wg".equals(mode) || "awg2-fast".equals(mode) || "awg2-strong".equals(mode);
    }

    private static String compileStandaloneProfile(JSONObject bundle, JSONObject profile, String modeId) throws Exception {
        if (AndroidStartLayer.nativeXray(modeId)) return AndroidXrayLibboxPolicy.check(bundle, profile, modeId);
        String asset = "wg".equals(modeId) ? "wg.conf" : nativeWireGuardFamily(modeId) ? "awg.conf" : "sing-box.json";
        int maximum = nativeWireGuardFamily(modeId) ? 1024 * 1024 : MAX_CONFIG;
        String encoded = profile.optString(asset, "");
        if (encoded.isEmpty() || encoded.length() > ((maximum + 2) / 3) * 4) {
            throw new IllegalStateException("The selected native profile is missing or oversized.");
        }
        byte[] raw = Base64.decode(encoded, Base64.DEFAULT);
        if (raw.length == 0 || raw.length > maximum) throw new IllegalStateException("Native profile size is invalid.");
        if (!nativeWireGuardFamily(modeId)) return compileNativeSIP003(profile, modeId, strictUTF8(raw));
        JSONArray names = profile.names();
        for (int i = 0; names != null && i < names.length(); i++) {
            String name = names.getString(i);
            if (!(asset.equals(name) || "stack.json".equals(name))) {
                throw new IllegalStateException("WireGuard profile contains an unowned helper asset.");
            }
        }
        String nodeID = AndroidNodeStore.stableNodeIdentity(bundle);
        return "wg".equals(modeId) ? Libbox.routerWireGuardExitConfig(strictUTF8(raw), nodeID)
                : Libbox.routerAmneziaExitConfig(strictUTF8(raw), nodeID);
    }

    private static String strictUTF8(byte[] raw) throws Exception {
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString();
    }

    private static String compileNativeSIP003(JSONObject profile, String modeId, String wrapper) throws Exception {
        if (!"ss-v2ray".equals(modeId)) return wrapper;
        if (wrapper.isEmpty() || wrapper.getBytes(StandardCharsets.UTF_8).length > MAX_CONFIG)
            throw new IllegalStateException("Native SIP003 config exceeds its safety limit.");
        JSONArray names = profile.names();
        if (names == null) throw new IllegalStateException("Native SIP003 profile is missing.");
        for (int i = 0; i < names.length(); i++) {
            String name = names.getString(i);
            if (!("sing-box.json".equals(name) || "sslocal.json".equals(name) || "cert.pem".equals(name) || "stack.json".equals(name)))
                throw new IllegalStateException("Native SIP003 profile contains an unowned helper asset.");
        }
        String encoded = profile.optString("sslocal.json", "");
        if (encoded.isEmpty() || encoded.length() > ((MAX_CONFIG + 2) / 3) * 4)
            throw new IllegalStateException("Native SIP003 helper profile exceeds its safety limit.");
        byte[] raw = Base64.decode(encoded, Base64.DEFAULT);
        if (raw.length == 0 || raw.length > MAX_CONFIG) throw new IllegalStateException("Native SIP003 helper profile is invalid.");
        String result = Libbox.routerCompileSIP003Profile(wrapper, strictUTF8(raw));
        if (result == null || result.isEmpty() || result.getBytes(StandardCharsets.UTF_8).length > MAX_CONFIG)
            throw new IllegalStateException("Native SIP003 compiler returned no bounded graph.");
        return result;
    }

    static void applySelectedDns(JSONObject bundle, JSONObject config) throws Exception {
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
        JSONArray servers = new JSONArray();
        if (!literalDnsHost(selected.host)) {
            JSONObject profile = AndroidProfileSelection.selectedRouterProfile(bundle);
            String bootstrap = firstNonEmpty(profile.optString("adguard_ipv4", ""), profile.optString("adguard_ipv6", ""));
            if (!literalDnsHost(bootstrap)) throw new IllegalStateException("Resolver hostname requires a configured literal home DNS bootstrap through the VPN.");
            servers.put(new JSONObject().put("type", "udp").put("tag", "routervpn-bootstrap-dns")
                    .put("server", bootstrap).put("server_port", 53).put("detour", detour));
            server.put("domain_resolver", "routervpn-bootstrap-dns");
        }
        servers.put(server);
        config.put("dns", new JSONObject().put("servers", servers).put("final", "selected-dns"));
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
        JSONObject profile = AndroidProfileSelection.selectedRouterProfile(bundle);
        DnsSelection s = new DnsSelection();
        s.mode = AndroidNativeProfilePolicy.stringPolicy(profile, "dns_mode", "home");
        if (s.mode.isEmpty()) s.mode = "home";
        if (!java.util.Arrays.asList("home", "fastest", "custom", "dot", "doh", "doh3", "rescue").contains(s.mode)) throw new IllegalStateException("Unknown DNS mode.");
        String fastest = profile.optString("fastest_dns_host", "").trim();
        s.protocol = profile.optString("dns_protocol", "udp").toLowerCase(Locale.ROOT);
        s.host = profile.optString("dns_host", fastest).trim();
        s.port = AndroidNativeProfilePolicy.exactInteger(profile, "dns_port", 0, 0, 65535);
        s.serverName = profile.optString("dns_server_name", "").trim();
        s.path = profile.optString("dns_path", "/dns-query").trim();
        if ("home".equals(s.mode)) { s.host=firstNonEmpty(profile.optString("adguard_ipv4", ""), profile.optString("adguard_ipv6", "")); s.protocol="udp";s.port=53;s.serverName="";s.path=""; }
        else if ("fastest".equals(s.mode)) { s.host=fastest;s.protocol="udp";s.port=53;s.serverName="";s.path=""; }
        else if ("doh".equals(s.mode)) { s.protocol="https";if(s.port<=0)s.port=443; }
        else if ("dot".equals(s.mode)) { s.protocol="tls";if(s.port<=0)s.port=853; }
        else if ("doh3".equals(s.mode)) { s.protocol="h3";if(s.port<=0)s.port=443; }
        else if ("rescue".equals(s.mode)) { s.protocol="rescue";if(s.host.isEmpty())s.host=firstNonEmpty(fastest,"1.1.1.1");if(s.port<=0)s.port=443; }
        else { if("doh".equals(s.protocol))s.protocol="https";else if("dot".equals(s.protocol))s.protocol="tls";else if("doh3".equals(s.protocol))s.protocol="h3"; if(s.port<=0)s.port=("https".equals(s.protocol)||"h3".equals(s.protocol))?443:"tls".equals(s.protocol)?853:53; }
        if(s.host.isEmpty()) throw new IllegalStateException("Selected DNS host is empty.");
        if(s.serverName.isEmpty()) { String known=KNOWN_TLS_NAMES.get(s.host); if(known!=null)s.serverName=known; else if(s.host.indexOf(':')<0 && hasLetter(s.host))s.serverName=s.host; }
        if(s.path.isEmpty())s.path="/dns-query";
        return s;
    }

    private static String firstNonEmpty(String first, String second) { return first.trim().isEmpty() ? second.trim() : first.trim(); }
    private static boolean literalDnsHost(String value) {
        try { return AndroidNumericAddress.parse(value) != null; }
        catch (Exception invalid) { return false; }
    }
    private static boolean hasLetter(String value){for(int i=0;i<value.length();i++)if(Character.isLetter(value.charAt(i)))return true;return false;}
    private static String chooseDnsDetour(JSONObject config) {
        for (String candidate:new String[]{"proxy","tcp-stack","ss-hop","outer"}) {
            for (String group:new String[]{"outbounds","endpoints"}) {
                JSONArray values=config.optJSONArray(group);
                if(values!=null) for(int i=0;i<values.length();i++) {
                    JSONObject outbound=values.optJSONObject(i);
                    if(outbound!=null && candidate.equals(outbound.optString("tag")) && !"direct".equals(outbound.optString("type")) && !"block".equals(outbound.optString("type"))) return candidate;
                }
            }
        }
        throw new IllegalStateException("Selected DNS has no owned encrypted outbound; direct fallback is forbidden.");
    }

    void start(SessionInfo session) {
        Intent intent = new Intent(context, LayeredVpnService.class).setAction(LayeredVpnService.ACTION_START).putExtra(LayeredVpnService.EXTRA_SESSION_ID, session.sessionId).putExtra(LayeredVpnService.EXTRA_MODE_ID, session.modeId);
        AndroidServiceStopConfirmation.start(STATE_KEY, () -> {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(intent); else context.startService(intent);
        });
    }
    void stop() {
        AndroidServiceStopConfirmation.request(STATE_KEY, command -> context.startService(
                new Intent(context, LayeredVpnService.class).setAction(LayeredVpnService.ACTION_STOP)
                        .putExtra(AndroidServiceStopConfirmation.EXTRA_COMMAND, command)));
    }
    String getState() {
        return AndroidServiceStopConfirmation.state(STATE_KEY,
                () -> context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(STATE_KEY, "DOWN"));
    }
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
