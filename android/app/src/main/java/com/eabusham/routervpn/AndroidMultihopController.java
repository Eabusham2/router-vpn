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
import java.util.List;
import java.util.Locale;

/**
 * Builds one real Android VpnService graph: standard WireGuard entry endpoint ->
 * independent WireGuard endpoint or Shadowsocks/Hysteria2 exit -> Internet.
 *
 * Pinned sing-box 1.14.1 resolves DialerOptions.detour through OutboundManager,
 * whose Outbound(tag) falls back to EndpointManager.Get(tag); WireGuard endpoints
 * implement adapter.Outbound. Keep other/mixed engine combinations fail-closed.
 */
final class AndroidMultihopController {
    private static final int MAX_BUNDLE = 32 * 1024 * 1024;
    private static final int MAX_CONFIG = 4 * 1024 * 1024;
    private static final int MAX_FILE = 8 * 1024 * 1024;
    private static final int MAX_TOTAL = 32 * 1024 * 1024;
    private static final int MAX_SESSION_DIRS = 32;
    static final int ENTRY_PROOF_PORT = 1098;
    static final int EXIT_PROOF_PORT = 1099;
    private static final SecureRandom RANDOM = new SecureRandom();
    private final Context context;
    private final NativeSingBoxController singBox;

    static final class Prepared {
        final NativeSingBoxController.SessionInfo session;
        final File exitBundle;
        final String exitMode;
        Prepared(NativeSingBoxController.SessionInfo session, File exitBundle, String exitMode) {
            this.session = session; this.exitBundle = exitBundle; this.exitMode = exitMode;
        }
    }

    private static final class EntryPrivate {
        final String host, username, password;
        final int port;
        EntryPrivate(String host, int port, String username, String password) {
            this.host = host; this.port = port; this.username = username; this.password = password;
        }
        JSONObject toOutboundJson() throws Exception {
            JSONObject out = new JSONObject()
                    .put("type", "socks")
                    .put("tag", "entry-private")
                    .put("server", host)
                    .put("server_port", port)
                    .put("version", "5")
                    .put("detour", "entry-wg");
            if (!username.isEmpty()) out.put("username", username).put("password", password);
            return out;
        }
    }

    AndroidMultihopController(Context context, NativeSingBoxController singBox) {
        this.context = context.getApplicationContext();
        this.singBox = singBox;
    }

    List<NativeSingBoxController.ModeInfo> listSupportedExitModes(File exitBundle) throws Exception {
        List<NativeSingBoxController.ModeInfo> result = new ArrayList<>();
        JSONObject bundle = loadBundle(exitBundle);
        JSONObject profiles = bundle.optJSONObject("profiles");
        if (profiles != null && profiles.optJSONObject("wg") != null) {
            String nativeConfig = io.nekohasekai.libbox.Libbox.routerWireGuardExitConfig(
                    readWireGuardText(bundle), AndroidNodeStore.stableNodeIdentity(bundle));
            io.nekohasekai.libbox.Libbox.checkConfig(nativeConfig);
            result.add(new NativeSingBoxController.ModeInfo("wg", "WireGuard"));
        }
        for (NativeSingBoxController.ModeInfo mode : singBox.listDirectLibboxModes(exitBundle)) {
            if ("shadowsocks".equals(mode.id) || "hysteria2".equals(mode.id)) result.add(mode);
        }
        return result;
    }

    Prepared prepare(File entryBundle, File exitBundle, String exitMode) throws Exception {
        return prepare(entryBundle, exitBundle, exitMode, "local");
    }
    Prepared prepare(File entryBundle, File exitBundle, String exitMode, String execution) throws Exception {
        return prepare(entryBundle, exitBundle, exitMode, execution, "wg");
    }
    Prepared prepare(File entryBundle, File exitBundle, String exitMode, String execution, String entryMode) throws Exception {
        if (!NativeSingBoxController.nativeWireGuardFamily(entryMode)) throw new IllegalArgumentException("Choose the exact native entry transport.");
        if(!java.util.Arrays.asList("local","server","auto").contains(execution))throw new IllegalArgumentException("Invalid multihop execution.");
        if (entryBundle == null || exitBundle == null) throw new IllegalArgumentException("Choose both an entry and an exit node.");
        if (entryBundle.getCanonicalFile().equals(exitBundle.getCanonicalFile())) throw new IllegalArgumentException("Entry and exit must be different stored nodes.");
        if (!("wg".equals(exitMode) || "shadowsocks".equals(exitMode) || "hysteria2".equals(exitMode))) throw new IllegalArgumentException("Android multihop requires a native WireGuard, Shadowsocks or Hysteria2 exit.");

        JSONObject entry = loadBundle(entryBundle);
        JSONObject exit = loadBundle(exitBundle);
        String entryIdentity = AndroidNodeStore.stableNodeIdentity(entry);
        String exitIdentity = AndroidNodeStore.stableNodeIdentity(exit);
        if (!entryIdentity.isEmpty() && entryIdentity.equals(exitIdentity)) throw new IllegalArgumentException("Entry and exit resolve to the same Router VPN node identity.");
        if (entryIdentity.isEmpty() || exitIdentity.isEmpty()) throw new IllegalArgumentException("Both multihop nodes need paired identities.");
        requireOwnedPolicies(entry); requireOwnedPolicies(exit);
        String entryText = readNativeText(entry, entryMode);
        String nativeEntry = "wg".equals(entryMode)
                ? io.nekohasekai.libbox.Libbox.routerCompileWireGuardProfile(entryText, entryIdentity)
                : io.nekohasekai.libbox.Libbox.routerCompileAmneziaProfile(entryText, entryIdentity);
        JSONObject wg = new JSONObject(nativeEntry).getJSONObject("endpoint").put("tag", "entry-wg");
        EntryPrivate entryPrivate = parseEntryPrivate(entry);
        JSONObject exitProfile;
        JSONObject config;
        if ("wg".equals(exitMode)) {
            String compiled = io.nekohasekai.libbox.Libbox.routerWireGuardExitConfig(readWireGuardText(exit), exitIdentity);
            config = new JSONObject(compiled);
            // Stage only the compiled graph: a second raw VPN is never started.
            exitProfile = new JSONObject().put("sing-box.json", "native-wireguard-graph");
        } else {
            exitProfile = requiredProfile(exit, exitMode);
            String encodedConfig = exitProfile.optString("sing-box.json", "").trim();
            if (encodedConfig.isEmpty() || encodedConfig.length() > MAX_CONFIG * 2) throw new IllegalStateException("Exit mode has no bounded embedded config.");
            byte[] rawConfig = Base64.decode(encodedConfig, Base64.DEFAULT);
            if (rawConfig.length == 0 || rawConfig.length > MAX_CONFIG) throw new IllegalStateException("Exit sing-box config size is invalid.");
            config = new JSONObject(strictUTF8(rawConfig));
        }
        makeMultihopConfig(config, wg, entryPrivate, exitMode);
        NativeSingBoxController.applySelectedDns(exit, config);
        JSONObject lanProfiles=new JSONObject().put("entry",selectedRouterProfile(entry)).put("exit",selectedRouterProfile(exit));
        String sized=io.nekohasekai.libbox.Libbox.routerApplyMultihopMTUPolicy(config.toString(),lanProfiles.toString());
        String filtered=io.nekohasekai.libbox.Libbox.routerApplyMultihopLANPolicy(sized,lanProfiles.toString());
        if(filtered==null||filtered.isEmpty())throw new IllegalStateException("Native multihop LAN policy was not compiled.");
        JSONObject entryPerformance = new JSONObject(selectedRouterProfile(entry).toString()).put("node_proof_id",entryIdentity);
        JSONObject exitPerformance = new JSONObject(selectedRouterProfile(exit).toString()).put("node_proof_id",exitIdentity);
        config = new JSONObject(io.nekohasekai.libbox.Libbox.routerApplyPerformancePolicy(filtered,new JSONObject().put("entry",entryPerformance).put("exit",exitPerformance).toString()));
        io.nekohasekai.libbox.Libbox.checkConfig(config.toString());
        byte[] patched = (config.toString() + "\n").getBytes(StandardCharsets.UTF_8);
        if (patched.length > MAX_CONFIG) throw new IllegalStateException("Multihop sing-box config exceeds safety limit.");

        File root = new File(context.getFilesDir(), "layered-sessions");
        if (!root.isDirectory() && !root.mkdirs()) throw new IllegalStateException("Cannot create layered session directory.");
        File[] dirs = root.listFiles(File::isDirectory);
        if (dirs != null && dirs.length >= MAX_SESSION_DIRS) throw new IllegalStateException("Too many private layered sessions exist; disconnect the current VPN before retrying.");
        String sessionId = randomHex(16);
        File session = new File(root, sessionId);
        if (!session.mkdir()) throw new IllegalStateException("Cannot create multihop session.");
        int total = 0;
        try {
            if (AndroidKillSwitchPolicy.strictRequested(entry) || AndroidKillSwitchPolicy.strictRequested(exit)) writeFile(new File(session, AndroidKillSwitchPolicy.SESSION_MARKER), new byte[]{'1','\n'});
            JSONArray names = exitProfile.names();
            if (names == null) throw new IllegalStateException("Exit profile is empty.");
            for (int i = 0; i < names.length(); i++) {
                String name = names.getString(i);
                if("routervpn-multihop.json".equals(name))throw new IllegalArgumentException("Imported profile uses a reserved multihop metadata file.");
                if (!safeFileName(name)) throw new IllegalStateException("Unsafe exit profile filename: " + name);
                byte[] data;
                if ("sing-box.json".equals(name)) data = patched;
                else {
                    String encoded = exitProfile.optString(name, "").trim();
                    if (encoded.isEmpty()) continue;
                    data = Base64.decode(encoded, Base64.DEFAULT);
                }
                if (data.length > MAX_FILE) throw new IllegalStateException("Exit profile file is too large: " + name);
                total += data.length;
                if (total > MAX_TOTAL) throw new IllegalStateException("Multihop session exceeds private staging limit.");
                writeFile(new File(session, name), data);
            }
            {
                JSONObject a=selectedRouterProfile(entry),b=selectedRouterProfile(exit);
                if(a==null||b==null)throw new IllegalArgumentException("Both paired node profiles are required.");
                JSONObject metadata=new JSONObject().put("entry_id",a.getString("id")).put("exit_id",b.getString("id"))
                    .put("entry_node_id",entryIdentity).put("entry_mode",entryMode)
                    .put("exit_node_id",exitIdentity)
                    .put("entry_api",a.getString("router_api")).put("exit_api",b.getString("router_api"))
                    .put("entry_token",a.getString("api_token")).put("exit_token",b.getString("api_token"))
                    .put("entry_tag","entry-wg").put("exit_mode",exitMode).put("execution",execution);
                byte[] privateMetadata=metadata.toString().getBytes(StandardCharsets.UTF_8);
                if(privateMetadata.length>16384)throw new IllegalArgumentException("Multihop metadata exceeds the safety bound.");
                writeFile(new File(session,"routervpn-multihop.json"),privateMetadata);
            }
            File configFile = new File(session, "sing-box.json");
            if (!configFile.isFile() || configFile.length() == 0) throw new IllegalStateException("Multihop session is missing sing-box.json.");
            return new Prepared(new NativeSingBoxController.SessionInfo(sessionId, "multihop-" + exitMode), exitBundle, exitMode);
        } catch (Throwable error) {
            deleteTree(session);
            throw error;
        }
    }

    private static void makeMultihopConfig(JSONObject config, JSONObject wg, EntryPrivate entryPrivate, String exitMode) throws Exception {
        JSONArray existingEndpoints = config.optJSONArray("endpoints");
        boolean wireGuardExit = "wg".equals(exitMode);
        if (config.has("endpoints") && existingEndpoints == null) throw new IllegalStateException("Malformed exit endpoints.");
        if (wireGuardExit) {
            if (existingEndpoints == null || existingEndpoints.length()!=1) throw new IllegalStateException("WireGuard exit requires exactly one owned endpoint.");
        } else if (existingEndpoints != null && existingEndpoints.length()!=0) throw new IllegalStateException("Unexpected exit endpoints.");
        JSONArray inbounds = config.optJSONArray("inbounds");
        if (inbounds == null || inbounds.length()!=1) throw new IllegalStateException("Multihop requires exactly one full-device TUN.");
        boolean fullDeviceTun = false;
        if (inbounds != null) for (int i = 0; i < inbounds.length(); i++) {
            JSONObject inbound = inbounds.optJSONObject(i);
            if (inbound == null) continue;
            if ("tun".equals(inbound.optString("type")) && inbound.optBoolean("auto_route", false)) fullDeviceTun = true;
            int port = inbound.optInt("listen_port", 0);
            String tag = inbound.optString("tag", "");
            if (port == ENTRY_PROOF_PORT || port == EXIT_PROOF_PORT) throw new IllegalStateException("Exit profile already consumes a reserved multihop proof port.");
            if ("multihop-entry-proof".equals(tag) || "multihop-proof".equals(tag)) throw new IllegalStateException("Exit profile already contains a reserved multihop proof inbound.");
        }
        if (!fullDeviceTun) throw new IllegalStateException("Exit mode is not a full-device libbox profile.");

        JSONObject route = config.optJSONObject("route");
        String finalTag = route == null ? "" : route.optString("final", "").trim();
        if (!"proxy".equals(finalTag)) throw new IllegalStateException("Exit profile final route is not the expected proxy outbound.");
        JSONArray outbounds = config.optJSONArray("outbounds");
        if (outbounds == null) throw new IllegalStateException("Exit profile has no outbounds.");
        JSONObject proxy = wireGuardExit ? existingEndpoints.getJSONObject(0) : null;
        if (wireGuardExit && outbounds.length()!=0) throw new IllegalStateException("WireGuard exit cannot contain an alternate outbound.");
        for (int i = 0; i < outbounds.length(); i++) {
            JSONObject outbound = outbounds.optJSONObject(i);
            if (outbound == null) throw new IllegalStateException("Invalid exit outbound.");
            String tag = outbound.optString("tag", "");
            if ("entry-private".equals(tag)) throw new IllegalStateException("Exit profile already contains reserved entry-private outbound.");
            if ("entry-wg".equals(tag)) throw new IllegalStateException("Exit consumes the owned entry tag.");
            if ("proxy".equals(tag)) {
                if (proxy != null) throw new IllegalStateException("Duplicate exit tags.");
                proxy=outbound;
            } else if (!("direct".equals(outbound.optString("type")) || "block".equals(outbound.optString("type")))) {
                throw new IllegalStateException("Unowned extra exit outbound.");
            }
        }
        if (proxy == null) throw new IllegalStateException("Exit profile has no proxy outbound.");
        String type = proxy.optString("type", "").toLowerCase(Locale.ROOT);
        String expected = wireGuardExit ? "wireguard" : exitMode;
        if (!expected.equals(type)) throw new IllegalStateException("Exit mode engine does not match its generated profile.");
        if (!"proxy".equals(proxy.optString("tag"))) throw new IllegalStateException("Exit endpoint lost its owned tag.");
        for (String key:new String[]{"detour","bind_interface","inet4_bind_address","inet6_bind_address","routing_mark","network_strategy","domain_resolver"}) {
            if (proxy.has(key)) throw new IllegalStateException("Exit already owns dial policy; it was not overwritten.");
        }
        if (wireGuardExit) {
            String a=wg.getJSONArray("peers").getJSONObject(0).getString("public_key");
            String b=proxy.getJSONArray("peers").getJSONObject(0).getString("public_key");
            if(a.equals(b)) throw new IllegalStateException("WireGuard hops cannot reuse the same server key under different labels.");
        } else if (!literalIP(proxy.optString("server", ""))) {
            throw new IllegalStateException("Exit requires a literal endpoint; direct DNS bootstrap is forbidden.");
        }

        JSONObject tun=inbounds.getJSONObject(0);
        for(String key:new String[]{"route_address","route_exclude_address","route_address_set","route_exclude_address_set"}) {
            if(tun.has(key)) throw new IllegalStateException("Saved split or bypass policy cannot be silently discarded.");
        }
        if(route.has("rule_set")) throw new IllegalStateException("Multihop cannot replace an imported rule set.");
        JSONArray importedRules=route.optJSONArray("rules");
        if(route.has("rules") && importedRules==null) throw new IllegalStateException("Invalid imported route rules.");
        if(importedRules!=null) for(int i=0;i<importedRules.length();i++) {
            JSONObject rule=importedRules.getJSONObject(i);
            if(rule.length()!=2 || !"dns".equals(rule.optString("protocol")) || !"hijack-dns".equals(rule.optString("action"))) throw new IllegalStateException("Multihop cannot replace custom routing rules.");
        }
        tun.put("strict_route",true).put("stack","system");
        tun.remove("interface_name");
        proxy.put("detour", "entry-wg");
        outbounds.put(entryPrivate.toOutboundJson());
        config.put("outbounds", outbounds);
        JSONArray endpoints=new JSONArray().put(wg);
        if(wireGuardExit) endpoints.put(proxy);
        config.put("endpoints", endpoints);
        inbounds.put(new JSONObject().put("type", "mixed").put("tag", "multihop-entry-proof").put("listen", "127.0.0.1").put("listen_port", ENTRY_PROOF_PORT));
        inbounds.put(new JSONObject().put("type", "mixed").put("tag", "multihop-proof").put("listen", "127.0.0.1").put("listen_port", EXIT_PROOF_PORT));
        config.put("inbounds", inbounds);

        JSONArray oldRules = route.optJSONArray("rules");
        JSONArray rules = new JSONArray();
        rules.put(new JSONObject().put("inbound", new JSONArray().put("multihop-entry-proof")).put("outbound", "entry-private"));
        rules.put(new JSONObject().put("inbound", new JSONArray().put("multihop-proof")).put("outbound", "proxy"));
        if (oldRules != null) for (int i = 0; i < oldRules.length(); i++) rules.put(oldRules.get(i));
        route.put("rules", rules);
        config.put("route", route);
    }

    private static JSONObject selectedRouterProfile(JSONObject bundle) {
        return AndroidProfileSelection.selectedRouterProfile(bundle);
    }

    private static void requireOwnedPolicies(JSONObject bundle) {
        JSONObject profile=selectedRouterProfile(bundle);
        for (String name:new String[]{"daita_enabled","jumbo_tun"}) {
            Object value=profile.opt(name);
            if (value!=null && value!=JSONObject.NULL && !(value instanceof Boolean)) throw new IllegalArgumentException("Invalid multihop policy type.");
            // The shared performance compiler enforces both captured policies
            // after graph/MTU/LAN composition and before any session is staged.
        }
        String start=profile.optString("start_layer","off").trim().toLowerCase(Locale.ROOT);
        if (!java.util.Arrays.asList("","off","none","disabled").contains(start)) throw new IllegalArgumentException("This graph does not own an additional Start Layer.");
    }

    private static EntryPrivate parseEntryPrivate(JSONObject bundle) {
        JSONObject profile = selectedRouterProfile(bundle);
        String host = profile == null ? "" : profile.optString("socks_host", "").trim();
        if (host.isEmpty()) host = bundle.optString("socks5Host", "").trim();
        host = stripBrackets(host);
        if (!literalIP(host)) throw new IllegalStateException("Android multihop entry private SOCKS host must be a literal IP address.");
        int port = profile == null ? 0 : profile.optInt("socks_port", 0);
        if (port == 0) port = bundle.optInt("socks5Port", 1080);
        if (port < 1 || port > 65535) throw new IllegalStateException("Android multihop entry private SOCKS port is invalid.");
        String username = profile == null ? "" : profile.optString("socks_username", "").trim();
        if (username.isEmpty()) username = bundle.optString("socks5Username", "").trim();
        String password = profile == null ? "" : profile.optString("socks_password", "");
        if (password.isEmpty()) password = bundle.optString("socks5Password", "");
        if (username.isEmpty() != password.isEmpty()) throw new IllegalStateException("Android multihop entry private SOCKS credentials are incomplete.");
        return new EntryPrivate(host, port, username, password);
    }

    private static boolean literalIP(String value) {
        try { return AndroidNumericAddress.parse(value) != null; }
        catch (Exception invalid) { return false; }
    }

    private static String stripBrackets(String value) {
        String out = value == null ? "" : value.trim();
        if (out.startsWith("[") && out.endsWith("]") && out.length() > 2) return out.substring(1, out.length() - 1);
        return out;
    }

    private static JSONObject requiredProfile(JSONObject bundle, String mode) {
        JSONObject profiles = bundle.optJSONObject("profiles");
        JSONObject profile = profiles == null ? null : profiles.optJSONObject(mode);
        if (profile == null) throw new IllegalStateException("Exit node does not contain " + mode + ".");
        return profile;
    }

    private static String readWireGuardText(JSONObject bundle) throws Exception {
        return readNativeText(bundle,"wg");
    }
    private static String readNativeText(JSONObject bundle, String mode) throws Exception {
        JSONObject profile=requiredProfile(bundle,mode);
        String encoded=profile.optString("wg".equals(mode) ? "wg.conf" : "awg.conf", "").trim();
        if (encoded.isEmpty() || encoded.length()>2*1024*1024) throw new IllegalStateException("Node has no bounded standard WireGuard profile.");
        byte[] raw=Base64.decode(encoded,Base64.DEFAULT);
        if(raw.length==0 || raw.length>1024*1024) throw new IllegalStateException("WireGuard profile size is invalid.");
        return strictUTF8(raw);
    }
    private static String strictUTF8(byte[] value) throws Exception {
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(value)).toString();
    }
    private static JSONObject loadBundle(File file) throws Exception {
        if (file == null || !file.isFile() || file.length() <= 0 || file.length() > MAX_BUNDLE) throw new IllegalStateException("Private node bundle is missing or invalid.");
        try (FileInputStream in = new FileInputStream(file); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] b = new byte[8192]; int total = 0, n; while ((n = in.read(b)) != -1) { total += n; if (total > MAX_BUNDLE) throw new IllegalStateException("Private node bundle exceeds safety limit."); out.write(b, 0, n); }
            JSONObject root = new JSONObject(new String(out.toByteArray(), StandardCharsets.UTF_8)); AndroidNodeStore.validateBundle(root); return root;
        }
    }
    private static void writeFile(File file, byte[] data) throws Exception { try (FileOutputStream out = new FileOutputStream(file, false)) { out.write(data); out.flush(); out.getFD().sync(); } }
    private static boolean safeFileName(String value) { return value != null && value.matches("[A-Za-z0-9._-]{1,128}") && !value.equals(".") && !value.equals("..") && !value.contains(".."); }
    private static String randomHex(int bytes) { byte[] value = new byte[bytes]; RANDOM.nextBytes(value); StringBuilder out = new StringBuilder(bytes * 2); for (byte b : value) out.append(String.format("%02x", b & 0xff)); return out.toString(); }
    private static void deleteTree(File file) { if (file == null || !file.exists()) return; File[] children = file.listFiles(); if (children != null) for (File child : children) deleteTree(child); file.delete(); }
}
