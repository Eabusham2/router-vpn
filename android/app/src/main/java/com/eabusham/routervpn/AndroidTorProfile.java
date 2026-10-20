package com.eabusham.routervpn;

import android.content.Context;
import io.nekohasekai.libbox.Libbox;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/** Captures Tor and its optional complete encrypted entry before the VPN starts. */
final class AndroidTorProfile {
    static final String SESSION_FILE = "routervpn-tor.json";
    static final String OUTBOUND = "routervpn-tor-exit";
    static final int MAX_CONFIG = 4 * 1024 * 1024;
    static final int MAX_METADATA = 256 * 1024;
    static final String[] TRANSPORTS = {"obfs4", "meek_lite", "snowflake", "webtunnel", "custom"};
    private static final Set<String> POLICY = new HashSet<>(Arrays.asList(
            "dns_mode", "dns_protocol", "dns_host", "dns_port", "dns_server_name", "dns_path",
            "ipv6_mode", "home_lan_access", "home_lan_cidrs", "mtu_policy", "manual_mtu"));

    static boolean isTor(String protocol) { return "tor".equals(protocol) || "tor-bridge".equals(protocol); }

    /** Restore the effective saved policy; opening an editor must not change it. */
    static JSONObject editorPolicy(AndroidStandardExitStore.Entry saved) throws Exception {
        if (saved == null) return new JSONObject().put("dns_mode", "rescue")
                .put("ipv6_mode", "off").put("home_lan_access", false);
        JSONObject policy = saved.torPolicy == null ? new JSONObject() : new JSONObject(saved.torPolicy.toString());
        String mode = policy.optString("dns_mode", "");
        if (mode.isEmpty() || "rescue".equals(mode)) {
            policy.put("dns_mode", "rescue");
            policy.remove("dns_protocol");
        } else {
            String protocol = "custom".equals(mode) ? policy.optString("dns_protocol", "") : mode;
            if ("tls".equals(protocol)) protocol = "dot";
            if ("https".equals(protocol)) protocol = "doh";
            if ((!"custom".equals(mode) && !"dot".equals(mode) && !"doh".equals(mode))
                    || (!"tcp".equals(protocol) && !"dot".equals(protocol) && !"doh".equals(protocol))) {
                throw new IllegalArgumentException("The saved Tor DNS policy cannot be edited as a supported endpoint.");
            }
            policy.put("dns_mode", "custom").put("dns_protocol", protocol);
        }
        String ipv6 = policy.optString("ipv6_mode", "");
        if (ipv6.isEmpty()) policy.put("ipv6_mode", "auto");
        if (!policy.has("home_lan_access")) policy.put("home_lan_access", true);
        return policy;
    }

    /** Keep untouched saved groups byte-for-byte in the captured profile. */
    static JSONObject editedPolicy(AndroidStandardExitStore.Entry saved, JSONObject initial, JSONObject edited) throws Exception {
        if (saved == null) return new JSONObject(edited.toString());
        JSONObject result = saved.torPolicy == null ? new JSONObject() : new JSONObject(saved.torPolicy.toString());
        for (String[] group : new String[][] {
                {"dns_mode", "dns_protocol", "dns_host", "dns_port", "dns_server_name", "dns_path"},
                {"ipv6_mode"}, {"home_lan_access", "home_lan_cidrs"}, {"mtu_policy", "manual_mtu"}}) {
            boolean changed = false;
            for (String key : group) {
                if (initial.has(key) != edited.has(key) || !String.valueOf(initial.opt(key)).equals(String.valueOf(edited.opt(key)))) changed = true;
            }
            if (!changed) continue;
            for (String key : group) {
                result.remove(key);
                if (edited.has(key)) result.put(key, edited.get(key));
            }
        }
        return result;
    }

    static JSONObject profile(AndroidStandardExitStore.Entry exit) throws Exception {
        if (exit == null || !isTor(exit.protocol)) throw new IllegalArgumentException("Select a saved Tor node.");
        JSONObject result = new JSONObject();
        JSONObject policy = exit.torPolicy == null ? new JSONObject() : new JSONObject(exit.torPolicy.toString());
        JSONArray keys = policy.names();
        for (int i = 0; keys != null && i < keys.length(); i++) {
            String key = keys.getString(i);
            if (!POLICY.contains(key)) throw new IllegalArgumentException("Tor settings contain an unowned policy field.");
            result.put(key, policy.get(key));
        }
        result.put("id", exit.id).put("node_kind", "external").put("start_layer", "off");
        JSONObject external = new JSONObject().put("protocol", exit.protocol);
        if ("tor-bridge".equals(exit.protocol)) {
            if (!Arrays.asList(TRANSPORTS).contains(exit.torTransport)) throw new IllegalArgumentException("Choose a supported Tor bridge transport.");
            external.put("tor_bridge", new JSONObject().put("transport", exit.torTransport).put("bridges", new JSONArray(exit.torBridges)));
        } else if (!exit.torBridges.isEmpty() || !empty(exit.torTransport)) {
            throw new IllegalArgumentException("Plain Tor cannot discard saved bridge settings.");
        }
        return result.put("external", external);
    }

    static void validate(AndroidStandardExitStore.Entry exit) throws Exception {
        if (!empty(exit.server) || exit.serverPort != 0 || !empty(exit.expectedPublicIp)
                || !empty(exit.username) || !empty(exit.password) || !empty(exit.method) || !empty(exit.secret)
                || !empty(exit.tlsServerName) || !empty(exit.wgPrivateKey) || !empty(exit.wgPeerPublicKey)
                || !empty(exit.wgPreSharedKey) || !empty(exit.openVPNConfig) || exit.wgMtu != 0
                || !exit.wgAddresses.isEmpty() || !exit.wgAllowedIps.isEmpty()) {
            throw new IllegalArgumentException("Tor uses its captured circuit and dynamic exit proof; remove the unrelated server, credentials or fixed exit IP.");
        }
        String captured = profile(exit).toString();
        if (captured.getBytes(StandardCharsets.UTF_8).length > MAX_METADATA) throw new IllegalArgumentException("Tor profile is too large.");
        // Shared validation preserves the exact saved DNS/interface policy and
        // rejects unsupported UDP/DoH3 instead of silently replacing it.
        String config = Libbox.routerCompileTorProfile(captured, "routervpn-tor-validation", "");
        if (!bounded(config, MAX_CONFIG)) throw new IllegalArgumentException("The saved Tor profile did not compile.");
    }

    static NativeSingBoxController.SessionInfo prepare(Context context, File entryFile,
            AndroidStandardExitStore.Entry selected, String entryMode) throws Exception {
        AndroidStandardExitStore.Entry exit = AndroidStandardExitStore.copy(selected);
        AndroidStandardExitStore.validate(exit);
        String capturedExit = AndroidStandardExitStore.snapshot(exit);
        String capturedProfile = profile(exit).toString();
        JSONObject entry = null, predecessorProfile = null;
        byte[] entryBytes = null;
        AndroidStartLayer.RelayPlan relay = null;
        AndroidMAXProfilePreparation maxPreparation = null;
        boolean maxStaged = false;
        String predecessor = "";
        try {
            if (entryFile != null) {
                if (!NativeSingBoxController.nativeMultihopEntry(entryMode)) throw new IllegalArgumentException("Choose the exact supported entry transport.");
                entryBytes = AndroidPrivateFileStore.read(entryFile, AndroidNodeStore.MAX_BUNDLE);
                entry = new JSONObject(strictText(entryBytes));
                AndroidNodeStore.validateBundle(entry);
                predecessorProfile = AndroidProfileSelection.selectedRouterProfile(entry);
                String node = AndroidNodeStore.stableNodeIdentity(entry);
                if (!node.matches("[0-9a-f]{64}") || !node.equals(predecessorProfile.optString("node_proof_id"))
                        || !"router-vpn".equals(predecessorProfile.optString("node_kind"))) {
                    throw new IllegalArgumentException("Tor entry lost its selected Router VPN node identity.");
                }
                JSONObject assets = entry.getJSONObject("profiles").getJSONObject(entryMode);
                JSONObject graph;
                if (AndroidNativeMAXProfile.isMode(entryMode)) {
                    AndroidMAXProfilePreparation.Source source = new AndroidMAXProfilePreparation.Source(entryFile, entry, entryMode);
                    maxPreparation = AndroidMAXProfilePreparation.begin(context, source);
                    graph = new JSONObject(maxPreparation == null ? AndroidNativeMAXProfile.compile(entry, assets, entryMode) : maxPreparation.compile(source));
                } else if (AndroidNativeCompositeProfile.isMode(entryMode)) {
                    graph = new JSONObject(AndroidNativeCompositeProfile.compile(entry, assets, entryMode));
                } else {
                    String compiled = AndroidStartLayer.nativeXray(entryMode)
                            ? AndroidXrayLibboxPolicy.resolve(entry, assets, entryMode)
                            : NativeSingBoxController.compileStandaloneProfile(entry, assets, entryMode);
                    graph = new JSONObject(compiled);
                }
                if ("hysteria2".equals(entryMode) || "shadowsocks".equals(entryMode)) {
                    JSONObject inline = new JSONObject(Libbox.routerCompileProxyEntry(assets.toString(), entryMode));
                    if (!entryMode.equals(inline.getString("type")) || inline.has("detour")) throw new IllegalStateException("Tor entry lost its captured transport.");
                    JSONArray outputs = graph.getJSONArray("outbounds");
                    int found = 0;
                    for (int i = 0; i < outputs.length(); i++) if ("proxy".equals(outputs.getJSONObject(i).optString("tag"))) {
                        outputs.put(i, inline.put("tag", "proxy")); found++;
                    }
                    if (found != 1) throw new IllegalStateException("Tor entry requires one captured transport owner.");
                }
                NativeSingBoxController.applySelectedDns(entry, graph);
                if (AndroidStartLayer.nativeXray(entryMode) && !AndroidNativeCompositeProfile.isMode(entryMode)) AndroidXrayLibboxPolicy.normalizeDnsRoutes(graph);
                if (!AndroidNativeMAXProfile.isMode(entryMode) && !AndroidNativeCompositeProfile.isMode(entryMode)) relay = AndroidStartLayer.apply(entry, graph, entryMode);
                graph = NativeSingBoxController.applyPerformance(entry, graph);
                predecessor = graph.toString();
            }
            String sessionId = UUID.randomUUID().toString();
            String config = Libbox.routerCompileTorProfile(capturedProfile, sessionId, predecessor);
            if (!bounded(config, MAX_CONFIG)) throw new IllegalStateException("Tor did not compile the complete captured graph.");
            RouterPQNative.install();
            Libbox.checkConfig(config);
            JSONObject metadata = new JSONObject().put("version", 1).put("session_id", sessionId)
                    .put("external_id", exit.id).put("protocol", exit.protocol).put("config_sha256", digest(config.getBytes(StandardCharsets.UTF_8)))
                    .put("entry_mode", entryFile == null ? "external" : entryMode)
                    .put("tor_profile", new JSONObject(capturedProfile));
            if (predecessorProfile != null) metadata.put("predecessor_profile", predecessorProfile);
            String metadataText = metadata.toString();
            if (!bounded(metadataText, MAX_METADATA)) throw new IllegalStateException("Tor session metadata exceeds its bound.");
            if (Thread.currentThread().isInterrupted() || !capturedExit.equals(AndroidStandardExitStore.snapshot(selected))
                    || entryFile != null && !Arrays.equals(entryBytes, AndroidPrivateFileStore.read(entryFile, AndroidNodeStore.MAX_BUNDLE))) {
                throw new IllegalStateException("Tor preparation was cancelled or a captured node changed.");
            }
            if (maxPreparation != null) maxPreparation.verify();
            File root = new File(context.getFilesDir(), "layered-sessions").getCanonicalFile();
            if (!root.isDirectory() && !root.mkdirs()) throw new IllegalStateException("Cannot create private Tor session storage.");
            File[] sessions = root.listFiles(File::isDirectory);
            if (sessions == null || sessions.length >= 32) throw new IllegalStateException("Private VPN session storage is unavailable or full.");
            File folder = new File(root, sessionId);
            if (!folder.mkdir()) throw new IllegalStateException("Cannot create the captured Tor session.");
            try {
                // Every Tor launch uses strict OS lockdown, including bootstrap.
                AndroidPrivateFileStore.write(new File(folder, AndroidKillSwitchPolicy.SESSION_MARKER), new byte[]{'1', '\n'}, 16);
                AndroidPrivateFileStore.write(new File(folder, "sing-box.json"), config.getBytes(StandardCharsets.UTF_8), MAX_CONFIG);
                AndroidPrivateFileStore.write(new File(folder, SESSION_FILE), metadataText.getBytes(StandardCharsets.UTF_8), MAX_METADATA);
                if (relay != null) AndroidPrivateFileStore.write(new File(folder, AndroidStartLayerRelay.SESSION_FILE), relay.metadata().toString().getBytes(StandardCharsets.UTF_8), 16384);
                String mode = (entryFile == null ? "standard-direct-" : "standard-") + exit.protocol;
                if (maxPreparation != null) maxPreparation.stage(folder, sessionId, mode, config);
                maxStaged = true;
                return new NativeSingBoxController.SessionInfo(sessionId, mode, maxPreparation);
            } catch (Throwable failure) {
                removeSession(folder);
                throw failure;
            }
        } finally {
            if (relay != null) relay.clear();
            if (maxPreparation != null && !maxStaged) maxPreparation.close();
        }
    }

    static JSONObject session(String config, String metadataText, String sessionId, String mode) throws Exception {
        if (!bounded(metadataText, MAX_METADATA) || !bounded(config, MAX_CONFIG)) throw new IllegalStateException("Tor session is empty or oversized.");
        JSONObject metadata = new JSONObject(metadataText), graph = new JSONObject(config);
        JSONObject capturedProfile = metadata.getJSONObject("tor_profile");
        if (!metadata.getString("external_id").equals(capturedProfile.getString("id"))
                || !metadata.getString("protocol").equals(capturedProfile.getJSONObject("external").getString("protocol")))
            throw new IllegalStateException("Tor lost its frozen selected profile.");
        if (metadata.getInt("version") != 1 || !sessionId.equals(metadata.getString("session_id"))
                || !isTor(metadata.getString("protocol")) || !mode.equals((metadata.has("predecessor_profile") ? "standard-" : "standard-direct-") + metadata.getString("protocol"))
                || !digest(config.getBytes(StandardCharsets.UTF_8)).equals(metadata.getString("config_sha256"))
                || !OUTBOUND.equals(graph.getJSONObject("route").getString("final"))) throw new IllegalStateException("Tor session identity or captured graph changed.");
        int owners = 0;
        JSONArray outputs = graph.getJSONArray("outbounds");
        for (int i = 0; i < outputs.length(); i++) {
            JSONObject output = outputs.getJSONObject(i);
            if ("routervpn-tor".equals(output.optString("type"))) {
                owners++;
                if (!OUTBOUND.equals(output.getString("tag")) || !sessionId.equals(output.getString("session_id"))
                        || output.has("detour") != metadata.has("predecessor_profile")) throw new IllegalStateException("Tor outbound lost its captured owner.");
            }
        }
        if (owners != 1 || graph.getJSONArray("inbounds").length() != 1 || !"tun".equals(graph.getJSONArray("inbounds").getJSONObject(0).getString("type"))) throw new IllegalStateException("Tor requires one owned runtime and one VPN interface.");
        return metadata;
    }

    static String summary(AndroidStandardExitStore.Entry exit) {
        return "tor".equals(exit.protocol) ? "Tor circuit • dynamic exit" : "Tor / " + exit.torTransport + " • dynamic exit";
    }
    static String strictText(byte[] bytes) throws Exception { return StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(bytes)).toString(); }
    static String digest(byte[] data) throws Exception { StringBuilder out = new StringBuilder(); for (byte value : MessageDigest.getInstance("SHA-256").digest(data)) out.append(String.format(java.util.Locale.ROOT, "%02x", value & 255)); return out.toString(); }
    private static boolean bounded(String value, int maximum) { return value != null && !value.isEmpty() && value.getBytes(StandardCharsets.UTF_8).length <= maximum; }
    private static boolean empty(String value) { return value == null || value.isEmpty(); }
    private static void removeSession(File file) { File[] children = file.listFiles(); if (children != null) for (File child : children) removeSession(child); file.delete(); }
    private AndroidTorProfile() {}
}
