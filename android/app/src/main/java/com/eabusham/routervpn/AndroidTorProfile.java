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
            "ipv6_mode", "home_lan_access", "home_lan_cidrs", "mtu_policy", "manual_mtu", "jumbo_tun", "kill_switch", "kill_switch_policy",
            "daita_enabled", "daita_rate_kbps"));

    static boolean isTor(String protocol) { return "tor".equals(protocol) || "tor-bridge".equals(protocol); }

    /** Restore the effective saved policy; opening an editor must not change it. */
    static JSONObject editorPolicy(AndroidStandardExitStore.Entry saved) throws Exception {
        if (saved == null) return new JSONObject().put("dns_mode", "home")
                .put("ipv6_mode", "on").put("home_lan_access", true);
        JSONObject policy = saved.torPolicy == null ? new JSONObject() : new JSONObject(saved.torPolicy.toString());
        AndroidExternalProtection.validate(policy);
        String mode = policy.optString("dns_mode", "");
        if (mode.isEmpty() || "home".equals(mode)) {
            policy.put("dns_mode", "home");
            String protocol = policy.optString("dns_protocol", "udp");
            if (protocol.isEmpty()) protocol = "udp";
            if ("tls".equals(protocol)) protocol = "dot";
            if ("https".equals(protocol)) protocol = "doh";
            if ("h3".equals(protocol)) protocol = "doh3";
            if (!Arrays.asList("udp", "tcp", "dot", "doh", "doh3").contains(protocol)) {
                throw new IllegalArgumentException("The saved Home DNS transport is unsupported.");
            }
            policy.put("dns_protocol", protocol);
        } else if ("rescue".equals(mode)) {
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
                {"ipv6_mode"}, {"home_lan_access", "home_lan_cidrs"}, {"mtu_policy", "manual_mtu"}, {"jumbo_tun"}}) {
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
        AndroidExternalProtection.validate(policy);
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
        // A Home-default or bounded Server-cover draft can be stored before an entry is selected.
        // This validates its exact policy without inventing a runnable graph;
        // prepare still requires the complete captured entry and live proof.
        Libbox.routerValidateTorProfile(captured);
    }

    static NativeSingBoxController.SessionInfo prepare(Context context, File entryFile,
            AndroidStandardExitStore.Entry selected, String entryMode) throws Exception {
        return prepare(context, entryFile, selected, entryMode, "local");
    }

    /** Pure compilation used by saved-path validation and actual native staging. */
    static String compileOrdinary(AndroidStandardExitStore.Entry entry, AndroidStandardExitStore.Entry exit,
            String sessionID, String execution) throws Exception {
        return ordinary(entry, exit, sessionID, execution).getString("config");
    }

    private static JSONObject ordinary(AndroidStandardExitStore.Entry selectedEntry, AndroidStandardExitStore.Entry selectedExit,
            String sessionID, String execution) throws Exception {
        AndroidStandardExitStore.Entry entry = AndroidStandardExitStore.copy(selectedEntry);
        AndroidStandardExitStore.Entry exit = AndroidStandardExitStore.copy(selectedExit);
        AndroidStandardExitStore.validate(entry);
        AndroidStandardExitStore.validate(exit);
        if (!AndroidExternalPolicy.supports(entry.protocol) || !isTor(exit.protocol) || entry.id.equals(exit.id)
                || !"local".equals(execution)) throw new IllegalArgumentException("An ordinary external entry requires a distinct Tor exit and Local execution.");
        JSONObject captured = AndroidExternalPolicy.captureTorPredecessor(entry);
        JSONObject predecessor = captured.getJSONObject("profile");
        String mode = AndroidExternalPolicy.protocol(entry.protocol);
        JSONObject selected = profile(exit).put("multihop_enabled", true).put("multihop_entry_id", entry.id)
                .put("multihop_exit_id", exit.id).put("multihop_entry_mode", mode)
                .put("multihop_exit_mode", exit.protocol).put("multihop_execution", execution);
        String source = captured.getString("config"), sourceProfile = predecessor.toString();
        String config = Libbox.routerCompileTorProfileWithExternalPredecessor(selected.toString(), sessionID, source, sourceProfile);
        if (!bounded(config, MAX_CONFIG)) throw new IllegalStateException("Tor did not compile the complete captured ordinary path.");
        JSONObject owner = null;
        JSONArray outputs = new JSONObject(config).getJSONArray("outbounds");
        for (int index = 0; index < outputs.length(); index++) if (OUTBOUND.equals(outputs.getJSONObject(index).optString("tag"))) {
            if (owner != null) throw new IllegalStateException("Tor ordinary path has more than one captured owner.");
            owner = outputs.getJSONObject(index);
        }
        if (owner == null || !sameJSON(new JSONObject(owner.getString("external_tor_profile")), selected)
                || !sameJSON(new JSONObject(owner.getString("external_predecessor_profile")), predecessor)
                || !sameJSON(new JSONObject(owner.getString("external_predecessor_config")), new JSONObject(source)))
            throw new IllegalStateException("Tor compiler changed its captured ordinary source.");
        return new JSONObject().put("config", config).put("profile", selected).put("predecessor", predecessor)
                .put("entry_mode", mode).put("predecessor_config_sha256", digest(owner.getString("external_predecessor_config").getBytes(StandardCharsets.UTF_8)));
    }

    static NativeSingBoxController.SessionInfo prepareOrdinary(Context context, AndroidStandardExitStore.Entry selectedEntry,
            AndroidStandardExitStore.Entry selectedExit, String execution) throws Exception {
        String entrySnapshot = AndroidStandardExitStore.snapshot(selectedEntry);
        String exitSnapshot = AndroidStandardExitStore.snapshot(selectedExit);
        String sessionID = UUID.randomUUID().toString();
        JSONObject captured = ordinary(selectedEntry, selectedExit, sessionID, execution);
        String config = captured.getString("config");
        JSONObject metadata = new JSONObject().put("version", 1).put("session_id", sessionID)
                .put("external_id", selectedExit.id).put("protocol", selectedExit.protocol)
                .put("config_sha256", digest(config.getBytes(StandardCharsets.UTF_8)))
                .put("entry_mode", captured.getString("entry_mode")).put("execution", execution)
                .put("tor_profile", captured.getJSONObject("profile"))
                .put("predecessor_profile", captured.getJSONObject("predecessor"))
                .put("predecessor_config_sha256", captured.getString("predecessor_config_sha256"));
        String text = metadata.toString(), mode = "standard-" + selectedExit.protocol;
        if (!bounded(text, MAX_METADATA)) throw new IllegalStateException("Tor ordinary session metadata exceeds its bound.");
        RouterPQNative.install();
        Libbox.checkConfig(config);
        session(config, text, sessionID, mode);
        if (Thread.currentThread().isInterrupted() || !entrySnapshot.equals(AndroidStandardExitStore.snapshot(selectedEntry))
                || !exitSnapshot.equals(AndroidStandardExitStore.snapshot(selectedExit))) throw new IllegalStateException("Ordinary Tor preparation was cancelled or a captured node changed.");
        File root = new File(context.getFilesDir(), "layered-sessions").getCanonicalFile();
        if (!root.isDirectory() && !root.mkdirs()) throw new IllegalStateException("Cannot create private Tor session storage.");
        File[] sessions = root.listFiles(File::isDirectory);
        if (sessions == null || sessions.length >= 32) throw new IllegalStateException("Private VPN session storage is unavailable or full.");
        File folder = new File(root, sessionID);
        if (!folder.mkdir()) throw new IllegalStateException("Cannot create the captured Tor session.");
        try {
            if (AndroidExternalProtection.torCapture(metadata)) AndroidPrivateFileStore.write(new File(folder, AndroidKillSwitchPolicy.SESSION_MARKER), new byte[]{'1', '\n'}, 16);
            AndroidPrivateFileStore.write(new File(folder, "sing-box.json"), config.getBytes(StandardCharsets.UTF_8), MAX_CONFIG);
            AndroidPrivateFileStore.write(new File(folder, SESSION_FILE), text.getBytes(StandardCharsets.UTF_8), MAX_METADATA);
            return new NativeSingBoxController.SessionInfo(sessionID, mode, null);
        } catch (Throwable failure) { removeSession(folder); throw failure; }
    }

    static NativeSingBoxController.SessionInfo prepare(Context context, File entryFile,
            AndroidStandardExitStore.Entry selected, String entryMode, String execution) throws Exception {
        AndroidStandardExitStore.Entry exit = AndroidStandardExitStore.copy(selected);
        AndroidStandardExitStore.validate(exit);
        AndroidStandardExitStore.validateExecution(exit, entryFile != null, execution);
        String capturedExit = AndroidStandardExitStore.snapshot(exit);
        JSONObject capturedSelection = profile(exit);
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
                // The entry and Tor exit share this one OS TUN. Raw protocol
                // assets may contain a different transport MTU; apply only
                // the captured entry's interface preference, leaving those
                // endpoint parameters unchanged for native validation.
                applyCapturedEntryMTU(predecessorProfile, graph);
                graph = NativeSingBoxController.applyPerformance(entry, graph);
                predecessor = graph.toString();
            }
            capturedSelection.put("multihop_enabled", predecessorProfile != null);
            if (predecessorProfile != null) {
                capturedSelection.put("multihop_entry_id", predecessorProfile.getString("id"))
                        .put("multihop_exit_id", exit.id).put("multihop_entry_mode", entryMode)
                        .put("multihop_exit_mode", exit.protocol).put("multihop_execution", execution);
            }
            String capturedProfile = capturedSelection.toString();
            String sessionId = UUID.randomUUID().toString();
            String entryProfile = predecessorProfile == null ? "" : predecessorProfile.toString();
            String config = "server".equals(execution)
                    ? Libbox.routerCompileServerTorProfileWithPredecessor(capturedProfile, sessionId, predecessor, entryProfile)
                    : Libbox.routerCompileTorProfileWithPredecessor(capturedProfile, sessionId, predecessor, entryProfile);
            if (!bounded(config, MAX_CONFIG)) throw new IllegalStateException("Tor did not compile the complete captured graph.");
            RouterPQNative.install();
            Libbox.checkConfig(config);
            JSONObject metadata = new JSONObject().put("version", 1).put("session_id", sessionId)
                    .put("external_id", exit.id).put("protocol", exit.protocol).put("config_sha256", digest(config.getBytes(StandardCharsets.UTF_8)))
                    .put("entry_mode", entryFile == null ? "external" : entryMode).put("execution", execution)
                    .put("tor_profile", new JSONObject(capturedProfile));
            if (predecessorProfile != null) metadata.put("predecessor_profile", predecessorProfile);
            if ("server".equals(execution)) metadata.put("predecessor_config_sha256", digest(predecessor.getBytes(StandardCharsets.UTF_8)));
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
                // Legacy Tor saves retain strict lockdown. Explicit protection
                // and the independent predecessor are captured together.
                if (AndroidExternalProtection.torCapture(metadata)) AndroidPrivateFileStore.write(new File(folder, AndroidKillSwitchPolicy.SESSION_MARKER), new byte[]{'1', '\n'}, 16);
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

    private static void applyCapturedEntryMTU(JSONObject entry, JSONObject graph) throws Exception {
        Object policy = entry.opt("mtu_policy");
        if (policy != null && !(policy instanceof String)) throw new IllegalArgumentException("The captured entry MTU policy must be text.");
        if (!"fixed".equals(policy) && !"manual".equals(policy)) return;
        Object value = entry.get("manual_mtu");
        if (!(value instanceof Number)) throw new IllegalArgumentException("The captured entry Fixed MTU must be an integer.");
        double mtu = ((Number) value).doubleValue();
        if (!Double.isFinite(mtu) || mtu != Math.floor(mtu) || mtu < 1280 || mtu > 9000)
            throw new IllegalArgumentException("The captured entry Fixed MTU must be between 1280 and 9000.");
        JSONArray inbounds = graph.getJSONArray("inbounds");
        if (inbounds.length() != 1 || !"tun".equals(inbounds.getJSONObject(0).optString("type")))
            throw new IllegalArgumentException("Tor requires one captured entry VPN interface.");
        inbounds.getJSONObject(0).put("mtu", (int) mtu);
    }

    static JSONObject session(String config, String metadataText, String sessionId, String mode) throws Exception {
        if (!bounded(metadataText, MAX_METADATA) || !bounded(config, MAX_CONFIG)) throw new IllegalStateException("Tor session is empty or oversized.");
        JSONObject metadata = new JSONObject(metadataText), graph = new JSONObject(config);
        AndroidExternalProtection.torCapture(metadata);
        String execution = execution(metadata);
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
            String type = output.optString("type");
            if ("routervpn-tor".equals(type) || "routervpn-server-tor".equals(type)) {
                owners++;
                if (!OUTBOUND.equals(output.getString("tag")) || !sessionId.equals(output.getString("session_id"))
                        || !type.equals("server".equals(execution) ? "routervpn-server-tor" : "routervpn-tor"))
                    throw new IllegalStateException("Tor outbound lost its captured execution owner.");
                if ("server".equals(execution)) {
                    if (output.length() != 6 || !metadata.has("predecessor_profile")
                            || !sameJSON(new JSONObject(output.getString("profile")), capturedProfile)
                            || !sameJSON(new JSONObject(output.getString("entry_profile")), metadata.getJSONObject("predecessor_profile"))
                            || !digest(output.getString("entry_config").getBytes(StandardCharsets.UTF_8)).equals(metadata.getString("predecessor_config_sha256")))
                        throw new IllegalStateException("Tor Server lost its captured entry, source or lease owner.");
                } else if (output.has("detour") != metadata.has("predecessor_profile")) {
                    throw new IllegalStateException("Tor outbound lost its captured entry owner.");
                }
                if (metadata.has("predecessor_profile") && "external".equals(metadata.getJSONObject("predecessor_profile").optString("node_kind"))) {
                    JSONObject predecessor = metadata.getJSONObject("predecessor_profile");
                    if (!"local".equals(execution) || !"custom-exit".equals(output.optString("detour"))
                            || !sameJSON(new JSONObject(output.getString("external_tor_profile")), capturedProfile)
                            || !sameJSON(new JSONObject(output.getString("external_predecessor_profile")), predecessor)
                            || !digest(output.getString("external_predecessor_config").getBytes(StandardCharsets.UTF_8)).equals(metadata.getString("predecessor_config_sha256"))
                            || !metadata.getString("entry_mode").equals(predecessor.getJSONObject("external").getString("protocol")))
                        throw new IllegalStateException("Tor ordinary path lost its captured provider source or selected mode.");
                    String expected = Libbox.routerCompileTorProfileWithExternalPredecessor(output.getString("external_tor_profile"), sessionId,
                            output.getString("external_predecessor_config"), output.getString("external_predecessor_profile"));
                    if (!sameJSON(new JSONObject(expected), graph)) throw new IllegalStateException("Tor ordinary native graph changed after capture.");
                } else if (output.has("external_tor_profile") || output.has("external_predecessor_profile") || output.has("external_predecessor_config")) {
                    throw new IllegalStateException("Tor ordinary source has no captured provider owner.");
                }
            }
        }
        if (owners != 1 || graph.getJSONArray("inbounds").length() != 1 || !"tun".equals(graph.getJSONArray("inbounds").getJSONObject(0).getString("type"))) throw new IllegalStateException("Tor requires one owned runtime and one VPN interface.");
        return metadata;
    }

    static String execution(JSONObject metadata) throws Exception {
        Object value = metadata.has("execution") ? metadata.get("execution") : "local";
        if (!(value instanceof String) || !Arrays.asList("local", "server").contains(value))
            throw new IllegalStateException("Tor requires its captured Local or Server execution.");
        JSONObject profile = metadata.getJSONObject("tor_profile");
        if (profile.has("multihop_execution") && !value.equals(profile.get("multihop_execution"))
                || "server".equals(value) && (!metadata.has("predecessor_profile") || !"server".equals(profile.opt("multihop_execution"))))
            throw new IllegalStateException("Tor execution differs from its captured profile.");
        return (String) value;
    }

    private static boolean sameJSON(Object left, Object right) throws Exception {
        if (left instanceof JSONObject && right instanceof JSONObject) {
            JSONObject a = (JSONObject) left, b = (JSONObject) right;
            if (a.length() != b.length()) return false;
            JSONArray keys = a.names();
            for (int i = 0; keys != null && i < keys.length(); i++) {
                String key = keys.getString(i);
                if (!b.has(key) || !sameJSON(a.get(key), b.get(key))) return false;
            }
            return true;
        }
        if (left instanceof JSONArray && right instanceof JSONArray) {
            JSONArray a = (JSONArray) left, b = (JSONArray) right;
            if (a.length() != b.length()) return false;
            for (int i = 0; i < a.length(); i++) if (!sameJSON(a.get(i), b.get(i))) return false;
            return true;
        }
        return left == null ? right == null : left.equals(right);
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
