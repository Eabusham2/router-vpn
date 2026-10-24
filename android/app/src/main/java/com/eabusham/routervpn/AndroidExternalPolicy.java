package com.eabusham.routervpn;

import android.content.Context;
import android.util.Base64;
import io.nekohasekai.libbox.Libbox;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/** Immutable saved policy and native graph for an ordinary external exit. */
final class AndroidExternalPolicy {
    static final String SESSION_FILE = "routervpn-external-policy.json";
    static final int MAX_CONFIG = 4 * 1024 * 1024;
    static final int MAX_CAPTURE = 8 * 1024 * 1024;
    static final int MAX_METADATA = 32 * 1024 * 1024;
    private static final Set<String> POLICY = new HashSet<>(Arrays.asList(
            "dns_mode", "dns_protocol", "dns_host", "dns_port", "dns_server_name", "dns_path",
            "fastest_dns_host", "fastest_dns_latency_ms", "dns_results", "dns_bootstrap", "ipv6_mode", "home_lan_access",
            "home_lan_cidrs", "mtu_policy", "manual_mtu", "effective_mtu", "start_layer"));

    static boolean supports(String protocol) {
        return Arrays.asList("wireguard", "amneziawg", "socks5", "http", "https", "shadowsocks", "hysteria2", "openvpn").contains(protocol);
    }

    static String protocol(String value) {
        return "http".equals(value) ? "http-connect" : "https".equals(value) ? "https-connect" : value;
    }

    /** Editing preserves the complete saved selection, including measured DNS evidence. */
    static JSONObject editorPolicy(AndroidStandardExitStore.Entry entry) throws Exception {
        JSONObject result = entry == null || entry.policy == null ? new JSONObject() : copy(entry.policy);
        checkPolicy(result);
        // Missing and blank policy retain the shared Home default. Rescue is
        // available only when the saved node or the user explicitly selects it.
        if (result.optString("dns_mode", "").isEmpty()) result.put("dns_mode", "home");
        if (!result.has("ipv6_mode")) result.put("ipv6_mode", "on");
        if (!result.has("home_lan_access")) result.put("home_lan_access", true);
        if (!result.has("mtu_policy")) result.put("mtu_policy", "auto");
        return result;
    }

    static void checkPolicy(JSONObject policy) throws Exception {
        if (policy == null || !bounded(policy.toString(), MAX_CAPTURE)) throw new IllegalArgumentException("External settings are missing or oversized.");
        JSONArray keys = policy.names();
        for (int i = 0; keys != null && i < keys.length(); i++) {
            if (!POLICY.contains(keys.getString(i))) throw new IllegalArgumentException("External settings contain an unowned policy field.");
        }
        for (String key : new String[]{"dns_mode", "dns_protocol", "dns_host", "dns_server_name", "dns_path", "fastest_dns_host", "ipv6_mode", "mtu_policy", "start_layer"}) {
            if (policy.has(key) && (!(policy.get(key) instanceof String) || policy.getString(key).length() > 4096)) throw new IllegalArgumentException("External settings require a bounded text value for " + key + ".");
        }
        if (!Arrays.asList("", "home", "rescue", "custom", "fastest", "dot", "doh", "doh3").contains(policy.optString("dns_mode", ""))) throw new IllegalArgumentException("Choose the exact saved DNS policy.");
        if (!Arrays.asList("", "on", "auto", "off").contains(policy.optString("ipv6_mode", ""))) throw new IllegalArgumentException("Choose On, Auto or Off for IPv6.");
        if (policy.has("home_lan_access") && !(policy.get("home_lan_access") instanceof Boolean)) throw new IllegalArgumentException("LAN access must be explicitly On or Off.");
        if (policy.has("home_lan_cidrs") && !(policy.get("home_lan_cidrs") instanceof JSONArray)) throw new IllegalArgumentException("LAN ranges must be a captured list.");
        if (policy.has("dns_bootstrap") && !(policy.get("dns_bootstrap") instanceof JSONObject)) throw new IllegalArgumentException("DNS bootstrap must capture its server and query together.");
        if (policy.has("dns_port")) {
            Object raw = policy.get("dns_port");
            if (!(raw instanceof Number) || ((Number) raw).doubleValue() != ((Number) raw).intValue() || ((Number) raw).intValue() < 0 || ((Number) raw).intValue() > 65535) throw new IllegalArgumentException("DNS port must be an integer from 1 through 65535, or zero for the protocol default.");
        }
        if (!Arrays.asList("", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening").contains(policy.optString("start_layer", "off"))) throw new IllegalArgumentException("Choose the exact provisioned external Start Layer.");
        String mtu = policy.optString("mtu_policy", "auto");
        if (!Arrays.asList("auto", "fixed", "manual").contains(mtu)) throw new IllegalArgumentException("Choose Auto or Fixed MTU.");
        if (!"auto".equals(mtu)) {
            Object raw = policy.get("manual_mtu");
            if (!(raw instanceof Number) || ((Number) raw).doubleValue() != ((Number) raw).intValue()
                    || ((Number) raw).intValue() < 1280 || ((Number) raw).intValue() > 9000) throw new IllegalArgumentException("Fixed MTU must be an integer from 1280 to 9000.");
        }
    }

    static JSONObject profile(AndroidStandardExitStore.Entry exit) throws Exception {
        if (exit == null || !supports(exit.protocol)) throw new IllegalArgumentException("Choose an ordinary native external exit.");
        JSONObject policy = exit.policy == null ? new JSONObject() : copy(exit.policy);
        checkPolicy(policy);
        AndroidStandardExitStore.validateStartLayer(exit);
        // The entry supplies Home's private resolver identity during native
        // composition. Its independent DNS selection cannot replace this exit's.
        if (!policy.has("ipv6_mode")) policy.put("ipv6_mode", "on");
        policy.remove("dns_bootstrap");
        policy.remove("effective_mtu"); // Historical measurements never size this new path.
        for (String field : new String[]{"dns_host", "fastest_dns_host"}) {
            String address = policy.optString(field, "");
            if (address.contains(":")) policy.put(field, AndroidNumericAddress.canonical(address));
        }
        JSONObject ext = new JSONObject().put("protocol", protocol(exit.protocol)).put("expected_public_ip", exit.expectedPublicIp);
        if(exit.responseProbe!=null&&exit.responseProbe.length()!=0)ext.put("response_probe",copy(exit.responseProbe));
        if(exit.startLayer!=null)ext.put("start_layer",copy(exit.startLayer));
        JSONObject transport;
        switch (exit.protocol) {
            case "wireguard": case "amneziawg":
                transport = new JSONObject().put("private_key", exit.wgPrivateKey).put("addresses", new JSONArray(exit.wgAddresses))
                        .put("peer_public_key", exit.wgPeerPublicKey).put("allowed_ips", new JSONArray(exit.wgAllowedIps))
                        .put("endpoint", (exit.server.contains(":") ? "[" + exit.server + "]" : exit.server) + ":" + exit.serverPort);
                if (!exit.wgPreSharedKey.isEmpty()) transport.put("preshared_key", exit.wgPreSharedKey);
                if (exit.wgMtu != 0) transport.put("mtu", exit.wgMtu);
                if (exit.wgKeepalive != null) transport.put("persistent_keepalive_interval",exit.wgKeepalive);
                if (!exit.wgDns.isEmpty()) transport.put("dns",new JSONArray(exit.wgDns));
                if ("amneziawg".equals(exit.protocol)) transport.put("parameters",AndroidExternalAmnezia.parameters(exit.awgParameters));
                ext.put(exit.protocol, transport); break;
            case "socks5": case "http": case "https":
                transport = new JSONObject().put("host", exit.server).put("port", exit.serverPort);
                if (!exit.username.isEmpty()) transport.put("username", exit.username).put("password", exit.password);
                if ("https".equals(exit.protocol)) transport.put("tls_server_name", exit.tlsServerName);
                ext.put(protocol(exit.protocol).replace('-', '_'), transport); break;
            case "shadowsocks":
                ext.put("shadowsocks", new JSONObject().put("server", exit.server).put("port", exit.serverPort).put("method", exit.method).put("password", exit.secret)); break;
            case "hysteria2":
                ext.put("hysteria2", new JSONObject().put("server", exit.server).put("port", exit.serverPort).put("password", exit.secret).put("tls_server_name", exit.tlsServerName)); break;
            case "openvpn":
                // Capture the original inline profile, including its complete
                // remote/TLS list. The shared compiler revalidates the exact
                // native endpoint; credentials retain intentional whitespace.
                ext.put("openvpn", new JSONObject().put("config", exit.openVPNConfig)
                        .put("username", exit.username).put("password", exit.password)); break;
            default: throw new IllegalArgumentException("Unowned external transport.");
        }
        return policy.put("id", exit.id).put("node_kind", "external").put("external", ext);
    }

    static final class Compiled {
        final String source, capture, config, metadataText;
        final JSONObject metadata;
        Compiled(String source, String capture) throws Exception {
            if (!bounded(source, MAX_CONFIG) || !bounded(capture, MAX_CAPTURE)) throw new IllegalArgumentException("External policy inputs exceed their bounds.");
            String encoded = Libbox.routerCompileExternalPolicy(source, capture);
            if (!bounded(encoded, MAX_METADATA)) throw new IllegalStateException("External policy compiler returned no bounded graph.");
            JSONObject envelope = new JSONObject(encoded);
            if (envelope.length() != 4 || envelope.getInt("schema") != 1) throw new IllegalStateException("External policy compiler envelope is invalid.");
            this.source = source; this.capture = capture;
            this.config = envelope.getString("config_json"); this.metadataText = envelope.getString("metadata_json");
            this.metadata = new JSONObject(metadataText);
            if (!bounded(config, MAX_CONFIG) || !bounded(metadataText, MAX_CAPTURE)
                    || metadata.getInt("schema") != 1 || !metadata.getString("source_sha256").matches("[0-9a-f]{64}")
                    || !metadata.getString("source_sha256").equals(envelope.getString("source_sha256"))
                    || !digest(config).equals(metadata.getString("config_sha256"))
                    || !"required".equals(metadata.getString("dns_proof")) || !"required".equals(metadata.getString("public_exit_proof"))) {
                throw new IllegalStateException("External policy compiler lost the captured graph or required proofs.");
            }
            JSONObject selected = new JSONObject(capture);
            if (!selected.getString("exit_id").equals(metadata.getString("exit_id"))
                    || !selected.getString("protocol").equals(metadata.getString("protocol"))
                    || !selected.getString("expected_public_ip").equals(metadata.getString("expected_public_ip"))) throw new IllegalStateException("External policy belongs to another saved exit.");
            JSONObject plan=selected.optJSONObject("execution");
            if(plan!=null){
                String requested=plan.getString("selection");
                if(!Arrays.asList("local","server","auto").contains(requested)||!requested.equals(metadata.optString("execution"))
                        ||!"https-response-time".equals(metadata.optString("last_node_measurement"))||!Arrays.asList("shadowsocks","hysteria2","socks5","http-connect","https-connect").contains(selected.getString("protocol"))||!selected.has("entry"))throw new IllegalStateException("External execution belongs to another captured path.");
            }else if(selected.has("execution")||metadata.has("execution")||metadata.has("last_node_measurement"))throw new IllegalStateException("External execution has no captured native owner.");
        }
    }

    /** Pure shipping graph builder; tests call the same Java and Go compilers. */
    static Compiled compile(AndroidStandardExitStore.Entry exit, JSONObject entry, String entryMode) throws Exception {
        return compile(exit,entry,entryMode,null);
    }

    static Compiled compile(AndroidStandardExitStore.Entry exit, JSONObject entry, String entryMode, AndroidExternalEntry captured) throws Exception {
        return compile(exit,entry,entryMode,captured,"local","");
    }

    static Compiled compile(AndroidStandardExitStore.Entry exit, JSONObject entry, String entryMode, AndroidExternalEntry captured, String execution, String restoredExecution) throws Exception {
        Captured input=capture(exit,entry,entryMode,captured,execution);
        String frozen=Libbox.routerPrepareExternalExecutionCapture(input.source,input.capture,restoredExecution);
        return new Compiled(input.source,frozen);
    }

    /** Idle validation keeps unresolved Home intent and grants no runnable graph or proof. */
    static void validateDraft(AndroidStandardExitStore.Entry selected)throws Exception{
        AndroidStandardExitStore.Entry exit=AndroidStandardExitStore.copy(selected);
        Captured input=capture(exit,null,"external",null,"local");
        JSONObject selectedCapture=new JSONObject(input.capture),profile=selectedCapture.getJSONObject("profile");
        if(selectedCapture.has("dns_bootstrap"))profile.put("dns_bootstrap",selectedCapture.getJSONObject("dns_bootstrap"));
        Libbox.routerValidateExternalTransport(input.source,input.capture);
        Libbox.routerValidateExternalDNS(profile.toString(),"");
        if(exit.responseProbe.length()!=0)Libbox.routerValidateExternalResponseProbe(exit.server,exit.responseProbe.toString());
    }

    private static final class Captured {
        final String source,capture;
        Captured(String source,String capture){this.source=source;this.capture=capture;}
    }

    private static Captured capture(AndroidStandardExitStore.Entry exit,JSONObject entry,String entryMode,AndroidExternalEntry captured,String execution)throws Exception{
        AndroidStandardExitStore.validate(exit);
        AndroidStandardExitStore.validateExecution(exit,entry!=null,execution);
        JSONArray endpoints = new JSONArray(), outbounds = new JSONArray();
        JSONObject predecessor = null;
        String entryTag = "";
        if (entry != null) {
            if (captured==null&&!"wg".equals(entryMode)) throw new IllegalArgumentException("The selected entry requires its complete native graph capture.");
            AndroidNodeStore.validateBundle(entry);
            String selectedID = entry.optString("selectedRouterID", entry.optString("selected_id", ""));
            if (selectedID.isEmpty()) throw new IllegalArgumentException("Select the exact Router VPN entry profile before connecting.");
            predecessor = copy(AndroidProfileSelection.selectedRouterProfile(entry));
            String node = AndroidNodeStore.stableNodeIdentity(entry);
            if (!node.matches("[0-9a-f]{64}") || !node.equals(predecessor.optString("node_proof_id"))) throw new IllegalArgumentException("The entry lost its captured node identity.");
            if(captured!=null){
                if(!predecessor.toString().equals(captured.profile.toString()))throw new IllegalStateException("The compiled entry belongs to a different frozen profile.");
                entryTag="external-entry";
            }else{
                String start = AndroidStartLayer.selectedMode(entry);
                if (!"off".equals(start)) throw new IllegalArgumentException("The selected Start Layer must be compiled into the complete external entry graph.");
                String encoded = entry.getJSONObject("profiles").getJSONObject(entryMode).getString("wg.conf");
                byte[] wg = Base64.decode(encoded, Base64.DEFAULT);
                if (wg.length == 0 || wg.length > 1024 * 1024) throw new IllegalArgumentException("The captured WireGuard profile is empty or oversized.");
                JSONObject parsed = new JSONObject(Libbox.routerCompileWireGuardProfile(AndroidTorProfile.strictText(wg), node));
                entryTag = "entry-wg";
                endpoints.put(parsed.getJSONObject("endpoint").put("tag", entryTag));
            }
        }else if(captured!=null){
            throw new IllegalArgumentException("A predecessor graph has no captured entry profile.");
        }
        JSONObject transport = AndroidDirectStandardExitController.customExitJson(exit);
        if (!entryTag.isEmpty()&&captured==null) transport.put("detour", entryTag);
        if ("wireguard".equals(exit.protocol) || "amneziawg".equals(exit.protocol) || "openvpn".equals(exit.protocol)) endpoints.put(transport); else outbounds.put(transport);
        JSONObject source = new JSONObject().put("log", new JSONObject().put("level", "warn"))
                .put("inbounds", new JSONArray().put(new JSONObject().put("type", "tun").put("tag", "tun-in")
                        .put("address", new JSONArray().put("172.29.93.1/30").put("fd29:93::1/126"))
                        .put("mtu", 1280).put("auto_route", true).put("strict_route", true).put("stack", "system")))
                .put("endpoints", endpoints).put("outbounds", outbounds)
                .put("route", new JSONObject().put("final", "custom-exit").put("auto_detect_interface", true));
        JSONObject capture = new JSONObject().put("schema", 1).put("exit_id", exit.id).put("protocol", protocol(exit.protocol))
                .put("expected_public_ip", exit.expectedPublicIp).put("profile", profile(exit));
        if (predecessor != null) {
            capture.put("entry", predecessor).put("entry_tag", entryTag);
            capture.getJSONObject("profile").put("multihop_enabled",true).put("multihop_entry_id",predecessor.getString("id"))
                    .put("multihop_exit_id",exit.id).put("multihop_exit_mode",protocol(exit.protocol)).put("multihop_execution",execution);
        }
        if (captured != null) capture.put("predecessor_config",captured.config);
        JSONObject policy = exit.policy;
        if (policy != null && policy.has("dns_bootstrap")) capture.put("dns_bootstrap", policy.getJSONObject("dns_bootstrap"));
        return new Captured(source.toString(),capture.toString());
    }

    static NativeSingBoxController.SessionInfo prepare(Context context, File entryFile, AndroidStandardExitStore.Entry selected, String entryMode) throws Exception {
        return prepare(context,entryFile,selected,entryMode,"local","");
    }

    static NativeSingBoxController.SessionInfo prepare(Context context, File entryFile, AndroidStandardExitStore.Entry selected, String entryMode, String execution, String restoredExecution) throws Exception {
        AndroidStandardExitStore.Entry exit = AndroidStandardExitStore.copy(selected);
        String exitSnapshot = AndroidStandardExitStore.snapshot(selected);
        byte[] entryBytes = entryFile == null ? null : AndroidPrivateFileStore.read(entryFile, AndroidNodeStore.MAX_BUNDLE);
        JSONObject entry = entryBytes == null ? null : new JSONObject(AndroidTorProfile.strictText(entryBytes));
        try(AndroidExternalEntry predecessor=entry==null?null:AndroidExternalEntry.prepare(context,entryFile,entry,entryMode)){
        Compiled compiled = compile(exit, entry, entryMode,predecessor,execution,restoredExecution);
        RouterPQNative.install();
        Libbox.checkConfig(compiled.config);
        String sessionId = UUID.randomUUID().toString();
        JSONObject metadata = new JSONObject().put("version", 1).put("session_id", sessionId).put("external_id", exit.id)
                .put("protocol", exit.protocol).put("entry_mode", entryFile == null ? "external" : entryMode)
                .put("source_config", compiled.source).put("capture_json", compiled.capture).put("metadata_json", compiled.metadataText);
        if (Thread.currentThread().isInterrupted() || !exitSnapshot.equals(AndroidStandardExitStore.snapshot(selected))
                || entryFile != null && !Arrays.equals(entryBytes, AndroidPrivateFileStore.read(entryFile, AndroidNodeStore.MAX_BUNDLE))) {
            throw new IllegalStateException("External preparation was cancelled or its captured selection changed.");
        }
        String text = metadata.toString();
        if (!bounded(text, MAX_METADATA)) throw new IllegalStateException("Captured external session exceeds its private storage bound.");
        File root = new File(context.getFilesDir(), "layered-sessions").getCanonicalFile();
        if (!root.isDirectory() && !root.mkdirs()) throw new IllegalStateException("Cannot create external session storage.");
        File[] sessions = root.listFiles(File::isDirectory);
        if (sessions == null || sessions.length >= 32) throw new IllegalStateException("Private VPN session storage is unavailable or full.");
        File folder = new File(root, sessionId);
        if (!folder.mkdir()) throw new IllegalStateException("Cannot create the captured external session.");
        try {
            if (entry == null || AndroidKillSwitchPolicy.strictRequested(entry)) AndroidPrivateFileStore.write(new File(folder, AndroidKillSwitchPolicy.SESSION_MARKER), new byte[]{'1', '\n'}, 16);
            AndroidPrivateFileStore.write(new File(folder, "sing-box.json"), compiled.config.getBytes(StandardCharsets.UTF_8), MAX_CONFIG);
            AndroidPrivateFileStore.write(new File(folder, SESSION_FILE), text.getBytes(StandardCharsets.UTF_8), MAX_METADATA);
            String mode=(entry == null ? "standard-direct-" : "standard-") + exit.protocol;
            if(predecessor!=null)predecessor.stage(folder,sessionId,mode,compiled.config);
            return new NativeSingBoxController.SessionInfo(sessionId,mode,predecessor==null?null:predecessor.maxPreparation);
        } catch (Throwable failure) { removeSession(folder); throw failure; }
        }
    }

    static JSONObject session(String config, String text, String sessionID, String mode) throws Exception {
        if (!bounded(text, MAX_METADATA) || !bounded(config, MAX_CONFIG)) throw new IllegalStateException("External session is empty or oversized.");
        JSONObject metadata = new JSONObject(text);
        if (metadata.length() != 8 || metadata.getInt("version") != 1 || !sessionID.equals(metadata.getString("session_id"))
                || !supports(metadata.getString("protocol"))) throw new IllegalStateException("The captured external session identity changed.");
        Compiled compiled = new Compiled(metadata.getString("source_config"), metadata.getString("capture_json"));
        boolean hasEntry = new JSONObject(compiled.capture).has("entry");
        if (!config.equals(compiled.config) || !compiled.metadataText.equals(metadata.getString("metadata_json"))
                || !compiled.metadata.getString("exit_id").equals(metadata.getString("external_id"))
                || !mode.equals((hasEntry ? "standard-" : "standard-direct-") + metadata.getString("protocol"))
                || !hasEntry && !"external".equals(metadata.getString("entry_mode"))) throw new IllegalStateException("External policy or graph changed after capture.");
        return metadata;
    }

    static String digest(String text) throws Exception { return AndroidTorProfile.digest(text.getBytes(StandardCharsets.UTF_8)); }
    static String entryDigest(File file) throws Exception {
        if (file == null) throw new IllegalArgumentException("Select the captured Router VPN entry.");
        return AndroidTorProfile.digest(AndroidPrivateFileStore.read(file, AndroidNodeStore.MAX_BUNDLE));
    }
    private static JSONObject copy(JSONObject value) throws Exception { return new JSONObject(value.toString()); }
    private static boolean bounded(String text, int max) { return text != null && !text.isEmpty() && text.getBytes(StandardCharsets.UTF_8).length <= max; }
    private static void removeSession(File file) { File[] children = file.listFiles(); if (children != null) for (File child : children) removeSession(child); file.delete(); }
    private AndroidExternalPolicy() {}
}
