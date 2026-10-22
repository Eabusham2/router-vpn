package com.eabusham.routervpn;

import io.nekohasekai.libbox.CommandServer;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterExternalProofRequest;
import io.nekohasekai.libbox.RouterHopMeasurement;
import io.nekohasekai.libbox.RouterMTU;
import io.nekohasekai.libbox.RouterMTUPlatform;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;

/** One cancellable ordinary-exit proof owned by the exact native VPN instance. */
final class AndroidExternalSession {
    interface Owner {
        boolean current(AndroidExternalSession session, CommandServer server);
        String network();
    }

    final String sessionID, externalID;
    private final String source, capture, sourceHash, configHash, entryID, entryNodeID, expectedIP, network;
    private final boolean hasEntry;
    private final String executionRequested;
    private final CommandServer server;
    private final Owner owner;
    private RouterExternalProofRequest request;
    private boolean cancelled, started, proved;
    private String result = "";

    AndroidExternalSession(JSONObject metadata, CommandServer server, Owner owner) throws Exception {
        this.sessionID = metadata.getString("session_id");
        this.externalID = metadata.getString("external_id");
        this.source = metadata.getString("source_config");
        this.capture = metadata.getString("capture_json");
        JSONObject policy = new JSONObject(metadata.getString("metadata_json"));
        this.sourceHash = policy.getString("source_sha256");
        this.configHash = policy.getString("config_sha256");
        this.entryID = policy.optString("entry_id", "");
        this.entryNodeID = policy.optString("entry_node_id", "");
        this.expectedIP = policy.getString("expected_public_ip");
        this.hasEntry = new JSONObject(capture).has("entry");
        this.executionRequested=policy.optString("execution","");
        if(!executionRequested.isEmpty()&&(!hasEntry||!java.util.Arrays.asList("local","server","auto").contains(executionRequested)))throw unavailable();
        this.server = server; this.owner = owner; this.network = owner.network();
        if (server == null || sessionID.isEmpty() || !externalID.equals(policy.getString("exit_id"))
                || hasEntry != !entryID.isEmpty() || network == null || network.isEmpty() || "[]".equals(network)) throw unavailable();
    }

    void prove() throws Exception {
        synchronized (this) {
            if (started || cancelled || !current()) throw unavailable();
            started = true;
        }
        long began = System.currentTimeMillis();
        RouterExternalProofRequest captured = Libbox.routerExternalCreateProof(server, source, capture, sessionID);
        if (captured == null) throw unavailable();
        synchronized (this) {
            request = captured;
            if (cancelled || !current()) { captured.cancel(); throw unavailable(); }
        }
        String response = captured.run();
        if (response == null || response.getBytes(StandardCharsets.UTF_8).length > 8192) throw unavailable();
        JSONObject proof = new JSONObject(response);
        if (proof.length() != (executionRequested.isEmpty()?11:12) || proof.getInt("schema") != 1 || !sessionID.equals(proof.getString("session_id"))
                || !sourceHash.equals(proof.getString("source_sha256")) || !configHash.equals(proof.getString("config_sha256"))
                || !externalID.equals(proof.getString("exit_id")) || !entryID.equals(proof.getString("entry_id"))
                || !entryNodeID.equals(proof.getString("entry_node_id"))
                || !(proof.get("dns_proven") instanceof Boolean) || !proof.getBoolean("dns_proven")
                || !(proof.get("entry_proven") instanceof Boolean) || proof.getBoolean("entry_proven") != hasEntry
                || !AndroidNumericAddress.parse(expectedIP).equals(AndroidNumericAddress.parse(proof.getString("ip")))) throw unavailable();
        if(!executionRequested.isEmpty()){
            String execution=proof.getString("execution");
            if(!java.util.Arrays.asList("local","server").contains(execution)||!"auto".equals(executionRequested)&&!executionRequested.equals(execution)
                    ||!execution.equals(captured.execution()))throw unavailable();
        }else if(proof.has("execution"))throw unavailable();
        Object time = proof.get("checked_at");
        if (!(time instanceof Number) || ((Number) time).doubleValue() != ((Number) time).longValue()) throw unavailable();
        long checked = ((Number) time).longValue();
        if (checked < began - 1000 || checked > System.currentTimeMillis() + 30000) throw unavailable();
        synchronized (this) {
            if (cancelled || !current() || !captured.healthy()) throw unavailable();
            result = response; proved = true;
        }
    }

    synchronized boolean healthy() { return proved && !cancelled && request != null && current() && request.healthy(); }

    synchronized String result(String session, String external) throws Exception {
        if (!sessionID.equals(session) || !externalID.equals(external) || !healthy()) throw unavailable();
        return result;
    }

    RouterHopMeasurement newHopMeasurement() throws Exception {
        final RouterExternalProofRequest proof;
        synchronized (this) { if (!healthy()) throw unavailable(); proof = request; }
        RouterHopMeasurement measurement = Libbox.routerExternalCreateHopMeasurement(server, proof, source, capture, sessionID);
        if (measurement == null) throw unavailable();
        final boolean owned;
        synchronized (this) { owned = request == proof && healthy(); }
        if (!owned) { measurement.close(); throw unavailable(); }
        return measurement;
    }

    synchronized JSONObject mtuProfile() throws Exception {
        if (!healthy()) throw unavailable();
        return new JSONObject(capture).getJSONObject("profile");
    }

    // The MTU platform adopts the returned handle before rechecking healthy().
    // Keeping that sole handle permits a failed native drain to be retried even
    // when Disconnect or a replacement proof wins during native construction.
    RouterMTU newMTU(RouterMTUPlatform platform) throws Exception {
        final RouterExternalProofRequest proof;
        synchronized (this) { if (!healthy()) throw unavailable(); proof = request; }
        return Libbox.newRouterExternalMTU(server, platform, proof, source, capture);
    }

    void cancel() {
        RouterExternalProofRequest captured;
        synchronized (this) { cancelled = true; proved = false; result = ""; captured = request; }
        if (captured != null) captured.cancel();
    }

    synchronized String execution(String session,String external)throws Exception {
        JSONObject proof=new JSONObject(result(session,external));
        String selected=proof.optString("execution","local");
        if(!java.util.Arrays.asList("local","server").contains(selected))throw unavailable();
        return selected;
    }

    /** Cancellation revokes results; Close separately proves relay cleanup and is retryable. */
    void close()throws Exception {
        cancel();
        final RouterExternalProofRequest captured;
        synchronized(this){captured=request;}
        if(captured!=null)captured.close();
    }

    private boolean current() { return owner.current(this, server) && network.equals(owner.network()); }
    private static IllegalStateException unavailable() {
        return new IllegalStateException("The captured external exit, entry, selected DNS or network proof is unavailable; reconnect to prove the selected path.");
    }
}
