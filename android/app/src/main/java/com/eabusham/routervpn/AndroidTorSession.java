package com.eabusham.routervpn;

import io.nekohasekai.libbox.CommandServer;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterTorProofRequest;
import io.nekohasekai.libbox.RouterHopMeasurement;
import org.json.JSONObject;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

/** One service-owned Tor proof, bound to a captured native instance and network. */
final class AndroidTorSession {
    interface Owner {
        boolean current(AndroidTorSession session, CommandServer server);
        String network();
    }

    final String sessionID, externalID;
    private final String predecessor, network;
    private final CommandServer server;
    private final Owner owner;
    private RouterTorProofRequest request;
    private boolean cancelled, proved, started;
    private String result = "";

    AndroidTorSession(JSONObject metadata, CommandServer server, Owner owner) throws Exception {
        this.sessionID = metadata.getString("session_id");
        this.externalID = metadata.getString("external_id");
        this.predecessor = metadata.has("predecessor_profile") ? metadata.getJSONObject("predecessor_profile").toString() : "";
        this.server = server;
        this.owner = owner;
        this.network = owner.network();
        if (server == null || network == null || network.isEmpty() || "[]".equals(network)) throw unavailable();
    }

    void prove() throws Exception {
        synchronized (this) {
            if (started || cancelled || !current()) throw unavailable();
            started = true;
        }
        Instant began = Instant.now();
        RouterTorProofRequest captured = predecessor.isEmpty()
                ? Libbox.routerTorCreateProof(server, AndroidTorProfile.OUTBOUND, sessionID)
                : Libbox.routerTorCreateProofWithPredecessor(server, AndroidTorProfile.OUTBOUND, sessionID, predecessor);
        if (captured == null) throw unavailable();
        synchronized (this) {
            request = captured;
            if (cancelled || !current()) { captured.cancel(); throw unavailable(); }
        }
        String response = captured.run();
        if (response == null || response.getBytes(StandardCharsets.UTF_8).length > 4096) throw unavailable();
        JSONObject proof = new JSONObject(response);
        if (proof.length() != 4 || !sessionID.equals(proof.getString("session_id"))
                || !(proof.get("is_tor") instanceof Boolean) || !proof.getBoolean("is_tor")) throw unavailable();
        InetAddress address = AndroidNumericAddress.parse(proof.getString("ip"));
        byte[] bytes = address.getAddress();
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()
                || bytes.length == 16 && (bytes[0] & 0xfe) == 0xfc
                || bytes.length == 4 && ((bytes[0] & 255) == 0 || (bytes[0] & 255) >= 224)) throw unavailable();
        Instant checked = Instant.parse(proof.getString("checked_at"));
        if (checked.isBefore(began.minusSeconds(1)) || checked.isAfter(Instant.now().plusSeconds(30))) throw unavailable();
        synchronized (this) { if (cancelled || !current() || !captured.healthy()) throw unavailable(); }
        // This uncached request uses the exact Box's selected DNS router. The
        // Tor request remains cancellable while the DNS traffic is in flight.
        Libbox.routerStrategyDNSProof(server);
        synchronized (this) {
            if (cancelled || !current() || !captured.healthy()) throw unavailable();
            result = response;
            proved = true;
        }
    }

    synchronized boolean healthy() { return proved && !cancelled && request != null && current() && request.healthy(); }

    synchronized String result(String session, String external) throws Exception {
        if (!sessionID.equals(session) || !externalID.equals(external) || !healthy()) throw unavailable();
        return result;
    }

    RouterHopMeasurement newHopMeasurement() throws Exception {
        final RouterTorProofRequest proof;
        synchronized (this) { if (!healthy()) throw unavailable(); proof = request; }
        RouterHopMeasurement measurement = Libbox.routerTorCreateHopMeasurement(server, proof, externalID);
        if (measurement == null) throw unavailable();
        final boolean owned;
        synchronized (this) { owned = request == proof && healthy(); }
        if (!owned) { measurement.close(); throw unavailable(); }
        return measurement;
    }

    void cancel() {
        RouterTorProofRequest captured;
        synchronized (this) { cancelled = true; proved = false; result = ""; captured = request; }
        if (captured != null) captured.cancel();
    }

    private boolean current() { return owner.current(this, server) && network.equals(owner.network()); }
    private static IllegalStateException unavailable() { return new IllegalStateException("The captured Tor circuit, entry proof, DNS or network owner is unavailable; reconnect to prove the path."); }
}
