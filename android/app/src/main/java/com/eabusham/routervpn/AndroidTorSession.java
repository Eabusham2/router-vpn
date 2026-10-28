package com.eabusham.routervpn;

import io.nekohasekai.libbox.CommandServer;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterTorProofRequest;
import io.nekohasekai.libbox.RouterHopMeasurement;
import io.nekohasekai.libbox.RouterDNSMeasurement;
import io.nekohasekai.libbox.RouterMTU;
import io.nekohasekai.libbox.RouterMTUPlatform;
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
    private final String predecessor, network, config, profile, execution;
    private final CommandServer server;
    private final Owner owner;
    private final AndroidTorPaddingReceipt padding;
    private RouterTorProofRequest request;
    private boolean cancelled, proved, started;
    private String result = "";

    AndroidTorSession(JSONObject metadata, String config, CommandServer server, Owner owner) throws Exception {
        this.sessionID = metadata.getString("session_id");
        this.externalID = metadata.getString("external_id");
        this.config = config;
        this.profile = metadata.getJSONObject("tor_profile").toString();
        this.execution = AndroidTorProfile.execution(metadata);
        if (config == null || config.isEmpty() || !externalID.equals(new JSONObject(profile).getString("id"))) throw unavailable();
        this.padding = new AndroidTorPaddingReceipt(config, profile, sessionID, execution);
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
        final boolean admitted;
        synchronized (this) {
            request = captured;
            admitted = !cancelled && current();
        }
        if (!admitted) { captured.cancel(); captured.close(); throw unavailable(); }
        try {
            proveCaptured(captured, began);
        } catch (Exception invalid) {
            rejectCaptured(captured);
            throw invalid;
        }
    }

    private void proveCaptured(RouterTorProofRequest captured, Instant began) throws Exception {
        String response = captured.run();
        if (response == null || response.getBytes(StandardCharsets.UTF_8).length > 4096) throw unavailable();
        JSONObject proof = new JSONObject(response);
        if (proof.length() != 5 || !sessionID.equals(proof.getString("session_id"))
                || !(proof.get("dns_proven") instanceof Boolean) || !proof.getBoolean("dns_proven")
                || !(proof.get("is_tor") instanceof Boolean) || !proof.getBoolean("is_tor")) throw unavailable();
        InetAddress address = AndroidNumericAddress.parse(proof.getString("ip"));
        byte[] bytes = address.getAddress();
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()
                || bytes.length == 16 && (bytes[0] & 0xfe) == 0xfc
                || bytes.length == 4 && ((bytes[0] & 255) == 0 || (bytes[0] & 255) >= 224)) throw unavailable();
        Instant checked = Instant.parse(proof.getString("checked_at"));
        if (checked.isBefore(began.minusSeconds(1)) || checked.isAfter(Instant.now().plusSeconds(30))) throw unavailable();
        synchronized (this) { if (cancelled || !current() || !captured.healthy()) throw unavailable(); padding.accept(captured.paddingStatusJSON(),System.currentTimeMillis()); }
        // This uncached request uses the exact Box's selected DNS router. The
        // Tor request remains cancellable while the DNS traffic is in flight.
        Libbox.routerStrategyDNSProof(server);
        synchronized (this) {
            if (cancelled || !current() || !captured.healthy()) throw unavailable();
            padding.accept(captured.paddingStatusJSON(),System.currentTimeMillis());
            result = response;
            proved = true;
        }
    }

    boolean healthy() {
        final RouterTorProofRequest captured;
        synchronized (this) {
            if (!proved || cancelled || request == null) return false;
            captured = request;
            try {
                if (!current() || !captured.healthy()) throw unavailable();
                // Keep these memory-only native reads serialized so concurrent
                // health callers cannot adopt a newer receipt before an older one.
                padding.accept(captured.paddingStatusJSON(), System.currentTimeMillis());
                return true;
            } catch (Exception invalid) {
                cancelled = true;
                proved = false;
                result = "";
            }
        }
        // Native data revocation is immediate and outside the session monitor.
        captured.cancel();
        return false;
    }

    /** Revoke this exact native data owner immediately. Its separate Close
     * retains and joins workers; cancellation never runs under this monitor. */
    private void rejectCaptured(RouterTorProofRequest captured) {
        synchronized (this) {
            if (request != captured || cancelled) return;
            cancelled = true;
            proved = false;
            result = "";
        }
        captured.cancel();
    }

    private synchronized RouterTorProofRequest provedRequest() throws Exception {
        if (!proved || cancelled || request == null || !current()) throw unavailable();
        return request;
    }

    String result(String session, String external) throws Exception {
        if (!sessionID.equals(session) || !externalID.equals(external) || !healthy()) throw unavailable();
        synchronized (this) {
            provedRequest();
            return result;
        }
    }

    String execution(String session, String external) throws Exception {
        result(session, external);
        return execution;
    }

    RouterHopMeasurement newHopMeasurement() throws Exception {
        if (!healthy()) throw unavailable();
        final RouterTorProofRequest proof = provedRequest();
        RouterHopMeasurement measurement = Libbox.routerTorCreateHopMeasurement(server, proof, externalID);
        if (measurement == null) throw unavailable();
        boolean owned = healthy();
        synchronized (this) { owned = owned && request == proof && proved && !cancelled && current(); }
        if (!owned) { measurement.close(); throw unavailable(); }
        return measurement;
    }

    RouterDNSMeasurement newDNSMeasurement() throws Exception {
        if (!healthy()) throw unavailable();
        final RouterTorProofRequest proof = provedRequest();
        RouterDNSMeasurement measurement = Libbox.routerTorCreateDNSMeasurement(server, proof, externalID);
        if (measurement == null) throw unavailable();
        boolean dnsOwned = healthy();
        synchronized (this) { dnsOwned = dnsOwned && request == proof && proved && !cancelled && current(); }
        if (!dnsOwned) { measurement.close(); throw unavailable(); }
        return measurement;
    }

    JSONObject mtuProfile() throws Exception {
        if (!healthy()) throw unavailable();
        synchronized (this) {
            provedRequest();
            return new JSONObject(profile);
        }
    }

    RouterMTU newMTU(RouterMTUPlatform platform) throws Exception {
        if (!healthy()) throw unavailable();
        final RouterTorProofRequest proof = provedRequest();
        // The MTU adapter first adopts this handle, then rechecks ownership and
        // retains it if its drain fails. Never abandon a late constructor here.
        RouterMTU mtu = Libbox.newRouterTorMTU(server, platform, proof, config, profile);
        if (mtu == null) throw unavailable();
        return mtu;
    }

    void cancel() {
        RouterTorProofRequest captured;
        synchronized (this) { cancelled = true; proved = false; result = ""; captured = request; }
        if (captured != null) captured.cancel();
    }

    /** Keep the captured native entry until padding workers drain and, for
     * Server execution, the owned lease acknowledges DELETE. */
    void close() throws Exception {
        cancel();
        final RouterTorProofRequest captured;
        synchronized (this) { captured = request; }
        if (captured != null) captured.close();
    }

    synchronized boolean retainsServerCleanup(CommandServer nativeServer) {
        return cancelled && !proved && request != null && server == nativeServer && "server".equals(execution);
    }

    synchronized boolean dataCancelled() { return cancelled; }

    private boolean current() { return owner.current(this, server) && network.equals(owner.network()); }
    private static IllegalStateException unavailable() { return new IllegalStateException("The captured Tor circuit, entry proof, DNS or network owner is unavailable; reconnect to prove the path."); }
}
