package com.eabusham.routervpn;

import android.content.Context;

import com.wireguard.android.backend.Tunnel;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Temporary, fail-closed pre-connect multihop measurement.
 *
 * It establishes the selected Router VPN entry with the real native WireGuard
 * backend in managed-child mode, proves that entry without publishing a normal
 * Home Connected session, measures candidate public endpoints through the live
 * full-device route, and fully disconnects the temporary entry before returning
 * any values to the picker. Results never enter the direct-node RTT cache.
 */
final class AndroidViaEntryLatencyProbe {
    interface Callback {
        void progress(String message);
        void finished(AndroidNodeStore.Node entry, List<AndroidTelemetry.Result> values, Throwable error);
    }

    private final Context context;
    private final NativeWireGuardController wireGuard;
    private final AndroidRuntimeRegistry runtime;
    private final AtomicBoolean busy = new AtomicBoolean(false);

    AndroidViaEntryLatencyProbe(Context context, AndroidRuntimeRegistry runtime, AndroidTelemetry telemetry) {
        this.context = context.getApplicationContext();
        this.runtime = runtime;
        this.wireGuard = runtime.wireGuard;
        // Keep the constructor shape stable for the shipping ProductActivity.
        // Via-entry measurements deliberately bypass AndroidTelemetry's direct
        // RTT cache and use AndroidViaEntryPathMeter instead.
        if (telemetry == null) throw new IllegalArgumentException("Android telemetry owner is required.");
    }

    boolean isBusy() { return busy.get(); }

    void measure(AndroidNodeStore.Node entry, List<AndroidNodeStore.Node> candidates, int samples, Callback callback) {
        if (entry == null) { callback.finished(null, null, new IllegalArgumentException("Choose a multihop entry first.")); return; }
        if (candidates == null || candidates.isEmpty()) { callback.finished(entry, null, new IllegalArgumentException("No candidate exits are available.")); return; }
        if (!busy.compareAndSet(false, true)) { callback.finished(entry, null, new IllegalStateException("A via-entry latency measurement is already running.")); return; }
        AndroidHomeStateStore.Snapshot home = AndroidHomeStateStore.snapshot(context);
        if (home.connected || "connecting".equals(home.phase) || runtime.orchestrator.isRunning() || runtime.multihop.isActiveOrTransitioning()
                || "UP".equals(runtime.singBox.getState()) || "STARTING".equals(runtime.singBox.getState())
                || "UP".equals(runtime.xray.getState()) || "STARTING".equals(runtime.xray.getState())
                || wireGuard.getState() != Tunnel.State.DOWN) {
            busy.set(false);
            callback.finished(entry, null, new IllegalStateException("Disconnect the current Router VPN session before measuring via-entry candidate latency."));
            return;
        }
        List<AndroidNodeStore.Node> safeCandidates = new ArrayList<>();
        for (AndroidNodeStore.Node node : candidates) if (node != null && !entry.id.equals(node.id)) safeCandidates.add(node);
        if (safeCandidates.isEmpty()) {
            busy.set(false);
            callback.finished(entry, null, new IllegalArgumentException("No different candidate exits are available."));
            return;
        }
        callback.progress("Connecting temporary proven WireGuard entry " + entry.name + " for live via-entry RTT…");
        wireGuard.connectManaged(entry.file, (state, message, error) -> {
            if (error != null || state != Tunnel.State.UP) {
                busy.set(false);
                callback.finished(entry, null, error != null ? error : new IllegalStateException(message));
                return;
            }

            List<AndroidTelemetry.Result> values = null;
            Throwable measureError = null;
            try {
                callback.progress("Entry proof passed; measuring " + safeCandidates.size() + " candidate exit(s) through " + entry.name + "…");
                values = AndroidViaEntryPathMeter.measure(entry, wireGuard, safeCandidates, samples);
            } catch (Throwable failure) {
                measureError = failure;
            }

            final List<AndroidTelemetry.Result> measured = values;
            final Throwable measurementFailure = measureError;
            callback.progress("Candidate RTT measurement complete; disconnecting temporary entry before showing results…");
            wireGuard.disconnectManaged((downState, downMessage, downError) -> {
                busy.set(false);
                if (downError != null || downState != Tunnel.State.DOWN) {
                    callback.finished(entry, null, downError != null ? downError : new IllegalStateException("Temporary entry did not fully disconnect; candidate results discarded."));
                    return;
                }
                if (measurementFailure != null) {
                    callback.finished(entry, null, measurementFailure);
                    return;
                }
                callback.finished(entry, measured, null);
            });
        });
    }
}
