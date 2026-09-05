package com.eabusham.routervpn;

import com.wireguard.android.backend.Tunnel;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Measures candidate node endpoint RTT through one temporary proven WireGuard
 * entry without publishing a normal Router VPN Home/session state.
 *
 * The entry is proved before and after the candidate measurements, the native
 * WG controller must remain UP throughout, and results are never written to the
 * direct-node latency cache. The caller must fully disconnect the temporary WG
 * transport before exposing any returned values to node selection UI.
 */
final class AndroidViaEntryPathMeter {
    private static final int[] PORTS = {443,8388,10443,11443,12443,13443,14443,15443,51820,51822};

    static List<AndroidTelemetry.Result> measure(
            AndroidNodeStore.Node entry,
            NativeWireGuardController wireGuard,
            List<AndroidNodeStore.Node> candidates,
            int samples) throws Exception {
        if (entry == null || entry.file == null || !entry.file.isFile()) {
            throw new IllegalArgumentException("Temporary via-entry measurement requires a stored Router VPN entry node.");
        }
        if (wireGuard == null || wireGuard.getState() != Tunnel.State.UP) {
            throw new IllegalStateException("Temporary WireGuard entry is not UP; refusing via-entry latency labels.");
        }
        if (!AndroidPathProbe.prove(entry.file, 8000)) {
            throw new IllegalStateException("Temporary WireGuard entry failed selected-entry private path proof before candidate RTT measurement.");
        }

        int count = Math.max(3, Math.min(10, samples));
        List<AndroidTelemetry.Result> out = new ArrayList<>();
        for (AndroidNodeStore.Node node : candidates) {
            if (node == null || entry.id.equals(node.id)) continue;
            if (wireGuard.getState() != Tunnel.State.UP) {
                throw new IllegalStateException("Temporary WireGuard entry stopped while measuring candidate latency; all results discarded.");
            }
            try {
                out.add(probeNode(node, count));
            } catch (Throwable ignored) {
                // One unreachable candidate does not invalidate the real routed
                // measurements from the other candidates. Zero successes does.
            }
        }

        if (wireGuard.getState() != Tunnel.State.UP) {
            throw new IllegalStateException("Temporary WireGuard entry stopped before candidate latency completed; all results discarded.");
        }
        if (!AndroidPathProbe.prove(entry.file, 8000)) {
            throw new IllegalStateException("Temporary WireGuard entry failed selected-entry private path proof after candidate RTT measurement; all results discarded.");
        }
        if (out.isEmpty()) {
            throw new IllegalStateException("No candidate node returned a live RTT through the selected temporary entry tunnel.");
        }
        Collections.sort(out, Comparator.comparingDouble(value -> value.medianMs));
        return out;
    }

    private static AndroidTelemetry.Result probeNode(AndroidNodeStore.Node node, int samples) throws Exception {
        if (node.endpoint == null || node.endpoint.trim().isEmpty()) {
            throw new IllegalArgumentException("Candidate node has no public endpoint.");
        }
        String host = endpointHost(node.endpoint);
        int port = discoverPort(host);
        List<Double> values = new ArrayList<>();
        int failed = 0;
        for (int i = 0; i < samples; i++) {
            long start = System.nanoTime();
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), 900);
                values.add((System.nanoTime() - start) / 1_000_000d);
            } catch (Exception error) {
                failed++;
            }
            if (i + 1 < samples) {
                try { Thread.sleep(20L); }
                catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw interrupted;
                }
            }
        }
        if (values.isEmpty()) throw new IllegalStateException("All live via-entry candidate probes failed.");
        Collections.sort(values);
        return new AndroidTelemetry.Result(
                node.id,
                node.name,
                round(values.get(0)),
                round(percentile(values, 0.50)),
                round(average(values)),
                round(percentile(values, 0.90)),
                round(values.get(values.size() - 1)),
                values.size(),
                failed);
    }

    private static int discoverPort(String host) throws Exception {
        Exception last = null;
        for (int port : PORTS) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), 450);
                return port;
            } catch (Exception error) {
                last = error;
            }
        }
        throw new IllegalStateException("No safe live probe port answered for via-entry candidate " + host, last);
    }

    private static String endpointHost(String endpoint) throws Exception {
        String value = endpoint == null ? "" : endpoint.trim();
        if (value.isEmpty()) throw new IllegalArgumentException("Candidate endpoint is empty.");
        if (value.contains("://")) {
            URI uri = URI.create(value);
            String host = uri.getHost();
            if (host == null || host.trim().isEmpty()) throw new IllegalArgumentException("Candidate endpoint URL has no host.");
            return host;
        }
        if (value.startsWith("[") && value.contains("]")) return value.substring(1, value.indexOf(']'));
        int colon = value.lastIndexOf(':');
        if (colon > 0 && value.indexOf(':') == colon) return value.substring(0, colon);
        return value;
    }

    private static double percentile(List<Double> sorted, double p) {
        if (sorted.size() == 1) return sorted.get(0);
        double index = (sorted.size() - 1) * p;
        int low = (int)Math.floor(index), high = (int)Math.ceil(index);
        if (low == high) return sorted.get(low);
        double weight = index - low;
        return sorted.get(low) * (1.0 - weight) + sorted.get(high) * weight;
    }

    private static double average(List<Double> values) {
        double total = 0;
        for (double value : values) total += value;
        return total / values.size();
    }

    private static double round(double value) { return Math.round(value * 1000d) / 1000d; }

    private AndroidViaEntryPathMeter() { }
}
