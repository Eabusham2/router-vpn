package com.eabusham.routervpn;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.DnsResolver;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.CancellationSignal;
import io.nekohasekai.libbox.RouterMAXEndpointResolver;
import org.json.JSONArray;
import org.json.JSONObject;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** One physical-network lookup. Application DNS remains inside the final VPN.
 * The system resolver keeps strict/opportunistic Private DNS semantics. Our
 * barrier joins the app's query/cancellation callbacks and legacy worker; it
 * does not claim ownership of Android's internal resolver service workers. */
final class AndroidMAXDNSOwner implements RouterMAXEndpointResolver, AutoCloseable {
    interface Current { boolean current(); }

    /** Immutable, socket-free network evidence, retained through native start. */
    static final class Physical {
        final ConnectivityManager connectivity;
        final Network network;
        final String snapshot;
        final String digest;

        Physical(Context context) throws Exception {
            connectivity = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (connectivity == null) throw unavailable();
            network = connectivity.getActiveNetwork();
            if (!physical(connectivity, network)) throw unavailable();
            snapshot = snapshot(connectivity);
            if (snapshot.isEmpty()) throw unavailable();
            digest = sha256(snapshot);
            if (!current(false)) throw unavailable();
        }

        boolean current(boolean vpnStarted) {
            try {
                if (!physical(connectivity, network) || !snapshot.equals(snapshot(connectivity))) return false;
                Network active = connectivity.getActiveNetwork();
                NetworkCapabilities capabilities = active == null ? null : connectivity.getNetworkCapabilities(active);
                return capabilities != null && (network.equals(active)
                        || vpnStarted && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
            } catch (Exception changed) { return false; }
        }

        private static boolean physical(ConnectivityManager manager, Network network) {
            if (network == null) return false;
            NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
            LinkProperties properties = manager.getLinkProperties(network);
            return capabilities != null && properties != null
                    && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    && !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
        }

        private static String snapshot(ConnectivityManager manager) throws Exception {
            List<String> networks = new ArrayList<>();
            for (Network network : manager.getAllNetworks()) {
                if (!physical(manager, network)) continue;
                LinkProperties properties = manager.getLinkProperties(network);
                NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
                List<InetAddress> dns = properties.getDnsServers();
                // A captured network without an observable DNS policy cannot
                // authorize an ambient resolver or a fixed public bootstrap.
                if (dns == null || dns.isEmpty() || dns.size() > 32) throw unavailable();
                JSONArray resolvers = new JSONArray();
                for (InetAddress address : dns) {
                    if (address == null) throw unavailable();
                    resolvers.put(address.getHostAddress());
                }
                List<String> addresses = new ArrayList<>(), routes = new ArrayList<>();
                for (Object address : properties.getLinkAddresses()) addresses.add(address.toString());
                for (Object route : properties.getRoutes()) routes.add(route.toString());
                Collections.sort(addresses); Collections.sort(routes);
                JSONObject row = new JSONObject().put("network", network.getNetworkHandle())
                        .put("interface", properties.getInterfaceName()).put("dns", resolvers)
                        .put("addresses", new JSONArray(addresses)).put("routes", new JSONArray(routes))
                        .put("wifi", capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
                        .put("cellular", capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR))
                        .put("ethernet", capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET));
                if (Build.VERSION.SDK_INT >= 28) {
                    // Active with no name is opportunistic Private DNS. Keep
                    // that distinction instead of inventing a TLS hostname.
                    row.put("private_dns_active", properties.isPrivateDnsActive())
                            .put("private_dns_name", properties.getPrivateDnsServerName() == null
                                    ? JSONObject.NULL : properties.getPrivateDnsServerName());
                }
                networks.add(row.toString());
            }
            if (networks.isEmpty() || networks.size() > 32) throw unavailable();
            Collections.sort(networks);
            return new JSONArray(networks).toString();
        }
    }

    private interface Query {
        void start(String hostname);
        void cancel();
        void join();
    }

    private final Object lock = new Object();
    private final String identity = UUID.randomUUID().toString();
    final Physical physical;
    private final Current source;
    private final String hostname;
    private final ExecutorService callbacks = Executors.newSingleThreadExecutor(r -> new Thread(r, "routervpn-max-dns-callback"));
    private final CountDownLatch closed = new CountDownLatch(1), lookupDone = new CountDownLatch(1);
    private boolean acceptCallbacks = true, started, finishing, queryStarted;
    private final Executor admitted = command -> {
        synchronized (lock) {
            if (!acceptCallbacks) return;
            callbacks.execute(command);
        }
    };
    private volatile boolean cancelled, drainFailed;
    private Query query;
    private Thread watch;
    private List<InetAddress> answer;
    private boolean answered, failed;

    AndroidMAXDNSOwner(Physical physical, Current source, String hostname) throws Exception {
        if (physical == null || source == null || hostname == null || hostname.isEmpty() || hostname.length() > 253) throw unavailable();
        this.physical = physical; this.source = source; this.hostname = hostname;
        if (!current()) { callbacks.shutdown(); throw unavailable(); }
    }

    @Override public String ownerID() { return identity; }
    @Override public boolean current() {
        if (cancelled || drainFailed) return false;
        try { return source.current() && physical.current(false); }
        catch (Exception changed) { return false; }
    }

    @Override public String lookup(String hostname) throws Exception {
        synchronized (lock) {
            if (started || cancelled || !current() || !this.hostname.equals(hostname)) throw unavailable();
            started = true;
            query = Build.VERSION.SDK_INT >= 29 ? new ModernQuery() : new LegacyQuery();
            watch = new Thread(() -> {
                try {
                    while (true) {
                        synchronized (lock) { if (finishing) return; }
                        if (!current()) { cancel(); return; }
                        Thread.sleep(40);
                    }
                } catch (InterruptedException stopped) { /* joined by finish */ }
            }, "routervpn-max-dns-watch");
            watch.start();
        }
        try {
            try { query.start(hostname); }
            catch (Throwable failure) { response(null, true); }
            finally { synchronized (lock) { queryStarted = true; lock.notifyAll(); } }
            synchronized (lock) {
                while (!answered && !cancelled) lock.wait();
            }
            finish();
            await(closed);
            if (!current()) throw unavailable();
            List<InetAddress> result;
            synchronized (lock) {
                if (failed || answer == null || answer.isEmpty() || answer.size() > 32) throw unavailable();
                result = new ArrayList<>(answer);
            }
            JSONArray addresses = new JSONArray();
            for (InetAddress address : result) {
                if (address == null || address.getHostAddress() == null || address.getHostAddress().contains("%")) throw unavailable();
                addresses.put(address.getHostAddress());
            }
            String resultJSON = new JSONObject().put("owner_id", identity).put("hostname", hostname)
                    .put("addresses", addresses).toString();
            if (resultJSON.getBytes(StandardCharsets.UTF_8).length > 4096 || !current()) throw unavailable();
            return resultJSON;
        } catch (InterruptedException interruption) {
            cancel();
            Thread.currentThread().interrupt();
            throw unavailable();
        } finally {
            finish();
            await(closed);
            synchronized (lock) { answer = null; }
            lookupDone.countDown();
        }
    }

    private void response(List<InetAddress> addresses, boolean error) {
        synchronized (lock) {
            if (cancelled || finishing || answered) return;
            answer = addresses == null ? null : new ArrayList<>(addresses);
            failed = error; answered = true; lock.notifyAll();
        }
    }

    @Override public void cancel() {
        synchronized (lock) { cancelled = true; lock.notifyAll(); }
        finish();
    }

    private void finish() {
        synchronized (lock) {
            if (finishing) return;
            finishing = true;
            // DnsResolver may submit a late result-reading runnable. Closing
            // admission first is safe because the exact cancellation signal
            // closes that query's app descriptor; no runnable can use a new one.
            acceptCallbacks = false;
            new Thread(() -> {
                try {
                    Query owned;
                    synchronized (lock) { owned = query; }
                    if (owned != null) {
                        try { owned.cancel(); } catch (Throwable failure) { drainFailed = true; }
                        synchronized (lock) { while (!queryStarted) waitUninterruptibly(lock); }
                        // Registration may have completed after first cancel.
                        try { owned.cancel(); } catch (Throwable failure) { drainFailed = true; }
                        try { owned.join(); } catch (Throwable failure) { drainFailed = true; }
                    }
                    callbacks.shutdown();
                    boolean interrupted = false;
                    while (!callbacks.isTerminated()) {
                        try { callbacks.awaitTermination(1, java.util.concurrent.TimeUnit.DAYS); }
                        catch (InterruptedException stopped) { interrupted = true; }
                    }
                    Thread observer;
                    synchronized (lock) { observer = watch; }
                    if (observer != null) { observer.interrupt(); joinThread(observer); }
                    if (interrupted) Thread.currentThread().interrupt();
                } catch (Throwable failure) { drainFailed = true; }
                finally { closed.countDown(); }
            }, "routervpn-max-dns-drain").start();
        }
    }

    @Override public void close() {
        cancel(); await(closed);
        boolean ran;
        synchronized (lock) { ran = started; }
        if (ran) await(lookupDone);
        if (drainFailed) throw unavailable();
    }

    private final class ModernQuery implements Query {
        private final CancellationSignal signal = new CancellationSignal();
        @Override public void start(String hostname) {
            DnsResolver.getInstance().query(physical.network, hostname,
                    DnsResolver.FLAG_NO_CACHE_LOOKUP, admitted, signal, new DnsResolver.Callback<List<InetAddress>>() {
                        @Override public void onAnswer(List<InetAddress> value, int rcode) { response(value, rcode != 0); }
                        @Override public void onError(DnsResolver.DnsException error) { response(null, true); }
                    });
        }
        @Override public void cancel() { signal.cancel(); }
        @Override public void join() { /* query call and admitted executor are joined by the owner */ }
    }

    private final class LegacyQuery implements Query {
        private Thread worker;
        private volatile boolean retired;
        @Override public void start(String hostname) {
            worker = new Thread(() -> {
                try {
                    if (retired) return;
                    // Explicit Network receiver preserves Android's resolver
                    // policy. No InetAddress/system-default lookup is permitted.
                    InetAddress[] value = physical.network.getAllByName(hostname);
                    admitted.execute(() -> response(value == null ? null : Arrays.asList(value), false));
                } catch (Exception failure) { admitted.execute(() -> response(null, true)); }
            }, "routervpn-max-dns-legacy");
            worker.start();
        }
        @Override public void cancel() { retired = true; Thread owned = worker; if (owned != null) owned.interrupt(); }
        @Override public void join() { Thread owned = worker; if (owned != null) joinThread(owned); }
    }

    static void await(CountDownLatch latch) {
        boolean interrupted = false;
        while (true) { try { latch.await(); break; } catch (InterruptedException stopped) { interrupted = true; } }
        if (interrupted) Thread.currentThread().interrupt();
    }
    private static void joinThread(Thread thread) {
        boolean interrupted = false;
        while (thread.isAlive()) { try { thread.join(); } catch (InterruptedException stopped) { interrupted = true; } }
        if (interrupted) Thread.currentThread().interrupt();
    }
    private static void waitUninterruptibly(Object monitor) {
        boolean interrupted = false;
        while (true) { try { monitor.wait(); break; } catch (InterruptedException stopped) { interrupted = true; } }
        if (interrupted) Thread.currentThread().interrupt();
    }
    static String sha256(String value) throws Exception {
        return sha256(value.getBytes(StandardCharsets.UTF_8));
    }
    static String sha256(byte[] value) throws Exception {
        StringBuilder result = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(value))
            result.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return result.toString();
    }
    private static IllegalStateException unavailable() { return new IllegalStateException("The captured physical-network DNS lookup is unavailable, changed or cancelled."); }
}
