package com.eabusham.routervpn;

import android.content.Context;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterMAXProfileRequest;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;

/** Captures a complete MAX launch and owns asynchronous endpoint preparation.
 * A process has one VPN transition. A cancelled preparation stays registered
 * until its exact native requests and foreign resolver callbacks have joined. */
final class AndroidMAXProfilePreparation implements AutoCloseable {
    static final String SESSION_FILE = "routervpn-max-preparation.json";
    static final String EXTRA_OWNER = "routervpn_max_preparation";
    private static final int MAX_GRAPH = 4 * 1024 * 1024;
    private static final Object REGISTRY = new Object();
    private static AndroidMAXProfilePreparation active;

    static final class Source {
        final File file;
        final String bytesSHA256, bundleJSON;
        final long length, modified;
        final AndroidNativeMAXProfile.Capture capture;
        Source(File file, JSONObject bundle, String mode) throws Exception {
            this.file = file.getCanonicalFile();
            byte[] bytes = AndroidPrivateFileStore.read(this.file, AndroidNodeStore.MAX_BUNDLE);
            try {
                bundleJSON = bundle.toString();
                if (!bundleJSON.equals(new JSONObject(strictText(bytes)).toString())) throw unavailable();
                bytesSHA256 = AndroidMAXDNSOwner.sha256(bytes);
                length = bytes.length; modified = this.file.lastModified();
                capture = AndroidNativeMAXProfile.isMode(mode)
                        ? AndroidNativeMAXProfile.capture(bundle, bundle.getJSONObject("profiles").getJSONObject(mode), mode) : null;
            } finally { Arrays.fill(bytes, (byte) 0); }
        }
        boolean current(boolean exact) {
            try {
                if (!file.isFile() || file.length() != length || file.lastModified() != modified) return false;
                if (!exact) return true;
                byte[] bytes = AndroidPrivateFileStore.read(file, AndroidNodeStore.MAX_BUNDLE);
                try { return bytesSHA256.equals(AndroidMAXDNSOwner.sha256(bytes)); }
                finally { Arrays.fill(bytes, (byte) 0); }
            } catch (Exception changed) { return false; }
        }
    }

    /** No handles survive this handoff. Native sockets keep the exact physical
     * Network, while source/network readback remains required before UP. */
    static final class Adopted {
        final AndroidMAXDNSOwner.Physical physical;
        final String identity, session;
        private final List<Source> sources;
        private final Context context;
        private final String homeSession;
        private volatile boolean cancelled;
        Adopted(AndroidMAXProfilePreparation preparation) {
            physical = preparation.physical; identity = preparation.identity;
            session = preparation.session;
            sources = new ArrayList<>(preparation.sources);
            context = preparation.context; homeSession = preparation.homeSession;
        }
        boolean current(boolean exact) {
            if (cancelled || !homeSession.equals(AndroidHomeStateStore.snapshot(context).sessionId)
                    || AndroidHomeStateStore.emergencyDisconnectPending(context) || !physical.current(true)) return false;
            for (Source source : sources) if (!source.current(exact)) return false;
            return true;
        }
        void cancel() { cancelled = true; }
    }

    static AndroidMAXProfilePreparation begin(Context context, Source... sources) throws Exception {
        boolean hostname = false;
        for (Source source : sources) hostname |= source.capture != null && source.capture.requiresResolution();
        if (!hostname) return null;
        AndroidMAXProfilePreparation result = new AndroidMAXProfilePreparation(context, Arrays.asList(sources));
        synchronized (REGISTRY) {
            if (active != null) throw unavailable();
            active = result;
        }
        result.startWatch();
        return result;
    }

    private final Object lock = new Object();
    private final Context context;
    final String identity = UUID.randomUUID().toString();
    final AndroidMAXDNSOwner.Physical physical;
    private final List<Source> sources;
    private final Thread caller = Thread.currentThread();
    private final String homeSession;
    private final List<RouterMAXProfileRequest> requests = new ArrayList<>();
    private final List<AndroidMAXDNSOwner> resolvers = new ArrayList<>();
    private final CountDownLatch drained = new CountDownLatch(1);
    private final long deadline = System.nanoTime() + 30_000_000_000L;
    private volatile boolean cancelled, closing, drainFailed;
    private boolean adopting;
    private volatile boolean adoptionCancelled;
    private int calls;
    private Thread watch;
    private File stageFolder;
    private String session = "", mode = "", marker = "", configSHA256 = "";

    private AndroidMAXProfilePreparation(Context context, List<Source> sources) throws Exception {
        this.context = context.getApplicationContext(); this.sources = new ArrayList<>(sources);
        homeSession = AndroidHomeStateStore.snapshot(this.context).sessionId;
        for (Source source : sources) if (!source.current(true)) throw unavailable();
        physical = new AndroidMAXDNSOwner.Physical(this.context);
        if (!current(false)) throw unavailable();
    }

    private boolean current(boolean exact) {
        if (cancelled || caller.isInterrupted() || System.nanoTime() > deadline) return false;
        if (!homeSession.equals(AndroidHomeStateStore.snapshot(context).sessionId)
                || AndroidHomeStateStore.emergencyDisconnectPending(context) || !physical.current(false)) return false;
        for (Source source : sources) if (!source.current(exact)) return false;
        return true;
    }

    private void startWatch() {
        synchronized (lock) {
        if (closing) return;
        watch = new Thread(() -> {
            try {
                while (!closing) {
                    if (!current(false)) { cancel(); return; }
                    Thread.sleep(40);
                }
            } catch (InterruptedException stopped) { /* close joins this owner */ }
        }, "routervpn-max-preparation-watch");
        watch.start();
        }
    }

    String compile(Source source) throws Exception {
        if (source == null || source.capture == null || !sources.contains(source)) throw unavailable();
        AndroidNativeMAXProfile.Capture captured = source.capture;
        if (!captured.requiresResolution()) {
            JSONObject bundle = new JSONObject(source.bundleJSON);
            return AndroidNativeMAXProfile.compile(bundle, new JSONObject(captured.files), captured.mode);
        }
        synchronized (lock) { if (closing || !session.isEmpty() || !current(true)) throw unavailable(); calls++; }
        try {
            captured.recheck();
            AndroidMAXDNSOwner resolver = new AndroidMAXDNSOwner(physical, () -> current(false), captured.endpoint);
            synchronized (lock) { resolvers.add(resolver); if (cancelled) resolver.cancel(); }
            RouterMAXProfileRequest request = Libbox.routerCreateMAXProfileRequest(captured.mode, captured.files, captured.metadata, resolver);
            if (request == null) throw unavailable();
            synchronized (lock) { requests.add(request); if (cancelled) request.cancel(); }
            if (!captured.source.equals(request.sourceSHA256()) || !current(true)) throw unavailable();
            String result = request.run();
            if (result == null || result.getBytes(StandardCharsets.UTF_8).length > 32 * 1024 * 1024
                    || !request.healthy() || !current(true)) throw unavailable();
            JSONObject envelope = new JSONObject(result);
            List<String> allowed = Arrays.asList("schema", "owner_id", "source_sha256", "hostname", "endpoint", "config_json", "files_json", "metadata_json");
            JSONArray names = envelope.names();
            if (names == null || names.length() != allowed.size()) throw unavailable();
            for (int i = 0; i < names.length(); i++) if (!allowed.contains(names.getString(i))) throw unavailable();
            if (!(envelope.get("schema") instanceof Integer) || envelope.getInt("schema") != 1
                    || !resolver.ownerID().equals(envelope.getString("owner_id"))
                    || !captured.source.equals(envelope.getString("source_sha256"))
                    || !captured.endpoint.equals(envelope.getString("hostname"))) throw unavailable();
            AndroidNumericAddress.parse(envelope.getString("endpoint"));
            String config = envelope.getString("config_json"), files = envelope.getString("files_json"), metadata = envelope.getString("metadata_json");
            if (config.getBytes(StandardCharsets.UTF_8).length > MAX_GRAPH
                    || files.getBytes(StandardCharsets.UTF_8).length > 16 * 1024 * 1024
                    || metadata.getBytes(StandardCharsets.UTF_8).length > 16384) throw unavailable();
            // Check the native private envelope with the literal-only compiler.
            // It is never written back to the original saved node or its assets.
            if (!config.equals(Libbox.routerCompileMAXProfile(captured.mode, files, metadata))) throw unavailable();
            AndroidNativeMAXProfile.validateGraph(new JSONObject(source.bundleJSON), new JSONObject(captured.files), new JSONObject(config), captured.mode);
            captured.recheck();
            if (!request.healthy() || !current(true)) throw unavailable();
            return config;
        } catch (Exception failure) {
            cancel();
            throw unavailable();
        } finally { synchronized (lock) { calls--; lock.notifyAll(); } }
    }

    void verify() throws Exception {
        if (!current(true)) throw unavailable();
        synchronized (lock) {
            if (closing || calls != 0) throw unavailable();
            for (RouterMAXProfileRequest request : requests) if (!request.healthy()) throw unavailable();
        }
        for (Source source : sources) if (source.capture != null) source.capture.recheck();
        if (!current(true)) throw unavailable();
    }

    void stage(File folder, String sessionID, String modeID, String config) throws Exception {
        verify();
        synchronized (lock) {
            if (!session.isEmpty() || closing) throw unavailable();
            session = sessionID; mode = modeID; configSHA256 = AndroidMAXDNSOwner.sha256(config);
            stageFolder = folder.getCanonicalFile();
            JSONArray inputs = new JSONArray();
            for (Source source : sources) inputs.put(new JSONObject().put("file_sha256", source.bytesSHA256)
                    .put("max_sha256", source.capture == null ? "" : source.capture.source));
            marker = new JSONObject().put("schema", 1).put("owner_id", identity).put("session_id", session)
                    .put("mode_id", mode).put("config_sha256", configSHA256).put("physical_sha256", physical.digest)
                    .put("sources", inputs).toString();
            AndroidPrivateFileStore.write(new File(folder, SESSION_FILE), marker.getBytes(StandardCharsets.UTF_8), 65536);
        }
        verify();
    }

    void beforeSubmit(String sessionID, String modeID) throws Exception {
        synchronized (lock) { if (!session.equals(sessionID) || !mode.equals(modeID) || adopting) throw unavailable(); }
        verify();
    }

    static Adopted claim(Context context, File folder, String sessionID, String modeID, String config, String expectedOwner) throws Exception {
        File markerFile = new File(folder, SESSION_FILE).getCanonicalFile();
        AndroidMAXProfilePreparation captured;
        synchronized (REGISTRY) { captured = active; }
        boolean expected = expectedOwner != null && !expectedOwner.isEmpty();
        if (!expected && !markerFile.exists() && (captured == null || !captured.session.equals(sessionID))) return null;
        if (!expected || captured == null || !captured.identity.equals(expectedOwner)
                || !folder.getCanonicalFile().equals(captured.stageFolder)
                || !markerFile.getParentFile().equals(folder.getCanonicalFile()) || !markerFile.isFile()) throw unavailable();
        captured.beforeSubmit(sessionID, modeID);
        String marker = strictText(AndroidPrivateFileStore.read(markerFile, 65536));
        if (!captured.marker.equals(marker) || !captured.configSHA256.equals(AndroidMAXDNSOwner.sha256(config))) throw unavailable();
        Adopted result;
        synchronized (captured.lock) {
            if (captured.adopting || captured.closing) throw unavailable();
            captured.adopting = true;
            result = new Adopted(captured);
            // Retirement for a successful handoff is distinct from STOP.
            // External cancellation during this barrier still invalidates it.
            captured.beginDrainLocked();
        }
        AndroidMAXDNSOwner.await(captured.drained);
        // No native DNS handle/callback survives claim. Check the independent
        // immutable source/path again after that barrier, before starting Box.
        if (captured.drainFailed || captured.adoptionCancelled || !result.current(true)) { result.cancel(); throw unavailable(); }
        return result;
    }

    void cancel() {
        synchronized (lock) {
            if (adopting) adoptionCancelled = true;
            beginDrainLocked();
        }
    }

    private void beginDrainLocked() {
        cancelled = true;
        if (closing) return;
        closing = true;
        for (RouterMAXProfileRequest request : requests) request.cancel();
        for (AndroidMAXDNSOwner resolver : resolvers) resolver.cancel();
        new Thread(this::drain, "routervpn-max-preparation-drain").start();
    }

    private void drain() {
        boolean interrupted = false;
        try {
            synchronized (lock) {
                while (calls != 0) {
                    try { lock.wait(); } catch (InterruptedException stopped) { interrupted = true; }
                }
            }
            for (RouterMAXProfileRequest request : requests) {
                try { request.cancel(); request.close(); } catch (Throwable failure) { drainFailed = true; }
            }
            for (AndroidMAXDNSOwner resolver : resolvers) {
                try { resolver.close(); } catch (Throwable failure) { drainFailed = true; }
            }
            if (watch != null) {
                watch.interrupt();
                while (watch.isAlive()) { try { watch.join(); } catch (InterruptedException stopped) { interrupted = true; } }
            }
            if (!drainFailed) {
                if ((!adopting || adoptionCancelled) && stageFolder != null) removeStaged(stageFolder);
                synchronized (REGISTRY) { if (active == this) active = null; }
            }
        } finally { drained.countDown(); if (interrupted) Thread.currentThread().interrupt(); }
    }

    @Override public void close() {
        cancel(); AndroidMAXDNSOwner.await(drained);
        if (drainFailed) throw unavailable();
    }
    static void cancelActive() { AndroidMAXProfilePreparation captured; synchronized (REGISTRY) { captured = active; } if (captured != null) captured.cancel(); }
    /** A failed service preflight may retire only the exact still-unclaimed preparation. */
    static void discardPrepared(String sessionID, String ownerID) {
        AndroidMAXProfilePreparation captured;
        synchronized(REGISTRY){captured=active;}
        if(captured==null||ownerID==null||ownerID.isEmpty())return;
        synchronized(captured.lock){
            if(!captured.identity.equals(ownerID)||!captured.session.equals(sessionID)||captured.adopting)return;
            captured.beginDrainLocked();
        }
        AndroidMAXDNSOwner.await(captured.drained);
        if(captured.drainFailed)throw unavailable();
    }
    static boolean busy() { synchronized (REGISTRY) { return active != null; } }
    private static String strictText(byte[] bytes) throws Exception {
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(bytes)).toString();
    }
    private static void removeStaged(File file) {
        try {
            if (file.getCanonicalFile().equals(file.getAbsoluteFile())) {
                File[] children = file.listFiles();
                if (children != null) for (File child : children) removeStaged(child);
            }
            file.delete();
        } catch (Exception ignored) { /* private leftover is not an active owner */ }
    }
    private static IllegalStateException unavailable() { return new IllegalStateException("Complete MAX preparation changed, was cancelled or has not finished its owned cleanup."); }
}
