package com.eabusham.routervpn;

import android.content.Context;
import io.nekohasekai.libbox.CommandServer;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterMTU;
import io.nekohasekai.libbox.RouterMTUPlatform;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/** One process-owned ordered source and its original native service. A private
 * file alone cannot authorize startup after process death or source replacement. */
final class AndroidNodeChainSession {
    interface Owner {
        boolean current(AndroidNodeChainSession session, CommandServer server);
        String network();
    }
    interface Host { void stop(AndroidNodeChainSession captured, Runnable complete); }
    static final String MODE = "node-chain";
    private static final Map<String, AndroidNodeChainSession> pending = new HashMap<>();
    final String sessionId = UUID.randomUUID().toString().replace("-", "");
    final AndroidNodeStore.ChainCapture source;
    final String selectionDigest;
    final AndroidHomeStateStore.Snapshot home;
    final AndroidNodeChainCapture capture;
    final File directory;
    final NativeSingBoxController.SessionInfo request;
    private final Context context;
    private final Object staging = new Object();
    private volatile boolean staged, claimed, cancelled, proofClosed, nativeClosed, released;
    private volatile CommandServer server;
    private volatile Owner owner;
    private volatile Host host;
    private volatile String network = "";

    AndroidNodeChainSession(Context context, AndroidNodeStore.ChainCapture source,
                            AndroidHomeStateStore.Snapshot home) throws Exception {
        this(context,source,home,selection(context,source));
    }
    AndroidNodeChainSession(Context context, AndroidNodeStore.ChainCapture source,
                            AndroidHomeStateStore.Snapshot home,String selectionDigest) throws Exception {
        this.context = context.getApplicationContext();
        this.source = source; this.home = home; this.selectionDigest=selectionDigest;
        source.requireCurrent();
        requireSelection(this.context,source,selectionDigest);
        if (!AndroidHomeStateStore.ownsNodeChain(this.context, home)) throw new IllegalStateException("The ordered launch lost its original Home selection.");
        File root = new File(this.context.getFilesDir(), "layered-sessions").getCanonicalFile();
        directory = new File(root, sessionId).getCanonicalFile();
        if (!directory.getParentFile().equals(root)) throw new IllegalStateException("The ordered private session path is unsafe.");
        capture = AndroidNodeChainCapture.compile(source);
        request = new NativeSingBoxController.SessionInfo(sessionId, MODE);
    }

    void stage() throws Exception {
        synchronized (staging) {
        requireSource();
        synchronized (pending) {
            if (!pending.isEmpty()) throw new IllegalStateException("An earlier ordered native owner has not completed cleanup.");
            pending.put(sessionId, this);
        }
        File root = directory.getParentFile();
        if ((!root.isDirectory() && !root.mkdirs()) || !directory.mkdir()) throw new IllegalStateException("Cannot create the original private ordered session.");
        if (!directory.setReadable(false, false) || !directory.setReadable(true, true)
                || !directory.setWritable(false, false) || !directory.setWritable(true, true)
                || !directory.setExecutable(false, false) || !directory.setExecutable(true, true)) {
            throw new IllegalStateException("Cannot protect the private ordered session.");
        }
        write("sing-box.json", capture.config);
        write(AndroidNodeChainCapture.SESSION_FILE, capture.launchInput);
        if (capture.strict) write(AndroidKillSwitchPolicy.SESSION_MARKER, "1\n");
        requireSource();
        staged = true;
        }
    }

    private void write(String name, String value) throws Exception {
        File target = new File(directory, name).getCanonicalFile();
        if (!target.getParentFile().equals(directory) || target.exists()) throw new IllegalStateException("The ordered private file has another owner.");
        try (FileOutputStream out = new FileOutputStream(target)) {
            if (!target.setReadable(false, false) || !target.setReadable(true, true)
                    || !target.setWritable(false, false) || !target.setWritable(true, true)) {
                throw new IllegalStateException("Cannot protect a private ordered source file.");
            }
            out.write(value.getBytes(StandardCharsets.UTF_8)); out.flush(); out.getFD().sync();
        }
    }

    static AndroidNodeChainSession claim(Context context, File directory, String sessionId,
                                         String mode, String config, String homeSession) throws Exception {
        AndroidNodeChainSession value;
        synchronized (pending) { value = pending.get(sessionId); }
        if (value == null || !MODE.equals(mode) || value.claimed || !value.staged || value.cancelled
                || !value.directory.equals(directory.getCanonicalFile()) || !value.home.sessionId.equals(homeSession)
                || !value.capture.config.equals(config)) throw new IllegalStateException("The ordered launch has no original process-owned capture.");
        value.requireSource();
        value.requireFiles();
        synchronized (pending) {
            if (pending.get(sessionId) != value || value.cancelled || value.claimed) throw new IllegalStateException("The ordered startup owner was retired.");
            value.claimed = true;
        }
        return value;
    }

    private void requireFiles() throws Exception {
        File[] files = directory.listFiles();
        if (files == null || files.length != (capture.strict ? 3 : 2)) throw new IllegalStateException("The ordered session contains another execution owner.");
        for (File file : files) {
            if (Files.isSymbolicLink(file.toPath()) || !file.isFile() || !file.getCanonicalFile().getParentFile().equals(directory)) throw new IllegalStateException("The ordered source file changed identity.");
            String expected;
            if ("sing-box.json".equals(file.getName())) expected = capture.config;
            else if (AndroidNodeChainCapture.SESSION_FILE.equals(file.getName())) expected = capture.launchInput;
            else if (capture.strict && AndroidKillSwitchPolicy.SESSION_MARKER.equals(file.getName())) expected = "1\n";
            else throw new IllegalStateException("The ordered source contains unowned metadata.");
            byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);
            if (file.length() != bytes.length || !java.util.Arrays.equals(bytes, Files.readAllBytes(file.toPath()))) throw new IllegalStateException("The ordered source changed after private staging.");
        }
    }

    void attach(CommandServer server, Owner owner, String expectedNetwork) throws Exception {
        if (server == null || owner == null || this.server != null || !claimed) throw new IllegalStateException("The ordered graph cannot adopt another native server.");
        this.server = server; this.owner = owner; network = expectedNetwork;
        if (network.isEmpty() || "[]".equals(network)) throw new IllegalStateException("The original physical network is unavailable.");
        requireCurrent();
    }

    void prove() throws Exception {
        requireCurrent();
        capture.plan.run(server);
        requireCurrent();
        if (!capture.plan.healthy()) throw new IllegalStateException("The complete ordered native path did not prove every node and selected DNS.");
        requireCurrent();
    }

    void requireSource() throws Exception {
        if (cancelled || released || proofClosed) throw new IllegalStateException("The original ordered source has been retired.");
        capture.requireCurrent();
        requireSelection(context,source,selectionDigest);
        if (!AndroidHomeStateStore.ownsNodeChain(context, home)) throw new IllegalStateException("The original ordered Home owner changed.");
    }

    static String selection(Context context,AndroidNodeStore.ChainCapture source)throws Exception {
        if(source==null)throw new IllegalStateException("The ordered source selection is missing.");
        return AndroidConnectionSelection.digest(source.control.id,AndroidConnectionSelection.preferences(context));
    }
    static void requireSelection(Context context,AndroidNodeStore.ChainCapture source,String expected)throws Exception {
        if(expected==null||!expected.matches("[0-9a-f]{64}")||!expected.equals(selection(context,source)))
            throw new IllegalStateException("The original saved ordered selection changed.");
    }

    void requireCurrent() throws Exception {
        requireSource();
        Owner current = owner; CommandServer nativeServer = server;
        if (current == null || nativeServer == null || !current.current(this, nativeServer)
                || !network.equals(current.network())) throw new IllegalStateException("The ordered proof belongs to another service or physical network.");
    }

    boolean healthy() {
        try { requireCurrent(); boolean proved = capture.plan.healthy(); requireCurrent(); return proved; }
        catch (Exception retired) { return false; }
    }

    String progressJSON() throws Exception { requireCurrent(); String result = capture.plan.progressJSON(); requireCurrent(); return result; }
    RouterMTU newMTU(RouterMTUPlatform platform) throws Exception {
        requireCurrent();
        if (!capture.plan.healthy()) throw new IllegalStateException("MTU requires the original complete ordered proof.");
        RouterMTU result = Libbox.routerNodeChainNewMTU(capture.plan, server, platform);
        if (result == null) throw new IllegalStateException("The ordered graph returned no native MTU owner.");
        // The caller retains this result before rechecking the source so that a
        // failed native drain cannot lose its newly constructed controller.
        return result;
    }

    void cancel() { cancelled = true; capture.plan.networkChanged(); }
    void closePlan() throws Exception { cancel(); capture.close(); proofClosed = true; }
    void nativeServiceClosed() { nativeClosed = true; }
    boolean released() { return released; }
    boolean claimed() { return claimed; }
    void adoptHost(Host value) {
        if (value == null || host != null || !claimed || released) throw new IllegalStateException("The ordered native host cannot be replaced.");
        host = value;
    }
    boolean hasHost() { return host != null; }
    void requestStop(Runnable complete) {
        if (released) { complete.run(); return; }
        Host original = host;
        if (original == null) throw new IllegalStateException("The ordered source has no adopted native host.");
        original.stop(this, complete);
    }
    boolean permitsStart(String mode, String homeSession) {
        return MODE.equals(mode) && staged && !claimed && !cancelled && !released && home.sessionId.equals(homeSession);
    }

    static AndroidNodeChainSession pending(String session) { synchronized (pending) { return pending.get(session); } }
    static AndroidNodeChainSession retained() { synchronized (pending) { return pending.isEmpty() ? null : pending.values().iterator().next(); } }

    void discardUnstarted() throws Exception {
        synchronized (staging) {
        if (server != null || host != null) throw new IllegalStateException("Only the original native service may retire this ordered plan.");
        closePlan(); nativeClosed = true; finishCleanup();
        }
    }

    void finishCleanup() throws Exception {
        if (!proofClosed || !nativeClosed) throw new IllegalStateException("The original native ordered cleanup has not been acknowledged.");
        if (!LayeredVpnService.discardPreparedSession(context, sessionId)) throw new IllegalStateException("The original ordered private directory has not been removed.");
        synchronized (pending) {
            if (pending.get(sessionId) == this) pending.remove(sessionId);
            released = true;
            host = null; owner = null; server = null;
        }
    }
}
