package com.eabusham.routervpn;

import io.nekohasekai.libbox.CommandServer;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterNodeChainExecution;
import io.nekohasekai.libbox.RouterNodeChainExecutionRestoreCapture;
import io.nekohasekai.libbox.RouterMTU;
import io.nekohasekai.libbox.RouterMTUPlatform;
import io.nekohasekai.libbox.RouterHopMeasurement;
import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

/** One execution preparation tied to the complete original Local source. The
 * preparation owns no forwarding permission; its native gate starts closed.
 * A serialized launch can validate source bytes, never restore a live owner. */
final class AndroidNodeChainExecutionCapture implements AutoCloseable {
    final AndroidNodeChainCapture local;
    final RouterNodeChainExecution plan;
    final String requested, source, launchInput, config, sourceSHA256, configSHA256;
    private volatile boolean closed;

    static AndroidNodeChainExecutionCapture compile(AndroidNodeChainCapture local, String requested) throws Exception {
        requireRequested(requested);
        if (local == null) throw new IllegalStateException("The original complete ordered source is missing.");
        local.requireCurrent();
        RouterNodeChainExecution plan = Libbox.routerNodeChainExecutionFromLaunch(local.launchInput, requested);
        return adopt(local, requested, plan);
    }

    /** Pure source replay. The service still requires its process-owned session,
     * original Home epoch, current selection and exact private file inventory. */
    static AndroidNodeChainExecutionCapture reopen(AndroidNodeChainCapture local, String input) throws Exception {
        if (local == null) throw new IllegalStateException("The original complete ordered source is missing.");
        local.requireCurrent();
        JSONObject record = privateJSON(input, AndroidNodeChainCapture.MAX_INPUT);
        JSONObject preparation = privateJSON(record.getString("source"), AndroidNodeChainCapture.MAX_INPUT);
        String requested = preparation.getString("execution");
        requireRequested(requested);
        AndroidNodeChainExecutionCapture result = adopt(local, requested, Libbox.newRouterNodeChainExecutionLaunch(input));
        if (!input.equals(result.launchInput)) {
            try { result.close(); }
            catch (Exception cleanup) { throw new IllegalStateException("The altered execution source could not retire its native capture.", cleanup); }
            throw new IllegalStateException("The private execution launch is not its original canonical source.");
        }
        return result;
    }

    private static AndroidNodeChainExecutionCapture adopt(AndroidNodeChainCapture local, String requested,
                                                           RouterNodeChainExecution plan) throws Exception {
        if (plan == null) throw new IllegalStateException("The native execution compiler returned no original owner.");
        try { return new AndroidNodeChainExecutionCapture(local, requested, plan); }
        catch (Exception invalid) {
            try { plan.close(); } catch (Exception cleanup) { invalid.addSuppressed(cleanup); }
            throw invalid;
        }
    }

    private AndroidNodeChainExecutionCapture(AndroidNodeChainCapture local, String requested,
                                              RouterNodeChainExecution plan) throws Exception {
        this.local = local; this.requested = requested; this.plan = plan;
        source = bounded(plan.source(), AndroidNodeChainCapture.MAX_INPUT);
        launchInput = bounded(plan.launchInput(), AndroidNodeChainCapture.MAX_INPUT);
        config = bounded(plan.config(), 4 * 1024 * 1024);
        sourceSHA256 = plan.sourceSHA256(); configSHA256 = plan.configSHA256();
        JSONObject preparation = privateJSON(source, AndroidNodeChainCapture.MAX_INPUT);
        JSONObject launch = privateJSON(launchInput, AndroidNodeChainCapture.MAX_INPUT);
        if (preparation.length() != 3 || preparation.getInt("schema") != 1
                || !requested.equals(preparation.getString("execution")) || !requested.equals(plan.requestedExecution())
                || !local.sourceSHA256.equals(plan.localSourceSHA256())
                || sourceSHA256 == null || !sourceSHA256.matches("[0-9a-f]{64}")
                || configSHA256 == null || !configSHA256.equals(digest(config))
                || launch.length() != 5 || !"routervpn-node-chain-execution-preparation-input".equals(launch.getString("kind"))
                || launch.getInt("schema") != 1 || !source.equals(launch.getString("source"))
                || !sourceSHA256.equals(launch.getString("source_sha256")) || !configSHA256.equals(launch.getString("config_sha256"))) {
            throw new IllegalStateException("The execution preparation changed its original requested path or native source.");
        }
        JSONObject original = privateJSON(local.launchInput, AndroidNodeChainCapture.MAX_INPUT);
        JSONObject returned = privateJSON(preparation.getString("local_source"), AndroidNodeChainCapture.MAX_INPUT);
        if (returned.length() != 4 || original.getInt("schema") != 1 || returned.getInt("schema") != 1
                || !"local".equals(returned.getString("execution"))
                || !sameStrings(original.getJSONArray("nodes"), returned.getJSONArray("nodes"))
                || !sameStrings(original.getJSONArray("identity_sources"), returned.getJSONArray("identity_sources"))) {
            throw new IllegalStateException("Server execution requires every original paired node in its exact Local order.");
        }
        local.requireCurrent();
    }

    void requireCurrent() throws Exception {
        if (closed) throw new IllegalStateException("The original ordered execution capture has retired.");
        local.requireCurrent();
    }

    // Binding also retains deny-only cleanup when cancellation won before the
    // fresh native construction. The Session validates source after this call,
    // before Start; Run and every proof still require a current source.
    void bindNative(CommandServer server) throws Exception { plan.bindNative(server); }
    void run(CommandServer server) throws Exception { requireCurrent(); plan.run(server); requireCurrent(); }
    boolean healthy() {
        try { requireCurrent(); boolean result = plan.healthy(); requireCurrent(); return result; }
        catch (Exception retired) { return false; }
    }
    String execution() throws Exception {
        requireCurrent();
        String result = plan.execution();
        if (!("local".equals(result) || "server".equals(result)) || !"auto".equals(requested) && !requested.equals(result))
            throw new IllegalStateException("The original ordered execution has no proved selected result.");
        requireCurrent(); return result;
    }
    String progressJSON() throws Exception { requireCurrent(); String result = plan.progressJSON(); requireCurrent(); return result; }
    void networkChanged() { plan.networkChanged(); }
    boolean retainsServerCleanup(CommandServer server) { return !closed && plan.retainsServerCleanup(server); }
    boolean nativeClosed() { return closed && plan.nativeClosed(); }
    RouterMTU newMTU(CommandServer server, RouterMTUPlatform platform) throws Exception {
        requireCurrent();
        if (!healthy()) throw new IllegalStateException("MTU requires the original proved execution.");
        return Libbox.routerNodeChainExecutionNewMTU(plan, server, platform);
    }
    RouterHopMeasurement newHopMeasurement(CommandServer server) throws Exception {
        requireCurrent();
        if (!healthy()) throw new IllegalStateException("Measurement requires the original proved execution.");
        return Libbox.routerNodeChainExecutionNewHopMeasurement(plan, server);
    }

    static final class RestoreCapture {
        private final AndroidNodeChainExecutionCapture original;
        private final RouterNodeChainExecutionRestoreCapture nativeCapture;
        final String execution;
        private RestoreCapture(AndroidNodeChainExecutionCapture original, RouterNodeChainExecutionRestoreCapture nativeCapture,
                               String execution) {
            this.original = original; this.nativeCapture = nativeCapture; this.execution = execution;
        }
    }

    RestoreCapture captureRestore() throws Exception {
        requireCurrent();
        String selected = execution();
        RouterNodeChainExecutionRestoreCapture nativeCapture = plan.captureRestore();
        if (nativeCapture == null || !healthy() || !selected.equals(execution()))
            throw new IllegalStateException("The original execution changed during its restore capture.");
        return new RestoreCapture(this, nativeCapture, selected);
    }

    static AndroidNodeChainExecutionCapture restore(AndroidNodeChainCapture local, RestoreCapture captured) throws Exception {
        if (captured == null || !captured.original.closed || local == null
                || !local.launchInput.equals(captured.original.local.launchInput))
            throw new IllegalStateException("Execution restore needs the complete original source and acknowledged native drain.");
        local.requireCurrent();
        AndroidNodeChainExecutionCapture result = adopt(local, captured.original.requested,
                Libbox.newRouterNodeChainExecutionRestore(captured.nativeCapture));
        if (!captured.original.source.equals(result.source) || !captured.original.config.equals(result.config)) {
            try { result.close(); }
            catch (Exception cleanup) { throw new IllegalStateException("The altered restore capture could not retire its native owner.", cleanup); }
            throw new IllegalStateException("Restore substituted a different execution preparation.");
        }
        return result;
    }

    boolean restoredMatches(RestoreCapture captured) throws Exception {
        return captured != null && captured.original != this && captured.original.closed
                && captured.original.source.equals(source) && captured.execution.equals(execution()) && healthy();
    }

    @Override public void close() throws Exception {
        // A failed close retains this exact bridge for retry while its original
        // Box/TUN remains alive. Source retirement never grants cleanup success.
        plan.close(); closed = true;
    }

    private static void requireRequested(String requested) {
        if (!"server".equals(requested) && !"auto".equals(requested))
            throw new IllegalStateException("Choose the exact ordered Server or Compare execution.");
    }
    private static boolean sameStrings(JSONArray a, JSONArray b) throws Exception {
        if (a.length() != b.length()) return false;
        for (int i = 0; i < a.length(); i++) {
            if (!(a.get(i) instanceof String) || !(b.get(i) instanceof String) || !a.getString(i).equals(b.getString(i))) return false;
        }
        return true;
    }
    private static JSONObject privateJSON(String raw, int limit) throws Exception {
        Libbox.routerValidatePrivateNodeJSON(bounded(raw, limit));
        return new JSONObject(raw);
    }
    private static String bounded(String value, int limit) {
        if (value == null || value.isEmpty() || value.getBytes(StandardCharsets.UTF_8).length > limit)
            throw new IllegalStateException("The complete private execution source exceeds its bound.");
        return value;
    }
    private static String digest(String value) throws Exception {
        StringBuilder result = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)))
            result.append(String.format(Locale.ROOT, "%02x", b & 255));
        return result.toString();
    }
}
