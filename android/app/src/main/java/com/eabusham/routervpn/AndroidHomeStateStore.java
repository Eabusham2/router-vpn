package com.eabusham.routervpn;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.File;
import java.util.UUID;

/** App-private runtime state used by the product Home dashboard. Never stores tunnel secrets. */
final class AndroidHomeStateStore {
    private static final String PREFS = "routervpn_home_state_v1";

    static final class Snapshot {
        final String sessionId, phase, logicalMode, runtimeMode, actualBase, fallback, warning;
        final String activeNodeId, activeEntryId, activeExitId;
        final boolean connected;
        Snapshot(SharedPreferences p) {
            sessionId = p.getString("session_id", "");
            phase = p.getString("phase", "off");
            logicalMode = p.getString("logical_mode", "");
            runtimeMode = p.getString("runtime_mode", "");
            actualBase = p.getString("actual_base", "");
            fallback = p.getString("fallback", "");
            warning = p.getString("warning", "");
            activeNodeId = p.getString("active_node_id", "");
            activeEntryId = p.getString("active_entry_id", "");
            activeExitId = p.getString("active_exit_id", "");
            connected = p.getBoolean("connected", false);
        }
    }

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    static Snapshot snapshot(Context context) { return new Snapshot(prefs(context)); }

    static String begin(Context context, String logicalMode, String runtimeMode, String base) {
        return begin(context, logicalMode, runtimeMode, base, "");
    }

    static String begin(Context context, String logicalMode, String runtimeMode, String base, String activeNodeId) {
        String session = UUID.randomUUID().toString();
        prefs(context).edit()
                .putString("session_id", session)
                .putString("phase", "connecting")
                .putString("logical_mode", clean(logicalMode))
                .putString("runtime_mode", clean(runtimeMode))
                .putString("actual_base", clean(base))
                .putString("active_node_id", clean(activeNodeId))
                .putString("fallback", "")
                .putString("warning", "")
                .putBoolean("connected", false)
                .remove("active_entry_id")
                .remove("active_exit_id")
                .remove("actual_exit_ip")
                .remove("actual_exit_session")
                .apply();
        return session;
    }

    static String beginMultihop(Context context, String entryId, String exitId, String runtimeMode) {
        String session = UUID.randomUUID().toString();
        prefs(context).edit()
                .putString("session_id", session)
                .putString("phase", "connecting")
                .putString("logical_mode", "multihop")
                .putString("runtime_mode", clean(runtimeMode))
                .putString("actual_base", "wg")
                .putString("active_node_id", clean(exitId))
                .putString("fallback", "")
                .putString("warning", "")
                .putString("active_entry_id", clean(entryId))
                .putString("active_exit_id", clean(exitId))
                .putBoolean("connected", false)
                .remove("actual_exit_ip")
                .remove("actual_exit_session")
                .apply();
        return session;
    }

    static void connected(Context context, String logicalMode, String runtimeMode, String base, String fallback) {
        connected(context, logicalMode, runtimeMode, base, fallback, "");
    }

    static void connected(Context context, String logicalMode, String runtimeMode, String base, String fallback, String activeNodeId) {
        SharedPreferences p = prefs(context);
        String session = p.getString("session_id", "");
        if (session == null || session.isEmpty()) session = UUID.randomUUID().toString();
        p.edit()
                .putString("session_id", session)
                .putString("phase", "connected")
                .putString("logical_mode", clean(logicalMode))
                .putString("runtime_mode", clean(runtimeMode))
                .putString("actual_base", clean(base))
                .putString("active_node_id", clean(activeNodeId))
                .putString("fallback", clean(fallback))
                .putString("warning", "")
                .putBoolean("connected", true)
                .remove("active_entry_id")
                .remove("active_exit_id")
                .apply();
    }

    static void connectedMultihop(Context context, String entryId, String exitId, String runtimeMode) {
        SharedPreferences p = prefs(context);
        String session = p.getString("session_id", "");
        if (session == null || session.isEmpty()) session = UUID.randomUUID().toString();
        p.edit()
                .putString("session_id", session)
                .putString("phase", "connected")
                .putString("logical_mode", "multihop")
                .putString("runtime_mode", clean(runtimeMode))
                .putString("actual_base", "wg")
                .putString("active_node_id", clean(exitId))
                .putString("fallback", "")
                .putString("warning", "")
                .putString("active_entry_id", clean(entryId))
                .putString("active_exit_id", clean(exitId))
                .putBoolean("connected", true)
                .apply();
    }

    static void warning(Context context, String warning) {
        prefs(context).edit().putString("warning", clean(warning)).apply();
    }

    static void failed(Context context, String warning) {
        prefs(context).edit()
                .putString("phase", "failed")
                .putString("warning", clean(warning))
                .putBoolean("connected", false)
                .remove("active_node_id")
                .remove("active_entry_id")
                .remove("active_exit_id")
                .remove("actual_exit_ip")
                .remove("actual_exit_session")
                .apply();
    }

    static void disconnected(Context context) {
        prefs(context).edit()
                .putString("session_id", "")
                .putString("phase", "off")
                .putString("logical_mode", "")
                .putString("runtime_mode", "")
                .putString("actual_base", "")
                .putString("fallback", "")
                .putString("warning", "")
                .putBoolean("connected", false)
                .remove("active_node_id")
                .remove("active_entry_id")
                .remove("active_exit_id")
                .remove("actual_exit_ip")
                .remove("actual_exit_session")
                .apply();
    }

    static void saveActualExit(Context context, String sessionId, String ip) {
        prefs(context).edit().putString("actual_exit_session", clean(sessionId)).putString("actual_exit_ip", clean(ip)).apply();
    }

    static String actualExitForCurrentSession(Context context) {
        SharedPreferences p = prefs(context);
        String session = p.getString("session_id", "");
        String proofSession = p.getString("actual_exit_session", "");
        if (session == null || session.isEmpty() || !session.equals(proofSession)) return "";
        return p.getString("actual_exit_ip", "");
    }

    static String nodeIdFromBundleFile(File file) {
        if (file == null) return "";
        String name = file.getName();
        return name != null && name.matches("[0-9a-f]{32}\\.json") ? name.substring(0, 32) : "";
    }

    private static String clean(String value) { return value == null ? "" : value.replace('\n', ' ').replace('\r', ' ').trim(); }
    private AndroidHomeStateStore() {}
}
