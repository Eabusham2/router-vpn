package com.eabusham.routervpn;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.File;
import java.util.UUID;

/** App-private runtime state used by the product Home dashboard. Never stores tunnel secrets. */
final class AndroidHomeStateStore {
    private static final String PREFS = "routervpn_home_state_v1";

    static final class Snapshot {
        final String sessionId, phase, logicalMode, runtimeMode, actualBase, fallback, warning, pathProof;
        final String activeNodeId, activeEntryId, activeExitId;
        final String activeExternalId, activeExternalName, activeExternalProtocol, expectedExternalIp;
        final long pathGeneration;
        final boolean connected;
        Snapshot(SharedPreferences p) {
            sessionId = p.getString("session_id", "");
            phase = p.getString("phase", "off");
            logicalMode = p.getString("logical_mode", "");
            runtimeMode = p.getString("runtime_mode", "");
            actualBase = p.getString("actual_base", "");
            fallback = p.getString("fallback", "");
            warning = p.getString("warning", "");
            pathProof = p.getString("path_proof", connectedValue(p) ? "passed" : "not-run");
            activeNodeId = p.getString("active_node_id", "");
            activeEntryId = p.getString("active_entry_id", "");
            activeExitId = p.getString("active_exit_id", "");
            activeExternalId = p.getString("active_external_id", "");
            activeExternalName = p.getString("active_external_name", "");
            activeExternalProtocol = p.getString("active_external_protocol", "");
            expectedExternalIp = p.getString("expected_external_ip", "");
            pathGeneration = p.getLong("path_generation", 0L);
            connected = connectedValue(p);
        }
        private static boolean connectedValue(SharedPreferences p) { return p.getBoolean("connected", false); }
    }

    private static SharedPreferences prefs(Context context) { return context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE); }
    static Snapshot snapshot(Context context) { return new Snapshot(prefs(context)); }

    static String begin(Context context, String logicalMode, String runtimeMode, String base) { return begin(context, logicalMode, runtimeMode, base, ""); }
    static String begin(Context context, String logicalMode, String runtimeMode, String base, String activeNodeId) {
        String session = UUID.randomUUID().toString();
        SharedPreferences.Editor e = clearGraphAndExternal(baseSession(context, session, logicalMode, runtimeMode, base));
        e.putString("active_node_id", clean(activeNodeId)).apply();
        return session;
    }

    static String beginMultihop(Context context, String entryId, String exitId, String runtimeMode) {
        String session = UUID.randomUUID().toString();
        SharedPreferences.Editor e = clearExternal(baseSession(context, session, "multihop", runtimeMode, "wg"));
        e.putString("active_node_id", clean(exitId)).putString("active_entry_id", clean(entryId)).putString("active_exit_id", clean(exitId)).apply();
        return session;
    }

    static String beginExternal(Context context, String externalId, String name, String protocol, String expectedIp, String base) {
        String session = UUID.randomUUID().toString();
        SharedPreferences.Editor e = clearRouterGraph(baseSession(context, session, "external", protocol, base));
        e.putString("active_external_id", clean(externalId)).putString("active_external_name", clean(name)).putString("active_external_protocol", clean(protocol)).putString("expected_external_ip", clean(expectedIp)).apply();
        return session;
    }

    static void connected(Context context, String logicalMode, String runtimeMode, String base, String fallback) { connected(context, logicalMode, runtimeMode, base, fallback, ""); }
    static void connected(Context context, String logicalMode, String runtimeMode, String base, String fallback, String activeNodeId) {
        SharedPreferences p = prefs(context); String session = existingOrNewSession(p);
        SharedPreferences.Editor e = clearGraphAndExternal(p.edit());
        e.putString("session_id", session).putString("phase", "connected").putString("logical_mode", clean(logicalMode)).putString("runtime_mode", clean(runtimeMode)).putString("actual_base", clean(base)).putString("active_node_id", clean(activeNodeId)).putString("fallback", clean(fallback)).putString("warning", "").putString("path_proof", "passed").putBoolean("connected", true).apply();
    }

    static void connectedMultihop(Context context, String entryId, String exitId, String runtimeMode) {
        SharedPreferences p = prefs(context); String session = existingOrNewSession(p);
        SharedPreferences.Editor e = clearExternal(p.edit());
        e.putString("session_id", session).putString("phase", "connected").putString("logical_mode", "multihop").putString("runtime_mode", clean(runtimeMode)).putString("actual_base", "wg").putString("active_node_id", clean(exitId)).putString("fallback", "").putString("warning", "").putString("path_proof", "passed").putString("active_entry_id", clean(entryId)).putString("active_exit_id", clean(exitId)).putBoolean("connected", true).apply();
    }

    static void connectedExternal(Context context, String externalId, String name, String protocol, String expectedIp, String base, String observedIp) {
        SharedPreferences p = prefs(context); String session = existingOrNewSession(p);
        SharedPreferences.Editor e = clearRouterGraph(p.edit());
        e.putString("session_id", session).putString("phase", "connected").putString("logical_mode", "external").putString("runtime_mode", clean(protocol)).putString("actual_base", clean(base)).putString("fallback", "").putString("warning", "").putString("path_proof", "passed").putString("active_external_id", clean(externalId)).putString("active_external_name", clean(name)).putString("active_external_protocol", clean(protocol)).putString("expected_external_ip", clean(expectedIp)).putBoolean("connected", true).putString("actual_exit_session", session).putString("actual_exit_ip", clean(observedIp)).apply();
    }

    static void warning(Context context, String warning) { prefs(context).edit().putString("warning", clean(warning)).apply(); }
    static void clearActualExit(Context context) { prefs(context).edit().remove("actual_exit_ip").remove("actual_exit_session").apply(); }
    static long advancePathGeneration(Context context) {
        SharedPreferences p = prefs(context); long next = p.getLong("path_generation", 0L) + 1L;
        p.edit().putLong("path_generation", next).remove("actual_exit_ip").remove("actual_exit_session").apply();
        return next;
    }
    static void failed(Context context, String warning) { SharedPreferences.Editor e=prefs(context).edit().putString("phase","failed").putString("warning",clean(warning)).putString("path_proof","failed").putBoolean("connected",false);clearAllIdentity(e).apply(); }
    static void disconnected(Context context) { SharedPreferences.Editor e=prefs(context).edit().putString("session_id","").putString("phase","off").putString("logical_mode","").putString("runtime_mode","").putString("actual_base","").putString("fallback","").putString("warning","").putString("path_proof","not-run").putBoolean("connected",false);clearAllIdentity(e).apply(); }

    static void saveActualExit(Context context, String sessionId, String ip) { prefs(context).edit().putString("actual_exit_session", clean(sessionId)).putString("actual_exit_ip", clean(ip)).apply(); }
    static String actualExitForCurrentSession(Context context) { SharedPreferences p=prefs(context);String session=p.getString("session_id","");String proofSession=p.getString("actual_exit_session","");if(session==null||session.isEmpty()||!session.equals(proofSession))return"";return p.getString("actual_exit_ip",""); }

    static String nodeIdFromBundleFile(File file) { if(file==null)return"";String name=file.getName();return name!=null&&name.matches("[0-9a-f]{32}\\.json")?name.substring(0,32):""; }

    private static SharedPreferences.Editor baseSession(Context context,String session,String logical,String runtime,String base){return prefs(context).edit().putString("session_id",session).putString("phase","connecting").putString("logical_mode",clean(logical)).putString("runtime_mode",clean(runtime)).putString("actual_base",clean(base)).putString("fallback","").putString("warning","").putString("path_proof","pending").putBoolean("connected",false).putLong("path_generation",0L).remove("actual_exit_ip").remove("actual_exit_session");}
    private static String existingOrNewSession(SharedPreferences p){String session=p.getString("session_id","");return session==null||session.isEmpty()?UUID.randomUUID().toString():session;}
    private static SharedPreferences.Editor clearRouterGraph(SharedPreferences.Editor e){return e.remove("active_node_id").remove("active_entry_id").remove("active_exit_id");}
    private static SharedPreferences.Editor clearExternal(SharedPreferences.Editor e){return e.remove("active_external_id").remove("active_external_name").remove("active_external_protocol").remove("expected_external_ip");}
    private static SharedPreferences.Editor clearGraphAndExternal(SharedPreferences.Editor e){return clearExternal(clearRouterGraph(e));}
    private static SharedPreferences.Editor clearAllIdentity(SharedPreferences.Editor e){return clearGraphAndExternal(e).remove("actual_exit_ip").remove("actual_exit_session").remove("path_generation");}
    private static String clean(String value){return value==null?"":value.replace('\n',' ').replace('\r',' ').trim();}
    private AndroidHomeStateStore(){}
}
