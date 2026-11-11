package com.eabusham.routervpn;

import android.content.Context;
import android.content.SharedPreferences;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Worker-produced display values. Reading this receipt never enters native code
 * or rereads a private bundle. It grants no authority to launch a connection. */
final class AndroidOrderedPathPresentation {
    static final class Member {
        final String id, name, mode;
        final double httpResponseMs;
        Member(AndroidNodeStore.ChainSource source,String mode,double response)throws Exception {
            id=source.id;name=source.profile().optString("name",source.profileId);this.mode=mode;httpResponseMs=response;
        }
    }
    final List<Member> members;
    final boolean live;
    private final String selection,homeSession;
    private final long homeGeneration;

    private AndroidOrderedPathPresentation(List<Member> members,boolean live,String selection,AndroidHomeStateStore.Snapshot home) {
        this.members=Collections.unmodifiableList(new ArrayList<>(members));this.live=live;this.selection=selection;
        homeSession=home.sessionId;homeGeneration=home.pathGeneration;
    }

    static boolean configured(Context context) {
        SharedPreferences p=context.getSharedPreferences("router-vpn-unified",Context.MODE_PRIVATE);
        synchronized(p) { return "router-vpn".equals(p.getString("selected_kind","router-vpn"))&&p.getBoolean("multihop_on",false)&&!p.getString("multihop_nodes","").isEmpty(); }
    }

    /** Call on a worker: complete source and retained native-owner checks can block. */
    static AndroidOrderedPathPresentation capture(Context context,AndroidNodeStore nodes,AndroidStandardExitStore exits,AndroidNodeChainRuntime runtime)throws Exception {
        String choice=selection(context);AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
        boolean live=home.connected&&"node-chain".equals(home.logicalMode);
        List<AndroidNodeStore.ChainSource> sources;List<String> modes;JSONObject progress=null;
        if(live) {
            AndroidNodeChainRuntime.ActiveCapture active=runtime.captureActive();
            if(active==null||active.pathGeneration!=home.pathGeneration||!active.homeSession.equals(home.sessionId))throw new IllegalStateException("The ordered display lost its current native owner.");
            sources=active.sources;modes=active.modes;progress=new JSONObject(active.progressJSON);
            if(!progress.optBoolean("ready")||!progress.optBoolean("complete")||!"local".equals(progress.optString("execution")))throw new IllegalStateException("The ordered proof receipt is no longer ready.");
        } else {
            if(!configured(context))return null;
            AndroidNodeStore.ChainCapture captured=new AndroidConnectionProfileStore(context,nodes,exits).currentOrderedPath();
            sources=captured.members;modes=captured.modes;
        }
        if(sources.size()<2||sources.size()!=modes.size())throw new IllegalStateException("The complete ordered display is unavailable.");
        JSONArray prefixes=live?progress.getJSONArray("prefixes"):new JSONArray();
        if(live&&prefixes.length()!=sources.size())throw new IllegalStateException("Every original ordered prefix must have its own proof receipt.");
        List<Member> values=new ArrayList<>();
        for(int i=0;i<sources.size();i++) {
            double ms=0;
            if(live) {
                JSONObject prefix=prefixes.getJSONObject(i);
                if(prefix.optInt("position",-1)!=i||!sources.get(i).profileId.equals(prefix.optString("profile_id"))||!prefix.optBoolean("proven"))throw new IllegalStateException("The ordered response belongs to another prefix.");
                ms=prefix.getDouble("response_ms");
                if(!Double.isFinite(ms)||ms<=0)throw new IllegalStateException("The ordered HTTP proof response is unavailable.");
            }
            values.add(new Member(sources.get(i),modes.get(i),ms));
        }
        AndroidOrderedPathPresentation out=new AndroidOrderedPathPresentation(values,live,choice,home);
        if(!out.current(context))throw new IllegalStateException("The ordered display changed during capture.");
        return out;
    }

    /** Lightweight main-thread admission: only immutable Home and preference values. */
    boolean current(Context context) {
        AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
        return homeGeneration==home.pathGeneration&&homeSession.equals(home.sessionId)
                &&(!live||home.connected&&"node-chain".equals(home.logicalMode))&&selection.equals(selection(context));
    }

    private static String selection(Context context) {
        SharedPreferences p=context.getSharedPreferences("router-vpn-unified",Context.MODE_PRIVATE);
        synchronized(p) {
            return new JSONArray().put(p.getString("selected_kind","router-vpn")).put(p.getString("selected_id",""))
                    .put(p.getBoolean("multihop_on",false)).put(p.getString("multihop_nodes","")).toString();
        }
    }
}
