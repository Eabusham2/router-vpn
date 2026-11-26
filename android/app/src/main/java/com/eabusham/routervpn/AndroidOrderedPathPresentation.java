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
        final boolean imported, testing;
        final double httpResponseMs;
        Member(AndroidNodeStore.ChainSource source,String mode,double response,boolean testing)throws Exception {
            id=source.id;imported=source.imported;name=imported?source.external().name:source.profile().optString("name",source.profileId);this.mode=mode;httpResponseMs=response;this.testing=testing;
        }
    }
    final List<Member> members;
    final boolean live, testing;
    final String requestedExecution, selectedExecution, comparisonDetails;
    private final AndroidNodeCandidatePreparation preparation;
    private final String selection,homeSession;
    private final long homeGeneration;

    private AndroidOrderedPathPresentation(List<Member> members,boolean live,boolean testing,AndroidNodeCandidatePreparation preparation,String selection,AndroidHomeStateStore.Snapshot home,String requested,String selected,String comparisonDetails) {
        this.members=Collections.unmodifiableList(new ArrayList<>(members));this.live=live;this.testing=testing;this.preparation=preparation;this.selection=selection;
        homeSession=home.sessionId;homeGeneration=home.pathGeneration;requestedExecution=requested;selectedExecution=selected;this.comparisonDetails=comparisonDetails;
    }

    static boolean configured(Context context) {
        SharedPreferences p=context.getSharedPreferences("router-vpn-unified",Context.MODE_PRIVATE);
        synchronized(p) { return "router-vpn".equals(p.getString("selected_kind","router-vpn"))&&p.getBoolean("multihop_on",false)&&!p.getString("multihop_nodes","").isEmpty(); }
    }

    /** Call on a worker: complete source and retained native-owner checks can block. */
    static AndroidOrderedPathPresentation capture(Context context,AndroidNodeStore nodes,AndroidStandardExitStore exits,AndroidNodeChainRuntime runtime)throws Exception {
        String choice=selection(context);AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
        final AndroidNodeCandidatePreparation preparation;final boolean testing;
        synchronized(AndroidNodeCandidatePreparation.class){preparation=AndroidNodeCandidatePreparation.retained();testing=AndroidNodeCandidatePreparation.busy();}
        boolean live=!testing&&home.connected&&"node-chain".equals(home.logicalMode);
        List<AndroidNodeStore.ChainSource> sources;List<String> modes;JSONObject progress=null;String requested,selected="";
        if(live) {
            AndroidNodeChainRuntime.ActiveCapture active=runtime.captureActive();
            if(active==null||active.pathGeneration!=home.pathGeneration||!active.homeSession.equals(home.sessionId))throw new IllegalStateException("The ordered display lost its current native owner.");
            sources=active.sources;modes=active.modes;progress=new JSONObject(active.progressJSON);
            requested=active.requestedExecution;selected=active.selectedExecution;
            if(!java.util.Arrays.asList("local","server","auto").contains(requested)
                    ||!java.util.Arrays.asList("local","server").contains(selected)||!"auto".equals(requested)&&!requested.equals(selected)
                    ||!progress.optBoolean("ready")||!progress.optBoolean("complete")||!selected.equals(progress.optString("execution")))
                throw new IllegalStateException("The ordered proof receipt lost its current selected execution.");
        } else {
            if(!configured(context))return null;
            AndroidNodeStore.ChainCapture captured=new AndroidConnectionProfileStore(context,nodes,exits).currentOrderedPath();
            sources=captured.members;modes=captured.modes;requested=captured.execution;
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
                if(sources.get(i).imported ? !"public-path".equals(prefix.optString("kind")) : prefix.has("kind")&&!"private-node".equals(prefix.optString("kind")))throw new IllegalStateException("The ordered proof changed its private or public path identity.");
                ms=prefix.getDouble("response_ms");
                if(!Double.isFinite(ms)||ms<=0)throw new IllegalStateException("The ordered HTTP proof response is unavailable.");
            }
            values.add(new Member(sources.get(i),modes.get(i),ms,testing&&preparation.testsSavedPosition(i)));
        }
        String details=live&&"auto".equals(requested)
                ?comparisonDetails(progress.optJSONObject("comparison"),sources.get(0).profileId,sources.get(sources.size()-1).profileId,selected):"";
        AndroidOrderedPathPresentation out=new AndroidOrderedPathPresentation(values,live,testing,preparation,choice,home,requested,selected,details);
        if(!out.current(context))throw new IllegalStateException("The ordered display changed during capture.");
        return out;
    }

    private static String comparisonLane(JSONObject candidate,String entry,String exit) {
        if(candidate==null||!"ordered-node-chain".equals(candidate.optString("transport"))
                ||!entry.equals(candidate.optString("entry_id"))||!exit.equals(candidate.optString("exit_id")))return "";
        String lane=candidate.optString("execution");
        return "local".equals(lane)||"server".equals(lane)?lane:"";
    }

    private static double positiveNumber(JSONObject value,String key) {
        Object raw=value.opt(key);
        double number=raw instanceof Number?((Number)raw).doubleValue():Double.NaN;
        return Double.isFinite(number)&&number>0?number:Double.NaN;
    }

    private static String comparisonDetails(JSONObject comparison,String entry,String exit,String selected) {
        String unavailable="Comparison trial scores unavailable for this captured route";
        if(comparison==null||!selected.equals(comparisonLane(comparison.optJSONObject("winner"),entry,exit))
                ||!(comparison.opt("target") instanceof String)||comparison.optString("target").isEmpty())return unavailable;
        JSONArray rows=comparison.optJSONArray("measurements");
        if(rows==null||rows.length()!=2)return unavailable;
        java.util.Set<String> seen=new java.util.HashSet<>();
        StringBuilder details=new StringBuilder("Comparison trial scores");
        for(int i=0;i<rows.length();i++) {
            JSONObject row=rows.optJSONObject(i);
            String lane=row==null?"":comparisonLane(row.optJSONObject("candidate"),entry,exit);
            if(lane.isEmpty()||!seen.add(lane)||!(row.opt("eligible") instanceof Boolean))return unavailable;
            String name="server".equals(lane)?"Server":"Local";
            if(row.optBoolean("eligible")) {
                double last=positiveNumber(row,"last_node_ms"),external=positiveNumber(row,"external_ms"),score=positiveNumber(row,"score_ms");
                if(!Double.isFinite(last)||!Double.isFinite(external)||!Double.isFinite(score)
                        ||Math.abs(score-(last/2+external/2))>Math.max(0.000001,score*0.000001))return unavailable;
                details.append(String.format(java.util.Locale.US,"\n%s: (last node %.1f + external %.1f) / 2 = %.1f ms",name,last,external,score));
            } else {
                if(selected.equals(lane))return unavailable;
                details.append("\n").append(name).append(": rejected — no valid comparison score");
            }
        }
        return details.toString();
    }

    String executionLabel() {
        String requested="auto".equals(requestedExecution)?"Compare both":"server".equals(requestedExecution)?"Server":"Local";
        return live&&"auto".equals(requestedExecution)?requested+" → "+("server".equals(selectedExecution)?"Server":"Local"):requested;
    }

    /** Lightweight main-thread admission: only immutable Home and preference values. */
    boolean current(Context context) {
        AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
        synchronized(AndroidNodeCandidatePreparation.class){
            if(preparation!=AndroidNodeCandidatePreparation.retained()||testing!=AndroidNodeCandidatePreparation.busy())return false;
        }
        return homeGeneration==home.pathGeneration&&homeSession.equals(home.sessionId)
                &&(!live||home.connected&&"node-chain".equals(home.logicalMode))&&selection.equals(selection(context));
    }

    private static String selection(Context context) {
        SharedPreferences p=context.getSharedPreferences("router-vpn-unified",Context.MODE_PRIVATE);
        synchronized(p) {
            return new JSONArray().put(p.getString("selected_kind","router-vpn")).put(p.getString("selected_id",""))
                    .put(p.getBoolean("multihop_on",false)).put(p.getString("multihop_nodes","")).put(p.getString("multihop_execution","local")).toString();
        }
    }
}
