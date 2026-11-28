package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;

/** A native completion's fixed lifetime is never renewed by reading it. */
final class AndroidNodeCandidateResult {
    final String id,name,source;
    final long measuredAt,expiresAt;
    final double score;
    final String requestedExecution,winningExecution,executionSource,executionCapture,originalAppendSource,requestID,selection,executionDetails;
    private AndroidNodeCandidateResult(String id,String name,String source,long measured,long expires,double score){
        this.id=id;this.name=name;this.source=source;measuredAt=measured;expiresAt=expires;this.score=score;
        requestedExecution=winningExecution=executionSource=executionCapture=originalAppendSource=requestID=selection=executionDetails="";
    }
    private AndroidNodeCandidateResult(AndroidNodeCandidateResult value,AndroidNodeCandidatePrefixCapture prefix,String request,String capture,String winner,String selection,String details){
        id=value.id;name=value.name;source=value.source;measuredAt=value.measuredAt;expiresAt=value.expiresAt;score=value.score;
        requestedExecution=prefix.requestedExecution();winningExecution=winner;executionSource=prefix.sourceSHA256;
        executionCapture=capture;originalAppendSource=prefix.original.append.sourceSHA256;requestID=request;this.selection=selection;executionDetails=details;
    }
    static AndroidNodeCandidateResult capture(String raw,String request,JSONObject metadata,String id,String name,long now)throws Exception{
        return capture(raw,request,metadata,id,name,now,false,false);
    }
    static AndroidNodeCandidateResult captureSelectedServer(String raw,String request,JSONObject metadata,String id,String name,long now)throws Exception{
        if(!"server".equals(metadata.getString("execution"))||!"routed-candidate-response".equals(metadata.getString("measurement")))throw new IllegalStateException("The retained Server response owner changed.");
        return capture(raw,request,metadata,id,name,now,true,false);
    }
    static AndroidNodeCandidateResult captureSelectedPublic(String raw,String request,JSONObject metadata,String id,String name,long now,
            int prefix,String prefixId,String requested,String winner,String source,String config)throws Exception{
        if (!"routed-public-candidate-response".equals(metadata.getString("measurement"))
                || prefix < 1 || prefix > 94 || prefixId.isEmpty() || !prefixId.equals(metadata.getString("prefix_id")) || integer(metadata,"prefix_position") != prefix
                || !requested.equals(metadata.getString("requested_execution")) || !winner.equals(metadata.getString("execution"))
                || !("server".equals(winner) && ("server".equals(requested) || "auto".equals(requested)) || "local".equals(winner) && "auto".equals(requested))
                || integer(metadata,"selection_epoch") <= 0 || !source.matches("[0-9a-f]{64}") || !config.matches("[0-9a-f]{64}")
                || source.equals(metadata.getString("source_sha256")) || !source.equals(metadata.getString("preparation_source_sha256"))
                || !config.equals(metadata.getString("preparation_config_sha256")))
            throw new IllegalStateException("The registered public candidate lost its original selected route.");
        return capture(raw,request,metadata,id,name,now,"server".equals(winner),true);
    }
    static AndroidNodeCandidateResult captureAppendExecution(String raw,String request,JSONObject metadata,String id,String name,long now,
            AndroidNodeCandidatePrefixCapture prefix)throws Exception {
        if(prefix==null||!prefix.appendExecution()||raw==null||raw.length()>32768)throw executionInvalid();
        prefix.requireCurrent();
        JSONObject status=new JSONObject(raw);
        keys(status,java.util.Set.of("request_id","stage","complete","drained","results","schema","measurement","prefix_position","prefix_id","capture_sha256","purpose","source_sha256",
                "execution_source_sha256","execution_capture_sha256","requested_execution","winning_execution"),
                java.util.Set.of("failure","candidate_id","candidate_source_sha256","measured_at","expires_at","selection"));
        String capture=prefix.plan.captureSHA256(),requested=prefix.requestedExecution();
        if(!capture.matches("[0-9a-f]{64}")||!"draft-prefix-append-execution".equals(status.getString("purpose"))
                ||!"draft-prefix-append-execution".equals(metadata.getString("purpose"))||!metadata.getString("capture_sha256").isEmpty()
                ||!metadata.getString("execution_capture_sha256").isEmpty()||!"routed-candidate-response".equals(status.getString("measurement"))
                ||integer(status,"schema")!=1||!request.equals(status.getString("request_id"))||!request.matches("[0-9a-f]{32}")
                ||!Boolean.TRUE.equals(status.get("complete"))||!Boolean.TRUE.equals(status.get("drained"))
                ||!prefix.original.append.sourceSHA256.equals(status.getString("source_sha256"))||!prefix.sourceSHA256.equals(status.getString("execution_source_sha256"))
                ||!requested.equals(status.getString("requested_execution"))||!requested.equals(metadata.getString("requested_execution"))
                ||!capture.equals(status.getString("capture_sha256"))||!capture.equals(status.getString("execution_capture_sha256"))
                ||integer(metadata,"prefix_position")!=integer(status,"prefix_position")||!metadata.getString("prefix_id").equals(status.getString("prefix_id")))throw executionInvalid();
        // Failed lanes remain genuine no-score rows; no winner or successful
        // comparison is fabricated to make a negative result selectable.
        if(!"complete".equals(status.getString("stage"))||!status.optString("failure").isEmpty())return null;
        JSONArray rows=status.getJSONArray("results");
        if(rows.length()!=1||!Boolean.TRUE.equals(rows.getJSONObject(0).opt("ready")))return null;
        String winner=status.getString("winning_execution"),selection="",details;
        if("server".equals(requested)) {
            if(!"server".equals(winner)||status.has("selection")||!prefix.plan.selectionJSON().isEmpty())throw executionInvalid();
            details="Server private response";
        } else if("auto".equals(requested)) {
            if(!java.util.Set.of("local","server").contains(winner)||!(status.opt("selection") instanceof JSONObject))throw executionInvalid();
            String original=prefix.plan.selectionJSON();
            if(original==null||original.isEmpty()||original.length()>16384)throw executionInvalid();
            JSONObject comparison=new JSONObject(original);
            if(!comparison.toString().equals(status.getJSONObject("selection").toString()))throw executionInvalid();
            String entry=prefix.original.append.original.members.get(0).profileId;
            details=compareDetails(comparison,entry,id,winner);selection=comparison.toString();
        } else throw executionInvalid();
        AndroidNodeCandidateResult measured=capture(raw,request,metadata,id,name,now,false,false,capture);
        if(measured==null)throw executionInvalid();
        prefix.requireCurrent();if(!capture.equals(prefix.plan.captureSHA256()))throw executionInvalid();
        return new AndroidNodeCandidateResult(measured,prefix,request,capture,winner,selection,details);
    }
    void requireAppendExecution(AndroidNodeCandidatePrefixCapture prefix,boolean live)throws Exception {
        if(prefix==null||!prefix.appendExecution()||prefix.original.append==null||!requestedExecution.equals(prefix.requestedExecution())
                ||!executionSource.equals(prefix.sourceSHA256)||!originalAppendSource.equals(prefix.original.append.sourceSHA256)
                ||!executionCapture.matches("[0-9a-f]{64}")||!requestID.matches("[0-9a-f]{32}")
                ||!AndroidNodeChainCapture.selectedResponseWinner(requestedExecution,winningExecution)
                ||live&&!executionCapture.equals(prefix.plan.captureSHA256()))throw executionInvalid();
        prefix.requireCurrent();
    }
    private static String compareDetails(JSONObject comparison,String entry,String candidate,String winner)throws Exception {
        keys(comparison,java.util.Set.of("target","measurements","winner","final"),java.util.Set.of());
        if(entry.isEmpty()||candidate.isEmpty()||entry.equals(candidate)||!java.util.Set.of("https://1.1.1.1/cdn-cgi/trace","https://1.0.0.1/cdn-cgi/trace").contains(comparison.getString("target")))throw executionInvalid();
        JSONArray measurements=comparison.getJSONArray("measurements");if(measurements.length()!=2)throw executionInvalid();
        java.util.Set<String> seen=new java.util.HashSet<>();double chosen=Double.NaN,minimum=Double.POSITIVE_INFINITY;
        StringBuilder details=new StringBuilder("Compare both");
        for(int i=0;i<measurements.length();i++) {
            JSONObject measured=measurements.getJSONObject(i);String lane=compareLane(measured.getJSONObject("candidate"),entry,candidate);
            if(!seen.add(lane))throw executionInvalid();double score=compareMeasurement(measured,entry,candidate);
            details.append(" • ").append(AndroidOrderedPathSelection.executionTitle(lane)).append(Double.isNaN(score)?" failed":String.format(java.util.Locale.US," %.2f ms",score));
            if(!Double.isNaN(score)){minimum=Math.min(minimum,score);if(lane.equals(winner))chosen=score;}
        }
        if(!seen.equals(java.util.Set.of("local","server"))||Double.isNaN(chosen)||chosen>minimum
                ||!winner.equals(compareLane(comparison.getJSONObject("winner"),entry,candidate)))throw executionInvalid();
        JSONObject last=comparison.getJSONObject("final");double finalScore=compareMeasurement(last,entry,candidate);
        if(Double.isNaN(finalScore)||!winner.equals(compareLane(last.getJSONObject("candidate"),entry,candidate)))throw executionInvalid();
        return details.append(" • Winner ").append(AndroidOrderedPathSelection.executionTitle(winner))
                .append(String.format(java.util.Locale.US,"; final recheck %.2f ms",finalScore)).toString();
    }
    private static String compareLane(JSONObject candidate,String entry,String exit)throws Exception {
        keys(candidate,java.util.Set.of("execution","transport","entry_id","exit_id"),java.util.Set.of());
        String lane=candidate.getString("execution");
        if(!java.util.Set.of("local","server").contains(lane)||!"ordered-prefix-append".equals(candidate.getString("transport"))
                ||!entry.equals(candidate.getString("entry_id"))||!exit.equals(candidate.getString("exit_id")))throw executionInvalid();
        return lane;
    }
    private static double compareMeasurement(JSONObject value,String entry,String exit)throws Exception {
        keys(value,java.util.Set.of("candidate","eligible"),java.util.Set.of("last_node_ms","external_ms","score_ms","failure"));
        compareLane(value.getJSONObject("candidate"),entry,exit);
        if(!(value.get("eligible") instanceof Boolean))throw executionInvalid();
        if(!value.getBoolean("eligible")) {
            if(value.has("score_ms")||value.optString("failure").isEmpty())throw executionInvalid();
            for(String key:new String[]{"last_node_ms","external_ms"})if(value.has(key))finite(value,key);
            return Double.NaN;
        }
        double last=finite(value,"last_node_ms"),external=finite(value,"external_ms"),score=finite(value,"score_ms");
        if(last<=0||external<=0||score<=0||!value.optString("failure").isEmpty()||Math.abs(score-(last/2+external/2))>0.000001)throw executionInvalid();
        return score;
    }
    private static void keys(JSONObject value,java.util.Set<String> required,java.util.Set<String> optional)throws Exception {
        for(String key:required)if(!value.has(key))throw executionInvalid();
        java.util.Iterator<String> keys=value.keys();while(keys.hasNext()){String key=keys.next();if(!required.contains(key)&&!optional.contains(key))throw executionInvalid();}
    }
    private static IllegalStateException executionInvalid(){return new IllegalStateException("The append response lost its original execution source, discovery capture or actual comparison.");}
    private static AndroidNodeCandidateResult capture(String raw,String request,JSONObject metadata,String id,String name,long now,boolean selectedServerResponse,boolean selectedPublic)throws Exception{
        return capture(raw,request,metadata,id,name,now,selectedServerResponse,selectedPublic,metadata.getString("capture_sha256"));
    }
    private static AndroidNodeCandidateResult capture(String raw,String request,JSONObject metadata,String id,String name,long now,boolean selectedServerResponse,boolean selectedPublic,String expectedCapture)throws Exception{
        if(raw==null||raw.length()>32768)throw new IllegalStateException("Invalid candidate receipt size");
        JSONObject status=new JSONObject(raw);
        String metric=metadata.optString("measurement","routed-tcp-connect");
        boolean privateResponse="routed-candidate-response".equals(metric);
        boolean publicResponse="routed-public-candidate-response".equals(metric);
        if(publicResponse && !selectedPublic && (metadata.has("execution") || metadata.has("requested_execution") || metadata.has("selection_epoch")
                || metadata.has("preparation_source_sha256") || metadata.has("preparation_config_sha256") || selectedServerResponse))throw new IllegalStateException("A public candidate response cannot inherit a selected execution.");
        if(!publicResponse&&!privateResponse&&!"routed-tcp-connect".equals(metric))throw new IllegalStateException("Unsupported candidate receipt measurement");
        if(integer(status,"schema")!=1||!metric.equals(status.getString("measurement"))
                ||!request.equals(status.getString("request_id"))||!Boolean.TRUE.equals(status.get("complete"))||!Boolean.TRUE.equals(status.get("drained"))
                ||!"complete".equals(status.getString("stage"))||!status.optString("failure").isEmpty()
                ||!expectedCapture.equals(status.getString("capture_sha256"))
                ||integer(metadata,"prefix_position")!=integer(status,"prefix_position")
                ||!metadata.getString("prefix_id").equals(status.getString("prefix_id"))
                ||!id.equals(status.getString("candidate_id")))throw new IllegalStateException("Candidate receipt belongs to another original prefix or request");
        String source="";JSONArray targets=metadata.getJSONArray("targets");
        for(int i=0;i<targets.length();i++)if(id.equals(targets.getJSONObject(i).getString("id"))){if(!source.isEmpty())throw new IllegalStateException("Duplicate candidate receipt");source=targets.getJSONObject(i).getString("source_sha256");}
        if(!source.matches("[0-9a-f]{64}")||!source.equals(status.getString("candidate_source_sha256")))throw new IllegalStateException("Candidate original source changed");
        long measured=integer(status,"measured_at"),expires=integer(status,"expires_at");
        if(measured<=0||expires-measured!=120000||now<measured||now>=expires)throw new IllegalStateException("Candidate result expired; retest this prefix");
        JSONArray rows=status.getJSONArray("results");if(rows.length()!=1)throw new IllegalStateException("Candidate receipt has another result set");
        JSONObject row=rows.getJSONObject(0);
        if(!id.equals(row.getString("node_id"))||!"candidate".equals(row.getString("role"))||!(publicResponse?"public-exit-response":privateResponse?"private-agent-response":"tcp-connect").equals(row.getString("kind")))throw new IllegalStateException("Candidate result belongs to another original target.");
        if((selectedServerResponse || selectedPublic) && Boolean.FALSE.equals(row.get("ready")) && row.get("failure") instanceof String && !row.getString("failure").isEmpty()
                && !row.has("benchmark") && (!row.has("candidate_disposition") || selectedServerResponse && "not-registered".equals(row.get("candidate_disposition"))))return null;
        if(row.has("candidate_disposition")||!Boolean.TRUE.equals(row.get("ready"))||!row.optString("failure").isEmpty())throw new IllegalStateException("Candidate has no complete score");
        JSONObject benchmark=row.getJSONObject("benchmark"),distribution=benchmark.getJSONObject("distribution");
        if(publicResponse&&!"https://1.1.1.1/cdn-cgi/trace".equals(benchmark.optString("endpoint")))throw new IllegalStateException("The public candidate did not verify its original HTTPS trace endpoint.");
        if(integer(benchmark,"schema")!=1||!metric.equals(benchmark.getString("measurement"))||integer(benchmark,"attempts")!=50||integer(benchmark,"failed")!=0||integer(distribution,"samples")!=50)throw new IllegalStateException("All fifty selected-prefix samples must succeed");
        double min=finite(distribution,"min_ms"),median=finite(distribution,"median_ms"),average=finite(distribution,"average_ms"),p90=finite(distribution,"p90_ms"),max=finite(distribution,"max_ms"),jitter=finite(distribution,"jitter_ms"),score=finite(benchmark,"trimmed_mean_ms");
        if(publicResponse && (min<=0 || max>60000 || selectedPublic && selectedServerResponse && max>2500))
            throw new IllegalStateException("Public candidate timing exceeds the original measurement interval");
        if(min>median||median>p90||p90>max||average<min||average>max||score<min||score>max||jitter>max-min)throw new IllegalStateException("Candidate distribution is inconsistent");
        return new AndroidNodeCandidateResult(id,name,source,measured,expires,score);
    }
    boolean current(long now){return now>=measuredAt&&now<expiresAt;}
    private static long integer(JSONObject value,String key)throws Exception{Object raw=value.get(key);if(!(raw instanceof Integer)&&!(raw instanceof Long))throw new IllegalStateException("Candidate counter is not an integer");return ((Number)raw).longValue();}
    private static double finite(JSONObject value,String key)throws Exception{Object raw=value.get(key);if(!(raw instanceof Number))throw new IllegalStateException("Candidate sample is not numeric");double n=((Number)raw).doubleValue();if(!Double.isFinite(n)||n<0)throw new IllegalStateException("Candidate sample is invalid");return n;}
}
