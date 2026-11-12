package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;

/** A native completion's fixed lifetime is never renewed by reading it. */
final class AndroidNodeCandidateResult {
    final String id,name,source;
    final long measuredAt,expiresAt;
    final double score;
    private AndroidNodeCandidateResult(String id,String name,String source,long measured,long expires,double score){this.id=id;this.name=name;this.source=source;measuredAt=measured;expiresAt=expires;this.score=score;}
    static AndroidNodeCandidateResult capture(String raw,String request,JSONObject metadata,String id,String name,long now)throws Exception{
        if(raw==null||raw.length()>32768)throw new IllegalStateException("Invalid candidate receipt size");
        JSONObject status=new JSONObject(raw);
        if(integer(status,"schema")!=1||!"routed-tcp-connect".equals(status.getString("measurement"))
                ||!request.equals(status.getString("request_id"))||!Boolean.TRUE.equals(status.get("complete"))||!Boolean.TRUE.equals(status.get("drained"))
                ||!"complete".equals(status.getString("stage"))||!status.optString("failure").isEmpty()
                ||!metadata.getString("capture_sha256").equals(status.getString("capture_sha256"))
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
        if(!id.equals(row.getString("node_id"))||!"candidate".equals(row.getString("role"))||!"tcp-connect".equals(row.getString("kind"))||!Boolean.TRUE.equals(row.get("ready"))||!row.optString("failure").isEmpty())throw new IllegalStateException("Candidate has no complete score");
        JSONObject benchmark=row.getJSONObject("benchmark"),distribution=benchmark.getJSONObject("distribution");
        if(integer(benchmark,"schema")!=1||!"routed-tcp-connect".equals(benchmark.getString("measurement"))||integer(benchmark,"attempts")!=50||integer(benchmark,"failed")!=0||integer(distribution,"samples")!=50)throw new IllegalStateException("All fifty TCP samples must succeed");
        double min=finite(distribution,"min_ms"),median=finite(distribution,"median_ms"),average=finite(distribution,"average_ms"),p90=finite(distribution,"p90_ms"),max=finite(distribution,"max_ms"),jitter=finite(distribution,"jitter_ms"),score=finite(benchmark,"trimmed_mean_ms");
        if(min>median||median>p90||p90>max||average<min||average>max||score<min||score>max||jitter>max-min)throw new IllegalStateException("Candidate distribution is inconsistent");
        return new AndroidNodeCandidateResult(id,name,source,measured,expires,score);
    }
    boolean current(long now){return now>=measuredAt&&now<expiresAt;}
    private static long integer(JSONObject value,String key)throws Exception{Object raw=value.get(key);if(!(raw instanceof Integer)&&!(raw instanceof Long))throw new IllegalStateException("Candidate counter is not an integer");return ((Number)raw).longValue();}
    private static double finite(JSONObject value,String key)throws Exception{Object raw=value.get(key);if(!(raw instanceof Number))throw new IllegalStateException("Candidate sample is not numeric");double n=((Number)raw).doubleValue();if(!Double.isFinite(n)||n<0)throw new IllegalStateException("Candidate sample is invalid");return n;}
}
