package com.eabusham.routervpn;

import org.json.JSONObject;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** Durable direct 50-attempt benchmark; separate from quick and current-path RTT. */
final class AndroidNodeStatistics {
    private static final int MAX_RECORD=8192;
    static final class Record {
        final String id,source,endpoint,path;
        final long measuredAt;
        final double min,median,average,trimmedMean,p90,max;
        final int samples,failed;
        Record(String id,String source,String endpoint,String path,long at,double min,double median,double average,double trimmedMean,double p90,double max,int samples,int failed){
            this.id=id;this.source=source;this.endpoint=endpoint;this.path=path;measuredAt=at;this.min=min;this.median=median;this.average=average;this.trimmedMean=trimmedMean;this.p90=p90;this.max=max;this.samples=samples;this.failed=failed;
        }
        boolean eligible(){return samples==50&&failed==0;}
        String detail(){return String.format(Locale.US,"Last 50-attempt direct TCP benchmark\nMedian %.1f ms • min %.1f • avg %.1f • 10%% trimmed mean %.1f • p90 %.1f • max %.1f\n%d successful / %d failed\nMeasured %s\n%s",median,min,average,trimmedMean,p90,max,samples,failed,new java.util.Date(measuredAt).toString(),eligible()?"Eligible for Lowest latency. Current-path RTT and quick probes are stored separately.":"Not eligible for Lowest latency: a complete successful 50-sample run is required.");}
    }
    private AndroidNodeStatistics(){}
    static String source(AndroidNodeStore.Node node)throws Exception{
        if(node==null||node.file==null||!node.id.matches("[0-9a-f]{32}")||!node.file.getName().equals(node.id+".json"))throw new IllegalStateException("Stored node identity is invalid.");
        byte[] bytes=AndroidPrivateFileStore.read(node.file,AndroidNodeStore.MAX_BUNDLE);
        JSONObject bundle=new JSONObject(new String(bytes,StandardCharsets.UTF_8));AndroidNodeStore.validateBundle(bundle);
        if(!node.id.equals(AndroidNodeStore.deriveId(bundle,bytes)))throw new IllegalStateException("The node source no longer matches its stored identity.");
        return AndroidTelemetryNetwork.digest(bytes);
    }
    static synchronized void save(AndroidNodeStore.Node node,Record record)throws Exception{
        validate(record);
        if(!node.id.equals(record.id)||!node.endpoint.equals(record.endpoint)||!source(node).equals(record.source))throw new IllegalStateException("The benchmark node changed before the durable result could be saved.");
        JSONObject json=new JSONObject().put("schema",1).put("node_id",record.id).put("source_sha256",record.source).put("endpoint",record.endpoint)
                .put("scope","direct").put("path_identity",record.path).put("measured_at_ms",record.measuredAt).put("attempts",50)
                .put("samples",record.samples).put("failed",record.failed).put("min_ms",record.min).put("median_ms",record.median)
                .put("average_ms",record.average).put("trimmed_mean_ms",record.trimmedMean).put("p90_ms",record.p90).put("max_ms",record.max);
        AndroidPrivateFileStore.write(file(node),json.toString().getBytes(StandardCharsets.UTF_8),MAX_RECORD);
    }
    static synchronized Record load(AndroidNodeStore.Node node){
        try{
            File file=file(node);if(!file.exists())return null;
            JSONObject json=new JSONObject(new String(AndroidPrivateFileStore.read(file,MAX_RECORD),StandardCharsets.UTF_8));
            if(json.optInt("schema")!=1||json.optInt("attempts")!=50||!"direct".equals(json.optString("scope")))return null;
            Record record=new Record(json.getString("node_id"),json.getString("source_sha256"),json.getString("endpoint"),json.getString("path_identity"),json.getLong("measured_at_ms"),json.getDouble("min_ms"),json.getDouble("median_ms"),json.getDouble("average_ms"),json.getDouble("trimmed_mean_ms"),json.getDouble("p90_ms"),json.getDouble("max_ms"),json.getInt("samples"),json.getInt("failed"));
            validate(record);
            if(!node.id.equals(record.id)||!node.endpoint.equals(record.endpoint)||!source(node).equals(record.source))return null;
            return record;
        }catch(Exception stale){return null;}
    }
    static void remove(AndroidNodeStore.Node node)throws Exception{AndroidPrivateFileStore.remove(file(node),MAX_RECORD);}
    private static File file(AndroidNodeStore.Node node){return new File(node.file.getParentFile(),"latency-"+node.id+".json");}
    private static void validate(Record r){
        if(r==null||!r.id.matches("[0-9a-f]{32}")||!r.source.matches("[0-9a-f]{64}")||r.endpoint.isEmpty()||r.path.isEmpty()||r.path.length()>512||r.measuredAt<=0||r.measuredAt>System.currentTimeMillis()+60000||!r.eligible())
            throw new IllegalArgumentException("Only a complete source-bound benchmark with 50 successful samples may replace saved statistics.");
        for(double n:new double[]{r.min,r.median,r.average,r.trimmedMean,r.p90,r.max})if(!Double.isFinite(n)||n<=0||n>60000)throw new IllegalArgumentException("Invalid measured latency.");
        if(r.min>r.median||r.median>r.p90||r.p90>r.max||r.average<r.min||r.average>r.max||r.trimmedMean<r.min||r.trimmedMean>r.max)throw new IllegalArgumentException("Inconsistent measured latency statistics.");
    }
}
