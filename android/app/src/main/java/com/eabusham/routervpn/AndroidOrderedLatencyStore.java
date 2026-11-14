package com.eabusham.routervpn;

import android.content.Context;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Separate historical ordered-prefix responses. No record authorizes a route,
 * direct-node ranking, candidate selection, throughput or native readiness. */
final class AndroidOrderedLatencyStore {
    static final String FILE_NAME="ordered-node-fifty-v1.json";
    static final String PRIVATE="routed-private-response-including-connection";
    static final String PUBLIC="routed-https-response-after-tls";
    static final String ENDPOINT="https://speed.cloudflare.com/__down?bytes=1";
    static final int MAX_RECEIPT=8192,MAX_STORE=1024*1024,MAX_RECORDS=128;
    interface Guard {void require()throws Exception;}
    static final class Record {
        final String raw,source,config,generation,node,request,kind,role,measurement;
        final int position,count;
        final long measuredAt;
        final double min,median,average,trimmed,p90,max,jitter;
        Record(String raw)throws Exception {
            if(raw==null||raw.isEmpty()||raw.getBytes(StandardCharsets.UTF_8).length>MAX_RECEIPT)throw invalid();
            io.nekohasekai.libbox.Libbox.routerValidatePrivateNodeJSON(raw);
            JSONObject value=new JSONObject(raw);
            keys(value,"schema","source_sha256","config_sha256","generation_sha256","position","node_id","request_id","measured_at","result");
            source=text(value,"source_sha256");config=text(value,"config_sha256");generation=text(value,"generation_sha256");node=text(value,"node_id");request=text(value,"request_id");
            long at=integer(value,"position");if(at<0||at>7)throw invalid();position=(int)at;measuredAt=integer(value,"measured_at");
            if(integer(value,"schema")!=1||!sha(source)||!sha(config)||!sha(generation)||!node.matches("[A-Za-z0-9_-]{1,64}")||!request.matches("[0-9a-f]{32}")||measuredAt<=0||measuredAt>System.currentTimeMillis()+60000)throw invalid();
            JSONObject result=value.getJSONObject("result");
            keys(result,"node_id","role","kind","label","ready","benchmark");
            kind=text(result,"kind");role=text(result,"role");
            if(!node.equals(text(result,"node_id"))||!bool(result,"ready")||!Arrays.asList("entry","intermediate","exit").contains(role)||!("private-node".equals(kind)||"public-path".equals(kind)))throw invalid();
            // Native ordered labels contain only positions, never a user name,
            // address or credential. Reject a label outside that closed form.
            String label=text(result,"label");
            if("public-path".equals(kind)) {
                if(position!=1||!"intermediate".equals(role)||!"Cumulative path through custom node 2 of 3 → Cloudflare edge".equals(label))throw invalid();
                count=3;
            } else {
                if(!label.matches("Cumulative path through node [1-8] of [2-8]")||!label.startsWith("Cumulative path through node "+(position+1)+" of "))throw invalid();
                count=label.charAt(label.length()-1)-'0';
                if(position>=count||!role.equals(position==0?"entry":position==count-1?"exit":"intermediate"))throw invalid();
            }
            JSONObject benchmark=result.getJSONObject("benchmark"),distribution=benchmark.getJSONObject("distribution");
            keys(benchmark,"schema","measurement","endpoint","attempts","failed","distribution","trimmed_mean_ms");
            keys(distribution,"samples","min_ms","median_ms","average_ms","p90_ms","max_ms","jitter_ms");
            measurement=text(benchmark,"measurement");
            if(integer(benchmark,"schema")!=1||integer(benchmark,"attempts")!=50||integer(benchmark,"failed")!=0||integer(distribution,"samples")!=50
                    ||!("public-path".equals(kind)?PUBLIC:PRIVATE).equals(measurement)
                    ||!("public-path".equals(kind)?ENDPOINT:"").equals(text(benchmark,"endpoint")))throw invalid();
            min=number(distribution,"min_ms");median=number(distribution,"median_ms");average=number(distribution,"average_ms");p90=number(distribution,"p90_ms");max=number(distribution,"max_ms");jitter=number(distribution,"jitter_ms");trimmed=number(benchmark,"trimmed_mean_ms");
            for(double n:new double[]{min,median,average,p90,max,trimmed})if(n<=0||n>60000)throw invalid();
            if(jitter<0||jitter>max-min+1e-9||min>median||median>p90||p90>max||average<min||average>max||trimmed<min||trimmed>max)throw invalid();
            this.raw=raw;
        }
        String key(){return source+":"+config+":"+position+":"+node+":"+kind+":"+measurement;}
        void require(String source,String config,int position,String node,String kind,String request)throws Exception {
            if(!this.source.equals(source)||!this.config.equals(config)||this.position!=position||!this.node.equals(node)||!this.kind.equals(kind)||!this.request.equals(request))throw invalid();
        }
        String detail(){return String.format(Locale.US,"Historical ordered-node benchmark • %d / %s\n50 successful responses • 0 failed\nMedian %.1f ms • min %.1f • average %.1f\n10%% trimmed mean %.1f • p90 %.1f • max %.1f • jitter %.1f\nMeasured %s\n\n%s\n\nThis is a saved result for the path through this node. It does not show current connection health, ICMP ping or the speed between individual servers. Compare it only with results for the same path and response type.",position+1,node,median,min,average,trimmed,p90,max,jitter,new java.util.Date(measuredAt).toString(),"public-path".equals(kind)?"Public HTTPS response through the custom middle; timing starts after DNS, TCP and TLS preparation.":"Private authenticated Router response through the ordered prefix; timing includes connection establishment.");}
    }

    static Record completed(String status,String saved,String request,String source,String config,int position,String node,String kind)throws Exception {
        JSONObject value=status(status,request);
        if(!bool(value,"complete")||!bool(value,"drained")||!"complete".equals(text(value,"stage"))||!value.optString("failure","").isEmpty())throw invalid();
        JSONArray results=value.getJSONArray("results");if(results.length()!=1)throw invalid();
        Record record=new Record(saved);record.require(source,config,position,node,kind,request);
        if(!same(results.getJSONObject(0),new JSONObject(record.raw).getJSONObject("result")))throw invalid();
        return record;
    }
    static JSONObject status(String raw,String request)throws Exception {
        if(raw==null||raw.getBytes(StandardCharsets.UTF_8).length>16384)throw invalid();
        io.nekohasekai.libbox.Libbox.routerValidatePrivateNodeJSON(raw);JSONObject result=new JSONObject(raw);
        if(result.has("failure"))keys(result,"request_id","stage","complete","drained","results","failure");else keys(result,"request_id","stage","complete","drained","results");
        if(!request.equals(text(result,"request_id"))||text(result,"stage").length()>160||result.getJSONArray("results").length()>1)throw invalid();
        bool(result,"complete");bool(result,"drained");if(result.has("failure"))text(result,"failure");return result;
    }
    static Record load(Context context,String source,String config,int position,String node,String kind)throws Exception {
        if(!sha(source)||!sha(config)||position<0||position>7||node==null||!node.matches("[A-Za-z0-9_-]{1,64}")||!Arrays.asList("private-node","public-path").contains(kind))throw invalid();
        synchronized(AndroidPrivateFileStore.class){return read(file(context)).get(source+":"+config+":"+position+":"+node+":"+kind+":"+("public-path".equals(kind)?PUBLIC:PRIVATE));}
    }
    /** Host service/Home locks and the request's MTU lease surround this
     * private transaction. Rollback never overwrites a later writer. */
    static void save(Context context,Record record,Guard guard)throws Exception {
        synchronized(AndroidPrivateFileStore.class){
            guard.require();Record checked=new Record(record.raw);File file=file(context);byte[] original=file.exists()?AndroidPrivateFileStore.read(file,MAX_STORE):null;
            Map<String,Record> records=read(file);Record old=records.get(checked.key());
            if(old!=null&&(old.request.equals(checked.request)||old.measuredAt>checked.measuredAt))throw new IllegalStateException("An equal or newer ordered benchmark already owns this history.");
            records.put(checked.key(),checked);if(records.size()>MAX_RECORDS)throw new IllegalStateException("The separate ordered benchmark history is full.");
            JSONArray values=new JSONArray();for(Record value:records.values())values.put(value.raw);
            byte[] written=new JSONObject().put("schema",1).put("records",values).toString().getBytes(StandardCharsets.UTF_8);
            guard.require();
            try{
                AndroidPrivateFileStore.write(file,written,MAX_STORE);
                if(!Arrays.equals(written,AndroidPrivateFileStore.read(file,MAX_STORE)))throw new IllegalStateException("The ordered history changed before durable readback.");
                guard.require();
            }catch(Exception failure){
                try{if(file.exists()&&Arrays.equals(written,AndroidPrivateFileStore.read(file,MAX_STORE))){if(original==null)AndroidPrivateFileStore.remove(file,MAX_STORE);else AndroidPrivateFileStore.write(file,original,MAX_STORE);}}
                catch(Exception rollback){failure.addSuppressed(rollback);}throw failure;
            }
        }
    }
    private static File file(Context context){return new File(context.getApplicationContext().getFilesDir(),FILE_NAME);}
    private static Map<String,Record> read(File file)throws Exception {
        Map<String,Record> records=new LinkedHashMap<>();if(!file.exists())return records;
        String raw=AndroidTorProfile.strictText(AndroidPrivateFileStore.read(file,MAX_STORE));io.nekohasekai.libbox.Libbox.routerValidatePrivateNodeJSON(raw);JSONObject root=new JSONObject(raw);keys(root,"schema","records");
        if(integer(root,"schema")!=1)throw invalid();JSONArray values=root.getJSONArray("records");if(values.length()>MAX_RECORDS)throw invalid();
        for(int i=0;i<values.length();i++){Object value=values.get(i);if(!(value instanceof String))throw invalid();Record record=new Record((String)value);if(records.put(record.key(),record)!=null)throw invalid();}return records;
    }
    private static boolean same(Object a,Object b)throws Exception {
        if(a instanceof JSONObject&&b instanceof JSONObject){JSONObject x=(JSONObject)a,y=(JSONObject)b;if(x.length()!=y.length())return false;for(java.util.Iterator<String> it=x.keys();it.hasNext();){String key=it.next();if(!y.has(key)||!same(x.get(key),y.get(key)))return false;}return true;}
        if(a instanceof Number&&b instanceof Number)return Double.compare(((Number)a).doubleValue(),((Number)b).doubleValue())==0;
        return a==null?b==null:a.equals(b);
    }
    private static boolean sha(String value){return value!=null&&value.matches("[0-9a-f]{64}");}
    private static String text(JSONObject value,String key)throws Exception{Object v=value.get(key);if(!(v instanceof String))throw invalid();return(String)v;}
    private static boolean bool(JSONObject value,String key)throws Exception{Object v=value.get(key);if(!(v instanceof Boolean))throw invalid();return(Boolean)v;}
    private static double number(JSONObject value,String key)throws Exception{Object v=value.get(key);if(!(v instanceof Number)||!Double.isFinite(((Number)v).doubleValue()))throw invalid();return((Number)v).doubleValue();}
    private static long integer(JSONObject value,String key)throws Exception{double n=number(value,key);long v=value.getLong(key);if(n!=v)throw invalid();return v;}
    private static void keys(JSONObject value,String...keys){Set<String> actual=new HashSet<>();for(java.util.Iterator<String> it=value.keys();it.hasNext();)actual.add(it.next());if(!actual.equals(new HashSet<>(Arrays.asList(keys))))throw invalid();}
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("No complete, correctly bound 50-response ordered benchmark.");}
    private AndroidOrderedLatencyStore(){}
}
