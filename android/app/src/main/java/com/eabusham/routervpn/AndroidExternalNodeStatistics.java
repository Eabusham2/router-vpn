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

/** Historical routed HTTPS responses. Never contributes to direct TCP rankings
 * or rewrites the private sources that own the running tunnel. */
final class AndroidExternalNodeStatistics {
    static final String FILE_NAME="external-node-statistics-v1.json";
    static final String MEASUREMENT="routed-https-response-after-tls";
    static final String ENDPOINT="https://speed.cloudflare.com/__down?bytes=1";
    private static final int MAX_STORE=192*1024,MAX_EXITS=512*1024;

    static final class Captured {
        final AndroidStandardExitRuntime.MeasurementSource path;
        final File exitsFile,routerFile;
        final String exitsSHA,exitSHA,entrySHA;
        final Set<String> existingIDs;
        private Captured(AndroidStandardExitRuntime.MeasurementSource path,File exitsFile,String exitsSHA,
                         File routerFile,String exitSHA,String entrySHA,Set<String> existingIDs){
            this.path=path;this.exitsFile=exitsFile;this.exitsSHA=exitsSHA;this.routerFile=routerFile;
            this.exitSHA=exitSHA;this.entrySHA=entrySHA;this.existingIDs=new HashSet<>(existingIDs);
        }
        void requireCurrent()throws Exception{
            if(!exitsSHA.equals(digest(AndroidPrivateFileStore.read(exitsFile,MAX_EXITS)))
                    ||routerFile!=null&&!entrySHA.equals(digest(AndroidPrivateFileStore.read(routerFile,AndroidNodeStore.MAX_BUNDLE))))
                throw new IllegalStateException("A saved external benchmark source changed; the previous completed result is retained.");
        }
    }

    static final class Record {
        final String id,exitSHA,entryKind,entryID,entrySHA,entryMode,requested,selected,request,configSHA,networkSHA;
        final long measuredAt;
        final double min,median,average,trimmedMean,p90,max,jitter;
        private Record(JSONObject value)throws Exception{
            exactKeys(value,"node_id","source_sha256","entry_kind","entry_id","entry_source_sha256","entry_mode",
                    "requested_execution","selected_execution","request_id","config_sha256","network_sha256","measured_at_ms",
                    "measurement","endpoint","attempts","failed","samples","min_ms","median_ms","average_ms","trimmed_mean_ms","p90_ms","max_ms","jitter_ms");
            id=text(value,"node_id");exitSHA=text(value,"source_sha256");entryKind=text(value,"entry_kind");entryID=text(value,"entry_id");entrySHA=text(value,"entry_source_sha256");entryMode=text(value,"entry_mode");
            requested=text(value,"requested_execution");selected=text(value,"selected_execution");request=text(value,"request_id");configSHA=text(value,"config_sha256");networkSHA=text(value,"network_sha256");
            measuredAt=integer(value,"measured_at_ms");min=number(value,"min_ms");median=number(value,"median_ms");average=number(value,"average_ms");trimmedMean=number(value,"trimmed_mean_ms");p90=number(value,"p90_ms");max=number(value,"max_ms");jitter=number(value,"jitter_ms");
            if(!safeID(id)||!sha(exitSHA)||!sha(configSHA)||!sha(networkSHA)||!request.matches("[0-9a-f]{32}")
                    ||!Arrays.asList("direct","router-vpn","external").contains(entryKind)
                    ||!Arrays.asList("local","server","auto").contains(requested)||!Arrays.asList("local","server").contains(selected)
                    ||!"auto".equals(requested)&&!requested.equals(selected)||measuredAt<=0||measuredAt>System.currentTimeMillis()+60000
                    ||!MEASUREMENT.equals(text(value,"measurement"))||!ENDPOINT.equals(text(value,"endpoint"))
                    ||integer(value,"attempts")!=50||integer(value,"samples")!=50||integer(value,"failed")!=0)
                throw new IllegalArgumentException("Invalid saved routed HTTPS benchmark identity.");
            if("direct".equals(entryKind)){
                if(!entryID.isEmpty()||!entrySHA.isEmpty()||!entryMode.isEmpty()||!"local".equals(requested))throw new IllegalArgumentException("A direct benchmark cannot borrow an entry.");
            }else if(!safeID(entryID)||id.equals(entryID)||!sha(entrySHA)||!entryMode.matches("[a-z0-9-]{1,64}")
                    ||"router-vpn".equals(entryKind)&&!entryID.matches("[0-9a-f]{32}")
                    ||"external".equals(entryKind)&&!"local".equals(requested))throw new IllegalArgumentException("Invalid saved benchmark entry.");
            for(double n:new double[]{min,median,average,trimmedMean,p90,max})if(n<=0||n>60000)throw new IllegalArgumentException("Invalid saved HTTPS response time.");
            if(jitter<0||jitter>60000||min>median||median>p90||p90>max||average<min||average>max||trimmedMean<min||trimmedMean>max)
                throw new IllegalArgumentException("Inconsistent saved HTTPS response statistics.");
        }
        String detail(){
            String path="direct".equals(entryKind)?"Direct external path":"Entry "+entryID+" ("+entryMode+") → external exit";
            return String.format(Locale.US,"Saved 50-sample routed HTTPS benchmark\nMedian %.1f ms • min %.1f • avg %.1f • 10%% trimmed mean %.1f • p90 %.1f • max %.1f • jitter %.1f\n50 successful / 0 failed\n%s • %s execution%s\nMeasured %s\n\n%s\nEach timer starts after the captured route's DNS, TCP and TLS preparation. This is an HTTPS response from the public measurement endpoint through the saved VPN path, not ICMP RTT or the VPN server's own response. Saved measurements are historical and remain separate from direct TCP Lowest latency / Fastest rankings.",
                    median,min,average,trimmedMean,p90,max,jitter,path,selected,"auto".equals(requested)?" (Compare selected)":"",new java.util.Date(measuredAt).toString(),ENDPOINT);
        }
        JSONObject json()throws Exception{
            return new JSONObject().put("node_id",id).put("source_sha256",exitSHA).put("entry_kind",entryKind).put("entry_id",entryID).put("entry_source_sha256",entrySHA).put("entry_mode",entryMode)
                    .put("requested_execution",requested).put("selected_execution",selected).put("request_id",request).put("config_sha256",configSHA).put("network_sha256",networkSHA).put("measured_at_ms",measuredAt)
                    .put("measurement",MEASUREMENT).put("endpoint",ENDPOINT).put("attempts",50).put("failed",0).put("samples",50)
                    .put("min_ms",min).put("median_ms",median).put("average_ms",average).put("trimmed_mean_ms",trimmedMean).put("p90_ms",p90).put("max_ms",max).put("jitter_ms",jitter);
        }
    }

    static Captured capture(Context context,AndroidStandardExitRuntime.MeasurementSource path)throws Exception{
        if(path==null)throw new IllegalStateException("No retained external launch source.");
        File exits=new File(context.getApplicationContext().getFilesDir(),"standard-exits.json");
        byte[] bytes=AndroidPrivateFileStore.read(exits,MAX_EXITS);
        Map<String,String> snapshots=snapshots(context);
        if(!path.exitSource.equals(snapshots.get(path.home.activeExternalId)))throw new IllegalStateException("The saved external node differs from its connected source.");
        File router=null;String entry="";
        if("router-vpn".equals(path.entryKind)){
            router=routerFile(context,path.home.activeEntryId);
            if(path.routerEntry==null||!router.getCanonicalFile().equals(path.routerEntry)||!path.entrySource.equals(AndroidExternalPolicy.entryDigest(router)))
                throw new IllegalStateException("The saved Router entry differs from its connected source.");
            entry=path.entrySource;
        }else if("external".equals(path.entryKind)){
            if(!path.entrySource.equals(snapshots.get(path.home.activeEntryId)))throw new IllegalStateException("The saved ordinary entry differs from its connected source.");
            entry=digest(path.entrySource);
        }else if(!"direct".equals(path.entryKind)||!path.entrySource.isEmpty()||!path.home.activeEntryId.isEmpty())throw new IllegalStateException("The retained external path is invalid.");
        Captured captured=new Captured(path,exits,digest(bytes),router,digest(path.exitSource),entry,snapshots.keySet());
        captured.requireCurrent();return captured;
    }

    /** Only a complete, drained native latency-only result can form a record. */
    static Record result(Captured source,LayeredVpnService.HopMeasurementOwner owner,String raw)throws Exception{
        if(raw==null||raw.length()>16384)throw new IllegalArgumentException("Invalid native benchmark response.");
        JSONObject status=new JSONObject(raw);
        if(!owner.requestID().equals(text(status,"request_id"))||!"complete".equals(text(status,"stage"))||!bool(status,"complete")||!bool(status,"drained")
                ||!status.optString("failure","").isEmpty())throw new IllegalStateException("The native benchmark did not complete and drain.");
        JSONArray rows=status.getJSONArray("results");if(rows.length()!=1)throw new IllegalStateException("The benchmark returned another path.");
        JSONObject row=rows.getJSONObject(0);
        if(!source.path.home.activeExternalId.equals(text(row,"node_id"))||!"exit".equals(text(row,"role"))||!"public-path".equals(text(row,"kind"))
                ||!bool(row,"ready")||!row.optString("failure","").isEmpty()||row.has("idle")||row.has("download")||row.has("upload"))
            throw new IllegalStateException("No complete 50-sample external benchmark; the previous saved result is retained.");
        JSONObject benchmark=row.getJSONObject("benchmark"),stats=benchmark.getJSONObject("distribution");
        if(integer(benchmark,"schema")!=1||!MEASUREMENT.equals(text(benchmark,"measurement"))||!ENDPOINT.equals(text(benchmark,"endpoint"))
                ||integer(benchmark,"attempts")!=50||integer(benchmark,"failed")!=0||integer(stats,"samples")!=50)
            throw new IllegalStateException("The native response is not a complete routed HTTPS benchmark.");
        JSONObject value=new JSONObject().put("node_id",source.path.home.activeExternalId).put("source_sha256",source.exitSHA)
                .put("entry_kind",source.path.entryKind).put("entry_id",source.path.home.activeEntryId).put("entry_source_sha256",source.entrySHA).put("entry_mode",source.path.home.activeEntryMode)
                .put("requested_execution",source.path.requestedExecution).put("selected_execution",source.path.selectedExecution).put("request_id",owner.requestID())
                .put("config_sha256",owner.configIdentity()).put("network_sha256",owner.networkIdentity()).put("measured_at_ms",System.currentTimeMillis())
                .put("measurement",MEASUREMENT).put("endpoint",ENDPOINT).put("attempts",50).put("failed",0).put("samples",50).put("trimmed_mean_ms",number(benchmark,"trimmed_mean_ms"));
        for(String key:new String[]{"min_ms","median_ms","average_ms","p90_ms","max_ms","jitter_ms"})value.put(key,number(stats,key));
        return new Record(value);
    }

    /** Caller holds runtime → native service → Home → private I/O. Native work
     * has drained, but the original MTU and cancellation owners remain held. */
    static void save(Context context,Captured source,Record record)throws Exception{
        synchronized(AndroidPrivateFileStore.class){
            source.requireCurrent();
            if(!record.id.equals(source.path.home.activeExternalId)||!record.exitSHA.equals(source.exitSHA)||!record.entrySHA.equals(source.entrySHA)
                    ||!record.entryKind.equals(source.path.entryKind)||!record.entryID.equals(source.path.home.activeEntryId)||!record.entryMode.equals(source.path.home.activeEntryMode)
                    ||!record.requested.equals(source.path.requestedExecution)||!record.selected.equals(source.path.selectedExecution))
                throw new IllegalStateException("Benchmark source identity changed before save.");
            File file=new File(context.getApplicationContext().getFilesDir(),FILE_NAME);
            Map<String,Record> records=read(file);
            Record old=records.get(record.id);if(old!=null&&old.request.equals(record.request))throw new IllegalStateException("This benchmark request was already saved.");
            // The exact current external store was re-read under the same I/O
            // monitor. Retire only records for verifiably removed node IDs.
            records.keySet().retainAll(source.existingIDs);records.put(record.id,record);
            if(records.size()>AndroidStandardExitStore.MAX_EXITS)throw new IllegalStateException("The bounded external benchmark store is full.");
            JSONArray values=new JSONArray();for(Record item:records.values())values.put(item.json());
            AndroidPrivateFileStore.write(file,new JSONObject().put("schema",1).put("records",values).toString().getBytes(StandardCharsets.UTF_8),MAX_STORE);
        }
    }

    static Record load(Context context,String exitID)throws Exception{
        if(!safeID(exitID))throw new IllegalArgumentException("Select a saved external node.");
        File exits=new File(context.getApplicationContext().getFilesDir(),"standard-exits.json");
        String storeSHA=digest(AndroidPrivateFileStore.read(exits,MAX_EXITS));Map<String,String> snapshots=snapshots(context);
        synchronized(AndroidPrivateFileStore.class){
            if(!storeSHA.equals(digest(AndroidPrivateFileStore.read(exits,MAX_EXITS))))throw new IllegalStateException("The selected external node changed while loading statistics.");
            Record result=read(new File(context.getApplicationContext().getFilesDir(),FILE_NAME)).get(exitID);
            if(result==null||!snapshots.containsKey(exitID)||!result.exitSHA.equals(digest(snapshots.get(exitID))))return null;
            if("router-vpn".equals(result.entryKind)){
                File router;try{router=routerFile(context,result.entryID);}catch(IllegalStateException removedOrChanged){return null;}
                if(!result.entrySHA.equals(AndroidExternalPolicy.entryDigest(router)))return null;
            }else if("external".equals(result.entryKind)&&(!snapshots.containsKey(result.entryID)||!result.entrySHA.equals(digest(snapshots.get(result.entryID)))))return null;
            return result;
        }
    }

    private static Map<String,String> snapshots(Context context)throws Exception{
        Map<String,String> values=new LinkedHashMap<>();for(AndroidStandardExitStore.Entry entry:new AndroidStandardExitStore(context).list())values.put(entry.id,AndroidStandardExitStore.snapshot(entry));return values;
    }
    private static Map<String,Record> read(File file)throws Exception{
        Map<String,Record> result=new LinkedHashMap<>();if(!file.exists())return result;
        String raw=AndroidTorProfile.strictText(AndroidPrivateFileStore.read(file,MAX_STORE));io.nekohasekai.libbox.Libbox.routerValidatePrivateNodeJSON(raw);
        JSONObject root=new JSONObject(raw);exactKeys(root,"schema","records");if(integer(root,"schema")!=1)throw new IllegalArgumentException("Unsupported external benchmark schema.");
        JSONArray records=root.getJSONArray("records");if(records.length()>AndroidStandardExitStore.MAX_EXITS)throw new IllegalArgumentException("External benchmark store is too large.");
        for(int i=0;i<records.length();i++){Record record=new Record(records.getJSONObject(i));if(result.put(record.id,record)!=null)throw new IllegalArgumentException("Duplicate external benchmark record.");}
        return result;
    }
    private static File routerFile(Context context,String id)throws Exception{
        if(id==null||!id.matches("[0-9a-f]{32}"))throw new IllegalArgumentException("Invalid benchmark Router entry identity.");
        return new AndroidNodeStore(context).file(id);
    }
    private static boolean safeID(String id){return id!=null&&id.matches("[A-Za-z0-9._-]{1,96}")&&!id.contains("..")&&!".".equals(id);}
    private static boolean sha(String value){return value.matches("[0-9a-f]{64}");}
    private static String digest(String text)throws Exception{return digest(text.getBytes(StandardCharsets.UTF_8));}
    private static String digest(byte[] bytes)throws Exception{return AndroidTorProfile.digest(bytes);}
    private static String text(JSONObject object,String key)throws Exception{Object value=object.get(key);if(!(value instanceof String))throw new IllegalArgumentException("Invalid benchmark text field.");return(String)value;}
    private static boolean bool(JSONObject object,String key)throws Exception{Object value=object.get(key);if(!(value instanceof Boolean))throw new IllegalArgumentException("Invalid benchmark Boolean field.");return(Boolean)value;}
    private static double number(JSONObject object,String key)throws Exception{Object value=object.get(key);if(!(value instanceof Number)||!Double.isFinite(((Number)value).doubleValue()))throw new IllegalArgumentException("Invalid benchmark number.");return((Number)value).doubleValue();}
    private static long integer(JSONObject object,String key)throws Exception{double value=number(object,key);long integer=object.getLong(key);if(value!=integer)throw new IllegalArgumentException("Invalid benchmark integer.");return integer;}
    private static void exactKeys(JSONObject object,String... keys){Set<String> actual=new HashSet<>();for(java.util.Iterator<String> it=object.keys();it.hasNext();)actual.add(it.next());if(!actual.equals(new HashSet<>(Arrays.asList(keys))))throw new IllegalArgumentException("Unexpected external benchmark fields.");}
    private AndroidExternalNodeStatistics(){}
}
