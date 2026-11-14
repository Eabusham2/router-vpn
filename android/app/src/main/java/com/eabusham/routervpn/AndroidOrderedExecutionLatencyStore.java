package com.eabusham.routervpn;

import android.content.Context;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/** Historical Server/Compare results. Preparation hashes locate history only;
 * the unmodified native receipt is bound to its actual selected projection and
 * generation. Reading this file never creates a live native capability. */
final class AndroidOrderedExecutionLatencyStore {
    static final String FILE_NAME="ordered-execution-fifty-v1.json";
    static final int MAX_ENTRY=32768;
    static final class Entry {
        final String raw,namespaceSource,namespaceConfig,requested;
        final AndroidOrderedExecutionLatencyCapture capture;
        final AndroidOrderedLatencyStore.Record record;
        Entry(String namespaceSource,String namespaceConfig,String requested,
              AndroidOrderedExecutionLatencyCapture capture,AndroidOrderedLatencyStore.Record record)throws Exception {
            this(new JSONObject().put("schema",1).put("namespace_source_sha256",namespaceSource)
                    .put("namespace_config_sha256",namespaceConfig).put("requested_execution",requested)
                    .put("capture",capture.raw).put("receipt",record.raw).toString());
        }
        Entry(String raw)throws Exception {
            if(raw==null||raw.isEmpty()||raw.getBytes(StandardCharsets.UTF_8).length>MAX_ENTRY)throw invalid();
            io.nekohasekai.libbox.Libbox.routerValidatePrivateNodeJSON(raw);
            JSONObject value=new JSONObject(raw);
            AndroidOrderedExecutionLatencyCapture.keys(value,"schema","namespace_source_sha256","namespace_config_sha256","requested_execution","capture","receipt");
            namespaceSource=AndroidOrderedExecutionLatencyCapture.text(value,"namespace_source_sha256");
            namespaceConfig=AndroidOrderedExecutionLatencyCapture.text(value,"namespace_config_sha256");
            requested=AndroidOrderedExecutionLatencyCapture.text(value,"requested_execution");
            if(AndroidOrderedExecutionLatencyCapture.integer(value,"schema")!=1
                    ||!AndroidOrderedExecutionLatencyCapture.sha(namespaceSource)||!AndroidOrderedExecutionLatencyCapture.sha(namespaceConfig))throw invalid();
            capture=new AndroidOrderedExecutionLatencyCapture(AndroidOrderedExecutionLatencyCapture.text(value,"capture"));
            capture.requireSelection(requested,capture.selected);
            record=new AndroidOrderedLatencyStore.Record(AndroidOrderedExecutionLatencyCapture.text(value,"receipt"),capture.selected);
            capture.requireRecord(record);this.raw=raw;
        }
        String key(){return AndroidOrderedExecutionLatencyStore.key(namespaceSource,namespaceConfig,requested,capture.selected,record.position,record.node,record.kind);}
        void require(String source,String config,String requested,String selected,int position,String node,String kind)throws Exception {
            if(!namespaceSource.equals(source)||!namespaceConfig.equals(config)||!this.requested.equals(requested)
                    ||!capture.selected.equals(selected)||record.position!=position||!record.node.equals(node)||!record.kind.equals(kind))throw invalid();
            capture.requireRecord(record);
        }
    }

    static Entry load(Context context,String source,String config,String requested,String selected,int position,String node,String kind)throws Exception {
        validateKey(source,config,requested,selected,position,node,kind);
        synchronized(AndroidPrivateFileStore.class){
            Entry result=read(file(context)).get(key(source,config,requested,selected,position,node,kind));
            if(result!=null)result.require(source,config,requested,selected,position,node,kind);
            return result;
        }
    }
    /** Caller retains the original session, selected execution, measurement and
     * MTU lease through both guard checks and durable readback. */
    static void save(Context context,Entry entry,AndroidOrderedLatencyStore.Guard guard)throws Exception {
        synchronized(AndroidPrivateFileStore.class){
            guard.require();Entry checked=new Entry(entry.raw);File file=file(context);
            byte[] original=file.exists()?AndroidPrivateFileStore.read(file,AndroidOrderedLatencyStore.MAX_STORE):null;
            Map<String,Entry> records=read(file);Entry previous=records.get(checked.key());
            if(previous!=null&&(previous.record.request.equals(checked.record.request)||previous.record.measuredAt>checked.record.measuredAt))
                throw new IllegalStateException("An equal or newer selected-execution result already owns this history.");
            records.put(checked.key(),checked);
            if(records.size()>AndroidOrderedLatencyStore.MAX_RECORDS)throw new IllegalStateException("The separate execution benchmark history is full.");
            JSONArray values=new JSONArray();for(Entry value:records.values())values.put(value.raw);
            byte[] written=new JSONObject().put("schema",1).put("records",values).toString().getBytes(StandardCharsets.UTF_8);
            guard.require();
            try{
                AndroidPrivateFileStore.write(file,written,AndroidOrderedLatencyStore.MAX_STORE);
                if(!Arrays.equals(written,AndroidPrivateFileStore.read(file,AndroidOrderedLatencyStore.MAX_STORE)))
                    throw new IllegalStateException("The execution history changed before durable readback.");
                guard.require();
            }catch(Exception failure){
                try{
                    if(file.exists()&&Arrays.equals(written,AndroidPrivateFileStore.read(file,AndroidOrderedLatencyStore.MAX_STORE))){
                        if(original==null)AndroidPrivateFileStore.remove(file,AndroidOrderedLatencyStore.MAX_STORE);
                        else AndroidPrivateFileStore.write(file,original,AndroidOrderedLatencyStore.MAX_STORE);
                    }
                }catch(Exception rollback){failure.addSuppressed(rollback);}
                throw failure;
            }
        }
    }
    private static File file(Context context){return new File(context.getApplicationContext().getFilesDir(),FILE_NAME);}
    private static Map<String,Entry> read(File file)throws Exception {
        Map<String,Entry> records=new LinkedHashMap<>();if(!file.exists())return records;
        String raw=AndroidTorProfile.strictText(AndroidPrivateFileStore.read(file,AndroidOrderedLatencyStore.MAX_STORE));
        io.nekohasekai.libbox.Libbox.routerValidatePrivateNodeJSON(raw);JSONObject root=new JSONObject(raw);
        AndroidOrderedExecutionLatencyCapture.keys(root,"schema","records");
        if(AndroidOrderedExecutionLatencyCapture.integer(root,"schema")!=1)throw invalid();
        JSONArray values=root.getJSONArray("records");if(values.length()>AndroidOrderedLatencyStore.MAX_RECORDS)throw invalid();
        for(int i=0;i<values.length();i++){
            Object value=values.get(i);if(!(value instanceof String))throw invalid();
            Entry entry=new Entry((String)value);if(records.put(entry.key(),entry)!=null)throw invalid();
        }
        return records;
    }
    private static void validateKey(String source,String config,String requested,String selected,int position,String node,String kind){
        if(!AndroidOrderedExecutionLatencyCapture.sha(source)||!AndroidOrderedExecutionLatencyCapture.sha(config)
                ||!Arrays.asList("server","auto").contains(requested)||!Arrays.asList("local","server").contains(selected)
                ||"server".equals(requested)&&!"server".equals(selected)||position<0||position>7
                ||node==null||!node.matches("[A-Za-z0-9_-]{1,64}")||!Arrays.asList("private-node","public-path").contains(kind))throw invalid();
    }
    private static String key(String source,String config,String requested,String selected,int position,String node,String kind){
        return source+":"+config+":"+requested+":"+selected+":"+position+":"+node+":"+kind+":"
                +("public-path".equals(kind)?AndroidOrderedLatencyStore.PUBLIC:AndroidOrderedLatencyStore.PRIVATE);
    }
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("No correctly bound historical execution benchmark.");}
    private AndroidOrderedExecutionLatencyStore(){}
}
