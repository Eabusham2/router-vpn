package com.eabusham.routervpn;

import android.content.Context;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Private, nonsecret usage receipts. Display statistics never rewrite a live node bundle. */
final class AndroidNodeUsage {
    static final String FILE_NAME = "node-usage-v1.json";
    private static final int MAX_BYTES = 96 * 1024, MAX_RECORDS = 128, MAX_EXIT_STORE = 512 * 1024;
    private static final String UNSAVED = " • Node usage could not be saved; the proved connection is unchanged.";
    private static final DateTimeFormatter DISPLAY_TIME = new DateTimeFormatterBuilder().appendInstant(3).toFormatter();

    static final class Metric {
        final int count;
        final long usedAt;
        final boolean available;
        Metric(int count,long usedAt){this(count,usedAt,true);}
        Metric(int count,long usedAt,boolean available){this.count=count;this.usedAt=usedAt;this.available=available;}
        String lastUsedAt(){return usedAt == 0 ? "" : DISPLAY_TIME.format(Instant.ofEpochMilli(usedAt));}
    }

    private static final class Source {
        final File file;
        final String sha256;
        final int limit;
        Source(File file,byte[] bytes,int limit)throws Exception{
            this.file=file.getCanonicalFile();this.sha256=AndroidTorProfile.digest(bytes);this.limit=limit;
        }
        void requireCurrent()throws Exception{
            if(!sha256.equals(AndroidTorProfile.digest(AndroidPrivateFileStore.read(file,limit))))
                throw new IllegalStateException("The captured usage source changed.");
        }
    }

    private static final class Node {
        final String kind,id,identity;
        final Metric imported;
        final Source source;
        Node(String kind,String id,String identity,Metric imported,Source source){
            this.kind=kind;this.id=id;this.identity=identity;this.imported=imported;this.source=source;
        }
        String key(){return kind+":"+id;}
    }

    /** Frozen before permission/launch and retained by the process-owned request.
     * UI recreation cannot opt a temporary test into usage or replace its sources. */
    static final class Attempt {
        private final List<Node> nodes;
        private final String topology,router,entry,exit,entryMode,externalProtocol;
        private final boolean unavailable;
        private String session="";
        private long generation=-1;
        private boolean invalid,completed;

        private Attempt(List<Node> nodes,String topology,String router,String entry,String exit,String entryMode,String externalProtocol,boolean unavailable){
            this.nodes=Collections.unmodifiableList(new ArrayList<>(nodes));this.topology=topology;this.router=router;
            this.entry=entry;this.exit=exit;this.entryMode=entryMode;this.externalProtocol=externalProtocol;this.unavailable=unavailable;
        }

        synchronized void owned(Context context,String value){
            if(completed)return;
            if(value==null||!value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
                    ||!session.isEmpty()&&!session.equals(value)){invalid=true;return;}
            session=value;
            AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
            if(!session.equals(home.sessionId)||generation>=0&&generation!=home.pathGeneration){invalid=true;return;}
            generation=home.pathGeneration;
        }

        synchronized void cancel(){completed=true;}

        void requireRouterSource(String id,String sha256){
            for(Node node:nodes)if("router-vpn".equals(node.kind)&&node.id.equals(id)){
                if(node.source.sha256.equals(sha256))return;
                throw new IllegalStateException("The captured permission source changed.");
            }
            throw new IllegalStateException("The captured permission has no matching Router source.");
        }

        synchronized String finished(Context context,String request,boolean success){
            if(completed)return "";
            completed=true;
            if(!success)return "";
            if(unavailable||invalid)return UNSAVED;
            try{
                // Home owns proof/session adoption; the private I/O monitor joins
                // source readback with the atomic sidecar write. Do not acquire
                // NodeStore/ExitStore instance locks while either is held.
                synchronized(AndroidHomeStateStore.class){
                    synchronized(AndroidPrivateFileStore.class){
                        AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
                        requireOwner(home);
                        if(AndroidHomeStateStore.emergencyDisconnectPending(context))throw new IllegalStateException("Disconnect owns this path.");
                        for(Node node:nodes)node.source.requireCurrent();
                        record(context,request,nodes);
                    }
                }
                return "";
            }catch(Exception unavailable){return UNSAVED;}
        }

        private void requireOwner(AndroidHomeStateStore.Snapshot home){
            if(home==null||session.isEmpty()||!session.equals(home.sessionId)||generation<0||generation!=home.pathGeneration||!home.connected
                    ||!"connected".equals(home.phase)||!"passed".equals(home.pathProof))throw new IllegalStateException("The proved usage owner changed.");
            if("router".equals(topology)){
                if(!router.equals(home.activeNodeId)||!home.activeEntryId.isEmpty()||!home.activeExitId.isEmpty()||!home.activeExternalId.isEmpty())
                    throw new IllegalStateException("The single-node usage path changed.");
            }else if("multihop".equals(topology)){
                if(!"multihop".equals(home.logicalMode)||!entry.equals(home.activeEntryId)||!exit.equals(home.activeExitId)
                        ||!exit.equals(home.activeNodeId)||!entryMode.equals(home.activeEntryMode)||!home.activeExternalId.isEmpty())
                    throw new IllegalStateException("The multihop usage path changed.");
            }else if(!"external".equals(home.logicalMode)||!exit.equals(home.activeExternalId)||!entry.equals(home.activeEntryId)
                    ||!entryMode.equals(home.activeEntryMode)||!externalProtocol.equals(home.activeExternalProtocol)
                    ||!home.activeNodeId.isEmpty()||!home.activeExitId.isEmpty())throw new IllegalStateException("The external usage path changed.");
        }
    }

    static Attempt unavailable(){return new Attempt(Collections.emptyList(),"","","","","","",true);}
    static String saveWarning(String message){return message!=null&&message.endsWith(UNSAVED)?UNSAVED.substring(3):"";}

    static Attempt router(AndroidNodeStore.Node node)throws Exception{
        Node captured=captureRouter(node);
        return new Attempt(Collections.singletonList(captured),"router",node.id,"","","","",false);
    }

    static Attempt multihop(AndroidNodeStore.Node entry,AndroidNodeStore.Node exit,String entryMode)throws Exception{
        if(entry==null||exit==null||entry.id.equals(exit.id))throw new IllegalArgumentException("Distinct captured usage nodes are required.");
        return new Attempt(Arrays.asList(captureRouter(entry),captureRouter(exit)),"multihop","",entry.id,exit.id,entryMode,"",false);
    }

    static Attempt importedMultihop(Context context,AndroidStandardExitStore.Entry entry,AndroidNodeStore.Node exit)throws Exception{
        if(entry==null||exit==null||entry.id.equals(exit.id)||!Arrays.asList("shadowsocks","hysteria2","wireguard","amneziawg").contains(entry.protocol))throw new IllegalArgumentException("The captured mixed usage path changed.");
        return new Attempt(Arrays.asList(captureExternal(context,entry),captureRouter(exit)),"multihop","",entry.id,exit.id,entry.protocol,"",false);
    }

    static Attempt external(Context context,AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry ordinary,
                            AndroidStandardExitStore.Entry exit,boolean direct,String entryMode)throws Exception{
        if(exit==null||direct&&(entry!=null||ordinary!=null)||!direct&&(entry==null)==(ordinary==null))
            throw new IllegalArgumentException("The captured external usage path is invalid.");
        List<Node> nodes=new ArrayList<>();
        if(entry!=null)nodes.add(captureRouter(entry));
        if(ordinary!=null)nodes.add(captureExternal(context,ordinary));
        nodes.add(captureExternal(context,exit));
        String first=entry!=null?entry.id:ordinary!=null?ordinary.id:"";
        return new Attempt(nodes,"external","",first,exit.id,direct?"":entryMode,exit.protocol,false);
    }

    private static Node captureRouter(AndroidNodeStore.Node node)throws Exception{
        if(node==null||node.file==null||!node.id.matches("[0-9a-f]{32}")||!node.file.getName().equals(node.id+".json"))
            throw new IllegalArgumentException("The stored Router usage identity is invalid.");
        byte[] bytes=AndroidPrivateFileStore.read(node.file,AndroidNodeStore.MAX_BUNDLE);
        JSONObject bundle=new JSONObject(AndroidTorProfile.strictText(bytes));AndroidNodeStore.validateBundle(bundle);
        if(!node.id.equals(AndroidNodeStore.deriveId(bundle,bytes)))throw new IllegalStateException("The Router usage source changed.");
        JSONObject profile=AndroidProfileSelection.selectedRouterProfile(bundle);
        return new Node("router-vpn",node.id,routerIdentity(node.id,bundle),imported(profile),new Source(node.file,bytes,AndroidNodeStore.MAX_BUNDLE));
    }

    private static Node captureExternal(Context context,AndroidStandardExitStore.Entry entry)throws Exception{
        AndroidStandardExitStore.validate(entry);
        File file=new File(context.getApplicationContext().getFilesDir(),"standard-exits.json");
        byte[] bytes=AndroidPrivateFileStore.read(file,MAX_EXIT_STORE);
        AndroidStandardExitStore.Entry saved=new AndroidStandardExitStore(context).get(entry.id);
        if(!AndroidStandardExitStore.snapshot(entry).equals(AndroidStandardExitStore.snapshot(saved)))
            throw new IllegalStateException("The external usage source changed.");
        Source source=new Source(file,bytes,MAX_EXIT_STORE);source.requireCurrent();
        return new Node("external",entry.id,externalIdentity(entry),new Metric(0,0),source);
    }

    static Metric routerMetric(AndroidNodeStore.Node node,JSONObject profile){
        Metric fallback=imported(profile);
        try{
            byte[] bytes=AndroidPrivateFileStore.read(node.file,AndroidNodeStore.MAX_BUNDLE);
            JSONObject bundle=new JSONObject(AndroidTorProfile.strictText(bytes));
            if(!node.id.equals(AndroidNodeStore.deriveId(bundle,bytes)))return new Metric(fallback.count,fallback.usedAt,false);
            File data=new File(node.file.getParentFile().getParentFile(),FILE_NAME);
            return metric(data,"router-vpn",node.id,routerIdentity(node.id,bundle),fallback);
        }catch(Exception unavailable){return new Metric(fallback.count,fallback.usedAt,false);}
    }

    static Metric externalMetric(File file,AndroidStandardExitStore.Entry entry){
        try{return metric(file,"external",entry.id,externalIdentity(entry),new Metric(0,0));}
        catch(Exception unavailable){return new Metric(0,0,false);}
    }

    private static String routerIdentity(String id,JSONObject bundle)throws Exception{
        JSONObject profile=AndroidProfileSelection.selectedRouterProfile(bundle);
        String proof=AndroidNodeStore.stableNodeIdentity(bundle),token=profile.optString("api_token","");
        if(!proof.matches("[0-9a-f]{64}")||token.isEmpty())throw new IllegalStateException("Authenticated Router usage identity is unavailable.");
        // Client tunnel key, transport choice, DNS, MTU, names and telemetry do
        // not change the authenticated home node. Exact bytes still gate adoption.
        return digest(new JSONObject().put("kind","router-vpn").put("id",id).put("proof",proof).put("api_token",token));
    }

    private static String externalIdentity(AndroidStandardExitStore.Entry entry)throws Exception{
        JSONObject source=new JSONObject(AndroidStandardExitStore.snapshot(entry)),identity=new JSONObject().put("kind","external");
        for(String key:new String[]{"id","protocol","server","server_port","username","password","method","secret","tls_server_name",
                "wg_private_key","wg_peer_public_key","wg_pre_shared_key","openvpn_config","tor_bridge"})
            if(source.has(key))identity.put(key,source.get(key));
        return digest(identity);
    }

    private static Metric imported(JSONObject profile){
        if(profile==null)return new Metric(0,0);
        Object raw=profile.opt("use_count");int count=0;
        if(raw instanceof Number){double number=((Number)raw).doubleValue();if(Double.isFinite(number)&&number>=0&&number<=Integer.MAX_VALUE&&number==Math.rint(number))count=(int)number;}
        long used=0;
        try{used=Instant.parse(profile.optString("last_used_at","")).toEpochMilli();if(used<0||used>System.currentTimeMillis()+60000)used=0;}catch(Exception invalid){}
        return new Metric(count,used);
    }

    private static Metric metric(File file,String kind,String id,String identity,Metric imported)throws Exception{
        synchronized(AndroidPrivateFileStore.class){
            JSONObject record=load(file).get(kind+":"+id);
            if(record==null||!identity.equals(record.getString("identity_sha256")))return imported;
            return new Metric(Math.max(imported.count,record.getInt("count")),Math.max(imported.usedAt,record.getLong("used_at_ms")));
        }
    }

    // Called under both Home and private-I/O monitors, after actual final proof
    // and all captured private sources still match. One write covers every
    // distinct node of the retained path; imported counts are maxima, not sums.
    private static void record(Context context,String request,List<Node> nodes)throws Exception{
        if(request==null||!request.matches("[0-9a-f]{32}")||nodes.isEmpty()||nodes.size()>2)throw new IllegalArgumentException("Invalid logical usage receipt.");
        File file=new File(context.getApplicationContext().getFilesDir(),FILE_NAME);
        Map<String,JSONObject> records=load(file);Set<String> seen=new HashSet<>();
        long now=System.currentTimeMillis();
        for(Node node:nodes){
            if(!seen.add(node.key()))continue;
            JSONObject previous=records.get(node.key());
            boolean same=previous!=null&&node.identity.equals(previous.getString("identity_sha256"));
            if(same&&request.equals(previous.getString("request_id")))continue;
            int count=Math.max(node.imported.count,same?previous.getInt("count"):0);
            if(count==Integer.MAX_VALUE)throw new IllegalStateException("Usage count cannot grow without overflow.");
            long used=Math.max(now,Math.max(node.imported.usedAt,same?previous.getLong("used_at_ms"):0));
            records.put(node.key(),new JSONObject().put("kind",node.kind).put("node_id",node.id).put("identity_sha256",node.identity)
                    .put("count",count+1).put("used_at_ms",used).put("request_id",request));
        }
        if(records.size()>MAX_RECORDS)throw new IllegalStateException("The bounded usage store is full.");
        JSONArray values=new JSONArray();for(JSONObject record:records.values())values.put(record);
        byte[] data=new JSONObject().put("schema",1).put("records",values).toString().getBytes(StandardCharsets.UTF_8);
        AndroidPrivateFileStore.write(file,data,MAX_BYTES);
    }

    private static Map<String,JSONObject> load(File file)throws Exception{
        Map<String,JSONObject> result=new LinkedHashMap<>();if(!file.exists())return result;
        String raw=AndroidTorProfile.strictText(AndroidPrivateFileStore.read(file,MAX_BYTES));
        io.nekohasekai.libbox.Libbox.routerValidatePrivateNodeJSON(raw);
        JSONObject root=new JSONObject(raw);
        exactKeys(root,"schema","records");
        if(!(root.get("schema") instanceof Number)||root.getDouble("schema")!=1)throw new IllegalArgumentException("Invalid usage schema.");
        JSONArray records=root.getJSONArray("records");if(records.length()>MAX_RECORDS)throw new IllegalArgumentException("Usage store exceeds its limit.");
        for(int i=0;i<records.length();i++){
            JSONObject record=records.getJSONObject(i);exactKeys(record,"kind","node_id","identity_sha256","count","used_at_ms","request_id");
            String kind=record.getString("kind"),id=record.getString("node_id");
            if(!Arrays.asList("router-vpn","external").contains(kind)||!id.matches("[A-Za-z0-9._-]{1,96}")||id.contains("..")||".".equals(id)
                    ||!record.getString("identity_sha256").matches("[0-9a-f]{64}")||!record.getString("request_id").matches("[0-9a-f]{32}"))
                throw new IllegalArgumentException("Invalid usage identity.");
            Object count=record.get("count"),used=record.get("used_at_ms");
            if(!(count instanceof Number)||record.getDouble("count")<1||record.getDouble("count")>Integer.MAX_VALUE
                    ||record.getDouble("count")!=record.getInt("count")||!(used instanceof Number)||record.getDouble("used_at_ms")<=0
                    ||record.getDouble("used_at_ms")>System.currentTimeMillis()+60000||record.getDouble("used_at_ms")!=record.getLong("used_at_ms")
                    ||result.put(kind+":"+id,record)!=null)throw new IllegalArgumentException("Invalid or duplicate usage record.");
        }
        return result;
    }

    private static void exactKeys(JSONObject object,String... keys){
        Set<String> actual=new HashSet<>();for(java.util.Iterator<String> it=object.keys();it.hasNext();)actual.add(it.next());
        if(!actual.equals(new HashSet<>(Arrays.asList(keys))))throw new IllegalArgumentException("Unexpected usage fields.");
    }
    private static String digest(Object value)throws Exception{return AndroidTorProfile.digest(canonical(value).getBytes(StandardCharsets.UTF_8));}
    private static String canonical(Object value)throws Exception{
        if(value instanceof JSONObject){JSONObject object=(JSONObject)value;List<String> keys=new ArrayList<>();for(java.util.Iterator<String> it=object.keys();it.hasNext();)keys.add(it.next());Collections.sort(keys);StringBuilder out=new StringBuilder("{");for(String key:keys){if(out.length()>1)out.append(',');out.append(JSONObject.quote(key)).append(':').append(canonical(object.get(key)));}return out.append('}').toString();}
        if(value instanceof JSONArray){JSONArray array=(JSONArray)value;StringBuilder out=new StringBuilder("[");for(int i=0;i<array.length();i++){if(i>0)out.append(',');out.append(canonical(array.get(i)));}return out.append(']').toString();}
        return value instanceof String?JSONObject.quote((String)value):String.valueOf(value);
    }
    private AndroidNodeUsage(){}
}
