package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Exact metadata returned by one typed execution facade. This parsed value is
 * not a forwarding capability: the service retains and checks the original
 * native execution, facade, measurement, session and MTU owner separately.
 * History can parse the same bytes without acquiring any of those owners. */
final class AndroidOrderedExecutionLatencyCapture {
    static final int MAX_BYTES=8192;
    // Each extension row has a bounded node ID and an optional original import tag and SHA-256.
    static int metadataLimit(int count) { return Math.max(MAX_BYTES,1024+512*count); }
    int extendedCount(){return nodes.size()>8?nodes.size():0;}
    final String raw,source,config,generation,selected;
    final String originalSource;
    final String privateStreamRoles;
    final List<Node> nodes;
    static final class Node {
        final String id,role,kind;
        final int position;
        Node(String id,int position,String role,String kind){this.id=id;this.position=position;this.role=role;this.kind=kind;}
    }

    AndroidOrderedExecutionLatencyCapture(String raw)throws Exception { this(raw,0,false); }

    static AndroidOrderedExecutionLatencyCapture fromHistory(String raw)throws Exception {
        return new AndroidOrderedExecutionLatencyCapture(raw,0,true);
    }
    AndroidOrderedExecutionLatencyCapture(String raw,int provedCount)throws Exception { this(raw,provedCount,false); }
    private AndroidOrderedExecutionLatencyCapture(String raw,int provedCount,boolean stored)throws Exception {
        if(provedCount!=0&&(provedCount<=8||provedCount>AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH))throw invalid();
        int limit=stored?AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH:provedCount;
        if(raw==null||raw.isEmpty()||raw.getBytes(StandardCharsets.UTF_8).length>metadataLimit(limit))throw invalid();
        io.nekohasekai.libbox.Libbox.routerValidatePrivateNodeJSON(raw);
        JSONObject value=new JSONObject(raw);
        JSONObject imported=null;
        if(value.has("multiple_imported")){
            keys(value,"schema","source_sha256","config_sha256","generation_sha256","selected_execution","nodes","multiple_imported");
            imported=value.getJSONObject("multiple_imported");
            keys(imported,"schema","original_source_sha256","public");
            originalSource=text(imported,"original_source_sha256");
            if(integer(imported,"schema")!=6||!sha(originalSource))throw invalid();
        }else{
            keys(value,"schema","source_sha256","config_sha256","generation_sha256","selected_execution","nodes");
            originalSource=null;
        }
        source=text(value,"source_sha256");config=text(value,"config_sha256");generation=text(value,"generation_sha256");selected=text(value,"selected_execution");
        if(integer(value,"schema")!=1||!sha(source)||!sha(config)||!sha(generation)||!Arrays.asList("local","server").contains(selected))throw invalid();
        JSONArray members=value.getJSONArray("nodes");
        int count=members.length();
        if(count<2||count>AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH || raw.getBytes(StandardCharsets.UTF_8).length>metadataLimit(count)
                || provedCount!=0 && count!=provedCount || count>8 && (imported==null||!stored&&count!=provedCount))throw invalid();
        List<Node> parsed=new ArrayList<>();Set<String> identities=new HashSet<>();
        JSONArray inventory=imported==null?null:imported.getJSONArray("public");
        int publicCount=0, privateStream=-1;
        JSONArray roles = new JSONArray();
        for(int i=0;i<members.length();i++){
            JSONObject member=members.getJSONObject(i);keys(member,"node_id","position","role","kind");
            String id=text(member,"node_id"),role=text(member,"role"),kind=text(member,"kind");
            String expectedRole=i==0?"entry":i==members.length()-1?"exit":"intermediate";
            if (count>8 && i>0 && i<count-1 && "private-node".equals(kind)) {
                if (i<2 || privateStream>=0 || inventory==null) throw invalid();
                privateStream=i;
            }
            roles.put(kind);
            if(integer(member,"position")!=i||!id.matches("[A-Za-z0-9_-]{1,64}")||!identities.add(id)||!expectedRole.equals(role)
                    ||!Arrays.asList("private-node","public-path").contains(kind)
                    ||"public-path".equals(kind)&&(i==0||i==members.length()-1||inventory==null&&i!=members.length()-2))throw invalid();
            if(inventory!=null&&"public-path".equals(kind)){
                JSONObject row=inventory.getJSONObject(publicCount++);
                keys(row,"position","tag","source_sha256");
                if(integer(row,"position")!=i||text(row,"tag").isEmpty()||!sha(text(row,"source_sha256")))throw invalid();
            }
            parsed.add(new Node(id,i,role,kind));
        }
        if(inventory!=null&&(publicCount==0||publicCount!=inventory.length()))throw invalid();
        privateStreamRoles = privateStream<0 ? "" : roles.toString();
        nodes=Collections.unmodifiableList(parsed);this.raw=raw;
    }

    void requireSelection(String requested,String selected)throws Exception {
        if(!Arrays.asList("server","auto").contains(requested)||!this.selected.equals(selected)
                ||"server".equals(requested)&&!"server".equals(selected))throw invalid();
    }
    void requireNode(int position,String id,String role,String kind,int count)throws Exception {
        if(count!=nodes.size()||position<0||position>=nodes.size())throw invalid();
        Node node=nodes.get(position);
        if(!node.id.equals(id)||!node.role.equals(role)||!node.kind.equals(kind))throw invalid();
    }
    String label(int position)throws Exception {
        if(position<0||position>=nodes.size())throw invalid();
        return "Cumulative "+selected+" path through "+("public-path".equals(nodes.get(position).kind)
                ?"custom node "+(position+1)+" of "+nodes.size()+" → Cloudflare edge":"node "+(position+1)+" of "+nodes.size());
    }
    void requireRecord(AndroidOrderedLatencyStore.Record record)throws Exception {
        if(record==null||!source.equals(record.source)||!config.equals(record.config)||!generation.equals(record.generation)
                ||!selected.equals(record.selectedExecution))throw invalid();
        requireNode(record.position,record.node,record.role,record.kind,record.count);
        if(!label(record.position).equals(record.label))throw invalid();
    }
    static boolean sha(String value){return value!=null&&value.matches("[0-9a-f]{64}");}
    static String text(JSONObject value,String key)throws Exception {Object v=value.get(key);if(!(v instanceof String))throw invalid();return(String)v;}
    static long integer(JSONObject value,String key)throws Exception {
        Object v=value.get(key);if(!(v instanceof Number)||!Double.isFinite(((Number)v).doubleValue()))throw invalid();
        long result=((Number)v).longValue();if(((Number)v).doubleValue()!=result)throw invalid();return result;
    }
    static void keys(JSONObject value,String...expected){
        Set<String> actual=new HashSet<>();for(java.util.Iterator<String> it=value.keys();it.hasNext();)actual.add(it.next());
        if(!actual.equals(new HashSet<>(Arrays.asList(expected))))throw invalid();
    }
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("The ordered benchmark lost its exact selected execution capture.");}
}
