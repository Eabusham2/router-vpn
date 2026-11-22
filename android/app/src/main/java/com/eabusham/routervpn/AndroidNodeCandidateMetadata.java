package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/** Read the original operation's bounded, ordered public target inventory.
 * No page is authority for a different operation or a subset of its source. */
final class AndroidNodeCandidateMetadata {
    interface Pages { String read(int offset)throws Exception; }
    private static final int LEGACY_BYTES=24*1024, PAGE_BYTES=12*1024;
    private static final java.util.regex.Pattern ID=java.util.regex.Pattern.compile("[A-Za-z0-9_.-]{1,128}");
    private static final java.util.regex.Pattern SHA256=java.util.regex.Pattern.compile("[0-9a-f]{64}");
    private AndroidNodeCandidateMetadata(){}

    // Native candidate construction uses hopmeasure.ObservationTimeout. Read
    // page zero and every continuation within one observation of that owner.
    static long observationDeadline(){return System.nanoTime()+1_500_000_000L;}
    static void requireBefore(long deadline){if(System.nanoTime()-deadline>=0)throw invalid();}

    static JSONObject read(String first,Pages pages,int originalCount,long deadline)throws Exception {
        JSONObject initial=frame(first,LEGACY_BYTES);
        int schema=integer(initial,"schema");
        if(schema==1)return initial;
        if(schema!=2||originalCount<1)throw invalid();
        requireBefore(deadline);
        if(first.getBytes(StandardCharsets.UTF_8).length>PAGE_BYTES)throw invalid();
        JSONObject page=initial;String header=null;
        Set<String> ids=new HashSet<>();
        JSONArray targets=new JSONArray();
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        digest.update((byte)'[');
        do{
            if(integer(page,"schema")!=2||integer(page,"target_total")!=originalCount||integer(page,"target_offset")!=targets.length())throw invalid();
            String expected=page.getString("targets_sha256");
            if(!SHA256.matcher(expected).matches())throw invalid();
            JSONArray batch=page.getJSONArray("targets");
            if(batch.length()==0||batch.length()>originalCount-targets.length())throw invalid();
            page.remove("targets");page.remove("target_offset");
            String current=page.toString();
            if(header==null)header=current;else if(!header.equals(current))throw invalid();
            for(int i=0;i<batch.length();i++){
                JSONObject target=batch.getJSONObject(i);
                Object idValue=target.get("id"),sourceValue=target.get("source_sha256");
                if(target.length()!=2||!(idValue instanceof String)||!(sourceValue instanceof String))throw invalid();
                String id=(String)idValue,source=(String)sourceValue;
                // The native source compiler's exactID admits only these ASCII
                // characters, so each ID has one canonical Go JSON encoding.
                if(!ID.matcher(id).matches()||!ids.add(id)||!SHA256.matcher(source).matches())throw invalid();
                if(targets.length()>0)digest.update((byte)',');
                String row="{\"id\":\""+id+"\",\"source_sha256\":\""+source+"\"}";
                digest.update(row.getBytes(StandardCharsets.UTF_8));targets.put(target);
            }
            requireBefore(deadline);
            if(targets.length()==originalCount){
                digest.update((byte)']');
                StringBuilder hex=new StringBuilder(64);
                for(byte value:digest.digest())hex.append(String.format(Locale.ROOT,"%02x",value&255));
                if(!expected.contentEquals(hex))throw invalid();
                // Subsequent validators consume the complete, in-process
                // legacy shape, including the original selected/prefix header.
                page.remove("target_total");page.remove("targets_sha256");page.put("schema",1);page.put("targets",targets);
                requireBefore(deadline);return page;
            }
            page=frame(pages.read(targets.length()),PAGE_BYTES);
        }while(true);
    }
    private static JSONObject frame(String raw,int limit)throws Exception{
        if(raw==null||raw.isEmpty()||raw.getBytes(StandardCharsets.UTF_8).length>limit)throw invalid();
        io.nekohasekai.libbox.Libbox.routerValidatePrivateNodeJSON(raw);
        return new JSONObject(raw);
    }
    private static int integer(JSONObject object,String key)throws Exception{
        Object value=object.get(key);if(!(value instanceof Integer||value instanceof Long))throw invalid();
        long n=((Number)value).longValue();if(n<0||n>Integer.MAX_VALUE)throw invalid();return (int)n;
    }
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("Candidate metadata did not preserve its original ordered source.");}
}
