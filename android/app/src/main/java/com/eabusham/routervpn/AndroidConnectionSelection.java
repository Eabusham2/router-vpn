package com.eabusham.routervpn;

import android.content.Context;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** Saved user choice shared by startup and manual Android permission owners.
 * This is independent of a temporary test's requested path. Only its digest is
 * allowed in Activity state; private profiles remain in their existing stores. */
final class AndroidConnectionSelection {
    private static final String[] KEYS={"selected_kind","selected_id","mode","custom_presets",
            "multihop_on","multihop_entry","multihop_exit","multihop_exit_mode","multihop_entry_mode","multihop_entry_kind","multihop_execution"};

    static Map<String,Object> preferences(Context context){
        Map<String,?> all=context.getApplicationContext().getSharedPreferences("router-vpn-unified",Context.MODE_PRIVATE).getAll();
        Map<String,Object> captured=new LinkedHashMap<>();
        for(String key:KEYS)if(all.containsKey(key)){
            Object value=all.get(key);
            if("multihop_on".equals(key)?!(value instanceof Boolean):!(value instanceof String))
                throw new IllegalStateException("The saved connection selection has an invalid value.");
            captured.put(key,value);
        }
        return Collections.unmodifiableMap(captured);
    }

    static String digest(Context context,AndroidNodeStore nodes)throws Exception{
        String active=nodes.activeId();
        Map<String,Object> captured=preferences(context);
        if(!java.util.Objects.equals(active,nodes.activeId()))throw new IllegalStateException("The selected private node changed during capture.");
        StringBuilder source=new StringBuilder("routervpn-connection-selection-v1\n");
        append(source,"active_node_id",active);
        for(String key:KEYS)if(captured.containsKey(key))append(source,key,captured.get(key));
        byte[] bytes=MessageDigest.getInstance("SHA-256").digest(source.toString().getBytes(StandardCharsets.UTF_8));
        StringBuilder result=new StringBuilder(64);
        for(byte value:bytes)result.append(String.format(Locale.ROOT,"%02x",value&255));
        return result.toString();
    }

    static void requireCurrent(Context context,AndroidNodeStore nodes,String expected)throws Exception{
        if(expected==null||!expected.matches("[0-9a-f]{64}")||!expected.equals(digest(context,nodes)))
            throw new IllegalStateException("The selected node or connection choices changed while Android permission was pending. Choose Connect again.");
    }

    private static void append(StringBuilder out,String key,Object value){
        out.append(key).append(':');
        if(value==null)out.append('n');
        else if(value instanceof Boolean)out.append('b').append(value);
        else{String text=(String)value;out.append('s').append(text.length()).append(':').append(text);}
        out.append('\n');
    }

    private AndroidConnectionSelection(){}
}
