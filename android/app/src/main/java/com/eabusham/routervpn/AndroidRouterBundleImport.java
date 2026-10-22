package com.eabusham.routervpn;

import android.content.Context;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;

/** A document-picker reply cannot overwrite a newer connection or node decision. */
final class AndroidRouterBundleImport {
    private AndroidRouterBundleImport(){}
    static String decision(Context context,AndroidNodeStore store)throws Exception{
        if(AndroidVpnMutationGuard.isBusy(context))throw new IllegalStateException("Disconnect and finish the current VPN operation before importing a Router bundle.");
        AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
        JSONObject value=new JSONObject().put("session",home.sessionId).put("phase",home.phase).put("generation",home.pathGeneration).put("active",store.activeId());
        JSONObject settings=new JSONObject();for(Map.Entry<String,?> entry:new TreeMap<>(context.getSharedPreferences("router-vpn-unified",Context.MODE_PRIVATE).getAll()).entrySet())settings.put(entry.getKey(),String.valueOf(entry.getValue()));
        value.put("settings",settings);JSONObject sources=new JSONObject();
        for(AndroidNodeStore.Node node:store.list())sources.put(node.id,AndroidNodeStatistics.source(node));
        value.put("sources",sources);return AndroidTelemetryNetwork.digest(value.toString().getBytes(StandardCharsets.UTF_8));
    }
    static void requireCurrent(Context context,AndroidNodeStore store,String captured)throws Exception{
        if(captured==null||captured.isEmpty()||!captured.equals(decision(context,store)))throw new IllegalStateException("The node selection, saved source or VPN decision changed while the document picker was open. Choose the bundle again.");
    }
    static byte[] read(InputStream input)throws Exception{
        if(input==null)throw new IllegalArgumentException("The selected document could not be opened.");
        try(InputStream in=input;ByteArrayOutputStream out=new ByteArrayOutputStream()){
            byte[] buffer=new byte[8192];int total=0;
            for(int count;(count=in.read(buffer))!=-1;){total+=count;if(total>AndroidNodeStore.MAX_BUNDLE)throw new IllegalArgumentException("The Router bundle exceeds the 32 MiB import limit.");out.write(buffer,0,count);}
            if(total==0)throw new IllegalArgumentException("The selected Router bundle is empty.");return out.toByteArray();
        }
    }
}
