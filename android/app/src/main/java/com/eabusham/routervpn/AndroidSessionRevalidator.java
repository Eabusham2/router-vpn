package com.eabusham.routervpn;

import android.content.Context;

import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Revalidates frozen session identity after the non-VPN Internet network changes. */
final class AndroidSessionRevalidator {
    private final Context context;
    private final AndroidRuntimeRegistry engines;
    private final AndroidUnderlyingNetworkMonitor monitor;
    private final ExecutorService executor=Executors.newSingleThreadExecutor();

    AndroidSessionRevalidator(Context context,AndroidRuntimeRegistry engines){
        this.context=context.getApplicationContext();this.engines=engines;this.monitor=new AndroidUnderlyingNetworkMonitor(this.context);
    }

    void start(){monitor.start(()->executor.execute(this::revalidate));}

    private void revalidate(){
        AndroidHomeStateStore.Snapshot before=AndroidHomeStateStore.snapshot(context);
        if(!before.connected)return;
        if("wg".equals(before.actualBase)||"awg".equals(before.actualBase)){
            if(!"multihop".equals(before.logicalMode)&&!"external".equals(before.logicalMode))return; // native WG/AWG controllers own their recovery.
        }
        String session=before.sessionId;
        if(session==null||session.isEmpty())return;
        try{
            AndroidHomeStateStore.warning(context,"Underlying network changed; re-proving the frozen Router VPN session before keeping Connected.");
            try{Thread.sleep(650L);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();return;}
            AndroidHomeStateStore.Snapshot current=AndroidHomeStateStore.snapshot(context);
            if(!current.connected||!session.equals(current.sessionId))return;
            if("external".equals(current.logicalMode)){
                if(current.expectedExternalIp==null||current.expectedExternalIp.isEmpty())throw new IllegalStateException("External session has no expected public-exit proof target.");
                String observed=AndroidStandardExitRuntime.proveExpectedPublicIp(current.expectedExternalIp);
                ensureSameSession(session);
                AndroidHomeStateStore.connectedExternal(context,current.activeExternalId,current.activeExternalName,current.activeExternalProtocol,current.expectedExternalIp,current.actualBase,observed);
                return;
            }
            String nodeId="multihop".equals(current.logicalMode)?current.activeExitId:current.activeNodeId;
            if(nodeId==null||nodeId.isEmpty())throw new IllegalStateException("Active session node identity is missing after network change.");
            File bundle=new AndroidNodeStore(context).file(nodeId);
            if(!AndroidPathProbe.prove(bundle,10000))throw new IllegalStateException("Frozen node private path proof failed after network change.");
            ensureSameSession(session);
            AndroidHomeStateStore.warning(context,"");
        }catch(Throwable error){
            try{if("xray".equals(before.actualBase))engines.xray.stop();else engines.singBox.stop();}catch(Throwable ignored){}
            if(session.equals(AndroidHomeStateStore.snapshot(context).sessionId))AndroidHomeStateStore.failed(context,"Network-change revalidation failed closed: "+safe(error));
        }
    }

    private void ensureSameSession(String session){AndroidHomeStateStore.Snapshot now=AndroidHomeStateStore.snapshot(context);if(!now.connected||!session.equals(now.sessionId))throw new IllegalStateException("Router VPN session changed during network-change revalidation.");}
    private static String safe(Throwable e){String value=e==null?"":e.getMessage();return value==null||value.trim().isEmpty()?"session proof failed":value.replace('\n',' ').replace('\r',' ').trim();}
}
