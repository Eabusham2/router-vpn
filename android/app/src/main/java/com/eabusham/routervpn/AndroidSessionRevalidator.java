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
            if(!"multihop".equals(before.logicalMode)&&!"external".equals(before.logicalMode))return; // native WG/AWG controllers own recovery/reproof.
        }
        if(before.sessionId==null||before.sessionId.isEmpty())return;

        AndroidHomeStateStore.Snapshot token=AndroidHomeStateStore.beginPathRevalidation(
                context,
                "Underlying network changed; re-proving the frozen Router VPN session before keeping Connected.");
        if(token==null)return;
        try{
            try{Thread.sleep(650L);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IllegalStateException("Android network-change revalidation was interrupted; refusing to keep stale Connected proof.",interrupted);}
            AndroidHomeStateStore.Snapshot current=requireSameRevalidation(token);
            if("external".equals(current.logicalMode)){
                if(current.expectedExternalIp==null||current.expectedExternalIp.isEmpty())throw new IllegalStateException("External session has no expected public-exit proof target.");
                String observed=AndroidStandardExitRuntime.proveExpectedPublicIp(current.expectedExternalIp);
                current=requireSameRevalidation(token);
                if(!AndroidHomeStateStore.completePathRevalidation(context,token))throw new IllegalStateException("External path proof completed for a stale Android session/generation.");
                AndroidHomeStateStore.saveActualExit(context,token.sessionId,observed);
                return;
            }
            String nodeId="multihop".equals(current.logicalMode)?current.activeExitId:current.activeNodeId;
            if(nodeId==null||nodeId.isEmpty())throw new IllegalStateException("Active session node identity is missing after network change.");
            File bundle=new AndroidNodeStore(context).file(nodeId);
            if(!AndroidPathProbe.prove(bundle,10000))throw new IllegalStateException("Frozen node private path proof failed after network change.");
            requireSameRevalidation(token);
            if(!AndroidHomeStateStore.completePathRevalidation(context,token))throw new IllegalStateException("Router VPN path proof completed for a stale Android session/generation.");
        }catch(Throwable error){
            failClosedOwnedRuntime(before,token,error);
        }
    }

    private void failClosedOwnedRuntime(AndroidHomeStateStore.Snapshot before,AndroidHomeStateStore.Snapshot token,Throwable error){
        // A stale revalidation worker has lost ownership. It must never stop a
        // newer tunnel/session merely because the old proof finished late.
        if(!isSameRevalidation(token))return;
        final String message="Network-change revalidation failed closed: "+safe(error);
        try{
            if("multihop".equals(before.logicalMode)){
                engines.multihop.failClosedForRevalidation();
                if(isSameRevalidation(token))AndroidHomeStateStore.failed(context,message);
                return;
            }
            if("external".equals(before.logicalMode)){
                engines.standardExit.failClosedForRevalidation();
                if(isSameRevalidation(token))AndroidHomeStateStore.failed(context,message);
                return;
            }
            // AUTO/SMART/CUSTOM/logical paths are owned by the orchestrator.
            // Its normal disconnect path clears the current managed child. The
            // callback runs while orchestrator.running is still true, so a new
            // orchestrated session cannot slip between cleanup and failed state.
            engines.orchestrator.disconnect(new AndroidModeOrchestrator.Callback(){
                @Override public void progress(String ignored){}
                @Override public void finished(boolean ok,String ignoredMode,String cleanupMessage){
                    if(ok||isSameRevalidation(token)){
                        String suffix=ok?"":"; owner cleanup reported: "+safeMessage(cleanupMessage);
                        AndroidHomeStateStore.failed(context,message+suffix);
                    }
                }
            });
        }catch(Throwable cleanupError){
            // The token is still ours here; make the failed proof visible even
            // when owner teardown itself reports an error instead of leaving a
            // stale Connected/connecting state behind.
            if(isSameRevalidation(token))AndroidHomeStateStore.failed(context,message+"; owner cleanup failed: "+safe(cleanupError));
        }
    }

    private AndroidHomeStateStore.Snapshot requireSameRevalidation(AndroidHomeStateStore.Snapshot token){
        AndroidHomeStateStore.Snapshot now=AndroidHomeStateStore.snapshot(context);
        if(!sameRevalidation(token,now))throw new IllegalStateException("Router VPN session/path generation changed during network-change revalidation.");
        return now;
    }

    private boolean isSameRevalidation(AndroidHomeStateStore.Snapshot token){return sameRevalidation(token,AndroidHomeStateStore.snapshot(context));}

    private static boolean sameRevalidation(AndroidHomeStateStore.Snapshot token,AndroidHomeStateStore.Snapshot now){
        return token!=null&&now!=null
                &&token.sessionId!=null&&token.sessionId.equals(now.sessionId)
                &&now.pathGeneration==token.pathGeneration+1L
                &&"connecting".equals(now.phase)
                &&!now.connected
                &&"pending".equals(now.pathProof);
    }

    private static String safe(Throwable e){String value=e==null?"":e.getMessage();return value==null||value.trim().isEmpty()?"session proof failed":value.replace('\n',' ').replace('\r',' ').trim();}
    private static String safeMessage(String value){return value==null||value.trim().isEmpty()?"runtime cleanup failed":value.replace('\n',' ').replace('\r',' ').trim();}
}
