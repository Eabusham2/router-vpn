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
    // Captured beside Home state so another network change cannot race proof adoption.
    private long networkRevision;

    AndroidSessionRevalidator(Context context,AndroidRuntimeRegistry engines){
        this.context=context.getApplicationContext();this.engines=engines;this.monitor=new AndroidUnderlyingNetworkMonitor(this.context);
    }

    void start(){
        monitor.start(() -> {
            synchronized (AndroidHomeStateStore.class) {
                networkRevision++;
                AndroidHomeStateStore.Snapshot observed = AndroidHomeStateStore.snapshot(context);
                if (observed.connected && "passed".equals(observed.pathProof))
                    executor.execute(() -> revalidate(observed));
            }
        });
    }

    private void revalidate(AndroidHomeStateStore.Snapshot observed){
        if("node-chain".equals(observed.logicalMode)){
            // An ordered graph owns every dependency on the original physical network.
            engines.nodeChain.networkChanged(observed);return;
        }
        if("wg".equals(observed.actualBase)||"awg".equals(observed.actualBase)){
            if(!"multihop".equals(observed.logicalMode)&&!"external".equals(observed.logicalMode))return;
        }
        AndroidHomeStateStore.Snapshot token=AndroidHomeStateStore.beginPathRevalidation(
                context, observed,
                "Underlying network changed; re-proving the frozen Router VPN session before keeping Connected.");
        if(token==null)return;
        try {
            Thread.sleep(650L);
            final AndroidHomeStateStore.Snapshot current;
            final long revision;
            synchronized (AndroidHomeStateStore.class) {
                if (!AndroidHomeStateStore.pendingRevalidation(context, token)) return;
                current = AndroidHomeStateStore.snapshot(context);
                revision = networkRevision;
            }
            String observedExit = prove(current);
            synchronized (AndroidHomeStateStore.class) {
                if (revision != networkRevision)
                    throw new IllegalStateException("The physical network changed during its selected-path proof.");
                if (!AndroidHomeStateStore.completePathRevalidation(context, token, observedExit))
                    throw new IllegalStateException("The selected path or observed exit changed before proof adoption.");
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            failClosedOwnedRuntime(token, interrupted);
        } catch (Throwable error) {
            failClosedOwnedRuntime(token, error);
        }
    }

    private String prove(AndroidHomeStateStore.Snapshot current) throws Exception {
        if ("external".equals(current.logicalMode)) {
            if (AndroidTorProfile.isTor(current.activeExternalProtocol))
                return engines.standardExit.capturedTorExit(current);
            if (current.expectedExternalIp.isEmpty() || !AndroidExternalPolicy.supports(current.activeExternalProtocol))
                throw new IllegalStateException("External session has no captured native proof target.");
            return engines.standardExit.capturedExternalExit(current);
        }
        String nodeId = "multihop".equals(current.logicalMode) ? current.activeExitId : current.activeNodeId;
        if (nodeId.isEmpty()) throw new IllegalStateException("Active session node identity is missing after network change.");
        File bundle = new AndroidNodeStore(context).file(nodeId);
        if (!AndroidPathProbe.prove(bundle, 10000))
            throw new IllegalStateException("Frozen node private path proof failed after network change.");
        return null;
    }

    private void failClosedOwnedRuntime(AndroidHomeStateStore.Snapshot token, Throwable error) {
        String message = "Network-change revalidation failed closed: " + safe(error);
        try {
            boolean released;
            if ("multihop".equals(token.logicalMode)) released = engines.multihop.failClosedForRevalidation(token);
            else if ("external".equals(token.logicalMode)) released = engines.standardExit.failClosedForRevalidation(token);
            else released = engines.orchestrator.failClosedForRevalidation(token);
            if (released) AndroidHomeStateStore.failRevalidation(context, token, message, true);
        } catch (Throwable cleanupError) {
            AndroidHomeStateStore.failRevalidation(context, token, message + "; owner cleanup failed: " + safe(cleanupError), false);
        }
    }

    private static String safe(Throwable e){String value=e==null?"":e.getMessage();return value==null||value.trim().isEmpty()?"session proof failed":value.replace('\n',' ').replace('\r',' ').trim();}
}
