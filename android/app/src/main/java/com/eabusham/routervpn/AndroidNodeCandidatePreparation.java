package com.eabusham.routervpn;

import android.content.Context;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Process-owned, initially idle candidate testing. Accepted packet prefixes
 * use a closed-ingress native purpose independent of the saved suffix. Other
 * saved paths retain the complete-graph flow. Results require exact native DOWN. */
final class AndroidNodeCandidatePreparation implements AndroidNodeChainRuntime.TemporaryGuard {
    final String nonce=java.util.UUID.randomUUID().toString().replace("-","");
    interface Callback {
        void progress(String detail);
        void finished(List<Choice> choices,Throwable failure);
    }
    static final class Choice {
        final AndroidNodeCandidateResult result;
        final AndroidNodeCandidateProfile profile;
        private Choice(AndroidNodeCandidateResult result,AndroidNodeCandidateProfile profile){this.result=result;this.profile=profile;}
    }
    private static AndroidNodeCandidatePreparation active;
    private final Context context;
    private final AndroidNodeChainRuntime runtime;
    private final AndroidNodeStore.ChainCapture source;
    private final AndroidHomeStateStore.Snapshot idle;
    private final String selected;
    private final int prefix;
    private final Map<String,?> settings;
    private volatile Callback observer;
    private volatile String detail="Waiting for Android VPN permission to test the saved path.";
    private long observerVersion;
    private AndroidExternalComparisonNetwork network;
    private Object lease;
    private AndroidNodeChainRuntime.Temporary temporary;
    private volatile AndroidNodeCandidateMeasurement measurement;
    private volatile AndroidNodeCandidateCatalog catalog;
    private AndroidNodeChainCapture capturedSource;
    private AndroidNodeCandidatePrefixCapture capturedPrefix;
    private volatile boolean started,startupDone,startupOK,startingMeasurement,stopRequested,userCancelled,batchDone,retired;
    private volatile boolean terminalCompletionReady;
    private volatile Throwable failure;
    private volatile String homeSession="";
    private volatile List<Choice> choices=Collections.emptyList();
    private AndroidHomeStateStore.Snapshot resultHome;

    private AndroidNodeCandidatePreparation(Context context,AndroidNodeChainRuntime runtime,
            AndroidNodeStore.ChainCapture source,AndroidHomeStateStore.Snapshot idle,String selected,int prefix,Callback observer) {
        this.context=context.getApplicationContext();this.runtime=runtime;this.source=source;this.idle=idle;
        this.selected=selected;this.prefix=prefix;this.observer=observer;
        settings=Collections.unmodifiableMap(new HashMap<>(this.context.getSharedPreferences("router-vpn-unified",Context.MODE_PRIVATE).getAll()));
    }
    /** Background capture before VPN permission. The returned owner starts no VPN. */
    static synchronized AndroidNodeCandidatePreparation reserve(Context context,AndroidNodeChainRuntime runtime,
            AndroidNodeStore.ChainCapture source,AndroidHomeStateStore.Snapshot idle,String selected,int prefix,Callback observer)throws Exception {
        if(active!=null)throw new IllegalStateException("The previous candidate preparation still owns cleanup or its result observer.");
        if(source==null||idle==null||prefix<0||prefix>=source.modes.size())throw new IllegalStateException("The saved original prefix is missing.");
        String mode=source.modes.get(prefix);
        if(!"local".equals(source.execution)||!("wg".equals(mode)||"awg2-fast".equals(mode)||"awg2-strong".equals(mode)))
            throw new IllegalStateException("This saved Local prefix cannot prepare candidate TCP timing.");
        AndroidNodeCandidatePreparation owner=new AndroidNodeCandidatePreparation(context,runtime,source,idle,selected,prefix,observer);
        active=owner;
        try {
            owner.lease=AndroidMTUMeasurementGate.acquire();
            owner.network=new AndroidExternalComparisonNetwork(owner.context);owner.network.start();owner.network.requireBeforeStart();
            owner.requireCurrent();
            if(packetPrefix(source,prefix)){
                owner.catalog=AndroidNodeCandidateCatalog.captureSources(context,source,prefix);
                owner.capturedSource=AndroidNodeChainCapture.compile(source);
                owner.capturedPrefix=AndroidNodeCandidatePrefixCapture.compile(owner.capturedSource,prefix,owner.catalog.inventory);
                owner.requireCurrent();
            }
            owner.temporary=runtime.reserveTemporary(source,idle,selected,owner,new AndroidNodeChainRuntime.Callback(){
                public void progress(String detail){owner.progress((owner.capturedPrefix==null?"Testing saved path: ":"Testing saved packet prefix: ")+detail);}
                public void owned(String home){owner.homeSession=home;}
                public void finished(boolean ok,String detail){owner.startupOK=ok;if(!ok)owner.failure=new IllegalStateException(detail);owner.startupDone=true;}
            },owner.capturedPrefix,owner.capturedPrefix==null?null:owner.catalog);
        } catch(Throwable failed){owner.failure=failed;owner.stopRequested=true;}
        // This watcher, not the permission callback or Activity, owns every
        // failed candidate/native join and the outer MTU hold through retry.
        new Thread(owner::watch,"temporary-ordered-candidate-owner").start();
        return owner;
    }
    static synchronized boolean busy(){return active!=null&&!active.retired;}
    static synchronized AndroidNodeCandidatePreparation retained(){return active;}
    static synchronized boolean testingHome(String home){return active!=null&&!active.retired&&active.homeSession.equals(home);}
    static synchronized boolean cancelActive(){if(active==null)return false;active.cancelFromUser();return true;}
    static boolean packetPrefix(AndroidNodeStore.ChainCapture source,int prefix){
        if(source==null||!"local".equals(source.execution)||prefix<0||prefix>=source.modes.size()-1)return false;
        for(int i=0;i<=prefix;i++){String mode=source.modes.get(i);if(!("wg".equals(mode)||"awg2-fast".equals(mode)||"awg2-strong".equals(mode)))return false;}
        return true;
    }
    boolean prefixOnly(){return capturedPrefix!=null;}
    boolean testsSavedPosition(int position){return position>=0&&position<source.modes.size()&&(!packetPrefix(source,prefix)||position<=prefix);}
    void attach(Callback callback){
        synchronized(this){observer=callback;observerVersion++;}
        if(terminalCompletionReady&&callback!=null)try{callback.finished(choices,failure);}catch(Throwable ignored){}
        else if(!retired&&callback!=null)try{callback.progress(detail);}catch(Throwable ignored){}
    }
    void detach(Callback callback){synchronized(this){if(observer==callback){observer=null;observerVersion++;}}}
    synchronized boolean observes(Callback callback){return observer==callback;}
    void cancelFromUser(){userCancelled=true;cancel();}
    void start() {
        synchronized(this){
            if(started||stopRequested||temporary==null)throw new IllegalStateException("The captured temporary permission owner is unavailable.");
            started=true;
            try{temporary.start();}catch(Throwable failed){failure=failed;stopRequested=true;}
        }
    }
    @Override public void requireCurrent()throws Exception {
        if(stopRequested||retired||!AndroidMTUMeasurementGate.owns(lease))throw new IllegalStateException("The original candidate preparation was retired.");
        requireSavedInputs();if(capturedPrefix!=null)catalog.requireSourcesCurrent();network.requireCurrent();
    }
    private void requireSavedInputs()throws Exception {
        source.requireCurrent();AndroidNodeChainSession.requireSelection(context,source,selected);
        if(capturedPrefix!=null)capturedPrefix.requireCurrent();
        if(!settings.equals(context.getSharedPreferences("router-vpn-unified",Context.MODE_PRIVATE).getAll()))
            throw new IllegalStateException("The captured connection settings changed during candidate preparation.");
    }
    @Override public void cancel(){stopRequested=true;AndroidNodeCandidateMeasurement worker=measurement;if(worker!=null)worker.cancel();}
    @Override public boolean drain(){
        cancel();
        if(startingMeasurement)return false;
        AndroidNodeCandidateMeasurement worker=measurement;return worker==null||worker.joined();
    }
    private void progress(String detail){this.detail=detail;Callback callback=observer;if(callback!=null)try{callback.progress(detail);}catch(Throwable ignored){}}
    private void beginMeasurement()throws Exception {
        startingMeasurement=true;
        try {
            requireCurrent();AndroidNodeChainSession session=temporary.session();
            network.requireProved(LayeredVpnService.prepareNodeCandidates(session,lease));requireCurrent();
            if(capturedPrefix==null)catalog=new AndroidNodeCandidateCatalog(context,session,prefix);
            else if(session.candidatePrefix!=capturedPrefix||session.candidateCatalog!=catalog)throw new IllegalStateException("The original prepared packet prefix was replaced.");
            requireCurrent();
            measurement=AndroidNodeCandidateMeasurement.startBorrowed(catalog,lease,new AndroidNodeCandidateMeasurement.Callback(){
                public void changed(List<AndroidNodeCandidateResult> ignored,String detail){progress("Testing candidates: "+detail);}
                public void completed(AndroidNodeCandidateMeasurement owner,List<AndroidNodeCandidateResult> results)throws Exception {
                    requireCurrent();List<Choice> captured=new ArrayList<>();
                    for(AndroidNodeCandidateResult result:results){
                        owner.requireResult(result);
                        captured.add(new Choice(result,AndroidNodeCandidateProfile.captureTemporary(owner,result,AndroidNodeCandidatePreparation.this::requireSavedResultCurrent)));
                    }
                    requireCurrent();choices=Collections.unmodifiableList(captured);batchDone=true;
                }
                public void finished(Throwable failed){if(failed!=null)failure=failed;if(!batchDone)stopRequested=true;}
            });
            if(stopRequested)measurement.cancel();
        } finally {startingMeasurement=false;}
    }
    private void watch() {
        try {
            while(!stopRequested&&!batchDone&&failure==null){
                requireCurrent();
                if(started&&startupDone){if(!startupOK)break;if(measurement==null)beginMeasurement();}
                Thread.sleep(100);
            }
        } catch(Throwable failed){failure=failed;}
        // Do not release the outer lease when the candidate joins: the complete
        // native graph can still own a failed Box/TUN close independently.
        boolean joined=false;
        while(!joined){
            try {
                joined=temporary==null?drain():temporary.drain();
                if(joined){
                    // Also join pure handles captured before permission or a
                    // failed native factory. They never lend Connected proof.
                    if(capturedPrefix!=null)capturedPrefix.close();
                    if(capturedSource!=null)capturedSource.close();
                }
            }
            catch(Throwable pending){joined=false;if(failure==null)failure=pending;}
            if(!joined){progress("Cancelling candidate test; original native cleanup is still pending and MTU remains paused.");pause();}
        }
        AndroidMTUMeasurementGate.release(lease);retired=true;
        try {
            if(measurement!=null&&measurement.completionFailure()!=null)failure=measurement.completionFailure();
            if(userCancelled||!batchDone||failure!=null)choices=Collections.emptyList();
            else {
                resultHome=AndroidHomeStateStore.snapshot(context);
                if(resultHome.connected||!resultHome.sessionId.isEmpty()||!"off".equals(resultHome.phase)
                        ||resultHome.pathGeneration!=idle.pathGeneration+2)
                    throw new IllegalStateException("The temporary graph did not return to its exact expected idle Home epoch.");
                for(Choice choice:choices)requireSavedResultCurrent(choice.result);
            }
        } catch(Throwable invalid){failure=invalid;choices=Collections.emptyList();}
        terminalCompletionReady=choices.isEmpty()||userCancelled;
        long delivered=deliverCompletion(-1);
        // Keep the captured network observer alive while the explicitly shown
        // result can authorize a future profile. A change-away/back retires it.
        while(!userCancelled&&!choices.isEmpty()){
            try{for(Choice choice:choices)requireSavedResultCurrent(choice.result);}
            catch(Throwable expired){failure=expired;choices=Collections.emptyList();terminalCompletionReady=true;deliverCompletion(-1);break;}
            delivered=deliverCompletion(delivered);
            pause();
        }
        if(userCancelled){choices=Collections.emptyList();terminalCompletionReady=true;deliverCompletion(-1);}
        boolean closed=network==null;
        while(!closed){try{network.close();closed=true;}catch(Throwable pending){pause();}}
        synchronized(AndroidNodeCandidatePreparation.class){if(active==this)active=null;}
        observer=null;
    }
    private long deliverCompletion(long delivered) {
        final Callback callback;final long version;
        synchronized(this){callback=observer;version=observerVersion;}
        if(version!=delivered&&callback!=null)try{callback.finished(choices,failure);}catch(Throwable ignored){}
        return version;
    }
    void requireSavedResultCurrent(AndroidNodeCandidateResult result)throws Exception {
        if(!retired||userCancelled||failure!=null||!batchDone||measurement==null||!measurement.joined()||resultHome==null
                ||!result.current(System.currentTimeMillis()))throw new IllegalStateException("Retest this completed original candidate before saving.");
        boolean found=false;for(Choice choice:choices)if(choice.result==result)found=true;
        if(!found)throw new IllegalStateException("This result does not belong to the original completed candidate batch.");
        requireSavedInputs();catalog.requireSavedSourcesCurrent();network.requireCurrent();
        AndroidHomeStateStore.Snapshot now=AndroidHomeStateStore.snapshot(context);
        if(runtime.isActiveOrTransitioning()||!sameIdle(now,resultHome)||AndroidHomeStateStore.emergencyDisconnectPending(context))
            throw new IllegalStateException("A newer connection or Home epoch retired the completed candidate batch.");
    }
    private static boolean sameIdle(AndroidHomeStateStore.Snapshot a,AndroidHomeStateStore.Snapshot b) {
        return !a.connected&&!b.connected&&a.pathGeneration==b.pathGeneration
                &&java.util.Arrays.asList(a.sessionId,a.phase,a.logicalMode,a.runtimeMode,a.actualBase,a.fallback,a.warning,a.pathProof,
                    a.activeNodeId,a.activeEntryId,a.activeExitId,a.activeEntryMode,a.activeChain,a.activeExternalId,a.activeExternalName,a.activeExternalProtocol,a.expectedExternalIp)
                .equals(java.util.Arrays.asList(b.sessionId,b.phase,b.logicalMode,b.runtimeMode,b.actualBase,b.fallback,b.warning,b.pathProof,
                    b.activeNodeId,b.activeEntryId,b.activeExitId,b.activeEntryMode,b.activeChain,b.activeExternalId,b.activeExternalName,b.activeExternalProtocol,b.expectedExternalIp));
    }
    private static void pause(){try{Thread.sleep(250);}catch(InterruptedException ignored){}}
}
