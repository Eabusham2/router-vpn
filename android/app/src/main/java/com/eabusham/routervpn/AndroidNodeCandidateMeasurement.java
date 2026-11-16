package com.eabusham.routervpn;

import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterNodeChainCandidateMeasurement;
import io.nekohasekai.libbox.RouterNodeChainCandidatePreparation;
import io.nekohasekai.libbox.RouterNodeChainSOCKSCandidateMeasurement;
import io.nekohasekai.libbox.RouterNodeChainCONNECTCandidateMeasurement;
import io.nekohasekai.libbox.RouterNodeChainExecutionCandidateMeasurement;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

/** The original native slot and MTU lease survive cancellation and failed close. */
final class AndroidNodeCandidateMeasurement {
    interface Callback {
        void changed(List<AndroidNodeCandidateResult> results,String detail);
        void finished(Throwable failure);
        default void completed(AndroidNodeCandidateMeasurement owner,List<AndroidNodeCandidateResult> results)throws Exception {}
    }
    private static AndroidNodeCandidateMeasurement active;
    final AndroidNodeCandidateCatalog catalog;
    private final Callback callback;
    private volatile boolean cancelled;
    private volatile NativeOwner nativeOwner;
    /** Both owners keep the same native fifty-sample protocol. Prefix-only
     * preparation already owns its closed-ingress native lifetime. */
    private static final class NativeOwner {
        final RouterNodeChainCandidateMeasurement connected;
        final RouterNodeChainCandidatePreparation prefix;
        final RouterNodeChainSOCKSCandidateMeasurement socks;
        final RouterNodeChainCONNECTCandidateMeasurement connect;
        final RouterNodeChainExecutionCandidateMeasurement execution;
        private String admittedRequest="";
        NativeOwner(RouterNodeChainCandidateMeasurement value){if(value==null)throw new IllegalStateException("Native candidate owner was not returned.");connected=value;prefix=null;socks=null;connect=null;execution=null;}
        NativeOwner(RouterNodeChainCandidatePreparation value){if(value==null)throw new IllegalStateException("Native prefix owner was not returned.");connected=null;prefix=value;socks=null;connect=null;execution=null;}
        NativeOwner(RouterNodeChainSOCKSCandidateMeasurement value){if(value==null)throw new IllegalStateException("Native SOCKS candidate owner was not returned.");connected=null;prefix=null;socks=value;connect=null;execution=null;}
        NativeOwner(RouterNodeChainCONNECTCandidateMeasurement value){if(value==null)throw new IllegalStateException("Native CONNECT candidate owner was not returned.");connected=null;prefix=null;socks=null;connect=value;execution=null;}
        NativeOwner(RouterNodeChainExecutionCandidateMeasurement value){if(value==null)throw new IllegalStateException("Native execution candidate owner was not returned.");connected=null;prefix=null;socks=null;connect=null;execution=value;}
        // Each connected constructor returns its unique reserved handle before
        // admitting any foreign callback. Store it before Prepare, so even a
        // failed preparation can retire only this exact original operation.
        void prepare()throws Exception{if(execution!=null)execution.prepare();else if(socks!=null)socks.prepare();else if(connect!=null)connect.prepare();else if(connected!=null)connected.prepare();}
        String metadata()throws Exception{return execution!=null?execution.metadata():socks!=null?socks.metadata():connect!=null?connect.metadata():prefix==null?connected.metadata():prefix.metadata();}
        String captureSHA256()throws Exception{return execution!=null?execution.captureSHA256():socks!=null?socks.captureSHA256():connect!=null?connect.captureSHA256():prefix==null?connected.captureSHA256():prefix.captureSHA256();}
        String statusJSON()throws Exception{return execution!=null?execution.statusJSON():socks!=null?socks.statusJSON():connect!=null?connect.statusJSON():prefix==null?connected.statusJSON():prefix.statusJSON();}
        void start(String request,String candidate)throws Exception{if(execution!=null)execution.start(request,candidate);else if(socks!=null)socks.start(request,candidate);else if(connect!=null)connect.start(request,candidate);else if(prefix==null)connected.start(request,candidate);else prefix.start(request,candidate);admittedRequest=request;}
        void cancel(String request){if(execution!=null)execution.cancel(request);else if(socks!=null)socks.cancel(request);else if(connect!=null)connect.cancel(request);else if(prefix==null)connected.cancel(request);else prefix.cancel(request);}
        void drain(String request)throws Exception{if(execution!=null)execution.drain(request);else if(socks!=null)socks.drain(request);else if(connect!=null)connect.drain(request);else if(prefix==null)connected.drain(request);else prefix.drain(request);}
        // The shared prefix is the outer service's proof owner. A failed native
        // Start joins its admission before returning; successful requests keep
        // their exact drain authority until callbacks and native holds join.
        // Connected handles close only their candidate operation, retaining the
        // exact complete typed connection and its existing proof owner.
        void close()throws Exception{if(execution!=null)execution.close();else if(socks!=null)socks.close();else if(connect!=null)connect.close();else if(prefix==null)connected.close();else if(!admittedRequest.isEmpty())prefix.drain(admittedRequest);}
    }
    private NativeOwner captureNativeOwner(AndroidNodeCandidatePrefixCapture prefix)throws Exception {
        // A temporary closed prefix always owns its measurement. Its typed
        // saved suffix is source provenance and must not be started here.
        if(prefix!=null)return new NativeOwner(prefix.plan);
        if(catalog.executionOwner!=null){
            if(catalog.prefix!=0||catalog.session.candidateExecutionOwner()!=catalog.executionOwner)
                throw new IllegalStateException("The original selected entry candidate owner changed.");
            return new NativeOwner(Libbox.routerNodeChainExecutionNewCandidateMeasurement(catalog.executionOwner,catalog.server,catalog.prefix,catalog.inventory,catalog));
        }
        AndroidNodeChainCapture captured=catalog.session.capture;
        if(captured.socks!=null||captured.connect!=null){
            if(!"local".equals(catalog.session.source.execution)||captured.plan!=null
                    ||captured.socks!=null&&captured.connect!=null)
                throw new IllegalStateException("Candidate TCP timing on this typed path requires its active Local execution.");
            if(captured.connect!=null)return new NativeOwner(Libbox.routerNodeChainCONNECTNewCandidateMeasurement(captured.connect.plan,catalog.server,catalog.prefix,catalog.inventory,catalog));
            return new NativeOwner(Libbox.routerNodeChainSOCKSNewCandidateMeasurement(captured.socks.plan,catalog.server,catalog.prefix,catalog.inventory,catalog));
        }
        if(!"local".equals(catalog.session.source.execution))throw new IllegalStateException("A selected execution cannot borrow a Local candidate owner.");
        return new NativeOwner(Libbox.routerNodeChainNewCandidateMeasurement(captured.plan,catalog.server,catalog.prefix,catalog.inventory,catalog));
    }

    private String retainedMetadata;
    private JSONObject requireMetadata()throws Exception {
        catalog.requireCurrent();String raw=nativeOwner.metadata();JSONObject metadata=new JSONObject(raw);
        if(!nativeOwner.captureSHA256().equals(metadata.getString("capture_sha256"))||catalog.prefix!=metadata.getInt("prefix_position"))
            throw new IllegalStateException("Candidate metadata belongs to another original chain.");
        if(catalog.executionOwner!=null){
            var owner=catalog.executionOwner;
            Object epoch=metadata.get("selection_epoch");
            if(catalog.prefix!=0||catalog.session.candidateExecutionOwner()!=owner
                    ||!owner.sourceSHA256().equals(metadata.getString("preparation_source_sha256"))
                    ||!owner.configSHA256().equals(metadata.getString("preparation_config_sha256"))
                    ||!catalog.originalSource.execution.equals(metadata.getString("requested_execution"))
                    ||!owner.requestedExecution().equals(metadata.getString("requested_execution"))
                    ||!owner.execution().equals(metadata.getString("execution"))
                    ||!(epoch instanceof Integer||epoch instanceof Long)||((Number)epoch).longValue()<=0
                    ||!metadata.getString("source_sha256").matches("[0-9a-f]{64}")
                    ||!metadata.getString("config_sha256").matches("[0-9a-f]{64}"))
                throw new IllegalStateException("Candidate metadata lost the selected preparation, projection or epoch.");
        }else{
            AndroidNodeCandidatePrefixCapture originalPrefix=catalog.session.candidatePrefix;
            if(!(originalPrefix==null?catalog.session.capture.sourceSHA256:originalPrefix.sourceSHA256).equals(metadata.getString("source_sha256"))
                    ||!(originalPrefix==null?catalog.session.capture.configSHA256:originalPrefix.configSHA256).equals(metadata.getString("config_sha256")))
                throw new IllegalStateException("Candidate metadata belongs to another original chain.");
        }
        if(retainedMetadata!=null&&!retainedMetadata.equals(raw))throw new IllegalStateException("The original candidate metadata was replaced.");
        retainedMetadata=raw;catalog.requireCurrent();return metadata;
    }

    private volatile String request="";
    private Object lease;
    private boolean borrowedLease;
    private final java.util.concurrent.CountDownLatch joined=new java.util.concurrent.CountDownLatch(1);
    private volatile Throwable completionFailure;
    private volatile List<AndroidNodeCandidateResult> admitted=java.util.Collections.emptyList();
    synchronized void requireResult(AndroidNodeCandidateResult result)throws Exception {
        if(cancelled||nativeOwner==null||!admitted.contains(result)||!result.current(System.currentTimeMillis()))throw new IllegalStateException("Retest this candidate before saving its next connection.");
        requireMetadata();JSONObject current=new JSONObject(nativeOwner.statusJSON());
        if("invalidated".equals(current.optString("stage"))||!current.optString("failure").isEmpty())throw new IllegalStateException("The original native prefix proof changed.");
        catalog.requireCurrent();
    }
    private AndroidNodeCandidateMeasurement(AndroidNodeCandidateCatalog catalog,Callback callback){this.catalog=catalog;this.callback=callback;}
    static synchronized AndroidNodeCandidateMeasurement start(AndroidNodeCandidateCatalog catalog,Callback callback){
        if(active!=null)throw new IllegalStateException("An original candidate test still owns native cleanup.");
        AndroidNodeCandidateMeasurement operation=new AndroidNodeCandidateMeasurement(catalog,callback);
        operation.lease=AndroidMTUMeasurementGate.acquire();active=operation;
        new Thread(operation::run,"retained-prefix-candidates").start();return operation;
    }
    /** The preparation owns this outer lease until its complete graph joins.
     * This worker retires only its inner native candidate activity. */
    static synchronized AndroidNodeCandidateMeasurement startBorrowed(AndroidNodeCandidateCatalog catalog,Object lease,Callback callback){
        if(active!=null)throw new IllegalStateException("An original candidate test still owns native cleanup.");
        if(callback==null||!AndroidMTUMeasurementGate.owns(lease))throw new IllegalStateException("The original preparation MTU lease is unavailable.");
        AndroidNodeCandidateMeasurement operation=new AndroidNodeCandidateMeasurement(catalog,callback);
        operation.lease=lease;operation.borrowedLease=true;active=operation;
        try{new Thread(operation::run,"temporary-prefix-candidates").start();}
        catch(Throwable failed){active=null;throw failed;}
        return operation;
    }
    static synchronized boolean cancelActive(){if(active==null)return false;active.cancel();return true;}
    static synchronized boolean busy(){return active!=null;}
    boolean joined(){return joined.getCount()==0;}
    Throwable completionFailure(){return completionFailure;}
    void cancel(){synchronized(this){cancelled=true;}NativeOwner value=nativeOwner;if(value!=null&&!request.isEmpty())value.cancel(request);}
    private void run(){
        Throwable failure=null;List<AndroidNodeCandidateResult> results=new ArrayList<>();
        try {
            catalog.requireCurrent();
            AndroidNodeCandidatePrefixCapture prefix=catalog.session.candidatePrefix;
            nativeOwner=captureNativeOwner(prefix);
            if(nativeOwner==null)throw new IllegalStateException("Native candidate owner was not returned.");
            nativeOwner.prepare();
            JSONObject metadata=requireMetadata();
            for(AndroidNodeCandidateCatalog.Row row:catalog.rows){
                if(cancelled)break;
                if(row.input.isEmpty())continue;
                requireMetadata();request=UUID.randomUUID().toString().replace("-","");
                nativeOwner.start(request,row.id);
                long deadline=System.nanoTime()+95_000_000_000L;String raw;
                while(true){
                    if(cancelled)nativeOwner.cancel(request);
                    raw=nativeOwner.statusJSON();JSONObject status=new JSONObject(raw);
                    if(!request.equals(status.optString("request_id")))throw new IllegalStateException("Candidate request was replaced.");
                    publish(results,"TCP connection samples through the retained prefix: "+row.name+" • "+status.optString("stage"));
                    if(status.optBoolean("complete")&&status.optBoolean("drained"))break;
                    if(System.nanoTime()>=deadline)throw new IllegalStateException("Candidate operation exceeded its complete bounded lifetime.");
                    Thread.sleep(100);
                }
                nativeOwner.drain(request);requireMetadata();
                if(cancelled)break;
                try { results.add(AndroidNodeCandidateResult.capture(raw,request,metadata,row.id,row.name,System.currentTimeMillis())); }
                catch(Exception noScore){ /* Failed or partial candidates keep an explicit no-score row. */ }
                publish(results,"50 TCP connections per eligible candidate; any failed sample has no score.");
            }
            if(borrowedLease&&!cancelled){catalog.requireCurrent();callback.completed(this,admitted);}
            while(!borrowedLease&&!cancelled&&!results.isEmpty()){
                requireMetadata();JSONObject current=new JSONObject(nativeOwner.statusJSON());
                if("invalidated".equals(current.optString("stage"))||!current.optString("failure").isEmpty())throw new IllegalStateException("The retained candidate proof changed.");
                publish(results,"Completed TCP connection times. Results expire 120 seconds after each completion; close to release MTU.");
                Thread.sleep(250);
            }
        } catch(Throwable error){failure=error;}
        finally {
            synchronized(this){cancelled=true;}
            // Every connected preparation retains its unique returned handle.
            // Constructor rejection owns no reservation; failed Prepare closes
            // only this operation, never an owner/key-matched replacement.
            boolean joined=false;
            while(!joined){
                try {
                    NativeOwner value=nativeOwner;
                    if(value!=null){if(!request.isEmpty())value.cancel(request);value.close();}
                    else if(catalog.session.candidatePrefix!=null){ /* No request was admitted by this worker. The service retains the prefix. */ }
                    joined=true;
                } catch(Exception pending){
                    if(failure==null)failure=pending;
                    try { callback.changed(java.util.Collections.emptyList(),"Cancelling; the original native callbacks are still draining and MTU remains paused."); }
                    catch(Throwable observerFailure){ /* An observer cannot abandon retained native cleanup. */ }
                    try{Thread.sleep(250);}catch(InterruptedException ignored){}
                }
            }
            synchronized(AndroidNodeCandidateMeasurement.class){if(active==this){if(!borrowedLease)AndroidMTUMeasurementGate.release(lease);active=null;}}
            // A cleanup watcher may itself be the observer. Publish the actual
            // native join before invoking it, and never let observer failure
            // discard the preparation's outer graph/MTU cleanup authority.
            completionFailure=failure;this.joined.countDown();
            try{callback.finished(failure);}catch(Throwable ignored){}
        }
    }
    private void publish(List<AndroidNodeCandidateResult> values,String detail){
        try{requireMetadata();}catch(Exception stale){throw new IllegalStateException("Candidate metadata changed before publication.",stale);}
        catalog.requireCurrent();long now=System.currentTimeMillis();values.removeIf(result->!result.current(now));
        values.sort(Comparator.comparingDouble(result->result.score));admitted=java.util.Collections.unmodifiableList(new ArrayList<>(values));callback.changed(admitted,detail);
    }
}
