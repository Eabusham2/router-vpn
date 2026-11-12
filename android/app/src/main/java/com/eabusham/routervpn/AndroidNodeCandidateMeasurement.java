package com.eabusham.routervpn;

import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterNodeChainCandidateMeasurement;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

/** The original native slot and MTU lease survive cancellation and failed close. */
final class AndroidNodeCandidateMeasurement {
    interface Callback { void changed(List<AndroidNodeCandidateResult> results,String detail); void finished(Throwable failure); }
    private static AndroidNodeCandidateMeasurement active;
    final AndroidNodeCandidateCatalog catalog;
    private final Callback callback;
    private volatile boolean cancelled;
    private volatile RouterNodeChainCandidateMeasurement nativeOwner;
    private volatile String request="";
    private Object lease;
    private AndroidNodeCandidateMeasurement(AndroidNodeCandidateCatalog catalog,Callback callback){this.catalog=catalog;this.callback=callback;}
    static synchronized AndroidNodeCandidateMeasurement start(AndroidNodeCandidateCatalog catalog,Callback callback){
        if(active!=null)throw new IllegalStateException("An original candidate test still owns native cleanup.");
        AndroidNodeCandidateMeasurement operation=new AndroidNodeCandidateMeasurement(catalog,callback);
        operation.lease=AndroidMTUMeasurementGate.acquire();active=operation;
        new Thread(operation::run,"retained-prefix-candidates").start();return operation;
    }
    static synchronized boolean cancelActive(){if(active==null)return false;active.cancel();return true;}
    static synchronized boolean busy(){return active!=null;}
    void cancel(){cancelled=true;RouterNodeChainCandidateMeasurement value=nativeOwner;if(value!=null&&!request.isEmpty())value.cancel(request);}
    private void run(){
        Throwable failure=null;List<AndroidNodeCandidateResult> results=new ArrayList<>();
        try {
            catalog.requireCurrent();
            nativeOwner=Libbox.routerNodeChainNewCandidateMeasurement(catalog.session.capture.plan,catalog.server,catalog.prefix,catalog.inventory,catalog);
            if(nativeOwner==null)throw new IllegalStateException("Native candidate owner was not returned.");
            JSONObject metadata=new JSONObject(nativeOwner.metadata());
            if(!nativeOwner.captureSHA256().equals(metadata.getString("capture_sha256"))||catalog.prefix!=metadata.getInt("prefix_position")
                    ||!catalog.session.capture.plan.sourceSHA256().equals(metadata.getString("source_sha256"))
                    ||!catalog.session.capture.plan.configSHA256().equals(metadata.getString("config_sha256")))throw new IllegalStateException("Candidate metadata belongs to another original chain.");
            for(AndroidNodeCandidateCatalog.Row row:catalog.rows){
                if(cancelled)break;
                if(row.input.isEmpty())continue;
                catalog.requireCurrent();request=UUID.randomUUID().toString().replace("-","");
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
                nativeOwner.drain(request);catalog.requireCurrent();
                if(cancelled)break;
                try { results.add(AndroidNodeCandidateResult.capture(raw,request,metadata,row.id,row.name,System.currentTimeMillis())); }
                catch(Exception noScore){ /* Failed or partial candidates keep an explicit no-score row. */ }
                publish(results,"50 TCP connections per eligible candidate; any failed sample has no score.");
            }
            while(!cancelled&&!results.isEmpty()){
                catalog.requireCurrent();JSONObject current=new JSONObject(nativeOwner.statusJSON());
                if("invalidated".equals(current.optString("stage"))||!current.optString("failure").isEmpty())throw new IllegalStateException("The retained candidate proof changed.");
                publish(results,"Completed TCP connection times. Results expire 120 seconds after each completion; close to release MTU.");
                Thread.sleep(250);
            }
        } catch(Throwable error){failure=error;}
        finally {
            cancelled=true;
            // A failed constructor can still retain a late native callback. The
            // exact captured factory args let cleanup recover that original slot.
            boolean joined=false;
            while(!joined){
                try {
                    RouterNodeChainCandidateMeasurement value=nativeOwner;
                    if(value!=null){if(!request.isEmpty())value.cancel(request);value.close();}
                    else Libbox.routerNodeChainCloseCandidateMeasurement(catalog.session.capture.plan,catalog.prefix,catalog.inventory);
                    joined=true;
                } catch(Exception pending){
                    if(failure==null)failure=pending;
                    callback.changed(java.util.Collections.emptyList(),"Cancelling; the original native callbacks are still draining and MTU remains paused.");
                    try{Thread.sleep(250);}catch(InterruptedException ignored){}
                }
            }
            synchronized(AndroidNodeCandidateMeasurement.class){if(active==this){AndroidMTUMeasurementGate.release(lease);active=null;}}
            callback.finished(failure);
        }
    }
    private void publish(List<AndroidNodeCandidateResult> values,String detail){
        catalog.requireCurrent();long now=System.currentTimeMillis();values.removeIf(result->!result.current(now));
        values.sort(Comparator.comparingDouble(result->result.score));callback.changed(java.util.Collections.unmodifiableList(new ArrayList<>(values)),detail);
    }
}
