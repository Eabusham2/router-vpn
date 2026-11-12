package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.UUID;

/** A bounded request on one retained native path, with MTU exclusion through drain. */
final class AndroidNativeHopMeasurement {
    interface Callback {
        void progress(String status); void finished(String status,Throwable error);
        /** The UI must recheck this exact native owner after its delivery queue. */
        default void progress(LayeredVpnService.HopMeasurementOwner owner,String status){progress(status);}
        /** Called after the exact native workers drain, while cancellation and
         * the MTU hold still belong to this request. */
        default void commit(LayeredVpnService.HopMeasurementOwner owner,String status)throws Exception{}
    }
    private static final class Job {
        final String id=UUID.randomUUID().toString().replace("-","");
        final Object lease;
        final boolean releaseLease;
        final boolean responseOnly;
        final Callback callback;
        LayeredVpnService.HopMeasurementOwner owner;
        volatile boolean cancelled;
        boolean quiesced;
        Job(Object lease,boolean releaseLease,boolean responseOnly,Callback callback){this.lease=lease;this.releaseLease=releaseLease;this.responseOnly=responseOnly;this.callback=callback;}
    }
    private volatile Job active;
    boolean isRunning(){return active!=null;}

    void run(Object borrowedLease,Callback callback){
        run(borrowedLease,null,"","",-1,false,callback);
    }

    void runLatency(String exitID,String nativeSession,String homeSession,long pathGeneration,Callback callback){
        runLatency(null,exitID,nativeSession,homeSession,pathGeneration,callback);
    }

    void runLatency(Object borrowedLease,String exitID,String nativeSession,String homeSession,long pathGeneration,Callback callback){
        if(exitID==null||exitID.isEmpty()){callback.finished(null,new IllegalArgumentException("Select a captured external node."));return;}
        run(borrowedLease,exitID,nativeSession,homeSession,pathGeneration,false,callback);
    }

    /** Fixed three-response live sample; never requests a saved benchmark or transfer. */
    void runResponse(String exitID,String nativeSession,String homeSession,long pathGeneration,Callback callback){
        if(exitID==null||exitID.isEmpty()){callback.finished(null,new IllegalArgumentException("Select a captured external node."));return;}
        run(null,exitID,nativeSession,homeSession,pathGeneration,true,callback);
    }

    private void run(Object borrowedLease,String exitID,String nativeSession,String homeSession,long pathGeneration,boolean responseOnly,Callback callback){
        final Job job;
        synchronized(this){
            if(active!=null){callback.finished(null,new IllegalStateException("A native path measurement still owns its request."));return;}
            Object lease=null;
            try{
                lease=borrowedLease==null?AndroidMTUMeasurementGate.acquire():borrowedLease;
                if(!AndroidMTUMeasurementGate.owns(lease))throw new IllegalStateException("The captured MTU measurement hold changed.");
                job=new Job(lease,borrowedLease==null,responseOnly,callback);
                job.owner=exitID==null?LayeredVpnService.captureHopMeasurement(job.id):LayeredVpnService.captureExternalHopMeasurement(job.id,exitID,nativeSession,homeSession,pathGeneration);
                // Automatic live polling yields to an existing MTU run. The
                // acquired gate prevents a new MTU start before native drain.
                if(responseOnly)job.owner.requireResponseIdle();active=job;
            }catch(Throwable error){if(borrowedLease==null)AndroidMTUMeasurementGate.release(lease);callback.finished(null,error);return;}
        }
        LayeredVpnService.quiesceMTUForSpeedLab(error->{
            synchronized(AndroidNativeHopMeasurement.this){if(active!=job||job.quiesced)return;job.quiesced=true;}
            new Thread(()->measure(job,error),"routervpn-native-hop-measurement").start();
        });
    }

    void cancel(){final Job job;synchronized(this){job=active;if(job==null)return;job.cancelled=true;}job.owner.cancel();}

    private void measure(Job job,Throwable initial){
        Throwable failure=initial;String result=null;
        try{
            if(failure!=null)throw new IllegalStateException("MTU work did not drain before path measurement.",failure);
            if(job.cancelled||!AndroidMTUMeasurementGate.owns(job.lease))throw new IllegalStateException("Path measurement was cancelled before startup.");
            if(job.responseOnly)job.owner.startResponse();else job.owner.start();
            long deadline=System.nanoTime()+(job.responseOnly?15_000_000_000L:100_000_000_000L);
            for(;;){
                if(job.cancelled)throw new IllegalStateException("Path measurement cancelled.");
                if(System.nanoTime()>deadline)throw new IllegalStateException("Path measurement timed out.");
                String response=job.owner.status();JSONObject status=validate(response,job.id);
                job.callback.progress(job.owner,response);
                if(status.getBoolean("complete")){result=response;break;}
                Thread.sleep(300L);
            }
        }catch(Throwable error){failure=error;}
        if(job.owner.started()){
            if(failure!=null||job.cancelled)job.owner.cancel();
            boolean joined=false;
            while(!joined){
                try{job.owner.drain();joined=true;}
                catch(Throwable pending){
                    // A timed native join retains both the old probe and its
                    // MTU hold. Disconnect can drain the old Box concurrently.
                    job.owner.cancel();failure=new IllegalStateException("Path measurement cleanup is waiting for its captured native workers.",pending);
                    try{job.callback.progress(draining(job.id));}catch(Throwable abandoned){job.cancelled=true;}
                    try{Thread.sleep(250L);}catch(InterruptedException interrupted){Thread.interrupted();job.cancelled=true;}
                }
            }
            if(failure==null&&!job.cancelled){
                try{result=job.owner.status();JSONObject status=validate(result,job.id);if(!status.getBoolean("complete")||!status.getBoolean("drained")||!status.optString("failure","").isEmpty())throw new IllegalStateException("The captured path did not return a complete drained measurement.");}
                catch(Throwable error){failure=error;}
            }
        }
        synchronized(this){
            if(active!=job)return;
            if(job.cancelled&&failure==null)failure=new IllegalStateException("Path measurement cancelled.");
            if(failure==null)try{job.callback.commit(job.owner,result);}catch(Throwable error){failure=error;}
            if(job.releaseLease)AndroidMTUMeasurementGate.release(job.lease);
            // Cancelling the short HTTPS request does not cancel the current
            // connection's first Auto run. Only this exact native owner may
            // resume its never-started policy after our workers and hold end.
            if(job.responseOnly)try{job.owner.resumeResponseMTU();}catch(Throwable changed){if(failure==null)failure=changed;}
            active=null;
        }
        job.callback.finished(failure==null?result:null,failure);
    }

    private static JSONObject validate(String response,String id)throws Exception{
        if(response==null||response.length()>16384)throw new IllegalStateException("Oversized native measurement response.");
        JSONObject status=new JSONObject(response);JSONArray results=status.optJSONArray("results");
        if(!id.equals(status.optString("request_id"))||!(status.get("complete") instanceof Boolean)||!(status.get("drained") instanceof Boolean)||results==null||results.length()>8)throw new IllegalStateException("Native measurement returned another request or invalid results.");
        return status;
    }
    private static String draining(String id){return "{\"request_id\":\""+id+"\",\"stage\":\"draining native workers; MTU remains held\",\"complete\":false,\"drained\":false,\"results\":[]}";}
}
