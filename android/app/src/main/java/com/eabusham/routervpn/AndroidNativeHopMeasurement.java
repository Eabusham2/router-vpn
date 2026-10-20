package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.UUID;

/** A bounded request on one retained native path, with MTU exclusion through drain. */
final class AndroidNativeHopMeasurement {
    interface Callback { void progress(String status); void finished(String status,Throwable error); }
    private static final class Job {
        final String id=UUID.randomUUID().toString().replace("-","");
        final Object lease;
        final boolean releaseLease;
        final Callback callback;
        LayeredVpnService.HopMeasurementOwner owner;
        volatile boolean cancelled;
        boolean quiesced;
        Job(Object lease,boolean releaseLease,Callback callback){this.lease=lease;this.releaseLease=releaseLease;this.callback=callback;}
    }
    private volatile Job active;
    boolean isRunning(){return active!=null;}

    void run(Object borrowedLease,Callback callback){
        final Job job;
        synchronized(this){
            if(active!=null){callback.finished(null,new IllegalStateException("A native path measurement still owns its request."));return;}
            Object lease=null;
            try{
                lease=borrowedLease==null?AndroidMTUMeasurementGate.acquire():borrowedLease;
                if(!AndroidMTUMeasurementGate.owns(lease))throw new IllegalStateException("The captured MTU measurement hold changed.");
                job=new Job(lease,borrowedLease==null,callback);job.owner=LayeredVpnService.captureHopMeasurement(job.id);active=job;
            }catch(Throwable error){if(borrowedLease==null)AndroidMTUMeasurementGate.release(lease);callback.finished(null,error);return;}
        }
        LayeredVpnService.quiesceMTUForSpeedLab(error->{
            synchronized(AndroidNativeHopMeasurement.this){if(active!=job||job.quiesced)return;job.quiesced=true;}
            new Thread(()->measure(job,error),"routervpn-native-hop-measurement").start();
        });
    }

    void cancel(){Job job=active;if(job==null)return;job.cancelled=true;job.owner.cancel();}

    private void measure(Job job,Throwable initial){
        Throwable failure=initial;String result=null;
        try{
            if(failure!=null)throw new IllegalStateException("MTU work did not drain before path measurement.",failure);
            if(job.cancelled||!AndroidMTUMeasurementGate.owns(job.lease))throw new IllegalStateException("Path measurement was cancelled before startup.");
            job.owner.start();long deadline=System.nanoTime()+100_000_000_000L;
            for(;;){
                if(job.cancelled)throw new IllegalStateException("Path measurement cancelled.");
                if(System.nanoTime()>deadline)throw new IllegalStateException("Path measurement timed out.");
                String response=job.owner.status();JSONObject status=validate(response,job.id);
                job.callback.progress(response);
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
        if(job.cancelled&&failure==null)failure=new IllegalStateException("Path measurement cancelled.");
        synchronized(this){if(active!=job)return;active=null;if(job.releaseLease)AndroidMTUMeasurementGate.release(job.lease);}
        job.callback.finished(failure==null?result:null,failure);
    }

    private static JSONObject validate(String response,String id)throws Exception{
        if(response==null||response.length()>16384)throw new IllegalStateException("Oversized native measurement response.");
        JSONObject status=new JSONObject(response);JSONArray results=status.optJSONArray("results");
        if(!id.equals(status.optString("request_id"))||!(status.get("complete") instanceof Boolean)||!(status.get("drained") instanceof Boolean)||results==null||results.length()>2)throw new IllegalStateException("Native measurement returned another request or invalid results.");
        return status;
    }
    private static String draining(String id){return "{\"request_id\":\""+id+"\",\"stage\":\"draining native workers; MTU remains held\",\"complete\":false,\"drained\":false,\"results\":[]}";}
}
