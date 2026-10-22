package com.eabusham.routervpn;

import org.json.JSONObject;
import java.util.UUID;

/** Native comparison; its owner and MTU hold survive UI close. Never writes settings. */
final class AndroidNativeDNSMeasurement {
    private static final long RESULT_LIFETIME_NS=120_000_000_000L;
    private final java.util.function.LongSupplier receiptClock;
    AndroidNativeDNSMeasurement(){this(System::nanoTime);}
    AndroidNativeDNSMeasurement(java.util.function.LongSupplier receiptClock){this.receiptClock=java.util.Objects.requireNonNull(receiptClock);}
    interface Callback { void progress(String stage); void finished(String result,Throwable error); }
    private static final class Job {
        final String id=UUID.randomUUID().toString().replace("-","");
        final String transport;
        final Object lease;
        final Callback callback;
        LayeredVpnService.DNSMeasurementOwner owner;
        volatile boolean cancelled;
        long completedAt;
        boolean quiesced;
        Job(String transport,Object lease,Callback callback){this.transport=transport;this.lease=lease;this.callback=callback;}
    }
    private volatile Job active;
    private volatile Job completed;
    boolean isRunning(){return active!=null;}
    JSONObject currentReceipt()throws Exception{
        Job job=completed;
        if(job==null||active!=null||job.cancelled||!fresh(job))throw new IllegalStateException("Retest DNS on the current connection before choosing a measured resolver. Results expire after two minutes.");
        JSONObject receipt=AndroidDNSMeasurementReceipt.validate(job.owner.status(),job.id,job.owner.nodeID,job.owner.sessionID,job.transport,true);
        if(completed!=job||active!=null||job.cancelled||!fresh(job))throw new IllegalStateException("The measured DNS request was replaced or expired.");
        return receipt;
    }
    private boolean fresh(Job job){long elapsed=receiptClock.getAsLong()-job.completedAt;return elapsed>=0&&elapsed<RESULT_LIFETIME_NS;}
    void run(String nodeID,String transport,Callback callback){
        final Job job;
        synchronized(this){
            if(active!=null){callback.finished(null,new IllegalStateException("DNS cleanup still owns this request."));return;}
            completed=null;
            Object lease=null;
            try{
                if(!java.util.Arrays.asList("tcp","tls","https").contains(transport))throw new IllegalArgumentException("Choose TCP, DoT or DoH.");
                lease=AndroidMTUMeasurementGate.acquire();job=new Job(transport,lease,callback);
                job.owner=LayeredVpnService.captureDNSMeasurement(job.id,nodeID);active=job;
            }catch(Throwable error){AndroidMTUMeasurementGate.release(lease);callback.finished(null,error);return;}
        }
        LayeredVpnService.quiesceMTUForSpeedLab(error->{
            synchronized(AndroidNativeDNSMeasurement.this){if(active!=job||job.quiesced)return;job.quiesced=true;}
            new Thread(()->measure(job,error),"routervpn-native-dns-measurement").start();
        });
    }
    void cancel(){final Job job;synchronized(this){completed=null;job=active;if(job!=null)job.cancelled=true;}if(job!=null)job.owner.cancel();}
    private void measure(Job job,Throwable initial){
        Throwable failure=initial;String result=null;
        try{
            if(initial!=null)throw new IllegalStateException("MTU work has not drained before DNS comparison.",initial);
            if(job.cancelled||!AndroidMTUMeasurementGate.owns(job.lease))throw new IllegalStateException("DNS comparison cancelled before startup.");
            job.owner.start(job.transport);long deadline=System.nanoTime()+90_000_000_000L;
            for(;;){
                if(job.cancelled||!AndroidMTUMeasurementGate.owns(job.lease))throw new IllegalStateException("DNS comparison cancelled.");
                if(System.nanoTime()>deadline)throw new IllegalStateException("DNS comparison timed out.");
                String raw=job.owner.status();JSONObject status=AndroidDNSMeasurementReceipt.validate(raw,job.id,job.owner.nodeID,job.owner.sessionID,job.transport,false);
                job.callback.progress(status.optString("stage","measuring"));
                if(status.getBoolean("complete")){result=raw;break;}
                Thread.sleep(250L);
            }
        }catch(Throwable error){failure=error;}
        // Cancel-before-start is a native tombstone. Even a rejected Start gets
        // an exact drain acknowledgement; a queued callback cannot reopen it.
        if(failure!=null||job.cancelled)job.owner.cancel();
        boolean joined=false;
        while(!joined){
            try{job.owner.drain();joined=true;}
            catch(Throwable pending){
                job.owner.cancel();failure=new IllegalStateException("DNS cleanup is waiting for its retained native workers.",pending);
                try{job.callback.progress("draining");}catch(Throwable abandoned){job.cancelled=true;}
                try{Thread.sleep(250L);}catch(InterruptedException interrupted){Thread.interrupted();job.cancelled=true;}
            }
        }
        if(failure==null&&!job.cancelled){
            try{result=job.owner.status();AndroidDNSMeasurementReceipt.validate(result,job.id,job.owner.nodeID,job.owner.sessionID,job.transport,true);}
            catch(Throwable error){failure=error;}
        }
        if(job.cancelled&&failure==null)failure=new IllegalStateException("DNS comparison cancelled.");
        synchronized(this){if(active!=job)return;job.completedAt=receiptClock.getAsLong();completed=failure==null&&!job.cancelled?job:null;active=null;AndroidMTUMeasurementGate.release(job.lease);}
        job.callback.finished(failure==null?result:null,failure);
    }
}
