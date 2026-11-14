package com.eabusham.routervpn;

import org.json.JSONObject;
import java.util.UUID;

/** Fifty responses from one original ordered prefix, never the six idle
 * samples in a throughput request. The retained job owns cleanup after UI exit. */
final class AndroidOrderedLatencyBenchmark {
    interface Callback {
        void progress(LayeredVpnService.OrderedLatencyOwner owner,String stage);
        void finished(LayeredVpnService.OrderedLatencyOwner owner,AndroidOrderedLatencyStore.Record record,Throwable error);
    }
    private static final class Job {
        final String id=UUID.randomUUID().toString().replace("-","");
        final Object lease;
        final LayeredVpnService.OrderedLatencyTarget target;
        final Callback callback;
        volatile LayeredVpnService.OrderedLatencyOwner owner;
        volatile boolean cancelled;
        boolean quiesced;
        Job(Object lease,LayeredVpnService.OrderedLatencyTarget target,Callback callback){this.lease=lease;this.target=target;this.callback=callback;}
    }
    private volatile Job active;
    boolean isRunning(){return active!=null;}
    void run(LayeredVpnService.OrderedLatencyTarget target,Callback callback){
        final Job job;
        synchronized(this){
            if(active!=null){callback.finished(null,null,new IllegalStateException("The previous ordered benchmark still owns cleanup."));return;}
            Object lease=null;
            try{
                lease=AndroidMTUMeasurementGate.acquire();job=new Job(lease,target,callback);
                active=job;
            }catch(Throwable error){AndroidMTUMeasurementGate.release(lease);callback.finished(null,null,error);return;}
        }
        LayeredVpnService.quiesceMTUForSpeedLab(error->{
            synchronized(AndroidOrderedLatencyBenchmark.this){if(active!=job||job.quiesced)return;job.quiesced=true;}
            new Thread(()->measure(job,error),"routervpn-ordered-fifty").start();
        });
    }
    void cancel(){final Job job;synchronized(this){job=active;if(job==null)return;job.cancelled=true;}LayeredVpnService.OrderedLatencyOwner owner=job.owner;if(owner!=null)owner.cancel();}
    private void require(Job job){if(job.cancelled||!AndroidMTUMeasurementGate.owns(job.lease))throw new IllegalStateException("The ordered benchmark was cancelled.");}
    private void progress(Job job,String stage){job.callback.progress(job.owner,stage);}
    private void pause(Job job){try{Thread.sleep(250L);}catch(InterruptedException interrupted){Thread.interrupted();job.cancelled=true;}}
    private void measure(Job job,Throwable initial){
        Throwable failure=initial;AndroidOrderedLatencyStore.Record result=null;
        try{
            if(failure!=null)throw new IllegalStateException("MTU work did not drain before the ordered benchmark.",failure);
            // The immutable target retains its original source/Home owner while
            // existing MTU work joins. Attach only after successful quiescence;
            // the strict native factory must never be used to preempt MTU.
            require(job);job.owner=LayeredVpnService.captureOrderedLatency(job.id,job.target);
            require(job);job.owner.start();
            long deadline=System.nanoTime()+100_000_000_000L;
            for(;;){
                require(job);if(System.nanoTime()>deadline)throw new IllegalStateException("The ordered fifty-response benchmark timed out.");
                JSONObject status=AndroidOrderedLatencyStore.status(job.owner.status(),job.id);
                progress(job,status.getString("stage"));
                if(status.getBoolean("complete")){
                    if(!status.optString("failure","").isEmpty())throw new IllegalStateException("The ordered benchmark did not complete all 50 responses.");
                    break;
                }
                Thread.sleep(300L);
            }
        }catch(Throwable error){failure=error;}
        if(job.owner!=null&&(failure!=null||job.cancelled))job.owner.cancel();
        // A throwing Start can still have acquired its exact native operation.
        // Close below joins that facade even when Start did not return success;
        // a string-only Drain would have no admission in the pre-start case.
        if(job.owner!=null&&job.owner.started()){
            for(;;){try{job.owner.drain();break;}catch(Throwable pending){
                job.owner.cancel();failure=new IllegalStateException("The ordered benchmark is waiting for its original workers.",pending);
                try{progress(job,"draining original native workers; MTU remains held");}catch(Throwable abandoned){job.cancelled=true;}
                pause(job);
            }}
            if(failure==null&&!job.cancelled)try{
                String status=job.owner.status(),saved=job.owner.saved();
                result=AndroidOrderedLatencyStore.completed(status,saved,job.id,job.target.source,job.target.config,job.target.position,job.target.node,job.target.kind);
            }catch(Throwable error){failure=error;}
        }
        if(job.owner!=null)for(;;){try{job.owner.close();break;}catch(Throwable pending){
            failure=new IllegalStateException("The ordered benchmark facade still owns native cleanup.",pending);
            job.owner.cancel();try{progress(job,"closing original benchmark facade; MTU remains held");}catch(Throwable abandoned){job.cancelled=true;}
            pause(job);
        }}
        synchronized(this){
            if(active!=job)throw new IllegalStateException("The original benchmark cleanup owner was replaced.");
            if(failure==null)try{
                require(job);if(result==null)throw new IllegalStateException("No complete ordered receipt.");
                job.owner.commit(result,()->require(job));
            }catch(Throwable error){failure=error;}
            AndroidMTUMeasurementGate.release(job.lease);active=null;
        }
        job.callback.finished(job.owner,failure==null?result:null,failure);
    }
}
