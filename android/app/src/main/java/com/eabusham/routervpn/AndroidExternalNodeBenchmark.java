package com.eabusham.routervpn;

import android.content.Context;

/** One selected external path, from its original launch source through native
 * drain and a source/owner-checked atomic historical result. */
final class AndroidExternalNodeBenchmark {
    interface Callback {void progress(String status);void finished(AndroidExternalNodeStatistics.Record result,Throwable error);}
    private final Context context;
    private final AndroidStandardExitRuntime runtime;
    private final AndroidNativeHopMeasurement measurement=new AndroidNativeHopMeasurement();
    AndroidExternalNodeBenchmark(Context context,AndroidStandardExitRuntime runtime){this.context=context.getApplicationContext();this.runtime=runtime;}
    boolean isRunning(){return measurement.isRunning();}

    synchronized void run(String exitID,Callback callback){
        if(measurement.isRunning()){callback.finished(null,new IllegalStateException("The previous external benchmark is still draining."));return;}
        final AndroidStandardExitRuntime.MeasurementSource path;
        final AndroidExternalNodeStatistics.Captured source;
        try{
            path=runtime.captureMeasurementSource(exitID);
            source=AndroidExternalNodeStatistics.capture(context,path);
            runtime.requireMeasurementSource(path);
        }catch(Throwable error){callback.finished(null,error);return;}
        final AndroidExternalNodeStatistics.Record[] saved={null};
        measurement.runLatency(exitID,path.nativeSession,path.home.sessionId,path.home.pathGeneration,new AndroidNativeHopMeasurement.Callback(){
            public void progress(String status){callback.progress(status);}
            public void commit(LayeredVpnService.HopMeasurementOwner owner,String status)throws Exception{
                // Cancellation is serialized by the original measurement owner.
                // No new connection, policy, source or network may adopt this
                // old result, and the MTU hold remains retained through save.
                synchronized(runtime){
                    runtime.requireMeasurementSource(path);
                    owner.commit(()->{
                        synchronized(AndroidHomeStateStore.class){
                            path.requireHome(AndroidHomeStateStore.snapshot(context));
                            if(AndroidHomeStateStore.emergencyDisconnectPending(context))throw new IllegalStateException("Disconnect cancelled the external benchmark.");
                            synchronized(AndroidPrivateFileStore.class){
                                source.requireCurrent();
                                AndroidExternalNodeStatistics.Record record=AndroidExternalNodeStatistics.result(source,owner,status);
                                AndroidExternalNodeStatistics.save(context,source,record);saved[0]=record;
                            }
                        }
                    });
                }
            }
            public void finished(String status,Throwable error){callback.finished(error==null?saved[0]:null,error);}
        });
    }
    synchronized void cancel(){measurement.cancel();}
}
