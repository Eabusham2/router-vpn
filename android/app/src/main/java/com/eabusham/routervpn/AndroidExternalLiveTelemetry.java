package com.eabusham.routervpn;

import android.content.Context;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;

/** Short current-path HTTPS responses. This owner never writes benchmark history. */
final class AndroidExternalLiveTelemetry {
    static final long MAX_AGE_NANOS=10_000_000_000L;
    interface Callback {void finished(Result result,Throwable error);}
    private final Context context;
    private final AndroidStandardExitRuntime runtime;
    private final AndroidNativeHopMeasurement measurement=new AndroidNativeHopMeasurement();
    private volatile long cancellation;

    final class Result {
        final String id;
        final double medianMs,minMs,averageMs,p90Ms,maxMs,jitterMs;
        private final AndroidExternalNodeStatistics.Captured source;
        private final LayeredVpnService.HopMeasurementOwner owner;
        private final long epoch,completedAt;
        private Result(AndroidExternalNodeStatistics.Captured source,LayeredVpnService.HopMeasurementOwner owner,long epoch,String raw)throws Exception{
            this.source=source;this.owner=owner;this.epoch=epoch;completedAt=System.nanoTime();id=source.path.home.activeExternalId;
            if(raw==null||raw.length()>16384)throw new IllegalArgumentException("Invalid live HTTPS response.");
            JSONObject status=new JSONObject(raw);
            if(!owner.requestID().equals(text(status,"request_id"))||!"complete".equals(text(status,"stage"))||!bool(status,"complete")||!bool(status,"drained")||!status.optString("failure","").isEmpty())
                throw new IllegalStateException("The live response did not complete and drain.");
            JSONArray rows=status.getJSONArray("results");if(rows.length()!=1)throw new IllegalStateException("The live response returned another path.");
            JSONObject row=rows.getJSONObject(0);
            if(!id.equals(text(row,"node_id"))||!"exit".equals(text(row,"role"))||!"public-path".equals(text(row,"kind"))||!bool(row,"ready")||!row.optString("failure","").isEmpty()
                    ||row.has("idle")||row.has("download")||row.has("upload")||row.has("benchmark"))throw new IllegalStateException("No complete live HTTPS response is available.");
            JSONObject response=row.getJSONObject("response"),stats=response.getJSONObject("distribution");
            exactKeys(response,"schema","measurement","endpoint","attempts","distribution");
            exactKeys(stats,"samples","min_ms","median_ms","average_ms","p90_ms","max_ms","jitter_ms");
            if(integer(response,"schema")!=1||!AndroidExternalNodeStatistics.MEASUREMENT.equals(text(response,"measurement"))||!AndroidExternalNodeStatistics.ENDPOINT.equals(text(response,"endpoint"))
                    ||integer(response,"attempts")!=3||integer(stats,"samples")!=3)throw new IllegalStateException("The live response is not the captured three-sample HTTPS measurement.");
            minMs=number(stats,"min_ms");medianMs=number(stats,"median_ms");averageMs=number(stats,"average_ms");p90Ms=number(stats,"p90_ms");maxMs=number(stats,"max_ms");jitterMs=number(stats,"jitter_ms");
            for(double value:new double[]{minMs,medianMs,averageMs,p90Ms,maxMs})if(value<=0||value>10000)throw new IllegalArgumentException("Invalid live HTTPS response time.");
            if(jitterMs<0||jitterMs>10000||minMs>medianMs||medianMs>p90Ms||p90Ms>maxMs||averageMs<minMs||averageMs>maxMs)throw new IllegalArgumentException("Inconsistent live HTTPS response statistics.");
        }
        /** Check again after UI queueing and before every reuse of this in-memory value. */
        void requireCurrent()throws Exception{
            requireFresh();
            synchronized(runtime){
                runtime.requireMeasurementSource(source.path);
                owner.commit(()->{
                    owner.requireResponseIdle();
                    synchronized(AndroidHomeStateStore.class){
                        source.path.requireHome(AndroidHomeStateStore.snapshot(context));
                        if(AndroidHomeStateStore.emergencyDisconnectPending(context))throw new IllegalStateException("Disconnect cancelled the live response.");
                        synchronized(AndroidPrivateFileStore.class){source.requireCurrent();requireFresh();}
                    }
                });
            }
        }
        private void requireFresh(){long age=System.nanoTime()-completedAt;if(epoch!=cancellation||age<0||age>MAX_AGE_NANOS)throw new IllegalStateException("The live HTTPS response expired or was cancelled.");}
        String detail(){return String.format(Locale.US,"Live current path • 3 HTTPS responses\nMedian %.1f ms • min %.1f • avg %.1f • p90 %.1f • max %.1f • jitter %.1f\n\n%s\nEach response is timed after routed DNS, TCP and TLS preparation through the current proved VPN path. The number expires after 10 seconds. It measures the public endpoint's HTTPS response, not ICMP RTT or the VPN node's own response. Saved 50-sample statistics and direct TCP rankings remain separate.",medianMs,minMs,averageMs,p90Ms,maxMs,jitterMs,AndroidExternalNodeStatistics.ENDPOINT);}
    }

    AndroidExternalLiveTelemetry(Context context,AndroidStandardExitRuntime runtime){this.context=context.getApplicationContext();this.runtime=runtime;}
    boolean isRunning(){return measurement.isRunning();}
    synchronized void measure(String exitID,Callback callback){
        if(measurement.isRunning()){callback.finished(null,new IllegalStateException("The previous live response is still draining."));return;}
        final AndroidExternalNodeStatistics.Captured source;
        final long epoch=cancellation;
        try{
            AndroidStandardExitRuntime.MeasurementSource path=runtime.captureMeasurementSource(exitID);
            source=AndroidExternalNodeStatistics.capture(context,path);runtime.requireMeasurementSource(path);
        }catch(Throwable error){callback.finished(null,error);return;}
        final Result[] result={null};
        measurement.runResponse(exitID,source.path.nativeSession,source.path.home.sessionId,source.path.home.pathGeneration,new AndroidNativeHopMeasurement.Callback(){
            public void progress(String status){}
            public void commit(LayeredVpnService.HopMeasurementOwner owner,String status)throws Exception{
                Result value=new Result(source,owner,epoch,status);value.requireCurrent();result[0]=value;
            }
            public void finished(String status,Throwable error){
                Throwable failure=error;
                if(failure==null)try{if(result[0]==null)throw new IllegalStateException("No current HTTPS response.");result[0].requireCurrent();}catch(Throwable unavailable){failure=unavailable;}
                callback.finished(failure==null?result[0]:null,failure);
            }
        });
    }
    void cancel(){synchronized(this){cancellation++;}measurement.cancel();}
    private static String text(JSONObject value,String key)throws Exception{Object item=value.get(key);if(!(item instanceof String))throw new IllegalArgumentException("Invalid live response identity.");return (String)item;}
    private static boolean bool(JSONObject value,String key)throws Exception{Object item=value.get(key);if(!(item instanceof Boolean))throw new IllegalArgumentException("Invalid live response state.");return (Boolean)item;}
    private static double number(JSONObject value,String key)throws Exception{Object item=value.get(key);if(!(item instanceof Number))throw new IllegalArgumentException("Invalid live response number.");double result=((Number)item).doubleValue();if(!Double.isFinite(result))throw new IllegalArgumentException("Non-finite live response number.");return result;}
    private static long integer(JSONObject value,String key)throws Exception{double result=number(value,key);if(result!=Math.rint(result))throw new IllegalArgumentException("Invalid live response count.");return (long)result;}
    private static void exactKeys(JSONObject value,String...names)throws Exception{HashSet<String> expected=new HashSet<>(Arrays.asList(names));if(value.length()!=expected.size())throw new IllegalArgumentException("Unexpected live response fields.");java.util.Iterator<String> keys=value.keys();while(keys.hasNext())if(!expected.contains(keys.next()))throw new IllegalArgumentException("Unexpected live response field.");}
}
