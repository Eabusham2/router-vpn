package com.eabusham.routervpn;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Process;
import com.wireguard.android.backend.Tunnel;

import java.io.File;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;

/** Temporary entry measurement: capture, prove, measure, drain, stop, then select. */
final class AndroidViaEntryLatencyProbe {
    interface Callback {
        void progress(String message);
        void finished(Result result, Throwable error);
    }

    static final class Result {
        final AndroidNodeStore.Node entry;
        final List<AndroidNodeStore.Node> candidates;
        final List<AndroidTelemetry.Result> values;
        private final AndroidViaEntryLatencyProbe probe;
        private final Map<File,byte[]> sources;
        private final long generation, created=System.nanoTime();
        private final String home;
        private final Network idleNetwork;
        Result(AndroidViaEntryLatencyProbe probe, AndroidNodeStore.Node entry, List<AndroidNodeStore.Node> candidates,
               List<AndroidTelemetry.Result> values, Map<File,byte[]> sources,long generation,String home,Network idleNetwork) {
            this.probe=probe;this.entry=entry;this.sources=sources;
            this.candidates=Collections.unmodifiableList(new ArrayList<>(candidates));
            this.values=Collections.unmodifiableList(new ArrayList<>(values));
            this.generation=generation;this.home=home;this.idleNetwork=idleNetwork;
        }
        void requireCurrent() throws Exception {
            if(probe.result!=this||probe.isBusy()||AndroidVpnMutationGuard.isBusy(probe.context)
                    ||probe.wireGuard.generation()!=generation||!home.equals(homeIdentity(probe.context))
                    ||!java.util.Objects.equals(idleNetwork,probe.connectivity().getActiveNetwork())
                    ||System.nanoTime()-created>120_000_000_000L)
                throw new IllegalStateException("The measured entry/candidates or network decision changed. Retest before selecting this result.");
            checkSources(sources);
        }
        AndroidTelemetry.Result measurement(String id) {
            for(AndroidTelemetry.Result value:values)if(value.id.equals(id))return value;
            return null;
        }
        AndroidNodeStore.Node fastest() {
            AndroidNodeStore.Node winner=null;double best=Double.POSITIVE_INFINITY;
            for(AndroidNodeStore.Node node:candidates){
                AndroidTelemetry.Result value=measurement(node.id);
                if(value!=null&&value.samples>=3&&value.failed==0&&Double.isFinite(value.medianMs)&&value.medianMs>0&&value.medianMs<best){winner=node;best=value.medianMs;}
            }
            return winner;
        }
    }

    private static final Object PROCESS_LOCK=new Object();
    private static Job processOwner;
    static boolean hasActiveOperation(){synchronized(PROCESS_LOCK){return processOwner!=null;}}
    /** A recreated Activity may cancel/retry this exact retained operation. */
    static boolean cancelActiveOperation(){
        Job job;synchronized(PROCESS_LOCK){job=processOwner;}
        if(job==null)return false;job.owner.cancel(job);return true;
    }
    private static final class Job {
        final AndroidViaEntryLatencyProbe owner;
        final AndroidNodeStore.Node entry;
        final List<AndroidNodeStore.Node> candidates;
        final Map<File,byte[]> sources;
        final Callback callback;
        final int samples;
        final String home;
        final Network idleNetwork;
        volatile boolean cancelled;
        volatile AndroidViaEntryProbeIO io;
        NativeWireGuardController.CapturedSession session;
        boolean connected, stopping, cleanupFailed;
        List<AndroidTelemetry.Result> values=Collections.emptyList();
        Throwable failure;
        Job(AndroidViaEntryLatencyProbe owner,AndroidNodeStore.Node entry,List<AndroidNodeStore.Node> candidates,Map<File,byte[]> sources,int samples,String home,Network idleNetwork,Callback callback){
            this.owner=owner;this.entry=entry;this.candidates=candidates;this.sources=sources;this.samples=samples;this.home=home;this.idleNetwork=idleNetwork;this.callback=callback;
        }
    }
    private final Context context;
    private final NativeWireGuardController wireGuard;
    private final AtomicBoolean busy=new AtomicBoolean();
    private volatile Job active;
    private volatile Result result;

    AndroidViaEntryLatencyProbe(Context context,AndroidRuntimeRegistry runtime,AndroidTelemetry telemetry){
        if(context==null||runtime==null||telemetry==null)throw new IllegalArgumentException("Android runtime/telemetry owners are required.");
        this.context=context.getApplicationContext();this.wireGuard=runtime.wireGuard;
    }
    boolean isBusy(){return busy.get();}

    void measure(AndroidNodeStore.Node entry,List<AndroidNodeStore.Node> candidates,int samples,Callback callback){
        final Job job;
        try{
            synchronized(PROCESS_LOCK){
                if(processOwner!=null||busy.get()||AndroidVpnMutationGuard.isBusy(context))throw new IllegalStateException("Disconnect/finish the current VPN operation before measuring via-entry candidates.");
                List<AndroidNodeStore.Node> captured=captureCandidates(entry,candidates);
                Map<File,byte[]> sources=captureSources(entry,captured);
                job=new Job(this,entry,captured,sources,Math.max(3,Math.min(10,samples)),homeIdentity(context),connectivity().getActiveNetwork(),callback);
                result=null;active=job;processOwner=job;busy.set(true);
            }
        }catch(Throwable error){callback.finished(null,error);return;}
        progress(job,"Connecting temporary proven WireGuard entry "+entry.name+" for candidate TCP response measurements…");
        try{
            wireGuard.connectManagedCaptured(entry.file,(session,state,message,error)->{
                synchronized(job){if(job.connected)return;job.connected=true;job.session=session;}
                if(error!=null||state!=Tunnel.State.UP){job.failure=error!=null?error:new IllegalStateException(message);stop(job);return;}
                try{new Thread(()->measureOwned(job),"routervpn-via-entry-candidates").start();}
                catch(Throwable startFailure){job.failure=startFailure;stop(job);}
            });
        }catch(Throwable error){finish(job,null,error);}
    }

    /** Cancels only this operation; the process reservation survives worker and VPN cleanup. */
    void cancel(){
        Job job=active;if(job==null){result=null;return;}
        cancel(job);
    }
    private void cancel(Job job){
        if(active!=job)return;
        job.cancelled=true;AndroidViaEntryProbeIO io=job.io;if(io!=null)io.cancel();
        progress(job,"Cancelling candidate measurement; waiting for captured sockets and entry teardown…");
        synchronized(job){if(!job.cleanupFailed)return;}
        stop(job);
    }

    Result unmeasured(AndroidNodeStore.Node entry,List<AndroidNodeStore.Node> candidates)throws Exception{
        if(isBusy()||AndroidVpnMutationGuard.isBusy(context))throw new IllegalStateException("Finish the current VPN operation before choosing hops.");
        List<AndroidNodeStore.Node> captured=captureCandidates(entry,candidates);
        long generation=wireGuard.generation();String home=homeIdentity(context);Network network=connectivity().getActiveNetwork();
        Result value=new Result(this,entry,captured,Collections.emptyList(),captureSources(entry,captured),generation,home,network);
        result=value;value.requireCurrent();return value;
    }

    private void measureOwned(Job job){
        try{
            checkJob(job);checkSources(job.sources);
            Network network=connectivity().getActiveNetwork();
            requireVPN(network);
            long deadline=System.nanoTime()+90_000_000_000L;
            AndroidViaEntryProbeIO io=new AndroidViaEntryProbeIO(()->{
                checkJob(job);
                if(System.nanoTime()>deadline)throw new IllegalStateException("Via-entry candidate measurement timed out.");
                requireVPN(network);
                if(!network.equals(connectivity().getActiveNetwork()))throw new IllegalStateException("The captured entry VPN network changed; all results discarded.");
            },network::getAllByName,network.getSocketFactory());
            job.io=io;io.attach();if(job.cancelled)io.cancel();
            progress(job,"Entry proof passed; measuring "+job.candidates.size()+" candidate(s) through "+job.entry.name+"…");
            job.values=AndroidViaEntryPathMeter.measure(job.entry,wireGuard,job.candidates,job.samples,io);
            checkJob(job);checkSources(job.sources);
        }catch(Throwable error){job.failure=error;job.values=Collections.emptyList();}
        finally{AndroidViaEntryProbeIO io=job.io;if(io!=null)io.drain();stop(job);}
    }

    private void checkJob(Job job)throws Exception{
        if(active!=job||job.cancelled)throw new CancellationException("Via-entry candidate measurement cancelled.");
        if(job.session==null||!job.session.current()||!job.home.equals(homeIdentity(context)))throw new IllegalStateException("The captured entry session/path changed; all results discarded.");
    }

    private void stop(Job job){
        synchronized(job){if(active!=job||job.stopping)return;job.stopping=true;job.cleanupFailed=false;}
        progress(job,"Candidate sockets drained; disconnecting only the captured temporary entry…");
        try{
            job.session.disconnect((state,message,error)->{
                if(error instanceof NativeWireGuardController.SessionReplaced){finish(job,null,error);return;}
                if(error!=null||state!=Tunnel.State.DOWN){
                    synchronized(job){job.stopping=false;job.cleanupFailed=true;job.failure=error!=null?error:new IllegalStateException("Temporary entry did not fully disconnect; candidate results discarded.");}
                    progress(job,"Temporary entry teardown is incomplete. Cancel retries its owned teardown; candidate results remain unavailable.");return;
                }
                if(job.cancelled){finish(job,null,new CancellationException("Via-entry candidate measurement cancelled; captured work drained."));return;}
                try{
                    checkSources(job.sources);
                    if(!job.session.retained())throw new NativeWireGuardController.SessionReplaced();
                    if(!job.home.equals(homeIdentity(context)))throw new IllegalStateException("A newer connection decision replaced the candidate measurement.");
                    Result value=new Result(this,job.entry,job.candidates,job.failure==null?job.values:Collections.emptyList(),job.sources,job.session.generation(),job.home,job.idleNetwork);
                    finish(job,value,job.failure);
                }catch(Throwable invalid){finish(job,null,invalid);}
            });
        }catch(Throwable error){
            synchronized(job){job.stopping=false;job.cleanupFailed=true;job.failure=error;}
            progress(job,"Temporary entry cleanup is still owned. Cancel retries its teardown.");
        }
    }

    private void finish(Job job,Result value,Throwable error){
        synchronized(PROCESS_LOCK){
            if(active!=job||processOwner!=job)return;
            active=null;processOwner=null;result=value;busy.set(false);
        }
        job.callback.finished(value,error);
    }
    private static void progress(Job job,String message){try{job.callback.progress(message);}catch(Throwable abandoned){job.cancelled=true;AndroidViaEntryProbeIO io=job.io;if(io!=null)io.cancel();}}
    private ConnectivityManager connectivity(){
        ConnectivityManager value=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if(value==null)throw new IllegalStateException("Android network ownership is unavailable.");return value;
    }
    private void requireVPN(Network network){
        NetworkCapabilities capabilities=network==null?null:connectivity().getNetworkCapabilities(network);
        if(capabilities==null||!capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN))throw new IllegalStateException("Candidate measurement requires the captured Android VPN network.");
        if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.R){int uid=capabilities.getOwnerUid();if(uid!=Process.myUid())throw new IllegalStateException("The captured VPN network does not prove this app's ownership.");}
    }
    private static String homeIdentity(Context context){
        AndroidHomeStateStore.Snapshot state=AndroidHomeStateStore.snapshot(context);
        return state.sessionId+"\n"+state.pathGeneration+"\n"+state.phase+"\n"+state.activeNodeId+"\n"+state.activeEntryId+"\n"+state.activeExitId;
    }
    private static List<AndroidNodeStore.Node> captureCandidates(AndroidNodeStore.Node entry,List<AndroidNodeStore.Node> candidates){
        if(entry==null||entry.file==null||entry.id==null||entry.id.isEmpty()||candidates==null||candidates.isEmpty()||candidates.size()>AndroidNodeStore.MAX_NODES)throw new IllegalArgumentException("Choose a stored entry and bounded candidate node list.");
        List<AndroidNodeStore.Node> out=new ArrayList<>();Set<String> seen=new HashSet<>();
        for(AndroidNodeStore.Node node:candidates){if(node==null||node.file==null||node.id==null||node.id.isEmpty())throw new IllegalArgumentException("Candidate node identity is missing.");if(entry.id.equals(node.id))continue;if(!seen.add(node.id))throw new IllegalArgumentException("Candidate node identity is duplicated.");out.add(node);}
        if(out.isEmpty())throw new IllegalArgumentException("Choose at least one different candidate exit.");
        return Collections.unmodifiableList(out);
    }
    private static byte[] digest(File file)throws Exception{return MessageDigest.getInstance("SHA-256").digest(AndroidPrivateFileStore.read(file,AndroidNodeStore.MAX_BUNDLE));}
    private static Map<File,byte[]> captureSources(AndroidNodeStore.Node entry,List<AndroidNodeStore.Node> candidates)throws Exception{
        Map<File,byte[]> sources=new LinkedHashMap<>();sources.put(entry.file,digest(entry.file));
        for(AndroidNodeStore.Node node:candidates){if(sources.put(node.file,digest(node.file))!=null)throw new IllegalArgumentException("Different hop identities cannot share a private node file.");}
        return Collections.unmodifiableMap(sources);
    }
    private static void checkSources(Map<File,byte[]> sources)throws Exception{
        for(Map.Entry<File,byte[]> source:sources.entrySet())if(!MessageDigest.isEqual(source.getValue(),digest(source.getKey())))throw new IllegalStateException("A captured entry/candidate node changed; all results discarded.");
    }
}
