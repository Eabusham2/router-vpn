package com.eabusham.routervpn;

import android.content.Context;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import io.nekohasekai.libbox.CommandServer;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterTorCompare;
import io.nekohasekai.libbox.RouterTorCompareCandidate;
import io.nekohasekai.libbox.RouterTorCompareHost;
import io.nekohasekai.libbox.RouterTorProofRequest;

/** Serial native candidates for one pending Home connection. The shared Go
 * coordinator owns scoring, target selection, retries and final verification;
 * this adapter owns the actual Android service, files and physical network. */
final class AndroidTorCompareRuntime implements RouterTorCompareHost, AutoCloseable {
    interface Owner {
        boolean current();
        void requireSource() throws Exception;
        void launch(NativeSingBoxController.SessionInfo session) throws Exception;
        void progress(String message);
    }

    private final Object lock = new Object();
    private final Context context;
    private final File entry;
    private final AndroidStandardExitStore.Entry exit;
    private final String entryMode, entryID, captureSHA;
    private final Owner owner;
    private final AndroidMAXDNSOwner.Physical physical;
    private final CountDownLatch watchDone = new CountDownLatch(1);
    private volatile boolean cancelled, adopted, networkCurrent = true, watchStopped;
    private volatile RouterTorCompare round;
    private volatile Candidate active;
    private String capturedTarget;
    private Thread watch;

    AndroidTorCompareRuntime(Context context, File entry, AndroidStandardExitStore.Entry exit,
                             String entryMode, String homeSession, String entryDigest, Owner owner) throws Exception {
        if(context==null||entry==null||owner==null||homeSession==null||homeSession.isEmpty()
                ||exit==null||!entry.getName().matches("[0-9a-f]{32}\\.json")||!AndroidTorProfile.isTor(exit.protocol))
            throw unavailable();
        this.context=context.getApplicationContext();this.entry=entry;
        this.exit=AndroidStandardExitStore.copy(exit);this.entryMode=entryMode;this.owner=owner;
        entryID=entry.getName().substring(0,32);
        owner.requireSource();
        physical=new AndroidMAXDNSOwner.Physical(this.context);
        captureSHA=AndroidTorProfile.digest((entryDigest+"\n"+AndroidStandardExitStore.snapshot(this.exit)
                +"\n"+entryMode+"\n"+homeSession+"\n"+physical.digest).getBytes(StandardCharsets.UTF_8));
        if(!current())throw unavailable();
    }

    NativeSingBoxController.SessionInfo run() throws Exception {
        synchronized(lock){
            if(round!=null||watch!=null||!current())throw unavailable();
            watch=new Thread(this::watchSource,"routervpn-tor-compare-network");watch.start();
        }
        RouterTorCompare created=Libbox.routerTorNewCompare(this,entryID,exit.id,exit.protocol,captureSHA);
        if(created==null)throw unavailable();
        synchronized(lock){round=created;}
        if(!current()){created.cancel();throw unavailable();}
        created.run();
        Candidate winner=active;
        String selected=created.execution();
        if(winner==null||!selected.equals(winner.execution)||!winner.current()||!current())throw unavailable();
        owner.requireSource();
        // Keep joins only the measurement handles. The Android trial then
        // transfers the same running service to ordinary runtime ownership.
        created.keep();
        synchronized(lock){
            if(!current())throw unavailable();
            winner.keep();adopted=true;
            // gomobile holds the Java Host from Go. Drop this reverse proxy
            // edge only after both owners transfer the proved running path.
            if(round==created)round=null;
        }
        stopWatch();
        return winner.prepared;
    }

    @Override public boolean current() {
        if(cancelled||!networkCurrent)return false;
        try{return owner.current();}catch(RuntimeException changed){return false;}
    }

    @Override public RouterTorCompareCandidate newCandidate(String execution,String target) {
        if(!current()||!Arrays.asList("local","server").contains(execution)
                ||!Arrays.asList("https://1.1.1.1/cdn-cgi/trace","https://1.0.0.1/cdn-cgi/trace").contains(target))return null;
        synchronized(lock){
            if(!current()||active!=null&&!active.closed||capturedTarget!=null&&!capturedTarget.equals(target))return null;
            if(capturedTarget==null)capturedTarget=target;
            Candidate next=new Candidate(execution);active=next;return next;
        }
    }

    @Override public void progress(String stage,String execution) {
        if(!current())return;
        String mode="server".equals(execution)?"Server":"Local";
        if("activation-failed".equals(stage))owner.progress("Tor "+mode+" failed its final routed HTTP checks and has no score; checking the remaining path…");
        else if("selected".equals(stage))owner.progress("Retaining the proved "+mode+" Tor path after both routed HTTP response checks…");
        else owner.progress("Comparing Tor "+mode+": last-relay and shared external routed HTTP response times…");
    }

    private void watchSource() {
        try{
            while(!watchStopped){
                if(!physical.current(true)||!owner.current()){networkCurrent=false;cancel();return;}
                try{owner.requireSource();}catch(Exception changed){networkCurrent=false;cancel();return;}
                try{Thread.sleep(200L);}catch(InterruptedException stop){if(!watchStopped){networkCurrent=false;cancel();}return;}
            }
        }finally{watchDone.countDown();}
    }

    void cancel() {
        final RouterTorCompare captured;final Candidate attempt;final Thread watcher;
        synchronized(lock){
            if(adopted)return;
            cancelled=true;captured=round;attempt=active;watcher=watch;watchStopped=true;
        }
        if(watcher!=null&&watcher!=Thread.currentThread())watcher.interrupt();
        if(captured!=null)captured.cancel();
        if(attempt!=null)attempt.cancel();
    }

    private void stopWatch() throws Exception {
        watchStopped=true;
        Thread captured=watch;
        if(captured==null)return;
        captured.interrupt();
        if(captured==Thread.currentThread())return;
        await(watchDone,3_000_000_000L,"Tor comparison source watcher did not drain.");
    }

    @Override public void close() throws Exception {
        if(adopted){stopWatch();return;}
        cancel();
        RouterTorCompare captured=round;
        try{
            if(captured!=null)captured.close();
            Candidate attempt=active;if(attempt!=null)attempt.close();
        }finally{stopWatch();}
        // A failed or pending native close retains its proxy for retry. A
        // late factory result cannot be cleared by another close invocation.
        synchronized(lock){if(round==captured)round=null;}
    }

    private final class Candidate implements RouterTorCompareCandidate {
        final String execution;
        final CountDownLatch startDone=new CountDownLatch(1);
        private final Object candidateLock=new Object();
        private final Object drainLock=new Object();
        private volatile boolean started, stopped, closed, kept;
        private volatile Thread startingThread;
        private volatile NativeSingBoxController.SessionInfo prepared;
        private volatile LayeredVpnService.TorCompareTrial trial;
        Candidate(String execution){this.execution=execution;}

        private boolean owned(){return !stopped&&!closed&&active==this&&AndroidTorCompareRuntime.this.current();}

        @Override public void start() throws Exception {
            synchronized(candidateLock){
                if(started||!owned())throw unavailable();
                started=true;startingThread=Thread.currentThread();
            }
            try{
                owner.requireSource();
                long physicalDeadline=System.nanoTime()+3_000_000_000L;
                while(!physical.current(false)){
                    if(!owned()||!physical.current(true)||System.nanoTime()>=physicalDeadline)throw unavailable();
                    Thread.sleep(50L);
                }
                NativeSingBoxController.SessionInfo built=AndroidTorProfile.prepare(context,entry,exit,entryMode,execution);
                prepared=built; // Retain even when cancellation won during compilation.
                if(!owned()||Thread.currentThread().isInterrupted())throw unavailable();
                owner.requireSource();
                LayeredVpnService.TorCompareTrial ticket=LayeredVpnService.TorCompareTrial.reserve(built,exit.id,execution,physical,this::owned);
                trial=ticket;
                if(!owned())throw unavailable();
                ticket.submit();
                owner.launch(built);
                long deadline=System.nanoTime()+200_000_000_000L;
                while(!ticket.current()){
                    if(!owned()||!ticket.failure().isEmpty()||System.nanoTime()>=deadline)throw unavailable();
                    Thread.sleep(50L);
                }
                if(!owned()||!ticket.current())throw unavailable();
            }finally{startingThread=null;startDone.countDown();}
        }

        @Override public boolean current(){LayeredVpnService.TorCompareTrial captured=trial;return owned()&&captured!=null&&captured.current();}
        @Override public CommandServer server(){LayeredVpnService.TorCompareTrial captured=trial;return current()?captured.server():null;}
        @Override public RouterTorProofRequest proof(){LayeredVpnService.TorCompareTrial captured=trial;return current()?captured.proof():null;}
        @Override public void cancel(){
            synchronized(candidateLock){if(kept)return;stopped=true;}
            Thread worker=startingThread;if(worker!=null)worker.interrupt();
            LayeredVpnService.TorCompareTrial captured=trial;if(captured!=null)captured.cancel();
        }
        @Override public void close() throws Exception {
            synchronized(drainLock){closeRetained();}
        }
        private void closeRetained() throws Exception {
            if(kept||closed)return;
            cancel();
            // Initiate native teardown before joining Start: proof startup can
            // be blocked on the very native sockets this closes.
            LayeredVpnService.TorCompareTrial captured=trial;if(captured!=null)captured.close();
            if(started)await(startDone,25_000_000_000L,"Tor candidate startup has not drained.");
            captured=trial;if(captured!=null)captured.close();
            NativeSingBoxController.SessionInfo staged=prepared;
            if(staged!=null){
                if(staged.maxPreparation!=null)staged.maxPreparation.close();
                if(!LayeredVpnService.discardPreparedSession(context,staged.sessionId))
                    throw new IllegalStateException("The exact Tor candidate workspace has not drained.");
            }
            closed=true;
            synchronized(lock){if(active==this)active=null;}
        }
        void keep() throws Exception {
            synchronized(candidateLock){
                if(!owned())throw unavailable();
                // Trial.keep performs only an exact memory-owner transfer;
                // all network proof and measurement drain already completed.
                trial.keep();kept=true;
            }
        }
    }

    private static void await(CountDownLatch done,long timeoutNanos,String message) throws Exception {
        boolean interrupted=Thread.interrupted();long deadline=System.nanoTime()+timeoutNanos;
        try{
            while(done.getCount()!=0){
                long left=deadline-System.nanoTime();if(left<=0)throw new IllegalStateException(message);
                try{done.await(left,TimeUnit.NANOSECONDS);}catch(InterruptedException pending){interrupted=true;}
            }
        }finally{if(interrupted)Thread.currentThread().interrupt();}
    }
    private static IllegalStateException unavailable(){return new IllegalStateException("The captured Tor comparison owner, path or source is unavailable.");}
}
