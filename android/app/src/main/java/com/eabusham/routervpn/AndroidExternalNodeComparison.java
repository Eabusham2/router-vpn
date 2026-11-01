package com.eabusham.routervpn;

import android.app.Activity;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/** A frozen external exit cohort. Every trial borrows the same MTU lease and
 * uses Speed Lab's existing captured stop/drain/restore transaction. */
final class AndroidExternalNodeComparison {
    interface Callback {void progress(String message);void finished(Result result,Throwable error);}
    static final class PathContext {
        final AndroidNodeStore.Node entry;
        final AndroidStandardExitStore.Entry ordinary;
        final String mode,execution;
        private PathContext(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry ordinary,String mode,String execution){this.entry=entry;this.ordinary=ordinary;this.mode=mode;this.execution=execution;}
        static PathContext direct(){return new PathContext(null,null,"wg","local");}
        static PathContext saved(AndroidConnectionProfileStore.ExternalSelection path)throws Exception{return new PathContext(path.entry,path.ordinaryEntry==null?null:AndroidStandardExitStore.copy(path.ordinaryEntry),path.entryMode,path.execution);}
        boolean directPath(){return entry==null&&ordinary==null;}
        String detail(){return directPath()?"Direct external paths":(entry!=null?entry.name:ordinary.name)+" ["+mode+"] → each external exit • "+execution;}
    }
    static final class Row {
        final String id,name,failure;
        final AndroidExternalNodeStatistics.Record measurement;
        final AndroidUnifiedConnectionController.RestorePoint path;
        Row(AndroidStandardExitStore.Entry node,String failure,AndroidExternalNodeStatistics.Record measurement,AndroidUnifiedConnectionController.RestorePoint path){id=node.id;name=node.name;this.failure=failure;this.measurement=measurement;this.path=path;}
        boolean scored(){return measurement!=null&&path!=null&&failure.isEmpty();}
        double score(){return scored()?measurement.trimmedMean:Double.POSITIVE_INFINITY;}
    }
    static final class Result {
        final List<Row> rows;
        final Row winner;
        final boolean adopted;
        final String context,usageMessage;
        Result(Job job){ArrayList<Row> sorted=new ArrayList<>(job.rows);sorted.sort(Comparator.comparingDouble(Row::score).thenComparing(r->r.id));rows=Collections.unmodifiableList(sorted);winner=fastest(rows);adopted=job.adopted;context=job.path.detail();usageMessage=job.usageMessage;}
        String detail(){
            StringBuilder text=new StringBuilder(context).append("\n\n50 routed HTTPS responses per eligible path • lowest 10% trimmed mean wins\n");
            for(Row row:rows){text.append("\n").append(row.name).append(" • ");if(row.scored())text.append(String.format(Locale.US,"%.1f ms (median %.1f, p90 %.1f) • %s",row.score(),row.measurement.median,row.measurement.p90,row.measurement.selected));else text.append("No score: ").append(row.failure);}
            if(winner!=null)text.append("\n\n").append(adopted?"Connected and freshly proved: ":"Fastest in this completed round: ").append(winner.name);
            else text.append("\n\nNo eligible path completed a valid 50-sample result.");
            text.append("\n\n").append(AndroidExternalNodeStatistics.ENDPOINT).append("\nResponses start after routed DNS, TCP and TLS preparation. These are HTTPS response times, separate from Router direct TCP ranking and ICMP RTT.");
            if(!adopted)text.append(" The original connection was restored; these results describe this completed round.");
            return text.append(usageMessage).toString();
        }
    }
    private static final Object PROCESS=new Object();
    private static Job processOwner;
    static boolean hasActiveOperation(){synchronized(PROCESS){return processOwner!=null;}}
    static boolean cancelActiveOperation(){Job job;synchronized(PROCESS){job=processOwner;}if(job==null)return false;job.owner.cancel(job);return true;}
    private static Row fastest(List<Row> rows){Row best=null;for(Row row:rows)if(row.scored()&&(best==null||row.score()<best.score()||row.score()==best.score()&&row.id.compareTo(best.id)<0))best=row;return best;}

    private static final class Candidate {
        final AndroidStandardExitStore.Entry exit;final String unavailable;
        Candidate(AndroidStandardExitStore.Entry exit,String unavailable)throws Exception{this.exit=AndroidStandardExitStore.copy(exit);this.unavailable=unavailable;}
    }
    private static final class Job {
        final AndroidExternalNodeComparison owner;
        final PathContext path;
        final List<Candidate> candidates;
        final AndroidUnifiedConnectionController.RestorePoint original;
        final String selection,activeNode,exitStoreSHA,entrySHA;
        final File exitStore,entryFile;
        final AndroidExternalComparisonNetwork network;
        final Object lease;
        final Callback callback;
        final boolean connectFastest;
        final List<Row> rows=new ArrayList<>();
        final String request=UUID.randomUUID().toString().replace("-","");
        AndroidHomeStateStore.Snapshot expectedHome;
        volatile boolean cancelled;
        volatile boolean adopted,finished,cleaning;
        Result terminalResult;
        Throwable terminalError;
        int next,cleanupAttempts;
        String usageMessage="";
        Job(AndroidExternalNodeComparison owner,PathContext path,List<Candidate> candidates,AndroidUnifiedConnectionController.RestorePoint original,String selection,String activeNode,String exits,File exitFile,String entrySHA,File entryFile,AndroidExternalComparisonNetwork network,Object lease,boolean connectFastest,Callback callback){this.owner=owner;this.path=path;this.candidates=Collections.unmodifiableList(candidates);this.original=original;expectedHome=original.home;this.selection=selection;this.activeNode=activeNode;exitStoreSHA=exits;exitStore=exitFile;this.entrySHA=entrySHA;this.entryFile=entryFile;this.network=network;this.lease=lease;this.connectFastest=connectFastest;this.callback=callback;}
    }

    /** Only this batch can mint a final selection receipt, after fresh proof. */
    static final class Adoption implements AndroidConnectionProfileStore.MeasuredSelection {
        final AndroidConnectionProfileStore.ExternalSelection path;
        private final Job job;
        private final AndroidUnifiedConnectionController.RestorePoint winner;
        private final String session;
        private Adoption(Job job,Row row,String session){this.job=job;winner=row.path;this.session=session;path=new AndroidConnectionProfileStore.ExternalSelection(winner.entry,winner.ordinaryEntry,winner.external,winner.home.activeEntryMode,winner.execution);}
        public AndroidConnectionProfileStore.ExternalSelection path(){return path;}
        public void requireBeforeSelection()throws Exception{job.owner.requireRound(job,true);requireProof();}
        public void requireAfterSelection()throws Exception{job.owner.requireRound(job,false);requireProof();}
        private void requireProof()throws Exception{if(job.adopted||!job.owner.connection.restoredCurrent(winner,session))throw new IllegalStateException("The fastest path lost its final fresh proof before selection.");job.owner.connection.requireRestoreSource(winner);job.owner.requireProvedPhysical(job,job.owner.connection.captureRestorePoint(),false);}
    }

    private final Activity activity;
    private final AndroidNodeStore nodes;
    private final AndroidUnifiedConnectionController connection;
    private final AndroidSpeedLabController trial;
    private final android.os.Handler main=new android.os.Handler(android.os.Looper.getMainLooper());
    private volatile Job active;
    AndroidExternalNodeComparison(Activity activity,AndroidNodeStore nodes,AndroidUnifiedConnectionController connection){this.activity=activity;this.nodes=nodes;this.connection=connection;trial=new AndroidSpeedLabController(activity,connection);}
    void cancel(){Job job=active;if(job!=null)cancel(job);}

    void run(PathContext context,boolean connectFastest,Callback callback){
        AndroidExternalComparisonNetwork network=null;Object lease=null;Job created=null;
        try{
            synchronized(PROCESS){if(processOwner!=null)throw new IllegalStateException("Another external comparison is still draining.");}
            if(context==null||AndroidMTUMeasurementGate.held()||connection.isPermissionPending())throw new IllegalStateException("Finish the current permission or measurement before comparing external exits.");
            context=new PathContext(context.entry,context.ordinary==null?null:AndroidStandardExitStore.copy(context.ordinary),context.mode,context.execution);
            String selection=AndroidConnectionSelection.digest(activity,nodes),activeNode=nodes.activeId();
            File store=new File(activity.getApplicationContext().getFilesDir(),"standard-exits.json");String exits=digest(store,512*1024);
            List<AndroidStandardExitStore.Entry> saved=connection.standardExits();
            if(saved.isEmpty()||saved.size()>AndroidStandardExitStore.MAX_EXITS)throw new IllegalStateException("Import a bounded set of external nodes before comparison.");
            List<Candidate> candidates=new ArrayList<>();java.util.HashSet<String> ids=new java.util.HashSet<>();
            for(AndroidStandardExitStore.Entry exit:saved){
                if(!ids.add(exit.id))throw new IllegalStateException("Duplicate external candidate identity.");
                String unavailable="";
                try{AndroidConnectionProfileStore.validateExternalGraph(exit,context.entry,context.ordinary,context.mode,context.execution);}
                catch(Exception invalid){unavailable=safe(invalid);}
                candidates.add(new Candidate(exit,unavailable));
            }
            if(!exits.equals(digest(store,512*1024)))throw new IllegalStateException("External sources changed during cohort capture.");
            File entry=context.entry==null?null:context.entry.file.getCanonicalFile();String entrySHA=entry==null?"":digest(entry,AndroidNodeStore.MAX_BUNDLE);
            if(context.ordinary!=null&&!AndroidStandardExitStore.snapshot(context.ordinary).equals(AndroidStandardExitStore.snapshot(new AndroidStandardExitStore(activity).get(context.ordinary.id))))throw new IllegalStateException("The ordinary entry changed before comparison.");
            AndroidUnifiedConnectionController.RestorePoint original=connection.captureRestorePoint();
            network=new AndroidExternalComparisonNetwork(activity);lease=AndroidMTUMeasurementGate.acquire();
            Job job=new Job(this,context,candidates,original,selection,activeNode,exits,store,entrySHA,entry,network,lease,connectFastest,callback);
            synchronized(PROCESS){if(processOwner!=null)throw new IllegalStateException("Another comparison acquired the process owner.");active=processOwner=job;created=job;}
            network.start();requireRound(job,true);requireOriginalOwner(job);next(job);
        }catch(Throwable failure){
            if(created!=null){finish(created,null,failure);return;}
            if(network!=null)try{network.close();}catch(Throwable close){failure.addSuppressed(close);}
            AndroidMTUMeasurementGate.release(lease);callback.finished(null,failure);
        }
    }

    private void requireRound(Job job,boolean selection)throws Exception{
        synchronized(PROCESS){if(processOwner!=job||active!=job||job.finished)throw new IllegalStateException("The external comparison owner changed.");}
        if(job.cancelled)throw new java.util.concurrent.CancellationException("External comparison cancelled; old candidates receive no score.");
        if(!AndroidMTUMeasurementGate.owns(job.lease))throw new IllegalStateException("The comparison lost its original MTU lease.");
        job.network.requireCurrent();
        if(!job.activeNode.equals(nodes.activeId())||!job.exitStoreSHA.equals(digest(job.exitStore,512*1024)))throw new IllegalStateException("A captured candidate or selected Router source changed.");
        if(selection)AndroidConnectionSelection.requireCurrent(activity,nodes,job.selection);
        if(job.entryFile!=null){File current=nodes.file(job.path.entry.id);if(current==null||!job.entryFile.equals(current.getCanonicalFile())||!job.entrySHA.equals(digest(job.entryFile,AndroidNodeStore.MAX_BUNDLE)))throw new IllegalStateException("The frozen entry was relinked or changed.");}
        connection.requireRestoreSource(job.original);
    }
    /** Invoked under native owner → Home → private I/O monitors. It uses
     * immutable captures, raw private reads and preferences only: no NodeStore
     * or ExitStore instance lock can invert the established save order. */
    private void requireCommit(Job job,LayeredVpnService.HopMeasurementOwner nativeOwner)throws Exception{
        synchronized(PROCESS){if(processOwner!=job||active!=job||job.finished||job.cleaning)throw new IllegalStateException("The comparison commit owner changed.");}
        if(job.cancelled||!AndroidMTUMeasurementGate.owns(job.lease))throw new IllegalStateException("The comparison commit was cancelled or lost its MTU lease.");
        try{job.network.requireProved(nativeOwner.physicalNetwork());}catch(Exception stale){job.network.invalidate();throw stale;}
        AndroidConnectionSelection.requireCurrent(activity,nodes,job.selection);
        if(!job.exitStoreSHA.equals(digest(job.exitStore,512*1024))||job.entryFile!=null&&!job.entrySHA.equals(digest(job.entryFile,AndroidNodeStore.MAX_BUNDLE)))throw new IllegalStateException("A frozen candidate source changed before benchmark save.");
        for(java.util.Map.Entry<File,String> source:job.original.files.entrySet())if(!source.getValue().equals(digest(source.getKey(),AndroidNodeStore.MAX_BUNDLE)))throw new IllegalStateException("The original source changed before benchmark save.");
    }
    private void requireProvedPhysical(Job job,AndroidUnifiedConnectionController.RestorePoint path)throws Exception{requireProvedPhysical(job,path,true);}
    private void requireProvedPhysical(Job job,AndroidUnifiedConnectionController.RestorePoint path,boolean selection)throws Exception{
        requireRound(job,selection);
        if(path==null||path.externalSource==null||!connection.pathCurrent(path.home))throw new IllegalStateException("The candidate has no exact proved native path owner.");
        AndroidStandardExitRuntime.MeasurementSource source=path.externalSource;
        LayeredVpnService.HopMeasurementOwner receipt=LayeredVpnService.captureExternalHopMeasurement(job.request,path.external.id,source.nativeSession,path.home.sessionId,path.home.pathGeneration);
        job.network.requireProved(receipt.physicalNetwork());
    }
    private void requireOriginalOwner(Job job)throws Exception{
        if(job.expectedHome==null||!connection.pathCurrent(job.expectedHome))throw new IllegalStateException("A newer connection decision replaced the batch's restored owner.");
        if(job.original.connected()? !connection.restoredCurrent(job.original,job.expectedHome.sessionId):!connection.idleCurrent(job.expectedHome))throw new IllegalStateException("The original complete connection was not restored and proved.");
    }
    private void next(Job job){
        try{
            requireRound(job,true);requireOriginalOwner(job);
            while(job.next<job.candidates.size()&&!job.candidates.get(job.next).unavailable.isEmpty()){
                Candidate skipped=job.candidates.get(job.next++);job.rows.add(new Row(skipped.exit,skipped.unavailable,null,null));
            }
            if(job.next==job.candidates.size()){
                Row winner=fastest(job.rows);
                if(job.connectFastest&&winner!=null){adopt(job,winner);return;}
                finish(job,new Result(job),null);return;
            }
            Candidate candidate=job.candidates.get(job.next++);
            progress(job,"External path "+job.next+" / "+job.candidates.size()+": "+candidate.exit.name+" • "+job.path.detail());
            AndroidSpeedLabController.Request request=new AndroidSpeedLabController.Request();request.scope="temporary";request.topology="external";request.entry=job.path.entry;request.ordinaryEntry=job.path.ordinary;request.standardExit=candidate.exit;request.externalDirect=job.path.directPath();request.entryMode=job.path.mode;request.execution=job.path.execution;
            trial.runExternalLatency(request,job.lease,new AndroidSpeedLabController.ExternalCallback(){
                public void validate()throws Exception{requireRound(job,true);}
                public void validateCommit(LayeredVpnService.HopMeasurementOwner nativeOwner)throws Exception{requireCommit(job,nativeOwner);}
                public void permissionDenied(){synchronized(job){job.cancelled=true;}}
                public void beforeStart()throws Exception{job.network.requireBeforeStart();}
                public void proved(AndroidUnifiedConnectionController.RestorePoint path)throws Exception{requireProvedPhysical(job,path);}
                public void progress(String message){AndroidExternalNodeComparison.this.progress(job,candidate.exit.name+": "+message);}
                public void finished(AndroidSpeedLabController.ExternalResult result,Throwable error){
                    try{
                        requireRound(job,true);
                        if(result==null||result.returnedHome==null)throw new IllegalStateException("A candidate did not return the original proved owner.",error);
                        job.expectedHome=result.returnedHome;requireOriginalOwner(job);
                        if(error==null){
                            if(result.measurement==null||result.measuredPath==null||!candidate.exit.id.equals(result.measurement.id)
                                    ||!job.network.identity().equals(result.measurement.networkSHA)
                                    ||!job.path.execution.equals(result.measurement.requested)
                                    ||!result.measuredPath.selectedExecution.equals(result.measurement.selected))throw new IllegalStateException("The candidate returned another path, execution or physical network.");
                            connection.requireRestoreSource(result.measuredPath);
                            job.rows.add(new Row(candidate.exit,"",result.measurement,result.measuredPath));
                        }else job.rows.add(new Row(candidate.exit,safe(error),null,null));
                        main.post(()->next(job));
                    }catch(Throwable stale){finish(job,null,stale);}
                }
            });
        }catch(Throwable failure){finish(job,null,failure);}
    }
    private void adopt(Job job,Row winner)throws Exception{
        requireRound(job,true);requireOriginalOwner(job);connection.requireRestoreSource(winner.path);
        final AndroidNodeUsage.Attempt usage;
        try{usage=AndroidNodeUsage.external(activity,winner.path.entry,winner.path.ordinaryEntry,winner.path.external,winner.path.entry==null&&winner.path.ordinaryEntry==null,winner.path.home.activeEntryMode);}
        catch(Exception failure){throw new IllegalStateException("The fastest path's final user adoption could not capture its private sources.",failure);}
        progress(job,"Restoring the measured winner "+winner.name+" ["+winner.measurement.selected+"] and requiring fresh proof…");
        trial.adoptExternal(winner.path,job.lease,new AndroidSpeedLabController.ExternalCallback(){
            public void validate()throws Exception{requireRound(job,true);}
            public void permissionDenied(){synchronized(job){job.cancelled=true;}}
            public void beforeStart()throws Exception{job.network.requireBeforeStart();}
            public void proved(AndroidUnifiedConnectionController.RestorePoint path)throws Exception{requireProvedPhysical(job,path);}
            public void owned(String session){usage.owned(activity,session);}
            public void progress(String message){AndroidExternalNodeComparison.this.progress(job,message);}
            public void adopted(AndroidUnifiedConnectionController.RestorePoint path,String session)throws Exception{
                synchronized(job){
                    requireRound(job,true);
                    Adoption receipt=new Adoption(job,winner,session);
                    new AndroidConnectionProfileStore(activity,nodes,new AndroidStandardExitStore(activity)).selectMeasuredExternal(receipt);
                    // Selection and the single user-use receipt commit under the
                    // original batch cancellation owner, after fresh path proof.
                    job.adopted=true;job.usageMessage=usage.finished(activity,job.request,true);
                }
            }
            public void finished(AndroidSpeedLabController.ExternalResult result,Throwable error){
                if(error!=null||result==null||!result.adopted||!job.adopted){usage.cancel();finish(job,null,error!=null?error:new IllegalStateException("The measured winner was not adopted."));return;}
                finish(job,new Result(job),null);
            }
        });
    }
    private void cancel(Job job){
        synchronized(job){if(job.finished)return;if(!job.adopted)job.cancelled=true;}
        activity.runOnUiThread(()->{if(trial.isRunning())trial.cancel();else finish(job,null,job.adopted?null:new java.util.concurrent.CancellationException("External comparison cancelled."));});
    }
    private void finish(Job job,Result result,Throwable error){
        synchronized(PROCESS){
            if(processOwner!=job||active!=job||job.finished||trial.isRunning())return;
            if(!job.cleaning){job.cleaning=true;job.terminalResult=job.adopted?new Result(job):result;job.terminalError=error;}
        }
        try{job.network.close();}catch(Throwable close){
            // Keep the exact observer and lease until Android confirms both
            // unregister operations. Cancel retries cleanup, including after
            // final adoption; it never undoes the committed user connection.
            job.cleanupAttempts++;
            if(job.terminalError==null)job.terminalError=close;
            else if(job.cleanupAttempts<=3)job.terminalError.addSuppressed(close);
            try{job.callback.progress((job.adopted?"Fastest path is connected. ":"")+"Network-observer cleanup is pending; the comparison still owns its lease. Tap Cancel comparison to retry cleanup.");}catch(Throwable ignored){}
            if(job.cleanupAttempts<3)main.postDelayed(()->finish(job,null,null),250);
            return;
        }
        synchronized(PROCESS){if(processOwner!=job||active!=job||job.finished)return;job.finished=true;}
        AndroidMTUMeasurementGate.release(job.lease);
        synchronized(PROCESS){if(processOwner==job)processOwner=null;if(active==job)active=null;}
        try{LayeredVpnService.startAutomaticMTU();}catch(Throwable restart){if(job.terminalError==null)job.terminalError=restart;else job.terminalError.addSuppressed(restart);}
        job.callback.finished(job.terminalResult,job.terminalError);
    }
    private void progress(Job job,String message){try{job.callback.progress(message);}catch(Throwable abandoned){cancel(job);}}
    private static String digest(File file,int maximum)throws Exception{return AndroidTorProfile.digest(AndroidPrivateFileStore.read(file,maximum));}
    private static String safe(Throwable error){String message=error==null?"No valid measurement.":error.getMessage();return message==null||message.isEmpty()?error.getClass().getSimpleName():message;}
}
