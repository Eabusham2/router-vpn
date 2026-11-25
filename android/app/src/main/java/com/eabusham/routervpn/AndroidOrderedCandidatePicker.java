package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/** Each picker owns one prefix decision, its permission request and its displayed receipts. */
final class AndroidOrderedCandidatePicker implements AndroidNodeCandidatePreparation.Callback {
    private static final int FIRST_PERMISSION=0x2000,LAST_PERMISSION=AndroidUnifiedConnectionController.PREPARE_UNIFIED-1;
    private static int nextPermission=FIRST_PERMISSION;
    private int pendingPermission=-1;
    static boolean isPermissionRequest(int code){return code>=FIRST_PERMISSION&&code<=LAST_PERMISSION;}
    private static synchronized int allocatePermission(){
        if(nextPermission>LAST_PERMISSION)throw new IllegalStateException("Restart the app to request another candidate VPN permission.");
        return nextPermission++;
    }
    private final Activity activity;
    private final boolean finalNode;
    private final AndroidNodeStore nodes;
    private final AndroidUnifiedConnectionController connection;
    private final BiConsumer<AndroidOrderedPathSelection,String> select;
    private final Consumer<AndroidOrderedPathSelection> back;
    private final Runnable changed;
    private final AndroidViaEntryLatencyProbe single;
    private final AndroidUnifiedConnectionController.Callback permissionOwner;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private final Map<String,AndroidNodeCandidateResult> scores=new HashMap<>();
    private final Map<String,String> unconnectable=new HashMap<>();
    private final List<AndroidNodeStore.Node> choices=new ArrayList<>(),paired=new ArrayList<>();
    private final Map<String,String> profileIds=new HashMap<>();
    private final AndroidOrderedPathSelection draft;
    private final long openedRevision;
    private AndroidNodeStore.ChainCapture saved;
    private AndroidNodeCandidatePreparation owner;
    private AndroidViaEntryLatencyProbe.Result singleScores;
    private AndroidNodeStore.Node first;
    private AndroidHomeStateStore.Snapshot permissionHome;
    private String permissionSelection;
    private AlertDialog dialog;
    private TextView status;
    private ArrayAdapter<String> rows;
    private int prefix;
    private boolean eligible,busy,closed,reviewing,response,publicResponse;
    private java.util.function.BooleanSupplier captureDispatched=()->true;
    private AndroidNodeCandidatePreparation retiringOwner;

    AndroidOrderedCandidatePicker(Activity activity,AndroidOrderedPathSelection draft,boolean finalNode,AndroidNodeStore nodes,
            AndroidUnifiedConnectionController connection,AndroidTelemetry telemetry,BiConsumer<AndroidOrderedPathSelection,String> select,
            Consumer<AndroidOrderedPathSelection> back,Runnable changed) {
        this.activity=activity;this.draft=draft;openedRevision=draft.revision();this.finalNode=finalNode;this.nodes=nodes;this.connection=connection;
        this.select=select;this.back=back;this.changed=changed;
        single=new AndroidViaEntryLatencyProbe(activity,AndroidRuntimeRegistry.get(activity),telemetry);
        permissionOwner=new AndroidUnifiedConnectionController.Callback(){
            public void progress(String detail){AndroidOrderedCandidatePicker.this.progress(detail);}
            public void finished(boolean ok,String detail){if(!ok)failure(detail);}
        };
    }

    void show(AndroidOrderedCandidatePicker previous) throws Exception {
        if(previous!=null&&previous.closed)retiringOwner=previous.retiringOwner;
        loadChoices();
        AlertDialog.Builder builder=new AlertDialog.Builder(activity);
        LinearLayout header=new LinearLayout(builder.getContext());header.setOrientation(LinearLayout.VERTICAL);
        int pad=Math.round(16*activity.getResources().getDisplayMetrics().density);header.setPadding(pad,pad,pad,pad/2);
        TextView title=new TextView(builder.getContext());title.setTextSize(18);title.setText(finalNode?"Final Router node":"Add intermediate node");header.addView(title);
        status=new TextView(builder.getContext());header.addView(status);
        rows=new ArrayAdapter<>(builder.getContext(),android.R.layout.simple_list_item_1);
        renderRows();
        dialog=builder.setCustomTitle(header).setAdapter(rows,(d,w)->choose(w))
                .setNeutralButton("Measure",null).setNegativeButton("Review path",null).create();
        dialog.setOnCancelListener(d->review());dialog.setCanceledOnTouchOutside(false);
        dialog.setOnDismissListener(d->{if(!reviewing)close();});dialog.show();
        dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setOnClickListener(v->review());
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v->start());
        if(!eligible) {
            status.setText(prefix<0?"Choose a node. Add an intermediate node to measure candidates through it.":"Timing is unavailable for this selected execution or prefix transport.");
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setVisibility(View.GONE);
        } else start();
    }

    private void requireDraft() throws Exception {
        draft.requireCurrent();
        if(draft.revision()!=openedRevision)throw new IllegalStateException("Reopen the picker for the changed draft.");
    }
    private void loadChoices() throws Exception {
        choices.clear();paired.clear();profileIds.clear();
        choices.addAll(draft.choices(finalNode));
        if(choices.isEmpty())throw new IllegalStateException("No unused node has a compatible transport for this position.");
        for(AndroidNodeStore.Node node:choices) {
            AndroidNodeStore.ChainSource source=draft.catalog.source(node.id);
            profileIds.put(node.id,source.profileId);
            if(!source.imported)paired.add(node);
        }
        List<AndroidOrderedPathSelection.Member> path=draft.members();
        prefix=path.size()-2;
        boolean local="local".equals(draft.execution());
        List<AndroidNodeStore.ChainSource> sources=new ArrayList<>(); List<String> modes=new ArrayList<>();
        for(AndroidOrderedPathSelection.Member member:path){sources.add(member.source);modes.add(member.mode);}
        response=AndroidNodeChainCapture.responsePrefix(sources,modes,prefix,draft.execution());
        publicResponse=response && path.get(path.size()-1).source.imported;
        eligible=prefix>=0&&List.of("local","server","auto").contains(draft.execution())
                && (!response || local || finalNode)
                &&(response||List.of("wg","awg2-fast","awg2-strong").contains(path.get(prefix).mode));
        saved=eligible&&local?draft.matchingSavedPath():null;first=null;
        if(saved==null&&eligible&&local&&prefix==0&&"wg".equals(path.get(0).mode)&&!paired.isEmpty()
                &&"off".equals(path.get(0).source.profile().optString("start_layer","off"))) {
            for(AndroidNodeStore.Node node:draft.catalog.nodes)if(node.id.equals(path.get(0).source.id))first=node;
        }
        if(eligible&&local&&saved==null&&first==null&&!response){
            for(int i=0;i<=prefix;i++){
                AndroidOrderedPathSelection.Member member=path.get(i);
                if(member.source.imported||!List.of("wg","awg2-fast","awg2-strong").contains(member.mode))eligible=false;
            }
        }
    }

    private void start() {
        if(!visible()||reviewing||busy)return;
        try {
            requireDraft();
            AndroidNodeCandidatePreparation previous=owner!=null?owner:retiringOwner;
            retireScores();
            if(previous!=null&&AndroidNodeCandidatePreparation.retained()==previous){
                busy=true;controls();status.setText("Waiting for the previous test to release its network observer…");
                waitForRetirement(previous);return;
            }
            busy=true;
            permissionHome=AndroidHomeStateStore.snapshot(activity);permissionSelection=AndroidConnectionSelection.digest(activity,nodes);
            if(connection.isActiveOrTransitioning()||!connection.pathCurrent(permissionHome))throw new IllegalStateException("Disconnect before measuring this prefix.");
            status.setText((publicResponse?"Measuring verified public HTTPS exit responses through ":response?"Measuring authenticated private candidate responses through ":"Measuring candidate TCP handshakes through ")+(prefix+1)+" selected hop(s)…");renderRows();controls();
            if(first!=null) {
                Intent permission=VpnService.prepare(activity);
                if(permission!=null){pendingPermission=allocatePermission();activity.startActivityForResult(permission,pendingPermission);}
                else measureFirst(true);
            } else if(saved!=null) {
                captureDispatched=connection.testOrderedCandidates(saved,permissionHome,permissionSelection,prefix,this,permissionOwner);
            } else {
                java.util.concurrent.Callable<AndroidNodeStore.ChainCapture> capture=draft.candidateDraftCapture(prefix);
                new Thread(()->{
                    try {
                        AndroidNodeStore.ChainCapture source=capture.call();
                        activity.runOnUiThread(()->{
                            if(!visible()||reviewing||!busy)return;
                            if(draft.revision()!=openedRevision){failure("Reopen the picker for the changed draft.");return;}
                            captureDispatched=connection.testOrderedCandidates(source,permissionHome,permissionSelection,prefix,this,permissionOwner);
                        });
                    } catch(Exception unavailable){failure(unavailable.getMessage());}
                },"routervpn-candidate-draft-capture").start();
            }
        } catch(Exception unavailable){failure(unavailable.getMessage());}
    }

    private void waitForRetirement(AndroidNodeCandidatePreparation previous) {
        handler.postDelayed(()->{
            if(!visible()||reviewing)return;
            if(AndroidNodeCandidatePreparation.retained()==previous){waitForRetirement(previous);return;}
            busy=false;start();
        },200);
    }

    void permission(int request,boolean granted) {
        if(request!=pendingPermission||pendingPermission<0)return;
        pendingPermission=-1;measureFirst(granted);
    }
    void pause(){
        if(pendingPermission<0&&!connection.isPermissionPending())close();
    }
    private void measureFirst(boolean granted) {
        if(!visible()||reviewing||first==null||!busy)return;
        try {
            if(!granted)throw new IllegalStateException("VPN permission was declined.");
            requireDraft();AndroidConnectionSelection.requireCurrent(activity,nodes,permissionSelection);
            if(!connection.pathCurrent(permissionHome))throw new IllegalStateException("The original idle VPN changed.");
            single.measure(first,paired,50,new AndroidViaEntryLatencyProbe.Callback(){
                public void progress(String detail){AndroidOrderedCandidatePicker.this.progress(detail);}
                public void finished(AndroidViaEntryLatencyProbe.Result value,Throwable error){activity.runOnUiThread(()->{
                    if(!visible()||reviewing)return;
                    try {
                        if(error!=null||value==null)throw new IllegalStateException(error==null?"No complete via-entry timing.":error.getMessage());
                        value.requireCurrent();requireDraft();singleScores=value;complete();
                    } catch(Exception stale){failure(stale.getMessage());}
                });}
            });
        } catch(Exception unavailable){failure(unavailable.getMessage());}
    }

    public void progress(String detail){activity.runOnUiThread(()->{if(visible()&&!reviewing)status.setText(detail);});}
    public void finished(List<AndroidNodeCandidatePreparation.Choice> measured,Throwable error){activity.runOnUiThread(()->{
        if(!visible()||reviewing)return;
        try {
            if(error!=null)throw new IllegalStateException(error.getMessage());
            AndroidNodeCandidatePreparation captured=AndroidNodeCandidatePreparation.retained();
            if(captured==null||!captured.observes(this))throw new IllegalStateException("The original candidate batch is unavailable.");
            requireDraft();scores.clear();unconnectable.clear();owner=captured;
            for(AndroidNodeCandidatePreparation.Choice choice:measured){
                owner.requireSavedResultCurrent(choice.result);scores.put(choice.result.id,choice.result);
                if (choice.profile==null) unconnectable.put(choice.result.id,choice.saveReason);
            }
            complete();
        } catch(Exception stale){failure(stale.getMessage());}
    });}

    private void complete() {
        busy=false;status.setText("Through "+(prefix+1)+" selected hop(s) • 50 "+(publicResponse?"verified public HTTPS exit responses":response?"authenticated private responses":"TCP handshakes")+" per scored node • 10% trimmed mean");
        renderRows();controls();changed.run();handler.removeCallbacks(expiry);handler.postDelayed(expiry,1000);
    }
    private final Runnable expiry=new Runnable(){public void run(){
        if(!visible()||reviewing||busy)return;
        try {
            if(singleScores!=null)singleScores.requireCurrent();
            else if(!scores.isEmpty()) {
                for(AndroidNodeCandidateResult result:scores.values())if(!result.current(System.currentTimeMillis()))throw new IllegalStateException("Candidate timings expired.");
            } else return;
            handler.postDelayed(this,1000);
        } catch(Exception stale){failure(stale.getMessage());}
    }};

    private void controls() {
        dialog.getListView().setEnabled(!busy);
        dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setText(busy?"Cancel test and review":"Review path");
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setEnabled(!busy);
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setText("Retest");
    }
    private void renderRows() {
        rows.setNotifyOnChange(false);rows.clear();
        for(AndroidNodeStore.Node node:choices) {
            AndroidNodeCandidateResult result=scores.get(profileIds.get(node.id));
            double score=result!=null?result.score:singleScores==null?Double.NaN:AndroidViaEntryLatencyProbe.Result.score(singleScores.measurement(node.id));
            rows.add(node.name+(prefix<0?"":Double.isFinite(score)?String.format(Locale.US," • %.1f ms",score):" • Unmeasured"));
        }
        rows.notifyDataSetChanged();
    }
    private void choose(int index) {
        try {
            if(reviewing||busy||connection.isActiveOrTransitioning())throw new IllegalStateException("Wait for the original temporary VPN to stop.");
            requireDraft();AndroidNodeStore.Node choice=choices.get(index);
            if(singleScores!=null)singleScores.requireCurrent();
            AndroidNodeCandidateResult measured=scores.get(profileIds.get(choice.id));
            if (response && finalNode && ("auto".equals(draft.execution()) || "server".equals(draft.execution()))) {
                if (measured==null) throw new IllegalStateException("Choose a different paired final with a current authenticated response from the selected route.");
                if (unconnectable.containsKey(measured.id)) throw new IllegalStateException(unconnectable.get(measured.id));
            }
            if(measured!=null)owner.requireSavedResultCurrent(measured);
            close();select.accept(draft,choice.id);
        } catch(Exception stale){android.widget.Toast.makeText(activity,stale.getMessage(),android.widget.Toast.LENGTH_LONG).show();}
    }
    private void failure(String detail) {activity.runOnUiThread(()->{
        if(!visible()||reviewing)return;busy=false;scores.clear();singleScores=null;status.setText("Timing unavailable. "+(detail==null?"":detail));
        renderRows();controls();
    });}
    private void review() {
        if(closed)return;
        reviewing=true;pendingPermission=-1;
        single.cancel();connection.cancelPending(permissionOwner);
        handler.removeCallbacks(returnAfterCleanup);returnAfterCleanup.run();
    }
    private final Runnable returnAfterCleanup=new Runnable(){public void run(){
        if(closed||activity.isFinishing()||activity.isDestroyed())return;
        // A permission capture may reserve its owner after Review was tapped.
        // Detach only our observer, and wait for that owner's actual retirement.
        retireScores();
        if(!captureDispatched.getAsBoolean()||single.isBusy()||
                (retiringOwner!=null&&AndroidNodeCandidatePreparation.retained()==retiringOwner)){
            if(!dialog.isShowing())dialog.show();
            dialog.getListView().setEnabled(false);dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setEnabled(false);
            dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setText("Retry cleanup");
            status.setText("Waiting for this test to release the VPN before reviewing the path…");
            handler.postDelayed(this,200);return;
        }
        try{requireDraft();close();back.accept(draft);}
        catch(Exception stale){close();android.widget.Toast.makeText(activity,stale.getMessage(),android.widget.Toast.LENGTH_LONG).show();}
    }};
    private void retireScores() {
        handler.removeCallbacks(expiry);scores.clear();singleScores=null;
        AndroidNodeCandidatePreparation captured=captureDispatched.getAsBoolean()?AndroidNodeCandidatePreparation.retained():null;
        if(captured!=null&&captured.observes(this)){retiringOwner=captured;captured.detach(this);captured.cancelFromUser();}
        owner=null;
    }
    boolean visible(){return !closed&&!activity.isFinishing()&&!activity.isDestroyed()&&dialog!=null&&dialog.isShowing();}
    void close() {
        if(closed)return;closed=true;pendingPermission=-1;handler.removeCallbacks(returnAfterCleanup);retireScores();single.cancel();connection.cancelPending(permissionOwner);
        if(dialog!=null&&dialog.isShowing())dialog.dismiss();
    }
}
