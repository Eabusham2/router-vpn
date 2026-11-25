package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** A screen attachment to a process-owned test; leaving the screen never owns
 * native teardown. Explicit Cancel/Close retires only this captured purpose. */
final class AndroidNodeCandidatePreparationDialog {
    private final Activity activity;
    private final AndroidNodeStore nodes;
    private final AndroidUnifiedConnectionController connection;
    private final Runnable changed;
    private final Notice notice;
    private final AndroidUnifiedConnectionController.Callback permission;
    private volatile boolean detached;
    private boolean waitingForReviewRelease;
    private AndroidNodeCandidatePreparation owner;
    private AlertDialog dialog,proposalDialog;
    private TextView output;
    private AndroidOrderedPathSelection editor;
    private final java.util.function.BiConsumer<AndroidOrderedPathSelection,Integer> continueDraft;
    private static WeakReference<AndroidNodeStore.ChainCapture> editorSource = new WeakReference<>(null);
    private static WeakReference<AndroidOrderedPathSelection> sourceEditor = new WeakReference<>(null);
    private List<AndroidNodeCandidatePreparation.Choice> choices=Collections.emptyList();

    private static final class Notice implements AndroidNodeCandidatePreparation.Callback {
        final WeakReference<AndroidNodeCandidatePreparationDialog> screen;
        Notice(AndroidNodeCandidatePreparationDialog screen){this.screen=new WeakReference<>(screen);}
        private AndroidNodeCandidatePreparationDialog attached(){AndroidNodeCandidatePreparationDialog value=screen.get();if(value!=null&&!value.detached)return value;AndroidNodeCandidatePreparation retained=AndroidNodeCandidatePreparation.retained();if(retained!=null)retained.detach(this);return null;}
        public void progress(String detail){AndroidNodeCandidatePreparationDialog value=attached();if(value!=null)value.update(detail);}
        public void finished(List<AndroidNodeCandidatePreparation.Choice> choices,Throwable failure){AndroidNodeCandidatePreparationDialog value=attached();if(value!=null)value.completed(choices,failure);}
    }
    AndroidNodeCandidatePreparationDialog(Activity activity,AndroidNodeStore nodes,AndroidUnifiedConnectionController connection,Runnable changed,java.util.function.BiConsumer<AndroidOrderedPathSelection,Integer> continueDraft){
        this.continueDraft=continueDraft;this.activity=activity;this.nodes=nodes;this.connection=connection;this.changed=changed;notice=new Notice(this);
        permission=new AndroidUnifiedConnectionController.Callback(){public void progress(String detail){update(detail);}public void finished(boolean ok,String detail){update(detail);}};
    }
    void show(){show(null,-1);}
    void showDraft(java.util.concurrent.Callable<AndroidNodeStore.ChainCapture> capture,int prefix,
            AndroidOrderedPathSelection editor) {
        this.editor=editor;
        show(capture,prefix);
    }
    void show(java.util.concurrent.Callable<AndroidNodeStore.ChainCapture> draft,int prefix){
        AndroidNodeCandidatePreparation existing=AndroidNodeCandidatePreparation.retained();
        if(existing!=null){
            if(draft!=null){showMessage("Finish the current candidate test before measuring this draft.");return;}
            owner=existing;
            if (existing.ownsSource(editorSource.get())) editor=sourceEditor.get();
            showProgress();owner.attach(notice);return;
        }
        final AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(activity);final String selected;
        try{if(connection.isActiveOrTransitioning()||home.connected)throw new IllegalStateException("Stop the current VPN before testing the saved ordered path.");selected=AndroidConnectionSelection.digest(activity,nodes);}
        catch(Exception failure){showMessage(failure.getMessage());return;}
        showProgress();output.setText(draft!=null?"Reading the original draft and measuring through hop "+(prefix+1)+"…":"Reading the saved Local path… A WireGuard or AmneziaWG prefix can be tested without later nodes. Other selections require the complete saved path. Each candidate needs 50 successful handshakes or authenticated private responses; results appear after the temporary VPN stops.");
        new Thread(()->{
            try{
                AndroidNodeStore.ChainCapture source=draft==null?new AndroidConnectionProfileStore(activity,nodes,new AndroidStandardExitStore(activity)).currentOrderedPath():draft.call();
                source.requireCurrent();
                if(draft!=null){
                    source.requireCandidatePurpose(prefix);
                    if(!source.measurementOnly()||!AndroidNodeChainCapture.responsePrefix(source.members,source.modes,prefix,source.execution))
                        throw new IllegalStateException("The draft lost its selected Shadowsocks response prefix.");
                    activity.runOnUiThread(()->{
                        if(visible()){
                            editorSource=new WeakReference<>(source);sourceEditor=new WeakReference<>(editor);
                            connection.testOrderedCandidates(source,home,selected,prefix,notice,permission);
                        }
                    });
                    return;
                }
                List<Integer> positions=new ArrayList<>();List<String> names=new ArrayList<>();
                if(!"local".equals(source.execution))throw new IllegalStateException("Choose Local execution for this saved path before testing candidates.");
                for(int i=0;i<source.modes.size();i++){String mode=source.modes.get(i);if("wg".equals(mode)||"awg2-fast".equals(mode)||"awg2-strong".equals(mode)||AndroidNodeChainCapture.responsePrefix(source.members,source.modes,i,source.execution)){positions.add(i);names.add("Through node "+(i+1)+" • "+mode+" • "+(AndroidNodeCandidatePreparation.packetPrefix(source,i)?"prefix only":"complete saved path"));}}
                if(positions.isEmpty())throw new IllegalStateException("The saved path has no qualified prefix for candidate measurement.");
                activity.runOnUiThread(()->{
                    if(!visible())return;
                    try{AndroidConnectionSelection.requireCurrent(activity,nodes,selected);if(!connection.pathCurrent(home))throw new IllegalStateException("The original idle connection choice changed.");}
                    catch(Exception failure){update(failure.getMessage());return;}
                    proposalDialog=new AlertDialog.Builder(activity).setTitle("Test candidates")
                        .setItems(names.toArray(new CharSequence[0]),(d,w)->connection.testOrderedCandidates(source,home,selected,positions.get(w),notice,permission))
                        .setNegativeButton("Cancel",(d,w)->cancel()).show();
                });
            }catch(Exception failure){update("Candidate testing unavailable: "+failure.getMessage());}
        },"routervpn-candidate-choice-capture").start();
    }
    private void showProgress(){
        output=new TextView(activity);output.setPadding(32,24,32,24);output.setTextIsSelectable(true);output.setText("Testing saved path…");
        LinearLayout body=new LinearLayout(activity);body.setOrientation(LinearLayout.VERTICAL);body.addView(output);
        if (editor != null) {
            Button use=new Button(activity);use.setText("Use in draft");use.setOnClickListener(v->chooseDraftInsertion());body.addView(use);
        }
        Button save=new Button(activity);save.setText("Save as profile");save.setOnClickListener(v->chooseProfile());body.addView(save);
        ScrollView scroll=new ScrollView(activity);scroll.addView(body);
        dialog=new AlertDialog.Builder(activity).setTitle("Test candidates").setView(scroll).setNegativeButton("Cancel / Close",(d,w)->cancel()).create();
        dialog.setOnDismissListener(d->{if(!detached)cancel();});dialog.show();
    }
    private AndroidNodeCandidatePreparation capturedOwner(){AndroidNodeCandidatePreparation current=AndroidNodeCandidatePreparation.retained();return current!=null&&current.observes(notice)?current:null;}
    private void update(String detail){activity.runOnUiThread(()->{if(!visible())return;if(owner==null)owner=capturedOwner();output.setText(detail);changed.run();});}
    private void completed(List<AndroidNodeCandidatePreparation.Choice> completed,Throwable failure){activity.runOnUiThread(()->{
        if(!visible() || waitingForReviewRelease)return;if(owner==null)owner=capturedOwner();choices=Collections.unmodifiableList(new ArrayList<>(completed));
        boolean savable=false;for(var choice:choices)if(choice.profile!=null&&choice.saveReason.isEmpty()&&choice.result.current(System.currentTimeMillis()))savable=true;
        StringBuilder text=new StringBuilder(failure==null?(choices.isEmpty()?"Temporary VPN stopped. No complete current candidate scores are available.":savable?"Temporary VPN stopped. Complete proposals are ready to save.":"Temporary VPN stopped. Candidate measurements are available. Each row gives its Save reason."):"Candidate results unavailable: "+failure.getMessage());
        text.append("\n\nPacket prefixes measure TCP handshakes. Qualified Shadowsocks prefixes measure authenticated responses from the paired candidate. Each score requires 50 successful samples. Load and Connect remain separate choices.");
        appendMeasuredRows(text,choices);output.setText(text.toString());changed.run();
    });}
    private static void appendMeasuredRows(StringBuilder text,List<AndroidNodeCandidatePreparation.Choice> rows){
        for(var choice:rows){
            text.append(String.format(Locale.US,"\n%s • %.2f ms (50/50, trimmed mean)",choice.result.name,choice.result.score));
            if(!choice.saveReason.isEmpty())text.append("\nSave unavailable: ").append(choice.saveReason);
            if(!choice.draftReason().isEmpty())text.append("\nCannot insert into this draft. ").append(choice.draftReason());
        }
    }
    private void chooseDraftInsertion() {
        if (!visible() || editor == null) return;
        List<AndroidNodeCandidatePreparation.Choice> available=new ArrayList<>();
        List<String> labels=new ArrayList<>();
        for (var choice : choices) {
            if (choice.draftInsertion() == null || !choice.result.current(System.currentTimeMillis())) continue;
            available.add(choice);
            labels.add(String.format(Locale.US,"%s • %.2f ms",choice.result.name,choice.result.score));
        }
        if (available.isEmpty()) {
            StringBuilder detail=new StringBuilder("A fresh, complete insertion is required to update this draft.");
            appendMeasuredRows(detail,choices);output.setText(detail.toString());return;
        }
        proposalDialog=new AlertDialog.Builder(activity).setTitle("Insert after measured hop").setItems(labels.toArray(new CharSequence[0]),(d,w)->{
            if (!visible()) return;
            try {
                AndroidNodeCandidatePreparation original=capturedOwner();
                if(original==null)throw new IllegalStateException("This candidate review has closed.");
                AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(activity);
                int inserted=available.get(w).draftInsertion().useInDraft(editor);
                long revision=editor.revision();
                WeakReference<AndroidNodeCandidatePreparationDialog> screen=new WeakReference<>(this);
                if(!original.finishDraftReview(notice,()->{
                    AndroidNodeCandidatePreparationDialog attached=screen.get();
                    if(attached!=null)attached.activity.runOnUiThread(()->attached.continueReleasedDraft(home,revision,inserted));
                }))throw new IllegalStateException("The previous review changed. Reopen the current draft.");
                choices=Collections.emptyList();
                waitingForReviewRelease=true;
                output.setText("Added the measured hop. Waiting for the previous review to close.");
            } catch (Exception stale) { update("Cannot insert into this draft. "+stale.getMessage()); }
        }).setNegativeButton("Back",null).show();
    }
    private void continueReleasedDraft(AndroidHomeStateStore.Snapshot home,long revision,int inserted) {
        if(!visible())return;
        waitingForReviewRelease=false;
        if(editor==null || editor.revision()!=revision || !connection.pathCurrent(home) ||
                connection.isActiveOrTransitioning() || AndroidNodeCandidatePreparation.retained()!=null){
            update("The editor or connection changed. Reopen the current draft to measure its next hop.");
            return;
        }
        detach();
        changed.run();
        continueDraft.accept(editor,inserted);
    }

    private void chooseProfile(){
        if(!visible())return;
        List<AndroidNodeCandidatePreparation.Choice> available=new ArrayList<>();List<String> labels=new ArrayList<>();
        boolean measured=false;
        for(var choice:choices)if(choice.result.current(System.currentTimeMillis())){
            measured=true;
            if(choice.profile!=null&&choice.saveReason.isEmpty()){available.add(choice);labels.add(choice.result.name+String.format(Locale.US," • %.2f ms",choice.result.score));}
        }
        if(available.isEmpty()){
            StringBuilder detail=new StringBuilder(measured?"These candidate measurements have no supported complete profile proposal.":"Wait for testing and temporary VPN cleanup to finish. Expired or invalid results require a new test.");
            if(measured)appendMeasuredRows(detail,choices);
            output.setText(detail.toString());return;
        }
        proposalDialog=new AlertDialog.Builder(activity).setTitle("Save as profile").setItems(labels.toArray(new CharSequence[0]),(d,w)->{
            var selected=available.get(w);EditText name=new EditText(activity);name.setHint("Profile name");
            proposalDialog=new AlertDialog.Builder(activity).setTitle("Save as profile").setMessage(selected.profile.description+"\n\nThis saves choices only. Use Connection profiles → Load, then Connect to prove this new path.").setView(name).setNegativeButton("Cancel",null).setPositiveButton("Save",(confirm,which)->{
                String chosen=name.getText().toString();
                new Thread(()->{try{var saved=selected.profile.save(activity,chosen);update("Saved "+saved.name+". Load and Connect remain separate choices.");}catch(Exception failure){update("Profile was not saved: "+failure.getMessage());}},"save-prepared-candidate-profile").start();
            }).show();
        }).setNegativeButton("Cancel",null).show();
    }
    private boolean visible(){return !detached&&!activity.isFinishing()&&!activity.isDestroyed()&&dialog!=null&&dialog.isShowing();}
    private void showMessage(String message){dialog=new AlertDialog.Builder(activity).setTitle("Test candidates").setMessage(message).setPositiveButton("Close",null).show();}
    void cancel(){if(detached)return;AndroidNodeCandidatePreparation captured=owner==null?capturedOwner():owner;if(captured!=null)connection.cancelCandidatePermission(captured);connection.cancelPending(permission);if(captured!=null)captured.cancelFromUser();detach();changed.run();}
    void detach(){if(detached)return;detached=true;AndroidNodeCandidatePreparation captured=owner==null?capturedOwner():owner;if(captured!=null)captured.detach(notice);if(proposalDialog!=null&&proposalDialog.isShowing())proposalDialog.dismiss();if(dialog!=null&&dialog.isShowing())dialog.dismiss();}
}
