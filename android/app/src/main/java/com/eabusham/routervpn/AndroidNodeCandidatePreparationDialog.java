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
    private AndroidNodeCandidatePreparation owner;
    private AlertDialog dialog,proposalDialog;
    private TextView output;
    private List<AndroidNodeCandidatePreparation.Choice> choices=Collections.emptyList();

    private static final class Notice implements AndroidNodeCandidatePreparation.Callback {
        final WeakReference<AndroidNodeCandidatePreparationDialog> screen;
        Notice(AndroidNodeCandidatePreparationDialog screen){this.screen=new WeakReference<>(screen);}
        private AndroidNodeCandidatePreparationDialog attached(){AndroidNodeCandidatePreparationDialog value=screen.get();if(value!=null&&!value.detached)return value;AndroidNodeCandidatePreparation retained=AndroidNodeCandidatePreparation.retained();if(retained!=null)retained.detach(this);return null;}
        public void progress(String detail){AndroidNodeCandidatePreparationDialog value=attached();if(value!=null)value.update(detail);}
        public void finished(List<AndroidNodeCandidatePreparation.Choice> choices,Throwable failure){AndroidNodeCandidatePreparationDialog value=attached();if(value!=null)value.completed(choices,failure);}
    }
    AndroidNodeCandidatePreparationDialog(Activity activity,AndroidNodeStore nodes,AndroidUnifiedConnectionController connection,Runnable changed){
        this.activity=activity;this.nodes=nodes;this.connection=connection;this.changed=changed;notice=new Notice(this);
        permission=new AndroidUnifiedConnectionController.Callback(){public void progress(String detail){update(detail);}public void finished(boolean ok,String detail){update(detail);}};
    }
    void show(){
        owner=AndroidNodeCandidatePreparation.retained();
        if(owner!=null){showProgress();owner.attach(notice);return;}
        final AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(activity);final String selected;
        try{if(connection.isActiveOrTransitioning()||home.connected)throw new IllegalStateException("Stop the current VPN before testing the saved ordered path.");selected=AndroidConnectionSelection.digest(activity,nodes);}
        catch(Exception failure){showMessage(failure.getMessage());return;}
        showProgress();output.setText("Reading the saved Local path… A WireGuard or AmneziaWG prefix can be tested without later nodes. Other selections require the complete saved path. Each candidate needs 50 successful TCP connections; results appear after the temporary VPN stops.");
        new Thread(()->{
            try{
                AndroidNodeStore.ChainCapture source=new AndroidConnectionProfileStore(activity,nodes,new AndroidStandardExitStore(activity)).currentOrderedPath();source.requireCurrent();
                List<Integer> positions=new ArrayList<>();List<String> names=new ArrayList<>();
                if(!"local".equals(source.execution))throw new IllegalStateException("Choose Local execution for this saved path before testing candidates.");
                for(int i=0;i<source.modes.size();i++){String mode=source.modes.get(i);if("wg".equals(mode)||"awg2-fast".equals(mode)||"awg2-strong".equals(mode)){positions.add(i);names.add("Through node "+(i+1)+" • "+mode+" • "+(AndroidNodeCandidatePreparation.packetPrefix(source,i)?"prefix only":"complete saved path"));}}
                if(positions.isEmpty())throw new IllegalStateException("The saved path has no WireGuard or AmneziaWG prefix for candidate TCP timing.");
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
        Button save=new Button(activity);save.setText("Save as profile");save.setOnClickListener(v->chooseProfile());body.addView(save);
        ScrollView scroll=new ScrollView(activity);scroll.addView(body);
        dialog=new AlertDialog.Builder(activity).setTitle("Test candidates").setView(scroll).setNegativeButton("Cancel / Close",(d,w)->cancel()).create();
        dialog.setOnDismissListener(d->{if(!detached)cancel();});dialog.show();
    }
    private AndroidNodeCandidatePreparation capturedOwner(){AndroidNodeCandidatePreparation current=AndroidNodeCandidatePreparation.retained();return current!=null&&current.observes(notice)?current:null;}
    private void update(String detail){activity.runOnUiThread(()->{if(!visible())return;if(owner==null)owner=capturedOwner();output.setText(detail);changed.run();});}
    private void completed(List<AndroidNodeCandidatePreparation.Choice> completed,Throwable failure){activity.runOnUiThread(()->{
        if(!visible())return;if(owner==null)owner=capturedOwner();choices=Collections.unmodifiableList(new ArrayList<>(completed));
        StringBuilder text=new StringBuilder(failure==null?(choices.isEmpty()?"Temporary VPN stopped. No complete current candidate scores are available.":"Temporary VPN stopped. Choose Save as profile to keep a tested path."):"Candidate results unavailable: "+failure.getMessage());
        text.append("\n\nTCP handshake timing only; not HTTP, ICMP or authenticated server proof. Each score requires 50 successful samples. Load and Connect remain separate choices.");
        for(var choice:choices)text.append(String.format(Locale.US,"\n%s • %.2f ms (50/50, trimmed mean)",choice.result.name,choice.result.score));
        output.setText(text.toString());changed.run();
    });}
    private void chooseProfile(){
        if(!visible())return;
        List<AndroidNodeCandidatePreparation.Choice> available=new ArrayList<>();List<String> labels=new ArrayList<>();
        for(var choice:choices)if(choice.result.current(System.currentTimeMillis())){available.add(choice);labels.add(choice.result.name+String.format(Locale.US," • %.2f ms",choice.result.score));}
        if(available.isEmpty()){output.setText("Wait for testing and temporary VPN cleanup to finish. Expired or invalid results require a new test.");return;}
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
