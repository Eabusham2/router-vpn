package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.widget.ScrollView;
import android.widget.TextView;

/** Explicit ordered-prefix metric, separate from direct TCP and external-final rankings. */
final class AndroidOrderedLatencyDialog {
    private final Activity activity;
    private final AndroidOrderedLatencyBenchmark benchmark=new AndroidOrderedLatencyBenchmark();
    private AlertDialog dialog;
    private TextView output;
    private LayeredVpnService.OrderedLatencyTarget target;
    private boolean closed;
    private long generation;
    AndroidOrderedLatencyDialog(Activity activity){this.activity=activity;}
    void show(){
        try{
            java.util.List<LayeredVpnService.OrderedLatencyTarget> targets=LayeredVpnService.orderedLatencyTargets();
            String[] labels=new String[targets.size()];for(int i=0;i<labels.length;i++)labels[i]=targets.get(i).label;
            dialog=new AlertDialog.Builder(activity).setTitle("Ordered path • select node for Fifty")
                    .setItems(labels,(d,w)->{if(!closed){target=targets.get(w);showTarget();}})
                    .setNegativeButton("Close",(d,w)->close()).create();
            dialog.setOnCancelListener(d->close());dialog.show();
        }catch(Exception error){dialog=new AlertDialog.Builder(activity).setTitle("Ordered fifty-response benchmark")
                .setMessage("Connect an ordered SOCKS or HTTP(S) CONNECT path and wait for connection checks or MTU adjustments to finish, then try again.\n\nNo test was started.")
                .setNegativeButton("Close",(d,w)->close()).create();dialog.setOnDismissListener(d->close());dialog.show();}
    }
    private void showTarget(){
        output=new TextView(activity);output.setPadding(32,24,32,24);output.setTextIsSelectable(true);
        ScrollView scroll=new ScrollView(activity);scroll.addView(output);
        dialog=new AlertDialog.Builder(activity).setTitle(target.label).setView(scroll)
                .setPositiveButton("Fifty / Retest",null).setNeutralButton("Saved history",null)
                .setNegativeButton("Close / cancel",(d,w)->close()).create();
        dialog.setOnDismissListener(d->close());dialog.show();
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->start());
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v->history());history();
    }
    private String meaning(){return "public-path".equals(target.kind)
            ?"50 public HTTPS responses through this ordered prefix. Timing starts after DNS, TCP and TLS preparation."
            :"50 authenticated private Router HTTP responses through this ordered prefix. Timing includes connection establishment.";}
    private void history(){
        if(closed||benchmark.isRunning())return;
        try{AndroidOrderedLatencyStore.Record record=AndroidOrderedLatencyStore.load(activity,target.source,target.config,target.position,target.node,target.kind);
            output.setText(target.label+"\n\n"+meaning()+"\n\n"+(record==null?"No saved result for this node on this path. Press Fifty / Retest to measure.":record.detail()));
        }catch(Exception invalid){output.setText("The saved result could not be read. Press Fifty / Retest for a new measurement.");}
    }
    private void start(){
        if(closed||benchmark.isRunning())return;
        final long delivery=++generation;
        buttons(false);output.setText(meaning()+"\n\nWaiting for any MTU adjustment to finish, then testing 50 responses. Cancel keeps your previous saved result.");
        benchmark.run(target,new AndroidOrderedLatencyBenchmark.Callback(){
            public void progress(LayeredVpnService.OrderedLatencyOwner owner,String stage){activity.runOnUiThread(()->{
                if(closed||delivery!=generation)return;
                try{owner.requireDelivery();output.setText(meaning()+"\n\n"+progressText(stage)+"\n\nYour result is saved only after all 50 responses and the test has fully finished. These responses are not ICMP ping or inter-server link speed.");}
                catch(Exception stale){benchmark.cancel();output.setText("The captured path changed. Stopping this test; your previous saved result is unchanged.");}
            });}
            public void finished(LayeredVpnService.OrderedLatencyOwner owner,AndroidOrderedLatencyStore.Record record,Throwable error){activity.runOnUiThread(()->{
                if(closed||delivery!=generation)return;buttons(true);
                try{if(error!=null||record==null)throw new IllegalStateException("No complete receipt.");owner.requireDelivery();output.setText(target.label+"\n\n"+record.detail()+"\n\nTest finished. Result saved.");}
                catch(Exception stale){output.setText("This test could not provide a current result. Your saved history is still available. Wait for connection or MTU adjustments to finish, then try Retest.");}
            });}
        });
    }
    private static String progressText(String stage){
        if(stage.matches("node [1-8]: response ([1-9]|[1-4][0-9]|50)/50"))return "Measuring response "+stage.substring(stage.indexOf("response ")+9).replace("/50"," of 50")+"…";
        return "Finishing the test… MTU adjustments remain paused.";
    }
    private void buttons(boolean enabled){dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(enabled);dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setEnabled(enabled);}
    void close(){if(closed)return;closed=true;generation++;benchmark.cancel();if(dialog!=null&&dialog.isShowing())dialog.dismiss();}
}
