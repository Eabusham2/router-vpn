package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONObject;

/** Visible latency-only operation on the selected retained external VPN path. */
final class AndroidExternalBenchmarkDialog {
    private final Activity activity;
    private final AndroidExternalNodeBenchmark benchmark;
    private final String exitID;
    private AlertDialog dialog;
    private TextView output;
    private boolean closed;
    AndroidExternalBenchmarkDialog(Activity activity,String exitID){
        this.activity=activity;this.exitID=exitID;
        benchmark=new AndroidExternalNodeBenchmark(activity,AndroidRuntimeRegistry.get(activity).standardExit);
    }
    void show(){
        output=new TextView(activity);output.setPadding(32,24,32,24);output.setTextIsSelectable(true);
        ScrollView scroll=new ScrollView(activity);scroll.addView(output);
        dialog=new AlertDialog.Builder(activity).setTitle("External path • 50 HTTPS samples").setView(scroll)
                .setPositiveButton("Retest",null).setNegativeButton("Close / cancel",(d,w)->close()).create();
        dialog.setOnDismissListener(d->close());dialog.show();
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->start());start();
    }
    private void start(){
        if(closed||benchmark.isRunning())return;
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);
        output.setText("Measuring 50 HTTPS responses through this exact connected external path and its selected DNS policy. Each timer starts after DNS, TCP and TLS preparation. No upload or throughput test is started. MTU work stays paused until the original native workers drain. Cancelling keeps the previous saved benchmark.");
        benchmark.run(exitID,new AndroidExternalNodeBenchmark.Callback(){
            public void progress(String status){activity.runOnUiThread(()->{
                if(closed)return;
                try{JSONObject value=new JSONObject(status);output.setText("Routed HTTPS benchmark: "+value.optString("stage","pending")+"\n\nThe saved result changes only after all 50 samples, fresh path proof and complete native drain. Close / cancel keeps the previous complete result.");}
                catch(Exception invalid){benchmark.cancel();output.setText("Invalid measurement discarded; waiting for native cleanup.");}
            });}
            public void finished(AndroidExternalNodeStatistics.Record result,Throwable error){activity.runOnUiThread(()->{
                if(closed)return;dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(true);
                output.setText(error==null&&result!=null?result.detail():"No new benchmark was saved. The previous completed result is retained.\n\n"+(error==null?"No complete result.":safe(error)));
            });}
        });
    }
    private static String safe(Throwable error){String message=error.getMessage();return message==null||message.isEmpty()?"The captured path could not be measured.":message;}
    void close(){if(closed)return;closed=true;benchmark.cancel();if(dialog!=null&&dialog.isShowing())dialog.dismiss();}
}
