package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import java.util.ArrayList;
import java.util.List;

/** Daily native entry points for one-context external comparison and adoption. */
final class AndroidExternalComparisonDialog {
    private final Activity activity;
    private final AndroidNodeStore nodes;
    private final AndroidStandardExitStore exits;
    private final AndroidUnifiedConnectionController connection;
    private final AndroidExternalNodeComparison comparison;
    private final Runnable refresh;
    private AlertDialog progress;
    private boolean closed;
    AndroidExternalComparisonDialog(Activity activity,AndroidNodeStore nodes,AndroidStandardExitStore exits,AndroidUnifiedConnectionController connection,Runnable refresh){this.activity=activity;this.nodes=nodes;this.exits=exits;this.connection=connection;this.refresh=refresh;comparison=new AndroidExternalNodeComparison(activity,nodes,connection);}
    void show(boolean connectFastest){
        if(AndroidExternalNodeComparison.hasActiveOperation()||AndroidMTUMeasurementGate.held()){
            new AlertDialog.Builder(activity).setTitle("External path comparison").setMessage("Finish or cancel the current measurement before another comparison.").setNegativeButton("Close",null).show();return;
        }
        final List<AndroidExternalNodeComparison.PathContext> contexts=new ArrayList<>();
        final List<String> labels=new ArrayList<>();contexts.add(AndroidExternalNodeComparison.PathContext.direct());labels.add("Direct external paths");
        String unavailable="";
        try{
            android.content.SharedPreferences preferences=activity.getSharedPreferences("router-vpn-unified",Activity.MODE_PRIVATE);
            if("external".equals(preferences.getString("selected_kind",""))){
                AndroidConnectionProfileStore.ExternalSelection saved=new AndroidConnectionProfileStore(activity,nodes,exits).currentExternalPath(preferences.getString("selected_id",""));
                if(!saved.direct()){AndroidExternalNodeComparison.PathContext context=AndroidExternalNodeComparison.PathContext.saved(saved);contexts.add(context);labels.add("Saved entry: "+context.detail());}
            }
        }catch(Exception error){unavailable="\nThe saved entry could not be captured: "+message(error);}
        android.widget.LinearLayout header=new android.widget.LinearLayout(activity);header.setOrientation(android.widget.LinearLayout.VERTICAL);header.setPadding(24,18,24,8);
        android.widget.TextView title=new android.widget.TextView(activity);title.setText(connectFastest?"Compare and connect fastest external path":"Compare all external exits");title.setTextSize(18);header.addView(title);
        android.widget.TextView description=new android.widget.TextView(activity);description.setText("Choose one entry context for the complete round. Each eligible exit must prove its path and complete 50 routed HTTPS responses. Lowest 10% trimmed mean wins; failed paths receive no score. Trials restore the original connection. Cancel waits for native cleanup."+(connectFastest?" The winner then reconnects with its measured Local/Server choice and fresh proof.":"")+unavailable);description.setTextSize(12);header.addView(description);
        new AlertDialog.Builder(activity).setCustomTitle(header)
                .setItems(labels.toArray(new String[0]),(dialog,which)->run(contexts.get(which),connectFastest)).setNegativeButton("Cancel",null).show();
    }
    private void run(AndroidExternalNodeComparison.PathContext context,boolean connectFastest){
        if(closed||activity.isFinishing()||activity.isDestroyed())return;
        progress=new AlertDialog.Builder(activity).setTitle(connectFastest?"Find and connect fastest external path":"Compare external paths")
                .setMessage("Capturing saved sources, original connection and physical network…").setCancelable(false).setNegativeButton("Cancel comparison",null).create();
        final AlertDialog owned=progress;owned.show();owned.getButton(AlertDialog.BUTTON_NEGATIVE).setOnClickListener(view->comparison.cancel());
        owned.setOnDismissListener(dialog->{if(progress==owned)comparison.cancel();});
        comparison.run(context,connectFastest,new AndroidExternalNodeComparison.Callback(){
            public void progress(String message){activity.runOnUiThread(()->{if(!closed&&progress==owned&&!activity.isFinishing()&&!activity.isDestroyed())owned.setMessage(message);});}
            public void finished(AndroidExternalNodeComparison.Result result,Throwable error){activity.runOnUiThread(()->{
                if(progress==owned){progress=null;owned.dismiss();}
                if(closed||activity.isFinishing()||activity.isDestroyed())return;
                refresh.run();
                new AlertDialog.Builder(activity).setTitle(result!=null&&result.adopted?"Fastest external path connected":error==null?"External path comparison complete":"External comparison stopped")
                        .setMessage(result!=null?result.detail()+(error==null?"":"\n\nCleanup or automatic MTU warning: "+message(error)):message(error)+"\nNo fastest result from this interrupted round was adopted. Check the current connection status before retrying.")
                        .setPositiveButton("Retest",(dialog,which)->run(context,connectFastest)).setNegativeButton("Close",null).show();
            });}
        });
    }
    void close(){closed=true;comparison.cancel();AlertDialog owned=progress;progress=null;if(owned!=null)owned.dismiss();}
    private static String message(Throwable error){if(error==null)return "The comparison did not produce a valid result.";String value=error.getMessage();return value==null||value.isEmpty()?error.getClass().getSimpleName():value;}
}
