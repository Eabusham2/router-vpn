package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.widget.ScrollView;
import android.widget.TextView;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** A connected-path measurement chooser; it never changes the saved route. */
final class AndroidNodeCandidateDialog {
    private final Activity activity;
    private volatile boolean closed;
    private volatile AndroidNodeCandidateMeasurement operation;
    private AlertDialog dialog;
    private TextView output;
    AndroidNodeCandidateDialog(Activity activity){this.activity=activity;}
    void show(){
        AndroidNodeChainSession session=AndroidNodeChainSession.retained();
        if(session==null){message("Connect an ordered Router path first. Candidate TCP timing uses its retained original prefix.");return;}
        List<Integer> positions=new ArrayList<>();List<String> names=new ArrayList<>();
        for(int i=0;i<session.source.modes.size();i++){
            String mode=session.source.modes.get(i);
            if("wg".equals(mode)||"awg2-fast".equals(mode)||"awg2-strong".equals(mode)){positions.add(i);names.add("Through node "+(i+1)+" • "+mode);}
        }
        if(positions.isEmpty()){message("This path has no retained packet prefix capable of timing destination TCP connections. No score is available.");return;}
        dialog=new AlertDialog.Builder(activity).setTitle("Candidate TCP connection times")
                .setItems(names.toArray(new CharSequence[0]),(d,w)->capture(session,positions.get(w)))
                .setNegativeButton("Cancel",(d,w)->close()).show();
    }
    private void capture(AndroidNodeChainSession session,int prefix){
        output=new TextView(activity);output.setPadding(32,24,32,24);output.setTextIsSelectable(true);
        output.setText("Capturing original saved candidates and the current native prefix…");ScrollView scroll=new ScrollView(activity);scroll.addView(output);
        dialog=new AlertDialog.Builder(activity).setTitle("Candidate TCP connection times").setView(scroll).setNegativeButton("Close / cancel",(d,w)->close()).create();
        dialog.setOnDismissListener(d->close());dialog.show();
        new Thread(()->{
            try {
                AndroidNodeCandidateCatalog catalog=new AndroidNodeCandidateCatalog(activity,session,prefix);
                if(closed)return;
                operation=AndroidNodeCandidateMeasurement.start(catalog,new AndroidNodeCandidateMeasurement.Callback(){
                    public void changed(List<AndroidNodeCandidateResult> results,String detail){activity.runOnUiThread(()->{
                        if(!visible())return;
                        try {catalog.requireCurrent();StringBuilder text=new StringBuilder(detail).append("\n\nTCP handshake timing only; not HTTP, ICMP or authenticated server proof. The active route is unchanged. MTU remains paused until native cleanup finishes.\n");
                            for(AndroidNodeCandidateResult result:results)if(result.current(System.currentTimeMillis()))text.append(String.format(Locale.US,"\n%s • %.2f ms (50/50, trimmed mean)",result.name,result.score));
                            for(AndroidNodeCandidateCatalog.Row row:catalog.rows){boolean scored=false;for(AndroidNodeCandidateResult value:results)if(!row.input.isEmpty()&&value.id.equals(row.id)&&value.current(System.currentTimeMillis())){scored=true;break;}if(!scored)text.append("\n").append(row.name).append(" • no score").append(row.reason.isEmpty()?" (pending, failed or expired)":" — "+row.reason);}
                            output.setText(text.toString());
                        }catch(Exception changed){close();}
                    });}
                    public void finished(Throwable failure){activity.runOnUiThread(()->{if(visible())output.setText(failure==null?"No current complete candidate scores. Native cleanup completed.":"Candidate results discarded. Native cleanup completed.");});}
                });
                if(closed)operation.cancel();
            }catch(Exception failure){activity.runOnUiThread(()->{if(visible())output.setText("Candidate timing unavailable: "+failure.getMessage());});}
        },"capture-prefix-candidates").start();
    }
    private boolean visible(){return !closed&&!activity.isFinishing()&&!activity.isDestroyed()&&dialog!=null&&dialog.isShowing();}
    private void message(String text){dialog=new AlertDialog.Builder(activity).setTitle("Candidate TCP connection times").setMessage(text).setPositiveButton("Close",null).show();}
    void close(){if(closed)return;closed=true;AndroidNodeCandidateMeasurement current=operation;if(current!=null)current.cancel();if(dialog!=null&&dialog.isShowing())dialog.dismiss();}
}
