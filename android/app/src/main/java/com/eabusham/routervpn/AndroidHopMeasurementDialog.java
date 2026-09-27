package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Handler;
import android.os.Looper;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.Locale;
import java.util.UUID;

/** Bounded readout from the retained native VPN engine, never a Java WAN probe. */
final class AndroidHopMeasurementDialog {
    private final Activity activity;
    private final AndroidUnifiedConnectionController connection;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private String id="";
    private long deadline;
    private boolean active;
    private AlertDialog dialog;
    private TextView output;
    AndroidHopMeasurementDialog(Activity activity,AndroidUnifiedConnectionController connection){this.activity=activity;this.connection=connection;}
    void show(){
        if(!connection.isConnected())return;
        id=UUID.randomUUID().toString().replace("-","");deadline=android.os.SystemClock.elapsedRealtime()+100000;active=true;
        output=new TextView(activity);output.setPadding(32,24,32,24);output.setTextIsSelectable(true);
        output.setText("Measuring device → entry and device → entry → exit independently. These are cumulative path rates, not inferred inter-server link speeds. Up to 32 MiB will be transferred; node credentials stay inside the native VPN service.");
        ScrollView scroll=new ScrollView(activity);scroll.addView(output);
        dialog=new AlertDialog.Builder(activity).setTitle("Routed hop measurements").setView(scroll).setNegativeButton("Close / cancel",(d,w)->close()).create();
        dialog.setOnDismissListener(d->close());dialog.show();
        try{LayeredVpnService.hopMeasurementRequest("start",id);handler.post(poll);}catch(Exception failure){output.setText("No proved native multihop measurement path is available.");closeRequest();}
    }
    private final Runnable poll=new Runnable(){public void run(){
        if(!active||dialog==null||!dialog.isShowing())return;
        if(!connection.isConnected()||android.os.SystemClock.elapsedRealtime()>deadline){discard();return;}
        try{
            JSONObject status=new JSONObject(LayeredVpnService.hopMeasurementRequest("status",id));
            if(!id.equals(status.optString("request_id"))){discard();return;}
            JSONArray rows=status.optJSONArray("results");if(rows==null||rows.length()>2){discard();return;}
            StringBuilder text=new StringBuilder("Routed hops: ").append(status.optString("stage","pending"));
            for(int i=0;i<rows.length();i++)text.append("\n\n").append(render(rows.getJSONObject(i)));
            if(!status.optString("failure").isEmpty())text.append("\n").append(status.optString("failure"));
            output.setText(text);
            if(status.optBoolean("complete")){active=false;return;}
            handler.postDelayed(this,350);
        }catch(Exception failure){discard();}
    }};
    private static String render(JSONObject row)throws Exception{
        String label=row.optString("role")+" • "+row.optString("node_id");
        if(!row.optBoolean("ready"))return label+": unavailable — "+row.optString("failure","unverified result");
        JSONObject idle=row.getJSONObject("idle"),down=row.getJSONObject("download"),up=row.getJSONObject("upload");
        if(!latency(idle)||!transfer(down)||!transfer(up))return label+": unavailable — invalid measurement";
        String text=String.format(Locale.US,"%s\nIdle %.1f ms • median %.1f • p90 %.1f • jitter %.1f\nDownload %.2f Mbps • Upload %.2f Mbps",label,idle.getDouble("average_ms"),idle.getDouble("median_ms"),idle.getDouble("p90_ms"),idle.getDouble("jitter_ms"),down.getDouble("mbps"),up.getDouble("mbps"));
        JSONObject[] values={down,up};String[] names={"Download","Upload"};
        for(int i=0;i<values.length;i++){JSONObject loaded=values[i].optJSONObject("loaded");double delta=values[i].optDouble("bufferbloat_ms",Double.NaN);
            if(loaded!=null&&latency(loaded)&&Double.isFinite(delta))text+=String.format(Locale.US,"\n%s loaded %.1f ms • Δ %.1f (%d samples)",names[i],loaded.getDouble("average_ms"),delta,loaded.getInt("samples"));
            else text+="\n"+names[i]+" loaded latency: unavailable — "+values[i].optString("loaded_reason","no complete samples");
        }return text;
    }
    private static boolean latency(JSONObject value){int count=value.optInt("samples");if(count<1||count>24)return false;for(String key:new String[]{"min_ms","median_ms","average_ms","p90_ms","max_ms","jitter_ms"}){double n=value.optDouble(key,Double.NaN);if(!Double.isFinite(n)||n<0)return false;}return true;}
    private static boolean transfer(JSONObject value){long bytes=value.optLong("bytes");double seconds=value.optDouble("seconds",Double.NaN),rate=value.optDouble("mbps",Double.NaN);return bytes>=65536&&bytes<=8388608&&Double.isFinite(seconds)&&seconds>0&&Double.isFinite(rate)&&rate>0&&Math.abs(bytes*8.0/seconds/1000000.0-rate)<=Math.max(0.000001,rate*0.000001);}
    private void discard(){closeRequest();output.setText("Measurement discarded: its request failed, timed out, or the native tunnel changed.");}
    private void closeRequest(){active=false;handler.removeCallbacks(poll);try{LayeredVpnService.hopMeasurementRequest("cancel",id);}catch(Exception ignored){} }
    void close(){closeRequest();}
}
