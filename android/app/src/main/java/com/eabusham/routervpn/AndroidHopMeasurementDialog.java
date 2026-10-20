package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.Locale;

/** Bounded readout from the retained native VPN engine, never a Java WAN probe. */
final class AndroidHopMeasurementDialog {
    private final Activity activity;
    private final AndroidUnifiedConnectionController connection;
    private final AndroidNativeHopMeasurement measurement=new AndroidNativeHopMeasurement();
    private AlertDialog dialog;
    private TextView output;
    AndroidHopMeasurementDialog(Activity activity,AndroidUnifiedConnectionController connection){this.activity=activity;this.connection=connection;}
    void show(){
        if(!connection.isConnected())return;
        output=new TextView(activity);output.setPadding(32,24,32,24);output.setTextIsSelectable(true);
        output.setText("Measuring the captured VPN paths. Private Router VPN nodes use their authenticated API; imported and Tor exits use HTTPS through the captured route. Rates describe cumulative paths, not inferred inter-server link speeds. Up to 32 MiB will be transferred. MTU stays paused until native cleanup finishes.");
        ScrollView scroll=new ScrollView(activity);scroll.addView(output);
        dialog=new AlertDialog.Builder(activity).setTitle("Routed path measurements").setView(scroll).setNegativeButton("Close / cancel",(d,w)->close()).create();
        dialog.setOnDismissListener(d->close());dialog.show();
        measurement.run(null,new AndroidNativeHopMeasurement.Callback(){
            public void progress(String status){activity.runOnUiThread(()->{if(dialog==null||!dialog.isShowing())return;try{output.setText(renderStatus(status));}catch(Exception invalid){measurement.cancel();output.setText("Invalid measurement discarded; waiting for native cleanup.");}});}
            public void finished(String status,Throwable error){activity.runOnUiThread(()->{if(dialog==null||!dialog.isShowing())return;if(error!=null){output.setText("Measurement discarded or cancelled. Its captured native work has drained.");return;}try{output.setText(renderStatus(status));}catch(Exception invalid){output.setText("Invalid native measurement discarded.");}});}
        });
    }
    static String renderStatus(String raw)throws Exception{
        if(raw==null||raw.length()>16384)throw new IllegalArgumentException("Oversized measurement status.");
        JSONObject status=new JSONObject(raw);JSONArray rows=status.getJSONArray("results");if(rows.length()>2)throw new IllegalArgumentException("Too many measured paths.");
        StringBuilder text=new StringBuilder("Routed paths: ").append(status.optString("stage","pending"));
        for(int i=0;i<rows.length();i++)text.append("\n\n").append(render(rows.getJSONObject(i)));
        if(!status.optString("failure").isEmpty())text.append("\n").append(status.optString("failure"));
        return text.toString();
    }
    private static String render(JSONObject row)throws Exception{
        String kind=row.optString("kind"),name=row.optString("label"),role=row.optString("role");
        if(!("private-node".equals(kind)||"public-path".equals(kind))||!("entry".equals(role)||"exit".equals(role))||name.isEmpty()||name.length()>160||name.matches("(?s).*[\\x00-\\x1f\\x7f].*"))return "Path unavailable — invalid measurement identity";
        String label=("public-path".equals(kind)?"Public routed path • ":"Private node • ")+name;
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
    void close(){measurement.cancel();}
}
