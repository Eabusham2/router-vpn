package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;

/** No host network probe and no persistent DNS policy mutation. */
final class AndroidDNSMeasurementDialog {
    interface Selection { void selected(AndroidNativeDNSMeasurement measurement,String rowID)throws Exception; }
    private final Activity activity;
    private final String nodeID;
    private final Selection selection;
    private final AndroidNativeDNSMeasurement measurement=new AndroidNativeDNSMeasurement();
    private AlertDialog dialog;
    private TextView output;
    private Spinner transport;
    private Button retest,cancel,fastest,choose;
    private boolean closed;
    AndroidDNSMeasurementDialog(Activity activity,String nodeID,Selection selection){this.activity=activity;this.nodeID=nodeID;this.selection=selection;}
    void show(){
        LinearLayout body=new LinearLayout(activity);body.setOrientation(LinearLayout.VERTICAL);body.setPadding(28,20,28,20);
        TextView explanation=new TextView(activity);explanation.setText("Compare resolvers through this proved external connection. Public tests use TCP, DoT or DoH; the Selected DNS row keeps its actual transport and route, including Home AdGuard through the captured entry. Each public time includes connection setup and a complete DNS answer. Results expire after two minutes. A measured public resolver can become an exact DNS draft for the next connection: Disconnect, review the fields, then Save.");body.addView(explanation);
        transport=new Spinner(activity);transport.setAdapter(new ArrayAdapter<>(activity,android.R.layout.simple_spinner_dropdown_item,new String[]{"TCP DNS","DoT · verified TLS","DoH · verified HTTPS"}));transport.setSelection(2);body.addView(transport);
        retest=new Button(activity);retest.setText("Measure DNS");retest.setOnClickListener(v->start());body.addView(retest);
        cancel=new Button(activity);cancel.setText("Cancel measurement");cancel.setEnabled(false);cancel.setOnClickListener(v->{measurement.cancel();output.setText("Cancelling; waiting for the captured queries and sockets to drain…");});body.addView(cancel);
        output=new TextView(activity);output.setTextIsSelectable(true);output.setText("Choose a transport, then Measure DNS. Unreachable or policy-filtered resolvers stay unavailable.");body.addView(output);
        fastest=new Button(activity);fastest.setText("Use fastest measured public DNS next time");fastest.setEnabled(false);fastest.setOnClickListener(v->use(null));body.addView(fastest);
        choose=new Button(activity);choose.setText("Choose measured public resolver…");choose.setEnabled(false);choose.setOnClickListener(v->choose());body.addView(choose);
        ScrollView scroll=new ScrollView(activity);scroll.addView(body);
        dialog=new AlertDialog.Builder(activity).setTitle("DNS on the current external path").setView(scroll).setNegativeButton("Close",(d,w)->close()).create();
        dialog.setOnDismissListener(d->close());dialog.show();
    }
    private void start(){
        if(closed||measurement.isRunning())return;
        retest.setEnabled(false);cancel.setEnabled(true);transport.setEnabled(false);fastest.setEnabled(false);choose.setEnabled(false);
        String chosen=new String[]{"tcp","tls","https"}[transport.getSelectedItemPosition()];
        output.setText("Measuring 3 DNS answers per resolver through the captured native path… MTU remains paused until cleanup completes.");
        measurement.run(nodeID,chosen,new AndroidNativeDNSMeasurement.Callback(){
            public void progress(String stage){activity.runOnUiThread(()->{if(!visible())return;output.setText("draining".equals(stage)?"Waiting for native DNS workers and sockets to drain; MTU remains paused.":"Measuring the selected DNS route and public "+AndroidDNSMeasurementReceipt.transportName(chosen)+" resolvers…");});}
            public void finished(String result,Throwable error){activity.runOnUiThread(()->{
                if(!visible())return;retest.setText("Retest DNS");retest.setEnabled(true);cancel.setEnabled(false);transport.setEnabled(true);
                if(error!=null){output.setText("DNS comparison was cancelled or could not start or complete on the captured path. "+message(error));return;}
                try{JSONObject receipt=measurement.currentReceipt();output.setText(AndroidDNSMeasurementReceipt.render(receipt));
                    try{AndroidDNSMeasurementReceipt.publicChoice(receipt,null);fastest.setEnabled(selection!=null);choose.setEnabled(selection!=null);}catch(Exception unavailable){}
                }catch(Exception invalid){output.setText("Invalid or stale native DNS result discarded. Retest on the current connection.");}
            });}
        });
    }
    private void choose(){
        try{
            JSONObject receipt=measurement.currentReceipt();JSONArray rows=receipt.getJSONArray("results");List<String> ids=new ArrayList<>(),labels=new ArrayList<>();
            for(int i=1;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);if(!row.getBoolean("ready"))continue;
                ids.add(row.getString("id"));labels.add(row.getString("name")+" · "+AndroidDNSMeasurementReceipt.transportName(row.getString("transport"))+" · "+row.getString("address")+String.format(java.util.Locale.US," · %.1f ms",row.getDouble("median_ms")));}
            if(ids.isEmpty())throw new IllegalStateException("No complete public resolver result is available.");
            new AlertDialog.Builder(activity).setTitle("Measured DNS for the next connection").setItems(labels.toArray(new String[0]),(d,w)->use(ids.get(w))).setNegativeButton("Cancel",null).show();
        }catch(Exception stale){discard(stale);}
    }
    private void use(String rowID){
        if(!visible()||measurement.isRunning()||selection==null)return;
        try{JSONObject selected=AndroidDNSMeasurementReceipt.publicChoice(measurement.currentReceipt(),rowID);selection.selected(measurement,selected.getString("id"));}
        catch(Exception stale){discard(stale);}
    }
    private void discard(Throwable error){fastest.setEnabled(false);choose.setEnabled(false);output.setText("This DNS choice is no longer available. Retest on the current connection. "+message(error));}
    private boolean visible(){return !closed&&dialog!=null&&dialog.isShowing()&&!activity.isFinishing();}
    private static String message(Throwable error){String message=error.getMessage();return message==null?"":message;}
    void close(){closed=true;measurement.cancel();if(dialog!=null&&dialog.isShowing())dialog.dismiss();}
}
