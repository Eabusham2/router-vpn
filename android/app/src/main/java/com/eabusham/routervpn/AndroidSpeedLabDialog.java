package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.SeekBar;
import android.widget.Spinner;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Full native Android control surface for AndroidSpeedLabController. */
final class AndroidSpeedLabDialog {
    private final Activity activity;
    private final AndroidNodeStore nodes;
    private final AndroidUnifiedConnectionController connection;
    private final AndroidSpeedLabController controller;
    private AlertDialog dialog;
    private Spinner scope,topology,node,entry,exit,standardExit,mode,exitMode,entryMode,execution,durationMode;
    private EditText layers;
    private CheckBox externalDirect;
    private SeekBar minTime,maxTime;
    private TextView minLabel,maxLabel,idle,download,upload,idleDetail,downloadDetail,uploadDetail,status,detail;
    private Button run,cancel;
    private List<AndroidNodeStore.Node> nodeValues=new ArrayList<>();
    private List<AndroidStandardExitStore.Entry> exitValues=new ArrayList<>();
    private List<AndroidStandardExitStore.Entry> ordinaryEntryValues=new ArrayList<>();
    private List<ModeOption> modeValues=new ArrayList<>();
    private AndroidConnectionProfileStore.ExternalSelection savedExternalSelection;
    private boolean restoringChoices;
    private String displayedExternalID="",displayedEntryID="";
    private int displayedTopology=-1;

    private static final class ModeOption { final String id,name; ModeOption(String id,String name){this.id=id;this.name=name;} @Override public String toString(){return name;} }

    AndroidSpeedLabDialog(Activity activity,AndroidNodeStore nodes,AndroidUnifiedConnectionController connection,AndroidSpeedLabController controller){this.activity=activity;this.nodes=nodes;this.connection=connection;this.controller=controller;}

    void show(){
        ScrollView scroll=new ScrollView(activity);LinearLayout root=new LinearLayout(activity);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(18),dp(12),dp(18),dp(12));root.setBackgroundColor(Color.rgb(8,16,30));scroll.addView(root);
        TextView eyebrow=text("SPEED LAB",12,true);eyebrow.setTextColor(Color.rgb(102,217,239));root.addView(eyebrow);TextView title=text("Router VPN path performance",26,true);root.addView(title);TextView sub=text("Real HTTPS throughput + idle, download-loaded and upload-loaded latency. Current path is default; Temporary tests a chosen path, then restores your original connection after fresh proof.",12,false);sub.setTextColor(Color.rgb(160,178,205));root.addView(sub);
        LinearLayout cards=row();cards.addView(metric("IDLE LATENCY",idle=text("-- ms",23,true),idleDetail=text("p90 / max / jitter",10,false)),weight());cards.addView(metric("DOWNLOAD",download=text("-- Mbps",23,true),downloadDetail=text("loaded -- ms",10,false)),weight());cards.addView(metric("UPLOAD",upload=text("-- Mbps",23,true),uploadDetail=text("loaded -- ms",10,false)),weight());root.addView(cards,margin(0,dp(12),0,0));

        scope=spinner(new String[]{"Current path","Temporary config"});topology=spinner(new String[]{"System direct","Router VPN node","Multihop","External exit / hop"});topology.setSelection(1);node=spinner(new String[]{});entry=spinner(new String[]{});exit=spinner(new String[]{});standardExit=spinner(new String[]{});mode=spinner(new String[]{});exitMode=spinner(new String[]{"Shadowsocks","Hysteria2"});entryMode=spinner(new String[]{});execution=spinner(new String[]{"Local","Server","Compare both"});durationMode=spinner(new String[]{"Auto timing","Custom timing"});layers=new EditText(activity);layers.setHint("CUSTOM layers, comma-separated");layers.setTextColor(Color.WHITE);layers.setHintTextColor(Color.rgb(120,140,170));externalDirect=new CheckBox(activity);externalDirect.setText("Direct external exit (off = saved entry → external exit)");externalDirect.setTextColor(Color.WHITE);externalDirect.setChecked(true);
        root.addView(field("Test",scope));root.addView(field("Topology",topology));root.addView(field("Node / exit",node));root.addView(field("Entry",entry));root.addView(field("Exit",exit));root.addView(field("Stored custom exit",standardExit));root.addView(field("Mode",mode));root.addView(field("Entry transport",entryMode));root.addView(field("Multihop exit transport",exitMode));root.addView(field("Execution",execution));root.addView(field("CUSTOM layers",layers));root.addView(externalDirect);

        LinearLayout timing=row();timing.addView(durationMode,new LinearLayout.LayoutParams(0,dp(48),.32f));minLabel=text("Min 4 s",11,true);maxLabel=text("Max 12 s",11,true);minTime=new SeekBar(activity);maxTime=new SeekBar(activity);minTime.setMax(59);maxTime.setMax(59);minTime.setProgress(3);maxTime.setProgress(11);LinearLayout minBox=new LinearLayout(activity);minBox.setOrientation(LinearLayout.VERTICAL);minBox.addView(minLabel);minBox.addView(minTime);LinearLayout maxBox=new LinearLayout(activity);maxBox.setOrientation(LinearLayout.VERTICAL);maxBox.addView(maxLabel);maxBox.addView(maxTime);timing.addView(minBox,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,.34f));timing.addView(maxBox,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,.34f));root.addView(timing,margin(0,dp(8),0,0));

        detail=text("Ready. Current path uses the path Android is actually routing now. Temporary configuration captures the current connection and restores it after test traffic has drained. A newer connection or Disconnect takes priority.",11,false);detail.setTextIsSelectable(true);detail.setPadding(dp(10),dp(10),dp(10),dp(10));detail.setBackgroundColor(Color.rgb(10,22,38));root.addView(detail,margin(0,dp(10),0,0));status=text("Cloudflare Speed Test edge • Mbps is never derived from RTT",11,false);status.setTextColor(Color.rgb(145,163,194));root.addView(status,margin(0,dp(8),0,0));

        Button hopMeasurements=new Button(activity);hopMeasurements.setText("Measure native entry and exit paths");hopMeasurements.setAllCaps(false);
        hopMeasurements.setOnClickListener(v->{if(!controller.isRunning()&&connection.isConnected())new AndroidHopMeasurementDialog(activity,connection).show();});root.addView(hopMeasurements);
        run=new Button(activity);run.setText("Run Speed Lab");run.setAllCaps(false);run.setOnClickListener(v->run());root.addView(run,margin(0,dp(8),0,0));cancel=new Button(activity);cancel.setText("Cancel test and restore connection");cancel.setAllCaps(false);cancel.setEnabled(false);cancel.setOnClickListener(v->{controller.cancel();cancel.setEnabled(false);status.setText("Cancelling traffic; waiting for native cleanup and original-path restoration…");});root.addView(cancel);
        AdapterView.OnItemSelectedListener changed=new AdapterView.OnItemSelectedListener(){public void onNothingSelected(AdapterView<?>p){}public void onItemSelected(AdapterView<?>p,View v,int position,long id){
            if(restoringChoices)return;
            if(p==standardExit){AndroidStandardExitStore.Entry selected=selectedExternal();String identity=selected==null?"":selected.id;if(!identity.equals(displayedExternalID)){displayedExternalID=identity;applyExternalDefaults();}}
            if(p==topology&&displayedTopology!=topology.getSelectedItemPosition()){displayedTopology=topology.getSelectedItemPosition();if(displayedTopology==3)applyExternalDefaults();else{refreshEntryChoices();refreshEntryModes();}}
            if(p==node)refreshModes();if(p==exit)refreshExitModes();
            if(p==entry){String identity=selectedEntryIdentity();if(!identity.equals(displayedEntryID)){displayedEntryID=identity;refreshEntryModes(savedEntryMode());}}
            refreshControls();
        }};scope.setOnItemSelectedListener(changed);topology.setOnItemSelectedListener(changed);node.setOnItemSelectedListener(changed);exit.setOnItemSelectedListener(changed);entry.setOnItemSelectedListener(changed);standardExit.setOnItemSelectedListener(changed);mode.setOnItemSelectedListener(changed);durationMode.setOnItemSelectedListener(changed);
        externalDirect.setOnCheckedChangeListener((b,on)->{if(restoringChoices)return;if(on)execution.setSelection(0);refreshControls();});
        SeekBar.OnSeekBarChangeListener timeChanged=new SeekBar.OnSeekBarChangeListener(){public void onStartTrackingTouch(SeekBar b){}public void onStopTrackingTouch(SeekBar b){}public void onProgressChanged(SeekBar b,int progress,boolean fromUser){int min=minTime.getProgress()+1,max=maxTime.getProgress()+1;if(b==minTime&&min>max)maxTime.setProgress(min-1);if(b==maxTime&&max<min)minTime.setProgress(max-1);minLabel.setText("Min "+(minTime.getProgress()+1)+" s");maxLabel.setText("Max "+(maxTime.getProgress()+1)+" s");}};minTime.setOnSeekBarChangeListener(timeChanged);maxTime.setOnSeekBarChangeListener(timeChanged);
        loadOptions();refreshControls();dialog=new AlertDialog.Builder(activity).setView(scroll).setNegativeButton("Close",null).create();dialog.setOnDismissListener(d->{if(controller.isRunning())controller.cancel();});dialog.show();
    }

    private void loadOptions(){
        restoringChoices=true;
        try{
            nodeValues=nodes.list();String[]labels=new String[nodeValues.size()];for(int i=0;i<nodeValues.size();i++)labels[i]=nodeValues.get(i).name;
            set(node,labels);set(entry,labels);set(exit,labels);if(labels.length>1)exit.setSelection(1);
            exitValues=connection.standardExits();String[]external=new String[exitValues.size()];for(int i=0;i<exitValues.size();i++)external[i]=exitValues.get(i).name+" • "+exitValues.get(i).protocol;set(standardExit,external);
            android.content.SharedPreferences prefs=activity.getSharedPreferences("router-vpn-unified",android.content.Context.MODE_PRIVATE);
            if("external".equals(prefs.getString("selected_kind","router-vpn"))){
                String selected=prefs.getString("selected_id","");
                savedExternalSelection=new AndroidConnectionProfileStore(activity,nodes,new AndroidStandardExitStore(activity)).currentExternalPath(selected);
                int index=-1;for(int i=0;i<exitValues.size();i++)if(exitValues.get(i).id.equals(selected))index=i;
                if(index<0||!AndroidStandardExitStore.snapshot(exitValues.get(index)).equals(AndroidStandardExitStore.snapshot(savedExternalSelection.exit)))throw new IllegalStateException("The saved external path changed while Speed Lab was opening.");
                standardExit.setSelection(index);topology.setSelection(3);
            }
            refreshModes();refreshEntryModes();refreshExitModes();
        }catch(Exception error){status.setText("Speed Lab options unavailable: "+safe(error));run.setEnabled(false);}
        finally{restoringChoices=false;}
        applyExternalDefaults();
        AndroidStandardExitStore.Entry selected=selectedExternal();displayedExternalID=selected==null?"":selected.id;
        displayedEntryID=selectedEntryIdentity();displayedTopology=topology.getSelectedItemPosition();
    }

    private String savedEntryMode(){
        AndroidStandardExitStore.Entry selected=selectedExternal();
        if(savedExternalSelection==null||selected==null||!savedExternalSelection.exit.id.equals(selected.id))return "";
        String identity=savedExternalSelection.ordinaryEntry!=null?"external:"+savedExternalSelection.ordinaryEntry.id:savedExternalSelection.entry!=null?"router-vpn:"+savedExternalSelection.entry.id:"";
        return identity.equals(selectedEntryIdentity())?savedExternalSelection.entryMode:"";
    }

    private void applyExternalDefaults(){
        if(restoringChoices)return;restoringChoices=true;
        try{
            AndroidStandardExitStore.Entry selected=selectedExternal();
            AndroidConnectionProfileStore.ExternalSelection saved=savedExternalSelection!=null&&selected!=null&&savedExternalSelection.exit.id.equals(selected.id)?savedExternalSelection:null;
            externalDirect.setChecked(saved==null||saved.direct());
            refreshEntryChoices();
            if(saved!=null&&!saved.direct()){
                int index=-1;
                if(saved.ordinaryEntry!=null){for(int i=0;i<ordinaryEntryValues.size();i++)if(ordinaryEntryValues.get(i).id.equals(saved.ordinaryEntry.id))index=nodeValues.size()+i;}
                else for(int i=0;i<nodeValues.size();i++)if(nodeValues.get(i).id.equals(saved.entry.id))index=i;
                entry.setSelection(index);
            }
            String requested=saved==null?"local":saved.execution;
            refreshEntryModes(savedEntryMode());
            int executionIndex=java.util.Arrays.asList("local","server","auto").indexOf(requested);execution.setSelection(executionIndex);
            displayedEntryID=selectedEntryIdentity();
        }finally{restoringChoices=false;}
        refreshControls();
    }

    private void refreshModes(){modeValues.clear();modeValues.add(new ModeOption("smart-auto","SMART AUTO"));modeValues.add(new ModeOption("auto","AUTO"));modeValues.add(new ModeOption("all","ALL / strongest available"));modeValues.add(new ModeOption("custom","CUSTOM layers"));AndroidNodeStore.Node n=selectedNode(node);if(n!=null)try{JSONObject root=readBundle(n);JSONArray logical=root.optJSONArray("logicalModes");if(logical!=null)for(int i=0;i<logical.length();i++){JSONObject m=logical.optJSONObject(i);if(m==null)continue;String id=m.optString("id","").trim();if(id.isEmpty()||"auto".equals(id)||"smart-auto".equals(id)||"custom".equals(id)||"all".equals(id))continue;modeValues.add(new ModeOption(id,m.optString("name",id)));}}catch(Exception ignored){}ArrayAdapter<ModeOption>a=new ArrayAdapter<>(activity,android.R.layout.simple_spinner_dropdown_item,modeValues);mode.setAdapter(a);}

    private void refreshEntryModes(){refreshEntryModes(selectedEntryMode());}
    private void refreshEntryChoices(){
        String previous=selectedEntryIdentity();boolean prior=restoringChoices;restoringChoices=true;
        try{
            List<String> labels=new ArrayList<>();List<String> identities=new ArrayList<>();ordinaryEntryValues=new ArrayList<>();
            for(AndroidNodeStore.Node value:nodeValues){labels.add(value.name+" • Router VPN");identities.add("router-vpn:"+value.id);}
            AndroidStandardExitStore.Entry selected=selectedExternal();
            if(topology.getSelectedItemPosition()==3&&selected!=null&&AndroidTorProfile.isTor(selected.protocol))for(AndroidStandardExitStore.Entry value:exitValues)
                if(!value.id.equals(selected.id)&&AndroidExternalPolicy.supports(value.protocol)){ordinaryEntryValues.add(value);labels.add(value.name+" • "+value.protocol);identities.add("external:"+value.id);}
            set(entry,labels.toArray(new String[0]));int index=identities.indexOf(previous);if(index>=0)entry.setSelection(index);
        }finally{restoringChoices=prior;}
    }
    private AndroidStandardExitStore.Entry selectedOrdinaryEntry(){
        int index=entry.getSelectedItemPosition()-nodeValues.size();
        return topology.getSelectedItemPosition()==3&&index>=0&&index<ordinaryEntryValues.size()?ordinaryEntryValues.get(index):null;
    }
    private String selectedEntryIdentity(){
        AndroidStandardExitStore.Entry ordinary=selectedOrdinaryEntry();if(ordinary!=null)return "external:"+ordinary.id;
        AndroidNodeStore.Node router=selectedNode(entry);return router==null?"":"router-vpn:"+router.id;
    }
    private void refreshEntryModes(String previous){
        AndroidNodeStore.Node selected=selectedNode(entry);
        try{
            AndroidStandardExitStore.Entry ordinary=selectedOrdinaryEntry();
            List<NativeSingBoxController.ModeInfo> values=ordinary!=null?Collections.singletonList(new NativeSingBoxController.ModeInfo(AndroidExternalPolicy.protocol(ordinary.protocol),ordinary.protocol)):connection.supportedNativeEntryModes(selected);String[] labels=new String[values.size()];
            for(int i=0;i<values.size();i++)labels[i]=values.get(i).name;
            entryMode.setTag(values);set(entryMode,labels);
            int priorExecution=execution.getSelectedItemPosition();set(execution,ordinary!=null?new String[]{"Local"}:new String[]{"Local","Server","Compare both"});execution.setSelection(ordinary!=null?0:Math.max(0,Math.min(2,priorExecution)));
            if(!previous.isEmpty()){int preferredIndex=-1;for(int i=0;i<values.size();i++)if(values.get(i).id.equals(previous)){preferredIndex=i;break;}entryMode.setSelection(preferredIndex);}
        }catch(Exception changed){entryMode.setTag(Collections.emptyList());set(entryMode,new String[]{});status.setText("The selected entry modes are unavailable; select a valid saved node.");}
    }

    private void refreshExitModes(){AndroidNodeStore.Node n=selectedNode(exit);if(n==null)return;try{List<NativeSingBoxController.ModeInfo>values=connection.supportedMultihopExitModes(n);String[]labels=new String[values.size()];for(int i=0;i<values.size();i++)labels[i]=values.get(i).name;set(exitMode,labels);for(int i=0;i<values.size();i++){View tag=new View(activity);tag.setTag(values.get(i).id);}exitMode.setTag(values);}catch(Exception e){set(exitMode,new String[]{});exitMode.setTag(Collections.emptyList());}}

    private void refreshControls(){boolean temporary=scope.getSelectedItemPosition()==1;topology.setEnabled(temporary);node.setEnabled(temporary);entry.setEnabled(temporary);exit.setEnabled(temporary);standardExit.setEnabled(temporary);mode.setEnabled(temporary);exitMode.setEnabled(temporary);entryMode.setEnabled(temporary);execution.setEnabled(temporary);layers.setEnabled(temporary);externalDirect.setEnabled(temporary);boolean customTime=durationMode.getSelectedItemPosition()==1;minTime.setEnabled(customTime);maxTime.setEnabled(customTime);int top=topology.getSelectedItemPosition();entry.setVisibility(temporary&&(top==2||top==3&&!externalDirect.isChecked())?View.VISIBLE:View.GONE);exit.setVisibility(temporary&&top==2?View.VISIBLE:View.GONE);exitMode.setVisibility(temporary&&top==2?View.VISIBLE:View.GONE);entryMode.setVisibility(temporary&&(top==2||top==3&&!externalDirect.isChecked())?View.VISIBLE:View.GONE);execution.setVisibility(temporary&&(top==2||top==3&&!externalDirect.isChecked())?View.VISIBLE:View.GONE);standardExit.setVisibility(temporary&&top==3?View.VISIBLE:View.GONE);externalDirect.setVisibility(temporary&&top==3?View.VISIBLE:View.GONE);node.setVisibility(temporary&&top==1?View.VISIBLE:View.GONE);mode.setVisibility(temporary&&top==1?View.VISIBLE:View.GONE);layers.setVisibility(temporary&&top==1&&selectedMode().equals("custom")?View.VISIBLE:View.GONE);}

    private void run(){AndroidSpeedLabController.Request q=new AndroidSpeedLabController.Request();q.scope=scope.getSelectedItemPosition()==0?"current":"temporary";q.durationMode=durationMode.getSelectedItemPosition()==0?"auto":"custom";q.minSeconds=minTime.getProgress()+1;q.maxSeconds=maxTime.getProgress()+1;if("temporary".equals(q.scope)){String[]tops={"system-direct","router","multihop","external"};q.topology=tops[Math.max(0,Math.min(3,topology.getSelectedItemPosition()))];q.node=selectedNode(node);q.ordinaryEntry="external".equals(q.topology)&&!externalDirect.isChecked()?selectedOrdinaryEntry():null;q.entry=q.ordinaryEntry==null?selectedNode(entry):null;q.exit=selectedNode(exit);q.standardExit=selectedExternal();q.externalDirect=externalDirect.isChecked();q.mode=selectedMode();q.exitMode=selectedExitMode();q.entryMode="external".equals(q.topology)&&q.externalDirect?"":selectedEntryMode();q.execution="external".equals(q.topology)&&q.externalDirect?"local":selectedExecution();if("custom".equals(q.mode)){List<String>values=new ArrayList<>();for(String x:layers.getText().toString().split(",")){String v=x.trim().toLowerCase(Locale.US);if(!v.isEmpty())values.add(v);}q.customLayers=values;}}
        run.setEnabled(false);cancel.setEnabled(true);status.setText("Capturing the original connection, proving the test path and measuring…");detail.setText("Temporary tests restore the exact original connection after all traffic drains. Cancel joins cleanup before restoration.");controller.run(q,new AndroidSpeedLabController.Callback(){public void progress(String message){activity.runOnUiThread(()->{if(dialog!=null&&dialog.isShowing())status.setText(message);});}public void finished(AndroidSpeedLab.Result result,Throwable error){activity.runOnUiThread(()->{run.setEnabled(true);cancel.setEnabled(false);if(error!=null){status.setText(error instanceof java.util.concurrent.CancellationException?"Speed Lab cancelled":"Speed Lab stopped");detail.setText(safe(error));return;}if(result==null){status.setText("Speed Lab returned no result");return;}idle.setText(String.format(Locale.US,"%.1f ms",result.idle.medianMs));download.setText(String.format(Locale.US,"%.1f Mbps",result.download.mbps));upload.setText(String.format(Locale.US,"%.1f Mbps",result.upload.mbps));idleDetail.setText(result.idle.detail());downloadDetail.setText(String.format(Locale.US,"loaded %.1f ms • +%.1f bloat • p90 %.1f",result.download.loadedLatency.medianMs,result.download.bufferbloatMs,result.download.loadedLatency.p90Ms));uploadDetail.setText(String.format(Locale.US,"loaded %.1f ms • +%.1f bloat • p90 %.1f",result.upload.loadedLatency.medianMs,result.upload.bufferbloatMs,result.upload.loadedLatency.p90Ms));StringBuilder hopText=new StringBuilder();String nativeHops=controller.nativeHops();if(!nativeHops.isEmpty())hopText.append(nativeHops).append("\n");List<AndroidSpeedLabHopMeter.Hop>hops=controller.hops();if(!hops.isEmpty()){hopText.append("PER-HOP — SAME PROVED GRAPH\n");for(AndroidSpeedLabHopMeter.Hop hop:hops)hopText.append(hop.summary()).append('\n');}String hopError=controller.hopError();if(hopError!=null&&!hopError.trim().isEmpty())hopText.append("Per-hop warning: ").append(hopError.trim()).append('\n');try{String json=result.json().toString(2);detail.setText(hopText.length()==0?json:hopText+"\nFULL RESULT\n"+json);}catch(Exception ignored){detail.setText(hopText.length()==0?result.summary():hopText+"\n"+result.summary());}status.setText("Finished • "+result.pathIdentity+" • real HTTPS throughput + loaded latency"+(hops.isEmpty()?"":" • "+hops.size()+" hop measurements"));});}});}

    private String selectedExecution(){int choice=execution.getSelectedItemPosition();return choice>=0&&choice<3?new String[]{"local","server","auto"}[choice]:"";}
    @SuppressWarnings("unchecked") private String selectedEntryMode(){Object tag=entryMode.getTag();if(tag instanceof List){List<NativeSingBoxController.ModeInfo> values=(List<NativeSingBoxController.ModeInfo>)tag;int selected=entryMode.getSelectedItemPosition();if(selected>=0&&selected<values.size())return values.get(selected).id;}return "";}
    @SuppressWarnings("unchecked") private String selectedExitMode(){Object tag=exitMode.getTag();if(tag instanceof List){List<NativeSingBoxController.ModeInfo>v=(List<NativeSingBoxController.ModeInfo>)tag;int i=exitMode.getSelectedItemPosition();if(i>=0&&i<v.size())return v.get(i).id;}return"shadowsocks";}
    private String selectedMode(){int i=mode.getSelectedItemPosition();return i>=0&&i<modeValues.size()?modeValues.get(i).id:"smart-auto";}
    private AndroidNodeStore.Node selectedNode(Spinner spinner){int i=spinner.getSelectedItemPosition();return i>=0&&i<nodeValues.size()?nodeValues.get(i):null;}
    private AndroidStandardExitStore.Entry selectedExternal(){int i=standardExit.getSelectedItemPosition();return i>=0&&i<exitValues.size()?exitValues.get(i):null;}
    private static JSONObject readBundle(AndroidNodeStore.Node n)throws Exception{try(FileInputStream in=new FileInputStream(n.file);ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]b=new byte[8192];int total=0,x;while((x=in.read(b))!=-1){total+=x;if(total>AndroidNodeStore.MAX_BUNDLE)throw new IllegalStateException("Node bundle exceeds safety limit.");out.write(b,0,x);}return new JSONObject(new String(out.toByteArray(),StandardCharsets.UTF_8));}}
    private View field(String label,View value){LinearLayout r=row();TextView l=text(label,11,true);l.setTextColor(Color.rgb(180,196,220));r.addView(l,new LinearLayout.LayoutParams(dp(110),LinearLayout.LayoutParams.WRAP_CONTENT));r.addView(value,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1));return r;}
    private LinearLayout metric(String heading,TextView big,TextView small){LinearLayout box=new LinearLayout(activity);box.setOrientation(LinearLayout.VERTICAL);box.setPadding(dp(8),dp(8),dp(8),dp(8));TextView h=text(heading,9,true);h.setTextColor(Color.rgb(145,166,198));small.setTextColor(Color.rgb(145,166,198));box.addView(h);box.addView(big);box.addView(small);return box;}
    private LinearLayout row(){LinearLayout r=new LinearLayout(activity);r.setOrientation(LinearLayout.HORIZONTAL);r.setGravity(Gravity.CENTER_VERTICAL);return r;}
    private TextView text(String value,int sp,boolean bold){TextView v=new TextView(activity);v.setText(value);v.setTextSize(sp);v.setTextColor(Color.WHITE);if(bold)v.setTypeface(v.getTypeface(),Typeface.BOLD);return v;}
    private Spinner spinner(String[]items){Spinner s=new Spinner(activity);set(s,items);return s;}
    private void set(Spinner s,String[]items){s.setAdapter(new ArrayAdapter<>(activity,android.R.layout.simple_spinner_dropdown_item,items));}
    private LinearLayout.LayoutParams weight(){return new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1);}
    private LinearLayout.LayoutParams margin(int l,int t,int r,int b){LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,LinearLayout.LayoutParams.WRAP_CONTENT);p.setMargins(l,t,r,b);return p;}
    private int dp(float v){return Math.round(v*activity.getResources().getDisplayMetrics().density);}
    private static String safe(Throwable e){String v=e==null?"":e.getMessage();return v==null||v.trim().isEmpty()?"Router VPN Speed Lab error":v.trim();}
}
