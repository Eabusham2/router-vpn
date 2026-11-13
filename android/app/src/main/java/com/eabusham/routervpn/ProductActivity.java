package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.Bundle;
import android.provider.Settings;
import android.text.InputType;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Unified native daily-use Android shell. */
public final class ProductActivity extends Activity {
    private static final String PREFS="router-vpn-unified";
    private static final String MODE_KEY="mode",CUSTOM_KEY="custom_presets",SELECTED_KIND="selected_kind",SELECTED_ID="selected_id";
    private static final String MULTI_ON="multihop_on",MULTI_ENTRY="multihop_entry",MULTI_EXIT="multihop_exit",MULTI_MODE="multihop_exit_mode";
    private static final int PREPARE_VIA_ENTRY_RTT=7606,IMPORT_ROUTER_BUNDLE=7607;
    private static final String STATE_IMPORT_DECISION="routervpn.import.decision";
    private static final String STATE_PROBE_ENTRY="routervpn.via_entry_probe.entry",STATE_PROBE_CANDIDATES="routervpn.via_entry_probe.candidates";

    private AndroidNodeStore nodeStore; private AndroidStandardExitStore exitStore; private AndroidUnifiedNodeCatalog catalog; private AndroidUnifiedConnectionController connection; private AndroidTelemetry telemetry; private AndroidForwardingMaster forwardingMaster; private AndroidViaEntryLatencyProbe viaEntryProbe;
    private RouterVpnNodeMapView mapView; private LinearLayout sheet; private ScrollView sheetScroll;
    private TextView nodeButton,statusView,modeHint,dnsHint,multihopHint,liveLatency,autoRequirementsHint;
    private Button connectButton,fastestButton,performanceButton,forwardButton;
    private CheckBox killSwitch,multihopToggle; private Spinner modeSpinner,dnsSpinner; private List<ModeChoice> modeChoices=new ArrayList<>();
    private float sheetTouchY; private boolean sheetExpanded,telemetryBusy,forwardingBusy; private long lastTelemetryAt; private double currentPathMs; private Boolean forwardingEnabled;
    private String pendingProbeEntryId=""; private ArrayList<String> pendingProbeCandidateIds=new ArrayList<>();
    private long viaEntryGeneration;
    private AlertDialog viaEntryDialog;
    private String importDecision="";
    private long importGeneration,telemetryGeneration;
    private boolean resumed;
    private AlertDialog currentSpeedDialog;
    private AlertDialog fastestProgressDialog;
    private AndroidHopMeasurementDialog routedHopDialog;
    private AndroidNodeCandidateDialog candidateDialog;
    private AndroidNodeCandidatePreparationDialog preparedCandidateDialog;
    private AndroidExternalBenchmarkDialog externalBenchmarkDialog;
    private AndroidExternalComparisonDialog externalComparisonDialog;
    private AndroidTelemetry.PathResult currentPathReceipt;
    private AndroidExternalLiveTelemetry externalTelemetry;
    private AndroidExternalLiveTelemetry.Result currentExternalReceipt;
    private AndroidOrderedPathPresentation orderedPresentation;
    private boolean orderedPresentationPending;
    private long orderedPresentationGeneration;
    private String externalProtectionID="",externalProtectionSource="";
    private final android.os.Handler telemetryHandler=new android.os.Handler(android.os.Looper.getMainLooper());
    private final Runnable telemetryTick=new Runnable(){public void run(){if(!resumed||isFinishing()||isDestroyed())return;requestOrderedPresentation();refreshTelemetry(false);telemetryHandler.postDelayed(this,5000);}};

    private static final class ModeChoice { final String id,title; final List<String> layers; ModeChoice(String id,String title){this(id,title,Collections.emptyList());} ModeChoice(String id,String title,List<String>layers){this.id=id;this.title=title;this.layers=layers==null?Collections.emptyList():layers;} @Override public String toString(){return title;} }
    private static final class CustomPreset { String name; List<String> layers; CustomPreset(String name,List<String>layers){this.name=name;this.layers=layers;} }

    @Override protected void onCreate(Bundle state){super.onCreate(state);nodeStore=new AndroidNodeStore(this);exitStore=new AndroidStandardExitStore(this);catalog=new AndroidUnifiedNodeCatalog(nodeStore,exitStore);connection=new AndroidUnifiedConnectionController(this,nodeStore);telemetry=new AndroidTelemetry(this,nodeStore);externalTelemetry=new AndroidExternalLiveTelemetry(this,AndroidRuntimeRegistry.get(this).standardExit);forwardingMaster=new AndroidForwardingMaster(this,nodeStore);viaEntryProbe=new AndroidViaEntryLatencyProbe(this,AndroidRuntimeRegistry.get(this),telemetry);if(state!=null){importDecision=state.getString(STATE_IMPORT_DECISION,"");pendingProbeEntryId=state.getString(STATE_PROBE_ENTRY,"");ArrayList<String> ids=state.getStringArrayList(STATE_PROBE_CANDIDATES);if(ids!=null)pendingProbeCandidateIds=ids;}setContentView(buildUi());refreshAll();if(state!=null&&!AndroidExternalNodeComparison.hasActiveOperation())connection.restorePending(state,callback());applyStartupPolicy(state!=null);AndroidProductOnboarding.showIfNeeded(this);}
    @Override protected void onResume(){super.onResume();resumed=true;if(connection!=null)connection.resumePending();resumeCandidatePreparation();telemetryHandler.removeCallbacks(telemetryTick);telemetryHandler.post(telemetryTick);refreshAll();if(viaEntryProbe!=null&&viaEntryProbe.isBusy()&&!pendingProbeEntryId.isEmpty())statusView.setText("Measuring live via-entry multihop candidate RTT…");}
    @Override protected void onPause(){closeRoutedHopMeasurement();closeCandidateMeasurement();detachCandidatePreparation();resumed=false;telemetryGeneration++;telemetryHandler.removeCallbacks(telemetryTick);if(externalTelemetry!=null)externalTelemetry.cancel();clearCurrentTelemetry();if(telemetry!=null){telemetry.cancelCurrent();telemetry.cancelFastest();}if(currentSpeedDialog!=null){currentSpeedDialog.dismiss();currentSpeedDialog=null;}if(externalBenchmarkDialog!=null){externalBenchmarkDialog.close();externalBenchmarkDialog=null;}super.onPause();}
    @Override protected void onSaveInstanceState(Bundle out){if(!importDecision.isEmpty())out.putString(STATE_IMPORT_DECISION,importDecision);if(connection!=null)connection.savePending(out);if(viaEntryProbe==null||!viaEntryProbe.isBusy()){if(!pendingProbeEntryId.isEmpty())out.putString(STATE_PROBE_ENTRY,pendingProbeEntryId);if(!pendingProbeCandidateIds.isEmpty())out.putStringArrayList(STATE_PROBE_CANDIDATES,new ArrayList<>(pendingProbeCandidateIds));}super.onSaveInstanceState(out);}
    @Override protected void onDestroy(){closeRoutedHopMeasurement();closeCandidateMeasurement();detachCandidatePreparation();importGeneration++;telemetryGeneration++;telemetryHandler.removeCallbacks(telemetryTick);if(externalTelemetry!=null)externalTelemetry.cancel();if(telemetry!=null)telemetry.close();if(fastestProgressDialog!=null){fastestProgressDialog.dismiss();fastestProgressDialog=null;}if(externalBenchmarkDialog!=null){externalBenchmarkDialog.close();externalBenchmarkDialog=null;}viaEntryGeneration++;if(viaEntryProbe!=null)viaEntryProbe.cancel();if(viaEntryDialog!=null){viaEntryDialog.dismiss();viaEntryDialog=null;}if(externalComparisonDialog!=null){externalComparisonDialog.close();externalComparisonDialog=null;}if(isFinishing())AndroidStartupPolicy.cancelPending();if(connection!=null)connection.close();super.onDestroy();}
    @Override protected void onActivityResult(int requestCode,int resultCode,Intent data){if(requestCode==IMPORT_ROUTER_BUNDLE){receiveRouterBundle(resultCode,data);return;}if(requestCode==PREPARE_VIA_ENTRY_RTT){if(resultCode==RESULT_OK)runPendingViaEntryProbe();else{AndroidNodeStore.Node entry=quietNode(pendingProbeEntryId);List<AndroidNodeStore.Node> exits=quietNodes(pendingProbeCandidateIds);clearPendingProbe();try{showViaEntryExitPicker(viaEntryProbe.unmeasured(entry,exits),new IllegalStateException("Android VPN permission was not granted; via-entry RTT is unavailable."));}catch(Exception error){toast(safe(error));}}return;}if(connection!=null&&connection.onActivityResult(requestCode,resultCode)){refreshConnectionLater();return;}super.onActivityResult(requestCode,resultCode,data);}

    @Override public void onRequestPermissionsResult(int requestCode,String[] permissions,int[] grantResults){if(AndroidUpdateDialog.onPermissionResult(this,requestCode))return;super.onRequestPermissionsResult(requestCode,permissions,grantResults);}

    private View buildUi(){
        LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(10),dp(10),dp(10),dp(8));root.setBackgroundColor(Color.rgb(8,16,30));
        nodeButton=text("Add / select node",14,true);nodeButton.setTextColor(Color.WHITE);nodeButton.setPadding(dp(12),dp(9),dp(12),dp(9));nodeButton.setBackground(round(Color.rgb(24,38,62),16));nodeButton.setOnClickListener(v->showNodes());root.addView(nodeButton,margins(0,0,0,dp(8)));
        mapView=new RouterVpnNodeMapView(this);mapView.setOnMarkerClickListener(marker->{String raw=marker.id==null?"":marker.id;int cut=raw.indexOf(':');if(cut<=0)return;selectCatalog(raw.substring(0,cut),raw.substring(cut+1));});LinearLayout.LayoutParams mapParams=new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,0,0.56f);root.addView(mapView,mapParams);

        sheet=new LinearLayout(this);sheet.setOrientation(LinearLayout.VERTICAL);sheet.setPadding(dp(14),dp(5),dp(14),dp(12));sheet.setBackground(round(Color.rgb(17,27,45),24));
        sheetScroll=new ScrollView(this);sheetScroll.setFillViewport(false);sheetScroll.setClipToPadding(false);sheetScroll.setOverScrollMode(View.OVER_SCROLL_IF_CONTENT_SCROLLS);sheetScroll.addView(sheet,new ScrollView.LayoutParams(ScrollView.LayoutParams.MATCH_PARENT,ScrollView.LayoutParams.WRAP_CONTENT));sheetScroll.setOnTouchListener((v,event)->{if(event.getAction()==MotionEvent.ACTION_DOWN){sheetTouchY=event.getY();return false;}if(event.getAction()==MotionEvent.ACTION_UP){float delta=event.getY()-sheetTouchY;if(Math.abs(delta)>dp(40)){sheetExpanded=delta<0;applySheetWeight();}return false;}return false;});LinearLayout.LayoutParams sheetParams=new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,0,0.44f);sheetParams.setMargins(0,dp(8),0,0);root.addView(sheetScroll,sheetParams);
        TextView handle=text("━━━━━━━━",16,true);handle.setTextColor(Color.rgb(112,126,148));handle.setGravity(Gravity.CENTER);sheet.addView(handle);
        LinearLayout statusRow=row();statusView=text("Disconnected",13,false);statusView.setTextColor(Color.rgb(173,190,214));statusView.setTextIsSelectable(true);statusView.setOnClickListener(v->showConnectionDetails());statusRow.addView(statusView,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));Button connectionDetails=smallButton("Details / proof");connectionDetails.setOnClickListener(v->showConnectionDetails());statusRow.addView(connectionDetails);sheet.addView(statusRow,margins(0,0,0,dp(7)));

        LinearLayout connectRow=row();fastestButton=smallButton("⚡ Fastest ▾");fastestButton.setContentDescription("Compare Router nodes by direct TCP, or compare and connect external paths using 50 routed HTTPS responses.");fastestButton.setOnClickListener(v->showFastConnectMenu());connectRow.addView(fastestButton);connectButton=primaryButton("Connect");connectButton.setOnClickListener(v->connectOrDisconnect());connectRow.addView(connectButton,new LinearLayout.LayoutParams(0,dp(50),1f));liveLatency=text("-- ms",11,true);liveLatency.setTextColor(Color.rgb(173,190,214));liveLatency.setGravity(Gravity.CENTER);liveLatency.setPadding(dp(6),0,dp(6),0);liveLatency.setContentDescription("Current path response; tap for measurement details");liveLatency.setOnClickListener(v->showLiveTelemetry());connectRow.addView(liveLatency);killSwitch=new CheckBox(this);killSwitch.setText("Kill");killSwitch.setContentDescription("Kill switch");killSwitch.setTextColor(Color.WHITE);killSwitch.setButtonTintList(ColorStateList.valueOf(Color.rgb(123,104,255)));killSwitch.setOnCheckedChangeListener((b,on)->{if(!b.isPressed())return;setQuickKillSwitch(on);});connectRow.addView(killSwitch);forwardButton=smallButton("Forward");forwardButton.setContentDescription("Server port-forwarding master");forwardButton.setOnClickListener(v->showForwarding());connectRow.addView(forwardButton);sheet.addView(connectRow);

        LinearLayout multiRow=row();multihopToggle=new CheckBox(this);multihopToggle.setText("Multihop");multihopToggle.setTextColor(Color.WHITE);multihopToggle.setButtonTintList(ColorStateList.valueOf(Color.rgb(55,145,255)));multihopToggle.setOnCheckedChangeListener((b,on)->{if(!b.isPressed())return;if(mutationBusy()){toast("Finish/disconnect the current VPN operation before changing multihop configuration.");refreshMultihopSummary();return;}if(on&&isExternalSelected()){configureMultihop();refreshMultihopSummary();return;}AndroidConnectionProfileStore.applySelection(prefs(),prefs().edit().putBoolean(MULTI_ON,on));refreshMap();refreshModeChoices();refreshConnectionState();refreshMultihopSummary();refreshTelemetry(true);});multiRow.addView(multihopToggle);multihopHint=text("Off",11,false);multihopHint.setTextColor(Color.rgb(173,190,214));multiRow.addView(multihopHint,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));Button hops=smallButton("Edit hops");hops.setOnClickListener(v->configureMultihop());multiRow.addView(hops);sheet.addView(multiRow,margins(0,dp(8),0,0));

        LinearLayout settingsRow=controlRow("Settings");Button settings=smallButton("Open settings");settings.setOnClickListener(v->showSettings());settingsRow.addView(settings);Button connectionProfiles=smallButton("Profiles");connectionProfiles.setContentDescription("Add, load, update or delete a whole non-secret connection profile");connectionProfiles.setOnClickListener(v->showConnectionProfiles());settingsRow.addView(connectionProfiles);performanceButton=smallButton("Performance");performanceButton.setOnClickListener(v->showPerformance());settingsRow.addView(performanceButton);Button mtu=smallButton("MTU");mtu.setOnClickListener(v->showMtuHelp());settingsRow.addView(mtu);sheet.addView(settingsRow,margins(0,dp(7),0,0));autoRequirementsHint=text("AUTO requirements: Off",11,false);autoRequirementsHint.setTextColor(Color.rgb(145,160,184));autoRequirementsHint.setPadding(dp(72),0,0,0);sheet.addView(autoRequirementsHint);
        LinearLayout speedRow=controlRow("Speed");Button speedLabButton=smallButton("Speed Lab");speedLabButton.setContentDescription("Run the dedicated current-path or temporary-config Speed Lab with idle and loaded latency, download/upload Mbps, and proved multihop hop metrics.");speedLabButton.setOnClickListener(v->new AndroidSpeedLabDialog(this,nodeStore,connection,new AndroidSpeedLabController(this,connection)).show());speedRow.addView(speedLabButton,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));sheet.addView(speedRow,margins(0,dp(7),0,0));
        LinearLayout modeRow=controlRow("Mode");modeSpinner=new Spinner(this);modeSpinner.setPopupBackgroundDrawable(round(Color.rgb(29,43,68),12));modeRow.addView(modeSpinner,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));Button modeDetails=smallButton("Presets");modeDetails.setOnClickListener(v->showCustomPresetManager());modeRow.addView(modeDetails);sheet.addView(modeRow,margins(0,dp(7),0,0));modeHint=text("SMART AUTO is the default.",11,false);modeHint.setTextColor(Color.rgb(145,160,184));sheet.addView(modeHint);
        LinearLayout dnsRow=controlRow("DNS");dnsSpinner=new Spinner(this);String[]dns={"Home AdGuard","Fastest measured","Custom","DoT","DoH","DoH3","Rescue"};dnsSpinner.setAdapter(new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,dns));dnsRow.addView(dnsSpinner,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));Button dnsDetails=smallButton("Details");dnsDetails.setOnClickListener(v->{if(!openSelectedExternal(false))AndroidProductParity.showDNS(this,nodeStore);});dnsRow.addView(dnsDetails);sheet.addView(dnsRow,margins(0,dp(7),0,0));dnsHint=text("DNS changes the next tunnel resolver path; Connected still requires runtime DNS/path proof.",11,false);dnsHint.setTextColor(Color.rgb(145,160,184));sheet.addView(dnsHint);dnsSpinner.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener(){boolean ready;public void onNothingSelected(android.widget.AdapterView<?>p){}public void onItemSelected(android.widget.AdapterView<?>p,View v,int pos,long id){if(!ready){ready=true;return;}if(isExternalSelected())return;if(mutationBusy()){toast("Disconnect/finish the current VPN operation before changing DNS.");refreshDnsSelection();return;}if(pos==0)setQuickDns("home");else if(pos==1)setQuickDns("fastest");else if(pos==6)setQuickDns("rescue");else AndroidProductParity.showDNS(ProductActivity.this,nodeStore);}});
        LinearLayout footer=row();Button nodes=smallButton("Nodes");nodes.setContentDescription("Add / manage nodes");nodes.setOnClickListener(v->showNodes());footer.addView(nodes);Button profiles=smallButton("Router nodes");profiles.setContentDescription("Manage linked Router VPN node records");profiles.setOnClickListener(v->showProfileManager());footer.addView(profiles);Button pair=smallButton("Add Router");pair.setOnClickListener(v->showAddRouter());footer.addView(pair);Button custom=smallButton("Add custom");custom.setOnClickListener(v->openStandardExits());footer.addView(custom);Button help=smallButton("Help");help.setOnClickListener(v->showHelp());footer.addView(help);sheet.addView(footer,margins(0,dp(8),0,0));return root;
    }

    private void applySheetWeight(){LinearLayout.LayoutParams p=(LinearLayout.LayoutParams)sheetScroll.getLayoutParams();p.weight=sheetExpanded?0.70f:0.44f;sheetScroll.setLayoutParams(p);LinearLayout.LayoutParams m=(LinearLayout.LayoutParams)mapView.getLayoutParams();m.weight=sheetExpanded?0.30f:0.56f;mapView.setLayoutParams(m);}
    private void refreshAll(){requestOrderedPresentation();refreshNodes();refreshModeChoices();refreshConnectionState();refreshSettingsState();refreshDnsSelection();refreshMultihopSummary();refreshTelemetry(false);refreshForwardingState();}
    private boolean orderedPathEnabled(){AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(this);return home.connected&&"node-chain".equals(home.logicalMode)||AndroidOrderedPathPresentation.configured(this);}
    private AndroidOrderedPathPresentation currentOrderedPresentation(){return orderedPresentation!=null&&orderedPresentation.current(this)?orderedPresentation:null;}
    private void requestOrderedPresentation(){
        if(!orderedPathEnabled()){orderedPresentation=null;orderedPresentationGeneration++;orderedPresentationPending=false;return;}
        if(orderedPresentationPending||isFinishing()||isDestroyed())return;
        orderedPresentationPending=true;long ticket=++orderedPresentationGeneration;
        new Thread(()->{
            AndroidOrderedPathPresentation captured=null;
            try{captured=AndroidOrderedPathPresentation.capture(this,nodeStore,exitStore,AndroidRuntimeRegistry.get(this).nodeChain);}catch(Exception changed){}
            final AndroidOrderedPathPresentation result=captured;
            runOnUiThread(()->{if(ticket!=orderedPresentationGeneration||isFinishing()||isDestroyed())return;orderedPresentationPending=false;orderedPresentation=result!=null&&result.current(this)?result:null;refreshNodes();refreshModeChoices();refreshMultihopSummary();});
        },"routervpn-ordered-display").start();
    }
    private boolean mutationBusy(){return orderedConnectCapturePending||startupCapturePending||AndroidExternalNodeComparison.hasActiveOperation()||(connection!=null&&connection.isActiveOrTransitioning())||AndroidVpnMutationGuard.isBusy(this)||(viaEntryProbe!=null&&viaEntryProbe.isBusy());}
    private void refreshConnectionLater(){mapView.postDelayed(this::refreshAll,350);mapView.postDelayed(this::refreshAll,1300);mapView.postDelayed(this::refreshAll,3000);}

    private boolean startupCapturePending,orderedConnectCapturePending;
    private long orderedConnectTicket;
    private long startupCaptureTicket;
    private void applyStartupPolicy(boolean restoredActivity){
        if(AndroidExternalNodeComparison.hasActiveOperation()||startupCapturePending)return;
        final long epoch=AndroidStartupPolicy.captureEpoch(),ticket=++startupCaptureTicket;
        startupCapturePending=true;
        new Thread(()->{
            AndroidStartupPolicy.Attempt captured=null;Exception failure=null;
            try{captured=AndroidStartupPolicy.coldLaunch(this,nodeStore,connection,restoredActivity,epoch);}catch(Exception unavailable){failure=unavailable;}
            final AndroidStartupPolicy.Attempt capture=captured;final Exception error=failure;
            runOnUiThread(()->{
                if(ticket!=startupCaptureTicket||isFinishing()||isDestroyed()){if(capture!=null)capture.cancel();return;}
                startupCapturePending=false;
                if(epoch!=AndroidStartupPolicy.captureEpoch()){if(capture!=null)capture.cancel();return;}
                if(error!=null){statusView.setText("Automatic startup stayed disconnected: "+safe(error));return;}
                if(capture!=null){
                    if(!capture.current()||!connection.pathCurrent(capture.idleOwner())){capture.cancel();return;}
                    statusView.setText("Preparing the captured startup path…");connection.connectStartup(capture,callback());
                }
            });
        },"routervpn-startup-capture").start();
    }

    private void connectOrDisconnect(){if(AndroidNodeCandidatePreparation.cancelActive()){connection.cancelPermissionPending();statusView.setText("Cancelling candidate testing; waiting for the temporary VPN to stop…");refreshConnectionLater();return;}if(orderedConnectCapturePending){orderedConnectCapturePending=false;orderedConnectTicket++;statusView.setText("Ordered connection capture was cancelled.");refreshConnectionLater();return;}if(startupCapturePending){startupCapturePending=false;startupCaptureTicket++;AndroidStartupPolicy.cancelPending();statusView.setText("Automatic startup was cancelled.");refreshConnectionLater();return;}if(AndroidExternalNodeComparison.cancelActiveOperation()){statusView.setText("Cancelling external comparison; retaining ownership through native drain and original restoration…");refreshConnectionLater();return;}if(connection.cancelStartupPending()||connection.cancelPermissionPending()){refreshConnectionLater();return;}AndroidStartupPolicy.cancelPending();if(AndroidViaEntryLatencyProbe.cancelActiveOperation()){statusView.setText("Cancelling the captured candidate test; waiting for owned sockets and entry teardown…");refreshConnectionLater();return;}if(connection.isActiveOrTransitioning()){statusView.setText("Disconnecting…");connectButton.setText("Disconnecting…");connection.disconnect(callback());return;}AndroidUnifiedNodeCatalog.Item selected=selectedCatalogItem();if(selected==null){showNodes();return;}if(!selected.isRouterVpn()){try{AndroidConnectionProfileStore.ExternalSelection path=new AndroidConnectionProfileStore(this,nodeStore,exitStore).currentExternalPath(selected.id);statusView.setText("Preparing external path…");connection.connectExternal(path,callback());}catch(Exception error){toast(safe(error));}return;}if(multihopToggle.isChecked()){try{if(!prefs().getString("multihop_nodes","").isEmpty()){connectSavedOrderedPath();return;}if("external".equals(prefs().getString("multihop_entry_kind","router-vpn"))){AndroidConnectionProfileStore.ImportedRouterSelection path=new AndroidConnectionProfileStore(this,nodeStore,exitStore).currentImportedRouterPath();statusView.setText("Preparing imported entry → Router final…");connection.connectImportedMultihop(path.entry,path.exit,path.exitMode,path.execution,callback());return;}AndroidNodeStore.Node entry=nodeById(prefs().getString(MULTI_ENTRY,"")),exit=nodeById(prefs().getString(MULTI_EXIT,""));String exitMode=prefs().getString(MULTI_MODE,"");if(entry==null||exit==null||exitMode.isEmpty()){configureMultihop();return;}statusView.setText("Preparing multihop…");connection.connectMultihop(entry,exit,exitMode,prefs().getString("multihop_execution","local"),prefs().getString("multihop_entry_mode","wg"),callback());}catch(Exception error){toast(safe(error));}return;}ModeChoice choice=currentMode();if(choice==null){refreshModeChoices();choice=currentMode();if(choice==null)return;}statusView.setText("Preparing "+choice.title+"…");connection.connect(choice.id,choice.layers,callback());}
    private void connectSavedOrderedPath(){
        final String selection;final AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(this);
        try{selection=AndroidConnectionSelection.digest(this,nodeStore);}catch(Exception changed){toast(safe(changed));return;}
        final long ticket=++orderedConnectTicket;orderedConnectCapturePending=true;
        statusView.setText("Capturing every original ordered Router node…");
        new Thread(()->{
            AndroidNodeStore.ChainCapture captured=null;Exception failure=null;
            try{captured=new AndroidConnectionProfileStore(this,nodeStore,exitStore).currentOrderedPath();}catch(Exception changed){failure=changed;}
            final AndroidNodeStore.ChainCapture path=captured;final Exception error=failure;
            runOnUiThread(()->{
                if(ticket!=orderedConnectTicket||isFinishing()||isDestroyed())return;
                orderedConnectCapturePending=false;
                try{if(error!=null)throw error;AndroidConnectionSelection.requireCurrent(this,nodeStore,selection);
                    if(!connection.pathCurrent(home))throw new IllegalStateException("A newer decision cancelled the ordered connection capture.");
                    connection.connectOrdered(path,home,selection,callback());
                }catch(Exception changed){statusView.setText("Ordered connection stayed disconnected: "+safe(changed));}
            });
        },"routervpn-ordered-choice-capture").start();
    }

    private AndroidUnifiedConnectionController.Callback callback(){return new AndroidUnifiedConnectionController.Callback(){public boolean recordsNodeUsage(){return true;}public void progress(String message){runOnUiThread(()->{if(isFinishing()||isDestroyed())return;statusView.setText(message);connectButton.setText("Disconnect");});}public void finished(boolean ok,String message){runOnUiThread(()->{if(isFinishing()||isDestroyed())return;statusView.setText(message);String usageWarning=AndroidNodeUsage.saveWarning(message);if(!ok)toast(message);else if(!usageWarning.isEmpty())toast(usageWarning);refreshAll();refreshConnectionLater();});}};}
    private void refreshConnectionState(){boolean active=connection!=null&&connection.isActiveOrTransitioning(),busy=mutationBusy(),candidate=AndroidNodeCandidatePreparation.busy()||AndroidViaEntryLatencyProbe.hasActiveOperation()||AndroidExternalNodeComparison.hasActiveOperation(),startup=startupCapturePending||connection!=null&&connection.isStartupPending(),permission=orderedConnectCapturePending||connection!=null&&connection.isPermissionPending();connectButton.setText(startup?"Cancel startup":candidate?"Cancel test":permission?"Cancel connection":active?"Disconnect":"Connect");nodeButton.setEnabled(!busy);fastestButton.setEnabled((!busy||connection.isConnected())&&!candidate&&!permission&&!startup&&!AndroidMTUMeasurementGate.held());killSwitch.setEnabled(!busy);multihopToggle.setEnabled(!busy);modeSpinner.setEnabled(!busy&&!isExternalSelected()&&!(prefs().getBoolean(MULTI_ON,false)&&!prefs().getString("multihop_nodes","").isEmpty()));dnsSpinner.setEnabled(!busy&&!isExternalSelected());if(startup)statusView.setText("Waiting for Android permission for the captured startup path. Cancel startup keeps the app disconnected.");else if(AndroidNodeCandidatePreparation.busy())statusView.setText("Testing saved path. Cancel test waits for the temporary VPN and candidate connections to stop.");else if(permission)statusView.setText("Waiting for Android permission for the captured connection. Cancel connection keeps the app disconnected.");else if(!candidate)statusView.setText(AndroidHomeSummary.format(this,nodeStore)+multihopExecutionSummary());else if(AndroidExternalNodeComparison.hasActiveOperation())statusView.setText("Comparing captured external paths. Cancel test waits for native cleanup and original restoration.");else if(!viaEntryProbe.isBusy())statusView.setText("A captured candidate test is draining. Cancel test retries only its temporary entry cleanup.");if(!connection.isConnected()){currentPathMs=0;liveLatency.setText("-- ms");}}

    private void showConnectionDetails(){String truth=AndroidHomeSummary.format(this,nodeStore);new AlertDialog.Builder(this).setTitle("Connection details & proof").setMessage(truth+"\n\nConnected is not treated as a proved public exit until the current app-owned VPN network, frozen session node/path and current-session exit proof all agree.").setPositiveButton("Prove actual exit",(d,w)->{statusView.setText("Proving actual public VPN exit for this session…");AndroidHomeSummary.proveActualExit(this,nodeStore,(message,error)->runOnUiThread(()->{statusView.setText(message);if(error!=null)toast(message);refreshAll();}));}).setNeutralButton("Emergency disconnect",(d,w)->{statusView.setText("Emergency disconnect requested…");AndroidHomeSummary.emergencyDisconnect(this,(message,error)->runOnUiThread(()->{statusView.setText(message);if(error!=null)toast(message);refreshAll();refreshConnectionLater();}));}).setNegativeButton("Close",null).show();}

    private void showFastConnectMenu(){
        if(AndroidExternalNodeComparison.hasActiveOperation()||AndroidMTUMeasurementGate.held()||connection.isPermissionPending()||AndroidViaEntryLatencyProbe.hasActiveOperation()){toast("Finish or cancel the active measurement or permission request first.");return;}
        new AlertDialog.Builder(this).setTitle("Fastest / compare nodes").setItems(new String[]{"Router nodes • 50 TCP responses","Compare external exits • 50 routed HTTPS","Compare and connect fastest external path"},(dialog,which)->{if(which==0)showRouterFastConnectMenu();else showExternalComparison(which==2);}).setNegativeButton("Close",null).show();
    }
    private void showExternalComparison(boolean connectFastest){
        if(externalComparisonDialog!=null)externalComparisonDialog.close();
        externalComparisonDialog=new AndroidExternalComparisonDialog(this,nodeStore,exitStore,connection,this::refreshAll);
        externalComparisonDialog.show(connectFastest);
    }

    private void showRouterFastConnectMenu(){runRouterNodeComparison(true);}

    private void runRouterNodeComparison(boolean chooseNode){
        if(mutationBusy()||fastestProgressDialog!=null){toast("Disconnect/finish the current VPN operation before changing the selected fastest node.");return;}
        fastestButton.setEnabled(false);fastestButton.setText("Testing 50 TCP samples…");
        final AlertDialog progress=new AlertDialog.Builder(this).setTitle(chooseNode?"Find fastest Router node":"Compare Router nodes")
            .setMessage("Collecting 50 TCP responses per node on one captured physical network. The lowest 10% trimmed mean wins; incomplete nodes receive no score. Saved benchmark statistics are preserved.")
            .setCancelable(false).setNegativeButton("Cancel measurement",null).create();
        fastestProgressDialog=progress;
        progress.setOnDismissListener(d->{if(fastestProgressDialog==progress)telemetry.cancelFastest();});
        progress.show();
        progress.getButton(AlertDialog.BUTTON_NEGATIVE).setOnClickListener(v->{telemetry.cancelFastest();progress.setMessage("Cancelling; waiting for the captured sockets to drain…");progress.getButton(AlertDialog.BUTTON_NEGATIVE).setEnabled(false);});
        telemetry.measureFastest((values,error)->runOnUiThread(()->{
            if(fastestProgressDialog!=progress||isFinishing()||isDestroyed())return;
            fastestProgressDialog=null;progress.dismiss();fastestButton.setEnabled(true);refreshNodes();
            if(error!=null){toast("Fastest-node test failed: "+safe(error));return;}
            if(values==null||values.isEmpty()){toast("No Router node completed all 50 TCP responses.");return;}
            if(!chooseNode){
                try{StringBuilder out=new StringBuilder("50 complete TCP responses per ranked node; ordered by 10% trimmed mean. Saved statistics and node selection are unchanged.\n\n");for(AndroidTelemetry.Result result:values){result.requireCurrent();out.append(result.detail()).append('\n');}dialog("50-sample Router comparison",out.toString());refreshMap();}
                catch(Exception stale){toast(safe(stale));}
                return;
            }
            String[]labels=new String[values.size()+1];
            labels[0]="⚡ Fastest — "+values.get(0).name+String.format(Locale.US," • %.1f ms trimmed mean",values.get(0).trimmedMeanMs);
            for(int i=0;i<values.size();i++)labels[i+1]=values.get(i).name+String.format(Locale.US," • %.1f ms trimmed mean",values.get(i).trimmedMeanMs);
            choiceDialog("Select node","Each ranked node completed 50 TCP responses. Ranking uses the 10% trimmed mean, excluding five samples at each end. Selecting a Router target does not connect; use Connect when ready. Saved benchmark statistics are unchanged.").setItems(labels,(d,w)->{
                if(mutationBusy()){toast("VPN state changed while Fastest was measuring; disconnect/finish before selecting another node.");return;}
                AndroidTelemetry.Result pick=values.get(w==0?0:w-1);
                try{synchronized(prefs()){pick.requireCurrent();nodeStore.select(pick.id);AndroidConnectionProfileStore.applySelection(prefs(),prefs().edit().putString(SELECTED_KIND,"router-vpn").putString(SELECTED_ID,pick.id));}refreshAll();toast("Selected "+pick.name+". Press Connect when ready.");}catch(Exception e){toast(safe(e));}
            }).setNegativeButton("Cancel",(d,w)->telemetry.cancelFastest()).show();
        }));
    }

    private void clearCurrentTelemetry(){currentPathReceipt=null;currentExternalReceipt=null;currentPathMs=0;liveLatency.setText("-- ms");}
    private void refreshTelemetry(boolean force){
        AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(this);
        if(connection==null||!connection.isConnected()){if(externalTelemetry!=null)externalTelemetry.cancel();clearCurrentTelemetry();refreshMap();return;}
        if("external".equals(home.logicalMode)){refreshExternalTelemetry(force,home);return;}
        if(currentExternalReceipt!=null||externalTelemetry!=null&&externalTelemetry.isRunning()){externalTelemetry.cancel();clearCurrentTelemetry();refreshMap();}
        if(currentPathReceipt!=null)try{currentPathReceipt.requireCurrent();}catch(Exception stale){clearCurrentTelemetry();}
        long now=android.os.SystemClock.elapsedRealtime();
        if(!resumed||telemetryBusy||AndroidMTUMeasurementGate.held()||AndroidViaEntryLatencyProbe.hasActiveOperation()||(!force&&now-lastTelemetryAt<4500))return;
        lastTelemetryAt=now;
        telemetryBusy=true;long ticket=telemetryGeneration;
        telemetry.currentPath(2,(path,error)->runOnUiThread(()->{
            telemetryBusy=false;if(!resumed||ticket!=telemetryGeneration||isFinishing()||isDestroyed())return;
            try{if(error!=null)throw new IllegalStateException(safe(error));if(path==null)throw new IllegalStateException("No current RTT result.");path.requireCurrent();currentPathReceipt=path;currentPathMs=path.medianMs;liveLatency.setText(String.format(Locale.US,"%.1f ms",path.medianMs));}
            catch(Exception stale){clearCurrentTelemetry();}
            refreshMultihopSummary();
        }));
    }
    private void refreshExternalTelemetry(boolean force,AndroidHomeStateStore.Snapshot home){
        if(currentPathReceipt!=null)clearCurrentTelemetry();
        if(currentExternalReceipt!=null)try{currentExternalReceipt.requireCurrent();}catch(Exception stale){clearCurrentTelemetry();refreshMap();}
        long now=android.os.SystemClock.elapsedRealtime();
        if(!resumed||telemetryBusy||externalTelemetry==null||externalTelemetry.isRunning()||AndroidMTUMeasurementGate.held()||AndroidViaEntryLatencyProbe.hasActiveOperation()||AndroidExternalNodeComparison.hasActiveOperation()||(!force&&now-lastTelemetryAt<4500))return;
        lastTelemetryAt=now;telemetryBusy=true;long ticket=telemetryGeneration;
        externalTelemetry.measure(home.activeExternalId,(result,error)->runOnUiThread(()->{
            telemetryBusy=false;if(!resumed||ticket!=telemetryGeneration||isFinishing()||isDestroyed())return;
            try{if(error!=null)throw new IllegalStateException(safe(error));if(result==null)throw new IllegalStateException("No current HTTPS response.");result.requireCurrent();currentExternalReceipt=result;currentPathReceipt=null;currentPathMs=result.medianMs;liveLatency.setText(String.format(Locale.US,"%.1f ms HTTPS",result.medianMs));}
            catch(Exception stale){clearCurrentTelemetry();}
            refreshMultihopSummary();refreshMap();
        }));
    }
    private double liveExternalMedian(String id){
        if(currentExternalReceipt==null||!currentExternalReceipt.id.equals(id))return 0;
        try{currentExternalReceipt.requireCurrent();return currentExternalReceipt.medianMs;}catch(Exception stale){return 0;}
    }
    private void showLiveTelemetry(){
        if(!connection.isConnected()){toast("Connect first for a current path response.");return;}
        if("external".equals(AndroidHomeStateStore.snapshot(this).logicalMode)){
            try{if(currentExternalReceipt==null)throw new IllegalStateException("Measuring the current path. The HTTPS value appears beside Disconnect when all three responses complete.");currentExternalReceipt.requireCurrent();dialog("Live HTTPS path response",currentExternalReceipt.detail());}
            catch(Exception stale){clearCurrentTelemetry();refreshTelemetry(true);dialog("Live HTTPS path response","Three responses use the current proved VPN path and its selected DNS. Timing starts after DNS, TCP and TLS preparation. This is a public HTTPS response, separate from ICMP RTT and saved 50-sample statistics.\n\n"+safe(stale));}
            return;
        }
        telemetry.currentPath(5,(r,e)->runOnUiThread(()->{
            if(isFinishing()||isDestroyed())return;
            try{if(e!=null)throw new IllegalStateException(safe(e));r.requireCurrent();dialog("Live tunnel RTT",String.format(Locale.US,"Median %.1f ms • %d ok / %d failed\n%s",r.medianMs,r.samples,r.failed,r.proof));}
            catch(Exception stale){dialog("Live tunnel RTT",safe(stale));}
        }));
    }
    private void refreshMultihopTelemetry(){refreshMultihopSummary();}

    private void showPerformance(){
        String[] actions={"Live current path response","50-sample selected node","Compare all Router nodes (50 TCP)","Real current VPN path speed","Routed multihop speeds","Path throughput / Auto MTU status","Last saved 50-sample statistics","Compare all external exits (50 HTTPS)","Compare and connect fastest external path","Test candidates through a saved or connected prefix"};
        choiceDialog("Performance","Router node benchmarks use direct TCP while disconnected. A selected external node uses 50 HTTPS responses through its connected, proved native path and selected DNS. These saved measurement types remain separate; external HTTPS results do not enter direct TCP Fastest or Lowest latency rankings. Current-path RTT and throughput are separate actions.").setItems(actions,(d,w)->{
            if(w==0){showLiveTelemetry();
            }else if(w==1){
                if(isExternalSelected()){runExternalBenchmark();return;}
                try{AndroidNodeStore.Node n=nodeById(nodeStore.activeId());if(n==null)throw new IllegalStateException("Select a Router VPN node first.");toast("Running 50 direct TCP samples…");
                    telemetry.measureNode(n,50,(r,e)->runOnUiThread(()->{if(isFinishing()||isDestroyed())return;try{if(e!=null)throw new IllegalStateException(safe(e));r.requireCurrent();dialog("50-sample node benchmark",r.detail()+"\n\n"+(r.samples==50&&r.failed==0?"Saved with this exact node source. Lowest latency uses only complete successful 50-sample records.":"Incomplete run was not saved. The previous complete 50-sample benchmark is retained."));refreshMap();}catch(Exception stale){toast(safe(stale));}}));
                }catch(Exception e){toast(safe(e));}
            }else if(w==2){
                runRouterNodeComparison(false);
            }else if(w==3){runCurrentSpeed();}
            else if(w==4){runRoutedHopSpeeds();}
            else if(w==6){showSavedStatistics();}
            else if(w==7){showExternalComparison(false);}
            else if(w==8){showExternalComparison(true);}
            else if(w==9){runCandidateTimes();}
            else{JSONObject p=activeRouterProfile();if(p==null){toast("Select a Router VPN node first.");return;}double mbps=p.optDouble("effective_mtu_mbps",0),rtt=p.optDouble("effective_mtu_median_rtt_ms",0);int mtu=p.optInt("effective_mtu",0);String value=mbps>0?String.format(Locale.US,"Last MTU-path optimizer result: %.1f Mbps • MTU %d • RTT %.1f ms\n\nThis is separate from the real 8 MiB down/up path speed test.",mbps,mtu,rtt):"No proven Auto-MTU optimizer result is stored for this path yet. Open Settings / MTU to configure Auto or Fixed MTU. Real path Mbps is a separate Performance action.";dialog("Path throughput / Auto MTU",value);}
        }).setNegativeButton("Close",null).show();
    }

    private void runCurrentSpeed(){
        if(!connection.isConnected()){toast("Connect Router VPN before testing current path speed.");return;}
        if(currentSpeedDialog!=null){toast("Finish or cancel the current speed test first.");return;}
        AlertDialog progress=new AlertDialog.Builder(this).setTitle("Current VPN path speed").setMessage("Verifying the exact private Router identity, then transferring 8 MiB down and 8 MiB up through its captured VPN network. MTU work remains paused until all test sockets have drained.").setNegativeButton("Cancel test",(d,w)->telemetry.cancelCurrent()).create();
        currentSpeedDialog=progress;progress.setOnDismissListener(d->{if(currentSpeedDialog==progress){currentSpeedDialog=null;telemetry.cancelCurrent();}});progress.show();
        telemetry.speedTest(8<<20,(result,error)->runOnUiThread(()->{
            if(currentSpeedDialog!=progress||isFinishing()||isDestroyed())return;currentSpeedDialog=null;progress.dismiss();
            try{if(error!=null)throw new IllegalStateException(safe(error));result.requireCurrent();dialog("Real VPN path speed",result.detail()+"\n\nExact Router identity proved before sending credentials. The native session, full node sources and Android network were rechecked; owned sockets are closed.");}
            catch(Exception stale){dialog("Real VPN path speed",safe(stale));}
        }));
    }

    private void showSavedStatistics(){
        if(isExternalSelected()){
            try{String id=prefs().getString(SELECTED_ID,"");AndroidStandardExitStore.Entry exit=exitStore.get(id);AndroidExternalNodeStatistics.Record result=AndroidExternalNodeStatistics.load(this,id);
                dialog("Saved HTTPS statistics • "+exit.name,result==null?"No complete 50-sample routed HTTPS result is saved for this external node and its exact saved path sources. Connect this node, then use Performance → 50-sample selected node. Direct TCP rankings are separate.":result.detail());
            }catch(Exception error){toast(safe(error));}return;
        }
        try{AndroidNodeStore.Node node=nodeById(nodeStore.activeId());if(node==null)throw new IllegalStateException("Select a Router VPN node first.");AndroidNodeStatistics.Record result=telemetry.savedStatistics(node);
            dialog("Saved node statistics • "+node.name,result==null?"No valid 50-attempt direct benchmark is saved for this exact node source. Run Performance → 50-sample selected node while disconnected. Reimported or changed sources invalidate their previous statistics.":result.detail());
        }catch(Exception error){toast(safe(error));}
    }

    private void runExternalBenchmark(){
        if(externalBenchmarkDialog!=null)externalBenchmarkDialog.close();
        externalBenchmarkDialog=new AndroidExternalBenchmarkDialog(this,prefs().getString(SELECTED_ID,""));externalBenchmarkDialog.show();
    }

    private void showNodeSort(){
        choiceDialog("Node order","Lowest latency ranks only source-matching saved 50-sample direct benchmarks with no failed samples. Quick RTT and current VPN measurements cannot replace them.")
            .setItems(new String[]{"Current node first","Last used","Name","Lowest latency order","Select lowest measured latency","Most used"},(d,w)->{
                if(w==4){if(mutationBusy()){toast("Disconnect/finish before changing the selected node.");return;}try{AndroidUnifiedNodeCatalog.Item lowest=catalog.lowestLatency();if(lowest==null){toast("Measure at least two Router nodes with 50 successful samples first.");return;}selectCatalog(lowest);toast("Selected "+lowest.name+" from saved 50-sample trimmed means. Saved times/networks may differ; use Fastest for a current comparison. Press Connect when ready.");}catch(Exception error){toast(safe(error));}return;}
                if(w==5){AndroidConnectionProfileStore.applySelection(prefs(),prefs().edit().putString("node_sort",AndroidUnifiedNodeCatalog.SORT_MOST_USED));showNodes();return;}
                AndroidConnectionProfileStore.applySelection(prefs(),prefs().edit().putString("node_sort",new String[]{AndroidUnifiedNodeCatalog.SORT_CURRENT,AndroidUnifiedNodeCatalog.SORT_LAST_USED,AndroidUnifiedNodeCatalog.SORT_NAME,AndroidUnifiedNodeCatalog.SORT_LATENCY}[w]));showNodes();
            }).setNegativeButton("Close",null).show();
    }

    private void runCandidateTimes(){closeCandidateMeasurement();detachCandidatePreparation();if(AndroidNodeCandidatePreparation.retained()!=null||!connection.isConnected()){preparedCandidateDialog=new AndroidNodeCandidatePreparationDialog(this,nodeStore,connection,this::refreshConnectionLater);preparedCandidateDialog.show();}else{candidateDialog=new AndroidNodeCandidateDialog(this);candidateDialog.show();}}
    private void resumeCandidatePreparation(){if(AndroidNodeCandidatePreparation.retained()!=null){detachCandidatePreparation();preparedCandidateDialog=new AndroidNodeCandidatePreparationDialog(this,nodeStore,connection,this::refreshConnectionLater);preparedCandidateDialog.show();}}
    private void detachCandidatePreparation(){if(preparedCandidateDialog!=null){preparedCandidateDialog.detach();preparedCandidateDialog=null;}}

    private void closeCandidateMeasurement(){AndroidNodeCandidateDialog owned=candidateDialog;candidateDialog=null;if(owned!=null)owned.close();}

    private void runRoutedHopSpeeds(){
        if(!connection.isMultihopConnected()){toast("Connect the actual Android multihop graph before testing routed hop speeds.");return;}
        closeRoutedHopMeasurement();
        routedHopDialog=new AndroidHopMeasurementDialog(this,connection);
        routedHopDialog.show();
    }

    private void closeRoutedHopMeasurement(){
        AndroidHopMeasurementDialog owned=routedHopDialog;routedHopDialog=null;
        if(owned!=null)owned.close();
    }

    private void refreshModeChoices(){
        if(orderedPathEnabled()) {
            modeSpinner.setOnItemSelectedListener(null);modeChoices=new ArrayList<>();modeChoices.add(new ModeChoice("node-chain","Per-hop transports • ordered path"));
            modeSpinner.setAdapter(new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,modeChoices));modeSpinner.setSelection(0,false);modeSpinner.setEnabled(false);
            modeHint.setText("Each ordered node keeps its selected transport. Use Edit hops to change the path; the single-node mode is remembered separately.");return;
        }
        AndroidUnifiedNodeCatalog.Item external=selectedCatalogItem();if(external!=null&&!external.isRouterVpn()){modeSpinner.setOnItemSelectedListener(null);modeChoices=new ArrayList<>();modeChoices.add(new ModeChoice("external",external.protocol+" • saved external protocol"));modeSpinner.setAdapter(new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,modeChoices));modeSpinner.setSelection(0,false);modeHint.setText("Saved external protocol and path; edit DNS and device policy in Settings.");return;}String wanted=prefs().getString(MODE_KEY,"smart-auto");List<ModeChoice> values=new ArrayList<>();values.add(new ModeChoice("smart-auto","SMART AUTO — recommended"));values.add(new ModeChoice("auto","AUTO — first proven path"));try{JSONObject root=activeBundle();JSONArray logical=root.optJSONArray("logicalModes");if(logical!=null)for(int i=0;i<logical.length();i++){JSONObject m=logical.optJSONObject(i);if(m==null)continue;String id=m.optString("id","");if(id.isEmpty())continue;values.add(new ModeChoice(id,m.optString("name",id)));}}catch(Exception ignored){}for(CustomPreset p:loadCustomPresets())values.add(new ModeChoice("custom:"+p.name,"CUSTOM • "+p.name,p.layers));values.add(new ModeChoice("custom:new","New CUSTOM preset…"));modeChoices=values;ArrayAdapter<ModeChoice> adapter=new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,values);modeSpinner.setAdapter(adapter);int index=0;for(int i=0;i<values.size();i++)if(values.get(i).id.equals(wanted)){index=i;break;}modeSpinner.setSelection(index,false);modeSpinner.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener(){boolean ready;public void onNothingSelected(android.widget.AdapterView<?>p){}public void onItemSelected(android.widget.AdapterView<?>p,View v,int pos,long id){if(!ready){ready=true;return;}if(pos<0||pos>=modeChoices.size())return;if(mutationBusy()){toast("Disconnect/finish the current VPN operation before changing the next connection mode or CUSTOM preset.");refreshModeChoices();return;}ModeChoice selected=modeChoices.get(pos);if("custom:new".equals(selected.id)){showCustomBuilder(null);return;}AndroidConnectionProfileStore.applySelection(prefs(),prefs().edit().putString(MODE_KEY,selected.id));modeHint.setText(selected.id.startsWith("custom:")?"Saved visual CUSTOM preset • exact required layers":"Unavailable presets remain visible; the engine fails closed with the exact readiness/proof reason.");}});}
    private ModeChoice currentMode(){if(modeSpinner==null||modeChoices.isEmpty())return null;int i=modeSpinner.getSelectedItemPosition();return i>=0&&i<modeChoices.size()?modeChoices.get(i):modeChoices.get(0);}
    private void showCustomPresetManager() {
        List<CustomPreset> presets = loadCustomPresets();
        List<String> labels = new ArrayList<>();
        labels.add("Mode catalog / availability"); labels.add("New CUSTOM preset");
        for (CustomPreset preset : presets) labels.add("Edit CUSTOM • " + preset.name);
        new AlertDialog.Builder(this).setTitle("Presets / CUSTOM")
            .setItems(labels.toArray(new CharSequence[0]), (d, which) -> {
                if (which == 0) AndroidProductParity.showModes(this, nodeStore);
                else showCustomBuilder(which == 1 ? null : presets.get(which - 2));
            }).setNegativeButton("Cancel", null).show();
    }

    private void showCustomBuilder(CustomPreset editing) {
        if (mutationBusy()) { toast("Disconnect/finish the current VPN operation before creating, editing or deleting CUSTOM presets."); return; }
        try {
            List<String> catalog = allCatalogLayers();
            List<String> layers = AndroidCustomPresetCommit.editableLayers(catalog, editing == null ? Collections.emptyList() : editing.layers);
            List<String> layerLabels = new ArrayList<>();
            for (String layer : layers) layerLabels.add(catalog.contains(layer) ? layer : layer + " — not in this catalog");
            if (layers.isEmpty()) { toast("No mode layers are available in the selected Router VPN bundle."); return; }
            LinearLayout body = new LinearLayout(this); body.setOrientation(LinearLayout.VERTICAL);
            body.setPadding(dp(18), dp(8), dp(18), 0);
            EditText name = new EditText(this); name.setHint("Preset name");
            if (editing != null) name.setText(editing.name);
            body.addView(name);
            body.addView(text("Choose exact required layers. Save never connects. Save & Connect requires a Router VPN node with Multihop off; incompatible stacks fail closed.", 12, false));
            Button delete = smallButton("Delete preset");
            if (editing != null) body.addView(delete);
            boolean[] checked = new boolean[layers.size()];
            Set<String> old = editing == null ? Collections.emptySet() : new LinkedHashSet<>(editing.layers);
            for (int i = 0; i < layers.size(); i++) checked[i] = old.contains(layers.get(i));
            AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(editing == null ? "New CUSTOM preset" : "Edit CUSTOM • " + editing.name)
                .setView(body).setMultiChoiceItems(layerLabels.toArray(new CharSequence[0]), checked, (d, w, on) -> checked[w] = on)
                .setPositiveButton("Save & Connect", null).setNeutralButton("Save", null)
                .setNegativeButton("Cancel", null).create();
            dialog.setOnShowListener(x -> {
                dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v -> saveCustomBuilder(dialog, name, layers, checked, editing, false));
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> saveCustomBuilder(dialog, name, layers, checked, editing, true));
            });
            if (editing != null) delete.setOnClickListener(v -> {
                if (mutationBusy()) { toast("VPN state changed; disconnect/finish before deleting CUSTOM presets."); return; }
                try { deleteCustomPreset(editing.name); dialog.dismiss(); refreshModeChoices(); }
                catch (Exception error) { toast(safe(error)); }
            });
            dialog.show();
        } catch (Exception error) { toast("CUSTOM builder unavailable: " + safe(error)); }
    }

    private void saveCustomBuilder(AlertDialog dialog, EditText name, List<String> layers,
                                   boolean[] checked, CustomPreset editing, boolean connect) {
        if (mutationBusy()) { toast("VPN state changed; disconnect/finish before saving CUSTOM presets."); return; }
        String clean = name.getText().toString().trim();
        List<String> selected = new ArrayList<>();
        for (int i = 0; i < checked.length; i++) if (checked[i]) selected.add(layers.get(i));
        if (!AndroidCustomPresetCommit.validName(clean)) { toast("Use a safe 1–64 character preset name, not new."); return; }
        if (selected.isEmpty()) { toast("CUSTOM requires at least one layer."); return; }
        CustomPreset preset = new CustomPreset(clean, selected);
        try { saveCustomPreset(preset, editing == null ? null : editing.name); }
        catch (Exception error) { toast(safe(error)); return; }
        dialog.dismiss(); refreshModeChoices();
        if (connect) connectSavedCustomPreset(preset);
    }

    private void connectSavedCustomPreset(CustomPreset preset) {
        if (isFinishing() || isDestroyed() || mutationBusy()) { toast("Preset saved; VPN state changed, so no new connection was started."); return; }
        AndroidUnifiedNodeCatalog.Item node = selectedCatalogItem();
        if (node == null || !node.isRouterVpn() || multihopToggle.isChecked()) {
            toast("Preset saved. Save & Connect requires a Router VPN node with Multihop off; no other graph was substituted."); return;
        }
        try {
            AndroidNodeStore.Node target = nodeById(node.id);
            if (target == null) throw new IllegalStateException("The selected Router VPN node is no longer available.");
            statusView.setText("Preparing CUSTOM • " + preset.name + "…");
            connection.connectNode(target, "custom:" + preset.name, new ArrayList<>(preset.layers), callback());
        } catch (Exception error) { toast("Preset saved; connection not started: " + safe(error)); }
    }

    private void refreshNodes(){
        if(catalog==null||mapView==null)return;
        try {
            List<AndroidUnifiedNodeCatalog.Item> items=catalog.list(AndroidUnifiedNodeCatalog.SORT_CURRENT);
            String selectedKind,selectedId;
            synchronized(prefs()) {
                selectedKind=prefs().getString(SELECTED_KIND,"router-vpn");selectedId=prefs().getString(SELECTED_ID,nodeStore.activeId());
                if(selectedId.isEmpty()&&!items.isEmpty()&&!mutationBusy()) {
                    AndroidUnifiedNodeCatalog.Item first=items.get(0);selectedKind=first.kind;selectedId=first.id;
                    if(first.isRouterVpn())nodeStore.select(first.id);
                    AndroidConnectionProfileStore.applySelection(prefs(),prefs().edit().putString(SELECTED_KIND,selectedKind).putString(SELECTED_ID,selectedId));
                }
            }
            List<String> ordered=new ArrayList<>();AndroidOrderedPathPresentation presentation=currentOrderedPresentation();boolean liveOrdered=presentation!=null&&presentation.live;
            if(presentation!=null) {
                for(AndroidOrderedPathPresentation.Member member:presentation.members)ordered.add(member.id);
                selectedKind="router-vpn";selectedId=ordered.get(ordered.size()-1);
            }
            String entry,exit,entryKind="router-vpn";boolean multi;
            if(connection.isMultihopConnected()) {
                entry=connection.activeMultihopEntryId();exit=connection.activeMultihopExitId();entryKind=connection.activeImportedMultihopEntry()==null?"router-vpn":"external";multi=true;
            } else {
                entry=prefs().getString(MULTI_ENTRY,"");exit=prefs().getString(MULTI_EXIT,"");multi=prefs().getBoolean(MULTI_ON,false);entryKind=prefs().getString("multihop_entry_kind","router-vpn");
            }
            List<RouterVpnNodeMapView.Marker> markers=new ArrayList<>();AndroidUnifiedNodeCatalog.Item chosen=null;
            for(AndroidUnifiedNodeCatalog.Item item:items) {
                if(item.kind.equals(selectedKind)&&item.id.equals(selectedId))chosen=item;
                if(!item.hasCoordinates())continue;
                int position=item.isRouterVpn()?ordered.indexOf(item.id):-1;String role;
                if(position>=0)role=position==0?RouterVpnNodeMapView.ROLE_ENTRY:position==ordered.size()-1?RouterVpnNodeMapView.ROLE_EXIT:RouterVpnNodeMapView.ROLE_HOP;
                else if(ordered.isEmpty()&&multi&&item.kind.equals(entryKind)&&item.id.equals(entry))role=RouterVpnNodeMapView.ROLE_ENTRY;
                else if(ordered.isEmpty()&&multi&&item.kind.equals(selectedKind)&&item.id.equals(exit))role=RouterVpnNodeMapView.ROLE_EXIT;
                else if(item.id.equals(selectedId)&&item.kind.equals(selectedKind))role=RouterVpnNodeMapView.ROLE_SELECTED;
                else if(!item.isRouterVpn())role=RouterVpnNodeMapView.ROLE_EXTERNAL;
                else role=RouterVpnNodeMapView.ROLE_NORMAL;
                double ms=position>=0?presentation.members.get(position).httpResponseMs:item.isRouterVpn()?(telemetry==null?0:telemetry.cachedMedian(item.id)):liveExternalMedian(item.id);
                if(position<0&&ms<=0&&item.hasMeasuredLatency())ms=item.latencyMedianMs;
                String name=(position>=0?(presentation.testing?"Testing • ":"")+(position+1)+". ":"")+item.name+(!item.isRouterVpn()&&ms>0?" • HTTPS":"");
                if(position>=0&&ms>0)name+=" • routed HTTP proof";
                markers.add(new RouterVpnNodeMapView.Marker(item.kind+":"+item.id,name,item.latitude,item.longitude,role,ms,!item.isRouterVpn()));
            }
            List<String> mapOrder=new ArrayList<>();for(String id:ordered)mapOrder.add("router-vpn:"+id);
            mapView.setMarkers(markers);mapView.setOrderedPath(mapOrder,liveOrdered);
            double chosenMs=presentation!=null?0:chosen==null?0:!chosen.isRouterVpn()?liveExternalMedian(chosen.id):telemetry!=null?telemetry.cachedMedian(chosen.id):chosen.hasMeasuredLatency()?chosen.latencyMedianMs:0;
            nodeButton.setText(chosen==null?"Add / select node":(chosen.isRouterVpn()?"Router • ":"Custom • ")+chosen.name+(chosen.location.isEmpty()?"":" • "+chosen.location)+(chosenMs>0?String.format(Locale.US," • %.1f ms%s",chosenMs,chosen.isRouterVpn()?"":" HTTPS"):"")+"  ▾");
            if(fastestButton!=null)fastestButton.setText(chosen==null?"⚡ Fastest ▾":"⚡ "+chosen.name+" ▾");
        } catch(Exception error) {
            nodeButton.setText("Node catalog unavailable");if(fastestButton!=null)fastestButton.setText("⚡ Fastest ▾");mapView.setMarkers(new ArrayList<>());mapView.setOrderedPath(new ArrayList<>(),false);
        }
    }
    private void refreshMap(){refreshNodes();}
    private AndroidUnifiedNodeCatalog.Item selectedCatalogItem(){try{String kind=prefs().getString(SELECTED_KIND,"router-vpn"),id=prefs().getString(SELECTED_ID,nodeStore.activeId());for(AndroidUnifiedNodeCatalog.Item item:catalog.list(AndroidUnifiedNodeCatalog.SORT_CURRENT))if(item.kind.equals(kind)&&item.id.equals(id))return item;}catch(Exception ignored){}return null;}
    private void selectCatalog(String kind,String id){try{for(AndroidUnifiedNodeCatalog.Item item:catalog.list(AndroidUnifiedNodeCatalog.SORT_CURRENT))if(item.kind.equals(kind)&&item.id.equals(id)){selectCatalog(item);return;}}catch(Exception error){toast(safe(error));}}
    private void selectCatalog(AndroidUnifiedNodeCatalog.Item item){if(mutationBusy()){toast("Disconnect/finish the current VPN operation before changing the selected node; live/probe identity is frozen.");return;}try{synchronized(prefs()){if(item.isRouterVpn())nodeStore.select(item.id);android.content.SharedPreferences.Editor selected=prefs().edit().putString(SELECTED_KIND,item.kind).putString(SELECTED_ID,item.id);if(!item.kind.equals(prefs().getString(SELECTED_KIND,""))||!item.id.equals(prefs().getString(SELECTED_ID,"")))selected.putBoolean(MULTI_ON,false).putString(MULTI_ENTRY,"").putString(MULTI_EXIT,"").putString("multihop_nodes","");AndroidConnectionProfileStore.applySelection(prefs(),selected);}refreshAll();}catch(Exception error){toast(safe(error));}}
    private void showNodes(){try{List<AndroidUnifiedNodeCatalog.Item>items=catalog.list(prefs().getString("node_sort",AndroidUnifiedNodeCatalog.SORT_CURRENT));if(items.isEmpty()){new AlertDialog.Builder(this).setTitle("Nodes").setMessage("No nodes yet. Pair a Router securely on your LAN, import its complete JSON bundle, or add a Custom / external exit.").setPositiveButton("Add Router node",(d,w)->showAddRouter()).setNeutralButton("Add custom",(d,w)->openStandardExits()).setNegativeButton("Close",null).show();return;}String[]labels=new String[items.size()];for(int i=0;i<items.size();i++){AndroidUnifiedNodeCatalog.Item item=items.get(i);double ms=item.hasMeasuredLatency()?item.latencyMedianMs:item.isRouterVpn()?telemetry.cachedMedian(item.id):0;labels[i]=(item.isRouterVpn()?"Router • ":"Custom • ")+item.name+(item.location.isEmpty()?"":" • "+item.location)+(!item.usageAvailable?" • usage unavailable":item.useCount>0?" • used "+item.useCount:"")+(ms>0?String.format(Locale.US,item.hasMeasuredLatency()?" • %.1f ms / 50 samples":" • quick %.1f ms",ms):"")+(item.hasCoordinates()?"":" • list only");}choiceDialog("Choose node",mutationBusy()?"The current live/probe identity is frozen. Disconnect/finish before selecting another node.":"One node is selected by default. Only real stored coordinates appear on the globe; no IP geolocation/fake pins.").setItems(labels,(d,w)->selectCatalog(items.get(w))).setPositiveButton("Add Router node",(d,w)->showAddRouter()).setNeutralButton("Sort / Lowest latency",(d,w)->showNodeSort()).setNegativeButton("Close",null).show();}catch(Exception error){toast(safe(error));}}

    private void showConnectionProfiles(){
        AndroidConnectionProfilesDialog.show(this,nodeStore,exitStore,this::refreshAll);
    }

    private void showProfileManager(){try{List<AndroidNodeStore.Node>nodes=nodeStore.list();if(nodes.isEmpty()){new AlertDialog.Builder(this).setTitle("Profiles").setMessage("No Router VPN profiles are stored. Pair/import one, or open Custom exits for standard external profiles.").setPositiveButton("Add Router",(d,w)->showAddRouter()).setNeutralButton("Custom exits",(d,w)->openStandardExits()).setNegativeButton("Close",null).show();return;}String[]labels=new String[nodes.size()];for(int i=0;i<nodes.size();i++)labels[i]=(nodes.get(i).id.equals(nodeStore.activeId())?"✓ ":"")+nodes.get(i).name+(telemetry.cachedMedian(nodes.get(i).id)>0?String.format(Locale.US," • %.1f ms",telemetry.cachedMedian(nodes.get(i).id)):"");choiceDialog("Router profiles","Select, update/re-pair, benchmark or delete. Re-pairing the same stable node identity updates its stored profile rather than creating a duplicate. Live sessions freeze profile identity until disconnect.").setItems(labels,(d,w)->showProfileActions(nodes.get(w))).setPositiveButton("Add / update Router",(d,w)->showAddRouter()).setNeutralButton("Custom profiles",(d,w)->openStandardExits()).setNegativeButton("Close",null).show();}catch(Exception e){toast(safe(e));}}
    private void showProfileActions(AndroidNodeStore.Node node){String[]a={"Select","50-sample benchmark","Update / re-pair","Delete"};new AlertDialog.Builder(this).setTitle(node.name).setItems(a,(d,w)->{try{if(w==0){if(mutationBusy()){toast("Disconnect/finish before selecting another Router profile.");return;}synchronized(prefs()){nodeStore.select(node.id);AndroidConnectionProfileStore.applySelection(prefs(),prefs().edit().putString(SELECTED_KIND,"router-vpn").putString(SELECTED_ID,node.id));}refreshAll();}else if(w==1){toast("Running 50 samples…");telemetry.measureNode(node,50,(r,e)->runOnUiThread(()->{if(isFinishing()||isDestroyed())return;try{if(e!=null)throw new IllegalStateException(safe(e));r.requireCurrent();dialog("Profile benchmark",r.detail()+"\n\n"+(r.samples==50&&r.failed==0?"Complete benchmark saved for Lowest latency.":"Incomplete run was not saved; the previous complete benchmark is retained."));refreshAll();}catch(Exception stale){toast(safe(stale));}}));}else if(w==2)showPairDialog();else new AlertDialog.Builder(this).setTitle("Delete "+node.name+"?").setMessage("Only this app-private Router VPN profile is removed.").setPositiveButton("Delete",(x,y)->{if(mutationBusy()){toast("Disconnect/finish before deleting a Router profile.");return;}try{nodeStore.remove(node.id);refreshAll();}catch(Exception e){toast(safe(e));}}).setNegativeButton("Cancel",null).show();}catch(Exception e){toast(safe(e));}}).setNegativeButton("Close",null).show();}

    private void chooseMultihopExecution(AndroidNodeStore.Node entry,AndroidNodeStore.Node exit,String mode,AndroidViaEntryLatencyProbe.Result selection){
        try{selection.requireCurrent();}catch(Exception stale){toast(safe(stale));return;}
        new AlertDialog.Builder(this).setTitle("Entry transport")
            .setItems(new String[]{"WireGuard","AmneziaWG Fast","AmneziaWG Strong","WireGuard + Rosenpass PQ","AmneziaWG + Rosenpass PQ","Shadowsocks","Hysteria2","Naive H2","Naive H3","Shadowsocks + WebSocket / Hysteria2","Split TLS / QUIC","MAX TLS / QUIC","REALITY Vision","PQ REALITY Vision","REALITY XHTTP","MAX TLS / WG-PQ","MAX TLS / AWG-PQ","MAX QUIC / WG-PQ","MAX QUIC / AWG-PQ"},(dialog,index)->chooseMultihopExecution(entry,exit,mode,new String[]{"wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","naive-h2","naive-h3","ss-v2ray","split","max","reality-vision","reality-pq-vision","reality-xhttp","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"}[index],selection))
            .setNegativeButton("Cancel",null).show();
    }
    private void chooseMultihopExecution(AndroidNodeStore.Node entry,AndroidNodeStore.Node exit,String mode,String entryMode,AndroidViaEntryLatencyProbe.Result selection){
        try{selection.requireCurrent();}catch(Exception stale){toast(safe(stale));return;}
        choiceDialog("Multihop execution","Local keeps the exit tunnel on this device. Server trusts the entry to run its paired exit. Compare uses (last-node + same random external-server response time) / 2; either timeout rejects that candidate.")
            .setItems(new String[]{"Local — device-owned exit","Server — entry-owned exit","Compare both — lower valid average"},(dialog,index)->{
                if(mutationBusy()){toast("VPN state changed; finish before saving.");return;}
                try{selection.requireCurrent();}catch(Exception stale){toast(safe(stale));return;}
                AndroidConnectionProfileStore.applySelection(prefs(),prefs().edit().putBoolean(MULTI_ON,true).putString("multihop_nodes","").putString("multihop_entry_kind","router-vpn").putString(MULTI_ENTRY,entry.id).putString(MULTI_EXIT,exit.id).putString(MULTI_MODE,mode).putString("multihop_entry_mode",entryMode).putString("multihop_execution",new String[]{"local","server","auto"}[index]));
                multihopToggle.setChecked(true);refreshAll();
            }).setNegativeButton("Cancel",null).show();
    }
    private String multihopExecutionSummary(){
        try{String raw=LayeredVpnService.multihopProgressJSON();if(raw.isEmpty()||raw.length()>16384)return "";
            JSONObject value=new JSONObject(raw);StringBuilder text=new StringBuilder("\nMultihop: ").append(value.optString("stage","pending")).append(" • ").append(value.optString("execution","comparing"));
            org.json.JSONArray rows=value.optJSONArray("measurements");
            if(rows!=null)for(int i=0;i<Math.min(rows.length(),64);i++){
                JSONObject row=rows.getJSONObject(i),candidate=row.optJSONObject("candidate");String name=candidate==null?"candidate":candidate.optString("execution","candidate");
                double last=row.optDouble("last_node_ms",Double.NaN),external=row.optDouble("external_ms",Double.NaN),score=row.optDouble("score_ms",Double.NaN);
                text.append("\n").append(name).append(": ");
                if(row.optBoolean("eligible")&&Double.isFinite(last)&&Double.isFinite(external)&&Double.isFinite(score)&&last>0&&external>0&&score>0)text.append(String.format(java.util.Locale.US,"(%.1f + %.1f) / 2 = %.1f ms",last,external,score));
                else text.append("rejected — ").append(row.optString("failure","probe failed"));
            }return text.toString();
        }catch(Exception ignored){return "";}
    }
    private void configureMultihop(){
        if(mutationBusy()){toast("Disconnect/finish the current VPN operation before editing its nodes.");return;}
        if(isExternalSelected()){configurePairMultihop();return;}
        choiceDialog("Choose multihop path","Keep each selected node's own keys, Start Layer, DNS and MTU policy. Saving changes the selected path; Connect starts it separately.")
                .setItems(new String[]{"Ordered Router nodes — add and reorder hops","Two nodes / imported entry — Local, Server or Compare"},(d,w)->{
                    if(w==1){configurePairMultihop();return;}
                    try{showOrderedEditor(new AndroidOrderedPathSelection(nodeStore,new AndroidConnectionProfileStore(this,nodeStore,exitStore)));}
                    catch(Exception error){toast(safe(error));}
                }).setNegativeButton("Cancel",null).show();
    }

    private void showOrderedEditor(AndroidOrderedPathSelection draft){
        try {
            if(mutationBusy())throw new IllegalStateException("Finish the current VPN operation before editing its ordered nodes.");
            draft.requireCurrent();List<AndroidOrderedPathSelection.Member> members=draft.members();
            List<String> labels=new ArrayList<>();
            for(int i=0;i<members.size();i++) {
                AndroidOrderedPathSelection.Member member=members.get(i);
                String name=member.source.profile().optString("name",member.source.profileId);
                labels.add((i+1)+". "+name+" • "+(i==members.size()-1?"Final • Shadowsocks 2022":AndroidOrderedPathSelection.prefixModeTitle(member.mode)));
            }
            if(members.isEmpty())labels.add("Choose final Router node");
            else if(members.size()<8)labels.add("Add another intermediate node");
            choiceDialog("Ordered Router path", "Local execution supports two to eight independent nodes: WireGuard, AmneziaWG Fast or AmneziaWG Strong intermediate hops and a Shadowsocks 2022 final. Tap an intermediate hop to change its transport, reorder or remove it, or tap the final node to replace it. The final node supplies the selected DNS; every node keeps its own Start Layer and MTU choice.")
                    .setItems(labels.toArray(new CharSequence[0]),(d,w)->{
                        if(members.isEmpty()){chooseOrderedNode(draft,true);return;}
                        if(w==members.size()){chooseOrderedNode(draft,false);return;}
                        if(w==members.size()-1){chooseOrderedNode(draft,true);return;}
                        editOrderedPrefix(draft,w);
                    }).setPositiveButton("Save path",(d,w)->{
                        try{if(mutationBusy())throw new IllegalStateException("The VPN state changed before saving the ordered path.");draft.save();refreshAll();statusView.setText("Ordered path saved. Press Connect to prove every selected node.");}
                        catch(Exception error){toast(safe(error));}
                    }).setNegativeButton("Cancel",null).show();
        } catch(Exception error) { toast(safe(error)); }
    }

    private void chooseOrderedNode(AndroidOrderedPathSelection draft,boolean finalNode){
        try {
            if(mutationBusy())throw new IllegalStateException("Finish the current VPN operation before choosing another node.");
            List<AndroidNodeStore.Node> nodes=draft.choices(finalNode);List<String> labels=new ArrayList<>();
            for(AndroidNodeStore.Node node:nodes)labels.add(node.name);
            if(nodes.isEmpty())throw new IllegalStateException(finalNode?"Add a different Router node with a complete Shadowsocks 2022 profile.":"Add another independent Router node with a complete WireGuard, AmneziaWG Fast or AmneziaWG Strong profile.");
            choiceDialog(finalNode?"Final Router node":"Add intermediate Router node", "Choose one original saved node. Its own keys, Start Layer and policy stay attached to this position.")
                    .setItems(labels.toArray(new CharSequence[0]),(d,w)->{
                        try{if(mutationBusy())throw new IllegalStateException("The VPN state changed while choosing a node.");if(finalNode){draft.setFinal(nodes.get(w).id);showOrderedEditor(draft);}else chooseOrderedMode(draft,nodes.get(w).id,-1);}
                        catch(Exception error){toast(safe(error));}
                    }).setNegativeButton("Back",(d,w)->showOrderedEditor(draft)).show();
        } catch(Exception error) { toast(safe(error)); }
    }

    private void chooseOrderedMode(AndroidOrderedPathSelection draft,String id,int position){
        try {
            if(mutationBusy())throw new IllegalStateException("Finish the current VPN operation before choosing a transport.");
            List<String> modes=draft.prefixModes(id);List<String> labels=new ArrayList<>();
            for(String mode:modes)labels.add(AndroidOrderedPathSelection.prefixModeTitle(mode));
            if(modes.isEmpty())throw new IllegalStateException("This original node has no supported intermediate transport.");
            choiceDialog("Intermediate transport", "Choose this node's own saved transport. Its exact keys and Amnezia parameters stay attached when the node is moved.")
                    .setItems(labels.toArray(new CharSequence[0]),(d,w)->{
                        try{if(mutationBusy())throw new IllegalStateException("The VPN state changed while choosing a transport.");if(position<0)draft.addPrefix(id,modes.get(w));else draft.setPrefixMode(position,modes.get(w));showOrderedEditor(draft);}
                        catch(Exception error){toast(safe(error));}
                    }).setNegativeButton("Back",(d,w)->showOrderedEditor(draft)).show();
        } catch(Exception error) { toast(safe(error)); }
    }

    private void editOrderedPrefix(AndroidOrderedPathSelection draft,int position){
        List<String> actions=new ArrayList<>();List<Integer> destinations=new ArrayList<>();
        if(position>0){actions.add("Move earlier");destinations.add(position-1);}
        if(position<draft.members().size()-2){actions.add("Move later");destinations.add(position+1);}
        actions.add("Remove this intermediate node");destinations.add(-1);
        actions.add("Change transport");destinations.add(-2);
        new AlertDialog.Builder(this).setTitle("Hop "+(position+1)).setItems(actions.toArray(new CharSequence[0]),(d,w)->{
            try{if(mutationBusy())throw new IllegalStateException("The VPN state changed while editing the ordered path.");int target=destinations.get(w);if(target==-2){chooseOrderedMode(draft,draft.members().get(position).source.id,position);return;}if(target<0)draft.removePrefix(position);else draft.movePrefix(position,target);showOrderedEditor(draft);}
            catch(Exception error){toast(safe(error));}
        }).setNegativeButton("Back",(d,w)->showOrderedEditor(draft)).show();
    }

    private void configurePairMultihop(){
        if(mutationBusy()){toast("Disconnect/finish the current VPN operation before editing multihop hops.");return;}
        if(openSelectedExternal(true))return;
        try{
            List<AndroidNodeStore.Node> nodes=nodeStore.list();
            List<AndroidStandardExitStore.Entry> imports=exitStore.list();
            if(nodes.isEmpty()||nodes.size()<2&&imports.isEmpty()){toast("Add a second Router or imported entry node in Nodes.");return;}
            List<String> labels=new ArrayList<>();
            for(AndroidNodeStore.Node node:nodes)labels.add("Router • "+node.name+(telemetry.cachedMedian(node.id)>0?String.format(Locale.US," • direct %.1f ms",telemetry.cachedMedian(node.id)):""));
            for(AndroidStandardExitStore.Entry entry:imports)labels.add("Custom • "+entry.name+" • "+entry.protocol);
            choiceDialog("Multihop entry","Choose hop 1, then the final Router node. For a Router entry, Router VPN will then briefly establish and prove this entry, measure candidates through it, and disconnect. Imported entries use Local execution. HTTP/HTTPS CONNECT supports paired SS2022 or REALITY Vision. Both keep the entry's independently provisioned Off, AES-256-GCM or AES+XOR layer. REALITY carries TCP and UDP and keeps the final node's independently provisioned layer; QUIC or DNS-over-HTTP/3 on port 443 requires that final node's UDP 443 option. With SS2022, selected TCP, DNS-over-TLS and DNS-over-HTTPS are supported; UDP and final AES or AES+XOR additionally require that final node's UDP-over-TCP service configuration. Otherwise SS2022 is TCP-only with the final layer Off. If your DNS server uses a hostname, its saved lookup resolver must also use a supported transport. Saved DNS is never changed automatically. Imported Shadowsocks 2022, Hysteria2, WireGuard, AmneziaWG and OpenVPN entries can use a complete paired final transport. Packet finals require the captured entry capacity to fit their data and handshake envelope; Auto may reduce the final endpoint MTU, while Fixed overflow is refused. These configured bounds are not a measured path MTU. Save the path, then press Connect.")
                .setItems(labels.toArray(new CharSequence[0]),(d,w)->{
                    if(w<nodes.size())prepareViaEntryExitMeasurement(nodes.get(w),nodes);
                    else chooseImportedRouterFinal(imports.get(w-nodes.size()),nodes);
                }).setNegativeButton("Cancel",null).show();
        }catch(Exception error){toast(safe(error));}
    }
    private void chooseImportedRouterFinal(AndroidStandardExitStore.Entry entry,List<AndroidNodeStore.Node> nodes){
        try{
            AndroidMultihopController.Source original=AndroidImportedRouterPath.captureSource(this,entry);
            List<AndroidNodeStore.Node> finals=new ArrayList<>();List<String> labels=new ArrayList<>();
            for(AndroidNodeStore.Node node:nodes)if(!node.id.equals(entry.id)){finals.add(node);labels.add("Router • "+node.name);}
            if(finals.isEmpty())throw new IllegalStateException("Add a different paired Router final node.");
            choiceDialog("Final Router node","The final node supplies its saved DNS and device policy. The imported entry and final node retain their own keys and Start Layers. Use Connect after saving this path.")
                .setItems(labels.toArray(new CharSequence[0]),(d,w)->{
                    chooseImportedRouterTransport(original,finals.get(w));
                }).setNegativeButton("Cancel",null).show();
        }catch(Exception error){toast(safe(error));}
    }
    private void chooseImportedRouterTransport(AndroidMultihopController.Source original,AndroidNodeStore.Node last){
        try{
            if(mutationBusy())throw new IllegalStateException("Finish the current VPN operation before choosing its transport.");
            AndroidStandardExitStore.Entry first=AndroidImportedRouterPath.entry(this,original);
            byte[] bytes=AndroidPrivateFileStore.read(last.file,AndroidNodeStore.MAX_BUNDLE);
            AndroidMultihopController.Source finalSource=AndroidMultihopController.captureSource(last.file,bytes);
            JSONObject bundle=AndroidImportedRouterPath.finalBundle(last.file);
            List<String> modes=new ArrayList<>();List<String> labels=new ArrayList<>();
            for(String mode:new String[]{"shadowsocks","hysteria2","wg","awg2-fast","awg2-strong","reality-vision","reality-pq-vision","reality-xhttp","naive-h2","naive-h3"}){
                try{AndroidImportedRouterPath.compile(first,bundle,mode,"local");modes.add(mode);labels.add(switch(mode){case "hysteria2"->"Hysteria2";case "wg"->"WireGuard";case "awg2-fast"->"AmneziaWG Fast";case "awg2-strong"->"AmneziaWG Strong";case "reality-vision"->"REALITY Vision";case "reality-pq-vision"->"PQ REALITY Vision";case "reality-xhttp"->"REALITY XHTTP";case "naive-h2"->"Naive HTTP/2";case "naive-h3"->"Naive HTTP/3";default->"Shadowsocks";});}
                catch(Exception unavailable){/* Only complete captured transport assets are offered. */}
            }
            original.require(null);finalSource.require(last.file);
            if(modes.isEmpty())throw new IllegalStateException("This paired node has no complete supported final transport for the selected entry and layers.");
            choiceDialog("Final Router transport","Choose the final transport. WireGuard, AmneziaWG, OpenVPN, SOCKS5, Shadowsocks 2022, Hysteria2 and HTTP/HTTPS CONNECT entries can use a paired REALITY Vision final. Both hops keep their original credentials and Start Layers; the final node supplies the selected DNS policy. This imported path uses Local execution.")
                .setItems(labels.toArray(new CharSequence[0]),(d,w)->{
                    try{
                        original.require(null);finalSource.require(last.file);
                        new AndroidConnectionProfileStore(this,nodeStore,exitStore).selectImportedRouterPath(
                                AndroidImportedRouterPath.entry(this,original),last,modes.get(w),finalSource.digest);
                        refreshAll();toast("Saved "+first.name+" → "+last.name+" • "+labels.get(w)+". Press Connect when ready.");
                    }catch(Exception changed){toast(safe(changed));}
                }).setNegativeButton("Cancel",null).show();
        }catch(Exception error){toast(safe(error));}
    }

    private void prepareViaEntryExitMeasurement(AndroidNodeStore.Node entry,List<AndroidNodeStore.Node> all){
        if(mutationBusy()){toast("VPN state changed; disconnect/finish before measuring multihop candidates.");return;}
        List<AndroidNodeStore.Node> exits=new ArrayList<>();for(AndroidNodeStore.Node node:all)if(!node.id.equals(entry.id))exits.add(node);
        if(exits.isEmpty()){toast("No different exit nodes are available.");return;}
        viaEntryGeneration++;pendingProbeEntryId=entry.id;pendingProbeCandidateIds=new ArrayList<>();
        for(AndroidNodeStore.Node node:exits)pendingProbeCandidateIds.add(node.id);
        Intent permission=VpnService.prepare(this);
        if(permission!=null){statusView.setText("Waiting for Android VPN permission to measure "+entry.name+" → candidate response times…");startActivityForResult(permission,PREPARE_VIA_ENTRY_RTT);}
        else runPendingViaEntryProbe();
    }
    private void runPendingViaEntryProbe(){
        if(mutationBusy()){clearPendingProbe();toast("VPN state changed while permission was open; disconnect/finish before measuring multihop candidates.");refreshAll();return;}
        AndroidNodeStore.Node entry=quietNode(pendingProbeEntryId);List<AndroidNodeStore.Node> exits=quietNodes(pendingProbeCandidateIds);
        if(entry==null||exits.isEmpty()){clearPendingProbe();toast("Multihop candidate measurement state expired; choose the entry again.");return;}
        final long operation=++viaEntryGeneration;
        final AlertDialog progressDialog=new AlertDialog.Builder(this).setTitle("Measure candidates through "+entry.name)
            .setMessage("Preparing the captured entry path…").setCancelable(false).setNegativeButton("Cancel measurement",null).create();
        viaEntryDialog=progressDialog;progressDialog.show();
        progressDialog.getButton(AlertDialog.BUTTON_NEGATIVE).setOnClickListener(v->{if(operation==viaEntryGeneration)viaEntryProbe.cancel();});
        statusView.setText("Preparing real "+entry.name+" → candidate response measurement…");
        viaEntryProbe.measure(entry,exits,50,new AndroidViaEntryLatencyProbe.Callback(){
            public void progress(String message){runOnUiThread(()->{if(operation==viaEntryGeneration&&!isFinishing()&&!isDestroyed()){statusView.setText(message);progressDialog.setMessage(message);}});}
            public void finished(AndroidViaEntryLatencyProbe.Result result,Throwable error){runOnUiThread(()->{
                if(operation!=viaEntryGeneration||isFinishing()||isDestroyed())return;
                if(viaEntryDialog==progressDialog){progressDialog.dismiss();viaEntryDialog=null;}
                clearPendingProbe();refreshAll();
                if(result==null){statusView.setText(safe(error));return;}
                showViaEntryExitPicker(result,error);
            });}
        });
    }
    private void showViaEntryExitPicker(AndroidViaEntryLatencyProbe.Result result,Throwable measurementError){
        if(result==null||result.candidates.isEmpty()){toast("Multihop candidate exits are unavailable.");return;}
        try{result.requireCurrent();}catch(Exception stale){toast(safe(stale));return;}
        AndroidNodeStore.Node entry=result.entry;
        List<AndroidNodeStore.Node> exits=new ArrayList<>(result.candidates);
        Collections.sort(exits,(left,right)->{
            AndroidTelemetry.Result a=result.measurement(left.id),b=result.measurement(right.id);
            double x=AndroidViaEntryLatencyProbe.Result.score(a),y=AndroidViaEntryLatencyProbe.Result.score(b);
            int compared=Double.compare(x,y);return compared!=0?compared:left.id.compareTo(right.id);
        });
        AndroidNodeStore.Node winner=measurementError==null?result.fastest():null;
        String[] labels=new String[exits.size()+1];
        labels[0]=winner==null?"⚡ Fastest unavailable • Retest":"⚡ Fastest • "+winner.name+String.format(Locale.US," • %.1f ms trimmed mean",result.measurement(winner.id).trimmedMeanMs);
        for(int i=0;i<exits.size();i++){
            AndroidTelemetry.Result value=measurementError==null?result.measurement(exits.get(i).id):null;
            labels[i+1]=entry.name+" → "+exits.get(i).name+" • "+(value==null?"unavailable":String.format(Locale.US,"%.1f ms median • %d ok / %d failed%s",value.medianMs,value.samples,value.failed,Double.isFinite(AndroidViaEntryLatencyProbe.Result.score(value))?String.format(Locale.US," • %.1f ms trimmed mean",value.trimmedMeanMs):" • no comparison score"));
        }
        String note=measurementError==null?"TCP connection response times were measured through the proved temporary WireGuard entry. Its sockets and tunnel are now stopped. Fastest requires all 50 successful samples and no failures, then ranks the 10% trimmed mean with stable node-ID ties; Connect stays separate. Values are not saved as direct-node RTTs.":"Via-entry response time could not be proven: "+safe(measurementError)+"\n\nChoose a candidate manually or Retest. No direct-node measurement is substituted.";
        choiceDialog("Multihop hop 2 • measured via "+entry.name,note).setItems(labels,(dialog,index)->{
            try{result.requireCurrent();}catch(Exception stale){toast(safe(stale));return;}
            if(index==0&&winner==null){prepareViaEntryExitMeasurement(entry,result.candidates);return;}
            chooseMultihopMode(entry,index==0?winner:exits.get(index-1),result);
        }).setNeutralButton("Retest",(dialog,index)->prepareViaEntryExitMeasurement(entry,result.candidates)).setNegativeButton("Cancel",null).show();
    }
    private void clearPendingProbe(){pendingProbeEntryId="";pendingProbeCandidateIds.clear();}
    private AndroidNodeStore.Node quietNode(String id){try{return nodeById(id);}catch(Exception ignored){return null;}}
    private List<AndroidNodeStore.Node> quietNodes(List<String> ids){List<AndroidNodeStore.Node>out=new ArrayList<>();if(ids==null)return out;try{List<AndroidNodeStore.Node>all=nodeStore.list();for(String id:ids)for(AndroidNodeStore.Node node:all)if(node.id.equals(id)){out.add(node);break;}}catch(Exception ignored){}return out;}
    private void chooseMultihopMode(AndroidNodeStore.Node entry,AndroidNodeStore.Node exit,AndroidViaEntryLatencyProbe.Result selection){if(mutationBusy()){toast("VPN state changed; disconnect/finish before editing multihop.");return;}try{selection.requireCurrent();List<NativeSingBoxController.ModeInfo>modes=connection.supportedMultihopExitModes(exit);if(modes.isEmpty()){toast("That exit has no available native WireGuard/Shadowsocks/Hysteria2 exit transport.");return;}String[]labels=new String[modes.size()];for(int i=0;i<modes.size();i++)labels[i]=modes.get(i).name+" ["+modes.get(i).id+"]";new AlertDialog.Builder(this).setTitle("Exit transport").setItems(labels,(d,w)->{if(mutationBusy()){toast("VPN state changed; disconnect/finish before saving multihop.");return;}chooseMultihopExecution(entry,exit,modes.get(w).id,selection);}).setNegativeButton("Cancel",null).show();}catch(Exception error){toast(safe(error));}}
    private void refreshMultihopSummary(){
        if(orderedPathEnabled()) {
            multihopToggle.setChecked(true);
            try {
                AndroidOrderedPathPresentation presentation=currentOrderedPresentation();if(presentation==null){multihopHint.setText("Checking the complete ordered path…");return;}
                StringBuilder summary=new StringBuilder(presentation.testing?"TESTING • ":presentation.live?"LIVE • ":"");
                for(int i=0;i<presentation.members.size();i++){if(i>0)summary.append(" → ");AndroidOrderedPathPresentation.Member member=presentation.members.get(i);summary.append(i+1).append(". ").append(member.name).append(" [").append(member.mode).append("]");if(member.httpResponseMs>0)summary.append(String.format(Locale.US,member.imported?" • Public path via custom node %.1f ms":" • HTTP proof %.1f ms",member.httpResponseMs));}
                multihopHint.setText(summary.append(" • Local").toString());
            }catch(Exception invalid){multihopHint.setText("The ordered path changed; reopen Edit hops.");}
            return;
        }
if(isExternalSelected()){boolean on=prefs().getBoolean(MULTI_ON,false);multihopToggle.setChecked(on);try{AndroidConnectionProfileStore.ExternalSelection path=new AndroidConnectionProfileStore(this,nodeStore,exitStore).currentExternalPath(prefs().getString(SELECTED_ID,""));multihopHint.setText(path.direct()?"Direct → "+path.exit.name:(path.ordinaryEntry!=null?path.ordinaryEntry.name:path.entry.name)+" → "+path.exit.name+" • "+path.entryMode+" → "+path.exit.protocol+" • "+("server".equals(path.execution)?"Server":"auto".equals(path.execution)?"Compare":"Local"));}catch(Exception invalid){multihopHint.setText("Choose external path in Edit hops");}return;}boolean live=connection.isMultihopConnected();boolean on=live||prefs().getBoolean(MULTI_ON,false);multihopToggle.setChecked(on);if(!on){multihopHint.setText("Off");return;}String entryId=live?connection.activeMultihopEntryId():prefs().getString(MULTI_ENTRY,""),exitId=live?connection.activeMultihopExitId():prefs().getString(MULTI_EXIT,""),mode=live?connection.activeMultihopExitMode():prefs().getString(MULTI_MODE,"");try{AndroidStandardExitStore.Entry ordinary=live?connection.activeImportedMultihopEntry():"external".equals(prefs().getString("multihop_entry_kind","router-vpn"))?exitStore.get(entryId):null;
        AndroidNodeStore.Node exit=nodeById(exitId);
        if(ordinary!=null){if(exit==null)throw new IllegalStateException("The final node is unavailable.");multihopHint.setText((live?"LIVE • ":"")+ordinary.name+" → "+exit.name+" • "+("wireguard".equals(ordinary.protocol)?"WireGuard":"amneziawg".equals(ordinary.protocol)?"AmneziaWG":"hysteria2".equals(ordinary.protocol)?"Hysteria2":"socks5".equals(ordinary.protocol)?"SOCKS5":"openvpn".equals(ordinary.protocol)?"OpenVPN":"http".equals(ordinary.protocol)?"HTTP CONNECT":"https".equals(ordinary.protocol)?"HTTPS CONNECT":"Shadowsocks 2022")+" → "+(switch(mode){case "hysteria2"->"Hysteria2";case "wg"->"WireGuard";case "awg2-fast"->"AmneziaWG Fast";case "awg2-strong"->"AmneziaWG Strong";case "shadowsocks"->"Shadowsocks";case "reality-vision"->"REALITY Vision";case "reality-pq-vision"->"PQ REALITY Vision";case "reality-xhttp"->"REALITY XHTTP";case "naive-h2"->"Naive HTTP/2";case "naive-h3"->"Naive HTTP/3";default->"Unsupported final transport";})+" • Local"+(live&&currentPathMs>0?String.format(Locale.US," • PATH %.1f ms",currentPathMs):""));return;}
        AndroidNodeStore.Node entry=nodeById(entryId);if(entry==null||exit==null){multihopHint.setText(live?"Live graph identity unavailable":"Choose hops");return;}double a=telemetry.cachedMedian(entry.id),b=telemetry.cachedMedian(exit.id);StringBuilder s=new StringBuilder(live?"LIVE • ":"").append(entry.name);if(a>0)s.append(String.format(Locale.US," %.1f ms",a));s.append(" → ").append(exit.name);if(b>0)s.append(String.format(Locale.US," %.1f ms",b));if(currentPathMs>0&&live)s.append(String.format(Locale.US," • PATH %.1f ms",currentPathMs));s.append(" • ").append(live?connection.activeMultihopEntryMode():prefs().getString("multihop_entry_mode","wg")).append(" → ").append(mode);multihopHint.setText(s.toString());}catch(Exception error){multihopHint.setText(live?"Live graph identity unavailable":"Choose hops");}}
    private AndroidNodeStore.Node nodeById(String id)throws Exception{if(id==null||id.isEmpty())return null;for(AndroidNodeStore.Node n:nodeStore.list())if(n.id.equals(id))return n;return null;}

    private boolean isExternalSelected(){return "external".equals(prefs().getString(SELECTED_KIND,"router-vpn"));}
    private boolean openSelectedExternal(boolean selectPath){
        AndroidUnifiedNodeCatalog.Item selected=selectedCatalogItem();if(selected==null||selected.isRouterVpn())return false;
        Intent intent=new Intent(this,StandardExitActivity.class);intent.putExtra(StandardExitActivity.EXTRA_EXIT_ID,selected.id);intent.putExtra(StandardExitActivity.EXTRA_SELECT_PATH,selectPath);startActivity(intent);return true;
    }

    private void showSettings(){if(openSelectedExternal(false))return;JSONObject p=activeRouterProfile();if(p==null){toast("Select a Router VPN node first.");return;}AndroidProfileSettingsDialog.show(this,nodeStore,this::refreshAll);}
    private void setQuickKillSwitch(boolean enabled){
        if(mutationBusy()){toast("Disconnect/finish before changing persistent kill-switch policy.");refreshSettingsState();return;}
        try{
            if(!externalProtectionID.isEmpty()&&!isExternalSelected())throw new IllegalStateException("The displayed external selection changed; refresh before saving protection.");
            if(isExternalSelected()){
                String id=externalProtectionID,source=externalProtectionSource;
                if(id.isEmpty()||source.isEmpty()||!id.equals(prefs().getString(SELECTED_ID,"")))throw new IllegalStateException("The displayed external node changed; refresh before saving its protection.");
                AndroidStandardExitStore.Entry next=AndroidStandardExitStore.copy(exitStore.get(id));
                if(!source.equals(AndroidStandardExitStore.snapshot(next)))throw new IllegalStateException("The saved external node changed; refresh before changing its protection.");
                if(AndroidTorProfile.isTor(next.protocol))next.torPolicy=AndroidExternalProtection.withChoice(next.torPolicy,enabled);
                else next.policy=AndroidExternalProtection.withChoice(next.policy,enabled);
                exitStore.saveIfUnchanged(next,source);
                toast(enabled?"Saved exit requires Android Always-on VPN and Block connections without VPN.":"Saved exit requirement is Off. Android system lockdown and a strict entry remain independent.");
            }else{
                JSONObject root=activeBundle(),p=selectedProfile(root);if(p==null)throw new IllegalStateException("Select a Router VPN node first.");
                p.put("kill_switch",enabled);p.put("kill_switch_policy",enabled?"on-connect":"off");nodeStore.importBundle(root.toString().getBytes(StandardCharsets.UTF_8));toast(enabled?"Kill switch enabled":"Kill switch disabled");
            }
        }catch(Exception error){toast(safe(error));}refreshSettingsState();
    }
    private void refreshSettingsState(){
        externalProtectionID="";externalProtectionSource="";
        if(isExternalSelected()){
            killSwitch.setText("Exit kill switch");
            try{
                String id=prefs().getString(SELECTED_ID,"");
                AndroidConnectionProfileStore.ExternalSelection path=new AndroidConnectionProfileStore(this,nodeStore,exitStore).currentExternalPath(id);
                AndroidStandardExitStore.Entry exit=path.exit;boolean tor=AndroidTorProfile.isTor(exit.protocol);
                boolean selected=AndroidExternalProtection.requested(tor?exit.torPolicy:exit.policy,tor||path.direct());
                boolean entryStrict=path.ordinaryEntry!=null?AndroidExternalProtection.requested(path.ordinaryEntry.policy,true):path.entry!=null&&AndroidKillSwitchPolicy.strictRequested(path.entry.file);
                Boolean os=LayeredVpnService.currentLockdownState();
                externalProtectionID=id;externalProtectionSource=AndroidStandardExitStore.snapshot(exit);
                killSwitch.setChecked(selected);killSwitch.setEnabled(!mutationBusy());
                if(autoRequirementsHint!=null)autoRequirementsHint.setText("Saved exit kill switch: "+(selected?"On; Android lockdown required":"Off")
                        +(entryStrict?" • Captured entry also requires lockdown":"")
                        +(Boolean.TRUE.equals(os)?" • Android system lockdown is currently On":os==null?" • Android system lockdown is controlled in VPN settings":" • Android system lockdown is currently Off")
                        +". Changing this saved exit does not turn off Android's system setting.");
            }catch(Exception invalid){killSwitch.setChecked(false);killSwitch.setEnabled(false);if(autoRequirementsHint!=null)autoRequirementsHint.setText("Choose this external node's valid path before changing its saved protection. Android system lockdown remains independent.");}
            return;
        }
        killSwitch.setText("Kill switch");JSONObject p=activeRouterProfile();boolean enabled=p!=null&&(!"off".equalsIgnoreCase(p.optString("kill_switch_policy","off"))||p.optBoolean("kill_switch",false));killSwitch.setChecked(enabled);
        if(autoRequirementsHint!=null){boolean encrypted=p!=null&&p.optBoolean("auto_require_encrypted",false),obfuscated=p!=null&&p.optBoolean("auto_require_obfuscation",false);String value=encrypted&&obfuscated?"Encrypted + Obfuscation":encrypted?"Encrypted":obfuscated?"Obfuscation":"Off";autoRequirementsHint.setText("AUTO requirements: "+value+" • Off by default • SMART never simplifies below enabled requirements");}
    }
    private void showMtuHelp(){AndroidMTUDialog.show(this);}

    private void refreshForwardingState(){AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(this);if(AndroidViaEntryLatencyProbe.hasActiveOperation()||!connection.isConnected()||"external".equals(home.logicalMode)){forwardingEnabled=null;forwardButton.setText("Forward");return;}if(forwardingBusy)return;forwardingBusy=true;forwardingMaster.get((enabled,error)->runOnUiThread(()->{forwardingBusy=false;if(error==null&&enabled!=null){forwardingEnabled=enabled;forwardButton.setText(enabled?"Forward ON":"Forward OFF");}else{forwardingEnabled=null;forwardButton.setText("Forward ?");}}));}
    private void showForwarding(){if(AndroidViaEntryLatencyProbe.hasActiveOperation()){dialog("Master port forwarding","Via-entry candidate measurement is using a temporary Router VPN tunnel. It will disconnect automatically; forwarding is not changed during this probe.");return;}AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(this);if(!connection.isConnected()){dialog("Master port forwarding","Connect a Router VPN home-node path first. The forwarding master is a real server-owned policy and is not changed while disconnected.");return;}if("external".equals(home.logicalMode)){dialog("Master port forwarding","A direct external exit does not own your Router VPN home-node forwarding policy. Connect a Router VPN home-node path first.");return;}if(forwardingBusy){toast("Forwarding master state is already being verified.");return;}forwardingBusy=true;forwardButton.setText("Forward …");forwardingMaster.get((enabled,error)->runOnUiThread(()->{forwardingBusy=false;if(error!=null||enabled==null){forwardingEnabled=null;forwardButton.setText("Forward ?");dialog("Master port forwarding","Could not verify the real forwarding-master state: "+safe(error));return;}forwardingEnabled=enabled;forwardButton.setText(enabled?"Forward ON":"Forward OFF");String state=enabled?"ON":"OFF";new AlertDialog.Builder(this).setTitle("Master port forwarding • "+state).setMessage("This is the real server forwarding master on the active Router VPN home node. It gates WAN→tunnel forwarding rules and Protected DMZ. The request is authenticated through the active VPN path; the Setup Center admin token never leaves the server.").setPositiveButton(enabled?"Turn OFF":"Turn ON",(d,w)->setForwardingMaster(!enabled)).setNeutralButton("Rules in Setup Center",(d,w)->dialog("Forwarding rules","The master switch is controlled here. Individual persistent rules and Protected DMZ remain server-owned in Setup Center so targets/owners/reserved ports can be validated safely.")).setNegativeButton("Close",null).show();}));}
    private void setForwardingMaster(boolean enabled){if(forwardingBusy)return;forwardingBusy=true;forwardButton.setText("Forward …");forwardingMaster.set(enabled,(actual,error)->runOnUiThread(()->{forwardingBusy=false;if(error!=null||actual==null){forwardingEnabled=null;forwardButton.setText("Forward ?");dialog("Forwarding update failed",safe(error));return;}forwardingEnabled=actual;forwardButton.setText(actual?"Forward ON":"Forward OFF");toast("Server port-forwarding master is now "+(actual?"ON":"OFF")+".");}));}

    private void setQuickDns(String mode){if(openSelectedExternal(false)){refreshDnsSelection();return;}if(mutationBusy()){toast("Disconnect/finish before changing DNS.");refreshDnsSelection();return;}try{JSONObject root=activeBundle(),p=selectedProfile(root);if(p==null)throw new IllegalStateException("Select a Router VPN node first.");if("fastest".equals(mode)&&p.optString("fastest_dns_host","").trim().isEmpty()){AndroidProductParity.showDNS(this,nodeStore);return;}AndroidProductParity.selectQuickDNS(p,mode);nodeStore.importBundle(root.toString().getBytes(StandardCharsets.UTF_8));toast("DNS set to "+mode+" for the next tunnel; runtime proof still required.");}catch(Exception error){toast(safe(error));}refreshDnsSelection();}
    private void refreshDnsSelection(){JSONObject p=activeRouterProfile();if(isExternalSelected()){try{AndroidStandardExitStore.Entry exit=exitStore.get(prefs().getString(SELECTED_ID,""));p=AndroidTorProfile.isTor(exit.protocol)?exit.torPolicy:exit.policy;if(p==null)p=new JSONObject();}catch(Exception invalid){dnsHint.setText("Saved external DNS unavailable; check Settings before connecting.");return;}dnsHint.setText("Saved external DNS; Details opens its complete policy. Connected requires the captured path and DNS proof.");}else dnsHint.setText("DNS changes the next tunnel resolver path; Connected still requires runtime DNS/path proof.");String mode=p==null?"home":p.optString("dns_mode","home").trim().toLowerCase(Locale.US);String[]ids={"home","fastest","custom","dot","doh","doh3","rescue"};int index=0;for(int i=0;i<ids.length;i++)if(ids[i].equals(mode)){index=i;break;}dnsSpinner.setSelection(index,false);}

    private void showAddRouter(){
        if(mutationBusy()){toast("Disconnect/finish before adding or updating Router profiles.");return;}
        choiceDialog("Add / update Router node","Use secure one-time LAN pairing or import a complete Router VPN JSON bundle. Import validates and stores the node, then selects it; Connect remains a separate action.")
            .setItems(new String[]{"Pair on LAN","Import Router bundle file","Add custom / external exit"},(d,w)->{if(w==0)showPairDialog();else if(w==1)chooseRouterBundle();else openStandardExits();}).setNegativeButton("Cancel",null).show();
    }

    private void chooseRouterBundle(){
        try{importDecision=AndroidRouterBundleImport.decision(this,nodeStore);importGeneration++;
            Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*");
            intent.putExtra(Intent.EXTRA_MIME_TYPES,new String[]{"application/json","text/json","text/plain","application/octet-stream"});startActivityForResult(intent,IMPORT_ROUTER_BUNDLE);
        }catch(Exception error){importDecision="";toast(safe(error));}
    }

    private void receiveRouterBundle(int resultCode,Intent data){
        String captured=importDecision;importDecision="";long ticket=++importGeneration;
        if(resultCode!=RESULT_OK)return;
        try{if(data==null||data.getData()==null||!"content".equals(data.getData().getScheme()))throw new IllegalArgumentException("Choose an accessible document from the Android file picker.");AndroidRouterBundleImport.requireCurrent(this,nodeStore,captured);}
        catch(Exception error){toast(safe(error));return;}
        android.net.Uri uri=data.getData();statusView.setText("Reading and validating Router bundle…");
        new Thread(()->{
            byte[] bytes=null;Throwable failure=null;try{bytes=AndroidRouterBundleImport.read(getContentResolver().openInputStream(uri));}catch(Throwable error){failure=error;}
            final byte[] ready=bytes;final Throwable error=failure;runOnUiThread(()->{
                if(ticket!=importGeneration||isFinishing()||isDestroyed())return;
                try{if(error!=null)throw new IllegalStateException(safe(error));
                    AndroidNodeStore.Node node;synchronized(prefs()){AndroidRouterBundleImport.requireCurrent(this,nodeStore,captured);node=nodeStore.importBundle(ready);AndroidConnectionProfileStore.applySelection(prefs(),prefs().edit().putString(SELECTED_KIND,"router-vpn").putString(SELECTED_ID,node.id).putBoolean(MULTI_ON,false).putString(MULTI_ENTRY,"").putString(MULTI_EXIT,""));}refreshAll();toast("Imported and selected "+node.name+". Press Connect when ready.");
                }catch(Exception rejected){refreshAll();toast("Bundle not imported: "+safe(rejected));}
            });
        },"routervpn-bundle-import").start();
    }

    private void showPairDialog(){
        if(mutationBusy()){toast("Disconnect/finish before adding or updating Router profiles.");return;}
        LinearLayout fields=new LinearLayout(this);fields.setOrientation(LinearLayout.VERTICAL);fields.setPadding(dp(20),dp(4),dp(20),0);
        EditText host=new EditText(this);host.setHint("AI Board LAN IP / hostname");host.setSingleLine(true);
        EditText code=new EditText(this);code.setHint("6-digit one-time pairing code");code.setSingleLine(true);code.setInputType(InputType.TYPE_CLASS_NUMBER|InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        fields.addView(host);fields.addView(code);
        AlertDialog pairDialog=new AlertDialog.Builder(this).setTitle("Add / update Router node").setMessage("Use the short-lived code from authenticated private Setup Center. Pairing stays LAN/private and one-time; the same stable node identity updates its stored profile.").setView(fields).setPositiveButton("Pair",null).setNegativeButton("Cancel",null).create();
        pairDialog.setOnShowListener(x->pairDialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
            if(mutationBusy()){toast("VPN state changed; disconnect/finish before redeeming the one-time pairing code.");return;}
            pairDialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);
            AndroidPairingClient.redeem(host.getText().toString(),code.getText().toString(),(bundle,error)->runOnUiThread(()->{
                if(error!=null){pairDialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(true);toast("Pairing failed: "+safe(error));return;}
                if(mutationBusy()){pairDialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(true);toast("VPN state changed after pairing redemption; bundle was not imported or selected. Disconnect, then pair again with a new code.");return;}
                try{AndroidNodeStore.Node node;synchronized(prefs()){node=nodeStore.importBundle(bundle);AndroidConnectionProfileStore.applySelection(prefs(),prefs().edit().putString(SELECTED_KIND,"router-vpn").putString(SELECTED_ID,node.id));}pairDialog.dismiss();refreshAll();toast("Added/updated and selected "+node.name);}catch(Exception importError){pairDialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(true);toast("Bundle rejected: "+safe(importError));}
            }));
        }));
        pairDialog.show();
    }

    private void openStandardExits(){if(mutationBusy()){toast("Disconnect/finish before adding, deleting, or selecting Custom / external exits.");return;}startActivity(new Intent(this,StandardExitActivity.class));}
    private void showHelp(){new AlertDialog.Builder(this).setTitle("Router VPN").setMessage("Map-first daily app: choose one Router or Custom node, or use ⚡ Fastest; Connect becomes Disconnect with live private-path RTT beside it. Multihop hop-2 candidates are measured through a real temporary proven hop-1 tunnel, then that probe tunnel is disconnected before selection. Live multihop map roles, path RTT and routed hop Mbps bind to the actual frozen runtime graph. Swipe up for Settings, Performance, Mode, DNS, Profiles and the real server forwarding master. Only real stored coordinates/measurements are rendered.").setPositiveButton("Run onboarding again",(d,w)->AndroidProductOnboarding.show(this,true)).setNeutralButton("More",(d,w)->AndroidUpdateDialog.showHelpActions(this)).setNegativeButton("Close",null).show();}

    private JSONObject activeBundle()throws Exception{String active=nodeStore.activeId();if(active==null||active.isEmpty())throw new IllegalStateException("Select a Router VPN node first.");try(FileInputStream in=new FileInputStream(nodeStore.file(active));ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]buf=new byte[8192];int n,total=0;while((n=in.read(buf))!=-1){total+=n;if(total>AndroidNodeStore.MAX_BUNDLE)throw new IllegalStateException("Bundle exceeds safety limit.");out.write(buf,0,n);}return new JSONObject(new String(out.toByteArray(),StandardCharsets.UTF_8));}}
    private JSONObject activeRouterProfile(){try{return selectedProfile(activeBundle());}catch(Exception ignored){return null;}}
    private static JSONObject selectedProfile(JSONObject bundle){return AndroidProfileSelection.selectedRouterProfile(bundle);}
    private List<String> allCatalogLayers()throws Exception{JSONObject root=activeBundle();JSONArray modes=root.optJSONArray("modes");Set<String>set=new LinkedHashSet<>();if(modes!=null)for(int i=0;i<modes.length();i++){JSONObject m=modes.optJSONObject(i);JSONArray l=m==null?null:m.optJSONArray("layers");if(l!=null)for(int j=0;j<l.length();j++){String v=l.optString(j,"").trim().toLowerCase(Locale.US);if(!v.isEmpty())set.add(v);}}return new ArrayList<>(set);}
    private List<CustomPreset> loadCustomPresets(){List<CustomPreset>out=new ArrayList<>();try{JSONArray a=new JSONArray(prefs().getString(CUSTOM_KEY,"[]"));for(int i=0;i<a.length();i++){JSONObject p=a.optJSONObject(i);if(p==null)continue;String name=p.optString("name","").trim();JSONArray l=p.optJSONArray("layers");List<String>layers=new ArrayList<>();if(l!=null)for(int j=0;j<l.length();j++){String v=l.optString(j,"").trim();if(!v.isEmpty())layers.add(v);}if(!name.isEmpty()&&!layers.isEmpty())out.add(new CustomPreset(name,layers));}}catch(Exception ignored){}return out;}
    private JSONArray checkedCustomRows(String raw) throws Exception {
        JSONArray rows = new JSONArray(raw);
        if (rows.length() > 64) throw new IllegalStateException("CUSTOM preset limit exceeded.");
        for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.getJSONObject(i);
            if (row.getString("name").trim().isEmpty()) throw new IllegalStateException("Existing CUSTOM preset name is invalid.");
            JSONArray layers = row.getJSONArray("layers");
            if (layers.length() == 0 || layers.length() > 128) throw new IllegalStateException("Existing CUSTOM layers are invalid.");
            for (int n = 0; n < layers.length(); n++) if (layers.getString(n).trim().isEmpty()) throw new IllegalStateException("Existing CUSTOM layer is invalid.");
        }
        return rows;
    }

    private void saveCustomPreset(CustomPreset preset, String oldName) throws Exception {
        AndroidCustomPresetCommit.Snapshot before = AndroidCustomPresetCommit.snapshot(prefs());
        JSONArray rows = checkedCustomRows(before.presets), next = new JSONArray();
        for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.getJSONObject(i); String name = row.getString("name");
            if ((oldName == null || !name.equalsIgnoreCase(oldName)) && !name.equalsIgnoreCase(preset.name)) next.put(row);
        }
        if (next.length() >= 64) throw new IllegalStateException("CUSTOM preset limit reached.");
        JSONObject row = new JSONObject(); row.put("name", preset.name); row.put("layers", new JSONArray(preset.layers)); next.put(row);
        AndroidCustomPresetCommit.publish(before, next.toString(), "custom:" + preset.name, () -> !mutationBusy());
    }

    private void deleteCustomPreset(String name) throws Exception {
        AndroidCustomPresetCommit.Snapshot before = AndroidCustomPresetCommit.snapshot(prefs());
        JSONArray rows = checkedCustomRows(before.presets), next = new JSONArray(); boolean found = false;
        for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.getJSONObject(i);
            if (row.getString("name").equalsIgnoreCase(name)) found = true; else next.put(row);
        }
        if (!found) throw new IllegalStateException("CUSTOM preset disappeared; reopen the list.");
        String mode = before.mode.equalsIgnoreCase("custom:" + name) ? "smart-auto" : before.mode;
        AndroidCustomPresetCommit.publish(before, next.toString(), mode, () -> !mutationBusy());
    }

    // AOSP AlertController gives a message priority over its item list. Put the
    // explanation in a custom title so every action remains visible/clickable.
    private AlertDialog.Builder choiceDialog(String title,String explanation){
        LinearLayout header=new LinearLayout(this);header.setOrientation(LinearLayout.VERTICAL);
        header.setPadding(dp(24),dp(18),dp(24),dp(8));header.addView(text(title,18,true));
        TextView note=text(explanation,12,false);note.setPadding(0,dp(8),0,0);header.addView(note);
        return new AlertDialog.Builder(this).setCustomTitle(header);
    }
    private void dialog(String title,String message){new AlertDialog.Builder(this).setTitle(title).setMessage(message).setPositiveButton("OK",null).show();}
    private SharedPreferences prefs(){return getSharedPreferences(PREFS,MODE_PRIVATE);}
    private LinearLayout row(){LinearLayout r=new LinearLayout(this);r.setOrientation(LinearLayout.HORIZONTAL);r.setGravity(Gravity.CENTER_VERTICAL);return r;}
    private LinearLayout controlRow(String title){LinearLayout r=row();TextView label=text(title,13,true);label.setTextColor(Color.WHITE);label.setGravity(Gravity.END);r.addView(label,new LinearLayout.LayoutParams(dp(72),LinearLayout.LayoutParams.WRAP_CONTENT));return r;}
    private TextView text(String value,int sp,boolean bold){TextView v=new TextView(this);v.setText(value);v.setTextSize(sp);v.setTextColor(Color.WHITE);if(bold)v.setTypeface(v.getTypeface(),Typeface.BOLD);return v;}
    private Button primaryButton(String value){Button b=smallButton(value);b.setTextSize(17);b.setTypeface(b.getTypeface(),Typeface.BOLD);b.setTextColor(Color.WHITE);b.setBackgroundTintList(ColorStateList.valueOf(Color.rgb(95,78,220)));return b;}
    private Button smallButton(String value){Button b=new Button(this);b.setText(value);b.setAllCaps(false);b.setTextColor(Color.WHITE);b.setTextSize(11);b.setMinWidth(0);b.setMinimumWidth(0);b.setPadding(dp(7),0,dp(7),0);b.setBackgroundTintList(ColorStateList.valueOf(Color.rgb(39,55,82)));return b;}
    private GradientDrawable round(int color,int radius){GradientDrawable d=new GradientDrawable();d.setColor(color);d.setCornerRadius(dp(radius));return d;}
    private LinearLayout.LayoutParams margins(int l,int t,int r,int b){LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,LinearLayout.LayoutParams.WRAP_CONTENT);p.setMargins(l,t,r,b);return p;}
    private int dp(float value){return Math.round(value*getResources().getDisplayMetrics().density);}
    private static String safe(Throwable error){String value=error==null?"":error.getMessage();return value==null||value.trim().isEmpty()?"Router VPN error":value.trim();}
    private void toast(String message){Toast.makeText(this,message==null?"Router VPN":message,Toast.LENGTH_LONG).show();}
}
